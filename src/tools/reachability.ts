import { isIP } from "node:net";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import { summarizePolicy, type Json } from "../firewall.js";
import type { LegacyClient } from "../legacy.js";
import { cidrContains, evaluatePolicies, ipv4ToInt, isPrivateIpv4, type Endpoint } from "../reachability.js";
import { formatInZone, nextWallClock } from "../scheduler.js";

interface NetInfo {
  id?: string; // official network id (zones reference these)
  name: string;
  zoneId?: string;
  subnet?: string; // gateway address/prefix, e.g. 192.168.98.1/24
  purpose?: string;
}

/** "192.168.98.1/24" (gateway address form) → "192.168.98.0/24". */
function networkCidr(gatewayCidr: string): string | undefined {
  const [ip, bits] = gatewayCidr.split("/");
  const n = ipv4ToInt(ip);
  const b = Number(bits);
  if (n === undefined || !(b >= 0 && b <= 32)) return undefined;
  const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
  const lo = (n & mask) >>> 0;
  return `${[24, 16, 8, 0].map((sh) => (lo >>> sh) & 255).join(".")}/${b}`;
}

const DOMAIN_RE = /^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)+$/i;

export function registerReachabilityTools(server: McpServer, ctx: UnifiContext): void {
  async function topology() {
    const [zones, official, conf, known, active, wlans] = await Promise.all([
      ctx.zones(),
      ctx.integration.siteList<Json>("/networks"),
      ctx.legacy.request<Json>("/rest/networkconf"),
      ctx.legacy.knownClients(),
      ctx.legacy.activeClients(),
      ctx.legacy.request<Json>("/rest/wlanconf").catch(() => []),
    ]);
    const nets: NetInfo[] = conf.map((n) => {
      const o = official.find((x) => x.name === n.name);
      return { id: o?.id, name: n.name, zoneId: o?.zoneId, subnet: n.ip_subnet, purpose: n.purpose };
    });
    const zoneByName = (name: string) => zones.find((z) => z.name.toLowerCase() === name.toLowerCase());
    const isolatedSsids = new Set(wlans.filter((w) => w.l2_isolation).map((w) => w.name));
    return { zones, nets, known, active, zoneByName, isolatedSsids };
  }
  type Topo = Awaited<ReturnType<typeof topology>>;

  function ipEndpoint(t: Topo, ip: string, label: string): Endpoint {
    const gw = t.zoneByName("Gateway");
    const ext = t.zoneByName("External");
    for (const n of t.nets) {
      if (!n.subnet) continue;
      const gwIp = n.subnet.split("/")[0];
      if (ip === gwIp && gw) return { label, kind: "ip", ip, zoneId: gw.id, zoneName: gw.name, networkName: `${n.name} gateway address` };
      if (!cidrContains(n.subnet, ip)) continue;
      if (n.zoneId) {
        const z = t.zones.find((x) => x.id === n.zoneId);
        return { label, kind: "ip", ip, zoneId: n.zoneId, zoneName: z?.name ?? n.zoneId, networkId: n.id, networkName: n.name };
      }
      if (/vpn/i.test(n.purpose ?? "")) {
        const vpn = t.zoneByName("Vpn");
        if (vpn) return { label, kind: "ip", ip, zoneId: vpn.id, zoneName: vpn.name, networkName: n.name };
      }
    }
    if (ipv4ToInt(ip) !== undefined && isPrivateIpv4(ip)) {
      throw new Error(`${ip} is a private address that is not in any configured network; cannot tell which zone it belongs to`);
    }
    if (!ext) throw new Error("No External zone found");
    return { label, kind: "internet", ip, zoneId: ext.id, zoneName: ext.name };
  }

  async function resolveEndpoint(t: Topo, spec: string, notes: string[]): Promise<Endpoint & { client?: LegacyClient; online?: boolean }> {
    const s = spec.trim();
    if (/^(internet|external|wan|outside|the internet)$/i.test(s)) {
      const ext = t.zoneByName("External");
      if (!ext) throw new Error("No External zone found");
      return { label: "the internet", kind: "internet", zoneId: ext.id, zoneName: ext.name };
    }
    // net.isIP rejects MAC addresses, which a loose hex-and-colons check would mistake for IPv6.
    if (isIP(s)) return ipEndpoint(t, s, s);

    // A configured network name (e.g. a VLAN) stands for every device on it.
    const named = t.nets.find((n) => n.zoneId && n.name.toLowerCase() === s.toLowerCase());
    if (named?.zoneId) {
      const z = t.zones.find((x) => x.id === named.zoneId);
      const range = named.subnet ? networkCidr(named.subnet) : undefined;
      return { label: `network ${named.name}`, kind: "network", networkId: named.id, networkName: named.name, subnet: range, zoneId: named.zoneId, zoneName: z?.name ?? named.zoneId };
    }

    let macs: string[] | undefined;
    try {
      macs = await ctx.resolveClientMacs(s);
    } catch (err) {
      if (DOMAIN_RE.test(s)) {
        const ext = t.zoneByName("External");
        if (!ext) throw new Error("No External zone found");
        notes.push(`"${s}" was treated as an internet domain; IP-, country- and app-based policies are reported as conditions`);
        return { label: s, kind: "internet", domain: s, zoneId: ext.id, zoneName: ext.name };
      }
      throw err;
    }
    const activeByMac = new Map(t.active.map((c) => [c.mac, c]));
    const candidates = macs.map((m) => ({ ...t.known.find((c) => c.mac === m), ...activeByMac.get(m), mac: m }) as LegacyClient);
    candidates.sort((a, b) => Number(activeByMac.has(b.mac)) - Number(activeByMac.has(a.mac)) || (b.last_seen ?? 0) - (a.last_seen ?? 0));
    const c = candidates[0];
    if (candidates.length > 1) {
      notes.push(`"${s}" matches ${candidates.length} clients; evaluated ${c.name || c.hostname || c.mac} (${c.mac}), the ${activeByMac.has(c.mac) ? "connected" : "most recently seen"} one`);
    }
    const online = activeByMac.has(c.mac);
    const ip = c.ip || (c.use_fixedip ? c.fixed_ip : undefined) || c.last_ip;
    const label = `${c.name || c.hostname || c.mac}`;
    const netName = c.network || c.last_connection_network_name;
    const net = t.nets.find((n) => n.name === netName && n.zoneId);
    if (net?.zoneId) {
      const z = t.zones.find((x) => x.id === net.zoneId);
      return { label, kind: "client", ip, mac: c.mac, networkId: net.id, networkName: net.name, zoneId: net.zoneId, zoneName: z?.name ?? net.zoneId, client: c, online };
    }
    if (ip) return { ...ipEndpoint(t, ip, label), kind: "client", mac: c.mac, client: c, online };
    throw new Error(`Cannot determine the network of ${label}; it has no known IP or network`);
  }

  defineTool(
    server,
    ctx,
    "unifi_check_reachability",
    {
      title: "Check reachability",
      description:
        "Answer 'can X reach Y?' by evaluating the zone-based firewall the way the gateway does: finds the zones of both ends, walks " +
        "that zone pair's policies in order (first match wins), honours schedules (including overnight windows) at the time checked, " +
        "skips return-traffic-only rules, and reports the deciding policy. Also handles blocked clients, same-network traffic (not " +
        "routed, so the zone firewall does not apply) and Wi-Fi client isolation. `from`/`to` accept a device name, hostname, IP, MAC, " +
        "a network (VLAN) name, a domain, or 'internet'. Without port/protocol, narrower earlier policies are listed: `exceptions` have the " +
        "opposite action (e.g. 'allowed, except DNS and VPN apps are blocked'), `conditions` the same one; `otherTimes` lists scheduled " +
        "policies inactive at the time checked. Verdict 'depends' means no policy fully matched.",
      input: {
        from: z.string().describe("Source: device (name, hostname, IP, MAC) or network name"),
        to: z.string().describe('Destination: device, IP, network name, domain, or "internet"'),
        port: z.number().int().min(1).max(65535).optional().describe("Destination port"),
        protocol: z.enum(["tcp", "udp", "icmp"]).optional(),
        at: z
          .string()
          .optional()
          .describe('When to evaluate schedules: ISO 8601 time, or "HH:MM" for the next occurrence in the console timezone (default now)'),
      },
    },
    async ({ from, to, port, protocol, at }) => {
      const tz = await ctx.consoleTimezone();
      const when = !at ? new Date() : /^\d{1,2}:\d{2}$/.test(at.trim()) ? nextWallClock(at, tz) : new Date(Date.parse(at));
      if (Number.isNaN(when.getTime())) throw new Error("at must be an ISO 8601 time or HH:MM");
      if (port !== undefined && protocol === "icmp") throw new Error("ICMP has no ports");

      const notes: string[] = [];
      const [t, policies, lookups] = await Promise.all([topology(), ctx.integration.siteList<Json>("/firewall/policies"), ctx.lookups()]);
      const src = await resolveEndpoint(t, from, notes);
      const dst = await resolveEndpoint(t, to, notes);
      const describe = (e: typeof src) => ({
        name: e.label,
        ...(e.mac ? { mac: e.mac } : {}),
        ...(e.ip ? { ip: e.ip } : {}),
        ...(e.networkName ? { network: e.networkName } : {}),
        zone: e.zoneName,
        ...(e.online !== undefined ? { online: e.online } : {}),
        ...(e.domain ? { domain: e.domain } : {}),
        ...(e.subnet ? { subnet: e.subnet } : {}),
      });
      const question = `${src.label} → ${dst.label}${protocol || port ? ` (${[protocol, port].filter(Boolean).join("/")})` : ""}`;
      const base = { question, checkedAt: formatInZone(when, tz), source: describe(src), destination: describe(dst) };

      if (src.client?.blocked) {
        return { ...base, verdict: "blocked", reason: `${src.label} is blocked from the network (unifi_unblock_client to lift)`, notes };
      }
      if (dst.client?.blocked) {
        return { ...base, verdict: "blocked", reason: `${dst.label} is blocked from the network`, notes };
      }
      if (dst.kind === "client" && dst.online === false) notes.push(`${dst.label} is not connected right now`);

      // Same network (and not the gateway itself): switched at layer 2, never reaches the zone firewall.
      if (src.networkId && src.networkId === dst.networkId && dst.zoneName.toLowerCase() !== "gateway") {
        const ssids = [src.client?.essid, dst.client?.essid].filter((s): s is string => Boolean(s));
        const isolated = ssids.filter((s) => t.isolatedSsids.has(s));
        if (isolated.length) {
          return {
            ...base,
            verdict: "blocked",
            reason: `Both are on network ${src.networkName}, but Wi-Fi client isolation is enabled on SSID ${[...new Set(isolated)].join(", ")}, which stops wireless clients from reaching other devices on it`,
            notes,
          };
        }
        return {
          ...base,
          verdict: "allowed",
          reason: `Both are on network ${src.networkName}; traffic is switched locally and does not pass through the zone firewall`,
          notes: [...notes, "Switch ACL rules and host firewalls are not evaluated"],
        };
      }

      const evaluation = evaluatePolicies(policies, src, dst, { protocol, port, at: when, timezone: tz });
      const notMatching = evaluation.steps.filter((s) => s.outcome === "not matching").length;
      return {
        ...base,
        verdict: evaluation.verdict,
        reason: evaluation.reason,
        ...(evaluation.decidedBy ? { decidingPolicy: summarizePolicy(evaluation.decidedBy, lookups.zoneName, lookups.networkName) } : {}),
        ...(evaluation.exceptions.length ? { exceptions: evaluation.exceptions } : {}),
        ...(evaluation.conditions.length ? { conditions: evaluation.conditions } : {}),
        ...(evaluation.scheduleNotes.length ? { otherTimes: evaluation.scheduleNotes } : {}),
        evaluated: {
          zonePair: `${src.zoneName} → ${dst.zoneName}`,
          steps: evaluation.steps.filter((s) => s.outcome !== "not matching"),
          policiesNotMatching: notMatching,
        },
        ...(notes.length ? { notes } : {}),
      };
    },
  );
}
