import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";
import { normalizeMac, type LegacyClient } from "../legacy.js";

const MAX_RAW_CHARS = 60_000;

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const kbps = (bytesPerSec?: number) => (bytesPerSec === undefined ? undefined : Math.round((bytesPerSec * 8) / 100) / 10);
const mb = (bytes?: number) => (bytes === undefined ? undefined : Math.round(bytes / 1e5) / 10);

/**
 * Traffic for a connected client. UniFi reports counters from the AP/switch port's point of view,
 * so "tx" is traffic sent to the client (its download) and "rx" is its upload.
 * Wired clients use the "wired-" prefixed counters.
 */
export function clientTraffic(c: LegacyClient): Json | undefined {
  const p = c.is_wired ? "wired-" : "";
  const down = num(c[`${p}tx_bytes-r`]);
  const up = num(c[`${p}rx_bytes-r`]);
  const totalDown = num(c[`${p}tx_bytes`]);
  const totalUp = num(c[`${p}rx_bytes`]);
  if ([down, up, totalDown, totalUp].every((v) => v === undefined)) return undefined;
  return {
    downKbps: kbps(down),
    upKbps: kbps(up),
    totalDownMB: mb(totalDown),
    totalUpMB: mb(totalUp),
  };
}

export function summarizeLegacyClient(c: LegacyClient, online: boolean): Json {
  const lastSeen = c.last_seen ? new Date(c.last_seen * 1000).toISOString() : undefined;
  return {
    mac: c.mac,
    name: c.name || c.hostname || undefined,
    hostname: c.hostname,
    vendor: c.oui || undefined,
    ip: c.ip || c.last_ip || undefined,
    fixedIp: c.use_fixedip ? c.fixed_ip : undefined,
    network: c.network || c.last_connection_network_name || undefined,
    connection: c.is_wired ? "wired" : c.essid ? `wifi:${c.essid}` : undefined,
    online,
    blocked: c.blocked ?? false,
    guest: c.is_guest || undefined,
    signal: online ? c.signal : undefined,
    traffic: online ? clientTraffic(c) : undefined,
    uptimeSec: online ? num(c.uptime) : undefined,
    lastSeen,
    note: c.note || undefined,
  };
}

function matches(c: Json, needle: string): boolean {
  const n = needle.toLowerCase();
  const macHex = n.replace(/[^0-9a-f]/g, "");
  return (
    ["name", "hostname", "vendor", "ip", "fixedIp", "network", "connection", "note"].some((k) =>
      String(c[k] ?? "").toLowerCase().includes(n),
    ) || (macHex.length >= 4 && String(c.mac).replace(/:/g, "").includes(macHex))
  );
}

function pick(item: unknown, fields: string[]): Json {
  const out: Json = {};
  for (const f of fields) {
    let v: unknown = item;
    for (const part of f.split(".")) v = v && typeof v === "object" ? (v as Json)[part] : undefined;
    if (v !== undefined) out[f] = v;
  }
  return out;
}

/** Page, filter and project list responses so they fit in one tool result. */
export function pageResult(
  data: unknown,
  opts: { fields?: string[]; match?: string; offset: number; limit: number },
): unknown {
  const list = Array.isArray(data) ? data : Array.isArray((data as Json)?.data) ? ((data as Json).data as unknown[]) : undefined;
  if (!list) {
    const text = JSON.stringify(data);
    return text.length > MAX_RAW_CHARS
      ? `${text.slice(0, MAX_RAW_CHARS)}\n…truncated (${text.length} chars total). This endpoint returned a single large object; request a narrower endpoint.`
      : data;
  }
  const needle = opts.match?.toLowerCase();
  const filtered = needle ? list.filter((i) => JSON.stringify(i).toLowerCase().includes(needle)) : list;
  let items = filtered.slice(opts.offset, opts.offset + opts.limit).map((i) => (opts.fields?.length ? pick(i, opts.fields) : i));

  // Shrink the page rather than cutting JSON mid-item when it is too large.
  let note: string | undefined;
  const size = (arr: unknown[]) => JSON.stringify(arr).length;
  if (size(items) > MAX_RAW_CHARS) {
    let lo = 0;
    let hi = items.length;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (size(items.slice(0, mid)) <= MAX_RAW_CHARS) lo = mid;
      else hi = mid - 1;
    }
    items = items.slice(0, Math.max(lo, 1));
    note = `Page reduced to ${items.length} items to stay under ${MAX_RAW_CHARS} characters. Pass \`fields\` to fetch more items per page.`;
  }
  const next = opts.offset + items.length;
  return {
    total: filtered.length,
    offset: opts.offset,
    returned: items.length,
    ...(next < filtered.length ? { nextOffset: next } : {}),
    ...(note ? { note } : {}),
    items,
  };
}

export function registerNetworkTools(server: McpServer, ctx: UnifiContext): void {
  defineTool(
    server,
    ctx,
    "unifi_get_overview",
    {
      title: "Network overview",
      description:
        "Summary of the UniFi site: Network application version, site, device counts by state, number of connected clients, WAN interfaces. Good first call to orient yourself.",
      input: {},
    },
    async () => {
      const i = ctx.integration;
      const [info, site] = await Promise.all([i.request<Json>("/v1/info"), i.resolveSite()]);
      const [devices, clientsPage, wans] = await Promise.all([
        i.siteList<Json>("/devices"),
        i.siteRequest<Json>("/clients", { query: { limit: 1 } }),
        i.siteList<Json>("/wans").catch(() => []),
      ]);
      const byState: Record<string, number> = {};
      for (const d of devices) byState[d.state] = (byState[d.state] ?? 0) + 1;
      return {
        application: info,
        site,
        devices: { total: devices.length, byState, firmwareUpdatable: devices.filter((d) => d.firmwareUpdatable).map((d) => d.name) },
        connectedClients: clientsPage.totalCount,
        wans,
        readOnlyMode: ctx.config.readOnly,
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_list_devices",
    {
      title: "List UniFi devices",
      description: "List adopted UniFi devices (gateways, switches, access points) with model, IP, MAC, state and firmware.",
      input: {
        filter: z
          .string()
          .optional()
          .describe("Optional API filter expression, e.g. state.eq('OFFLINE') or name.like('*AP*'). Fields: id, macAddress, ipAddress, name, model, state, firmwareUpdatable."),
      },
    },
    async ({ filter }) => ctx.integration.siteList("/devices", filter),
  );

  defineTool(
    server,
    ctx,
    "unifi_get_device",
    {
      title: "Get device details",
      description: "Full details for one adopted device (ports, radios, uplink) plus its latest statistics (CPU, memory, uptime, load).",
      input: { deviceId: z.string().describe("Device UUID from unifi_list_devices") },
    },
    async ({ deviceId }) => {
      const [details, stats] = await Promise.all([
        ctx.integration.siteRequest(`/devices/${deviceId}`),
        ctx.integration.siteRequest(`/devices/${deviceId}/statistics/latest`).catch((e: Error) => ({ error: e.message })),
      ]);
      return { details, statistics: stats };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_list_clients",
    {
      title: "List / search clients",
      description:
        "List client devices (phones, laptops, IoT…) with name, hostname, vendor, IP, MAC, network, wifi/wired, blocked status, " +
        "and for connected clients current traffic (downKbps/upKbps, a per-second snapshot) and totals since connecting (totalDownMB/totalUpMB). " +
        "Use `search` to find a client by name, hostname, vendor, IP or partial MAC before blocking or writing a firewall rule for it. " +
        "Use sortBy=traffic to find the busiest devices. For every field of one client, use unifi_get_client.",
      input: {
        status: z
          .enum(["connected", "all", "blocked"])
          .default("connected")
          .describe("connected = online now; all = every client ever seen (incl. offline); blocked = currently blocked clients"),
        search: z.string().optional().describe("Case-insensitive match on name, hostname, vendor, IP, network or MAC"),
        sortBy: z
          .enum(["name", "traffic", "totalTraffic", "lastSeen"])
          .default("name")
          .describe("traffic = current rate, highest first; totalTraffic = bytes since connecting; lastSeen = most recent first"),
        offset: z.number().int().min(0).default(0).describe("Skip this many clients (use nextOffset from a previous call)"),
        limit: z.number().int().min(1).max(1000).default(200),
      },
    },
    async ({ status, search, sortBy, offset, limit }) => {
      let clients: Json[];
      let source = "internal";
      try {
        const active = await ctx.legacy.activeClients();
        const onlineMacs = new Set(active.map((c) => c.mac));
        if (status === "connected") {
          clients = active.map((c) => summarizeLegacyClient(c, true));
        } else {
          const known = await ctx.legacy.knownClients();
          const merged = new Map(known.map((c) => [c.mac, c]));
          for (const a of active) merged.set(a.mac, { ...merged.get(a.mac), ...a });
          clients = [...merged.values()].map((c) => summarizeLegacyClient(c, onlineMacs.has(c.mac)));
          if (status === "blocked") clients = clients.filter((c) => c.blocked);
        }
      } catch (err) {
        if (status !== "connected" || !ctx.integration.available) throw err;
        // Internal API unavailable (e.g. API key not accepted there): fall back to the official API.
        source = `official (internal API unavailable: ${(err as Error).message})`;
        clients = await ctx.integration.siteList<Json>("/clients");
      }
      if (search) clients = clients.filter((c) => matches(c, search));
      const rate = (c: Json) => (c.traffic?.downKbps ?? 0) + (c.traffic?.upKbps ?? 0);
      const total = (c: Json) => (c.traffic?.totalDownMB ?? 0) + (c.traffic?.totalUpMB ?? 0);
      const byName = (a: Json, b: Json) => String(a.name ?? a.mac).localeCompare(String(b.name ?? b.mac));
      const order: Record<string, (a: Json, b: Json) => number> = {
        name: byName,
        traffic: (a, b) => rate(b) - rate(a) || byName(a, b),
        totalTraffic: (a, b) => total(b) - total(a) || byName(a, b),
        lastSeen: (a, b) => String(b.lastSeen ?? "").localeCompare(String(a.lastSeen ?? "")) || byName(a, b),
      };
      clients.sort(order[sortBy]);
      const page = clients.slice(offset, offset + limit);
      const next = offset + page.length;
      return {
        source,
        total: clients.length,
        offset,
        returned: page.length,
        ...(next < clients.length ? { nextOffset: next } : {}),
        clients: page,
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_get_client",
    {
      title: "Get client details",
      description:
        "Every field the controller has for one client (known record merged with live stats when connected): " +
        "radio, channel, AP, switch port, signal, rates, counters, DHCP and fingerprint data. Prefer this over unifi_api_get for a single device.",
      input: { mac: z.string().describe("Client MAC address (any separator)") },
    },
    async ({ mac }) => {
      const m = normalizeMac(mac);
      const [known, active] = await Promise.all([ctx.legacy.knownClients(), ctx.legacy.activeClients()]);
      const k = known.find((c) => c.mac === m);
      const a = active.find((c) => c.mac === m);
      if (!k && !a) throw new Error(`No client with MAC ${m}. Use unifi_list_clients with search to find it.`);
      const record = { ...k, ...a } as LegacyClient;
      return { summary: summarizeLegacyClient(record, Boolean(a)), record };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_list_networks",
    {
      title: "List networks / VLANs",
      description: "List configured networks (LAN/VLANs) with IDs, VLAN IDs and subnets. Network names can be used directly in firewall policy tools.",
      input: {},
    },
    async () => ctx.networks(),
  );

  defineTool(
    server,
    ctx,
    "unifi_list_wifi",
    { title: "List WiFi networks", description: "List WiFi broadcasts (SSIDs) and their settings.", input: {} },
    async () => ctx.integration.siteList("/wifi/broadcasts"),
  );

  defineTool(
    server,
    ctx,
    "unifi_api_get",
    {
      title: "Raw API GET",
      description:
        "Read-only escape hatch for any GET endpoint not covered by other tools. " +
        "api=official: path under /proxy/network/integration, e.g. /v1/sites/{siteId}/vpn/servers ({siteId} is substituted). " +
        "api=internal: path under /proxy/network/api/s/<site>, e.g. /stat/health, /stat/sysinfo, /rest/portforward, /stat/event. " +
        "List responses are paged: use `fields` to keep only the keys you need (dot paths allowed) and `match` to filter items, " +
        "then follow nextOffset. Responses are capped at about 60,000 characters.",
      input: {
        api: z.enum(["official", "internal"]),
        path: z.string().startsWith("/"),
        fields: z
          .array(z.string())
          .optional()
          .describe('Keys to keep from each list item, e.g. ["mac","hostname","tx_bytes-r","rx_bytes-r"] or ["uplink.name"]'),
        match: z.string().optional().describe("Keep only list items whose JSON contains this text (case-insensitive)"),
        offset: z.number().int().min(0).default(0),
        limit: z.number().int().min(1).max(1000).default(100),
      },
    },
    async ({ api, path, fields, match, offset, limit }) => {
      let data: unknown;
      if (api === "official") {
        const site = await ctx.integration.resolveSite();
        data = await ctx.integration.request(path.replace("{siteId}", site.id));
      } else {
        data = await ctx.legacy.request(path);
      }
      return pageResult(data, { fields, match, offset, limit });
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_restart_device",
    {
      title: "Restart a UniFi device",
      description: "Reboot an adopted UniFi device (AP, switch, gateway). Clients on it will lose connectivity for a few minutes.",
      input: { deviceId: z.string().describe("Device UUID from unifi_list_devices") },
      write: true,
      destructive: true,
    },
    async ({ deviceId }) => {
      const res = await ctx.integration.siteRequest(`/devices/${deviceId}/actions`, { method: "POST", body: { action: "RESTART" } });
      await ctx.audit("restart_device", { deviceId });
      return { ok: true, result: res };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_power_cycle_port",
    {
      title: "Power-cycle a PoE port",
      description: "Power-cycle a PoE port on a UniFi switch, rebooting whatever it powers (camera, AP…).",
      input: {
        deviceId: z.string().describe("Switch UUID"),
        portIdx: z.number().int().min(1).describe("Port number"),
      },
      write: true,
      destructive: true,
    },
    async ({ deviceId, portIdx }) => {
      const res = await ctx.integration.siteRequest(`/devices/${deviceId}/interfaces/ports/${portIdx}/actions`, {
        method: "POST",
        body: { action: "POWER_CYCLE" },
      });
      await ctx.audit("power_cycle_port", { deviceId, portIdx });
      return { ok: true, result: res };
    },
  );
}
