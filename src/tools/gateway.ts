import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";

const toMbps = (bytesPerSec: unknown) => (typeof bytesPerSec === "number" ? Math.round(((bytesPerSec * 8) / 1e6) * 100) / 100 : undefined);
const iso = (unixSec: unknown) => (typeof unixSec === "number" && unixSec > 0 ? new Date(unixSec * 1000).toISOString() : undefined);
const anyIfEmpty = (v: unknown) => (v === undefined || v === null || v === "" || v === "any" ? "any" : v);

export function registerGatewayTools(server: McpServer, ctx: UnifiContext): void {
  defineTool(
    server,
    ctx,
    "unifi_list_port_forwards",
    {
      title: "List port forwards",
      description:
        "Port-forwarding rules on the gateway: which WAN ports are open to which internal host and port, protocol, WAN interface, " +
        "source restrictions and whether each rule is enabled. Internal targets are labelled with the device name when known.",
      input: {},
    },
    async () => {
      const [rules, known] = await Promise.all([
        ctx.legacy.request<Json>("/rest/portforward"),
        ctx.legacy.knownClients().catch(() => []),
      ]);
      const byIp = new Map<string, string>();
      for (const c of known) {
        const name = c.name || c.hostname;
        if (!name) continue;
        for (const ip of [c.fixed_ip, c.ip, c.last_ip]) if (ip && !byIp.has(ip)) byIp.set(ip, name);
      }
      return {
        count: rules.length,
        enabled: rules.filter((r) => r.enabled).length,
        rules: rules.map((r) => ({
          id: r._id,
          name: r.name,
          enabled: r.enabled,
          protocol: r.proto,
          wanPort: r.dst_port,
          forwardTo: `${r.fwd}:${r.fwd_port || r.dst_port}`,
          device: byIp.get(r.fwd),
          wanInterface: r.pfwd_interface,
          wanAddress: anyIfEmpty(r.destination_ip),
          allowedSources: r.src_limiting_enabled ? anyIfEmpty(r.src) : "any",
          logging: r.log || undefined,
        })),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_wan_health",
    {
      title: "WAN / internet health",
      description:
        "Current internet health: WAN status, ISP, public IP, gateway and DNS servers, latency, packet drops, uptime and availability " +
        "per WAN with monitor probes (degradedMonitors lists any below 100% availability), last speed test, current throughput, and gateway CPU/memory. For usage over time use unifi_wan_usage.",
      input: {},
    },
    async () => {
      const [health, wans] = await Promise.all([
        ctx.legacy.request<Json>("/stat/health"),
        ctx.integration.available ? ctx.integration.siteList<Json>("/wans").catch(() => []) : Promise.resolve([]),
      ]);
      const sub = (name: string) => health.find((s) => s.subsystem === name) ?? {};
      const wan = sub("wan");
      const www = sub("www");
      const stats = wan["gw_system-stats"] ?? {};

      // `alerting_monitors` are the probes used for outage alerts (not ones currently failing); `monitors` are the others.
      const perWan = Object.entries((wan.uptime_stats ?? {}) as Record<string, Json>).map(([iface, u]) => {
        const probes = [
          ...(u.alerting_monitors ?? []).map((m: Json) => ({ ...m, usedForAlerts: true })),
          ...(u.monitors ?? []).map((m: Json) => ({ ...m, usedForAlerts: false })),
        ];
        const fmt = (m: Json) => `${m.type} ${m.target}: ${m.availability}% avail, ${m.latency_average} ms${m.usedForAlerts ? " (alerting)" : ""}`;
        return {
          interface: iface,
          availabilityPct: u.availability,
          latencyAvgMs: u.latency_average,
          uptimeSec: u.uptime,
          periodSec: u.time_period,
          degradedMonitors: probes.filter((m) => typeof m.availability === "number" && m.availability < 100).map(fmt),
          monitors: probes.map(fmt),
        };
      });

      return {
        status: { wan: wan.status, internet: www.status, lan: sub("lan").status, wlan: sub("wlan").status, vpn: sub("vpn").status },
        isp: { name: wan.isp_name, organization: wan.isp_organization, asn: wan.asn },
        wanIp: wan.wan_ip,
        configuredWans: wans.map((w) => w.name),
        gateways: wan.gateways,
        dns: wan.nameservers,
        latencyMs: www.latency,
        drops: www.drops,
        internetUptimeSec: www.uptime,
        perWan,
        throughputNowMbps: { down: toMbps(www["rx_bytes-r"] ?? wan["rx_bytes-r"]), up: toMbps(www["tx_bytes-r"] ?? wan["tx_bytes-r"]) },
        lastSpeedTest: {
          status: www.speedtest_status,
          ranAt: iso(www.speedtest_lastrun),
          downMbps: www.xput_down,
          upMbps: www.xput_up,
          pingMs: www.speedtest_ping,
        },
        gatewayDevice: {
          name: wan.gw_name,
          mac: wan.gw_mac,
          firmware: wan.gw_version,
          cpuPct: stats.cpu !== undefined ? Number(stats.cpu) : undefined,
          memPct: stats.mem !== undefined ? Number(stats.mem) : undefined,
          uptimeSec: stats.uptime !== undefined ? Number(stats.uptime) : undefined,
        },
        clients: { wired: sub("lan").num_user, wireless: sub("wlan").num_user, guests: (sub("wlan").num_guest ?? 0) + (sub("lan").num_guest ?? 0) },
      };
    },
  );
}
