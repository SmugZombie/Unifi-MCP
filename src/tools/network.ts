import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";
import type { LegacyClient } from "../legacy.js";

const MAX_RAW_CHARS = 60_000;

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
        "List client devices (phones, laptops, IoT…) with name, hostname, vendor, IP, MAC, network, wifi/wired, and blocked status. " +
        "Use `search` to find a client by name, hostname, vendor, IP or partial MAC before blocking or writing a firewall rule for it.",
      input: {
        status: z
          .enum(["connected", "all", "blocked"])
          .default("connected")
          .describe("connected = online now; all = every client ever seen (incl. offline); blocked = currently blocked clients"),
        search: z.string().optional().describe("Case-insensitive match on name, hostname, vendor, IP, network or MAC"),
        limit: z.number().int().min(1).max(1000).default(200),
      },
    },
    async ({ status, search, limit }) => {
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
      clients.sort((a, b) => String(a.name ?? a.mac).localeCompare(String(b.name ?? b.mac)));
      return { source, total: clients.length, clients: clients.slice(0, limit) };
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
        "api=internal: path under /proxy/network/api/s/<site>, e.g. /stat/health, /stat/sysinfo, /rest/portforward, /stat/event.",
      input: {
        api: z.enum(["official", "internal"]),
        path: z.string().startsWith("/"),
      },
    },
    async ({ api, path }) => {
      let data: unknown;
      if (api === "official") {
        const site = await ctx.integration.resolveSite();
        data = await ctx.integration.request(path.replace("{siteId}", site.id));
      } else {
        data = await ctx.legacy.request(path);
      }
      const text = JSON.stringify(data, null, 1);
      return text.length > MAX_RAW_CHARS ? text.slice(0, MAX_RAW_CHARS) + `\n…truncated (${text.length} chars total)` : data;
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
