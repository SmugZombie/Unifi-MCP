import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";
import { normalizeMac } from "../legacy.js";

/**
 * Traffic flows (Insights → Flows in the UniFi UI) come from the internal v2 API:
 *   POST /v2/api/site/{site}/traffic-flows                       list, filters in the body
 *   GET  /v2/api/site/{site}/traffic-flows/{id}                  one flow
 *   GET  /v2/api/site/{site}/traffic-flow-latest-statistics      summaries (?period=&top=)
 * Filter values must be arrays. Without an action filter the controller returns only blocked flows.
 */

const MAX_WINDOW_MIN = 31 * 24 * 60;

interface FlowPage {
  data: Json[];
  has_next?: boolean;
  page_number?: number;
  total_element_count?: number;
  total_page_count?: number;
}

function hostPort(ep: Json | undefined): string {
  if (!ep) return "?";
  const ip = ep.ip ?? "?";
  const addr = ep.port ? (String(ip).includes(":") ? `[${ip}]:${ep.port}` : `${ip}:${ep.port}`) : String(ip);
  return addr;
}

/** Official-API DPI application id for a (category, app) pair as reported in flow statistics. */
export const dpiAppKey = (categoryId: number | undefined, appId: number) => ((categoryId ?? 0) << 16) | appId;

export function summarizeFlow(f: Json, nameOf: (mac?: string) => string | undefined): Json {
  const src = f.source ?? {};
  const dst = f.destination ?? {};
  const label = (ep: Json) => {
    const name = nameOf(ep.mac);
    const domains = Array.isArray(ep.domains) && ep.domains.length ? ` (${ep.domains.slice(0, 3).join(", ")})` : "";
    return [name, hostPort(ep) + domains, ep.region && ep.region !== "--" ? ep.region : undefined].filter(Boolean).join(" ");
  };
  return {
    id: f.id,
    time: typeof f.time === "number" ? new Date(f.time).toISOString() : f.time,
    action: f.action,
    direction: f.direction,
    risk: f.risk,
    protocol: f.protocol,
    service: f.service,
    from: label(src),
    fromMac: src.mac,
    to: label(dst),
    toZone: dst.zone_name,
    policies: Array.isArray(f.policies) && f.policies.length ? f.policies.map((p: Json) => p.type ?? p.internal_type) : undefined,
    count: f.count > 1 ? f.count : undefined,
    traffic: f.traffic_data && Object.keys(f.traffic_data).length ? f.traffic_data : undefined,
  };
}

export function registerFlowTools(server: McpServer, ctx: UnifiContext): void {
  /** MAC → friendly name from the controller's known clients (best effort). */
  async function clientNames(): Promise<(mac?: string) => string | undefined> {
    try {
      const known = await ctx.legacy.knownClients();
      const map = new Map(known.map((c) => [c.mac, c.name || c.hostname]));
      return (mac) => (mac ? map.get(mac.toLowerCase()) || undefined : undefined);
    } catch {
      return () => undefined;
    }
  }

  /** Resolve a client name, hostname, IP or MAC to MAC addresses. */
  async function resolveClient(query: string): Promise<string[]> {
    try {
      return [normalizeMac(query)];
    } catch {
      // Not a MAC; search known clients.
    }
    const q = query.toLowerCase();
    const known = await ctx.legacy.knownClients();
    const exact = known.filter((c) => [c.name, c.hostname, c.ip, c.last_ip].some((v) => v && String(v).toLowerCase() === q));
    const hits = exact.length
      ? exact
      : known.filter((c) => [c.name, c.hostname, c.oui].some((v) => v && String(v).toLowerCase().includes(q)));
    if (!hits.length) throw new Error(`No client matches "${query}". Use unifi_list_clients with search to find it.`);
    if (hits.length > 10) {
      throw new Error(`"${query}" matches ${hits.length} clients; be more specific or pass a MAC address.`);
    }
    return hits.map((c) => c.mac);
  }

  defineTool(
    server,
    ctx,
    "unifi_list_flows",
    {
      title: "List traffic flows",
      description:
        "Traffic flow logs from the gateway (Insights → Flows): completed connections with source, destination, port, protocol, " +
        "service, risk, matching firewall policy and allowed/blocked action. Use it to answer 'what is this device talking to', " +
        "'what got blocked', or 'who connected to port 22'. Filters combine with AND. Results are paged (newest first); " +
        "follow nextPage. For counts and top talkers over a period, use unifi_flow_statistics instead.",
      input: {
        lastMinutes: z
          .number()
          .int()
          .min(1)
          .max(MAX_WINDOW_MIN)
          .default(60)
          .describe("Time window ending now (default 60). Ignored when `from` is given."),
        from: z.string().optional().describe("Window start, ISO 8601 (e.g. 2026-10-01T22:00:00-07:00)"),
        to: z.string().optional().describe("Window end, ISO 8601 (default now)"),
        action: z.enum(["all", "allowed", "blocked"]).default("all"),
        direction: z.array(z.enum(["incoming", "outgoing", "local"])).optional(),
        risk: z.array(z.enum(["low", "medium", "high"])).optional(),
        client: z
          .string()
          .optional()
          .describe("Local device that originated the traffic: name, hostname, IP or MAC (resolved to MAC addresses)"),
        sourceIp: z.array(z.string()).optional(),
        destinationIp: z.array(z.string()).optional(),
        destinationPort: z.array(z.number().int().min(1).max(65535)).optional(),
        destinationDomain: z.array(z.string()).optional(),
        destinationRegion: z.array(z.string()).optional().describe('ISO country codes, e.g. ["CN","RU"]'),
        search: z.string().optional().describe("Free-text search, as in the UI search box"),
        page: z.number().int().min(0).default(0),
        pageSize: z.number().int().min(1).max(200).default(50),
      },
    },
    async (args) => {
      const toMs = args.to ? Date.parse(args.to) : Date.now();
      const fromMs = args.from ? Date.parse(args.from) : toMs - args.lastMinutes * 60_000;
      if (Number.isNaN(fromMs) || Number.isNaN(toMs)) throw new Error("from/to must be ISO 8601 timestamps");
      if (fromMs >= toMs) throw new Error("from must be before to");

      const body: Json = {
        timestampFrom: fromMs,
        timestampTo: toMs,
        pageNumber: args.page,
        pageSize: args.pageSize,
        action: args.action === "all" ? ["allowed", "blocked"] : [args.action],
      };
      if (args.direction?.length) body.direction = args.direction;
      if (args.risk?.length) body.risk = args.risk;
      if (args.client) body.source_mac = await resolveClient(args.client);
      if (args.sourceIp?.length) body.source_ip = args.sourceIp;
      if (args.destinationIp?.length) body.destination_ip = args.destinationIp;
      if (args.destinationPort?.length) body.destination_port = args.destinationPort;
      if (args.destinationDomain?.length) body.destination_domain = args.destinationDomain;
      if (args.destinationRegion?.length) body.destination_region = args.destinationRegion.map((r) => r.toUpperCase());
      if (args.search) body.search_text = args.search;

      const [page, nameOf] = await Promise.all([
        ctx.legacy.requestV2<FlowPage>("/traffic-flows", { method: "POST", body }),
        clientNames(),
      ]);
      return {
        window: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
        ...(body.source_mac ? { clientMacs: body.source_mac } : {}),
        total: page.total_element_count,
        page: page.page_number ?? args.page,
        totalPages: page.total_page_count,
        ...(page.has_next ? { nextPage: (page.page_number ?? args.page) + 1 } : {}),
        flows: (page.data ?? []).map((f) => summarizeFlow(f, nameOf)),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_get_flow",
    {
      title: "Get traffic flow details",
      description: "Full record of one traffic flow (interfaces, IPs, timing, policies, byte and packet counts) by id from unifi_list_flows.",
      input: { flowId: z.string() },
    },
    async ({ flowId }) => {
      if (!/^[A-Za-z0-9_-]+$/.test(flowId)) throw new Error("Invalid flow id");
      const [flow, nameOf] = await Promise.all([ctx.legacy.requestV2<Json>(`/traffic-flows/${flowId}`), clientNames()]);
      return { summary: summarizeFlow(flow, nameOf), flow };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_flow_statistics",
    {
      title: "Traffic flow statistics",
      description:
        "Summary of traffic flows over a period: top clients, top destinations, top applications by bytes, " +
        "top blocking policies and most-blocked clients, plus allowed/blocked counts by country and risk level.",
      input: {
        period: z.enum(["HOUR", "DAY", "WEEK", "MONTH"]).default("DAY"),
        top: z.number().int().min(1).max(50).default(10).describe("How many entries per top-N list"),
      },
    },
    async ({ period, top }) => {
      const [stats, nameOf, dpi] = await Promise.all([
        ctx.legacy.requestV2<Json>(`/traffic-flow-latest-statistics?period=${period}&top=${top}`),
        clientNames(),
        ctx.dpiCatalogue().catch(() => ({ apps: new Map<number, string>(), categories: new Map<number, string>() })),
      ]);
      const out: Json = { period };
      for (const [key, value] of Object.entries(stats)) {
        if (!Array.isArray(value)) {
          out[key] = value;
          continue;
        }
        out[key] = value.map((row: Json) => {
          const { client_fingerprint: _f, icon_filename: _i, icon_resolutions: _r, client_name, ...rest } = row;
          if (rest.client_mac) {
            const name = (typeof client_name === "string" && client_name) || nameOf(rest.client_mac);
            if (name) rest.client = name;
          }
          if (typeof rest.application_id === "number") {
            const app = dpi.apps.get(dpiAppKey(rest.category_id, rest.application_id));
            if (app) rest.application = app;
            const category = dpi.categories.get(rest.category_id);
            if (category) rest.category = category;
          }
          if (typeof rest.bytes === "number") rest.MB = Math.round(rest.bytes / 1e5) / 10;
          return rest;
        });
      }
      return out;
    },
  );
}
