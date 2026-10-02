import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";

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

/** Filters shared by unifi_list_flows and unifi_flow_top. */
const FLOW_FILTERS = {
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
};

type FlowFilterArgs = {
  lastMinutes: number;
  from?: string;
  to?: string;
  action: "all" | "allowed" | "blocked";
  direction?: string[];
  risk?: string[];
  client?: string;
  sourceIp?: string[];
  destinationIp?: string[];
  destinationPort?: number[];
  destinationDomain?: string[];
  destinationRegion?: string[];
  search?: string;
};

/** Translate tool filters into the traffic-flows request body. Filter values must be arrays. */
export async function buildFlowQuery(args: FlowFilterArgs, resolveClient: (q: string) => Promise<string[]>) {
  const toMs = args.to ? Date.parse(args.to) : Date.now();
  const fromMs = args.from ? Date.parse(args.from) : toMs - args.lastMinutes * 60_000;
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) throw new Error("from/to must be ISO 8601 timestamps");
  if (fromMs >= toMs) throw new Error("from must be before to");

  const body: Json = {
    timestampFrom: fromMs,
    timestampTo: toMs,
    // Without an action filter the controller returns only blocked flows.
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
  return { body, fromMs, toMs };
}

const GROUP_KEYS = {
  sourceIp: (f: Json) => f.source?.ip,
  sourceRegion: (f: Json) => f.source?.region,
  client: (f: Json) => f.source?.mac,
  destinationIp: (f: Json) => f.destination?.ip,
  destinationPort: (f: Json) => f.destination?.port,
  destinationRegion: (f: Json) => f.destination?.region,
  destinationDomain: (f: Json) => (Array.isArray(f.destination?.domains) && f.destination.domains[0]) || undefined,
  service: (f: Json) => f.service,
  protocol: (f: Json) => f.protocol,
  policy: (f: Json) => (Array.isArray(f.policies) && f.policies.length ? f.policies.map((p: Json) => p.type ?? p.internal_type).join("+") : "none"),
  direction: (f: Json) => f.direction,
  action: (f: Json) => f.action,
} as const;
export type FlowGroupKey = keyof typeof GROUP_KEYS;

/** Count flows (weighted by their repeat count) and bytes per group, highest first. */
export function aggregateFlows(flows: Json[], groupBy: FlowGroupKey, secondary?: FlowGroupKey) {
  const groups = new Map<string, { flows: number; bytes: number; first: number; last: number; examples: Map<string, number> }>();
  for (const f of flows) {
    const raw = GROUP_KEYS[groupBy](f);
    const key = raw === undefined || raw === null || raw === "" || raw === "--" ? "(unknown)" : String(raw);
    const g = groups.get(key) ?? { flows: 0, bytes: 0, first: Infinity, last: 0, examples: new Map() };
    const n = typeof f.count === "number" && f.count > 0 ? f.count : 1;
    g.flows += n;
    const td = f.traffic_data ?? {};
    g.bytes += (td.bytes_rx ?? 0) + (td.bytes_tx ?? 0);
    if (typeof f.time === "number") {
      g.first = Math.min(g.first, f.time);
      g.last = Math.max(g.last, f.time);
    }
    if (secondary) {
      const sk = String(GROUP_KEYS[secondary](f) ?? "(unknown)");
      g.examples.set(sk, (g.examples.get(sk) ?? 0) + n);
    }
    groups.set(key, g);
  }
  return [...groups.entries()]
    .map(([key, g]) => ({ key, ...g }))
    .sort((a, b) => b.flows - a.flows || b.bytes - a.bytes);
}

export function registerFlowTools(server: McpServer, ctx: UnifiContext): void {
  const clientNames = () => ctx.clientNames();
  const resolveClient = (query: string) => ctx.resolveClientMacs(query);

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
        "follow nextPage. To group flows (top source IPs, countries, ports, clients) use unifi_flow_top; for ready-made period " +
        "summaries use unifi_flow_statistics.",
      input: {
        ...FLOW_FILTERS,
        page: z.number().int().min(0).default(0),
        pageSize: z.number().int().min(1).max(200).default(50),
      },
    },
    async (args) => {
      const { body, fromMs, toMs } = await buildFlowQuery(args, (q) => resolveClient(q));
      body.pageNumber = args.page;
      body.pageSize = args.pageSize;

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
    "unifi_flow_top",
    {
      title: "Top-N traffic flows",
      description:
        "Group traffic flows server-side and return the top N, instead of pulling thousands of rows: e.g. blocked incoming traffic " +
        "by source IP, country or destination port; outgoing connections by client or domain. Accepts the same filters as " +
        "unifi_list_flows. `thenBy` adds a breakdown inside each group (e.g. groupBy=sourceRegion thenBy=destinationPort). " +
        "Counts are flows weighted by their repeat count. If the window holds more than maxFlows flows, only the newest maxFlows are " +
        "grouped and `sampled` is true.",
      input: {
        ...FLOW_FILTERS,
        groupBy: z.enum(Object.keys(GROUP_KEYS) as [FlowGroupKey, ...FlowGroupKey[]]),
        thenBy: z.enum(Object.keys(GROUP_KEYS) as [FlowGroupKey, ...FlowGroupKey[]]).optional(),
        top: z.number().int().min(1).max(100).default(20),
        maxFlows: z.number().int().min(1000).max(50_000).default(10_000).describe("Upper bound on flows read (1,000 per request)"),
      },
    },
    async (args) => {
      const { body, fromMs, toMs } = await buildFlowQuery(args, (q) => resolveClient(q));
      const PAGE = 1000;
      const flows: Json[] = [];
      let total: number | undefined;
      for (let page = 0; flows.length < args.maxFlows; page++) {
        const res = await ctx.legacy.requestV2<FlowPage>("/traffic-flows", {
          method: "POST",
          body: { ...body, pageNumber: page, pageSize: PAGE },
        });
        total ??= res.total_element_count;
        flows.push(...(res.data ?? []));
        if (!res.has_next || !res.data?.length) break;
      }
      const used = flows.slice(0, args.maxFlows);
      const nameOf = await clientNames();
      const label = (key: FlowGroupKey, value: string) =>
        key === "client" && value !== "(unknown)" ? `${nameOf(value) ?? "unnamed"} (${value})` : value;

      const groups = aggregateFlows(used, args.groupBy, args.thenBy);
      return {
        window: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
        groupBy: args.groupBy,
        ...(args.thenBy ? { thenBy: args.thenBy } : {}),
        flowsMatched: total,
        flowsGrouped: used.length,
        sampled: total !== undefined && total > used.length,
        groupCount: groups.length,
        top: groups.slice(0, args.top).map((g) => ({
          [args.groupBy]: label(args.groupBy, g.key),
          flows: g.flows,
          ...(g.bytes ? { KB: Math.round(g.bytes / 100) / 10 } : {}),
          firstSeen: Number.isFinite(g.first) ? new Date(g.first).toISOString() : undefined,
          lastSeen: g.last ? new Date(g.last).toISOString() : undefined,
          ...(args.thenBy
            ? {
                [args.thenBy]: [...g.examples.entries()]
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 5)
                  .map(([k, n]) => `${label(args.thenBy!, k)} (${n})`),
              }
            : {}),
        })),
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
