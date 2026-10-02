import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import type { Json } from "../firewall.js";
import { dpiAppKey } from "./flows.js";

/**
 * Usage reporting:
 *   GET  /v2/api/site/{site}/traffic?start&end&includeUnidentified=true   DPI usage per app and per client
 *   POST /api/s/{site}/stat/report/{5minutes,hourly,daily}.site           WAN byte counters per interval
 * Default console retention: 5-minute data 24 h, hourly 168 h, daily 2160 h (90 days); see stat/sysinfo.
 */

const mb = (bytes: number | undefined) => (typeof bytes === "number" ? Math.round(bytes / 1e5) / 10 : undefined);
const mbps = (bytes: number, seconds: number) => Math.round(((bytes * 8) / seconds / 1e6) * 100) / 100;

interface UsageEntry {
  application: number;
  category: number;
  bytes_received?: number;
  bytes_transmitted?: number;
  total_bytes?: number;
  client_count?: number;
  activity_seconds?: number;
}

interface TrafficResponse {
  total_usage_by_app?: UsageEntry[];
  client_usage_by_app?: { client: Json; usage_by_app: UsageEntry[] }[];
}

const GRANULARITY = {
  "5min": { report: "5minutes.site", seconds: 300, maxHours: 24 },
  hourly: { report: "hourly.site", seconds: 3600, maxHours: 24 * 7 },
  daily: { report: "daily.site", seconds: 86400, maxHours: 24 * 90 },
} as const;

export function pickGranularity(hours: number, requested: "auto" | keyof typeof GRANULARITY): keyof typeof GRANULARITY {
  if (requested !== "auto") return requested;
  if (hours <= 6) return "5min";
  if (hours <= 24 * 7) return "hourly";
  return "daily";
}

export function registerUsageTools(server: McpServer, ctx: UnifiContext): void {
  async function dpiNamer() {
    const dpi = await ctx.dpiCatalogue().catch(() => ({ apps: new Map<number, string>(), categories: new Map<number, string>() }));
    return (e: UsageEntry) => ({
      app: dpi.apps.get(dpiAppKey(e.category, e.application)) ?? `unknown app ${e.category}:${e.application}`,
      category: dpi.categories.get(e.category),
    });
  }

  function usage(e: UsageEntry): Json {
    // Counters are from the client's point of view: received = download.
    return {
      totalMB: mb(e.total_bytes ?? (e.bytes_received ?? 0) + (e.bytes_transmitted ?? 0)),
      downMB: mb(e.bytes_received),
      upMB: mb(e.bytes_transmitted),
    };
  }

  defineTool(
    server,
    ctx,
    "unifi_traffic_by_app",
    {
      title: "Traffic by app and client",
      description:
        "DPI usage over a period: which apps/services used the most data, which devices used the most, and what a given device spends " +
        "its traffic on (e.g. find the BitTorrent host, top streaming devices this month). view=apps ranks applications; view=clients " +
        "ranks devices with their top apps; `client` narrows to one device; `app` narrows to devices using a matching application.",
      input: {
        lastDays: z.number().min(0.04).max(31).default(1).describe("Window ending now, in days (fractions allowed, e.g. 0.25 = 6 hours)"),
        from: z.string().optional().describe("Window start, ISO 8601 (overrides lastDays)"),
        to: z.string().optional().describe("Window end, ISO 8601 (default now)"),
        view: z.enum(["apps", "clients"]).default("apps"),
        client: z.string().optional().describe("Only this device: name, hostname, IP or MAC"),
        app: z.string().optional().describe('Only usage of applications whose name contains this text, e.g. "torrent", "youtube"'),
        top: z.number().int().min(1).max(100).default(15),
      },
    },
    async (args) => {
      const end = args.to ? Date.parse(args.to) : Date.now();
      const start = args.from ? Date.parse(args.from) : end - args.lastDays * 86_400_000;
      if (Number.isNaN(start) || Number.isNaN(end) || start >= end) throw new Error("Invalid time window");

      const [data, nameOf, nameApp] = await Promise.all([
        ctx.legacy.requestV2<TrafficResponse>(`/traffic?start=${start}&end=${end}&includeUnidentified=true`),
        ctx.clientNames(),
        dpiNamer(),
      ]);
      const macs = args.client ? new Set(await ctx.resolveClientMacs(args.client)) : undefined;
      const appNeedle = args.app?.toLowerCase();
      const appMatches = (e: UsageEntry) => !appNeedle || nameApp(e).app.toLowerCase().includes(appNeedle);
      const window = { from: new Date(start).toISOString(), to: new Date(end).toISOString() };

      let clients = (data.client_usage_by_app ?? []).map((c) => ({
        mac: String(c.client?.mac ?? ""),
        name: c.client?.name || nameOf(c.client?.mac) || c.client?.hostname || undefined,
        vendor: c.client?.oui || undefined,
        wired: c.client?.is_wired,
        apps: (c.usage_by_app ?? []).filter(appMatches),
      }));
      if (macs) clients = clients.filter((c) => macs.has(c.mac));
      clients = clients.filter((c) => c.apps.length);
      const bytes = (apps: UsageEntry[]) => apps.reduce((a, e) => a + (e.total_bytes ?? 0), 0);

      if (args.view === "clients" || macs) {
        const ranked = clients
          .map((c) => ({ ...c, total: bytes(c.apps) }))
          .sort((a, b) => b.total - a.total)
          .slice(0, args.top)
          .map((c) => ({
            name: c.name,
            mac: c.mac,
            vendor: c.vendor,
            wired: c.wired,
            totalMB: mb(c.total),
            topApps: [...c.apps]
              .sort((a, b) => (b.total_bytes ?? 0) - (a.total_bytes ?? 0))
              .slice(0, macs ? args.top : 5)
              .map((e) => ({ ...nameApp(e), ...usage(e), activeMinutes: e.activity_seconds ? Math.round(e.activity_seconds / 60) : undefined })),
          }));
        return { window, clientCount: clients.length, ...(macs ? { clientMacs: [...macs] } : {}), clients: ranked };
      }

      // Rank applications. With an app filter, totals are recomputed from the matching per-client rows.
      let totals = (data.total_usage_by_app ?? []).filter(appMatches);
      const all = bytes(data.total_usage_by_app ?? []);
      totals = [...totals].sort((a, b) => (b.total_bytes ?? 0) - (a.total_bytes ?? 0));
      return {
        window,
        totalMB: mb(all),
        appCount: totals.length,
        apps: totals.slice(0, args.top).map((e) => ({
          ...nameApp(e),
          ...usage(e),
          share: all ? `${Math.round(((e.total_bytes ?? 0) / all) * 1000) / 10}%` : undefined,
          clients: e.client_count,
          ...(appNeedle
            ? {
                topClients: clients
                  .map((c) => ({ c, b: bytes(c.apps.filter((x) => x.application === e.application && x.category === e.category)) }))
                  .filter((x) => x.b > 0)
                  .sort((a, b) => b.b - a.b)
                  .slice(0, 5)
                  .map(({ c, b }) => ({ name: c.name, mac: c.mac, MB: mb(b) })),
              }
            : {}),
        })),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_lookup_dpi",
    {
      title: "Look up DPI applications",
      description:
        "Translate DPI application/category IDs into names, or search the catalogue by name. Flow and traffic data report an app as a " +
        "(category, application) pair; the combined id used by the official API is (category << 16) | application.",
      input: {
        query: z.string().optional().describe('Search app or category names, e.g. "torrent"'),
        ids: z
          .array(z.object({ category: z.number().int().min(0), application: z.number().int().min(0) }))
          .optional()
          .describe("Pairs to translate"),
        combinedIds: z.array(z.number().int().min(0)).optional().describe("Official-API combined ids to translate"),
      },
    },
    async ({ query, ids, combinedIds }) => {
      if (!query && !ids?.length && !combinedIds?.length) throw new Error("Pass query, ids or combinedIds");
      const dpi = await ctx.dpiCatalogue();
      const describe = (id: number) => {
        const category = id >> 16;
        return { id, category, application: id & 0xffff, name: dpi.apps.get(id), categoryName: dpi.categories.get(category) };
      };
      const results: Json[] = [];
      for (const p of ids ?? []) results.push(describe(dpiAppKey(p.category, p.application)));
      for (const id of combinedIds ?? []) results.push(describe(id));
      if (query) {
        const q = query.toLowerCase();
        const catHits = new Set([...dpi.categories].filter(([, n]) => n.toLowerCase().includes(q)).map(([id]) => id));
        for (const [id, name] of dpi.apps) {
          if (name.toLowerCase().includes(q) || catHits.has(id >> 16)) results.push(describe(id));
          if (results.length >= 50) break;
        }
      }
      return { count: results.length, results };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_wan_usage",
    {
      title: "WAN usage report",
      description:
        "Internet (WAN) usage over time from the gateway's reports: download/upload totals, average Mbps, the busiest interval, and " +
        "per-interval rows. Granularity auto picks 5-minute data up to 6 hours, hourly up to 7 days, daily beyond. " +
        "Peaks are interval averages, not instantaneous maxima.",
      input: {
        lastHours: z.number().min(1).max(24 * 90).default(24).describe("Window ending now, in hours (e.g. 168 = 7 days, 720 = 30 days)"),
        granularity: z.enum(["auto", "5min", "hourly", "daily"]).default("auto"),
        includeRows: z.boolean().default(true).describe("Include one row per interval"),
      },
    },
    async ({ lastHours, granularity, includeRows }) => {
      const g = pickGranularity(lastHours, granularity);
      const spec = GRANULARITY[g];
      if (lastHours > spec.maxHours) {
        throw new Error(`${g} data only covers about ${spec.maxHours} hours; use a coarser granularity or a shorter window`);
      }
      const end = Date.now();
      const start = end - lastHours * 3_600_000;
      const attrs = ["wan-rx_bytes", "wan-tx_bytes", "wan2-rx_bytes", "wan2-tx_bytes", "num_sta", "time"];
      const rows = await ctx.legacy.request<Json>(`/stat/report/${spec.report}`, { method: "POST", body: { attrs, start, end } });

      const hasWan2 = rows.some((r) => (r["wan2-rx_bytes"] ?? 0) + (r["wan2-tx_bytes"] ?? 0) > 0);
      // rx = received from the internet (download).
      const down = (r: Json) => (r["wan-rx_bytes"] ?? 0) + (hasWan2 ? (r["wan2-rx_bytes"] ?? 0) : 0);
      const up = (r: Json) => (r["wan-tx_bytes"] ?? 0) + (hasWan2 ? (r["wan2-tx_bytes"] ?? 0) : 0);
      const totalDown = rows.reduce((a, r) => a + down(r), 0);
      const totalUp = rows.reduce((a, r) => a + up(r), 0);
      const covered = rows.length * spec.seconds;
      const peak = (f: (r: Json) => number) => {
        const r = rows.reduce<Json | undefined>((best, x) => (!best || f(x) > f(best) ? x : best), undefined);
        return r ? { time: new Date(r.time).toISOString(), mbps: mbps(f(r), spec.seconds), MB: mb(f(r)) } : undefined;
      };

      return {
        granularity: g,
        window: { from: new Date(start).toISOString(), to: new Date(end).toISOString() },
        intervals: rows.length,
        ...(hasWan2 ? { note: "Includes WAN2 (failover/load-balance) traffic" } : {}),
        totals: { downGB: Math.round(totalDown / 1e7) / 100, upGB: Math.round(totalUp / 1e7) / 100 },
        averageMbps: covered ? { down: mbps(totalDown, covered), up: mbps(totalUp, covered) } : undefined,
        peakInterval: { down: peak(down), up: peak(up) },
        ...(includeRows
          ? {
              rows: rows.map((r) => ({
                time: new Date(r.time).toISOString(),
                downMB: mb(down(r)),
                upMB: mb(up(r)),
                downMbps: mbps(down(r), spec.seconds),
                upMbps: mbps(up(r), spec.seconds),
                clients: r.num_sta,
              })),
            }
          : {}),
      };
    },
  );
}
