import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ZodRawShape, z } from "zod";
import type { Config } from "./config.js";
import type { Json, Lookups } from "./firewall.js";
import { HttpTransport } from "./http.js";
import { IntegrationClient } from "./integration.js";
import { LegacyApiClient, normalizeMac } from "./legacy.js";
import { ProfileStore, ProfileWatcher } from "./profiles.js";
import { Scheduler, type ScheduledJob } from "./scheduler.js";

export interface Zone {
  id: string;
  name: string;
  networkIds: string[];
  metadata?: { origin?: string };
}

export interface Network {
  id: string;
  name: string;
  vlanId?: number;
  [key: string]: unknown;
}

const CACHE_TTL_MS = 30_000;

export class UnifiContext {
  readonly integration: IntegrationClient;
  readonly legacy: LegacyApiClient;
  readonly scheduler: Scheduler;
  readonly profiles: ProfileStore;
  readonly watcher: ProfileWatcher;
  private cache = new Map<string, { at: number; value: unknown }>();

  constructor(readonly config: Config) {
    const http = new HttpTransport(config);
    this.integration = new IntegrationClient(http, config.apiKey, config.site);
    this.legacy = new LegacyApiClient(http, config, async () =>
      // The internal API addresses sites by their short name ("default").
      this.integration.available ? (await this.integration.resolveSite()).internalReference : config.site,
    );
    this.scheduler = new Scheduler(config.stateFile, (job) => this.runScheduled(job), config.schedulerIntervalMs);
    this.profiles = new ProfileStore(config.profilesFile);
    this.watcher = new ProfileWatcher(
      this.profiles,
      {
        activeClients: () => this.legacy.activeClients(),
        knownClients: () => this.legacy.knownClients(),
        updateClient: (id, body) => this.legacy.updateClient(id, body),
        kick: (mac) => this.legacy.kick(mac),
        audit: async (action, details) => {
          this.invalidate();
          await this.audit(action, details);
        },
      },
      config.watchIntervalMs,
    );
  }

  /** Perform a scheduled undo. Must be idempotent (see Scheduler). */
  private async runScheduled(job: ScheduledJob): Promise<void> {
    switch (job.action) {
      case "unblock_client":
        await this.legacy.unblock(job.args.mac);
        break;
      case "delete_firewall_policy":
        try {
          await this.integration.siteRequest(`/firewall/policies/${job.args.policyId}`, { method: "DELETE" });
        } catch (err) {
          // Already removed (by hand or by another server process) counts as done.
          if (!IntegrationClient.isNotFound(err)) throw err;
        }
        break;
      default:
        throw new Error(`Unknown scheduled action ${(job as ScheduledJob).action}`);
    }
    this.invalidate();
    await this.audit(`scheduled_${job.action}`, { job: job.id, label: job.label, args: job.args });
  }

  private consoleTz?: string;

  /** The console's configured timezone (falls back to this machine's). */
  async consoleTimezone(): Promise<string> {
    if (this.consoleTz) return this.consoleTz;
    try {
      const [info] = await this.legacy.request<{ timezone?: string }>("/stat/sysinfo");
      this.consoleTz = info?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
    } catch {
      this.consoleTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    }
    return this.consoleTz;
  }

  private async cached<T>(key: string, load: () => Promise<T>): Promise<T> {
    const hit = this.cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.value as T;
    const value = await load();
    this.cache.set(key, { at: Date.now(), value });
    return value;
  }

  invalidate(): void {
    this.cache.clear();
  }

  zones(): Promise<Zone[]> {
    return this.cached("zones", () => this.integration.siteList<Zone>("/firewall/zones"));
  }

  networks(): Promise<Network[]> {
    return this.cached("networks", () => this.integration.siteList<Network>("/networks"));
  }

  private dpi?: Promise<{ apps: Map<number, string>; categories: Map<number, string> }>;

  /**
   * DPI catalogue (cached for the process lifetime). Application ids in the official API combine
   * category and app: (categoryId << 16) | appId. Flow statistics report the two parts separately.
   */
  dpiCatalogue(): Promise<{ apps: Map<number, string>; categories: Map<number, string> }> {
    type Item = { id: number; name: string };
    this.dpi ??= Promise.all([
      this.integration.listAll<Item>("/v1/dpi/applications", undefined, 20000),
      this.integration.listAll<Item>("/v1/dpi/categories"),
    ])
      .then(([apps, cats]) => ({
        apps: new Map(apps.map((a) => [a.id, a.name])),
        categories: new Map(cats.map((c) => [c.id, c.name])),
      }))
      .catch((err) => {
        this.dpi = undefined;
        throw err;
      });
    return this.dpi;
  }

  /** MAC → friendly name from the controller's known clients (best effort, never throws). */
  async clientNames(): Promise<(mac?: string) => string | undefined> {
    try {
      const known = await this.cached("knownClients", () => this.legacy.knownClients());
      const map = new Map(known.map((c) => [c.mac, c.name || c.hostname]));
      return (mac) => (mac ? map.get(mac.toLowerCase()) || undefined : undefined);
    } catch {
      return () => undefined;
    }
  }

  /** Resolve a client name, hostname, IP or MAC to MAC addresses (several for randomized MACs or partial names). */
  async resolveClientMacs(query: string): Promise<string[]> {
    try {
      return [normalizeMac(query)];
    } catch {
      // Not a MAC; search known clients.
    }
    const q = query.toLowerCase();
    const known = await this.cached("knownClients", () => this.legacy.knownClients());
    const exact = known.filter((c) => [c.name, c.hostname, c.ip, c.last_ip].some((v) => v && String(v).toLowerCase() === q));
    const hits = exact.length
      ? exact
      : known.filter((c) => [c.name, c.hostname, c.oui].some((v) => v && String(v).toLowerCase().includes(q)));
    if (!hits.length) throw new Error(`No client matches "${query}". Use unifi_list_clients with search to find it.`);
    if (hits.length > 10) throw new Error(`"${query}" matches ${hits.length} clients; be more specific or pass a MAC address.`);
    return hits.map((c) => c.mac);
  }

  /** Name/ID resolvers for zones and networks, so tools can accept "IoT" instead of a UUID. */
  async lookups(): Promise<Lookups & { zoneName(id: string): string; networkName(id: string): string }> {
    const [zones, networks] = await Promise.all([this.zones(), this.networks()]);
    const resolve = (kind: string, items: { id: string; name: string }[], key: string) => {
      const k = key.trim().toLowerCase();
      const hit = items.find((i) => i.id === key) ?? items.find((i) => i.name.toLowerCase() === k);
      if (hit) return hit.id;
      const partial = items.filter((i) => i.name.toLowerCase().includes(k));
      if (partial.length === 1) return partial[0].id;
      throw new Error(`Unknown ${kind} "${key}". Known ${kind}s: ${items.map((i) => i.name).join(", ")}`);
    };
    const name = (items: { id: string; name: string }[]) => (id: string) => items.find((i) => i.id === id)?.name ?? id;
    return {
      zoneId: (k) => resolve("zone", zones, k),
      networkId: (k) => resolve("network", networks, k),
      zoneName: name(zones),
      networkName: name(networks),
    };
  }

  /** Append a write operation to the audit log. Failures to log never block the operation. */
  async audit(action: string, details: Json): Promise<void> {
    if (!this.config.auditLog) return;
    try {
      await mkdir(dirname(this.config.auditLog), { recursive: true });
      await appendFile(this.config.auditLog, JSON.stringify({ at: new Date().toISOString(), action, ...details }) + "\n");
    } catch (err) {
      console.error(`audit log write failed: ${(err as Error).message}`);
    }
  }
}

export function ok(data: unknown): CallToolResult {
  return { content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data) }] };
}

interface ToolDef<S extends ZodRawShape> {
  title: string;
  description: string;
  input: S;
  /** Write tools are not registered when UNIFI_READ_ONLY=true. */
  write?: boolean;
  destructive?: boolean;
}

/** Register a tool with consistent annotations and error handling. */
export function defineTool<S extends ZodRawShape>(
  server: McpServer,
  ctx: UnifiContext,
  name: string,
  def: ToolDef<S>,
  handler: (args: z.infer<z.ZodObject<S>>) => Promise<unknown>,
): void {
  if (def.write && ctx.config.readOnly) return;
  server.registerTool(
    name,
    {
      title: def.title,
      description: def.description,
      inputSchema: def.input,
      annotations: {
        title: def.title,
        readOnlyHint: !def.write,
        destructiveHint: def.write ? (def.destructive ?? false) : false,
        openWorldHint: false,
      },
    },
    (async (args: z.infer<z.ZodObject<S>>) => {
      try {
        const result = await handler(args);
        if (def.write) ctx.invalidate();
        return ok(result);
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] } satisfies CallToolResult;
      }
    }) as never,
  );
}
