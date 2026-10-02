import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ZodRawShape, z } from "zod";
import type { Config } from "./config.js";
import type { Json, Lookups } from "./firewall.js";
import { HttpTransport } from "./http.js";
import { IntegrationClient } from "./integration.js";
import { LegacyApiClient } from "./legacy.js";

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
  private cache = new Map<string, { at: number; value: unknown }>();

  constructor(readonly config: Config) {
    const http = new HttpTransport(config);
    this.integration = new IntegrationClient(http, config.apiKey, config.site);
    this.legacy = new LegacyApiClient(http, config, async () =>
      // The internal API addresses sites by their short name ("default").
      this.integration.available ? (await this.integration.resolveSite()).internalReference : config.site,
    );
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
  return { content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }] };
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
