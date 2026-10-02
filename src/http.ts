import { readFileSync } from "node:fs";
import { Agent, fetch, type Response } from "undici";
import type { Config } from "./config.js";

export class UnifiApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly method: string,
    readonly path: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "UnifiApiError";
  }
}

/**
 * Join a fixed API prefix with a caller-supplied sub-path, refusing anything that could resolve
 * outside the prefix: dot segments (including percent-encoded ones, which URL parsing also
 * collapses), encoded slashes, backslashes and fragments. Query strings are allowed.
 */
export function safeJoin(prefix: string, subPath: string): string {
  if (!subPath.startsWith("/")) throw new Error(`Invalid API path "${subPath}": must start with /`);
  if (/[\\#]/.test(subPath)) throw new Error(`Invalid API path "${subPath}": backslashes and # are not allowed`);
  const [pathPart] = subPath.split("?", 1);
  for (const segment of pathPart.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error(`Invalid API path "${subPath}": malformed percent-encoding`);
    }
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\")) {
      throw new Error(`Invalid API path "${subPath}": "." / ".." segments and encoded slashes are not allowed`);
    }
  }
  const full = prefix + subPath;
  // Belt and braces: resolution must not move the path out of the prefix.
  const resolved = new URL(full, "http://unifi.invalid").pathname;
  if (resolved !== full.split("?", 1)[0] || !resolved.startsWith(prefix + "/")) {
    throw new Error(`Invalid API path "${subPath}": resolves outside ${prefix}`);
  }
  return full;
}

export interface RequestOptions {
  method?: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  headers?: Record<string, string>;
}

/** Thin fetch wrapper that handles TLS settings, timeouts, JSON encoding and error decoding. */
export class HttpTransport {
  private readonly dispatcher: Agent;

  constructor(private readonly config: Config) {
    this.dispatcher = new Agent({
      connect: {
        rejectUnauthorized: config.verifyTls,
        ca: config.caCertPath ? readFileSync(config.caCertPath) : undefined,
      },
    });
  }

  get host(): string {
    return this.config.host;
  }

  async raw(path: string, opts: RequestOptions = {}): Promise<Response> {
    const url = new URL(this.config.host + path);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.body);
    }
    try {
      return await fetch(url, {
        method: opts.method ?? "GET",
        headers,
        body,
        dispatcher: this.dispatcher,
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (err) {
      const cause = (err as { cause?: { code?: string; message?: string } }).cause;
      const code = cause?.code ?? "";
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code)) {
        throw new Error(
          `TLS verification failed for ${this.config.host} (${code}). UniFi consoles use a self-signed certificate: ` +
            `set UNIFI_CA_CERT to the console's certificate, or UNIFI_VERIFY_TLS=false on a trusted LAN.`,
        );
      }
      throw new Error(`Could not reach ${this.config.host}: ${cause?.message ?? (err as Error).message}`);
    }
  }

  static async decode(res: Response, method: string, path: string): Promise<unknown> {
    const text = await res.text();
    let parsed: unknown = text;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        // Leave as text; some endpoints return HTML on auth errors.
      }
    }
    if (!res.ok) {
      const detail =
        parsed && typeof parsed === "object"
          ? ((parsed as Record<string, unknown>).message ?? (parsed as { meta?: { msg?: string } }).meta?.msg ?? JSON.stringify(parsed))
          : String(parsed).slice(0, 300);
      throw new UnifiApiError(`${method} ${path} failed: HTTP ${res.status} ${detail}`, res.status, method, path, parsed);
    }
    return parsed;
  }
}
