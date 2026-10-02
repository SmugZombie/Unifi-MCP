import { homedir } from "node:os";
import { join } from "node:path";

export interface Config {
  /** Base URL of the UniFi console, e.g. https://192.168.1.1 */
  host: string;
  /** API key from Network > Settings > Control Plane > Integrations. */
  apiKey?: string;
  /** Local admin credentials, used for the internal API when the API key is rejected. */
  username?: string;
  password?: string;
  /** Site name, internal reference ("default"), or UUID. */
  site: string;
  verifyTls: boolean;
  caCertPath?: string;
  readOnly: boolean;
  /** Path to the JSONL audit log of write operations, or undefined to disable. */
  auditLog?: string;
  timeoutMs: number;
  transport: TransportConfig;
  /** JSON file holding scheduled undo actions (timed blocks). */
  stateFile: string;
  schedulerIntervalMs: number;
}

export type TransportConfig =
  | { kind: "stdio" }
  | { kind: "http"; host: string; port: number; authToken: string; allowedOrigins: string[] };

function loadTransport(env: NodeJS.ProcessEnv): TransportConfig {
  const kind = (env.MCP_TRANSPORT ?? "stdio").toLowerCase();
  if (kind === "stdio") return { kind: "stdio" };
  if (kind !== "http") throw new Error(`MCP_TRANSPORT must be "stdio" or "http" (got "${kind}")`);

  // Over HTTP anyone who can reach the port could change the firewall, so a token is mandatory.
  const authToken = env.MCP_AUTH_TOKEN?.trim() ?? "";
  if (authToken.length < 24) {
    throw new Error("MCP_TRANSPORT=http requires MCP_AUTH_TOKEN of at least 24 characters (e.g. `openssl rand -hex 32`)");
  }
  return {
    kind: "http",
    host: env.MCP_HOST?.trim() || "127.0.0.1",
    port: Number(env.MCP_PORT) || 3000,
    authToken,
    allowedOrigins: (env.MCP_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((o) => o.trim())
      .filter(Boolean),
  };
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const rawHost = env.UNIFI_HOST?.trim();
  if (!rawHost) {
    throw new Error("UNIFI_HOST is required (e.g. https://192.168.1.1)");
  }
  const host = (/^https?:\/\//i.test(rawHost) ? rawHost : `https://${rawHost}`).replace(/\/+$/, "");

  const apiKey = env.UNIFI_API_KEY?.trim() || undefined;
  const username = env.UNIFI_USERNAME?.trim() || undefined;
  const password = env.UNIFI_PASSWORD || undefined;
  if (!apiKey && !(username && password)) {
    throw new Error("Set UNIFI_API_KEY (recommended) and/or UNIFI_USERNAME + UNIFI_PASSWORD");
  }

  const auditEnv = env.UNIFI_AUDIT_LOG;
  const auditLog =
    auditEnv === undefined ? join(homedir(), ".unifi-mcp", "audit.log") : ["", "off", "false", "0"].includes(auditEnv) ? undefined : auditEnv;

  return {
    host,
    apiKey,
    username,
    password,
    site: env.UNIFI_SITE?.trim() || "default",
    verifyTls: bool(env.UNIFI_VERIFY_TLS, true),
    caCertPath: env.UNIFI_CA_CERT || undefined,
    readOnly: bool(env.UNIFI_READ_ONLY, false),
    auditLog,
    timeoutMs: Number(env.UNIFI_TIMEOUT_MS) || 15000,
    transport: loadTransport(env),
    stateFile: env.UNIFI_STATE_FILE || join(homedir(), ".unifi-mcp", "scheduled.json"),
    schedulerIntervalMs: Number(env.UNIFI_SCHEDULER_INTERVAL_MS) || 30_000,
  };
}
