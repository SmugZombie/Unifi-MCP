import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { TransportConfig } from "./config.js";
import type { UnifiContext } from "./context.js";
import { createMcpServer, VERSION } from "./server.js";

type HttpConfig = Extract<TransportConfig, { kind: "http" }>;

const MAX_BODY_BYTES = 1024 * 1024;

function sendJson(res: ServerResponse, status: number, data: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(data));
}

function jsonRpcError(res: ServerResponse, status: number, message: string, headers?: Record<string, string>) {
  sendJson(res, status, { jsonrpc: "2.0", error: { code: -32000, message }, id: null }, headers);
}

function tokenMatches(header: string | undefined, expected: string): boolean {
  const supplied = Buffer.from(header?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim() ?? "");
  const want = Buffer.from(expected);
  return supplied.length === want.length && timingSafeEqual(supplied, want);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error("Request body too large");
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
}

/**
 * Serve MCP over Streamable HTTP at /mcp (stateless: a fresh MCP server per request,
 * sharing one UniFi context so login sessions and caches are reused).
 */
export function startHttpServer(ctx: UnifiContext, cfg: HttpConfig) {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;

    if (path === "/healthz") return sendJson(res, 200, { status: "ok", version: VERSION });
    if (path !== "/mcp") return sendJson(res, 404, { error: "not found" });

    // Browsers send Origin; refuse unknown ones to block DNS-rebinding style attacks.
    const origin = req.headers.origin;
    if (origin && !cfg.allowedOrigins.includes(origin)) return jsonRpcError(res, 403, "Origin not allowed");
    if (!tokenMatches(req.headers.authorization, cfg.authToken)) {
      return jsonRpcError(res, 401, "Unauthorized", { "www-authenticate": "Bearer" });
    }
    if (req.method !== "POST") {
      // Stateless mode has no server-initiated streams or sessions to resume or delete.
      return jsonRpcError(res, 405, "Method not allowed", { allow: "POST" });
    }

    let body: unknown;
    try {
      body = await readJson(req);
    } catch (err) {
      return jsonRpcError(res, 400, (err as Error).message);
    }

    const mcp = createMcpServer(ctx);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (err) {
      console.error(`unifi-mcp: request failed: ${(err as Error).message}`);
      if (!res.headersSent) jsonRpcError(res, 500, "Internal server error");
    }
  });

  server.listen(cfg.port, cfg.host, () => {
    console.error(`unifi-mcp: listening on http://${cfg.host}:${cfg.port}/mcp`);
  });
  return server;
}
