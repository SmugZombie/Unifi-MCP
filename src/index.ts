#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { UnifiContext } from "./context.js";
import { startHttpServer } from "./httpServer.js";
import { createMcpServer } from "./server.js";

async function main() {
  const config = loadConfig();
  if (!config.verifyTls) console.error("unifi-mcp: TLS certificate verification is disabled (UNIFI_VERIFY_TLS=false)");
  const ctx = new UnifiContext(config);
  ctx.scheduler.start();
  if (!config.readOnly) ctx.watcher.start();
  const target = `${config.host} (site "${config.site}"${config.readOnly ? ", read-only" : ""})`;

  if (config.transport.kind === "http") {
    const server = startHttpServer(ctx, config.transport);
    const shutdown = () => server.close(() => process.exit(0));
    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);
    console.error(`unifi-mcp: managing ${target}`);
    return;
  }

  await createMcpServer(ctx).connect(new StdioServerTransport());
  console.error(`unifi-mcp: connected to ${target}`);
}

main().catch((err) => {
  console.error(`unifi-mcp: ${err.message}`);
  process.exit(1);
});
