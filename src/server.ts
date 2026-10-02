import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { UnifiContext } from "./context.js";
import { registerClientTools } from "./tools/clients.js";
import { registerFirewallTools } from "./tools/firewall.js";
import { registerNetworkTools } from "./tools/network.js";

export const VERSION = "0.2.0";

const INSTRUCTIONS = `Tools for a UniFi Network (10.x) home/office network: devices, clients, networks, zone-based firewall policies and client blocking.

Guidelines:
- Resolve vague references first: use unifi_list_clients(search=...) to find a device by name, vendor or IP, and unifi_list_firewall_zones / unifi_list_networks before writing firewall policies.
- Before any change, state exactly what will change and confirm with the user. For firewall changes, call with dryRun=true first and show the summary.
- Firewall policies are evaluated in order per source→destination zone pair, first match wins. A new BLOCK policy may need position="top" to take effect ahead of existing ALLOW policies.
- Prefer disabling a policy over deleting it. Deleting returns a rawPolicy that can recreate it.
- Blocking a client (unifi_block_client) cuts it off the whole network; to restrict only some traffic, create a firewall policy matching its MAC instead.
- Never block the gateway, switches, APs, or the machine this agent runs on.`;

/** Build an MCP server with all tools bound to the shared UniFi context. */
export function createMcpServer(ctx: UnifiContext): McpServer {
  const server = new McpServer({ name: "unifi-mcp", version: VERSION }, { instructions: INSTRUCTIONS });
  registerNetworkTools(server, ctx);
  registerClientTools(server, ctx);
  registerFirewallTools(server, ctx);
  return server;
}
