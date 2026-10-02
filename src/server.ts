import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { UnifiContext } from "./context.js";
import { registerClientTools } from "./tools/clients.js";
import { registerFirewallTools } from "./tools/firewall.js";
import { registerFlowTools } from "./tools/flows.js";
import { registerGatewayTools } from "./tools/gateway.js";
import { registerNetworkTools } from "./tools/network.js";
import { registerReachabilityTools } from "./tools/reachability.js";
import { registerUsageTools } from "./tools/usage.js";

export const VERSION = "0.2.0";

const INSTRUCTIONS = `Tools for a UniFi Network (10.x) home/office network: devices, clients, networks, zone-based firewall policies and client blocking.

Guidelines:
- For bandwidth questions use unifi_list_clients(sortBy="traffic"): it includes current download/upload rates (a per-second snapshot) and totals since connecting. Use unifi_get_client for every field of one device.
- For "what is this device talking to / what was blocked" use unifi_list_flows (connection logs with filters); for top talkers, destinations, apps and blocking policies over a period use unifi_flow_statistics.
- For data usage by app or device over days/weeks use unifi_traffic_by_app; for internet bandwidth over time (averages, totals, busiest hours) use unifi_wan_usage; to turn DPI ids into names use unifi_lookup_dpi.
- For "can X reach Y" questions use unifi_check_reachability instead of reasoning over policy lists by hand; pass port/protocol when known, and \`at\` to check a scheduled time.
- To summarise many flows (top source IPs, countries, ports, clients) use unifi_flow_top rather than paging unifi_list_flows.
- For temporary restrictions use expiries: unifi_block_client(untilTime="06:00") removes a device from the network; unifi_block_internet keeps it on the LAN but cuts internet. Times are in the console's timezone. Tell the user when the block will lift.
- Avoid dumping large raw lists with unifi_api_get; pass \`fields\` and \`match\`, and follow nextOffset.
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
  registerFlowTools(server, ctx);
  registerUsageTools(server, ctx);
  registerGatewayTools(server, ctx);
  registerReachabilityTools(server, ctx);
  return server;
}
