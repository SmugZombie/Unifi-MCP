import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import {
  buildAction,
  buildEndpoint,
  buildIpProtocolScope,
  buildPolicy,
  deepMerge,
  resolveProtocol,
  summarizePolicy,
  toWritable,
  type EndpointSpec,
  type Json,
} from "../firewall.js";

const endpointSchema = z
  .object({
    ips: z.array(z.string()).optional().describe('IP addresses, CIDR subnets or ranges, e.g. ["10.0.0.5", "10.0.20.0/24", "10.0.0.10-10.0.0.20"]'),
    networks: z.array(z.string()).optional().describe("Network names or IDs (see unifi_list_networks)"),
    macs: z.array(z.string()).optional().describe("Client MAC addresses (source only)"),
    domains: z.array(z.string()).optional().describe("Domain names (destination only)"),
    regions: z.array(z.string()).optional().describe('ISO 3166 country codes, e.g. ["CN", "RU"]'),
    ports: z.array(z.union([z.number().int(), z.string()])).optional().describe('Ports or ranges, e.g. [22, "8000-8100"]'),
    matchOpposite: z.boolean().optional().describe("For networks: match everything EXCEPT the listed networks"),
  })
  .describe("Optional traffic filter. Only one of ips / networks / domains / regions per side; ports may be combined with any.");

const protocolSchema = z
  .enum(["all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6"])
  .optional()
  .describe("Defaults to tcp_udp when ports are given, otherwise all");
const ipVersionSchema = z.enum(["IPV4", "IPV6", "IPV4_AND_IPV6"]).optional().describe("Default IPV4_AND_IPV6");
const actionSchema = z.enum(["ALLOW", "BLOCK", "REJECT"]);
const connectionStatesSchema = z
  .array(z.enum(["NEW", "INVALID", "ESTABLISHED", "RELATED"]))
  .optional()
  .describe("Match only these connection states (default: all)");
const positionSchema = z.enum(["top", "bottom"]).optional().describe("Move the policy to the top or bottom of its zone pair's user-defined policies");

const POLICY_HELP =
  "Zone-based firewall: a policy matches traffic from a source zone to a destination zone (e.g. Internal → External, IoT → Internal). " +
  "Use unifi_list_firewall_zones to see zones. Zone and network names are accepted in place of IDs.";

export function registerFirewallTools(server: McpServer, ctx: UnifiContext): void {
  const policies = () => ctx.integration.siteList<Json>("/firewall/policies");
  const getPolicy = (id: string) => ctx.integration.siteRequest<Json>(`/firewall/policies/${id}`);

  async function summary(p: Json) {
    const l = await ctx.lookups();
    return summarizePolicy(p, l.zoneName, l.networkName);
  }

  async function assertUserDefined(p: Json) {
    if (p.metadata?.origin && p.metadata.origin !== "USER_DEFINED") {
      throw new Error(`Policy "${p.name}" is ${p.metadata.origin} and cannot be modified through the API. Create an overriding user-defined policy instead.`);
    }
  }

  async function move(policyId: string, position: "top" | "bottom" | "before" | "after", relativeTo?: string) {
    const p = await getPolicy(policyId);
    const query = { sourceFirewallZoneId: p.source.zoneId, destinationFirewallZoneId: p.destination.zoneId };
    const current = await ctx.integration.siteRequest<Json>("/firewall/policies/ordering", { query });
    const before: string[] = (current.orderedFirewallPolicyIds?.beforeSystemDefined ?? []).filter((id: string) => id !== policyId);
    const after: string[] = (current.orderedFirewallPolicyIds?.afterSystemDefined ?? []).filter((id: string) => id !== policyId);

    if (position === "top") before.unshift(policyId);
    else if (position === "bottom") before.push(policyId);
    else {
      if (!relativeTo) throw new Error(`position "${position}" requires relativeTo`);
      const list = before.includes(relativeTo) ? before : after.includes(relativeTo) ? after : undefined;
      if (!list) throw new Error(`Policy ${relativeTo} is not a user-defined policy in the same zone pair`);
      list.splice(list.indexOf(relativeTo) + (position === "after" ? 1 : 0), 0, policyId);
    }
    const body = { orderedFirewallPolicyIds: { beforeSystemDefined: before, afterSystemDefined: after } };
    return ctx.integration.siteRequest<Json>("/firewall/policies/ordering", { method: "PUT", query, body });
  }

  defineTool(
    server,
    ctx,
    "unifi_list_firewall_zones",
    {
      title: "List firewall zones",
      description: "List zone-based firewall zones (Internal, External, Gateway, VPN, Hotspot, DMZ, custom…) and the networks assigned to each.",
      input: {},
    },
    async () => {
      const [zones, l] = await Promise.all([ctx.zones(), ctx.lookups()]);
      return zones.map((z) => ({ id: z.id, name: z.name, origin: z.metadata?.origin, networks: z.networkIds.map(l.networkName) }));
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_list_firewall_policies",
    {
      title: "List firewall policies",
      description: `List firewall policies with a readable summary of source, destination, protocol and action. ${POLICY_HELP}`,
      input: {
        sourceZone: z.string().optional().describe("Only policies from this zone (name or ID)"),
        destinationZone: z.string().optional().describe("Only policies to this zone (name or ID)"),
        search: z.string().optional().describe("Case-insensitive match on name/description"),
        includeSystemDefined: z.boolean().default(false).describe("Include built-in system policies"),
        full: z.boolean().default(false).describe("Return the complete policy JSON instead of summaries"),
      },
    },
    async ({ sourceZone, destinationZone, search, includeSystemDefined, full }) => {
      const l = await ctx.lookups();
      const src = sourceZone ? l.zoneId(sourceZone) : undefined;
      const dst = destinationZone ? l.zoneId(destinationZone) : undefined;
      const all = await policies();
      const s = search?.toLowerCase();
      const selected = all
        .filter((p) => includeSystemDefined || p.metadata?.origin === "USER_DEFINED")
        .filter((p) => !src || p.source?.zoneId === src)
        .filter((p) => !dst || p.destination?.zoneId === dst)
        .filter((p) => !s || `${p.name} ${p.description ?? ""}`.toLowerCase().includes(s))
        .sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
      return {
        total: all.length,
        shown: selected.length,
        policies: full ? selected : selected.map((p) => summarizePolicy(p, l.zoneName, l.networkName)),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_get_firewall_policy",
    {
      title: "Get firewall policy",
      description: "Full JSON of a single firewall policy plus a readable summary.",
      input: { policyId: z.string() },
    },
    async ({ policyId }) => {
      const p = await getPolicy(policyId);
      return { summary: await summary(p), policy: p };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_create_firewall_policy",
    {
      title: "Create firewall policy",
      description:
        `Create a zone-based firewall policy. ${POLICY_HELP} ` +
        "Examples: block an IoT network from reaching Internal: action=BLOCK sourceZone=IoT destinationZone=Internal. " +
        "Block a client from the internet: action=BLOCK sourceZone=Internal source.macs=[mac] destinationZone=External. " +
        "Block inbound from countries: sourceZone=External source.regions=[...] destinationZone=Internal. " +
        "For anything the simple fields cannot express (apps, schedules, traffic matching lists) pass rawPolicy using the API schema. " +
        "Use dryRun=true to preview the exact request first.",
      input: {
        name: z.string().optional(),
        description: z.string().optional(),
        action: actionSchema.optional(),
        allowReturnTraffic: z.boolean().optional().describe("ALLOW only: also allow return traffic (default true)"),
        sourceZone: z.string().optional(),
        destinationZone: z.string().optional(),
        source: endpointSchema.optional(),
        destination: endpointSchema.optional(),
        protocol: protocolSchema,
        ipVersion: ipVersionSchema,
        connectionStates: connectionStatesSchema,
        logging: z.boolean().optional(),
        enabled: z.boolean().optional().describe("Default true"),
        schedule: z.record(z.string(), z.any()).optional().describe('API schedule object, e.g. {"mode":"EVERY_DAY","timeFilter":{"startTime":"22:00","stopTime":"06:00"}}'),
        rawPolicy: z.record(z.string(), z.any()).optional().describe("Complete CreateOrUpdateFirewallPolicy body; overrides all simple fields"),
        position: positionSchema,
        dryRun: z.boolean().default(false),
      },
      write: true,
    },
    async (args) => {
      let body: Json;
      if (args.rawPolicy) {
        body = args.rawPolicy;
      } else {
        if (!args.name || !args.action || !args.sourceZone || !args.destinationZone) {
          throw new Error("name, action, sourceZone and destinationZone are required (or pass rawPolicy)");
        }
        body = buildPolicy(
          {
            name: args.name,
            description: args.description,
            enabled: args.enabled,
            action: args.action,
            allowReturnTraffic: args.allowReturnTraffic,
            sourceZone: args.sourceZone,
            destinationZone: args.destinationZone,
            source: args.source as EndpointSpec | undefined,
            destination: args.destination as EndpointSpec | undefined,
            protocol: args.protocol,
            ipVersion: args.ipVersion,
            connectionStates: args.connectionStates,
            logging: args.logging,
            schedule: args.schedule,
          },
          await ctx.lookups(),
        );
      }
      if (args.dryRun) return { dryRun: true, request: { method: "POST", path: "/firewall/policies", body } };

      const created = await ctx.integration.siteRequest<Json>("/firewall/policies", { method: "POST", body });
      await ctx.audit("create_firewall_policy", { id: created.id, body });
      let ordering: unknown;
      if (args.position) ordering = await move(created.id, args.position);
      return { ok: true, summary: await summary(created), policy: created, ...(ordering ? { ordering } : {}) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_update_firewall_policy",
    {
      title: "Update firewall policy",
      description:
        "Modify an existing user-defined firewall policy. Only the fields you pass change. " +
        "Passing sourceZone/source (or destinationZone/destination) rebuilds that side's match from the simple fields. " +
        "`changes` is deep-merged into the policy JSON for advanced edits (null deletes a key). Use dryRun=true to preview.",
      input: {
        policyId: z.string(),
        name: z.string().optional(),
        description: z.string().optional(),
        enabled: z.boolean().optional(),
        action: actionSchema.optional(),
        allowReturnTraffic: z.boolean().optional(),
        sourceZone: z.string().optional(),
        destinationZone: z.string().optional(),
        source: endpointSchema.optional(),
        destination: endpointSchema.optional(),
        protocol: protocolSchema,
        ipVersion: ipVersionSchema,
        connectionStates: connectionStatesSchema,
        logging: z.boolean().optional(),
        changes: z.record(z.string(), z.any()).optional(),
        dryRun: z.boolean().default(false),
      },
      write: true,
    },
    async (args) => {
      const existing = await getPolicy(args.policyId);
      await assertUserDefined(existing);
      let body = toWritable(existing);
      const l = await ctx.lookups();

      if (args.name !== undefined) body.name = args.name;
      if (args.description !== undefined) body.description = args.description;
      if (args.enabled !== undefined) body.enabled = args.enabled;
      if (args.logging !== undefined) body.loggingEnabled = args.logging;
      if (args.connectionStates !== undefined) {
        if (args.connectionStates.length) body.connectionStateFilter = args.connectionStates;
        else delete body.connectionStateFilter;
      }
      if (args.action !== undefined || args.allowReturnTraffic !== undefined) {
        body.action = buildAction(args.action ?? body.action.type, args.allowReturnTraffic ?? body.action.allowReturnTraffic);
      }
      if (args.sourceZone !== undefined || args.source !== undefined) {
        const zoneId = args.sourceZone ? l.zoneId(args.sourceZone) : body.source.zoneId;
        body.source = args.source ? buildEndpoint("source", zoneId, args.source as EndpointSpec, l) : { ...body.source, zoneId };
      }
      if (args.destinationZone !== undefined || args.destination !== undefined) {
        const zoneId = args.destinationZone ? l.zoneId(args.destinationZone) : body.destination.zoneId;
        body.destination = args.destination
          ? buildEndpoint("destination", zoneId, args.destination as EndpointSpec, l)
          : { ...body.destination, zoneId };
      }
      const portsUsed = [body.source, body.destination].some((side: Json) => Boolean(side?.trafficFilter?.portFilter));
      if (args.protocol !== undefined) {
        const protocol = resolveProtocol(args.protocol, [portsUsed ? { ports: [0] } : undefined]);
        const keepVersion = !["icmp", "icmpv6"].includes(protocol) ? body.ipProtocolScope?.ipVersion : undefined;
        body.ipProtocolScope = buildIpProtocolScope(protocol, args.ipVersion ?? keepVersion);
      } else {
        if (args.ipVersion !== undefined) body.ipProtocolScope = { ...body.ipProtocolScope, ipVersion: args.ipVersion };
        if (portsUsed && !body.ipProtocolScope?.protocolFilter) {
          // Port matching needs a TCP/UDP protocol; mirror the create default.
          body.ipProtocolScope = buildIpProtocolScope("tcp_udp", body.ipProtocolScope?.ipVersion);
        }
      }
      if (args.changes) body = deepMerge(body, args.changes);

      if (args.dryRun) {
        return { dryRun: true, before: await summary(existing), after: await summary({ ...existing, ...body }), request: { method: "PUT", body } };
      }
      const updated = await ctx.integration.siteRequest<Json>(`/firewall/policies/${args.policyId}`, { method: "PUT", body });
      await ctx.audit("update_firewall_policy", { id: args.policyId, before: existing, after: body });
      return { ok: true, before: await summary(existing), after: await summary(updated) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_set_firewall_policy_enabled",
    {
      title: "Enable / disable firewall policy",
      description: "Turn a user-defined firewall policy on or off without deleting it.",
      input: { policyId: z.string(), enabled: z.boolean() },
      write: true,
    },
    async ({ policyId, enabled }) => {
      const existing = await getPolicy(policyId);
      await assertUserDefined(existing);
      const body = { ...toWritable(existing), enabled };
      const updated = await ctx.integration.siteRequest<Json>(`/firewall/policies/${policyId}`, { method: "PUT", body });
      await ctx.audit("set_firewall_policy_enabled", { id: policyId, name: existing.name, enabled });
      return { ok: true, policy: await summary(updated) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_delete_firewall_policy",
    {
      title: "Delete firewall policy",
      description: "Permanently delete a user-defined firewall policy. Consider unifi_set_firewall_policy_enabled(false) if it may be needed again.",
      input: { policyId: z.string() },
      write: true,
      destructive: true,
    },
    async ({ policyId }) => {
      const existing = await getPolicy(policyId);
      await assertUserDefined(existing);
      await ctx.integration.siteRequest(`/firewall/policies/${policyId}`, { method: "DELETE" });
      // The audit log keeps the full policy so it can be recreated with rawPolicy.
      await ctx.audit("delete_firewall_policy", { id: policyId, deleted: existing });
      return { ok: true, deleted: await summary(existing), restoreWith: { rawPolicy: toWritable(existing) } };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_get_firewall_policy_order",
    {
      title: "Get firewall policy order",
      description: "Show the evaluation order of user-defined policies for one source→destination zone pair (first match wins).",
      input: { sourceZone: z.string(), destinationZone: z.string() },
    },
    async ({ sourceZone, destinationZone }) => {
      const l = await ctx.lookups();
      const query = { sourceFirewallZoneId: l.zoneId(sourceZone), destinationFirewallZoneId: l.zoneId(destinationZone) };
      const [order, all] = await Promise.all([ctx.integration.siteRequest<Json>("/firewall/policies/ordering", { query }), policies()]);
      const name = (id: string) => ({ id, name: all.find((p) => p.id === id)?.name });
      return {
        beforeSystemDefined: (order.orderedFirewallPolicyIds?.beforeSystemDefined ?? []).map(name),
        afterSystemDefined: (order.orderedFirewallPolicyIds?.afterSystemDefined ?? []).map(name),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_move_firewall_policy",
    {
      title: "Reorder firewall policy",
      description:
        "Change where a user-defined policy sits in its zone pair's evaluation order (first match wins). " +
        "top/bottom place it within the policies evaluated before the system-defined ones; before/after are relative to another policy.",
      input: {
        policyId: z.string(),
        position: z.enum(["top", "bottom", "before", "after"]),
        relativeTo: z.string().optional().describe("Policy ID, required for before/after"),
      },
      write: true,
    },
    async ({ policyId, position, relativeTo }) => {
      const result = await move(policyId, position, relativeTo);
      await ctx.audit("move_firewall_policy", { id: policyId, position, relativeTo });
      return { ok: true, ordering: result };
    },
  );
}
