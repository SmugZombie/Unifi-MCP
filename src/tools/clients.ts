import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import { buildPolicy, summarizePolicy, type Json } from "../firewall.js";
import { normalizeMac } from "../legacy.js";
import { expiryFrom, formatInZone } from "../scheduler.js";
import { movePolicy } from "./firewall.js";
import { summarizeLegacyClient } from "./network.js";

const macInput = z.string().describe("Client MAC address (any separator). Use unifi_list_clients with `search` to find it.");

const expiryInput = {
  durationMinutes: z.number().int().min(1).max(31 * 24 * 60).optional().describe("Undo automatically after this many minutes"),
  untilTime: z
    .string()
    .optional()
    .describe('Undo at the next occurrence of this wall-clock time (HH:MM, 24h) in the console\'s timezone, e.g. "06:00"'),
  until: z.string().optional().describe("Undo at this ISO 8601 time with offset, e.g. 2026-10-03T06:00:00-07:00"),
};

export function registerClientTools(server: McpServer, ctx: UnifiContext): void {
  async function describeClient(mac: string) {
    const known = (await ctx.legacy.knownClients()).find((c) => c.mac === mac);
    return known ? summarizeLegacyClient(known, false) : { mac, note: "not previously seen by the controller" };
  }

  defineTool(
    server,
    ctx,
    "unifi_block_client",
    {
      title: "Block a client",
      description:
        "Block (blacklist) a client device by MAC so it can no longer connect to the network at all (Wi-Fi or wired). Disconnects it " +
        "immediately. Optionally give an expiry (durationMinutes, untilTime or until) to unblock it automatically; otherwise it stays " +
        "blocked until unifi_unblock_client. To cut only internet access while keeping it on the LAN, use unifi_block_internet.",
      input: {
        mac: macInput,
        reason: z.string().optional().describe("Why the client is being blocked; recorded in the audit log and the client's note"),
        ...expiryInput,
      },
      write: true,
      destructive: true,
    },
    async ({ mac, reason, ...expiry }) => {
      const m = normalizeMac(mac);
      const tz = await ctx.consoleTimezone();
      const until = expiryFrom(expiry, tz);
      await ctx.legacy.block(m);
      if (reason) {
        await ctx.legacy.setClientAlias(m, undefined, `Blocked: ${reason}`).catch(() => undefined);
      }
      const client = await describeClient(m);
      let scheduled: Json | undefined;
      if (until) {
        const job = await ctx.scheduler.add({
          action: "unblock_client",
          args: { mac: m },
          label: `Unblock ${client.name ?? m}`,
          reason,
          runAt: until.toISOString(),
        });
        scheduled = { id: job.id, unblockAt: formatInZone(until, tz) };
      }
      await ctx.audit("block_client", { mac: m, reason, until: until?.toISOString() });
      return { ok: true, blocked: client, ...(scheduled ? { scheduledUnblock: scheduled } : { expires: "never" }) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_unblock_client",
    {
      title: "Unblock a client",
      description: "Remove a client from the block list so it can connect again. Use unifi_list_clients status=blocked to see blocked clients.",
      input: { mac: macInput },
      write: true,
    },
    async ({ mac }) => {
      const m = normalizeMac(mac);
      await ctx.legacy.unblock(m);
      await ctx.audit("unblock_client", { mac: m });
      return { ok: true, unblocked: await describeClient(m) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_reconnect_client",
    {
      title: "Reconnect (kick) a client",
      description: "Force a connected client to disconnect and reconnect. Does not block it.",
      input: { mac: macInput },
      write: true,
    },
    async ({ mac }) => {
      const m = normalizeMac(mac);
      await ctx.legacy.kick(m);
      await ctx.audit("reconnect_client", { mac: m });
      return { ok: true, mac: m };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_rename_client",
    {
      title: "Rename / annotate a client",
      description: "Set a friendly name and/or note on a known client, making it easier to identify later.",
      input: {
        mac: macInput,
        name: z.string().optional(),
        note: z.string().optional().describe("Empty string clears the note"),
      },
      write: true,
    },
    async ({ mac, name, note }) => {
      if (name === undefined && note === undefined) throw new Error("Provide name and/or note");
      const m = normalizeMac(mac);
      await ctx.legacy.setClientAlias(m, name, note);
      await ctx.audit("rename_client", { mac: m, name, note });
      return { ok: true, client: await describeClient(m) };
    },
  );

  /** Zone of the network a client last connected to (falls back to "Internal"). */
  async function zoneForClient(mac: string): Promise<{ zoneId: string; zoneName: string; guessed: boolean }> {
    const [known, zones, networks] = await Promise.all([ctx.legacy.knownClients(), ctx.zones(), ctx.networks()]);
    const client = known.find((c) => c.mac === mac);
    const netName = String(client?.last_connection_network_name || client?.network || "").toLowerCase();
    const net = networks.find((n) => n.name.toLowerCase() === netName);
    const zone = net ? zones.find((z) => z.networkIds.includes(net.id)) : undefined;
    if (zone) return { zoneId: zone.id, zoneName: zone.name, guessed: false };
    const internal = zones.find((z) => z.name.toLowerCase() === "internal");
    if (!internal) throw new Error(`Cannot determine the firewall zone for ${mac}; no "Internal" zone found`);
    return { zoneId: internal.id, zoneName: internal.name, guessed: true };
  }

  defineTool(
    server,
    ctx,
    "unifi_block_internet",
    {
      title: "Block internet access (timed)",
      description:
        "Cut internet access for one or more devices while they stay connected to the local network (e.g. kids' devices until 06:00). " +
        "Creates a BLOCK firewall policy per firewall zone, matching the devices' MACs toward the External zone, placed first in " +
        "order; with an expiry the policy is deleted automatically. Devices can be given by name, hostname, IP or MAC; a name that " +
        "matches several MACs (randomized addresses) blocks all of them. Expiry needs this server running at that time; a missed " +
        "expiry runs when it next starts. See unifi_list_scheduled_actions.",
      input: {
        devices: z.array(z.string()).min(1).max(20).describe("Device names, hostnames, IPs or MACs"),
        reason: z.string().optional(),
        ...expiryInput,
      },
      write: true,
      destructive: true,
    },
    async ({ devices, reason, ...expiry }) => {
      const tz = await ctx.consoleTimezone();
      const until = expiryFrom(expiry, tz);
      const nameOf = await ctx.clientNames();

      const macs = new Map<string, string>(); // mac -> requested name
      for (const d of devices) for (const mac of await ctx.resolveClientMacs(d)) macs.set(mac, d);

      const byZone = new Map<string, { zoneName: string; macs: string[]; guessed: boolean }>();
      for (const mac of macs.keys()) {
        const z = await zoneForClient(mac);
        const g = byZone.get(z.zoneId) ?? { zoneName: z.zoneName, macs: [], guessed: false };
        g.macs.push(mac);
        g.guessed ||= z.guessed;
        byZone.set(z.zoneId, g);
      }

      const lookups = await ctx.lookups();
      const label = [...new Set(devices)].join(", ");
      const created: Json[] = [];
      for (const [zoneId, g] of byZone) {
        const name = `Timed internet block: ${label}`.slice(0, 120);
        const body = buildPolicy(
          {
            name,
            description:
              `Created by unifi-mcp${reason ? `: ${reason}` : ""}. ` + (until ? `Removed automatically at ${formatInZone(until, tz)}.` : "No expiry."),
            action: "BLOCK",
            sourceZone: zoneId,
            destinationZone: "External",
            source: { macs: g.macs },
          },
          lookups,
        );
        const policy = await ctx.integration.siteRequest<Json>("/firewall/policies", { method: "POST", body });
        await movePolicy(ctx, policy.id, "top");
        let job: Json | undefined;
        if (until) {
          job = await ctx.scheduler.add({
            action: "delete_firewall_policy",
            args: { policyId: policy.id },
            label: `Remove "${name}" (${g.zoneName})`,
            reason,
            runAt: until.toISOString(),
          });
        }
        await ctx.audit("block_internet", { policyId: policy.id, macs: g.macs, zone: g.zoneName, reason, until: until?.toISOString() });
        created.push({
          policy: summarizePolicy(policy, lookups.zoneName, lookups.networkName),
          devices: g.macs.map((m) => `${nameOf(m) ?? "unnamed"} (${m})`),
          ...(g.guessed ? { note: `Zone could not be determined for some devices; assumed ${g.zoneName}` } : {}),
          ...(job ? { scheduledRemoval: job.id } : {}),
        });
      }
      return { ok: true, expires: until ? formatInZone(until, tz) : "never (delete the policy to restore access)", policies: created };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_list_scheduled_actions",
    {
      title: "List scheduled actions",
      description: "Pending automatic undos from timed blocks (unblock a client, remove a temporary firewall policy), optionally with recent history.",
      input: { includeHistory: z.boolean().default(false).describe("Also show done, failed and cancelled actions from the last 7 days") },
    },
    async ({ includeHistory }) => {
      const tz = await ctx.consoleTimezone();
      const jobs = await ctx.scheduler.list(includeHistory);
      return {
        timezone: tz,
        actions: jobs.map((j) => ({
          id: j.id,
          status: j.status,
          action: j.label,
          runAt: formatInZone(new Date(j.runAt), tz),
          reason: j.reason,
          ...(j.lastError ? { lastError: j.lastError, attempts: j.attempts } : {}),
        })),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_cancel_scheduled_action",
    {
      title: "Cancel or run a scheduled action",
      description:
        "Change a pending timed undo. runNow=true performs it immediately (e.g. lift a timed block early); runNow=false cancels it so " +
        "the block stays in place indefinitely.",
      input: { id: z.string(), runNow: z.boolean() },
      write: true,
    },
    async ({ id, runNow }) => {
      const job = await ctx.scheduler.cancel(id, runNow);
      await ctx.audit(runNow ? "run_scheduled_action_now" : "cancel_scheduled_action", { id, label: job.label });
      return { ok: true, id, status: job.status, action: job.label };
    },
  );
}
