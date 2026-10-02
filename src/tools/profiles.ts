import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import { planProfileChanges, type DeviceProfile, type ProfileRef } from "../profiles.js";

interface Named {
  _id: string;
  name: string;
  purpose?: string;
}

function describeProfile(p: DeviceProfile) {
  return {
    id: p.id,
    name: p.name,
    enabled: p.enabled,
    hostnames: p.hostnames,
    network: p.network?.name,
    speedGroup: p.speedGroup?.name,
    reconnect: p.reconnect,
  };
}

export function registerProfileTools(server: McpServer, ctx: UnifiContext): void {
  async function resolve(kind: string, path: string, key: string, usable: (n: Named) => boolean = () => true): Promise<ProfileRef> {
    const items = (await ctx.legacy.request<Named>(path)).filter(usable);
    const k = key.trim().toLowerCase();
    const hit = items.find((i) => i._id === key) ?? items.find((i) => i.name.toLowerCase() === k);
    if (!hit) throw new Error(`Unknown ${kind} "${key}". Known ${kind}s: ${items.map((i) => i.name).join(", ")}`);
    return { id: hit._id, name: hit.name };
  }

  defineTool(
    server,
    ctx,
    "unifi_list_device_profiles",
    {
      title: "List device profiles",
      description:
        "Device profiles and the watcher that enforces them. A profile recognises a device by hostname, whatever MAC address it " +
        "uses, and keeps it on a chosen Wi-Fi network and speed-limit group; the watcher re-checks connected clients on a timer and " +
        "fixes any that rejoined under a new (randomized) MAC. Shows recent changes it made.",
      input: {},
    },
    async () => ({
      watcher: {
        running: !ctx.config.readOnly,
        intervalSec: Math.round(ctx.watcher.intervalMs / 1000),
        lastRunAt: ctx.watcher.lastRunAt,
        ...(ctx.watcher.lastError ? { lastError: ctx.watcher.lastError } : {}),
      },
      profiles: (await ctx.profiles.list()).map(describeProfile),
      recentChanges: (await ctx.profiles.events()).slice(-20).reverse(),
    }),
  );

  defineTool(
    server,
    ctx,
    "unifi_set_device_profile",
    {
      title: "Create or update a device profile",
      description:
        "Keep a device on a given Wi-Fi network and/or speed-limit group even when it rejoins under a new MAC address. The device is " +
        "recognised by hostname (exact, case-insensitive), so it stops working if the device is renamed. Saving a profile with an " +
        "existing name replaces it. The watcher applies it at its next check (see unifi_list_device_profiles for the interval); call " +
        "unifi_run_device_profiles to apply immediately. The result lists connected clients that would change. Use dryRun=true to " +
        "preview without saving. Never create a profile for the gateway, switches, APs or the machine this server runs on.",
      input: {
        name: z.string().min(1).max(60).describe('Profile name, e.g. "Kids PC"; also used to name newly seen MACs'),
        hostnames: z.array(z.string().min(3)).min(1).max(10).describe("Hostnames that identify the device, as shown by unifi_list_clients"),
        network: z.string().optional().describe("Network to force the device onto (Wi-Fi network override), by name"),
        speedGroup: z.string().optional().describe("Speed-limit group (client group) to assign, by name"),
        reconnect: z.boolean().default(true).describe("Disconnect the device after changing its network so the change takes effect"),
        enabled: z.boolean().default(true),
        dryRun: z.boolean().default(false),
      },
      write: true,
    },
    async ({ name, hostnames, network, speedGroup, reconnect, enabled, dryRun }) => {
      if (!network && !speedGroup) throw new Error("Give a network and/or a speedGroup for the profile to enforce");
      const draft = {
        name: name.trim(),
        hostnames: [...new Set(hostnames.map((h) => h.trim()))],
        network: network ? await resolve("network", "/rest/networkconf", network, (n) => n.purpose !== "wan") : undefined,
        speedGroup: speedGroup ? await resolve("speed group", "/rest/usergroup", speedGroup) : undefined,
        reconnect,
        enabled,
      };
      const saved: DeviceProfile = dryRun ? { ...draft, id: "(dry run)", createdAt: new Date().toISOString() } : await ctx.profiles.upsert(draft);
      if (!dryRun) await ctx.audit("set_device_profile", describeProfile(saved));
      const [active, known] = await Promise.all([ctx.legacy.activeClients(), ctx.legacy.knownClients()]);
      const pending = planProfileChanges([{ ...saved, enabled: true }], active, known);
      return {
        ok: true,
        dryRun,
        profile: describeProfile(saved),
        wouldChangeNow: pending.map((c) => ({ mac: c.mac, hostname: c.hostname, changes: c.changes, reconnect: c.reconnect })),
        appliesWithinSec: dryRun || !enabled ? undefined : Math.round(ctx.watcher.intervalMs / 1000),
      };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_delete_device_profile",
    {
      title: "Delete a device profile",
      description: "Stop enforcing a device profile. Settings already applied to clients are left in place.",
      input: { profile: z.string().describe("Profile name or id") },
      write: true,
    },
    async ({ profile }) => {
      const gone = await ctx.profiles.remove(profile);
      await ctx.audit("delete_device_profile", describeProfile(gone));
      return { ok: true, deleted: describeProfile(gone) };
    },
  );

  defineTool(
    server,
    ctx,
    "unifi_run_device_profiles",
    {
      title: "Apply device profiles now",
      description:
        "Run the device-profile check immediately instead of waiting for the timer: finds connected clients that match a profile but " +
        "lack its network or speed group, fixes them and reconnects them if needed. dryRun=true only reports what would change.",
      input: { dryRun: z.boolean().default(false) },
      write: true,
    },
    async ({ dryRun }) => ctx.watcher.run(dryRun),
  );
}
