import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { defineTool, type UnifiContext } from "../context.js";
import { normalizeMac } from "../legacy.js";
import { summarizeLegacyClient } from "./network.js";

const macInput = z.string().describe("Client MAC address (any separator). Use unifi_list_clients with `search` to find it.");

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
        "Block (blacklist) a client device by MAC so it can no longer connect to the network (WiFi or wired). Disconnects it immediately. Reversible with unifi_unblock_client.",
      input: {
        mac: macInput,
        reason: z.string().optional().describe("Why the client is being blocked; recorded in the audit log and the client's note"),
      },
      write: true,
      destructive: true,
    },
    async ({ mac, reason }) => {
      const m = normalizeMac(mac);
      await ctx.legacy.block(m);
      if (reason) {
        await ctx.legacy.setClientAlias(m, undefined, `Blocked: ${reason}`).catch(() => undefined);
      }
      await ctx.audit("block_client", { mac: m, reason });
      return { ok: true, blocked: await describeClient(m) };
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
}
