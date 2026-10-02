#!/usr/bin/env node
/** Connectivity check: verifies host, TLS, API key, site and internal-API access. Run with `npm run check`. */
import { loadConfig } from "./config.js";
import { UnifiContext } from "./context.js";

async function step(label: string, fn: () => Promise<string>): Promise<boolean> {
  try {
    console.log(`  ok    ${label}: ${await fn()}`);
    return true;
  } catch (err) {
    console.log(`  FAIL  ${label}: ${(err as Error).message}`);
    return false;
  }
}

const config = loadConfig();
const ctx = new UnifiContext(config);
console.log(`Checking ${config.host} (site "${config.site}")`);

let allOk = true;
if (config.apiKey) {
  allOk &&= await step("Official API / API key", async () => {
    const info = await ctx.integration.request<{ applicationVersion?: string }>("/v1/info");
    return `Network ${info.applicationVersion ?? JSON.stringify(info)}`;
  });
  allOk &&= await step("Site", async () => {
    const s = await ctx.integration.resolveSite();
    return `${s.name} (${s.internalReference}, ${s.id})`;
  });
  await step("Firewall zones", async () => `${(await ctx.zones()).map((z) => z.name).join(", ")}`);
} else {
  console.log("  skip  Official API: UNIFI_API_KEY not set (firewall, device and network tools will not work)");
}
const legacyOk = await step("Internal API (needed for blocking clients)", async () => {
  const known = await ctx.legacy.knownClients();
  return `${known.length} known clients`;
});
if (!legacyOk && !config.username) {
  console.log("        → set UNIFI_USERNAME / UNIFI_PASSWORD (local admin account) to enable block/unblock.");
}
process.exit(allOk ? 0 : 1);
