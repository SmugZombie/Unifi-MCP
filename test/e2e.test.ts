/**
 * End-to-end: runs the built MCP server over stdio against a fake UniFi console.
 * The fake rejects the API key on the internal API to exercise the session-login fallback.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

const SITE = "11111111-1111-1111-1111-111111111111";
const zones = [
  { id: "z-int", name: "Internal", networkIds: ["n-lan"], metadata: { origin: "SYSTEM_DEFINED" } },
  { id: "z-ext", name: "External", networkIds: [], metadata: { origin: "SYSTEM_DEFINED" } },
  { id: "z-iot", name: "IoT", networkIds: ["n-iot"], metadata: { origin: "USER_DEFINED" } },
];
const networks = [{ id: "n-lan", name: "Default" }, { id: "n-iot", name: "IoT VLAN", vlanId: 30 }];
const policies: any[] = [
  { id: "p-sys", index: 1, name: "Allow All Traffic", enabled: true, action: { type: "ALLOW", allowReturnTraffic: false }, source: { zoneId: "z-int" }, destination: { zoneId: "z-ext" }, ipProtocolScope: { ipVersion: "IPV4_AND_IPV6" }, loggingEnabled: false, metadata: { origin: "SYSTEM_DEFINED" } },
];
let ordering: string[] = [];
const blocked = new Set<string>();
const users = [
  { _id: "u1", mac: "aa:bb:cc:dd:ee:01", hostname: "living-room-tv", oui: "Samsung", last_ip: "10.0.30.20", blocked: false },
  { _id: "u2", mac: "aa:bb:cc:dd:ee:02", name: "Alex iPhone", oui: "Apple", ip: "10.0.0.15", essid: "Home" },
];
const requests: string[] = [];

async function body(req: IncomingMessage) {
  let s = "";
  for await (const c of req) s += c;
  return s ? JSON.parse(s) : undefined;
}

const fake = createServer(async (req, res) => {
  const url = new URL(req.url!, "http://x");
  const p = url.pathname;
  requests.push(`${req.method} ${p}`);
  const json = (status: number, data: unknown, headers: Record<string, string | string[]> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(data));
  };
  const page = (data: unknown[]) => json(200, { offset: 0, limit: 200, count: data.length, totalCount: data.length, data });
  const b = await body(req);

  if (p === "/api/auth/login") {
    if (b.username === "admin" && b.password === "pw") return json(200, {}, { "set-cookie": ["TOKEN=sess123; Path=/; HttpOnly"], "x-csrf-token": "csrf1" });
    return json(401, { message: "bad creds" });
  }
  if (p.startsWith("/proxy/network/api/s/default/")) {
    if (req.headers.cookie !== "TOKEN=sess123") return json(401, { meta: { rc: "error", msg: "api.err.LoginRequired" } });
    if (req.method !== "GET" && req.headers["x-csrf-token"] !== "csrf1") return json(403, { meta: { rc: "error", msg: "csrf" } });
    const sub = p.slice("/proxy/network/api/s/default".length);
    const env = (data: unknown[]) => json(200, { meta: { rc: "ok" }, data });
    if (sub === "/rest/user") return env(users.map((u) => ({ ...u, blocked: blocked.has(u.mac) })));
    if (sub === "/stat/sta") return env([users[1]]);
    if (sub === "/cmd/stamgr") {
      if (b.cmd === "block-sta") blocked.add(b.mac);
      if (b.cmd === "unblock-sta") blocked.delete(b.mac);
      return env([]);
    }
    if (sub.startsWith("/rest/user/")) return env([]);
    return json(404, { meta: { rc: "error", msg: "not found" } });
  }
  if (!p.startsWith("/proxy/network/integration/")) return json(404, {});
  if (req.headers["x-api-key"] !== "key123") return json(401, { message: "Unauthorized" });
  const ip = p.slice("/proxy/network/integration".length);
  const s = `/v1/sites/${SITE}`;
  if (ip === "/v1/info") return json(200, { applicationVersion: "10.6.106" });
  if (ip === "/v1/sites") return page([{ id: SITE, internalReference: "default", name: "Default" }]);
  if (ip === `${s}/firewall/zones`) return page(zones);
  if (ip === `${s}/networks`) return page(networks);
  if (ip === `${s}/devices`) return page([{ id: "d1", name: "UDM", state: "ONLINE", firmwareUpdatable: false }]);
  if (ip === `${s}/clients`) return page([{ id: "c1", name: "Alex iPhone" }]);
  if (ip === `${s}/wans`) return page([]);
  if (ip === `${s}/firewall/policies` && req.method === "GET") return page(policies);
  if (ip === `${s}/firewall/policies` && req.method === "POST") {
    const created = { ...b, id: `p-${policies.length}`, index: 100 + policies.length, metadata: { origin: "USER_DEFINED" } };
    policies.push(created);
    ordering.push(created.id);
    return json(201, created);
  }
  if (ip === `${s}/firewall/policies/ordering`) {
    if (req.method === "PUT") ordering = b.orderedFirewallPolicyIds.beforeSystemDefined;
    return json(200, { orderedFirewallPolicyIds: { beforeSystemDefined: ordering, afterSystemDefined: [] } });
  }
  const m = ip.match(new RegExp(`^${s}/firewall/policies/([^/]+)$`));
  if (m) {
    const i = policies.findIndex((x) => x.id === m[1]);
    if (i < 0) return json(404, { message: "not found" });
    if (req.method === "GET") return json(200, policies[i]);
    if (req.method === "PUT") {
      assert.equal(b.id, undefined, "PUT body must not contain read-only id");
      policies[i] = { ...b, id: policies[i].id, index: policies[i].index, metadata: policies[i].metadata };
      return json(200, policies[i]);
    }
    if (req.method === "DELETE") {
      policies.splice(i, 1);
      return json(200, {});
    }
  }
  json(404, { message: `no route ${ip}` });
});

let client: Client;
let httpChild: ChildProcess | undefined;
const auditLog = join(mkdtempSync(join(tmpdir(), "unifi-mcp-")), "audit.log");
const TOKEN = "t".repeat(32);
const HTTP_PORT = 39000 + Math.floor(Math.random() * 1000);

function serverEnv(): Record<string, string> {
  return {
    PATH: process.env.PATH!,
    UNIFI_HOST: `http://127.0.0.1:${(fake.address() as { port: number }).port}`,
    UNIFI_API_KEY: "key123",
    UNIFI_USERNAME: "admin",
    UNIFI_PASSWORD: "pw",
    UNIFI_AUDIT_LOG: auditLog,
  };
}

before(async () => {
  await new Promise<void>((r) => fake.listen(0, "127.0.0.1", r));
  client = new Client({ name: "test", version: "1" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ["dist/index.js"], env: serverEnv() }));
});

after(async () => {
  await client?.close();
  httpChild?.kill();
  fake.close();
});

async function call(name: string, args: Record<string, unknown> = {}) {
  const r: any = await client.callTool({ name, arguments: args });
  const text = r.content[0].text;
  if (r.isError) throw new Error(text);
  return JSON.parse(text);
}

test("lists tools", async () => {
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  for (const n of ["unifi_get_overview", "unifi_block_client", "unifi_create_firewall_policy", "unifi_delete_firewall_policy"]) assert.ok(names.includes(n), n);
  assert.equal(tools.find((t) => t.name === "unifi_block_client")!.annotations?.destructiveHint, true);
});

test("overview", async () => {
  const o = await call("unifi_get_overview");
  assert.equal(o.application.applicationVersion, "10.6.106");
  assert.equal(o.connectedClients, 1);
});

test("search clients and block/unblock via session fallback", async () => {
  const found = await call("unifi_list_clients", { status: "all", search: "tv" });
  assert.equal(found.total, 1);
  assert.equal(found.clients[0].mac, "aa:bb:cc:dd:ee:01");
  assert.equal(found.clients[0].online, false);

  await call("unifi_block_client", { mac: "AA-BB-CC-DD-EE-01", reason: "unknown device" });
  const b = await call("unifi_list_clients", { status: "blocked" });
  assert.deepEqual(b.clients.map((c: any) => c.mac), ["aa:bb:cc:dd:ee:01"]);

  await call("unifi_unblock_client", { mac: "aa:bb:cc:dd:ee:01" });
  assert.equal((await call("unifi_list_clients", { status: "blocked" })).total, 0);
  assert.ok(requests.includes("POST /api/auth/login"));
});

test("firewall policy lifecycle by zone/network names", async () => {
  const dry = await call("unifi_create_firewall_policy", {
    name: "IoT to LAN", action: "BLOCK", sourceZone: "IoT", destinationZone: "internal", source: { networks: ["IoT VLAN"] }, dryRun: true,
  });
  assert.equal(dry.request.body.source.trafficFilter.networkFilter.networkIds[0], "n-iot");
  assert.equal(policies.length, 1, "dry run must not create");

  const created = await call("unifi_create_firewall_policy", {
    name: "IoT to LAN", action: "BLOCK", sourceZone: "IoT", destinationZone: "Internal", destination: { ports: [22, 443] }, position: "top",
  });
  const id = created.policy.id;
  assert.equal(created.summary.to, "Internal: ports 22,443");

  const list = await call("unifi_list_firewall_policies", { sourceZone: "IoT" });
  assert.equal(list.shown, 1);

  const upd = await call("unifi_update_firewall_policy", { policyId: id, action: "REJECT", logging: true });
  assert.equal(upd.after.action, "REJECT");
  assert.equal(upd.after.logging, true);

  await call("unifi_set_firewall_policy_enabled", { policyId: id, enabled: false });
  assert.equal(policies.find((p) => p.id === id).enabled, false);

  await assert.rejects(call("unifi_update_firewall_policy", { policyId: "p-sys", enabled: false }), /SYSTEM_DEFINED/);

  const del = await call("unifi_delete_firewall_policy", { policyId: id });
  assert.equal(del.restoreWith.rawPolicy.name, "IoT to LAN");
  assert.equal(policies.length, 1);

  const audit = readFileSync(auditLog, "utf8").trim().split("\n").map((l) => JSON.parse(l).action);
  assert.deepEqual(audit.slice(-4), ["create_firewall_policy", "update_firewall_policy", "set_firewall_policy_enabled", "delete_firewall_policy"]);
});

test("unknown zone gives a helpful error", async () => {
  await assert.rejects(call("unifi_list_firewall_policies", { sourceZone: "Nope" }), /Known zones: Internal, External, IoT/);
});

test("HTTP transport: health, auth, origin and tool calls", async () => {
  httpChild = spawn(process.execPath, ["dist/index.js"], {
    env: { ...serverEnv(), MCP_TRANSPORT: "http", MCP_PORT: String(HTTP_PORT), MCP_AUTH_TOKEN: TOKEN },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let log = "";
  httpChild.stderr!.on("data", (d) => (log += d));
  while (!log.includes("listening")) await once(httpChild.stderr!, "data");

  const base = `http://127.0.0.1:${HTTP_PORT}`;
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  const init = { jsonrpc: "2.0", id: 1, method: "tools/list" };
  const post = (headers: Record<string, string>) =>
    fetch(`${base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(init) });
  assert.equal((await post({})).status, 401);
  assert.equal((await post({ authorization: "Bearer wrong" })).status, 401);
  assert.equal((await post({ authorization: `Bearer ${TOKEN}`, origin: "http://evil.example" })).status, 403);

  const http = new Client({ name: "http-test", version: "1" });
  await http.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }));
  const { tools } = await http.listTools();
  assert.ok(tools.some((t) => t.name === "unifi_block_client"));
  const r: any = await http.callTool({ name: "unifi_list_firewall_zones", arguments: {} });
  assert.deepEqual(JSON.parse(r.content[0].text).map((z: any) => z.name), ["Internal", "External", "IoT"]);
  await http.close();
});

test("HTTP transport refuses to start without a strong token", async () => {
  const child = spawn(process.execPath, ["dist/index.js"], { env: { ...serverEnv(), MCP_TRANSPORT: "http", MCP_AUTH_TOKEN: "short" }, stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  child.stderr!.on("data", (d) => (err += d));
  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(err, /MCP_AUTH_TOKEN/);
});
