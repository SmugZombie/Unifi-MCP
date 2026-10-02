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
  { _id: "u2", mac: "aa:bb:cc:dd:ee:02", name: "Alex iPhone", oui: "Apple", ip: "10.0.0.15", essid: "Home", "tx_bytes-r": 125000, "rx_bytes-r": 12500, tx_bytes: 5e8, rx_bytes: 2e7, uptime: 3600 },
  { _id: "u3", mac: "aa:bb:cc:dd:ee:03", name: "NAS", oui: "Synology", ip: "10.0.0.5", is_wired: true, "wired-tx_bytes-r": 250000, "wired-rx_bytes-r": 1000, "wired-tx_bytes": 1e9, "wired-rx_bytes": 1e6, uptime: 7200 },
];
const requests: string[] = [];
let lastFlowQuery: any;
const flow = {
  id: "f1", time: 1790928000000, action: "blocked", direction: "outgoing", risk: "low", protocol: "TCP", service: "HTTPS", count: 1,
  source: { ip: "10.0.0.5", port: 50000, mac: "aa:bb:cc:dd:ee:03" },
  destination: { ip: "203.0.113.9", port: 443, region: "CN", zone_name: "External", domains: ["example.cn"] },
  policies: [{ id: "x", type: "FIREWALL" }], traffic_data: { bytes_rx: 100 },
};

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
    if (sub === "/stat/sta") return env([users[1], users[2]]);
    if (sub === "/cmd/stamgr") {
      if (b.cmd === "block-sta") blocked.add(b.mac);
      if (b.cmd === "unblock-sta") blocked.delete(b.mac);
      return env([]);
    }
    if (sub.startsWith("/rest/user/")) return env([]);
    return json(404, { meta: { rc: "error", msg: "not found" } });
  }
  if (p.startsWith("/proxy/network/v2/api/site/default/")) {
    if (req.headers.cookie !== "TOKEN=sess123") return json(401, {});
    const sub = p.slice("/proxy/network/v2/api/site/default".length);
    if (sub === "/traffic-flows" && req.method === "POST") {
      lastFlowQuery = b;
      return json(200, { data: [flow], has_next: true, page_number: b.pageNumber, total_element_count: 120, total_page_count: 3 });
    }
    if (sub === "/clients/active") return json(200, [{ mac: "aa:bb:cc:dd:ee:02", idletime: 3 }, { mac: "aa:bb:cc:dd:ee:03", idletime: 0 }]);
    if (sub === "/traffic-flows/f1") return json(200, { ...flow, flow_start_time: 1790927990000 });
    if (sub === "/traffic-flow-latest-statistics") {
      return json(200, {
        blocked_count_by_risk: { low: 4 },
        top_all_traffic_by_application: [{ application_id: 112, category_id: 4, bytes: 7e9 }],
        top_all_count_by_client: [{ count: 9, client_mac: "aa:bb:cc:dd:ee:03", client_name: null, icon_filename: "x.png" }],
      });
    }
    return json(404, {});
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
  if (ip === "/v1/dpi/applications") return page([{ id: (4 << 16) | 112, name: "Youtube" }, { id: 112, name: "Wrong app" }]);
  if (ip === "/v1/dpi/categories") return page([{ id: 4, name: "Media streaming services" }]);
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

test("client traffic: rates, sorting and full details", async () => {
  const r = await call("unifi_list_clients", { sortBy: "traffic" });
  assert.deepEqual(r.clients.map((c: any) => c.name), ["NAS", "Alex iPhone"]);
  // tx is traffic sent to the client (its download); wired clients use the wired- counters.
  assert.deepEqual(r.clients[0].traffic, { downKbps: 2000, upKbps: 8, totalDownMB: 1000, totalUpMB: 1 });
  assert.deepEqual(r.clients[1].traffic, { downKbps: 1000, upKbps: 100, totalDownMB: 500, totalUpMB: 20 });
  assert.equal(r.clients[1].uptimeSec, 3600);

  const p1 = await call("unifi_list_clients", { status: "all", limit: 2 });
  assert.equal(p1.total, 3);
  assert.equal(p1.nextOffset, 2);
  const p2 = await call("unifi_list_clients", { status: "all", limit: 2, offset: p1.nextOffset });
  assert.equal(p2.returned, 1);
  assert.equal(p2.nextOffset, undefined);

  const d = await call("unifi_get_client", { mac: "AA:BB:CC:DD:EE:02" });
  assert.equal(d.record["tx_bytes-r"], 125000);
  assert.equal(d.summary.online, true);
  await assert.rejects(call("unifi_get_client", { mac: "00:00:00:00:00:99" }), /No client/);
});

test("traffic flows: query body, client resolution, summaries", async () => {
  const r = await call("unifi_list_flows", { client: "nas", lastMinutes: 30, destinationPort: [443], risk: ["low"], page: 1, pageSize: 10 });
  assert.deepEqual(lastFlowQuery.action, ["allowed", "blocked"], "default must request both, the controller defaults to blocked only");
  assert.deepEqual(lastFlowQuery.source_mac, ["aa:bb:cc:dd:ee:03"]);
  assert.deepEqual(lastFlowQuery.destination_port, [443]);
  assert.deepEqual(lastFlowQuery.risk, ["low"]);
  assert.equal(lastFlowQuery.pageNumber, 1);
  assert.equal(lastFlowQuery.timestampTo - lastFlowQuery.timestampFrom, 30 * 60_000);
  assert.equal(r.total, 120);
  assert.equal(r.nextPage, 2);
  assert.equal(r.flows[0].from, "NAS 10.0.0.5:50000");
  assert.equal(r.flows[0].to, "203.0.113.9:443 (example.cn) CN");

  await call("unifi_list_flows", { action: "blocked" });
  assert.deepEqual(lastFlowQuery.action, ["blocked"]);
  assert.equal(lastFlowQuery.source_mac, undefined);
  await assert.rejects(call("unifi_list_flows", { client: "nonexistent" }), /No client matches/);

  const d = await call("unifi_get_flow", { flowId: "f1" });
  assert.equal(d.flow.flow_start_time, 1790927990000);
  await assert.rejects(call("unifi_get_flow", { flowId: "../x" }), /Invalid flow id/);

  const st = await call("unifi_flow_statistics", { period: "WEEK", top: 3 });
  assert.equal(st.top_all_traffic_by_application[0].application, "Youtube", "app id must combine category << 16");
  assert.equal(st.top_all_traffic_by_application[0].category, "Media streaming services");
  assert.equal(st.top_all_count_by_client[0].client, "NAS");
  assert.equal(st.top_all_count_by_client[0].icon_filename, undefined);
  assert.ok(requests.includes("GET /proxy/network/v2/api/site/default/traffic-flow-latest-statistics"));
});

test("path traversal is refused before any request is sent", async () => {
  const before = requests.length;
  await assert.rejects(call("unifi_api_get", { api: "internal", path: "/../../../v2/api/site/default/clients/active" }), /Invalid API path/);
  await assert.rejects(call("unifi_api_get", { api: "internal", path: "/stat/%2e%2e/%2e%2e/%2e%2e/%2e%2e/api/users" }), /Invalid API path/);
  await assert.rejects(call("unifi_api_get", { api: "official", path: "/v1/../../../api/users" }), /Invalid API path/);
  await assert.rejects(call("unifi_get_device", { deviceId: "../../../../api/users" }), /Invalid API path/);
  await assert.rejects(call("unifi_get_firewall_policy", { policyId: "..%2f..%2f..%2fapi" }), /Invalid API path/);
  assert.equal(requests.slice(before).filter((r) => r.includes("/api/users") || !r.includes("/v1/sites")).length, 0, "nothing escaped to the console");
});

test("raw GET supports v2 endpoints that return bare arrays", async () => {
  const r = await call("unifi_api_get", { api: "internal-v2", path: "/clients/active", fields: ["mac", "idletime"] });
  assert.equal(r.total, 2);
  assert.deepEqual(r.items[0], { mac: "aa:bb:cc:dd:ee:02", idletime: 3 });
});

test("raw GET pages and projects list responses", async () => {
  const p = await call("unifi_api_get", { api: "internal", path: "/rest/user", fields: ["mac", "oui"], limit: 2 });
  assert.equal(p.total, 3);
  assert.equal(p.returned, 2);
  assert.equal(p.nextOffset, 2);
  assert.deepEqual(p.items[0], { mac: "aa:bb:cc:dd:ee:01", oui: "Samsung" });
  const m = await call("unifi_api_get", { api: "internal", path: "/rest/user", match: "synology" });
  assert.equal(m.total, 1);
  assert.equal(m.nextOffset, undefined);
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
