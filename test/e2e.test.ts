/**
 * End-to-end: runs the built MCP server over stdio against a fake UniFi console.
 * The fake rejects the API key on the internal API to exercise the session-login fallback.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
  { id: "z-gw", name: "Gateway", networkIds: [], metadata: { origin: "SYSTEM_DEFINED" } },
];
const networks = [{ id: "n-lan", name: "Default", zoneId: "z-int" }, { id: "n-iot", name: "IoT VLAN", vlanId: 30, zoneId: "z-iot" }];
const networkconf = [
  { _id: "c1", name: "Default", purpose: "corporate", ip_subnet: "10.0.0.1/24" },
  { _id: "c2", name: "IoT VLAN", purpose: "corporate", ip_subnet: "10.0.30.1/24" },
  { _id: "c3", name: "Internet 1", purpose: "wan" },
];
let homeSsidIsolated = false;
const sys = (id: string, src: string, dst: string, action: string, extra: any = {}) => ({
  id, index: 2147483647, name: `${action === "BLOCK" ? "Block" : "Allow"} All Traffic`, enabled: true, action: { type: action },
  source: { zoneId: src }, destination: { zoneId: dst }, ipProtocolScope: { ipVersion: "IPV4_AND_IPV6" }, loggingEnabled: false,
  metadata: { origin: "SYSTEM_DEFINED" }, ...extra,
});
const policies: any[] = [
  { id: "p-sys", index: 2147483647, name: "Allow All Traffic", enabled: true, action: { type: "ALLOW", allowReturnTraffic: false }, source: { zoneId: "z-int" }, destination: { zoneId: "z-ext" }, ipProtocolScope: { ipVersion: "IPV4_AND_IPV6" }, loggingEnabled: false, metadata: { origin: "SYSTEM_DEFINED" } },
  sys("p-sys-iot-int", "z-iot", "z-int", "BLOCK"),
  sys("p-sys-iot-int-ret", "z-iot", "z-int", "ALLOW", { index: 30000, name: "Allow Return Traffic", connectionStateFilter: ["RELATED", "ESTABLISHED"] }),
  sys("p-sys-int-iot", "z-int", "z-iot", "ALLOW"),
  sys("p-sys-iot-ext", "z-iot", "z-ext", "ALLOW"),
  sys("p-sys-int-gw", "z-int", "z-gw", "ALLOW"),
];
let ordering: string[] = [];
let policySeq = 0;
const blocked = new Set<string>();
const users = [
  { _id: "u1", mac: "aa:bb:cc:dd:ee:01", hostname: "living-room-tv", oui: "Samsung", last_ip: "10.0.30.20", blocked: false, last_connection_network_name: "IoT VLAN" },
  { _id: "u2", mac: "aa:bb:cc:dd:ee:02", name: "Alex iPhone", oui: "Apple", ip: "10.0.0.15", essid: "Home", network: "Default", idletime: 12, "tx_bytes-r": 125000, "rx_bytes-r": 12500, tx_bytes: 5e8, rx_bytes: 2e7, uptime: 3600 },
  { _id: "u3", mac: "aa:bb:cc:dd:ee:03", name: "NAS", oui: "Synology", ip: "10.0.0.5", fixed_ip: "10.0.0.5", use_fixedip: true, network: "Default", is_wired: true, "wired-tx_bytes-r": 250000, "wired-rx_bytes-r": 1000, "wired-tx_bytes": 1e9, "wired-rx_bytes": 1e6, uptime: 7200 },
];
const requests: string[] = [];
let lastFlowQuery: any;
let lastReportQuery: any;
let flowPagesServed = 0;
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
    if (sub === "/stat/sysinfo") return env([{ timezone: "America/Phoenix" }]);
    if (sub === "/rest/networkconf") return env(networkconf);
    if (sub === "/rest/wlanconf") return env([{ _id: "w1", name: "Home", l2_isolation: homeSsidIsolated }]);
    if (sub === "/rest/portforward") {
      return env([
        { _id: "pf1", name: "NAS web", enabled: true, proto: "tcp", dst_port: "8443", fwd: "10.0.0.5", fwd_port: "443", pfwd_interface: "wan", src: "any", src_limiting_enabled: false, log: false },
        { _id: "pf2", name: "Game", enabled: false, proto: "udp", dst_port: "3074", fwd: "10.0.0.99", fwd_port: "", pfwd_interface: "both", src: "203.0.113.0/24", src_limiting_enabled: true, destination_ip: "" },
      ]);
    }
    if (sub === "/stat/health") {
      return env([
        { subsystem: "wan", status: "ok", wan_ip: "203.0.113.2", isp_name: "Example ISP", gateways: ["203.0.113.1"], nameservers: ["1.1.1.1"], gw_name: "UDM", gw_version: "4.0", "gw_system-stats": { cpu: "12.5", mem: "60.1", uptime: "1000" },
          uptime_stats: { WAN: { availability: 99.5, latency_average: 20, uptime: 900, time_period: 1000,
            alerting_monitors: [{ type: "icmp", target: "ping.ui.com", availability: 100, latency_average: 15 }],
            monitors: [{ type: "icmp", target: "1.1.1.1", availability: 98, latency_average: 30 }] } } },
        { subsystem: "www", status: "ok", latency: 21, drops: 2, uptime: 5000, xput_down: 900, xput_up: 40, speedtest_status: "Success", speedtest_lastrun: 1790900000, speedtest_ping: 12, "rx_bytes-r": 1250000, "tx_bytes-r": 125000 },
        { subsystem: "lan", status: "ok", num_user: 10 },
        { subsystem: "wlan", status: "ok", num_user: 20, num_guest: 1 },
      ]);
    }
    if (sub === "/stat/report/hourly.site" && req.method === "POST") {
      lastReportQuery = b;
      const t0 = Math.floor(b.start / 3600000) * 3600000;
      return env([
        { time: t0, "wan-rx_bytes": 450e6, "wan-tx_bytes": 45e6, num_sta: 40 },
        { time: t0 + 3600000, "wan-rx_bytes": 900e6, "wan-tx_bytes": 90e6, num_sta: 42 },
      ]);
    }
    return json(404, { meta: { rc: "error", msg: "not found" } });
  }
  if (p.startsWith("/proxy/network/v2/api/site/default/")) {
    if (req.headers.cookie !== "TOKEN=sess123") return json(401, {});
    const sub = p.slice("/proxy/network/v2/api/site/default".length);
    if (sub === "/traffic-flows" && req.method === "POST") {
      lastFlowQuery = b;
      flowPagesServed++;
      const second = { ...flow, id: "f2", source: { ip: "198.51.100.7", port: 1234, region: "NL" }, destination: { ...flow.destination, port: 22 }, count: 3 };
      return json(200, { data: b.pageSize >= 1000 ? [flow, second] : [flow], has_next: b.pageNumber < 2, page_number: b.pageNumber, total_element_count: b.pageSize >= 1000 ? 6 : 120, total_page_count: 3 });
    }
    if (sub === "/traffic") {
      const app = (category: number, application: number, rx: number, tx: number) => ({ category, application, bytes_received: rx, bytes_transmitted: tx, total_bytes: rx + tx, activity_seconds: 600 });
      return json(200, {
        total_usage_by_app: [
          { ...app(4, 112, 8e9, 1e8), client_count: 2 },
          { ...app(1, 2, 2e9, 5e8), client_count: 1 },
        ],
        client_usage_by_app: [
          { client: { mac: "aa:bb:cc:dd:ee:02", name: "Alex iPhone", oui: "Apple" }, usage_by_app: [app(4, 112, 3e9, 5e7)] },
          { client: { mac: "aa:bb:cc:dd:ee:03", hostname: "nas", oui: "Synology", is_wired: true }, usage_by_app: [app(4, 112, 5e9, 5e7), app(1, 2, 2e9, 5e8)] },
        ],
      });
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
  if (ip === "/v1/dpi/applications") return page([{ id: (4 << 16) | 112, name: "Youtube" }, { id: 112, name: "Wrong app" }, { id: (1 << 16) | 2, name: "BitTorrent Series" }]);
  if (ip === "/v1/dpi/categories") return page([{ id: 4, name: "Media streaming services" }, { id: 1, name: "Peer-to-peer networks" }]);
  if (ip === `${s}/firewall/policies` && req.method === "GET") return page(policies);
  if (ip === `${s}/firewall/policies` && req.method === "POST") {
    // Unique ids, like the real controller (ids must not be reused after deletes).
    const created = { ...b, id: `p-${++policySeq}`, index: 100 + policySeq, metadata: { origin: "USER_DEFINED" } };
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
    UNIFI_STATE_FILE: join(dirname(auditLog), "scheduled.json"),
    UNIFI_SCHEDULER_INTERVAL_MS: "200",
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
  assert.equal(r.clients[1].idleSec, 12);
  assert.equal(r.clients[0].idleSec, undefined, "wired clients report no idle time");

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

test("usage: traffic by app and client, DPI lookup, WAN report", async () => {
  const apps = await call("unifi_traffic_by_app", { lastDays: 7 });
  assert.deepEqual(apps.apps.map((a: any) => a.app), ["Youtube", "BitTorrent Series"]);
  assert.equal(apps.apps[0].downMB, 8000);
  assert.equal(apps.apps[0].share, "76.4%", "8.1 GB of 10.6 GB");

  const torrent = await call("unifi_traffic_by_app", { lastDays: 30, app: "torrent" });
  assert.deepEqual(torrent.apps.map((a: any) => a.app), ["BitTorrent Series"]);
  assert.deepEqual(torrent.apps[0].topClients.map((c: any) => c.name), ["NAS"]);

  const clients = await call("unifi_traffic_by_app", { view: "clients" });
  assert.deepEqual(clients.clients.map((c: any) => c.name), ["NAS", "Alex iPhone"], "hostname-only clients get their known name");
  const one = await call("unifi_traffic_by_app", { client: "Alex iPhone" });
  assert.equal(one.clients.length, 1);
  assert.equal(one.clients[0].topApps[0].app, "Youtube");

  const lookup = await call("unifi_lookup_dpi", { query: "torrent", ids: [{ category: 4, application: 112 }] });
  assert.equal(lookup.results[0].name, "Youtube");
  assert.ok(lookup.results.some((r: any) => r.name === "BitTorrent Series" && r.category === 1 && r.application === 2));

  const wan = await call("unifi_wan_usage", { lastHours: 48 });
  assert.equal(wan.granularity, "hourly");
  assert.deepEqual(lastReportQuery.attrs.slice(0, 2), ["wan-rx_bytes", "wan-tx_bytes"]);
  assert.equal(lastReportQuery.end - lastReportQuery.start, 48 * 3_600_000);
  assert.deepEqual(wan.totals, { downGB: 1.35, upGB: 0.14 });
  assert.equal(wan.peakInterval.down.mbps, 2, "900 MB in an hour = 2 Mbps");
  assert.equal(wan.rows.length, 2);
  await assert.rejects(call("unifi_wan_usage", { lastHours: 48, granularity: "5min" }), /only covers/);
});

test("raw API POST is limited to read-only query endpoints", async () => {
  const ok = await call("unifi_api_get", { api: "internal", path: "/stat/report/hourly.site", body: { attrs: ["wan-rx_bytes"], start: 0, end: 7200000 } });
  assert.equal(ok.total, 2);
  for (const [api, path] of [["internal", "/cmd/stamgr"], ["internal", "/rest/user"], ["internal-v2", "/traffic-flows/f1"], ["official", "/v1/sites"]]) {
    await assert.rejects(call("unifi_api_get", { api, path, body: { cmd: "block-sta" } }), /only allowed for read-only/, `${api} ${path}`);
  }
  assert.ok(!blocked.size, "nothing was blocked");
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
  const initialCount = policies.length;
  const dry = await call("unifi_create_firewall_policy", {
    name: "IoT to LAN", action: "BLOCK", sourceZone: "IoT", destinationZone: "internal", source: { networks: ["IoT VLAN"] }, dryRun: true,
  });
  assert.equal(dry.request.body.source.trafficFilter.networkFilter.networkIds[0], "n-iot");
  assert.equal(policies.length, initialCount, "dry run must not create");

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
  assert.equal(policies.length, initialCount);

  const audit = readFileSync(auditLog, "utf8").trim().split("\n").map((l) => JSON.parse(l).action);
  assert.deepEqual(audit.slice(-4), ["create_firewall_policy", "update_firewall_policy", "set_firewall_policy_enabled", "delete_firewall_policy"]);
});

test("unknown zone gives a helpful error", async () => {
  await assert.rejects(call("unifi_list_firewall_policies", { sourceZone: "Nope" }), /Known zones: Internal, External, IoT, Gateway/);
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
  assert.deepEqual(JSON.parse(r.content[0].text).map((z: any) => z.name), ["Internal", "External", "IoT", "Gateway"]);
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

async function waitFor(check: () => boolean, ms = 5000) {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) {
      let state = "";
      try {
        state = readFileSync(join(dirname(auditLog), "scheduled.json"), "utf8");
      } catch {}
      throw new Error(`timed out waiting; scheduler state: ${state}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
}

test("flow top-N groups across pages", async () => {
  flowPagesServed = 0;
  const r = await call("unifi_flow_top", { action: "blocked", direction: ["incoming"], groupBy: "destinationPort", thenBy: "sourceRegion" });
  assert.equal(flowPagesServed, 3, "follows has_next across pages");
  assert.equal(r.flowsGrouped, 6);
  assert.equal(r.sampled, false);
  // f2 has count 3 per page, f1 count 1: port 22 = 9 flows, port 443 = 3.
  assert.deepEqual(r.top.map((g: any) => [g.destinationPort, g.flows]), [["22", 9], ["443", 3]]);
  assert.deepEqual(r.top[0].sourceRegion, ["NL (9)"]);
  assert.deepEqual(lastFlowQuery.direction, ["incoming"]);
  const byClient = await call("unifi_flow_top", { groupBy: "client", maxFlows: 1000 });
  assert.deepEqual(
    byClient.top.map((g: any) => [g.client, g.flows]),
    [["(unknown)", 9], ["NAS (aa:bb:cc:dd:ee:03)", 3]],
    "flows without a source MAC (inbound) group as (unknown); local MACs get their names",
  );
});

test("port forwards and WAN health", async () => {
  const pf = await call("unifi_list_port_forwards");
  assert.equal(pf.count, 2);
  assert.deepEqual(pf.rules[0], { id: "pf1", name: "NAS web", enabled: true, protocol: "tcp", wanPort: "8443", forwardTo: "10.0.0.5:443", device: "NAS", wanInterface: "wan", wanAddress: "any", allowedSources: "any" });
  assert.equal(pf.rules[1].forwardTo, "10.0.0.99:3074", "empty fwd_port means same as WAN port");
  assert.equal(pf.rules[1].allowedSources, "203.0.113.0/24");

  const h = await call("unifi_wan_health");
  assert.equal(h.isp.name, "Example ISP");
  assert.deepEqual(h.throughputNowMbps, { down: 10, up: 1 });
  assert.equal(h.lastSpeedTest.downMbps, 900);
  assert.equal(h.gatewayDevice.cpuPct, 12.5);
  assert.deepEqual(h.perWan[0].degradedMonitors, ["icmp 1.1.1.1: 98% avail, 30 ms"], "alerting monitors at 100% are not degraded");
});

test("timed client block is lifted automatically", async () => {
  const until = new Date(Date.now() + 1200).toISOString();
  const r = await call("unifi_block_client", { mac: "aa:bb:cc:dd:ee:01", until, reason: "homework" });
  assert.ok(r.scheduledUnblock.id);
  assert.match(r.scheduledUnblock.unblockAt, /America\/Phoenix/);
  assert.ok(blocked.has("aa:bb:cc:dd:ee:01"));
  await waitFor(() => !blocked.has("aa:bb:cc:dd:ee:01"));
  // The job is marked done just after the unblock call returns; poll for the saved status.
  const stateFile = join(dirname(auditLog), "scheduled.json");
  const jobStatus = () => (JSON.parse(readFileSync(stateFile, "utf8")) as any[]).find((j) => j.id === r.scheduledUnblock.id)?.status;
  await waitFor(() => jobStatus() === "done");
  const hist = await call("unifi_list_scheduled_actions", { includeHistory: true });
  assert.equal(hist.actions.find((a: any) => a.id === r.scheduledUnblock.id).status, "done");
  await assert.rejects(call("unifi_block_client", { mac: "aa:bb:cc:dd:ee:01", until: "2020-01-01T00:00:00Z" }), /past/);
});

test("timed internet block creates per-zone policies and removes them", async () => {
  const start = policies.length;
  const r = await call("unifi_block_internet", { devices: ["living-room-tv", "NAS"], durationMinutes: 60, reason: "bedtime" });
  assert.equal(r.policies.length, 2, "one policy per zone (IoT and Internal)");
  assert.equal(policies.length, start + 2);
  const zonesUsed = policies.slice(start).map((p) => p.source.zoneId).sort();
  assert.deepEqual(zonesUsed, ["z-int", "z-iot"]);
  for (const p of policies.slice(start)) {
    assert.equal(p.action.type, "BLOCK");
    assert.equal(p.destination.zoneId, "z-ext");
    assert.equal(p.source.trafficFilter.type, "MAC_ADDRESS");
  }
  assert.equal(ordering[0], policies[start + 1].id, "placed first in order");

  const pending = await call("unifi_list_scheduled_actions");
  const mine = pending.actions.filter((a: any) => a.reason === "bedtime");
  assert.equal(mine.length, 2);
  // Lift one early, keep the other indefinitely.
  await call("unifi_cancel_scheduled_action", { id: mine[0].id, runNow: true });
  await call("unifi_cancel_scheduled_action", { id: mine[1].id, runNow: false });
  assert.equal(policies.length, start + 1);
  assert.equal((await call("unifi_list_scheduled_actions")).actions.filter((a: any) => a.reason === "bedtime").length, 0);

  // Short expiry removes the policy on its own.
  const before = policies.length;
  await call("unifi_block_internet", { devices: ["aa:bb:cc:dd:ee:02"], until: new Date(Date.now() + 1200).toISOString() });
  assert.equal(policies.length, before + 1);
  await waitFor(() => policies.length === before);
  const audit = readFileSync(auditLog, "utf8");
  assert.match(audit, /"action":"scheduled_delete_firewall_policy"/);
  assert.match(audit, /"action":"scheduled_unblock_client"/);
});

test("reachability: zones, policy order, ports, blocked clients, same network, isolation", async () => {
  // IoT -> Internal hits the system catch-all BLOCK (return-traffic rule is skipped for new connections).
  let r = await call("unifi_check_reachability", { from: "living-room-tv", to: "NAS", port: 22, protocol: "tcp" });
  assert.equal(r.source.zone, "IoT");
  assert.equal(r.destination.zone, "Internal");
  assert.equal(r.verdict, "blocked");
  assert.equal(r.decidingPolicy.name, "Block All Traffic");
  assert.equal(r.evaluated.steps[0].outcome, "skipped");

  // A user exception for Home Assistant on 8123.
  const created = await call("unifi_create_firewall_policy", {
    name: "TV to HA", action: "ALLOW", sourceZone: "IoT", destinationZone: "Internal", destination: { ips: ["10.0.0.5"], ports: [8123] }, protocol: "tcp",
  });
  try {
    r = await call("unifi_check_reachability", { from: "aa:bb:cc:dd:ee:01", to: "10.0.0.5", port: 8123, protocol: "tcp" });
    assert.equal(r.source.name, "living-room-tv", "MAC input resolves to the client, not an IPv6 address");
    assert.equal(r.verdict, "allowed");
    assert.equal(r.decidingPolicy.name, "TV to HA");
    r = await call("unifi_check_reachability", { from: "IoT VLAN", to: "NAS" });
    assert.equal(r.source.subnet, "10.0.30.0/24");
    assert.equal(r.verdict, "blocked");
    assert.match(r.exceptions[0], /TV to HA.*allows.*ports 8123/);
  } finally {
    await call("unifi_delete_firewall_policy", { policyId: created.policy.id });
  }

  // Gateway address and the internet.
  r = await call("unifi_check_reachability", { from: "NAS", to: "10.0.0.1" });
  assert.equal(r.destination.zone, "Gateway");
  assert.equal(r.verdict, "allowed");
  r = await call("unifi_check_reachability", { from: "NAS", to: "example.org" });
  assert.equal(r.destination.zone, "External");
  assert.equal(r.destination.domain, "example.org");

  // Same network: switched, not routed — unless Wi-Fi client isolation is on.
  r = await call("unifi_check_reachability", { from: "Alex iPhone", to: "NAS" });
  assert.equal(r.verdict, "allowed");
  assert.match(r.reason, /switched locally/);
  homeSsidIsolated = true;
  try {
    r = await call("unifi_check_reachability", { from: "Alex iPhone", to: "NAS" });
    assert.equal(r.verdict, "blocked");
    assert.match(r.reason, /client isolation.*Home/);
  } finally {
    homeSsidIsolated = false;
  }

  // Blocked clients cannot reach anything.
  await call("unifi_block_client", { mac: "aa:bb:cc:dd:ee:03" });
  try {
    r = await call("unifi_check_reachability", { from: "NAS", to: "internet" });
    assert.equal(r.verdict, "blocked");
    assert.match(r.reason, /blocked from the network/);
  } finally {
    await call("unifi_unblock_client", { mac: "aa:bb:cc:dd:ee:03" });
  }
  await assert.rejects(call("unifi_check_reachability", { from: "NAS", to: "172.31.9.9" }), /not in any configured network/);
});
