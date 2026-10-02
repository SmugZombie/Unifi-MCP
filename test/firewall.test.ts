import assert from "node:assert/strict";
import { test } from "node:test";
import { buildPolicy, deepMerge, summarizePolicy, type Lookups } from "../src/firewall.ts";
import { isReadOnlyQuery, pageResult } from "../src/tools/network.ts";
import { pickGranularity } from "../src/tools/usage.ts";

const lookups: Lookups = {
  zoneId: (k) => ({ internal: "z-int", external: "z-ext", iot: "z-iot" })[k.toLowerCase()] ?? k,
  networkId: (k) => ({ cameras: "n-cam" })[k.toLowerCase()] ?? k,
};

test("block a MAC from the internet", () => {
  const p = buildPolicy(
    { name: "No internet for TV", action: "BLOCK", sourceZone: "Internal", destinationZone: "External", source: { macs: ["AA:BB:CC:DD:EE:FF"] } },
    lookups,
  );
  assert.deepEqual(p.action, { type: "BLOCK" });
  assert.deepEqual(p.source, { zoneId: "z-int", trafficFilter: { type: "MAC_ADDRESS", macAddressFilter: { macAddresses: ["aa:bb:cc:dd:ee:ff"] } } });
  assert.deepEqual(p.destination, { zoneId: "z-ext" });
  assert.deepEqual(p.ipProtocolScope, { ipVersion: "IPV4_AND_IPV6" });
  assert.equal(p.enabled, true);
  assert.equal(p.loggingEnabled, false);
});

test("ports default the protocol to TCP/UDP and parse ranges", () => {
  const p = buildPolicy(
    { name: "SSH", action: "ALLOW", sourceZone: "IoT", destinationZone: "Internal", destination: { ips: ["10.0.0.5", "10.0.1.0/24", "10.0.2.1-10.0.2.9"], ports: [22, "8000-8100"] } },
    lookups,
  );
  assert.deepEqual(p.action, { type: "ALLOW", allowReturnTraffic: true });
  assert.deepEqual(p.ipProtocolScope.protocolFilter, { type: "PRESET", preset: { name: "TCP_UDP" } });
  assert.deepEqual(p.destination.trafficFilter.ipAddressFilter.items, [
    { type: "IP_ADDRESS", value: "10.0.0.5" },
    { type: "SUBNET", value: "10.0.1.0/24" },
    { type: "IP_ADDRESS_RANGE", start: "10.0.2.1", stop: "10.0.2.9" },
  ]);
  assert.deepEqual(p.destination.trafficFilter.portFilter.items, [
    { type: "PORT_NUMBER", value: 22 },
    { type: "PORT_NUMBER_RANGE", start: 8000, stop: 8100 },
  ]);
});

test("ports only → PORT filter", () => {
  const p = buildPolicy({ name: "x", action: "REJECT", sourceZone: "iot", destinationZone: "external", destination: { ports: [53] }, protocol: "udp" }, lookups);
  assert.equal(p.destination.trafficFilter.type, "PORT");
  assert.equal(p.ipProtocolScope.protocolFilter.protocol.name, "UDP");
});

test("network filter with single source MAC", () => {
  const p = buildPolicy(
    { name: "x", action: "BLOCK", sourceZone: "iot", destinationZone: "internal", source: { networks: ["Cameras"], macs: ["aa:aa:aa:aa:aa:aa"], matchOpposite: true } },
    lookups,
  );
  assert.deepEqual(p.source.trafficFilter, {
    type: "NETWORK",
    networkFilter: { networkIds: ["n-cam"], matchOpposite: true },
    macAddressFilter: "aa:aa:aa:aa:aa:aa",
  });
});

test("icmp forces IPv4", () => {
  const p = buildPolicy({ name: "x", action: "BLOCK", sourceZone: "external", destinationZone: "internal", protocol: "icmp" }, lookups);
  assert.equal(p.ipProtocolScope.ipVersion, "IPV4");
  assert.throws(() => buildPolicy({ name: "x", action: "BLOCK", sourceZone: "a", destinationZone: "b", protocol: "icmp", ipVersion: "IPV6" }, lookups));
});

test("rejects invalid combinations", () => {
  const base = { name: "x", action: "BLOCK" as const, sourceZone: "a", destinationZone: "b" };
  assert.throws(() => buildPolicy({ ...base, source: { ips: ["1.1.1.1"], regions: ["CN"] } }, lookups), /only one of/);
  assert.throws(() => buildPolicy({ ...base, destination: { macs: ["aa:bb:cc:dd:ee:ff"] } }, lookups), /source/);
  assert.throws(() => buildPolicy({ ...base, destination: { ports: [22] }, protocol: "all" }, lookups), /requires protocol/);
  assert.throws(() => buildPolicy({ ...base, destination: { ports: ["ssh"] } }, lookups), /Invalid port/);
});

test("deepMerge replaces arrays and deletes nulls", () => {
  assert.deepEqual(deepMerge({ a: { b: 1, c: [1, 2] }, d: 1 }, { a: { c: [3] }, d: null }), { a: { b: 1, c: [3] } });
});

test("summarizePolicy is readable", () => {
  const p = buildPolicy(
    { name: "Geo", action: "BLOCK", sourceZone: "external", destinationZone: "internal", source: { regions: ["cn", "ru"] }, destination: { ports: [443] } },
    lookups,
  );
  const s = summarizePolicy({ ...p, id: "1", metadata: { origin: "USER_DEFINED" } }, (id) => id.replace("z-", ""), (id) => id);
  assert.equal(s.from, "ext: regions CN,RU");
  assert.equal(s.to, "int: ports 443");
  assert.equal(s.protocol, "TCP_UDP (IPV4_AND_IPV6)");
});

test("pageResult shrinks oversized pages instead of cutting JSON", () => {
  const big = Array.from({ length: 200 }, (_, i) => ({ i, blob: "x".repeat(1000) }));
  const r = pageResult(big, { offset: 0, limit: 200 }) as any;
  assert.ok(r.returned < 200 && r.returned > 0);
  assert.equal(r.nextOffset, r.returned);
  assert.match(r.note, /fields/);
  assert.ok(JSON.stringify(r.items).length <= 60_000);
  const slim = pageResult(big, { offset: 0, limit: 200, fields: ["i"] }) as any;
  assert.equal(slim.returned, 200);
  assert.equal(slim.nextOffset, undefined);
});

test("WAN report granularity selection", () => {
  assert.equal(pickGranularity(3, "auto"), "5min");
  assert.equal(pickGranularity(24, "auto"), "hourly");
  assert.equal(pickGranularity(168, "auto"), "hourly");
  assert.equal(pickGranularity(720, "auto"), "daily");
  assert.equal(pickGranularity(720, "hourly"), "hourly");
});

test("read-only POST allowlist", () => {
  assert.ok(isReadOnlyQuery("internal", "/stat/report/daily.site"));
  assert.ok(isReadOnlyQuery("internal-v2", "/traffic-flows"));
  assert.ok(!isReadOnlyQuery("internal", "/stat/report"));
  assert.ok(!isReadOnlyQuery("internal", "/stat/report/x/y"));
  assert.ok(!isReadOnlyQuery("internal", "/cmd/stamgr"));
  assert.ok(!isReadOnlyQuery("internal-v2", "/stat/report/daily.site"));
  assert.ok(!isReadOnlyQuery("official", "/v1/sites"));
});
