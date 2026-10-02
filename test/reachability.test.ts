import assert from "node:assert/strict";
import { test } from "node:test";
import { cidrContains, evaluatePolicies, scheduleActive, type Endpoint, type TrafficQuery } from "../src/reachability.ts";

const TZ = "America/Phoenix"; // UTC-7, no DST
const at = (local: string) => new Date(`${local}-07:00`); // 2026-10-04 is a Sunday
const q = (o: Partial<TrafficQuery> = {}): TrafficQuery => ({ at: at("2026-10-02T12:00:00"), timezone: TZ, ...o });

const INT = "z-int";
const EXT = "z-ext";
const laptop: Endpoint = { label: "laptop", kind: "client", zoneId: INT, zoneName: "Internal", ip: "192.168.98.6", mac: "aa:aa:aa:aa:aa:01", networkId: "n-peach", networkName: "Peach" };
const mario: Endpoint = { label: "network Mario", kind: "network", zoneId: INT, zoneName: "Internal", networkId: "n-mario", networkName: "Mario", subnet: "192.168.100.0/24" };
const bowser: Endpoint = { label: "network Bowser", kind: "network", zoneId: INT, zoneName: "Internal", networkId: "n-bowser", networkName: "Bowser", subnet: "192.168.104.0/24" };
const peach: Endpoint = { label: "network Peach", kind: "network", zoneId: INT, zoneName: "Internal", networkId: "n-peach", networkName: "Peach", subnet: "192.168.98.0/24" };
const internet: Endpoint = { label: "the internet", kind: "internet", zoneId: EXT, zoneName: "External" };

let seq = 0;
const policy = (o: Record<string, any>) => ({
  id: `p${++seq}`,
  enabled: true,
  metadata: { origin: "USER_DEFINED" },
  ipProtocolScope: { ipVersion: "IPV4_AND_IPV6" },
  source: { zoneId: INT },
  destination: { zoneId: INT },
  ...o,
});
const allowAll = policy({ index: 2147483647, name: "Allow All Traffic", action: { type: "ALLOW" }, metadata: { origin: "SYSTEM_DEFINED" } });
const net = (ids: string[], matchOpposite = false) => ({ type: "NETWORK", networkFilter: { networkIds: ids, matchOpposite } });
const ips = (...items: any[]) => ({ type: "IP_ADDRESS", ipAddressFilter: { type: "IP_ADDRESSES", items } });

test("cidr helpers", () => {
  assert.ok(cidrContains("192.168.98.0/24", "192.168.98.200"));
  assert.ok(!cidrContains("192.168.98.0/24", "192.168.99.1"));
  assert.ok(cidrContains("0.0.0.0/0", "8.8.8.8"));
  assert.ok(cidrContains("10.0.0.5/32", "10.0.0.5"));
});

test("first fully matching policy decides; disabled and return-only policies are skipped", () => {
  const pols = [
    allowAll,
    policy({ index: 10001, name: "Off rule", enabled: false, action: { type: "BLOCK" }, source: { zoneId: INT, trafficFilter: net(["n-bowser"]) } }),
    policy({ index: 30000, name: "Return", action: { type: "ALLOW" }, connectionStateFilter: ["RELATED", "ESTABLISHED"], metadata: { origin: "DERIVED" } }),
    policy({ index: 10002, name: "Peach to Mario", action: { type: "BLOCK" }, source: { zoneId: INT, trafficFilter: net(["n-peach"]) }, destination: { zoneId: INT, trafficFilter: net(["n-mario"]) } }),
  ];
  const r = evaluatePolicies(pols, peach, mario, q());
  assert.equal(r.verdict, "blocked");
  assert.equal(r.decidedBy?.name, "Peach to Mario");
  assert.deepEqual(r.steps.map((s) => s.outcome), ["skipped", "decides"], "index order: 10001 (off) then 10002; 30000 never reached");
  assert.equal(evaluatePolicies(pols, bowser, mario, q()).decidedBy?.name, "Allow All Traffic");
});

test("subnet-based rules against whole networks: full cover, partial, none", () => {
  const isolated = policy({ index: 30004, name: "Isolated Networks", action: { type: "BLOCK" }, metadata: { origin: "SYSTEM_DEFINED" }, source: { zoneId: INT, trafficFilter: ips({ type: "SUBNET", value: "192.168.98.0/24" }) } });
  const pihole = policy({
    index: 10000,
    name: "Peach to PiHole",
    action: { type: "ALLOW", allowReturnTraffic: true },
    source: { zoneId: INT, trafficFilter: net(["n-peach"]) },
    destination: { zoneId: INT, trafficFilter: { ...ips({ type: "IP_ADDRESS", value: "192.168.104.53" }), portFilter: { type: "PORTS", items: [{ type: "PORT_NUMBER", value: 53 }] } } },
  });
  const pols = [pihole, isolated, allowAll];
  const r = evaluatePolicies(pols, peach, bowser, q());
  assert.equal(r.verdict, "blocked");
  assert.equal(r.decidedBy?.name, "Isolated Networks");
  assert.equal(r.exceptions.length, 1);
  assert.match(r.exceptions[0], /Peach to PiHole.*allows.*192\.168\.104\.53.*ports 53/);

  const dns = evaluatePolicies(pols, peach, { ...bowser, kind: "ip", ip: "192.168.104.53", subnet: undefined }, q({ port: 53, protocol: "udp" }));
  assert.equal(dns.verdict, "allowed");
  assert.equal(dns.decidedBy?.name, "Peach to PiHole");
  assert.equal(evaluatePolicies(pols, peach, { ...bowser, kind: "ip", ip: "192.168.104.53", subnet: undefined }, q({ port: 443, protocol: "tcp" })).decidedBy?.name, "Isolated Networks");
  assert.equal(evaluatePolicies(pols, bowser, mario, q()).decidedBy?.name, "Allow All Traffic", "Bowser subnet not covered by the isolation rule");
});

test("matchOpposite networks and MAC rules", () => {
  const notMario = policy({ index: 10000, name: "Only Mario allowed", action: { type: "BLOCK" }, source: { zoneId: INT, trafficFilter: net(["n-mario"], true) } });
  assert.equal(evaluatePolicies([notMario, allowAll], peach, bowser, q()).verdict, "blocked");
  assert.equal(evaluatePolicies([notMario, allowAll], mario, bowser, q()).verdict, "allowed");

  const macBlock = policy({ index: 10000, name: "Laptop off", action: { type: "BLOCK" }, destination: { zoneId: EXT }, source: { zoneId: INT, trafficFilter: { type: "MAC_ADDRESS", macAddressFilter: { macAddresses: ["AA:AA:AA:AA:AA:01"] } } } });
  const extAllow = { ...allowAll, destination: { zoneId: EXT } };
  assert.equal(evaluatePolicies([macBlock, extAllow], laptop, internet, q()).verdict, "blocked");
  const whole = evaluatePolicies([macBlock, extAllow], peach, internet, q());
  assert.equal(whole.verdict, "allowed");
  assert.match(whole.exceptions[0], /only for specific devices/);
});

test("overnight weekly schedules", () => {
  const s = { mode: "EVERY_WEEK", repeatOnDays: ["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY"], timeFilter: { startTime: "23:45", stopTime: "06:00" } };
  assert.ok(scheduleActive(s, at("2026-10-04T23:50:00"), TZ), "Sunday 23:50");
  assert.ok(scheduleActive(s, at("2026-10-05T02:00:00"), TZ), "Monday 02:00 belongs to Sunday's window");
  assert.ok(scheduleActive(s, at("2026-10-02T02:00:00"), TZ), "Friday 02:00 belongs to Thursday's window");
  assert.ok(!scheduleActive(s, at("2026-10-03T02:00:00"), TZ), "Saturday 02:00: Friday has no window");
  assert.ok(!scheduleActive(s, at("2026-10-05T06:00:00"), TZ), "stop time is exclusive");
  assert.ok(!scheduleActive(s, at("2026-10-05T12:00:00"), TZ));
  assert.ok(scheduleActive({ mode: "EVERY_DAY", timeFilter: { startTime: "03:00", stopTime: "03:30" } }, at("2026-10-05T03:10:00"), TZ));
  assert.ok(scheduleActive({ mode: "EVERY_WEEK", repeatOnDays: ["SATURDAY"] }, at("2026-10-03T15:00:00"), TZ), "no timeFilter = all day");
  assert.ok(scheduleActive({ mode: "ONE_TIME_ONLY", date: "2026-10-03", timeFilter: { startTime: "22:00", stopTime: "02:00" } }, at("2026-10-04T01:00:00"), TZ));

  const bedtime = policy({ index: 10000, name: "Bedtime", action: { type: "BLOCK" }, destination: { zoneId: EXT }, schedule: s, source: { zoneId: INT, trafficFilter: { type: "MAC_ADDRESS", macAddressFilter: { macAddresses: [laptop.mac] } } } });
  const extAllow = { ...allowAll, destination: { zoneId: EXT } };
  const night = evaluatePolicies([bedtime, extAllow], laptop, internet, q({ at: at("2026-10-05T01:00:00") }));
  assert.equal(night.verdict, "blocked");
  const noon = evaluatePolicies([bedtime, extAllow], laptop, internet, q({ at: at("2026-10-05T12:00:00") }));
  assert.equal(noon.verdict, "allowed");
  assert.match(noon.scheduleNotes[0], /Bedtime.*sun,mon,tue,wed,thu 23:45–06:00/);
});

test("protocol and port matching, and 'depends' when nothing fully matches", () => {
  const ssh = policy({ index: 10000, name: "No SSH", action: { type: "BLOCK" }, ipProtocolScope: { ipVersion: "IPV4", protocolFilter: { type: "NAMED_PROTOCOL", matchOpposite: false, protocol: { name: "TCP" } } }, destination: { zoneId: INT, trafficFilter: { type: "PORT", portFilter: { type: "PORTS", items: [{ type: "PORT_NUMBER", value: 22 }] } } } });
  const pols = [ssh, allowAll];
  assert.equal(evaluatePolicies(pols, peach, mario, q({ protocol: "tcp", port: 22 })).verdict, "blocked");
  assert.equal(evaluatePolicies(pols, peach, mario, q({ protocol: "udp", port: 22 })).verdict, "allowed");
  assert.equal(evaluatePolicies(pols, peach, mario, q({ protocol: "tcp", port: 80 })).verdict, "allowed");
  const vague = evaluatePolicies(pols, peach, mario, q());
  assert.equal(vague.verdict, "allowed");
  assert.match(vague.exceptions[0], /No SSH.*only for ports 22.*only for TCP/);

  const appOnly = policy({ index: 10000, name: "Block VPN apps", action: { type: "BLOCK" }, destination: { zoneId: EXT, trafficFilter: { type: "APPLICATION_CATEGORY", applicationCategoryFilter: { applicationCategoryIds: [11] } } } });
  const d = evaluatePolicies([appOnly], laptop, internet, q());
  assert.equal(d.verdict, "depends");
  assert.match(d.conditions[0], /application categories/);
});
