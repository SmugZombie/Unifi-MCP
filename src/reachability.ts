/**
 * Reachability evaluation for the UniFi zone-based firewall.
 *
 * Policies for a source→destination zone pair are evaluated in ascending `index` order
 * (user-defined ~10000+, system/derived ~30000+, catch-all 2147483647); the first match decides.
 * Each condition evaluates to yes / no / maybe. "maybe" means the policy applies only to part of
 * the traffic in question (specific ports, apps, domains, countries) or depends on data we don't
 * have; those are reported as conditions rather than decisions.
 */
import type { Json } from "./firewall.js";

export interface Endpoint {
  label: string;
  kind: "client" | "ip" | "internet" | "network";
  zoneId: string;
  zoneName: string;
  ip?: string;
  mac?: string;
  networkId?: string;
  networkName?: string;
  region?: string;
  domain?: string;
  /** For kind "network": the network's CIDR, e.g. 192.168.98.0/24. */
  subnet?: string;
}

export interface TrafficQuery {
  protocol?: "tcp" | "udp" | "icmp";
  port?: number;
  at: Date;
  timezone: string;
}

type Tri = { r: "yes" | "no" | "maybe"; why?: string };
const YES: Tri = { r: "yes" };
const NO: Tri = { r: "no" };
const maybe = (why: string): Tri => ({ r: "maybe", why });

function all(...parts: Tri[]): Tri {
  if (parts.some((p) => p.r === "no")) return NO;
  const m = parts.filter((p) => p.r === "maybe").map((p) => p.why);
  return m.length ? maybe(m.join("; ")) : YES;
}

// ---------- IP helpers (IPv4; IPv6 compared literally) ----------

export function ipv4ToInt(ip: string): number | undefined {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return undefined;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return undefined;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function cidrContains(cidr: string, ip: string): boolean {
  const [base, bitsStr] = cidr.split("/");
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  const b = ipv4ToInt(base);
  const i = ipv4ToInt(ip);
  if (b === undefined || i === undefined || !(bits >= 0 && bits <= 32)) return base === ip;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (b & mask) === (i & mask);
}

function inRange(start: string, stop: string, ip: string): boolean {
  const a = ipv4ToInt(start);
  const z = ipv4ToInt(stop);
  const i = ipv4ToInt(ip);
  return a !== undefined && z !== undefined && i !== undefined && i >= a && i <= z;
}

export function isPrivateIpv4(ip: string): boolean {
  return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16"].some((c) => cidrContains(c, ip));
}

// ---------- Filter matching ----------

function describeIps(f: Json): string {
  if (f?.type === "TRAFFIC_MATCHING_LIST") return "a traffic matching list";
  return (f?.items ?? []).map((i: Json) => (i.type === "IP_ADDRESS_RANGE" ? `${i.start}-${i.stop}` : i.value)).join(", ");
}

function cidrRange(cidr: string): [number, number] | undefined {
  const [base, bitsStr] = cidr.split("/");
  const b = ipv4ToInt(base);
  const bits = bitsStr === undefined ? 32 : Number(bitsStr);
  if (b === undefined || !(bits >= 0 && bits <= 32)) return undefined;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const lo = (b & mask) >>> 0;
  return [lo, (lo | (~mask >>> 0)) >>> 0];
}

/** Compare a whole subnet with an IP filter: covered entirely (yes), partly (maybe) or not at all (no). */
function matchSubnet(f: Json, subnet: string, who: string): Tri {
  const net = cidrRange(subnet);
  if (!net) return maybe(`could not compare ${who} subnet ${subnet}`);
  let partial = false;
  for (const i of f?.items ?? []) {
    let r: [number, number] | undefined;
    if (i.type === "SUBNET") r = cidrRange(i.value);
    else if (i.type === "IP_ADDRESS") r = cidrRange(`${i.value}/32`);
    else if (i.type === "IP_ADDRESS_RANGE") {
      const a = ipv4ToInt(i.start);
      const z = ipv4ToInt(i.stop);
      r = a !== undefined && z !== undefined ? [a, z] : undefined;
    }
    if (!r) continue;
    if (r[0] <= net[0] && net[1] <= r[1]) return YES;
    if (r[0] <= net[1] && net[0] <= r[1]) partial = true;
  }
  return partial ? maybe(`only for some ${who} addresses (${describeIps(f)})`) : NO;
}

function matchIps(f: Json, ip: string | undefined, who: string, subnet?: string): Tri {
  if (f?.type === "TRAFFIC_MATCHING_LIST") return maybe(`${who} IPs come from a traffic matching list`);
  if (!ip && subnet) return matchSubnet(f, subnet, who);
  if (!ip) return maybe(`only for ${who} IPs ${describeIps(f)}`);
  const hit = (f?.items ?? []).some((i: Json) =>
    i.type === "IP_ADDRESS" ? i.value === ip : i.type === "SUBNET" ? cidrContains(i.value, ip) : i.type === "IP_ADDRESS_RANGE" ? inRange(i.start, i.stop, ip) : false,
  );
  return hit ? YES : NO;
}

function describePorts(pf: Json): string {
  if (pf?.type === "TRAFFIC_MATCHING_LIST") return "a traffic matching list";
  return (pf?.items ?? []).map((i: Json) => (i.type === "PORT_NUMBER_RANGE" ? `${i.start}-${i.stop}` : String(i.value))).join(",");
}

function matchPorts(pf: Json | undefined, port: number | undefined, side: "source" | "destination"): Tri {
  if (!pf) return YES;
  if (pf.type === "TRAFFIC_MATCHING_LIST") return maybe(`${side} ports come from a traffic matching list`);
  if (side === "source") return maybe(`only for source ports ${describePorts(pf)}`);
  if (port === undefined) return maybe(`only for ports ${describePorts(pf)}`);
  const hit = (pf.items ?? []).some((i: Json) =>
    i.type === "PORT_NUMBER" ? i.value === port : i.type === "PORT_NUMBER_RANGE" ? port >= i.start && port <= i.stop : false,
  );
  return hit ? YES : NO;
}

export function matchSide(side: "source" | "destination", tf: Json | undefined, ep: Endpoint, q: TrafficQuery): Tri {
  if (!tf) return YES;
  const who = side;
  let main: Tri;
  switch (tf.type) {
    case "NETWORK": {
      const ids: string[] = tf.networkFilter?.networkIds ?? [];
      const inList = ep.networkId ? ids.includes(ep.networkId) : false;
      main = inList !== Boolean(tf.networkFilter?.matchOpposite) ? YES : NO;
      break;
    }
    case "IP_ADDRESS":
      main = matchIps(tf.ipAddressFilter, ep.ip, who, ep.subnet);
      break;
    case "MAC_ADDRESS": {
      const macs: string[] = (tf.macAddressFilter?.macAddresses ?? []).map((m: string) => m.toLowerCase());
      if (ep.kind === "network") main = maybe(`only for specific devices (${macs.join(", ")})`);
      else main = ep.mac && macs.includes(ep.mac.toLowerCase()) ? YES : NO;
      break;
    }
    case "REGION": {
      const regions: string[] = tf.regionFilter?.regions ?? [];
      if (ep.region) main = regions.includes(ep.region.toUpperCase()) ? YES : NO;
      else main = ep.kind === "internet" || (ep.ip && !isPrivateIpv4(ep.ip)) ? maybe(`only for ${who} countries ${regions.join(",")}`) : NO;
      break;
    }
    case "DOMAIN": {
      const domains: string[] = tf.domainFilter?.domains ?? [];
      if (ep.domain) {
        const d = ep.domain.toLowerCase();
        main = domains.some((x) => d === x.toLowerCase() || d.endsWith(`.${x.toLowerCase()}`)) ? YES : NO;
      } else main = ep.kind === "internet" ? maybe(`only for domains ${domains.join(", ")}`) : NO;
      break;
    }
    case "APPLICATION":
      main = maybe(`only for specific applications (DPI ids ${(tf.applicationFilter?.applicationIds ?? []).join(",")})`);
      break;
    case "APPLICATION_CATEGORY":
      main = maybe(`only for application categories (DPI ids ${(tf.applicationCategoryFilter?.applicationCategoryIds ?? []).join(",")})`);
      break;
    case "PORT":
      main = YES; // port filter evaluated below
      break;
    case "VPN_SERVER":
    case "SITE_TO_SITE_VPN_TUNNEL":
      main = ep.zoneName.toLowerCase() === "vpn" ? maybe(`only for a specific VPN (${tf.type})`) : NO;
      break;
    case "IPV6_IID":
      main = maybe("only for a specific IPv6 interface identifier");
      break;
    default:
      main = maybe(`unrecognised ${who} filter ${tf.type}`);
  }
  const mac =
    typeof tf.macAddressFilter !== "string"
      ? YES
      : ep.kind === "network"
        ? maybe(`only for device ${tf.macAddressFilter}`)
        : ep.mac && ep.mac.toLowerCase() === tf.macAddressFilter.toLowerCase()
          ? YES
          : NO;
  return all(main, mac, matchPorts(tf.portFilter, q.port, side));
}

const PROTO_NUMBERS: Record<string, number> = { tcp: 6, udp: 17, icmp: 1 };

export function matchProtocol(scope: Json | undefined, q: TrafficQuery, dstIp?: string): Tri {
  if (!scope) return YES;
  const v = scope.ipVersion;
  const isV6 = dstIp?.includes(":");
  if (dstIp && ((v === "IPV6" && !isV6) || (v === "IPV4" && isV6))) return NO;
  if (!dstIp && v === "IPV6") return maybe("only for IPv6 traffic");
  const pf = scope.protocolFilter;
  if (!pf) return YES;
  const want = q.protocol;
  let r: Tri;
  if (pf.type === "PRESET" && pf.preset?.name === "TCP_UDP") {
    r = want ? (want === "tcp" || want === "udp" ? YES : NO) : maybe("only for TCP/UDP");
    return r;
  }
  if (pf.type === "NAMED_PROTOCOL") {
    const name = String(pf.protocol?.name ?? "").toLowerCase();
    if (!want) return maybe(`only for ${pf.matchOpposite ? "protocols other than " : ""}${name.toUpperCase()}`);
    const hit = name === want || (name === "icmpv6" && want === "icmp");
    return hit !== Boolean(pf.matchOpposite) ? YES : NO;
  }
  if (pf.type === "PROTOCOL_NUMBER") {
    if (!want) return maybe(`only for protocol number ${pf.protocolNumber}`);
    return (PROTO_NUMBERS[want] === pf.protocolNumber) !== Boolean(pf.matchOpposite) ? YES : NO;
  }
  return maybe(`unrecognised protocol filter ${pf.type}`);
}

// ---------- Schedules ----------

const DAYS = ["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"];

function wallClock(at: Date, tz: string) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", weekday: "long", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
      .formatToParts(at)
      .map((p) => [p.type, p.value]),
  );
  const date = `${parts.year}-${parts.month}-${parts.day}`;
  const dayIdx = DAYS.indexOf(String(parts.weekday).toUpperCase());
  const prev = new Date(Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day) - 1)).toISOString().slice(0, 10);
  return { date, prevDate: prev, day: DAYS[dayIdx], prevDay: DAYS[(dayIdx + 6) % 7], minutes: Number(parts.hour) * 60 + Number(parts.minute) };
}

const toMin = (hhmm: string) => {
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
};

export function describeSchedule(s: Json | undefined): string {
  if (!s || s.mode === "ALWAYS") return "always";
  const t = s.timeFilter ? ` ${s.timeFilter.startTime}–${s.timeFilter.stopTime}` : " all day";
  const days = (s.repeatOnDays ?? []).map((d: string) => d.slice(0, 3).toLowerCase()).join(",");
  switch (s.mode) {
    case "EVERY_DAY":
      return `every day${t}`;
    case "EVERY_WEEK":
      return `${days}${t}`;
    case "ONE_TIME_ONLY":
      return `${s.date}${t}`;
    case "CUSTOM":
      return `${s.startDate}..${s.stopDate} ${days}${t}`;
    default:
      return String(s.mode);
  }
}

/** Is the schedule active at `at` in `tz`? Windows whose stop is before their start run past midnight. */
export function scheduleActive(s: Json | undefined, at: Date, tz: string): boolean {
  if (!s || s.mode === "ALWAYS") return true;
  const w = wallClock(at, tz);
  const start = s.timeFilter ? toMin(s.timeFilter.startTime) : 0;
  const stop = s.timeFilter ? toMin(s.timeFilter.stopTime) : 24 * 60;
  const overnight = s.timeFilter && stop <= start;
  // Does a window that started on (day, date) cover now?
  const covers = (dayOk: (day: string, date: string) => boolean): boolean => {
    if (!overnight) return dayOk(w.day, w.date) && w.minutes >= start && w.minutes < stop;
    return (dayOk(w.day, w.date) && w.minutes >= start) || (dayOk(w.prevDay, w.prevDate) && w.minutes < stop);
  };
  const days: string[] = s.repeatOnDays ?? [];
  switch (s.mode) {
    case "EVERY_DAY":
      return covers(() => true);
    case "EVERY_WEEK":
      return covers((day) => days.includes(day));
    case "ONE_TIME_ONLY":
      return covers((_d, date) => date === s.date);
    case "CUSTOM":
      return covers((day, date) => date >= s.startDate && date <= s.stopDate && (!days.length || days.includes(day)));
    default:
      return true;
  }
}

// ---------- Evaluation ----------

export interface PolicyStep {
  index: number;
  name: string;
  action: string;
  origin?: string;
  outcome: "decides" | "may apply" | "skipped" | "not matching";
  detail?: string;
}

export interface Evaluation {
  verdict: "allowed" | "blocked" | "depends";
  decidedBy?: Json;
  reason: string;
  /** Earlier, narrower policies with the opposite action: the verdict holds except for this traffic. */
  exceptions: string[];
  /** Earlier, narrower policies with the same action as the verdict. */
  conditions: string[];
  scheduleNotes: string[];
  steps: PolicyStep[];
}

const isBlock = (p: Json) => p.action?.type === "BLOCK" || p.action?.type === "REJECT";

export function evaluatePolicies(policies: Json[], src: Endpoint, dst: Endpoint, q: TrafficQuery): Evaluation {
  const ordered = policies
    .filter((p) => p.source?.zoneId === src.zoneId && p.destination?.zoneId === dst.zoneId)
    .sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
  const steps: PolicyStep[] = [];
  const partial: { block: boolean; text: string }[] = [];
  const scheduleNotes: string[] = [];
  const step = (p: Json, outcome: PolicyStep["outcome"], detail?: string) =>
    steps.push({ index: p.index, name: p.name, action: p.action?.type, origin: p.metadata?.origin, outcome, ...(detail ? { detail } : {}) });

  for (const p of ordered) {
    if (!p.enabled) {
      step(p, "skipped", "disabled");
      continue;
    }
    const states: string[] | undefined = p.connectionStateFilter;
    if (states?.length && !states.includes("NEW")) {
      step(p, "skipped", `only ${states.join("/")} connections (return traffic), not new ones`);
      continue;
    }
    if (p.ipsecFilter === "MATCH_ENCRYPTED") {
      step(p, "skipped", "only IPsec-encrypted traffic");
      continue;
    }
    const match = all(
      matchSide("source", p.source?.trafficFilter, src, q),
      matchSide("destination", p.destination?.trafficFilter, dst, q),
      matchProtocol(p.ipProtocolScope, q, dst.ip),
    );
    if (match.r === "no") {
      step(p, "not matching");
      continue;
    }
    const active = scheduleActive(p.schedule, q.at, q.timezone);
    if (!active) {
      scheduleNotes.push(`"${p.name}" (${p.action?.type}) ${match.r === "maybe" ? `may apply (${match.why}) ` : "applies "}on schedule ${describeSchedule(p.schedule)}; inactive at the time checked`);
      step(p, "skipped", `schedule inactive (${describeSchedule(p.schedule)})`);
      continue;
    }
    if (match.r === "maybe") {
      partial.push({ block: isBlock(p), text: `"${p.name}" ${isBlock(p) ? "blocks" : "allows"} this ${match.why}` });
      step(p, "may apply", match.why);
      continue;
    }
    step(p, "decides", p.schedule && p.schedule.mode !== "ALWAYS" ? `schedule active (${describeSchedule(p.schedule)})` : undefined);
    const blocked = isBlock(p);
    const exceptions = partial.filter((x) => x.block !== blocked).map((x) => x.text);
    return {
      verdict: blocked ? "blocked" : "allowed",
      decidedBy: p,
      reason:
        `${blocked ? "Blocked" : "Allowed"} by "${p.name}" (${p.metadata?.origin === "USER_DEFINED" ? "user policy" : "system policy"}, order ${p.index})` +
        (exceptions.length ? `, except for the traffic listed under exceptions` : ""),
      exceptions,
      conditions: partial.filter((x) => x.block === blocked).map((x) => x.text),
      scheduleNotes,
      steps,
    };
  }
  return {
    verdict: "depends",
    reason: `No policy for ${src.zoneName} → ${dst.zoneName} fully matches; the outcome depends on the conditional policies listed`,
    exceptions: [],
    conditions: partial.map((x) => x.text),
    scheduleNotes,
    steps,
  };
}
