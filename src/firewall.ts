/**
 * Helpers for the zone-based firewall policy schema of the UniFi Network API (10.x).
 * See docs/unifi-network-api-10.6.106.yaml, schema CreateOrUpdateFirewallPolicy.
 */

// The API schema is deeply discriminated; policies are handled as plain JSON here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = Record<string, any>;

export type Protocol = "all" | "tcp" | "udp" | "tcp_udp" | "icmp" | "icmpv6";
export type IpVersion = "IPV4" | "IPV6" | "IPV4_AND_IPV6";

export interface EndpointSpec {
  ips?: string[];
  networks?: string[];
  macs?: string[];
  domains?: string[];
  regions?: string[];
  ports?: (number | string)[];
  matchOpposite?: boolean;
}

export interface Lookups {
  zoneId(nameOrId: string): string;
  networkId(nameOrId: string): string;
}

export interface SimplePolicySpec {
  name: string;
  description?: string;
  enabled?: boolean;
  action: "ALLOW" | "BLOCK" | "REJECT";
  allowReturnTraffic?: boolean;
  sourceZone: string;
  destinationZone: string;
  source?: EndpointSpec;
  destination?: EndpointSpec;
  protocol?: Protocol;
  ipVersion?: IpVersion;
  connectionStates?: ("NEW" | "INVALID" | "ESTABLISHED" | "RELATED")[];
  logging?: boolean;
  schedule?: Json;
}

function parsePorts(ports: (number | string)[]): Json {
  const items = ports.map((p) => {
    const s = String(p).trim();
    const range = s.match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) return { type: "PORT_NUMBER_RANGE", start: Number(range[1]), stop: Number(range[2]) };
    if (!/^\d+$/.test(s)) throw new Error(`Invalid port "${p}" (use 443 or 8000-8100)`);
    return { type: "PORT_NUMBER", value: Number(s) };
  });
  return { type: "PORTS", items };
}

function parseIps(ips: string[]): Json {
  const items = ips.map((raw) => {
    const s = raw.trim();
    const range = s.split(/\s*-\s*/);
    if (range.length === 2 && !s.includes("/")) return { type: "IP_ADDRESS_RANGE", start: range[0], stop: range[1] };
    if (s.includes("/")) return { type: "SUBNET", value: s };
    return { type: "IP_ADDRESS", value: s };
  });
  return { type: "IP_ADDRESSES", items };
}

const nonEmpty = (a?: unknown[]) => Array.isArray(a) && a.length > 0;

export function buildEndpoint(side: "source" | "destination", zoneId: string, spec: EndpointSpec | undefined, lookups: Lookups): Json {
  const out: Json = { zoneId };
  if (!spec) return out;

  const primaries = (["ips", "networks", "domains", "regions"] as const).filter((k) => nonEmpty(spec[k]));
  if (primaries.length > 1) {
    throw new Error(`${side}: only one of ips, networks, domains, regions may be set per policy (got ${primaries.join(", ")}). Create separate policies instead.`);
  }
  if (side === "source" && nonEmpty(spec.domains)) throw new Error("source: domains can only be matched on the destination");
  if (side === "destination" && nonEmpty(spec.macs)) throw new Error("destination: MAC addresses can only be matched on the source");

  const portFilter = nonEmpty(spec.ports) ? parsePorts(spec.ports!) : undefined;
  const primary = primaries[0];
  let filter: Json | undefined;

  switch (primary) {
    case "ips":
      filter = { type: "IP_ADDRESS", ipAddressFilter: parseIps(spec.ips!) };
      break;
    case "networks":
      filter = {
        type: "NETWORK",
        networkFilter: { networkIds: spec.networks!.map((n) => lookups.networkId(n)), matchOpposite: spec.matchOpposite ?? false },
      };
      break;
    case "domains":
      filter = { type: "DOMAIN", domainFilter: { type: "DOMAINS", domains: spec.domains } };
      break;
    case "regions":
      filter = { type: "REGION", regionFilter: { regions: spec.regions!.map((r) => r.toUpperCase()) } };
      break;
  }

  if (nonEmpty(spec.macs)) {
    const macs = spec.macs!.map((m) => m.toLowerCase());
    if (!filter) {
      filter = { type: "MAC_ADDRESS", macAddressFilter: { macAddresses: macs } };
    } else if (primary === "ips" || primary === "networks") {
      if (macs.length > 1) throw new Error("source: only a single MAC can be combined with ips/networks");
      filter.macAddressFilter = macs[0];
    } else {
      throw new Error(`source: MACs cannot be combined with ${primary}`);
    }
  }

  if (portFilter) {
    filter = filter ? { ...filter, portFilter } : { type: "PORT", portFilter };
  }
  if (filter) out.trafficFilter = filter;
  return out;
}

export function buildIpProtocolScope(protocol: Protocol, ipVersion?: IpVersion): Json {
  let version: IpVersion = ipVersion ?? "IPV4_AND_IPV6";
  if (protocol === "icmp") {
    if (ipVersion && ipVersion !== "IPV4") throw new Error("protocol icmp requires ipVersion IPV4 (use icmpv6 for IPv6)");
    version = "IPV4";
  }
  if (protocol === "icmpv6") {
    if (ipVersion && ipVersion !== "IPV6") throw new Error("protocol icmpv6 requires ipVersion IPV6");
    version = "IPV6";
  }
  const scope: Json = { ipVersion: version };
  const named = (name: string) => ({ type: "NAMED_PROTOCOL", matchOpposite: false, protocol: { name } });
  switch (protocol) {
    case "tcp":
      scope.protocolFilter = named("TCP");
      break;
    case "udp":
      scope.protocolFilter = named("UDP");
      break;
    case "tcp_udp":
      scope.protocolFilter = { type: "PRESET", preset: { name: "TCP_UDP" } };
      break;
    case "icmp":
      scope.protocolFilter = named("ICMP");
      break;
    case "icmpv6":
      scope.protocolFilter = named("ICMPV6");
      break;
  }
  return scope;
}

function hasPorts(spec?: EndpointSpec) {
  return nonEmpty(spec?.ports);
}

export function resolveProtocol(protocol: Protocol | undefined, specs: (EndpointSpec | undefined)[]): Protocol {
  const ports = specs.some(hasPorts);
  const p = protocol ?? (ports ? "tcp_udp" : "all");
  if (ports && !["tcp", "udp", "tcp_udp"].includes(p)) {
    throw new Error(`Port matching requires protocol tcp, udp or tcp_udp (got ${p})`);
  }
  return p;
}

export function buildAction(action: SimplePolicySpec["action"], allowReturnTraffic?: boolean): Json {
  return action === "ALLOW" ? { type: "ALLOW", allowReturnTraffic: allowReturnTraffic ?? true } : { type: action };
}

export function buildPolicy(spec: SimplePolicySpec, lookups: Lookups): Json {
  const protocol = resolveProtocol(spec.protocol, [spec.source, spec.destination]);
  const policy: Json = {
    name: spec.name,
    enabled: spec.enabled ?? true,
    action: buildAction(spec.action, spec.allowReturnTraffic),
    source: buildEndpoint("source", lookups.zoneId(spec.sourceZone), spec.source, lookups),
    destination: buildEndpoint("destination", lookups.zoneId(spec.destinationZone), spec.destination, lookups),
    ipProtocolScope: buildIpProtocolScope(protocol, spec.ipVersion),
    loggingEnabled: spec.logging ?? false,
  };
  if (spec.description) policy.description = spec.description;
  if (spec.connectionStates?.length) policy.connectionStateFilter = spec.connectionStates;
  if (spec.schedule) policy.schedule = spec.schedule;
  return policy;
}

/** Fields returned by GET that must not be sent back on PUT. */
export function toWritable(policy: Json): Json {
  const { id: _id, index: _index, metadata: _metadata, ...rest } = policy;
  return rest;
}

/** Recursive merge where arrays and primitives in `patch` replace those in `base`; null deletes a key. */
export function deepMerge(base: Json, patch: Json): Json {
  const out: Json = { ...base };
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete out[k];
    else if (typeof v === "object" && !Array.isArray(v) && typeof out[k] === "object" && out[k] && !Array.isArray(out[k])) {
      out[k] = deepMerge(out[k], v);
    } else out[k] = v;
  }
  return out;
}

// ---------- Human-readable summaries ----------

function describePorts(pf?: Json): string | undefined {
  if (!pf) return undefined;
  if (pf.type === "TRAFFIC_MATCHING_LIST") return `ports in list ${pf.trafficMatchingListId}`;
  return (
    "ports " +
    (pf.items ?? []).map((i: Json) => (i.type === "PORT_NUMBER_RANGE" ? `${i.start}-${i.stop}` : String(i.value))).join(",")
  );
}

function describeFilter(tf: Json | undefined, networkName: (id: string) => string): string {
  if (!tf) return "any";
  const parts: string[] = [];
  const not = (b?: boolean) => (b ? "NOT " : "");
  switch (tf.type) {
    case "IP_ADDRESS": {
      const f = tf.ipAddressFilter;
      parts.push(
        f?.type === "TRAFFIC_MATCHING_LIST"
          ? `IPs in list ${f.trafficMatchingListId}`
          : "IPs " + (f?.items ?? []).map((i: Json) => (i.type === "IP_ADDRESS_RANGE" ? `${i.start}-${i.stop}` : i.value)).join(","),
      );
      break;
    }
    case "NETWORK":
      parts.push(`${not(tf.networkFilter?.matchOpposite)}networks ${(tf.networkFilter?.networkIds ?? []).map(networkName).join(",")}`);
      break;
    case "MAC_ADDRESS":
      parts.push(`MACs ${(tf.macAddressFilter?.macAddresses ?? []).join(",")}`);
      break;
    case "DOMAIN":
      parts.push(`domains ${(tf.domainFilter?.domains ?? []).join(",")}`);
      break;
    case "REGION":
      parts.push(`regions ${(tf.regionFilter?.regions ?? []).join(",")}`);
      break;
    case "APPLICATION":
      parts.push(`apps ${(tf.applicationFilter?.applicationIds ?? []).join(",")}`);
      break;
    case "APPLICATION_CATEGORY":
      parts.push(`app categories ${(tf.applicationCategoryFilter?.applicationCategoryIds ?? []).join(",")}`);
      break;
    case "VPN_SERVER":
      parts.push(`${not(tf.vpnServerFilter?.matchOpposite)}VPN servers ${(tf.vpnServerFilter?.vpnServerIds ?? []).join(",")}`);
      break;
    case "SITE_TO_SITE_VPN_TUNNEL":
      parts.push(`S2S tunnel ${tf.siteToSiteVpnTunnelFilter?.siteToSiteVpnTunnelId}`);
      break;
    case "IPV6_IID":
      parts.push(`${not(tf.ipv6IidFilter?.matchOpposite)}IPv6 IID ${tf.ipv6IidFilter?.ipv6Iid}`);
      break;
    case "PORT":
      break;
    default:
      parts.push(String(tf.type));
  }
  if (typeof tf.macAddressFilter === "string") parts.push(`MAC ${tf.macAddressFilter}`);
  const ports = describePorts(tf.portFilter);
  if (ports) parts.push(ports);
  return parts.join(" + ") || "any";
}

function describeProtocol(scope?: Json): string {
  if (!scope) return "?";
  const pf = scope.protocolFilter;
  let proto = "all";
  if (pf?.type === "PRESET") proto = pf.preset?.name;
  else if (pf?.type === "NAMED_PROTOCOL") proto = `${pf.matchOpposite ? "not " : ""}${pf.protocol?.name}`;
  else if (pf?.type === "PROTOCOL_NUMBER") proto = `${pf.matchOpposite ? "not " : ""}proto#${pf.protocolNumber}`;
  return `${proto} (${scope.ipVersion})`;
}

export function summarizePolicy(p: Json, zoneName: (id: string) => string, networkName: (id: string) => string): Json {
  return {
    id: p.id,
    index: p.index,
    name: p.name,
    enabled: p.enabled,
    action: p.action?.type + (p.action?.allowReturnTraffic ? " (+return)" : ""),
    from: `${zoneName(p.source?.zoneId)}: ${describeFilter(p.source?.trafficFilter, networkName)}`,
    to: `${zoneName(p.destination?.zoneId)}: ${describeFilter(p.destination?.trafficFilter, networkName)}`,
    protocol: describeProtocol(p.ipProtocolScope),
    origin: p.metadata?.origin,
    ...(p.connectionStateFilter ? { states: p.connectionStateFilter.join(",") } : {}),
    ...(p.schedule && p.schedule.mode !== "ALWAYS" ? { schedule: p.schedule.mode } : {}),
    ...(p.loggingEnabled ? { logging: true } : {}),
    ...(p.description ? { description: p.description } : {}),
  };
}
