// SPDX-License-Identifier: MPL-2.0

export const ALL_PROTOCOLS = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "hysteria2",
  "tuic",
  "anytls",
  "wireguard",
  "naive",
  "socks",
  "http",
] as const;

export type ProtocolType = (typeof ALL_PROTOCOLS)[number];

export interface NodeLike {
  id?: string;
  name?: string;
  user_alias?: string;
  protocol?: string;
  address?: string;
  sub_id?: string;
  favorite?: boolean;
  group?: string;
  tags?: string[];
  engine_pref?: string;
  network?: string;
  vless_encryption?: string;
  mldsa65_verify?: string;
  allow_insecure?: boolean;
  latency?: number;
  ping_ms?: number;
  down_speed_mbps?: number;
  up_speed_mbps?: number;
}

export interface GroupLike {
  id: string;
  name: string;
}

export function nodeNeedsXray(node: NodeLike): boolean {
  if (node.engine_pref?.toLowerCase() === "xray") return true;
  if (node.engine_pref?.toLowerCase() === "sing-box") return false;
  const net = node.network?.toLowerCase();
  if (net === "xhttp" || net === "splithttp" || net === "httpupgrade") return true;
  const enc = node.vless_encryption?.trim().toLowerCase();
  if (enc && enc !== "none") return true;
  if (node.mldsa65_verify?.trim()) return true;
  return false;
}

export function nodeHasInsecureTLS(node: NodeLike): boolean {
  return Boolean(node.allow_insecure);
}

export function formatBytes(bytes: number): string {
  const n = Number.isFinite(bytes) ? Math.max(0, bytes) : 0;
  if (n < 1024) return `${Math.round(n)} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatLatency(ms?: number): string {
  if (ms === undefined || ms === 0) return "--";
  if (ms < 0) return "Timeout";
  return `${ms} ms`;
}

export const DEFAULT_HIGH_LATENCY_MS = 800;

export type NodeHealthState = "untested" | "ok" | "high" | "unavailable";

export function getNodeHealthState(
  latency: number | undefined | null,
  highThresholdMs = DEFAULT_HIGH_LATENCY_MS,
): NodeHealthState {
  if (latency === undefined || latency === null || latency === 0) return "untested";
  if (latency < 0) return "unavailable";
  const threshold = Number.isFinite(highThresholdMs) && highThresholdMs > 0 ? highThresholdMs : DEFAULT_HIGH_LATENCY_MS;
  if (latency >= threshold) return "high";
  return "ok";
}

export interface NodeHealthStyles {
  dotClass: string;
  textClass: string;
  badgeClass: string;
}

export function getNodeHealthStyles(state: NodeHealthState): NodeHealthStyles {
  switch (state) {
    case "unavailable":
      return {
        dotClass: "bg-red-500",
        textClass: "text-red-500",
        badgeClass: "border-red-500/40 bg-red-500/10 text-red-500",
      };
    case "high":
      return {
        dotClass: "bg-amber-500",
        textClass: "text-amber-600 dark:text-amber-400",
        badgeClass: "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
      };
    case "ok":
      return {
        dotClass: "bg-emerald-500",
        textClass: "text-emerald-600 dark:text-emerald-400",
        badgeClass: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
      };
    default:
      return {
        dotClass: "bg-muted-foreground/40",
        textClass: "text-muted-foreground",
        badgeClass: "border-border bg-muted/40 text-muted-foreground",
      };
  }
}

export function isRuleSetReady(
  ruleSets: ReadonlyArray<{ id?: string; tag?: string; synced?: boolean; enabled?: boolean }>,
  tag: string,
): boolean {
  return ruleSets.some((rs) => Boolean(rs.synced) && rs.enabled !== false && (rs.tag === tag || rs.id === tag));
}

export function formatSpeedMbps(mbps?: number): string {
  if (mbps === undefined || mbps <= 0) return "--";
  return mbps >= 10 ? `${mbps.toFixed(1)} Mbps` : `${mbps.toFixed(2)} Mbps`;
}

export function formatDurationShort(startISO: string, nowMs = Date.now()): string {
  const started = Date.parse(startISO);
  if (!Number.isFinite(started)) return "--";
  const sec = Math.max(0, Math.floor((nowMs - started) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${sec % 60}s`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m`;
}

export function formatExpiryDays(expireUnix: number, nowUnix = Math.floor(Date.now() / 1000)): number | null {
  if (!expireUnix || expireUnix <= 0) return null;
  const diff = expireUnix - nowUnix;
  if (diff <= 0) return 0;
  return Math.ceil(diff / 86400);
}

export function buildApiUrl(baseApiUrl: string, path: string): string {
  const cleanBase = baseApiUrl.replace(/\/+$/, "");
  const cleanPath = path.replace(/^\/+/, "");
  return `${cleanBase}/${cleanPath}`;
}

export function buildWsUrl(baseApiUrl: string, path: string, token = "", baseOrigin = "http://127.0.0.1"): string {
  const httpUrl = buildApiUrl(baseApiUrl, path);
  const url = new URL(httpUrl, baseOrigin);
  if (token) {
    url.searchParams.set("token", token);
  }
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export interface ResolvedConnectionRoute {
  outboundKind: "node" | "direct" | "block" | "proxy";
  nodeId: string;
  nodeName: string;
  groupId: string;
  groupName: string;
  engine: "sing-box" | "xray" | "direct" | "block";
}

export function resolveConnectionRoute(
  chains: string[] | undefined,
  nodes: NodeLike[],
  groups: GroupLike[],
): ResolvedConnectionRoute {
  const list = chains || [];
  let nodeId = "";
  let groupId = "";
  let rawLeaf = "";

  for (const tag of list) {
    const t = (tag || "").trim();
    if (!t) continue;
    if (!rawLeaf) rawLeaf = t;
    if (!nodeId && t.startsWith("node-")) {
      nodeId = t.slice(5);
    } else if (!groupId && t.startsWith("group-")) {
      groupId = t.slice(6);
    }
  }

  const groupObj = groupId ? groups.find((g) => g.id === groupId) : undefined;
  const groupName = groupObj?.name || (groupId ? groupId : "");

  if (list.some((c) => c === "block-out" || c === "REJECT" || c === "reject")) {
    return {
      outboundKind: "block",
      nodeId: "",
      nodeName: "BLOCK",
      groupId,
      groupName,
      engine: "block",
    };
  }
  if (list.some((c) => c === "direct" || c === "DIRECT")) {
    return {
      outboundKind: "direct",
      nodeId: "",
      nodeName: "DIRECT",
      groupId,
      groupName,
      engine: "direct",
    };
  }

  if (nodeId) {
    const found = nodes.find((n) => n.id === nodeId);
    const engine: "sing-box" | "xray" = found && nodeNeedsXray(found) ? "xray" : "sing-box";
    return {
      outboundKind: "node",
      nodeId,
      nodeName: found?.user_alias || found?.name || rawLeaf || nodeId,
      groupId,
      groupName,
      engine,
    };
  }

  return {
    outboundKind: "proxy",
    nodeId: "",
    nodeName: rawLeaf || groupName || "proxy",
    groupId,
    groupName,
    engine: "sing-box",
  };
}

export type NodeSortField = "default" | "latency" | "ping" | "down" | "up" | "name" | "protocol";
export type SortDirection = "asc" | "desc";

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

export function sortNodesByMetric<T extends NodeLike>(
  nodes: T[],
  field: NodeSortField,
  direction: SortDirection = field === "down" || field === "up" ? "desc" : "asc",
): T[] {
  if (field === "default") return nodes;
  const copy = [...nodes];
  const factor = direction === "asc" ? 1 : -1;

  const cmpPositiveMetric = (va: number, vb: number): number => {
    const aValid = Number.isFinite(va) && va > 0;
    const bValid = Number.isFinite(vb) && vb > 0;
    if (aValid && bValid) return (va - vb) * factor;
    if (aValid !== bValid) return aValid ? -1 : 1;
    // Timeout (-1) before completely untested (0) when both invalid
    if (va !== vb) return va < vb ? -1 : 1;
    return 0;
  };

  copy.sort((a, b) => {
    switch (field) {
      case "latency":
        return cmpPositiveMetric(a.latency || 0, b.latency || 0);
      case "ping":
        return cmpPositiveMetric(a.ping_ms || 0, b.ping_ms || 0);
      case "down":
        return cmpPositiveMetric(a.down_speed_mbps || 0, b.down_speed_mbps || 0);
      case "up":
        return cmpPositiveMetric(a.up_speed_mbps || 0, b.up_speed_mbps || 0);
      case "protocol":
        return factor * collator.compare(a.protocol || "", b.protocol || "");
      case "name":
        return factor * collator.compare(a.user_alias || a.name || "", b.user_alias || b.name || "");
      default:
        return 0;
    }
  });
  return copy;
}

export type NodeFilterTabKind = "builtin" | "subscription" | "custom";

export interface NodeFilterTab {
  id: string;
  label: string;
  count: number;
  kind?: NodeFilterTabKind;
  deletable?: boolean;
  tagName?: string;
}

export interface SubscriptionLike {
  id: string;
  name: string;
}

export function nodeHasTag(node: NodeLike, tag: string): boolean {
  const clean = tag.trim();
  if (!clean) return false;
  if ((node.tags || []).some((t) => t.trim() === clean)) return true;
  return (node.group || "").trim() === clean;
}

export function nodeMatchesFilterTab(node: NodeLike, tabId: string): boolean {
  if (!tabId || tabId === "all") return true;
  if (tabId === "manual") return !node.sub_id?.trim();
  if (tabId === "favorites") return Boolean(node.favorite);
  if (tabId.startsWith("sub:")) return (node.sub_id || "").trim() === tabId.slice(4);
  if (tabId.startsWith("utag:")) return nodeHasTag(node, tabId.slice(5));
  return true;
}

export function nodeMatchesFilterTabs(node: NodeLike, tabIds: ReadonlyArray<string>): boolean {
  if (!tabIds || tabIds.length === 0 || tabIds.includes("all")) return true;
  return tabIds.some((id) => nodeMatchesFilterTab(node, id));
}

export function buildNodeFilterTabs(
  nodes: NodeLike[],
  subscriptions: SubscriptionLike[],
  customNodeTabs: string[],
  labels: { all: string; manual: string; favorites: string },
): NodeFilterTab[] {
  const manualCount = nodes.filter((n) => !n.sub_id?.trim()).length;
  const favCount = nodes.filter((n) => Boolean(n.favorite)).length;

  const tabs: NodeFilterTab[] = [
    { id: "all", label: labels.all, count: nodes.length, kind: "builtin", deletable: false },
    { id: "manual", label: labels.manual, count: manualCount, kind: "builtin", deletable: false },
    { id: "favorites", label: labels.favorites, count: favCount, kind: "builtin", deletable: false },
  ];

  const seenSubIds = new Set<string>();
  for (const s of subscriptions) {
    seenSubIds.add(s.id);
    const count = nodes.filter((n) => (n.sub_id || "").trim() === s.id).length;
    tabs.push({ id: `sub:${s.id}`, label: s.name, count, kind: "subscription", deletable: false });
  }
  for (const n of nodes) {
    const sid = n.sub_id?.trim();
    if (sid && !seenSubIds.has(sid)) {
      seenSubIds.add(sid);
      const count = nodes.filter((item) => (item.sub_id || "").trim() === sid).length;
      tabs.push({ id: `sub:${sid}`, label: sid, count, kind: "subscription", deletable: false });
    }
  }

  const orderedTags: string[] = [];
  const seenTags = new Set<string>();
  const pushTag = (raw: string) => {
    const clean = raw.trim();
    if (!clean || seenTags.has(clean)) return;
    seenTags.add(clean);
    orderedTags.push(clean);
  };
  for (const t of customNodeTabs) pushTag(t);
  for (const n of nodes) {
    for (const t of n.tags || []) pushTag(t);
    if (n.group) pushTag(n.group);
  }
  for (const tag of orderedTags) {
    const count = nodes.filter((n) => nodeHasTag(n, tag)).length;
    tabs.push({ id: `utag:${tag}`, label: tag, count, kind: "custom", deletable: true, tagName: tag });
  }
  return tabs;
}

export interface RoutingRuleLike {
  id?: string;
  name?: string;
  enabled: boolean;
  domains?: string[];
  domain_suffix?: string[];
  domain_keyword?: string[];
  domain_regex?: string[];
  ip_cidr?: string[];
  source_ip_cidr?: string[];
  ip_is_private?: boolean;
  rule_set?: string[];
  network?: string[];
  port?: number[];
  port_range?: string[];
  source_port?: number[];
  process_name?: string[];
  process_path?: string[];
  package_name?: string[];
  protocol?: string[];
  inbound?: string[];
  invert?: boolean;
  outbound: string;
}

export interface RoutingProfileLike {
  mode: string;
  block_ads: boolean;
  bypass_lan: boolean;
  allow_lan_broadcast?: boolean;
  bypass_cn: boolean;
  local_dns: string;
  remote_dns: string;
  domain_strategy?: string;
  hijack_dns?: boolean;
  fake_ip?: boolean;
  fake_ip_filter?: string[];
  kill_switch?: boolean;
  webrtc_mode?: string;
  per_app_mode?: string;
  per_app_packages?: string[];
  custom_rules: RoutingRuleLike[];
}

function normStrList(arr?: string[]): string[] {
  return (arr || []).map((v) => v.trim()).filter(Boolean);
}

function normNumList(arr?: number[]): number[] {
  return (arr || []).filter((n) => Number.isFinite(n));
}

function normRule(rule: RoutingRuleLike) {
  return {
    id: (rule.id || "").trim(),
    name: (rule.name || "").trim(),
    enabled: Boolean(rule.enabled),
    domains: normStrList(rule.domains),
    domain_suffix: normStrList(rule.domain_suffix),
    domain_keyword: normStrList(rule.domain_keyword),
    domain_regex: normStrList(rule.domain_regex),
    ip_cidr: normStrList(rule.ip_cidr),
    source_ip_cidr: normStrList(rule.source_ip_cidr),
    ip_is_private: Boolean(rule.ip_is_private),
    rule_set: normStrList(rule.rule_set),
    network: normStrList(rule.network),
    port: normNumList(rule.port),
    port_range: normStrList(rule.port_range),
    source_port: normNumList(rule.source_port),
    process_name: normStrList(rule.process_name),
    process_path: normStrList(rule.process_path),
    package_name: normStrList(rule.package_name),
    protocol: normStrList(rule.protocol),
    inbound: normStrList(rule.inbound),
    invert: Boolean(rule.invert),
    outbound: (rule.outbound || "proxy").trim() || "proxy",
  };
}

export function isRoutingProfileEqual(a: RoutingProfileLike, b: RoutingProfileLike): boolean {
  const norm = (p: RoutingProfileLike) => ({
    mode: (p.mode || "rule").trim().toLowerCase(),
    block_ads: Boolean(p.block_ads),
    bypass_lan: Boolean(p.bypass_lan),
    allow_lan_broadcast: Boolean(p.bypass_lan && p.allow_lan_broadcast),
    bypass_cn: Boolean(p.bypass_cn),
    local_dns: (p.local_dns || "").trim(),
    remote_dns: (p.remote_dns || "").trim(),
    domain_strategy: (p.domain_strategy || "prefer_ipv4").trim(),
    hijack_dns: p.hijack_dns ?? true,
    fake_ip: Boolean(p.fake_ip),
    fake_ip_filter: normStrList(p.fake_ip_filter),
    kill_switch: p.kill_switch ?? true,
    webrtc_mode: (p.webrtc_mode || "block").trim(),
    per_app_mode: (p.per_app_mode || "all").trim(),
    per_app_packages: normStrList(p.per_app_packages),
    custom_rules: (p.custom_rules || []).map(normRule),
  });
  return JSON.stringify(norm(a)) === JSON.stringify(norm(b));
}
