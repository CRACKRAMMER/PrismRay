// SPDX-License-Identifier: MPL-2.0

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { translations, t, normalizeLocale } from "./i18n.ts";
import {
  DEFAULT_APPEARANCE,
  hsvToRgb,
  normalizeAppearance,
  normalizeHexColor,
  pickAccessibleForeground,
  rgbToHex,
  rgbToHsv,
} from "./appearance.ts";
import {
  formatGoDuration,
  joinToHours,
  joinToMilliseconds,
  joinToSeconds,
  parseGoDuration,
  splitHours,
  splitMilliseconds,
  splitSeconds,
} from "./duration.ts";
import { clampColumnWidth } from "./useResizableColumns.ts";
import { classifyQrPayload } from "./qrImport.ts";
import {
  ROUTING_SHARE_GZIP_PREFIX,
  decodeRoutingShareInput,
  encodeRoutingShareString,
} from "./routingShare.ts";
import { normalizeThemeMode, resolveColorScheme } from "./theme.ts";
import {
  ALL_PROTOCOLS,
  buildApiUrl,
  buildNodeFilterTabs,
  buildWsUrl,
  formatBytes,
  formatDurationShort,
  formatExpiryDays,
  formatLatency,
  formatRate,
  formatSpeedMbps,
  getNodeHealthState,
  getNodeHealthStyles,
  isRoutingProfileEqual,
  isRuleSetReady,
  nodeHasInsecureTLS,
  nodeMatchesFilterTab,
  nodeMatchesFilterTabs,
  nodeNeedsXray,
  resolveConnectionRoute,
  sortNodesByMetric,
} from "./helpers.ts";

describe("v1.0.0 frontend modules", () => {
  it("keeps full i18n key parity between zh-CN and en-US", () => {
    const zhKeys = Object.keys(translations["zh-CN"]).sort();
    const enKeys = Object.keys(translations["en-US"]).sort();
    assert.deepEqual(enKeys, zhKeys);
    assert.equal(normalizeLocale("en"), "en-US");
    assert.equal(normalizeLocale("en-US"), "en-US");
    assert.equal(normalizeLocale("ja-JP"), "en-US");
    assert.equal(normalizeLocale("ko-KR"), "en-US");
    assert.equal(normalizeLocale("fr-FR"), "en-US");
    assert.equal(normalizeLocale(""), "en-US");
    assert.equal(normalizeLocale(undefined), "en-US");
    assert.equal(normalizeLocale("zh"), "zh-CN");
    assert.equal(normalizeLocale("zh-CN"), "zh-CN");
    assert.equal(normalizeLocale("zh-TW"), "zh-CN");
    assert.equal(normalizeLocale("zh-HK"), "zh-CN");
    assert.equal(normalizeLocale("zh-Hans"), "zh-CN");
    assert.equal(normalizeLocale("zh-Hant"), "zh-CN");
    assert.equal(normalizeLocale("zh_TW"), "zh-CN");
    assert.equal(t("en-US", "subs.daysLeft", { days: 7 }), "7d left");
    assert.equal(t("zh-CN", "subs.daysLeft", { days: 7 }), "剩余 7 天");
  });

  it("resolves Light / Dark / System theme overrides accurately", () => {
    assert.equal(normalizeThemeMode("light"), "light");
    assert.equal(normalizeThemeMode("dark"), "dark");
    assert.equal(normalizeThemeMode("system"), "system");
    assert.equal(normalizeThemeMode("other"), "system");
    assert.equal(normalizeThemeMode(null), "system");
    assert.equal(resolveColorScheme("system", true), "dark");
    assert.equal(resolveColorScheme("system", false), "light");
    assert.equal(resolveColorScheme("light", true), "light");
    assert.equal(resolveColorScheme("dark", false), "dark");
  });

  it("identifies all 11 protocols, Xray coprocessor triggers, and Insecure TLS badges", () => {
    assert.equal(ALL_PROTOCOLS.length, 11);
    assert.equal(nodeNeedsXray({ protocol: "vless", network: "xhttp" }), true);
    assert.equal(nodeNeedsXray({ protocol: "vless", network: "splithttp" }), true);
    assert.equal(nodeNeedsXray({ protocol: "vless", mldsa65_verify: "pqv-key" }), true);
    assert.equal(nodeNeedsXray({ protocol: "vless", vless_encryption: "mlkem768x25519plus" }), true);
    assert.equal(nodeNeedsXray({ protocol: "hysteria2", engine_pref: "xray" }), true);
    assert.equal(nodeNeedsXray({ protocol: "vless", network: "xhttp", engine_pref: "sing-box" }), false);
    assert.equal(nodeNeedsXray({ protocol: "hysteria2", network: "udp" }), false);
    assert.equal(nodeHasInsecureTLS({ allow_insecure: true }), true);
    assert.equal(nodeHasInsecureTLS({ allow_insecure: false }), false);
  });

  it("formats throughput, bytes, expiry countdowns, and API/WS URLs", () => {
    assert.equal(formatBytes(512), "512 B");
    assert.equal(formatBytes(2048), "2.0 KB");
    assert.equal(formatRate(1048576), "1.00 MB/s");
    assert.equal(formatLatency(0), "--");
    assert.equal(formatLatency(-1), "Timeout");
    assert.equal(formatLatency(42), "42 ms");
    assert.equal(formatExpiryDays(0, 1000), null);
    assert.equal(formatExpiryDays(500, 1000), 0);
    assert.equal(formatExpiryDays(1000 + 86400 * 3, 1000), 3);

    assert.equal(buildApiUrl("http://127.0.0.1:2178/api/", "/process/status"), "http://127.0.0.1:2178/api/process/status");
    assert.equal(
      buildWsUrl("http://127.0.0.1:2178/api", "traffic", "abc123"),
      "ws://127.0.0.1:2178/api/traffic?token=abc123",
    );
    assert.equal(
      buildWsUrl("https://proxy.example.com/api", "/logs", ""),
      "wss://proxy.example.com/api/logs",
    );
    assert.equal(formatSpeedMbps(0), "--");
    assert.equal(formatSpeedMbps(5.432), "5.43 Mbps");
    assert.equal(formatSpeedMbps(128.46), "128.5 Mbps");
    const baseMs = Date.parse("2026-11-18T12:00:00Z");
    assert.equal(formatDurationShort("2026-11-18T11:58:15Z", baseMs), "1m 45s");
    assert.equal(formatDurationShort("2026-11-18T10:30:00Z", baseMs), "1h 30m");
  });

  it("resolves connection node, group, and engine and sorts nodes across metrics", () => {
    const sampleNodes = [
      { id: "n1", name: "Tokyo", user_alias: "Tokyo-01", protocol: "vless", network: "tcp", latency: 85, ping_ms: 42, down_speed_mbps: 180, up_speed_mbps: 45 },
      { id: "n2", name: "Singapore", protocol: "vless", network: "xhttp", latency: 40, ping_ms: 28, down_speed_mbps: 95, up_speed_mbps: 60 },
      { id: "n3", name: "Unreachable", protocol: "trojan", latency: -1, ping_ms: 0, down_speed_mbps: 0, up_speed_mbps: 0 },
    ];
    const sampleGroups = [{ id: "g-auto", name: "Auto Fastest" }];

    assert.deepEqual(resolveConnectionRoute(["node-n1", "group-g-auto"], sampleNodes, sampleGroups), {
      outboundKind: "node",
      nodeId: "n1",
      nodeName: "Tokyo-01",
      groupId: "g-auto",
      groupName: "Auto Fastest",
      engine: "sing-box",
    });
    assert.equal(resolveConnectionRoute(["node-n2"], sampleNodes, sampleGroups).engine, "xray");
    assert.equal(resolveConnectionRoute(["direct"], sampleNodes, sampleGroups).engine, "direct");
    assert.equal(resolveConnectionRoute(["block-out"], sampleNodes, sampleGroups).engine, "block");

    assert.deepEqual(
      sortNodesByMetric(sampleNodes, "latency", "asc").map((n) => n.id),
      ["n2", "n1", "n3"],
    );
    assert.deepEqual(
      sortNodesByMetric(sampleNodes, "down", "desc").map((n) => n.id),
      ["n1", "n2", "n3"],
    );
    assert.deepEqual(
      sortNodesByMetric(sampleNodes, "ping", "asc").map((n) => n.id),
      ["n2", "n1", "n3"],
    );
  });

  it("builds shared node filter tabs and detects routing profile dirty state accurately", () => {
    const sampleNodes = [
      { id: "n1", name: "JP", sub_id: "sub1", favorite: true, tags: ["Streaming", "AI"] },
      { id: "n2", name: "Manual", favorite: false, group: "Gaming" },
    ];
    const tabs = buildNodeFilterTabs(sampleNodes, [{ id: "sub1", name: "Provider A" }], ["Streaming", "Work"], {
      all: "All",
      manual: "Manual",
      favorites: "Fav",
    });
    assert.deepEqual(
      tabs.map((t) => [t.id, t.count]),
      [
        ["all", 2],
        ["manual", 1],
        ["favorites", 1],
        ["sub:sub1", 1],
        ["utag:Streaming", 1],
        ["utag:Work", 0],
        ["utag:AI", 1],
        ["utag:Gaming", 1],
      ],
    );
    assert.equal(nodeMatchesFilterTab(sampleNodes[0], "utag:Streaming"), true);
    assert.equal(nodeMatchesFilterTab(sampleNodes[1], "utag:Gaming"), true);
    assert.equal(nodeMatchesFilterTab(sampleNodes[1], "sub:sub1"), false);

    const baseProfile = {
      mode: "rule",
      block_ads: true,
      bypass_lan: true,
      bypass_cn: true,
      local_dns: "223.5.5.5",
      remote_dns: "https://dns.google/dns-query",
      domain_strategy: "prefer_ipv4",
      hijack_dns: true,
      fake_ip: false,
      fake_ip_filter: [],
      kill_switch: true,
      webrtc_mode: "block" as const,
      per_app_mode: "all",
      per_app_packages: [],
      custom_rules: [
        { id: "r1", name: "Rule 1", enabled: true, domain_suffix: ["a.com"], outbound: "direct" },
        { id: "r2", name: "Rule 2", enabled: true, domain_suffix: ["b.com"], outbound: "proxy" },
      ],
    };
    // Whitespace / omitted defaults keep profiles equal
    assert.equal(
      isRoutingProfileEqual(baseProfile, {
        ...baseProfile,
        hijack_dns: undefined,
        kill_switch: undefined,
        local_dns: " 223.5.5.5 ",
      }),
      true,
    );
    // Toggling field or reordering rules marks dirty
    assert.equal(isRoutingProfileEqual(baseProfile, { ...baseProfile, bypass_cn: false }), false);
    assert.equal(
      isRoutingProfileEqual(baseProfile, {
        ...baseProfile,
        custom_rules: [baseProfile.custom_rules[1], baseProfile.custom_rules[0]],
      }),
      false,
    );
  });

  it("encodes and decodes RoutingProfile QR share strings (gzip + raw JSON)", async () => {
    const sample = {
      mode: "rule" as const,
      block_ads: true,
      bypass_lan: true,
      bypass_cn: true,
      local_dns: "223.5.5.5",
      remote_dns: "https://dns.google/dns-query",
      custom_rules: [
        {
          id: "r-google",
          name: "Google",
          enabled: true,
          domain_suffix: ["google.com", "youtube.com", "googleapis.com"],
          outbound: "proxy",
        },
      ],
    };
    const encoded = await encodeRoutingShareString(sample);
    assert.ok(encoded.startsWith(ROUTING_SHARE_GZIP_PREFIX) || encoded.startsWith("prismray-route://v1-plain/"));
    const decoded = await decodeRoutingShareInput(encoded);
    assert.equal(decoded.mode, "rule");
    assert.equal(decoded.local_dns, "223.5.5.5");
    assert.equal(decoded.custom_rules.length, 1);
    assert.deepEqual(decoded.custom_rules[0].domain_suffix, ["google.com", "youtube.com", "googleapis.com"]);

    // Also accepts standalone JSON and v4 backup wrapper containing routing_profile
    const fromWrapped = await decodeRoutingShareInput(JSON.stringify({ version: 4, routing_profile: sample }));
    assert.equal(fromWrapped.custom_rules.length, 1);
  });

  it("appearance hex normalization, WCAG foreground picking & clamping", () => {
    assert.equal(normalizeHexColor("#ABC"), "#aabbcc");
    assert.equal(normalizeHexColor("#10B981"), "#10b981");
    assert.equal(normalizeHexColor("not-a-hex"), "");

    // Dark indigo prefers white text; bright yellow prefers dark slate text
    assert.equal(pickAccessibleForeground("#4f46e5"), "#ffffff");
    assert.equal(pickAccessibleForeground("#facc15"), "#0f172a");

    const norm = normalizeAppearance({
      accentHex: "#0ea5e9",
      bgPreset: "aurora",
      bgBlur: 99,
      glassBlur: 50,
      bgDim: -5,
      cardOpacity: 10,
    });
    assert.equal(norm.bgBlur, 24);
    assert.equal(norm.glassBlur, 32);
    assert.equal(norm.bgDim, 0);
    assert.equal(norm.cardOpacity, 20);

    const fallback = normalizeAppearance({ bgPreset: "unknown" as typeof DEFAULT_APPEARANCE.bgPreset });
    assert.equal(fallback.bgPreset, "none");

    // HSV <-> RGB round-trip accuracy for circular color wheel
    const hsv = rgbToHsv(5, 150, 105);
    const back = hsvToRgb(hsv.h, hsv.s, hsv.v);
    assert.equal(rgbToHex(back.r, back.g, back.b), "#059669");
  });

  it("duration parsing, formatting & lossless unit conversions", () => {
    assert.deepEqual(parseGoDuration("5m"), { value: 5, unit: "m" });
    assert.deepEqual(parseGoDuration("500ms"), { value: 500, unit: "ms" });
    assert.deepEqual(parseGoDuration("24h"), { value: 1, unit: "d" });
    assert.equal(formatGoDuration(1, "d"), "24h");
    assert.equal(formatGoDuration(30, "s"), "30s");

    assert.deepEqual(splitMilliseconds(1000, ["ms", "s", "m"]), { value: 1, unit: "s" });
    assert.equal(joinToMilliseconds(2, "s"), 2000);
    assert.deepEqual(splitSeconds(180, ["s", "m", "h", "d"]), { value: 3, unit: "m" });
    assert.equal(joinToSeconds(2, "h"), 7200);
    assert.deepEqual(splitHours(48, ["h", "d"]), { value: 2, unit: "d" });
    assert.equal(joinToHours(3, "d"), 72);
  });

  it("resizable column width clamping respects bounds", () => {
    const spec = { defaultWidth: 160, minWidth: 80, maxWidth: 400 };
    assert.equal(clampColumnWidth(40, spec), 80);
    assert.equal(clampColumnWidth(245.6, spec), 246);
    assert.equal(clampColumnWidth(900, spec), 400);
  });

  it("classifies QR payloads between node links and subscription URLs", () => {
    const vless = classifyQrPayload("vless://uuid@example.com:443?security=reality#Node1");
    assert.equal(vless.kind, "nodes");
    assert.equal(vless.allowSwitch, false);

    const sub = classifyQrPayload("https://sub.example.com/api/v1/client/subscribe?token=abc#My%20Airport");
    assert.equal(sub.kind, "subscription");
    assert.equal(sub.suggestedName, "My Airport");
    assert.equal(sub.allowSwitch, true);

    const httpProxy = classifyQrPayload("http://user:pass@proxy.example.com:8080");
    assert.equal(httpProxy.kind, "nodes");
    assert.equal(httpProxy.allowSwitch, true);

    const multiLine = classifyQrPayload("vmess://abc\nss://def");
    assert.equal(multiLine.kind, "nodes");
  });

  it("classifies 4-state node health with default 800ms and custom thresholds", () => {
    assert.equal(getNodeHealthState(undefined), "untested");
    assert.equal(getNodeHealthState(null), "untested");
    assert.equal(getNodeHealthState(0), "untested");
    assert.equal(getNodeHealthState(-1), "unavailable");
    assert.equal(getNodeHealthState(120), "ok");
    assert.equal(getNodeHealthState(799), "ok");
    assert.equal(getNodeHealthState(800), "high");
    assert.equal(getNodeHealthState(1450), "high");

    // Custom threshold (e.g. 500ms)
    assert.equal(getNodeHealthState(499, 500), "ok");
    assert.equal(getNodeHealthState(500, 500), "high");

    // Color mappings for all 4 states
    assert.match(getNodeHealthStyles("unavailable").dotClass, /red/);
    assert.match(getNodeHealthStyles("high").dotClass, /amber/);
    assert.match(getNodeHealthStyles("ok").dotClass, /emerald/);
    assert.match(getNodeHealthStyles("untested").dotClass, /muted/);
  });

  it("matches built-in .srs rule sets by tag even when id uses builtin-* prefix", () => {
    const specs = [
      { id: "builtin-geosite-ads", tag: "geosite-category-ads-all", synced: true, enabled: true },
      { id: "builtin-geosite-cn", tag: "geosite-cn", synced: true, enabled: true },
      { id: "builtin-geoip-cn", tag: "geoip-cn", synced: false, enabled: true },
    ];
    assert.equal(isRuleSetReady(specs, "geosite-category-ads-all"), true);
    assert.equal(isRuleSetReady(specs, "geosite-cn"), true);
    assert.equal(isRuleSetReady(specs, "geoip-cn"), false);
    assert.equal(
      isRuleSetReady(
        [{ id: "builtin-geosite-ads", tag: "geosite-category-ads-all", synced: true, enabled: false }],
        "geosite-category-ads-all",
      ),
      false,
    );
  });

  it("supports multi-select node tab filtering and protects builtin & subscription tabs from deletion", () => {
    const nodes = [
      { id: "n1", name: "SubA-1", sub_id: "sub-a", tags: ["Game"] },
      { id: "n2", name: "Manual-1", favorite: true, tags: ["AI"] },
      { id: "n3", name: "SubB-1", sub_id: "sub-b" },
    ];
    const subs = [
      { id: "sub-a", name: "Airport A" },
      { id: "sub-b", name: "Airport B" },
    ];
    const tabs = buildNodeFilterTabs(nodes, subs, ["Game", "AI"], {
      all: "All",
      manual: "Manual",
      favorites: "Favorites",
    });

    const byId = new Map(tabs.map((tab) => [tab.id, tab]));
    assert.equal(byId.get("all")?.deletable, false);
    assert.equal(byId.get("manual")?.deletable, false);
    assert.equal(byId.get("favorites")?.deletable, false);
    assert.equal(byId.get("sub:sub-a")?.kind, "subscription");
    assert.equal(byId.get("sub:sub-a")?.deletable, false);
    assert.equal(byId.get("utag:Game")?.kind, "custom");
    assert.equal(byId.get("utag:Game")?.deletable, true);

    // Multi-select union filtering
    assert.equal(nodeMatchesFilterTabs(nodes[0], []), true);
    assert.equal(nodeMatchesFilterTabs(nodes[0], ["sub:sub-a", "utag:AI"]), true);
    assert.equal(nodeMatchesFilterTabs(nodes[1], ["sub:sub-a", "utag:AI"]), true);
    assert.equal(nodeMatchesFilterTabs(nodes[2], ["sub:sub-a", "utag:AI"]), false);
  });
});
