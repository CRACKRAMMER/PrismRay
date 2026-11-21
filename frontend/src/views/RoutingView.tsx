// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  GripVertical,
  Pencil,
  Plus,
  QrCode,
  RefreshCw,
  RotateCcw,
  Route,
  Save,
  Sparkles,
  Trash2,
} from "lucide-react";
import {
  type RoutingProfile,
  type RoutingRule,
  androidBridge,
  api,
  formatApiError,
} from "../lib/api.ts";
import { isRoutingProfileEqual, isRuleSetReady } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { BottomSheetDialog, ContextInspector } from "../components/ContextInspector.tsx";
import { HelpTip } from "../components/HelpTip.tsx";
import { PerAppProxyCard } from "../components/PerAppProxyCard.tsx";
import { RoutingQrModal } from "../components/RoutingQrModal.tsx";
import { RuleEditorForm } from "../components/RuleEditorModal.tsx";
import { SectionAnchorBar } from "../components/SectionAnchorBar.tsx";
import { SwipeActionRow } from "../components/SwipeActionRow.tsx";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Input } from "../components/ui/input.tsx";
import { Select } from "../components/ui/select.tsx";
import { Switch } from "../components/ui/switch.tsx";

const DEFAULT_PROFILE: RoutingProfile = {
  mode: "rule",
  block_ads: true,
  bypass_lan: true,
  allow_lan_broadcast: false,
  bypass_cn: true,
  webrtc_mode: "block",
  local_dns: "223.5.5.5",
  remote_dns: "https://1.1.1.1/dns-query",
  domain_strategy: "prefer_ipv4",
  hijack_dns: true,
  fake_ip: false,
  fake_ip_filter: [],
  kill_switch: true,
  per_app_mode: "all",
  per_app_packages: [],
  custom_rules: [],
};

function splitCSV(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function summarizeRuleConditions(rule: RoutingRule): string[] {
  const badges: string[] = [];
  if (rule.domains?.length) badges.push(`domain:${rule.domains.slice(0, 2).join(",")}`);
  if (rule.domain_suffix?.length) badges.push(`suffix:${rule.domain_suffix.slice(0, 2).join(",")}`);
  if (rule.domain_keyword?.length) badges.push(`kw:${rule.domain_keyword.slice(0, 2).join(",")}`);
  if (rule.domain_regex?.length) badges.push(`regex:${rule.domain_regex.length}`);
  if (rule.ip_cidr?.length) badges.push(`ip:${rule.ip_cidr.slice(0, 2).join(",")}`);
  if (rule.source_ip_cidr?.length) badges.push(`src:${rule.source_ip_cidr.slice(0, 2).join(",")}`);
  if (rule.ip_is_private) badges.push("private-ip");
  if (rule.network?.length) badges.push(`net:${rule.network.join("/")}`);
  if (rule.port?.length) badges.push(`port:${rule.port.join(",")}`);
  if (rule.port_range?.length) badges.push(`range:${rule.port_range.join(",")}`);
  if (rule.source_port?.length) badges.push(`sport:${rule.source_port.join(",")}`);
  if (rule.protocol?.length) badges.push(`proto:${rule.protocol.join(",")}`);
  if (rule.process_name?.length) badges.push(`proc:${rule.process_name.slice(0, 2).join(",")}`);
  if (rule.process_path?.length) badges.push(`path:${rule.process_path.length}`);
  if (rule.inbound?.length) badges.push(`in:${rule.inbound.join(",")}`);
  if (rule.rule_set?.length) badges.push(`set:${rule.rule_set.join(",")}`);
  if (rule.package_name?.length) badges.push(`pkg:${rule.package_name.slice(0, 2).join(",")}`);
  return badges;
}

export function RoutingView() {
  const { activeTab, tr, locale, routing, ruleSets, status, nodes, groups, listeners, refreshAll, notify, registerUnsavedGuard } =
    useAppStore();
  const idPrefix = useId();
  const [draft, setDraft] = useState<RoutingProfile>(routing || DEFAULT_PROFILE);
  const [saving, setSaving] = useState(false);
  const [syncingRuleSets, setSyncingRuleSets] = useState(false);
  const [qrModalOpen, setQrModalOpen] = useState(false);

  const adsRuleReady = useMemo(() => isRuleSetReady(ruleSets, "geosite-category-ads-all"), [ruleSets]);
  const cnRuleReady = useMemo(
    () => isRuleSetReady(ruleSets, "geosite-cn") && isRuleSetReady(ruleSets, "geoip-cn"),
    [ruleSets],
  );

  const needsRuleSetRefreshRef = useRef(false);
  needsRuleSetRefreshRef.current = !adsRuleReady || !cnRuleReady;

  // When visiting Routing tab while built-in .srs files are still marked unsynced (e.g. background
  // auto-sync just finished after connecting), refresh once so switches unlock immediately.
  useEffect(() => {
    if (activeTab === "routing" && needsRuleSetRefreshRef.current) {
      void refreshAll();
    }
  }, [activeTab, refreshAll]);

  const handleQuickSyncRuleSets = async () => {
    setSyncingRuleSets(true);
    try {
      const res = await api.syncRuleSets();
      await refreshAll();
      const errEntries = Object.entries(res.errors || {});
      const syncedCount = res.synced_count ?? res.rule_sets.filter((r) => r.synced).length;
      if (errEntries.length > 0) {
        notify(
          `${tr("settings.rulesetsSyncPartial", { count: syncedCount, failed: errEntries.length })} (${errEntries[0][0]}: ${errEntries[0][1]})`,
          "warning",
        );
      } else {
        notify(tr("settings.rulesetsSyncedReloaded", { count: syncedCount }));
      }
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSyncingRuleSets(false);
    }
  };

  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [editingRuleIdx, setEditingRuleIdx] = useState<number | null>(null);
  const [reorderStatus, setReorderStatus] = useState("");
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const holdTimerRef = useRef<number | null>(null);
  const activeDragRef = useRef<number | null>(null);
  const dragStartedAtRef = useRef<number>(0);

  useEffect(() => {
    const onQuickCreate = (e: Event) => {
      if ((e as CustomEvent<string>).detail === "rule") {
        setEditingRuleIdx(null);
        setRuleModalOpen(true);
      }
    };
    window.addEventListener("prismray-quick-create", onQuickCreate);
    return () => window.removeEventListener("prismray-quick-create", onQuickCreate);
  }, []);

  const isAndroid = androidBridge.available() || Boolean(status?.android_mode);
  const [presetsOpen, setPresetsOpen] = useState(false);
  const presetsMenuRef = useRef<HTMLDivElement>(null);

  const baselineProfile = useMemo<RoutingProfile>(() => {
    if (!routing) return DEFAULT_PROFILE;
    return {
      ...DEFAULT_PROFILE,
      ...routing,
      webrtc_mode: routing.webrtc_mode || "block",
      hijack_dns: routing.hijack_dns !== false,
      fake_ip: Boolean(routing.fake_ip),
      fake_ip_filter: routing.fake_ip_filter || [],
      kill_switch: routing.kill_switch !== false,
      per_app_packages: routing.per_app_packages || [],
      custom_rules: routing.custom_rules || [],
    };
  }, [routing]);

  const isDirty = useMemo(() => !isRoutingProfileEqual(draft, baselineProfile), [draft, baselineProfile]);
  const isDefault = useMemo(() => isRoutingProfileEqual(draft, DEFAULT_PROFILE), [draft]);

  useEffect(() => {
    if (routing) {
      setDraft(baselineProfile);
    }
  }, [routing, baselineProfile]);

  useEffect(() => {
    if (!presetsOpen) return;
    const onPointerDown = (e: PointerEvent) => {
      if (presetsMenuRef.current && !presetsMenuRef.current.contains(e.target as Node)) {
        setPresetsOpen(false);
      }
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPresetsOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [presetsOpen]);

  const reorderRule = (fromIndex: number, toIndex: number) => {
    if (fromIndex === toIndex || toIndex < 0 || toIndex >= draft.custom_rules.length) return;
    const ruleName = draft.custom_rules[fromIndex]?.name || `Rule #${fromIndex + 1}`;
    setDraft((prev) => {
      const next = [...prev.custom_rules];
      const [item] = next.splice(fromIndex, 1);
      if (!item) return prev;
      next.splice(toIndex, 0, item);
      return { ...prev, custom_rules: next };
    });
    setReorderStatus(tr("routing.reorderedNotice", { name: ruleName, pos: toIndex + 1 }));
  };

  useEffect(() => {
    const onPointerMove = (e: PointerEvent) => {
      const currentIdx = activeDragRef.current;
      if (currentIdx === null || !listRef.current) return;
      const rows = Array.from(listRef.current.querySelectorAll<HTMLElement>("[data-rule-row]"));
      for (const row of rows) {
        const idxAttr = Number(row.dataset.ruleRow);
        if (!Number.isFinite(idxAttr) || idxAttr === currentIdx) continue;
        const rect = row.getBoundingClientRect();
        const mid = rect.top + rect.height / 2;
        if ((currentIdx < idxAttr && e.clientY > mid) || (currentIdx > idxAttr && e.clientY < mid)) {
          reorderRule(currentIdx, idxAttr);
          activeDragRef.current = idxAttr;
          setDragIndex(idxAttr);
          break;
        }
      }
    };

    const endDrag = () => {
      if (holdTimerRef.current !== null) {
        window.clearTimeout(holdTimerRef.current);
        holdTimerRef.current = null;
      }
      if (activeDragRef.current !== null) {
        activeDragRef.current = null;
        setDragIndex(null);
      }
    };

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", endDrag);
    window.addEventListener("pointercancel", endDrag);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", endDrag);
      window.removeEventListener("pointercancel", endDrag);
    };
  });

  const startDrag = (idx: number) => {
    activeDragRef.current = idx;
    dragStartedAtRef.current = Date.now();
    setDragIndex(idx);
  };

  const handleRowPointerDown = (idx: number, e: React.PointerEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement;
    if (target.closest("button, input, select, [role='switch']")) return;
    if (holdTimerRef.current !== null) window.clearTimeout(holdTimerRef.current);
    holdTimerRef.current = window.setTimeout(() => {
      startDrag(idx);
    }, 200);
  };

  const updateRule = (index: number, patch: Partial<RoutingRule>) => {
    setDraft((prev) => ({
      ...prev,
      custom_rules: prev.custom_rules.map((r, i) => (i === index ? { ...r, ...patch } : r)),
    }));
  };

  const moveRule = (index: number, delta: -1 | 1) => {
    reorderRule(index, index + delta);
  };

  const openAddRuleModal = () => {
    setEditingRuleIdx(null);
    setRuleModalOpen(true);
  };

  const openEditRuleModal = (index: number) => {
    setEditingRuleIdx(index);
    setRuleModalOpen(true);
  };

  const handleModalSave = (savedRule: RoutingRule) => {
    setDraft((prev) => {
      if (editingRuleIdx === null) {
        return { ...prev, custom_rules: [...prev.custom_rules, savedRule] };
      }
      return {
        ...prev,
        custom_rules: prev.custom_rules.map((r, i) => (i === editingRuleIdx ? savedRule : r)),
      };
    });
    setRuleModalOpen(false);
    setEditingRuleIdx(null);
    notify(tr("routing.ruleSaved"));
  };

  const removeRule = (index: number) => {
    setDraft((prev) => ({
      ...prev,
      custom_rules: prev.custom_rules.filter((_, i) => i !== index),
    }));
  };

  const handleSave = async (): Promise<boolean> => {
    setSaving(true);
    try {
      const payload: RoutingProfile = {
        ...draft,
        allow_lan_broadcast: Boolean(draft.bypass_lan && draft.allow_lan_broadcast),
      };
      const prevRouting = routing;
      const vpnLayerChanged =
        isAndroid &&
        prevRouting != null &&
        (Boolean(prevRouting.bypass_lan) !== Boolean(payload.bypass_lan) ||
          Boolean(prevRouting.bypass_lan && prevRouting.allow_lan_broadcast) !== Boolean(payload.allow_lan_broadcast) ||
          (prevRouting.per_app_mode || "all") !== (payload.per_app_mode || "all") ||
          JSON.stringify(prevRouting.per_app_packages || []) !== JSON.stringify(payload.per_app_packages || []));

      await api.saveRouting(payload);
      await refreshAll();

      if (vpnLayerChanged && androidBridge.getVpnStatus()?.active) {
        androidBridge.prepareAndStartVpn({
          per_app_mode: payload.per_app_mode || "all",
          per_app_packages: payload.per_app_packages || [],
          bypass_lan: payload.bypass_lan,
          allow_lan_broadcast: payload.allow_lan_broadcast,
        });
        notify(
          locale === "zh-CN"
            ? "路由策略已保存，正在刷新 Android VPN 路由…"
            : "Routing policy saved, refreshing Android VPN routes…",
        );
      } else {
        notify(locale === "zh-CN" ? "路由策略已保存" : "Routing policy saved");
      }
      return true;
    } catch (err) {
      notify(formatApiError(err), "error");
      return false;
    } finally {
      setSaving(false);
    }
  };

  const isDirtyRef = useRef(isDirty);
  isDirtyRef.current = isDirty;
  const handleSaveRef = useRef(handleSave);
  handleSaveRef.current = handleSave;

  useEffect(() => {
    registerUnsavedGuard("routing", {
      isDirty: () => isDirtyRef.current,
      save: () => handleSaveRef.current(),
    });
    return () => registerUnsavedGuard("routing", null);
  }, [registerUnsavedGuard]);

  const handleResetDefault = () => {
    setDraft(DEFAULT_PROFILE);
    notify(tr("routing.resetDone"));
  };

  const applyRulePreset = (preset: "steam" | "cdn" | "google") => {
    setPresetsOpen(false);
    if (preset === "google") {
      const googleRule: RoutingRule = {
        id: "preset-google-proxy",
        name: locale === "zh-CN" ? "Google 全家桶与 AI 服务 (代理)" : "Google Suite & AI (Proxy)",
        enabled: true,
        domain_suffix: [
          "google.com",
          "google.com.hk",
          "googleapis.com",
          "gstatic.com",
          "googleusercontent.com",
          "googlevideo.com",
          "youtube.com",
          "youtu.be",
          "ytimg.com",
          "ggpht.com",
          "gmail.com",
          "googlemail.com",
          "g.co",
          "goo.gl",
          "deepmind.google",
          "ai.dev",
          "android.com",
          "gvt1.com",
          "gvt2.com",
        ],
        outbound: "proxy",
      };
      setDraft((prev) => {
        const filtered = prev.custom_rules.filter((r) => r.id !== "preset-google-proxy");
        return { ...prev, custom_rules: [googleRule, ...filtered] };
      });
      notify(tr("routing.presetAdded", { name: tr("routing.presetGoogle") }));
      return;
    }

    if (preset === "steam") {
      const steamRules: RoutingRule[] = [
        {
          id: "preset-steam-download-direct",
          name: locale === "zh-CN" ? "Steam 下载与本地 CDN (直连)" : "Steam Downloads & CDN (Direct)",
          enabled: true,
          domain_suffix: [
            "steamserver.net",
            "steamcontent.com",
            "dl.steam.clngaa.com",
            "st.dl.eccdnx.com",
            "st.dl.bscstorage.net",
            "steampipe.akamaized.net",
          ],
          port_range: ["27015:27050"],
          outbound: "direct",
        },
        {
          id: "preset-steam-store-proxy",
          name: locale === "zh-CN" ? "Steam 登录/商店/社区 (代理)" : "Steam Login/Store/Community (Proxy)",
          enabled: true,
          domain_suffix: [
            "steampowered.com",
            "steamcommunity.com",
            "steamstatic.com",
            "steamcommunity-a.akamaihd.net",
            "steamgames.com",
            "steamusercontent.com",
            "s.team",
          ],
          outbound: "proxy",
        },
      ];
      setDraft((prev) => {
        const filtered = prev.custom_rules.filter(
          (r) => r.id !== "preset-steam-download-direct" && r.id !== "preset-steam-store-proxy",
        );
        return { ...prev, custom_rules: [...steamRules, ...filtered] };
      });
      notify(tr("routing.presetAdded", { name: tr("routing.presetSteam") }));
      return;
    }

    const lbGroup = groups.find((g) => {
      const s = (g.strategy || "").trim().toLowerCase();
      return s === "loadbalance" || s === "load-balance" || s === "hash";
    });
    const cdnRule: RoutingRule = {
      id: "preset-cdn-loadbalance",
      name: locale === "zh-CN" ? "CDN 与开源镜像并发均衡" : "CDN & Open-Source Mirrors (LB)",
      enabled: true,
      domain_suffix: [
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "crates.io",
        "static.crates.io",
      ],
      outbound: lbGroup ? lbGroup.id : "proxy",
    };
    setDraft((prev) => {
      const filtered = prev.custom_rules.filter((r) => r.id !== "preset-cdn-loadbalance");
      return { ...prev, custom_rules: [cdnRule, ...filtered] };
    });
    notify(tr("routing.presetAdded", { name: tr("routing.presetCdnLb") }));
  };

  const anchorItems = [
    { id: "routing-mode", label: tr("routing.anchorMode") },
    { id: "routing-dns", label: tr("routing.anchorDns") },
    ...(isAndroid ? [{ id: "routing-per-app", label: tr("routing.anchorPerApp") }] : []),
    { id: "routing-rules", label: tr("routing.anchorRules") },
  ];

  return (
    <div className="flex flex-col md:flex-row md:items-start gap-4">
      <div className="flex-1 min-w-0 space-y-5">
      {/* Unified Sticky Top Bar (Desktop sticky; mobile flows normally so it never clips under mobile header) */}
      <div className="md:sticky md:top-0 md:z-20 rounded-[10px] border border-border bg-card/95 px-3 py-2.5 backdrop-blur space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <Route className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="truncate text-base font-semibold text-foreground">{tr("routing.title")}</h2>
            {isDirty ? (
              <span className="shrink-0 whitespace-nowrap badge-radius border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                {tr("routing.unsavedBadge")}
              </span>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setQrModalOpen(true)}
            >
              <QrCode className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("routing.qrShareBtn")}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={isDefault || saving}
              onClick={handleResetDefault}
            >
              <RotateCcw className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("routing.resetDefault")}
            </Button>
            <Button
              type="button"
              size="sm"
              disabled={!isDirty || saving}
              onClick={() => void handleSave()}
              className="disabled:bg-muted disabled:text-muted-foreground disabled:border disabled:border-border disabled:opacity-100"
            >
              <Save className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("action.save")}
            </Button>
          </div>
        </div>
        <SectionAnchorBar embedded ariaLabel={tr("routing.anchorNav")} items={anchorItems} />
      </div>

      {/* Mode & Preset Switches & DNS */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section id="routing-mode" tabIndex={-1} className="scroll-mt-28 outline-none">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{tr("overview.mode")}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-2">
                {(
                  [
                    { id: "rule", label: tr("routing.modeRule") },
                    { id: "global", label: tr("routing.modeGlobal") },
                    { id: "direct", label: tr("routing.modeDirect") },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setDraft((prev) => ({ ...prev, mode: item.id }))}
                    className={[
                      "rounded-xl border px-3 py-2 text-xs font-semibold transition-colors",
                      draft.mode === item.id
                        ? "border-primary bg-primary/15 text-primary"
                        : "bg-background text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    {item.label}
                  </button>
                ))}
              </div>

              <div className="space-y-3 border-t pt-3">
                {!adsRuleReady || !cnRuleReady ? (
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-xs">
                    <span className="min-w-0 flex-1 leading-snug text-amber-700 dark:text-amber-300">
                      {tr("routing.srsSyncNeededDesc")}
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={syncingRuleSets}
                      onClick={() => void handleQuickSyncRuleSets()}
                      className="h-7 shrink-0 border-amber-500/40 bg-background/80 px-2.5 text-[11px]"
                    >
                      <RefreshCw className={`mr-1.5 h-3 w-3 ${syncingRuleSets ? "animate-spin" : ""}`} aria-hidden="true" />
                      {syncingRuleSets ? tr("routing.syncingSrs") : tr("routing.syncSrsNow")}
                    </Button>
                  </div>
                ) : null}
                <div className="flex items-center justify-between gap-2 text-sm">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className={!adsRuleReady ? "text-muted-foreground" : ""}>{tr("routing.blockAds")}</span>
                    {!adsRuleReady ? (
                      <span className="shrink-0 whitespace-nowrap badge-radius border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                        {tr("routing.srsRequiredBadge")}
                      </span>
                    ) : null}
                  </div>
                  <Switch
                    aria-label={tr("routing.blockAds")}
                    disabled={!adsRuleReady}
                    checked={adsRuleReady && draft.block_ads}
                    onCheckedChange={(checked) => setDraft((prev) => ({ ...prev, block_ads: checked }))}
                  />
                </div>
                <div className="flex items-center justify-between gap-2 text-sm">
                  <span>{tr("routing.bypassLan")}</span>
                  <Switch
                    aria-label={tr("routing.bypassLan")}
                    checked={draft.bypass_lan}
                    onCheckedChange={(checked) =>
                      setDraft((prev) => ({
                        ...prev,
                        bypass_lan: checked,
                        allow_lan_broadcast: checked ? Boolean(prev.allow_lan_broadcast) : false,
                      }))
                    }
                  />
                </div>
                <div className="flex items-center justify-between gap-3 rounded-lg border border-border/60 bg-muted/25 px-3 py-2 text-sm">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="font-medium text-foreground">{tr("routing.allowLanBroadcast")}</span>
                      <HelpTip
                        ariaLabel={tr("routing.allowLanBroadcast")}
                        text={tr("routing.allowLanBroadcastHint")}
                      />
                    </div>
                    <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
                      {tr("routing.allowLanBroadcastRequiresBypassLan")}
                    </p>
                  </div>
                  <Switch
                    className="shrink-0"
                    aria-label={tr("routing.allowLanBroadcast")}
                    checked={Boolean(draft.bypass_lan && draft.allow_lan_broadcast)}
                    onCheckedChange={(checked) =>
                      setDraft((prev) => ({
                        ...prev,
                        bypass_lan: checked ? true : prev.bypass_lan,
                        allow_lan_broadcast: checked,
                      }))
                    }
                  />
                </div>
                <div className="flex items-center justify-between gap-2 text-sm">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className={!cnRuleReady ? "text-muted-foreground" : ""}>{tr("routing.bypassCn")}</span>
                    {!cnRuleReady ? (
                      <span className="shrink-0 whitespace-nowrap badge-radius border border-amber-500/40 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                        {tr("routing.srsRequiredBadge")}
                      </span>
                    ) : null}
                  </div>
                  <Switch
                    aria-label={tr("routing.bypassCn")}
                    disabled={!cnRuleReady}
                    checked={cnRuleReady && draft.bypass_cn}
                    onCheckedChange={(checked) => setDraft((prev) => ({ ...prev, bypass_cn: checked }))}
                  />
                </div>
                <div className="flex items-center justify-between gap-3 border-t pt-3 text-sm">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className="font-medium text-foreground">{tr("routing.killSwitch")}</span>
                    <HelpTip ariaLabel={tr("routing.killSwitch")} text={tr("routing.killSwitchHint")} />
                  </div>
                  <Switch
                    className="shrink-0"
                    aria-label={tr("routing.killSwitch")}
                    checked={draft.kill_switch !== false}
                    onCheckedChange={(checked) => setDraft((prev) => ({ ...prev, kill_switch: checked }))}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section id="routing-dns" tabIndex={-1} className="scroll-mt-28 outline-none">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">DNS</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1">
                <label htmlFor={`${idPrefix}-local-dns`} className="text-xs font-medium text-muted-foreground">
                  {tr("routing.localDns")}
                </label>
                <Input
                  id={`${idPrefix}-local-dns`}
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={draft.local_dns}
                  onChange={(e) => setDraft((prev) => ({ ...prev, local_dns: e.target.value }))}
                />
              </div>
              <div className="space-y-1">
                <label htmlFor={`${idPrefix}-remote-dns`} className="text-xs font-medium text-muted-foreground">
                  {tr("routing.remoteDns")}
                </label>
                <Input
                  id={`${idPrefix}-remote-dns`}
                  autoCorrect="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  value={draft.remote_dns}
                  onChange={(e) => setDraft((prev) => ({ ...prev, remote_dns: e.target.value }))}
                />
              </div>
              <div className="space-y-1">
                <label htmlFor={`${idPrefix}-domain-strategy`} className="text-xs font-medium text-muted-foreground">
                  {tr("routing.domainStrategy")}
                </label>
                <Select
                  id={`${idPrefix}-domain-strategy`}
                  value={draft.domain_strategy || "prefer_ipv4"}
                  onChange={(e) => setDraft((prev) => ({ ...prev, domain_strategy: e.target.value }))}
                >
                  <option value="prefer_ipv4">prefer_ipv4</option>
                  <option value="prefer_ipv6">prefer_ipv6</option>
                  <option value="ipv4_only">ipv4_only</option>
                  <option value="ipv6_only">ipv6_only</option>
                </Select>
              </div>

            <div className="space-y-3 border-t pt-3">
              <div className="flex items-center justify-between gap-2 text-sm">
                <span className="min-w-0">{tr("routing.hijackDns")}</span>
                <Switch
                  aria-label={tr("routing.hijackDns")}
                  checked={draft.hijack_dns !== false}
                  onCheckedChange={(checked) => setDraft((prev) => ({ ...prev, hijack_dns: checked }))}
                />
              </div>

              <div className="flex items-center justify-between gap-3 text-sm">
                <div className="flex min-w-0 items-center gap-1.5">
                  <span>{tr("routing.fakeIp")}</span>
                  <HelpTip ariaLabel={tr("routing.fakeIp")} text={tr("routing.fakeIpHint")} />
                </div>
                <Switch
                  className="shrink-0"
                  aria-label={tr("routing.fakeIp")}
                  checked={Boolean(draft.fake_ip)}
                  onCheckedChange={(checked) => setDraft((prev) => ({ ...prev, fake_ip: checked }))}
                />
              </div>

              {draft.fake_ip ? (
                <div className="space-y-1">
                  <label htmlFor={`${idPrefix}-fakeip-filter`} className="block text-xs font-medium text-muted-foreground">
                    {tr("routing.fakeIpFilter")}
                  </label>
                  <Input
                    id={`${idPrefix}-fakeip-filter`}
                    className="font-mono text-xs"
                    autoCorrect="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    placeholder=".lan, .ts.net, pool.ntp.org"
                    value={(draft.fake_ip_filter || []).join(", ")}
                    onChange={(e) => setDraft((prev) => ({ ...prev, fake_ip_filter: splitCSV(e.target.value) }))}
                  />
                </div>
              ) : null}

              <div className="space-y-1.5 border-t pt-3">
                <div className="flex items-center gap-1.5">
                  <label htmlFor={`${idPrefix}-webrtc-mode`} className="block text-xs font-medium text-foreground">
                    {tr("routing.webrtcTitle")}
                  </label>
                  <HelpTip ariaLabel={tr("routing.webrtcTitle")} text={tr("routing.webrtcDesc")} />
                </div>
                <Select
                  id={`${idPrefix}-webrtc-mode`}
                  value={draft.webrtc_mode || "block"}
                  onChange={(e) =>
                    setDraft((prev) => ({ ...prev, webrtc_mode: e.target.value as "block" | "proxy" | "direct" }))
                  }
                >
                  <option value="block">{tr("overview.webrtcBlock")}</option>
                  <option value="proxy">{tr("overview.webrtcProxy")}</option>
                  <option value="direct">{tr("overview.webrtcDirect")}</option>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>
        </section>
      </div>

      {/* Android Per-App Proxy (placed directly above Custom Rules on mobile/Android) */}
      {isAndroid ? (
        <section id="routing-per-app" tabIndex={-1} className="scroll-mt-28 outline-none">
          <PerAppProxyCard
            mode={draft.per_app_mode || "all"}
            packages={draft.per_app_packages || []}
            onChangeMode={(nextMode) => setDraft((prev) => ({ ...prev, per_app_mode: nextMode }))}
            onChangePackages={(nextPackages) =>
              setDraft((prev) => ({ ...prev, per_app_packages: nextPackages }))
            }
          />
        </section>
      ) : null}

      {/* Ordered Compact Custom Rules */}
      <section id="routing-rules" tabIndex={-1} className="scroll-mt-28 outline-none">
      <p role="status" className="visually-hidden">
        {reorderStatus}
      </p>
      <Card>
        <CardHeader className="flex flex-col gap-2 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-1.5">
            <CardTitle className="text-base">{tr("routing.customRules")} ({draft.custom_rules.length})</CardTitle>
            <HelpTip ariaLabel={tr("routing.customRules")} text={tr("routing.compactHint")} />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div ref={presetsMenuRef} className="relative">
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-expanded={presetsOpen}
                onClick={() => setPresetsOpen((v) => !v)}
              >
                <Sparkles className="mr-1.5 h-3.5 w-3.5 text-primary" aria-hidden="true" />
                <span>{tr("routing.presetsBtn")}</span>
                <ChevronDown className="ml-1 h-3.5 w-3.5 opacity-70" aria-hidden="true" />
              </Button>
              {presetsOpen ? (
                <div
                  role="menu"
                  className="hidden md:block absolute right-0 top-full z-30 mt-1 w-80 max-w-[calc(100vw-24px)] rounded-[10px] border border-border bg-popover p-1.5 text-popover-foreground shadow-sm"
                >
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => applyRulePreset("google")}
                    className="w-full rounded-[6px] px-2.5 py-2 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetGoogle")}</div>
                    <div className="mt-0.5 text-[11px] text-muted-foreground">{tr("routing.presetGoogleDesc")}</div>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => applyRulePreset("steam")}
                    className="mt-0.5 w-full rounded-[6px] px-2.5 py-2 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetSteam")}</div>
                    <div className="mt-0.5 text-[11px] text-muted-foreground">{tr("routing.presetSteamDesc")}</div>
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => applyRulePreset("cdn")}
                    className="mt-0.5 w-full rounded-[6px] px-2.5 py-2 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetCdnLb")}</div>
                    <div className="mt-0.5 text-[11px] text-muted-foreground">{tr("routing.presetCdnLbDesc")}</div>
                  </button>
                </div>
              ) : null}
              <BottomSheetDialog
                open={presetsOpen && typeof window !== "undefined" && window.matchMedia("(max-width: 767px)").matches}
                title={tr("routing.presetsBtn")}
                onClose={() => setPresetsOpen(false)}
              >
                <div className="space-y-2">
                  <button
                    type="button"
                    onClick={() => applyRulePreset("google")}
                    className="w-full rounded-[8px] border border-border bg-card px-3 py-2.5 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetGoogle")}</div>
                    <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                      {tr("routing.presetGoogleDesc")}
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => applyRulePreset("steam")}
                    className="w-full rounded-[8px] border border-border bg-card px-3 py-2.5 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetSteam")}</div>
                    <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                      {tr("routing.presetSteamDesc")}
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={() => applyRulePreset("cdn")}
                    className="w-full rounded-[8px] border border-border bg-card px-3 py-2.5 text-left transition-colors hover:bg-muted"
                  >
                    <div className="text-xs font-semibold text-foreground">{tr("routing.presetCdnLb")}</div>
                    <div className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                      {tr("routing.presetCdnLbDesc")}
                    </div>
                  </button>
                </div>
              </BottomSheetDialog>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={openAddRuleModal}>
              <Plus className="mr-1.5 h-4 w-4" aria-hidden="true" />
              {tr("routing.addRule")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {draft.custom_rules.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground">
              {locale === "zh-CN" ? "暂无自定义规则，将按内置规则与 DNS 策略执行。" : "No custom rules configured."}
            </p>
          ) : (
            <div ref={listRef} className="space-y-1.5">
              {draft.custom_rules.map((rule, idx) => {
                const ruleLabel = rule.name || `Rule #${idx + 1}`;
                const condPills = summarizeRuleConditions(rule);
                const resolvedGroup = groups.find((g) => g.id === rule.outbound);
                const resolvedNode = nodes.find((n) => n.id === rule.outbound);
                const targetLabel =
                  rule.outbound === "proxy"
                    ? tr("routing.outboundMainProxy")
                    : rule.outbound === "direct"
                      ? tr("routing.outboundDirect")
                      : rule.outbound === "block"
                        ? tr("routing.outboundBlock")
                        : resolvedGroup
                          ? `${tr("settings.targetGroupPrefix")}: ${resolvedGroup.name}`
                          : resolvedNode
                            ? `${tr("settings.targetNodePrefix")}: ${resolvedNode.user_alias || resolvedNode.name}`
                            : rule.outbound;
                const outboundTone =
                  rule.outbound === "block"
                    ? "bg-destructive/15 text-destructive"
                    : rule.outbound === "direct"
                      ? "bg-muted text-foreground"
                      : "bg-primary/15 text-primary";

                const selected = ruleModalOpen && editingRuleIdx === idx;
                return (
                  <SwipeActionRow
                    key={rule.id || idx}
                    className={`rounded-[6px] border transition-colors ${
                      selected ? "border-primary bg-accent/50" : "border-border bg-background/70"
                    } ${dragIndex === idx ? "rule-row-dragging" : ""} ${!rule.enabled ? "opacity-60" : ""}`}
                    actions={[
                      {
                        key: "edit",
                        label: tr("action.edit"),
                        icon: <Pencil className="h-4 w-4" />,
                        tone: "primary",
                        onClick: () => openEditRuleModal(idx),
                      },
                      {
                        key: "delete",
                        label: tr("action.delete"),
                        icon: <Trash2 className="h-4 w-4" />,
                        tone: "danger",
                        onClick: () => removeRule(idx),
                      },
                    ]}
                  >
                  <div
                    data-rule-row={idx}
                    onPointerDown={(e) => handleRowPointerDown(idx, e)}
                    className="dense-row flex flex-wrap items-center gap-2 px-2.5 py-1.5 text-xs select-none hover:bg-muted/35"
                  >
                    <button
                      type="button"
                      onPointerDown={(e) => {
                        e.stopPropagation();
                        startDrag(idx);
                      }}
                      aria-label={`${tr("routing.dragHandle")} ${ruleLabel}`}
                      title={tr("routing.dragHandle")}
                      className="inline-flex h-7 w-7 shrink-0 cursor-grab items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground active:cursor-grabbing"
                    >
                      <GripVertical className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>

                    <span className="w-6 shrink-0 mono-num text-[11px] font-semibold text-muted-foreground">
                      #{idx + 1}
                    </span>

                    <div className="min-w-32 flex-1 space-y-0.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="font-semibold text-foreground">{ruleLabel}</span>
                        {rule.invert ? (
                          <span className="badge-radius bg-amber-500/15 px-1.5 py-0.5 mono-num text-[10px] font-semibold text-amber-400">
                            INVERT
                          </span>
                        ) : null}
                      </div>
                      <div className="flex flex-wrap items-center gap-1">
                        {condPills.slice(0, 3).map((pill, pIdx) => (
                          <span
                            key={pIdx}
                            className="max-w-40 truncate badge-radius bg-muted px-1.5 py-0.5 mono-num text-[10px] text-muted-foreground"
                            title={pill}
                          >
                            {pill}
                          </span>
                        ))}
                        {condPills.length > 3 ? (
                          <span className="badge-radius bg-muted px-1.5 py-0.5 mono-num text-[10px] text-muted-foreground">
                            +{condPills.length - 3}
                          </span>
                        ) : null}
                        {condPills.length === 0 ? (
                          <span className="text-[10px] text-muted-foreground/70 mono-num">match-all</span>
                        ) : null}
                      </div>
                    </div>

                    <span className={`shrink-0 badge-radius px-2 py-0.5 text-[11px] font-semibold ${outboundTone}`}>
                      {targetLabel}
                    </span>

                    <div className="flex shrink-0 items-center gap-1">
                      <Switch
                        aria-label={`Enable ${ruleLabel}`}
                        checked={rule.enabled}
                        onCheckedChange={(checked) => updateRule(idx, { enabled: checked })}
                      />
                      <button
                        type="button"
                        onClick={() => openEditRuleModal(idx)}
                        aria-label={`${tr("action.edit")} ${ruleLabel}`}
                        className="hidden md:inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground"
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => moveRule(idx, -1)}
                        disabled={idx === 0}
                        aria-label={`Move ${ruleLabel} up`}
                        className="inline-flex h-7 w-7 max-md:min-h-10 max-md:min-w-10 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted disabled:opacity-40"
                      >
                        <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => moveRule(idx, 1)}
                        disabled={idx === draft.custom_rules.length - 1}
                        aria-label={`Move ${ruleLabel} down`}
                        className="inline-flex h-7 w-7 max-md:min-h-10 max-md:min-w-10 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted disabled:opacity-40"
                      >
                        <ArrowDown className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => removeRule(idx)}
                        aria-label={`${tr("action.delete")} ${ruleLabel}`}
                        className="hidden md:inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                  </SwipeActionRow>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
      </section>
      </div>

      {/* Right Context Inspector for Rule Editor */}
      <ContextInspector
        open={ruleModalOpen}
        title={
          editingRuleIdx !== null
            ? `${tr("routing.editRule")} — ${draft.custom_rules[editingRuleIdx]?.name || `#${editingRuleIdx + 1}`}`
            : tr("routing.addRule")
        }
        subtitle={tr("inspector.ruleTitle")}
        onClose={() => {
          setRuleModalOpen(false);
          setEditingRuleIdx(null);
        }}
      >
        <RuleEditorForm
          key={editingRuleIdx !== null ? draft.custom_rules[editingRuleIdx]?.id || String(editingRuleIdx) : "new-rule"}
          embedded
          initialRule={editingRuleIdx !== null ? draft.custom_rules[editingRuleIdx] || null : null}
          isAndroid={isAndroid}
          nodes={nodes}
          groups={groups}
          listeners={listeners}
          onClose={() => {
            setRuleModalOpen(false);
            setEditingRuleIdx(null);
          }}
          onSave={handleModalSave}
        />
      </ContextInspector>

      <RoutingQrModal
        open={qrModalOpen}
        profile={draft}
        onClose={() => setQrModalOpen(false)}
        onImported={async (importedProfile) => {
          setDraft(importedProfile);
          await api.saveRouting(importedProfile);
          await refreshAll();
        }}
      />
    </div>
  );
}
