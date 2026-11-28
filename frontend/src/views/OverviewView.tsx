// SPDX-License-Identifier: MPL-2.0

import { Suspense, lazy, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Copy,
  Globe,
  Network,
  Power,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import {
  androidBridge,
  api,
  formatApiError,
  isAndroidClient,
  type ListenConfig,
  type RoutingProfile,
  type SystemTailscaleInfo,
  type TailscaleConfig,
  type TailscalePeerStatus,
  type TailscalePingResult,
  type TailscaleRuntimeStatus,
  type TrafficHistoryResponse,
} from "../lib/api.ts";
import { formatBytes, formatRate } from "../lib/helpers.ts";
import { useAppStore, useTrafficTelemetry } from "../store/appStore.ts";
import { ProfileSwitcher } from "../components/ProfileSwitcher.tsx";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Select } from "../components/ui/select.tsx";
import { Switch } from "../components/ui/switch.tsx";

const LiveTrafficChart = lazy(() => import("../components/LiveTrafficChart.tsx"));
const TrafficHistoryChart = lazy(() => import("../components/TrafficHistoryChart.tsx"));

const DEFAULT_ROUTING_BASE: RoutingProfile = {
  mode: "rule",
  block_ads: true,
  bypass_lan: true,
  allow_lan_broadcast: false,
  bypass_cn: true,
  webrtc_mode: "block",
  local_dns: "223.5.5.5",
  remote_dns: "https://1.1.1.1/dns-query",
  custom_rules_enabled: true,
  custom_rules: [],
};

export function OverviewView({ isActive = true }: { isActive?: boolean } = {}) {
  const {
    tr,
    locale,
    status,
    isProxyRunning,
    isTunActive,
    nodes,
    groups,
    listeners,
    routing,
    tunState,
    systemProxyEnabled,
    busy,
    toggleConnect,
    toggleTUN,
    toggleSystemProxy,
    refreshAll,
    notify,
    navigateTo,
  } = useAppStore();
  const { trafficNow, trafficHistory } = useTrafficTelemetry();

  const [authorizing, setAuthorizing] = useState(false);
  const [tsConfig, setTsConfig] = useState<TailscaleConfig | null>(null);
  const [tsStateInit, setTsStateInit] = useState(false);
  const [tsStatus, setTsStatus] = useState<TailscaleRuntimeStatus | null>(null);
  const [sysTailscale, setSysTailscale] = useState<SystemTailscaleInfo | null>(null);
  const [tsBusy, setTsBusy] = useState(false);
  const [tsRefreshing, setTsRefreshing] = useState(false);
  const [exitNodeBusyId, setExitNodeBusyId] = useState<string | null>(null);
  const [taildropBusyId, setTaildropBusyId] = useState<string | null>(null);
  const taildropPeerRef = useRef<string>("");
  const taildropInputRef = useRef<HTMLInputElement | null>(null);
  const [peerPings, setPeerPings] = useState<Record<string, { busy?: boolean; result?: TailscalePingResult; err?: string }>>({});
  const [trafficFilter, setTrafficFilter] = useState<"all" | "proxy" | "direct">("all");
  const [trafficRange, setTrafficRange] = useState<"live" | "24h" | "7d" | "30d">("live");
  const [historyData, setHistoryData] = useState<TrafficHistoryResponse | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    if (!isActive || trafficRange === "live") return;
    let cancelled = false;
    setHistoryLoading(true);
    api
      .getTrafficHistory(trafficRange)
      .then((res) => {
        if (!cancelled) setHistoryData(res);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setHistoryLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isActive, trafficRange]);

  const handleClearTrafficHistory = async () => {
    try {
      await api.clearTrafficHistory();
      if (trafficRange !== "live") {
        const res = await api.getTrafficHistory(trafficRange);
        setHistoryData(res);
      }
      notify(tr("overview.trafficHistoryCleared"));
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handlePingTailscalePeer = async (ip: string) => {
    if (!ip) return;
    setPeerPings((prev) => ({ ...prev, [ip]: { busy: true } }));
    try {
      const res = await api.pingTailscalePeer(ip, 3);
      setPeerPings((prev) => ({ ...prev, [ip]: { busy: false, result: res, err: res.error || undefined } }));
    } catch (err) {
      setPeerPings((prev) => ({ ...prev, [ip]: { busy: false, err: formatApiError(err) } }));
    }
  };

  const copyText = async (value: string) => {
    const clean = value.trim();
    if (!clean) return;
    try {
      if (window.PrismRayAndroid?.copyToClipboard?.(clean)) {
        notify(tr("toast.copied"));
        return;
      }
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(clean);
        notify(tr("toast.copied"));
      }
    } catch {
      // Ignore clipboard errors.
    }
  };

  const refreshTailscaleNow = async () => {
    setTsRefreshing(true);
    try {
      const res = await api.getTailscale();
      setTsConfig(res.config);
      setTsStateInit(Boolean(res.state_initialized));
      setTsStatus(res.status || null);
      setSysTailscale(res.system_tailscale || null);
    } catch {
      // Ignore transient errors.
    } finally {
      setTsRefreshing(false);
    }
  };

  const handleQuickTogglePeerExitNode = async (peer: TailscalePeerStatus) => {
    const stableId = peer.stable_id || "";
    if (!stableId) return;
    const isCurrentExit = Boolean(peer.exit_node || (tsStatus?.active_exit_node_id && tsStatus.active_exit_node_id === stableId));
    setExitNodeBusyId(stableId);
    try {
      const nextId = isCurrentExit ? "" : stableId;
      const nextVal = isCurrentExit ? "" : peer.ipv4 || peer.dns_name || peer.hostname || "";
      const res = await api.setTailscaleExitNode({ stable_id: nextId, exit_node: nextVal });
      setTsConfig(res.config);
      if (res.status) setTsStatus(res.status);
      notify(isCurrentExit ? tr("tailscale.exitNodeCleared") : tr("tailscale.exitNodeSwitched"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setExitNodeBusyId(null);
    }
  };

  const handleOpenPeerTaildrop = (peerStableId: string) => {
    if (!peerStableId) return;
    taildropPeerRef.current = peerStableId;
    if (taildropInputRef.current) {
      taildropInputRef.current.value = "";
      taildropInputRef.current.click();
    }
  };

  const handlePeerTaildropFileSelected = async (file: File | undefined) => {
    const peerId = taildropPeerRef.current;
    if (!file || !peerId) return;
    setTaildropBusyId(peerId);
    try {
      const res = await api.sendTaildropFile(peerId, file);
      notify(tr("tailscale.taildropSent", { name: res.file_name || file.name }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setTaildropBusyId(null);
      taildropPeerRef.current = "";
    }
  };

  useEffect(() => {
    if (!isActive) return;
    let cancelled = false;
    const fetchTs = () => {
      api
        .getTailscale()
        .then((res) => {
          if (cancelled) return;
          setTsConfig(res.config);
          setTsStateInit(Boolean(res.state_initialized));
          setTsStatus(res.status || null);
          setSysTailscale(res.system_tailscale || null);
        })
        .catch(() => {
          // Ignore transient fetch errors while locked.
        });
    };
    fetchTs();
    if (!tsConfig?.enabled) {
      return () => {
        cancelled = true;
      };
    }
    const pollMs =
      tsStatus?.state === "connecting" || tsStatus?.state === "needs_auth" ? 3000 : 10000;
    const timer = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      fetchTs();
    }, pollMs);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isActive, status?.running, tsConfig?.enabled, tsStatus?.state]);

  const handleToggleTailscale = async (enabled: boolean) => {
    const base: TailscaleConfig = tsConfig || {
      enabled: false,
      accept_routes: true,
      magic_dns: true,
      udp_timeout: "5m",
    };
    if (enabled && !base.has_auth_key && !tsStateInit) {
      notify(tr("overview.tailscaleNeedSetup"), "warning");
      navigateTo("routing", "routing-tailscale");
      return;
    }
    setTsBusy(true);
    try {
      const payload: TailscaleConfig = { ...base, enabled };
      delete payload.auth_key;
      delete payload.has_auth_key;
      delete payload.clear_auth_key;
      const res = await api.saveTailscale(payload);
      setTsConfig(res.config);
      setTsStateInit(Boolean(res.state_initialized));
      setTsStatus(res.status || null);
      if (androidBridge.available()) {
        androidBridge.refreshQuickTiles();
        if (androidBridge.getVpnStatus()?.active && routing?.allow_lan_broadcast) {
          androidBridge.prepareAndStartVpn({
            per_app_mode: routing?.per_app_mode || "all",
            per_app_packages: routing?.per_app_packages || [],
            bypass_lan: routing?.bypass_lan,
            allow_lan_broadcast: routing?.allow_lan_broadcast,
          });
        }
      }
      await refreshAll();
      notify(enabled ? tr("overview.tailscaleEnabledToast") : tr("overview.tailscaleDisabledToast"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setTsBusy(false);
    }
  };

  const tsDotClass = (() => {
    if (!tsConfig?.enabled) return "bg-muted-foreground/50";
    switch (tsStatus?.state) {
      case "connected":
        return "bg-emerald-500 status-radar-dot";
      case "connecting":
      case "needs_auth":
        return "bg-amber-500 animate-pulse";
      case "error":
        return "bg-destructive";
      default:
        return "bg-muted-foreground";
    }
  })();

  const tsSummaryText = (() => {
    if (!tsConfig?.enabled) return tr("overview.tailscaleOff");
    switch (tsStatus?.state) {
      case "connected":
        if (tsStatus.ipv4 && (tsStatus.peers_total ?? 0) > 0) {
          return tr("overview.tailscaleConnectedPeers", {
            ip: tsStatus.ipv4,
            online: tsStatus.peers_online ?? 0,
            total: tsStatus.peers_total ?? 0,
          });
        }
        if (tsStatus.ipv4) {
          return `${tr("tailscale.statusConnected")} · ${tsStatus.ipv4}`;
        }
        return tsStatus.hostname?.trim()
          ? tr("overview.tailscaleOn", { name: tsStatus.hostname.trim() })
          : tr("tailscale.statusConnected");
      case "connecting":
        return tr("overview.tailscaleConnecting");
      case "needs_auth":
        return tr("overview.tailscaleNeedsAuth");
      case "error":
        return tr("overview.tailscaleError");
      case "stopped":
        return tr("overview.tailscaleStandby");
      default:
        return tsConfig.hostname?.trim()
          ? tr("overview.tailscaleOn", { name: tsConfig.hostname.trim() })
          : tr("overview.tailscaleOnDefault");
    }
  })();

  const isAndroid = isAndroidClient();
  const activeGroup = groups.find((g) => g.id === status?.active_group_id);
  const activeNode = nodes.find((n) => n.id === status?.active_node_id);
  const resolvedGroupMember =
    activeNode || (activeGroup?.selected_node_id ? nodes.find((n) => n.id === activeGroup.selected_node_id) : undefined);

  const strategyLabel = (strategy?: string) => {
    const s = (strategy || "").trim().toLowerCase();
    if (s === "urltest") return tr("overview.exitStrategyUrlTest");
    if (s === "failover") return tr("overview.exitStrategyFailover");
    if (s === "loadbalance" || s === "load-balance" || s === "hash") return tr("overview.exitStrategyLoadBalance");
    return tr("overview.exitStrategySelector");
  };

  const isLoadBalanceGroup = (strategy?: string) => {
    const s = (strategy || "").trim().toLowerCase();
    return s === "loadbalance" || s === "load-balance" || s === "hash";
  };

  const activeLabel = activeGroup
    ? `[${tr("overview.exitTypeGroup")}] ${activeGroup.name}`
    : activeNode
      ? `[${tr("overview.exitTypeNode")}] ${activeNode.user_alias || activeNode.name}`
      : status?.active_tag || tr("overview.noneSelected");

  const currentMode = routing?.mode || status?.mode || "rule";
  const currentWebRTC = routing?.webrtc_mode || "block";

  const handleAuthorizeTun = async () => {
    setAuthorizing(true);
    try {
      await api.authorizeTUN();
      await refreshAll();
      notify(locale === "zh-CN" ? "TUN 权限状态已更新" : "TUN authorization updated");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setAuthorizing(false);
    }
  };

  const killSwitchEnabled = routing ? routing.kill_switch !== false : status?.kill_switch_enabled !== false;

  const updateRoutingPatch = async (patch: Partial<RoutingProfile>, successMessage: string) => {
    try {
      const base = routing || { ...DEFAULT_ROUTING_BASE, mode: status?.mode || "rule" };
      await api.saveRouting({ ...base, ...patch });
      await refreshAll();
      notify(successMessage);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleToggleKillSwitch = async (enabled: boolean) => {
    await updateRoutingPatch(
      { kill_switch: enabled },
      enabled
        ? locale === "zh-CN"
          ? "已开启节点异常自动断网保护"
          : "Kill Switch enabled"
        : locale === "zh-CN"
          ? "已关闭节点异常自动断网保护"
          : "Kill Switch disabled",
    );
  };

  const resolveInboundTarget = (l: ListenConfig) => {
    const raw = (l.target_outbound || "").trim().toLowerCase();
    if (raw === "direct") {
      return tr("settings.targetDirect");
    }
    if (l.target_group_id) {
      const grp = groups.find((g) => g.id === l.target_group_id);
      return `${tr("settings.targetGroupPrefix")}: ${grp?.name || l.target_group_id}`;
    }
    if (l.node_ids && l.node_ids.length > 0) {
      const names = l.node_ids.map((id) => {
        const nd = nodes.find((n) => n.id === id);
        return nd ? nd.user_alias || nd.name : id;
      });
      if (names.length > 1) {
        return `${tr("settings.targetNodePrefix")} (${names.length}): ${names.join(", ")}`;
      }
      return `${tr("settings.targetNodePrefix")}: ${names[0]}`;
    }
    return `${tr("settings.targetDefaultProxy")} · ${activeLabel}`;
  };

  return (
    <div className="space-y-6">
      {/* Hero Control Card */}
      <Card className={`prism-hero-surface border-border ${isProxyRunning ? "is-running" : ""}`}>
        <CardContent className="flex flex-col gap-4 p-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={[
                  "inline-flex min-h-8 items-center gap-1.5 overflow-hidden badge-radius border px-2.5 py-1 text-xs font-semibold leading-normal tabular-nums",
                  isProxyRunning
                    ? "border-primary/30 bg-primary/15 text-primary"
                    : "border-border bg-muted text-muted-foreground",
                ].join(" ")}
              >
                <span
                  className={[
                    "h-1.5 w-1.5 shrink-0 rounded-full",
                    isProxyRunning ? "bg-primary status-radar-dot" : "bg-muted-foreground",
                  ].join(" ")}
                  aria-hidden="true"
                />
                <span className="inline-flex items-center">{busy ? tr("status.connecting") : isProxyRunning ? tr("status.running") : tr("status.stopped")}</span>
              </span>

              <span className="badge-radius inline-flex min-h-8 flex-wrap items-center gap-1.5 border border-border bg-muted/40 px-2.5 py-1 text-xs leading-normal text-muted-foreground tabular-nums">
                <span className="inline-flex items-center">{tr("overview.activeTarget")}:</span>
                {activeGroup ? (
                  <>
                    <span className="inline-flex h-5 items-center rounded bg-accent px-1.5 text-[11px] font-medium leading-none text-primary">
                      {tr("overview.exitTypeGroup")} · {strategyLabel(activeGroup.strategy)}
                    </span>
                    <strong className="inline-flex items-center font-semibold text-foreground">{activeGroup.name}</strong>
                    {isLoadBalanceGroup(activeGroup.strategy) ? (
                      <span className="inline-flex items-center text-xs text-muted-foreground">
                        →{" "}
                        {tr("overview.lbShardsSummary", {
                          count: Math.min(
                            activeGroup.load_balance_shards && activeGroup.load_balance_shards > 0
                              ? activeGroup.load_balance_shards
                              : 4,
                            activeGroup.node_ids.length,
                          ),
                        })}
                      </span>
                    ) : status?.active_resolved_node_name || resolvedGroupMember ? (
                      <span className="inline-flex items-center text-xs text-muted-foreground">
                        → {status?.active_resolved_node_name || resolvedGroupMember?.user_alias || resolvedGroupMember?.name}
                      </span>
                    ) : null}
                  </>
                ) : activeNode ? (
                  <>
                    <span className="inline-flex h-5 items-center rounded border border-border bg-background px-1.5 text-[11px] font-medium leading-none text-foreground">
                      {tr("overview.exitTypeNode")}
                    </span>
                    <strong className="inline-flex items-center font-semibold text-foreground">{activeNode.user_alias || activeNode.name}</strong>
                  </>
                ) : (
                  <strong className="inline-flex items-center font-semibold text-foreground">{activeLabel}</strong>
                )}
              </span>
            </div>

            <div>
              <h2 className="text-lg font-semibold tracking-tight text-foreground">{tr("overview.heroTitle")}</h2>
              <p className="text-xs text-muted-foreground">{tr("overview.heroSubtitle")}</p>
            </div>
          </div>

          <div className="flex min-w-0 max-w-full flex-col gap-2.5 sm:flex-row sm:flex-wrap sm:items-center">
            <ProfileSwitcher compact />
            <div
              role="group"
              aria-label={tr("overview.mode")}
              className="grid w-full grid-cols-3 rounded-[6px] border border-border bg-background p-0.5 text-xs sm:inline-flex sm:w-auto sm:flex-nowrap"
            >
              {(["rule", "global", "direct"] as const).map((m) => {
                const selected = currentMode === m;
                const fullLabel =
                  m === "rule" ? tr("routing.modeRule") : m === "global" ? tr("routing.modeGlobal") : tr("routing.modeDirect");
                const shortLabel =
                  m === "rule"
                    ? tr("routing.modeRuleShort")
                    : m === "global"
                      ? tr("routing.modeGlobalShort")
                      : tr("routing.modeDirectShort");
                return (
                  <button
                    key={m}
                    type="button"
                    disabled={busy}
                    aria-pressed={selected}
                    onClick={() =>
                      void updateRoutingPatch(
                        { mode: m },
                        locale === "zh-CN" ? `路由模式已切换为 ${fullLabel}` : `Routing mode switched to ${fullLabel}`,
                      )
                    }
                    className={[
                      "rounded-[4px] px-2 py-1 text-center max-md:min-h-[var(--m-btn-sm-h)] sm:px-2.5 font-medium transition-colors whitespace-nowrap truncate",
                      selected
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    <span className="sm:hidden">{shortLabel}</span>
                    <span className="hidden sm:inline">{fullLabel}</span>
                  </button>
                );
              })}
            </div>

            <Button
              type="button"
              size="lg"
              variant={isProxyRunning ? "destructive" : "default"}
              disabled={busy}
              onClick={() => void toggleConnect()}
              className="min-w-32 shrink-0 rounded-[6px]"
            >
              <Power className="mr-2 h-4 w-4" aria-hidden="true" />
              {isProxyRunning ? tr("action.disconnect") : tr("action.connect")}
            </Button>
          </div>
        </CardContent>

        {status?.last_error ? (
          <div className="border-t border-destructive/30 bg-destructive/10 px-6 py-3 text-xs text-destructive">
            {status.last_error}
          </div>
        ) : null}
      </Card>

      {/* Kill Switch Tripped Banner */}
      {status?.kill_switch_tripped ? (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-[10px] border border-destructive/40 bg-destructive/10 p-3.5 text-sm text-destructive"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <div className="space-y-0.5">
            <div className="font-semibold">{tr("overview.killSwitchTripped")}</div>
            {status.kill_switch_reason ? <div className="text-xs opacity-90">{status.kill_switch_reason}</div> : null}
          </div>
        </div>
      ) : null}

      {/* Skipped NaiveProxy warning */}
      {status?.skipped_naive && status.skipped_naive.length > 0 ? (
        <div
          role="alert"
          className="flex items-start gap-3 rounded-[10px] border border-amber-500/40 bg-amber-500/10 p-3.5 text-sm text-foreground"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" aria-hidden="true" />
          <div className="space-y-1">
            <div className="font-medium">{tr("overview.naiveWarning")}</div>
            <div className="text-xs text-muted-foreground">{status.skipped_naive.join(", ")}</div>
          </div>
        </div>
      ) : null}

      {/* Quick Toggles Row: 3+2 balanced two-row layout on PC, 4-card grid on Android */}
      {(() => {
        const tunCard = (
          <Card className="prism-surface h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <Shield className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                  <div className="min-w-0">
                    <CardTitle className="text-sm font-semibold">{tr("overview.tunVpn")}</CardTitle>
                    <CardDescription className="text-xs">
                      {isAndroid
                        ? "Android VpnService · Full TUN"
                        : tunState?.privilege?.os === "darwin"
                          ? `macOS utun · ${tunState?.stack || "mixed"}`
                          : `prismray0 · ${tunState?.stack || "mixed"}`}
                    </CardDescription>
                  </div>
                </div>
                <Switch
                  aria-label={tr("overview.tunVpn")}
                  checked={isTunActive}
                  disabled={busy}
                  onCheckedChange={(checked) => void toggleTUN(checked)}
                />
              </div>
            </CardHeader>
            {!isAndroid &&
            (tunState?.privilege?.os === "linux" || tunState?.privilege?.os === "darwin") &&
            !tunState.privilege.ready_without_password ? (
              <CardContent className="space-y-2 pt-0">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={authorizing}
                  onClick={() => void handleAuthorizeTun()}
                >
                  <ShieldCheck className="mr-2 h-4 w-4" aria-hidden="true" />
                  {tr("overview.authorizeTun")}
                </Button>
                {tunState.privilege.os === "darwin" ? (
                  <p className="text-[11px] leading-snug text-muted-foreground">
                    {tr("overview.macosUtunHint")}
                  </p>
                ) : null}
              </CardContent>
            ) : !isAndroid && tunState?.privilege?.os === "darwin" ? (
              <CardContent className="pt-0">
                <p className="text-[11px] leading-snug text-muted-foreground">
                  {tr("overview.macosUtunHint")}
                </p>
              </CardContent>
            ) : !isAndroid &&
              tunState?.privilege?.os === "windows" &&
              !tunState.privilege.ready_without_password ? (
              <CardContent className="pt-0">
                <p className="text-[11px] leading-snug text-amber-600 dark:text-amber-400">
                  {tr("overview.windowsAdminTunHint")}
                </p>
              </CardContent>
            ) : null}
          </Card>
        );

        const sysProxyCard = (
          <Card className="prism-surface h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <Globe className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                  <div className="min-w-0">
                    <CardTitle className="text-sm font-semibold">{tr("overview.systemProxy")}</CardTitle>
                    <CardDescription className="text-xs tabular-nums">
                      {tr("overview.mixedPort")}: {status?.mixed_port || 10808}
                    </CardDescription>
                  </div>
                </div>
                <Switch
                  aria-label={tr("overview.systemProxy")}
                  checked={systemProxyEnabled}
                  disabled={busy}
                  onCheckedChange={(checked) => void toggleSystemProxy(checked)}
                />
              </div>
            </CardHeader>
            {isTunActive && systemProxyEnabled ? (
              <CardContent className="pt-0">
                <p className="text-[11px] leading-snug text-muted-foreground">
                  {tr("overview.tunAndSysProxyHint")}
                </p>
              </CardContent>
            ) : null}
          </Card>
        );

        const killSwitchCard = (
          <Card className={`prism-surface h-full ${status?.kill_switch_tripped ? "border-destructive/50" : ""}`}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <ShieldAlert
                    className={`h-5 w-5 shrink-0 ${status?.kill_switch_tripped ? "text-destructive" : "text-primary"}`}
                    aria-hidden="true"
                  />
                  <div className="min-w-0">
                    <CardTitle className="text-sm font-semibold">{tr("overview.killSwitch")}</CardTitle>
                    <CardDescription className="text-xs">{tr("overview.killSwitchDesc")}</CardDescription>
                  </div>
                </div>
                <Switch
                  aria-label={tr("overview.killSwitch")}
                  checked={killSwitchEnabled}
                  disabled={busy}
                  onCheckedChange={(checked) => void handleToggleKillSwitch(checked)}
                />
              </div>
            </CardHeader>
          </Card>
        );

        const webrtcCard = (
          <Card className="prism-surface h-full">
            <CardHeader className="space-y-2.5 pb-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <ShieldBan className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                  <CardTitle className="text-sm font-semibold">{tr("overview.webrtcTitle")}</CardTitle>
                </div>
                <div className="w-44 shrink-0">
                  <Select
                    aria-label={tr("overview.webrtcTitle")}
                    size="sm"
                    value={currentWebRTC}
                    disabled={busy}
                    onChange={(e) => void updateRoutingPatch({ webrtc_mode: e.target.value as "block" | "proxy" | "direct" }, tr("overview.webrtcUpdated"))}
                  >
                    <option value="block">{tr("overview.webrtcBlock")}</option>
                    <option value="proxy">{tr("overview.webrtcProxy")}</option>
                    <option value="direct">{tr("overview.webrtcDirect")}</option>
                  </Select>
                </div>
              </div>
              {!isAndroid && !isTunActive ? (
                <div className="flex items-start gap-2 rounded-[8px] border border-amber-500/25 bg-amber-500/8 px-2.5 py-1.5 text-[11px] leading-snug text-amber-700 dark:text-amber-300">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{tr("overview.webrtcNonTunCaveat")}</span>
                </div>
              ) : (
                <CardDescription className="text-xs">{tr("routing.webrtcDesc")}</CardDescription>
              )}
            </CardHeader>
          </Card>
        );

        const tailscaleCard = (
          <Card className={`prism-surface h-full ${tsStatus?.state === "error" ? "border-destructive/50" : tsStatus?.state === "connected" ? "border-emerald-500/35" : ""}`}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-2.5">
                  <Network className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 shrink-0 rounded-full ${tsDotClass}`} aria-hidden="true" />
                      <CardTitle className="text-sm font-semibold">{tr("overview.tailscaleTitle")}</CardTitle>
                      <button
                        type="button"
                        onClick={() => navigateTo("routing", "routing-tailscale")}
                        className="text-[11px] font-medium text-primary hover:underline"
                      >
                        {tr("overview.tailscaleConfigure")}
                      </button>
                    </div>
                    <CardDescription
                      className={`truncate text-xs ${tsStatus?.state === "error" ? "cursor-pointer text-destructive" : tsStatus?.state === "needs_auth" ? "cursor-pointer text-amber-600 dark:text-amber-400" : tsStatus?.ipv4 ? "font-mono" : ""}`}
                      onClick={
                        tsStatus?.state === "error" || tsStatus?.state === "needs_auth"
                          ? () => navigateTo("routing", "routing-tailscale")
                          : undefined
                      }
                    >
                      {!tsConfig?.enabled && sysTailscale?.detected && routing?.bypass_system_tailscale !== false
                        ? tr("overview.systemTailscaleBypassed", { iface: sysTailscale.interface || "tailscale0" })
                        : tsSummaryText}
                    </CardDescription>
                  </div>
                </div>
                <Switch
                  aria-label={tr("overview.tailscaleTitle")}
                  checked={Boolean(tsConfig?.enabled)}
                  disabled={busy || tsBusy}
                  onCheckedChange={(checked) => void handleToggleTailscale(checked)}
                />
              </div>
            </CardHeader>
          </Card>
        );

        if (isAndroid) {
          return (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              {tunCard}
              {killSwitchCard}
              {webrtcCard}
              {tailscaleCard}
            </div>
          );
        }
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {tunCard}
              {sysProxyCard}
              {killSwitchCard}
            </div>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {webrtcCard}
              {tailscaleCard}
            </div>
          </div>
        );
      })()}

      {/* Tailscale Network Devices Card */}
      {tsConfig?.enabled ? (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Network className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                <CardTitle className="text-base">{tr("overview.tailscalePeersTitle")}</CardTitle>
                {(tsStatus?.peers_total ?? 0) > 0 ? (
                  <span className="badge-radius border border-border bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground tabular-nums">
                    {tr("overview.tailscalePeersCount", {
                      online: tsStatus?.peers_online ?? 0,
                      total: tsStatus?.peers_total ?? 0,
                    })}
                  </span>
                ) : null}
              </div>
              <div className="flex items-center gap-1.5">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-xs"
                  disabled={tsRefreshing}
                  onClick={() => void refreshTailscaleNow()}
                  aria-label={tr("action.refresh")}
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${tsRefreshing ? "animate-spin" : ""}`} aria-hidden="true" />
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="h-7 px-2.5 text-xs"
                  onClick={() => navigateTo("routing", "routing-tailscale")}
                >
                  {tr("overview.tailscaleConfigure")}
                </Button>
              </div>
            </div>

            {tsStatus?.ipv4 || tsStatus?.dns_name ? (
              <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 overflow-hidden rounded-[8px] border border-primary/25 bg-primary/5 px-2.5 py-2 text-xs">
                <span className="badge-radius inline-flex shrink-0 items-center gap-1.5 border border-primary/30 bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
                  <span className={`h-1.5 w-1.5 rounded-full ${tsDotClass}`} aria-hidden="true" />
                  {tr("overview.tailscalePeerSelf")}
                </span>
                {tsStatus.hostname ? (
                  <span className="min-w-0 truncate font-medium text-foreground">{tsStatus.hostname}</span>
                ) : null}
                {tsStatus.ipv4 ? (
                  <button
                    type="button"
                    onClick={() => void copyText(tsStatus.ipv4 || "")}
                    title={tr("toast.clickToCopy")}
                    className="inline-flex max-w-full min-w-0 items-center gap-1 font-mono text-foreground hover:text-primary"
                  >
                    <strong className="truncate">{tsStatus.ipv4}</strong>
                    <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden="true" />
                  </button>
                ) : null}
                {tsStatus.dns_name ? (
                  <button
                    type="button"
                    onClick={() => void copyText(tsStatus.dns_name || "")}
                    title={`${tsStatus.dns_name} (${tr("toast.clickToCopy")})`}
                    className="flex max-w-full min-w-0 items-center gap-1 overflow-hidden font-mono text-muted-foreground hover:text-primary"
                  >
                    <span className="min-w-0 flex-1 truncate text-left">{tsStatus.dns_name}</span>
                    <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden="true" />
                  </button>
                ) : null}
              </div>
            ) : null}
          </CardHeader>

          <CardContent className="pt-0">
            <input
              ref={taildropInputRef}
              type="file"
              className="hidden"
              onChange={(e) => void handlePeerTaildropFileSelected(e.target.files?.[0])}
            />
            {tsStatus?.peers && tsStatus.peers.length > 0 ? (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {tsStatus.peers.map((peer, idx) => {
                  const ip = peer.ipv4 || peer.tailscale_ips?.[0] || "";
                  const name = peer.hostname || peer.dns_name || ip || `Peer #${idx + 1}`;
                  return (
                    <div
                      key={peer.stable_id || ip || `${name}-${idx}`}
                      className={[
                        "flex min-w-0 items-center justify-between gap-2 rounded-[8px] border px-3 py-2 text-xs transition-colors",
                        peer.online
                          ? "border-emerald-500/30 bg-emerald-500/5"
                          : "border-border/70 bg-muted/20 opacity-80",
                      ].join(" ")}
                    >
                      <div className="min-w-0 flex-1 space-y-0.5">
                        <div className="flex min-w-0 items-center gap-1.5">
                          <span
                            className={`h-2 w-2 shrink-0 rounded-full ${peer.online ? "bg-emerald-500" : "bg-muted-foreground/50"}`}
                            aria-hidden="true"
                          />
                          <span className="min-w-0 truncate font-semibold text-foreground" title={peer.dns_name || name}>
                            {name}
                          </span>
                          {peer.os ? (
                            <span className="shrink-0 rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground">
                              {peer.os}
                            </span>
                          ) : null}
                          {peer.exit_node ? (
                            <span className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1 py-0.5 text-[10px] font-medium text-primary">
                              {tr("overview.tailscalePeerExitNode")}
                            </span>
                          ) : null}
                        </div>
                        <div className="flex min-w-0 items-center justify-between gap-2 text-[11px] text-muted-foreground">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className={peer.online ? "font-medium text-emerald-600 dark:text-emerald-400" : ""}>
                              {peer.online ? tr("overview.tailscalePeerOnline") : tr("overview.tailscalePeerOffline")}
                            </span>
                            {ip ? (
                              <button
                                type="button"
                                onClick={() => void copyText(ip)}
                                title={tr("toast.clickToCopy")}
                                className="inline-flex max-w-full min-w-0 items-center gap-1 font-mono text-foreground/90 hover:text-primary"
                              >
                                <span className="truncate">{ip}</span>
                                <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden="true" />
                              </button>
                            ) : null}
                          </div>
                          <div className="flex shrink-0 items-center gap-1">
                            {peer.online && ip && tsStatus?.control_available ? (
                              <button
                                type="button"
                                disabled={peerPings[ip]?.busy}
                                onClick={() => void handlePingTailscalePeer(ip)}
                                className="shrink-0 rounded border border-border bg-background/80 px-1.5 py-0.5 text-[10px] font-medium text-foreground hover:border-primary/50 hover:text-primary disabled:opacity-50"
                              >
                                {peerPings[ip]?.busy ? "…" : tr("tailscale.pingBtn")}
                              </button>
                            ) : null}
                            {peer.stable_id && (peer.exit_node_option || peer.exit_node) && tsStatus?.control_available ? (
                              <button
                                type="button"
                                disabled={exitNodeBusyId === peer.stable_id}
                                onClick={() => void handleQuickTogglePeerExitNode(peer)}
                                className={[
                                  "shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors disabled:opacity-50",
                                  peer.exit_node
                                    ? "border-primary/50 bg-primary/15 text-primary hover:bg-primary/25"
                                    : "border-border bg-background/80 text-foreground hover:border-primary/50 hover:text-primary",
                                ].join(" ")}
                              >
                                {exitNodeBusyId === peer.stable_id
                                  ? "…"
                                  : peer.exit_node
                                    ? tr("tailscale.clearExitNodeShort")
                                    : tr("tailscale.useExitNodeShort")}
                              </button>
                            ) : null}
                            {peer.online && peer.stable_id && tsStatus?.can_share_files && tsStatus?.control_available ? (
                              <button
                                type="button"
                                disabled={taildropBusyId === peer.stable_id}
                                onClick={() => handleOpenPeerTaildrop(peer.stable_id!)}
                                title={tr("tailscale.taildropSend")}
                                className="inline-flex shrink-0 items-center gap-0.5 rounded border border-border bg-background/80 px-1.5 py-0.5 text-[10px] font-medium text-foreground hover:border-primary/50 hover:text-primary disabled:opacity-50"
                              >
                                <Send className="h-2.5 w-2.5" aria-hidden="true" />
                                {taildropBusyId === peer.stable_id ? "…" : tr("tailscale.sendShort")}
                              </button>
                            ) : null}
                          </div>
                        </div>
                        {ip && peerPings[ip] && !peerPings[ip].busy ? (
                          <div className="pt-0.5 text-[10px] mono-num">
                            {peerPings[ip].err ? (
                              <span className="text-destructive">{peerPings[ip].err}</span>
                            ) : peerPings[ip].result ? (
                              <span
                                className={
                                  peerPings[ip].result.is_direct
                                    ? "text-emerald-600 dark:text-emerald-400"
                                    : "text-amber-600 dark:text-amber-400"
                                }
                              >
                                {Math.round(peerPings[ip].result.avg_ms || peerPings[ip].result.latency_ms)} ms ·{" "}
                                {peerPings[ip].result.is_direct
                                  ? tr("tailscale.pingDirect")
                                  : `${tr("tailscale.pingDerp")}${
                                      peerPings[ip].result.derp_region_code
                                        ? `(${peerPings[ip].result.derp_region_code})`
                                        : ""
                                    }`}
                              </span>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                {tsStatus?.source === "log" && tsStatus.state === "connected"
                  ? tr("overview.tailscalePeersDesktopNote")
                  : tr("overview.tailscalePeersEmpty")}
              </p>
            )}
          </CardContent>
        </Card>
      ) : null}

      {/* Live Traffic + History Chart */}
      <Card>
        <CardHeader className="space-y-3 pb-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" aria-hidden="true" />
              <CardTitle className="text-base">{tr("overview.trafficChart")}</CardTitle>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center rounded-[8px] border border-border bg-muted/40 p-0.5 text-xs">
                {(
                  [
                    { id: "live", label: tr("overview.trafficLive") },
                    { id: "24h", label: tr("overview.traffic24h") },
                    { id: "7d", label: tr("overview.traffic7d") },
                    { id: "30d", label: tr("overview.traffic30d") },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setTrafficRange(opt.id)}
                    className={[
                      "rounded-[6px] px-2 py-1 text-[11px] font-medium transition-colors",
                      trafficRange === opt.id
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <div className="inline-flex items-center rounded-[8px] border border-border bg-muted/40 p-0.5 text-xs">
                {(
                  [
                    { id: "all", label: tr("overview.trafficFilterAll") },
                    { id: "proxy", label: tr("overview.trafficFilterProxy") },
                    { id: "direct", label: tr("overview.trafficFilterDirect") },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setTrafficFilter(opt.id)}
                    className={[
                      "rounded-[6px] px-2.5 py-1 text-[11px] font-medium transition-colors",
                      trafficFilter === opt.id
                        ? "bg-background text-foreground shadow-xs"
                        : "text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              {trafficRange !== "live" ? (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-[11px] text-muted-foreground hover:text-destructive"
                  onClick={() => void handleClearTrafficHistory()}
                >
                  {tr("overview.trafficClearHistory")}
                </Button>
              ) : null}
            </div>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-[10px] border border-primary/20 bg-primary/5 px-3 py-2 text-xs mono-num">
              <span className="inline-flex items-center gap-1.5 font-semibold text-primary">
                <span className="h-2 w-2 rounded-full bg-primary" aria-hidden="true" />
                {tr("overview.proxyTraffic")}
                {trafficRange !== "live" ? (
                  <span className="text-[10px] font-normal text-muted-foreground">({tr("overview.trafficHistoryTotal")})</span>
                ) : null}
              </span>
              <div className="flex items-center gap-3.5">
                <span className="inline-flex items-center gap-1" title={tr("overview.proxyUpload")}>
                  <ArrowUp className="h-3.5 w-3.5 text-primary/70" aria-hidden="true" />
                  <strong className="text-foreground">
                    {trafficRange === "live"
                      ? formatRate(trafficNow.proxy_up ?? 0)
                      : formatBytes(historyData?.totals?.proxy_up ?? 0)}
                  </strong>
                </span>
                <span className="inline-flex items-center gap-1" title={tr("overview.proxyDownload")}>
                  <ArrowDown className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                  <strong className="text-foreground">
                    {trafficRange === "live"
                      ? formatRate(trafficNow.proxy_down ?? 0)
                      : formatBytes(historyData?.totals?.proxy_down ?? 0)}
                  </strong>
                </span>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-[10px] border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-xs mono-num">
              <span className="inline-flex items-center gap-1.5 font-semibold text-emerald-500">
                <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
                {tr("overview.directTraffic")}
                {trafficRange !== "live" ? (
                  <span className="text-[10px] font-normal text-muted-foreground">({tr("overview.trafficHistoryTotal")})</span>
                ) : null}
              </span>
              <div className="flex items-center gap-3.5">
                <span className="inline-flex items-center gap-1" title={tr("overview.directUpload")}>
                  <ArrowUp className="h-3.5 w-3.5 text-emerald-500/70" aria-hidden="true" />
                  <strong className="text-foreground">
                    {trafficRange === "live"
                      ? formatRate(trafficNow.direct_up ?? 0)
                      : formatBytes(historyData?.totals?.direct_up ?? 0)}
                  </strong>
                </span>
                <span className="inline-flex items-center gap-1" title={tr("overview.directDownload")}>
                  <ArrowDown className="h-3.5 w-3.5 text-emerald-500" aria-hidden="true" />
                  <strong className="text-foreground">
                    {trafficRange === "live"
                      ? formatRate(trafficNow.direct_down ?? 0)
                      : formatBytes(historyData?.totals?.direct_down ?? 0)}
                  </strong>
                </span>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-52 w-full min-w-0">
            {isActive ? (
              <Suspense
                fallback={
                  <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                    …
                  </div>
                }
              >
                {trafficRange === "live" ? (
                  <LiveTrafficChart
                    data={trafficHistory}
                    trafficFilter={trafficFilter}
                    labels={{
                      proxyDownload: tr("overview.proxyDownload"),
                      proxyUpload: tr("overview.proxyUpload"),
                      directDownload: tr("overview.directDownload"),
                      directUpload: tr("overview.directUpload"),
                    }}
                  />
                ) : historyLoading ? (
                  <div className="flex h-full items-center justify-center text-xs text-muted-foreground">…</div>
                ) : (
                  <TrafficHistoryChart
                    buckets={historyData?.buckets || []}
                    granularity={historyData?.granularity || "hour"}
                    trafficFilter={trafficFilter}
                    labels={{
                      proxyDownload: tr("overview.proxyDownload"),
                      proxyUpload: tr("overview.proxyUpload"),
                      directDownload: tr("overview.directDownload"),
                      directUpload: tr("overview.directUpload"),
                    }}
                  />
                )}
              </Suspense>
            ) : null}
          </div>
        </CardContent>
      </Card>

      {/* Primary Exit & Multi-Inbound Mapping Matrix */}
      <Card>
        <CardHeader className="flex flex-col gap-2 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-5 w-5 text-primary" aria-hidden="true" />
              {tr("overview.inboundMatrix")}
            </CardTitle>
            <CardDescription className="text-xs">{tr("overview.inboundMatrixDesc")}</CardDescription>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={() => navigateTo("settings", "settings-listeners")}>
            <SlidersHorizontal className="mr-1.5 h-4 w-4" aria-hidden="true" />
            {tr("overview.manageInbounds")}
          </Button>
        </CardHeader>
        <CardContent>
          {/* Mobile Key-Value Stacked Cards (<768px) */}
          <div className="space-y-2.5 md:hidden">
            <div className="space-y-2 rounded-[10px] border border-primary/25 bg-accent/25 p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-foreground">{tr("overview.defaultExit")}</span>
                <span
                  className={[
                    "shrink-0 whitespace-nowrap badge-radius border px-2 py-0.5 text-[11px] font-medium mono-num",
                    isProxyRunning
                      ? "border-primary/30 bg-primary/15 text-primary"
                      : "border-border bg-muted text-muted-foreground",
                  ].join(" ")}
                >
                  {isProxyRunning ? tr("status.running") : tr("status.stopped")}
                </span>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-border/60 pt-2">
                <span className="shrink-0 text-muted-foreground">{tr("overview.portProtocol")}</span>
                <span className="mono-num text-right text-foreground break-all">
                  TUN / mixed · 127.0.0.1:{status?.mixed_port || 10808}
                </span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="shrink-0 text-muted-foreground">{tr("overview.bindTarget")}</span>
                <span className="inline-flex max-w-[68%] truncate items-center badge-radius border border-primary/30 bg-primary/15 px-2 py-0.5 font-medium text-primary">
                  {activeLabel}
                </span>
              </div>
            </div>

            {listeners.map((l) => (
              <div key={l.id} className="space-y-2 rounded-[10px] border border-border bg-card p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-semibold text-foreground">{l.name || l.id}</span>
                    {l.allow_lan ? (
                      <span className="shrink-0 badge-radius border border-border px-1 py-0.2 text-[10px] text-muted-foreground mono-num">
                        LAN
                      </span>
                    ) : null}
                  </div>
                  <span
                    className={[
                      "shrink-0 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium",
                      l.enabled ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                    ].join(" ")}
                  >
                    {l.enabled ? tr("status.active") : tr("status.stopped")}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3 border-t border-border/60 pt-2">
                  <span className="shrink-0 text-muted-foreground">{tr("overview.portProtocol")}</span>
                  <span className="truncate mono-num text-right text-foreground">
                    {l.protocol} · {l.address}:{l.port}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="shrink-0 text-muted-foreground">{tr("overview.bindTarget")}</span>
                  <span className="inline-flex max-w-[68%] truncate items-center badge-radius border border-border bg-background px-2 py-0.5 font-medium text-foreground">
                    {resolveInboundTarget(l)}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Desktop Horizontal Table (>=768px) */}
          <div className="hidden md:block overflow-x-auto rounded-[10px] border border-border">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/40 text-muted-foreground">
                  <th className="px-3 py-2 font-semibold whitespace-nowrap">{tr("overview.inboundPorts")}</th>
                  <th className="px-3 py-2 font-semibold whitespace-nowrap">{tr("overview.portProtocol")}</th>
                  <th className="px-3 py-2 font-semibold whitespace-nowrap">{tr("overview.bindTarget")}</th>
                  <th className="px-3 py-2 font-semibold text-right whitespace-nowrap">{locale === "zh-CN" ? "状态" : "Status"}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                <tr className="bg-accent/25">
                  <td className="px-3 py-2 font-semibold text-foreground whitespace-nowrap">{tr("overview.defaultExit")}</td>
                  <td className="px-3 py-2 mono-num text-muted-foreground whitespace-nowrap">
                    TUN / mixed · 127.0.0.1:{status?.mixed_port || 10808}
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center badge-radius border border-primary/30 bg-primary/15 px-2 py-0.5 font-medium text-primary whitespace-nowrap">
                      {activeLabel}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right whitespace-nowrap">
                    <span
                      className={[
                        "badge-radius border px-2 py-0.5 text-[11px] font-medium mono-num whitespace-nowrap",
                        isProxyRunning
                          ? "border-primary/30 bg-primary/15 text-primary"
                          : "border-border bg-muted text-muted-foreground",
                      ].join(" ")}
                    >
                      {isProxyRunning ? tr("status.running") : tr("status.stopped")}
                    </span>
                  </td>
                </tr>
                {listeners.map((l) => (
                  <tr key={l.id} className="hover:bg-muted/30">
                    <td className="px-3 py-2 font-medium text-foreground">
                      <div className="flex items-center gap-1.5">
                        <span>{l.name || l.id}</span>
                        {l.allow_lan ? (
                          <span className="badge-radius border border-border px-1 py-0.2 text-[10px] text-muted-foreground mono-num">
                            LAN
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-3 py-2 mono-num text-muted-foreground whitespace-nowrap">
                      {l.protocol} · {l.address}:{l.port}
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center badge-radius border border-border bg-background px-2 py-0.5 font-medium text-foreground whitespace-nowrap">
                        {resolveInboundTarget(l)}
                      </span>
                    </td>
                    <td className="px-3.5 py-2.5 text-right whitespace-nowrap">
                      <span
                        className={[
                          "rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap",
                          l.enabled ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                        ].join(" ")}
                      >
                        {l.enabled ? tr("status.active") : tr("status.stopped")}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
