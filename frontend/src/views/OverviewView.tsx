// SPDX-License-Identifier: MPL-2.0

import { useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Globe,
  Network,
  Power,
  Shield,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, formatApiError, isAndroidClient, type ListenConfig, type RoutingProfile } from "../lib/api.ts";
import { formatRate } from "../lib/helpers.ts";
import { useAppStore, useTelemetry } from "../store/appStore.ts";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Select } from "../components/ui/select.tsx";
import { Switch } from "../components/ui/switch.tsx";

const DEFAULT_ROUTING_BASE: RoutingProfile = {
  mode: "rule",
  block_ads: true,
  bypass_lan: true,
  allow_lan_broadcast: false,
  bypass_cn: true,
  webrtc_mode: "block",
  local_dns: "223.5.5.5",
  remote_dns: "https://dns.google/dns-query",
  custom_rules: [],
};

export function OverviewView() {
  const {
    tr,
    locale,
    status,
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
    setActiveTab,
  } = useAppStore();
  const { trafficNow, trafficHistory } = useTelemetry();

  const [authorizing, setAuthorizing] = useState(false);

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
      <Card className={`prism-hero-surface border-border ${status?.running ? "is-running" : ""}`}>
        <CardContent className="flex flex-col gap-4 p-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={[
                  "inline-flex min-h-8 items-center gap-1.5 overflow-hidden badge-radius border px-2.5 py-1 text-xs font-semibold leading-normal tabular-nums",
                  status?.running
                    ? "border-primary/30 bg-primary/15 text-primary"
                    : "border-border bg-muted text-muted-foreground",
                ].join(" ")}
              >
                <span
                  className={[
                    "h-1.5 w-1.5 shrink-0 rounded-full",
                    status?.running ? "bg-primary status-radar-dot" : "bg-muted-foreground",
                  ].join(" ")}
                  aria-hidden="true"
                />
                <span className="inline-flex items-center">{busy ? tr("status.connecting") : status?.running ? tr("status.running") : tr("status.stopped")}</span>
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
                        → {tr("overview.lbShardsSummary", { count: activeGroup.node_ids.length })}
                      </span>
                    ) : resolvedGroupMember ? (
                      <span className="inline-flex items-center text-xs text-muted-foreground">
                        → {resolvedGroupMember.user_alias || resolvedGroupMember.name}
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
              variant={status?.running ? "destructive" : "default"}
              disabled={busy}
              onClick={() => void toggleConnect()}
              className="min-w-32 shrink-0 rounded-[6px]"
            >
              <Power className="mr-2 h-4 w-4" aria-hidden="true" />
              {status?.running ? tr("action.disconnect") : tr("action.connect")}
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

      {/* Quick Toggles Row */}
      <div className={`grid grid-cols-1 gap-4 ${isAndroid ? "md:grid-cols-3" : "md:grid-cols-2 xl:grid-cols-4"}`}>
        <Card className="prism-surface">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2.5">
                <Shield className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
                <div className="min-w-0">
                  <CardTitle className="text-sm font-semibold">{tr("overview.tunVpn")}</CardTitle>
                  <CardDescription className="text-xs">
                    {isAndroid ? "Android VpnService · Full TUN" : `prismray0 · ${tunState?.stack || "mixed"}`}
                  </CardDescription>
                </div>
              </div>
              <Switch
                aria-label={tr("overview.tunVpn")}
                checked={isAndroid ? Boolean(status?.running && status?.android_mode) : Boolean(tunState?.enabled)}
                disabled={busy}
                onCheckedChange={(checked) => void toggleTUN(checked)}
              />
            </div>
          </CardHeader>
          {!isAndroid &&
          (tunState?.privilege?.os === "linux" || tunState?.privilege?.os === "darwin") &&
          !tunState.privilege.ready_without_password ? (
            <CardContent className="pt-0">
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

        {!isAndroid ? (
          <Card className="prism-surface">
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
          </Card>
        ) : null}

        <Card className={`prism-surface ${status?.kill_switch_tripped ? "border-destructive/50" : ""}`}>
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

        <Card className="prism-surface">
          <CardHeader className="space-y-2.5 pb-3">
            <div className="flex items-center gap-2.5">
              <ShieldBan className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
              <CardTitle className="text-sm font-semibold">{tr("overview.webrtcTitle")}</CardTitle>
            </div>
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
          </CardHeader>
        </Card>
      </div>

      {/* Live Traffic + Chart */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-primary" aria-hidden="true" />
              <CardTitle className="text-base">{tr("overview.trafficChart")}</CardTitle>
            </div>
            <div className="flex items-center gap-5 text-sm mono-num">
              <span className="inline-flex items-center gap-1.5">
                <ArrowUp className="h-4 w-4 text-primary" aria-hidden="true" />
                <span className="text-xs text-muted-foreground">{tr("overview.upload")}:</span>
                <strong className="text-foreground">{formatRate(trafficNow.up)}</strong>
              </span>
              <span className="inline-flex items-center gap-1.5">
                <ArrowDown className="h-4 w-4 text-sky-400" aria-hidden="true" />
                <span className="text-xs text-muted-foreground">{tr("overview.download")}:</span>
                <strong className="text-foreground">{formatRate(trafficNow.down)}</strong>
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-52 w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart accessibilityLayer={false} data={trafficHistory} margin={{ top: 8, right: 12, left: 4, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} minTickGap={24} />
                <YAxis tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} unit=" KB" width={74} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "var(--popover)",
                    borderColor: "var(--border)",
                    borderRadius: "10px",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="downKB"
                  name={`${tr("overview.download")} (KB/s)`}
                  stroke="#38bdf8"
                  fill="#38bdf8"
                  fillOpacity={0.12}
                  strokeWidth={1.75}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="upKB"
                  name={`${tr("overview.upload")} (KB/s)`}
                  stroke="var(--primary)"
                  fill="var(--primary)"
                  fillOpacity={0.15}
                  strokeWidth={2}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
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
          <Button type="button" variant="outline" size="sm" onClick={() => setActiveTab("settings")}>
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
                    status?.running
                      ? "border-primary/30 bg-primary/15 text-primary"
                      : "border-border bg-muted text-muted-foreground",
                  ].join(" ")}
                >
                  {status?.running ? tr("status.running") : tr("status.stopped")}
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
                        status?.running
                          ? "border-primary/30 bg-primary/15 text-primary"
                          : "border-border bg-muted text-muted-foreground",
                      ].join(" ")}
                    >
                      {status?.running ? tr("status.running") : tr("status.stopped")}
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
