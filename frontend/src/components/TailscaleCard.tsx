// SPDX-License-Identifier: MPL-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  AlertTriangle,
  ChevronDown,
  Copy,
  Download,
  ExternalLink,
  LogOut,
  Network,
  RefreshCw,
  RotateCcw,
  Save,
  Send,
  Trash2,
} from "lucide-react";
import {
  androidBridge,
  api,
  formatApiError,
  isAndroidClient,
  isDesktop,
  type SystemTailscaleInfo,
  type TaildropInboxResponse,
  type TailscaleConfig,
  type TailscaleRuntimeStatus,
} from "../lib/api.ts";
import { formatBytes } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card.tsx";
import { Input } from "./ui/input.tsx";
import { Select } from "./ui/select.tsx";
import { Switch } from "./ui/switch.tsx";

const DEFAULT_TS: TailscaleConfig = {
  enabled: false,
  control_url: "",
  auth_key: "",
  has_auth_key: false,
  hostname: "",
  ephemeral: false,
  accept_routes: true,
  exit_node: "",
  exit_node_allow_lan: false,
  magic_dns: true,
  extra_domains: [],
  extra_subnets: [],
  detour_id: "",
  udp_timeout: "5m",
};

function isSafeHttpUrl(raw: string | undefined): boolean {
  if (!raw) return false;
  try {
    const u = new URL(raw.trim());
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

async function openTailscaleAuthUrl(raw: string): Promise<void> {
  if (!isSafeHttpUrl(raw)) return;
  const clean = raw.trim();
  if (window.PrismRayAndroid?.openExternalUrl?.(clean)) {
    return;
  }
  if (isDesktop) {
    try {
      await openUrl(clean);
      return;
    } catch {
      // Fallback to browser window.open.
    }
  }
  window.open(clean, "_blank", "noopener,noreferrer");
}

function parseCsvList(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

interface TailscaleCardProps {
  onConfigChanged?: (cfg: TailscaleConfig) => void;
  forceExpandSignal?: number;
}

export function TailscaleCard({ onConfigChanged, forceExpandSignal = 0 }: TailscaleCardProps) {
  const { activeTab, tr, locale, nodes, groups, routing, status, tailscaleEnabled, storeRevision, notify, refreshAll } = useAppStore();
  const [cfg, setCfg] = useState<TailscaleConfig>(DEFAULT_TS);
  const [savedCfgBaseline, setSavedCfgBaseline] = useState<string>("");
  const [stateInit, setStateInit] = useState(false);
  const [tsStatus, setTsStatus] = useState<TailscaleRuntimeStatus | null>(null);
  const [sysTailscale, setSysTailscale] = useState<SystemTailscaleInfo | null>(null);
  const [refreshingStatus, setRefreshingStatus] = useState(false);
  const [authKeyInput, setAuthKeyInput] = useState("");
  const [clearAuthKey, setClearAuthKey] = useState(false);
  const [extraSubnetsText, setExtraSubnetsText] = useState("");
  const [extraDomainsText, setExtraDomainsText] = useState("");
  const [advertiseRoutesText, setAdvertiseRoutesText] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedEnabled, setSavedEnabled] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const [switchingExitNode, setSwitchingExitNode] = useState(false);
  const [taildropOpen, setTaildropOpen] = useState(false);
  const [taildropInbox, setTaildropInbox] = useState<TaildropInboxResponse | null>(null);
  const [taildropPeerId, setTaildropPeerId] = useState("");
  const [taildropSending, setTaildropSending] = useState(false);

  useEffect(() => {
    if (forceExpandSignal > 0) {
      setExpanded(true);
    }
  }, [forceExpandSignal]);

  const isDirtyRef = useRef(false);
  isDirtyRef.current =
    Boolean(savedCfgBaseline) &&
    (JSON.stringify({
      ...cfg,
      extra_subnets: parseCsvList(extraSubnetsText),
      extra_domains: parseCsvList(extraDomainsText),
      advertise_routes: parseCsvList(advertiseRoutesText),
    }) !== savedCfgBaseline ||
      Boolean(authKeyInput.trim()) ||
      clearAuthKey);

  const loadConfig = useCallback(async (onlyStatus = false) => {
    try {
      const res = await api.getTailscale();
      setStateInit(Boolean(res.state_initialized));
      setTsStatus(res.status || null);
      setSysTailscale(res.system_tailscale || null);
      if (!onlyStatus) {
        setCfg(res.config);
        setSavedCfgBaseline(
          JSON.stringify({
            ...res.config,
            extra_subnets: res.config.extra_subnets || [],
            extra_domains: res.config.extra_domains || [],
            advertise_routes: res.config.advertise_routes || [],
          }),
        );
        setSavedEnabled(Boolean(res.config.enabled));
        setExtraSubnetsText((res.config.extra_subnets || []).join(", "));
        setExtraDomainsText((res.config.extra_domains || []).join(", "));
        setAdvertiseRoutesText((res.config.advertise_routes || []).join(", "));
        setAuthKeyInput("");
        setClearAuthKey(false);
        if (res.config.enabled) {
          setExpanded(true);
        }
        onConfigChanged?.(res.config);
      }
    } catch {
      // Ignore transient load error until unlocked.
    }
  }, [onConfigChanged]);

  useEffect(() => {
    void loadConfig(false);
  }, [loadConfig]);

  // Re-sync when global store refreshes (Overview toggle, Tray toggle, Profile switch, Backup restore).
  useEffect(() => {
    if (storeRevision === 0 || activeTab !== "routing") return;
    void loadConfig(isDirtyRef.current);
  }, [storeRevision, tailscaleEnabled, activeTab, loadConfig]);

  // Refresh live runtime status when main proxy starts/stops or while Tailscale is enabled and tab is visible.
  useEffect(() => {
    if (activeTab !== "routing") return;
    void loadConfig(true);
  }, [loadConfig, status?.running, activeTab]);

  useEffect(() => {
    if (!cfg.enabled || activeTab !== "routing") return;
    const pollMs =
      tsStatus?.state === "connecting" || tsStatus?.state === "needs_auth" ? 3000 : 10000;
    const id = window.setInterval(() => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
      void loadConfig(true);
    }, pollMs);
    return () => window.clearInterval(id);
  }, [cfg.enabled, activeTab, tsStatus?.state, loadConfig]);

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
      // Ignore clipboard failures.
    }
  };

  const handleManualRefreshStatus = async () => {
    setRefreshingStatus(true);
    try {
      await loadConfig(true);
    } finally {
      setRefreshingStatus(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const wasEnabled = savedEnabled;
      const payload: TailscaleConfig = {
        ...cfg,
        auth_key: authKeyInput.trim() || undefined,
        clear_auth_key: clearAuthKey && !authKeyInput.trim(),
        extra_subnets: parseCsvList(extraSubnetsText),
        extra_domains: parseCsvList(extraDomainsText),
        advertise_routes: parseCsvList(advertiseRoutesText),
      };
      const res = await api.saveTailscale(payload);
      setCfg(res.config);
      setSavedCfgBaseline(
        JSON.stringify({
          ...res.config,
          extra_subnets: res.config.extra_subnets || [],
          extra_domains: res.config.extra_domains || [],
          advertise_routes: res.config.advertise_routes || [],
        }),
      );
      setSavedEnabled(Boolean(res.config.enabled));
      setStateInit(Boolean(res.state_initialized));
      setTsStatus(res.status || null);
      setAdvertiseRoutesText((res.config.advertise_routes || []).join(", "));
      setAuthKeyInput("");
      setClearAuthKey(false);
      onConfigChanged?.(res.config);
      await refreshAll();

      // Sync Android Quick Settings Tile state immediately.
      if (androidBridge.available()) {
        androidBridge.refreshQuickTiles();
      }
      // If on Android with LAN broadcast bypass enabled and Tailscale state changed, refresh VPN routes
      // so 100.64.0.0/10 and custom Tailnet subnets are routed cleanly into tun0.
      if (
        androidBridge.available() &&
        androidBridge.getVpnStatus()?.active &&
        (wasEnabled !== res.config.enabled || routing?.allow_lan_broadcast)
      ) {
        androidBridge.prepareAndStartVpn({
          per_app_mode: routing?.per_app_mode || "all",
          per_app_packages: routing?.per_app_packages || [],
          bypass_lan: routing?.bypass_lan,
          allow_lan_broadcast: routing?.allow_lan_broadcast,
        });
      }
      notify(tr("tailscale.saved"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSaving(false);
    }
  };

  const handleResetState = async () => {
    setResetting(true);
    try {
      const res = await api.resetTailscaleState();
      setStateInit(Boolean(res.state_initialized));
      setTsStatus(res.status || null);
      notify(tr("tailscale.resetDone"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setResetting(false);
    }
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      const res = await api.logoutTailscale();
      setTsStatus(res.status || null);
      notify(tr("tailscale.logoutDone"));
      await loadConfig(true);
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setLoggingOut(false);
    }
  };

  const handleSelectExitNode = async (stableId: string, labelOrIp: string) => {
    setSwitchingExitNode(true);
    try {
      const res = await api.setTailscaleExitNode({ stable_id: stableId, exit_node: labelOrIp });
      setCfg(res.config);
      setSavedCfgBaseline(
        JSON.stringify({
          ...res.config,
          extra_subnets: res.config.extra_subnets || [],
          extra_domains: res.config.extra_domains || [],
          advertise_routes: res.config.advertise_routes || [],
        }),
      );
      if (res.status) setTsStatus(res.status);
      notify(res.hot_switched ? tr("tailscale.exitNodeHotSwitched") : tr("tailscale.exitNodeSaved"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSwitchingExitNode(false);
    }
  };

  const refreshTaildrop = useCallback(async () => {
    try {
      const inbox = await api.getTaildropInbox();
      setTaildropInbox(inbox);
    } catch {
      // Ignore if control server unavailable.
    }
  }, []);

  useEffect(() => {
    if (taildropOpen && tsStatus?.state === "connected") {
      void refreshTaildrop();
    }
  }, [taildropOpen, tsStatus?.state, refreshTaildrop]);

  const handleSendTaildropFile = async (file: File | null) => {
    if (!file || !taildropPeerId) return;
    setTaildropSending(true);
    try {
      await api.sendTaildropFile(taildropPeerId, file);
      notify(tr("tailscale.taildropSent", { name: file.name }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setTaildropSending(false);
    }
  };

  const handleDownloadTaildrop = async (name: string) => {
    try {
      const blob = await api.downloadTaildropFile(name);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1500);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleDeleteTaildrop = async (name: string) => {
    try {
      await api.deleteTaildropFile(name);
      notify(tr("tailscale.taildropDeleted"));
      await refreshTaildrop();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const exitNodePeers = (tsStatus?.peers || []).filter((p) => p.exit_node_option || p.exit_node);
  const onlinePeers = (tsStatus?.peers || []).filter((p) => p.online && p.stable_id);

  const nonLbGroups = groups.filter((g) => {
    const s = (g.strategy || "").trim().toLowerCase();
    return s !== "loadbalance" && s !== "load-balance" && s !== "hash" && (g.node_ids || []).length > 0;
  });

  const renderStatusBadge = () => {
    if (!cfg.enabled && tsStatus?.state !== "error") return null;
    const st = tsStatus?.state || (cfg.enabled ? "stopped" : "disabled");
    if (st === "connected") {
      return (
        <span className="badge-radius inline-flex items-center gap-1.5 border border-emerald-500/35 bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 status-radar-dot" aria-hidden="true" />
          {tr("tailscale.statusConnected")}
          {tsStatus?.ipv4 ? <span className="font-mono">· {tsStatus.ipv4}</span> : null}
        </span>
      );
    }
    if (st === "connecting") {
      return (
        <span className="badge-radius inline-flex items-center gap-1.5 border border-amber-500/35 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-500" aria-hidden="true" />
          {tr("tailscale.statusConnecting")}
        </span>
      );
    }
    if (st === "needs_auth") {
      return (
        <span className="badge-radius inline-flex items-center gap-1 border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
          {tr("tailscale.statusNeedsAuth")}
        </span>
      );
    }
    if (st === "error") {
      return (
        <span className="badge-radius inline-flex items-center gap-1 border border-destructive/40 bg-destructive/15 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
          <AlertTriangle className="h-3 w-3" aria-hidden="true" />
          {tr("tailscale.statusError")}
        </span>
      );
    }
    if (st === "stopped") {
      return (
        <span className="badge-radius border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
          {tr("tailscale.statusStopped")}
        </span>
      );
    }
    return null;
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="min-w-0 flex-1 space-y-0.5">
            <div className="flex flex-wrap items-center gap-2">
              <Network className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
              <CardTitle className="text-base">{tr("tailscale.title")}</CardTitle>
              {renderStatusBadge()}
              {stateInit ? (
                <span className="badge-radius border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                  {tr("tailscale.stateReadyBadge")}
                </span>
              ) : null}
              {!cfg.enabled && !isAndroidClient() && sysTailscale?.detected ? (
                <span className="badge-radius border border-emerald-500/35 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-400">
                  {tr("tailscale.systemDetectedBadge", { iface: sysTailscale.interface || "tailscale0" })}
                </span>
              ) : null}
            </div>
            <CardDescription className="text-xs leading-relaxed">{tr("tailscale.subtitle")}</CardDescription>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Switch
              aria-label={tr("tailscale.enable")}
              checked={cfg.enabled}
              onCheckedChange={(checked) => {
                setCfg((prev) => ({ ...prev, enabled: checked }));
                if (checked) setExpanded(true);
              }}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => setExpanded((v) => !v)}
              aria-expanded={expanded}
              aria-label={expanded ? "Collapse Tailscale settings" : "Expand Tailscale settings"}
            >
              <ChevronDown className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </Button>
          </div>
        </div>

        {/* Live Tailscale Status Details Strip */}
        {(cfg.enabled || tsStatus?.state === "error") && tsStatus && tsStatus.state !== "disabled" ? (
          <div className="mt-2.5 space-y-2 text-xs">
            {(tsStatus.ipv4 || tsStatus.dns_name || (tsStatus.peers_total ?? 0) > 0 || tsStatus.state === "connected") ? (
              <div className="flex items-start justify-between gap-2 overflow-hidden rounded-[8px] border border-border/70 bg-muted/30 px-2.5 py-2">
                <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-1.5">
                  {tsStatus.ipv4 ? (
                    <button
                      type="button"
                      onClick={() => void copyText(tsStatus.ipv4 || "")}
                      title={tr("toast.clickToCopy")}
                      className="flex max-w-full min-w-0 items-center gap-1.5 font-mono text-foreground hover:text-primary"
                    >
                      <span className="shrink-0 font-sans text-muted-foreground">{tr("tailscale.ipLabel")}:</span>
                      <strong className="truncate">{tsStatus.ipv4}</strong>
                      <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden="true" />
                    </button>
                  ) : null}
                  {tsStatus.dns_name ? (
                    <button
                      type="button"
                      onClick={() => void copyText(tsStatus.dns_name || "")}
                      title={`${tsStatus.dns_name} (${tr("toast.clickToCopy")})`}
                      className="flex max-w-full min-w-0 items-center gap-1.5 overflow-hidden font-mono text-foreground hover:text-primary"
                    >
                      <span className="shrink-0 font-sans text-muted-foreground">{tr("tailscale.dnsLabel")}:</span>
                      <span className="min-w-0 flex-1 truncate text-left">{tsStatus.dns_name}</span>
                      <Copy className="h-3 w-3 shrink-0 opacity-60" aria-hidden="true" />
                    </button>
                  ) : null}
                  {(tsStatus.peers_total ?? 0) > 0 ? (
                    <span className="inline-flex shrink-0 items-center gap-1 text-muted-foreground tabular-nums">
                      <span>{tr("tailscale.peersLabel")}:</span>
                      <strong className="text-foreground">
                        {tsStatus.peers_online ?? 0} / {tsStatus.peers_total}
                      </strong>
                    </span>
                  ) : null}
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-6 shrink-0 px-2 text-[11px]"
                  disabled={refreshingStatus}
                  onClick={() => void handleManualRefreshStatus()}
                >
                  <RefreshCw className={`h-3 w-3 ${refreshingStatus ? "animate-spin" : ""}`} aria-hidden="true" />
                </Button>
              </div>
            ) : null}

            {tsStatus.state === "needs_auth" && tsStatus.auth_url ? (
              <div className="space-y-1.5 rounded-[8px] border border-amber-500/40 bg-amber-500/10 p-2.5 text-amber-800 dark:text-amber-200">
                <div className="font-medium">{tr("tailscale.authRequiredHint")}</div>
                <div className="break-all rounded bg-background/70 px-2 py-1 font-mono text-[11px] text-foreground">
                  {tsStatus.auth_url}
                </div>
                <div className="flex flex-wrap items-center gap-2 pt-0.5">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-7 text-[11px]"
                    onClick={() => void copyText(tsStatus.auth_url || "")}
                  >
                    <Copy className="mr-1 h-3 w-3" aria-hidden="true" />
                    {tr("tailscale.copyAuthUrl")}
                  </Button>
                  {isSafeHttpUrl(tsStatus.auth_url) ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      className="h-7 text-[11px]"
                      onClick={() => void openTailscaleAuthUrl(tsStatus.auth_url || "")}
                    >
                      <ExternalLink className="mr-1 h-3 w-3" aria-hidden="true" />
                      {tr("tailscale.openAuthUrl")}
                    </Button>
                  ) : null}
                </div>
              </div>
            ) : null}

            {tsStatus.last_error ? (
              <div className="rounded-[8px] border border-destructive/40 bg-destructive/10 p-2.5 text-destructive">
                <div className="font-semibold">{tr("tailscale.errorTitle")}</div>
                <div className="mt-0.5 break-all font-mono text-[11px] opacity-90">{tsStatus.last_error}</div>
              </div>
            ) : null}
          </div>
        ) : null}
      </CardHeader>

      {expanded ? (
        <CardContent className="space-y-3 border-t border-border/60 pt-3 text-xs">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.controlUrl")}</label>
              <Input
                value={cfg.control_url || ""}
                onChange={(e) => setCfg((prev) => ({ ...prev, control_url: e.target.value }))}
                placeholder={tr("tailscale.controlUrlPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-2">
                <label className="block font-medium text-muted-foreground">{tr("tailscale.authKey")}</label>
                {cfg.has_auth_key && !clearAuthKey ? (
                  <button
                    type="button"
                    onClick={() => {
                      setClearAuthKey(true);
                      setAuthKeyInput("");
                    }}
                    className="text-[11px] text-destructive hover:underline"
                  >
                    {tr("tailscale.clearAuthKey")}
                  </button>
                ) : null}
              </div>
              <Input
                type="password"
                autoComplete="off"
                value={authKeyInput}
                onChange={(e) => {
                  setAuthKeyInput(e.target.value);
                  if (e.target.value) setClearAuthKey(false);
                }}
                placeholder={
                  cfg.has_auth_key && !clearAuthKey
                    ? tr("tailscale.authKeySetPlaceholder")
                    : tr("tailscale.authKeyPlaceholder")
                }
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.hostname")}</label>
              <Input
                value={cfg.hostname || ""}
                onChange={(e) => setCfg((prev) => ({ ...prev, hostname: e.target.value }))}
                placeholder="prismray-device"
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.detour")}</label>
              <Select
                value={cfg.detour_id || ""}
                onChange={(e) => setCfg((prev) => ({ ...prev, detour_id: e.target.value }))}
              >
                <option value="">{tr("tailscale.detourDirect")}</option>
                {nonLbGroups.length > 0 ? (
                  <optgroup label={tr("routing.outboundGroups")}>
                    {nonLbGroups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name} ({g.strategy})
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {nodes.length > 0 ? (
                  <optgroup label={tr("routing.outboundNodes")}>
                    {nodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.user_alias || n.name} ({n.protocol.toUpperCase()})
                      </option>
                    ))}
                  </optgroup>
                ) : null}
              </Select>
            </div>
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.extraSubnets")}</label>
              <Input
                value={extraSubnetsText}
                onChange={(e) => setExtraSubnetsText(e.target.value)}
                placeholder={tr("tailscale.extraSubnetsPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.extraDomains")}</label>
              <Input
                value={extraDomainsText}
                onChange={(e) => setExtraDomainsText(e.target.value)}
                placeholder={tr("tailscale.extraDomainsPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1 sm:col-span-2">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.exitNode")}</label>
              <div className="flex flex-col gap-1.5 sm:flex-row">
                {exitNodePeers.length > 0 ? (
                  <Select
                    disabled={switchingExitNode}
                    value={tsStatus?.active_exit_node_id || ""}
                    onChange={(e) => {
                      const sid = e.target.value;
                      const chosen = exitNodePeers.find((p) => p.stable_id === sid);
                      const fallbackAddr = chosen?.ipv4 || chosen?.hostname || "";
                      void handleSelectExitNode(sid, fallbackAddr);
                    }}
                    className="sm:w-1/2"
                  >
                    <option value="">{tr("tailscale.exitNodeNone")}</option>
                    {exitNodePeers.map((p) => (
                      <option key={p.stable_id || p.hostname} value={p.stable_id || ""}>
                        {p.hostname || p.dns_name} {p.ipv4 ? `(${p.ipv4})` : ""} {p.online ? "●" : "○"}
                      </option>
                    ))}
                  </Select>
                ) : null}
                <Input
                  value={cfg.exit_node || ""}
                  onChange={(e) => setCfg((prev) => ({ ...prev, exit_node: e.target.value }))}
                  placeholder={tr("tailscale.exitNodePlaceholder")}
                  className="font-mono text-xs sm:flex-1"
                />
              </div>
            </div>
            <div className="space-y-1 sm:col-span-2">
              <label className="block font-medium text-muted-foreground">{tr("tailscale.advertiseRoutes")}</label>
              <Input
                value={advertiseRoutesText}
                onChange={(e) => {
                  setAdvertiseRoutesText(e.target.value);
                  setCfg((prev) => ({ ...prev, advertise_routes: parseCsvList(e.target.value) }));
                }}
                placeholder={tr("tailscale.advertiseRoutesPlaceholder")}
                className="font-mono text-xs"
              />
            </div>
          </div>

          {(parseCsvList(advertiseRoutesText).length > 0 || cfg.advertise_exit_node) ? (
            <div className="rounded-[8px] border border-amber-500/35 bg-amber-500/10 px-2.5 py-2 text-[11px] text-amber-800 dark:text-amber-200">
              {tr("tailscale.subnetApprovalHint")}
            </div>
          ) : null}

          {tsStatus?.state === "connected" && tsStatus.control_available ? (
            <div className="rounded-[8px] border border-border/70 bg-muted/20 p-2.5 space-y-2">
              <button
                type="button"
                onClick={() => setTaildropOpen((v) => !v)}
                className="flex w-full items-center justify-between text-xs font-medium text-foreground"
              >
                <span className="inline-flex items-center gap-1.5">
                  <Send className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                  {tr("tailscale.taildropTitle")}
                  {(tsStatus.waiting_file_count ?? 0) > 0 ? (
                    <span className="badge-radius bg-primary/15 px-1.5 py-0.5 text-[10px] text-primary">
                      {tsStatus.waiting_file_count}
                    </span>
                  ) : null}
                </span>
                <ChevronDown className={`h-3.5 w-3.5 transition-transform ${taildropOpen ? "rotate-180" : ""}`} />
              </button>
              {taildropOpen ? (
                <div className="space-y-2 border-t border-border/60 pt-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Select
                      value={taildropPeerId}
                      onChange={(e) => setTaildropPeerId(e.target.value)}
                      className="min-w-[160px] flex-1"
                    >
                      <option value="">{tr("tailscale.taildropSelectPeer")}</option>
                      {onlinePeers.map((p) => (
                        <option key={p.stable_id} value={p.stable_id || ""}>
                          {p.hostname || p.dns_name} ({p.ipv4 || p.os || "online"})
                        </option>
                      ))}
                    </Select>
                    <label
                      className={[
                        "inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-[6px] border border-border bg-background px-2.5 text-xs font-medium hover:bg-accent",
                        !taildropPeerId || taildropSending ? "pointer-events-none opacity-50" : "",
                      ].join(" ")}
                    >
                      <Send className="h-3.5 w-3.5" aria-hidden="true" />
                      {tr("tailscale.taildropSend")}
                      <input
                        type="file"
                        className="hidden"
                        disabled={!taildropPeerId || taildropSending}
                        onChange={(e) => {
                          const f = e.target.files?.[0] || null;
                          e.target.value = "";
                          void handleSendTaildropFile(f);
                        }}
                      />
                    </label>
                    <Button type="button" variant="ghost" size="sm" onClick={() => void refreshTaildrop()}>
                      <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                    </Button>
                  </div>
                  {taildropInbox && taildropInbox.files.length > 0 ? (
                    <div className="space-y-1">
                      {taildropInbox.files.map((f) => (
                        <div
                          key={f.name}
                          className="flex items-center justify-between gap-2 rounded-[6px] border border-border/60 bg-background/70 px-2 py-1.5 text-[11px]"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="truncate font-medium text-foreground">{f.name}</div>
                            <div className="text-[10px] text-muted-foreground">
                              {formatBytes(f.size)} {f.sender_name ? `· ${f.sender_name}` : ""}
                            </div>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              className="h-6 px-2 text-[10px]"
                              onClick={() => void handleDownloadTaildrop(f.name)}
                            >
                              <Download className="mr-1 h-3 w-3" aria-hidden="true" />
                              {tr("tailscale.taildropDownload")}
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6 text-destructive"
                              onClick={() => void handleDeleteTaildrop(f.name)}
                              aria-label={tr("action.delete")}
                            >
                              <Trash2 className="h-3 w-3" aria-hidden="true" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] text-muted-foreground">{tr("tailscale.taildropInboxEmpty")}</div>
                  )}
                </div>
              ) : null}
            </div>
          ) : null}

          <div className="grid grid-cols-1 gap-2 rounded-[8px] border border-border/70 bg-muted/25 p-2.5 sm:grid-cols-2">
            <label className="flex cursor-pointer items-center justify-between gap-2">
              <span>{tr("tailscale.acceptRoutes")}</span>
              <Switch
                checked={cfg.accept_routes}
                onCheckedChange={(checked) => setCfg((prev) => ({ ...prev, accept_routes: checked }))}
              />
            </label>
            <label className="flex cursor-pointer items-center justify-between gap-2">
              <span>{tr("tailscale.magicDns")}</span>
              <Switch
                checked={cfg.magic_dns}
                onCheckedChange={(checked) => setCfg((prev) => ({ ...prev, magic_dns: checked }))}
              />
            </label>
            <label className="flex cursor-pointer items-center justify-between gap-2">
              <span>{tr("tailscale.ephemeral")}</span>
              <Switch
                checked={Boolean(cfg.ephemeral)}
                onCheckedChange={(checked) => setCfg((prev) => ({ ...prev, ephemeral: checked }))}
              />
            </label>
            <label className="flex cursor-pointer items-center justify-between gap-2">
              <span>{tr("tailscale.advertiseExitNode")}</span>
              <Switch
                checked={Boolean(cfg.advertise_exit_node)}
                onCheckedChange={(checked) => setCfg((prev) => ({ ...prev, advertise_exit_node: checked }))}
              />
            </label>
            {cfg.exit_node?.trim() ? (
              <label className="flex cursor-pointer items-center justify-between gap-2">
                <span>{tr("tailscale.exitNodeAllowLan")}</span>
                <Switch
                  checked={Boolean(cfg.exit_node_allow_lan)}
                  onCheckedChange={(checked) => setCfg((prev) => ({ ...prev, exit_node_allow_lan: checked }))}
                />
              </label>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex flex-wrap items-center gap-2">
              {tsStatus?.state === "connected" && tsStatus.control_available ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={loggingOut}
                  onClick={() => void handleLogout()}
                >
                  <LogOut className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("tailscale.logoutBtn")}
                </Button>
              ) : null}
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={resetting || !stateInit}
                onClick={() => void handleResetState()}
              >
                <RotateCcw className={`mr-1.5 h-3.5 w-3.5 ${resetting ? "animate-spin" : ""}`} aria-hidden="true" />
                {tr("tailscale.resetState")}
              </Button>
            </div>
            <Button type="button" size="sm" disabled={saving} onClick={() => void handleSave()}>
              <Save className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {locale === "zh-CN" ? "保存并应用 Tailscale" : "Save & Apply Tailscale"}
            </Button>
          </div>
        </CardContent>
      ) : null}
    </Card>
  );
}
