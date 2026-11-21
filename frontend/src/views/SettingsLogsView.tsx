// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  Cpu,
  Download,
  FileArchive,
  Fingerprint,
  Gauge,
  Image as ImageIcon,
  Lock,
  LogOut,
  Monitor,
  Palette,
  Plus,
  QrCode,
  RefreshCw,
  RotateCcw,
  Save,
  ScrollText,
  Server,
  ShieldAlert,
  Trash2,
  Upload,
} from "lucide-react";
import {
  androidBridge,
  type AppSettings,
  type AutostartStatus,
  type BiometricStatus,
  type GpuStatus,
  type HealthSettings,
  type ListenConfig,
  api,
  formatApiError,
  getBiometricStatus,
  getGpuStatus,
  isDesktop,
  setGpuMode,
} from "../lib/api.ts";
import {
  ACCENT_PRESETS,
  BACKGROUND_PRESETS,
  DEFAULT_APPEARANCE,
  type AppearanceConfig,
  type BackgroundPresetId,
  clearWallpaperDataUrl,
  compressWallpaperFile,
  loadAppearanceConfig,
  loadWallpaperDataUrl,
  saveAppearanceConfig,
  saveWallpaperDataUrl,
} from "../lib/appearance.ts";
import {
  type DurationUnit,
  joinToMilliseconds,
  joinToSeconds,
  splitMilliseconds,
  splitSeconds,
} from "../lib/duration.ts";
import { formatBytes } from "../lib/helpers.ts";
import { type TranslationKey } from "../lib/i18n.ts";
import { ALL_CONNECTION_COLUMNS, type ConnectionColumnId, useAppStore, useLogsTelemetry } from "../store/appStore.ts";
import { ColorWheelPicker } from "../components/ColorWheelPicker.tsx";
import { DurationInput } from "../components/DurationInput.tsx";
import { AppUpdateCard } from "../components/AppUpdateCard.tsx";
import { HelpTip } from "../components/HelpTip.tsx";
import { type ListenerExitValue, NodeMultiSelectDropdown } from "../components/NodeMultiSelectDropdown.tsx";
import { RoutingQrModal } from "../components/RoutingQrModal.tsx";
import { SectionAnchorBar } from "../components/SectionAnchorBar.tsx";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Input } from "../components/ui/input.tsx";
import { Select } from "../components/ui/select.tsx";
import { Switch } from "../components/ui/switch.tsx";

export function SettingsLogsView() {
  const {
    tr,
    locale,
    setLocale,
    themeMode,
    resolvedTheme,
    setThemeMode,
    nodeViewMode,
    setNodeViewMode,
    connectionColumns,
    setConnectionColumns,
    nodes,
    groups,
    subscriptions,
    customNodeTabs,
    routing,
    authStatus,
    setAuthStatus,
    listeners,
    cores,
    ruleSets,
    registerUnsavedGuard,
    tunState,
    refreshAll,
    notify,
  } = useAppStore();
  const { logs } = useLogsTelemetry();
  const idPrefix = useId();

  const [lisName, setLisName] = useState("Local Mixed");
  const [lisProto, setLisProto] = useState("mixed");
  const [lisAddr, setLisAddr] = useState("127.0.0.1");
  const [lisPort, setLisPort] = useState(2081);
  const [lisAllowLan, setLisAllowLan] = useState(false);
  const [lisExit, setLisExit] = useState<ListenerExitValue>({ kind: "default" });

  const [gpuStatus, setGpuStatus] = useState<GpuStatus | null>(null);
  const [savingGpu, setSavingGpu] = useState(false);
  const [biometricStatus, setBiometricStatus] = useState<BiometricStatus | null>(null);
  const [savingBiometric, setSavingBiometric] = useState(false);
  const [routingQrOpen, setRoutingQrOpen] = useState(false);
  const [routingQrTab, setRoutingQrTab] = useState<"export" | "import">("export");
  const [backupModules, setBackupModules] = useState<Record<string, boolean>>({
    nodes: true,
    groups: true,
    subscriptions: true,
    routing: true,
    listeners: true,
    settings: true,
  });

  const [healthDraft, setHealthDraft] = useState<HealthSettings>({
    url: "https://www.gstatic.com/generate_204",
    speed_down_url: "https://speed.cloudflare.com/__down?bytes=10000000",
    speed_up_url: "https://speed.cloudflare.com/__up",
    interval_seconds: 60,
    tolerance_ms: 80,
    high_latency_ms: 800,
    priority_rule: "latency_first",
    failover: true,
    recover: true,
  });
  const [healthBaseline, setHealthBaseline] = useState<HealthSettings | null>(null);
  const [savingHealth, setSavingHealth] = useState(false);

  const [settingsDraft, setSettingsDraft] = useState<AppSettings | null>(null);
  const [settingsBaseline, setSettingsBaseline] = useState<AppSettings | null>(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [autostartState, setAutostartState] = useState<AutostartStatus | null>(null);
  const [savingAutostart, setSavingAutostart] = useState(false);
  const isAndroid = androidBridge.available();
  const [androidBootAutostart, setAndroidBootAutostart] = useState<boolean>(() =>
    androidBridge.available() ? androidBridge.getBootAutostart() : false,
  );

  const [lockPassword, setLockPassword] = useState("");
  const [lockCurrentPassword, setLockCurrentPassword] = useState("");
  const [logLevelFilter, setLogLevelFilter] = useState("all");
  const [logSearch, setLogSearch] = useState("");
  const [syncingRulesets, setSyncingRulesets] = useState(false);
  const [ensuringCores, setEnsuringCores] = useState(false);

  const [appearance, setAppearance] = useState<AppearanceConfig>(() => loadAppearanceConfig());
  const [wallpaperPreview, setWallpaperPreview] = useState<string | null>(null);
  const [uploadingWallpaper, setUploadingWallpaper] = useState(false);

  const [healthIntervalVal, setHealthIntervalVal] = useState(1);
  const [healthIntervalUnit, setHealthIntervalUnit] = useState<DurationUnit>("m");
  const [healthToleranceVal, setHealthToleranceVal] = useState(50);
  const [healthToleranceUnit, setHealthToleranceUnit] = useState<DurationUnit>("ms");

  useEffect(() => {
    void loadWallpaperDataUrl().then(setWallpaperPreview);
  }, []);

  const updateAppearance = (patch: Partial<AppearanceConfig>) => {
    const next = saveAppearanceConfig({ ...appearance, ...patch });
    setAppearance(next);
  };

  const handleUploadWallpaper = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      notify(tr("settings.bgInvalidImage"), "error");
      return;
    }
    setUploadingWallpaper(true);
    try {
      const dataUrl = await compressWallpaperFile(file, 1920);
      await saveWallpaperDataUrl(dataUrl);
      setWallpaperPreview(dataUrl);
      const next = saveAppearanceConfig({ ...appearance, bgPreset: "custom" });
      setAppearance(next);
      notify(tr("settings.bgUploaded"), "success");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setUploadingWallpaper(false);
    }
  };

  const handleRemoveWallpaper = async () => {
    await clearWallpaperDataUrl();
    setWallpaperPreview(null);
    if (appearance.bgPreset === "custom") {
      const next = saveAppearanceConfig({ ...appearance, bgPreset: "none" });
      setAppearance(next);
    }
  };

  const handleResetAppearance = async () => {
    await clearWallpaperDataUrl();
    setWallpaperPreview(null);
    const next = saveAppearanceConfig({ ...DEFAULT_APPEARANCE });
    setAppearance(next);
    notify(tr("settings.appearanceResetDone"), "success");
  };

  useEffect(() => {
    void api
      .getSettings()
      .then((s) => {
        setSettingsDraft(s);
        setSettingsBaseline(s);
      })
      .catch(() => {});
    void api
      .getHealthSettings()
      .then((h) => {
        setHealthDraft(h);
        setHealthBaseline(h);
        const intParts = splitSeconds(h.interval_seconds || 60, ["s", "m", "h", "d"], "m");
        setHealthIntervalVal(intParts.value);
        setHealthIntervalUnit(intParts.unit);
        const tolParts = splitMilliseconds(h.tolerance_ms ?? 50, ["ms", "s", "m"], "ms");
        setHealthToleranceVal(tolParts.value);
        setHealthToleranceUnit(tolParts.unit);
      })
      .catch(() => {});
    if (androidBridge.available()) {
      setAndroidBootAutostart(androidBridge.getBootAutostart());
      void getBiometricStatus()
        .then(setBiometricStatus)
        .catch(() => {});
    } else if (isDesktop) {
      void api
        .getAutostart()
        .then(setAutostartState)
        .catch(() => {});
      void getGpuStatus()
        .then(setGpuStatus)
        .catch(() => {});
      void getBiometricStatus()
        .then(setBiometricStatus)
        .catch(() => {});
    }
  }, []);

  const stripAnsiCodes = (raw: string): string =>
    raw
      .replace(/\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))/g, "")
      .replace(/\[(?:\d{1,3}(?:;\d{1,3})*)m/g, "");

  const handleCopyLogLine = async (text: string) => {
    try {
      if (window.PrismRayAndroid?.copyToClipboard?.(text)) {
        notify(tr("settings.logCopied"));
        return;
      }
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(text);
        notify(tr("settings.logCopied"));
        return;
      }
    } catch {
      // Fallback below.
    }
    try {
      const el = document.createElement("textarea");
      el.value = text;
      el.setAttribute("readonly", "");
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      notify(tr("settings.logCopied"));
    } catch {
      // Ignore clipboard restriction.
    }
  };

  const filteredLogs = useMemo(() => {
    const q = logSearch.trim().toLowerCase();
    return logs
      .filter((entry) => {
        if (logLevelFilter !== "all" && entry.level.toLowerCase() !== logLevelFilter) return false;
        if (!q) return true;
        return (
          entry.message.toLowerCase().includes(q) ||
          entry.core.toLowerCase().includes(q)
        );
      })
      .slice(-200);
  }, [logs, logLevelFilter, logSearch]);

  const decodeListenerExit = (l: ListenConfig): ListenerExitValue => {
    if ((l.target_outbound || "").trim().toLowerCase() === "direct") return { kind: "direct" };
    if (l.target_group_id) return { kind: "group", groupId: l.target_group_id };
    if (l.node_ids && l.node_ids.length > 0) return { kind: "nodes", nodeIds: l.node_ids };
    return { kind: "default" };
  };

  const encodeListenerExit = (
    exitVal: ListenerExitValue,
  ): { target_outbound: string; target_group_id: string; node_ids: string[] } => {
    if (exitVal.kind === "direct") {
      return { target_outbound: "direct", target_group_id: "", node_ids: [] };
    }
    if (exitVal.kind === "group") {
      return { target_outbound: "", target_group_id: exitVal.groupId, node_ids: [] };
    }
    if (exitVal.kind === "nodes" && exitVal.nodeIds.length > 0) {
      return { target_outbound: "", target_group_id: "", node_ids: exitVal.nodeIds };
    }
    return { target_outbound: "", target_group_id: "", node_ids: [] };
  };

  const handleToggleAddAllowLan = (checked: boolean) => {
    setLisAllowLan(checked);
    const trimmed = lisAddr.trim();
    if (checked && (!trimmed || trimmed === "127.0.0.1" || trimmed === "::1")) {
      setLisAddr("0.0.0.0");
    } else if (!checked && trimmed === "0.0.0.0") {
      setLisAddr("127.0.0.1");
    }
  };

  const handleAddListener = async (e: React.FormEvent) => {
    e.preventDefault();
    const encoded = encodeListenerExit(lisExit);
    try {
      await api.addListener({
        name: lisName.trim() || lisProto,
        protocol: lisProto,
        address: lisAddr.trim() || "127.0.0.1",
        port: Number(lisPort),
        allow_lan: lisAllowLan,
        target_outbound: encoded.target_outbound,
        target_group_id: encoded.target_group_id,
        node_ids: encoded.node_ids,
        enabled: true,
      });
      setLisExit({ kind: "default" });
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleUpdateListenerTarget = async (l: ListenConfig, exitVal: ListenerExitValue) => {
    const encoded = encodeListenerExit(exitVal);
    try {
      await api.updateListener(l.id, {
        ...l,
        target_outbound: encoded.target_outbound,
        target_group_id: encoded.target_group_id,
        node_ids: encoded.node_ids,
      });
      await refreshAll();
      notify(locale === "zh-CN" ? "入站绑定出口已更新" : "Listener exit target updated");
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleGpuModeChange = async (mode: "auto" | "on" | "off") => {
    setSavingGpu(true);
    try {
      const next = await setGpuMode(mode);
      if (next) setGpuStatus(next);
      notify(tr("settings.gpuSaved"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingGpu(false);
    }
  };

  const saveHealthSettingsNow = async (): Promise<boolean> => {
    setSavingHealth(true);
    try {
      const saved = await api.saveHealthSettings(healthDraft);
      setHealthDraft(saved);
      setHealthBaseline(saved);
      await refreshAll();
      notify(tr("settings.healthSaved"));
      return true;
    } catch (err) {
      notify(formatApiError(err), "error");
      return false;
    } finally {
      setSavingHealth(false);
    }
  };

  const handleSaveHealthSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    await saveHealthSettingsNow();
  };

  const handleDeleteListener = async (id: string) => {
    try {
      await api.deleteListener(id);
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleApplyListeners = async () => {
    try {
      await api.applyListeners();
      await refreshAll();
      notify(locale === "zh-CN" ? "入站监听端口已应用" : "Listeners applied");
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleEnsureCores = async () => {
    setEnsuringCores(true);
    try {
      await api.ensureCores();
      await refreshAll();
      notify(locale === "zh-CN" ? "核心校验/补齐完成" : "Dual cores verified");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setEnsuringCores(false);
    }
  };

  const handleInstallCore = async (core: "sing-box" | "xray") => {
    setEnsuringCores(true);
    try {
      await api.installCore({ core, download: true });
      await refreshAll();
      notify(`${core} installed`);
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setEnsuringCores(false);
    }
  };

  const handleSyncRuleSets = async () => {
    setSyncingRulesets(true);
    try {
      const res = await api.syncRuleSets();
      await refreshAll();
      const errEntries = Object.entries(res.errors || {});
      const syncedCount = res.synced_count ?? res.rule_sets.filter((r) => r.synced).length;
      if (errEntries.length > 0 && syncedCount === 0) {
        const firstErr = `${errEntries[0][0]}: ${errEntries[0][1]}`;
        notify(
          locale === "zh-CN"
            ? `.srs 规则集同步失败 (${errEntries.length} 项): ${firstErr}`
            : `Rule set sync failed (${errEntries.length}): ${firstErr}`,
          "error",
        );
      } else if (errEntries.length > 0) {
        notify(
          tr("settings.rulesetsSyncPartial", { count: syncedCount, failed: errEntries.length }),
          "warning",
        );
      } else if (res.reloaded) {
        notify(tr("settings.rulesetsSyncedReloaded", { count: syncedCount }));
      } else {
        notify(locale === "zh-CN" ? `已同步 ${syncedCount} 个 .srs 规则集` : `Synced ${syncedCount} rule sets`);
      }
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSyncingRulesets(false);
    }
  };

  const handleTogglePasswordLock = async (enable: boolean) => {
    try {
      await api.setPasswordLock({
        enabled: enable,
        password: lockPassword,
        current_password: lockCurrentPassword || undefined,
      });
      setLockPassword("");
      setLockCurrentPassword("");
      const nextAuth = await api.getAuthStatus();
      setAuthStatus(nextAuth);
      notify(locale === "zh-CN" ? "启动密码锁设置已更新" : "Password lock updated");
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleToggleBiometric = async (enable: boolean) => {
    if (enable && !lockCurrentPassword.trim()) {
      notify(tr("settings.biometricNeedPassword"), "error");
      return;
    }
    setSavingBiometric(true);
    try {
      await api.setBiometricUnlock({
        enabled: enable,
        current_password: enable ? lockCurrentPassword : undefined,
      });
      setLockCurrentPassword("");
      const nextAuth = await api.getAuthStatus();
      setAuthStatus(nextAuth);
      notify(
        enable
          ? locale === "zh-CN"
            ? "系统生物信息解锁已启用"
            : "Biometric unlock enabled"
          : locale === "zh-CN"
            ? "系统生物信息解锁已关闭"
            : "Biometric unlock disabled",
      );
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingBiometric(false);
    }
  };

  const handleExportRoutingJson = async () => {
    try {
      const profile = routing || (await api.getRouting());
      const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prismray-routing-profile-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const selectedBackupKeys = Object.entries(backupModules)
    .filter(([, checked]) => checked)
    .map(([key]) => key);

  const handleExportBackup = async () => {
    if (selectedBackupKeys.length === 0) {
      notify(locale === "zh-CN" ? "请至少勾选一个要导出的配置模块" : "Select at least one module to export", "error");
      return;
    }
    try {
      const data = await api.exportBackup(selectedBackupKeys);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prismray-backup-v4-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleRestoreBackup = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as Record<string, unknown>;
      await api.restoreBackup(parsed);
      await refreshAll();
      notify(locale === "zh-CN" ? "备份恢复成功" : "Backup restored");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      e.target.value = "";
    }
  };

  const handleMergeBackup = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as Record<string, unknown>;
      const res = await api.mergeBackup(parsed);
      await refreshAll();
      notify(
        locale === "zh-CN"
          ? `合并导入成功（节点 ${res.nodes} / 分组 ${res.groups} / 规则 ${res.custom_rules}）`
          : `Merged bundle (${res.nodes} nodes, ${res.groups} groups, ${res.custom_rules} rules)`,
      );
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      e.target.value = "";
    }
  };

  const saveCoreSettingsNow = async (): Promise<boolean> => {
    if (!settingsDraft) return true;
    setSavingSettings(true);
    try {
      const res = await api.saveSettings(settingsDraft);
      setSettingsDraft(res.saved);
      setSettingsBaseline(res.saved);
      notify(res.restart_required ? tr("settings.restartNotice") : tr("action.save"));
      return true;
    } catch (err) {
      notify(formatApiError(err), "error");
      return false;
    } finally {
      setSavingSettings(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    await saveCoreSettingsNow();
  };

  const healthDirty = Boolean(healthBaseline && JSON.stringify(healthDraft) !== JSON.stringify(healthBaseline));
  const settingsPortsDirty = Boolean(
    !isAndroid &&
      settingsDraft &&
      settingsBaseline &&
      JSON.stringify(settingsDraft) !== JSON.stringify(settingsBaseline),
  );
  const settingsUnsavedRef = useRef({
    healthDirty,
    settingsPortsDirty,
    saveHealthSettingsNow,
    saveCoreSettingsNow,
  });
  settingsUnsavedRef.current = {
    healthDirty,
    settingsPortsDirty,
    saveHealthSettingsNow,
    saveCoreSettingsNow,
  };

  useEffect(() => {
    registerUnsavedGuard("settings", {
      isDirty: () => settingsUnsavedRef.current.healthDirty || settingsUnsavedRef.current.settingsPortsDirty,
      save: async () => {
        const cur = settingsUnsavedRef.current;
        if (cur.healthDirty) {
          const ok = await cur.saveHealthSettingsNow();
          if (!ok) return false;
        }
        if (cur.settingsPortsDirty) {
          const ok = await cur.saveCoreSettingsNow();
          if (!ok) return false;
        }
        return true;
      },
    });
    return () => registerUnsavedGuard("settings", null);
  }, [registerUnsavedGuard]);

  const handleAutostartUpdate = async (enabled: boolean, minimized: boolean) => {
    setSavingAutostart(true);
    try {
      const next = await api.setAutostart({ enabled, minimized });
      setAutostartState(next);
      notify(tr("settings.autostartSaved"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingAutostart(false);
    }
  };

  const handleExportLogs = async () => {
    try {
      const text = await api.fetchLogsText();
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `prismray-logs-${new Date().toISOString().slice(0, 10)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleLockOrLogout = async (logout: boolean) => {
    try {
      if (logout) await api.logoutAuth();
      else await api.lockAuth();
      const next = await api.getAuthStatus();
      setAuthStatus(next);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const currentThemeWord = resolvedTheme === "dark" ? tr("settings.themeDark") : tr("settings.themeLight");

  const anchorItems = [
    { id: "settings-appearance", label: tr("settings.anchorAppearance") },
    { id: "settings-listeners", label: tr("settings.anchorListeners") },
    { id: "settings-health", label: tr("settings.healthAnchor") },
    { id: "settings-cores", label: tr("settings.anchorCores") },
    { id: "settings-backup", label: tr("settings.anchorBackup") },
    { id: "settings-security", label: tr("settings.anchorSecurity") },
    ...(settingsDraft && !isAndroid ? [{ id: "settings-ports", label: tr("settings.anchorPorts") }] : []),
    { id: "settings-logs", label: tr("settings.anchorLogs") },
  ];

  const CONN_COL_LABELS: Record<ConnectionColumnId, TranslationKey> = {
    target: "conns.colTarget",
    network: "conns.colNetwork",
    outboundNode: "conns.colOutboundNode",
    engine: "conns.colEngine",
    group: "conns.colGroup",
    rule: "conns.colRule",
    process: "conns.colProcess",
    traffic: "conns.colTraffic",
    duration: "conns.colDuration",
    source: "conns.colSource",
    action: "conns.colAction",
  };

  const toggleDefaultConnCol = (colId: ConnectionColumnId) => {
    if (connectionColumns.includes(colId)) {
      if (connectionColumns.length <= 2) return;
      setConnectionColumns(connectionColumns.filter((c) => c !== colId));
    } else {
      setConnectionColumns([...connectionColumns, colId]);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold text-foreground">{tr("settings.title")}</h2>

      <SectionAnchorBar ariaLabel={tr("settings.anchorNav")} items={anchorItems} />

      {/* Appearance & Language & Default Node View */}
      <section id="settings-appearance" tabIndex={-1} className="scroll-mt-20 outline-none">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Palette className="h-5 w-5 text-primary" aria-hidden="true" />
              {tr("settings.appearance")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-2" role="group" aria-label={tr("settings.appearance")}>
                {(
                  [
                    { id: "light", label: tr("settings.themeLight") },
                    { id: "dark", label: tr("settings.themeDark") },
                    { id: "system", label: tr("settings.themeSystem", { current: currentThemeWord }) },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    aria-pressed={themeMode === opt.id}
                    onClick={() => setThemeMode(opt.id)}
                    className={[
                      "rounded-[6px] border px-3 py-1.5 max-md:min-h-[var(--m-btn-sm-h)] text-xs font-medium transition-colors",
                      themeMode === opt.id
                        ? "border-primary bg-primary/15 text-primary"
                        : "border-border bg-background text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-2">
                <span className="whitespace-nowrap text-xs text-muted-foreground">{tr("settings.language")}:</span>
                <div className="w-32 shrink-0">
                  <Select
                    aria-label={tr("settings.language")}
                    size="sm"
                    value={locale}
                    onChange={(e) => setLocale(e.target.value as "zh-CN" | "en-US")}
                  >
                    <option value="zh-CN">简体中文</option>
                    <option value="en-US">English</option>
                  </Select>
                </div>
              </div>
            </div>

            {/* Mobile / Touch Control & Icon Density */}
            <div className="flex flex-col gap-2 border-t border-border pt-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-medium text-foreground">{tr("settings.uiDensity")}</span>
                <HelpTip ariaLabel={tr("settings.uiDensity")} text={tr("settings.uiDensityHint")} />
              </div>
              <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label={tr("settings.uiDensity")}>
                {(
                  [
                    { id: "ultra", label: tr("settings.uiDensityUltra") },
                    { id: "compact", label: tr("settings.uiDensityCompact") },
                    { id: "comfortable", label: tr("settings.uiDensityComfortable") },
                  ] as const
                ).map((opt) => {
                  const selected = (appearance.uiDensity || "compact") === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => updateAppearance({ uiDensity: opt.id })}
                      className={[
                        "rounded-[6px] border px-2.5 py-1 max-md:min-h-[var(--m-btn-sm-h)] text-xs font-medium transition-colors",
                        selected
                          ? "border-primary bg-primary/15 text-primary"
                          : "border-border bg-background text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Custom Theme Accent Color */}
            <div className="space-y-2.5 border-t border-border pt-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-medium text-foreground">{tr("settings.accentColor")}</span>
                  <HelpTip ariaLabel={tr("settings.accentColor")} text={tr("settings.accentColorHint")} />
                </div>
                {(appearance.accentHex || appearance.bgPreset !== "none" || wallpaperPreview) ? (
                  <Button type="button" variant="ghost" size="sm" onClick={() => void handleResetAppearance()}>
                    <RotateCcw className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                    {tr("settings.resetAppearance")}
                  </Button>
                ) : null}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {ACCENT_PRESETS.map((preset) => {
                  const selected = appearance.accentHex.toLowerCase() === preset.hex.toLowerCase();
                  const swatchColor = preset.hex || (resolvedTheme === "dark" ? "#5e6ad2" : "#4f46e5");
                  const label = locale === "zh-CN" ? preset.labelZh : preset.labelEn;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      aria-pressed={selected}
                      title={label}
                      onClick={() => updateAppearance({ accentHex: preset.hex })}
                      className={[
                        "inline-flex items-center gap-1.5 rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors",
                        selected
                          ? "border-primary bg-primary/15 text-primary"
                          : "border-border bg-background text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                    >
                      <span
                        className="color-swatch-chip h-3.5 w-3.5 shrink-0 rounded-full border border-black/15 dark:border-white/20"
                        style={{ backgroundColor: swatchColor }}
                        aria-hidden="true"
                      />
                      <span>{label}</span>
                    </button>
                  );
                })}

                <ColorWheelPicker
                  value={appearance.accentHex || (resolvedTheme === "dark" ? "#5e6ad2" : "#4f46e5")}
                  selected={Boolean(
                    appearance.accentHex &&
                      !ACCENT_PRESETS.some((p) => p.hex.toLowerCase() === appearance.accentHex.toLowerCase()),
                  )}
                  label={tr("settings.customAccentPicker")}
                  title={tr("settings.colorWheelTitle")}
                  onChange={(hex) => updateAppearance({ accentHex: hex })}
                />
              </div>
            </div>

            {/* Custom Background & Frosted Glass Controls */}
            <div className="space-y-3 border-t border-border pt-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  <ImageIcon className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                  <span className="text-xs font-medium text-foreground">{tr("settings.bgWallpaper")}</span>
                  <HelpTip ariaLabel={tr("settings.bgWallpaper")} text={tr("settings.bgWallpaperHint")} />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative inline-flex items-center">
                    <input
                      id={`${idPrefix}-upload-wallpaper`}
                      type="file"
                      accept="image/*"
                      disabled={uploadingWallpaper}
                      className="visually-hidden peer"
                      onChange={(e) => void handleUploadWallpaper(e)}
                    />
                    <label
                      htmlFor={`${idPrefix}-upload-wallpaper`}
                      className="inline-flex min-h-7 cursor-pointer items-center rounded-[6px] border border-input bg-background px-2.5 py-1 text-xs font-medium hover:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring"
                    >
                      <Upload className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                      {uploadingWallpaper ? tr("common.loadingView") : tr("settings.bgUploadBtn")}
                    </label>
                  </div>
                  {wallpaperPreview ? (
                    <Button type="button" variant="ghost" size="sm" onClick={() => void handleRemoveWallpaper()}>
                      <Trash2 className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                      {tr("settings.bgClearImage")}
                    </Button>
                  ) : null}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2" role="group" aria-label={tr("settings.bgWallpaper")}>
                {BACKGROUND_PRESETS.map((preset) => {
                  const selected = appearance.bgPreset === preset.id;
                  const label = locale === "zh-CN" ? preset.labelZh : preset.labelEn;
                  const previewGrad = resolvedTheme === "dark" ? preset.darkGradient : preset.lightGradient;
                  return (
                    <button
                      key={preset.id}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => updateAppearance({ bgPreset: preset.id as BackgroundPresetId })}
                      className={[
                        "inline-flex items-center gap-2 rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors",
                        selected
                          ? "border-primary bg-primary/15 text-primary"
                          : "border-border bg-background text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                    >
                      <span
                        className="color-swatch-chip h-3.5 w-5 shrink-0 rounded-[3px] border border-border bg-muted"
                        style={previewGrad !== "none" ? { backgroundImage: previewGrad } : undefined}
                        aria-hidden="true"
                      />
                      <span>{label}</span>
                    </button>
                  );
                })}
                {wallpaperPreview ? (
                  <button
                    type="button"
                    aria-pressed={appearance.bgPreset === "custom"}
                    onClick={() => updateAppearance({ bgPreset: "custom" })}
                    className={[
                      "inline-flex items-center gap-2 rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors",
                      appearance.bgPreset === "custom"
                        ? "border-primary bg-primary/15 text-primary"
                        : "border-border bg-background text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    <span
                      className="h-3.5 w-5 shrink-0 rounded-[3px] border border-border bg-cover bg-center"
                      style={{ backgroundImage: `url("${wallpaperPreview}")` }}
                      aria-hidden="true"
                    />
                    <span>{tr("settings.bgCustomImage")}</span>
                  </button>
                ) : null}
              </div>

              {appearance.bgPreset !== "none" && (appearance.bgPreset !== "custom" || Boolean(wallpaperPreview)) ? (
                <div className="grid grid-cols-1 gap-3 rounded-[8px] border border-border bg-muted/25 p-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                  <label className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">{tr("settings.bgBlur")}</span>
                      <span className="tabular-nums font-medium text-foreground">{appearance.bgBlur}px</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={24}
                      step={1}
                      value={appearance.bgBlur}
                      onChange={(e) => updateAppearance({ bgBlur: Number(e.target.value) })}
                      className="w-full accent-primary cursor-pointer"
                    />
                  </label>
                  <label className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">{tr("settings.glassBlur")}</span>
                      <span className="tabular-nums font-medium text-foreground">{appearance.glassBlur}px</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={32}
                      step={1}
                      value={appearance.glassBlur}
                      onChange={(e) => updateAppearance({ glassBlur: Number(e.target.value) })}
                      className="w-full accent-primary cursor-pointer"
                    />
                  </label>
                  <label className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">{tr("settings.bgDim")}</span>
                      <span className="tabular-nums font-medium text-foreground">{appearance.bgDim}%</span>
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={85}
                      step={1}
                      value={appearance.bgDim}
                      onChange={(e) => updateAppearance({ bgDim: Number(e.target.value) })}
                      className="w-full accent-primary cursor-pointer"
                    />
                  </label>
                  <label className="space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-muted-foreground">{tr("settings.cardGlass")}</span>
                      <span className="tabular-nums font-medium text-foreground">{appearance.cardOpacity}%</span>
                    </div>
                    <input
                      type="range"
                      min={20}
                      max={96}
                      step={1}
                      value={appearance.cardOpacity}
                      onChange={(e) => updateAppearance({ cardOpacity: Number(e.target.value) })}
                      className="w-full accent-primary cursor-pointer"
                    />
                  </label>
                </div>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
              <span className="text-xs font-medium text-muted-foreground">{tr("settings.nodeViewMode")}</span>
              <div className="flex items-center gap-2" role="group" aria-label={tr("settings.nodeViewMode")}>
                {(
                  [
                    { id: "grid", label: tr("proxies.viewGrid") },
                    { id: "list", label: tr("proxies.viewList") },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    aria-pressed={nodeViewMode === opt.id}
                    onClick={() => setNodeViewMode(opt.id)}
                    className={[
                      "rounded-[6px] border px-3 py-1.5 max-md:min-h-[var(--m-btn-sm-h)] text-xs font-medium transition-colors",
                      nodeViewMode === opt.id
                        ? "border-primary bg-primary/15 text-primary"
                        : "border-border bg-background text-muted-foreground hover:text-foreground",
                    ].join(" ")}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {isAndroid ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <label htmlFor={`${idPrefix}-android-autostart`} className="block text-xs font-medium text-foreground">
                      {tr("settings.autostart")}
                    </label>
                    <HelpTip ariaLabel={tr("settings.autostart")} text={tr("settings.androidAutostartDesc")} />
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => androidBridge.openVpnSettings()}
                  >
                    {tr("settings.openVpnSettings")}
                  </Button>
                  <Switch
                    id={`${idPrefix}-android-autostart`}
                    checked={androidBootAutostart}
                    onCheckedChange={(checked) => {
                      setAndroidBootAutostart(checked);
                      androidBridge.setBootAutostart(checked);
                      notify(
                        checked
                          ? locale === "zh-CN"
                            ? "已开启 Android 开机自动连接 VPN"
                            : "Android boot autostart enabled"
                          : locale === "zh-CN"
                            ? "已关闭 Android 开机自启"
                            : "Android boot autostart disabled",
                      );
                    }}
                  />
                </div>
              </div>
            ) : autostartState && (autostartState.supported || autostartState.reason) ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
                <div className="min-w-0 space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <label htmlFor={`${idPrefix}-autostart`} className="block text-xs font-medium text-foreground">
                      {tr("settings.autostart")}
                    </label>
                    <HelpTip
                      ariaLabel={tr("settings.autostart")}
                      text={
                        <div className="space-y-1">
                          <div>{autostartState.supported ? tr("settings.autostartDesc") : autostartState.reason}</div>
                          {autostartState.supported && autostartState.executable ? (
                            <div className="break-all font-mono text-[11px] text-muted-foreground">
                              {autostartState.executable}
                            </div>
                          ) : null}
                        </div>
                      }
                    />
                  </div>
                </div>
                {autostartState.supported && (
                  <div className="flex shrink-0 items-center gap-4">
                    <label className="flex items-center gap-1.5 whitespace-nowrap text-xs text-muted-foreground">
                      <input
                        type="checkbox"
                        className="accent-primary"
                        checked={autostartState.minimized}
                        disabled={savingAutostart}
                        onChange={(e) => {
                          const nextMin = e.target.checked;
                          if (autostartState.enabled) {
                            void handleAutostartUpdate(true, nextMin);
                          } else {
                            setAutostartState({ ...autostartState, minimized: nextMin });
                          }
                        }}
                      />
                      {tr("settings.autostartMinimized")}
                    </label>
                    <Switch
                      id={`${idPrefix}-autostart`}
                      checked={autostartState.enabled}
                      disabled={savingAutostart}
                      onCheckedChange={(checked) => void handleAutostartUpdate(checked, autostartState.minimized)}
                    />
                  </div>
                )}
              </div>
            ) : null}

            {/* Desktop GPU Hardware Rendering (hidden on Android/mobile) */}
            {!isAndroid ? (
            <div className="space-y-2.5 border-t pt-3">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 text-xs font-medium text-foreground">
                    <Monitor className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                    <span>{tr("settings.gpuTitle")}</span>
                    <HelpTip
                      ariaLabel={tr("settings.gpuTitle")}
                      text={gpuStatus ? tr("settings.gpuDesc") : tr("settings.gpuDesktopOnly")}
                    />
                    {gpuStatus?.cli_override ? (
                      <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] text-amber-600 dark:text-amber-400">
                        CLI: {gpuStatus.cli_override}
                      </span>
                    ) : null}
                  </div>
                </div>

                <div className="flex shrink-0 flex-wrap items-center gap-1.5" role="group" aria-label={tr("settings.gpuTitle")}>
                  {(
                    [
                      { id: "auto", label: tr("settings.gpuAuto") },
                      { id: "on", label: tr("settings.gpuOn") },
                      { id: "off", label: tr("settings.gpuOff") },
                    ] as const
                  ).map((opt) => {
                    const selected = (gpuStatus?.configured_mode || "auto") === opt.id;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        disabled={!gpuStatus || savingGpu}
                        aria-pressed={selected}
                        onClick={() => void handleGpuModeChange(opt.id)}
                        className={[
                          "rounded-[6px] border px-2.5 py-1.5 max-md:min-h-[var(--m-btn-sm-h)] text-xs font-medium transition-colors disabled:opacity-50",
                          selected
                            ? "border-primary bg-primary/15 text-primary"
                            : "border-border bg-background text-muted-foreground hover:text-foreground",
                        ].join(" ")}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {gpuStatus ? (
                <div className="flex flex-wrap items-center gap-2 rounded-[6px] border border-border bg-muted/40 px-3 py-2 mono-num text-[11px] text-muted-foreground">
                  <span>
                    {tr("settings.gpuEffective")}:{" "}
                    <strong className={gpuStatus.active ? "text-primary" : "text-foreground"}>
                      {gpuStatus.active ? "GPU Active" : "Software"} ({gpuStatus.effective_mode})
                    </strong>
                  </span>
                  <span>·</span>
                  <span>{gpuStatus.session}</span>
                  <span>·</span>
                  <span>{gpuStatus.vendor}</span>
                  {gpuStatus.detail ? <span>({gpuStatus.detail})</span> : null}
                </div>
              ) : null}
            </div>
            ) : null}

            {/* Default Connection Table Columns (desktop table only; hidden on mobile card view) */}
            <div className="hidden md:block space-y-2 border-t border-border pt-3">
              <div className="text-xs font-medium text-foreground">{tr("settings.connColumnsTitle")}</div>
              <div className="flex flex-wrap gap-1.5">
                {ALL_CONNECTION_COLUMNS.map((colId) => {
                  const active = connectionColumns.includes(colId);
                  return (
                    <button
                      key={colId}
                      type="button"
                      aria-pressed={active}
                      onClick={() => toggleDefaultConnCol(colId)}
                      className={[
                        "badge-radius border px-2 py-1 max-md:min-h-10 text-xs font-medium transition-colors",
                        active
                          ? "border-primary bg-primary/15 text-primary"
                          : "border-border bg-background text-muted-foreground hover:text-foreground",
                      ].join(" ")}
                    >
                      {tr(CONN_COL_LABELS[colId])}
                    </button>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Multi-Listener CRUD */}
      <section id="settings-listeners" tabIndex={-1} className="scroll-mt-20 outline-none">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Server className="h-5 w-5 text-primary" aria-hidden="true" />
            {tr("settings.listeners")}
          </CardTitle>
          <Button type="button" variant="outline" size="sm" onClick={() => void handleApplyListeners()}>
            {tr("settings.applyListeners")}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={(e) => void handleAddListener(e)} className="space-y-2.5 rounded-[10px] border border-border bg-muted/25 p-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-[1.2fr_0.8fr_1fr_0.7fr]">
              <Input aria-label="Listener Name" value={lisName} onChange={(e) => setLisName(e.target.value)} placeholder="Name" />
              <Select
                aria-label="Listener Protocol"
                value={lisProto}
                onChange={(e) => setLisProto(e.target.value)}
              >
                <option value="mixed">mixed</option>
                <option value="socks">socks</option>
                <option value="http">http</option>
              </Select>
              <Input aria-label="Listener Address" value={lisAddr} onChange={(e) => setLisAddr(e.target.value)} placeholder="127.0.0.1" />
              <Input
                aria-label="Listener Port"
                type="number"
                min={1}
                max={65535}
                value={lisPort}
                onChange={(e) => setLisPort(Number(e.target.value))}
              />
            </div>
            <div className="flex flex-wrap items-center gap-2.5">
              <NodeMultiSelectDropdown
                mode="listener-exit"
                className="min-w-[220px] flex-1"
                nodes={nodes}
                subscriptions={subscriptions}
                customNodeTabs={customNodeTabs}
                groups={groups}
                value={lisExit}
                onChange={setLisExit}
              />
              <div className="flex h-8 shrink-0 items-center gap-2 rounded-[6px] border border-input bg-card px-2.5 max-md:min-h-12">
                <Switch
                  id={`${idPrefix}-lis-lan`}
                  checked={lisAllowLan}
                  onCheckedChange={handleToggleAddAllowLan}
                />
                <label
                  htmlFor={`${idPrefix}-lis-lan`}
                  className="cursor-pointer whitespace-nowrap text-xs font-medium text-foreground"
                >
                  {tr("settings.lanAllowCapsule")}
                </label>
              </div>
              <Button type="submit" size="sm" className="shrink-0">
                <Plus className="mr-1 h-4 w-4" aria-hidden="true" />
                {tr("action.add")}
              </Button>
            </div>
          </form>

          <div className="space-y-2">
            {listeners.map((l) => {
              const exitVal = decodeListenerExit(l);
              const isLan = Boolean(l.allow_lan) || l.address === "0.0.0.0";
              return (
                <div key={l.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs">
                  <div className="flex min-w-44 flex-wrap items-center gap-1.5">
                    <span className="font-semibold text-foreground">{l.name}</span>
                    <span className="font-mono text-muted-foreground">
                      ({l.protocol}) {l.address}:{l.port}
                    </span>
                    {isLan ? (
                      <span className="badge-radius border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary">
                        LAN
                      </span>
                    ) : null}
                  </div>
                  <div className="flex flex-1 items-center justify-end gap-2">
                    <NodeMultiSelectDropdown
                      mode="listener-exit"
                      className="w-64 max-w-full"
                      nodes={nodes}
                      subscriptions={subscriptions}
                      customNodeTabs={customNodeTabs}
                      groups={groups}
                      value={exitVal}
                      onChange={(next) => void handleUpdateListenerTarget(l, next)}
                    />
                    <button
                      type="button"
                      onClick={() => void handleDeleteListener(l.id)}
                      aria-label={`${tr("action.delete")} ${l.name}`}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
      </section>

      {/* Policy Group Health, Speed Endpoints & Failover */}
      <section id="settings-health" tabIndex={-1} className="scroll-mt-20 outline-none">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Gauge className="h-5 w-5 text-primary" aria-hidden="true" />
              {tr("settings.healthTitle")}
              <HelpTip
                ariaLabel={tr("settings.healthTitle")}
                text={
                  <div className="space-y-1">
                    <div>{tr("settings.healthDesc")}</div>
                    <div className="text-muted-foreground">{tr("settings.healthGlobalDefaultHint")}</div>
                  </div>
                }
              />
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={(e) => void handleSaveHealthSettings(e)} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">Probe URL (204)</label>
                  <Input
                    className="font-mono text-xs"
                    value={healthDraft.url}
                    onChange={(e) => setHealthDraft((h) => ({ ...h, url: e.target.value }))}
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">{tr("settings.speedDownUrl")}</label>
                  <Input
                    className="font-mono text-xs"
                    value={healthDraft.speed_down_url}
                    onChange={(e) => setHealthDraft((h) => ({ ...h, speed_down_url: e.target.value }))}
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">{tr("settings.speedUpUrl")}</label>
                  <Input
                    className="font-mono text-xs"
                    value={healthDraft.speed_up_url}
                    onChange={(e) => setHealthDraft((h) => ({ ...h, speed_up_url: e.target.value }))}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">{tr("settings.probeIntervalClean")}</label>
                  <DurationInput
                    locale={locale}
                    value={healthIntervalVal}
                    unit={healthIntervalUnit}
                    units={["s", "m", "h", "d"]}
                    min={1}
                    ariaLabel={tr("settings.probeIntervalClean")}
                    onChange={(v, u) => {
                      setHealthIntervalVal(v);
                      setHealthIntervalUnit(u);
                      setHealthDraft((h) => ({
                        ...h,
                        interval_seconds: Math.max(10, joinToSeconds(v, u) || 60),
                      }));
                    }}
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">{tr("settings.toleranceClean")}</label>
                  <DurationInput
                    locale={locale}
                    value={healthToleranceVal}
                    unit={healthToleranceUnit}
                    units={["ms", "s", "m"]}
                    min={0}
                    ariaLabel={tr("settings.toleranceClean")}
                    onChange={(v, u) => {
                      setHealthToleranceVal(v);
                      setHealthToleranceUnit(u);
                      setHealthDraft((h) => ({
                        ...h,
                        tolerance_ms: Math.max(0, joinToMilliseconds(v, u)),
                      }));
                    }}
                  />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-1">
                    <label
                      htmlFor={`${idPrefix}-high-latency-ms`}
                      className="block font-medium text-muted-foreground"
                    >
                      {tr("settings.highLatencyThreshold")}
                    </label>
                    <HelpTip
                      ariaLabel={tr("settings.highLatencyThreshold")}
                      text={tr("settings.highLatencyThresholdHint")}
                    />
                  </div>
                  <Input
                    id={`${idPrefix}-high-latency-ms`}
                    type="number"
                    min={100}
                    max={10000}
                    step={50}
                    className="font-mono text-xs tabular-nums"
                    value={healthDraft.high_latency_ms ?? 800}
                    onChange={(e) => {
                      const raw = Number(e.target.value);
                      setHealthDraft((h) => ({
                        ...h,
                        high_latency_ms: Number.isFinite(raw) ? raw : 800,
                      }));
                    }}
                  />
                </div>
                <div className="space-y-1">
                  <label className="block font-medium text-muted-foreground">{tr("settings.priorityRule")}</label>
                  <Select
                    value={healthDraft.priority_rule}
                    onChange={(e) =>
                      setHealthDraft((h) => ({
                        ...h,
                        priority_rule: e.target.value as HealthSettings["priority_rule"],
                      }))
                    }
                  >
                    <option value="latency_first">{tr("settings.ruleLatencyFirst")}</option>
                    <option value="speed_first">{tr("settings.ruleSpeedFirst")}</option>
                    <option value="hybrid_score">{tr("settings.ruleHybridScore")}</option>
                  </Select>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
                <div className="flex items-center gap-2.5">
                  <Switch
                    id={`${idPrefix}-health-failover`}
                    checked={healthDraft.failover}
                    onCheckedChange={(checked) => setHealthDraft((h) => ({ ...h, failover: checked }))}
                  />
                  <label htmlFor={`${idPrefix}-health-failover`} className="font-medium text-foreground">
                    {tr("settings.autoFailover")}
                  </label>
                </div>
                <Button type="submit" size="sm" disabled={savingHealth}>
                  <Save className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("action.save")}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </section>

      {/* Dual Cores & RuleSets */}
      <section id="settings-cores" tabIndex={-1} className="scroll-mt-20 outline-none">
      {(() => {
        const androidBundledCores = Boolean(cores?.managed_by_apk) || androidBridge.available();
        return (
      <Card>
        <CardHeader className="flex flex-wrap flex-row items-center justify-between gap-2 pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Cpu className="h-5 w-5 text-primary" aria-hidden="true" />
            {tr("settings.coresTitle")}
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            {!androidBundledCores ? (
              <Button type="button" variant="outline" size="sm" disabled={ensuringCores} onClick={() => void handleEnsureCores()}>
                <RefreshCw className={`mr-1.5 h-4 w-4 ${ensuringCores ? "animate-spin" : ""}`} aria-hidden="true" />
                {tr("settings.ensureCores")}
              </Button>
            ) : null}
            <Button type="button" variant="outline" size="sm" disabled={syncingRulesets} onClick={() => void handleSyncRuleSets()}>
              <RefreshCw className={`mr-1.5 h-4 w-4 ${syncingRulesets ? "animate-spin" : ""}`} aria-hidden="true" />
              {tr("settings.syncRulesets")}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          <AppUpdateCard />
          {androidBundledCores ? (
            <div className="rounded-[8px] border border-primary/25 bg-primary/5 px-3 py-2 text-xs text-muted-foreground">
              <span className="font-medium text-primary">{tr("settings.androidBundledCore")}</span>
              {" · "}
              {tr("settings.androidBundledCoreHint")}
            </div>
          ) : null}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="min-w-0 space-y-2 rounded-[10px] border border-border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-foreground">
                  {tr("status.singbox")}
                </span>
                {androidBundledCores ? (
                  <span className="badge-radius border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                    APK
                  </span>
                ) : (
                  <Button type="button" size="sm" variant="ghost" onClick={() => void handleInstallCore("sing-box")}>
                    {tr("settings.installUpdate")}
                  </Button>
                )}
              </div>
              <div className="font-mono text-muted-foreground break-words">{cores?.sing_box?.binary || "--"}</div>
              {!androidBundledCores ? (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={Boolean(cores?.auto_update?.sing_box)}
                    onChange={(e) =>
                      void api
                        .updateCoreAutoUpdate({
                          sing_box: e.target.checked,
                          xray: Boolean(cores?.auto_update?.xray),
                        })
                        .then(refreshAll)
                    }
                  />
                  <span>
                    {tr("settings.autoUpdateCore", {
                      core: tr("status.singbox"),
                    })}
                  </span>
                </label>
              ) : null}
            </div>

            <div className="min-w-0 space-y-2 rounded-[10px] border border-border bg-muted/30 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-foreground">
                  {tr("status.xray")}
                </span>
                {androidBundledCores ? (
                  <span className="badge-radius border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-medium text-primary">
                    APK
                  </span>
                ) : (
                  <Button type="button" size="sm" variant="ghost" onClick={() => void handleInstallCore("xray")}>
                    {tr("settings.installUpdate")}
                  </Button>
                )}
              </div>
              <div className="font-mono text-muted-foreground break-words">{cores?.xray?.binary || "--"}</div>
              {!androidBundledCores ? (
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={Boolean(cores?.auto_update?.xray)}
                    onChange={(e) =>
                      void api
                        .updateCoreAutoUpdate({
                          sing_box: Boolean(cores?.auto_update?.sing_box),
                          xray: e.target.checked,
                        })
                        .then(refreshAll)
                    }
                  />
                  <span>
                    {tr("settings.autoUpdateCore", {
                      core: tr("status.xray"),
                    })}
                  </span>
                </label>
              ) : null}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {ruleSets.map((rs) => (
              <div key={rs.id} className="rounded-lg border px-3 py-2">
                <div className="flex items-center justify-between gap-2 font-medium text-foreground">
                  <span className="truncate">{rs.tag}</span>
                  <span className={`shrink-0 whitespace-nowrap ${rs.synced ? "text-primary" : "text-amber-500"}`}>
                    {rs.synced ? formatBytes(rs.size_bytes) : tr("settings.notSynced")}
                  </span>
                </div>
                <div className="truncate font-mono text-xs text-muted-foreground">{rs.format} · {rs.source_type}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
        );
      })()}
      </section>

      {/* Split Cards: Independent Backup & Migration + Startup Password Lock & Biometrics */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section id="settings-backup" tabIndex={-1} className="scroll-mt-20 outline-none">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileArchive className="h-5 w-5 text-primary" aria-hidden="true" />
                {tr("settings.backupTitle")}
                <HelpTip ariaLabel={tr("settings.backupTitle")} text={tr("settings.backupDesc")} />
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {(
                  [
                    { key: "nodes", label: tr("settings.backupModNodes"), count: nodes.length },
                    { key: "groups", label: tr("settings.backupModGroups"), count: groups.length },
                    { key: "subscriptions", label: tr("settings.backupModSubs"), count: subscriptions.length },
                    {
                      key: "routing",
                      label: tr("settings.backupModRouting"),
                      count: routing?.custom_rules?.length || 0,
                    },
                    { key: "listeners", label: tr("settings.backupModListeners"), count: listeners.length },
                    { key: "settings", label: tr("settings.backupModSettings"), count: null },
                  ] as const
                ).map((item) => (
                  <label
                    key={item.key}
                    className={`flex cursor-pointer items-center justify-between gap-2 rounded-[8px] border px-2.5 py-2 transition-colors ${
                      backupModules[item.key]
                        ? "border-primary/40 bg-primary/5 text-foreground"
                        : "border-border bg-muted/20 text-muted-foreground"
                    }`}
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      <input
                        type="checkbox"
                        checked={Boolean(backupModules[item.key])}
                        onChange={(e) =>
                          setBackupModules((prev) => ({
                            ...prev,
                            [item.key]: e.target.checked,
                          }))
                        }
                      />
                      <span className="truncate font-medium">{item.label}</span>
                    </span>
                    {item.count !== null ? (
                      <span className="shrink-0 mono-num text-[11px] text-muted-foreground">{item.count}</span>
                    ) : null}
                  </label>
                ))}
              </div>

              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  size="sm"
                  disabled={selectedBackupKeys.length === 0}
                  onClick={() => void handleExportBackup()}
                >
                  <Download className="mr-1.5 h-4 w-4" aria-hidden="true" />
                  {tr("settings.exportBackup")}
                </Button>
                <div className="relative inline-flex items-center">
                  <input
                    id={`${idPrefix}-restore-backup`}
                    type="file"
                    accept="application/json,.json"
                    className="visually-hidden peer"
                    onChange={(e) => void handleRestoreBackup(e)}
                  />
                  <label
                    htmlFor={`${idPrefix}-restore-backup`}
                    className="inline-flex min-h-9 cursor-pointer items-center rounded-md border border-input bg-background px-3 py-2 text-xs font-medium hover:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring"
                  >
                    <Upload className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {tr("settings.restoreBackup")}
                  </label>
                </div>
                <div className="relative inline-flex items-center">
                  <input
                    id={`${idPrefix}-merge-backup`}
                    type="file"
                    accept="application/json,.json"
                    className="visually-hidden peer"
                    onChange={(e) => void handleMergeBackup(e)}
                  />
                  <label
                    htmlFor={`${idPrefix}-merge-backup`}
                    className="inline-flex min-h-9 cursor-pointer items-center rounded-md border border-input bg-background px-3 py-2 text-xs font-medium hover:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring"
                  >
                    <Upload className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {tr("settings.mergeBackup")}
                  </label>
                </div>
              </div>

              <div className="space-y-2 border-t pt-3">
                <div className="text-xs font-semibold text-foreground">{tr("settings.routingJsonBackupTitle")}</div>
                <div className="flex flex-wrap gap-2">
                  <div className="relative inline-flex items-center">
                    <input
                      id={`${idPrefix}-import-routing-json`}
                      type="file"
                      accept="application/json,.json"
                      className="visually-hidden peer"
                      onChange={(e) => void handleMergeBackup(e)}
                    />
                    <label
                      htmlFor={`${idPrefix}-import-routing-json`}
                      className="inline-flex min-h-9 cursor-pointer items-center rounded-md border border-input bg-background px-3 py-2 text-xs font-medium hover:bg-accent peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring"
                    >
                      <Upload className="mr-1.5 h-4 w-4" aria-hidden="true" />
                      {tr("routing.importJson")}
                    </label>
                  </div>
                  <Button type="button" variant="outline" size="sm" onClick={() => void handleExportRoutingJson()}>
                    <Download className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {tr("routing.exportJson")}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setRoutingQrTab("export");
                      setRoutingQrOpen(true);
                    }}
                  >
                    <QrCode className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {tr("routing.qrShareBtn")}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        <section id="settings-security" tabIndex={-1} className="scroll-mt-20 outline-none">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Lock className="h-5 w-5 text-primary" aria-hidden="true" />
                {tr("settings.securityTitle")}
                <HelpTip ariaLabel={tr("settings.securityTitle")} text={tr("settings.securityDesc")} />
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-xs">

              {isDesktop ? (
                <div className="space-y-2.5">
                  <div className="font-semibold text-foreground">{tr("settings.passwordLock")}</div>
                  {authStatus?.password_lock_enabled ? (
                    <Input
                      type="password"
                      placeholder={tr("auth.password")}
                      value={lockCurrentPassword}
                      onChange={(e) => setLockCurrentPassword(e.target.value)}
                    />
                  ) : (
                    <Input
                      type="password"
                      placeholder={`${tr("auth.password")} (>= 8 chars)`}
                      value={lockPassword}
                      onChange={(e) => setLockPassword(e.target.value)}
                    />
                  )}
                  <div className="flex flex-wrap gap-2">
                    {authStatus?.password_lock_enabled ? (
                      <Button type="button" variant="destructive" size="sm" onClick={() => void handleTogglePasswordLock(false)}>
                        {tr("settings.disableLock")}
                      </Button>
                    ) : (
                      <Button type="button" size="sm" onClick={() => void handleTogglePasswordLock(true)}>
                        {tr("settings.enableLock")}
                      </Button>
                    )}
                  </div>

                  {/* System Biometric Unlock Section */}
                  <div className="space-y-2 rounded-[10px] border border-border bg-muted/30 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center gap-1.5 font-semibold text-foreground">
                        <Fingerprint className="h-4 w-4 text-primary" aria-hidden="true" />
                        {tr("settings.biometricTitle")}
                        <HelpTip
                          ariaLabel={tr("settings.biometricTitle")}
                          text={
                            <div className="space-y-1">
                              <div>{biometricStatus?.available ? biometricStatus.detail : tr("settings.biometricUnavailable")}</div>
                              {!authStatus?.password_lock_enabled ? (
                                <div className="text-muted-foreground">
                                  {locale === "zh-CN"
                                    ? "请先启用启动密码锁，随后即可绑定系统生物信息解锁。"
                                    : "Enable Startup Password Lock first to bind OS biometric unlock."}
                                </div>
                              ) : null}
                            </div>
                          }
                        />
                      </span>
                      <span
                        className={`badge-radius border px-1.5 py-0.5 text-[10px] font-medium ${
                          authStatus?.biometric_enabled
                            ? "border-primary/40 bg-primary/15 text-primary"
                            : "border-border bg-background text-muted-foreground"
                        }`}
                      >
                        {authStatus?.biometric_enabled
                          ? tr("settings.biometricEnabledBadge")
                          : tr("settings.biometricDisabledBadge")}
                      </span>
                    </div>
                    {authStatus?.password_lock_enabled ? (
                      <div className="flex flex-wrap gap-2">
                        {authStatus.biometric_enabled ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={savingBiometric}
                            onClick={() => void handleToggleBiometric(false)}
                          >
                            {tr("settings.biometricDisableBtn")}
                          </Button>
                        ) : (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={savingBiometric || !biometricStatus?.available}
                            onClick={() => void handleToggleBiometric(true)}
                          >
                            <Fingerprint className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                            {tr("settings.biometricEnableBtn")}
                          </Button>
                        )}
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}

              <div className="flex flex-wrap items-center gap-2 border-t pt-3">
                {tunState?.sudo_cached ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => void api.clearSudo().then(refreshAll)}
                  >
                    <ShieldAlert className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {tr("settings.clearSudo")}
                  </Button>
                ) : null}
                {authStatus?.authentication ? (
                  <>
                    <Button type="button" variant="outline" size="sm" onClick={() => void handleLockOrLogout(false)}>
                      <Lock className="mr-1.5 h-4 w-4" aria-hidden="true" />
                      {tr("settings.lockNow")}
                    </Button>
                    <Button type="button" variant="ghost" size="sm" onClick={() => void handleLockOrLogout(true)}>
                      <LogOut className="mr-1.5 h-4 w-4" aria-hidden="true" />
                      {tr("settings.logout")}
                    </Button>
                  </>
                ) : null}
              </div>
            </CardContent>
          </Card>
        </section>
      </div>

      {/* Core Server Ports (Desktop / Headless only; Android binds ephemeral loopback ports) */}
      {settingsDraft && !isAndroid ? (
        <section id="settings-ports" tabIndex={-1} className="scroll-mt-20 outline-none">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileArchive className="h-5 w-5 text-primary" aria-hidden="true" />
                {tr("settings.corePortsTitle")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={(e) => void handleSaveSettings(e)} className="space-y-3 text-xs">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <label className="text-muted-foreground">{tr("overview.mixedPort")}</label>
                    <Input
                      type="number"
                      value={settingsDraft.sing_box.mixed_port}
                      onChange={(e) =>
                        setSettingsDraft((s) =>
                          s ? { ...s, sing_box: { ...s.sing_box, mixed_port: Number(e.target.value) } } : s,
                        )
                      }
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-muted-foreground">{tr("overview.clashPort")}</label>
                    <Input
                      type="number"
                      value={settingsDraft.sing_box.clash_api_port}
                      onChange={(e) =>
                        setSettingsDraft((s) =>
                          s ? { ...s, sing_box: { ...s.sing_box, clash_api_port: Number(e.target.value) } } : s,
                        )
                      }
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-muted-foreground">{tr("settings.xraySocksPort")}</label>
                    <Input
                      type="number"
                      value={settingsDraft.xray.socks_port}
                      onChange={(e) =>
                        setSettingsDraft((s) =>
                          s ? { ...s, xray: { ...s.xray, socks_port: Number(e.target.value) } } : s,
                        )
                      }
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-muted-foreground">{tr("settings.controlPlanePort")}</label>
                    <Input
                      type="number"
                      value={settingsDraft.server.port}
                      onChange={(e) =>
                        setSettingsDraft((s) =>
                          s ? { ...s, server: { ...s.server, port: Number(e.target.value) } } : s,
                        )
                      }
                    />
                  </div>
                </div>
                <Button type="submit" size="sm" disabled={savingSettings}>
                  {tr("action.save")}
                </Button>
              </form>
            </CardContent>
          </Card>
          </section>
        ) : null}

      {/* Live 4-Level Log Viewer */}
      <section id="settings-logs" tabIndex={-1} className="scroll-mt-20 outline-none">
      <Card>
        <CardHeader className="flex flex-col gap-2.5 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <CardTitle className="flex shrink-0 items-center gap-2 whitespace-nowrap text-base">
            <ScrollText className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
            <span>{tr("settings.logsTitle")}</span>
          </CardTitle>
          <div className="flex min-w-0 flex-1 flex-nowrap items-center justify-end gap-2">
            <div className="w-24 shrink-0">
              <Select
                aria-label="Log level"
                size="sm"
                value={logLevelFilter}
                onChange={(e) => setLogLevelFilter(e.target.value)}
              >
                <option value="all">ALL</option>
                <option value="debug">DEBUG</option>
                <option value="info">INFO</option>
                <option value="warn">WARN</option>
                <option value="error">ERROR</option>
              </Select>
            </div>
            <Input
              aria-label={tr("settings.filterLogsPlaceholder")}
              className="h-8 min-h-0 min-w-0 flex-1 sm:max-w-52 text-xs"
              placeholder={tr("settings.filterLogsPlaceholder")}
              value={logSearch}
              onChange={(e) => setLogSearch(e.target.value)}
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-8 shrink-0 whitespace-nowrap"
              onClick={() => void handleExportLogs()}
            >
              <Download className="mr-1.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {tr("settings.exportLogs")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="max-h-72 space-y-1 overflow-y-auto rounded-[10px] border border-border bg-muted/40 p-2.5 mono-num text-xs">
            {filteredLogs.length === 0 ? (
              <div className="py-4 text-center text-muted-foreground">--</div>
            ) : (
              filteredLogs.map((l) => {
                const lvl = l.level.toLowerCase();
                const cleanMsg = stripAnsiCodes(l.message);
                const fullCopyText = `[${l.timestamp}] [${l.core}/${lvl.toUpperCase()}] ${cleanMsg}`;
                const badgeClass =
                  lvl === "error" || lvl === "fatal"
                    ? "border-destructive/40 bg-destructive/15 text-destructive"
                    : lvl === "warn" || lvl === "warning"
                      ? "border-amber-500/40 bg-amber-500/15 text-amber-600 dark:text-amber-400"
                      : lvl === "debug"
                        ? "border-border bg-muted text-muted-foreground"
                        : "border-sky-500/35 bg-sky-500/12 text-sky-600 dark:text-sky-400";
                const msgClass =
                  lvl === "error" || lvl === "fatal"
                    ? "text-destructive"
                    : lvl === "warn" || lvl === "warning"
                      ? "text-amber-600 dark:text-amber-300"
                      : lvl === "debug"
                        ? "text-muted-foreground"
                        : "text-foreground";
                return (
                  <div
                    key={l.seq}
                    role="button"
                    tabIndex={0}
                    title={tr("toast.clickToCopy")}
                    onClick={() => void handleCopyLogLine(fullCopyText)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        void handleCopyLogLine(fullCopyText);
                      }
                    }}
                    className="cursor-pointer rounded-[6px] px-1.5 py-1 leading-relaxed break-words transition-colors hover:bg-background/70 active:bg-background"
                  >
                    <span className="text-[11px] text-muted-foreground">{l.timestamp.replace(/^.*T/, "").replace(/[Z+].*$/, "")}</span>{" "}
                    <span className={`inline-flex items-center rounded border px-1 py-0 text-[10px] font-semibold uppercase leading-tight ${badgeClass}`}>
                      {l.core}/{lvl}
                    </span>{" "}
                    <span className={msgClass}>{cleanMsg}</span>
                  </div>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>
      </section>

      <RoutingQrModal
        open={routingQrOpen}
        initialTab={routingQrTab}
        profile={
          routing || {
            mode: "rule",
            block_ads: true,
            bypass_lan: true,
            allow_lan_broadcast: false,
            bypass_cn: true,
            local_dns: "223.5.5.5",
            remote_dns: "https://1.1.1.1/dns-query",
            custom_rules: [],
          }
        }
        onClose={() => setRoutingQrOpen(false)}
        onImported={async (importedProfile) => {
          await api.saveRouting(importedProfile);
          await refreshAll();
        }}
      />
    </div>
  );
}
