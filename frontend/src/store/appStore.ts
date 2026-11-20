// SPDX-License-Identifier: MPL-2.0

import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  type AuthStatus,
  type ConnectionsSnapshot,
  type CoresStatus,
  type GroupConfig,
  type ListenConfig,
  type LogEntry,
  type NodeConfig,
  type ProcessStatus,
  type RoutingProfile,
  type RuleSetSpec,
  type SubscriptionImportResult,
  type SubscriptionRecord,
  type TrafficSample,
  type TrayTargetItem,
  type TUNState,
  androidBridge,
  api,
  formatApiError,
  subscribeStream,
  updateNativeTray,
} from "../lib/api.ts";
import { type Locale, getStoredLocale, setStoredLocale, t, type TranslationKey } from "../lib/i18n.ts";
import {
  type ThemeMode,
  applyThemeMode,
  getStoredThemeMode,
  subscribeThemeChanges,
} from "../lib/theme.ts";

export type NavTab = "overview" | "proxies" | "connections" | "subscriptions" | "routing" | "settings";
export type NodeViewMode = "grid" | "list";
export type ConnectionColumnId =
  | "target"
  | "network"
  | "outboundNode"
  | "engine"
  | "group"
  | "rule"
  | "process"
  | "traffic"
  | "duration"
  | "source"
  | "action";

export const DEFAULT_CONNECTION_COLUMNS: ConnectionColumnId[] = [
  "target",
  "network",
  "outboundNode",
  "engine",
  "group",
  "rule",
  "process",
  "traffic",
  "action",
];

export const ALL_CONNECTION_COLUMNS: ConnectionColumnId[] = [
  "target",
  "network",
  "outboundNode",
  "engine",
  "group",
  "rule",
  "process",
  "traffic",
  "duration",
  "source",
  "action",
];

const NODE_VIEW_STORAGE_KEY = "prismray-node-view-mode";
const CONN_COLS_STORAGE_KEY = "prismray-conn-columns";
const SIDEBAR_COLLAPSED_KEY = "prismray-sidebar-collapsed";
const RECENT_TARGETS_KEY = "prismray-recent-targets";

function getStoredSidebarCollapsed(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

function getStoredRecentTargets(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_TARGETS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string").slice(0, 5) : [];
  } catch {
    return [];
  }
}

function getStoredNodeViewMode(): NodeViewMode {
  if (typeof window === "undefined") return "grid";
  try {
    return window.localStorage.getItem(NODE_VIEW_STORAGE_KEY) === "list" ? "list" : "grid";
  } catch {
    return "grid";
  }
}

function getStoredConnectionColumns(): ConnectionColumnId[] {
  if (typeof window === "undefined") return DEFAULT_CONNECTION_COLUMNS;
  try {
    const raw = window.localStorage.getItem(CONN_COLS_STORAGE_KEY);
    if (!raw) return DEFAULT_CONNECTION_COLUMNS;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return DEFAULT_CONNECTION_COLUMNS;
    const valid = parsed.filter((c): c is ConnectionColumnId =>
      ALL_CONNECTION_COLUMNS.includes(c as ConnectionColumnId),
    );
    return valid.length > 0 ? valid : DEFAULT_CONNECTION_COLUMNS;
  } catch {
    return DEFAULT_CONNECTION_COLUMNS;
  }
}

export interface ToastNotice {
  id: number;
  message: string;
  tone: "success" | "warning" | "error";
  durationSec: number;
}

export interface TrafficPoint {
  time: string;
  upKB: number;
  downKB: number;
}

export interface UnsavedTabGuard {
  isDirty: () => boolean;
  save: () => Promise<boolean>;
}

export interface AppStoreValue {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  registerUnsavedGuard: (tab: NavTab, guard: UnsavedTabGuard | null) => void;
  pendingTabSwitch: NavTab | null;
  savingPendingTabSwitch: boolean;
  confirmTabSwitchSave: () => Promise<void>;
  confirmTabSwitchDiscard: () => void;
  cancelTabSwitch: () => void;
  locale: Locale;
  setLocale: (loc: Locale) => void;
  tr: (key: TranslationKey, vars?: Record<string, string | number>) => string;
  themeMode: ThemeMode;
  resolvedTheme: "light" | "dark";
  setThemeMode: (mode: ThemeMode) => void;
  nodeViewMode: NodeViewMode;
  setNodeViewMode: (mode: NodeViewMode) => void;
  sidebarCollapsed: boolean;
  setSidebarCollapsed: (collapsed: boolean) => void;
  commandPaletteOpen: boolean;
  setCommandPaletteOpen: (open: boolean) => void;
  connectionColumns: ConnectionColumnId[];
  setConnectionColumns: (cols: ConnectionColumnId[]) => void;
  customNodeTabs: string[];
  saveCustomNodeTabs: (tabs: string[]) => Promise<void>;
  notice: ToastNotice | null;
  notify: (message: string, tone?: "success" | "warning" | "error") => void;
  clearNotice: () => void;

  authStatus: AuthStatus | null;
  status: ProcessStatus | null;
  nodes: NodeConfig[];
  groups: GroupConfig[];
  listeners: ListenConfig[];
  routing: RoutingProfile | null;
  ruleSets: RuleSetSpec[];
  subscriptions: SubscriptionRecord[];
  tunState: TUNState | null;
  cores: CoresStatus | null;
  systemProxyEnabled: boolean;
  lastImportDiagnostic: SubscriptionImportResult | null;
  setLastImportDiagnostic: (res: SubscriptionImportResult | null) => void;

  busy: boolean;
  refreshAll: () => Promise<void>;
  toggleConnect: (target?: { nodeId?: string; groupId?: string }) => Promise<void>;
  toggleTUN: (enabled: boolean) => Promise<void>;
  toggleSystemProxy: (enabled: boolean) => Promise<void>;
  setAuthStatus: React.Dispatch<React.SetStateAction<AuthStatus | null>>;
}

export interface AppTelemetryValue {
  connections: ConnectionsSnapshot;
  logs: LogEntry[];
  trafficNow: TrafficSample;
  trafficHistory: TrafficPoint[];
}

const AppStoreContext = createContext<AppStoreValue | null>(null);
const AppTelemetryContext = createContext<AppTelemetryValue | null>(null);

function AppTelemetryProvider({ unlocked, children }: { unlocked: boolean; children?: React.ReactNode }) {
  const [connections, setConnections] = useState<ConnectionsSnapshot>({
    downloadTotal: 0,
    uploadTotal: 0,
    connections: [],
  });
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [trafficNow, setTrafficNow] = useState<TrafficSample>({ up: 0, down: 0 });
  const [trafficHistory, setTrafficHistory] = useState<TrafficPoint[]>([]);
  const initializedStreams = useRef(false);

  useEffect(() => {
    if (!unlocked) {
      initializedStreams.current = false;
      return;
    }
    if (initializedStreams.current) return;
    initializedStreams.current = true;

    const unsubTraffic = subscribeStream("traffic", (evt) => {
      try {
        const frame = JSON.parse(evt.data) as TrafficSample;
        const up = Math.max(0, Number(frame.up) || 0);
        const down = Math.max(0, Number(frame.down) || 0);
        setTrafficNow({ up, down, timestamp: frame.timestamp });
        const nowLabel = new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        setTrafficHistory((prev) => {
          const next = [
            ...prev,
            {
              time: nowLabel,
              upKB: Number((up / 1024).toFixed(1)),
              downKB: Number((down / 1024).toFixed(1)),
            },
          ];
          return next.length > 36 ? next.slice(next.length - 36) : next;
        });
      } catch {
        // Ignore malformed telemetry frame.
      }
    });

    const unsubConnections = subscribeStream("connections", (evt) => {
      try {
        const snap = JSON.parse(evt.data) as ConnectionsSnapshot;
        setConnections({
          downloadTotal: Number(snap.downloadTotal) || 0,
          uploadTotal: Number(snap.uploadTotal) || 0,
          memory: snap.memory,
          connections: Array.isArray(snap.connections) ? snap.connections : [],
        });
      } catch {
        // Ignore malformed snapshot.
      }
    });

    const unsubLogs = subscribeStream("logs", (evt) => {
      try {
        const entry = JSON.parse(evt.data) as LogEntry;
        setLogs((prev) => {
          if (prev.some((item) => item.seq === entry.seq)) return prev;
          const next = [...prev, entry];
          return next.length > 500 ? next.slice(next.length - 500) : next;
        });
      } catch {
        // Ignore malformed log line.
      }
    });

    return () => {
      initializedStreams.current = false;
      unsubTraffic();
      unsubConnections();
      unsubLogs();
    };
  }, [unlocked]);

  const telemetryValue = useMemo<AppTelemetryValue>(
    () => ({
      connections,
      logs,
      trafficNow,
      trafficHistory,
    }),
    [connections, logs, trafficNow, trafficHistory],
  );

  return React.createElement(AppTelemetryContext.Provider, { value: telemetryValue }, children);
}

export function AppStoreProvider({ children }: { children: React.ReactNode }) {
  const [activeTab, setActiveTabState] = useState<NavTab>("overview");
  const unsavedGuardsRef = useRef<Partial<Record<NavTab, UnsavedTabGuard>>>({});
  const [pendingTabSwitch, setPendingTabSwitch] = useState<NavTab | null>(null);
  const [savingPendingTabSwitch, setSavingPendingTabSwitch] = useState(false);

  const registerUnsavedGuard = useCallback((tab: NavTab, guard: UnsavedTabGuard | null) => {
    if (guard) {
      unsavedGuardsRef.current[tab] = guard;
    } else {
      delete unsavedGuardsRef.current[tab];
    }
  }, []);

  const setActiveTab = useCallback(
    (nextTab: NavTab) => {
      if (nextTab === activeTab) return;
      const guard = unsavedGuardsRef.current[activeTab];
      if (guard && guard.isDirty()) {
        setPendingTabSwitch(nextTab);
        return;
      }
      setPendingTabSwitch(null);
      setActiveTabState(nextTab);
    },
    [activeTab],
  );

  const confirmTabSwitchDiscard = useCallback(() => {
    setPendingTabSwitch((target) => {
      if (target) {
        setActiveTabState(target);
      }
      return null;
    });
  }, []);

  const cancelTabSwitch = useCallback(() => {
    if (savingPendingTabSwitch) return;
    setPendingTabSwitch(null);
  }, [savingPendingTabSwitch]);

  const confirmTabSwitchSave = useCallback(async () => {
    if (!pendingTabSwitch || savingPendingTabSwitch) return;
    const guard = unsavedGuardsRef.current[activeTab];
    const target = pendingTabSwitch;
    if (!guard || !guard.isDirty()) {
      setPendingTabSwitch(null);
      setActiveTabState(target);
      return;
    }
    setSavingPendingTabSwitch(true);
    try {
      const ok = await guard.save();
      if (ok) {
        setPendingTabSwitch(null);
        setActiveTabState(target);
      }
    } finally {
      setSavingPendingTabSwitch(false);
    }
  }, [activeTab, pendingTabSwitch, savingPendingTabSwitch]);
  const [locale, setLocaleState] = useState<Locale>(() => getStoredLocale());
  const [themeMode, setThemeModeState] = useState<ThemeMode>(() => getStoredThemeMode());
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() =>
    applyThemeMode(getStoredThemeMode(), false),
  );
  const [nodeViewMode, setNodeViewModeState] = useState<NodeViewMode>(() => getStoredNodeViewMode());
  const [sidebarCollapsed, setSidebarCollapsedState] = useState<boolean>(() => getStoredSidebarCollapsed());
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [recentTargetKeys, setRecentTargetKeys] = useState<string[]>(() => getStoredRecentTargets());
  const [connectionColumns, setConnectionColumnsState] = useState<ConnectionColumnId[]>(() =>
    getStoredConnectionColumns(),
  );
  const [customNodeTabs, setCustomNodeTabs] = useState<string[]>([]);
  const [notice, setNotice] = useState<ToastNotice | null>(null);
  const noticeSeqRef = useRef(0);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);

  const [status, setStatus] = useState<ProcessStatus | null>(null);
  const [nodes, setNodes] = useState<NodeConfig[]>([]);
  const [groups, setGroups] = useState<GroupConfig[]>([]);
  const [listeners, setListeners] = useState<ListenConfig[]>([]);
  const [routing, setRouting] = useState<RoutingProfile | null>(null);
  const [ruleSets, setRuleSets] = useState<RuleSetSpec[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionRecord[]>([]);
  const [tunState, setTunState] = useState<TUNState | null>(null);
  const [cores, setCores] = useState<CoresStatus | null>(null);
  const [systemProxyEnabled, setSystemProxyEnabled] = useState(false);
  const [lastImportDiagnostic, setLastImportDiagnostic] = useState<SubscriptionImportResult | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.lang = locale;
    }
  }, [locale]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onLanguageChange = () => {
      try {
        if (!window.localStorage.getItem("prismray-locale")) {
          setLocaleState(getStoredLocale());
        }
      } catch {
        setLocaleState(getStoredLocale());
      }
    };
    window.addEventListener("languagechange", onLanguageChange);
    return () => window.removeEventListener("languagechange", onLanguageChange);
  }, []);

  useEffect(() => {
    return subscribeThemeChanges((mode, resolved) => {
      setThemeModeState(mode);
      setResolvedTheme(resolved);
    });
  }, []);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    setStoredLocale(next);
  }, []);

  const setThemeMode = useCallback((next: ThemeMode) => {
    setThemeModeState(next);
    setResolvedTheme(applyThemeMode(next, true));
  }, []);

  const setNodeViewMode = useCallback((next: NodeViewMode) => {
    setNodeViewModeState(next);
    if (typeof window !== "undefined") {
      try {
        window.localStorage.setItem(NODE_VIEW_STORAGE_KEY, next);
      } catch {
        // Ignore storage failures.
      }
    }
  }, []);

  const setSidebarCollapsed = useCallback((collapsed: boolean) => {
    setSidebarCollapsedState(collapsed);
    if (typeof window !== "undefined") {
      try {
        window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? "1" : "0");
      } catch {
        // Ignore storage failures.
      }
    }
  }, []);

  const recordRecentTarget = useCallback((key: string) => {
    if (!key) return;
    setRecentTargetKeys((prev) => {
      const next = [key, ...prev.filter((item) => item !== key)].slice(0, 5);
      if (typeof window !== "undefined") {
        try {
          window.localStorage.setItem(RECENT_TARGETS_KEY, JSON.stringify(next));
        } catch {
          // Ignore storage failures.
        }
      }
      return next;
    });
  }, []);

  const setConnectionColumns = useCallback((cols: ConnectionColumnId[]) => {
    const valid = ALL_CONNECTION_COLUMNS.filter((c) => cols.includes(c));
    const next = valid.length > 0 ? valid : DEFAULT_CONNECTION_COLUMNS;
    setConnectionColumnsState(next);
    if (typeof window !== "undefined") {
      try {
        window.localStorage.setItem(CONN_COLS_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore storage failures.
      }
    }
  }, []);

  const tr = useCallback(
    (key: TranslationKey, vars?: Record<string, string | number>) => t(locale, key, vars),
    [locale],
  );

  const notify = useCallback((message: string, tone: "success" | "warning" | "error" = "success") => {
    noticeSeqRef.current += 1;
    setNotice({
      id: noticeSeqRef.current,
      message,
      tone,
      durationSec: tone === "error" ? 6 : tone === "warning" ? 5 : 4,
    });
  }, []);

  const clearNotice = useCallback(() => setNotice(null), []);

  const refreshAll = useCallback(async () => {
    const results = await Promise.allSettled([
      api.getStatus(),
      api.listNodes(),
      api.listGroups(),
      api.listListeners(),
      api.getRouting(),
      api.listRuleSets(),
      api.listSubscriptions(),
      api.getTUN(),
      api.getCores(),
      api.getSystemProxy(),
      api.getNodeTabs(),
    ]);

    const [stRes, ndRes, grRes, lsRes, rtRes, rsRes, sbRes, tunRes, coreRes, spRes, tabsRes] = results;
    if (stRes.status === "fulfilled") {
      setStatus(stRes.value);
      if (typeof stRes.value.system_proxy_enabled === "boolean") {
        setSystemProxyEnabled(stRes.value.system_proxy_enabled);
      }
    }
    if (ndRes.status === "fulfilled") setNodes(ndRes.value || []);
    if (grRes.status === "fulfilled") setGroups(grRes.value || []);
    if (lsRes.status === "fulfilled") setListeners(lsRes.value || []);
    if (rtRes.status === "fulfilled") setRouting(rtRes.value);
    if (rsRes.status === "fulfilled") setRuleSets(rsRes.value || []);
    if (sbRes.status === "fulfilled") setSubscriptions(sbRes.value || []);
    if (tunRes.status === "fulfilled") setTunState(tunRes.value);
    if (coreRes.status === "fulfilled") setCores(coreRes.value);
    if (spRes.status === "fulfilled") {
      setSystemProxyEnabled(
        stRes.status === "fulfilled" && typeof stRes.value.system_proxy_enabled === "boolean"
          ? stRes.value.system_proxy_enabled
          : Boolean(spRes.value.enabled),
      );
    }
    if (tabsRes.status === "fulfilled") {
      setCustomNodeTabs(Array.isArray(tabsRes.value?.tabs) ? tabsRes.value.tabs : []);
    }
  }, []);

  const saveCustomNodeTabs = useCallback(
    async (tabs: string[]) => {
      const saved = await api.saveNodeTabs(tabs);
      setCustomNodeTabs(saved.tabs || []);
    },
    [],
  );

  const unlocked = Boolean(
    authStatus && (!authStatus.authentication || (authStatus.authenticated && authStatus.unlocked)),
  );

  useEffect(() => {
    if (!unlocked) return;
    void refreshAll();
    // Sync again shortly after boot so async backend RestoreLastSession (runtime/TUN/system proxy)
    // is reflected in UI switches without needing a manual interaction.
    const t1 = window.setTimeout(() => void refreshAll(), 900);
    const t2 = window.setTimeout(() => void refreshAll(), 2200);

    const onAndroidChanged = (ev: Event) => {
      const detail = (ev as CustomEvent<{ running?: boolean; approved?: boolean; error?: string }>).detail;
      if (detail?.error) {
        notify(detail.error, "error");
      }
      void refreshAll();
      window.setTimeout(() => {
        void refreshAll();
      }, 600);
    };
    window.addEventListener("prismray-vpn-changed", onAndroidChanged);

    return () => {
      window.clearTimeout(t1);
      window.clearTimeout(t2);
      window.removeEventListener("prismray-vpn-changed", onAndroidChanged);
    };
  }, [unlocked, refreshAll, notify]);

  const toggleConnect = useCallback(
    async (target?: { nodeId?: string; groupId?: string }) => {
      setBusy(true);
      try {
        if (androidBridge.available()) {
          if (status?.running && !target) {
            androidBridge.stopVpn();
            await api.stopAndroidVPN().catch(() => {});
            await api.stopProcess().catch(() => {});
            await refreshAll();
            return;
          }
          const groupId = target?.groupId ?? (target?.nodeId ? "" : status?.active_group_id ?? "");
          const nodeId =
            target?.nodeId ??
            (target?.groupId ? "" : status?.active_node_id ?? (groupId ? "" : nodes[0]?.id ?? ""));
          const res = androidBridge.prepareAndStartVpn({
            per_app_mode: routing?.per_app_mode || "all",
            per_app_packages: routing?.per_app_packages || [],
            active_node_id: nodeId,
            active_group_id: groupId,
          });
          if (res.status === "error" || res.status === "unavailable") {
            notify(
              res.error ||
                (locale === "zh-CN" ? "Android VPN 桥接不可用" : "Android VPN bridge unavailable"),
              "error",
            );
            return;
          }
          if (res.status === "starting") {
            notify(locale === "zh-CN" ? "正在启动 Android VPN…" : "Starting Android VPN…");
          }
          window.setTimeout(() => void refreshAll(), 700);
          window.setTimeout(() => void refreshAll(), 2000);
          return;
        }

        if (status?.running && !target) {
          await api.stopProcess();
        } else if (target?.nodeId || target?.groupId) {
          if (target.groupId) recordRecentTarget(`group:${target.groupId}`);
          else if (target.nodeId) recordRecentTarget(`node:${target.nodeId}`);
          await api.connectProcess({
            node_id: target.nodeId,
            group_id: target.groupId,
          });
        } else {
          const fallbackGroupId = status?.active_group_id || undefined;
          const fallbackNodeId = status?.active_node_id || nodes[0]?.id || undefined;
          if (fallbackGroupId) recordRecentTarget(`group:${fallbackGroupId}`);
          else if (fallbackNodeId) recordRecentTarget(`node:${fallbackNodeId}`);
          await api.connectProcess({
            node_id: fallbackNodeId,
            group_id: fallbackGroupId,
          });
        }
        await refreshAll();
      } catch (err) {
        notify(formatApiError(err), "error");
      } finally {
        setBusy(false);
      }
    },
    [status, nodes, routing, locale, refreshAll, notify, recordRecentTarget],
  );

  const toggleTUN = useCallback(
    async (enabled: boolean) => {
      setBusy(true);
      try {
        if (androidBridge.available()) {
          if (enabled) {
            const groupId = status?.active_group_id || "";
            const nodeId = status?.active_node_id || (groupId ? "" : nodes[0]?.id || "");
            const res = androidBridge.prepareAndStartVpn({
              per_app_mode: routing?.per_app_mode || "all",
              per_app_packages: routing?.per_app_packages || [],
              active_node_id: nodeId,
              active_group_id: groupId,
            });
            if (res.status === "error" || res.status === "unavailable") {
              notify(
                res.error ||
                  (locale === "zh-CN" ? "Android VPN 桥接不可用" : "Android VPN bridge unavailable"),
                "error",
              );
              return;
            }
          } else {
            androidBridge.stopVpn();
            await api.stopAndroidVPN().catch(() => {});
          }
          window.setTimeout(() => void refreshAll(), 700);
          window.setTimeout(() => void refreshAll(), 2000);
          return;
        }
        await api.setTUN({
          enabled,
          node_id: status?.active_node_id || nodes[0]?.id || undefined,
          group_id: status?.active_group_id || undefined,
          stack: tunState?.stack || undefined,
        });
        await refreshAll();
      } catch (err) {
        notify(formatApiError(err), "error");
      } finally {
        setBusy(false);
      }
    },
    [routing, status, nodes, tunState, locale, refreshAll, notify],
  );

  const toggleSystemProxy = useCallback(
    async (enabled: boolean) => {
      setBusy(true);
      try {
        await api.setSystemProxy(enabled);
        await refreshAll();
      } catch (err) {
        notify(formatApiError(err), "error");
      } finally {
        setBusy(false);
      }
    },
    [refreshAll, notify],
  );

  // Keep native desktop tray icon (5 states), tooltip, and interactive menu synchronized.
  const syncNativeTray = useCallback(() => {
    if (!unlocked) return;
    const activeNode = nodes.find((n) => n.id === status?.active_node_id);
    const activeGroup = groups.find((g) => g.id === status?.active_group_id);
    const activeLabel = activeGroup
      ? activeGroup.name
      : activeNode
        ? activeNode.user_alias || activeNode.name
        : "";
    const groupPrefix = locale === "en-US" ? "[Group]" : "[组]";
    const targetMap = new Map<string, TrayTargetItem>();
    for (const g of groups) {
      targetMap.set(`group:${g.id}`, {
        actionId: `group:${g.id}`,
        label: `${groupPrefix} ${g.name}`,
        active: Boolean(status?.running) && status?.active_group_id === g.id,
      });
    }
    for (const n of nodes) {
      targetMap.set(`node:${n.id}`, {
        actionId: `node:${n.id}`,
        label: n.user_alias || n.name,
        active: Boolean(status?.running) && !status?.active_group_id && status?.active_node_id === n.id,
      });
    }
    const orderedKeys: string[] = [];
    const pushKey = (key: string) => {
      if (targetMap.has(key) && !orderedKeys.includes(key)) {
        orderedKeys.push(key);
      }
    };
    if (status?.active_group_id) pushKey(`group:${status.active_group_id}`);
    else if (status?.active_node_id) pushKey(`node:${status.active_node_id}`);
    for (const key of recentTargetKeys) pushKey(key);
    for (const g of groups) pushKey(`group:${g.id}`);
    for (const n of nodes) pushKey(`node:${n.id}`);

    const recentTargets = orderedKeys
      .slice(0, 5)
      .map((key) => targetMap.get(key)!)
      .filter(Boolean);

    void updateNativeTray({
      running: Boolean(status?.running),
      tunEnabled: Boolean(tunState?.enabled),
      systemProxyEnabled,
      mode: routing?.mode || "rule",
      activeLabel,
      recentTargets,
    });
  }, [unlocked, status, tunState, systemProxyEnabled, routing, groups, nodes, recentTargetKeys, locale]);

  useEffect(() => {
    syncNativeTray();
  }, [syncNativeTray]);

  const trayActionHandlerRef = useRef<(action: string) => Promise<void>>(async () => {});
  trayActionHandlerRef.current = async (action: string) => {
    try {
      if (action === "connect") {
        if (!status?.running) await toggleConnect();
        return;
      }
      if (action === "disconnect") {
        if (status?.running) await toggleConnect();
        return;
      }
      if (action === "toggle:tun") {
        await toggleTUN(!Boolean(tunState?.enabled));
        return;
      }
      if (action === "toggle:sysproxy") {
        await toggleSystemProxy(!systemProxyEnabled);
        return;
      }
      if (action.startsWith("mode:") && routing) {
        const nextMode = action.slice("mode:".length);
        if (nextMode === "rule" || nextMode === "global" || nextMode === "direct") {
          await api.saveRouting({ ...routing, mode: nextMode });
          await refreshAll();
        }
        return;
      }
      if (action.startsWith("group:")) {
        const groupId = action.slice("group:".length);
        if (groupId) {
          await toggleConnect({ groupId });
        }
        return;
      }
      if (action.startsWith("node:")) {
        const nodeId = action.slice("node:".length);
        if (nodeId) {
          await toggleConnect({ nodeId });
        }
      }
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      syncNativeTray();
    }
  };

  useEffect(() => {
    const isTauri =
      typeof window !== "undefined" &&
      ("__TAURI_INTERNALS__" in window || "__TAURI__" in window) &&
      !androidBridge.available();
    if (!isTauri) return;

    let cancelled = false;
    const unsubs: Array<() => void> = [];
    void import("@tauri-apps/api/event")
      .then(async ({ listen }) => {
        if (cancelled) return;
        const u1 = await listen("proxy-disconnect", () => {
          void trayActionHandlerRef.current("disconnect");
        });
        const u2 = await listen<string>("proxy-tray-action", (evt) => {
          if (typeof evt.payload === "string") {
            void trayActionHandlerRef.current(evt.payload);
          }
        });
        if (cancelled) {
          u1();
          u2();
        } else {
          unsubs.push(u1, u2);
        }
      })
      .catch(() => {
        // Non-Tauri web runtime.
      });

    return () => {
      cancelled = true;
      for (const unsub of unsubs) {
        try {
          unsub();
        } catch {
          // Ignore teardown error.
        }
      }
    };
  }, []);

  const value = useMemo<AppStoreValue>(
    () => ({
      activeTab,
      setActiveTab,
      registerUnsavedGuard,
      pendingTabSwitch,
      savingPendingTabSwitch,
      confirmTabSwitchSave,
      confirmTabSwitchDiscard,
      cancelTabSwitch,
      locale,
      setLocale,
      tr,
      themeMode,
      resolvedTheme,
      setThemeMode,
      nodeViewMode,
      setNodeViewMode,
      sidebarCollapsed,
      setSidebarCollapsed,
      commandPaletteOpen,
      setCommandPaletteOpen,
      connectionColumns,
      setConnectionColumns,
      customNodeTabs,
      saveCustomNodeTabs,
      notice,
      notify,
      clearNotice,
      authStatus,
      status,
      nodes,
      groups,
      listeners,
      routing,
      ruleSets,
      subscriptions,
      tunState,
      cores,
      systemProxyEnabled,
      lastImportDiagnostic,
      setLastImportDiagnostic,
      busy,
      refreshAll,
      toggleConnect,
      toggleTUN,
      toggleSystemProxy,
      setAuthStatus,
    }),
    [
      activeTab,
      setActiveTab,
      registerUnsavedGuard,
      pendingTabSwitch,
      savingPendingTabSwitch,
      confirmTabSwitchSave,
      confirmTabSwitchDiscard,
      cancelTabSwitch,
      locale,
      setLocale,
      tr,
      themeMode,
      resolvedTheme,
      setThemeMode,
      nodeViewMode,
      setNodeViewMode,
      sidebarCollapsed,
      setSidebarCollapsed,
      commandPaletteOpen,
      setCommandPaletteOpen,
      connectionColumns,
      setConnectionColumns,
      customNodeTabs,
      saveCustomNodeTabs,
      notice,
      notify,
      clearNotice,
      authStatus,
      status,
      nodes,
      groups,
      listeners,
      routing,
      ruleSets,
      subscriptions,
      tunState,
      cores,
      systemProxyEnabled,
      lastImportDiagnostic,
      busy,
      refreshAll,
      toggleConnect,
      toggleTUN,
      toggleSystemProxy,
    ],
  );

  return React.createElement(
    AppStoreContext.Provider,
    { value },
    React.createElement(AppTelemetryProvider, { unlocked }, children),
  );
}

export function useAppStore(): AppStoreValue {
  const ctx = useContext(AppStoreContext);
  if (!ctx) {
    throw new Error("useAppStore must be used inside AppStoreProvider");
  }
  return ctx;
}

export function useTelemetry(): AppTelemetryValue {
  const ctx = useContext(AppTelemetryContext);
  if (!ctx) {
    throw new Error("useTelemetry must be used inside AppStoreProvider");
  }
  return ctx;
}
