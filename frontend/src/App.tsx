// SPDX-License-Identifier: MPL-2.0

import React, { Suspense, lazy, useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Globe,
  Layers,
  MoreHorizontal,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Power,
  QrCode,
  Route,
  Rss,
  Search,
  Settings,
  Sun,
} from "lucide-react";
import {
  APP_UPDATE_BADGE_EVENT,
  LAST_UPDATE_CHECK_TS_KEY,
  TRIGGER_UPDATE_CHECK_EVENT,
  isAutoUpdateCheckEnabled,
  loadCachedUpdateResult,
  saveCachedUpdateResult,
} from "./components/AppUpdateCard.tsx";
import { AuthGate } from "./components/AuthGate.tsx";
import { CommandPalette } from "./components/CommandPalette.tsx";
import { BottomSheetDialog } from "./components/ContextInspector.tsx";
import { PrismRayLogo } from "./components/PrismRayLogo.tsx";
import { Button } from "./components/ui/button.tsx";
import { QrLinkImportModal } from "./components/QrLinkImportModal.tsx";
import { StatusToast } from "./components/StatusToast.tsx";
import { api, formatApiError } from "./lib/api.ts";
import {
  APPEARANCE_EVENT,
  BACKGROUND_PRESETS,
  type AppearanceConfig,
  applyAppearanceToDocument,
  loadAppearanceConfig,
  loadWallpaperDataUrl,
} from "./lib/appearance.ts";
import { formatRate } from "./lib/helpers.ts";
import { useShiftHorizontalScroll } from "./lib/useShiftHorizontalScroll.ts";
import { AppStoreProvider, type NavTab, useAppStore, useTelemetry } from "./store/appStore.ts";

const OverviewView = lazy(() => import("./views/OverviewView.tsx").then((m) => ({ default: m.OverviewView })));
const ProxiesView = lazy(() => import("./views/ProxiesView.tsx").then((m) => ({ default: m.ProxiesView })));
const ConnectionsView = lazy(() => import("./views/ConnectionsView.tsx").then((m) => ({ default: m.ConnectionsView })));
const SubscriptionsView = lazy(() => import("./views/SubscriptionsView.tsx").then((m) => ({ default: m.SubscriptionsView })));
const RoutingView = lazy(() => import("./views/RoutingView.tsx").then((m) => ({ default: m.RoutingView })));
const SettingsLogsView = lazy(() => import("./views/SettingsLogsView.tsx").then((m) => ({ default: m.SettingsLogsView })));

function SidebarConnectionsBadge() {
  const { connections } = useTelemetry();
  if (connections.connections.length <= 0) return null;
  return (
    <span className="shrink-0 badge-radius border border-primary/30 bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary mono-num">
      {connections.connections.length}
    </span>
  );
}

function MobileConnectionsBadge() {
  const { connections } = useTelemetry();
  if (connections.connections.length <= 0) return null;
  return (
    <span className="badge-radius bg-primary/15 text-primary px-2 py-0.5 text-xs mono-num">
      {connections.connections.length}
    </span>
  );
}

function SidebarTrafficRates() {
  const { trafficNow } = useTelemetry();
  return (
    <div className="flex items-center justify-between gap-2 mono-num text-[11px]">
      <span className="inline-flex items-center gap-1 text-emerald-500">
        <ArrowDown className="h-3 w-3" aria-hidden="true" />
        {formatRate(trafficNow.down)}
      </span>
      <span className="inline-flex items-center gap-1 text-sky-500">
        <ArrowUp className="h-3 w-3" aria-hidden="true" />
        {formatRate(trafficNow.up)}
      </span>
    </div>
  );
}

const NAV_ITEMS: Array<{ id: NavTab; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "overview", icon: Activity },
  { id: "proxies", icon: Layers },
  { id: "connections", icon: Network },
  { id: "subscriptions", icon: Rss },
  { id: "routing", icon: Route },
  { id: "settings", icon: Settings },
];

const SIDEBAR_WIDTH_STORAGE_KEY = "prismray.sidebarWidth";
const SIDEBAR_FOOTER_TIER_KEY = "prismray.sidebarFooterTier";
const SIDEBAR_MIN_WIDTH = 160;
const SIDEBAR_COLLAPSED_WIDTH = 56;
const SIDEBAR_SNAP_COLLAPSE = 115;
const SIDEBAR_SNAP_EXPAND = 135;

type SidebarFooterTier = 0 | 1 | 2;

function loadSidebarFooterTier(): SidebarFooterTier {
  if (typeof window === "undefined") return 2;
  try {
    const raw = Number(window.localStorage.getItem(SIDEBAR_FOOTER_TIER_KEY));
    if (raw === 0 || raw === 1 || raw === 2) return raw;
  } catch {
    // Ignore storage read errors.
  }
  return 2;
}

function computeDefaultSidebarWidth(): number {
  if (typeof window === "undefined") return 228;
  return Math.round(Math.min(240, Math.max(192, window.innerWidth * 0.175)));
}

function computeMaxSidebarWidth(): number {
  if (typeof window === "undefined") return 420;
  const vw = window.innerWidth;
  return Math.max(SIDEBAR_MIN_WIDTH, Math.min(480, Math.floor(vw * 0.42), vw - 520));
}

function clampSidebarWidth(w: number): number {
  return Math.round(Math.min(computeMaxSidebarWidth(), Math.max(SIDEBAR_MIN_WIDTH, w)));
}

function loadSidebarWidth(): number {
  if (typeof window === "undefined") return 228;
  try {
    const raw = Number(window.localStorage.getItem(SIDEBAR_WIDTH_STORAGE_KEY));
    if (Number.isFinite(raw) && raw >= SIDEBAR_MIN_WIDTH) {
      return clampSidebarWidth(raw);
    }
  } catch {
    // Ignore storage read errors.
  }
  return computeDefaultSidebarWidth();
}

function Shell() {
  const {
    activeTab,
    setActiveTab,
    pendingTabSwitch,
    savingPendingTabSwitch,
    confirmTabSwitchSave,
    confirmTabSwitchDiscard,
    cancelTabSwitch,
    locale,
    setLocale,
    themeMode,
    resolvedTheme,
    setThemeMode,
    sidebarCollapsed,
    setSidebarCollapsed,
    setCommandPaletteOpen,
    status,
    busy,
    nodes,
    groups,
    routing,
    tunState,
    systemProxyEnabled,
    toggleConnect,
    toggleTUN,
    toggleSystemProxy,
    refreshAll,
    notify,
    tr,
  } = useAppStore();

  const [mobileMoreOpen, setMobileMoreOpen] = useState(false);
  const [quickCreateOpen, setQuickCreateOpen] = useState(false);
  const [qrScanModalOpen, setQrScanModalOpen] = useState(false);
  const [updateBadge, setUpdateBadge] = useState<{ hasUpdate: boolean; latestVersion: string }>(() => {
    const cached = loadCachedUpdateResult();
    return {
      hasUpdate: Boolean(cached?.has_update),
      latestVersion: cached?.latest_version || "",
    };
  });
  const [appearance, setAppearance] = useState<AppearanceConfig>(() => loadAppearanceConfig());
  const [wallpaperUrl, setWallpaperUrl] = useState<string | null>(null);

  const [sidebarWidth, setSidebarWidth] = useState<number>(() => loadSidebarWidth());
  const [resizingSidebarW, setResizingSidebarW] = useState(false);
  const [sidebarFooterTier, setSidebarFooterTier] = useState<SidebarFooterTier>(() => loadSidebarFooterTier());
  const [draggingFooterTier, setDraggingFooterTier] = useState(false);

  const asideRef = useRef<HTMLElement | null>(null);
  const scrollRootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(SIDEBAR_FOOTER_TIER_KEY, String(sidebarFooterTier));
    } catch {
      // Ignore storage write errors.
    }
  }, [sidebarFooterTier]);

  const startSidebarFooterDrag = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    const target = e.currentTarget;
    const startY = e.clientY;
    const startTier = sidebarFooterTier;
    let moved = false;

    try {
      target.setPointerCapture(e.pointerId);
    } catch {
      // Synthetic event fallback.
    }
    setDraggingFooterTier(true);
    document.body.classList.add("prismray-row-resizing");

    const onMove = (ev: PointerEvent) => {
      const deltaY = startY - ev.clientY; // dragging up expands tier
      if (Math.abs(deltaY) > 6) moved = true;
      const steps = Math.trunc(deltaY / 28);
      const next = Math.max(0, Math.min(2, startTier + steps)) as SidebarFooterTier;
      setSidebarFooterTier(next);
    };

    const onEnd = () => {
      setDraggingFooterTier(false);
      document.body.classList.remove("prismray-row-resizing");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onEnd);
      window.removeEventListener("pointercancel", onEnd);
      if (!moved) {
        // Quick click on handle toggles between full (2) and compact (0)
        setSidebarFooterTier((cur) => (cur === 2 ? 0 : ((cur + 1) as SidebarFooterTier)));
      }
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onEnd);
    window.addEventListener("pointercancel", onEnd);
  };

  useShiftHorizontalScroll();

  // Keep sidebar width clamped cleanly whenever the window resizes across displays / split screens
  useEffect(() => {
    if (typeof window === "undefined") return;
    window.PrismRayAndroid?.applyInsetsNow?.();
    const onResize = () => {
      setSidebarWidth((prev) => clampSidebarWidth(prev));
    };
    const onBadge = (event: Event) => {
      const detail = (event as CustomEvent<{ hasUpdate?: boolean; latestVersion?: string }>).detail;
      if (!detail) return;
      setUpdateBadge({
        hasUpdate: Boolean(detail.hasUpdate),
        latestVersion: detail.latestVersion || "",
      });
    };
    window.addEventListener("resize", onResize);
    window.addEventListener(APP_UPDATE_BADGE_EVENT, onBadge);
    return () => {
      window.removeEventListener("resize", onResize);
      window.removeEventListener(APP_UPDATE_BADGE_EVENT, onBadge);
    };
  }, []);

  // Silent 24-hour background app update check on startup
  useEffect(() => {
    if (typeof window === "undefined" || !isAutoUpdateCheckEnabled()) return;
    try {
      const lastTs = Number(window.localStorage.getItem(LAST_UPDATE_CHECK_TS_KEY) || "0");
      if (Number.isFinite(lastTs) && Date.now() - lastTs < 24 * 60 * 60 * 1000) {
        return;
      }
    } catch {
      // Proceed with check if storage is unavailable.
    }
    const timer = window.setTimeout(() => {
      void api
        .checkAppUpdate(false)
        .then((res) => {
          if (res.status !== "error") {
            saveCachedUpdateResult(res);
          }
        })
        .catch(() => {});
    }, 3500);
    return () => window.clearTimeout(timer);
  }, []);

  const openUpdateSection = () => {
    setActiveTab("settings");
    window.setTimeout(() => {
      document.getElementById("settings-cores")?.scrollIntoView({ behavior: "smooth", block: "start" });
      window.dispatchEvent(new CustomEvent(TRIGGER_UPDATE_CHECK_EVENT));
    }, 180);
  };

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(SIDEBAR_WIDTH_STORAGE_KEY, String(sidebarWidth));
    } catch {
      // Ignore storage write errors.
    }
  }, [sidebarWidth]);

  const startSidebarWidthResize = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    const target = e.currentTarget;
    try {
      target.setPointerCapture(e.pointerId);
    } catch {
      // Synthetic event fallback.
    }
    setResizingSidebarW(true);
    document.body.classList.add("prismray-col-resizing");

    let collapsedNow = sidebarCollapsed;
    const onMove = (ev: PointerEvent) => {
      const pointerX = ev.clientX;
      if (!collapsedNow && pointerX < SIDEBAR_SNAP_COLLAPSE) {
        collapsedNow = true;
        setSidebarCollapsed(true);
        return;
      }
      if (collapsedNow && pointerX > SIDEBAR_SNAP_EXPAND) {
        collapsedNow = false;
        setSidebarCollapsed(false);
        setSidebarWidth(clampSidebarWidth(pointerX));
        return;
      }
      if (!collapsedNow) {
        setSidebarWidth(clampSidebarWidth(pointerX));
      }
    };

    const onEnd = () => {
      setResizingSidebarW(false);
      document.body.classList.remove("prismray-col-resizing");
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onEnd);
      window.removeEventListener("pointercancel", onEnd);
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onEnd);
    window.addEventListener("pointercancel", onEnd);
  };

  const activeGroup = groups.find((g) => g.id === status?.active_group_id);
  const activeNode = nodes.find((n) => n.id === status?.active_node_id);
  const activeTargetLabel = activeGroup
    ? activeGroup.name
    : activeNode
      ? activeNode.user_alias || activeNode.name
      : tr("overview.noneSelected");
  const currentRoutingMode = routing?.mode || "rule";

  const switchSidebarMode = async (mode: "rule" | "global" | "direct") => {
    if (!routing || routing.mode === mode) return;
    try {
      await api.saveRouting({ ...routing, mode });
      await refreshAll();
      const label =
        mode === "rule" ? tr("routing.modeRule") : mode === "global" ? tr("routing.modeGlobal") : tr("routing.modeDirect");
      notify(locale === "zh-CN" ? `路由模式已切换为 ${label}` : `Routing mode switched to ${label}`);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  useEffect(() => {
    let active = true;
    const syncWallpaper = () => {
      void loadWallpaperDataUrl().then((url) => {
        if (active) setWallpaperUrl(url);
      });
    };
    syncWallpaper();

    const onAppearanceChange = () => {
      setAppearance(loadAppearanceConfig());
      syncWallpaper();
    };
    const onStorage = (ev: StorageEvent) => {
      if (ev.key === null || ev.key === "prismray-appearance-v1") {
        setAppearance(loadAppearanceConfig());
      }
    };
    window.addEventListener(APPEARANCE_EVENT, onAppearanceChange);
    window.addEventListener("storage", onStorage);
    return () => {
      active = false;
      window.removeEventListener(APPEARANCE_EVENT, onAppearanceChange);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  useEffect(() => {
    applyAppearanceToDocument(appearance, resolvedTheme, Boolean(wallpaperUrl));
  }, [appearance, resolvedTheme, wallpaperUrl]);

  useEffect(() => {
    scrollRootRef.current?.scrollTo({ top: 0 });
  }, [activeTab]);

  const cycleTheme = () => {
    if (themeMode === "system") setThemeMode("light");
    else if (themeMode === "light") setThemeMode("dark");
    else setThemeMode("system");
  };

  const triggerQuickCreate = (targetTab: NavTab, action: "node" | "subscription" | "rule") => {
    setQuickCreateOpen(false);
    setActiveTab(targetTab);
    window.setTimeout(() => {
      window.dispatchEvent(new CustomEvent("prismray-quick-create", { detail: action }));
    }, 40);
  };

  const themeLabel =
    themeMode === "light"
      ? tr("sidebar.themeLight")
      : themeMode === "dark"
        ? tr("sidebar.themeDark")
        : tr("sidebar.themeSystem");

  const renderView = () => {
    switch (activeTab) {
      case "overview":
        return <OverviewView />;
      case "proxies":
        return <ProxiesView />;
      case "connections":
        return <ConnectionsView />;
      case "subscriptions":
        return <SubscriptionsView />;
      case "routing":
        return <RoutingView />;
      case "settings":
        return <SettingsLogsView />;
    }
  };

  const activeBgPreset =
    appearance.bgPreset !== "none" && appearance.bgPreset !== "custom"
      ? BACKGROUND_PRESETS.find((p) => p.id === appearance.bgPreset)
      : null;
  const customBgImageStyle: React.CSSProperties | null =
    appearance.bgPreset === "custom" && wallpaperUrl
      ? { backgroundImage: `url("${wallpaperUrl}")` }
      : activeBgPreset
        ? {
            backgroundImage:
              resolvedTheme === "dark" ? activeBgPreset.darkGradient : activeBgPreset.lightGradient,
          }
        : null;

  return (
    <>
      {customBgImageStyle ? (
        <div className="app-bg-layer" aria-hidden="true">
          <div className="app-bg-media" style={customBgImageStyle} />
          <div className="app-bg-scrim" />
        </div>
      ) : null}
      <div className="app-shell-root relative z-10 flex min-h-dvh bg-background text-foreground md:fixed md:inset-0 md:overflow-hidden">
      {/* Desktop Sidebar (dynamically resizable with snap-to-collapse + vertical footer splitter) */}
      <aside
        ref={asideRef}
        style={{
          width: `${sidebarCollapsed ? SIDEBAR_COLLAPSED_WIDTH : sidebarWidth}px`,
        }}
        className={[
          "prism-sidebar relative hidden shrink-0 flex-col border-r border-border bg-background md:flex md:h-full",
          resizingSidebarW ? "" : "transition-[width] duration-150 ease-[cubic-bezier(0.16,1,0.3,1)]",
        ].join(" ")}
      >
        {/* Right-edge draggable width splitter (double-click to reset, drag left to snap-collapse) */}
        <div
          role="separator"
          tabIndex={0}
          aria-orientation="vertical"
          aria-label={tr("sidebar.resizeWidthHint")}
          aria-valuenow={sidebarCollapsed ? SIDEBAR_COLLAPSED_WIDTH : sidebarWidth}
          title={tr("sidebar.resizeWidthHint")}
          onPointerDown={startSidebarWidthResize}
          onDoubleClick={() => {
            setSidebarCollapsed(false);
            setSidebarWidth(computeDefaultSidebarWidth());
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowLeft") {
              e.preventDefault();
              if (!sidebarCollapsed) setSidebarWidth((w) => clampSidebarWidth(w - 12));
            } else if (e.key === "ArrowRight") {
              e.preventDefault();
              if (sidebarCollapsed) {
                setSidebarCollapsed(false);
                setSidebarWidth(SIDEBAR_MIN_WIDTH);
              } else {
                setSidebarWidth((w) => clampSidebarWidth(w + 12));
              }
            } else if (e.key === "Enter") {
              e.preventDefault();
              setSidebarCollapsed(false);
              setSidebarWidth(computeDefaultSidebarWidth());
            }
          }}
          className={`sidebar-resize-handle outline-none ${resizingSidebarW ? "is-active" : ""}`}
        />
        <div className="shrink-0 space-y-2 border-b border-border px-2.5 py-2.5">
          <div className={`flex items-center ${sidebarCollapsed ? "justify-center" : "justify-between gap-2"}`}>
            {!sidebarCollapsed ? (
              <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
                <PrismRayLogo className="h-7 w-7 shrink-0 rounded-[7px]" />
                <div className="min-w-0 flex-1 overflow-hidden">
                  <div className="flex min-w-0 items-baseline gap-1 overflow-hidden">
                    <span className="truncate text-[13px] font-bold tracking-tight text-foreground">
                      {tr("app.name")}
                    </span>
                    {sidebarWidth >= 215 ? (
                      <button
                        type="button"
                        onClick={openUpdateSection}
                        title={
                          updateBadge.hasUpdate
                            ? tr("update.badgeTooltip", { version: updateBadge.latestVersion })
                            : tr("update.versionTooltip", { version: tr("app.version") })
                        }
                        className="inline-flex shrink-0 items-center gap-1 rounded px-1 py-0.5 text-[10px] tabular-nums text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
                      >
                        <span>{tr("app.version")}</span>
                        {updateBadge.hasUpdate ? (
                          <span className="h-1.5 w-1.5 rounded-full bg-primary" aria-hidden="true" />
                        ) : null}
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
            ) : (
              <button
                type="button"
                onClick={() => setSidebarCollapsed(false)}
                title={tr("sidebar.expand")}
                aria-label={tr("sidebar.expand")}
                className="inline-flex h-8 w-8 items-center justify-center rounded-[7px] transition-opacity hover:opacity-90"
              >
                <PrismRayLogo className="h-7 w-7" />
              </button>
            )}

            {!sidebarCollapsed && (
              <div className="flex items-center gap-1 shrink-0">
                <span
                  className={[
                    "inline-flex items-center gap-1.5 overflow-hidden badge-radius border px-1.5 py-0.5 text-[10px] font-semibold leading-none tabular-nums",
                    status?.running
                      ? "border-primary/30 bg-primary/15 text-primary"
                      : "border-border bg-muted text-muted-foreground",
                  ].join(" ")}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      status?.running ? "bg-primary status-radar-dot" : "bg-muted-foreground/70"
                    }`}
                    aria-hidden="true"
                  />
                  {status?.running ? "ON" : "OFF"}
                </span>
                <button
                  type="button"
                  onClick={() => setSidebarCollapsed(true)}
                  title={tr("sidebar.collapse")}
                  aria-label={tr("sidebar.collapse")}
                  className="inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
                >
                  <PanelLeftClose className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={() => setCommandPaletteOpen(true)}
            title={`${tr("cmd.trigger")} (Ctrl+K)`}
            aria-label={tr("cmd.trigger")}
            className={[
              "w-full flex items-center rounded-[6px] border border-border bg-card text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors duration-150",
              sidebarCollapsed ? "justify-center h-8 px-0" : "justify-between gap-2 px-2.5 py-1.5 text-xs",
            ].join(" ")}
          >
            <span className="flex items-center gap-1.5 min-w-0">
              <Search className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {!sidebarCollapsed && <span className="truncate">{tr("cmd.trigger")}</span>}
            </span>
            {!sidebarCollapsed && (
              <kbd className="shrink-0 badge-radius border border-border bg-muted px-1 py-0.5 text-[10px] mono-num">
                ⌘K
              </kbd>
            )}
          </button>
        </div>

        <nav aria-label="Main navigation" className="flex-1 space-y-0.5 overflow-y-auto p-2">
          {sidebarCollapsed && (
            <button
              type="button"
              onClick={() => setSidebarCollapsed(false)}
              title={tr("sidebar.expand")}
              aria-label={tr("sidebar.expand")}
              className="mb-1 flex w-full items-center justify-center rounded-[6px] py-1.5 text-muted-foreground hover:bg-muted/70 hover:text-foreground transition-colors"
            >
              <PanelLeftOpen className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
          {NAV_ITEMS.map(({ id, icon: Icon }) => {
            const active = activeTab === id;
            const labelKey = `nav.${id}` as const;
            return (
              <button
                key={id}
                type="button"
                title={sidebarCollapsed ? tr(labelKey) : undefined}
                aria-current={active ? "page" : undefined}
                onClick={() => setActiveTab(id)}
                className={[
                  "group relative flex w-full items-center rounded-[6px] min-h-[34px] text-left text-[13px] transition-colors duration-150 ease-[cubic-bezier(0.16,1,0.3,1)] focus-visible:ring-inset",
                  sidebarCollapsed ? "justify-center px-0 py-1.5" : "gap-2.5 px-2.5 py-1.5",
                  active
                    ? "bg-accent font-semibold text-accent-foreground"
                    : "text-muted-foreground hover:bg-muted/70 hover:text-foreground",
                ].join(" ")}
              >
                {active ? (
                  <span
                    className="nav-indicator-pill absolute inset-y-1.5 left-0 w-0.5 rounded-r bg-primary"
                    aria-hidden="true"
                  />
                ) : null}
                <Icon className="h-4 w-4 shrink-0 transition-transform duration-150 group-hover:scale-105" />
                {!sidebarCollapsed && <span className="truncate flex-1">{tr(labelKey)}</span>}
                {!sidebarCollapsed && id === "connections" ? <SidebarConnectionsBadge /> : null}
              </button>
            );
          })}
        </nav>

        {/* Zero-gap snap-tier drag handle (snaps cleanly between 3 dock levels with no dead whitespace) */}
        {!sidebarCollapsed ? (
          <div
            role="separator"
            tabIndex={0}
            aria-orientation="horizontal"
            aria-label={tr("sidebar.resizeHeightHint")}
            title={tr("sidebar.resizeHeightHint")}
            onPointerDown={startSidebarFooterDrag}
            onKeyDown={(e) => {
              if (e.key === "ArrowUp") {
                e.preventDefault();
                setSidebarFooterTier((cur) => Math.min(2, cur + 1) as SidebarFooterTier);
              } else if (e.key === "ArrowDown") {
                e.preventDefault();
                setSidebarFooterTier((cur) => Math.max(0, cur - 1) as SidebarFooterTier);
              } else if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setSidebarFooterTier((cur) => (cur === 2 ? 0 : 2));
              }
            }}
            className="group flex h-3.5 shrink-0 cursor-row-resize select-none items-center justify-center border-t border-border/60 outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            <span
              aria-hidden="true"
              className={[
                "h-[3px] w-7 rounded-full transition-all duration-150",
                draggingFooterTier
                  ? "w-10 bg-primary"
                  : "bg-muted-foreground/30 group-hover:w-9 group-hover:bg-primary/65",
              ].join(" ")}
            />
          </div>
        ) : (
          <div className="border-t border-border/60" />
        )}

        <div className="shrink-0 px-2 pb-2 pt-0.5 text-xs flex flex-col gap-1.5">
          {!sidebarCollapsed && (
            <div className="space-y-2 rounded-xl bg-muted/40 p-2 ring-1 ring-border/50">
              {/* 1. Active Outbound + Quick Connect/Disconnect (Tier 2) */}
              {sidebarFooterTier >= 2 ? (
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5 text-[10px] leading-tight text-muted-foreground">
                      <span
                        className={[
                          "h-1.5 w-1.5 shrink-0 rounded-full",
                          status?.running ? "bg-emerald-500" : "bg-muted-foreground/50",
                        ].join(" ")}
                        aria-hidden="true"
                      />
                      <span className="truncate">{tr("overview.activeTarget")}</span>
                    </div>
                    <div
                      className="mt-0.5 truncate text-xs font-semibold leading-tight text-foreground"
                      title={activeTargetLabel}
                    >
                      {activeTargetLabel}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void toggleConnect()}
                    title={status?.running ? tr("action.disconnect") : tr("action.connect")}
                    aria-label={status?.running ? tr("action.disconnect") : tr("action.connect")}
                    className={[
                      "inline-flex h-7 w-7 min-h-0 shrink-0 items-center justify-center rounded-lg transition-all active:scale-[0.94] disabled:opacity-50",
                      status?.running
                        ? "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90"
                        : "bg-background/80 text-primary ring-1 ring-border/70 hover:bg-primary/10",
                    ].join(" ")}
                  >
                    <Power className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              ) : null}

              {/* 2. Quick Routing Mode Switcher (Tier >= 1) */}
              {sidebarFooterTier >= 1 ? (
                <div
                  role="group"
                  aria-label={tr("overview.mode")}
                  className="grid grid-cols-3 gap-0.5 rounded-lg bg-background/75 p-0.5 text-[11px]"
                >
                  {(
                    [
                      { id: "rule", label: locale === "zh-CN" ? "分流" : "Rule" },
                      { id: "global", label: locale === "zh-CN" ? "全局" : "Global" },
                      { id: "direct", label: locale === "zh-CN" ? "直连" : "Direct" },
                    ] as const
                  ).map((m) => {
                    const active = currentRoutingMode === m.id;
                    return (
                      <button
                        key={m.id}
                        type="button"
                        disabled={busy}
                        aria-pressed={active}
                        onClick={() => void switchSidebarMode(m.id)}
                        className={[
                          "min-h-0 truncate rounded-md px-1 py-1 font-medium leading-none transition-all",
                          active
                            ? "bg-primary text-primary-foreground shadow-xs"
                            : "text-muted-foreground hover:text-foreground",
                        ].join(" ")}
                      >
                        {m.label}
                      </button>
                    );
                  })}
                </div>
              ) : null}

              {/* 3. Live Traffic Speed + TUN / System Proxy Quick Toggles (Always visible) */}
              <div className="space-y-1.5">
                <SidebarTrafficRates />
                <div className="grid grid-cols-2 gap-1.5 text-[11px] tabular-nums">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void toggleTUN(!Boolean(tunState?.enabled))}
                    title={tunState?.enabled ? tr("sidebar.tunOn") : tr("sidebar.tunOff")}
                    className={[
                      "min-h-0 truncate rounded-lg px-1.5 py-1.5 text-center font-medium leading-none transition-all active:scale-[0.97] disabled:opacity-50",
                      tunState?.enabled
                        ? "bg-primary/15 text-primary ring-1 ring-primary/30 hover:bg-primary/20"
                        : "bg-background/75 text-muted-foreground hover:bg-background hover:text-foreground",
                    ].join(" ")}
                  >
                    {tunState?.enabled ? tr("sidebar.tunOn") : tr("sidebar.tunOff")}
                  </button>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void toggleSystemProxy(!systemProxyEnabled)}
                    title={systemProxyEnabled ? tr("sidebar.sysOn") : tr("sidebar.sysOff")}
                    className={[
                      "min-h-0 truncate rounded-lg px-1.5 py-1.5 text-center font-medium leading-none transition-all active:scale-[0.97] disabled:opacity-50",
                      systemProxyEnabled
                        ? "bg-primary/15 text-primary ring-1 ring-primary/30 hover:bg-primary/20"
                        : "bg-background/75 text-muted-foreground hover:bg-background hover:text-foreground",
                    ].join(" ")}
                  >
                    {systemProxyEnabled ? tr("sidebar.sysOn") : tr("sidebar.sysOff")}
                  </button>
                </div>
              </div>
            </div>
          )}
          {/* 4. Theme (Follow System) + Language Switcher */}
          <div className={`flex ${sidebarCollapsed ? "flex-col items-center gap-1.5" : "items-center gap-1.5"}`}>
            <button
              type="button"
              onClick={cycleTheme}
              title={themeLabel}
              aria-label={themeLabel}
              className={[
                "flex items-center justify-center rounded-lg bg-muted/45 text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground",
                sidebarCollapsed ? "h-8 w-8" : "min-w-0 flex-1 gap-1.5 px-2.5 py-1.5",
              ].join(" ")}
            >
              {resolvedTheme === "dark" ? (
                <Moon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              ) : (
                <Sun className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              )}
              {!sidebarCollapsed && <span className="truncate whitespace-nowrap text-[11px] font-medium">{themeLabel}</span>}
            </button>
            <button
              type="button"
              onClick={() => setLocale(locale === "zh-CN" ? "en-US" : "zh-CN")}
              title={tr("settings.language")}
              className={[
                "flex shrink-0 items-center justify-center rounded-lg bg-muted/45 whitespace-nowrap text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground",
                sidebarCollapsed ? "h-8 w-8 text-[10px]" : "gap-1 px-2.5 py-1.5 text-[11px] font-medium",
              ].join(" ")}
            >
              <Globe className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {!sidebarCollapsed && <span>{locale === "zh-CN" ? "EN" : "中文"}</span>}
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area (independent scroll pane on desktop) */}
      <div
        id="prismray-scroll-root"
        ref={scrollRootRef}
        className="flex min-w-0 flex-1 flex-col scroll-smooth scroll-pb-24 md:scroll-pb-6 md:h-full md:overflow-y-auto"
      >
        {/* Mobile Sticky Compact Header */}
        <header className="prism-glass-bar safe-top sticky top-0 z-30 flex items-center justify-between gap-2 border-b border-border bg-card/95 px-3 py-2 backdrop-blur md:hidden">
          <div className="flex items-center gap-2 min-w-0">
            <PrismRayLogo className="h-7 w-7 shrink-0 rounded-[7px]" />
            <span className="text-[15px] font-semibold text-foreground truncate">{tr(`nav.${activeTab}`)}</span>
            <span
              className={[
                "shrink-0 badge-radius border px-1.5 py-0.5 text-[10px] font-semibold mono-num",
                status?.running
                  ? "border-primary/30 bg-primary/15 text-primary"
                  : "border-border bg-muted text-muted-foreground",
              ].join(" ")}
            >
              {status?.running ? "ON" : "OFF"}
            </span>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => setCommandPaletteOpen(true)}
              aria-label={tr("cmd.trigger")}
              className="inline-flex h-[var(--m-btn-icon)] w-[var(--m-btn-icon)] min-h-[var(--m-btn-icon)] min-w-[var(--m-btn-icon)] items-center justify-center rounded-[6px] border border-border bg-background text-foreground"
            >
              <Search className="h-4 w-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={cycleTheme}
              aria-label={tr("settings.appearance")}
              className="inline-flex h-[var(--m-btn-icon)] w-[var(--m-btn-icon)] min-h-[var(--m-btn-icon)] min-w-[var(--m-btn-icon)] items-center justify-center rounded-[6px] border border-border bg-background text-foreground"
            >
              {resolvedTheme === "dark" ? (
                <Moon className="h-4 w-4" aria-hidden="true" />
              ) : (
                <Sun className="h-4 w-4" aria-hidden="true" />
              )}
            </button>
          </div>
        </header>

        <main className="mobile-safe-main mx-auto w-full max-w-[1440px] flex-1 p-3 pb-24 md:p-5 md:pb-6">
          <Suspense
            fallback={
              <div className="flex items-center justify-center py-16 text-xs text-muted-foreground">
                {tr("common.loadingView")}
              </div>
            }
          >
            <div key={activeTab} className="view-stage">
              {renderView()}
            </div>
          </Suspense>
        </main>

        {/* Mobile Bottom Navigation (4 Core Tabs + Center + Quick Create) */}
        <nav
          aria-label="Mobile navigation"
          className="prism-glass-bar safe-bottom fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 items-center border-t border-border bg-card/95 backdrop-blur md:hidden"
        >
          {(
            [
              { id: "overview", icon: Activity, label: tr("nav.overview") },
              { id: "proxies", icon: Layers, label: tr("nav.proxies") },
            ] as const
          ).map(({ id, icon: Icon, label }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                type="button"
                aria-current={active ? "page" : undefined}
                onClick={() => setActiveTab(id)}
                className={[
                  "relative flex min-h-12 flex-col items-center justify-center gap-0.5 px-1 py-1 text-[11px] transition-colors",
                  active ? "font-semibold text-primary" : "text-muted-foreground",
                ].join(" ")}
              >
                {active && <span className="absolute top-0 inset-x-4 h-0.5 rounded-b bg-primary" aria-hidden="true" />}
                <Icon className="h-4 w-4 shrink-0" />
                <span className="max-w-full truncate">{label}</span>
              </button>
            );
          })}

          <div className="flex items-center justify-center">
            <button
              type="button"
              onClick={() => setQuickCreateOpen(true)}
              aria-label={tr("mobile.quickCreate")}
              className="inline-flex h-10 w-12 items-center justify-center rounded-[10px] bg-primary text-primary-foreground hover:opacity-90 transition-opacity"
            >
              <Plus className="h-5 w-5" aria-hidden="true" />
            </button>
          </div>

          <button
            type="button"
            aria-current={activeTab === "routing" ? "page" : undefined}
            onClick={() => setActiveTab("routing")}
            className={[
              "relative flex min-h-12 flex-col items-center justify-center gap-0.5 px-1 py-1 text-[11px] transition-colors",
              activeTab === "routing" ? "font-semibold text-primary" : "text-muted-foreground",
            ].join(" ")}
          >
            {activeTab === "routing" && (
              <span className="absolute top-0 inset-x-4 h-0.5 rounded-b bg-primary" aria-hidden="true" />
            )}
            <Route className="h-4 w-4 shrink-0" />
            <span className="max-w-full truncate">{tr("nav.routing")}</span>
          </button>

          <button
            type="button"
            onClick={() => setMobileMoreOpen(true)}
            aria-expanded={mobileMoreOpen}
            className={[
              "relative flex min-h-12 flex-col items-center justify-center gap-0.5 px-1 py-1 text-[11px] transition-colors",
              activeTab === "connections" || activeTab === "subscriptions" || activeTab === "settings"
                ? "font-semibold text-primary"
                : "text-muted-foreground",
            ].join(" ")}
          >
            {(activeTab === "connections" || activeTab === "subscriptions" || activeTab === "settings") && (
              <span className="absolute top-0 inset-x-4 h-0.5 rounded-b bg-primary" aria-hidden="true" />
            )}
            <MoreHorizontal className="h-4 w-4 shrink-0" />
            <span className="max-w-full truncate">{tr("mobile.more")}</span>
          </button>
        </nav>

        <BottomSheetDialog open={quickCreateOpen} title={tr("mobile.quickCreate")} onClose={() => setQuickCreateOpen(false)}>
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => {
                setQuickCreateOpen(false);
                setQrScanModalOpen(true);
              }}
              className="w-full min-h-12 flex items-center gap-3 rounded-[6px] border border-primary/40 bg-primary/10 px-3.5 py-2 text-left text-[15px] font-medium text-primary hover:bg-primary/15"
            >
              <QrCode className="h-4 w-4 shrink-0" />
              <span>{tr("mobile.scanQr")}</span>
            </button>
            <button
              type="button"
              onClick={() => triggerQuickCreate("proxies", "node")}
              className="w-full min-h-12 flex items-center gap-3 rounded-[6px] border border-border bg-card px-3.5 py-2 text-left text-[15px] font-medium hover:bg-muted"
            >
              <Layers className="h-4 w-4 text-primary shrink-0" />
              <span>{tr("mobile.createNode")}</span>
            </button>
            <button
              type="button"
              onClick={() => triggerQuickCreate("subscriptions", "subscription")}
              className="w-full min-h-12 flex items-center gap-3 rounded-[6px] border border-border bg-card px-3.5 py-2 text-left text-[15px] font-medium hover:bg-muted"
            >
              <Rss className="h-4 w-4 text-primary shrink-0" />
              <span>{tr("mobile.createSub")}</span>
            </button>
            <button
              type="button"
              onClick={() => triggerQuickCreate("routing", "rule")}
              className="w-full min-h-12 flex items-center gap-3 rounded-[6px] border border-border bg-card px-3.5 py-2 text-left text-[15px] font-medium hover:bg-muted"
            >
              <Route className="h-4 w-4 text-primary shrink-0" />
              <span>{tr("mobile.createRule")}</span>
            </button>
          </div>
        </BottomSheetDialog>

        <BottomSheetDialog open={mobileMoreOpen} title={tr("mobile.more")} onClose={() => setMobileMoreOpen(false)}>
          <div className="space-y-2">
            {(
              [
                { id: "connections", icon: Network },
                { id: "subscriptions", icon: Rss },
                { id: "settings", icon: Settings },
              ] as const
            ).map(({ id, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => {
                  setActiveTab(id);
                  setMobileMoreOpen(false);
                }}
                className={`w-full min-h-12 flex items-center justify-between gap-3 rounded-[6px] border px-3.5 py-2 text-left text-[15px] font-medium ${
                  activeTab === id ? "border-primary bg-accent text-accent-foreground" : "border-border bg-card"
                }`}
              >
                <span className="flex items-center gap-3">
                  <Icon className="h-4 w-4 shrink-0" />
                  <span>{tr(`nav.${id}`)}</span>
                </span>
                {id === "connections" ? <MobileConnectionsBadge /> : null}
              </button>
            ))}
            <div className="pt-2 border-t border-border grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={cycleTheme}
                className="min-h-12 flex items-center justify-center gap-2 rounded-[6px] border border-border bg-card px-3 text-sm"
              >
                {resolvedTheme === "dark" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
                <span>{themeLabel}</span>
              </button>
              <button
                type="button"
                onClick={() => setLocale(locale === "zh-CN" ? "en-US" : "zh-CN")}
                className="min-h-12 flex items-center justify-center gap-2 rounded-[6px] border border-border bg-card px-3 text-sm"
              >
                <Globe className="h-4 w-4" />
                <span>{locale === "zh-CN" ? "English" : "简体中文"}</span>
              </button>
            </div>
          </div>
        </BottomSheetDialog>
      </div>
      <CommandPalette />
      <QrLinkImportModal open={qrScanModalOpen} onClose={() => setQrScanModalOpen(false)} />
      <BottomSheetDialog
        open={pendingTabSwitch !== null}
        title={tr("unsaved.title")}
        onClose={cancelTabSwitch}
      >
        <div className="space-y-4">
          <p className="text-sm leading-relaxed text-muted-foreground">{tr("unsaved.desc")}</p>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={savingPendingTabSwitch}
              onClick={cancelTabSwitch}
            >
              {tr("unsaved.stay")}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={savingPendingTabSwitch}
              className="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
              onClick={confirmTabSwitchDiscard}
            >
              {tr("unsaved.discard")}
            </Button>
            <Button
              type="button"
              size="sm"
              disabled={savingPendingTabSwitch}
              onClick={() => void confirmTabSwitchSave()}
            >
              {tr("unsaved.saveAndLeave")}
            </Button>
          </div>
        </div>
      </BottomSheetDialog>
      </div>
    </>
  );
}

export function App() {
  return (
    <AppStoreProvider>
      <AuthGate>
        <Shell />
      </AuthGate>
      <StatusToast />
    </AppStoreProvider>
  );
}

export default App;
