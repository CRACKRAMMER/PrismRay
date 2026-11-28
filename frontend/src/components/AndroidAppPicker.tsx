// SPDX-License-Identifier: MPL-2.0

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CheckSquare, ChevronDown, RefreshCw, Search, Square, Trash2 } from "lucide-react";
import { type AndroidAppInfo, androidBridge } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";
import { Switch } from "./ui/switch.tsx";

type AppFilterTab = "user" | "all" | "system" | "selected";

interface AppCategoryPreset {
  id: string;
  labelKey: "routing.perAppPresetCn" | "routing.perAppPresetGoogle" | "routing.perAppPresetBrowser" | "routing.perAppPresetChat";
  packages: string[];
}

const APP_CATEGORY_PRESETS: AppCategoryPreset[] = [
  {
    id: "cn",
    labelKey: "routing.perAppPresetCn",
    packages: [
      "com.tencent.mm",
      "com.tencent.mobileqq",
      "com.eg.android.AlipayGphone",
      "com.taobao.taobao",
      "com.jingdong.app.mall",
      "com.xunmeng.pinduoduo",
      "com.ss.android.ugc.aweme",
      "tv.danmaku.bili",
      "com.xingin.xhs",
      "com.sina.weibo",
      "com.autonavi.minimap",
      "com.baidu.BaiduMap",
      "com.sankuai.meituan",
      "com.netease.cloudmusic",
      "com.tencent.qqmusic",
    ],
  },
  {
    id: "google",
    labelKey: "routing.perAppPresetGoogle",
    packages: [
      "com.android.vending",
      "com.google.android.gms",
      "com.google.android.gsf",
      "com.google.android.googlequicksearchbox",
      "com.google.android.youtube",
      "com.google.android.gm",
      "com.google.android.apps.maps",
      "com.google.android.apps.docs",
      "com.google.android.apps.photos",
      "com.google.android.apps.bard",
    ],
  },
  {
    id: "browser",
    labelKey: "routing.perAppPresetBrowser",
    packages: [
      "com.android.chrome",
      "com.chrome.beta",
      "org.mozilla.firefox",
      "com.microsoft.emmx",
      "com.brave.browser",
      "com.opera.browser",
      "com.kiwibrowser.browser",
      "com.vivaldi.browser",
      "mark.via.gp",
      "com.sec.android.app.sbrowser",
    ],
  },
  {
    id: "chat",
    labelKey: "routing.perAppPresetChat",
    packages: [
      "org.telegram.messenger",
      "org.telegram.messenger.web",
      "tw.nekomimi.nekogram",
      "com.whatsapp",
      "com.discord",
      "org.thoughtcrime.securesms",
      "jp.naver.line.android",
      "com.Slack",
      "com.twitter.android",
    ],
  },
];

interface AppRowProps {
  app: AndroidAppInfo;
  checked: boolean;
  iconSrc?: string;
  systemTagLabel: string;
  onToggle: (pkg: string) => void;
}

const AppPickerRow = memo(function AppPickerRow({
  app,
  checked,
  iconSrc,
  systemTagLabel,
  onToggle,
}: AppRowProps) {
  const initial = (app.label || app.packageName).trim().slice(0, 1).toUpperCase() || "?";
  return (
    <div
      onClick={() => onToggle(app.packageName)}
      className={[
        "flex cursor-pointer items-center justify-between gap-2.5 px-2.5 py-2 transition-colors",
        checked ? "bg-primary/5" : "hover:bg-muted/40",
      ].join(" ")}
    >
      <div className="flex min-w-0 flex-1 items-center gap-2.5">
        {iconSrc ? (
          <img
            src={iconSrc}
            alt=""
            loading="lazy"
            className="h-8 w-8 shrink-0 rounded-[8px] object-cover shadow-xs"
          />
        ) : (
          <span
            aria-hidden="true"
            className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-[8px] border text-xs font-semibold ${toneForPackage(app.packageName)}`}
          >
            {initial}
          </span>
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-[13px] font-medium text-foreground">{app.label}</span>
            {app.system ? (
              <span className="shrink-0 rounded border border-border bg-muted px-1 py-0 text-[10px] text-muted-foreground">
                {systemTagLabel}
              </span>
            ) : null}
          </div>
          <div className="truncate font-mono text-[11px] text-muted-foreground">{app.packageName}</div>
        </div>
      </div>
      <div className="shrink-0" onClick={(e) => e.stopPropagation()}>
        <Switch
          checked={checked}
          onCheckedChange={() => onToggle(app.packageName)}
          aria-label={app.label}
        />
      </div>
    </div>
  );
});

const AVATAR_TONES = [
  "bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border-indigo-500/25",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/25",
  "bg-sky-500/15 text-sky-600 dark:text-sky-300 border-sky-500/25",
  "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/25",
  "bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/25",
  "bg-violet-500/15 text-violet-600 dark:text-violet-300 border-violet-500/25",
];

// Shared in-memory cache so PerAppProxyCard and RuleEditorModal never repeat synchronous JNI queries.
let cachedInstalledApps: AndroidAppInfo[] | null = null;
const cachedAppIcons: Record<string, string> = {};

function toneForPackage(pkg: string): string {
  let hash = 0;
  for (let i = 0; i < pkg.length; i += 1) {
    hash = (hash * 31 + pkg.charCodeAt(i)) | 0;
  }
  return AVATAR_TONES[Math.abs(hash) % AVATAR_TONES.length];
}

export function splitPackageList(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of text.split(/[\n,]/)) {
    const cleaned = part.trim();
    if (!cleaned || seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
  }
  return out;
}

export interface AndroidAppPickerProps {
  packages: string[];
  onChangePackages: (packages: string[]) => void;
  active?: boolean;
  maxListHeightClass?: string;
  showManualToggle?: boolean;
}

export function AndroidAppPicker({
  packages,
  onChangePackages,
  active = true,
  maxListHeightClass = "max-h-72",
  showManualToggle = true,
}: AndroidAppPickerProps) {
  const { tr } = useAppStore();

  const [installedApps, setInstalledApps] = useState<AndroidAppInfo[]>(() => cachedInstalledApps ?? []);
  const [loadingApps, setLoadingApps] = useState(false);
  const [search, setSearch] = useState("");
  const [filterTab, setFilterTab] = useState<AppFilterTab>("user");
  const [iconMap, setIconMap] = useState<Record<string, string>>(() => ({ ...cachedAppIcons }));
  const [manualOpen, setManualOpen] = useState(false);
  const requestedIconsRef = useRef<Set<string>>(new Set(Object.keys(cachedAppIcons)));
  // Freeze "selected-first" sort order while toggling checkboxes so Android WebView never jumps scroll position.
  // Only re-snapshot when opening, switching tabs, or clicking Refresh.
  const [sortPinnedSnapshot, setSortPinnedSnapshot] = useState<Set<string>>(() => new Set(packages));
  const packagesRef = useRef(packages);
  packagesRef.current = packages;
  const mountedRef = useRef(true);
  const pendingLoadCleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      pendingLoadCleanupRef.current?.();
      pendingLoadCleanupRef.current = null;
    };
  }, []);

  const selectedSet = useMemo(() => new Set(packages), [packages]);

  const loadApps = useCallback((forceRefresh = false) => {
    if (!androidBridge.available()) return;
    if (!forceRefresh && cachedInstalledApps !== null) {
      setInstalledApps(cachedInstalledApps);
      return;
    }
    pendingLoadCleanupRef.current?.();
    pendingLoadCleanupRef.current = null;
    setLoadingApps(true);

    const finishWithApps = (apps: AndroidAppInfo[]) => {
      cachedInstalledApps = apps;
      if (!mountedRef.current) return;
      setInstalledApps(apps);
      setSortPinnedSnapshot(new Set(packagesRef.current));
      setLoadingApps(false);
    };

    const runSyncFallback = () => {
      try {
        const apps = androidBridge.listInstalledApps();
        finishWithApps(apps);
      } catch {
        if (mountedRef.current) {
          setLoadingApps(false);
        }
      }
    };

    const reqId = `apps-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    let settled = false;
    let fallbackTimer = 0;

    const cleanup = () => {
      window.removeEventListener("prismray-android-apps", onResult as EventListener);
      if (fallbackTimer) {
        window.clearTimeout(fallbackTimer);
        fallbackTimer = 0;
      }
    };

    const onResult = (evt: Event) => {
      const detail = (evt as CustomEvent<{ requestId?: string; apps?: AndroidAppInfo[] }>).detail;
      if (detail?.requestId !== reqId || settled) return;
      settled = true;
      cleanup();
      if (pendingLoadCleanupRef.current === cleanup) {
        pendingLoadCleanupRef.current = null;
      }
      const taken = androidBridge.takeInstalledAppsResult(reqId);
      const apps = taken !== null ? taken : Array.isArray(detail.apps) ? detail.apps : [];
      finishWithApps(apps);
    };

    window.addEventListener("prismray-android-apps", onResult as EventListener);
    fallbackTimer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      if (pendingLoadCleanupRef.current === cleanup) {
        pendingLoadCleanupRef.current = null;
      }
      runSyncFallback();
    }, 5000);
    pendingLoadCleanupRef.current = cleanup;

    // Invoke via androidBridge wrapper so window.PrismRayAndroid remains bound as receiver (`this`).
    if (androidBridge.listInstalledAppsAsync(reqId)) {
      return;
    }
    settled = true;
    cleanup();
    pendingLoadCleanupRef.current = null;
    runSyncFallback();
  }, []);

  // Re-snapshot pinned sort order when becoming visible again.
  useEffect(() => {
    if (active) {
      setSortPinnedSnapshot(new Set(packagesRef.current));
    }
  }, [active]);

  // Defer synchronous JNI listInstalledApps() until picker is actually visible/active.
  useEffect(() => {
    if (!active || !androidBridge.available()) return;
    if (cachedInstalledApps !== null) {
      setInstalledApps(cachedInstalledApps);
      return;
    }
    const timer = window.setTimeout(() => {
      loadApps(false);
    }, 16);
    return () => window.clearTimeout(timer);
  }, [active, loadApps]);

  const counts = useMemo(() => {
    let user = 0;
    let system = 0;
    for (const app of installedApps) {
      if (app.system) system += 1;
      else user += 1;
    }
    return {
      user,
      system,
      all: installedApps.length,
      selected: packages.length,
    };
  }, [installedApps, packages.length]);

  // Base catalog merges installed apps with any manually-entered unknown package names from snapshot/selection.
  const baseCatalog = useMemo(() => {
    const byPkg = new Map<string, AndroidAppInfo>();
    for (const app of installedApps) {
      byPkg.set(app.packageName, app);
    }
    const merged: AndroidAppInfo[] = [...installedApps];
    for (const pkg of sortPinnedSnapshot) {
      if (!byPkg.has(pkg)) {
        const custom = { packageName: pkg, label: pkg, system: false };
        byPkg.set(pkg, custom);
        merged.push(custom);
      }
    }
    return merged;
  }, [installedApps, sortPinnedSnapshot]);

  const filteredApps = useMemo(() => {
    const q = search.trim().toLowerCase();
    let pool = baseCatalog;
    if (filterTab === "selected") {
      // Include any newly selected unknown packages when explicitly viewing the Selected tab.
      const existing = new Set(baseCatalog.map((a) => a.packageName));
      const extras = packages
        .filter((pkg) => !existing.has(pkg))
        .map((pkg) => ({ packageName: pkg, label: pkg, system: false }));
      pool = extras.length > 0 ? [...baseCatalog, ...extras] : baseCatalog;
    }

    const list = pool.filter((app) => {
      if (filterTab === "user" && app.system) return false;
      if (filterTab === "system" && !app.system) return false;
      if (filterTab === "selected" && !selectedSet.has(app.packageName)) return false;
      if (!q) return true;
      return (
        app.label.toLowerCase().includes(q) ||
        app.packageName.toLowerCase().includes(q)
      );
    });

    list.sort((a, b) => {
      const aSel = sortPinnedSnapshot.has(a.packageName) ? 0 : 1;
      const bSel = sortPinnedSnapshot.has(b.packageName) ? 0 : 1;
      if (aSel !== bSel) return aSel - bSel;
      return a.label.localeCompare(b.label);
    });
    return list;
  }, [baseCatalog, filterTab, search, sortPinnedSnapshot, filterTab === "selected" ? selectedSet : null, filterTab === "selected" ? packages : null]);

  // Lazily fetch real Android app icons in rolling chunks across the entire filtered list
  // (never truncating after the first 36 apps and never re-running on checkbox toggles).
  const iconBatchKey = useMemo(() => filteredApps.map((a) => a.packageName).join(","), [filteredApps]);
  useEffect(() => {
    if (!active || !androidBridge.available() || !iconBatchKey) {
      return;
    }
    const queue = iconBatchKey
      .split(",")
      .filter((pkg) => pkg && !requestedIconsRef.current.has(pkg));
    if (queue.length === 0) return;

    let cancelled = false;
    let offset = 0;
    let timer = 0;

    const pumpBatch = () => {
      if (cancelled || offset >= queue.length) return;
      const chunk = queue.slice(offset, offset + 24);
      offset += chunk.length;
      for (const pkg of chunk) requestedIconsRef.current.add(pkg);
      const fetched = androidBridge.getAppIcons(chunk);
      if (!cancelled && Object.keys(fetched).length > 0) {
        Object.assign(cachedAppIcons, fetched);
        setIconMap((prev) => ({ ...prev, ...fetched }));
      }
      if (!cancelled && offset < queue.length) {
        timer = window.setTimeout(pumpBatch, 60);
      }
    };

    timer = window.setTimeout(pumpBatch, 40);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [iconBatchKey, active]);

  const togglePackage = useCallback(
    (pkg: string) => {
      const next = new Set(packagesRef.current);
      if (next.has(pkg)) next.delete(pkg);
      else next.add(pkg);
      onChangePackages(Array.from(next));
    },
    [onChangePackages],
  );

  const selectAllFiltered = () => {
    const next = new Set(packages);
    for (const app of filteredApps) next.add(app.packageName);
    onChangePackages(Array.from(next));
  };

  const invertFiltered = () => {
    const next = new Set(packages);
    for (const app of filteredApps) {
      if (next.has(app.packageName)) next.delete(app.packageName);
      else next.add(app.packageName);
    }
    onChangePackages(Array.from(next));
  };

  const clearAll = () => {
    onChangePackages([]);
  };

  const installedSet = useMemo(() => new Set(installedApps.map((a) => a.packageName)), [installedApps]);

  const presetMatches = useMemo(
    () =>
      APP_CATEGORY_PRESETS.map((preset) => {
        const matched = preset.packages.filter((pkg) => installedSet.has(pkg));
        const selectedCount = matched.filter((pkg) => selectedSet.has(pkg)).length;
        return {
          ...preset,
          matched,
          allSelected: matched.length > 0 && selectedCount === matched.length,
        };
      }).filter((p) => p.matched.length > 0),
    [installedSet, selectedSet],
  );

  const togglePreset = (matched: string[], allSelected: boolean) => {
    const next = new Set(packagesRef.current);
    if (allSelected) {
      for (const pkg of matched) next.delete(pkg);
    } else {
      for (const pkg of matched) next.add(pkg);
    }
    onChangePackages(Array.from(next));
  };

  return (
    <div className="space-y-2.5">
      {/* Search + Refresh */}
      <div className="flex items-center gap-2">
        <div className="relative min-w-0 flex-1">
          <Search
            className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={tr("routing.perAppSearchPlaceholder")}
            className="pl-8"
          />
        </div>
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={() => loadApps(true)}
          disabled={loadingApps}
          title={tr("routing.perAppRefresh")}
          aria-label={tr("routing.perAppRefresh")}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loadingApps ? "animate-spin" : ""}`} aria-hidden="true" />
        </Button>
      </div>

      {/* Filter Chips */}
      <div className="no-scrollbar flex items-center gap-1.5 overflow-x-auto pb-0.5">
        {(
          [
            { id: "user", label: tr("routing.perAppTabUser"), count: counts.user },
            { id: "all", label: tr("routing.perAppTabAll"), count: counts.all },
            { id: "system", label: tr("routing.perAppTabSystem"), count: counts.system },
            { id: "selected", label: tr("routing.perAppTabSelected"), count: counts.selected },
          ] as const
        ).map((tab) => {
          const isTabActive = filterTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              aria-pressed={isTabActive}
              onClick={() => {
                setSortPinnedSnapshot(new Set(packagesRef.current));
                setFilterTab(tab.id);
              }}
              className={[
                "inline-flex shrink-0 items-center gap-1 rounded-[6px] border px-2.5 py-1 text-xs font-medium whitespace-nowrap transition-colors",
                isTabActive
                  ? "border-primary/40 bg-primary/15 text-primary"
                  : "border-border bg-background text-muted-foreground hover:text-foreground",
              ].join(" ")}
            >
              <span>{tab.label}</span>
              <span className="mono-num text-[10px] opacity-75">{tab.count}</span>
            </button>
          );
        })}
      </div>

      {/* Quick Category Presets (only shows presets matching installed apps) */}
      {presetMatches.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-muted-foreground">{tr("routing.perAppPresets")}:</span>
          {presetMatches.map((preset) => (
            <button
              key={preset.id}
              type="button"
              onClick={() => togglePreset(preset.matched, preset.allSelected)}
              className={`inline-flex items-center gap-1 rounded-[6px] border px-2 py-0.5 font-medium transition-colors ${
                preset.allSelected
                  ? "border-primary/45 bg-primary/15 text-primary"
                  : "border-border bg-muted/30 text-muted-foreground hover:text-foreground"
              }`}
            >
              <span>{tr(preset.labelKey)}</span>
              <span className="mono-num text-[10px] opacity-80">({preset.matched.length})</span>
            </button>
          ))}
        </div>
      ) : null}

      {/* Batch Actions Bar */}
      <div className="flex flex-wrap items-center justify-between gap-1.5 text-xs">
        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={selectAllFiltered}
            disabled={filteredApps.length === 0}
          >
            <CheckSquare className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            {tr("routing.perAppSelectFiltered")}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={invertFiltered}
            disabled={filteredApps.length === 0}
          >
            <Square className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            {tr("routing.perAppInvertFiltered")}
          </Button>
        </div>
        {packages.length > 0 ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={clearAll}
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
            {tr("routing.perAppClearAll")}
          </Button>
        ) : null}
      </div>

      {/* Installed App List */}
      <div
        className={`${maxListHeightClass} divide-y divide-border/70 overflow-y-auto [overflow-anchor:none] rounded-[8px] border border-border bg-background/50`}
      >
        {loadingApps && filteredApps.length === 0 ? (
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">
            {tr("common.loadingView")}
          </div>
        ) : filteredApps.length === 0 ? (
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">
            {tr("routing.perAppEmpty")}
          </div>
        ) : (
          filteredApps.map((app) => (
            <AppPickerRow
              key={app.packageName}
              app={app}
              checked={selectedSet.has(app.packageName)}
              iconSrc={iconMap[app.packageName]}
              systemTagLabel={tr("routing.perAppSystemTag")}
              onToggle={togglePackage}
            />
          ))
        )}
      </div>

      {/* Optional Collapsible Manual Package Editor */}
      {showManualToggle ? (
        <div className="rounded-[8px] border border-border bg-muted/20">
          <button
            type="button"
            onClick={() => setManualOpen((prev) => !prev)}
            aria-expanded={manualOpen}
            className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-xs font-medium text-muted-foreground hover:text-foreground"
          >
            <span>{tr("routing.perAppManualToggle")}</span>
            <ChevronDown
              className={`h-3.5 w-3.5 shrink-0 transition-transform ${manualOpen ? "rotate-180" : ""}`}
              aria-hidden="true"
            />
          </button>
          {manualOpen ? (
            <div className="space-y-1.5 border-t border-border px-3 py-2.5">
              <p className="text-[11px] text-muted-foreground">{tr("routing.perAppManualHint")}</p>
              <textarea
                rows={3}
                className="w-full min-h-[4.5rem] rounded-[6px] border border-input bg-background px-2.5 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground"
                placeholder="com.android.chrome&#10;org.telegram.messenger"
                value={packages.join("\n")}
                onChange={(e) => onChangePackages(splitPackageList(e.target.value))}
              />
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
