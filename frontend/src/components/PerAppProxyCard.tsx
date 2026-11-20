// SPDX-License-Identifier: MPL-2.0

import { useEffect, useMemo, useRef, useState } from "react";
import { CheckSquare, ChevronDown, RefreshCw, Search, Smartphone, Square, Trash2 } from "lucide-react";
import { type AndroidAppInfo, androidBridge } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";
import { Input } from "./ui/input.tsx";
import { Switch } from "./ui/switch.tsx";

type PerAppMode = "all" | "whitelist" | "blacklist";
type AppFilterTab = "user" | "all" | "system" | "selected";

interface PerAppProxyCardProps {
  mode: string;
  packages: string[];
  onChangeMode: (mode: PerAppMode) => void;
  onChangePackages: (packages: string[]) => void;
}

const AVATAR_TONES = [
  "bg-indigo-500/15 text-indigo-600 dark:text-indigo-300 border-indigo-500/25",
  "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/25",
  "bg-sky-500/15 text-sky-600 dark:text-sky-300 border-sky-500/25",
  "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/25",
  "bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/25",
  "bg-violet-500/15 text-violet-600 dark:text-violet-300 border-violet-500/25",
];

function toneForPackage(pkg: string): string {
  let hash = 0;
  for (let i = 0; i < pkg.length; i += 1) {
    hash = (hash * 31 + pkg.charCodeAt(i)) | 0;
  }
  return AVATAR_TONES[Math.abs(hash) % AVATAR_TONES.length];
}

function splitPackages(text: string): string[] {
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

export function PerAppProxyCard({
  mode,
  packages,
  onChangeMode,
  onChangePackages,
}: PerAppProxyCardProps) {
  const { tr } = useAppStore();
  const normalizedMode: PerAppMode =
    mode === "whitelist" || mode === "blacklist" ? mode : "all";

  const [installedApps, setInstalledApps] = useState<AndroidAppInfo[]>([]);
  const [loadingApps, setLoadingApps] = useState(false);
  const [search, setSearch] = useState("");
  const [filterTab, setFilterTab] = useState<AppFilterTab>("user");
  const [iconMap, setIconMap] = useState<Record<string, string>>({});
  const [manualOpen, setManualOpen] = useState(false);
  const requestedIconsRef = useRef<Set<string>>(new Set());

  const selectedSet = useMemo(() => new Set(packages), [packages]);

  const loadApps = () => {
    setLoadingApps(true);
    try {
      const apps = androidBridge.listInstalledApps();
      setInstalledApps(apps);
    } finally {
      setLoadingApps(false);
    }
  };

  useEffect(() => {
    if (androidBridge.available()) {
      loadApps();
    }
  }, []);

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

  const filteredApps = useMemo(() => {
    const q = search.trim().toLowerCase();
    // Ensure manually typed packages that aren't in installedApps still appear in "selected" view
    const byPkg = new Map<string, AndroidAppInfo>();
    for (const app of installedApps) {
      byPkg.set(app.packageName, app);
    }
    const merged: AndroidAppInfo[] = [...installedApps];
    for (const pkg of packages) {
      if (!byPkg.has(pkg)) {
        merged.push({ packageName: pkg, label: pkg, system: false });
      }
    }

    const list = merged.filter((app) => {
      if (filterTab === "user" && app.system) return false;
      if (filterTab === "system" && !app.system) return false;
      if (filterTab === "selected" && !selectedSet.has(app.packageName)) return false;
      if (!q) return true;
      return (
        app.label.toLowerCase().includes(q) ||
        app.packageName.toLowerCase().includes(q)
      );
    });

    // Pin selected apps to top, then sort by label
    list.sort((a, b) => {
      const aSel = selectedSet.has(a.packageName) ? 0 : 1;
      const bSel = selectedSet.has(b.packageName) ? 0 : 1;
      if (aSel !== bSel) return aSel - bSel;
      return a.label.localeCompare(b.label);
    });
    return list;
  }, [installedApps, packages, filterTab, search, selectedSet]);

  // Lazily fetch real Android app icons in small chunks so scroll stays responsive
  useEffect(() => {
    if (!androidBridge.available() || normalizedMode === "all" || filteredApps.length === 0) {
      return;
    }
    const missing = filteredApps
      .map((a) => a.packageName)
      .filter((pkg) => !requestedIconsRef.current.has(pkg))
      .slice(0, 36);
    if (missing.length === 0) return;

    let cancelled = false;
    const timer = window.setTimeout(() => {
      if (cancelled) return;
      for (const pkg of missing) requestedIconsRef.current.add(pkg);
      const fetched = androidBridge.getAppIcons(missing);
      if (!cancelled && Object.keys(fetched).length > 0) {
        setIconMap((prev) => ({ ...prev, ...fetched }));
      }
    }, 40);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [filteredApps, normalizedMode]);

  const togglePackage = (pkg: string) => {
    const next = new Set(packages);
    if (next.has(pkg)) next.delete(pkg);
    else next.add(pkg);
    onChangePackages(Array.from(next));
  };

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

  const modeDesc =
    normalizedMode === "whitelist"
      ? tr("routing.perAppModeWhitelistDesc")
      : normalizedMode === "blacklist"
        ? tr("routing.perAppModeBlacklistDesc")
        : tr("routing.perAppModeAllDesc");

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Smartphone className="h-4 w-4 text-primary" aria-hidden="true" />
            {tr("routing.perAppTitle")}
          </CardTitle>
          {normalizedMode !== "all" ? (
            <span className="badge-radius border border-primary/30 bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary mono-num">
              {tr("routing.perAppSelectedBadge", { count: packages.length })}
            </span>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* 3-Way Segmented Mode Selector */}
        <div className="grid grid-cols-3 gap-1.5 rounded-[8px] border border-border bg-muted/40 p-1">
          {(
            [
              { id: "all", label: tr("routing.perAppModeAllShort") },
              { id: "whitelist", label: tr("routing.perAppModeWhitelistShort") },
              { id: "blacklist", label: tr("routing.perAppModeBlacklistShort") },
            ] as const
          ).map((item) => {
            const active = normalizedMode === item.id;
            return (
              <button
                key={item.id}
                type="button"
                aria-pressed={active}
                onClick={() => onChangeMode(item.id)}
                className={[
                  "rounded-[6px] px-2 py-1.5 text-xs font-medium transition-colors text-center truncate",
                  active
                    ? "bg-primary text-primary-foreground shadow-xs"
                    : "text-muted-foreground hover:bg-background/70 hover:text-foreground",
                ].join(" ")}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        <p className="text-xs leading-relaxed text-muted-foreground">{modeDesc}</p>

        {normalizedMode !== "all" ? (
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
                onClick={loadApps}
                disabled={loadingApps}
                title={tr("routing.perAppRefresh")}
                aria-label={tr("routing.perAppRefresh")}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loadingApps ? "animate-spin" : ""}`} aria-hidden="true" />
              </Button>
            </div>

            {/* Filter Chips (horizontally scrollable on narrow screens) */}
            <div className="no-scrollbar flex items-center gap-1.5 overflow-x-auto pb-0.5">
              {(
                [
                  { id: "user", label: tr("routing.perAppTabUser"), count: counts.user },
                  { id: "all", label: tr("routing.perAppTabAll"), count: counts.all },
                  { id: "system", label: tr("routing.perAppTabSystem"), count: counts.system },
                  { id: "selected", label: tr("routing.perAppTabSelected"), count: counts.selected },
                ] as const
              ).map((tab) => {
                const active = filterTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    aria-pressed={active}
                    onClick={() => setFilterTab(tab.id)}
                    className={[
                      "inline-flex shrink-0 items-center gap-1 rounded-[6px] border px-2.5 py-1 text-xs font-medium whitespace-nowrap transition-colors",
                      active
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
            <div className="max-h-72 divide-y divide-border/70 overflow-y-auto rounded-[8px] border border-border bg-background/50">
              {filteredApps.length === 0 ? (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                  {tr("routing.perAppEmpty")}
                </div>
              ) : (
                filteredApps.map((app) => {
                  const checked = selectedSet.has(app.packageName);
                  const iconSrc = iconMap[app.packageName];
                  const initial = (app.label || app.packageName).trim().slice(0, 1).toUpperCase() || "?";
                  return (
                    <div
                      key={app.packageName}
                      onClick={() => togglePackage(app.packageName)}
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
                            <span className="truncate text-[13px] font-medium text-foreground">
                              {app.label}
                            </span>
                            {app.system ? (
                              <span className="shrink-0 rounded border border-border bg-muted px-1 py-0 text-[10px] text-muted-foreground">
                                {tr("routing.perAppSystemTag")}
                              </span>
                            ) : null}
                          </div>
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            {app.packageName}
                          </div>
                        </div>
                      </div>
                      <div
                        className="shrink-0"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Switch
                          checked={checked}
                          onCheckedChange={() => togglePackage(app.packageName)}
                          aria-label={app.label}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Collapsible Manual Package Editor */}
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
                    onChange={(e) => onChangePackages(splitPackages(e.target.value))}
                  />
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
