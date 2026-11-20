// SPDX-License-Identifier: MPL-2.0

import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  AlertCircle,
  ArrowUpCircle,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  Loader2,
  RefreshCw,
} from "lucide-react";
import {
  api,
  formatApiError,
  isAndroidClient,
  isDesktop,
  type AppUpdateCheckResult,
} from "../lib/api.ts";
import { formatBytes } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";

export const AUTO_UPDATE_CHECK_STORAGE_KEY = "prismray.autoUpdateCheck";
export const LAST_UPDATE_CHECK_TS_KEY = "prismray.lastUpdateCheckTs";
export const LAST_UPDATE_RESULT_KEY = "prismray.lastUpdateResult";
export const APP_UPDATE_BADGE_EVENT = "prismray-app-update-badge";
export const TRIGGER_UPDATE_CHECK_EVENT = "prismray-trigger-update-check";

export function isAutoUpdateCheckEnabled(): boolean {
  if (typeof window === "undefined") return true;
  try {
    const raw = window.localStorage.getItem(AUTO_UPDATE_CHECK_STORAGE_KEY);
    return raw !== "0";
  } catch {
    return true;
  }
}

export function loadCachedUpdateResult(): AppUpdateCheckResult | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(LAST_UPDATE_RESULT_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as AppUpdateCheckResult;
  } catch {
    return null;
  }
}

export function saveCachedUpdateResult(result: AppUpdateCheckResult): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(LAST_UPDATE_RESULT_KEY, JSON.stringify(result));
    window.localStorage.setItem(LAST_UPDATE_CHECK_TS_KEY, String(Date.now()));
  } catch {
    // Ignore storage quota errors.
  }
  window.dispatchEvent(
    new CustomEvent(APP_UPDATE_BADGE_EVENT, {
      detail: {
        hasUpdate: Boolean(result.has_update),
        latestVersion: result.latest_version || "",
      },
    })
  );
}

async function openExternalLink(url: string): Promise<void> {
  if (!url) return;
  if (isDesktop) {
    try {
      await openUrl(url);
      return;
    } catch {
      // Fallback to window.open.
    }
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

interface TauriPendingUpdate {
  version: string;
  body?: string;
  downloadAndInstall: (onEvent?: (event: { event: string; data?: { contentLength?: number; chunkLength?: number } }) => void) => Promise<void>;
}

export function AppUpdateCard() {
  const { tr, notify } = useAppStore();
  const [checking, setChecking] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installProgress, setInstallProgress] = useState<number | null>(null);
  const [includePrerelease, setIncludePrerelease] = useState(false);
  const [autoCheck, setAutoCheck] = useState<boolean>(() => isAutoUpdateCheckEnabled());
  const [result, setResult] = useState<AppUpdateCheckResult | null>(() => loadCachedUpdateResult());
  const [tauriUpdate, setTauriUpdate] = useState<TauriPendingUpdate | null>(null);

  const runCheck = useCallback(
    async (silent = false) => {
      setChecking(true);
      setTauriUpdate(null);
      try {
        // 1. Check signed Tauri desktop updater first if configured.
        if (isDesktop && !isAndroidClient()) {
          try {
            const updaterMod = await import("@tauri-apps/plugin-updater");
            const found = await updaterMod.check();
            if (found && found.available) {
              setTauriUpdate({
                version: found.version,
                body: found.body,
                downloadAndInstall: (cb) => found.downloadAndInstall(cb as never),
              });
            }
          } catch {
            // Updater endpoint/pubkey may not be configured; fall back seamlessly to GitHub Releases.
          }
        }

        // 2. Query backend /api/app/update-check (GitHub Releases with proxy fallback & platform matching).
        const data = await api.checkAppUpdate(includePrerelease);
        setResult(data);
        saveCachedUpdateResult(data);

        if (!silent) {
          if (data.status === "update_available") {
            notify(tr("update.available", { version: data.latest_version || "" }));
          } else if (data.status === "up_to_date") {
            notify(tr("update.upToDate"));
          } else if (data.status === "no_published_release") {
            notify(tr("update.noRelease"));
          } else if (data.status === "error") {
            notify(data.message || tr("update.failed"), "error");
          }
        }
      } catch (err) {
        if (!silent) {
          notify(formatApiError(err), "error");
        }
      } finally {
        setChecking(false);
      }
    },
    [includePrerelease, notify, tr]
  );

  useEffect(() => {
    const onTrigger = () => {
      void runCheck(false);
    };
    window.addEventListener(TRIGGER_UPDATE_CHECK_EVENT, onTrigger);
    return () => window.removeEventListener(TRIGGER_UPDATE_CHECK_EVENT, onTrigger);
  }, [runCheck]);

  const toggleAutoCheck = (next: boolean) => {
    setAutoCheck(next);
    try {
      window.localStorage.setItem(AUTO_UPDATE_CHECK_STORAGE_KEY, next ? "1" : "0");
    } catch {
      // Ignore storage errors.
    }
  };

  const handleInstallTauriUpdate = async () => {
    if (!tauriUpdate) return;
    setInstalling(true);
    setInstallProgress(0);
    try {
      await invoke("prepare_update");
      let total = 0;
      let downloaded = 0;
      await tauriUpdate.downloadAndInstall((evt) => {
        if (evt.event === "Started" && evt.data?.contentLength) {
          total = evt.data.contentLength;
        } else if (evt.event === "Progress" && evt.data?.chunkLength) {
          downloaded += evt.data.chunkLength;
          if (total > 0) {
            setInstallProgress(Math.min(100, Math.round((downloaded / total) * 100)));
          }
        } else if (evt.event === "Finished") {
          setInstallProgress(100);
        }
      });
    } catch (err) {
      notify(formatApiError(err), "error");
      setInstalling(false);
      setInstallProgress(null);
    }
  };

  const handleCopyCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      notify(tr("update.copiedCmd"));
    } catch {
      // Ignore clipboard denial.
    }
  };

  const effectiveHasUpdate = Boolean(tauriUpdate || result?.has_update);
  const effectiveLatest = tauriUpdate?.version || result?.latest_version || "";
  const effectiveNotes = tauriUpdate?.body || result?.release_notes || "";

  return (
    <div className="space-y-3 rounded-[10px] border border-border bg-muted/30 p-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <ArrowUpCircle className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
          <span className="font-semibold text-foreground">{tr("update.title")}</span>
          <span className="rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[11px] text-foreground">
            v{result?.current_version || "1.0.0"}
          </span>
          {result?.platform ? (
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {result.mode || "desktop"} · {result.platform}
            </span>
          ) : null}
          {effectiveHasUpdate ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-primary/40 bg-primary/15 px-2 py-0.5 text-[11px] font-medium text-primary">
              <ArrowUpCircle className="h-3 w-3" aria-hidden="true" />
              {tr("update.available", { version: effectiveLatest })}
            </span>
          ) : result?.status === "up_to_date" ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
              {tr("update.upToDate")}
            </span>
          ) : result?.status === "no_published_release" ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-background px-2 py-0.5 text-[11px] text-muted-foreground">
              {tr("update.noRelease")}
            </span>
          ) : result?.status === "error" ? (
            <span className="inline-flex items-center gap-1 rounded-full border border-destructive/30 bg-destructive/10 px-2 py-0.5 text-[11px] text-destructive">
              <AlertCircle className="h-3 w-3" aria-hidden="true" />
              {tr("update.failed")}
            </span>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {tauriUpdate ? (
            <Button type="button" size="sm" disabled={installing} onClick={() => void handleInstallTauriUpdate()}>
              {installing ? (
                <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              )}
              {installing
                ? `${tr("update.installing")}${installProgress !== null ? ` ${installProgress}%` : ""}`
                : tr("update.installNow")}
            </Button>
          ) : null}

          {effectiveHasUpdate && result?.recommended_asset ? (
            <Button
              type="button"
              size="sm"
              variant={tauriUpdate ? "outline" : "default"}
              onClick={() => void openExternalLink(result.recommended_asset!.download_url)}
            >
              <Download className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("update.downloadInstaller")}
              {result.recommended_asset.size > 0 ? ` (${formatBytes(result.recommended_asset.size)})` : ""}
            </Button>
          ) : null}

          {result?.release_url ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => void openExternalLink(result.release_url!)}
            >
              <ExternalLink className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("update.openRelease")}
            </Button>
          ) : null}

          <Button type="button" size="sm" variant="outline" disabled={checking} onClick={() => void runCheck(false)}>
            <RefreshCw className={`mr-1.5 h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} aria-hidden="true" />
            {checking ? tr("update.checking") : tr("update.checkBtn")}
          </Button>
        </div>
      </div>

      {/* Options Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-muted-foreground">
        <div className="flex flex-wrap items-center gap-4">
          <label className="inline-flex cursor-pointer items-center gap-1.5">
            <input
              type="checkbox"
              className="accent-primary"
              checked={autoCheck}
              onChange={(e) => toggleAutoCheck(e.target.checked)}
            />
            <span>{tr("update.autoCheck")}</span>
          </label>
          <label className="inline-flex cursor-pointer items-center gap-1.5">
            <input
              type="checkbox"
              className="accent-primary"
              checked={includePrerelease}
              onChange={(e) => setIncludePrerelease(e.target.checked)}
            />
            <span>{tr("update.includePrerelease")}</span>
          </label>
        </div>
        {result?.checked_at ? (
          <span className="font-mono">
            {tr("update.lastChecked", { time: new Date(result.checked_at).toLocaleString() })}
          </span>
        ) : null}
      </div>

      {result?.status === "no_published_release" ? (
        <p className="text-[11px] text-muted-foreground">{tr("update.noReleaseHint")}</p>
      ) : null}

      {result?.status === "error" && result.message ? (
        <div className="rounded-[6px] border border-destructive/30 bg-destructive/10 px-2.5 py-1.5 font-mono text-[11px] text-destructive">
          {result.message}
        </div>
      ) : null}

      {result?.install_hint ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-[6px] border border-border bg-background/80 px-2.5 py-1.5 font-mono text-[11px]">
          <span className="truncate text-foreground">{result.install_hint}</span>
          <button
            type="button"
            onClick={() => void handleCopyCommand(result.install_hint!)}
            className="inline-flex shrink-0 items-center gap-1 rounded border border-border px-2 py-0.5 text-[10px] text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <Copy className="h-3 w-3" aria-hidden="true" />
            {tr("action.copy")}
          </button>
        </div>
      ) : null}

      {effectiveHasUpdate && effectiveNotes ? (
        <details className="rounded-[6px] border border-border bg-background/70 p-2.5" open>
          <summary className="cursor-pointer select-none text-[11px] font-medium text-foreground">
            {tr("update.releaseNotes")} ({result?.release_name || `v${effectiveLatest}`})
          </summary>
          <pre className="mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap break-words font-sans text-[11px] leading-relaxed text-muted-foreground">
            {effectiveNotes}
          </pre>
        </details>
      ) : null}
    </div>
  );
}
