// SPDX-License-Identifier: MPL-2.0

import { useEffect, useState } from "react";
import { AlertCircle, AlertTriangle, Check, CheckCircle2, Copy, X } from "lucide-react";
import { useAppStore } from "../store/appStore.ts";

async function copyTextSafe(text: string): Promise<boolean> {
  if (!text) return false;
  try {
    if (window.PrismRayAndroid?.copyToClipboard?.(text)) {
      return true;
    }
  } catch {
    // Fall through to web clipboard APIs.
  }
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall back to execCommand below (e.g. Android WebView / non-secure origin).
  }
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "");
    el.style.position = "fixed";
    el.style.opacity = "0";
    el.style.pointerEvents = "none";
    document.body.appendChild(el);
    el.select();
    el.setSelectionRange(0, text.length);
    const ok = document.execCommand("copy");
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

export function StatusToast() {
  const { notice, clearNotice, tr } = useAppStore();
  const [countdown, setCountdown] = useState<{ noticeId: number; remaining: number }>({
    noticeId: 0,
    remaining: 0,
  });
  const [paused, setPaused] = useState(false);
  const [copiedNoticeId, setCopiedNoticeId] = useState<number | null>(null);

  useEffect(() => {
    if (!notice) {
      setPaused(false);
      setCopiedNoticeId(null);
      return;
    }
    setCountdown({ noticeId: notice.id, remaining: Math.max(1, notice.durationSec) });
    setPaused(false);
    setCopiedNoticeId(null);
  }, [notice?.id, notice?.durationSec]);

  useEffect(() => {
    if (!notice || paused) return;
    if (countdown.noticeId === notice.id && countdown.remaining <= 0) {
      clearNotice();
      return;
    }
    const timer = window.setTimeout(() => {
      setCountdown((prev) => {
        const current = prev.noticeId === notice.id ? prev.remaining : Math.max(1, notice.durationSec);
        return { noticeId: notice.id, remaining: Math.max(0, current - 1) };
      });
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [notice, paused, countdown, clearNotice]);

  useEffect(() => {
    if (copiedNoticeId === null) return;
    const t = window.setTimeout(() => setCopiedNoticeId(null), 1500);
    return () => window.clearTimeout(t);
  }, [copiedNoticeId]);

  const remainingSec = notice
    ? countdown.noticeId === notice.id
      ? countdown.remaining
      : Math.max(1, notice.durationSec)
    : 0;
  const isError = notice?.tone === "error";
  const isWarning = notice?.tone === "warning";
  const canCopy = isError || isWarning;
  const isCopied = Boolean(canCopy && notice && copiedNoticeId === notice.id);
  const progressPct =
    notice && notice.durationSec > 0
      ? Math.max(0, Math.min(100, (remainingSec / notice.durationSec) * 100))
      : 0;

  const handleCopy = async () => {
    if (!canCopy || !notice?.message) return;
    const ok = await copyTextSafe(notice.message);
    if (ok) {
      setCopiedNoticeId(notice.id);
    }
  };

  return (
    <div
      role="region"
      aria-label={tr("toast.regionLabel")}
      className="pointer-events-none fixed right-3 bottom-[68px] z-50 md:right-4 md:bottom-5"
    >
      {notice ? (
        <div
          key={notice.id}
          role={isError || isWarning ? "alert" : "status"}
          aria-live={isError ? "assertive" : "polite"}
          title={canCopy ? tr("toast.clickToCopy") : undefined}
          onClick={canCopy ? () => void handleCopy() : undefined}
          onMouseEnter={() => setPaused(true)}
          onMouseLeave={() => setPaused(false)}
          onFocusCapture={() => setPaused(true)}
          onBlurCapture={(e) => {
            if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
              setPaused(false);
            }
          }}
          className={[
            "pointer-events-auto relative flex items-center gap-2 overflow-hidden rounded-lg border px-2.5 py-2 shadow-lg max-md:max-w-[min(260px,calc(100vw-24px))] md:max-w-md md:items-start md:gap-3 md:rounded-xl md:px-4 md:py-3 md:shadow-xl",
            canCopy ? "cursor-pointer transition-transform active:scale-[0.98]" : "",
            isError
              ? "border-destructive/40 bg-card/95 text-destructive backdrop-blur"
              : isWarning
                ? "border-amber-500/45 bg-card/95 text-amber-700 backdrop-blur dark:text-amber-300"
                : "border-primary/40 bg-card/95 text-foreground backdrop-blur",
          ].join(" ")}
        >
          {isCopied ? (
            <Check className="h-3.5 w-3.5 shrink-0 text-emerald-500 md:mt-0.5 md:h-5 md:w-5" aria-hidden="true" />
          ) : isError ? (
            <AlertCircle className="h-3.5 w-3.5 shrink-0 text-destructive md:mt-0.5 md:h-5 md:w-5" aria-hidden="true" />
          ) : isWarning ? (
            <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500 md:mt-0.5 md:h-5 md:w-5" aria-hidden="true" />
          ) : (
            <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-primary md:mt-0.5 md:h-5 md:w-5" aria-hidden="true" />
          )}

          <div className="min-w-0 flex-1 md:space-y-1">
            <p className="text-xs leading-snug break-words max-md:line-clamp-3 md:text-sm md:leading-relaxed">
              {notice.message}
            </p>
            {canCopy ? (
              <div className="flex items-center gap-2 text-[10px] font-medium tabular-nums text-muted-foreground md:text-[11px]">
                {isCopied ? (
                  <span className="text-emerald-600 dark:text-emerald-400">{tr("toast.copied")}</span>
                ) : (
                  <>
                    <span className="inline-flex items-center gap-1 opacity-75">
                      <Copy className="h-2.5 w-2.5 md:h-3 md:w-3" aria-hidden="true" />
                      {tr("toast.clickToCopy")}
                    </span>
                    <span className="hidden md:inline">·</span>
                    <span className="hidden md:inline">
                      {tr("toast.dismissIn", { sec: Math.max(1, remainingSec) })}
                    </span>
                  </>
                )}
              </div>
            ) : (
              <div className="hidden text-[11px] font-medium tabular-nums text-muted-foreground md:block">
                {tr("toast.dismissIn", { sec: Math.max(1, remainingSec) })}
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              clearNotice();
            }}
            aria-label={tr("action.close")}
            className="keep-icon-size inline-flex h-6 w-6 min-h-0 min-w-0 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:h-8 md:w-8 md:rounded-lg"
          >
            <X className="h-3.5 w-3.5 md:h-4 md:w-4" aria-hidden="true" />
          </button>

          <div
            aria-hidden="true"
            className={[
              "absolute inset-x-0 bottom-0 h-0.5 transition-[width] duration-1000 ease-linear",
              isError ? "bg-destructive/75" : isWarning ? "bg-amber-500/75" : "bg-primary/75",
            ].join(" ")}
            style={{ width: `${progressPct}%` }}
          />
        </div>
      ) : null}
    </div>
  );
}
