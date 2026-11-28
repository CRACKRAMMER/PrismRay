// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { CircleAlert } from "lucide-react";

let hintFallbackInstalled = false;

/**
 * Per modern-web-guidance (interest-triggered-tooltips):
 * Where `popover="hint"` is unsupported (Safari / WebKitGTK), switch toggletips
 * from `"hint"` to `"auto"` inside a capturing `beforetoggle` listener so click-opened
 * toggletips still light-dismiss on outside click and Escape.
 */
function ensureHintFallbackListener() {
  if (hintFallbackInstalled || typeof document === "undefined") return;
  hintFallbackInstalled = true;
  try {
    const probe = document.createElement("div") as HTMLElement & { popover?: string };
    if ("popover" in probe) {
      probe.popover = "hint";
      if (probe.popover !== "hint") {
        document.addEventListener(
          "beforetoggle",
          (ev: Event) => {
            const toggleEv = ev as Event & { newState?: string };
            const target = ev.target as (HTMLElement & { popover?: string }) | null;
            if (!target || target.getAttribute("popover") !== "hint") return;
            if (toggleEv.newState === "open" && target.id && document.querySelector(`[popovertarget="${CSS.escape(target.id)}"]`)) {
              target.popover = "auto";
            }
          },
          true,
        );
      }
    }
  } catch {
    // Ignore on legacy engines without Popover API.
  }
}

export interface HelpTipProps {
  /** Explanatory text displayed inside the floating popover on hover, focus, or click */
  text: React.ReactNode;
  /** Accessible label for the trigger button */
  ariaLabel?: string;
  /** Optional additional class for the wrapper */
  className?: string;
  /** Visual tone */
  tone?: "muted" | "warning" | "primary";
}

/**
 * Compact `!` toggletip component replacing verbose inline helper paragraphs.
 * Supports hover, keyboard focus, click toggle, Escape dismiss, and WCAG 1.4.13
 * hoverable persistence, rendered in the browser top-layer popover stack so it is
 * never clipped by cards, tables, or slide-over drawers.
 */
export function HelpTip({
  text,
  ariaLabel = "Info",
  className = "",
  tone = "muted",
}: HelpTipProps) {
  const tipId = `ht-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | null>(null);
  const pinnedRef = useRef(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    ensureHintFallbackListener();
  }, []);

  const clearCloseTimer = useCallback(() => {
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }, []);

  const positionPopover = useCallback(() => {
    const trigger = triggerRef.current;
    const pop = popRef.current;
    if (!trigger || !pop) return;

    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const margin = 10;
    const gap = 8;

    // Measure popover dimensions cleanly while visible
    const popRect = pop.getBoundingClientRect();
    const popW = Math.min(popRect.width || 272, vw - margin * 2);
    const popH = popRect.height || 72;

    // Prefer above trigger if room, otherwise below
    let top = rect.top - popH - gap;
    if (top < margin) {
      top = Math.min(vh - popH - margin, rect.bottom + gap);
    }
    let left = rect.left + rect.width / 2 - popW / 2;
    left = Math.max(margin, Math.min(vw - popW - margin, left));

    pop.style.top = `${Math.round(top)}px`;
    pop.style.left = `${Math.round(left)}px`;
  }, []);

  const openPopover = useCallback(
    (pinned: boolean) => {
      clearCloseTimer();
      if (pinned) pinnedRef.current = true;
      const pop = popRef.current as (HTMLDivElement & { showPopover?: () => void }) | null;
      if (!pop) return;
      try {
        if (typeof pop.showPopover === "function") {
          if (!pop.matches(":popover-open")) {
            pop.showPopover();
          }
        } else {
          pop.setAttribute("data-open", "true");
        }
      } catch {
        pop.setAttribute("data-open", "true");
      }
      setOpen(true);
      window.requestAnimationFrame(positionPopover);
    },
    [clearCloseTimer, positionPopover],
  );

  const closePopover = useCallback(() => {
    clearCloseTimer();
    pinnedRef.current = false;
    const pop = popRef.current as (HTMLDivElement & { hidePopover?: () => void }) | null;
    if (!pop) return;
    try {
      if (typeof pop.hidePopover === "function") {
        if (pop.matches(":popover-open")) {
          pop.hidePopover();
        }
      } else {
        pop.removeAttribute("data-open");
      }
    } catch {
      pop.removeAttribute("data-open");
    }
    setOpen(false);
  }, [clearCloseTimer]);

  const scheduleClose = useCallback(() => {
    if (pinnedRef.current) return;
    clearCloseTimer();
    closeTimerRef.current = window.setTimeout(() => {
      closePopover();
    }, 150);
  }, [clearCloseTimer, closePopover]);

  useEffect(() => {
    const pop = popRef.current;
    if (!pop) return;
    const onToggle = (ev: Event) => {
      const toggleEv = ev as Event & { newState?: string };
      const isOpen = toggleEv.newState === "open";
      setOpen(isOpen);
      if (isOpen) {
        window.requestAnimationFrame(positionPopover);
      } else {
        pinnedRef.current = false;
      }
    };
    pop.addEventListener("toggle", onToggle);
    return () => pop.removeEventListener("toggle", onToggle);
  }, [positionPopover]);

  useEffect(() => {
    if (!open) return;
    const onScrollOrResize = () => positionPopover();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closePopover();
    };
    const onDocPointerDown = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (t && (triggerRef.current?.contains(t) || popRef.current?.contains(t))) return;
      closePopover();
    };
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onDocPointerDown, true);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
      window.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onDocPointerDown, true);
    };
  }, [open, positionPopover, closePopover]);

  useEffect(() => () => clearCloseTimer(), [clearCloseTimer]);

  const toneClass =
    tone === "warning"
      ? "text-amber-500/85 hover:text-amber-500"
      : tone === "primary"
        ? "text-primary/85 hover:text-primary"
        : "text-muted-foreground/75 hover:text-primary";

  return (
    <span className={`inline-flex items-center align-middle ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-controls={tipId}
        {...({
          interestfor: tipId,
          popovertarget: tipId,
          popovertargetaction: "show",
        } as Record<string, string>)}
        onMouseEnter={() => openPopover(false)}
        onMouseLeave={scheduleClose}
        onFocus={() => openPopover(false)}
        onBlur={scheduleClose}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          if (open && pinnedRef.current) {
            closePopover();
          } else {
            openPopover(true);
          }
        }}
        className={`helptip-trigger inline-flex h-[18px] w-[18px] min-h-0 shrink-0 items-center justify-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${toneClass}`}
      >
        <CircleAlert className="h-[14px] w-[14px]" aria-hidden="true" />
      </button>
      <div
        ref={popRef}
        id={tipId}
        role="tooltip"
        {...({ popover: "hint" } as Record<string, string>)}
        onMouseEnter={clearCloseTimer}
        onMouseLeave={scheduleClose}
        className="helptip-popover"
      >
        {text}
      </div>
    </span>
  );
}
