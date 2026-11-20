// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";

let hoverHintFallbackInstalled = false;

function ensureHoverHintFallback() {
  if (hoverHintFallbackInstalled || typeof document === "undefined") return;
  hoverHintFallbackInstalled = true;
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
            if (toggleEv.newState === "open" && target.classList.contains("hover-popover")) {
              target.popover = "auto";
            }
          },
          true,
        );
      }
    }
  } catch {
    // Ignore on legacy engines.
  }
}

export interface HoverPopoverProps {
  /** Trigger element (kept inline/block per className) */
  children: React.ReactNode;
  /** Rich content rendered inside the floating top-layer popover */
  content: React.ReactNode;
  /** Optional condition evaluated before opening (e.g. only when text overflows) */
  shouldOpen?: (triggerEl: HTMLElement) => boolean;
  /** Additional classes for trigger wrapper */
  className?: string;
  /** Max width class or inline maxWidth for popover */
  maxWidthPx?: number;
  /** Accessible label when trigger is interactive */
  ariaLabel?: string;
  /** Stop click propagation (useful inside selectable table rows) */
  stopPropagationOnTap?: boolean;
}

/**
 * Top-layer floating popover supporting desktop hover/focus AND touch press-hold/tap.
 * Never clipped by overflow-hidden cards, tables, or drawers.
 */
export function HoverPopover({
  children,
  content,
  shouldOpen,
  className = "",
  maxWidthPx = 320,
  ariaLabel,
  stopPropagationOnTap = false,
}: HoverPopoverProps) {
  const popId = `hp-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);
  const closeTimerRef = useRef<number | null>(null);
  const pressTimerRef = useRef<number | null>(null);
  const pinnedRef = useRef(false);
  const longPressedRef = useRef(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    ensureHoverHintFallback();
  }, []);

  const clearTimers = useCallback(() => {
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
    if (pressTimerRef.current !== null) {
      window.clearTimeout(pressTimerRef.current);
      pressTimerRef.current = null;
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
    const gap = 7;

    const popRect = pop.getBoundingClientRect();
    const popW = Math.min(popRect.width || maxWidthPx, vw - margin * 2);
    const popH = popRect.height || 64;

    let top = rect.top - popH - gap;
    if (top < margin) {
      top = Math.min(vh - popH - margin, rect.bottom + gap);
    }
    let left = rect.left + rect.width / 2 - popW / 2;
    left = Math.max(margin, Math.min(vw - popW - margin, left));

    pop.style.top = `${Math.round(top)}px`;
    pop.style.left = `${Math.round(left)}px`;
  }, [maxWidthPx]);

  const openPopover = useCallback(
    (pinned: boolean) => {
      const trigger = triggerRef.current;
      if (trigger && shouldOpen && !shouldOpen(trigger)) {
        return;
      }
      if (closeTimerRef.current !== null) {
        window.clearTimeout(closeTimerRef.current);
        closeTimerRef.current = null;
      }
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
    [positionPopover, shouldOpen],
  );

  const closePopover = useCallback(() => {
    clearTimers();
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
  }, [clearTimers]);

  const scheduleClose = useCallback(() => {
    if (pinnedRef.current) return;
    if (closeTimerRef.current !== null) window.clearTimeout(closeTimerRef.current);
    closeTimerRef.current = window.setTimeout(() => {
      closePopover();
    }, 140);
  }, [closePopover]);

  useEffect(() => {
    const pop = popRef.current;
    if (!pop) return;
    const onToggle = (ev: Event) => {
      const toggleEv = ev as Event & { newState?: string };
      const isOpen = toggleEv.newState === "open";
      setOpen(isOpen);
      if (isOpen) window.requestAnimationFrame(positionPopover);
      else pinnedRef.current = false;
    };
    pop.addEventListener("toggle", onToggle);
    return () => pop.removeEventListener("toggle", onToggle);
  }, [positionPopover]);

  useEffect(() => {
    if (!open) return;
    const onReposition = () => positionPopover();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") closePopover();
    };
    const onDocDown = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (t && (triggerRef.current?.contains(t) || popRef.current?.contains(t))) return;
      closePopover();
    };
    window.addEventListener("scroll", onReposition, true);
    window.addEventListener("resize", onReposition);
    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("pointerdown", onDocDown, true);
    return () => {
      window.removeEventListener("scroll", onReposition, true);
      window.removeEventListener("resize", onReposition);
      window.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("pointerdown", onDocDown, true);
    };
  }, [open, positionPopover, closePopover]);

  useEffect(() => () => clearTimers(), [clearTimers]);

  return (
    <>
      <span
        ref={triggerRef}
        tabIndex={0}
        aria-label={ariaLabel}
        aria-expanded={open}
        aria-controls={popId}
        onMouseEnter={() => openPopover(false)}
        onMouseLeave={scheduleClose}
        onFocus={() => openPopover(false)}
        onBlur={scheduleClose}
        onPointerDown={(e) => {
          longPressedRef.current = false;
          if (e.pointerType === "touch" || e.pointerType === "pen") {
            if (pressTimerRef.current !== null) window.clearTimeout(pressTimerRef.current);
            pressTimerRef.current = window.setTimeout(() => {
              longPressedRef.current = true;
              openPopover(true);
            }, 300);
          }
        }}
        onPointerUp={() => {
          if (pressTimerRef.current !== null) {
            window.clearTimeout(pressTimerRef.current);
            pressTimerRef.current = null;
          }
        }}
        onPointerCancel={() => {
          if (pressTimerRef.current !== null) {
            window.clearTimeout(pressTimerRef.current);
            pressTimerRef.current = null;
          }
        }}
        onClick={(e) => {
          if (stopPropagationOnTap) {
            e.stopPropagation();
          }
          if (longPressedRef.current) {
            longPressedRef.current = false;
            return;
          }
          if (stopPropagationOnTap) {
            if (open && pinnedRef.current) closePopover();
            else openPopover(true);
          }
        }}
        className={`outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-[4px] ${className}`}
      >
        {children}
      </span>
      <div
        ref={popRef}
        id={popId}
        role="tooltip"
        {...({ popover: "hint" } as Record<string, string>)}
        style={{ maxWidth: `min(${maxWidthPx}px, calc(100vw - 20px))` }}
        onMouseEnter={() => {
          if (closeTimerRef.current !== null) {
            window.clearTimeout(closeTimerRef.current);
            closeTimerRef.current = null;
          }
        }}
        onMouseLeave={scheduleClose}
        className="hover-popover"
      >
        {content}
      </div>
    </>
  );
}

export interface TruncateTipProps {
  /** Primary display text truncated to 1 line with ellipsis */
  text: string;
  /** Optional richer secondary content shown inside the popover (defaults to `text`) */
  detail?: React.ReactNode;
  /** Always allow opening popover even if text doesn't overflow (useful when `detail` adds extra context) */
  alwaysPopover?: boolean;
  /** Additional className for the single-line truncated container */
  className?: string;
}

/**
 * Strict single-line ellipsis text (`...`) that reveals the full string on hover,
 * keyboard focus, or touch press-hold without ever wrapping into multiple lines.
 */
export function TruncateTip({
  text,
  detail,
  alwaysPopover = false,
  className = "",
}: TruncateTipProps) {
  const shouldOpen = useCallback(
    (el: HTMLElement) => {
      if (alwaysPopover || detail !== undefined) return Boolean(text || detail);
      return el.scrollWidth > el.clientWidth + 1;
    },
    [alwaysPopover, detail, text],
  );

  return (
    <HoverPopover
      shouldOpen={shouldOpen}
      maxWidthPx={360}
      className={`block min-w-0 max-w-full truncate ${className}`}
      content={
        detail ?? (
          <div className="break-all font-normal text-popover-foreground">{text}</div>
        )
      }
    >
      {text}
    </HoverPopover>
  );
}
