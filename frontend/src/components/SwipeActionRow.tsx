// SPDX-License-Identifier: MPL-2.0

import React, { useRef, useState } from "react";
import { MoreHorizontal } from "lucide-react";
import { useIsMobile } from "./ContextInspector.tsx";
import { useAppStore } from "../store/appStore.ts";

export interface SwipeAction {
  key: string;
  label: string;
  icon: React.ReactNode;
  tone?: "default" | "primary" | "danger";
  onClick: () => void;
}

/**
 * Pure CSS Scroll Snap swipe-to-reveal wrapper for mobile (<768px) list rows.
 * Renders children directly on PC (>=768px), and provides both touch left-swipe and an
 * accessible toggle button (WCAG 2.5.1 pointer gesture alternative) on mobile.
 */
export function SwipeActionRow({
  actions,
  children,
  className = "",
}: {
  actions: SwipeAction[];
  children: React.ReactNode;
  className?: string;
}) {
  const { tr } = useAppStore();
  const isMobile = useIsMobile();
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const [expanded, setExpanded] = useState(false);

  if (!isMobile || actions.length === 0) {
    return <div className={className}>{children}</div>;
  }

  const toggleReveal = (e: React.MouseEvent) => {
    e.stopPropagation();
    const el = scrollerRef.current;
    if (!el) return;
    const nextLeft = expanded ? 0 : el.scrollWidth;
    el.scrollTo({ left: nextLeft, behavior: "smooth" });
    setExpanded(!expanded);
  };

  const resetScroll = () => {
    const el = scrollerRef.current;
    if (el) el.scrollTo({ left: 0, behavior: "smooth" });
    setExpanded(false);
  };

  return (
    <div
      ref={scrollerRef}
      onScroll={() => {
        const el = scrollerRef.current;
        if (!el) return;
        const openNow = el.scrollLeft > 16;
        if (openNow !== expanded) setExpanded(openNow);
      }}
      className={`SwipeReveal ${className}`}
    >
      <div className="SwipeReveal-content flex items-center gap-1 min-w-0">
        <div className="flex-1 min-w-0">{children}</div>
        <button
          type="button"
          onClick={toggleReveal}
          aria-expanded={expanded}
          aria-label={tr("mobile.actions")}
          className="shrink-0 min-h-12 min-w-10 inline-flex items-center justify-center text-muted-foreground hover:text-foreground px-1.5"
        >
          <MoreHorizontal className="w-4 h-4" />
        </button>
      </div>
      <div className="SwipeReveal-panel bg-muted/95 border-l border-border">
        {actions.map((act) => {
          const toneCls =
            act.tone === "danger"
              ? "bg-destructive text-destructive-foreground"
              : act.tone === "primary"
                ? "bg-primary text-primary-foreground"
                : "bg-secondary text-secondary-foreground";
          return (
            <button
              key={act.key}
              type="button"
              tabIndex={expanded ? 0 : -1}
              onClick={(e) => {
                e.stopPropagation();
                resetScroll();
                act.onClick();
              }}
              aria-label={act.label}
              title={act.label}
              className={`min-h-12 min-w-[56px] px-2.5 flex flex-col items-center justify-center gap-0.5 text-[11px] font-medium border-r border-border/50 last:border-r-0 ${toneCls}`}
            >
              {act.icon}
              <span className="truncate max-w-[56px]">{act.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
