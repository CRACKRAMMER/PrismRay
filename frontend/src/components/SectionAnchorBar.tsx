// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Compass } from "lucide-react";

export interface AnchorSectionItem {
  id: string;
  label: string;
}

interface SectionAnchorBarProps {
  ariaLabel: string;
  items: AnchorSectionItem[];
  embedded?: boolean;
}

export function SectionAnchorBar({ ariaLabel, items, embedded = false }: SectionAnchorBarProps) {
  const [activeId, setActiveId] = useState<string>(items[0]?.id || "");
  const [canScrollLeft, setCanScrollLeft] = useState(false);
  const [canScrollRight, setCanScrollRight] = useState(false);
  const [dragging, setDragging] = useState(false);

  const navRef = useRef<HTMLElement | null>(null);
  const dragStateRef = useRef<{
    active: boolean;
    pointerId: number;
    startX: number;
    startScrollLeft: number;
    moved: boolean;
  }>({
    active: false,
    pointerId: -1,
    startX: 0,
    startScrollLeft: 0,
    moved: false,
  });
  const suppressClickUntilRef = useRef<number>(0);

  const idsKey = items.map((i) => i.id).join("|");

  const updateScrollBounds = useCallback(() => {
    const el = navRef.current;
    if (!el) {
      setCanScrollLeft(false);
      setCanScrollRight(false);
      return;
    }
    const maxScroll = el.scrollWidth - el.clientWidth;
    setCanScrollLeft(el.scrollLeft > 2);
    setCanScrollRight(maxScroll - el.scrollLeft > 2);
  }, []);

  useEffect(() => {
    const el = navRef.current;
    if (!el) return;
    updateScrollBounds();

    const onScroll = () => updateScrollBounds();
    const onWheel = (event: WheelEvent) => {
      if (el.scrollWidth <= el.clientWidth + 1) return;
      let delta = Math.abs(event.deltaX) > Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
      if (event.deltaMode === 1) {
        delta *= 32;
      } else if (event.deltaMode === 2) {
        delta *= el.clientWidth * 0.85;
      }
      if (Math.abs(delta) < 0.01) return;
      const maxScroll = el.scrollWidth - el.clientWidth;
      const next = Math.max(0, Math.min(maxScroll, el.scrollLeft + delta));
      if (next !== el.scrollLeft) {
        event.preventDefault();
        event.stopPropagation();
        el.scrollLeft = next;
        updateScrollBounds();
      } else if (event.shiftKey) {
        // Keep Shift+Wheel from bubbling into vertical scroll while cursor rests on the bar.
        event.preventDefault();
        event.stopPropagation();
      }
    };

    el.addEventListener("scroll", onScroll, { passive: true });
    el.addEventListener("wheel", onWheel, { passive: false });

    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(() => updateScrollBounds());
      ro.observe(el);
    }
    window.addEventListener("resize", updateScrollBounds);

    return () => {
      el.removeEventListener("scroll", onScroll);
      el.removeEventListener("wheel", onWheel);
      ro?.disconnect();
      window.removeEventListener("resize", updateScrollBounds);
    };
  }, [idsKey, updateScrollBounds]);

  useEffect(() => {
    if (items.length === 0) return;
    setActiveId((prev) => (items.some((i) => i.id === prev) ? prev : items[0].id));

    const scrollContainer = document.getElementById("prismray-scroll-root");
    const overflowY = scrollContainer ? window.getComputedStyle(scrollContainer).overflowY : "";
    const observerRoot =
      overflowY === "auto" || overflowY === "scroll" ? scrollContainer : null;

    const elements = items
      .map((item) => document.getElementById(item.id))
      .filter((el): el is HTMLElement => el !== null);
    if (elements.length === 0 || typeof IntersectionObserver === "undefined") return;

    const visibleMap = new Map<string, number>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            visibleMap.set(entry.target.id, entry.boundingClientRect.top);
          } else {
            visibleMap.delete(entry.target.id);
          }
        }
        if (visibleMap.size > 0) {
          const sorted = Array.from(visibleMap.entries()).sort((a, b) => Math.abs(a[1]) - Math.abs(b[1]));
          setActiveId(sorted[0][0]);
        }
      },
      {
        root: observerRoot,
        rootMargin: "-15% 0px -65% 0px",
        threshold: 0,
      },
    );

    elements.forEach((el) => observer.observe(el));
    return () => observer.disconnect();
  }, [idsKey]);

  const handlePointerDown = (e: React.PointerEvent<HTMLElement>) => {
    // Let native touch momentum handle touch pointers; enable click-and-drag for mouse/pen.
    if (e.pointerType === "touch" || e.button !== 0) return;
    const el = navRef.current;
    if (!el || el.scrollWidth <= el.clientWidth + 1) return;

    dragStateRef.current = {
      active: true,
      pointerId: e.pointerId,
      startX: e.clientX,
      startScrollLeft: el.scrollLeft,
      moved: false,
    };

    const onMove = (ev: PointerEvent) => {
      const state = dragStateRef.current;
      if (!state.active || ev.pointerId !== state.pointerId) return;
      const dx = ev.clientX - state.startX;
      if (!state.moved && Math.abs(dx) >= 5) {
        state.moved = true;
        setDragging(true);
      }
      if (state.moved) {
        ev.preventDefault();
        el.scrollLeft = state.startScrollLeft - dx;
        updateScrollBounds();
      }
    };

    const onEnd = (ev: PointerEvent) => {
      const state = dragStateRef.current;
      if (ev.pointerId !== state.pointerId) return;
      if (state.moved) {
        suppressClickUntilRef.current = Date.now() + 250;
      }
      state.active = false;
      state.moved = false;
      setDragging(false);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onEnd);
      window.removeEventListener("pointercancel", onEnd);
    };

    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onEnd);
    window.addEventListener("pointercancel", onEnd);
  };

  const scrollByStep = (direction: -1 | 1) => {
    const el = navRef.current;
    if (!el) return;
    const step = Math.max(140, Math.round(el.clientWidth * 0.55));
    el.scrollBy({ left: direction * step, behavior: "smooth" });
  };

  const handleJump = (e: React.MouseEvent<HTMLAnchorElement>, id: string) => {
    e.preventDefault();
    if (Date.now() < suppressClickUntilRef.current) {
      return;
    }
    setActiveId(id);
    const target = document.getElementById(id);
    if (!target) return;
    const rawMargin = parseFloat(window.getComputedStyle(target).scrollMarginTop || "0");
    const headerOffset = Number.isFinite(rawMargin) && rawMargin > 0 ? rawMargin : 96;
    const scrollRoot = document.getElementById("prismray-scroll-root");
    if (scrollRoot && scrollRoot.scrollHeight > scrollRoot.clientHeight + 2) {
      const rootRect = scrollRoot.getBoundingClientRect();
      const targetRect = target.getBoundingClientRect();
      const nextTop = Math.max(0, scrollRoot.scrollTop + (targetRect.top - rootRect.top) - headerOffset);
      scrollRoot.scrollTo({ top: nextTop, behavior: "smooth" });
    } else {
      const nextTop = Math.max(0, window.scrollY + target.getBoundingClientRect().top - headerOffset);
      window.scrollTo({ top: nextTop, behavior: "smooth" });
    }
    target.focus({ preventScroll: true });
  };

  if (items.length === 0) return null;

  const isScrollable = canScrollLeft || canScrollRight;
  const navCursorClass = isScrollable
    ? dragging
      ? "cursor-grabbing select-none"
      : "cursor-grab select-none"
    : "";

  const scrollArrows = (
    <>
      {canScrollLeft ? (
        <button
          type="button"
          tabIndex={-1}
          aria-label="Scroll left"
          onClick={() => scrollByStep(-1)}
          className="keep-icon-size hidden md:inline-flex h-7 w-7 min-h-0 min-w-0 shrink-0 items-center justify-center rounded-md border border-border/70 bg-background/90 text-muted-foreground shadow-xs transition-colors hover:bg-muted hover:text-foreground"
        >
          <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ) : null}
      {canScrollRight ? (
        <button
          type="button"
          tabIndex={-1}
          aria-label="Scroll right"
          onClick={() => scrollByStep(1)}
          className="keep-icon-size hidden md:inline-flex h-7 w-7 min-h-0 min-w-0 shrink-0 items-center justify-center rounded-md border border-border/70 bg-background/90 text-muted-foreground shadow-xs transition-colors hover:bg-muted hover:text-foreground"
        >
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ) : null}
    </>
  );

  if (embedded) {
    return (
      <div className="flex min-w-0 items-center gap-1">
        {canScrollLeft ? (
          <button
            type="button"
            tabIndex={-1}
            aria-label="Scroll left"
            onClick={() => scrollByStep(-1)}
            className="keep-icon-size hidden md:inline-flex h-6 w-6 min-h-0 min-w-0 shrink-0 items-center justify-center rounded-md border border-border/70 bg-background/90 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        ) : null}
        <nav
          ref={navRef}
          aria-label={ariaLabel}
          onPointerDown={handlePointerDown}
          className={`anchor-spy-nav no-scrollbar flex min-w-0 flex-1 flex-nowrap items-center gap-1.5 overflow-x-auto py-0.5 ${navCursorClass}`}
        >
          {items.map((item) => {
            const active = activeId === item.id;
            return (
              <a
                key={item.id}
                href={`#${item.id}`}
                draggable={false}
                onDragStart={(e) => e.preventDefault()}
                onClick={(e) => handleJump(e, item.id)}
                aria-current={active ? "location" : undefined}
                className={`anchor-spy-link inline-flex shrink-0 items-center whitespace-nowrap rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors max-md:min-h-[34px] md:min-h-0 ${
                  active
                    ? "target-current border-primary bg-accent text-accent-foreground font-semibold"
                    : "border-border/70 bg-background/80 text-muted-foreground hover:bg-muted hover:text-foreground"
                }`}
              >
                {item.label}
              </a>
            );
          })}
        </nav>
        {canScrollRight ? (
          <button
            type="button"
            tabIndex={-1}
            aria-label="Scroll right"
            onClick={() => scrollByStep(1)}
            className="keep-icon-size hidden md:inline-flex h-6 w-6 min-h-0 min-w-0 shrink-0 items-center justify-center rounded-md border border-border/70 bg-background/90 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <div className="prism-glass-bar md:sticky md:top-0 z-20 flex min-w-0 items-center gap-1.5 rounded-xl border border-border bg-card px-2.5 py-1.5 md:px-3 md:py-2 shadow-xs">
      <Compass className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
      <nav
        ref={navRef}
        aria-label={ariaLabel}
        onPointerDown={handlePointerDown}
        className={`anchor-spy-nav no-scrollbar flex min-w-0 flex-1 flex-nowrap items-center gap-1.5 overflow-x-auto ${navCursorClass}`}
      >
        {items.map((item) => {
          const isCurrent = activeId === item.id;
          return (
            <a
              key={item.id}
              href={`#${item.id}`}
              draggable={false}
              onDragStart={(e) => e.preventDefault()}
              aria-current={isCurrent ? "true" : undefined}
              onClick={(e) => handleJump(e, item.id)}
              className={[
                "anchor-spy-link inline-flex shrink-0 items-center rounded-lg border px-2.5 py-1 text-xs whitespace-nowrap transition-colors max-md:min-h-[34px] md:min-h-8",
                isCurrent
                  ? "target-current border-primary bg-primary/15 font-semibold text-primary"
                  : "border-transparent bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground",
              ].join(" ")}
            >
              {item.label}
            </a>
          );
        })}
      </nav>
      {isScrollable ? <div className="hidden md:flex shrink-0 items-center gap-1">{scrollArrows}</div> : null}
    </div>
  );
}
