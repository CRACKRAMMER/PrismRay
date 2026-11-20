// SPDX-License-Identifier: MPL-2.0

import { useEffect } from "react";

function isHorizontallyScrollable(el: HTMLElement): boolean {
  if (el.scrollWidth <= el.clientWidth + 1) return false;
  const style = window.getComputedStyle(el);
  const ox = style.overflowX;
  return ox === "auto" || ox === "scroll" || ox === "overlay";
}

function findHorizontalScrollContainer(start: EventTarget | null): HTMLElement | null {
  let node = start instanceof HTMLElement ? start : start instanceof Node ? start.parentElement : null;
  while (node && node !== document.documentElement) {
    if (isHorizontallyScrollable(node)) {
      return node;
    }
    node = node.parentElement;
  }
  return null;
}

/**
 * Enables smooth `Shift + Mouse Wheel` horizontal scrolling across all horizontally
 * scrollable tables, tab bars, and filter strips (especially on Linux/WebKitGTK where
 * Shift+Wheel may not translate vertical wheel deltas into horizontal scroll).
 */
export function useShiftHorizontalScroll(): void {
  useEffect(() => {
    if (typeof window === "undefined") return;

    const onWheel = (event: WheelEvent) => {
      if (!event.shiftKey) return;
      // If the OS/browser already delivered native horizontal deltaX with zero deltaY, let it handle naturally.
      if (Math.abs(event.deltaY) < 0.01 && Math.abs(event.deltaX) > 0) return;

      const container = findHorizontalScrollContainer(event.target);
      if (!container) return;

      let delta = event.deltaY !== 0 ? event.deltaY : event.deltaX;
      if (event.deltaMode === 1) {
        // DOM_DELTA_LINE
        delta *= 32;
      } else if (event.deltaMode === 2) {
        // DOM_DELTA_PAGE
        delta *= container.clientWidth * 0.85;
      }
      if (delta === 0) return;

      const maxScrollLeft = container.scrollWidth - container.clientWidth;
      const atStart = container.scrollLeft <= 0 && delta < 0;
      const atEnd = container.scrollLeft >= maxScrollLeft - 1 && delta > 0;
      if (atStart || atEnd) return;

      event.preventDefault();
      container.scrollLeft = Math.max(0, Math.min(maxScrollLeft, container.scrollLeft + delta));
    };

    window.addEventListener("wheel", onWheel, { passive: false });
    return () => window.removeEventListener("wheel", onWheel);
  }, []);
}
