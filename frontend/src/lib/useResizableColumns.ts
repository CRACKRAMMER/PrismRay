// SPDX-License-Identifier: MPL-2.0

import type React from "react";
import { useCallback, useEffect, useRef, useState } from "react";

export interface ColumnWidthSpec {
  defaultWidth: number;
  minWidth: number;
  maxWidth?: number;
}

export type ColumnSpecMap<K extends string> = Record<K, ColumnWidthSpec>;

function storageKeyFor(tableId: string): string {
  return `prismray.colWidths.${tableId}`;
}

export function clampColumnWidth(width: number, spec: ColumnWidthSpec): number {
  const max = spec.maxWidth ?? 680;
  return Math.round(Math.min(max, Math.max(spec.minWidth, width)));
}

export function loadColumnWidths<K extends string>(
  tableId: string,
  specs: ColumnSpecMap<K>,
): Record<K, number> {
  const defaults = {} as Record<K, number>;
  (Object.keys(specs) as K[]).forEach((k) => {
    defaults[k] = specs[k].defaultWidth;
  });
  if (typeof window === "undefined") return defaults;
  try {
    const raw = window.localStorage.getItem(storageKeyFor(tableId));
    if (!raw) return defaults;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    (Object.keys(specs) as K[]).forEach((k) => {
      const val = Number(parsed[k]);
      if (Number.isFinite(val) && val > 0) {
        defaults[k] = clampColumnWidth(val, specs[k]);
      }
    });
  } catch {
    // Ignore malformed localStorage state.
  }
  return defaults;
}

/**
 * Hook providing draggable, persisted table column widths with double-click reset.
 */
export function useResizableColumns<K extends string>(
  tableId: string,
  specs: ColumnSpecMap<K>,
) {
  const specsRef = useRef(specs);
  specsRef.current = specs;

  const [widths, setWidths] = useState<Record<K, number>>(() => loadColumnWidths(tableId, specs));
  const [resizingCol, setResizingCol] = useState<K | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(storageKeyFor(tableId), JSON.stringify(widths));
    } catch {
      // Ignore storage write errors.
    }
  }, [tableId, widths]);

  const startResize = useCallback(
    (colKey: K, e: React.PointerEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.stopPropagation();
      const target = e.currentTarget;
      const startX = e.clientX;
      const spec = specsRef.current[colKey];
      const thEl = target.closest("th");
      const startWidth = thEl ? thEl.getBoundingClientRect().width : widths[colKey];

      try {
        target.setPointerCapture(e.pointerId);
      } catch {
        // Fallback for synthetic events in automated tests.
      }
      setResizingCol(colKey);
      document.body.classList.add("prismray-col-resizing");

      const onMove = (ev: PointerEvent) => {
        const next = clampColumnWidth(startWidth + (ev.clientX - startX), spec);
        setWidths((prev) => (prev[colKey] === next ? prev : { ...prev, [colKey]: next }));
      };

      const onEnd = () => {
        setResizingCol(null);
        document.body.classList.remove("prismray-col-resizing");
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onEnd);
        window.removeEventListener("pointercancel", onEnd);
      };

      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onEnd);
      window.addEventListener("pointercancel", onEnd);
    },
    [widths],
  );

  const resetColumn = useCallback((colKey: K) => {
    const spec = specsRef.current[colKey];
    setWidths((prev) => ({ ...prev, [colKey]: spec.defaultWidth }));
  }, []);

  const resetAllColumns = useCallback(() => {
    const next = {} as Record<K, number>;
    (Object.keys(specsRef.current) as K[]).forEach((k) => {
      next[k] = specsRef.current[k].defaultWidth;
    });
    setWidths(next);
  }, []);

  return {
    widths,
    resizingCol,
    startResize,
    resetColumn,
    resetAllColumns,
  };
}
