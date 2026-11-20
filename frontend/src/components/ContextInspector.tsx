// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { useAppStore } from "../store/appStore.ts";

const DRAWER_WIDTH_STORAGE_KEY = "prismray.drawerWidth";
const DEFAULT_DRAWER_WIDTH = 460;
const MIN_DRAWER_WIDTH = 360;
const MAX_DRAWER_WIDTH = 840;

function loadStoredDrawerWidth(): number {
  if (typeof window === "undefined") return DEFAULT_DRAWER_WIDTH;
  try {
    const raw = Number(window.localStorage.getItem(DRAWER_WIDTH_STORAGE_KEY));
    if (Number.isFinite(raw) && raw >= MIN_DRAWER_WIDTH && raw <= MAX_DRAWER_WIDTH) {
      return Math.round(raw);
    }
  } catch {
    // Ignore storage read errors.
  }
  return DEFAULT_DRAWER_WIDTH;
}

export function useIsMobile(breakpointPx = 768): boolean {
  const [mobile, setMobile] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia(`(max-width: ${breakpointPx - 1}px)`).matches;
  });

  useEffect(() => {
    if (typeof window === "undefined") return;
    const mq = window.matchMedia(`(max-width: ${breakpointPx - 1}px)`);
    const update = () => setMobile(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, [breakpointPx]);

  return mobile;
}

export interface ContextInspectorProps {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  headerActions?: React.ReactNode;
  children: React.ReactNode;
  widthClass?: string;
}

/**
 * Adaptive contextual inspector rendered as a top-layer Cover overlay:
 * - PC (>=768px): native modal <dialog class="slide-over-drawer"> anchored on the right edge,
 *   with a draggable left-edge resize handle (persisted width, double-click to reset).
 * - Mobile (<768px): native top-layer <dialog class="bottom-sheet"> with backdrop light-dismiss.
 */
export function ContextInspector({
  open,
  title,
  subtitle,
  onClose,
  headerActions,
  children,
}: ContextInspectorProps) {
  const { tr } = useAppStore();
  const isMobile = useIsMobile();
  const dlgRef = useRef<HTMLDialogElement | null>(null);
  const pointerDownOutsideRef = useRef(false);
  const headingId = useId();
  const [drawerWidth, setDrawerWidth] = useState<number>(() => loadStoredDrawerWidth());
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(DRAWER_WIDTH_STORAGE_KEY, String(drawerWidth));
    } catch {
      // Ignore storage write errors.
    }
  }, [drawerWidth]);

  useEffect(() => {
    const dlg = dlgRef.current;
    if (!dlg) return;
    if (open) {
      if (!dlg.open) {
        dlg.showModal();
        // Focus the dialog surface itself instead of auto-focusing the Close button
        // so opening the drawer doesn't flash a blue focus ring on `×`.
        dlg.focus({ preventScroll: true });
      }
    } else if (dlg.open) {
      dlg.close();
    }
  }, [open]);

  const startDrawerResize = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (isMobile) return;
      e.preventDefault();
      e.stopPropagation();
      const handle = e.currentTarget;
      const startX = e.clientX;
      const startWidth = dlgRef.current?.getBoundingClientRect().width || drawerWidth;

      try {
        handle.setPointerCapture(e.pointerId);
      } catch {
        // Fallback for synthetic events.
      }
      setIsResizing(true);
      document.body.classList.add("prismray-col-resizing");

      const onMove = (ev: PointerEvent) => {
        const maxAllowed = Math.min(MAX_DRAWER_WIDTH, Math.floor(window.innerWidth * 0.92));
        const next = Math.round(
          Math.min(maxAllowed, Math.max(MIN_DRAWER_WIDTH, startWidth + (startX - ev.clientX))),
        );
        setDrawerWidth(next);
      };

      const onEnd = () => {
        setIsResizing(false);
        document.body.classList.remove("prismray-col-resizing");
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onEnd);
        window.removeEventListener("pointercancel", onEnd);
      };

      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onEnd);
      window.addEventListener("pointercancel", onEnd);
    },
    [drawerWidth, isMobile],
  );

  const isPointerOutside = (e: React.PointerEvent<HTMLDialogElement>, dialog: HTMLDialogElement) => {
    const r = dialog.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  };

  if (!open) return null;

  const dialogNode = (
    <dialog
      ref={dlgRef}
      tabIndex={-1}
      className={isMobile ? "bottom-sheet outline-none" : "slide-over-drawer outline-none"}
      style={
        !isMobile
          ? ({ "--drawer-width": `${drawerWidth}px` } as React.CSSProperties)
          : undefined
      }
      aria-labelledby={headingId}
      {...({ closedby: "any" } as Record<string, string>)}
      onCancel={(e) => {
        e.stopPropagation();
      }}
      onClose={(e) => {
        e.stopPropagation();
        if (e.target !== dlgRef.current) return;
        if (dlgRef.current) dlgRef.current.returnValue = "";
        onClose();
      }}
      onPointerDown={(e) => {
        e.stopPropagation();
        if (typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype) return;
        const dlg = dlgRef.current;
        if (e.target !== dlg) {
          pointerDownOutsideRef.current = false;
          return;
        }
        pointerDownOutsideRef.current = Boolean(dlg && isPointerOutside(e, dlg));
      }}
      onPointerUp={(e) => {
        e.stopPropagation();
        if (typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype) return;
        const dlg = dlgRef.current;
        if (e.target === dlg && pointerDownOutsideRef.current && dlg && isPointerOutside(e, dlg)) {
          pointerDownOutsideRef.current = false;
          dlg.close();
        }
        pointerDownOutsideRef.current = false;
      }}
    >
      {!isMobile ? (
        <div
          role="separator"
          aria-orientation="vertical"
          aria-label={tr("inspector.resizeHint")}
          title={tr("inspector.resizeHint")}
          onPointerDown={startDrawerResize}
          onDoubleClick={() => setDrawerWidth(DEFAULT_DRAWER_WIDTH)}
          className={`drawer-resize-handle ${isResizing ? "is-active" : ""}`}
        />
      ) : null}

      {isMobile ? (
        <div className="pt-2 pb-1 flex justify-center border-b border-border bg-card rounded-t-[12px]">
          <span className="w-9 h-1 rounded-full bg-muted-foreground/30" aria-hidden="true" />
        </div>
      ) : null}
      <div
        className={`flex items-center justify-between gap-2 border-b border-border ${
          isMobile ? "bg-card px-4 py-2.5" : "bg-muted/30 px-4 py-3"
        }`}
      >
        <div className="min-w-0">
          <h3 id={headingId} className={`${isMobile ? "text-[15px]" : "text-[14px]"} font-semibold truncate`}>
            {title}
          </h3>
          {subtitle ? (
            <p className={`${isMobile ? "text-xs" : "text-[11px]"} mono-num text-muted-foreground truncate`}>
              {subtitle}
            </p>
          ) : null}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {headerActions}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              dlgRef.current?.close();
            }}
            title={tr("inspector.close")}
            aria-label={tr("inspector.close")}
            className={`inline-flex items-center justify-center rounded-[6px] text-muted-foreground hover:text-foreground hover:bg-muted transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
              isMobile ? "min-h-11 min-w-11" : "h-7 w-7"
            }`}
          >
            <X className={isMobile ? "w-5 h-5" : "w-4 h-4"} />
          </button>
        </div>
      </div>
      <div
        className={
          isMobile
            ? "p-4 overflow-y-auto max-h-[calc(86dvh-4.75rem)] safe-bottom space-y-3"
            : "p-4 overflow-y-auto flex-1 space-y-3"
        }
      >
        {children}
      </div>
    </dialog>
  );

  return typeof document !== "undefined" ? createPortal(dialogNode, document.body) : dialogNode;
}

/**
 * Reusable mobile Bottom Sheet dialog for filter/sort pickers & quick-create menus.
 * Portaled to document.body so closing a nested BottomSheetDialog never bubbles to parent dialogs.
 */
export function BottomSheetDialog({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const { tr } = useAppStore();
  const dlgRef = useRef<HTMLDialogElement | null>(null);
  const pointerDownOutsideRef = useRef(false);
  const headingId = useId();

  useEffect(() => {
    const dlg = dlgRef.current;
    if (!dlg) return;
    if (open) {
      if (!dlg.open) {
        dlg.showModal();
        dlg.focus({ preventScroll: true });
      }
    } else if (dlg.open) {
      dlg.close();
    }
  }, [open]);

  if (!open) return null;

  const sheetNode = (
    <dialog
      ref={dlgRef}
      tabIndex={-1}
      className="bottom-sheet outline-none"
      aria-labelledby={headingId}
      {...({ closedby: "any" } as Record<string, string>)}
      onCancel={(e) => {
        e.stopPropagation();
      }}
      onClose={(e) => {
        e.stopPropagation();
        if (e.target !== dlgRef.current) return;
        if (dlgRef.current) dlgRef.current.returnValue = "";
        onClose();
      }}
      onPointerDown={(e) => {
        e.stopPropagation();
        if (typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype) return;
        const dlg = dlgRef.current;
        if (!dlg || e.target !== dlg) {
          pointerDownOutsideRef.current = false;
          return;
        }
        const r = dlg.getBoundingClientRect();
        pointerDownOutsideRef.current = e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      }}
      onPointerUp={(e) => {
        e.stopPropagation();
        if (typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype) return;
        const dlg = dlgRef.current;
        if (!dlg || e.target !== dlg) {
          pointerDownOutsideRef.current = false;
          return;
        }
        const r = dlg.getBoundingClientRect();
        const outside = e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
        if (pointerDownOutsideRef.current && outside) {
          pointerDownOutsideRef.current = false;
          dlg.close();
        }
        pointerDownOutsideRef.current = false;
      }}
    >
      <div className="pt-2 pb-1 flex justify-center border-b border-border bg-card rounded-t-[12px]">
        <span className="w-9 h-1 rounded-full bg-muted-foreground/30" aria-hidden="true" />
      </div>
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-card">
        <h3 id={headingId} className="text-[15px] font-semibold truncate">{title}</h3>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            dlgRef.current?.close();
          }}
          aria-label={tr("inspector.close")}
          className="min-h-11 min-w-11 inline-flex items-center justify-center rounded-[6px] text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="w-5 h-5" />
        </button>
      </div>
      <div className="p-4 overflow-y-auto max-h-[calc(86dvh-4.5rem)] safe-bottom space-y-2">{children}</div>
    </dialog>
  );

  return typeof document !== "undefined" ? createPortal(sheetNode, document.body) : sheetNode;
}
