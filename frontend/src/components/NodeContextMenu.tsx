// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { CheckSquare, Gauge, Pencil, Play, QrCode, Square, Star, Trash2 } from "lucide-react";
import { type NodeConfig } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";

export interface NodeContextMenuState {
  x: number;
  y: number;
  node: NodeConfig;
}

interface NodeContextMenuProps {
  state: NodeContextMenuState | null;
  isActive: boolean;
  isSelected: boolean;
  selectedCount: number;
  probing: boolean;
  onClose: () => void;
  onToggleConnect: (nodeId: string) => void;
  onProbeSingle: (nodeId: string) => void;
  onProbeSelected: () => void;
  onToggleSelect: (nodeId: string) => void;
  onToggleFavorite: (node: NodeConfig) => void;
  onEditNode: (node: NodeConfig) => void;
  onShareQr: (node: NodeConfig) => void;
  onDeleteNode: (nodeId: string) => void;
}

export function NodeContextMenu({
  state,
  isActive,
  isSelected,
  selectedCount,
  probing,
  onClose,
  onToggleConnect,
  onProbeSingle,
  onProbeSelected,
  onToggleSelect,
  onToggleFavorite,
  onEditNode,
  onShareQr,
  onDeleteNode,
}: NodeContextMenuProps) {
  const { tr } = useAppStore();
  const menuRef = useRef<HTMLDivElement>(null);
  const [coords, setCoords] = useState<{ left: number; top: number }>({ left: 0, top: 0 });
  const supportsFocusgroup =
    typeof HTMLElement !== "undefined" && "focusGroup" in HTMLElement.prototype;

  useLayoutEffect(() => {
    if (!state) return;
    const el = menuRef.current;
    if (!el) {
      setCoords({ left: state.x, top: state.y });
      return;
    }
    const rect = el.getBoundingClientRect();
    const pad = 8;
    const left =
      state.x + rect.width > window.innerWidth - pad
        ? Math.max(pad, state.x - rect.width)
        : Math.max(pad, state.x);
    const top =
      state.y + rect.height > window.innerHeight - pad
        ? Math.max(pad, state.y - rect.height)
        : Math.max(pad, state.y);
    setCoords({ left, top });
  }, [state]);

  useEffect(() => {
    if (!state) return;
    const el = menuRef.current;
    const firstItem = el?.querySelector<HTMLButtonElement>("button:not(:disabled)");
    firstItem?.focus({ preventScroll: true });

    const onPointerDown = (e: PointerEvent) => {
      if (el && !el.contains(e.target as Node)) {
        onClose();
      }
    };
    const onScrollOrResize = () => onClose();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };

    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onScrollOrResize);
    window.addEventListener("blur", onScrollOrResize);
    const scrollRoot = document.getElementById("prismray-scroll-root");
    scrollRoot?.addEventListener("scroll", onScrollOrResize, { passive: true });
    return () => {
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onScrollOrResize);
      window.removeEventListener("blur", onScrollOrResize);
      scrollRoot?.removeEventListener("scroll", onScrollOrResize);
    };
  }, [state, onClose]);

  if (!state) return null;

  const { node } = state;
  const displayName = node.user_alias || node.name;
  const itemRoleProps = supportsFocusgroup ? {} : { role: "menuitem" as const };

  const handleMenuKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const keys = supportsFocusgroup ? ["Home", "End"] : ["ArrowDown", "ArrowUp", "Home", "End"];
    if (!keys.includes(e.key)) return;
    const el = menuRef.current;
    if (!el) return;
    const items = Array.from(el.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"));
    if (items.length === 0) return;
    e.preventDefault();
    const cur = items.indexOf(document.activeElement as HTMLButtonElement);
    let next = 0;
    if (e.key === "End") next = items.length - 1;
    else if (e.key === "ArrowDown") next = cur < 0 ? 0 : (cur + 1) % items.length;
    else if (e.key === "ArrowUp") next = cur <= 0 ? items.length - 1 : cur - 1;
    items[next]?.focus({ preventScroll: true });
  };

  const runAction = (fn: () => void) => {
    onClose();
    fn();
  };

  const focusHoverItem = (el: HTMLButtonElement) => {
    el.focus({ preventScroll: true, focusVisible: false } as FocusOptions);
  };

  const itemClass =
    "flex w-full items-center gap-2.5 rounded-[6px] px-2.5 py-1.5 text-left text-xs text-popover-foreground transition-colors hover:bg-muted focus-visible:bg-muted focus-visible:outline-none disabled:opacity-45 max-md:min-h-11";

  return (
    <div
      ref={menuRef}
      {...({ focusgroup: "menu nomemory" } as Record<string, string>)}
      role={supportsFocusgroup ? undefined : "menu"}
      aria-label={`${tr("ctx.nodeMenu")}: ${displayName}`}
      onKeyDown={handleMenuKeyDown}
      style={{ position: "fixed", left: coords.left, top: coords.top, inset: `${coords.top}px auto auto ${coords.left}px`, margin: 0 }}
      className="z-50 w-56 rounded-[10px] border border-border bg-popover p-1.5 text-popover-foreground shadow-sm"
    >
      <div className="px-2.5 py-1 text-[11px] font-medium text-muted-foreground truncate" aria-hidden="true">
        {displayName}
      </div>
      <hr className="my-1 border-border" />

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onToggleConnect(node.id))}
        className={itemClass}
      >
        <Play className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
        <span className="flex-1 truncate">{isActive ? tr("ctx.disconnect") : tr("action.connect")}</span>
      </button>

      <button
        type="button"
        {...itemRoleProps}
        disabled={probing}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onProbeSingle(node.id))}
        className={itemClass}
      >
        <Gauge className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="flex-1 truncate">{tr("ctx.probeSingle")}</span>
      </button>

      {selectedCount > 1 ? (
        <button
          type="button"
          {...itemRoleProps}
          onPointerMove={(e) => focusHoverItem(e.currentTarget)}
          onClick={() => runAction(() => onProbeSelected())}
          className={itemClass}
        >
          <Gauge className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
          <span className="flex-1 truncate">{tr("proxies.probeSelected", { count: selectedCount })}</span>
        </button>
      ) : null}

      <hr className="my-1 border-border" />

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onToggleSelect(node.id))}
        className={itemClass}
      >
        {isSelected ? (
          <CheckSquare className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
        ) : (
          <Square className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        )}
        <span className="flex-1 truncate">{isSelected ? tr("ctx.deselectNode") : tr("ctx.selectNode")}</span>
      </button>

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onToggleFavorite(node))}
        className={itemClass}
      >
        <Star
          className={`h-3.5 w-3.5 shrink-0 ${node.favorite ? "text-amber-500" : "text-muted-foreground"}`}
          fill={node.favorite ? "currentColor" : "none"}
          aria-hidden="true"
        />
        <span className="flex-1 truncate">{node.favorite ? tr("ctx.favoriteRemove") : tr("ctx.favoriteAdd")}</span>
      </button>

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onEditNode(node))}
        className={itemClass}
      >
        <Pencil className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="flex-1 truncate">{tr("ctx.editNode")}</span>
      </button>

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onShareQr(node))}
        className={itemClass}
      >
        <QrCode className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <span className="flex-1 truncate">{tr("ctx.shareQr")}</span>
      </button>

      <hr className="my-1 border-border" />

      <button
        type="button"
        {...itemRoleProps}
        onPointerMove={(e) => focusHoverItem(e.currentTarget)}
        onClick={() => runAction(() => onDeleteNode(node.id))}
        className="flex w-full items-center gap-2.5 rounded-[6px] px-2.5 py-1.5 text-left text-xs text-destructive transition-colors hover:bg-destructive/15 focus-visible:bg-destructive/15 focus-visible:outline-none max-md:min-h-11"
      >
        <Trash2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span className="flex-1 truncate">{tr("action.delete")}</span>
      </button>
    </div>
  );
}
