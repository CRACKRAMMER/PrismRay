// SPDX-License-Identifier: MPL-2.0

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown, Search, X } from "lucide-react";
import { type GroupConfig, type NodeConfig, type SubscriptionRecord } from "../lib/api.ts";
import {
  buildNodeFilterTabs,
  formatLatency,
  getNodeHealthState,
  getNodeHealthStyles,
  nodeMatchesFilterTab,
} from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { BottomSheetDialog, useIsMobile } from "./ContextInspector.tsx";

export type ListenerExitValue =
  | { kind: "default" }
  | { kind: "direct" }
  | { kind: "group"; groupId: string }
  | { kind: "nodes"; nodeIds: string[] };

interface BaseProps {
  nodes: NodeConfig[];
  subscriptions: SubscriptionRecord[];
  customNodeTabs: string[];
  label?: string;
  placeholder?: string;
  className?: string;
  triggerId?: string;
}

export type NodeMultiSelectDropdownProps =
  | (BaseProps & {
      mode: "nodes";
      selectedNodeIds: string[];
      onChangeNodeIds: (ids: string[]) => void;
    })
  | (BaseProps & {
      mode: "listener-exit";
      value: ListenerExitValue;
      onChange: (next: ListenerExitValue) => void;
      groups: GroupConfig[];
    });

export function NodeMultiSelectDropdown(props: NodeMultiSelectDropdownProps) {
  const { nodes, subscriptions, customNodeTabs, label, placeholder, className, triggerId } = props;
  const { tr, locale, highLatencyMs } = useAppStore();
  const isMobile = useIsMobile();

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [tabId, setTabId] = useState("all");
  const [menuPos, setMenuPos] = useState<{
    top: number;
    left: number;
    width: number;
    maxHeight: number;
  }>({ top: 0, left: 0, width: 380, maxHeight: 420 });

  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const tabs = useMemo(
    () =>
      buildNodeFilterTabs(nodes, subscriptions, customNodeTabs, {
        all: tr("proxies.tabAll"),
        manual: tr("proxies.tabManual"),
        favorites: tr("proxies.tabFavorites"),
      }),
    [nodes, subscriptions, customNodeTabs, tr],
  );

  const effectiveTabId = tabs.some((t) => t.id === tabId) ? tabId : "all";

  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nodes.filter((n) => {
      if (!nodeMatchesFilterTab(n, effectiveTabId)) return false;
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        (n.user_alias || "").toLowerCase().includes(q) ||
        (n.address || "").toLowerCase().includes(q) ||
        (n.protocol || "").toLowerCase().includes(q) ||
        (n.group || "").toLowerCase().includes(q) ||
        (n.tags || []).join(" ").toLowerCase().includes(q)
      );
    });
  }, [nodes, effectiveTabId, search]);

  const selectedNodeIds = useMemo(() => {
    if (props.mode === "nodes") return props.selectedNodeIds;
    return props.value.kind === "nodes" ? props.value.nodeIds : [];
  }, [props]);

  const selectedSet = useMemo(() => new Set(selectedNodeIds), [selectedNodeIds]);

  const updateViewportPlacement = useCallback(() => {
    if (typeof window === "undefined" || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const pad = 12;
    const gap = 6;
    const width = Math.min(Math.max(rect.width, 380), vw - pad * 2);
    const left = Math.max(pad, Math.min(rect.left, vw - width - pad));
    const spaceBelow = vh - rect.bottom - gap - pad;
    const spaceAbove = rect.top - gap - pad;
    const preferredHeight = 400;
    const openAbove = spaceBelow < 280 && spaceAbove > spaceBelow;
    const availHeight = openAbove ? spaceAbove : spaceBelow;
    const maxHeight = Math.max(200, Math.min(460, availHeight));
    const estHeight = Math.min(preferredHeight, maxHeight);
    const top = openAbove
      ? Math.max(pad, rect.top - gap - estHeight)
      : Math.max(pad, Math.min(rect.bottom + gap, vh - pad - estHeight));
    setMenuPos({ top, left, width, maxHeight });
  }, []);

  useEffect(() => {
    if (!open || isMobile) return;
    const el = popoverRef.current;
    updateViewportPlacement();

    const canPopover =
      el !== null &&
      typeof HTMLElement !== "undefined" &&
      "showPopover" in HTMLElement.prototype &&
      typeof (el as HTMLElement & { showPopover?: () => void }).showPopover === "function";
    if (canPopover && el) {
      try {
        (el as HTMLElement & { showPopover: () => void }).showPopover();
      } catch {
        // Ignore if already open or unsupported in current engine.
      }
    }

    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (containerRef.current?.contains(target)) return;
      if (popoverRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    const onResizeOrScroll = (e?: Event) => {
      const target = e?.target as Node | null;
      if (target && popoverRef.current?.contains(target)) return;
      updateViewportPlacement();
    };

    window.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("resize", onResizeOrScroll);
    window.addEventListener("scroll", onResizeOrScroll, true);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown, true);
      window.removeEventListener("resize", onResizeOrScroll);
      window.removeEventListener("scroll", onResizeOrScroll, true);
      if (canPopover && el) {
        try {
          (el as HTMLElement & { hidePopover?: () => void }).hidePopover?.();
        } catch {
          // Ignore close races.
        }
      }
    };
  }, [open, isMobile, updateViewportPlacement]);

  useEffect(() => {
    if (open && !isMobile) {
      const id = window.setTimeout(() => searchInputRef.current?.focus({ preventScroll: true }), 10);
      return () => window.clearTimeout(id);
    }
  }, [open, isMobile]);

  const commitNodeIds = (nextIds: string[]) => {
    if (props.mode === "nodes") {
      props.onChangeNodeIds(nextIds);
      return;
    }
    if (nextIds.length === 0) {
      props.onChange({ kind: "default" });
    } else {
      props.onChange({ kind: "nodes", nodeIds: nextIds });
    }
  };

  const toggleNode = (nodeId: string) => {
    const next = selectedSet.has(nodeId)
      ? selectedNodeIds.filter((id) => id !== nodeId)
      : [...selectedNodeIds, nodeId];
    commitNodeIds(next);
  };

  const handleSelectFiltered = () => {
    const merged = [...selectedNodeIds];
    const seen = new Set(merged);
    for (const n of filteredNodes) {
      if (!seen.has(n.id)) {
        seen.add(n.id);
        merged.push(n.id);
      }
    }
    commitNodeIds(merged);
  };

  const handleClear = () => {
    if (props.mode === "nodes") {
      props.onChangeNodeIds([]);
    } else {
      props.onChange({ kind: "default" });
    }
  };

  const nodeLabelMap = useMemo(() => {
    const m = new Map<string, NodeConfig>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  const renderTriggerSummary = () => {
    if (props.mode === "listener-exit") {
      const v = props.value;
      if (v.kind === "direct") return tr("settings.targetDirect");
      if (v.kind === "group") {
        const g = props.groups.find((item) => item.id === v.groupId);
        return `${tr("settings.targetGroupPrefix")}: ${g?.name || v.groupId}`;
      }
      if (v.kind === "nodes" && v.nodeIds.length > 0) {
        const names = v.nodeIds.map((id) => {
          const n = nodeLabelMap.get(id);
          return n ? n.user_alias || n.name : id;
        });
        if (v.nodeIds.length === 1) {
          return `${tr("settings.targetNodePrefix")}: ${names[0]}`;
        }
        return `${tr("settings.targetNodePrefix")} (${v.nodeIds.length}): ${names.slice(0, 2).join(", ")}${v.nodeIds.length > 2 ? "…" : ""}`;
      }
      return tr("settings.targetDefaultProxy");
    }

    if (selectedNodeIds.length === 0) {
      return placeholder || tr("proxies.selectNodesPlaceholder");
    }
    const names = selectedNodeIds.map((id) => {
      const n = nodeLabelMap.get(id);
      return n ? n.user_alias || n.name : id;
    });
    if (selectedNodeIds.length <= 2) {
      return names.join(", ");
    }
    return `${tr("proxies.selectedNodesCount", { count: selectedNodeIds.length })} (${names.slice(0, 2).join(", ")}…)`;
  };

  const panelBody = (
    <div className="space-y-2.5 text-xs">
      {props.mode === "listener-exit" ? (
        <div className="space-y-1.5 border-b border-border pb-2.5">
          <div className="grid grid-cols-2 gap-1.5">
            <button
              type="button"
              onClick={() => {
                props.onChange({ kind: "default" });
                setOpen(false);
              }}
              className={`min-h-8 rounded-[6px] border px-2 py-1 text-left text-xs font-medium transition-colors max-md:min-h-11 ${
                props.value.kind === "default"
                  ? "border-primary bg-accent text-accent-foreground"
                  : "border-border bg-background text-foreground hover:bg-muted"
              }`}
            >
              {tr("settings.targetDefaultProxy")}
            </button>
            <button
              type="button"
              onClick={() => {
                props.onChange({ kind: "direct" });
                setOpen(false);
              }}
              className={`min-h-8 rounded-[6px] border px-2 py-1 text-left text-xs font-medium transition-colors max-md:min-h-11 ${
                props.value.kind === "direct"
                  ? "border-primary bg-accent text-accent-foreground"
                  : "border-border bg-background text-foreground hover:bg-muted"
              }`}
            >
              {tr("settings.targetDirect")}
            </button>
          </div>
          {props.groups.length > 0 ? (
            <div className="space-y-1">
              <div className="text-[11px] font-medium text-muted-foreground">{tr("routing.outboundGroups")}</div>
              <div className="flex flex-wrap gap-1">
                {props.groups.map((g) => {
                  const active = props.value.kind === "group" && props.value.groupId === g.id;
                  return (
                    <button
                      key={g.id}
                      type="button"
                      onClick={() => {
                        props.onChange({ kind: "group", groupId: g.id });
                        setOpen(false);
                      }}
                      className={`inline-flex items-center gap-1 rounded-[4px] border px-2 py-1 text-[11px] font-medium transition-colors max-md:min-h-10 ${
                        active
                          ? "border-primary bg-accent text-accent-foreground"
                          : "border-border bg-background text-foreground hover:bg-muted"
                      }`}
                    >
                      <span>{g.name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">({g.strategy})</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : null}
          <div className="text-[11px] text-muted-foreground">
            {locale === "zh-CN"
              ? "或勾选下方单个 / 多个节点作为该端口独立出口（多选自动启用测速优选）："
              : "Or pick 1+ specific nodes below for this inbound (multi-node auto-selects lowest latency):"}
          </div>
        </div>
      ) : null}

      {/* Search bar */}
      <div className="flex h-8 items-center gap-2 rounded-[6px] border border-input bg-card px-2.5 focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-1 max-md:h-11">
        <Search className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        <input
          ref={searchInputRef}
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={tr("proxies.searchPlaceholder")}
          className="h-full min-w-0 flex-1 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none max-md:text-[15px]"
        />
        {search ? (
          <button
            type="button"
            onClick={() => setSearch("")}
            aria-label="Clear search"
            className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </div>

      {/* Node filter tabs (shared with ProxiesView) */}
      <div className="tablist-scroller" role="tablist" aria-label={tr("proxies.nodeTags")}>
        {tabs.map((tab) => {
          const active = effectiveTabId === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setTabId(tab.id)}
              className={`tab-chip inline-flex items-center gap-1 rounded-[4px] border px-2 py-1 text-[11px] font-medium transition-colors max-md:min-h-10 ${
                active
                  ? "border-primary bg-accent text-accent-foreground"
                  : "border-border bg-background text-muted-foreground hover:bg-muted hover:text-foreground"
              }`}
            >
              <span>{tab.label}</span>
              <span className="mono-num text-[10px] opacity-75">({tab.count})</span>
            </button>
          );
        })}
      </div>

      {/* Bulk actions */}
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={handleSelectFiltered}
            className="rounded-[4px] border border-border bg-background px-2 py-0.5 font-medium text-foreground hover:bg-muted max-md:min-h-9"
          >
            {tr("proxies.filterAllSelected")} ({filteredNodes.length})
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="rounded-[4px] border border-border bg-background px-2 py-0.5 text-muted-foreground hover:bg-muted hover:text-foreground max-md:min-h-9"
          >
            {tr("proxies.clearSelectedNodes")}
          </button>
        </div>
        <span className="mono-num rounded-[4px] bg-muted px-1.5 py-0.5 font-semibold text-foreground">
          {tr("proxies.selectedNodesCount", { count: selectedNodeIds.length })}
        </span>
      </div>

      {/* Node checklist */}
      <div className="max-h-60 overflow-y-auto rounded-[6px] border border-border bg-background divide-y divide-border/60">
        {filteredNodes.length === 0 ? (
          <div className="px-3 py-4 text-center text-xs text-muted-foreground">
            {tr("proxies.noNodes")}
          </div>
        ) : (
          filteredNodes.map((n) => {
            const checked = selectedSet.has(n.id);
            const displayName = n.user_alias || n.name;
            const health = getNodeHealthStyles(getNodeHealthState(n.latency, highLatencyMs));
            return (
              <button
                key={n.id}
                type="button"
                role="option"
                aria-selected={checked}
                onClick={() => toggleNode(n.id)}
                className={`flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-left transition-colors max-md:min-h-12 ${
                  checked ? "bg-accent/70 text-foreground" : "text-foreground hover:bg-muted/70"
                }`}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-[4px] border ${
                      checked
                        ? "border-primary bg-primary text-primary-foreground"
                        : "border-input bg-card"
                    }`}
                    aria-hidden="true"
                  >
                    {checked ? <Check className="h-3 w-3" /> : null}
                  </span>
                  <span className={`h-2 w-2 shrink-0 rounded-full ${health.dotClass}`} aria-hidden="true" />
                  <span className="truncate font-medium">{displayName}</span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  <span className="rounded-[4px] border border-border px-1 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                    {n.protocol}
                  </span>
                  <span className={`mono-num text-[11px] font-medium ${health.textClass}`}>
                    {formatLatency(n.latency)}
                  </span>
                </span>
              </button>
            );
          })
        )}
      </div>
    </div>
  );

  return (
    <div ref={containerRef} className={`relative ${className || ""}`}>
      {label ? <span className="mb-1 block text-xs font-medium text-muted-foreground">{label}</span> : null}
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex h-8 w-full items-center justify-between gap-2 rounded-[6px] border border-input bg-card px-2.5 text-left text-xs text-foreground transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring max-md:min-h-[var(--m-input-h)] max-md:text-[13px]"
      >
        <span
          className={`min-w-0 flex-1 truncate ${
            props.mode === "nodes" && selectedNodeIds.length === 0 ? "text-muted-foreground" : "text-foreground"
          }`}
        >
          {renderTriggerSummary()}
        </span>
        <span className="flex shrink-0 items-center gap-1.5">
          {selectedNodeIds.length > 0 ? (
            <span className="mono-num rounded-[4px] bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
              {selectedNodeIds.length}
            </span>
          ) : null}
          <ChevronDown
            className={`h-3.5 w-3.5 text-muted-foreground transition-transform duration-150 ${
              open ? "rotate-180" : ""
            }`}
            aria-hidden="true"
          />
        </span>
      </button>

      {open && !isMobile && typeof document !== "undefined"
        ? createPortal(
            <div
              ref={popoverRef}
              {...({ popover: "manual" } as Record<string, string>)}
              role="dialog"
              aria-label={label || tr("proxies.groupsTitle")}
              onPointerDown={(e) => e.stopPropagation()}
              onClick={(e) => e.stopPropagation()}
              style={{
                position: "fixed",
                top: `${menuPos.top}px`,
                left: `${menuPos.left}px`,
                width: `${menuPos.width}px`,
                maxHeight: `${menuPos.maxHeight}px`,
                zIndex: 100,
              }}
              className="node-multiselect-popover overflow-y-auto rounded-[10px] border border-border bg-popover/95 p-3 text-popover-foreground shadow-xl backdrop-blur-md"
            >
              {panelBody}
            </div>,
            triggerRef.current?.closest("dialog") ?? document.body,
          )
        : null}

      {isMobile ? (
        <BottomSheetDialog
          open={open}
          title={
            label ||
            (props.mode === "listener-exit" ? tr("settings.listenerTarget") : tr("proxies.nodeTags"))
          }
          onClose={() => setOpen(false)}
        >
          {panelBody}
          <div className="pt-2 border-t border-border">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setOpen(false);
              }}
              className="w-full min-h-11 rounded-[8px] bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
            >
              {locale === "zh-CN"
                ? `完成选择${selectedNodeIds.length > 0 ? `（已选 ${selectedNodeIds.length} 个）` : ""}`
                : `Done${selectedNodeIds.length > 0 ? ` (${selectedNodeIds.length} selected)` : ""}`}
            </button>
          </div>
        </BottomSheetDialog>
      ) : null}
    </div>
  );
}
