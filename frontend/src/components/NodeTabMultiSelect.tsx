// SPDX-License-Identifier: MPL-2.0

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown, Lock, Minus, Pencil, Plus, Tag, Trash2, X } from "lucide-react";
import { type NodeFilterTab } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { BottomSheetDialog, useIsMobile } from "./ContextInspector.tsx";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";

export interface LockedSourceTab {
  id: string;
  label: string;
}

export type TagCheckState = "all" | "some" | "none";

interface FilterModeProps {
  mode: "filter";
  tabs: NodeFilterTab[];
  selectedTabIds: string[];
  onChangeTabIds: (next: string[]) => void;
  onCreateTab?: (name: string) => Promise<void> | void;
  onRenameTab?: (oldName: string, newName: string) => Promise<void> | void;
  onDeleteTab?: (name: string) => Promise<void> | void;
  busy?: boolean;
  className?: string;
}

interface AssignModeProps {
  mode: "assign";
  lockedSources: LockedSourceTab[];
  customTags: string[];
  tagStates: Record<string, TagCheckState>;
  onToggleTag: (tag: string, nextChecked: boolean) => Promise<void> | void;
  onCreateAndAssignTag?: (tag: string) => Promise<void> | void;
  triggerLabel?: string;
  placeholder?: string;
  busy?: boolean;
  disabled?: boolean;
  className?: string;
}

export type NodeTabMultiSelectProps = FilterModeProps | AssignModeProps;

export function NodeTabMultiSelect(props: NodeTabMultiSelectProps) {
  const { tr, locale } = useAppStore();
  const isMobile = useIsMobile();

  const [open, setOpen] = useState(false);
  const [newTagName, setNewTagName] = useState("");
  const [renamingTag, setRenamingTag] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number; maxHeight: number }>({
    top: 0,
    left: 0,
    width: 320,
    maxHeight: 420,
  });

  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);

  const updateViewportPlacement = useCallback(() => {
    if (typeof window === "undefined" || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const pad = 12;
    const gap = 6;
    const width = Math.min(Math.max(rect.width, 320), vw - pad * 2);
    const left = Math.max(pad, Math.min(rect.left, vw - width - pad));
    const spaceBelow = vh - rect.bottom - gap - pad;
    const spaceAbove = rect.top - gap - pad;
    const preferredHeight = 380;
    const openAbove = spaceBelow < 240 && spaceAbove > spaceBelow;
    const availHeight = openAbove ? spaceAbove : spaceBelow;
    const maxHeight = Math.max(180, Math.min(440, availHeight));
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

  const filterSelectedSet = useMemo(() => {
    if (props.mode !== "filter") return new Set<string>();
    return new Set(props.selectedTabIds.filter((id) => id && id !== "all"));
  }, [props]);

  const handleToggleFilterTab = (tabId: string) => {
    if (props.mode !== "filter") return;
    if (tabId === "all") {
      props.onChangeTabIds([]);
      return;
    }
    const next = new Set(filterSelectedSet);
    if (next.has(tabId)) {
      next.delete(tabId);
    } else {
      next.add(tabId);
    }
    props.onChangeTabIds(Array.from(next));
  };

  const handleCreateSubmit = async () => {
    const clean = newTagName.trim();
    if (!clean) return;
    if (props.mode === "filter" && props.onCreateTab) {
      await props.onCreateTab(clean);
      setNewTagName("");
    } else if (props.mode === "assign" && props.onCreateAndAssignTag) {
      await props.onCreateAndAssignTag(clean);
      setNewTagName("");
    }
  };

  const handleCommitRename = async (oldName: string) => {
    if (props.mode !== "filter" || !props.onRenameTab) return;
    const clean = renameDraft.trim();
    if (clean && clean !== oldName) {
      await props.onRenameTab(oldName, clean);
    }
    setRenamingTag(null);
  };

  const renderTriggerLabel = () => {
    if (props.mode === "filter") {
      const allTab = props.tabs.find((t) => t.id === "all");
      if (filterSelectedSet.size === 0) {
        return `${allTab?.label || tr("proxies.tabAll")} (${allTab?.count ?? 0})`;
      }
      const chosen = props.tabs.filter((t) => filterSelectedSet.has(t.id));
      if (chosen.length === 1) {
        const only = chosen[0];
        return `${only.tagName ? `#${only.label}` : only.label} (${only.count})`;
      }
      const preview = chosen
        .slice(0, 2)
        .map((t) => (t.tagName ? `#${t.label}` : t.label))
        .join(", ");
      return `${tr("proxies.tabSelectedSummary", { count: chosen.length })}: ${preview}${chosen.length > 2 ? "…" : ""}`;
    }

    if (props.triggerLabel) {
      return props.triggerLabel;
    }
    const checkedCustom = props.customTags.filter((tag) => props.tagStates[tag] === "all");
    const lockedLabels = props.lockedSources.map((s) => s.label);
    const combined = [...lockedLabels, ...checkedCustom.map((t) => `#${t}`)];
    if (combined.length === 0) {
      return props.placeholder || tr("proxies.nodeTags");
    }
    if (combined.length <= 2) {
      return combined.join(", ");
    }
    return `${tr("proxies.tabSelectedSummary", { count: combined.length })}: ${combined.slice(0, 2).join(", ")}…`;
  };

  const renderFilterBody = () => {
    if (props.mode !== "filter") return null;
    const builtinTabs = props.tabs.filter((t) => (t.kind || "builtin") === "builtin");
    const subTabs = props.tabs.filter((t) => t.kind === "subscription" || t.id.startsWith("sub:"));
    const customTabs = props.tabs.filter((t) => t.kind === "custom" || t.id.startsWith("utag:"));

    const renderCheckRow = (tab: NodeFilterTab) => {
      const isAll = tab.id === "all";
      const checked = isAll ? filterSelectedSet.size === 0 : filterSelectedSet.has(tab.id);
      const isCustom = Boolean(tab.deletable && tab.tagName);

      if (isCustom && renamingTag === tab.tagName) {
        return (
          <div key={tab.id} className="flex items-center gap-1.5 px-2 py-1.5">
            <Input
              className="h-7 flex-1 px-2 text-xs"
              value={renameDraft}
              onChange={(e) => setRenameDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void handleCommitRename(tab.tagName!);
                } else if (e.key === "Escape") {
                  e.stopPropagation();
                  setRenamingTag(null);
                }
              }}
              autoFocus
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={props.busy}
              className="h-7 px-2 text-[11px]"
              onClick={() => void handleCommitRename(tab.tagName!)}
            >
              {tr("action.save")}
            </Button>
            <button
              type="button"
              onClick={() => setRenamingTag(null)}
              className="rounded p-1 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        );
      }

      return (
        <div
          key={tab.id}
          className={`flex items-center justify-between gap-1.5 px-2 py-1.5 transition-colors max-md:min-h-11 ${
            checked ? "bg-accent/70 text-foreground" : "text-foreground hover:bg-muted/70"
          }`}
        >
          <button
            type="button"
            role="option"
            aria-selected={checked}
            onClick={() => handleToggleFilterTab(tab.id)}
            className="flex min-w-0 flex-1 items-center gap-2 text-left"
          >
            <span
              className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-[4px] border ${
                checked ? "border-primary bg-primary text-primary-foreground" : "border-input bg-card"
              }`}
              aria-hidden="true"
            >
              {checked ? <Check className="h-3 w-3" /> : null}
            </span>
            <span className="truncate font-medium">
              {tab.tagName ? `#${tab.label}` : tab.label}
            </span>
          </button>
          <div className="flex shrink-0 items-center gap-1">
            <span className="mono-num rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
              {tab.count}
            </span>
            {tab.kind === "subscription" ? (
              <span
                title={tr("proxies.tabGroupSubscription")}
                className="inline-flex h-6 w-6 items-center justify-center text-muted-foreground/60"
              >
                <Lock className="h-3 w-3" aria-hidden="true" />
              </span>
            ) : isCustom ? (
              <>
                {props.onRenameTab ? (
                  <button
                    type="button"
                    disabled={props.busy}
                    onClick={() => {
                      setRenamingTag(tab.tagName!);
                      setRenameDraft(tab.tagName!);
                    }}
                    title={tr("proxies.renameTab")}
                    aria-label={`${tr("proxies.renameTab")} ${tab.tagName}`}
                    className="inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                  >
                    <Pencil className="h-3 w-3" aria-hidden="true" />
                  </button>
                ) : null}
                {props.onDeleteTab ? (
                  <button
                    type="button"
                    disabled={props.busy}
                    onClick={() => void props.onDeleteTab?.(tab.tagName!)}
                    title={tr("proxies.deleteTab")}
                    aria-label={`${tr("proxies.deleteTab")} ${tab.tagName}`}
                    className="inline-flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                  >
                    <Trash2 className="h-3 w-3" aria-hidden="true" />
                  </button>
                ) : null}
              </>
            ) : null}
          </div>
        </div>
      );
    };

    return (
      <div className="space-y-2.5 text-xs">
        <div className="flex items-center justify-between gap-2 text-[11px]">
          <span className="text-muted-foreground">{tr("proxies.tabFilterPlaceholder")}</span>
          {filterSelectedSet.size > 0 ? (
            <button
              type="button"
              onClick={() => props.onChangeTabIds([])}
              className="rounded border border-border px-1.5 py-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              {tr("proxies.clearSelectedNodes")}
            </button>
          ) : null}
        </div>

        <div className="max-h-72 overflow-y-auto space-y-2">
          {/* Built-in tabs (never deletable) */}
          <div className="space-y-1">
            <div className="px-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              {tr("proxies.tabGroupBuiltin")}
            </div>
            <div className="overflow-hidden rounded-[6px] border border-border bg-background divide-y divide-border/60">
              {builtinTabs.map(renderCheckRow)}
            </div>
          </div>

          {/* Subscription tabs (auto-created, removed when subscription deleted) */}
          {subTabs.length > 0 ? (
            <div className="space-y-1">
              <div className="px-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {tr("proxies.tabGroupSubscription")}
              </div>
              <div className="overflow-hidden rounded-[6px] border border-border bg-background divide-y divide-border/60">
                {subTabs.map(renderCheckRow)}
              </div>
            </div>
          ) : null}

          {/* User-created custom tabs (editable & deletable) */}
          <div className="space-y-1">
            <div className="px-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              {tr("proxies.tabGroupCustom")}
            </div>
            {customTabs.length === 0 ? (
              <div className="rounded-[6px] border border-dashed border-border bg-muted/20 px-3 py-2 text-center text-[11px] text-muted-foreground">
                {tr("proxies.tabNoCustomYet")}
              </div>
            ) : (
              <div className="overflow-hidden rounded-[6px] border border-border bg-background divide-y divide-border/60">
                {customTabs.map(renderCheckRow)}
              </div>
            )}
          </div>
        </div>

        {props.onCreateTab ? (
          <div className="flex items-center gap-1.5 border-t border-border pt-2">
            <Input
              className="h-8 flex-1 text-xs"
              placeholder={tr("proxies.newTabPlaceholder")}
              value={newTagName}
              onChange={(e) => setNewTagName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void handleCreateSubmit();
                }
              }}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={props.busy || !newTagName.trim()}
              onClick={() => void handleCreateSubmit()}
              className="h-8 shrink-0 px-2.5"
            >
              <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              {tr("action.add")}
            </Button>
          </div>
        ) : null}
      </div>
    );
  };

  const renderAssignBody = () => {
    if (props.mode !== "assign") return null;
    return (
      <div className="space-y-2.5 text-xs">
        <p className="text-[11px] leading-snug text-muted-foreground">{tr("proxies.tabBatchHint")}</p>

        <div className="max-h-64 overflow-y-auto space-y-2">
          {/* Locked subscription source tags */}
          {props.lockedSources.length > 0 ? (
            <div className="space-y-1">
              <div className="px-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                {tr("proxies.tabGroupSubscription")}
              </div>
              <div className="overflow-hidden rounded-[6px] border border-border bg-muted/25 divide-y divide-border/60">
                {props.lockedSources.map((src) => (
                  <div
                    key={src.id}
                    title={tr("proxies.tabLockedOrigin")}
                    aria-disabled="true"
                    className="flex items-center justify-between gap-2 px-2.5 py-1.5 text-muted-foreground select-none max-md:min-h-11"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-[4px] border border-primary/40 bg-primary/20 text-primary"
                        aria-hidden="true"
                      >
                        <Check className="h-3 w-3" />
                      </span>
                      <span className="truncate font-medium text-foreground/80">{src.label}</span>
                    </span>
                    <span className="inline-flex shrink-0 items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      <Lock className="h-2.5 w-2.5" aria-hidden="true" />
                      <span>{tr("proxies.tabLockedOrigin")}</span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* Checkable custom manual tags */}
          <div className="space-y-1">
            <div className="px-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              {tr("proxies.tabGroupCustom")}
            </div>
            {props.customTags.length === 0 ? (
              <div className="rounded-[6px] border border-dashed border-border bg-muted/20 px-3 py-2.5 text-center text-[11px] text-muted-foreground">
                {tr("proxies.tabNoCustomYet")}
              </div>
            ) : (
              <div className="overflow-hidden rounded-[6px] border border-border bg-background divide-y divide-border/60">
                {props.customTags.map((tag) => {
                  const state = props.tagStates[tag] || "none";
                  const isAll = state === "all";
                  const isSome = state === "some";
                  return (
                    <button
                      key={tag}
                      type="button"
                      role="option"
                      aria-selected={isAll}
                      disabled={props.busy}
                      onClick={() => void props.onToggleTag(tag, !isAll)}
                      className={`flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-left transition-colors max-md:min-h-11 disabled:opacity-50 ${
                        isAll || isSome ? "bg-accent/60 text-foreground" : "text-foreground hover:bg-muted/70"
                      }`}
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <span
                          className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-[4px] border ${
                            isAll || isSome
                              ? "border-primary bg-primary text-primary-foreground"
                              : "border-input bg-card"
                          }`}
                          aria-hidden="true"
                        >
                          {isAll ? (
                            <Check className="h-3 w-3" />
                          ) : isSome ? (
                            <Minus className="h-3 w-3" />
                          ) : null}
                        </span>
                        <span className="truncate font-medium">#{tag}</span>
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {props.onCreateAndAssignTag ? (
          <div className="flex items-center gap-1.5 border-t border-border pt-2">
            <Input
              className="h-8 flex-1 text-xs"
              placeholder={tr("proxies.newTabPlaceholder")}
              value={newTagName}
              onChange={(e) => setNewTagName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void handleCreateSubmit();
                }
              }}
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={props.busy || !newTagName.trim()}
              onClick={() => void handleCreateSubmit()}
              className="h-8 shrink-0 px-2.5"
            >
              <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
              {tr("action.add")}
            </Button>
          </div>
        ) : null}
      </div>
    );
  };

  const panelBody = props.mode === "filter" ? renderFilterBody() : renderAssignBody();
  const isDisabled = props.mode === "assign" && Boolean(props.disabled);
  const badgeCount =
    props.mode === "filter"
      ? filterSelectedSet.size
      : props.customTags.filter((tag) => props.tagStates[tag] === "all").length + props.lockedSources.length;

  return (
    <div ref={containerRef} className={`relative ${props.className || ""}`}>
      <button
        ref={triggerRef}
        type="button"
        disabled={isDisabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex h-8 w-full items-center justify-between gap-2 rounded-[6px] border border-input bg-card px-2.5 text-left text-xs text-foreground transition-colors hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50 max-md:min-h-[var(--m-input-h)] max-md:text-[13px]"
      >
        <span className="flex min-w-0 flex-1 items-center gap-1.5">
          <Tag className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
          <span className="truncate font-medium">{renderTriggerLabel()}</span>
        </span>
        <span className="flex shrink-0 items-center gap-1">
          {badgeCount > 0 ? (
            <span className="mono-num rounded-[4px] bg-primary/15 px-1.5 py-0.5 text-[10px] font-semibold text-primary">
              {badgeCount}
            </span>
          ) : null}
          {props.mode === "filter" && filterSelectedSet.size > 0 ? (
            <span
              role="button"
              tabIndex={-1}
              aria-label={tr("proxies.clearSelectedNodes")}
              onClick={(e) => {
                e.stopPropagation();
                props.onChangeTabIds([]);
              }}
              className="inline-flex h-4 w-4 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <X className="h-3 w-3" aria-hidden="true" />
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
              aria-label={props.mode === "filter" ? tr("proxies.tabFilterPlaceholder") : tr("proxies.nodeTags")}
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
          title={props.mode === "filter" ? tr("proxies.tabFilterPlaceholder") : tr("proxies.nodeTags")}
          onClose={() => setOpen(false)}
        >
          {panelBody}
          <div className="border-t border-border pt-2">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setOpen(false);
              }}
              className="w-full min-h-11 rounded-[8px] bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
            >
              {locale === "zh-CN" ? "完成" : "Done"}
            </button>
          </div>
        </BottomSheetDialog>
      ) : null}
    </div>
  );
}
