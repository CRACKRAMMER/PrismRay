// SPDX-License-Identifier: MPL-2.0

import * as React from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "../../lib/utils.ts";
import { BottomSheetDialog } from "../ContextInspector.tsx";

export interface SelectProps
  extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, "size"> {
  size?: "default" | "sm";
}

interface ParsedOption {
  value: string;
  label: string;
  disabled?: boolean;
  group?: string;
}

function extractNodeText(node: React.ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(extractNodeText).join("");
  if (React.isValidElement<{ children?: React.ReactNode }>(node)) {
    return extractNodeText(node.props.children);
  }
  return "";
}

function parseOptions(children: React.ReactNode, groupLabel?: string): ParsedOption[] {
  const result: ParsedOption[] = [];
  React.Children.forEach(children, (child) => {
    if (!React.isValidElement(child)) return;
    if (child.type === React.Fragment) {
      const fragProps = child.props as { children?: React.ReactNode };
      result.push(...parseOptions(fragProps.children, groupLabel));
      return;
    }
    if (child.type === "optgroup") {
      const ogProps = child.props as React.OptgroupHTMLAttributes<HTMLOptGroupElement> & {
        children?: React.ReactNode;
      };
      result.push(...parseOptions(ogProps.children, ogProps.label || ""));
      return;
    }
    if (child.type === "option") {
      const optProps = child.props as React.OptionHTMLAttributes<HTMLOptionElement> & {
        children?: React.ReactNode;
      };
      const label = extractNodeText(optProps.children).trim();
      const val =
        optProps.value !== undefined && optProps.value !== null
          ? String(optProps.value)
          : label;
      result.push({
        value: val,
        label: label || val,
        disabled: Boolean(optProps.disabled),
        group: groupLabel,
      });
    }
  });
  return result;
}

function isMobileViewport(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(max-width: 767px)").matches;
}

export const Select = React.forwardRef<HTMLButtonElement, SelectProps>(
  (
    {
      className,
      size = "default",
      children,
      value,
      defaultValue,
      onChange,
      disabled,
      name,
      id,
      "aria-label": ariaLabel,
      "aria-labelledby": ariaLabelledBy,
      title,
    },
    ref,
  ) => {
    const options = React.useMemo(() => parseOptions(children), [children]);
    const isControlled = value !== undefined;
    const [internalVal, setInternalVal] = React.useState<string>(() => {
      if (defaultValue !== undefined && defaultValue !== null) return String(defaultValue);
      return options[0]?.value ?? "";
    });
    const currentValue = isControlled
      ? value === null
        ? ""
        : String(value)
      : internalVal;

    const [open, setOpen] = React.useState(false);
    const [mobileMode, setMobileMode] = React.useState(false);
    const [activeIndex, setActiveIndex] = React.useState<number>(-1);
    const [menuPos, setMenuPos] = React.useState<{
      top: number;
      left: number;
      width: number;
      maxHeight: number;
      openAbove: boolean;
    }>({ top: 0, left: 0, width: 180, maxHeight: 260, openAbove: false });

    const triggerRef = React.useRef<HTMLButtonElement | null>(null);
    const popoverRef = React.useRef<HTMLDivElement | null>(null);
    const listboxId = React.useId();

    const setMergedRef = React.useCallback(
      (node: HTMLButtonElement | null) => {
        triggerRef.current = node;
        if (typeof ref === "function") ref(node);
        else if (ref) (ref as React.MutableRefObject<HTMLButtonElement | null>).current = node;
      },
      [ref],
    );

    const selectedOption = React.useMemo(
      () => options.find((o) => o.value === currentValue) || options[0],
      [options, currentValue],
    );

    const computeMenuPosition = React.useCallback(() => {
      const btn = triggerRef.current;
      if (!btn || typeof window === "undefined") return;
      const rect = btn.getBoundingClientRect();
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      const gap = 6;
      const desiredWidth = Math.max(rect.width, 160);
      const width = Math.min(desiredWidth, vw - 16);
      const left = Math.max(8, Math.min(rect.left, vw - width - 8));
      const spaceBelow = vh - rect.bottom - gap - 8;
      const spaceAbove = rect.top - gap - 8;
      const estHeight = Math.min(280, Math.max(44, options.length * 36 + 16));
      const openAbove = spaceBelow < Math.min(estHeight, 180) && spaceAbove > spaceBelow;
      const maxHeight = Math.max(120, Math.min(300, openAbove ? spaceAbove : spaceBelow));
      const top = openAbove
        ? Math.max(8, rect.top - gap - Math.min(estHeight, maxHeight))
        : rect.bottom + gap;
      setMenuPos({ top, left, width, maxHeight, openAbove });
    }, [options.length]);

    const openMenu = React.useCallback(() => {
      if (disabled) return;
      const mobile = isMobileViewport();
      setMobileMode(mobile);
      const idx = options.findIndex((o) => o.value === currentValue && !o.disabled);
      setActiveIndex(idx >= 0 ? idx : options.findIndex((o) => !o.disabled));
      if (!mobile) {
        computeMenuPosition();
      }
      setOpen(true);
    }, [disabled, options, currentValue, computeMenuPosition]);

    const closeMenu = React.useCallback(() => {
      setOpen(false);
    }, []);

    const commitValue = React.useCallback(
      (nextVal: string) => {
        if (!isControlled) {
          setInternalVal(nextVal);
        }
        if (onChange) {
          const synthetic = {
            target: { value: nextVal, name: name || "" },
            currentTarget: { value: nextVal, name: name || "" },
          } as unknown as React.ChangeEvent<HTMLSelectElement>;
          onChange(synthetic);
        }
        setOpen(false);
      },
      [isControlled, name, onChange],
    );

    // Promote desktop floating dropdown into browser top-layer via Popover API (falls back to fixed z-[100]).
    React.useEffect(() => {
      if (!open || mobileMode) return;
      const el = popoverRef.current;
      if (!el) return;
      computeMenuPosition();
      const canPopover =
        typeof HTMLElement !== "undefined" &&
        "showPopover" in HTMLElement.prototype &&
        typeof (el as HTMLElement & { showPopover?: () => void }).showPopover === "function";
      if (canPopover) {
        try {
          (el as HTMLElement & { showPopover: () => void }).showPopover();
        } catch {
          // Ignore if already open or unsupported in current engine.
        }
      }
      const onPointerDown = (e: PointerEvent) => {
        const target = e.target as Node | null;
        if (!target) return;
        if (triggerRef.current?.contains(target)) return;
        if (popoverRef.current?.contains(target)) return;
        setOpen(false);
      };
      const onReposition = (e?: Event) => {
        const target = e?.target as Node | null;
        if (target && popoverRef.current?.contains(target)) return;
        computeMenuPosition();
      };
      window.addEventListener("pointerdown", onPointerDown, true);
      window.addEventListener("resize", onReposition);
      window.addEventListener("scroll", onReposition, true);
      return () => {
        window.removeEventListener("pointerdown", onPointerDown, true);
        window.removeEventListener("resize", onReposition);
        window.removeEventListener("scroll", onReposition, true);
        if (canPopover) {
          try {
            (el as HTMLElement & { hidePopover?: () => void }).hidePopover?.();
          } catch {
            // Ignore close races.
          }
        }
      };
    }, [open, mobileMode, computeMenuPosition]);

    const moveActive = (delta: number) => {
      if (options.length === 0) return;
      let next = activeIndex;
      for (let step = 0; step < options.length; step += 1) {
        next = (next + delta + options.length) % options.length;
        if (!options[next].disabled) {
          setActiveIndex(next);
          return;
        }
      }
    };

    const handleTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
      if (disabled) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        if (!open) openMenu();
        else moveActive(1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        if (!open) openMenu();
        else moveActive(-1);
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        if (!open) {
          openMenu();
        } else if (activeIndex >= 0 && options[activeIndex] && !options[activeIndex].disabled) {
          commitValue(options[activeIndex].value);
        }
      } else if (e.key === "Escape" && open) {
        e.preventDefault();
        e.stopPropagation();
        closeMenu();
      }
    };

    const renderOptionList = (forMobile: boolean) => {
      let lastGroup: string | undefined;
      return options.map((opt, idx) => {
        const isSelected = opt.value === currentValue;
        const isHighlighted = !forMobile && idx === activeIndex;
        const showGroupHeader = opt.group !== undefined && opt.group !== lastGroup;
        lastGroup = opt.group;
        return (
          <React.Fragment key={`${opt.group ?? ""}-${opt.value}-${idx}`}>
            {showGroupHeader && opt.group ? (
              <div className="px-2.5 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground select-none">
                {opt.group}
              </div>
            ) : null}
            <button
              type="button"
              role="option"
              aria-selected={isSelected}
              disabled={opt.disabled}
              onPointerDown={(e) => e.stopPropagation()}
              onMouseEnter={() => {
                if (!forMobile && !opt.disabled) setActiveIndex(idx);
              }}
              onClick={(e) => {
                e.stopPropagation();
                if (!opt.disabled) commitValue(opt.value);
              }}
              className={cn(
                "flex w-full items-center justify-between gap-2 text-left transition-colors disabled:opacity-45 disabled:cursor-not-allowed",
                forMobile
                  ? "min-h-11 rounded-[8px] px-3 py-2 text-[13px]"
                  : "min-h-8 rounded-[6px] px-2.5 py-1.5 text-xs",
                isSelected
                  ? "bg-primary/15 font-semibold text-primary"
                  : isHighlighted
                    ? "bg-muted text-foreground"
                    : "text-popover-foreground hover:bg-muted/70",
              )}
            >
              <span className="min-w-0 flex-1 truncate">{opt.label}</span>
              {isSelected ? (
                <Check className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
              ) : null}
            </button>
          </React.Fragment>
        );
      });
    };

    const sheetTitle =
      ariaLabel ||
      title ||
      (typeof document !== "undefined" && document.documentElement.lang.startsWith("en")
        ? "Select option"
        : "请选择");

    return (
      <>
        <button
          ref={setMergedRef}
          id={id}
          type="button"
          role="combobox"
          disabled={disabled}
          aria-label={ariaLabel}
          aria-labelledby={ariaLabelledBy}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-controls={open ? listboxId : undefined}
          title={title}
          onClick={() => (open ? closeMenu() : openMenu())}
          onKeyDown={handleTriggerKeyDown}
          className={cn(
            "inline-flex w-full items-center justify-between gap-2 rounded-[6px] border border-input bg-background text-left text-foreground transition-[border-color,box-shadow,background-color] duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50",
            size === "sm"
              ? "min-h-[1.875rem] px-2.5 py-1 text-xs max-md:min-h-[var(--m-btn-sm-h)]"
              : "min-h-8 px-2.5 py-1.5 text-[13px] max-md:min-h-[var(--m-input-h)] max-md:text-[13px]",
            className,
          )}
        >
          <span className="min-w-0 flex-1 truncate">
            {selectedOption?.label ?? ""}
          </span>
          <ChevronDown
            className={cn(
              "keep-icon-size h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform duration-150",
              open && "rotate-180 text-primary",
            )}
            aria-hidden="true"
          />
        </button>

        {name ? <input type="hidden" name={name} value={currentValue} /> : null}

        {/* Desktop Viewport-Aware Glass Popover (top-layer promoted via Popover API;
            portaled into nearest <dialog> ancestor when inside a modal dialog so it is never inert) */}
        {open && !mobileMode && typeof document !== "undefined"
          ? createPortal(
              <div
                ref={popoverRef}
                {...({ popover: "manual" } as Record<string, string>)}
                style={{
                  position: "fixed",
                  top: `${menuPos.top}px`,
                  left: `${menuPos.left}px`,
                  width: `${menuPos.width}px`,
                  zIndex: 100,
                }}
                className="custom-select-popover"
                onPointerDown={(e) => e.stopPropagation()}
                onClick={(e) => e.stopPropagation()}
              >
                <div
                  id={listboxId}
                  role="listbox"
                  aria-label={sheetTitle}
                  style={{ maxHeight: `${menuPos.maxHeight}px` }}
                  className="overflow-y-auto rounded-[10px] border border-border bg-popover/95 p-1 text-popover-foreground shadow-xl backdrop-blur-md space-y-0.5"
                >
                  {renderOptionList(false)}
                </div>
              </div>,
              triggerRef.current?.closest("dialog") ?? document.body,
            )
          : null}

        {/* Mobile Bottom Sheet Picker (<768px) */}
        <BottomSheetDialog
          open={open && mobileMode}
          title={sheetTitle}
          onClose={closeMenu}
        >
          <div id={listboxId} role="listbox" aria-label={sheetTitle} className="space-y-1 pb-1">
            {renderOptionList(true)}
          </div>
        </BottomSheetDialog>
      </>
    );
  },
);

Select.displayName = "Select";
