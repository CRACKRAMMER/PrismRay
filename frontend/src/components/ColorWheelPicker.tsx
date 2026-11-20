// SPDX-License-Identifier: MPL-2.0

import React, { useCallback, useEffect, useId, useRef, useState } from "react";
import { Pipette, X } from "lucide-react";
import {
  clampNumber,
  contrastRatioForHex,
  hexToRgb,
  hsvToRgb,
  normalizeHexColor,
  pickAccessibleForeground,
  rgbToHex,
  rgbToHsv,
} from "../lib/appearance.ts";

export interface ColorWheelPickerProps {
  /** Active hex color (e.g. "#059669") */
  value: string;
  /** Whether a custom (non-preset) color is active */
  selected?: boolean;
  /** Button label */
  label: string;
  /** Title shown inside the color wheel popover */
  title: string;
  /** Callback invoked live whenever user drags the wheel or edits HEX/RGB */
  onChange: (hex: string) => void;
}

const WHEEL_SIZE = 188;

/**
 * Custom circular HSV/RGB color wheel popover rendered on a HiDPI canvas,
 * replacing the inconsistent OS/GTK native <input type="color"> dialog.
 */
export function ColorWheelPicker({
  value,
  selected = false,
  label,
  title,
  onChange,
}: ColorWheelPickerProps) {
  const popId = `cwp-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const initialRgb = hexToRgb(value) ?? { r: 79, g: 70, b: 229 };
  const initialHsv = rgbToHsv(initialRgb.r, initialRgb.g, initialRgb.b);

  const [open, setOpen] = useState(false);
  const [hsv, setHsv] = useState(initialHsv);
  const [hexDraft, setHexDraft] = useState(rgbToHex(initialRgb.r, initialRgb.g, initialRgb.b));

  // Sync external color changes into internal HSV state when picker is closed or preset clicked
  useEffect(() => {
    const rgb = hexToRgb(value);
    if (!rgb) return;
    const currentHex = rgbToHex(
      hsvToRgb(hsv.h, hsv.s, hsv.v).r,
      hsvToRgb(hsv.h, hsv.s, hsv.v).g,
      hsvToRgb(hsv.h, hsv.s, hsv.v).b,
    );
    const norm = normalizeHexColor(value);
    if (norm && norm !== currentHex) {
      setHsv(rgbToHsv(rgb.r, rgb.g, rgb.b));
      setHexDraft(norm);
    }
  }, [value]);

  const rgb = hsvToRgb(hsv.h, hsv.s, hsv.v);
  const currentHex = rgbToHex(rgb.r, rgb.g, rgb.b);
  const fgHex = pickAccessibleForeground(currentHex);
  const contrast = contrastRatioForHex(currentHex, fgHex);

  const commitHsv = useCallback(
    (next: { h: number; s: number; v: number }) => {
      setHsv(next);
      const nextRgb = hsvToRgb(next.h, next.s, next.v);
      const nextHex = rgbToHex(nextRgb.r, nextRgb.g, nextRgb.b);
      setHexDraft(nextHex);
      onChange(nextHex);
    },
    [onChange],
  );

  // Draw crisp circular HSV color wheel on HiDPI canvas
  useEffect(() => {
    if (!open) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const pxSize = Math.round(WHEEL_SIZE * dpr);
    if (canvas.width !== pxSize || canvas.height !== pxSize) {
      canvas.width = pxSize;
      canvas.height = pxSize;
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const img = ctx.createImageData(pxSize, pxSize);
    const data = img.data;
    const radius = pxSize / 2;
    const v = hsv.v;

    for (let y = 0; y < pxSize; y++) {
      const dy = y - radius + 0.5;
      for (let x = 0; x < pxSize; x++) {
        const dx = x - radius + 0.5;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const idx = (y * pxSize + x) * 4;
        if (dist <= radius) {
          const sat = Math.min(1, dist / radius);
          let deg = (Math.atan2(dy, dx) * 180) / Math.PI;
          if (deg < 0) deg += 360;
          const c = hsvToRgb(deg, sat, v);
          data[idx] = c.r;
          data[idx + 1] = c.g;
          data[idx + 2] = c.b;
          // Anti-alias outer 1.5px circle edge
          const edgeAlpha = dist > radius - 1.5 ? Math.max(0, (radius - dist) / 1.5) : 1;
          data[idx + 3] = Math.round(edgeAlpha * 255);
        } else {
          data[idx + 3] = 0;
        }
      }
    }
    ctx.putImageData(img, 0, 0);
  }, [open, hsv.v]);

  const positionPopover = useCallback(() => {
    const trigger = triggerRef.current;
    const pop = popRef.current;
    if (!trigger || !pop) return;
    const rect = trigger.getBoundingClientRect();
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const margin = 12;
    const gap = 8;
    const popW = pop.offsetWidth || 256;
    const popH = pop.offsetHeight || 348;

    let top = rect.bottom + gap;
    if (top + popH > vh - margin) {
      top = Math.max(margin, rect.top - popH - gap);
    }
    let left = rect.left + rect.width / 2 - popW / 2;
    left = Math.max(margin, Math.min(vw - popW - margin, left));

    pop.style.top = `${Math.round(top)}px`;
    pop.style.left = `${Math.round(left)}px`;
  }, []);

  const showPicker = useCallback(() => {
    const pop = popRef.current as (HTMLDivElement & { showPopover?: () => void }) | null;
    if (!pop) return;
    try {
      if (typeof pop.showPopover === "function") {
        if (!pop.matches(":popover-open")) pop.showPopover();
      } else {
        pop.setAttribute("data-open", "true");
      }
    } catch {
      pop.setAttribute("data-open", "true");
    }
    setOpen(true);
    window.requestAnimationFrame(positionPopover);
  }, [positionPopover]);

  const hidePicker = useCallback(() => {
    const pop = popRef.current as (HTMLDivElement & { hidePopover?: () => void }) | null;
    if (!pop) return;
    try {
      if (typeof pop.hidePopover === "function") {
        if (pop.matches(":popover-open")) pop.hidePopover();
      } else {
        pop.removeAttribute("data-open");
      }
    } catch {
      pop.removeAttribute("data-open");
    }
    setOpen(false);
  }, []);

  useEffect(() => {
    const pop = popRef.current;
    if (!pop) return;
    const onToggle = (ev: Event) => {
      const toggleEv = ev as Event & { newState?: string };
      const isOpen = toggleEv.newState === "open";
      setOpen(isOpen);
      if (isOpen) window.requestAnimationFrame(positionPopover);
    };
    pop.addEventListener("toggle", onToggle);
    return () => pop.removeEventListener("toggle", onToggle);
  }, [positionPopover]);

  useEffect(() => {
    if (!open) return;
    const onReposition = () => positionPopover();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") hidePicker();
    };
    const onDocDown = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (t && (triggerRef.current?.contains(t) || popRef.current?.contains(t))) return;
      hidePicker();
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
  }, [open, positionPopover, hidePicker]);

  const pickAtClientPoint = useCallback(
    (clientX: number, clientY: number) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const radius = rect.width / 2;
      const dx = clientX - (rect.left + radius);
      const dy = clientY - (rect.top + radius);
      const dist = Math.min(radius, Math.sqrt(dx * dx + dy * dy));
      let hue = (Math.atan2(dy, dx) * 180) / Math.PI;
      if (hue < 0) hue += 360;
      const sat = radius > 0 ? dist / radius : 0;
      commitHsv({ h: hue, s: sat, v: hsv.v });
    },
    [commitHsv, hsv.v],
  );

  const onWheelPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const target = e.currentTarget;
    try {
      target.setPointerCapture(e.pointerId);
    } catch {
      // Synthetic event fallback.
    }
    pickAtClientPoint(e.clientX, e.clientY);

    const onMove = (ev: PointerEvent) => pickAtClientPoint(ev.clientX, ev.clientY);
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
  };

  // Compute reticle marker position inside the wheel
  const rad = (hsv.h * Math.PI) / 180;
  const rPx = hsv.s * (WHEEL_SIZE / 2);
  const reticleX = WHEEL_SIZE / 2 + Math.cos(rad) * rPx;
  const reticleY = WHEEL_SIZE / 2 + Math.sin(rad) * rPx;

  const pureHueRgb = hsvToRgb(hsv.h, hsv.s, 1);
  const pureHueHex = rgbToHex(pureHueRgb.r, pureHueRgb.g, pureHueRgb.b);

  const handleRgbChannel = (channel: "r" | "g" | "b", rawVal: string) => {
    const num = Math.round(clampNumber(Number(rawVal), 0, 255, 0));
    const nextRgb = { ...rgb, [channel]: num };
    const nextHsv = rgbToHsv(nextRgb.r, nextRgb.g, nextRgb.b);
    setHsv(nextHsv);
    const nextHex = rgbToHex(nextRgb.r, nextRgb.g, nextRgb.b);
    setHexDraft(nextHex);
    onChange(nextHex);
  };

  const handleHexInput = (raw: string) => {
    setHexDraft(raw);
    const norm = normalizeHexColor(raw);
    if (norm) {
      const parsed = hexToRgb(norm);
      if (parsed) {
        setHsv(rgbToHsv(parsed.r, parsed.g, parsed.b));
        onChange(norm);
      }
    }
  };

  return (
    <span className="inline-flex items-center">
      <button
        ref={triggerRef}
        type="button"
        aria-expanded={open}
        aria-controls={popId}
        onClick={() => (open ? hidePicker() : showPicker())}
        className={[
          "inline-flex items-center gap-1.5 rounded-[6px] border px-2.5 py-1 text-xs font-medium transition-colors",
          selected || open
            ? "border-primary bg-primary/15 text-primary"
            : "border-border bg-background text-muted-foreground hover:border-primary/50 hover:text-foreground",
        ].join(" ")}
      >
        <span
          className="color-swatch-chip h-3.5 w-3.5 shrink-0 rounded-full border border-black/20 dark:border-white/25"
          style={{ backgroundColor: currentHex }}
          aria-hidden="true"
        />
        <Pipette className="h-3 w-3 shrink-0 opacity-75" aria-hidden="true" />
        <span>{label}</span>
      </button>

      <div
        ref={popRef}
        id={popId}
        role="dialog"
        aria-label={title}
        {...({ popover: "auto" } as Record<string, string>)}
        className="colorwheel-popover"
      >
        <div className="flex items-center justify-between gap-2 border-b border-border pb-2">
          <div className="flex items-center gap-2 min-w-0">
            <span
              className="color-swatch-chip h-5 w-5 shrink-0 rounded-full border border-black/15 shadow-inner dark:border-white/25"
              style={{ backgroundColor: currentHex }}
              aria-hidden="true"
            />
            <span className="truncate text-xs font-semibold text-foreground">{title}</span>
          </div>
          <button
            type="button"
            onClick={hidePicker}
            aria-label="Close"
            className="inline-flex h-6 w-6 min-h-0 items-center justify-center rounded-[5px] text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>

        {/* Circular HSV Color Wheel */}
        <div className="flex justify-center py-2.5">
          <div
            className="relative select-none"
            style={{ width: `${WHEEL_SIZE}px`, height: `${WHEEL_SIZE}px` }}
          >
            <canvas
              ref={canvasRef}
              onPointerDown={onWheelPointerDown}
              className="color-swatch-chip block h-full w-full cursor-crosshair rounded-full shadow-md ring-1 ring-border"
              style={{ touchAction: "none" }}
              aria-label={title}
            />
            <span
              className="color-swatch-chip pointer-events-none absolute h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-white shadow-[0_0_0_1.5px_rgba(0,0,0,0.45)]"
              style={{
                left: `${reticleX}px`,
                top: `${reticleY}px`,
                backgroundColor: currentHex,
              }}
              aria-hidden="true"
            />
          </div>
        </div>

        {/* Brightness (Value) Slider */}
        <div className="space-y-1 pb-2.5">
          <div className="flex items-center justify-between text-[11px] text-muted-foreground">
            <span>Brightness</span>
            <span className="tabular-nums font-medium text-foreground">{Math.round(hsv.v * 100)}%</span>
          </div>
          <input
            type="range"
            min={10}
            max={100}
            step={1}
            aria-label="Brightness"
            value={Math.round(hsv.v * 100)}
            onChange={(e) => commitHsv({ ...hsv, v: clampNumber(Number(e.target.value) / 100, 0.1, 1, 0.9) })}
            className="color-swatch-chip colorwheel-value-slider w-full cursor-pointer"
            style={{
              background: `linear-gradient(90deg, #111827 0%, ${pureHueHex} 100%)`,
            }}
          />
        </div>

        {/* Live HEX + RGB Inputs */}
        <div className="grid grid-cols-[1.5fr_1fr_1fr_1fr] gap-1.5 text-[11px]">
          <label className="space-y-0.5">
            <span className="block text-[10px] font-medium text-muted-foreground">HEX</span>
            <input
              type="text"
              value={hexDraft}
              onChange={(e) => handleHexInput(e.target.value)}
              spellCheck={false}
              className="h-7 min-h-0 w-full rounded-[5px] border border-input bg-background px-1.5 font-mono text-[11px] text-foreground outline-none focus:border-primary"
            />
          </label>
          {(["r", "g", "b"] as const).map((ch) => (
            <label key={ch} className="space-y-0.5">
              <span className="block text-[10px] font-medium uppercase text-muted-foreground">{ch}</span>
              <input
                type="number"
                min={0}
                max={255}
                value={rgb[ch]}
                onChange={(e) => handleRgbChannel(ch, e.target.value)}
                className="h-7 min-h-0 w-full rounded-[5px] border border-input bg-background px-1.5 text-center tabular-nums text-[11px] text-foreground outline-none focus:border-primary"
              />
            </label>
          ))}
        </div>

        {/* Live Contrast Preview Pill */}
        <div className="mt-2.5 flex items-center justify-between gap-2 border-t border-border pt-2 text-[11px]">
          <span
            className="color-swatch-chip inline-flex items-center rounded-[5px] px-2 py-0.5 text-[11px] font-medium"
            style={{ backgroundColor: currentHex, color: fgHex }}
          >
            Aa {currentHex.toUpperCase()}
          </span>
          <span className="tabular-nums text-muted-foreground">
            WCAG {contrast.toFixed(1)}:1 {contrast >= 4.5 ? "AA" : "OK"}
          </span>
        </div>
      </div>
    </span>
  );
}
