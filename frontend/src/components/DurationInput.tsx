// SPDX-License-Identifier: MPL-2.0

import {
  ALL_DURATION_UNITS,
  type DurationUnit,
  durationUnitLabel,
} from "../lib/duration.ts";
import { Select } from "./ui/select.tsx";

export interface DurationInputProps {
  value: number;
  unit: DurationUnit;
  units?: DurationUnit[];
  locale: "zh-CN" | "en-US";
  min?: number;
  max?: number;
  step?: number;
  ariaLabel?: string;
  unitAriaLabel?: string;
  placeholder?: string;
  disabled?: boolean;
  onChange: (nextValue: number, nextUnit: DurationUnit) => void;
}

/**
 * Composite duration input combining a numeric input and a unit dropdown
 * (ms / s / m / h / d) inside a single unified control frame.
 */
export function DurationInput({
  value,
  unit,
  units = ALL_DURATION_UNITS,
  locale,
  min = 0,
  max,
  step = 1,
  ariaLabel,
  unitAriaLabel,
  placeholder,
  disabled = false,
  onChange,
}: DurationInputProps) {
  const effectiveUnits = units.length > 0 ? units : ALL_DURATION_UNITS;
  const effectiveUnit = effectiveUnits.includes(unit) ? unit : effectiveUnits[0];

  return (
    <div
      className={[
        "duration-input-group flex h-8 max-md:h-[var(--m-input-h)] w-full items-stretch overflow-hidden rounded-[6px] border border-input bg-background transition-[border-color,box-shadow] duration-150",
        "focus-within:border-primary focus-within:ring-2 focus-within:ring-ring/40",
        disabled ? "opacity-50 pointer-events-none" : "",
      ].join(" ")}
    >
      <input
        type="number"
        min={min}
        max={max}
        step={step}
        disabled={disabled}
        aria-label={ariaLabel}
        placeholder={placeholder}
        value={Number.isFinite(value) ? value : 0}
        onChange={(e) => {
          const raw = e.target.value;
          const num = raw === "" ? 0 : Number(raw);
          if (Number.isFinite(num)) {
            const clamped = Math.max(min, max !== undefined ? Math.min(max, num) : num);
            onChange(clamped, effectiveUnit);
          }
        }}
        className="min-w-0 flex-1 bg-transparent px-2.5 text-[13px] text-foreground tabular-nums outline-none min-h-0"
      />
      <Select
        size="sm"
        disabled={disabled}
        aria-label={unitAriaLabel || `${ariaLabel || "Duration"} unit`}
        value={effectiveUnit}
        onChange={(e) => onChange(value, e.target.value as DurationUnit)}
        className="w-auto min-w-[4.5rem] shrink-0 rounded-none border-0 border-l border-input bg-muted/45 px-2 text-xs font-medium text-foreground min-h-0 h-full max-md:min-h-0 hover:bg-muted/75 focus-visible:ring-inset"
      >
        {effectiveUnits.map((u) => (
          <option key={u} value={u}>
            {durationUnitLabel(u, locale)}
          </option>
        ))}
      </Select>
    </div>
  );
}
