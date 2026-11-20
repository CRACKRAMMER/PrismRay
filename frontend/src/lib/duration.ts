// SPDX-License-Identifier: MPL-2.0

export type DurationUnit = "ms" | "s" | "m" | "h" | "d";

export interface DurationParts {
  value: number;
  unit: DurationUnit;
}

export const ALL_DURATION_UNITS: DurationUnit[] = ["ms", "s", "m", "h", "d"];

const UNIT_TO_MS: Record<DurationUnit, number> = {
  ms: 1,
  s: 1000,
  m: 60 * 1000,
  h: 3600 * 1000,
  d: 24 * 3600 * 1000,
};

export function durationUnitLabel(unit: DurationUnit, locale: "zh-CN" | "en-US"): string {
  if (locale === "zh-CN") {
    switch (unit) {
      case "ms":
        return "毫秒";
      case "s":
        return "秒";
      case "m":
        return "分";
      case "h":
        return "时";
      case "d":
        return "天";
    }
  }
  switch (unit) {
    case "ms":
      return "ms";
    case "s":
      return "sec";
    case "m":
      return "min";
    case "h":
      return "hr";
    case "d":
      return "day";
  }
}

function cleanNumeric(n: number): number {
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.round(n * 1000) / 1000;
}

/**
 * Pick the largest allowed unit that divides `totalMs` cleanly (or the smallest allowed unit if 0).
 */
export function splitMilliseconds(
  totalMs: number,
  allowedUnits: DurationUnit[] = ALL_DURATION_UNITS,
  fallbackUnit: DurationUnit = "ms",
): DurationParts {
  const safe = Math.max(0, Number.isFinite(totalMs) ? totalMs : 0);
  const units = allowedUnits.length > 0 ? allowedUnits : ALL_DURATION_UNITS;
  if (safe === 0) {
    return { value: 0, unit: units.includes(fallbackUnit) ? fallbackUnit : units[0] };
  }
  // Check from largest to smallest for an exact integer fit
  const descending: DurationUnit[] = ["d", "h", "m", "s", "ms"].filter((u) =>
    units.includes(u as DurationUnit),
  ) as DurationUnit[];
  for (const unit of descending) {
    const factor = UNIT_TO_MS[unit];
    if (safe >= factor && safe % factor === 0) {
      return { value: safe / factor, unit };
    }
  }
  // Otherwise pick the smallest allowed unit
  const smallest = descending[descending.length - 1] ?? fallbackUnit;
  return { value: cleanNumeric(safe / UNIT_TO_MS[smallest]), unit: smallest };
}

export function joinToMilliseconds(value: number, unit: DurationUnit): number {
  const safe = Math.max(0, Number.isFinite(value) ? value : 0);
  return Math.round(safe * UNIT_TO_MS[unit]);
}

export function splitSeconds(
  totalSeconds: number,
  allowedUnits: DurationUnit[] = ["s", "m", "h", "d"],
  fallbackUnit: DurationUnit = "s",
): DurationParts {
  return splitMilliseconds(Math.max(0, totalSeconds) * 1000, allowedUnits, fallbackUnit);
}

export function joinToSeconds(value: number, unit: DurationUnit): number {
  return Math.round(joinToMilliseconds(value, unit) / 1000);
}

export function splitHours(
  totalHours: number,
  allowedUnits: DurationUnit[] = ["h", "d"],
  fallbackUnit: DurationUnit = "h",
): DurationParts {
  const safe = Math.max(0, Number.isFinite(totalHours) ? Math.round(totalHours) : 0);
  if (safe === 0) {
    return { value: 0, unit: allowedUnits.includes(fallbackUnit) ? fallbackUnit : allowedUnits[0] || "h" };
  }
  if (allowedUnits.includes("d") && safe >= 24 && safe % 24 === 0) {
    return { value: safe / 24, unit: "d" };
  }
  return { value: safe, unit: "h" };
}

export function joinToHours(value: number, unit: DurationUnit): number {
  const safe = Math.max(0, Number.isFinite(value) ? value : 0);
  if (unit === "d") return Math.round(safe * 24);
  if (unit === "h") return Math.round(safe);
  return Math.round(joinToMilliseconds(safe, unit) / (3600 * 1000));
}

/**
 * Parse a Go duration string (e.g. "500ms", "30s", "5m", "2h", "24h", "1h30m", or "1d")
 * into total milliseconds, then split into clean numeric value + unit.
 */
export function parseGoDuration(
  raw: string | null | undefined,
  allowedUnits: DurationUnit[] = ALL_DURATION_UNITS,
  fallback: DurationParts = { value: 5, unit: "m" },
): DurationParts {
  const s = (raw || "").trim().toLowerCase();
  if (!s) return fallback;

  // Match compound or single segments like "1d", "2h30m", "500ms", "5m"
  const tokenRegex = /(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)/g;
  let totalMs = 0;
  let matched = false;
  let m: RegExpExecArray | null;
  while ((m = tokenRegex.exec(s)) !== null) {
    const num = Number(m[1]);
    const unit = m[2] as DurationUnit;
    if (Number.isFinite(num) && unit in UNIT_TO_MS) {
      totalMs += num * UNIT_TO_MS[unit];
      matched = true;
    }
  }
  if (!matched) {
    const plain = Number(s);
    if (Number.isFinite(plain) && plain >= 0) {
      return { value: plain, unit: fallback.unit };
    }
    return fallback;
  }
  return splitMilliseconds(Math.round(totalMs), allowedUnits, fallback.unit);
}

/**
 * Format numeric value + unit into a Go `time.ParseDuration`-compatible string.
 * Go's `time.ParseDuration` does not recognize "d", so days are serialized as `${value * 24}h`.
 */
export function formatGoDuration(value: number, unit: DurationUnit): string {
  const safe = cleanNumeric(value);
  if (safe <= 0) return `0${unit === "d" ? "h" : unit}`;
  if (unit === "d") {
    return `${cleanNumeric(safe * 24)}h`;
  }
  return `${safe}${unit}`;
}
