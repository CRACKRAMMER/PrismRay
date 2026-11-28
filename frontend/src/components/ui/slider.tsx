// SPDX-License-Identifier: MPL-2.0

import * as React from "react";
import { cn } from "../../lib/utils.ts";

export type SliderProps = Omit<React.InputHTMLAttributes<HTMLInputElement>, "type">;

export const Slider = React.forwardRef<HTMLInputElement, SliderProps>(
  ({ className, min = 0, max = 100, value, defaultValue, style, onInput, onChange, ...props }, ref) => {
    const minNum = Number(min) || 0;
    const maxNum = Number(max);
    const upper = Number.isFinite(maxNum) && maxNum > minNum ? maxNum : minNum + 100;
    const rawVal = value !== undefined ? Number(value) : Number(defaultValue ?? minNum);
    const clampedVal = Number.isFinite(rawVal) ? Math.min(upper, Math.max(minNum, rawVal)) : minNum;
    const [pct, setPct] = React.useState(() => ((clampedVal - minNum) / (upper - minNum)) * 100);

    React.useEffect(() => {
      if (value !== undefined) {
        const nextVal = Math.min(upper, Math.max(minNum, Number(value) || minNum));
        setPct(((nextVal - minNum) / (upper - minNum)) * 100);
      }
    }, [value, minNum, upper]);

    const syncProgress = (target: HTMLInputElement) => {
      const next = Math.min(upper, Math.max(minNum, Number(target.value) || minNum));
      setPct(((next - minNum) / (upper - minNum)) * 100);
    };

    return (
      <input
        ref={ref}
        type="range"
        min={min}
        max={max}
        value={value}
        defaultValue={defaultValue}
        style={
          {
            "--slider-progress": `${pct.toFixed(2)}%`,
            ...style,
          } as React.CSSProperties
        }
        onInput={(e) => {
          syncProgress(e.currentTarget);
          onInput?.(e);
        }}
        onChange={(e) => {
          syncProgress(e.currentTarget);
          onChange?.(e);
        }}
        className={cn("prism-slider w-full", className)}
        {...props}
      />
    );
  },
);

Slider.displayName = "Slider";
