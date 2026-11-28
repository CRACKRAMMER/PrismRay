// SPDX-License-Identifier: MPL-2.0

import * as React from "react";
import { cn } from "../../lib/utils.ts";

export interface CheckboxProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type" | "size"> {
  indeterminate?: boolean;
  size?: "sm" | "default";
}

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, indeterminate = false, size = "default", ...props }, ref) => {
    const innerRef = React.useRef<HTMLInputElement | null>(null);

    const setMergedRef = React.useCallback(
      (node: HTMLInputElement | null) => {
        innerRef.current = node;
        if (typeof ref === "function") {
          ref(node);
        } else if (ref) {
          ref.current = node;
        }
      },
      [ref],
    );

    React.useEffect(() => {
      if (innerRef.current) {
        innerRef.current.indeterminate = Boolean(indeterminate);
      }
    }, [indeterminate]);

    return (
      <input
        ref={setMergedRef}
        type="checkbox"
        className={cn(
          "prism-checkbox shrink-0",
          size === "sm" && "prism-checkbox-sm",
          className,
        )}
        {...props}
      />
    );
  },
);

Checkbox.displayName = "Checkbox";
