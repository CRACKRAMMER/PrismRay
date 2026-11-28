// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useRef } from "react";
import { cn } from "../../lib/utils.ts";

export interface ModalDialogProps {
  open: boolean;
  onClose: () => void;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  className?: string;
  children: React.ReactNode;
}

/**
 * Accessible native modal <dialog> wrapper promoted to browser top layer via showModal().
 * Uses native closedby="any" light dismiss where supported with a bounding-box pointer fallback.
 */
export function ModalDialog({
  open,
  onClose,
  ariaLabel,
  ariaLabelledBy,
  className,
  children,
}: ModalDialogProps) {
  const dlgRef = useRef<HTMLDialogElement | null>(null);
  const pointerDownOutsideRef = useRef(false);

  useEffect(() => {
    const dlg = dlgRef.current;
    if (!dlg) return;
    if (open) {
      pointerDownOutsideRef.current = false;
      if (!dlg.open) {
        dlg.showModal();
        dlg.focus({ preventScroll: true });
      }
    } else if (dlg.open) {
      pointerDownOutsideRef.current = false;
      dlg.close();
    }
  }, [open]);

  const supportsClosedBy =
    typeof HTMLDialogElement !== "undefined" && "closedBy" in HTMLDialogElement.prototype;

  const isPointerOutside = (e: React.MouseEvent<HTMLDialogElement>, dialog: HTMLDialogElement) => {
    const r = dialog.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  };

  return (
    <dialog
      ref={dlgRef}
      tabIndex={-1}
      aria-label={ariaLabel}
      aria-labelledby={ariaLabelledBy}
      {...({ closedby: "any" } as Record<string, string>)}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClose={() => {
        if (open) onClose();
      }}
      onPointerDown={(e) => {
        if (supportsClosedBy) return;
        const dlg = dlgRef.current;
        pointerDownOutsideRef.current = Boolean(
          dlg && e.target === dlg && isPointerOutside(e, dlg),
        );
      }}
      onClick={(e) => {
        if (supportsClosedBy) return;
        const dlg = dlgRef.current;
        const startedOutside = pointerDownOutsideRef.current;
        pointerDownOutsideRef.current = false;
        if (startedOutside && dlg && e.target === dlg && isPointerOutside(e, dlg)) {
          onClose();
        }
      }}
      className={cn("prism-modal-dialog outline-none", className)}
    >
      {children}
    </dialog>
  );
}
