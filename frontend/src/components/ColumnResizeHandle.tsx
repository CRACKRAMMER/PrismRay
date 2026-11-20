// SPDX-License-Identifier: MPL-2.0

import React from "react";

export function ColumnResizeHandle({
  active,
  title,
  onPointerDown,
  onDoubleClick,
}: {
  active?: boolean;
  title?: string;
  onPointerDown: (e: React.PointerEvent<HTMLDivElement>) => void;
  onDoubleClick: () => void;
}) {
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      title={title}
      onPointerDown={onPointerDown}
      onDoubleClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onDoubleClick();
      }}
      onClick={(e) => e.stopPropagation()}
      className={`col-resize-handle ${active ? "is-active" : ""}`}
    />
  );
}
