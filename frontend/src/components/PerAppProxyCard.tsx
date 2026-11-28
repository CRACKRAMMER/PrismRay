// SPDX-License-Identifier: MPL-2.0

import { Smartphone } from "lucide-react";
import { useAppStore } from "../store/appStore.ts";
import { AndroidAppPicker } from "./AndroidAppPicker.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";

type PerAppMode = "all" | "whitelist" | "blacklist";

interface PerAppProxyCardProps {
  mode: string;
  packages: string[];
  onChangeMode: (mode: PerAppMode) => void;
  onChangePackages: (packages: string[]) => void;
}

export function PerAppProxyCard({
  mode,
  packages,
  onChangeMode,
  onChangePackages,
}: PerAppProxyCardProps) {
  const { tr } = useAppStore();
  const normalizedMode: PerAppMode =
    mode === "whitelist" || mode === "blacklist" ? mode : "all";

  const modeDesc =
    normalizedMode === "whitelist"
      ? tr("routing.perAppModeWhitelistDesc")
      : normalizedMode === "blacklist"
        ? tr("routing.perAppModeBlacklistDesc")
        : tr("routing.perAppModeAllDesc");

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Smartphone className="h-4 w-4 text-primary" aria-hidden="true" />
            {tr("routing.perAppTitle")}
          </CardTitle>
          {normalizedMode !== "all" ? (
            <span className="badge-radius border border-primary/30 bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary mono-num">
              {tr("routing.perAppSelectedBadge", { count: packages.length })}
            </span>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* 3-Way Segmented Mode Selector */}
        <div className="grid grid-cols-3 gap-1.5 rounded-[8px] border border-border bg-muted/40 p-1">
          {(
            [
              { id: "all", label: tr("routing.perAppModeAllShort") },
              { id: "whitelist", label: tr("routing.perAppModeWhitelistShort") },
              { id: "blacklist", label: tr("routing.perAppModeBlacklistShort") },
            ] as const
          ).map((item) => {
            const active = normalizedMode === item.id;
            return (
              <button
                key={item.id}
                type="button"
                aria-pressed={active}
                onClick={() => onChangeMode(item.id)}
                className={[
                  "rounded-[6px] px-2 py-1.5 text-xs font-medium transition-colors text-center truncate",
                  active
                    ? "bg-primary text-primary-foreground shadow-xs"
                    : "text-muted-foreground hover:bg-background/70 hover:text-foreground",
                ].join(" ")}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        <p className="text-xs leading-relaxed text-muted-foreground">{modeDesc}</p>

        {normalizedMode === "whitelist" ? (
          <div className="rounded-[8px] border border-amber-500/35 bg-amber-500/10 px-3 py-2 text-xs leading-relaxed text-amber-700 dark:text-amber-300">
            {tr("routing.perAppWhitelistPlayHint")}
          </div>
        ) : null}

        {normalizedMode !== "all" ? (
          <AndroidAppPicker
            packages={packages}
            onChangePackages={onChangePackages}
            active
          />
        ) : null}
      </CardContent>
    </Card>
  );
}
