// SPDX-License-Identifier: MPL-2.0

import { RefreshCw, ServerCrash } from "lucide-react";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "./ui/card.tsx";

interface ConnectionErrorProps {
  endpoint: string;
  error: string;
  retrying?: boolean;
  onRetry: () => void;
}

export function ConnectionError({ endpoint, error, retrying = false, onRetry }: ConnectionErrorProps) {
  const { tr } = useAppStore();

  return (
    <div className="flex min-h-dvh items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md border-destructive/40 shadow-lg">
        <CardHeader className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-2 rounded-full bg-destructive/15 px-3 py-1 text-xs font-semibold text-destructive">
              <ServerCrash className="h-3.5 w-3.5" aria-hidden="true" />
              {tr("auth.connectErrorTag")}
            </span>
          </div>
          <CardTitle className="text-xl">{tr("auth.connectErrorTitle")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="rounded-lg border bg-muted/60 p-3">
            <div className="text-xs font-medium text-muted-foreground">{tr("auth.apiEndpoint")}</div>
            <div className="mt-1 font-mono text-xs break-all text-foreground">{endpoint}</div>
          </div>
          {error ? (
            <p className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-xs leading-relaxed text-destructive break-words">
              {error}
            </p>
          ) : null}
        </CardContent>
        <CardFooter>
          <Button type="button" className="w-full" onClick={onRetry} disabled={retrying}>
            <RefreshCw className={`mr-2 h-4 w-4 ${retrying ? "animate-spin" : ""}`} aria-hidden="true" />
            {retrying ? tr("auth.retrying") : tr("auth.retry")}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
