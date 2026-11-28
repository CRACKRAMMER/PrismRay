// SPDX-License-Identifier: MPL-2.0

import React, { useState } from "react";
import { AlertTriangle, CheckCircle2, Info, Loader2, Search, ShieldCheck } from "lucide-react";
import { api, formatApiError, type DNSDiagnosticsResponse, type SimulationResult } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card.tsx";
import { Input } from "./ui/input.tsx";

export function DnsDiagnosticsCard() {
  const { tr, notify } = useAppStore();
  const [tab, setTab] = useState<"dns" | "sim">("dns");
  const [domain, setDomain] = useState("www.google.com");
  const [simIp, setSimIp] = useState("");
  const [simPort, setSimPort] = useState("");
  const [running, setRunning] = useState(false);
  const [dnsResult, setDnsResult] = useState<DNSDiagnosticsResponse | null>(null);
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault();
    setRunning(true);
    try {
      if (tab === "dns") {
        const res = await api.runDnsDiagnostics(domain.trim() || "www.google.com");
        setDnsResult(res);
      } else {
        const res = await api.simulateRouting({
          domain: domain.trim() || undefined,
          ip: simIp.trim() || undefined,
          port: simPort.trim() ? Number(simPort) : undefined,
        });
        setSimResult(res);
      }
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setRunning(false);
    }
  };

  return (
    <Card>
      <CardHeader className="flex flex-col gap-2 pb-3 sm:flex-row sm:items-center sm:justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-4 w-4 text-primary" aria-hidden="true" />
          {tr("dnsDiag.title")}
        </CardTitle>
        <div className="inline-flex items-center rounded-[8px] border border-border bg-muted/40 p-0.5 text-xs">
          {(
            [
              { id: "dns", label: tr("dnsDiag.tabDns") },
              { id: "sim", label: tr("dnsDiag.tabSim") },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`rounded-[6px] px-2.5 py-1 text-[11px] font-medium transition-colors ${
                tab === item.id ? "bg-background text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </CardHeader>

      <CardContent className="space-y-3 text-xs">
        <form onSubmit={(e) => void handleRun(e)} className="flex flex-wrap items-center gap-2">
          <Input
            className="min-w-[12rem] flex-1 font-mono text-xs"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder={tr("dnsDiag.domainPlaceholder")}
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
          />
          {tab === "sim" ? (
            <>
              <Input
                className="w-36 font-mono text-xs"
                value={simIp}
                onChange={(e) => setSimIp(e.target.value)}
                placeholder="IP (optional)"
              />
              <Input
                type="number"
                className="w-24 font-mono text-xs"
                value={simPort}
                onChange={(e) => setSimPort(e.target.value)}
                placeholder="Port"
              />
            </>
          ) : null}
          <Button type="submit" size="sm" disabled={running}>
            {running ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
            ) : (
              <Search className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {running ? tr("dnsDiag.running") : tr("dnsDiag.runBtn")}
          </Button>
        </form>

        {tab === "dns" && dnsResult ? (
          <div className="space-y-3">
            <div
              className={`flex items-start gap-2 rounded-[8px] border px-3 py-2 ${
                dnsResult.leak_status === "warning"
                  ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                  : dnsResult.leak_status === "safe"
                    ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : "border-border bg-muted/30 text-muted-foreground"
              }`}
            >
              {dnsResult.leak_status === "warning" ? (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              ) : dnsResult.leak_status === "safe" ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              ) : (
                <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              )}
              <div className="min-w-0 space-y-1">
                <div className="font-semibold">
                  {dnsResult.leak_status === "warning"
                    ? tr("dnsDiag.statusWarn")
                    : dnsResult.leak_status === "safe"
                      ? tr("dnsDiag.statusSafe")
                      : tr("dnsDiag.statusInfo")}
                </div>
                <div className="text-[11px] opacity-90">
                  {tr("dnsDiag.matchedRoute")}: <strong className="font-mono">{dnsResult.simulation.outbound}</strong>{" "}
                  ({dnsResult.simulation.matched_rule}) · FakeIP={dnsResult.fake_ip ? "ON" : "OFF"} · HijackDNS=
                  {dnsResult.hijack_dns ? "ON" : "OFF"}
                </div>
                {dnsResult.notes?.length > 0 ? (
                  <ul className="list-disc pl-4 text-[11px] space-y-0.5 opacity-90">
                    {dnsResult.notes.map((n, idx) => (
                      <li key={idx}>{n}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              {[
                { label: tr("dnsDiag.systemDns"), step: dnsResult.system_resolver },
                { label: tr("dnsDiag.localDns"), step: dnsResult.local_dns },
                { label: tr("dnsDiag.remoteDns"), step: dnsResult.remote_dns },
              ].map(({ label, step }) => (
                <div key={step.name} className="space-y-1 rounded-[8px] border border-border bg-muted/20 p-2.5">
                  <div className="flex items-center justify-between gap-1.5">
                    <span className="font-semibold text-foreground">{label}</span>
                    <span className="mono-num text-[10px] text-muted-foreground">{step.latency_ms} ms</span>
                  </div>
                  <div className="truncate font-mono text-[10px] text-muted-foreground" title={step.server}>
                    {step.server} ({step.via_proxy ? tr("dnsDiag.viaProxy") : tr("dnsDiag.direct")})
                  </div>
                  {step.error ? (
                    <div className="break-words text-[11px] text-destructive">{step.error}</div>
                  ) : step.ips?.length > 0 ? (
                    <div className="flex flex-wrap gap-1 pt-0.5">
                      {step.ips.slice(0, 4).map((ip) => (
                        <span
                          key={ip}
                          className="rounded bg-background px-1.5 py-0.5 font-mono text-[10px] text-foreground border border-border/70"
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] text-muted-foreground">—</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {tab === "sim" && simResult ? (
          <div className="rounded-[8px] border border-primary/30 bg-primary/5 px-3 py-2 text-xs">
            <span className="font-semibold text-primary">{simResult.outbound}</span>
            <span className="mx-2 text-muted-foreground">·</span>
            <span className="font-mono text-foreground">{simResult.matched_rule}</span>
            <span className="mx-2 text-muted-foreground">({simResult.action})</span>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
