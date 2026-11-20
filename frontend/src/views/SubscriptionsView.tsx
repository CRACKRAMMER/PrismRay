// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  DownloadCloud,
  FileWarning,
  Loader2,
  Pencil,
  Plus,
  QrCode,
  RefreshCw,
  Rss,
  Trash2,
} from "lucide-react";
import { api, formatApiError, type SubscriptionRecord } from "../lib/api.ts";
import { type DurationUnit, joinToHours, splitHours } from "../lib/duration.ts";
import { formatBytes, formatExpiryDays } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { ContextInspector } from "../components/ContextInspector.tsx";
import { DurationInput } from "../components/DurationInput.tsx";
import { HelpTip } from "../components/HelpTip.tsx";
import { QrLinkImportModal } from "../components/QrLinkImportModal.tsx";
import { SwipeActionRow } from "../components/SwipeActionRow.tsx";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Input } from "../components/ui/input.tsx";

export function SubscriptionsView() {
  const {
    tr,
    locale,
    subscriptions,
    lastImportDiagnostic,
    setLastImportDiagnostic,
    refreshAll,
    notify,
  } = useAppStore();

  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [autoIntervalVal, setAutoIntervalVal] = useState(0);
  const [autoIntervalUnit, setAutoIntervalUnit] = useState<DurationUnit>("h");
  const [adding, setAdding] = useState(false);

  const [editingSub, setEditingSub] = useState<SubscriptionRecord | null>(null);
  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editIntervalVal, setEditIntervalVal] = useState(0);
  const [editIntervalUnit, setEditIntervalUnit] = useState<DurationUnit>("h");
  const [savingEdit, setSavingEdit] = useState(false);

  const [importUrl, setImportUrl] = useState("");
  const [rawContent, setRawContent] = useState("");
  const [importing, setImporting] = useState(false);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTitle, setDrawerTitle] = useState("");
  const [drawerWarnings, setDrawerWarnings] = useState<string[]>([]);
  const [qrImportOpen, setQrImportOpen] = useState(false);
  const addUrlInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onQuickCreate = (e: Event) => {
      if ((e as CustomEvent<string>).detail === "subscription") {
        addUrlInputRef.current?.focus();
        addUrlInputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    };
    window.addEventListener("prismray-quick-create", onQuickCreate);
    return () => window.removeEventListener("prismray-quick-create", onQuickCreate);
  }, []);

  const openEditDialog = (sub: SubscriptionRecord) => {
    setDrawerOpen(false);
    setEditingSub(sub);
    setEditName(sub.name);
    setEditUrl(sub.url);
    const parts = splitHours(Math.max(0, sub.auto_update_hours ?? 0), ["h", "d"], "h");
    setEditIntervalVal(parts.value);
    setEditIntervalUnit(parts.unit);
  };

  const closeInspector = () => {
    setEditingSub(null);
    setDrawerOpen(false);
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingSub) return;
    setSavingEdit(true);
    try {
      await api.updateSubscription(editingSub.id, {
        name: editName.trim() || editingSub.name,
        url: editUrl.trim() || editingSub.url,
        auto_update_hours: Math.max(0, joinToHours(editIntervalVal, editIntervalUnit)),
      });
      setEditingSub(null);
      await refreshAll();
      notify(tr("subs.saved"));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingEdit(false);
    }
  };

  const handleCreateSubscription = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subUrl.trim()) return;
    setAdding(true);
    try {
      await api.createSubscription({
        name: subName.trim() || "Subscription",
        url: subUrl.trim(),
        auto_update_hours: Math.max(0, joinToHours(autoIntervalVal, autoIntervalUnit)),
      });
      setSubName("");
      setSubUrl("");
      await refreshAll();
      notify(locale === "zh-CN" ? "订阅已添加" : "Subscription added");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setAdding(false);
    }
  };

  const handleBatchImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!importUrl.trim() && !rawContent.trim()) return;
    setImporting(true);
    try {
      const res = await api.importSubscription({
        url: importUrl.trim() || undefined,
        content: rawContent.trim() || undefined,
      });
      setLastImportDiagnostic(res);
      setImportUrl("");
      setRawContent("");
      await refreshAll();

      if ((res.skipped?.length || 0) > 0 || (res.warnings?.length || 0) > 0) {
        setDrawerTitle(tr("subs.diagnosticDrawer"));
        setDrawerWarnings(res.warnings || []);
        setDrawerOpen(true);
      } else {
        notify(tr("subs.importedCount", { count: res.imported }));
      }
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setImporting(false);
    }
  };

  const handleRefresh = async (id: string) => {
    setRefreshingId(id);
    try {
      await api.refreshSubscription(id);
      await refreshAll();
      notify(locale === "zh-CN" ? "订阅已刷新" : "Subscription refreshed");
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setRefreshingId(null);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteSubscription(id);
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const formatExpiryText = (expireUnix: number) => {
    const days = formatExpiryDays(expireUnix);
    if (days === null) return tr("subs.neverExpire");
    if (days === 0) return tr("subs.expired");
    return tr("subs.daysLeft", { days });
  };

  return (
    <div className="flex flex-col md:flex-row md:items-start gap-4">
      <div className="flex-1 min-w-0 space-y-5">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Add Subscription Feed */}
        <Card>
          <CardHeader className="pb-2.5">
            <CardTitle className="flex items-center gap-2 text-sm font-semibold">
              <Rss className="h-4 w-4 text-primary" aria-hidden="true" />
              {tr("subs.addTitle")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={(e) => void handleCreateSubscription(e)} className="space-y-3">
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                <div className="space-y-1 sm:col-span-2">
                  <label className="text-xs font-medium text-muted-foreground">{tr("subs.name")}</label>
                  <Input
                    value={subName}
                    onChange={(e) => setSubName(e.target.value)}
                    placeholder="My Airport / Feed"
                  />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5">
                    <label className="text-xs font-medium text-muted-foreground">{tr("subs.autoHoursClean")}</label>
                    <HelpTip ariaLabel={tr("subs.autoHoursClean")} text={tr("subs.autoHoursZeroHint")} />
                  </div>
                  <DurationInput
                    locale={locale}
                    value={autoIntervalVal}
                    unit={autoIntervalUnit}
                    units={["h", "d"]}
                    min={0}
                    ariaLabel={tr("subs.autoHoursClean")}
                    onChange={(v, u) => {
                      setAutoIntervalVal(v);
                      setAutoIntervalUnit(u);
                    }}
                  />
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">{tr("subs.url")}</label>
                <Input
                  ref={addUrlInputRef}
                  type="url"
                  value={subUrl}
                  onChange={(e) => setSubUrl(e.target.value)}
                  placeholder="https://..."
                  required
                />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button type="submit" disabled={adding}>
                  {adding ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <Plus className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />}
                  {tr("action.add")}
                </Button>
                <Button type="button" variant="outline" onClick={() => setQrImportOpen(true)}>
                  <QrCode className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("qr.scanBtn")}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Batch Import */}
        <Card>
          <CardHeader className="pb-2.5">
            <CardTitle className="flex items-center gap-2 text-sm font-semibold">
              <DownloadCloud className="h-4 w-4 text-primary" aria-hidden="true" />
              {tr("subs.quickImportTitle")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={(e) => void handleBatchImport(e)} className="space-y-3">
              <Input
                type="url"
                value={importUrl}
                onChange={(e) => setImportUrl(e.target.value)}
                placeholder={`${tr("subs.url")} (optional)`}
              />
              <textarea
                rows={4}
                className="w-full min-h-[5.5rem] rounded-[6px] border border-input bg-background px-2.5 py-1.5 font-mono text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                placeholder={tr("subs.rawContent")}
                value={rawContent}
                onChange={(e) => setRawContent(e.target.value)}
              />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Button type="submit" disabled={importing || (!importUrl.trim() && !rawContent.trim())}>
                  {importing ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : null}
                  {tr("action.import")}
                </Button>
                {lastImportDiagnostic ? (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setEditingSub(null);
                      setDrawerTitle(tr("subs.diagnosticDrawer"));
                      setDrawerWarnings(lastImportDiagnostic.warnings || []);
                      setDrawerOpen(true);
                    }}
                  >
                    <FileWarning className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                    {tr("subs.diagnosticDrawer")} ({lastImportDiagnostic.skipped?.length || 0})
                  </Button>
                ) : null}
              </div>
            </form>
          </CardContent>
        </Card>
      </div>

      {/* Saved Subscriptions */}
      <div className="space-y-2.5">
        <h2 className="text-base font-semibold text-foreground">{tr("subs.title")}</h2>
        {subscriptions.length === 0 ? (
          <Card>
            <CardContent className="p-8 text-center text-xs text-muted-foreground">
              {locale === "zh-CN" ? "暂无保存的订阅源。" : "No saved subscription feeds yet."}
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {subscriptions.map((sub) => {
              const used = (sub.upload_bytes || 0) + (sub.download_bytes || 0);
              const total = sub.total_bytes || 0;
              const pct = total > 0 ? Math.min(100, Math.round((used / total) * 100)) : 0;
              const isSelected = editingSub?.id === sub.id;

              return (
                <SwipeActionRow
                  key={sub.id}
                  className={`rounded-[10px] border bg-card transition-colors ${
                    isSelected ? "border-primary bg-accent/25" : "border-border"
                  }`}
                  actions={[
                    {
                      key: "refresh",
                      label: tr("action.refresh"),
                      icon: <RefreshCw className="h-4 w-4" />,
                      tone: "primary",
                      onClick: () => void handleRefresh(sub.id),
                    },
                    {
                      key: "edit",
                      label: tr("subs.edit"),
                      icon: <Pencil className="h-4 w-4" />,
                      onClick: () => openEditDialog(sub),
                    },
                    {
                      key: "delete",
                      label: tr("action.delete"),
                      icon: <Trash2 className="h-4 w-4" />,
                      tone: "danger",
                      onClick: () => void handleDelete(sub.id),
                    },
                  ]}
                >
                  <div className="space-y-2.5 p-3.5">
                    <div className="flex items-start justify-between gap-2.5">
                      <div className="min-w-0">
                        <div className="truncate text-[14px] font-semibold text-foreground">{sub.name}</div>
                        <div className="truncate mono-num text-[11px] text-muted-foreground" title={sub.url}>
                          {sub.url}
                        </div>
                      </div>
                      <div className="hidden md:flex shrink-0 items-center gap-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => openEditDialog(sub)}
                          aria-label={`${tr("subs.edit")} ${sub.name}`}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground"
                        >
                          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleRefresh(sub.id)}
                          disabled={refreshingId === sub.id}
                          aria-label={`${tr("action.refresh")} ${sub.name}`}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground"
                        >
                          <RefreshCw
                            className={`h-3.5 w-3.5 ${refreshingId === sub.id ? "animate-spin" : ""}`}
                            aria-hidden="true"
                          />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDelete(sub.id)}
                          aria-label={`${tr("action.delete")} ${sub.name}`}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className="badge-radius border border-primary/30 bg-primary/15 px-2 py-0.5 font-medium text-primary mono-num">
                        {tr("subs.importedCount", { count: sub.imported_count })}
                      </span>
                      {sub.skipped_count > 0 ? (
                        <span className="badge-radius border border-amber-500/30 bg-amber-500/15 px-2 py-0.5 font-medium text-amber-400 mono-num">
                          {tr("subs.skippedCount", { count: sub.skipped_count })}
                        </span>
                      ) : null}
                      <span className="badge-radius border border-border px-2 py-0.5 text-muted-foreground mono-num">
                        {tr("subs.expiry")}: {formatExpiryText(sub.expire_unix)}
                      </span>
                      <span className="badge-radius bg-muted px-2 py-0.5 text-muted-foreground mono-num">
                        {sub.auto_update_hours > 0
                          ? tr("subs.everyHoursBadge", { hours: sub.auto_update_hours })
                          : tr("subs.manualOnlyBadge")}
                      </span>
                    </div>

                    {total > 0 ? (
                      <div className="space-y-1">
                        <div className="flex justify-between text-[11px] text-muted-foreground">
                          <span>{tr("subs.usage")}</span>
                          <span className="mono-num text-foreground">
                            {formatBytes(used)} / {formatBytes(total)} ({pct}%)
                          </span>
                        </div>
                        <div className="h-1.5 overflow-hidden badge-radius bg-muted">
                          <div className="h-full bg-primary transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    ) : null}

                    {sub.warnings && sub.warnings.length > 0 ? (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setEditingSub(null);
                          setDrawerTitle(`${sub.name} — ${tr("subs.diagnosticDrawer")}`);
                          setDrawerWarnings(sub.warnings);
                          setDrawerOpen(true);
                        }}
                        className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-400 hover:underline"
                      >
                        <AlertCircle className="h-3.5 w-3.5" aria-hidden="true" />
                        {sub.warnings.length} warnings
                      </button>
                    ) : null}
                  </div>
                </SwipeActionRow>
              );
            })}
          </div>
        )}
      </div>
      </div>

      {/* Right Context Inspector for Subscription Editing & Diagnostics */}
      <ContextInspector
        open={Boolean(editingSub || drawerOpen)}
        title={
          editingSub
            ? `${tr("subs.editTitle")} — ${editingSub.name}`
            : drawerTitle || tr("subs.diagnosticDrawer")
        }
        onClose={closeInspector}
      >
        {editingSub ? (
          <form onSubmit={(e) => void handleSaveEdit(e)} className="space-y-3 text-xs">
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("subs.name")}</label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} required />
            </div>
            <div className="space-y-1">
              <label className="block font-medium text-muted-foreground">{tr("subs.url")}</label>
              <Input type="url" value={editUrl} onChange={(e) => setEditUrl(e.target.value)} required />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-1.5">
                <label className="block font-medium text-muted-foreground">{tr("subs.autoHoursClean")}</label>
                <HelpTip ariaLabel={tr("subs.autoHoursClean")} text={tr("subs.autoHoursZeroHint")} />
              </div>
              <DurationInput
                locale={locale}
                value={editIntervalVal}
                unit={editIntervalUnit}
                units={["h", "d"]}
                min={0}
                ariaLabel={tr("subs.autoHoursClean")}
                onChange={(v, u) => {
                  setEditIntervalVal(v);
                  setEditIntervalUnit(u);
                }}
              />
            </div>
            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <Button type="button" variant="outline" onClick={closeInspector}>
                {tr("action.cancel")}
              </Button>
              <Button type="submit" disabled={savingEdit}>
                {savingEdit ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : null}
                {tr("action.save")}
              </Button>
            </div>
          </form>
        ) : (
          <div className="space-y-3 text-xs">
            {drawerWarnings.length > 0 ? (
              <div className="space-y-1.5">
                <div className="font-semibold text-amber-400">Warnings</div>
                {drawerWarnings.map((w, idx) => (
                  <div key={idx} className="rounded-[6px] border border-amber-500/30 bg-amber-500/10 p-2 text-foreground">
                    {w}
                  </div>
                ))}
              </div>
            ) : null}

            {lastImportDiagnostic?.skipped && lastImportDiagnostic.skipped.length > 0 ? (
              <div className="space-y-1.5">
                <div className="font-semibold text-foreground">
                  {tr("subs.skippedCount", { count: lastImportDiagnostic.skipped.length })}
                </div>
                {lastImportDiagnostic.skipped.map((entry, idx) => (
                  <div key={idx} className="space-y-1 rounded-[6px] border border-border bg-muted/40 p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-foreground mono-num">
                        #{entry.index} {entry.name || "Unnamed"}
                      </span>
                      <span className="text-destructive">{entry.reason}</span>
                    </div>
                    {entry.raw ? (
                      <div className="mono-num text-[11px] break-all text-muted-foreground">{entry.raw}</div>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : drawerWarnings.length === 0 ? (
              <p className="text-muted-foreground">{tr("subs.diagnosticEmpty")}</p>
            ) : null}
          </div>
        )}
      </ContextInspector>

      <QrLinkImportModal open={qrImportOpen} defaultMode="subscription" onClose={() => setQrImportOpen(false)} />
    </div>
  );
}
