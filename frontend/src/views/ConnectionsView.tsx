// SPDX-License-Identifier: MPL-2.0

import { useEffect, useId, useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Columns3,
  Network,
  Pause,
  Play,
  RotateCcw,
  Search,
  Trash2,
  X,
} from "lucide-react";
import { api, type ConnectionItem, formatApiError } from "../lib/api.ts";
import {
  formatBytes,
  formatDurationShort,
  resolveConnectionRoute,
  type ResolvedConnectionRoute,
} from "../lib/helpers.ts";
import { type TranslationKey } from "../lib/i18n.ts";
import {
  ALL_CONNECTION_COLUMNS,
  type ConnectionColumnId,
  DEFAULT_CONNECTION_COLUMNS,
  useAppStore,
  useTelemetry,
} from "../store/appStore.ts";
import { BottomSheetDialog, ContextInspector, useIsMobile } from "../components/ContextInspector.tsx";
import { TruncateTip } from "../components/HoverPopover.tsx";
import { SwipeActionRow } from "../components/SwipeActionRow.tsx";
import { ColumnResizeHandle } from "../components/ColumnResizeHandle.tsx";
import { type ColumnSpecMap, useResizableColumns } from "../lib/useResizableColumns.ts";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent } from "../components/ui/card.tsx";
import { Input } from "../components/ui/input.tsx";
import { Select } from "../components/ui/select.tsx";

type SortColumn = "target" | "outboundNode" | "engine" | "group" | "traffic" | "duration";
type SortDir = "asc" | "desc";

const COLUMN_LABEL_KEY: Record<ConnectionColumnId, TranslationKey> = {
  target: "conns.colTarget",
  network: "conns.colNetwork",
  outboundNode: "conns.colOutboundNode",
  engine: "conns.colEngine",
  group: "conns.colGroup",
  rule: "conns.colRule",
  process: "conns.colProcess",
  traffic: "conns.colTraffic",
  duration: "conns.colDuration",
  source: "conns.colSource",
  action: "conns.colAction",
};

const SORTABLE_COLS = new Set<ConnectionColumnId>([
  "target",
  "outboundNode",
  "engine",
  "group",
  "traffic",
  "duration",
]);

const CONN_COL_SPECS: ColumnSpecMap<ConnectionColumnId> = {
  target: { defaultWidth: 230, minWidth: 130, maxWidth: 520 },
  network: { defaultWidth: 112, minWidth: 80, maxWidth: 220 },
  outboundNode: { defaultWidth: 170, minWidth: 100, maxWidth: 360 },
  engine: { defaultWidth: 118, minWidth: 84, maxWidth: 220 },
  group: { defaultWidth: 130, minWidth: 86, maxWidth: 280 },
  rule: { defaultWidth: 168, minWidth: 100, maxWidth: 360 },
  process: { defaultWidth: 138, minWidth: 90, maxWidth: 300 },
  traffic: { defaultWidth: 146, minWidth: 110, maxWidth: 260 },
  duration: { defaultWidth: 88, minWidth: 68, maxWidth: 160 },
  source: { defaultWidth: 152, minWidth: 100, maxWidth: 300 },
  action: { defaultWidth: 74, minWidth: 60, maxWidth: 140 },
};

const textCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

interface EnrichedConnection {
  item: ConnectionItem;
  dest: string;
  source: string;
  route: ResolvedConnectionRoute;
  totalBytes: number;
  startMs: number;
}

export function ConnectionsView() {
  const {
    tr,
    locale,
    nodes,
    groups,
    connectionColumns,
    setConnectionColumns,
    refreshAll,
    notify,
  } = useAppStore();
  const { connections } = useTelemetry();

  const headingId = useId();
  const isMobile = useIsMobile();
  const {
    widths: connColWidths,
    resizingCol: resizingConnCol,
    startResize: startConnColResize,
    resetColumn: resetConnColWidth,
  } = useResizableColumns("connections-live", CONN_COL_SPECS);
  const [query, setQuery] = useState("");
  const [protoFilter, setProtoFilter] = useState<string>("all");
  const [engineFilter, setEngineFilter] = useState<string>("all");
  const [outboundFilter, setOutboundFilter] = useState<string>("all");
  const [paused, setPaused] = useState(false);
  const [frozenList, setFrozenList] = useState<ConnectionItem[]>(connections.connections || []);
  const [colMenuOpen, setColMenuOpen] = useState(false);
  const [sortCol, setSortCol] = useState<SortColumn>("traffic");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [sortStatus, setSortStatus] = useState("");
  const [closingAll, setClosingAll] = useState(false);
  const [inspectedConnId, setInspectedConnId] = useState<string | null>(null);

  useEffect(() => {
    if (!paused) {
      setFrozenList(connections.connections || []);
    }
  }, [connections.connections, paused]);

  const activeList = paused ? frozenList : connections.connections || [];

  const enriched = useMemo<EnrichedConnection[]>(() => {
    return activeList.map((item) => {
      const m = item.metadata;
      const dest = `${m.host || m.destinationIP || "unknown"}:${m.destinationPort || ""}`;
      const source = m.sourceIP ? `${m.sourceIP}:${m.sourcePort || ""}` : "--";
      const route = resolveConnectionRoute(item.chains, nodes, groups);
      const startMs = Date.parse(item.start) || 0;
      return {
        item,
        dest,
        source,
        route,
        totalBytes: (item.upload || 0) + (item.download || 0),
        startMs,
      };
    });
  }, [activeList, nodes, groups]);

  const uniqueOutbounds = useMemo(() => {
    const names = new Set<string>();
    for (const row of enriched) {
      if (row.route.nodeName) names.add(row.route.nodeName);
    }
    return Array.from(names).sort((a, b) => textCollator.compare(a, b));
  }, [enriched]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return enriched.filter((row) => {
      const m = row.item.metadata;
      if (protoFilter !== "all" && (m.network || "").toLowerCase() !== protoFilter) {
        return false;
      }
      if (engineFilter !== "all" && row.route.engine !== engineFilter) {
        return false;
      }
      if (outboundFilter !== "all" && row.route.nodeName !== outboundFilter) {
        return false;
      }
      if (!q) return true;
      return (
        row.dest.toLowerCase().includes(q) ||
        row.source.toLowerCase().includes(q) ||
        (m.processPath || "").toLowerCase().includes(q) ||
        (row.item.rule || "").toLowerCase().includes(q) ||
        row.route.nodeName.toLowerCase().includes(q) ||
        row.route.groupName.toLowerCase().includes(q) ||
        row.route.engine.toLowerCase().includes(q) ||
        (row.item.chains || []).join(" ").toLowerCase().includes(q)
      );
    });
  }, [enriched, query, protoFilter, engineFilter, outboundFilter]);

  const sortedItems = useMemo(() => {
    const copy = [...filtered];
    copy.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case "target":
          cmp = textCollator.compare(a.dest, b.dest);
          break;
        case "outboundNode":
          cmp = textCollator.compare(a.route.nodeName, b.route.nodeName);
          break;
        case "engine":
          cmp = textCollator.compare(a.route.engine, b.route.engine);
          break;
        case "group":
          cmp = textCollator.compare(a.route.groupName || "--", b.route.groupName || "--");
          break;
        case "duration":
          cmp = a.startMs - b.startMs;
          break;
        case "traffic":
        default:
          cmp = a.totalBytes - b.totalBytes;
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [filtered, sortCol, sortDir]);

  const toggleSort = (col: SortColumn) => {
    const nextDir: SortDir =
      sortCol === col
        ? sortDir === "asc"
          ? "desc"
          : "asc"
        : col === "traffic"
          ? "desc"
          : "asc";
    setSortCol(col);
    setSortDir(nextDir);
    const colLabel = tr(COLUMN_LABEL_KEY[col]);
    setSortStatus(
      locale === "zh-CN"
        ? `已按「${colLabel}」${nextDir === "asc" ? "升序" : "降序"}排列`
        : `Sorted by ${colLabel} (${nextDir === "asc" ? "ascending" : "descending"})`,
    );
  };

  const toggleColumn = (col: ConnectionColumnId) => {
    if (connectionColumns.includes(col)) {
      if (connectionColumns.length <= 2) return;
      setConnectionColumns(connectionColumns.filter((c) => c !== col));
    } else {
      setConnectionColumns([...connectionColumns, col]);
    }
  };

  const handleCloseAll = async () => {
    setClosingAll(true);
    try {
      await api.closeAllConnections();
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setClosingAll(false);
    }
  };

  const handleCloseOne = async (id: string) => {
    try {
      await api.closeConnection(id);
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const visibleColumns = ALL_CONNECTION_COLUMNS.filter((c) => connectionColumns.includes(c));
  const nowMs = Date.now();
  const inspectedEntry = useMemo(
    () => sortedItems.find((e) => e.item.id === inspectedConnId) ?? null,
    [sortedItems, inspectedConnId],
  );

  const handleListKeyDown = (e: React.KeyboardEvent) => {
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
    if (sortedItems.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const idx = sortedItems.findIndex((x) => x.item.id === inspectedConnId);
      const next = idx < 0 ? 0 : (idx + 1) % sortedItems.length;
      setInspectedConnId(sortedItems[next].item.id);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const idx = sortedItems.findIndex((x) => x.item.id === inspectedConnId);
      const next = idx <= 0 ? sortedItems.length - 1 : idx - 1;
      setInspectedConnId(sortedItems[next].item.id);
    }
  };

  const renderEngineBadge = (engine: ResolvedConnectionRoute["engine"]) => {
    if (engine === "xray") {
      return (
        <span className="inline-flex shrink-0 whitespace-nowrap badge-radius border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 mono-num text-[11px] font-medium text-sky-400">
          xray
        </span>
      );
    }
    if (engine === "direct") {
      return (
        <span className="inline-flex shrink-0 whitespace-nowrap badge-radius border border-border bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground">
          {tr("conns.engineDirect")}
        </span>
      );
    }
    if (engine === "block") {
      return (
        <span className="inline-flex shrink-0 whitespace-nowrap badge-radius border border-destructive/30 bg-destructive/10 px-1.5 py-0.5 text-[11px] font-medium text-destructive">
          {tr("conns.engineBlock")}
        </span>
      );
    }
    return (
      <span className="inline-flex shrink-0 whitespace-nowrap badge-radius border border-primary/30 bg-primary/15 px-1.5 py-0.5 mono-num text-[11px] font-medium text-primary">
        sing-box
      </span>
    );
  };

  const columnSelectorBody = (
    <>
      <div className="mb-2 flex items-center justify-between border-b border-border pb-2 text-xs font-semibold">
        <span>{tr("conns.columns")}</span>
        <button
          type="button"
          onClick={() => setConnectionColumns(DEFAULT_CONNECTION_COLUMNS)}
          className="inline-flex items-center gap-1 text-[11px] font-medium text-primary hover:underline"
        >
          <RotateCcw className="h-3 w-3" aria-hidden="true" />
          {tr("conns.resetColumns")}
        </button>
      </div>
      <div className="max-h-72 space-y-1 overflow-y-auto text-xs">
        {ALL_CONNECTION_COLUMNS.map((colId) => {
          const checked = connectionColumns.includes(colId);
          return (
            <label
              key={colId}
              className="flex cursor-pointer items-center justify-between gap-2 rounded-[6px] px-2 py-1.5 max-md:min-h-12 hover:bg-muted/60"
            >
              <span className="text-foreground">{tr(COLUMN_LABEL_KEY[colId])}</span>
              <input type="checkbox" checked={checked} onChange={() => toggleColumn(colId)} />
            </label>
          );
        })}
      </div>
    </>
  );

  return (
    <div onKeyDown={handleListKeyDown} className="flex flex-col md:flex-row md:items-start gap-4">
      <div className="flex-1 min-w-0 space-y-3">
      <p role="status" className="visually-hidden">
        {sortStatus}
      </p>

      {/* Header & Totals */}
      <div className="flex flex-col gap-2.5 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-0.5">
          <div className="flex flex-wrap items-center gap-2">
            <h2 id={headingId} className="flex items-center gap-2 text-base font-semibold text-foreground">
              <Network className="h-4 w-4 text-primary" aria-hidden="true" />
              {tr("connections.title")}
            </h2>
            <span className="badge-radius border border-primary/30 bg-primary/15 px-2 py-0.5 text-[11px] font-semibold text-primary mono-num">
              {sortedItems.length}
            </span>
            {paused ? (
              <span className="badge-radius border border-amber-500/30 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-400">
                {tr("conns.pausedBadge")}
              </span>
            ) : null}
          </div>
          <p className="mono-num text-[11px] text-muted-foreground">
            {tr("conns.showingCount", { shown: sortedItems.length, total: activeList.length })} ·{" "}
            {tr("conns.totalUpload")}: {formatBytes(connections.uploadTotal)} · {tr("conns.totalDownload")}:{" "}
            {formatBytes(connections.downloadTotal)}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            type="button"
            variant={paused ? "default" : "outline"}
            size="sm"
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? <Play className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" /> : <Pause className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />}
            {paused ? tr("conns.resume") : tr("conns.pause")}
          </Button>

          <div className="relative hidden md:block">
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-expanded={colMenuOpen}
              onClick={() => setColMenuOpen((o) => !o)}
            >
              <Columns3 className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("conns.columns")}
            </Button>
            {colMenuOpen && !isMobile ? (
              <div className="absolute right-0 z-30 mt-1.5 w-56 rounded-[10px] border border-border bg-popover p-3">
                {columnSelectorBody}
              </div>
            ) : null}
          </div>

          <Button
            type="button"
            variant="destructive"
            size="sm"
            disabled={closingAll || activeList.length === 0}
            onClick={() => void handleCloseAll()}
          >
            <Trash2 className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {tr("connections.closeAll")}
          </Button>
        </div>
      </div>

      {/* Multi-Faceted Filter Bar */}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-[1.6fr_0.75fr_0.85fr_1fr]">
        <search className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            aria-label={tr("connections.searchPlaceholder")}
            className="pl-8"
            placeholder={tr("connections.searchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </search>

        <Select
          aria-label={tr("conns.colNetwork")}
          value={protoFilter}
          onChange={(e) => setProtoFilter(e.target.value)}
        >
          <option value="all">{tr("conns.filterAllProto")}</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </Select>

        <Select
          aria-label={tr("conns.colEngine")}
          value={engineFilter}
          onChange={(e) => setEngineFilter(e.target.value)}
        >
          <option value="all">{tr("conns.filterAllEngine")}</option>
          <option value="sing-box">sing-box</option>
          <option value="xray">xray</option>
          <option value="direct">{tr("conns.engineDirect")}</option>
          <option value="block">{tr("conns.engineBlock")}</option>
        </Select>

        <Select
          aria-label={tr("conns.colOutboundNode")}
          value={outboundFilter}
          onChange={(e) => setOutboundFilter(e.target.value)}
        >
          <option value="all">{tr("conns.filterAllOutbound")}</option>
          {uniqueOutbounds.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </Select>
      </div>

      {sortedItems.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-xs text-muted-foreground">
            {tr("connections.empty")}
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="space-y-2 md:hidden">
            {sortedItems.map(({ item, dest, route }) => (
              <SwipeActionRow
                key={item.id}
                className="rounded-[10px] border border-border bg-card"
                actions={[
                  {
                    key: "close",
                    label: tr("action.close"),
                    icon: <X className="h-4 w-4" />,
                    tone: "danger",
                    onClick: () => void handleCloseOne(item.id),
                  },
                ]}
              >
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => setInspectedConnId(item.id)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setInspectedConnId(item.id);
                    }
                  }}
                  className="p-3 space-y-1.5 text-left"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono-num text-[14px] font-medium truncate text-foreground">{dest}</span>
                    {renderEngineBadge(route.engine)}
                  </div>
                  <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                    <span className="truncate">{route.nodeName || route.groupName || "--"}</span>
                    <span className="mono-num shrink-0">
                      ↑{formatBytes(item.upload)} ↓{formatBytes(item.download)}
                    </span>
                  </div>
                </div>
              </SwipeActionRow>
            ))}
          </div>

          <div tabIndex={0} role="region" aria-labelledby={headingId} className="hidden md:block table-wrapper">
            <table className="responsive-table table-resizable [&_th]:py-1.5 [&_th]:px-2.5 [&_td]:py-1.5 [&_td]:px-2.5">
              <colgroup>
                {visibleColumns.map((colId) => (
                  <col key={colId} style={{ width: `${connColWidths[colId]}px` }} />
                ))}
              </colgroup>
              <thead>
                <tr>
                  {visibleColumns.map((colId) => {
                    const label = tr(COLUMN_LABEL_KEY[colId]);
                    if (SORTABLE_COLS.has(colId)) {
                      const sCol = colId as SortColumn;
                      const isSorted = sortCol === sCol;
                      return (
                        <th
                          key={colId}
                          scope="col"
                          className="sortable-th whitespace-nowrap text-[11px] uppercase tracking-wide"
                          aria-sort={isSorted ? (sortDir === "asc" ? "ascending" : "descending") : undefined}
                        >
                          <button type="button" onClick={() => toggleSort(sCol)}>
                            <span>{label}</span>
                            {isSorted ? (
                              sortDir === "asc" ? (
                                <ArrowUp className="h-3 w-3 shrink-0 text-primary" aria-hidden="true" />
                              ) : (
                                <ArrowDown className="h-3 w-3 shrink-0 text-primary" aria-hidden="true" />
                              )
                            ) : (
                              <ArrowUpDown className="h-3 w-3 shrink-0 opacity-45" aria-hidden="true" />
                            )}
                          </button>
                          <ColumnResizeHandle
                            active={resizingConnCol === colId}
                            title={tr("table.resizeHint")}
                            onPointerDown={(e) => startConnColResize(colId, e)}
                            onDoubleClick={() => resetConnColWidth(colId)}
                          />
                        </th>
                      );
                    }
                    return (
                      <th key={colId} scope="col" className="whitespace-nowrap text-[11px] uppercase tracking-wide">
                        <span className="block truncate">{label}</span>
                        <ColumnResizeHandle
                          active={resizingConnCol === colId}
                          title={tr("table.resizeHint")}
                          onPointerDown={(e) => startConnColResize(colId, e)}
                          onDoubleClick={() => resetConnColWidth(colId)}
                        />
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody>
                {sortedItems.map(({ item, dest, source, route }) => {
                  const m = item.metadata;
                  const chainText = (item.chains || []).join(" → ");
                  const isSelected = inspectedConnId === item.id;
                  return (
                    <tr
                      key={item.id}
                      onClick={() => setInspectedConnId(item.id)}
                      className={`cursor-pointer dense-row transition-colors duration-100 ${
                        isSelected ? "bg-accent/70" : "hover:bg-muted/50"
                      }`}
                    >
                      {visibleColumns.map((colId) => {
                        const colLabel = tr(COLUMN_LABEL_KEY[colId]);
                        switch (colId) {
                          case "target":
                            return (
                              <th key={colId} scope="row" className="min-w-0 font-mono text-xs font-medium text-foreground">
                                <TruncateTip text={dest} />
                              </th>
                            );
                          case "network":
                            return (
                              <td key={colId} data-label={colLabel} className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                                {[m.network, m.type].filter(Boolean).join(" / ") || "--"}
                              </td>
                            );
                          case "outboundNode":
                            return (
                              <td key={colId} data-label={colLabel} className="min-w-0 text-xs font-medium text-foreground">
                                <TruncateTip text={route.nodeName || "--"} />
                              </td>
                            );
                          case "engine":
                            return (
                              <td key={colId} data-label={colLabel} className="whitespace-nowrap">
                                {renderEngineBadge(route.engine)}
                              </td>
                            );
                          case "group":
                            return (
                              <td key={colId} data-label={colLabel} className="min-w-0 text-xs text-muted-foreground">
                                {route.groupName ? (
                                  <TruncateTip
                                    text={route.groupName}
                                    className="inline-block max-w-full badge-radius border border-border bg-muted px-1.5 py-0.5 text-foreground"
                                  />
                                ) : (
                                  "--"
                                )}
                              </td>
                            );
                          case "rule": {
                            const fullRule = [item.rule || "--", item.rulePayload].filter(Boolean).join(" ");
                            return (
                              <td key={colId} data-label={colLabel} className="min-w-0 text-xs text-muted-foreground">
                                <TruncateTip
                                  text={fullRule}
                                  detail={
                                    <div className="space-y-1 text-xs">
                                      <div className="break-all font-medium text-foreground">{fullRule}</div>
                                      {chainText ? (
                                        <div className="break-all font-mono text-[11px] text-muted-foreground">
                                          {chainText}
                                        </div>
                                      ) : null}
                                    </div>
                                  }
                                />
                              </td>
                            );
                          }
                          case "process":
                            return (
                              <td key={colId} data-label={colLabel} className="min-w-0 text-xs text-muted-foreground">
                                <TruncateTip text={m.processPath || "--"} />
                              </td>
                            );
                          case "traffic":
                            return (
                              <td key={colId} data-label={colLabel} className="whitespace-nowrap text-xs tabular-nums text-foreground">
                                ↑ {formatBytes(item.upload)} / ↓ {formatBytes(item.download)}
                              </td>
                            );
                          case "duration":
                            return (
                              <td key={colId} data-label={colLabel} className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                                {formatDurationShort(item.start, nowMs)}
                              </td>
                            );
                          case "source":
                            return (
                              <td key={colId} data-label={colLabel} className="min-w-0 font-mono text-xs text-muted-foreground">
                                <TruncateTip text={source} />
                              </td>
                            );
                          case "action":
                            return (
                              <td key={colId} data-label={colLabel} onClick={(e) => e.stopPropagation()}>
                                <button
                                  type="button"
                                  onClick={() => void handleCloseOne(item.id)}
                                  aria-label={`${tr("action.close")} ${dest}`}
                                  className="inline-flex h-7 w-7 items-center justify-center rounded-[6px] text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                                >
                                  <X className="h-3.5 w-3.5" aria-hidden="true" />
                                </button>
                              </td>
                            );
                        }
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
      </div>

      <ContextInspector
        open={Boolean(inspectedEntry)}
        title={tr("inspector.connTitle")}
        subtitle={inspectedEntry?.dest}
        onClose={() => setInspectedConnId(null)}
      >
        {inspectedEntry ? (
          <div className="space-y-3 text-xs">
            <div className="rounded-[10px] border border-border bg-muted/30 p-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("conns.colEngine")}</span>
                {renderEngineBadge(inspectedEntry.route.engine)}
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("conns.colOutboundNode")}</span>
                <span className="font-medium text-foreground truncate max-w-[200px]">
                  {inspectedEntry.route.nodeName || "--"}
                </span>
              </div>
              {inspectedEntry.route.groupName ? (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">{tr("conns.colGroup")}</span>
                  <span className="badge-radius border border-border bg-background px-1.5 py-0.5 text-[11px]">
                    {inspectedEntry.route.groupName}
                  </span>
                </div>
              ) : null}
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("conns.colNetwork")}</span>
                <span className="mono-num text-foreground">
                  {[inspectedEntry.item.metadata.network, inspectedEntry.item.metadata.type].filter(Boolean).join(" / ") || "--"}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("conns.colDuration")}</span>
                <span className="mono-num text-foreground">{formatDurationShort(inspectedEntry.item.start, nowMs)}</span>
              </div>
            </div>

            <div className="rounded-[10px] border border-border bg-muted/30 p-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("overview.upload")} / {tr("overview.download")}</span>
                <span className="mono-num text-foreground">
                  ↑ {formatBytes(inspectedEntry.item.upload)} / ↓ {formatBytes(inspectedEntry.item.download)}
                </span>
              </div>
              <div className="space-y-0.5">
                <div className="text-muted-foreground">{tr("conns.colSource")}</div>
                <div className="mono-num text-foreground break-all">{inspectedEntry.source || "--"}</div>
              </div>
              <div className="space-y-0.5">
                <div className="text-muted-foreground">{tr("conns.colRule")}</div>
                <div className="mono-num text-foreground break-all">
                  {inspectedEntry.item.rule || "--"}
                  {inspectedEntry.item.rulePayload ? ` (${inspectedEntry.item.rulePayload})` : ""}
                </div>
              </div>
              {inspectedEntry.item.metadata.processPath ? (
                <div className="space-y-0.5">
                  <div className="text-muted-foreground">{tr("conns.colProcess")}</div>
                  <div className="mono-num text-[11px] text-foreground break-all">
                    {inspectedEntry.item.metadata.processPath}
                  </div>
                </div>
              ) : null}
              <div className="space-y-1">
                <div className="text-muted-foreground">Chains</div>
                <div className="flex flex-wrap gap-1">
                  {(inspectedEntry.item.chains || []).map((c, idx) => (
                    <span key={idx} className="badge-radius border border-border bg-background px-1.5 py-0.5 mono-num text-[11px]">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={() => {
                  const id = inspectedEntry.item.id;
                  setInspectedConnId(null);
                  void handleCloseOne(id);
                }}
              >
                <X className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                {tr("action.close")}
              </Button>
            </div>
          </div>
        ) : null}
      </ContextInspector>

      {isMobile ? (
        <BottomSheetDialog open={colMenuOpen} title={tr("mobile.columnsSheet")} onClose={() => setColMenuOpen(false)}>
          {columnSelectorBody}
        </BottomSheetDialog>
      ) : null}
    </div>
  );
}
