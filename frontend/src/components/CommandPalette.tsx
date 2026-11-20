// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowUpCircle,
  Compass,
  FolderKanban,
  Globe,
  Power,
  Rss,
  Search,
  Server,
  Settings2,
  Shield,
  Split,
} from "lucide-react";
import { TRIGGER_UPDATE_CHECK_EVENT } from "./AppUpdateCard.tsx";
import { formatLatency } from "../lib/helpers.ts";
import { api, formatApiError } from "../lib/api.ts";
import { type NavTab, useAppStore } from "../store/appStore.ts";

interface CommandEntry {
  id: string;
  group: string;
  label: string;
  meta?: string;
  icon: React.ComponentType<{ className?: string }>;
  keywords: string;
  active?: boolean;
  run: () => void | Promise<void>;
}

export function CommandPalette() {
  const {
    tr,
    commandPaletteOpen,
    setCommandPaletteOpen,
    setActiveTab,
    status,
    tunState,
    systemProxyEnabled,
    routing,
    nodes,
    groups,
    toggleConnect,
    toggleTUN,
    toggleSystemProxy,
    refreshAll,
    notify,
  } = useAppStore();

  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const pointerDownOutsideRef = useRef(false);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const [query, setQuery] = useState("");
  const [activeIdx, setActiveIdx] = useState(0);

  // Global Cmd/Ctrl+K toggle
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  // Sync React boolean state with native top-layer <dialog>
  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (commandPaletteOpen) {
      setQuery("");
      setActiveIdx(0);
      if (!dlg.open) {
        dlg.showModal();
      }
      requestAnimationFrame(() => inputRef.current?.focus());
    } else if (dlg.open) {
      dlg.close();
    }
  }, [commandPaletteOpen]);

  const entries = useMemo<CommandEntry[]>(() => {
    const navGroup = tr("cmd.groupNav");
    const actGroup = tr("cmd.groupActions");
    const pgGroup = tr("cmd.groupPolicyGroups");
    const nodeGroup = tr("cmd.groupNodes");

    const switchMode = async (nextMode: "rule" | "global" | "direct") => {
      if (!routing) return;
      try {
        await api.saveRouting({ ...routing, mode: nextMode });
        await refreshAll();
      } catch (err) {
        notify(formatApiError(err), "error");
      }
    };

    const items: CommandEntry[] = [
      {
        id: "nav:overview",
        group: navGroup,
        label: tr("nav.overview"),
        meta: "1",
        icon: Activity,
        keywords: "overview dashboard home 概览 首页",
        run: () => setActiveTab("overview" as NavTab),
      },
      {
        id: "nav:proxies",
        group: navGroup,
        label: tr("nav.proxies"),
        meta: "2",
        icon: Server,
        keywords: "proxies nodes groups 节点 分组",
        run: () => setActiveTab("proxies"),
      },
      {
        id: "nav:connections",
        group: navGroup,
        label: tr("nav.connections"),
        meta: "3",
        icon: Compass,
        keywords: "connections traffic active 实时 连接",
        run: () => setActiveTab("connections"),
      },
      {
        id: "nav:subscriptions",
        group: navGroup,
        label: tr("nav.subscriptions"),
        meta: "4",
        icon: Rss,
        keywords: "subscriptions feeds 订阅",
        run: () => setActiveTab("subscriptions"),
      },
      {
        id: "nav:routing",
        group: navGroup,
        label: tr("nav.routing"),
        meta: "5",
        icon: Split,
        keywords: "routing dns rules 路由 规则",
        run: () => setActiveTab("routing"),
      },
      {
        id: "nav:settings",
        group: navGroup,
        label: tr("nav.settings"),
        meta: "6",
        icon: Settings2,
        keywords: "settings logs inbound gpu 设置 日志 入站",
        run: () => setActiveTab("settings"),
      },
      {
        id: "act:connect",
        group: actGroup,
        label: tr("cmd.actionToggleConnect"),
        meta: status?.running ? tr("status.running") : tr("status.stopped"),
        icon: Power,
        keywords: "connect disconnect toggle start stop 连接 断开 开关",
        run: () => toggleConnect(),
      },
      {
        id: "act:tun",
        group: actGroup,
        label: tr("cmd.actionToggleTun"),
        meta: tunState?.enabled ? "ON" : "OFF",
        icon: Shield,
        keywords: "tun virtual nic 虚拟网卡 接管",
        run: () => toggleTUN(!Boolean(tunState?.enabled)),
      },
      {
        id: "act:sysproxy",
        group: actGroup,
        label: tr("cmd.actionToggleSysProxy"),
        meta: systemProxyEnabled ? "ON" : "OFF",
        icon: Globe,
        keywords: "system proxy http socks 系统代理",
        run: () => toggleSystemProxy(!systemProxyEnabled),
      },
      {
        id: "act:mode-rule",
        group: actGroup,
        label: tr("cmd.actionModeRule"),
        meta: routing?.mode === "rule" ? "ACTIVE" : undefined,
        icon: Split,
        keywords: "mode rule split 规则分流",
        active: routing?.mode === "rule",
        run: () => switchMode("rule"),
      },
      {
        id: "act:mode-global",
        group: actGroup,
        label: tr("cmd.actionModeGlobal"),
        meta: routing?.mode === "global" ? "ACTIVE" : undefined,
        icon: Split,
        keywords: "mode global 全局代理",
        active: routing?.mode === "global",
        run: () => switchMode("global"),
      },
      {
        id: "act:mode-direct",
        group: actGroup,
        label: tr("cmd.actionModeDirect"),
        meta: routing?.mode === "direct" ? "ACTIVE" : undefined,
        icon: Split,
        keywords: "mode direct 直连",
        active: routing?.mode === "direct",
        run: () => switchMode("direct"),
      },
      {
        id: "act:check-update",
        group: actGroup,
        label: tr("update.cmdAction"),
        meta: tr("app.version"),
        icon: ArrowUpCircle,
        keywords: "update upgrade version release 检查更新 版本 升级",
        run: () => {
          setActiveTab("settings");
          window.setTimeout(() => {
            document.getElementById("settings-cores")?.scrollIntoView({ behavior: "smooth", block: "start" });
            window.dispatchEvent(new CustomEvent(TRIGGER_UPDATE_CHECK_EVENT));
          }, 180);
        },
      },
    ];

    for (const g of groups) {
      items.push({
        id: `group:${g.id}`,
        group: pgGroup,
        label: g.name,
        meta: `${g.strategy} · ${g.node_ids?.length || 0}`,
        icon: FolderKanban,
        keywords: `group ${g.name} ${g.strategy} 策略组`,
        active: Boolean(status?.running) && status?.active_group_id === g.id,
        run: () => toggleConnect({ groupId: g.id }),
      });
    }

    for (const n of nodes) {
      const display = n.user_alias || n.name;
      items.push({
        id: `node:${n.id}`,
        group: nodeGroup,
        label: display,
        meta: `${n.protocol.toUpperCase()} · ${formatLatency(n.latency)}`,
        icon: Server,
        keywords: `node ${display} ${n.name} ${n.address} ${n.protocol} 节点`,
        active: Boolean(status?.running) && !status?.active_group_id && status?.active_node_id === n.id,
        run: () => toggleConnect({ nodeId: n.id }),
      });
    }

    return items;
  }, [
    tr,
    routing,
    status,
    tunState,
    systemProxyEnabled,
    groups,
    nodes,
    setActiveTab,
    toggleConnect,
    toggleTUN,
    toggleSystemProxy,
    refreshAll,
    notify,
  ]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      // Show nav, actions, policy groups, and top 8 nodes cleanly when empty
      const nodeCount = { n: 0 };
      return entries.filter((entry) => {
        if (!entry.id.startsWith("node:")) return true;
        nodeCount.n += 1;
        return nodeCount.n <= 8;
      });
    }
    const tokens = q.split(/\s+/).filter(Boolean);
    return entries
      .filter((entry) => {
        const hay = `${entry.label} ${entry.keywords} ${entry.meta ?? ""}`.toLowerCase();
        return tokens.every((tok) => hay.includes(tok));
      })
      .slice(0, 32);
  }, [entries, query]);

  useEffect(() => {
    setActiveIdx((prev) => (filtered.length === 0 ? 0 : Math.min(prev, filtered.length - 1)));
  }, [filtered.length]);

  useEffect(() => {
    const btn = itemRefs.current[activeIdx];
    btn?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  const executeEntry = (entry: CommandEntry | undefined) => {
    if (!entry) return;
    setCommandPaletteOpen(false);
    void entry.run();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => (filtered.length === 0 ? 0 : (i + 1) % filtered.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => (filtered.length === 0 ? 0 : (i - 1 + filtered.length) % filtered.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      executeEntry(filtered[activeIdx]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      setCommandPaletteOpen(false);
    }
  };

  // Group filtered items preserving order for visual section labels
  const sections = useMemo(() => {
    const map = new Map<string, Array<{ entry: CommandEntry; index: number }>>();
    filtered.forEach((entry, index) => {
      const list = map.get(entry.group);
      if (list) list.push({ entry, index });
      else map.set(entry.group, [{ entry, index }]);
    });
    return Array.from(map.entries());
  }, [filtered]);

  return (
    <dialog
      ref={dialogRef}
      className="command-palette-dialog text-popover-foreground"
      {...({ closedby: "any" } as Record<string, string>)}
      onClose={() => {
        if (dialogRef.current) dialogRef.current.returnValue = "";
        setCommandPaletteOpen(false);
      }}
      onCancel={(e) => {
        e.preventDefault();
        setCommandPaletteOpen(false);
      }}
      onPointerDown={(e) => {
        pointerDownOutsideRef.current = e.target === dialogRef.current;
      }}
      onPointerUp={(e) => {
        if (pointerDownOutsideRef.current && e.target === dialogRef.current) {
          pointerDownOutsideRef.current = false;
          setCommandPaletteOpen(false);
        }
      }}
    >
      <div onKeyDown={handleKeyDown} className="flex flex-col max-h-[min(70dvh,540px)]">
        <div className="flex items-center gap-2.5 border-b border-border px-3.5 py-2.5">
          <Search className="w-4 h-4 shrink-0 text-muted-foreground" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIdx(0);
            }}
            placeholder={tr("cmd.placeholder")}
            aria-label={tr("cmd.placeholder")}
            className="w-full bg-transparent text-[13px] max-md:text-[15px] text-foreground placeholder:text-muted-foreground focus:outline-none min-h-8 max-md:min-h-10"
          />
          <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[11px] mono-num rounded-[4px] border border-border bg-muted text-muted-foreground">
            ESC
          </kbd>
        </div>

        <div className="overflow-y-auto p-1.5 space-y-2" role="listbox" aria-label={tr("cmd.trigger")}>
          {sections.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">{tr("cmd.empty")}</div>
          ) : (
            sections.map(([groupName, rows]) => (
              <div key={groupName} className="space-y-0.5">
                <div className="px-2.5 py-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  {groupName}
                </div>
                {rows.map(({ entry, index }) => {
                  const Icon = entry.icon;
                  const isFocused = index === activeIdx;
                  return (
                    <button
                      key={entry.id}
                      ref={(el) => {
                        itemRefs.current[index] = el;
                      }}
                      type="button"
                      role="option"
                      aria-selected={isFocused}
                      onMouseEnter={() => setActiveIdx(index)}
                      onClick={() => executeEntry(entry)}
                      className={`w-full flex items-center justify-between gap-2.5 px-2.5 py-1.5 max-md:py-2.5 min-h-[34px] max-md:min-h-[48px] rounded-[6px] text-left transition-colors duration-100 ${
                        isFocused ? "bg-accent text-accent-foreground" : "text-foreground hover:bg-muted/70"
                      }`}
                    >
                      <span className="flex items-center gap-2.5 min-w-0">
                        <Icon className="w-4 h-4 shrink-0 opacity-80" />
                        <span className="truncate text-[13px] max-md:text-[15px] font-medium">{entry.label}</span>
                        {entry.active && (
                          <span className="badge-radius px-1.5 py-0.5 text-[10px] font-semibold bg-primary/15 text-primary border border-primary/30 shrink-0">
                            ACTIVE
                          </span>
                        )}
                      </span>
                      {entry.meta && (
                        <span className="text-[11px] mono-num text-muted-foreground shrink-0">{entry.meta}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        <div className="flex items-center justify-between border-t border-border px-3.5 py-2 text-[11px] mono-num text-muted-foreground bg-muted/40 rounded-b-[12px]">
          <span>{tr("cmd.hint")}</span>
          <span>{filtered.length}</span>
        </div>
      </div>
    </dialog>
  );
}
