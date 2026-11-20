// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CheckSquare,
  FolderPlus,
  Gauge,
  GitBranch,
  GripVertical,
  Hand,
  Layers,
  LayoutGrid,
  List,
  Pencil,
  Play,
  Plus,
  QrCode,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Square,
  Star,
  Tag,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { type GroupConfig, type HealthSettings, type NodeConfig, type ProbeMode, api, formatApiError } from "../lib/api.ts";
import {
  ALL_PROTOCOLS,
  type NodeFilterTab,
  type NodeSortField,
  type SortDirection,
  buildNodeFilterTabs,
  formatLatency,
  formatSpeedMbps,
  nodeHasInsecureTLS,
  nodeHasTag,
  nodeMatchesFilterTab,
  sortNodesByMetric,
} from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { BottomSheetDialog, ContextInspector, useIsMobile } from "../components/ContextInspector.tsx";
import { HelpTip } from "../components/HelpTip.tsx";
import { HoverPopover, TruncateTip } from "../components/HoverPopover.tsx";
import { NodeContextMenu, type NodeContextMenuState } from "../components/NodeContextMenu.tsx";
import { NodeEditorForm, QRSharePanel } from "../components/NodeFormModal.tsx";
import { NodeMultiSelectDropdown } from "../components/NodeMultiSelectDropdown.tsx";
import { QrLinkImportModal } from "../components/QrLinkImportModal.tsx";
import { SwipeActionRow } from "../components/SwipeActionRow.tsx";
import { ColumnResizeHandle } from "../components/ColumnResizeHandle.tsx";
import { DurationInput } from "../components/DurationInput.tsx";
import {
  type DurationUnit,
  formatGoDuration,
  joinToMilliseconds,
  parseGoDuration,
  splitMilliseconds,
} from "../lib/duration.ts";
import { type ColumnSpecMap, useResizableColumns } from "../lib/useResizableColumns.ts";
import { Button } from "../components/ui/button.tsx";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card.tsx";
import { Input } from "../components/ui/input.tsx";
import { Select } from "../components/ui/select.tsx";

type GroupStrategy = "selector" | "urltest" | "failover" | "loadbalance";
type GroupSortMode = "manual" | "name" | "strategy" | "count";
type ProxyTableCol = "select" | "name" | "protocol" | "endpoint" | "ping" | "latency" | "down" | "up" | "action";

const PROXY_TABLE_COL_SPECS: ColumnSpecMap<ProxyTableCol> = {
  select: { defaultWidth: 36, minWidth: 34, maxWidth: 64 },
  name: { defaultWidth: 224, minWidth: 140, maxWidth: 560 },
  protocol: { defaultWidth: 88, minWidth: 70, maxWidth: 180 },
  endpoint: { defaultWidth: 162, minWidth: 110, maxWidth: 380 },
  ping: { defaultWidth: 74, minWidth: 62, maxWidth: 150 },
  latency: { defaultWidth: 84, minWidth: 72, maxWidth: 160 },
  down: { defaultWidth: 84, minWidth: 70, maxWidth: 160 },
  up: { defaultWidth: 84, minWidth: 70, maxWidth: 160 },
  action: { defaultWidth: 196, minWidth: 184, maxWidth: 280 },
};

const groupCollator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

function canonicalStrategy(raw: string): GroupStrategy {
  const lower = (raw || "").trim().toLowerCase();
  if (lower === "urltest" || lower === "latency") return "urltest";
  if (lower === "failover") return "failover";
  if (lower === "loadbalance" || lower === "load-balance" || lower === "hash") return "loadbalance";
  return "selector";
}

export function ProxiesView() {
  const {
    tr,
    locale,
    status,
    nodes,
    groups,
    subscriptions,
    customNodeTabs,
    saveCustomNodeTabs,
    nodeViewMode,
    setNodeViewMode,
    refreshAll,
    toggleConnect,
    notify,
  } = useAppStore();

  const [categoryTab, setCategoryTab] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [protoFilter, setProtoFilter] = useState("all");
  const [probeMode, setProbeMode] = useState<ProbeMode>("urltest");
  const [sortField, setSortField] = useState<NodeSortField>("default");
  const [sortDir, setSortDir] = useState<SortDirection>("asc");
  const [sortStatus, setSortStatus] = useState("");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [probingBatch, setProbingBatch] = useState(false);
  const [probingId, setProbingId] = useState<string | null>(null);
  const [probingGroupId, setProbingGroupId] = useState<string | null>(null);

  const [manageTabsOpen, setManageTabsOpen] = useState(false);
  const [newTabName, setNewTabName] = useState("");
  const [renamingTag, setRenamingTag] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");
  const [savingTabs, setSavingTabs] = useState(false);

  const isMobile = useIsMobile();
  const [inspectorMode, setInspectorMode] = useState<null | "node" | "qr" | "group">(null);
  const [filterSheetOpen, setFilterSheetOpen] = useState(false);
  const [editingNode, setEditingNode] = useState<NodeConfig | null>(null);
  const [qrState, setQrState] = useState<{ open: boolean; name: string; uri: string }>({
    open: false,
    name: "",
    uri: "",
  });
  const [contextMenu, setContextMenu] = useState<NodeContextMenuState | null>(null);

  useEffect(() => {
    const onQuickCreate = (e: Event) => {
      if ((e as CustomEvent<string>).detail === "node") {
        setEditingNode(null);
        setInspectorMode("node");
      }
    };
    window.addEventListener("prismray-quick-create", onQuickCreate);
    return () => window.removeEventListener("prismray-quick-create", onQuickCreate);
  }, []);

  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [groupName, setGroupName] = useState("");
  const [groupStrategy, setGroupStrategy] = useState<GroupStrategy>("selector");
  const [groupPriorityRule, setGroupPriorityRule] = useState("");
  const [groupAutoFailover, setGroupAutoFailover] = useState<"inherit" | "on" | "off">("inherit");
  const [groupDetourId, setGroupDetourId] = useState("");
  const [groupIntervalVal, setGroupIntervalVal] = useState(5);
  const [groupIntervalUnit, setGroupIntervalUnit] = useState<DurationUnit>("m");
  const [groupToleranceVal, setGroupToleranceVal] = useState(50);
  const [groupToleranceUnit, setGroupToleranceUnit] = useState<DurationUnit>("ms");
  const [groupSortOrder, setGroupSortOrder] = useState(0);
  const [groupSelectedNodeId, setGroupSelectedNodeId] = useState("");
  const [groupNodeIds, setGroupNodeIds] = useState<string[]>([]);
  const [savingGroup, setSavingGroup] = useState(false);

  const [healthSettings, setHealthSettings] = useState<HealthSettings | null>(null);
  const [groupSortBy, setGroupSortBy] = useState<GroupSortMode>("manual");
  const [groupOrderOverride, setGroupOrderOverride] = useState<string[] | null>(null);
  const [groupDragIndex, setGroupDragIndex] = useState<number | null>(null);
  const groupListRef = useRef<HTMLDivElement>(null);
  const activeGroupDragRef = useRef<number | null>(null);
  const groupOrderOverrideRef = useRef<string[] | null>(null);

  const tabRefs = useRef<Map<string, HTMLButtonElement>>(new Map());

  useEffect(() => {
    void api
      .getHealthSettings()
      .then(setHealthSettings)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (activeGroupDragRef.current === null) {
      setGroupOrderOverride(null);
      groupOrderOverrideRef.current = null;
    }
  }, [groups]);

  const [qrImportOpen, setQrImportOpen] = useState(false);

  const subNameMap = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of subscriptions) {
      map.set(s.id, s.name);
    }
    return map;
  }, [subscriptions]);

  const allUserTags = useMemo(() => {
    const ordered: string[] = [];
    const seen = new Set<string>();
    const pushTag = (raw: string) => {
      const clean = raw.trim();
      if (!clean || seen.has(clean)) return;
      seen.add(clean);
      ordered.push(clean);
    };
    for (const t of customNodeTabs) pushTag(t);
    for (const n of nodes) {
      for (const t of n.tags || []) pushTag(t);
      if (n.group) pushTag(n.group);
    }
    return ordered;
  }, [customNodeTabs, nodes]);

  const nodeTabs = useMemo<NodeFilterTab[]>(
    () =>
      buildNodeFilterTabs(nodes, subscriptions, customNodeTabs, {
        all: tr("proxies.tabAll"),
        manual: tr("proxies.tabManual"),
        favorites: tr("proxies.tabFavorites"),
      }),
    [nodes, subscriptions, customNodeTabs, tr],
  );

  const effectiveTab = nodeTabs.some((tab) => tab.id === categoryTab) ? categoryTab : "all";

  useEffect(() => {
    const btn = tabRefs.current.get(effectiveTab);
    btn?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [effectiveTab]);

  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nodes.filter((n) => {
      if (!nodeMatchesFilterTab(n, effectiveTab)) return false;

      if (protoFilter !== "all" && n.protocol !== protoFilter) return false;
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        (n.user_alias || "").toLowerCase().includes(q) ||
        (n.group || "").toLowerCase().includes(q) ||
        (n.tags || []).join(" ").toLowerCase().includes(q) ||
        n.address.toLowerCase().includes(q) ||
        n.protocol.toLowerCase().includes(q)
      );
    });
  }, [nodes, effectiveTab, search, protoFilter]);

  const displayedNodes = useMemo(
    () => sortNodesByMetric(filteredNodes, sortField, sortDir),
    [filteredNodes, sortField, sortDir],
  );

  const nodeIdSet = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const selectedValidIds = useMemo(
    () => selectedIds.filter((id) => nodeIdSet.has(id)),
    [selectedIds, nodeIdSet],
  );
  const selectedSet = useMemo(() => new Set(selectedValidIds), [selectedValidIds]);
  const allFilteredSelected =
    displayedNodes.length > 0 && displayedNodes.every((n) => selectedSet.has(n.id));

  const toggleSelectNode = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    );
  };

  const toggleSelectAllFiltered = () => {
    const filteredIds = displayedNodes.map((n) => n.id);
    if (allFilteredSelected) {
      const filteredSet = new Set(filteredIds);
      setSelectedIds((prev) => prev.filter((id) => !filteredSet.has(id)));
    } else {
      setSelectedIds((prev) => Array.from(new Set([...prev, ...filteredIds])));
    }
  };

  const probeModeLabel = (mode: ProbeMode) => {
    switch (mode) {
      case "ping":
        return tr("proxies.probeModePing");
      case "speed":
        return tr("proxies.probeModeSpeed");
      case "full":
        return tr("proxies.probeModeFull");
      default:
        return tr("proxies.probeModeUrl");
    }
  };

  const handleSortFieldChange = (nextField: NodeSortField) => {
    if (nextField === sortField && nextField !== "default") {
      const nextDir: SortDirection = sortDir === "asc" ? "desc" : "asc";
      setSortDir(nextDir);
      setSortStatus(
        locale === "zh-CN"
          ? `已切换排序方向为${nextDir === "asc" ? "升序" : "降序"}`
          : `Sort direction changed to ${nextDir}`,
      );
      return;
    }
    const defaultDir: SortDirection = nextField === "down" || nextField === "up" ? "desc" : "asc";
    setSortField(nextField);
    setSortDir(defaultDir);
    if (nextField !== "default") {
      setSortStatus(
        locale === "zh-CN"
          ? `已按 ${nextField} 排序`
          : `Sorted nodes by ${nextField}`,
      );
    }
  };

  const handleProbeBatch = async (targetIds?: string[]) => {
    setProbingBatch(true);
    try {
      const payload =
        targetIds && targetIds.length > 0
          ? { node_ids: targetIds, mode: probeMode }
          : { mode: probeMode };
      const res = await api.probeNodes(payload);
      await refreshAll();
      notify(tr("proxies.probeCompleted", { count: res.tested, mode: probeModeLabel(probeMode) }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setProbingBatch(false);
    }
  };

  const handleProbeSingle = async (id: string) => {
    setProbingId(id);
    try {
      await api.probeNode(id, { mode: probeMode });
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setProbingId(null);
    }
  };

  const handleProbeGroup = async (group: GroupConfig) => {
    setProbingGroupId(group.id);
    try {
      await api.probeGroup(group.id, { mode: probeMode === "ping" ? "ping" : "urltest" });
      await refreshAll();
      notify(tr("proxies.groupProbed", { name: group.name }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setProbingGroupId(null);
    }
  };

  const handleCreateCustomTab = async (e: React.FormEvent) => {
    e.preventDefault();
    const clean = newTabName.trim();
    if (!clean) return;
    setSavingTabs(true);
    try {
      const next = Array.from(new Set([...customNodeTabs, clean]));
      await saveCustomNodeTabs(next);
      setNewTabName("");
      setCategoryTab(`utag:${clean}`);
      notify(tr("proxies.tabCreated", { name: clean }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingTabs(false);
    }
  };

  const handleDeleteCustomTab = async (tagName: string) => {
    setSavingTabs(true);
    try {
      const nextTabs = customNodeTabs.filter((t) => t !== tagName);
      await saveCustomNodeTabs(nextTabs);
      const affected = nodes.filter((n) => (n.tags || []).includes(tagName));
      await Promise.all(
        affected.map((n) =>
          api.updateNode(n.id, { ...n, tags: (n.tags || []).filter((t) => t !== tagName) }),
        ),
      );
      if (effectiveTab === `utag:${tagName}`) setCategoryTab("all");
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingTabs(false);
    }
  };

  const handleCommitRenameTab = async (oldName: string) => {
    const clean = renameDraft.trim();
    if (!clean || clean === oldName) {
      setRenamingTag(null);
      return;
    }
    setSavingTabs(true);
    try {
      const nextTabs = Array.from(
        new Set(customNodeTabs.map((t) => (t === oldName ? clean : t))),
      );
      if (!nextTabs.includes(clean)) nextTabs.push(clean);
      await saveCustomNodeTabs(nextTabs);
      const affected = nodes.filter((n) => nodeHasTag(n, oldName));
      await Promise.all(
        affected.map((n) => {
          const nextNodeTags = Array.from(
            new Set([
              ...(n.tags || []).filter((t) => t !== oldName),
              clean,
            ]),
          );
          return api.updateNode(n.id, {
            ...n,
            group: (n.group || "").trim() === oldName ? clean : n.group,
            tags: nextNodeTags,
          });
        }),
      );
      if (effectiveTab === `utag:${oldName}`) setCategoryTab(`utag:${clean}`);
      setRenamingTag(null);
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingTabs(false);
    }
  };

  const handleBatchAssignTag = async (tagName: string) => {
    if (!tagName || selectedValidIds.length === 0) return;
    try {
      const targets = nodes.filter((n) => selectedSet.has(n.id));
      await Promise.all(
        targets.map((n) => {
          const nextTags = Array.from(new Set([...(n.tags || []), tagName]));
          return api.updateNode(n.id, { ...n, tags: nextTags });
        }),
      );
      await refreshAll();
      notify(`${tr("proxies.assignTab")}: #${tagName} (${targets.length})`);
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleToggleFavorite = async (node: NodeConfig) => {
    try {
      await api.updateNode(node.id, { ...node, favorite: !node.favorite });
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleDeleteNode = async (id: string) => {
    try {
      await api.deleteNode(id);
      setSelectedIds((prev) => prev.filter((item) => item !== id));
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const handleOpenQR = async (node: NodeConfig) => {
    try {
      const res = await api.getNodeUri(node.id);
      setQrState({ open: true, name: node.user_alias || node.name, uri: res.uri });
      setInspectorMode("qr");
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const openNodeInspector = (node: NodeConfig | null) => {
    setEditingNode(node);
    setInspectorMode("node");
  };

  const handleSelectGroupNode = async (groupId: string, nodeId: string) => {
    try {
      await api.selectGroupNode(groupId, nodeId);
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const openCreateGroupForm = () => {
    setEditingGroupId(null);
    setGroupName("");
    setGroupStrategy("selector");
    setGroupPriorityRule("");
    setGroupAutoFailover("inherit");
    setGroupDetourId("");
    setGroupIntervalVal(5);
    setGroupIntervalUnit("m");
    setGroupToleranceVal(50);
    setGroupToleranceUnit("ms");
    setGroupSortOrder(groups.length);
    setGroupSelectedNodeId("");
    setGroupNodeIds([]);
    setInspectorMode("group");
  };

  const openEditGroupForm = (g: GroupConfig) => {
    const strat = canonicalStrategy(g.strategy);
    const parsedInt = parseGoDuration(
      g.interval || (strat === "failover" ? "1m" : strat === "loadbalance" ? "3m" : "5m"),
      ["ms", "s", "m", "h", "d"],
      { value: strat === "failover" ? 1 : strat === "loadbalance" ? 3 : 5, unit: "m" },
    );
    const parsedTol = splitMilliseconds(
      g.tolerance_ms || (strat === "failover" ? 1000 : 50),
      ["ms", "s", "m"],
      "ms",
    );
    setEditingGroupId(g.id);
    setGroupName(g.name);
    setGroupStrategy(strat);
    setGroupPriorityRule(g.priority_rule || "");
    setGroupAutoFailover(g.auto_failover === true ? "on" : g.auto_failover === false ? "off" : "inherit");
    setGroupDetourId(g.detour_id || "");
    setGroupIntervalVal(parsedInt.value);
    setGroupIntervalUnit(parsedInt.unit);
    setGroupToleranceVal(parsedTol.value);
    setGroupToleranceUnit(parsedTol.unit);
    setGroupSortOrder(g.sort_order || 0);
    setGroupSelectedNodeId(g.selected_node_id || "");
    setGroupNodeIds(g.node_ids || []);
    setInspectorMode("group");
  };

  const closeGroupForm = () => {
    setEditingGroupId(null);
    setInspectorMode(null);
  };

  const handleSubmitGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupName.trim()) return;
    setSavingGroup(true);
    try {
      const nextSelected =
        groupSelectedNodeId && groupNodeIds.includes(groupSelectedNodeId)
          ? groupSelectedNodeId
          : groupNodeIds[0] || "";
      const needsHealthTiming = groupStrategy !== "selector" || groupAutoFailover === "on";
      const serializedInterval =
        groupIntervalVal > 0
          ? formatGoDuration(groupIntervalVal, groupIntervalUnit)
          : groupStrategy === "loadbalance"
            ? "3m"
            : "5m";
      const serializedToleranceMs = Math.max(0, joinToMilliseconds(groupToleranceVal, groupToleranceUnit));
      const payload = {
        name: groupName.trim(),
        strategy: groupStrategy,
        selected_node_id: nextSelected,
        priority_rule: groupPriorityRule,
        auto_failover: groupAutoFailover === "inherit" ? null : groupAutoFailover === "on",
        detour_id: groupDetourId.trim(),
        interval: needsHealthTiming ? serializedInterval : "",
        tolerance_ms: needsHealthTiming ? serializedToleranceMs || 50 : 0,
        sort_order: groupSortOrder,
        node_ids: groupNodeIds,
      };
      if (editingGroupId) {
        await api.updateGroup(editingGroupId, { id: editingGroupId, ...payload });
        notify(locale === "zh-CN" ? "策略分组已更新" : "Policy group updated");
      } else {
        await api.createGroup(payload);
        notify(locale === "zh-CN" ? "策略分组已创建" : "Policy group created");
      }
      closeGroupForm();
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSavingGroup(false);
    }
  };

  const displayedGroups = useMemo(() => {
    const copy = [...groups];
    if (groupSortBy === "manual") {
      if (groupOrderOverride) {
        const orderMap = new Map<string, number>();
        groupOrderOverride.forEach((id, idx) => orderMap.set(id, idx));
        copy.sort((a, b) => (orderMap.get(a.id) ?? a.sort_order) - (orderMap.get(b.id) ?? b.sort_order));
      } else {
        copy.sort((a, b) => (a.sort_order ?? 0) - (b.sort_order ?? 0));
      }
      return copy;
    }
    if (groupSortBy === "name") {
      copy.sort((a, b) => groupCollator.compare(a.name, b.name));
    } else if (groupSortBy === "strategy") {
      copy.sort(
        (a, b) =>
          groupCollator.compare(canonicalStrategy(a.strategy), canonicalStrategy(b.strategy)) ||
          groupCollator.compare(a.name, b.name),
      );
    } else if (groupSortBy === "count") {
      copy.sort((a, b) => (b.node_ids?.length || 0) - (a.node_ids?.length || 0) || groupCollator.compare(a.name, b.name));
    }
    return copy;
  }, [groups, groupSortBy, groupOrderOverride]);

  const persistGroupOrder = async (orderedIds: string[]) => {
    try {
      await api.reorderGroups(orderedIds);
      setGroupOrderOverride(null);
      groupOrderOverrideRef.current = null;
      await refreshAll();
      notify(tr("proxies.groupReordered"));
    } catch (err) {
      setGroupOrderOverride(null);
      groupOrderOverrideRef.current = null;
      notify(formatApiError(err), "error");
    }
  };

  const swapGroupOrderDraft = (fromIndex: number, toIndex: number) => {
    const base = groupOrderOverrideRef.current || displayedGroups.map((g) => g.id);
    if (fromIndex === toIndex || toIndex < 0 || toIndex >= base.length) return;
    const next = [...base];
    const [item] = next.splice(fromIndex, 1);
    if (!item) return;
    next.splice(toIndex, 0, item);
    groupOrderOverrideRef.current = next;
    setGroupOrderOverride(next);
  };

  const moveGroupOrder = (idx: number, delta: -1 | 1) => {
    const targetIdx = idx + delta;
    const ids = displayedGroups.map((g) => g.id);
    if (targetIdx < 0 || targetIdx >= ids.length) return;
    const next = [...ids];
    const [item] = next.splice(idx, 1);
    if (!item) return;
    next.splice(targetIdx, 0, item);
    groupOrderOverrideRef.current = next;
    setGroupOrderOverride(next);
    void persistGroupOrder(next);
  };

  useEffect(() => {
    const onPointerMove = (e: PointerEvent) => {
      const currentIdx = activeGroupDragRef.current;
      if (currentIdx === null || !groupListRef.current) return;
      const cards = Array.from(groupListRef.current.querySelectorAll<HTMLElement>("[data-group-card]"));
      for (const card of cards) {
        const idxAttr = Number(card.dataset.groupCard);
        if (!Number.isFinite(idxAttr) || idxAttr === currentIdx) continue;
        const rect = card.getBoundingClientRect();
        if (
          e.clientX >= rect.left &&
          e.clientX <= rect.right &&
          ((currentIdx < idxAttr && e.clientY > rect.top + rect.height / 2) ||
            (currentIdx > idxAttr && e.clientY < rect.top + rect.height / 2))
        ) {
          swapGroupOrderDraft(currentIdx, idxAttr);
          activeGroupDragRef.current = idxAttr;
          setGroupDragIndex(idxAttr);
          break;
        }
      }
    };

    const endGroupDrag = () => {
      if (activeGroupDragRef.current !== null) {
        activeGroupDragRef.current = null;
        setGroupDragIndex(null);
        const pending = groupOrderOverrideRef.current;
        if (pending && pending.length > 0) {
          void persistGroupOrder(pending);
        }
      }
    };

    window.addEventListener("pointermove", onPointerMove);
    window.addEventListener("pointerup", endGroupDrag);
    window.addEventListener("pointercancel", endGroupDrag);
    return () => {
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", endGroupDrag);
      window.removeEventListener("pointercancel", endGroupDrag);
    };
  });

  const handleDeleteGroup = async (groupId: string) => {
    try {
      await api.deleteGroup(groupId);
      if (editingGroupId === groupId) {
        closeGroupForm();
      }
      await refreshAll();
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  const getNodeSourceLabel = (n: NodeConfig): string => {
    const sid = n.sub_id?.trim();
    if (sid) return subNameMap.get(sid) || sid;
    const grp = n.group?.trim();
    if (grp && !(n.tags || []).includes(grp)) return `#${grp}`;
    return tr("proxies.sourceManual");
  };

  const getDetourLabel = (detourId?: string) => {
    const id = (detourId || "").trim();
    if (!id) return "";
    const g = groups.find((item) => item.id === id);
    if (g) return g.name;
    const targetNode = nodes.find((item) => item.id === id);
    if (targetNode) return targetNode.user_alias || targetNode.name;
    return id;
  };

  const renderStrategyPill = (strat: GroupStrategy, memberCount: number) => {
    const config: Record<
      GroupStrategy,
      { label: string; icon: React.ReactNode; toneClass: string }
    > = {
      selector: {
        label: locale === "zh-CN" ? "手动选择" : "Manual",
        icon: <Hand className="h-3 w-3 shrink-0" aria-hidden="true" />,
        toneClass: "border-border/80 bg-muted/75 text-foreground/80",
      },
      urltest: {
        label: locale === "zh-CN" ? "自动优选" : "Auto Fast",
        icon: <Zap className="h-3 w-3 shrink-0" aria-hidden="true" />,
        toneClass: "border-primary/35 bg-primary/12 text-primary",
      },
      failover: {
        label: locale === "zh-CN" ? "故障转移" : "Failover",
        icon: <ShieldCheck className="h-3 w-3 shrink-0" aria-hidden="true" />,
        toneClass: "border-amber-500/35 bg-amber-500/12 text-amber-700 dark:text-amber-400",
      },
      loadbalance: {
        label: locale === "zh-CN" ? "负载均衡" : "Load Balance",
        icon: <GitBranch className="h-3 w-3 shrink-0" aria-hidden="true" />,
        toneClass: "border-emerald-500/35 bg-emerald-500/12 text-emerald-700 dark:text-emerald-400",
      },
    };
    const c = config[strat];
    return (
      <>
        <span
          className={`inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium leading-none ${c.toneClass}`}
        >
          {c.icon}
          <span>{c.label}</span>
        </span>
        <span className="inline-flex shrink-0 items-center whitespace-nowrap rounded-full bg-muted/60 px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground tabular-nums">
          {locale === "zh-CN" ? `${memberCount} 节点` : `${memberCount} nodes`}
        </span>
      </>
    );
  };

  const renderNodeTelemetryBadge = (n: NodeConfig, showExtraWhenWide = false) => {
    const latencyTone =
      n.latency && n.latency > 0
        ? "border-primary/40 bg-primary/8 text-primary"
        : n.latency === -1
          ? "border-destructive/40 bg-destructive/8 text-destructive"
          : "border-border bg-muted/40 text-muted-foreground";

    return (
      <HoverPopover
        stopPropagationOnTap
        ariaLabel={tr("proxies.metricUrl")}
        maxWidthPx={280}
        className="inline-flex shrink-0 items-center gap-1.5 cursor-help"
        content={
          <div className="space-y-2 text-xs tabular-nums">
            <div className="flex items-center justify-between gap-2 border-b border-border pb-1.5">
              <span className="truncate font-semibold text-foreground">{n.user_alias || n.name}</span>
              <span className="shrink-0 badge-radius bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                {n.protocol}
              </span>
            </div>
            <div className="break-all font-mono text-[11px] text-muted-foreground">
              {n.address}:{n.port}
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 pt-0.5 text-[11px]">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("proxies.metricPing")}</span>
                <span className="font-medium text-foreground">{formatLatency(n.ping_ms)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("proxies.metricUrl")}</span>
                <span className="font-medium text-primary">{formatLatency(n.latency)}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("proxies.metricDown")}</span>
                <span className="font-medium text-emerald-600 dark:text-emerald-400">
                  {formatSpeedMbps(n.down_speed_mbps)}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">{tr("proxies.metricUp")}</span>
                <span className="font-medium text-sky-500">{formatSpeedMbps(n.up_speed_mbps)}</span>
              </div>
            </div>
          </div>
        }
      >
        <span
          className={`inline-flex items-center gap-1 badge-radius border px-1.5 py-0.5 text-[11px] font-medium leading-none tabular-nums ${latencyTone}`}
        >
          <span>{formatLatency(n.latency)}</span>
        </span>
        {showExtraWhenWide && n.down_speed_mbps && n.down_speed_mbps > 0 ? (
          <span className="node-card-extra-metric inline-flex items-center text-[11px] font-medium leading-none text-emerald-600 dark:text-emerald-400 tabular-nums">
            ↓{formatSpeedMbps(n.down_speed_mbps)}
          </span>
        ) : null}
      </HoverPopover>
    );
  };

  const renderNodeActionButtons = (n: NodeConfig, compact = false) => {
    const isActive = status?.running && status.active_node_id === n.id;
    const displayName = n.user_alias || n.name;
    const connectTip = isActive ? tr("action.disconnect") : tr("action.connect");
    return (
      <div className={`flex flex-nowrap items-center gap-0.5 ${compact ? "justify-start" : "justify-end"}`}>
        <button
          type="button"
          onClick={() => void toggleConnect({ nodeId: n.id })}
          title={connectTip}
          aria-label={`${connectTip} ${displayName}`}
          className={[
            "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] border transition-[color,background-color,border-color,transform] duration-150 active:scale-[0.95]",
            isActive
              ? "border-primary/45 bg-primary/15 text-primary hover:bg-primary/25"
              : "border-transparent text-primary hover:bg-primary/15",
          ].join(" ")}
        >
          {isActive ? (
            <Square className="h-3 w-3 fill-current" aria-hidden="true" />
          ) : (
            <Play className="h-3.5 w-3.5" aria-hidden="true" />
          )}
        </button>

        {compact ? (
          <button
            type="button"
            onClick={() => void handleToggleFavorite(n)}
            title={tr("proxies.tabFavorites")}
            aria-label={`${tr("proxies.tabFavorites")} ${displayName}`}
            className={[
              "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted",
              n.favorite ? "text-amber-500" : "text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            <Star className="h-3.5 w-3.5" fill={n.favorite ? "currentColor" : "none"} aria-hidden="true" />
          </button>
        ) : null}

        <button
          type="button"
          onClick={() => void handleProbeSingle(n.id)}
          disabled={probingId === n.id}
          title={tr("proxies.metricUrl")}
          aria-label={`Probe ${displayName}`}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted hover:text-foreground disabled:opacity-50"
        >
          <Gauge className={`h-3.5 w-3.5 ${probingId === n.id ? "animate-spin text-primary" : ""}`} aria-hidden="true" />
        </button>

        <button
          type="button"
          onClick={() => openNodeInspector(n)}
          title={tr("action.edit")}
          aria-label={`${tr("action.edit")} ${displayName}`}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted hover:text-foreground"
        >
          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
        </button>

        <button
          type="button"
          onClick={() => void handleOpenQR(n)}
          title={tr("proxies.qrTitle")}
          aria-label={`${tr("proxies.qrTitle")} ${displayName}`}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted hover:text-foreground"
        >
          <QrCode className="h-3.5 w-3.5" aria-hidden="true" />
        </button>

        <button
          type="button"
          onClick={() => void handleDeleteNode(n.id)}
          title={tr("action.delete")}
          aria-label={`${tr("action.delete")} ${displayName}`}
          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-destructive/15 hover:text-destructive"
        >
          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>
    );
  };

  const strategyDescKey =
    groupStrategy === "urltest"
      ? "proxies.strategyUrltestDesc"
      : groupStrategy === "failover"
        ? "proxies.strategyFailoverDesc"
        : groupStrategy === "loadbalance"
          ? "proxies.strategyLoadbalanceDesc"
          : "proxies.strategySelectorDesc";

  const globalRuleLabel = (rule?: string) => {
    if (rule === "speed_first") return tr("settings.ruleSpeedFirst");
    if (rule === "hybrid_score") return tr("settings.ruleHybridScore");
    return tr("settings.ruleLatencyFirst");
  };
  const globalFailoverStateLabel = healthSettings?.failover
    ? locale === "zh-CN"
      ? "开启"
      : "On"
    : locale === "zh-CN"
      ? "关闭"
      : "Off";

  const isFiltered = effectiveTab !== "all" || Boolean(search.trim()) || protoFilter !== "all";
  const primaryProbeTargets =
    selectedValidIds.length > 0
      ? selectedValidIds
      : isFiltered
        ? displayedNodes.map((n) => n.id)
        : undefined;
  const primaryProbeLabel =
    selectedValidIds.length > 0
      ? tr("proxies.probeSelected", { count: selectedValidIds.length })
      : isFiltered
        ? tr("proxies.probeFiltered", { count: displayedNodes.length })
        : tr("action.testAll");

  const {
    widths: nodeColWidths,
    resizingCol: resizingNodeCol,
    startResize: startNodeColResize,
    resetColumn: resetNodeColWidth,
  } = useResizableColumns("proxies-nodes", PROXY_TABLE_COL_SPECS);

  const renderSortableColHeader = (col: NodeSortField, label: string, widthKey: ProxyTableCol) => {
    const isSorted = sortField === col;
    return (
      <th
        scope="col"
        className="sortable-th whitespace-nowrap"
        aria-sort={isSorted ? (sortDir === "asc" ? "ascending" : "descending") : undefined}
      >
        <button type="button" onClick={() => handleSortFieldChange(col)}>
          <span>{label}</span>
          {isSorted ? (
            sortDir === "asc" ? (
              <ArrowUp className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
            ) : (
              <ArrowDown className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
            )
          ) : (
            <ArrowUpDown className="h-3.5 w-3.5 shrink-0 opacity-45" aria-hidden="true" />
          )}
        </button>
        <ColumnResizeHandle
          active={resizingNodeCol === widthKey}
          title={tr("table.resizeHint")}
          onPointerDown={(e) => startNodeColResize(widthKey, e)}
          onDoubleClick={() => resetNodeColWidth(widthKey)}
        />
      </th>
    );
  };

  const inspectedNode = useMemo(() => {
    if (!editingNode) return null;
    return nodes.find((n) => n.id === editingNode.id) ?? editingNode;
  }, [nodes, editingNode]);

  return (
    <div className="flex flex-col md:flex-row md:items-start gap-4">
      <div className="flex-1 min-w-0 space-y-4">
      <p role="status" className="visually-hidden">
        {sortStatus}
      </p>

      {/* Policy Groups */}
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2 space-y-0 pb-2.5">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" aria-hidden="true" />
            <CardTitle className="text-sm font-semibold">{tr("proxies.groupsTitle")}</CardTitle>
          </div>
          <div className="flex shrink-0 items-center gap-2 whitespace-nowrap">
            {groups.length > 1 ? (
              <Select
                size="sm"
                className="w-32 shrink-0"
                aria-label={tr("proxies.groupSortBy")}
                value={groupSortBy}
                onChange={(e) => setGroupSortBy(e.target.value as GroupSortMode)}
              >
                <option value="manual">{tr("proxies.groupSortManual")}</option>
                <option value="name">{tr("proxies.groupSortName")}</option>
                <option value="strategy">{tr("proxies.groupSortStrategy")}</option>
                <option value="count">{tr("proxies.groupSortCount")}</option>
              </Select>
            ) : null}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="shrink-0 whitespace-nowrap"
              onClick={openCreateGroupForm}
            >
              <Plus className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
              {tr("proxies.addGroup")}
            </Button>
          </div>
        </CardHeader>

        <CardContent className="space-y-3">
          {displayedGroups.length === 0 ? (
            <p className="text-xs text-muted-foreground">{tr("proxies.groupEmpty")}</p>
          ) : (
            <div ref={groupListRef} className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,19rem),1fr))] gap-3">
              {displayedGroups.map((g, idx) => {
                const strat = canonicalStrategy(g.strategy);
                const dragging = groupDragIndex === idx;
                return (
                  <div
                    key={g.id}
                    data-group-card={idx}
                    className={`prism-card-interactive space-y-2 rounded-[10px] border border-border bg-muted/20 p-3 ${
                      dragging ? "rule-row-dragging" : "hover:border-primary/40"
                    }`}
                  >
                    {/* Row 1: Strict single-line title + 6 aligned action icons (never wraps on resize) */}
                    <div className="flex h-7 items-center justify-between gap-2">
                      <div className="flex min-w-0 flex-1 items-center gap-1.5">
                        {groupSortBy === "manual" && displayedGroups.length > 1 ? (
                          <button
                            type="button"
                            onPointerDown={() => {
                              groupOrderOverrideRef.current = displayedGroups.map((item) => item.id);
                              activeGroupDragRef.current = idx;
                              setGroupDragIndex(idx);
                            }}
                            aria-label={tr("routing.dragHandle")}
                            title={tr("routing.dragHandle")}
                            className="drag-handle inline-flex h-6 w-6 shrink-0 cursor-grab items-center justify-center rounded-[4px] text-muted-foreground hover:bg-muted hover:text-foreground active:cursor-grabbing max-md:min-h-10 max-md:min-w-10"
                          >
                            <GripVertical className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        ) : null}
                        <span className="min-w-0 truncate text-[13px] font-semibold leading-none text-foreground" title={g.name}>
                          {g.name}
                        </span>
                      </div>
                      <div className="flex shrink-0 flex-nowrap items-center gap-0.5">
                        {groupSortBy === "manual" && displayedGroups.length > 1 ? (
                          <>
                            <button
                              type="button"
                              disabled={idx === 0}
                              onClick={() => moveGroupOrder(idx, -1)}
                              title={locale === "zh-CN" ? "上移" : "Move up"}
                              aria-label="Move group up"
                              className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-30"
                            >
                              <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
                            </button>
                            <button
                              type="button"
                              disabled={idx === displayedGroups.length - 1}
                              onClick={() => moveGroupOrder(idx, 1)}
                              title={locale === "zh-CN" ? "下移" : "Move down"}
                              aria-label="Move group down"
                              className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-colors hover:bg-muted hover:text-foreground disabled:opacity-30"
                            >
                              <ArrowDown className="h-3.5 w-3.5" aria-hidden="true" />
                            </button>
                          </>
                        ) : null}
                        <button
                          type="button"
                          disabled={probingGroupId === g.id}
                          onClick={() => void handleProbeGroup(g)}
                          title={tr("proxies.probeGroupBtn")}
                          aria-label={`${tr("proxies.probeGroupBtn")} ${g.name}`}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted hover:text-foreground disabled:opacity-50"
                        >
                          <Gauge className={`h-3.5 w-3.5 ${probingGroupId === g.id ? "animate-spin text-primary" : ""}`} aria-hidden="true" />
                        </button>
                        {(() => {
                          const groupActive = status?.active_group_id === g.id && status.running;
                          const tip = groupActive ? tr("action.disconnect") : tr("action.connect");
                          return (
                            <button
                              type="button"
                              onClick={() => void toggleConnect({ groupId: g.id })}
                              title={tip}
                              aria-label={`${tip} ${g.name}`}
                              className={[
                                "inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] border transition-[color,background-color,border-color,transform] duration-150 active:scale-[0.95]",
                                groupActive
                                  ? "border-primary/45 bg-primary/15 text-primary hover:bg-primary/25"
                                  : "border-transparent text-primary hover:bg-primary/15",
                              ].join(" ")}
                            >
                              {groupActive ? (
                                <Square className="h-3 w-3 fill-current" aria-hidden="true" />
                              ) : (
                                <Play className="h-3.5 w-3.5" aria-hidden="true" />
                              )}
                            </button>
                          );
                        })()}
                        <button
                          type="button"
                          onClick={() => openEditGroupForm(g)}
                          title={tr("proxies.editGroup")}
                          aria-label={`${tr("proxies.editGroup")} ${g.name}`}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-muted hover:text-foreground"
                        >
                          <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeleteGroup(g.id)}
                          title={tr("action.delete")}
                          aria-label={`${tr("action.delete")} ${g.name}`}
                          className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] text-muted-foreground transition-[color,background-color,transform] duration-150 active:scale-[0.95] hover:bg-destructive/15 hover:text-destructive"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </div>
                    </div>

                    {/* Row 2: Harmonious localized strategy pill + count + metadata badges */}
                    <div className="flex flex-wrap items-center gap-1.5">
                      {renderStrategyPill(strat, (g.node_ids || []).length)}
                      {g.priority_rule ? (
                        <span className="inline-flex shrink-0 items-center whitespace-nowrap rounded-full border border-border bg-background px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
                          {globalRuleLabel(g.priority_rule)}
                        </span>
                      ) : null}
                      {g.auto_failover === true || g.auto_failover === false ? (
                        <span className="inline-flex shrink-0 items-center whitespace-nowrap rounded-full border border-border bg-background px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
                          {g.auto_failover
                            ? locale === "zh-CN"
                              ? "自动切换"
                              : "Auto Switch"
                            : locale === "zh-CN"
                              ? "仅排序"
                              : "Rank Only"}
                        </span>
                      ) : null}
                      {g.detour_id ? (
                        <span
                          className="inline-flex shrink-0 max-w-[12rem] items-center truncate whitespace-nowrap rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[10px] font-medium leading-none text-primary"
                          title={tr("node.detourVia", { name: getDetourLabel(g.detour_id) })}
                        >
                          {tr("node.detourVia", { name: getDetourLabel(g.detour_id) })}
                        </span>
                      ) : null}
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      {(g.node_ids || []).map((nid, idx) => {
                        const node = nodes.find((n) => n.id === nid);
                        if (!node) return null;
                        const selected = g.selected_node_id === nid;
                        return (
                          <button
                            key={nid}
                            type="button"
                            onClick={() => void handleSelectGroupNode(g.id, nid)}
                            className={[
                              "inline-flex max-w-full items-center gap-1.5 rounded-lg border px-2 py-1 text-left font-sans text-xs leading-none transition-colors tabular-nums active:scale-[0.98]",
                              selected
                                ? "border-primary bg-primary/15 font-medium text-primary"
                                : "bg-background text-muted-foreground hover:text-foreground",
                            ].join(" ")}
                          >
                            <span className="inline-flex shrink-0 items-center rounded bg-muted px-1 py-0.5 text-[10px] font-semibold leading-none text-foreground tabular-nums">
                              {tr("proxies.priorityRank", { rank: idx + 1 })}
                            </span>
                            <span className="truncate leading-normal">{node.user_alias || node.name}</span>
                            <span className="shrink-0 text-xs leading-normal opacity-80 tabular-nums">
                              {formatLatency(node.latency)}
                            </span>
                            {node.down_speed_mbps && node.down_speed_mbps > 0 ? (
                              <span className="shrink-0 text-xs leading-normal text-emerald-600 dark:text-emerald-400 tabular-nums">
                                {formatSpeedMbps(node.down_speed_mbps)}
                              </span>
                            ) : null}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Node Source / User-Defined Category Tabs */}
      <div className="space-y-2 rounded-[10px] border border-border bg-card p-2">
        <div className="flex items-center gap-2">
          <div
            role="tablist"
            aria-label={tr("proxies.nodesTitle")}
            className="tablist-scroller flex-1"
          >
            {nodeTabs.map((tab) => {
              const active = effectiveTab === tab.id;
              return (
                <button
                  key={tab.id}
                  ref={(el) => {
                    if (el) tabRefs.current.set(tab.id, el);
                    else tabRefs.current.delete(tab.id);
                  }}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setCategoryTab(tab.id)}
                  className={[
                    "tab-chip inline-flex min-h-8 items-center gap-1.5 rounded-lg px-3 py-1 text-xs font-medium whitespace-nowrap transition-colors",
                    active
                      ? "bg-primary/15 text-primary"
                      : "bg-muted/50 text-muted-foreground hover:bg-muted hover:text-foreground",
                  ].join(" ")}
                >
                  {tab.tagName ? <Tag className="h-3 w-3 shrink-0" aria-hidden="true" /> : null}
                  <span>{tab.label}</span>
                  <span className="rounded-full bg-background/80 px-1.5 py-0.2 font-mono text-[11px] text-muted-foreground tabular-nums">
                    {tab.count}
                  </span>
                </button>
              );
            })}
          </div>

          <Button
            type="button"
            variant={manageTabsOpen ? "default" : "outline"}
            size="sm"
            className="shrink-0"
            onClick={() => setManageTabsOpen((o) => !o)}
          >
            <FolderPlus className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {tr("proxies.manageTabs")}
          </Button>
        </div>

        {manageTabsOpen ? (
          <div className="space-y-2.5 border-t pt-2.5 text-xs">
            <form onSubmit={(e) => void handleCreateCustomTab(e)} className="flex flex-wrap items-center gap-2">
              <Input
                className="h-8 max-w-xs text-xs"
                placeholder={tr("proxies.newTabPlaceholder")}
                value={newTabName}
                onChange={(e) => setNewTabName(e.target.value)}
              />
              <Button type="submit" size="sm" disabled={savingTabs || !newTabName.trim()}>
                <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                {tr("proxies.createTab")}
              </Button>
            </form>

            {customNodeTabs.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {customNodeTabs.map((tag) => (
                  <div key={tag} className="inline-flex items-center gap-1 rounded-lg border bg-muted/40 px-2 py-1">
                    {renamingTag === tag ? (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void handleCommitRenameTab(tag);
                        }}
                        className="flex items-center gap-1"
                      >
                        <Input
                          className="h-6 w-28 px-1.5 text-xs"
                          value={renameDraft}
                          onChange={(e) => setRenameDraft(e.target.value)}
                          autoFocus
                        />
                        <Button type="submit" size="sm" variant="outline" className="h-6 px-2 text-[11px]">
                          {tr("action.save")}
                        </Button>
                        <button
                          type="button"
                          onClick={() => setRenamingTag(null)}
                          className="text-muted-foreground hover:text-foreground"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </form>
                    ) : (
                      <>
                        <span className="font-medium text-foreground">#{tag}</span>
                        <button
                          type="button"
                          onClick={() => {
                            setRenamingTag(tag);
                            setRenameDraft(tag);
                          }}
                          aria-label={`${tr("proxies.renameTab")} ${tag}`}
                          className="rounded p-0.5 text-muted-foreground hover:text-foreground"
                        >
                          <Pencil className="h-3 w-3" aria-hidden="true" />
                        </button>
                        <button
                          type="button"
                          onClick={() => void handleDeleteCustomTab(tag)}
                          aria-label={`${tr("proxies.deleteTab")} ${tag}`}
                          className="rounded p-0.5 text-muted-foreground hover:text-destructive"
                        >
                          <Trash2 className="h-3 w-3" aria-hidden="true" />
                        </button>
                      </>
                    )}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>

      {/* Filter Toolbar, Sort Controls & Multi-Mode Probe */}
      <div className="space-y-2 md:space-y-0 md:flex md:flex-wrap md:items-center md:justify-between md:gap-2">
        <div className="flex items-center gap-2 md:min-w-[20rem] md:flex-1 md:flex-wrap">
          <search className="relative flex-1 min-w-0 md:min-w-44">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              aria-label={tr("proxies.searchPlaceholder")}
              className="pl-8"
              placeholder={tr("proxies.searchPlaceholder")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </search>

          {/* Mobile Filter & Sort Bottom-Sheet Trigger */}
          <Button
            type="button"
            variant="outline"
            onClick={() => setFilterSheetOpen(true)}
            className="md:hidden shrink-0"
          >
            <SlidersHorizontal className="mr-1.5 h-4 w-4" aria-hidden="true" />
            {tr("mobile.filterSheet")}
          </Button>

          <div className="hidden md:block w-28 shrink-0">
            <Select
              aria-label={tr("proxies.allProtocols")}
              size="sm"
              value={protoFilter}
              onChange={(e) => setProtoFilter(e.target.value)}
            >
              <option value="all">{tr("proxies.allProtocols")}</option>
              {ALL_PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </Select>
          </div>

          <div className="hidden md:flex items-center gap-1 shrink-0">
            <Select
              aria-label={tr("proxies.sortBy")}
              size="sm"
              className="w-28"
              value={sortField}
              onChange={(e) => handleSortFieldChange(e.target.value as NodeSortField)}
            >
              <option value="default">{tr("proxies.sortDefault")}</option>
              <option value="latency">{tr("proxies.sortLatency")}</option>
              <option value="ping">{tr("proxies.sortPing")}</option>
              <option value="down">{tr("proxies.sortDownSpeed")}</option>
              <option value="up">{tr("proxies.sortUpSpeed")}</option>
              <option value="name">{tr("proxies.sortName")}</option>
              <option value="protocol">{tr("proxies.sortProtocol")}</option>
            </Select>
            {sortField !== "default" ? (
              <button
                type="button"
                onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
                aria-label="Toggle sort order"
                className="inline-flex h-8 w-8 items-center justify-center rounded-[6px] border border-border bg-background text-muted-foreground hover:text-foreground"
              >
                {sortDir === "asc" ? <ArrowUp className="h-3.5 w-3.5" /> : <ArrowDown className="h-3.5 w-3.5" />}
              </button>
            ) : null}
          </div>

          <div className="hidden md:inline-flex shrink-0 rounded-[6px] border border-border bg-background p-0.5" role="group" aria-label={tr("settings.nodeViewMode")}>
            <button
              type="button"
              aria-pressed={nodeViewMode === "grid"}
              aria-label={tr("proxies.viewGrid")}
              title={tr("proxies.viewGrid")}
              onClick={() => setNodeViewMode("grid")}
              className={[
                "inline-flex h-7 w-7 items-center justify-center rounded-[4px] transition-colors",
                nodeViewMode === "grid" ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground",
              ].join(" ")}
            >
              <LayoutGrid className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
            <button
              type="button"
              aria-pressed={nodeViewMode === "list"}
              aria-label={tr("proxies.viewList")}
              title={tr("proxies.viewList")}
              onClick={() => setNodeViewMode("list")}
              className={[
                "inline-flex h-7 w-7 items-center justify-center rounded-[4px] transition-colors",
                nodeViewMode === "list" ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground",
              ].join(" ")}
            >
              <List className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={displayedNodes.length === 0}
            onClick={toggleSelectAllFiltered}
          >
            {allFilteredSelected ? (
              <CheckSquare className="mr-1.5 h-3.5 w-3.5 text-primary" aria-hidden="true" />
            ) : (
              <Square className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            )}
            {allFilteredSelected ? tr("proxies.clearSelection") : tr("proxies.selectAll")}
          </Button>
          {selectedValidIds.length > 0 && !allFilteredSelected ? (
            <Button type="button" variant="ghost" size="sm" onClick={() => setSelectedIds([])}>
              {tr("proxies.clearSelection")} ({selectedValidIds.length})
            </Button>
          ) : null}

          {selectedValidIds.length > 0 && allUserTags.length > 0 ? (
            <div className="w-28 shrink-0">
              <Select
                aria-label={tr("proxies.assignTab")}
                size="sm"
                value=""
                onChange={(e) => {
                  const v = e.target.value;
                  if (v) void handleBatchAssignTag(v);
                }}
              >
                <option value="">{tr("proxies.assignTab")}</option>
                {allUserTags.map((tag) => (
                  <option key={tag} value={tag}>
                    #{tag}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}

          <div className="hidden md:block w-28 shrink-0">
            <Select
              aria-label="Probe mode"
              size="sm"
              value={probeMode}
              onChange={(e) => setProbeMode(e.target.value as ProbeMode)}
            >
              <option value="urltest">{tr("proxies.probeModeUrl")}</option>
              <option value="ping">{tr("proxies.probeModePing")}</option>
              <option value="speed">{tr("proxies.probeModeSpeed")}</option>
              <option value="full">{tr("proxies.probeModeFull")}</option>
            </Select>
          </div>

          <Button
            type="button"
            size="sm"
            variant={selectedValidIds.length > 0 ? "default" : "outline"}
            disabled={
              probingBatch ||
              (selectedValidIds.length > 0 ? selectedValidIds.length === 0 : displayedNodes.length === 0)
            }
            onClick={() => void handleProbeBatch(primaryProbeTargets)}
          >
            <Gauge className={`mr-1.5 h-3.5 w-3.5 ${probingBatch ? "animate-spin" : ""}`} aria-hidden="true" />
            {primaryProbeLabel}
          </Button>
          {primaryProbeTargets && nodes.length > primaryProbeTargets.length ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={probingBatch}
              onClick={() => void handleProbeBatch()}
            >
              {tr("action.testAll")}
            </Button>
          ) : null}

          <Button type="button" size="sm" variant="outline" onClick={() => setQrImportOpen(true)}>
            <QrCode className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {tr("qr.scanBtn")}
          </Button>
          <Button type="button" size="sm" onClick={() => openNodeInspector(null)}>
            <Plus className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {tr("proxies.addNode")}
          </Button>
        </div>
      </div>

      {/* Node Cards Grid or Compact Sortable List */}
      {displayedNodes.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-xs text-muted-foreground">{tr("proxies.noNodes")}</CardContent>
        </Card>
      ) : nodeViewMode === "list" ? (
        <>
          {/* Mobile List with SwipeActionRow & >=48px targets */}
          <div className="space-y-2 md:hidden">
            {displayedNodes.map((n) => {
              const isActive = status?.running && status.active_node_id === n.id;
              const isInspected = inspectorMode === "node" && editingNode?.id === n.id;
              const displayName = n.user_alias || n.name;
              return (
                <SwipeActionRow
                  key={n.id}
                  className={`rounded-[10px] border bg-card ${
                    isInspected ? "border-primary bg-accent/30" : isActive ? "border-primary/60" : "border-border"
                  }`}
                  actions={[
                    {
                      key: "connect",
                      label: tr("action.connect"),
                      icon: <Play className="h-4 w-4" />,
                      tone: "primary",
                      onClick: () => void toggleConnect({ nodeId: n.id }),
                    },
                    {
                      key: "probe",
                      label: tr("proxies.metricUrl"),
                      icon: <Gauge className="h-4 w-4" />,
                      onClick: () => void handleProbeSingle(n.id),
                    },
                    {
                      key: "edit",
                      label: tr("action.edit"),
                      icon: <Pencil className="h-4 w-4" />,
                      onClick: () => openNodeInspector(n),
                    },
                    {
                      key: "delete",
                      label: tr("action.delete"),
                      icon: <Trash2 className="h-4 w-4" />,
                      tone: "danger",
                      onClick: () => void handleDeleteNode(n.id),
                    },
                  ]}
                >
                  <div
                    role="button"
                    tabIndex={0}
                    aria-pressed={selectedSet.has(n.id)}
                    onClick={() => toggleSelectNode(n.id)}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setContextMenu({ x: e.clientX, y: e.clientY, node: n });
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggleSelectNode(n.id);
                      }
                    }}
                    className={`p-3 space-y-1 text-left ${selectedSet.has(n.id) ? "bg-accent/35" : ""}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-1.5">
                        <span className="truncate text-[14px] font-semibold text-foreground">{displayName}</span>
                        {n.detour_id ? (
                          <span className="shrink-0 whitespace-nowrap badge-radius border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                            {tr("node.detourVia", { name: getDetourLabel(n.detour_id) })}
                          </span>
                        ) : null}
                      </div>
                      <span
                        className={`badge-radius border px-1.5 py-0.5 mono-num text-[11px] shrink-0 ${
                          n.latency && n.latency > 0
                            ? "border-primary/40 text-primary"
                            : n.latency === -1
                              ? "border-destructive/40 text-destructive"
                              : "border-border text-muted-foreground"
                        }`}
                      >
                        {formatLatency(n.latency)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 mono-num text-xs text-muted-foreground">
                      <span className="truncate">
                        {n.protocol.toUpperCase()} · {n.address}:{n.port}
                      </span>
                      <span className="shrink-0">{formatSpeedMbps(n.down_speed_mbps)}</span>
                    </div>
                  </div>
                </SwipeActionRow>
              );
            })}
          </div>

          {/* Desktop Adaptive List: wide 9-col resizable table vs ultra-compact 2-row narrow list */}
          <div className="hidden md:block proxies-list-stage">
            <div className="proxies-list-wide table-wrapper">
              <table className="responsive-table table-resizable [&_th]:py-1.5 [&_th]:px-2 [&_td]:py-1.5 [&_td]:px-2">
                <colgroup>
                  <col style={{ width: `${nodeColWidths.select}px` }} />
                  <col style={{ width: `${nodeColWidths.name}px` }} />
                  <col style={{ width: `${nodeColWidths.protocol}px` }} />
                  <col style={{ width: `${nodeColWidths.endpoint}px` }} />
                  <col style={{ width: `${nodeColWidths.ping}px` }} />
                  <col style={{ width: `${nodeColWidths.latency}px` }} />
                  <col style={{ width: `${nodeColWidths.down}px` }} />
                  <col style={{ width: `${nodeColWidths.up}px` }} />
                  <col style={{ width: `${nodeColWidths.action}px` }} />
                </colgroup>
                <thead>
                  <tr>
                    <th scope="col" className="w-9">
                      <input
                        type="checkbox"
                        aria-label={allFilteredSelected ? tr("proxies.clearSelection") : tr("proxies.selectAll")}
                        checked={allFilteredSelected}
                        onChange={toggleSelectAllFiltered}
                      />
                    </th>
                    {renderSortableColHeader("name", locale === "zh-CN" ? "节点名称 / 来源" : "Node / Source", "name")}
                    {renderSortableColHeader("protocol", locale === "zh-CN" ? "协议" : "Protocol", "protocol")}
                    <th scope="col" className="whitespace-nowrap">
                      <span className="block truncate">{tr("proxies.colEndpoint")}</span>
                      <ColumnResizeHandle
                        active={resizingNodeCol === "endpoint"}
                        title={tr("table.resizeHint")}
                        onPointerDown={(e) => startNodeColResize("endpoint", e)}
                        onDoubleClick={() => resetNodeColWidth("endpoint")}
                      />
                    </th>
                    {renderSortableColHeader("ping", tr("proxies.metricPing"), "ping")}
                    {renderSortableColHeader("latency", tr("proxies.metricUrl"), "latency")}
                    {renderSortableColHeader("down", tr("proxies.metricDown"), "down")}
                    {renderSortableColHeader("up", tr("proxies.metricUp"), "up")}
                    <th scope="col" className="whitespace-nowrap">
                      <span className="block truncate">{tr("connections.colAction")}</span>
                      <ColumnResizeHandle
                        active={resizingNodeCol === "action"}
                        title={tr("table.resizeHint")}
                        onPointerDown={(e) => startNodeColResize("action", e)}
                        onDoubleClick={() => resetNodeColWidth("action")}
                      />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {displayedNodes.map((n) => {
                    const isActive = status?.running && status.active_node_id === n.id;
                    const isSelected = selectedSet.has(n.id);
                    const isInspected = inspectorMode === "node" && editingNode?.id === n.id;
                    const insecure = nodeHasInsecureTLS(n);
                    const displayName = n.user_alias || n.name;
                    return (
                      <tr
                        key={n.id}
                        onClick={(e) => {
                          if (!(e.target as HTMLElement).closest("button, input, select, a, label")) {
                            toggleSelectNode(n.id);
                          }
                        }}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setContextMenu({ x: e.clientX, y: e.clientY, node: n });
                        }}
                        className={[
                          "cursor-pointer dense-row transition-colors duration-100 select-none",
                          isInspected
                            ? "bg-accent/70"
                            : isSelected
                              ? "bg-accent/45"
                              : isActive
                                ? "bg-primary/10"
                                : "hover:bg-muted/40",
                        ].join(" ")}
                      >
                        <td data-label={tr("proxies.colSelect")}>
                          <input
                            type="checkbox"
                            aria-label={`${tr("proxies.colSelect")} ${displayName}`}
                            checked={isSelected}
                            onChange={() => toggleSelectNode(n.id)}
                          />
                        </td>
                        <th scope="row" className="min-w-0">
                          <div className="flex min-w-0 items-center gap-1.5">
                            <TruncateTip text={displayName} className="font-semibold text-foreground" />
                            <span className="shrink-0 whitespace-nowrap badge-radius bg-muted px-1.5 py-0.5 text-[10px] font-normal text-muted-foreground">
                              {getNodeSourceLabel(n)}
                            </span>
                            {n.detour_id ? (
                              <span
                                className="shrink-0 whitespace-nowrap badge-radius border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary"
                                title={tr("node.detourVia", { name: getDetourLabel(n.detour_id) })}
                              >
                                {tr("node.detourVia", { name: getDetourLabel(n.detour_id) })}
                              </span>
                            ) : null}
                          </div>
                        </th>
                        <td data-label={locale === "zh-CN" ? "协议" : "Protocol"}>
                          <div className="flex flex-wrap items-center gap-1">
                            <span className="badge-radius border border-border bg-muted px-1.5 py-0.5 text-[11px] uppercase tabular-nums text-muted-foreground">
                              {n.protocol}
                            </span>
                            {insecure ? (
                              <span className="badge-radius bg-destructive/15 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
                                {tr("proxies.insecureBadge")}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td data-label={tr("proxies.colEndpoint")} className="mono-num text-xs text-muted-foreground">
                          <TruncateTip text={`${n.address}:${n.port}`} />
                        </td>
                        <td data-label={tr("proxies.metricPing")} className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
                          {formatLatency(n.ping_ms)}
                        </td>
                        <td data-label={tr("proxies.metricUrl")} className="whitespace-nowrap text-xs">
                          {renderNodeTelemetryBadge(n, false)}
                        </td>
                        <td data-label={tr("proxies.metricDown")} className="whitespace-nowrap text-xs tabular-nums text-emerald-500">
                          {formatSpeedMbps(n.down_speed_mbps)}
                        </td>
                        <td data-label={tr("proxies.metricUp")} className="whitespace-nowrap text-xs tabular-nums text-sky-400">
                          {formatSpeedMbps(n.up_speed_mbps)}
                        </td>
                        <td data-label={tr("connections.colAction")}>{renderNodeActionButtons(n, true)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Ultra-compact 2-row narrow list (<640px container width): replaces tall 9-row stacked cards */}
            <div className="proxies-list-narrow">
              {displayedNodes.map((n) => {
                const isActive = status?.running && status.active_node_id === n.id;
                const isSelected = selectedSet.has(n.id);
                const isInspected = inspectorMode === "node" && editingNode?.id === n.id;
                const insecure = nodeHasInsecureTLS(n);
                const displayName = n.user_alias || n.name;
                return (
                  <div
                    key={n.id}
                    data-narrow-node-row={n.id}
                    onClick={(e) => {
                      if (!(e.target as HTMLElement).closest("button, input, select, a, label")) {
                        toggleSelectNode(n.id);
                      }
                    }}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setContextMenu({ x: e.clientX, y: e.clientY, node: n });
                    }}
                    className={[
                      "prism-card prism-card-interactive cursor-pointer select-none rounded-[10px] border px-3 py-2 space-y-1.5",
                      isInspected
                        ? "border-primary bg-accent/55"
                        : isSelected
                          ? "border-primary/70 bg-accent/35"
                          : isActive
                            ? "border-primary/60 bg-primary/10"
                            : "border-border bg-card hover:border-primary/40",
                    ].join(" ")}
                  >
                    {/* Line 1: Checkbox + Truncated Name + Protocol + Hoverable 真连接 Telemetry Pill */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 flex-1 items-center gap-2">
                        <input
                          type="checkbox"
                          aria-label={`${tr("proxies.colSelect")} ${displayName}`}
                          checked={isSelected}
                          onChange={() => toggleSelectNode(n.id)}
                          className="shrink-0"
                        />
                        <TruncateTip text={displayName} className="text-[13px] font-semibold text-foreground" />
                        <span className="shrink-0 whitespace-nowrap badge-radius border border-border bg-muted px-1.5 py-0.5 text-[10px] uppercase leading-none text-muted-foreground">
                          {n.protocol}
                        </span>
                      </div>
                      {renderNodeTelemetryBadge(n, false)}
                    </div>

                    {/* Line 2: Compact Source/Detour on left + Single-Row Icon Actions on right */}
                    <div className="flex items-center justify-between gap-2 pl-5">
                      <div className="flex min-w-0 flex-1 items-center gap-1.5 overflow-hidden text-[11px]">
                        <span className="shrink-0 badge-radius bg-muted px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
                          {getNodeSourceLabel(n)}
                        </span>
                        {n.detour_id ? (
                          <TruncateTip
                            text={tr("node.detourVia", { name: getDetourLabel(n.detour_id) })}
                            className="badge-radius border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium leading-none text-primary"
                          />
                        ) : null}
                        {insecure ? (
                          <span className="shrink-0 badge-radius bg-destructive/15 px-1.5 py-0.5 text-[10px] font-medium leading-none text-destructive">
                            {tr("proxies.insecureBadge")}
                          </span>
                        ) : null}
                      </div>
                      <div className="shrink-0">{renderNodeActionButtons(n, true)}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,17rem),1fr))] gap-2.5">
          {displayedNodes.map((n) => {
            const isActive = status?.running && status.active_node_id === n.id;
            const isSelected = selectedSet.has(n.id);
            const isInspected = inspectorMode === "node" && editingNode?.id === n.id;
            const insecure = nodeHasInsecureTLS(n);
            const displayName = n.user_alias || n.name;
            return (
              <SwipeActionRow
                key={n.id}
                className="rounded-[10px]"
                actions={[
                  {
                    key: "connect",
                    label: tr("action.connect"),
                    icon: <Play className="h-4 w-4" />,
                    tone: "primary",
                    onClick: () => void toggleConnect({ nodeId: n.id }),
                  },
                  {
                    key: "probe",
                    label: tr("proxies.metricUrl"),
                    icon: <Gauge className="h-4 w-4" />,
                    onClick: () => void handleProbeSingle(n.id),
                  },
                  {
                    key: "edit",
                    label: tr("action.edit"),
                    icon: <Pencil className="h-4 w-4" />,
                    onClick: () => openNodeInspector(n),
                  },
                  {
                    key: "delete",
                    label: tr("action.delete"),
                    icon: <Trash2 className="h-4 w-4" />,
                    tone: "danger",
                    onClick: () => void handleDeleteNode(n.id),
                  },
                ]}
              >
                <Card
                  data-node-card={n.id}
                  onClick={(e) => {
                    if (!(e.target as HTMLElement).closest("button, input, select, a, label")) {
                      toggleSelectNode(n.id);
                    }
                  }}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setContextMenu({ x: e.clientX, y: e.clientY, node: n });
                  }}
                  className={[
                    "node-card-container prism-card-interactive cursor-pointer select-none",
                    isInspected
                      ? "border-primary bg-accent/45"
                      : isSelected
                        ? "border-primary/70 bg-accent/35"
                        : isActive
                          ? "border-primary/60 bg-primary/10"
                          : "hover:border-primary/40",
                  ].join(" ")}
                >
                  <CardContent className="space-y-2 p-3">
                    {/* Upper Tier: Checkbox + Name + Protocol + Favorite & Single-line Address */}
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex min-w-0 flex-1 items-start gap-2">
                        <input
                          type="checkbox"
                          aria-label={`${tr("proxies.colSelect")} ${displayName}`}
                          checked={isSelected}
                          onChange={() => toggleSelectNode(n.id)}
                          className="mt-1 shrink-0"
                        />
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <div className="flex min-w-0 items-center gap-1.5">
                            <TruncateTip
                              text={displayName}
                              className="text-[13px] max-md:text-[15px] font-semibold text-foreground"
                            />
                            <span className="shrink-0 whitespace-nowrap badge-radius border border-border bg-muted px-1.5 py-0.5 text-[10px] uppercase leading-none text-muted-foreground">
                              {n.protocol}
                            </span>
                            {insecure ? (
                              <span
                                className="inline-flex shrink-0 items-center badge-radius bg-destructive/15 px-1 py-0.5 text-[10px] font-medium leading-none text-destructive"
                                title={tr("proxies.insecureBadge")}
                              >
                                <AlertTriangle className="h-3 w-3" aria-hidden="true" />
                              </span>
                            ) : null}
                          </div>
                          <div className="flex min-w-0 items-center gap-1.5">
                            <TruncateTip
                              text={`${n.address}:${n.port}`}
                              className="font-mono text-[11px] text-muted-foreground"
                            />
                            {n.detour_id ? (
                              <TruncateTip
                                text={tr("node.detourVia", { name: getDetourLabel(n.detour_id) })}
                                className="shrink-0 max-w-[7.5rem] badge-radius border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium leading-none text-primary"
                              />
                            ) : null}
                          </div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => void handleToggleFavorite(n)}
                        aria-label={tr("proxies.tabFavorites")}
                        className={[
                          "inline-flex h-7 w-7 max-md:h-[var(--m-btn-icon)] max-md:w-[var(--m-btn-icon)] shrink-0 items-center justify-center rounded-[6px] transition-colors hover:bg-muted",
                          n.favorite ? "text-amber-500" : "text-muted-foreground",
                        ].join(" ")}
                      >
                        <Star className="h-3.5 w-3.5" fill={n.favorite ? "currentColor" : "none"} aria-hidden="true" />
                      </button>
                    </div>

                    {/* Lower Tier (Unified single line): Hover/Press-Hold 真连接 Telemetry + Source | Icon Actions */}
                    <div className="flex items-center justify-between gap-2 border-t border-border/80 pt-2">
                      <div className="flex min-w-0 flex-1 items-center gap-1.5 overflow-hidden">
                        {renderNodeTelemetryBadge(n, true)}
                        <span className="truncate badge-radius bg-muted px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">
                          {getNodeSourceLabel(n)}
                        </span>
                      </div>
                      <div className="hidden md:block shrink-0">{renderNodeActionButtons(n, false)}</div>
                    </div>
                  </CardContent>
                </Card>
              </SwipeActionRow>
            );
          })}
        </div>
      )}
      </div>

      {/* Node Right-Click Context Menu */}
      <NodeContextMenu
        state={contextMenu}
        isActive={Boolean(contextMenu && status?.running && status.active_node_id === contextMenu.node.id)}
        isSelected={Boolean(contextMenu && selectedSet.has(contextMenu.node.id))}
        selectedCount={selectedValidIds.length}
        probing={Boolean(contextMenu && probingId === contextMenu.node.id)}
        onClose={() => setContextMenu(null)}
        onToggleConnect={(id) => void toggleConnect({ nodeId: id })}
        onProbeSingle={(id) => void handleProbeSingle(id)}
        onProbeSelected={() => void handleProbeBatch(selectedValidIds)}
        onToggleSelect={toggleSelectNode}
        onToggleFavorite={(node) => void handleToggleFavorite(node)}
        onEditNode={openNodeInspector}
        onShareQr={(node) => void handleOpenQR(node)}
        onDeleteNode={(id) => void handleDeleteNode(id)}
      />

      {/* Right Context Inspector for Node Details / Editor / Group Editor / QR Share */}
      <ContextInspector
        open={inspectorMode !== null}
        title={
          inspectorMode === "qr"
            ? `${tr("proxies.qrTitle")} — ${qrState.name}`
            : inspectorMode === "group"
              ? editingGroupId
                ? `${tr("proxies.editGroup")} — ${groupName}`
                : tr("proxies.addGroup")
              : inspectedNode
                ? `${tr("action.edit")} — ${inspectedNode.user_alias || inspectedNode.name}`
                : tr("proxies.addNode")
        }
        subtitle={
          inspectorMode === "node"
            ? tr("inspector.nodeTitle")
            : inspectorMode === "group"
              ? tr("group.inspectorSubtitle")
              : undefined
        }
        onClose={() => {
          if (inspectorMode === "group") closeGroupForm();
          else setInspectorMode(null);
        }}
      >
        {inspectorMode === "qr" ? (
          <QRSharePanel nodeName={qrState.name} uri={qrState.uri} onClose={() => setInspectorMode(null)} />
        ) : inspectorMode === "group" ? (
          <form onSubmit={(e) => void handleSubmitGroup(e)} className="space-y-4 text-xs">
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "分组名称" : "Group Name"}
                </label>
                <Input
                  placeholder={locale === "zh-CN" ? "分组名称 (例如 Auto / HK / LB)" : "Group name"}
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-1">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs font-medium text-muted-foreground">{tr("proxies.groupStrategy")}</label>
                  <HelpTip
                    ariaLabel={tr("proxies.groupStrategy")}
                    text={
                      <div className="space-y-1">
                        <div className="font-medium text-foreground">{tr(strategyDescKey)}</div>
                        <div className="text-muted-foreground">{tr("proxies.noLoadBalanceHint")}</div>
                      </div>
                    }
                  />
                </div>
                <Select
                  aria-label={tr("proxies.groupStrategy")}
                  value={groupStrategy}
                  onChange={(e) => {
                    const next = e.target.value as GroupStrategy;
                    setGroupStrategy(next);
                    if (next === "failover") {
                      setGroupIntervalVal(1);
                      setGroupIntervalUnit("m");
                      setGroupToleranceVal(1);
                      setGroupToleranceUnit("s");
                    } else if (next === "loadbalance") {
                      setGroupIntervalVal(3);
                      setGroupIntervalUnit("m");
                      setGroupToleranceVal(50);
                      setGroupToleranceUnit("ms");
                    } else if (next === "urltest") {
                      setGroupIntervalVal(5);
                      setGroupIntervalUnit("m");
                      setGroupToleranceVal(50);
                      setGroupToleranceUnit("ms");
                    }
                  }}
                >
                  <option value="selector">selector ({locale === "zh-CN" ? "手动选择" : "Manual"})</option>
                  <option value="urltest">urltest ({locale === "zh-CN" ? "自动优选低延迟" : "Auto Fastest"})</option>
                  <option value="failover">failover ({locale === "zh-CN" ? "主备故障转移" : "Failover"})</option>
                  <option value="loadbalance">loadbalance ({locale === "zh-CN" ? "主域名哈希负载均衡" : "Domain Hash LB"})</option>
                </Select>
              </div>

              <div className="space-y-1">
                <div className="flex items-center gap-1.5">
                  <label className="text-xs font-medium text-muted-foreground" htmlFor="group-detour-select">
                    {tr("group.detourLabel")}
                  </label>
                  <HelpTip ariaLabel={tr("group.detourLabel")} text={tr("group.detourHint")} />
                </div>
                <Select
                  id="group-detour-select"
                  value={groupDetourId}
                  onChange={(e) => setGroupDetourId(e.target.value)}
                >
                  <option value="">{tr("node.detourNone")}</option>
                  {groups.filter((g) => {
                    const st = canonicalStrategy(g.strategy);
                    return g.id !== editingGroupId && st !== "loadbalance" && (g.node_ids || []).length > 0;
                  }).length > 0 ? (
                    <optgroup label={tr("node.detourGroups")}>
                      {groups
                        .filter((g) => {
                          const st = canonicalStrategy(g.strategy);
                          return g.id !== editingGroupId && st !== "loadbalance" && (g.node_ids || []).length > 0;
                        })
                        .map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name} ({canonicalStrategy(g.strategy)})
                          </option>
                        ))}
                    </optgroup>
                  ) : null}
                  {nodes.filter((n) => !groupNodeIds.includes(n.id)).length > 0 ? (
                    <optgroup label={tr("node.detourNodes")}>
                      {nodes
                        .filter((n) => !groupNodeIds.includes(n.id))
                        .map((n) => (
                          <option key={n.id} value={n.id}>
                            {n.user_alias || n.name} ({n.protocol.toUpperCase()})
                          </option>
                        ))}
                    </optgroup>
                  ) : null}
                </Select>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <div className="flex h-5 items-center gap-1.5">
                    <label className="truncate text-xs font-medium text-muted-foreground">{tr("settings.priorityRule")}</label>
                  </div>
                  <Select
                    aria-label={tr("settings.priorityRule")}
                    value={groupPriorityRule}
                    onChange={(e) => setGroupPriorityRule(e.target.value)}
                  >
                    <option value="">
                      {tr("proxies.groupRuleInherit", { rule: globalRuleLabel(healthSettings?.priority_rule) })}
                    </option>
                    <option value="latency_first">{tr("settings.ruleLatencyFirst")}</option>
                    <option value="speed_first">{tr("settings.ruleSpeedFirst")}</option>
                    <option value="hybrid_score">{tr("settings.ruleHybridScore")}</option>
                  </Select>
                </div>
                <div className="space-y-1">
                  <div className="flex h-5 items-center gap-1.5">
                    <label className="truncate text-xs font-medium text-muted-foreground">{tr("proxies.failoverShort")}</label>
                    <HelpTip ariaLabel={tr("proxies.failoverShort")} text={tr("settings.autoFailover")} />
                  </div>
                  <Select
                    aria-label={tr("settings.autoFailover")}
                    value={groupAutoFailover}
                    onChange={(e) => setGroupAutoFailover(e.target.value as "inherit" | "on" | "off")}
                  >
                    <option value="inherit">
                      {tr("proxies.groupFailoverInherit", { state: globalFailoverStateLabel })}
                    </option>
                    <option value="on">{tr("proxies.groupFailoverOn")}</option>
                    <option value="off">{tr("proxies.groupFailoverOff")}</option>
                  </Select>
                </div>
              </div>

              {groupStrategy !== "selector" || groupAutoFailover === "on" ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <label className="block text-xs font-medium text-muted-foreground">{tr("proxies.groupIntervalClean")}</label>
                    <DurationInput
                      locale={locale}
                      value={groupIntervalVal}
                      unit={groupIntervalUnit}
                      units={["ms", "s", "m", "h", "d"]}
                      min={1}
                      ariaLabel={tr("proxies.groupIntervalClean")}
                      onChange={(v, u) => {
                        setGroupIntervalVal(v);
                        setGroupIntervalUnit(u);
                      }}
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-xs font-medium text-muted-foreground">{tr("proxies.groupToleranceClean")}</label>
                    <DurationInput
                      locale={locale}
                      value={groupToleranceVal}
                      unit={groupToleranceUnit}
                      units={["ms", "s", "m"]}
                      min={0}
                      ariaLabel={tr("proxies.groupToleranceClean")}
                      onChange={(v, u) => {
                        setGroupToleranceVal(v);
                        setGroupToleranceUnit(u);
                      }}
                    />
                  </div>
                </div>
              ) : null}

              <NodeMultiSelectDropdown
                mode="nodes"
                nodes={nodes}
                subscriptions={subscriptions}
                customNodeTabs={customNodeTabs}
                selectedNodeIds={groupNodeIds}
                onChangeNodeIds={setGroupNodeIds}
                label={locale === "zh-CN" ? "组内节点（支持搜索与按标签页筛选）" : "Group Member Nodes (Search & Tab Filter)"}
              />
            </div>

            <div className="flex justify-end gap-2 border-t border-border pt-3">
              <Button type="button" variant="ghost" size="sm" onClick={closeGroupForm}>
                {tr("action.cancel")}
              </Button>
              <Button type="submit" size="sm" disabled={savingGroup}>
                {tr("action.save")}
              </Button>
            </div>
          </form>
        ) : inspectorMode === "node" ? (
          <div className="space-y-3">
            {inspectedNode ? (
              <div className="flex flex-wrap items-center gap-1.5 rounded-[10px] border border-border bg-muted/40 p-2">
                <Button
                  type="button"
                  size="sm"
                  variant={status?.running && status.active_node_id === inspectedNode.id ? "default" : "outline"}
                  onClick={() => void toggleConnect({ nodeId: inspectedNode.id })}
                >
                  <Play className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                  {tr("action.connect")}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={probingId === inspectedNode.id}
                  onClick={() => void handleProbeSingle(inspectedNode.id)}
                >
                  <Gauge className={`mr-1 h-3.5 w-3.5 ${probingId === inspectedNode.id ? "animate-spin text-primary" : ""}`} aria-hidden="true" />
                  {probeModeLabel(probeMode)}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => void handleOpenQR(inspectedNode)}
                >
                  <QrCode className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                  QR
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  onClick={() => void handleToggleFavorite(inspectedNode)}
                  aria-label={tr("proxies.tabFavorites")}
                >
                  <Star
                    className={`h-3.5 w-3.5 ${inspectedNode.favorite ? "text-amber-500" : ""}`}
                    fill={inspectedNode.favorite ? "currentColor" : "none"}
                    aria-hidden="true"
                  />
                </Button>
              </div>
            ) : null}

            <NodeEditorForm
              key={inspectedNode?.id || "new-node"}
              embedded
              initialNode={inspectedNode}
              onClose={() => setInspectorMode(null)}
              onSaved={refreshAll}
            />
          </div>
        ) : null}
      </ContextInspector>

      {/* Mobile Bottom Sheet for Protocol Filter, Sort Order, View Mode & Probe Type */}
      {isMobile ? (
        <BottomSheetDialog open={filterSheetOpen} title={tr("mobile.filterSheet")} onClose={() => setFilterSheetOpen(false)}>
          <div className="space-y-3 text-xs">
            <div className="space-y-1">
              <label className="font-medium text-muted-foreground">{tr("proxies.allProtocols")}</label>
              <Select value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)}>
                <option value="all">{tr("proxies.allProtocols")}</option>
                {ALL_PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </Select>
            </div>
            <div className="space-y-1">
              <label className="font-medium text-muted-foreground">{tr("proxies.sortBy")}</label>
              <div className="flex gap-2">
                <Select
                  className="flex-1"
                  value={sortField}
                  onChange={(e) => handleSortFieldChange(e.target.value as NodeSortField)}
                >
                  <option value="default">{tr("proxies.sortDefault")}</option>
                  <option value="latency">{tr("proxies.sortLatency")}</option>
                  <option value="ping">{tr("proxies.sortPing")}</option>
                  <option value="down">{tr("proxies.sortDownSpeed")}</option>
                  <option value="up">{tr("proxies.sortUpSpeed")}</option>
                  <option value="name">{tr("proxies.sortName")}</option>
                  <option value="protocol">{tr("proxies.sortProtocol")}</option>
                </Select>
                {sortField !== "default" ? (
                  <Button type="button" variant="outline" onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}>
                    {sortDir === "asc" ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />}
                  </Button>
                ) : null}
              </div>
            </div>
            <div className="space-y-1">
              <label className="font-medium text-muted-foreground">Probe Mode</label>
              <Select value={probeMode} onChange={(e) => setProbeMode(e.target.value as ProbeMode)}>
                <option value="urltest">{tr("proxies.probeModeUrl")}</option>
                <option value="ping">{tr("proxies.probeModePing")}</option>
                <option value="speed">{tr("proxies.probeModeSpeed")}</option>
                <option value="full">{tr("proxies.probeModeFull")}</option>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="font-medium text-muted-foreground">{tr("settings.nodeViewMode")}</label>
              <div className="grid grid-cols-2 gap-2">
                <Button
                  type="button"
                  variant={nodeViewMode === "grid" ? "default" : "outline"}
                  onClick={() => setNodeViewMode("grid")}
                >
                  <LayoutGrid className="mr-1.5 h-4 w-4" />
                  {tr("proxies.viewGrid")}
                </Button>
                <Button
                  type="button"
                  variant={nodeViewMode === "list" ? "default" : "outline"}
                  onClick={() => setNodeViewMode("list")}
                >
                  <List className="mr-1.5 h-4 w-4" />
                  {tr("proxies.viewList")}
                </Button>
              </div>
            </div>
          </div>
        </BottomSheetDialog>
      ) : null}

      <QrLinkImportModal open={qrImportOpen} defaultMode="nodes" onClose={() => setQrImportOpen(false)} />
    </div>
  );
}
