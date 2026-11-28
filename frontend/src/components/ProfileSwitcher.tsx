// SPDX-License-Identifier: MPL-2.0

import React, { useState } from "react";
import { Check, Layers, Plus, Trash2 } from "lucide-react";
import { androidBridge, api, formatApiError } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { ContextInspector } from "./ContextInspector.tsx";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";
import { Select } from "./ui/select.tsx";

export interface ProfileSwitcherProps {
  compact?: boolean;
}

export function ProfileSwitcher({ compact = false }: ProfileSwitcherProps) {
  const { tr, nodes, groups, routing, profiles, activeProfileId, tailscaleEnabled, refreshAll, notify } = useAppStore();
  const [switching, setSwitching] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);

  const [newName, setNewName] = useState("");
  const [newTemplate, setNewTemplate] = useState("clone");
  const [newTarget, setNewTarget] = useState("");
  const [newTailscale, setNewTailscale] = useState<"" | "enable" | "disable">("");
  const [creating, setCreating] = useState(false);

  const activeId = activeProfileId || "default";

  const handleSwitch = async (nextId: string) => {
    if (!nextId || nextId === activeId) return;
    setSwitching(true);
    try {
      const prevRouting = routing;
      const prevTs = tailscaleEnabled;
      const res = await api.activateProfile(nextId);
      await refreshAll();
      if (androidBridge.available() && androidBridge.getVpnStatus()?.active) {
        const [nextRouting, nextTs] = await Promise.all([
          api.getRouting().catch(() => null),
          api.getTailscale().catch(() => null),
        ]);
        const vpnFieldsChanged =
          Boolean(nextRouting) &&
          (nextRouting?.per_app_mode !== prevRouting?.per_app_mode ||
            JSON.stringify(nextRouting?.per_app_packages || []) !== JSON.stringify(prevRouting?.per_app_packages || []) ||
            Boolean(nextRouting?.bypass_lan) !== Boolean(prevRouting?.bypass_lan) ||
            Boolean(nextRouting?.allow_lan_broadcast) !== Boolean(prevRouting?.allow_lan_broadcast));
        const tsChanged = nextTs ? Boolean(nextTs.config?.enabled) !== prevTs : false;
        if (nextRouting && (vpnFieldsChanged || tsChanged)) {
          androidBridge.prepareAndStartVpn({
            per_app_mode: nextRouting.per_app_mode || "all",
            per_app_packages: nextRouting.per_app_packages || [],
            bypass_lan: nextRouting.bypass_lan,
            allow_lan_broadcast: Boolean(nextRouting.bypass_lan && nextRouting.allow_lan_broadcast),
          });
        }
        if (tsChanged) {
          androidBridge.refreshQuickTiles();
        }
      }
      const chosen = (res.profiles || []).find((p) => p.id === nextId);
      notify(tr("profiles.switched", { name: chosen?.name || nextId }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setSwitching(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newName.trim();
    if (!trimmed) return;
    setCreating(true);
    try {
      let preferred_node_id = "";
      let preferred_group_id = "";
      if (newTarget.startsWith("group:")) {
        preferred_group_id = newTarget.slice("group:".length);
      } else if (newTarget.startsWith("node:")) {
        preferred_node_id = newTarget.slice("node:".length);
      }
      const tailscale_enabled =
        newTailscale === "enable" ? true : newTailscale === "disable" ? false : null;

      await api.createProfile({
        name: trimmed,
        template: newTemplate === "clone" ? "" : newTemplate,
        clone_from_id: activeId,
        preferred_node_id: preferred_node_id || undefined,
        preferred_group_id: preferred_group_id || undefined,
        tailscale_enabled,
      });
      await refreshAll();
      setNewName("");
      setNewTarget("");
      setNewTailscale("");
      notify(tr("profiles.created", { name: trimmed }));
    } catch (err) {
      notify(formatApiError(err), "error");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteProfile(id);
      await refreshAll();
      notify(tr("profiles.deleted"));
    } catch (err) {
      notify(formatApiError(err), "error");
    }
  };

  if (profiles.length === 0) return null;

  return (
    <>
      <div className="inline-flex min-w-0 items-center gap-1.5">
        <Layers className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
        <Select
          size="sm"
          aria-label={tr("profiles.title")}
          disabled={switching}
          value={activeId}
          onChange={(e) => void handleSwitch(e.target.value)}
          className={compact ? "h-8 min-w-[7.5rem] max-w-[11rem] text-xs" : "h-8 min-w-[8.5rem] max-w-[13rem] text-xs"}
        >
          {profiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.mode})
            </option>
          ))}
        </Select>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-8 px-2 text-xs"
          onClick={() => {
            void refreshAll();
            setManageOpen(true);
          }}
        >
          <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
          <span className={compact ? "hidden sm:inline" : ""}>{tr("profiles.manage")}</span>
        </Button>
      </div>

      <ContextInspector
        open={manageOpen}
        title={tr("profiles.title")}
        onClose={() => setManageOpen(false)}
      >
        <div className="space-y-4">
          <div className="space-y-2">
            {profiles.map((p) => (
              <div
                key={p.id}
                className={`flex items-center justify-between gap-2 rounded-[8px] border px-3 py-2 text-xs ${
                  p.id === activeId ? "border-primary/45 bg-primary/5" : "border-border bg-muted/20"
                }`}
              >
                <div className="min-w-0 flex-1 space-y-0.5">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-semibold text-foreground">{p.name}</span>
                    {p.id === activeId ? (
                      <span className="badge-radius border border-primary/40 bg-primary/15 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                        {tr("profiles.activeBadge")}
                      </span>
                    ) : null}
                  </div>
                  <div className="text-[11px] text-muted-foreground mono-num">
                    {p.mode} · {p.custom_rule_count} rules
                    {p.tailscale_enabled === true ? " · Tailscale ON" : p.tailscale_enabled === false ? " · Tailscale OFF" : ""}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  {p.id !== activeId ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      disabled={switching}
                      onClick={() => void handleSwitch(p.id)}
                      className="h-7 px-2 text-[11px]"
                    >
                      <Check className="mr-1 h-3 w-3" aria-hidden="true" />
                      {tr("action.apply")}
                    </Button>
                  ) : null}
                  {profiles.length > 1 ? (
                    <button
                      type="button"
                      onClick={() => void handleDelete(p.id)}
                      aria-label={`${tr("action.delete")} ${p.name}`}
                      className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-destructive/15 hover:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>

          <form onSubmit={(e) => void handleCreate(e)} className="space-y-3 border-t border-border pt-3 text-xs">
            <div className="font-semibold text-foreground">{tr("profiles.createTitle")}</div>
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div className="space-y-1">
                <label className="text-muted-foreground">{tr("profiles.name")}</label>
                <Input
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="Office / Home / Travel"
                  required
                />
              </div>
              <div className="space-y-1">
                <label className="text-muted-foreground">{tr("profiles.template")}</label>
                <Select value={newTemplate} onChange={(e) => setNewTemplate(e.target.value)}>
                  <option value="clone">{tr("profiles.tplClone")}</option>
                  <option value="office">{tr("profiles.tplOffice")}</option>
                  <option value="home">{tr("profiles.tplHome")}</option>
                  <option value="travel">{tr("profiles.tplTravel")}</option>
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-muted-foreground">{tr("profiles.preferredTarget")}</label>
                <Select value={newTarget} onChange={(e) => setNewTarget(e.target.value)}>
                  <option value="">{tr("profiles.keepCurrentTarget")}</option>
                  {groups.map((g) => (
                    <option key={g.id} value={`group:${g.id}`}>
                      [{tr("overview.exitTypeGroup")}] {g.name}
                    </option>
                  ))}
                  {nodes.map((n) => (
                    <option key={n.id} value={`node:${n.id}`}>
                      [{tr("overview.exitTypeNode")}] {n.user_alias || n.name}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="space-y-1">
                <label className="text-muted-foreground">{tr("profiles.tailscaleAction")}</label>
                <Select
                  value={newTailscale}
                  onChange={(e) => setNewTailscale(e.target.value as "" | "enable" | "disable")}
                >
                  <option value="">{tr("profiles.tailscaleKeep")}</option>
                  <option value="enable">{tr("profiles.tailscaleEnable")}</option>
                  <option value="disable">{tr("profiles.tailscaleDisable")}</option>
                </Select>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setManageOpen(false)}>
                {tr("action.close")}
              </Button>
              <Button type="submit" size="sm" disabled={creating || !newName.trim()}>
                <Plus className="mr-1 h-3.5 w-3.5" aria-hidden="true" />
                {tr("action.add")}
              </Button>
            </div>
          </form>
        </div>
      </ContextInspector>
    </>
  );
}
