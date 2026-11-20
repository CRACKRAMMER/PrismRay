// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import { type GroupConfig, type ListenConfig, type NodeConfig, type RoutingRule } from "../lib/api.ts";
import { useAppStore } from "../store/appStore.ts";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";
import { Select } from "./ui/select.tsx";
import { Switch } from "./ui/switch.tsx";

interface RuleEditorModalProps {
  open: boolean;
  initialRule: RoutingRule | null;
  isAndroid: boolean;
  nodes: NodeConfig[];
  groups: GroupConfig[];
  listeners: ListenConfig[];
  onClose: () => void;
  onSave: (rule: RoutingRule) => void;
}

function splitCSV(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function splitNums(text: string): number[] {
  return splitCSV(text)
    .map((v) => Number.parseInt(v, 10))
    .filter((n) => Number.isFinite(n) && n > 0 && n <= 65535);
}

const EMPTY_RULE: RoutingRule = {
  name: "",
  enabled: true,
  domains: [],
  domain_suffix: [],
  domain_keyword: [],
  domain_regex: [],
  ip_cidr: [],
  source_ip_cidr: [],
  ip_is_private: false,
  rule_set: [],
  network: [],
  port: [],
  port_range: [],
  source_port: [],
  process_name: [],
  process_path: [],
  package_name: [],
  protocol: [],
  inbound: [],
  invert: false,
  outbound: "proxy",
};

export interface RuleEditorFormProps {
  initialRule: RoutingRule | null;
  isAndroid: boolean;
  nodes: NodeConfig[];
  groups: GroupConfig[];
  listeners: ListenConfig[];
  onClose: () => void;
  onSave: (rule: RoutingRule) => void;
  embedded?: boolean;
}

export function RuleEditorForm({
  initialRule,
  isAndroid,
  nodes,
  groups,
  listeners,
  onClose,
  onSave,
  embedded = false,
}: RuleEditorFormProps) {
  const { tr, locale } = useAppStore();
  const idPrefix = useId();

  const [form, setForm] = useState<RoutingRule>(EMPTY_RULE);
  const [textFields, setTextFields] = useState<Record<string, string>>({});

  useEffect(() => {
    const base: RoutingRule = {
      ...EMPTY_RULE,
      ...initialRule,
      id: initialRule?.id || `rule-${Date.now()}`,
      enabled: initialRule ? initialRule.enabled : true,
      outbound: initialRule?.outbound || "proxy",
    };
    setForm(base);
    setTextFields({
      domains: (base.domains || []).join(", "),
      domain_suffix: (base.domain_suffix || []).join(", "),
      domain_keyword: (base.domain_keyword || []).join(", "),
      domain_regex: (base.domain_regex || []).join(", "),
      ip_cidr: (base.ip_cidr || []).join(", "),
      source_ip_cidr: (base.source_ip_cidr || []).join(", "),
      rule_set: (base.rule_set || []).join(", "),
      network: (base.network || []).join(", "),
      port: (base.port || []).join(", "),
      port_range: (base.port_range || []).join(", "),
      source_port: (base.source_port || []).join(", "),
      process_name: (base.process_name || []).join(", "),
      process_path: (base.process_path || []).join(", "),
      package_name: (base.package_name || []).join(", "),
      protocol: (base.protocol || []).join(", "),
      inbound: (base.inbound || []).join(", "),
    });
  }, [initialRule]);

  const setTxt = (key: string, val: string) => {
    setTextFields((prev) => ({ ...prev, [key]: val }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned: RoutingRule = {
      id: form.id || `rule-${Date.now()}`,
      name: (form.name || "").trim() || "Custom Rule",
      enabled: form.enabled,
      outbound: form.outbound || "proxy",
      invert: Boolean(form.invert),
      ip_is_private: Boolean(form.ip_is_private),
      domains: splitCSV(textFields.domains || ""),
      domain_suffix: splitCSV(textFields.domain_suffix || ""),
      domain_keyword: splitCSV(textFields.domain_keyword || ""),
      domain_regex: splitCSV(textFields.domain_regex || ""),
      ip_cidr: splitCSV(textFields.ip_cidr || ""),
      source_ip_cidr: splitCSV(textFields.source_ip_cidr || ""),
      rule_set: splitCSV(textFields.rule_set || ""),
      network: splitCSV(textFields.network || "").map((v) => v.toLowerCase()),
      port: splitNums(textFields.port || ""),
      port_range: splitCSV(textFields.port_range || ""),
      source_port: splitNums(textFields.source_port || ""),
      process_name: splitCSV(textFields.process_name || ""),
      process_path: splitCSV(textFields.process_path || ""),
      package_name: splitCSV(textFields.package_name || ""),
      protocol: splitCSV(textFields.protocol || "").map((v) => v.toLowerCase()),
      inbound: splitCSV(textFields.inbound || ""),
    };
    onSave(cleaned);
  };

  const isBuiltinOutbound =
    form.outbound === "proxy" || form.outbound === "direct" || form.outbound === "block";
  const hasMatchingTarget =
    isBuiltinOutbound ||
    groups.some((g) => g.id === form.outbound) ||
    nodes.some((n) => n.id === form.outbound);

  const inboundHintTags = listeners.map((l) => `in-${l.id}`).slice(0, 4).join(", ");
  const inputCls = "min-h-8 font-mono text-xs";

  return (
      <form onSubmit={handleSubmit} className="flex flex-1 flex-col overflow-hidden">
        <div className={embedded ? "space-y-4 text-xs" : "flex-1 space-y-5 overflow-y-auto px-5 py-4 text-xs"}>
          {/* Primary Identity & Action */}
          <div className={embedded ? "grid grid-cols-1 gap-3" : "grid grid-cols-1 gap-3 sm:grid-cols-2"}>
            <div className="space-y-1">
              <label htmlFor={`${idPrefix}-name`} className="block font-medium text-muted-foreground">
                {locale === "zh-CN" ? "规则名称" : "Rule Name"}
              </label>
              <Input
                id={`${idPrefix}-name`}
                value={form.name || ""}
                onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
                placeholder="e.g. AI Services / LAN Direct"
                required
              />
            </div>

            <div className="space-y-1">
              <label htmlFor={`${idPrefix}-outbound`} className="block font-medium text-muted-foreground">
                {locale === "zh-CN" ? "目标出站" : "Target Outbound"}
              </label>
              <Select
                id={`${idPrefix}-outbound`}
                value={form.outbound}
                onChange={(e) => setForm((p) => ({ ...p, outbound: e.target.value }))}
              >
                <option value="proxy">{tr("routing.outboundMainProxy")}</option>
                <option value="direct">{tr("routing.outboundDirect")}</option>
                <option value="block">{tr("routing.outboundBlock")}</option>
                {groups.length > 0 ? (
                  <optgroup label={tr("routing.outboundGroups")}>
                    {groups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name} ({g.id})
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {nodes.length > 0 ? (
                  <optgroup label={tr("routing.outboundNodes")}>
                    {nodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.user_alias || n.name}
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                {!hasMatchingTarget && form.outbound ? (
                  <option value={form.outbound}>{form.outbound}</option>
                ) : null}
              </Select>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border bg-muted/30 px-3.5 py-2.5">
            <div className="flex items-center gap-2.5">
              <Switch
                id={`${idPrefix}-enabled`}
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((p) => ({ ...p, enabled: checked }))}
              />
              <label htmlFor={`${idPrefix}-enabled`} className="font-medium text-foreground">
                {locale === "zh-CN" ? "启用此规则" : "Enable rule"}
              </label>
            </div>

            <label className="flex cursor-pointer items-center gap-2 font-medium text-foreground">
              <input
                type="checkbox"
                checked={Boolean(form.invert)}
                onChange={(e) => setForm((p) => ({ ...p, invert: e.target.checked }))}
              />
              <span>{tr("routing.invertMatch")}</span>
            </label>
          </div>

          {/* Domain Matching */}
          <fieldset className="space-y-3 rounded-xl border p-3.5">
            <legend className="px-1.5 text-xs font-semibold text-primary">{tr("routing.catDomain")}</legend>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "精准域名 (domains)" : "Exact Domains"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="accounts.google.com, dl.google.com"
                  value={textFields.domains || ""}
                  onChange={(e) => setTxt("domains", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "域名后缀 (domain_suffix)" : "Domain Suffix"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="openai.com, anthropic.com"
                  value={textFields.domain_suffix || ""}
                  onChange={(e) => setTxt("domain_suffix", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "域名关键词 (domain_keyword)" : "Domain Keyword"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="youtube, googlevideo"
                  value={textFields.domain_keyword || ""}
                  onChange={(e) => setTxt("domain_keyword", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.domainRegex")}</label>
                <Input
                  className={inputCls}
                  placeholder="^cdn[0-9]+\\.example\\.com$"
                  value={textFields.domain_regex || ""}
                  onChange={(e) => setTxt("domain_regex", e.target.value)}
                />
              </div>
            </div>
          </fieldset>

          {/* IP Matching */}
          <fieldset className="space-y-3 rounded-xl border p-3.5">
            <legend className="px-1.5 text-xs font-semibold text-primary">{tr("routing.catIP")}</legend>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "目标 IP CIDR (ip_cidr)" : "Dest IP CIDR"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="1.1.1.1/32, 35.212.0.0/16"
                  value={textFields.ip_cidr || ""}
                  onChange={(e) => setTxt("ip_cidr", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.sourceIpCidr")}</label>
                <Input
                  className={inputCls}
                  placeholder="192.168.1.0/24"
                  value={textFields.source_ip_cidr || ""}
                  onChange={(e) => setTxt("source_ip_cidr", e.target.value)}
                />
              </div>
            </div>
            <label className="flex cursor-pointer items-center gap-2 font-medium text-foreground">
              <input
                type="checkbox"
                checked={Boolean(form.ip_is_private)}
                onChange={(e) => setForm((p) => ({ ...p, ip_is_private: e.target.checked }))}
              />
              <span>{tr("routing.ipIsPrivate")}</span>
            </label>
          </fieldset>

          {/* Transport & Ports */}
          <fieldset className="space-y-3 rounded-xl border p-3.5">
            <legend className="px-1.5 text-xs font-semibold text-primary">{tr("routing.catTransport")}</legend>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.networkFilter")}</label>
                <Input
                  className={inputCls}
                  placeholder="tcp, udp"
                  value={textFields.network || ""}
                  onChange={(e) => setTxt("network", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "目标端口 (port)" : "Dest Ports"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="443, 8443"
                  value={textFields.port || ""}
                  onChange={(e) => setTxt("port", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.portRange")}</label>
                <Input
                  className={inputCls}
                  placeholder="1000:2000, 3478:3481"
                  value={textFields.port_range || ""}
                  onChange={(e) => setTxt("port_range", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.sourcePort")}</label>
                <Input
                  className={inputCls}
                  placeholder="50000"
                  value={textFields.source_port || ""}
                  onChange={(e) => setTxt("source_port", e.target.value)}
                />
              </div>
              <div className="space-y-1 sm:col-span-2">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "嗅探协议 (protocol)" : "Sniffed Protocol"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="tls, http, quic, bittorrent, stun"
                  value={textFields.protocol || ""}
                  onChange={(e) => setTxt("protocol", e.target.value)}
                />
              </div>
            </div>
          </fieldset>

          {/* Client, Process & Inbound */}
          <fieldset className="space-y-3 rounded-xl border p-3.5">
            <legend className="px-1.5 text-xs font-semibold text-primary">{tr("routing.catClient")}</legend>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "进程名 (process_name)" : "Process Name"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="curl, chrome, firefox"
                  value={textFields.process_name || ""}
                  onChange={(e) => setTxt("process_name", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.processPath")}</label>
                <Input
                  className={inputCls}
                  placeholder="/usr/bin/curl"
                  value={textFields.process_path || ""}
                  onChange={(e) => setTxt("process_path", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">{tr("routing.inboundFilter")}</label>
                <Input
                  className={inputCls}
                  placeholder={inboundHintTags || "mixed-in, tun-in"}
                  value={textFields.inbound || ""}
                  onChange={(e) => setTxt("inbound", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="block font-medium text-muted-foreground">
                  {locale === "zh-CN" ? "规则集标签 (rule_set)" : "Rule Set Tags"}
                </label>
                <Input
                  className={inputCls}
                  placeholder="geosite-cn, geoip-cn"
                  value={textFields.rule_set || ""}
                  onChange={(e) => setTxt("rule_set", e.target.value)}
                />
              </div>
              {isAndroid || (form.package_name?.length || 0) > 0 ? (
                <div className="space-y-1 sm:col-span-2">
                  <label className="block font-medium text-muted-foreground">
                    {locale === "zh-CN" ? "应用包名 (package_name)" : "Package Name"}
                  </label>
                  <Input
                    className={inputCls}
                    placeholder="com.android.vending"
                    value={textFields.package_name || ""}
                    onChange={(e) => setTxt("package_name", e.target.value)}
                  />
                </div>
              ) : null}
            </div>
          </fieldset>
        </div>

        <div className={embedded ? "flex justify-end gap-2 border-t border-border pt-3 mt-3" : "flex justify-end gap-2 border-t px-5 py-3"}>
          <Button type="button" variant="outline" onClick={onClose}>
            {embedded ? tr("action.close") : tr("action.cancel")}
          </Button>
          <Button type="submit">{tr("action.save")}</Button>
        </div>
      </form>
  );
}

export function RuleEditorModal({
  open,
  initialRule,
  isAndroid,
  nodes,
  groups,
  listeners,
  onClose,
  onSave,
}: RuleEditorModalProps) {
  const { tr } = useAppStore();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const pointerDownOutsideRef = useRef(false);

  useEffect(() => {
    const dlg = dialogRef.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.returnValue = "";
      dlg.close();
    }
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      {...({ closedby: "any" } as Record<string, string>)}
      className="m-auto flex max-h-[88dvh] w-[min(94vw,46rem)] flex-col overflow-hidden rounded-[12px] border border-border bg-popover p-0 text-popover-foreground"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClose={() => {
        if (dialogRef.current) dialogRef.current.returnValue = "";
        onClose();
      }}
      onPointerDown={(e) => {
        pointerDownOutsideRef.current = e.target === dialogRef.current;
      }}
      onPointerUp={(e) => {
        if (pointerDownOutsideRef.current && e.target === dialogRef.current) {
          pointerDownOutsideRef.current = false;
          onClose();
        }
      }}
    >
      <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
        <h2 id={titleId} className="text-[15px] font-semibold text-foreground">
          {initialRule ? tr("routing.editRule") : tr("routing.addRule")}
        </h2>
        <button
          type="button"
          onClick={onClose}
          aria-label={tr("action.close")}
          className="inline-flex h-8 w-8 max-md:h-[var(--m-btn-icon)] max-md:w-[var(--m-btn-icon)] items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
      <RuleEditorForm
        initialRule={initialRule}
        isAndroid={isAndroid}
        nodes={nodes}
        groups={groups}
        listeners={listeners}
        onClose={onClose}
        onSave={onSave}
      />
    </dialog>
  );
}
