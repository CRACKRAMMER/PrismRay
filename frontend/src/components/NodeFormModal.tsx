// SPDX-License-Identifier: MPL-2.0

import React, { useEffect, useId, useRef, useState } from "react";
import { AlertTriangle, Check, Copy, Loader2, QrCode, X } from "lucide-react";
import QRCode from "qrcode";
import { type NodeConfig, api, formatApiError } from "../lib/api.ts";
import { ALL_PROTOCOLS } from "../lib/helpers.ts";
import { useAppStore } from "../store/appStore.ts";
import { HelpTip } from "./HelpTip.tsx";
import { NodeTabMultiSelect, type LockedSourceTab, type TagCheckState } from "./NodeTabMultiSelect.tsx";
import { Button } from "./ui/button.tsx";
import { Input } from "./ui/input.tsx";
import { Select } from "./ui/select.tsx";

const EMPTY_NODE: Omit<NodeConfig, "id"> = {
  name: "",
  user_alias: "",
  group: "",
  tags: [],
  protocol: "vless",
  address: "",
  port: 443,
  engine_pref: "",
  detour_id: "",
  security: "tls",
  network: "tcp",
  sni: "",
  fingerprint: "chrome",
  alpn: [],
  allow_insecure: false,
  uuid: "",
  password: "",
  username: "",
  method: "2022-blake3-aes-128-gcm",
  cipher: "auto",
  alter_id: 0,
  flow: "",
  vless_encryption: "",
  public_key: "",
  short_id: "",
  spider_x: "",
  mldsa65_verify: "",
  path: "",
  host: "",
  service_name: "",
  xhttp_mode: "auto",
  mux_enabled: false,
  up_mbps: 100,
  down_mbps: 100,
  obfs_type: "",
  obfs_password: "",
  hop_ports: "",
  hop_interval: "30s",
  congestion_control: "bbr",
  udp_relay_mode: "native",
  zero_rtt_handshake: false,
  heartbeat: "10s",
  idle_session_check_interval: "30s",
  idle_session_timeout: "30s",
  min_idle_session: 5,
  private_key: "",
  peer_public_key: "",
  pre_shared_key: "",
  local_addresses: ["10.0.0.2/32"],
  reserved: [],
  mtu: 1408,
  workers: 2,
  naive_quic: false,
};

interface NodeFormModalProps {
  open: boolean;
  initialNode: NodeConfig | null;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}

export interface NodeEditorFormProps {
  initialNode: NodeConfig | null;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
  embedded?: boolean;
}

function defaultSecurityForProtocol(proto: string): string {
  switch (proto) {
    case "vless":
    case "trojan":
    case "hysteria2":
    case "tuic":
    case "anytls":
    case "naive":
      return "tls";
    default:
      return "none";
  }
}

export function NodeEditorForm({ initialNode, onClose, onSaved, embedded = false }: NodeEditorFormProps) {
  const { locale, tr, notify, nodes, groups, subscriptions, customNodeTabs, saveCustomNodeTabs } = useAppStore();

  const [form, setForm] = useState<Omit<NodeConfig, "id">>({ ...EMPTY_NODE });
  const [alpnText, setAlpnText] = useState("");
  const [localAddrText, setLocalAddrText] = useState("10.0.0.2/32");
  const [reservedText, setReservedText] = useState("");
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    if (initialNode) {
      setForm({ ...EMPTY_NODE, ...initialNode });
      setAlpnText((initialNode.alpn || []).join(", "));
      setLocalAddrText((initialNode.local_addresses || ["10.0.0.2/32"]).join(", "));
      setReservedText((initialNode.reserved || []).join(", "));
    } else {
      setForm({ ...EMPTY_NODE });
      setAlpnText("");
      setLocalAddrText("10.0.0.2/32");
      setReservedText("");
    }
    setFormError("");
  }, [initialNode]);

  const setField = <K extends keyof Omit<NodeConfig, "id">>(key: K, value: Omit<NodeConfig, "id">[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleProtocolChange = (proto: string) => {
    setForm((prev) => ({
      ...prev,
      protocol: proto,
      security: defaultSecurityForProtocol(proto),
      network: proto === "vless" || proto === "vmess" || proto === "trojan" ? prev.network || "tcp" : "tcp",
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    if (!form.name.trim() || !form.address.trim() || !form.port || form.port < 1 || form.port > 65535) {
      setFormError(
        locale === "zh-CN"
          ? "请填写有效的节点名称、服务器地址与端口 (1-65535)"
          : "Valid name, server address, and port (1-65535) are required.",
      );
      return;
    }

    const alpn = alpnText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const localAddresses = localAddrText
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const reserved = reservedText
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 0 && n <= 255);

    const payload: NodeConfig = {
      ...(form as NodeConfig),
      id: initialNode?.id || "",
      name: form.name.trim(),
      user_alias: form.user_alias?.trim() || "",
      group: form.group?.trim() || "",
      detour_id: form.detour_id?.trim() || "",
      address: form.address.trim(),
      port: Number(form.port),
      alpn,
      local_addresses: form.protocol === "wireguard" ? localAddresses : undefined,
      reserved: form.protocol === "wireguard" ? reserved : undefined,
    };

    setSaving(true);
    try {
      if (initialNode?.id) {
        await api.updateNode(initialNode.id, payload);
      } else {
        await api.addNode(payload);
      }
      await onSaved();
      notify(locale === "zh-CN" ? "节点已保存" : "Node saved");
      onClose();
    } catch (err) {
      setFormError(formatApiError(err));
    } finally {
      setSaving(false);
    }
  };

  const labelClass = "text-xs font-medium text-muted-foreground";
  const proto = form.protocol;
  const showsTransport = ["vless", "vmess", "trojan", "shadowsocks", "anytls"].includes(proto);
  const showsTLS = proto !== "wireguard";
  const isXrayExclusive =
    form.engine_pref === "xray" ||
    (proto === "vless" &&
      (form.network === "xhttp" ||
        Boolean(form.vless_encryption?.trim()) ||
        Boolean(form.mldsa65_verify?.trim())));
  const eligibleDetourGroups = groups.filter((g) => {
    const st = (g.strategy || "").trim().toLowerCase();
    return st !== "loadbalance" && st !== "load-balance" && st !== "hash" && (g.node_ids || []).length > 0;
  });
  const eligibleDetourNodes = nodes.filter((n) => n.id !== initialNode?.id);

  const lockedSubSources: LockedSourceTab[] = (() => {
    const sid = (form.sub_id || "").trim();
    if (!sid) return [];
    const sub = subscriptions.find((s) => s.id === sid);
    return [{ id: sid, label: sub?.name || sid }];
  })();

  const availableTagChoices = Array.from(
    new Set(
      [...(customNodeTabs || []), ...(form.tags || []), (form.group || "").trim()]
        .map((t) => t.trim())
        .filter(Boolean),
    ),
  );

  const nodeTagStates: Record<string, TagCheckState> = {};
  for (const tag of availableTagChoices) {
    const active = (form.tags || []).some((t) => t.trim() === tag) || (form.group || "").trim() === tag;
    nodeTagStates[tag] = active ? "all" : "none";
  }

  const handleToggleNodeTag = (tag: string, nextChecked: boolean) => {
    const clean = tag.trim();
    if (!clean) return;
    setForm((prev) => {
      if (nextChecked) {
        const nextTags = Array.from(new Set([...(prev.tags || []), clean]));
        return { ...prev, tags: nextTags };
      }
      const nextTags = (prev.tags || []).filter((t) => t.trim() !== clean);
      const nextGroup = (prev.group || "").trim() === clean ? "" : prev.group;
      return { ...prev, group: nextGroup, tags: nextTags };
    });
  };

  const handleAddInlineTag = async (rawName: string) => {
    const clean = rawName.trim();
    if (!clean) return;
    if (!customNodeTabs.includes(clean)) {
      await saveCustomNodeTabs([...customNodeTabs, clean]).catch(() => {});
    }
    setForm((prev) => ({
      ...prev,
      tags: Array.from(new Set([...(prev.tags || []), clean])),
    }));
  };

  return (
      <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-1 flex-col overflow-hidden">
        <div className={embedded ? "space-y-4 text-xs" : "flex-1 space-y-5 overflow-y-auto px-5 py-4"}>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "节点名称" : "Name"}</label>
              <Input value={form.name} onChange={(e) => setField("name", e.target.value)} required />
            </div>
            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "自定义备注（别名）" : "Custom Alias"}</label>
              <Input
                value={form.user_alias || ""}
                onChange={(e) => setField("user_alias", e.target.value)}
                placeholder={locale === "zh-CN" ? "同步订阅时保留" : "Preserved across sync"}
              />
            </div>

            <div className="space-y-1 sm:col-span-2">
              <label className={labelClass}>{tr("proxies.customTag")}</label>
              <Input
                value={form.group || ""}
                onChange={(e) => setField("group", e.target.value)}
                placeholder={locale === "zh-CN" ? "可选分类标签，如 GCP / 自建 / 游戏（用于节点页 Tab 筛选）" : "Optional tag e.g. Self-hosted / Work"}
              />
            </div>

            <div className="space-y-1.5 sm:col-span-2">
              <label className={labelClass}>{tr("proxies.nodeTags")}</label>
              <NodeTabMultiSelect
                mode="assign"
                lockedSources={lockedSubSources}
                customTags={availableTagChoices}
                tagStates={nodeTagStates}
                onToggleTag={handleToggleNodeTag}
                onCreateAndAssignTag={handleAddInlineTag}
                placeholder={tr("proxies.nodeTags")}
              />
            </div>

            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "协议类型" : "Protocol"}</label>
              <Select value={proto} onChange={(e) => handleProtocolChange(e.target.value)}>
                {ALL_PROTOCOLS.map((p) => (
                  <option key={p} value={p}>
                    {p.toUpperCase()}
                  </option>
                ))}
              </Select>
            </div>

            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "内核引擎偏好" : "Engine Preference"}</label>
              <Select
                value={form.engine_pref || ""}
                onChange={(e) => setField("engine_pref", e.target.value)}
              >
                <option value="">{locale === "zh-CN" ? "自动分派 (推荐)" : "Auto (Recommended)"}</option>
                <option value="sing-box">sing-box</option>
                <option value="xray">Xray-core</option>
              </Select>
            </div>

            <div className="space-y-1 sm:col-span-2">
              <div className="flex items-center gap-1.5">
                <label className={labelClass} htmlFor="node-detour-select">
                  {tr("node.detourLabel")}
                </label>
                <HelpTip
                  ariaLabel={tr("node.detourLabel")}
                  tone={isXrayExclusive ? "warning" : "muted"}
                  text={isXrayExclusive ? tr("node.detourXrayUnsupported") : tr("node.detourHint")}
                />
              </div>
              <Select
                id="node-detour-select"
                value={isXrayExclusive ? "" : form.detour_id || ""}
                disabled={isXrayExclusive}
                onChange={(e) => setField("detour_id", e.target.value)}
              >
                <option value="">{tr("node.detourNone")}</option>
                {eligibleDetourGroups.length > 0 && (
                  <optgroup label={tr("node.detourGroups")}>
                    {eligibleDetourGroups.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name} ({g.strategy})
                      </option>
                    ))}
                  </optgroup>
                )}
                {eligibleDetourNodes.length > 0 && (
                  <optgroup label={tr("node.detourNodes")}>
                    {eligibleDetourNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.user_alias || n.name} ({n.protocol.toUpperCase()})
                      </option>
                    ))}
                  </optgroup>
                )}
              </Select>
            </div>

            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "服务器地址" : "Server Address"}</label>
              <Input value={form.address} onChange={(e) => setField("address", e.target.value)} required />
            </div>
            <div className="space-y-1">
              <label className={labelClass}>{locale === "zh-CN" ? "端口" : "Port"}</label>
              <Input
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(e) => setField("port", Number(e.target.value))}
                required
              />
            </div>
          </div>

          {/* Authentication Fields */}
          {proto !== "wireguard" ? (
            <div className="space-y-3 rounded-xl border bg-muted/30 p-3.5">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {locale === "zh-CN" ? "认证凭据" : "Credentials"}
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {(proto === "vless" || proto === "vmess" || proto === "tuic") && (
                  <div className="space-y-1 sm:col-span-2">
                    <label className={labelClass}>UUID</label>
                    <Input
                      value={form.uuid || ""}
                      onChange={(e) => setField("uuid", e.target.value)}
                      placeholder="00000000-0000-0000-0000-000000000000"
                    />
                  </div>
                )}
                {proto === "vless" && (
                  <>
                    <div className="space-y-1">
                      <label className={labelClass}>Flow</label>
                      <Select
                        value={form.flow || ""}
                        onChange={(e) => setField("flow", e.target.value)}
                      >
                        <option value="">None</option>
                        <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                        <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <label className={labelClass}>VLESS Encryption (v26+)</label>
                      <Input
                        value={form.vless_encryption || ""}
                        onChange={(e) => setField("vless_encryption", e.target.value)}
                        placeholder="none or mlkem768..."
                      />
                    </div>
                  </>
                )}
                {proto === "vmess" && (
                  <>
                    <div className="space-y-1">
                      <label className={labelClass}>Cipher / Security</label>
                      <Select
                        value={form.cipher || "auto"}
                        onChange={(e) => setField("cipher", e.target.value)}
                      >
                        <option value="auto">auto</option>
                        <option value="aes-128-gcm">aes-128-gcm</option>
                        <option value="chacha20-poly1305">chacha20-poly1305</option>
                        <option value="none">none</option>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <label className={labelClass}>Alter ID</label>
                      <Input
                        type="number"
                        min={0}
                        value={form.alter_id || 0}
                        onChange={(e) => setField("alter_id", Number(e.target.value))}
                      />
                    </div>
                  </>
                )}
                {proto === "shadowsocks" && (
                  <div className="space-y-1">
                    <label className={labelClass}>{locale === "zh-CN" ? "加密套件" : "Method"}</label>
                    <Select
                      value={form.method || "2022-blake3-aes-128-gcm"}
                      onChange={(e) => setField("method", e.target.value)}
                    >
                      <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
                      <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
                      <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
                      <option value="aes-256-gcm">aes-256-gcm</option>
                      <option value="aes-128-gcm">aes-128-gcm</option>
                      <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
                    </Select>
                  </div>
                )}
                {(proto === "socks" || proto === "http" || proto === "naive") && (
                  <div className="space-y-1">
                    <label className={labelClass}>{locale === "zh-CN" ? "用户名" : "Username"}</label>
                    <Input value={form.username || ""} onChange={(e) => setField("username", e.target.value)} />
                  </div>
                )}
                {proto !== "vless" && proto !== "vmess" && (
                  <div className="space-y-1">
                    <label className={labelClass}>{locale === "zh-CN" ? "密码 / Auth" : "Password"}</label>
                    <Input
                      type="password"
                      value={form.password || ""}
                      onChange={(e) => setField("password", e.target.value)}
                    />
                  </div>
                )}
              </div>
              {proto === "naive" ? (
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <input
                    type="checkbox"
                    checked={Boolean(form.naive_quic)}
                    onChange={(e) => setField("naive_quic", e.target.checked)}
                  />
                  <span>Enable QUIC (HTTP/3) for NaiveProxy</span>
                </label>
              ) : null}
            </div>
          ) : null}

          {/* Protocol Specific Sections */}
          {proto === "hysteria2" && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-2">
                Hysteria2
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Up Mbps</label>
                <Input
                  type="number"
                  value={form.up_mbps ?? 100}
                  onChange={(e) => setField("up_mbps", Number(e.target.value))}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Down Mbps</label>
                <Input
                  type="number"
                  value={form.down_mbps ?? 100}
                  onChange={(e) => setField("down_mbps", Number(e.target.value))}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Obfs Type</label>
                <Select
                  value={form.obfs_type || ""}
                  onChange={(e) => setField("obfs_type", e.target.value)}
                >
                  <option value="">None</option>
                  <option value="salamander">salamander</option>
                </Select>
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Obfs Password</label>
                <Input
                  value={form.obfs_password || ""}
                  onChange={(e) => setField("obfs_password", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Hop Ports</label>
                <Input
                  value={form.hop_ports || ""}
                  onChange={(e) => setField("hop_ports", e.target.value)}
                  placeholder="20000-50000"
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Hop Interval</label>
                <Input
                  value={form.hop_interval || "30s"}
                  onChange={(e) => setField("hop_interval", e.target.value)}
                />
              </div>
            </div>
          )}

          {proto === "tuic" && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-2">
                TUIC v5
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Congestion Control</label>
                <Select
                  value={form.congestion_control || "bbr"}
                  onChange={(e) => setField("congestion_control", e.target.value)}
                >
                  <option value="bbr">bbr</option>
                  <option value="cubic">cubic</option>
                  <option value="new_reno">new_reno</option>
                </Select>
              </div>
              <div className="space-y-1">
                <label className={labelClass}>UDP Relay Mode</label>
                <Select
                  value={form.udp_relay_mode || "native"}
                  onChange={(e) => setField("udp_relay_mode", e.target.value)}
                >
                  <option value="native">native</option>
                  <option value="quic">quic</option>
                </Select>
              </div>
              <label className="flex items-center gap-2 text-xs text-foreground sm:col-span-2">
                <input
                  type="checkbox"
                  checked={Boolean(form.zero_rtt_handshake)}
                  onChange={(e) => setField("zero_rtt_handshake", e.target.checked)}
                />
                <span>0-RTT Handshake</span>
              </label>
            </div>
          )}

          {proto === "anytls" && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-3">
                AnyTLS
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Check Interval</label>
                <Input
                  value={form.idle_session_check_interval || "30s"}
                  onChange={(e) => setField("idle_session_check_interval", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Idle Timeout</label>
                <Input
                  value={form.idle_session_timeout || "30s"}
                  onChange={(e) => setField("idle_session_timeout", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Min Idle Sessions</label>
                <Input
                  type="number"
                  min={0}
                  value={form.min_idle_session ?? 5}
                  onChange={(e) => setField("min_idle_session", Number(e.target.value))}
                />
              </div>
            </div>
          )}

          {proto === "wireguard" && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-2">
                WireGuard Endpoint
              </div>
              <div className="space-y-1 sm:col-span-2">
                <label className={labelClass}>Private Key</label>
                <Input
                  type="password"
                  value={form.private_key || ""}
                  onChange={(e) => setField("private_key", e.target.value)}
                />
              </div>
              <div className="space-y-1 sm:col-span-2">
                <label className={labelClass}>Peer Public Key</label>
                <Input
                  value={form.peer_public_key || ""}
                  onChange={(e) => setField("peer_public_key", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Pre-Shared Key</label>
                <Input
                  type="password"
                  value={form.pre_shared_key || ""}
                  onChange={(e) => setField("pre_shared_key", e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Local Addresses (CIDR, comma separated)</label>
                <Input value={localAddrText} onChange={(e) => setLocalAddrText(e.target.value)} />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>MTU</label>
                <Input
                  type="number"
                  value={form.mtu ?? 1408}
                  onChange={(e) => setField("mtu", Number(e.target.value))}
                />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Reserved (e.g. 1, 2, 3)</label>
                <Input
                  value={reservedText}
                  onChange={(e) => setReservedText(e.target.value)}
                  placeholder="0, 0, 0"
                />
              </div>
            </div>
          )}

          {/* Transport */}
          {showsTransport && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-2">
                {locale === "zh-CN" ? "传输层与 XHTTP" : "Transport & XHTTP"}
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Network</label>
                <Select
                  value={form.network || "tcp"}
                  onChange={(e) => setField("network", e.target.value)}
                >
                  <option value="tcp">TCP</option>
                  <option value="ws">WebSocket</option>
                  <option value="grpc">gRPC</option>
                  <option value="xhttp">XHTTP (Xray)</option>
                  <option value="httpupgrade">HTTPUpgrade (Xray)</option>
                  <option value="h2">HTTP/2</option>
                </Select>
              </div>
              {form.network === "xhttp" ? (
                <div className="space-y-1">
                  <label className={labelClass}>XHTTP Mode</label>
                  <Select
                    value={form.xhttp_mode || "auto"}
                    onChange={(e) => setField("xhttp_mode", e.target.value)}
                  >
                    <option value="auto">auto</option>
                    <option value="packet-up">packet-up</option>
                    <option value="stream-up">stream-up</option>
                    <option value="stream-one">stream-one</option>
                  </Select>
                </div>
              ) : (
                <div className="space-y-1">
                  <label className={labelClass}>Host Header</label>
                  <Input value={form.host || ""} onChange={(e) => setField("host", e.target.value)} />
                </div>
              )}
              <div className="space-y-1">
                <label className={labelClass}>Path</label>
                <Input value={form.path || ""} onChange={(e) => setField("path", e.target.value)} placeholder="/" />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>gRPC Service Name</label>
                <Input
                  value={form.service_name || ""}
                  onChange={(e) => setField("service_name", e.target.value)}
                />
              </div>
            </div>
          )}

          {/* TLS & REALITY */}
          {showsTLS && (
            <div className="grid grid-cols-1 gap-3 rounded-xl border bg-muted/30 p-3.5 sm:grid-cols-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground sm:col-span-2">
                TLS & REALITY
              </div>
              <div className="space-y-1">
                <label className={labelClass}>Security</label>
                <Select
                  value={form.security || "none"}
                  onChange={(e) => setField("security", e.target.value)}
                >
                  <option value="none">none</option>
                  <option value="tls">tls</option>
                  <option value="reality">reality</option>
                </Select>
              </div>
              <div className="space-y-1">
                <label className={labelClass}>SNI / ServerName</label>
                <Input value={form.sni || ""} onChange={(e) => setField("sni", e.target.value)} />
              </div>
              <div className="space-y-1">
                <label className={labelClass}>uTLS Fingerprint</label>
                <Select
                  value={form.fingerprint || ""}
                  onChange={(e) => setField("fingerprint", e.target.value)}
                >
                  <option value="">Default</option>
                  <option value="chrome">chrome</option>
                  <option value="firefox">firefox</option>
                  <option value="safari">safari</option>
                  <option value="ios">ios</option>
                  <option value="android">android</option>
                  <option value="edge">edge</option>
                  <option value="randomized">randomized</option>
                </Select>
              </div>
              <div className="space-y-1">
                <label className={labelClass}>ALPN (comma separated)</label>
                <Input value={alpnText} onChange={(e) => setAlpnText(e.target.value)} placeholder="h2, http/1.1" />
              </div>

              {form.security === "reality" && (
                <>
                  <div className="space-y-1 sm:col-span-2">
                    <label className={labelClass}>REALITY Public Key (pbk)</label>
                    <Input
                      value={form.public_key || ""}
                      onChange={(e) => setField("public_key", e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label className={labelClass}>Short ID (sid)</label>
                    <Input
                      value={form.short_id || ""}
                      onChange={(e) => setField("short_id", e.target.value)}
                    />
                  </div>
                  <div className="space-y-1">
                    <label className={labelClass}>ML-DSA-65 Verify (pqv)</label>
                    <Input
                      value={form.mldsa65_verify || ""}
                      onChange={(e) => setField("mldsa65_verify", e.target.value)}
                    />
                  </div>
                </>
              )}

              <div className="space-y-2 sm:col-span-2">
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <input
                    type="checkbox"
                    checked={Boolean(form.allow_insecure)}
                    onChange={(e) => setField("allow_insecure", e.target.checked)}
                  />
                  <span>{tr("proxies.insecureBadge")} (allow_insecure)</span>
                </label>
                {form.allow_insecure ? (
                  <div className="flex items-center gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                    <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>
                      {locale === "zh-CN"
                        ? "警告：跳过 TLS 证书校验会降低传输安全性，仅建议用于可信自签测试环境。"
                        : "Warning: Skipping TLS verification exposes connections to MitM; use only for trusted testing."}
                    </span>
                  </div>
                ) : null}
              </div>
            </div>
          )}
        </div>

        <div className={embedded ? "border-t border-border pt-3 mt-3" : "border-t px-5 py-3"}>
          <div className="mb-2 min-h-4 text-xs text-destructive" role="alert" aria-live="polite">
            {formError || ""}
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={onClose}>
              {embedded ? tr("action.close") : tr("action.cancel")}
            </Button>
            <Button type="submit" disabled={saving}>
              {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" /> : null}
              {tr("action.save")}
            </Button>
          </div>
        </div>
      </form>
  );
}

export function NodeFormModal({ open, initialNode, onClose, onSaved }: NodeFormModalProps) {
  const { tr } = useAppStore();
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const pointerDownOutsideRef = useRef(false);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open) {
      if (!dialog.open) dialog.showModal();
    } else if (dialog.open) {
      dialog.returnValue = "";
      dialog.close();
    }
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      {...({ closedby: "any" } as Record<string, string>)}
      className="m-auto flex max-h-[90dvh] w-[min(94vw,46rem)] flex-col overflow-hidden rounded-[12px] border border-border bg-popover p-0 text-popover-foreground"
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
          {initialNode
            ? `${tr("action.edit")} — ${initialNode.user_alias || initialNode.name}`
            : tr("proxies.addNode")}
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
      <NodeEditorForm initialNode={initialNode} onClose={onClose} onSaved={onSaved} />
    </dialog>
  );
}

interface QRShareModalProps {
  open: boolean;
  nodeName: string;
  uri: string;
  onClose: () => void;
}

export function QRSharePanel({ nodeName, uri, onClose }: { nodeName: string; uri: string; onClose?: () => void }) {
  const { tr } = useAppStore();
  const [dataUrl, setDataUrl] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setCopied(false);
    if (uri) {
      void QRCode.toDataURL(uri, { width: 224, margin: 2 }).then(setDataUrl).catch(() => setDataUrl(""));
    } else {
      setDataUrl("");
    }
  }, [uri]);

  const handleCopy = async () => {
    if (!uri) return;
    try {
      await navigator.clipboard.writeText(uri);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="flex flex-col items-center gap-3">
      {dataUrl ? (
        <div className="rounded-[10px] border border-border bg-white p-2.5">
          <img src={dataUrl} alt={nodeName} className="h-48 w-48" />
        </div>
      ) : null}
      <div className="w-full rounded-[6px] border border-border bg-muted p-2.5 font-mono text-[11px] break-all text-foreground">
        {uri}
      </div>
      <div className="flex w-full justify-end gap-2">
        {onClose && (
          <Button type="button" variant="outline" onClick={onClose}>
            {tr("action.close")}
          </Button>
        )}
        <Button type="button" onClick={() => void handleCopy()}>
          {copied ? <Check className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />}
          {tr("action.copy")}
        </Button>
      </div>
    </div>
  );
}

export function QRShareModal({ open, nodeName, uri, onClose }: QRShareModalProps) {
  const { tr } = useAppStore();
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const pointerDownOutsideRef = useRef(false);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open) {
      if (!dialog.open) dialog.showModal();
    } else if (dialog.open) {
      dialog.returnValue = "";
      dialog.close();
    }
  }, [open]);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      {...({ closedby: "any" } as Record<string, string>)}
      className="m-auto w-[min(92vw,26rem)] rounded-[12px] border border-border bg-popover p-0 text-popover-foreground"
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
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div className="flex items-center gap-2 min-w-0">
          <QrCode className="h-4 w-4 text-primary shrink-0" aria-hidden="true" />
          <h2 id={titleId} className="text-sm font-semibold text-foreground truncate">
            {tr("proxies.qrTitle")} — {nodeName}
          </h2>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label={tr("action.close")}
          className="inline-flex h-8 w-8 max-md:h-[var(--m-btn-icon)] max-md:w-[var(--m-btn-icon)] items-center justify-center rounded-[6px] text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
      <div className="p-4">
        <QRSharePanel nodeName={nodeName} uri={uri} onClose={onClose} />
      </div>
    </dialog>
  );
}
