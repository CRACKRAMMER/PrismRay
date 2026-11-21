// SPDX-License-Identifier: MPL-2.0

import axios from "axios";
import { invoke } from "@tauri-apps/api/core";
import { buildApiUrl, buildWsUrl } from "./helpers.ts";

axios.defaults.withCredentials = true;

export const isDesktop = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export interface AndroidBridgeInterface {
  isAndroid(): boolean;
  prepareAndStartVpn(configJson: string): string;
  stopVpn(): boolean;
  getVpnStatus(): string;
  listInstalledApps(): string;
  getAppIcons?: (packagesJson: string) => string;
  startQrScan?: () => boolean;
  applyInsetsNow?: () => boolean;
  copyToClipboard?: (text: string) => boolean;
  getBiometricStatus?: () => string;
  authenticateBiometric?: (reason: string) => boolean;
  getBootAutostart?: () => boolean;
  setBootAutostart?: (enabled: boolean) => boolean;
  openVpnSettings?: () => boolean;
}

declare global {
  interface Window {
    PrismRayAndroid?: AndroidBridgeInterface;
  }
}

export const isAndroidClient = (): boolean =>
  typeof window !== "undefined" && Boolean(window.PrismRayAndroid?.isAndroid?.());

export let desktopToken = "";
export let API_URL =
  typeof window !== "undefined"
    ? (
        import.meta.env.VITE_API_URL ||
        (isDesktop ? "http://127.0.0.1:2178/api" : `${window.location.origin}/api`)
      ).replace(/\/$/, "")
    : "http://127.0.0.1:2178/api";

export const AUTH_REQUIRED_EVENT = "prismray-auth-required";

export interface NodeConfig {
  id: string;
  sub_id?: string;
  group?: string;
  name: string;
  user_alias?: string;
  favorite?: boolean;
  engine_pref?: string;
  detour_id?: string;
  protocol: string;
  address: string;
  port: number;
  uuid?: string;
  password?: string;
  username?: string;
  method?: string;
  cipher?: string;
  alter_id?: number;
  flow?: string;
  uot?: boolean;
  security: string;
  allow_insecure?: boolean;
  sni?: string;
  fingerprint?: string;
  alpn?: string[];
  public_key?: string;
  short_id?: string;
  spider_x?: string;
  mldsa65_verify?: string;
  vless_encryption?: string;
  network?: string;
  path?: string;
  host?: string;
  service_name?: string;
  ws_headers?: Record<string, string>;
  early_data?: number;
  early_data_header?: string;
  xhttp_mode?: string;
  xhttp_extra?: Record<string, unknown>;
  mux_enabled?: boolean;
  up_mbps?: number;
  down_mbps?: number;
  obfs_type?: string;
  obfs_password?: string;
  hop_ports?: string;
  hop_interval?: string;
  congestion_control?: string;
  udp_relay_mode?: string;
  zero_rtt_handshake?: boolean;
  heartbeat?: string;
  idle_session_check_interval?: string;
  idle_session_timeout?: string;
  min_idle_session?: number;
  private_key?: string;
  peer_public_key?: string;
  pre_shared_key?: string;
  local_addresses?: string[];
  reserved?: number[];
  mtu?: number;
  workers?: number;
  naive_quic?: boolean;
  extra_headers?: Record<string, string>;
  tags?: string[];
  latency?: number;
  ping_ms?: number;
  down_speed_mbps?: number;
  up_speed_mbps?: number;
}

export interface GroupConfig {
  id: string;
  name: string;
  strategy: string;
  selected_node_id?: string;
  manual_pin?: boolean;
  filter?: string;
  priority_rule?: string;
  auto_failover?: boolean | null;
  detour_id?: string;
  tolerance_ms?: number;
  interval?: string;
  sort_order: number;
  node_ids: string[];
}

export interface ListenConfig {
  id: string;
  name: string;
  protocol: string;
  address: string;
  port: number;
  allow_lan?: boolean;
  username?: string;
  password?: string;
  target_outbound?: string;
  target_group_id?: string;
  node_ids: string[];
  enabled: boolean;
}

export interface RoutingRule {
  id?: string;
  name?: string;
  enabled: boolean;
  domains?: string[];
  domain_suffix?: string[];
  domain_keyword?: string[];
  domain_regex?: string[];
  ip_cidr?: string[];
  source_ip_cidr?: string[];
  ip_is_private?: boolean;
  rule_set?: string[];
  network?: string[];
  port?: number[];
  port_range?: string[];
  source_port?: number[];
  process_name?: string[];
  process_path?: string[];
  package_name?: string[];
  protocol?: string[];
  inbound?: string[];
  invert?: boolean;
  outbound: string;
}

export interface RoutingProfile {
  mode: string;
  block_ads: boolean;
  bypass_lan: boolean;
  allow_lan_broadcast?: boolean;
  bypass_cn: boolean;
  local_dns: string;
  remote_dns: string;
  domain_strategy?: string;
  hijack_dns?: boolean;
  fake_ip?: boolean;
  fake_ip_v4_range?: string;
  fake_ip_v6_range?: string;
  fake_ip_filter?: string[];
  kill_switch?: boolean;
  webrtc_mode?: "block" | "proxy" | "direct";
  log_level?: string;
  per_app_mode?: string;
  per_app_packages?: string[];
  custom_rules: RoutingRule[];
}

export interface RuleSetSpec {
  id: string;
  tag: string;
  format: string;
  source_type: string;
  url: string;
  local_path: string;
  update_interval: string;
  enabled: boolean;
  synced: boolean;
  size_bytes: number;
  last_synced_at?: string;
}

export interface SimulationInput {
  domain?: string;
  ip?: string;
  source_ip?: string;
  network?: string;
  process_name?: string;
  process_path?: string;
  package_name?: string;
  port?: number;
  protocol?: string;
  inbound?: string;
}

export interface HealthSettings {
  url: string;
  speed_down_url: string;
  speed_up_url: string;
  interval_seconds: number;
  tolerance_ms: number;
  high_latency_ms?: number;
  priority_rule: "latency_first" | "speed_first" | "hybrid_score";
  failover: boolean;
  recover: boolean;
}

export interface GpuStatus {
  configured_mode: "auto" | "on" | "off";
  effective_mode: "auto" | "on" | "off";
  cli_override?: string | null;
  active: boolean;
  session: string;
  vendor: string;
  has_render_node: boolean;
  detail: string;
  restart_required: boolean;
}

export type ProbeMode = "urltest" | "ping" | "speed" | "full";

export interface ProbeResult {
  node_id: string;
  latency_ms: number;
  ping_ms?: number;
  down_speed_mbps?: number;
  up_speed_mbps?: number;
  mode?: ProbeMode;
  error?: string;
}

export interface SimulationResult {
  outbound: string;
  matched_rule: string;
  action: string;
}

export interface SubscriptionRecord {
  id: string;
  name: string;
  url: string;
  upload_bytes: number;
  download_bytes: number;
  total_bytes: number;
  expire_unix: number;
  auto_update_hours: number;
  imported_count: number;
  skipped_count: number;
  warnings: string[];
  last_updated_at: string;
}

export interface SkippedEntry {
  index: number;
  name?: string;
  raw?: string;
  reason: string;
}

export interface SubscriptionImportResult {
  imported: number;
  nodes: NodeConfig[];
  skipped: SkippedEntry[];
  warnings: string[];
  meta: {
    upload_bytes: number;
    download_bytes: number;
    total_bytes: number;
    expire_unix: number;
  };
}

export interface ProcessStatus {
  status: string;
  running: boolean;
  singbox_running: boolean;
  xray_running: boolean;
  singbox_pid?: number;
  xray_pid?: number;
  active_node_id: string;
  active_group_id: string;
  active_node_name?: string;
  active_group_name?: string;
  active_resolved_node_name?: string;
  live_group_nodes?: Record<string, string>;
  active_tag: string;
  tun_enabled: boolean;
  system_proxy_enabled?: boolean;
  system_proxy_wanted?: boolean;
  android_mode: boolean;
  mixed_port: number;
  clash_api_port: number;
  uptime_seconds: number;
  last_error?: string;
  skipped_naive?: string[];
  resolved_singbox?: string;
  resolved_xray?: string;
  listener_health?: string;
  mode: string;
  kill_switch_enabled?: boolean;
  kill_switch_tripped?: boolean;
  kill_switch_reason?: string;
}

export interface AuthStatus {
  mode?: string;
  initialized: boolean;
  unlocked: boolean;
  authentication: boolean;
  authenticated: boolean;
  password_lock_enabled?: boolean;
  biometric_enabled?: boolean;
  bootstrap_token_required?: boolean;
}

export interface BiometricStatus {
  available: boolean;
  kind: string;
  detail: string;
}

export async function getBiometricStatus(): Promise<BiometricStatus> {
  if (isAndroidClient() && typeof window.PrismRayAndroid?.getBiometricStatus === "function") {
    try {
      const raw = window.PrismRayAndroid.getBiometricStatus();
      const parsed = JSON.parse(raw) as { available?: boolean; platform?: string; detail?: string };
      return {
        available: Boolean(parsed.available),
        kind: parsed.platform || "android",
        detail: parsed.detail || "Android BiometricPrompt",
      };
    } catch {
      return { available: false, kind: "android", detail: "Unavailable" };
    }
  }
  if (!isDesktop) {
    return { available: false, kind: "web", detail: "Web mode" };
  }
  try {
    return await invoke<BiometricStatus>("biometric_status");
  } catch {
    return { available: false, kind: "unavailable", detail: "Unavailable" };
  }
}

export async function authenticateBiometric(reason: string): Promise<void> {
  if (isAndroidClient() && typeof window.PrismRayAndroid?.authenticateBiometric === "function") {
    return new Promise<void>((resolve, reject) => {
      const onResult = (ev: Event) => {
        window.removeEventListener("prismray-biometric-result", onResult);
        const detail = (ev as CustomEvent<{ success?: boolean; error?: string }>).detail;
        if (detail?.success) {
          resolve();
        } else {
          reject(new Error(detail?.error || "Biometric authentication cancelled"));
        }
      };
      window.addEventListener("prismray-biometric-result", onResult, { once: true });
      const launched = window.PrismRayAndroid?.authenticateBiometric?.(reason);
      if (!launched) {
        window.removeEventListener("prismray-biometric-result", onResult);
        reject(new Error("Failed to launch Android BiometricPrompt"));
      }
    });
  }
  if (!isDesktop) {
    throw new Error("System biometric authentication is only available on desktop");
  }
  await invoke("biometric_authenticate", { reason });
}

export interface ConnectionMetadata {
  network: string;
  type: string;
  sourceIP: string;
  destinationIP: string;
  sourcePort: string;
  destinationPort: string;
  host: string;
  dnsMode?: string;
  processPath?: string;
  specialProxy?: string;
  remoteDestination?: string;
}

export interface ConnectionItem {
  id: string;
  metadata: ConnectionMetadata;
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rulePayload?: string;
}

export interface ConnectionsSnapshot {
  downloadTotal: number;
  uploadTotal: number;
  memory?: number;
  connections: ConnectionItem[];
}

export interface TrafficSample {
  up: number;
  down: number;
  timestamp?: string;
}

export interface LogEntry {
  seq: number;
  timestamp: string;
  core: string;
  level: string;
  message: string;
}

export interface TUNPrivilege {
  os: string;
  singbox_path: string;
  has_cap_admin: boolean;
  is_root: boolean;
  ready_without_password: boolean;
  can_pkexec: boolean;
  detail: string;
  sudo_cached?: boolean;
}

export interface TUNState {
  enabled: boolean;
  running: boolean;
  stack: string;
  node_id: string;
  group_id: string;
  privilege: TUNPrivilege;
  sudo_cached: boolean;
}

export interface AppUpdateAsset {
  name: string;
  download_url: string;
  size: number;
}

export interface AppUpdateCheckResult {
  current_version: string;
  latest_version?: string;
  has_update: boolean;
  status: "update_available" | "up_to_date" | "no_published_release" | "error";
  message?: string;
  prerelease?: boolean;
  release_name?: string;
  release_notes?: string;
  published_at?: string;
  release_url?: string;
  recommended_asset?: AppUpdateAsset;
  install_hint?: string;
  assets?: AppUpdateAsset[];
  platform: string;
  mode: string;
  checked_at: string;
}

export interface CoresStatus {
  managed_by_apk?: boolean;
  sing_box: {
    installed: boolean;
    available: boolean;
    binary: string;
    versions: string[];
    cronet_available: boolean;
  };
  xray: {
    installed: boolean;
    available: boolean;
    binary: string;
    versions: string[];
  };
  auto_update: {
    xray: boolean;
    sing_box: boolean;
  };
}

export interface AndroidAppInfo {
  packageName: string;
  label: string;
  system: boolean;
}

export interface AndroidVPNStatus {
  active: boolean;
  running: boolean;
  protect_path?: string;
  tun_fd?: number;
  mixed_port?: number;
  per_app_mode?: string;
  per_app_packages?: string[];
  active_node_id?: string;
  active_group_id?: string;
}

export interface AppSettings {
  server: { allowed_origins: string[]; host: string; port: number };
  sing_box: {
    binary_path: string;
    config_path: string;
    mixed_port: number;
    clash_api_port: number;
    clash_api_secret?: string;
    rule_set_dir: string;
    auto_update: boolean;
  };
  xray: {
    binary_path: string;
    config_path: string;
    socks_port: number;
    stats_port: number;
    auto_update: boolean;
  };
  storage: { database_path: string; nodes_file?: string };
}

export interface AutostartStatus {
  supported: boolean;
  enabled: boolean;
  minimized: boolean;
  executable?: string;
  entry_path?: string;
  reason?: string;
}

export function formatApiError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      const endpoint = API_URL.replace(/\/api$/, "");
      return `Unable to reach backend (${endpoint})`;
    }
    const data = error.response.data;
    if (typeof data === "string" && data.trim()) return data.trim();
    if (data && typeof data === "object" && "message" in data) {
      return String(data.message);
    }
    if (error.response.status === 401) return "Authentication required (401)";
    if (error.response.status === 423) return "Configuration locked (423)";
    return `HTTP ${error.response.status}`;
  }
  return error instanceof Error ? error.message : String(error);
}

export async function initializeBackend(): Promise<void> {
  if (!isDesktop) return;
  const connection = await invoke<{ url: string; token: string }>("backend_connection");
  API_URL = connection.url.replace(/\/$/, "");
  desktopToken = connection.token;
}

axios.interceptors.request.use((config) => {
  if (desktopToken && config.url?.startsWith(API_URL + "/")) {
    config.headers.Authorization = `Bearer ${desktopToken}`;
  }
  return config;
});

axios.interceptors.response.use(undefined, (error) => {
  const status = axios.isAxiosError(error) ? error.response?.status : undefined;
  const url = axios.isAxiosError(error) ? error.config?.url || "" : "";
  if ((status === 401 || status === 423) && !url.includes("/auth/")) {
    window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
  }
  return Promise.reject(error);
});

export function subscribeStream(
  path: string,
  onMessage: (event: MessageEvent) => void,
  onOpen?: () => void,
): () => void {
  let stopped = false;
  let socket: WebSocket | null = null;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let delay = 1000;

  const connect = () => {
    const wsUrl = buildWsUrl(API_URL, path, desktopToken, window.location.href);
    socket = new WebSocket(wsUrl);
    socket.onopen = () => {
      delay = 1000;
      onOpen?.();
    };
    socket.onmessage = onMessage;
    socket.onerror = () => socket?.close();
    socket.onclose = () => {
      if (!stopped) {
        retry = setTimeout(connect, delay);
        delay = Math.min(delay * 2, 15000);
      }
    };
  };

  connect();
  return () => {
    stopped = true;
    clearTimeout(retry);
    socket?.close();
  };
}

export interface TrayTargetItem {
  actionId: string;
  label: string;
  active: boolean;
}

export interface TrayUpdatePayload {
  running: boolean;
  tunEnabled: boolean;
  systemProxyEnabled: boolean;
  mode: string;
  activeLabel: string;
  recentTargets: TrayTargetItem[];
}

export async function updateNativeTray(payload: TrayUpdatePayload): Promise<void> {
  if (!isDesktop || isAndroidClient()) return;
  try {
    await invoke("update_tray", { payload });
  } catch {
    // Ignore unsupported platform tray calls.
  }
}

export async function getGpuStatus(): Promise<GpuStatus | null> {
  if (!isDesktop || isAndroidClient()) return null;
  try {
    return await invoke<GpuStatus>("get_gpu_status");
  } catch {
    return null;
  }
}

export async function setGpuMode(mode: "auto" | "on" | "off"): Promise<GpuStatus | null> {
  if (!isDesktop || isAndroidClient()) return null;
  return invoke<GpuStatus>("set_gpu_mode", { mode });
}

export const androidBridge = {
  available(): boolean {
    return isAndroidClient();
  },
  prepareAndStartVpn(config: {
    per_app_mode?: string;
    per_app_packages?: string[];
    bypass_lan?: boolean;
    allow_lan_broadcast?: boolean;
    active_node_id?: string;
    active_group_id?: string;
  }): { status: string; error?: string } {
    const raw = window.PrismRayAndroid?.prepareAndStartVpn(JSON.stringify(config));
    if (!raw) return { status: "unavailable" };
    return JSON.parse(raw) as { status: string; error?: string };
  },
  stopVpn(): boolean {
    return Boolean(window.PrismRayAndroid?.stopVpn());
  },
  getVpnStatus(): AndroidVPNStatus | null {
    const raw = window.PrismRayAndroid?.getVpnStatus();
    if (!raw) return null;
    try {
      return JSON.parse(raw) as AndroidVPNStatus;
    } catch {
      return null;
    }
  },
  listInstalledApps(): AndroidAppInfo[] {
    const raw = window.PrismRayAndroid?.listInstalledApps();
    if (!raw) return [];
    try {
      return JSON.parse(raw) as AndroidAppInfo[];
    } catch {
      return [];
    }
  },
  getAppIcons(packages: string[]): Record<string, string> {
    if (!packages.length) return {};
    const raw = window.PrismRayAndroid?.getAppIcons?.(JSON.stringify(packages));
    if (!raw) return {};
    try {
      return JSON.parse(raw) as Record<string, string>;
    } catch {
      return {};
    }
  },
  getBootAutostart(): boolean {
    try {
      return Boolean(window.PrismRayAndroid?.getBootAutostart?.());
    } catch {
      return false;
    }
  },
  setBootAutostart(enabled: boolean): boolean {
    try {
      return Boolean(window.PrismRayAndroid?.setBootAutostart?.(enabled));
    } catch {
      return false;
    }
  },
  openVpnSettings(): boolean {
    try {
      return Boolean(window.PrismRayAndroid?.openVpnSettings?.());
    } catch {
      return false;
    }
  },
};

const apiUrl = (path: string) => buildApiUrl(API_URL, path);

export const api = {
  getAuthStatus: () => axios.get<AuthStatus>(apiUrl("/auth/status")).then((r) => r.data),
  initializeAuth: (password: string, bootstrap_token = "") =>
    axios.post(apiUrl("/auth/initialize"), { password, bootstrap_token }).then((r) => r.data),
  loginAuth: (password: string) => axios.post(apiUrl("/auth/login"), { password }).then((r) => r.data),
  lockAuth: () => axios.post(apiUrl("/auth/lock")).then((r) => r.data),
  logoutAuth: () => axios.post(apiUrl("/auth/logout")).then((r) => r.data),
  setPasswordLock: (payload: { enabled: boolean; password: string; current_password?: string }) =>
    axios
      .post<{ password_lock_enabled: boolean; biometric_enabled?: boolean }>(apiUrl("/auth/password-lock"), payload)
      .then((r) => r.data),
  setBiometricUnlock: (payload: { enabled: boolean; current_password?: string }) =>
    axios
      .post<{ password_lock_enabled: boolean; biometric_enabled: boolean }>(apiUrl("/auth/biometric"), payload)
      .then((r) => r.data),
  biometricUnlock: () => axios.post<{ unlocked: boolean }>(apiUrl("/auth/biometric-unlock")).then((r) => r.data),
  cacheSudo: (password: string) => axios.put(apiUrl("/auth/sudo-cache"), { password }).then((r) => r.data),
  clearSudo: () => axios.delete(apiUrl("/auth/sudo-cache")),

  getStatus: () => axios.get<ProcessStatus>(apiUrl("/process/status")).then((r) => r.data),
  connectProcess: (payload: { node_id?: string; group_id?: string; node?: NodeConfig }) =>
    axios.post<ProcessStatus>(apiUrl("/process/connect"), payload).then((r) => r.data),
  startProcess: () => axios.post<ProcessStatus>(apiUrl("/process/start")).then((r) => r.data),
  stopProcess: () => axios.post<ProcessStatus>(apiUrl("/process/stop")).then((r) => r.data),
  restartProcess: () => axios.post<ProcessStatus>(apiUrl("/process/restart")).then((r) => r.data),

  listNodes: (params?: { search?: string; protocol?: string; favorite?: boolean }) =>
    axios.get<NodeConfig[]>(apiUrl("/nodes"), { params }).then((r) => r.data),
  addNode: (node: Omit<NodeConfig, "id"> & { id?: string }) =>
    axios.post<NodeConfig>(apiUrl("/nodes"), node).then((r) => r.data),
  updateNode: (id: string, node: NodeConfig) =>
    axios.put<NodeConfig>(apiUrl(`/nodes/${id}`), node).then((r) => r.data),
  deleteNode: (id: string) => axios.delete(apiUrl(`/nodes/${id}`)),
  getNodeUri: (id: string) => axios.get<{ uri: string }>(apiUrl(`/nodes/${id}/uri`)).then((r) => r.data),
  probeNodes: (payload?: { node_ids?: string[]; mode?: ProbeMode; url?: string; timeout_ms?: number }) =>
    axios
      .post<{
        mode?: ProbeMode;
        results: ProbeResult[];
        tested: number;
      }>(apiUrl("/nodes/probe"), payload || {})
      .then((r) => r.data),
  probeNode: (id: string, payload?: { mode?: ProbeMode; url?: string }) =>
    axios
      .post<{
        id: string;
        node_id?: string;
        latency_ms: number;
        ping_ms?: number;
        down_speed_mbps?: number;
        up_speed_mbps?: number;
        mode?: ProbeMode;
        error?: string;
      }>(apiUrl(`/nodes/${id}/probe`), payload || {})
      .then((r) => r.data),

  getNodeTabs: () => axios.get<{ tabs: string[] }>(apiUrl("/node-tabs")).then((r) => r.data),
  saveNodeTabs: (tabs: string[]) =>
    axios.put<{ tabs: string[] }>(apiUrl("/node-tabs"), { tabs }).then((r) => r.data),

  listGroups: () => axios.get<GroupConfig[]>(apiUrl("/groups")).then((r) => r.data),
  createGroup: (group: Partial<GroupConfig> & { name: string; strategy: string; node_ids: string[] }) =>
    axios.post<GroupConfig>(apiUrl("/groups"), group).then((r) => r.data),
  updateGroup: (id: string, group: GroupConfig) =>
    axios.put<GroupConfig>(apiUrl(`/groups/${id}`), group).then((r) => r.data),
  deleteGroup: (id: string) => axios.delete(apiUrl(`/groups/${id}`)),
  reorderGroups: (groupIds: string[]) =>
    axios.put<GroupConfig[]>(apiUrl("/groups/reorder"), { group_ids: groupIds }).then((r) => r.data),
  probeGroup: (id: string, payload?: { mode?: ProbeMode; priority_rule?: string; url?: string }) =>
    axios
      .post<{
        group: GroupConfig;
        results: ProbeResult[];
        switched: boolean;
        priority_rule: string;
      }>(apiUrl(`/groups/${id}/probe`), payload || {})
      .then((r) => r.data),
  selectGroupNode: (groupId: string, nodeId: string, auto?: boolean) =>
    axios
      .put<{ group_id: string; node_id: string; manual_pin?: boolean }>(apiUrl(`/groups/${groupId}/select`), {
        node_id: nodeId,
        auto,
      })
      .then((r) => r.data),

  getHealthSettings: () => axios.get<HealthSettings>(apiUrl("/health-settings")).then((r) => r.data),
  saveHealthSettings: (settings: HealthSettings) =>
    axios.put<HealthSettings>(apiUrl("/health-settings"), settings).then((r) => r.data),

  getConnections: () => axios.get<ConnectionsSnapshot>(apiUrl("/connections")).then((r) => r.data),
  closeConnection: (id: string) => axios.delete(apiUrl(`/connections/${id}`)),
  closeAllConnections: () => axios.delete(apiUrl("/connections")),

  listSubscriptions: () => axios.get<SubscriptionRecord[]>(apiUrl("/subscriptions")).then((r) => r.data),
  createSubscription: (payload: { name: string; url: string; auto_update_hours: number }) =>
    axios.post<SubscriptionRecord[]>(apiUrl("/subscriptions"), payload).then((r) => r.data),
  updateSubscription: (id: string, payload: { name?: string; url?: string; auto_update_hours?: number }) =>
    axios.put<SubscriptionRecord>(apiUrl(`/subscriptions/${id}`), payload).then((r) => r.data),
  deleteSubscription: (id: string) =>
    axios.delete<SubscriptionRecord[]>(apiUrl(`/subscriptions/${id}`)).then((r) => r.data),
  refreshSubscription: (id: string) =>
    axios.post<SubscriptionRecord>(apiUrl(`/subscriptions/${id}/refresh`)).then((r) => r.data),
  importSubscription: (payload: { url?: string; content?: string }) =>
    axios.post<SubscriptionImportResult>(apiUrl("/subscription/import"), payload).then((r) => r.data),

  getRouting: () => axios.get<RoutingProfile>(apiUrl("/routing")).then((r) => r.data),
  saveRouting: (profile: RoutingProfile) => axios.put<RoutingProfile>(apiUrl("/routing"), profile).then((r) => r.data),
  simulateRouting: (input: SimulationInput) =>
    axios.post<SimulationResult>(apiUrl("/routing/simulate"), input).then((r) => r.data),

  listRuleSets: () => axios.get<RuleSetSpec[]>(apiUrl("/rulesets")).then((r) => r.data),
  saveRuleSet: (spec: RuleSetSpec) => axios.post<RuleSetSpec[]>(apiUrl("/rulesets"), spec).then((r) => r.data),
  syncRuleSets: (ids?: string[]) =>
    axios
      .post<{
        rule_sets: RuleSetSpec[];
        errors: Record<string, string>;
        synced_count?: number;
        reloaded?: boolean;
      }>(apiUrl("/rulesets/sync"), ids ? { ids } : {})
      .then((r) => r.data),

  getTUN: () => axios.get<TUNState>(apiUrl("/tun")).then((r) => r.data),
  setTUN: (payload: { enabled: boolean; node_id?: string; group_id?: string; stack?: string }) =>
    axios.put<{ enabled: boolean }>(apiUrl("/tun"), payload).then((r) => r.data),
  getTUNPrivilege: () => axios.get<TUNPrivilege>(apiUrl("/tun/privilege")).then((r) => r.data),
  authorizeTUN: () => axios.post<TUNPrivilege>(apiUrl("/tun/authorize")).then((r) => r.data),

  getAndroidVPNStatus: () => axios.get<AndroidVPNStatus>(apiUrl("/vpn/android/status")).then((r) => r.data),
  stopAndroidVPN: () => axios.post(apiUrl("/vpn/android/stop")).then((r) => r.data),

  getSystemProxy: () => axios.get<{ enabled: boolean; port: number }>(apiUrl("/system-proxy")).then((r) => r.data),
  setSystemProxy: (enabled: boolean) =>
    axios.put<{ enabled: boolean }>(apiUrl("/system-proxy"), { enabled }).then((r) => r.data),

  getAutostart: () => axios.get<AutostartStatus>(apiUrl("/autostart")).then((r) => r.data),
  setAutostart: (payload: { enabled: boolean; minimized?: boolean }) =>
    axios.put<AutostartStatus>(apiUrl("/autostart"), payload).then((r) => r.data),

  listListeners: () => axios.get<ListenConfig[]>(apiUrl("/listeners")).then((r) => r.data),
  addListener: (lis: Omit<ListenConfig, "id">) =>
    axios.post<ListenConfig>(apiUrl("/listeners"), lis).then((r) => r.data),
  updateListener: (id: string, lis: ListenConfig) =>
    axios.put<ListenConfig>(apiUrl(`/listeners/${id}`), lis).then((r) => r.data),
  deleteListener: (id: string) => axios.delete(apiUrl(`/listeners/${id}`)),
  applyListeners: () => axios.post<ProcessStatus>(apiUrl("/listeners/apply")).then((r) => r.data),

  checkAppUpdate: (includePrerelease = false) =>
    axios
      .get<AppUpdateCheckResult>(apiUrl("/app/update-check"), {
        params: includePrerelease ? { include_prerelease: "1" } : undefined,
      })
      .then((r) => r.data),

  getCores: () => axios.get<CoresStatus>(apiUrl("/cores")).then((r) => r.data),
  ensureCores: () => axios.post<Record<string, unknown>>(apiUrl("/cores/ensure")).then((r) => r.data),
  installCore: (payload: { core: string; version?: string; download?: boolean }) =>
    axios.post(apiUrl("/cores"), payload).then((r) => r.data),
  updateCoreAutoUpdate: (auto_update: { xray: boolean; sing_box: boolean }) =>
    axios.post(apiUrl("/cores"), { auto_update }).then((r) => r.data),

  getSettings: () => axios.get<AppSettings>(apiUrl("/settings")).then((r) => r.data),
  saveSettings: (cfg: AppSettings) =>
    axios.put<{ restart_required: boolean; saved: AppSettings }>(apiUrl("/settings"), cfg).then((r) => r.data),

  exportBackup: (include?: string[]) =>
    axios
      .get<Record<string, unknown>>(apiUrl("/backup"), {
        params: include && include.length > 0 ? { include: include.join(",") } : undefined,
      })
      .then((r) => r.data),
  restoreBackup: (backup: Record<string, unknown>) => axios.post(apiUrl("/backup"), backup).then((r) => r.data),
  mergeBackup: (bundle: Record<string, unknown>) =>
    axios
      .post<{ mode: string; nodes: number; groups: number; custom_rules: number }>(
        apiUrl("/backup?mode=merge"),
        bundle,
      )
      .then((r) => r.data),
  fetchLogsText: () => axios.get<string>(apiUrl("/logs/export"), { responseType: "text" }).then((r) => r.data),
};
