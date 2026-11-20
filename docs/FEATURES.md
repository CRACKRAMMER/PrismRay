# v1.0.0 功能与验证范围

本版本（`v1.0.0`）重构为 **sing-box 1.14+ 主数据面 + Xray-core v26+ 按需协处理器** 双核架构，统一覆盖无桌面 Web、Tauri v2 桌面端（Linux / Windows / macOS）与 Android 客户端。

## 核心功能矩阵

- **双核协同调度**：
  - `sing-box 1.14+` 作为主数据面：承担 Mixed/SOCKS/HTTP 多入站、策略分组（`selector`/`urltest`）、DNS、`.srs` 二进制规则集路由、系统 TUN、Android `tun_fd` 注入以及 Clash API 实时连接/流量接口。
  - `Xray-core v26+` 作为按需协处理器：仅在活跃节点/分组启用 `xhttp`、`httpupgrade`、`vless_encryption`、`mldsa65_verify` 或显式 `engine_pref: "xray"` 时拉起为本地认证回环 SOCKS 出口并由 `sing-box` 桥接。
  - 安装器按平台校验 SHA-256 下载并部署两套核心（含 Windows `.zip` 与 Android arm64 `.so` 提取）。
- **11 种协议与弹性订阅**：
  - 协议全集：`VLESS`（Vision / REALITY / ML-DSA-65 / VLESS Encryption）、`VMess`、`Trojan`、`Shadowsocks`（含 SS2022 与 UoT）、`Hysteria2`、`TUIC v5`、`AnyTLS`、`WireGuard`、`NaiveProxy`（缺少 libcronet 构建时安全跳过并告警）、`SOCKS5`、`HTTP/HTTPS`。
  - 格式与弹性导入：分享链接、Base64、Clash/Mihomo/Stash YAML、sing-box JSON（`outbounds` + `endpoints`）、Xray/V2Ray JSON（单份与批处理）、SIP008 JSON、WireGuard `.conf`。导入返回结构化 `skipped` 与 `warnings` 诊断，刷新保留用户别名（`user_alias`）和收藏。详见 [SUBSCRIPTIONS.md](SUBSCRIPTIONS.md)。
- **平台自适应认证与 SQLite `v100`**：
  - SQLite (`prismray.db`) 作为唯一权威存储，使用 Argon2id 与 AES-256-GCM 加密敏感凭据。
  - **无桌面 Web**：首次启动生成终端一次性初始化令牌 + 主密码 + HttpOnly 会话 Cookie + 同源保护。
  - **PC 桌面 / Android**：随应用数据目录自动初始化，使用动态回环端口与 256-bit Bearer 令牌通信，可选开启**启动密码锁**（锁定时业务 API 返回 HTTP 423）。
- **跨端系统集成**：
  - **桌面端**：原生系统托盘、系统代理设置与退出还原（Linux GNOME `gsettings` / KDE / Windows WinINET / macOS `networksetup`）、AppImage 内置核心持久落盘复用、Linux `CAP_NET_ADMIN` / `pkexec` 免密授权（授权后自动热重载 TUN）以及可选加密缓存 sudo 密码。
  - **Android**：`TauriActivity` WebView 桥（`PrismRayAndroid`）、`ProxyVpnService`、`ProxyTileService` 快捷开关磁贴、可缩放桌面小组件、原生 `BiometricPrompt` 生物识别锁、开机自启、基于文件系统 Unix Socket `SCM_RIGHTS` 的出站 FD `protect()`、白名单/黑名单/全局分应用代理、可选局域网广播/组播发现绕过（联动绕过局域网）及实时吞吐通知。
- **备份 v4 与实时脱敏日志**：
  - `GET /api/backup` 与 `POST /api/backup` 升级为 **version 4** 备份格式，涵盖节点、策略分组、入站监听器、路由与 DNS 策略、规则集、订阅元数据（不覆盖跨机端口与绝对可执行路径）。
  - 实时 WebSocket 流（`/api/traffic`、`/api/connections`、`/api/logs`）支持 ANSI 清理、分级着色与脱敏导出。

## 应用更新发布配置（桌面端 Updater）

Actions 仓库变量：`UPDATER_PUBLIC_KEY`、`UPDATER_ENDPOINT`（HTTPS）。  
Actions Secrets：`TAURI_SIGNING_PRIVATE_KEY`、可选的 `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`。  
详见 [RELEASING.md](RELEASING.md) 与官方格式 https://v2.tauri.app/plugin/updater/。

## 验证边界

自动测试套件验证：Go `-race` 与 `go vet`（含本机真实 `sing-box` 与 `xray` 二进制配置校验及 Xray 协处理器链路测试）、前端单元测试与 TypeScript 生产构建、Rust `--locked` 桌面编译、Android debug `.apk` 构建与原生 `.so` 打包，以及无桌面 Web / 桌面认证锁 / 11 协议订阅端到端集成测试。系统级路由接管（Linux TUN / Windows WinINET / macOS networksetup / Android 真机 VPN 流量转发）仍需目标真机或特权测试环境验收。
