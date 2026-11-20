# 安装包使用说明 (PrismRay v1.0.0)

## 桌面端（Linux / Windows / macOS）

安装并打开桌面程序（或直接在 Linux 上对 `prismray-linux-x64.AppImage` 赋予执行权限后启动）后，Tauri v2 会自动拉起内置 Go 控制面（通过随机回环端口与单次会话 Bearer 密钥认证，默认无需手动输入密码；可在“设置与日志”页面按需开启启动密码锁）。

- 默认配置目录：Linux `~/.config/prismray/`、Windows `%APPDATA%\prismray\`、macOS `~/Library/Application Support/prismray/`（保存 `settings.json` 与 `prismray.db`）。
- 默认运行数据目录：Linux `~/.local/share/prismray/`、Windows `%LOCALAPPDATA%\prismray/`（保存自动下载的内核 `cores/`、`.srs` 规则集与运行态文件）。
- 首次连接可在“设置与日志 → 双核与 .srs 规则集”中点击“检查并补齐核心”，自动校验 SHA-256 并下载 **sing-box**（主数据面）与 **Xray-core**（按需协处理器）。
- 连接成功后可在概览页启用**系统代理**或 **TUN 全局接管**（Linux 支持通过 `CAP_NET_ADMIN` / `pkexec` 授权，Windows/macOS 需相应系统权限）。
- 压缩包中附带独立的 `prismray-server`；如需部署纯无桌面服务器（含编译好的 Web UI），可直接下载 Release 中的 `prismray-headless-linux-x64.tar.gz` 或 `prismray-headless-linux-arm64.tar.gz`，解压后直接运行 `./prismray-server`。

## Android 端（ARM64 APK，包名 `com.crackrammer.prismray`）

安装 APK 后即可直接使用，包内已集成 `libprismray.so`（Go 控制面）、`libsingbox.so`（主数据面）与 `libxray.so`（协处理器）。

- 在“概览”页一键启动或在系统控制中心添加 **PrismRay** 快捷开关磁贴；首次开启会弹出 Android 系统 VPN 与通知权限确认框。
- 可在“路由与 DNS → Android 分应用代理”中按全部应用 / 白名单 / 黑名单选择需要代理的应用包名。

`LICENSE` 与 `THIRD_PARTY_NOTICES.md` 随发行压缩包提供。
