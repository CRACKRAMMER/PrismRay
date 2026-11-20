# PrismRay v1.0.0

[English](README.md) | [简体中文](README.zh-CN.md)

**PrismRay** 是一款跨平台双核代理客户端与无桌面网关，基于 **Go 1.26**、**React 19 + Tailwind CSS 4** 与 **Tauri v2** 构建，完整覆盖 **无桌面 Web 服务**、**PC 桌面端（Linux / Windows / macOS）** 以及 **Android 客户端（原生 Kotlin `VpnService` + 下拉磁贴 `TileService`）**。

---

## v1.0.0 架构设计

```
                         ┌──────────────────────────────┐
  Web / Desktop /        │   Go 控制面 (:2178 Web 或     │
  Android UI     ◄─────► │   随机回环端口 + Bearer /     │
  (React 19 + TS)        │   Android IPC 桥接)           │
                         └──────────────┬───────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
┌─────────────────────────────────┐          ┌──────────────────────────────────┐
│   sing-box 1.14+ (主数据面)      │          │   Xray-core v26+ (按需协处理器)   │
│  • 多路 Mixed/SOCKS/HTTP 入站    │  SOCKS5  │  • 仅当活跃节点使用 XHTTP、      │
│  • 系统 TUN 与 Android tun_fd    │ ◄──────► │    HTTPUpgrade、VLESS 加密或     │
│  • .srs 规则集与 DNS 分流策略     │   桥接   │    REALITY ML-DSA-65 时自动唤醒  │
│  • Clash API (/traffic, conns)  │          │    作为回环认证 SOCKS 协同出站     │
└─────────────────────────────────┘          └──────────────────────────────────┘
```

### 核心特性

1. **双核协同数据面**：
   - **sing-box 1.14+** 承担主数据面：多入站监听、策略分组（`selector` / `urltest`）、DNS 与 `.srs` 规则集路由、系统 TUN / Android VPN 数据包转发以及 Clash API 实时连接/流量统计。
   - **Xray-core v26+** 按需作为回环认证 SOCKS 协处理器按需拉起，原生支撑 `XHTTP`、`HTTPUpgrade`、`VLESS Encryption`、后量子 `REALITY ML-DSA-65` 等高级传输能力。
   - 内置上游核心下载器与 SHA-256 校验（含 Windows `.zip` 解压与多端路径适配）。
2. **11 种协议与弹性多格式订阅解析**：
   - **支持协议**：`VLESS`、`VMess`、`Trojan`、`Shadowsocks`（含 AEAD / SS2022 / UoT）、`Hysteria2`（混淆与端口跳跃）、`TUIC v5`、`AnyTLS`、`WireGuard`、`NaiveProxy`（需 `with_naive_outbound`/libcronet 构建；缺失时安全跳过并在界面提示）、`SOCKS5` 与 `HTTP/HTTPS`。
   - **订阅格式**：分享链接、Base64、Clash/Mihomo/Stash YAML、sing-box JSON（`outbounds` + `endpoints`）、Xray/V2Ray JSON 与批处理、SIP008 JSON、WireGuard `.conf`。
   - **弹性导入诊断与别名保留**：单条无效节点不会阻塞合法节点导入，跳过原因与 `allow_insecure` TLS 安全警告均通过导入诊断抽屉透明呈现；订阅刷新自动保留用户自定义备注（`user_alias`）与收藏标记。
3. **平台自适应安全与持久化（SQLite `v100`）**：
   - 所有业务配置、加密凭据、规则、订阅与核心状态统一存储于 `prismray.db`（Argon2id + AES-256-GCM）。
   - **无桌面 Web**：首次启动生成一次性初始化令牌，配合主密码登录与 HttpOnly 会话 Cookie / Origin 校验。
   - **PC / Android**：自动初始化并生成随机回环端口与 256-bit Bearer 令牌，同时支持在设置中可选开启**启动密码锁**（锁定期间 API 返回 HTTP 423）。
4. **跨端系统集成**：
   - **桌面端**：原生系统托盘、系统代理自动接管与退出还原、AppImage 内置核心自动持久落盘、Linux `CAP_NET_ADMIN` / `pkexec` 无密 TUN 授权。
   - **Android 端**：内置 `ProxyVpnService`、`ProxyTileService` 快捷开关磁贴、可缩放桌面小组件、开机自启与原生生物识别解锁；通过文件系统 Unix Socket `SCM_RIGHTS` 安全保护代理出站 FD（`libprismray.so` / `libsingbox.so` / `libxray.so`），支持全局/白名单/黑名单分应用代理及可选局域网广播/组播发现绕过（支持 KDE Connect / 投屏）。
5. **响应式跨端前端**：
   - 采用原生 `<dialog>` 顶层模态框、自定义下拉选择层、容器查询自适应连接表、默认跟随系统的浅色/深色主题与中/英文自动识别，兼顾桌面侧边栏与移动端底部安全区导航栏。

---

## 安装与快速开始

### macOS（Homebrew Tap）

在 Apple Silicon（`arm64`，macOS 12+）设备上可通过独立维护的 Homebrew Tap（[`CRACKRAMMER/homebrew-tap`](https://github.com/CRACKRAMMER/homebrew-tap)）一键安装与更新：

```sh
# Full 版（内置 sing-box + Xray，离线开箱即用）
brew install --cask --no-quarantine CRACKRAMMER/tap/prismray

# Lite 版（精简壳体，按需在线下载核心；与 Full 版互斥）
brew install --cask --no-quarantine CRACKRAMMER/tap/prismray-lite
```

> 开源发行版未购买 Apple Developer ID 公证；若未携带 `--no-quarantine` 参数，首次启动前可执行 `xattr -dr com.apple.quarantine "/Applications/PrismRay.app"` 解除 Gatekeeper 拦截。

### Arch Linux（`pacman` 统一软件源）

将原生 `archlinux:base-devel` 容器构建的统一 Pacman 静态源（[`CRACKRAMMER/arch-repo`](https://github.com/CRACKRAMMER/arch-repo)）写入 `/etc/pacman.conf`：

```ini
[crackrammer]
SigLevel = Optional TrustAll
Server = https://crackrammer.github.io/arch-repo/arch/$arch
```

随后直接使用 `pacman` 安装与更新：

```sh
sudo pacman -Syu prismray          # 桌面端客户端（Tauri v2 + 内置 Go 后端）
sudo pacman -Syu prismray-server   # 可选：无桌面 Web 服务 + systemd 用户单元
```

如需 GPG 签名校验配置、单包 `pacman -U` 或本地 `makepkg -si` 编译，见 [packaging/aur/README.md](packaging/aur/README.md)。

### 预构建安装包（GitHub Releases）

GitHub Releases 直接平铺发布各平台原生安装包，PC 端同时提供 **Full 版**（内置 `sing-box` + `Xray`，无代理环境下离线开箱即用）与 **Lite 版**（纯壳体，按需在线下载核心）：
- **Linux x64**：`-full` / `-lite` 的 `.deb`、`.rpm`、`.AppImage`、Arch `.pkg.tar.zst` 以及无桌面 Web `.tar.gz`（`x64` / `arm64`）
- **Windows x64**：`-full` / `-lite` 的 `.exe`（NSIS）与 `.msi`（WiX）
- **macOS ARM64**：`-full` / `-lite` 的 `.dmg`
- **Android ARM64**：`.apk`（内置 `libprismray.so` / `libsingbox.so` / `libxray.so`、全流量 TUN 与原生扫码）

### 运行无桌面 Web 服务

```sh
python3 scripts/build_headless.py
tar -xzf artifacts/headless/prismray-headless-linux-x64.tar.gz
cd prismray-headless-linux-x64
./prismray-server
# 浏览器打开 http://127.0.0.1:2178 并输入终端日志打印的初始化令牌
```

> 默认配置与数据路径：桌面端配置文件与 `prismray.db` 存放于 `~/.config/prismray/`（Windows：`%APPDATA%\prismray\`；macOS：`~/Library/Application Support/prismray/`），下载内核与运行状态存放于 `~/.local/share/prismray/`（Windows：`%LOCALAPPDATA%\prismray\`）。Android 包名为 `com.crackrammer.prismray`。

### 桌面端开发与打包

```sh
cd frontend && npm install
npm run desktop:dev
```

### Android APK 构建 (`arm64-v8a`)

```sh
python3 scripts/build_android_natives.py --download --abi arm64-v8a
JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
ANDROID_HOME="$HOME/Android/Sdk" \
NDK_HOME="$HOME/Android/Sdk/ndk/29.0.14206865" \
CC_aarch64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
AR_aarch64_linux_android="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar" \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android" \
npm --prefix frontend run tauri -- android build --apk --debug --target aarch64
```

### 完整验证命令

```sh
go -C backend test -race ./... && go -C backend vet ./...
npm --prefix frontend test && npm --prefix frontend run build
cargo check --manifest-path frontend/src-tauri/Cargo.toml --locked
python3 -m unittest discover -s scripts -p 'test_*.py'
```

---

## 相关文档

- [功能清单与验证边界](docs/FEATURES.md)
- [无桌面 Linux / Web 部署](docs/HEADLESS.md)
- [订阅协议与格式兼容矩阵](docs/SUBSCRIPTIONS.md)
- [Arch Linux / AUR 打包说明](packaging/aur/README.md)
- [GitHub Actions 发布流程](docs/RELEASING.md)

## 开源协议

本项目基于 [MPL-2.0](LICENSE) 协议开源。第三方许可说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
