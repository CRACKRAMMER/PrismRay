# PrismRay v1.0.0

[English](README.md) | [简体中文](README.zh-CN.md)

**PrismRay** is a cross-platform, dual-core proxy client and headless gateway built with **Go 1.26**, **React 19 + Tailwind CSS 4**, and **Tauri v2** across **Headless Web**, **Desktop (Linux / Windows / macOS)**, and **Android (VpnService + Quick Settings Tile)**.

---

## Architecture (`v1.0.0`)

```
                         ┌──────────────────────────────┐
  Web / Desktop /        │   Go Control Plane (:2178    │
  Android UI     ◄─────► │   Web, or dynamic loopback   │
  (React 19 + TS)        │   Bearer + Android IPC)      │
                         └──────────────┬───────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
┌─────────────────────────────────┐          ┌──────────────────────────────────┐
│   sing-box 1.14+ (Primary)      │          │   Xray-core v26+ (Coprocessor)   │
│  • Multi-inbound listeners      │  SOCKS5  │  • Spawned on demand only when   │
│  • TUN / Android tun_fd (rev 1) │ ◄──────► │    active node uses XHTTP,       │
│  • .srs Rule Sets + DNS Routing │  bridge  │    HTTPUpgrade, VLESS Encryption │
│  • Clash API (/traffic, conns)  │          │    or REALITY ML-DSA-65 (`pqv`)  │
└─────────────────────────────────┘          └──────────────────────────────────┘
```

### Core Capabilities

1. **Dual-Core Data Plane**:
   - **sing-box 1.14+** handles primary inbound listeners (Mixed/SOCKS/HTTP), policy groups (`selector` / `urltest`), DNS routing, `.srs` rule sets, system/gvisor TUN, Android `tun_fd` injection, and Clash API telemetry (`/traffic`, `/connections`, `/logs`).
   - **Xray-core v26+** runs on demand as an authenticated loopback SOCKS coprocessor whenever selected nodes require Xray-exclusive features (`xhttp`, `httpupgrade`, `vless_encryption`, `mldsa65_verify`, or explicit `engine_pref: "xray"`).
   - Automatic verified release installer downloads upstream binaries with SHA-256 verification (including Windows `.zip` extraction, desktop `sing-box` + `xray`, and mobile `.so` staging).
2. **11 Protocols + Resilient Multi-Format Subscriptions**:
   - **Protocols**: `VLESS` (Vision + REALITY + ML-DSA-65 + VLESS Encryption), `VMess`, `Trojan`, `Shadowsocks` (AEAD + SS2022 + UoT), `Hysteria2` (obfs + port hopping), `TUIC v5`, `AnyTLS`, `WireGuard` (endpoints), `NaiveProxy` (requires cronet-enabled build; skipped gracefully with UI warning otherwise), `SOCKS5`, and `HTTP/HTTPS`.
   - **Subscription Formats**: Share links, Base64, Clash/Mihomo/Stash YAML, sing-box JSON (`outbounds` + `endpoints`), Xray/V2Ray JSON (single & batch), Shadowsocks SIP008 JSON, and WireGuard `.conf` INI.
   - **Resilient Import & Diagnostics**: Valid nodes succeed while malformed/unsupported entries are collected into structured `skipped` & `warnings` diagnostics (`allow_insecure` warnings surfaced in UI without silently failing batches). User aliases (`user_alias`) and favorites are preserved across subscription refreshes.
3. **Platform-Adaptive Storage & Auth (`SQLite v100`)**:
   - Configuration, nodes, policy groups, multi-listeners, routing rules, rule-sets, subscriptions, and encrypted credentials live in `prismray.db` (Argon2id + AES-256-GCM data key).
   - **Headless Web**: Bootstrap token on first run + password login + HttpOnly session cookie + CSRF/Origin guard.
   - **Desktop / Android**: Auto-initialized with random loopback port + 256-bit Bearer token + parent-pipe/stdin lifecycle supervision, plus an optional Startup Password Lock toggle (`HTTP 423` while locked).
4. **Cross-Platform System Integration**:
   - **Desktop**: Native system tray icon, system proxy synchronization/restoration (`gsettings` GNOME, KDE `kwriteconfig`, Windows WinINET, macOS `networksetup`), AppImage core staging for persistent capabilities, and Linux `cap_net_admin` / `pkexec` / optional encrypted sudo TUN authorization.
   - **Android**: Kotlin `ProxyVpnService` (`VpnService`), filesystem `LocalServerSocket` `SCM_RIGHTS` FD `protect()` bridge (`libprismray.so` / `libsingbox.so` / `libxray.so`), Android Quick Settings `ProxyTileService`, resizable Home Screen VPN widget, native `BiometricPrompt` lock, Boot Autostart, Per-App proxy (`All`, `Whitelist`, `Blacklist`), and optional LAN broadcast/multicast discovery bypass (for KDE Connect / mDNS / casting).
5. **Adaptive UI**:
   - Responsive mobile bottom bar + desktop sidebar across 6 modules: Overview, Proxies & Groups, Connections, Subscriptions, Routing & DNS (including custom rule ordering, Android Per-App selector, and LAN broadcast toggle), and Settings & Logs (`System` / `Light` / `Dark` color scheme + automatic system language `zh-CN` / `en-US`, Backup v4 export/restore).

---

## Project Layout

```
PrismRay/
├── backend/                          # Go 1.26 control plane & dual-core orchestrator
│   ├── cmd/server/main.go            # Entry point (--desktop, --config, --data-dir, --web-dir)
│   └── internal/
│       ├── androidvpn/               # Android Unix SCM_RIGHTS protect() & VPN bridge
│       ├── api/                      # REST + WebSocket API server, auth, backup v4
│       ├── config/                   # 11-protocol parser, WireGuard .conf, URI export
│       ├── singbox/                  # sing-box 1.14 compiler, Clash API, .srs rulesets, installer
│       ├── storage/                  # SQLite v100 encrypted persistence + migrations
│       └── xray/                     # On-demand Xray v26 coprocessor & installer
├── frontend/                         # React 19 + Vite 7 + Tailwind CSS 4 + Tauri v2
│   ├── src/
│   │   ├── components/               # AuthGate, NodeFormModal (<dialog>), StatusToast, UI primitives
│   │   ├── lib/                      # api.ts, helpers.ts, i18n.ts, theme.ts, v1.test.ts
│   │   ├── store/appStore.ts         # Unified state + WebSocket streams + Android JS bridge
│   │   └── views/                    # Overview, Proxies, Connections, Subscriptions, Routing, SettingsLogs
│   └── src-tauri/                    # Tauri v2 desktop & mobile shell + Android Kotlin VPN/Tile
├── packaging/                        # AUR PKGBUILDs, desktop entry, systemd user unit
├── scripts/                          # Build, packaging, release & backend integration tests
└── docs/                             # Feature, headless, subscription & release documentation
```

---

## Installation & Quick Start

### macOS (`Homebrew`)

Install on Apple Silicon (`arm64`, macOS 12+) via the shared Homebrew Tap ([`CRACKRAMMER/homebrew-tap`](https://github.com/CRACKRAMMER/homebrew-tap)):

```sh
# Full edition (bundled sing-box + Xray, ready offline out of the box)
brew install --cask --no-quarantine CRACKRAMMER/tap/prismray

# Lite edition (minimal shell, downloads cores on demand; conflicts with prismray)
brew install --cask --no-quarantine CRACKRAMMER/tap/prismray-lite
```

> Open-source builds are ad-hoc signed (without Apple Developer ID notarization). If installed without `--no-quarantine`, clear the quarantine attribute before first launch: `xattr -dr com.apple.quarantine "/Applications/PrismRay.app"`.

### Arch Linux (`pacman`)

Add the unified CRACKRAMMER Arch Linux Pacman repository ([`CRACKRAMMER/arch-repo`](https://github.com/CRACKRAMMER/arch-repo), built natively inside `archlinux:base-devel`) to `/etc/pacman.conf`:

```ini
[crackrammer]
SigLevel = Optional TrustAll
Server = https://crackrammer.github.io/arch-repo/arch/$arch
```

Then install or upgrade with Pacman:

```sh
sudo pacman -Syu prismray          # Desktop client (Tauri v2 + Go sidecar)
sudo pacman -Syu prismray-server   # Optional headless Web server + systemd user unit
```

See [packaging/aur/README.md](packaging/aur/README.md) for GPG signing setup, `pacman -U` Release installs, and local `makepkg -si` recipes.

### Prebuilt Release Installers

GitHub Releases publish standalone installers directly in **Full** (bundled `sing-box` + `Xray`, works offline out of the box) and **Lite** (minimal shell, downloads cores on demand) editions:
- **Linux x64**: `-full` / `-lite` `.deb`, `.rpm`, `.AppImage`, Arch `.pkg.tar.zst`, and Headless Web `.tar.gz` (`x64` / `arm64`)
- **Windows x64**: `-full` / `-lite` `.exe` (NSIS) and `.msi` (WiX)
- **macOS ARM64**: `-full` / `-lite` `.dmg`
- **Android ARM64**: `.apk` (bundles `libprismray.so`, `libsingbox.so`, `libxray.so`, full-device TUN, and native QR scanner)

### Prerequisites (From Source)

- **Go** `1.26+`
- **Node.js** `22+` & `npm`
- **Rust** (`stable`) for Tauri desktop/mobile builds
- **Desktop Linux system deps**: `webkit2gtk-4.1`, `gtk3`, `libayatana-appindicator3`, `openssl`, `librsvg`
- **Android APK deps (optional)**: JDK 21, Android SDK (`platforms;android-36`, `build-tools;35.0.0`), NDK `29.0.14206865`, Rust target `aarch64-linux-android`

### Desktop Development

```sh
cd frontend
npm install
npm run desktop:dev
```

### Headless Web Build & Run (Linux)

```sh
python3 scripts/build_headless.py
tar -xzf artifacts/headless/prismray-headless-linux-x64.tar.gz
cd prismray-headless-linux-x64
./prismray-server
# Open http://127.0.0.1:2178 and enter the bootstrap token printed in stderr
```

> Default desktop paths: configuration (`settings.json`, `prismray.db`) lives in `~/.config/prismray/` on Linux (`%APPDATA%\prismray\` on Windows, `~/Library/Application Support/prismray/` on macOS), while downloaded cores, `.srs` rulesets, and generated runtime files live in `~/.local/share/prismray/` (`%LOCALAPPDATA%\prismray\` on Windows). Android package ID: `com.crackrammer.prismray`.

### Android APK Build (`aarch64`)

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

---

## Verification & Tests

```sh
# 1. Go unit + dual-core integration tests + go vet
go -C backend test -race ./... && go -C backend vet ./...

# 2. Frontend unit tests & TypeScript production build
npm --prefix frontend test && npm --prefix frontend run build

# 3. Tauri desktop compile check
cargo check --manifest-path frontend/src-tauri/Cargo.toml --locked

# 4. Python packaging & release tests
python3 -m unittest discover -s scripts -p 'test_*.py'

# 5. End-to-end Headless Web, Desktop & Subscription integration tests
CGO_ENABLED=0 go -C backend build -o backend/server ./cmd/server
python3 scripts/build_sidecar.py
PRISMRAY_TEST_BINARY=backend/server PRISMRAY_WEB_DIR=frontend/dist python3 scripts/test_headless_backend.py
PRISMRAY_TEST_BINARY=frontend/src-tauri/binaries/prismray-server-x86_64-unknown-linux-gnu python3 scripts/test_desktop_backend.py
PRISMRAY_TEST_BINARY=frontend/src-tauri/binaries/prismray-server-x86_64-unknown-linux-gnu python3 scripts/test_subscription_backend.py
```

---

## Documentation

- [Features & Verification Scope](docs/FEATURES.md)
- [Headless Linux / Web Deployment](docs/HEADLESS.md)
- [Subscription Compatibility Matrix](docs/SUBSCRIPTIONS.md)
- [Arch Linux / AUR Recipes](packaging/aur/README.md)
- [GitHub Actions Release Guide](docs/RELEASING.md)

## License

Licensed under [MPL-2.0](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
