# Changelog

All notable changes to PrismRay are documented in this file.

## [1.0.0] - 2026-11-21

Initial public open-source release of **PrismRay** (MPL-2.0).

### Highlights
- **Dual-core engine**: `sing-box 1.14+` primary data plane paired with an on-demand `Xray-core v26+` authenticated SOCKS coprocessor (VLESS XHTTP / HTTPUpgrade / VLESS Encryption / REALITY ML-DSA-65).
- **11 protocols & resilient multi-format subscriptions**: VLESS, VMess, Trojan, Shadowsocks (AEAD / SS2022 / UoT), Hysteria2, TUIC v5, AnyTLS, WireGuard, NaiveProxy, SOCKS5, and HTTP/HTTPS across share links, Base64, Clash/Mihomo/Stash YAML, sing-box JSON, Xray/V2Ray JSON, SIP008, and WireGuard `.conf`.
- **Encrypted SQLite `v100` storage & adaptive auth**: Argon2id + AES-256-GCM encrypted credentials, Headless Web bootstrap token + HttpOnly sessions, Desktop/Android ephemeral loopback Bearer auth + optional Startup Password & Biometric Lock, Backup v4 export/restore.
- **Desktop integration (Linux / Windows / macOS)**: Tauri v2 native tray with 5-state icons, system proxy management with safe self-loop sanitization, Linux `pkexec setcap` TUN authorization with automatic AppImage core staging and hot reload, Wayland/DMA-BUF GPU control, and Arch Linux Pacman repository recipes.
- **Android ARM64 native app**: Bundled `libprismray.so`, `libsingbox.so`, and `libxray.so` full-device TUN VPN with `SCM_RIGHTS` FD `protect()`, Quick Settings Tile, resizable Home Screen VPN toggle widget, Boot Autostart, native `BiometricPrompt` lock, Per-App proxy (all / whitelist / blacklist), optional LAN broadcast & multicast discovery bypass (for KDE Connect / casting / mDNS), and native camera QR scanning.
- **Cross-platform responsive UI**: Automatic system theme (`System` / `Light` / `Dark`) & system locale detection (`zh-CN` for Chinese locales, `en-US` default for all others), custom glass appearance, custom top-layer `<Select>` / `<dialog>` controls, unsaved-tab switch guard, and ANSI-cleaned live log viewer.
