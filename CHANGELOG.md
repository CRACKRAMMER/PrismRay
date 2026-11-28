# Changelog

All notable changes to PrismRay are documented in this file.

## [1.1.0] - 2026-11-28

### Highlights
- **Unified `sing-box` wrapper & privileged TUN hardening**: Built-in `with_tailscale` unified `sing-box` core with `PRISMRAY_TAILSCALE_STATUS_TOKEN` instance matching, atomic `0o600` status/state ownership handoff under `sudo` TUN (`chownFileFD`, symlink-safe `os.Lstat`/`os.Lchown`, `cache.db` ownership transfer), bounded `SIGKILL` reaper wait, and Linux IPv4/IPv6 stale table `2178` route cleanup.
- **Host Tailscale coexistence, IPv6 control & WebRTC leak prevention**: Automatic host external Tailscale detection (`system-tailscale-direct` interface binding & MagicDNS `100.100.100.100:53`), default-on **Disable IPv6** switch (`AAAA`/`HTTPS` preemption and `2000::/3 -> reject` before `Global`), DoH/DoT bootstrap resolver, cloud IMDS metadata host rejection, WebRTC leak hardening (STUN/TURN TCP+UDP rules, `tailscaled` UDP `3478` exemption, LoadBalance shard alignment, and non-TUN warning banner), plus LoadBalance shard circuit-breaker & affinity fixes.
- **Security, auth & cross-platform reliability**: Argon2id `recordGen` re-check eliminating unlock-vs-lockout/disable races, keyring delete rollback, deterministic subscription content-hash node IDs migrating `DetourID` & SQLite group memberships, SSRF `0.0.0.0/8`/`fc00::/7`/FakeIP hardening, compiled-config WS header redaction & Xray bridge injection, Windows DPAPI `.device.key`, macOS Touch ID ObjC `BOOL` ABI & timeout fixes, and Android `ProxyVpnService` generation guards + strict HTTPS/SHA-256 in-app updater verification.
- **New capabilities**: One-click connection-to-routing rule creation, batch node cleanup/dedupe/clone/export (`PATCH /api/nodes/batch`), 13 built-in `.srs` rule-set catalog entries, Tailscale subnet route & Exit Node advertising + Taildrop send, live per-connection throughput + recently-closed ring buffer, kernel log level selector with dynamic `DEBUG` filter, and multi-profile switcher with QR share/import.
- **PC Desktop UI modernization & packaging/CI**: Linear/Raycast Light & Dark contrast tokens, balanced 3+2 Overview control grid, strict 2-color SVG-gradient throughput charts, native top-layer `<ModalDialog>` discrete transitions, accessible `<Checkbox>` & `<Slider>`, standardized thin scrollbars, anchored drawer multi-select popovers, Arch `/usr/lib/prismray-server/sing-box` alignment, pinned CI actions, and Windows post-`signtool` Tauri `.sig` re-signing.

## [1.0.1] - 2026-11-21

- Policy group upgrades, DNS/TUN routing fixes, Android UX refinements, and multi-select filter tabs.

## [1.0.0] - 2026-11-21

Initial public open-source release of **PrismRay** (MPL-2.0).

### Highlights
- **Dual-core engine**: `sing-box 1.14+` primary data plane paired with an on-demand `Xray-core v26+` authenticated SOCKS coprocessor (VLESS XHTTP / HTTPUpgrade / VLESS Encryption / REALITY ML-DSA-65).
- **11 protocols & resilient multi-format subscriptions**: VLESS, VMess, Trojan, Shadowsocks (AEAD / SS2022 / UoT), Hysteria2, TUIC v5, AnyTLS, WireGuard, NaiveProxy, SOCKS5, and HTTP/HTTPS across share links, Base64, Clash/Mihomo/Stash YAML, sing-box JSON, Xray/V2Ray JSON, SIP008, and WireGuard `.conf`.
- **Encrypted SQLite `v100` storage & adaptive auth**: Argon2id + AES-256-GCM encrypted credentials, Headless Web bootstrap token + HttpOnly sessions, Desktop/Android ephemeral loopback Bearer auth + optional Startup Password & Biometric Lock, Backup v4 export/restore.
- **Desktop integration (Linux / Windows / macOS)**: Tauri v2 native tray with 5-state icons, system proxy management with safe self-loop sanitization, Linux `pkexec setcap` TUN authorization with automatic AppImage core staging and hot reload, Wayland/DMA-BUF GPU control, and Arch Linux Pacman repository recipes.
- **Android ARM64 native app**: Bundled `libprismray.so`, `libsingbox.so`, and `libxray.so` full-device TUN VPN with `SCM_RIGHTS` FD `protect()`, Quick Settings Tile, resizable Home Screen VPN toggle widget, Boot Autostart, native `BiometricPrompt` lock, Per-App proxy (all / whitelist / blacklist), optional LAN broadcast & multicast discovery bypass (for KDE Connect / casting / mDNS), and native camera QR scanning.
- **Cross-platform responsive UI**: Automatic system theme (`System` / `Light` / `Dark`) & system locale detection (`zh-CN` for Chinese locales, `en-US` default for all others), custom glass appearance, custom top-layer `<Select>` / `<dialog>` controls, unsaved-tab switch guard, and ANSI-cleaned live log viewer.
