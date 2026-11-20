# Security Policy

## Supported Versions

Security fixes are provided for the latest released `1.x` version of PrismRay:

| Version | Supported |
| ------- | --------- |
| `1.0.x` | Yes       |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, please report them privately via one of the following channels:
1. **GitHub Security Advisories** (preferred): Open a private vulnerability report under the repository's **Security → Advisories** tab.
2. **Email**: Contact `crackrammer@gmail.com` with `[PrismRay Security]` in the subject line.

Please include:
- Affected platform and version (Desktop Linux/Windows/macOS, Headless Web, or Android ARM64)
- Reproduction steps or proof of concept
- Expected impact and any suggested remediation

We aim to acknowledge reports within 72 hours and provide a coordinated fix timeline once reproduced.

## Security Architecture Notes

- **Credential storage**: Sensitive node credentials and subscription secrets are encrypted at rest in SQLite (`prismray.db`) using Argon2id key derivation + AES-256-GCM.
- **Control-plane authentication**:
  - Desktop & Android bind to ephemeral loopback (`127.0.0.1:0`) with a per-session 256-bit Bearer token and optional Startup Password / Biometric Lock.
  - Headless Web uses a first-run terminal bootstrap token, master password, HttpOnly session cookies, and strict Origin/CORS checks.
- **Android hardening**: `android:allowBackup="false"`, cleartext traffic limited strictly to `127.0.0.1`/`localhost`, and internal non-exported receiver isolation for home-screen widget VPN toggles.
- **TUN privilege isolation**: Linux desktop TUN uses least-privilege `cap_net_admin,cap_net_raw,cap_net_bind_service+ep` on a persistent staged `sing-box` binary rather than running the GUI as root.
