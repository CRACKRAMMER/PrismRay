# Arch Linux / Pacman Repository & PKGBUILDs (v1.0.0)

PrismRay provides **two ways** to install on Arch Linux / CachyOS / EndeavourOS:

1. **Self-Hosted Static Pacman Repository (Recommended, prebuilt natively on Arch Linux)**
2. **Local `makepkg` VCS builds (`packaging/aur/prismray-git` and `packaging/aur/prismray-server-git`)**

---

## 1. Self-Hosted Pacman Repository (`CRACKRAMMER/arch-repo`)

GitHub Actions (`.github/workflows/arch-repo.yml`) builds native Arch Linux `x86_64` packages inside `archlinux:base-devel` for both `prismray` (Desktop) and `prismray-server` (Headless Web), incrementally merges them into the shared multi-project static repository (`CRACKRAMMER/arch-repo`), and serves them via GitHub Pages at:

`https://crackrammer.github.io/arch-repo/`

### Add the Repository to `/etc/pacman.conf`

```ini
[crackrammer]
SigLevel = Optional TrustAll
Server = https://crackrammer.github.io/arch-repo/arch/$arch
```

> If the repository is GPG-signed (see [GPG Signing](#gpg-signing-maintainer-optional-upgrade) below), check `https://crackrammer.github.io/arch-repo/` for the published `crackrammer.gpg` key and switch `SigLevel` to `Required DatabaseOptional`.
>
> **Forks without `ARCH_REPO_TOKEN`**: the workflow automatically falls back to publishing a standalone `[prismray]` repository on the fork's own `gh-pages` branch (`https://<owner>.github.io/<repo>/arch/$arch`).

### Install or Upgrade

```sh
# Desktop client (Tauri v2 + embedded Go sidecar)
sudo pacman -Syu prismray

# Headless Web server + systemd user unit (optional, can coexist with prismray)
sudo pacman -Syu prismray-server
```

To enable the optional headless user service:

```sh
systemctl --user enable --now prismray-server.service
```

### Single-Package Offline Install (`pacman -U`)

You can also download `prismray-<ver>-1-x86_64.pkg.tar.zst` or `prismray-server-<ver>-1-x86_64.pkg.tar.zst` directly from **GitHub Releases** and install with:

```sh
sudo pacman -U prismray-1.0.0-1-x86_64.pkg.tar.zst
```

### GPG Signing (Maintainer Optional Upgrade)

`.github/workflows/arch-repo.yml` supports progressive GPG signing without blocking unsigned HTTPS releases:

- **Default (no secrets configured)**: builds an unsigned Pacman repository over HTTPS (`SigLevel = Optional TrustAll`).
- **Signed mode**: add the following GitHub Actions repository secrets:
  - `ARCH_GPG_PRIVATE_KEY`: ASCII-armored GPG private key (`gpg --armor --export-secret-keys <KEYID>`)
  - `ARCH_GPG_PASSPHRASE` *(optional)*: passphrase if the signing key is protected
- When `ARCH_GPG_PRIVATE_KEY` is present, CI automatically signs every `.pkg.tar.zst` and `crackrammer.db.tar.gz` (or `prismray.db.tar.gz` in fork fallback mode), exports `https://crackrammer.github.io/arch-repo/crackrammer.gpg`, and switches the landing page instructions to `SigLevel = Required DatabaseOptional` + `pacman-key --add` / `--lsign-key`.

---

## 2. Local Source Build (`makepkg`)

`packaging/aur/prismray-git/PKGBUILD` and `packaging/aur/prismray-server-git/PKGBUILD` are VCS recipes that build directly from `main`. Both desktop executables live under `/usr/lib/prismray` with `/usr/bin/prismray` as a symlink. No root service, autostart, or system proxy change is installed by default. `sing-box` and `xray` remain optional external cores; PrismRay can download and verify both automatically.

On Arch Linux with `base-devel` installed:

```sh
cd packaging/aur/prismray-git
makepkg -si
```

For the headless server without Rust/GTK/WebKit dependencies:

```sh
cd packaging/aur/prismray-server-git
makepkg -si
```

Regenerate `.SRCINFO` after modifying either `PKGBUILD`:

```sh
makepkg --printsrcinfo > .SRCINFO
```

Recipe fields follow the [Arch PKGBUILD manual](https://man.archlinux.org/man/PKGBUILD.5.en). See [headless deployment](../../docs/HEADLESS.md) for server configuration details.
