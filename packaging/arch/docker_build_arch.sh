#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Build native Arch Linux packages (prismray + prismray-server) and static Pacman repo inside archlinux:base-devel.
set -euo pipefail

STAGED_DIR="${STAGED_DIR:-/work/staged}"
OUT_DIR="${OUT_DIR:-/out}"
REPO_NAME="${REPO_NAME:-prismray}"
ARCH="${ARCH:-$(uname -m)}"
PAGES_URL="${PAGES_URL:-https://crackrammer.github.io/PrismRay}"
PKG_VERSION="${PKG_VERSION:-1.0.0}"
SOURCE_COMMIT="${SOURCE_COMMIT:-}"

echo "==> Updating Arch Linux keyring and installing build dependencies"
pacman -Sy --noconfirm archlinux-keyring
pacman -Syu --noconfirm --needed \
  base-devel \
  ca-certificates \
  gnupg \
  go \
  gtk3 \
  hicolor-icon-theme \
  libayatana-appindicator \
  librsvg \
  nodejs \
  npm \
  openssl \
  pkgconf \
  python \
  rust \
  webkit2gtk-4.1

if ! id -u builder >/dev/null 2>&1; then
  useradd -m -s /bin/bash builder
fi

BUILD_ROOT="/home/builder/build"
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"
cp -a "$STAGED_DIR/." "$BUILD_ROOT/"
chown -R builder:builder "$BUILD_ROOT"

PKG_OUT="$OUT_DIR/packages"
SITE_OUT="$OUT_DIR/site"
rm -rf "$PKG_OUT" "$SITE_OUT"
mkdir -p "$PKG_OUT" "$SITE_OUT"

for pkg in prismray prismray-server; do
  echo "==> Building Arch package: $pkg"
  su - builder -c "cd '$BUILD_ROOT/$pkg' && MAKEFLAGS='-j$(nproc)' makepkg --noconfirm"
  for built in "$BUILD_ROOT/$pkg"/*.pkg.tar.zst; do
    echo "==> Verifying package metadata: $(basename "$built")"
    pacman -Qip "$built"
    echo "==> Package file list (first 40 entries):"
    pacman -Qlp "$built" | head -n 40
    cp -f "$built" "$PKG_OUT/"
  done
done

GPG_KEY_ID=""
GPG_FPR=""
GNUPG_TMP=""
cleanup_gpg() {
  if [ -n "$GNUPG_TMP" ] && [ -d "$GNUPG_TMP" ]; then
    gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf "$GNUPG_TMP"
  fi
}
trap cleanup_gpg EXIT

if [ -n "${ARCH_GPG_PRIVATE_KEY:-}" ]; then
  echo "==> Configuring GPG signing from ARCH_GPG_PRIVATE_KEY"
  GNUPG_TMP="$(mktemp -d)"
  chmod 700 "$GNUPG_TMP"
  export GNUPGHOME="$GNUPG_TMP"
  cat > "$GNUPGHOME/gpg.conf" <<'EOF'
batch
yes
pinentry-mode loopback
EOF
  cat > "$GNUPGHOME/gpg-agent.conf" <<'EOF'
allow-loopback-pinentry
allow-preset-passphrase
default-cache-ttl 3600
max-cache-ttl 7200
EOF
  gpgconf --launch gpg-agent

  if [ -n "${ARCH_GPG_PASSPHRASE:-}" ]; then
    printf '%s\n' "$ARCH_GPG_PRIVATE_KEY" | gpg --batch --yes --passphrase-fd 3 --import 3<<<"$ARCH_GPG_PASSPHRASE"
  else
    printf '%s\n' "$ARCH_GPG_PRIVATE_KEY" | gpg --batch --yes --import
  fi

  GPG_FPR="$(gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" {print $10; exit}')"
  if [ -z "$GPG_FPR" ]; then
    echo "Error: Failed to extract secret key fingerprint from ARCH_GPG_PRIVATE_KEY" >&2
    exit 1
  fi
  GPG_KEY_ID="$GPG_FPR"

  if [ -n "${ARCH_GPG_PASSPHRASE:-}" ] && [ -x /usr/lib/gnupg/gpg-preset-passphrase ]; then
    while IFS= read -r keygrip; do
      [ -n "$keygrip" ] || continue
      printf '%s\n' "$ARCH_GPG_PASSPHRASE" | /usr/lib/gnupg/gpg-preset-passphrase --preset "$keygrip"
    done < <(gpg --list-secret-keys --with-keygrip --with-colons | awk -F: '$1 == "grp" {print $10}')
  fi

  for pkgfile in "$PKG_OUT"/*.pkg.tar.zst; do
    echo "==> Signing $(basename "$pkgfile")"
    if [ -n "${ARCH_GPG_PASSPHRASE:-}" ]; then
      gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --detach-sign --use-agent -u "$GPG_KEY_ID" "$pkgfile" 3<<<"$ARCH_GPG_PASSPHRASE"
    else
      gpg --batch --yes --pinentry-mode loopback --detach-sign --use-agent -u "$GPG_KEY_ID" "$pkgfile"
    fi
  done
else
  echo "==> ARCH_GPG_PRIVATE_KEY not configured; building unsigned HTTPS Pacman repository"
fi

echo "==> Generating static Pacman repository and GitHub Pages site"
SITE_ARGS=(
  --pkg-dir "$PKG_OUT"
  --site-dir "$SITE_OUT"
  --arch "$ARCH"
  --repo-name "$REPO_NAME"
  --pages-url "$PAGES_URL"
  --version "$PKG_VERSION"
  --commit "$SOURCE_COMMIT"
  --gpg-key-id "$GPG_KEY_ID"
  --gpg-fingerprint "$GPG_FPR"
)
if [ -n "${EXISTING_SITE_DIR:-}" ] && [ -d "$EXISTING_SITE_DIR" ]; then
  echo "==> Merging incrementally with existing Pacman site at $EXISTING_SITE_DIR"
  SITE_ARGS+=(--existing-site-dir "$EXISTING_SITE_DIR")
fi
python /src/packaging/arch/build_repo.py build-site "${SITE_ARGS[@]}"

cp -f "$SITE_OUT/arch/$ARCH/SHA256SUMS.txt" "$PKG_OUT/SHA256SUMS.txt"
if [ -f "$SITE_OUT/${REPO_NAME}.gpg" ]; then
  cp -f "$SITE_OUT/${REPO_NAME}.gpg" "$PKG_OUT/${REPO_NAME}.gpg"
fi

chmod -R a+rX "$OUT_DIR"
echo "==> Arch Pacman build complete:"
ls -lh "$PKG_OUT" "$SITE_OUT/arch/$ARCH"
