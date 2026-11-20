#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Generate or update Homebrew Cask manifests for CRACKRAMMER/homebrew-tap."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


DEFAULT_REPO = 'CRACKRAMMER/PrismRay'
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def normalize_version(raw: str) -> str:
    cleaned = raw.strip().lstrip('v')
    if not re.fullmatch(r'[0-9A-Za-z._+-]+', cleaned):
        raise ValueError(f'Invalid release version: {raw!r}')
    return cleaned


def parse_checksums_file(path: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        digest = parts[0].strip().lower()
        name = parts[1].strip().lstrip('*')
        if SHA256_RE.fullmatch(digest):
            mapping[Path(name).name] = digest
    return mapping


def render_cask(
    *,
    token: str,
    version: str,
    sha256: str,
    asset_name: str,
    conflict_token: str,
    desc: str,
    repo: str = DEFAULT_REPO,
) -> str:
    ver = normalize_version(version)
    digest = sha256.strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError(f'Invalid SHA-256 for {token}: {sha256!r}')

    tap_slug = f'{repo.split("/", 1)[0]}/tap' if '/' in repo else 'CRACKRAMMER/tap'
    return f'''cask "{token}" do
  version "{ver}"
  sha256 "{digest}"

  url "https://github.com/{repo}/releases/download/v#{{version}}/{asset_name}"
  name "PrismRay"
  desc "{desc}"
  homepage "https://github.com/{repo}"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: ">= :monterey"
  conflicts_with cask: "{conflict_token}"

  app "PrismRay.app"

  zap trash: [
    "~/Library/Application Support/prismray",
    "~/Library/Caches/com.crackrammer.prismray",
    "~/Library/Preferences/com.crackrammer.prismray.plist",
    "~/Library/Saved Application State/com.crackrammer.prismray.savedState",
    "~/Library/WebKit/com.crackrammer.prismray",
  ]

  caveats <<~EOS
    PrismRay is an open-source release without Apple Developer ID notarization.
    If macOS Gatekeeper blocks the first launch, run:
      xattr -dr com.apple.quarantine "/Applications/PrismRay.app"
    Or install directly with:
      brew install --cask --no-quarantine {tap_slug}/{token}
  EOS
end
'''


def update_tap_casks(
    *,
    tap_dir: Path,
    version: str,
    sha256_full: str = '',
    sha256_lite: str = '',
    repo: str = DEFAULT_REPO,
) -> list[Path]:
    casks_dir = tap_dir / 'Casks'
    casks_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if sha256_full:
        full_path = casks_dir / 'prismray.rb'
        full_path.write_text(
            render_cask(
                token='prismray',
                version=version,
                sha256=sha256_full,
                asset_name='prismray-macos-arm64-full.dmg',
                conflict_token='prismray-lite',
                desc='Cross-platform dual-core proxy client (Full edition with bundled sing-box & Xray)',
                repo=repo,
            ),
            encoding='utf-8',
        )
        written.append(full_path)

    if sha256_lite:
        lite_path = casks_dir / 'prismray-lite.rb'
        lite_path.write_text(
            render_cask(
                token='prismray-lite',
                version=version,
                sha256=sha256_lite,
                asset_name='prismray-macos-arm64-lite.dmg',
                conflict_token='prismray',
                desc='Cross-platform dual-core proxy client (Lite edition, downloads cores on demand)',
                repo=repo,
            ),
            encoding='utf-8',
        )
        written.append(lite_path)

    if not written:
        raise ValueError('No macOS DMG SHA-256 provided; nothing to write')
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tap-dir', type=Path, required=True, help='Root directory of homebrew-tap checkout')
    parser.add_argument('--version', required=True, help='Release version (e.g. 1.0.0 or v1.0.0)')
    parser.add_argument('--repo', default=DEFAULT_REPO, help='GitHub owner/repo hosting release DMGs')
    parser.add_argument('--checksums', type=Path, default=None, help='Path to SHA256SUMS.txt containing macOS DMGs')
    parser.add_argument('--sha256-full', default='', help='Explicit SHA-256 for prismray-macos-arm64-full.dmg')
    parser.add_argument('--sha256-lite', default='', help='Explicit SHA-256 for prismray-macos-arm64-lite.dmg')
    args = parser.parse_args(argv)

    sha_full = args.sha256_full.strip()
    sha_lite = args.sha256_lite.strip()
    if args.checksums is not None:
        sums = parse_checksums_file(args.checksums)
        sha_full = sha_full or sums.get('prismray-macos-arm64-full.dmg', '')
        sha_lite = sha_lite or sums.get('prismray-macos-arm64-lite.dmg', '')

    written = update_tap_casks(
        tap_dir=args.tap_dir,
        version=args.version,
        sha256_full=sha_full,
        sha256_lite=sha_lite,
        repo=args.repo,
    )
    for path in written:
        print(path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
