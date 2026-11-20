#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Prepare complete release assets and create/update a draft GitHub prerelease."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

PLATFORMS = {
    'linux-x64': (
        '-full.deb', '-full.rpm', '-full.AppImage',
        '-lite.deb', '-lite.rpm', '-lite.AppImage',
    ),
    'windows-x64': (
        '-full.exe', '-full.msi',
        '-lite.exe', '-lite.msi',
    ),
    'macos-arm64': (
        '-full.dmg',
        '-lite.dmg',
    ),
    'headless-linux-x64': ('.tar.gz',),
    'headless-linux-arm64': ('.tar.gz',),
    'android-arm64': ('.apk',),
}


def validate_version(root, tag):
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', tag):
        raise ValueError('Expected a vMAJOR.MINOR.PATCH[-prerelease] tag')
    expected = tag[1:]
    paths = ['frontend/package.json', 'frontend/src-tauri/tauri.conf.json']
    for path in paths:
        if json.loads((root / path).read_text())['version'] != expected:
            raise ValueError(f'{path} version does not match {tag}')
    lock = json.loads((root / 'frontend/package-lock.json').read_text())
    if lock['version'] != expected or lock['packages']['']['version'] != expected:
        raise ValueError('npm lockfile version does not match tag')
    cargo = (root / 'frontend/src-tauri/Cargo.toml').read_text().split('[package]', 1)[1].split('\n[', 1)[0]
    match = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)
    if not match or match[1] != expected:
        raise ValueError('Cargo package version does not match tag')


def collect(downloads, output, sha):
    selected = []
    # A rerun of only the release job can reuse earlier successful jobs in this run.
    for platform, suffixes in PLATFORMS.items():
        pattern = re.compile(rf'prismray-{re.escape(platform)}-{re.escape(sha)}-(\d+)')
        candidates = [(int(m[1]), p) for p in downloads.iterdir() if p.is_dir() and (m := pattern.fullmatch(p.name))]
        if not candidates:
            raise ValueError(f'Missing artifact for {platform}')
        folder = max(candidates, key=lambda item: item[0])[1]
        for suffix in suffixes:
            asset = folder / f'prismray-{platform}{suffix}'
            if not asset.is_file() or asset.is_symlink() or asset.stat().st_size == 0:
                raise ValueError(f'Missing or invalid package: {asset}')
            selected.append(asset)
    output.mkdir(parents=True, exist_ok=True)
    result = []
    for asset in selected:
        dest = output / asset.name
        shutil.copyfile(asset, dest)
        if dest.suffix == '.AppImage':
            dest.chmod(0o755)
        result.append(dest)
    checksum = output / 'SHA256SUMS.txt'
    lines = []
    for asset in result:
        digest = hashlib.sha256()
        with asset.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        lines.append(f'{digest.hexdigest()}  {asset.name}\n')
    checksum.write_text(''.join(lines))
    return result + [checksum]


def main():
    root = Path(__file__).resolve().parents[1]
    tag, sha = os.environ['GITHUB_REF_NAME'], os.environ['GITHUB_SHA']
    validate_version(root, tag)
    if os.environ.get('RELEASE_VALIDATE_ONLY') == '1':
        return
    repo = os.environ['GITHUB_REPOSITORY']
    downloaded, output = root / 'release-downloads', root / 'release-assets'
    subprocess.run(['gh', 'run', 'download', os.environ['GITHUB_RUN_ID'], '--repo', repo,
                    '--pattern', f'prismray-*-{sha}-*', '--dir', str(downloaded)], check=True)
    assets = collect(downloaded, output, sha)
    notes = output / 'RELEASE_NOTES.md'
    notes.write_text(
        f'''PrismRay {tag}\n\n'''
        f'''Source commit: {sha}\n\n'''
        '''Packages: Desktop Full (bundled sing-box + Xray, offline ready) & Lite (shell only) across Linux x64 (.deb / .rpm / .AppImage), Windows x64 (.exe / .msi), macOS ARM64 (.dmg); Linux Headless Web (x64 & ARM64 .tar.gz); Android ARM64 (.apk with embedded sing-box + Xray + full TUN).\n'''
        '''Dual-Core runtime: sing-box (primary data plane, TUN & Clash API) + Xray-core (on-demand XHTTP / VLESS Encryption / REALITY ML-DSA-65 coprocessor).\n\n'''
        '''Desktop & Web bundles embed the Go backend; external sing-box / Xray binaries can be ensured from the UI. Android APKs bundle libprismray.so, libsingbox.so, and libxray.so directly.\n\n'''
        '''Known validation limits:\n'''
        '''- System proxy restoration and privileged TUN require platform-specific hardware testing.\n'''
        '''- Windows installers are unsigned; macOS uses ad-hoc signing without notarization; CI debug APKs use Android debug signing.\n'''
        '''- In-app updates require a separately configured HTTPS manifest and signing key.\n\n'''
        '''Verify downloads against SHA256SUMS.txt before publishing.\n'''
    )
    existing = subprocess.run(['gh', 'release', 'view', tag, '--repo', repo, '--json', 'isDraft'], capture_output=True, text=True)
    if existing.returncode == 0:
        if not json.loads(existing.stdout)['isDraft']:
            raise RuntimeError('Refusing to modify an already published release')
        subprocess.run(['gh', 'release', 'edit', tag, '--repo', repo, '--draft', '--prerelease',
                        '--title', f'PrismRay {tag}', '--notes-file', str(notes)], check=True)
        subprocess.run(['gh', 'release', 'upload', tag, '--repo', repo, '--clobber', *map(str, assets)], check=True)
    else:
        subprocess.run(['gh', 'release', 'create', tag, '--repo', repo, '--verify-tag', '--draft',
                        '--prerelease', '--title', f'PrismRay {tag}', '--notes-file', str(notes),
                        *map(str, assets)], check=True)


if __name__ == '__main__':
    main()
