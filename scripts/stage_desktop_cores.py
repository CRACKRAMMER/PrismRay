#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Download and stage bundled desktop sing-box + Xray binaries for Full Edition installers."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile

ROOT_DIR = Path(__file__).resolve().parents[1]
SINGBOX_CORE_DIR = ROOT_DIR / 'backend' / 'singbox-android'
BINARIES_DIR = ROOT_DIR / 'frontend' / 'src-tauri' / 'binaries'
CACHE_DIR = ROOT_DIR / 'backend' / 'cores' / 'desktop'
UPDATER_OVERLAY = ROOT_DIR / 'frontend' / 'src-tauri' / 'updater.generated.json'
FULL_OVERLAY = ROOT_DIR / 'frontend' / 'src-tauri' / 'full.generated.json'

DEFAULT_SINGBOX_VERSION = '1.14.4'
DEFAULT_XRAY_VERSION = '26.3.27'
SINGBOX_DESKTOP_TAGS = 'with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_tailscale'

TARGET_MAP = {
    'x86_64-unknown-linux-gnu': {
        'ext': '',
        'goos': 'linux',
        'goarch': 'amd64',
        'singbox_asset': lambda ver: f'sing-box-{ver}-linux-amd64.tar.gz',
        'singbox_archive': 'tar.gz',
        'xray_asset': 'Xray-linux-64.zip',
    },
    'x86_64-pc-windows-msvc': {
        'ext': '.exe',
        'goos': 'windows',
        'goarch': 'amd64',
        'singbox_asset': lambda ver: f'sing-box-{ver}-windows-amd64.zip',
        'singbox_archive': 'zip',
        'xray_asset': 'Xray-windows-64.zip',
    },
    'aarch64-apple-darwin': {
        'ext': '',
        'goos': 'darwin',
        'goarch': 'arm64',
        'singbox_asset': lambda ver: f'sing-box-{ver}-darwin-arm64.tar.gz',
        'singbox_archive': 'tar.gz',
        'xray_asset': 'Xray-macos-arm64-v8a.zip',
    },
}


def set_exec(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def download_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'PrismRay-Desktop-Builder/1.0'})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read()


def parse_dgst_sha256(text: str) -> str | None:
    match = re.search(r'SHA2-256\s*=\s*([0-9a-fA-F]{64})', text)
    if match:
        return match.group(1).lower()
    match = re.search(r'SHA256\s*[=:]\s*([0-9a-fA-F]{64})', text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def fetch_github_asset_sha256(repo: str, tag: str, asset_name: str) -> str | None:
    api_url = f'https://api.github.com/repos/{repo}/releases/tags/{tag}'
    req = urllib.request.Request(
        api_url,
        headers={
            'User-Agent': 'PrismRay-Desktop-Builder/1.0',
            'Accept': 'application/vnd.github+json',
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        meta = json.loads(resp.read().decode('utf-8', errors='replace'))
    for asset in meta.get('assets', []):
        if asset.get('name') == asset_name:
            digest = str(asset.get('digest') or '').strip().lower()
            if digest.startswith('sha256:'):
                digest = digest[len('sha256:') :]
            if re.fullmatch(r'[0-9a-f]{64}', digest):
                return digest
    return None


def verify_sha256(raw: bytes, expected_sha: str | None, label: str, allow_unverified: bool = False) -> None:
    actual_sha = hashlib.sha256(raw).hexdigest().lower()
    if expected_sha:
        if actual_sha != expected_sha.lower():
            raise RuntimeError(f'SHA-256 mismatch for {label}: {actual_sha} != {expected_sha}')
        print(f'Verified {label} SHA-256 ({actual_sha[:12]}...)')
        return
    if not allow_unverified:
        raise RuntimeError(
            f'Refusing to stage unverified artifact {label} (missing upstream SHA-256 digest; pass --allow-unverified to override)'
        )
    print(f'Warning: staging {label} without upstream SHA-256 (--allow-unverified)')


def build_desktop_singbox_wrapper(target: str, dest: Path) -> None:
    spec = TARGET_MAP[target]
    ext = spec['ext']
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['CGO_ENABLED'] = '0'
    env['GOOS'] = spec['goos']
    env['GOARCH'] = spec['goarch']
    cmd = [
        'go',
        '-C',
        str(SINGBOX_CORE_DIR),
        'build',
        '-trimpath',
        '-tags',
        SINGBOX_DESKTOP_TAGS,
        '-ldflags=-s -w',
        '-o',
        str(dest),
        '.',
    ]
    print(f'Building PrismRay unified sing-box wrapper for {target} -> {dest}')
    subprocess.run(cmd, env=env, check=True)
    if not ext:
        set_exec(dest)


def download_singbox(target: str, version: str, dest: Path, allow_unverified: bool = False) -> None:
    spec = TARGET_MAP[target]
    ext = spec['ext']
    asset = spec['singbox_asset'](version)
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset}'
    print(f'Downloading sing-box for {target}: {url}')
    raw = download_bytes(url)
    expected_sha = None
    try:
        expected_sha = fetch_github_asset_sha256('SagerNet/sing-box', f'v{version}', asset)
    except urllib.error.URLError as exc:
        if not allow_unverified:
            raise RuntimeError(f'Failed to fetch sing-box SHA-256 digest for {asset}: {exc}') from exc
    verify_sha256(raw, expected_sha, asset, allow_unverified=allow_unverified)
    want_name = f'sing-box{ext}'
    if spec['singbox_archive'] == 'tar.gz':
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tf:
            for member in tf.getmembers():
                if member.isfile() and Path(member.name).name == want_name:
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(extracted.read())
                    if not ext:
                        set_exec(dest)
                    return
    else:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for name in zf.namelist():
                if not name.endswith('/') and Path(name).name == want_name:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(zf.read(name))
                    if not ext:
                        set_exec(dest)
                    return
    raise RuntimeError(f'{want_name} not found in archive {asset}')


def download_xray(target: str, version: str, dest: Path, allow_unverified: bool = False) -> None:
    spec = TARGET_MAP[target]
    ext = spec['ext']
    asset = spec['xray_asset']
    base = f'https://github.com/XTLS/Xray-core/releases/download/v{version}'
    zip_url = f'{base}/{asset}'
    dgst_url = f'{zip_url}.dgst'
    print(f'Downloading Xray for {target}: {zip_url}')
    raw = download_bytes(zip_url)
    expected_sha = None
    try:
        dgst_text = download_bytes(dgst_url).decode('utf-8', errors='replace')
        expected_sha = parse_dgst_sha256(dgst_text)
    except urllib.error.URLError as exc:
        try:
            expected_sha = fetch_github_asset_sha256('XTLS/Xray-core', f'v{version}', asset)
        except urllib.error.URLError:
            if not allow_unverified:
                raise RuntimeError(f'Failed to fetch Xray SHA-256 digest ({dgst_url}): {exc}') from exc
    verify_sha256(raw, expected_sha, asset, allow_unverified=allow_unverified)

    want_name = f'xray{ext}'
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            if not name.endswith('/') and Path(name).name == want_name:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
                if not ext:
                    set_exec(dest)
                return
    raise RuntimeError(f'{want_name} not found in archive {asset}')


def write_full_overlay(updater_overlay: Path = UPDATER_OVERLAY, out_path: Path = FULL_OVERLAY) -> Path:
    cfg: dict = {}
    if updater_overlay.is_file():
        loaded = json.loads(updater_overlay.read_text(encoding='utf-8'))
        if isinstance(loaded, dict):
            cfg = loaded
    bundle = cfg.get('bundle')
    if not isinstance(bundle, dict):
        bundle = {}
    bundle['externalBin'] = [
        'binaries/prismray-server',
        'binaries/sing-box',
        'binaries/xray',
    ]
    cfg['bundle'] = bundle
    out_path.write_text(json.dumps(cfg, indent=2) + '\n', encoding='utf-8')
    return out_path


def stage_for_target(
    target: str,
    singbox_version: str,
    xray_version: str,
    use_upstream_singbox: bool = False,
    allow_unverified: bool = False,
) -> None:
    if target not in TARGET_MAP:
        raise ValueError(f'Unsupported desktop target {target!r} (expected one of {sorted(TARGET_MAP)})')
    ext = TARGET_MAP[target]['ext']
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    sb_dest = BINARIES_DIR / f'sing-box-{target}{ext}'
    if not use_upstream_singbox and (SINGBOX_CORE_DIR / 'go.mod').is_file():
        build_desktop_singbox_wrapper(target, sb_dest)
    else:
        sb_cache = CACHE_DIR / target / f'sing-box-{singbox_version}{ext}'
        if not sb_cache.is_file():
            download_singbox(target, singbox_version, sb_cache, allow_unverified=allow_unverified)
        shutil.copy2(sb_cache, sb_dest)
        if not ext:
            set_exec(sb_dest)

    xr_cache = CACHE_DIR / target / f'xray-{xray_version}{ext}'
    if not xr_cache.is_file():
        download_xray(target, xray_version, xr_cache, allow_unverified=allow_unverified)
    xr_dest = BINARIES_DIR / f'xray-{target}{ext}'
    shutil.copy2(xr_cache, xr_dest)
    if not ext:
        set_exec(xr_dest)

    overlay = write_full_overlay()
    print(f'Staged desktop cores -> {sb_dest.name}, {xr_dest.name} + overlay {overlay.name}')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=sorted(TARGET_MAP))
    parser.add_argument('--singbox-version', default=DEFAULT_SINGBOX_VERSION)
    parser.add_argument('--xray-version', default=DEFAULT_XRAY_VERSION)
    parser.add_argument('--upstream-singbox', action='store_true', help='Download upstream sing-box instead of building PrismRay unified wrapper')
    parser.add_argument('--allow-unverified', action='store_true', help='Allow downloads without upstream SHA-256 verification')
    args = parser.parse_args()
    stage_for_target(
        args.target,
        args.singbox_version,
        args.xray_version,
        use_upstream_singbox=args.upstream_singbox,
        allow_unverified=args.allow_unverified,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
