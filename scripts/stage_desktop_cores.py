#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Download and stage bundled desktop sing-box + Xray binaries for Full Edition installers."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import stat
import tarfile
import urllib.request
import zipfile

ROOT_DIR = Path(__file__).resolve().parents[1]
BINARIES_DIR = ROOT_DIR / 'frontend' / 'src-tauri' / 'binaries'
CACHE_DIR = ROOT_DIR / 'backend' / 'cores' / 'desktop'
UPDATER_OVERLAY = ROOT_DIR / 'frontend' / 'src-tauri' / 'updater.generated.json'
FULL_OVERLAY = ROOT_DIR / 'frontend' / 'src-tauri' / 'full.generated.json'

DEFAULT_SINGBOX_VERSION = '1.14.4'
DEFAULT_XRAY_VERSION = '26.3.27'

TARGET_MAP = {
    'x86_64-unknown-linux-gnu': {
        'ext': '',
        'singbox_asset': lambda ver: f'sing-box-{ver}-linux-amd64.tar.gz',
        'singbox_archive': 'tar.gz',
        'xray_asset': 'Xray-linux-64.zip',
    },
    'x86_64-pc-windows-msvc': {
        'ext': '.exe',
        'singbox_asset': lambda ver: f'sing-box-{ver}-windows-amd64.zip',
        'singbox_archive': 'zip',
        'xray_asset': 'Xray-windows-64.zip',
    },
    'aarch64-apple-darwin': {
        'ext': '',
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


def download_singbox(target: str, version: str, dest: Path) -> None:
    spec = TARGET_MAP[target]
    ext = spec['ext']
    asset = spec['singbox_asset'](version)
    url = f'https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset}'
    print(f'Downloading sing-box for {target}: {url}')
    raw = download_bytes(url)
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


def download_xray(target: str, version: str, dest: Path) -> None:
    spec = TARGET_MAP[target]
    ext = spec['ext']
    asset = spec['xray_asset']
    base = f'https://github.com/XTLS/Xray-core/releases/download/v{version}'
    zip_url = f'{base}/{asset}'
    dgst_url = f'{zip_url}.dgst'
    print(f'Downloading Xray for {target}: {zip_url}')
    raw = download_bytes(zip_url)
    try:
        dgst_text = download_bytes(dgst_url).decode('utf-8', errors='replace')
        expected_sha = parse_dgst_sha256(dgst_text)
        if expected_sha:
            actual_sha = hashlib.sha256(raw).hexdigest().lower()
            if actual_sha != expected_sha:
                raise RuntimeError(f'Xray SHA-256 mismatch for {asset}: {actual_sha} != {expected_sha}')
            print(f'Verified Xray SHA-256 ({actual_sha[:12]}...)')
    except urllib.error.URLError as exc:
        print(f'Warning: could not fetch {dgst_url} ({exc}); continuing with archive extraction')

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


def stage_for_target(target: str, singbox_version: str, xray_version: str) -> None:
    if target not in TARGET_MAP:
        raise ValueError(f'Unsupported desktop target {target!r} (expected one of {sorted(TARGET_MAP)})')
    ext = TARGET_MAP[target]['ext']
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    sb_cache = CACHE_DIR / target / f'sing-box-{singbox_version}{ext}'
    if not sb_cache.is_file():
        download_singbox(target, singbox_version, sb_cache)
    sb_dest = BINARIES_DIR / f'sing-box-{target}{ext}'
    shutil.copy2(sb_cache, sb_dest)
    if not ext:
        set_exec(sb_dest)

    xr_cache = CACHE_DIR / target / f'xray-{xray_version}{ext}'
    if not xr_cache.is_file():
        download_xray(target, xray_version, xr_cache)
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
    args = parser.parse_args()
    stage_for_target(args.target, args.singbox_version, args.xray_version)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
