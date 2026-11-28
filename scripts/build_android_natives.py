#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Stage native Android ELF binaries (libprismray.so, libsingbox.so, libxray.so, libhev-socks5-tunnel.so) into jniLibs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
SINGBOX_ANDROID_DIR = BACKEND_DIR / "singbox-android"
JNI_LIBS_DIR = ROOT_DIR / "frontend" / "src-tauri" / "gen" / "android" / "app" / "src" / "main" / "jniLibs"
ANDROID_CORES_DIR = BACKEND_DIR / "cores" / "android"

DEFAULT_SINGBOX_VERSION = "1.14.4"
DEFAULT_XRAY_VERSION = "26.3.27"
DEFAULT_HEVTUN_VERSION = "2.20.0"
# Omit unused with_acme and with_dhcp to trim Android binary footprint while preserving
# full protocol, uTLS, WireGuard, QUIC, Clash API, and Tailscale capabilities.
SINGBOX_ANDROID_TAGS = "with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_tailscale"

ABI_MAP = {
    "arm64-v8a": {
        "goarch": "arm64",
        "singbox_asset": lambda ver: f"sing-box-{ver}-android-arm64.tar.gz",
        "xray_asset": "Xray-android-arm64-v8a.zip",
        "hevtun_jni_member": "jni/arm64-v8a/libhev-socks5-tunnel.so",
    },
    "x86_64": {
        "goarch": "amd64",
        "singbox_asset": lambda ver: f"sing-box-{ver}-android-amd64.tar.gz",
        "xray_asset": "Xray-android-amd64.zip",
        "hevtun_jni_member": "jni/x86_64/libhev-socks5-tunnel.so",
    },
}


def verify_elf(path: Path) -> None:
    data = path.read_bytes()[:4]
    if data != b"\x7fELF":
        raise RuntimeError(f"Expected ELF binary at {path}, got header {data!r}")


def set_exec(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def download_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "PrismRay-Android-Builder/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def parse_dgst_sha256(text: str) -> str | None:
    match = re.search(r"SHA2-256\s*=\s*([0-9a-fA-F]{64})", text)
    if match:
        return match.group(1).lower()
    match = re.search(r"SHA256\s*[=:]\s*([0-9a-fA-F]{64})", text, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return None


def fetch_github_asset_sha256(repo: str, tag: str, asset_name: str) -> str | None:
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    req = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "PrismRay-Android-Builder/1.0",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        meta = json.loads(resp.read().decode("utf-8", errors="replace"))
    for asset in meta.get("assets", []):
        if asset.get("name") == asset_name:
            digest = str(asset.get("digest") or "").strip().lower()
            if digest.startswith("sha256:"):
                digest = digest[len("sha256:") :]
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                return digest
    return None


def verify_sha256(raw: bytes, expected_sha: str | None, label: str, allow_unverified: bool = False) -> None:
    actual_sha = hashlib.sha256(raw).hexdigest().lower()
    if expected_sha:
        if actual_sha != expected_sha.lower():
            raise RuntimeError(f"SHA-256 mismatch for {label}: {actual_sha} != {expected_sha}")
        print(f"Verified {label} SHA-256 ({actual_sha[:12]}...)")
        return
    if not allow_unverified:
        raise RuntimeError(
            f"Refusing to install unverified artifact {label} (missing upstream SHA-256 digest; pass --allow-unverified to override)"
        )
    print(f"Warning: {label} installed without upstream SHA-256 digest (--allow-unverified)")


def download_singbox(abi: str, version: str, dest: Path, allow_unverified: bool = False) -> None:
    asset = ABI_MAP[abi]["singbox_asset"](version)
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/{asset}"
    print(f"Downloading sing-box for {abi}: {url}")
    raw = download_bytes(url)
    expected_sha = None
    try:
        expected_sha = fetch_github_asset_sha256("SagerNet/sing-box", f"v{version}", asset)
    except urllib.error.URLError as exc:
        if not allow_unverified:
            raise RuntimeError(f"Failed to fetch sing-box release SHA-256 for {asset}: {exc}") from exc
    verify_sha256(raw, expected_sha, asset, allow_unverified=allow_unverified)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isfile() and Path(member.name).name == "sing-box":
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(extracted.read())
                verify_elf(dest)
                set_exec(dest)
                return
    raise RuntimeError(f"sing-box binary not found in archive {asset}")


def download_xray(abi: str, version: str, dest: Path, allow_unverified: bool = False) -> None:
    asset = ABI_MAP[abi]["xray_asset"]
    base = f"https://github.com/XTLS/Xray-core/releases/download/v{version}"
    zip_url = f"{base}/{asset}"
    dgst_url = f"{zip_url}.dgst"
    print(f"Downloading Xray for {abi}: {zip_url}")
    raw = download_bytes(zip_url)
    expected_sha = None
    try:
        dgst_text = download_bytes(dgst_url).decode("utf-8", errors="replace")
        expected_sha = parse_dgst_sha256(dgst_text)
    except urllib.error.URLError as exc:
        try:
            expected_sha = fetch_github_asset_sha256("XTLS/Xray-core", f"v{version}", asset)
        except urllib.error.URLError:
            if not allow_unverified:
                raise RuntimeError(f"Failed to fetch Xray SHA-256 digest ({dgst_url}): {exc}") from exc
    verify_sha256(raw, expected_sha, asset, allow_unverified=allow_unverified)

    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for name in zf.namelist():
            if not name.endswith("/") and Path(name).name == "xray":
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
                verify_elf(dest)
                set_exec(dest)
                return
    raise RuntimeError(f"xray binary not found in archive {asset}")


def extract_hevtun_from_aar(aar_bytes: bytes, abi: str, dest: Path) -> None:
    expected_member = ABI_MAP[abi]["hevtun_jni_member"]
    with zipfile.ZipFile(io.BytesIO(aar_bytes)) as zf:
        for name in zf.namelist():
            if name == expected_member or (
                not name.endswith("/")
                and name.endswith("/libhev-socks5-tunnel.so")
                and f"/{abi}/" in f"/{name}"
            ):
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
                verify_elf(dest)
                set_exec(dest)
                return
    raise RuntimeError(f"libhev-socks5-tunnel.so for {abi} not found in hev-socks5-tunnel.aar")


def download_hevtun(abi: str, version: str, dest: Path, allow_unverified: bool = False) -> None:
    asset = "hev-socks5-tunnel.aar"
    url = f"https://github.com/heiher/hev-socks5-tunnel/releases/download/{version}/{asset}"
    print(f"Downloading hev-socks5-tunnel for {abi}: {url}")
    raw = download_bytes(url)
    expected_sha = None
    try:
        expected_sha = fetch_github_asset_sha256("heiher/hev-socks5-tunnel", version, asset)
    except urllib.error.URLError as exc:
        if not allow_unverified:
            raise RuntimeError(f"Failed to fetch hev-socks5-tunnel SHA-256 digest: {exc}") from exc
    verify_sha256(raw, expected_sha, asset, allow_unverified=allow_unverified)
    extract_hevtun_from_aar(raw, abi, dest)


def build_go_backend(abi: str) -> None:
    out_path = JNI_LIBS_DIR / abi / "libprismray.so"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = "android"
    env["GOARCH"] = ABI_MAP[abi]["goarch"]
    cmd = [
        "go",
        "-C",
        str(BACKEND_DIR),
        "build",
        "-trimpath",
        "-ldflags=-s -w",
        "-o",
        str(out_path),
        "./cmd/server",
    ]
    print(f"Building Go backend for Android {abi} -> {out_path}")
    subprocess.run(cmd, env=env, check=True)
    verify_elf(out_path)
    set_exec(out_path)


def _singbox_android_sources_newer_than(binary: Path) -> bool:
    if not binary.is_file():
        return True
    bin_mtime = binary.stat().st_mtime
    for path in SINGBOX_ANDROID_DIR.rglob("*"):
        if path.is_file() and (path.suffix == ".go" or path.name in ("go.mod", "go.sum")):
            if path.stat().st_mtime > bin_mtime:
                return True
    return False


def build_android_singbox(abi: str, version: str, dest: Path) -> None:
    """Compile PrismRay's Android sing-box wrapper with PlatformInterface (fixes netlinkrib on Android 11+ Tailscale)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"
    env["GOOS"] = "android"
    env["GOARCH"] = ABI_MAP[abi]["goarch"]
    cmd = [
        "go",
        "-C",
        str(SINGBOX_ANDROID_DIR),
        "build",
        "-trimpath",
        "-tags",
        SINGBOX_ANDROID_TAGS,
        "-ldflags=-s -w -buildid=",
        "-o",
        str(dest),
        ".",
    ]
    print(f"Building Android sing-box wrapper v{version} for {abi} -> {dest}")
    subprocess.run(cmd, env=env, check=True)
    verify_elf(dest)
    set_exec(dest)


def stage_android_singbox(abi: str, version: str, explicit_bin: Path | None) -> None:
    jni_dest = JNI_LIBS_DIR / abi / "libsingbox.so"
    jni_dest.parent.mkdir(parents=True, exist_ok=True)
    if explicit_bin is not None:
        stage_core(abi, "sing-box", version, "libsingbox.so", explicit_bin, None)
        return
    cache_path = ANDROID_CORES_DIR / abi / f"sing-box-{version}-prismray"
    if _singbox_android_sources_newer_than(cache_path):
        build_android_singbox(abi, version, cache_path)
    shutil.copy2(cache_path, jni_dest)
    verify_elf(jni_dest)
    set_exec(jni_dest)


def stage_core(abi: str, core_name: str, version: str, lib_name: str, explicit_bin: Path | None, download_fn) -> None:
    jni_dest = JNI_LIBS_DIR / abi / lib_name
    jni_dest.parent.mkdir(parents=True, exist_ok=True)
    cache_path = ANDROID_CORES_DIR / abi / f"{core_name}-{version}"

    if explicit_bin is not None:
        if not explicit_bin.is_file():
            raise FileNotFoundError(f"{core_name} binary not found at {explicit_bin}")
        if explicit_bin.resolve() != cache_path.resolve():
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(explicit_bin, cache_path)
        shutil.copy2(explicit_bin, jni_dest)
        verify_elf(jni_dest)
        set_exec(jni_dest)
        return

    if not cache_path.is_file():
        if download_fn is None:
            raise FileNotFoundError(
                f"Missing {core_name} for {abi} at {cache_path}; pass --download or --{core_name}-bin"
            )
        download_fn(cache_path)

    shutil.copy2(cache_path, jni_dest)
    verify_elf(jni_dest)
    set_exec(jni_dest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--abis",
        default="arm64-v8a",
        help="Comma-separated Android ABIs to build (supported: arm64-v8a,x86_64)",
    )
    parser.add_argument("--singbox-version", default=DEFAULT_SINGBOX_VERSION)
    parser.add_argument("--xray-version", default=DEFAULT_XRAY_VERSION)
    parser.add_argument("--hevtun-version", default=DEFAULT_HEVTUN_VERSION)
    parser.add_argument("--singbox-bin", type=Path, default=None, help="Explicit sing-box Android ELF path (single ABI)")
    parser.add_argument("--xray-bin", type=Path, default=None, help="Explicit xray Android ELF path (single ABI)")
    parser.add_argument("--hevtun-bin", type=Path, default=None, help="Explicit libhev-socks5-tunnel.so path (single ABI)")
    parser.add_argument("--download", action="store_true", help="Download missing core binaries from GitHub releases")
    parser.add_argument("--allow-unverified", action="store_true", help="Allow downloads without upstream SHA-256 verification")
    parser.add_argument("--skip-cores", action="store_true", help="Only build Go backend libprismray.so")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    abis = [item.strip() for item in args.abis.split(",") if item.strip()]
    if not abis:
        raise SystemExit("At least one ABI must be specified")
    for abi in abis:
        if abi not in ABI_MAP:
            raise SystemExit(f"Unsupported Android ABI: {abi!r} (expected one of {sorted(ABI_MAP)})")

    if (args.singbox_bin or args.xray_bin or args.hevtun_bin) and len(abis) > 1:
        raise SystemExit("--singbox-bin / --xray-bin / --hevtun-bin can only be used with a single ABI")

    for abi in abis:
        build_go_backend(abi)
        if not args.skip_cores:
            xr_dl = (lambda dest, a=abi: download_xray(a, args.xray_version, dest, allow_unverified=args.allow_unverified)) if args.download else None
            ht_dl = (lambda dest, a=abi: download_hevtun(a, args.hevtun_version, dest, allow_unverified=args.allow_unverified)) if args.download else None
            stage_android_singbox(abi, args.singbox_version, args.singbox_bin)
            stage_core(abi, "xray", args.xray_version, "libxray.so", args.xray_bin, xr_dl)
            stage_core(abi, "hev-socks5-tunnel", args.hevtun_version, "libhev-socks5-tunnel.so", args.hevtun_bin, ht_dl)

    print("Android native binaries staged successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
