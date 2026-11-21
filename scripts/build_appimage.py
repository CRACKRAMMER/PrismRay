#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build and verify a standalone Linux AppImage for PrismRay."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

LINUX_TARGETS: dict[str, tuple[str, str]] = {
    "x86_64-unknown-linux-gnu": ("amd64", "linux-x64"),
    "aarch64-unknown-linux-gnu": ("arm64", "linux-arm64"),
}

APPIMAGE_RUNTIME_ARCH: dict[str, str] = {
    "x86_64-unknown-linux-gnu": "x86_64",
    "aarch64-unknown-linux-gnu": "aarch64",
}

APPIMAGE_RUNTIME_URL = (
    "https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-{arch}"
)


def ensure_appimage_runtime(rust_target: str, *, cache_dir: Path | None = None) -> Path | None:
    """Cache AppImage type2-runtime locally so appimagetool never fails on transient GitHub hiccups."""
    existing = os.environ.get("LDAI_RUNTIME_FILE", "").strip()
    if existing:
        existing_path = Path(existing)
        if existing_path.is_file() and existing_path.stat().st_size > 100_000:
            return existing_path

    arch = APPIMAGE_RUNTIME_ARCH.get(rust_target)
    if not arch:
        return None

    if cache_dir is None:
        xdg_cache = os.environ.get("XDG_CACHE_HOME", "").strip()
        cache_dir = (Path(xdg_cache) if xdg_cache else (Path.home() / ".cache")) / "tauri"

    dest = cache_dir / f"runtime-{arch}"
    if dest.is_file() and dest.stat().st_size > 100_000:
        try:
            if dest.read_bytes()[:4] == b"\x7fELF":
                return dest
        except OSError:
            pass

    url = APPIMAGE_RUNTIME_URL.format(arch=arch)
    dest.parent.mkdir(parents=True, exist_ok=True)
    last_err: Exception | None = None
    for attempt in range(1, 4):
        try:
            print(f"==> Caching AppImage runtime ({arch}, attempt {attempt}/3)...", flush=True)
            req = urllib.request.Request(url, headers={"User-Agent": "PrismRay-AppImage-Builder/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            if len(data) <= 100_000 or data[:4] != b"\x7fELF":
                raise RuntimeError(f"Invalid AppImage runtime payload ({len(data)} bytes)")
            tmp = dest.with_name(f".{dest.name}.tmp.{os.getpid()}")
            tmp.write_bytes(data)
            tmp.chmod(0o755)
            os.replace(tmp, dest)
            return dest
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            if attempt < 3:
                time.sleep(attempt * 2)
    print(f"Warning: failed to pre-cache AppImage runtime from {url}: {last_err}", file=sys.stderr)
    return None


def detect_linux_target(target_override: str | None = None) -> str:
    """Resolve and validate the Linux Rust target triple."""
    candidate = (target_override or os.environ.get("RUST_TARGET") or "").strip()
    if not candidate:
        rustc_output = subprocess.check_output(["rustc", "-vV"], text=True)
        for line in rustc_output.splitlines():
            if line.startswith("host: "):
                candidate = line.split(": ", 1)[1].strip()
                break
    if candidate not in LINUX_TARGETS:
        supported = ", ".join(sorted(LINUX_TARGETS))
        raise ValueError(
            f"Unsupported Linux Rust target {candidate!r}; expected one of: {supported}"
        )
    return candidate


def verify_appimage_excludes_wayland(appimage: Path) -> None:
    """Verify the AppImage does not bundle host Wayland client libraries."""
    resolved = appimage.resolve()
    env = os.environ.copy()
    env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    with tempfile.TemporaryDirectory(prefix="prismray-appimage-check-") as temporary:
        extract_dir = Path(temporary)
        result = subprocess.run(
            [str(resolved), "--appimage-extract"],
            cwd=extract_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to extract AppImage {resolved} for Wayland check:\n{result.stdout}"
            )
        usr_lib = extract_dir / "squashfs-root" / "usr" / "lib"
        if usr_lib.is_dir():
            matches = sorted(usr_lib.rglob("libwayland-client.so*"))
            if matches:
                joined = ", ".join(str(p.relative_to(extract_dir)) for p in matches)
                raise RuntimeError(
                    "AppImage still bundles libwayland-client.so*, which breaks host "
                    f"Wayland compositors: {joined}"
                )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_appimage(
    root: Path,
    *,
    target: str | None = None,
    output: Path | None = None,
    clean_deps: bool = False,
    locked: bool = True,
    skip_verify: bool = False,
) -> Path:
    """Build the Go sidecar, bundle the Linux AppImage, verify it, and stage output."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError(
            f"Linux AppImage builds must run on Linux (detected platform: {sys.platform})"
        )

    for tool in ("go", "cargo", "rustc", "npm"):
        if shutil.which(tool) is None:
            raise FileNotFoundError(f"Required build tool not found in PATH: {tool}")

    resolved_target = detect_linux_target(target)
    goarch, platform = LINUX_TARGETS[resolved_target]

    frontend_dir = root / "frontend"
    backend_dir = root / "backend"
    node_modules_dir = frontend_dir / "node_modules"

    if clean_deps or not node_modules_dir.exists():
        print("==> Installing frontend dependencies (npm ci)...")
        subprocess.run(["npm", "ci"], cwd=frontend_dir, check=True)

    sidecar_path = (
        frontend_dir / "src-tauri" / "binaries" / f"prismray-server-{resolved_target}"
    )
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)

    go_env = os.environ.copy()
    go_env["GOOS"] = "linux"
    go_env["GOARCH"] = goarch
    go_env["CGO_ENABLED"] = "0"

    print(f"==> Building Go sidecar ({resolved_target}, GOARCH={goarch})...")
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-ldflags=-s -w",
            "-o",
            str(sidecar_path),
            "./cmd/server",
        ],
        cwd=backend_dir,
        env=go_env,
        check=True,
    )
    sidecar_path.chmod(0o755)

    updater_key = os.environ.get("UPDATER_PUBLIC_KEY", "").strip()
    updater_endpoint = os.environ.get("UPDATER_ENDPOINT", "").strip()
    use_updater_config = bool(updater_key or updater_endpoint)
    if use_updater_config:
        print("==> Generating signed updater config...")
        subprocess.run(
            [sys.executable, str(root / "scripts" / "configure_updater.py")],
            cwd=root,
            check=True,
        )

    tauri_cmd = [
        "npm",
        "run",
        "tauri",
        "--",
        "build",
        "--ci",
        "--ignore-version-mismatches",
        "--target",
        resolved_target,
        "--bundles",
        "appimage",
    ]
    if use_updater_config:
        tauri_cmd.extend(["--config", "src-tauri/updater.generated.json"])
    if locked:
        tauri_cmd.extend(["--", "--locked"])

    tauri_env = os.environ.copy()
    tauri_env["APPIMAGE_EXTRACT_AND_RUN"] = os.environ.get("APPIMAGE_EXTRACT_AND_RUN", "1")
    tauri_env["NO_STRIP"] = os.environ.get("NO_STRIP", "true")
    runtime_file = ensure_appimage_runtime(resolved_target)
    if runtime_file is not None:
        tauri_env["LDAI_RUNTIME_FILE"] = str(runtime_file)

    print(f"==> Bundling Tauri AppImage ({resolved_target})...")
    subprocess.run(tauri_cmd, cwd=frontend_dir, env=tauri_env, check=True)

    bundle_dir = (
        frontend_dir
        / "src-tauri"
        / "target"
        / resolved_target
        / "release"
        / "bundle"
        / "appimage"
    )
    appimages = (
        sorted(
            (p for p in bundle_dir.glob("*.AppImage") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if bundle_dir.is_dir()
        else []
    )
    if not appimages:
        raise FileNotFoundError(f"No .AppImage artifact found in {bundle_dir}")
    bundle_appimage = appimages[0]

    if not skip_verify:
        print("==> Verifying AppImage excludes libwayland-client.so*...")
        verify_appimage_excludes_wayland(bundle_appimage)

    output_path = output or (root / "artifacts" / f"prismray-{platform}.AppImage")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bundle_appimage, output_path)
    output_path.chmod(0o755)

    size_mib = output_path.stat().st_size / (1024 * 1024)
    sha256 = _sha256_file(output_path)
    print(f"Bundle: {bundle_appimage}")
    print(f"Output: {output_path}")
    print(f"Size:   {size_mib:.2f} MiB")
    print(f"SHA256: {sha256}")
    return output_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=tuple(LINUX_TARGETS),
        help="Rust target triple (defaults to RUST_TARGET or rustc host triple).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Destination AppImage path (defaults to artifacts/prismray-<platform>.AppImage).",
    )
    parser.add_argument(
        "--clean-deps",
        action="store_true",
        help="Force running 'npm ci' in frontend/ even if node_modules exists.",
    )
    parser.add_argument(
        "--unlocked",
        action="store_true",
        help="Omit '-- --locked' when invoking Cargo via Tauri build.",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip '--appimage-extract' Wayland client library check.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    build_appimage(
        root,
        target=args.target,
        output=args.output.resolve() if args.output else None,
        clean_deps=args.clean_deps,
        locked=not args.unlocked,
        skip_verify=args.skip_verify,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
