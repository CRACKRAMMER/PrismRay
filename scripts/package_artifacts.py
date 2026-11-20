# SPDX-License-Identifier: MPL-2.0
"""Collect standalone CI installers without bundling local settings, node data or caches."""

import argparse
from pathlib import Path
import shutil

PLATFORMS = {
    "linux-x64": ("x86_64-unknown-linux-gnu", (".deb", ".rpm", ".AppImage")),
    "windows-x64": ("x86_64-pc-windows-msvc", (".exe", ".msi")),
    "macos-arm64": ("aarch64-apple-darwin", (".dmg",)),
    "android-arm64": ("aarch64-linux-android", (".apk",)),
}


def _select_installer(candidates: list[Path], suffix: str) -> Path:
    matching = [p for p in candidates if p.suffix == suffix]
    if not matching:
        raise FileNotFoundError(f"No {suffix} installer found")
    if suffix == ".apk":
        # Prefer signed release APKs over unsigned or debug APKs, and universal/arm64 over other ABIs.
        signed_release = [
            p for p in matching
            if "release" in p.name.lower() and "unsigned" not in p.name.lower()
        ]
        pool = signed_release or matching
        for token in ("universal", "arm64"):
            for path in pool:
                if token in path.name.lower():
                    return path
        return pool[0]
    return matching[0]


def package(root: Path, platform: str, target: str, variant: str = "") -> list[Path]:
    expected_target, suffixes = PLATFORMS[platform]
    if target != expected_target:
        raise ValueError(f"{platform} requires {expected_target}, got {target}")
    clean_variant = variant.strip().lower()
    if clean_variant not in ("", "lite", "full"):
        raise ValueError(f"Unsupported variant {variant!r} (expected '', 'lite', or 'full')")

    output = root / "artifacts"
    output.mkdir(parents=True, exist_ok=True)

    if platform == "android-arm64":
        bundle_dir = (
            root
            / "frontend"
            / "src-tauri"
            / "gen"
            / "android"
            / "app"
            / "build"
            / "outputs"
            / "apk"
        )
        candidates = sorted(p for p in bundle_dir.rglob("*.apk") if p.is_file())
    else:
        bundle_dir = root / "frontend" / "src-tauri" / "target" / target / "release" / "bundle"
        candidates = sorted(p for p in bundle_dir.rglob("*") if p.is_file() and p.suffix in suffixes)

    suffix_tag = f"-{clean_variant}" if clean_variant else ""
    name = f"prismray-{platform}{suffix_tag}"
    exported: list[Path] = []
    for suffix in suffixes:
        installer = _select_installer(candidates, suffix)
        destination = output / f"{name}{suffix}"
        shutil.copy2(installer, destination)
        if suffix == ".AppImage":
            destination.chmod(0o755)
        exported.append(destination)
    return exported


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--target", required=True)
    parser.add_argument("--variant", default="", choices=("", "lite", "full"))
    args = parser.parse_args()
    for path in package(Path(__file__).resolve().parents[1], args.platform, args.target, args.variant):
        print(path)
