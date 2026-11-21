#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build local PrismRay release packages mirroring .github/workflows/build.yml into releases/."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from build_appimage import ensure_appimage_runtime

ROOT = Path(__file__).resolve().parents[1]
LINUX_RUST_TARGET = 'x86_64-unknown-linux-gnu'
DEFAULT_TARGETS = ('linux-appimage', 'headless', 'android')


def run(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print('==>', ' '.join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), env=env, check=True)


def verify_full_linux_appimage(appimage_path: Path) -> None:
    """Mirror CI verification: exclude host libwayland-client and bundle sing-box + xray."""
    with tempfile.TemporaryDirectory(prefix='prismray-appimage-verify-') as tmp:
        env = os.environ.copy()
        env['APPIMAGE_EXTRACT_AND_RUN'] = '1'
        run([str(appimage_path.resolve()), '--appimage-extract'], cwd=Path(tmp), env=env)
        squash = Path(tmp) / 'squashfs-root'
        wayland_libs = list((squash / 'usr' / 'lib').glob('libwayland-client.so*')) if (squash / 'usr' / 'lib').is_dir() else []
        if wayland_libs:
            raise RuntimeError(f'AppImage still bundles host Wayland client library: {wayland_libs}')
        for bin_name in ('sing-box', 'xray'):
            expected = squash / 'usr' / 'bin' / bin_name
            if not expected.is_file():
                raise RuntimeError(f'Full AppImage is missing bundled core: {expected}')
    print(f'Verified Full AppImage: {appimage_path.name} (no libwayland-client, includes sing-box + xray)', flush=True)


def build_linux_full_appimage(output_dir: Path) -> Path:
    sidecar_env = os.environ.copy()
    sidecar_env['RUST_TARGET'] = LINUX_RUST_TARGET
    sidecar_env['GOOS'] = 'linux'
    sidecar_env['GOARCH'] = 'amd64'
    sidecar_env['CGO_ENABLED'] = '0'
    run([sys.executable, str(ROOT / 'scripts' / 'build_sidecar.py')], env=sidecar_env)
    run([sys.executable, str(ROOT / 'scripts' / 'configure_updater.py')])

    bundle_dir = ROOT / 'frontend' / 'src-tauri' / 'target' / LINUX_RUST_TARGET / 'release' / 'bundle'
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)

    run([sys.executable, str(ROOT / 'scripts' / 'stage_desktop_cores.py'), '--target', LINUX_RUST_TARGET])

    tauri_env = os.environ.copy()
    tauri_env['APPIMAGE_EXTRACT_AND_RUN'] = '1'
    tauri_env['NO_STRIP'] = 'true'
    runtime_file = ensure_appimage_runtime(LINUX_RUST_TARGET)
    if runtime_file is not None:
        tauri_env['LDAI_RUNTIME_FILE'] = str(runtime_file)
    run(
        [
            'npm',
            '--prefix',
            str(ROOT / 'frontend'),
            'run',
            'tauri',
            '--',
            'build',
            '--ci',
            '--ignore-version-mismatches',
            '--config',
            'src-tauri/full.generated.json',
            '--target',
            LINUX_RUST_TARGET,
            '--bundles',
            'appimage',
            '--',
            '--locked',
        ],
        env=tauri_env,
    )

    appimage_dir = bundle_dir / 'appimage'
    candidates = sorted(p for p in appimage_dir.glob('*.AppImage') if p.is_file())
    if not candidates:
        raise FileNotFoundError(f'No .AppImage produced under {appimage_dir}')
    src = candidates[0]
    verify_full_linux_appimage(src)

    dest = output_dir / 'prismray-linux-x64-full.AppImage'
    tmp = dest.with_name(f'.{dest.name}.tmp.{os.getpid()}')
    shutil.copy2(src, tmp)
    tmp.chmod(0o755)
    os.replace(tmp, dest)
    return dest


def build_headless_archives(output_dir: Path) -> list[Path]:
    web_dist = ROOT / 'frontend' / 'dist'
    if not (web_dist / 'index.html').is_file():
        run(['npm', '--prefix', str(ROOT / 'frontend'), 'run', 'build'])

    built: list[Path] = []
    for platform, goarch in (('linux-x64', 'amd64'), ('linux-arm64', 'arm64')):
        run(
            [
                sys.executable,
                str(ROOT / 'scripts' / 'build_headless.py'),
                '--platform',
                platform,
                '--goos',
                'linux',
                '--goarch',
                goarch,
                '--web-dist',
                str(web_dist),
                '--output-dir',
                str(output_dir),
            ]
        )
        built.append(output_dir / f'prismray-headless-{platform}.tar.gz')
    return built


def has_android_release_signing() -> bool:
    if (
        os.environ.get('PRISMRAY_ANDROID_KEYSTORE_PATH', '').strip()
        and os.environ.get('PRISMRAY_ANDROID_KEYSTORE_PASSWORD', '').strip()
        and os.environ.get('PRISMRAY_ANDROID_KEY_ALIAS', '').strip()
    ):
        return True
    return (ROOT / 'keystore' / 'keystore.properties').is_file() or (
        ROOT / 'frontend' / 'src-tauri' / 'gen' / 'android' / 'keystore.properties'
    ).is_file()


def build_android_apk(output_dir: Path, *, force_download_cores: bool = False) -> Path:
    jni_dir = ROOT / 'frontend' / 'src-tauri' / 'gen' / 'android' / 'app' / 'src' / 'main' / 'jniLibs' / 'arm64-v8a'
    has_staged_cores = (jni_dir / 'libsingbox.so').is_file() and (jni_dir / 'libxray.so').is_file()
    release_signed = has_android_release_signing()

    if release_signed:
        print('==> Detected Android release keystore; building signed Release APK (aarch64)')
        android_sdk = (
            os.environ.get('ANDROID_HOME')
            or os.environ.get('ANDROID_SDK_ROOT')
            or str(Path.home() / 'Android' / 'Sdk')
        )
        ndk_home = os.environ.get('NDK_HOME') or os.environ.get('ANDROID_NDK_HOME') or f'{android_sdk}/ndk/29.0.14206865'
        java_home = os.environ.get('JAVA_HOME') or (
            '/usr/lib/jvm/java-21-openjdk' if Path('/usr/lib/jvm/java-21-openjdk').is_dir() else ''
        )
        env = {
            **os.environ,
            'ANDROID_HOME': android_sdk,
            'ANDROID_SDK_ROOT': android_sdk,
            'NDK_HOME': ndk_home,
            'ANDROID_NDK_HOME': ndk_home,
            'CC_aarch64_linux_android': f'{ndk_home}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang',
            'AR_aarch64_linux_android': f'{ndk_home}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar',
            'CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER': f'{ndk_home}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang',
        }
        if java_home:
            env['JAVA_HOME'] = java_home
            env['PATH'] = f'{java_home}/bin:{env.get("PATH", "")}'

        stage_cmd = [sys.executable, str(ROOT / 'scripts' / 'build_android_natives.py'), '--abi', 'arm64-v8a']
        if not has_staged_cores or force_download_cores:
            stage_cmd.append('--download')
        run(stage_cmd, env=env)
        run(
            [
                'npm',
                '--prefix',
                str(ROOT / 'frontend'),
                'run',
                'tauri',
                '--',
                'android',
                'build',
                '--ci',
                '--ignore-version-mismatches',
                '--apk',
                '--target',
                'aarch64',
            ],
            env=env,
        )
    else:
        print('==> No Android release keystore configured; falling back to Debug APK (arm64-v8a)')
        cmd = [sys.executable, str(ROOT / 'scripts' / 'android_studio_dev.py'), '--abis', 'arm64-v8a']
        if has_staged_cores and not force_download_cores:
            cmd.append('--skip-cores')
        run(cmd)

    apk_root = ROOT / 'frontend' / 'src-tauri' / 'gen' / 'android' / 'app' / 'build' / 'outputs' / 'apk'
    candidates = sorted(p for p in apk_root.rglob('*.apk') if p.is_file())
    if not candidates:
        raise FileNotFoundError(f'No .apk produced under {apk_root}')

    if release_signed:
        signed_release = [
            p for p in candidates
            if 'release' in p.name.lower() and 'unsigned' not in p.name.lower()
        ]
        if not signed_release:
            raise RuntimeError(
                f'Release signing was configured but no signed release APK was produced under {apk_root}: {candidates}'
            )
        pool = signed_release
    else:
        pool = [p for p in candidates if 'debug' in p.name.lower()] or candidates

    selected = pool[0]
    for token in ('universal', 'arm64'):
        for cand in pool:
            if token in cand.name.lower():
                selected = cand
                break
        else:
            continue
        break

    dest = output_dir / 'prismray-android-arm64.apk'
    tmp = dest.with_name(f'.{dest.name}.tmp.{os.getpid()}')
    shutil.copy2(selected, tmp)
    os.replace(tmp, dest)
    return dest


def write_checksums(output_dir: Path) -> Path:
    checksum_file = output_dir / 'SHA256SUMS.txt'
    assets = sorted(
        p for p in output_dir.iterdir()
        if p.is_file() and p.name != checksum_file.name
    )
    lines: list[str] = []
    for asset in assets:
        digest = hashlib.sha256()
        with asset.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        lines.append(f'{digest.hexdigest()}  {asset.name}\n')
    checksum_file.write_text(''.join(lines), encoding='utf-8')
    return checksum_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--targets',
        default=','.join(DEFAULT_TARGETS),
        help=f'Comma-separated targets from {",".join(DEFAULT_TARGETS)} (default: {",".join(DEFAULT_TARGETS)})',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=ROOT / 'releases',
        help='Output directory for packaged release assets (default: ./releases)',
    )
    parser.add_argument(
        '--download-android-cores',
        action='store_true',
        help='Force re-downloading Android sing-box + Xray cores even when already staged',
    )
    args = parser.parse_args()

    targets = [t.strip().lower() for t in args.targets.split(',') if t.strip()]
    invalid = [t for t in targets if t not in DEFAULT_TARGETS]
    if invalid:
        raise SystemExit(f'Unsupported target(s): {", ".join(invalid)} (valid: {", ".join(DEFAULT_TARGETS)})')

    output_dir = args.output_dir if args.output_dir.is_absolute() else (ROOT / args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Ensure frontend production assets are fresh once before packaging.
    run(['npm', '--prefix', str(ROOT / 'frontend'), 'run', 'build'])

    exported: list[Path] = []
    if 'linux-appimage' in targets:
        exported.append(build_linux_full_appimage(output_dir))
    if 'headless' in targets:
        exported.extend(build_headless_archives(output_dir))
    if 'android' in targets:
        exported.append(build_android_apk(output_dir, force_download_cores=args.download_android_cores))

    checksum_file = write_checksums(output_dir)
    exported.append(checksum_file)

    print('\nLocal release artifacts ready in', output_dir)
    for item in exported:
        size_mb = item.stat().st_size / (1024 * 1024)
        print(f'  - {item.name} ({size_mb:.2f} MiB)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
