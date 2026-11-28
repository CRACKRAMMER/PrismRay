#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build local PrismRay release packages mirroring .github/workflows/build.yml into releases/."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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


def format_versioned_artifact_name(version: str, target_suffix: str) -> str:
    """Format a versioned filename under releases/ such as prismray-v1.0.1-local.1-android-arm64.apk."""
    clean_ver = version.strip().lstrip('vV')
    if not clean_ver:
        raise ValueError('Version must not be empty')
    clean_suffix = target_suffix.strip().lstrip('-')
    return f'prismray-v{clean_ver}-{clean_suffix}'


def build_linux_full_appimage(output_dir: Path, *, version: str | None = None) -> Path:
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

    base_version = (version or read_repo_version(ROOT)).strip()
    dest = output_dir / format_versioned_artifact_name(base_version, 'linux-x64-full.AppImage')
    tmp = dest.with_name(f'.{dest.name}.tmp.{os.getpid()}')
    shutil.copy2(src, tmp)
    tmp.chmod(0o755)
    os.replace(tmp, dest)
    return dest


def build_headless_archives(output_dir: Path, *, version: str | None = None) -> list[Path]:
    web_dist = ROOT / 'frontend' / 'dist'
    if not (web_dist / 'index.html').is_file():
        run(['npm', '--prefix', str(ROOT / 'frontend'), 'run', 'build'])

    base_version = (version or read_repo_version(ROOT)).strip()
    built: list[Path] = []
    with tempfile.TemporaryDirectory(prefix='prismray-headless-stage-') as stage_dir:
        stage_path = Path(stage_dir)
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
                    str(stage_path),
                ]
            )
            src = stage_path / f'prismray-headless-{platform}.tar.gz'
            dest = output_dir / format_versioned_artifact_name(base_version, f'headless-{platform}.tar.gz')
            tmp = dest.with_name(f'.{dest.name}.tmp.{os.getpid()}')
            shutil.copy2(src, tmp)
            os.replace(tmp, dest)
            built.append(dest)
    return built


SEMVER_RE = re.compile(r'^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$')


def compute_android_version_code(version: str, local_seq: int | None = None) -> int:
    """Mirror frontend/src-tauri/gen/android/app/build.gradle.kts monotonic versionCode formula."""
    match = SEMVER_RE.fullmatch(version.strip())
    if not match:
        raise ValueError(f'Invalid semver version: {version!r}')
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))
    if local_seq is not None and not (1 <= local_seq <= 998):
        raise ValueError(f'local_seq must be in 1..998, got {local_seq}')
    offset = local_seq if local_seq is not None else 999
    return major * 10_000_000 + minor * 100_000 + patch * 1_000 + offset


def read_repo_version(root: Path = ROOT) -> str:
    data = json.loads((root / 'frontend' / 'src-tauri' / 'tauri.conf.json').read_text(encoding='utf-8'))
    return str(data['version']).strip()


def next_local_build_seq(state_file: Path, base_version: str) -> int:
    """Persistently increment 1..998 build counter per base_version without dirtying git."""
    seq = 1
    if state_file.is_file():
        try:
            saved = json.loads(state_file.read_text(encoding='utf-8'))
            if saved.get('version') == base_version and isinstance(saved.get('seq'), int):
                seq = saved['seq'] + 1
        except (ValueError, OSError):
            seq = 1
    if seq > 998:
        seq = 998
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps({'version': base_version, 'seq': seq}, indent=2) + '\n', encoding='utf-8')
    return seq


def bump_repo_version(root: Path, new_version: str) -> list[str]:
    """Synchronize version string across frontend, Tauri, Cargo, i18n, and Go backend."""
    clean = new_version.strip().lstrip('v')
    if not SEMVER_RE.fullmatch(clean):
        raise ValueError(f'Expected MAJOR.MINOR.PATCH[-prerelease], got {new_version!r}')
    updated: list[str] = []

    for rel in ('frontend/package.json', 'frontend/src-tauri/tauri.conf.json'):
        p = root / rel
        if p.is_file():
            text = p.read_text(encoding='utf-8')
            next_text, n = re.subn(r'("version"\s*:\s*")[^"]+(")', rf'\g<1>{clean}\2', text, count=1)
            if n:
                p.write_text(next_text, encoding='utf-8')
                updated.append(rel)

    lock_path = root / 'frontend/package-lock.json'
    if lock_path.is_file():
        lock = json.loads(lock_path.read_text(encoding='utf-8'))
        lock['version'] = clean
        if isinstance(lock.get('packages'), dict) and isinstance(lock['packages'].get(''), dict):
            lock['packages']['']['version'] = clean
        lock_path.write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
        updated.append('frontend/package-lock.json')

    cargo_path = root / 'frontend/src-tauri/Cargo.toml'
    if cargo_path.is_file():
        text = cargo_path.read_text(encoding='utf-8')
        head, sep, tail = text.partition('[package]')
        if sep:
            pkg_block, next_sep, rest = tail.partition('\n[')
            pkg_block, n = re.subn(r'^(version\s*=\s*")[^"]+(")', rf'\g<1>{clean}\2', pkg_block, count=1, flags=re.M)
            if n:
                cargo_path.write_text(head + sep + pkg_block + next_sep + rest, encoding='utf-8')
                updated.append('frontend/src-tauri/Cargo.toml')

    i18n_path = root / 'frontend/src/lib/i18n.ts'
    if i18n_path.is_file():
        text = i18n_path.read_text(encoding='utf-8')
        next_text, n = re.subn(r'("app\.version"\s*:\s*"v)[^"]+(")', rf'\g<1>{clean}\2', text)
        if n:
            i18n_path.write_text(next_text, encoding='utf-8')
            updated.append('frontend/src/lib/i18n.ts')

    go_patterns: list[tuple[str, str, str]] = [
        ('backend/internal/api/app_update.go', r'(AppVersion\s*=\s*")[^"]+(")', rf'\g<1>{clean}\2'),
        ('backend/cmd/server/main.go', r'("version",\s*")[^"]+(")', rf'\g<1>{clean}\2'),
        ('backend/internal/api/tools.go', r'("version"\s*:\s*")[^"]+(")', rf'\g<1>{clean}\2'),
        ('backend/internal/api/handlers.go', r'(PrismRay/)[\d.]+(?:-[0-9A-Za-z.-]+)?', rf'\g<1>{clean}'),
        ('backend/internal/api/subscriptions.go', r'(PrismRay/)[\d.]+(?:-[0-9A-Za-z.-]+)?', rf'\g<1>{clean}'),
        ('backend/internal/api/core.go', r'(PrismRay/)[\d.]+(?:-[0-9A-Za-z.-]+)?', rf'\g<1>{clean}'),
        ('backend/internal/orchestrator/orchestrator.go', r'(PrismRay/)[\d.]+(?:-[0-9A-Za-z.-]+)?', rf'\g<1>{clean}'),
        ('packaging/arch/prismray/PKGBUILD', r'^(pkgver=)[^\s]+', rf'\g<1>{clean.replace("-", ".")}'),
        ('packaging/arch/prismray-server/PKGBUILD', r'^(pkgver=)[^\s]+', rf'\g<1>{clean.replace("-", ".")}'),
    ]
    for rel, pat, repl in go_patterns:
        p = root / rel
        if p.is_file():
            text = p.read_text(encoding='utf-8')
            next_text, n = re.subn(pat, repl, text, flags=re.M)
            if n:
                p.write_text(next_text, encoding='utf-8')
                updated.append(rel)

    return updated


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


def build_android_apk(
    output_dir: Path,
    *,
    force_download_cores: bool = False,
    local_build_seq: int | None = None,
    use_release_version_code: bool = False,
) -> Path:
    jni_dir = ROOT / 'frontend' / 'src-tauri' / 'gen' / 'android' / 'app' / 'src' / 'main' / 'jniLibs' / 'arm64-v8a'
    has_staged_cores = (
        (jni_dir / 'libsingbox.so').is_file()
        and (jni_dir / 'libxray.so').is_file()
        and (jni_dir / 'libhev-socks5-tunnel.so').is_file()
    )
    release_signed = has_android_release_signing()
    base_version = read_repo_version(ROOT)
    seq: int | None = None
    if not use_release_version_code:
        seq = local_build_seq if local_build_seq is not None else next_local_build_seq(output_dir / '.local_build_seq.json', base_version)
    resolved_code = compute_android_version_code(base_version, seq)
    resolved_name = f'{base_version}-local.{seq}' if seq is not None else base_version
    print(f'==> Android APK version: versionName={resolved_name} versionCode={resolved_code}', flush=True)

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
        if seq is not None:
            env['PRISMRAY_ANDROID_LOCAL_BUILD_SEQ'] = str(seq)
        else:
            env.pop('PRISMRAY_ANDROID_LOCAL_BUILD_SEQ', None)
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
        debug_env = dict(os.environ)
        if seq is not None:
            debug_env['PRISMRAY_ANDROID_LOCAL_BUILD_SEQ'] = str(seq)
        else:
            debug_env.pop('PRISMRAY_ANDROID_LOCAL_BUILD_SEQ', None)
        cmd = [sys.executable, str(ROOT / 'scripts' / 'android_studio_dev.py'), '--abis', 'arm64-v8a']
        if has_staged_cores and not force_download_cores:
            cmd.append('--skip-cores')
        run(cmd, env=debug_env)

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

    dest = output_dir / format_versioned_artifact_name(resolved_name, 'android-arm64.apk')
    tmp = dest.with_name(f'.{dest.name}.tmp.{os.getpid()}')
    shutil.copy2(selected, tmp)
    os.replace(tmp, dest)
    return dest


def write_checksums(output_dir: Path) -> Path:
    checksum_file = output_dir / 'SHA256SUMS.txt'
    assets = sorted(
        p for p in output_dir.iterdir()
        if p.is_file() and p.name != checksum_file.name and not p.name.startswith('.')
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
    parser.add_argument(
        '--bump-version',
        default='',
        help='Synchronize repository version across manifests, i18n, and Go backend (e.g. 1.0.2) before building',
    )
    parser.add_argument(
        '--android-local-seq',
        type=int,
        default=None,
        help='Explicit local Android build sequence (1..998); defaults to auto-incrementing releases/.local_build_seq.json',
    )
    parser.add_argument(
        '--release-version-code',
        action='store_true',
        help='Build Android APK with official release versionCode offset (999) instead of local sequence',
    )
    args = parser.parse_args()

    if args.bump_version:
        updated_files = bump_repo_version(ROOT, args.bump_version)
        print(f'==> Bumped repo version to {args.bump_version.lstrip("v")} ({len(updated_files)} files updated)')

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
        exported.append(
            build_android_apk(
                output_dir,
                force_download_cores=args.download_android_cores,
                local_build_seq=args.android_local_seq,
                use_release_version_code=args.release_version_code,
            )
        )

    checksum_file = write_checksums(output_dir)
    exported.append(checksum_file)

    print('\nLocal release artifacts ready in', output_dir)
    for item in exported:
        size_mb = item.stat().st_size / (1024 * 1024)
        print(f'  - {item.name} ({size_mb:.2f} MiB)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
