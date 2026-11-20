#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Sync PrismRay frontend, Go backend, and Rust JNI libraries for Android Studio debugging."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / 'frontend'
ANDROID_PROJECT_DIR = FRONTEND_DIR / 'src-tauri' / 'gen' / 'android'

ABI_TO_TAURI_TARGET = {
    'arm64-v8a': ('aarch64', 'aarch64-linux-android', 'aarch64-linux-android26-clang'),
    'x86_64': ('x86_64', 'x86_64-linux-android', 'x86_64-linux-android26-clang'),
}


def detect_android_sdk() -> Path:
    for env_key in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
        val = os.environ.get(env_key, '').strip()
        if val and Path(val).is_dir():
            return Path(val)
    for candidate in (
        Path.home() / 'Android' / 'Sdk',
        Path('/opt/android-sdk'),
        Path('/usr/local/lib/android/sdk'),
    ):
        if candidate.is_dir():
            return candidate
    raise SystemExit('Android SDK not found. Set ANDROID_HOME or install via Android Studio SDK Manager.')


def detect_ndk(sdk: Path) -> Path:
    for env_key in ('NDK_HOME', 'ANDROID_NDK_HOME'):
        val = os.environ.get(env_key, '').strip()
        if val and Path(val).is_dir():
            return Path(val)
    ndk_root = sdk / 'ndk'
    if ndk_root.is_dir():
        versions = sorted((p for p in ndk_root.iterdir() if p.is_dir()), reverse=True)
        if versions:
            return versions[0]
    raise SystemExit(f'Android NDK not found under {ndk_root}. Install NDK in Android Studio SDK Manager.')


def detect_java_home() -> str | None:
    if os.environ.get('JAVA_HOME'):
        return os.environ['JAVA_HOME']
    for candidate in (
        Path('/usr/lib/jvm/java-21-openjdk'),
        Path('/opt/android-studio/jbr'),
        Path('/usr/lib/jvm/default'),
    ):
        if candidate.is_dir():
            return str(candidate)
    return None


def configure_build_env(sdk: Path, ndk: Path) -> dict[str, str]:
    env = os.environ.copy()
    env['ANDROID_HOME'] = str(sdk)
    env['ANDROID_SDK_ROOT'] = str(sdk)
    env['NDK_HOME'] = str(ndk)
    env['ANDROID_NDK_HOME'] = str(ndk)
    java_home = detect_java_home()
    if java_home:
        env['JAVA_HOME'] = java_home

    prebuilt = ndk / 'toolchains' / 'llvm' / 'prebuilt' / 'linux-x86_64' / 'bin'
    if prebuilt.is_dir():
        env['AR_aarch64_linux_android'] = str(prebuilt / 'llvm-ar')
        env['AR_x86_64_linux_android'] = str(prebuilt / 'llvm-ar')
        cc_arm64 = prebuilt / 'aarch64-linux-android26-clang'
        cc_x64 = prebuilt / 'x86_64-linux-android26-clang'
        if cc_arm64.is_file():
            env['CC_aarch64_linux_android'] = str(cc_arm64)
            env['CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER'] = str(cc_arm64)
        if cc_x64.is_file():
            env['CC_x86_64_linux_android'] = str(cc_x64)
            env['CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER'] = str(cc_x64)
    return env


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print(f'==> {" ".join(cmd)}')
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--abis', default='arm64-v8a', help='Comma-separated ABIs: arm64-v8a, x86_64')
    parser.add_argument('--skip-cores', action='store_true', help='Skip downloading/staging sing-box and xray')
    parser.add_argument('--skip-apk', action='store_true', help='Only stage Go/frontend natives without running Tauri APK build')
    parser.add_argument('--install', action='store_true', help='Install built debug APK via adb and launch app')
    parser.add_argument('--open', action='store_true', help='Open frontend/src-tauri/gen/android in Android Studio')
    args = parser.parse_args()

    abis = [a.strip() for a in args.abis.split(',') if a.strip()]
    for abi in abis:
        if abi not in ABI_TO_TAURI_TARGET:
            raise SystemExit(f'Unsupported ABI {abi!r} (expected arm64-v8a or x86_64)')

    sdk = detect_android_sdk()
    ndk = detect_ndk(sdk)
    env = configure_build_env(sdk, ndk)

    native_cmd = [sys.executable, str(ROOT / 'scripts' / 'build_android_natives.py'), '--abis', ','.join(abis)]
    if args.skip_cores:
        native_cmd.append('--skip-cores')
    else:
        native_cmd.append('--download')
    run(native_cmd, cwd=ROOT, env=env)

    if not args.skip_apk:
        tauri_targets = [ABI_TO_TAURI_TARGET[a][0] for a in abis]
        tauri_cmd = [
            'npm', '--prefix', str(FRONTEND_DIR), 'run', 'tauri', '--',
            'android', 'build', '--ignore-version-mismatches', '--apk', '--debug',
        ]
        for target in tauri_targets:
            tauri_cmd.extend(['--target', target])
        run(tauri_cmd, cwd=ROOT, env=env)

    if args.install:
        apk_root = ANDROID_PROJECT_DIR / 'app' / 'build' / 'outputs' / 'apk'
        apks = sorted(apk_root.rglob('*.apk'))
        if not apks:
            raise SystemExit(f'No APK found under {apk_root}')
        apk = next((p for p in apks if 'universal' in p.name.lower()), apks[0])
        run(['adb', 'install', '-r', str(apk)], env=env)
        run(['adb', 'shell', 'am', 'start', '-n', 'com.crackrammer.prismray/.MainActivity'], env=env)

    if args.open:
        studio = shutil.which('android-studio') or shutil.which('studio.sh')
        if not studio:
            raise SystemExit('android-studio executable not found in PATH')
        print(f'==> Launching Android Studio on {ANDROID_PROJECT_DIR}')
        subprocess.Popen([studio, str(ANDROID_PROJECT_DIR)], env=env, start_new_session=True)

    print('\nReady for Android Studio debugging:')
    print(f'  Gradle Project : {ANDROID_PROJECT_DIR}')
    print('  Logcat Filter  : tag:PrismRayMain | tag:PrismRayVPN | tag:PrismRayIPC')
    print('  WebView Inspect: chrome://inspect/#devices (Debug builds auto-enable WebView debugging)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
