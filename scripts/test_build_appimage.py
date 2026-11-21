# SPDX-License-Identifier: MPL-2.0
"""Unit tests for scripts/build_appimage.py."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from build_appimage import (
    build_appimage,
    detect_linux_target,
    ensure_appimage_runtime,
    verify_appimage_excludes_wayland,
)


class BuildAppImageTests(unittest.TestCase):
    def test_detect_linux_target_priority_and_validation(self):
        with mock.patch.dict(os.environ, {"RUST_TARGET": "aarch64-unknown-linux-gnu"}, clear=False):
            self.assertEqual(
                detect_linux_target("x86_64-unknown-linux-gnu"),
                "x86_64-unknown-linux-gnu",
            )
            self.assertEqual(detect_linux_target(), "aarch64-unknown-linux-gnu")

        rustc_info = "rustc 1.88.0\nhost: x86_64-unknown-linux-gnu\nrelease: 1.88.0\n"
        with (
            mock.patch.dict(os.environ, {"RUST_TARGET": ""}, clear=False),
            mock.patch("build_appimage.subprocess.check_output", return_value=rustc_info),
        ):
            self.assertEqual(detect_linux_target(), "x86_64-unknown-linux-gnu")

        with self.assertRaises(ValueError):
            detect_linux_target("x86_64-pc-windows-msvc")

    def test_verify_appimage_excludes_wayland(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_appimage = Path(temporary) / "PrismRay.AppImage"
            fake_appimage.write_text("appimage")

            def fake_extract_clean(cmd, cwd, env, stdout, stderr, text):
                self.assertEqual(cmd, [str(fake_appimage.resolve()), "--appimage-extract"])
                self.assertEqual(env["APPIMAGE_EXTRACT_AND_RUN"], "1")
                usr_lib = Path(cwd) / "squashfs-root" / "usr" / "lib"
                usr_lib.mkdir(parents=True)
                (usr_lib / "libgtk-3.so.0").write_text("ok")
                return subprocess.CompletedProcess(cmd, 0, stdout="")

            with mock.patch("build_appimage.subprocess.run", side_effect=fake_extract_clean):
                verify_appimage_excludes_wayland(fake_appimage)

            def fake_extract_with_wayland(cmd, cwd, env, stdout, stderr, text):
                usr_lib = Path(cwd) / "squashfs-root" / "usr" / "lib" / "x86_64-linux-gnu"
                usr_lib.mkdir(parents=True)
                (usr_lib / "libwayland-client.so.0").write_text("bad")
                return subprocess.CompletedProcess(cmd, 0, stdout="")

            with (
                mock.patch("build_appimage.subprocess.run", side_effect=fake_extract_with_wayland),
                self.assertRaisesRegex(RuntimeError, "libwayland-client.so"),
            ):
                verify_appimage_excludes_wayland(fake_appimage)

    def test_build_appimage_invocations_and_output_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "backend").mkdir()
            (root / "frontend" / "node_modules").mkdir(parents=True)
            (root / "scripts").mkdir()

            calls = []

            def fake_run(cmd, cwd=None, env=None, check=False, stdout=None, stderr=None, text=None):
                calls.append((cmd, Path(cwd), env or {}))
                if cmd[:2] == ["go", "build"]:
                    out_file = Path(cmd[cmd.index("-o") + 1])
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text("sidecar")
                    return subprocess.CompletedProcess(cmd, 0)
                if cmd[:4] == ["npm", "run", "tauri", "--"]:
                    target = cmd[cmd.index("--target") + 1]
                    bundle_dir = (
                        root
                        / "frontend"
                        / "src-tauri"
                        / "target"
                        / target
                        / "release"
                        / "bundle"
                        / "appimage"
                    )
                    bundle_dir.mkdir(parents=True, exist_ok=True)
                    (bundle_dir / "PrismRay_1.0.0_amd64.AppImage").write_bytes(b"ELF-appimage")
                    return subprocess.CompletedProcess(cmd, 0)
                if len(cmd) == 2 and cmd[1] == "--appimage-extract":
                    usr_lib = Path(cwd) / "squashfs-root" / "usr" / "lib"
                    usr_lib.mkdir(parents=True, exist_ok=True)
                    return subprocess.CompletedProcess(cmd, 0, stdout="")
                raise AssertionError(f"Unexpected subprocess command: {cmd}")

            clean_env = {
                k: v
                for k, v in os.environ.items()
                if k
                not in (
                    "UPDATER_PUBLIC_KEY",
                    "UPDATER_ENDPOINT",
                    "APPIMAGE_EXTRACT_AND_RUN",
                    "NO_STRIP",
                )
            }
            fake_runtime = root / "runtime-x86_64"
            fake_runtime.write_bytes(b"\x7fELF" + b"\x00" * 120_000)
            with (
                mock.patch("build_appimage.sys.platform", "linux"),
                mock.patch("build_appimage.shutil.which", return_value="/usr/bin/tool"),
                mock.patch("build_appimage.subprocess.run", side_effect=fake_run),
                mock.patch("build_appimage.ensure_appimage_runtime", return_value=fake_runtime),
                mock.patch.dict(os.environ, clean_env, clear=True),
            ):
                output = build_appimage(root, target="x86_64-unknown-linux-gnu")

            expected_output = root / "artifacts" / "prismray-linux-x64.AppImage"
            self.assertEqual(output, expected_output)
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
            self.assertEqual(output.read_bytes(), b"ELF-appimage")

            go_cmd, go_cwd, go_env = calls[0]
            self.assertEqual(go_cwd, root / "backend")
            self.assertEqual(go_env["CGO_ENABLED"], "0")
            self.assertEqual(go_env["GOOS"], "linux")
            self.assertEqual(go_env["GOARCH"], "amd64")
            self.assertIn("-ldflags=-s -w", go_cmd)

            tauri_cmd, tauri_cwd, tauri_env = calls[1]
            self.assertEqual(tauri_cwd, root / "frontend")
            self.assertEqual(tauri_env["APPIMAGE_EXTRACT_AND_RUN"], "1")
            self.assertEqual(tauri_env["NO_STRIP"], "true")
            self.assertEqual(tauri_env["LDAI_RUNTIME_FILE"], str(fake_runtime))
            self.assertIn("--ignore-version-mismatches", tauri_cmd)
            self.assertIn("appimage", tauri_cmd)
            self.assertEqual(tauri_cmd[-2:], ["--", "--locked"])

            extract_cmd, _, _ = calls[2]
            self.assertEqual(extract_cmd[1], "--appimage-extract")

    def test_ensure_appimage_runtime_reuses_cached_elf(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_dir = Path(temporary)
            cached = cache_dir / "runtime-x86_64"
            cached.write_bytes(b"\x7fELF" + b"\x00" * 120_000)
            with (
                mock.patch.dict(os.environ, {"LDAI_RUNTIME_FILE": ""}, clear=False),
                mock.patch("build_appimage.urllib.request.urlopen") as mock_open,
            ):
                resolved = ensure_appimage_runtime("x86_64-unknown-linux-gnu", cache_dir=cache_dir)
            self.assertEqual(resolved, cached)
            mock_open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
