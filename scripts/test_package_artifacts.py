# SPDX-License-Identifier: MPL-2.0
from pathlib import Path
import tempfile
import unittest

from package_artifacts import PLATFORMS, package


class PackageTests(unittest.TestCase):
    def fixture(self, root: Path, platform: str):
        target, suffixes = PLATFORMS[platform]
        (root / "nodes.json").write_text("private data")
        if platform == "android-arm64":
            apk_dir = (
                root
                / "frontend"
                / "src-tauri"
                / "gen"
                / "android"
                / "app"
                / "build"
                / "outputs"
                / "apk"
                / "universal"
                / "debug"
            )
            apk_dir.mkdir(parents=True)
            (apk_dir / "app-universal-debug.apk").write_bytes(b"apk-binary")
            return target, apk_dir
        bundle = root / "frontend" / "src-tauri" / "target" / target / "release" / "bundle"
        bundle.mkdir(parents=True)
        for suffix in suffixes:
            (bundle / f"installer{suffix}").write_bytes(f"installer-{suffix}".encode())
        return target, bundle

    def test_exports_standalone_installers_for_every_platform(self):
        for platform, (_, suffixes) in PLATFORMS.items():
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target, _ = self.fixture(root, platform)
                results = package(root, platform, target)
                self.assertEqual([p.name for p in results], [f"prismray-{platform}{s}" for s in suffixes])
                for path in results:
                    self.assertTrue(path.is_file())
                    self.assertGreater(path.stat().st_size, 0)
                    if path.suffix == ".AppImage":
                        self.assertEqual(path.stat().st_mode & 0o777, 0o755)
                self.assertFalse((root / "artifacts" / "nodes.json").exists())

    def test_supports_lite_and_full_variants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, _ = self.fixture(root, "windows-x64")
            lite = package(root, "windows-x64", target, variant="lite")
            full = package(root, "windows-x64", target, variant="full")
            self.assertEqual([p.name for p in lite], ["prismray-windows-x64-lite.exe", "prismray-windows-x64-lite.msi"])
            self.assertEqual([p.name for p in full], ["prismray-windows-x64-full.exe", "prismray-windows-x64-full.msi"])

    def test_missing_installer_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, bundle = self.fixture(root, "linux-x64")
            (bundle / "installer.rpm").unlink()
            with self.assertRaises(FileNotFoundError):
                package(root, "linux-x64", target)

    def test_missing_windows_msi_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, bundle = self.fixture(root, "windows-x64")
            (bundle / "installer.msi").unlink()
            with self.assertRaises(FileNotFoundError):
                package(root, "windows-x64", target)

    def test_missing_android_apk_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, apk_dir = self.fixture(root, "android-arm64")
            (apk_dir / "app-universal-debug.apk").unlink()
            with self.assertRaises(FileNotFoundError):
                package(root, "android-arm64", target)

    def test_mismatched_target_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, "windows-x64")
            with self.assertRaises(ValueError):
                package(root, "windows-x64", "aarch64-apple-darwin")


if __name__ == "__main__":
    unittest.main()
