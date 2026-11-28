# SPDX-License-Identifier: MPL-2.0
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_local_release as blr


class BuildLocalReleaseVersioningTests(unittest.TestCase):
    def test_monotonic_version_code_ordering(self):
        legacy_v101 = 1_000_001
        local_101_1 = blr.compute_android_version_code('1.0.1', 1)
        local_101_2 = blr.compute_android_version_code('1.0.1', 2)
        release_101 = blr.compute_android_version_code('1.0.1', None)
        local_102_1 = blr.compute_android_version_code('1.0.2', 1)
        release_102 = blr.compute_android_version_code('1.0.2', None)
        self.assertLess(legacy_v101, local_101_1)
        self.assertLess(local_101_1, local_101_2)
        self.assertLess(local_101_2, release_101)
        self.assertLess(release_101, local_102_1)
        self.assertLess(local_102_1, release_102)
        self.assertEqual(local_102_1, 10_002_001)
        self.assertEqual(release_102, 10_002_999)

    def test_next_local_build_seq_increments_and_resets_on_version_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / '.local_build_seq.json'
            self.assertEqual(blr.next_local_build_seq(state, '1.0.1'), 1)
            self.assertEqual(blr.next_local_build_seq(state, '1.0.1'), 2)
            self.assertEqual(blr.next_local_build_seq(state, '1.0.2'), 1)

    def test_bump_repo_version_syncs_all_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'frontend/src-tauri').mkdir(parents=True)
            (root / 'frontend/src/lib').mkdir(parents=True)
            (root / 'backend/internal/api').mkdir(parents=True)
            (root / 'frontend/package.json').write_text('{"name":"x","version":"1.0.1"}\n', encoding='utf-8')
            (root / 'frontend/package-lock.json').write_text(
                json.dumps({'name': 'x', 'version': '1.0.1', 'packages': {'': {'version': '1.0.1'}}}),
                encoding='utf-8',
            )
            (root / 'frontend/src-tauri/tauri.conf.json').write_text('{"version":"1.0.1"}\n', encoding='utf-8')
            (root / 'frontend/src-tauri/Cargo.toml').write_text(
                '[package]\nname = "prismray"\nversion = "1.0.1"\n[dependencies]\nfoo = { version = "0.1.0" }\n',
                encoding='utf-8',
            )
            (root / 'frontend/src/lib/i18n.ts').write_text(
                '"app.version": "v1.0.1",\n"app.version": "v1.0.1",\n',
                encoding='utf-8',
            )
            (root / 'backend/internal/api/app_update.go').write_text('const AppVersion = "1.0.1"\n', encoding='utf-8')

            updated = blr.bump_repo_version(root, 'v1.0.2')
            self.assertEqual(len(updated), 6)
            self.assertIn('"1.0.2"', (root / 'frontend/package.json').read_text(encoding='utf-8'))
            self.assertIn('version = "1.0.2"', (root / 'frontend/src-tauri/Cargo.toml').read_text(encoding='utf-8'))
            self.assertIn('foo = { version = "0.1.0" }', (root / 'frontend/src-tauri/Cargo.toml').read_text(encoding='utf-8'))
            self.assertIn('"v1.0.2"', (root / 'frontend/src/lib/i18n.ts').read_text(encoding='utf-8'))
            self.assertIn('AppVersion = "1.0.2"', (root / 'backend/internal/api/app_update.go').read_text(encoding='utf-8'))

    def test_format_versioned_artifact_names(self):
        self.assertEqual(
            blr.format_versioned_artifact_name('1.0.1-local.1', 'android-arm64.apk'),
            'prismray-v1.0.1-local.1-android-arm64.apk',
        )
        self.assertEqual(
            blr.format_versioned_artifact_name('v1.0.2', 'linux-x64-full.AppImage'),
            'prismray-v1.0.2-linux-x64-full.AppImage',
        )
        self.assertEqual(
            blr.format_versioned_artifact_name('1.0.2', 'headless-linux-arm64.tar.gz'),
            'prismray-v1.0.2-headless-linux-arm64.tar.gz',
        )


if __name__ == '__main__':
    unittest.main()
