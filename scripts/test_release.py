# SPDX-License-Identifier: MPL-2.0
import hashlib
from pathlib import Path
import tempfile
import unittest
from release import collect, validate_version, PLATFORMS


class ReleaseTests(unittest.TestCase):
    def test_complete_assets_and_latest_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            downloads = root / 'downloads'
            downloads.mkdir()
            for platform, suffixes in PLATFORMS.items():
                for attempt in (1, 2):
                    folder = downloads / f'prismray-{platform}-abc-{attempt}'
                    folder.mkdir()
                    for suffix in suffixes:
                        (folder / f'prismray-{platform}{suffix}').write_bytes(str(attempt).encode())
            assets = collect(downloads, root / 'out', 'abc')
            expected_count = sum(len(suffixes) for suffixes in PLATFORMS.values()) + 1
            self.assertEqual(len(assets), expected_count)
            self.assertEqual(assets[0].read_bytes(), b'2')
            self.assertIn(hashlib.sha256(b'2').hexdigest(), assets[-1].read_text())

    def test_incomplete_build_cannot_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                collect(root, root / 'out', 'abc')
            self.assertFalse((root / 'out').exists())

    def test_tag_must_match_all_versions(self):
        root = Path(__file__).resolve().parents[1]
        import json
        version = json.loads((root / 'frontend/package.json').read_text())['version']
        validate_version(root, 'v' + version)
        with self.assertRaises(ValueError):
            validate_version(root, 'v999.0.0')
        with self.assertRaises(ValueError):
            validate_version(root, 'main')


if __name__ == "__main__":
    unittest.main()
