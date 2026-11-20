# SPDX-License-Identifier: MPL-2.0
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'scripts'))

import update_homebrew_cask as hb  # noqa: E402


class HomebrewCaskTests(unittest.TestCase):
    def test_parse_checksums_and_render_full_and_lite_casks(self):
        full_hash = 'a' * 64
        lite_hash = 'b' * 64
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sums = tmp_path / 'SHA256SUMS.txt'
            sums.write_text(
                f'{full_hash}  prismray-macos-arm64-full.dmg\n'
                f'{lite_hash}  prismray-macos-arm64-lite.dmg\n'
                f'{"c" * 64}  prismray-linux-x64-full.AppImage\n',
                encoding='utf-8',
            )
            parsed = hb.parse_checksums_file(sums)
            self.assertEqual(parsed['prismray-macos-arm64-full.dmg'], full_hash)
            self.assertEqual(parsed['prismray-macos-arm64-lite.dmg'], lite_hash)

            tap_dir = tmp_path / 'homebrew-tap'
            written = hb.update_tap_casks(
                tap_dir=tap_dir,
                version='v1.0.0',
                sha256_full=parsed['prismray-macos-arm64-full.dmg'],
                sha256_lite=parsed['prismray-macos-arm64-lite.dmg'],
            )
            self.assertEqual(len(written), 2)

            full_rb = (tap_dir / 'Casks' / 'prismray.rb').read_text(encoding='utf-8')
            self.assertIn('cask "prismray" do', full_rb)
            self.assertIn('version "1.0.0"', full_rb)
            self.assertIn(f'sha256 "{full_hash}"', full_rb)
            self.assertIn('depends_on arch: :arm64', full_rb)
            self.assertIn('prismray-macos-arm64-full.dmg', full_rb)
            self.assertIn('conflicts_with cask: "prismray-lite"', full_rb)
            self.assertIn('xattr -dr com.apple.quarantine', full_rb)

            lite_rb = (tap_dir / 'Casks' / 'prismray-lite.rb').read_text(encoding='utf-8')
            self.assertIn('cask "prismray-lite" do', lite_rb)
            self.assertIn(f'sha256 "{lite_hash}"', lite_rb)
            self.assertIn('conflicts_with cask: "prismray"', lite_rb)

    def test_rejects_invalid_sha_or_version(self):
        with self.assertRaises(ValueError):
            hb.normalize_version('1.0.0; rm -rf /')
        with self.assertRaises(ValueError):
            hb.render_cask(
                token='prismray',
                version='1.0.0',
                sha256='not-a-sha',
                asset_name='prismray-macos-arm64-full.dmg',
                conflict_token='prismray-lite',
                desc='test',
            )


if __name__ == '__main__':
    unittest.main()
