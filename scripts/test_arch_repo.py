# SPDX-License-Identifier: MPL-2.0
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'packaging' / 'arch'))

import build_repo  # noqa: E402


class ArchRepoTests(unittest.TestCase):
    def test_normalize_pkgver_and_pkgrel(self):
        self.assertEqual(build_repo.normalize_pkgver('v1.0.0'), '1.0.0')
        self.assertEqual(build_repo.normalize_pkgver('1.0.0-rc.1'), '1.0.0.rc.1')
        self.assertEqual(build_repo.validate_pkgrel('1'), '1')
        self.assertEqual(build_repo.validate_pkgrel('2.1'), '2.1')
        with self.assertRaises(ValueError):
            build_repo.normalize_pkgver('1.0.0;rm -rf /')
        with self.assertRaises(ValueError):
            build_repo.validate_pkgrel('bad')

    def test_stage_pkgbuilds_writes_exact_version_and_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tarball = tmp_path / 'sample.tar.gz'
            tarball.write_bytes(b'fake-archive-payload')
            out_dir = tmp_path / 'staged'
            meta = build_repo.stage_pkgbuilds(
                repo_root=REPO_ROOT,
                out_dir=out_dir,
                version='v1.2.3-rc1',
                pkgrel='2',
                tarball=tarball,
            )
            self.assertEqual(meta['pkgver'], '1.2.3.rc1')
            self.assertEqual(meta['pkgrel'], '2')
            for pkg in ('prismray', 'prismray-server'):
                pkgbuild = (out_dir / pkg / 'PKGBUILD').read_text(encoding='utf-8')
                self.assertIn('pkgver=1.2.3.rc1', pkgbuild)
                self.assertIn('pkgrel=2', pkgbuild)
                self.assertIn(f"sha256sums=('{meta['sha256']}')", pkgbuild)
                self.assertTrue((out_dir / pkg / 'PrismRay-1.2.3.rc1.tar.gz').is_file())

    def test_dereference_symlinks_and_render_unsigned_and_signed_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pkg_dir = tmp_path / 'pkgs'
            pkg_dir.mkdir()
            (pkg_dir / 'prismray-1.0.0-1-x86_64.pkg.tar.zst').write_bytes(b'desktop-pkg')
            (pkg_dir / 'prismray-server-1.0.0-1-x86_64.pkg.tar.zst').write_bytes(b'server-pkg')

            site_unsigned = tmp_path / 'site-unsigned'
            arch_dir = site_unsigned / 'arch' / 'x86_64'
            arch_dir.mkdir(parents=True)
            (arch_dir / 'prismray.db.tar.gz').write_bytes(b'db-bytes')
            (arch_dir / 'prismray.db').symlink_to('prismray.db.tar.gz')
            (arch_dir / 'prismray.db.tar.gz.old').write_bytes(b'old-db')

            result = build_repo.build_site(
                pkg_dir=pkg_dir,
                site_dir=site_unsigned,
                version='1.0.0',
                commit='abcdef1234567890',
                skip_repo_add=True,
            )
            self.assertFalse(result['signed'])
            self.assertIn('prismray.db', result['dereferenced'])
            self.assertFalse((arch_dir / 'prismray.db').is_symlink())
            self.assertEqual((arch_dir / 'prismray.db').read_bytes(), b'db-bytes')
            self.assertFalse((arch_dir / 'prismray.db.tar.gz.old').exists())
            self.assertTrue((site_unsigned / '.nojekyll').is_file())
            html_unsigned = (site_unsigned / 'index.html').read_text(encoding='utf-8')
            self.assertIn('SigLevel = Optional TrustAll', html_unsigned)
            self.assertIn('prismray-1.0.0-1-x86_64.pkg.tar.zst', html_unsigned)
            self.assertIn('prismray-server-1.0.0-1-x86_64.pkg.tar.zst', html_unsigned)
            self.assertIn('SHA256SUMS.txt', html_unsigned)

            # Signed variant
            (pkg_dir / 'prismray-1.0.0-1-x86_64.pkg.tar.zst.sig').write_bytes(b'sig-bytes')
            site_signed = tmp_path / 'site-signed'
            result_signed = build_repo.build_site(
                pkg_dir=pkg_dir,
                site_dir=site_signed,
                version='1.0.0',
                commit='abcdef1234567890',
                gpg_key_id='DEADBEEF12345678',
                gpg_fingerprint='0123456789ABCDEF0123456789ABCDEFDEADBEEF',
                skip_repo_add=True,
            )
            self.assertTrue(result_signed['signed'])
            html_signed = (site_signed / 'index.html').read_text(encoding='utf-8')
            self.assertIn('SigLevel = Required DatabaseOptional', html_signed)
            self.assertIn('pacman-key --lsign-key 0123456789ABCDEF0123456789ABCDEFDEADBEEF', html_signed)
            checksums = (site_signed / 'arch' / 'x86_64' / 'SHA256SUMS.txt').read_text(encoding='utf-8')
            self.assertIn('prismray-1.0.0-1-x86_64.pkg.tar.zst.sig', checksums)

    def test_incremental_multi_project_merge_preserves_other_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            existing = tmp_path / 'existing-site'
            existing_arch = existing / 'arch' / 'x86_64'
            existing_arch.mkdir(parents=True)
            (existing / 'CNAME').write_text('arch.example.org\n', encoding='utf-8')
            (existing / 'arch' / 'aarch64').mkdir(parents=True)
            (existing / 'arch' / 'aarch64' / 'arm-tool-1.0.0-1-aarch64.pkg.tar.zst').write_bytes(b'arm-pkg')
            (existing_arch / 'prismray-0.9.0-1-x86_64.pkg.tar.zst').write_bytes(b'old-prismray')
            (existing_arch / 'other-app-2.1.0-1-x86_64.pkg.tar.zst').write_bytes(b'other-project-pkg')
            (existing_arch / 'other-app-2.1.0-1-x86_64.pkg.tar.zst.sig').write_bytes(b'other-sig')

            new_pkg_dir = tmp_path / 'new-pkgs'
            new_pkg_dir.mkdir()
            (new_pkg_dir / 'prismray-1.0.0-1-x86_64.pkg.tar.zst').write_bytes(b'new-prismray')
            (new_pkg_dir / 'prismray-server-1.0.0-1-x86_64.pkg.tar.zst').write_bytes(b'new-server')

            merged_site = tmp_path / 'merged-site'
            result = build_repo.build_site(
                pkg_dir=new_pkg_dir,
                site_dir=merged_site,
                repo_name='crackrammer',
                pages_url='https://crackrammer.github.io/arch-repo',
                version='1.0.0',
                commit='1234567890abcdef',
                skip_repo_add=True,
                existing_site_dir=existing,
            )
            self.assertEqual(
                result['packages'],
                [
                    'other-app-2.1.0-1-x86_64.pkg.tar.zst',
                    'prismray-1.0.0-1-x86_64.pkg.tar.zst',
                    'prismray-server-1.0.0-1-x86_64.pkg.tar.zst',
                ],
            )
            merged_arch = merged_site / 'arch' / 'x86_64'
            self.assertFalse((merged_arch / 'prismray-0.9.0-1-x86_64.pkg.tar.zst').exists())
            self.assertTrue((merged_arch / 'other-app-2.1.0-1-x86_64.pkg.tar.zst.sig').is_file())
            self.assertEqual((merged_site / 'CNAME').read_text(encoding='utf-8'), 'arch.example.org\n')
            self.assertTrue((merged_site / 'arch' / 'aarch64' / 'arm-tool-1.0.0-1-aarch64.pkg.tar.zst').is_file())
            html_merged = (merged_site / 'index.html').read_text(encoding='utf-8')
            self.assertIn('[crackrammer]', html_merged)
            self.assertIn('https://crackrammer.github.io/arch-repo/arch/$arch', html_merged)
            self.assertIn('other-app-2.1.0-1-x86_64.pkg.tar.zst', html_merged)


if __name__ == '__main__':
    unittest.main()
