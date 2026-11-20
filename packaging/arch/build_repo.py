#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Stage Arch Linux PKGBUILDs and build a static GitHub Pages Pacman repository."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


PACKAGES = ('prismray', 'prismray-server')
PKG_FILENAME_RE = re.compile(r'^(?P<name>.+)-[^-]+-[^-]+-[^-]+\.pkg\.tar(?:\.[A-Za-z0-9]+)?$')


def parse_arch_pkgname(filename: str) -> str:
    """Extract Arch package name from <pkgname>-<pkgver>-<pkgrel>-<arch>.pkg.tar.*."""
    m = PKG_FILENAME_RE.match(filename)
    if m:
        return m.group('name')
    return filename


def normalize_pkgver(raw: str) -> str:
    cleaned = raw.strip().lstrip('v').replace('-', '.')
    if not re.fullmatch(r'[0-9A-Za-z._+]+', cleaned):
        raise ValueError(f'Invalid Arch pkgver: {raw!r}')
    return cleaned


def validate_pkgrel(raw: str) -> str:
    cleaned = raw.strip()
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', cleaned):
        raise ValueError(f'Invalid Arch pkgrel: {raw!r}')
    return cleaned


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def format_size(num_bytes: int) -> str:
    units = ('B', 'KiB', 'MiB', 'GiB')
    value = float(num_bytes)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f'{value:.2f} {unit}' if unit != 'B' else f'{int(value)} B'
        value /= 1024.0
    return f'{num_bytes} B'


def read_project_version(repo_root: Path) -> str:
    package_json = repo_root / 'frontend' / 'package.json'
    return json.loads(package_json.read_text(encoding='utf-8'))['version']


def rewrite_pkgbuild(text: str, pkgver: str, pkgrel: str, tarball_sha256: str) -> str:
    out, count_ver = re.subn(r'^pkgver=.*$', f'pkgver={pkgver}', text, count=1, flags=re.M)
    out, count_rel = re.subn(r'^pkgrel=.*$', f'pkgrel={pkgrel}', out, count=1, flags=re.M)
    out, count_sum = re.subn(
        r"^sha256sums=\('[^']*'\)$",
        f"sha256sums=('{tarball_sha256}')",
        out,
        count=1,
        flags=re.M,
    )
    if not (count_ver == 1 and count_rel == 1 and count_sum == 1):
        raise ValueError('PKGBUILD template is missing pkgver, pkgrel, or sha256sums')
    return out


def stage_pkgbuilds(
    repo_root: Path,
    out_dir: Path,
    version: str | None = None,
    pkgrel: str = '1',
    tarball: Path | None = None,
) -> dict[str, str]:
    raw_version = version or read_project_version(repo_root)
    pkgver = normalize_pkgver(raw_version)
    rel = validate_pkgrel(pkgrel)
    out_dir.mkdir(parents=True, exist_ok=True)

    tarball_name = f'PrismRay-{pkgver}.tar.gz'
    staged_tarball = out_dir / tarball_name
    if tarball is not None:
        if tarball.resolve() != staged_tarball.resolve():
            shutil.copy2(tarball, staged_tarball)
    else:
        subprocess.run(
            [
                'git',
                '-C',
                str(repo_root),
                'archive',
                '--format=tar.gz',
                f'--prefix=PrismRay-{pkgver}/',
                '-o',
                str(staged_tarball),
                'HEAD',
            ],
            check=True,
        )

    tarball_hash = sha256_file(staged_tarball)
    for pkg in PACKAGES:
        src_pkgbuild = repo_root / 'packaging' / 'arch' / pkg / 'PKGBUILD'
        if not src_pkgbuild.is_file():
            raise FileNotFoundError(f'Missing PKGBUILD template: {src_pkgbuild}')
        pkg_dir = out_dir / pkg
        pkg_dir.mkdir(parents=True, exist_ok=True)
        rendered = rewrite_pkgbuild(src_pkgbuild.read_text(encoding='utf-8'), pkgver, rel, tarball_hash)
        (pkg_dir / 'PKGBUILD').write_text(rendered, encoding='utf-8')
        pkg_tarball = pkg_dir / tarball_name
        if pkg_tarball.exists():
            pkg_tarball.unlink()
        shutil.copy2(staged_tarball, pkg_tarball)

    return {
        'pkgver': pkgver,
        'pkgrel': rel,
        'tarball': str(staged_tarball),
        'sha256': tarball_hash,
    }


def dereference_repo_symlinks(repo_arch_dir: Path) -> list[str]:
    """Replace repo-add symlinks with regular files for static HTTP hosting (GitHub Pages)."""
    replaced: list[str] = []
    for entry in sorted(repo_arch_dir.iterdir()):
        if entry.name.endswith('.old') or entry.name.endswith('.old.sig'):
            entry.unlink()
            continue
    for entry in sorted(repo_arch_dir.iterdir()):
        if entry.is_symlink():
            target = entry.resolve(strict=True)
            if target.parent != repo_arch_dir.resolve():
                raise ValueError(f'Refusing to dereference symlink outside repo dir: {entry} -> {target}')
            data = target.read_bytes()
            entry.unlink()
            entry.write_bytes(data)
            replaced.append(entry.name)
    return replaced


def render_index_html(
    *,
    repo_name: str,
    arch: str,
    pages_url: str,
    version: str,
    commit: str,
    signed: bool,
    gpg_fingerprint: str,
    packages: list[dict[str, str]],
    updated_utc: str,
) -> str:
    base_url = pages_url.rstrip('/')
    sig_level = 'Required DatabaseOptional' if signed else 'Optional TrustAll'
    pacman_conf = (
        f'[{repo_name}]\n'
        f'SigLevel = {sig_level}\n'
        f'Server = {base_url}/arch/$arch'
    )
    gpg_section = ''
    if signed:
        fp_display = html.escape(gpg_fingerprint or f'see {repo_name}.gpg')
        gpg_cmd = (
            f'curl -fsSL {base_url}/{repo_name}.gpg | sudo pacman-key --add -\n'
            f'sudo pacman-key --lsign-key {gpg_fingerprint or "<KEY_FINGERPRINT>"}'
        )
        gpg_section = f'''
      <section class="card">
        <h2>1. Trust Repository GPG Key / 导入签名公钥</h2>
        <p class="muted">Packages and database metadata are GPG-signed. Fingerprint: <code>{fp_display}</code></p>
        <pre><code>{html.escape(gpg_cmd)}</code></pre>
        <p><a class="btn" href="./{html.escape(repo_name)}.gpg">Download {html.escape(repo_name)}.gpg</a></p>
      </section>'''
    else:
        gpg_section = f'''
      <section class="card notice">
        <h2>Transport Security Note / 安全说明</h2>
        <p class="muted">This repository is currently served over HTTPS without a repository GPG key (<code>SigLevel = Optional TrustAll</code>). Once the maintainer adds <code>ARCH_GPG_PRIVATE_KEY</code> to GitHub Actions secrets, signed packages and <code>{html.escape(repo_name)}.gpg</code> will be published here automatically.</p>
      </section>'''

    step_conf = '2' if signed else '1'
    step_install = '3' if signed else '2'
    rows = '\n'.join(
        f'          <tr>'
        f'<td><a href="./arch/{html.escape(arch)}/{html.escape(pkg["name"])}"><code>{html.escape(pkg["name"])}</code></a></td>'
        f'<td>{html.escape(pkg["size"])}</td>'
        f'<td><code class="hash">{html.escape(pkg["sha256"])}</code></td>'
        f'</tr>'
        for pkg in packages
    )
    commit_short = html.escape(commit[:12]) if commit else 'unknown'
    is_dedicated_prismray = repo_name == 'prismray'
    page_title = (
        'PrismRay Arch Linux Pacman Repository'
        if is_dedicated_prismray
        else f'{repo_name} Arch Linux Pacman Repository'
    )
    page_subtitle = (
        'Official static Pacman repository built natively on Arch Linux for <code>prismray</code> (Desktop) and <code>prismray-server</code> (Headless Web).'
        if is_dedicated_prismray
        else 'Unified multi-project Arch Linux Pacman repository maintained by CRACKRAMMER, built natively inside <code>archlinux:base-devel</code>.'
    )
    repo_link_url = (
        'https://github.com/CRACKRAMMER/PrismRay'
        if is_dedicated_prismray
        else 'https://github.com/CRACKRAMMER/arch-repo'
    )
    repo_link_label = 'GitHub Repository' if is_dedicated_prismray else 'CRACKRAMMER/arch-repo'
    return f'''<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{html.escape(page_title)}</title>
    <style>
      :root {{
        color-scheme: light dark;
        --bg: #f8fafc;
        --card: #ffffff;
        --fg: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --accent: #4f46e5;
        --code-bg: #f1f5f9;
      }}
      @media (prefers-color-scheme: dark) {{
        :root {{
          --bg: #0b1120;
          --card: #111827;
          --fg: #f8fafc;
          --muted: #94a3b8;
          --border: #1e293b;
          --accent: #818cf8;
          --code-bg: #0f172a;
        }}
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: var(--bg);
        color: var(--fg);
        line-height: 1.6;
      }}
      main {{
        max-width: 900px;
        margin: 0 auto;
        padding: 2.5rem 1.25rem 4rem;
      }}
      header {{ margin-bottom: 1.75rem; }}
      h1 {{ margin: 0 0 0.5rem; font-size: 1.9rem; }}
      h2 {{ margin: 0 0 0.75rem; font-size: 1.15rem; }}
      p {{ margin: 0 0 0.85rem; }}
      .muted {{ color: var(--muted); font-size: 0.94rem; }}
      .badges {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem; }}
      .badge {{
        display: inline-block;
        padding: 0.2rem 0.65rem;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: var(--card);
        font-size: 0.82rem;
        color: var(--muted);
      }}
      .card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1.15rem;
      }}
      pre {{
        margin: 0.5rem 0 0.75rem;
        padding: 0.9rem 1rem;
        border-radius: 10px;
        background: var(--code-bg);
        border: 1px solid var(--border);
        overflow-x: auto;
      }}
      code {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.88rem;
      }}
      .hash {{ font-size: 0.78rem; word-break: break-all; }}
      table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
      th, td {{
        text-align: left;
        padding: 0.6rem 0.5rem;
        border-bottom: 1px solid var(--border);
        vertical-align: top;
      }}
      th {{ color: var(--muted); font-weight: 600; }}
      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .btn {{
        display: inline-block;
        padding: 0.45rem 0.85rem;
        border-radius: 8px;
        border: 1px solid var(--border);
        background: var(--code-bg);
        font-size: 0.88rem;
      }}
    </style>
  </head>
  <body>
    <main>
      <header>
        <h1>{html.escape(page_title)}</h1>
        <p class="muted">{page_subtitle}</p>
        <div class="badges">
          <span class="badge">Version: {html.escape(version)}</span>
          <span class="badge">Arch: {html.escape(arch)}</span>
          <span class="badge">Commit: {commit_short}</span>
          <span class="badge">Signing: {"GPG Signed" if signed else "HTTPS Unsigned"}</span>
          <span class="badge">Updated: {html.escape(updated_utc)}</span>
        </div>
      </header>
{gpg_section}
      <section class="card">
        <h2>{step_conf}. Add Repository to <code>/etc/pacman.conf</code> / 添加软件源</h2>
        <pre><code>{html.escape(pacman_conf)}</code></pre>
      </section>

      <section class="card">
        <h2>{step_install}. Install or Upgrade with Pacman / 安装与更新</h2>
        <pre><code># Desktop client (Tauri v2 + Go sidecar)
sudo pacman -Syu prismray

# Headless Web server + systemd user unit (optional)
sudo pacman -Syu prismray-server</code></pre>
      </section>

      <section class="card">
        <h2>Published Packages (<code>{html.escape(arch)}</code>) / 当前已发布软件包</h2>
        <table>
          <thead>
            <tr><th>Package</th><th>Size</th><th>SHA-256</th></tr>
          </thead>
          <tbody>
{rows}
          </tbody>
        </table>
        <p class="muted" style="margin-top: 0.9rem;">
          <a href="./arch/{html.escape(arch)}/SHA256SUMS.txt">SHA256SUMS.txt</a> ·
          <a href="./arch/{html.escape(arch)}/{html.escape(repo_name)}.db">{html.escape(repo_name)}.db</a> ·
          <a href="{html.escape(repo_link_url)}">{html.escape(repo_link_label)}</a>
        </p>
      </section>
    </main>
  </body>
</html>
'''


def build_site(
    *,
    pkg_dir: Path,
    site_dir: Path,
    arch: str = 'x86_64',
    repo_name: str = 'prismray',
    pages_url: str = 'https://crackrammer.github.io/PrismRay',
    version: str = '1.0.0',
    commit: str = '',
    gpg_key_id: str = '',
    gpg_fingerprint: str = '',
    skip_repo_add: bool = False,
    existing_site_dir: Path | None = None,
) -> dict[str, object]:
    new_pkgs = sorted(
        p for p in pkg_dir.iterdir()
        if p.is_file() and p.name.endswith('.pkg.tar.zst') and not p.name.endswith('.sig')
    )
    if not new_pkgs:
        raise FileNotFoundError(f'No .pkg.tar.zst packages found in {pkg_dir}')

    repo_arch_dir = site_dir / 'arch' / arch
    repo_arch_dir.mkdir(parents=True, exist_ok=True)

    new_pkgnames = {parse_arch_pkgname(p.name) for p in new_pkgs}
    retained_pkgs: list[Path] = []
    if existing_site_dir is not None:
        existing_cname = existing_site_dir / 'CNAME'
        if existing_cname.is_file():
            shutil.copy2(existing_cname, site_dir / 'CNAME')
        existing_arch_root = existing_site_dir / 'arch'
        if existing_arch_root.is_dir():
            for other_arch in sorted(existing_arch_root.iterdir()):
                if other_arch.is_dir() and other_arch.name != arch:
                    shutil.copytree(other_arch, site_dir / 'arch' / other_arch.name, dirs_exist_ok=True)
        existing_arch_dir = existing_arch_root / arch
        if existing_arch_dir.is_dir():
            for old_pkg in sorted(existing_arch_dir.iterdir()):
                if not (old_pkg.is_file() and old_pkg.name.endswith('.pkg.tar.zst') and not old_pkg.name.endswith('.sig')):
                    continue
                if parse_arch_pkgname(old_pkg.name) in new_pkgnames:
                    # Drop previous versions of packages being updated in this run.
                    continue
                dest = repo_arch_dir / old_pkg.name
                shutil.copy2(old_pkg, dest)
                retained_pkgs.append(dest)
                old_sig = old_pkg.with_name(old_pkg.name + '.sig')
                if old_sig.is_file():
                    shutil.copy2(old_sig, repo_arch_dir / old_sig.name)

    copied_pkgs: list[Path] = list(retained_pkgs)
    for pkg in new_pkgs:
        dest = repo_arch_dir / pkg.name
        shutil.copy2(pkg, dest)
        copied_pkgs.append(dest)
        sig = pkg.with_name(pkg.name + '.sig')
        if sig.is_file():
            shutil.copy2(sig, repo_arch_dir / sig.name)
    copied_pkgs = sorted(copied_pkgs, key=lambda p: p.name)

    signed = bool(gpg_key_id)
    db_path = repo_arch_dir / f'{repo_name}.db.tar.gz'
    if not skip_repo_add:
        cmd = ['repo-add']
        if signed:
            cmd.extend(['--sign', '--key', gpg_key_id])
        cmd.append(str(db_path))
        cmd.extend(str(p) for p in copied_pkgs)
        subprocess.run(cmd, check=True)

    replaced_symlinks = dereference_repo_symlinks(repo_arch_dir)

    if signed and not skip_repo_add:
        pub = subprocess.check_output(['gpg', '--armor', '--export', gpg_key_id])
        if not pub.strip():
            raise RuntimeError(f'Failed to export public GPG key for {gpg_key_id}')
        (site_dir / f'{repo_name}.gpg').write_bytes(pub)

    package_meta: list[dict[str, str]] = []
    checksum_lines: list[str] = []
    for pkg in copied_pkgs:
        digest = sha256_file(pkg)
        package_meta.append({
            'name': pkg.name,
            'size': format_size(pkg.stat().st_size),
            'sha256': digest,
        })
        checksum_lines.append(f'{digest}  {pkg.name}\n')
        sig = pkg.with_name(pkg.name + '.sig')
        if sig.is_file():
            checksum_lines.append(f'{sha256_file(sig)}  {sig.name}\n')

    (repo_arch_dir / 'SHA256SUMS.txt').write_text(''.join(checksum_lines), encoding='utf-8')
    (site_dir / '.nojekyll').write_text('', encoding='utf-8')

    updated_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    index_html = render_index_html(
        repo_name=repo_name,
        arch=arch,
        pages_url=pages_url,
        version=version,
        commit=commit,
        signed=signed,
        gpg_fingerprint=gpg_fingerprint or gpg_key_id,
        packages=package_meta,
        updated_utc=updated_utc,
    )
    (site_dir / 'index.html').write_text(index_html, encoding='utf-8')

    return {
        'packages': [p.name for p in copied_pkgs],
        'signed': signed,
        'dereferenced': replaced_symlinks,
        'site_dir': str(site_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Build Arch Linux packages and static Pacman repository.')
    sub = parser.add_subparsers(dest='command', required=True)

    p_stage = sub.add_parser('stage-pkgbuilds', help='Create source tarball and render PKGBUILDs')
    p_stage.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[2])
    p_stage.add_argument('--out-dir', type=Path, required=True)
    p_stage.add_argument('--version', default=None)
    p_stage.add_argument('--pkgrel', default='1')
    p_stage.add_argument('--tarball', type=Path, default=None)

    p_site = sub.add_parser('build-site', help='Generate Pacman DB, dereference symlinks, and render index.html')
    p_site.add_argument('--pkg-dir', type=Path, required=True)
    p_site.add_argument('--site-dir', type=Path, required=True)
    p_site.add_argument('--arch', default='x86_64')
    p_site.add_argument('--repo-name', default='prismray')
    p_site.add_argument('--pages-url', default='https://crackrammer.github.io/PrismRay')
    p_site.add_argument('--version', default='1.0.0')
    p_site.add_argument('--commit', default='')
    p_site.add_argument('--gpg-key-id', default='')
    p_site.add_argument('--gpg-fingerprint', default='')
    p_site.add_argument('--skip-repo-add', action='store_true')
    p_site.add_argument('--existing-site-dir', type=Path, default=None)

    args = parser.parse_args(argv)
    if args.command == 'stage-pkgbuilds':
        result = stage_pkgbuilds(
            repo_root=args.repo_root,
            out_dir=args.out_dir,
            version=args.version,
            pkgrel=args.pkgrel,
            tarball=args.tarball,
        )
        print(json.dumps(result, indent=2))
        return 0
    if args.command == 'build-site':
        result = build_site(
            pkg_dir=args.pkg_dir,
            site_dir=args.site_dir,
            arch=args.arch,
            repo_name=args.repo_name,
            pages_url=args.pages_url,
            version=args.version,
            commit=args.commit,
            gpg_key_id=args.gpg_key_id,
            gpg_fingerprint=args.gpg_fingerprint,
            skip_repo_add=args.skip_repo_add,
            existing_site_dir=args.existing_site_dir,
        )
        print(json.dumps(result, indent=2))
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
