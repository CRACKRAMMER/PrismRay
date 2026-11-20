#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build a portable Linux headless server + static Web UI archive."""
import argparse
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile


def build_headless(
    root: pathlib.Path,
    *,
    goos: str | None = None,
    goarch: str | None = None,
    platform: str | None = None,
    web_dist: pathlib.Path | None = None,
    output_dir: pathlib.Path | None = None,
) -> pathlib.Path:
    env = os.environ.copy()
    env['CGO_ENABLED'] = '0'
    if not goos:
        goos = subprocess.check_output(['go', 'env', 'GOOS'], env=env, text=True).strip()
    if not goarch:
        goarch = subprocess.check_output(['go', 'env', 'GOARCH'], env=env, text=True).strip()
    env['GOOS'] = goos
    env['GOARCH'] = goarch

    if not platform:
        arch_label = 'x64' if goarch == 'amd64' else goarch
        platform = f'{goos}-{arch_label}'

    if web_dist is None:
        subprocess.run(['npm', 'ci', '--no-audit', '--no-fund'], cwd=root / 'frontend', check=True)
        subprocess.run(['npm', 'run', 'build'], cwd=root / 'frontend', check=True)
        web_dist = root / 'frontend/dist'
    elif not web_dist.is_absolute():
        web_dist = root / web_dist

    if not (web_dist / 'index.html').is_file():
        raise FileNotFoundError(f'Missing built Web entrypoint: {web_dist / "index.html"}')

    output = output_dir if output_dir is not None else (root / 'artifacts/headless')
    if not output.is_absolute():
        output = root / output
    output.mkdir(parents=True, exist_ok=True)

    folder_name = f'prismray-headless-{platform}'
    archive_path = output / f'{folder_name}.tar.gz'

    with tempfile.TemporaryDirectory(prefix='prismray-headless-') as temporary:
        staging = pathlib.Path(temporary) / folder_name
        staging.mkdir()

        binary_name = 'prismray-server.exe' if goos == 'windows' else 'prismray-server'
        binary = staging / binary_name
        subprocess.run(
            ['go', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary), './cmd/server'],
            cwd=root / 'backend',
            env=env,
            check=True,
        )
        if goos != 'windows':
            binary.chmod(0o755)

        shutil.copytree(web_dist, staging / 'web')
        for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
            shutil.copy2(root / name, staging / name)
        shutil.copy2(root / 'docs/HEADLESS.md', staging / 'README.md')
        shutil.copy2(root / 'packaging/prismray-server.service', staging / 'prismray-server.service')
        (staging / 'SOURCE_COMMIT.txt').write_text(os.environ.get('GITHUB_SHA', 'local') + '\n')

        with tarfile.open(archive_path, 'w:gz') as archive:
            archive.add(staging, arcname=folder_name)

    return archive_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goos', default=None, help='Target GOOS (defaults to host go env GOOS)')
    parser.add_argument('--goarch', default=None, help='Target GOARCH (defaults to host go env GOARCH)')
    parser.add_argument('--platform', default=None, help='Output archive platform suffix (e.g. linux-x64)')
    parser.add_argument('--web-dist', type=pathlib.Path, default=None, help='Reuse an existing frontend/dist directory')
    parser.add_argument('--output-dir', type=pathlib.Path, default=None, help='Destination directory for .tar.gz')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    print(
        build_headless(
            root,
            goos=args.goos,
            goarch=args.goarch,
            platform=args.platform,
            web_dist=args.web_dist,
            output_dir=args.output_dir,
        )
    )


if __name__ == '__main__':
    main()
