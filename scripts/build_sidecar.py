#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build the matching Go sidecar before cargo check / Tauri builds."""
import os
import pathlib
import subprocess
root = pathlib.Path(__file__).resolve().parents[1]
target = os.environ.get('RUST_TARGET') or next(line.split(': ',1)[1] for line in subprocess.check_output(['rustc','-vV'],text=True).splitlines() if line.startswith('host:'))
ext = '.exe' if 'windows' in target else ''
out = root / 'frontend/src-tauri/binaries' / ('prismray-server-' + target + ext)
out.parent.mkdir(parents=True,exist_ok=True)
subprocess.run(['go','build','-trimpath',"-ldflags=-s -w",'-o',str(out),'./cmd/server'],cwd=root/'backend',check=True)
# Cargo check does not stage the executable; local development uses the same sibling layout.
if not os.environ.get('RUST_TARGET'):
 import shutil
 dev = root / 'frontend/src-tauri/target/debug'
 dev.mkdir(parents=True,exist_ok=True)
 shutil.copy2(out,dev / ('prismray-server'+ext))
