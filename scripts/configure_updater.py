#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Generate a public Tauri config overlay; private signing keys remain in CI env."""
import json
import os
from pathlib import Path
from urllib.parse import urlparse
key = os.environ.get('UPDATER_PUBLIC_KEY', '').strip()
endpoint = os.environ.get('UPDATER_ENDPOINT', '').strip()
config = {}
if key or endpoint:
    if not key or urlparse(endpoint).scheme != 'https':
        raise SystemExit('Set both UPDATER_PUBLIC_KEY and an HTTPS UPDATER_ENDPOINT')
    if not os.environ.get('TAURI_SIGNING_PRIVATE_KEY'):
        raise SystemExit('Signing key is required when generating updater artifacts')
    config = {'bundle': {'createUpdaterArtifacts': True}, 'plugins': {'updater': {'pubkey': key, 'endpoints': [endpoint]}}}
path = Path(__file__).resolve().parents[1] / 'frontend/src-tauri/updater.generated.json'
path.write_text(json.dumps(config, indent=2) + '\n')
