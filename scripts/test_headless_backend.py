#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Test production Web assets and API with no display, desktop bus or stdin."""
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import http.cookiejar


def main():
    binary = pathlib.Path(os.environ['PRISMRAY_TEST_BINARY']).resolve()
    web = pathlib.Path(os.environ['PRISMRAY_WEB_DIR']).resolve()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='prismray-headless-test-') as directory:
        pathlib.Path(directory, 'settings.json').write_text(json.dumps({'server': {'host': '127.0.0.1', 'port': port}}))
        env = os.environ.copy()
        env['PRISMRAY_BOOTSTRAP_TOKEN'] = 'headless-test-bootstrap'
        for key in ('DISPLAY', 'WAYLAND_DISPLAY', 'DBUS_SESSION_BUS_ADDRESS'):
            env.pop(key, None)
        process = subprocess.Popen([str(binary), '--web-dir', str(web)], cwd=directory,
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        endpoint = f'http://127.0.0.1:{port}'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        try:
            for _ in range(100):
                try:
                    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(endpoint, timeout=1) as response:
                        html = response.read().decode()
                    break
                except (urllib.error.URLError, ConnectionError):
                    assert process.poll() is None, 'headless backend exited'
                    time.sleep(0.1)
            else:
                raise AssertionError('headless startup timeout')
            assert 'PrismRay' in html and '<script' in html
            assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', html)
            assert assets
            for asset in assets:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(endpoint + asset, timeout=5) as response:
                    data = response.read()
                    assert response.status == 200 and len(data) > 0
                    if asset.endswith(".css"):
                        assert not re.search(rb"@import[^;]*https?://", data), "render-blocking external CSS import"
            init = urllib.request.Request(endpoint + '/api/auth/initialize',
                data=json.dumps({'password': 'headless-test-password', 'bootstrap_token': 'headless-test-bootstrap'}).encode(),
                headers={'Content-Type': 'application/json', 'Origin': endpoint})
            with opener.open(init, timeout=10) as response:
                assert json.load(response)['unlocked'] is True
            req = urllib.request.Request(endpoint + '/api/subscription/import',
                data=json.dumps({'content': 'proxies:\n - {type: trojan, name: Test, server: example.invalid, port: 443, password: test-only}'}).encode(),
                headers={'Content-Type': 'application/json', 'Origin': endpoint})
            with opener.open(req, timeout=5) as response:
                assert json.load(response)['imported'] == 1
            for path in ('/settings.json', '/nodes.json', '/assets/'):
                try:
                    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(endpoint + path, timeout=5)
                    raise AssertionError('exposed private or directory path: ' + path)
                except urllib.error.HTTPError as error:
                    assert error.code == 404
            assert process.poll() is None, 'stdin EOF stopped headless backend'
            process.terminate()
            assert process.wait(timeout=15) == 0
            print('Headless: no DISPLAY/Wayland/DBus/stdin; Web assets, same-origin import, private-file isolation and shutdown passed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
