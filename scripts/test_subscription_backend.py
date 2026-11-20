#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise v1.0.0 subscription formats & resilient import against a built sidecar without starting a core."""
import base64
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.request


def main():
    binary = pathlib.Path(os.environ['PRISMRAY_TEST_BINARY']).resolve()
    identity = '11111111-1111-4111-8111-111111111111'
    vmess = {
        'v': '2',
        'ps': 'VMess',
        'add': 'example.invalid',
        'port': 443,
        'id': identity,
        'aid': 0,
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'tls': 'tls',
        'path': '/proxy',
    }
    uri = 'vmess://' + base64.b64encode(json.dumps(vmess).encode()).decode()
    xray_vless_xhttp = {
        'outbounds': [
            {
                'protocol': 'vless',
                'tag': 'vless-xhttp',
                'settings': {
                    'vnext': [
                        {
                            'address': 'example.invalid',
                            'port': 443,
                            'users': [{'id': identity, 'encryption': 'none'}],
                        }
                    ]
                },
                'streamSettings': {
                    'network': 'xhttp',
                    'security': 'tls',
                    'xhttpSettings': {'path': '/xhttp', 'mode': 'auto'},
                },
            }
        ]
    }
    cases = {
        'VMess URI': uri,
        'Base64 URI': base64.b64encode(uri.encode()).decode(),
        'Clash VLESS': 'proxies:\n - name: VLESS-YAML\n   type: vless\n   server: example.invalid\n   port: 443\n   uuid: ' + identity + '\n   tls: true',
        'Clash Hysteria2': 'proxies:\n - name: Hy2-YAML\n   type: hysteria2\n   server: example.invalid\n   port: 8443\n   password: hy2-secret',
        'Clash TUIC': 'proxies:\n - name: TUIC-YAML\n   type: tuic\n   server: example.invalid\n   port: 443\n   uuid: ' + identity + '\n   password: tuic-secret\n   congestion-controller: bbr',
        'Clash AnyTLS': 'proxies:\n - name: AnyTLS-YAML\n   type: anytls\n   server: example.invalid\n   port: 443\n   password: any-secret',
        'sing-box JSON': json.dumps({'outbounds': [{'type': 'trojan', 'tag': 'sb-trojan', 'server': 'example.invalid', 'server_port': 443, 'password': 'secret', 'tls': {'enabled': True}}]}),
        'Xray VLESS XHTTP JSON': json.dumps(xray_vless_xhttp),
        'V2Ray batch JSON': json.dumps([xray_vless_xhttp]),
        'SIP008 JSON': json.dumps({'servers': [{'server': 'example.invalid', 'server_port': 8388, 'method': 'aes-128-gcm', 'password': 'test-only'}]}),
        'WireGuard .conf': '[Interface]\nPrivateKey = privkey-test\nAddress = 10.0.0.2/32\nMTU = 1408\n[Peer]\nPublicKey = pubkey-test\nEndpoint = example.invalid:51820\n',
    }

    with tempfile.TemporaryDirectory(prefix='prismray-subscription-test-') as directory:
        test_env = {
            **os.environ,
            'PRISMRAY_KEYRING': 'file',
            'HOME': directory,
            'XDG_CONFIG_HOME': str(pathlib.Path(directory, 'xdg-config')),
            'XDG_DATA_HOME': str(pathlib.Path(directory, 'xdg-data')),
        }
        process = subprocess.Popen(
            [str(binary), '--desktop'],
            cwd=directory,
            env=test_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            connection = json.loads(process.stdout.readline())

            def request(path, data=None):
                raw = json.dumps(data).encode() if data is not None else None
                req = urllib.request.Request(
                    connection['url'] + path,
                    data=raw,
                    headers={
                        'Authorization': 'Bearer ' + connection['token'],
                        'Content-Type': 'application/json',
                    },
                )
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as response:
                    return json.load(response)

            # Desktop backend is auto-initialized in v1.0.0
            for name, content in cases.items():
                before = len(request('/nodes'))
                result = request('/subscription/import', {'content': content})
                assert result['imported'] == 1, f'{name}: {result}'
                assert len(request('/nodes')) == before + 1, name
                print(name + ': import passed', flush=True)

            # Resilient mixed import: valid Hysteria2 + unsupported ssr:// line
            mixed_content = 'hysteria2://hy2pass@example.invalid:8443#ValidHy2\nssr://invalid-entry'
            mixed_res = request('/subscription/import', {'content': mixed_content})
            assert mixed_res['imported'] == 1, mixed_res
            assert len(mixed_res['skipped']) == 1, mixed_res

            # All-invalid import must return 400 and preserve existing nodes
            before = request('/nodes')
            try:
                request(
                    '/subscription/import',
                    {'content': '{"proxies":[{"type":"ssr","server":"example.invalid","port":443}]}'},
                )
                raise AssertionError('all-invalid import unexpectedly accepted')
            except urllib.error.HTTPError as error:
                assert error.code == 400, f'expected 400, got {error.code}'
            assert request('/nodes') == before

            for node in before:
                exported = request('/nodes/' + node['id'] + '/uri')['uri']
                assert isinstance(exported, str) and '://' in exported, node

            process.stdin.close()
            assert process.wait(timeout=15) == 0
            print('Subscription v1.0.0: 11-protocol formats, resilient skip, URI export and rollback safety passed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
