#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Local integration check; does not start a proxy core or change OS settings."""
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.request


def main():
    binary = pathlib.Path(os.environ['PRISMRAY_TEST_BINARY']).resolve()
    with tempfile.TemporaryDirectory(prefix='prismray-desktop-test-') as directory:
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
            endpoint = connection['url']
            assert endpoint.startswith('http://127.0.0.1:')
            assert len(connection['token']) == 64

            # Unauthenticated calls must be rejected (401)
            try:
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(endpoint + '/nodes', timeout=5)
                raise AssertionError('unauthorized access accepted')
            except urllib.error.HTTPError as error:
                assert error.code == 401, f'expected 401, got {error.code}'

            def request(path, data=None, method=None):
                raw = json.dumps(data).encode() if data is not None else None
                req = urllib.request.Request(
                    endpoint + path,
                    data=raw,
                    method=method,
                    headers={
                        'Authorization': 'Bearer ' + connection['token'],
                        'Content-Type': 'application/json',
                    },
                )
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as response:
                    return json.load(response)

            # Platform-adaptive desktop mode auto-initializes & unlocks immediately
            auth_status = request('/auth/status')
            assert auth_status['initialized'] is True
            assert auth_status['unlocked'] is True
            assert auth_status['password_lock_enabled'] is False

            assert request('/nodes') == []
            node = {
                'id': 'sample',
                'name': 'Sample',
                'protocol': 'trojan',
                'address': 'example.invalid',
                'port': 443,
                'password': 'test-only',
                'security': 'tls',
                'network': 'tcp',
            }
            request('/nodes', node)
            assert request('/nodes/sample/uri')['uri'].startswith('trojan://')

            request(
                '/routing',
                {
                    'mode': 'global',
                    'block_ads': True,
                    'bypass_lan': True,
                    'bypass_cn': False,
                    'local_dns': '223.5.5.5',
                    'remote_dns': 'https://dns.google/dns-query',
                    'domain_strategy': 'prefer_ipv4',
                    'custom_rules': [],
                },
                'PUT',
            )

            backup = request('/backup')
            assert backup['version'] == 4 and len(backup['nodes']) == 1
            assert request('/diagnostics')['nodes'] == 1
            request('/backup', backup)
            assert not pathlib.Path(directory, 'restore.pending.json').exists()

            # Enable optional startup password lock and restart
            lock_resp = request(
                '/auth/password-lock',
                {'enabled': True, 'password': 'desktop-test-password'},
            )
            assert lock_resp['password_lock_enabled'] is True

            process.stdin.close()
            assert process.wait(timeout=15) == 0

            process = subprocess.Popen(
                [str(binary), '--desktop'],
                cwd=directory,
                env=test_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            connection = json.loads(process.stdout.readline())
            endpoint = connection['url']

            # While locked with startup password lock, data endpoints return 423
            try:
                req = urllib.request.Request(
                    endpoint + '/nodes',
                    headers={'Authorization': 'Bearer ' + connection['token']},
                )
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5)
                raise AssertionError('locked desktop backend accepted data request')
            except urllib.error.HTTPError as error:
                assert error.code == 423, f'expected 423, got {error.code}'

            request('/auth/login', {'password': 'desktop-test-password'})
            assert request('/nodes')[0]['id'] == 'sample'

            process.stdin.close()
            assert process.wait(timeout=15) == 0

            # Verify split --config and --data-dir keep settings.json + prismray.db in config dir
            cfg_dir = pathlib.Path(directory, 'split-config', 'prismray')
            run_dir = pathlib.Path(directory, 'split-share', 'prismray')
            split_proc = subprocess.Popen(
                [
                    str(binary),
                    '--desktop',
                    '--config',
                    str(cfg_dir / 'settings.json'),
                    '--data-dir',
                    str(run_dir),
                ],
                cwd=directory,
                env=test_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                split_conn = json.loads(split_proc.stdout.readline())
                req = urllib.request.Request(
                    split_conn['url'] + '/auth/status',
                    headers={'Authorization': 'Bearer ' + split_conn['token']},
                )
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as resp:
                    assert json.load(resp)['initialized'] is True
                assert (cfg_dir / 'settings.json').is_file()
                assert (cfg_dir / 'prismray.db').is_file()
                assert not (run_dir / 'prismray.db').exists()
            finally:
                if split_proc.stdin and not split_proc.stdin.closed:
                    split_proc.stdin.close()
                if split_proc.poll() is None:
                    split_proc.terminate()
                    split_proc.wait(timeout=10)
                assert split_proc.returncode == 0

            print(
                'Desktop backend v1.0.0: platform-adaptive auth, backup v4, routing, startup lock, split config/data dirs and shutdown passed'
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
