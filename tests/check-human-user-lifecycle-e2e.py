#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise human management through the real daemon, client and wyctl."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def run(daemon, wyctl, templates, inspector):
    with tempfile.TemporaryDirectory(prefix='human-lifecycle-') as directory:
        root = Path(directory)
        key = root / 'policy.key'
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        (root / 'facts').mkdir(mode=0o700)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        log = root / 'daemon.log'
        process = None

        def http(path, *, token=None, query=None, body=None, status=200, method='POST'):
            if query:
                path += '?' + urllib.parse.urlencode(query)
            headers = {}
            if token:
                headers['Authorization'] = 'Bearer ' + token.read_text(encoding='utf-8').strip()
            if isinstance(body, dict):
                body = json.dumps(body).encode('utf-8')
                headers['Content-Type'] = 'application/json'
            elif isinstance(body, str):
                body = body.encode('utf-8')
                headers['Content-Type'] = 'text/tab-separated-values'
            request = urllib.request.Request(base + path, data=body if body is not None else (b'' if method == 'POST' else None), headers=headers, method=method)
            try:
                response = urllib.request.urlopen(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                content = response.read().decode('utf-8')
                assert response.status == status, (path, response.status, content)
                return json.loads(content) if content.lstrip().startswith(('{', '[')) else content

        def cli(*arguments, token=None, success=True):
            args = [wyctl, '--daemon-url', base, '--timeout-ms', '15000', *arguments]
            if token:
                args += ['--access-token-file', str(token), '--guard-timestamp', str(time.time_ns() // 1000), '--guard-loc-class', 'trusted', '--guard-risk', '0']
            result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', timeout=30)
            assert (result.returncode == 0) == success, (arguments, result.returncode, result.stdout, result.stderr)
            return result

        def arm(subject, permission, scope, token):
            cli('policy', 'permission-transition', '--subject', subject, '--perm', permission,
                '--scope', scope, '--event', 'grant', token=token)

        def start_daemon():
            nonlocal process
            with log.open('ab') as output:
                process = subprocess.Popen([daemon, '--production', '--profile', 'system', '--template-dir', templates,
                    '--policy-db', str(root / 'policy.sqlite'), '--policy-keyprovider', 'file:' + str(key),
                    '--audit-db', str(root / 'audit.duckdb'), '--fact-root', str(root / 'facts'),
                    '--listen-port', str(port), '--bootstrap-admin-subject', 'admin',
                    '--bootstrap-admin-allow-skip-mfa'], stdout=output, stderr=output)
            for _ in range(200):
                if process.poll() is not None:
                    raise AssertionError(log.read_text(encoding='utf-8'))
                try:
                    http('/healthz', method='GET')
                    break
                except (urllib.error.URLError, ConnectionError):
                    time.sleep(0.1)
            else:
                raise AssertionError('daemon startup timed out')

        try:
            start_daemon()
            admin = root / 'admin.token'
            admin.write_text(http('/auth/login', query={'username': 'admin', 'skip_mfa': 'true'})['access_token'], encoding='utf-8')
            admin.chmod(0o600)
            # User management requires MFA even for the bootstrap administrator.
            cli('user', 'create', '--subject', 'alice', token=admin, success=False)
            auth_helper = Path(__file__).with_name('human-user-auth-fixture.py')
            subprocess.run([sys.executable, str(auth_helper), base, str(admin), 'admin', str(root / 'admin.seed')], check=True, timeout=60)
            for action in ('disable', 'delete'):
                args = ['user', action, '--subject', 'admin'] + (['--yes'] if action == 'delete' else [])
                refused = cli(*args, token=admin, success=False)
                assert 'last_system_admin' in refused.stderr
            absent = http('/auth/login', query={'username': 'alice'}, status=403)
            assert absent == {'error': 'login_denied'}
            created = cli('user', 'create', '--subject', 'alice', token=admin)
            request = created.stdout.strip().split('request_id=')[1]
            for invalid in ('svc:worker', 'wr.system', '.', '..', 'bad subject'):
                assert http('/users', body={'subject': invalid, 'request_id': request}, status=400) == {'error': 'invalid_user_subject'}
            assert http('/users', query={'tenant': 'foreign'}, body={'subject': 'valid', 'request_id': request}, status=400) == {'error': 'invalid_user_tenant'}
            assert http('/users', body={'subject': 'valid', 'request_id': request, 'extra': 'rejected'}, status=400) == {'error': 'invalid_user_request'}
            cli('user', 'create', '--subject', 'alice', '--request-id', request, token=admin)
            cli('user', 'create', '--subject', 'different', '--request-id', request, token=admin, success=False)
            listing = cli('user', 'list', token=admin).stdout
            assert 'subject=alice state=active' in listing
            cli('policy', 'role-grant', '--subject', 'alice', '--role', 'wr.viewer', '--scope', '__wr_default', token=admin)
            alice = root / 'alice.token'
            alice.write_text(admin.read_text(encoding='utf-8'), encoding='utf-8')
            alice.chmod(0o600)
            subprocess.run([sys.executable, str(auth_helper), base, str(alice), 'alice', str(root / 'alice.seed')], check=True, timeout=60)
            cli('user', 'list', token=alice, success=False)
            cli('user', 'create', '--subject', 'unauthorized', token=alice, success=False)
            cli('user', 'disable', '--subject', 'admin', token=alice, success=False)
            cli('policy', 'role-grant', '--subject', 'alice', '--role', 'wr.system_admin', '--scope', '__wr_default', token=admin)
            arm('alice', 'wr.tenant.manage', '__wr_default', alice)
            refused = cli('user', 'disable', '--subject', 'alice', '--request-id', request,
                          token=admin, success=False)
            assert 'user_request_conflict' in refused.stderr
            assert 'subject=alice state=active' in cli('user', 'list', token=alice).stdout
            cli('tenant', 'create', '--name', 'alice-data', token=alice)
            for permission in ('wr.graph.manage', 'wr.schema.manage', 'wr.fact.append'):
                arm('alice', permission, 'alice-data', alice)
            subprocess.run([sys.executable, str(auth_helper), base, str(alice), 'alice', str(root / 'alice.seed'), 'alice-data'], check=True, timeout=60)
            cli('graph', 'create', '--tenant', 'alice-data', '--graph', 'orders', token=alice)
            cli('fact', 'schema', 'register', '--tenant', 'alice-data', '--graph', 'orders',
                '--namespace', 'shop', '--relation', 'orders', '--schema-version', '1',
                '--columns', 'order_id:symbol,amount:int64', token=alice)
            facts = root / 'orders.tsv'
            facts.write_text('order_id\tamount\norder-1\t42\n', encoding='utf-8')
            cli('fact', 'put', '--tenant', 'alice-data', '--graph', 'orders', '--namespace', 'shop',
                '--relation', 'orders', '--schema-version', '1', '--batch-id', 'human-test',
                '--idempotency-key', 'human-test', '--format', 'tsv', '--input', str(facts), token=alice)
            assert list((root / 'facts').rglob('facts.duckdb'))
            subprocess.run([sys.executable, str(auth_helper), base, str(alice), 'alice', str(root / 'alice.seed')], check=True, timeout=60)
            # The owner must prepare the tenant explicitly before deletion.
            refused = cli('user', 'delete', '--subject', 'alice', '--yes', token=admin, success=False)
            assert 'alice-data' in refused.stderr and 'unsealed' in refused.stderr
            cli('policy', 'role-grant', '--subject', 'admin', '--role', 'wr.system_admin', '--scope', 'alice-data', token=alice)
            arm('admin', 'wr.tenant.manage', '__wr_default', admin)
            seal_request = '000000000000000000000000230'
            cli('tenant', 'seal', '--name', 'alice-data', '--confirm', '--request-id', seal_request, token=admin)
            refused = cli('user', 'delete', '--subject', 'alice', '--yes', token=admin, success=False)
            assert 'alice-data:admin:role:wr.system_admin' in refused.stderr
            cli('tenant', 'unseal', '--name', 'alice-data', token=admin)
            refused = cli('tenant', 'seal', '--name', 'alice-data', '--confirm',
                          '--request-id', seal_request, token=admin, success=False)
            assert 'tenant_seal_superseded' in refused.stderr
            subprocess.run([sys.executable, str(auth_helper), base, str(alice), 'alice', str(root / 'alice.seed'), 'alice-data'], check=True, timeout=60)
            facts.write_text('order_id\tamount\norder-2\t99\n', encoding='utf-8')
            cli('fact', 'put', '--tenant', 'alice-data', '--graph', 'orders', '--namespace', 'shop',
                '--relation', 'orders', '--schema-version', '1', '--batch-id', 'human-after-unseal',
                '--idempotency-key', 'human-after-unseal', '--format', 'tsv', '--input', str(facts), token=alice)
            subprocess.run([sys.executable, str(auth_helper), base, str(alice), 'alice', str(root / 'alice.seed')], check=True, timeout=60)
            cli('policy', 'role-revoke', '--subject', 'admin', '--role', 'wr.system_admin', '--scope', 'alice-data', token=alice)
            cli('tenant', 'seal', '--name', 'alice-data', '--confirm', token=admin)
            cli('user', 'disable', '--subject', 'alice', token=admin)
            assert http('/auth/login', query={'username': 'alice'}, status=403) == absent
            cli('user', 'list', token=alice, success=False)
            cli('user', 'delete', '--subject', 'alice', token=admin, success=False)
            deleted = cli('user', 'delete', '--subject', 'alice', '--yes', token=admin)
            assert not list((root / 'facts').rglob('facts.duckdb'))
            request = deleted.stdout.strip().split('request_id=')[1]
            cli('user', 'delete', '--subject', 'alice', '--yes', '--request-id', request, token=admin)
            assert http('/auth/login', query={'username': 'alice'}, status=403) == absent
            cli('user', 'create', '--subject', 'alice', token=admin, success=False)
            cli('policy', 'role-grant', '--subject', 'alice', '--role', 'wr.system_admin', '--scope', '__wr_default', token=admin, success=False)
            assert 'subject=alice state=deleted' in cli('user', 'list', token=admin).stdout
            assert 'alice-data' not in cli('tenant', 'list', token=admin).stdout
            process.terminate()
            process.wait(timeout=30)
            subprocess.run([inspector, "--inspect-deleted", str(root / "policy.sqlite"), str(key), "alice"], check=True, timeout=30)
            start_daemon()
            assert http('/auth/login', query={'username': 'alice'}, status=403) == absent
            subprocess.run([sys.executable, str(auth_helper), base, str(admin), 'admin', str(root / 'admin.seed')], check=True, timeout=60)
            cli('user', 'create', '--subject', 'alice', token=admin, success=False)
            listing = cli('user', 'list', token=admin).stdout
            assert 'subject=alice state=deleted' in listing
            assert 'wyrelogd-' not in listing
            assert not list((root / 'facts').rglob('facts.duckdb'))
        except Exception:
            print(log.read_text(encoding='utf-8'), file=sys.stderr)
            raise
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=30)


if __name__ == '__main__':
    run(*sys.argv[1:])
