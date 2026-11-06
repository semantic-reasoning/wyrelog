#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise human management through the real daemon, client and wyctl."""
import json
from concurrent.futures import ThreadPoolExecutor
import threading
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


def check_self_service(root, base, admin, cli, http, arm, restart):
    """Create-only humans keep their grant while exercising isolated tenants."""
    helper = Path(__file__).with_name('human-user-auth-fixture.py')
    users, tenants = {}, {}
    guard = {'guard_timestamp': '123', 'guard_loc_class': 'trusted', 'guard_risk': '0'}

    def login(subject, tenant='__wr_default'):
        token = root / f'{subject}-{tenant}.token'
        token.write_text(admin.read_text(encoding='utf-8'), encoding='utf-8')
        token.chmod(0o600)
        subprocess.run([sys.executable, str(helper), base, str(token), subject,
                        str(root / f'{subject}.seed'), tenant], check=True, timeout=100)
        return token

    def read(tenant, token, status=200, graph='orders'):
        return http(f'/datalog/{tenant}/{graph}/query', token=token,
                    query={**guard, 'tenant': tenant},
                    body={'query': 'orders(O,A)', 'output': 'json', 'limit': 10}, status=status)

    def append(tenant, token, graph='orders', key='shared-key', batch='batch-1', marker=None, status=200):
        return http(f'/facts/{tenant}/{graph}/orders:append', token=token,
                    query={**guard, 'tenant': tenant, 'namespace': 'shop', 'schema_version': 1,
                           'batch_id': batch, 'idempotency_key': key},
                    body=f'order_id\tamount\n{marker or tenant}\t42\n', status=status)

    def usage(tenant, token):
        value = http('/facts/quota', method='GET', token=token,
                     query={**guard, 'tenant': tenant, 'dimension': 'logical_bytes'})
        assert value['pending_rows'] == value['pending_bytes'] == 0, value
        return value['committed_rows'], value['committed_bytes']

    for subject in ('creator-a', 'creator-b'):
        cli('user', 'create', '--subject', subject, token=admin)
        cli('policy', 'permission-grant', '--subject', subject,
            '--perm', 'wr.tenant.create', '--scope', '__wr_default', token=admin)
        token = login(subject)
        users[subject] = token
        refused = cli('tenant', 'create', '--name', subject + '-dormant', token=token, success=False)
        assert 'tenant_denied' in refused.stderr
        arm(subject, 'wr.tenant.create', '__wr_default', admin)
        pending = http('/auth/login', query={'username': subject})
        http('/tenants/create', query={**guard, 'name': subject + '-nonmfa',
             'session_token': pending['session_token']}, status=401)
        cli('user', 'list', token=token, success=False)
        cli('tenant', 'list', token=token, success=False)
        for i in (1, 2):
            tenant = f'{subject}-{i}'
            cli('tenant', 'create', '--name', tenant, token=token)
            assert 'changed=false' in cli('tenant', 'create', '--name', tenant, token=token).stdout
            assert f'owner={subject}' in cli('tenant', 'show', '--name', tenant, token=token).stdout
            for permission in ('wr.graph.manage', 'wr.schema.manage', 'wr.fact.append',
                               'wr.fact.forget', 'wr.datalog.query'):
                arm(subject, permission, tenant, token)
            scoped = login(subject, tenant)
            tenants[tenant] = (subject, scoped)
            cli('graph', 'create', '--tenant', tenant, '--graph', 'orders', token=scoped)
            cli('fact', 'schema', 'register', '--tenant', tenant, '--graph', 'orders',
                '--namespace', 'shop', '--relation', 'orders', '--schema-version', '1',
                '--columns', 'order_id:symbol,amount:int64', token=scoped)
            # A non-default bearer cannot create, even for its own human.
            http('/tenants/create', token=scoped,
                 query={**guard, 'tenant': tenant, 'name': tenant + '-nested'}, status=403)

    # A denied cross-tenant request arrives before any owner uses the key.
    for tenant, (_, token) in tenants.items():
        for victim in tenants:
            if victim != tenant:
                append(victim, token, marker='unauthorized', status=403)
    barrier = threading.Barrier(2 * len(tenants))
    def concurrent_append(tenant):
        barrier.wait(timeout=30)
        return tenant, append(tenant, tenants[tenant][1])['inserted']
    with ThreadPoolExecutor(max_workers=2 * len(tenants)) as pool:
        receipts = list(pool.map(concurrent_append, list(tenants) * 2))
    for tenant, (_, token) in tenants.items():
        assert sum(inserted for target, inserted in receipts if target == tenant) == 1
        assert read(tenant, token)['rows'] == [{'O': tenant, 'A': 42}]
        assert usage(tenant, token)[0] == 1
        append(tenant, token, marker='changed', status=409)
        append(tenant, token, batch='changed-batch', status=409)
        cli('graph', 'create', '--tenant', tenant, '--graph', 'archive', token=token)
        cli('fact', 'schema', 'register', '--tenant', tenant, '--graph', 'archive',
            '--namespace', 'shop', '--relation', 'orders', '--schema-version', '1',
            '--columns', 'order_id:symbol,amount:int64', token=token)
        assert append(tenant, token, graph='archive', marker=tenant + '-archive')['inserted']
        assert usage(tenant, token)[0] == 2

    for tenant, (subject, scoped) in tenants.items():
        for foreign in tenants:
            if foreign == tenant:
                continue
            read(foreign, scoped, status=403)
            http(f'/facts/{foreign}/orders/orders:append', token=scoped,
                 query={**guard, 'tenant': foreign, 'namespace': 'shop', 'schema_version': 1,
                        'batch_id': tenant + '-attack', 'idempotency_key': tenant + '-attack'},
                 body='order_id\tamount\nforeign\t99\n', status=403)
            http(f'/facts/{foreign}/orders/orders:forget', method='DELETE', token=scoped,
                 query={**guard, 'tenant': foreign, 'namespace': 'shop', 'schema_version': 1},
                 body={'batch_id': 'batch-1', 'operator': subject, 'reason': 'test'}, status=403)
        foreign = 'creator-b-1' if subject == 'creator-a' else 'creator-a-1'
        for action in ('create', 'show', 'seal', 'unseal', 'delete', 'transfer-owner'):
            extra = ['--confirm'] if action == 'seal' else ['--to', subject] if action == 'transfer-owner' else []
            refused = cli('tenant', action, '--name', foreign, *extra, token=users[subject], success=False)
            expected = 'tenant_transfer_denied' if action == 'transfer-owner' else 'tenant_denied'
            assert expected in refused.stderr, (action, refused.returncode, refused.stderr)
        assert read(tenant, scoped)['rows'] == [{'O': tenant, 'A': 42}]

    before = {tenant: usage(tenant, token) for tenant, (_, token) in tenants.items()}
    restart()
    for subject in users:
        users[subject] = login(subject)
    for tenant, (subject, _) in list(tenants.items()):
        token = login(subject, tenant)
        tenants[tenant] = subject, token
        assert not append(tenant, token)['inserted']
        assert not append(tenant, token, graph='archive', marker=tenant + '-archive')['inserted']
        assert read(tenant, token)['rows'] == [{'O': tenant, 'A': 42}]
        assert usage(tenant, token) == before[tenant]
        append(tenant, token, marker='changed-after-restart', status=409)

    first, second = list(tenants)[:2]
    http('/facts/quota', token=tenants[first][1],
         query={**guard, 'tenant': first, 'dimension': 'logical_bytes', 'row_limit': 2, 'limit': 10000})
    append(first, tenants[first][1], key='quota-probe', batch='quota-probe', status=429)
    assert append(second, tenants[second][1], key='quota-probe', batch='quota-probe', marker='extra')['inserted']
    assert usage(first, tenants[first][1]) == before[first]
    assert usage(second, tenants[second][1])[0] == 3

    # Revoke the grant without replacing the live bearer. Existing-name no-ops
    # must reauthorize too; ownership still permits the separate lifecycle.
    for subject, token in users.items():
        cli('policy', 'permission-revoke', '--subject', subject,
            '--perm', 'wr.tenant.create', '--scope', '__wr_default', token=admin)
        for name in (subject + '-revoked', subject + '-1'):
            assert 'tenant_denied' in cli('tenant', 'create', '--name', name,
                                         token=token, success=False).stderr
    remaining = set(tenants)
    for tenant, (subject, scoped) in tenants.items():
        http(f'/facts/{tenant}/orders/orders:forget', method='DELETE', token=scoped,
             query={**guard, 'tenant': tenant, 'namespace': 'shop', 'schema_version': 1},
             body={'batch_id': 'batch-1', 'operator': subject, 'reason': 'test cleanup'})
        if tenant == second:
            http(f'/facts/{tenant}/orders/orders:forget', method='DELETE', token=scoped,
                 query={**guard, 'tenant': tenant, 'namespace': 'shop', 'schema_version': 1},
                 body={'batch_id': 'quota-probe', 'operator': subject, 'reason': 'test cleanup'})
        assert read(tenant, scoped)['row_count'] == 0
        cli('tenant', 'seal', '--name', tenant, '--confirm', token=users[subject])
        cli('tenant', 'delete', '--name', tenant, token=users[subject])
        remaining.remove(tenant)
        for survivor in remaining:
            survivor_token = tenants[survivor][1]
            prior = usage(survivor, survivor_token)
            assert not append(survivor, survivor_token, graph='archive', marker=survivor + '-archive')['inserted']
            assert read(survivor, survivor_token, graph='archive')['rows'] == [{'O': survivor + '-archive', 'A': 42}]
            assert usage(survivor, survivor_token) == prior
    assert not list((root / 'facts').rglob('facts.duckdb'))


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
            def restart():
                process.terminate()
                process.wait(timeout=30)
                start_daemon()
                subprocess.run([sys.executable, str(auth_helper), base, str(admin), 'admin', str(root / 'admin.seed')], check=True, timeout=60)
            check_self_service(root, base, admin, cli, http, arm, restart)
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
