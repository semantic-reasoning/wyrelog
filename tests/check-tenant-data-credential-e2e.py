#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise `wyctl tenant data-credential` against a real daemon (#1477).

The tenant owner issues a credential to a 0600 file, a program exchanges
that file's bytes at /auth/service-token and queries a graph with the
bearer, and revoking the credential stops both the exchange and the bearer.
The secret must never reach wyctl's stdout or stderr, nor the daemon log.
Each credential is exchanged at most twice, well inside the exchange
limiter.
"""
import base64
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from e2e_daemon import stop_daemon

# WYL_LOG_LEVEL_INFO in wyrelog/wyl-log-private.h.
LOG_LEVEL_INFO = 3
GUARD = {'guard_timestamp': '123', 'guard_loc_class': 'trusted',
         'guard_risk': '0'}


def secret_of(path):
    return json.loads(path.read_text(encoding='utf-8'))['credential_secret']


def run(daemon, wyctl, templates, log_max_level):
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix='data-credential-') as directory:
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
        helper = Path(__file__).with_name('human-user-auth-fixture.py')
        process = None

        def http(path, *, token=None, bearer=None, query=None, body=None,
                 status=200, method='POST'):
            if query:
                path += '?' + urllib.parse.urlencode(query)
            headers = {}
            if token is not None:
                bearer = token.read_text(encoding='utf-8').strip()
            if bearer is not None:
                headers['Authorization'] = 'Bearer ' + bearer
            if isinstance(body, dict):
                body = json.dumps(body).encode('utf-8')
                headers['Content-Type'] = 'application/json'
            elif isinstance(body, str):
                body = body.encode('utf-8')
                headers['Content-Type'] = 'text/tab-separated-values'
            elif isinstance(body, bytes):
                headers['Content-Type'] = 'application/json'
            data = body if body is not None else (
                b'' if method == 'POST' else None)
            request = urllib.request.Request(base + path, data=data,
                                             headers=headers, method=method)
            try:
                response = urllib.request.urlopen(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                content = response.read().decode('utf-8')
                assert response.status == status, (path, response.status,
                                                   content)
                if content.lstrip().startswith(('{', '[')):
                    return json.loads(content)
                return content

        def cli(*arguments, token=None, success=True):
            args = [wyctl, '--daemon-url', base, '--timeout-ms', '15000',
                    *arguments]
            if token is not None:
                args += ['--access-token-file', str(token),
                         '--guard-timestamp', str(time.time_ns() // 1000),
                         '--guard-loc-class', 'trusted', '--guard-risk', '0']
            result = subprocess.run(args, capture_output=True, text=True,
                                    encoding='utf-8', timeout=30)
            assert (result.returncode == 0) == success, (
                arguments, result.returncode, result.stdout, result.stderr)
            return result

        def data_credential(action, *arguments, token, success=True):
            return cli('tenant', 'data-credential', action, '--tenant',
                       'acme', *arguments, token=token, success=success)

        def login(subject, tenant='__wr_default', grantor=None):
            token = root / f'{subject}-{tenant}.token'
            if grantor is not None:
                token.write_text(grantor.read_text(encoding='utf-8'),
                                 encoding='utf-8')
                token.chmod(0o600)
            subprocess.run([sys.executable, str(helper), base, str(token),
                            subject, str(root / f'{subject}.seed'), tenant],
                           check=True, timeout=100)
            return token

        def arm(subject, permission, scope, token):
            cli('policy', 'permission-transition', '--subject', subject,
                '--perm', permission, '--scope', scope, '--event', 'grant',
                token=token)

        def exchange(path, status=200):
            return http('/auth/service-token', body=path.read_bytes(),
                        status=status)

        def query(bearer, status=200):
            return http('/datalog/acme/orders/query', bearer=bearer,
                        query={**GUARD, 'tenant': 'acme'},
                        body={'query': 'orders(O,A)', 'output': 'json',
                              'limit': 10}, status=status)

        def listing(token):
            lines = data_credential('list', token=token).stdout.splitlines()
            return {line.split()[0].split('=', 1)[1]: line for line in lines}

        def assert_no_secret(result, *secrets):
            for secret in secrets:
                assert secret not in result.stdout, result.stdout
                assert secret not in result.stderr, result.stderr

        def assert_private(path):
            mode = path.lstat().st_mode
            assert stat.S_ISREG(mode), oct(mode)
            assert stat.S_IMODE(mode) == 0o600, oct(mode)

        try:
            with log.open('ab') as output:
                process = subprocess.Popen(
                    [daemon, '--production', '--profile', 'system',
                     '--template-dir', templates,
                     '--policy-db', str(root / 'policy.sqlite'),
                     '--policy-keyprovider', 'file:' + str(key),
                     '--audit-db', str(root / 'audit.duckdb'),
                     '--fact-root', str(root / 'facts'),
                     '--listen-port', str(port),
                     '--bootstrap-admin-subject', 'admin',
                     '--bootstrap-admin-allow-skip-mfa'],
                    stdout=output, stderr=output,
                    env={**os.environ, 'WYL_LOG': '*:debug'})
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

            # 1. The owner creates the tenant with MFA, holds the query
            # permissions there, and creates graph orders with one row.
            admin = root / 'admin-__wr_default.token'
            admin.write_text(http('/auth/login', query={
                'username': 'admin', 'skip_mfa': 'true'})['access_token'],
                encoding='utf-8')
            admin.chmod(0o600)
            login('admin')
            cli('user', 'create', '--subject', 'owner', token=admin)
            cli('policy', 'permission-grant', '--subject', 'owner',
                '--perm', 'wr.tenant.create', '--scope', '__wr_default',
                token=admin)
            owner = login('owner', grantor=admin)
            arm('owner', 'wr.tenant.create', '__wr_default', admin)
            cli('tenant', 'create', '--name', 'acme', token=owner)
            for permission in ('wr.graph.manage', 'wr.schema.manage',
                               'wr.fact.append', 'wr.datalog.query',
                               'wr.fact.read'):
                arm('owner', permission, 'acme', owner)
            scoped = login('owner', 'acme', grantor=owner)
            cli('graph', 'create', '--tenant', 'acme', '--graph', 'orders',
                token=scoped)
            cli('fact', 'schema', 'register', '--tenant', 'acme', '--graph',
                'orders', '--namespace', 'shop', '--relation', 'orders',
                '--schema-version', '1', '--columns',
                'order_id:symbol,amount:int64', token=scoped)
            facts = root / 'orders.tsv'
            facts.write_text('order_id\tamount\norder-1\t42\n',
                             encoding='utf-8')
            cli('fact', 'put', '--tenant', 'acme', '--graph', 'orders',
                '--namespace', 'shop', '--relation', 'orders',
                '--schema-version', '1', '--batch-id', 'dc-test',
                '--idempotency-key', 'dc-test', '--format', 'tsv',
                '--input', str(facts), token=scoped)
            owner = login('owner')

            # 2. Issue: the secret lands only in the 0600 file.
            out = root / 'out'
            out.mkdir(mode=0o700)
            first = out / 'dc.json'
            issued = data_credential('issue', '--ops', 'query', '--graph',
                                     'orders', '--expires-in', '1h',
                                     '--output', str(first), token=owner)
            assert_private(first)
            document = json.loads(first.read_text(encoding='utf-8'))
            assert sorted(document) == ['credential_id', 'credential_secret']
            first_id = document['credential_id']
            first_secret = document['credential_secret']
            assert_no_secret(issued, first_secret)
            assert first.read_text(encoding='utf-8') == json.dumps(
                document, separators=(',', ':')) + '\n'
            assert issued.stdout.startswith(
                f'tenant=acme credential_id={first_id} state=active '
                'operations=query graphs=orders expires_at_us='), issued.stdout
            assert issued.stderr == (f'wyctl: secret written to {first} '
                                     '(mode 0600); it is not shown again\n')
            before = listing(owner)
            assert list(before) == [first_id], before

            # 3. An existing --output is refused and left as it was.
            original = first.read_bytes()
            again = data_credential('issue', '--ops', 'query', '--graph',
                                    'orders', '--expires-in', '1h',
                                    '--output', str(first), token=owner,
                                    success=False)
            assert again.returncode == 2, again
            assert again.stderr == f'wyctl: --output already exists: {first}\n'
            assert first.read_bytes() == original
            assert_private(first)
            assert listing(owner) == before

            # 4. A missing --expires-in is refused before anything is sent.
            unexpiring = out / 'unexpiring.json'
            refused = data_credential('issue', '--ops', 'query', '--graph',
                                      'orders', '--output', str(unexpiring),
                                      token=owner, success=False)
            assert refused.returncode == 2, refused
            assert 'missing --expires-in' in refused.stderr, refused.stderr
            assert not unexpiring.exists()
            assert listing(owner) == before

            # The service-credential exchange command reads only service
            # credential documents; it refuses this file locally.
            service = cli('auth', 'service-token', '--credential-file',
                          str(first), '--token-output',
                          str(out / 'service.token'), success=False)
            assert service.returncode == 2, service
            assert not (out / 'service.token').exists()
            assert_no_secret(service, first_secret)

            # 5. A program exchanges the file's bytes and queries the graph.
            bearer = exchange(first)['access_token']
            claims = json.loads(base64.urlsafe_b64decode(
                bearer.split('.')[1] + '=' * (-len(bearer.split('.')[1]) % 4)))
            assert 0 < claims['exp'] - claims['iat'] <= 300, claims
            assert query(bearer)['rows'] == [{'O': 'order-1', 'A': 42}]

            # 6. list shows the credential and its issuer.
            row = listing(owner)[first_id]
            assert ' state=active operations=query graphs=orders ' \
                'issuer=owner generation=' in row, row
            assert row.endswith(' revoked_at_us=- revoked_by=- '
                                'revoked_reason=- rotated_from=-'), row
            assert ' last_used_at_us=-' not in row, row

            # 7. Revoke stops the next exchange and the earlier bearer.
            revoked = data_credential('revoke', '--id', first_id, token=owner)
            assert revoked.stdout == (f'tenant=acme credential_id={first_id} '
                                      'state=revoked changed=true\n')
            exchange(first, status=401)
            query(bearer, status=401)
            repeated = data_credential('revoke', '--id', first_id, token=owner)
            assert repeated.stdout.endswith(' changed=false\n'), repeated
            assert ' revoked_by=owner revoked_reason=revoked ' in \
                listing(owner)[first_id]

            # 8. Rotate: the old file is refused, the new one exchanges.
            second = out / 'second.json'
            data_credential('issue', '--ops', 'query', '--all-graphs',
                            '--expires-in', '2h', '--output', str(second),
                            token=owner)
            second_id = json.loads(second.read_text(
                encoding='utf-8'))['credential_id']
            third = out / 'third.json'
            rotated = data_credential('rotate', '--id', second_id,
                                      '--output', str(third), token=owner)
            assert_private(third)
            third_id = json.loads(third.read_text(
                encoding='utf-8'))['credential_id']
            assert rotated.stdout.startswith(
                f'tenant=acme credential_id={third_id} '
                f'rotated_from={second_id} generation='), rotated.stdout
            assert_no_secret(rotated, secret_of(second), secret_of(third))
            exchange(second, status=401)
            assert query(exchange(third)['access_token'])['rows'] == [
                {'O': 'order-1', 'A': 42}]
            rows = listing(owner)
            assert ' graphs=* ' in rows[third_id], rows[third_id]
            assert rows[third_id].endswith(f' rotated_from={second_id}')
            assert ' revoked_reason=rotated ' in rows[second_id]

            # The daemon log names the credentials but never a secret.
            secrets = [first_secret, secret_of(second), secret_of(third)]
            text = log.read_text(encoding='utf-8', errors='replace')
            if int(log_max_level) >= LOG_LEVEL_INFO:
                for credential_id in (first_id, second_id, third_id):
                    assert credential_id in text, credential_id
            for secret in secrets:
                assert secret not in text
        except Exception:
            print(log.read_text(encoding='utf-8', errors='replace'),
                  file=sys.stderr)
            raise
        finally:
            stop_daemon(process, primary_error=sys.exc_info()[1])


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print('usage: check-tenant-data-credential-e2e.py WYRELOGD WYCTL '
              'TEMPLATE_DIR LOG_MAX_LEVEL', file=sys.stderr)
        sys.exit(2)
    run(*sys.argv[1:])
