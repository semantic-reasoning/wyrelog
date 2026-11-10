#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real daemon/client/wyctl recursive acceptance; timings are observations only."""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


LINEAR = 'reachable(X,Y):-edge(X,Y).\nreachable(X,Z):-reachable(X,Y),edge(Y,Z).\n'


def closure(edges):
    """Independent per-source BFS, matching recursive-rule-test-support.h."""
    result = set()
    for start in {x for pair in edges for x in pair}:
        pending = [y for x, y in edges if x == start]
        seen = set()
        while pending:
            vertex = pending.pop()
            if vertex not in seen:
                seen.add(vertex)
                pending.extend(y for x, y in edges if x == vertex)
        result.update((start, end) for end in seen)
    return result



def restore_tree(source, destination):
    """Restore bytes in place, preserving the provisioned directory bindings."""
    for child in destination.iterdir():
        if not (source / child.name).exists():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir():
            target.mkdir(exist_ok=True, mode=0o700)
            restore_tree(child, target)
        else:
            shutil.copy2(child, target)


def run(daemon, wyctl, templates):
    with tempfile.TemporaryDirectory(prefix='recursive-product-') as directory:
        root = Path(directory).resolve()
        live = root / 'live'
        live.mkdir(mode=0o700)
        (live / 'facts').mkdir(mode=0o700)
        key = live / 'policy.key'
        key.write_bytes(os.urandom(32))
        key.chmod(0o600)
        tenant = 'recursive-qualification'
        token = root / 'admin.token'
        scoped_token = root / 'tenant.token'
        tenant_created = False
        log = root / 'daemon.log'
        process = None
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        environment = dict(os.environ)
        for name in list(environment):
            if name.startswith(('WIRELOG_', 'WYL_TEST_')):
                del environment[name]

        def http(path, query=None):
            if query:
                path += '?' + urllib.parse.urlencode(query)
            request = urllib.request.Request(base + path, data=b'' if query else None)
            with urllib.request.urlopen(request, timeout=10) as response:
                content = response.read().decode('utf-8')
                return json.loads(content) if content.startswith('{') else content

        def cli(*args, success=True):
            credential = scoped_token if '--tenant' in args and tenant in args else token
            result = subprocess.run([wyctl, '--daemon-url', base, '--timeout-ms', '30000',
                *map(str, args), '--access-token-file', str(credential),
                '--guard-timestamp', '123', '--guard-loc-class', 'trusted', '--guard-risk', '29'],
                capture_output=True, text=True, encoding='utf-8', timeout=40, env=environment)
            assert (result.returncode == 0) == success, (args, result.returncode, result.stdout, result.stderr)
            return result

        def stop():
            nonlocal process
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                    assert process.returncode == 0, ('daemon shutdown', process.returncode)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    raise AssertionError('daemon shutdown watchdog expired')
                finally:
                    process = None

        def start():
            nonlocal process
            with log.open('ab') as output:
                process = subprocess.Popen([daemon, '--production', '--profile', 'system',
                    '--template-dir', templates, '--policy-db', str(live / 'policy.sqlite'),
                    '--policy-keyprovider', 'file:' + str(key), '--audit-db', str(live / 'audit.duckdb'),
                    '--fact-root', str(live / 'facts'), '--listen-port', str(port),
                    '--bootstrap-admin-subject', 'admin', '--bootstrap-admin-allow-skip-mfa'],
                    stdout=output, stderr=output, env=environment)
            for _ in range(300):
                assert process.poll() is None, 'daemon exited during startup'
                try:
                    http('/healthz')
                    break
                except (urllib.error.URLError, ConnectionError):
                    time.sleep(0.1)
            else:
                raise AssertionError('daemon startup watchdog expired')
            if not token.exists():
                token.write_text(http('/auth/login', {'username': 'admin', 'skip_mfa': 'true'})['access_token'], encoding='utf-8')
                token.chmod(0o600)
            login(token)
            if tenant_created:
                login(scoped_token, tenant)

        def login(destination, scope='__wr_default'):
            if not destination.exists():
                shutil.copy2(token, destination)
            subprocess.run([sys.executable, str(Path(__file__).with_name('human-user-auth-fixture.py')),
                base, str(destination), 'admin', str(root / 'admin.seed'), scope],
                check=True, timeout=100, env=environment)

        def arm(permission, scope):
            cli('policy', 'permission-transition', '--subject', 'admin', '--perm', permission,
                '--scope', scope, '--event', 'grant')

        def target(graph):
            return ('--tenant', tenant, '--graph', graph)

        def pack(graph, source=LINEAR, success=True):
            path = root / 'pack.rules'
            path.write_text(source, encoding='utf-8')
            return cli('fact', 'rule-pack', 'register', *target(graph), '--file', path, success=success)

        def create(graph):
            cli('graph', 'create', *target(graph))
            for relation in ('edge', 'reachable'):
                cli('fact', 'schema', 'register', *target(graph), '--namespace', 'shop',
                    '--relation', relation, '--schema-version', '1', '--columns', 'src:symbol,dst:symbol', '--max-rows', '10000')
            return pack(graph)

        sequence = 0
        def mutate(graph, edges, action='put', relation='edge'):
            nonlocal sequence
            sequence += 1
            batch = f'batch-{sequence}'
            path = root / 'input.tsv'
            path.write_text('src\tdst\n' + ''.join(f'{x}\t{y}\n' for x, y in sorted(edges)), encoding='utf-8')
            cli('fact', action, *target(graph), '--namespace', 'shop', '--relation', relation,
                '--schema-version', '1', '--batch-id', batch, '--idempotency-key', batch,
                '--format', 'tsv', '--input', path)
            return batch

        def query(graph, expected, relation='reachable'):
            started = time.monotonic()
            result = cli('datalog', 'query', *target(graph), '--query', f'{relation}(X,Y)',
                '--output', 'json', '--limit', '10000')
            elapsed = time.monotonic() - started
            value = json.loads(result.stdout)
            assert value['graph_id'] == graph and value['relation'] == relation, value
            assert value['columns'] == ['X', 'Y'] and value['truncated'] is False, value
            rows = value['rows']
            assert all(set(row) == {'X', 'Y'} for row in rows), value
            actual = [(row['X'], row['Y']) for row in rows]
            assert len(actual) == len(set(actual)) == value['row_count'], value
            assert set(actual) == expected, (graph, relation, expected, value)
            return elapsed

        try:
            start()
            arm('wr.tenant.manage', '__wr_default')
            cli('tenant', 'create', '--name', tenant)
            tenant_created = True
            login(scoped_token, tenant)
            for permission in ('wr.graph.manage', 'wr.schema.manage', 'wr.fact.append',
                               'wr.fact.retract', 'wr.fact.forget', 'wr.datalog.query',
                               'wr.datalog.infer'):
                arm(permission, tenant)
            graph = 'recursive'
            registered = create(graph)
            assert 'pack_version=1 ' in registered.stdout, registered.stdout
            digest = registered.stdout.split('digest=')[1].strip()
            query(graph, set())
            edges = {('a', 'b'), ('b', 'c')}
            mutate(graph, edges)
            query(graph, {('a', 'b'), ('b', 'c'), ('a', 'c')})
            query(graph, closure(edges))
            query(graph, edges, 'edge')
            mutate(graph, {('b', 'c')}, 'retract')
            edges.remove(('b', 'c'))
            query(graph, closure(edges))
            alternate = {('a', 'd'), ('d', 'c')}
            alternate_batch = mutate(graph, alternate)
            edges |= alternate
            query(graph, closure(edges))
            durable = mutate(graph, {('a', 'c')}, relation='reachable')
            cli('fact', 'forget', *target(graph), '--namespace', 'shop', '--relation', 'edge',
                '--schema-version', '1', '--batch-id', alternate_batch, '--operator', 'admin',
                '--reason', 'qualification', '--confirm')
            edges -= alternate
            query(graph, closure(edges) | {('a', 'c')})
            refused = pack(graph, 'reachable(X,Y):-edge(X,Y),!reachable(X,Y).', success=False)
            assert 'rule_pack_negative_cycle' in refused.stderr, refused.stderr
            query(graph, closure(edges) | {('a', 'c')})
            replacement = pack(graph)
            assert 'pack_version=2 ' in replacement.stdout, replacement.stdout
            assert replacement.stdout.split('digest=')[1].strip() == digest
            stop()
            shutil.copytree(live, root / 'backup')
            start()
            query(graph, closure(edges) | {('a', 'c')})
            mutate(graph, {('c', 'z')})
            query(graph, closure(edges | {('c', 'z')}) | {('a', 'c'), ('a', 'z')})
            # A changed active pack makes restoration of policy observable too.
            pack(graph, 'reachable(X,Y):-edge(X,Y).')
            query(graph, edges | {('c', 'z'), ('a', 'c')})
            stop()
            restore_tree(root / 'backup', live)
            start()
            query(graph, closure(edges) | {('a', 'c')})
            mutate(graph, {('b', 'q')})
            query(graph, closure(edges | {('b', 'q')}) | {('a', 'c')})
            cli('fact', 'forget', *target(graph), '--namespace', 'shop', '--relation', 'reachable',
                '--schema-version', '1', '--batch-id', durable, '--operator', 'admin',
                '--reason', 'qualification', '--confirm')
            query(graph, closure(edges | {('b', 'q')}))
            print(json.dumps({'case': 'lifecycle', 'result': 'passed',
                'restore': 'stopped matching policy/key/audit/fact-root, changed facts and pack before rollback'}), flush=True)
            for shape in ('chain', 'cycle', 'fanout'):
                for size in (8, 16, 32):
                    name = f'{shape}-{size}'
                    create(name)
                    pairs = {(f'v{i}', f'v{i+1}') for i in range(size - 1)}
                    if shape == 'cycle':
                        pairs.add((f'v{size-1}', 'v0'))
                    elif shape == 'fanout':
                        pairs = {('v0', f'v{i}') for i in range(1, size)}
                    mutate(name, pairs)
                    expected = closure(pairs)
                    first = query(name, expected)
                    unchanged = query(name, expected)
                    started = time.monotonic()
                    cli('tenant', 'seal', '--name', tenant, '--confirm')
                    seal = time.monotonic() - started
                    cli('tenant', 'unseal', '--name', tenant)
                    query(name, expected)
                    print(json.dumps({'case': 'growth', 'shape': shape, 'vertices': size,
                        'seed_rows': len(pairs), 'result_rows': len(expected), 'workers': 1,
                        'seal_scope': 'dedicated tenant, cumulative graphs',
                        'timing_route': 'wyctl subprocess plus HTTP/client',
                        'first_query_seconds': first, 'unchanged_query_seconds': unchanged,
                        'sequential_tenant_seal_seconds': seal}), flush=True)
            cli('tenant', 'seal', '--name', tenant, '--confirm')
            cli('tenant', 'delete', '--name', tenant)
            assert not list((live / 'facts').rglob('facts.duckdb')), 'tenant facts survived deletion'
            print(json.dumps({'case': 'tenant-deletion', 'result': 'passed'}), flush=True)
        except BaseException:
            if log.exists():
                print(log.read_text(encoding='utf-8', errors='replace'), file=sys.stderr)
            raise
        finally:
            stop()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, interrupted)
    run(*sys.argv[1:])
