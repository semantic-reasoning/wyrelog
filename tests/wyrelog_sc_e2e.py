#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared stdlib-only helper for the packaged service-credential lifecycle
e2e harness (issue #382).

Invoked as:  python3 wyrelog_sc_e2e.py <subcommand> [args...]

Every subcommand is deliberately small and library-style so the shell harness
can compose the packaged public surface (HTTP + wyctl) without inlining Python
heredocs. No secret or token is ever accepted or printed as a command-line
argument; bearer tokens are always read from 0600 files.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TENANT = "__wr_default"

# Standard KSUID: 20-byte image (4-byte big-endian (unix - epoch) + 16 random
# bytes) base62-encoded to exactly 27 chars. This matches libchronoid, so a
# minted id passes the daemon's wyl_request_id_is_canonical round-trip check.
_KSUID_EPOCH = 1400000000
_B62_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


def _mint_ksuid():
    ts = int(time.time()) - _KSUID_EPOCH
    raw = struct.pack(">I", ts) + os.urandom(16)
    n = int.from_bytes(raw, "big")
    out = []
    for _ in range(27):
        n, rem = divmod(n, 62)
        out.append(_B62_ALPHABET[rem])
    return "".join(reversed(out))


def _read_token(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _post(url, token=None, data=None, timeout=5):
    """POST to url, optionally with a bearer token and JSON body bytes. Returns
    (status, body_str)."""
    req = urllib.request.Request(url, method="POST", data=data)
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.getcode(), response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _totp(seed, step=None):
    """RFC-6238 6-digit TOTP for the given base32-decoded seed and 30s step."""
    if step is None:
        step = int(time.time()) // 30
    digest = hmac.new(seed, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return code % 1000000


def cmd_pick_port(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        print(sock.getsockname()[1])
    return 0


def cmd_login_skip_mfa(args):
    url = "%s/auth/login?username=%s&tenant=%s&skip_mfa=true" % (
        args.base_url, args.username, DEFAULT_TENANT)
    status, body = _post(url)
    if status != 200:
        sys.stderr.write("login-skip-mfa: HTTP %d: %s\n" % (status, body))
        return 1
    token = json.loads(body).get("access_token")
    if not token:
        sys.stderr.write("login-skip-mfa: no access_token in %s\n" % body)
        return 1
    print(token)
    return 0


def cmd_totp_admin(args):
    """Enroll a REAL TOTP administrator via the packaged HTTP surface and print
    its bearer access token. Mirrors the RFC-6238 enroll + login + mfa/verify
    sequence in check-wyrelogd-bootstrap-admin.sh."""
    admin_token = _read_token(args.admin_token_file)

    # Enroll the new subject using an existing admin bearer. Start the challenge,
    # capture secret_base32, then confirm with the current TOTP code.
    start_url = ("%s/auth/mfa/enroll/start?tenant=%s"
                 "&guard_timestamp=%d&guard_loc_class=public&guard_risk=10") % (
        args.base_url, DEFAULT_TENANT, int(time.time() * 1_000_000))
    start_req = urllib.request.Request(
        start_url, method="POST",
        data=json.dumps({"subject": args.username}).encode("utf-8"))
    start_req.add_header("Authorization", "Bearer " + admin_token)
    start_req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(start_req, timeout=5) as response:
            challenge = json.load(response)
    except urllib.error.HTTPError as exc:
        sys.stderr.write("totp-admin: enroll/start HTTP %d: %s\n" % (
            exc.code, exc.read().decode("utf-8")))
        return 1

    secret_b32 = challenge.get("secret_base32")
    challenge_id = challenge.get("challenge")
    if not secret_b32 or not challenge_id:
        sys.stderr.write("totp-admin: missing secret_base32/challenge in %s\n"
                         % json.dumps(challenge))
        return 1
    seed = base64.b32decode(secret_b32)

    confirm_url = ("%s/auth/mfa/enroll/confirm?tenant=%s"
                   "&guard_timestamp=%d&guard_loc_class=public&guard_risk=10") % (
        args.base_url, DEFAULT_TENANT, int(time.time() * 1_000_000))

    def confirm(step=None):
        body = json.dumps(
            {"challenge": challenge_id, "code": "%06d" % _totp(seed, step)})
        req = urllib.request.Request(
            confirm_url, method="POST", data=body.encode("utf-8"))
        req.add_header("Authorization", "Bearer " + admin_token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.getcode(), response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    status, cbody = confirm()
    if status != 200:
        # Retry once on the next step boundary in case of a watermark race.
        time.sleep(30 - (time.time() % 30) + 0.25)
        status, cbody = confirm()
        if status != 200:
            sys.stderr.write("totp-admin: enroll/confirm HTTP %d: %s\n" % (
                status, cbody))
            return 1

    if args.secret_out:
        with open(args.secret_out, "w", encoding="utf-8") as handle:
            handle.write(secret_b32)

    # Enrollment consumes the current step as its replay watermark; wait for the
    # next window before proving the enrolled admin can log in.
    time.sleep(30 - (time.time() % 30) + 0.25)

    login_url = "%s/auth/login?username=%s&tenant=%s" % (
        args.base_url, args.username, DEFAULT_TENANT)
    status, lbody = _post(login_url)
    if status != 200:
        sys.stderr.write("totp-admin: login HTTP %d: %s\n" % (status, lbody))
        return 1
    session = json.loads(lbody).get("session_token")
    if not session:
        sys.stderr.write("totp-admin: no session_token in %s\n" % lbody)
        return 1

    verify_url = "%s/auth/mfa/verify?session_token=%s&code=%06d" % (
        args.base_url, session, _totp(seed))
    status, vbody = _post(verify_url)
    if status != 200:
        sys.stderr.write("totp-admin: mfa/verify HTTP %d: %s\n" % (
            status, vbody))
        return 1
    token = json.loads(vbody).get("access_token")
    if not token:
        sys.stderr.write("totp-admin: no access_token in %s\n" % vbody)
        return 1
    print(token)
    return 0


def cmd_login_totp(args):
    """Mint a fresh MFA-assured bearer for an ALREADY-ENROLLED admin using its
    saved TOTP secret. Unlike totp-admin (which enrolls), this only drives the
    login -> mfa/verify handshake, so it can re-mint a live-MFA session on a
    later daemon boot (sessions are in-memory and lost on restart; a management
    self-arm + issue/rotate needs a live session on THAT boot). The secret is
    read from a 0600 file, never passed on a command line.

    mfa/verify consumes the current TOTP step as a replay watermark, so on a
    non-200 verify we retry once on the next 30s window."""
    with open(args.secret_file, "r", encoding="utf-8") as handle:
        secret_b32 = handle.read().strip()
    seed = base64.b32decode(secret_b32)

    def one_attempt():
        login_url = "%s/auth/login?username=%s&tenant=%s" % (
            args.base_url, args.username, DEFAULT_TENANT)
        status, lbody = _post(login_url)
        if status != 200:
            return status, "login: " + lbody, None
        session = json.loads(lbody).get("session_token")
        if not session:
            return status, "login: no session_token in " + lbody, None
        verify_url = "%s/auth/mfa/verify?session_token=%s&code=%06d" % (
            args.base_url, session, _totp(seed))
        vstatus, vbody = _post(verify_url)
        if vstatus != 200:
            return vstatus, "verify: " + vbody, None
        token = json.loads(vbody).get("access_token")
        if not token:
            return vstatus, "verify: no access_token in " + vbody, None
        return 200, None, token

    status, err, token = one_attempt()
    if token is None:
        # Retry on the next TOTP window in case the current step was already
        # consumed as a replay watermark.
        time.sleep(30 - (time.time() % 30) + 0.25)
        status, err, token = one_attempt()
        if token is None:
            sys.stderr.write("login-totp: %s (HTTP %d)\n" % (err, status))
            return 1
    print(token)
    return 0


def cmd_http_post(args):
    token = _read_token(args.token_file)
    query = "&".join(args.query) if args.query else ""
    url = "%s%s" % (args.base_url, args.path)
    if query:
        url = "%s?%s" % (url, query)
    data = None
    if args.json_field:
        obj = {}
        for pair in args.json_field:
            key, _, value = pair.partition("=")
            obj[key] = value
        data = json.dumps(obj).encode("utf-8")
    status, body = _post(url, token=token, data=data)
    print("status=%d" % status)
    if body:
        print(body)
    return 0 if 200 <= status < 300 else 1


def cmd_mint_request_id(args):
    print(_mint_ksuid())
    return 0


def cmd_decide(args):
    """Observe a service-token authorization decision via raw POST /decide.

    The service token goes in the Authorization: Bearer header; user/perm/tenant
    identify the subject, permission, and tenant to evaluate. This replaces
    `wyctl policy check`, which pins tenant to __wr_default and cannot observe a
    service token in a created tenant.

    The daemon's /decide handler requires a non-empty `session_token` query
    param, which it maps into the decide request as the resource id. The
    --resource value (default "decision") supplies it."""
    token = _read_token(args.token_file)
    resource = args.resource if args.resource else "decision"
    url = "%s/decide?user=%s&perm=%s&tenant=%s&session_token=%s" % (
        args.base_url, args.user, args.perm, args.tenant, resource)
    status, body = _post(url, token=token)
    decision = "error"
    try:
        parsed = json.loads(body)
        raw = parsed.get("decision")
        if raw == 1:
            decision = "allow"
        elif raw == 0:
            decision = "deny"
    except (ValueError, TypeError):
        pass
    # A non-2xx from the tenant/actor gate (403 tenant_denied, decide_denied,
    # 401 auth) is itself a deny outcome for the matrix; surface it as deny.
    if status != 200 and decision == "error":
        decision = "deny"
    print("status=%d decision=%s" % (status, decision))
    print(body)
    return 0


def cmd_arm(args):
    """Self-arm the service-credential management authority for the caller's own
    live-MFA session (POST /service-management-authority/arm). The daemon's HTTP
    query parser reads UNDERSCORE guard keys (guard_timestamp/guard_loc_class/
    guard_risk); the hyphenated forms are only the wyctl CLI spelling. A 200 with
    ok:true is the sole success shape."""
    token = _read_token(args.token_file)
    url = ("%s/service-management-authority/arm?guard_timestamp=%s"
           "&guard_loc_class=%s&guard_risk=%s") % (
        args.base_url, args.guard_timestamp, args.guard_loc_class,
        args.guard_risk)
    status, body = _post(url, token=token)
    if status != 200:
        sys.stderr.write("arm: expected HTTP 200, got %d: %s\n" % (status, body))
        return 1
    try:
        ok = json.loads(body).get("ok")
    except (ValueError, TypeError):
        ok = None
    if ok is not True:
        sys.stderr.write("arm: response not ok:true: %s\n" % body)
        return 1
    print("arm: ok")
    return 0


def cmd_receipt_field(args):
    """Read a whitespace-separated key=value receipt line from stdin and print a
    single field's value. Used to lift credential_id/state/delivered out of the
    `wyctl service-credential issue` receipt line without a shell parser."""
    value = None
    for line in sys.stdin:
        for token in line.split():
            key, sep, val = token.partition("=")
            if sep and key == args.field:
                value = val
    if value is None:
        sys.stderr.write("receipt-field: field %s not found\n" % args.field)
        return 1
    print(value)
    return 0


def cmd_assert_decide(args):
    """Hardened service-token authorization assertion via raw POST /decide.

    Unlike `decide`, a non-200 or an unparseable/decision-less body is a HARD
    FAILURE, never silently counted as a deny. ALLOW requires HTTP 200 AND
    decision==1; DENY requires HTTP 200 AND decision==0 (a true policy deny).
    This keeps an expired service JWT (300s TTL) or an unrelated 403 gate from
    falsely satisfying an --expect deny.

    The daemon's /decide handler maps the session_token query param to the decide
    request's resource id, which IS the decision SCOPE (the engine evaluates
    allow(user, perm, scope) with scope=resource_id). It must therefore equal the
    scope a role was granted at -- the tenant -- not an opaque literal. --scope
    overrides it; by default the request tenant doubles as the scope, matching
    the #744 public-path fixture in test-daemon-http-decide.c."""
    token = _read_token(args.token_file)
    scope = args.scope if args.scope else args.tenant
    url = "%s/decide?user=%s&perm=%s&tenant=%s&session_token=%s" % (
        args.base_url, args.user, args.perm, args.tenant, scope)
    status, body = _post(url, token=token)
    if status != 200:
        sys.stderr.write(
            "assert-decide: expected HTTP 200, got %d: %s\n" % (status, body))
        return 1
    try:
        raw = json.loads(body).get("decision")
    except (ValueError, TypeError):
        sys.stderr.write("assert-decide: unparseable body: %s\n" % body)
        return 1
    if raw == 1:
        decision = "allow"
    elif raw == 0:
        decision = "deny"
    else:
        sys.stderr.write("assert-decide: no decision field in body: %s\n" % body)
        return 1
    if decision != args.expect:
        sys.stderr.write(
            "assert-decide: expected %s, got %s (HTTP 200): %s\n" % (
                args.expect, decision, body))
        return 1
    print("assert-decide: %s (expected)" % decision)
    return 0


def cmd_assert_http_status(args):
    """Assert a POST to an arbitrary packaged route returns an EXACT HTTP status
    (and, optionally, that the JSON error body carries an expected error code).

    This is the fail-loud counterpart to assert-decide for the NON-200 outcomes
    that assert-decide deliberately treats as hard failures: a 401 at service
    bearer resolution (a revoked credential / disabled principal token that stops
    resolving) or a 400 tenant_sealed (a decide against a sealed tenant). A bearer
    token is optional (--token-file); query params and an optional JSON body are
    composed exactly as cmd_http_post does, so /decide can be driven with the
    service token in the Authorization header and user/perm/tenant/session_token
    in the query string."""
    token = _read_token(args.token_file) if args.token_file else None
    query = "&".join(args.query) if args.query else ""
    url = "%s%s" % (args.base_url, args.path)
    if query:
        url = "%s?%s" % (url, query)
    data = None
    if args.json_field:
        obj = {}
        for pair in args.json_field:
            key, _, value = pair.partition("=")
            obj[key] = value
        data = json.dumps(obj).encode("utf-8")
    status, body = _post(url, token=token, data=data)
    if status != args.expect_status:
        sys.stderr.write(
            "assert-http-status: expected HTTP %d, got %d: %s\n" % (
                args.expect_status, status, body))
        return 1
    if args.expect_error is not None:
        observed = None
        try:
            observed = json.loads(body).get("error")
        except (ValueError, TypeError):
            observed = None
        if observed != args.expect_error:
            sys.stderr.write(
                "assert-http-status: expected error %r, got %r (HTTP %d): %s\n"
                % (args.expect_error, observed, status, body))
            return 1
    print("assert-http-status: HTTP %d%s (expected)" % (
        status, (" error=%s" % args.expect_error) if args.expect_error else ""))
    return 0


def cmd_assert_no_refresh(args):
    """Prove a LIVE service token has no refresh/renewal path.

    A service-credential exchange yields ONLY an access token -- no refresh token
    is ever issued for a service credential -- and the sole refresh route,
    /auth/refresh, is human-only: it looks up an opaque server-side refresh token
    (which a service exchange never mints) and additionally rejects any
    service-prefixed subject. Presenting the live service access token to
    /auth/refresh MUST fail with 401; a 200 minting a fresh token would be a
    survivorship/renewal finding. The token is read from a 0600 file and only ever
    placed in the request body-equivalent query, never on a command line."""
    token = _read_token(args.token_file)
    url = "%s/auth/refresh?refresh_token=%s" % (
        args.base_url, urllib.parse.quote(token, safe=""))
    status, body = _post(url)
    if status != 401:
        sys.stderr.write(
            "assert-no-refresh: expected HTTP 401 (not refreshable), got %d: %s\n"
            % (status, body))
        return 1
    print("assert-no-refresh: service token not refreshable (HTTP 401)")
    return 0


def _expand_scan_targets(paths, recursive):
    """Resolve the caller's scan targets into a concrete list of readable files.

    A named target that is missing is a HARD FAILURE (never a vacuous "absent"
    pass): the caller is asserting each named sink is clean, so a sink that
    cannot even be located must fail loud. When --recursive is set a directory
    target is walked and every regular file under it is scanned; without it a
    directory target is itself an error, because the caller almost certainly
    meant to scan a tree and silently scanning nothing would be a skip-as-pass.
    """
    resolved = []
    for path in paths:
        if not os.path.exists(path):
            sys.stderr.write("scan-absent: sink not found: %s\n" % path)
            return None
        if os.path.isdir(path):
            if not recursive:
                sys.stderr.write(
                    "scan-absent: %s is a directory (pass --recursive)\n" % path)
                return None
            for root, _dirs, files in os.walk(path):
                for name in files:
                    full = os.path.join(root, name)
                    if os.path.isfile(full):
                        resolved.append(full)
        else:
            resolved.append(path)
    return resolved


def cmd_scan_absent(args):
    if args.needle_file:
        with open(args.needle_file, "rb") as handle:
            needle = handle.read().strip()
    elif args.needle is not None:
        needle = args.needle.encode("utf-8")
    else:
        sys.stderr.write("scan-absent: --needle or --needle-file is required\n")
        return 2
    if not needle:
        sys.stderr.write("scan-absent: empty needle\n")
        return 2
    if args.hex_needle:
        # The needle is a hex TEXT of an authoritative binary value (verifier /
        # salt). Decode it so the scan covers BOTH the raw bytes (raw form) and
        # the hex spelling (hex form) -- proving the value neither sits as
        # plaintext bytes nor as a hex second-occurrence in any sink.
        try:
            needle = bytes.fromhex(needle.decode("ascii").strip())
        except (ValueError, UnicodeDecodeError) as exc:
            sys.stderr.write("scan-absent: --hex-needle not valid hex: %s\n"
                             % exc)
            return 2
        if not needle:
            sys.stderr.write("scan-absent: empty hex needle\n")
            return 2
    targets = _expand_scan_targets(args.files, args.recursive)
    if targets is None:
        return 2
    forms = {
        "raw": needle,
        "base64": base64.b64encode(needle),
        "hex": needle.hex().encode("ascii"),
    }
    leaked = False
    for path in targets:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            # A named target that cannot be read is a hard failure, never a
            # vacuous "absent" pass: the caller is asserting this sink is clean.
            sys.stderr.write("scan-absent: cannot read %s: %s\n" % (path, exc))
            return 2
        for name, form in forms.items():
            if form and form in data:
                sys.stderr.write(
                    "scan-absent: needle leaked (%s form) in %s\n" % (
                        name, path))
                leaked = True
    if leaked:
        return 1
    print("scan-absent: needle absent from %d file(s)" % len(targets))
    return 0


def _write_secret_file(path, text):
    """Write a captured sensitive canary to a 0600 file, never to stdout, so it
    can be fed to scan-absent via --needle-file without ever transiting argv or
    a scanned capture file."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def cmd_escrow_extract(args):
    """Parse a published credential escrow document and write ONE field to a
    0600 file. The escrow doc is the single place the plaintext credential
    secret legitimately lives; this lifts the secret (or credential_id) out of
    it into a 0600 needle file so the leak scan can assert the secret is ABSENT
    from every OTHER (forbidden) sink. The value never touches stdout or argv."""
    with open(args.escrow_file, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        sys.stderr.write("escrow-extract: unparseable escrow doc: %s\n" % exc)
        return 1
    key = {"secret": "credential_secret", "credential_id": "credential_id"}[
        args.field]
    value = doc.get(key)
    if not value:
        sys.stderr.write("escrow-extract: no %s in escrow doc\n" % key)
        return 1
    _write_secret_file(args.out, value)
    return 0


def _jwt_payload(token):
    """Decode the (unverified) claim set of a compact JWS. The scan only needs
    the claim VALUES as canaries; signature verification is irrelevant here."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    body = parts[1]
    body += "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body.encode("ascii")))


def cmd_jwt_claim(args):
    """Decode a service JWT (read from a 0600 token file) and write one claim
    value (jti / session_id / sub) to a 0600 file so the leak scan can assert
    that raw jti / session id never appears in a forbidden sink."""
    token = _read_token(args.token_file)
    try:
        claims = _jwt_payload(token)
    except (ValueError, TypeError) as exc:
        sys.stderr.write("jwt-claim: cannot decode token: %s\n" % exc)
        return 1
    value = claims.get(args.claim)
    if not value:
        sys.stderr.write("jwt-claim: no %s claim in token\n" % args.claim)
        return 1
    _write_secret_file(args.out, str(value))
    return 0


def cmd_bearer_file(args):
    """Reconstruct the exact `Authorization: Bearer <jwt>` header value into a
    0600 file so the leak scan can assert the full bearer header string never
    lands in a forbidden sink."""
    token = _read_token(args.token_file)
    _write_secret_file(args.out, "Bearer " + token)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pick-port").set_defaults(func=cmd_pick_port)

    p = sub.add_parser("login-skip-mfa")
    p.add_argument("--base-url", required=True)
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_login_skip_mfa)

    p = sub.add_parser("totp-admin")
    p.add_argument("--base-url", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--admin-token-file", required=True)
    p.add_argument("--secret-out", default=None)
    p.set_defaults(func=cmd_totp_admin)

    p = sub.add_parser("login-totp")
    p.add_argument("--base-url", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--secret-file", required=True)
    p.set_defaults(func=cmd_login_totp)

    p = sub.add_parser("http-post")
    p.add_argument("--base-url", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--query", action="append", default=[])
    p.add_argument("--json-field", action="append", default=[],
                   help="k=v pair added to a JSON request body (string values)")
    p.set_defaults(func=cmd_http_post)

    sub.add_parser("mint-request-id").set_defaults(func=cmd_mint_request_id)

    p = sub.add_parser("decide")
    p.add_argument("--base-url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--perm", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--resource", default=None)
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("arm")
    p.add_argument("--base-url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--guard-timestamp", required=True)
    p.add_argument("--guard-loc-class", required=True)
    p.add_argument("--guard-risk", required=True)
    p.set_defaults(func=cmd_arm)

    p = sub.add_parser("receipt-field")
    p.add_argument("--field", required=True)
    p.set_defaults(func=cmd_receipt_field)

    p = sub.add_parser("assert-decide")
    p.add_argument("--base-url", required=True)
    p.add_argument("--token-file", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--perm", required=True)
    p.add_argument("--tenant", required=True)
    p.add_argument("--expect", required=True, choices=("allow", "deny"))
    p.add_argument("--scope", default=None,
                   help="decision scope (session_token); defaults to --tenant")
    p.set_defaults(func=cmd_assert_decide)

    p = sub.add_parser("assert-http-status")
    p.add_argument("--base-url", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--token-file", default=None,
                   help="optional bearer token file (Authorization header)")
    p.add_argument("--query", action="append", default=[])
    p.add_argument("--json-field", action="append", default=[],
                   help="k=v pair added to a JSON request body (string values)")
    p.add_argument("--expect-status", required=True, type=int)
    p.add_argument("--expect-error", default=None,
                   help="expected JSON `error` field value, if any")
    p.set_defaults(func=cmd_assert_http_status)

    p = sub.add_parser("assert-no-refresh")
    p.add_argument("--base-url", required=True)
    p.add_argument("--token-file", required=True)
    p.set_defaults(func=cmd_assert_no_refresh)

    p = sub.add_parser("scan-absent")
    p.add_argument("--needle", default=None)
    p.add_argument("--needle-file", default=None,
                   help="read the secret needle from a 0600 file (avoids argv)")
    p.add_argument("--recursive", action="store_true",
                   help="walk directory targets, scanning every file under them")
    p.add_argument("--hex-needle", action="store_true",
                   help="decode the needle from hex so raw bytes AND the hex "
                        "spelling are both scanned (verifier/salt)")
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_scan_absent)

    p = sub.add_parser("escrow-extract")
    p.add_argument("--escrow-file", required=True)
    p.add_argument("--field", required=True, choices=("secret", "credential_id"))
    p.add_argument("--out", required=True,
                   help="0600 file to receive the extracted value")
    p.set_defaults(func=cmd_escrow_extract)

    p = sub.add_parser("jwt-claim")
    p.add_argument("--token-file", required=True)
    p.add_argument("--claim", required=True,
                   choices=("jti", "session_id", "sub"))
    p.add_argument("--out", required=True,
                   help="0600 file to receive the claim value")
    p.set_defaults(func=cmd_jwt_claim)

    p = sub.add_parser("bearer-file")
    p.add_argument("--token-file", required=True)
    p.add_argument("--out", required=True,
                   help="0600 file to receive the `Bearer <jwt>` header value")
    p.set_defaults(func=cmd_bearer_file)

    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
