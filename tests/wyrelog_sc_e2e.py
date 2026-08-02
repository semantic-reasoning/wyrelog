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


def cmd_scan_absent(args):
    needle = args.needle.encode("utf-8")
    forms = {
        "raw": needle,
        "base64": base64.b64encode(needle),
        "hex": needle.hex().encode("ascii"),
    }
    leaked = False
    for path in args.files:
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        for name, form in forms.items():
            if form and form in data:
                sys.stderr.write(
                    "scan-absent: needle leaked (%s form) in %s\n" % (
                        name, path))
                leaked = True
    if leaked:
        return 1
    print("scan-absent: needle absent from %d file(s)" % len(args.files))
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

    p = sub.add_parser("scan-absent")
    p.add_argument("--needle", required=True)
    p.add_argument("files", nargs="+")
    p.set_defaults(func=cmd_scan_absent)

    return parser


def main(argv):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
