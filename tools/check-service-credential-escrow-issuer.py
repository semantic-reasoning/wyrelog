#!/usr/bin/env python3
"""Freeze the daemon issue/rotate surface to the non-secret escrow receipt.

The #517 capstone: the daemon HTTP issue and rotate handlers must reach
issuance ONLY through the escrow handoff and must return ONLY the module's
non-secret receipt.  Three structural invariants enforce that no future
edit can regress into echoing a plaintext credential:

  A1  No secret-returning domain issuer is called from any daemon/*.c.
      The four dangerous entrypoints -- wyl_service_credential_issue,
      _issue_with_runtime, _rotate, _rotate_with_runtime -- hand back a
      live secret.  Only the escrow variants (_issue_handoff_with_runtime,
      _rotate_handoff_checked_with_runtime) may be reached, and they never
      surface the secret.  The regex structurally excludes the escrow
      variants: after issue/rotate the next char is '_handoff', so the
      optional _with_runtime group fails and \\s*\\( cannot match '_'.

  A2  No inline secret RESPONSE key.  A2 forbids ONLY the escaped-quote
      spelling \\"credential_secret\\" -- the form that appears inside a C
      string literal being appended to a response body.  The daemon
      legitimately holds a secret as INPUT to the /auth/service-token
      exchange, spelled with a BARE key "credential_secret" (a request
      field descriptor), which A2 deliberately does NOT match.  A2 is
      intentionally narrow; A1 is what guarantees the daemon HTTP surface
      can never OBTAIN a fresh secret to echo in the first place.

  A3  Receipt shape lock on service-credential-handoff-private.c:
      (a) the bare token 'secret' must not appear anywhere in the module;
      (b) every emitted JSON key literal must be a SUBSET of the frozen
          allowlist.  The receipt emits keys through three GString forms
          (g_string_new, g_string_append, g_string_append_printf); the
          extractor matches the escaped-quote key form \\"<key>\\": across
          the whole file, so it covers all three forms uniformly.  A3(b)
          locks STATICALLY-spelled keys; a computed key (e.g. a \\"%s\\":
          format placeholder) is not extracted, so containment ultimately
          rests on A1 -- the daemon cannot obtain a fresh secret to smuggle
          under any key -- with A3 as the reviewable shape freeze.

The A3(b) allowlist is a deliberate capstone FREEZE.  A future PR that
legitimately adds a receipt field MUST update BOTH the allowlist below AND
the self-test fixtures -- that is the intended, reviewable friction.
"""

from pathlib import Path
import re
import sys


# A1: the four secret-returning domain issuers, excluding the escrow
# variants (see the module docstring for why the exclusion is structural).
A1_ISSUER = re.compile(
    r"\bwyl_service_credential_(issue|rotate)(_with_runtime)?\s*\(")

# A2: the escaped-quote RESPONSE-emission spelling only.  The bare input
# field "credential_secret" at http.c must NOT match.
A2_RESPONSE_KEY = '\\"credential_secret\\"'

# A3(a): the bare token that a future secret serialization would introduce.
A3_SECRET_TOKEN = re.compile(r"\bsecret\b")

# A3(b): an emitted JSON key inside a C string literal, i.e. an escaped
# quote, an identifier, an escaped quote, then a colon.  Matching on the
# raw file text covers g_string_new, g_string_append and
# g_string_append_printf identically.
A3_RECEIPT_KEY = re.compile(r'\\"([A-Za-z_][A-Za-z0-9_]*)\\":')

# The frozen receipt shape.  DO NOT extend without also extending the
# self-test; see the capstone-freeze note in the module docstring.
RECEIPT_KEY_ALLOWLIST = frozenset({
    "state",
    "request_id",
    "credential_id",
    "generation",
    "destination",
    "publication_receipt_id",
    "delivered",
})

HANDOFF_MODULE = "service-credential-handoff-private.c"


def a1_violations(text: str) -> list[str]:
    return sorted({match.group(0) for match in A1_ISSUER.finditer(text)})


def a2_violation(text: str) -> bool:
    return A2_RESPONSE_KEY in text


def a3_secret_violation(text: str) -> bool:
    return A3_SECRET_TOKEN.search(text) is not None


def a3_receipt_keys(text: str) -> set[str]:
    return set(A3_RECEIPT_KEY.findall(text))


def a3_key_violations(text: str) -> list[str]:
    return sorted(a3_receipt_keys(text) - RECEIPT_KEY_ALLOWLIST)


def check_root(root: Path) -> int:
    daemon = root / "wyrelog" / "daemon"
    sources = sorted(daemon.glob("*.c"))
    if not sources:
        print(f"no daemon sources under {daemon}", file=sys.stderr)
        return 1
    for source in sources:
        text = source.read_text(encoding="utf-8")
        offenders = a1_violations(text)
        if offenders:
            print(f"secret-returning issuer reached from {source}:",
                  *offenders, sep="\n  ", file=sys.stderr)
            return 1
        if a2_violation(text):
            print(f"inline secret response key in {source}: "
                  f"{A2_RESPONSE_KEY}", file=sys.stderr)
            return 1
    handoff = daemon / HANDOFF_MODULE
    text = handoff.read_text(encoding="utf-8")
    if a3_secret_violation(text):
        print(f"secret token present in {handoff}", file=sys.stderr)
        return 1
    keys = a3_receipt_keys(text)
    if not keys:
        print(f"receipt-key extractor found no keys in {handoff}: "
              "the guard is broken, not the source", file=sys.stderr)
        return 1
    offenders = sorted(keys - RECEIPT_KEY_ALLOWLIST)
    if offenders:
        print(f"receipt key outside the frozen allowlist in {handoff}:",
              *offenders, sep="\n  ", file=sys.stderr)
        return 1
    return 0


def self_test() -> int:
    # A1: a dangerous call fails; the escrow variants and a clean source
    # pass.
    if a1_violations("rc = wyl_service_credential_issue (handle, &out);") \
            != ["wyl_service_credential_issue ("]:
        return 1
    if a1_violations(
            "wyl_service_credential_rotate_with_runtime (h, &r);") \
            != ["wyl_service_credential_rotate_with_runtime ("]:
        return 1
    if a1_violations(
            "wyl_service_credential_issue_handoff_with_runtime (h);"):
        return 1
    if a1_violations(
            "wyl_service_credential_rotate_handoff_checked_with_runtime (h);"):
        return 1
    if a1_violations("wyl_daemon_service_credential_handoff (&ctx, &in);"):
        return 1

    # A2: the escaped response spelling fails; the bare input field passes.
    if not a2_violation('g_string_append (json, ",\\"credential_secret\\":");'):
        return 1
    bare_input_field = (
        '{"credential_secret", 16384, '
        'WYL_DAEMON_HTTP_STRICT_JSON_STRING},')
    if a2_violation(bare_input_field):
        return 1

    # A3(a): the bare secret token fails; a clean module passes.
    if not a3_secret_violation("out->secret = g_strdup (record->secret);"):
        return 1
    if a3_secret_violation('g_string_append (json, ",\\"delivered\\":");'):
        return 1

    # A3(b): a clean 7-key receipt (all three GString forms) passes.
    clean_receipt = (
        'GString *json = g_string_new ("{\\"state\\":");\n'
        'g_string_append (json, ",\\"request_id\\":");\n'
        'g_string_append (json, ",\\"credential_id\\":");\n'
        'g_string_append_printf (json, ",\\"generation\\":%llu", gen);\n'
        'g_string_append (json, ",\\"destination\\":");\n'
        'g_string_append (json, ",\\"publication_receipt_id\\":");\n'
        'g_string_append_printf (json, ",\\"delivered\\":%s}", flag);\n')
    if a3_receipt_keys(clean_receipt) != RECEIPT_KEY_ALLOWLIST:
        return 1
    if a3_key_violations(clean_receipt):
        return 1
    # Anchor coverage: state proves g_string_new, generation/delivered
    # prove g_string_append_printf, destination proves g_string_append.
    for anchor in ("state", "generation", "delivered", "destination"):
        if anchor not in a3_receipt_keys(clean_receipt):
            return 1

    # A3(b) tamper via g_string_append_printf MUST be caught -- this proves
    # the extractor is not limited to g_string_new/g_string_append.
    printf_tamper = clean_receipt + \
        'g_string_append_printf (json, ",\\"escrow_path\\":%s", path);\n'
    if a3_key_violations(printf_tamper) != ["escrow_path"]:
        return 1

    # A3(b) tamper via g_string_append is also caught.
    append_tamper = clean_receipt + \
        'g_string_append (json, ",\\"leaked_root\\":");\n'
    if a3_key_violations(append_tamper) != ["leaked_root"]:
        return 1

    # A3(b) tamper via g_string_new is also caught.
    new_tamper = 'GString *j = g_string_new ("{\\"escrow_dir\\":");\n'
    if a3_key_violations(new_tamper) != ["escrow_dir"]:
        return 1

    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 2:
        print("usage: check-service-credential-escrow-issuer.py "
              "ROOT | --self-test", file=sys.stderr)
        return 2
    return check_root(Path(sys.argv[1]))


if __name__ == "__main__":
    raise SystemExit(main())
