#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Packaged, encrypted, end-to-end LEAK SCAN for the service-credential surface
# (issue #382, Unit 5). Drives the PACKAGED production daemon and the wyctl
# client through the full lifecycle prefix (bootstrap -> real-TOTP admin ->
# self-arm -> tenant/principal -> issue -> exchange -> grant -> decide ->
# rotate), captures a per-run UNIQUE canary for every sensitive value the test
# can observe, and then asserts each canary is ABSENT from EVERY forbidden sink
# in raw + base64 + hex forms. A single hit is a real secret leak in the
# packaged product: the scan FAILS LOUD and never weakens or omits a sink.
#
# THE LEAK/STORAGE CONTRACT (#382), implemented EXACTLY:
#   AUTHORITATIVE (permitted, must remain stable):
#     - each credential's per-row salt + verifier live in the authoritative
#       service_credentials columns of the ENCRYPTED policy store;
#     - the sealed CVK envelope lives in its authoritative singleton storage.
#     These are NOT plaintext secrets/CVK. The ONE permitted plaintext artifact
#     is the deliberately-published escrow document under $PUBROOT.
#   FORBIDDEN sinks (must contain NO sensitive material):
#     - Wirelog facts        ($FACT_ROOT, recursively)
#     - audit store          ($AUDIT_DB [+ .wal])
#     - recovery records     ($OPROOT, recursively)
#     - daemon logs          ($LOG.out, $LOG.err)
#     - operation captures   ($CAP, recursively: every CLI/HTTP stdout+stderr)
#   The escrow doc under $PUBROOT is the ONLY place the credential secret may
#   appear, so $PUBROOT is deliberately NOT in the sink set (scanning it would
#   be a false positive). Every canary is proven absent from every OTHER file.
#
# CANARY SET (each per-run unique; scanned raw+base64+hex across ALL sinks):
#   1. issued credential SECRET       (parsed from the credA escrow doc)
#   2. rotated credential SECRET       (B's secret, parsed from the credB escrow)
#   3. exchanged ACCESS TOKEN           (the service JWT)
#   4. Authorization BEARER value       ("Bearer <jwt>")
#   5. SESSION ID claim                 (decoded from the JWT payload)
#   6. JTI claim                        (decoded from the JWT payload)
#   7. injected REQUEST-BODY canary     (a unique KSUID posted in a request body)
#   8. admin TOTP seed                  (the enrolled base32 secret)
# AUTHORITATIVE-STORAGE-AWARE (verifier/salt captured via store-inspect):
#   9. verifier hex/bytes  -- allowed in the authoritative row; asserted to NOT
#      appear a SECOND time in any forbidden sink, AND asserted ABSENT (raw
#      bytes and hex) from the ENCRYPTED $POLICY_DB (opaque at rest).
#  10. salt hex/bytes      -- same authoritative-storage-aware treatment.
# Sealed CVK: no raw CVK is obtainable; store-inspect never exposes it, and the
# known plaintext-forbidden materials (secrets, JWT, bearer, jti, session id)
# are all asserted absent.
#
# argv: the harness writes every SECRET canary to a 0600 file and feeds
# scan-absent via --needle-file, so no secret is ever placed on a command line.
# The only --needle-on-argv value is the non-secret request-body marker, which
# is a non-secret random marker, not sensitive material.

set -eu

WYRELOGD=$1
WYCTL=$2
STORE_INSPECT=$3
TEMPLATE_DIR=$4
PY=$5
SC_E2E_PY=$6

: "${STORE_INSPECT:?store-inspect helper path required}"

TMPDIR=$(mktemp -d)
chmod 700 "$TMPDIR"
PID=

cleanup() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

fail() {
  echo "check-service-credential-leak-scan-e2e: $1" >&2
  shift
  for f in "$@"; do
    if [ -f "$f" ]; then
      echo "--- $f ---" >&2
      cat "$f" >&2
    fi
  done
  exit 1
}

now_us() {
  "$PY" - <<'PY'
import time
print(int(time.time() * 1_000_000))
PY
}

if [ ! -d "$TEMPLATE_DIR" ]; then
  fail "template dir not found at $TEMPLATE_DIR"
fi

# ---------------------------------------------------------------------------
# Encrypted, owner-only, MUTUALLY DISJOINT store/root layout. The scanned
# forbidden sinks ($FACT_ROOT, $OPROOT, $AUDIT_DB, $LOG.*, $CAP) are kept
# strictly disjoint from the canary needle files ($SEC), the escrow docs
# ($PUBROOT), the injected-request capture ($INJ), and the scan outputs
# ($SCAN) so a legitimate home is never mistaken for a leak.
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/policy.store"
KEY="$TMPDIR/policy.key"
AUDIT_DB="$TMPDIR/audit.duckdb"
FACT_ROOT="$TMPDIR/facts"
PUBROOT="$TMPDIR/publication"
OPROOT="$TMPDIR/operations"
LOG="$TMPDIR/daemon.log"
CAP="$TMPDIR/captures"    # forbidden sink: every CLI/HTTP stdout+stderr
SEC="$TMPDIR/secrets"     # 0600 canary needles + store-inspect (NOT scanned)
INJ="$TMPDIR/inject"      # injected-canary request/response (NOT scanned)
SCAN="$TMPDIR/scan"       # scan result outputs (NOT scanned)

"$PY" - "$KEY" <<'PY'
import os
import sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY

mkdir -p "$FACT_ROOT" "$PUBROOT" "$OPROOT" "$CAP" "$SEC" "$INJ" "$SCAN"
chmod 700 "$FACT_ROOT" "$PUBROOT" "$OPROOT" "$CAP" "$SEC" "$INJ" "$SCAN"

PORT=$("$PY" "$SC_E2E_PY" pick-port)
URL="http://127.0.0.1:$PORT"

"$WYRELOGD" --production --profile system --template-dir "$TEMPLATE_DIR" \
  --policy-db "$POLICY_DB" --policy-keyprovider "file:$KEY" \
  --audit-db "$AUDIT_DB" --fact-root "$FACT_ROOT" \
  --credential-publication-root "$PUBROOT" --operation-root "$OPROOT" \
  --bootstrap-admin-subject admin1 --bootstrap-admin-allow-skip-mfa \
  --listen-port "$PORT" >"$LOG.out" 2>"$LOG.err" &
PID=$!

# Readiness: poll `wyctl status`==ok with a kill -0 liveness break.
i=0
ready=0
while [ "$i" -lt 200 ]; do
  i=$((i + 1))
  if "$WYCTL" --daemon-url "$URL" --timeout-ms 500 status \
      >"$CAP/status.out" 2>"$CAP/status.err"; then
    if [ "$(cat "$CAP/status.out")" = "ok" ]; then
      ready=1
      break
    fi
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    fail "daemon exited during bootstrap" "$LOG.err"
  fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || fail "daemon did not become ready" "$LOG.err"

# --- bootstrap admin1 + real-TOTP admin2 + self-arm + tenant/principal. -------
ADMIN1_TOKEN="$SEC/admin1.token"
"$PY" "$SC_E2E_PY" login-skip-mfa --base-url "$URL" --username admin1 \
  >"$ADMIN1_TOKEN" 2>"$CAP/admin1.err" \
  || fail "admin1 skip-MFA login failed" "$CAP/admin1.err" "$LOG.err"
chmod 600 "$ADMIN1_TOKEN"

"$WYCTL" --daemon-url "$URL" policy role-grant \
  --subject admin2 --role wr.system_admin --scope __wr_default \
  --access-token-file "$ADMIN1_TOKEN" \
  --guard-timestamp 1 --guard-loc-class public --guard-risk 0 \
  >"$CAP/seed-admin2.out" 2>"$CAP/seed-admin2.err" \
  || fail "seeding admin2 system_admin failed" "$CAP/seed-admin2.err" "$LOG.err"

# The admin TOTP seed is CANARY #8; totp-admin writes it to a 0600 file.
ADMIN2_TOKEN="$SEC/admin2.token"
ADMIN2_SECRET="$SEC/admin2.secret"
"$PY" "$SC_E2E_PY" totp-admin --base-url "$URL" --username admin2 \
  --admin-token-file "$ADMIN1_TOKEN" --secret-out "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN" 2>"$CAP/admin2.err" \
  || fail "admin2 real-TOTP enrollment failed" "$CAP/admin2.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN"
chmod 600 "$ADMIN2_SECRET"

"$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
  >"$CAP/arm.out" 2>"$CAP/arm.err" \
  || fail "self-arm failed" "$CAP/arm.out" "$CAP/arm.err" "$LOG.err"

"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/permissions/transition --token-file "$ADMIN2_TOKEN" \
  --query subject=admin2 --query perm=wr.tenant.manage \
  --query scope=__wr_default --query event=grant \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$CAP/tenant-manage.out" 2>"$CAP/tenant-manage.err" \
  || fail "arming wr.tenant.manage failed" "$CAP/tenant-manage.out" "$LOG.err"

"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-a --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$CAP/tenant-create.out" 2>"$CAP/tenant-create.err" \
  || fail "creating tenant-a failed" "$CAP/tenant-create.out" "$LOG.err"

"$WYCTL" --daemon-url "$URL" service-principal create \
  --subject svc:svc-app --display-name "svc app" --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$CAP/principal.out" 2>"$CAP/principal.err" \
  || fail "service-principal create failed" "$CAP/principal.err" "$LOG.err"
grep -q "subject_id=svc:svc-app" "$CAP/principal.out" \
  || fail "service-principal create did not report subject_id=svc:svc-app" \
    "$CAP/principal.out"

# --- issue credential A -> escrow doc; CANARY #1: the issued SECRET. -----------
EXPIRES=$(( $(now_us) + 315360000000000 ))     # ~10 years out
"$WYCTL" --daemon-url "$URL" service-credential issue \
  --subject svc:svc-app --tenant tenant-a --destination credA \
  --expires-at-us "$EXPIRES" --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$CAP/issue.out" 2>"$CAP/issue.err" \
  || fail "service-credential issue failed" "$CAP/issue.err" "$LOG.err"
CRED_A=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id <"$CAP/issue.out") \
  || fail "issue receipt missing credential_id" "$CAP/issue.out"
[ -n "$CRED_A" ] && [ "$CRED_A" != "-" ] \
  || fail "issue receipt carried no credential_id" "$CAP/issue.out"
test -s "$PUBROOT/credA" || fail "escrow doc not written to \$PUBROOT/credA"
SECRET_A="$SEC/secretA.needle"
"$PY" "$SC_E2E_PY" escrow-extract --escrow-file "$PUBROOT/credA" \
  --field secret --out "$SECRET_A" \
  >"$CAP/extractA.out" 2>"$CAP/extractA.err" \
  || fail "could not extract credential A secret from escrow doc" \
    "$CAP/extractA.err"

# --- exchange -> service JWT; CANARIES #3 (token), #4 (bearer), #5/#6 claims. --
SVC_TOKEN="$SEC/svc.token"
rm -f "$SVC_TOKEN"
"$WYCTL" --daemon-url "$URL" auth service-token \
  --credential-file "$PUBROOT/credA" --token-output "$SVC_TOKEN" \
  >"$CAP/exchange.out" 2>"$CAP/exchange.err" \
  || fail "service-token exchange failed" "$CAP/exchange.err" "$LOG.err"
test -s "$SVC_TOKEN" || fail "service token not written"
chmod 600 "$SVC_TOKEN"

BEARER="$SEC/bearer.needle"
JTI="$SEC/jti.needle"
SID="$SEC/sid.needle"
"$PY" "$SC_E2E_PY" bearer-file --token-file "$SVC_TOKEN" --out "$BEARER" \
  >"$CAP/bearer.out" 2>"$CAP/bearer.err" \
  || fail "could not build bearer header canary" "$CAP/bearer.err"
"$PY" "$SC_E2E_PY" jwt-claim --token-file "$SVC_TOKEN" --claim jti --out "$JTI" \
  >"$CAP/jti.out" 2>"$CAP/jti.err" \
  || fail "could not decode jti claim" "$CAP/jti.err"
"$PY" "$SC_E2E_PY" jwt-claim --token-file "$SVC_TOKEN" --claim session_id \
  --out "$SID" >"$CAP/sid.out" 2>"$CAP/sid.err" \
  || fail "could not decode session_id claim" "$CAP/sid.err"

# --- CANARY #7: inject a unique request-body marker into a real request. ------
# The marker is posted as a JSON body field to a live route; it must not be
# echoed into any forbidden sink (daemon logs / audit / facts / recovery). The
# request/response capture lives in $INJ, which is NOT a scanned sink, so a
# legitimate response echo is never a false positive.
REQ_CANARY=$("$PY" "$SC_E2E_PY" mint-request-id)
[ -n "$REQ_CANARY" ] || fail "could not mint request-body canary"
REQ_NEEDLE="$SEC/req.needle"
printf '%s' "$REQ_CANARY" >"$REQ_NEEDLE"
chmod 600 "$REQ_NEEDLE"
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" --path /decide \
  --token-file "$SVC_TOKEN" \
  --query user=svc:svc-app --query perm=wr.svc.read_decision \
  --query tenant=tenant-a --query session_token=tenant-a \
  --json-field "leak_canary=$REQ_CANARY" \
  >"$INJ/inject.out" 2>"$INJ/inject.err" || true
# The decide itself may deny (that is fine), but the request MUST have reached
# the daemon or the request-body canary scan below would be vacuous. Assert
# delivery via the status line http-post always prints on a completed round-trip.
grep -q '^status=' "$INJ/inject.out" \
  || fail "injected request-body canary was not delivered to the daemon" \
    "$INJ/inject.err" "$LOG.err"

# --- grant + decide ALLOW (exercise the decide path + audit). ------------------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/roles/grant --token-file "$ADMIN2_TOKEN" \
  --query subject=svc:svc-app --query role=wr.viewer \
  --query scope=tenant-a --query "guard_timestamp=$(now_us)" \
  --query guard_loc_class=trusted --query guard_risk=10 \
  >"$CAP/grant.out" 2>"$CAP/grant.err" \
  || fail "granting wr.viewer@tenant-a failed" "$CAP/grant.out" "$LOG.err"

"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$CAP/decide-allow.out" 2>"$CAP/decide-allow.err" \
  || fail "post-grant /decide was not an ALLOW" \
    "$CAP/decide-allow.out" "$CAP/decide-allow.err" "$LOG.err"

# --- rotate A -> B on the SAME armed session; CANARY #2: B's SECRET. -----------
ROT_EXPIRES=$(( $(now_us) + 315360000000000 ))
"$WYCTL" --daemon-url "$URL" service-credential rotate \
  --credential-id "$CRED_A" --tenant tenant-a --destination credB \
  --expires-at-us "$ROT_EXPIRES" --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$CAP/rotate.out" 2>"$CAP/rotate.err" \
  || fail "service-credential rotate failed" "$CAP/rotate.err" "$LOG.err"
CRED_B=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id <"$CAP/rotate.out") \
  || fail "rotate receipt missing credential_id" "$CAP/rotate.out"
[ -n "$CRED_B" ] && [ "$CRED_B" != "-" ] && [ "$CRED_B" != "$CRED_A" ] \
  || fail "rotate did not produce a distinct successor" "$CAP/rotate.out"
test -s "$PUBROOT/credB" || fail "successor escrow not written to \$PUBROOT/credB"
SECRET_B="$SEC/secretB.needle"
"$PY" "$SC_E2E_PY" escrow-extract --escrow-file "$PUBROOT/credB" \
  --field secret --out "$SECRET_B" \
  >"$CAP/extractB.out" 2>"$CAP/extractB.err" \
  || fail "could not extract credential B secret from escrow doc" \
    "$CAP/extractB.err"

# ===========================================================================
# Stop the daemon so the encrypted store is released for offline store-inspect
# and so all sinks are at rest for the scan.
# ===========================================================================
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=

# --- CANARIES #9/#10: authoritative verifier/salt (active successor B). -------
# store-inspect output is the LEGITIMATE, authoritative view of these values,
# so it is written under $SEC (never a scanned sink).
"$STORE_INSPECT" "$POLICY_DB" "$KEY" "$CRED_B" \
  >"$SEC/inspectB.out" 2>"$SEC/inspectB.err" \
  || fail "store-inspect failed for successor B" "$SEC/inspectB.err"
STATE_B=$("$PY" "$SC_E2E_PY" receipt-field --field state <"$SEC/inspectB.out") \
  || fail "store-inspect output missing state" "$SEC/inspectB.out"
[ "$STATE_B" = "active" ] \
  || fail "successor B not active in authoritative store (state=$STATE_B)"
VERIFIER_HEX="$SEC/verifierB.hex"
SALT_HEX="$SEC/saltB.hex"
"$PY" "$SC_E2E_PY" receipt-field --field verifier <"$SEC/inspectB.out" \
  >"$VERIFIER_HEX" || fail "store-inspect output missing verifier" \
    "$SEC/inspectB.out"
"$PY" "$SC_E2E_PY" receipt-field --field salt <"$SEC/inspectB.out" \
  >"$SALT_HEX" || fail "store-inspect output missing salt" "$SEC/inspectB.out"
chmod 600 "$VERIFIER_HEX" "$SALT_HEX"

# ===========================================================================
# The scan. Assemble the forbidden-sink set explicitly and prove NONE is
# omitted; scan every canary across ALL of them in raw+base64+hex forms.
# ===========================================================================
# Guard against a vacuous scan: the daemon-owned sinks that this lifecycle
# genuinely populates MUST carry real content, otherwise the scan proves
# nothing. The audit store and the operation-recovery journal ($OPROOT op-*
# records) are both written by the issue/exchange/rotate flow. $FACT_ROOT is a
# named forbidden sink too and is still scanned recursively, but this
# management-plane flow emits no datalog facts, so an empty fact root is
# expected and is NOT required to be non-empty.
test -s "$AUDIT_DB" || fail "audit store is empty; a vacuous scan proves nothing"
[ -n "$(find "$OPROOT" -type f -name 'op-*' -print -quit)" ] \
  || fail "operation-recovery journal has no records; a vacuous scan proves nothing"

SINKS="$FACT_ROOT $OPROOT $AUDIT_DB $LOG.out $LOG.err $CAP"
[ -f "$AUDIT_DB.wal" ] && SINKS="$SINKS $AUDIT_DB.wal"

POLICY_FILES="$POLICY_DB"
[ -f "$POLICY_DB-wal" ] && POLICY_FILES="$POLICY_FILES $POLICY_DB-wal"
[ -f "$POLICY_DB-shm" ] && POLICY_FILES="$POLICY_FILES $POLICY_DB-shm"

# scan_needle NEEDLE_FILE LABEL -- assert a secret canary is ABSENT from every
# forbidden sink (raw+base64+hex). A hit is a real leak: FAIL LOUD.
scan_needle() {
  _needle=$1
  _label=$2
  # shellcheck disable=SC2086
  "$PY" "$SC_E2E_PY" scan-absent --needle-file "$_needle" --recursive $SINKS \
    >"$SCAN/$_label.out" 2>"$SCAN/$_label.err" \
    || fail "LEAK: $_label canary found in a forbidden sink" "$SCAN/$_label.err"
}

scan_needle "$SECRET_A"      "issued-secret"
scan_needle "$SECRET_B"      "rotated-secret"
scan_needle "$SVC_TOKEN"     "access-token"
scan_needle "$BEARER"        "bearer-header"
scan_needle "$SID"           "session-id"
scan_needle "$JTI"           "jti"
scan_needle "$REQ_NEEDLE"    "request-body"
scan_needle "$ADMIN2_SECRET" "totp-seed"

# Authoritative-storage-aware verifier/salt: allowed in the authoritative store
# row, but must NOT appear a SECOND time (raw bytes or hex) in any forbidden
# sink. --hex-needle decodes the hex so both the raw bytes and the hex spelling
# are covered.
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$VERIFIER_HEX" --hex-needle \
  --recursive $SINKS >"$SCAN/verifier-sinks.out" 2>"$SCAN/verifier-sinks.err" \
  || fail "LEAK: verifier found a SECOND time in a forbidden sink" \
    "$SCAN/verifier-sinks.err"
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$SALT_HEX" --hex-needle \
  --recursive $SINKS >"$SCAN/salt-sinks.out" 2>"$SCAN/salt-sinks.err" \
  || fail "LEAK: salt found a SECOND time in a forbidden sink" \
    "$SCAN/salt-sinks.err"

# Encrypted-at-rest: the ENCRYPTED policy store must expose NEITHER the raw
# verifier/salt bytes NOR their hex spelling. Finding nothing here proves the
# authoritative row is sealed (opaque ciphertext), not sitting in plaintext.
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$VERIFIER_HEX" --hex-needle \
  $POLICY_FILES >"$SCAN/verifier-policy.out" 2>"$SCAN/verifier-policy.err" \
  || fail "LEAK: verifier bytes/hex found in plaintext inside \$POLICY_DB" \
    "$SCAN/verifier-policy.err"
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$SALT_HEX" --hex-needle \
  $POLICY_FILES >"$SCAN/salt-policy.out" 2>"$SCAN/salt-policy.err" \
  || fail "LEAK: salt bytes/hex found in plaintext inside \$POLICY_DB" \
    "$SCAN/salt-policy.err"

echo "check-service-credential-leak-scan-e2e: leak scan"
echo "  credentials       : A=$CRED_A (rotated) -> B=$CRED_B (active)"
echo "  forbidden sinks   : \$FACT_ROOT(rec) \$OPROOT(rec) \$AUDIT_DB[+.wal]"
echo "                      \$LOG.out \$LOG.err \$CAP(rec: all CLI/HTTP output)"
echo "  secret canaries   : issued-secret rotated-secret access-token"
echo "                      bearer-header session-id jti request-body totp-seed"
echo "  authoritative     : verifier + salt absent as 2nd occurrence in sinks;"
echo "                      verifier + salt absent (raw+hex) from encrypted store"
echo "  all canaries ABSENT from all forbidden sinks (raw+base64+hex)"
echo "check-service-credential-leak-scan-e2e: PASS"
exit 0
