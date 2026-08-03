#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Packaged, encrypted, end-to-end proof of the KeyProvider ROOT ROTATION +
# CREDENTIAL ROTATION + RESTART + AUDIT sequence for service credentials
# (issue #382, Unit 3). This is the FIRST test to rotate an encrypted policy
# store that actually CONTAINS a live service credential, so it proves the
# populated CVK envelope, credential row (verifier/salt), and handoff survive an
# offline `wyctl key rotate` byte-for-byte, then that a subsequent
# `wyctl service-credential rotate` retires credential A and stands up its
# successor B, all across real daemon restarts and against a real audit sink.
#
# Everything FAILS LOUD; nothing is skipped-as-pass. Exact statuses / exit codes
# / hex bytes are asserted. The shared setup mirrors the Unit 1a lifecycle driver
# (bootstrap -> real-TOTP admin2 -> self-arm -> tenant-a -> svc:svc-app). Because
# a live-MFA session and its armed authority are in-memory (lost on restart), any
# boot that performs a management op re-mints an MFA bearer (login-totp using the
# saved TOTP secret) and re-arms on that boot.
#
# Sequence:
#   1. Issue credential A, exchange -> token, grant wr.viewer@tenant-a, /decide
#      ALLOW. Record A's credential_id + generation, then STOP and capture A's
#      authoritative VERIFIER/SALT bytes under the OLD provider (verifier_A).
#   2. STOP; `wyctl key rotate` from file:$KEY_OLD to a fresh file:$KEY_NEW
#      (retain $KEY_OLD until verified). Assert the rotate succeeds (exit 0).
#   3. Reopen with ONLY the new root and prove A survives: (a) A re-exchanges ->
#      token -> /decide ALLOW; (b) A's verifier/salt bytes are BYTE-IDENTICAL to
#      verifier_A (store-inspect under $KEY_NEW opens the store, which requires
#      unsealing the rewrapped CVK envelope under the NEW provider -- the open
#      itself proves the envelope validated); (c) fail-closed: starting with the
#      OLD root after rotation must NOT become ready (bounded, no hang).
#   4. `wyctl service-credential rotate` A -> B. Prove A is revoked (fresh
#      exchange of A fails; store-inspect A state=revoked), B exchanges -> token
#      -> /decide ALLOW at tenant-a (B inherits the subject's role), and B's
#      escrow is written 0600.
#   5. Restart the packaged daemon under $KEY_NEW; B re-exchanges -> ALLOW while
#      A remains denied (fresh exchange of A still fails).
#   6. Durable sanitized audit: the stopped audit DuckDB carries durable success
#      records (service_exchange_receipt_projections for the exchanges; allowed
#      wr.service_credential.manage decisions for issue/rotate) AND no per-run
#      secret canary (a live service JWT, the admin TOTP secret) appears anywhere
#      in the audit store bytes.

set -eu

WYRELOGD=$1
WYCTL=$2
STORE_INSPECT=$3
TEMPLATE_DIR=$4
PY=$5
SC_E2E_PY=$6
AUDIT_QUERY=$7

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
  echo "check-service-credential-rotation-e2e: $1" >&2
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
# Encrypted, owner-only, MUTUALLY DISJOINT store/root layout. KEY_OLD is the
# initial (current) Policy KeyProvider root; KEY_NEW is minted just before the
# root rotation in step 2.
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/policy.store"
KEY_OLD="$TMPDIR/policy.key.old"
KEY_NEW="$TMPDIR/policy.key.new"
AUDIT_DB="$TMPDIR/audit.duckdb"
FACT_ROOT="$TMPDIR/facts"
PUBROOT="$TMPDIR/publication"
OPROOT="$TMPDIR/operations"
LOG="$TMPDIR/daemon.log"

"$PY" - "$KEY_OLD" <<'PY'
import os
import sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY

mkdir -p "$FACT_ROOT" "$PUBROOT" "$OPROOT"
chmod 700 "$FACT_ROOT" "$PUBROOT" "$OPROOT"

PORT=$("$PY" "$SC_E2E_PY" pick-port)
URL="http://127.0.0.1:$PORT"

# start_daemon KEYSPEC -> launch the packaged production daemon against the
# shared encrypted store under the given "file:PATH" Policy KeyProvider, writing
# $LOG.out / $LOG.err. Sets global PID.
start_daemon() {
  _keyspec=$1
  "$WYRELOGD" --production --profile system --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" --policy-keyprovider "$_keyspec" \
    --audit-db "$AUDIT_DB" --fact-root "$FACT_ROOT" \
    --credential-publication-root "$PUBROOT" --operation-root "$OPROOT" \
    --bootstrap-admin-subject admin1 --bootstrap-admin-allow-skip-mfa \
    --listen-port "$PORT" >"$LOG.out" 2>"$LOG.err" &
  PID=$!
}

# wait_ready -> poll `wyctl status`==ok with a kill -0 liveness break, up to
# ~20s. Sets global `ready` to 1 on success, 0 otherwise. A daemon that dies
# during boot breaks the loop immediately.
wait_ready() {
  i=0
  ready=0
  while [ "$i" -lt 200 ]; do
    i=$((i + 1))
    if "$WYCTL" --daemon-url "$URL" --timeout-ms 500 status \
        >"$TMPDIR/status.out" 2>"$TMPDIR/status.err"; then
      if [ "$(cat "$TMPDIR/status.out")" = "ok" ]; then
        ready=1
        break
      fi
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
}

# stop_daemon -> TERM the running daemon and reap it, clearing PID so the store
# is released for offline store-inspect / key rotate / audit reads.
stop_daemon() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=
  fi
}

# exchange_ok DESTINATION OUT_TOKEN_PATH -> exchange an escrow doc to a live
# service token; FAILS LOUD otherwise.
exchange_ok() {
  _dest=$1
  _out=$2
  rm -f "$_out"
  "$WYCTL" --daemon-url "$URL" auth service-token \
    --credential-file "$PUBROOT/$_dest" --token-output "$_out" \
    >"$TMPDIR/exchange.out" 2>"$TMPDIR/exchange.err" \
    || fail "expected exchange to succeed for $_dest" \
      "$TMPDIR/exchange.err" "$LOG.err"
  test -s "$_out" || fail "exchange for $_dest wrote no token"
  chmod 600 "$_out"
}

# exchange_must_fail DESTINATION LABEL -> assert a fresh exchange FAILS and no
# token is minted (A must be dead after rotation to B).
exchange_must_fail() {
  _dest=$1
  _label=$2
  rm -f "$TMPDIR/$_label-reexchange.token"
  if "$WYCTL" --daemon-url "$URL" auth service-token \
      --credential-file "$PUBROOT/$_dest" \
      --token-output "$TMPDIR/$_label-reexchange.token" \
      >"$TMPDIR/$_label-reexchange.out" 2>"$TMPDIR/$_label-reexchange.err"; then
    fail "$_label: a fresh exchange SUCCEEDED (expected failure)" \
      "$TMPDIR/$_label-reexchange.out"
  fi
  if [ -s "$TMPDIR/$_label-reexchange.token" ]; then
    fail "$_label: a token was minted (expected none)" \
      "$TMPDIR/$_label-reexchange.token"
  fi
}

# inspect_field POLICY_KEY CREDENTIAL_ID FIELD -> print one authoritative
# non-secret field (state|generation|verifier|salt) for a credential from the
# STOPPED encrypted store. FAILS LOUD on open/lookup/parse error.
inspect_field() {
  _key=$1
  _cid=$2
  _field=$3
  "$STORE_INSPECT" "$POLICY_DB" "$_key" "$_cid" \
    >"$TMPDIR/inspect.out" 2>"$TMPDIR/inspect.err" \
    || fail "store-inspect failed for $_cid under $_key" \
      "$TMPDIR/inspect.out" "$TMPDIR/inspect.err"
  "$PY" "$SC_E2E_PY" receipt-field --field "$_field" <"$TMPDIR/inspect.out" \
    || fail "store-inspect output missing $_field for $_cid" "$TMPDIR/inspect.out"
}

perms_of() {
  "$PY" - "$1" <<'PY'
import os
import sys
print("%03o" % (os.stat(sys.argv[1]).st_mode & 0o777))
PY
}

# ===========================================================================
# Boot 1 (KEY_OLD): shared lifecycle setup + issue A + exchange + allow.
# ===========================================================================
start_daemon "file:$KEY_OLD"
wait_ready
[ "$ready" -eq 1 ] || fail "daemon did not become ready on boot 1" "$LOG.err"

ADMIN1_TOKEN="$TMPDIR/admin1.token"
"$PY" "$SC_E2E_PY" login-skip-mfa --base-url "$URL" --username admin1 \
  >"$ADMIN1_TOKEN" 2>"$TMPDIR/admin1.err" \
  || fail "admin1 skip-MFA login failed" "$TMPDIR/admin1.err" "$LOG.err"
chmod 600 "$ADMIN1_TOKEN"

"$WYCTL" --daemon-url "$URL" policy role-grant \
  --subject admin2 --role wr.system_admin --scope __wr_default \
  --access-token-file "$ADMIN1_TOKEN" \
  --guard-timestamp 1 --guard-loc-class public --guard-risk 0 \
  >"$TMPDIR/seed-admin2.out" 2>"$TMPDIR/seed-admin2.err" \
  || fail "seeding admin2 system_admin failed" \
    "$TMPDIR/seed-admin2.err" "$LOG.err"

ADMIN2_TOKEN="$TMPDIR/admin2.token"
ADMIN2_SECRET="$TMPDIR/admin2.secret"
"$PY" "$SC_E2E_PY" totp-admin --base-url "$URL" --username admin2 \
  --admin-token-file "$ADMIN1_TOKEN" --secret-out "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN" 2>"$TMPDIR/admin2.err" \
  || fail "admin2 real-TOTP enrollment failed" "$TMPDIR/admin2.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN"
chmod 600 "$ADMIN2_SECRET"

# arm SUBCMD re-usable: self-arm the service-credential management authority for
# the CURRENT MFA bearer file (each boot's session is distinct).
arm_authority() {
  _tokfile=$1
  "$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$_tokfile" \
    --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
    >"$TMPDIR/arm.out" 2>"$TMPDIR/arm.err" \
    || fail "self-arm failed" "$TMPDIR/arm.out" "$TMPDIR/arm.err" "$LOG.err"
}

arm_authority "$ADMIN2_TOKEN"

"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/permissions/transition --token-file "$ADMIN2_TOKEN" \
  --query subject=admin2 --query perm=wr.tenant.manage \
  --query scope=__wr_default --query event=grant \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-manage.out" 2>"$TMPDIR/tenant-manage.err" \
  || fail "arming wr.tenant.manage failed" \
    "$TMPDIR/tenant-manage.out" "$LOG.err"

"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-a --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-create.out" 2>"$TMPDIR/tenant-create.err" \
  || fail "creating tenant-a failed" "$TMPDIR/tenant-create.out" "$LOG.err"

"$WYCTL" --daemon-url "$URL" service-principal create \
  --subject svc:svc-app --display-name "svc app" --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/principal.out" 2>"$TMPDIR/principal.err" \
  || fail "service-principal create failed" "$TMPDIR/principal.err" "$LOG.err"
grep -q "subject_id=svc:svc-app" "$TMPDIR/principal.out" \
  || fail "service-principal create did not report subject_id=svc:svc-app" \
    "$TMPDIR/principal.out"

# --- 1. issue credential A, exchange, grant, /decide ALLOW. -------------------
EXPIRES=$(( $(now_us) + 315360000000000 ))     # ~10 years out
"$WYCTL" --daemon-url "$URL" service-credential issue \
  --subject svc:svc-app --tenant tenant-a --destination credA \
  --expires-at-us "$EXPIRES" --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/issue.out" 2>"$TMPDIR/issue.err" \
  || fail "service-credential issue failed" "$TMPDIR/issue.err" "$LOG.err"
CRED_A=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id \
  <"$TMPDIR/issue.out") \
  || fail "issue receipt missing credential_id" "$TMPDIR/issue.out"
GEN_A=$("$PY" "$SC_E2E_PY" receipt-field --field generation \
  <"$TMPDIR/issue.out") \
  || fail "issue receipt missing generation" "$TMPDIR/issue.out"
[ -n "$CRED_A" ] && [ "$CRED_A" != "-" ] \
  || fail "issue receipt carried no credential_id" "$TMPDIR/issue.out"
test -s "$PUBROOT/credA" || fail "escrow doc not written to \$PUBROOT/credA"

SVC_TOKEN="$TMPDIR/svc.token"
exchange_ok credA "$SVC_TOKEN"

# Zero-role deny proves the token is live before the grant.
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/decide-deny.out" 2>"$TMPDIR/decide-deny.err" \
  || fail "zero-role /decide was not a live DENY" \
    "$TMPDIR/decide-deny.out" "$TMPDIR/decide-deny.err" "$LOG.err"

"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/roles/grant --token-file "$ADMIN2_TOKEN" \
  --query subject=svc:svc-app --query role=wr.viewer \
  --query scope=tenant-a --query "guard_timestamp=$(now_us)" \
  --query guard_loc_class=trusted --query guard_risk=10 \
  >"$TMPDIR/grant.out" 2>"$TMPDIR/grant.err" \
  || fail "granting wr.viewer@tenant-a failed" "$TMPDIR/grant.out" "$LOG.err"

"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/decide-allow.out" 2>"$TMPDIR/decide-allow.err" \
  || fail "pre-rotation /decide was not an ALLOW" \
    "$TMPDIR/decide-allow.out" "$TMPDIR/decide-allow.err" "$LOG.err"

# --- capture verifier_A under the OLD provider (daemon stopped). --------------
stop_daemon
STATE_A_OLD=$(inspect_field "$KEY_OLD" "$CRED_A" state)
GEN_A_OLD=$(inspect_field "$KEY_OLD" "$CRED_A" generation)
VERIFIER_A=$(inspect_field "$KEY_OLD" "$CRED_A" verifier)
SALT_A=$(inspect_field "$KEY_OLD" "$CRED_A" salt)
[ "$STATE_A_OLD" = "active" ] \
  || fail "credential A not active before rotation (state=$STATE_A_OLD)"
[ "$GEN_A_OLD" = "$GEN_A" ] \
  || fail "store generation $GEN_A_OLD != receipt generation $GEN_A"
case "$VERIFIER_A" in
  ????????????????????????????????????????????????????????????????) : ;;
  *) fail "verifier_A is not 64 hex chars: $VERIFIER_A" ;;
esac

# ===========================================================================
# 2. Rotate the KeyProvider ROOT: file:$KEY_OLD -> file:$KEY_NEW (offline).
# ===========================================================================
"$PY" - "$KEY_NEW" <<'PY'
import os
import sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY

"$WYCTL" key rotate --store "$POLICY_DB" \
  --from-keyprovider "file:$KEY_OLD" --to-keyprovider "file:$KEY_NEW" \
  >"$TMPDIR/rotate.out" 2>"$TMPDIR/rotate.err" \
  || fail "key rotate failed" "$TMPDIR/rotate.out" "$TMPDIR/rotate.err"
grep -q "status=rotated" "$TMPDIR/rotate.out" \
  || fail "key rotate did not report status=rotated" "$TMPDIR/rotate.out"

# ===========================================================================
# 3. Reopen under ONLY the new root; prove A survives byte-for-byte.
# ===========================================================================
# 3(c) fail-closed FIRST: the OLD root must NOT open the rotated store. Bounded
# readiness with a kill -0 liveness break so a fail-closed daemon that keeps
# running-but-not-ready cannot hang the test.
start_daemon "file:$KEY_OLD"
wait_ready
if [ "$ready" -eq 1 ]; then
  fail "daemon became ready under the OLD root after rotation (fail-closed violated)" \
    "$LOG.err"
fi
stop_daemon

# 3(a) A still exchanges and authorizes under the NEW root.
start_daemon "file:$KEY_NEW"
wait_ready
[ "$ready" -eq 1 ] || fail "daemon did not become ready under the NEW root" \
  "$LOG.err"

SVC_TOKEN_NEW="$TMPDIR/svc-new.token"
exchange_ok credA "$SVC_TOKEN_NEW"
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN_NEW" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/decide-allow-new.out" 2>"$TMPDIR/decide-allow-new.err" \
  || fail "post-root-rotation /decide (A) was not an ALLOW" \
    "$TMPDIR/decide-allow-new.out" "$TMPDIR/decide-allow-new.err" "$LOG.err"
stop_daemon

# 3(b) A's authoritative verifier/salt bytes are BYTE-IDENTICAL under the NEW
# provider. store-inspect opening the store under $KEY_NEW requires unsealing the
# rewrapped CVK envelope, so a clean open + identical bytes proves the envelope
# validated and the inner CVK was copied byte-for-byte.
STATE_A_NEW=$(inspect_field "$KEY_NEW" "$CRED_A" state)
GEN_A_NEW=$(inspect_field "$KEY_NEW" "$CRED_A" generation)
VERIFIER_A_NEW=$(inspect_field "$KEY_NEW" "$CRED_A" verifier)
SALT_A_NEW=$(inspect_field "$KEY_NEW" "$CRED_A" salt)
[ "$VERIFIER_A_NEW" = "$VERIFIER_A" ] \
  || fail "verifier bytes changed across root rotation: $VERIFIER_A -> $VERIFIER_A_NEW"
[ "$SALT_A_NEW" = "$SALT_A" ] \
  || fail "salt bytes changed across root rotation: $SALT_A -> $SALT_A_NEW"
[ "$STATE_A_NEW" = "active" ] \
  || fail "credential A not active after root rotation (state=$STATE_A_NEW)"
[ "$GEN_A_NEW" = "$GEN_A" ] \
  || fail "credential A generation changed across root rotation: $GEN_A -> $GEN_A_NEW"

# ===========================================================================
# 4. Rotate credential A -> B via the public management workflow.
# ===========================================================================
start_daemon "file:$KEY_NEW"
wait_ready
[ "$ready" -eq 1 ] || fail "daemon did not become ready for credential rotation" \
  "$LOG.err"

# Fresh MFA bearer + re-arm on THIS boot (in-memory session was lost on restart).
ADMIN2_TOKEN2="$TMPDIR/admin2b.token"
"$PY" "$SC_E2E_PY" login-totp --base-url "$URL" --username admin2 \
  --secret-file "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN2" 2>"$TMPDIR/admin2b.err" \
  || fail "admin2 TOTP re-login failed" "$TMPDIR/admin2b.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN2"
arm_authority "$ADMIN2_TOKEN2"

ROT_EXPIRES=$(( $(now_us) + 315360000000000 ))
"$WYCTL" --daemon-url "$URL" service-credential rotate \
  --credential-id "$CRED_A" --tenant tenant-a --destination credB \
  --expires-at-us "$ROT_EXPIRES" --access-token-file "$ADMIN2_TOKEN2" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/cred-rotate.out" 2>"$TMPDIR/cred-rotate.err" \
  || fail "service-credential rotate failed" \
    "$TMPDIR/cred-rotate.err" "$LOG.err"
CRED_B=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id \
  <"$TMPDIR/cred-rotate.out") \
  || fail "rotate receipt missing credential_id" "$TMPDIR/cred-rotate.out"
ROT_DELIVERED=$("$PY" "$SC_E2E_PY" receipt-field --field delivered \
  <"$TMPDIR/cred-rotate.out") \
  || fail "rotate receipt missing delivered" "$TMPDIR/cred-rotate.out"
[ "$ROT_DELIVERED" = "yes" ] \
  || fail "rotate receipt delivered=$ROT_DELIVERED (expected yes)" \
    "$TMPDIR/cred-rotate.out"
[ -n "$CRED_B" ] && [ "$CRED_B" != "-" ] && [ "$CRED_B" != "$CRED_A" ] \
  || fail "rotate did not produce a distinct successor credential_id" \
    "$TMPDIR/cred-rotate.out"
test -s "$PUBROOT/credB" || fail "successor escrow not written to \$PUBROOT/credB"
CREDB_PERMS=$(perms_of "$PUBROOT/credB")
[ "$CREDB_PERMS" = "600" ] \
  || fail "successor escrow credB perms=$CREDB_PERMS (expected 600)"

# A is revoked: a fresh exchange of A's escrow now FAILS.
exchange_must_fail credA credA-postrotate

# B exchanges -> token -> /decide ALLOW at tenant-a (B inherits svc:svc-app's
# tenant-a role; a rotate retires A but not the subject's grants).
TOKEN_B="$TMPDIR/credB.token"
exchange_ok credB "$TOKEN_B"
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_B" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/decide-allow-b.out" 2>"$TMPDIR/decide-allow-b.err" \
  || fail "successor credential B /decide was not an ALLOW" \
    "$TMPDIR/decide-allow-b.out" "$TMPDIR/decide-allow-b.err" "$LOG.err"
stop_daemon

# Authoritative store view: A revoked, B active.
STATE_A_REVOKED=$(inspect_field "$KEY_NEW" "$CRED_A" state)
STATE_B_ACTIVE=$(inspect_field "$KEY_NEW" "$CRED_B" state)
[ "$STATE_A_REVOKED" = "revoked" ] \
  || fail "credential A not revoked after credential rotation (state=$STATE_A_REVOKED)"
[ "$STATE_B_ACTIVE" = "active" ] \
  || fail "successor B not active after credential rotation (state=$STATE_B_ACTIVE)"

# ===========================================================================
# 5. Restart under $KEY_NEW; B re-exchanges (ALLOW), A remains denied.
# ===========================================================================
start_daemon "file:$KEY_NEW"
wait_ready
[ "$ready" -eq 1 ] || fail "daemon did not become ready on restart" "$LOG.err"

TOKEN_B2="$TMPDIR/credB-restart.token"
exchange_ok credB "$TOKEN_B2"
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_B2" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/decide-allow-b2.out" 2>"$TMPDIR/decide-allow-b2.err" \
  || fail "post-restart /decide (B) was not an ALLOW" \
    "$TMPDIR/decide-allow-b2.out" "$TMPDIR/decide-allow-b2.err" "$LOG.err"
exchange_must_fail credA credA-restart
stop_daemon

# ===========================================================================
# 6. Durable, sanitized success audit.
# ===========================================================================
# The audit sink is a DuckDB store. Read it offline (daemon stopped) with the
# build-guaranteed check-audit-events-query helper. The durable SUCCESS records this unit's operations
# leave in the audit db are:
#   - service.credential.issue     (allow)  -- credential A was issued;
#   - service.credential.rotate    (allow)  -- credential A was rotated to B;
#   - wr.service_credential.manage (allow)  -- the authorization decisions that
#     admitted the issue + rotate management calls.
# NOTE ON EXCHANGE: a cleanly ACKNOWLEDGED service-token exchange deliberately
# leaves NO row in service_exchange_receipt_projections -- that table is a
# crash-recovery projection populated only for a LOST-RESPONSE exchange by
# wyl_daemon_recover_service_exchange_on_startup (see test-daemon-startup-
# recovery.c). All four exchanges here completed and were acknowledged, so an
# empty projection table is CORRECT, not a missing record. The exchange's
# SANITIZATION is proven below (its live JWT never appears in the audit bytes);
# its SUCCESS is proven functionally by the ALLOW decisions on the exchanged
# tokens in steps 1/3/4/5.
audit_count() {
  _action=$1
  _decision=$2
  _label=$3
  _n=$("$AUDIT_QUERY" "$AUDIT_DB" "$_action" "$_decision" \
    2>"$TMPDIR/audit-query.err") \
    || fail "audit-query ($_label) failed" "$TMPDIR/audit-query.err"
  printf '%s' "$_n"
}

ISSUE_ROWS=$(audit_count "service.credential.issue" 1 "issue")
[ "$ISSUE_ROWS" -ge 1 ] 2>/dev/null \
  || fail "no durable allowed service.credential.issue audit row (got '$ISSUE_ROWS')" \
    "$TMPDIR/audit-query.err"

ROTATE_ROWS=$(audit_count "service.credential.rotate" 1 "rotate")
[ "$ROTATE_ROWS" -ge 1 ] 2>/dev/null \
  || fail "no durable allowed service.credential.rotate audit row (got '$ROTATE_ROWS')" \
    "$TMPDIR/audit-query.err"

MANAGE_ROWS=$(audit_count "wr.service_credential.manage" 1 "manage")
[ "$MANAGE_ROWS" -ge 2 ] 2>/dev/null \
  || fail "expected >=2 allowed manage-decision audit rows (issue+rotate), got '$MANAGE_ROWS'" \
    "$TMPDIR/audit-query.err"

# Sanitization: no per-run secret canary appears anywhere in the audit store
# bytes. Canaries: a live service JWT (the exchanged bearer) and the admin TOTP
# seed. Scan the DuckDB file plus any sidecar WAL.
AUDIT_FILES="$AUDIT_DB"
[ -f "$AUDIT_DB.wal" ] && AUDIT_FILES="$AUDIT_FILES $AUDIT_DB.wal"
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$TOKEN_B2" $AUDIT_FILES \
  >"$TMPDIR/scan-token.out" 2>"$TMPDIR/scan-token.err" \
  || fail "a service JWT leaked into the audit store" \
    "$TMPDIR/scan-token.err"
# shellcheck disable=SC2086
"$PY" "$SC_E2E_PY" scan-absent --needle-file "$ADMIN2_SECRET" $AUDIT_FILES \
  >"$TMPDIR/scan-totp.out" 2>"$TMPDIR/scan-totp.err" \
  || fail "the admin TOTP seed leaked into the audit store" \
    "$TMPDIR/scan-totp.err"

echo "check-service-credential-rotation-e2e: root+credential rotation e2e"
echo "  verifier_A (old root) : $VERIFIER_A"
echo "  verifier_A (new root) : $VERIFIER_A_NEW  (byte-identical)"
echo "  A pre-rotate  ALLOW   : $(cat "$TMPDIR/decide-allow.out")"
echo "  A new-root    ALLOW   : $(cat "$TMPDIR/decide-allow-new.out")"
echo "  B post-rotate ALLOW   : $(cat "$TMPDIR/decide-allow-b.out")"
echo "  B post-restart ALLOW  : $(cat "$TMPDIR/decide-allow-b2.out")"
echo "  A: $CRED_A revoked; B: $CRED_B active"
echo "  audit: issue=$ISSUE_ROWS rotate=$ROTATE_ROWS manage-allow=$MANAGE_ROWS durable, sanitized"
echo "check-service-credential-rotation-e2e: PASS"
exit 0
