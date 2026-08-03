#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Packaged, encrypted, end-to-end ZERO-SURVIVOR + NO-REFRESH runtime proof for
# the service-credential lifecycle (issue #382, Unit 2). Drives the PACKAGED
# production daemon and the wyctl client to prove that an authority mutation --
# credential revoke, service-principal disable, or tenant seal -- leaves ZERO
# usable or pending service tokens, through the real public handlers, against a
# real encrypted policy store, a real audit sink, and a real fact root; and that
# a service token has NO refresh/renewal path.
#
# Shared prefix (mirrors the Unit 1a lifecycle driver):
#   bootstrap -> admin1 skip-MFA -> seed admin2 -> admin2 REAL-TOTP mfa_assured
#   -> self-arm service-credential authority -> arm wr.tenant.manage
#   -> create tenant-a -> create svc:svc-app.
#
# Each property below FAILS LOUD; an EXPECTED non-200 (401 at resolve, 400
# tenant_sealed) is asserted as that EXACT status (assert-http-status), never
# swallowed. assert-decide is used only for genuine 200+decision outcomes (the
# pre-mutation "the token is live" proofs). Every property first establishes a
# live, working token AND a repeatable escrow (a pre-mutation control exchange),
# so the post-mutation failure is attributable to the mutation, not to single-
# use escrow:
#
#   1. CREDENTIAL REVOKE -> zero survivor: revoke the issued credential; a fresh
#      exchange from the same escrow FAILS (non-zero wyctl exit) and the already
#      minted token stops resolving (/decide -> 401).
#   2. PRINCIPAL DISABLE -> zero survivor: disable a second principal; a fresh
#      exchange FAILS and its already minted token stops resolving (/decide 401).
#   3. TENANT SEAL -> zero survivor: seal a tenant; /decide for that tenant is
#      400 tenant_sealed and a fresh exchange FAILS.
#   4. NO REFRESH: a live service token presented to the sole refresh route
#      (/auth/refresh) is rejected (401) -- there is no refresh CLI/route/flow
#      for a service token (exchange-only contract).

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
  echo "check-service-credential-zero-survivor-e2e: $1" >&2
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
# Encrypted, owner-only, MUTUALLY DISJOINT store/root layout.
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/policy.store"
KEY="$TMPDIR/policy.key"
AUDIT_DB="$TMPDIR/audit.duckdb"
FACT_ROOT="$TMPDIR/facts"
PUBROOT="$TMPDIR/publication"
OPROOT="$TMPDIR/operations"
LOG="$TMPDIR/daemon.log"

"$PY" - "$KEY" <<'PY'
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

"$WYRELOGD" --production --profile system --template-dir "$TEMPLATE_DIR" \
  --policy-db "$POLICY_DB" --policy-keyprovider "file:$KEY" \
  --audit-db "$AUDIT_DB" --fact-root "$FACT_ROOT" \
  --credential-publication-root "$PUBROOT" --operation-root "$OPROOT" \
  --bootstrap-admin-subject admin1 --bootstrap-admin-allow-skip-mfa \
  --listen-port "$PORT" >"$LOG.out" 2>"$LOG.err" &
PID=$!

# Readiness: poll `wyctl status`==ok, with a kill -0 liveness break so a daemon
# that dies during boot fails fast instead of looping to timeout.
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
    fail "daemon exited during bootstrap" "$LOG.err"
  fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || fail "daemon did not become ready" "$LOG.err"

# --- admin1 bootstrap skip-MFA bearer. ---------------------------------------
ADMIN1_TOKEN="$TMPDIR/admin1.token"
"$PY" "$SC_E2E_PY" login-skip-mfa --base-url "$URL" --username admin1 \
  >"$ADMIN1_TOKEN" 2>"$TMPDIR/admin1.err" \
  || fail "admin1 skip-MFA login failed" "$TMPDIR/admin1.err" "$LOG.err"
chmod 600 "$ADMIN1_TOKEN"

# --- seed admin2 as wr.system_admin so it can self-enroll + self-arm. --------
"$WYCTL" --daemon-url "$URL" policy role-grant \
  --subject admin2 --role wr.system_admin --scope __wr_default \
  --access-token-file "$ADMIN1_TOKEN" \
  --guard-timestamp 1 --guard-loc-class public --guard-risk 0 \
  >"$TMPDIR/seed-admin2.out" 2>"$TMPDIR/seed-admin2.err" \
  || fail "seeding admin2 system_admin failed" \
    "$TMPDIR/seed-admin2.err" "$LOG.err"

# --- admin2 REAL-TOTP bearer (mfa_assured). ----------------------------------
ADMIN2_TOKEN="$TMPDIR/admin2.token"
ADMIN2_SECRET="$TMPDIR/admin2.secret"
"$PY" "$SC_E2E_PY" totp-admin --base-url "$URL" --username admin2 \
  --admin-token-file "$ADMIN1_TOKEN" --secret-out "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN" 2>"$TMPDIR/admin2.err" \
  || fail "admin2 real-TOTP enrollment failed" "$TMPDIR/admin2.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN"
chmod 600 "$ADMIN2_SECRET"

# --- self-arm the service-credential management authority. -------------------
"$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
  >"$TMPDIR/arm.out" 2>"$TMPDIR/arm.err" \
  || fail "self-arm failed" "$TMPDIR/arm.out" "$TMPDIR/arm.err" "$LOG.err"

# --- arm wr.tenant.manage for admin2 (create + seal both need it). -----------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/permissions/transition --token-file "$ADMIN2_TOKEN" \
  --query subject=admin2 --query perm=wr.tenant.manage \
  --query scope=__wr_default --query event=grant \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-manage.out" 2>"$TMPDIR/tenant-manage.err" \
  || fail "arming wr.tenant.manage failed" \
    "$TMPDIR/tenant-manage.out" "$LOG.err"

# --- create tenant-a. --------------------------------------------------------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-a --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-create.out" 2>"$TMPDIR/tenant-create.err" \
  || fail "creating tenant-a failed" "$TMPDIR/tenant-create.out" "$LOG.err"

# --- create the primary service principal svc:svc-app. -----------------------
"$WYCTL" --daemon-url "$URL" service-principal create \
  --subject svc:svc-app --display-name "svc app" --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/principal.out" 2>"$TMPDIR/principal.err" \
  || fail "service-principal create failed" "$TMPDIR/principal.err" "$LOG.err"
grep -q "subject_id=svc:svc-app" "$TMPDIR/principal.out" \
  || fail "service-principal create did not report subject_id=svc:svc-app" \
    "$TMPDIR/principal.out"

# ---------------------------------------------------------------------------
# Shared helpers (run as statements, never in $(...), so fail() exits cleanly).
# ---------------------------------------------------------------------------
# issue_credential SUBJECT TENANT DESTINATION LABEL -> escrow $PUBROOT/DEST,
#   receipt at $TMPDIR/LABEL-issue.out. CRED_ID is lifted separately.
issue_credential() {
  _subj=$1
  _ten=$2
  _dest=$3
  _label=$4
  _exp=$(( $(now_us) + 315360000000000 ))     # ~10 years out
  "$WYCTL" --daemon-url "$URL" service-credential issue \
    --subject "$_subj" --tenant "$_ten" --destination "$_dest" \
    --expires-at-us "$_exp" --access-token-file "$ADMIN2_TOKEN" \
    --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
    >"$TMPDIR/$_label-issue.out" 2>"$TMPDIR/$_label-issue.err" \
    || fail "$_label issue failed" "$TMPDIR/$_label-issue.err" "$LOG.err"
  test -s "$PUBROOT/$_dest" \
    || fail "$_label escrow doc not written to \$PUBROOT/$_dest"
}

# exchange_ok DESTINATION OUT_TOKEN_PATH -> exchange the escrow to a live token;
#   FAILS LOUD if the exchange does not succeed. Used for the live token and for
#   the pre-mutation control (proving the escrow is repeatable while active).
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

# exchange_must_fail DESTINATION LABEL -> assert a fresh exchange FAILS (zero
#   survivor: no new token may be minted from a mutated credential's escrow).
exchange_must_fail() {
  _dest=$1
  _label=$2
  rm -f "$TMPDIR/$_label-reexchange.token"
  if "$WYCTL" --daemon-url "$URL" auth service-token \
      --credential-file "$PUBROOT/$_dest" \
      --token-output "$TMPDIR/$_label-reexchange.token" \
      >"$TMPDIR/$_label-reexchange.out" 2>"$TMPDIR/$_label-reexchange.err"; then
    fail "$_label: a fresh exchange SUCCEEDED after mutation (zero survivor violated)" \
      "$TMPDIR/$_label-reexchange.out"
  fi
  if [ -s "$TMPDIR/$_label-reexchange.token" ]; then
    fail "$_label: a token was minted after mutation (zero survivor violated)" \
      "$TMPDIR/$_label-reexchange.token"
  fi
}

# ===========================================================================
# Property 1: CREDENTIAL REVOKE -> zero survivor.
# ===========================================================================
issue_credential svc:svc-app tenant-a credA credA
CRED_A=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id \
  <"$TMPDIR/credA-issue.out") \
  || fail "credA issue receipt missing credential_id" "$TMPDIR/credA-issue.out"
[ -n "$CRED_A" ] && [ "$CRED_A" != "-" ] \
  || fail "credA issue receipt carried no credential_id" "$TMPDIR/credA-issue.out"

TOKEN_A="$TMPDIR/credA.token"
exchange_ok credA "$TOKEN_A"

# The token is live (zero-role deny is a genuine 200 policy deny).
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_A" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/credA-live.out" 2>"$TMPDIR/credA-live.err" \
  || fail "credA token was not a live pre-revoke DENY" \
    "$TMPDIR/credA-live.out" "$TMPDIR/credA-live.err" "$LOG.err"

# Control: while active, the SAME escrow exchanges again (escrow is repeatable,
# so a post-revoke failure is attributable to the revoke, not single-use).
exchange_ok credA "$TMPDIR/credA-control.token"

# Revoke the credential.
"$WYCTL" --daemon-url "$URL" service-credential revoke \
  --credential-id "$CRED_A" --tenant tenant-a \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/credA-revoke.out" 2>"$TMPDIR/credA-revoke.err" \
  || fail "credA revoke failed" "$TMPDIR/credA-revoke.err" "$LOG.err"
grep -q "state=revoked" "$TMPDIR/credA-revoke.out" \
  || fail "credA revoke did not report state=revoked" "$TMPDIR/credA-revoke.out"

# (a) A fresh exchange from the same escrow FAILS.
exchange_must_fail credA credA

# (b) The already-minted token stops resolving: /decide -> 401.
"$PY" "$SC_E2E_PY" assert-http-status --base-url "$URL" \
  --path /decide --token-file "$TOKEN_A" \
  --query user=svc:svc-app --query perm=wr.svc.read_decision \
  --query tenant=tenant-a --query session_token=tenant-a \
  --expect-status 401 \
  >"$TMPDIR/credA-401.out" 2>"$TMPDIR/credA-401.err" \
  || fail "revoked credential's token still resolved (expected 401)" \
    "$TMPDIR/credA-401.out" "$TMPDIR/credA-401.err" "$LOG.err"

# ===========================================================================
# Property 2: PRINCIPAL DISABLE -> zero survivor.
# ===========================================================================
"$WYCTL" --daemon-url "$URL" service-principal create \
  --subject svc:svc-two --display-name "svc two" --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/principal2.out" 2>"$TMPDIR/principal2.err" \
  || fail "service-principal svc:svc-two create failed" \
    "$TMPDIR/principal2.err" "$LOG.err"
grep -q "subject_id=svc:svc-two" "$TMPDIR/principal2.out" \
  || fail "svc:svc-two create did not report subject_id" "$TMPDIR/principal2.out"

issue_credential svc:svc-two tenant-a credB credB
TOKEN_B="$TMPDIR/credB.token"
exchange_ok credB "$TOKEN_B"

# The token is live.
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_B" \
  --user svc:svc-two --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/credB-live.out" 2>"$TMPDIR/credB-live.err" \
  || fail "credB token was not a live pre-disable DENY" \
    "$TMPDIR/credB-live.out" "$TMPDIR/credB-live.err" "$LOG.err"

# Control: repeatable while the principal is enabled.
exchange_ok credB "$TMPDIR/credB-control.token"

# Disable the principal.
"$WYCTL" --daemon-url "$URL" service-principal disable \
  --subject svc:svc-two --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/principal2-disable.out" 2>"$TMPDIR/principal2-disable.err" \
  || fail "svc:svc-two disable failed" \
    "$TMPDIR/principal2-disable.err" "$LOG.err"
grep -q "disabled=yes" "$TMPDIR/principal2-disable.out" \
  || fail "svc:svc-two disable did not report disabled=yes" \
    "$TMPDIR/principal2-disable.out"

# (a) Fresh exchange FAILS.
exchange_must_fail credB credB

# (b) Existing token stops resolving: /decide -> 401.
"$PY" "$SC_E2E_PY" assert-http-status --base-url "$URL" \
  --path /decide --token-file "$TOKEN_B" \
  --query user=svc:svc-two --query perm=wr.svc.read_decision \
  --query tenant=tenant-a --query session_token=tenant-a \
  --expect-status 401 \
  >"$TMPDIR/credB-401.out" 2>"$TMPDIR/credB-401.err" \
  || fail "disabled principal's token still resolved (expected 401)" \
    "$TMPDIR/credB-401.out" "$TMPDIR/credB-401.err" "$LOG.err"

# ===========================================================================
# Property 3: TENANT SEAL -> zero survivor.
# ===========================================================================
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-c --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-c-create.out" 2>"$TMPDIR/tenant-c-create.err" \
  || fail "creating tenant-c failed" "$TMPDIR/tenant-c-create.out" "$LOG.err"

issue_credential svc:svc-app tenant-c credC credC
TOKEN_C="$TMPDIR/credC.token"
exchange_ok credC "$TOKEN_C"

# The token is live at tenant-c (zero-role deny is a genuine 200 policy deny).
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_C" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-c \
  --expect deny >"$TMPDIR/credC-live.out" 2>"$TMPDIR/credC-live.err" \
  || fail "credC token was not a live pre-seal DENY at tenant-c" \
    "$TMPDIR/credC-live.out" "$TMPDIR/credC-live.err" "$LOG.err"

# Control: repeatable while tenant-c is active.
exchange_ok credC "$TMPDIR/credC-control.token"

# Seal tenant-c. The seal route reads UNDERSCORE guard keys and a strict JSON
# retirement body {version:"1", request_id:<canonical>}.
SEAL_RID=$("$PY" "$SC_E2E_PY" mint-request-id) \
  || fail "unable to mint seal request id"
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/seal --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-c --query "guard_timestamp=$(now_us)" \
  --query guard_loc_class=trusted --query guard_risk=10 \
  --json-field version=1 --json-field "request_id=$SEAL_RID" \
  >"$TMPDIR/tenant-c-seal.out" 2>"$TMPDIR/tenant-c-seal.err" \
  || fail "sealing tenant-c failed" \
    "$TMPDIR/tenant-c-seal.out" "$TMPDIR/tenant-c-seal.err" "$LOG.err"

# (a) /decide for the sealed tenant is 400 tenant_sealed.
"$PY" "$SC_E2E_PY" assert-http-status --base-url "$URL" \
  --path /decide --token-file "$TOKEN_C" \
  --query user=svc:svc-app --query perm=wr.svc.read_decision \
  --query tenant=tenant-c --query session_token=tenant-c \
  --expect-status 400 --expect-error tenant_sealed \
  >"$TMPDIR/credC-sealed.out" 2>"$TMPDIR/credC-sealed.err" \
  || fail "sealed tenant still authorized (expected 400 tenant_sealed)" \
    "$TMPDIR/credC-sealed.out" "$TMPDIR/credC-sealed.err" "$LOG.err"

# (b) A fresh exchange from the sealed tenant's escrow FAILS.
exchange_must_fail credC credC

# ===========================================================================
# Property 4: NO REFRESH -- a service token cannot be refreshed/renewed.
# ===========================================================================
issue_credential svc:svc-app tenant-a credR credR
TOKEN_R="$TMPDIR/credR.token"
exchange_ok credR "$TOKEN_R"

# The token is live right now.
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$TOKEN_R" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/credR-live.out" 2>"$TMPDIR/credR-live.err" \
  || fail "credR token was not live before the no-refresh check" \
    "$TMPDIR/credR-live.out" "$TMPDIR/credR-live.err" "$LOG.err"

# The sole refresh route rejects the live service token (no refresh flow).
"$PY" "$SC_E2E_PY" assert-no-refresh --base-url "$URL" --token-file "$TOKEN_R" \
  >"$TMPDIR/credR-norefresh.out" 2>"$TMPDIR/credR-norefresh.err" \
  || fail "a service token WAS refreshable (no-refresh contract violated)" \
    "$TMPDIR/credR-norefresh.out" "$TMPDIR/credR-norefresh.err" "$LOG.err"

echo "check-service-credential-zero-survivor-e2e: zero-survivor + no-refresh"
echo "  1 revoke   401 : $(cat "$TMPDIR/credA-401.out")"
echo "  2 disable  401 : $(cat "$TMPDIR/credB-401.out")"
echo "  3 seal     400 : $(cat "$TMPDIR/credC-sealed.out")"
echo "  4 no-refresh    : $(cat "$TMPDIR/credR-norefresh.out")"
echo "check-service-credential-zero-survivor-e2e: PASS"
exit 0
