#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Packaged, encrypted, end-to-end runtime proof for the service-credential
# lifecycle authorization MATRIX (issue #382, Units 1a + 1b). Drives the
# PACKAGED production daemon and the wyctl client through the load-bearing
# deny->allow transition AND the live revocation / cross-tenant isolation edges,
# exercising the merged #729/#740/#744/#762 authorization seams against a real
# encrypted policy store, a real audit sink, and a real fact root.
#
# Flow:
#   1. bootstrap the production encrypted daemon;
#   2. mint a bootstrap skip-MFA admin (admin1) bearer;
#   3. seed admin2 as wr.system_admin so it can self-enroll;
#   4. enroll admin2 with a REAL TOTP authenticator and mint an mfa_assured
#      bearer (#740 self-arm rejects skip-MFA bearers with 403);
#   5. admin2 self-arms the service-credential management authority;
#   6. arm wr.tenant.manage for admin2;
#   7. create tenant-a (the creator receives wr.system_admin@tenant-a plus a
#      active tenant scope state);
#   8. create the service principal svc:svc-app (a __wr_default identity);
#   9. issue credential A, escrowed to $PUBROOT/credA;
#  10. exchange the escrow doc for a live service JWT;
#  11. /decide ZERO-ROLE DENY for the fresh service token (proves the token is
#      live BEFORE the grant -- a non-200/expired token is a hard failure, never
#      a silent deny);
#  12. grant wr.viewer@tenant-a to svc:svc-app (carries the data-plane perm
#      wr.svc.read_decision; admin2 holds grant authority at tenant-a via #744);
#  13. /decide ALLOW -- the deny->allow proof.
#
# Unit 1b completes the live authorization matrix with the SAME unchanged
# service token:
#  14. create tenant-b (a second created tenant, seeded like tenant-a);
#  15. TENANT ISOLATION: with the tenant-a-scoped token, re-confirm tenant-a
#      ALLOW, then prove tenant-b is refused. The service token is bound to its
#      credential's tenant (JWT claim tenant=tenant-a), so a tenant-b decide is
#      rejected at the daemon's tenant gate with HTTP 403 tenant_denied -- a
#      STRONGER isolation than a policy-level deny: the tenant-a token cannot
#      even be presented for tenant-b. (assert-decide is reserved for genuine
#      200+decision outcomes; the 403 gate is asserted with assert-http-status.)
#  16. LIVE ROLE REVOKE: revoke wr.viewer@tenant-a from svc:svc-app;
#  17. /decide DENY at tenant-a with the SAME unchanged token -- the allow->deny
#      transition with no token change. Because revoke removes has_permission,
#      the #762 decide-time arming of approved data-plane perms does not fire.
#
# NOTE ON SCOPES: the service principal svc:svc-app is a __wr_default identity
# (service principals always live in __wr_default), yet the role grant and both
# /decide calls are tenant-a-scoped. This is correct, not inconsistent: it
# relies on tenant-a's active scope state at create time so a tenant-a-scoped
# decision can be authorized.

set -eu

WYRELOGD=$1
WYCTL=$2
# STORE_INSPECT (the offline encrypted-store reader) is threaded in for parity
# with later lifecycle units; Unit 1a does not read raw store rows.
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
  echo "check-service-credential-lifecycle-e2e: $1" >&2
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

# --- 2. admin1 bootstrap skip-MFA bearer (human, NOT mfa_assured). -----------
ADMIN1_TOKEN="$TMPDIR/admin1.token"
"$PY" "$SC_E2E_PY" login-skip-mfa --base-url "$URL" --username admin1 \
  >"$ADMIN1_TOKEN" 2>"$TMPDIR/admin1.err" \
  || fail "admin1 skip-MFA login failed" "$TMPDIR/admin1.err" "$LOG.err"
chmod 600 "$ADMIN1_TOKEN"

# --- 3. seed admin2 as wr.system_admin so it can self-enroll + self-arm. ------
"$WYCTL" --daemon-url "$URL" policy role-grant \
  --subject admin2 --role wr.system_admin --scope __wr_default \
  --access-token-file "$ADMIN1_TOKEN" \
  --guard-timestamp 1 --guard-loc-class public --guard-risk 0 \
  >"$TMPDIR/seed-admin2.out" 2>"$TMPDIR/seed-admin2.err" \
  || fail "seeding admin2 system_admin failed" \
    "$TMPDIR/seed-admin2.err" "$LOG.err"

# --- 4. admin2 REAL-TOTP bearer (mfa_assured). --------------------------------
ADMIN2_TOKEN="$TMPDIR/admin2.token"
ADMIN2_SECRET="$TMPDIR/admin2.secret"
"$PY" "$SC_E2E_PY" totp-admin --base-url "$URL" --username admin2 \
  --admin-token-file "$ADMIN1_TOKEN" --secret-out "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN" 2>"$TMPDIR/admin2.err" \
  || fail "admin2 real-TOTP enrollment failed" "$TMPDIR/admin2.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN"
chmod 600 "$ADMIN2_SECRET"

# --- 5. self-arm the service-credential management authority. -----------------
# The daemon's HTTP query parser reads UNDERSCORE guard keys; the arm helper
# owns that spelling internally.
"$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
  >"$TMPDIR/arm.out" 2>"$TMPDIR/arm.err" \
  || fail "self-arm failed" "$TMPDIR/arm.out" "$TMPDIR/arm.err" "$LOG.err"

# --- 6. arm wr.tenant.manage for admin2. --------------------------------------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/permissions/transition --token-file "$ADMIN2_TOKEN" \
  --query subject=admin2 --query perm=wr.tenant.manage \
  --query scope=__wr_default --query event=grant \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-manage.out" 2>"$TMPDIR/tenant-manage.err" \
  || fail "arming wr.tenant.manage failed" \
    "$TMPDIR/tenant-manage.out" "$LOG.err"

# --- 7. create tenant-a (the creator receives tenant-scoped authority). -------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-a --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-create.out" 2>"$TMPDIR/tenant-create.err" \
  || fail "creating tenant-a failed" "$TMPDIR/tenant-create.out" "$LOG.err"

# --- 8. create the service principal (lives in __wr_default; svc: prefix). -----
"$WYCTL" --daemon-url "$URL" service-principal create \
  --subject svc:svc-app --display-name "svc app" --tenant __wr_default \
  --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/principal.out" 2>"$TMPDIR/principal.err" \
  || fail "service-principal create failed" "$TMPDIR/principal.err" "$LOG.err"
grep -q "subject_id=svc:svc-app" "$TMPDIR/principal.out" \
  || fail "service-principal create did not report subject_id=svc:svc-app" \
    "$TMPDIR/principal.out"

# --- 9. issue credential A (escrowed to $PUBROOT/credA). ----------------------
EXPIRES=$(( $(now_us) + 315360000000000 ))     # ~10 years out
"$WYCTL" --daemon-url "$URL" service-credential issue \
  --subject svc:svc-app --tenant tenant-a --destination credA \
  --expires-at-us "$EXPIRES" --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/issue.out" 2>"$TMPDIR/issue.err" \
  || fail "service-credential issue failed" "$TMPDIR/issue.err" "$LOG.err"

ISSUE_STATE=$("$PY" "$SC_E2E_PY" receipt-field --field state \
  <"$TMPDIR/issue.out") \
  || fail "issue receipt missing state field" "$TMPDIR/issue.out"
ISSUE_DELIVERED=$("$PY" "$SC_E2E_PY" receipt-field --field delivered \
  <"$TMPDIR/issue.out") \
  || fail "issue receipt missing delivered field" "$TMPDIR/issue.out"
CRED_ID=$("$PY" "$SC_E2E_PY" receipt-field --field credential_id \
  <"$TMPDIR/issue.out") \
  || fail "issue receipt missing credential_id field" "$TMPDIR/issue.out"
[ "$ISSUE_STATE" = "terminal" ] \
  || fail "issue receipt state=$ISSUE_STATE (expected terminal)" \
    "$TMPDIR/issue.out"
[ "$ISSUE_DELIVERED" = "yes" ] \
  || fail "issue receipt delivered=$ISSUE_DELIVERED (expected yes)" \
    "$TMPDIR/issue.out"
[ -n "$CRED_ID" ] && [ "$CRED_ID" != "-" ] \
  || fail "issue receipt did not carry a credential_id" "$TMPDIR/issue.out"
test -s "$PUBROOT/credA" || fail "escrow doc not written to \$PUBROOT/credA"

# --- 10. exchange the escrow doc for a live service JWT. ----------------------
SVC_TOKEN="$TMPDIR/svc.token"
rm -f "$SVC_TOKEN"
"$WYCTL" --daemon-url "$URL" auth service-token \
  --credential-file "$PUBROOT/credA" --token-output "$SVC_TOKEN" \
  >"$TMPDIR/exchange.out" 2>"$TMPDIR/exchange.err" \
  || fail "service-token exchange failed" "$TMPDIR/exchange.err" "$LOG.err"
test -s "$SVC_TOKEN" || fail "service token not written"
chmod 600 "$SVC_TOKEN"

# --- 11. /decide ZERO-ROLE DENY (proves the token is live pre-grant). --------
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/decide-deny.out" 2>"$TMPDIR/decide-deny.err" \
  || fail "zero-role /decide was not a live DENY" \
    "$TMPDIR/decide-deny.out" "$TMPDIR/decide-deny.err" "$LOG.err"

# --- 12. grant wr.viewer@tenant-a to svc:svc-app. ----------------------------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/roles/grant --token-file "$ADMIN2_TOKEN" \
  --query subject=svc:svc-app --query role=wr.viewer \
  --query scope=tenant-a --query "guard_timestamp=$(now_us)" \
  --query guard_loc_class=trusted --query guard_risk=10 \
  >"$TMPDIR/grant.out" 2>"$TMPDIR/grant.err" \
  || fail "granting wr.viewer@tenant-a failed" "$TMPDIR/grant.out" "$LOG.err"

# --- 13. /decide ALLOW -- the deny->allow proof. -----------------------------
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/decide-allow.out" 2>"$TMPDIR/decide-allow.err" \
  || fail "post-grant /decide was not an ALLOW (deny->allow transition broke)" \
    "$TMPDIR/decide-allow.out" "$TMPDIR/decide-allow.err" "$LOG.err"

# --- 14. create tenant-b (a second created tenant, seeded like tenant-a). -----
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /tenants/create --token-file "$ADMIN2_TOKEN" \
  --query name=tenant-b --query tenant=__wr_default \
  --query "guard_timestamp=$(now_us)" --query guard_loc_class=trusted \
  --query guard_risk=10 \
  >"$TMPDIR/tenant-b-create.out" 2>"$TMPDIR/tenant-b-create.err" \
  || fail "creating tenant-b failed" "$TMPDIR/tenant-b-create.out" "$LOG.err"

# --- 15. TENANT ISOLATION with the SAME tenant-a-scoped token. ----------------
# Re-confirm tenant-a still ALLOWs (the grant is live), then prove the token is
# refused for tenant-b. A tenant-a-bound service token cannot be presented for
# tenant-b: the daemon's tenant gate rejects it with 403 tenant_denied BEFORE
# any policy evaluation -- stronger isolation than a policy deny.
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect allow >"$TMPDIR/iso-a.out" 2>"$TMPDIR/iso-a.err" \
  || fail "tenant-a ALLOW regressed before isolation check" \
    "$TMPDIR/iso-a.out" "$TMPDIR/iso-a.err" "$LOG.err"

"$PY" "$SC_E2E_PY" assert-http-status --base-url "$URL" \
  --path /decide --token-file "$SVC_TOKEN" \
  --query user=svc:svc-app --query perm=wr.svc.read_decision \
  --query tenant=tenant-b --query session_token=tenant-b \
  --expect-status 403 --expect-error tenant_denied \
  >"$TMPDIR/iso-b.out" 2>"$TMPDIR/iso-b.err" \
  || fail "tenant-b was NOT isolated (expected 403 tenant_denied)" \
    "$TMPDIR/iso-b.out" "$TMPDIR/iso-b.err" "$LOG.err"

# --- 16. LIVE ROLE REVOKE: revoke wr.viewer@tenant-a from svc:svc-app. --------
"$PY" "$SC_E2E_PY" http-post --base-url "$URL" \
  --path /policy/roles/revoke --token-file "$ADMIN2_TOKEN" \
  --query subject=svc:svc-app --query role=wr.viewer \
  --query scope=tenant-a --query "guard_timestamp=$(now_us)" \
  --query guard_loc_class=trusted --query guard_risk=10 \
  >"$TMPDIR/revoke.out" 2>"$TMPDIR/revoke.err" \
  || fail "revoking wr.viewer@tenant-a failed" "$TMPDIR/revoke.out" "$LOG.err"

# --- 17. /decide DENY with the SAME unchanged token -- the allow->deny proof. -
"$PY" "$SC_E2E_PY" assert-decide --base-url "$URL" --token-file "$SVC_TOKEN" \
  --user svc:svc-app --perm wr.svc.read_decision --tenant tenant-a \
  --expect deny >"$TMPDIR/decide-revoked.out" 2>"$TMPDIR/decide-revoked.err" \
  || fail "post-revoke /decide was not a DENY (allow->deny transition broke)" \
    "$TMPDIR/decide-revoked.out" "$TMPDIR/decide-revoked.err" "$LOG.err"

echo "check-service-credential-lifecycle-e2e: authorization matrix"
echo "  DENY (zero-role) : $(cat "$TMPDIR/decide-deny.out")"
echo "  ALLOW (granted)  : $(cat "$TMPDIR/decide-allow.out")"
echo "  ISOLATION (t-b)  : $(cat "$TMPDIR/iso-b.out")"
echo "  DENY (revoked)   : $(cat "$TMPDIR/decide-revoked.out")"
echo "check-service-credential-lifecycle-e2e: PASS"
exit 0
