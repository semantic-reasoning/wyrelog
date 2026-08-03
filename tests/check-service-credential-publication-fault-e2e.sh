#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Packaged, encrypted, end-to-end LOCAL-PUBLICATION-FAULT + ORPHAN-RECOVERY
# runtime proof for the service-credential handoff (issue #382, Unit 4; the
# #380 orphan-window contract). Drives the PACKAGED daemon and the wyctl client
# to prove that when a service-credential SERVER-COMMIT succeeds but the LOCAL
# publication fails post-commit, there is:
#   * NO secret on disk (no escrow doc, no stage temp on $PUBROOT), and
#   * a restart-surviving, retryable ORPHAN credential id keyed by the request
#     id, recoverable and revocable through the PUBLIC workflow.
#
# The post-commit publication fault is forced by the compile-gated, single-shot
# #754 seam, armed with the daemon flag --fault-inject-sc-publication-once. The
# seam fails exactly once BEFORE any publication I/O (before plan / escrow unseal
# / stage_exact), leaving a durable SERVER_COMMITTED orphan with no secret
# decoded, then self-disarms.
#
# WHY --production HERE: the fault-injection flag and its whole seam only exist
# in a build configured with -Denable_fault_injection=enabled (this test is
# gated on that option); a release build omits the flag and the seam entirely,
# so a release daemon can never be armed. Because the flag exists ONLY in a
# fault-injection build, it is deliberately allowed alongside --production, and
# the daemon is run WITH --production so the encrypted policy store and its
# credential vault key (which the daemon wires only under --production) are
# available for a real service-credential SERVER-COMMIT. This is a real,
# encrypted, out-of-process --production daemon that happens to have the one-shot
# publication fault armed.
#
# Flow:
#   0. launch the daemon ARMED (--production --fault-inject-sc-publication-once);
#   1. bootstrap -> admin1 skip-MFA -> seed admin2 -> admin2 REAL-TOTP mfa_assured
#      -> self-arm service-credential authority -> arm wr.tenant.manage
#      -> create tenant-a -> create svc:svc-app (the shared lifecycle prefix);
#   2. issue credF keyed by request id R -> FAILS (the seam fired post-commit):
#      non-zero wyctl exit;
#   3. NO secret on disk: $PUBROOT is EMPTY (no credF escrow doc, no stage temp);
#   4. the orphan is present + keyed by R: recover --request-id R reports
#      state=server_committed with a successor_credential_id and a
#      server_committed recovery classification; recover is read-only and does
#      NOT deliver the secret ($PUBROOT stays empty);
#   5. RESTART the daemon WITHOUT the fault flag (still WITH --production);
#   6. the orphan SURVIVED restart: recover --request-id R still reports
#      state=server_committed with the SAME successor id ($PUBROOT still empty);
#   7. REVOCABLE via the public workflow: revoke the orphan's successor
#      credential id -> state=revoked; $PUBROOT still empty (no secret ever
#      landed);
#   8. NEGATIVE CONTROL: a SECOND issue with a FRESH request id on the restarted
#      (unarmed) daemon COMPLETES normally (delivered, escrow written) -- proving
#      the single-shot seam did not wedge the daemon.

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
  echo "check-service-credential-publication-fault-e2e: $1" >&2
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

# Assert $PUBROOT holds ZERO regular files: no escrow doc, no stage temp. Any
# file at all after a pre-publication fault is a real secret-on-disk leak.
assert_pubroot_empty() {
  _where=$1
  _leftover=$(find "$PUBROOT" -mindepth 1 -type f 2>/dev/null || true)
  if [ -n "$_leftover" ]; then
    echo "--- \$PUBROOT contents ($_where) ---" >&2
    echo "$_leftover" >&2
    fail "secret/stage-temp on \$PUBROOT ($_where): expected an empty publication root" \
      "$LOG.err"
  fi
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

# launch_daemon [extra args...] -> start wyrelogd WITH --production (see header:
# the encrypted store / CVK the SC issue needs is only wired under --production),
# poll wyctl status==ok, break fast on daemon death. Reuses $PORT across the
# restart (the previous daemon is killed and waited by stop_daemon first).
launch_daemon() {
  "$WYRELOGD" --production --profile system --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" --policy-keyprovider "file:$KEY" \
    --audit-db "$AUDIT_DB" --fact-root "$FACT_ROOT" \
    --credential-publication-root "$PUBROOT" --operation-root "$OPROOT" \
    --bootstrap-admin-subject admin1 --bootstrap-admin-allow-skip-mfa \
    --listen-port "$PORT" "$@" >"$LOG.out" 2>"$LOG.err" &
  PID=$!
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
}

stop_daemon() {
  if [ -n "$PID" ]; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    PID=
  fi
}

# --- 0. launch the daemon ARMED with the single-shot publication fault. -------
launch_daemon --fault-inject-sc-publication-once
grep -q "publication fault injection ARMED" "$LOG.err" \
  || fail "armed daemon did not emit the loud fault-injection warning" "$LOG.err"

# --- 1. shared lifecycle prefix (mirrors the Unit 1a/2 drivers). --------------
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

"$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
  >"$TMPDIR/arm.out" 2>"$TMPDIR/arm.err" \
  || fail "self-arm failed" "$TMPDIR/arm.out" "$TMPDIR/arm.err" "$LOG.err"

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

# --- 2. issue credF keyed by request id R -> MUST FAIL (seam fired). ----------
REQ_ID=$("$PY" "$SC_E2E_PY" mint-request-id) \
  || fail "unable to mint request id"
EXPIRES=$(( $(now_us) + 315360000000000 ))     # ~10 years out
if "$WYCTL" --daemon-url "$URL" service-credential issue \
    --request-id "$REQ_ID" --subject svc:svc-app --tenant tenant-a \
    --destination credF --expires-at-us "$EXPIRES" \
    --access-token-file "$ADMIN2_TOKEN" \
    --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
    >"$TMPDIR/issue.out" 2>"$TMPDIR/issue.err"; then
  fail "armed issue SUCCEEDED (expected a post-commit publication fault)" \
    "$TMPDIR/issue.out" "$TMPDIR/issue.err" "$LOG.err"
fi

# --- 3. NO secret on disk: $PUBROOT is empty (no escrow doc, no stage temp). --
test ! -e "$PUBROOT/credF" \
  || fail "escrow doc for credF landed on \$PUBROOT despite the publication fault"
assert_pubroot_empty "after armed issue"

# --- 4. the orphan is present + keyed by R (recover is read-only). ------------
"$WYCTL" --daemon-url "$URL" service-credential recover \
  --request-id "$REQ_ID" --tenant tenant-a --access-token-file "$ADMIN2_TOKEN" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/recover1.out" 2>"$TMPDIR/recover1.err" \
  || fail "recover of the orphan failed" "$TMPDIR/recover1.err" "$LOG.err"

REC1_STATE=$("$PY" "$SC_E2E_PY" receipt-field --field state <"$TMPDIR/recover1.out") \
  || fail "recover row missing state" "$TMPDIR/recover1.out"
REC1_SUCC=$("$PY" "$SC_E2E_PY" receipt-field --field successor_credential_id \
  <"$TMPDIR/recover1.out") \
  || fail "recover row missing successor_credential_id" "$TMPDIR/recover1.out"
REC1_RECOVERY=$("$PY" "$SC_E2E_PY" receipt-field --field recovery \
  <"$TMPDIR/recover1.out") \
  || fail "recover row missing recovery classification" "$TMPDIR/recover1.out"
[ "$REC1_STATE" = "server_committed" ] \
  || fail "orphan state=$REC1_STATE (expected server_committed)" "$TMPDIR/recover1.out"
[ -n "$REC1_SUCC" ] && [ "$REC1_SUCC" != "-" ] \
  || fail "orphan carried no successor_credential_id" "$TMPDIR/recover1.out"
case "$REC1_RECOVERY" in
  server_committed | server_committed_replay) : ;;
  *) fail "orphan recovery=$REC1_RECOVERY (expected server_committed[_replay])" \
    "$TMPDIR/recover1.out" ;;
esac
# recover must not auto-resume publication / deliver the secret.
assert_pubroot_empty "after recover (pre-restart)"

# --- 5. RESTART the daemon WITHOUT the fault flag (still WITH --production). ---
stop_daemon
launch_daemon

# The live-MFA session and its armed service-credential authority are in-memory
# and are lost on restart, so this boot re-mints an MFA bearer (login-totp using
# the saved TOTP secret) and re-arms the authority on the new session before any
# post-restart management op (recover/revoke/issue).
ADMIN2_TOKEN2="$TMPDIR/admin2b.token"
"$PY" "$SC_E2E_PY" login-totp --base-url "$URL" --username admin2 \
  --secret-file "$ADMIN2_SECRET" \
  >"$ADMIN2_TOKEN2" 2>"$TMPDIR/admin2b.err" \
  || fail "admin2 TOTP re-login after restart failed" \
    "$TMPDIR/admin2b.err" "$LOG.err"
chmod 600 "$ADMIN2_TOKEN2"
"$PY" "$SC_E2E_PY" arm --base-url "$URL" --token-file "$ADMIN2_TOKEN2" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 10 \
  >"$TMPDIR/arm2.out" 2>"$TMPDIR/arm2.err" \
  || fail "post-restart self-arm failed" "$TMPDIR/arm2.out" "$TMPDIR/arm2.err" \
    "$LOG.err"

# --- 6. the orphan SURVIVED restart: same successor id, still committed. ------
"$WYCTL" --daemon-url "$URL" service-credential recover \
  --request-id "$REQ_ID" --tenant tenant-a --access-token-file "$ADMIN2_TOKEN2" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/recover2.out" 2>"$TMPDIR/recover2.err" \
  || fail "post-restart recover failed (orphan did not survive)" \
    "$TMPDIR/recover2.err" "$LOG.err"
REC2_STATE=$("$PY" "$SC_E2E_PY" receipt-field --field state <"$TMPDIR/recover2.out") \
  || fail "post-restart recover row missing state" "$TMPDIR/recover2.out"
REC2_SUCC=$("$PY" "$SC_E2E_PY" receipt-field --field successor_credential_id \
  <"$TMPDIR/recover2.out") \
  || fail "post-restart recover row missing successor_credential_id" \
    "$TMPDIR/recover2.out"
[ "$REC2_STATE" = "server_committed" ] \
  || fail "post-restart orphan state=$REC2_STATE (expected server_committed)" \
    "$TMPDIR/recover2.out"
[ "$REC2_SUCC" = "$REC1_SUCC" ] \
  || fail "post-restart successor id changed ($REC1_SUCC -> $REC2_SUCC)" \
    "$TMPDIR/recover2.out"
assert_pubroot_empty "after restart + recover"

# --- 7. REVOCABLE via the public workflow (revoke the orphan's successor). ----
# The orphan is a durable SERVER_COMMITTED credential whose id the operator
# learns from `recover`; it is revoked through the ordinary public revoke path.
REVOKE_RID=$("$PY" "$SC_E2E_PY" mint-request-id) \
  || fail "unable to mint revoke request id"
"$WYCTL" --daemon-url "$URL" service-credential revoke \
  --credential-id "$REC2_SUCC" --request-id "$REVOKE_RID" --tenant tenant-a \
  --access-token-file "$ADMIN2_TOKEN2" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/revoke.out" 2>"$TMPDIR/revoke.err" \
  || fail "revoking the orphan credential failed" "$TMPDIR/revoke.err" "$LOG.err"
grep -q "state=revoked" "$TMPDIR/revoke.out" \
  || fail "orphan revoke did not report state=revoked" "$TMPDIR/revoke.out"
# A revoked orphan still never delivered a secret.
assert_pubroot_empty "after revoke"

# --- 8. NEGATIVE CONTROL: a fresh issue on the restarted daemon completes. -----
FRESH_RID=$("$PY" "$SC_E2E_PY" mint-request-id) \
  || fail "unable to mint fresh request id"
FRESH_EXPIRES=$(( $(now_us) + 315360000000000 ))
"$WYCTL" --daemon-url "$URL" service-credential issue \
  --request-id "$FRESH_RID" --subject svc:svc-app --tenant tenant-a \
  --destination credG --expires-at-us "$FRESH_EXPIRES" \
  --access-token-file "$ADMIN2_TOKEN2" \
  --guard-timestamp "$(now_us)" --guard-loc-class trusted --guard-risk 0 \
  >"$TMPDIR/issue2.out" 2>"$TMPDIR/issue2.err" \
  || fail "post-restart fresh issue failed (single-shot seam wedged the daemon)" \
    "$TMPDIR/issue2.err" "$LOG.err"
FRESH_STATE=$("$PY" "$SC_E2E_PY" receipt-field --field state <"$TMPDIR/issue2.out") \
  || fail "fresh issue receipt missing state" "$TMPDIR/issue2.out"
FRESH_DELIVERED=$("$PY" "$SC_E2E_PY" receipt-field --field delivered \
  <"$TMPDIR/issue2.out") \
  || fail "fresh issue receipt missing delivered" "$TMPDIR/issue2.out"
[ "$FRESH_STATE" = "terminal" ] \
  || fail "fresh issue state=$FRESH_STATE (expected terminal)" "$TMPDIR/issue2.out"
[ "$FRESH_DELIVERED" = "yes" ] \
  || fail "fresh issue delivered=$FRESH_DELIVERED (expected yes)" "$TMPDIR/issue2.out"
test -s "$PUBROOT/credG" \
  || fail "fresh issue did not write the escrow doc to \$PUBROOT/credG"

echo "check-service-credential-publication-fault-e2e: #380 orphan-window proof"
echo "  2 issue failed (armed) : non-zero wyctl exit (post-commit fault)"
echo "  3 no secret on disk     : \$PUBROOT empty after failed issue"
echo "  4 orphan recover        : state=$REC1_STATE recovery=$REC1_RECOVERY succ=$REC1_SUCC"
echo "  6 survived restart      : state=$REC2_STATE succ=$REC2_SUCC"
echo "  7 revoked (public wf)   : $(cat "$TMPDIR/revoke.out")"
echo "  8 fresh issue completes : state=$FRESH_STATE delivered=$FRESH_DELIVERED"
echo "check-service-credential-publication-fault-e2e: PASS"
exit 0
