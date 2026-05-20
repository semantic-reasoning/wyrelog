#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Subprocess-level coverage for the wyrelogd --config TOCTOU gate and
# the --profile-info bootstrap-key staleness warning.
#
# Commit 1 of issue #335 (d8341a7) added a static unit-test reference
# implementation of conf_file_open_safely and the bootstrap-key probe
# logic. Those unit tests cover the in-process helpers but cannot
# exercise the real open(2)/fstat(2)/sqlite3_open code paths through
# the daemon binary -- which is exactly the regression surface a future
# refactor of options.c or wyrelogd.c would land on. This test drives
# the daemon as a subprocess so the FS-level edge cases are observed
# end-to-end.
#
# Case matrix (Architect+Critic, issue #335 commit 3):
#
#   1. mode 0664 + --production       -> fail-fast, "wyrelogd: conf: refusing"
#   2. mode 0664 (no --production)    -> WARN "wyrelogd: conf:", proceeds
#   3. symlink at conf path           -> refuse regardless of mode
#   4. nonexistent conf path          -> fail-fast, "wyrelogd: conf:"
#   5. bootstrap_admin_subject + populated store -> stale-key WARN
#   6. bootstrap_admin_subject + empty store     -> no stale-key WARN
#   7. no bootstrap_admin_* + populated store    -> no bootstrap_admin WARN
#   8. mode 0640                                 -> loads cleanly
#
# Case 8 documents (but cannot exercise) the root:wyrelog ownership the
# package installer wires up: the test harness runs unprivileged so it
# cannot chown to root. The gate in options.c is mode-only (no st_uid
# check), so a same-uid 0640 fixture covers the positive path that the
# packaged install will hit. The owner-stability property is a packaging
# concern (see packaging/tmpfiles.d, sysusers.d) and is asserted by
# check-packaged-install-readiness.sh.

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

write_key () {
  "$PYTHON" - "$1" <<'PY'
import os
import sys
with open(sys.argv[1], "wb") as f:
    f.write(os.urandom(32))
os.chmod(sys.argv[1], 0o600)
PY
}

write_principal_states_db () {
  # Create a *plain* sqlite database (no SQLCipher) with the
  # principal_states schema and the given number of rows. The probe
  # in wyrelogd.c opens with SQLITE_OPEN_READONLY and NO custom VFS,
  # so a plain sqlite file is exactly what the probe expects to see
  # when the live policy authority is unencrypted (or, equivalently,
  # what a test fixture should look like).
  "$PYTHON" - "$1" "$2" <<'PY'
import sqlite3
import sys
path = sys.argv[1]
rows = int(sys.argv[2])
conn = sqlite3.connect(path)
conn.executescript(
    "CREATE TABLE IF NOT EXISTS principal_states ("
    "  subject_id TEXT PRIMARY KEY,"
    "  state TEXT NOT NULL,"
    "  updated_at INTEGER,"
    "  failed_attempt_count INTEGER NOT NULL DEFAULT 0,"
    "  locked_at INTEGER"
    ");"
)
for i in range(rows):
    conn.execute(
        "INSERT OR REPLACE INTO principal_states "
        "(subject_id, state, updated_at, failed_attempt_count, locked_at) "
        "VALUES (?, ?, ?, 0, NULL)",
        (f"seed-subject-{i}", "ACTIVE", 0),
    )
conn.commit()
conn.close()
PY
}

write_conf () {
  # $1 dest, $2 mode (octal), $3..N additional [daemon] keys.
  dest=$1
  mode=$2
  shift 2
  policy_db=${POLICY_DB:-$TMPDIR/policy.sqlite}
  audit_db=${AUDIT_DB:-$TMPDIR/audit.duckdb}
  {
    printf '[daemon]\n'
    printf 'profile=system\n'
    printf 'template_dir=%s\n' "$TEMPLATE_DIR"
    printf 'policy_db=%s\n' "$policy_db"
    printf 'policy_keyprovider=file:%s\n' "$KEY_FILE"
    printf 'audit_db=%s\n' "$audit_db"
    for extra in "$@"; do
      printf '%s\n' "$extra"
    done
  } >"$dest"
  chmod "$mode" "$dest"
}

KEY_FILE="$TMPDIR/policy.key"
write_key "$KEY_FILE"

# ---------------------------------------------------------------------------
# Case 1: mode 0664 + --production -> fail-fast with "wyrelogd: conf: refusing"
# ---------------------------------------------------------------------------
CONF1="$TMPDIR/case1.conf"
write_conf "$CONF1" 0664
if "$WYRELOGD" --config "$CONF1" --production --profile-info \
    >"$TMPDIR/case1.out" 2>"$TMPDIR/case1.err"; then
  echo "case 1: --production accepted a 0664 conf file" >&2
  cat "$TMPDIR/case1.err" >&2
  exit 1
fi
if ! grep -q "wyrelogd: conf: refusing" "$TMPDIR/case1.err"; then
  echo "case 1: missing greppable refusal token" >&2
  cat "$TMPDIR/case1.err" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Case 2: mode 0664 (no --production) -> WARN "wyrelogd: conf:", proceeds
# ---------------------------------------------------------------------------
CONF2="$TMPDIR/case2.conf"
write_conf "$CONF2" 0664
# Use --profile-info to exit fast after the warn-and-continue path
# without entering the runtime main loop.
if ! "$WYRELOGD" --config "$CONF2" --profile-info \
    >"$TMPDIR/case2.out" 2>"$TMPDIR/case2.err"; then
  echo "case 2: non-production conf-gate refused a 0664 conf" >&2
  cat "$TMPDIR/case2.err" >&2
  exit 1
fi
if ! grep -q "wyrelogd: conf:" "$TMPDIR/case2.err"; then
  echo "case 2: missing greppable WARN prefix" >&2
  cat "$TMPDIR/case2.err" >&2
  exit 1
fi
if grep -q "wyrelogd: conf: refusing" "$TMPDIR/case2.err"; then
  echo "case 2: non-production WARN incorrectly used refusal phrasing" >&2
  cat "$TMPDIR/case2.err" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Case 3: symlink at conf path -> refuse regardless of --production
# ---------------------------------------------------------------------------
REAL_CONF="$TMPDIR/case3.real.conf"
LINK_CONF="$TMPDIR/case3.link.conf"
write_conf "$REAL_CONF" 0640
ln -s "$REAL_CONF" "$LINK_CONF"
# With --production: must refuse and mention ELOOP or "symlink".
if "$WYRELOGD" --config "$LINK_CONF" --production --profile-info \
    >"$TMPDIR/case3a.out" 2>"$TMPDIR/case3a.err"; then
  echo "case 3a: --production accepted a symlinked conf file" >&2
  cat "$TMPDIR/case3a.err" >&2
  exit 1
fi
if ! grep -Eq "symlink|ELOOP" "$TMPDIR/case3a.err"; then
  echo "case 3a: refusal did not mention symlink or ELOOP" >&2
  cat "$TMPDIR/case3a.err" >&2
  exit 1
fi
# Without --production: symlink is still a HARD failure (open(2) with
# O_NOFOLLOW returns ELOOP before the perm-check branch can soften it).
if "$WYRELOGD" --config "$LINK_CONF" --profile-info \
    >"$TMPDIR/case3b.out" 2>"$TMPDIR/case3b.err"; then
  echo "case 3b: non-production accepted a symlinked conf file" >&2
  cat "$TMPDIR/case3b.err" >&2
  exit 1
fi
if ! grep -Eq "symlink|ELOOP" "$TMPDIR/case3b.err"; then
  echo "case 3b: non-production refusal did not mention symlink or ELOOP" >&2
  cat "$TMPDIR/case3b.err" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Case 4: nonexistent conf path -> fail-fast with "wyrelogd: conf:" prefix
# ---------------------------------------------------------------------------
MISSING_CONF="$TMPDIR/does-not-exist.conf"
if "$WYRELOGD" --config "$MISSING_CONF" --production --profile-info \
    >"$TMPDIR/case4.out" 2>"$TMPDIR/case4.err"; then
  echo "case 4: --production accepted a nonexistent conf path" >&2
  cat "$TMPDIR/case4.err" >&2
  exit 1
fi
if ! grep -q "wyrelogd: conf:" "$TMPDIR/case4.err"; then
  echo "case 4: missing greppable conf-prefix on ENOENT" >&2
  cat "$TMPDIR/case4.err" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Case 5: bootstrap_admin_subject=foo + populated store -> stale-key WARN
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/case5/policy.sqlite"
AUDIT_DB="$TMPDIR/case5/audit.duckdb"
mkdir -p "$TMPDIR/case5"
write_principal_states_db "$POLICY_DB" 1
CONF5="$TMPDIR/case5.conf"
write_conf "$CONF5" 0640 \
  "bootstrap_admin_subject=foo" \
  "bootstrap_admin_allow_skip_mfa=false"
if ! "$WYRELOGD" --config "$CONF5" --profile-info \
    >"$TMPDIR/case5.out" 2>"$TMPDIR/case5.err"; then
  echo "case 5: --profile-info exited nonzero unexpectedly" >&2
  cat "$TMPDIR/case5.err" >&2
  exit 1
fi
if ! grep -q "wyrelogd: bootstrap_admin: stale-key" "$TMPDIR/case5.err"; then
  echo "case 5: missing stale-key WARN on populated store" >&2
  cat "$TMPDIR/case5.err" >&2
  exit 1
fi
if ! grep -q "subject=foo" "$TMPDIR/case5.err"; then
  echo "case 5: stale-key WARN missing subject=foo" >&2
  cat "$TMPDIR/case5.err" >&2
  exit 1
fi
if ! grep -q "allow_skip_mfa=false" "$TMPDIR/case5.err"; then
  echo "case 5: stale-key WARN missing allow_skip_mfa=false" >&2
  cat "$TMPDIR/case5.err" >&2
  exit 1
fi
unset POLICY_DB AUDIT_DB

# ---------------------------------------------------------------------------
# Case 6: bootstrap_admin_subject=foo + empty store -> NO stale-key WARN
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/case6/policy.sqlite"
AUDIT_DB="$TMPDIR/case6/audit.duckdb"
mkdir -p "$TMPDIR/case6"
write_principal_states_db "$POLICY_DB" 0
CONF6="$TMPDIR/case6.conf"
write_conf "$CONF6" 0640 \
  "bootstrap_admin_subject=foo" \
  "bootstrap_admin_allow_skip_mfa=false"
if ! "$WYRELOGD" --config "$CONF6" --profile-info \
    >"$TMPDIR/case6.out" 2>"$TMPDIR/case6.err"; then
  echo "case 6: --profile-info exited nonzero unexpectedly" >&2
  cat "$TMPDIR/case6.err" >&2
  exit 1
fi
if grep -q "wyrelogd: bootstrap_admin: stale-key" "$TMPDIR/case6.err"; then
  echo "case 6: stale-key WARN fired on a fresh policy store" >&2
  cat "$TMPDIR/case6.err" >&2
  exit 1
fi
unset POLICY_DB AUDIT_DB

# ---------------------------------------------------------------------------
# Case 7: no bootstrap_admin_* keys + populated store -> no bootstrap_admin WARN
# ---------------------------------------------------------------------------
POLICY_DB="$TMPDIR/case7/policy.sqlite"
AUDIT_DB="$TMPDIR/case7/audit.duckdb"
mkdir -p "$TMPDIR/case7"
write_principal_states_db "$POLICY_DB" 1
CONF7="$TMPDIR/case7.conf"
write_conf "$CONF7" 0640
if ! "$WYRELOGD" --config "$CONF7" --profile-info \
    >"$TMPDIR/case7.out" 2>"$TMPDIR/case7.err"; then
  echo "case 7: --profile-info exited nonzero unexpectedly" >&2
  cat "$TMPDIR/case7.err" >&2
  exit 1
fi
if grep -q "wyrelogd: bootstrap_admin:" "$TMPDIR/case7.err"; then
  echo "case 7: bootstrap_admin WARN fired without bootstrap_admin_* keys" >&2
  cat "$TMPDIR/case7.err" >&2
  exit 1
fi
unset POLICY_DB AUDIT_DB

# ---------------------------------------------------------------------------
# Case 8: mode 0640 -> loads cleanly (positive case, guards against
#                     gate-too-strict regression).
#
# Documented gap: this test runs unprivileged, so it cannot chown the
# fixture to root:wyrelog. The gate is mode-only (no st_uid/st_gid
# check) so a same-uid 0640 file exercises the same accept-path the
# packaged install will hit. Ownership stability is asserted by the
# packaging tests (tmpfiles.d, sysusers.d) rather than here.
# ---------------------------------------------------------------------------
CONF8="$TMPDIR/case8.conf"
write_conf "$CONF8" 0640
if ! "$WYRELOGD" --config "$CONF8" --production --profile-info \
    >"$TMPDIR/case8.out" 2>"$TMPDIR/case8.err"; then
  echo "case 8: --production rejected a 0640 conf file (gate too strict)" >&2
  cat "$TMPDIR/case8.err" >&2
  exit 1
fi
if grep -q "wyrelogd: conf:" "$TMPDIR/case8.err"; then
  echo "case 8: 0640 conf produced an unexpected conf-gate diagnostic" >&2
  cat "$TMPDIR/case8.err" >&2
  exit 1
fi
# Sanity: the stdout should be the parseable profile-info report.
if ! grep -q "^profile=system$" "$TMPDIR/case8.out"; then
  echo "case 8: --profile-info stdout missing profile= line" >&2
  cat "$TMPDIR/case8.out" >&2
  exit 1
fi

exit 0
