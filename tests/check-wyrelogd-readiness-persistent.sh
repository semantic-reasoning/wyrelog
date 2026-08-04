#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

WYRELOGD=$1
TEMPLATE_DIR=$2
PYTHON=$3
HAS_FACT=${4:-0}

TMPDIR=$(mktemp -d)
POLICY_DB="$TMPDIR/policy.sqlite"
FACT_ROOT="$TMPDIR/facts"
trap 'rm -rf "$TMPDIR"' EXIT INT TERM

run_check() {
  set -- "$WYRELOGD" --template-dir "$TEMPLATE_DIR" \
    --policy-db "$POLICY_DB" --check
  if [ "$HAS_FACT" = "1" ]; then
    set -- "$@" --fact-root "$FACT_ROOT"
  fi
  "$@"
}

assert_exact_count() {
  "$PYTHON" - "$POLICY_DB" "$1" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
expected = int(sys.argv[2])
connection = sqlite3.connect(path)
events = connection.execute(
    """
    SELECT id, created_at_us
      FROM audit_events
     WHERE subject_id='wyrelogd'
       AND action='policy_audit_reload_check'
       AND resource_id='audit_event'
       AND deny_reason='readiness'
       AND deny_origin='policy_store'
       AND request_id='wyrelogd-readiness-request'
       AND decision=1
     ORDER BY created_at_us, id
    """
).fetchall()
committed = connection.execute(
    """
    SELECT e.id, e.created_at_us
      FROM audit_events AS e
      JOIN audit_intentions AS i ON i.audit_id=e.id
     WHERE e.subject_id='wyrelogd'
       AND e.action='policy_audit_reload_check'
       AND e.resource_id='audit_event'
       AND e.deny_reason='readiness'
       AND e.deny_origin='policy_store'
       AND e.request_id='wyrelogd-readiness-request'
       AND e.decision=1
       AND i.created_at_us=e.created_at_us
       AND i.subject_id=e.subject_id
       AND i.action=e.action
       AND i.resource_id=e.resource_id
       AND i.deny_reason=e.deny_reason
       AND i.deny_origin=e.deny_origin
       AND i.request_id=e.request_id
       AND i.decision=e.decision
       AND i.state='committed'
       AND i.attempt_count=0
       AND i.last_error IS NULL
     ORDER BY e.created_at_us, e.id
    """
).fetchall()
unfinished = connection.execute(
    """
    SELECT COUNT(*) FROM audit_intentions
     WHERE action='policy_audit_reload_check'
       AND state IN ('pending','failed')
    """
).fetchone()[0]
duplicate_ids = connection.execute(
    """
    SELECT COUNT(*) FROM (
      SELECT audit_id FROM audit_intentions
       WHERE action='policy_audit_reload_check'
       GROUP BY audit_id HAVING COUNT(*) != 1
    )
    """
).fetchone()[0]
connection.close()

if len(events) != expected or committed != events:
    raise SystemExit(
        f"readiness bundle mismatch: expected={expected} "
        f"events={events!r} committed={committed!r}"
    )
if len({event_id for event_id, _ in events}) != expected:
    raise SystemExit(f"readiness IDs are not fresh: {events!r}")
if unfinished != 0 or duplicate_ids != 0:
    raise SystemExit(
        f"readiness residue: unfinished={unfinished} duplicates={duplicate_ids}"
    )
PY
}

run_check
assert_exact_count 1
run_check
assert_exact_count 2

rm -rf "$TMPDIR"
trap - EXIT INT TERM
