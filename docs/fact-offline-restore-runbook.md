# Offline restore operator runbook

This guide covers daemon-managed, staged restore of a tenant's selected graph set or one graph. It uses the shipped `wyctl fact restore` routes. The file-level disaster-recovery procedure in [Operator runbook](operator-runbook.md#backup-and-restore) replaces profile files while the daemon is stopped; it is a separate workflow and must not be mixed with this journaled restore.

## Before starting

Run the stateful restore on Linux. macOS admits `begin` and a graph-scope `prepare` but cannot `commit`, and `resume` makes no progress there, so a macOS restore can only be aborted; see [the daemon API](offline-restore-daemon-api.md). The restore publication and recovery paths depend on Linux filesystem primitives; a successful `dry-run` on another platform does not mean `commit` or `resume` is supported there.

Obtain the bundle manifest SHA-256 through a separately trusted channel, such as a signed backup receipt. Do not trust a digest copied from the bundle or restore journal. Put the bundle in the daemon-readable owner-only bundle directory, and use the exact same bundle and digest throughout this operation. Register every schema definition selected by the backup on the destination before sealing it; the backup manifest carries selected versions, not schema definitions. See [schema transition limits](fact-offline-restore-schema-transition.md).

Prepare the destination while it is sealed for maintenance. Ensure the caller has the control-plane `wr.tenant.manage` permission in `__wr_default` for a tenant restore, or `wr.graph.manage` there for a graph restore. The session and guard query must also use `__wr_default`; a grant scoped only to the sealed destination cannot authorize this operation. Use unique operation UUIDs, and record each UUID with the incident or change record.

Set the common shell values below before running either example. The guard values must satisfy the deployment's configured policy.

```sh
export DAEMON_URL='http://127.0.0.1:8080'
export TOKEN_FILE='/run/wyrelog/operator-access-token'
export GUARD_TIMESTAMP_US='1760000000000000'
export GUARD_LOC_CLASS='trusted'
export GUARD_RISK='0'
export TENANT='tenant-a'
export BUNDLE='/var/lib/wyrelog/restore/bundle'
export TRUSTED_SHA256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
```

Use a fresh guard timestamp and values accepted by your policy at each invocation. The timestamp above is an example placeholder, not a reusable credential.

## Tenant restore

Tenant scope restores the selected graph set contained in the bundle. First check eligibility. This does not create a claim or alter the destination.

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore dry-run \
  --scope tenant --tenant "$TENANT" --bundle "$BUNDLE" \
  --trusted-sha256 "$TRUSTED_SHA256" --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

Review the destination, schema transition, graph count, eligibility and any failure code. If eligible, record a new UUID and create the durable claim:

```sh
export OPERATION_UUID='11111111-2222-4333-8444-555555555555'
wyctl --daemon-url "$DAEMON_URL" fact restore begin \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --confirm \
  --format json --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

Read status and pass its current `revision` to `prepare`:

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore status \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --format json --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"

export RESTORE_REVISION='1'
wyctl --daemon-url "$DAEMON_URL" fact restore prepare \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --revision "$RESTORE_REVISION" --bundle "$BUNDLE" \
  --trusted-sha256 "$TRUSTED_SHA256" --format json \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

After preflight succeeds, inspect status and review the prepared graph set. `PREPARED` is an operator decision point. Commit only after that review, using the latest returned revision:

```sh
export RESTORE_REVISION='2'
wyctl --daemon-url "$DAEMON_URL" fact restore commit \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --revision "$RESTORE_REVISION" --bundle "$BUNDLE" \
  --trusted-sha256 "$TRUSTED_SHA256" --confirm --format json \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

The revision values above illustrate the sequence. Always use the revision returned by the preceding command. A successful commit publishes the selected restore and automatically completes the normal lifecycle handoff, including unseal and replay. Do not manually unseal a successfully committed restore.

## Graph restore

Graph scope follows the same sequence but includes `--graph` on every command and affects only that destination graph. For example, eligibility and begin are:

```sh
export GRAPH='orders'
wyctl --daemon-url "$DAEMON_URL" fact restore dry-run \
  --scope graph --tenant "$TENANT" --graph "$GRAPH" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"

export GRAPH_OPERATION_UUID='66666666-7777-4888-8999-aaaaaaaaaaaa'
wyctl --daemon-url "$DAEMON_URL" fact restore begin \
  --scope graph --tenant "$TENANT" --graph "$GRAPH" \
  --uuid "$GRAPH_OPERATION_UUID" --bundle "$BUNDLE" \
  --trusted-sha256 "$TRUSTED_SHA256" --confirm --format json \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

Read status and prepare the graph using its current revision:

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore status \
  --scope graph --tenant "$TENANT" --graph "$GRAPH" \
  --uuid "$GRAPH_OPERATION_UUID" --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"

export GRAPH_RESTORE_REVISION='1'
wyctl --daemon-url "$DAEMON_URL" fact restore prepare \
  --scope graph --tenant "$TENANT" --graph "$GRAPH" \
  --uuid "$GRAPH_OPERATION_UUID" --revision "$GRAPH_RESTORE_REVISION" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --format json \
  --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

After reviewing `PREPARED` from status, commit with the latest status revision:

```sh
export GRAPH_RESTORE_REVISION='2'
wyctl --daemon-url "$DAEMON_URL" fact restore commit \
  --scope graph --tenant "$TENANT" --graph "$GRAPH" \
  --uuid "$GRAPH_OPERATION_UUID" --revision "$GRAPH_RESTORE_REVISION" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --confirm \
  --format json --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

The revision values above illustrate the sequence; use the revision actually
returned by each preceding command. Successful commit performs the lifecycle
handoff for this graph.

## Restart and response-loss recovery

The durable journal records the operation tuple, revision, per-graph progress, selected schema, and decision. States exposed by status include `PREPARING`, `PREPARED`, `COMMITTING`, `ACTIVE`, `ABORTING`, `ABORTED`, `COMMITTED`, and `UNKNOWN`. `PREPARING` means BEGIN was durably recorded and preparation can continue. `PREPARED` has no commit decision yet. Once COMMIT is durable, `COMMITTING` must be resumed; it cannot be aborted. A terminal receipt remains after the live journal and claim are removed, so status can still confirm a completed operation by UUID.

### Restart immediately before COMMIT

If the process stops after preflight and before the COMMIT decision is
recorded, inspect status after restart. A `PREPARED` result means publication
has not been committed. Review the prepared graph set again, then either run
`commit` with the returned revision or abort with that same revision. The
abort command is only for an operation before COMMIT; use the same UUID and
explicit confirmation:

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore abort \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --revision "$RESTORE_REVISION" --confirm --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

### Restart immediately after COMMIT

If the process stops after COMMIT was durably decided but before the response
or lifecycle handoff completes, status reports `COMMITTING`. Continue that
decision with `resume` and the latest revision. Never issue `abort` after
COMMIT. The daemon completes publication, unseal/replay and receipt recording.

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore resume \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --revision "$RESTORE_REVISION" --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

If a mutation response is lost, malformed or mismatched, keep the original UUID and inspect status before retrying. Never create a new UUID for an uncertain operation. If BEGIN may not have reached the daemon, run status with `--retry-begin` and the original bundle tuple. The CLI offers a retry `begin` only when status returns `failure_code=restore_not_found`; an `UNKNOWN` state by itself is not sufficient:

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore status \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --retry-begin \
  --format json --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

Only this unknown-BEGIN recovery uses `--retry-begin`. It retains the original UUID, destination, bundle and digest. Follow the returned state; do not run a fresh begin with a different tuple.

## Failure responses and safe next actions

The command's exit code is authoritative for automation; also inspect its sanitized JSON fields. The response does not contain paths, tokens, digests or fact data.

| Exit | Meaning | Safe next action |
| --- | --- | --- |
| `0` | Requested step completed | Read the returned state and revision before the next step. |
| `2` | Invalid local arguments | Correct the command; no request was made. |
| `4` | Refused, cancelled or not found | Check authorization, destination scope and status. A not-found after an ambiguous release does not prove release succeeded; inspect destination and policy. |
| `5` | Other failure | Inspect the sanitized failure code and daemon logs. Do not assume a mutation rolled back. Read status before deciding. |
| `6` | Authentication failed | Refresh the access token, then retry with the same UUID and tuple. |
| `7` | Revision or tuple conflict | Read status; use its revision and verify the original operation tuple. Do not replace the UUID. |
| `8` | Operation remains in progress or busy | Read status and continue the indicated durable phase. |
| `9` | Mutation outcome is unknown | Preserve the UUID, read status and resume or retry only the same operation as indicated. |

An exit `8` is not evidence of failure. Exit `9` requires inspection because the client could not prove what the daemon committed.

### Foreign artifact walkthrough

If status or a restore mutation refuses because a stage is foreign, replaced,
or has an unexpected identity, stop the operation. Preserve the bundle, stage,
claim and journal. Record the UUID and sanitized failure code, then have an
operator inspect the destination and daemon logs. Do not delete, rename, adopt
or recreate the artifact, and do not release the claim manually. Continue only
through the daemon's verified recovery path after the identity and policy
checks succeed. A partial abort also retains its claim and journal so a later
abort retry can recheck completed graphs. See [abort recovery](fact-offline-restore-abort-recovery.md).

## Schema and rollback boundary

All selected schema definitions must already be registered before the target is sealed. A legacy manifest without relation-version selection can be restored only when its active schema digest matches the destination. Schema changes selected by a new manifest are made active with the final publication; pre-COMMIT abort leaves the old activation in place.

Before the durable COMMIT decision, an authorized operator may choose abort. After COMMIT, the only safe path is forward recovery with `resume`; the daemon finishes publication, normal unseal/replay, and terminal receipt recording. This daemon-managed workflow does not replace the separate stopped-daemon file-level rollback procedure described in the operator runbook.
