# Offline restore daemon API

Offline restore operations are available under `/facts/restore/`:

| Route | Purpose |
| --- | --- |
| `dry-run` | Read-only eligibility observation |
| `begin` | Create the confirmed restore claim |
| `prepare` | Import and replay preflight |
| `commit` | Admit the durable commit decision |
| `resume` | Continue a decided commit after interruption |
| `abort` | Roll back an undecided operation and release it after proof |
| `status` | Inspect a journal by operation UUID |

Calls use `POST` with a strict JSON object containing string-valued fields:
`scope` (`tenant` or `graph`), `tenant_id`, `graph_id` (empty for tenant
scope), `bundle_path`, `trusted_manifest_sha256`, `operation_uuid`,
`expected_revision` (decimal), and `confirmed` (`true` or `false`). Unknown,
duplicate, missing, or mistyped fields are refused. `status`, `abort`, and
`resume` do not consume a bundle; other operations require the daemon-readable
owner-only bundle directory and a 64 digit SHA-256 digest.

The digest must come from a separately trusted channel. The daemon checks it
against the exact manifest bytes and validates the bundle inventory. A digest
or marker read only from inside the bundle or restore journal does not
authenticate the source. The caller remains responsible for establishing the
digest provenance.

Every request also carries the normal daemon guard query. Tenant restore is
authorized with `wr.tenant.manage` in the `__wr_default` control tenant; the
destination tenant is named in the body. The query tenant and authenticated
session must both be `__wr_default` for that control-plane action. Graph
restore also uses an active `__wr_default` session and query, and evaluates
`wr.graph.manage` in `__wr_default`. This is a global control-plane restore
privilege across destination tenants, including sealed targets. A grant scoped
only to a destination tenant cannot authorize its restore because sealed
tenant session state is closed. The body still binds each operation to its
destination tenant and graph; these must match the durable operation journal.
`begin`
and `commit` require
`confirmed: "true"`; other operations require false. Mutations use the
operation UUID as their idempotency key and the observed journal revision as
their compare-and-swap guard. A UUID replay with a different request tuple or
stale revision is a conflict. A request using a UUID from another scope returns
not found, so the daemon does not disclose an operation across scope
boundaries. After abort is proven complete, the daemon stores a terminal
receipt atomically with claim and journal removal. Status and an abort retry
with the same UUID return the receipt after rechecking the caller's
authorization and exact tenant/graph scope. The receipt permanently reserves
that UUID so a later begin cannot silently create a different operation. A
completed commit is also terminalized into a receipt after the lifecycle
handoff is durably recorded; the same transaction stores committed terminal
history and removes its journal and claims. Status and resume with the same UUID
then return the receipt, including after a lost COMMIT or resume response.
Terminal receipt responses retain the operation scope and destination, UUID,
final revision, and graph count, with `publication_eligible: false`, the
terminal state, and no failure code.
New receipts persist the operation's graph count at terminalization. A
pre-existing tenant-scope aborted receipt can have `graph_count: 0` after
upgrade because its journal and terminal history were already removed, so no
durable source remains from which to reconstruct its original count. Committed
receipts are backfilled from terminal history, and graph-scope aborted receipts
have a count of one.

Responses contain only the scope, destination identifiers, operation UUID,
revision, graph count, publication eligibility, stable state, and an optional
sanitized failure code. They never include bundle paths, tokens, or fact data.
The typed client is declared in `wyrelog/client.h`. If a mutation loses its
transport response, the client reports an unknown outcome and preserves the
same operation UUID; callers should inspect status or resume with that UUID
instead of starting a new operation.

## `wyctl` workflow

`wyctl fact restore` exposes these lifecycle routes. Every command needs the
daemon URL, an access-token file, and the normal guard values. Obtain the
64-character manifest digest through a separately trusted channel.

```sh
wyctl --daemon-url "$DAEMON_URL" fact restore dry-run \
  --scope tenant --tenant "$TENANT" --bundle "$BUNDLE" \
  --trusted-sha256 "$TRUSTED_SHA256" --format json \
  --access-token-file "$TOKEN_FILE" --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"

wyctl --daemon-url "$DAEMON_URL" fact restore begin \
  --scope tenant --tenant "$TENANT" --uuid "$OPERATION_UUID" \
  --bundle "$BUNDLE" --trusted-sha256 "$TRUSTED_SHA256" --confirm \
  --format json --access-token-file "$TOKEN_FILE" \
  --guard-timestamp "$GUARD_TIMESTAMP_US" \
  --guard-loc-class "$GUARD_LOC_CLASS" --guard-risk "$GUARD_RISK"
```

For graph scope, add `--graph "$GRAPH"` to each command. After `begin`, use
`status` to read the current revision, then pass that revision to `prepare`.
After successful preflight, inspect status again and use the returned revision
for `commit --confirm`. If commit was decided but interrupted, use `resume`;
use `abort --confirm` only before commit has been decided. Each mutation uses
the same `--uuid` throughout the lifecycle. Do not replace it after a lost
response.

`status --retry-begin` is for an unknown BEGIN that may never have reached the
daemon. Supply the original `--bundle` and `--trusted-sha256`; its recovery
command retains that tuple. Replay `begin` only with the same UUID, scope,
destination, bundle, and digest. A status result of `PREPARING` means the BEGIN
was recorded and the next step is `prepare`.

The CLI emits one JSON object or one text line. JSON keys are stable and
ordered: `operation`, `outcome`, `scope`, `tenant_id`, `graph_id`,
`operation_uuid`, `revision`, `expected_revision`, `graph_count`,
`publication_eligible`, `state`, `failure_code`, `next_command`. Text uses the
same order as `key=value` fields; string values are URI-escaped. Missing values
are JSON `null` and text `-`. Neither format includes bundle paths, digests,
tokens, or fact data. Treat `next_command` as guidance and review its
placeholders before running it.

| Exit | Meaning | Next action |
| --- | --- | --- |
| `0` | Step completed | Continue using the returned revision and state |
| `2` | Invalid CLI arguments | Correct the command before retrying |
| `4` | Refused, cancelled, or not found | Check authorization, scope, and recovery guidance |
| `5` | Other failure | Inspect the sanitized result and daemon logs |
| `6` | Authentication failure | Refresh the access token |
| `7` | Revision or tuple conflict | Read status and reconcile the operation |
| `8` | Operation remains in progress | Read status; continue with the indicated step |
| `9` | Mutation outcome is unknown | Keep the UUID and inspect status before retrying |

An in-progress result can be returned with exit `8`; it is a durable state,
not proof that the operation failed. Exit `9` means a mutation's result could
not be trusted, including a lost, incomplete, malformed, or mismatched
response. Status failures use the non-mutation failure codes.
