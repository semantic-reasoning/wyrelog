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
boundaries. After abort is proven complete, the daemon stores a
terminal receipt atomically with claim and journal removal. Status and an
abort retry with the same UUID return the receipt after rechecking the caller's
authorization and exact tenant/graph scope. The receipt permanently reserves
that UUID so a later begin cannot silently create a different operation. A
completed commit remains represented by its durable journal; status reports
`committed` once its lifecycle handoff is durably recorded, including after a
lost COMMIT/resume response.

Responses contain only the scope, destination identifiers, operation UUID,
revision, graph count, publication eligibility, stable state, and an optional
sanitized failure code. They never include bundle paths, tokens, or fact data.
The typed client is declared in `wyrelog/client.h`. If a mutation loses its
transport response, the client reports an unknown outcome and preserves the
same operation UUID; callers should inspect status or resume with that UUID
instead of starting a new operation.
