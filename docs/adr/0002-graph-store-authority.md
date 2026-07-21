# ADR 0002: Graph Store Authority and Recovery Contract

Status: accepted

Related issues: #536, #537, #538, #539, #540, #544

## Context

Each graph will eventually use its own physical Datalog store. A pathname or
an open file is not sufficient authority for deciding whether that store is
canonical, writable, sealed, compatible, or recoverable. Existing policy rows
also predate physical-store identity and lifecycle metadata, so treating an
unsealed legacy row as active would silently adopt storage that has never been
verified.

This decision establishes the control-plane contract before physical store
creation, path resolution, or runtime engine ownership changes. Those data-plane
operations remain outside #537.

## Decision

The policy SQLite database is the sole durable authority for tenant and graph
store lifecycle. Filesystem presence, `storage_uri`, `storage_path`, and the
compatibility `sealed` booleans are observations or legacy behavior; they do
not override an authority record.

The tenant authority record owns:

| Field | Meaning and recovery owner |
| --- | --- |
| `lifecycle_state` | Admission state for tenant-wide lifecycle work. The lifecycle coordinator owns normal transitions. Legacy promotion is owned by reconciliation. |
| `lifecycle_generation` | Signed-63-bit CAS generation for every normal or reconciliation lifecycle change. The writer that commits a legal transition increments it exactly once. |
| `reconciliation_generation` | Signed-63-bit CAS generation that distinguishes recovery/adoption work from normal lifecycle changes. Reconciliation increments it exactly once. |

The graph authority record owns:

| Field | Meaning and recovery owner |
| --- | --- |
| `lifecycle_state` | Whether the graph store is unclassified, provisioning, active, sealed, or degraded. Provisioning and lifecycle coordinators own normal transitions; reconciliation alone owns recovery from degraded. |
| `store_uuid` | Canonical, globally unique, write-once physical identity. Provisioning reserves it; reconciliation verifies it but never substitutes another UUID. |
| `format_version` | Reserved store-format contract. Provisioning assigns it with the UUID; open/reconciliation code compares it with supported versions. |
| `path_encoding_version` | Reserved mapping contract from authority identity to a physical path. Provisioning assigns it with the UUID; path resolution must reject unsupported versions. |
| `lifecycle_generation` | Signed-63-bit CAS generation for lifecycle changes. Every applied normal or reconciliation transition increments it exactly once. |
| `reconciliation_generation` | Signed-63-bit CAS generation for recovery work. Only successful reconciliation increments it. |
| `last_error_class` | Sanitized closed error class for a degraded graph. It contains no raw path, SQL, secret, or exception text. The operation that degrades the graph chooses the class; successful reconciliation clears it. |

All generations and versions use SQLite integer storage with exact type and
range constraints. Generations cannot wrap. The three identity fields are
either all null or all present; reservation is the only null-to-present path.
`store_uuid` is canonical, globally unique, and cannot be cleared or replaced,
including through direct SQL.

## Compatibility state

Pre-#537 rows and rows created by the pre-cutover graph API are
`LEGACY_UNCLASSIFIED`. This is an explicit migration-only state, not an alias
for active. A sealed legacy graph cannot be reserved. An unsealed legacy graph
can leave this state only through graph reservation; a legacy tenant can leave
it only through tenant reconciliation. Normal lifecycle transition APIs never
adopt legacy state.

The existing `sealed` columns remain compatibility projections. They do not
prove engine drain, engine eviction, a no-open barrier, or canonical store
identity. Until the later lifecycle work supplies those barriers, callers must
not infer them from the boolean.

## Canonical physical locator

For path-encoding version 1, the configured fact root and the logical
`tenant_id` and `graph_id` are the only inputs to the physical location. Each
identifier's UTF-8 bytes are encoded as unpadded lowercase base32hex in one
filename component with a `v1-` prefix. The encoded payload alphabet is limited
to lowercase ASCII letters and digits, so case folding, reserved-name syntax,
colons, and trailing dots cannot alias logical identifiers on supported
filesystems. A 128-byte identifier occupies 208 bytes including the prefix and
therefore fits a 255-byte filename component. Decoding and re-encoding must
reproduce the component byte-for-byte. Uppercase or padded spellings, nonzero
padding bits, NUL, invalid UTF-8, raw separators, and other non-canonical
spellings are rejected.

The resulting layout is:

```text
<configured-fact-root>/<v1-tenant>/<v1-graph>/facts.duckdb
```

`storage_path` and `storage_uri` remain descriptive registry metadata. They
are useful for inspection and compatibility, but they are never path authority
and cannot redirect a create, replay, append, retract, or forget operation.
Restart and replay derive the same location again from the configured root and
logical identifiers.

On POSIX, the resolver opens an absolute root component by component and then
resolves tenant, graph, and file names relative to already-open directory
descriptors. Symbolic links are rejected at every resolved component. Owned
fact-root, tenant, and graph directories must retain their recorded identity,
owner, directory type, and exact mode `0700`; graph files must be owned regular
files with exact mode `0600`.

On Windows, the resolver accepts only fixed local volumes. It traverses from an
open volume root with handle-relative `NtCreateFile` calls and opens every entry
with reparse-point semantics, rejecting reparse points, remote or mapped drives,
reserved-device aliases, alternate data streams, trailing-dot/space aliases,
and non-exact case aliases. Directories and regular files must retain their full
volume/file identity and a protected current-user-only DACL. Windows file
descriptors are CRT owners of their underlying handles; resolver validation
borrows those handles and never closes them independently.

On both platforms, named entries are rechecked against held handles so
replacement, type changes, permission widening, and escape from the configured
tree fail closed. Creation durably flushes the containing directory where the
platform supports directory flushes. Unsupported filesystems and platforms
return a policy error instead of falling back to unsafe path traversal.

Each live policy-store handle binds the first configured fact-root string and
its platform identity for the rest of that store lifetime: POSIX device/inode,
or Windows volume serial and 128-bit file ID. Reusing the same configured string
revalidates the pinned identity; supplying another root or replacing the named
root fails before graph materialization, replay, or a subsequent resolver
operation can enter the replacement tree. This does not close the already
documented same-owner replacement window after a resolver operation hands a
pathname to DuckDB; #544 still owns that residual on both platforms.

Tenant and graph directory descriptors remain operation-scoped in #539. Their
exact identity and named containment are enforced throughout each resolver
operation, but they are opened and verified again for a later operation. A
store-lifetime tenant/graph identity pin and descriptor-bound DuckDB ownership
belong to #538 and #544; callers must not infer those stronger guarantees from
the fact-root binding.

The resolver also supplies a durable staging protocol for immutable file
publication. A POSIX `0600` or Windows protected owner-only staging file is
synced and published to a previously absent final name without overwrite.
POSIX publication links the final name and then removes the stage name; Windows
uses a handle-relative no-replace rename. The graph directory is durably flushed
at the platform-defined checkpoints. Retry classifies stage and final names by
the recorded platform identity, allowing recovery after either publication
checkpoint while rejecting foreign or replaced entries. Abort is allowed only
before a final name exists; after publication begins, the caller must resume
publication to convergence.

#539 and #540 deliberately do not reserve physical identity or provision the
final DuckDB schema. Policy graph creation materializes only canonical private
directories. On the first fact write, DuckDB creates `facts.duckdb` at the
canonical derived path; the caller closes that first handle, hardens and
revalidates the file through the resolver, and then reopens it. DuckDB currently
accepts only a pathname, so there is still a
same-owner replacement window between resolver verification and DuckDB's
path-based open. Registry metadata cannot exploit that window, but an attacker
with the service account's filesystem authority can. The identity reservation
and descriptor-bound provisioning cutover in #544 owns removal of this
residual risk; `/proc/self/fd` is not treated as a portable substitute. A
lifetime root-writer lease excludes cooperating daemon writers before policy
or graph mutation, but deliberately does not claim to close that same-owner
pathname window.

## Physical graph-store identity

Every identity-aware fact-store handle validates an exact, self-identifying
record in `main.fact_store_metadata`. The table has only a `VARCHAR PRIMARY
KEY` named `key` and a non-null `VARCHAR` named `value`, with no defaults
or additional constraints. It contains exactly one row for each of:

| Key | Required value |
| --- | --- |
| `store_kind` | `wyrelog.fact` |
| `format_version` | Canonical decimal supported format version |
| `store_uuid` | The exact canonical lowercase UUID reserved in policy |
| `path_encoding_version` | Canonical decimal supported path-encoding version |
| `tenant_id` | The exact tenant identifier from policy |
| `graph_id` | The exact graph identifier from policy |

Validation is read-only and never creates a missing pathname. A missing,
partial, duplicated, structurally different, foreign, or unsupported identity
returns no handle. Known audit-store shapes are foreign even if an otherwise
valid fact metadata table was copied into the catalog. Ordinary fact and
projection tables are permitted after the identity is established.
All catalog-shape and metadata-value reads for one validation run share an
explicit DuckDB read transaction. Acquisition of its read snapshot at the
first catalog read is the validation linearization point. Successful
transaction cleanup is a prerequisite to returning a handle; query failures
roll back, and uncertain cleanup returns no handle. A concurrent metadata or
catalog mutation therefore cannot splice observations from different
committed states into one accepted identity.

Initialization is allowed only when the current DuckDB catalog has no
user-created table, view, sequence, type, function, or schema. The metadata
table and all six values are written and read back inside one transaction
before commit. A failure at any step rolls back the complete identity; a
committed exact tuple is an idempotent, write-free reentry, while a partial
legacy table is never repaired or adopted.

Identity-aware opens expose stable fact-local failure classes for identity,
format, path encoding, schema, open, and internal failures. The returned handle
owns a copy of the expected tuple and rejects fact operations for another
tenant or graph. Within one process, discovery through initialization commit is
serialized because separate DuckDB database objects do not provide a safe
first-creator boundary for a new pathname. The durable cross-process writer
lease is held for the complete writable-handle lifetime. Descriptor-bound
long-lived engine ownership remains owned by #544.

The identity-aware API is private in #538. Existing raw fact-store opens and
lazy legacy scope binding remain unchanged until the production cutover, so
this decision does not silently adopt or migrate an existing deployment.

## State machines

Tenant normal transitions are:

| Current | Allowed next state |
| --- | --- |
| `ACTIVE` | `SEALING` |
| `SEALING` | `SEALED`, or rollback to `ACTIVE` |
| `SEALED` | `UNSEALING` |
| `UNSEALING` | `ACTIVE`, or rollback to `SEALED` |

Tenant reconciliation promotes `LEGACY_UNCLASSIFIED` to `ACTIVE` or `SEALED`
and increments both generations. No other reconciliation edge is defined by
#537.

Graph normal transitions are:

| Current | Allowed next state |
| --- | --- |
| `PROVISIONING` | `ACTIVE` or `DEGRADED` |
| `ACTIVE` | `SEALED` or `DEGRADED` |
| `SEALED` | `ACTIVE` or `DEGRADED` |
| `DEGRADED` | none |

Graph reconciliation is the only `DEGRADED` to `ACTIVE` path and increments
both generations. Reservation changes an unsealed `LEGACY_UNCLASSIFIED` graph
to `PROVISIONING`, assigns the complete identity tuple, and increments only the
lifecycle generation.

`DEGRADED` requires one of `PATH`, `IDENTITY`, `FORMAT`, `SCHEMA`, `OPEN`,
`REPLAY`, `RECOVERY`, or `INTERNAL`. Every other canonical graph state requires
`NONE`.

## CAS and result contract

Every authority mutation matches the exact expected state and both expected
generations in one conditional SQL update. A mutation returns one of:

| Result | Meaning |
| --- | --- |
| `APPLIED` | This call applied the exact requested mutation. |
| `UNCHANGED_REPLAY` | The stored record is already the exact single-generation successor, including target state, error, and reservation identity where applicable. |
| `STALE` | A valid request did not match the current state or either expected generation. The caller must read again before deciding what to do. |
| `ILLEGAL_TRANSITION` | The edge, error combination, reservation precondition, uniqueness rule, or generation bound forbids the request. Retrying unchanged cannot make it legal. |
| `NOT_FOUND` | The valid authority key does not exist. |

Invalid identifiers, enum values, or numeric ranges are API errors rather than
mutation results. A statically illegal known edge is reported as illegal
without consulting mutable database state. For a valid edge, exact replay is
recognized before stale classification; a matching current state that cannot
advance because of overflow is illegal. No failed outcome partially changes
identity, state, error, or generations.

## Linearization, transactions, and lock order

The per-store recursive `graph_authority_mutex` is acquired before starting an
authority mutation and held through its conditional update, classification,
and commit or rollback. Typed authority reads and lists, plus the compatibility
tenant/graph writers that touch these rows, use the same mutex. No authority
operation acquires a service-domain, service-lifecycle, or CVK mutex while it
is held. Code that must combine domains must therefore complete those other
operations before acquiring graph authority, or use an explicitly reviewed
higher-level transaction that does not invert this order.

On an autocommit connection the mutation uses `BEGIN IMMEDIATE`. The write lock
is therefore the cross-connection linearization boundary, and a competing
writer receives `WYRELOG_E_BUSY` for bounded retry. The update and any result
classification read occur under that same writer lock. Unexpected constraint
failures fail closed as policy errors rather than being treated as CAS misses.

If a caller already owns a transaction on the same connection, the authority
mutation uses a nested savepoint. `APPLIED` then means applied to the
caller-owned transaction, not durably committed; the caller can still roll it
back. Releasing the savepoint must leave the outer transaction active. Such a
caller owns same-handle serialization for every unrelated policy mutation in
that outer transaction. #537 serializes authority APIs and compatibility
tenant/graph writes, but it does not retrofit the graph mutex onto every
unrelated policy-store API.

Cleanup errors take precedence over body or commit errors. A caller must not
continue using an uncertain transaction as if rollback or savepoint release
had succeeded.

## Crash recovery and newer formats

The durable policy row, not the physical file, chooses the next recovery
action:

| Durable evidence | Recovery decision |
| --- | --- |
| `LEGACY_UNCLASSIFIED` | Do not automatically open or adopt a graph-local store. Graph reservation must first establish the complete identity and enter `PROVISIONING`; no graph reconciliation edge leaves this state. |
| `PROVISIONING` | The provisioning coordinator inspects the reserved UUID and versions, then idempotently completes creation or degrades the same record. It never allocates a replacement identity for the reservation. |
| `ACTIVE` | Runtime code may consider opening only after the later path, identity, format, schema, and engine-ownership checks all succeed. Authority state alone is necessary but not sufficient. |
| `SEALED` | Do not open for normal work. Later lifecycle code owns drain and eviction proof. |
| `DEGRADED` | Do not open or write. Reconciliation inspects the physical evidence and either performs the one legal recovery CAS or leaves the sanitized error class intact. |

When a physical store's format or path-encoding version is newer than the
running binary supports, the process must not open it for writes, downgrade it,
rewrite its identity, or guess a compatible layout. The lifecycle owner records
`FORMAT` (or `PATH` for an unsupported path encoding) through a legal degrade
transition. Reconciliation remains the only owner of recovery after compatible
software is installed. Older supported formats may be upgraded only by a later
explicitly versioned workflow; #537 authorizes no implicit file migration.

SQLite busy/locked results are retryable transport contention, not evidence of
failed provisioning or degradation. Callers retry with bounded backoff and
then reread authority. A lost response is retried with the identical expected
tuple so it becomes either exact replay or stale; it must not allocate another
UUID.

## Migration and failure behavior

Fresh DDL and legacy upgrade run inside one
`SAVEPOINT wyrelog_graph_authority_schema`. The migration validates exact
columns and constraints, the partial UUID index, invariant triggers, and all
pre-existing rows before release. Any injected or organic failure rolls the
whole authority migration back, including fresh tables, so close/reopen/retry
starts from a coherent schema. Existing rows retain their legacy metadata and
are never inferred active.

Runtime mutation tests expose one-shot checkpoints immediately after the
conditional update and immediately before transaction finish. A checkpoint
failure is an I/O failure and rolls the authority savepoint or owned
transaction back. When nested in a caller transaction, rollback is limited to
the authority savepoint: prior caller work and the outer transaction remain
intact. These seams are private test/coordinator infrastructure and do not
alter production result classification.

## Consequences

The control plane now has one typed, durable source of truth and deterministic
CAS outcomes suitable for later per-graph physical storage work. Concurrency,
lost responses, crashes, and unsupported formats fail closed without identity
replacement or partial metadata updates.

Canonical path derivation and fail-closed POSIX and Windows resolution are now
available, and runtime fact operations no longer trust registry paths. Physical
identity reservation, descriptor-bound DuckDB provisioning/open, runtime engine
ownership, tenant drain barriers, API exposure, deletion, retirement, ID reuse,
and purge remain follow-up work. This ADR deliberately grants none of those
operations authority merely because a policy row or canonical directory
exists.
