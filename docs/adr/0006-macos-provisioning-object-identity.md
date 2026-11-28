# ADR 0006: macOS Provisioning Object Identity Contract

Status: accepted

Related issues: #921, #923

## Context

Secure graph provisioning publishes a held staging object as
`facts.duckdb`. Linux can hard-link the held descriptor through
`/proc/self/fd`, retain the operation-derived stage name, and later prove that
the stage and final names still resolve to one inode at `nlink == 2`. Darwin
has no public `linkat` equivalent to Linux `AT_EMPTY_PATH`. Linking or renaming
a stage pathname after validating its descriptor would therefore reopen a
same-UID namespace substitution race.

The original macOS candidate paired `ATTR_VOL_UUID` with
`ATTR_CMN_OBJPERMANENTID`. That candidate is invalid for the hosted APFS class:
XNU documents that when `VOL_CAP_FMT_64BIT_OBJECT_IDS` is set,
`ATTR_CMN_FILEID` and `ATTR_CMN_PARENTID` are the only legitimate object-ID
attributes and the 32-bit fields returned by `ATTR_CMN_OBJPERMANENTID` are
undefined.

XNU also documents a stronger capability,
`VOL_CAP_FMT_PATH_FROM_ID`: a volume setting that bit has persistent object IDs
which are not recycled. This is the authoritative lifetime guarantee needed
to compare a descriptor captured before a restart with a descriptor opened
after it. A runtime observation cannot prove non-reuse, so the capability bit
is a mandatory semantic gate rather than an optimization.

The public contracts used by this decision are:

- [XNU `attr.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/attr.h), including the format-capability semantics and the 64-bit object-ID selection rule;
- [Darwin `getattrlist(2)`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getattrlist.2), including descriptor queries, returned-attribute reporting, attribute ordering, `ATTR_CMN_FILEID`, and `ATTR_VOL_UUID`.

## Decision

macOS provisioning may eventually use durable object evidence only on an APFS
volume whose descriptor reports `f_fstypename == "apfs"` and the `MNT_LOCAL`
mount flag. The volume must also satisfy every condition below at the time
evidence is captured and every time it is compared:

1. `ATTR_CMN_RETURNED_ATTRS` confirms every requested attribute was returned.
2. `ATTR_VOL_CAPABILITIES` marks both required capability bits valid and set:
   `VOL_CAP_FMT_64BIT_OBJECT_IDS` and `VOL_CAP_FMT_PATH_FROM_ID`.
3. `ATTR_VOL_UUID` is returned and is not the all-zero UUID.
4. `ATTR_CMN_FILEID` is returned for the held graph directory and held
   artifact descriptors, both IDs are nonzero, and the IDs are distinct.
5. The graph directory and artifact report the same volume UUID.

`VOL_CAP_FMT_PATH_FROM_ID` is consumed only for its documented persistence and
non-recycling guarantee. The runtime must not treat `/.vol`, a derived path, or
an ID-to-path API as authority. Recovery derives the canonical graph directory
from the configured fact root and logical identifiers, opens each component
through held directory descriptors, opens `facts.duckdb` relative to the held
graph descriptor, and compares evidence captured from those descriptors.

Non-APFS and non-local mounts, volumes without either capability, volumes which
omit a requested attribute, 32-bit object-ID volumes, zero or malformed
values, and cross-volume graph/artifact pairs fail closed. There is no
`ATTR_CMN_OBJPERMANENTID` fallback in evidence version 1.

The threat model covers unprivileged and same-UID namespace replacement within
one locally mounted APFS volume. It does not claim rollback resistance against
an actor able to clone, attach, or substitute a block-level volume while
preserving its filesystem UUID, object IDs, and store contents. Such an actor
already controls storage below the descriptor-relative namespace boundary.
Operators must not mount a duplicated volume UUID at the configured fact root;
trusted mount provenance and anti-rollback storage are separate controls.

This decision defines a platform contract. It does not by itself enable macOS
provisioning or change the current Linux or Windows runtime. The policy-store
columns that hold the evidence are added by the persistence work that
implements it: the provisioning row's column, and the restore replacement's
column described in the last section.

## Evidence version 1

The durable value is exactly 56 bytes. Integers use unsigned big-endian byte
order. UUIDs use the 16 RFC 4122/9562 network-order bytes, not a Darwin native
structure or textual spelling.

| Offset | Size | Field | Required value |
| ---: | ---: | --- | --- |
| 0 | 4 | `version` | `1` |
| 4 | 4 | `identity_kind` | `1` (`darwin-fileid64`) |
| 8 | 16 | `operation_uuid` | Canonical UUIDv7 bytes |
| 24 | 16 | `volume_uuid` | Nonzero filesystem UUID |
| 40 | 8 | `graph_file_id` | Nonzero `ATTR_CMN_FILEID` |
| 48 | 8 | `artifact_file_id` | Nonzero `ATTR_CMN_FILEID`, unequal to `graph_file_id` |

The operation UUID must have version nibble 7 and RFC variant bits `10`. It
binds the evidence to the durable provisioning operation in the same way as
the Windows operation-evidence tuple; a filesystem identity alone cannot be
relabelled as another operation. Decoders require the exact length and reject
trailing bytes, unknown versions or kinds, invalid UUID version or variant,
zero UUIDs or IDs, and equal graph/artifact IDs before performing filesystem
work.

The one volume UUID applies to both object IDs. Capture commits no evidence
unless independently queried graph and artifact descriptors return that exact
UUID. Reopen compares both descriptors against the same stored UUID and then
compares their individual file IDs.

Native `attribute_set_t`, `uuid_t`, structure padding, and host endianness
never enter durable storage. The future locator-private implementation owns
capture, encoding, strict decoding, and comparison. Policy storage owns only
the opaque versioned bytes; provisioning and DuckDB code must not inspect
Darwin attribute structures.

## Namespace and comparison protocol

The future implementation must maintain these boundaries:

- Create an absent final only with descriptor-relative
  `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` through the validated graph
  directory. A pathname validated earlier is never a creation capability.
- Capture the graph and artifact IDs from held descriptors with
  `fgetattrlist`. Revalidate the full root, tenant, and graph chain around each
  irreversible step.
- On recovery, reopen the canonical graph chain and `facts.duckdb` or, after
  a restore's `RETAIN`, that restore's operation-derived rollback name (see
  "Restore witness"); compare descriptor-derived volume, graph, and artifact
  evidence. Never search for an object by ID and never accept any other name
  which happens to expose the expected ID.
- Require exact owner, type, mode, chain identity, operation UUID, evidence,
  and secure DuckDB identity together. Evidence is necessary but not
  sufficient authority.
- Refuse partial, malformed, unsupported, absent, foreign, cross-volume, or
  mismatched evidence without mutation.

## Durability and crash states

The existing provisioning phases keep one sequence but have Darwin-specific
evidence meanings:

| Phase | Darwin meaning |
| --- | --- |
| `RESERVED` | The durable operation exists. The final may be absent, or a crash may have left a final with no evidence. Exact evidence may have committed before the phase CAS. |
| `STAGED` | The complete evidence is durable and was re-read exactly; the direct final and graph directory were synced. No stage pathname is implied. |
| `PUBLISHED` | A canonical reopen through the held graph chain matched the durable evidence. Secure DuckDB identity may still be absent. |
| `VERIFIED` | Secure identity initialization/validation and a final canonical evidence comparison both succeeded. |
| `ACTIVE` | Policy authority admits consumers; every open still revalidates chain, evidence, and secure identity. |

Future runtime work must preserve this ordering:

1. Persist the complete `RESERVED` provisioning operation.
2. Create the absent final through the held graph directory with exclusive,
   no-follow semantics.
3. Initialize bytes required before exposure, sync the artifact, and capture
   graph/artifact evidence from the still-held descriptors.
4. Revalidate the complete directory chain and both descriptors, then sync the
   graph directory so final-name creation is durable.
5. Commit the complete 56-byte evidence atomically to the `RESERVED` operation.
   Re-read it exactly, then advance `RESERVED` to `STAGED`.
6. Canonically reopen the graph and final through the held chain, compare the
   complete evidence, and advance `STAGED` to `PUBLISHED`.
7. Initialize and durably validate the exact secure DuckDB store identity.
   Canonically reopen and compare evidence again before advancing `PUBLISHED`
   to `VERIFIED`.
8. Revalidate the chain, evidence, and secure identity at the admission
   boundary, then advance `VERIFIED` to `ACTIVE`.

Every consumer requires `ACTIVE` plus an exact evidence and store-identity
match. A visible file in any earlier phase has no read or write authority.

| Durable observation | Required recovery result |
| --- | --- |
| `RESERVED`, no final, no evidence | Exclusive final creation may start. |
| Final exists, evidence absent | Never adopt, delete, overwrite, or initialize automatically; fail closed for operator disposition. |
| Evidence exists, final absent | Fail closed and degrade; evidence cannot create or select a replacement. |
| Evidence partial, malformed, unsupported, cross-volume, or mismatched | Fail closed without filesystem or policy mutation. |
| `RESERVED`, final and evidence exact | Re-read evidence and advance to `STAGED`; the next rule owns canonical publication comparison. Do not initialize secure identity yet. |
| `STAGED`, final and evidence exact | Canonically compare and advance to `PUBLISHED`. |
| `PUBLISHED`, evidence exact, secure identity absent | Eligible only for bounded identity initialization; not active authority. |
| `PUBLISHED`, secure identity partial or foreign | Fail closed; never repair or adopt. |
| `PUBLISHED`, evidence and secure identity exact | Canonically revalidate both and advance to `VERIFIED` idempotently. |
| `VERIFIED`, evidence and secure identity exact | Revalidate at admission and advance to `ACTIVE` idempotently. |
| `ACTIVE` with any chain, evidence, or secure identity mismatch | Refuse open and require explicit remediation; never replace automatically. |

The unavoidable final-created/evidence-absent seam is intentionally a safe
operational wedge. Reopening the name and minting evidence after the held
descriptor was lost would adopt an object that could have been substituted.
Automatic unlink has the symmetric pathname race and is also forbidden.

## Consequences

Hosted macOS tests characterize the runner volume by checking APFS and
`MNT_LOCAL`, the required capability and returned-attribute masks, descriptor
stability after closing and reopening, rename and process boundaries, and
mismatch after deletion and replacement. That probe shows the runner supplies
the contract; it does not prove the XNU lifetime semantics, behavior on every
macOS filesystem, or privileged block-volume provenance. The authoritative
capability contract supplies persistence and non-reuse, and unsupported
environments remain closed.

Follow-up implementation must add the strict codec, atomic policy persistence,
locator-private capture/comparison, coordinator recovery, and secure bridge
integration before #921 can restore macOS provisioning runtime tests. Linux
retains its same-inode `nlink == 2` pair, and Windows retains its existing
operation-bound volume/file evidence unchanged.

## Restore witness

A restore proves the old provisioned main before it binds a journal to it.
Linux proves that object through its second name, the provisioning companion
at link count two. On macOS the final has one link under the canonical name,
so the restore witness holds a descriptor on `facts.duckdb` opened through
the validated graph chain and, on every revalidation, compares the
descriptor-derived evidence with the provisioning evidence together with the
journal-pinned device and inode, mode, owner, link count one and the absence
of the legacy stage name.

Before `RETAIN` the witness holds `facts.duckdb`. After it, the witness holds
the old main at the restore operation's rollback name,
`restore-<operation>.duckdb.superseded`. Three of the reasons given under
"Windows rollback name" transfer unchanged. The name is derived from the
restore's canonical UUID, and nothing is looked up by its ID. The object has
one link, so while it is at the rollback name it is at no other name, and a
second link anywhere refuses the witness. Identity is compared through a held
descriptor, whose volume, graph and artifact evidence a rename cannot change.
Every revalidation runs the descriptor evidence, device, inode, mode, owner
and legacy-stage checks twice, and requires `facts.duckdb` to be absent or a
different one-link regular file with mode 0600 and the effective owner. The
inequality with the old object is load-bearing: a rename of the rollback name
onto `facts.duckdb` between the two name lookups keeps one link, and within a
pass only that comparison refuses it.

One Windows reason does not transfer. macOS checks the rollback name by a
lookup of that name, not by a correlated capture of the whole directory, and
the restore volume is usually case-insensitive. A case variant of the rollback
name is therefore the same directory entry the volume's own lookup resolves,
exactly as for the restore stage; it cannot name a different object, because
the entry and the held descriptor are the same object.

As on Windows, acceptance does not prove that `RETAIN` moved the object. The
owner, or root, can rename the evidenced main to that name under the
owner-only graph directory. That moves nothing the evidence does not already
name, so it grants no integrity the owner lacks, and the journal, not the
slot, records that `RETAIN` ran. The dual-companion witness has no macOS
meaning and stays refused.

The transition model is not told that the witness ran: a one-link old main,
at either name, is its ordinary shape, and the proof is the successful witness
call in the restore path, which must therefore use the evidence form of the
capture and of the execute.

## Windows rollback name

Windows accepts the `RETAINED_ROLLBACK` slot, and macOS accepts it under the
reasons that transfer (see "Restore witness"). Like a macOS main, a provisioned
Windows main has one link and is proved by its operation evidence, so the same
comparison rule applies: the evidenced object is never found by its ID, and a
name merely exposing the expected ID is not proof. The rollback name is
accepted because acceptance rests on the object and on a name the operation
fixes, not on a name that was searched for:

- The name is `restore-<operation>.duckdb.superseded`, derived from the
  restore operation's canonical UUID. The transition provider opens nothing
  else in that slot and never looks an object up by its ID.
- The object has one link, so while it is at the rollback name it is at no
  other name; a second link anywhere refuses the step.
- Every acceptance compares, from one correlated capture of the whole graph
  directory, the volume and FileId with the evidence and the request, with
  link count one, no reparse point and the conforming owner-only ACL. Case
  aliases, delete-pending entries and unknown names fail the capture's
  inventory, and the provider refuses any name component with a stream
  separator.

Acceptance does not prove how the object reached the rollback name. Only the
operation's own `RETAIN` is meant to move it there, by a no-replace rename of
the authorized, FileId-pinned main relative to the held graph directory
handle, but the owner-only graph DACL keeps out only other, non-administrative
principals (ADR 0005): a process running as the owner, an administrator, or a
holder of the backup and restore privileges can rename the evidenced main to
that name itself. That moves nothing the evidence does not already name, so it
grants no integrity the owner lacks; it does mean the slot is not evidence
that `RETAIN` was applied, and the journal, not the slot, is what records it.

So the evidence form of the provisioned capture and execute admit
`RETAINED_ROLLBACK` on Windows and authorize only the steps that follow
`RETAIN` (`SYNC_ROLLBACK_FILE`, `SYNC_RETAIN_DIR`, `PUBLISH`,
`SYNC_PUBLISH_DIR`, `ROLLBACK`) and `SYNC_STAGED`. The transition machine
holds durability only in memory, so a transition admitted afresh after
`RETAIN`, as each restarted commit step's is, flushes the stage again before
the steps that follow; the stage it flushes must be the request's staged main.
Every one of them renames onto an absent name
or flushes; `FINALIZE`, the only delete, stays refused for a provisioned main
until the provisioning record's cleanup is journaled. That is the transition
machine's `FINALIZE` operation, and it stays refused on macOS too: a
selected restore's cleanup is a locator path of its own (see "Restore
replacement evidence"), not that operation. `PUBLISH` re-pins the
stage it moves, not the object at the rollback name, so a caller must
recapture and reauthorize before each step rather than reuse an authorization
across a restart. macOS adopts this reasoning for its restore witness,
capture and evidence execute (see "macOS evidence execute").

A committed Windows graph restore therefore runs from the stage sync through
`RETAIN`, the rollback-side flushes, `PUBLISH` and the directory flush, and
stops at `PUBLISHED_DURABLE` with `FINALIZE` next. What follows on Linux stays
refused on Windows. Selection, `FINALIZE` and promotion retire or replace the
old main's provisioning record, and a Windows replacement main has no
operation evidence of its own yet: the capture below is the macOS form, and
nothing mints Windows evidence for the object `PUBLISH` placed at the main
name. Companion recovery rebuilds the Linux companion link, which a Windows
main does not have. Commit admission is refused on Windows as
well, until the replay-validation session it requires runs there, and it must
stay refused until the steps after `PUBLISHED_DURABLE` exist, so that no
decided restore is left with no way to finish. Until then a Windows graph
restore can be rolled back before commit but not committed, and the committed
steps above are proved by tests that reach the decision directly; tenant-scope
restores stay refused throughout.

## macOS evidence execute

The macOS evidence execute takes the active provisioning UUID and its stored
evidence, the pair the capture took. It infers the slot from where the
request's expected main sits in the authorized observation: one link under
`facts.duckdb` is `READY_MAIN`, and one link under this restore's rollback
name is `RETAINED_ROLLBACK`. The step list for each slot and the provenance
rule are the Windows ones: the observation is unmarked, directory and lease
are the request's, any stage is the request's staged main, and after `RETAIN`
any main is the request's staged main too.

Unlike Windows, which reopens no witness, the macOS execute reopens the
evidence witness for that slot and revalidates it before the public execute.
Darwin evidence is compared through a held descriptor and name lookups, not as
a value from a correlated directory capture, so the observation alone does not
bind the object. The public execute then revalidates authority and re-pins the
source by device, inode, link count one, mode and owner. The witness stays open
across that call, so its held descriptor keeps the old inode from being
recycled and a reused inode cannot satisfy the re-pin. A call refused before
the public execute touches nothing and reports `UNKNOWN`. `PUBLISH` and the
directory flushes pin no file at the rollback name; the witness pass just
before is what covers it, the residual Windows also accepts.

The public execute accepts the same unmarked one-link observation without
that proof, so the commit path must call the evidence form. Each commit step
names the provisioned capture and execute only through two helpers of the
commit authority, which on macOS call the evidence capture and the evidence
execute with the step's provenance: the operation UUID of the graph's single
`ACTIVE` provisioning record, which must be the journal's old provisioning
operation on the row's store, and that record's stored evidence, decoded
against the same UUID. Missing or malformed evidence, and evidence bound to
another operation, are refused before the provider opens and before any
journal change. Evidence that names another object is refused by the evidence
witness in the provider's capture, before the step's effect. The stage sync
captures before it journals its attempt, so there the refusal comes before
any journal change; `RETAIN`, the rollback-side syncs, `PUBLISH` and its
directory flush journal their attempt as `UNKNOWN` first, and that attempt
then refuses the same way.
`tests/test-darwin-restore-bind-wiring.py` pins the bind, both helpers, the
provenance decode and the routing of each ported step through the helpers.
The stage sync, `RETAIN`, the two rollback-side syncs (`SYNC_ROLLBACK_FILE`,
then `SYNC_RETAIN_DIR`), `PUBLISH` and its directory flush
(`SYNC_PUBLISH_DIR`) run on macOS from a decided journal, and the resume
dispatcher runs them in turn. After `RETAIN` each step re-proves the old main
at this restore's rollback name through the same evidence witness, so a
same-bytes object there, or evidence that names another volume, is refused.
`PUBLISH` renames the stage it re-pins by the journal's device and inode onto
`facts.duckdb` without replacing (`renameatx_np` with `RENAME_EXCL`): an
object already at `facts.duckdb` is refused before the rename, and one placed
there after the capture fails the no-replace rename. Until replacement
evidence exists (see "Restore replacement evidence") no evidence names the
object at `facts.duckdb`: the witness accepts there any one-link 0600 file of
the effective owner other than the old main, and only the journal-pinned
staged identity binds it, so a same-bytes substitute is refused by the
transition model rather than by evidence. Once the companion step persists
the replacement evidence, its compare form names that object too. The
evidence execute stops at `PUBLISHED_DURABLE` with `FINALIZE` next. The
companion step (see "Restore replacement evidence") then binds the replacement
evidence and advances the replacement row, and selection (see "Restore
replacement evidence") then takes the restore to `selected_pending_cleanup`,
and `FINALIZE` (see "Restore replacement evidence") then takes it to
`FINALIZED`, which the terminal proof (see "Restore replacement evidence")
proves, and promotion (see "Restore replacement evidence") then commits it,
which the published proof resolves after a lost response. The select resume
dispatcher drives the companion step and selection and replays a selected
restore; the `FINALIZE` resume dispatcher finalizes a selected restore and
proves it terminal; the promote resume dispatcher promotes a finalized
restore and answers its replay from the receipt; `RETIRE_STAGE` still
refuses. Since #1303 U5-16 the daemon's commit handler binds and admits a
macOS graph restore (see "Commit admission (macOS)") and its resume handler
drives these steps to the committed receipt. The per-step tests still reach
the decision directly, and the companion step, selection, the select resume
dispatcher, `FINALIZE`, the `FINALIZE` resume dispatcher, the terminal proof,
promotion, the published proof and the promote resume dispatcher are proved
by tests that call them directly; `daemon-macos-commit/*` and
`macos/commit-admit-*` in `tests/test-fact-offline-backup-source.c` cover
the operator path.

## Commit admission (macOS)

macOS graph commit admission
(`wyl_fact_offline_restore_graph_commit_admit_run`, #1303 U5-16) is the
Linux function opened in place: only its Windows gate remains, and the
daemon's commit handler (`wyrelog/daemon/http.c`) no longer refuses before
the bind. `commit` binds the prepared journal through the restore witness
(see "Restore witness"), then admits it. Admission's validation session
opens the pair through the `ACTIVE` record's evidence
(`offline-restore-validation-session-private.c`), so the device and inode
compare of its inventory is anchored to a descriptor the evidence proved,
not accepted by identity alone. It replays the stage inside the scheduler.
It then reserves the replacement row in its own write, and decides `COMMIT`
in one guarded write whose proof re-inventories the pair opened from
evidence. A refusal after the reservation leaves the row `reserved`, and a
retried admission accepts that row as `UNCHANGED_REPLAY`. A lost response
of the guarded write is accepted only as the exact canonical successor.
After the decision abort is barred (403, at the handler and at
`wyl_fact_offline_restore_rollback_recover_run` alike), and resume is the
only forward action; the daemon then answers `committing` at the bound
revision plus one, and resume answers `committed` at the selected revision
plus four.

The proof's closed-admission check runs while the session holds the
graph's quiescence token, which closes admission for as long as it is held,
so a runtime entry that was `OPEN` before admission does not stop it: the
proof decides, and releasing the token restores `OPEN`
(`macos/commit-admit-runtime-open`). The same holds on Linux, where the
code is shared. If admission left a reservation without deciding COMMIT,
rollback can retire the stage and release the reservation with an aborted
receipt. Linux and macOS regression tests cover a persistent refusal at
the admission proof and a retry of interrupted release (#1570).

Tenant-scope commit stays refused on macOS. The daemon now reaches
`wyl_fact_offline_restore_tenant_bind_all_provisioned_old_run`, which
refuses on every host but Linux before it reads the journal, so a tenant
commit still answers 403 with the journal byte-identical, and tenant
admission refuses on macOS and Windows as well. Tenant resume refuses on
macOS. `tests/test-darwin-restore-bind-wiring.py` pins both gates
(E_TENANT_BIND_ALL_GATE, E_TENANT_ADMIT_GATE), and lifting either is #1303
U6. Windows still refuses commit, at the handler and at admission (#1304).
The `G_OS_WIN32` blocks in `wyrelog/daemon/http.c` and
`wyrelog/fact/offline-restore-prepare-private.c` keep comments that still
name macOS, because the Windows view of both files stays byte-identical;
#1304 rewrites them. The guard pins the handler's gate, its bind-before-admit
order and the absence of any `__APPLE__` in `http.c`, and graph admission's
gate (E_HTTP_COMMIT_GATE, E_HTTP_COMMIT_ORDER, E_HTTP_NO_APPLE,
E_GRAPH_ADMIT_GATE).

## Restore replacement evidence

A committed graph restore makes the published restore stage the graph's new
main. After promotion its replacement provisioning row is the `ACTIVE` row, so
on macOS it must carry version 1 evidence bound to the replacement UUID; store
open, backup and a later restore read only that row. The stage is not created
by the provisioning protocol above: the restore creates
`restore-<operation>.duckdb` exclusively through the held graph directory,
records its device and inode, logical size and checksum in the journal before
`RETAIN`, and `PUBLISH` renames that object onto `facts.duckdb`. For a restore
stage the journal pin stands in for the creation descriptor that step 3 of the
provisioning order requires.

Evidence is therefore captured after `SYNC_PUBLISH_DIR`, by reopening
`facts.duckdb` through the held graph chain, and is accepted only when that
descriptor shows the journal's device and inode, the journal's logical size
and checksum, link count one, mode 0600 and the effective owner, with the
replacement's legacy stage name, `provision-<replacement>.sqlite`, absent. A
mismatch fails closed for operator disposition; nothing is minted for an
object the journal does not name. The state is the same final-exists,
evidence-absent seam as above, and it is resolved by the journal pin rather
than refused. That departs from the provisioning rule deliberately: a live
device and inode name exactly one object, APFS does not recycle file IDs while
`ATTR_CMN_FILEID` lookup remains valid, and the full checksum re-read goes
through the same descriptor whose identity is compared. The re-read costs one
full read of the main.

The device number is not durable identity: it only has to match within the
restore that recorded it. A remount or reboot after the restore binds its
journal can change it. Every later step compares the journal's device and
inode, both the restore witness on each revalidation and this capture, so each
refuses rather than weakening the comparison, and the restore is an operator
wedge, not a retry. Once captured, the volume UUID and `ATTR_CMN_FILEID` pair
is the durable identity, under the same capability gate as provisioning.

The evidence commits write-once to the `reserved` replacement row and is
re-read before the row advances. The schema cannot require evidence, because
Linux and Windows replacement rows carry none, so the order is an obligation
of the macOS commit path: on macOS the replacement row must not advance to
`companion_synced` until its evidence is durable and re-read, and a selection
whose replacement row carries no evidence is refused. Policy enforces both
on macOS before any effect or write: it refuses to advance a replacement row
to `companion_synced` without evidence, even as a replay of a row that
advanced before the evidence column existed, and it refuses such a
selection. Selection copies the row's
evidence into the `restore_selected` provisioning row in the same
transaction, the replacement row's selection update refuses a missing or
different copy, and promotion's phase update keeps the evidence column, so
the `ACTIVE` record carries the replacement's version 1 evidence bound to
the replacement UUID. Store open, backup, unseal and a later restore read
that record. Policy keeps the envelope
opaque throughout; the caller decodes it against the replacement UUID before
persisting it. The provisioning insert guard names only replacement columns
that every released replacement table has, so no trigger refers to the new
column before a migration creates it.

The macOS companion step is the step after `PUBLISHED_DURABLE` that Linux
spends on the replacement companion link; on macOS it binds the replacement
evidence instead. It first
proves the published namespace under the root writer lease and quiescence:
the graph directory holds exactly `facts.duckdb`, this restore's rollback
name and at most `facts.duckdb.lock`, each a one-link 0600 regular file of
the effective owner, and no stage, no provisioning legacy name and nothing
else. The old main is proved at the rollback name by the old `ACTIVE`
record's evidence through the restore witness; the new main is proved by the
journal's device, inode and logical size. Names are matched byte for byte,
so a case variant of the main or the lock on a case-insensitive volume fails
closed as an unlisted name. Then, only while the `reserved` row has no
evidence, the step captures it, persists it write-once and re-reads the row;
on both paths it compares the stored evidence through a fresh descriptor
and advances the row inside the policy transaction, whose effect re-proves
the namespace and requires the row's evidence to be the bytes it compared.
macOS has no companion link and no dual layout: the row's evidence is the
discriminator Linux takes from its companion link. Every locator refusal
after `SYNC_PUBLISH_DIR`, absence and busy included, is a policy refusal:
an operator wedge, never a retry.

The macOS selection step takes a `companion_synced` replacement row to
`selected_pending_cleanup`. Under the root writer lease and quiescence it
refuses a row without evidence before it reads the old evidence, the
namespace or the main. It then loads the old `ACTIVE` record's evidence,
proves the published namespace as the companion step does, compares the
stored replacement evidence through a fresh descriptor and selects in one
policy transaction. The transaction's effect proves the namespace again,
including the old main at the rollback name by the old evidence, and
requires the row's evidence to be the bytes it compared. The store copies
that evidence into the `restore_selected` record, deletes the old `ACTIVE`
record and advances the row. The old evidence is write-once, by the
provisioning immutable trigger, so the copy the step loads under the lease
is the record's value when the transaction commits. Every locator refusal is
a policy refusal.

Selection deletes the only record that holds the old main's evidence, yet
`FINALIZE` still has to prove that object before it unlinks the rollback
name. The old evidence is a function of values that outlive the record: the
journal's old provisioning operation and old main file ID, and the volume
UUID and graph directory file ID, which the replacement evidence shares
because both were taken from the same held graph directory. Selection checks
that premise while it still can: it rebuilds the old evidence from those
values and refuses unless the result equals the stored bytes of the record
it is about to delete.

The macOS select resume dispatcher
(`wyl_fact_offline_restore_graph_commit_select_resume_run`, #1303 U5-13)
shares its loop with Linux. From `PUBLISHED_DURABLE` it runs the companion
step for a `reserved` row and selection for a `companion_synced` one, each
the public step above, and then replays the selected journal; on a selected
journal it only replays. The replay is read-only under its own root writer
lease and quiescence, and copies the authority checks of the Linux replay:
a journal or row other than the one the loop loaded is stale (`BUSY`). It
refuses a row without evidence before the graph is opened, rebuilds the old
main's evidence from the `restore_selected` record and requires `DUAL`:
`TERMINAL` with a fresh selected journal, which only `FINALIZE` leaves, is an
operator wedge. `DUAL` proves the new main by device, inode and logical size
only, so the replay compares the stored replacement evidence through a fresh
descriptor, and a journal or row changed during that compare gives `BUSY`.
Every locator refusal is a policy refusal. A stale revision is `BUSY`;
`FINALIZE` pending or `FINALIZED` is `POLICY`, as on Linux. A remount or
reboot after selection changes the device number the witness compares, so
the replay then refuses as an operator wedge (`POLICY`). The loop is shared,
so a call from a `reserved` row reads the main four times: the companion
step's capture and compare, selection's compare and the replay's compare,
which right after a selection in the same call proves again what selection
just compared.

The macOS `FINALIZE` step takes a `selected_pending_cleanup` restore to
`FINALIZED`. Under the root writer lease and quiescence, with the journal
predicate of the Linux step, it refuses a row without evidence before it
reads the old evidence, the namespace or the main. It loads the
`restore_selected` record, which must be the graph's only record and carry
the row's evidence, and rebuilds the old evidence from it with the journal's
old provisioning operation and old main file ID. Inside each `FINALIZE`
transaction the store's selection postcondition
(`restore_selection_postcondition_locked` in `wyrelog/policy/store.c`)
requires the `restore_selected` record's evidence to be the row's, and the
row is immutable in `selected_pending_cleanup`, so the bytes loaded under the
lease are the bytes the transaction commits against. The cleanup namespace
has two accepted shapes and no partial one, as there is no companion link.
`DUAL` is the published namespace the companion step proves, the old main at
the rollback name proved by the rebuilt evidence through the same
`RETAINED_ROLLBACK` evidence witness. `TERMINAL` is that namespace without the
rollback name: the new main by the journal's device, inode and logical size,
at most a lock that is not the old main, and nothing else. The capability gate
is the one every step before it passes: the witness compares the rebuilt
evidence through the held descriptor's volume UUID and file ID, and the
replacement compare runs the volume preflight. No step proves the rollback
object by its device and inode alone.

A fresh `FINALIZE` requires `DUAL`. It compares the stored replacement
evidence through a fresh descriptor, the only proof of the new main's bytes
and evidence on either shape, journals the attempt (`FINALIZE` pending) and
then, in one policy transaction, requires the row's evidence to be the bytes
it compared, opens the witness on the old main, revalidates it, unlinks the
rollback name, flushes the directory, proves `TERMINAL` and CASes
`FINALIZED`. The acceptance criterion of `FINALIZE` is one rule on every
call: a `TERMINAL` proof of the graph directory, so the old main has no name
left there. After the unlink the step also refuses if the held,
evidence-proved object still has a link. That check detects interference
during this call only (a same-user actor swapping, linking or removing the
rollback name after the last revalidation); it is not a guarantee that the
old main is gone, and it does not claim that the removed name was that
object. A pending `FINALIZE`, which only a durable begin from `DUAL`
produces, also accepts `TERMINAL`, and so does the transaction of a fresh
call, as on Linux. A failure after the unlink rolls back the CAS but not the
unlink, leaving `TERMINAL` with `FINALIZE` pending, and the next call
finalizes from it if its `TERMINAL` proof holds. So after an interfered call
the retry can finalize with the old main surviving outside the graph
directory; a second name inside the directory fails that proof instead and
is an operator wedge. Every other locator refusal is a policy refusal. A
remount or reboot between selection and `FINALIZE` changes the device number
the witness and the `TERMINAL` inventory compare, so `FINALIZE` then refuses
as an operator wedge, the liveness every step after `RETAIN` already has;
after the unlink and before the CAS it makes the `TERMINAL` retry such a
wedge.

The macOS terminal proof
(`wyl_fact_offline_restore_graph_commit_finalized_prove_terminal`) is
read-only under the root writer lease and quiescence. The caller's
`FINALIZED` journal must equal the stored journal byte for byte; any other
journal is stale and gives `BUSY`. A row that disagrees with the journal
gives `POLICY`, and a row without evidence is refused before the graph is
opened. The proof rebuilds the old main's evidence from the
`restore_selected` record, which must carry the row's evidence; that load's
store errors pass through unmapped and its mismatches are `POLICY`. It requires
`TERMINAL`: `DUAL`, including the old main proved back at the rollback name,
is an operator wedge, and so is the old main at the lock. `TERMINAL` proves
the new main by device, inode and logical size only, so the proof compares
the stored replacement evidence through a fresh descriptor, the only proof
of the new main's bytes. Every locator refusal is a policy refusal. A change
of the journal or the row between the reads
(`check_finalized_persisted`) gives `BUSY`. A remount or reboot after
`FINALIZE` changes the device number the `TERMINAL` inventory compares, so
the proof then refuses as an operator wedge (`POLICY`). For a `HANDOFF` graph
journal with a `COMMIT` decision, from commit admission or a direct call,
the daemon's resume handler on macOS takes the restore through the
remaining commit steps, the companion step and selection, deleting the old
`ACTIVE` record, through the `FINALIZE` resume dispatcher to `FINALIZED`,
unlinking the rollback name, and through the promote resume dispatcher (#1303
U5-15c) to the committed receipt at the selected revision plus four, with the
graph and the tenant active and unsealed in policy and the graph's runtime
open and queryable. The handler then answers 200 with state `committed` at
that revision. `publication_eligible` is `false`: the handler takes it from
the journal it loaded before the resume, so the answer is the same as on
Linux and the same as the receipt answer. Any step's `BUSY` or `IO` can
return first, and the handler reports `BUSY` as a conflict when the revision
moved. The handler's `SELECTED` branch (`wyrelog/daemon/http.c`, for a stored
`selected_pending_cleanup` journal) finalizes a selected journal that is not
yet `FINALIZED` the same way, or runs the terminal proof on a `FINALIZED`
one, and then promotes through the same dispatcher. Once promotion has
committed the journal is gone, so a retry finds no journal and is answered
from the committed receipt (200, state `committed`, the receipt's revision)
before any resume step runs: it does not unseal. If promotion commits and its
tail then fails, for example because the unseal refuses a substituted main,
the handler answers 403 (`POLICY`) with the receipt committed and the runtime
closed, and a retry answers 200 from the receipt. The restore handler never
reopens that runtime, after this tail failure or after a promotion whose
response was lost (`IO`, then 200 from the receipt): it stays closed until
boot opens the graph through the `ACTIVE` evidence or refuses it, unless
another path, such as an operator unseal, opens it first. No test seam
reaches that tail failure through the handler, so this is accepted on
reasoning. Since #1303 U5-16 commit admission produces that journal through
the daemon, and `daemon-macos-commit/*` drives the whole path over HTTP,
including a resume stopped after `FINALIZE` and finished through the
`SELECTED` branch.

The macOS `FINALIZE` resume dispatcher
(`wyl_fact_offline_restore_graph_selected_finalize_resume_run`, #1303 U5-14)
is the Linux dispatcher opened in place, with no platform arm: every platform
difference lives behind the public steps it calls, `FINALIZE` and the terminal
proof. The caller's selected journal, fresh or with `FINALIZE` pending, is the
anchor; any other caller journal, a `FINALIZED` or a not yet selected one
included, is `POLICY` before the store is read. A stored journal that
disagrees with its record is `BUSY`, and a row that disagrees with the journal
or is not `selected_pending_cleanup` is `POLICY`. A stored journal equal to
the anchor runs `FINALIZE` and then the terminal proof on its output. The
anchor with `FINALIZE` begun one revision past it (a lost begin) runs
`FINALIZE` from that revision, from `DUAL` or, once the rollback name is gone,
from `TERMINAL`. A stored `FINALIZED` journal equal to the anchor's completion
(a lost completion) runs only the terminal proof. Any other stored journal is
stale (`BUSY`). The dispatcher reads no namespace and takes no lease or
quiescence itself; each step takes its own and releases it, so one call reads
the main twice, or once when only the proof runs, and the runtime stays
closed. It never unseals. Step refusals pass through unmapped: a call can
return `IO`, `BUSY` or `POLICY` after `FINALIZE` committed, with the store at
`FINALIZED`, and the retry with the same anchor resolves it as a lost
completion.

The macOS promotion (`wyl_fact_offline_restore_graph_commit_promote_run`)
takes a `FINALIZED` restore to its committed receipt. Under its own root
writer lease and quiescence, with the journal predicate of the Linux step,
it refuses any revision but the `FINALIZED` one (`POLICY`), and a quiescence
held elsewhere passes through as `BUSY`. It refuses a row without evidence
before the graph is opened. It rebuilds the old main's evidence from the
`restore_selected` record under its own lease, which must be the graph's
only record and carry the row's evidence. A diverged or missing
`restore_selected` evidence is refused before the namespace is read: by that
load, or, on the missing-closed quiescence path, already by the store's
selection postcondition, which the quiescence's reacquire proof runs. It
then requires `TERMINAL` and fails fast otherwise: `DUAL`, the old main
proved back at the rollback name, is an operator wedge. A recheck
(`check_finalized_persisted`) gives `BUSY` for a journal or row changed
since it was loaded. One fenced policy transaction then requires the stored
journal to be the loaded one byte for byte and the row to be the loaded one,
evidence included (a store `STALE` gives `BUSY`), runs the selection
postcondition and the schema check, and runs the effect. The effect requires
the row's evidence to be the loaded bytes, proves `TERMINAL` again and
compares the stored replacement evidence through a fresh descriptor, the
only read of the main. The compare runs inside the transaction, unlike the
compare of the earlier steps, which run before theirs: promotion makes the
evidence `ACTIVE` and cannot be undone, so no byte of the main may change
between the compare and the commit, and nothing up to the commit is accepted
by device and inode alone. The cost is that the compare holds the graph
authority mutex and the store connection mutex for a full SHA-256 read of
the main, and every store call in the process waits for it. Through the
promote resume dispatcher the daemon's resume handler now runs that compare
(#1303 U5-15c). The daemon's reads that go through the authority already wait
while a restore holds the policy write
(`wyrelog/auth/service-auth-coordination.c`), so the stall adds nothing for
them. It additionally blocks the store calls that take only the store
connection mutex, outside policy-write coordination, for a full SHA-256 of
the main, which grows with the main's size. Measured on an Apple M2 Max with
GLib 2.90.1 (the build's), warm cache, 64 KiB `pread`s into
`g_checksum_update`, the loop of the compare: 3.11 s per GiB (328.5 to
329.0 MiB/s over seven runs of a 1 GiB file), plus the device read on a cold
cache. The connection is opened `SQLITE_OPEN_FULLMUTEX`, so every policy
store statement in the process, authentication included, waits on the
connection mutex (`sqlite3_db_mutex`, `wyrelog/policy/store.c`) for that
long. A fresh resume through the daemon reads the new main in full seven
times (counted at the digest loop over `daemon-macos-commit/fresh`), so its
request takes about 22 s per GiB of hashing; only promotion's read, 3.1 s
per GiB, runs inside the store transaction. The restore handler runs
synchronously on the HTTP server's main loop, so that server answers
nothing else for the whole resume. A client that times out first, as wyctl
does after its default 2000 ms (`default-timeout-ms`, which `--timeout-ms` or
the setting raises), loses the response; the restore still finishes, and
`status` answers it from the journal or the receipt. This is accepted now
that operators reach it: a daemon restore already holds the exclusive policy
write, so the authority readers already wait; the extra blocked set is the
store calls that take only the connection mutex; and the compare cannot
move out of the transaction without accepting the main by identity alone,
which this ADR forbids. A hardware-accelerated SHA-256 (CommonCrypto
`CC_SHA256`, the ARMv8 SHA extensions) would keep the in-transaction proof
and shorten the hold; its factor is not measured, and it is #1571.
The store then promotes the schema, publishes the journal, activates the
graph, moves the `restore_selected` record to `ACTIVE` with its evidence
and the row to `verified`, takes the tenant through `unsealing` to `active`,
and terminalizes: history, receipt and terminal guard, then the replacement
row, the claim and the journal are deleted. Promotion changes no file. The
graph is unsealed afterwards through the `ACTIVE` evidence; the existing
macOS unseal coverage is in `tests/test-fact-graph-seal.c`. Every locator
refusal is a policy refusal. If the commit is durable and its response is
lost, the call returns `IO` and the store goes terminal, so the same call
cannot read the receipt and does not unseal. After a reopen the policy shows
the promotion committed (the receipt at the selected revision plus four, the
journal, row and claim gone, the `ACTIVE` record with the replacement
evidence, the graph active and unsealed in policy), the runtime stays closed
in that process until the published proof or boot opens the graph through
the `ACTIVE` evidence, and a retry gives `NOT_FOUND` and changes nothing.
The macOS published proof
(`wyl_fact_offline_restore_graph_commit_published_prove_terminal`, #1303
U5-12) resolves the lost response in process. A direct caller must pass the
current `FINALIZED` journal: a well-formed journal that is not `FINALIZED` is
`POLICY` before the store is read, and a malformed one is `INVALID`.
The proof reads only the receipt and the graph's authority before
the unseal; the unseal reads the `ACTIVE` evidence and opens the main by
identity. No receipt is `POLICY`, with no lease, quiescence or namespace
read: promotion terminalizes in its own transaction, so no macOS store holds
a published journal without a receipt, and the Linux "published, no receipt"
branch has no macOS counterpart. A receipt that does not name the journal's
operation, tenant, graph and manifest at its revision plus two is `POLICY`.
The receipt is terminal and outlives the graph's later lifecycle, so the
graph must still be active and unsealed in policy, as promotion left it: a
graph sealed since is a stale replay (`POLICY`), and nothing is unsealed.
Otherwise the proof returns the journal marked published and handed off and
unseals the graph, in the same process after a reopen or after a restart; a
ready runtime is accepted, so a replay changes nothing. No `TERMINAL` proof
or byte compare follows the receipt: the graph is live, and a WAL and writes
are legitimate. Store errors pass through, so before a reopen the proof
returns `IO`. An unseal that refuses a substituted main returns `POLICY` and
leaves the runtime entry evicted and closed.
A remount or reboot after `FINALIZE`
changes the device number the `TERMINAL` inventory compares, so promotion
then refuses as an operator wedge (`POLICY`).

The macOS promote resume dispatcher
(`wyl_fact_offline_restore_graph_selected_promote_resume_run`, #1303 U5-15c)
is the Linux dispatcher opened in place, with no platform arm: every platform
difference lives behind the public steps it calls, the published proof and
promotion. The caller's `FINALIZED` journal is the anchor. Missing arguments
are `INVALID`, and an anchor that is not `FINALIZED` is `POLICY` before the
store is read. The dispatcher runs the published proof first. A matching
committed receipt answers `OK` with the receipt's journal, the graph unsealed
or its ready runtime accepted, and nothing else changes, so a replay is
idempotent; any refusal of the proof but `POLICY` (`BUSY`, `IO`) passes
through. On the proof's `POLICY` the dispatcher loads the stored journal. A
stored journal that disagrees with its record, or is not the anchor byte for
byte, is `BUSY`; a row that disagrees with the journal or is not
`selected_pending_cleanup` is `POLICY`. Promotion then runs, and its
refusals pass through unmapped. On success the output is promotion's: the
journal published and handed off at the anchor's revision plus two, with the
receipt committed at the selected revision plus four, the graph and the
tenant active, the `restore_selected` record `ACTIVE` with the replacement
evidence, and the runtime open and queryable. The dispatcher's own shape
check does not read `replay_preflighted`: an anchor without it against a
stored journal with it differs in bytes and is `BUSY`, and promotion's
`POLICY` for it applies only when the stored journal lacks it too. The
proof's `POLICY` has six meanings: no receipt; a receipt that does not name
the journal; a stale replay of a graph sealed since; a substituted main that
the unseal refuses; a journal that is not `FINALIZED`, which the
dispatcher's shape check catches first; and a graph sealed inside the
unseal's publication fence. The daemon reaches the dispatcher only with "no
receipt": the handler's journal load proves the journal exists, promotion
deletes it and writes the receipt in one transaction, and the exclusive
policy write excludes a promotion between the two. For a direct caller every
other `POLICY` meets a deleted journal, or a stored journal that is not the
anchor, so the dispatcher answers `NOT_FOUND` or `BUSY`, and nothing is
unsealed. The proof's own `NOT_FOUND` means the graph is gone, since its
authority read finds nothing, which is not the dispatcher's "journal gone";
it passes through as `NOT_FOUND` all the same, and the daemon's answer is
the same under either meaning. A replay of a restore's
anchor after a later restore of the same graph is answered from the earlier
restore's genuine receipt: `OK` with its journal, which truthfully reports
that it committed. The recovery-only unseal writes no policy and a ready
runtime is accepted, so this is accepted; comparing the `ACTIVE` record with
the journal's replacement would widen the published proof's contract, which
reads only the receipt and the authority, and is left to a follow-up. The
Linux branch for a stored published journal two revisions past the anchor is
dead on macOS, since no macOS store holds a published journal, and stays as
the Linux body. Opening this dispatcher does not close the seal residual
described in the next paragraph (#1569), and it adds no new way to
reach it: a direct caller could already call the proof and promotion, and
the daemon serializes restore with seal through the policy write.

The restore unseal is recovery-only, on Linux and macOS (#1303 U5-15a).
Every restore tail, macOS or not, ends in `restore_unseal_graph`, and its
one unseal is `wyl_fact_graph_unseal_recovery_with_root_lease`. A restore
tail never writes graph authority; any non-`ACTIVE` initial lifecycle
(sealed, degraded, provisioning, legacy unclassified) is refused inside the
publication fence with `POLICY`; the unseal leaves the runtime as
`restore_unseal_graph`'s pre-fence eviction of a runtime that is not
`READY`, `OPEN` and queryable left it. The fence reads the
initial lifecycle under the graph authority mutex in its own transaction, so
a seal cannot commit between the check and the fence commit. An `ACTIVE`
graph whose runtime is not recovery-eligible keeps the store's answer,
`BUSY`. This changes the Linux behaviour as well (Windows restore entry
points refuse before any tail; the shared code is ungated, so a future
Windows tail inherits the rule): before it, a restore tail unsealed a
sealed graph durably, the operator's unseal without the operator's write
lease, and answered `BUSY` for a degraded, provisioning or unsealed legacy
graph. On Linux the published proof's receipt branch has no
authority check, so a replay of the `FINALIZED` journal after a later seal
unsealed the graph; it is now `POLICY` and the graph stays sealed. The
daemon serializes restore and seal through the exclusive policy write, so
this refusal is what keeps a direct caller that breaks that contract from
unsealing. On macOS a seal that lands between the published proof's
authority check and its unseal is refused the same way, so the proof's
`POLICY` also means "sealed inside the fence". A direct caller that breaks
that serialization and seals between a tenant restore's proof and its
unseal gets `POLICY` the same way, and the tenant journal stays
unterminalized. One residual remains:
before any fence, `restore_unseal_graph` accepts a runtime that is `READY`,
`OPEN` and queryable, and returns `OK` for a graph durably sealed while
still admitting, the state a seal leaves when it found no runtime entry to
close. That residual stands while #1569, the seal's own fix, is out
of this change. `tests/test-darwin-restore-bind-wiring.py` pins the
call (E_RESTORE_UNSEAL_RECOVERY); `tests/test-fact-graph-seal.c` pins the
refusal.

| Durable observation | Required recovery result |
| --- | --- |
| `HANDOFF`, bound, commit refused after the bind (macOS) | The journal stays at the bound revision (4 in the daemon), byte-identical; the handler answers 403 (`POLICY`), 409 `restore_conflict` (`BUSY` with the revision moved) or 500 (`IO`). The forward action is `commit` at the bound revision: the bind replays and admission proceeds. Abort remains available before the COMMIT decision. |
| `HANDOFF`, bound, row `reserved`, no decision | Status exposes the reservation. Retry commit at the bound revision or abort. Once rollback proves the stage is absent, release removes the untouched reservation and records the aborted receipt in the same transaction (#1570). A remount or changed active pair can still prevent proof. |
| `HANDOFF`, `COMMIT` decided (macOS) | Abort is barred (403 at the handler, `POLICY` at rollback) with the journal byte-identical; resume is the only forward action. |
| Published, replacement `reserved`, evidence absent | Capture only under the journal-pin match above; otherwise fail closed (capture, write-once, re-read, compare, advance). |
| `reserved`, evidence present | Re-read exactly and advance; never recapture. |
| `companion_synced`, evidence absent (macOS) | Fail closed at the companion step, at mark and at selection; no recapture; operator wedge. |
| `companion_synced`, evidence present, the old evidence rebuilds from it, the namespace and compare hold (macOS) | Select: copy the evidence into `restore_selected`, delete the old `ACTIVE` record and advance the row, in one transaction. |
| `companion_synced`, the old `ACTIVE` evidence does not rebuild from the replacement evidence and the journal (macOS) | Fail closed at selection before the namespace is read; the old record stays; operator wedge. |
| `selected_pending_cleanup`, `FINALIZE` not begun, replayed by the select resume dispatcher (macOS) | Read-only: `DUAL` and the replacement compare, then the stored journal returned byte for byte; `TERMINAL`, a mismatch or a row without evidence is `POLICY`, and a journal or row changed during the proof is `BUSY`. |
| `selected_pending_cleanup`, `FINALIZE` not begun (macOS) | `FINALIZE` requires `DUAL`, the old main proved at the rollback name by the old evidence rebuilt from the `restore_selected` evidence and the journal; a mismatch, an absent rollback name or a changed device is an operator wedge. |
| `selected_pending_cleanup`, `FINALIZE` pending (macOS) | `FINALIZE` accepts `DUAL` or `TERMINAL`, compares the replacement evidence on both and finishes; any other shape is an operator wedge. |
| `selected_pending_cleanup`, resumed by the `FINALIZE` resume dispatcher (macOS) | The anchor equal to the stored journal runs `FINALIZE` and the terminal proof; a lost begin runs `FINALIZE` from the begun revision; a lost completion runs the proof only; any other stored journal is `BUSY` and any other anchor `POLICY`; nothing is unsealed. |
| `FINALIZED` (macOS) | The terminal proof requires `TERMINAL` and the replacement compare, mutates nothing, and returns the journal. Promotion requires `TERMINAL` before and inside its transaction and the replacement compare inside it, then commits; a diverged `restore_selected` or row evidence, a reappeared rollback name or a changed main is an operator wedge, and a journal or row changed since it was loaded is `BUSY`. |
| `FINALIZED`, resumed by the promote resume dispatcher (macOS) | The published proof first: a matching committed receipt answers `OK` with the receipt's journal and changes nothing but the runtime it opens. Otherwise the stored journal must be the anchor byte for byte (`BUSY`) and the row `selected_pending_cleanup` (`POLICY`), and promotion runs, its refusals passed through. Any other proof `POLICY` meets a deleted journal (`NOT_FOUND`) or a present journal that is not the anchor (`BUSY`), and nothing is unsealed. |
| Promoted, response lost (macOS) | The call returns `IO` and does not unseal; after a reopen the receipt shows the promotion committed and a retry of promotion gives `NOT_FOUND`; the published proof, or the promote resume dispatcher retried with the `FINALIZED` journal, matches the receipt to that journal and unseals through the `ACTIVE` evidence, in process after a reopen or after a restart. Before a reopen the dispatcher's retry returns `IO` and unseals nothing. |
| Committed receipt (macOS) | The published proof requires the `FINALIZED` journal, a matching committed receipt and the graph still active and unsealed in policy; it reads only the receipt and the graph's authority before the unseal, and the unseal reads the `ACTIVE` evidence and opens the main by identity. No receipt, a mismatch or a graph sealed since is `POLICY`, and nothing is unsealed. |
| `ACTIVE` after promotion (macOS) | The record carries the replacement's version 1 evidence bound to the replacement UUID; unseal, store open, backup and a later restore read it. |
| Evidence present, reopened main mismatches it | Fail closed without mutation. |
| Rollback after evidence was written | The evidence stays on the replacement row until the terminal delete; nothing is promoted and nothing reads it. |
| `restore_selected` or `ACTIVE`, evidence differs from the replacement row | Unreachable by schema; while the replacement row exists, store open treats it as corruption and refuses. After the terminal delete only the `ACTIVE` row holds the evidence, and nothing compares. |
