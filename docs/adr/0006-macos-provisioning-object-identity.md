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
- On recovery, reopen the canonical graph chain and `facts.duckdb`; compare
  descriptor-derived volume, graph, and artifact evidence. Never search for an
  object by ID and never accept a different name which happens to expose the
  expected ID.
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
of the legacy stage name. Only the canonical name is witnessed. The rollback
name would expose the evidenced object under a different name, which the
comparison protocol above forbids, so a `RETAINED_ROLLBACK` witness is refused
on macOS until the commit and resume port decides that slot under the same
rule. The transition model is not told that the witness ran: a one-link main
is its ordinary shape, and the proof is the successful witness call in the
restore path, which must therefore use the evidence form of the capture.

## Windows rollback name

Windows accepts the `RETAINED_ROLLBACK` slot that macOS still refuses. Like a
macOS main, a provisioned Windows main has one link and is proved by its
operation evidence, so the same comparison rule applies: the evidenced object
is never found by its ID, and a name merely exposing the expected ID is not
proof. The rollback name is accepted because acceptance rests on the object
and on a name the operation fixes, not on a name that was searched for:

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
until the provisioning record's cleanup is journaled. `PUBLISH` re-pins the
stage it moves, not the object at the rollback name, so a caller must
recapture and reauthorize before each step rather than reuse an authorization
across a restart. macOS keeps refusing the slot; its commit and
resume port may adopt this reasoning, which depends on nothing
Windows-specific beyond the one-link main.

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
legacy stage name absent. A mismatch fails closed for operator disposition;
nothing is minted for an object the journal does not name. The state is the
same final-exists, evidence-absent seam as above, and it is resolved by the
journal pin rather than refused. That departs from the provisioning rule
deliberately: a live device and inode name exactly one object, APFS does not
recycle file IDs while `ATTR_CMN_FILEID` lookup remains valid, and the full
checksum re-read goes through the same descriptor whose identity is compared.
The re-read costs one full read of the main.

The device number is not durable identity: it only has to match within the
restore that recorded it. A remount or reboot between `PUBLISH` and capture
can change it; capture then refuses rather than weakening the comparison, and
the restore is an operator wedge, not a retry. Once captured, the volume UUID
and `ATTR_CMN_FILEID` pair is the durable identity, under the same capability
gate as provisioning.

The evidence commits write-once to the `reserved` replacement row and is
re-read before the row advances. The schema cannot require evidence, because
Linux and Windows replacement rows carry none, so the order is an obligation
of the macOS commit path: on macOS the replacement row must not advance to
`companion_synced` until its evidence is durable and re-read, and a selection
whose replacement row carries no evidence is refused. Policy also refuses
such a selection on macOS before any write. Selection copies the row's
evidence into the `restore_selected` provisioning row in the same
transaction, the replacement row's selection update refuses a missing or
different copy, and promotion leaves it unchanged. Policy keeps the envelope
opaque throughout; the caller decodes it against the replacement UUID before
persisting it. The provisioning insert guard names only replacement columns
that every released replacement table has, so no trigger refers to the new
column before a migration creates it.

| Durable observation | Required recovery result |
| --- | --- |
| Published, replacement `reserved`, evidence absent | Capture only under the journal-pin match above; otherwise fail closed. |
| `reserved`, evidence present | Re-read exactly and advance; never recapture. |
| Evidence present, reopened main mismatches it | Fail closed without mutation. |
| Rollback after evidence was written | The evidence stays on the replacement row until the terminal delete; nothing is promoted and nothing reads it. |
| `restore_selected` or `ACTIVE`, evidence differs from the replacement row | Unreachable by schema; while the replacement row exists, store open treats it as corruption and refuses. After the terminal delete only the `ACTIVE` row holds the evidence, and nothing compares. |
