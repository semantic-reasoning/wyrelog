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

This decision defines a platform contract. It does not enable macOS
provisioning, add policy-store columns, or change the current Linux or Windows
runtime.

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
