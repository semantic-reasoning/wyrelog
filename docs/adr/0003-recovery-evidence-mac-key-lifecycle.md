# ADR 0003: Authenticated Temporary-Recovery Evidence Key Lifecycle

Status: accepted

Related issues: #653, #827

## Context

Temporary-recovery evidence is persisted outside the graph directory and can
be supplied after a process restart. The existing WTR1 and WTE1 records only
validate shape and identity fields. An unkeyed checksum would detect
accidental corruption, but an attacker who can rewrite the evidence can
recompute it and replace the identities. Recovery therefore requires
attacker-resistant authentication, not merely a digest trailer.

The fact-artifact layer must not receive or persist a policy root key. It also
cannot assume that a daemon-only key file is available to an offline recovery
tool. Key availability and rotation must be explicit rather than silently
falling back to unauthenticated evidence.

## Decision

The policy/key-provider layer owns a provider-backed root and creates an
opaque, graph-scoped recovery-MAC handle. The handle contains only a provider
reference, immutable tenant/graph identity, and key generation/identifier;
raw root or derived key bytes never cross into the fact layer, evidence, logs,
or the repository.

The provider derives a separate key with the fixed purpose
`wyrelog.fact.recovery-evidence.mac.v1`, the key identifier, version, and
length-prefixed tenant, graph, and operation identifiers. Each length is a
bounded unsigned 16-bit field; text is canonical UTF-8, contains no NUL, and
is not normalized. The policy layer passes this canonical binary label to the
provider; labels and raw keys are never logged. The service CVK is not reused.
The only allowed tag algorithm is keyed BLAKE2b/`crypto_generichash` with a
32-byte output. Derived keys and MAC scratch buffers are wiped by the owner
after each operation.

The fact layer receives opaque callbacks for `compute` and `verify` plus the
scoped handle. The handle owns an explicit provider/reference lifetime and
immutable canonical graph scope. It is ref-counted and closed before provider
teardown; callbacks are serialized or documented thread-safe, and an in-flight
close makes them fail safely rather than dereferencing a dangling provider.
Callbacks are valid only while the graph scope and lease are valid. A missing
callback, stale handle, provider error, unavailable key, scope mismatch, or
generation mismatch returns a policy/crypto failure before any mutation. No
legacy WTR1/WTE1 record is accepted on a MAC-required path; those versions are
inspection-only and can never authorize mutation.

Future WTR2 and WTE2 envelopes include a format version, algorithm/check kind,
key identifier/generation, canonical length fields, the tenant/graph scope,
all platform identity fields, and a fixed 32-byte tag over the exact preceding
canonical bytes. Integers are fixed-width big-endian; lengths are bounded
unsigned 16-bit values; text is canonical UTF-8 with no normalization or
alternate spelling; duplicate, unknown, truncated, or oversized fields are
rejected before allocation. The algorithm allowlist and constant-time tag
comparison are fixed by the format. Shared golden vectors are consumed by
both platform codecs. The identities are included both in the derivation
domain and in the authenticated payload. Each platform accepts only its own
magic; cross-platform decoder rejection is intentional.

The default rotation policy retains verification keys by identifier until
their evidence expiry; an implementation that cannot retain history must
explicitly invalidate all prior evidence and return a deterministic stale-key
error. Decoders never guess a current key for an unknown identifier. Evidence
also carries an
operation nonce/expiry or a durable consumed-generation rule when the caller
requires one-shot recovery; key generation alone is not replay protection.
The verifier binds the canonical stable tenant/graph identity to the active
lease before any mutation. Missing, wrong, stale, or malformed keys/tags fail
closed without touching the named artifact.

The key identifier in the envelope is the exact provider lookup input and is
included in the derivation domain. Offline recovery is supported only when the configured provider can resolve
the required key identifier in the recovery environment. If it cannot, the
operation is unavailable and must be reported as a non-mutating policy
failure; an owner-only evidence file is not treated as a substitute for the
key. Key identifiers and retention/expiry metadata are durable policy state;
provider teardown zeroizes all derived material. Key compromise, malicious
provider output, and error/log leakage are treated as security failures, not
as reasons to fall back to an older or current key.

## Required API and test contract

The eventual implementation must keep raw key material private and test the
opaque boundary with fixed provider seams. Tests must cover canonical
length-prefix domain separation, golden vectors, round trips, bit flips,
truncation and extension, wrong key and unknown key identifier,
missing/offline provider, rotation with retained and invalidated generations,
cross-tenant/graph and operation replay, legacy read-only behavior, bounded
parsing, handle close races, and mutation-free fail-closed behavior. POSIX
WTR2 and Windows WTE2 implementations are separate changes but consume this
same contract.
