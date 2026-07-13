# Developer lifecycle constraints

## Raw `fork()`

Wyrelog deliberately installs no `pthread_atfork` handlers. After a process
with any live Wyrelog handle, store, provider, lease, logger, or error state
calls raw `fork()`, the child must immediately call an `exec*` function or
`_exit()`.

Before `exec*` or `_exit()`, the child must not call any Wyrelog API, close or
free inherited Wyrelog state, format a Wyrelog error, emit a log, call GLib
cleanup that can reach Wyrelog state, or call C `exit()`. The child may use
only async-signal-safe preparation required for `exec*`; if `exec*` fails it
must terminate with `_exit()`.

Policy-store lease descriptors use `CLOEXEC`. Windows lease handles are
created non-inheritable. This makes `fork()` followed immediately by `exec*`
safe without child-side lifecycle processing while preserving the live
parent's exclusive store lease.

## Provider-backed store path threat model

Every provider-backed store, encrypted or plaintext, must be placed in an
operator-owned, non-replaceable namespace. The resolved parent and every path
ancestor must be protected from rename, reparse, and write operations by any
principal whose trust is lower than the operating-system identity running
Wyrelog for the store's entire lifetime, from before open until close has
completed. This is a deployment requirement, not an optional hardening
measure.

The store lease provides alias normalization, retained-parent identity
verification, cooperating-process exclusion tied to the lease sidecar/store
lease identity, and stale-close prevention. It does not pin or continuously
match the canonical SQLite store inode. After acquisition, Wyrelog pins its
own canonical reads, encrypted persistence, and clear-work helper cleanup to
the resolved parent authority.

SQLite does not expose a portable `openat()` VFS. It opens an encrypted
clear-work database, or a plaintext provider-backed canonical database,
through a lease-resolved pathname. Parent-identity checks bracket only the
initial main-database `sqlite3_open_v2()` call. They can detect a persistent
parent replacement across that initial bracket, but not a transient
swap-and-restore inside it. Later VFS opens for journal, WAL, SHM, temporary,
and other files remain pathname-derived throughout the store lifetime and are
not pinned or bracketed by those checks. Persistent or transient namespace
changes after the post-open check are therefore also unprotected. The lease
does not make an attacker-writable namespace safe at any point in the store
lifetime.

## Policy-store provider ownership

`wyl_policy_store_open_with_options()` consumes a non-null KeyProvider state
on every outcome once both `opts` and `out_store` have passed entry validation.
It copies the supplied vtable by value. A successful open retains the state
until store close; a failure releases it before returning. The caller must not
invoke provider operations or `wipe` after transfer. If
`keyprovider_state_free` is non-null, the caller must not release the state:
Wyrelog invokes `wipe` exactly once when that callback is available, then
invokes `keyprovider_state_free` exactly once.

A providerless configuration has null vtable, state, and free callback. Any
other combination is configured and requires non-null state and vtable, with
all of `probe`, `seal`, `unseal`, `derive`, `wipe`, and `clear_sealed_blob`.
The state free callback is the only optional member. Configured plaintext
stores call `probe` exactly once, call no `derive`, and retain the provider for
the same close-time lifecycle as encrypted stores.

If `keyprovider_state_free` is null, Wyrelog still consumes the logical
provider state and invokes `wipe` exactly once when available, but does not
deallocate its backing storage. That storage must outlive a successful store
handle. The caller may reclaim it only after store close, or after a failed
open returns; its contents must not be reused as KeyProvider state. Invalid
partial configurations are released using only the lifecycle callbacks they
provide; an unavailable callback is invoked zero times.

An invalid entry where `opts` or `out_store` is null transfers nothing and
invokes no lifecycle callback. If store lease acquisition returns
`WYRELOG_E_BUSY`, no operational KeyProvider callback (`probe`, `seal`,
`unseal`, or `derive`) is invoked; the transferred state's lifecycle cleanup
still follows the available-callback rules above.

`seal` callers pass an output initialized to `{ NULL, 0 }`. Failure preserves
that empty value. A successful output is released only through the producing
provider's `clear_sealed_blob`, which securely wipes its length, uses the
matching allocator to free it, and resets it to `{ NULL, 0 }`. Clearing a null
or already-cleared blob is safe.

Key rotation performs no transfer for an empty path, null option, or aliased
non-null old/new state. After basic validation it consumes both states on every
outcome. The old provider is retained by the internal store while the new
provider is validated and used. An old-provider failure, including
`WYRELOG_E_BUSY`, also releases the new provider. Rotation uses the old store's
snapshotted CVK secure runtime for locked scratch. The runtime supplied through
`new_opts`, if any, is not adopted or invoked by this transient operation.

The clear SQLite work database is disposable rotation staging. After schema
and snapshot validation in `BEGIN IMMEDIATE`, an existing CVK is unsealed with
the old provider and re-sealed under a distinct new-provider binding with its
generation incremented; the 32-byte CVK and every credential verifier remain
unchanged. The staged transaction commits before an encrypted candidate is
prepared with the new database key. A fully written, file-synced and closed
temporary file is then renamed over the canonical file. That rename is the
sole rotation linearization point: a failure before it leaves the old canonical
file byte-for-byte unchanged, while a failure of directory durability after it
is logged as a warning and the already-committed rotation returns success.
Provider handoff and secret-buffer cleanup occur while the exclusive lease is
still held, and close never performs a second persist.

The post-rename warning contains no key, CVK, credential or path material. It
means atomic visibility has committed successfully but power-loss durability of
the directory entry could not be confirmed; it must never be translated into a
failure that invites an unsafe retry with the old root.

Crash recovery follows the same boundary: a crash before rename leaves the old
root authoritative; a crash after rename leaves the new root authoritative.
The operation is deliberately not crash-resumable or idempotently retryable in
#354 because a caller cannot infer which root won after losing the response.
Operators must retain both roots and follow the explicit recovery procedure
tracked by #364.

## Service credential verification key

The service credential CVK is created only by the issuance path. The
existing-only path never creates authority: an empty store returns
`WYRELOG_E_NOT_FOUND`, while credentials without the singleton CVK row are a
policy-corruption failure. Both paths reject an outer SQLite transaction and
serialize their top-level `BEGIN IMMEDIATE` transaction with a per-store
mutex. A newly generated or unsealed CVK becomes observable through the
store's borrowed cache only after the database commit succeeds.

The cache is a locked, store-owned 124-byte version-1 envelope. It is wiped,
unlocked, and freed at store close. The envelope binds its fixed magic,
domain, version, singleton slot, generation, provider binding, and 32-byte CVK
at fixed byte offsets. The provider binding is derived under the KeyProvider
label `wyrelog.service-credential.cvk.provider-binding.v1` and a separately
domain-separated keyed BLAKE2b transcript. Provider outputs are always
released with the producing provider's `clear_sealed_blob` callback.

The optional CVK runtime table is shallow-copied at store open. Its callbacks
and `data` pointer are borrowed; no ownership is transferred. The callback
code and data context must outlive the store and remain valid through the end
of `wyl_policy_store_close()`.

Root-provider rotation never creates a missing CVK. A missing row with existing
credentials is policy corruption; a missing row with no credentials follows
the legacy database-key-only rotation path without CVK derive, unseal, seal or
random-number callbacks. Existing rows require a non-overflowing generation
and a new provider binding distinct from the old binding.
