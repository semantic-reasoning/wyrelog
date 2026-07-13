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
The caller must not invoke provider operations or `wipe` on that state after
the call. If `keyprovider_state_free` is non-null, the caller must not release
the state: Wyrelog invokes the provider's `wipe` callback once, when present,
then invokes `keyprovider_state_free` once.

If `keyprovider_state_free` is null, Wyrelog still consumes the logical
provider state and invokes `wipe` once when present, but does not deallocate
its backing storage. The caller remains responsible for eventually reclaiming
that storage after the call returns; its contents may have been wiped and must
not be reused as KeyProvider state.

An invalid entry where `opts` or `out_store` is null transfers nothing and
invokes no lifecycle callback. If store lease acquisition returns
`WYRELOG_E_BUSY`, no operational KeyProvider callback (`probe`, `seal`,
`unseal`, or `derive`) is invoked; the transferred state's lifecycle cleanup
still follows the rules above.
