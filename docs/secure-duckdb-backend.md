# Secure DuckDB backend

The private secure backend is coupled to the DuckDB 1.5.5 C++ `FileSystem`
and `FileHandle` ABI. It is not a general pathname filesystem. Its only
authority is an imported, held graph directory and an existing, held
`facts.duckdb` identity.

The adapter maps only these source-observed logical objects:

- `facts.duckdb` through a reader-main or writer-main binding;
- the fixed WAL/checkpoint/recovery names through sidecar bindings;
- a provider-minted temporary root and source-pinned DuckDB spill children.

The graph mutation lease supplies writer locking. Every working descriptor is
revalidated through its issuing provider immediately before and after raw I/O
and is closed only through that provider. The fixed virtual home
`/__wyrelog_duckdb_home__` has no backing host directory: metadata opens,
listing, creation, extension loading, secret access, and runtime redirection
are denied. The adapter registers no LocalFileSystem fallback.

DuckDB's fixed `checkpoint -> WAL` and `recovery -> WAL` moves use one exact
held binding for each name. A live old-WAL descriptor is checked-closed and
detached before the provider transfers the source identity to the WAL binding;
DuckDB's later close is then a no-op. Ambiguous replacement, revalidation,
checked-close, retirement, or terminal-cleanup failure poisons the shared
filesystem state, so subsequent operations cannot retry with stale authority.

Call `wyl_secure_duckdb_bridge_finalize()` when cleanup success is part of the
caller-visible result. It destroys the connection and database, then returns
the retained filesystem health after handle and temporary-root cleanup.
`wyl_secure_duckdb_bridge_free()` invokes the same cleanup only as a
best-effort void fallback.

`wyl_fact_store_open_identified_pinned()` is the one-shot identified-store
consumer for an already constructed generic namespace. The POSIX retained
provisioning-pair consumer is instead
`wyl_fact_store_open_identified_provisioned_pair_pinned()`. That is the only
callable API accepting the opaque operation-bound pair: no pair-to-generic
namespace factory is declared, and the pair cannot be passed to generic
namespace, lease, main-binding, or raw-descriptor APIs.

The retained pair pins the exact identity validated by the #595 opener, an
independent full root/tenant/graph chain, an `O_RDONLY` held final descriptor,
and a separately acquired and identity-checked `O_RDWR` final descriptor.
Direct reads and reader bindings duplicate only the read descriptor; only a
writer binding may duplicate the writable descriptor. Every duplicate and
I/O/close boundary revalidates the held descriptors, both retained names, and
the complete directory chain. The generic namespace continues to require an
unaliased `nlink=1` main artifact.

The operation-bound entry has a distinct authority preflight immediately
before the hidden namespace factory. It revalidates the pair before lock
creation or DuckDB inspection, so a fresh database can fail there without
changing database bytes, retained names, aliases, lock, WAL, or temporary
state. R0 through R5 keep their ordinary lifecycle meanings: before
construction, after construction, before identity work, after identity work,
before finalization, and at final revalidation. The actual lifecycle performs
bounded construction, typed identity SQL, checked finalization, and final
validation under the common in-process identity guard. Identity values use
prepared parameters and exact tagged cells; no display conversion, SQL
interpolation, live DuckDB handle, pathname, or descriptor escapes.
Test-only control follows the same ownership boundary: the generic and pair
entries consume independently synchronized one-shot controls. The pair passes
its own lifecycle control explicitly into the inner core, which never consumes
the generic global control.

#611 completes this private storage handoff. #544 remains responsible for
persisting and selecting the canonical operation UUID, calling the sole pair
entry at the coordinator-defined point, recording its result, and applying
startup/recovery/HTTP ordering. The legacy pathname identity API remains
available for existing callers but is not provisioning authority.

## Version upgrade procedure

An upgrade is a security-contract change, not a dependency-only update.

1. Update every pinned source and prebuilt wrap together, including hashes.
2. Regenerate the source-recording fixture for the proposed DuckDB release.
   Review every open flag/lock tuple, logical artifact name, WAL recovery
   transition, temporary-child grammar, directory operation, home/secret
   probe, sync, close, and cleanup event.
3. Update the closed adapter vocabulary and provider capabilities only from
   that reviewed evidence. Never add a suffix allowlist or LocalFileSystem
   fallback to make a trace pass.
4. Update the compile-time `DUCKDB_VERSION`, type, and representability
   assertions. Re-run numeric rejection/no-mutation and sparse high-offset
   tests.
5. Run `secure-duckdb-recording-filesystem`,
   `secure-duckdb-filesystem`, and `secure-duckdb-bridge` from the pinned
   source build on Linux and macOS. Windows builds the same pinned source and
   runs `secure-duckdb-bridge`, `secure-duckdb-recording-filesystem` and
   `fact-artifact-namespace-windows`: the bridge object is platform-neutral
   and succeeds there. What still returns
   `WYRELOG_E_POLICY` on Windows is every artifact-bound authority -- the
   provisioned pair, the neutral namespace open, and the fixed WAL
   replacement -- so no production path reaches a live store. Do not read a
   green Windows lane as native runtime authority.

The POSIX CI jobs execute the real adapter target; compilation or recording
evidence alone is not an acceptance signal.
