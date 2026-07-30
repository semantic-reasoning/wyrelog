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
consumer of this backend. It brackets bounded construction, typed identity
SQL, checked finalization, and final namespace validation with the common
in-process identity guard. Identity values are passed only as prepared
parameters and returned as exact tagged null, signed-64-bit, or byte cells;
the adapter never uses display conversion or SQL interpolation. No live
DuckDB handle escapes. The pathname identity API remains available for legacy
callers but is not a provisioning authority. #611 and #544 own the later
retained-pair lifecycle and coordinator consumption.

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
   source build on Linux and macOS. Windows must continue to compile and
   return `WYRELOG_E_POLICY` until its native runtime authority is implemented.

The POSIX CI jobs execute the real adapter target; compilation or recording
evidence alone is not an acceptance signal.
