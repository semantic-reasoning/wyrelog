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
