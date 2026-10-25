# DuckDB `AFTER_WAL_START` test seam

The secure DuckDB recording tests pin DuckDB v2.0.0 by source-tarball
checksum. The test-only `WYL_DUCKDB_TEST_AFTER_WAL_START` variant adds one
rendezvous in `SingleFileCheckpointWriter::CreateCheckpoint`
(`src/storage/checkpoint_manager.cpp`), immediately after
`StorageManager::WALStartCheckpoint` returns `true` and the checkpoint context
is taken from its wrapper.

At that point the main WAL checkpoint marker is durable, the lazy
`.wal.checkpoint` writer is installed, and `WALStartCheckpoint`'s local WAL
mutex guard has been destroyed. Checkpoint serialization, debug sleep,
metadata flush, header write, and the `BEFORE_HEADER` fault are all still
ahead. A prepared transaction can therefore commit into the checkpoint WAL
while the checkpoint thread waits on a test-owned condition variable.

The seam is absent from the regular `duckdb_lib`: its callback fields and call
site are compile-time guarded, the seam archive is non-installed and
non-default, and only the two focused Linux/macOS tests consume it. It is not a
SQL setting, production callback, filesystem authority, or general tracing
API.

## Upgrade review

Changing the DuckDB pin requires deliberate review of all of the following:

1. Verify `WALStartCheckpoint` still installs the checkpoint WAL and releases
   its WAL mutex before returning.
2. Verify the callback remains immediately after the successful return and
   before debug sleep, serialization, metadata/header work, and
   `BEFORE_HEADER`.
3. Regenerate the package patch against the new release source and update its
   release checksum, then regenerate the build overlay with
   `tools/generate-duckdb-source-overlay.py`.
4. Update the source-boundary test only after reviewing the new adjacent
   source, then rerun both focused rendezvous tests on Linux and macOS.

The boundary test intentionally fails if the checksum, patch name, guarded
phase, or call-site context drifts.

## Valid transaction-control failure characterization

The same non-installed DuckDB test archive also defines the independent
`WYL_DUCKDB_TEST_TRANSACTION_CONTROL` guard. Its callback fields are absent
from the regular archive and its two call sites are inside the active
`COMMIT` and `ROLLBACK` branches of
`ClientContext::RunTransactionStatementInternal` (`src/main/client_context.cpp`),
after the autocommit refusal and immediately before DuckDB clears the
transaction through `TransactionContext::Commit` or `Rollback`.
The rollback callback additionally checks the original `TransactionInfo` type,
so DuckDB's conversion of an invalidated `COMMIT` into internal rollback does
not masquerade as an explicitly issued `ROLLBACK;` failure.

The callback is a synchronous boolean decision. The test-owned context arms
one phase (`BEFORE_COMMIT` or `BEFORE_ROLLBACK`) and disarms itself before it
returns `true`; DuckDB then raises a `PermissionException`. DuckDB 2.0.0
aborts the transaction the failed statement belongs to: every later statement
on that connection except `ROLLBACK`, including `SELECT 1` and a nested
`BEGIN`, is refused with `Current transaction is aborted (please ROLLBACK)`.
(DuckDB 1.5.5 left such a transaction usable.)

Each case uses a fresh database. It proves the baseline is committed, the
candidate is visible only to the subject connection before the injected
failure, and an independent observer still sees only the baseline after it.
It then pins the aborted state above, checks that the one-shot hook is inert,
performs cleanup with an exact `ROLLBACK`, and verifies baseline-only
persistence across a close and reopen. This is a pre-commit/pre-rollback
execution failure seam; it does not model an ambiguous failure after a commit
has become durable.
