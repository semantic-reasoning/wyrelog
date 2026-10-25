# DuckDB fixed-WAL lifecycle evidence

Wyrelog's source-pinned DuckDB v2.0.0 tests record the two fixed WAL
replacement paths used by the secure filesystem design:

- a live or completed checkpoint moves `facts.duckdb.wal.checkpoint` to
  `facts.duckdb.wal`;
- recovery of an interrupted checkpoint moves
  `facts.duckdb.wal.recovery` to `facts.duckdb.wal`.

The tests are evidence only. They do not grant production replacement,
pathname, descriptor, or checked-close authority.

## Deterministic scenarios

The seam-enabled test dependency pauses at `AFTER_WAL_START`, after DuckDB has
installed the lazy checkpoint WAL and released its WAL mutex. A bounded
concurrent commit populates that WAL before the checkpoint resumes. No
filesystem callback, payload size, sleep, polling loop, or scheduler-fairness
window controls the phase.

Three separate finite grammars are asserted:

1. a successful live checkpoint performs
   `.wal.checkpoint -> .wal`;
2. a `BEFORE_WAL_FINISH` abort leaves a completed checkpoint whose reopen
   performs `.wal.checkpoint -> .wal`;
3. a `BEFORE_HEADER` abort leaves an incomplete checkpoint whose reopen merges
   both WALs and performs `.wal.recovery -> .wal`.

The successful, recovery, and reopen grammars fix every relevant handle's
stable identity, artifact role, open flags, I/O, sync, close, and destruction.
The abort-child grammar instead ends at the deliberate `_exit()` process-death
boundary: the main and checkpoint handles must still be open, and their absent
close/destruction events are part of the exact evidence. The `MoveFile()`
snapshot fixes the complete relevant live-handle set. The old destination
handle may remain live across replacement, but only its terminal close and
destruction may follow the move; any post-move I/O fails the test.

The abort strings, committed rows, intermediate sidecars, second reopen, and
final main-only artifact set are also exact assertions. Linux and macOS run
the three named tests repeatedly through the non-installed seam target.
Windows continues to use the regular dependency and has no runtime requirement
from this evidence.

## Windows sidecar rename durability

DuckDB 1.5.5 replaced a sidecar with `MoveFileExW`, which a live reader of the
destination refuses; wyrelog patched in POSIX-semantics renames and opened the
source with `FILE_FLAG_WRITE_THROUGH`, so that fast path was at least as
durable as the `MOVEFILE_WRITE_THROUGH` fallback. DuckDB 2.0 performs the
POSIX-semantics rename itself (`LocalFileSystem::MoveFile`), so the patch was
dropped, but upstream opens the source with `DELETE` access only and no
write-through. It also throws when it cannot open the source, and on any
rename failure other than `ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED` and
`ERROR_INVALID_FUNCTION`, where the patch fell back to `MoveFileExW`.

This is an accepted change, not an oversight, and its scope is every Windows
build that does not use the secure bridge, prebuilt and source alike; the
prebuilt library never carried the patch. A rename there can return before
it is durable, so a power loss right after recovery can still find the
pre-rename sidecar: the completed-checkpoint state whose reopen performs the
same rename again. Secure-bridge builds
are unaffected: their `MoveFile()` replaces the WAL through the artifact
authority rather than through `LocalFileSystem`.

## DuckDB source-pin upgrades

Any change from v2.0.0 must deliberately review all of the following before
updating the structural boundary:

- `WALStartCheckpoint()` and `WALFinishCheckpoint()` ordering;
- successful-checkpoint, completed-checkpoint recovery, and
  incomplete-checkpoint recovery event grammars;
- every handle ID, role, flags tuple, I/O sequence, close, and destruction;
- the complete live-handle snapshots at both replacement pairs;
- exact `BEFORE_HEADER` and `BEFORE_WAL_FINISH` errors;
- row recovery, intermediate sidecars, second reopen, and final artifacts.

Observed drift must be explained and the finite grammars updated intentionally;
weakening them to prefixes, unordered sets, or broad path/flag allowances is
not an upgrade procedure.
