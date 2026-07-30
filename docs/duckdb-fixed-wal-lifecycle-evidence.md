# DuckDB fixed-WAL lifecycle evidence

Wyrelog's source-pinned DuckDB v1.5.5 tests record the two fixed WAL
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

## DuckDB source-pin upgrades

Any change from v1.5.5 must deliberately review all of the following before
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
