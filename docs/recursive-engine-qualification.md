# Recursive engine qualification

This is the executable capability handoff for #1503 to #1504, #1505 and #1506,
under #1502. It does **not** enable recursive rule-pack registration: the
production cycle and recursive-stratum rejection checks remain in place.

The inspected baseline is Wyrelog `c462944d` and Wirelog
`9cb295ad49280c2562e29148796d1ac7ec69c2ef`. Qualification uses that pinned
source **plus** `0002-easy-snapshot-completeness.patch`. The patch fixes
[Wirelog #2345](https://github.com/semantic-reasoning/wirelog/issues/2345).
An unpatched provider at the same version is not equivalent.

## Executable contract

`tests/test-engine-recursion.c` uses `wyl_engine_open_source()`, engine-owned
symbol interning and insert/remove, READ ownership, and
`wyl_engine_snapshot()`. This bypasses rule-pack admission intentionally;
it tests the actual easy facade used by fact engines without pretending the
HTTP feature is already enabled. Host-owned symbol IDs are mapped back to
finite vertex indices. Callback capture checks relation, arity, unknown
vertices, duplicates and every expected/absent tuple.

A breadth-first search from each vertex is the independent reachability
oracle. It does not reuse Wirelog output or implement its join algorithm.
Unary mutually recursive heads are compared to the union of host seed values
and independently reachable vertices.

| Program / case | Required result |
|---|---|
| Linear closure over `(0,1),(1,2)` | Exactly `(0,1),(1,2),(0,2)` |
| Two-vertex cycle | Exactly `(0,0),(0,1),(1,0),(1,1)` |
| Diamond paths | One row per pair regardless of derivation count |
| Empty input / seed removal | Empty model, including recursive cycles without support |
| 64-vertex chain | Every pair in the host BFS closure, not just a row count |
| Nonlinear `reachable(X,Z) :- reachable(X,Y), reachable(Y,Z)` | Same closure oracle |
| Mutual `p`/`q`, seeded from `seed`, expanded along edges | Exact equal unary sets in both heads |
| Insert, retract, alternate support, final support removal, re-add | Recomputed host model after every mutation |
| First empty read, input before first read, dirty and unchanged reads | Exact fresh collectors for each snapshot |
| Additional `observed` identity head | Correct relation filtering and complete downstream model |

These finite fixtures qualify direct, mutual and nonlinear positive recursion
for the tested symbol relations. They do not qualify new value-generating
operators, every possible recursive program, stratified-negation admission,
or pack persistence/security integration. Those remain owned by the later
umbrella units. Fact rebuild semantics may use fresh engines rather than the
in-place remove path exercised here.

## Routes and configuration

| Setting | Evidence and limit |
|---|---|
| `num_workers=0` | `wyl_engine_open_source()` maps it to 1; exact-set lifecycle suite |
| `num_workers=1` | Production source-engine default; exact-set lifecycle suite |
| `num_workers=2` | Explicit host option; exact-set lifecycle suite, including initial and dirty reads |
| Two workers with `WIRELOG_TDD_MIN_ROWS_PER_WORKER=1` | Isolated subprocess exercises seeded 64-vertex programs; asserts runtime diagnostic `use_tdd=1`, then checks unchanged/removed/re-added models |
| Backend | Easy facade calls `wl_backend_columnar()`; no backend selection is exposed by the Wyrelog source opener |
| Optimizer | Easy open calls the pinned `wirelog_optimize()` pipeline; Wyrelog exposes no optimizer-disable option here |

Requested workers alone do not establish TDD dispatch. The forced-route
subprocess checks the actual dispatch diagnostic; it does not assert every
stratum uses TDD. Runtime diagnostics also expose legitimate serial fallbacks.
Unexposed advanced/raw backends, optimizer variants and larger worker counts
are not qualified by this suite. Native Windows/macOS execution is not
established merely by local Linux results; #1507 owns the supported product
matrix. Normal tests do not reference internal Wirelog symbols.

## Failure and retry semantics

The join-output-limit case uses an isolated subprocess with
`WIRELOG_JOIN_OUTPUT_LIMIT=1`. A real recursive join exceeds the latched
limit: snapshot must return `WYRELOG_E_EXEC`, deliver zero callbacks, and not
latch successful snapshot mode. Clearing the environment does not change the
existing session: a second attempt must still fail. A new unrestricted engine
must recover the full independently computed model.

The separate hook-enabled static configuration sets the **real upstream**
`wl_columnar_eval_serial_test_iteration_limit` and
`wl_columnar_session_test_iteration_limit` to 1. A seeded 13-edge mutual chain
requires 14 values per head. Before the patch, the actual Wyrelog snapshot
returned success with only 5 values. The test preserves the stronger contract:
error, zero callbacks, then exact recovery on the **same engine** after limits
are restored, followed by an unchanged exact snapshot.

Cap cases cover configured workers 0/1/2, first evaluation and a forced full
reevaluation after a previously successful model, each recursive head, an
independent `seed_seen` head and an unmatched relation. A separate forced-TDD
subprocess checks a capped 64-vertex linear closure and same-engine recovery
with runtime dispatch evidence. The mutual program legitimately falls back
to serial evaluation even with two configured workers. This verifies
callback suppression even when the requested output is outside the capped
stratum or would otherwise emit nothing.

The downstream patch suppresses easy-facade callbacks while the raw session
reports `eval_stratum_iteration_capped`, and converts otherwise-successful
capped completion to `WIRELOG_ERR_EXEC`. Existing error mapping takes
precedence; pending-input and retry state are retained. This does not alter
the raw backend's continuation behavior, promise rollback to a prior published
engine, or make all possible errors transactionally atomic. It protects the
easy snapshot's complete-model contract only, not raw/advanced/STEP facades.

`WIRELOG_EASY_SNAPSHOT_COMPLETENESS_VERSION >= 1` identifies this narrow
provider contract. The dependency selector rejects unmarked/older system
headers and uses the patched pinned fallback, or reports an actionable error
with `--wrap-mode=nofallback`. It also refuses an unpatched fallback. The
provider must ship matching headers and library; the macro is an admission
contract, not a substitute for behavioral tests. Remove the package patch
only after a new pinned upstream provides and passes the same contract.

## Reproduction and validation commands

Normal shared build (no internal cap hooks):

```sh
meson setup builddir-recursion --force-fallback-for=wirelog \
  -Ddefault_library=shared -Denable_tpm=disabled \
  -Denable_fact_store=enabled -Denable_audit=enabled \
  -Denable_client=enabled -Denable_fault_injection=enabled \
  -Dduckdb_source=prebuilt
meson compile -C builddir-recursion test-engine-recursion
meson test -C builddir-recursion engine-recursion --print-errorlogs
```

The cap checks must also run in a **separate static test build**. The define
must apply to Wirelog library objects and the test, not only to the executable.
Do not install this instrumented build as a product:

```sh
meson setup builddir-recursion-hooks --force-fallback-for=wirelog \
  -Ddefault_library=static -Dc_args=-DWL_SESSION_TEST_HOOKS=1 \
  -Denable_tpm=disabled -Denable_fact_store=enabled -Denable_audit=enabled \
  -Denable_client=enabled -Denable_fault_injection=enabled \
  -Dduckdb_source=prebuilt
meson compile -C builddir-recursion-hooks test-engine-recursion
meson test -C builddir-recursion-hooks engine-recursion --print-errorlogs
```

Repeat the static configuration in another directory with
`-Db_sanitize=address,undefined` and run with:

```sh
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1 \
UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1 \
meson test -C builddir-recursion-asan engine-recursion --print-errorlogs
```

Run `tests/test-wirelog-dependency-boundary.py` with the repository root and
absolute Meson executable path to exercise accepted and rejected provider
fixtures, including absent/old completeness markers, forced fallback and
nofallback refusals. Run relevant engine/rule-pack tests and the full
feature-enabled repository suite before merging. `tools/check-format.sh
--ledger` is a separate required check. Host-specific logs belong in the PR;
these commands and assertions are the durable reproducible evidence.

## Resource-control inventory and downstream work

The pin already contains memory admission/governor machinery and internal
`wl_session_options_t` fields for memory governor and evaluation control,
including work/cancellation reporting and controlled-session routes. Public
advanced options also contain spill/batch configuration. This is not evidence
that no controls exist upstream.

Wyrelog's source opener configures workers and eager plan/session construction
through the easy API; it does not attach those internal evaluation controls.
The `WIRELOG_MEMORY_BUDGET` environment policy and join-output limit are not
an end-to-end per-query work/time/cancellation guarantee. Eager construction
also does not mean eager fixed-point evaluation. Static rule/atom/byte caps,
result limits, subprocess watchdogs and measured runtime do not bound join
work or intermediate growth.

#1504 consumes the qualified positive-recursion envelope while retaining
schema/type/variable safety and adding signed negative-cycle checks. #1505
owns canonical storage and downgrade contracts. #1506 owns registration,
replay/publication, inference authorization, mutation/restore and isolation.
A demonstrated defect has a narrow tracked dependency (Wirelog #2345);
completion of the unrelated resource-control umbrella #1817 is not required.
