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

All engine cases run in isolated subprocesses. The launcher clears ambient
evaluator knobs, then supplies each case's settings before process creation;
child initialization preserves them. This matters on Windows, where GLib and
the evaluator can use different CRT environment copies. Changing GLib's
environment after startup is not reliable configuration for the evaluator.
The TDD cases also receive their threshold and diagnostic flags at startup.

The join-output-limit case starts a subprocess with
`WIRELOG_JOIN_OUTPUT_LIMIT=1`. A real recursive join exceeds the latched
limit: snapshot must return `WYRELOG_E_EXEC`, deliver zero callbacks, and not
latch successful snapshot mode. A second attempt on that engine must still
fail. A separate subprocess starts without the limit and must recover the full
independently computed model from the same inputs. On POSIX, the limited child
additionally clears the environment between attempts, proving the existing
session retains its limit while a newly opened engine recovers. Windows does
not rely on a late GLib unset reaching the evaluator's CRT.

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

## Internal rule-pack compiler capability (#1504)

`wyl_fact_rule_pack_compile_with_mode()` accepts an explicit private language
mode. `WYL_FACT_RULE_PACK_POSITIVE_RECURSION` permits direct, mutual and
nonlinear positive recursion with stratified negation. The existing
`compile()` and `compile_canonical()` entry points select
`WYL_FACT_RULE_PACK_ACYCLIC`: production registration and replay still reject
recursive packs. This option is neither authorization nor a storage format
marker. #1505 owns reader/storage compatibility and #1506 owns activation.

The grammar remains finite-domain: variables, existing scalar constants and
opaque compound references range over input values and rule constants. There
are no arithmetic expressions, aggregates, constructors or value-generating
extensions. Each positive recursive component denotes its least fixed point
with set semantics. A positive self-cycle without input has an empty model.
Durable rows enter the renderer's separate `_input` relations and are unioned
with derived rows in customer heads; duplicate support does not duplicate
query tuples. Derived rows remain query results, not durable fact batches.

Dependency nodes are the resolved schema identities used by rendering, so
qualified and unqualified aliases cannot conceal cycles. SCC connectivity
uses both positive and negative edges. A negative edge within an SCC is
rejected; a negative edge to an independent lower stratum is accepted. For
example, recursive `reachable` may feed
`visible(X,Y):-reachable(X,Y),!blocked(X,Y).` when `blocked` is independent.
All existing relation, arity, type, variable safety, string and size checks run
before dependency analysis. Acyclic canonical text and digest inputs remain
byte-identical in both modes.

The opted path reports `rule_pack_negative_cycle`. `rule_index` and
`atom_index` select the first internal negative edge in source order;
`cycle_rules` lists the ascending unique rules having internal edges in that
edge's SCC. It excludes seed-only rules and unrelated components. The first
listed rule can precede `rule_index`. Owned head/body namespace and relation
fields identify the resolved endpoints separately, even when names contain
dots. Legacy callers retain the original `rule_pack_cycle` diagnostics.

`fact-rule-pack` asserts literal rendered/canonical text, negative-cycle
diagnostics under schema permutation, and exact engine results with one
worker. Its real parser witness confirms recursive strata in the complete
rendered program, exercising the revised compile backstop. The unreachable
legacy recursive-stratum invariant failure is not artificially injected.
`fact-replay` additionally verifies that rejected recursive replacements leave
the stored pack version, digest and rules unchanged; normal replay still
refuses stored recursive packs. No test-only raw compiler bypass is added.

## Stored reader compatibility (#1505)

`wyl_fact_rule_pack_compile_stored()` consumes counted canonical rows, version
and digest plus the exact selected schemas and an explicit #1504 mode. It
rechecks identity and the complete joined byte limit, compiles with schema and
safety validation, then requires byte-identical canonical rows. No usable
output is returned on failure. Unknown capability is an explicit invalid
request. Positive recursion refused by an acyclic reader is distinguished from
unsafe negative cycles through diagnostic-only positive-mode analysis; that
analysis never publishes a program. Normal replay and restore explicitly pass
`ACYCLIC`. #1506 owns any production opt-in and publication/security changes.

The v1 ordered rows and digest already represent recursive programs, so no
marker, migration or rewrite was introduced. The low-level writer remains
structural and transactional; it is not a semantic admission API. Its byte
limit includes separators, matching the compiler. The loader checks row counts
and byte limits before copying text, and refuses corrupt latest versions
instead of falling back. A failed second-row insertion leaves neither header
nor rows visible after reopening the policy database.

`fact-rule-pack-store` proves exact known-answer acyclic/recursive identities
across upgrade, close/reopen and SQLite policy backup/restore, mixed ordinary
and recursive graphs, corruption refusal and acyclic replacement preserving
recursive history. The standalone historical fixture compiles byte-exact
pre-#1504 compiler/renderer sources; a provenance test checks their SHA-256 and
Git blob hashes. Its new read-only SQL adapter and current Wirelog dependency
are explicitly narrower evidence than a full old daemon. Current production
replay separately proves graph-local recursive refusal across restart.

The secure-bridge `fact-offline-restore-stage-replay` test checks acyclic
identity preservation and recursive refusal without source/stage/pack changes.
Fact bundles do not transport policy rows; policy backup is a separate part of
the matching stopped-writer backup set. See the operator runbook's
[downgrade procedure](operator-runbook.md#rule-pack-storage-compatibility-and-downgrade).

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
