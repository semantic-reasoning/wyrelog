# Recursive engine qualification

This is the executable capability handoff for #1503 to #1504, #1505 and #1506,
under #1502, extended with production activation evidence for #1506.
Production registration and replay now enable the qualified positive recursive
subset; unsafe negative cycles remain refused.

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
`-Db_sanitize=address,undefined -Dwirelog:b_sanitize=address,undefined`
and `-Dwirelog:b_lto=false` so the provider is instrumented too, and run with:

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
`WYL_FACT_RULE_PACK_ACYCLIC` for compatibility callers. Production registration,
replay and restore explicitly select positive recursion (#1506). This option
is neither authorization nor a storage format marker.

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
`fact-replay` additionally verifies that rejected negative-cycle replacements
leave the stored pack version, digest and rules unchanged. Normal replay
accepts valid stored positive recursive packs and refuses invalid packs.
No test-only raw compiler bypass is added.

## Stored reader compatibility (#1505)

`wyl_fact_rule_pack_compile_stored()` consumes counted canonical rows, version
and digest plus the exact selected schemas and an explicit #1504 mode. It
rechecks identity and the complete joined byte limit, compiles with schema and
safety validation, then requires byte-identical canonical rows. No usable
output is returned on failure. Unknown capability is an explicit invalid
request. Positive recursion refused by an acyclic reader is distinguished from
unsafe negative cycles through diagnostic-only positive-mode analysis; that
analysis never publishes a program. Normal replay and restore explicitly pass
`POSITIVE_RECURSION`; historical-reader tests retain `ACYCLIC`.

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
replay proves recursive recovery across restart and graph-local refusal of
invalid stored packs.

The secure-bridge `fact-offline-restore-stage-replay` test checks acyclic
and recursive identity preservation without source/stage/pack changes.
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
owns canonical storage and downgrade contracts. #1506 activates registration,
replay/publication, inference authorization, mutation/restore and isolation.
A demonstrated defect has a narrow tracked dependency (Wirelog #2345);
completion of the unrelated resource-control umbrella #1817 is not required.

## Production activation checks (#1506)

`fact-recursive-replay` compares relation-qualified exact sets with the shared independent
BFS oracle after append/retract/forget, alternate derivations and durable heads.
It covers empty seeds, cyclic inputs, nonlinear and mutual rules, stratified
negation, restart and supplied-store restore replay. The secure stage-reader
suite separately verifies recursive restore validation and unchanged artifact
and pack identities; validation itself does not run inference.

Deterministic query barriers cover first-pack publication, schema replacement
(two symbol columns to one int64 column), and seal draining on success/error.
The query decoder's namespace, relation, version and ordered column metadata
must match the pinned engine. A mismatch fails before evaluation. The engine
continues to own the generation's pack identity and input/model state.

`daemon-http-facts` exercises recursive registration, exact closure, repeated
reads, retract and forget through HTTP. Human query-only/infer-only denials
cover both base and derived relations. `daemon-http-recursive-credentials`
uses the test-only engine archive to count actual evaluator entries while
checking operation bits, issuer permissions, tenant/graph scope and lifecycle.
The ordinary production-linked credential tests remain in place. Denied
requests must not increment the evaluator counter; authorized controls do.

In the static hook build above, also run:

```sh
meson compile -C builddir-recursion-hooks test-fact-replay
builddir-recursion-hooks/tests/test-fact-replay -p /fact-replay/recursive/lazy-retry
```

This sets actual provider iteration limits during base and derived production
queries, requires an error and no JSON, then checks the complete set twice on
the same published generation after restoring limits. Synthetic snapshot
failure in the seal test proves admission cleanup only. No test or publication
step moves inference ahead of authorization, and no automatic rollback after
lazy evaluation failure is promised.

## Product qualification (#1507)

The product qualification baseline is Wyrelog
`6e052590f8e8fd57cf6d41f6c9be0b9e615e3f76` (including merged #1506 and the
subsequent checkpoint-WAL fixes). The Wirelog pin above is unchanged, with both
wrap patches applied. The test and workflow changes in the #1507 PR are part
of the candidate: baseline binaries alone do not exercise the new test.

`recursive-rule-packs-e2e` launches the actual production daemon and uses
`wyctl` and its linked client for graph/schema registration, fact mutations,
pack replacement and queries. The only direct HTTP operations are bootstrap
and authentication. It checks response graph/relation/columns, rejects
truncation and duplicate rows, and compares every tuple with an independent
BFS expected set. Queries use the registered allowlisted name (`reachable`);
rule definitions may qualify it as `shop.reachable`.

The fixture creates owner-only temporary keys and stores, clears ambient
`WIRELOG_*` evaluator settings, bounds child calls and readiness, and stops
and reaps the daemon before removing the complete temporary tree. Its stopped
backup includes the matching policy store, key, audit store and entire fact
root. It changes both facts and the active pack before restoring to the
original paths in place (retaining provisioned directory bindings), then proves the earlier facts and recursive behavior returned.
This exercises the runbook's **file-level disaster recovery**, not the separate
journaled `fact restore commit` protocol. The latter remains covered by the
secure restore suites and their platform restrictions.

### Reproducible commands and acceptance mapping

Use a feature-enabled build; missing test registrations are failures, not
qualification passes. A standard prebuilt profile is:

```sh
meson setup build-qualification --force-fallback-for=wirelog \
  -Denable_tpm=disabled -Denable_client=enabled \
  -Denable_fact_store=enabled -Denable_audit=enabled \
  -Denable_fault_injection=enabled -Dduckdb_source=prebuilt
meson compile -C build-qualification
meson test -C build-qualification --no-rebuild \
  engine-recursion fact-rule-pack fact-rule-pack-store fact-recursive-replay \
  fact-runtime daemon-http-facts daemon-http-recursive-credentials \
  recursive-rule-packs-e2e --logbase recursive-focused --print-errorlogs
meson test -C build-qualification --suite wyrelog \
  --logbase recursive-full --print-errorlogs
python3 tools/report-inactive-suites.py build-qualification
sh tools/check-format.sh --ledger
```

For source/secure qualification, configure another directory with
`-Dduckdb_source=subproject -Denable_secure_duckdb_bridge=enabled` and the same
feature flags, then also run `fact-offline-restore-stage-replay` and the full
suite. `report-inactive-suites.py --strict` must pass in this profile; the
prebuilt profile intentionally omits the secure bridge and cannot qualify its
restore routes. Run the static hook configuration above, including
`fact-recursive-replay`, separately with and without ASan/UBSan. Sanitizer
instrumentation of Wyrelog does not imply instrumentation of prebuilt DuckDB.

| Required behavior | Concrete test / exact assertion |
|---|---|
| Direct, mutual, nonlinear recursion; empty, duplicate, cyclic inputs; nontrivial chain | `engine-recursion`: independent BFS for 64 vertices, workers 0/1/2; `fact-recursive-replay` `/recursive/program-forms`, `/recursive/durable-lifecycle` |
| Stratified negation and rejected negative SCC diagnostics | `fact-rule-pack`; `/fact-replay/recursive/stratified-negation`; E2E requires `rule_pack_negative_cycle` and no consumed version |
| Two edges produce exactly three reachable tuples | E2E literal expected set `{(a,b),(b,c),(a,c)}`, plus base relation query |
| Retraction, alternate support, durable heads, forget, unchanged queries | E2E checks exact sets after each operation; durable replay additionally checks relation-qualified internal callbacks |
| Concurrent replacement and failed prepublication build | `/fact-replay/recursive/generation-races`, `fact-runtime`; pinned generation and previous usable engine assertions |
| Real lazy iteration failure, no successful incomplete response, retry | Static hook `engine-recursion` iteration-cap cases and `/fact-replay/recursive/lazy-retry`; absent hooks are not equivalent evidence |
| Startup and matching backup/restore | E2E stopped backup, changed live facts/pack, restored earlier model; `/fact-replay/recursive/restore-model`; secure `fact-offline-restore-stage-replay` |
| Downgrade and stored identity | `fact-rule-pack-store` with frozen legacy-reader executable; `rule-pack-legacy-fixture-provenance` |
| Human/data query and infer permissions, base reads, issuer checks | `daemon-http-facts`, `daemon-http-recursive-credentials`; denial asserts evaluator-entry counter unchanged, positive control increments it |
| Graph/tenant isolation and seal coordination | `/fact-replay/recursive/durable-lifecycle`, `/recursive/query-seal`, credential tests; deterministic barriers cover success and error drain |
| Growth and tenant-seal observations | E2E JSON records for chain/cycle/fanout at 8/16/32 vertices; exact sets checked before and after seal/unseal |

### Platform and backend evidence policy

Both `ci-pr.yml` and `ci-main.yml` explicitly run recursive tests in the POSIX
prebuilt and source/secure profiles and in feature-enabled Windows profiles.
The prebuilt profile also runs the full feature-enabled suite.
They retain `recursive-full`, `recursive-prebuilt`, `recursive-secure`, `recursive-windows`,
`recursive-sanitizer` and `recursive-hooks` Meson logs on success and failure.
The focused sanitizer job now includes the separately registered
`fact-recursive-replay`; `fact-replay` alone deliberately excludes that group.
A separate static hook build runs real iteration failure/retry under sanitizers.

| Platform/profile | Required evidence and limitations |
|---|---|
| Linux prebuilt, bridge off | Native semantic/credential tests, executable lifecycle, full feature-enabled suite; secure bridge tests are intentionally absent |
| Linux source, secure bridge on | Same recursive group plus secure restore validation; full feature-enabled suite |
| macOS prebuilt and source/secure | Named recursive group and executable lifecycle in hosted CI; Linux results cannot fill these rows |
| Windows prebuilt and source/secure | Named engine, compiler, durable replay and credential tests in native hosted CI. The subprocess lifecycle fixture is currently registered only on POSIX; native Windows daemon/wyctl lifecycle evidence remains incomplete |
| Hook-enabled static Linux | Real serial/TDD iteration-cap failures and complete retry, including production lazy retry |
| ASan/UBSan Linux | Focused recursive group and static hook run; any conditional skip is reported explicitly |

**Qualification is incomplete until actual hosted outcomes and the remaining
native Windows executable-lifecycle evidence are attached to #1502/#1507.**
CI wiring is a requirement to collect evidence, not a successful run. Do not
close either issue merely because local Linux checks pass. Journaled restore
commit remains Linux-only; macOS begin/prepare does not establish commit or
resume support. See the [restore runbook](fact-offline-restore-runbook.md).

### Interpreting the measurements

Each JSON record includes shape, vertex count, seed/result cardinalities,
configured production worker count (one), first query, unchanged query and
sequential tenant-seal elapsed seconds. Query time includes `wyctl` startup,
client/HTTP, authorization and result serialization. The fanout is a star;
chain results grow as `n*(n-1)/2`, cycle results as `n*n`, and fanout results as
`n-1`. Exact expected sets, not those formulas, determine test success.

Graphs accumulate in the dedicated tenant during this run, so seal timing
includes all graphs created so far. These are sequential observations, not
worst-case latency bounds or proof of cancellation during inference. The
separate deterministic query/seal barrier fixture supplies overlap evidence.
No timing threshold is asserted; subprocess and Meson timeouts are watchdogs.
Unchanged queries may reuse a model. Neither fast repeated reads nor the
registration size/response limits bound intermediate evaluation work.
