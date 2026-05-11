# GA Hardening Gates

This document defines the bounded release-confidence gates for the
decision hot path, fuzz harnesses, leak checking, sanitizer runs,
cold-start readiness, and dependency pinning.

## Decision Latency

`wyrelog:decision-latency` seeds a deterministic policy-store fixture and
measures repeated `wyl_decide` calls after warmup. The default CI smoke
uses a small sample count and intentionally conservative budgets so
hosted runners and audit-enabled builds do not create noise:

- `WYL_LATENCY_ITERATIONS=32`
- `WYL_LATENCY_P50_USEC=250000`
- `WYL_LATENCY_P95_USEC=750000`
- `WYL_LATENCY_P99_USEC=1000000`

Release candidates can tighten the same executable without changing the
code, for example:

```
WYL_LATENCY_ITERATIONS=5000 WYL_LATENCY_P99_USEC=5000 \
  meson test -C builddir wyrelog:decision-latency --print-errorlogs
```

## Bounded Fuzz

`wyrelog:hardening-fuzz` runs deterministic corpus generation for:

- decide request carriers and guard-context values;
- invalid and partial decision inputs;
- template loading with malformed fixed-order template trees.

Set `WYL_FUZZ_SEED` to reproduce a run. Set `WYL_FUZZ_ARTIFACT_DIR` to
preserve the last seed before each fuzz case, which gives CI/nightly jobs
a stable crash-reproduction hook.

## Valgrind

`tools/run-valgrind-gate.sh` wraps a test executable with:

- `--leak-check=full`
- `--show-leak-kinds=definite`
- `--errors-for-leak-kinds=definite`

The gate fails when definitely-lost bytes are nonzero. It exits with 77
when Valgrind is not installed so Meson reports a skip on unsupported
platforms.

## Sanitizers

`tools/run-sanitizer-suite.sh` configures a separate build directory with
AddressSanitizer and UndefinedBehaviorSanitizer flags, then runs the
requested Meson test set. ThreadSanitizer should be run in a separate
toolchain job because it is mutually noisy with ASan on common CI images.

## Cold-Start Readiness

`wyrelogd-startup-readiness` keeps the daemon fail-closed during policy
engine load failures. It distinguishes startup not-ready behavior from
ordinary HTTP authorization failures by proving the daemon does not serve
`/healthz` after a deliberately broken template tree fails `--check`.

## Supply Chain

`wyrelog:supply-chain-pins` verifies wrap metadata before release:

- file wraps must carry `source_url`, `source_filename`, `source_hash`,
  and `directory`;
- git wraps must carry `url` and `revision`;
- moving git revisions are rejected unless explicitly allowlisted for an
  in-family development dependency;
- vendored subprojects must carry LICENSE or NOTICE metadata;
- when `subprojects/packagecache` exists, missing platform archives are
  reported; set `WYL_SUPPLY_CHAIN_REQUIRE_PACKAGECACHE=1` to make partial
  cache coverage fail the gate.
