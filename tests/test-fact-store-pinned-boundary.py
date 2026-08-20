#!/usr/bin/env python3
"""Lock the pinned identity opener to typed, bounded storage authority."""

from pathlib import Path
import os
import shlex
import subprocess
import sys

root = Path(sys.argv[1])
core = (root / "wyrelog/fact/store-identity-private.c").read_text(
    encoding="utf-8"
)
bridge = (root / "wyrelog/fact/secure-duckdb-bridge-private.cc").read_text(
    encoding="utf-8"
)
header = (root / "wyrelog/fact/store-private.h").read_text(encoding="utf-8")
types = (
    root / "wyrelog/fact/store-identity-types-private.h"
).read_text(encoding="utf-8")
locator_types = (
    root / "wyrelog/fact/graph-locator-private.h"
).read_text(encoding="utf-8")
namespace_types = (
    root / "wyrelog/fact/graph-artifact-namespace-private.h"
).read_text(encoding="utf-8")

for forbidden in ("#include <duckdb.h>", "#include <duckdb.hpp>", "ToString"):
    if forbidden in core:
        raise SystemExit(f"pure-C identity core contains provider token: {forbidden}")

for required in (
    "WYL_FACT_STORE_IDENTITY_CELL_NULL",
    "WYL_FACT_STORE_IDENTITY_CELL_INT64",
    "WYL_FACT_STORE_IDENTITY_CELL_BYTES",
    "VALUES (?,?)",
    "BEGIN TRANSACTION;",
    "ROLLBACK;",
):
    if required not in core:
        raise SystemExit(f"typed identity core lost contract: {required}")

for forbidden in (
    "/proc/self/fd",
    "LocalFileSystem",
    "ToString",
    "wyl_fact_store_t **",
):
    if forbidden in bridge:
        raise SystemExit(f"pinned source adapter escaped its boundary: {forbidden}")

for required in (
    "connection->Prepare (sql)",
    "GetValue<int64_t>",
    "GetValue<duckdb::string>",
    "bridge_new_bounded",
    "bridge_populate_bounded",
    "DetachLeaseOwnership",
    "bridge_finalize_storage",
    "PinnedLifecycleResults",
    "reduce_pinned_lifecycle",
    "pinned_authority_revalidate",
    "wyl_fact_artifact_mutation_lease_revalidate",
    "WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT",
    "WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE",
    "wyl_fact_store_open_identified_provisioned_pair_pinned",
    "wyl_fact_artifact_namespace_open_provisioned_pair",
):
    if required not in bridge:
        raise SystemExit(f"pinned source adapter lost contract: {required}")

if "preserve_first_error" in bridge:
    raise SystemExit("pinned lifecycle collapsed distinct stage authority")

if "unsuitable" not in header or "security-sensitive provisioning" not in header:
    raise SystemExit("legacy pathname warning is missing")
if "returns no live DuckDB handle" not in types:
    raise SystemExit("pinned one-shot handle boundary is missing")
if "typedef struct WylFactGraphProvisionedPair" not in locator_types:
    raise SystemExit("retained-pair authority is not opaque")
if "wyl_fact_artifact_namespace_open_provisioned_pair" in namespace_types:
    raise SystemExit("operation pair escapes through the generic namespace API")
pair_declaration = types.split(
    "wyl_fact_store_open_identified_provisioned_pair_pinned", 1
)[1].split(";", 1)[0]
for forbidden in ("gchar", "gint", "WylFactGraphDirectory"):
    if forbidden in pair_declaration:
        raise SystemExit(
            f"pair handoff exposes raw or mutable authority: {forbidden}"
        )
if "WYL_FACT_STORE_IDENTITY_RESULT_OPEN" not in bridge:
    raise SystemExit("pinned identity result classification is missing")

if sys.platform != "win32":
    # pkg-config and the compiler emit output in the toolchain locale's
    # codec, which need not be UTF-8.  Name the codec explicitly so the read
    # never falls back to the machine locale, and pair it with a non-raising
    # error handler so a stray byte cannot crash the boundary check.  The
    # handler differs by what the text is used for:
    #
    #   - pkg-config --cflags is re-emitted as compiler argv, so it must
    #     round-trip byte-for-byte.  errors="surrogateescape" parks an
    #     undecodable byte in a lone surrogate that re-encodes to the very
    #     same byte, preserving a non-UTF-8 include path verbatim.
    #     errors="replace" would substitute U+FFFD and hand the compiler a
    #     path that does not exist, reporting a nonexistent -I directory as
    #     "sole operation entry does not compile".
    #   - the compile probes' stdout/stderr below are only ever shown to a
    #     human in a failure message, so errors="replace" is right there: a
    #     visible U+FFFD beats a lone surrogate that would itself raise on
    #     the way out to the terminal.
    cflags = subprocess.run(
        ["pkg-config", "--cflags", "glib-2.0"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
    ).stdout.split()
    compiler = shlex.split(os.environ.get("CC", "cc"))
    common = compiler + [
        "-std=c11",
        "-fsyntax-only",
        "-I",
        str(root),
        "-I",
        str(root / "wyrelog"),
        *cflags,
        "-x",
        "c",
        "-",
    ]
    positive = subprocess.run(
        common,
        input="""
#include "fact/store-identity-types-private.h"
static void consume(WylFactGraphProvisionedPair *pair,
                    const WylFactStoreIdentity *identity,
                    WylFactStoreIdentityResult *result) {
  (void) wyl_fact_store_open_identified_provisioned_pair_pinned(
      pair, identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, result);
}
""",
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if positive.returncode:
        raise SystemExit(
            "sole operation entry does not compile:\n" + positive.stderr
        )
    negative = subprocess.run(
        common
        + [
            "-Werror=implicit-function-declaration",
            "-Werror=incompatible-pointer-types",
        ],
        input="""
#include "fact/graph-artifact-namespace-private.h"
static void escape(WylFactGraphProvisionedPair *pair) {
  WylFactArtifactNamespace *namespace_ = 0;
  WylFactArtifactMutationLease *lease = 0;
  (void) wyl_fact_artifact_namespace_open_provisioned_pair(
      pair, &namespace_);
  (void) wyl_fact_artifact_namespace_acquire_reader_guard(pair, &lease);
}
""",
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if negative.returncode == 0:
        raise SystemExit("operation pair compiled against generic authority APIs")
