#!/usr/bin/env python3
"""Smoke-check the documented cross-domain fact publication lock order."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
seal = (root / "wyrelog/fact/graph-seal-private.c").read_text(encoding="utf-8")
handle = (root / "wyrelog/wyl-handle.c").read_text(encoding="utf-8")
runtime_header = (root / "wyrelog/fact/runtime-private.h").read_text(
    encoding="utf-8"
)


def body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"missing function {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function {name}")


unseal = body(seal, "wyl_fact_graph_unseal_core")
handle_unseal = body(handle, "wyl_handle_unseal_fact_graph")

# The handle's lifetime lease and coordinator precede the graph sequencer.
assert handle_unseal.index("wyl_fact_root_writer_lease_verify") < handle_unseal.index(
    "g_mutex_lock (&self->fact_replay_coordinator_lock)"
)
assert handle_unseal.index(
    "g_mutex_lock (&self->fact_replay_coordinator_lock)"
) < handle_unseal.index("wyl_fact_graph_unseal_with_root_lease")

# The sequencer must retain the artifact lease through runtime publication,
# and must take the policy fence after the runtime writer has closed admission.
assert unseal.index("acquire_graph_artifact_lease") < unseal.index(
    "wyl_fact_graph_runtime_publication_begin_closed"
)
assert unseal.index(
    "wyl_fact_graph_runtime_publication_begin_closed"
) < unseal.index("wyl_policy_store_graph_publication_fence_begin")
assert unseal.index(
    "wyl_fact_replay_refresh_graph_publication"
) < unseal.index("wyl_policy_store_graph_publication_fence_commit")

# All documented exits clear the policy fence before the artifact lease and
# namespace are released by the common finish path.
assert "wyl_policy_store_graph_publication_fence_clear (&fence)" in unseal
assert "wyl_fact_artifact_mutation_lease_free (artifact_lease)" in unseal

# Runtime comments are the source-level guard against recursive build entry;
# this boundary must not silently lose that explicit deadlock contract.
assert "Calling it from inside a build callback" in runtime_header
assert "deadlocks outright" in runtime_header
assert "writer_lock" in runtime_header
assert "state_lock" in runtime_header

print("fact publication lock-order boundary: OK")
