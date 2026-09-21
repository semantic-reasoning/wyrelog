#!/usr/bin/env python3
"""Smoke-check the documented cross-domain fact publication lock order."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
seal = (root / "wyrelog/fact/graph-seal-private.c").read_text(encoding="utf-8")
handle = (root / "wyrelog/wyl-handle.c").read_text(encoding="utf-8")
http = (root / "wyrelog/daemon/http.c").read_text(encoding="utf-8")
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
handle_unseal_execute = body(handle, "handle_replay_unseal_execute")
admission_acquire = body(handle, "wyl_handle_fact_replay_admission_acquire")
facts_route = body(http, "facts_route_handler")
policy_write_acquire = body(http, "wyl_daemon_policy_write_acquire")

# Fair scheduler admission is a separate API that callers must complete before
# acquiring their thread-affine service write lease. The lifecycle API accepts
# only an already-admitted token and cannot queue while that lease is held.
assert "handle_replay_caller_gate_enter" in admission_acquire
assert "handle_replay_caller_gate_enter" not in handle_unseal
assert "admission->context" in handle_unseal
for owner in (
    "WYL_DAEMON_POLICY_WRITE_OWNER_FACT_FORGET",
    "WYL_DAEMON_POLICY_WRITE_OWNER_FACT_PUBLICATION",
):
    owner_at = facts_route.index(owner)
    admission_at = facts_route.rfind(
        "wyl_handle_fact_replay_admission_acquire", 0, owner_at
    )
    prior_write_at = facts_route.rfind(
        "wyl_daemon_policy_write_acquire", 0, owner_at
    )
    assert admission_at >= 0 and prior_write_at > admission_at
assert "wyl_handle_refresh_fact_graph_admitted" in facts_route
assert "&lookup.info, replay_admission" in facts_route
assert policy_write_acquire.index("g_cancellable_connect") < \
    policy_write_acquire.index("wyl_service_auth_authority_acquire_write")
assert handle_unseal_execute.index(
    "wyl_fact_root_writer_lease_verify"
) < handle_unseal_execute.index(
    "g_mutex_lock (&self->fact_replay_coordinator_lock)"
)
assert handle_unseal_execute.index(
    "g_mutex_lock (&self->fact_replay_coordinator_lock)"
) < handle_unseal_execute.index("wyl_fact_graph_unseal_with_root_lease_bounded")

# The sequencer must retain the artifact lease through runtime publication,
# and must take the policy fence after the runtime writer has closed admission.
#
# The unseal path reaches the runtime writer through unseal_claim rather than
# publication_begin_closed: claim is the call that enters publication_begin_entry
# and takes writer_lock, while the prepare that precedes it only observes state
# and takes no lock.  The order being asserted is unchanged; only the name of
# the step that establishes the publication moved.
assert unseal.index("acquire_graph_artifact_lease") < unseal.index(
    "wyl_fact_graph_runtime_unseal_claim"
)
assert unseal.index(
    "wyl_fact_graph_runtime_unseal_claim"
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
