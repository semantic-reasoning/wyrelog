#!/usr/bin/env python3
"""Structural gate for fact-root writer authority and startup ordering."""

from pathlib import Path
import re
import sys


root = Path(sys.argv[1])
runtime_source = (root / "wyrelog/daemon/runtime.c").read_text(
    encoding="utf-8"
)
build = (root / "wyrelog/meson.build").read_text(encoding="utf-8")
handle = (root / "wyrelog/wyl-handle.c").read_text(encoding="utf-8")
handle_private = (root / "wyrelog/wyl-handle-private.h").read_text(
    encoding="utf-8"
)
fact_replay = (root / "wyrelog/fact/replay.c").read_text(encoding="utf-8")
policy_store = (root / "wyrelog/policy/store.c").read_text(encoding="utf-8")
posix = (root / "wyrelog/fact/root-writer-lease-private.c").read_text(
    encoding="utf-8"
)
windows = (root / "wyrelog/fact/graph-locator-windows-private.c").read_text(
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


def without_macro_branches(source: str, macro: str) -> str:
    """Blank branches that require @macro while retaining line layout."""
    output = []
    stack: list[tuple[bool, bool, bool]] = []
    enabled = True
    opener = re.compile(rf"#\s*(ifdef|ifndef)\s+{re.escape(macro)}\b")
    defined_opener = re.compile(
        rf"#\s*if\s+defined\s*\(\s*{re.escape(macro)}\s*\)")
    for line in source.splitlines(keepends=True):
        directive = line.lstrip()
        match = opener.match(directive)
        defined_match = defined_opener.match(directive)
        if match or defined_match:
            parent = enabled
            positive = defined_match is not None or match.group(1) == "ifdef"
            branch = not positive  # the macro is undefined in production
            stack.append((True, parent, branch))
            enabled = parent and branch
            output.append("\n" if line.endswith("\n") else "")
            continue
        if re.match(r"#\s*(if|ifdef|ifndef)\b", directive):
            stack.append((False, enabled, True))
        elif re.match(r"#\s*else\b", directive) and stack and stack[-1][0]:
            target, parent, branch = stack[-1]
            branch = not branch
            stack[-1] = (target, parent, branch)
            enabled = parent and branch
            output.append("\n" if line.endswith("\n") else "")
            continue
        elif re.match(r"#\s*endif\b", directive) and stack:
            target, parent, _branch = stack.pop()
            if target:
                enabled = parent
                output.append("\n" if line.endswith("\n") else "")
                continue
        output.append(line if enabled else ("\n" if line.endswith("\n") else ""))
    return "".join(output)


# The readiness override exists only in the non-installed compile-only daemon
# twin, so the installed daemon is the text that survives with the macro
# undefined.  Preprocess before extracting bodies so the ordering and
# authority gates below read what production wyrelogd actually contains.
READINESS_OVERRIDE = "WYL_TEST_PERSISTENT_READINESS_STORE"
runtime = without_macro_branches(runtime_source, READINESS_OVERRIDE)

open_runtime = body(runtime, "open_runtime_handle")
open_readiness = body(runtime, "open_readiness_handle")
open_handle = body(handle, "wyl_handle_open_with_options")
shutdown = body(handle, "wyl_handle_complete_shutdown")
replay_graphs = body(handle, "wyl_handle_replay_fact_graphs")
replay_policy_graphs = body(fact_replay, "wyl_fact_replay_policy_graphs")
authorized_bind = body(policy_store, "wyl_policy_store_bind_fact_root_authorized")
bind_locked = body(policy_store, "bind_fact_root_locked")

assert ".fact_root = opts->fact_root" in open_runtime
assert ".fact_root" not in open_readiness
assert ".policy_store_path = scratch_policy_store" in open_readiness

# Preprocessing the override away is only sound while the override cannot
# reach an installed binary.  The macro must stay confined to one non-installed
# compile-only twin, and the installed daemon must never receive it.
assert build.count(READINESS_OVERRIDE) == 1
twin_start = build.index(
    "wyrelogd_readiness_persistent_test_exe = executable("
)
twin = build[twin_start:build.index("\nendif", twin_start)]
assert f"-D{READINESS_OVERRIDE}" in twin
assert "install : false" in twin
assert "build_by_default : false" in twin
daemon_start = build.index("wyrelogd_exe = executable('wyrelogd',")
daemon = build[daemon_start:build.index("\n)\n", daemon_start)]
assert READINESS_OVERRIDE not in daemon
assert "install : true" in daemon
assert open_handle.index("wyl_fact_root_writer_lease_acquire") < open_handle.index(
    "wyl_policy_store_open_with_options"
)
assert open_handle.index("wyl_policy_store_open_with_options") < open_handle.index(
    "wyl_policy_store_bind_fact_root_authorized"
)
assert open_handle.index("wyl_policy_store_bind_fact_root_authorized") < open_handle.index(
    "wyl_policy_store_create_schema"
)
assert open_handle.index("wyl_policy_store_create_schema") < open_handle.index(
    "wyl_handle_replay_fact_graphs"
)
assert shutdown.index("wyl_fact_graph_runtime_manager_shutdown") < shutdown.index(
    "wyl_policy_store_close"
)
assert shutdown.index("wyl_policy_store_close") < shutdown.index(
    "wyl_fact_root_writer_lease_release"
)
assert "g_rec_mutex_locker_new (&store->graph_authority_mutex)" in authorized_bind
assert "bind_fact_root_locked (store, fact_root, lease)" in authorized_bind
assert "wyl_fact_root_writer_lease_authorizes_resolver" in bind_locked
assert "fact_graph_engines" not in handle
assert "fact_graph_statuses" not in handle
assert "fact_graphs_lock" not in handle
assert "wyl_handle_get_fact_graph_engine" not in handle
assert "wyl_handle_get_fact_graph_engine" not in handle_private
assert replay_graphs.index("g_mutex_lock (&self->fact_replay_coordinator_lock)") < replay_graphs.index(
    "wyl_handle_policy_store_pin_current"
)
assert replay_graphs.index("wyl_handle_policy_store_pin_current") < replay_graphs.index(
    "wyl_fact_replay_policy_graphs"
)
assert replay_graphs.index("wyl_fact_replay_policy_graphs") < replay_graphs.index(
    "wyl_handle_policy_store_unpin"
)
assert replay_graphs.index("wyl_handle_policy_store_unpin") < replay_graphs.rindex(
    "g_mutex_unlock (&self->fact_replay_coordinator_lock)"
)
assert replay_policy_graphs.index("wyl_policy_store_foreach_fact_graph") < replay_policy_graphs.index(
    "wyl_fact_graph_runtime_manager_refresh"
)
assert replay_policy_graphs.index("wyl_fact_graph_runtime_manager_refresh") < replay_policy_graphs.index(
    "wyl_fact_graph_runtime_manager_retire_unseen"
)

# POSIX uses one kernel namespace on the verified root directory itself.  It
# must never introduce a sidecar or silently fall back to process locks.
assert "flock (fd, LOCK_EX | LOCK_NB)" in posix
assert "lease->resolver.fd" in posix
assert "O_CREAT" not in posix
assert "fcntl" not in posix
assert "writer-lock" not in posix

# Windows uses one permanent, fixed-name root-relative artifact.  Share zero
# is the authority; the artifact is validated but never removed on release.
windows_acquire = body(windows, "open_root_writer_lock")
windows_release = body(windows, "wyl_fact_root_writer_lease_release")
assert 'L".wyrelog-writer-lock"' in windows_acquire
assert "attributes.RootDirectory = resolver->handle" in windows_acquire
assert "0, FILE_OPEN_IF" in windows_acquire
assert "FILE_OPEN_REPARSE_POINT" in windows_acquire
assert "validate_zero_length_regular" in windows_acquire
assert "validate_parent_entry" in windows_acquire
assert "CloseHandle" in windows_release
assert "DeleteFile" not in windows_release
assert "set_delete_disposition" not in windows_release

for public_header in (root / "wyrelog").glob("*.h"):
    assert "WylFactRootWriterLease" not in public_header.read_text(
        encoding="utf-8"
    )

print("fact root writer lease boundary: OK")
