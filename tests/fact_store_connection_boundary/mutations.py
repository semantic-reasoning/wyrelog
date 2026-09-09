"""Mutation corpus and execution for the fact-store boundary contract."""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
import difflib
import hashlib
import multiprocessing
import os
import re
from pathlib import PureWindowsPath

from .contract import *


@dataclass(frozen=True)
class MutationCase:
    """A stable, pickleable description of one historical mutation fixture."""

    mutation_id: str
    old_index: int
    fingerprint: str
    files: dict[str, str]
    expected_error: str | None = None
    critical: bool = False
    label: str | None = None


def _mutation_fingerprint(
    baseline: dict[str, str], mutation: dict[str, str],
) -> str:
    digest = hashlib.sha256()
    for path, source in mutation_delta(baseline, mutation):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update((source or "<deleted>").encode("utf-8"))
    return digest.hexdigest()


def _stable_mutation_id(
    baseline: dict[str, str], mutation: dict[str, str], label: str | None,
) -> str:
    delta = mutation_delta(baseline, mutation)
    changed = "\n".join(source or "" for _path, source in delta).lower()
    categories = (
        ("meson-wiring", ("meson", "test-seam")),
        ("session-lifecycle", ("session", "release", "admission")),
        ("duckdb-authority", ("duckdb", "conn", "connection")),
        ("replay-lifetime", ("replay", "result", "provider")),
        ("header-contract", ("private.h", "#include", "header")),
    )
    category = next(
        (name for name, needles in categories
         if any(needle in changed for needle in needles)),
        "source-contract",
    )
    hints = []
    for path, source in delta:
        before = (baseline.get(path) or "").splitlines()
        after = (source or "").splitlines()
        locations = []
        matcher = difflib.SequenceMatcher(a=before, b=after, autojunk=False)
        for tag, before_start, before_end, after_start, after_end in matcher.get_opcodes():
            if tag != "equal":
                locations.append(
                    f"b{before_start + 1}-{before_end}/a{after_start + 1}-{after_end}"
                )
        changed_lines = [
            line[1:].strip() for line in difflib.ndiff(before, after)
            if line[:2] in {"+ ", "- "} and line[2:].strip()
        ]
        hint = "-".join(changed_lines)
        hint = re.sub(r"[^A-Za-z0-9]+", "-", hint).strip("-").lower()
        path_hint = re.sub(r"[^A-Za-z0-9]+", "-", path).strip("-").lower()
        location_hint = "-".join(locations) or "no-location"
        hints.append(f"{path_hint}-{location_hint}-{hint or 'deleted'}")
    semantic_hint = re.sub(
        r"[^A-Za-z0-9.-]+", "-", "-".join(hints)
    ).strip("-")
    if label is not None:
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")
        return f"critical.{safe_label}.{category}.{semantic_hint}"
    return f"mutation.{category}.{semantic_hint}"

_MUTATION_BASELINE: dict[str, str] | None = None


def initialize_mutation_worker(files: dict[str, str]) -> None:
    global _MUTATION_BASELINE
    _MUTATION_BASELINE = files


def mutation_delta(
    baseline: dict[str, str], mutation: dict[str, str],
) -> tuple[tuple[str, str | None], ...]:
    return tuple(
        (path, mutation.get(path))
        for path in sorted(baseline.keys() | mutation.keys())
        if baseline.get(path) != mutation.get(path)
    )


def mutation_validation_error(
    delta: tuple[tuple[str, str | None], ...],
) -> str | None:
    if _MUTATION_BASELINE is None:
        return "mutation worker has no baseline"
    files = dict(_MUTATION_BASELINE)
    for path, source in delta:
        if source is None:
            files.pop(path, None)
        else:
            files[path] = source
    try:
        validate(files)
    except AssertionError as error:
        return str(error)
    return None


def control_validation_error(
    delta: tuple[tuple[str, str | None], ...],
) -> str | None:
    # Safe controls are full contract validations too; execute them in the
    # same worker pool so the parent cannot serialize the CI budget.
    return mutation_validation_error(delta)


def source_key(root: PurePath, path: PurePath) -> str:
    return path.relative_to(root).as_posix()


def load(root: Path) -> dict[str, str]:
    paths = {
        ROLE_HEADER,
        CONFIG_SEAM_HEADER,
        "wyrelog/fact/store-test-seams-private.h",
        "wyrelog/fact/store-private.h",
        "wyrelog/fact/store.c",
        "wyrelog/fact/compound.c",
        "wyrelog/fact/replay.c",
        "wyrelog/fact/query.c",
        "tests/meson.build",
    }
    for directory in (root / "wyrelog", root / "tests"):
        for path in directory.rglob("*"):
            if path.suffix in {".c", ".h", ".cc", ".cpp"}:
                paths.add(source_key(root, path))
    return {path: (root / path).read_text(encoding="utf-8") for path in paths}


def self_test(files: dict[str, str]) -> None:
    mutations = []
    validation_controls = []
    critical_mutations = []

    windows_root = PureWindowsPath("C:/wyrelog")
    windows_source = windows_root / "wyrelog/fact/store.c"
    if source_key(windows_root, windows_source) != "wyrelog/fact/store.c":
        raise AssertionError("Windows source keys must use POSIX separators")

    for declaration in (
        "struct BoundaryItem { int member; };\n"
        "struct BoundaryItem boundary_value = {0};\n",
        "struct BoundaryItem { int member; };\n"
        "struct BoundaryItem boundary_value = {.member = 1};\n",
    ):
        control = dict(files)
        control["wyrelog/fact/store.c"] += "\n" + declaration
        validation_controls.append(control)

    safe_macro_controls = (
        "#if 0\n"
        "#define WYL_SAFE_REDEFINED(object) ((object)->conn)\n"
        "#endif\n"
        "#define WYL_SAFE_REDEFINED(value) (value)\n"
        "static int boundary_safe_value = WYL_SAFE_REDEFINED(0);\n",
        "#define WYL_SAFE_PASTE(left, right) left ## right\n"
        "static int WYL_SAFE_PASTE(boundary_, value) = 0;\n",
        "#define WYL_GET_VALUE(object) ((object)->value)\n"
        "struct BoundaryValue { int value; };\n"
        "static struct BoundaryValue boundary_object = {0};\n"
        "static int boundary_member(void) { "
        "return WYL_GET_VALUE(&boundary_object); }\n",
        "#if (0)\n"
        "#define WYL_PAREN_SAFE(object) ((object)->conn)\n"
        "#else\n"
        "#define WYL_PAREN_SAFE(value) (value)\n"
        "#endif\n"
        "static int boundary_parenthesized = WYL_PAREN_SAFE(0);\n",
        "#define WYL_STRING_ONLY(value) \"->conn\"\n"
        "static const char *boundary_string = WYL_STRING_ONLY(ignored);\n",
        "#define WYL_STRINGIFY(value) #value\n"
        "static const char *boundary_stringified = "
        "WYL_STRINGIFY(store->conn);\n",
        "#define WYL_INNER_STRINGIFY(value) #value\n"
        "#define WYL_OUTER_STRINGIFY(value) WYL_INNER_STRINGIFY(value)\n"
        "static const char *boundary_indirect_stringified = "
        "WYL_OUTER_STRINGIFY(store->conn);\n",
        "static const char *boundary_type_string = \"duckdb_connection\";\n"
        "/* duckdb_database is documented here. */\n",
        "#if 0\n"
        "static gpointer boundary_inactive_raw(wyl_fact_store_t *store) "
        "{ return store->conn; }\n"
        "#endif\n",
        "#if 1\n"
        "static int boundary_active_branch = 1;\n"
        "#else\n"
        "static gpointer boundary_dead_else(wyl_fact_store_t *store) "
        "{ return store->conn; }\n"
        "#endif\n",
    )
    for source in safe_macro_controls:
        control = dict(files)
        control["wyrelog/fact/store.c"] += "\n" + source
        validation_controls.append(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    replay_marker = "static wyrelog_error_t\nlist_replay_relations"
    safe_collision = (
        "static wyrelog_error_t\n"
        "reject_audit_database_unlocked (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n  return WYRELOG_E_OK;\n}\n\n"
        "static wyrelog_error_t\n"
        "boundary_safe_collision_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return reject_audit_database_unlocked (store);\n}\n\n"
    )
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_collision + replay_marker, 1
    ).replace(
        replay_admission,
        "  (void) boundary_safe_collision_wrapper (store);\n"
        + replay_admission,
        1,
    )
    validation_controls.append(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    local_alias_target = (
        "static void\n"
        "boundary_safe_session_alias_target (void)\n"
        "{\n}\n\n"
    )
    local_safe_alias = (
        "  {\n"
        "    void (*wyl_fact_store_close) (void) = "
        "boundary_safe_session_alias_target;\n"
        "    wyl_fact_store_close ();\n"
        "  }\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_target + replay_marker, 1
    ).replace(
        replay_admission, local_safe_alias + replay_admission, 1
    )
    validation_controls.append(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    safe_for_alias = (
        "  for (void (*wyl_fact_store_close) (void) = "
        "boundary_safe_session_alias_target; FALSE;)\n"
        "    wyl_fact_store_close ();\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_target + replay_marker, 1
    ).replace(
        replay_admission, safe_for_alias + replay_admission, 1
    )
    validation_controls.append(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    safe_assignment_target = (
        "static void\n"
        "boundary_safe_assignment_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_assignment_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_assignment_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    boundary_assignment_alias = "
        "boundary_safe_assignment_target;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_assignment_alias (store);\n",
        1,
    )
    validation_controls.append(control)

    control = dict(files)
    control["tests/test-fact-store.c"] += (
        "\n#if 0\n"
        "#define WYL_UNRELATED_SAFE(object) ((object)->conn)\n"
        "#endif\n"
    )
    control["wyrelog/fact/store.c"] += (
        "\n#define WYL_UNRELATED_SAFE(value) (value)\n"
        "static int boundary_unrelated_value = WYL_UNRELATED_SAFE(0);\n"
    )
    validation_controls.append(control)

    control = dict(files)
    control["wyrelog/fact/stringify-boundary.h"] = (
        "#define WYL_HEADER_STRINGIFY(value) #value\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "stringify-boundary.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic const char *boundary_header_stringified = "
        "WYL_HEADER_STRINGIFY(store->conn);\n"
    )
    validation_controls.append(control)

    control = dict(files)
    control["wyrelog/fact/session-stringify-boundary.h"] = (
        "#define WYL_SESSION_STRINGIFY(value) #value\n"
    )
    replay_source = control["wyrelog/fact/replay.c"]
    relation_at = replay_source.index("list_replay_relations")
    session_at = replay_source.index(
        "WylFactStoreConnectionSession session = { 0 };", relation_at
    )
    control["wyrelog/fact/replay.c"] = (
        '#include "session-stringify-boundary.h"\n'
        + replay_source[:session_at]
        + "const char *boundary_text = "
        "WYL_SESSION_STRINGIFY(store->conn);\n  "
        + replay_source[session_at:]
    )
    validation_controls.append(control)

    control = dict(files)
    control["wyrelog/fact/recursive-stringify-inner.h"] = (
        "#define WYL_RECURSIVE_STRINGIFY(value) #value\n"
    )
    control["wyrelog/fact/recursive-stringify-outer.h"] = (
        '#define WYL_RECURSIVE_HEADER "recursive-stringify-inner.h"\n'
        "#include WYL_RECURSIVE_HEADER\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "recursive-stringify-outer.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic const char *boundary_recursive_stringified = "
        "WYL_RECURSIVE_STRINGIFY(store->conn);\n"
    )
    validation_controls.append(control)

    control = dict(files)
    control["wyrelog/fact/pragma-once-boundary.h"] = (
        "#pragma once\n"
        "#ifndef WYL_PRAGMA_ONCE_SEEN\n"
        "#define WYL_PRAGMA_ONCE_SEEN 1\n"
        "#define WYL_PRAGMA_ONCE_VALUE(value) (value)\n"
        "#else\n"
        "#define WYL_PRAGMA_ONCE_VALUE(object) ((object)->conn)\n"
        "#endif\n"
    )
    control["wyrelog/fact/store.c"] = (
        '#include "pragma-once-boundary.h"\n'
        '#include "pragma-once-boundary.h"\n'
        + control["wyrelog/fact/store.c"]
        + "\nstatic int boundary_pragma_once = WYL_PRAGMA_ONCE_VALUE(0);\n"
    )
    validation_controls.append(control)

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    relation_at = replay_source.index("list_replay_relations")
    session_at = replay_source.index(
        "WylFactStoreConnectionSession session = { 0 };", relation_at
    )
    control["wyrelog/fact/replay.c"] = (
        replay_source[:session_at]
        + 'const gchar *boundary_text = "} store->conn";\n  '
        + "(void) boundary_text;\n  " + replay_source[session_at:]
    )
    validation_controls.append(control)

    control = dict(files)
    control["wyrelog/fact/replay.c"] = control[
        "wyrelog/fact/replay.c"
    ].replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "boundary_cleanup:\n"
        "  wyl_fact_store_connection_session_end (&session);\n",
        1,
    )
    validation_controls.append(control)

    def require_boundary_rejection(
        label: str, expected: str, mutation: dict[str, str],
    ) -> None:
        critical_mutations.append((label, expected, mutation))

    source = files["wyrelog/fact/store.c"]

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    replay_marker = "static wyrelog_error_t\nlist_replay_relations"
    for label, declarations, call in (
        (
            "copied-alias-retains-raw-authority",
            "  void (*boundary_source) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            "  void (*boundary_copy) (wyl_fact_store_t *) = boundary_source;\n",
            "  boundary_copy (store);\n",
        ),
        (
            "partial-array-write-retains-other-element-authority",
            "  void (*boundary_slots[2]) (wyl_fact_store_t *) = "
            "{ wyl_fact_store_close, NULL };\n"
            "  boundary_slots[1] = NULL;\n",
            "  boundary_slots[0] (store);\n",
        ),
    ):
        changed = dict(files)
        store_source = changed["wyrelog/fact/store.c"]
        function_at = store_source.index("\nwyl_fact_store_test_exec_sql (")
        changed["wyrelog/fact/store.c"] = store_source[:function_at] + store_source[
            function_at:
        ].replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            declarations
            + "  wyl_fact_store_connection_session_end (&session);\n" + call,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "stale DuckDB authority used after session end", changed
        )
    changed = dict(files)
    local_alias_shadow = (
        "static void\n"
        "boundary_safe_alias_target (void)\n"
        "{\n}\n\n"
        "static void\n"
        "boundary_unrelated_local_alias (void)\n"
        "{\n"
        "  void (*wyl_fact_store_close) (void) = "
        "boundary_safe_alias_target;\n"
        "  wyl_fact_store_close ();\n"
        "}\n\n"
    )
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, local_alias_shadow + replay_marker, 1
    ).replace(
        replay_admission,
        "  wyl_fact_store_close (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-alias-must-not-shadow-cross-function-raw-call",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    expired_alias_wrapper = (
        "static void\n"
        "boundary_expired_alias_target (void)\n"
        "{\n}\n\n"
        "static void\n"
        "boundary_expired_alias_wrapper (wyl_fact_store_t *store)\n"
        "{\n"
        "  {\n"
        "    void (*wyl_fact_store_close) (void) = "
        "boundary_expired_alias_target;\n"
        "    wyl_fact_store_close ();\n"
        "  }\n"
        "  wyl_fact_store_close (store);\n"
        "}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, expired_alias_wrapper + replay_marker, 1
    ).replace(
        replay_admission,
        "  boundary_expired_alias_wrapper (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "block-local-alias-must-expire-before-external-raw-call",
        "session authority precedes successful admission",
        changed,
    )

    for label, loop_body in (
        (
            "braced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "    {\n"
            "      wyl_fact_store_close ();\n"
            "    }\n",
        ),
        (
            "unbraced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "    wyl_fact_store_close ();\n",
        ),
        (
            "labeled-braced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "boundary_for_body:\n"
            "    {\n"
            "      wyl_fact_store_close ();\n"
            "    }\n",
        ),
        (
            "labeled-unbraced",
            "  for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE;)\n"
            "boundary_for_body:\n"
            "    wyl_fact_store_close ();\n",
        ),
        (
            "case-braced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      case 0:\n"
            "        {\n"
            "          wyl_fact_store_close ();\n"
            "        }\n",
        ),
        (
            "case-unbraced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      case 0:\n"
            "        wyl_fact_store_close ();\n",
        ),
        (
            "default-braced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      default:\n"
            "        {\n"
            "          wyl_fact_store_close ();\n"
            "        }\n",
        ),
        (
            "default-unbraced",
            "  switch (1)\n"
            "    for (void (*wyl_fact_store_close) (void) = "
            "boundary_safe_for_target; FALSE; "
            "(void) wyl_fact_store_close)\n"
            "      default:\n"
            "        wyl_fact_store_close ();\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        for_alias_wrapper = (
            "static void\n"
            "boundary_safe_for_target (void)\n"
            "{\n}\n\n"
            "static void\n"
            "boundary_for_alias_wrapper (wyl_fact_store_t *store)\n"
            "{\n"
            + loop_body
            + "  wyl_fact_store_close (store);\n"
            "}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, for_alias_wrapper + replay_marker, 1
        ).replace(
            replay_admission,
            "  boundary_for_alias_wrapper (store);\n" + replay_admission,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"for-{label}-local-alias-must-expire-after-loop",
            "session authority precedes successful admission",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_close_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_close_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, designator in (
        ("parenthesized", "(wyl_fact_store_close)"),
        ("addressed", "&wyl_fact_store_close"),
        ("dereferenced", "(*wyl_fact_store_close)"),
        ("nested-address-dereference", "*(&wyl_fact_store_close)"),
        (
            "cast",
            "(void (*)(wyl_fact_store_t *)) wyl_fact_store_close",
        ),
        (
            "cast-parenthesized",
            "(void (*)(wyl_fact_store_t *)) (wyl_fact_store_close)",
        ),
    ):
        for operation in ("declaration", "assignment"):
            changed = dict(files)
            if operation == "declaration":
                alias_setup = (
                    "  void (*boundary_designator_alias) "
                    "(wyl_fact_store_t *) = " + designator + ";\n"
                )
            else:
                alias_setup = (
                    "  void (*boundary_designator_alias) "
                    "(wyl_fact_store_t *) = boundary_safe_designator_target;\n"
                    "  boundary_designator_alias = " + designator + ";\n"
                )
            replay_source = changed["wyrelog/fact/replay.c"]
            safe_designator_target = (
                "static void\n"
                "boundary_safe_designator_target (wyl_fact_store_t *store)\n"
                "{\n  (void) store;\n}\n\n"
            )
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                replay_marker, safe_designator_target + replay_marker, 1
            ).replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                alias_setup
                + "  wyl_fact_store_connection_session_end (&session);\n"
                "  boundary_designator_alias (store);\n",
                1,
            )
            mutations.append(changed)
            require_boundary_rejection(
                f"{label}-raw-alias-{operation}-after-session-release",
                "stale DuckDB authority used after session end",
                changed,
            )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    typedef_shadow_target = (
        "static void\n"
        "boundary_safe_typedef_shadow_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryClose) (wyl_fact_store_t *);\n"
        "  BoundaryClose boundary_typedef_alias = wyl_fact_store_close;\n"
        "  {\n"
        "    BoundaryClose boundary_typedef_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_typedef_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_typedef_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "typedef-alias-inner-shadow-must-preserve-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryQualifiedClose) (wyl_fact_store_t *);\n"
        "  volatile BoundaryQualifiedClose boundary_qualified_alias = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    volatile BoundaryQualifiedClose boundary_qualified_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_qualified_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_qualified_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "qualified-typedef-inner-shadow-preserves-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, typedef_shadow_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  typedef void (*BoundaryAtomicClose) (wyl_fact_store_t *);\n"
        "  _Atomic(BoundaryAtomicClose) boundary_atomic_alias = "
        "wyl_fact_store_close;\n"
        "  {\n"
        "    _Atomic(BoundaryAtomicClose) boundary_atomic_alias = "
        "boundary_safe_typedef_shadow_target;\n"
        "    (void) boundary_atomic_alias;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_atomic_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "atomic-typedef-inner-shadow-preserves-outer-raw-target",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, declarations in (
        (
            "raw-first",
            "  BoundaryAlias boundary_multi_alias = wyl_fact_store_close,\n"
            "      boundary_multi_safe = boundary_safe_multi_target;\n"
            "  (void) boundary_multi_safe;\n",
        ),
        (
            "raw-last",
            "  BoundaryAlias boundary_multi_safe = "
            "boundary_safe_multi_target,\n"
            "      boundary_multi_alias = wyl_fact_store_close;\n"
            "  (void) boundary_multi_safe;\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_multi_target = (
            "typedef void (*BoundaryAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_multi_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_multi_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            declarations
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_multi_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"multi-declarator-{label}-raw-alias-after-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker,
        "typedef void (*BoundaryArrayAlias) (wyl_fact_store_t *);\n\n"
        + replay_marker,
        1,
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryArrayAlias boundary_aliases[] = "
        "{ wyl_fact_store_close };\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_aliases[0] (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-array-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, initializer, invocation in (
        (
            "raw-second",
            "{ boundary_safe_array_target, wyl_fact_store_close }",
            "boundary_aliases[1] (store);",
        ),
        (
            "nested-raw-second",
            "{ { boundary_safe_array_target, wyl_fact_store_close } }",
            "boundary_aliases[0][1] (store);",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        array_support = (
            "typedef void (*BoundaryNestedArrayAlias) "
            "(wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_array_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        dimensions = "[][2]" if label.startswith("nested") else "[]"
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, array_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  BoundaryNestedArrayAlias boundary_aliases"
            + dimensions + " = " + initializer + ";\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  " + invocation + "\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"local-array-{label}-called-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    dispatch_type = (
        "typedef struct\n"
        "{\n  void (*call) (wyl_fact_store_t *);\n}\n"
        "BoundaryDispatch;\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, dispatch_type + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryDispatch boundary_dispatch = "
        "{ wyl_fact_store_close };\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_dispatch.call (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "local-aggregate-raw-alias-called-after-session-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for kind, support, declaration, lvalue in (
        (
            "indexed",
            "typedef void (*BoundaryAssignedAlias) (wyl_fact_store_t *);\n",
            "BoundaryAssignedAlias boundary_assigned_alias[] = "
            "{ boundary_safe_assigned_target };",
            "boundary_assigned_alias[0]",
        ),
        (
            "member",
            "typedef struct\n"
            "{\n  void (*call) (wyl_fact_store_t *);\n}\n"
            "BoundaryAssignedDispatch;\n",
            "BoundaryAssignedDispatch boundary_assigned_alias = "
            "{ boundary_safe_assigned_target };",
            "boundary_assigned_alias.call",
        ),
    ):
        for flow, prefix in (
            ("unconditional", ""),
            ("conditional", "if (store != NULL)\n    "),
        ):
            changed = dict(files)
            replay_source = changed["wyrelog/fact/replay.c"]
            assignment_support = (
                support
                + "static void\n"
                "boundary_safe_assigned_target (wyl_fact_store_t *store)\n"
                "{\n  (void) store;\n}\n\n"
            )
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                replay_marker, assignment_support + replay_marker, 1
            ).replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                "  " + declaration + "\n"
                "  " + prefix + lvalue + " = wyl_fact_store_close;\n"
                "  wyl_fact_store_connection_session_end (&session);\n"
                "  " + lvalue + " (store);\n",
                1,
            )
            mutations.append(changed)
            require_boundary_rejection(
                f"{flow}-{kind}-raw-assignment-after-session-release",
                "stale DuckDB authority used after session end",
                changed,
            )

    for label, declaration, lvalue, invocation in (
        (
            "parenthesized",
            "BoundaryLvalueAlias boundary_lvalue_alias = "
            "boundary_safe_lvalue_target;",
            "(boundary_lvalue_alias)",
            "boundary_lvalue_alias (store);",
        ),
        (
            "nested-parenthesized",
            "BoundaryLvalueAlias boundary_lvalue_alias = "
            "boundary_safe_lvalue_target;",
            "((boundary_lvalue_alias))",
            "boundary_lvalue_alias (store);",
        ),
        (
            "parenthesized-indexed",
            "BoundaryLvalueAlias boundary_lvalue_alias[] = "
            "{ boundary_safe_lvalue_target };",
            "(boundary_lvalue_alias)[0]",
            "(boundary_lvalue_alias)[0] (store);",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        lvalue_support = (
            "typedef void (*BoundaryLvalueAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_lvalue_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, lvalue_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  " + declaration + "\n"
            "  " + lvalue + " = wyl_fact_store_close;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  " + invocation + "\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-lvalue-assignment-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    chain_support = (
        "typedef void (*BoundaryChainAlias) (wyl_fact_store_t *);\n"
        "static void\n"
        "boundary_safe_chain_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, chain_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryChainAlias boundary_chain_first = "
        "boundary_safe_chain_target;\n"
        "  BoundaryChainAlias boundary_chain_second = "
        "boundary_safe_chain_target;\n"
        "  boundary_chain_first = boundary_chain_second = "
        "wyl_fact_store_close;\n"
        "  (void) boundary_chain_first;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_chain_second (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "chained-raw-assignment-reaches-second-alias-after-release",
        "stale DuckDB authority used after session end",
        changed,
    )

    for flow, prefix, slot_initializer, extra_pointer, lvalue in (
        (
            "direct", "", "&boundary_pointer_alias", "",
            "*boundary_pointer_slot",
        ),
        (
            "conditional", "if (store != NULL)\n    ",
            "&boundary_pointer_alias", "",
            "*boundary_pointer_slot",
        ),
        (
            "indexed", "", "&boundary_pointer_alias", "",
            "boundary_pointer_slot[0]",
        ),
        (
            "parenthesized-dereference", "", "&boundary_pointer_alias", "",
            "*(boundary_pointer_slot)",
        ),
        (
            "zero-offset-dereference", "", "&boundary_pointer_alias", "",
            "*(boundary_pointer_slot + 0)",
        ),
        (
            "ternary-retarget", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias boundary_pointer_second = "
            "boundary_safe_pointer_target;\n"
            "  boundary_pointer_slot = store == NULL ? "
            "&boundary_pointer_second : boundary_pointer_slot;\n",
            "*boundary_pointer_slot",
        ),
        (
            "short-circuit-retarget", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias boundary_pointer_second = "
            "boundary_safe_pointer_target;\n"
            "  (store == NULL) && "
            "(boundary_pointer_slot = &boundary_pointer_second);\n",
            "*boundary_pointer_slot",
        ),
        (
            "cast-address", "", "(BoundaryPointerAlias *) "
            "(&boundary_pointer_alias)", "", "*boundary_pointer_slot",
        ),
        (
            "multi-level", "", "&boundary_pointer_alias",
            "  BoundaryPointerAlias **boundary_pointer_outer = "
            "&boundary_pointer_slot;\n",
            "**boundary_pointer_outer",
        ),
        (
            "after-inner-shadow", "", "&boundary_pointer_alias",
            "  {\n"
            "    BoundaryPointerAlias boundary_pointer_inner = "
            "boundary_safe_pointer_target;\n"
            "    BoundaryPointerAlias *boundary_pointer_slot = "
            "&boundary_pointer_inner;\n"
            "    (void) boundary_pointer_slot;\n"
            "  }\n",
            "*boundary_pointer_slot",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        pointer_support = (
            "typedef void (*BoundaryPointerAlias) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_pointer_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        pointer_body = (
            "  BoundaryPointerAlias boundary_pointer_alias = "
            "boundary_safe_pointer_target;\n"
            "  BoundaryPointerAlias *boundary_pointer_slot = "
            f"{slot_initializer};\n"
            f"{extra_pointer}"
            f"  {prefix}{lvalue} = wyl_fact_store_close;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_pointer_alias (store);\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, pointer_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            pointer_body,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{flow}-pointer-write-propagates-to-post-release-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    control = dict(files)
    replay_source = control["wyrelog/fact/replay.c"]
    pointer_retarget_support = (
        "typedef void (*BoundaryPointerRetargetAlias) (wyl_fact_store_t *);\n"
        "static void\n"
        "boundary_safe_pointer_retarget (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    pointer_retarget_body = (
        "  BoundaryPointerRetargetAlias boundary_pointer_outer = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias *boundary_pointer_shadow = "
        "&boundary_pointer_outer;\n"
        "  {\n"
        "    BoundaryPointerRetargetAlias boundary_pointer_inner = "
        "boundary_safe_pointer_retarget;\n"
        "    BoundaryPointerRetargetAlias *boundary_pointer_shadow = "
        "&boundary_pointer_inner;\n"
        "    *boundary_pointer_shadow = wyl_fact_store_close;\n"
        "  }\n"
        "  BoundaryPointerRetargetAlias boundary_pointer_first = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias boundary_pointer_second = "
        "boundary_safe_pointer_retarget;\n"
        "  BoundaryPointerRetargetAlias *boundary_pointer_retarget = "
        "&boundary_pointer_first;\n"
        "  boundary_pointer_retarget = &boundary_pointer_second;\n"
        "  *boundary_pointer_retarget = wyl_fact_store_close;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_pointer_outer (store);\n"
        "  boundary_pointer_first (store);\n"
    )
    control["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, pointer_retarget_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        pointer_retarget_body,
        1,
    )
    validation_controls.append(control)

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    pointer_declaration_support = (
        "typedef void (*BoundaryPointerDeclarationAlias) "
        "(wyl_fact_store_t *);\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, pointer_declaration_support + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  BoundaryPointerDeclarationAlias boundary_pointer_raw = "
        "wyl_fact_store_close;\n"
        "  BoundaryPointerDeclarationAlias *boundary_pointer_declaration = "
        "&boundary_pointer_raw;\n"
        "  (void) boundary_pointer_declaration;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_pointer_raw (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "pointer-declaration-does-not-reset-raw-alias",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, callee in (
        (
            "raw-first",
            "store != NULL ? boundary_conditional_raw : "
            "boundary_conditional_safe",
        ),
        (
            "raw-last",
            "store == NULL ? boundary_conditional_safe : "
            "boundary_conditional_raw",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        callee_support = (
            "typedef void (*BoundaryConditionalCallee) (wyl_fact_store_t *);\n"
            "static void\n"
            "boundary_safe_conditional_callee (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, callee_support + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  BoundaryConditionalCallee boundary_conditional_raw = "
            "wyl_fact_store_close;\n"
            "  BoundaryConditionalCallee boundary_conditional_safe = "
            "boundary_safe_conditional_callee;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  (" + callee + ") (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"conditional-callee-{label}-raw-after-session-release",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    inner_assignment_target = (
        "static void\n"
        "boundary_safe_inner_assignment_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, inner_assignment_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_inner_assignment_alias) (wyl_fact_store_t *) = "
        "boundary_safe_inner_assignment_target;\n"
        "  {\n"
        "    boundary_inner_assignment_alias = wyl_fact_store_close;\n"
        "  }\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_inner_assignment_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "inner-block-raw-assignment-persists-after-block",
        "stale DuckDB authority used after session end",
        changed,
    )

    for label, reassignment in (
        (
            "conditional",
            "  if (FALSE)\n"
            "    boundary_conditional_alias = "
            "boundary_safe_conditional_target;\n",
        ),
        (
            "inactive",
            "#if 0\n"
            "  boundary_conditional_alias = "
            "boundary_safe_conditional_target;\n"
            "#endif\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_conditional_target = (
            "static void\n"
            "boundary_safe_conditional_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_conditional_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_conditional_alias) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            + reassignment
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_conditional_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-safe-reassignment-must-not-hide-raw-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, expression in (
        (
            "deterministic-ternary",
            "FALSE ? boundary_safe_expression_target : "
            "wyl_fact_store_close",
        ),
        (
            "runtime-ternary",
            "store == NULL ? boundary_safe_expression_target : "
            "wyl_fact_store_close",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_expression_target = (
            "static void\n"
            "boundary_safe_expression_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_expression_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_expression_alias) (wyl_fact_store_t *) = "
            "boundary_safe_expression_target;\n"
            "  boundary_expression_alias = " + expression + ";\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_expression_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-target-reaches-post-release-alias-call",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, condition in (
        ("inactive", "FALSE"),
        ("runtime-conditional", "store == NULL"),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_comma_target = (
            "static void\n"
            "boundary_safe_comma_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_comma_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_comma_alias) (wyl_fact_store_t *) = "
            "wyl_fact_store_close;\n"
            "  if (" + condition + ")\n"
            "    (void) 0, boundary_comma_alias = "
            "boundary_safe_comma_target;\n"
            "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_comma_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-comma-safe-assignment-must-not-hide-raw-alias",
            "stale DuckDB authority used after session end",
            changed,
        )

    for label, branches in (
        (
            "unbraced-if-else",
            "  if (TRUE)\n"
            "    boundary_branch_alias = wyl_fact_store_close;\n"
            "  else\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n",
        ),
        (
            "braced-if-else",
            "  if (TRUE)\n"
            "    { boundary_branch_alias = wyl_fact_store_close; }\n"
            "  else\n"
            "    { boundary_branch_alias = "
            "boundary_safe_branch_target; }\n",
        ),
        (
            "nested-else-if",
            "  if (FALSE)\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n"
            "  else if (TRUE)\n"
            "    boundary_branch_alias = wyl_fact_store_close;\n"
            "  else\n"
            "    boundary_branch_alias = boundary_safe_branch_target;\n",
        ),
    ):
        changed = dict(files)
        replay_source = changed["wyrelog/fact/replay.c"]
        safe_branch_target = (
            "static void\n"
            "boundary_safe_branch_target (wyl_fact_store_t *store)\n"
            "{\n  (void) store;\n}\n\n"
        )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            replay_marker, safe_branch_target + replay_marker, 1
        ).replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            "  void (*boundary_branch_alias) (wyl_fact_store_t *) = "
            "boundary_safe_branch_target;\n"
            + branches
            + "  wyl_fact_store_connection_session_end (&session);\n"
            "  boundary_branch_alias (store);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-raw-branch-must-reach-post-release-call",
            "stale DuckDB authority used after session end",
            changed,
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    safe_goto_target = (
        "static void\n"
        "boundary_safe_goto_target (wyl_fact_store_t *store)\n"
        "{\n  (void) store;\n}\n\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        replay_marker, safe_goto_target + replay_marker, 1
    ).replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  void (*boundary_goto_alias) (wyl_fact_store_t *) = "
        "wyl_fact_store_close;\n"
        "  goto boundary_goto_release;\n"
        "  boundary_goto_alias = boundary_safe_goto_target;\n"
        "boundary_goto_release:\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  boundary_goto_alias (store);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "forward-goto-skips-safe-alias-assignment",
        "stale DuckDB authority used after session end",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION, &transaction",
        "WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-transaction-kind-removed",
        "transaction owner kind drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}\n\n"
        "/* Retire an intent",
        "finish:\n  return rc;\n}\n\n/* Retire an intent",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-common-finish-bypass",
        "forget migration cleanup drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-direct-return",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-failure-edge-removed",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  rc = WYRELOG_E_OK;\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-body-result-overwritten",
        "forget migration body sequence drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  if (rc != WYRELOG_E_OK) {\n"
        "    transaction.open = FALSE;\n"
        "    goto finish;\n"
        "  }\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-transaction-disarmed",
        "forget migration references transaction outside owner calls",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  WylFactStoreTransaction transaction = { 0 };\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION,",
        "  WylFactStoreTransaction transaction = { 0 };\n"
        "  WylFactStoreTransaction *owner_alias = &transaction;\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_STATE_MIGRATION,",
        1,
    ).replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)",
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  owner_alias->open = FALSE;\n"
        "  if (rc == WYRELOG_E_OK)",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-owner-alias-disarmed",
        "forget migration references transaction outside owner calls",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "#if 0\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "#endif\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "conditional-migration-body-failure-edge",
        "forget migration must remain unconditional source",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "static wyrelog_error_t\n"
        "migrate_forget_intent_state_check_unlocked (",
        "#define WYL_DISARM_MIGRATION transaction.open = FALSE\n\n"
        "static wyrelog_error_t\n"
        "migrate_forget_intent_state_check_unlocked (",
        1,
    ).replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  if (rc == WYRELOG_E_OK)",
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
        "  WYL_DISARM_MIGRATION;\n"
        "  if (rc == WYRELOG_E_OK)",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "external-macro-migration-disarm",
        "forget migration uses unaudited repository macro",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store-connection-private.h"] = changed[
        "wyrelog/fact/store-connection-private.h"
    ].replace(
        "#pragma once\n",
        "#pragma once\n\n"
        "#define WYL_DISARM_MIGRATION_ON_FAILURE() \\\n"
        "  do { if (rc != WYRELOG_E_OK) transaction.open = FALSE; } while (0)\n",
        1,
    )
    changed["wyrelog/fact/store.c"] = source.replace(
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "  WYL_DISARM_MIGRATION_ON_FAILURE ();\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "header-macro-migration-disarm",
        "forget migration uses unaudited repository macro",
        changed,
    )

    for directive, label in (
        ("%:define", "digraph"),
        ("#/**/define", "comment-separated"),
        ("#\\\ndefine", "line-spliced"),
        ("#\vdefine", "vertical-tab"),
        ("#\fdefine", "form-feed"),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store-connection-private.h"] = changed[
            "wyrelog/fact/store-connection-private.h"
        ].replace(
            "#pragma once\n",
            "#pragma once\n\n"
            f"{directive} WYL_TRANSLATED_DISARM transaction.open = FALSE\n",
            1,
        )
        changed["wyrelog/fact/store.c"] = source.replace(
            "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
            "  if (rc == WYRELOG_E_OK)",
            "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n"
            "  WYL_TRANSLATED_DISARM;\n"
            "  if (rc == WYRELOG_E_OK)",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            f"{label}-header-macro-migration-disarm",
            "forget migration uses unaudited repository macro",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/store-connection-private.h"] = changed[
        "wyrelog/fact/store-connection-private.h"
    ].replace(
        "#pragma once\n",
        "#pragma once\n\n"
        "#define WYL_SPLICE_DISARM transaction.open = FALSE\n",
        1,
    )
    changed["wyrelog/fact/store.c"] = source.replace(
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n",
        "  WYL_SPLICE_\\\nDISARM;\n"
        "  rc = exec_sql (store->conn, fact_forget_intent_rebuild_sql);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "split-header-macro-migration-disarm",
        "forget migration body sequence drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "#define FACT_FORGET_INTENT_COLUMNS \\\n"
        '  "  op_uuid         VARCHAR PRIMARY KEY,"',
        "#define FACT_FORGET_INTENT_COLUMNS \\\n"
        '  "existing columns"; transaction.open = FALSE; \\\n'
        '  "  op_uuid         VARCHAR PRIMARY KEY,"',
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "trusted-columns-macro-code-injection",
        "forget intent columns macro must contain only string literals",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "#define FACT_FORGET_INTENT_COLUMNS \\\n",
        "static WylFactStoreTransaction transaction;\n"
        "#define FACT_FORGET_INTENT_COLUMNS \\\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "file-scope-transaction-owner",
        "fact store transaction owner must not have file scope",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "    goto finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        "    goto bypass_finish;\n"
        "  rc = exec_sql (store->conn,\n"
        '          "DROP TABLE fact_forget_intent;"',
        1,
    ).replace(
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "}\n\n"
        "/* Retire an intent",
        "finish:\n"
        "  return wyl_fact_store_transaction_finish (&transaction, rc);\n"
        "bypass_finish:\n"
        "  return rc;\n"
        "}\n\n"
        "/* Retire an intent",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "migration-goto-bypass",
        "forget migration body-failure cleanup edge drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        "        rc = quarantine_rc;\n        broke = TRUE;",
        "        (void) quarantine_rc;\n        broke = TRUE;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "ignored-quarantine-failure",
        "forget quarantine failure propagation drifted",
        changed,
    )

    for label, replacement in (
        (
            "internal-only-quarantine-failure",
            "if (quarantine_rc == WYRELOG_E_INTERNAL) {",
        ),
        (
            "disabled-quarantine-failure",
            "if (FALSE && quarantine_rc != WYRELOG_E_OK) {",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] = source.replace(
            "if (quarantine_rc != WYRELOG_E_OK) {", replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label,
            "forget quarantine failure propagation drifted",
            changed,
        )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        '#include "store-duckdb-config-test-seams-private.h"\n', "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "  guint duckdb_configured_settings;\n", "", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store-private.h"] += "\nwyl_fact_store_lock(store);\n"
    mutations.append(changed)

    source = files["wyrelog/fact/store.c"]
    begin_region = (
        "  wyrelog_error_t rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
    )
    rename_region = (
        "  rc = rename_metadata_value_column_once_unlocked (store);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    goto finish;\n"
    )
    if begin_region not in source or rename_region not in source:
        raise AssertionError("forget rename seam mutation fixture drifted")

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        rename_region, "", 1
    ).replace(
        begin_region,
        "  wyrelog_error_t rc = WYRELOG_E_OK;\n"
        "#if defined(WYL_TEST_HANDLE_SEAMS)\n"
        + rename_region
        + "#endif\n"
        "  rc = wyl_fact_store_transaction_begin (session,\n"
        "          WYL_FACT_STORE_TRANSACTION_FORGET_COMPLETE, &transaction);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "rename-before-begin", "escaped its admitted transaction", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = source.replace(
        rename_region,
        rename_region.replace("    goto finish;", "    return rc;"),
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "rename-direct-return", "bypasses common transaction cleanup", changed
    )

    for macro_path in ("source", "header"):
        for producer_kind in ("direct", "transitive"):
            changed = dict(files)
            definitions = "#define WYL_MEMBER_ID(value) value\n"
            member_name = "WYL_MEMBER_ID"
            if producer_kind == "transitive":
                definitions += (
                    "#define WYL_MEMBER_BRIDGE(value) "
                    "WYL_MEMBER_ID(value)\n"
                )
                member_name = "WYL_MEMBER_BRIDGE"
            definitions += (
                "#define WYL_LITERAL_OP_RAW(object) "
                f"((object)->{member_name}(conn))\n"
            )
            if macro_path == "source":
                role_source = definitions + changed["wyrelog/fact/store.c"]
            else:
                changed[ROLE_HEADER] += "\n" + definitions
                role_source = changed["wyrelog/fact/store.c"]
            create_at = role_source.index("wyl_fact_store_create_schema (")
            session_at = role_source.index(
                "WylFactStoreConnectionSession session = { 0 };", create_at
            )
            changed["wyrelog/fact/store.c"] = (
                role_source[:session_at]
                + "duckdb_connection leaked = "
                "WYL_LITERAL_OP_RAW (store);\n"
                "  (void) leaked;\n  " + role_source[session_at:]
            )
            mutations.append(changed)

    for macro_path in ("source", "header"):
        for operator in ("->", "."):
            changed = dict(files)
            definitions = (
                "#define WYL_PARAMETER_RAW(object, member) "
                f"((object){operator}member)\n"
            )
            if macro_path == "source":
                role_source = definitions + changed["wyrelog/fact/store.c"]
            else:
                changed[ROLE_HEADER] += "\n" + definitions
                role_source = changed["wyrelog/fact/store.c"]
            create_at = role_source.index("wyl_fact_store_create_schema (")
            session_at = role_source.index(
                "WylFactStoreConnectionSession session = { 0 };", create_at
            )
            changed["wyrelog/fact/store.c"] = (
                role_source[:session_at]
                + "duckdb_connection leaked = "
                "WYL_PARAMETER_RAW (store, conn);\n"
                "  (void) leaked;\n  " + role_source[session_at:]
            )
            mutations.append(changed)

    for directive in (
        "/* leading comment */ #define",
        "#/**/define",
        "%:define",
        "??=define",
    ):
        changed = dict(files)
        definitions = (
            f"{directive} WYL_LEXICAL_RAW(object) ((object)->conn)\n"
        )
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at]
            + "duckdb_connection leaked = WYL_LEXICAL_RAW (store);\n"
            "  (void) leaked;\n  " + role_source[session_at:]
        )
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#define WYL_ARGUMENT_PASTE(left, right) left ## right\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = "
        "store->WYL_ARGUMENT_PASTE(co, nn);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "argument-token-paste", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#if WYL_UNKNOWN_PROFILE\n"
        "#define WYL_BRANCH_RAW(value) (value)\n"
        "#else\n"
        "#define WYL_BRANCH_RAW(object) ((object)->conn)\n"
        "#endif\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_BRANCH_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "active-else-macro", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store-private.h"] += (
        "\n#define WYL_INCLUDED_RAW(object) ((object)->conn)\n"
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_INCLUDED_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "included-header-macro", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = (
        "#define WYL_STRING_RAW(object) "
        "((void) \"http://\", (object)->conn)\n"
        + changed["wyrelog/fact/store.c"]
    )
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "duckdb_connection leaked = WYL_STRING_RAW (store);\n"
        "  (void) leaked;\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "string-comment-marker", "macro-generated raw authority", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed[
        "wyrelog/fact/store.c"
    ].replace(
        "  store->rename_metadata_value_column_once = TRUE;",
        "  (void) duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "  store->rename_metadata_value_column_once = TRUE;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "arm-seam-direct-duckdb", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nwyrelog_error_t\n"
        "wyl_fact_store_raw_escape (wyl_fact_store_t *store)\n"
        "{\n  return duckdb_query (store->conn, \"SELECT 1;\", NULL) "
        "== DuckDBSuccess ? WYRELOG_E_OK : WYRELOG_E_IO;\n}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-external-raw-root", "raw DuckDB authority inventory", changed
    )

    for macro_path in ("source", "header"):
        changed = dict(files)
        definitions = (
            "#define WYL_PASTE(left, right) left ## right\n"
            "#define WYL_RAW_OPERATOR WYL_PASTE(-, >)\n"
            "#define WYL_RAW_MEMBER WYL_PASTE(co, nn)\n"
            "#define WYL_PASTED_RAW(object) "
            "((object) WYL_RAW_OPERATOR WYL_RAW_MEMBER)\n"
        )
        if macro_path == "source":
            role_source = definitions + changed["wyrelog/fact/store.c"]
        else:
            changed[ROLE_HEADER] += "\n" + definitions
            role_source = changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at]
            + "duckdb_connection leaked = WYL_PASTED_RAW (store);\n"
            "  (void) leaked;\n  " + role_source[session_at:]
        )
        mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/compound.c"] = changed[
        "wyrelog/fact/compound.c"
    ].replace(marker, marker + "\n  if (rc == WYRELOG_E_INVALID)\n"
              "    return rc;\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    marker = "wyl_fact_store_connection_session_end (&session);"
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(marker, marker + "\n  duckdb_query (conn, \"SELECT 1\", NULL);", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("owned->cells[c].text = g_strdup (value);",
              "owned->cells[c].text = value;", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("WylFactStoreConnectionSession session = { 0 };",
              "static\n  WylFactStoreConnectionSession session = { 0 };", 1)
    mutations.append(changed)

    for escaped in (
        "\nWylFactStoreConnectionSession escaped_global;\n",
        "\nWylFactStoreConnectionSession *escaped_global_pointer;\n",
        "\ntypedef struct { WylFactStoreConnectionSession session; } "
        "EscapedContext;\n",
        "\ntypedef union { WylFactStoreConnectionSession *session; gpointer raw; } "
        "EscapedUnion;\n",
        "\nstatic void escaped_heap(void) { "
        "g_new0(WylFactStoreConnectionSession, 1); }\n",
        "\nWylFactStoreConnectionSession escaped_return(void) { "
        "WylFactStoreConnectionSession session = { 0 }; return session; }\n",
        "\nWylFactStoreConnectionSession *escaped_pointer_return(void) { "
        "return NULL; }\n",
        "\nstatic void escaped_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_thread, &session); }\n",
        "\nstatic void escaped_indirect_thread(void) { "
        "WylFactStoreConnectionSession session = { 0 }; gpointer value = &session; "
        "g_thread_new(\"escaped\", (GThreadFunc) escaped_indirect_thread, value); }\n",
        "\nstatic gpointer escaped_opaque;\n"
        "static void escaped_opaque_store(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_opaque = (gpointer) &session; }\n",
        "\nstatic void escaped_helper(gpointer value) { (void) value; }\n"
        "static void escaped_indirect_helper(void) { "
        "WylFactStoreConnectionSession session = { 0 }; "
        "escaped_helper((gpointer) &session); }\n",
        "\nstatic void *escaped_session_pointer;\n"
        "static void escaped_pointer_alias(WylFactStoreConnectionSession *session) { "
        "escaped_session_pointer = (void *) session; }\n",
        "\nstatic void escaped_opaque_sink(void *value) { (void) value; }\n"
        "static void escaped_pointer_helper(WylFactStoreConnectionSession *session) { "
        "escaped_opaque_sink((gpointer) session); }\n",
        "\nstatic void escaped_bare_sink(void *value) { (void) value; }\n"
        "static void escaped_bare_helper(WylFactStoreConnectionSession *session) { "
        "escaped_bare_sink(session); }\n",
        "\nstatic void escaped_pointer_local(WylFactStoreConnectionSession *session) { "
        "void *alias = session; (void) alias; }\n",
        "\nstatic void *escaped_pointer_return(WylFactStoreConnectionSession *session) { "
        "return session; }\n",
        "\nstatic gconstpointer escaped_const_pointer;\n"
        "static void escaped_gconstpointer(WylFactStoreConnectionSession *session) { "
        "escaped_const_pointer = (gconstpointer) session; }\n",
        "\nstatic const void *escaped_const_void_pointer;\n"
        "static void escaped_const_void(WylFactStoreConnectionSession *session) { "
        "escaped_const_void_pointer = (const void *) session; }\n",
        "\ntypedef gpointer EscapedPointer;\n"
        "static EscapedPointer escaped_custom_pointer;\n"
        "static void escaped_custom_cast(WylFactStoreConnectionSession *session) { "
        "escaped_custom_pointer = (EscapedPointer) session; }\n",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] += escaped
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace("wyl_fact_store_connection_session_end (&session);", "", 1)
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/query.c"] += '\n#include "store-connection-private.h"\n'
    mutations.append(changed)

    changed = dict(files)
    changed[ROLE_HEADER] = changed[ROLE_HEADER].replace(
        "#if !defined(WYL_FACT_STORE_CONNECTION_ROLE)", "#if 0", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "#if defined(WYL_TEST_HANDLE_SEAMS)\nvoid\n"
        "wyl_fact_store_test_set_transaction_hook",
        "void\nwyl_fact_store_test_set_transaction_hook",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    marker = "dependencies : [wyrelog_handle_test_seams_dep, wirelog_dep"
    changed["tests/meson.build"] = changed["tests/meson.build"].replace(
        marker, "dependencies : [wyrelog_dep, wyrelog_handle_test_seams_dep, wirelog_dep", 1
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health == WYL_FACT_STORE_POISONED",
        "FALSE",
        1,
    )
    mutations.append(changed)

    for token in (
        "if (active != NULL)",
        "session->owner == g_thread_self ()",
        "session->store->session_owner == session->owner",
        "g_private_get (&active_connection_session) == session",
        "connection_session_is_current (session)",
        "connection_session_is_current (transaction->session)",
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
            token, "FALSE", 1
        )
        mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "if (active != NULL)\n    if (active->store == store)\n"
        "      return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nstatic void pre_tls_duckdb_escape(wyl_fact_store_t *store) { "
        "duckdb_query(store->conn, \"SELECT 1;\", NULL); }\n"
    )
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        "pre_tls_duckdb_escape (store);\n"
        "  WylFactStoreConnectionSession *active =\n"
        "      g_private_get (&active_connection_session);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        "duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "  if (active != NULL)\n    return WYRELOG_E_INTERNAL;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        "store->health = WYL_FACT_STORE_POISONED;",
        "store->health = WYL_FACT_STORE_HEALTHY;",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "g_assert_false(wyl_fact_store_test_try_lock(store));",
        "g_assert_false(TRUE);",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "waiter->rc = wyl_fact_store_table_exists",
        "waiter->rc = fake_internal_table_exists",
        1,
    )
    mutations.append(changed)

    changed = dict(files)
    changed["tests/test-fact-store-poison.c"] = changed[
        "tests/test-fact-store-poison.c"
    ].replace(
        "assert_engine_marker(engine);",
        "(void) wyl_engine_insert(engine, \"poison_marker\", marker_value, 1);\n"
        "  assert_engine_marker(engine);",
        1,
    )
    mutations.append(changed)

    for token, replacement in (
        ("SELECT COUNT(*) FROM fact_event_log;",
         "SELECT COUNT(*) FROM fact_batches;"),
        ('store, &schema, "poison-append"',
         'store, &schema, "poison-append-mutated"'),
        ('store, &schema, "owner-retract"',
         'store, &schema, "owner-retract-mutated"'),
        ('store, &schema, "retract-core-attempt"',
         'store, &schema, "retract-core-attempt-mutated"'),
    ):
        changed = dict(files)
        changed["tests/test-fact-store-poison.c"] = changed[
            "tests/test-fact-store-poison.c"
        ].replace(token, replacement, 1)
        mutations.append(changed)

    for path, token in (
        ("wyrelog/fact/store.c", "g_private_get (&active_connection_session)"),
        ("wyrelog/fact/store.c", "store->session_owner = NULL;"),
        ("wyrelog/fact/replay.c",
         "wyl_fact_store_connection_session_end (&admission);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(exists);"),
        ("tests/test-fact-store-poison.c", "g_assert_false(inserted);"),
        ("tests/test-fact-store-poison.c", "assert_zero_delta(&delta);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(row_count, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(table);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(purged, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(compound_ref, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_cmpint(handle, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(g_hash_table_size(handles), ==, 1);"),
        ("tests/test-fact-store-poison.c", "assert_engine_marker(engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(admission_calls, ==, 0);"),
        ("tests/test-fact-store-poison.c",
         "nested_session_admissions);"),
        ("tests/test-fact-store-poison.c", "nested_duckdb_calls);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(replay_engine);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpint(query_value, ==, 0);"),
        ("tests/test-fact-store-poison.c", "g_assert_null(query_text);"),
        ("tests/test-fact-store-poison.c",
         "g_assert_cmpuint(wyl_fact_store_test_duckdb_call_count(store), ==,\n"
         "      duckdb_calls);"),
    ):
        changed = dict(files)
        changed[path] = changed[path].replace(token, "", 1)
        mutations.append(changed)

    for label, body in (
        (
            "renamed-receiver-raw-root",
            "\nstatic gpointer\nraw_receiver_escape (wyl_fact_store_t *s)\n"
            "{\n  return (gpointer) s->conn;\n}\n",
        ),
        (
            "dereferenced-receiver-raw-root",
            "\nstatic gpointer\nraw_dereference_escape "
            "(wyl_fact_store_t *store)\n"
            "{\n  return (gpointer) (*store).conn;\n}\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/store.c"] += body
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw DuckDB authority inventory", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer WYL_LATE_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer late_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_LATE_STRINGIFY(store->conn); }\n"
        "#define WYL_LATE_STRINGIFY(value) #value\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "late-stringification-definition", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/inactive-stringify-boundary.h"] = (
        "#if 0\n"
        "#define WYL_INACTIVE_COLLIDE(value) #value\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#include "inactive-stringify-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_INACTIVE_COLLIDE(gpointer value) "
        "{ return value; }\n"
        "static gpointer inactive_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_INACTIVE_COLLIDE(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "inactive-header-stringification", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/undef-stringify-boundary.h"] = (
        "#define WYL_UNDEF_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#include "undef-stringify-boundary.h"\n'
        "#undef WYL_UNDEF_STRINGIFY\n"
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_UNDEF_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer undef_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_UNDEF_STRINGIFY(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "undef-header-stringifier", "raw DuckDB authority inventory", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/unrelated-stringify-boundary.h"] = (
        "#define WYL_UNRELATED_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] = (
        '#define WYL_LOG_HEADER "unrelated-stringify-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
        + "\nstatic gpointer WYL_UNRELATED_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer unrelated_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_UNRELATED_STRINGIFY(store->conn); }\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "unrelated-literal-macro-header",
        "raw DuckDB authority inventory",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/later-stringify-boundary.h"] = (
        "#define WYL_LATER_HEADER_STRINGIFY(value) #value\n"
    )
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer WYL_LATER_HEADER_STRINGIFY(gpointer value) "
        "{ return value; }\n"
        "static gpointer later_header_stringify_escape(wyl_fact_store_t *store) "
        "{ return WYL_LATER_HEADER_STRINGIFY(store->conn); }\n"
        '#include "later-stringify-boundary.h"\n'
    )
    mutations.append(changed)
    require_boundary_rejection(
        "later-header-stringifier", "raw DuckDB authority inventory", changed
    )

    for label, definitions, statement in (
        (
            "apple-profile-raw",
            "#if defined(__APPLE__)\n"
            "#define WYL_PLATFORM_RAW(object, member) ((object)->member)\n"
            "#else\n#define WYL_PLATFORM_RAW(object, member) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_PLATFORM_RAW (store, conn);",
        ),
        (
            "multiline-macro-invocation",
            "#define WYL_MULTILINE_RAW(object) ((object)->conn)\n",
            "duckdb_connection leaked = WYL_MULTILINE_RAW\n    (store);",
        ),
        (
            "variadic-member-macro",
            "#define WYL_VARIADIC_RAW(object, ...) "
            "((object)->__VA_ARGS__)\n",
            "duckdb_connection leaked = WYL_VARIADIC_RAW (store, conn);",
        ),
        (
            "c-integer-conditional",
            "#if -3 / 2 == -1\n"
            "#define WYL_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_INTEGER_RAW (store);",
        ),
        (
            "parenthesized-c-integer-conditional",
            "#if (-3) / 2 == -1\n"
            "#define WYL_PAREN_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_PAREN_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_PAREN_INTEGER_RAW (store);",
        ),
        (
            "left-associative-c-integer-conditional",
            "#if 8 % 3 / 2 == 1\n"
            "#define WYL_ASSOC_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_ASSOC_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_ASSOC_INTEGER_RAW (store);",
        ),
        (
            "multiplicative-c-integer-conditional",
            "#if 8 * 3 / 5 == 4\n"
            "#define WYL_MULTIPLY_INTEGER_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_MULTIPLY_INTEGER_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_MULTIPLY_INTEGER_RAW (store);",
        ),
        (
            "parenthesized-expression-conditional",
            "#if -7 / (2 + 1) == -2\n"
            "#define WYL_EXPRESSION_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_EXPRESSION_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_EXPRESSION_RAW (store);",
        ),
        (
            "ternary-expression-conditional",
            "#if 1 ? 1 : 0\n"
            "#define WYL_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_TERNARY_RAW (store);",
        ),
        (
            "character-expression-conditional",
            "#if 'A' == 65\n"
            "#define WYL_CHARACTER_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_CHARACTER_RAW (store);",
        ),
        (
            "c-comparison-associativity",
            "#if !(3 > 2 > 1)\n"
            "#define WYL_COMPARE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_COMPARE_RAW (store);",
        ),
        (
            "c-false-first-comparison-associativity",
            "#if 2 < 1 < 2\n"
            "#define WYL_FALSE_FIRST_COMPARE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = "
            "WYL_FALSE_FIRST_COMPARE_RAW (store);",
        ),
        (
            "nested-ternary-expression",
            "#if 0 ? 0 : 0 ? 0 : 1\n"
            "#define WYL_NESTED_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_NESTED_TERNARY_RAW (store);",
        ),
        (
            "short-circuit-expression",
            "#if 1 || (1 / 0)\n"
            "#define WYL_SHORT_CIRCUIT_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_SHORT_CIRCUIT_RAW (store);",
        ),
        (
            "unsigned-expression",
            "#if -1U > 0\n"
            "#define WYL_UNSIGNED_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UNSIGNED_RAW (store);",
        ),
        (
            "unsigned-long-long-expression",
            "#if -1ULL > 0\n"
            "#define WYL_ULL_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_ULL_RAW (store);",
        ),
        (
            "unsigned-hex-expression",
            "#if -0x1U > 0\n"
            "#define WYL_UNSIGNED_HEX_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UNSIGNED_HEX_RAW (store);",
        ),
        (
            "parenthesized-ternary-expression",
            "#if (0 ? 0 : 1)\n"
            "#define WYL_PAREN_TERNARY_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_PAREN_TERNARY_RAW (store);",
        ),
        (
            "logical-not-precedence",
            "#if !0 < 2\n"
            "#define WYL_NOT_PRECEDENCE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_NOT_PRECEDENCE_RAW (store);",
        ),
        (
            "bitwise-equality-precedence",
            "#if 1 & 2 == 2\n"
            "#define WYL_BITWISE_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_BITWISE_RAW (store);",
        ),
        (
            "preprocessor-uintmax-width",
            "#if 0xffffffffU + 1 == 0\n"
            "#define WYL_UINTMAX_RAW(object) (0)\n"
            "#else\n"
            "#define WYL_UINTMAX_RAW(object) ((object)->conn)\n"
            "#endif\n",
            "duckdb_connection leaked = WYL_UINTMAX_RAW (store);",
        ),
        (
            "ternary-common-unsigned-type",
            "#if (1 ? -1 : 0U) > 0\n"
            "#define WYL_TERNARY_TYPE_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_TERNARY_TYPE_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_TERNARY_TYPE_RAW (store);",
        ),
        (
            "unsuffixed-hex-uintmax",
            "#if 0xffffffffffffffff + 1 == 0\n"
            "#define WYL_HEX_UINTMAX_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_HEX_UINTMAX_RAW(object) (0)\n#endif\n",
            "duckdb_connection leaked = WYL_HEX_UINTMAX_RAW (store);",
        ),
    ):
        changed = dict(files)
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at] + statement + "\n  (void) leaked;\n  "
            + role_source[session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "macro-generated raw authority", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/repeat-boundary.h"] = (
        "#ifdef WYL_REPEAT_ON\n"
        "#define WYL_REPEAT_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_REPEAT_ON 1\n#endif\n"
    )
    role_source = (
        '#include "repeat-boundary.h"\n#include "repeat-boundary.h"\n'
        + changed["wyrelog/fact/store.c"]
    )
    create_at = role_source.index("wyl_fact_store_create_schema (")
    session_at = role_source.index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        role_source[:session_at]
        + "duckdb_connection leaked = WYL_REPEAT_RAW (store);\n"
        "  (void) leaked;\n  " + role_source[session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "repeat-include-state", "macro-generated raw authority", changed
    )

    def queue_macro_escape(
        label: str, definitions: str, statement: str,
        extra_files: dict[str, str] | None = None,
    ) -> None:
        changed = dict(files)
        if extra_files is not None:
            changed.update(extra_files)
        role_source = definitions + changed["wyrelog/fact/store.c"]
        create_at = role_source.index("wyl_fact_store_create_schema (")
        session_at = role_source.index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            role_source[:session_at] + statement + "\n  "
            + role_source[session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(label, "macro", changed)

    aliases = "#define WYL_DEPTH_0(object) ((object)->conn)\n"
    for index in range(1, 40):
        aliases += f"#define WYL_DEPTH_{index} WYL_DEPTH_{index - 1}\n"
    queue_macro_escape(
        "macro-depth-exhaustion", aliases,
        "(void) WYL_DEPTH_39(store);",
    )
    queue_macro_escape(
        "variadic-call-forwarding",
        "#define WYL_CALL(function, ...) function(__VA_ARGS__)\n",
        "(void) WYL_CALL(duckdb_query, "
        "wyl_fact_store_connection_session_get (&session), "
        "\"SELECT 1;\", NULL);",
    )
    queue_macro_escape(
        "expanded-include",
        "#define WYL_BOUNDARY_HEADER \"macro-boundary.h\"\n"
        "#include WYL_BOUNDARY_HEADER\n",
        "(void) WYL_INCLUDED_ESCAPE(store);",
        {"wyrelog/fact/macro-boundary.h":
            "#define WYL_INCLUDED_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "expanded-angle-include",
        "#define WYL_ANGLE_HEADER <wyrelog/fact/angle-boundary.h>\n"
        "#include WYL_ANGLE_HEADER\n",
        "(void) WYL_ANGLE_ESCAPE(store);",
        {"wyrelog/fact/angle-boundary.h":
            "#define WYL_ANGLE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "direct-angle-include",
        "#include <wyrelog/fact/direct-angle-boundary.h>\n",
        "(void) WYL_DIRECT_ANGLE_ESCAPE(store);",
        {"wyrelog/fact/direct-angle-boundary.h":
            "#define WYL_DIRECT_ANGLE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "outside-fact-include",
        '#include "../include/raw-boundary.h"\n',
        "(void) WYL_OUTSIDE_FACT_ESCAPE(store);",
        {"wyrelog/include/raw-boundary.h":
            "#define WYL_OUTSIDE_FACT_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "literal-include-operand",
        "#define literal changed\n"
        '#include "literal-boundary.h"\n',
        "(void) WYL_LITERAL_INCLUDE_ESCAPE(store);",
        {"wyrelog/fact/literal-boundary.h":
            "#define WYL_LITERAL_INCLUDE_ESCAPE(object) ((object)->conn)\n"},
    )
    queue_macro_escape(
        "defined-external-profile",
        "#if defined(WYL_EXTERNAL_PROFILE)\n"
        "#define WYL_EXTERNAL_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_EXTERNAL_RAW(object) (0)\n#endif\n",
        "(void) WYL_EXTERNAL_RAW(store);",
    )
    queue_macro_escape(
        "mixed-external-profile",
        "#if WYL_EXTERNAL_A && !WYL_EXTERNAL_B\n"
        "#define WYL_MIXED_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_MIXED_RAW(object) (0)\n#endif\n",
        "(void) WYL_MIXED_RAW(store);",
    )
    queue_macro_escape(
        "three-way-external-profile",
        "#if WYL_EXTERNAL_A && WYL_EXTERNAL_B && !WYL_EXTERNAL_C\n"
        "#define WYL_THREE_WAY_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_THREE_WAY_RAW(object) (0)\n#endif\n",
        "(void) WYL_THREE_WAY_RAW(store);",
    )
    queue_macro_escape(
        "six-name-external-profile",
        "#if WYL_SIX_A && WYL_SIX_B && WYL_SIX_C "
        "&& !WYL_SIX_D && !WYL_SIX_E && !WYL_SIX_F\n"
        "#define WYL_SIX_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_SIX_RAW(object) (0)\n#endif\n",
        "(void) WYL_SIX_RAW(store);",
    )
    queue_macro_escape(
        "nested-external-profile",
        "#if WYL_NESTED_A\n#if WYL_NESTED_B\n"
        "#define WYL_NESTED_RAW(object) ((object)->conn)\n"
        "#endif\n#endif\n",
        "(void) WYL_NESTED_RAW(store);",
    )
    queue_macro_escape(
        "later-local-profile-definition",
        "#if WYL_LATER_LOCAL\n"
        "#define WYL_LATER_LOCAL_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_LATER_LOCAL_RAW(object) (0)\n#endif\n"
        "#define WYL_LATER_LOCAL 0\n",
        "(void) WYL_LATER_LOCAL_RAW(store);",
    )
    queue_macro_escape(
        "header-local-external-profile",
        '#include "profile-boundary.h"\n',
        "(void) WYL_HEADER_PROFILE_RAW(store);",
        {"wyrelog/fact/profile-boundary.h":
            "#if WYL_HEADER_PROFILE\n"
            "#define WYL_HEADER_PROFILE_RAW(object) ((object)->conn)\n"
            "#else\n#define WYL_HEADER_PROFILE_RAW(object) (0)\n#endif\n"},
    )
    queue_macro_escape(
        "recursive-header-external-profile",
        '#include "profile-outer-boundary.h"\n',
        "(void) WYL_RECURSIVE_PROFILE_RAW(store);",
        {
            "wyrelog/fact/profile-outer-boundary.h":
                '#include "profile-inner-boundary.h"\n',
            "wyrelog/fact/profile-inner-boundary.h":
                "#if WYL_RECURSIVE_PROFILE\n"
                "#define WYL_RECURSIVE_PROFILE_RAW(object) ((object)->conn)\n"
                "#else\n"
                "#define WYL_RECURSIVE_PROFILE_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "inherited-macro-include-profile",
        "#define WYL_INHERITED_HEADER \"profile-inherited-inner.h\"\n"
        '#include "profile-inherited-outer.h"\n',
        "(void) WYL_INHERITED_PROFILE_RAW(store);",
        {
            "wyrelog/fact/profile-inherited-outer.h":
                "#include WYL_INHERITED_HEADER\n",
            "wyrelog/fact/profile-inherited-inner.h":
                "#if WYL_INHERITED_PROFILE\n"
                "#define WYL_INHERITED_PROFILE_RAW(object) ((object)->conn)\n"
                "#else\n"
                "#define WYL_INHERITED_PROFILE_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "token-pasted-header-external-profile",
        '#include "profile-token-paste.h"\n',
        "(void) WYL_PROFILE_PASTED_RAW(store);",
        {
            "wyrelog/fact/profile-token-paste.h":
                "#define WYL_PROFILE_CAT(left, right) left ## right\n"
                "#if WYL_PROFILE_PASTED_EXTERNAL\n"
                "#define WYL_PROFILE_PASTED_RAW(object) "
                "((object) WYL_PROFILE_CAT(-, >) WYL_PROFILE_CAT(co, nn))\n"
                "#else\n"
                "#define WYL_PROFILE_PASTED_RAW(object) (0)\n"
                "#endif\n",
        },
    )
    queue_macro_escape(
        "inactive-profile-definition",
        "#if 0\n#define WYL_INACTIVE_DEFINED 1\n#endif\n"
        "#if WYL_INACTIVE_DEFINED\n"
        "#define WYL_INACTIVE_DEFINED_RAW(object) ((object)->conn)\n"
        "#else\n#define WYL_INACTIVE_DEFINED_RAW(object) (0)\n#endif\n",
        "(void) WYL_INACTIVE_DEFINED_RAW(store);",
    )
    queue_macro_escape(
        "empty-token-paste",
        "#define WYL_EMPTY_CAT(left, right) left ## right\n"
        "#define WYL_EMPTY_RAW(object) "
        "((object)->WYL_EMPTY_CAT(,conn))\n",
        "(void) WYL_EMPTY_RAW(store);",
    )
    queue_macro_escape(
        "token-pasted-authority-type",
        "#define WYL_TYPE_CAT(left, right) left ## right\n"
        "#define WYL_RAW_TYPE WYL_TYPE_CAT(duckdb_, connection)\n",
        "WYL_RAW_TYPE escaped_connection = NULL; "
        "(void) escaped_connection;",
    )
    queue_macro_escape(
        "inactive-pragma-once",
        '#include "inactive-once-boundary.h"\n'
        '#include "inactive-once-boundary.h"\n',
        "(void) WYL_INACTIVE_ONCE_VALUE(store);",
        {"wyrelog/fact/inactive-once-boundary.h":
            "#if 0\n#pragma once\n#endif\n"
            "#ifndef WYL_INACTIVE_ONCE_SEEN\n"
            "#define WYL_INACTIVE_ONCE_SEEN 1\n"
            "#define WYL_INACTIVE_ONCE_VALUE(value) (value)\n"
            "#else\n"
            "#define WYL_INACTIVE_ONCE_VALUE(object) ((object)->conn)\n"
            "#endif\n"},
    )
    queue_macro_escape(
        "hexadecimal-condition",
        "#if 0x1\n#define WYL_HEX_RAW(object) ((object)->conn)\n#endif\n",
        "(void) WYL_HEX_RAW(store);",
    )
    queue_macro_escape(
        "vertical-tab-directive",
        "#define\vWYL_VERTICAL_RAW(object) ((object)->conn)\n",
        "(void) WYL_VERTICAL_RAW(store);",
    )

    changed = dict(files)
    create_at = changed["wyrelog/fact/store.c"].index(
        "wyl_fact_store_create_schema ("
    )
    session_at = changed["wyrelog/fact/store.c"].index(
        "WylFactStoreConnectionSession session = { 0 };", create_at
    )
    changed["wyrelog/fact/store.c"] = (
        changed["wyrelog/fact/store.c"][:session_at]
        + "(void) (*duckdb_query) (store->conn, \"SELECT 1;\", NULL);\n  "
        + changed["wyrelog/fact/store.c"][session_at:]
    )
    mutations.append(changed)
    require_boundary_rejection(
        "parenthesized-duckdb-designator",
        "raw DuckDB authority inventory",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] = changed[
        "wyrelog/fact/store.c"
    ].replace(
        "    rc = exec_sql (store->conn,\n"
        "            \"CREATE TABLE IF NOT EXISTS fact_store_metadata (\"",
        "    rc = exec_sql (NULL,\n"
        "            \"CREATE TABLE IF NOT EXISTS fact_store_metadata (\"",
        1,
    )
    changed["wyrelog/fact/store.c"] += (
        "\nstatic gpointer raw_member_escape(wyl_fact_store_t *store)\n"
        "{\n"
        "  return store->conn;\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "raw-member-moved-between-functions",
        "raw DuckDB authority moved between functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\n#if WYL_REVIEW_RAW_PROFILE\n"
        "static wyrelog_error_t\n"
        "review_profile_raw_access (wyl_fact_store_t *store)\n"
        "{\n"
        "  duckdb_result result = { 0 };\n"
        "  duckdb_state state = duckdb_query (store->conn, "
        "\"SELECT 1;\", &result);\n"
        "  duckdb_destroy_result (&result);\n"
        "  return state == DuckDBSuccess ? WYRELOG_E_OK : "
        "WYRELOG_E_QUERY_FAILED;\n"
        "}\n"
        "#endif\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "external-profile-raw-function",
        "raw DuckDB authority inventory drifted",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-header-raw-boundary.h"] = (
        "#if WYL_HEADER_RAW_PROFILE\n"
        "static wyrelog_error_t\n"
        "review_header_raw_access (wyl_fact_store_t *store)\n"
        "{\n"
        "  return duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
        "}\n"
        "#endif\n"
    )
    store_marker = (
        "};\n\nstatic WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;"
    )
    changed["wyrelog/fact/store.c"] = changed["wyrelog/fact/store.c"].replace(
        store_marker,
        "};\n\n#include \"review-header-raw-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "included-header-external-profile-raw-function",
        "unexpected transitive raw authority functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\nwyrelog_error_t\n"
        "wyl_fact_store_raw_escape (wyl_fact_store_t *store)\n"
        "{\n"
        "  return reject_audit_database_unlocked (store);\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-external-transitive-raw-wrapper",
        "unexpected transitive raw authority functions",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/store.c"] += (
        "\n#if WYL_REVIEW_WRAPPER_PROFILE\n"
        "wyrelog_error_t\n"
        "wyl_fact_store_profile_raw_escape (wyl_fact_store_t *store)\n"
        "{\n"
        "  return reject_audit_database_unlocked (store);\n"
        "}\n"
        "#endif\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "new-profile-transitive-raw-wrapper",
        "unexpected transitive raw authority functions",
        changed,
    )

    for label, statement in (
        (
            "multiply-parenthesized-duckdb-designator",
            "(void) ((duckdb_query)) (store->conn, \"SELECT 1;\", NULL);",
        ),
        (
            "comment-separated-duckdb-designator",
            "(void) (duckdb_query /* gap */) "
            "(store->conn, \"SELECT 1;\", NULL);",
        ),
    ):
        changed = dict(files)
        create_at = changed["wyrelog/fact/store.c"].index(
            "wyl_fact_store_create_schema ("
        )
        session_at = changed["wyrelog/fact/store.c"].index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            changed["wyrelog/fact/store.c"][:session_at]
            + statement + "\n  "
            + changed["wyrelog/fact/store.c"][session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw DuckDB authority inventory", changed
        )

    for label, statement in (
        (
            "ternary-duckdb-designator-before-admission",
            "(void) (1 ? duckdb_query : NULL) "
            "(NULL, \"SELECT 1;\", NULL);",
        ),
        (
            "local-duckdb-function-pointer-before-admission",
            "typedef duckdb_state BoundaryQueryState;\n"
            "  BoundaryQueryState (*boundary_query) () = duckdb_query;\n"
            "  (void) boundary_query (NULL, \"SELECT 1;\", NULL);",
        ),
        (
            "local-addressed-duckdb-function-pointer-before-admission",
            "typedef duckdb_state BoundaryQueryState;\n"
            "  BoundaryQueryState (*boundary_query) () = &duckdb_query;\n"
            "  (void) boundary_query (NULL, \"SELECT 1;\", NULL);",
        ),
    ):
        changed = dict(files)
        create_at = changed["wyrelog/fact/store.c"].index(
            "wyl_fact_store_create_schema ("
        )
        session_at = changed["wyrelog/fact/store.c"].index(
            "WylFactStoreConnectionSession session = { 0 };", create_at
        )
        changed["wyrelog/fact/store.c"] = (
            changed["wyrelog/fact/store.c"][:session_at]
            + statement + "\n  "
            + changed["wyrelog/fact/store.c"][session_at:]
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "session authority precedes successful admission", changed
        )

    changed = dict(files)
    replay_source = changed["wyrelog/fact/replay.c"]
    admitted_region = (
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
    )
    reordered_region = (
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
    )
    if admitted_region not in replay_source:
        raise AssertionError("session dominance mutation fixture drifted")
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region, reordered_region, 1
    )
    mutations.append(changed)
    require_boundary_rejection(
        "session-get-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "  (void) duckdb_query (NULL, \"SELECT 1;\", NULL);\n"
        + admitted_region,
        1,
    ).replace(
        "    duckdb_free (namespace_id);\n",
        "    (void) namespace_id;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "duckdb-call-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    store_source = changed["wyrelog/fact/store.c"]
    create_session = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  wyrelog_error_t rc = wyl_fact_store_connection_session_begin (store,\n"
        "          &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  rc = reject_audit_database_unlocked (store);\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        create_session,
        "  wyrelog_error_t rc = reject_audit_database_unlocked (store);\n"
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "raw-helper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-token-wrapper-boundary.h"] = (
        "#if WYL_HEADER_WRAPPER_PROFILE\n"
        "#define WYL_JOIN_INNER(a, b) a ## b\n"
        "#define WYL_JOIN(a, b) WYL_JOIN_INNER(a, b)\n"
        "#define WYL_RAW_HELPER "
        "WYL_JOIN(reject_audit_database_, unlocked)\n"
        "static wyrelog_error_t WYL_RAW_HELPER(wyl_fact_store_t *);\n"
        "static wyrelog_error_t\n"
        "boundary_token_raw_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return WYL_RAW_HELPER(store);\n}\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        store_marker,
        "};\n\n#include \"review-token-wrapper-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    ).replace(
        create_session,
        "#if WYL_HEADER_WRAPPER_PROFILE\n"
        "  (void) boundary_token_raw_wrapper (store);\n"
        "#endif\n" + create_session,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "token-pasted-header-wrapper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/review-alias-state-boundary.h"] = (
        "#if WYL_REVIEW_ALIAS_PROFILE\n"
        "#define WYL_REVIEW_RAW_HELPER reject_audit_database_unlocked\n"
        "static wyrelog_error_t "
        "WYL_REVIEW_RAW_HELPER(wyl_fact_store_t *);\n"
        "#endif\n"
    )
    changed["wyrelog/fact/review-wrapper-state-boundary.h"] = (
        "#if WYL_REVIEW_WRAPPER_PROFILE\n"
        "static wyrelog_error_t\n"
        "boundary_stateful_raw_wrapper (wyl_fact_store_t *store)\n"
        "{\n  return WYL_REVIEW_RAW_HELPER(store);\n}\n"
        "#endif\n"
    )
    changed["wyrelog/fact/store.c"] = store_source.replace(
        store_marker,
        "};\n\n#include \"review-alias-state-boundary.h\"\n"
        "#include \"review-wrapper-state-boundary.h\"\n\n"
        "static WylFactStoreIdentityValidationTestHook "
        "identity_validation_test_hook;",
        1,
    ).replace(
        create_session,
        "#if WYL_REVIEW_ALIAS_PROFILE && WYL_REVIEW_WRAPPER_PROFILE\n"
        "  (void) boundary_stateful_raw_wrapper (store);\n"
        "#endif\n" + create_session,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "cross-header-macro-state-wrapper-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    for label, declaration, invocation in (
        (
            "cross-tu-session-owner-name-collision",
            "\nstatic wyrelog_error_t list_replay_relations"
            "(wyl_fact_store_t *store)\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) list_replay_relations (store);\n",
        ),
        (
            "transitive-raw-wrapper-before-admission",
            "\nstatic wyrelog_error_t boundary_raw_wrapper"
            "(wyl_fact_store_t *store)\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) boundary_raw_wrapper (store);\n",
        ),
        (
            "old-style-transitive-raw-wrapper-before-admission",
            "\nstatic wyrelog_error_t\n"
            "boundary_old_style_raw_wrapper (store)\n"
            "    wyl_fact_store_t *store;\n"
            "{\n  return reject_audit_database_unlocked (store);\n}\n",
            "  (void) boundary_old_style_raw_wrapper (store);\n",
        ),
        (
            "parenthesized-raw-helper-before-admission",
            "",
            "  (void) (reject_audit_database_unlocked) (store);\n",
        ),
        (
            "dereferenced-raw-helper-before-admission",
            "",
            "  (void) (*reject_audit_database_unlocked) (store);\n",
        ),
        (
            "raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_call) (wyl_fact_store_t *) = "
            "reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "typedef-raw-function-pointer-before-admission",
            "",
            "  typedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "  BoundaryRawCall boundary_raw_call = "
            "reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "split-raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_call) "
            "(wyl_fact_store_t *) = NULL;\n"
            "  boundary_raw_call = reject_audit_database_unlocked;\n"
            "  (void) boundary_raw_call (store);\n",
        ),
        (
            "array-raw-function-pointer-before-admission",
            "",
            "  wyrelog_error_t (*boundary_raw_calls[]) "
            "(wyl_fact_store_t *) = { "
            "reject_audit_database_unlocked };\n"
            "  (void) boundary_raw_calls[0] (store);\n",
        ),
        (
            "callback-raw-helper-before-admission",
            "\nstatic wyrelog_error_t boundary_invoke "
            "(wyrelog_error_t (*function) (wyl_fact_store_t *), "
            "wyl_fact_store_t *store)\n"
            "{\n  return function (store);\n}\n",
            "  (void) boundary_invoke "
            "(reject_audit_database_unlocked, store);\n",
        ),
    ):
        changed = dict(files)
        source_with_call = changed["wyrelog/fact/store.c"].replace(
            create_session, invocation + create_session, 1
        )
        if declaration:
            marker = "wyrelog_error_t\nwyl_fact_store_create_schema"
            source_with_call = source_with_call.replace(
                marker, declaration + "\n" + marker, 1
            )
        changed["wyrelog/fact/store.c"] = source_with_call
        mutations.append(changed)
        require_boundary_rejection(
            label, "session authority precedes successful admission", changed
        )

    changed = dict(files)
    replay_admission = (
        "  WylFactStoreConnectionSession session = { 0 };\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);"
    )
    changed["wyrelog/fact/replay.c"] = changed[
        "wyrelog/fact/replay.c"
    ].replace(
        replay_admission,
        "  wyl_fact_store_close (store);\n" + replay_admission,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "cross-tu-external-raw-before-admission",
        "session authority precedes successful admission",
        changed,
    )

    for label, declaration, invocation in (
        (
            "global-duckdb-function-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query) () = "
            "duckdb_query;\n",
            "  (void) boundary_global_query (NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-addressed-duckdb-function-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query) () = "
            "&duckdb_query;\n",
            "  (void) boundary_global_query (NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-duckdb-function-array-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "static BoundaryQueryState (*boundary_global_query[]) () = { "
            "NULL, duckdb_query };\n",
            "  (void) boundary_global_query[1] "
            "(NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-duckdb-function-struct-alias",
            "\ntypedef duckdb_state BoundaryQueryState;\n"
            "typedef struct { BoundaryQueryState (*query) (); } "
            "BoundaryDuckdbDispatch;\n"
            "static BoundaryDuckdbDispatch boundary_global_query = { "
            "duckdb_query };\n",
            "  (void) boundary_global_query.query "
            "(NULL, \"SELECT 1;\", NULL);\n",
        ),
        (
            "global-address-of-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "&reject_audit_database_unlocked;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-parenthesized-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(reject_audit_database_unlocked);\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-cast-parenthesized-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(BoundaryRawCall) (reject_audit_database_unlocked);\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-macro-address-raw-alias",
            "\n#define BOUNDARY_RAW reject_audit_database_unlocked\n"
            "typedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = &BOUNDARY_RAW;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-cast-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw = "
            "(BoundaryRawCall) reject_audit_database_unlocked;\n",
            "  (void) boundary_global_raw (store);\n",
        ),
        (
            "global-array-second-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw[] = { "
            "NULL, reject_audit_database_unlocked };\n",
            "  (void) boundary_global_raw[1] (store);\n",
        ),
        (
            "global-struct-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "typedef struct { BoundaryRawCall call; } BoundaryRawDispatch;\n"
            "static BoundaryRawDispatch boundary_global_raw = { "
            "reject_audit_database_unlocked };\n",
            "  (void) boundary_global_raw.call (store);\n",
        ),
        (
            "global-nested-array-raw-alias",
            "\ntypedef wyrelog_error_t (*BoundaryRawCall) "
            "(wyl_fact_store_t *);\n"
            "static BoundaryRawCall boundary_global_raw[][2] = { "
            "{ NULL, NULL }, { NULL, reject_audit_database_unlocked } };\n",
            "  (void) boundary_global_raw[1][1] (store);\n",
        ),
    ):
        changed = dict(files)
        source_with_call = changed["wyrelog/fact/store.c"].replace(
            create_session, invocation + create_session, 1
        )
        marker = "wyrelog_error_t\nwyl_fact_store_create_schema"
        changed["wyrelog/fact/store.c"] = source_with_call.replace(
            marker, declaration + "\n" + marker, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "raw authority entered file-scope alias", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "wyl_fact_store_connection_session_get (&session)",
        "/* wyl_fact_store_connection_session_get */ session.connection",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "direct-session-field-with-comment-pad",
        "raw DuckDB authority inventory drifted",
        changed,
    )

    for label, replacement in (
        (
            "inactive-admission-failure-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "#if 0\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "#endif\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "empty-admission-success-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  if (rc == WYRELOG_E_OK) {\n  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "overwritten-admission-result",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  rc = WYRELOG_E_OK;\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "dead-c-admission-failure-guard",
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "  if (0) {\n"
            "    if (rc != WYRELOG_E_OK)\n"
            "      return rc;\n"
            "  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "different-admitted-session",
            "  WylFactStoreConnectionSession other_session = { 0 };\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &other_session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "dead-c-admission-block",
            "  if (0) {\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "    if (rc != WYRELOG_E_OK)\n"
            "      return rc;\n"
            "  }\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
        ),
        (
            "macro-admission-after-authority",
            "#define WYL_BOUNDARY_BEGIN "
            "wyl_fact_store_connection_session_ ## begin\n"
            "#define WYL_BOUNDARY_ADDRESS(value) &value\n"
            "  /* wyl_fact_store_connection_session_begin\n"
            "   * if (rc != WYRELOG_E_OK) return rc; */\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n"
            "  rc = WYL_BOUNDARY_BEGIN(store, WYL_BOUNDARY_ADDRESS(session));\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(
            label,
            "session owner lost admission"
            if label == "macro-admission-after-authority"
            else "session authority precedes successful admission",
            changed,
        )

    changed = dict(files)
    source_order_replacement = (
        "#define WYL_SOURCE_ORDER_BEGIN() WYRELOG_E_OK\n"
        "  rc = WYL_SOURCE_ORDER_BEGIN();\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "#undef WYL_SOURCE_ORDER_BEGIN\n"
        "#define WYL_SOURCE_ORDER_BEGIN "
        "wyl_fact_store_connection_session_begin\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region, source_order_replacement, 1
    )
    mutations.append(changed)
    require_boundary_rejection(
        "source-order-macro-redefinition", "session owner lost admission", changed
    )

    changed = dict(files)
    file_macro_source = (
        "#define WYL_FILE_GET(value) "
        "wyl_fact_store_connection_session_get(&(value))\n"
        + replay_source
    )
    changed["wyrelog/fact/replay.c"] = file_macro_source.replace(
        admitted_region,
        "  duckdb_connection conn = WYL_FILE_GET(session);\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "file-scope-macro-get-before-admission", "macro-generated", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] += (
        "\nstatic gpointer boundary_session_get_escape(void)\n"
        "{\n"
        "  WylFactStoreConnectionSession stray = { 0 };\n"
        "  return (gpointer) "
        "wyl_fact_store_connection_session_get (&stray);\n"
        "}\n"
    )
    mutations.append(changed)
    require_boundary_rejection(
        "session-get-outside-owner", "session get inventory drifted", changed
    )

    for label, replacement, expected in (
        (
            "single-line-dead-admission",
            "  if (0)\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "return-before-session-release",
            admitted_region
            + "  if (store != NULL)\n"
            "    return WYRELOG_E_INTERNAL;\n",
            "session return bypasses release",
        ),
        (
            "switch-controlled-admission",
            "  switch (0)\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "else-controlled-admission",
            "  if (1)\n"
            "    rc = WYRELOG_E_OK;\n"
            "  else\n"
            "    rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session authority precedes successful admission",
        ),
        (
            "goto-skips-session-admission",
            "  if (store != NULL)\n"
            "    goto boundary_after_begin;\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "boundary_after_begin:\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session control flow may bypass release",
        ),
        (
            "glib-return-macro-skips-release",
            admitted_region
            + "  g_return_val_if_fail (store == NULL, "
            "WYRELOG_E_INTERNAL);\n",
            "session return bypasses release",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    for label, replacement, expected in (
        (
            "conditional-profile-skips-admission",
            "#if WYL_SKIP_ADMISSION\n"
            "  rc = WYRELOG_E_OK;\n"
            "#else\n"
            "  rc = wyl_fact_store_connection_session_begin "
            "(store, &session);\n"
            "#endif\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            "session owner lost admission",
        ),
        (
            "conditional-profile-skips-release",
            None,
            "session owner lost release",
        ),
    ):
        changed = dict(files)
        if replacement is not None:
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                admitted_region, replacement, 1
            )
        else:
            changed["wyrelog/fact/replay.c"] = replay_source.replace(
                "  wyl_fact_store_connection_session_end (&session);\n",
                "#if WYL_SKIP_RELEASE\n"
                "  (void) store;\n"
                "#else\n"
                "  wyl_fact_store_connection_session_end (&session);\n"
                "#endif\n",
                1,
            )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    changed = dict(files)
    changed["wyrelog/fact/review-return-boundary.h"] = (
        "#define WYL_REVIEW_RETURN(condition, value) "
        "g_return_val_if_fail((condition), (value))\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        admitted_region
        + '#include "review-return-boundary.h"\n'
        "  WYL_REVIEW_RETURN (store == NULL, WYRELOG_E_INTERNAL);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-include-early-return",
        "session return bypasses release",
        changed,
    )

    for label, prefix, expected in (
        (
            "profile-direct-duckdb-before-admission",
            "#if WYL_PROFILE_EARLY_RAW\n"
            "  (void) duckdb_query (store->conn, \"SELECT 1;\", NULL);\n"
            "#endif\n",
            "raw DuckDB authority inventory drifted",
        ),
        (
            "profile-goto-skips-admission",
            "#if WYL_PROFILE_GOTO\n"
            "  goto boundary_profile_after_begin;\n"
            "#endif\n",
            "session control flow may bypass release",
        ),
    ):
        changed = dict(files)
        replacement = prefix + admitted_region
        if label == "profile-goto-skips-admission":
            replacement = replacement.replace(
                "  duckdb_connection conn = ",
                "boundary_profile_after_begin:\n"
                "  duckdb_connection conn = ",
                1,
            )
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region, replacement, 1
        )
        mutations.append(changed)
        require_boundary_rejection(label, expected, changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        admitted_region
        + "#if WYL_PROFILE_RETURN\n"
        "  return WYRELOG_E_INTERNAL;\n"
        "#endif\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "profile-return-skips-release", "session return bypasses release", changed
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#if WYL_ADMISSION_MODE == 2\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-profile-value-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#if WYL_RELATIONAL_ADMISSION_MODE > 1\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-relational-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    for label, condition in (
        ("numeric-reverse-relational-profile-skips-admission",
         "1 < WYL_REVERSE_ADMISSION_MODE"),
        ("numeric-bitmask-profile-skips-admission",
         "WYL_ADMISSION_FLAGS & 2"),
        ("numeric-character-profile-skips-admission",
         "WYL_CHARACTER_ADMISSION_MODE == 'A'"),
        ("numeric-nonlinear-profile-skips-admission",
         "WYL_NONLINEAR_ADMISSION_MODE * "
         "WYL_NONLINEAR_ADMISSION_MODE == 4"),
        ("numeric-large-nonlinear-profile-skips-admission",
         "WYL_LARGE_NONLINEAR_MODE * WYL_LARGE_NONLINEAR_MODE == 400"),
        ("numeric-negative-profile-skips-admission",
         "WYL_NEGATIVE_ADMISSION_MODE < -1"),
        ("numeric-octal-profile-skips-admission",
         "WYL_OCTAL_ADMISSION_MODE == 010"),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            admitted_region,
            f"#if {condition}\n"
            "  rc = WYRELOG_E_OK;\n"
            "#else\n"
            "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
            "#endif\n"
            "  if (rc != WYRELOG_E_OK)\n"
            "    return rc;\n"
            "  duckdb_connection conn = "
            "wyl_fact_store_connection_session_get (&session);\n",
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(
            label, "session owner lost admission", changed
        )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#define WYL_DERIVED_ADMISSION_TWO (1 << 1)\n"
        "#if WYL_DERIVED_ADMISSION_MODE & WYL_DERIVED_ADMISSION_TWO\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-macro-derived-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        "#define WYL_LARGE_DERIVED_TARGET (1 << 10)\n"
        "#if WYL_LARGE_DERIVED_MODE == WYL_LARGE_DERIVED_TARGET\n"
        "  rc = WYRELOG_E_OK;\n"
        "#else\n"
        "  rc = wyl_fact_store_connection_session_begin (store, &session);\n"
        "#endif\n"
        "  if (rc != WYRELOG_E_OK)\n"
        "    return rc;\n"
        "  duckdb_connection conn = "
        "wyl_fact_store_connection_session_get (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "numeric-large-macro-derived-profile-skips-admission",
        "session owner lost admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/function-raw-boundary.h"] = (
        "duckdb_connection boundary_included_early = session.connection;\n"
        "(void) boundary_included_early;\n"
    )
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        admitted_region,
        '#include "function-raw-boundary.h"\n' + admitted_region,
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "function-local-include-direct-raw-code",
        "session authority precedes successful admission",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  if (0)\n"
        "    wyl_fact_store_connection_session_end (&session);\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "single-line-dead-session-release", "session owner lost release", changed
    )

    for label, replacement in (
        (
            "switch-controlled-session-release",
            "  switch (0)\n"
            "    wyl_fact_store_connection_session_end (&session);\n",
        ),
        (
            "else-controlled-session-release",
            "  if (1)\n"
            "    rc = WYRELOG_E_OK;\n"
            "  else\n"
            "    wyl_fact_store_connection_session_end (&session);\n",
        ),
    ):
        changed = dict(files)
        changed["wyrelog/fact/replay.c"] = replay_source.replace(
            "  wyl_fact_store_connection_session_end (&session);\n",
            replacement,
            1,
        )
        mutations.append(changed)
        require_boundary_rejection(label, "session owner lost release", changed)

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "  if (store != NULL)\n"
        "    goto boundary_after_release;\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "boundary_after_release:\n"
        "  ",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "goto-bypasses-session-release",
        "session control flow may bypass release",
        changed,
    )

    changed = dict(files)
    changed["wyrelog/fact/replay.c"] = replay_source.replace(
        "  wyl_fact_store_connection_session_end (&session);\n",
        "boundary_reenter_authority:\n"
        "  wyl_fact_store_connection_session_end (&session);\n"
        "  if (store != NULL)\n"
        "    goto boundary_reenter_authority;\n",
        1,
    )
    mutations.append(changed)
    require_boundary_rejection(
        "goto-reenters-released-authority",
        "session control flow may bypass release",
        changed,
    )

    critical_mutation_ids = {id(mutation) for _label, _expected, mutation
                             in critical_mutations}
    critical_by_identity = {
        id(mutation): (label, expected)
        for label, expected, mutation in critical_mutations
    }
    mutation_cases = []
    semantic_occurrences = {}
    for old_index, mutation in enumerate(mutations, 1):
        label, expected = critical_by_identity.get(id(mutation), (None, None))
        semantic_id = _stable_mutation_id(files, mutation, label)
        occurrence = semantic_occurrences.get(semantic_id, 0) + 1
        semantic_occurrences[semantic_id] = occurrence
        mutation_id = (
            semantic_id if occurrence == 1
            else f"{semantic_id}.variant-{occurrence}"
        )
        mutation_cases.append(MutationCase(
            mutation_id=mutation_id,
            old_index=old_index,
            fingerprint=_mutation_fingerprint(files, mutation),
            files=mutation,
            expected_error=expected,
            critical=id(mutation) in critical_mutation_ids,
            label=label,
        ))
    if {case.old_index for case in mutation_cases} != set(range(1, len(mutations) + 1)):
        raise AssertionError("connection-boundary mutation indices are not contiguous")
    cases = [case for case in mutation_cases if case.critical] + [
        case for case in mutation_cases if not case.critical
    ]
    workers = min(4, len(cases) + len(validation_controls), os.cpu_count() or 1)
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=workers,
        mp_context=multiprocessing.get_context("spawn"),
        initializer=initialize_mutation_worker,
        initargs=(files,),
    ) as executor:
        control_errors = executor.map(
            control_validation_error,
            (mutation_delta(files, control) for control in validation_controls),
            chunksize=1,
        )
        for index, error in enumerate(control_errors, 1):
            if error is not None:
                raise AssertionError(
                    f"connection-boundary safe control {index} rejected: {error}"
                )
        errors = executor.map(
            mutation_validation_error,
            (
                mutation_delta(files, case.files)
                for case in cases
            ),
            # Keep each mutation independently scheduled; large batches can
            # strand the serialized self-test behind one worker failure.
            chunksize=1,
        )
        for case, error in zip(cases, errors):
            if error is None:
                kind = "critical mutation" if case.critical else "mutation"
                raise AssertionError(
                    f"connection-boundary {kind} survived: {case.mutation_id}"
                )
            if case.critical and case.expected_error not in error:
                raise AssertionError(
                    f"connection-boundary critical mutation hit wrong guard: "
                    f"{case.mutation_id}: {error}"
                )
    return tuple(mutation_cases)
