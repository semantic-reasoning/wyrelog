#!/usr/bin/env python3
"""Check the structural boundary around the handle-owned engine pair.

This intentionally checks symbols and ownership, not C control flow.  The
typed WylEngineSession capability is the proof that production consumers hold
one interval; legacy handle operations exist only in test-seam preprocessing.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import re
import sys


LEGACY_HANDLE_OPERATIONS = (
    "wyl_handle_intern_engine_symbol",
    "wyl_handle_dup_engine_symbol",
    "wyl_handle_make_engine_compound",
    "wyl_handle_make_read_engine_compound",
    "wyl_handle_make_guard_context_compound",
    "wyl_handle_engine_insert",
    "wyl_handle_engine_remove",
    "wyl_handle_engine_contains",
    "wyl_handle_engine_decide",
    "wyl_handle_engine_step_delta",
    "wyl_handle_engine_set_delta_callback",
    "wyl_handle_replay_delta_insert",
    "wyl_handle_get_read_engine",
    "wyl_handle_get_delta_engine",
)
AGGREGATE_FIELDS = (
    "read_engine",
    "delta_engine",
    "engine_symbols_by_id",
    "pending_deltas",
    "delta_callback",
    "delta_callback_user_data",
    "engine_pair_poisoned",
    "engine_pair_replacement_building",
    "engine_session_depth",
)
OWNER_ONLY_FIELDS = ("template_dir", "engine_session_mutex")


class PathFlavor(Enum):
    POSIX = "posix"
    WINDOWS = "windows"


@dataclass(frozen=True)
class RawSourcePath:
    spelling: str
    flavor: PathFlavor


@dataclass(frozen=True)
class RepoPath:
    spelling: str


OWNER = RepoPath("wyrelog/wyl-handle.c")
OWNED_ENGINE_ALLOWLIST = {
    OWNER,
    RepoPath("wyrelog/wyl-engine.c"),
    RepoPath("wyrelog/wyl-engine-private.h"),
    RepoPath("wyrelog/fact/compound.c"),
    RepoPath("wyrelog/fact/query.c"),
    RepoPath("wyrelog/fact/replay.c"),
}
OWNER_FUNCTION_ALLOWLIST = {
    "classify_audit_projection",
    "clear_pending_deltas",
    "engine_pair_unavailable",
    "reconcile_committed_engine_pair_in_session",
    "reconcile_guarded_engine_pair_in_session",
    "fail_partial_engine_pair_mutation_locked",
    "flush_pending_deltas",
    "poison_engine_pair_locked",
    "probe_audit_projection_relation",
    "repair_engine_pair_after_projection_failure",
    "replace_engine_pair",
    "replace_live_engine_pair_serialized",
    "step_delta_engine_and_flush",
    "wyl_engine_session_lookup_symbol",
    "wyl_engine_session_acquire",
    "wyl_engine_session_finish_external_publication",
    "wyl_engine_session_release",
    "wyl_engine_session_run_committed_audit_publication",
    "wyl_engine_session_run_committed_publication",
    "wyl_engine_verification_enqueue_delta",
    "wyl_handle_buffer_delta_cb",
    "wyl_handle_complete_shutdown",
    "wyl_handle_dup_engine_symbol_locked",
    "wyl_handle_engine_contains_locked",
    "wyl_handle_engine_insert_locked",
    "wyl_handle_engine_pair_is_poisoned",
    "wyl_handle_engine_remove_locked",
    "wyl_handle_engine_set_delta_callback_locked",
    "wyl_handle_engine_step_delta_locked",
    "wyl_handle_finalize",
    "wyl_handle_init",
    "wyl_handle_insert_audit_fact",
    "wyl_handle_insert_audit_fact_locked",
    "wyl_handle_intern_engine_symbol_locked",
    "wyl_handle_lookup_engine_symbol_locked",
    "wyl_handle_intern_guard_symbol",
    "wyl_handle_intern_symbol_on_engine",
    "wyl_handle_load_policy_store_audit_events",
    "engine_session_lock_owner",
    "wyl_handle_make_engine_compound_locked",
    "wyl_handle_make_guard_binary_compound",
    "wyl_handle_make_guard_cmp_compound",
    "wyl_handle_make_guard_context_compound_locked",
    "wyl_handle_make_guard_expr_compound",
    "wyl_handle_make_guard_tag_compound",
    "wyl_handle_make_guard_unary_compound",
    "wyl_handle_make_read_engine_compound_locked",
    "wyl_handle_open_engine_pair",
    "wyl_handle_open_with_options",
    "wyl_handle_reconcile_committed_engine_pair",
    "wyl_handle_replay_delta_insert_locked",
    "wyl_handle_seed_perm_arm_rule_on_engine",
    "wyl_handle_seed_perm_arm_rules",
    "wyl_handle_shutdown_ordered",
}
CONTROL_WORDS = {"if", "for", "while", "switch"}


def native_path_flavor(path: PurePath) -> PathFlavor | None:
    """Return a path object's native flavor without inspecting its spelling."""
    if isinstance(path, PureWindowsPath):
        return PathFlavor.WINDOWS
    if isinstance(path, PurePosixPath):
        return PathFlavor.POSIX
    return None


def discovered_source_path(
    path: PurePath,
    root: PurePath,
) -> tuple[RawSourcePath | None, str | None]:
    """Preserve native flavor and parts for one filesystem-discovered path."""
    path_flavor = native_path_flavor(path)
    root_flavor = native_path_flavor(root)
    if path_flavor is None or root_flavor is None:
        return None, "unsupported native path flavor"
    if path_flavor is not root_flavor:
        return None, "path flavor does not match root flavor"
    try:
        relative = path.relative_to(root)
    except ValueError:
        return None, "path is outside source root"
    separator = "\\" if path_flavor is PathFlavor.WINDOWS else "/"
    return RawSourcePath(separator.join(relative.parts), path_flavor), None


def canonical_repo_path(raw: RawSourcePath) -> tuple[RepoPath | None, str | None]:
    """Validate a flavored raw identity and emit its slash-separated key."""
    if not isinstance(raw, RawSourcePath):
        return None, "untyped source path"
    if not isinstance(raw.spelling, str):
        return None, "non-string spelling"
    if not isinstance(raw.flavor, PathFlavor):
        return None, "invalid path flavor"
    if raw.spelling == "":
        return None, "empty path"

    if raw.flavor is PathFlavor.POSIX:
        path = PurePosixPath(raw.spelling)
        components = raw.spelling.split("/")
        if path.anchor or path.is_absolute():
            return None, "absolute or anchored path"
        if raw.spelling.endswith("/"):
            return None, "trailing separator"
        if "//" in raw.spelling:
            return None, "repeated separator"
    else:
        path = PureWindowsPath(raw.spelling)
        separator_pattern = r"[\\/]"
        components = re.split(separator_pattern, raw.spelling)
        if path.drive and not path.root:
            return None, "drive-relative path"
        if path.anchor or path.drive or path.root or path.is_absolute():
            return None, "absolute or anchored path"
        if raw.spelling.endswith(("\\", "/")):
            return None, "trailing separator"
        if re.search(separator_pattern + r"{2,}", raw.spelling):
            return None, "repeated separator"

    if ".." in components:
        return None, "parent component"
    if "." in components:
        return None, "dot component"
    if "" in components:
        return None, "empty component"
    return RepoPath(path.as_posix()), None


def invalid_repo_path_reason(path: RepoPath) -> str | None:
    """Reject forged or noncanonical keys even when wrapped as RepoPath."""
    if not isinstance(path, RepoPath):
        return "expected RepoPath key"
    canonical, reason = canonical_repo_path(
        RawSourcePath(path.spelling, PathFlavor.POSIX))
    if reason is not None:
        return reason
    if canonical != path:
        return "noncanonical repository path"
    return None


def without_test_seams(source: str) -> str:
    """Blank WYL_TEST_HANDLE_SEAMS branches while retaining line layout."""
    output = []
    stack: list[tuple[bool, bool, bool]] = []
    enabled = True
    for line in source.splitlines(keepends=True):
        directive = line.lstrip()
        match = re.match(r"#\s*(ifdef|ifndef)\s+WYL_TEST_HANDLE_SEAMS\b",
                         directive)
        defined_match = re.match(
            r"#\s*if\s+defined\s*\(\s*WYL_TEST_HANDLE_SEAMS\s*\)",
            directive)
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


def mask_comments_and_literals(source: str) -> str:
    """Replace comments and literals, preserving newlines and token spacing."""
    pattern = re.compile(
        r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'",
        re.DOTALL,
    )
    return pattern.sub(lambda m: "".join("\n" if c == "\n" else " "
                                          for c in m.group()), source)


def top_level_functions(source: str) -> list[tuple[str, str]]:
    """Return top-level C function names and bodies from already-masked text."""
    functions = []
    depth = 0
    start = 0
    name = None
    for index, char in enumerate(source):
        if char == "{":
            if depth == 0:
                prefix = source[max(0, index - 2000):index]
                match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*"
                                  r"\([^;{}]*\)\s*$", prefix, re.DOTALL)
                if match and match.group(1) not in CONTROL_WORDS:
                    name = match.group(1)
                    start = index
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and name is not None:
                functions.append((name, source[start:index + 1]))
                name = None
    return functions


def check(sources: dict[RepoPath, str]) -> list[str]:
    errors = []
    legacy = re.compile(r"\b(?:" + "|".join(map(re.escape,
                        LEGACY_HANDLE_OPERATIONS)) + r")\s*\(")
    member = (r"(?:->|\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\."
              r"|\b[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]\s*\.)\s*(?:")
    fields = re.compile(member + "|".join(map(re.escape,
                        AGGREGATE_FIELDS + ("engine_session_mutex",))) + r")\b")
    owner_fields = re.compile(member + "|".join(map(re.escape,
                              AGGREGATE_FIELDS + OWNER_ONLY_FIELDS)) + r")\b")
    owned = re.compile(r"\bwyl_engine_owned_[A-Za-z0-9_]*\s*\(")
    raw_lock = re.compile(r"\bwyl_handle_lock_engine_session\s*\(")

    for path, raw in sources.items():
        invalid_reason = invalid_repo_path_reason(path)
        if invalid_reason is not None:
            errors.append(
                f"invalid source key ({invalid_reason}): {path!r}")
            continue
        assert isinstance(path, RepoPath)
        source = mask_comments_and_literals(without_test_seams(raw))
        if legacy.search(source):
            errors.append(
                "legacy handle engine operation in production: "
                f"{path.spelling!r}")
        if path != OWNER and fields.search(source):
            errors.append(
                "handle-owned engine aggregate accessed outside owner: "
                f"{path.spelling!r}")
        if path not in OWNED_ENGINE_ALLOWLIST and owned.search(source):
            errors.append(
                "owned engine primitive outside allowlist: "
                f"{path.spelling!r}")
        if path != OWNER and raw_lock.search(source):
            errors.append(
                f"untyped engine lock outside owner: {path.spelling!r}")
        if path == OWNER:
            for name, body in top_level_functions(source):
                if (owner_fields.search(body) or owned.search(body)
                        or raw_lock.search(body)) and name not in OWNER_FUNCTION_ALLOWLIST:
                    errors.append(
                        f"owner aggregate access outside function allowlist: {name}")
    return sorted(set(errors))


def collect_sources(root: Path) -> tuple[dict[RepoPath, str], list[str]]:
    """Discover, canonicalize, and inventory production source identities."""
    sources = {}
    errors = []
    owner_occurrences = 0
    for path in (root / "wyrelog").rglob("*"):
        if path.suffix not in {".c", ".cc", ".h", ".hh", ".hpp"}:
            continue
        raw_path, discovery_error = discovered_source_path(path, root)
        if discovery_error is not None:
            errors.append(
                "invalid discovered source path "
                f"({discovery_error}): {str(path)!r}")
            continue
        assert raw_path is not None
        repo_path, canonical_error = canonical_repo_path(raw_path)
        if canonical_error is not None:
            errors.append(
                f"invalid source path ({canonical_error}): {raw_path!r}")
            continue
        assert repo_path is not None
        if repo_path == OWNER:
            owner_occurrences += 1
        if repo_path in sources:
            errors.append(
                f"duplicate canonical source path: {repo_path.spelling!r}")
            continue
        sources[repo_path] = path.read_text(encoding="utf-8")
    if owner_occurrences != 1:
        errors.append(
            "owner source must occur exactly once: "
            f"{OWNER.spelling!r} (found {owner_occurrences})")
    return sources, errors


def self_test() -> int:
    accepted = {
        OWNER: (
            "static void allowed_owner(WylHandle *h) { (void) h; }"
        ),
        RepoPath("wyrelog/good.c"): (
            "void good(WylEngineSession *s) { "
            "wyl_engine_session_insert(s, \"r\", 0, 0); }\n"
            "#ifdef WYL_TEST_HANDLE_SEAMS\n"
            "void seam(WylHandle *h) { wyl_handle_get_read_engine(h); }\n"
            "#endif\n"
        ),
    }
    if check(accepted):
        print("self-test rejected valid fixture", file=sys.stderr)
        return 1

    windows_root = PureWindowsPath(r"C:\source\wyrelog")
    windows_owner_raw, windows_owner_error = discovered_source_path(
        windows_root / "wyrelog" / "wyl-handle.c", windows_root)
    windows_fact_raw, windows_fact_error = discovered_source_path(
        windows_root / "wyrelog" / "fact" / "compound.c", windows_root)
    if (windows_owner_error is not None or windows_fact_error is not None
            or windows_owner_raw is None or windows_fact_raw is None
            or windows_owner_raw.flavor is not PathFlavor.WINDOWS
            or windows_owner_raw.spelling != r"wyrelog\wyl-handle.c"
            or windows_fact_raw.spelling
            != r"wyrelog\fact\compound.c"):
        print("self-test failed Windows path discovery normalization",
              file=sys.stderr)
        return 1
    windows_owner, windows_owner_error = canonical_repo_path(windows_owner_raw)
    windows_fact_compound, windows_fact_error = canonical_repo_path(
        windows_fact_raw)
    if (windows_owner_error is not None or windows_fact_error is not None
            or windows_owner is None or windows_fact_compound is None):
        print("self-test failed Windows path canonicalization", file=sys.stderr)
        return 1
    windows_accepted = {
        windows_owner: (
            "static void wyl_handle_init(WylHandle *h) { "
            "h->read_engine = 0; }"
        ),
        windows_fact_compound: (
            "void good(WylEngine *e) { "
            "wyl_engine_owned_insert(e, 0, 0, 0); }"
        ),
    }
    if check(windows_accepted):
        print("self-test rejected Windows-style valid paths", file=sys.stderr)
        return 1

    windows_bad_raw, windows_bad_error = discovered_source_path(
        windows_root / "wyrelog" / "bad.c", windows_root)
    if windows_bad_error is not None or windows_bad_raw is None:
        print("self-test failed Windows diagnostic discovery", file=sys.stderr)
        return 1
    windows_bad, windows_bad_error = canonical_repo_path(windows_bad_raw)
    if windows_bad_error is not None or windows_bad is None:
        print("self-test failed Windows diagnostic canonicalization",
              file=sys.stderr)
        return 1
    windows_errors = check({
        windows_bad: (
            "void bad(WylEngine *e) { "
            "wyl_engine_owned_insert(e, 0, 0, 0); }"
        ),
    })
    if windows_errors != [
            "owned engine primitive outside allowlist: 'wyrelog/bad.c'"]:
        print("self-test emitted noncanonical Windows diagnostic",
              file=sys.stderr)
        return 1

    posix_root = PurePosixPath("/source/wyrelog")
    posix_fact_raw, posix_fact_error = discovered_source_path(
        posix_root / "wyrelog" / r"fact\compound.c", posix_root)
    if posix_fact_error is not None or posix_fact_raw is None:
        print("self-test failed POSIX spoof discovery", file=sys.stderr)
        return 1
    posix_fact_spoof, posix_fact_error = canonical_repo_path(posix_fact_raw)
    if posix_fact_error is not None or posix_fact_spoof is None:
        print("self-test failed POSIX spoof canonicalization", file=sys.stderr)
        return 1
    posix_spoof_errors = check({
        posix_fact_spoof: (
            "void bad(WylEngine *e) { "
            "wyl_engine_owned_insert(e, 0, 0, 0); }"
        ),
    })
    if posix_spoof_errors != [
            r"owned engine primitive outside allowlist: 'wyrelog/fact\\compound.c'"]:
        print("self-test aliased POSIX literal-backslash fact path",
              file=sys.stderr)
        return 1

    posix_owner_spoof, posix_owner_error = canonical_repo_path(RawSourcePath(
        r"wyrelog\wyl-handle.c", PathFlavor.POSIX))
    if posix_owner_error is not None or posix_owner_spoof is None:
        print("self-test failed POSIX owner spoof canonicalization",
              file=sys.stderr)
        return 1
    if check({posix_owner_spoof: (
            "static void wyl_handle_init(WylHandle *h) { "
            "h->read_engine = 0; }"
            )}) != [
            r"handle-owned engine aggregate accessed outside owner: 'wyrelog\\wyl-handle.c'"]:
        print("self-test aliased POSIX literal-backslash owner path",
              file=sys.stderr)
        return 1

    invalid_paths = (
        (RawSourcePath("", PathFlavor.POSIX), "empty path"),
        (RawSourcePath("/wyrelog/fact/compound.c", PathFlavor.POSIX),
         "absolute or anchored path"),
        (RawSourcePath("wyrelog/../fact/compound.c", PathFlavor.POSIX),
         "parent component"),
        (RawSourcePath("wyrelog/./fact/compound.c", PathFlavor.POSIX),
         "dot component"),
        (RawSourcePath("wyrelog//fact/compound.c", PathFlavor.POSIX),
         "repeated separator"),
        (RawSourcePath("wyrelog/fact/", PathFlavor.POSIX),
         "trailing separator"),
        (RawSourcePath("", PathFlavor.WINDOWS), "empty path"),
        (RawSourcePath(r"C:\wyrelog\fact\compound.c", PathFlavor.WINDOWS),
         "absolute or anchored path"),
        (RawSourcePath(r"\\server\share\wyrelog\fact\compound.c",
                       PathFlavor.WINDOWS), "absolute or anchored path"),
        (RawSourcePath(r"\wyrelog\fact\compound.c", PathFlavor.WINDOWS),
         "absolute or anchored path"),
        (RawSourcePath(r"C:wyrelog\fact\compound.c", PathFlavor.WINDOWS),
         "drive-relative path"),
        (RawSourcePath(r"wyrelog\..\fact\compound.c", PathFlavor.WINDOWS),
         "parent component"),
        (RawSourcePath(r"wyrelog\.\fact\compound.c", PathFlavor.WINDOWS),
         "dot component"),
        (RawSourcePath(r"wyrelog\\fact\compound.c", PathFlavor.WINDOWS),
         "repeated separator"),
        (RawSourcePath("wyrelog\\fact\\", PathFlavor.WINDOWS),
         "trailing separator"),
    )
    for invalid_path, reason in invalid_paths:
        invalid_repo_path, invalid_reason = canonical_repo_path(invalid_path)
        if invalid_repo_path is not None or invalid_reason != reason:
            print(f"self-test accepted invalid path: {invalid_path!r}",
                  file=sys.stderr)
            return 1

    untyped_errors = check({OWNER.spelling: ""})
    if untyped_errors != [
            f"invalid source key (expected RepoPath key): {OWNER.spelling!r}"]:
        print("self-test accepted untyped source-map identity", file=sys.stderr)
        return 1

    forged_errors = check({RepoPath("/wyrelog/wyl-handle.c"): ""})
    if forged_errors != [
            "invalid source key (absolute or anchored path): "
            "RepoPath(spelling='/wyrelog/wyl-handle.c')"]:
        print("self-test accepted forged RepoPath identity", file=sys.stderr)
        return 1

    case_variant = RepoPath("Wyrelog/wyl-handle.c")
    case_errors = check({case_variant: (
        "static void wyl_handle_init(WylHandle *h) { h->read_engine = 0; }"
    )})
    if case_errors != [
            "handle-owned engine aggregate accessed outside owner: "
            "'Wyrelog/wyl-handle.c'"]:
        print("self-test folded source path case", file=sys.stderr)
        return 1

    mismatch_raw, mismatch_error = discovered_source_path(
        PureWindowsPath(r"C:\source\wyrelog\wyrelog\wyl-handle.c"),
        PurePosixPath("/source/wyrelog"))
    if (mismatch_raw is not None
            or mismatch_error != "path flavor does not match root flavor"):
        print("self-test accepted mismatched native path flavors",
              file=sys.stderr)
        return 1

    mutants = (
        "void bad(WylHandle *h) { wyl_handle_engine_insert(h, 0, 0, 0); }",
        "void bad(WylHandle *h) { (void) h->delta_engine; }",
        "void bad(WylHandle *h) { (void) (*h).read_engine; }",
        "void bad(WylHandle *h) { (void) h[0].engine_pair_poisoned; }",
        "void bad(WylEngine *e) { wyl_engine_owned_insert(e, 0, 0, 0); }",
        "void bad(WylHandle *h) { wyl_handle_lock_engine_session(h); }",
        "void bad(WylHandle *h) { g_rec_mutex_lock(&(*h).engine_session_mutex); }",
        "void bad(WylHandle *h) { g_rec_mutex_unlock(&h[0].engine_session_mutex); }",
    )
    for mutant in mutants:
        if not check({OWNER: "", RepoPath("wyrelog/bad.c"): mutant}):
            print(f"self-test accepted mutant: {mutant}", file=sys.stderr)
            return 1
    owner_mutants = (
        "static void bad_read(WylHandle *h) { h->read_engine = 0; }",
        "static void bad_deref(WylHandle *h) { (*h).delta_engine = 0; }",
        "static void bad_array(WylHandle *h) { h[0].pending_deltas = 0; }",
        "static void bad_template(WylHandle *h) { h->template_dir = 0; }",
        "static void bad_mutex(WylHandle *h) { g_rec_mutex_lock(&h->engine_session_mutex); }",
        "static void bad_owned(WylEngine *e) { wyl_engine_owned_step(e); }",
    )
    for mutant in owner_mutants:
        if not check({OWNER: mutant}):
            print(f"self-test accepted owner mutant: {mutant}", file=sys.stderr)
            return 1
    allowed_owner = (
        "static void wyl_handle_init(WylHandle *h) { "
        "(*h).read_engine = 0; h[0].engine_pair_poisoned = 0; "
        "g_rec_mutex_init(&(*h).engine_session_mutex); }"
    )
    if check({OWNER: allowed_owner}):
        print("self-test rejected allowlisted owner body", file=sys.stderr)
        return 1
    literal = 'const char *s = "wyl_handle_get_read_engine(h)"; /* h->read_engine */'
    if check({OWNER: "", RepoPath("wyrelog/literal.c"): literal}):
        print("self-test rejected comments/literals", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    if len(sys.argv) != 2:
        print("usage: check-engine-session-boundary.py SOURCE_ROOT | --self-test",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    sources, errors = collect_sources(root)
    errors.extend(check(sources))
    errors = sorted(set(errors))
    if errors:
        print("engine-session boundary violations:", *errors, sep="\n  ",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
