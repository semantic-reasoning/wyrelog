#!/usr/bin/env python3
"""Check the structural boundary around the handle-owned engine pair.

This intentionally checks symbols and ownership, not C control flow.  The
typed WylEngineSession capability is the proof that production consumers hold
one interval; legacy handle operations exist only in test-seam preprocessing.

Discovery is hardened so a lexical scan cannot prove properties about a
different inventory than the one that is built: REJECT symlinks/reparse/
junctions; every production source must be a contained regular file with
exactly one physical identity; and compiled production TUs are reconciled
against the scan and fail CLOSED if a compiled unit was never scanned.  POSIX
detects aliases with S_ISLNK; Windows additionally sets
FILE_ATTRIBUTE_REPARSE_POINT on junction directories.
"""

import argparse
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import re
import stat
import sys
import tempfile


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
    "engine_terminal_state",
    "engine_terminal_generation",
    "engine_terminal_serial",
)
OWNER_ONLY_FIELDS = (
    "template_dir",
    "engine_session_mutex",
    "engine_terminal_mutex",
)
TERMINAL_FIELDS = (
    "engine_terminal_state",
    "engine_terminal_generation",
    "engine_terminal_serial",
)
LOCKED_REPLACEMENT_LOADERS = (
    "load_policy_store_audit_facts_locked",
    "load_policy_store_role_permissions_locked",
    "load_policy_store_role_memberships_locked",
    "load_policy_store_direct_permissions_locked",
    "load_policy_store_permission_states_locked",
    "load_policy_store_permission_state_events_locked",
    "load_policy_store_principal_states_locked",
    "load_policy_store_principal_events_locked",
    "load_policy_store_session_states_locked",
    "load_policy_store_session_events_locked",
)
PUBLIC_REPLACEMENT_LOADERS = tuple(
    name.removesuffix("_locked").replace("load_policy_store_",
                                           "wyl_handle_load_policy_store_")
    for name in LOCKED_REPLACEMENT_LOADERS
)
# These exact transition owners may inspect terminal fields, but must acquire
# and release the terminal mutex in their own body.  The narrow inventory is a
# capability list: similarly named helpers gain no authority.
TERMINAL_MUTEX_OWNERS = {
    "engine_terminal_admit_after_engine_lock",
    "engine_terminal_abandon_recovery",
    "engine_terminal_finish_pending",
    "wyl_engine_session_finish_terminal_recovery",
    "wyl_handle_engine_terminal_begin",
    "wyl_handle_engine_terminal_get_state",
}


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


def escape_ascii_identity(spelling: str) -> str:
    """Render a spelling as a double-quoted, ASCII-only, single-line literal.

    The result is always wrapped in double quotes.  Reversing the escapes
    ``\\\\ \\" \\n \\r \\t \\xHH \\uHHHH \\U00HHHHHH`` inside the outer double
    quotes recovers the exact original spelling byte-for-byte: case is
    preserved and no Unicode normalization is applied.  A literal single quote
    is left as-is because it is unambiguous inside double quotes.
    """
    escaped = spelling.replace("\\", "\\\\")
    escaped = escaped.replace("\"", "\\\"")
    escaped = escaped.replace("\n", "\\n")
    escaped = escaped.replace("\r", "\\r")
    escaped = escaped.replace("\t", "\\t")
    out = []
    for char in escaped:
        codepoint = ord(char)
        if codepoint < 0x20 or codepoint == 0x7f or codepoint > 0x7e:
            if codepoint <= 0xff:
                out.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xffff:
                out.append(f"\\u{codepoint:04x}")
            else:
                out.append(f"\\U{codepoint:08x}")
        else:
            out.append(char)
    result = "\"" + "".join(out) + "\""
    assert result.isascii()
    assert "\n" not in result
    assert "\r" not in result
    return result


def render_source_identity(
    value: "str | RepoPath | RawSourcePath | PurePath") -> str:
    """Render any source identity as an ASCII-safe single-line diagnostic."""
    flavor: PathFlavor | None = None
    tagged = False
    if isinstance(value, RepoPath):
        spelling = value.spelling
    elif isinstance(value, RawSourcePath):
        spelling = value.spelling
        flavor = value.flavor
        tagged = True
    elif isinstance(value, PurePath):
        spelling = str(value)
        flavor = native_path_flavor(value)
        tagged = True
    elif isinstance(value, str):
        spelling = value
    else:
        spelling = str(value)
    rendered = escape_ascii_identity(spelling)
    if tagged:
        tag = flavor.value if flavor is not None else "unknown-flavor"
        rendered = f"{rendered} [{tag}]"
    return rendered


OWNER = RepoPath("wyrelog/wyl-handle.c")
ENGINE_OWNER = RepoPath("wyrelog/wyl-engine.c")
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
    # Recovery-owner cleanup: RECOVERING -> FAILED on abandoned release.
    "engine_terminal_abandon_recovery",
    "engine_terminal_admit_after_engine_lock",
    # Exact pending-token completion/failure transition owner.
    "engine_terminal_finish_pending",
    # Caller-held terminal-mutex token comparison helper.
    "engine_terminal_token_matches_locked",
    "engine_session_acquire_full",
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
    "wyl_engine_session_begin_external_service_authority_transaction",
    "wyl_engine_session_finish_terminal_recovery",
    "wyl_engine_session_get_accepted_session_state",
    "wyl_engine_session_has_exact_accepted_member_of",
    "wyl_engine_session_finish_external_publication",
    "wyl_engine_session_release",
    "wyl_engine_session_release_checked",
    "wyl_engine_session_repair_committed_publication",
    "wyl_engine_session_run_committed_audit_publication",
    "wyl_engine_session_run_committed_publication",
    "wyl_engine_verification_enqueue_delta",
    "wyl_engine_verification_get_accepted_session_state",
    "wyl_engine_verification_has_exact_accepted_member_of",
    "wyl_engine_verification_has_exact_keyed_row",
    "wyl_handle_buffer_delta_cb",
    "wyl_handle_complete_shutdown",
    "wyl_handle_dup_engine_symbol_locked",
    "wyl_handle_engine_contains_locked",
    "wyl_handle_engine_terminal_begin",
    # Mutex-synchronized, read-only terminal-state snapshot.
    "wyl_handle_engine_terminal_get_state",
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
DIRECT_SUBSTRATE_FUNCTIONS = {
    "wyl_engine_insert_unchecked",
    "wyl_engine_remove_unchecked",
}
TYPED_EXTERNAL_TRANSACTION_BEGIN = (
    "wyl_engine_session_begin_external_service_authority_transaction")
RAW_EXTERNAL_TRANSACTION_BEGIN = (
    "wyl_policy_store_service_authority_transaction_"
    "begin_retained_engine_parent")
TYPED_EXTERNAL_TRANSACTION_CONSUMERS = {
    OWNER,
    RepoPath("wyrelog/wyl-handle-private.h"),
    RepoPath("wyrelog/auth/service-credential-domain.c"),
}
RAW_EXTERNAL_TRANSACTION_CONSUMERS = {
    OWNER,
    RepoPath("wyrelog/policy/store.c"),
    RepoPath("wyrelog/policy/store-private.h"),
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


def link_component_rejection(st_mode: int,
                             st_file_attributes: int = 0) -> str | None:
    """Reject a symlink or reparse-point path component from its lstat mode.

    Pure over the stat fields so mocked tests can drive it without a real
    filesystem.  POSIX uses S_ISLNK; Windows sets FILE_ATTRIBUTE_REPARSE_POINT
    on junctions and other reparse points.
    """
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(st_mode) or (st_file_attributes & reparse):
        return "symlinked or reparse-point path component"
    return None


def nonregular_leaf_rejection(st_mode: int) -> str | None:
    """Reject a non-regular leaf (fifo/device/socket) from its lstat mode.

    Symlinks are already caught by link_component_rejection; this covers the
    remaining non-regular kinds.
    """
    if not stat.S_ISREG(st_mode):
        return "non-regular source file"
    return None


def duplicate_identity_rejection(
        repo_path: RepoPath, identity: tuple[int, int],
        identities: dict[tuple[int, int], "RepoPath"]) -> str | None:
    """Reject a second repo key that aliases an already-seen physical identity.

    Records the first key for a given (st_dev, st_ino) and rejects any later
    key that maps to it.  Mutates @identities on acceptance so the caller and
    mocked tests share one identity map.
    """
    prior = identities.get(identity)
    if prior is not None:
        return (f"duplicate physical identity: {repo_path.spelling} "
                f"aliases {prior.spelling}")
    identities[identity] = repo_path
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
                        AGGREGATE_FIELDS + ("engine_session_mutex",
                                            "engine_terminal_mutex"))) + r")\b")
    owner_fields = re.compile(member + "|".join(map(re.escape,
                              AGGREGATE_FIELDS + OWNER_ONLY_FIELDS)) + r")\b")
    owned = re.compile(r"\bwyl_engine_owned_[A-Za-z0-9_]*\s*\(")
    raw_lock = re.compile(r"\bwyl_handle_lock_engine_session\s*\(")
    typed_external_begin = re.compile(
        rf"\b{re.escape(TYPED_EXTERNAL_TRANSACTION_BEGIN)}\s*\(")
    raw_external_begin = re.compile(
        rf"\b{re.escape(RAW_EXTERNAL_TRANSACTION_BEGIN)}\s*\(")
    direct_substrate = re.compile(r"\bwirelog_easy_(?:insert|remove)\s*\(")

    for path, raw in sources.items():
        invalid_reason = invalid_repo_path_reason(path)
        if invalid_reason is not None:
            errors.append(
                f"invalid source key ({invalid_reason}): "
                f"{render_source_identity(path)}")
            continue
        assert isinstance(path, RepoPath)
        source = mask_comments_and_literals(without_test_seams(raw))
        if legacy.search(source):
            errors.append(
                "legacy handle engine operation in production: "
                f"{render_source_identity(path)}")
        if path != OWNER and fields.search(source):
            errors.append(
                "handle-owned engine aggregate accessed outside owner: "
                f"{render_source_identity(path)}")
        if path not in OWNED_ENGINE_ALLOWLIST and owned.search(source):
            errors.append(
                "owned engine primitive outside allowlist: "
                f"{render_source_identity(path)}")
        if path != ENGINE_OWNER and direct_substrate.search(source):
            errors.append(
                "direct Wirelog input mutation outside engine owner: "
                f"{render_source_identity(path)}")
        if path != OWNER and raw_lock.search(source):
            errors.append(
                "untyped engine lock outside owner: "
                f"{render_source_identity(path)}")
        if (path not in TYPED_EXTERNAL_TRANSACTION_CONSUMERS
                and typed_external_begin.search(source)):
            errors.append(
                "typed external transaction begin outside allowlist: "
                f"{render_source_identity(path)}")
        if (path not in RAW_EXTERNAL_TRANSACTION_CONSUMERS
                and raw_external_begin.search(source)):
            errors.append(
                "raw external transaction begin outside owner/store: "
                f"{render_source_identity(path)}")
        if path == OWNER:
            functions = dict(top_level_functions(source))
            for name, body in functions.items():
                if (owner_fields.search(body) or owned.search(body)
                        or raw_lock.search(body)) and name not in OWNER_FUNCTION_ALLOWLIST:
                    errors.append(
                        f"owner aggregate access outside function allowlist: {name}")

            terminal_field = re.compile(
                member + "|".join(map(re.escape, TERMINAL_FIELDS)) + r")\b")
            terminal_lock = re.compile(
                r"\bg_mutex_lock\s*\(\s*&\s*"
                r"[A-Za-z_][A-Za-z0-9_]*\s*->\s*"
                r"engine_terminal_mutex\s*\)")
            terminal_unlock = re.compile(
                r"\bg_mutex_unlock\s*\(\s*&\s*"
                r"[A-Za-z_][A-Za-z0-9_]*\s*->\s*"
                r"engine_terminal_mutex\s*\)")
            for name in TERMINAL_MUTEX_OWNERS:
                body = functions.get(name)
                if (body is not None and terminal_field.search(body)
                        and (not terminal_lock.search(body)
                             or not terminal_unlock.search(body))):
                    errors.append(
                        "terminal field access without owned mutex interval: "
                        f"{name}")

            acquire = re.compile(
                r"\bwyl_engine_session_acquire"
                r"(?:_terminal_recovery)?\s*\(")
            rank = re.compile(r"\bwyl_service_auth_rank_[A-Za-z0-9_]*\s*\(")
            terminal_access = re.compile(
                member + "|".join(map(re.escape,
                    TERMINAL_FIELDS + ("engine_terminal_mutex",))) + r")\b")
            terminal_call = re.compile(
                r"\b(?:engine_terminal_|wyl_handle_engine_terminal_|"
                r"wyl_engine_session_finish_terminal_recovery)"
                r"[A-Za-z0-9_]*\s*\(")
            for name in LOCKED_REPLACEMENT_LOADERS:
                body = functions.get(name)
                if body is None:
                    continue
                if (acquire.search(body) or rank.search(body)
                        or terminal_access.search(body)
                        or terminal_call.search(body)):
                    errors.append(
                        "locked replacement loader crosses session boundary: "
                        f"{name}")

            audit_callback = functions.get("insert_policy_store_audit_fact")
            public_audit_insert = re.compile(
                r"\bwyl_handle_insert_audit_fact\s*\(")
            locked_audit_insert = re.compile(
                r"\bwyl_handle_insert_audit_fact_locked\s*\(")
            if audit_callback is not None and (
                    public_audit_insert.search(audit_callback)
                    or not locked_audit_insert.search(audit_callback)):
                errors.append(
                    "audit replay callback must use locked insertion")

            load_body = functions.get("load_current_engine_pair")
            if load_body is not None:
                for name in LOCKED_REPLACEMENT_LOADERS:
                    if not re.search(rf"\b{re.escape(name)}\s*\(", load_body):
                        errors.append(
                            "replacement load chain missing locked core: "
                            f"{name}")
                if acquire.search(load_body):
                    errors.append(
                        "replacement load chain reacquires engine session")
                for name in PUBLIC_REPLACEMENT_LOADERS:
                    if re.search(rf"\b{re.escape(name)}\s*\(", load_body):
                        errors.append(
                            "replacement load chain calls public loader: "
                            f"{name}")

            replace_body = functions.get("replace_engine_pair")
            if replace_body is not None:
                explicit_candidate = re.compile(
                    r"\bload_current_engine_pair\s*\(\s*session\s*,\s*"
                    r"wyl_engine_session_state_capability\s*\(\s*"
                    r"new_read_engine\s*\)\s*\)")
                if not explicit_candidate.search(replace_body):
                    errors.append(
                        "replacement must pass candidate session capability")
                if acquire.search(replace_body):
                    errors.append(
                        "replacement path reacquires engine session")
        if path == ENGINE_OWNER:
            for name, body in top_level_functions(source):
                if (direct_substrate.search(body)
                        and name not in DIRECT_SUBSTRATE_FUNCTIONS):
                    errors.append(
                        "direct Wirelog input mutation outside funnel: "
                        f"{name}")
    return sorted(set(errors))


def collect_sources(root: Path) -> tuple[dict[RepoPath, str], list[str]]:
    """Discover, canonicalize, and inventory production source identities.

    Every rglob hit is proven to be a contained regular file with a unique
    physical identity BEFORE it is read, so the scan cannot silently follow a
    filesystem alias to a different inventory.  For each hit, in order:
      (a) reject any symlink/reparse-point path component (ancestor or leaf),
          via lstat and BEFORE any resolve() -- resolve(strict=False) does not
          raise on a dangling link, so the lstat walk is the real detector;
      (b) reject a non-regular leaf (fifo/device/socket);
      (c) reject a leaf that resolves outside the source root (defense in
          depth against an escape a component walk missed);
      (d) reject a second repo key that aliases an already-seen (dev, ino).
    """
    sources = {}
    errors = []
    owner_occurrences = 0
    production = root / "wyrelog"
    root_real = root.resolve()
    identities: dict[tuple[int, int], RepoPath] = {}
    for path in production.rglob("*"):
        if path.suffix not in {".c", ".cc", ".h", ".hh", ".hpp"}:
            continue

        # (a) Ancestor + leaf symlink/reparse walk, before any resolve().
        alias_error = None
        leaf_stat = None
        cumulative = production
        for component in path.relative_to(production).parts:
            cumulative = cumulative / component
            try:
                leaf_stat = os.lstat(cumulative)
            except OSError as error:
                alias_error = (
                    "unreadable source path component "
                    f"({error.strerror}): "
                    f"{render_source_identity(cumulative)}")
                break
            reason = link_component_rejection(
                leaf_stat.st_mode,
                getattr(leaf_stat, "st_file_attributes", 0))
            if reason is not None:
                alias_error = (
                    f"{reason}: {render_source_identity(cumulative)}")
                break
        if alias_error is not None:
            errors.append(alias_error)
            continue
        assert leaf_stat is not None

        # (b) The leaf must be a regular file.
        leaf_reason = nonregular_leaf_rejection(leaf_stat.st_mode)
        if leaf_reason is not None:
            errors.append(
                f"{leaf_reason}: {render_source_identity(path)}")
            continue

        # (c) Containment: the resolved leaf must stay within the source root.
        real = path.resolve()
        if not real.is_relative_to(root_real):
            errors.append(
                "source resolves outside root: "
                f"{render_source_identity(path)}")
            continue

        raw_path, discovery_error = discovered_source_path(path, root)
        if discovery_error is not None:
            errors.append(
                "invalid discovered source path "
                f"({discovery_error}): {render_source_identity(path)}")
            continue
        assert raw_path is not None
        repo_path, canonical_error = canonical_repo_path(raw_path)
        if canonical_error is not None:
            errors.append(
                f"invalid source path ({canonical_error}): "
                f"{render_source_identity(raw_path)}")
            continue
        assert repo_path is not None
        if repo_path in sources:
            errors.append(
                "duplicate canonical source path: "
                f"{render_source_identity(repo_path)}")
            continue

        # (d) One physical identity per repo key.
        identity_error = duplicate_identity_rejection(
            repo_path, (leaf_stat.st_dev, leaf_stat.st_ino), identities)
        if identity_error is not None:
            errors.append(identity_error)
            continue
        # Count OWNER only once the source is accepted, so an alias that
        # displaces the real owner (rejected by the duplicate-identity or
        # duplicate-key checks above) leaves the count at zero and fails loud
        # rather than silently reading one.
        if repo_path == OWNER:
            owner_occurrences += 1
        sources[repo_path] = path.read_text(encoding="utf-8")
    if owner_occurrences != 1:
        errors.append(
            "owner source must occur exactly once: "
            f"{render_source_identity(OWNER)} (found {owner_occurrences})")
    return sources, errors


INVENTORY_ANCHORS = (ENGINE_OWNER, OWNER)


def compiled_production_tus(
        build_root: Path, root: Path) -> tuple[set[RepoPath], list[str]]:
    """Map compiled production translation units to canonical repo keys.

    Reads the authoritative compile_commands.json.  A missing/unreadable/
    non-JSON database returns an error so the caller fails CLOSED rather than
    silently reconciling against an empty set.  Only .c/.cc units resolving
    under root/wyrelog are kept (auto-excluding subprojects, tests, and
    builddir-generated sources).  Both sides are mapped through a RESOLVED root
    so scanned and compiled keys are comparable.
    """
    errors: list[str] = []
    database = build_root / "compile_commands.json"
    try:
        entries = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return set(), [f"unreadable compile database ({database}): {error}"]
    if not isinstance(entries, list):
        return set(), [f"malformed compile database (not a list): {database}"]
    resolved_root = root.resolve()
    production = (resolved_root / "wyrelog").resolve()
    compiled: set[RepoPath] = set()
    for entry in entries:
        try:
            real = (Path(entry["directory"]) / entry["file"]).resolve()
        except (KeyError, TypeError):
            errors.append("malformed compile database entry")
            continue
        if not real.is_relative_to(production):
            continue
        if real.suffix not in {".c", ".cc"}:
            continue
        raw_path, discovery_error = discovered_source_path(real, resolved_root)
        if discovery_error is not None:
            errors.append(
                "invalid compiled source path "
                f"({discovery_error}): {str(real)!r}")
            continue
        assert raw_path is not None
        repo_path, canonical_error = canonical_repo_path(raw_path)
        if canonical_error is not None:
            errors.append(
                "invalid compiled source path "
                f"({canonical_error}): {raw_path!r}")
            continue
        assert repo_path is not None
        compiled.add(repo_path)
    return compiled, errors


def inventory_anchor_errors(compiled: set[RepoPath]) -> list[str]:
    """Fail CLOSED when the compile inventory lacks an always-compiled anchor.

    wyl-engine.c and wyl-handle.c are the only unconditionally compiled
    production units; their absence means the database is empty or unusable,
    not that the tree lacks them.
    """
    errors: list[str] = []
    for anchor in INVENTORY_ANCHORS:
        if anchor not in compiled:
            errors.append(
                "compile inventory unusable (missing anchor "
                f"{anchor.spelling} or empty)")
    return errors


def reconcile(scanned_keys: set[RepoPath],
              compiled: set[RepoPath]) -> list[str]:
    """Fail CLOSED on any compiled production TU absent from the scan.

    Scanned-but-not-compiled is ALLOWED (conditional sources) and not flagged.
    """
    errors: list[str] = []
    for tu in sorted(compiled - scanned_keys, key=lambda key: key.spelling):
        errors.append(
            "compiled production TU not scanned: "
            f"{render_source_identity(tu)}")
    return errors


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

    direct_bypass = RepoPath("wyrelog/auth/direct-bypass.c")
    if check({direct_bypass: (
            "void bad(void *s) { wirelog_easy_insert(s, \"r\", 0, 0); }"
            )}) != [
            "direct Wirelog input mutation outside engine owner: "
            "\"wyrelog/auth/direct-bypass.c\""]:
        print("self-test accepted direct Wirelog input mutation",
              file=sys.stderr)
        return 1

    if check({ENGINE_OWNER: (
            "static void bad(void *s) { "
            "wirelog_easy_remove(s, \"r\", 0, 0); }"
            )}) != [
            "direct Wirelog input mutation outside funnel: bad"]:
        print("self-test accepted direct Wirelog mutation outside funnel",
              file=sys.stderr)
        return 1

    canonical_funnels = (
        "static void wyl_engine_insert_unchecked(void *s) { "
        "wirelog_easy_insert(s, \"r\", 0, 0); } "
        "static void wyl_engine_remove_unchecked(void *s) { "
        "wirelog_easy_remove(s, \"r\", 0, 0); }"
    )
    if check({ENGINE_OWNER: canonical_funnels}):
        print("self-test rejected canonical Wirelog mutation funnels",
              file=sys.stderr)
        return 1

    typed_bypass = RepoPath("wyrelog/auth/typed-bypass.c")
    if check({typed_bypass: (
            "void bad(WylEngineSession *s) { "
            f"{TYPED_EXTERNAL_TRANSACTION_BEGIN}(s, 0, 0, 0, 0); }}"
            )}) != [
            "typed external transaction begin outside allowlist: "
            "\"wyrelog/auth/typed-bypass.c\""]:
        print("self-test accepted typed external begin bypass",
              file=sys.stderr)
        return 1

    raw_bypass = RepoPath("wyrelog/auth/raw-bypass.c")
    if check({raw_bypass: (
            "void bad(void) { "
            f"{RAW_EXTERNAL_TRANSACTION_BEGIN}(0, 0, 0, 0); }}"
            )}) != [
            "raw external transaction begin outside owner/store: "
            "\"wyrelog/auth/raw-bypass.c\""]:
        print("self-test accepted raw external begin bypass", file=sys.stderr)
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
            "owned engine primitive outside allowlist: \"wyrelog/bad.c\""]:
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
            r'owned engine primitive outside allowlist: "wyrelog/fact\\compound.c"']:
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
            r'handle-owned engine aggregate accessed outside owner: "wyrelog\\wyl-handle.c"']:
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
            "invalid source key (expected RepoPath key): "
            f"{render_source_identity(OWNER.spelling)}"]:
        print("self-test accepted untyped source-map identity", file=sys.stderr)
        return 1

    forged_errors = check({RepoPath("/wyrelog/wyl-handle.c"): ""})
    if forged_errors != [
            "invalid source key (absolute or anchored path): "
            "\"/wyrelog/wyl-handle.c\""]:
        print("self-test accepted forged RepoPath identity", file=sys.stderr)
        return 1

    case_variant = RepoPath("Wyrelog/wyl-handle.c")
    case_errors = check({case_variant: (
        "static void wyl_handle_init(WylHandle *h) { h->read_engine = 0; }"
    )})
    if case_errors != [
            "handle-owned engine aggregate accessed outside owner: "
            "\"Wyrelog/wyl-handle.c\""]:
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
        "void bad(WylHandle *h) { (void) h->engine_terminal_state; }",
        "void bad(WylHandle *h) { (void) (*h).engine_terminal_generation; }",
        "void bad(WylHandle *h) { (void) h[0].engine_terminal_serial; }",
        "void bad(WylEngine *e) { wyl_engine_owned_insert(e, 0, 0, 0); }",
        "void bad(WylHandle *h) { wyl_handle_lock_engine_session(h); }",
        "void bad(WylHandle *h) { g_rec_mutex_lock(&(*h).engine_session_mutex); }",
        "void bad(WylHandle *h) { g_rec_mutex_unlock(&h[0].engine_session_mutex); }",
        "void bad(WylHandle *h) { g_mutex_lock(&h->engine_terminal_mutex); }",
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
    typed_repair_owner = (
        "static void wyl_engine_session_repair_committed_publication"
        "(WylHandle *h) { (void) h->engine_pair_poisoned; }"
    )
    if check({OWNER: typed_repair_owner}):
        print("self-test rejected typed repair owner access", file=sys.stderr)
        return 1
    other_repair_owner = typed_repair_owner.replace(
        "wyl_engine_session_repair_committed_publication",
        "wyl_engine_session_repair_other_publication")
    if check({OWNER: other_repair_owner}) != [
            "owner aggregate access outside function allowlist: "
            "wyl_engine_session_repair_other_publication"]:
        print("self-test accepted aggregate access in another repair helper",
              file=sys.stderr)
        return 1

    exact_terminal_owners = (
        "static int engine_terminal_token_matches_locked(WylHandle *h) { "
        "return h->engine_terminal_serial != 0; } "
        "static void engine_terminal_abandon_recovery(WylHandle *h) { "
        "g_mutex_lock(&h->engine_terminal_mutex); "
        "h->engine_terminal_state = 0; "
        "g_mutex_unlock(&h->engine_terminal_mutex); } "
        "static void engine_terminal_finish_pending(WylHandle *h) { "
        "g_mutex_lock(&h->engine_terminal_mutex); "
        "h->engine_terminal_generation = 0; "
        "g_mutex_unlock(&h->engine_terminal_mutex); } "
        "static int wyl_handle_engine_terminal_get_state(WylHandle *h) { "
        "g_mutex_lock(&h->engine_terminal_mutex); "
        "int state = h->engine_terminal_state; "
        "g_mutex_unlock(&h->engine_terminal_mutex); return state; }"
    )
    if check({OWNER: exact_terminal_owners}):
        print("self-test rejected exact terminal capability owners",
              file=sys.stderr)
        return 1
    renamed_terminal_owner = exact_terminal_owners.replace(
        "engine_terminal_abandon_recovery",
        "engine_terminal_abandon_recovery_renamed", 1)
    renamed_errors = check({OWNER: renamed_terminal_owner})
    renamed_required = (
        "owner aggregate access outside function allowlist: "
        "engine_terminal_abandon_recovery_renamed")
    if not renamed_errors or renamed_required not in renamed_errors:
        print("self-test accepted renamed terminal capability owner",
              file=sys.stderr)
        return 1
    unlocked_terminal_owner = (
        "static int wyl_handle_engine_terminal_get_state(WylHandle *h) { "
        "return h->engine_terminal_state; }")
    unlocked_errors = check({OWNER: unlocked_terminal_owner})
    unlocked_required = (
        "terminal field access without owned mutex interval: "
        "wyl_handle_engine_terminal_get_state")
    if not unlocked_errors or unlocked_required not in unlocked_errors:
        print("self-test accepted terminal field access without mutex",
              file=sys.stderr)
        return 1
    unauthorized_terminal_owner = (
        "static void unrelated_terminal_writer(WylHandle *h) { "
        "g_mutex_lock(&h->engine_terminal_mutex); "
        "h->engine_terminal_state = 0; "
        "g_mutex_unlock(&h->engine_terminal_mutex); }")
    unauthorized_errors = check({OWNER: unauthorized_terminal_owner})
    unauthorized_required = (
        "owner aggregate access outside function allowlist: "
        "unrelated_terminal_writer")
    if (not unauthorized_errors
            or unauthorized_required not in unauthorized_errors):
        print("self-test accepted terminal calls in unauthorized owner",
              file=sys.stderr)
        return 1

    locked_calls = " ".join(
        f"rc |= {name}(h);" for name in LOCKED_REPLACEMENT_LOADERS)
    valid_replacement_chain = (
        "static int load_current_engine_pair(void *session, int capability) { "
        f"void *h = session; int rc = capability; {locked_calls} return rc; }} "
        "static int replace_engine_pair(void *session) { "
        "void *new_read_engine = session; "
        "return load_current_engine_pair(session, "
        "wyl_engine_session_state_capability(new_read_engine)); }")
    if check({OWNER: valid_replacement_chain}):
        print("self-test rejected locked replacement load chain",
              file=sys.stderr)
        return 1
    public_loader_chain = valid_replacement_chain.replace(
        LOCKED_REPLACEMENT_LOADERS[0], PUBLIC_REPLACEMENT_LOADERS[0], 1)
    public_loader_errors = check({OWNER: public_loader_chain})
    if ("replacement load chain calls public loader: "
            f"{PUBLIC_REPLACEMENT_LOADERS[0]}" not in public_loader_errors
            or "replacement load chain missing locked core: "
            f"{LOCKED_REPLACEMENT_LOADERS[0]}" not in public_loader_errors):
        print("self-test accepted public loader in replacement chain",
              file=sys.stderr)
        return 1
    stale_capability_chain = valid_replacement_chain.replace(
        "new_read_engine));", "old_read_engine));")
    stale_capability_errors = check({OWNER: stale_capability_chain})
    if (not stale_capability_errors
            or "replacement must pass candidate session capability"
            not in stale_capability_errors):
        print("self-test accepted non-candidate replacement capability",
              file=sys.stderr)
        return 1

    locked_core_mutants = (
        "wyl_engine_session_acquire(h);",
        "wyl_service_auth_rank_enter(h, 1);",
        "h->engine_terminal_state = 0;",
    )
    for mutation in locked_core_mutants:
        locked_core = (
            f"static void {LOCKED_REPLACEMENT_LOADERS[0]}"
            f"(WylHandle *h) {{ {mutation} }}")
        required_error = (
            "locked replacement loader crosses session boundary: "
            f"{LOCKED_REPLACEMENT_LOADERS[0]}")
        if required_error not in check({OWNER: locked_core}):
            print(f"self-test accepted locked-core mutation: {mutation}",
                  file=sys.stderr)
            return 1
    public_audit_callback = (
        "static void insert_policy_store_audit_fact(WylHandle *h) { "
        "wyl_handle_insert_audit_fact(h, 0, 0, 0, 0, 0, 0, 0, 0, 0); }")
    public_audit_errors = check({OWNER: public_audit_callback})
    if (not public_audit_errors
            or "audit replay callback must use locked insertion"
            not in public_audit_errors):
        print("self-test accepted public insertion in audit callback",
              file=sys.stderr)
        return 1
    literal = 'const char *s = "wyl_handle_get_read_engine(h)"; /* h->read_engine */'
    if check({OWNER: "", RepoPath("wyrelog/literal.c"): literal}):
        print("self-test rejected comments/literals", file=sys.stderr)
        return 1

    # (A) Direct renderer unit checks: these cover the collect_sources()
    # discovery/canonical diagnostic sites that check()-driven tests never
    # reach, plus flavor disambiguation of same-byte spellings.
    if render_source_identity("wyrelog/plain.c") != "\"wyrelog/plain.c\"":
        print("self-test mis-rendered a plain identity", file=sys.stderr)
        return 1
    same_bytes = "wyrelog/fact\\compound.c"
    posix_render = render_source_identity(
        RawSourcePath(same_bytes, PathFlavor.POSIX))
    windows_render = render_source_identity(
        RawSourcePath(same_bytes, PathFlavor.WINDOWS))
    if not posix_render.endswith(" [posix]"):
        print("self-test dropped the posix flavor tag", file=sys.stderr)
        return 1
    if not windows_render.endswith(" [windows]"):
        print("self-test dropped the windows flavor tag", file=sys.stderr)
        return 1
    posix_body = posix_render[:-len(" [posix]")]
    windows_body = windows_render[:-len(" [windows]")]
    if posix_body != windows_body or "\\\\" not in posix_body:
        print("self-test failed same-byte flavor disambiguation",
              file=sys.stderr)
        return 1
    pure_render = render_source_identity(PurePosixPath("wyrelog/x.c"))
    if (not pure_render.endswith(" [posix]") or not pure_render.isascii()
            or "\n" in pure_render or "\r" in pure_render):
        print("self-test failed PurePath identity rendering", file=sys.stderr)
        return 1

    def decode_identity(entry: str) -> str:
        body = entry
        for tag in (" [posix]", " [windows]", " [unknown-flavor]"):
            if body.endswith(tag):
                body = body[:-len(tag)]
                break
        quoted = body[body.index("\""):]
        if not (quoted.startswith("\"") and quoted.endswith("\"")):
            raise ValueError("identity is not double-quoted")
        inner = quoted[1:-1]
        out = []
        index = 0
        while index < len(inner):
            char = inner[index]
            if char != "\\":
                out.append(char)
                index += 1
                continue
            marker = inner[index + 1]
            if marker == "\\":
                out.append("\\")
                index += 2
            elif marker == "\"":
                out.append("\"")
                index += 2
            elif marker == "n":
                out.append("\n")
                index += 2
            elif marker == "r":
                out.append("\r")
                index += 2
            elif marker == "t":
                out.append("\t")
                index += 2
            elif marker == "x":
                out.append(chr(int(inner[index + 2:index + 4], 16)))
                index += 4
            elif marker == "u":
                out.append(chr(int(inner[index + 2:index + 6], 16)))
                index += 6
            elif marker == "U":
                out.append(chr(int(inner[index + 2:index + 10], 16)))
                index += 10
            else:
                raise ValueError("unknown escape marker")
        return "".join(out)

    # (B) Hostile spellings through check().  Each forged key is a canonical
    # posix spelling that is not the owner, so the aggregate-access body below
    # yields exactly one diagnostic routed through render_source_identity.
    aggregate_body = "static void f(WylHandle *h){ h->read_engine = 0; }"
    hostile_spellings = (
        "wyrelog/a\nb.c",
        "wyrelog/a\rb.c",
        "wyrelog/a\tb.c",
        "wyrelog/a\x1bb.c",
        "wyrelog/a\\b.c",
        "wyrelog/a'b.c",
        "wyrelog/a\"b.c",
        "wyrelog/a‮b.c",
        "wyrelog/а.c",
    )
    for spelling in hostile_spellings:
        hostile_errors = check({RepoPath(spelling): aggregate_body})
        if (len(hostile_errors) != 1 or "\n" in hostile_errors[0]
                or "\r" in hostile_errors[0]):
            print("self-test emitted an unsafe hostile diagnostic",
                  file=sys.stderr)
            return 1
        if not hostile_errors[0].isascii():
            print("self-test emitted a non-ASCII hostile diagnostic",
                  file=sys.stderr)
            return 1
        if decode_identity(hostile_errors[0]) != spelling:
            print("self-test lost the hostile spelling round-trip",
                  file=sys.stderr)
            return 1

    # Distinct look-alike spellings must not merge under dedup.
    newline_errors = check({RepoPath("wyrelog/a\nb.c"): aggregate_body})
    literal_bsn_errors = check({RepoPath("wyrelog/a\\nb.c"): aggregate_body})
    if newline_errors[0] == literal_bsn_errors[0]:
        print("self-test merged newline and literal backslash-n spellings",
              file=sys.stderr)
        return 1

    # A newline in a spelling must not fabricate an extra bullet: main() joins
    # entries with newline-plus-indent, so an unescaped newline would forge one.
    fabricated_errors = check(
        {RepoPath("wyrelog/x.c\n  fabricated violation: y"): aggregate_body})
    if len(fabricated_errors) != 1 or "\\n" not in fabricated_errors[0]:
        print("self-test allowed a fabricated violation bullet",
              file=sys.stderr)
        return 1

    # A hostile sibling must not suppress a genuine violation on a benign key.
    benign_violation = (
        "handle-owned engine aggregate accessed outside owner: "
        "\"wyrelog/benign.c\"")
    suppression_errors = check({
        RepoPath("wyrelog/a\nb.c"): aggregate_body,
        RepoPath("wyrelog/benign.c"): aggregate_body,
    })
    if (benign_violation not in suppression_errors
            or len(suppression_errors) != 2
            or len(set(suppression_errors)) != 2):
        print("self-test let a hostile sibling suppress a violation",
              file=sys.stderr)
        return 1

    # A bare str key and a forged RepoPath must stay distinguishable.
    str_key_errors = check({OWNER.spelling: ""})
    anchored_errors = check({RepoPath("/wyrelog/wyl-handle.c"): ""})
    if str_key_errors != [
            "invalid source key (expected RepoPath key): "
            "\"wyrelog/wyl-handle.c\""]:
        print("self-test mis-rendered a bare str key", file=sys.stderr)
        return 1
    if anchored_errors != [
            "invalid source key (absolute or anchored path): "
            "\"/wyrelog/wyl-handle.c\""]:
        print("self-test mis-rendered a forged RepoPath key", file=sys.stderr)
        return 1
    if str_key_errors[0] == anchored_errors[0]:
        print("self-test collapsed str-key and forged-RepoPath diagnostics",
              file=sys.stderr)
        return 1

    if self_test_identity_and_inventory() or self_test_alias_integration():
        return 1
    return 0


def self_test_identity_and_inventory() -> int:
    """Mocked identity/reconciliation checks driven by synthetic stat data."""
    regular = stat.S_IFREG | 0o644
    if (link_component_rejection(regular, 0) is not None
            or nonregular_leaf_rejection(regular) is not None):
        print("self-test rejected a regular file", file=sys.stderr)
        return 1
    if link_component_rejection(stat.S_IFLNK | 0o777, 0) is None:
        print("self-test accepted a symlink component", file=sys.stderr)
        return 1
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if link_component_rejection(regular, reparse) is None:
        print("self-test accepted a reparse-point component", file=sys.stderr)
        return 1
    for nonregular in (stat.S_IFIFO | 0o644, stat.S_IFCHR | 0o644,
                       stat.S_IFSOCK | 0o644, stat.S_IFDIR | 0o755):
        if nonregular_leaf_rejection(nonregular) is None:
            print(f"self-test accepted non-regular leaf mode: {nonregular}",
                  file=sys.stderr)
            return 1

    identities: dict[tuple[int, int], RepoPath] = {}
    first = RepoPath("wyrelog/one.c")
    second = RepoPath("wyrelog/two.c")
    if duplicate_identity_rejection(first, (7, 11), identities) is not None:
        print("self-test rejected a fresh physical identity", file=sys.stderr)
        return 1
    alias = duplicate_identity_rejection(second, (7, 11), identities)
    if alias != ("duplicate physical identity: wyrelog/two.c "
                 "aliases wyrelog/one.c"):
        print("self-test missed a duplicate physical identity",
              file=sys.stderr)
        return 1

    scanned = {RepoPath("wyrelog/wyl-engine.c"), RepoPath("wyrelog/wyl-handle.c")}
    compiled = scanned | {RepoPath("wyrelog/fact/compound.c")}
    if reconcile(scanned, compiled) != [
            "compiled production TU not scanned: \"wyrelog/fact/compound.c\""]:
        print("self-test missed a compiled-but-unscanned TU", file=sys.stderr)
        return 1
    if reconcile(compiled, scanned):
        print("self-test flagged an allowed scanned-but-uncompiled TU",
              file=sys.stderr)
        return 1

    if inventory_anchor_errors(set()) != [
            "compile inventory unusable (missing anchor "
            "wyrelog/wyl-engine.c or empty)",
            "compile inventory unusable (missing anchor "
            "wyrelog/wyl-handle.c or empty)"]:
        print("self-test accepted an empty compile inventory", file=sys.stderr)
        return 1
    if inventory_anchor_errors({ENGINE_OWNER}) != [
            "compile inventory unusable (missing anchor "
            "wyrelog/wyl-handle.c or empty)"]:
        print("self-test accepted an inventory missing the handle anchor",
              file=sys.stderr)
        return 1
    if inventory_anchor_errors({ENGINE_OWNER, OWNER}):
        print("self-test rejected a complete compile inventory",
              file=sys.stderr)
        return 1
    return 0


def self_test_alias_integration() -> int:
    """Exercise the real discovery hardening against a live filesystem tree."""
    if os.name == "posix" and hasattr(os, "symlink"):
        return self_test_posix_alias_integration()
    if os.name == "nt":
        return self_test_windows_junction_integration()
    return 0


def _seed_owner_tree(root: Path) -> None:
    production = root / "wyrelog"
    production.mkdir(parents=True, exist_ok=True)
    (production / "wyl-handle.c").write_text(
        "static void wyl_handle_init(WylHandle *h) { h->read_engine = 0; }\n",
        encoding="utf-8")


def self_test_posix_alias_integration() -> int:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        _seed_owner_tree(root)
        production = root / "wyrelog"
        (production / "target.c").write_text(
            "static void inner(void) {}\n", encoding="utf-8")
        try:
            os.symlink(production / "target.c", production / "alias.c")
        except OSError as error:
            print(f"self-test could not create a symlink: {error}",
                  file=sys.stderr)
            return 1
        _sources, errors = collect_sources(root)
        alias_errors = [e for e in errors
                        if "symlinked or reparse-point path component" in e
                        and "alias.c" in e]
        if len(alias_errors) != 1:
            print(f"self-test did not reject a leaf symlink: {errors}",
                  file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as name:
        root = Path(name)
        _seed_owner_tree(root)
        production = root / "wyrelog"
        (production / "one.c").write_text(
            "static void inner(void) {}\n", encoding="utf-8")
        try:
            os.link(production / "one.c", production / "two.c")
        except OSError as error:
            print(f"self-test could not create a hardlink: {error}",
                  file=sys.stderr)
            return 1
        _sources, errors = collect_sources(root)
        dup_errors = [e for e in errors
                      if "duplicate physical identity" in e
                      and "one.c" in e and "two.c" in e]
        if len(dup_errors) != 1:
            print(f"self-test did not reject hardlink aliases: {errors}",
                  file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as name, \
            tempfile.TemporaryDirectory() as outside_name:
        root = Path(name)
        _seed_owner_tree(root)
        production = root / "wyrelog"
        outside = Path(outside_name) / "external.c"
        outside.write_text("static void outer(void) {}\n", encoding="utf-8")
        try:
            os.symlink(outside, production / "external.c")
        except OSError as error:
            print(f"self-test could not create an external symlink: {error}",
                  file=sys.stderr)
            return 1
        _sources, errors = collect_sources(root)
        external_errors = [e for e in errors if "external.c" in e]
        if not external_errors or not all(
                "symlinked or reparse-point path component" in e
                for e in external_errors):
            print(f"self-test did not reject an external symlink: {errors}",
                  file=sys.stderr)
            return 1
    return 0


def self_test_windows_junction_integration() -> int:
    import subprocess
    with tempfile.TemporaryDirectory() as outside_name, \
            tempfile.TemporaryDirectory() as name:
        root = Path(name)
        _seed_owner_tree(root)
        production = root / "wyrelog"
        real_dir = Path(outside_name) / "real"
        real_dir.mkdir()
        (real_dir / "inner.c").write_text(
            "static void inner(void) {}\n", encoding="utf-8")
        junction = production / "linked"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            # Creating the reparse point must not silently count as proof.
            print("self-test could not create a junction: "
                  + result.stderr.decode(errors="replace"), file=sys.stderr)
            return 1
        _sources, errors = collect_sources(root)
        # rglob does not descend a reparse-point directory, so the junction's
        # contents must never be admitted as clean scanned sources; if the
        # leaf is walked at all, (a) must reject it.  Either outcome is safe;
        # silently admitting the junction target is not.
        if RepoPath("wyrelog/linked/inner.c") in _sources:
            print(f"self-test admitted a junction target: {errors}",
                  file=sys.stderr)
            return 1
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    parser = argparse.ArgumentParser(
        description="Check the handle-owned engine-session boundary.")
    parser.add_argument("root", type=Path)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline self-test and exit")
    args = parser.parse_args()
    root = args.root.resolve()
    sources, errors = collect_sources(root)
    errors.extend(check(sources))
    if args.build_root is not None:
        build_root = args.build_root.resolve()
        compiled, compile_errors = compiled_production_tus(build_root, root)
        errors.extend(compile_errors)
        errors.extend(inventory_anchor_errors(compiled))
        errors.extend(reconcile(set(sources.keys()), compiled))
    else:
        print("engine-session-boundary: reconciliation skipped "
              "(no --build-root)", file=sys.stderr)
    errors = sorted(set(errors))
    if errors:
        print("engine-session boundary violations:", *errors, sep="\n  ",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
