#!/usr/bin/env python3
"""Freeze the private service-session source and binary boundary.

Every tracked textual file participates in the exact-reference manifest.
Macro synthesis is additionally checked for each compiled C translation unit
from compile_commands.json (or every fixture C file), recursively inlining
local headers with that TU's ordered compiler include roots. Conditional source
files absent from the current binary configuration remain raw-manifest-only.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import secrets
import subprocess
import stat as stat_module
import sys
import tempfile
import threading
import time
from typing import NamedTuple

PROTECTED = (
    "wyl_session_new_service_detached",
    "wyl_session_get_auth_method_private",
    "wyl_session_is_active_private",
    "wyl_session_copy_persistent_id_private",
    "wyl_session_dup_service_jti_private",
    "wyl_session_dup_service_subject_private",
    "wyl_session_dup_service_tenant_private",
    "wyl_session_dup_service_credential_id_private",
    "wyl_session_get_service_credential_generation_private",
    "wyl_session_get_service_issued_at_seconds_private",
    "wyl_session_get_service_expires_at_seconds_private",
    "wyl_jwt_sign_hs256_service",
)

# #358 may add references only at this exact orchestrator owner. Its counts
# must be added to MANIFEST in the same change; every other path remains fatal.
FUTURE_OWNER = "wyrelog/daemon/service-token-exchange.c"

SELF_EXCLUDED = {
    "tools/check-service-session-private-boundary.py",
    "tools/check-service-session-private-exports.py",
    "tests/test-service-session-private-boundary.py",
}

MANIFEST = {
    symbol: {
        "wyrelog/wyl-session-private.h": 1,
        "wyrelog/auth/service-session-private.c": 1,
        "tests/test-service-session-metadata.c": (
            5 if symbol == "wyl_session_new_service_detached" else 1),
    }
    for symbol in PROTECTED
}
MANIFEST["wyl_jwt_sign_hs256_service"] = {
    "wyrelog/auth/jwt-private.h": 1,
    "wyrelog/auth/service-jwt-private.c": 1,
    "tests/test-jwt.c": 5,
    "tests/test-daemon-http-decide.c": 3,
}
for symbol in PROTECTED:
    if symbol not in {"wyl_session_new_service_detached",
                      "wyl_jwt_sign_hs256_service"}:
        MANIFEST[symbol]["wyrelog/daemon/http.c"] = (
            2 if symbol in {"wyl_session_get_auth_method_private",
                            "wyl_session_is_active_private"} else 1)
MANIFEST["wyl_session_new_service_detached"][
    "tests/test-daemon-http-decide.c"] = 2


class BoundaryError(RuntimeError):
    pass


def decode_escapes(text: str) -> str:
    text = re.sub(r"\\\r?\n", "", text)
    text = re.sub(r"\\x([0-9a-fA-F]{2})",
                  lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\([0-7]{1,3})",
                  lambda m: chr(int(m.group(1), 8)), text)
    text = re.sub(r"\\u([0-9a-fA-F]{4})",
                  lambda m: chr(int(m.group(1), 16)), text)
    return text


def source_files(root: Path):
    if (root / ".git").exists():
        result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                check=False, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise BoundaryError("git ls-files failed: "
                                + result.stderr.decode(errors="replace"))
        paths = (root / name.decode(errors="surrogateescape")
                 for name in result.stdout.split(b"\0") if name)
    else:
        paths = root.rglob("*")
    for path in paths:
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in SELF_EXCLUDED:
            continue
        try:
            yield rel, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue


def logical_source(text: str) -> str:
    return re.sub(r"\\\r?\n", "", text)


def valid_macro_directive(line: str) -> tuple[str, str] | None:
    # Validate only the macro name. Parameter lists and replacement tokens are
    # compiler dialect, including GNU named variadics (`args...`), and must be
    # passed unchanged to the authoritative preprocessor. Invalid template
    # placeholders such as `@PREFIX@` fail this lexical name boundary.
    match = re.match(
        r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(?=\s|\(|$)", line)
    if match is None:
        return None
    return match.group(1), line


def include_roots(arguments: list[str], directory: Path):
    quote_only = []
    common = []
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        value = None
        quote = argument == "-iquote"
        if argument in {"-I", "-isystem", "-iquote", "/I", "/external:I"}:
            index += 1
            if index < len(arguments):
                value = arguments[index]
        elif argument.startswith("-I") and len(argument) > 2:
            value = argument[2:]
        elif argument.startswith("-isystem") and len(argument) > 8:
            value = argument[8:]
        elif argument.startswith("-iquote") and len(argument) > 7:
            value = argument[7:]
            quote = True
        elif argument.lower().startswith("/external:i"):
            value = argument[len("/external:I"):]
        elif argument.lower().startswith("/i") and len(argument) > 2:
            value = argument[2:]
        if value:
            path = Path(value)
            resolved = ((directory / path).resolve() if not path.is_absolute()
                        else path.resolve())
            (quote_only if quote else common).append(resolved)
        index += 1
    common = list(dict.fromkeys(common))
    return list(dict.fromkeys(quote_only + common)), common


def windows_command_line_split(command: str) -> list[str]:
    arguments = []
    index = 0
    while index < len(command):
        while index < len(command) and command[index].isspace():
            index += 1
        if index == len(command):
            break
        value = []
        quoted = False
        while index < len(command) and (quoted or not command[index].isspace()):
            if command[index] == '"':
                quoted = not quoted
                index += 1
                continue
            if command[index] == "\\":
                start = index
                while index < len(command) and command[index] == "\\":
                    index += 1
                count = index - start
                if index < len(command) and command[index] == '"':
                    value.extend("\\" * (count // 2))
                    if count % 2:
                        value.append('"')
                        index += 1
                    else:
                        quoted = not quoted
                        index += 1
                else:
                    value.extend("\\" * count)
                continue
            value.append(command[index])
            index += 1
        if quoted:
            raise BoundaryError("unterminated quote in Windows compiler command")
        arguments.append("".join(value))
    return arguments


def expand_response_files(arguments: list[str], directory: Path,
                          windows: bool = False) -> list[str]:
    expanded = []
    for argument in arguments:
        if not argument.startswith("@"):
            expanded.append(argument)
            continue
        path = Path(argument[1:])
        path = path if path.is_absolute() else directory / path
        try:
            content = path.read_text(encoding="utf-8")
            nested = (windows_command_line_split(content) if windows
                      else shlex.split(content))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise BoundaryError(f"cannot expand compiler response file: {path}") from error
        # GCC, Clang, and MSVC resolve nested response paths relative to the
        # compiler invocation working directory, not the containing response.
        expanded.extend(expand_response_files(nested, directory, windows))
    return expanded


def semantic_arguments(arguments: list[str], directory: Path,
                       source: Path, windows: bool = False) -> list[str]:
    arguments = expand_response_files(arguments, directory, windows)
    result = []
    paired = {"-o", "-MF", "-MT", "-MQ", "-MJ", "-Xlinker"}
    standalone = {"-c", "/c", "-MD", "-MMD", "-MP", "/showIncludes"}
    index = 1
    while index < len(arguments):
        argument = arguments[index]
        path_option = None
        if argument in {"-I", "-isystem", "-iquote", "-include", "/I", "/FI",
                        "/external:I", "--sysroot"}:
            if index + 1 >= len(arguments):
                raise BoundaryError(f"compiler option lacks value: {argument}")
            value = Path(arguments[index + 1])
            value = value if value.is_absolute() else (directory / value).resolve()
            result.extend([argument, str(value)])
            index += 2
            continue
        for prefix in ("-isystem", "-iquote", "-include", "--sysroot=", "-I",
                       "/external:I", "/FI", "/I"):
            if argument.lower().startswith(prefix.lower()) and len(argument) > len(prefix):
                value = Path(argument[len(prefix):])
                value = value if value.is_absolute() else (directory / value).resolve()
                path_option = prefix + str(value)
                break
        if path_option is not None:
            result.append(path_option)
            index += 1
            continue
        candidate = Path(argument)
        candidate = ((directory / candidate).resolve()
                     if not candidate.is_absolute() else candidate.resolve())
        if candidate == source:
            index += 1
            continue
        if argument in paired:
            index += 2
            continue
        if argument in standalone:
            index += 1
            continue
        if (re.match(r"^-(?:o|MF|MT|MQ|MJ).+", argument)
                or re.match(r"^/(?:Fo|Fd|Fe).+", argument, re.IGNORECASE)):
            index += 1
            continue
        result.append(argument)
        index += 1
    return result


def compile_database_contexts(build_root: Path | None, compiler_id: str,
                              source_root: Path | None = None):
    database = {}
    path = build_root / "compile_commands.json" if build_root else None
    if path is None or not path.is_file():
        return database
    for entry in json.loads(path.read_text(encoding="utf-8")):
        directory = Path(entry["directory"]).resolve()
        windows = compiler_id in {"msvc", "clang-cl"}
        arguments = entry.get("arguments") or (
            windows_command_line_split(entry["command"]) if windows
            else shlex.split(entry["command"]))
        source = Path(entry["file"])
        source = (directory / source).resolve() if not source.is_absolute() else source.resolve()
        semantics = semantic_arguments(arguments, directory, source, windows)
        quote_roots, angle_roots = include_roots(
            [arguments[0], *semantics], directory)
        context = (quote_roots, angle_roots, semantics)
        variants = database.setdefault(str(source), [])
        if context not in variants:
            variants.append(context)
    return database


class CandidateObservation(NamedTuple):
    anchor_identity: str
    lexical_identity: str
    canonical_identity: str | None
    state: str
    stat_identity: tuple[int, int, int, int, int] | None = None
    error_prefix: str | None = None
    error_path: str | None = None


class Expansion(NamedTuple):
    parts: tuple[object, ...]
    footprint: frozenset[str]
    observed_backedge: bool
    literal_bytes: int


REPORT_PHASES = frozenset(("startup", "discovery", "raw", "distill",
                           "validate1", "compiler", "validate2", "owners"))
REPORT_OPS = frozenset(("idle", "read", "resolve", "lstat", "stat",
                        "expand", "flatten", "preprocess", "check"))


class NullReporter:
    snapshot = (0, "startup", "idle") + (0,) * 19
    expansion_calls = 0

    def start(self) -> None:
        pass

    def update(self, _phase: str, _op: str, **_values) -> None:
        pass

    def note_expansion(self, **_values) -> None:
        pass

    def stop(self) -> None:
        pass


class HeartbeatReporter:
    """Failure-isolated progress reporter containing enums and integers only."""

    FIELDS = {name: index for index, name in enumerate((
        "file", "files", "tu", "tus", "context", "contexts", "root",
        "roots", "resolutions", "resolution_hits", "candidate_checks",
        "candidate_hits", "text_reads", "expansion_calls", "expansion_hits",
        "tasks", "nodes", "retained", "validations"), 3)}

    def __init__(self, interval: float = 30.0, emitter=None,
                 join_timeout: float = 1.0, waiter=None,
                 thread_factory=threading.Thread):
        self.interval = interval
        self.emitter = emitter or self._emit
        self.join_timeout = join_timeout
        self.stop_event = threading.Event()
        self.waiter = waiter or self.stop_event.wait
        self.thread_factory = thread_factory
        self.thread = None
        self.disabled = False
        self.snapshot = (0, "startup", "idle") + (0,) * 19
        self.expansion_calls = 0

    @staticmethod
    def _emit(report: tuple) -> None:
        print("boundary progress: " + " ".join(map(str, report)),
              file=sys.stderr, flush=True)

    def start(self) -> None:
        try:
            self.thread = self.thread_factory(target=self._run, daemon=True)
            self.thread.start()
        except Exception:
            self.disabled = True

    def note_expansion(self, **values) -> None:
        self.expansion_calls += 1
        if self.expansion_calls % 256 == 0:
            self.update("distill", "expand",
                        expansion_calls=self.expansion_calls, **values)

    def _run(self) -> None:
        previous_sequence = -1
        unchanged = 0
        while True:
            try:
                if self.waiter(self.interval):
                    return
                snapshot = self.snapshot
                if snapshot[0] == previous_sequence:
                    unchanged += 1
                else:
                    unchanged = 0
                    previous_sequence = snapshot[0]
                self.emitter(snapshot + (unchanged,
                                          int(unchanged * self.interval)))
            except Exception:
                self.disabled = True
                return

    def stop(self) -> None:
        try:
            self.stop_event.set()
        except Exception:
            self.disabled = True
        try:
            if self.thread is not None:
                self.thread.join(self.join_timeout)
        except Exception:
            self.disabled = True

    def update(self, phase: str, op: str, **values) -> None:
        if self.disabled:
            return
        try:
            if phase not in REPORT_PHASES or op not in REPORT_OPS:
                self.disabled = True
                return
            state = list(self.snapshot)
            state[0] += 1
            state[1] = phase
            state[2] = op
            for name, value in values.items():
                index = self.FIELDS[name]
                state[index] = int(value)
            self.snapshot = tuple(state)
        except Exception:
            self.disabled = True


class ReporterGuard:
    """Prevents injected reporter doubles from changing the guard verdict."""

    def __init__(self, reporter):
        self.reporter = reporter

    @property
    def expansion_calls(self) -> int:
        try:
            return int(self.reporter.expansion_calls)
        except Exception:
            return 0

    def start(self) -> None:
        try:
            self.reporter.start()
        except Exception:
            pass

    def update(self, phase: str, op: str, **values) -> None:
        try:
            self.reporter.update(phase, op, **values)
        except Exception:
            pass

    def note_expansion(self, **values) -> None:
        try:
            self.reporter.note_expansion(**values)
        except Exception:
            pass

    def stop(self) -> None:
        try:
            self.reporter.stop()
        except Exception:
            pass


def make_reporter(factory) -> ReporterGuard:
    try:
        return ReporterGuard(factory())
    except Exception:
        return ReporterGuard(NullReporter())


def flatten_expansion(expansion: Expansion) -> str:
    output = []
    pending = list(reversed(expansion.parts))
    while pending:
        part = pending.pop()
        if isinstance(part, Expansion):
            pending.extend(reversed(part.parts))
        else:
            output.append(part)
    return "".join(output)


def dependency_prefix(path: Path, bases: tuple[Path, ...]) -> Path | None:
    """Return the vendored dependency tree containing @path, if any.

    A dependency installed inside the checkout is still a dependency.  Its
    headers sit under the project root and would otherwise be distilled as
    project source, and glib and libsoup alone exhaust the expansion budget;
    installed outside the tree, the same headers are left to the real
    preprocessor.  Honour the vcpkg sentinel rather than a directory name so
    the layout, not the platform, decides.

    CI installs its dependencies outside the checkout, so this guards the
    developer who vendors one in-tree rather than any configured runner.

    Only vendored trees strictly inside a local base qualify.  The search stops
    at the base so a sentinel at or above the checkout cannot classify the
    project itself as a dependency and silently disable distillation.  This
    recognises a classic vcpkg clone; a manifest-mode `vcpkg_installed/`
    carries no sentinel and is not detected here.
    """
    for parent in path.parents:
        if parent in bases:
            break
        if (parent / ".vcpkg-root").exists():
            return parent
    return None


class IncludeSnapshot:
    def __init__(self, local_bases: tuple[Path, ...],
                 expansion_cap: int = 64 * 1024 * 1024,
                 reporter=None):
        self.local_bases = local_bases
        self.dependency_prefixes = {}
        self.resolutions = {}
        self.resolution_errors = {}
        self.text = {}
        self.fingerprints = {}
        self.negative_paths = set()
        self.canonical_identities = {}
        self.candidates = {}
        self.logical_lines = {}
        self.expansions = {}
        self.expansion_cap = expansion_cap
        self.expansion_bytes = 0
        self.expansion_hits = 0
        self.expansion_bypasses = 0
        self.expansion_backedges = 0
        self.expansion_cap_rejections = 0
        self.reporter = reporter or NullReporter()
        self.root_ordinal = 0
        self.root_total = 0
        self.reads = 0
        self.resolution_hits = 0
        self.identity_resolves = 0
        self.candidate_checks = 0
        self.candidate_hits = 0

    def canonical_identity(self, path: Path) -> str:
        identity = self.canonical_identities.get(path)
        if identity is None:
            self.reporter.update("distill", "resolve",
                                 root=self.root_ordinal, roots=self.root_total)
            identity = str(path.resolve())
            self.canonical_identities[path] = identity
            self.identity_resolves += 1
        return identity

    def _reject_link_components(self, anchor: Path, candidate: Path,
                                owner: str) -> None:
        current = anchor
        for component in candidate.relative_to(anchor).parts:
            current /= component
            try:
                self.reporter.update(
                    "distill", "lstat", root=self.root_ordinal,
                    roots=self.root_total)
                info = current.lstat()
            except FileNotFoundError:
                return
            except OSError as error:
                raise BoundaryError(
                    f"cannot lstat local include component: {owner}: {current}") from error
            attributes = getattr(info, "st_file_attributes", 0)
            reparse = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if stat_module.S_ISLNK(info.st_mode) or attributes & reparse:
                raise BoundaryError(
                    f"symlink/reparse local include component: {owner}: {current}")

    @staticmethod
    def _stat_identity(info) -> tuple[int, int, int, int, int]:
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns)

    def _observe_candidate(self, anchor: Path, name: str,
                           owner: str) -> CandidateObservation:
        lexical = anchor / name
        anchor_identity = self.canonical_identity(anchor)
        try:
            self._reject_link_components(anchor, lexical, owner)
            self.reporter.update(
                "distill", "resolve", root=self.root_ordinal,
                roots=self.root_total)
            candidate = lexical.resolve(strict=False)
            try:
                self.reporter.update(
                    "distill", "stat", root=self.root_ordinal,
                    roots=self.root_total)
                info = candidate.stat()
            except FileNotFoundError:
                return CandidateObservation(
                    anchor_identity, str(lexical), str(candidate), "missing")
            state = "regular" if stat_module.S_ISREG(info.st_mode) else "nonregular"
            return CandidateObservation(
                anchor_identity, str(lexical), str(candidate), state,
                self._stat_identity(info))
        except BoundaryError as error:
            text = str(error)
            marker = f": {owner}: "
            prefix, path = (text.split(marker, 1) if marker in text
                            else ("include candidate rejected", str(lexical)))
            return CandidateObservation(anchor_identity, str(lexical), None,
                                        "error", error_prefix=prefix,
                                        error_path=path)
        except OSError:
            return CandidateObservation(
                anchor_identity, str(lexical), None, "error",
                error_prefix="cannot stat include candidate",
                error_path=str(lexical))

    @staticmethod
    def _raise_observation(observation: CandidateObservation,
                           owner: str) -> None:
        if observation.state == "error":
            raise BoundaryError(
                f"{observation.error_prefix}: {owner}: {observation.error_path}")

    def candidate(self, anchor: Path, name: str,
                  owner: str) -> CandidateObservation:
        key = (self.canonical_identity(anchor), name)
        observation = self.candidates.get(key)
        if observation is None:
            observation = self._observe_candidate(anchor, name, owner)
            self.candidates[key] = observation
            self.candidate_checks += 1
        else:
            self.candidate_hits += 1
        self._raise_observation(observation, owner)
        return observation

    def resolve(self, parent: Path, delimiter: str, name: str,
                roots: list[Path], owner: str) -> Path | None:
        search = ([parent] + roots) if delimiter == '"' else roots
        key = (self.canonical_identity(parent), delimiter, name,
               tuple(self.canonical_identity(root) for root in roots))
        if key in self.resolutions:
            self.resolution_hits += 1
            return self.resolutions[key]
        try:
            selected = None
            self.root_total = len(search)
            for root_number, base in enumerate(search, 1):
                self.root_ordinal = root_number
                observation = self.candidate(base, name, owner)
                candidate = (Path(observation.canonical_identity)
                             if observation.canonical_identity else base / name)
                if observation.state == "regular":
                    selected = candidate
                    break
                self.negative_paths.add(candidate)
        except BoundaryError as error:
            # Candidate observations own reusable error state so diagnostics
            # can be rehydrated with the current translation-unit owner.
            self.resolution_errors[key] = True
            raise
        self.resolutions[key] = selected
        return selected

    def is_local(self, path: Path) -> bool:
        if not any(path == base or base in path.parents
                   for base in self.local_bases):
            return False
        # Keyed by the parent because dependency_prefix() reads only the
        # ancestors: every file in a directory shares the same verdict.
        directory = path.parent
        if directory not in self.dependency_prefixes:
            self.dependency_prefixes[directory] = dependency_prefix(
                path, self.local_bases)
        return self.dependency_prefixes[directory] is None

    def read_local(self, path: Path) -> str:
        identity = str(path)
        if identity in self.text:
            value = self.text[identity]
            if isinstance(value, Exception):
                raise BoundaryError(f"unreadable include in boundary probe: {path}") from value
            return value
        try:
            self.reporter.update("distill", "read", text_reads=self.reads)
            data = path.read_bytes()
            value = data.decode("utf-8")
            self.reporter.update("distill", "stat", text_reads=self.reads)
            stat = path.stat()
        except (OSError, UnicodeDecodeError) as error:
            self.text[identity] = error
            raise BoundaryError(f"unreadable include in boundary probe: {path}") from error
        self.reads += 1
        self.text[identity] = value
        self.fingerprints[identity] = (
            stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
            hashlib.sha256(data).digest())
        return value

    def validate(self) -> None:
        for (anchor_identity, name), expected in sorted(
                self.candidates.items(), key=lambda item: item[0]):
            actual = self._observe_candidate(Path(anchor_identity), name,
                                             "snapshot validation")
            if actual != expected:
                raise BoundaryError(
                    f"include candidate changed during boundary scan: "
                    f"{expected.lexical_identity}")
            self._raise_observation(actual, "snapshot validation")
        for path in sorted(self.negative_paths, key=str):
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise BoundaryError(
                    f"cannot revalidate include candidate: {path}") from error
            raise BoundaryError(
                f"include candidate appeared during boundary scan: {path}")
        for identity, expected in sorted(self.fingerprints.items()):
            path = Path(identity)
            try:
                data = path.read_bytes()
                stat = path.stat()
            except OSError as error:
                raise BoundaryError(
                    f"include changed or became unreadable: {path}") from error
            actual = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns,
                      hashlib.sha256(data).digest())
            if actual != expected:
                raise BoundaryError(f"include changed during boundary scan: {path}")


def distilled_expansion(rel: str, raw: str, path: Path,
                        quote_roots: list[Path], angle_roots: list[Path],
                        local_bases: tuple[Path, ...],
                        snapshot: IncludeSnapshot,
                        stack: tuple[str, ...] = ()) -> Expansion:
    """Keep real local macro/include order while removing external includes.

    Quoted includes that name scanned files are expanded in place.  This gives
    the compiler the same macro state and ordering as the tracked translation
    unit without requiring generated or system headers to be installed.
    """
    snapshot.reporter.note_expansion(
        resolutions=len(snapshot.resolutions),
        candidate_checks=snapshot.candidate_checks,
        candidate_hits=snapshot.candidate_hits,
        expansion_hits=snapshot.expansion_hits,
        nodes=len(snapshot.expansions), retained=snapshot.expansion_bytes)
    path_identity = str(path)
    context_key = (path_identity, tuple(map(str, quote_roots)),
                   tuple(map(str, angle_roots)))
    cached = snapshot.expansions.get(context_key)
    if cached is not None:
        if cached.footprint.isdisjoint(stack):
            snapshot.expansion_hits += 1
            return cached
        snapshot.expansion_bypasses += 1
    lines = snapshot.logical_lines.get(path_identity)
    if lines is None:
        lines = tuple(logical_source(raw).splitlines())
        snapshot.logical_lines[path_identity] = lines
    body = []
    footprint = {path_identity}
    observed_backedge = False
    conditional = re.compile(
        r"^\s*#\s*(?:define|undef|if|ifdef|ifndef|elif|else|endif)\b")
    include_directive = re.compile(
        r'^\s*#\s*include\s*(["<])([^">\r\n]+)[">]')
    any_include = re.compile(r"^\s*#\s*include\b")
    unsupported_include = re.compile(
        r"^\s*#\s*(?:include_next|import|embed)\b")
    for line in lines:
        include = include_directive.match(line)
        if include is not None:
            delimiter, name = include.groups()
            roots = quote_roots if delimiter == '"' else angle_roots
            candidate = snapshot.resolve(path.parent, delimiter, name, roots,
                                         rel)
            if candidate is None:
                # Preserve compiler/builtin includes that are outside explicit
                # roots. The real preprocessor resolves them or fails closed.
                body.append(line)
                continue
            if not candidate.is_absolute() or not path.is_absolute():
                raise BoundaryError(
                    f"non-absolute snapshotted include identity: {rel}")
            candidate_id = str(candidate)
            is_local = snapshot.is_local(candidate)
            if not is_local:
                # Let the real compiler process external/system headers with
                # the TU's exact ordered search roots and conditional state.
                body.append(line)
            elif candidate_id not in stack:
                candidate_raw = snapshot.read_local(candidate)
                child = distilled_expansion(
                    candidate.as_posix(), candidate_raw, candidate,
                    quote_roots, angle_roots,
                    local_bases, snapshot,
                    stack + (path_identity,))
                body.append(child)
                footprint.update(child.footprint)
                observed_backedge |= child.observed_backedge
            else:
                body.append("")
                observed_backedge = True
                snapshot.expansion_backedges += 1
        elif any_include.match(line):
            raise BoundaryError(
                f"non-literal include in boundary probe: {rel}: {line.strip()}")
        elif unsupported_include.match(line):
            raise BoundaryError(
                f"unsupported include-like directive in boundary probe: "
                f"{rel}: {line.strip()}")
        elif not re.match(r"^\s*#", line):
            body.append(line)
        elif conditional.match(line):
            if re.match(r"^\s*#\s*define\b", line):
                body.append(line if valid_macro_directive(line) is not None else "")
            else:
                body.append(line)
        else:
            body.append("")
    parts = []
    for item in body:
        if parts:
            parts.append("\n")
        parts.append(item)
    parts.append("\n")
    literal_bytes = sum(len(part.encode("utf-8")) for part in parts
                        if isinstance(part, str))
    expansion = Expansion(tuple(parts), frozenset(footprint),
                          observed_backedge, literal_bytes)
    if not observed_backedge and expansion.footprint.isdisjoint(stack):
        if snapshot.expansion_bytes + literal_bytes <= snapshot.expansion_cap:
            snapshot.expansions[context_key] = expansion
            snapshot.expansion_bytes += literal_bytes
        else:
            snapshot.expansion_cap_rejections += 1
    return expansion


def distilled_source(rel: str, raw: str, path: Path,
                     quote_roots: list[Path], angle_roots: list[Path],
                     local_bases: tuple[Path, ...],
                     snapshot: IncludeSnapshot,
                     stack: tuple[str, ...] = ()) -> str:
    return flatten_expansion(distilled_expansion(
        rel, raw, path, quote_roots, angle_roots, local_bases, snapshot,
        stack))


def preprocess(command: list[str], compiler_id: str, source: str) -> str:
    if not command:
        raise BoundaryError("C preprocessor command is unavailable")
    if compiler_id in {"msvc", "clang-cl"}:
        argv = command + ["/nologo", "/EP", "/TC", "-"]
    else:
        argv = command + ["-E", "-P", "-x", "c", "-"]
    try:
        result = subprocess.run(argv, input=source, text=True, check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as error:
        raise BoundaryError(f"C preprocessor execution failed: {error}") from error
    if result.returncode != 0:
        raise BoundaryError("C preprocessor rejected boundary probe: "
                            + " ".join(argv) + "\n" + result.stderr)
    return result.stdout


def worker_count(compiler_id: str) -> int:
    """Bound native Windows parallelism without regressing GNU runners."""
    if compiler_id in {"msvc", "clang-cl"}:
        return min(4, max(1, os.cpu_count() or 1))
    return 1


def guarded_inspect(root: Path, manifest: dict[str, dict[str, int]],
            protected: tuple[str, ...], compiler: list[str],
            compiler_id: str, build_root: Path | None = None,
            reporter_factory=HeartbeatReporter) -> None:
    reporter = make_reporter(reporter_factory)
    reporter.start()
    try:
        return inspect(root, manifest, protected, compiler, compiler_id,
                       build_root, reporter)
    finally:
        try:
            reporter.stop()
        except Exception:
            pass


def inspect(root: Path, manifest: dict[str, dict[str, int]],
            protected: tuple[str, ...], compiler: list[str],
            compiler_id: str, build_root: Path | None,
            reporter) -> None:
    reporter.update("discovery", "read")
    actual = {symbol: {} for symbol in protected}
    files = list(source_files(root))
    windows = compiler_id in {"msvc", "clang-cl"}
    expanded_fixture = ([compiler[0]]
                        + expand_response_files(compiler[1:], root, windows))
    fixture_semantics = semantic_arguments(
        expanded_fixture, root, (root / "__boundary_fixture__.c").resolve(),
        windows)
    fallback_quote, fallback_angle = include_roots(expanded_fixture, root)
    bases = [base.resolve() for base in (root, build_root)
             if base is not None]
    fallback_quote = list(dict.fromkeys(fallback_quote + bases))
    fallback_angle = list(dict.fromkeys(fallback_angle + bases))
    database = compile_database_contexts(build_root, compiler_id, root)
    local_bases = tuple(base.resolve() for base in (root, build_root)
                        if base is not None)
    snapshot = IncludeSnapshot(local_bases, reporter=reporter)
    tasks = []
    print(f"boundary phase: tracked_files={len(files)} "
          f"compiled_sources={len(database)}", file=sys.stderr, flush=True)
    for source_number, (rel, raw) in enumerate(files, 1):
        reporter.update("raw", "check", file=source_number, files=len(files))
        decoded = decode_escapes(raw)
        for symbol in protected:
            count = len(re.findall(rf"\b{re.escape(symbol)}\b", decoded))
            if count:
                actual[symbol][rel] = count

        for lineno, line in enumerate(decoded.splitlines(), 1):
            compact = re.sub(r"[^A-Za-z0-9_]", "", line)
            for symbol in protected:
                if symbol in compact and symbol not in line:
                    raise BoundaryError(
                        f"obfuscated protected reference: {rel}:{lineno}: {symbol}")

        if Path(rel).suffix.lower() == ".c":
            reporter.update("distill", "resolve", file=source_number,
                            files=len(files))
            source_path = (root / rel).resolve()
            if manifest is MANIFEST and str(source_path) not in database:
                continue
            contexts = database.get(str(source_path), [(
                fallback_quote, fallback_angle, fixture_semantics)])
            probes = []
            for context_number, (quote_roots, angle_roots, _) in enumerate(
                    contexts, 1):
                reporter.update("distill", "expand", file=source_number,
                                files=len(files), context=context_number,
                                contexts=len(contexts), tu=len(tasks) +
                                len(probes) + 1)
                probes.append(distilled_expansion(
                    rel, raw, source_path, quote_roots, angle_roots,
                    local_bases, snapshot))
            for probe, (_, _, semantics) in zip(probes, contexts):
                tasks.append((rel, probe, protected, compiler, compiler_id,
                              semantics))

    # GNU preprocessing is memory-bandwidth bound on constrained runners;
    # native Windows clang-cl benefits from bounded host parallelism.
    print(f"boundary probes ready: tus={len(tasks)} "
          f"include_resolutions={len(snapshot.resolutions)} "
          f"resolution_hits={snapshot.resolution_hits} "
          f"candidate_checks={snapshot.candidate_checks} "
          f"candidate_hits={snapshot.candidate_hits} "
          f"expansion_hits={snapshot.expansion_hits} "
          f"expansion_bypasses={snapshot.expansion_bypasses} "
          f"expansion_backedges={snapshot.expansion_backedges} "
          f"expansion_bytes={snapshot.expansion_bytes} "
          f"expansion_cap_rejections={snapshot.expansion_cap_rejections} "
          f"local_reads={snapshot.reads} negatives={len(snapshot.negative_paths)}",
          file=sys.stderr, flush=True)
    reporter.update(
        "validate1", "lstat", tus=len(tasks), tasks=len(tasks),
        resolutions=len(snapshot.resolutions),
        resolution_hits=snapshot.resolution_hits,
        candidate_checks=snapshot.candidate_checks,
        candidate_hits=snapshot.candidate_hits, text_reads=snapshot.reads,
        expansion_calls=reporter.expansion_calls,
        expansion_hits=snapshot.expansion_hits, nodes=len(snapshot.expansions),
        retained=snapshot.expansion_bytes)
    validation_started = time.monotonic()
    snapshot.validate()
    reporter.update("validate1", "check", validations=1)
    print("boundary include snapshot initial validation complete: "
          f"elapsed={time.monotonic() - validation_started:.2f}s",
          file=sys.stderr, flush=True)
    workers = worker_count(compiler_id)
    scan_started = time.monotonic()
    reporter.update("compiler", "preprocess", tus=len(tasks), tasks=len(tasks))
    if compiler_id in {"msvc", "clang-cl"}:
        groups = {}
        for rel, probe, protected_items, compiler_items, compiler_kind, semantics in tasks:
            key = tuple(semantics)
            groups.setdefault(key, []).append((rel, probe, protected_items))
        batch_tasks = [(items, compiler, compiler_id, list(key))
                       for key, items in groups.items()]
        print(f"boundary semantic contexts: tus={len(tasks)} "
              f"groups={len(batch_tasks)} batches={len(batch_tasks)} "
              f"workers={workers}", file=sys.stderr, flush=True)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(lambda arguments: inspect_probe_batch(*arguments),
                              batch_tasks))
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(lambda arguments: inspect_probe(*arguments), tasks))
    print(f"boundary semantic scan complete: tus={len(tasks)} "
          f"workers={workers} elapsed={time.monotonic() - scan_started:.2f}s",
          file=sys.stderr, flush=True)
    validation_started = time.monotonic()
    reporter.update("validate2", "lstat", validations=1)
    snapshot.validate()
    reporter.update("validate2", "check", validations=2)
    print("boundary include snapshot revalidated: "
          f"elapsed={time.monotonic() - validation_started:.2f}s",
          file=sys.stderr, flush=True)

    if manifest is MANIFEST:
        reporter.update("owners", "resolve", validations=2)
        required = {str((root / path).resolve())
                    for owners in manifest.values() for path in owners
                    if path.endswith(".c")}
        missing = sorted(path for path in required if path not in database)
        if missing:
            raise BoundaryError(
                "allowed compiled boundary owner missing from compile database: "
                + json.dumps(missing))

    reporter.update("owners", "read", validations=2)
    if actual != manifest:
        reporter.update("owners", "check", validations=2)
        raise BoundaryError("protected reference manifest mismatch\nexpected="
                            + json.dumps(manifest, sort_keys=True)
                            + "\nactual=" + json.dumps(actual, sort_keys=True))

    if manifest is MANIFEST:
        for symbol in protected:
            owners = manifest[symbol]
            headers = [path for path in owners if path.endswith(".h")]
            implementations = [path for path in owners
                               if path.startswith("wyrelog/auth/")
                               and path.endswith(".c")]
            if len(headers) != 1 or len(implementations) != 1:
                raise BoundaryError(
                    f"private owner cardinality changed: {symbol}")
            header = (root / headers[0]).read_text(encoding="utf-8")
            implementation = (root / implementations[0]).read_text(
                encoding="utf-8")
            declaration = re.compile(
                rf"G_GNUC_INTERNAL\b[^;{{}}]*\b{re.escape(symbol)}\s*\(")
            definition = re.compile(rf"^[^;{{}}]*\b{re.escape(symbol)}\s*\(",
                                    re.MULTILINE)
            if len(declaration.findall(header)) != 1:
                raise BoundaryError(
                    f"private declaration cardinality changed: {symbol}")
            if len(definition.findall(implementation)) != 1:
                raise BoundaryError(
                    f"private definition cardinality changed: {symbol}")


def inspect_probe(rel: str, probe: str, protected: tuple[str, ...],
                  compiler: list[str], compiler_id: str,
                  semantics: list[str]) -> None:
            masked_probe, calibration, sentinels = prepare_probe(
                rel, flatten_expansion(probe), protected)
            expanded = preprocess(compiler[:1] + semantics, compiler_id,
                                  masked_probe)
            validate_expanded((rel,), expanded, protected, calibration,
                              sentinels)


def prepare_probe(rel: str, probe: str, protected: tuple[str, ...]):
            reserved = re.search(r"\bWYL_BOUNDARY_LITERAL_[A-Za-z0-9_]*\b",
                                 probe)
            if reserved is not None:
                raise BoundaryError(
                    f"reserved boundary sentinel in source: {rel}: "
                    f"{reserved.group(0)}")
            masked_probe = probe
            sentinels = []
            nonce = secrets.token_hex(16).upper()
            calibration = f"WYL_BOUNDARY_CALIBRATION_{nonce}"
            for index, symbol in enumerate(protected):
                occurrence = 0

                def replace_literal(_match: re.Match[str]) -> str:
                    nonlocal occurrence
                    sentinel = (f"WYL_BOUNDARY_LITERAL_{nonce}_{index}_"
                                f"{occurrence}")
                    occurrence += 1
                    sentinels.append(sentinel)
                    return sentinel

                masked_probe = re.sub(
                    rf"\b{re.escape(symbol)}\b", replace_literal, masked_probe)
            return calibration + "\n" + masked_probe, calibration, sentinels


def validate_expanded(rels: tuple[str, ...], expanded: str,
                      protected: tuple[str, ...], calibration: str,
                      sentinels: list[str]) -> None:
            location = ", ".join(rels)
            if len(re.findall(rf"\b{calibration}\b", expanded)) != 1:
                raise BoundaryError(
                    f"preprocessor calibration marker did not survive: {location}")
            for sentinel in sentinels:
                if len(re.findall(rf"\b{re.escape(sentinel)}\b", expanded)) > 1:
                    raise BoundaryError(
                        f"preprocessor multiplied protected reference: "
                        f"{location}: {sentinel}")
            for symbol in protected:
                expanded_count = len(re.findall(
                    rf"\b{re.escape(symbol)}\b", expanded))
                if expanded_count:
                    raise BoundaryError(
                        f"preprocessor synthesized protected reference: "
                        f"{location}: {symbol}")


def inspect_probe_batch(items, compiler: list[str], compiler_id: str,
                        semantics: list[str]) -> None:
    prepared = [(rel, *prepare_probe(rel, flatten_expansion(probe), protected))
                for rel, probe, protected in items]
    with tempfile.TemporaryDirectory() as directory:
        paths = []
        for index, (_, source, _, _) in enumerate(prepared):
            path = Path(directory) / f"probe-{index}.c"
            path.write_text(source, encoding="utf-8")
            paths.append(str(path))
        argv = compiler[:1] + semantics + ["/nologo", "/EP", "/TC", *paths]
        try:
            result = subprocess.run(argv, text=True, check=False, timeout=300,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired as error:
            rels = ", ".join(item[0] for item in prepared)
            raise BoundaryError(
                f"C preprocessor batch timed out after 300s: {rels}: "
                + " ".join(argv)) from error
        except OSError as error:
            raise BoundaryError(
                f"C preprocessor batch execution failed: {error}") from error
        if result.returncode != 0:
            raise BoundaryError("C preprocessor rejected boundary batch: "
                                + " ".join(argv) + "\n" + result.stderr)
    rels = tuple(item[0] for item in prepared)
    for _, _, calibration, sentinels in prepared:
        validate_expanded(rels, result.stdout, items[0][2], calibration,
                          sentinels)

def main() -> int:
    argv = sys.argv[1:]
    compiler = []
    if "--" in argv:
        separator = argv.index("--")
        compiler = argv[separator + 1:]
        argv = argv[:separator]
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--fixture-manifest")
    parser.add_argument("--fixture-symbol")
    parser.add_argument("--compiler-id", default="")
    parser.add_argument("--build-root", type=Path)
    args = parser.parse_args(argv)
    if not compiler:
        compiler = shlex.split(os.environ.get("CC", "cc"))
    compiler_id = args.compiler_id
    if not compiler_id:
        name = Path(compiler[-1]).name.lower()
        compiler_id = "clang-cl" if "clang-cl" in name else (
            "msvc" if name in {"cl", "cl.exe"} else "gnu")
    try:
        if args.fixture_manifest is not None:
            if args.fixture_symbol not in PROTECTED:
                raise BoundaryError("invalid fixture symbol")
            manifest = json.loads(args.fixture_manifest)
            guarded_inspect(
                args.root.resolve(), manifest, (args.fixture_symbol,),
                compiler, compiler_id,
                args.build_root.resolve() if args.build_root else None)
        else:
            guarded_inspect(
                args.root.resolve(), MANIFEST, PROTECTED, compiler,
                compiler_id,
                args.build_root.resolve() if args.build_root else None)
    except (BoundaryError, json.JSONDecodeError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
