#!/usr/bin/env python3
"""Reject implicit text encodings in repository Python scripts.

The scanner discovers Python and POSIX-shell units recursively below
``tests/`` and ``tools/`` by their shebangs.  Python embedded in shell
heredocs is parsed with the same AST scanner as standalone Python, with
diagnostics mapped back to the original shell line and column.

The analysis intentionally follows direct imports, simple name aliases and
statically-proven ``pathlib.Path`` values.  Dynamic reflection such as
``getattr(value, name)`` is outside the contract: it cannot be classified
without executing repository code.  Conversely, once a protected callable
(``open``, ``Path.open``, ``read_text`` or ``write_text``) is identified,
passing, returning, storing or otherwise escaping it is a structural error
rather than a silent blind spot.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from enum import Enum, auto
from pathlib import Path
import re
import sys
import tempfile


MIN_UNIT_COUNT = 55
REQUIRED_UNIT = Path("tools/gst-indent")

PYTHON_SHEBANG = re.compile(
    rb"^#![^\r\n]*(?:^|[/ ])(?:python(?:3(?:\.[0-9]+)?)?)(?:[ \r\n]|$)"
)
SHELL_SHEBANG = re.compile(
    rb"^#![^\r\n]*(?:^|[/ ])(?:sh|bash|dash|ksh|zsh)(?:[ \r\n]|$)"
)


@dataclass(frozen=True)
class Location:
    path: Path
    line: int
    column: int

    def render(self) -> str:
        return f"{self.path.as_posix()}:{self.line}:{self.column}"


@dataclass(frozen=True)
class Finding:
    location: Location
    message: str

    def render(self) -> str:
        return f"{self.location.render()}: {self.message}"


@dataclass(frozen=True)
class CallableValue:
    name: str
    mode_position: int | None
    encoding_position: int


UNKNOWN = object()
BUILTINS_MODULE = object()
IO_MODULE = object()
PATHLIB_MODULE = object()
PATH_CLASS = object()
PATH_VALUE = object()
PATH_ITERABLE = object()
NEXT_BUILTIN = object()
ITER_BUILTIN = object()

BUILTIN_OPEN = CallableValue("open", 1, 3)
BOUND_PATH_OPEN = CallableValue("Path.open", 0, 2)
UNBOUND_PATH_OPEN = CallableValue("Path.open", 1, 3)
BOUND_READ_TEXT = CallableValue("Path.read_text", None, 0)
UNBOUND_READ_TEXT = CallableValue("Path.read_text", None, 1)
BOUND_WRITE_TEXT = CallableValue("Path.write_text", None, 1)
UNBOUND_WRITE_TEXT = CallableValue("Path.write_text", None, 2)


@dataclass(frozen=True)
class PossibleValue:
    alternatives: frozenset[object]


@dataclass(frozen=True)
class MappingValue:
    key: object
    value: object


@dataclass(frozen=True)
class PairValue:
    first: object
    second: object


@dataclass(frozen=True)
class IterableValue:
    element: object


def alternatives(value: object) -> frozenset[object]:
    if isinstance(value, PossibleValue):
        return value.alternatives
    return frozenset({value})


def merge_values(*values: object) -> object:
    merged = frozenset().union(*(alternatives(value) for value in values))
    if len(merged) == 1:
        return next(iter(merged))
    return PossibleValue(merged)


def has_value(value: object, expected: object) -> bool:
    return expected in alternatives(value)


def callable_values(value: object) -> tuple[CallableValue, ...]:
    return tuple(
        item
        for item in alternatives(value)
        if isinstance(item, CallableValue)
    )


def iterable_element(value: object) -> object:
    if has_value(value, PATH_ITERABLE):
        return PATH_VALUE
    for candidate in alternatives(value):
        if isinstance(candidate, MappingValue):
            return candidate.key
        if isinstance(candidate, IterableValue):
            return candidate.element
    return UNKNOWN


def pair_components(value: object) -> tuple[object, object] | None:
    candidates = alternatives(value)
    if not any(isinstance(item, PairValue) for item in candidates):
        return None
    first: list[object] = []
    second: list[object] = []
    for candidate in candidates:
        if isinstance(candidate, PairValue):
            first.append(candidate.first)
            second.append(candidate.second)
        else:
            first.append(UNKNOWN)
            second.append(UNKNOWN)
    return merge_values(*first), merge_values(*second)


@dataclass
class ScanResult:
    units: list[Path] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[Finding] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.findings or self.errors)


@dataclass
class Scope:
    values: dict[str, object]
    local_names: set[str]
    kind: str
    parent: int | None
    global_names: set[str] = field(default_factory=set)
    nonlocal_names: set[str] = field(default_factory=set)
    future_values: dict[str, object] = field(default_factory=dict)


class LocalBindingCollector(ast.NodeVisitor):
    """Collect names whose presence makes a function name local."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()

    def bind_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.names.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind_target(item)
        elif isinstance(target, ast.Starred):
            self.bind_target(target.value)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self.bind_target(target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.bind_target(node.target)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.bind_target(node.target)
        self.visit(node.value)

    def visit_For(self, node: ast.For) -> None:
        self.bind_target(node.target)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self.bind_target(item.optional_vars)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.names.add(item.asname or item.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name != "*":
                self.names.add(item.asname or item.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.bind_target(node.target)
        self.visit(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self.bind_target(target)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.names.add(node.name)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def visit_Global(self, node: ast.Global) -> None:
        self.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocal_names.update(node.names)


@dataclass(frozen=True)
class FutureBinding:
    names: tuple[str, ...]
    expression: ast.AST | None = None
    annotation: ast.AST | None = None
    static_value: object = UNKNOWN
    is_static: bool = False


class FutureAssignmentCollector(ast.NodeVisitor):
    """Collect same-scope assignments without entering deferred scopes."""

    def __init__(self) -> None:
        self.bindings: list[FutureBinding] = []

    @staticmethod
    def names(target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [
                name
                for item in target.elts
                for name in FutureAssignmentCollector.names(item)
            ]
        if isinstance(target, ast.Starred):
            return FutureAssignmentCollector.names(target.value)
        return []

    def visit_Assign(self, node: ast.Assign) -> None:
        names = [
            name
            for target in node.targets
            for name in self.names(target)
        ]
        if names:
            self.bindings.append(FutureBinding(tuple(names), node.value))
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        names = self.names(node.target)
        if names:
            self.bindings.append(
                FutureBinding(
                    tuple(names),
                    node.value,
                    node.annotation,
                )
            )
        if node.value is not None:
            self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        names = self.names(node.target)
        if names:
            self.bindings.append(FutureBinding(tuple(names), node.value))
        self.visit(node.value)

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            name = item.asname or item.name.split(".", 1)[0]
            value = {
                "builtins": BUILTINS_MODULE,
                "io": IO_MODULE,
                "pathlib": PATHLIB_MODULE,
            }.get(item.name, UNKNOWN)
            self.bindings.append(
                FutureBinding((name,), static_value=value, is_static=True)
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name == "*":
                continue
            name = item.asname or item.name
            value = UNKNOWN
            if node.module in {"builtins", "io"} and item.name == "open":
                value = BUILTIN_OPEN
            elif node.module == "builtins" and item.name == "next":
                value = NEXT_BUILTIN
            elif node.module == "builtins" and item.name == "iter":
                value = ITER_BUILTIN
            elif node.module == "pathlib" and item.name == "Path":
                value = PATH_CLASS
            self.bindings.append(
                FutureBinding((name,), static_value=value, is_static=True)
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


class PythonScanner(ast.NodeVisitor):
    PATH_METHODS = {
        "resolve",
        "absolute",
        "expanduser",
        "joinpath",
        "readlink",
        "relative_to",
        "rename",
        "replace",
        "with_name",
        "with_stem",
        "with_suffix",
    }
    PATH_CLASS_METHODS = {"cwd", "home"}
    PATH_ITERATORS = {"glob", "rglob", "iterdir"}

    def __init__(
        self,
        path: Path,
        line_map: list[tuple[int, int]] | None = None,
    ) -> None:
        self.path = path
        self.line_map = line_map
        self.findings: list[Finding] = []
        self.errors: list[Finding] = []
        self.scopes = [Scope({}, set(), "module", None)]
        self.exception_state_sinks: list[list[list[Scope]]] = []

    def location(self, node: ast.AST) -> Location:
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        if self.line_map is not None and 1 <= line <= len(self.line_map):
            original_line, offset = self.line_map[line - 1]
            return Location(self.path, original_line, offset + column)
        return Location(self.path, line, column)

    def finding(self, node: ast.AST, message: str) -> None:
        self.findings.append(Finding(self.location(node), message))

    def error(self, node: ast.AST, message: str) -> None:
        self.errors.append(Finding(self.location(node), message))

    def resolve(self, name: str) -> object:
        index: int | None = len(self.scopes) - 1
        crossed_scope = False
        while index is not None:
            scope = self.scopes[index]
            if name in scope.global_names:
                index = 0
                scope = self.scopes[index]
                crossed_scope = True
            if crossed_scope and name in scope.future_values:
                fallback = {
                    "open": BUILTIN_OPEN,
                    "next": NEXT_BUILTIN,
                    "iter": ITER_BUILTIN,
                }.get(name, UNKNOWN)
                current = scope.values.get(
                    name,
                    fallback if scope.kind == "module" else UNKNOWN,
                )
                return merge_values(current, scope.future_values[name])
            if name in scope.values:
                return scope.values[name]
            if name in scope.local_names:
                return UNKNOWN
            index = scope.parent
            crossed_scope = True
        if name == "open":
            return BUILTIN_OPEN
        if name == "next":
            return NEXT_BUILTIN
        if name == "iter":
            return ITER_BUILTIN
        return UNKNOWN

    def binding_scope(self, name: str) -> int:
        current = len(self.scopes) - 1
        scope = self.scopes[current]
        if name in scope.global_names:
            return 0
        if name in scope.nonlocal_names:
            index = scope.parent
            while index not in {None, 0}:
                parent = self.scopes[index]
                if name in parent.local_names:
                    return index
                index = parent.parent
            return scope.parent if scope.parent is not None else 0
        return current

    def bind(self, name: str, value: object) -> None:
        index = self.binding_scope(name)
        self.scopes[index].values[name] = value
        self.scopes[index].local_names.add(name)
        for sink in self.exception_state_sinks:
            if sink and len(sink[0]) == len(self.scopes):
                sink.append(self.capture_state())

    def lexical_parent(self, skip_class: bool = False) -> int | None:
        index: int | None = len(self.scopes) - 1
        if skip_class:
            while index is not None and self.scopes[index].kind == "class":
                index = self.scopes[index].parent
        return index

    def capture_state(self) -> list[Scope]:
        return self.copy_state(self.scopes)

    def restore_state(self, state: list[Scope]) -> None:
        self.scopes = self.copy_state(state)

    @staticmethod
    def copy_state(state: list[Scope]) -> list[Scope]:
        return [
            Scope(
                dict(scope.values),
                set(scope.local_names),
                scope.kind,
                scope.parent,
                set(scope.global_names),
                set(scope.nonlocal_names),
                dict(scope.future_values),
            )
            for scope in state
        ]

    def join_states(self, *states: list[Scope]) -> None:
        joined = self.copy_state(states[0])
        for index, scope in enumerate(joined):
            scope.local_names = set().union(
                *(state[index].local_names for state in states)
            )
            names = set().union(
                *(set(state[index].values) for state in states)
            )
            scope.values = {}
            for name in names:
                possible = [
                    state[index].values.get(name, UNKNOWN)
                    for state in states
                ]
                scope.values[name] = merge_values(*possible)
        self.scopes = joined

    def precompute_future(self, statements: list[ast.stmt]) -> None:
        collector = FutureAssignmentCollector()
        for statement in statements:
            collector.visit(statement)
        if not collector.bindings:
            return

        saved = self.capture_state()
        targets: set[tuple[int, str]] = set()
        for _iteration in range(64):
            changed = False
            for binding in collector.bindings:
                assigned = (
                    binding.static_value
                    if binding.is_static
                    else self.value(binding.expression)
                )
                annotated = self.annotation_value(binding.annotation)
                if annotated is not UNKNOWN:
                    assigned = annotated
                for name in binding.names:
                    index = self.binding_scope(name)
                    targets.add((index, name))
                    current = self.scopes[index].values.get(name, UNKNOWN)
                    merged = merge_values(current, assigned)
                    if merged != current or name not in self.scopes[index].values:
                        self.scopes[index].values[name] = merged
                        self.scopes[index].local_names.add(name)
                        changed = True
            if not changed:
                break
        else:
            self.error(
                statements[0],
                "future-binding analysis did not reach a fixed point",
            )

        future = {
            (index, name): self.scopes[index].values.get(name, UNKNOWN)
            for index, name in targets
        }
        self.restore_state(saved)
        for (index, name), value in future.items():
            existing = self.scopes[index].future_values.get(name, UNKNOWN)
            self.scopes[index].future_values[name] = merge_values(
                existing,
                value,
            )

    def bind_target(self, target: ast.AST, value: object) -> bool:
        if isinstance(target, ast.Name):
            self.bind(target.id, value)
            return True
        if isinstance(target, (ast.Tuple, ast.List)):
            if callable_values(value):
                return False
            pair = pair_components(value)
            if pair is not None and len(target.elts) == 2:
                self.bind_target(target.elts[0], pair[0])
                self.bind_target(target.elts[1], pair[1])
                return True
            for item in target.elts:
                self.bind_target(item, UNKNOWN)
            return True
        if isinstance(target, ast.Starred):
            if callable_values(value):
                return False
            return self.bind_target(target.value, UNKNOWN)
        return not callable_values(value)

    def update_mapping_target(
        self,
        target: ast.AST,
        assigned: object,
    ) -> bool:
        if not isinstance(target, ast.Subscript) or not isinstance(
            target.value,
            ast.Name,
        ):
            return False
        current = self.value(target.value)
        if not any(
            isinstance(candidate, MappingValue)
            for candidate in alternatives(current)
        ):
            return False
        key = self.value(target.slice)
        updated: list[object] = []
        for candidate in alternatives(current):
            if isinstance(candidate, MappingValue):
                updated.append(
                    MappingValue(
                        merge_values(candidate.key, key),
                        merge_values(candidate.value, assigned),
                    )
                )
            else:
                updated.append(candidate)
        self.bind(target.value.id, merge_values(*updated))
        return True

    def value(self, node: ast.AST | None) -> object:
        if node is None:
            return UNKNOWN
        if isinstance(node, ast.Name):
            return self.resolve(node.id)
        if isinstance(node, ast.Attribute):
            owner = self.value(node.value)
            results: list[object] = []
            for candidate in alternatives(owner):
                result = UNKNOWN
                if (
                    candidate in {BUILTINS_MODULE, IO_MODULE}
                    and node.attr == "open"
                ):
                    result = BUILTIN_OPEN
                elif candidate is BUILTINS_MODULE and node.attr == "next":
                    result = NEXT_BUILTIN
                elif candidate is BUILTINS_MODULE and node.attr == "iter":
                    result = ITER_BUILTIN
                elif candidate is PATH_CLASS:
                    result = {
                        "open": UNBOUND_PATH_OPEN,
                        "read_text": UNBOUND_READ_TEXT,
                        "write_text": UNBOUND_WRITE_TEXT,
                    }.get(node.attr, UNKNOWN)
                elif candidate is PATH_VALUE:
                    if node.attr == "parent":
                        result = PATH_VALUE
                    else:
                        result = {
                            "open": BOUND_PATH_OPEN,
                            "read_text": BOUND_READ_TEXT,
                            "write_text": BOUND_WRITE_TEXT,
                        }.get(node.attr, UNKNOWN)
                elif candidate is PATHLIB_MODULE and node.attr == "Path":
                    result = PATH_CLASS
                results.append(result)
            return merge_values(*results)
        if isinstance(node, ast.Call):
            callable_value = self.value(node.func)
            results: list[object] = []
            for candidate in alternatives(callable_value):
                if candidate is PATH_CLASS:
                    results.append(PATH_VALUE)
                elif candidate is NEXT_BUILTIN and node.args:
                    iterable = self.value(node.args[0])
                    results.append(iterable_element(iterable))
                elif candidate is ITER_BUILTIN and node.args:
                    iterable = self.value(node.args[0])
                    element = iterable_element(iterable)
                    results.append(
                        IterableValue(element)
                        if element is not UNKNOWN
                        else UNKNOWN
                    )
            if isinstance(node.func, ast.Attribute):
                owner = self.value(node.func.value)
                if has_value(owner, PATH_VALUE):
                    if node.func.attr in self.PATH_METHODS:
                        results.append(PATH_VALUE)
                    elif node.func.attr in self.PATH_ITERATORS:
                        results.append(PATH_ITERABLE)
                if (
                    has_value(owner, PATH_CLASS)
                    and node.func.attr in self.PATH_CLASS_METHODS
                ):
                    results.append(PATH_VALUE)
                for candidate in alternatives(owner):
                    if not isinstance(candidate, MappingValue):
                        continue
                    if node.func.attr == "items":
                        results.append(
                            IterableValue(
                                PairValue(candidate.key, candidate.value)
                            )
                        )
                    elif node.func.attr == "keys":
                        results.append(IterableValue(candidate.key))
                    elif node.func.attr == "values":
                        results.append(IterableValue(candidate.value))
            return merge_values(*(results or [UNKNOWN]))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if has_value(self.value(node.left), PATH_VALUE):
                return PATH_VALUE
        if isinstance(node, ast.IfExp):
            left = self.value(node.body)
            right = self.value(node.orelse)
            return merge_values(left, right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            if any(has_value(self.value(item), PATH_VALUE) for item in node.elts):
                return PATH_ITERABLE
        if isinstance(node, ast.Dict):
            keys = [
                self.value(item)
                for item in node.keys
                if item is not None
            ]
            values = [self.value(item) for item in node.values]
            return MappingValue(
                merge_values(*(keys or [UNKNOWN])),
                merge_values(*(values or [UNKNOWN])),
            )
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)
        ):
            return self.comprehension_value(node)
        if isinstance(node, ast.DictComp):
            return self.dict_comprehension_value(node)
        return UNKNOWN

    def annotation_value(self, node: ast.AST | None) -> object:
        if node is None:
            return UNKNOWN
        if has_value(self.value(node), PATH_CLASS):
            return PATH_VALUE
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            compact = node.value.replace(" ", "")
            if compact in {"Path", "pathlib.Path"}:
                return PATH_VALUE
            if re.search(
                r"(?:list|set|tuple|Iterable|Iterator|Sequence|"
                r"Generator)\[(?:pathlib\.)?Path(?:[,\]])",
                compact,
            ):
                return PATH_ITERABLE
            if re.search(
                r"(?:dict|Mapping|MutableMapping)"
                r"\[(?:pathlib\.)?Path,",
                compact,
            ):
                return MappingValue(PATH_VALUE, UNKNOWN)
            if re.search(
                r"(?:dict|Mapping|MutableMapping)"
                r"\[[^,]+,(?:pathlib\.)?Path\]",
                compact,
            ):
                return MappingValue(UNKNOWN, PATH_VALUE)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return merge_values(
                self.annotation_value(node.left),
                self.annotation_value(node.right),
            )
        if isinstance(node, ast.Subscript):
            container = self.annotation_name(node.value)
            if container in {"dict", "Mapping", "MutableMapping"}:
                if (
                    isinstance(node.slice, ast.Tuple)
                    and len(node.slice.elts) >= 2
                ):
                    key = self.annotation_value(node.slice.elts[0])
                    value = self.annotation_value(node.slice.elts[1])
                    return MappingValue(
                        key,
                        value,
                    )
                return UNKNOWN
            element = self.annotation_value(node.slice)
            if container in {
                "list",
                "set",
                "tuple",
                "Iterable",
                "Iterator",
                "Sequence",
                "Generator",
            } and has_value(element, PATH_VALUE):
                return PATH_ITERABLE
            return element
        if isinstance(node, ast.Tuple):
            return merge_values(
                *(self.annotation_value(item) for item in node.elts)
            )
        return UNKNOWN

    @staticmethod
    def annotation_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""

    @staticmethod
    def keyword(call: ast.Call, name: str) -> ast.AST | None:
        for item in call.keywords:
            if item.arg == name:
                return item.value
        return None

    @staticmethod
    def positional(call: ast.Call, position: int) -> ast.AST | None:
        if position < len(call.args):
            return call.args[position]
        return None

    def check_encoding_call(
        self, node: ast.Call, callable_value: CallableValue
    ) -> None:
        mode = self.keyword(node, "mode")
        if mode is None and callable_value.mode_position is not None:
            mode = self.positional(node, callable_value.mode_position)

        if (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and "b" in mode.value
        ):
            return

        encoding = self.keyword(node, "encoding")
        if encoding is None:
            encoding = self.positional(node, callable_value.encoding_position)
        if encoding is None or (
            isinstance(encoding, ast.Constant) and encoding.value is None
        ):
            self.finding(
                node,
                f"{callable_value.name} text operation needs an explicit "
                "non-None encoding",
            )

    def scan_expression(
        self, node: ast.AST | None, allow_top_callable: bool = False
    ) -> None:
        if node is None:
            return
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            self.visit_comprehension_expression(node)
            return
        if isinstance(node, ast.Lambda):
            self.visit_Lambda(node)
            return
        if isinstance(node, ast.NamedExpr):
            self.visit_NamedExpr(node)
            return
        if isinstance(node, ast.IfExp) and allow_top_callable:
            self.scan_expression(node.test)
            self.scan_expression(
                node.body,
                allow_top_callable=bool(callable_values(self.value(node.body))),
            )
            self.scan_expression(
                node.orelse,
                allow_top_callable=bool(
                    callable_values(self.value(node.orelse))
                ),
            )
            return
        if isinstance(node, ast.Call):
            protected = callable_values(self.value(node.func))
            seen: set[CallableValue] = set()
            for callable_value in protected:
                if callable_value not in seen:
                    self.check_encoding_call(node, callable_value)
                    seen.add(callable_value)
            # A protected outer callable never makes its receiver inert:
            # Path(open(...)).read_text(...) must still inspect open(...).
            self.scan_expression(node.func, allow_top_callable=True)
            for arg in node.args:
                self.scan_expression(arg)
            for item in node.keywords:
                self.scan_expression(item.value)
            return
        if isinstance(node, (ast.Name, ast.Attribute)):
            protected = callable_values(self.value(node))
            if protected and not allow_top_callable:
                names = ", ".join(sorted({item.name for item in protected}))
                self.error(
                    node,
                    f"protected callable {names} escapes static "
                    "analysis",
                )
                return
            if isinstance(node, ast.Attribute):
                self.scan_expression(node.value)
            return
        for child in ast.iter_child_nodes(node):
            self.scan_expression(child)

    def visit_Expr(self, node: ast.Expr) -> None:
        self.scan_expression(node.value)

    def visit_Module(self, node: ast.Module) -> None:
        self.precompute_future(node.body)
        for statement in node.body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        self.scan_expression(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.scan_expression(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.scan_expression(node)

    def visit_Return(self, node: ast.Return) -> None:
        self.scan_expression(node.value)

    def visit_Raise(self, node: ast.Raise) -> None:
        self.scan_expression(node.exc)
        self.scan_expression(node.cause)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.scan_expression(node.test)
        self.scan_expression(node.msg)

    def visit_Assign(self, node: ast.Assign) -> None:
        assigned = self.value(node.value)
        allow = bool(callable_values(assigned))
        self.scan_expression(node.value, allow_top_callable=allow)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                self.scan_expression(target)
            if self.update_mapping_target(target, assigned):
                continue
            if not self.bind_target(target, assigned):
                names = ", ".join(
                    sorted({item.name for item in callable_values(assigned)})
                )
                self.error(
                    target,
                    f"protected callable {names} must be assigned "
                    "only to simple names",
                )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        assigned = self.value(node.value)
        annotated = self.annotation_value(node.annotation)
        if annotated is not UNKNOWN:
            assigned = annotated
        allow = bool(callable_values(assigned))
        self.scan_expression(node.value, allow_top_callable=allow)
        if not isinstance(node.target, ast.Name):
            self.scan_expression(node.target)
        if self.update_mapping_target(node.target, assigned):
            return
        if not self.bind_target(node.target, assigned):
            names = ", ".join(
                sorted({item.name for item in callable_values(assigned)})
            )
            self.error(
                node.target,
                f"protected callable {names} must be assigned only "
                "to a simple name",
            )

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.scan_expression(node.target)
        self.scan_expression(node.value)
        self.bind_target(node.target, UNKNOWN)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        assigned = self.value(node.value)
        allow = bool(callable_values(assigned))
        self.scan_expression(node.value, allow_top_callable=allow)
        if not self.bind_target(node.target, assigned):
            names = ", ".join(
                sorted({item.name for item in callable_values(assigned)})
            )
            self.error(
                node.target,
                f"protected callable {names} must be assigned only "
                "to a simple name",
            )

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            name = item.asname or item.name.split(".", 1)[0]
            if item.name == "builtins":
                self.bind(name, BUILTINS_MODULE)
            elif item.name == "io":
                self.bind(name, IO_MODULE)
            elif item.name == "pathlib":
                self.bind(name, PATHLIB_MODULE)
            else:
                self.bind(name, UNKNOWN)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            if item.name == "*":
                continue
            name = item.asname or item.name
            if node.module in {"builtins", "io"} and item.name == "open":
                self.bind(name, BUILTIN_OPEN)
            elif node.module == "builtins" and item.name == "next":
                self.bind(name, NEXT_BUILTIN)
            elif node.module == "builtins" and item.name == "iter":
                self.bind(name, ITER_BUILTIN)
            elif node.module == "pathlib" and item.name == "Path":
                self.bind(name, PATH_CLASS)
            else:
                self.bind(name, UNKNOWN)

    def function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Scope:
        collector = LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)
        local_names = (
            collector.names - collector.global_names - collector.nonlocal_names
        )
        values = {name: UNKNOWN for name in local_names}
        arguments = (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            values[argument.arg] = self.annotation_value(argument.annotation)
            local_names.add(argument.arg)
        return Scope(
            values,
            local_names,
            "function",
            self.lexical_parent(skip_class=True),
            collector.global_names,
            collector.nonlocal_names,
        )

    def visit_FunctionDef(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        for decorator in node.decorator_list:
            self.scan_expression(decorator)
        for default in list(node.args.defaults) + [
            item for item in node.args.kw_defaults if item is not None
        ]:
            self.scan_expression(default)
        self.bind(node.name, UNKNOWN)
        outer_state = self.capture_state()
        self.scopes.append(self.function_scope(node))
        self.precompute_future(node.body)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.restore_state(outer_state)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        names = {
            item.arg
            for item in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
        }
        values = {name: UNKNOWN for name in names}
        self.scopes.append(
            Scope(
                values,
                names,
                "function",
                self.lexical_parent(skip_class=True),
            )
        )
        self.scan_expression(node.body)
        self.scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for base in node.bases:
            self.scan_expression(base)
        for item in node.keywords:
            self.scan_expression(item.value)
        for decorator in node.decorator_list:
            self.scan_expression(decorator)
        self.bind(node.name, UNKNOWN)
        collector = LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)
        self.scopes.append(
            Scope(
                {},
                set(),
                "class",
                self.lexical_parent(),
                collector.global_names,
                collector.nonlocal_names,
            )
        )
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def visit_If(self, node: ast.If) -> None:
        self.scan_expression(node.test)
        before = self.capture_state()
        self.restore_state(before)
        for statement in node.body:
            self.visit(statement)
        body_state = self.capture_state()
        self.restore_state(before)
        for statement in node.orelse:
            self.visit(statement)
        else_state = self.capture_state()
        self.join_states(body_state, else_state)

    def visit_While(self, node: ast.While) -> None:
        before = self.capture_state()
        head = before
        for _iteration in range(64):
            self.restore_state(head)
            self.scan_expression(node.test)
            for statement in node.body:
                self.visit(statement)
            body_state = self.capture_state()
            self.join_states(head, before, body_state)
            next_head = self.capture_state()
            if next_head == head:
                head = next_head
                break
            head = next_head
        else:
            self.error(node, "while analysis did not reach a fixed point")
        self.restore_state(head)
        for statement in node.orelse:
            self.visit(statement)
        else_state = self.capture_state()
        self.join_states(head, else_state)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.scan_expression(node.iter)
        before = self.capture_state()
        element = (
            iterable_element(self.value(node.iter))
        )
        head = before
        for _iteration in range(64):
            self.restore_state(head)
            self.bind_target(node.target, element)
            for statement in node.body:
                self.visit(statement)
            body_state = self.capture_state()
            self.join_states(head, before, body_state)
            next_head = self.capture_state()
            if next_head == head:
                head = next_head
                break
            head = next_head
        else:
            self.error(node, "for analysis did not reach a fixed point")
        self.restore_state(head)
        for statement in node.orelse:
            self.visit(statement)
        else_state = self.capture_state()
        self.join_states(head, else_state)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.scan_expression(item.context_expr)
            if item.optional_vars is not None:
                self.bind_target(item.optional_vars, UNKNOWN)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_Try(self, node: ast.Try) -> None:
        before = self.capture_state()
        exception_states = [before]
        self.exception_state_sinks.append(exception_states)
        for statement in node.body:
            self.visit(statement)
            exception_states.append(self.capture_state())
        self.exception_state_sinks.pop()
        try_state = self.capture_state()
        handler_states: list[list[Scope]] = []
        for handler in node.handlers:
            self.join_states(*exception_states)
            if handler.type is not None:
                self.scan_expression(handler.type)
            if handler.name is not None:
                self.bind(handler.name, UNKNOWN)
            for statement in handler.body:
                self.visit(statement)
            handler_states.append(self.capture_state())
        self.restore_state(try_state)
        for statement in node.orelse:
            self.visit(statement)
        normal_state = self.capture_state()
        self.join_states(normal_state, *handler_states)
        for statement in node.finalbody:
            self.visit(statement)

    visit_TryStar = visit_Try

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.bind(target.id, UNKNOWN)
            else:
                self.scan_expression(target)

    def visit_comprehension_expression(
        self,
        node: ast.ListComp
        | ast.SetComp
        | ast.GeneratorExp
        | ast.DictComp,
    ) -> None:
        self.scopes.append(
            Scope(
                {},
                set(),
                "comprehension",
                self.lexical_parent(skip_class=True),
            )
        )
        for generator in node.generators:
            self.scan_expression(generator.iter)
            element = (
                iterable_element(self.value(generator.iter))
            )
            self.bind_target(generator.target, element)
            for condition in generator.ifs:
                self.scan_expression(condition)
        if isinstance(node, ast.DictComp):
            self.scan_expression(node.key)
            self.scan_expression(node.value)
        else:
            self.scan_expression(node.elt)
        self.scopes.pop()

    def comprehension_value(
        self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp
    ) -> object:
        self.scopes.append(
            Scope(
                {},
                set(),
                "comprehension",
                self.lexical_parent(skip_class=True),
            )
        )
        for generator in node.generators:
            element = (
                iterable_element(self.value(generator.iter))
            )
            self.bind_target(generator.target, element)
        element_value = self.value(node.elt)
        self.scopes.pop()
        return (
            PATH_ITERABLE
            if has_value(element_value, PATH_VALUE)
            else UNKNOWN
        )

    def dict_comprehension_value(self, node: ast.DictComp) -> object:
        self.scopes.append(
            Scope(
                {},
                set(),
                "comprehension",
                self.lexical_parent(skip_class=True),
            )
        )
        for generator in node.generators:
            self.bind_target(
                generator.target,
                iterable_element(self.value(generator.iter)),
            )
        key = self.value(node.key)
        value = self.value(node.value)
        self.scopes.pop()
        return MappingValue(key, value)

    visit_ListComp = visit_comprehension_expression
    visit_SetComp = visit_comprehension_expression
    visit_GeneratorExp = visit_comprehension_expression
    visit_DictComp = visit_comprehension_expression


@dataclass(frozen=True)
class HereDoc:
    delimiter: str
    strip_tabs: bool
    selected: bool
    operator_line: int
    operator_column: int


@dataclass(frozen=True)
class ShellWord:
    value: str
    start: int
    end: int


@dataclass
class ShellSegment:
    pipeline: int
    words: list[ShellWord] = field(default_factory=list)
    stdin_events: list[tuple[str, int]] = field(default_factory=list)
    stdout_redirected: bool = False


class PipelineSourceKind(Enum):
    PASSTHROUGH = auto()
    BLOCKED = auto()
    UNSUPPORTED = auto()


@dataclass(frozen=True)
class TrailingPipeline:
    heredoc_index: int
    source_kind: PipelineSourceKind
    position: int


@dataclass
class ShellLexResult:
    heredocs: list[HereDoc]
    errors: list[tuple[int, str]]
    has_command: bool
    accepts_incoming_pipeline: bool
    has_trailing_pipe: bool
    trailing_pipeline: TrailingPipeline | None


@dataclass(frozen=True)
class PendingPipelineBody:
    source_kind: PipelineSourceKind
    source: str
    line_map: list[tuple[int, int]]
    location: Location


def shell_word(command: str, start: int) -> tuple[str, int, bool]:
    output: list[str] = []
    index = start
    quote: str | None = None
    while index < len(command):
        char = command[index]
        if quote is None:
            if char in " \t\r\n;|&()<>":
                break
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "\\" and index + 1 < len(command):
                output.append(command[index + 1])
                index += 2
                continue
            output.append(char)
            index += 1
            continue
        if char == quote:
            quote = None
            index += 1
            continue
        if char == "\\" and quote == '"' and index + 1 < len(command):
            output.append(command[index + 1])
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output), index, quote is None


def command_words(segment: ShellSegment) -> tuple[str, list[str]] | None:
    words = [word.value for word in segment.words]
    reserved = {
        "if",
        "then",
        "elif",
        "while",
        "until",
        "do",
        "!",
    }
    while words and (
        words[0] in reserved
        or ("=" in words[0] and not words[0].startswith("="))
    ):
        words.pop(0)
    while words and Path(words[0]).name in {"command", "exec", "env"}:
        wrapper = Path(words.pop(0)).name
        if wrapper == "command":
            while words and words[0] in {"-p", "--"}:
                option = words.pop(0)
                if option == "--":
                    break
            if words and words[0] in {"-v", "-V"}:
                return None
            if words and words[0].startswith("-"):
                raise ValueError("unsupported command wrapper option")
            continue
        if wrapper == "exec":
            while words and words[0].startswith("-"):
                option = words.pop(0)
                if option in {"-a", "--argv0"}:
                    if not words:
                        raise ValueError("missing exec argv0 value")
                    words.pop(0)
                elif option == "--":
                    break
                elif option not in {"-c", "-l"}:
                    raise ValueError("unsupported exec wrapper option")
            continue
        while words:
            word = words[0]
            if word in {"-u", "--unset", "-C", "--chdir"}:
                if len(words) < 2:
                    raise ValueError("missing env wrapper option value")
                del words[:2]
            elif word.startswith(("--unset=", "--chdir=")):
                words.pop(0)
            elif word in {"-i", "--ignore-environment", "--"}:
                words.pop(0)
                if word == "--":
                    break
            elif word.startswith("-u") and len(word) > 2:
                words.pop(0)
            elif word.startswith("-"):
                raise ValueError("unsupported env wrapper option")
            elif "=" in word and not word.startswith("="):
                words.pop(0)
            else:
                break
    if not words:
        return None
    return words[0], words[1:]


def is_python_stdin(segment: ShellSegment) -> bool:
    command = command_words(segment)
    if command is None:
        return False
    executable, arguments = command
    name = Path(executable).name
    if executable not in {"$PYTHON", "${PYTHON}"} and not re.fullmatch(
        r"python(?:3(?:\.[0-9]+)*)?", name
    ):
        return False

    index = 0
    no_input_options = {
        "-h",
        "--help",
        "-V",
        "-VV",
        "--version",
    }
    flag_options = {
        "-b",
        "-B",
        "-d",
        "-E",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-q",
        "-s",
        "-S",
        "-u",
        "-v",
        "-x",
    }
    combined_flags = frozenset("bBdEiIOPqSsuvx")
    interactive = False
    while index < len(arguments):
        argument = arguments[index]
        if argument == "-":
            return True
        if argument in no_input_options:
            return False
        if argument == "-i":
            interactive = True
            index += 1
            continue
        if argument.startswith("-i") and len(argument) > 2:
            remainder = argument[2:]
            interactive = True
            if remainder.startswith(("c", "m")):
                return True
            if not set(remainder) <= combined_flags:
                raise ValueError(
                    f"unsupported combined Python option {argument!r}"
                )
            index += 1
            continue
        if argument in {"-c", "-m"} or argument.startswith(("-c", "-m")):
            return interactive
        if argument in {"-W", "-X"}:
            index += 2
            continue
        if argument.startswith(("-W", "-X")):
            index += 1
            continue
        if argument == "--":
            if index + 1 == len(arguments):
                return True
            if arguments[index + 1] == "-":
                return True
            return interactive
        if argument in flag_options:
            index += 1
            continue
        if (
            argument.startswith("-")
            and len(argument) > 2
            and set(argument[1:]) <= combined_flags
        ):
            interactive = interactive or "i" in argument[1:]
            index += 1
            continue
        if argument.startswith("-"):
            raise ValueError(
                f"unsupported Python interpreter option {argument!r}"
            )
        return interactive
    return True


def pipeline_source_kind(segment: ShellSegment) -> PipelineSourceKind:
    try:
        command = command_words(segment)
    except ValueError:
        return PipelineSourceKind.UNSUPPORTED
    if command is None:
        return PipelineSourceKind.UNSUPPORTED
    executable, arguments = command
    name = Path(executable).name
    if name == "cat":
        if (
            (not arguments or arguments == ["-"])
            and not segment.stdout_redirected
        ):
            return PipelineSourceKind.PASSTHROUGH
        return PipelineSourceKind.BLOCKED
    if name in {"true", "false"}:
        return PipelineSourceKind.BLOCKED
    return PipelineSourceKind.UNSUPPORTED


def lex_shell_command(
    command: str,
    positions: list[tuple[int, int]],
) -> ShellLexResult:
    segments = [ShellSegment(0)]
    heredocs: list[HereDoc] = []
    errors: list[tuple[int, str]] = []
    pipeline = 0
    index = 0
    while index < len(command):
        char = command[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "#":
            while index < len(command) and command[index] != "\n":
                index += 1
            continue
        if command.startswith("&&", index) or command.startswith("||", index):
            pipeline += 1
            segments.append(ShellSegment(pipeline))
            index += 2
            continue
        if command.startswith("|&", index):
            errors.append((index, "unsupported pipeline operator '|&'"))
            pipeline += 1
            segments.append(ShellSegment(pipeline))
            index += 2
            continue
        if char == "|":
            segments.append(ShellSegment(pipeline))
            index += 1
            continue
        if char in ";&()":
            pipeline += 1
            segments.append(ShellSegment(pipeline))
            index += 1
            continue
        if command.startswith("<<", index) and not command.startswith(
            "<<<", index
        ):
            operator = index
            descriptor = 0
            if (
                segments[-1].words
                and segments[-1].words[-1].end == operator
                and segments[-1].words[-1].value.isdigit()
            ):
                descriptor = int(segments[-1].words.pop().value)
            index += 2
            strip_tabs = False
            if index < len(command) and command[index] == "-":
                strip_tabs = True
                index += 1
            while index < len(command) and command[index] in " \t":
                index += 1
            delimiter, end, closed = shell_word(command, index)
            if not delimiter or not closed:
                errors.append((operator, "malformed heredoc delimiter"))
                index = max(end, index + 1)
                continue
            line, column = positions[operator]
            heredoc_index = len(heredocs)
            heredocs.append(
                HereDoc(
                    delimiter,
                    strip_tabs,
                    False,
                    line,
                    column,
                )
            )
            if descriptor == 0:
                segments[-1].stdin_events.append(
                    ("heredoc", heredoc_index)
                )
            index = end
            continue
        if char == "<":
            operator = index
            descriptor = 0
            if (
                segments[-1].words
                and segments[-1].words[-1].end == operator
                and segments[-1].words[-1].value.isdigit()
            ):
                descriptor = int(segments[-1].words.pop().value)
            if command.startswith(("<<<", "<&", "<>"), index):
                errors.append(
                    (operator, "unsupported input redirection syntax")
                )
                index += 2
                continue
            index += 1
            while index < len(command) and command[index] in " \t":
                index += 1
            _target, end, closed = shell_word(command, index)
            if end == index or not closed:
                errors.append((operator, "malformed input redirection"))
                index = max(end, index + 1)
                continue
            if descriptor == 0:
                segments[-1].stdin_events.append(("other", -1))
            index = end
            continue
        if char == ">":
            operator = index
            descriptor = 1
            if segments[-1].words and (
                segments[-1].words[-1].end == operator
                and segments[-1].words[-1].value.isdigit()
            ):
                descriptor = int(segments[-1].words.pop().value)
            if descriptor == 1:
                segments[-1].stdout_redirected = True
            index += 2 if command.startswith((">>", ">&"), index) else 1
            while index < len(command) and command[index] in " \t":
                index += 1
            _target, end, closed = shell_word(command, index)
            if end == index or not closed:
                errors.append((operator, "malformed output redirection"))
                index = max(end, index + 1)
                continue
            index = end
            continue
        value, end, closed = shell_word(command, index)
        if end == index:
            index += 1
            continue
        if not closed:
            errors.append((index, "unterminated shell quote"))
        segments[-1].words.append(ShellWord(value, index, end))
        index = end

    python_inputs: dict[int, bool] = {}
    for segment in segments:
        try:
            python_inputs[id(segment)] = is_python_stdin(segment)
        except ValueError as exc:
            position = segment.words[0].start if segment.words else 0
            errors.append((position, str(exc)))
            python_inputs[id(segment)] = False

    for pipeline_id in {segment.pipeline for segment in segments}:
        group = [
            segment for segment in segments if segment.pipeline == pipeline_id
        ]
        for target_index, segment in enumerate(group):
            if not python_inputs[id(segment)]:
                continue
            if segment.stdin_events:
                kind, heredoc_index = segment.stdin_events[-1]
                if kind == "heredoc":
                    heredocs[heredoc_index] = replace(
                        heredocs[heredoc_index],
                        selected=True,
                    )
                continue
            if target_index == 0:
                continue
            producer = group[target_index - 1]
            if producer.stdin_events:
                kind, heredoc_index = producer.stdin_events[-1]
                source_kind = pipeline_source_kind(producer)
                if (
                    kind == "heredoc"
                    and source_kind is PipelineSourceKind.PASSTHROUGH
                ):
                    heredocs[heredoc_index] = replace(
                        heredocs[heredoc_index],
                        selected=True,
                    )
                elif (
                    kind == "heredoc"
                    and source_kind is PipelineSourceKind.UNSUPPORTED
                ):
                    position = (
                        producer.words[0].start if producer.words else 0
                    )
                    errors.append(
                        (
                            position,
                            "unsupported heredoc pipeline source",
                        )
                    )
                continue
            earlier = [
                item
                for item in group[: target_index - 1]
                if item.stdin_events
            ]
            if earlier:
                position = (
                    earlier[-1].words[0].start
                    if earlier[-1].words
                    else 0
                )
                errors.append(
                    (
                        position,
                        "unsupported multi-stage heredoc pipeline",
                    )
                )

    nonempty = [
        segment
        for segment in segments
        if segment.words or segment.stdin_events
    ]
    accepts_incoming = bool(
        nonempty
        and python_inputs[id(nonempty[0])]
        and not nonempty[0].stdin_events
    )

    trailing: TrailingPipeline | None = None
    has_trailing_pipe = (
        len(segments) >= 2
        and not segments[-1].words
        and not segments[-1].stdin_events
        and segments[-1].pipeline == segments[-2].pipeline
    )
    if has_trailing_pipe:
        producer = segments[-2]
        if producer.stdin_events:
            kind, heredoc_index = producer.stdin_events[-1]
            if kind == "heredoc":
                position = producer.words[0].start if producer.words else 0
                trailing = TrailingPipeline(
                    heredoc_index,
                    pipeline_source_kind(producer),
                    position,
                )
        else:
            earlier = [
                segment
                for segment in segments[:-2]
                if segment.pipeline == producer.pipeline
                and segment.stdin_events
            ]
            if earlier:
                source = earlier[-1]
                kind, heredoc_index = source.stdin_events[-1]
                if kind == "heredoc":
                    position = source.words[0].start if source.words else 0
                    trailing = TrailingPipeline(
                        heredoc_index,
                        PipelineSourceKind.UNSUPPORTED,
                        position,
                    )

    return ShellLexResult(
        heredocs,
        errors,
        bool(nonempty),
        accepts_incoming,
        has_trailing_pipe,
        trailing,
    )


def continued_shell_command(
    lines: list[str], start: int
) -> tuple[str, list[tuple[int, int]], int]:
    command: list[str] = []
    positions: list[tuple[int, int]] = []
    line_index = start
    single = False
    double = False
    while line_index < len(lines):
        line = lines[line_index]
        continuation = False
        index = 0
        while index < len(line):
            char = line[index]
            if (
                char == "#"
                and not single
                and not double
                and (
                    index == 0
                    or line[index - 1] in " \t\r\n;|&()"
                )
            ):
                break
            if char == "\\" and not single:
                if index == len(line) - 1:
                    continuation = True
                    break
                index += 2
                continue
            if char == "'" and not double:
                single = not single
            elif char == '"' and not single:
                double = not double
            index += 1
        limit = len(line) - 1 if continuation else len(line)
        for column, char in enumerate(line[:limit], 1):
            command.append(char)
            positions.append((line_index + 1, column))
        if not continuation:
            command.append("\n")
            positions.append((line_index + 1, len(line) + 1))
            if not single and not double:
                return "".join(command), positions, line_index + 1
        line_index += 1
    return "".join(command), positions, line_index


def scan_python(
    source: str,
    path: Path,
    line_map: list[tuple[int, int]] | None = None,
) -> tuple[list[Finding], list[Finding]]:
    try:
        tree = ast.parse(source, filename=path.as_posix())
    except SyntaxError as exc:
        line = exc.lineno or 1
        column = exc.offset or 1
        if line_map is not None and 1 <= line <= len(line_map):
            original_line, offset = line_map[line - 1]
            line = original_line
            column += offset
        error = Finding(
            Location(path, line, column),
            f"cannot parse selected Python: {exc.msg}",
        )
        return [], [error]
    scanner = PythonScanner(path, line_map)
    scanner.visit(tree)
    def unique(items: list[Finding]) -> list[Finding]:
        seen: set[tuple[Location, str]] = set()
        output: list[Finding] = []
        for item in items:
            key = (item.location, item.message)
            if key not in seen:
                seen.add(key)
                output.append(item)
        return output

    return unique(scanner.findings), unique(scanner.errors)


def scan_shell(
    source: str, path: Path
) -> tuple[list[Finding], list[Finding]]:
    lines = source.splitlines()
    findings: list[Finding] = []
    errors: list[Finding] = []
    pending: PendingPipelineBody | None = None
    line_index = 0
    while line_index < len(lines):
        command, positions, next_line = continued_shell_command(
            lines, line_index
        )
        analysis = lex_shell_command(command, positions)
        for position, message in analysis.errors:
            original_line, original_column = positions[
                min(position, len(positions) - 1)
            ]
            errors.append(
                Finding(
                    Location(path, original_line, original_column),
                    message,
                )
            )
        if pending is not None and analysis.has_command:
            if analysis.accepts_incoming_pipeline:
                if pending.source_kind is PipelineSourceKind.PASSTHROUGH:
                    found, broken = scan_python(
                        pending.source,
                        path,
                        pending.line_map,
                    )
                    findings.extend(found)
                    errors.extend(broken)
                elif pending.source_kind is PipelineSourceKind.UNSUPPORTED:
                    errors.append(
                        Finding(
                            pending.location,
                            "unsupported heredoc pipeline source",
                        )
                    )
                pending = None
            elif analysis.has_trailing_pipe:
                if pending.source_kind is PipelineSourceKind.PASSTHROUGH:
                    pending = replace(
                        pending,
                        source_kind=PipelineSourceKind.UNSUPPORTED,
                    )
            else:
                pending = None
        line_index = next_line
        for heredoc_index, heredoc in enumerate(analysis.heredocs):
            body: list[str] = []
            line_map: list[tuple[int, int]] = []
            found_terminator = False
            while line_index < len(lines):
                physical = lines[line_index]
                candidate = physical.lstrip("\t") if heredoc.strip_tabs else physical
                if candidate == heredoc.delimiter:
                    found_terminator = True
                    line_index += 1
                    break
                if heredoc.strip_tabs:
                    stripped = len(physical) - len(physical.lstrip("\t"))
                    body.append(physical[stripped:])
                    line_map.append((line_index + 1, stripped))
                else:
                    body.append(physical)
                    line_map.append((line_index + 1, 0))
                line_index += 1
            if not found_terminator:
                errors.append(
                    Finding(
                        Location(
                            path,
                            heredoc.operator_line,
                            heredoc.operator_column,
                        ),
                        f"unterminated heredoc {heredoc.delimiter!r}",
                    )
                )
                return findings, errors
            selected = "\n".join(body) + ("\n" if body else "")
            trailing = analysis.trailing_pipeline
            if (
                trailing is not None
                and trailing.heredoc_index == heredoc_index
            ):
                original_line, original_column = positions[
                    min(trailing.position, len(positions) - 1)
                ]
                pending = PendingPipelineBody(
                    trailing.source_kind,
                    selected,
                    line_map,
                    Location(path, original_line, original_column),
                )
            elif heredoc.selected:
                found, broken = scan_python(selected, path, line_map)
                findings.extend(found)
                errors.extend(broken)
    if pending is not None:
        errors.append(
            Finding(
                pending.location,
                "pipeline is missing a downstream command",
            )
        )
    return findings, errors


def shebang_kind(first_line: bytes) -> str | None:
    if PYTHON_SHEBANG.search(first_line):
        return "python"
    if SHELL_SHEBANG.search(first_line):
        return "shell"
    return None


def scan_root(root: Path) -> ScanResult:
    result = ScanResult()
    root = root.resolve()
    selected: list[tuple[Path, str]] = []
    for directory_name in ("tests", "tools"):
        directory = root / directory_name
        if not directory.is_dir():
            result.errors.append(
                Finding(
                    Location(Path(directory_name), 1, 1),
                    "required scan directory is missing",
                )
            )
            continue
        try:
            paths = sorted(path for path in directory.rglob("*") if path.is_file())
        except OSError as exc:
            result.errors.append(
                Finding(
                    Location(Path(directory_name), 1, 1),
                    f"cannot walk scan directory: {exc}",
                )
            )
            continue
        for absolute in paths:
            relative = absolute.relative_to(root)
            try:
                with absolute.open("rb") as stream:
                    first_line = stream.readline()
            except OSError as exc:
                result.errors.append(
                    Finding(
                        Location(relative, 1, 1),
                        f"cannot inspect candidate unit: {exc}",
                    )
                )
                continue
            kind = shebang_kind(first_line)
            if kind is not None:
                selected.append((relative, kind))

    result.units = [path for path, _kind in selected]
    if not result.units:
        result.errors.append(
            Finding(
                Location(Path("."), 1, 1),
                "unit discovery selected zero scripts",
            )
        )
    elif len(result.units) < MIN_UNIT_COUNT:
        result.errors.append(
            Finding(
                Location(Path("."), 1, 1),
                f"unit discovery selected {len(result.units)} scripts; "
                f"expected at least {MIN_UNIT_COUNT}",
            )
        )
    if REQUIRED_UNIT not in result.units:
        result.errors.append(
            Finding(
                Location(REQUIRED_UNIT, 1, 1),
                "required extensionless shell unit was not selected",
            )
        )

    for relative, kind in selected:
        absolute = root / relative
        try:
            source = absolute.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            result.errors.append(
                Finding(
                    Location(relative, 1, 1),
                    f"cannot read selected unit as UTF-8: {exc}",
                )
            )
            continue
        if kind == "python":
            findings, errors = scan_python(source, relative)
        else:
            findings, errors = scan_shell(source, relative)
        result.findings.extend(findings)
        result.errors.extend(errors)

    result.findings.sort(
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.line,
            item.location.column,
            item.message,
        )
    )
    result.errors.sort(
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.line,
            item.location.column,
            item.message,
        )
    )
    return result


HISTORICAL_PYTHON_UNITS = (
    "tests/test-daemon-bearer-resolver-exports.py",
    "tests/test-daemon-bearer-resolver-structure.py",
    "tests/test-daemon-http-guards-structure.py",
    "tests/test-daemon-policy-write-authority-guard.py",
    "tests/test-daemon-startup-recovery-boundary.py",
    "tests/test-duckdb-after-walstart-boundary.py",
    "tests/test-duckdb-compile-swap.py",
    "tests/test-duckdb-fixed-wal-lifecycle-boundary.py",
    "tests/test-duckdb-source-codegen-boundary.py",
    "tests/test-duckdb-test-seam-wiring.py",
    "tests/test-fact-root-writer-lease-boundary.py",
    "tests/test-fact-store-pinned-boundary.py",
    "tests/test-human-refresh-single-flight-boundary.py",
    "tests/test-private-header-not-installed.py",
    "tests/test-secure-duckdb-ci-wiring.py",
    "tests/test-secure-duckdb-numeric-boundary.py",
    "tests/test-service-auth-registry-capability-boundary.py",
    "tests/test-service-exchange-audit-vectors.py",
    "tests/test-service-exchange-private-root-boundary.py",
    "tests/test-service-exchange-projector-boundary.py",
    "tests/test-service-exchange-shadow-boundary.py",
    "tests/test-service-session-private-boundary.py",
    "tools/check-client-exports.py",
    "tools/check-daemon-bearer-resolver-exports.py",
    "tools/check-daemon-bearer-resolver-structure.py",
    "tools/check-daemon-policy-write-authority.py",
    "tools/check-sccache-fallback.py",
    "tools/check-service-credential-escrow-issuer.py",
    "tools/check-service-exchange-audit-exports.py",
    "tools/check-service-handoff-delivery-boundary.py",
    "tools/check-service-session-private-boundary.py",
    "tools/check-service-session-private-exports.py",
    "tools/check-wyctl-operation-delegation.py",
)

HISTORICAL_SHELL_UNITS = (
    "tests/check-client-audit-daemon.sh",
    "tests/check-packaged-install-readiness.sh",
    "tests/check-wyctl-status-daemon.sh",
    "tests/check-wyrelogd-bootstrap-admin.sh",
    "tests/check-wyrelogd-conf-gate.sh",
    "tests/check-wyrelogd-datalog-product-flow.sh",
    "tests/check-wyrelogd-healthz.sh",
    "tests/check-wyrelogd-production-gates.sh",
    "tests/check-wyrelogd-profiles.sh",
    "tests/check-wyrelogd-startup-readiness.sh",
    "tools/check-format.sh",
    "tools/check-no-derived-fsm-replay.sh",
    "tools/check-private-headers-not-installed.sh",
    "tools/check-public-headers-no-novelty-tokens.sh",
    "tools/check-supply-chain-pins.sh",
    "tools/gst-indent",
    "tools/install-gnu-indent.sh",
    "tools/run-sanitizer-suite.sh",
    "tools/run-valgrind-gate.sh",
    "tools/setup-git-hooks.sh",
    "tools/test-format-tooling.sh",
    "tools/verify-template-release.sh",
)

HISTORICAL_DISTRIBUTION = {
    "tests/check-wyrelogd-bootstrap-admin.sh": 4,
    "tests/check-wyrelogd-startup-readiness.sh": 2,
    "tests/test-daemon-startup-recovery-boundary.py": 7,
    "tests/test-fact-root-writer-lease-boundary.py": 8,
    "tests/test-fact-store-pinned-boundary.py": 7,
    "tests/test-service-exchange-projector-boundary.py": 5,
}


def write_fixture(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def clean_unit_fixture(root: Path) -> None:
    for relative in HISTORICAL_PYTHON_UNITS:
        write_fixture(root, relative, "#!/usr/bin/env python3\n")
    for relative in HISTORICAL_SHELL_UNITS:
        write_fixture(root, relative, "#!/bin/sh\n")


def historical_fixture(root: Path) -> None:
    clean_unit_fixture(root)
    read_calls = {
        "tests/test-daemon-startup-recovery-boundary.py": 7,
        "tests/test-fact-root-writer-lease-boundary.py": 8,
        "tests/test-fact-store-pinned-boundary.py": 7,
        "tests/test-service-exchange-projector-boundary.py": 5,
    }
    for relative, count in read_calls.items():
        body = ["#!/usr/bin/env python3", "from pathlib import Path"]
        body.extend(
            f"Path('source-{index}').read_text()" for index in range(count)
        )
        write_fixture(root, relative, "\n".join(body) + "\n")

    write_fixture(
        root,
        "tests/check-wyrelogd-bootstrap-admin.sh",
        """#!/bin/sh
$PYTHON - <<'PY'
open("secret", "w")
open("token")
open("seed")
open("token", "w")
PY
""",
    )
    write_fixture(
        root,
        "tests/check-wyrelogd-startup-readiness.sh",
        """#!/bin/sh
${PYTHON} \\
  - <<P'Y'
from pathlib import Path
path = Path("decision.dl")
path.read_text()
path.write_text("text")
PY
""",
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fixture_case(
    root: Path,
    relative: str,
    source: str,
    expected_findings: int,
    expected_errors: int,
    label: str,
) -> ScanResult:
    clean_unit_fixture(root)
    write_fixture(root, relative, source)
    result = scan_root(root)
    require(
        len(result.findings) == expected_findings
        and len(result.errors) == expected_errors,
        f"{label}: expected F={expected_findings}/E={expected_errors}, "
        f"got F={len(result.findings)}/E={len(result.errors)}",
    )
    return result


def clean_control_source() -> str:
    return '''#!/usr/bin/env python3
import builtins as bi
import io as stream
import pathlib as pl
from pathlib import Path as P
from zipfile import ZipFile

open("binary", "wb")
open("text", encoding="ascii")
stream.open("text", "r", -1, "utf-8-sig")
bi.open("text", mode="r", encoding=get_codec())
Ctor = P
make = Ctor
path: pl.Path = make("root")
copy = path
child = copy / "child"
child.parent.resolve().joinpath("x").with_name("y").with_suffix(".z").open(
    encoding="utf-8"
)
reader = child.read_text
writer = child.write_text
reader("utf-8")
writer("data", "utf-8")
unbound = P.open
unbound(child, "r", -1, "utf-8")
for found in path.rglob("*"):
    found.read_text(encoding="utf-8")
texts = [found.read_text(encoding="utf-8") for found in path.glob("*")]
ZipFile("a.zip").open("member")

def shadowed(open):
    open("not-a-file")

def local_definition():
    def open(value):
        return value
    open("not-a-file")

def local_import():
    from zipfile import ZipFile as open
    open("not-a-file")

# open("comment")
embedded = """open("string")"""
dynamic = getattr(path, "read_text")
'''


def self_test() -> bool:
    try:
        require(
            len(HISTORICAL_PYTHON_UNITS) == 33
            and len(HISTORICAL_SHELL_UNITS) == 22,
            "historical unit inventory must remain exactly 33 Python + 22 shell",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            historical = scan_root(root)
            require(not historical.errors, "historical fixture must be structural")
            require(
                len(historical.units) == 55,
                "historical fixture must discover exactly 55 units",
            )
            require(
                len(historical.findings) == 33,
                "historical fixture must expose exactly 33 findings",
            )
            distribution: dict[str, int] = {}
            for finding in historical.findings:
                name = finding.location.path.as_posix()
                distribution[name] = distribution.get(name, 0) + 1
            require(
                distribution == HISTORICAL_DISTRIBUTION,
                f"historical distribution changed: {distribution!r}",
            )

            historical_fixture(root)
            write_fixture(
                root,
                "tests/test-daemon-startup-recovery-boundary.py",
                clean_control_source(),
            )
            for relative in HISTORICAL_DISTRIBUTION:
                if relative.endswith(".py") and relative != (
                    "tests/test-daemon-startup-recovery-boundary.py"
                ):
                    write_fixture(
                        root, relative, "#!/usr/bin/env python3\n"
                    )
                elif relative.endswith(".sh"):
                    write_fixture(root, relative, "#!/bin/sh\n")
            write_fixture(
                root,
                "tests/check-wyrelogd-bootstrap-admin.sh",
                """#!/bin/sh
# $PYTHON <<NO
echo 'python <<NO'
cat <<'DATA' <<-D\\A'TA2'
not python: open("ignored")
DATA
\tnot python either: open("ignored")
\tDATA2
python3 - <<'PY'
open("binary", "ab")
open("text", encoding="latin-1")
from pathlib import Path
Path("x").write_text("x", encoding=codec)
PY
""",
            )
            clean = scan_root(root)
            require(
                not clean.findings and not clean.errors,
                "negative controls must scan clean",
            )

            write_fixture(
                root,
                "tests/test-daemon-startup-recovery-boundary.py",
                """#!/usr/bin/env python3
import io
from builtins import open as builtin_reader
from pathlib import Path

mode = choose_mode()
open("dynamic", mode)
io.open("none", encoding=None)
alias = builtin_reader
alias("alias")
path = Path("x").absolute()
path.open()
Path.read_text(path)
Path.write_text(path, "x")
""",
            )
            dirty = scan_root(root)
            require(
                len(dirty.findings) == 6 and not dirty.errors,
                "positive Python controls must expose six findings",
            )

            write_fixture(
                root,
                "tests/test-daemon-startup-recovery-boundary.py",
                """#!/usr/bin/env python3
from pathlib import Path
callback = Path("x").read_text
consume(callback)
""",
            )
            escaped = scan_root(root)
            require(
                len(escaped.errors) == 1
                and "escapes static analysis" in escaped.errors[0].message,
                "protected callable escape must fail closed at its use",
            )

            write_fixture(
                root,
                "tests/test-daemon-startup-recovery-boundary.py",
                "#!/usr/bin/env python3\n",
            )
            write_fixture(
                root,
                "tests/check-wyrelogd-startup-readiness.sh",
                """#!/bin/sh
python \\
  - <<-P\\Y
\tfrom pathlib import Path
\tPath("x").read_text()
\tPY
""",
            )
            shell_dirty = scan_root(root)
            require(
                len(shell_dirty.findings) == 1
                and shell_dirty.findings[0].location.line == 5
                and shell_dirty.findings[0].location.column == 2,
                "shell diagnostic must retain original one-based location",
            )

            invalid = root / HISTORICAL_PYTHON_UNITS[0]
            invalid.write_bytes(b"#!/usr/bin/env python3\n\xff\n")
            invalid_result = scan_root(root)
            require(
                any("UTF-8" in item.message for item in invalid_result.errors),
                "invalid UTF-8 must fail closed",
            )

            python_cases = (
                (
                    "if keeps pre-branch callable",
                    """op = open
if condition:
    op = harmless
op("x")
""",
                    1,
                    0,
                ),
                (
                    "if joins protected and harmless branches",
                    """if condition:
    op = open
else:
    op = harmless
op("x")
""",
                    1,
                    0,
                ),
                (
                    "while keeps zero-iteration callable",
                    """op = open
while condition:
    op = harmless
op("x")
""",
                    1,
                    0,
                ),
                (
                    "for keeps zero-iteration callable",
                    """op = open
for item in items:
    op = harmless
op("x")
""",
                    1,
                    0,
                ),
                (
                    "for reaches a multi-iteration callable fixed point",
                    """op = harmless
for item in items:
    previous = op
    op = open
    previous("x")
""",
                    1,
                    0,
                ),
                (
                    "while reaches a multi-iteration callable fixed point",
                    """op = harmless
while condition:
    previous = op
    op = open
    previous("x")
""",
                    1,
                    0,
                ),
                (
                    "try keeps normal-path callable",
                    """op = open
try:
    risky()
except Exception:
    op = harmless
op("x")
""",
                    1,
                    0,
                ),
                (
                    "try keeps pre-assignment exception callable",
                    """op = open
try:
    op = harmless
except Exception:
    pass
op("x")
""",
                    1,
                    0,
                ),
                (
                    "try keeps intermediate exception callable",
                    """op = harmless
try:
    op = open
    risky()
    op = harmless
except Exception:
    pass
op("x")
""",
                    1,
                    0,
                ),
                (
                    "try keeps nested intermediate exception callable",
                    """op = harmless
try:
    if condition:
        op = open
        risky()
        op = harmless
except Exception:
    pass
op("x")
""",
                    1,
                    0,
                ),
                (
                    "method skips class open binding",
                    """class Example:
    open = harmless
    def method(self):
        open("x")
""",
                    1,
                    0,
                ),
                (
                    "method does not capture class callable alias",
                    """class Example:
    op = open
    def method(self):
        op("x")
""",
                    0,
                    0,
                ),
                (
                    "class body still scans callable alias",
                    """class Example:
    op = open
    op("x")
""",
                    1,
                    0,
                ),
                (
                    "global declaration resolves before assignment",
                    """op = open
def function():
    global op
    op("x")
    op = harmless
""",
                    1,
                    0,
                ),
                (
                    "nonlocal declaration resolves before assignment",
                    """def outer():
    op = open
    def inner():
        nonlocal op
        op("x")
        op = harmless
""",
                    1,
                    0,
                ),
                (
                    "future closure binding is visible to nested body",
                    """def outer():
    def inner():
        op("x")
    op = open
    inner()
""",
                    1,
                    0,
                ),
                (
                    "future global binding is visible to deferred body",
                    """def function():
    global op
    op("x")
    op = open
function()
""",
                    1,
                    0,
                ),
                (
                    "future global import is visible to deferred body",
                    """def function():
    global op
    op("x")
from builtins import open as op
function()
""",
                    1,
                    0,
                ),
                (
                    "future import is visible to nested closure",
                    """def outer():
    def inner():
        op("x")
    from builtins import open as op
    inner()
""",
                    1,
                    0,
                ),
                (
                    "future Path import and value reach deferred body",
                    """def function():
    path.read_text()
from pathlib import Path
path = Path("x")
function()
""",
                    1,
                    0,
                ),
                (
                    "future module imports feed alias fixed point",
                    """def function():
    path.read_text()
import pathlib as paths
path = paths.Path("x")
function()
""",
                    1,
                    0,
                ),
                (
                    "future Path annotation reaches deferred body",
                    """def function():
    path.read_text()
path: Path = make_path()
from pathlib import Path
function()
""",
                    1,
                    0,
                ),
                (
                    "future mapping annotation reaches deferred body",
                    """def function():
    for path in mapping.values():
        path.read_text()
mapping: dict[str, Path] = make_mapping()
from pathlib import Path
function()
""",
                    1,
                    0,
                ),
                (
                    "future non-Path annotation stays clean",
                    """def function():
    value.read_text()
value: str = make_value()
function()
""",
                    0,
                    0,
                ),
                (
                    "IfExp identical callable aliases deduplicate",
                    """op = open if condition else open
op("x")
""",
                    1,
                    0,
                ),
                (
                    "IfExp mixed callable aliases do not escape",
                    """from pathlib import Path
op = open if condition else Path.open
op("x")
""",
                    2,
                    0,
                ),
                (
                    "protected call still scans Path receiver",
                    """from pathlib import Path
Path(open("x")).read_text(encoding="utf-8")
""",
                    1,
                    0,
                ),
                (
                    "protected call still scans encoding argument",
                    """from pathlib import Path
path = Path("x")
path.read_text(encoding=choose(open))
""",
                    0,
                    1,
                ),
                (
                    "Path collection is not a Path value",
                    """from pathlib import Path
paths: list[Path]
paths.read_text()
""",
                    0,
                    0,
                ),
                (
                    "Path collection loop target is a Path",
                    """from pathlib import Path
paths: list[Path]
for path in paths:
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "assigned generator and next preserve Path",
                    """from pathlib import Path
root = Path("x")
paths = (path for path in root.glob("*"))
next(paths).read_text()
""",
                    1,
                    0,
                ),
                (
                    "iter and next preserve Path",
                    """from pathlib import Path
paths = iter(Path(".").glob("*"))
next(paths).read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict Path values are not Path keys",
                    """from pathlib import Path
mapping: dict[str, Path]
mapping.read_text()
""",
                    0,
                    0,
                ),
                (
                    "dict Path keys propagate through iteration",
                    """from pathlib import Path
mapping: dict[Path, str]
for path in mapping:
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict Path values propagate through values",
                    """from pathlib import Path
mapping: dict[str, Path]
for path in mapping.values():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict Path keys propagate through keys",
                    """from pathlib import Path
mapping: dict[Path, str]
for path in mapping.keys():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict literal Path keys propagate through iteration",
                    """from pathlib import Path
mapping = {Path("x"): "value"}
for path in mapping:
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict non-Path values stay clean",
                    """from pathlib import Path
mapping: dict[Path, str]
for value in mapping.values():
    value.read_text()
""",
                    0,
                    0,
                ),
                (
                    "dict items propagate Path values",
                    """from pathlib import Path
mapping: dict[str, Path]
for key, path in mapping.items():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict items propagate Path keys",
                    """from pathlib import Path
mapping: dict[Path, str]
for path, value in mapping.items():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict items keep non-Path values clean",
                    """from pathlib import Path
mapping: dict[Path, str]
for path, value in mapping.items():
    value.read_text()
""",
                    0,
                    0,
                ),
                (
                    "dict subscript mutation propagates Path values",
                    """from pathlib import Path
mapping = {}
mapping["x"] = Path("x")
for path in mapping.values():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict subscript mutation keeps string values clean",
                    """from pathlib import Path
mapping = {}
mapping[Path("x")] = "value"
for value in mapping.values():
    value.read_text()
""",
                    0,
                    0,
                ),
                (
                    "dict comprehension propagates Path values",
                    """from pathlib import Path
mapping = {name: Path(name) for name in names}
for path in mapping.values():
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict comprehension propagates Path keys",
                    """from pathlib import Path
mapping = {Path(name): name for name in names}
for path in mapping:
    path.read_text()
""",
                    1,
                    0,
                ),
                (
                    "dict comprehension keeps string keys clean",
                    """mapping = {name: "value" for name in names}
for name in mapping:
    name.read_text()
""",
                    0,
                    0,
                ),
                (
                    "comprehension target is a Path",
                    """from pathlib import Path
root = Path("x")
texts = [path.read_text() for path in root.rglob("*")]
""",
                    1,
                    0,
                ),
                (
                    "Path cwd and return methods preserve Path",
                    """from pathlib import Path
Path.cwd().expanduser().rename("x").replace("y").read_text()
""",
                    1,
                    0,
                ),
                (
                    "Path home preserves Path",
                    """from pathlib import Path
Path.home().read_text()
""",
                    1,
                    0,
                ),
                (
                    "branch join preserves Path provenance",
                    """from pathlib import Path
path = Path("x")
if condition:
    path = unknown
path.read_text()
""",
                    1,
                    0,
                ),
            )
            python_unit = HISTORICAL_PYTHON_UNITS[0]
            for label, source, findings, errors in python_cases:
                fixture_case(
                    root,
                    python_unit,
                    "#!/usr/bin/env python3\n" + source,
                    findings,
                    errors,
                    label,
                )

            shell_cases = (
                (
                    "absolute Python executable",
                    """/usr/bin/python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "versioned Python executable",
                    """python3.12 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "env unset wrapper",
                    """env -u PYTHONWARNINGS python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "exec wrapper",
                    """exec python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "script source ignores heredoc",
                    """python3 script.py <<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "command source ignores heredoc",
                    """python3 -c pass <<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "interactive command continues with stdin",
                    """python3 -i -c pass <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "interactive module continues with stdin",
                    """python3 -i -m module <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "interactive script continues with stdin",
                    """python3 -i script.py <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "attached interactive command continues with stdin",
                    """python3 -icpass <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "module source ignores heredoc",
                    """python3 -m module <<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "implicit interactive source reads heredoc",
                    """python3 <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "implicit stdin after Python option",
                    """python3 -q <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "implicit stdin after option terminator",
                    """python3 -- <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "command wrapper options preserve executable",
                    """command -p python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "command option terminator preserves executable",
                    """command -- python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "env chdir wrapper preserves executable",
                    """env -C /tmp python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "exec argv0 wrapper preserves executable",
                    """exec -a py python3 - <<PY
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "Python help does not consume stdin",
                    """python3 --help <<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "Python version does not consume stdin",
                    """python3 -V <<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "unknown Python option fails closed",
                    """python3 -Z <<PY
open("x")
PY
""",
                    0,
                    1,
                ),
                (
                    "pipeline producer feeds Python stdin",
                    """cat <<PY | python3 -
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "explicit cat stdin feeds Python stdin",
                    """cat - <<PY | python3 -
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "stderr pipeline operator fails closed",
                    """cat <<PY |& python3 -
open("x")
PY
""",
                    0,
                    1,
                ),
                (
                    "non-passthrough pipeline producer is ignored",
                    """true <<PY | python3 -
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "redirected cat does not feed pipeline",
                    """cat <<PY >/dev/null | python3 -
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "physical downstream command receives cat heredoc",
                    """cat <<PY |
open("x")
PY
python3 -
""",
                    1,
                    0,
                ),
                (
                    "physical multi-stage pipeline fails closed",
                    """cat <<PY |
open("x")
PY
tee |
python3 -
""",
                    0,
                    1,
                ),
                (
                    "unsupported pipeline source fails closed",
                    """sed <<PY | python3 -
open("x")
PY
""",
                    0,
                    1,
                ),
                (
                    "unsupported multi-stage pipeline fails closed",
                    """cat <<PY | tee | python3 -
open("x")
PY
""",
                    0,
                    1,
                ),
                (
                    "non-stdin descriptor heredoc is ignored",
                    """python3 - 3<<PY
open("x")
PY
""",
                    0,
                    0,
                ),
                (
                    "last stdin heredoc wins clean",
                    """python3 - <<OLD <<PY
open("x")
OLD
open("x", encoding="utf-8")
PY
""",
                    0,
                    0,
                ),
                (
                    "last stdin heredoc wins dirty",
                    """python3 - <<OLD <<PY
open("x", encoding="utf-8")
OLD
open("x")
PY
""",
                    1,
                    0,
                ),
                (
                    "unsupported input syntax fails closed",
                    """python3 - <<<'open("x")'
""",
                    0,
                    1,
                ),
            )
            shell_unit = HISTORICAL_SHELL_UNITS[0]
            for label, source, findings, errors in shell_cases:
                fixture_case(
                    root,
                    shell_unit,
                    "#!/bin/sh\n" + source,
                    findings,
                    errors,
                    label,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tests").mkdir()
            (root / "tools").mkdir()
            zero = scan_root(root)
            require(
                any("zero scripts" in item.message for item in zero.errors),
                "zero-unit discovery must fail",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            (root / HISTORICAL_PYTHON_UNITS[0]).unlink()
            floor = scan_root(root)
            require(
                any("expected at least" in item.message for item in floor.errors),
                "unit-count floor must fail",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            (root / REQUIRED_UNIT).unlink()
            missing = scan_root(root)
            require(
                any(
                    "required extensionless" in item.message
                    for item in missing.errors
                ),
                "missing required unit must fail",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            write_fixture(root, REQUIRED_UNIT.as_posix(), "# no shebang\n")
            unselected = scan_root(root)
            require(
                any(
                    "required extensionless" in item.message
                    for item in unselected.errors
                ),
                "unselected required unit must fail",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            write_fixture(
                root,
                HISTORICAL_SHELL_UNITS[0],
                "#!/bin/sh\npython3 - <<'PY'\nopen('x')\n",
            )
            unterminated = scan_root(root)
            require(
                any("unterminated heredoc" in item.message for item in unterminated.errors),
                "selected missing heredoc terminator must fail",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            historical_fixture(root)
            write_fixture(
                root,
                HISTORICAL_SHELL_UNITS[0],
                "#!/bin/sh\npython3 - <<'PY'\nif (\nPY\n",
            )
            syntax = scan_root(root)
            require(
                any("cannot parse selected Python" in item.message for item in syntax.errors),
                "selected heredoc syntax error must fail",
            )
    except AssertionError as exc:
        print(f"explicit-encoding self-test: {exc}", file=sys.stderr)
        return False
    print("explicit-encoding self-test: OK")
    return True


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return 0 if self_test() else 1
    if len(argv) != 1:
        print(
            "usage: check-explicit-encoding.py ROOT | --self-test",
            file=sys.stderr,
        )
        return 2

    result = scan_root(Path(argv[0]))
    for item in result.findings:
        print(item.render())
    for item in result.errors:
        print(f"{item.render()}: structural error", file=sys.stderr)
    if result.failed:
        return 1
    print(
        f"explicit-encoding: OK ({len(result.units)} script units)",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
