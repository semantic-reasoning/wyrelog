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
from dataclasses import dataclass, field
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

BUILTIN_OPEN = CallableValue("open", 1, 3)
BOUND_PATH_OPEN = CallableValue("Path.open", 0, 2)
UNBOUND_PATH_OPEN = CallableValue("Path.open", 1, 3)
BOUND_READ_TEXT = CallableValue("Path.read_text", None, 0)
UNBOUND_READ_TEXT = CallableValue("Path.read_text", None, 1)
BOUND_WRITE_TEXT = CallableValue("Path.write_text", None, 1)
UNBOUND_WRITE_TEXT = CallableValue("Path.write_text", None, 2)


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


class LocalBindingCollector(ast.NodeVisitor):
    """Collect names whose presence makes a function name local."""

    def __init__(self) -> None:
        self.names: set[str] = set()

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


class PythonScanner(ast.NodeVisitor):
    PATH_METHODS = {
        "resolve",
        "absolute",
        "joinpath",
        "with_name",
        "with_suffix",
    }
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
        self.scopes = [Scope({}, set())]

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
        for scope in reversed(self.scopes):
            if name in scope.values:
                return scope.values[name]
            if name in scope.local_names:
                return UNKNOWN
        if name == "open":
            return BUILTIN_OPEN
        return UNKNOWN

    def bind(self, name: str, value: object) -> None:
        self.scopes[-1].values[name] = value
        self.scopes[-1].local_names.add(name)

    def bind_target(self, target: ast.AST, value: object) -> bool:
        if isinstance(target, ast.Name):
            self.bind(target.id, value)
            return True
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, CallableValue):
                return False
            for item in target.elts:
                self.bind_target(item, UNKNOWN)
            return True
        if isinstance(target, ast.Starred):
            if isinstance(value, CallableValue):
                return False
            return self.bind_target(target.value, UNKNOWN)
        return not isinstance(value, CallableValue)

    def value(self, node: ast.AST | None) -> object:
        if node is None:
            return UNKNOWN
        if isinstance(node, ast.Name):
            return self.resolve(node.id)
        if isinstance(node, ast.Attribute):
            owner = self.value(node.value)
            if owner in {BUILTINS_MODULE, IO_MODULE} and node.attr == "open":
                return BUILTIN_OPEN
            if owner is PATH_CLASS:
                return {
                    "open": UNBOUND_PATH_OPEN,
                    "read_text": UNBOUND_READ_TEXT,
                    "write_text": UNBOUND_WRITE_TEXT,
                }.get(node.attr, UNKNOWN)
            if owner is PATH_VALUE:
                if node.attr == "parent":
                    return PATH_VALUE
                return {
                    "open": BOUND_PATH_OPEN,
                    "read_text": BOUND_READ_TEXT,
                    "write_text": BOUND_WRITE_TEXT,
                }.get(node.attr, UNKNOWN)
            if owner is PATHLIB_MODULE and node.attr == "Path":
                return PATH_CLASS
            return UNKNOWN
        if isinstance(node, ast.Call):
            callable_value = self.value(node.func)
            if callable_value is PATH_CLASS:
                return PATH_VALUE
            if isinstance(node.func, ast.Attribute):
                owner = self.value(node.func.value)
                if owner is PATH_VALUE and node.func.attr in self.PATH_METHODS:
                    return PATH_VALUE
                if (
                    owner is PATH_VALUE
                    and node.func.attr in self.PATH_ITERATORS
                ):
                    return PATH_ITERABLE
            return UNKNOWN
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if self.value(node.left) is PATH_VALUE:
                return PATH_VALUE
        if isinstance(node, ast.IfExp):
            left = self.value(node.body)
            right = self.value(node.orelse)
            if left is right:
                return left
        return UNKNOWN

    def annotation_is_path(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if self.value(node) is PATH_CLASS:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value in {"Path", "pathlib.Path"}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return self.annotation_is_path(node.left) or self.annotation_is_path(
                node.right
            )
        if isinstance(node, ast.Subscript):
            return self.annotation_is_path(node.slice)
        return False

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
        if isinstance(node, ast.Call):
            callable_value = self.value(node.func)
            if isinstance(callable_value, CallableValue):
                self.check_encoding_call(node, callable_value)
            else:
                self.scan_expression(node.func)
            for arg in node.args:
                self.scan_expression(arg)
            for item in node.keywords:
                self.scan_expression(item.value)
            return
        if isinstance(node, (ast.Name, ast.Attribute)):
            node_value = self.value(node)
            if isinstance(node_value, CallableValue) and not allow_top_callable:
                self.error(
                    node,
                    f"protected callable {node_value.name} escapes static "
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
        allow = isinstance(assigned, CallableValue)
        self.scan_expression(node.value, allow_top_callable=allow)
        for target in node.targets:
            if not self.bind_target(target, assigned):
                self.error(
                    target,
                    f"protected callable {assigned.name} must be assigned "
                    "only to simple names",
                )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        assigned = self.value(node.value)
        if self.annotation_is_path(node.annotation):
            assigned = PATH_VALUE
        allow = isinstance(assigned, CallableValue)
        self.scan_expression(node.value, allow_top_callable=allow)
        if not self.bind_target(node.target, assigned):
            self.error(
                node.target,
                f"protected callable {assigned.name} must be assigned only "
                "to a simple name",
            )

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.scan_expression(node.target)
        self.scan_expression(node.value)
        self.bind_target(node.target, UNKNOWN)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        assigned = self.value(node.value)
        allow = isinstance(assigned, CallableValue)
        self.scan_expression(node.value, allow_top_callable=allow)
        if not self.bind_target(node.target, assigned):
            self.error(
                node.target,
                f"protected callable {assigned.name} must be assigned only "
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
            elif node.module == "pathlib" and item.name == "Path":
                self.bind(name, PATH_CLASS)
            else:
                self.bind(name, UNKNOWN)

    def function_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Scope:
        collector = LocalBindingCollector()
        for statement in node.body:
            collector.visit(statement)
        values = {name: UNKNOWN for name in collector.names}
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
            values[argument.arg] = (
                PATH_VALUE
                if self.annotation_is_path(argument.annotation)
                else UNKNOWN
            )
            collector.names.add(argument.arg)
        return Scope(values, collector.names)

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
        self.scopes.append(self.function_scope(node))
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

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
        self.scopes.append(Scope(values, names))
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
        self.scopes.append(Scope({}, set()))
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def visit_If(self, node: ast.If) -> None:
        self.scan_expression(node.test)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_While(self, node: ast.While) -> None:
        self.scan_expression(node.test)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.scan_expression(node.iter)
        element = (
            PATH_VALUE if self.value(node.iter) is PATH_ITERABLE else UNKNOWN
        )
        self.bind_target(node.target, element)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

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
        for statement in node.body:
            self.visit(statement)
        for handler in node.handlers:
            if handler.type is not None:
                self.scan_expression(handler.type)
            if handler.name is not None:
                self.bind(handler.name, UNKNOWN)
            for statement in handler.body:
                self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
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
        self.scopes.append(Scope({}, set()))
        for generator in node.generators:
            self.scan_expression(generator.iter)
            element = (
                PATH_VALUE
                if self.value(generator.iter) is PATH_ITERABLE
                else UNKNOWN
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

    visit_ListComp = visit_comprehension_expression
    visit_SetComp = visit_comprehension_expression
    visit_GeneratorExp = visit_comprehension_expression
    visit_DictComp = visit_comprehension_expression


@dataclass(frozen=True)
class HereDoc:
    delimiter: str
    strip_tabs: bool
    python: bool
    operator_line: int
    operator_column: int


@dataclass(frozen=True)
class ShellWord:
    value: str
    start: int
    end: int


def shell_word(command: str, start: int) -> tuple[str, int]:
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
    return "".join(output), index


def command_is_python(words: list[ShellWord], position: int) -> bool:
    separators = {";", "&&", "||", "|", "&", "(", ")"}
    start = 0
    for word in words:
        if word.end <= position and word.value in separators:
            start = word.end
    segment = [
        word.value
        for word in words
        if start <= word.start < position and word.value not in separators
    ]
    reserved = {"if", "then", "elif", "while", "until", "do", "!", "command"}
    while segment and (
        segment[0] in reserved
        or ("=" in segment[0] and not segment[0].startswith("="))
    ):
        segment.pop(0)
    if segment and segment[0] == "env":
        segment.pop(0)
        while segment and (
            segment[0].startswith("-")
            or ("=" in segment[0] and not segment[0].startswith("="))
        ):
            segment.pop(0)
    return bool(
        segment
        and segment[0] in {"$PYTHON", "${PYTHON}", "python", "python3"}
    )


def lex_shell_command(
    command: str,
    positions: list[tuple[int, int]],
) -> list[HereDoc]:
    words: list[ShellWord] = []
    operators: list[tuple[int, bool, str, int]] = []
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
            words.append(ShellWord(command[index : index + 2], index, index + 2))
            index += 2
            continue
        if char in ";|&()":
            words.append(ShellWord(char, index, index + 1))
            index += 1
            continue
        if command.startswith("<<", index) and not command.startswith(
            "<<<", index
        ):
            operator = index
            index += 2
            strip_tabs = False
            if index < len(command) and command[index] == "-":
                strip_tabs = True
                index += 1
            while index < len(command) and command[index] in " \t":
                index += 1
            delimiter, end = shell_word(command, index)
            if delimiter:
                operators.append((operator, strip_tabs, delimiter, end))
                index = end
                continue
        value, end = shell_word(command, index)
        if end == index:
            index += 1
            continue
        words.append(ShellWord(value, index, end))
        index = end

    heredocs: list[HereDoc] = []
    for operator, strip_tabs, delimiter, _end in operators:
        line, column = positions[operator]
        heredocs.append(
            HereDoc(
                delimiter,
                strip_tabs,
                command_is_python(words, operator),
                line,
                column,
            )
        )
    return heredocs


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
    return scanner.findings, scanner.errors


def scan_shell(
    source: str, path: Path
) -> tuple[list[Finding], list[Finding]]:
    lines = source.splitlines()
    findings: list[Finding] = []
    errors: list[Finding] = []
    line_index = 0
    while line_index < len(lines):
        command, positions, next_line = continued_shell_command(
            lines, line_index
        )
        heredocs = lex_shell_command(command, positions)
        line_index = next_line
        for heredoc in heredocs:
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
            if heredoc.python:
                selected = "\n".join(body) + ("\n" if body else "")
                found, broken = scan_python(selected, path, line_map)
                findings.extend(found)
                errors.extend(broken)
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


def historical_fixture(root: Path) -> None:
    for relative in HISTORICAL_PYTHON_UNITS:
        write_fixture(root, relative, "#!/usr/bin/env python3\n")
    for relative in HISTORICAL_SHELL_UNITS:
        write_fixture(root, relative, "#!/bin/sh\n")

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
