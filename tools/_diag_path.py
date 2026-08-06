"""Shared ASCII-safe single-line source-identity renderer extracted from the #750 engine checker, consumed by all structural checkers; escaping is message-only and must stay byte-stable."""

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath, PurePosixPath, PureWindowsPath


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


def native_path_flavor(path: PurePath) -> PathFlavor | None:
    """Return a path object's native flavor without inspecting its spelling."""
    if isinstance(path, PureWindowsPath):
        return PathFlavor.WINDOWS
    if isinstance(path, PurePosixPath):
        return PathFlavor.POSIX
    return None


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
