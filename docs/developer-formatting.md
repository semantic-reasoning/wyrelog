# C formatting

Wyrelog's authoritative C formatter is GNU indent 2.2.13 through
`tools/gst-indent`. The exact version matters: older GNU indent releases do
not produce the same output for this tree.

## Install the formatter

If the system package supplies exactly version 2.2.13, install it normally.
Homebrew currently provides it as `gnu-indent`, with the executable named
`gindent`.

The repository also provides a source installer for POSIX development hosts.
It downloads the GNU 2.2.13 release archive, verifies the pinned SHA-256
digest, builds it, and installs beneath an explicit absolute prefix:

```sh
./tools/install-gnu-indent.sh /absolute/path/to/format-tools
export PATH="/absolute/path/to/format-tools/bin:$PATH"
./tools/gst-indent --check-version
```

The installer requires Python 3, creates the requested prefix, resolves it with
physical filesystem semantics, rejects a canonical prefix of `/`, and uses
only that canonical path for configure, installation, and version
verification. A symlink at the requested prefix itself is rejected, including
a non-root symlink and one written with trailing `/`. Symlinks in ancestor
components are allowed so conventional paths such as macOS `/tmp` remain
usable; their physical target is reflected in the canonical installation path.

GNU indent 2.2.13's upstream Autoconf and Make recipes do not safely preserve
shell metacharacters in an installation prefix. Both the requested path and
its physical canonical path must therefore contain only ASCII letters, digits,
`/`, `.`, `_`, `+`, and `-`. This also excludes all whitespace.

The expected output is:

```text
GNU indent 2.2.13
```

## Format and check

Format a file in place:

```sh
./tools/gst-indent path/to/file.c
```

Check every tracked C source and header without changing the worktree:

```sh
./tools/check-format.sh --all
```

The formatter runs twice because the inherited GStreamer-style GNU indent
contract requires two passes. The checked-in tree must be unchanged after
that complete formatting operation.

## Committed pre-commit hook

Run the idempotent setup helper, or run `meson setup`, once after cloning:

```sh
./tools/setup-git-hooks.sh
```

Run the helper from the root of the same worktree that contains it. It refuses
to change Git configuration when the caller and script resolve to different
repository roots, or when an unpacked source directory merely happens to be
nested below another Git repository. Meson applies the same physical
source-root versus Git-top-level check before invoking it.

The helper sets the repository-local value `core.hooksPath=hooks`. Git resolves
that relative path from the active worktree, so each linked worktree executes
the executable `hooks/pre-commit` file committed on its checked-out branch.
The checker also requires the hook and formatting authority scripts to have
committed index mode `100755`. There is no copied `.git/hooks/pre-commit` file
to become stale.

Repository-local Git configuration is shared by linked worktrees, so activating
`core.hooksPath=hooks` affects all of them immediately. A worktree on a commit
or branch from before the committed hook was introduced has no gate until it
is updated or rebased. The setup helper inspects every listed worktree and
prints an explicit warning with the escaped worktree path when
`hooks/pre-commit` is missing or is not executable. Warnings for other
worktrees do not block setup; the invoking worktree's hook remains a required
precondition and fails setup when absent. Paths containing spaces remain
readable; the exceptional case of an embedded newline is rendered as
`byte-hex:` followed by the path bytes so one warning stays on one line.

The hook materializes the checker and formatter from index blobs, so unstaged
source, checker, and formatter changes cannot affect its result. Git chooses
the worktree hook before the script can inspect the index, so the committed
hook intentionally remains a small launcher and is covered by a behavior
test. Ordinarily the checker examines staged C and header files. When the
formatter, checker, pinned installer, or hook itself changes, it checks every
C and header blob in the prospective index to prevent a tooling-only commit
from invalidating the rest of the tree.

Failures distinguish a missing formatter, an incompatible version, an
unformatted tracked tree, and unformatted staged content.
