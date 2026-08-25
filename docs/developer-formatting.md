# C formatting

Wyrelog's authoritative C formatter is Uncrustify 0.83.0 through
`tools/format-c`, configured by `tools/uncrustify.cfg`. The exact version
matters: formatter releases change their output, and this repository's contract
is that migrated files are exact fixed points.

## Migration state

The tree is part-way through a migration from GNU indent 2.2.13 to Uncrustify.
Uncrustify cannot reproduce GNU indent's continuation-indent model for wrapped
declarations, so the two formatters disagree about roughly 80% of the tracked C
files. Rather than rewrite them all at once, the migration is incremental:

- `tools/formatted-files.txt` is the ledger of files already migrated.
- Every ledger entry must be an exact fixed point of the pinned formatter.
- Any C file a change touches must be formatted and added to the ledger.

The migrated set therefore only grows, and touching a file is what migrates it.
Files nobody edits stay in their old formatting until someone does.

## Install the formatter

The repository provides a source installer for POSIX development hosts. It
downloads the pinned release archive, verifies its SHA-256 digest, builds it
with CMake, and installs beneath an explicit absolute prefix:

```sh
./tools/install-uncrustify.sh /absolute/path/to/format-tools
export PATH="/absolute/path/to/format-tools/bin:$PATH"
./tools/format-c --check-version
```

The installer requires `curl`, `cmake`, and `tar`. It rejects a relative
prefix and a symlink at the requested prefix itself, including one written with
a trailing `/`, and it validates the prefix before running any download or
build command so a rejected prefix leaves no side effects. Symlinks in ancestor
components remain allowed so conventional paths such as macOS `/tmp` stay
usable.

On Windows, the upstream project publishes a prebuilt binary
(`uncrustify-0.83.0_f-win64.zip`) which avoids needing a toolchain locally.

The expected output is:

```text
Uncrustify-0.83.0_f
```

## Format and check

Format a file in place, then record it in the ledger:

```sh
./tools/format-c path/to/file.c
# add path/to/file.c to tools/formatted-files.txt, keeping the file sorted
```

Check the files a change touches, plus every migrated file:

```sh
./tools/check-format.sh --changed origin/main
```

Check only the migrated set:

```sh
./tools/check-format.sh --ledger
```

Check the prospective index, as the pre-commit hook does:

```sh
./tools/check-format.sh --staged
```

The formatter runs twice per file. Uncrustify is single-pass, but the contract
being enforced is that a file is a fixed point, and a second pass is what
demonstrates the first converged rather than assuming it.

### Multi-line block comments

Continuation stars in a block comment align with the star in the opening
`/*`. For example:

```c
  /* The first line introduces the comment and continues below.
   * The continuation star remains aligned with the opening star. */
```

Uncrustify 0.83.0's default `cmt_indent_multi` behavior can violate that rule.
For a long comment with at least two star-prefixed lines after the opener, with
the last of those lines ending in an inline `*/`, it can move correctly aligned
continuation stars one column left. The misaligned result is itself a fixed
point, so running the formatter twice does not detect the problem.

The defect was initially observed through two prose-sensitive effects:
shortening either the first or last line could preserve alignment, and removing
an apostrophe from one larger comment could do the same. Those observations
helped isolate the formatter behavior, but neither is a general rule. A smaller
reproduction showed that absolute line width is not the trigger: long text,
multiple continuation lines, and an inline closing delimiter are the relevant
shape. Putting `*/` on its own line or shortening the comment was a workable
pre-fix escape hatch.

Wyrelog pins `cmt_indent_multi = false` so the correctly aligned form is the
authoritative fixed point. `tools/test-format-tooling.sh` embeds the exact
nine-line reproduction and checks both directions:

```sh
./tools/test-format-tooling.sh
```

The test requires the repository configuration to preserve the canonical
fixture byte for byte. It also removes exactly that one option in a temporary
configuration, runs the same pinned Uncrustify binary successfully, and
requires the historical rewrite to reappear. That negative control invokes
Uncrustify directly because `tools/format-c` intentionally always binds the
repository's `tools/uncrustify.cfg`.

`--ledger` and `--changed` re-verify the whole migrated set, which is what
catches a formatter or configuration change: altering `tools/uncrustify.cfg`
without reformatting the ledger fails CI. `--staged` deliberately does not scan
the whole ledger, because it runs on every commit and that cost grows with the
ledger; CI carries the exhaustive check instead.

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
hook intentionally remains a small launcher and is covered by a behavior test.

Failures distinguish a missing formatter, an incompatible version, a changed
file that has not been migrated, an invalid ledger, and content that is not a
fixed point.
