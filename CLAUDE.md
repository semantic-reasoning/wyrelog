# wyrelog - Claude Code Project Configuration

## Git Commit Configuration

**Important**: wyrelog commits should NOT include Co-Authored-By information.

When committing to this project:
- Do NOT add "Co-Authored-By: Claude" lines
- Commit message format should be clean author attribution only
- Do NOT use emojis in commit messages (clean text only)

### Reason
wyrelog is a professional open-source project with dual licensing (GPL-3.0-or-later and commercial).
Commit messages should be professional and emoji-free.

## Development Methodology

**Test-Driven Development (TDD):**
- Write tests FIRST, before implementation code
- Each feature/module must have accompanying unit tests
- Regression test suite must pass after every change
- Use test-driven approach for all feature work

**Atomic Commits:**
- Each commit should be logically independent and compilable
- Include test changes in the same commit as implementation
- Before committing:
  1. Verify `git diff` shows only logical changes (no formatting-only changes)
  2. Run full test suite: `meson test -C builddir`
  3. Run `./tools/format-c` on changed C files, add each one to
     `tools/formatted-files.txt`, then stage only the intended formatting
     hunks (for example, with `git add -p`)

**Code Style:**
- Uncrustify 0.83.0 is the authoritative formatter, configured by
  `tools/uncrustify.cfg` and installed by `tools/install-uncrustify.sh`.
- The tree is mid-migration from GNU indent. `tools/formatted-files.txt` lists
  the files already migrated; every one of them must stay an exact fixed point.
  Any C file you touch must be formatted and added to that ledger, so the
  migrated set only grows.
- Run `./tools/format-c <file>` to format, then stage only the intended
  formatting hunks (for example, with `git add -p`).
- 2-space indentation, no tabs, 80-char line limit
- The committed hook is activated automatically by `meson setup`.
- See `docs/developer-formatting.md` for installation and worktree behavior.

**Peer Review:**
- All implementation changes must be reviewed by a peer before merge
- Code review should cover: correctness, memory safety, performance impact

## Project Guidelines

- Language: C17 (strict C17 compliance)
- Build: Meson
- Core dependencies: GLib 2.0, DuckDB (subproject)
- License: GPL-3.0-or-later + Commercial dual license
