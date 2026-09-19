#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pin the fact_batches / fact_event_log column macros against drift.

The #1103 convergence migration rebuilds both tables from FACT_BATCHES_COLUMNS
and FACT_EVENT_LOG_COLUMNS and moves their rows with explicit
INSERT (<names>) SELECT <names>, where <names> comes from a separate macro.
Nothing in C makes the two agree.  A name dropped from the names list silently
omits a column from the copy, and neither EXCEPT proof can see that, because
both sides read the same list.  (Transposing two names within the names macro
is harmless -- the same list supplies the INSERT target and the SELECT, so it
is an identity copy.  Omission is the hazard, and it is silent only for the
nullable columns; dropping a NOT NULL column fails loudly at runtime.)

This is deliberately partial: it pins the column NAMES and the stage table's
shape, not the table constraints.  Losing the FOREIGN KEY from
FACT_EVENT_LOG_COLUMNS passes this gate and is caught in C instead, by
check_fact_store_logical_bytes_shape_is_identical_fresh_and_migrated asserting
fact_event_log still carries exactly one FOREIGN KEY on both store shapes.  Do
not read a pass here as "the schema macros are correct".

The (14, 10) counts in PAIRS are a second edit site when the schema legitimately
grows -- that is the point, not an oversight.  FACT_BATCHES_COLUMN_COUNT, which
store.c refuses to converge against at runtime, is pinned to the same number
here so the macro, that guard and this gate cannot drift apart.

So this asserts what the compiler will not: each *_COLUMN_NAMES macro is
exactly the column names of its *_COLUMNS macro, in order, and every one of
these macros expands to string literals only -- the same rule
test-fact-store-forget-transaction-boundary.py pins for
FACT_FORGET_INTENT_COLUMNS, and for the same reason.
"""

import re
import sys

SOURCE = "wyrelog/fact/store.c"

# (definition macro, names macro, expected column count)
PAIRS = (
    ("FACT_BATCHES_COLUMNS", "FACT_BATCHES_COLUMN_NAMES", 14),
    ("FACT_EVENT_LOG_COLUMNS", "FACT_EVENT_LOG_COLUMN_NAMES", 10),
)
# Column definitions that are table constraints rather than columns.
CONSTRAINT_PREFIXES = ("FOREIGN KEY", "PRIMARY KEY", "UNIQUE", "CHECK")
STAGE_PAIR = ("FACT_EVENT_LOG_COLUMNS", "FACT_EVENT_LOG_STAGE_COLUMNS")


def read_macro(text, name):
    """Return the macro body of |name| as a single joined string."""
    match = re.search(
        r"^#define[ \t]+" + re.escape(name) + r"[ \t]*((?:.*\\\n)*.*)$",
        text,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("macro not defined: %s" % name)
    return match.group(1)


def literal_value(name, body):
    """Assert |body| is string literals only and return their concatenation."""
    residue = re.sub(r'"(?:[^"\\]|\\.)*"', "", body)
    residue = residue.replace("\\\n", "").strip()
    if residue:
        raise AssertionError(
            "macro %s is not string literals only: %r" % (name, residue))
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', body))


def split_columns(value):
    """Split a column list on top-level commas (CHECK bodies have their own)."""
    parts = []
    depth = 0
    current = ""
    for char in value:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
            continue
        current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def column_names(entries):
    names = []
    for entry in entries:
        if entry.upper().startswith(CONSTRAINT_PREFIXES):
            continue
        names.append(entry.split()[0])
    return names


def column_types(entries):
    types = {}
    for entry in entries:
        if entry.upper().startswith(CONSTRAINT_PREFIXES):
            continue
        fields = entry.split()
        types[fields[0]] = fields[1]
    return types


def main(argv):
    if len(argv) != 2:
        print("usage: %s <source-root>" % argv[0], file=sys.stderr)
        return 2
    with open(argv[1] + "/" + SOURCE, encoding="utf-8") as handle:
        text = handle.read()
    try:
        return check(text)
    except AssertionError as failure:
        print("fact schema macro drift: %s" % failure, file=sys.stderr)
        return 1


def check(text):
    failures = []
    for definition, names_macro, expected in PAIRS:
        columns = split_columns(
            literal_value(definition, read_macro(text, definition)))
        declared = column_names(columns)
        listed = [
            name.strip() for name in
            literal_value(names_macro, read_macro(text, names_macro)).split(",")
            if name.strip()
        ]
        if len(declared) != expected:
            failures.append(
                "%s declares %d columns, expected %d"
                % (definition, len(declared), expected))
        if definition == "FACT_BATCHES_COLUMNS":
            guard = re.search(
                r"^#define[ \t]+FACT_BATCHES_COLUMN_COUNT[ \t]+(\d+)",
                text, re.MULTILINE)
            if guard is None:
                failures.append("FACT_BATCHES_COLUMN_COUNT is not defined")
            elif int(guard.group(1)) != len(declared):
                failures.append(
                    "FACT_BATCHES_COLUMN_COUNT is %s but %s declares %d"
                    % (guard.group(1), definition, len(declared)))
        if declared != listed:
            failures.append(
                "%s does not match %s:\n  declared: %s\n  listed:   %s"
                % (names_macro, definition, declared, listed))

    # The staging table carries the event log's rows across the window where
    # the real table must not exist, so it must agree on names and types and
    # differ only by dropping the constraints.
    real, stage = STAGE_PAIR
    real_columns = split_columns(literal_value(real, read_macro(text, real)))
    stage_columns = split_columns(
        literal_value(stage, read_macro(text, stage)))
    if column_types(real_columns) != column_types(stage_columns):
        failures.append(
            "%s does not carry the same column names and types as %s"
            % (stage, real))
    for entry in stage_columns:
        if entry.upper().startswith(CONSTRAINT_PREFIXES) or "NOT NULL" in entry:
            failures.append(
                "%s must not carry constraints, found: %s" % (stage, entry))

    if failures:
        for failure in failures:
            print("fact schema macro drift: " + failure, file=sys.stderr)
        return 1
    print("fact schema macro consistency: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
