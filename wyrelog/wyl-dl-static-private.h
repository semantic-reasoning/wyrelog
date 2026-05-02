/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Static stratification check for Datalog rule sets.
 *
 * A Datalog program is stratified iff its predicate dependency graph
 * contains no cycle whose edges include a negation. Stratification is
 * a sufficient condition for the program to have a unique well-founded
 * model under negation as failure. wyrelog rejects non-stratified
 * inputs at load time so evaluation never observes a value that
 * depends on its own absence.
 *
 * The checker operates on a caller-owned array of rules. Each rule
 * names one head predicate and zero or more body atoms; each body
 * atom carries a flag marking whether it appears under negation
 * ("\+" in the source program). Strings are inspected only -- the
 * checker neither copies nor frees them, and the caller must keep
 * them alive across the call. Predicate names are matched
 * byte-for-byte (case-sensitive); arity is not part of the identity
 * in v0, so callers that need arity disambiguation encode it into
 * the name (for example "foo/2").
 *
 * Implementation note: the underlying SCC pass uses recursive DFS,
 * so callers must keep the predicate count below roughly ten
 * thousand to avoid stack overflow on default thread stacks. v0
 * policies are well below that bound; an iterative rewrite is left
 * to a future hardening commit.
 *
 * Return codes:
 *   WYRELOG_E_OK        program is stratified (or trivially empty).
 *   WYRELOG_E_POLICY    a negation edge participates in a cycle;
 *                       the program is rejected.
 *   WYRELOG_E_INVALID   rules == NULL with n > 0, or any rule's head
 *                       is NULL, or any body atom has a NULL
 *                       predicate, or body == NULL while body_len > 0.
 *
 * The checker does not return WYRELOG_E_NOMEM because all of its
 * allocations go through GLib, and GLib aborts the process on
 * allocation failure by design.
 */

typedef struct wyl_dl_body_atom_t
{
  const char *predicate;
  bool negated;
} wyl_dl_body_atom_t;

typedef struct wyl_dl_rule_t
{
  const char *head;
  const wyl_dl_body_atom_t *body;
  size_t body_len;
} wyl_dl_rule_t;

wyrelog_error_t wyl_dl_static_check (const wyl_dl_rule_t * rules, size_t n);

G_END_DECLS;
