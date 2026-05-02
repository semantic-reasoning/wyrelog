/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

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
  const gchar *predicate;
  gboolean negated;
} wyl_dl_body_atom_t;

typedef struct wyl_dl_rule_t
{
  const gchar *head;
  const wyl_dl_body_atom_t *body;
  gsize body_len;
} wyl_dl_rule_t;

wyrelog_error_t wyl_dl_static_check (const wyl_dl_rule_t * rules, gsize n);


/*
 * Load-time integrity checks over flat fact rows.
 *
 * The checks below operate on caller-owned arrays of fact rows.
 * A row carries the head predicate name plus a borrowed pointer
 * vector of argument strings. The checkers borrow every pointer;
 * the caller must keep the row backing storage alive across the
 * call. No string is copied, no row is rewritten, and no memory
 * is retained after the call returns.
 */

typedef struct wyl_dl_fact_row_t
{
  const gchar *head;
  const gchar *const *args;
  gsize arity;
} wyl_dl_fact_row_t;

/*
 * Witness populated when wyl_dl_check_functional_ic refuses a
 * program. All pointer fields borrow from the rows array passed
 * in; callers must not free them and must not retain them past
 * the lifetime of that array.
 *
 *   head            : the predicate that violated the constraint
 *   key             : pointer to the first key_arity strings of
 *                     the conflicting rows (the same key on both)
 *   key_arity       : echoes the key_arity argument
 *   value_a         : tail value of the first sighting
 *   value_b         : tail value of the conflicting row
 *   first_index     : index of the first sighting in rows[]
 *   conflict_index  : index of the conflicting row in rows[]
 *
 * Multi-way conflicts (three or more distinct tails for the same
 * key) surface only the first detected pair; existential witness
 * is sufficient for the load-time refusal contract.
 */
typedef struct wyl_dl_ic_violation_t
{
  const gchar *head;
  const gchar *const *key;
  gsize key_arity;
  const gchar *value_a;
  const gchar *value_b;
  gsize first_index;
  gsize conflict_index;
} wyl_dl_ic_violation_t;

/*
 * Functional integrity constraint: for every group of rows that
 * share the same (head, args[0..key_arity-1]) the tail value at
 * args[key_arity] must agree. Used to reject a non-functional
 * FSM transition table at load time, where two rows for the same
 * (from, event) point at distinct destinations.
 *
 * Each row must satisfy arity > key_arity; the tail comparison
 * uses args[key_arity] only, additional tail columns are ignored
 * (callers that need multi-column tail equality can encode the
 * tuple into one string before calling).
 *
 * Return codes:
 *   WYRELOG_E_OK       no group has conflicting tails (or trivially empty)
 *   WYRELOG_E_POLICY   first conflict surfaces in *out_witness when non-NULL
 *   WYRELOG_E_INVALID  rows == NULL with n > 0, any row.head is NULL, any
 *                      args == NULL while arity > 0, any args[k] is NULL
 *                      for k < arity, or any row.arity <= key_arity.
 */
wyrelog_error_t wyl_dl_check_functional_ic (const wyl_dl_fact_row_t * rows,
    gsize n, gsize key_arity, wyl_dl_ic_violation_t * out_witness);

/*
 * Empty-extension assertion: refuse the program if any row in
 * the input bears a head equal to expected_head. When
 * expected_head is NULL every row counts as a violation, which
 * is useful for a pre-filtered fact list.
 *
 *   *out_witness_row, when non-NULL, is set to the first matching
 *   row pointer on policy refusal; left untouched on OK or INVALID.
 *
 * Used to implement the load-time SoD contract by passing a
 * post-evaluation snapshot of the policy_violation EDB and
 * expected_head = "policy_violation"; non-empty input refuses
 * the load.
 *
 * Return codes:
 *   WYRELOG_E_OK       no row matches expected_head (or rows is empty)
 *   WYRELOG_E_POLICY   at least one row matches; first match in
 *                      *out_witness_row when non-NULL
 *   WYRELOG_E_INVALID  rows == NULL with n > 0, or any row.head is
 *                      NULL when needed for the comparison.
 */
wyrelog_error_t wyl_dl_assert_edb_empty (const wyl_dl_fact_row_t * rows,
    gsize n, const gchar * expected_head,
    const wyl_dl_fact_row_t ** out_witness_row);

G_END_DECLS;
