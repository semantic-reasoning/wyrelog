/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Guard expression AST.
 *
 * In-memory representation of a policy guard expression. The
 * grammar is recursive over five node kinds:
 *
 *   guard_expr ::= and(guard_expr, guard_expr)
 *                | or(guard_expr, guard_expr)
 *                | not(guard_expr)
 *                | cmp(field, op, value)
 *                | tag(atom)
 *
 * Comparison fields are drawn from a fixed alphabet (risk, tenant,
 * loc_class, timestamp). The raw location identifier is
 * deliberately absent; site policies that need it must encode
 * through tag atoms. Comparison operators are the six total
 * orderings plus a set-membership operator (in).
 *
 * Structural limits (load-time enforced):
 *   - depth <= 4
 *   - leaf atom count (cmp + tag) <= 8
 *
 * Depth convention: depth(cmp) = depth(tag) = 1; depth(not(c)) =
 * 1 + depth(c); depth(and(l,r)) = depth(or(l,r)) = 1 + max(depth(l),
 * depth(r)).
 *
 * Memory ownership: builders take ownership of every child
 * argument unconditionally. If the builder rejects its arguments
 * (NULL child where one is required, out-of-range enum, or invalid
 * value pointer) it frees the passed-in children before returning
 * NULL. Callers therefore never free a child after handing it to a
 * builder; the whole tree is released by a single
 * wyl_guard_expr_free at the root, or via g_autoptr.
 *
 * Aliasing rule: callers must not alias subtrees. Each node
 * appears at most once in the tree. The validator does not
 * implement a visited set; instead, the depth limit acts as a
 * structural bound that catches accidental cycles by treating any
 * traversal beyond depth 4 as malformed.
 */

#define WYL_GUARD_MAX_DEPTH ((gsize) 4)
#define WYL_GUARD_MAX_ATOMS ((gsize) 8)

typedef enum wyl_guard_kind_t
{
  WYL_GUARD_KIND_AND = 0,
  WYL_GUARD_KIND_OR,
  WYL_GUARD_KIND_NOT,
  WYL_GUARD_KIND_CMP,
  WYL_GUARD_KIND_TAG,
  WYL_GUARD_KIND_LAST_,
} wyl_guard_kind_t;

typedef enum wyl_guard_field_t
{
  WYL_GUARD_FIELD_RISK = 0,
  WYL_GUARD_FIELD_TENANT,
  WYL_GUARD_FIELD_LOC_CLASS,
  WYL_GUARD_FIELD_TIMESTAMP,
  WYL_GUARD_FIELD_LAST_,
} wyl_guard_field_t;

typedef enum wyl_guard_op_t
{
  WYL_GUARD_OP_EQ = 0,
  WYL_GUARD_OP_NE,
  WYL_GUARD_OP_LT,
  WYL_GUARD_OP_LE,
  WYL_GUARD_OP_GT,
  WYL_GUARD_OP_GE,
  WYL_GUARD_OP_IN,
  WYL_GUARD_OP_LAST_,
} wyl_guard_op_t;

typedef struct wyl_guard_expr_t wyl_guard_expr_t;

struct wyl_guard_expr_t
{
  wyl_guard_kind_t kind;
  union
  {
    struct
    {
      wyl_guard_expr_t *left;
      wyl_guard_expr_t *right;
    } binop;
    struct
    {
      wyl_guard_expr_t *child;
    } unary;
    struct
    {
      wyl_guard_field_t field;
      wyl_guard_op_t op;
      gchar *value;
    } cmp;
    struct
    {
      gchar *atom;
    } tag;
  } u;
};

/*
 * Builders. Each builder takes ownership of every passed-in
 * pointer; on validation failure the builder frees them and
 * returns NULL. The string arguments to wyl_guard_cmp and
 * wyl_guard_tag are duplicated.
 */
wyl_guard_expr_t *wyl_guard_cmp (wyl_guard_field_t field,
    wyl_guard_op_t op, const gchar * value);
wyl_guard_expr_t *wyl_guard_tag (const gchar * atom);
wyl_guard_expr_t *wyl_guard_not (wyl_guard_expr_t * child);
wyl_guard_expr_t *wyl_guard_and (wyl_guard_expr_t * left,
    wyl_guard_expr_t * right);
wyl_guard_expr_t *wyl_guard_or (wyl_guard_expr_t * left,
    wyl_guard_expr_t * right);

/*
 * Recursive deep-free. NULL-safe; suitable for autoptr cleanup
 * and g_clear_pointer.
 */
void wyl_guard_expr_free (wyl_guard_expr_t * e);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_guard_expr_t, wyl_guard_expr_free);

/*
 * Returns WYRELOG_E_OK if the tree is well-formed and within the
 * structural limits. WYRELOG_E_INVALID for NULL, out-of-range
 * enums, or NULL children where the kind requires them.
 * WYRELOG_E_POLICY when depth exceeds WYL_GUARD_MAX_DEPTH or the
 * leaf-atom count exceeds WYL_GUARD_MAX_ATOMS.
 *
 * The validator bounds its own recursion at WYL_GUARD_MAX_DEPTH
 * so a malformed (aliased / cyclic) input is caught as a policy
 * violation rather than crashing the process.
 */
wyrelog_error_t wyl_guard_validate (const wyl_guard_expr_t * e);

/*
 * Test introspection. Both functions return 0 for NULL and obey
 * the same depth bound; if the structural limits are exceeded the
 * counters saturate at WYL_GUARD_MAX_DEPTH + 1 / WYL_GUARD_MAX_ATOMS
 * + 1 respectively to make the over-limit case observable without
 * a crash.
 */
gsize wyl_guard_depth (const wyl_guard_expr_t * e);
gsize wyl_guard_atom_count (const wyl_guard_expr_t * e);

/*
 * Lexical names for kind / field / op ordinals. NULL on
 * out-of-range input. Used by tests and by future reporting
 * paths; callers must not free the returned strings.
 */
const gchar *wyl_guard_kind_name (wyl_guard_kind_t k);
const gchar *wyl_guard_field_name (wyl_guard_field_t f);
const gchar *wyl_guard_op_name (wyl_guard_op_t op);

G_END_DECLS;
