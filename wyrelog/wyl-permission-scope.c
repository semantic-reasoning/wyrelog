/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-permission-scope-private.h"

#include <errno.h>
#include <stdlib.h>

/* --- baseline catalogue ------------------------------------------ */

static wyl_guard_expr_t *
build_admin (void)
{
  return wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "30"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "trusted"));
}

static wyl_guard_expr_t *
build_key_rotate (void)
{
  return wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "20"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "trusted"));
}

static wyl_guard_expr_t *
build_merkle_seal (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ, "trusted");
}

static wyl_guard_expr_t *
build_policy_write (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "50");
}

static wyl_guard_expr_t *
build_policy_grant_role (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30");
}

static wyl_guard_expr_t *
build_svc_freeze (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "40");
}

static wyl_guard_expr_t *
build_svc_unfreeze (void)
{
  return wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "30"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "trusted"));
}

static wyl_guard_expr_t *
build_svc_grant_role (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30");
}

static wyl_guard_expr_t *
build_audit_read (void)
{
  return wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "70");
}

static wyl_guard_expr_t *
build_audit_explain (void)
{
  return wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "50"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "trusted"));
}

typedef struct catalogue_entry_t
{
  const gchar *perm_id;
  wyl_guard_expr_t *(*build) (void);
} catalogue_entry_t;

static const catalogue_entry_t catalogue[] = {
  {"wr.sys.admin", build_admin},
  {"wr.sys.key_rotate", build_key_rotate},
  {"wr.sys.merkle_seal", build_merkle_seal},
  {"wr.policy.write", build_policy_write},
  {"wr.policy.grant_role", build_policy_grant_role},
  {"wr.svc.freeze", build_svc_freeze},
  {"wr.svc.unfreeze", build_svc_unfreeze},
  {"wr.svc.grant_role", build_svc_grant_role},
  {"wr.audit.read", build_audit_read},
  {"wr.audit.explain", build_audit_explain},
};

/* The compiled trees are owned by this module for process
 * lifetime; freeing them on shutdown would race with any other
 * cleanup that invokes wyl_eval_guard. */
static wyl_guard_expr_t *catalogue_trees[G_N_ELEMENTS (catalogue)];
static GHashTable *catalogue_index;

static gpointer
catalogue_init_once (gpointer user_data)
{
  (void) user_data;
  catalogue_index = g_hash_table_new (g_str_hash, g_str_equal);
  for (gsize i = 0; i < G_N_ELEMENTS (catalogue); i++) {
    wyl_guard_expr_t *tree = catalogue[i].build ();
    if (tree == NULL || wyl_guard_validate (tree) != WYRELOG_E_OK) {
      g_error ("permission-scope catalogue row %" G_GSIZE_FORMAT
          " (%s) failed to build or validate", i, catalogue[i].perm_id);
    }
    catalogue_trees[i] = tree;
    g_hash_table_insert (catalogue_index, (gpointer) catalogue[i].perm_id,
        tree);
  }
  return NULL;
}

static void
catalogue_ensure (void)
{
  static GOnce once = G_ONCE_INIT;
  g_once (&once, catalogue_init_once, NULL);
}

const wyl_guard_expr_t *
wyl_perm_arm_rule_lookup (const gchar *perm_id)
{
  if (perm_id == NULL)
    return NULL;
  catalogue_ensure ();
  return g_hash_table_lookup (catalogue_index, perm_id);
}

gsize
wyl_perm_arm_rule_count (void)
{
  return G_N_ELEMENTS (catalogue);
}

const gchar *
wyl_perm_arm_rule_perm_id (gsize idx)
{
  if (idx >= G_N_ELEMENTS (catalogue))
    return NULL;
  return catalogue[idx].perm_id;
}

const wyl_guard_expr_t *
wyl_perm_arm_rule_expr (gsize idx)
{
  if (idx >= G_N_ELEMENTS (catalogue))
    return NULL;
  catalogue_ensure ();
  return catalogue_trees[idx];
}

/* --- evaluator --------------------------------------------------- */

static gboolean
parse_signed_int (const gchar *value, gint64 *out)
{
  if (value == NULL || value[0] == '\0')
    return FALSE;
  errno = 0;
  gchar *end = NULL;
  gint64 v = (gint64) g_ascii_strtoll (value, &end, 10);
  if (errno != 0 || end == NULL || *end != '\0')
    return FALSE;
  *out = v;
  return TRUE;
}

static gboolean
eval_int_op (wyl_guard_op_t op, gint64 lhs, gint64 rhs)
{
  switch (op) {
    case WYL_GUARD_OP_EQ:
      return lhs == rhs;
    case WYL_GUARD_OP_NE:
      return lhs != rhs;
    case WYL_GUARD_OP_LT:
      return lhs < rhs;
    case WYL_GUARD_OP_LE:
      return lhs <= rhs;
    case WYL_GUARD_OP_GT:
      return lhs > rhs;
    case WYL_GUARD_OP_GE:
      return lhs >= rhs;
    case WYL_GUARD_OP_IN:
    case WYL_GUARD_OP_LAST_:
    default:
      return FALSE;
  }
}

static gboolean
eval_string_op (wyl_guard_op_t op, const gchar *lhs, const gchar *rhs)
{
  if (lhs == NULL || rhs == NULL)
    return FALSE;
  switch (op) {
    case WYL_GUARD_OP_EQ:
      return g_strcmp0 (lhs, rhs) == 0;
    case WYL_GUARD_OP_NE:
      return g_strcmp0 (lhs, rhs) != 0;
    case WYL_GUARD_OP_LT:
    case WYL_GUARD_OP_LE:
    case WYL_GUARD_OP_GT:
    case WYL_GUARD_OP_GE:
    case WYL_GUARD_OP_IN:
    case WYL_GUARD_OP_LAST_:
    default:
      return FALSE;
  }
}

static gboolean
eval_cmp (const wyl_guard_expr_t *e, const wyl_scope_t *s)
{
  switch (e->u.cmp.field) {
    case WYL_GUARD_FIELD_RISK:{
      gint64 rhs = 0;
      if (!parse_signed_int (e->u.cmp.value, &rhs))
        return FALSE;
      return eval_int_op (e->u.cmp.op, s->risk, rhs);
    }
    case WYL_GUARD_FIELD_LOC_CLASS:
      return eval_string_op (e->u.cmp.op, s->loc_class, e->u.cmp.value);
    case WYL_GUARD_FIELD_TENANT:
      /* Tenant is reserved for tenant-scoped policy wiring in a
       * follow-up commit; v0 has no tenant slot in scope so any
       * tenant cmp fails closed. */
      return FALSE;
    case WYL_GUARD_FIELD_TIMESTAMP:
      if (e->u.cmp.op != WYL_GUARD_OP_IN)
        return FALSE;
      if (s->in_window == NULL)
        return FALSE;
      return s->in_window (s->timestamp, e->u.cmp.value,
          s->in_window_user_data);
    case WYL_GUARD_FIELD_LAST_:
    default:
      return FALSE;
  }
}

gboolean
wyl_eval_guard (const wyl_guard_expr_t *e, const wyl_scope_t *s)
{
  if (e == NULL || s == NULL)
    return FALSE;

  switch (e->kind) {
    case WYL_GUARD_KIND_AND:
      return wyl_eval_guard (e->u.binop.left, s) &&
          wyl_eval_guard (e->u.binop.right, s);
    case WYL_GUARD_KIND_OR:
      return wyl_eval_guard (e->u.binop.left, s) ||
          wyl_eval_guard (e->u.binop.right, s);
    case WYL_GUARD_KIND_NOT:
      return !wyl_eval_guard (e->u.unary.child, s);
    case WYL_GUARD_KIND_CMP:
      return eval_cmp (e, s);
    case WYL_GUARD_KIND_TAG:
      /* Tag predicate is reserved for site policy in a future
       * commit; v0 fails closed. */
      return FALSE;
    case WYL_GUARD_KIND_LAST_:
    default:
      return FALSE;
  }
}
