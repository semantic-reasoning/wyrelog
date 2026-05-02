/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-guard-expr-private.h"

static const gchar *const kind_names[] = {
  "and",
  "or",
  "not",
  "cmp",
  "tag",
};

static const gchar *const field_names[] = {
  "risk",
  "tenant",
  "loc_class",
  "timestamp",
};

static const gchar *const op_names[] = {
  "eq",
  "ne",
  "lt",
  "le",
  "gt",
  "ge",
  "in",
};

G_STATIC_ASSERT (G_N_ELEMENTS (kind_names) == WYL_GUARD_KIND_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (field_names) == WYL_GUARD_FIELD_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (op_names) == WYL_GUARD_OP_LAST_);

const gchar *
wyl_guard_kind_name (wyl_guard_kind_t k)
{
  if ((guint) k >= WYL_GUARD_KIND_LAST_)
    return NULL;
  return kind_names[k];
}

const gchar *
wyl_guard_field_name (wyl_guard_field_t f)
{
  if ((guint) f >= WYL_GUARD_FIELD_LAST_)
    return NULL;
  return field_names[f];
}

const gchar *
wyl_guard_op_name (wyl_guard_op_t op)
{
  if ((guint) op >= WYL_GUARD_OP_LAST_)
    return NULL;
  return op_names[op];
}

void
wyl_guard_expr_free (wyl_guard_expr_t *e)
{
  if (e == NULL)
    return;

  switch (e->kind) {
    case WYL_GUARD_KIND_AND:
    case WYL_GUARD_KIND_OR:
      wyl_guard_expr_free (e->u.binop.left);
      wyl_guard_expr_free (e->u.binop.right);
      break;
    case WYL_GUARD_KIND_NOT:
      wyl_guard_expr_free (e->u.unary.child);
      break;
    case WYL_GUARD_KIND_CMP:
      g_free (e->u.cmp.value);
      break;
    case WYL_GUARD_KIND_TAG:
      g_free (e->u.tag.atom);
      break;
    case WYL_GUARD_KIND_LAST_:
    default:
      /* Fall through; nothing to free for malformed nodes that
       * may have been zero-initialized but never populated. */
      break;
  }

  g_free (e);
}

wyl_guard_expr_t *
wyl_guard_cmp (wyl_guard_field_t field, wyl_guard_op_t op, const gchar *value)
{
  if (value == NULL)
    return NULL;
  if ((guint) field >= WYL_GUARD_FIELD_LAST_)
    return NULL;
  if ((guint) op >= WYL_GUARD_OP_LAST_)
    return NULL;

  wyl_guard_expr_t *e = g_new0 (wyl_guard_expr_t, 1);
  e->kind = WYL_GUARD_KIND_CMP;
  e->u.cmp.field = field;
  e->u.cmp.op = op;
  e->u.cmp.value = g_strdup (value);
  return e;
}

wyl_guard_expr_t *
wyl_guard_tag (const gchar *atom)
{
  if (atom == NULL)
    return NULL;

  wyl_guard_expr_t *e = g_new0 (wyl_guard_expr_t, 1);
  e->kind = WYL_GUARD_KIND_TAG;
  e->u.tag.atom = g_strdup (atom);
  return e;
}

wyl_guard_expr_t *
wyl_guard_not (wyl_guard_expr_t *child)
{
  if (child == NULL)
    return NULL;

  wyl_guard_expr_t *e = g_new0 (wyl_guard_expr_t, 1);
  e->kind = WYL_GUARD_KIND_NOT;
  e->u.unary.child = child;
  return e;
}

static wyl_guard_expr_t *
build_binop (wyl_guard_kind_t kind, wyl_guard_expr_t *left,
    wyl_guard_expr_t *right)
{
  if (left == NULL || right == NULL) {
    /* Builders consume their children unconditionally. If either
     * is NULL the contract still requires us to release whatever
     * the caller did pass in. */
    wyl_guard_expr_free (left);
    wyl_guard_expr_free (right);
    return NULL;
  }

  wyl_guard_expr_t *e = g_new0 (wyl_guard_expr_t, 1);
  e->kind = kind;
  e->u.binop.left = left;
  e->u.binop.right = right;
  return e;
}

wyl_guard_expr_t *
wyl_guard_and (wyl_guard_expr_t *left, wyl_guard_expr_t *right)
{
  return build_binop (WYL_GUARD_KIND_AND, left, right);
}

wyl_guard_expr_t *
wyl_guard_or (wyl_guard_expr_t *left, wyl_guard_expr_t *right)
{
  return build_binop (WYL_GUARD_KIND_OR, left, right);
}

/*
 * Bounded recursive walk. Returns the depth of the subtree rooted
 * at `e`, or WYL_GUARD_MAX_DEPTH + 1 if the depth exceeds the
 * limit. Accumulates atom count into *atoms (which is also clamped
 * at WYL_GUARD_MAX_ATOMS + 1 to make the over-limit case
 * observable without overflow).
 *
 * Returns 0 only if `e` is NULL; the caller must therefore
 * disambiguate "missing subtree" from "depth-1 leaf" by checking
 * for NULL before calling.
 */
static gsize
walk (const wyl_guard_expr_t *e, gsize current_depth, gsize *atoms)
{
  if (e == NULL)
    return 0;
  if (current_depth >= WYL_GUARD_MAX_DEPTH + 1)
    return WYL_GUARD_MAX_DEPTH + 1;

  switch (e->kind) {
    case WYL_GUARD_KIND_CMP:
    case WYL_GUARD_KIND_TAG:
      if (*atoms < WYL_GUARD_MAX_ATOMS + 1)
        (*atoms)++;
      return 1;

    case WYL_GUARD_KIND_NOT:{
      gsize d = walk (e->u.unary.child, current_depth + 1, atoms);
      if (d == 0)
        return WYL_GUARD_MAX_DEPTH + 1;
      gsize result = 1 + d;
      if (result > WYL_GUARD_MAX_DEPTH + 1)
        result = WYL_GUARD_MAX_DEPTH + 1;
      return result;
    }

    case WYL_GUARD_KIND_AND:
    case WYL_GUARD_KIND_OR:{
      gsize l = walk (e->u.binop.left, current_depth + 1, atoms);
      gsize r = walk (e->u.binop.right, current_depth + 1, atoms);
      if (l == 0 || r == 0)
        return WYL_GUARD_MAX_DEPTH + 1;
      gsize m = (l > r) ? l : r;
      gsize result = 1 + m;
      if (result > WYL_GUARD_MAX_DEPTH + 1)
        result = WYL_GUARD_MAX_DEPTH + 1;
      return result;
    }

    case WYL_GUARD_KIND_LAST_:
    default:
      return WYL_GUARD_MAX_DEPTH + 1;
  }
}

gsize
wyl_guard_depth (const wyl_guard_expr_t *e)
{
  gsize atoms = 0;
  return walk (e, 0, &atoms);
}

gsize
wyl_guard_atom_count (const wyl_guard_expr_t *e)
{
  gsize atoms = 0;
  (void) walk (e, 0, &atoms);
  return atoms;
}

/*
 * Strict structural validation. Recurses without the depth clamp
 * so that any hop past WYL_GUARD_MAX_DEPTH triggers the policy
 * rejection rather than being silently saturated.
 */
static wyrelog_error_t
validate_node (const wyl_guard_expr_t *e, gsize current_depth, gsize *atoms)
{
  if (e == NULL)
    return WYRELOG_E_INVALID;
  if (current_depth >= WYL_GUARD_MAX_DEPTH)
    return WYRELOG_E_POLICY;

  switch (e->kind) {
    case WYL_GUARD_KIND_CMP:
      if ((guint) e->u.cmp.field >= WYL_GUARD_FIELD_LAST_)
        return WYRELOG_E_INVALID;
      if ((guint) e->u.cmp.op >= WYL_GUARD_OP_LAST_)
        return WYRELOG_E_INVALID;
      if (e->u.cmp.value == NULL)
        return WYRELOG_E_INVALID;
      (*atoms)++;
      if (*atoms > WYL_GUARD_MAX_ATOMS)
        return WYRELOG_E_POLICY;
      return WYRELOG_E_OK;

    case WYL_GUARD_KIND_TAG:
      if (e->u.tag.atom == NULL)
        return WYRELOG_E_INVALID;
      (*atoms)++;
      if (*atoms > WYL_GUARD_MAX_ATOMS)
        return WYRELOG_E_POLICY;
      return WYRELOG_E_OK;

    case WYL_GUARD_KIND_NOT:
      return validate_node (e->u.unary.child, current_depth + 1, atoms);

    case WYL_GUARD_KIND_AND:
    case WYL_GUARD_KIND_OR:{
      wyrelog_error_t rc =
          validate_node (e->u.binop.left, current_depth + 1, atoms);
      if (rc != WYRELOG_E_OK)
        return rc;
      return validate_node (e->u.binop.right, current_depth + 1, atoms);
    }

    case WYL_GUARD_KIND_LAST_:
    default:
      return WYRELOG_E_INVALID;
  }
}

wyrelog_error_t
wyl_guard_validate (const wyl_guard_expr_t *e)
{
  if (e == NULL)
    return WYRELOG_E_INVALID;
  gsize atoms = 0;
  return validate_node (e, 0, &atoms);
}
