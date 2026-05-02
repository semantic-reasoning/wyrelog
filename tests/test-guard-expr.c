/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyl-guard-expr-private.h"

/* --- Name lookup round-trip ------------------------------------- */

static gint
check_name_roundtrip (void)
{
  for (guint k = 0; k < WYL_GUARD_KIND_LAST_; k++) {
    if (wyl_guard_kind_name ((wyl_guard_kind_t) k) == NULL)
      return 1;
  }
  if (wyl_guard_kind_name (WYL_GUARD_KIND_LAST_) != NULL)
    return 2;

  for (guint f = 0; f < WYL_GUARD_FIELD_LAST_; f++) {
    if (wyl_guard_field_name ((wyl_guard_field_t) f) == NULL)
      return 3;
  }
  if (wyl_guard_field_name (WYL_GUARD_FIELD_LAST_) != NULL)
    return 4;

  for (guint op = 0; op < WYL_GUARD_OP_LAST_; op++) {
    if (wyl_guard_op_name ((wyl_guard_op_t) op) == NULL)
      return 5;
  }
  if (wyl_guard_op_name (WYL_GUARD_OP_LAST_) != NULL)
    return 6;

  return 0;
}

/* --- AND fixture ------------------------------------------------ */

static gint
check_build_and (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "30"), wyl_guard_tag ("audit"));
  if (g == NULL)
    return 10;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 11;
  if (wyl_guard_depth (g) != 2)
    return 12;
  if (wyl_guard_atom_count (g) != 2)
    return 13;
  return 0;
}

/* --- OR fixture ------------------------------------------------- */

static gint
check_build_or (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_TENANT, WYL_GUARD_OP_EQ,
          "t1"), wyl_guard_cmp (WYL_GUARD_FIELD_TENANT, WYL_GUARD_OP_EQ, "t2"));
  if (g == NULL)
    return 20;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 21;
  if (wyl_guard_depth (g) != 2)
    return 22;
  if (wyl_guard_atom_count (g) != 2)
    return 23;
  return 0;
}

/* --- NOT fixture ------------------------------------------------ */

static gint
check_build_not (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_not (wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "public"));
  if (g == NULL)
    return 30;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 31;
  if (wyl_guard_depth (g) != 2)
    return 32;
  if (wyl_guard_atom_count (g) != 1)
    return 33;
  return 0;
}

/* --- Nested mixed fixture --------------------------------------- */

static gint
check_nested_mixed (void)
{
  /* and(or(cmp,cmp), not(tag)) — depth 3, 3 atoms */
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_and (wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
              WYL_GUARD_OP_LT, "20"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS,
              WYL_GUARD_OP_EQ, "trusted")),
      wyl_guard_not (wyl_guard_tag ("break_glass")));
  if (g == NULL)
    return 40;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 41;
  if (wyl_guard_depth (g) != 3)
    return 42;
  if (wyl_guard_atom_count (g) != 3)
    return 43;
  return 0;
}

/* --- Depth-4 boundary accept ------------------------------------ */

static gint
check_depth_4_boundary (void)
{
  /* Left-leaning chain:
   *   and(and(and(cmp, cmp), cmp), cmp)  — depth 4, 4 atoms */
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_cmp
              (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "10"),
              wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "20")),
          wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30")),
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "40"));
  if (g == NULL)
    return 50;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 51;
  if (wyl_guard_depth (g) != 4)
    return 52;
  if (wyl_guard_atom_count (g) != 4)
    return 53;
  return 0;
}

/* --- Depth-5 reject --------------------------------------------- */

static gint
check_depth_5_reject (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_cmp
                  (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "10"),
                  wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "20")),
              wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30")),
          wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "40")),
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "50"));
  if (g == NULL)
    return 60;
  if (wyl_guard_validate (g) != WYRELOG_E_POLICY)
    return 61;
  /* The walking depth counter saturates at MAX_DEPTH + 1. */
  if (wyl_guard_depth (g) != WYL_GUARD_MAX_DEPTH + 1)
    return 62;
  return 0;
}

/* --- Atom limit accept (8 atoms, depth 4) ----------------------- */

static gint
check_atom_limit_accept (void)
{
  /* Balanced tree, depth 4, 8 leaves. */
#define LEAF() \
  wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "1")
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_and (wyl_guard_and (wyl_guard_and (LEAF (), LEAF ()),
          wyl_guard_and (LEAF (), LEAF ())),
      wyl_guard_and (wyl_guard_and (LEAF (), LEAF ()), wyl_guard_and (LEAF (),
              LEAF ())));
#undef LEAF
  if (g == NULL)
    return 70;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 71;
  if (wyl_guard_depth (g) != 4)
    return 72;
  if (wyl_guard_atom_count (g) != 8)
    return 73;
  return 0;
}

/* --- Atom limit reject (9 atoms) -------------------------------- */

static gint
check_atom_limit_reject (void)
{
  /* Nine leaves wired through nested OR. The validator must reject
   * with WYRELOG_E_POLICY whether the rejection is triggered by
   * the atom limit (>8) or the depth limit (>4); either condition
   * is a policy violation. */
  g_autoptr (wyl_guard_expr_t) reject =
      wyl_guard_or (wyl_guard_or (wyl_guard_or (wyl_guard_cmp
              (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "1"),
              wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "2")),
          wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
                  "3"), wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
                  "4"))),
      wyl_guard_or (wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
                  WYL_GUARD_OP_LT, "5"), wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
                  WYL_GUARD_OP_LT, "6")),
          wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
                  "7"), wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
                      WYL_GUARD_OP_LT, "8"),
                  wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
                      "9")))));
  if (reject == NULL)
    return 81;
  /* 9 atoms — exceeds limit. depth could also exceed; either way
   * validate must reject. */
  if (wyl_guard_validate (reject) != WYRELOG_E_POLICY)
    return 82;
  return 0;
}

/* --- in operator with timestamp field --------------------------- */

static gint
check_in_with_timestamp (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN, "off_hours");
  if (g == NULL)
    return 90;
  if (wyl_guard_validate (g) != WYRELOG_E_OK)
    return 91;
  if (wyl_guard_depth (g) != 1)
    return 92;
  if (wyl_guard_atom_count (g) != 1)
    return 93;
  return 0;
}

/* --- Argument validation (builders) ----------------------------- */

static gint
check_builder_validation (void)
{
  /* Out-of-range field: builder rejects. */
  if (wyl_guard_cmp (WYL_GUARD_FIELD_LAST_, WYL_GUARD_OP_EQ, "x") != NULL)
    return 100;
  /* Out-of-range op: rejects. */
  if (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LAST_, "x") != NULL)
    return 101;
  /* NULL value: rejects. */
  if (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_EQ, NULL) != NULL)
    return 102;
  /* NULL atom for tag: rejects. */
  if (wyl_guard_tag (NULL) != NULL)
    return 103;
  /* NULL child for not: rejects. */
  if (wyl_guard_not (NULL) != NULL)
    return 104;
  /* Builder consumes children even on rejection: pass a real left
   * with a NULL right and confirm no leak (we cannot directly
   * observe leaks, but the contract is exercised). */
  wyl_guard_expr_t *l =
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "1");
  if (l == NULL)
    return 105;
  if (wyl_guard_and (l, NULL) != NULL)
    return 106;
  /* l has been freed by the builder; do not touch it again. */

  /* validate(NULL) -> INVALID. */
  if (wyl_guard_validate (NULL) != WYRELOG_E_INVALID)
    return 107;

  return 0;
}

/* --- Validator invariant (manual struct poke) ------------------- */

static gint
check_validate_oor_field (void)
{
  /* Forge a cmp node with an out-of-range field bypassing the
   * builder, to exercise the validator's defensive enum check. */
  g_autoptr (wyl_guard_expr_t) e = g_new0 (wyl_guard_expr_t, 1);
  e->kind = WYL_GUARD_KIND_CMP;
  e->u.cmp.field = WYL_GUARD_FIELD_LAST_;
  e->u.cmp.op = WYL_GUARD_OP_EQ;
  e->u.cmp.value = g_strdup ("x");
  if (wyl_guard_validate (e) != WYRELOG_E_INVALID)
    return 110;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_name_roundtrip ()) != 0)
    return rc;
  if ((rc = check_build_and ()) != 0)
    return rc;
  if ((rc = check_build_or ()) != 0)
    return rc;
  if ((rc = check_build_not ()) != 0)
    return rc;
  if ((rc = check_nested_mixed ()) != 0)
    return rc;
  if ((rc = check_depth_4_boundary ()) != 0)
    return rc;
  if ((rc = check_depth_5_reject ()) != 0)
    return rc;
  if ((rc = check_atom_limit_accept ()) != 0)
    return rc;
  if ((rc = check_atom_limit_reject ()) != 0)
    return rc;
  if ((rc = check_in_with_timestamp ()) != 0)
    return rc;
  if ((rc = check_builder_validation ()) != 0)
    return rc;
  if ((rc = check_validate_oor_field ()) != 0)
    return rc;
  return 0;
}
