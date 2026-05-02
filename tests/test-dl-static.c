/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyl-dl-static-private.h"

static gint
check (const wyl_dl_rule_t *rules, gsize n)
{
  return (gint) wyl_dl_static_check (rules, n);
}

int
main (void)
{
  /* Case 1: empty input -> OK. */
  if (check (NULL, 0) != WYRELOG_E_OK)
    return 1;

  /* Case 2: NULL rules with n > 0 -> INVALID. */
  if (check (NULL, 1) != WYRELOG_E_INVALID)
    return 2;

  /* Case 3: NULL head -> INVALID. */
  {
    wyl_dl_rule_t rules[] = { {NULL, NULL, 0}
    };
    if (check (rules, 1) != WYRELOG_E_INVALID)
      return 3;
  }

  /* Case 4: NULL body predicate -> INVALID. */
  {
    wyl_dl_body_atom_t body[] = { {NULL, FALSE}
    };
    wyl_dl_rule_t rules[] = { {"p", body, 1}
    };
    if (check (rules, 1) != WYRELOG_E_INVALID)
      return 4;
  }

  /* Case 5: single fact, no body (p.) -> OK. */
  {
    wyl_dl_rule_t rules[] = { {"p", NULL, 0}
    };
    if (check (rules, 1) != WYRELOG_E_OK)
      return 5;
  }

  /* Case 6: linear chain r :- q. q :- p. -> OK. */
  {
    wyl_dl_body_atom_t body_r[] = { {"q", FALSE}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", FALSE}
    };
    wyl_dl_rule_t rules[] = {
      {"r", body_r, 1},
      {"q", body_q, 1},
    };
    if (check (rules, 2) != WYRELOG_E_OK)
      return 6;
  }

  /* Case 7: self-loop without negation p :- p. -> OK. */
  {
    wyl_dl_body_atom_t body[] = { {"p", FALSE}
    };
    wyl_dl_rule_t rules[] = { {"p", body, 1}
    };
    if (check (rules, 1) != WYRELOG_E_OK)
      return 7;
  }

  /* Case 8: self-loop with negation p :- \+ p. -> POLICY. */
  {
    wyl_dl_body_atom_t body[] = { {"p", TRUE}
    };
    wyl_dl_rule_t rules[] = { {"p", body, 1}
    };
    if (check (rules, 1) != WYRELOG_E_POLICY)
      return 8;
  }

  /* Case 9: mutual recursion without negation
   *   p :- q.  q :- p.  -> OK. */
  {
    wyl_dl_body_atom_t body_p[] = { {"q", FALSE}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", FALSE}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_p, 1},
      {"q", body_q, 1},
    };
    if (check (rules, 2) != WYRELOG_E_OK)
      return 9;
  }

  /* Case 10: mutual recursion with negation in cycle
   *   p :- \+ q.  q :- p.  -> POLICY. */
  {
    wyl_dl_body_atom_t body_p[] = { {"q", TRUE}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", FALSE}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_p, 1},
      {"q", body_q, 1},
    };
    if (check (rules, 2) != WYRELOG_E_POLICY)
      return 10;
  }

  /* Case 11: cross-stratum negation (no cycle through negation)
   *   p :- q.  r :- \+ p.   -> OK. */
  {
    wyl_dl_body_atom_t body_p[] = { {"q", FALSE}
    };
    wyl_dl_body_atom_t body_r[] = { {"p", TRUE}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_p, 1},
      {"r", body_r, 1},
    };
    if (check (rules, 2) != WYRELOG_E_OK)
      return 11;
  }

  /* Case 12: two SCCs connected by a negation edge that is NOT
   * inside either SCC.
   *   p :- p.            (singleton SCC {p})
   *   q :- q.            (singleton SCC {q})
   *   q :- \+ p.         (negation crosses SCC boundary)
   *  -> OK. */
  {
    wyl_dl_body_atom_t body_p_self[] = { {"p", FALSE}
    };
    wyl_dl_body_atom_t body_q_self[] = { {"q", FALSE}
    };
    wyl_dl_body_atom_t body_q_not_p[] = { {"p", TRUE}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_p_self, 1},
      {"q", body_q_self, 1},
      {"q", body_q_not_p, 1},
    };
    if (check (rules, 3) != WYRELOG_E_OK)
      return 12;
  }

  /* Case 13: multi-rule same head (no cycle)
   *   p :- q.  p :- r.  -> OK. */
  {
    wyl_dl_body_atom_t body_a[] = { {"q", FALSE}
    };
    wyl_dl_body_atom_t body_b[] = { {"r", FALSE}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_a, 1},
      {"p", body_b, 1},
    };
    if (check (rules, 2) != WYRELOG_E_OK)
      return 13;
  }

  /* --- Functional integrity constraint check ----------------- */

  /* Case 100: NULL rows with n > 0 -> INVALID. */
  if (wyl_dl_check_functional_ic (NULL, 1, 2, NULL) != WYRELOG_E_INVALID)
    return 100;

  /* Case 101: row.arity <= key_arity -> INVALID. */
  {
    const gchar *args[] = { "a", "b" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "t",.args = args,.arity = 2},
    };
    if (wyl_dl_check_functional_ic (rows, 1, 2, NULL) != WYRELOG_E_INVALID)
      return 101;
  }

  /* Case 102: NULL args[k] -> INVALID. */
  {
    const gchar *args[] = { "a", NULL, "c" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "t",.args = args,.arity = 3},
    };
    if (wyl_dl_check_functional_ic (rows, 1, 2, NULL) != WYRELOG_E_INVALID)
      return 102;
  }

  /* Case 103: pass -- two distinct keys. */
  {
    const gchar *r0[] = { "auth", "login_ok", "active" };
    const gchar *r1[] = { "anon", "login_ok", "auth" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "principal_transition",.args = r0,.arity = 3},
      {.head = "principal_transition",.args = r1,.arity = 3},
    };
    if (wyl_dl_check_functional_ic (rows, 2, 2, NULL) != WYRELOG_E_OK)
      return 103;
  }

  /* Case 104: reject (B) -- (auth, login_ok) -> {mfa_required, active}. */
  {
    const gchar *r0[] = { "auth", "login_ok", "mfa_required" };
    const gchar *r1[] = { "auth", "login_ok", "active" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "principal_transition",.args = r0,.arity = 3},
      {.head = "principal_transition",.args = r1,.arity = 3},
    };
    wyl_dl_ic_violation_t w = { 0 };
    if (wyl_dl_check_functional_ic (rows, 2, 2, &w) != WYRELOG_E_POLICY)
      return 104;
    if (g_strcmp0 (w.head, "principal_transition") != 0)
      return 1041;
    if (w.key_arity != 2)
      return 1042;
    if (g_strcmp0 (w.key[0], "auth") != 0)
      return 1043;
    if (g_strcmp0 (w.key[1], "login_ok") != 0)
      return 1044;
    if (g_strcmp0 (w.value_a, "mfa_required") != 0)
      return 1045;
    if (g_strcmp0 (w.value_b, "active") != 0)
      return 1046;
    if (w.first_index != 0)
      return 1047;
    if (w.conflict_index != 1)
      return 1048;
  }

  /* Case 105: reject (C) -- mix of valid + non-functional rows. */
  {
    const gchar *r0[] = { "x", "e1", "y" };
    const gchar *r1[] = { "y", "e2", "z" };
    const gchar *r2[] = { "z", "e3", "w" };
    const gchar *r3[] = { "x", "e1", "different" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "t",.args = r0,.arity = 3},
      {.head = "t",.args = r1,.arity = 3},
      {.head = "t",.args = r2,.arity = 3},
      {.head = "t",.args = r3,.arity = 3},
    };
    wyl_dl_ic_violation_t w = { 0 };
    if (wyl_dl_check_functional_ic (rows, 4, 2, &w) != WYRELOG_E_POLICY)
      return 105;
    if (w.first_index != 0 || w.conflict_index != 3)
      return 1051;
  }

  /* Case 106: literal duplicate (same key, same tail) -> OK. */
  {
    const gchar *r0[] = { "a", "b", "c" };
    const gchar *r1[] = { "a", "b", "c" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "t",.args = r0,.arity = 3},
      {.head = "t",.args = r1,.arity = 3},
    };
    if (wyl_dl_check_functional_ic (rows, 2, 2, NULL) != WYRELOG_E_OK)
      return 106;
  }

  /* Case 107: NULL out_witness on POLICY case -> still POLICY. */
  {
    const gchar *r0[] = { "a", "b", "c" };
    const gchar *r1[] = { "a", "b", "d" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "t",.args = r0,.arity = 3},
      {.head = "t",.args = r1,.arity = 3},
    };
    if (wyl_dl_check_functional_ic (rows, 2, 2, NULL) != WYRELOG_E_POLICY)
      return 107;
  }

  /* Case 108: cross-head same key -> OK (heads differentiate the group). */
  {
    const gchar *r0[] = { "a", "b", "c" };
    const gchar *r1[] = { "a", "b", "d" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "principal_transition",.args = r0,.arity = 3},
      {.head = "session_transition",.args = r1,.arity = 3},
    };
    if (wyl_dl_check_functional_ic (rows, 2, 2, NULL) != WYRELOG_E_OK)
      return 108;
  }

  /* --- Empty-extension assertion ----------------------------- */

  /* Case 110: empty rows -> OK. */
  if (wyl_dl_assert_edb_empty (NULL, 0, "policy_violation",
          NULL) != WYRELOG_E_OK)
    return 110;

  /* Case 111: rows present but none match expected_head -> OK. */
  {
    const gchar *r0[] = { "x" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "other",.args = r0,.arity = 1},
    };
    if (wyl_dl_assert_edb_empty (rows, 1, "policy_violation",
            NULL) != WYRELOG_E_OK)
      return 111;
  }

  /* Case 112: one matching row -> POLICY + witness pointer. */
  {
    const gchar *r0[] = { "sod", "u", "p", "w" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "policy_violation",.args = r0,.arity = 4},
    };
    const wyl_dl_fact_row_t *wit = NULL;
    if (wyl_dl_assert_edb_empty (rows, 1, "policy_violation",
            &wit) != WYRELOG_E_POLICY)
      return 112;
    if (wit != &rows[0])
      return 1121;
  }

  /* Case 113: NULL expected_head with non-empty rows -> POLICY. */
  {
    const gchar *r0[] = { "x" };
    wyl_dl_fact_row_t rows[] = {
      {.head = "anything",.args = r0,.arity = 1},
    };
    if (wyl_dl_assert_edb_empty (rows, 1, NULL, NULL) != WYRELOG_E_POLICY)
      return 113;
  }

  /* Case 114: NULL rows with n > 0 -> INVALID. */
  if (wyl_dl_assert_edb_empty (NULL, 1, "policy_violation",
          NULL) != WYRELOG_E_INVALID)
    return 114;

  return 0;
}
