/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/wyl-dl-static-private.h"

static int
check (const wyl_dl_rule_t *rules, size_t n)
{
  return (int) wyl_dl_static_check (rules, n);
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
    wyl_dl_body_atom_t body[] = { {NULL, false}
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
    wyl_dl_body_atom_t body_r[] = { {"q", false}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", false}
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
    wyl_dl_body_atom_t body[] = { {"p", false}
    };
    wyl_dl_rule_t rules[] = { {"p", body, 1}
    };
    if (check (rules, 1) != WYRELOG_E_OK)
      return 7;
  }

  /* Case 8: self-loop with negation p :- \+ p. -> POLICY. */
  {
    wyl_dl_body_atom_t body[] = { {"p", true}
    };
    wyl_dl_rule_t rules[] = { {"p", body, 1}
    };
    if (check (rules, 1) != WYRELOG_E_POLICY)
      return 8;
  }

  /* Case 9: mutual recursion without negation
   *   p :- q.  q :- p.  -> OK. */
  {
    wyl_dl_body_atom_t body_p[] = { {"q", false}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", false}
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
    wyl_dl_body_atom_t body_p[] = { {"q", true}
    };
    wyl_dl_body_atom_t body_q[] = { {"p", false}
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
    wyl_dl_body_atom_t body_p[] = { {"q", false}
    };
    wyl_dl_body_atom_t body_r[] = { {"p", true}
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
    wyl_dl_body_atom_t body_p_self[] = { {"p", false}
    };
    wyl_dl_body_atom_t body_q_self[] = { {"q", false}
    };
    wyl_dl_body_atom_t body_q_not_p[] = { {"p", true}
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
    wyl_dl_body_atom_t body_a[] = { {"q", false}
    };
    wyl_dl_body_atom_t body_b[] = { {"r", false}
    };
    wyl_dl_rule_t rules[] = {
      {"p", body_a, 1},
      {"p", body_b, 1},
    };
    if (check (rules, 2) != WYRELOG_E_OK)
      return 13;
  }

  return 0;
}
