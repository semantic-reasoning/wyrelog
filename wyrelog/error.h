/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

typedef enum wyrelog_error_t
{
  WYRELOG_E_OK = 0,
  WYRELOG_E_INVALID = -1,
  WYRELOG_E_NOMEM = -2,
  WYRELOG_E_IO = -3,
  WYRELOG_E_CRYPTO = -4,
  WYRELOG_E_POLICY = -5,
  WYRELOG_E_AUTH = -6,
  WYRELOG_E_INTERNAL = -7,
  /*
   * Runtime fault inside the embedded Datalog evaluator after a
   * successful policy load: e.g. recursion/aggregate overflow,
   * dynamic negation cycle, or a fact-shape mismatch surfaced at
   * evaluation time. Distinct from WYRELOG_E_POLICY (load-time
   * shape error) and WYRELOG_E_INTERNAL (wyrelog-side invariant
   * violation) so operators can route incidents correctly.
   */
  WYRELOG_E_EXEC = -8,
} wyrelog_error_t;

const gchar *wyrelog_error_string (wyrelog_error_t err);

G_END_DECLS;
