/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/fact/reconcile-private.h"

/* Precedence is deliberately explicit.  Safety overrides all positive
 * evidence, so a foreign/ambiguous/newer artifact can never be adopted. */
wyrelog_error_t
wyl_fact_reconcile_classify (const WylFactReconcileEvidence *e,
    WylFactReconcileResult *out)
{
  if (e == NULL || out == NULL)
    return WYRELOG_E_INVALID;

  out->classification = WYL_FACT_RECONCILE_AMBIGUOUS;
  out->action = WYL_FACT_RECONCILE_ACTION_REVIEW;

  if (e->ambiguous)
    return WYRELOG_E_OK;
  if (e->path_collision) {
    out->classification = WYL_FACT_RECONCILE_PATH_COLLISION;
    return WYRELOG_E_OK;
  }
  if (e->foreign) {
    out->classification = WYL_FACT_RECONCILE_FOREIGN;
    return WYRELOG_E_OK;
  }
  if (e->unsupported_newer) {
    out->classification = WYL_FACT_RECONCILE_UNSUPPORTED_NEWER;
    return WYRELOG_E_OK;
  }
  if (e->orphan) {
    out->classification = WYL_FACT_RECONCILE_ORPHAN;
    return WYRELOG_E_OK;
  }

  if (e->raw_present && e->canonical_present) {
    out->classification = (e->raw_valid && e->canonical_valid)
        ? WYL_FACT_RECONCILE_PATH_COLLISION : WYL_FACT_RECONCILE_PARTIAL;
    return WYRELOG_E_OK;
  }
  if (e->raw_present || e->canonical_present) {
    gboolean valid = e->raw_present ? e->raw_valid : e->canonical_valid;
    if (!valid) {
      out->classification = WYL_FACT_RECONCILE_CORRUPT;
      return WYRELOG_E_OK;
    }
    if (!e->schema_registered) {
      out->classification = WYL_FACT_RECONCILE_MISSING_WITHOUT_SCHEMA;
      return WYRELOG_E_OK;
    }
    if (!e->schema_valid) {
      out->classification = WYL_FACT_RECONCILE_CORRUPT;
      return WYRELOG_E_OK;
    }
    out->classification = WYL_FACT_RECONCILE_EXISTING_VALID;
    out->action = WYL_FACT_RECONCILE_ACTION_ADOPT;
    return WYRELOG_E_OK;
  }

  out->classification = e->schema_registered
      ? WYL_FACT_RECONCILE_MISSING_WITH_SCHEMA
      : WYL_FACT_RECONCILE_MISSING_WITHOUT_SCHEMA;
  return WYRELOG_E_OK;
}

const gchar *
wyl_fact_reconcile_class_name (WylFactReconcileClass v)
{
  static const gchar *names[] = { "existing-valid", "missing-without-schema",
    "missing-with-schema", "partial", "corrupt", "foreign",
    "unsupported-newer", "path-collision", "ambiguous", "orphan"
  };
  return v < G_N_ELEMENTS (names) ? names[v] : "ambiguous";
}

const gchar *
wyl_fact_reconcile_action_name (WylFactReconcileAction v)
{
  static const gchar *names[] = { "none", "adopt", "degrade", "review" };
  return v < G_N_ELEMENTS (names) ? names[v] : "review";
}
