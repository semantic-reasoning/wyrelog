/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include "wyrelog/fact/reconcile-private.h"

static void
classify (WylFactReconcileEvidence e, WylFactReconcileClass klass,
    WylFactReconcileAction action)
{
  WylFactReconcileResult result;
  g_assert_cmpint (wyl_fact_reconcile_classify (&e, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.classification, ==, klass);
  g_assert_cmpint (result.action, ==, action);
}

static void
test_precedence (void)
{
  WylFactReconcileEvidence e = {.raw_present = TRUE,.raw_valid = TRUE,
    .schema_registered = TRUE,.schema_valid = TRUE,.foreign = TRUE,
    .unsupported_newer = TRUE,.ambiguous = TRUE
  };
  classify (e, WYL_FACT_RECONCILE_AMBIGUOUS, WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.ambiguous = FALSE;
  classify (e, WYL_FACT_RECONCILE_FOREIGN, WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.foreign = FALSE;
  classify (e, WYL_FACT_RECONCILE_UNSUPPORTED_NEWER,
      WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.unsupported_newer = FALSE;
  classify (e, WYL_FACT_RECONCILE_EXISTING_VALID,
      WYL_FACT_RECONCILE_ACTION_RECONCILE);
}

static void
test_classes (void)
{
  WylFactReconcileEvidence e = { 0 };
  classify (e, WYL_FACT_RECONCILE_MISSING_WITHOUT_SCHEMA,
      WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.schema_registered = TRUE;
  classify (e, WYL_FACT_RECONCILE_MISSING_WITH_SCHEMA,
      WYL_FACT_RECONCILE_ACTION_DEGRADE);
  e.canonical_present = TRUE;
  classify (e, WYL_FACT_RECONCILE_CORRUPT, WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.canonical_valid = TRUE;
  e.schema_valid = TRUE;
  classify (e, WYL_FACT_RECONCILE_EXISTING_VALID,
      WYL_FACT_RECONCILE_ACTION_RECONCILE);
  e.raw_present = TRUE;
  e.raw_valid = TRUE;
  classify (e, WYL_FACT_RECONCILE_PARTIAL, WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.raw_valid = FALSE;
  classify (e, WYL_FACT_RECONCILE_PARTIAL, WYL_FACT_RECONCILE_ACTION_REVIEW);
  e.raw_present = FALSE;
  e.orphan = TRUE;
  classify (e, WYL_FACT_RECONCILE_ORPHAN, WYL_FACT_RECONCILE_ACTION_REVIEW);
}

static void
test_invalid (void)
{
  WylFactReconcileResult result;
  g_assert_cmpint (wyl_fact_reconcile_classify (NULL, &result), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_reconcile_classify (NULL, NULL), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpstr (wyl_fact_reconcile_class_name (99), ==, "ambiguous");
  g_assert_cmpstr (wyl_fact_reconcile_class_name (-1), ==, "ambiguous");
  g_assert_cmpstr (wyl_fact_reconcile_action_name (-1), ==, "review");
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/reconcile/precedence", test_precedence);
  g_test_add_func ("/fact/reconcile/classes", test_classes);
  g_test_add_func ("/fact/reconcile/invalid", test_invalid);
  return g_test_run ();
}
