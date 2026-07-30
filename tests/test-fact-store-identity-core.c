/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "fact/store-identity-private.h"

typedef struct
{
  gboolean rollback_fails;
  guint inserts;
  gboolean leaked_identity;
} FakeExecutor;

static gboolean
emit_count (WylFactStoreIdentityRowFunc row_func, gpointer row_data,
    guint64 *out_rows, gint64 count)
{
  WylFactStoreIdentityCell cell = {
    .type = WYL_FACT_STORE_IDENTITY_CELL_INT64,
    .as.int64_value = count,
  };
  *out_rows = 1;
  return row_func != NULL && row_func (&cell, 1, row_data);
}

static wyrelog_error_t
fake_execute (gpointer context, const gchar *sql,
    const WylFactStoreIdentityCell *params, gsize n_params,
    WylFactStoreIdentityRowFunc row_func, gpointer row_data, guint64 *out_rows)
{
  FakeExecutor *fake = context;
  *out_rows = 0;
  if (strstr (sql, "tenant-a") != NULL || strstr (sql, "graph-a") != NULL
      || strstr (sql, "01890f47-3c4b-6cc2-b8c4-dc0c0c073989") != NULL)
    fake->leaked_identity = TRUE;
  if (strcmp (sql, "ROLLBACK;") == 0 && fake->rollback_fails)
    return WYRELOG_E_IO;
  if (strstr (sql, "SELECT CAST(COUNT(*) AS BIGINT)") != NULL)
    return emit_count (row_func, row_data, out_rows, 0) ?
        WYRELOG_E_OK : WYRELOG_E_IO;
  if (strstr (sql, "VALUES (?,?)") != NULL) {
    g_assert_cmpuint (n_params, ==, 2);
    g_assert_nonnull (params);
    g_assert_cmpint (params[0].type, ==, WYL_FACT_STORE_IDENTITY_CELL_BYTES);
    g_assert_cmpint (params[1].type, ==, WYL_FACT_STORE_IDENTITY_CELL_BYTES);
    fake->inserts++;
  } else {
    g_assert_cmpuint (n_params, ==, 0);
  }
  return WYRELOG_E_OK;
}

static const WylFactStoreIdentity identity = {
  "tenant-a",
  "graph-a",
  "01890f47-3c4b-6cc2-b8c4-dc0c0c073989",
  1,
  1,
};

static void
test_prepared_identity_and_rollback_precedence (void)
{
  FakeExecutor fake = { 0 };
  WylFactStoreIdentityExecutor executor = {
    &fake, fake_execute, NULL
  };
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;

  wyl_fact_store_identity_set_test_fault
      (WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_STORE_KIND);
  g_assert_cmpint (wyl_fact_store_identity_execute (&executor, &identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
      WYRELOG_E_INTERNAL);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
  g_assert_cmpuint (fake.inserts, ==, 1);
  g_assert_false (fake.leaked_identity);

  fake = (FakeExecutor) {
  .rollback_fails = TRUE};
  wyl_fact_store_identity_set_test_fault
      (WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE);
  g_assert_cmpint (wyl_fact_store_identity_execute (&executor, &identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
      WYRELOG_E_INTERNAL);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL);
}

static void
test_mode_cross_values_do_not_execute (void)
{
  FakeExecutor fake = { 0 };
  WylFactStoreIdentityExecutor executor = {
    &fake, fake_execute, NULL
  };
  const gint invalid[] = { -1, 2, G_MAXINT };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_identity_execute (&executor, &identity,
            (WylFactStoreIdentityOpenMode) invalid[i], &result), ==,
        WYRELOG_E_INVALID);
    g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-store-identity-core/prepared-rollback",
      test_prepared_identity_and_rollback_precedence);
  g_test_add_func ("/fact-store-identity-core/mode-cross-values",
      test_mode_cross_values_do_not_execute);
  return g_test_run ();
}
