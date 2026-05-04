/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/engine.h"

/* Allow direct access to internal struct fields for after-close tests. */
#define WYL_ENGINE_INTERNAL 1
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static WylEngine *
open_engine_from_real_templates (void)
{
  WylEngine *engine = NULL;
  wyrelog_error_t rc = wyl_engine_open (WYL_TEST_TEMPLATE_DIR, 1, &engine);

  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_nonnull (engine);

  return engine;
}

static void
build_member_of_row (WylEngine *engine, gint64 row[3])
{
  gint64 role_id = -1;
  gint64 resource_id = -1;
  wyrelog_error_t rc;

  rc = wyl_engine_intern_symbol (engine, "wr.viewer", &role_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (role_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "resource-a", &resource_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (resource_id, >=, 0);

  row[0] = 7;
  row[1] = role_id;
  row[2] = resource_id;
}

static void
test_insert_nominal (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3];

  build_member_of_row (engine, row);

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
}

static void
test_remove_nominal (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3];

  build_member_of_row (engine, row);

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_remove (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
}

static void
test_insert_remove_idempotent_remove (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3];

  build_member_of_row (engine, row);

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_remove (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_remove (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
}

static void
test_insert_null_self (void)
{
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_insert (NULL, "member_of", row, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_insert_null_relation (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_insert (engine, NULL, row, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_insert_null_row (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", NULL, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_insert_zero_ncols (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 0),
      ==, WYRELOG_E_INVALID);
}

static void
test_insert_after_close (void)
{
  WylEngine *engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  wl_easy_close (engine->session);
  engine->session = NULL;

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 3),
      ==, WYRELOG_E_INVALID);

  g_object_unref (engine);
}

static void
test_remove_null_self (void)
{
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_remove (NULL, "member_of", row, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_remove_null_relation (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_remove (engine, NULL, row, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_remove_null_row (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();

  g_assert_cmpint (wyl_engine_remove (engine, "member_of", NULL, 3),
      ==, WYRELOG_E_INVALID);
}

static void
test_remove_zero_ncols (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  g_assert_cmpint (wyl_engine_remove (engine, "member_of", row, 0),
      ==, WYRELOG_E_INVALID);
}

static void
test_remove_after_close (void)
{
  WylEngine *engine = open_engine_from_real_templates ();
  gint64 row[3] = { 1, 2, 3 };

  wl_easy_close (engine->session);
  engine->session = NULL;

  g_assert_cmpint (wyl_engine_remove (engine, "member_of", row, 3),
      ==, WYRELOG_E_INVALID);

  g_object_unref (engine);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/engine-io/insert-nominal", test_insert_nominal);
  g_test_add_func ("/engine-io/remove-nominal", test_remove_nominal);
  g_test_add_func ("/engine-io/insert-remove-idempotent-remove",
      test_insert_remove_idempotent_remove);
  g_test_add_func ("/engine-io/insert-null-self", test_insert_null_self);
  g_test_add_func ("/engine-io/insert-null-relation",
      test_insert_null_relation);
  g_test_add_func ("/engine-io/insert-null-row", test_insert_null_row);
  g_test_add_func ("/engine-io/insert-zero-ncols", test_insert_zero_ncols);
  g_test_add_func ("/engine-io/insert-after-close", test_insert_after_close);
  g_test_add_func ("/engine-io/remove-null-self", test_remove_null_self);
  g_test_add_func ("/engine-io/remove-null-relation",
      test_remove_null_relation);
  g_test_add_func ("/engine-io/remove-null-row", test_remove_null_row);
  g_test_add_func ("/engine-io/remove-zero-ncols", test_remove_zero_ncols);
  g_test_add_func ("/engine-io/remove-after-close", test_remove_after_close);

  return g_test_run ();
}
