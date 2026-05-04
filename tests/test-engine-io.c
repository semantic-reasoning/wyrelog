/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/engine.h"

/* Allow direct access to internal struct fields for after-close tests. */
#define WYL_ENGINE_INTERNAL 1
#include "wyrelog/wyl-engine-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  const gchar *relation;
  const gint64 *expected_row;
  guint expected_ncols;
  guint seen;
} SnapshotExpect;

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
  gint64 user_id = -1;
  gint64 role_id = -1;
  gint64 resource_id = -1;
  wyrelog_error_t rc;

  rc = wyl_engine_intern_symbol (engine, "user-a", &user_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (user_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "wr.viewer", &role_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (role_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "resource-a", &resource_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (resource_id, >=, 0);

  row[0] = user_id;
  row[1] = role_id;
  row[2] = resource_id;
}

static void
build_snapshot_rows (WylEngine *engine, gint64 member_row[3],
    gint64 role_permission_row[2], gint64 expected_permission_row[3])
{
  gint64 user_id = -1;
  gint64 role_id = -1;
  gint64 permission_id = -1;
  gint64 resource_id = -1;
  wyrelog_error_t rc;

  rc = wyl_engine_intern_symbol (engine, "snapshot-user-a", &user_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (user_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "wr.snapshot-role-a", &role_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (role_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "wr.snapshot-permission-a",
      &permission_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (permission_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "snapshot-resource-a", &resource_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (resource_id, >=, 0);

  member_row[0] = user_id;
  member_row[1] = role_id;
  member_row[2] = resource_id;

  role_permission_row[0] = role_id;
  role_permission_row[1] = permission_id;

  expected_permission_row[0] = user_id;
  expected_permission_row[1] = permission_id;
  expected_permission_row[2] = resource_id;
}

static void
snapshot_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SnapshotExpect *expect = user_data;

  g_assert_cmpstr (relation, ==, expect->relation);
  g_assert_cmpuint (ncols, ==, expect->expected_ncols);
  for (guint i = 0; i < ncols; i++)
    g_assert_cmpint (row[i], ==, expect->expected_row[i]);

  expect->seen++;
}

static void
snapshot_count_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  guint *seen = user_data;

  (void) relation;
  (void) row;
  (void) ncols;

  (*seen)++;
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
test_step_nominal (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 row[3];

  build_member_of_row (engine, row);

  g_assert_cmpint (wyl_engine_insert (engine, "member_of", row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);
}

static void
test_step_after_snapshot_rejected (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  guint seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (engine, "member_of",
          snapshot_count_cb, &seen), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_INVALID);
}

static void
test_snapshot_after_step_rejected (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  guint seen = 0;

  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_snapshot (engine, "member_of",
          snapshot_count_cb, &seen), ==, WYRELOG_E_INVALID);
}

static void
test_snapshot_observes_inserted_row (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 role_permission_row[2];
  gint64 expected_permission_row[3];
  SnapshotExpect expect;

  build_snapshot_rows (engine, member_row, role_permission_row,
      expected_permission_row);

  g_assert_cmpint (wyl_engine_insert (engine, "role_permission",
          role_permission_row, 2), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);

  expect.relation = "has_permission";
  expect.expected_row = expected_permission_row;
  expect.expected_ncols = 3;
  expect.seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (engine, "has_permission",
          snapshot_expect_cb, &expect), ==, WYRELOG_E_OK);
  g_assert_cmpuint (expect.seen, ==, 1);
}

static void
test_snapshot_observes_removed_row (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 role_permission_row[2];
  gint64 expected_permission_row[3];
  guint seen = 0;

  build_snapshot_rows (engine, member_row, role_permission_row,
      expected_permission_row);

  g_assert_cmpint (wyl_engine_insert (engine, "role_permission",
          role_permission_row, 2), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_remove (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_snapshot (engine, "has_permission",
          snapshot_count_cb, &seen), ==, WYRELOG_E_OK);
  g_assert_cmpuint (seen, ==, 0);
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
test_step_null_self (void)
{
  g_assert_cmpint (wyl_engine_step (NULL), ==, WYRELOG_E_INVALID);
}

static void
test_step_after_close (void)
{
  WylEngine *engine = open_engine_from_real_templates ();

  wl_easy_close (engine->session);
  engine->session = NULL;

  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_INVALID);

  g_object_unref (engine);
}

static void
test_snapshot_null_self (void)
{
  guint seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (NULL, "member_of", snapshot_count_cb,
          &seen), ==, WYRELOG_E_INVALID);
}

static void
test_snapshot_null_relation (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  guint seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (engine, NULL, snapshot_count_cb,
          &seen), ==, WYRELOG_E_INVALID);
}

static void
test_snapshot_null_cb (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  guint seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (engine, "member_of", NULL, &seen),
      ==, WYRELOG_E_INVALID);
}

static void
test_snapshot_after_close (void)
{
  WylEngine *engine = open_engine_from_real_templates ();
  guint seen = 0;

  wl_easy_close (engine->session);
  engine->session = NULL;

  g_assert_cmpint (wyl_engine_snapshot (engine, "member_of",
          snapshot_count_cb, &seen), ==, WYRELOG_E_INVALID);

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
  g_test_add_func ("/engine-io/step-nominal", test_step_nominal);
  g_test_add_func ("/engine-io/step-after-snapshot-rejected",
      test_step_after_snapshot_rejected);
  g_test_add_func ("/engine-io/snapshot-after-step-rejected",
      test_snapshot_after_step_rejected);
  g_test_add_func ("/engine-io/snapshot-observes-inserted-row",
      test_snapshot_observes_inserted_row);
  g_test_add_func ("/engine-io/snapshot-observes-removed-row",
      test_snapshot_observes_removed_row);
  g_test_add_func ("/engine-io/insert-null-self", test_insert_null_self);
  g_test_add_func ("/engine-io/insert-null-relation",
      test_insert_null_relation);
  g_test_add_func ("/engine-io/insert-null-row", test_insert_null_row);
  g_test_add_func ("/engine-io/insert-zero-ncols", test_insert_zero_ncols);
  g_test_add_func ("/engine-io/insert-after-close", test_insert_after_close);
  g_test_add_func ("/engine-io/step-null-self", test_step_null_self);
  g_test_add_func ("/engine-io/step-after-close", test_step_after_close);
  g_test_add_func ("/engine-io/snapshot-null-self", test_snapshot_null_self);
  g_test_add_func ("/engine-io/snapshot-null-relation",
      test_snapshot_null_relation);
  g_test_add_func ("/engine-io/snapshot-null-cb", test_snapshot_null_cb);
  g_test_add_func ("/engine-io/snapshot-after-close",
      test_snapshot_after_close);
  g_test_add_func ("/engine-io/remove-null-self", test_remove_null_self);
  g_test_add_func ("/engine-io/remove-null-relation",
      test_remove_null_relation);
  g_test_add_func ("/engine-io/remove-null-row", test_remove_null_row);
  g_test_add_func ("/engine-io/remove-zero-ncols", test_remove_zero_ncols);
  g_test_add_func ("/engine-io/remove-after-close", test_remove_after_close);

  return g_test_run ();
}
