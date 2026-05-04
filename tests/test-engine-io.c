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

typedef struct
{
  const gchar *expected_relation;
  const gint64 (*expected_rows)[3];
  guint expected_row_count;
  WylDeltaKind expected_kind;
  guint invoked;
  guint matching;
  gchar *last_relation;
  WylDeltaKind last_kind;
} DeltaExpect;

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
build_delta_rows (WylEngine *engine, gint64 member_row[3],
    gint64 expected_member_rows[1][3])
{
  gint64 user_id = -1;
  gint64 role_id = -1;
  gint64 scope_id = -1;
  wyrelog_error_t rc;

  rc = wyl_engine_intern_symbol (engine, "alice", &user_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (user_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "wr.viewer", &role_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (role_id, >=, 0);

  rc = wyl_engine_intern_symbol (engine, "scope1", &scope_id);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (scope_id, >=, 0);

  member_row[0] = user_id;
  member_row[1] = role_id;
  member_row[2] = scope_id;

  expected_member_rows[0][0] = user_id;
  expected_member_rows[0][1] = role_id;
  expected_member_rows[0][2] = scope_id;
}

static gboolean
delta_row_matches (const DeltaExpect *expect, const gint64 *row, guint ncols)
{
  if (ncols != 3)
    return FALSE;

  for (guint i = 0; i < expect->expected_row_count; i++) {
    gboolean matches = TRUE;

    for (guint j = 0; j < ncols; j++) {
      if (row[j] != expect->expected_rows[i][j]) {
        matches = FALSE;
        break;
      }
    }

    if (matches)
      return TRUE;
  }

  return FALSE;
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
delta_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  DeltaExpect *expect = user_data;

  expect->invoked++;
  g_clear_pointer (&expect->last_relation, g_free);
  expect->last_relation = g_strdup (relation);
  expect->last_kind = kind;

  if (g_strcmp0 (relation, expect->expected_relation) == 0
      && kind == expect->expected_kind && delta_row_matches (expect, row,
          ncols)) {
    expect->matching++;
  }
}

static void
delta_expect_reset (DeltaExpect *expect)
{
  expect->invoked = 0;
  expect->matching = 0;
  g_clear_pointer (&expect->last_relation, g_free);
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
  /* Pin: the wirelog substrate currently treats removing a never-inserted row
   * as a no-op update.  This test exists to detect a future upstream change
   * that promotes the case to an error. */
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
test_delta_nominal (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 expected_member_rows[1][3];
  DeltaExpect expect = {
    "effective_member",
    expected_member_rows,
    1,
    WYL_DELTA_INSERT,
    0,
    0,
    NULL,
    0,
  };

  build_delta_rows (engine, member_row, expected_member_rows);

  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          &expect), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);

  g_assert_cmpuint (expect.matching, >=, 1);
  g_assert_cmpstr (expect.last_relation, !=, NULL);

  g_clear_pointer (&expect.last_relation, g_free);
}

static void
test_delta_remove (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 expected_member_rows[1][3];
  DeltaExpect expect = {
    "effective_member",
    expected_member_rows,
    1,
    WYL_DELTA_INSERT,
    0,
    0,
    NULL,
    0,
  };

  build_delta_rows (engine, member_row, expected_member_rows);

  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          &expect), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);
  g_assert_cmpuint (expect.matching, >=, 1);

  delta_expect_reset (&expect);
  expect.expected_kind = WYL_DELTA_REMOVE;

  g_assert_cmpint (wyl_engine_remove (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);

  g_assert_cmpuint (expect.matching, >=, 1);
  g_assert_cmpstr (expect.last_relation, !=, NULL);

  g_clear_pointer (&expect.last_relation, g_free);
}

static void
test_delta_clear (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 expected_member_rows[1][3];
  DeltaExpect expect = {
    "effective_member",
    expected_member_rows,
    1,
    WYL_DELTA_INSERT,
    0,
    0,
    NULL,
    0,
  };

  build_delta_rows (engine, member_row, expected_member_rows);

  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          &expect), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_set_delta_callback (engine, NULL, NULL),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);

  g_assert_cmpuint (expect.invoked, ==, 0);
}

static void
test_delta_replace (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  gint64 member_row[3];
  gint64 expected_member_rows[1][3];
  DeltaExpect expect_a = {
    "effective_member",
    expected_member_rows,
    1,
    WYL_DELTA_INSERT,
    0,
    0,
    NULL,
    0,
  };
  DeltaExpect expect_b = {
    "effective_member",
    expected_member_rows,
    1,
    WYL_DELTA_INSERT,
    0,
    0,
    NULL,
    0,
  };

  build_delta_rows (engine, member_row, expected_member_rows);

  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          &expect_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          &expect_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_insert (engine, "member_of", member_row, 3),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_step (engine), ==, WYRELOG_E_OK);

  g_assert_cmpuint (expect_a.invoked, ==, 0);
  g_assert_cmpuint (expect_b.matching, >=, 1);

  g_clear_pointer (&expect_a.last_relation, g_free);
  g_clear_pointer (&expect_b.last_relation, g_free);
}

static void
test_delta_after_snapshot_rejected (void)
{
  g_autoptr (WylEngine) engine = open_engine_from_real_templates ();
  guint seen = 0;

  g_assert_cmpint (wyl_engine_snapshot (engine, "member_of",
          snapshot_count_cb, &seen), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          NULL), ==, WYRELOG_E_INVALID);
}

static void
test_delta_null_self (void)
{
  g_assert_cmpint (wyl_engine_set_delta_callback (NULL, delta_expect_cb, NULL),
      ==, WYRELOG_E_INVALID);
}

static void
test_delta_after_close (void)
{
  WylEngine *engine = open_engine_from_real_templates ();

  wl_easy_close (engine->session);
  engine->session = NULL;

  g_assert_cmpint (wyl_engine_set_delta_callback (engine, delta_expect_cb,
          NULL), ==, WYRELOG_E_INVALID);

  /* g_autoptr is intentionally not used: the test mutates engine->session via
   * the private header, and that reach-in is incompatible with autoptr's
   * blanket cleanup discipline.  On assertion failure the engine leaks until
   * process exit, which is acceptable for a test-side fixture. */
  g_object_unref (engine);
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

  /* g_autoptr is intentionally not used: the test mutates engine->session via
   * the private header, and that reach-in is incompatible with autoptr's
   * blanket cleanup discipline.  On assertion failure the engine leaks until
   * process exit, which is acceptable for a test-side fixture. */
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

  /* g_autoptr is intentionally not used: the test mutates engine->session via
   * the private header, and that reach-in is incompatible with autoptr's
   * blanket cleanup discipline.  On assertion failure the engine leaks until
   * process exit, which is acceptable for a test-side fixture. */
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

  /* g_autoptr is intentionally not used: the test mutates engine->session via
   * the private header, and that reach-in is incompatible with autoptr's
   * blanket cleanup discipline.  On assertion failure the engine leaks until
   * process exit, which is acceptable for a test-side fixture. */
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

  /* g_autoptr is intentionally not used: the test mutates engine->session via
   * the private header, and that reach-in is incompatible with autoptr's
   * blanket cleanup discipline.  On assertion failure the engine leaks until
   * process exit, which is acceptable for a test-side fixture. */
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
  g_test_add_func ("/engine-io/delta-nominal", test_delta_nominal);
  g_test_add_func ("/engine-io/delta-remove", test_delta_remove);
  g_test_add_func ("/engine-io/delta-clear", test_delta_clear);
  g_test_add_func ("/engine-io/delta-replace", test_delta_replace);
  g_test_add_func ("/engine-io/delta-after-snapshot-rejected",
      test_delta_after_snapshot_rejected);
  g_test_add_func ("/engine-io/delta-null-self", test_delta_null_self);
  g_test_add_func ("/engine-io/delta-after-close", test_delta_after_close);
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
