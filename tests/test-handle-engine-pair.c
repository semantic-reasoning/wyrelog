/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  const gint64 *expected_row;
  guint seen;
} SnapshotExpect;

typedef struct
{
  const gchar *expected_relation;
  const gint64 *expected_row;
  WylDeltaKind expected_kind;
  guint matching;
} DeltaExpect;

static void
snapshot_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SnapshotExpect *expect = user_data;

  if (g_strcmp0 (relation, "has_permission") != 0 || ncols != 3)
    return;
  if (row[0] == expect->expected_row[0] && row[1] == expect->expected_row[1]
      && row[2] == expect->expected_row[2]) {
    expect->seen++;
  }
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

  if (g_strcmp0 (relation, expect->expected_relation) != 0 || ncols != 3)
    return;
  if (kind != expect->expected_kind)
    return;
  if (row[0] == expect->expected_row[0] && row[1] == expect->expected_row[1]
      && row[2] == expect->expected_row[2]) {
    expect->matching++;
  }
}

static wyrelog_error_t
intern3 (WylHandle *handle, const gchar *a, const gchar *b, const gchar *c,
    gint64 row[3])
{
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, c, &row[2]);
}

static wyrelog_error_t
insert1_symbol (WylHandle *handle, const gchar *relation, const gchar *a)
{
  gint64 row[1];

  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 1);
}

static wyrelog_error_t
insert_decision_fixture (WylHandle *handle, const gchar *user,
    const gchar *role, const gchar *permission, const gchar *scope,
    const gchar *principal_state, const gchar *session_state,
    gint64 decision_row[3])
{
  gint64 member_row[3];
  gint64 principal_state_row[2];
  gint64 session_state_row[2];
  wyrelog_error_t rc = intern3 (handle, user, role, scope, member_row);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 role_permission_row[2] = { member_row[1], -1 };
  rc = wyl_handle_intern_engine_symbol (handle, permission,
      &role_permission_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (handle, "role_permission",
      role_permission_row, 2);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (handle, "member_of", member_row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;

  principal_state_row[0] = member_row[0];
  rc = wyl_handle_intern_engine_symbol (handle, principal_state,
      &principal_state_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (handle, "principal_state",
      principal_state_row, 2);
  if (rc != WYRELOG_E_OK)
    return rc;

  session_state_row[0] = member_row[2];
  rc = wyl_handle_intern_engine_symbol (handle, session_state,
      &session_state_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (handle, "session_state", session_state_row, 2);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = insert1_symbol (handle, "session_active", session_state);
  if (rc != WYRELOG_E_OK)
    return rc;

  decision_row[0] = member_row[0];
  decision_row[1] = role_permission_row[1];
  decision_row[2] = member_row[2];
  return WYRELOG_E_OK;
}

static gint
check_init_keeps_engines_absent (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 11;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 12;
  return 0;
}

static gint
check_open_pair_creates_distinct_engines (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 21;
  WylEngine *read_engine = wyl_handle_get_read_engine (handle);
  WylEngine *delta_engine = wyl_handle_get_delta_engine (handle);
  if (read_engine == NULL)
    return 22;
  if (delta_engine == NULL)
    return 23;
  if (read_engine == delta_engine)
    return 24;
  return 0;
}

static gint
check_init_config_opens_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 25;
  if (wyl_handle_get_read_engine (handle) == NULL)
    return 26;
  if (wyl_handle_get_delta_engine (handle) == NULL)
    return 27;
  if (wyl_handle_get_read_engine (handle) == wyl_handle_get_delta_engine
      (handle))
    return 28;
  return 0;
}

static gint
check_invalid_template_pair_open_fails_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  if (wyl_handle_open_engine_pair (handle,
          "/definitely/not/a/wyrelog/template-dir")
      != WYRELOG_E_IO)
    return 31;
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 32;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 33;
  return 0;
}

static gint
check_invalid_config_init_fails_closed (void)
{
  WylHandle *handle = (WylHandle *) 0x1;

  if (wyl_init ("/definitely/not/a/wyrelog/template-dir", &handle)
      != WYRELOG_E_IO)
    return 35;
  if (handle != NULL)
    return 36;
  return 0;
}

static gint
check_shutdown_clears_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 41;
  wyl_shutdown (handle);
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 42;
  if (wyl_handle_get_delta_engine (handle) != NULL)
    return 43;
  return 0;
}

static gint
check_second_open_is_rejected (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 50;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 51;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_INVALID)
    return 52;
  return 0;
}

static gint
check_symbol_intern_reaches_both_engines (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 pair_id = -1;
  gint64 read_id = -1;
  gint64 delta_id = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 60;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 61;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-a", &pair_id)
      != WYRELOG_E_OK)
    return 62;
  if (pair_id < 0)
    return 63;
  if (wyl_engine_intern_symbol (wyl_handle_get_read_engine (handle),
          "pair-symbol-a", &read_id) != WYRELOG_E_OK)
    return 64;
  if (wyl_engine_intern_symbol (wyl_handle_get_delta_engine (handle),
          "pair-symbol-a", &delta_id) != WYRELOG_E_OK)
    return 65;
  if (pair_id != read_id)
    return 66;
  if (pair_id != delta_id)
    return 67;
  return 0;
}

static gint
check_symbol_intern_is_stable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 first = -1;
  gint64 second = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 70;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 71;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-b", &first)
      != WYRELOG_E_OK)
    return 72;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-b", &second)
      != WYRELOG_E_OK)
    return 73;
  if (first != second)
    return 74;
  return 0;
}

static gint
check_symbol_intern_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 id = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 80;
  if (wyl_handle_intern_engine_symbol (handle, "pair-symbol-c", &id)
      != WYRELOG_E_INVALID)
    return 81;
  if (id != -1)
    return 82;
  return 0;
}

static gint
check_insert_fanout_reaches_read_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 member_row[3];
  gint64 role_permission_row[2];
  gint64 expected_row[3];
  SnapshotExpect expect = { expected_row, 0 };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 90;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 91;
  if (intern3 (handle, "fanout-user-a", "wr.fanout-role-a", "fanout-scope-a",
          member_row) != WYRELOG_E_OK)
    return 92;
  expected_row[0] = member_row[0];
  role_permission_row[0] = member_row[1];
  if (wyl_handle_intern_engine_symbol (handle, "wr.fanout-permission-a",
          &expected_row[1]) != WYRELOG_E_OK)
    return 93;
  role_permission_row[1] = expected_row[1];
  expected_row[2] = member_row[2];

  if (wyl_handle_engine_insert (handle, "role_permission",
          role_permission_row, 2) != WYRELOG_E_OK)
    return 94;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 95;
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "has_permission", snapshot_expect_cb, &expect) != WYRELOG_E_OK)
    return 96;
  if (expect.seen != 1)
    return 97;
  return 0;
}

static gint
check_insert_fanout_reaches_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 member_row[3];
  DeltaExpect expect = {
    "effective_member",
    member_row,
    WYL_DELTA_INSERT,
    0,
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 100;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 101;
  if (intern3 (handle, "fanout-user-b", "wr.viewer", "fanout-scope-b",
          member_row) != WYRELOG_E_OK)
    return 102;
  if (wyl_engine_set_delta_callback (wyl_handle_get_delta_engine (handle),
          delta_expect_cb, &expect) != WYRELOG_E_OK)
    return 103;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 104;
  if (wyl_engine_step (wyl_handle_get_delta_engine (handle)) != WYRELOG_E_OK)
    return 105;
  if (expect.matching == 0)
    return 106;
  return 0;
}

static gint
check_remove_fanout_reaches_read_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 member_row[3];
  guint seen = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 110;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 111;
  if (intern3 (handle, "fanout-user-c", "wr.viewer", "fanout-scope-c",
          member_row) != WYRELOG_E_OK)
    return 112;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 113;
  if (wyl_handle_engine_remove (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 114;
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "effective_member", snapshot_count_cb, &seen) != WYRELOG_E_OK)
    return 115;
  if (seen != 0)
    return 116;
  return 0;
}

static gint
check_insert_fanout_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3] = { 1, 2, 3 };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 120;
  if (wyl_handle_engine_insert (handle, "member_of", row, 3)
      != WYRELOG_E_INVALID)
    return 121;
  if (wyl_handle_engine_remove (handle, "member_of", row, 3)
      != WYRELOG_E_INVALID)
    return 122;
  return 0;
}

static gint
check_decision_query_allows_matching_tuple (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = FALSE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 130;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 131;
  if (insert_decision_fixture (handle, "decision-user-a",
          "wr.decision-role-a", "wr.decision-permission-a",
          "decision-scope-a", "authenticated", "active", decision_row)
      != WYRELOG_E_OK)
    return 132;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 133;
  if (!allowed)
    return 134;
  return 0;
}

static gint
check_decision_query_denies_missing_tuple (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 140;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 141;
  if (insert_decision_fixture (handle, "decision-user-b",
          "wr.decision-role-b", "wr.decision-permission-b",
          "decision-scope-b", "unverified", "active", decision_row)
      != WYRELOG_E_OK)
    return 142;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 143;
  if (allowed)
    return 144;
  return 0;
}

static gint
check_decision_query_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3] = { 1, 2, 3 };
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 150;
  if (wyl_handle_engine_decide (handle, row, &allowed) != WYRELOG_E_INVALID)
    return 151;
  if (!allowed)
    return 152;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_init_keeps_engines_absent ()) != 0)
    return rc;
  if ((rc = check_open_pair_creates_distinct_engines ()) != 0)
    return rc;
  if ((rc = check_init_config_opens_engine_pair ()) != 0)
    return rc;
  if ((rc = check_invalid_template_pair_open_fails_closed ()) != 0)
    return rc;
  if ((rc = check_invalid_config_init_fails_closed ()) != 0)
    return rc;
  if ((rc = check_shutdown_clears_engine_pair ()) != 0)
    return rc;
  if ((rc = check_second_open_is_rejected ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_reaches_both_engines ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_is_stable ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_read_engine ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_delta_engine ()) != 0)
    return rc;
  if ((rc = check_remove_fanout_reaches_read_engine ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_decision_query_allows_matching_tuple ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_missing_tuple ()) != 0)
    return rc;
  if ((rc = check_decision_query_rejects_missing_pair ()) != 0)
    return rc;

  return 0;
}
