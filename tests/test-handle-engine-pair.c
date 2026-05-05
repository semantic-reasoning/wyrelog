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
insert2_symbol (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b)
{
  gint64 row[2];
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 2);
}

static wyrelog_error_t
insert3_symbol (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b, const gchar *c)
{
  gint64 row[3];
  wyrelog_error_t rc = intern3 (handle, a, b, c, row);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 3);
}

static wyrelog_error_t
insert4_symbol (WylHandle *handle, const gchar *relation, const gchar *a,
    const gchar *b, const gchar *c, const gchar *d)
{
  gint64 row[4];
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 4);
}

static wyrelog_error_t
insert_decision_fixture_state (WylHandle *handle, const gchar *user,
    const gchar *role, const gchar *permission, const gchar *scope,
    const gchar *principal_state, const gchar *session_state,
    gboolean armed, gint64 decision_row[3])
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
  if (armed) {
    rc = insert4_symbol (handle, "perm_state", user, permission, scope,
        "armed");
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  decision_row[0] = member_row[0];
  decision_row[1] = role_permission_row[1];
  decision_row[2] = member_row[2];
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_decision_fixture (WylHandle *handle, const gchar *user,
    const gchar *role, const gchar *permission, const gchar *scope,
    const gchar *principal_state, const gchar *session_state,
    gint64 decision_row[3])
{
  return insert_decision_fixture_state (handle, user, role, permission, scope,
      principal_state, session_state, TRUE, decision_row);
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
check_reload_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 55;
  if (wyl_handle_reload_engine_pair (NULL) != WYRELOG_E_INVALID)
    return 56;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_INVALID)
    return 57;
  return 0;
}

static gint
check_reload_loads_policy_store_snapshot (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 58;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 59;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.reload-role", "reload role")
      != WYRELOG_E_OK)
    return 53;
  if (wyl_policy_store_upsert_permission (store, "wr.reload.read",
          "reload read", "basic") != WYRELOG_E_OK)
    return 54;
  if (wyl_policy_store_grant_role_permission (store, "wr.reload-role",
          "wr.reload.read") != WYRELOG_E_OK)
    return 45;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 46;

  if (insert3_symbol (handle, "member_of", "reload-user", "wr.reload-role",
          "reload-scope") != WYRELOG_E_OK)
    return 47;
  if (insert2_symbol (handle, "principal_state", "reload-user",
          "authenticated") != WYRELOG_E_OK)
    return 48;
  if (insert2_symbol (handle, "session_state", "reload-scope", "active")
      != WYRELOG_E_OK)
    return 49;
  if (insert4_symbol (handle, "perm_state", "reload-user", "wr.reload.read",
          "reload-scope", "armed") != WYRELOG_E_OK)
    return 44;

  gint64 decision_row[3];
  if (intern3 (handle, "reload-user", "wr.reload.read", "reload-scope",
          decision_row) != WYRELOG_E_OK)
    return 33;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 34;
  if (!allowed)
    return 37;
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
check_symbol_intern_can_be_reversed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 id = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 28;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 29;
  if (wyl_handle_intern_engine_symbol (handle, "reverse-symbol", &id)
      != WYRELOG_E_OK)
    return 30;
  g_autofree gchar *symbol = wyl_handle_dup_engine_symbol (handle, id);
  if (g_strcmp0 (symbol, "reverse-symbol") != 0)
    return 31;
  if (wyl_handle_dup_engine_symbol (handle, -42) != NULL)
    return 32;
  if (wyl_handle_dup_engine_symbol (NULL, id) != NULL)
    return 33;
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
  if (wyl_handle_engine_set_delta_callback (handle, delta_expect_cb, &expect)
      != WYRELOG_E_OK)
    return 103;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 104;
  if (expect.matching == 0)
    return 105;
  return 0;
}

static gint
check_snapshot_only_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3];
  DeltaExpect expect = {
    "direct_permission",
    row,
    WYL_DELTA_INSERT,
    0,
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 180;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 181;
  if (intern3 (handle, "snapshot-only-user", "wr.stream.list",
          "snapshot-only-scope", row) != WYRELOG_E_OK)
    return 182;
  if (wyl_handle_engine_set_delta_callback (handle, delta_expect_cb, &expect)
      != WYRELOG_E_OK)
    return 183;
  if (wyl_handle_engine_insert (handle, "direct_permission", row, 3)
      != WYRELOG_E_OK)
    return 184;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 185;
  if (expect.matching != 0)
    return 186;
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
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_INVALID)
    return 123;
  if (wyl_handle_engine_set_delta_callback (handle, delta_expect_cb, NULL)
      != WYRELOG_E_INVALID)
    return 124;
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
check_decision_query_denies_frozen_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 145;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 146;
  if (insert_decision_fixture (handle, "decision-user-c",
          "wr.decision-role-c", "wr.decision-permission-c",
          "decision-scope-c", "authenticated", "active", decision_row)
      != WYRELOG_E_OK)
    return 147;
  if (insert1_symbol (handle, "frozen", "decision-scope-c") != WYRELOG_E_OK)
    return 148;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 149;
  if (allowed)
    return 150;
  return 0;
}

static gint
check_decision_query_denies_disabled_role (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 155;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 156;
  if (insert_decision_fixture (handle, "decision-user-d",
          "wr.decision-role-d", "wr.decision-permission-d",
          "decision-scope-d", "authenticated", "active", decision_row)
      != WYRELOG_E_OK)
    return 157;
  if (insert2_symbol (handle, "disabled_role_for", "decision-user-d",
          "wr.decision-permission-d") != WYRELOG_E_OK)
    return 158;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 159;
  if (allowed)
    return 160;
  return 0;
}

static gint
check_decision_query_denies_sod_violation (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 165;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 166;
  if (insert_decision_fixture (handle, "decision-user-e",
          "wr.decision-role-e", "wr.decision-permission-e",
          "decision-scope-e", "authenticated", "active", decision_row)
      != WYRELOG_E_OK)
    return 167;
  if (insert4_symbol (handle, "policy_violation", "sod", "decision-user-e",
          "wr.decision-permission-e", "witness-e") != WYRELOG_E_OK)
    return 168;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 169;
  if (allowed)
    return 170;
  return 0;
}

static gint
check_decision_query_denies_unarmed_catalogue_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 171;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 172;
  if (insert_decision_fixture_state (handle, "decision-user-f",
          "wr.decision-role-f", "wr.audit.read", "decision-scope-f",
          "authenticated", "active", FALSE, decision_row) != WYRELOG_E_OK)
    return 173;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 174;
  if (allowed)
    return 175;
  return 0;
}

static gint
check_decision_query_denies_armed_catalogue_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 decision_row[3];
  gboolean allowed = TRUE;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 176;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 177;
  if (insert_decision_fixture_state (handle, "decision-user-g",
          "wr.decision-role-g", "wr.audit.read", "decision-scope-g",
          "authenticated", "active", TRUE, decision_row) != WYRELOG_E_OK)
    return 178;
  gboolean guarded = FALSE;
  if (wyl_handle_engine_contains (handle, "guarded_perm", &decision_row[1], 1,
          &guarded) != WYRELOG_E_OK)
    return 179;
  if (!guarded)
    return 180;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 181;
  if (allowed)
    return 182;
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

static gint
check_policy_store_role_permissions_load_into_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 320;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.store-role", "store role")
      != WYRELOG_E_OK)
    return 321;
  if (wyl_policy_store_upsert_permission (store, "wr.store.read",
          "store read", "basic") != WYRELOG_E_OK)
    return 322;
  if (wyl_policy_store_grant_role_permission (store, "wr.store-role",
          "wr.store.read") != WYRELOG_E_OK)
    return 323;
  if (wyl_handle_load_policy_store_role_permissions (handle) != WYRELOG_E_OK)
    return 324;

  gint64 decision_row[3];
  if (insert_decision_fixture (handle, "store-user", "wr.store-role",
          "wr.store.read", "store-scope", "authenticated", "active",
          decision_row) != WYRELOG_E_OK)
    return 325;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 326;
  if (!allowed)
    return 328;
  return 0;
}

static gint
check_policy_store_role_permissions_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 340;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.autoload-role",
          "autoload role") != WYRELOG_E_OK)
    return 341;
  if (wyl_policy_store_upsert_permission (store, "wr.autoload.read",
          "autoload read", "basic") != WYRELOG_E_OK)
    return 342;
  if (wyl_policy_store_grant_role_permission (store, "wr.autoload-role",
          "wr.autoload.read") != WYRELOG_E_OK)
    return 343;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 344;

  gint64 decision_row[3];
  if (insert_decision_fixture (handle, "autoload-user", "wr.autoload-role",
          "wr.autoload.read", "autoload-scope", "authenticated", "active",
          decision_row) != WYRELOG_E_OK)
    return 345;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 346;
  if (!allowed)
    return 347;
  return 0;
}

static gint
check_policy_store_role_permissions_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 330;
  if (wyl_handle_load_policy_store_role_permissions (NULL)
      != WYRELOG_E_INVALID)
    return 331;
  if (wyl_handle_load_policy_store_role_permissions (handle)
      != WYRELOG_E_INVALID)
    return 332;
  return 0;
}

static gint
check_policy_store_direct_permissions_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 350;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.direct.autoload",
          "direct autoload", "basic") != WYRELOG_E_OK)
    return 351;
  if (wyl_policy_store_grant_direct_permission (store, "direct-load-user",
          "wr.direct.autoload", "direct-load-scope") != WYRELOG_E_OK)
    return 352;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 353;

  if (insert2_symbol (handle, "principal_state", "direct-load-user",
          "authenticated") != WYRELOG_E_OK)
    return 354;
  if (insert2_symbol (handle, "session_state", "direct-load-scope",
          "active") != WYRELOG_E_OK)
    return 355;
  if (insert1_symbol (handle, "session_active", "active") != WYRELOG_E_OK)
    return 356;

  gint64 decision_row[3];
  if (intern3 (handle, "direct-load-user", "wr.direct.autoload",
          "direct-load-scope", decision_row) != WYRELOG_E_OK)
    return 357;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 358;
  if (!allowed)
    return 359;
  return 0;
}

static gint
check_policy_store_direct_permissions_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 360;
  if (wyl_handle_load_policy_store_direct_permissions (NULL)
      != WYRELOG_E_INVALID)
    return 361;
  if (wyl_handle_load_policy_store_direct_permissions (handle)
      != WYRELOG_E_INVALID)
    return 362;
  return 0;
}

static gint
check_policy_store_principal_states_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 370;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_set_principal_state (store, "state-load-user",
          "authenticated") != WYRELOG_E_OK)
    return 371;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 372;

  if (insert2_symbol (handle, "role_permission", "wr.state-role",
          "wr.state.read") != WYRELOG_E_OK)
    return 373;
  if (insert2_symbol (handle, "session_state", "state-scope", "active")
      != WYRELOG_E_OK)
    return 374;
  gint64 member_row[3];
  if (intern3 (handle, "state-load-user", "wr.state-role", "state-scope",
          member_row) != WYRELOG_E_OK)
    return 376;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 384;
  if (insert4_symbol (handle, "perm_state", "state-load-user",
          "wr.state.read", "state-scope", "armed") != WYRELOG_E_OK)
    return 377;

  gint64 row[3];
  if (intern3 (handle, "state-load-user", "wr.state.read", "state-scope",
          row) != WYRELOG_E_OK)
    return 378;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, row, &allowed)
      != WYRELOG_E_OK)
    return 379;
  if (!allowed)
    return 383;
  return 0;
}

static gint
check_policy_store_principal_states_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 380;
  if (wyl_handle_load_policy_store_principal_states (NULL)
      != WYRELOG_E_INVALID)
    return 381;
  if (wyl_handle_load_policy_store_principal_states (handle)
      != WYRELOG_E_INVALID)
    return 382;
  return 0;
}

static gint
check_policy_store_session_states_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 390;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_set_session_state (store, "session-load-scope",
          "active") != WYRELOG_E_OK)
    return 391;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 392;

  if (insert2_symbol (handle, "role_permission", "wr.session-role",
          "wr.session.read") != WYRELOG_E_OK)
    return 393;
  if (insert2_symbol (handle, "principal_state", "session-load-user",
          "authenticated") != WYRELOG_E_OK)
    return 394;
  gint64 member_row[3];
  if (intern3 (handle, "session-load-user", "wr.session-role",
          "session-load-scope", member_row) != WYRELOG_E_OK)
    return 396;
  if (wyl_handle_engine_insert (handle, "member_of", member_row, 3)
      != WYRELOG_E_OK)
    return 397;
  if (insert4_symbol (handle, "perm_state", "session-load-user",
          "wr.session.read", "session-load-scope", "armed") != WYRELOG_E_OK)
    return 398;

  gint64 row[3];
  if (intern3 (handle, "session-load-user", "wr.session.read",
          "session-load-scope", row) != WYRELOG_E_OK)
    return 399;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, row, &allowed)
      != WYRELOG_E_OK)
    return 400;
  if (!allowed)
    return 401;
  return 0;
}

static gint
check_policy_store_session_states_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 410;
  if (wyl_handle_load_policy_store_session_states (NULL) != WYRELOG_E_INVALID)
    return 411;
  if (wyl_handle_load_policy_store_session_states (handle)
      != WYRELOG_E_INVALID)
    return 412;
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
  if ((rc = check_reload_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_reload_loads_policy_store_snapshot ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_reaches_both_engines ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_is_stable ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_can_be_reversed ()) != 0)
    return rc;
  if ((rc = check_symbol_intern_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_read_engine ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_delta_engine ()) != 0)
    return rc;
  if ((rc = check_snapshot_only_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_remove_fanout_reaches_read_engine ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_decision_query_allows_matching_tuple ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_missing_tuple ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_frozen_scope ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_disabled_role ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_sod_violation ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_unarmed_catalogue_permission ()) != 0)
    return rc;
  if ((rc = check_decision_query_denies_armed_catalogue_permission ()) != 0)
    return rc;
  if ((rc = check_decision_query_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_permissions_load_into_engine ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_permissions_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_permissions_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_direct_permissions_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_direct_permissions_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_states_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_states_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_states_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_states_require_engine_pair ()) != 0)
    return rc;

  return 0;
}
