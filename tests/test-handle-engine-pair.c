/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-compound-private.h"
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
  guint ncols;
  guint seen;
} RelationSnapshotExpect;

typedef struct
{
  const gchar *expected_relation;
  const gint64 *first_row;
  const gint64 *second_row;
  guint ncols;
  guint first_seen;
  guint second_seen;
} RelationPairSnapshotExpect;

typedef struct
{
  const gchar *expected_relation;
  const gint64 *expected_row;
  WylDeltaKind expected_kind;
  guint matching;
} DeltaExpect;

typedef struct
{
  const gchar *expected_relation;
  const gint64 *expected_row;
  guint ncols;
  WylDeltaKind expected_kind;
  guint matching;
} DeltaRowExpect;

typedef struct
{
  const gint64 *row;
  guint matches;
} GuardBridgeExpect;

typedef struct
{
  gint64 expected_id;
  guint matches;
} SeenExpect;

static gchar *
make_tmpdir (void)
{
  g_autoptr (GError) err = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-handle-compound-test-XXXXXX", &err);
  if (dir == NULL) {
    g_printerr ("make_tmpdir: %s\n", err ? err->message : "?");
    return NULL;
  }
  return dir;
}

static gboolean
write_file_in_dir (const gchar *dir, const gchar *filename,
    const gchar *contents)
{
  g_autofree gchar *path = g_build_filename (dir, filename, NULL);
  g_autoptr (GError) err = NULL;
  return g_file_set_contents (path, contents, -1, &err);
}

static void
rmdir_recursive (const gchar *dir)
{
  g_autoptr (GDir) d = g_dir_open (dir, 0, NULL);
  if (d == NULL) {
    g_rmdir (dir);
    return;
  }

  const gchar *name;
  while ((name = g_dir_read_name (d)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir, name, NULL);
    if (g_file_test (path, G_FILE_TEST_IS_DIR))
      rmdir_recursive (path);
    else
      g_unlink (path);
  }
  g_rmdir (dir);
}

static gboolean
write_compound_templates (const gchar *dir)
{
  g_autofree gchar *fsm_dir = g_build_filename (dir, "fsm", NULL);
  if (g_mkdir (fsm_dir, 0755) != 0)
    return FALSE;
  g_autofree gchar *lobac_dir = g_build_filename (dir, "lobac", NULL);
  if (g_mkdir (lobac_dir, 0755) != 0)
    return FALSE;

  return write_file_in_dir (dir, "bootstrap.dl",
      ".decl event(id: int64, payload: scope/1 side)\n"
      ".decl seen(id: int64)\n" "seen(ID) :- event(ID, scope(_)).\n")
      && write_file_in_dir (dir, "fsm/principal.dl",
      ".decl principal_transition(from_state: symbol, event: symbol,"
      " to_state: symbol)\n")
      && write_file_in_dir (dir, "fsm/session.dl",
      ".decl session_active(state: symbol)\n"
      ".decl session_transition(from_state: symbol, event: symbol,"
      " to_state: symbol)\n")
      && write_file_in_dir (dir, "fsm/permission_scope.dl",
      ".decl perm_arm_rule(perm: symbol, guard_handle: symbol)\n")
      && write_file_in_dir (dir, "lobac/decision.dl", "// decision stub\n");
}

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
relation_snapshot_expect_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  RelationSnapshotExpect *expect = user_data;

  if (g_strcmp0 (relation, expect->expected_relation) != 0)
    return;
  if (ncols != expect->ncols)
    return;
  for (guint i = 0; i < ncols; i++) {
    if (row[i] != expect->expected_row[i])
      return;
  }
  expect->seen++;
}

static void
relation_pair_snapshot_expect_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  RelationPairSnapshotExpect *expect = user_data;

  if (g_strcmp0 (relation, expect->expected_relation) != 0)
    return;
  if (ncols != expect->ncols)
    return;

  gboolean matches_first = TRUE;
  gboolean matches_second = TRUE;
  for (guint i = 0; i < ncols; i++) {
    if (row[i] != expect->first_row[i])
      matches_first = FALSE;
    if (row[i] != expect->second_row[i])
      matches_second = FALSE;
  }
  if (matches_first)
    expect->first_seen++;
  if (matches_second)
    expect->second_seen++;
}

static void
guard_context_count_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  GuardBridgeExpect *expect = user_data;

  (void) relation;

  if (ncols == 6 && row[1] == expect->row[0] && row[2] == expect->row[2])
    expect->matches++;
}

static void
context_now_count_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  GuardBridgeExpect *expect = user_data;

  (void) relation;

  if (ncols == 3 && row[0] == expect->row[0] && row[1] == expect->row[2])
    expect->matches++;
}

static void
eval_guard_count_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  GuardBridgeExpect *expect = user_data;

  (void) relation;

  if (ncols == 4 && row[0] == expect->row[0] && row[1] == expect->row[1]
      && row[2] == expect->row[2])
    expect->matches++;
}

static void
seen_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  SeenExpect *expect = user_data;

  if (g_strcmp0 (relation, "seen") != 0 || ncols != 1)
    return;
  if (row[0] == expect->expected_id)
    expect->matches++;
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

static void
delta_count_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  guint *seen = user_data;

  (void) relation;
  (void) row;
  (void) ncols;
  (void) kind;

  (*seen)++;
}

static wyrelog_error_t
drain_delta_callbacks (WylHandle *handle, guint *deltas)
{
  for (guint i = 0; i < 8; i++) {
    *deltas = 0;
    wyrelog_error_t rc = wyl_handle_engine_step_delta (handle);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (*deltas == 0)
      return WYRELOG_E_OK;
  }
  return WYRELOG_E_INTERNAL;
}

static void
delta_row_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  DeltaRowExpect *expect = user_data;

  if (g_strcmp0 (relation, expect->expected_relation) != 0)
    return;
  if (ncols != expect->ncols || kind != expect->expected_kind)
    return;
  for (guint i = 0; i < ncols; i++) {
    if (row[i] != expect->expected_row[i])
      return;
  }
  expect->matching++;
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

static gint
expect_guard_bridge_absent (WylHandle *handle, const gchar *subject,
    const gchar *perm, const gchar *scope, gint base_code)
{
  gint64 row[3];
  if (intern3 (handle, subject, perm, scope, row) != WYRELOG_E_OK)
    return base_code;

  GuardBridgeExpect expect = { row, 0 };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "guard_context", guard_context_count_cb, &expect) != WYRELOG_E_OK)
    return base_code + 1;
  if (expect.matches != 0)
    return base_code + 2;

  expect.matches = 0;
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle), "context_now",
          context_now_count_cb, &expect) != WYRELOG_E_OK)
    return base_code + 3;
  if (expect.matches != 0)
    return base_code + 4;

  expect.matches = 0;
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle), "eval_guard",
          eval_guard_count_cb, &expect) != WYRELOG_E_OK)
    return base_code + 5;
  if (expect.matches != 0)
    return base_code + 6;

  return 0;
}

static wyrelog_error_t
intern4 (WylHandle *handle, const gchar *a, const gchar *b, const gchar *c,
    const gchar *d, gint64 row[4])
{
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, d, &row[3]);
}

static wyrelog_error_t
intern_event5 (WylHandle *handle, gint64 event_id, const gchar *a,
    const gchar *b, const gchar *c, const gchar *d, gint64 row[5])
{
  row[0] = event_id;
  wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle, a, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, b, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, c, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, d, &row[4]);
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
  wyrelog_error_t rc = intern4 (handle, a, b, c, d, row);
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
check_compound_make_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 id = -1;
  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, 123},
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 83;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 84;
  if (wyl_handle_make_engine_compound (NULL, "scope", args, 1, &id)
      != WYRELOG_E_INVALID)
    return 85;
  if (id != 0)
    return 86;
  id = -1;
  if (wyl_handle_make_engine_compound (handle, NULL, args, 1, &id)
      != WYRELOG_E_INVALID)
    return 87;
  if (id != 0)
    return 88;
  id = -1;
  if (wyl_handle_make_engine_compound (handle, "", args, 1, &id)
      != WYRELOG_E_INVALID)
    return 89;
  if (id != 0)
    return 90;
  id = -1;
  if (wyl_handle_make_engine_compound (handle, "scope", NULL, 1, &id)
      != WYRELOG_E_INVALID)
    return 91;
  if (id != 0)
    return 92;
  id = -1;
  if (wyl_handle_make_engine_compound (handle, "scope", args, 0, &id)
      != WYRELOG_E_INVALID)
    return 93;
  if (id != 0)
    return 94;
  if (wyl_handle_make_engine_compound (handle, "scope", args, 1, NULL)
      != WYRELOG_E_INVALID)
    return 95;
  return 0;
}

static gint
check_compound_make_rejects_missing_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 id = -1;
  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, 123},
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 96;
  if (wyl_handle_make_engine_compound (handle, "scope", args, 1, &id)
      != WYRELOG_E_INVALID)
    return 97;
  if (id != 0)
    return 98;
  return 0;
}

static gint
check_compound_make_reaches_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 loc_class = -1;
  gint64 compound = -1;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 99;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 100;
  if (wyl_handle_intern_engine_symbol (handle, "trusted", &loc_class)
      != WYRELOG_E_OK)
    return 101;

  wirelog_compound_arg_t args[3] = {
    {WIRELOG_TYPE_INT64, 1700000000},
    {WIRELOG_TYPE_STRING, loc_class},
    {WIRELOG_TYPE_INT64, 10},
  };
  if (wyl_handle_make_engine_compound (handle, "metadata", args,
          G_N_ELEMENTS (args), &compound) != WYRELOG_E_OK)
    return 102;
  if (compound <= 0)
    return 103;
  return 0;
}

static gint
check_compound_make_result_is_insertable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_autofree gchar *tmpdir = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 104;
  tmpdir = make_tmpdir ();
  if (tmpdir == NULL)
    return 105;
  if (!write_compound_templates (tmpdir)) {
    rmdir_recursive (tmpdir);
    return 106;
  }
  if (wyl_handle_open_engine_pair (handle, tmpdir) != WYRELOG_E_OK) {
    rmdir_recursive (tmpdir);
    return 107;
  }

  gint64 payload = -1;
  wirelog_compound_arg_t args[1] = {
    {WIRELOG_TYPE_INT64, 42},
  };
  if (wyl_handle_make_engine_compound (handle, "scope", args,
          G_N_ELEMENTS (args), &payload) != WYRELOG_E_OK) {
    rmdir_recursive (tmpdir);
    return 108;
  }

  const gint64 row[2] = { 7, payload };
  if (wyl_handle_engine_insert (handle, "event", row, G_N_ELEMENTS (row))
      != WYRELOG_E_OK) {
    rmdir_recursive (tmpdir);
    return 109;
  }

  SeenExpect expect = {
    .expected_id = row[0],
    .matches = 0,
  };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle), "seen",
          seen_expect_cb, &expect) != WYRELOG_E_OK) {
    rmdir_recursive (tmpdir);
    return 110;
  }
  rmdir_recursive (tmpdir);
  if (expect.matches != 1)
    return 111;
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
check_principal_event_fanout_derives_delta (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 event_row[5];
  gint64 fired_row[5];
  DeltaRowExpect expect = {
    "principal_fired",
    fired_row,
    5,
    WYL_DELTA_INSERT,
    0,
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 106;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 107;
  if (intern_event5 (handle, 101, "delta-principal-user", "login_ok",
          "unverified", "mfa_required", event_row) != WYRELOG_E_OK)
    return 108;
  if (intern_event5 (handle, 101, "delta-principal-user", "unverified",
          "login_ok", "mfa_required", fired_row) != WYRELOG_E_OK)
    return 109;
  if (wyl_handle_engine_set_delta_callback (handle, delta_row_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 117;
  if (wyl_handle_engine_insert (handle, "principal_event", event_row, 5)
      != WYRELOG_E_OK)
    return 118;
  if (expect.matching != 1)
    return 119;
  if (intern_event5 (handle, 102, "delta-principal-user", "login_ok",
          "unverified", "mfa_required", event_row) != WYRELOG_E_OK)
    return 150;
  fired_row[0] = 102;
  if (wyl_handle_engine_insert (handle, "principal_event", event_row, 5)
      != WYRELOG_E_OK)
    return 151;
  return expect.matching == 2 ? 0 : 152;
}

static gint
check_session_event_fanout_derives_delta (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 event_row[5];
  gint64 fired_row[5];
  DeltaRowExpect expect = {
    "session_fired",
    fired_row,
    5,
    WYL_DELTA_INSERT,
    0,
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 125;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 126;
  if (intern_event5 (handle, 201, "delta-session", "elevate_grant", "active",
          "elevated", event_row) != WYRELOG_E_OK)
    return 127;
  if (intern_event5 (handle, 201, "delta-session", "active", "elevate_grant",
          "elevated", fired_row) != WYRELOG_E_OK)
    return 128;
  if (wyl_handle_engine_set_delta_callback (handle, delta_row_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 129;
  if (wyl_handle_engine_insert (handle, "session_event", event_row, 5)
      != WYRELOG_E_OK)
    return 135;
  if (expect.matching != 1)
    return 136;
  if (intern_event5 (handle, 202, "delta-session", "elevate_grant", "active",
          "elevated", event_row) != WYRELOG_E_OK)
    return 153;
  fired_row[0] = 202;
  if (wyl_handle_engine_insert (handle, "session_event", event_row, 5)
      != WYRELOG_E_OK)
    return 154;
  return expect.matching == 2 ? 0 : 155;
}

static gint
check_delta_callback_survives_reload (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 live_event_row[5];
  gint64 fired_row[5];
  DeltaRowExpect expect = {
    "session_fired",
    fired_row,
    5,
    WYL_DELTA_INSERT,
    0,
  };

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 137;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 138;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_append_session_event (store, "delta-replay-session",
          "elevate_grant", "active", "elevated", NULL) != WYRELOG_E_OK)
    return 139;
  if (intern_event5 (handle, 301, "delta-reload-session", "idle_timeout",
          "active", "idle", live_event_row) != WYRELOG_E_OK)
    return 146;
  if (intern_event5 (handle, 301, "delta-reload-session", "active",
          "idle_timeout", "idle", fired_row) != WYRELOG_E_OK)
    return 146;
  if (wyl_handle_engine_set_delta_callback (handle, delta_row_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 147;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 148;
  if (expect.matching != 0)
    return 152;
  if (wyl_handle_engine_insert (handle, "session_event", live_event_row, 5)
      != WYRELOG_E_OK)
    return 149;
  return expect.matching == 1 ? 0 : 156;
}

static gint
check_snapshot_only_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[3];
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 180;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 181;
  if (intern3 (handle, "snapshot-only-user", "wr.stream.list",
          "snapshot-only-scope", row) != WYRELOG_E_OK)
    return 182;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 183;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 185;
  if (wyl_handle_engine_insert (handle, "direct_permission", row, 3)
      != WYRELOG_E_OK)
    return 184;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 187;
  if (deltas != 0)
    return 188;
  return 0;
}

static gint
check_role_permission_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  gint64 row[2];
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 187;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 188;
  if (wyl_handle_intern_engine_symbol (handle, "wr.snapshot-role", &row[0])
      != WYRELOG_E_OK)
    return 189;
  if (wyl_handle_intern_engine_symbol (handle, "wr.snapshot-role.read",
          &row[1]) != WYRELOG_E_OK)
    return 190;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 191;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 193;
  if (wyl_handle_engine_insert (handle, "role_permission", row, 2)
      != WYRELOG_E_OK)
    return 192;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 195;
  if (deltas != 0)
    return 196;
  return 0;
}

static gint
check_principal_state_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 195;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 196;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 197;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 201;
  if (insert2_symbol (handle, "principal_state", "snapshot-state-user",
          "authenticated") != WYRELOG_E_OK)
    return 198;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 202;
  return deltas == 0 ? 0 : 203;
}

static gint
check_session_state_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 201;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 202;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 203;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 207;
  if (insert2_symbol (handle, "session_state", "snapshot-session",
          "active") != WYRELOG_E_OK)
    return 204;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 208;
  return deltas == 0 ? 0 : 209;
}

static gint
check_session_active_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 207;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 208;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 209;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 213;
  if (insert1_symbol (handle, "session_active", "snapshot-active")
      != WYRELOG_E_OK)
    return 210;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 214;
  return deltas == 0 ? 0 : 215;
}

static gint
check_perm_state_insert_skips_delta_engine (void)
{
  g_autoptr (WylHandle) handle = NULL;
  guint deltas = 0;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 213;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 214;
  if (wyl_handle_engine_set_delta_callback (handle, delta_count_cb, &deltas)
      != WYRELOG_E_OK)
    return 215;
  if (drain_delta_callbacks (handle, &deltas) != WYRELOG_E_OK)
    return 219;
  if (insert4_symbol (handle, "perm_state", "snapshot-perm-user",
          "wr.snapshot-perm", "snapshot-perm-scope", "armed")
      != WYRELOG_E_OK)
    return 216;
  if (wyl_handle_engine_step_delta (handle) != WYRELOG_E_OK)
    return 220;
  return deltas == 0 ? 0 : 221;
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
check_policy_store_role_inheritances_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 348;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.inherit-child",
          "inherit child") != WYRELOG_E_OK)
    return 349;
  if (wyl_policy_store_upsert_role (store, "wr.inherit-parent",
          "inherit parent") != WYRELOG_E_OK)
    return 350;
  if (wyl_policy_store_upsert_permission (store, "wr.inherit.read",
          "inherit read", "basic") != WYRELOG_E_OK)
    return 351;
  if (wyl_policy_store_grant_role_permission (store, "wr.inherit-parent",
          "wr.inherit.read") != WYRELOG_E_OK)
    return 352;
  if (wyl_policy_store_grant_role_inheritance (store, "wr.inherit-child",
          "wr.inherit-parent") != WYRELOG_E_OK)
    return 353;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 354;

  if (insert3_symbol (handle, "member_of", "inherit-user",
          "wr.inherit-child", "inherit-scope") != WYRELOG_E_OK)
    return 355;
  if (insert2_symbol (handle, "principal_state", "inherit-user",
          "authenticated") != WYRELOG_E_OK)
    return 356;
  if (insert2_symbol (handle, "session_state", "inherit-scope", "active")
      != WYRELOG_E_OK)
    return 357;
  if (insert4_symbol (handle, "perm_state", "inherit-user",
          "wr.inherit.read", "inherit-scope", "armed") != WYRELOG_E_OK)
    return 358;

  gint64 decision_row[3];
  if (intern3 (handle, "inherit-user", "wr.inherit.read", "inherit-scope",
          decision_row) != WYRELOG_E_OK)
    return 359;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 360;
  if (!allowed)
    return 361;
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
check_policy_store_role_memberships_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 333;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.member-load-role",
          "member load role") != WYRELOG_E_OK)
    return 334;
  if (wyl_policy_store_upsert_permission (store, "wr.member-load.read",
          "member load read", "basic") != WYRELOG_E_OK)
    return 335;
  if (wyl_policy_store_grant_role_permission (store, "wr.member-load-role",
          "wr.member-load.read") != WYRELOG_E_OK)
    return 336;
  if (wyl_policy_store_grant_role_membership (store, "member-load-user",
          "wr.member-load-role", "member-load-scope") != WYRELOG_E_OK)
    return 337;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 338;

  if (insert2_symbol (handle, "principal_state", "member-load-user",
          "authenticated") != WYRELOG_E_OK)
    return 339;
  if (insert2_symbol (handle, "session_state", "member-load-scope",
          "active") != WYRELOG_E_OK)
    return 340;
  if (insert4_symbol (handle, "perm_state", "member-load-user",
          "wr.member-load.read", "member-load-scope", "armed")
      != WYRELOG_E_OK)
    return 341;

  gint64 decision_row[3];
  if (intern3 (handle, "member-load-user", "wr.member-load.read",
          "member-load-scope", decision_row) != WYRELOG_E_OK)
    return 342;
  gboolean allowed = FALSE;
  if (wyl_handle_engine_decide (handle, decision_row, &allowed)
      != WYRELOG_E_OK)
    return 343;
  return allowed ? 0 : 344;
}

static gint
check_policy_store_role_memberships_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 345;
  if (wyl_handle_load_policy_store_role_memberships (NULL)
      != WYRELOG_E_INVALID)
    return 346;
  if (wyl_handle_load_policy_store_role_memberships (handle)
      != WYRELOG_E_INVALID)
    return 347;
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
check_policy_store_guarded_direct_permissions_do_not_auto_arm (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 365;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 366;
  if (wyl_policy_store_grant_direct_permission (store, "guarded-load-user",
          "wr.audit.read", "guarded-load-scope") != WYRELOG_E_OK)
    return 367;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 368;

  if (insert2_symbol (handle, "principal_state", "guarded-load-user",
          "authenticated") != WYRELOG_E_OK)
    return 369;
  if (insert2_symbol (handle, "session_state", "guarded-load-scope",
          "active") != WYRELOG_E_OK)
    return 370;
  if (insert1_symbol (handle, "session_active", "active") != WYRELOG_E_OK)
    return 371;

  gint64 state_row[4];
  if (intern4 (handle, "guarded-load-user", "wr.audit.read",
          "guarded-load-scope", "armed", state_row) != WYRELOG_E_OK)
    return 372;
  gint64 permission_row[3];
  if (intern3 (handle, "guarded-load-user", "wr.audit.read",
          "guarded-load-scope", permission_row) != WYRELOG_E_OK)
    return 373;
  gboolean found = FALSE;
  if (wyl_handle_engine_contains (handle, "has_permission", permission_row, 3,
          &found) != WYRELOG_E_OK)
    return 374;
  if (!found)
    return 375;

  if (wyl_handle_engine_contains (handle, "perm_state", state_row, 4, &found)
      != WYRELOG_E_OK)
    return 376;
  if (found)
    return 377;
  return 0;
}

static gint
check_policy_store_guarded_direct_permission_decides_with_context (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 378;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 379;
  if (wyl_policy_store_grant_direct_permission (store, "guarded-decide-user",
          "wr.audit.read", "guarded-decide-scope") != WYRELOG_E_OK)
    return 380;
  if (wyl_policy_store_set_principal_state (store, "guarded-decide-user",
          "authenticated") != WYRELOG_E_OK)
    return 381;
  if (wyl_policy_store_set_session_state (store, "guarded-decide-scope",
          "active") != WYRELOG_E_OK)
    return 382;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 383;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "guarded-decide-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "guarded-decide-scope");
  wyl_decide_req_set_guard_context (req, 123, "public", 69);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 384;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 385;
  gint residue = expect_guard_bridge_absent (handle, "guarded-decide-user",
      "wr.audit.read", "guarded-decide-scope", 386);
  if (residue != 0)
    return residue;
  return 0;
}

static gint
check_policy_store_guarded_direct_permission_tags_miss_after_allow (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 420;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 421;
  if (wyl_policy_store_grant_direct_permission (store, "guarded-seq-user",
          "wr.audit.read", "guarded-seq-scope") != WYRELOG_E_OK)
    return 422;
  if (wyl_policy_store_set_principal_state (store, "guarded-seq-user",
          "authenticated") != WYRELOG_E_OK)
    return 423;
  if (wyl_policy_store_set_session_state (store, "guarded-seq-scope",
          "active") != WYRELOG_E_OK)
    return 424;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 425;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "guarded-seq-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "guarded-seq-scope");
  wyl_decide_req_set_guard_context (req, 123, "public", 69);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 426;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 427;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 428;
  if (wyl_decide_resp_get_deny_origin (resp) != NULL)
    return 429;

  wyl_decide_req_set_guard_context (req, 123, "public", 70);
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 430;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 431;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 432;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 433;
  gint residue = expect_guard_bridge_absent (handle, "guarded-seq-user",
      "wr.audit.read", "guarded-seq-scope", 434);
  if (residue != 0)
    return residue;
  return 0;
}

static gint
check_policy_store_guarded_direct_permission_denies_without_context (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 393;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 394;
  if (wyl_policy_store_grant_direct_permission (store, "guarded-empty-user",
          "wr.audit.read", "guarded-empty-scope") != WYRELOG_E_OK)
    return 395;
  if (wyl_policy_store_set_principal_state (store, "guarded-empty-user",
          "authenticated") != WYRELOG_E_OK)
    return 396;
  if (wyl_policy_store_set_session_state (store, "guarded-empty-scope",
          "active") != WYRELOG_E_OK)
    return 397;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 398;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "guarded-empty-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "guarded-empty-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 399;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 400;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 401;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 402;
  return 0;
}

static gint
check_policy_store_guarded_direct_permission_denies_context_miss (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 403;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 404;
  if (wyl_policy_store_grant_direct_permission (store, "guarded-miss-user",
          "wr.audit.read", "guarded-miss-scope") != WYRELOG_E_OK)
    return 405;
  if (wyl_policy_store_set_principal_state (store, "guarded-miss-user",
          "authenticated") != WYRELOG_E_OK)
    return 406;
  if (wyl_policy_store_set_session_state (store, "guarded-miss-scope",
          "active") != WYRELOG_E_OK)
    return 407;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 408;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "guarded-miss-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "guarded-miss-scope");
  wyl_decide_req_set_guard_context (req, 123, "public", 70);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 409;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 410;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 411;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 412;
  gint residue = expect_guard_bridge_absent (handle, "guarded-miss-user",
      "wr.audit.read", "guarded-miss-scope", 413);
  if (residue != 0)
    return residue;
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
check_policy_store_principal_state_required_for_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 385;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 386;

  if (insert2_symbol (handle, "role_permission", "wr.state-required-role",
          "wr.state.required") != WYRELOG_E_OK)
    return 387;
  if (insert2_symbol (handle, "session_state", "state-required-scope",
          "active") != WYRELOG_E_OK)
    return 388;
  if (insert1_symbol (handle, "session_active", "active") != WYRELOG_E_OK)
    return 389;
  if (insert3_symbol (handle, "member_of", "state-required-user",
          "wr.state-required-role", "state-required-scope") != WYRELOG_E_OK)
    return 390;
  if (insert4_symbol (handle, "perm_state", "state-required-user",
          "wr.state.required", "state-required-scope", "armed")
      != WYRELOG_E_OK)
    return 391;

  gint64 row[3];
  if (intern3 (handle, "state-required-user", "wr.state.required",
          "state-required-scope", row) != WYRELOG_E_OK)
    return 392;
  gboolean allowed = TRUE;
  if (wyl_handle_engine_decide (handle, row, &allowed) != WYRELOG_E_OK)
    return 393;
  if (allowed)
    return 394;
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
check_policy_store_principal_events_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 390;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 event_id = -1;
  if (wyl_policy_store_append_principal_event (store, "event-load-user",
          "login_ok", "unverified", "mfa_required", &event_id)
      != WYRELOG_E_OK)
    return 391;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 392;

  gint64 fired_row[5];
  if (intern_event5 (handle, event_id, "event-load-user", "unverified",
          "login_ok", "mfa_required", fired_row) != WYRELOG_E_OK)
    return 393;
  RelationSnapshotExpect fired_expect = {
    .expected_relation = "principal_fired",
    .expected_row = fired_row,
    .ncols = 5,
  };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "principal_fired", relation_snapshot_expect_cb, &fired_expect)
      != WYRELOG_E_OK)
    return 394;
  if (fired_expect.seen != 1)
    return 395;
  return 0;
}

static gint
check_policy_store_principal_events_reject_invalid_edges (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 400;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_append_principal_event (store, "event-invalid-user",
          "mfa_ok", "unverified", "authenticated", NULL) != WYRELOG_E_OK)
    return 401;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_POLICY)
    return 402;
  return 0;
}

static gint
check_policy_store_principal_event_duplicates_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 446;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 first_event_id = -1;
  gint64 second_event_id = -1;
  if (wyl_policy_store_append_principal_event (store, "event-dup-user",
          "login_ok", "unverified", "mfa_required", &first_event_id)
      != WYRELOG_E_OK)
    return 447;
  if (wyl_policy_store_append_principal_event (store, "event-dup-user",
          "login_ok", "unverified", "mfa_required", &second_event_id)
      != WYRELOG_E_OK)
    return 448;
  if (second_event_id <= first_event_id)
    return 449;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 450;

  gint64 first_fired[5];
  if (intern_event5 (handle, first_event_id, "event-dup-user", "unverified",
          "login_ok", "mfa_required", first_fired) != WYRELOG_E_OK)
    return 451;
  gint64 second_fired[5];
  if (intern_event5 (handle, second_event_id, "event-dup-user", "unverified",
          "login_ok", "mfa_required", second_fired) != WYRELOG_E_OK)
    return 452;
  RelationPairSnapshotExpect fired_expect = {
    .expected_relation = "principal_fired",
    .first_row = first_fired,
    .second_row = second_fired,
    .ncols = 5,
  };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "principal_fired", relation_pair_snapshot_expect_cb, &fired_expect)
      != WYRELOG_E_OK)
    return 453;
  if (fired_expect.first_seen != 1)
    return 454;
  if (fired_expect.second_seen != 1)
    return 455;
  return 0;
}

static gint
check_policy_store_principal_events_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 410;
  if (wyl_handle_load_policy_store_principal_events (NULL)
      != WYRELOG_E_INVALID)
    return 411;
  if (wyl_handle_load_policy_store_principal_events (handle)
      != WYRELOG_E_INVALID)
    return 412;
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

static gint
check_policy_store_session_events_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 420;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 event_id = -1;
  if (wyl_policy_store_append_session_event (store, "session-event-load",
          "elevate_grant", "active", "elevated", &event_id) != WYRELOG_E_OK)
    return 421;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 422;

  gint64 fired_row[5];
  if (intern_event5 (handle, event_id, "session-event-load", "active",
          "elevate_grant", "elevated", fired_row) != WYRELOG_E_OK)
    return 423;
  RelationSnapshotExpect fired_expect = {
    .expected_relation = "session_fired",
    .expected_row = fired_row,
    .ncols = 5,
  };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "session_fired", relation_snapshot_expect_cb, &fired_expect)
      != WYRELOG_E_OK)
    return 424;
  if (fired_expect.seen != 1)
    return 425;
  return 0;
}

static gint
check_policy_store_session_events_reject_invalid_edges (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 430;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_append_session_event (store, "session-event-invalid",
          "request", "expiring", "active", NULL) != WYRELOG_E_OK)
    return 431;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_POLICY)
    return 432;
  return 0;
}

static gint
check_policy_store_session_event_duplicates_autoload_on_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 457;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 first_event_id = -1;
  gint64 second_event_id = -1;
  if (wyl_policy_store_append_session_event (store, "session-event-dup",
          "elevate_grant", "active", "elevated", &first_event_id)
      != WYRELOG_E_OK)
    return 458;
  if (wyl_policy_store_append_session_event (store, "session-event-dup",
          "elevate_grant", "active", "elevated", &second_event_id)
      != WYRELOG_E_OK)
    return 459;
  if (second_event_id <= first_event_id)
    return 460;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 461;

  gint64 first_fired[5];
  if (intern_event5 (handle, first_event_id, "session-event-dup", "active",
          "elevate_grant", "elevated", first_fired) != WYRELOG_E_OK)
    return 462;
  gint64 second_fired[5];
  if (intern_event5 (handle, second_event_id, "session-event-dup", "active",
          "elevate_grant", "elevated", second_fired) != WYRELOG_E_OK)
    return 463;
  RelationPairSnapshotExpect fired_expect = {
    .expected_relation = "session_fired",
    .first_row = first_fired,
    .second_row = second_fired,
    .ncols = 5,
  };
  if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "session_fired", relation_pair_snapshot_expect_cb, &fired_expect)
      != WYRELOG_E_OK)
    return 464;
  if (fired_expect.first_seen != 1)
    return 465;
  if (fired_expect.second_seen != 1)
    return 466;
  return 0;
}

static gint
check_policy_store_session_events_reload_failure_preserves_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 433;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 434;
  WylEngine *read_engine = wyl_handle_get_read_engine (handle);
  WylEngine *delta_engine = wyl_handle_get_delta_engine (handle);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_append_session_event (store, "session-event-invalid",
          "request", "expiring", "active", NULL) != WYRELOG_E_OK)
    return 435;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_POLICY)
    return 436;
  if (wyl_handle_get_read_engine (handle) != read_engine)
    return 437;
  return wyl_handle_get_delta_engine (handle) == delta_engine ? 0 : 438;
}

static gint
check_policy_store_inheritance_cycle_fails_open (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 467;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "wr.cycle-a", "cycle a")
      != WYRELOG_E_OK)
    return 468;
  if (wyl_policy_store_upsert_role (store, "wr.cycle-b", "cycle b")
      != WYRELOG_E_OK)
    return 469;
  if (wyl_policy_store_grant_role_inheritance (store, "wr.cycle-a",
          "wr.cycle-b") != WYRELOG_E_OK)
    return 470;
  if (wyl_policy_store_grant_role_inheritance (store, "wr.cycle-b",
          "wr.cycle-a") != WYRELOG_E_OK)
    return 471;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_POLICY)
    return 472;
  if (wyl_handle_get_read_engine (handle) != NULL)
    return 473;
  return wyl_handle_get_delta_engine (handle) == NULL ? 0 : 474;
}

static gint
check_policy_store_inheritance_depth_fails_reload_and_preserves_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 475;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 476;
  WylEngine *read_engine = wyl_handle_get_read_engine (handle);
  WylEngine *delta_engine = wyl_handle_get_delta_engine (handle);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  for (guint i = 0; i < 5; i++) {
    g_autofree gchar *role_id = g_strdup_printf ("wr.depth-%u", i);
    g_autofree gchar *role_name = g_strdup_printf ("depth %u", i);
    if (wyl_policy_store_upsert_role (store, role_id, role_name)
        != WYRELOG_E_OK)
      return 477;
  }
  for (guint i = 0; i < 4; i++) {
    g_autofree gchar *child = g_strdup_printf ("wr.depth-%u", i);
    g_autofree gchar *parent = g_strdup_printf ("wr.depth-%u", i + 1);
    if (wyl_policy_store_grant_role_inheritance (store, child, parent)
        != WYRELOG_E_OK)
      return 478;
  }

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_POLICY)
    return 479;
  if (wyl_handle_get_read_engine (handle) != read_engine)
    return 480;
  return wyl_handle_get_delta_engine (handle) == delta_engine ? 0 : 481;
}

static gint
check_policy_store_audit_facts_reload_failure_preserves_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 443;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 444;
  WylEngine *read_engine = wyl_handle_get_read_engine (handle);
  WylEngine *delta_engine = wyl_handle_get_delta_engine (handle);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, subject_id, action, resource_id, "
          "deny_reason, deny_origin, decision) "
          "VALUES ('not-a-wyl-id', 1, 'audit-reload-user', "
          "'wr.audit.read', 'audit-reload-scope', NULL, NULL, 0);",
          NULL, NULL, NULL) != SQLITE_OK)
    return 445;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_POLICY)
    return 446;
  if (wyl_handle_get_read_engine (handle) != read_engine)
    return 447;
  return wyl_handle_get_delta_engine (handle) == delta_engine ? 0 : 448;
}

static gint
check_policy_store_session_events_require_engine_pair (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 440;
  if (wyl_handle_load_policy_store_session_events (NULL) != WYRELOG_E_INVALID)
    return 441;
  if (wyl_handle_load_policy_store_session_events (handle)
      != WYRELOG_E_INVALID)
    return 442;
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
  if ((rc = check_compound_make_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_compound_make_rejects_missing_pair ()) != 0)
    return rc;
  if ((rc = check_compound_make_reaches_engine_pair ()) != 0)
    return rc;
  if ((rc = check_compound_make_result_is_insertable ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_read_engine ()) != 0)
    return rc;
  if ((rc = check_insert_fanout_reaches_delta_engine ()) != 0)
    return rc;
  if ((rc = check_principal_event_fanout_derives_delta ()) != 0)
    return rc;
  if ((rc = check_session_event_fanout_derives_delta ()) != 0)
    return rc;
  if ((rc = check_delta_callback_survives_reload ()) != 0)
    return rc;
  if ((rc = check_snapshot_only_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_role_permission_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_principal_state_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_session_state_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_session_active_insert_skips_delta_engine ()) != 0)
    return rc;
  if ((rc = check_perm_state_insert_skips_delta_engine ()) != 0)
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
  if ((rc = check_policy_store_role_inheritances_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_permissions_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_memberships_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_role_memberships_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_direct_permissions_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_guarded_direct_permissions_do_not_auto_arm ())
      != 0)
    return rc;
  if ((rc =
          check_policy_store_guarded_direct_permission_decides_with_context ())
      != 0)
    return rc;
  if ((rc =
          check_policy_store_guarded_direct_permission_tags_miss_after_allow ())
      != 0)
    return rc;
  if ((rc =
          check_policy_store_guarded_direct_permission_denies_without_context
          ())
      != 0)
    return rc;
  if ((rc = check_policy_store_guarded_direct_permission_denies_context_miss ())
      != 0)
    return rc;
  if ((rc = check_policy_store_direct_permissions_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_states_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_state_required_for_decide ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_states_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_events_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_event_duplicates_autoload_on_open ())
      != 0)
    return rc;
  if ((rc = check_policy_store_principal_events_reject_invalid_edges ()) != 0)
    return rc;
  if ((rc = check_policy_store_principal_events_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_states_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_states_require_engine_pair ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_events_autoload_on_open ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_event_duplicates_autoload_on_open ())
      != 0)
    return rc;
  if ((rc = check_policy_store_session_events_reject_invalid_edges ()) != 0)
    return rc;
  if ((rc = check_policy_store_session_events_reload_failure_preserves_pair ())
      != 0)
    return rc;
  if ((rc = check_policy_store_inheritance_cycle_fails_open ()) != 0)
    return rc;
  if ((rc =
          check_policy_store_inheritance_depth_fails_reload_and_preserves_pair
          ()) != 0)
    return rc;
  if ((rc = check_policy_store_audit_facts_reload_failure_preserves_pair ())
      != 0)
    return rc;
  if ((rc = check_policy_store_session_events_require_engine_pair ()) != 0)
    return rc;

  return 0;
}
