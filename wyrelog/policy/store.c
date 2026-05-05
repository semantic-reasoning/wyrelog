/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

#include "wyrelog/wyl-id-private.h"

struct wyl_policy_store_t
{
  sqlite3 *db;
};

static wyrelog_error_t
exec_sql (sqlite3 *db, const gchar *sql)
{
  char *errmsg = NULL;

  if (sqlite3_exec (db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
    sqlite3_free (errmsg);
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
prepare_stmt (sqlite3 *db, const gchar *sql, sqlite3_stmt **out_stmt)
{
  if (sqlite3_prepare_v2 (db, sql, -1, out_stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
bind_text (sqlite3_stmt *stmt, int index, const gchar *value)
{
  if (sqlite3_bind_text (stmt, index, value, -1, SQLITE_TRANSIENT)
      != SQLITE_OK)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
bind_nullable_text (sqlite3_stmt *stmt, int index, const gchar *value)
{
  if (value == NULL) {
    if (sqlite3_bind_null (stmt, index) != SQLITE_OK)
      return WYRELOG_E_IO;
    return WYRELOG_E_OK;
  }
  return bind_text (stmt, index, value);
}

static gboolean
column_nullable_text_equal (sqlite3_stmt *stmt, int col, const gchar *expected)
{
  if (sqlite3_column_type (stmt, col) == SQLITE_NULL)
    return expected == NULL;
  return g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, col),
      expected) == 0;
}

wyrelog_error_t
wyl_policy_store_open (const gchar *path, wyl_policy_store_t **out_store)
{
  if (out_store == NULL)
    return WYRELOG_E_INVALID;

  const gchar *effective_path = path;
  if (effective_path == NULL || g_strcmp0 (effective_path, ":memory:") == 0)
    effective_path = ":memory:";

  wyl_policy_store_t *self = g_new0 (wyl_policy_store_t, 1);
  if (sqlite3_open_v2 (effective_path, &self->db,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
          NULL) != SQLITE_OK) {
    if (self->db != NULL)
      sqlite3_close (self->db);
    g_free (self);
    return WYRELOG_E_IO;
  }

  wyrelog_error_t rc = exec_sql (self->db,
      "PRAGMA foreign_keys = ON;" "PRAGMA journal_mode = WAL;");
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_close (self);
    return rc;
  }

  *out_store = self;
  return WYRELOG_E_OK;
}

void
wyl_policy_store_close (wyl_policy_store_t *store)
{
  if (store == NULL)
    return;
  if (store->db != NULL)
    sqlite3_close (store->db);
  g_free (store);
}

sqlite3 *
wyl_policy_store_get_db (wyl_policy_store_t *store)
{
  if (store == NULL)
    return NULL;
  return store->db;
}

wyrelog_error_t
wyl_policy_store_create_schema (wyl_policy_store_t *store)
{
  static const gchar *ddl =
      "CREATE TABLE IF NOT EXISTS roles ("
      "  role_id TEXT PRIMARY KEY,"
      "  role_name TEXT UNIQUE NOT NULL,"
      "  description TEXT,"
      "  created_at INTEGER,"
      "  modified_at INTEGER"
      ");"
      "CREATE TABLE IF NOT EXISTS permissions ("
      "  perm_id TEXT PRIMARY KEY,"
      "  perm_name TEXT UNIQUE NOT NULL,"
      "  class TEXT NOT NULL CHECK "
      "    (class IN ('basic', 'sensitive', 'critical')),"
      "  created_at INTEGER"
      ");"
      "CREATE TABLE IF NOT EXISTS role_permissions ("
      "  role_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (role_id, perm_id),"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id),"
      "  FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id "
      "  ON role_permissions (role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_permissions_perm_id "
      "  ON role_permissions (perm_id);"
      "CREATE TABLE IF NOT EXISTS role_inheritances ("
      "  child_role_id TEXT NOT NULL,"
      "  parent_role_id TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (child_role_id, parent_role_id),"
      "  FOREIGN KEY (child_role_id) REFERENCES roles (role_id),"
      "  FOREIGN KEY (parent_role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_inheritances_child "
      "  ON role_inheritances (child_role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_inheritances_parent "
      "  ON role_inheritances (parent_role_id);"
      "CREATE TABLE IF NOT EXISTS role_memberships ("
      "  subject_id TEXT NOT NULL,"
      "  role_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  granted_by TEXT,"
      "  PRIMARY KEY (subject_id, role_id, scope),"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_memberships_role_id "
      "  ON role_memberships (role_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_memberships_subject_scope "
      "  ON role_memberships (subject_id, scope);"
      "CREATE TABLE IF NOT EXISTS role_membership_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  role_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  operation TEXT NOT NULL CHECK (operation IN ('grant', 'revoke')),"
      "  created_at INTEGER NOT NULL,"
      "  FOREIGN KEY (role_id) REFERENCES roles (role_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_role_membership_events_subject "
      "  ON role_membership_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_role_membership_events_role "
      "  ON role_membership_events (role_id);"
      "CREATE TABLE IF NOT EXISTS direct_permissions ("
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  granted_at INTEGER,"
      "  PRIMARY KEY (subject_id, perm_id, scope),"
      "  FOREIGN KEY (perm_id) REFERENCES permissions (perm_id)"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_direct_permissions_perm_id "
      "  ON direct_permissions (perm_id);"
      "CREATE INDEX IF NOT EXISTS idx_direct_permissions_subject_scope "
      "  ON direct_permissions (subject_id, scope);"
      "CREATE TABLE IF NOT EXISTS direct_permission_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  perm_id TEXT NOT NULL,"
      "  scope TEXT NOT NULL,"
      "  operation TEXT NOT NULL CHECK "
      "    (operation IN ('grant', 'revoke')),"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_direct_permission_events_subject "
      "  ON direct_permission_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_direct_permission_events_perm "
      "  ON direct_permission_events (perm_id);"
      "CREATE TABLE IF NOT EXISTS principal_states ("
      "  subject_id TEXT PRIMARY KEY,"
      "  state TEXT NOT NULL,"
      "  updated_at INTEGER"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_principal_states_state "
      "  ON principal_states (state);"
      "CREATE TABLE IF NOT EXISTS principal_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  subject_id TEXT NOT NULL,"
      "  event TEXT NOT NULL,"
      "  from_state TEXT NOT NULL,"
      "  to_state TEXT NOT NULL,"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_principal_events_subject_id "
      "  ON principal_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_principal_events_event "
      "  ON principal_events (event);"
      "CREATE TABLE IF NOT EXISTS session_states ("
      "  session_id TEXT PRIMARY KEY,"
      "  state TEXT NOT NULL,"
      "  updated_at INTEGER"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_session_states_state "
      "  ON session_states (state);"
      "CREATE TABLE IF NOT EXISTS session_events ("
      "  event_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  session_id TEXT NOT NULL,"
      "  event TEXT NOT NULL,"
      "  from_state TEXT NOT NULL,"
      "  to_state TEXT NOT NULL,"
      "  created_at INTEGER NOT NULL"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_session_events_session_id "
      "  ON session_events (session_id);"
      "CREATE INDEX IF NOT EXISTS idx_session_events_event "
      "  ON session_events (event);"
      "CREATE TABLE IF NOT EXISTS audit_events ("
      "  id TEXT PRIMARY KEY,"
      "  created_at_us INTEGER NOT NULL,"
      "  subject_id TEXT,"
      "  action TEXT,"
      "  resource_id TEXT,"
      "  deny_reason TEXT,"
      "  deny_origin TEXT,"
      "  decision INTEGER NOT NULL CHECK (decision IN (0, 1))"
      ");"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_created_at_us "
      "  ON audit_events (created_at_us);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_subject_id "
      "  ON audit_events (subject_id);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_action "
      "  ON audit_events (action);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_decision "
      "  ON audit_events (decision);"
      "CREATE INDEX IF NOT EXISTS idx_audit_events_deny_reason "
      "  ON audit_events (deny_reason);"
      "CREATE TABLE IF NOT EXISTS policy_signatures ("
      "  policy_version INTEGER PRIMARY KEY,"
      "  policy_hash BLOB NOT NULL,"
      "  signature BLOB NOT NULL,"
      "  signed_by TEXT NOT NULL," "  signed_at INTEGER NOT NULL" ");";

  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  return exec_sql (store->db, ddl);
}

wyrelog_error_t
wyl_policy_store_table_exists (wyl_policy_store_t *store,
    const gchar *table_name, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || table_name == NULL
      || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?;";
  if (sqlite3_prepare_v2 (store->db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return WYRELOG_E_IO;
  if (sqlite3_bind_text (stmt, 1, table_name, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int rc = sqlite3_step (stmt);
  if (rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_upsert_role (wyl_policy_store_t *store, const gchar *role_id,
    const gchar *role_name)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL
      || role_name == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO roles (role_id, role_name, created_at, modified_at) "
      "VALUES (?, ?, unixepoch(), unixepoch()) "
      "ON CONFLICT(role_id) DO UPDATE SET "
      "  role_name = excluded.role_name,"
      "  modified_at = excluded.modified_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_name)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_direct_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO direct_permissions "
      "  (subject_id, perm_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, perm_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_revoke_direct_permission (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "DELETE FROM direct_permissions "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_direct_permission_exists (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM direct_permissions "
      "WHERE subject_id = ? AND perm_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_direct_permission (wyl_policy_store_t *store,
    wyl_policy_direct_permission_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, perm_id, scope FROM direct_permissions "
      "ORDER BY subject_id, perm_id, scope;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    rc = cb (subject_id, perm_id, scope, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_direct_permission_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *operation)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL || operation == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO direct_permission_events "
      "  (subject_id, perm_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, operation)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_direct_permission_event (wyl_policy_store_t *store,
    wyl_policy_direct_permission_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, perm_id, scope, operation "
      "FROM direct_permission_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, perm_id, scope, operation, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_principal_state (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL || state == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO principal_states (subject_id, state, updated_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(subject_id) DO UPDATE SET "
      "  state = excluded.state," "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_principal_state (wyl_policy_store_t *store,
    wyl_policy_principal_state_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, state FROM principal_states " "ORDER BY subject_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (subject_id, state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_principal_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *event, const gchar *from_state,
    const gchar *to_state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || event == NULL || from_state == NULL || to_state == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO principal_events "
      "  (subject_id, event, from_state, to_state, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, event)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, to_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_principal_event (wyl_policy_store_t *store,
    wyl_policy_principal_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, event, from_state, to_state "
      "FROM principal_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, event, from_state, to_state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_set_session_state (wyl_policy_store_t *store,
    const gchar *session_id, const gchar *state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || session_id == NULL || state == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO session_states (session_id, state, updated_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(session_id) DO UPDATE SET "
      "  state = excluded.state," "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, session_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_session_state (wyl_policy_store_t *store,
    wyl_policy_session_state_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT session_id, state FROM session_states " "ORDER BY session_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *session_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *state = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (session_id, state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_session_event (wyl_policy_store_t *store,
    const gchar *session_id, const gchar *event, const gchar *from_state,
    const gchar *to_state)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || session_id == NULL
      || event == NULL || from_state == NULL || to_state == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO session_events "
      "  (session_id, event, from_state, to_state, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, session_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, event)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, from_state)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, to_state)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_session_event (wyl_policy_store_t *store,
    wyl_policy_session_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT session_id, event, from_state, to_state "
      "FROM session_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *session_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (session_id, event, from_state, to_state, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_upsert_permission (wyl_policy_store_t *store,
    const gchar *perm_id, const gchar *perm_name, const gchar *klass)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || perm_id == NULL
      || perm_name == NULL || klass == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO permissions (perm_id, perm_name, class, created_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(perm_id) DO UPDATE SET "
      "  perm_name = excluded.perm_name," "  class = excluded.class;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, perm_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_name)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, klass)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_role_permission (wyl_policy_store_t *store,
    const gchar *role_id, const gchar *perm_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || role_id == NULL || perm_id == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO role_permissions (role_id, perm_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(role_id, perm_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, perm_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_permission (wyl_policy_store_t *store,
    wyl_policy_role_permission_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "WITH RECURSIVE effective_role_permissions(role_id, perm_id) AS ("
      "  SELECT role_id, perm_id FROM role_permissions"
      "  UNION "
      "  SELECT ri.child_role_id, erp.perm_id "
      "  FROM role_inheritances ri "
      "  JOIN effective_role_permissions erp "
      "    ON erp.role_id = ri.parent_role_id"
      ") "
      "SELECT role_id, perm_id FROM effective_role_permissions "
      "ORDER BY role_id, perm_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *perm_id = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (role_id, perm_id, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_role_inheritance (wyl_policy_store_t *store,
    const gchar *child_role_id, const gchar *parent_role_id)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || child_role_id == NULL
      || parent_role_id == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO role_inheritances "
      "  (child_role_id, parent_role_id, granted_at) "
      "VALUES (?, ?, unixepoch()) "
      "ON CONFLICT(child_role_id, parent_role_id) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, child_role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, parent_role_id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_inheritance (wyl_policy_store_t *store,
    wyl_policy_role_inheritance_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT child_role_id, parent_role_id FROM role_inheritances "
      "ORDER BY child_role_id, parent_role_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *child_role_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *parent_role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    rc = cb (child_role_id, parent_role_id, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_grant_role_membership (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO role_memberships "
      "  (subject_id, role_id, scope, granted_at) "
      "VALUES (?, ?, ?, unixepoch()) "
      "ON CONFLICT(subject_id, role_id, scope) DO UPDATE SET "
      "  granted_at = excluded.granted_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_revoke_role_membership (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "DELETE FROM role_memberships "
      "WHERE subject_id = ? AND role_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_role_membership_exists (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  static const gchar *sql =
      "SELECT 1 FROM role_memberships "
      "WHERE subject_id = ? AND role_id = ? AND scope = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW)
    *out_exists = TRUE;
  else if (step_rc != SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_role_membership (wyl_policy_store_t *store,
    wyl_policy_role_membership_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, role_id, scope FROM role_memberships "
      "ORDER BY subject_id, role_id, scope;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    rc = cb (subject_id, role_id, scope, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_role_membership_event (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    const gchar *operation)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL || operation == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "INSERT INTO role_membership_events "
      "  (subject_id, role_id, scope, operation, created_at) "
      "VALUES (?, ?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, subject_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 2, role_id)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 3, scope)) != WYRELOG_E_OK
      || (rc = bind_text (stmt, 4, operation)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_role_membership_event (wyl_policy_store_t *store,
    wyl_policy_role_membership_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT subject_id, role_id, scope, operation "
      "FROM role_membership_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 0);
    const gchar *role_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *scope = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *operation = (const gchar *) sqlite3_column_text (stmt, 3);
    rc = cb (subject_id, role_id, scope, operation, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_append_audit_event (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL || created_at_us < 0)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  if (decision != WYL_DECISION_DENY && decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_INVALID;

  static const gchar *select_sql =
      "SELECT created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, decision FROM audit_events WHERE id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, select_sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int select_rc = sqlite3_step (stmt);
  if (select_rc == SQLITE_ROW) {
    gboolean equal =
        sqlite3_column_int64 (stmt, 0) == created_at_us
        && column_nullable_text_equal (stmt, 1, subject_id)
        && column_nullable_text_equal (stmt, 2, action)
        && column_nullable_text_equal (stmt, 3, resource_id)
        && column_nullable_text_equal (stmt, 4, deny_reason)
        && column_nullable_text_equal (stmt, 5, deny_origin)
        && sqlite3_column_int (stmt, 6) == (int) decision;
    sqlite3_finalize (stmt);
    return equal ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  }
  sqlite3_finalize (stmt);
  stmt = NULL;
  if (select_rc != SQLITE_DONE)
    return WYRELOG_E_IO;

  static const gchar *sql =
      "INSERT INTO audit_events "
      "  (id, created_at_us, subject_id, action, resource_id, "
      "   deny_reason, deny_origin, decision) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
  rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK
      || sqlite3_bind_int64 (stmt, 2, created_at_us) != SQLITE_OK
      || (rc = bind_nullable_text (stmt, 3, subject_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 4, action)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 5, resource_id)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 6, deny_reason)) != WYRELOG_E_OK
      || (rc = bind_nullable_text (stmt, 7, deny_origin)) != WYRELOG_E_OK
      || sqlite3_bind_int (stmt, 8, (int) decision) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_foreach_audit_event (wyl_policy_store_t *store,
    wyl_policy_audit_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT id, created_at_us, subject_id, action, resource_id, "
      "deny_reason, deny_origin, decision "
      "FROM audit_events ORDER BY created_at_us ASC, id ASC;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    const gchar *id = (const gchar *) sqlite3_column_text (stmt, 0);
    gint64 created_at_us = sqlite3_column_int64 (stmt, 1);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *action = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *resource_id = (const gchar *) sqlite3_column_text (stmt, 4);
    const gchar *deny_reason = (const gchar *) sqlite3_column_text (stmt, 5);
    const gchar *deny_origin = (const gchar *) sqlite3_column_text (stmt, 6);
    int decision = sqlite3_column_int (stmt, 7);
    wyl_id_t parsed_id;

    if (id == NULL || wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK
        || created_at_us < 0 || (decision != WYL_DECISION_DENY
            && decision != WYL_DECISION_ALLOW)) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (id, created_at_us, subject_id, action, resource_id, deny_reason,
        deny_origin, (wyl_decision_t) decision, user_data);
    if (rc != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}
