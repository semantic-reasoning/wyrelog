/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

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
      "SELECT role_id, perm_id FROM role_permissions "
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
