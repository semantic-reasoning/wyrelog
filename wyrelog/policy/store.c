/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "store-private.h"

#include "wyrelog/wyl-id-private.h"

struct wyl_policy_store_t
{
  sqlite3 *db;
};

typedef struct
{
  const gchar *id;
  const gchar *name;
} BuiltinRole;

typedef struct
{
  const gchar *id;
  const gchar *name;
  const gchar *klass;
} BuiltinPermission;

static const BuiltinRole builtin_roles[] = {
  {"wr.system_admin", "system admin"},
  {"wr.auditor", "auditor"},
  {"wr.system_agent", "system agent"},
  {"wr.break_glass", "break glass"},
  {"wr.service_admin", "service admin"},
  {"wr.operator", "operator"},
  {"wr.analyst", "analyst"},
  {"wr.viewer", "viewer"},
  {"wr.svc_agent", "service agent"},
  {"wr.security_officer", "security officer"},
};

static const BuiltinPermission builtin_permissions[] = {
  {"wr.sys.admin", "system admin", "critical"},
  {"wr.sys.key_rotate", "system key rotate", "critical"},
  {"wr.sys.merkle_seal", "system merkle seal", "critical"},
  {"wr.sys.reload_template", "system template reload", "critical"},
  {"wr.policy.read", "policy read", "sensitive"},
  {"wr.policy.write", "policy write", "critical"},
  {"wr.policy.grant_role", "policy role grant", "critical"},
  {"wr.stream.read", "stream read", "basic"},
  {"wr.stream.write_reserved", "reserved stream write", "critical"},
  {"wr.stream.list", "stream list", "basic"},
  {"wr.svc.admin", "service admin", "critical"},
  {"wr.svc.reload", "service reload", "sensitive"},
  {"wr.svc.flush_cache", "service cache flush", "sensitive"},
  {"wr.svc.grant_role", "service role grant", "critical"},
  {"wr.svc.freeze", "service freeze", "critical"},
  {"wr.svc.unfreeze", "service unfreeze", "critical"},
  {"wr.svc.read_decision", "service decision read", "basic"},
  {"wr.explain.read", "explanation read", "sensitive"},
  {"wr.explain.read_sensitive", "sensitive explanation read", "sensitive"},
  {"wr.audit.read", "audit read", "sensitive"},
  {"wr.audit.explain", "audit explanation read", "sensitive"},
  {"wr.audit.write", "audit write", "critical"},
};

static const BuiltinRole *
find_builtin_role (const gchar *role_id)
{
  if (role_id == NULL)
    return NULL;
  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    if (g_strcmp0 (builtin_roles[i].id, role_id) == 0)
      return &builtin_roles[i];
  }
  return NULL;
}

static const BuiltinPermission *
find_builtin_permission (const gchar *perm_id)
{
  if (perm_id == NULL)
    return NULL;
  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    if (g_strcmp0 (builtin_permissions[i].id, perm_id) == 0)
      return &builtin_permissions[i];
  }
  return NULL;
}

static gboolean
is_reserved_catalog_id (const gchar *id)
{
  return g_str_has_prefix (id, "wr.");
}

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

static gboolean
deployment_mode_is_valid (const gchar *mode)
{
  return g_strcmp0 (mode, "production") == 0
      || g_strcmp0 (mode, "development") == 0 || g_strcmp0 (mode, "demo") == 0;
}

static wyrelog_error_t
query_has_rows (sqlite3 *db, const gchar *sql, gboolean *out_has_rows)
{
  if (db == NULL || sql == NULL || out_has_rows == NULL)
    return WYRELOG_E_INVALID;
  *out_has_rows = FALSE;

  sqlite3_stmt *stmt = NULL;
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    *out_has_rows = TRUE;
    sqlite3_finalize (stmt);
    return WYRELOG_E_OK;
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
query_single_text (sqlite3 *db, const gchar *sql, const gchar *id,
    gchar **out_value)
{
  sqlite3_stmt *stmt = NULL;

  if (db == NULL || sql == NULL || id == NULL || out_value == NULL)
    return WYRELOG_E_INVALID;
  *out_value = NULL;

  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    if (sqlite3_column_type (stmt, 0) == SQLITE_NULL) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    *out_value = g_strdup ((const gchar *) sqlite3_column_text (stmt, 0));
    sqlite3_finalize (stmt);
    return *out_value == NULL ? WYRELOG_E_IO : WYRELOG_E_OK;
  }

  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_POLICY : WYRELOG_E_IO;
}

static wyrelog_error_t
validate_builtin_roles (sqlite3 *db)
{
  static const gchar *sql = "SELECT role_name FROM roles WHERE role_id = ?;";

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    g_autofree gchar *name = NULL;
    wyrelog_error_t rc = query_single_text (db, sql, builtin_roles[i].id,
        &name);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (name, builtin_roles[i].name) != 0)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_builtin_permissions (sqlite3 *db)
{
  static const gchar *name_sql =
      "SELECT perm_name FROM permissions WHERE perm_id = ?;";
  static const gchar *class_sql =
      "SELECT class FROM permissions WHERE perm_id = ?;";

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    g_autofree gchar *name = NULL;
    wyrelog_error_t rc = query_single_text (db, name_sql,
        builtin_permissions[i].id, &name);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (name, builtin_permissions[i].name) != 0)
      return WYRELOG_E_POLICY;

    g_autofree gchar *klass = NULL;
    rc = query_single_text (db, class_sql, builtin_permissions[i].id, &klass);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (g_strcmp0 (klass, builtin_permissions[i].klass) != 0)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_builtin_catalog (sqlite3 *db)
{
  wyrelog_error_t rc = validate_builtin_roles (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  return validate_builtin_permissions (db);
}

static wyrelog_error_t
seed_builtin_roles (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT OR IGNORE INTO roles "
      "  (role_id, role_name, description, created_at, modified_at) "
      "VALUES (?, ?, 'built-in', unixepoch(), unixepoch());";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_roles); i++) {
    sqlite3_reset (stmt);
    sqlite3_clear_bindings (stmt);
    if ((rc = bind_text (stmt, 1, builtin_roles[i].id)) != WYRELOG_E_OK
        || (rc = bind_text (stmt, 2, builtin_roles[i].name))
        != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
    if (sqlite3_step (stmt) != SQLITE_DONE) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
seed_builtin_permissions (sqlite3 *db)
{
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "INSERT OR IGNORE INTO permissions "
      "  (perm_id, perm_name, class, created_at) "
      "VALUES (?, ?, ?, unixepoch());";
  wyrelog_error_t rc = prepare_stmt (db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  for (gsize i = 0; i < G_N_ELEMENTS (builtin_permissions); i++) {
    sqlite3_reset (stmt);
    sqlite3_clear_bindings (stmt);
    if ((rc = bind_text (stmt, 1, builtin_permissions[i].id)) != WYRELOG_E_OK
        || (rc = bind_text (stmt, 2, builtin_permissions[i].name))
        != WYRELOG_E_OK
        || (rc = bind_text (stmt, 3, builtin_permissions[i].klass))
        != WYRELOG_E_OK) {
      sqlite3_finalize (stmt);
      return rc;
    }
    if (sqlite3_step (stmt) != SQLITE_DONE) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_IO;
    }
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
seed_builtin_catalog (sqlite3 *db)
{
  wyrelog_error_t rc = seed_builtin_roles (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = seed_builtin_permissions (db);
  if (rc != WYRELOG_E_OK)
    return rc;
  return validate_builtin_catalog (db);
}

wyrelog_error_t
wyl_policy_store_begin_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  return exec_sql (store->db, "SAVEPOINT wyrelog_policy_mutation;");
}

wyrelog_error_t
wyl_policy_store_commit_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;
  return exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_policy_mutation;");
}

void
wyl_policy_store_rollback_mutation (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return;
  (void) exec_sql (store->db, "ROLLBACK TO SAVEPOINT wyrelog_policy_mutation;");
  (void) exec_sql (store->db, "RELEASE SAVEPOINT wyrelog_policy_mutation;");
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
      "CREATE TABLE IF NOT EXISTS wyrelog_config ("
      "  config_key TEXT PRIMARY KEY,"
      "  config_value TEXT NOT NULL CHECK ("
      "    config_key != 'deployment_mode' OR "
      "    config_value IN ('production', 'development', 'demo')),"
      "  updated_at INTEGER NOT NULL"
      ");"
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
  wyrelog_error_t rc = exec_sql (store->db, ddl);
  if (rc != WYRELOG_E_OK)
    return rc;
  return seed_builtin_catalog (store->db);
}

gsize
wyl_policy_store_builtin_role_count (void)
{
  return G_N_ELEMENTS (builtin_roles);
}

const gchar *
wyl_policy_store_builtin_role_id (gsize idx)
{
  if (idx >= G_N_ELEMENTS (builtin_roles))
    return NULL;
  return builtin_roles[idx].id;
}

gsize
wyl_policy_store_builtin_permission_count (void)
{
  return G_N_ELEMENTS (builtin_permissions);
}

const gchar *
wyl_policy_store_builtin_permission_id (gsize idx)
{
  if (idx >= G_N_ELEMENTS (builtin_permissions))
    return NULL;
  return builtin_permissions[idx].id;
}

wyrelog_error_t
wyl_policy_store_set_deployment_mode (wyl_policy_store_t *store,
    const gchar *mode)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || mode == NULL)
    return WYRELOG_E_INVALID;
  if (!deployment_mode_is_valid (mode))
    return WYRELOG_E_POLICY;

  static const gchar *sql =
      "INSERT INTO wyrelog_config (config_key, config_value, updated_at) "
      "VALUES ('deployment_mode', ?, unixepoch()) "
      "ON CONFLICT(config_key) DO UPDATE SET "
      "  config_value = excluded.config_value,"
      "  updated_at = excluded.updated_at;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, mode)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
  }

  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  return (step_rc == SQLITE_DONE) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_policy_store_get_deployment_mode (wyl_policy_store_t *store,
    gchar **out_mode)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || out_mode == NULL)
    return WYRELOG_E_INVALID;

  *out_mode = NULL;
  static const gchar *sql =
      "SELECT config_value FROM wyrelog_config "
      "WHERE config_key = 'deployment_mode';";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_ROW) {
    const gchar *mode = (const gchar *) sqlite3_column_text (stmt, 0);
    if (!deployment_mode_is_valid (mode)) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    *out_mode = g_strdup (mode);
  } else if (step_rc == SQLITE_DONE) {
    *out_mode = g_strdup ("production");
  } else {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }

  sqlite3_finalize (stmt);
  return WYRELOG_E_OK;
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
wyl_policy_store_validate_snapshot (wyl_policy_store_t *store)
{
  if (store == NULL || store->db == NULL)
    return WYRELOG_E_INVALID;

  gboolean found = FALSE;
  static const gchar *cycle_sql =
      "WITH RECURSIVE walk(root, node, depth, path) AS ("
      "  SELECT child_role_id, parent_role_id, 1,"
      "    '|' || child_role_id || '|' || parent_role_id || '|' "
      "  FROM role_inheritances"
      "  UNION ALL "
      "  SELECT walk.root, ri.parent_role_id, walk.depth + 1,"
      "    walk.path || ri.parent_role_id || '|' "
      "  FROM walk "
      "  JOIN role_inheritances ri ON ri.child_role_id = walk.node "
      "  WHERE walk.depth < 32 "
      "    AND instr(walk.path, '|' || ri.parent_role_id || '|') = 0"
      ") "
      "SELECT 1 FROM walk WHERE root = node "
      "UNION ALL "
      "SELECT 1 FROM walk "
      "JOIN role_inheritances ri ON ri.child_role_id = walk.node "
      "WHERE ri.parent_role_id = walk.root " "LIMIT 1;";
  wyrelog_error_t rc = query_has_rows (store->db, cycle_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *depth_sql =
      "WITH RECURSIVE walk(child, parent, depth) AS ("
      "  SELECT child_role_id, parent_role_id, 1 FROM role_inheritances"
      "  UNION ALL "
      "  SELECT walk.child, ri.parent_role_id, walk.depth + 1 "
      "  FROM walk "
      "  JOIN role_inheritances ri ON ri.child_role_id = walk.parent "
      "  WHERE walk.depth < 4"
      ") " "SELECT 1 FROM walk WHERE depth > 3 LIMIT 1;";
  rc = query_has_rows (store->db, depth_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *role_permission_sod_sql =
      "SELECT 1 FROM role_permissions "
      "WHERE (role_id = 'wr.break_glass' AND perm_id = 'wr.audit.write') "
      "   OR (role_id = 'wr.system_admin' AND perm_id GLOB 'wr.audit.*') "
      "   OR (role_id = 'wr.auditor' AND perm_id IN ("
      "        'wr.policy.write', 'wr.policy.grant_role', "
      "        'wr.svc.grant_role')) " "LIMIT 1;";
  rc = query_has_rows (store->db, role_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *role_membership_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), effective_membership(subject_id, scope, effective_role_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rc.effective_role_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id"
      ") "
      "SELECT 1 FROM effective_membership privileged "
      "JOIN effective_membership auditor "
      "  ON auditor.subject_id = privileged.subject_id "
      " AND auditor.scope = privileged.scope "
      "WHERE privileged.effective_role_id IN ("
      "    'wr.system_admin', 'wr.service_admin', 'wr.break_glass') "
      "  AND auditor.effective_role_id = 'wr.auditor' " "LIMIT 1;";
  rc = query_has_rows (store->db, role_membership_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *direct_permission_sod_sql =
      "SELECT 1 FROM direct_permissions audit "
      "JOIN direct_permissions privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, direct_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *mixed_permission_role_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), effective_membership(subject_id, scope, effective_role_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rc.effective_role_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id"
      ") "
      "SELECT 1 FROM direct_permissions audit "
      "JOIN effective_membership privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.effective_role_id IN ("
      "    'wr.system_admin', 'wr.service_admin', 'wr.break_glass') "
      "UNION ALL "
      "SELECT 1 FROM effective_membership auditor "
      "JOIN direct_permissions privileged "
      "  ON privileged.subject_id = auditor.subject_id "
      " AND privileged.scope = auditor.scope "
      "WHERE auditor.effective_role_id = 'wr.auditor' "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, mixed_permission_role_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

  static const gchar *effective_permission_sod_sql =
      "WITH RECURSIVE role_closure(role_id, effective_role_id) AS ("
      "  SELECT role_id, role_id FROM roles "
      "  UNION "
      "  SELECT role_closure.role_id, ri.parent_role_id "
      "  FROM role_closure "
      "  JOIN role_inheritances ri "
      "    ON ri.child_role_id = role_closure.effective_role_id"
      "), role_subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT rm.subject_id, rm.scope, rp.perm_id "
      "  FROM role_memberships rm "
      "  JOIN role_closure rc ON rc.role_id = rm.role_id "
      "  JOIN role_permissions rp ON rp.role_id = rc.effective_role_id"
      "), subject_permission(subject_id, scope, perm_id) AS ("
      "  SELECT subject_id, scope, perm_id FROM direct_permissions "
      "  UNION "
      "  SELECT subject_id, scope, perm_id FROM role_subject_permission"
      ") "
      "SELECT 1 FROM subject_permission audit "
      "JOIN subject_permission privileged "
      "  ON privileged.subject_id = audit.subject_id "
      " AND privileged.scope = audit.scope "
      "WHERE audit.perm_id IN ("
      "    'wr.audit.read', 'wr.audit.explain', 'wr.audit.write') "
      "  AND privileged.perm_id IN ("
      "    'wr.sys.admin', 'wr.svc.admin', "
      "    'wr.policy.write', 'wr.policy.grant_role', "
      "    'wr.svc.grant_role') " "LIMIT 1;";
  rc = query_has_rows (store->db, effective_permission_sod_sql, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (found)
    return WYRELOG_E_POLICY;

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

  const BuiltinRole *builtin = find_builtin_role (role_id);
  if (builtin != NULL && g_strcmp0 (role_name, builtin->name) != 0)
    return WYRELOG_E_POLICY;
  if (builtin == NULL && is_reserved_catalog_id (role_id))
    return WYRELOG_E_POLICY;

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
    wyl_policy_store_apply_direct_permission_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, wyl_decision_t audit_decision)
{
  if (store == NULL || store->db == NULL || subject_id == NULL
      || perm_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (insert) {
    gboolean exists = FALSE;
    rc = wyl_policy_store_permission_exists (store, perm_id, &exists);
    if (rc == WYRELOG_E_OK && !exists && is_reserved_catalog_id (perm_id))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK && !exists)
      rc = wyl_policy_store_upsert_permission (store, perm_id, perm_id,
          "basic");
  } else {
    rc = WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK) {
    rc = insert
        ? wyl_policy_store_grant_direct_permission (store, subject_id, perm_id,
        scope)
        : wyl_policy_store_revoke_direct_permission (store, subject_id,
        perm_id, scope);
  }
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_direct_permission_event (store, subject_id,
        perm_id, scope, insert ? "grant" : "revoke");
  }
  if (rc == WYRELOG_E_OK && audit_id != NULL) {
    rc = wyl_policy_store_append_audit_event (store, audit_id,
        audit_created_at_us, audit_subject_id, audit_action,
        audit_resource_id, audit_deny_reason, audit_deny_origin,
        audit_decision);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_direct_permission_mutation (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    gboolean insert)
{
  return wyl_policy_store_apply_direct_permission_mutation_with_audit (store,
      subject_id, perm_id, scope, insert, NULL, 0, NULL, NULL, NULL, NULL, NULL,
      WYL_DECISION_DENY);
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
    const gchar *to_state, gint64 *out_event_id)
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
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (out_event_id != NULL) {
    sqlite3_int64 event_id = sqlite3_last_insert_rowid (store->db);
    if (event_id <= 0)
      return WYRELOG_E_IO;
    *out_event_id = event_id;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_principal_event (wyl_policy_store_t *store,
    wyl_policy_principal_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT event_id, subject_id, event, from_state, to_state "
      "FROM principal_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    gint64 event_id = sqlite3_column_int64 (stmt, 0);
    const gchar *subject_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 4);
    if (event_id <= 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (event_id, subject_id, event, from_state, to_state, user_data);
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
    const gchar *to_state, gint64 *out_event_id)
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
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  if (out_event_id != NULL) {
    sqlite3_int64 event_id = sqlite3_last_insert_rowid (store->db);
    if (event_id <= 0)
      return WYRELOG_E_IO;
    *out_event_id = event_id;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_foreach_session_event (wyl_policy_store_t *store,
    wyl_policy_session_event_cb cb, gpointer user_data)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || cb == NULL)
    return WYRELOG_E_INVALID;

  static const gchar *sql =
      "SELECT event_id, session_id, event, from_state, to_state "
      "FROM session_events ORDER BY event_id;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;

  int step_rc;
  while ((step_rc = sqlite3_step (stmt)) == SQLITE_ROW) {
    gint64 event_id = sqlite3_column_int64 (stmt, 0);
    const gchar *session_id = (const gchar *) sqlite3_column_text (stmt, 1);
    const gchar *event = (const gchar *) sqlite3_column_text (stmt, 2);
    const gchar *from_state = (const gchar *) sqlite3_column_text (stmt, 3);
    const gchar *to_state = (const gchar *) sqlite3_column_text (stmt, 4);
    if (event_id <= 0) {
      sqlite3_finalize (stmt);
      return WYRELOG_E_POLICY;
    }
    rc = cb (event_id, session_id, event, from_state, to_state, user_data);
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

  const BuiltinPermission *builtin = find_builtin_permission (perm_id);
  if (builtin != NULL && (g_strcmp0 (perm_name, builtin->name) != 0
          || g_strcmp0 (klass, builtin->klass) != 0))
    return WYRELOG_E_POLICY;
  if (builtin == NULL && is_reserved_catalog_id (perm_id))
    return WYRELOG_E_POLICY;

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

static wyrelog_error_t
catalog_row_exists (wyl_policy_store_t *store, const gchar *table,
    const gchar *column, const gchar *value, gboolean *out_exists)
{
  sqlite3_stmt *stmt = NULL;

  if (store == NULL || store->db == NULL || table == NULL || column == NULL ||
      value == NULL || out_exists == NULL)
    return WYRELOG_E_INVALID;

  *out_exists = FALSE;
  g_autofree gchar *sql =
      g_strdup_printf ("SELECT 1 FROM %s WHERE %s = ?;", table, column);
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, value)) != WYRELOG_E_OK) {
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
wyl_policy_store_role_exists (wyl_policy_store_t *store, const gchar *role_id,
    gboolean *out_exists)
{
  return catalog_row_exists (store, "roles", "role_id", role_id, out_exists);
}

wyrelog_error_t
wyl_policy_store_permission_exists (wyl_policy_store_t *store,
    const gchar *perm_id, gboolean *out_exists)
{
  return catalog_row_exists (store, "permissions", "perm_id", perm_id,
      out_exists);
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
    wyl_policy_store_apply_role_membership_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * role_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, wyl_decision_t audit_decision)
{
  if (store == NULL || store->db == NULL || subject_id == NULL
      || role_id == NULL || scope == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = insert
      ? wyl_policy_store_grant_role_membership (store, subject_id, role_id,
      scope)
      : wyl_policy_store_revoke_role_membership (store, subject_id, role_id,
      scope);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_role_membership_event (store, subject_id,
        role_id, scope, insert ? "grant" : "revoke");
  }
  if (rc == WYRELOG_E_OK && audit_id != NULL) {
    rc = wyl_policy_store_append_audit_event (store, audit_id,
        audit_created_at_us, audit_subject_id, audit_action,
        audit_resource_id, audit_deny_reason, audit_deny_origin,
        audit_decision);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_validate_snapshot (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }

  rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_apply_role_membership_mutation (wyl_policy_store_t *store,
    const gchar *subject_id, const gchar *role_id, const gchar *scope,
    gboolean insert)
{
  return wyl_policy_store_apply_role_membership_mutation_with_audit (store,
      subject_id, role_id, scope, insert, NULL, 0, NULL, NULL, NULL, NULL, NULL,
      WYL_DECISION_DENY);
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
wyl_policy_store_append_audit_event_full (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision, gboolean *out_inserted)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL || created_at_us < 0
      || out_inserted == NULL)
    return WYRELOG_E_INVALID;
  *out_inserted = FALSE;
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
  if (step_rc != SQLITE_DONE)
    return WYRELOG_E_IO;
  *out_inserted = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_policy_store_append_audit_event (wyl_policy_store_t *store,
    const gchar *id, gint64 created_at_us, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, wyl_decision_t decision)
{
  gboolean inserted = FALSE;

  return wyl_policy_store_append_audit_event_full (store, id, created_at_us,
      subject_id, action, resource_id, deny_reason, deny_origin, decision,
      &inserted);
}

wyrelog_error_t
wyl_policy_store_delete_audit_event (wyl_policy_store_t *store, const gchar *id)
{
  sqlite3_stmt *stmt = NULL;
  wyl_id_t parsed_id;

  if (store == NULL || store->db == NULL || id == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_id_parse (id, &parsed_id) != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;

  static const gchar *sql = "DELETE FROM audit_events WHERE id = ?;";
  wyrelog_error_t rc = prepare_stmt (store->db, sql, &stmt);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = bind_text (stmt, 1, id)) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return rc;
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
