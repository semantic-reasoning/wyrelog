/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_SQLITE_SCHEMA_PATH
#error "WYL_TEST_SQLITE_SCHEMA_PATH must be defined by the build."
#endif

static gint
check_store_creates_authority_schema (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 10;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 11;

  const gchar *tables[] = {
    "wyrelog_config",
    "roles",
    "permissions",
    "role_permissions",
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
    "permission_states",
    "permission_state_events",
    "principal_events",
    "principal_states",
    "session_states",
    "session_events",
    "audit_events",
    "policy_signatures",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tables); i++) {
    gboolean exists = FALSE;
    if (wyl_policy_store_table_exists (store, tables[i], &exists)
        != WYRELOG_E_OK)
      return 12;
    if (!exists)
      return 13;
  }

  return 0;
}

static gint
check_template_schema_creates_state_tables (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *schema = NULL;
  gsize schema_len = 0;
  g_autoptr (GError) error = NULL;
  char *errmsg = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 20;
  if (!g_file_get_contents (WYL_TEST_SQLITE_SCHEMA_PATH, &schema,
          &schema_len, &error))
    return 21;
  if (sqlite3_exec (wyl_policy_store_get_db (store), schema, NULL, NULL,
          &errmsg) != SQLITE_OK) {
    sqlite3_free (errmsg);
    return 22;
  }

  const gchar *tables[] = {
    "wyrelog_config",
    "roles",
    "permissions",
    "role_permissions",
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
    "permission_states",
    "permission_state_events",
    "principal_events",
    "principal_states",
    "session_states",
    "session_events",
    "audit_events",
    "policy_signatures",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tables); i++) {
    gboolean exists = FALSE;
    if (wyl_policy_store_table_exists (store, tables[i], &exists)
        != WYRELOG_E_OK)
      return 23;
    if (!exists)
      return 24;
  }
  return 0;
}

static gint
check_store_rejects_invalid_args (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 30;
  gboolean exists = FALSE;
  if (wyl_policy_store_create_schema (NULL) != WYRELOG_E_INVALID)
    return 31;
  if (wyl_policy_store_table_exists (NULL, "roles", &exists)
      != WYRELOG_E_INVALID)
    return 32;
  if (wyl_policy_store_table_exists (store, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 33;
  if (wyl_policy_store_table_exists (store, "roles", NULL)
      != WYRELOG_E_INVALID)
    return 34;
  if (wyl_policy_store_set_deployment_mode (NULL, "production")
      != WYRELOG_E_INVALID)
    return 35;
  if (wyl_policy_store_set_deployment_mode (store, NULL) != WYRELOG_E_INVALID)
    return 36;
  if (wyl_policy_store_get_deployment_mode (NULL, NULL) != WYRELOG_E_INVALID)
    return 37;
  if (wyl_policy_store_get_deployment_mode (store, NULL)
      != WYRELOG_E_INVALID)
    return 38;
  if (wyl_policy_store_apply_permission_state_transition (NULL, "user",
          "perm", "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 39;
  if (wyl_policy_store_apply_permission_state_transition (store, NULL,
          "perm", "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 56;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          NULL, "scope", "grant", NULL) != WYRELOG_E_INVALID)
    return 57;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", NULL, "grant", NULL) != WYRELOG_E_INVALID)
    return 62;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", "scope", NULL, NULL) != WYRELOG_E_INVALID)
    return 63;
  if (wyl_policy_store_apply_permission_state_transition (store, "user",
          "perm", "scope", "bogus", NULL) != WYRELOG_E_INVALID)
    return 64;
  return 0;
}

static gint
check_store_gets_default_deployment_mode (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *mode = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 42;
  if (g_strcmp0 (mode, "production") != 0)
    return 43;
  return 0;
}

static gint
check_store_sets_deployment_mode (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *mode = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 45;
  if (wyl_policy_store_set_deployment_mode (store, "development")
      != WYRELOG_E_OK)
    return 46;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 47;
  if (g_strcmp0 (mode, "development") != 0)
    return 48;

  g_clear_pointer (&mode, g_free);
  if (wyl_policy_store_set_deployment_mode (store, "demo") != WYRELOG_E_OK)
    return 49;
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 50;
  if (g_strcmp0 (mode, "demo") != 0)
    return 51;
  const gchar *bad_modes[] = { "test", "", " demo", "DEMO" };
  for (gsize i = 0; i < G_N_ELEMENTS (bad_modes); i++) {
    if (wyl_policy_store_set_deployment_mode (store, bad_modes[i])
        != WYRELOG_E_POLICY)
      return 52;
  }
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE wyrelog_config SET config_value = 'test' "
          "WHERE config_key = 'deployment_mode';", NULL, NULL, NULL)
      == SQLITE_OK)
    return 53;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 54;
  g_clear_pointer (&mode, g_free);
  if (wyl_policy_store_get_deployment_mode (store, &mode) != WYRELOG_E_OK)
    return 55;
  if (g_strcmp0 (mode, "demo") != 0)
    return 56;
  return 0;
}

static gint
check_handle_owns_policy_store (void)
{
  g_autoptr (WylHandle) handle = NULL;

  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return 31;
  if (wyl_policy_store_get_db (store) == NULL)
    return 32;

  gboolean exists = FALSE;
  if (wyl_policy_store_table_exists (store, "role_permissions", &exists)
      != WYRELOG_E_OK)
    return 33;
  if (!exists)
    return 34;
  return 0;
}

static gint
count_rows (wyl_policy_store_t *store, const gchar *sql, gint *out_count)
{
  sqlite3_stmt *stmt = NULL;

  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 1;

  int rc = sqlite3_step (stmt);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return 2;
  }

  *out_count = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  return 0;
}

static gint
check_store_seeds_builtin_catalog (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 200;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 201;

  gboolean exists = FALSE;
  if (wyl_policy_store_role_exists (store, "wr.auditor", &exists)
      != WYRELOG_E_OK)
    return 202;
  if (!exists)
    return 203;
  if (wyl_policy_store_permission_exists (store, "wr.audit.read", &exists)
      != WYRELOG_E_OK)
    return 204;
  if (!exists)
    return 205;

  gint matches = 0;
  if (count_rows (store, "SELECT COUNT(*) FROM roles "
          "WHERE role_id = 'wr.auditor';", &matches) != 0)
    return 206;
  if (matches != 1)
    return 207;

  if (count_rows (store, "SELECT COUNT(*) FROM permissions "
          "WHERE perm_id = 'wr.audit.read';", &matches) != 0)
    return 208;
  if (matches != 1)
    return 209;
  if (count_rows (store, "SELECT COUNT(*) FROM permissions "
          "WHERE perm_id = 'wr.login.skip_mfa' "
          "AND class = 'critical';", &matches) != 0)
    return 210;
  if (matches != 1)
    return 211;

  if (wyl_policy_store_upsert_role (store, "site.local-admin",
          "local admin") != WYRELOG_E_OK)
    return 212;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 213;
  if (wyl_policy_store_role_exists (store, "site.local-admin", &exists)
      != WYRELOG_E_OK)
    return 214;
  if (!exists)
    return 215;

  if (count_rows (store, "SELECT COUNT(*) FROM roles "
          "WHERE role_id = 'wr.auditor';", &matches) != 0)
    return 216;
  if (matches != 1)
    return 217;

  return 0;
}

static gint
check_store_rejects_builtin_catalog_drift (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 216;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 217;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE roles SET role_name = 'changed auditor' "
          "WHERE role_id = 'wr.auditor';", NULL, NULL, NULL) != SQLITE_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 219;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 220;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 221;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "UPDATE permissions SET class = 'basic' "
          "WHERE perm_id = 'wr.audit.read';", NULL, NULL, NULL) != SQLITE_OK)
    return 222;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 223;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 224;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 225;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO roles (role_id, role_name, description, created_at, "
          "modified_at) VALUES ('wr.unregistered', 'unregistered', "
          "'raw', unixepoch(), unixepoch());", NULL, NULL, NULL) != SQLITE_OK)
    return 226;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 227;

  g_clear_pointer (&store, wyl_policy_store_close);
  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 228;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 229;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO permissions (perm_id, perm_name, class, created_at) "
          "VALUES ('wr.unregistered.read', 'unregistered read', 'basic', "
          "unixepoch());", NULL, NULL, NULL) != SQLITE_OK)
    return 230;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_POLICY)
    return 231;

  return 0;
}

static gint
check_store_rejects_builtin_catalog_upsert_drift (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 232;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 233;

  if (wyl_policy_store_upsert_role (store, "wr.auditor", "auditor")
      != WYRELOG_E_OK)
    return 234;
  if (wyl_policy_store_upsert_role (store, "wr.auditor", "changed auditor")
      != WYRELOG_E_POLICY)
    return 235;

  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 236;
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "changed audit read", "sensitive") != WYRELOG_E_POLICY)
    return 237;
  if (wyl_policy_store_upsert_permission (store, "wr.login.skip_mfa",
          "login skip mfa", "critical") != WYRELOG_E_OK)
    return 242;
  if (wyl_policy_store_upsert_permission (store, "wr.login.skip_mfa",
          "login skip mfa", "sensitive") != WYRELOG_E_POLICY)
    return 243;
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "basic") != WYRELOG_E_POLICY)
    return 238;
  if (wyl_policy_store_upsert_role (store, "wr.unregistered",
          "unregistered") != WYRELOG_E_POLICY)
    return 239;
  if (wyl_policy_store_upsert_permission (store, "wr.unregistered.read",
          "unregistered read", "basic") != WYRELOG_E_POLICY)
    return 240;
  if (wyl_policy_store_apply_direct_permission_mutation (store, "subject",
          "wr.unregistered.read", "scope", TRUE) != WYRELOG_E_POLICY)
    return 241;

  return 0;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} DirectPermissionExpect;

static wyrelog_error_t
direct_permission_expect_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, gpointer user_data)
{
  DirectPermissionExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
direct_permission_event_expect_cb (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  DirectPermissionExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (operation, expect->operation) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *state;
  guint matches;
} PermissionStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PermissionStateEventExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *state;
  guint matches;
} PrincipalStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *subject_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PrincipalEventExpect;

static wyrelog_error_t
permission_state_expect_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, const gchar *state, gpointer user_data)
{
  PermissionStateExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
permission_state_event_expect_cb (gint64 event_id, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  PermissionStateEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
principal_state_expect_cb (const gchar *subject_id, const gchar *state,
    gpointer user_data)
{
  PrincipalStateExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
principal_event_expect_cb (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  PrincipalEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *session_id;
  const gchar *state;
  guint matches;
} SessionStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *session_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} SessionEventExpect;

static wyrelog_error_t
session_state_expect_cb (const gchar *session_id, const gchar *state,
    gpointer user_data)
{
  SessionStateExpect *expect = user_data;

  if (g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
session_event_expect_cb (gint64 event_id, const gchar *session_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  SessionEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *role_id;
  const gchar *perm_id;
  guint matches;
} RolePermissionExpect;

typedef struct
{
  const gchar *child_role_id;
  const gchar *parent_role_id;
  guint matches;
} RoleInheritanceExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *role_id;
  const gchar *scope;
  guint matches;
} RoleMembershipExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *role_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} RoleMembershipEventExpect;

typedef struct
{
  const gchar *id;
  gint64 created_at_us;
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  wyl_decision_t decision;
  guint matches;
} AuditEventExpect;

static wyrelog_error_t
role_permission_expect_cb (const gchar *role_id, const gchar *perm_id,
    gpointer user_data)
{
  RolePermissionExpect *expect = user_data;

  if (g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_inheritance_expect_cb (const gchar *child_role_id,
    const gchar *parent_role_id, gpointer user_data)
{
  RoleInheritanceExpect *expect = user_data;

  if (g_strcmp0 (child_role_id, expect->child_role_id) == 0
      && g_strcmp0 (parent_role_id, expect->parent_role_id) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_membership_expect_cb (const gchar *subject_id, const gchar *role_id,
    const gchar *scope, gpointer user_data)
{
  RoleMembershipExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
role_membership_event_expect_cb (const gchar *subject_id,
    const gchar *role_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  RoleMembershipEventExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (role_id, expect->role_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (operation, expect->operation) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
audit_event_expect_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    wyl_decision_t decision, gpointer user_data)
{
  AuditEventExpect *expect = user_data;

  if (g_strcmp0 (id, expect->id) == 0
      && created_at_us == expect->created_at_us
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (action, expect->action) == 0
      && g_strcmp0 (resource_id, expect->resource_id) == 0
      && g_strcmp0 (deny_reason, expect->deny_reason) == 0
      && g_strcmp0 (deny_origin, expect->deny_origin) == 0
      && decision == expect->decision)
    expect->matches++;
  return WYRELOG_E_OK;
}

static gint
check_store_grants_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_upsert_role (store, "site.test-role", "test role")
      != WYRELOG_E_OK)
    return 42;
  if (wyl_policy_store_upsert_permission (store, "site.test.read", "test read",
          "basic") != WYRELOG_E_OK)
    return 43;
  if (wyl_policy_store_grant_role_permission (store, "site.test-role",
          "site.test.read") != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_grant_role_permission (store, "site.test-role",
          "site.test.read") != WYRELOG_E_OK)
    return 45;

  RolePermissionExpect expect = {
    .role_id = "site.test-role",
    .perm_id = "site.test.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 46;
  if (expect.matches != 1)
    return 47;
  return 0;
}

static gint
check_store_catalog_existence_probes (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 219;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_exists (store, "wr.missing-role", &exists)
      != WYRELOG_E_OK)
    return 220;
  if (exists)
    return 221;
  if (wyl_policy_store_permission_exists (store, "wr.missing-perm", &exists)
      != WYRELOG_E_OK)
    return 222;
  if (exists)
    return 223;

  if (wyl_policy_store_upsert_role (store, "site.exists-role",
          "exists role") != WYRELOG_E_OK)
    return 224;
  if (wyl_policy_store_upsert_permission (store, "site.exists-perm",
          "exists perm", "basic") != WYRELOG_E_OK)
    return 225;

  if (wyl_policy_store_role_exists (store, "site.exists-role", &exists)
      != WYRELOG_E_OK)
    return 226;
  if (!exists)
    return 227;
  if (wyl_policy_store_permission_exists (store, "site.exists-perm", &exists)
      != WYRELOG_E_OK)
    return 228;
  if (!exists)
    return 229;

  if (wyl_policy_store_role_exists (NULL, "site.exists-role", &exists)
      != WYRELOG_E_INVALID)
    return 230;
  if (wyl_policy_store_permission_exists (store, NULL, &exists)
      != WYRELOG_E_INVALID)
    return 231;
  if (wyl_policy_store_permission_exists (store, "site.exists-perm", NULL)
      != WYRELOG_E_INVALID)
    return 232;
  return 0;
}

static gint
check_store_grants_role_inheritance (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 48;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 49;
  if (wyl_policy_store_upsert_role (store, "site.child-role", "child role")
      != WYRELOG_E_OK)
    return 58;
  if (wyl_policy_store_upsert_role (store, "site.parent-role", "parent role")
      != WYRELOG_E_OK)
    return 59;
  if (wyl_policy_store_grant_role_inheritance (store, "site.child-role",
          "site.parent-role") != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_grant_role_inheritance (store, "site.child-role",
          "site.parent-role") != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "site.inherited.read",
          "inherited read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_role_permission (store, "site.parent-role",
          "site.inherited.read") != WYRELOG_E_OK)
    return 63;

  RoleInheritanceExpect expect = {
    .child_role_id = "site.child-role",
    .parent_role_id = "site.parent-role",
  };
  if (wyl_policy_store_foreach_role_inheritance (store,
          role_inheritance_expect_cb, &expect) != WYRELOG_E_OK)
    return 64;
  if (expect.matches != 1)
    return 65;

  RolePermissionExpect permission_expect = {
    .role_id = "site.child-role",
    .perm_id = "site.inherited.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &permission_expect) != WYRELOG_E_OK)
    return 66;
  if (permission_expect.matches != 1)
    return 67;
  return 0;
}

static gint
check_store_grants_role_membership (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 68;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 69;
  if (wyl_policy_store_upsert_role (store, "site.member-role", "member role")
      != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "site.member-role", "member-scope", "grant") != WYRELOG_E_OK)
    return 100;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 72;

  RoleMembershipExpect expect = {
    .subject_id = "member-user",
    .role_id = "site.member-role",
    .scope = "member-scope",
  };
  if (wyl_policy_store_foreach_role_membership (store,
          role_membership_expect_cb, &expect) != WYRELOG_E_OK)
    return 73;
  if (expect.matches != 1)
    return 74;
  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "site.member-role", "member-scope", &exists) != WYRELOG_E_OK)
    return 101;
  if (!exists)
    return 102;

  RoleMembershipEventExpect event_expect = {
    .subject_id = "member-user",
    .role_id = "site.member-role",
    .scope = "member-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event (store,
          role_membership_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 103;
  if (event_expect.matches != 1)
    return 104;
  if (wyl_policy_store_revoke_role_membership (store, "member-user",
          "site.member-role", "member-scope") != WYRELOG_E_OK)
    return 105;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "site.member-role", "member-scope", "revoke") != WYRELOG_E_OK)
    return 106;
  exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "site.member-role", "member-scope", &exists) != WYRELOG_E_OK)
    return 107;
  if (exists)
    return 108;
  return 0;
}

static gint
check_store_grants_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "site.direct.read",
          "direct read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 63;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 64;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "site.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 65;
  if (!exists)
    return 66;
  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "site.direct.read",
    .scope = "direct-scope",
  };
  if (wyl_policy_store_foreach_direct_permission (store,
          direct_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 78;
  if (expect.matches != 1)
    return 79;
  if (wyl_policy_store_revoke_direct_permission (store, "direct-user",
          "site.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 67;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "site.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 68;
  if (exists)
    return 69;
  return 0;
}

static gint
check_store_checks_effective_subject_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 233;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 234;
  if (wyl_policy_store_upsert_permission (store, "site.effective.read",
          "effective read", "basic") != WYRELOG_E_OK)
    return 235;
  if (wyl_policy_store_grant_direct_permission (store, "direct-effective-user",
          "site.effective.read", "effective-scope") != WYRELOG_E_OK)
    return 236;

  gboolean has_permission = FALSE;
  if (wyl_policy_store_subject_has_permission (store, "direct-effective-user",
          "site.effective.read", "effective-scope", &has_permission)
      != WYRELOG_E_OK)
    return 237;
  if (!has_permission)
    return 238;

  if (wyl_policy_store_upsert_role (store, "site.effective-role",
          "effective role") != WYRELOG_E_OK)
    return 239;
  if (wyl_policy_store_grant_role_permission (store, "site.effective-role",
          "site.effective.read") != WYRELOG_E_OK)
    return 240;
  if (wyl_policy_store_grant_role_membership (store, "role-effective-user",
          "site.effective-role", "effective-scope") != WYRELOG_E_OK)
    return 241;

  has_permission = FALSE;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "effective-scope", &has_permission)
      != WYRELOG_E_OK)
    return 242;
  if (!has_permission)
    return 243;

  has_permission = TRUE;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "other-scope", &has_permission)
      != WYRELOG_E_OK)
    return 244;
  if (has_permission)
    return 245;
  if (wyl_policy_store_subject_has_permission (store, "role-effective-user",
          "site.effective.read", "effective-scope", NULL)
      != WYRELOG_E_INVALID)
    return 246;
  return 0;
}

static gint
check_role_membership_mutation_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 197;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 198;
  if (wyl_policy_store_upsert_role (store, "site.rollback-role",
          "rollback role") != WYRELOG_E_OK)
    return 199;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_role_membership_event "
          "BEFORE INSERT ON role_membership_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 200;

  if (wyl_policy_store_apply_role_membership_mutation (store,
          "rollback-role-user", "site.rollback-role", "rollback-role-scope",
          TRUE) != WYRELOG_E_IO)
    return 201;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "rollback-role-user",
          "site.rollback-role", "rollback-role-scope", &exists)
      != WYRELOG_E_OK)
    return 202;
  if (exists)
    return 203;

  RoleMembershipEventExpect expect = {
    .subject_id = "rollback-role-user",
    .role_id = "site.rollback-role",
    .scope = "rollback-role-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event (store,
          role_membership_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 204;
  if (expect.matches != 0)
    return 205;
  return 0;
}

static gint
check_role_membership_revoke_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 206;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 207;
  if (wyl_policy_store_upsert_role (store, "site.rollback-role-revoke",
          "rollback role revoke") != WYRELOG_E_OK)
    return 208;
  if (wyl_policy_store_grant_role_membership (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope") != WYRELOG_E_OK)
    return 209;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_role_membership_revoke_event "
          "BEFORE INSERT ON role_membership_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 210;

  if (wyl_policy_store_apply_role_membership_mutation (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope", FALSE) != WYRELOG_E_IO)
    return 211;

  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store,
          "rollback-role-revoke-user", "site.rollback-role-revoke",
          "rollback-role-revoke-scope", &exists) != WYRELOG_E_OK)
    return 212;
  if (!exists)
    return 213;
  return 0;
}

static gint
check_store_appends_direct_permission_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 92;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 93;
  if (wyl_policy_store_append_direct_permission_event (store, "direct-user",
          "site.direct.read", "direct-scope", "grant") != WYRELOG_E_OK)
    return 94;

  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "site.direct.read",
    .scope = "direct-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event (store,
          direct_permission_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 95;
  if (expect.matches != 1)
    return 96;
  return 0;
}

static gint
check_direct_permission_mutation_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 180;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 181;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_direct_permission_event "
          "BEFORE INSERT ON direct_permission_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 182;

  if (wyl_policy_store_apply_direct_permission_mutation (store,
          "rollback-user", "site.rollback-direct", "rollback-scope", TRUE)
      != WYRELOG_E_IO)
    return 183;

  gboolean exists = TRUE;
  if (wyl_policy_store_direct_permission_exists (store, "rollback-user",
          "site.rollback-direct", "rollback-scope", &exists) != WYRELOG_E_OK)
    return 184;
  if (exists)
    return 185;

  DirectPermissionExpect expect = {
    .subject_id = "rollback-user",
    .perm_id = "site.rollback-direct",
    .scope = "rollback-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event (store,
          direct_permission_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 186;
  if (expect.matches != 0)
    return 187;

  gboolean permission_exists = FALSE;
  if (wyl_policy_store_table_exists (store, "permissions", &permission_exists)
      != WYRELOG_E_OK || !permission_exists)
    return 188;
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
          "SELECT 1 FROM permissions WHERE perm_id = ?;", -1, &stmt,
          NULL) != SQLITE_OK)
    return 214;
  if (sqlite3_bind_text (stmt, 1, "site.rollback-direct", -1,
          SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 215;
  }
  int step_rc = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (step_rc == SQLITE_ROW)
    return 216;
  if (step_rc != SQLITE_DONE)
    return 217;
  return 0;
}

static gint
check_direct_permission_revoke_rolls_back_on_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 189;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 190;
  if (wyl_policy_store_upsert_permission (store, "site.rollback-revoke",
          "rollback revoke", "basic") != WYRELOG_E_OK)
    return 191;
  if (wyl_policy_store_grant_direct_permission (store, "rollback-revoke-user",
          "site.rollback-revoke", "rollback-revoke-scope") != WYRELOG_E_OK)
    return 192;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_direct_permission_revoke_event "
          "BEFORE INSERT ON direct_permission_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 193;

  if (wyl_policy_store_apply_direct_permission_mutation (store,
          "rollback-revoke-user", "site.rollback-revoke",
          "rollback-revoke-scope", FALSE) != WYRELOG_E_IO)
    return 194;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store,
          "rollback-revoke-user", "site.rollback-revoke",
          "rollback-revoke-scope", &exists) != WYRELOG_E_OK)
    return 195;
  if (!exists)
    return 196;
  return 0;
}

static gint
check_store_sets_permission_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 218;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 219;
  if (wyl_policy_store_set_permission_state (store, "perm-user",
          "wr.perm.read", "perm-scope", "armed") != WYRELOG_E_OK)
    return 220;
  if (wyl_policy_store_set_permission_state (store, "perm-user",
          "wr.perm.read", "perm-scope", "dormant") != WYRELOG_E_OK)
    return 221;

  gboolean exists = FALSE;
  if (wyl_policy_store_permission_state_exists (store, "perm-user",
          "wr.perm.read", "perm-scope", &exists) != WYRELOG_E_OK)
    return 222;
  if (!exists)
    return 223;
  if (wyl_policy_store_permission_state_exists (store, "perm-user",
          "wr.perm.read", "missing-scope", &exists) != WYRELOG_E_OK)
    return 224;
  if (exists)
    return 225;

  PermissionStateExpect expect = {
    .subject_id = "perm-user",
    .perm_id = "wr.perm.read",
    .scope = "perm-scope",
    .state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 226;
  if (expect.matches != 1)
    return 227;
  return 0;
}

static gint
check_store_appends_permission_state_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 228;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 229;
  gint64 event_id = -1;
  if (wyl_policy_store_append_permission_state_event (store, "perm-event-user",
          "wr.perm.event", "perm-event-scope", "grant", "dormant", "armed",
          &event_id) != WYRELOG_E_OK)
    return 230;

  PermissionStateEventExpect expect = {
    .event_id = event_id,
    .subject_id = "perm-event-user",
    .perm_id = "wr.perm.event",
    .scope = "perm-event-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 231;
  if (expect.matches != 1)
    return 232;
  return 0;
}

static gint
check_store_applies_permission_state_transition (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 238;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 239;

  gint64 grant_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-apply-user", "wr.perm.apply", "perm-apply-scope", "grant",
          &grant_event_id) != WYRELOG_E_OK)
    return 240;
  if (grant_event_id <= 0)
    return 241;

  PermissionStateExpect state_expect = {
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &state_expect) != WYRELOG_E_OK)
    return 242;
  if (state_expect.matches != 1)
    return 243;

  PermissionStateEventExpect grant_expect = {
    .event_id = grant_event_id,
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &grant_expect) != WYRELOG_E_OK)
    return 244;
  if (grant_expect.matches != 1)
    return 245;

  gint64 revoke_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-apply-user", "wr.perm.apply", "perm-apply-scope", "revoke",
          &revoke_event_id) != WYRELOG_E_OK)
    return 246;
  if (revoke_event_id <= grant_event_id)
    return 247;

  PermissionStateExpect dormant_expect = {
    .subject_id = "perm-apply-user",
    .perm_id = "wr.perm.apply",
    .scope = "perm-apply-scope",
    .state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &dormant_expect) != WYRELOG_E_OK)
    return 248;
  if (dormant_expect.matches != 1)
    return 249;

  gint64 trigger_event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-trigger-user", "wr.perm.trigger", "perm-trigger-scope",
          "grant", NULL) != WYRELOG_E_OK)
    return 279;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-trigger-user", "wr.perm.trigger", "perm-trigger-scope",
          "trigger", &trigger_event_id) != WYRELOG_E_OK)
    return 280;
  if (trigger_event_id <= revoke_event_id)
    return 281;

  PermissionStateExpect firing_expect = {
    .subject_id = "perm-trigger-user",
    .perm_id = "wr.perm.trigger",
    .scope = "perm-trigger-scope",
    .state = "firing",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_expect_cb, &firing_expect) != WYRELOG_E_OK)
    return 282;
  if (firing_expect.matches != 1)
    return 283;

  PermissionStateEventExpect trigger_expect = {
    .event_id = trigger_event_id,
    .subject_id = "perm-trigger-user",
    .perm_id = "wr.perm.trigger",
    .scope = "perm-trigger-scope",
    .event = "trigger",
    .from_state = "armed",
    .to_state = "firing",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &trigger_expect) != WYRELOG_E_OK)
    return 284;
  if (trigger_expect.matches != 1)
    return 285;
  return 0;
}

static gint
check_store_permission_state_transition_rejects_invalid_edge (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 250;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 251;

  gint64 event_id = 77;
  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-invalid-user", "wr.perm.invalid", "perm-invalid-scope",
          "revoke", &event_id) != WYRELOG_E_POLICY)
    return 252;
  if (event_id != -1)
    return 253;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-invalid-user",
          "wr.perm.invalid", "perm-invalid-scope", &exists) != WYRELOG_E_OK)
    return 254;
  if (exists)
    return 255;

  PermissionStateEventExpect expect = {
    .event_id = -1,
    .subject_id = "perm-invalid-user",
    .perm_id = "wr.perm.invalid",
    .scope = "perm-invalid-scope",
    .event = "revoke",
    .from_state = "dormant",
    .to_state = "dormant",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 256;
  if (expect.matches != 0)
    return 257;
  return 0;
}

static gint
check_store_permission_state_transition_rolls_back_event_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 258;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 259;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_permission_state_event "
          "BEFORE INSERT ON permission_state_events "
          "BEGIN SELECT RAISE(ABORT, 'fail event'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 260;

  if (wyl_policy_store_apply_permission_state_transition (store,
          "perm-rollback-user", "wr.perm.rollback", "perm-rollback-scope",
          "grant", NULL) != WYRELOG_E_IO)
    return 261;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-rollback-user",
          "wr.perm.rollback", "perm-rollback-scope", &exists)
      != WYRELOG_E_OK)
    return 262;
  if (exists)
    return 263;
  return 0;
}

static gint
check_store_permission_state_transition_appends_audit (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 264;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 265;

  gint64 event_id = -1;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-audit-user", "wr.perm.audit", "perm-audit-scope", "grant",
          &event_id, "01890c10-2e3f-7000-8000-000000000010", 999,
          "perm-audit-user", "permission_state.grant", "wr.perm.audit",
          "allowed", "permission_state", WYL_DECISION_ALLOW) != WYRELOG_E_OK)
    return 266;
  if (event_id <= 0)
    return 267;

  AuditEventExpect audit_expect = {
    .id = "01890c10-2e3f-7000-8000-000000000010",
    .created_at_us = 999,
    .subject_id = "perm-audit-user",
    .action = "permission_state.grant",
    .resource_id = "wr.perm.audit",
    .deny_reason = "allowed",
    .deny_origin = "permission_state",
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          &audit_expect) != WYRELOG_E_OK)
    return 268;
  if (audit_expect.matches != 1)
    return 269;
  return 0;
}

static gint
check_store_permission_state_transition_rolls_back_audit_failure (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 270;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 271;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "CREATE TRIGGER fail_permission_state_audit "
          "BEFORE INSERT ON audit_events "
          "BEGIN SELECT RAISE(ABORT, 'fail audit'); END;",
          NULL, NULL, NULL) != SQLITE_OK)
    return 272;

  gint64 event_id = 99;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-audit-rollback-user", "wr.perm.audit.rollback",
          "perm-audit-rollback-scope", "grant", &event_id,
          "01890c10-2e3f-7000-8000-000000000011", 1000,
          "perm-audit-rollback-user", "permission_state.grant",
          "wr.perm.audit.rollback", "allowed", "permission_state",
          WYL_DECISION_ALLOW) != WYRELOG_E_IO)
    return 273;
  if (event_id != -1)
    return 274;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store,
          "perm-audit-rollback-user", "wr.perm.audit.rollback",
          "perm-audit-rollback-scope", &exists) != WYRELOG_E_OK)
    return 275;
  if (exists)
    return 276;

  PermissionStateEventExpect event_expect = {
    .subject_id = "perm-audit-rollback-user",
    .perm_id = "wr.perm.audit.rollback",
    .scope = "perm-audit-rollback-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 277;
  if (event_expect.matches != 0)
    return 278;
  return 0;
}

static gint
check_store_permission_state_transition_rejects_invalid_audit (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 286;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 287;

  gint64 event_id = 101;
  if (wyl_policy_store_apply_permission_state_transition_with_audit (store,
          "perm-bad-audit-user", "wr.perm.bad.audit",
          "perm-bad-audit-scope", "grant", &event_id, "not-a-wyl-id", 1000,
          "perm-bad-audit-user", "permission_state.grant",
          "wr.perm.bad.audit", "allowed", "permission_state",
          WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 288;
  if (event_id != -1)
    return 289;

  gboolean exists = TRUE;
  if (wyl_policy_store_permission_state_exists (store, "perm-bad-audit-user",
          "wr.perm.bad.audit", "perm-bad-audit-scope", &exists)
      != WYRELOG_E_OK)
    return 290;
  if (exists)
    return 291;

  PermissionStateEventExpect event_expect = {
    .subject_id = "perm-bad-audit-user",
    .perm_id = "wr.perm.bad.audit",
    .scope = "perm-bad-audit-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 292;
  if (event_expect.matches != 0)
    return 293;
  return 0;
}

static gint
check_store_sets_principal_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 80;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 81;
  if (wyl_policy_store_set_principal_state (store, "principal-user",
          "mfa_required") != WYRELOG_E_OK)
    return 82;
  if (wyl_policy_store_set_principal_state (store, "principal-user",
          "authenticated") != WYRELOG_E_OK)
    return 83;

  PrincipalStateExpect expect = {
    .subject_id = "principal-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (store,
          principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 84;
  if (expect.matches != 1)
    return 85;
  return 0;
}

static gint
check_store_sets_session_state (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 86;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 87;
  if (wyl_policy_store_set_session_state (store, "session/1", "active")
      != WYRELOG_E_OK)
    return 88;
  if (wyl_policy_store_set_session_state (store, "session/1", "closed")
      != WYRELOG_E_OK)
    return 89;

  SessionStateExpect expect = {
    .session_id = "session/1",
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (store,
          session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 90;
  if (expect.matches != 1)
    return 91;
  return 0;
}

static gint
check_store_appends_principal_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 92;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 93;
  gint64 event_id = -1;
  if (wyl_policy_store_append_principal_event (store, "principal-user",
          "login_skip_mfa", "unverified", "authenticated", &event_id)
      != WYRELOG_E_OK)
    return 94;

  PrincipalEventExpect expect = {
    .event_id = event_id,
    .subject_id = "principal-user",
    .event = "login_skip_mfa",
    .from_state = "unverified",
    .to_state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_event (store,
          principal_event_expect_cb, &expect) != WYRELOG_E_OK)
    return 95;
  if (expect.matches != 1)
    return 96;
  return 0;
}

static gint
check_store_appends_session_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 97;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 98;
  gint64 event_id = -1;
  if (wyl_policy_store_append_session_event (store, "session/1",
          "elevate_grant", "active", "elevated", &event_id) != WYRELOG_E_OK)
    return 99;

  SessionEventExpect expect = {
    .event_id = event_id,
    .session_id = "session/1",
    .event = "elevate_grant",
    .from_state = "active",
    .to_state = "elevated",
  };
  if (wyl_policy_store_foreach_session_event (store, session_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 100;
  if (expect.matches != 1)
    return 101;
  return 0;
}

static gint
check_store_distinguishes_duplicate_events (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 102;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 103;
  gint64 principal_first = -1;
  gint64 principal_second = -1;
  if (wyl_policy_store_append_principal_event (store, "principal-dup",
          "login_ok", "unverified", "mfa_required", &principal_first)
      != WYRELOG_E_OK)
    return 104;
  if (wyl_policy_store_append_principal_event (store, "principal-dup",
          "login_ok", "unverified", "mfa_required", &principal_second)
      != WYRELOG_E_OK)
    return 105;
  if (principal_first <= 0 || principal_second <= principal_first)
    return 106;

  PrincipalEventExpect principal_expect = {
    .subject_id = "principal-dup",
    .event = "login_ok",
    .from_state = "unverified",
    .to_state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_event (store,
          principal_event_expect_cb, &principal_expect) != WYRELOG_E_OK)
    return 107;
  if (principal_expect.matches != 2)
    return 108;

  gint64 session_first = -1;
  gint64 session_second = -1;
  if (wyl_policy_store_append_session_event (store, "session-dup",
          "elevate_grant", "active", "elevated", &session_first)
      != WYRELOG_E_OK)
    return 109;
  if (wyl_policy_store_append_session_event (store, "session-dup",
          "elevate_grant", "active", "elevated", &session_second)
      != WYRELOG_E_OK)
    return 110;
  if (session_first <= 0 || session_second <= session_first)
    return 111;

  SessionEventExpect session_expect = {
    .session_id = "session-dup",
    .event = "elevate_grant",
    .from_state = "active",
    .to_state = "elevated",
  };
  if (wyl_policy_store_foreach_session_event (store, session_event_expect_cb,
          &session_expect) != WYRELOG_E_OK)
    return 112;
  if (session_expect.matches != 2)
    return 113;
  gint64 perm_first = -1;
  gint64 perm_second = -1;
  if (wyl_policy_store_append_permission_state_event (store, "perm-dup-user",
          "wr.perm.dup", "perm-dup-scope", "grant", "dormant", "armed",
          &perm_first) != WYRELOG_E_OK)
    return 233;
  if (wyl_policy_store_append_permission_state_event (store, "perm-dup-user",
          "wr.perm.dup", "perm-dup-scope", "grant", "dormant", "armed",
          &perm_second) != WYRELOG_E_OK)
    return 234;
  if (perm_first <= 0 || perm_second <= perm_first)
    return 235;
  PermissionStateEventExpect perm_expect = {
    .subject_id = "perm-dup-user",
    .perm_id = "wr.perm.dup",
    .scope = "perm-dup-scope",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_expect_cb, &perm_expect) != WYRELOG_E_OK)
    return 236;
  if (perm_expect.matches != 2)
    return 237;
  return 0;
}

static gint
check_store_appends_audit_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 120;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 121;
  if (wyl_policy_store_append_audit_event (store,
          "01890c10-2e3f-7000-8000-000000000001", 123,
          "audit-user", "read", "doc/1", "not_armed", "perm_state",
          WYL_DECISION_DENY) != WYRELOG_E_OK)
    return 122;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT subject_id, action, resource_id, deny_reason, deny_origin, "
      "decision FROM audit_events WHERE id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 123;
  if (sqlite3_bind_text (stmt, 1, "01890c10-2e3f-7000-8000-000000000001",
          -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 124;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 125;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
          "audit-user") != 0)
    rc = 126;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
          "read") != 0)
    rc = 127;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 2),
          "doc/1") != 0)
    rc = 128;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 3),
          "not_armed") != 0)
    rc = 129;
  else if (g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
          "perm_state") != 0)
    rc = 130;
  else if (sqlite3_column_int (stmt, 5) != WYL_DECISION_DENY)
    rc = 131;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_iterates_audit_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 132;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 133;
  if (wyl_policy_store_append_audit_event (store,
          "01890c10-2e3f-7000-8000-000000000002", 456,
          "audit-user", "write", "doc/2", "allowed", "test",
          WYL_DECISION_ALLOW) != WYRELOG_E_OK)
    return 134;

  AuditEventExpect expect = {
    .id = "01890c10-2e3f-7000-8000-000000000002",
    .created_at_us = 456,
    .subject_id = "audit-user",
    .action = "write",
    .resource_id = "doc/2",
    .deny_reason = "allowed",
    .deny_origin = "test",
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 135;
  if (expect.matches != 1)
    return 136;
  return 0;
}

static gint
check_store_append_audit_event_is_idempotent (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  static const gchar *id = "01890c10-2e3f-7000-8000-000000000005";

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 144;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 145;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "same.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK)
    return 146;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "same.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_OK)
    return 147;
  if (wyl_policy_store_append_audit_event (store, id, 777, NULL,
          "different.action", NULL, NULL, NULL, WYL_DECISION_ALLOW)
      != WYRELOG_E_POLICY)
    return 148;

  sqlite3_stmt *stmt = NULL;
  static const gchar *sql = "SELECT COUNT(*) FROM audit_events WHERE id = ?;";
  if (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql, -1, &stmt,
          NULL) != SQLITE_OK)
    return 149;
  if (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
    sqlite3_finalize (stmt);
    return 150;
  }

  int step_rc = sqlite3_step (stmt);
  gint rc = 0;
  if (step_rc != SQLITE_ROW)
    rc = 151;
  else if (sqlite3_column_int64 (stmt, 0) != 1)
    rc = 152;

  sqlite3_finalize (stmt);
  return rc;
}

static gint
check_store_rejects_corrupt_audit_events (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 137;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 138;

  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, action, decision) "
          "VALUES ('not-a-uuid', 1, 'bad.id', 1);",
          NULL, NULL, NULL) != SQLITE_OK)
    return 139;
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          NULL) != WYRELOG_E_POLICY)
    return 140;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "DELETE FROM audit_events;", NULL, NULL, NULL) != SQLITE_OK)
    return 141;

  if (sqlite3_exec (wyl_policy_store_get_db (store),
          "INSERT INTO audit_events "
          "(id, created_at_us, action, decision) "
          "VALUES ('01890c10-2e3f-7000-8000-000000000004', -1, "
          "'bad.timestamp', 1);", NULL, NULL, NULL) != SQLITE_OK)
    return 142;
  if (wyl_policy_store_foreach_audit_event (store, audit_event_expect_cb,
          NULL) != WYRELOG_E_POLICY)
    return 143;

  return 0;
}

static gint
check_store_rejects_bad_direct_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean exists = FALSE;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_IO)
    return 72;
  if (wyl_policy_store_grant_direct_permission (NULL, "direct-user",
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 73;
  if (wyl_policy_store_revoke_direct_permission (store, NULL,
          "missing-perm", "direct-scope") != WYRELOG_E_INVALID)
    return 74;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", NULL) != WYRELOG_E_INVALID)
    return 75;
  if (wyl_policy_store_foreach_direct_permission (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 78;
  if (wyl_policy_store_append_direct_permission_event (store, NULL,
          "missing-perm", "direct-scope", "grant") != WYRELOG_E_INVALID)
    return 79;
  if (wyl_policy_store_foreach_direct_permission_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 80;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "missing-perm", "direct-scope", &exists) != WYRELOG_E_OK)
    return 76;
  if (exists)
    return 77;
  return 0;
}

static gint
check_store_rejects_bad_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 50;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 51;
  if (wyl_policy_store_grant_role_permission (store, "missing-role",
          "missing-perm") != WYRELOG_E_IO)
    return 52;
  if (wyl_policy_store_upsert_role (NULL, "role", "role") != WYRELOG_E_INVALID)
    return 53;
  if (wyl_policy_store_upsert_permission (store, "perm", "perm", "unknown")
      != WYRELOG_E_IO)
    return 54;
  if (wyl_policy_store_foreach_role_permission (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 55;
  if (wyl_policy_store_grant_role_inheritance (store, "missing-child",
          "missing-parent") != WYRELOG_E_IO)
    return 58;
  if (wyl_policy_store_foreach_role_inheritance (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 59;
  if (wyl_policy_store_grant_role_membership (store, "role-user",
          "missing-role", "role-scope") != WYRELOG_E_IO)
    return 97;
  if (wyl_policy_store_grant_role_membership (store, NULL, "missing-role",
          "role-scope") != WYRELOG_E_INVALID)
    return 98;
  if (wyl_policy_store_revoke_role_membership (store, NULL, "missing-role",
          "role-scope") != WYRELOG_E_INVALID)
    return 100;
  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, NULL, "missing-role",
          "role-scope", &exists) != WYRELOG_E_INVALID)
    return 101;
  if (wyl_policy_store_foreach_role_membership (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 99;
  if (wyl_policy_store_append_role_membership_event (store, "role-user",
          "missing-role", "role-scope", "grant") != WYRELOG_E_IO)
    return 102;
  if (wyl_policy_store_append_role_membership_event (store, "role-user",
          "missing-role", "role-scope", "invalid") != WYRELOG_E_IO)
    return 103;
  if (wyl_policy_store_foreach_role_membership_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 104;
  if (wyl_policy_store_set_permission_state (store, NULL, "wr.read", "scope",
          "armed") != WYRELOG_E_INVALID)
    return 105;
  if (wyl_policy_store_set_permission_state (store, "user", NULL, "scope",
          "armed") != WYRELOG_E_INVALID)
    return 106;
  if (wyl_policy_store_set_permission_state (store, "user", "wr.read", NULL,
          "armed") != WYRELOG_E_INVALID)
    return 107;
  if (wyl_policy_store_set_permission_state (store, "user", "wr.read", "scope",
          NULL) != WYRELOG_E_INVALID)
    return 108;
  gboolean permission_state_exists = FALSE;
  if (wyl_policy_store_permission_state_exists (store, NULL, "wr.read", "scope",
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 109;
  if (wyl_policy_store_permission_state_exists (store, "user", NULL, "scope",
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 110;
  if (wyl_policy_store_permission_state_exists (store, "user", "wr.read", NULL,
          &permission_state_exists) != WYRELOG_E_INVALID)
    return 111;
  if (wyl_policy_store_permission_state_exists (store, "user", "wr.read",
          "scope", NULL) != WYRELOG_E_INVALID)
    return 112;
  if (wyl_policy_store_foreach_permission_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 113;
  if (wyl_policy_store_append_permission_state_event (store, NULL, "wr.read",
          "scope", "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 114;
  if (wyl_policy_store_append_permission_state_event (store, "user", NULL,
          "scope", "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 115;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          NULL, "grant", "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 116;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", NULL, "dormant", "armed", NULL) != WYRELOG_E_INVALID)
    return 117;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", "grant", NULL, "armed", NULL) != WYRELOG_E_INVALID)
    return 118;
  if (wyl_policy_store_append_permission_state_event (store, "user", "wr.read",
          "scope", "grant", "dormant", NULL, NULL) != WYRELOG_E_INVALID)
    return 119;
  if (wyl_policy_store_foreach_permission_state_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 120;
  if (wyl_policy_store_set_principal_state (store, NULL, "authenticated")
      != WYRELOG_E_INVALID)
    return 56;
  if (wyl_policy_store_foreach_principal_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 57;
  if (wyl_policy_store_append_principal_event (store, NULL, "login_ok",
          "unverified", "mfa_required", NULL) != WYRELOG_E_INVALID)
    return 92;
  if (wyl_policy_store_foreach_principal_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 93;
  if (wyl_policy_store_set_session_state (store, NULL, "active")
      != WYRELOG_E_INVALID)
    return 58;
  if (wyl_policy_store_foreach_session_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 59;
  if (wyl_policy_store_append_session_event (store, NULL, "request", "idle",
          "active", NULL) != WYRELOG_E_INVALID)
    return 60;
  if (wyl_policy_store_foreach_session_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 61;
  if (wyl_policy_store_append_audit_event (store, NULL, 0, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 94;
  if (wyl_policy_store_append_audit_event (store,
          "01890c10-2e3f-7000-8000-000000000003", -1, NULL, NULL, NULL,
          NULL, NULL, WYL_DECISION_ALLOW) != WYRELOG_E_INVALID)
    return 95;
  if (wyl_policy_store_append_audit_event (store, "audit-bad", 0, NULL,
          NULL, NULL, NULL, NULL, (wyl_decision_t) 9) != WYRELOG_E_INVALID)
    return 96;
  if (wyl_policy_store_foreach_audit_event (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 105;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_store_creates_authority_schema ()) != 0)
    return rc;
  if ((rc = check_template_schema_creates_state_tables ()) != 0)
    return rc;
  if ((rc = check_store_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_store_gets_default_deployment_mode ()) != 0)
    return rc;
  if ((rc = check_store_sets_deployment_mode ()) != 0)
    return rc;
  if ((rc = check_handle_owns_policy_store ()) != 0)
    return rc;
  if ((rc = check_store_seeds_builtin_catalog ()) != 0)
    return rc;
  if ((rc = check_store_rejects_builtin_catalog_drift ()) != 0)
    return rc;
  if ((rc = check_store_rejects_builtin_catalog_upsert_drift ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_permission ()) != 0)
    return rc;
  if ((rc = check_store_catalog_existence_probes ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_inheritance ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_membership ()) != 0)
    return rc;
  if ((rc = check_store_grants_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_checks_effective_subject_permission ()) != 0)
    return rc;
  if ((rc = check_role_membership_mutation_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_role_membership_revoke_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_appends_direct_permission_event ()) != 0)
    return rc;
  if ((rc = check_direct_permission_mutation_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_direct_permission_revoke_rolls_back_on_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_sets_permission_state ()) != 0)
    return rc;
  if ((rc = check_store_appends_permission_state_event ()) != 0)
    return rc;
  if ((rc = check_store_applies_permission_state_transition ()) != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rejects_invalid_edge ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rolls_back_event_failure ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_appends_audit ()) != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rolls_back_audit_failure ())
      != 0)
    return rc;
  if ((rc = check_store_permission_state_transition_rejects_invalid_audit ())
      != 0)
    return rc;
  if ((rc = check_store_sets_principal_state ()) != 0)
    return rc;
  if ((rc = check_store_sets_session_state ()) != 0)
    return rc;
  if ((rc = check_store_appends_principal_event ()) != 0)
    return rc;
  if ((rc = check_store_appends_session_event ()) != 0)
    return rc;
  if ((rc = check_store_distinguishes_duplicate_events ()) != 0)
    return rc;
  if ((rc = check_store_appends_audit_event ()) != 0)
    return rc;
  if ((rc = check_store_iterates_audit_event ()) != 0)
    return rc;
  if ((rc = check_store_append_audit_event_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_store_rejects_corrupt_audit_events ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_role_permission ()) != 0)
    return rc;
  return 0;
}
