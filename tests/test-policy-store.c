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
    "roles",
    "permissions",
    "role_permissions",
    "direct_permissions",
    "principal_events",
    "principal_states",
    "session_states",
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
    "roles",
    "permissions",
    "role_permissions",
    "direct_permissions",
    "principal_events",
    "principal_states",
    "session_states",
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

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
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

typedef struct
{
  const gchar *subject_id;
  const gchar *state;
  guint matches;
} PrincipalStateExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PrincipalEventExpect;

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
principal_event_expect_cb (const gchar *subject_id, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  PrincipalEventExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
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

typedef struct
{
  const gchar *role_id;
  const gchar *perm_id;
  guint matches;
} RolePermissionExpect;

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

static gint
check_store_grants_role_permission (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 40;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 41;
  if (wyl_policy_store_upsert_role (store, "wr.test-role", "test role")
      != WYRELOG_E_OK)
    return 42;
  if (wyl_policy_store_upsert_permission (store, "wr.test.read", "test read",
          "basic") != WYRELOG_E_OK)
    return 43;
  if (wyl_policy_store_grant_role_permission (store, "wr.test-role",
          "wr.test.read") != WYRELOG_E_OK)
    return 44;
  if (wyl_policy_store_grant_role_permission (store, "wr.test-role",
          "wr.test.read") != WYRELOG_E_OK)
    return 45;

  RolePermissionExpect expect = {
    .role_id = "wr.test-role",
    .perm_id = "wr.test.read",
  };
  if (wyl_policy_store_foreach_role_permission (store,
          role_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 46;
  if (expect.matches != 1)
    return 47;
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
  if (wyl_policy_store_upsert_permission (store, "wr.direct.read",
          "direct read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 63;
  if (wyl_policy_store_grant_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 64;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "wr.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 65;
  if (!exists)
    return 66;
  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "wr.direct.read",
    .scope = "direct-scope",
  };
  if (wyl_policy_store_foreach_direct_permission (store,
          direct_permission_expect_cb, &expect) != WYRELOG_E_OK)
    return 78;
  if (expect.matches != 1)
    return 79;
  if (wyl_policy_store_revoke_direct_permission (store, "direct-user",
          "wr.direct.read", "direct-scope") != WYRELOG_E_OK)
    return 67;
  if (wyl_policy_store_direct_permission_exists (store, "direct-user",
          "wr.direct.read", "direct-scope", &exists) != WYRELOG_E_OK)
    return 68;
  if (exists)
    return 69;
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
  if (wyl_policy_store_append_principal_event (store, "principal-user",
          "login_skip_mfa", "unverified", "authenticated") != WYRELOG_E_OK)
    return 94;

  PrincipalEventExpect expect = {
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
  if (wyl_policy_store_set_principal_state (store, NULL, "authenticated")
      != WYRELOG_E_INVALID)
    return 56;
  if (wyl_policy_store_foreach_principal_state (store, NULL, NULL)
      != WYRELOG_E_INVALID)
    return 57;
  if (wyl_policy_store_append_principal_event (store, NULL, "login_ok",
          "unverified", "mfa_required") != WYRELOG_E_INVALID)
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
  if ((rc = check_handle_owns_policy_store ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_permission ()) != 0)
    return rc;
  if ((rc = check_store_grants_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_sets_principal_state ()) != 0)
    return rc;
  if ((rc = check_store_sets_session_state ()) != 0)
    return rc;
  if ((rc = check_store_appends_principal_event ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_rejects_bad_role_permission ()) != 0)
    return rc;
  return 0;
}
