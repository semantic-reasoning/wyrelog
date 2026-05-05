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
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
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
    "roles",
    "permissions",
    "role_permissions",
    "role_inheritances",
    "role_memberships",
    "role_membership_events",
    "direct_permissions",
    "direct_permission_events",
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
check_store_grants_role_inheritance (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 48;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 49;
  if (wyl_policy_store_upsert_role (store, "wr.child-role", "child role")
      != WYRELOG_E_OK)
    return 58;
  if (wyl_policy_store_upsert_role (store, "wr.parent-role", "parent role")
      != WYRELOG_E_OK)
    return 59;
  if (wyl_policy_store_grant_role_inheritance (store, "wr.child-role",
          "wr.parent-role") != WYRELOG_E_OK)
    return 60;
  if (wyl_policy_store_grant_role_inheritance (store, "wr.child-role",
          "wr.parent-role") != WYRELOG_E_OK)
    return 61;
  if (wyl_policy_store_upsert_permission (store, "wr.inherited.read",
          "inherited read", "basic") != WYRELOG_E_OK)
    return 62;
  if (wyl_policy_store_grant_role_permission (store, "wr.parent-role",
          "wr.inherited.read") != WYRELOG_E_OK)
    return 63;

  RoleInheritanceExpect expect = {
    .child_role_id = "wr.child-role",
    .parent_role_id = "wr.parent-role",
  };
  if (wyl_policy_store_foreach_role_inheritance (store,
          role_inheritance_expect_cb, &expect) != WYRELOG_E_OK)
    return 64;
  if (expect.matches != 1)
    return 65;

  RolePermissionExpect permission_expect = {
    .role_id = "wr.child-role",
    .perm_id = "wr.inherited.read",
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
  if (wyl_policy_store_upsert_role (store, "wr.member-role", "member role")
      != WYRELOG_E_OK)
    return 70;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "wr.member-role", "member-scope") != WYRELOG_E_OK)
    return 71;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "wr.member-role", "member-scope", "grant") != WYRELOG_E_OK)
    return 100;
  if (wyl_policy_store_grant_role_membership (store, "member-user",
          "wr.member-role", "member-scope") != WYRELOG_E_OK)
    return 72;

  RoleMembershipExpect expect = {
    .subject_id = "member-user",
    .role_id = "wr.member-role",
    .scope = "member-scope",
  };
  if (wyl_policy_store_foreach_role_membership (store,
          role_membership_expect_cb, &expect) != WYRELOG_E_OK)
    return 73;
  if (expect.matches != 1)
    return 74;
  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "wr.member-role", "member-scope", &exists) != WYRELOG_E_OK)
    return 101;
  if (!exists)
    return 102;

  RoleMembershipEventExpect event_expect = {
    .subject_id = "member-user",
    .role_id = "wr.member-role",
    .scope = "member-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event (store,
          role_membership_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 103;
  if (event_expect.matches != 1)
    return 104;
  if (wyl_policy_store_revoke_role_membership (store, "member-user",
          "wr.member-role", "member-scope") != WYRELOG_E_OK)
    return 105;
  if (wyl_policy_store_append_role_membership_event (store, "member-user",
          "wr.member-role", "member-scope", "revoke") != WYRELOG_E_OK)
    return 106;
  exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "member-user",
          "wr.member-role", "member-scope", &exists) != WYRELOG_E_OK)
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
check_store_appends_direct_permission_event (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;

  if (wyl_policy_store_open (NULL, &store) != WYRELOG_E_OK)
    return 92;
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 93;
  if (wyl_policy_store_append_direct_permission_event (store, "direct-user",
          "wr.direct.read", "direct-scope", "grant") != WYRELOG_E_OK)
    return 94;

  DirectPermissionExpect expect = {
    .subject_id = "direct-user",
    .perm_id = "wr.direct.read",
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
  if ((rc = check_handle_owns_policy_store ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_permission ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_inheritance ()) != 0)
    return rc;
  if ((rc = check_store_grants_role_membership ()) != 0)
    return rc;
  if ((rc = check_store_grants_direct_permission ()) != 0)
    return rc;
  if ((rc = check_store_appends_direct_permission_event ()) != 0)
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
