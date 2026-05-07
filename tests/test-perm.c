/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/*
 * v0 contract for wyl_perm_grant / wyl_perm_revoke: validate
 * arguments, persist direct permission authority rows, project those
 * rows into any attached policy engine pair, record the admin
 * operation in the audit log when audit is enabled, and return
 * WYRELOG_E_OK. The permission-state lifecycle remains a separate
 * contract; unguarded direct permissions keep a compatibility
 * projection path until callers migrate to explicit transitions.
 */

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} DirectPermissionEventExpect;

typedef struct
{
  const gchar *subject_id;
  const gchar *role_id;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} RoleMembershipEventExpect;

static wyrelog_error_t
direct_permission_event_expect_cb (const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  DirectPermissionEventExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (perm_id, expect->perm_id) == 0
      && g_strcmp0 (scope, expect->scope) == 0
      && g_strcmp0 (operation, expect->operation) == 0)
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

static gint
seed_role_permission (WylHandle *handle, const gchar *role_id,
    const gchar *perm_id)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (wyl_policy_store_upsert_role (store, role_id, role_id) != WYRELOG_E_OK)
    return 1;
  if (wyl_policy_store_upsert_permission (store, perm_id, perm_id, "basic")
      != WYRELOG_E_OK)
    return 2;
  if (wyl_policy_store_grant_role_permission (store, role_id, perm_id)
      != WYRELOG_E_OK)
    return 3;
  if (wyl_handle_get_read_engine (handle) != NULL
      && wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 4;
  return 0;
}

static gint
insert_perm_state (WylHandle *handle, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *state)
{
  gint64 row[4];

  if (wyl_handle_intern_engine_symbol (handle, subject_id, &row[0])
      != WYRELOG_E_OK)
    return 1;
  if (wyl_handle_intern_engine_symbol (handle, perm_id, &row[1])
      != WYRELOG_E_OK)
    return 2;
  if (wyl_handle_intern_engine_symbol (handle, scope, &row[2])
      != WYRELOG_E_OK)
    return 3;
  if (wyl_handle_intern_engine_symbol (handle, state, &row[3])
      != WYRELOG_E_OK)
    return 4;
  if (wyl_handle_engine_insert (handle, "perm_state", row, 4)
      != WYRELOG_E_OK)
    return 5;
  return 0;
}

static gint
check_grant_returns_ok (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (req, "alice");
  wyl_grant_req_set_action (req, "read");
  wyl_grant_req_set_resource_id (req, "doc/42");

  if (wyl_perm_grant (handle, req) != WYRELOG_E_OK)
    return 11;
  return 0;
}

static gint
check_revoke_returns_ok (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (req, "alice");
  wyl_revoke_req_set_action (req, "read");
  wyl_revoke_req_set_resource_id (req, "doc/42");

  if (wyl_perm_revoke (handle, req) != WYRELOG_E_OK)
    return 21;
  return 0;
}

static gint
check_grant_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();

  if (wyl_perm_grant (NULL, req) != WYRELOG_E_INVALID)
    return 31;
  if (wyl_perm_grant (handle, NULL) != WYRELOG_E_INVALID)
    return 32;
  return 0;
}

static gint
check_grant_rejects_incomplete_req (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 35;

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
  if (wyl_perm_grant (handle, req) != WYRELOG_E_INVALID)
    return 36;
  wyl_grant_req_set_subject_id (req, "alice");
  wyl_grant_req_set_action (req, "read");
  if (wyl_perm_grant (handle, req) != WYRELOG_E_INVALID)
    return 37;
  return 0;
}

static gint
check_revoke_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;

  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();

  if (wyl_perm_revoke (NULL, req) != WYRELOG_E_INVALID)
    return 41;
  if (wyl_perm_revoke (handle, NULL) != WYRELOG_E_INVALID)
    return 42;
  return 0;
}

static gint
check_revoke_rejects_incomplete_req (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 45;

  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  if (wyl_perm_revoke (handle, req) != WYRELOG_E_INVALID)
    return 46;
  wyl_revoke_req_set_subject_id (req, "alice");
  wyl_revoke_req_set_action (req, "read");
  if (wyl_perm_revoke (handle, req) != WYRELOG_E_INVALID)
    return 47;
  return 0;
}

static gint
check_role_grant_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 90;

  g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();

  if (wyl_role_grant (NULL, req) != WYRELOG_E_INVALID)
    return 91;
  if (wyl_role_grant (handle, NULL) != WYRELOG_E_INVALID)
    return 92;
  return 0;
}

static gint
check_role_grant_rejects_incomplete_req (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 95;

  g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();
  if (wyl_role_grant (handle, req) != WYRELOG_E_INVALID)
    return 96;
  wyl_role_grant_req_set_subject_id (req, "alice");
  wyl_role_grant_req_set_role_id (req, "wr.role");
  if (wyl_role_grant (handle, req) != WYRELOG_E_INVALID)
    return 97;
  return 0;
}

static gint
check_role_revoke_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 98;

  g_autoptr (wyl_role_revoke_req_t) req = wyl_role_revoke_req_new ();

  if (wyl_role_revoke (NULL, req) != WYRELOG_E_INVALID)
    return 99;
  if (wyl_role_revoke (handle, NULL) != WYRELOG_E_INVALID)
    return 100;
  return 0;
}

static gint
check_role_revoke_rejects_incomplete_req (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 101;

  g_autoptr (wyl_role_revoke_req_t) req = wyl_role_revoke_req_new ();
  if (wyl_role_revoke (handle, req) != WYRELOG_E_INVALID)
    return 102;
  wyl_role_revoke_req_set_subject_id (req, "alice");
  wyl_role_revoke_req_set_role_id (req, "wr.role");
  if (wyl_role_revoke (handle, req) != WYRELOG_E_INVALID)
    return 103;
  return 0;
}

static gint
check_role_grant_requires_existing_role (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 104;

  g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (req, "missing-role-user");
  wyl_role_grant_req_set_role_id (req, "wr.missing-role");
  wyl_role_grant_req_set_scope (req, "missing-role-scope");
  if (wyl_role_grant (handle, req) != WYRELOG_E_IO)
    return 105;
  return 0;
}

static gint
check_direct_grant_compat_allows_engine_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "grant-user");
  wyl_grant_req_set_action (grant, "site.grant-permission");
  wyl_grant_req_set_resource_id (grant, "grant-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK)
    return 51;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "grant-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 52;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 59;

  gint64 active_row[1];
  if (wyl_handle_intern_engine_symbol (handle, "active", &active_row[0])
      != WYRELOG_E_OK)
    return 53;
  if (wyl_handle_engine_insert (handle, "session_active", active_row, 1)
      != WYRELOG_E_OK)
    return 54;
  gint64 session_row[2];
  if (wyl_handle_intern_engine_symbol (handle, "grant-scope",
          &session_row[0]) != WYRELOG_E_OK)
    return 55;
  session_row[1] = active_row[0];
  if (wyl_handle_engine_insert (handle, "session_state", session_row, 2)
      != WYRELOG_E_OK)
    return 56;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "grant-user");
  wyl_decide_req_set_action (decide, "site.grant-permission");
  wyl_decide_req_set_resource_id (decide, "grant-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 57;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 58;
  return 0;
}

static gint
check_role_grant_with_armed_state_allows_engine_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;
  if (seed_role_permission (handle, "site.role-grant-role",
          "site.role-grant-permission") != 0)
    return 111;

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "role-grant-user");
  wyl_role_grant_req_set_role_id (grant, "site.role-grant-role");
  wyl_role_grant_req_set_scope (grant, "role-grant-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_OK)
    return 112;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "role-grant-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 113;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 114;

  gint64 active_row[1];
  if (wyl_handle_intern_engine_symbol (handle, "active", &active_row[0])
      != WYRELOG_E_OK)
    return 115;
  if (wyl_handle_engine_insert (handle, "session_active", active_row, 1)
      != WYRELOG_E_OK)
    return 116;
  gint64 session_row[2];
  if (wyl_handle_intern_engine_symbol (handle, "role-grant-scope",
          &session_row[0]) != WYRELOG_E_OK)
    return 117;
  session_row[1] = active_row[0];
  if (wyl_handle_engine_insert (handle, "session_state", session_row, 2)
      != WYRELOG_E_OK)
    return 118;
  if (insert_perm_state (handle, "role-grant-user",
          "site.role-grant-permission", "role-grant-scope", "armed") != 0)
    return 119;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "role-grant-user");
  wyl_decide_req_set_action (decide, "site.role-grant-permission");
  wyl_decide_req_set_resource_id (decide, "role-grant-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 120;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 121;
  return 0;
}

static gint
check_gated_grant_is_rejected_by_engine_path (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 59;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "gated-grant-user");
  wyl_grant_req_set_action (grant, "wr.audit.read");
  wyl_grant_req_set_resource_id (grant, "gated-grant-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_POLICY)
    return 68;
  return 0;
}

static gint
check_grant_persists_direct_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 70;

  g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (req, "store-user");
  wyl_grant_req_set_action (req, "site.store-direct");
  wyl_grant_req_set_resource_id (req, "store-scope");
  if (wyl_perm_grant (handle, req) != WYRELOG_E_OK)
    return 71;

  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (wyl_handle_get_policy_store
          (handle), "store-user", "site.store-direct", "store-scope",
          &exists) != WYRELOG_E_OK)
    return 72;
  if (!exists)
    return 73;

  DirectPermissionEventExpect expect = {
    .subject_id = "store-user",
    .perm_id = "site.store-direct",
    .scope = "store-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event
      (wyl_handle_get_policy_store (handle), direct_permission_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 74;
  if (expect.matches != 1)
    return 75;
  return 0;
}

static gint
check_revoke_removes_store_grant (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 80;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "store-revoke-user");
  wyl_grant_req_set_action (grant, "site.store-revoke");
  wyl_grant_req_set_resource_id (grant, "store-revoke-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK)
    return 81;

  g_autoptr (wyl_revoke_req_t) revoke = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (revoke, "store-revoke-user");
  wyl_revoke_req_set_action (revoke, "site.store-revoke");
  wyl_revoke_req_set_resource_id (revoke, "store-revoke-scope");
  if (wyl_perm_revoke (handle, revoke) != WYRELOG_E_OK)
    return 82;

  gboolean exists = TRUE;
  if (wyl_policy_store_direct_permission_exists (wyl_handle_get_policy_store
          (handle), "store-revoke-user", "site.store-revoke",
          "store-revoke-scope", &exists)
      != WYRELOG_E_OK)
    return 83;
  if (exists)
    return 84;
  DirectPermissionEventExpect grant_expect = {
    .subject_id = "store-revoke-user",
    .perm_id = "site.store-revoke",
    .scope = "store-revoke-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_direct_permission_event
      (wyl_handle_get_policy_store (handle), direct_permission_event_expect_cb,
          &grant_expect) != WYRELOG_E_OK)
    return 85;
  if (grant_expect.matches != 1)
    return 86;
  DirectPermissionEventExpect revoke_expect = {
    .subject_id = "store-revoke-user",
    .perm_id = "site.store-revoke",
    .scope = "store-revoke-scope",
    .operation = "revoke",
  };
  if (wyl_policy_store_foreach_direct_permission_event
      (wyl_handle_get_policy_store (handle), direct_permission_event_expect_cb,
          &revoke_expect) != WYRELOG_E_OK)
    return 87;
  if (revoke_expect.matches != 1)
    return 88;
  return 0;
}

static gint
check_role_grant_persists_membership (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 121;
  if (seed_role_permission (handle, "site.store-role", "site.store-role.read")
      != 0)
    return 122;

  g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (req, "store-role-user");
  wyl_role_grant_req_set_role_id (req, "site.store-role");
  wyl_role_grant_req_set_scope (req, "store-role-scope");
  if (wyl_role_grant (handle, req) != WYRELOG_E_OK)
    return 123;

  gboolean exists = FALSE;
  if (wyl_policy_store_role_membership_exists (wyl_handle_get_policy_store
          (handle), "store-role-user", "site.store-role", "store-role-scope",
          &exists) != WYRELOG_E_OK)
    return 124;
  if (!exists)
    return 125;

  RoleMembershipEventExpect expect = {
    .subject_id = "store-role-user",
    .role_id = "site.store-role",
    .scope = "store-role-scope",
    .operation = "grant",
  };
  if (wyl_policy_store_foreach_role_membership_event
      (wyl_handle_get_policy_store (handle), role_membership_event_expect_cb,
          &expect) != WYRELOG_E_OK)
    return 126;
  if (expect.matches != 1)
    return 127;
  return 0;
}

static gint
check_role_revoke_removes_store_membership (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 128;
  if (seed_role_permission (handle, "site.store-revoke-role",
          "site.store-revoke-role.read") != 0)
    return 129;

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "store-role-revoke-user");
  wyl_role_grant_req_set_role_id (grant, "site.store-revoke-role");
  wyl_role_grant_req_set_scope (grant, "store-role-revoke-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_OK)
    return 130;

  g_autoptr (wyl_role_revoke_req_t) revoke = wyl_role_revoke_req_new ();
  wyl_role_revoke_req_set_subject_id (revoke, "store-role-revoke-user");
  wyl_role_revoke_req_set_role_id (revoke, "site.store-revoke-role");
  wyl_role_revoke_req_set_scope (revoke, "store-role-revoke-scope");
  if (wyl_role_revoke (handle, revoke) != WYRELOG_E_OK)
    return 131;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (wyl_handle_get_policy_store
          (handle), "store-role-revoke-user", "site.store-revoke-role",
          "store-role-revoke-scope", &exists) != WYRELOG_E_OK)
    return 132;
  if (exists)
    return 133;
  RoleMembershipEventExpect revoke_expect = {
    .subject_id = "store-role-revoke-user",
    .role_id = "site.store-revoke-role",
    .scope = "store-role-revoke-scope",
    .operation = "revoke",
  };
  if (wyl_policy_store_foreach_role_membership_event
      (wyl_handle_get_policy_store (handle), role_membership_event_expect_cb,
          &revoke_expect) != WYRELOG_E_OK)
    return 134;
  if (revoke_expect.matches != 1)
    return 135;
  return 0;
}

static gint
check_revoke_removes_engine_grant (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 60;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "revoke-user");
  wyl_grant_req_set_action (grant, "site.revoke-permission");
  wyl_grant_req_set_resource_id (grant, "revoke-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK)
    return 61;

  g_autoptr (wyl_revoke_req_t) revoke = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (revoke, "revoke-user");
  wyl_revoke_req_set_action (revoke, "site.revoke-permission");
  wyl_revoke_req_set_resource_id (revoke, "revoke-scope");
  if (wyl_perm_revoke (handle, revoke) != WYRELOG_E_OK)
    return 62;

  gint64 row[3];
  if (wyl_handle_intern_engine_symbol (handle, "revoke-user", &row[0])
      != WYRELOG_E_OK)
    return 63;
  if (wyl_handle_intern_engine_symbol (handle, "site.revoke-permission",
          &row[1]) != WYRELOG_E_OK)
    return 64;
  if (wyl_handle_intern_engine_symbol (handle, "revoke-scope", &row[2])
      != WYRELOG_E_OK)
    return 65;
  gboolean allowed = TRUE;
  if (wyl_handle_engine_decide (handle, row, &allowed) != WYRELOG_E_OK)
    return 66;
  if (allowed)
    return 67;
  return 0;
}

static gint
check_role_revoke_removes_engine_membership (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 140;
  if (seed_role_permission (handle, "site.role-revoke-role",
          "site.role-revoke-permission") != 0)
    return 141;

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "role-revoke-user");
  wyl_role_grant_req_set_role_id (grant, "site.role-revoke-role");
  wyl_role_grant_req_set_scope (grant, "role-revoke-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_OK)
    return 142;

  g_autoptr (wyl_role_revoke_req_t) revoke = wyl_role_revoke_req_new ();
  wyl_role_revoke_req_set_subject_id (revoke, "role-revoke-user");
  wyl_role_revoke_req_set_role_id (revoke, "site.role-revoke-role");
  wyl_role_revoke_req_set_scope (revoke, "role-revoke-scope");
  if (wyl_role_revoke (handle, revoke) != WYRELOG_E_OK)
    return 143;
  if (insert_perm_state (handle, "role-revoke-user",
          "site.role-revoke-permission", "role-revoke-scope", "armed") != 0)
    return 149;

  gint64 row[3];
  if (wyl_handle_intern_engine_symbol (handle, "role-revoke-user", &row[0])
      != WYRELOG_E_OK)
    return 144;
  if (wyl_handle_intern_engine_symbol (handle, "site.role-revoke-permission",
          &row[1]) != WYRELOG_E_OK)
    return 145;
  if (wyl_handle_intern_engine_symbol (handle, "role-revoke-scope", &row[2])
      != WYRELOG_E_OK)
    return 146;
  gboolean allowed = TRUE;
  if (wyl_handle_engine_decide (handle, row, &allowed) != WYRELOG_E_OK)
    return 147;
  if (allowed)
    return 148;
  return 0;
}

static gint
check_role_grant_rolls_back_invalid_snapshot (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_role (store, "site.audit-role",
          "site audit role") != WYRELOG_E_OK)
    return 151;
  if (wyl_policy_store_upsert_role (store, "site.grant-role",
          "site grant role") != WYRELOG_E_OK)
    return 152;
  if (wyl_policy_store_upsert_permission (store, "wr.audit.read",
          "audit read", "sensitive") != WYRELOG_E_OK)
    return 153;
  if (wyl_policy_store_upsert_permission (store, "wr.policy.grant_role",
          "policy role grant", "critical") != WYRELOG_E_OK)
    return 154;
  if (wyl_policy_store_grant_role_permission (store, "site.audit-role",
          "wr.audit.read") != WYRELOG_E_OK)
    return 155;
  if (wyl_policy_store_grant_role_permission (store, "site.grant-role",
          "wr.policy.grant_role") != WYRELOG_E_OK)
    return 156;
  if (wyl_policy_store_grant_role_membership (store, "rollback-sod-user",
          "site.audit-role", "rollback-sod-scope") != WYRELOG_E_OK)
    return 157;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 158;

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, "rollback-sod-user");
  wyl_role_grant_req_set_role_id (grant, "site.grant-role");
  wyl_role_grant_req_set_scope (grant, "rollback-sod-scope");
  if (wyl_role_grant (handle, grant) != WYRELOG_E_POLICY)
    return 159;

  gboolean exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "rollback-sod-user",
          "site.grant-role", "rollback-sod-scope", &exists) != WYRELOG_E_OK)
    return 160;
  return exists ? 161 : 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_grant_returns_ok ()) != 0)
    return rc;
  if ((rc = check_revoke_returns_ok ()) != 0)
    return rc;
  if ((rc = check_grant_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_grant_rejects_incomplete_req ()) != 0)
    return rc;
  if ((rc = check_revoke_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_revoke_rejects_incomplete_req ()) != 0)
    return rc;
  if ((rc = check_role_grant_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_role_grant_rejects_incomplete_req ()) != 0)
    return rc;
  if ((rc = check_role_revoke_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_role_revoke_rejects_incomplete_req ()) != 0)
    return rc;
  if ((rc = check_role_grant_requires_existing_role ()) != 0)
    return rc;
  if ((rc = check_direct_grant_compat_allows_engine_decide ()) != 0)
    return rc;
  if ((rc = check_role_grant_with_armed_state_allows_engine_decide ()) != 0)
    return rc;
  if ((rc = check_gated_grant_is_rejected_by_engine_path ()) != 0)
    return rc;
  if ((rc = check_grant_persists_direct_permission ()) != 0)
    return rc;
  if ((rc = check_role_grant_persists_membership ()) != 0)
    return rc;
  if ((rc = check_revoke_removes_store_grant ()) != 0)
    return rc;
  if ((rc = check_role_revoke_removes_store_membership ()) != 0)
    return rc;
  if ((rc = check_revoke_removes_engine_grant ()) != 0)
    return rc;
  if ((rc = check_role_revoke_removes_engine_membership ()) != 0)
    return rc;
  if ((rc = check_role_grant_rolls_back_invalid_snapshot ()) != 0)
    return rc;
  return 0;
}
