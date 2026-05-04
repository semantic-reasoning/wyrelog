/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/*
 * v0 contract for wyl_perm_grant / wyl_perm_revoke: validate
 * arguments, mirror direct permission plus armed-state facts into
 * any attached policy engine pair, record the admin operation in
 * the audit log when audit is enabled, and return WYRELOG_E_OK
 * without touching a durable permission store. The store wiring is
 * a follow-up.
 */

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
check_grant_allows_engine_decide (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "grant-user");
  wyl_grant_req_set_action (grant, "wr.grant-permission");
  wyl_grant_req_set_resource_id (grant, "grant-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK)
    return 51;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "grant-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 52;

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
  wyl_decide_req_set_action (decide, "wr.grant-permission");
  wyl_decide_req_set_resource_id (decide, "grant-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 57;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 58;
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
check_revoke_removes_engine_grant (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 60;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "revoke-user");
  wyl_grant_req_set_action (grant, "wr.revoke-permission");
  wyl_grant_req_set_resource_id (grant, "revoke-scope");
  if (wyl_perm_grant (handle, grant) != WYRELOG_E_OK)
    return 61;

  g_autoptr (wyl_revoke_req_t) revoke = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (revoke, "revoke-user");
  wyl_revoke_req_set_action (revoke, "wr.revoke-permission");
  wyl_revoke_req_set_resource_id (revoke, "revoke-scope");
  if (wyl_perm_revoke (handle, revoke) != WYRELOG_E_OK)
    return 62;

  gint64 row[3];
  if (wyl_handle_intern_engine_symbol (handle, "revoke-user", &row[0])
      != WYRELOG_E_OK)
    return 63;
  if (wyl_handle_intern_engine_symbol (handle, "wr.revoke-permission",
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
  if ((rc = check_grant_allows_engine_decide ()) != 0)
    return rc;
  if ((rc = check_gated_grant_is_rejected_by_engine_path ()) != 0)
    return rc;
  if ((rc = check_revoke_removes_engine_grant ()) != 0)
    return rc;
  return 0;
}
