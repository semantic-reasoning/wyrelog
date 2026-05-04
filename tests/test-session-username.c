/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
}

static wyrelog_error_t
insert_symbol_row1 (WylHandle *handle, const gchar *relation,
    const gchar *value)
{
  gint64 row[1];
  wyrelog_error_t rc = intern_symbol (handle, value, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 1);
}

static wyrelog_error_t
insert_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b)
{
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 2);
}

static wyrelog_error_t
insert_symbol_row3 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 3);
}

static wyrelog_error_t
insert_symbol_row4 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c, const gchar *d)
{
  gint64 row[4];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 4);
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
  const gchar *subject_id;
  const gchar *state;
  guint matches;
} PrincipalStateExpect;

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

static WylSession *
login_with_username (const gchar *username)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return NULL;

  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, username);

  WylSession *session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK)
    return NULL;
  return session;
}

static gint
check_login_propagates_username (void)
{
  g_autoptr (WylSession) session = login_with_username ("alice");
  if (session == NULL)
    return 10;
  g_autofree gchar *got = wyl_session_dup_username (session);
  if (got == NULL)
    return 11;
  if (strcmp (got, "alice") != 0)
    return 12;
  return 0;
}

static gint
check_login_with_null_request (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_OK)
    return 21;
  if (session == NULL)
    return 22;
  /* No request -> no username carried into the session. */
  if (wyl_session_dup_username (session) != NULL)
    return 23;
  return 0;
}

static gint
check_login_with_unset_username (void)
{
  g_autoptr (WylSession) session = login_with_username (NULL);
  if (session == NULL)
    return 30;
  if (wyl_session_dup_username (session) != NULL)
    return 31;
  return 0;
}

static gint
check_request_buffer_independent_of_session (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;

  wyl_login_req_t *req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "bob");

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK) {
    wyl_login_req_free (req);
    return 41;
  }

  /* Free the request before reading the session. The session's copy
   * of the username must survive. */
  wyl_login_req_free (req);

  g_autofree gchar *got = wyl_session_dup_username (session);
  if (got == NULL)
    return 42;
  if (strcmp (got, "bob") != 0)
    return 43;
  return 0;
}

static gint
check_dup_returns_distinct_buffers (void)
{
  g_autoptr (WylSession) session = login_with_username ("carol");
  if (session == NULL)
    return 50;
  g_autofree gchar *first = wyl_session_dup_username (session);
  g_autofree gchar *second = wyl_session_dup_username (session);
  if (first == NULL || second == NULL)
    return 51;
  if (first == second)
    return 52;
  if (strcmp (first, second) != 0)
    return 53;
  return 0;
}

static gint
check_dup_null_session (void)
{
  if (wyl_session_dup_username (NULL) != NULL)
    return 60;
  return 0;
}

static gint
check_login_requires_mfa_before_allow (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;

  if (insert_symbol_row2 (handle, "role_permission", "wr.login-role",
          "wr.login-permission") != WYRELOG_E_OK)
    return 71;
  if (insert_symbol_row3 (handle, "member_of", "login-user",
          "wr.login-role", "login-scope") != WYRELOG_E_OK)
    return 72;
  if (insert_symbol_row2 (handle, "session_state", "login-scope", "active")
      != WYRELOG_E_OK)
    return 73;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 74;
  if (insert_symbol_row4 (handle, "perm_state", "login-user",
          "wr.login-permission", "login-scope", "armed") != WYRELOG_E_OK)
    return 75;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 76;
  if (session == NULL)
    return 77;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "login-user");
  wyl_decide_req_set_action (decide, "wr.login-permission");
  wyl_decide_req_set_resource_id (decide, "login-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 78;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 79;
  return 0;
}

static gint
check_mfa_verify_authenticates_engine_principal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 80;

  if (insert_symbol_row2 (handle, "role_permission", "wr.login-role",
          "wr.login-permission") != WYRELOG_E_OK)
    return 81;
  if (insert_symbol_row3 (handle, "member_of", "login-user",
          "wr.login-role", "login-scope") != WYRELOG_E_OK)
    return 82;
  if (insert_symbol_row2 (handle, "session_state", "login-scope", "active")
      != WYRELOG_E_OK)
    return 83;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 84;
  if (insert_symbol_row4 (handle, "perm_state", "login-user",
          "wr.login-permission", "login-scope", "armed") != WYRELOG_E_OK)
    return 85;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 86;
  if (session == NULL)
    return 87;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 88;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "login-user");
  wyl_decide_req_set_action (decide, "wr.login-permission");
  wyl_decide_req_set_resource_id (decide, "login-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 89;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 90;
  return 0;
}

static gint
check_mfa_verify_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 100;

  if (wyl_session_mfa_verify (NULL, NULL) != WYRELOG_E_INVALID)
    return 101;
  if (wyl_session_mfa_verify (handle, NULL) != WYRELOG_E_INVALID)
    return 102;

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_OK)
    return 103;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_INVALID)
    return 104;
  return 0;
}

static gint
check_login_persists_mfa_required_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "persist-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 111;

  PrincipalStateExpect expect = {
    .subject_id = "persist-user",
    .state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
          (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 112;
  if (expect.matches != 1)
    return 113;
  return 0;
}

static gint
check_mfa_verify_persists_authenticated_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 120;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "persist-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 121;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 122;

  PrincipalStateExpect expect = {
    .subject_id = "persist-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
          (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 123;
  if (expect.matches != 1)
    return 124;
  return 0;
}

static gint
check_login_persists_active_session_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 130;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 131;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 132;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "active",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 133;
  if (expect.matches != 1)
    return 134;
  return 0;
}

static gint
check_login_session_id_is_active_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 140;

  if (insert_symbol_row2 (handle, "role_permission", "wr.session-id-role",
          "wr.session-id-permission") != WYRELOG_E_OK)
    return 141;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-id-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 142;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 143;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 144;
  if (insert_symbol_row3 (handle, "member_of", "session-id-user",
          "wr.session-id-role", session_id) != WYRELOG_E_OK)
    return 145;
  if (insert_symbol_row4 (handle, "perm_state", "session-id-user",
          "wr.session-id-permission", session_id, "armed") != WYRELOG_E_OK)
    return 146;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "session-id-user");
  wyl_decide_req_set_action (decide, "wr.session-id-permission");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 147;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 148;
  return 0;
}

static gint
check_login_skip_mfa_authenticates_principal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;

  if (insert_symbol_row2 (handle, "role_permission", "wr.skip-mfa-role",
          "wr.skip-mfa-permission") != WYRELOG_E_OK)
    return 151;
  if (insert_symbol_row3 (handle, "member_of", "skip-mfa-user",
          "wr.skip-mfa-role", "skip-mfa-scope") != WYRELOG_E_OK)
    return 152;
  if (insert_symbol_row2 (handle, "session_state", "skip-mfa-scope", "active")
      != WYRELOG_E_OK)
    return 153;
  if (insert_symbol_row4 (handle, "perm_state", "skip-mfa-user",
          "wr.skip-mfa-permission", "skip-mfa-scope", "armed") != WYRELOG_E_OK)
    return 154;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 155;

  PrincipalStateExpect expect = {
    .subject_id = "skip-mfa-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
          (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 156;
  if (expect.matches != 1)
    return 157;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "skip-mfa-user");
  wyl_decide_req_set_action (decide, "wr.skip-mfa-permission");
  wyl_decide_req_set_resource_id (decide, "skip-mfa-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 158;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 159;
  return 0;
}

static gint
check_session_close_persists_closed_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 160;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "close-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 161;
  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 162;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 163;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 164;
  if (expect.matches != 1)
    return 165;
  return 0;
}

static gint
check_session_close_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 170;

  if (insert_symbol_row2 (handle, "role_permission", "wr.close-role",
          "wr.close-permission") != WYRELOG_E_OK)
    return 171;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "close-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 172;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 173;
  if (insert_symbol_row3 (handle, "member_of", "close-user", "wr.close-role",
          session_id) != WYRELOG_E_OK)
    return 174;
  if (insert_symbol_row4 (handle, "perm_state", "close-user",
          "wr.close-permission", session_id, "armed") != WYRELOG_E_OK)
    return 175;

  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 176;

  g_autoptr (wyl_decide_req_t) after = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (after, "close-user");
  wyl_decide_req_set_action (after, "wr.close-permission");
  wyl_decide_req_set_resource_id (after, session_id);
  g_autoptr (wyl_decide_resp_t) after_resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, after, after_resp) != WYRELOG_E_OK)
    return 177;
  if (wyl_decide_resp_get_decision (after_resp) != WYL_DECISION_DENY)
    return 178;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (after_resp),
          "session_inactive") != 0)
    return 179;
  return 0;
}

static gint
check_session_close_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 190;

  if (wyl_session_close (NULL, NULL) != WYRELOG_E_INVALID)
    return 191;
  if (wyl_session_close (handle, NULL) != WYRELOG_E_INVALID)
    return 192;
  return 0;
}

static gint
check_session_elevate_persists_elevated_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 200;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevate-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 201;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 202;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 203;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "elevated",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 204;
  if (expect.matches != 1)
    return 205;
  return 0;
}

static gint
check_session_drop_elevation_persists_active_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 210;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "drop-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 211;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 212;
  if (wyl_session_drop_elevation (handle, session) != WYRELOG_E_OK)
    return 213;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 214;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "active",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 215;
  if (expect.matches != 1)
    return 216;
  return 0;
}

static gint
check_elevated_session_remains_active_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 220;

  if (insert_symbol_row2 (handle, "role_permission", "wr.elevate-role",
          "wr.elevate-permission") != WYRELOG_E_OK)
    return 221;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevate-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 222;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 223;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 224;
  if (insert_symbol_row3 (handle, "member_of", "elevate-user",
          "wr.elevate-role", session_id) != WYRELOG_E_OK)
    return 225;
  if (insert_symbol_row4 (handle, "perm_state", "elevate-user",
          "wr.elevate-permission", session_id, "armed") != WYRELOG_E_OK)
    return 226;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevate-user");
  wyl_decide_req_set_action (decide, "wr.elevate-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 227;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 228;
  return 0;
}

static gint
check_elevated_session_close_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 230;

  if (insert_symbol_row2 (handle, "role_permission", "wr.elevated-close-role",
          "wr.elevated-close-permission") != WYRELOG_E_OK)
    return 231;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevated-close-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 232;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 233;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 234;
  if (insert_symbol_row3 (handle, "member_of", "elevated-close-user",
          "wr.elevated-close-role", session_id) != WYRELOG_E_OK)
    return 235;
  if (insert_symbol_row4 (handle, "perm_state", "elevated-close-user",
          "wr.elevated-close-permission", session_id, "armed") != WYRELOG_E_OK)
    return 236;

  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 237;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevated-close-user");
  wyl_decide_req_set_action (decide, "wr.elevated-close-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 238;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 239;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "session_inactive") != 0)
    return 240;
  return 0;
}

static gint
check_session_idle_timeout_persists_idle_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 260;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "idle-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 261;
  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 262;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 263;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "idle",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 264;
  if (expect.matches != 1)
    return 265;
  return 0;
}

static gint
check_idle_session_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 270;

  if (insert_symbol_row2 (handle, "role_permission", "wr.idle-role",
          "wr.idle-permission") != WYRELOG_E_OK)
    return 271;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "idle-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 272;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 273;
  if (insert_symbol_row3 (handle, "member_of", "idle-user", "wr.idle-role",
          session_id) != WYRELOG_E_OK)
    return 274;
  if (insert_symbol_row4 (handle, "perm_state", "idle-user",
          "wr.idle-permission", session_id, "armed") != WYRELOG_E_OK)
    return 275;

  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 276;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "idle-user");
  wyl_decide_req_set_action (decide, "wr.idle-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 277;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 278;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "session_inactive") != 0)
    return 279;
  return 0;
}

static gint
check_elevated_session_idle_timeout_deactivates_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 280;

  if (insert_symbol_row2 (handle, "role_permission", "wr.elevated-idle-role",
          "wr.elevated-idle-permission") != WYRELOG_E_OK)
    return 281;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevated-idle-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 282;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 283;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 284;
  if (insert_symbol_row3 (handle, "member_of", "elevated-idle-user",
          "wr.elevated-idle-role", session_id) != WYRELOG_E_OK)
    return 285;
  if (insert_symbol_row4 (handle, "perm_state", "elevated-idle-user",
          "wr.elevated-idle-permission", session_id, "armed") != WYRELOG_E_OK)
    return 286;

  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 287;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevated-idle-user");
  wyl_decide_req_set_action (decide, "wr.elevated-idle-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 288;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 289;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "session_inactive") != 0)
    return 290;
  return 0;
}

static gint
check_session_elevation_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 250;

  if (wyl_session_elevate (NULL, NULL) != WYRELOG_E_INVALID)
    return 251;
  if (wyl_session_elevate (handle, NULL) != WYRELOG_E_INVALID)
    return 252;
  if (wyl_session_drop_elevation (NULL, NULL) != WYRELOG_E_INVALID)
    return 253;
  if (wyl_session_drop_elevation (handle, NULL) != WYRELOG_E_INVALID)
    return 254;
  if (wyl_session_idle_timeout (NULL, NULL) != WYRELOG_E_INVALID)
    return 255;
  if (wyl_session_idle_timeout (handle, NULL) != WYRELOG_E_INVALID)
    return 256;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_propagates_username ()) != 0)
    return rc;
  if ((rc = check_login_with_null_request ()) != 0)
    return rc;
  if ((rc = check_login_with_unset_username ()) != 0)
    return rc;
  if ((rc = check_request_buffer_independent_of_session ()) != 0)
    return rc;
  if ((rc = check_dup_returns_distinct_buffers ()) != 0)
    return rc;
  if ((rc = check_dup_null_session ()) != 0)
    return rc;
  if ((rc = check_login_requires_mfa_before_allow ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_authenticates_engine_principal ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_login_persists_mfa_required_state ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_persists_authenticated_state ()) != 0)
    return rc;
  if ((rc = check_login_persists_active_session_state ()) != 0)
    return rc;
  if ((rc = check_login_session_id_is_active_decision_scope ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_authenticates_principal ()) != 0)
    return rc;
  if ((rc = check_session_close_persists_closed_state ()) != 0)
    return rc;
  if ((rc = check_session_close_deactivates_decision_scope ()) != 0)
    return rc;
  if ((rc = check_session_close_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_session_elevate_persists_elevated_state ()) != 0)
    return rc;
  if ((rc = check_session_drop_elevation_persists_active_state ()) != 0)
    return rc;
  if ((rc = check_elevated_session_remains_active_decision_scope ()) != 0)
    return rc;
  if ((rc = check_elevated_session_close_deactivates_decision_scope ()) != 0)
    return rc;
  if ((rc = check_session_idle_timeout_persists_idle_state ()) != 0)
    return rc;
  if ((rc = check_idle_session_deactivates_decision_scope ()) != 0)
    return rc;
  if ((rc = check_elevated_session_idle_timeout_deactivates_scope ()) != 0)
    return rc;
  if ((rc = check_session_elevation_rejects_invalid_args ()) != 0)
    return rc;

  return 0;
}
