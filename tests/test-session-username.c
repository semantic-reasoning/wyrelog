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
check_login_authenticates_engine_principal (void)
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

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 75;
  if (session == NULL)
    return 76;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "login-user");
  wyl_decide_req_set_action (decide, "wr.login-permission");
  wyl_decide_req_set_resource_id (decide, "login-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 77;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 78;
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
  if ((rc = check_login_authenticates_engine_principal ()) != 0)
    return rc;

  return 0;
}
