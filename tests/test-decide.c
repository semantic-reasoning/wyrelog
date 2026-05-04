/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

/*
 * wyl_decide returns a fail-closed DENY when no policy engine pair is wired.
 * When a handle-owned engine pair is present, it queries allow_bool/3.
 */

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
insert_allow_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.decide-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.decide-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static gint
check_decide_returns_ok_and_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_action (req, "read");
  wyl_decide_req_set_resource_id (req, "doc/42");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 11;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 12;
  return 0;
}

static gint
check_decide_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  if (wyl_decide (NULL, req, resp) != WYRELOG_E_INVALID)
    return 21;
  if (wyl_decide (handle, NULL, resp) != WYRELOG_E_INVALID)
    return 22;
  if (wyl_decide (handle, req, NULL) != WYRELOG_E_INVALID)
    return 23;
  return 0;
}

static gint
check_decide_rejects_incomplete_req_as_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  /* Pre-set ALLOW; invalid decide must overwrite back to DENY. */
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 31;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 32;
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_action (req, "read");
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 33;
  return 0;
}

static gint
check_decide_allows_engine_tuple (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 41;
  if (insert_allow_fixture (handle, "decide-user-a",
          "wr.decide-permission-a", "decide-resource-a") != WYRELOG_E_OK)
    return 42;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-a");
  wyl_decide_req_set_action (req, "wr.decide-permission-a");
  wyl_decide_req_set_resource_id (req, "decide-resource-a");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 43;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 44;
  return 0;
}

static gint
check_decide_denies_engine_miss (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 50;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 51;
  if (insert_allow_fixture (handle, "decide-user-b",
          "wr.decide-permission-b", "decide-resource-b") != WYRELOG_E_OK)
    return 52;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-b");
  wyl_decide_req_set_action (req, "wr.decide-permission-b");
  wyl_decide_req_set_resource_id (req, "other-resource-b");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 53;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 54;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_decide_returns_ok_and_deny ()) != 0)
    return rc;
  if ((rc = check_decide_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_decide_rejects_incomplete_req_as_deny ()) != 0)
    return rc;
  if ((rc = check_decide_allows_engine_tuple ()) != 0)
    return rc;
  if ((rc = check_decide_denies_engine_miss ()) != 0)
    return rc;
  return 0;
}
