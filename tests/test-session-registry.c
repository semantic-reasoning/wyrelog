/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static WylSession *
login_one (WylHandle *handle, const gchar *username)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  if (username != NULL)
    wyl_login_req_set_username (req, username);

  WylSession *session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK)
    return NULL;
  return session;
}

static gint
check_login_assigns_nonzero_sid (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 2;

  if (wyl_session_get_id (session) == 0)
    return 3;
  return 0;
}

static gint
check_two_logins_distinct_sids (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (WylSession) a = login_one (handle, "alice");
  g_autoptr (WylSession) b = login_one (handle, "bob");
  if (a == NULL || b == NULL)
    return 11;

  if (wyl_session_get_id (a) == 0 || wyl_session_get_id (b) == 0)
    return 12;
  if (wyl_session_get_id (a) == wyl_session_get_id (b))
    return 13;
  return 0;
}

static gint
check_lookup_returns_registered_session (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 21;

  wyl_session_id_t sid = wyl_session_get_id (session);
  if (wyl_handle_lookup_session_by_id (handle, sid) != session)
    return 22;
  return 0;
}

static gint
check_lookup_unknown_returns_null (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;

  if (wyl_handle_lookup_session_by_id (handle, 999999) != NULL)
    return 31;
  return 0;
}

static gint
check_lookup_null_handle_returns_null (void)
{
  if (wyl_handle_lookup_session_by_id (NULL, 1) != NULL)
    return 40;
  return 0;
}

static gint
check_get_id_null_session_returns_zero (void)
{
  if (wyl_session_get_id (NULL) != 0)
    return 50;
  return 0;
}

static gint
check_lookups_isolated_per_handle (void)
{
  g_autoptr (WylHandle) ha = NULL;
  g_autoptr (WylHandle) hb = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &ha) != WYRELOG_E_OK)
    return 60;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &hb) != WYRELOG_E_OK)
    return 61;

  g_autoptr (WylSession) sa = login_one (ha, "alice");
  if (sa == NULL)
    return 62;

  /* Looking up A's sid on B must not return A's session. */
  if (wyl_handle_lookup_session_by_id (hb, wyl_session_get_id (sa)) != NULL)
    return 63;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_assigns_nonzero_sid ()) != 0)
    return rc;
  if ((rc = check_two_logins_distinct_sids ()) != 0)
    return rc;
  if ((rc = check_lookup_returns_registered_session ()) != 0)
    return rc;
  if ((rc = check_lookup_unknown_returns_null ()) != 0)
    return rc;
  if ((rc = check_lookup_null_handle_returns_null ()) != 0)
    return rc;
  if ((rc = check_get_id_null_session_returns_zero ()) != 0)
    return rc;
  if ((rc = check_lookups_isolated_per_handle ()) != 0)
    return rc;

  return 0;
}
