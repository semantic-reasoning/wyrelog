/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

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

  return 0;
}
