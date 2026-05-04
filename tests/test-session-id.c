/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static WylSession *
login_one (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return NULL;
  WylSession *session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_OK)
    return NULL;
  return session;
}

static gint
check_login_yields_id (void)
{
  g_autoptr (WylSession) session = login_one ();
  if (session == NULL)
    return 10;
  g_autofree gchar *id = wyl_session_dup_id_string (session);
  if (id == NULL)
    return 11;
  if (strlen (id) != 36)
    return 12;
  if (id[14] != '7')
    return 13;
  return 0;
}

static gint
check_id_is_stable (void)
{
  g_autoptr (WylSession) session = login_one ();
  if (session == NULL)
    return 20;
  g_autofree gchar *first = wyl_session_dup_id_string (session);
  g_autofree gchar *second = wyl_session_dup_id_string (session);
  if (first == NULL || second == NULL)
    return 21;
  if (strcmp (first, second) != 0)
    return 22;
  return 0;
}

static gint
check_distinct_sessions_have_distinct_ids (void)
{
  g_autoptr (WylSession) a = login_one ();
  g_autoptr (WylSession) b = login_one ();
  if (a == NULL || b == NULL)
    return 30;
  g_autofree gchar *ida = wyl_session_dup_id_string (a);
  g_autofree gchar *idb = wyl_session_dup_id_string (b);
  if (ida == NULL || idb == NULL)
    return 31;
  if (strcmp (ida, idb) == 0)
    return 32;
  return 0;
}

static gint
check_created_at_is_recent (void)
{
  gint64 before = g_get_real_time ();
  g_autoptr (WylSession) session = login_one ();
  gint64 after = g_get_real_time ();
  if (session == NULL)
    return 40;
  gint64 created = wyl_session_get_created_at_us (session);
  if (created < before || created > after)
    return 41;
  return 0;
}

static gint
check_accessor_null_safety (void)
{
  if (wyl_session_get_created_at_us (NULL) != -1)
    return 50;
  if (wyl_session_dup_id_string (NULL) != NULL)
    return 51;
  return 0;
}

static gint
check_login_rejects_null_handle (void)
{
  WylSession *session = (WylSession *) 0x1;

  if (wyl_session_login (NULL, NULL, &session) != WYRELOG_E_INVALID)
    return 60;
  if (session != NULL)
    return 61;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_yields_id ()) != 0)
    return rc;
  if ((rc = check_id_is_stable ()) != 0)
    return rc;
  if ((rc = check_distinct_sessions_have_distinct_ids ()) != 0)
    return rc;
  if ((rc = check_created_at_is_recent ()) != 0)
    return rc;
  if ((rc = check_accessor_null_safety ()) != 0)
    return rc;
  if ((rc = check_login_rejects_null_handle ()) != 0)
    return rc;

  return 0;
}
