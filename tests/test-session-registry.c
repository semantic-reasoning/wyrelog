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

static gint
check_handle_finalize_releases_registered_sessions (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;

  WylSession *session = login_one (handle, "alice");
  if (session == NULL) {
    g_object_unref (handle);
    return 71;
  }

  /* Track the session through a weak pointer so we can observe
   * finalize without holding a strong reference of our own. The
   * registry inside |handle| holds the only remaining strong
   * reference once we drop the caller's ref below. */
  gpointer weak_session = session;
  g_object_add_weak_pointer (G_OBJECT (session), &weak_session);
  g_object_unref (session);

  if (weak_session == NULL) {
    /* The registry's strong reference should still keep the session
     * alive, so the weak pointer must not have been cleared yet. */
    g_object_unref (handle);
    return 72;
  }

  g_object_unref (handle);

  /* After the handle is finalized the registry is unrefed, dropping
   * its strong reference; the session must finalize and the weak
   * pointer must be cleared. */
  if (weak_session != NULL)
    return 73;
  return 0;
}

static gint
check_logout_tombstones_registry_entry (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 80;

  WylSession *session = login_one (handle, "alice");
  if (session == NULL)
    return 81;
  wyl_session_id_t sid = wyl_session_get_id (session);

  /* Track the session via a weak pointer; the registry holds the
   * only strong reference after we drop the caller's. */
  gpointer weak_session = session;
  g_object_add_weak_pointer (G_OBJECT (session), &weak_session);
  g_object_unref (session);
  if (weak_session == NULL)
    return 82;

  /* Logout must drop the registry's strong reference so the session
   * is finalized synchronously (no other refs are held by the test). */
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 83;
  if (weak_session != NULL)
    return 84;

  /* The borrowed-pointer lookup must now report a tombstone (entry
   * present, session NULL) rather than returning a freed pointer. */
  if (wyl_handle_lookup_session_by_id (handle, sid) != NULL)
    return 85;
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
  if ((rc = check_handle_finalize_releases_registered_sessions ()) != 0)
    return rc;
  if ((rc = check_logout_tombstones_registry_entry ()) != 0)
    return rc;

  return 0;
}
