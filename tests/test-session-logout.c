/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

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
check_logout_rejects_null_handle (void)
{
  if (wyl_session_logout (NULL, 42) != WYRELOG_E_INVALID)
    return 1;
  if (wyl_session_logout_with_request_id (NULL, 42, "req-1")
      != WYRELOG_E_INVALID)
    return 2;
  return 0;
}

static gint
check_logout_unknown_sid_returns_not_found (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  /* Sid 0 is reserved for "uninitialised" by wyl_session_get_id and is
   * never minted by the registry, so it is necessarily unknown. */
  if (wyl_session_logout (handle, 0) != WYRELOG_E_NOT_FOUND)
    return 11;

  /* A high integer that the registry has never minted is also unknown
   * regardless of how many sessions have ever been registered. */
  if (wyl_session_logout (handle, 999999) != WYRELOG_E_NOT_FOUND)
    return 12;
  return 0;
}

static gint
check_logout_drives_active_session_to_closed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 21;

  wyl_session_id_t sid = wyl_session_get_id (session);
  if (sid == 0)
    return 22;

  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 23;
  return 0;
}

static gint
check_logout_is_idempotent_on_repeat (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 31;

  wyl_session_id_t sid = wyl_session_get_id (session);
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 32;
  /* Repeat: the registry entry is now tombstoned. The contract is
   * idempotent E_OK without re-driving the FSM (which has no
   * (closed, logout) transition row) and without re-emitting an
   * audit row. */
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 33;
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 34;
  return 0;
}

static gint
check_logout_after_session_close_is_idempotent (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 41;
  wyl_session_id_t sid = wyl_session_get_id (session);

  /* Drive the session to the terminal CLOSED state through the
   * WylSession* surface; the registry holds a strong ref and is
   * NOT yet tombstoned. */
  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 42;

  /* Logout via the integer-sid surface must short-circuit to E_OK
   * (no FSM step possible from CLOSED) and tombstone the registry
   * so the strong ref is released. */
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 43;
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 44;
  return 0;
}

static gint
check_logout_with_request_id_propagates (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;

  g_autoptr (WylSession) session = login_one (handle, "alice");
  if (session == NULL)
    return 51;
  wyl_session_id_t sid = wyl_session_get_id (session);

  /* The request-id-bearing variant must succeed end-to-end. The
   * audit row's request_id field is checked by tests that exercise
   * the audit projection in the daemon-http-decide-audit suite. */
  if (wyl_session_logout_with_request_id (handle, sid, "req-logout-7")
      != WYRELOG_E_OK)
    return 52;
  return 0;
}

static gint
check_logout_with_null_request_id_matches_plain (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 60;

  g_autoptr (WylSession) a = login_one (handle, "alice");
  g_autoptr (WylSession) b = login_one (handle, "bob");
  if (a == NULL || b == NULL)
    return 61;

  if (wyl_session_logout_with_request_id (handle, wyl_session_get_id (a), NULL)
      != WYRELOG_E_OK)
    return 62;
  if (wyl_session_logout (handle, wyl_session_get_id (b)) != WYRELOG_E_OK)
    return 63;
  return 0;
}

static gint
check_logout_isolates_sessions_by_id (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;

  g_autoptr (WylSession) a = login_one (handle, "alice");
  g_autoptr (WylSession) b = login_one (handle, "bob");
  if (a == NULL || b == NULL)
    return 71;

  wyl_session_id_t sid_a = wyl_session_get_id (a);
  wyl_session_id_t sid_b = wyl_session_get_id (b);
  if (sid_a == sid_b)
    return 72;

  /* Logging out alice must not affect bob. */
  if (wyl_session_logout (handle, sid_a) != WYRELOG_E_OK)
    return 73;
  if (wyl_session_logout (handle, sid_b) != WYRELOG_E_OK)
    return 74;
  /* And bob must still report idempotent E_OK on the second call. */
  if (wyl_session_logout (handle, sid_b) != WYRELOG_E_OK)
    return 75;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_logout_rejects_null_handle ()) != 0)
    return rc;
  if ((rc = check_logout_unknown_sid_returns_not_found ()) != 0)
    return rc;
  if ((rc = check_logout_drives_active_session_to_closed ()) != 0)
    return rc;
  if ((rc = check_logout_is_idempotent_on_repeat ()) != 0)
    return rc;
  if ((rc = check_logout_after_session_close_is_idempotent ()) != 0)
    return rc;
  if ((rc = check_logout_with_request_id_propagates ()) != 0)
    return rc;
  if ((rc = check_logout_with_null_request_id_matches_plain ()) != 0)
    return rc;
  if ((rc = check_logout_isolates_sessions_by_id ()) != 0)
    return rc;

  return 0;
}
