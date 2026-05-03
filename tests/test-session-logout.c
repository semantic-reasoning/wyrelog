/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

/*
 * v0 contract for wyl_session_logout: validate handle, record the
 * logout in the audit log when audit is enabled, and return
 * WYRELOG_E_OK without touching a durable session table. The
 * session-store teardown is a follow-up.
 */

static gint
check_logout_returns_ok (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;

  if (wyl_session_logout (handle, 42) != WYRELOG_E_OK)
    return 11;
  return 0;
}

static gint
check_logout_rejects_null_handle (void)
{
  if (wyl_session_logout (NULL, 42) != WYRELOG_E_INVALID)
    return 20;
  return 0;
}

static gint
check_logout_accepts_zero_sid (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  /* sid is an opaque integer at this layer; the session-table
   * implementation will reject unknown ids in a future commit, but
   * v0 has no table to consult so any well-formed integer is
   * accepted. */
  if (wyl_session_logout (handle, 0) != WYRELOG_E_OK)
    return 31;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_logout_returns_ok ()) != 0)
    return rc;
  if ((rc = check_logout_rejects_null_handle ()) != 0)
    return rc;
  if ((rc = check_logout_accepts_zero_sid ()) != 0)
    return rc;
  return 0;
}
