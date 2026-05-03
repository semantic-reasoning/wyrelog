/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

/*
 * v0 contract for wyl_perm_grant / wyl_perm_revoke: validate
 * arguments, record the admin operation in the audit log when
 * audit is enabled, and return WYRELOG_E_OK without touching a
 * durable permission store. The store wiring is a follow-up.
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
  if ((rc = check_revoke_rejects_null_args ()) != 0)
    return rc;
  return 0;
}
