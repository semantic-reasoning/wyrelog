/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

/*
 * wyl_decide v0 contract: every decide call returns WYRELOG_E_OK
 * with a DENY verdict (the policy decision point is not yet wired
 * to a configured allow-list). Validates argument-handling and the
 * fail-closed default.
 */

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
check_decide_default_resp_stays_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  /* Pre-set ALLOW; decide must overwrite back to DENY. */
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 31;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 32;
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
  if ((rc = check_decide_default_resp_stays_deny ()) != 0)
    return rc;
  return 0;
}
