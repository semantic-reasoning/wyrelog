/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

static gint
check_default_is_deny (void)
{
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (resp == NULL)
    return 10;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 11;
  return 0;
}

static gint
check_set_allow (void)
{
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 20;
  return 0;
}

static gint
check_set_deny (void)
{
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 30;
  return 0;
}

static gint
check_get_null_is_deny (void)
{
  /* Fail-closed contract: NULL response means "no decision was
   * produced", which downstream consumers must treat as a denial. */
  if (wyl_decide_resp_get_decision (NULL) != WYL_DECISION_DENY)
    return 40;
  return 0;
}

static gint
check_deny_is_zero (void)
{
  /* g_new0 zero-initialises the struct; that zero value must mean
   * DENY so a forgotten populate path stays fail-closed. */
  if (WYL_DECISION_DENY != 0)
    return 50;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_default_is_deny ()) != 0)
    return rc;
  if ((rc = check_set_allow ()) != 0)
    return rc;
  if ((rc = check_set_deny ()) != 0)
    return rc;
  if ((rc = check_get_null_is_deny ()) != 0)
    return rc;
  if ((rc = check_deny_is_zero ()) != 0)
    return rc;

  return 0;
}
