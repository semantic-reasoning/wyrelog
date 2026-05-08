/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

#ifdef WYL_HAS_BREAK_GLASS

static gint
check_arm_rejects_null_handle (void)
{
  if (wyl_handle_break_glass_arm (NULL,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60)
      != WYRELOG_E_INVALID)
    return 1;
  if (wyl_handle_break_glass_disarm (NULL) != WYRELOG_E_INVALID)
    return 2;
  if (wyl_handle_break_glass_is_active (NULL) != FALSE)
    return 3;
  return 0;
}

static gint
check_arm_rejects_out_of_range_reason (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 10;

  if (wyl_handle_break_glass_arm (handle,
          (wyl_break_glass_reason_code_t) WYL_BREAK_GLASS_REASON_LAST_, 60)
      != WYRELOG_E_INVALID)
    return 11;
  if (wyl_handle_break_glass_arm (handle,
          (wyl_break_glass_reason_code_t) 99, 60)
      != WYRELOG_E_INVALID)
    return 12;
  if (wyl_handle_break_glass_is_active (handle))
    return 13;
  return 0;
}

static gint
check_arm_rejects_bad_ttl (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 20;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 0)
      != WYRELOG_E_INVALID)
    return 21;
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, -1)
      != WYRELOG_E_INVALID)
    return 22;
  /* Strictly above the 900s ceiling rejected. */
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 901)
      != WYRELOG_E_INVALID)
    return 23;
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, G_MAXINT64)
      != WYRELOG_E_INVALID)
    return 24;
  if (wyl_handle_break_glass_is_active (handle))
    return 25;
  return 0;
}

static gint
check_arm_then_active_then_disarm (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 30;

  if (wyl_handle_break_glass_is_active (handle))
    return 31;
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION, 60)
      != WYRELOG_E_OK)
    return 32;
  if (!wyl_handle_break_glass_is_active (handle))
    return 33;
  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 34;
  if (wyl_handle_break_glass_is_active (handle))
    return 35;
  /* Disarm is idempotent. */
  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 36;
  return 0;
}

static gint
check_double_arm_is_rejected (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 40;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_SERVICE_UNFREEZE, 60)
      != WYRELOG_E_OK)
    return 41;
  /* Second arm before disarm: the operator must explicitly tear
   * down the first activation before starting a fresh one. */
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60)
      != WYRELOG_E_INVALID)
    return 42;
  /* The original activation is still in effect after the rejected
   * second arm; the rejection does not silently disarm. */
  if (!wyl_handle_break_glass_is_active (handle))
    return 43;
  return 0;
}

static gint
check_disarm_then_arm_succeeds (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 50;

  if (wyl_handle_break_glass_arm (handle, WYL_BREAK_GLASS_REASON_OTHER, 60)
      != WYRELOG_E_OK)
    return 51;
  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 52;
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT, 60)
      != WYRELOG_E_OK)
    return 53;
  if (!wyl_handle_break_glass_is_active (handle))
    return 54;
  return 0;
}

static gint
check_isolation_across_handles (void)
{
  g_autoptr (WylHandle) ha = NULL;
  g_autoptr (WylHandle) hb = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &ha) != WYRELOG_E_OK)
    return 60;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &hb) != WYRELOG_E_OK)
    return 61;

  if (wyl_handle_break_glass_arm (ha,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60)
      != WYRELOG_E_OK)
    return 62;
  /* Activation on handle A must not be visible on handle B. */
  if (wyl_handle_break_glass_is_active (hb))
    return 63;
  if (!wyl_handle_break_glass_is_active (ha))
    return 64;
  return 0;
}

#else /* !WYL_HAS_BREAK_GLASS */

static gint
check_arm_in_disabled_build_returns_disabled_error (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60)
      != WYRELOG_E_BREAK_GLASS_DISABLED)
    return 71;
  if (wyl_handle_break_glass_disarm (handle)
      != WYRELOG_E_BREAK_GLASS_DISABLED)
    return 72;
  if (wyl_handle_break_glass_is_active (handle))
    return 73;
  return 0;
}

#endif

int
main (void)
{
  gint rc;

#ifdef WYL_HAS_BREAK_GLASS
  if ((rc = check_arm_rejects_null_handle ()) != 0)
    return rc;
  if ((rc = check_arm_rejects_out_of_range_reason ()) != 0)
    return rc;
  if ((rc = check_arm_rejects_bad_ttl ()) != 0)
    return rc;
  if ((rc = check_arm_then_active_then_disarm ()) != 0)
    return rc;
  if ((rc = check_double_arm_is_rejected ()) != 0)
    return rc;
  if ((rc = check_disarm_then_arm_succeeds ()) != 0)
    return rc;
  if ((rc = check_isolation_across_handles ()) != 0)
    return rc;
#else
  if ((rc = check_arm_in_disabled_build_returns_disabled_error ()) != 0)
    return rc;
#endif

  return 0;
}
