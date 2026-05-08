/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "access/break-glass-private.h"

static gint
check_error_string_for_break_glass_disabled (void)
{
  const gchar *s = wyrelog_error_string (WYRELOG_E_BREAK_GLASS_DISABLED);
  if (s == NULL || s[0] == '\0')
    return 1;
  if (strstr (s, "break-glass") == NULL)
    return 2;
  return 0;
}

static gint
check_error_value_is_distinct_at_tail (void)
{
  /* The enumerator must append at the tail of wyrelog_error_t so the
   * numeric values of every existing code remain stable. The previous
   * tail was WYRELOG_E_NOT_FOUND = -9; the new tail is -10. Pin both
   * values so a reorder is caught at compile time of this test. */
  if ((int) WYRELOG_E_NOT_FOUND != -9)
    return 10;
  if ((int) WYRELOG_E_BREAK_GLASS_DISABLED != -10)
    return 11;
  return 0;
}

static gint
check_reason_name_round_trip (void)
{
  for (guint i = 0; i < WYL_BREAK_GLASS_REASON_LAST_; i++) {
    const gchar *name =
        wyl_break_glass_reason_name ((wyl_break_glass_reason_code_t) i);
    if (name == NULL || name[0] == '\0')
      return 20;
    wyl_break_glass_reason_code_t resolved = WYL_BREAK_GLASS_REASON_LAST_;
    if (wyl_break_glass_reason_from_name (name, &resolved) != WYRELOG_E_OK)
      return 21;
    if ((guint) resolved != i)
      return 22;
  }
  return 0;
}

static gint
check_reason_name_unknown_returns_unknown_string (void)
{
  const gchar *s = wyl_break_glass_reason_name (WYL_BREAK_GLASS_REASON_LAST_);
  if (g_strcmp0 (s, "unknown") != 0)
    return 30;
  return 0;
}

static gint
check_reason_from_name_unknown_returns_not_found (void)
{
  wyl_break_glass_reason_code_t code = WYL_BREAK_GLASS_REASON_LAST_;
  if (wyl_break_glass_reason_from_name ("definitely_not_a_reason", &code)
      != WYRELOG_E_NOT_FOUND)
    return 40;
  return 0;
}

static gint
check_reason_from_name_rejects_invalid_args (void)
{
  wyl_break_glass_reason_code_t code = WYL_BREAK_GLASS_REASON_LAST_;
  if (wyl_break_glass_reason_from_name (NULL, &code) != WYRELOG_E_INVALID)
    return 50;
  if (wyl_break_glass_reason_from_name ("", &code) != WYRELOG_E_INVALID)
    return 51;
  if (wyl_break_glass_reason_from_name ("incident_response", NULL)
      != WYRELOG_E_INVALID)
    return 52;
  return 0;
}

static gint
check_default_ttl_matches_bootstrap_dl (void)
{
  /* templates/access/bootstrap.dl carries ttl("break_glass", 900); the
   * compile-time ceiling exposed to the host must match so the
   * host-side wall-clock gate cannot exceed the DL self-disable
   * horizon. Pin the value so a divergence is caught here. */
  if (WYL_BREAK_GLASS_DEFAULT_TTL_SECONDS != 900)
    return 60;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_error_string_for_break_glass_disabled ()) != 0)
    return rc;
  if ((rc = check_error_value_is_distinct_at_tail ()) != 0)
    return rc;
  if ((rc = check_reason_name_round_trip ()) != 0)
    return rc;
  if ((rc = check_reason_name_unknown_returns_unknown_string ()) != 0)
    return rc;
  if ((rc = check_reason_from_name_unknown_returns_not_found ()) != 0)
    return rc;
  if ((rc = check_reason_from_name_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_default_ttl_matches_bootstrap_dl ()) != 0)
    return rc;

  return 0;
}
