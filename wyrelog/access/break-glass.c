/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "break-glass-private.h"

#include <string.h>

static const gchar *const reason_names[] = {
  [WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE] = "incident_response",
  [WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION] = "policy_corruption",
  [WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT] =
      "security_officer_lockout",
  [WYL_BREAK_GLASS_REASON_SERVICE_UNFREEZE] = "service_unfreeze",
  [WYL_BREAK_GLASS_REASON_OTHER] = "other",
};

G_STATIC_ASSERT (G_N_ELEMENTS (reason_names) == WYL_BREAK_GLASS_REASON_LAST_);

const gchar *
wyl_break_glass_reason_name (wyl_break_glass_reason_code_t code)
{
  if ((guint) code >= WYL_BREAK_GLASS_REASON_LAST_)
    return "unknown";
  return reason_names[code];
}

wyrelog_error_t
wyl_break_glass_reason_from_name (const gchar *name,
    wyl_break_glass_reason_code_t *out_code)
{
  if (name == NULL || name[0] == '\0' || out_code == NULL)
    return WYRELOG_E_INVALID;

  for (guint i = 0; i < WYL_BREAK_GLASS_REASON_LAST_; i++) {
    if (g_strcmp0 (name, reason_names[i]) == 0) {
      *out_code = (wyl_break_glass_reason_code_t) i;
      return WYRELOG_E_OK;
    }
  }
  return WYRELOG_E_NOT_FOUND;
}
