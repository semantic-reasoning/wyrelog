/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "decision-private.h"

static const gchar *const reason_names[] = {
  "frozen",
  "disabled_role",
  "sod",
  "not_authenticated",
  "session_inactive",
  "not_armed",
};

static const gchar *const reason_origins[] = {
  "frozen",
  "disabled_role_for",
  "policy_violation",
  "principal_state",
  "session_state",
  "perm_state",
};

G_STATIC_ASSERT (G_N_ELEMENTS (reason_names) == WYL_DENY_REASON_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (reason_origins) == WYL_DENY_REASON_LAST_);

const gchar *
wyl_deny_reason_name (wyl_deny_reason_code_t code)
{
  if ((guint) code >= WYL_DENY_REASON_LAST_)
    return NULL;
  return reason_names[code];
}

const gchar *
wyl_deny_reason_origin (wyl_deny_reason_code_t code)
{
  if ((guint) code >= WYL_DENY_REASON_LAST_)
    return NULL;
  return reason_origins[code];
}

guint
wyl_deny_reason_priority (wyl_deny_reason_code_t code)
{
  if ((guint) code >= WYL_DENY_REASON_LAST_)
    return G_MAXUINT;
  return (guint) code;
}

wyl_deny_reason_code_t
wyl_deny_reason_from_name (const gchar *name)
{
  if (name == NULL)
    return WYL_DENY_REASON_LAST_;
  for (guint i = 0; i < WYL_DENY_REASON_LAST_; i++) {
    if (g_strcmp0 (name, reason_names[i]) == 0)
      return (wyl_deny_reason_code_t) i;
  }
  return WYL_DENY_REASON_LAST_;
}

gsize
wyl_deny_reason_count (void)
{
  return WYL_DENY_REASON_LAST_;
}
