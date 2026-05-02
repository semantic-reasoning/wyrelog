/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-fsm-principal-private.h"

static const wyl_principal_transition_t fsm_table[] = {
  {WYL_PRINCIPAL_STATE_UNVERIFIED, WYL_PRINCIPAL_EVENT_LOGIN_OK,
      WYL_PRINCIPAL_STATE_MFA_REQUIRED},
  {WYL_PRINCIPAL_STATE_UNVERIFIED, WYL_PRINCIPAL_EVENT_LOGIN_SKIP_MFA,
      WYL_PRINCIPAL_STATE_AUTHENTICATED},
  {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_MFA_OK,
      WYL_PRINCIPAL_STATE_AUTHENTICATED},
  {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT,
      WYL_PRINCIPAL_STATE_MFA_REQUIRED},
  {WYL_PRINCIPAL_STATE_MFA_REQUIRED, WYL_PRINCIPAL_EVENT_LOCK,
      WYL_PRINCIPAL_STATE_LOCKED},
  {WYL_PRINCIPAL_STATE_AUTHENTICATED, WYL_PRINCIPAL_EVENT_LOCK,
      WYL_PRINCIPAL_STATE_LOCKED},
  {WYL_PRINCIPAL_STATE_AUTHENTICATED, WYL_PRINCIPAL_EVENT_REVOKE,
      WYL_PRINCIPAL_STATE_REVOKED},
  {WYL_PRINCIPAL_STATE_LOCKED, WYL_PRINCIPAL_EVENT_UNLOCK,
      WYL_PRINCIPAL_STATE_UNVERIFIED},
};

static const gchar *const state_names[] = {
  "unverified",
  "mfa_required",
  "authenticated",
  "locked",
  "revoked",
};

static const gchar *const event_names[] = {
  "login_ok",
  "login_skip_mfa",
  "mfa_ok",
  "failed_attempt",
  "lock",
  "unlock",
  "revoke",
};

G_STATIC_ASSERT (G_N_ELEMENTS (state_names) == WYL_PRINCIPAL_STATE_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (event_names) == WYL_PRINCIPAL_EVENT_LAST_);

wyrelog_error_t
wyl_fsm_principal_step (wyl_principal_state_t from,
    wyl_principal_event_t event, wyl_principal_state_t *out_to)
{
  if (out_to == NULL)
    return WYRELOG_E_INVALID;
  if ((guint) from >= WYL_PRINCIPAL_STATE_LAST_)
    return WYRELOG_E_INVALID;
  if ((guint) event >= WYL_PRINCIPAL_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < G_N_ELEMENTS (fsm_table); i++) {
    if (fsm_table[i].from == from && fsm_table[i].event == event) {
      *out_to = fsm_table[i].to;
      return WYRELOG_E_OK;
    }
  }
  return WYRELOG_E_POLICY;
}

const wyl_principal_transition_t *
wyl_fsm_principal_table (gsize *out_len)
{
  if (out_len != NULL)
    *out_len = G_N_ELEMENTS (fsm_table);
  return fsm_table;
}

const gchar *
wyl_principal_state_name (wyl_principal_state_t s)
{
  if ((guint) s >= WYL_PRINCIPAL_STATE_LAST_)
    return NULL;
  return state_names[s];
}

const gchar *
wyl_principal_event_name (wyl_principal_event_t ev)
{
  if ((guint) ev >= WYL_PRINCIPAL_EVENT_LAST_)
    return NULL;
  return event_names[ev];
}
