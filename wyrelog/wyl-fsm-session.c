/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-fsm-session-private.h"

static const wyl_session_transition_t fsm_table[] = {
  {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
      WYL_SESSION_STATE_ACTIVE},
  {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_EXPIRY,
      WYL_SESSION_STATE_CLOSED},
  {WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_LOGOUT,
      WYL_SESSION_STATE_CLOSED},
  {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_IDLE_TIMEOUT,
      WYL_SESSION_STATE_IDLE},
  {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_EXPIRY,
      WYL_SESSION_STATE_EXPIRING},
  {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_ELEVATE_GRANT,
      WYL_SESSION_STATE_ELEVATED},
  {WYL_SESSION_STATE_ACTIVE, WYL_SESSION_EVENT_LOGOUT,
      WYL_SESSION_STATE_CLOSED},
  {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_IDLE_TIMEOUT,
      WYL_SESSION_STATE_IDLE},
  {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_EXPIRY,
      WYL_SESSION_STATE_EXPIRING},
  {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_ELEVATE_DROP,
      WYL_SESSION_STATE_ACTIVE},
  {WYL_SESSION_STATE_ELEVATED, WYL_SESSION_EVENT_LOGOUT,
      WYL_SESSION_STATE_CLOSED},
  {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_EXPIRY,
      WYL_SESSION_STATE_CLOSED},
  {WYL_SESSION_STATE_EXPIRING, WYL_SESSION_EVENT_LOGOUT,
      WYL_SESSION_STATE_CLOSED},
};

static const gchar *const state_names[] = {
  "idle",
  "active",
  "elevated",
  "expiring",
  "closed",
};

static const gchar *const event_names[] = {
  "request",
  "idle_timeout",
  "expiry",
  "elevate_grant",
  "elevate_drop",
  "logout",
};

G_STATIC_ASSERT (G_N_ELEMENTS (state_names) == WYL_SESSION_STATE_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (event_names) == WYL_SESSION_EVENT_LAST_);

wyrelog_error_t
wyl_fsm_session_step (wyl_session_state_t from,
    wyl_session_event_t event, wyl_session_state_t *out_to)
{
  if (out_to == NULL)
    return WYRELOG_E_INVALID;
  if ((guint) from >= WYL_SESSION_STATE_LAST_)
    return WYRELOG_E_INVALID;
  if ((guint) event >= WYL_SESSION_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < G_N_ELEMENTS (fsm_table); i++) {
    if (fsm_table[i].from == from && fsm_table[i].event == event) {
      *out_to = fsm_table[i].to;
      return WYRELOG_E_OK;
    }
  }
  return WYRELOG_E_POLICY;
}

const wyl_session_transition_t *
wyl_fsm_session_table (gsize *out_len)
{
  if (out_len != NULL)
    *out_len = G_N_ELEMENTS (fsm_table);
  return fsm_table;
}

const gchar *
wyl_session_state_name (wyl_session_state_t s)
{
  if ((guint) s >= WYL_SESSION_STATE_LAST_)
    return NULL;
  return state_names[s];
}

const gchar *
wyl_session_event_name (wyl_session_event_t ev)
{
  if ((guint) ev >= WYL_SESSION_EVENT_LAST_)
    return NULL;
  return event_names[ev];
}
