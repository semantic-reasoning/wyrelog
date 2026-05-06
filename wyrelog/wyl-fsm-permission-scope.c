/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-fsm-permission-scope-private.h"

static const wyl_perm_transition_t fsm_table[] = {
  {WYL_PERM_STATE_DORMANT, WYL_PERM_EVENT_GRANT, WYL_PERM_STATE_ARMED},
  {WYL_PERM_STATE_ARMED, WYL_PERM_EVENT_REVOKE, WYL_PERM_STATE_DORMANT},
  {WYL_PERM_STATE_ARMED, WYL_PERM_EVENT_TRIGGER, WYL_PERM_STATE_FIRING},
  {WYL_PERM_STATE_FIRING, WYL_PERM_EVENT_COMPLETE, WYL_PERM_STATE_COOLDOWN},
  {WYL_PERM_STATE_COOLDOWN, WYL_PERM_EVENT_RESET, WYL_PERM_STATE_ARMED},
  {WYL_PERM_STATE_COOLDOWN, WYL_PERM_EVENT_EXPIRE, WYL_PERM_STATE_DORMANT},
};

static const gchar *const state_names[] = {
  "dormant",
  "armed",
  "firing",
  "cooldown",
};

static const gchar *const event_names[] = {
  "grant",
  "revoke",
  "trigger",
  "complete",
  "reset",
  "expire",
};

G_STATIC_ASSERT (G_N_ELEMENTS (state_names) == WYL_PERM_STATE_LAST_);
G_STATIC_ASSERT (G_N_ELEMENTS (event_names) == WYL_PERM_EVENT_LAST_);

wyrelog_error_t
wyl_fsm_permission_scope_step (wyl_perm_state_t from, wyl_perm_event_t event,
    wyl_perm_state_t *out_to)
{
  if (out_to == NULL)
    return WYRELOG_E_INVALID;
  if ((guint) from >= WYL_PERM_STATE_LAST_)
    return WYRELOG_E_INVALID;
  if ((guint) event >= WYL_PERM_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < G_N_ELEMENTS (fsm_table); i++) {
    if (fsm_table[i].from == from && fsm_table[i].event == event) {
      *out_to = fsm_table[i].to;
      return WYRELOG_E_OK;
    }
  }
  return WYRELOG_E_POLICY;
}

const wyl_perm_transition_t *
wyl_fsm_permission_scope_table (gsize *out_len)
{
  if (out_len != NULL)
    *out_len = G_N_ELEMENTS (fsm_table);
  return fsm_table;
}

const gchar *
wyl_perm_state_name (wyl_perm_state_t s)
{
  if ((guint) s >= WYL_PERM_STATE_LAST_)
    return NULL;
  return state_names[s];
}

const gchar *
wyl_perm_event_name (wyl_perm_event_t ev)
{
  if ((guint) ev >= WYL_PERM_EVENT_LAST_)
    return NULL;
  return event_names[ev];
}

wyl_perm_state_t
wyl_perm_state_from_name (const gchar *name)
{
  if (name == NULL)
    return WYL_PERM_STATE_LAST_;
  for (guint i = 0; i < WYL_PERM_STATE_LAST_; i++) {
    if (g_strcmp0 (name, state_names[i]) == 0)
      return (wyl_perm_state_t) i;
  }
  return WYL_PERM_STATE_LAST_;
}

wyl_perm_event_t
wyl_perm_event_from_name (const gchar *name)
{
  if (name == NULL)
    return WYL_PERM_EVENT_LAST_;
  for (guint i = 0; i < WYL_PERM_EVENT_LAST_; i++) {
    if (g_strcmp0 (name, event_names[i]) == 0)
      return (wyl_perm_event_t) i;
  }
  return WYL_PERM_EVENT_LAST_;
}
