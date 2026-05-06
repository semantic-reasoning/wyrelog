/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Permission-state FSM reference stepper.
 *
 * Mirrors the transition table shipped at
 * <datadir>/wyrelog/access/fsm/permission_scope.dl. The .dl file is the
 * system of record; tests parse the template and assert row-for-row equality
 * with this C mirror.
 */

typedef enum wyl_perm_state_t
{
  WYL_PERM_STATE_DORMANT = 0,
  WYL_PERM_STATE_ARMED,
  WYL_PERM_STATE_FIRING,
  WYL_PERM_STATE_COOLDOWN,
  WYL_PERM_STATE_LAST_,
} wyl_perm_state_t;

typedef enum wyl_perm_event_t
{
  WYL_PERM_EVENT_GRANT = 0,
  WYL_PERM_EVENT_REVOKE,
  WYL_PERM_EVENT_TRIGGER,
  WYL_PERM_EVENT_COMPLETE,
  WYL_PERM_EVENT_RESET,
  WYL_PERM_EVENT_EXPIRE,
  WYL_PERM_EVENT_LAST_,
} wyl_perm_event_t;

typedef struct wyl_perm_transition_t
{
  wyl_perm_state_t from;
  wyl_perm_event_t event;
  wyl_perm_state_t to;
} wyl_perm_transition_t;

wyrelog_error_t wyl_fsm_permission_scope_step (wyl_perm_state_t from,
    wyl_perm_event_t event, wyl_perm_state_t * out_to);

const wyl_perm_transition_t *wyl_fsm_permission_scope_table (gsize * out_len);

const gchar *wyl_perm_state_name (wyl_perm_state_t s);
const gchar *wyl_perm_event_name (wyl_perm_event_t ev);
wyl_perm_state_t wyl_perm_state_from_name (const gchar * name);
wyl_perm_event_t wyl_perm_event_from_name (const gchar * name);

G_END_DECLS;
