/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Session FSM reference stepper.
 *
 * Mirrors the transition table shipped at
 * <datadir>/wyrelog/access/fsm/session.dl. The C side is a
 * table-driven Mealy machine: callers feed (state, event), receive
 * the next state, and an undefined (from, event) pair returns
 * WYRELOG_E_POLICY without mutating *out_to.
 *
 * Two intentional omissions encode a security invariant:
 *   - (expiring, request)      forbids silent renewal,
 *   - (expiring, idle_timeout) forbids implicit collection.
 *
 * The .dl file is the system of record. The C table is kept in
 * sync by tests/test-fsm-session.c, which parses the .dl source
 * and asserts row-for-row equality against the array exposed
 * through wyl_fsm_session_table.
 */

typedef enum wyl_session_state_t
{
  WYL_SESSION_STATE_IDLE = 0,
  WYL_SESSION_STATE_ACTIVE,
  WYL_SESSION_STATE_ELEVATED,
  WYL_SESSION_STATE_EXPIRING,
  WYL_SESSION_STATE_CLOSED,
  WYL_SESSION_STATE_LAST_,
} wyl_session_state_t;

typedef enum wyl_session_event_t
{
  WYL_SESSION_EVENT_REQUEST = 0,
  WYL_SESSION_EVENT_IDLE_TIMEOUT,
  WYL_SESSION_EVENT_EXPIRY,
  WYL_SESSION_EVENT_ELEVATE_GRANT,
  WYL_SESSION_EVENT_ELEVATE_DROP,
  WYL_SESSION_EVENT_LOGOUT,
  WYL_SESSION_EVENT_LAST_,
} wyl_session_event_t;

typedef struct wyl_session_transition_t
{
  wyl_session_state_t from;
  wyl_session_event_t event;
  wyl_session_state_t to;
} wyl_session_transition_t;

/* Drives one step of the session FSM. Returns WYRELOG_E_OK and
 * writes the next state to *out_to on a defined transition.
 * Returns WYRELOG_E_POLICY when no row matches (out_to is left
 * untouched). Returns WYRELOG_E_INVALID when out_to is NULL or
 * either input enum is out of range. */
wyrelog_error_t wyl_fsm_session_step (wyl_session_state_t from,
    wyl_session_event_t event, wyl_session_state_t * out_to);

/* Read-only access to the transition table. Callers must not
 * mutate the returned storage. The table is sorted in declaration
 * order, matching the .dl source line order, so tests can compare
 * row-by-row. */
const wyl_session_transition_t *wyl_fsm_session_table (gsize * out_len);

/* Lexical names for state and event ordinals. Used by the
 * .dl text-mirror oracle in the test harness. NULL on out-of-range
 * input. */
const gchar *wyl_session_state_name (wyl_session_state_t s);
const gchar *wyl_session_event_name (wyl_session_event_t ev);

G_END_DECLS;
