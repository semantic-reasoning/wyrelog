/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * Principal FSM reference stepper.
 *
 * Mirrors the transition table shipped at
 * <datadir>/wyrelog/access/fsm/principal.dl. The C side is a
 * table-driven Mealy machine: callers feed (state, event), receive
 * the next state, and an undefined (from, event) pair returns
 * WYRELOG_E_POLICY without mutating *out_to.
 *
 * The .dl file is the system of record. The C table is kept in
 * sync by tests/test-fsm-principal.c, which parses the .dl source
 * and asserts row-for-row equality against the array exposed
 * through wyl_fsm_principal_table.
 */

typedef enum wyl_principal_state_t
{
  WYL_PRINCIPAL_STATE_UNVERIFIED = 0,
  WYL_PRINCIPAL_STATE_MFA_REQUIRED,
  WYL_PRINCIPAL_STATE_AUTHENTICATED,
  WYL_PRINCIPAL_STATE_LOCKED,
  WYL_PRINCIPAL_STATE_REVOKED,
  WYL_PRINCIPAL_STATE_LAST_,
} wyl_principal_state_t;

#ifndef WYL_PRINCIPAL_EVENT_T_DEFINED
#define WYL_PRINCIPAL_EVENT_T_DEFINED
typedef enum wyl_principal_event_t
{
  WYL_PRINCIPAL_EVENT_LOGIN_OK = 0,
  WYL_PRINCIPAL_EVENT_LOGIN_SKIP_MFA,
  WYL_PRINCIPAL_EVENT_MFA_OK,
  WYL_PRINCIPAL_EVENT_FAILED_ATTEMPT,
  WYL_PRINCIPAL_EVENT_LOCK,
  WYL_PRINCIPAL_EVENT_UNLOCK,
  WYL_PRINCIPAL_EVENT_REVOKE,
  WYL_PRINCIPAL_EVENT_LAST_,
} wyl_principal_event_t;
#endif /* WYL_PRINCIPAL_EVENT_T_DEFINED */

typedef struct wyl_principal_transition_t
{
  wyl_principal_state_t from;
  wyl_principal_event_t event;
  wyl_principal_state_t to;
} wyl_principal_transition_t;

/* Drives one step of the principal FSM. Returns WYRELOG_E_OK and
 * writes the next state to *out_to on a defined transition.
 * Returns WYRELOG_E_POLICY when no row matches (out_to is left
 * untouched). Returns WYRELOG_E_INVALID when out_to is NULL or
 * either input enum is out of range. */
wyrelog_error_t wyl_fsm_principal_step (wyl_principal_state_t from,
    wyl_principal_event_t event, wyl_principal_state_t * out_to);

/* Read-only access to the transition table. Callers must not
 * mutate the returned storage. The table is sorted in declaration
 * order, matching the .dl source line order, so tests can compare
 * row-by-row. */
const wyl_principal_transition_t *wyl_fsm_principal_table (gsize * out_len);

/* Lexical names for state and event ordinals. Used by the
 * .dl text-mirror oracle in the test harness. NULL on out-of-range
 * input. */
const gchar *wyl_principal_state_name (wyl_principal_state_t s);
const gchar *wyl_principal_event_name (wyl_principal_event_t ev);

G_END_DECLS;
