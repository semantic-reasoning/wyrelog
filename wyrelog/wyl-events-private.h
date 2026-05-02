/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"

G_BEGIN_DECLS;

/*
 * Access event envelope.
 *
 * The ingress layer translates external requests into a stream of
 * events that the engine routes to one of two state machines: the
 * principal authentication FSM or the per-session lifecycle FSM.
 * The envelope here is the carrier for that decision: a domain
 * discriminator that picks which FSM to drive plus a tagged union
 * over the two FSM event vocabularies, alongside common metadata
 * (timestamp, user, session) that every event carries regardless
 * of domain.
 *
 * Composition rather than redefinition: the principal and session
 * event enumerations are owned by their respective FSM headers
 * (F1 and F2). This module re-uses them through the union so that
 * a future change to either FSM's event vocabulary propagates
 * automatically without a third source of truth to keep in sync.
 *
 * The total number of distinct events the envelope can carry is
 * therefore equal to the sum of the two FSM event counts -- seven
 * principal events plus six session events for thirteen variants
 * in v0. The earlier ten-event sketch in the design notes
 * predates the FSM lock; it is superseded here so that no FSM
 * transition is orphaned at the ingress boundary.
 */

typedef enum wyl_access_event_domain_t
{
  WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL = 0,
  WYL_ACCESS_EVENT_DOMAIN_SESSION,
  WYL_ACCESS_EVENT_DOMAIN_LAST_,
} wyl_access_event_domain_t;

typedef struct wyl_access_event_t
{
  wyl_access_event_domain_t domain;
  union
  {
    wyl_principal_event_t principal;
    wyl_session_event_t session;
  } event;
  gint64 timestamp_us;
  const gchar *user_id;
  const gchar *session_id;
} wyl_access_event_t;

/*
 * Lexical name of the domain ordinal. NULL on out-of-range input.
 */
const gchar *wyl_access_event_domain_name (wyl_access_event_domain_t domain);

/*
 * Lexical name of the carried FSM event. Dispatches to the
 * corresponding F1/F2 accessor. Returns NULL when the envelope
 * pointer is NULL, when the domain is out of range, or when the
 * carried FSM event ordinal is out of range for its domain.
 */
const gchar *wyl_access_event_kind_name (const wyl_access_event_t * event);

/*
 * Total number of distinct event variants representable by the
 * envelope. Equals the sum of the principal and session FSM event
 * counts; useful as a loop bound for exhaustive coverage tests.
 */
gsize wyl_access_event_total_kinds (void);

G_END_DECLS;
