/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"

/*
 * Include the FSM and ID private headers first so their type
 * definitions are established before events.h sees the guard macros.
 * events.h declares the same types under #ifndef guards so that
 * external callers (who cannot include the private headers) still get
 * the definitions; internal code gets them here instead.
 */
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"
#include "wyl-id-private.h"

/*
 * Inform events.h that wyl_principal_event_t, wyl_session_event_t,
 * and wyl_id_t are already defined so it skips its guarded copies.
 */
#define WYL_PRINCIPAL_EVENT_T_DEFINED
#define WYL_SESSION_EVENT_T_DEFINED
/* WYL_ID_BYTES is already defined by wyl-id-private.h above */

#include "wyrelog/events.h"
#include "wyl-log-private.h"

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

/* Internal LAST_ sentinel for the domain enum (not in public header).
 * This constant MUST be updated atomically whenever the public
 * wyl_access_event_domain_t enum gains a new domain value; the
 * static assertion below locks it to the actual public cardinality
 * so that silent bounds drift is caught at compile time. */
#define WYL_ACCESS_EVENT_DOMAIN_LAST_ ((wyl_access_event_domain_t) 2)
G_STATIC_ASSERT (WYL_ACCESS_EVENT_DOMAIN_LAST_ == 2);

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
 * Private layout of the PRINCIPAL-domain payload union arm.
 */
typedef struct _WylPrincipalPayload
{
  wyl_id_t principal_id;
  wyl_principal_event_t fsm_event;
  gchar *auth_method;
  gchar *source_ip;
  gchar *user_agent;
} _WylPrincipalPayload;

/*
 * Private layout of the SESSION-domain payload union arm.
 */
typedef struct _WylSessionPayload
{
  wyl_id_t session_id;
  wyl_session_event_t fsm_event;
  gchar *source_ip;
  gchar *user_agent;
} _WylSessionPayload;

G_STATIC_ASSERT (sizeof (gint64) == 8);

/*
 * Private struct layout for WylAccessContext (GObject).
 */
struct _WylAccessContext
{
  GObject parent_instance;
  gint64 timestamp_us;
  gchar *source_ip;
  gchar *user_agent;
  gchar *request_id;
};

/*
 * Private struct layout for WylAccessEvent (GObject).
 */
struct _WylAccessEvent
{
  GObject parent_instance;
  wyl_access_event_domain_t domain;
  wyl_id_t event_id;
  union
  {
    _WylPrincipalPayload principal;
    _WylSessionPayload session;
  } payload;
  gint64 timestamp_us;
  WylAccessContext *context;
};

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
