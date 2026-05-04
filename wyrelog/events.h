/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * WylAccessEvent - opaque access event carrier.
 *
 * Records a single access-related occurrence for one of two domains:
 * a principal authentication event or a session lifecycle event.
 * Each event carries a caller-issued identifier, a domain-specific
 * FSM event, optional string metadata, a microsecond-precision
 * timestamp, and an optional context attachment.
 *
 * Immutable post-construction. Not thread-safe; ownership must be
 * transferred explicitly before handing off to another thread.
 * Strings supplied at construction time are duplicated; modifying
 * the caller's buffer after construction does not affect the stored
 * value.
 *
 * Released with g_object_unref or g_autoptr(WylAccessEvent).
 */
G_DECLARE_FINAL_TYPE (WylAccessEvent, wyl_access_event, WYL, ACCESS_EVENT,
    GObject);
#define WYL_TYPE_ACCESS_EVENT (wyl_access_event_get_type ())

/*
 * WylAccessContext - opaque request context carrier.
 *
 * Provides a domain-neutral surface for ingress code to attach
 * per-request metadata (timestamp, source address, user-agent string,
 * and similar request-scoped fields) alongside an access event
 * payload. Context objects are reference-counted; attaching a context
 * to an event increments the reference count, and the event releases
 * its reference when finalized.
 *
 * Released with g_object_unref or g_autoptr(WylAccessContext).
 */
G_DECLARE_FINAL_TYPE (WylAccessContext, wyl_access_context, WYL,
    ACCESS_CONTEXT, GObject);
#define WYL_TYPE_ACCESS_CONTEXT (wyl_access_context_get_type ())

/*
 * Domain discriminator: selects which FSM vocabulary the event
 * carries and which accessor family is valid.
 */
typedef enum wyl_access_event_domain_t
{
  WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL = 0,
  WYL_ACCESS_EVENT_DOMAIN_SESSION,
} wyl_access_event_domain_t;

/*
 * Time-ordered identifier: 16-byte value type backed by a UUIDv7-shaped
 * generator. Bytewise lexicographic order tracks creation order at
 * millisecond granularity.
 *
 * The all-zero value WYL_ID_NIL is reserved for "no identifier" slots.
 * Constructors reject WYL_ID_NIL inputs for mandatory identifier fields.
 *
 * Guard: wyl-id-private.h defines WYL_ID_BYTES and is the authoritative
 * definition site for library-internal code. This block is guarded so
 * that whichever header is included first wins; the two definitions are
 * identical and the guard prevents a redefinition error.
 */
#ifndef WYL_ID_BYTES
#define WYL_ID_BYTES 16

typedef struct wyl_id_t
{
  guint8 bytes[WYL_ID_BYTES];
} wyl_id_t;

G_STATIC_ASSERT (sizeof (wyl_id_t) == WYL_ID_BYTES);

extern const wyl_id_t WYL_ID_NIL;

/*
 * Bytewise equality. Returns FALSE when either pointer is NULL.
 */
gboolean wyl_id_equal (const wyl_id_t * a, const wyl_id_t * b);

#endif /* WYL_ID_BYTES */

/*
 * Principal FSM event vocabulary (input to the authentication FSM).
 *
 * Guard: wyl-fsm-principal-private.h is the authoritative definition
 * site for library-internal code. This block is guarded so that
 * whichever header is included first wins.
 */
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

/*
 * Session lifecycle FSM event vocabulary.
 *
 * Guard: wyl-fsm-session-private.h is the authoritative definition
 * site for library-internal code. This block is guarded so that
 * whichever header is included first wins.
 */
#ifndef WYL_SESSION_EVENT_T_DEFINED
#define WYL_SESSION_EVENT_T_DEFINED

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

#endif /* WYL_SESSION_EVENT_T_DEFINED */

/* -----------------------------------------------------------------------
 * WylAccessContext constructors and accessors
 * --------------------------------------------------------------------- */

/*
 * Construct a new WylAccessContext carrying per-request metadata.
 *
 * @timestamp_us:  wall-clock time of the originating request in
 *                 microseconds since the Unix epoch.
 * @source_ip:     NUL-terminated source IP address string, or NULL.
 * @user_agent:    NUL-terminated user-agent string, or NULL.
 * @request_id:    NUL-terminated opaque request identifier, or NULL.
 *
 * On success sets *out to the new context and returns WYRELOG_E_OK.
 * Returns WYRELOG_E_INVALID when out is NULL.
 *
 * Caller releases with g_object_unref or g_autoptr(WylAccessContext).
 */
wyrelog_error_t wyl_access_context_new (gint64 timestamp_us,
    const gchar * source_ip, const gchar * user_agent,
    const gchar * request_id, WylAccessContext ** out);

/*
 * Returns the timestamp recorded in the context, in microseconds
 * since the Unix epoch. Returns 0 when ctx is NULL.
 */
gint64 wyl_access_context_get_timestamp_us (const WylAccessContext * ctx);

/*
 * Returns the borrowed source IP string, or NULL when absent or
 * when ctx is NULL. Pointer is valid for the lifetime of ctx.
 */
const gchar *wyl_access_context_get_source_ip (const WylAccessContext * ctx);

/*
 * Returns the borrowed user-agent string, or NULL when absent or
 * when ctx is NULL. Pointer is valid for the lifetime of ctx.
 */
const gchar *wyl_access_context_get_user_agent (const WylAccessContext * ctx);

/*
 * Returns the borrowed request identifier string, or NULL when
 * absent or when ctx is NULL. Pointer is valid for the lifetime
 * of ctx.
 */
const gchar *wyl_access_context_get_request_id (const WylAccessContext * ctx);

/* -----------------------------------------------------------------------
 * WylAccessEvent constructors
 * --------------------------------------------------------------------- */

/*
 * Construct a new access event for the principal authentication domain.
 *
 * @event_id:     caller-issued identifier for this event; MUST NOT be
 *                WYL_ID_NIL.
 * @principal_id: identifier of the principal; MUST NOT be WYL_ID_NIL.
 * @fsm_event:    the FSM event being recorded; MUST be a valid ordinal
 *                less than WYL_PRINCIPAL_EVENT_LAST_.
 * @auth_method:  NUL-terminated authentication method string; MUST NOT
 *                be NULL.
 * @source_ip:    NUL-terminated source IP address string, or NULL.
 * @user_agent:   NUL-terminated user-agent string, or NULL.
 * @timestamp_us: event timestamp in microseconds since the Unix epoch.
 * @context:      optional context attachment; may be NULL. When
 *                non-NULL the event holds a reference for its lifetime.
 * @out:          MUST NOT be NULL; receives the new event on success.
 *
 * Returns WYRELOG_E_OK on success.
 * Returns WYRELOG_E_INVALID when any mandatory argument is absent or
 * out-of-range (event_id is NIL, principal_id is NIL, auth_method is
 * NULL, fsm_event is at or beyond WYL_PRINCIPAL_EVENT_LAST_, or out
 * is NULL).
 *
 * Strings are duplicated at construction; the event is immutable
 * post-construction. Caller releases with g_object_unref or
 * g_autoptr(WylAccessEvent).
 */
wyrelog_error_t wyl_access_event_new_principal (wyl_id_t event_id,
    wyl_id_t principal_id, wyl_principal_event_t fsm_event,
    const gchar * auth_method, const gchar * source_ip,
    const gchar * user_agent, gint64 timestamp_us,
    WylAccessContext * context, WylAccessEvent ** out);

/*
 * Construct a new access event for the session lifecycle domain.
 *
 * @event_id:    caller-issued identifier for this event; MUST NOT be
 *               WYL_ID_NIL.
 * @session_id:  identifier of the session; MUST NOT be WYL_ID_NIL.
 * @fsm_event:   the session FSM event being recorded; MUST be a valid
 *               ordinal less than WYL_SESSION_EVENT_LAST_.
 * @source_ip:   NUL-terminated source IP address string, or NULL.
 * @user_agent:  NUL-terminated user-agent string, or NULL.
 * @timestamp_us: event timestamp in microseconds since the Unix epoch.
 * @context:     optional context attachment; may be NULL.
 * @out:         MUST NOT be NULL; receives the new event on success.
 *
 * Returns WYRELOG_E_OK on success.
 * Returns WYRELOG_E_INVALID on any mandatory-argument violation.
 */
wyrelog_error_t wyl_access_event_new_session (wyl_id_t event_id,
    wyl_id_t session_id, wyl_session_event_t fsm_event,
    const gchar * source_ip, const gchar * user_agent,
    gint64 timestamp_us, WylAccessContext * context, WylAccessEvent ** out);

/* -----------------------------------------------------------------------
 * WylAccessEvent common accessors
 * --------------------------------------------------------------------- */

/*
 * Returns the domain discriminator of the event.
 * Returns WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL when e is NULL.
 */
wyl_access_event_domain_t wyl_access_event_get_domain (const WylAccessEvent
    * e);

/*
 * Returns the caller-issued event identifier.
 * Returns WYL_ID_NIL when e is NULL.
 */
wyl_id_t wyl_access_event_get_event_id (const WylAccessEvent * e);

/*
 * Returns the event timestamp in microseconds since the Unix epoch.
 * Returns 0 when e is NULL.
 */
gint64 wyl_access_event_get_timestamp_us (const WylAccessEvent * e);

/*
 * Returns the context attached at construction time, or NULL when no
 * context was provided or when e is NULL.
 * The returned pointer is borrowed from the event; do not unref.
 */
WylAccessContext *wyl_access_event_get_context (const WylAccessEvent * e);

/* -----------------------------------------------------------------------
 * WylAccessEvent domain-gated accessors
 *
 * Accessors in the PRINCIPAL family return a sentinel (WYL_ID_NIL or
 * NULL) and log a recoverable error when called on a SESSION event,
 * and vice versa.
 * --------------------------------------------------------------------- */

/*
 * Returns the principal identifier carried by a PRINCIPAL-domain
 * event. Returns WYL_ID_NIL and logs an error when e is NULL or when
 * e is a SESSION-domain event.
 */
wyl_id_t wyl_access_event_get_principal_id (const WylAccessEvent * e);

/*
 * Returns the FSM event ordinal carried by a PRINCIPAL-domain event.
 * Returns WYL_PRINCIPAL_EVENT_LAST_ and logs an error when e is NULL
 * or when e is a SESSION-domain event.
 */
wyl_principal_event_t wyl_access_event_get_principal_fsm_event (const
    WylAccessEvent * e);

/*
 * Returns the borrowed authentication method string from a
 * PRINCIPAL-domain event. Returns NULL and logs an error when e is
 * NULL or when e is a SESSION-domain event.
 */
const gchar *wyl_access_event_get_auth_method (const WylAccessEvent * e);

/*
 * Returns the borrowed source IP string from a PRINCIPAL-domain
 * event. Returns NULL and logs an error when e is NULL or when e is
 * a SESSION-domain event.
 */
const gchar *wyl_access_event_get_principal_source_ip (const WylAccessEvent
    * e);

/*
 * Returns the borrowed user-agent string from a PRINCIPAL-domain
 * event. Returns NULL and logs an error when e is NULL or when e is
 * a SESSION-domain event.
 */
const gchar *wyl_access_event_get_principal_user_agent (const WylAccessEvent
    * e);

/*
 * Returns the session identifier carried by a SESSION-domain event.
 * Returns WYL_ID_NIL and logs an error when e is NULL or when e is a
 * PRINCIPAL-domain event.
 */
wyl_id_t wyl_access_event_get_session_id (const WylAccessEvent * e);

/*
 * Returns the FSM event ordinal carried by a SESSION-domain event.
 * Returns WYL_SESSION_EVENT_LAST_ and logs an error when e is NULL
 * or when e is a PRINCIPAL-domain event.
 */
wyl_session_event_t wyl_access_event_get_session_fsm_event (const
    WylAccessEvent * e);

/*
 * Returns the borrowed source IP string from a SESSION-domain event.
 * Returns NULL and logs an error when e is NULL or when e is a
 * PRINCIPAL-domain event.
 */
const gchar *wyl_access_event_get_session_source_ip (const WylAccessEvent * e);

/*
 * Returns the borrowed user-agent string from a SESSION-domain event.
 * Returns NULL and logs an error when e is NULL or when e is a
 * PRINCIPAL-domain event.
 */
const gchar *wyl_access_event_get_session_user_agent (const WylAccessEvent * e);

G_END_DECLS;
