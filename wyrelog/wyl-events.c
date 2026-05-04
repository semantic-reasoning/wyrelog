/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-events-private.h"

/* -----------------------------------------------------------------------
 * Legacy flat-struct helpers (preserved; used by existing tests)
 * --------------------------------------------------------------------- */

static const gchar *const domain_names[] = {
  "principal",
  "session",
};

G_STATIC_ASSERT (G_N_ELEMENTS (domain_names) == 2);

const gchar *
wyl_access_event_domain_name (wyl_access_event_domain_t domain)
{
  if ((guint) domain >= (guint) WYL_ACCESS_EVENT_DOMAIN_LAST_)
    return NULL;
  return domain_names[domain];
}

const gchar *
wyl_access_event_kind_name (const wyl_access_event_t *event)
{
  if (event == NULL)
    return NULL;
  switch (event->domain) {
    case WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL:
      return wyl_principal_event_name (event->event.principal);
    case WYL_ACCESS_EVENT_DOMAIN_SESSION:
      return wyl_session_event_name (event->event.session);
    default:
      return NULL;
  }
}

gsize
wyl_access_event_total_kinds (void)
{
  return (gsize) WYL_PRINCIPAL_EVENT_LAST_ + (gsize) WYL_SESSION_EVENT_LAST_;
}

/* -----------------------------------------------------------------------
 * WylAccessContext GObject implementation
 * --------------------------------------------------------------------- */

G_DEFINE_FINAL_TYPE (WylAccessContext, wyl_access_context, G_TYPE_OBJECT);

static void
wyl_access_context_finalize (GObject *object)
{
  WylAccessContext *self = WYL_ACCESS_CONTEXT (object);

  g_clear_pointer (&self->source_ip, g_free);
  g_clear_pointer (&self->user_agent, g_free);
  g_clear_pointer (&self->request_id, g_free);

  G_OBJECT_CLASS (wyl_access_context_parent_class)->finalize (object);
}

static void
wyl_access_context_class_init (WylAccessContextClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_access_context_finalize;
}

static void
wyl_access_context_init (WylAccessContext *self)
{
  self->timestamp_us = 0;
  self->source_ip = NULL;
  self->user_agent = NULL;
  self->request_id = NULL;
}

wyrelog_error_t
wyl_access_context_new (gint64 timestamp_us, const gchar *source_ip,
    const gchar *user_agent, const gchar *request_id, WylAccessContext **out)
{
  if (out == NULL)
    return WYRELOG_E_INVALID;

  WylAccessContext *ctx = g_object_new (WYL_TYPE_ACCESS_CONTEXT, NULL);
  ctx->timestamp_us = timestamp_us;
  ctx->source_ip = g_strdup (source_ip);
  ctx->user_agent = g_strdup (user_agent);
  ctx->request_id = g_strdup (request_id);

  *out = ctx;
  return WYRELOG_E_OK;
}

gint64
wyl_access_context_get_timestamp_us (const WylAccessContext *ctx)
{
  if (ctx == NULL)
    return 0;
  return ctx->timestamp_us;
}

const gchar *
wyl_access_context_get_source_ip (const WylAccessContext *ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->source_ip;
}

const gchar *
wyl_access_context_get_user_agent (const WylAccessContext *ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->user_agent;
}

const gchar *
wyl_access_context_get_request_id (const WylAccessContext *ctx)
{
  if (ctx == NULL)
    return NULL;
  return ctx->request_id;
}

/* -----------------------------------------------------------------------
 * WylAccessEvent GObject implementation
 * --------------------------------------------------------------------- */

G_DEFINE_FINAL_TYPE (WylAccessEvent, wyl_access_event, G_TYPE_OBJECT);

static void
wyl_access_event_finalize (GObject *object)
{
  WylAccessEvent *self = WYL_ACCESS_EVENT (object);

  switch (self->domain) {
    case WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL:
      g_clear_pointer (&self->payload.principal.auth_method, g_free);
      g_clear_pointer (&self->payload.principal.source_ip, g_free);
      g_clear_pointer (&self->payload.principal.user_agent, g_free);
      break;
    case WYL_ACCESS_EVENT_DOMAIN_SESSION:
      g_clear_pointer (&self->payload.session.source_ip, g_free);
      g_clear_pointer (&self->payload.session.user_agent, g_free);
      break;
    default:
      break;
  }

  G_OBJECT_CLASS (wyl_access_event_parent_class)->finalize (object);
}

static void
wyl_access_event_dispose (GObject *object)
{
  WylAccessEvent *self = WYL_ACCESS_EVENT (object);

  g_clear_object (&self->context);

  G_OBJECT_CLASS (wyl_access_event_parent_class)->dispose (object);
}

static void
wyl_access_event_class_init (WylAccessEventClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_access_event_finalize;
  object_class->dispose = wyl_access_event_dispose;
}

static void
wyl_access_event_init (WylAccessEvent *self)
{
  self->domain = WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL;
  self->timestamp_us = 0;
  self->context = NULL;
}

/* --- Helper: compare two wyl_id_t values against WYL_ID_NIL ---------- */

static gboolean
id_is_nil (const wyl_id_t *id)
{
  return wyl_id_equal (id, &WYL_ID_NIL);
}

/* -----------------------------------------------------------------------
 * Constructors
 * --------------------------------------------------------------------- */

wyrelog_error_t
wyl_access_event_new_principal (wyl_id_t event_id, wyl_id_t principal_id,
    wyl_principal_event_t fsm_event, const gchar *auth_method,
    const gchar *source_ip, const gchar *user_agent,
    gint64 timestamp_us, WylAccessContext *context, WylAccessEvent **out)
{
  if (out == NULL)
    return WYRELOG_E_INVALID;
  if (id_is_nil (&event_id))
    return WYRELOG_E_INVALID;
  if (id_is_nil (&principal_id))
    return WYRELOG_E_INVALID;
  if (auth_method == NULL)
    return WYRELOG_E_INVALID;
  if (fsm_event == WYL_PRINCIPAL_EVENT_LAST_ ||
      (guint) fsm_event >= (guint) WYL_PRINCIPAL_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  WylAccessEvent *self = g_object_new (WYL_TYPE_ACCESS_EVENT, NULL);
  self->domain = WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL;
  self->event_id = event_id;
  self->timestamp_us = timestamp_us;
  self->payload.principal.principal_id = principal_id;
  self->payload.principal.fsm_event = fsm_event;
  self->payload.principal.auth_method = g_strdup (auth_method);
  self->payload.principal.source_ip = g_strdup (source_ip);
  self->payload.principal.user_agent = g_strdup (user_agent);
  if (context != NULL)
    self->context = g_object_ref (context);

  *out = self;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_access_event_new_session (wyl_id_t event_id, wyl_id_t session_id,
    wyl_session_event_t fsm_event, const gchar *source_ip,
    const gchar *user_agent, gint64 timestamp_us,
    WylAccessContext *context, WylAccessEvent **out)
{
  if (out == NULL)
    return WYRELOG_E_INVALID;
  if (id_is_nil (&event_id))
    return WYRELOG_E_INVALID;
  if (id_is_nil (&session_id))
    return WYRELOG_E_INVALID;
  if (fsm_event == WYL_SESSION_EVENT_LAST_ ||
      (guint) fsm_event >= (guint) WYL_SESSION_EVENT_LAST_)
    return WYRELOG_E_INVALID;

  WylAccessEvent *self = g_object_new (WYL_TYPE_ACCESS_EVENT, NULL);
  self->domain = WYL_ACCESS_EVENT_DOMAIN_SESSION;
  self->event_id = event_id;
  self->timestamp_us = timestamp_us;
  self->payload.session.session_id = session_id;
  self->payload.session.fsm_event = fsm_event;
  self->payload.session.source_ip = g_strdup (source_ip);
  self->payload.session.user_agent = g_strdup (user_agent);
  if (context != NULL)
    self->context = g_object_ref (context);

  *out = self;
  return WYRELOG_E_OK;
}

/* -----------------------------------------------------------------------
 * Common accessors
 * --------------------------------------------------------------------- */

wyl_access_event_domain_t
wyl_access_event_get_domain (const WylAccessEvent *e)
{
  if (e == NULL)
    return WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL;
  return e->domain;
}

wyl_id_t
wyl_access_event_get_event_id (const WylAccessEvent *e)
{
  if (e == NULL)
    return WYL_ID_NIL;
  return e->event_id;
}

gint64
wyl_access_event_get_timestamp_us (const WylAccessEvent *e)
{
  if (e == NULL)
    return 0;
  return e->timestamp_us;
}

WylAccessContext *
wyl_access_event_get_context (const WylAccessEvent *e)
{
  if (e == NULL)
    return NULL;
  return e->context;
}

/* -----------------------------------------------------------------------
 * Domain-gated PRINCIPAL accessors
 * --------------------------------------------------------------------- */

wyl_id_t
wyl_access_event_get_principal_id (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_id: NULL event");
    return WYL_ID_NIL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_id: called on session-domain event");
    return WYL_ID_NIL;
  }
  return e->payload.principal.principal_id;
}

wyl_principal_event_t
wyl_access_event_get_principal_fsm_event (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_fsm_event: NULL event");
    return WYL_PRINCIPAL_EVENT_LAST_;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_fsm_event: called on session-domain "
        "event");
    return WYL_PRINCIPAL_EVENT_LAST_;
  }
  return e->payload.principal.fsm_event;
}

const gchar *
wyl_access_event_get_auth_method (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_auth_method: NULL event");
    return NULL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_auth_method: called on session-domain event");
    return NULL;
  }
  return e->payload.principal.auth_method;
}

const gchar *
wyl_access_event_get_principal_source_ip (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_source_ip: NULL event");
    return NULL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_source_ip: called on session-domain "
        "event");
    return NULL;
  }
  return e->payload.principal.source_ip;
}

const gchar *
wyl_access_event_get_principal_user_agent (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_user_agent: NULL event");
    return NULL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_principal_user_agent: called on session-domain "
        "event");
    return NULL;
  }
  return e->payload.principal.user_agent;
}

/* -----------------------------------------------------------------------
 * Domain-gated SESSION accessors
 * --------------------------------------------------------------------- */

wyl_id_t
wyl_access_event_get_session_id (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_id: NULL event");
    return WYL_ID_NIL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_SESSION) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_id: called on principal-domain event");
    return WYL_ID_NIL;
  }
  return e->payload.session.session_id;
}

wyl_session_event_t
wyl_access_event_get_session_fsm_event (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_fsm_event: NULL event");
    return WYL_SESSION_EVENT_LAST_;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_SESSION) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_fsm_event: called on principal-domain "
        "event");
    return WYL_SESSION_EVENT_LAST_;
  }
  return e->payload.session.fsm_event;
}

const gchar *
wyl_access_event_get_session_source_ip (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_source_ip: NULL event");
    return NULL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_SESSION) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_source_ip: called on principal-domain "
        "event");
    return NULL;
  }
  return e->payload.session.source_ip;
}

const gchar *
wyl_access_event_get_session_user_agent (const WylAccessEvent *e)
{
  if (e == NULL) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_user_agent: NULL event");
    return NULL;
  }
  if (e->domain != WYL_ACCESS_EVENT_DOMAIN_SESSION) {
    WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL,
        "wyl_access_event_get_session_user_agent: called on principal-domain "
        "event");
    return NULL;
  }
  return e->payload.session.user_agent;
}
