/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "audit/event-private.h"
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "policy/store-private.h"

struct _WylSession
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
  gchar *username;
  wyl_session_state_t state;
};

G_DEFINE_FINAL_TYPE (WylSession, wyl_session, G_TYPE_OBJECT);

static void
wyl_session_finalize (GObject *object)
{
  WylSession *self = WYL_SESSION (object);

  g_free (self->username);

  G_OBJECT_CLASS (wyl_session_parent_class)->finalize (object);
}

static void
wyl_session_class_init (WylSessionClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_session_finalize;
}

static void
wyl_session_init (WylSession *self)
{
  /* Stamp the session with a fresh id and timestamp at login time so
   * audit events emitted on its behalf can be correlated back to the
   * specific session that produced them. The stamps are independent
   * of wyl_session_id_t (the integer handle exposed for logout
   * dispatch) -- this id is the long-lived persistence-side
   * identifier. Failure to mint an id is fatal for the same reason
   * it is on WylAuditEvent and WylHandle: a zero-id session would
   * collapse correlation downstream. */
  if (wyl_id_new (&self->id) != WYRELOG_E_OK)
    g_error ("wyl_session_init: failed to mint identifier");
  self->created_at_us = g_get_real_time ();
  self->state = WYL_SESSION_STATE_IDLE;
}

static wyrelog_error_t
reload_session_snapshot (WylHandle *handle)
{
  if (wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
login_skip_mfa_allowed (WylHandle *handle, const wyl_login_req_t *req,
    gboolean *out_allowed)
{
  if (handle == NULL || req == NULL || out_allowed == NULL)
    return WYRELOG_E_INVALID;

  *out_allowed = FALSE;
  if (wyl_handle_get_login_skip_mfa_allowed (handle)) {
    *out_allowed = TRUE;
    return WYRELOG_E_OK;
  }

  const gchar *username = wyl_login_req_get_username (req);
  if (username == NULL || username[0] == '\0')
    return WYRELOG_E_OK;

  if (wyl_handle_get_read_engine (handle) == NULL
      || wyl_handle_get_delta_engine (handle) == NULL)
    return WYRELOG_E_OK;

  wyrelog_error_t rc = reload_session_snapshot (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 row[1];
  rc = wyl_handle_intern_engine_symbol (handle, username, &row[0]);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_OK;

  rc = wyl_handle_engine_contains (handle, "login_skip_mfa_authz", row, 1,
      out_allowed);
  wyrelog_error_t reload_rc = reload_session_snapshot (handle);
  if (reload_rc != WYRELOG_E_OK)
    return reload_rc;
  if (rc != WYRELOG_E_OK) {
    *out_allowed = FALSE;
    return WYRELOG_E_OK;
  }
  return WYRELOG_E_OK;
}

#ifdef WYL_HAS_AUDIT
static WylAuditEvent *
new_login_skip_mfa_denied_audit (const gchar *username, const gchar *request_id)
{
  WylAuditEvent *ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, username);
  wyl_audit_event_set_action (ev, "login_skip_mfa");
  wyl_audit_event_set_resource_id (ev, "principal_state");
  wyl_audit_event_set_deny_reason (ev, "skip_mfa_not_allowed");
  wyl_audit_event_set_deny_origin (ev, "login_ingress");
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);
  return ev;
}

static wyrelog_error_t
emit_login_skip_mfa_denied_audit (WylHandle *handle, const gchar *username,
    const gchar *request_id)
{
  g_autoptr (WylAuditEvent) ev =
      new_login_skip_mfa_denied_audit (username, request_id);
  return wyl_audit_emit (handle, ev);
}

static WylAuditEvent *
new_principal_state_audit (const gchar *username,
    const gchar *old_state, const gchar *new_state, const gchar *event,
    const gchar *request_id)
{
  WylAuditEvent *ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, username);
  wyl_audit_event_set_action (ev, "principal_state");
  wyl_audit_event_set_resource_id (ev, new_state);
  wyl_audit_event_set_deny_reason (ev, event);
  wyl_audit_event_set_deny_origin (ev, old_state);
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return ev;
}
#endif

static wyrelog_error_t
append_policy_audit_event (wyl_policy_store_t *store, const gchar *audit_id,
    const WylAuditEvent *event)
{
  gboolean inserted = FALSE;

  return wyl_policy_store_append_audit_event_full (store, audit_id,
      wyl_audit_event_get_created_at_us (event),
      wyl_audit_event_get_subject_id (event),
      wyl_audit_event_get_action (event),
      wyl_audit_event_get_resource_id (event),
      wyl_audit_event_get_deny_reason (event),
      wyl_audit_event_get_deny_origin (event),
      wyl_audit_event_get_request_id (event),
      wyl_audit_event_get_decision (event), &inserted);
}

static wyrelog_error_t
insert_principal_event_fact (WylHandle *handle, gint64 event_id,
    const gchar *username, wyl_principal_state_t old_state,
    wyl_principal_event_t event, wyl_principal_state_t new_state)
{
  if (wyl_handle_get_read_engine (handle) == NULL
      || wyl_handle_get_delta_engine (handle) == NULL)
    return WYRELOG_E_OK;
  if (event_id <= 0)
    return WYRELOG_E_OK;

  const gchar *old_state_name = wyl_principal_state_name (old_state);
  const gchar *event_name = wyl_principal_event_name (event);
  const gchar *new_state_name = wyl_principal_state_name (new_state);
  if (old_state_name == NULL || event_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  gint64 row[5];
  row[0] = event_id;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, username, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, event_name, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, old_state_name, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, new_state_name, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, "principal_event", row, 5);
}

static wyrelog_error_t
apply_principal_state_mutation (WylHandle *handle, const gchar *username,
    wyl_principal_state_t old_state, wyl_principal_event_t event,
    wyl_principal_state_t new_state, const WylAuditEvent *audit_event,
    gint64 *out_event_id)
{
  if (username == NULL)
    return WYRELOG_E_OK;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_OK;

  const gchar *old_state_name = wyl_principal_state_name (old_state);
  const gchar *event_name = wyl_principal_event_name (event);
  const gchar *new_state_name = wyl_principal_state_name (new_state);
  if (old_state_name == NULL || event_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_principal_state_t validated = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_principal_step (old_state, event, &validated);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated != new_state)
    return WYRELOG_E_POLICY;

  g_autofree gchar *audit_id = NULL;
  if (audit_event != NULL) {
    audit_id = wyl_audit_event_dup_id_string (audit_event);
    if (audit_id == NULL)
      return WYRELOG_E_INTERNAL;
  }

  gint64 event_id = -1;
  rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_policy_store_set_principal_state (store, username, new_state_name);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_principal_event (store, username,
        event_name, old_state_name, new_state_name, &event_id);
  }
  if (rc == WYRELOG_E_OK && audit_event != NULL) {
    rc = append_policy_audit_event (store, audit_id, audit_event);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  if (out_event_id != NULL)
    *out_event_id = event_id;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
finish_session_mutation (WylHandle *handle, const WylAuditEvent *audit_event)
{
  wyrelog_error_t rc = reload_session_snapshot (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

#ifdef WYL_HAS_AUDIT
  if (audit_event != NULL)
    /* Policy-store audit is durable; the live audit sink is best effort. */
    (void) wyl_audit_mirror_event (handle, audit_event);
#else
  (void) handle;
  (void) audit_event;
#endif

  return rc;
}

static wyrelog_error_t
transition_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t old_state, wyl_principal_state_t new_state)
{
  const gchar *old_state_name = wyl_principal_state_name (old_state);
  const gchar *new_state_name = wyl_principal_state_name (new_state);
  if (old_state_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_principal_state_audit (username,
      old_state_name,
      new_state_name, wyl_principal_event_name (WYL_PRINCIPAL_EVENT_MFA_OK),
      NULL);
#else
  WylAuditEvent *ev = NULL;
#endif
  gint64 event_id = -1;
  wyrelog_error_t rc = apply_principal_state_mutation (handle, username,
      old_state, WYL_PRINCIPAL_EVENT_MFA_OK, new_state, ev, &event_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_principal_event_fact (handle, event_id, username, old_state,
      WYL_PRINCIPAL_EVENT_MFA_OK, new_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_session_mutation (handle, ev);
}

#ifdef WYL_HAS_AUDIT
static WylAuditEvent *
new_session_state_audit (const gchar *session_id,
    const gchar *old_state, const gchar *new_state, const gchar *request_id)
{
  WylAuditEvent *ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, session_id);
  wyl_audit_event_set_action (ev, "session_state");
  wyl_audit_event_set_resource_id (ev, new_state);
  wyl_audit_event_set_deny_origin (ev, old_state);
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return ev;
}
#endif

static wyrelog_error_t
insert_session_event_fact (WylHandle *handle, gint64 event_id,
    const gchar *session_id, wyl_session_state_t old_state,
    wyl_session_event_t event, wyl_session_state_t new_state)
{
  if (wyl_handle_get_read_engine (handle) == NULL
      || wyl_handle_get_delta_engine (handle) == NULL)
    return WYRELOG_E_OK;
  if (event_id <= 0)
    return WYRELOG_E_OK;

  const gchar *old_state_name = wyl_session_state_name (old_state);
  const gchar *event_name = wyl_session_event_name (event);
  const gchar *new_state_name = wyl_session_state_name (new_state);
  if (old_state_name == NULL || event_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  gint64 row[5];
  row[0] = event_id;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, session_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, event_name, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, old_state_name, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, new_state_name, &row[4]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, "session_event", row, 5);
}

static wyrelog_error_t
apply_session_state_mutation (WylHandle *handle, const gchar *session_id,
    wyl_session_state_t old_state, wyl_session_event_t event,
    wyl_session_state_t new_state, const WylAuditEvent *audit_event,
    gint64 *out_event_id)
{
  if (session_id == NULL)
    return WYRELOG_E_OK;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_OK;

  const gchar *old_state_name = wyl_session_state_name (old_state);
  const gchar *event_name = wyl_session_event_name (event);
  const gchar *new_state_name = wyl_session_state_name (new_state);
  if (old_state_name == NULL || event_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_session_state_t validated = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (old_state, event, &validated);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated != new_state)
    return WYRELOG_E_POLICY;

  g_autofree gchar *audit_id = NULL;
  if (audit_event != NULL) {
    audit_id = wyl_audit_event_dup_id_string (audit_event);
    if (audit_id == NULL)
      return WYRELOG_E_INTERNAL;
  }

  gint64 event_id = -1;
  rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_policy_store_set_session_state (store, session_id, new_state_name);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_session_event (store, session_id,
        event_name, old_state_name, new_state_name, &event_id);
  }
  if (rc == WYRELOG_E_OK && audit_event != NULL) {
    rc = append_policy_audit_event (store, audit_id, audit_event);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  if (out_event_id != NULL)
    *out_event_id = event_id;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
apply_login_state_mutation (WylHandle *handle, const gchar *username,
    wyl_principal_event_t principal_event,
    wyl_principal_state_t principal_new_state, const gchar *session_id,
    wyl_session_state_t session_old_state, wyl_session_event_t session_event,
    wyl_session_state_t session_new_state,
    const WylAuditEvent *principal_audit_event,
    const WylAuditEvent *session_audit_event, gint64 *out_principal_event_id,
    gint64 *out_session_event_id)
{
  if (username == NULL || session_id == NULL)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_OK;

  wyl_principal_state_t validated_principal = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_UNVERIFIED, principal_event,
      &validated_principal);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated_principal != principal_new_state)
    return WYRELOG_E_POLICY;

  wyl_session_state_t validated_session = WYL_SESSION_STATE_LAST_;
  rc = wyl_fsm_session_step (session_old_state, session_event,
      &validated_session);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (validated_session != session_new_state)
    return WYRELOG_E_POLICY;

  const gchar *principal_event_name =
      wyl_principal_event_name (principal_event);
  const gchar *principal_from_state =
      wyl_principal_state_name (WYL_PRINCIPAL_STATE_UNVERIFIED);
  const gchar *principal_to_state =
      wyl_principal_state_name (principal_new_state);
  const gchar *session_event_name = wyl_session_event_name (session_event);
  const gchar *session_from_state = wyl_session_state_name (session_old_state);
  const gchar *session_to_state = wyl_session_state_name (session_new_state);
  if (principal_event_name == NULL || principal_from_state == NULL
      || principal_to_state == NULL || session_event_name == NULL
      || session_from_state == NULL || session_to_state == NULL)
    return WYRELOG_E_INTERNAL;

  g_autofree gchar *principal_audit_id = NULL;
  if (principal_audit_event != NULL) {
    principal_audit_id = wyl_audit_event_dup_id_string (principal_audit_event);
    if (principal_audit_id == NULL)
      return WYRELOG_E_INTERNAL;
  }
  g_autofree gchar *session_audit_id = NULL;
  if (session_audit_event != NULL) {
    session_audit_id = wyl_audit_event_dup_id_string (session_audit_event);
    if (session_audit_id == NULL)
      return WYRELOG_E_INTERNAL;
  }

  gint64 principal_event_id = -1;
  gint64 session_event_id = -1;
  rc = wyl_policy_store_begin_mutation (store);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_policy_store_set_principal_state (store, username,
      principal_to_state);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_principal_event (store, username,
        principal_event_name, principal_from_state, principal_to_state,
        &principal_event_id);
  }
  if (rc == WYRELOG_E_OK && principal_audit_event != NULL) {
    rc = append_policy_audit_event (store, principal_audit_id,
        principal_audit_event);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_set_session_state (store, session_id,
        session_to_state);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_append_session_event (store, session_id,
        session_event_name, session_from_state, session_to_state,
        &session_event_id);
  }
  if (rc == WYRELOG_E_OK && session_audit_event != NULL) {
    rc = append_policy_audit_event (store, session_audit_id,
        session_audit_event);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_commit_mutation (store);
  if (rc != WYRELOG_E_OK) {
    wyl_policy_store_rollback_mutation (store);
    return rc;
  }
  if (out_principal_event_id != NULL)
    *out_principal_event_id = principal_event_id;
  if (out_session_event_id != NULL)
    *out_session_event_id = session_event_id;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
transition_session_state (WylHandle *handle, WylSession *session,
    wyl_session_state_t old_state, wyl_session_event_t event,
    wyl_session_state_t new_state)
{
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  const gchar *old_state_name = wyl_session_state_name (old_state);
  const gchar *new_state_name = wyl_session_state_name (new_state);
  if (old_state_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_session_state_audit (session_id,
      old_state_name, new_state_name, NULL);
#else
  WylAuditEvent *ev = NULL;
#endif
  gint64 event_id = -1;
  wyrelog_error_t rc = apply_session_state_mutation (handle, session_id,
      old_state, event, new_state, ev, &event_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_session_event_fact (handle, event_id, session_id, old_state,
      event, new_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = finish_session_mutation (handle, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  session->state = new_state;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_session_login (WylHandle *handle, const wyl_login_req_t *req,
    WylSession **out_session)
{
  if (out_session == NULL)
    return WYRELOG_E_INVALID;
  *out_session = NULL;
  if (handle == NULL)
    return WYRELOG_E_INVALID;

  if (req != NULL && wyl_login_req_get_skip_mfa (req)) {
    gboolean skip_mfa_allowed = FALSE;
    wyrelog_error_t rc = login_skip_mfa_allowed (handle, req,
        &skip_mfa_allowed);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!skip_mfa_allowed) {
#ifdef WYL_HAS_AUDIT
      wyrelog_error_t audit_rc = emit_login_skip_mfa_denied_audit (handle,
          wyl_login_req_get_username (req), wyl_login_req_get_request_id (req));
      if (audit_rc != WYRELOG_E_OK)
        return audit_rc;
#endif
      return WYRELOG_E_POLICY;
    }
  }

  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  const gchar *username = NULL;
  if (req != NULL) {
    username = wyl_login_req_get_username (req);
    session->username = g_strdup (username);
  }

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (username != NULL) {
    wyl_principal_state_t state = WYL_PRINCIPAL_STATE_LAST_;
    wyl_principal_event_t event = WYL_PRINCIPAL_EVENT_LOGIN_OK;
    wyl_principal_state_t expected = WYL_PRINCIPAL_STATE_MFA_REQUIRED;
    if (req != NULL && wyl_login_req_get_skip_mfa (req)) {
      event = WYL_PRINCIPAL_EVENT_LOGIN_SKIP_MFA;
      expected = WYL_PRINCIPAL_STATE_AUTHENTICATED;
    }
    wyrelog_error_t rc = wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_UNVERIFIED,
        event, &state);
    if (rc != WYRELOG_E_OK || state != expected) {
      g_object_unref (session);
      return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;
    }
#ifdef WYL_HAS_AUDIT
    g_autoptr (WylAuditEvent) principal_ev =
        new_principal_state_audit (username,
        wyl_principal_state_name (WYL_PRINCIPAL_STATE_UNVERIFIED),
        wyl_principal_state_name (state), wyl_principal_event_name (event),
        wyl_login_req_get_request_id (req));
    g_autoptr (WylAuditEvent) session_ev =
        new_session_state_audit (session_id,
        wyl_session_state_name (session->state), "active",
        wyl_login_req_get_request_id (req));
#else
    WylAuditEvent *principal_ev = NULL;
    WylAuditEvent *session_ev = NULL;
#endif
    gint64 principal_event_id = -1;
    gint64 session_event_id = -1;
    rc = apply_login_state_mutation (handle, username, event, state,
        session_id, WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
        WYL_SESSION_STATE_ACTIVE, principal_ev, session_ev,
        &principal_event_id, &session_event_id);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    rc = insert_principal_event_fact (handle, principal_event_id, username,
        WYL_PRINCIPAL_STATE_UNVERIFIED, event, state);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    rc = insert_session_event_fact (handle, session_event_id, session_id,
        WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
        WYL_SESSION_STATE_ACTIVE);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    rc = reload_session_snapshot (handle);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
#ifdef WYL_HAS_AUDIT
    /* Policy-store audit is durable; the live audit sink is best effort. */
    (void) wyl_audit_mirror_event (handle, principal_ev);
    (void) wyl_audit_mirror_event (handle, session_ev);
#endif
    session->state = WYL_SESSION_STATE_ACTIVE;
    *out_session = session;
    return WYRELOG_E_OK;
  }
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_session_state_audit (session_id,
      wyl_session_state_name (session->state), "active",
      req != NULL ? wyl_login_req_get_request_id (req) : NULL);
#else
  WylAuditEvent *ev = NULL;
#endif
  gint64 event_id = -1;
  wyrelog_error_t rc = apply_session_state_mutation (handle, session_id,
      WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
      WYL_SESSION_STATE_ACTIVE, ev, &event_id);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
  rc = insert_session_event_fact (handle, event_id, session_id,
      WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
      WYL_SESSION_STATE_ACTIVE);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
  rc = finish_session_mutation (handle, ev);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
  session->state = WYL_SESSION_STATE_ACTIVE;

  *out_session = session;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
mark_session_mfa_verified (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;
  if (session->username == NULL)
    return WYRELOG_E_INVALID;

  wyl_principal_state_t state = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_MFA_OK, &state);
  if (rc != WYRELOG_E_OK || state != WYL_PRINCIPAL_STATE_AUTHENTICATED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_principal_state (handle, session->username,
      WYL_PRINCIPAL_STATE_MFA_REQUIRED, state);
}

wyrelog_error_t
wyl_session_mfa_verify (WylHandle *handle, WylSession *session)
{
  return mark_session_mfa_verified (handle, session);
}

wyrelog_error_t
wyl_session_mfa_verify_with_proof (WylHandle *handle, WylSession *session,
    const gchar *proof, WylMfaValidator validator, gpointer user_data)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session) ||
      session->username == NULL)
    return WYRELOG_E_INVALID;
  if (proof == NULL || proof[0] == '\0' || validator == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = validator (handle, session, proof, user_data);
  if (rc != WYRELOG_E_OK)
    return rc;

  return mark_session_mfa_verified (handle, session);
}

wyrelog_error_t
wyl_session_close (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_session_step (session->state, WYL_SESSION_EVENT_LOGOUT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_CLOSED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, session->state,
      WYL_SESSION_EVENT_LOGOUT, state);
}

wyrelog_error_t
wyl_session_elevate (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (session->state,
      WYL_SESSION_EVENT_ELEVATE_GRANT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_ELEVATED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, session->state,
      WYL_SESSION_EVENT_ELEVATE_GRANT, state);
}

wyrelog_error_t
wyl_session_drop_elevation (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (session->state,
      WYL_SESSION_EVENT_ELEVATE_DROP, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_ACTIVE)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, session->state,
      WYL_SESSION_EVENT_ELEVATE_DROP, state);
}

wyrelog_error_t
wyl_session_idle_timeout (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (session->state,
      WYL_SESSION_EVENT_IDLE_TIMEOUT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_IDLE)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, session->state,
      WYL_SESSION_EVENT_IDLE_TIMEOUT, state);
}

wyrelog_error_t
wyl_session_expire (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_session_step (session->state, WYL_SESSION_EVENT_EXPIRY, &state);
  if (rc != WYRELOG_E_OK)
    return rc;

  return transition_session_state (handle, session, session->state,
      WYL_SESSION_EVENT_EXPIRY, state);
}

wyrelog_error_t
wyl_session_logout (WylHandle *handle, wyl_session_id_t sid)
{
  if (handle == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  /* Mirror the logout in the audit log so session terminations are
   * observable even before the session table that owns the sid is
   * wired. The action column carries "logout" semantics; the
   * subject_id column carries the integer session handle as text
   * so log readers can tie the event back to the originating
   * wyl_session_login. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  g_autofree gchar *sid_str = g_strdup_printf ("%" G_GUINT64_FORMAT, sid);
  wyl_audit_event_set_subject_id (ev, sid_str);
  wyl_audit_event_set_action (ev, "logout");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (handle, ev);
#else
  (void) sid;
#endif

  /* Real session-table teardown lands in a follow-up; v0 returns
   * E_OK after argument validation and audit recording. */
  return WYRELOG_E_OK;
}

gchar *
wyl_session_dup_id_string (const WylSession *self)
{
  gchar buf[WYL_ID_STRING_BUF];

  g_return_val_if_fail (WYL_IS_SESSION (self), NULL);

  if (wyl_id_format (&self->id, buf, sizeof buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup (buf);
}

gint64
wyl_session_get_created_at_us (const WylSession *self)
{
  g_return_val_if_fail (WYL_IS_SESSION (self), -1);
  return self->created_at_us;
}

gchar *
wyl_session_dup_username (const WylSession *self)
{
  g_return_val_if_fail (WYL_IS_SESSION (self), NULL);
  if (self->username == NULL)
    return NULL;
  return g_strdup (self->username);
}
