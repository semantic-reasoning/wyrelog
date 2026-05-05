/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

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
insert_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t state)
{
  if (username == NULL || wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;

  const gchar *state_name = wyl_principal_state_name (state);
  if (state_name == NULL)
    return WYRELOG_E_INTERNAL;

  gint64 row[2];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, username, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, state_name, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, "principal_state", row, 2);
}

static wyrelog_error_t
remove_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t state)
{
  if (username == NULL || wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;

  const gchar *state_name = wyl_principal_state_name (state);
  if (state_name == NULL)
    return WYRELOG_E_INTERNAL;

  gint64 row[2];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, username, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, state_name, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_remove (handle, "principal_state", row, 2);
}

static wyrelog_error_t
store_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t state)
{
  if (username == NULL)
    return WYRELOG_E_OK;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_OK;

  const gchar *state_name = wyl_principal_state_name (state);
  if (state_name == NULL)
    return WYRELOG_E_INTERNAL;

  return wyl_policy_store_set_principal_state (store, username, state_name);
}

static wyrelog_error_t
store_principal_event (WylHandle *handle, const gchar *username,
    wyl_principal_state_t old_state, wyl_principal_event_t event,
    wyl_principal_state_t new_state)
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

  return wyl_policy_store_append_principal_event (store, username, event_name,
      old_state_name, new_state_name);
}

static wyrelog_error_t
set_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t state)
{
  wyrelog_error_t rc = insert_principal_state (handle, username, state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return store_principal_state (handle, username, state);
}

#ifdef WYL_HAS_AUDIT
static void
emit_principal_state_audit (WylHandle *handle, const gchar *username,
    const gchar *old_state, const gchar *new_state, const gchar *event)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, username);
  wyl_audit_event_set_action (ev, "principal_state");
  wyl_audit_event_set_resource_id (ev, new_state);
  wyl_audit_event_set_deny_reason (ev, event);
  wyl_audit_event_set_deny_origin (ev, old_state);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (handle, ev);
}
#endif

static wyrelog_error_t
transition_principal_state (WylHandle *handle, const gchar *username,
    wyl_principal_state_t old_state, wyl_principal_state_t new_state)
{
  const gchar *old_state_name = wyl_principal_state_name (old_state);
  const gchar *new_state_name = wyl_principal_state_name (new_state);
  if (old_state_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  wyrelog_error_t rc = remove_principal_state (handle, username, old_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_principal_state (handle, username, new_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = store_principal_state (handle, username, new_state);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = store_principal_event (handle, username, old_state,
      WYL_PRINCIPAL_EVENT_MFA_OK, new_state);
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef WYL_HAS_AUDIT
  emit_principal_state_audit (handle, username, old_state_name, new_state_name,
      wyl_principal_event_name (WYL_PRINCIPAL_EVENT_MFA_OK));
#endif
  return WYRELOG_E_OK;
}

static wyrelog_error_t
insert_session_state (WylHandle *handle, const gchar *session_id,
    const gchar *state)
{
  if (session_id == NULL || wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;
  if (state == NULL)
    return WYRELOG_E_INVALID;

  gint64 row[2];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, session_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, state, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, "session_state", row, 2);
}

static wyrelog_error_t
remove_session_state (WylHandle *handle, const gchar *session_id,
    const gchar *state)
{
  if (session_id == NULL || wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;
  if (state == NULL)
    return WYRELOG_E_INVALID;

  gint64 row[2];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, session_id, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, state, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_remove (handle, "session_state", row, 2);
}

static wyrelog_error_t
store_session_state (WylHandle *handle, const gchar *session_id,
    const gchar *state)
{
  if (session_id == NULL)
    return WYRELOG_E_OK;
  if (state == NULL)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_OK;

  return wyl_policy_store_set_session_state (store, session_id, state);
}

#ifdef WYL_HAS_AUDIT
static void
emit_session_state_audit (WylHandle *handle, const gchar *session_id,
    const gchar *old_state, const gchar *new_state)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, session_id);
  wyl_audit_event_set_action (ev, "session_state");
  wyl_audit_event_set_resource_id (ev, new_state);
  wyl_audit_event_set_deny_origin (ev, old_state);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (handle, ev);
}
#endif

static wyrelog_error_t
set_session_state (WylHandle *handle, WylSession *session, const gchar *state)
{
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  wyrelog_error_t rc = insert_session_state (handle, session_id, state);
  if (rc != WYRELOG_E_OK)
    return rc;
  return store_session_state (handle, session_id, state);
}

static wyrelog_error_t
transition_session_state (WylHandle *handle, WylSession *session,
    wyl_session_state_t old_state, wyl_session_state_t new_state)
{
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  const gchar *old_state_name = wyl_session_state_name (old_state);
  const gchar *new_state_name = wyl_session_state_name (new_state);
  if (old_state_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

  wyrelog_error_t rc =
      remove_session_state (handle, session_id, old_state_name);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_session_state (handle, session_id, new_state_name);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = store_session_state (handle, session_id, new_state_name);
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef WYL_HAS_AUDIT
  emit_session_state_audit (handle, session_id, old_state_name, new_state_name);
#endif
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

  WylSession *session = g_object_new (WYL_TYPE_SESSION, NULL);
  const gchar *username = NULL;
  if (req != NULL) {
    username = wyl_login_req_get_username (req);
    session->username = g_strdup (username);
  }

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
    rc = set_principal_state (handle, username, state);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    rc = store_principal_event (handle, username,
        WYL_PRINCIPAL_STATE_UNVERIFIED, event, state);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
#ifdef WYL_HAS_AUDIT
    emit_principal_state_audit (handle, username,
        wyl_principal_state_name (WYL_PRINCIPAL_STATE_UNVERIFIED),
        wyl_principal_state_name (state), wyl_principal_event_name (event));
#endif
  }

  wyrelog_error_t rc = set_session_state (handle, session, "active");
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
#ifdef WYL_HAS_AUDIT
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  emit_session_state_audit (handle, session_id,
      wyl_session_state_name (session->state), "active");
#endif
  session->state = WYL_SESSION_STATE_ACTIVE;

  *out_session = session;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_session_mfa_verify (WylHandle *handle, WylSession *session)
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
wyl_session_close (WylHandle *handle, WylSession *session)
{
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_session_step (session->state, WYL_SESSION_EVENT_LOGOUT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_CLOSED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, session->state, state);
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

  return transition_session_state (handle, session, session->state, state);
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

  return transition_session_state (handle, session, session->state, state);
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

  return transition_session_state (handle, session, session->state, state);
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

  return transition_session_state (handle, session, session->state, state);
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
