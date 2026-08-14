/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include "wyrelog/wyrelog.h"

#include "access/break-glass-private.h"
#include "access/decision-private.h"
#include "policy/store-private.h"
#include "wyl-decide-private.h"
#include "wyl-handle-compound-private.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-decide-private.h"
#include "wyl-permission-scope-private.h"

struct _wyl_decide_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
  gchar *request_id;
  gboolean has_guard_context;
  gint64 guard_timestamp;
  gchar *guard_loc_class;
  gint64 guard_risk;
  wyl_guard_window_matcher_t guard_in_window;
  gpointer guard_in_window_user_data;
  gboolean service_bearer_authenticated;
};

struct _wyl_decide_resp
{
  wyl_decision_t decision;
  gchar *deny_reason;
  gchar *deny_origin;
};

struct _WylServiceDecisionAuthority
{
  GMutex mutex;
  WylHandle *handle;
  WylServiceAuthReadLease *lease;
  gchar *context_id;
  gchar *subject_id;
  gchar *tenant_id;
  gboolean consumed;
};

typedef struct guard_eval_facts_t
{
  gint64 context_now[3];
  gint64 guard_context[6];
  gint64 guard_context_timestamp[3];
  gint64 guard_context_loc_class[3];
  gint64 guard_context_risk[3];
  gint64 guard_context_in_window[4];
  gint64 eval_guard[4];
  gboolean context_now_inserted;
  gboolean guard_context_inserted;
  gboolean guard_context_timestamp_inserted;
  gboolean guard_context_loc_class_inserted;
  gboolean guard_context_risk_inserted;
  gboolean guard_context_in_window_inserted;
  gboolean eval_guard_inserted;
} guard_eval_facts_t;

wyl_decide_req_t *
wyl_decide_req_new (void)
{
  return g_new0 (wyl_decide_req_t, 1);
}

void
wyl_decide_req_free (wyl_decide_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->action);
  g_free (req->resource_id);
  g_free (req->request_id);
  g_free (req->guard_loc_class);
  g_free (req);
}

void
wyl_decide_req_set_subject_id (wyl_decide_req_t *req, const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_decide_req_get_subject_id (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_decide_req_set_action (wyl_decide_req_t *req, const gchar *action)
{
  g_return_if_fail (req != NULL);
  g_free (req->action);
  req->action = g_strdup (action);
}

const gchar *
wyl_decide_req_get_action (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->action;
}

void
wyl_decide_req_set_resource_id (wyl_decide_req_t *req, const gchar *resource_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->resource_id);
  req->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_decide_req_get_resource_id (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->resource_id;
}

void
wyl_decide_req_set_request_id (wyl_decide_req_t *req, const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_decide_req_get_request_id (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
}

void
wyl_decide_req_set_guard_context (wyl_decide_req_t *req, gint64 timestamp,
    const gchar *loc_class, gint64 risk)
{
  g_return_if_fail (req != NULL);
  req->has_guard_context = TRUE;
  req->guard_timestamp = timestamp;
  g_free (req->guard_loc_class);
  req->guard_loc_class = g_strdup (loc_class);
  req->guard_risk = risk;
}

void
wyl_decide_req_clear_guard_context (wyl_decide_req_t *req)
{
  g_return_if_fail (req != NULL);
  req->has_guard_context = FALSE;
  req->guard_timestamp = 0;
  g_clear_pointer (&req->guard_loc_class, g_free);
  req->guard_risk = 0;
  req->guard_in_window = NULL;
  req->guard_in_window_user_data = NULL;
}

gboolean
wyl_decide_req_has_guard_context (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, FALSE);
  return req->has_guard_context;
}

gint64
wyl_decide_req_get_guard_timestamp (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, 0);
  return req->guard_timestamp;
}

const gchar *
wyl_decide_req_get_guard_loc_class (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->guard_loc_class;
}

gint64
wyl_decide_req_get_guard_risk (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, 0);
  return req->guard_risk;
}

void
wyl_decide_req_set_guard_window_matcher (wyl_decide_req_t *req,
    wyl_guard_window_matcher_t matcher, gpointer user_data)
{
  g_return_if_fail (req != NULL);
  req->guard_in_window = matcher;
  req->guard_in_window_user_data = user_data;
}

wyl_guard_window_matcher_t
wyl_decide_req_get_guard_window_matcher (const wyl_decide_req_t *req,
    gpointer *out_user_data)
{
  g_return_val_if_fail (req != NULL, NULL);
  if (out_user_data != NULL)
    *out_user_data = req->guard_in_window_user_data;
  return req->guard_in_window;
}

void
wyl_decide_req_set_service_bearer_authenticated (wyl_decide_req_t *req,
    gboolean authenticated)
{
  g_return_if_fail (req != NULL);
  req->service_bearer_authenticated = authenticated;
}

gboolean
wyl_decide_req_get_service_bearer_authenticated (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, FALSE);
  return req->service_bearer_authenticated;
}

wyl_decide_resp_t *
wyl_decide_resp_new (void)
{
  return g_new0 (wyl_decide_resp_t, 1);
}

void
wyl_decide_resp_free (wyl_decide_resp_t *resp)
{
  if (resp == NULL)
    return;
  g_free (resp->deny_reason);
  g_free (resp->deny_origin);
  g_free (resp);
}

void
wyl_decide_resp_set_decision (wyl_decide_resp_t *resp, wyl_decision_t decision)
{
  g_return_if_fail (resp != NULL);
  resp->decision = decision;
}

static void
wyl_decide_resp_set_deny_tags (wyl_decide_resp_t *resp,
    const gchar *deny_reason, const gchar *deny_origin)
{
  g_return_if_fail (resp != NULL);
  g_free (resp->deny_reason);
  g_free (resp->deny_origin);
  resp->deny_reason = g_strdup (deny_reason);
  resp->deny_origin = g_strdup (deny_origin);
}

wyl_decision_t
wyl_decide_resp_get_decision (const wyl_decide_resp_t *resp)
{
  /* Fail-closed default for a NULL or unset response: a caller that
   * forgets to inspect the error path or never populates the
   * response must not silently observe an ALLOW. */
  g_return_val_if_fail (resp != NULL, WYL_DECISION_DENY);
  return resp->decision;
}

const gchar *
wyl_decide_resp_get_deny_reason (const wyl_decide_resp_t *resp)
{
  g_return_val_if_fail (resp != NULL, NULL);
  return resp->deny_reason;
}

const gchar *
wyl_decide_resp_get_deny_origin (const wyl_decide_resp_t *resp)
{
  g_return_val_if_fail (resp != NULL, NULL);
  return resp->deny_origin;
}

static gboolean
guard_context_is_valid (const wyl_decide_req_t *req)
{
  if (!req->has_guard_context)
    return TRUE;
  if (req->guard_timestamp < 0)
    return FALSE;
  if (!wyl_guard_loc_class_is_valid (req->guard_loc_class))
    return FALSE;
  return req->guard_risk >= 0 && req->guard_risk <= 100;
}

static gboolean
guard_is_satisfied (const wyl_guard_expr_t *guard, const wyl_decide_req_t *req)
{
  if (guard == NULL || !req->has_guard_context)
    return FALSE;

  wyl_scope_t scope = {
    .user = wyl_decide_req_get_subject_id (req),
    .timestamp = req->guard_timestamp,
    .loc_class = req->guard_loc_class,
    .risk = req->guard_risk,
    .in_window = req->guard_in_window,
    .in_window_user_data = req->guard_in_window_user_data,
  };
  return wyl_eval_guard (guard, &scope);
}

/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
remove_guard_eval_facts (WylEngineSession *session,
    const guard_eval_facts_t *facts)
{
  wyrelog_error_t first_rc = WYRELOG_E_OK;

  if (facts->eval_guard_inserted) {
    wyrelog_error_t rc =
        wyl_engine_session_remove (session, "eval_guard", facts->eval_guard, 4);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->context_now_inserted) {
    wyrelog_error_t rc =
        wyl_engine_session_remove (session, "context_now", facts->context_now,
            3);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->guard_context_timestamp_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session,
            "guard_context_timestamp", facts->guard_context_timestamp, 3);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->guard_context_loc_class_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session,
            "guard_context_loc_class", facts->guard_context_loc_class, 3);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->guard_context_risk_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session,
            "guard_context_risk", facts->guard_context_risk, 3);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->guard_context_in_window_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session,
            "guard_context_in_window", facts->guard_context_in_window, 4);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->guard_context_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session, "guard_context",
            facts->guard_context, 6);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }

  return first_rc;
}

/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
insert_guard_eval_facts (WylEngineSession *session, const gint64 row[3],
    const wyl_guard_expr_t *guard, const wyl_decide_req_t *req,
    guard_eval_facts_t *facts)
{
  memset (facts, 0, sizeof (*facts));

  gint64 loc_class_id = 0;
  wyrelog_error_t rc = wyl_engine_session_intern_symbol (session,
          req->guard_loc_class, &loc_class_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 context_id = 0;
  rc = wyl_engine_session_make_guard_context_compound (session,
          req->guard_timestamp, loc_class_id, req->guard_risk, row[2], &context_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  facts->guard_context[0] = context_id;
  facts->guard_context[1] = row[0];
  facts->guard_context[2] = row[2];
  facts->guard_context[3] = req->guard_timestamp;
  facts->guard_context[4] = loc_class_id;
  facts->guard_context[5] = req->guard_risk;

  facts->guard_context_timestamp[0] = row[0];
  facts->guard_context_timestamp[1] = row[2];
  facts->guard_context_timestamp[2] = req->guard_timestamp;

  facts->guard_context_loc_class[0] = row[0];
  facts->guard_context_loc_class[1] = row[2];
  facts->guard_context_loc_class[2] = loc_class_id;

  facts->guard_context_risk[0] = row[0];
  facts->guard_context_risk[1] = row[2];
  facts->guard_context_risk[2] = req->guard_risk;

  const gchar *window = wyl_guard_expr_timestamp_window (guard);
  if (window != NULL) {
    gint64 window_id = 0;
    rc = wyl_engine_session_intern_symbol (session, window, &window_id);
    if (rc != WYRELOG_E_OK)
      return rc;
    facts->guard_context_in_window[0] = row[0];
    facts->guard_context_in_window[1] = row[2];
    facts->guard_context_in_window[2] = req->guard_timestamp;
    facts->guard_context_in_window[3] = window_id;
  }

  facts->context_now[0] = row[0];
  facts->context_now[1] = row[2];
  facts->context_now[2] = context_id;

  facts->eval_guard[0] = row[0];
  facts->eval_guard[1] = row[1];
  facts->eval_guard[2] = row[2];
  facts->eval_guard[3] = context_id;

  rc = wyl_engine_session_insert (session, "guard_context",
          facts->guard_context, 6);
  if (rc != WYRELOG_E_OK)
    return rc;
  facts->guard_context_inserted = TRUE;

  rc = wyl_engine_session_insert (session, "guard_context_timestamp",
          facts->guard_context_timestamp, 3);
  if (rc != WYRELOG_E_OK) {
    (void) remove_guard_eval_facts (session, facts);
    return rc;
  }
  facts->guard_context_timestamp_inserted = TRUE;

  rc = wyl_engine_session_insert (session, "guard_context_loc_class",
          facts->guard_context_loc_class, 3);
  if (rc != WYRELOG_E_OK) {
    (void) remove_guard_eval_facts (session, facts);
    return rc;
  }
  facts->guard_context_loc_class_inserted = TRUE;

  rc = wyl_engine_session_insert (session, "guard_context_risk",
          facts->guard_context_risk, 3);
  if (rc != WYRELOG_E_OK) {
    (void) remove_guard_eval_facts (session, facts);
    return rc;
  }
  facts->guard_context_risk_inserted = TRUE;

  if (window != NULL) {
    rc = wyl_engine_session_insert (session, "guard_context_in_window",
            facts->guard_context_in_window, 4);
    if (rc != WYRELOG_E_OK) {
      (void) remove_guard_eval_facts (session, facts);
      return rc;
    }
    facts->guard_context_in_window_inserted = TRUE;
  }

  rc = wyl_engine_session_insert (session, "context_now", facts->context_now,
          3);
  if (rc != WYRELOG_E_OK) {
    (void) remove_guard_eval_facts (session, facts);
    return rc;
  }
  facts->context_now_inserted = TRUE;

  rc = wyl_engine_session_insert (session, "eval_guard", facts->eval_guard, 4);
  if (rc != WYRELOG_E_OK) {
    (void) remove_guard_eval_facts (session, facts);
    return rc;
  }
  facts->eval_guard_inserted = TRUE;

  return WYRELOG_E_OK;
}

/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
intern_deny_reason_catalog (WylEngineSession *session,
    gint64 names[WYL_DENY_REASON_LAST_], gint64 origins[WYL_DENY_REASON_LAST_])
{
  for (guint i = 0; i < wyl_deny_reason_count (); i++) {
    const gchar *name = wyl_deny_reason_name ((wyl_deny_reason_code_t) i);
    const gchar *origin = wyl_deny_reason_origin ((wyl_deny_reason_code_t) i);
    if (name == NULL || origin == NULL)
      return WYRELOG_E_INTERNAL;

    wyrelog_error_t rc =
        wyl_engine_session_intern_symbol (session, name, &names[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_engine_session_intern_symbol (session, origin, &origins[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
find_deny_reason (WylEngineSession *session, const gint64 row[3],
    const gint64 names[WYL_DENY_REASON_LAST_],
    const gint64 origins[WYL_DENY_REASON_LAST_],
    wyl_deny_reason_code_t *out_code)
{
  if (out_code == NULL)
    return WYRELOG_E_INVALID;
  *out_code = WYL_DENY_REASON_LAST_;

  for (guint i = 0; i < wyl_deny_reason_count (); i++) {
    gint64 reason_row[5] = { row[0], row[1], row[2], names[i], origins[i] };

    gboolean found = FALSE;
    wyrelog_error_t rc = wyl_engine_session_contains (session, "deny_reason",
            reason_row, 5, &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (found) {
      *out_code = (wyl_deny_reason_code_t) i;
      return WYRELOG_E_OK;
    }
  }
  return WYRELOG_E_OK;
}

/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
fill_guard_miss_deny_reason (WylEngineSession *session, const gint64 row[3],
    const gint64 names[WYL_DENY_REASON_LAST_],
    const gint64 origins[WYL_DENY_REASON_LAST_],
    wyl_deny_reason_code_t *out_code)
{
  if (out_code == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc =
      find_deny_reason (session, row, names, origins, out_code);
  if (rc != WYRELOG_E_OK || *out_code != WYL_DENY_REASON_LAST_)
    return rc;

  gboolean base_allowed = FALSE;
  rc = wyl_engine_session_contains (session, "allow_guard_base", row, 3,
          &base_allowed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (base_allowed)
    *out_code = WYL_DENY_REASON_NOT_ARMED;
  return WYRELOG_E_OK;
}

#ifdef WYL_HAS_AUDIT
static void
fail_closed_for_audit (wyl_decide_resp_t *resp)
{
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  wyl_decide_resp_set_deny_tags (resp, "audit_unavailable", "audit_events");
}
#endif

static void
emit_decide_audit (WylHandle *handle, const wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
#ifndef WYL_HAS_AUDIT
  (void) handle;
  (void) req;
  (void) resp;
#else
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, wyl_decide_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, wyl_decide_req_get_action (req));
  wyl_audit_event_set_resource_id (ev, wyl_decide_req_get_resource_id (req));
  wyl_audit_event_set_deny_reason (ev, wyl_decide_resp_get_deny_reason (resp));
  wyl_audit_event_set_deny_origin (ev, wyl_decide_resp_get_deny_origin (resp));
  wyl_audit_event_set_request_id (ev, wyl_decide_req_get_request_id (req));
  wyl_audit_event_set_decision (ev, wyl_decide_resp_get_decision (resp));
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK)
    fail_closed_for_audit (resp);
#endif
}

wyrelog_error_t
wyl_service_decision_authority_new_resolved (WylHandle *handle,
    WylServiceAuthReadLease **inout_lease, const gchar *subject_id,
    const gchar *tenant_id, WylServiceDecisionAuthority **out_authority)
{
  if (out_authority != NULL)
    *out_authority = NULL;
  if (!WYL_IS_HANDLE (handle) || inout_lease == NULL || *inout_lease == NULL
      || subject_id == NULL || tenant_id == NULL || out_authority == NULL)
    return WYRELOG_E_INVALID;
  if (!wyl_policy_service_subject_is_valid (subject_id, strlen (subject_id))
      || !wyl_policy_store_tenant_id_is_valid (tenant_id))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_service_auth_read_lease_validate (*inout_lease, handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_id_t id = WYL_ID_NIL;
  rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar id_string[WYL_ID_STRING_BUF] = { 0 };
  rc = wyl_id_format (&id, id_string, sizeof id_string);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylServiceDecisionAuthority *authority =
      g_new0 (WylServiceDecisionAuthority, 1);
  g_mutex_init (&authority->mutex);
  authority->handle = g_object_ref (handle);
  authority->lease = g_steal_pointer (inout_lease);
  authority->context_id = g_strdup (id_string);
  authority->subject_id = g_strdup (subject_id);
  authority->tenant_id = g_strdup (tenant_id);
  *out_authority = authority;
  return WYRELOG_E_OK;
}

void
wyl_service_decision_authority_free (WylServiceDecisionAuthority *authority)
{
  if (authority == NULL)
    return;
  if (authority->lease != NULL)
    (void) wyl_service_auth_read_lease_release_terminal (&authority->lease);
  g_clear_object (&authority->handle);
  g_clear_pointer (&authority->context_id, g_free);
  g_clear_pointer (&authority->subject_id, g_free);
  g_clear_pointer (&authority->tenant_id, g_free);
  g_mutex_clear (&authority->mutex);
  g_free (authority);
}

wyrelog_error_t
wyl_decide_with_service_authority (WylHandle *handle,
    const wyl_decide_req_t *req, WylServiceDecisionAuthority *authority,
    wyl_decide_resp_t *resp)
{
  if (handle == NULL || req == NULL || authority == NULL || resp == NULL)
    return WYRELOG_E_INVALID;
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  wyl_decide_resp_set_deny_tags (resp, NULL, NULL);
  const gchar *subject = wyl_decide_req_get_subject_id (req);
  const gchar *action = wyl_decide_req_get_action (req);
  const gchar *scope = wyl_decide_req_get_resource_id (req);
  if (subject == NULL || action == NULL || scope == NULL
      || authority->handle != handle)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc =
      wyl_service_auth_read_lease_validate (authority->lease, handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return WYRELOG_E_INVALID;

  g_mutex_lock (&authority->mutex);
  if (authority->consumed) {
    g_mutex_unlock (&authority->mutex);
    return WYRELOG_E_INVALID;
  }
  authority->consumed = TRUE;
  g_mutex_unlock (&authority->mutex);

  gboolean inserted = FALSE;
  gboolean allowed = FALSE;
  if (!g_str_equal (subject, authority->subject_id)) {
    rc = WYRELOG_E_INVALID;
    goto release;
  }
  if (!wyl_handle_engine_pair_is_ready (handle)) {
    rc = WYRELOG_E_INVALID;
    goto release;
  }

  gint64 context_row[3];
  rc = wyl_engine_session_intern_symbol (engine_session, authority->context_id,
          &context_row[0]);
  if (rc != WYRELOG_E_OK)
    goto release;
  rc = wyl_engine_session_intern_symbol (engine_session, authority->subject_id,
          &context_row[1]);
  if (rc != WYRELOG_E_OK)
    goto release;
  rc = wyl_engine_session_intern_symbol (engine_session, authority->tenant_id,
          &context_row[2]);
  if (rc != WYRELOG_E_OK)
    goto release;
  rc = wyl_engine_session_insert (engine_session, "service_request_auth", context_row,
          G_N_ELEMENTS (context_row));
  if (rc != WYRELOG_E_OK)
    goto release;
  inserted = TRUE;

  gint64 decision_row[4] = { context_row[0], context_row[1], 0, 0 };
  rc = wyl_engine_session_intern_symbol (engine_session, action, &decision_row[2]);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  rc = wyl_engine_session_intern_symbol (engine_session, scope, &decision_row[3]);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  rc = wyl_engine_session_contains (engine_session, "service_allow_bool",
          decision_row, G_N_ELEMENTS (decision_row), &allowed);

cleanup:
  if (inserted) {
    wyrelog_error_t cleanup_rc = wyl_engine_session_remove (engine_session,
            "service_request_auth", context_row, G_N_ELEMENTS (context_row));
    if (cleanup_rc != WYRELOG_E_OK) {
      wyl_handle_poison_engine_pair (handle);
      rc = cleanup_rc;
    }
  }

release:
  g_clear_pointer (&engine_session, wyl_engine_session_release);
  {
    wyrelog_error_t release_rc =
        wyl_service_auth_read_lease_release_terminal (&authority->lease);
    if (release_rc != WYRELOG_E_OK)
      rc = release_rc;
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (allowed)
    wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  emit_decide_audit (handle, req, resp);
  return WYRELOG_E_OK;
}

#ifdef WYL_HAS_BREAK_GLASS
typedef struct
{
  gint64 now_row[1];
  gint64 used_row[1];
  gboolean now_inserted;
  gboolean used_inserted;
} break_glass_eval_facts_t;

/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
remove_break_glass_facts (WylEngineSession *session,
    const break_glass_eval_facts_t *facts)
{
  wyrelog_error_t first_rc = WYRELOG_E_OK;
  if (facts->used_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session, "break_glass_used",
            facts->used_row, 1);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  if (facts->now_inserted) {
    wyrelog_error_t rc = wyl_engine_session_remove (session, "now",
            facts->now_row, 1);
    if (first_rc == WYRELOG_E_OK)
      first_rc = rc;
  }
  return first_rc;
}

/*
 * Inserts the host-supplied EDB rows that templates/access/bootstrap.dl
 * declares as runtime-only (now/1 and break_glass_used/1) so the
 * self-disable rule disabled_role("wr.break_glass") can fire when the
 * activation outlives its TTL. The facts are inserted lock-free under
 * the per-decide critical section the caller already owns; on any
 * insertion failure the partially-inserted facts are removed before
 * returning so the engine state is restored to its pre-call shape.
 *
 * The injection happens unconditionally on every break-glass-aware
 * decide so a handle whose break-glass window has expired since the
 * previous decide does not need a separate host-side gate to surface
 * the deny. now/1 is always injected; break_glass_used/1 is injected
 * only when the handle has observed at least one armed decide.
 */
/* WYL_ENGINE_SESSION_REQUIRES: called only by the locked decision session. */
static wyrelog_error_t
insert_break_glass_facts (WylEngineSession *session, WylHandle *handle,
    break_glass_eval_facts_t *facts)
{
  facts->now_row[0] = g_get_real_time () / G_USEC_PER_SEC;
  wyrelog_error_t rc = wyl_engine_session_insert (session, "now",
          facts->now_row, 1);
  if (rc != WYRELOG_E_OK)
    return rc;
  facts->now_inserted = TRUE;

  if (wyl_handle_break_glass_has_been_used (handle)) {
    gint64 activated_at_us = 0;
    if (wyl_handle_break_glass_get_activated_at_us (handle, &activated_at_us)
        == WYRELOG_E_OK) {
      facts->used_row[0] = activated_at_us / G_USEC_PER_SEC;
      rc = wyl_engine_session_insert (session, "break_glass_used",
              facts->used_row, 1);
      if (rc != WYRELOG_E_OK) {
        (void) remove_break_glass_facts (session, facts);
        return rc;
      }
      facts->used_inserted = TRUE;
    }
  }
  return WYRELOG_E_OK;
}
#endif

wyrelog_error_t
wyl_decide (WylHandle *handle, const wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
  if (handle == NULL || req == NULL || resp == NULL)
    return WYRELOG_E_INVALID;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  wyl_decide_resp_set_deny_tags (resp, NULL, NULL);
  if (wyl_decide_req_get_subject_id (req) == NULL
      || wyl_decide_req_get_action (req) == NULL
      || wyl_decide_req_get_resource_id (req) == NULL)
    return WYRELOG_E_INVALID;
  if (!guard_context_is_valid (req))
    return WYRELOG_E_INVALID;
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return WYRELOG_E_INVALID;

  const gchar *deny_reason = NULL;
  const gchar *deny_origin = NULL;
  if (wyl_handle_engine_pair_is_ready (handle)) {
    gint64 row[3];
    wyrelog_error_t rc = wyl_engine_session_intern_symbol (session,
            wyl_decide_req_get_subject_id (req), &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_engine_session_intern_symbol (session, wyl_decide_req_get_action
              (req), &row[1]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_engine_session_intern_symbol (session,
            wyl_decide_req_get_resource_id (req), &row[2]);
    if (rc != WYRELOG_E_OK)
      return rc;
    gint64 reason_names[WYL_DENY_REASON_LAST_] = { 0 };
    gint64 reason_origins[WYL_DENY_REASON_LAST_] = { 0 };
    rc = intern_deny_reason_catalog (session, reason_names, reason_origins);
    if (rc != WYRELOG_E_OK)
      return rc;

    gboolean allowed = FALSE;
    guard_eval_facts_t guard_facts = { 0 };
    wyrelog_error_t cleanup_rc = WYRELOG_E_OK;
#ifdef WYL_HAS_BREAK_GLASS
    break_glass_eval_facts_t break_glass_facts = { 0 };
    gboolean break_glass_active_now = wyl_handle_break_glass_is_active (handle);
#endif

    /*
     * #740 WALL 1: a fully validated live service (svc:) bearer has no
     * store fact principal_state(subject,"authenticated") -- that row is
     * written only for human sessions (insert_policy_store_principal_state
     * in wyl-handle.c). allow_guard_base (templates/access/decision.dl)
     * requires it, so a service token that authenticated and holds a role
     * grant still denies not_authenticated. Inject the fact TRANSIENTLY
     * into the read engine for the duration of THIS decide only, gated on
     * req->service_bearer_authenticated -- a flag the daemon sets ONLY
     * after it has fully validated a live service bearer. Nothing is
     * written to the policy store: no .dl change, no re-sign, no manifest
     * bump. The fact is removed on every exit path via decide_cleanup.
     *
     * The insert is guarded by a was-absent probe so a set-semantics
     * remove can never delete a pre-existing legitimate row. Injection
     * runs BEFORE the guard-arm-rule lookup so a guarded service action
     * with a guard-context miss reports not_armed, not not_authenticated.
     *
     * SCOPE: this clears ONLY the principal_state blocker (Wall 1). Public
     * end-to-end service /decide allow at a FRESH tenant remains gated by
     * Wall 2 (fresh-tenant session_state seeding, #382), out of scope here.
     */
    gint64 pstate_row[2] = { 0, 0 };
    gboolean pstate_injected = FALSE;
    /*
     * #762: perm_state cleanup state, declared alongside pstate_row BEFORE
     * the first goto decide_cleanup so the cleanup block can reference it
     * (clang rejects a goto into the scope of a later declaration).
     */
    gint64 perm_state_row[4] = { 0, 0, 0, 0 };
    gboolean perm_state_injected = FALSE;
    if (wyl_decide_req_get_service_bearer_authenticated (req)) {
      gint64 authenticated_id = 0;
      rc = wyl_engine_session_intern_symbol (session, "authenticated",
              &authenticated_id);
      if (rc != WYRELOG_E_OK)
        return rc;
      pstate_row[0] = row[0];
      pstate_row[1] = authenticated_id;
      gboolean present = FALSE;
      rc = wyl_engine_session_contains (session, "principal_state", pstate_row,
              2, &present);
      if (rc != WYRELOG_E_OK)
        return rc;
      if (!present) {
        rc = wyl_engine_session_insert (session, "principal_state", pstate_row,
                2);
        if (rc != WYRELOG_E_OK)
          return rc;
        pstate_injected = TRUE;
      }
    }

    /*
     * #762 WALL 3: a granted svc: principal for an unguarded APPROVED
     * data-plane permission still can't authorize. armed/3 rule-1
     * (templates/access/fsm/permission_scope.dl) needs a durable
     * perm_state(U,P,S,"armed") EDB row, but the store hard-rejects
     * perm_state for svc: subjects, so the row is never written and the
     * decide denies not_armed. Mirror the #740 principal_state injection:
     * insert the armed perm_state TRANSIENTLY into the read engine for
     * THIS decide only, so armed derives and (with the #740
     * principal_state + #744 session_state) allow_guard_base allows.
     * Nothing is written to the policy store: no .dl change, no re-sign.
     * The fact is removed on every exit path via decide_cleanup.
     *
     * Triple gate -- inject ONLY when ALL hold (any false -> skip, deny
     * path unchanged); the three cheap gates run before the insert so
     * nothing is written when any fails:
     *   1. the daemon-set service-bearer-authenticated flag (#740, reused
     *      -- no new flag, no daemon change);
     *   2. has_permission(U,P,S) already holds -- arm a real grant only;
     *   3. the action is one of the approved data-plane permissions. The
     *      authoritative source is the C-list the .dl mirrors
     *      (approved_data_plane_permissions[] in policy/store.c), read via
     *      the parameterless accessors below -- NOT a snapshot probe.
     *      Control-plane actions are never in this closed set, so a svc:
     *      principal can never arm a control-plane perm.
     *
     * Inject the RAW "perm_state" EDB only (arity 4) -- the relation
     * armed/3 rule-1 reads. Do NOT inject "perm_state_replayed": that is
     * the public durable replay-observation path, and a transient arming
     * must never appear there (an observability lie). NOTE the
     * observed-vs-raw asymmetry: the was-absent probe below reads the
     * snapshot mirror perm_state_observed (wyl_engine_session_contains
     * remaps "perm_state"), which derives from perm_state_replayed, NOT
     * the raw EDB rule-1 reads. It is safe here only because a svc:
     * subject has neither a raw nor a replayed perm_state row (the store
     * rejects durable svc: perm_state), so the mirror faithfully reports
     * the raw EDB is absent. Do NOT "fix" this by also injecting
     * perm_state_replayed. The was-absent probe is kept for
     * defense-in-depth so a set-semantics remove can never delete a
     * pre-existing legitimate row, mirroring #740.
     */
    if (wyl_decide_req_get_service_bearer_authenticated (req)) {
      gboolean has_perm = FALSE;
      rc = wyl_engine_session_contains (session, "has_permission", row, 3,
              &has_perm);
      if (rc != WYRELOG_E_OK) {
        cleanup_rc = rc;
        goto decide_cleanup;
      }
      gboolean data_plane = FALSE;
      const gchar *action_id = wyl_decide_req_get_action (req);
      for (gsize i = 0;
          i < wyl_policy_store_approved_data_plane_permission_count (); i++) {
        if (g_strcmp0 (wyl_policy_store_approved_data_plane_permission_id (i),
            action_id) == 0) {
          data_plane = TRUE;
          break;
        }
      }
      if (has_perm && data_plane) {
        gint64 armed_id = 0;
        rc = wyl_engine_session_intern_symbol (session, "armed", &armed_id);
        if (rc != WYRELOG_E_OK) {
          cleanup_rc = rc;
          goto decide_cleanup;
        }
        perm_state_row[0] = row[0];
        perm_state_row[1] = row[1];
        perm_state_row[2] = row[2];
        perm_state_row[3] = armed_id;
        gboolean present = FALSE;
        rc = wyl_engine_session_contains (session, "perm_state", perm_state_row,
                4, &present);
        if (rc != WYRELOG_E_OK) {
          cleanup_rc = rc;
          goto decide_cleanup;
        }
        if (!present) {
          rc = wyl_engine_session_insert (session, "perm_state", perm_state_row,
                  4);
          if (rc != WYRELOG_E_OK) {
            cleanup_rc = rc;
            goto decide_cleanup;
          }
          perm_state_injected = TRUE;
        }
      }
    }

    const wyl_guard_expr_t *guard =
        wyl_perm_arm_rule_lookup (wyl_decide_req_get_action (req));
    if (guard != NULL) {
      if (!guard_is_satisfied (guard, req)) {
        wyl_deny_reason_code_t code = WYL_DENY_REASON_LAST_;
        rc = fill_guard_miss_deny_reason (session, row, reason_names,
                reason_origins, &code);
        if (rc != WYRELOG_E_OK) {
          cleanup_rc = rc;
          goto decide_cleanup;
        }
        deny_reason = wyl_deny_reason_name (code);
        deny_origin = wyl_deny_reason_origin (code);
        goto decide_cleanup;
      }
      rc = insert_guard_eval_facts (session, row, guard, req, &guard_facts);
      if (rc != WYRELOG_E_OK) {
        cleanup_rc = rc;
        goto decide_cleanup;
      }
    }
#ifdef WYL_HAS_BREAK_GLASS
    if (break_glass_active_now) {
      rc = insert_break_glass_facts (session, handle, &break_glass_facts);
      if (rc != WYRELOG_E_OK) {
        cleanup_rc = rc;
        goto decide_cleanup;
      }
    }
#endif

    rc = wyl_engine_session_decide (session, row, &allowed);
    if (rc != WYRELOG_E_OK) {
      cleanup_rc = rc;
      goto decide_cleanup;
    }
    if (allowed) {
      wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
    } else {
      wyl_deny_reason_code_t code = WYL_DENY_REASON_LAST_;
      rc = find_deny_reason (session, row, reason_names, reason_origins, &code);
      if (rc != WYRELOG_E_OK) {
        cleanup_rc = rc;
        goto decide_cleanup;
      }
      deny_reason = wyl_deny_reason_name (code);
      deny_origin = wyl_deny_reason_origin (code);
    }

    /*
     * Single cleanup boundary (#740): EVERY exit path in the read-engine
     * block after the transient inject above reaches this label, so the
     * guard-eval facts, break-glass facts, and the transient
     * principal_state fact are removed exactly once and never leak into a
     * subsequent decide (a leaked principal_state row would be a privilege
     * escalation across requests). cleanup_rc carries any error that must
     * be returned WITHOUT emitting an audit row; a clean fall-through
     * continues to the audit emit below.
     */
decide_cleanup:
    {
      wyrelog_error_t guard_remove_rc = WYRELOG_E_OK;
      wyrelog_error_t pstate_remove_rc = WYRELOG_E_OK;
      wyrelog_error_t perm_state_remove_rc = WYRELOG_E_OK;
      if (guard_facts.eval_guard_inserted)
        guard_remove_rc = remove_guard_eval_facts (session, &guard_facts);
#ifdef WYL_HAS_BREAK_GLASS
      (void) remove_break_glass_facts (session, &break_glass_facts);
#endif
      if (pstate_injected)
        pstate_remove_rc =
            wyl_engine_session_remove (session, "principal_state", pstate_row,
                2);
      if (perm_state_injected)
        perm_state_remove_rc = wyl_engine_session_remove (session, "perm_state",
                perm_state_row, 4);
      /*
       * All removes run BEFORE any failure-return so nothing leaks, then
       * the fail-closed checks fire in precedence order. The transient
       * principal_state removal is fail-closed symmetrically with the
       * guard-eval cleanup: if the row cannot be removed it would persist
       * on the read engine and pass the auth gate on a later decide for
       * this subject -- the exact cross-request escalation this change
       * guards against -- so surface it as a DENY and propagate the error.
       */
      if (cleanup_rc != WYRELOG_E_OK)
        return cleanup_rc;
      if (guard_remove_rc != WYRELOG_E_OK) {
        wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
        wyl_decide_resp_set_deny_tags (resp, "guard_cleanup_failed",
            "eval_guard");
        return guard_remove_rc;
      }
      if (pstate_remove_rc != WYRELOG_E_OK) {
        wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
        wyl_decide_resp_set_deny_tags (resp, "principal_state_cleanup_failed",
            "principal_state");
        return pstate_remove_rc;
      }
      /*
       * #762: the transient perm_state removal is fail-closed
       * symmetrically with the principal_state cleanup. A row that cannot
       * be removed would persist on the read engine and arm this subject
       * on a later decide -- a cross-request escalation -- so surface it
       * as a DENY and propagate the error. Precedence after cleanup_rc:
       * guard -> principal_state -> perm_state.
       */
      if (perm_state_remove_rc != WYRELOG_E_OK) {
        wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
        wyl_decide_resp_set_deny_tags (resp, "perm_state_cleanup_failed",
            "perm_state");
        return perm_state_remove_rc;
      }
    }
  }
  wyl_decide_resp_set_deny_tags (resp, deny_reason, deny_origin);
#ifndef WYL_HAS_AUDIT
  (void) deny_reason;
  (void) deny_origin;
#endif
  emit_decide_audit (handle, req, resp);

#ifdef WYL_HAS_BREAK_GLASS
  /*
   * Mark the activation observed AFTER the audit row has committed
   * so a fail-closed audit emit does not falsely register a usage
   * the operator's incident docket cannot see. The mark is a no-op
   * when the handle is not currently in an activation window.
   */
  wyl_handle_break_glass_mark_used (handle);
#endif

  return WYRELOG_E_OK;
}
