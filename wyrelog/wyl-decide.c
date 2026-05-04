/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "access/decision-private.h"
#include "wyl-handle-private.h"
#include "wyl-permission-scope-private.h"

struct _wyl_decide_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
  gboolean has_guard_context;
  gint64 guard_timestamp;
  gchar *guard_loc_class;
  gint64 guard_risk;
};

struct _wyl_decide_resp
{
  wyl_decision_t decision;
  gchar *deny_reason;
  gchar *deny_origin;
};

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
guard_is_satisfied (const wyl_guard_expr_t *guard, const wyl_decide_req_t *req)
{
  if (guard == NULL || !req->has_guard_context)
    return FALSE;

  wyl_scope_t scope = {
    .user = wyl_decide_req_get_subject_id (req),
    .timestamp = req->guard_timestamp,
    .loc_class = req->guard_loc_class,
    .risk = req->guard_risk,
  };
  return wyl_eval_guard (guard, &scope);
}

static wyrelog_error_t
insert_guard_eval_facts (WylHandle *handle, const gint64 row[3])
{
  gint64 context_row[2] = { row[0], row[2] };
  wyrelog_error_t rc =
      wyl_handle_engine_insert (handle, "context_now", context_row, 2);
  if (rc != WYRELOG_E_OK)
    return rc;

  return wyl_handle_engine_insert (handle, "eval_guard", row, 3);
}

static wyrelog_error_t
intern_deny_reason_catalog (WylHandle *handle,
    gint64 names[WYL_DENY_REASON_LAST_], gint64 origins[WYL_DENY_REASON_LAST_])
{
  for (guint i = 0; i < wyl_deny_reason_count (); i++) {
    const gchar *name = wyl_deny_reason_name ((wyl_deny_reason_code_t) i);
    const gchar *origin = wyl_deny_reason_origin ((wyl_deny_reason_code_t) i);
    if (name == NULL || origin == NULL)
      return WYRELOG_E_INTERNAL;

    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (handle, name, &names[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (handle, origin, &origins[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
find_deny_reason (WylHandle *handle, const gint64 row[3],
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
    wyrelog_error_t rc = wyl_handle_engine_contains (handle, "deny_reason",
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

#ifdef WYL_HAS_AUDIT
static void
fail_closed_for_audit (wyl_decide_resp_t *resp)
{
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  wyl_decide_resp_set_deny_tags (resp, "audit_unavailable", "audit_events");
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

  const gchar *deny_reason = NULL;
  const gchar *deny_origin = NULL;
  if (wyl_handle_get_read_engine (handle) != NULL) {
    gint64 row[3];
    wyrelog_error_t rc = wyl_handle_intern_engine_symbol (handle,
        wyl_decide_req_get_subject_id (req), &row[0]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (handle, wyl_decide_req_get_action
        (req), &row[1]);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_handle_intern_engine_symbol (handle,
        wyl_decide_req_get_resource_id (req), &row[2]);
    if (rc != WYRELOG_E_OK)
      return rc;
    gint64 reason_names[WYL_DENY_REASON_LAST_] = { 0 };
    gint64 reason_origins[WYL_DENY_REASON_LAST_] = { 0 };
    rc = intern_deny_reason_catalog (handle, reason_names, reason_origins);
    if (rc != WYRELOG_E_OK)
      return rc;

    gboolean allowed = FALSE;
    const wyl_guard_expr_t *guard =
        wyl_perm_arm_rule_lookup (wyl_decide_req_get_action (req));
    if (guard != NULL) {
      if (!guard_is_satisfied (guard, req)) {
        wyl_deny_reason_code_t code = WYL_DENY_REASON_LAST_;
        rc = find_deny_reason (handle, row, reason_names, reason_origins,
            &code);
        if (rc != WYRELOG_E_OK)
          return rc;
        deny_reason = wyl_deny_reason_name (code);
        deny_origin = wyl_deny_reason_origin (code);
        wyl_decide_resp_set_deny_tags (resp, deny_reason, deny_origin);
        goto emit_audit;
      }
      rc = insert_guard_eval_facts (handle, row);
      if (rc != WYRELOG_E_OK)
        return rc;
    }

    rc = wyl_handle_engine_decide (handle, row, &allowed);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (allowed) {
      wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
    } else {
      wyl_deny_reason_code_t code = WYL_DENY_REASON_LAST_;
      rc = find_deny_reason (handle, row, reason_names, reason_origins, &code);
      if (rc != WYRELOG_E_OK)
        return rc;
      deny_reason = wyl_deny_reason_name (code);
      deny_origin = wyl_deny_reason_origin (code);
    }
  }
  wyl_decide_resp_set_deny_tags (resp, deny_reason, deny_origin);
emit_audit:
  ;
#ifndef WYL_HAS_AUDIT
  (void) deny_reason;
  (void) deny_origin;
#endif
#ifdef WYL_HAS_AUDIT
  /* Mirror the decision into the audit log so every decide call
   * leaves a row regardless of whether downstream callers also
   * emit explicitly. If the append fails, close the response back
   * to DENY so the caller never observes an unaudited ALLOW. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, wyl_decide_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, wyl_decide_req_get_action (req));
  wyl_audit_event_set_resource_id (ev, wyl_decide_req_get_resource_id (req));
  wyl_audit_event_set_deny_reason (ev, deny_reason);
  wyl_audit_event_set_deny_origin (ev, deny_origin);
  wyl_audit_event_set_decision (ev, wyl_decide_resp_get_decision (resp));
  if (wyl_audit_emit (handle, ev) != WYRELOG_E_OK)
    fail_closed_for_audit (resp);
#endif

  return WYRELOG_E_OK;
}
