/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

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
  g_free (resp);
}

void
wyl_decide_resp_set_decision (wyl_decide_resp_t *resp, wyl_decision_t decision)
{
  g_return_if_fail (resp != NULL);
  resp->decision = decision;
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

static wyrelog_error_t
guard_base_decide_if_satisfied (WylHandle *handle,
    const wyl_guard_expr_t *guard, const wyl_decide_req_t *req,
    const gint64 row[3], gboolean *out_allowed)
{
  *out_allowed = FALSE;

  if (guard == NULL || !req->has_guard_context)
    return WYRELOG_E_OK;

  wyl_scope_t scope = {
    .user = wyl_decide_req_get_subject_id (req),
    .timestamp = req->guard_timestamp,
    .loc_class = req->guard_loc_class,
    .risk = req->guard_risk,
  };
  if (!wyl_eval_guard (guard, &scope))
    return WYRELOG_E_OK;

  return wyl_handle_engine_contains (handle, "allow_guard_base", row, 3,
      out_allowed);
}

wyrelog_error_t
wyl_decide (WylHandle *handle, const wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
  if (handle == NULL || req == NULL || resp == NULL)
    return WYRELOG_E_INVALID;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);
  if (wyl_decide_req_get_subject_id (req) == NULL
      || wyl_decide_req_get_action (req) == NULL
      || wyl_decide_req_get_resource_id (req) == NULL)
    return WYRELOG_E_INVALID;

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

    gboolean allowed = FALSE;
    const wyl_guard_expr_t *guard =
        wyl_perm_arm_rule_lookup (wyl_decide_req_get_action (req));
    if (guard != NULL) {
      rc = guard_base_decide_if_satisfied (handle, guard, req, row, &allowed);
      if (rc != WYRELOG_E_OK)
        return rc;
    } else {
      rc = wyl_handle_engine_decide (handle, row, &allowed);
      if (rc != WYRELOG_E_OK)
        return rc;
    }
    if (allowed)
      wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  }
#ifdef WYL_HAS_AUDIT
  /* Mirror the decision into the audit log so every decide call
   * leaves a row regardless of whether downstream callers also
   * emit explicitly. Failures from emit are intentionally not
   * propagated: a decision was made and reported; the audit-side
   * write is best-effort relative to the caller's contract. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, wyl_decide_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, wyl_decide_req_get_action (req));
  wyl_audit_event_set_resource_id (ev, wyl_decide_req_get_resource_id (req));
  wyl_audit_event_set_decision (ev, wyl_decide_resp_get_decision (resp));
  (void) wyl_audit_emit (handle, ev);
#endif

  return WYRELOG_E_OK;
}
