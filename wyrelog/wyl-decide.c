/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _wyl_decide_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
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

wyrelog_error_t
wyl_decide (WylHandle *handle, const wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
  if (handle == NULL || req == NULL || resp == NULL)
    return WYRELOG_E_INVALID;

  /* The policy decision point is not yet wired to the principal /
   * session FSMs or to a configured allow-list, so every decide
   * call returns DENY. This keeps the public contract fail-closed
   * by default; a future commit will replace this with the actual
   * Datalog evaluation. */
  wyl_decide_resp_set_decision (resp, WYL_DECISION_DENY);

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
