/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _wyl_login_req
{
  gchar *username;
};

struct _wyl_grant_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
};

struct _wyl_revoke_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
};

wyl_login_req_t *
wyl_login_req_new (void)
{
  return g_new0 (wyl_login_req_t, 1);
}

void
wyl_login_req_free (wyl_login_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->username);
  g_free (req);
}

void
wyl_login_req_set_username (wyl_login_req_t *req, const gchar *username)
{
  g_return_if_fail (req != NULL);
  g_free (req->username);
  req->username = g_strdup (username);
}

const gchar *
wyl_login_req_get_username (const wyl_login_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->username;
}

wyl_grant_req_t *
wyl_grant_req_new (void)
{
  return g_new0 (wyl_grant_req_t, 1);
}

void
wyl_grant_req_free (wyl_grant_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->action);
  g_free (req->resource_id);
  g_free (req);
}

void
wyl_grant_req_set_subject_id (wyl_grant_req_t *req, const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_grant_req_get_subject_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_grant_req_set_action (wyl_grant_req_t *req, const gchar *action)
{
  g_return_if_fail (req != NULL);
  g_free (req->action);
  req->action = g_strdup (action);
}

const gchar *
wyl_grant_req_get_action (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->action;
}

void
wyl_grant_req_set_resource_id (wyl_grant_req_t *req, const gchar *resource_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->resource_id);
  req->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_grant_req_get_resource_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->resource_id;
}

wyl_revoke_req_t *
wyl_revoke_req_new (void)
{
  return g_new0 (wyl_revoke_req_t, 1);
}

void
wyl_revoke_req_free (wyl_revoke_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->action);
  g_free (req->resource_id);
  g_free (req);
}

void
wyl_revoke_req_set_subject_id (wyl_revoke_req_t *req, const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_revoke_req_get_subject_id (const wyl_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_revoke_req_set_action (wyl_revoke_req_t *req, const gchar *action)
{
  g_return_if_fail (req != NULL);
  g_free (req->action);
  req->action = g_strdup (action);
}

const gchar *
wyl_revoke_req_get_action (const wyl_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->action;
}

void
wyl_revoke_req_set_resource_id (wyl_revoke_req_t *req, const gchar *resource_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->resource_id);
  req->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_revoke_req_get_resource_id (const wyl_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->resource_id;
}

wyrelog_error_t
wyl_perm_grant (WylHandle *handle, const wyl_grant_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  /* Record the grant attempt in the audit log so admin operations
   * are observable even before the durable permission store is
   * wired. WYL_DECISION_ALLOW marks the operation accepted at the
   * API surface; rejection logic lands when the policy decision
   * point gets a real backing store. Audit-emit failures are not
   * propagated; the operation has been accepted and that should
   * not be undone by a transient log write hiccup. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, wyl_grant_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, wyl_grant_req_get_action (req));
  wyl_audit_event_set_resource_id (ev, wyl_grant_req_get_resource_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (handle, ev);
#endif

  /* Real persistence into a durable permission store lands in a
   * follow-up; v0 returns E_OK after validating the request and
   * recording it in the audit log. */
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_perm_revoke (WylHandle *handle, const wyl_revoke_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  /* Mirror revoke in audit alongside grant (see wyl_perm_grant for
   * rationale). The decision field still reads ALLOW because the
   * admin operation itself was accepted; the audit row's action
   * column carries the "revoke" semantics. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, wyl_revoke_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, wyl_revoke_req_get_action (req));
  wyl_audit_event_set_resource_id (ev, wyl_revoke_req_get_resource_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (handle, ev);
#endif

  return WYRELOG_E_OK;
}
