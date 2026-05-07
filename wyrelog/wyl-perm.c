/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "audit/event-private.h"
#include "wyl-handle-private.h"
#include "wyl-permission-scope-private.h"

struct _wyl_login_req
{
  gchar *username;
  gchar *tenant;
  gchar *request_id;
  gboolean skip_mfa;
};

struct _wyl_grant_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
  gchar *actor_id;
  gchar *request_id;
};

struct _wyl_revoke_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
  gchar *actor_id;
  gchar *request_id;
};

struct _wyl_role_grant_req
{
  gchar *subject_id;
  gchar *role_id;
  gchar *scope;
  gchar *actor_id;
  gchar *request_id;
};

struct _wyl_role_revoke_req
{
  gchar *subject_id;
  gchar *role_id;
  gchar *scope;
  gchar *actor_id;
  gchar *request_id;
};

static wyrelog_error_t finish_policy_mutation (WylHandle * handle,
    const WylAuditEvent * audit_event);

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
  g_free (req->tenant);
  g_free (req->request_id);
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

void
wyl_login_req_set_tenant (wyl_login_req_t *req, const gchar *tenant)
{
  g_return_if_fail (req != NULL);
  g_free (req->tenant);
  req->tenant = g_strdup (tenant);
}

const gchar *
wyl_login_req_get_tenant (const wyl_login_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->tenant;
}

void
wyl_login_req_set_skip_mfa (wyl_login_req_t *req, gboolean skip_mfa)
{
  g_return_if_fail (req != NULL);
  req->skip_mfa = skip_mfa;
}

gboolean
wyl_login_req_get_skip_mfa (const wyl_login_req_t *req)
{
  g_return_val_if_fail (req != NULL, FALSE);
  return req->skip_mfa;
}

void
wyl_login_req_set_request_id (wyl_login_req_t *req, const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_login_req_get_request_id (const wyl_login_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
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
  g_free (req->actor_id);
  g_free (req->request_id);
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

void
wyl_grant_req_set_actor_id (wyl_grant_req_t *req, const gchar *actor_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->actor_id);
  req->actor_id = g_strdup (actor_id);
}

const gchar *
wyl_grant_req_get_actor_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->actor_id;
}

void
wyl_grant_req_set_request_id (wyl_grant_req_t *req, const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_grant_req_get_request_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
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
  g_free (req->actor_id);
  g_free (req->request_id);
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

void
wyl_revoke_req_set_actor_id (wyl_revoke_req_t *req, const gchar *actor_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->actor_id);
  req->actor_id = g_strdup (actor_id);
}

const gchar *
wyl_revoke_req_get_actor_id (const wyl_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->actor_id;
}

void
wyl_revoke_req_set_request_id (wyl_revoke_req_t *req, const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_revoke_req_get_request_id (const wyl_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
}

wyl_role_grant_req_t *
wyl_role_grant_req_new (void)
{
  return g_new0 (wyl_role_grant_req_t, 1);
}

void
wyl_role_grant_req_free (wyl_role_grant_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->role_id);
  g_free (req->scope);
  g_free (req->actor_id);
  g_free (req->request_id);
  g_free (req);
}

void
wyl_role_grant_req_set_subject_id (wyl_role_grant_req_t *req,
    const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_role_grant_req_get_subject_id (const wyl_role_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_role_grant_req_set_role_id (wyl_role_grant_req_t *req, const gchar *role_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->role_id);
  req->role_id = g_strdup (role_id);
}

const gchar *
wyl_role_grant_req_get_role_id (const wyl_role_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->role_id;
}

void
wyl_role_grant_req_set_scope (wyl_role_grant_req_t *req, const gchar *scope)
{
  g_return_if_fail (req != NULL);
  g_free (req->scope);
  req->scope = g_strdup (scope);
}

const gchar *
wyl_role_grant_req_get_scope (const wyl_role_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->scope;
}

void
wyl_role_grant_req_set_actor_id (wyl_role_grant_req_t *req,
    const gchar *actor_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->actor_id);
  req->actor_id = g_strdup (actor_id);
}

const gchar *
wyl_role_grant_req_get_actor_id (const wyl_role_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->actor_id;
}

void
wyl_role_grant_req_set_request_id (wyl_role_grant_req_t *req,
    const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_role_grant_req_get_request_id (const wyl_role_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
}

wyl_role_revoke_req_t *
wyl_role_revoke_req_new (void)
{
  return g_new0 (wyl_role_revoke_req_t, 1);
}

void
wyl_role_revoke_req_free (wyl_role_revoke_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->role_id);
  g_free (req->scope);
  g_free (req->actor_id);
  g_free (req->request_id);
  g_free (req);
}

void
wyl_role_revoke_req_set_subject_id (wyl_role_revoke_req_t *req,
    const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_role_revoke_req_get_subject_id (const wyl_role_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_role_revoke_req_set_role_id (wyl_role_revoke_req_t *req,
    const gchar *role_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->role_id);
  req->role_id = g_strdup (role_id);
}

const gchar *
wyl_role_revoke_req_get_role_id (const wyl_role_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->role_id;
}

void
wyl_role_revoke_req_set_scope (wyl_role_revoke_req_t *req, const gchar *scope)
{
  g_return_if_fail (req != NULL);
  g_free (req->scope);
  req->scope = g_strdup (scope);
}

const gchar *
wyl_role_revoke_req_get_scope (const wyl_role_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->scope;
}

void
wyl_role_revoke_req_set_actor_id (wyl_role_revoke_req_t *req,
    const gchar *actor_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->actor_id);
  req->actor_id = g_strdup (actor_id);
}

const gchar *
wyl_role_revoke_req_get_actor_id (const wyl_role_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->actor_id;
}

void
wyl_role_revoke_req_set_request_id (wyl_role_revoke_req_t *req,
    const gchar *request_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->request_id);
  req->request_id = g_strdup (request_id);
}

const gchar *
wyl_role_revoke_req_get_request_id (const wyl_role_revoke_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->request_id;
}

static wyrelog_error_t
update_direct_permission_store (WylHandle *handle, const gchar *subject_id,
    const gchar *action, const gchar *resource_id, gboolean insert,
    const WylAuditEvent *audit_event)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INVALID;

  if (audit_event == NULL) {
    return wyl_policy_store_apply_direct_permission_mutation (store,
        subject_id, action, resource_id, insert);
  }

  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (audit_event);
  if (audit_id == NULL)
    return WYRELOG_E_INTERNAL;

  return wyl_policy_store_apply_direct_permission_mutation_with_audit (store,
      subject_id, action, resource_id, insert, audit_id,
      wyl_audit_event_get_created_at_us (audit_event),
      wyl_audit_event_get_subject_id (audit_event),
      wyl_audit_event_get_action (audit_event),
      wyl_audit_event_get_resource_id (audit_event),
      wyl_audit_event_get_deny_reason (audit_event),
      wyl_audit_event_get_deny_origin (audit_event),
      wyl_audit_event_get_request_id (audit_event),
      wyl_audit_event_get_decision (audit_event));
}

static wyrelog_error_t
update_role_membership_store (WylHandle *handle, const gchar *subject_id,
    const gchar *role_id, const gchar *scope, gboolean insert,
    const WylAuditEvent *audit_event)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INVALID;

  if (audit_event == NULL) {
    return wyl_policy_store_apply_role_membership_mutation (store, subject_id,
        role_id, scope, insert);
  }

  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (audit_event);
  if (audit_id == NULL)
    return WYRELOG_E_INTERNAL;

  return wyl_policy_store_apply_role_membership_mutation_with_audit (store,
      subject_id, role_id, scope, insert, audit_id,
      wyl_audit_event_get_created_at_us (audit_event),
      wyl_audit_event_get_subject_id (audit_event),
      wyl_audit_event_get_action (audit_event),
      wyl_audit_event_get_resource_id (audit_event),
      wyl_audit_event_get_deny_reason (audit_event),
      wyl_audit_event_get_deny_origin (audit_event),
      wyl_audit_event_get_request_id (audit_event),
      wyl_audit_event_get_decision (audit_event));
}

wyrelog_error_t
wyl_handle_apply_permission_state_transition (WylHandle *handle,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, const WylAuditEvent *audit_event, gint64 *out_event_id)
{
  if (handle == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  if (subject_id == NULL || perm_id == NULL || scope == NULL || event == NULL)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = WYRELOG_E_OK;
  if (audit_event == NULL) {
    rc = wyl_policy_store_apply_permission_state_transition (store,
        subject_id, perm_id, scope, event, out_event_id);
  } else {
    g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (audit_event);
    if (audit_id == NULL)
      return WYRELOG_E_INTERNAL;
    rc = wyl_policy_store_apply_permission_state_transition_with_audit (store,
        subject_id, perm_id, scope, event, out_event_id, audit_id,
        wyl_audit_event_get_created_at_us (audit_event),
        wyl_audit_event_get_subject_id (audit_event),
        wyl_audit_event_get_action (audit_event),
        wyl_audit_event_get_resource_id (audit_event),
        wyl_audit_event_get_deny_reason (audit_event),
        wyl_audit_event_get_deny_origin (audit_event),
        wyl_audit_event_get_request_id (audit_event),
        wyl_audit_event_get_decision (audit_event));
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_policy_mutation (handle, audit_event);
}

static wyrelog_error_t
reload_policy_snapshot (WylHandle *handle)
{
  if (wyl_handle_get_read_engine (handle) == NULL)
    return WYRELOG_E_OK;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
finish_policy_mutation (WylHandle *handle, const WylAuditEvent *audit_event)
{
  wyrelog_error_t rc = reload_policy_snapshot (handle);

#ifdef WYL_HAS_AUDIT
  if (audit_event != NULL)
    (void) wyl_audit_mirror_event (handle, audit_event);
#else
  (void) audit_event;
#endif

  return rc;
}

wyrelog_error_t
wyl_perm_grant (WylHandle *handle, const wyl_grant_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_grant_req_get_subject_id (req) == NULL
      || wyl_grant_req_get_action (req) == NULL
      || wyl_grant_req_get_resource_id (req) == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_handle_get_read_engine (handle) != NULL
      && wyl_perm_arm_rule_lookup (wyl_grant_req_get_action (req)) != NULL)
    return WYRELOG_E_POLICY;

#ifdef WYL_HAS_AUDIT
  /* Record the accepted admin operation in the durable audit store as
   * part of the policy mutation savepoint. The action column carries
   * operation semantics while deny_origin retains the permission name. */
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev,
      wyl_grant_req_get_actor_id (req) != NULL
      ? wyl_grant_req_get_actor_id (req)
      : wyl_grant_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, "permission_grant");
  wyl_audit_event_set_resource_id (ev, wyl_grant_req_get_resource_id (req));
  wyl_audit_event_set_deny_origin (ev, wyl_grant_req_get_action (req));
  wyl_audit_event_set_request_id (ev, wyl_grant_req_get_request_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
#else
  WylAuditEvent *ev = NULL;
#endif

  wyrelog_error_t rc = update_direct_permission_store (handle,
      wyl_grant_req_get_subject_id (req), wyl_grant_req_get_action (req),
      wyl_grant_req_get_resource_id (req), TRUE, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_policy_mutation (handle, ev);
}

wyrelog_error_t
wyl_perm_revoke (WylHandle *handle, const wyl_revoke_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_revoke_req_get_subject_id (req) == NULL
      || wyl_revoke_req_get_action (req) == NULL
      || wyl_revoke_req_get_resource_id (req) == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev,
      wyl_revoke_req_get_actor_id (req) != NULL
      ? wyl_revoke_req_get_actor_id (req)
      : wyl_revoke_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, "permission_revoke");
  wyl_audit_event_set_resource_id (ev, wyl_revoke_req_get_resource_id (req));
  wyl_audit_event_set_deny_origin (ev, wyl_revoke_req_get_action (req));
  wyl_audit_event_set_request_id (ev, wyl_revoke_req_get_request_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
#else
  WylAuditEvent *ev = NULL;
#endif

  wyrelog_error_t rc = update_direct_permission_store (handle,
      wyl_revoke_req_get_subject_id (req), wyl_revoke_req_get_action (req),
      wyl_revoke_req_get_resource_id (req), FALSE, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_policy_mutation (handle, ev);
}

wyrelog_error_t
wyl_role_grant (WylHandle *handle, const wyl_role_grant_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_role_grant_req_get_subject_id (req) == NULL
      || wyl_role_grant_req_get_role_id (req) == NULL
      || wyl_role_grant_req_get_scope (req) == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev,
      wyl_role_grant_req_get_actor_id (req) != NULL
      ? wyl_role_grant_req_get_actor_id (req)
      : wyl_role_grant_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, "role_grant");
  wyl_audit_event_set_resource_id (ev, wyl_role_grant_req_get_scope (req));
  wyl_audit_event_set_deny_origin (ev, wyl_role_grant_req_get_role_id (req));
  wyl_audit_event_set_request_id (ev, wyl_role_grant_req_get_request_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
#else
  WylAuditEvent *ev = NULL;
#endif

  wyrelog_error_t rc = update_role_membership_store (handle,
      wyl_role_grant_req_get_subject_id (req),
      wyl_role_grant_req_get_role_id (req), wyl_role_grant_req_get_scope (req),
      TRUE, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_policy_mutation (handle, ev);
}

wyrelog_error_t
wyl_role_revoke (WylHandle *handle, const wyl_role_revoke_req_t *req)
{
  if (handle == NULL || req == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_role_revoke_req_get_subject_id (req) == NULL
      || wyl_role_revoke_req_get_role_id (req) == NULL
      || wyl_role_revoke_req_get_scope (req) == NULL)
    return WYRELOG_E_INVALID;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev,
      wyl_role_revoke_req_get_actor_id (req) != NULL
      ? wyl_role_revoke_req_get_actor_id (req)
      : wyl_role_revoke_req_get_subject_id (req));
  wyl_audit_event_set_action (ev, "role_revoke");
  wyl_audit_event_set_resource_id (ev, wyl_role_revoke_req_get_scope (req));
  wyl_audit_event_set_deny_origin (ev, wyl_role_revoke_req_get_role_id (req));
  wyl_audit_event_set_request_id (ev, wyl_role_revoke_req_get_request_id (req));
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
#else
  WylAuditEvent *ev = NULL;
#endif

  wyrelog_error_t rc = update_role_membership_store (handle,
      wyl_role_revoke_req_get_subject_id (req),
      wyl_role_revoke_req_get_role_id (req),
      wyl_role_revoke_req_get_scope (req), FALSE, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
  return finish_policy_mutation (handle, ev);
}
