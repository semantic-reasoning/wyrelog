/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "audit/event-private.h"
#include "wyl-fsm-permission-scope-private.h"
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

typedef struct
{
  WylHandle *handle;
  const gchar *a;
  const gchar *b;
  const gchar *c;
  gboolean insert;
  const WylAuditEvent *audit_event;
} WylPermissionPublication;

typedef struct
{
  WylPermissionPublication publication;
  wyl_policy_store_t *store;
  const gchar *event;
  gchar *from_state;
  gchar *to_state;
  gint64 event_id;
} WylPermissionTransitionPublication;

static wyrelog_error_t
verify_symbol_row (WylEngineVerification *verification, const gchar *relation,
    const gchar *const *symbols, guint ncols, gboolean expected)
{
  gint64 row[4] = { 0 };
  if (ncols == 0 || ncols > G_N_ELEMENTS (row))
    return WYRELOG_E_INVALID;
  for (guint i = 0; i < ncols; i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i]);
    if (rc == WYRELOG_E_NOT_FOUND)
      return expected ? WYRELOG_E_POLICY : WYRELOG_E_OK;
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_engine_verification_contains (verification,
      relation, row, ncols, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found == expected ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

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
append_permission_audit_body (wyl_policy_store_t *store,
    const WylAuditEvent *audit_event)
{
  if (audit_event == NULL)
    return WYRELOG_E_OK;
  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (audit_event);
  if (audit_id == NULL)
    return WYRELOG_E_INTERNAL;
  gboolean inserted = FALSE;
  return wyl_policy_store_append_audit_event_full (store, audit_id,
      wyl_audit_event_get_created_at_us (audit_event),
      wyl_audit_event_get_subject_id (audit_event),
      wyl_audit_event_get_action (audit_event),
      wyl_audit_event_get_resource_id (audit_event),
      wyl_audit_event_get_deny_reason (audit_event),
      wyl_audit_event_get_deny_origin (audit_event),
      wyl_audit_event_get_request_id (audit_event),
      wyl_audit_event_get_decision (audit_event), &inserted);
}

static wyrelog_error_t
mutate_direct_permission (wyl_policy_store_t *store, gpointer data)
{
  WylPermissionPublication *ctx = data;
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (ctx->insert) {
    gboolean exists = FALSE;
    rc = wyl_policy_store_permission_exists (store, ctx->b, &exists);
    if (rc == WYRELOG_E_OK && !exists)
      rc = wyl_policy_store_upsert_permission (store, ctx->b, ctx->b, "basic");
  }
  if (rc == WYRELOG_E_OK)
    rc = ctx->insert ? wyl_policy_store_grant_direct_permission (store,
        ctx->a, ctx->b, ctx->c) :
        wyl_policy_store_revoke_direct_permission (store, ctx->a, ctx->b,
        ctx->c);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_direct_permission_event (store, ctx->a,
        ctx->b, ctx->c, ctx->insert ? "grant" : "revoke");
  if (rc == WYRELOG_E_OK)
    rc = append_permission_audit_body (store, ctx->audit_event);
  return rc;
}

static wyrelog_error_t
verify_direct_permission (WylEngineVerification *verification, gpointer data)
{
  WylPermissionPublication *ctx = data;
  const gchar *symbols[] = { ctx->a, ctx->b, ctx->c };
  return verify_symbol_row (verification, "has_permission", symbols,
      G_N_ELEMENTS (symbols), ctx->insert);
}

static wyrelog_error_t
mutate_role_membership (wyl_policy_store_t *store, gpointer data)
{
  WylPermissionPublication *ctx = data;
  wyrelog_error_t rc = ctx->insert ?
      wyl_policy_store_grant_role_membership (store, ctx->a, ctx->b, ctx->c) :
      wyl_policy_store_revoke_role_membership (store, ctx->a, ctx->b, ctx->c);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_role_membership_event (store, ctx->a,
        ctx->b, ctx->c, ctx->insert ? "grant" : "revoke");
  if (rc == WYRELOG_E_OK)
    rc = append_permission_audit_body (store, ctx->audit_event);
  return rc;
}

static wyrelog_error_t
verify_role_membership (WylEngineVerification *verification, gpointer data)
{
  WylPermissionPublication *ctx = data;
  const gchar *symbols[] = { ctx->a, ctx->b, ctx->c };
  return verify_symbol_row (verification, "effective_member", symbols,
      G_N_ELEMENTS (symbols), ctx->insert);
}

static wyrelog_error_t
publish_permission_mutation (WylPermissionPublication *ctx,
    WylCommittedEngineMutationBody mutate, WylEnginePublicationVerifier verify)
{
  g_autoptr (WylEngineSession) session =
      wyl_engine_session_acquire (ctx->handle);
  if (session == NULL)
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_engine_session_run_committed_publication (session,
      mutate, ctx, verify, ctx, NULL, NULL, NULL);
  g_clear_pointer (&session, wyl_engine_session_release);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL)
    (void) wyl_audit_mirror_event (ctx->handle, ctx->audit_event);
#endif
  return rc;
}

static wyrelog_error_t
mutate_permission_transition (wyl_policy_store_t *store, gpointer data)
{
  WylPermissionTransitionPublication *ctx = data;
  g_clear_pointer (&ctx->from_state, g_free);
  g_clear_pointer (&ctx->to_state, g_free);
  ctx->event_id = -1;
  wyrelog_error_t rc = wyl_policy_store_get_permission_state_for_publication
      (store,
      ctx->publication.a, ctx->publication.b, ctx->publication.c,
      &ctx->from_state);
  if (rc == WYRELOG_E_OK && ctx->from_state == NULL)
    ctx->from_state = g_strdup (wyl_perm_state_name (WYL_PERM_STATE_DORMANT));
  wyl_perm_state_t from = wyl_perm_state_from_name (ctx->from_state);
  wyl_perm_event_t event = wyl_perm_event_from_name (ctx->event);
  wyl_perm_state_t to = WYL_PERM_STATE_LAST_;
  if (rc == WYRELOG_E_OK && (from == WYL_PERM_STATE_LAST_
          || event == WYL_PERM_EVENT_LAST_))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fsm_permission_scope_step (from, event, &to);
  if (rc == WYRELOG_E_OK) {
    const gchar *to_name = wyl_perm_state_name (to);
    if (to_name == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      ctx->to_state = g_strdup (to_name);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_set_permission_state (store, ctx->publication.a,
        ctx->publication.b, ctx->publication.c, ctx->to_state);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_permission_state_event (store,
        ctx->publication.a, ctx->publication.b, ctx->publication.c,
        ctx->event, ctx->from_state, ctx->to_state, &ctx->event_id);
  if (rc == WYRELOG_E_OK)
    rc = append_permission_audit_body (store, ctx->publication.audit_event);
  return rc;
}

static wyrelog_error_t
verify_permission_transition (WylEngineVerification *verification,
    gpointer data)
{
  WylPermissionTransitionPublication *ctx = data;
  if (ctx->from_state == NULL || ctx->to_state == NULL || ctx->event_id <= 0)
    return WYRELOG_E_POLICY;
  const gchar *symbols[] = { ctx->publication.a, ctx->publication.b,
    ctx->publication.c, ctx->to_state
  };
  wyrelog_error_t rc = verify_symbol_row (verification, "perm_state", symbols,
      G_N_ELEMENTS (symbols), TRUE);
  if (rc != WYRELOG_E_OK)
    return rc;
  gint64 event_row[7] = { ctx->event_id, 0, 0, 0, 0, 0, 0 };
  const gchar *event_symbols[] = { ctx->publication.a, ctx->publication.b,
    ctx->publication.c, ctx->from_state, ctx->event, ctx->to_state
  };
  for (guint i = 0; i < G_N_ELEMENTS (event_symbols); i++) {
    rc = wyl_engine_verification_lookup_symbol (verification,
        event_symbols[i], &event_row[i + 1]);
    if (rc != WYRELOG_E_OK)
      return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  }
  gboolean found = FALSE;
  rc = wyl_engine_verification_contains (verification, "perm_state_fired",
      event_row, G_N_ELEMENTS (event_row), &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_handle_apply_permission_state_transition (WylHandle *handle,
    const gchar *subject_id, const gchar *perm_id, const gchar *scope,
    const gchar *event, const WylAuditEvent *audit_event, gint64 *out_event_id)
{
  if (out_event_id != NULL)
    *out_event_id = -1;
  if (handle == NULL || !WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;
  if (subject_id == NULL || perm_id == NULL || scope == NULL || event == NULL)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return WYRELOG_E_INVALID;

  WylPermissionTransitionPublication transition = {
    .publication = {handle, subject_id, perm_id, scope, TRUE, audit_event},
    .store = store,
    .event = event,
    .event_id = -1,
  };
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_BUSY;
  gboolean commit_confirmed = FALSE;
  wyrelog_error_t rc = wyl_engine_session_run_committed_publication (session,
      mutate_permission_transition, &transition, verify_permission_transition,
      &transition, NULL, NULL, &commit_confirmed);
  if (commit_confirmed && out_event_id != NULL)
    *out_event_id = transition.event_id;
  g_clear_pointer (&session, wyl_engine_session_release);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK && audit_event != NULL)
    (void) wyl_audit_mirror_event (handle, audit_event);
#endif
  g_free (transition.from_state);
  g_free (transition.to_state);
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
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return WYRELOG_E_INVALID;
  if (wyl_handle_engine_pair_is_ready (handle)
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

  WylPermissionPublication publication = { handle,
    wyl_grant_req_get_subject_id (req), wyl_grant_req_get_action (req),
    wyl_grant_req_get_resource_id (req), TRUE, ev
  };
  return publish_permission_mutation (&publication, mutate_direct_permission,
      verify_direct_permission);
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
  if (wyl_handle_engine_pair_is_poisoned (handle))
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

  WylPermissionPublication publication = { handle,
    wyl_revoke_req_get_subject_id (req), wyl_revoke_req_get_action (req),
    wyl_revoke_req_get_resource_id (req), FALSE, ev
  };
  return publish_permission_mutation (&publication, mutate_direct_permission,
      verify_direct_permission);
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
  if (wyl_handle_engine_pair_is_poisoned (handle))
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

  WylPermissionPublication publication = { handle,
    wyl_role_grant_req_get_subject_id (req),
    wyl_role_grant_req_get_role_id (req), wyl_role_grant_req_get_scope (req),
    TRUE, ev
  };
  return publish_permission_mutation (&publication, mutate_role_membership,
      verify_role_membership);
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
  if (wyl_handle_engine_pair_is_poisoned (handle))
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

  WylPermissionPublication publication = { handle,
    wyl_role_revoke_req_get_subject_id (req),
    wyl_role_revoke_req_get_role_id (req),
    wyl_role_revoke_req_get_scope (req), FALSE, ev
  };
  return publish_permission_mutation (&publication, mutate_role_membership,
      verify_role_membership);
}
