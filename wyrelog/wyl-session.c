/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "audit/event-private.h"
#include "wyl-common-private.h"
#include "wyl-fsm-principal-private.h"
#include "wyl-fsm-session-private.h"
#include "wyl-handle-private.h"
#include "wyl-id-private.h"
#include "wyl-session-layout-private.h"
#include "wyl-session-private.h"
#include "policy/store-private.h"

G_DEFINE_FINAL_TYPE (WylSession, wyl_session, G_TYPE_OBJECT);

static void
wyl_session_finalize (GObject *object)
{
  WylSession *self = WYL_SESSION (object);

  g_free (self->username);
  g_free (self->tenant);
  g_free (self->service_jti);
  g_free (self->service_subject_id);
  g_free (self->service_credential_id);

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
  wyl_session_state_store_private (self, WYL_SESSION_STATE_IDLE);
  self->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
}

static gboolean
session_is_service (const WylSession *session)
{
  return WYL_IS_SESSION ((gpointer) session)
      && session->auth_method == WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL;
}

static wyrelog_error_t
reload_session_snapshot (WylHandle *handle)
{
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return WYRELOG_E_INVALID;
  if (!wyl_handle_engine_pair_is_ready (handle))
    return WYRELOG_E_OK;
  return wyl_handle_reload_engine_pair (handle);
}

static gboolean
login_tenant_is_valid (const gchar *tenant)
{
  return wyl_policy_store_tenant_id_is_valid (tenant);
}

static wyrelog_error_t
login_skip_mfa_allowed (WylHandle *handle, const wyl_login_req_t *req,
    gboolean *out_allowed)
{
  if (handle == NULL || req == NULL || out_allowed == NULL)
    return WYRELOG_E_INVALID;
  if (wyl_handle_engine_pair_is_poisoned (handle))
    return WYRELOG_E_INVALID;

  *out_allowed = FALSE;
  if (wyl_handle_get_login_skip_mfa_allowed (handle)) {
    *out_allowed = TRUE;
    return WYRELOG_E_OK;
  }

  const gchar *username = wyl_login_req_get_username (req);
  if (username == NULL || username[0] == '\0')
    return WYRELOG_E_OK;

  if (!wyl_handle_engine_pair_is_ready (handle))
    return WYRELOG_E_OK;

  wyrelog_error_t rc = reload_session_snapshot (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  {
    g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
    gint64 row[1];
    rc = wyl_engine_session_intern_symbol (session, username, &row[0]);
    if (rc != WYRELOG_E_OK)
      return WYRELOG_E_OK;

    rc = wyl_engine_session_contains (session, "login_skip_mfa_authz", row, 1,
        out_allowed);
  }
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

static WylAuditEvent *
new_login_skip_mfa_allowed_audit (const gchar *username,
    const gchar *request_id)
{
  WylAuditEvent *ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, username);
  wyl_audit_event_set_action (ev, "login_skip_mfa");
  wyl_audit_event_set_resource_id (ev, "principal_state");
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
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
verify_session_symbol_row (WylEngineVerification *verification,
    const gchar *relation, const gchar *const *symbols, guint ncols)
{
  gint64 row[5] = { 0 };
  if (ncols == 0 || ncols > G_N_ELEMENTS (row))
    return WYRELOG_E_INVALID;
  for (guint i = 0; i < ncols; i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_engine_verification_contains (verification,
      relation, row, ncols, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
build_session_event_row (WylEngineVerification *verification,
    gint64 event_id, const gchar *entity, const gchar *event,
    const gchar *old_state, const gchar *new_state, gint64 row[5])
{
  if (event_id <= 0)
    return WYRELOG_E_POLICY;
  row[0] = event_id;
  /* The durable EDB event rows are projected through the FSM's *_fired
   * relations, whose canonical order is entity, from, event, to. */
  const gchar *symbols[] = { entity, old_state, event, new_state };
  for (guint i = 0; i < G_N_ELEMENTS (symbols); i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i + 1]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
verify_session_event_row (WylEngineVerification *verification,
    const gchar *relation, gint64 event_id, const gchar *entity,
    const gchar *event, const gchar *old_state, const gchar *new_state)
{
  gint64 row[5] = { 0 };
  wyrelog_error_t rc = build_session_event_row (verification, event_id,
      entity, event, old_state, new_state, row);
  if (rc != WYRELOG_E_OK)
    return rc;
  gboolean found = FALSE;
  rc = wyl_engine_verification_contains (verification,
      relation, row, G_N_ELEMENTS (row), &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
enqueue_session_event_delta (WylEngineVerification *verification,
    const gchar *relation, gint64 event_id, const gchar *entity,
    const gchar *event, const gchar *old_state, const gchar *new_state)
{
  gint64 row[5] = { 0 };
  wyrelog_error_t rc = build_session_event_row (verification, event_id,
      entity, event, old_state, new_state, row);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_verification_enqueue_delta (verification, relation, row,
      G_N_ELEMENTS (row), WYL_DELTA_INSERT);
}

typedef struct
{
  WylHandle *handle;
  const gchar *username;
  wyl_principal_state_t old_state;
  wyl_principal_event_t event;
  wyl_principal_state_t new_state;
  const WylAuditEvent *audit_event;
  gint64 event_id;
} WylPrincipalPublication;

static wyrelog_error_t
mutate_principal_publication (wyl_policy_store_t *store, gpointer data)
{
  WylPrincipalPublication *ctx = data;
  /* Issue #752: subject-global expected-from-state CAS.  The transition is
   * gated on the durable observed state re-read inside this savepoint, so a
   * concurrent superseding commit collapses to a clean no-op rather than a
   * blind overwrite.  The caller-supplied old_state is treated as a hint;
   * the real observed origin is reflected back into the ctx so the verifier
   * and delta producer assert the exact committed edge. */
  wyl_principal_state_t from = WYL_PRINCIPAL_STATE_LAST_;
  wyl_principal_state_t to = WYL_PRINCIPAL_STATE_LAST_;
  gboolean transitioned = FALSE;
  wyrelog_error_t rc = wyl_policy_store_apply_principal_transition (store,
      ctx->username, ctx->event, 0, 0, &from, &to, &transitioned,
      &ctx->event_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  /* No legal edge from the observed state (already superseded / idempotent):
   * precommit-reject cleanly so no duplicate or illegal event is published. */
  if (!transitioned)
    return WYRELOG_E_POLICY;
  ctx->old_state = from;
  ctx->new_state = to;
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL) {
    g_autofree gchar *audit_id =
        wyl_audit_event_dup_id_string (ctx->audit_event);
    if (audit_id == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      rc = append_policy_audit_event (store, audit_id, ctx->audit_event);
  }
  return rc;
}

static wyrelog_error_t
verify_principal_publication (WylEngineVerification *verification,
    gpointer data)
{
  WylPrincipalPublication *ctx = data;
  const gchar *old_state = wyl_principal_state_name (ctx->old_state);
  const gchar *event = wyl_principal_event_name (ctx->event);
  const gchar *new_state = wyl_principal_state_name (ctx->new_state);
  if (old_state == NULL || event == NULL || new_state == NULL)
    return WYRELOG_E_INTERNAL;
  const gchar *state_row[] = { ctx->username, new_state };
  wyrelog_error_t rc = verify_session_symbol_row (verification,
      "principal_state", state_row, G_N_ELEMENTS (state_row));
  if (rc != WYRELOG_E_OK)
    return rc;
  return verify_session_event_row (verification, "principal_fired",
      ctx->event_id, ctx->username, event, old_state, new_state);
}

static wyrelog_error_t
produce_principal_publication_delta (WylEngineVerification *verification,
    gpointer data)
{
  WylPrincipalPublication *ctx = data;
  return enqueue_session_event_delta (verification, "principal_fired",
      ctx->event_id, ctx->username, wyl_principal_event_name (ctx->event),
      wyl_principal_state_name (ctx->old_state),
      wyl_principal_state_name (ctx->new_state));
}

static wyrelog_error_t
publish_principal_mutation (WylPrincipalPublication *ctx)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (ctx->handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_engine_session_run_committed_publication
      (engine_session, mutate_principal_publication, ctx,
      verify_principal_publication, ctx, produce_principal_publication_delta,
      ctx, NULL);
  g_clear_pointer (&engine_session, wyl_engine_session_release);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL)
    (void) wyl_audit_mirror_event (ctx->handle, ctx->audit_event);
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
  WylPrincipalPublication publication = { handle, username, old_state,
    WYL_PRINCIPAL_EVENT_MFA_OK, new_state, ev, -1
  };
  return publish_principal_mutation (&publication);
}

/* Wraps the shared principal-publication ctx with the TOTP step the
 * mutate must compare-and-advance inside the driver-owned transaction. */
typedef struct
{
  WylPrincipalPublication publication;
  gint64 matched_step;
} WylTotpMfaOkPublication;

/*
 * mutate body for the atomic TOTP MFA_OK commit (issue #751).  Runs
 * inside the committed-publication driver's owned transaction and gates
 * on the durable pre-state before consuming the proof:
 *   (a) the principal must still be exactly mfa_required (else a
 *       superseded replay / concurrent loser -> E_POLICY, clean rollback)
 *   (b) compare-and-advance the replay watermark; a concurrent winner
 *       that already advanced it yields !advanced -> E_POLICY
 *   (c) reset the failure counter (folds the locked_at clear)
 *   (d) the same state+event(+audit) writes mutate_principal_publication
 *       performs.
 * A store fault surfaces as E_INTERNAL so the driver poisons/rolls back;
 * an E_POLICY return rolls back cleanly without poisoning.
 */
static wyrelog_error_t
totp_mutate_mfa_ok (wyl_policy_store_t *store, gpointer data)
{
  WylTotpMfaOkPublication *wrap = data;
  WylPrincipalPublication *ctx = &wrap->publication;

  gchar *state = NULL;
  gint64 failed_count = 0;
  gint64 locked_at = 0;
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_policy_store_get_principal_lock_info (store,
      ctx->username, &state, &failed_count, &locked_at, &found);
  if (rc != WYRELOG_E_OK) {
    g_free (state);
    return WYRELOG_E_INTERNAL;
  }
  gboolean is_mfa_required = found && g_strcmp0 (state,
      wyl_principal_state_name (WYL_PRINCIPAL_STATE_MFA_REQUIRED)) == 0;
  g_free (state);
  if (!is_mfa_required)
    return WYRELOG_E_POLICY;

  gboolean advanced = FALSE;
  rc = wyl_policy_store_totp_enrollment_advance_step (store, ctx->username,
      wrap->matched_step, &advanced);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;
  if (!advanced)
    return WYRELOG_E_POLICY;

  rc = wyl_policy_store_reset_principal_failure_counter (store, ctx->username);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  const gchar *old_state = wyl_principal_state_name (ctx->old_state);
  const gchar *event = wyl_principal_event_name (ctx->event);
  const gchar *new_state = wyl_principal_state_name (ctx->new_state);
  if (old_state == NULL || event == NULL || new_state == NULL)
    return WYRELOG_E_INTERNAL;
  rc = wyl_policy_store_set_principal_state (store, ctx->username, new_state);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_principal_event (store, ctx->username,
        event, old_state, new_state, &ctx->event_id);
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL) {
    g_autofree gchar *audit_id =
        wyl_audit_event_dup_id_string (ctx->audit_event);
    if (audit_id == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      rc = append_policy_audit_event (store, audit_id, ctx->audit_event);
  }
  return (rc == WYRELOG_E_OK) ? WYRELOG_E_OK : WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_session_totp_commit_mfa_ok (WylHandle *handle, WylSession *session,
    gint64 matched_step, WylMfaTotpReceipt *out_receipt)
{
  if (out_receipt != NULL)
    *out_receipt = WYL_MFA_TOTP_RECEIPT_REPLAY_SUPERSEDED;
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session)
      || session->username == NULL)
    return WYRELOG_E_INVALID;

  /* Pure FSM shape check, identical to mark_session_mfa_verified: the
   * MFA_REQUIRED --MFA_OK--> AUTHENTICATED edge must exist before we
   * attempt the durable transition. */
  wyl_principal_state_t new_state = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_MFA_OK, &new_state);
  if (rc != WYRELOG_E_OK || new_state != WYL_PRINCIPAL_STATE_AUTHENTICATED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_principal_state_audit (session->username,
      wyl_principal_state_name (WYL_PRINCIPAL_STATE_MFA_REQUIRED),
      wyl_principal_state_name (new_state),
      wyl_principal_event_name (WYL_PRINCIPAL_EVENT_MFA_OK), NULL);
#else
  WylAuditEvent *ev = NULL;
#endif
  WylTotpMfaOkPublication publication = {
    {handle, session->username, WYL_PRINCIPAL_STATE_MFA_REQUIRED,
        WYL_PRINCIPAL_EVENT_MFA_OK, new_state, ev, -1},
    matched_step
  };

  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  WylCommittedPublicationStage stage =
      WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED;
  rc = wyl_engine_session_run_committed_publication (engine_session,
      totp_mutate_mfa_ok, &publication, verify_principal_publication,
      &publication.publication, produce_principal_publication_delta,
      &publication.publication, &stage);
  g_clear_pointer (&engine_session, wyl_engine_session_release);

  if (rc == WYRELOG_E_OK && stage == WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED) {
    g_atomic_int_set ((gint *) & session->mfa_assured, 1);
#ifdef WYL_HAS_AUDIT
    if (publication.publication.audit_event != NULL)
      (void) wyl_audit_mirror_event (handle,
          publication.publication.audit_event);
#endif
    if (out_receipt != NULL)
      *out_receipt = WYL_MFA_TOTP_RECEIPT_WON_COMMITTED;
    return WYRELOG_E_OK;
  }

  if (out_receipt != NULL) {
    switch (stage) {
      case WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED:
        *out_receipt = (rc == WYRELOG_E_POLICY)
            ? WYL_MFA_TOTP_RECEIPT_REPLAY_SUPERSEDED
            : WYL_MFA_TOTP_RECEIPT_PRECOMMIT_STORE_FAILURE;
        break;
      case WYL_COMMITTED_PUBLICATION_COMMIT_AMBIGUOUS:
        *out_receipt = WYL_MFA_TOTP_RECEIPT_COMMIT_UNCERTAIN;
        break;
      case WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED:
        *out_receipt = WYL_MFA_TOTP_RECEIPT_POSTCOMMIT_PUBLICATION_FAILURE;
        break;
    }
  }

  return (rc == WYRELOG_E_POLICY) ? WYRELOG_E_POLICY : WYRELOG_E_INTERNAL;
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

typedef struct
{
  WylHandle *handle;
  const gchar *session_id;
  wyl_session_state_t old_state;
  wyl_session_event_t event;
  wyl_session_state_t new_state;
  const WylAuditEvent *audit_event;
  gint64 event_id;
} WylSessionPublication;

static wyrelog_error_t
mutate_session_publication (wyl_policy_store_t *store, gpointer data)
{
  WylSessionPublication *ctx = data;
  const gchar *old_state = wyl_session_state_name (ctx->old_state);
  const gchar *event = wyl_session_event_name (ctx->event);
  const gchar *new_state = wyl_session_state_name (ctx->new_state);
  if (old_state == NULL || event == NULL || new_state == NULL)
    return WYRELOG_E_INTERNAL;
  wyrelog_error_t rc = wyl_policy_store_set_session_state (store,
      ctx->session_id, new_state);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_session_event (store, ctx->session_id,
        event, old_state, new_state, &ctx->event_id);
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL) {
    g_autofree gchar *audit_id =
        wyl_audit_event_dup_id_string (ctx->audit_event);
    if (audit_id == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      rc = append_policy_audit_event (store, audit_id, ctx->audit_event);
  }
  return rc;
}

static wyrelog_error_t
verify_session_publication (WylEngineVerification *verification, gpointer data)
{
  WylSessionPublication *ctx = data;
  const gchar *old_state = wyl_session_state_name (ctx->old_state);
  const gchar *event = wyl_session_event_name (ctx->event);
  const gchar *new_state = wyl_session_state_name (ctx->new_state);
  if (old_state == NULL || event == NULL || new_state == NULL)
    return WYRELOG_E_INTERNAL;
  return verify_session_event_row (verification, "session_fired",
      ctx->event_id, ctx->session_id, event, old_state, new_state);
}

static wyrelog_error_t
produce_session_publication_delta (WylEngineVerification *verification,
    gpointer data)
{
  WylSessionPublication *ctx = data;
  return enqueue_session_event_delta (verification, "session_fired",
      ctx->event_id, ctx->session_id, wyl_session_event_name (ctx->event),
      wyl_session_state_name (ctx->old_state),
      wyl_session_state_name (ctx->new_state));
}

static wyrelog_error_t
publish_session_mutation (WylSessionPublication *ctx)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (ctx->handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_engine_session_run_committed_publication
      (engine_session, mutate_session_publication, ctx,
      verify_session_publication, ctx, produce_session_publication_delta,
      ctx, NULL);
  g_clear_pointer (&engine_session, wyl_engine_session_release);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK && ctx->audit_event != NULL)
    (void) wyl_audit_mirror_event (ctx->handle, ctx->audit_event);
#endif
  return rc;
}

typedef struct
{
  WylHandle *handle;
  const gchar *username;
  wyl_principal_event_t principal_event;
  wyl_principal_state_t principal_new_state;
  const gchar *session_id;
  wyl_session_state_t session_old_state;
  wyl_session_event_t session_event;
  wyl_session_state_t session_new_state;
  const WylAuditEvent *principal_audit_event;
  const WylAuditEvent *session_audit_event;
  gint64 principal_event_id;
  gint64 session_event_id;
} WylLoginPublication;

static wyrelog_error_t
mutate_login_publication (wyl_policy_store_t *store, gpointer data)
{
  WylLoginPublication *ctx = data;
  const gchar *principal_event = wyl_principal_event_name
      (ctx->principal_event);
  const gchar *principal_from = wyl_principal_state_name
      (WYL_PRINCIPAL_STATE_UNVERIFIED);
  const gchar *principal_to = wyl_principal_state_name
      (ctx->principal_new_state);
  const gchar *session_event = wyl_session_event_name (ctx->session_event);
  const gchar *session_from = wyl_session_state_name (ctx->session_old_state);
  const gchar *session_to = wyl_session_state_name (ctx->session_new_state);
  if (principal_event == NULL || principal_from == NULL
      || principal_to == NULL || session_event == NULL
      || session_from == NULL || session_to == NULL)
    return WYRELOG_E_INTERNAL;

  wyrelog_error_t rc = wyl_policy_store_set_principal_state (store,
      ctx->username, principal_to);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_principal_event (store, ctx->username,
        principal_event, principal_from, principal_to,
        &ctx->principal_event_id);
  if (rc == WYRELOG_E_OK && ctx->principal_audit_event != NULL) {
    g_autofree gchar *audit_id = wyl_audit_event_dup_id_string
        (ctx->principal_audit_event);
    if (audit_id == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      rc = append_policy_audit_event (store, audit_id,
          ctx->principal_audit_event);
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_set_session_state (store, ctx->session_id,
        session_to);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_session_event (store, ctx->session_id,
        session_event, session_from, session_to, &ctx->session_event_id);
  if (rc == WYRELOG_E_OK && ctx->session_audit_event != NULL) {
    g_autofree gchar *audit_id = wyl_audit_event_dup_id_string
        (ctx->session_audit_event);
    if (audit_id == NULL)
      rc = WYRELOG_E_INTERNAL;
    else
      rc = append_policy_audit_event (store, audit_id,
          ctx->session_audit_event);
  }
  return rc;
}

static wyrelog_error_t
verify_login_publication (WylEngineVerification *verification, gpointer data)
{
  WylLoginPublication *ctx = data;
  const gchar *principal_event = wyl_principal_event_name
      (ctx->principal_event);
  const gchar *principal_from = wyl_principal_state_name
      (WYL_PRINCIPAL_STATE_UNVERIFIED);
  const gchar *principal_to = wyl_principal_state_name
      (ctx->principal_new_state);
  const gchar *session_event = wyl_session_event_name (ctx->session_event);
  const gchar *session_from = wyl_session_state_name (ctx->session_old_state);
  const gchar *session_to = wyl_session_state_name (ctx->session_new_state);
  if (principal_event == NULL || principal_from == NULL
      || principal_to == NULL || session_event == NULL
      || session_from == NULL || session_to == NULL)
    return WYRELOG_E_INTERNAL;
  const gchar *principal_state[] = { ctx->username, principal_to };
  wyrelog_error_t rc = verify_session_symbol_row (verification,
      "principal_state", principal_state, G_N_ELEMENTS (principal_state));
  if (rc == WYRELOG_E_OK)
    rc = verify_session_event_row (verification, "principal_fired",
        ctx->principal_event_id, ctx->username, principal_event,
        principal_from, principal_to);
  if (rc == WYRELOG_E_OK)
    rc = verify_session_event_row (verification, "session_fired",
        ctx->session_event_id, ctx->session_id, session_event, session_from,
        session_to);
  return rc;
}

static wyrelog_error_t
produce_login_publication_deltas (WylEngineVerification *verification,
    gpointer data)
{
  WylLoginPublication *ctx = data;
  wyrelog_error_t rc = enqueue_session_event_delta (verification,
      "principal_fired", ctx->principal_event_id, ctx->username,
      wyl_principal_event_name (ctx->principal_event),
      wyl_principal_state_name (WYL_PRINCIPAL_STATE_UNVERIFIED),
      wyl_principal_state_name (ctx->principal_new_state));
  if (rc != WYRELOG_E_OK)
    return rc;
  return enqueue_session_event_delta (verification, "session_fired",
      ctx->session_event_id, ctx->session_id,
      wyl_session_event_name (ctx->session_event),
      wyl_session_state_name (ctx->session_old_state),
      wyl_session_state_name (ctx->session_new_state));
}

static wyrelog_error_t
publish_login_mutation (WylLoginPublication *ctx)
{
  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (ctx->handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  wyrelog_error_t rc = wyl_engine_session_run_committed_publication
      (engine_session, mutate_login_publication, ctx,
      verify_login_publication, ctx, produce_login_publication_deltas, ctx,
      NULL);
  g_clear_pointer (&engine_session, wyl_engine_session_release);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK && ctx->principal_audit_event != NULL)
    (void) wyl_audit_mirror_event (ctx->handle, ctx->principal_audit_event);
  if (rc == WYRELOG_E_OK && ctx->session_audit_event != NULL)
    (void) wyl_audit_mirror_event (ctx->handle, ctx->session_audit_event);
#endif
  return rc;
}

static wyrelog_error_t
transition_session_state (WylHandle *handle, WylSession *session,
    wyl_session_state_t old_state, wyl_session_event_t event,
    wyl_session_state_t new_state, const gchar *request_id)
{
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  const gchar *old_state_name = wyl_session_state_name (old_state);
  const gchar *new_state_name = wyl_session_state_name (new_state);
  if (old_state_name == NULL || new_state_name == NULL)
    return WYRELOG_E_INTERNAL;

#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_session_state_audit (session_id,
      old_state_name, new_state_name, request_id);
#else
  WylAuditEvent *ev = NULL;
  (void) request_id;
#endif
  WylSessionPublication publication = { handle, session_id, old_state, event,
    new_state, ev, -1
  };
  wyrelog_error_t rc = publish_session_mutation (&publication);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_session_state_store_private (session, new_state);
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

  const gchar *tenant = WYL_TENANT_DEFAULT;
  if (req != NULL && wyl_login_req_get_tenant (req) != NULL)
    tenant = wyl_login_req_get_tenant (req);
  if (!login_tenant_is_valid (tenant))
    return WYRELOG_E_INVALID;

  const gchar *requested_username =
      req != NULL ? wyl_login_req_get_username (req) : NULL;
  if (wyl_policy_subject_has_service_prefix (requested_username))
    return WYRELOG_E_POLICY;

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
  if (wyl_id_new (&session->id) != WYRELOG_E_OK)
    g_error ("wyl_session_login: failed to mint identifier");
  session->created_at_us = g_get_real_time ();
  const gchar *username = NULL;
  if (req != NULL) {
    username = wyl_login_req_get_username (req);
    session->username = g_strdup (username);
  }
  session->tenant = g_strdup (tenant);

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
    g_autoptr (WylAuditEvent) principal_ev = NULL;
    if (req != NULL && wyl_login_req_get_skip_mfa (req))
      principal_ev = new_login_skip_mfa_allowed_audit (username,
          wyl_login_req_get_request_id (req));
    else
      principal_ev = new_principal_state_audit (username,
          wyl_principal_state_name (WYL_PRINCIPAL_STATE_UNVERIFIED),
          wyl_principal_state_name (state), wyl_principal_event_name (event),
          wyl_login_req_get_request_id (req));
    g_autoptr (WylAuditEvent) session_ev =
        new_session_state_audit (session_id,
        wyl_session_state_name (wyl_session_state_load_private (session)),
        "active", wyl_login_req_get_request_id (req));
#else
    WylAuditEvent *principal_ev = NULL;
    WylAuditEvent *session_ev = NULL;
#endif
    WylLoginPublication publication = { handle, username, event, state,
      session_id, WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
      WYL_SESSION_STATE_ACTIVE, principal_ev, session_ev, -1, -1
    };
    rc = publish_login_mutation (&publication);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    wyl_session_state_store_private (session, WYL_SESSION_STATE_ACTIVE);
    rc = wyl_handle_register_session (handle, session, &session->sid);
    if (rc != WYRELOG_E_OK) {
      g_object_unref (session);
      return rc;
    }
    *out_session = session;
    return WYRELOG_E_OK;
  }
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = new_session_state_audit (session_id,
      wyl_session_state_name (wyl_session_state_load_private (session)),
      "active", req != NULL ? wyl_login_req_get_request_id (req) : NULL);
#else
  WylAuditEvent *ev = NULL;
#endif
  WylSessionPublication publication = { handle, session_id,
    WYL_SESSION_STATE_IDLE, WYL_SESSION_EVENT_REQUEST,
    WYL_SESSION_STATE_ACTIVE, ev, -1
  };
  wyrelog_error_t rc = publish_session_mutation (&publication);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
  wyl_session_state_store_private (session, WYL_SESSION_STATE_ACTIVE);

  rc = wyl_handle_register_session (handle, session, &session->sid);
  if (rc != WYRELOG_E_OK) {
    g_object_unref (session);
    return rc;
  }
  *out_session = session;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
mark_session_mfa_verified (WylHandle *handle, WylSession *session)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;
  if (session->username == NULL)
    return WYRELOG_E_INVALID;

  wyl_principal_state_t state = WYL_PRINCIPAL_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_principal_step (WYL_PRINCIPAL_STATE_MFA_REQUIRED,
      WYL_PRINCIPAL_EVENT_MFA_OK, &state);
  if (rc != WYRELOG_E_OK || state != WYL_PRINCIPAL_STATE_AUTHENTICATED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  rc = transition_principal_state (handle, session->username,
      WYL_PRINCIPAL_STATE_MFA_REQUIRED, state);
  if (rc == WYRELOG_E_OK)
    g_atomic_int_set ((gint *) & session->mfa_assured, 1);
  return rc;
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
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session) ||
      session->username == NULL)
    return WYRELOG_E_INVALID;
  if (proof == NULL || proof[0] == '\0' || validator == NULL)
    return WYRELOG_E_INVALID;

  /* The proof-path validator now performs the durable
   * MFA_REQUIRED -> AUTHENTICATED transition atomically with consuming
   * the proof (issue #751, wyl_session_totp_commit_mfa_ok).  Driving
   * mark_session_mfa_verified again here would be a second, unconditional
   * transition that re-appends the MFA_OK event and could authenticate a
   * replayed/superseded attempt.  Return the validator result directly;
   * it has already set mfa_assured on the winning commit. */
  return validator (handle, session, proof, user_data);
}

wyrelog_error_t
wyl_session_close_with_request_id (WylHandle *handle, WylSession *session,
    const gchar *request_id)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t current = wyl_session_state_load_private (session);
  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_session_step (current, WYL_SESSION_EVENT_LOGOUT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_CLOSED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, current,
      WYL_SESSION_EVENT_LOGOUT, state, request_id);
}

wyrelog_error_t
wyl_session_close (WylHandle *handle, WylSession *session)
{
  return wyl_session_close_with_request_id (handle, session, NULL);
}

wyrelog_error_t
wyl_session_elevate (WylHandle *handle, WylSession *session)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t current = wyl_session_state_load_private (session);
  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (current,
      WYL_SESSION_EVENT_ELEVATE_GRANT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_ELEVATED)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, current,
      WYL_SESSION_EVENT_ELEVATE_GRANT, state, NULL);
}

wyrelog_error_t
wyl_session_drop_elevation (WylHandle *handle, WylSession *session)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t current = wyl_session_state_load_private (session);
  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (current,
      WYL_SESSION_EVENT_ELEVATE_DROP, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_ACTIVE)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, current,
      WYL_SESSION_EVENT_ELEVATE_DROP, state, NULL);
}

wyrelog_error_t
wyl_session_idle_timeout (WylHandle *handle, WylSession *session)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t current = wyl_session_state_load_private (session);
  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc = wyl_fsm_session_step (current,
      WYL_SESSION_EVENT_IDLE_TIMEOUT, &state);
  if (rc != WYRELOG_E_OK || state != WYL_SESSION_STATE_IDLE)
    return (rc == WYRELOG_E_OK) ? WYRELOG_E_INTERNAL : rc;

  return transition_session_state (handle, session, current,
      WYL_SESSION_EVENT_IDLE_TIMEOUT, state, NULL);
}

wyrelog_error_t
wyl_session_expire (WylHandle *handle, WylSession *session)
{
  if (session_is_service (session))
    return WYRELOG_E_POLICY;
  if (handle == NULL || session == NULL || !WYL_IS_SESSION (session))
    return WYRELOG_E_INVALID;

  wyl_session_state_t current = wyl_session_state_load_private (session);
  wyl_session_state_t state = WYL_SESSION_STATE_LAST_;
  wyrelog_error_t rc =
      wyl_fsm_session_step (current, WYL_SESSION_EVENT_EXPIRY, &state);
  if (rc != WYRELOG_E_OK)
    return rc;

  return transition_session_state (handle, session, current,
      WYL_SESSION_EVENT_EXPIRY, state, NULL);
}

wyrelog_error_t
wyl_session_logout_with_request_id (WylHandle *handle, wyl_session_id_t sid,
    const gchar *request_id)
{
  if (handle == NULL)
    return WYRELOG_E_INVALID;

  /*
   * State matrix (resolved against the per-handle session registry):
   *   - sid not registered: WYRELOG_E_NOT_FOUND. Distinct from
   *     WYRELOG_E_INVALID so callers can tell "you handed me junk"
   *     from "you asked for a session this handle never knew about".
   *   - sid registered but tombstoned (already torn down): idempotent
   *     WYRELOG_E_OK with no FSM step and no fresh audit row.
   *   - sid registered and live in {idle, active, elevated, expiring}:
   *     drive the session FSM through WYL_SESSION_EVENT_LOGOUT (which
   *     is the canonical event for those four source states), record
   *     the durable transition + audit row through the existing
   *     close-with-request-id primitive, then tombstone the registry
   *     entry so a repeat logout collapses to the idempotent path.
   *   - sid registered and live but already in the terminal CLOSED
   *     state (e.g. wyl_session_close was driven directly through the
   *     WylSession* surface and the registry was not yet tombstoned):
   *     skip the FSM step (the FSM has no (closed, logout) row),
   *     tombstone the entry, and return E_OK so this entry point is
   *     idempotent against both prior code paths.
   */
  wyl_session_lookup_state_t state = WYL_SESSION_LOOKUP_UNKNOWN;
  g_autoptr (WylSession) live = NULL;
  wyrelog_error_t rc = wyl_handle_lookup_session_by_id_ref (handle, sid,
      &state, &live);
  if (rc != WYRELOG_E_OK)
    return rc;

  switch (state) {
    case WYL_SESSION_LOOKUP_UNKNOWN:
      return WYRELOG_E_NOT_FOUND;
    case WYL_SESSION_LOOKUP_TOMBSTONED:
      return WYRELOG_E_OK;
    case WYL_SESSION_LOOKUP_LIVE:
      break;
  }

  if (wyl_session_state_load_private (live) == WYL_SESSION_STATE_CLOSED) {
    (void) wyl_handle_tombstone_session (handle, sid);
    return WYRELOG_E_OK;
  }

  rc = wyl_session_close_with_request_id (handle, live, request_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  (void) wyl_handle_tombstone_session (handle, sid);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_session_logout (WylHandle *handle, wyl_session_id_t sid)
{
  return wyl_session_logout_with_request_id (handle, sid, NULL);
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

wyl_session_id_t
wyl_session_get_id (const WylSession *self)
{
  if (self == NULL || !WYL_IS_SESSION (self))
    return 0;
  return self->sid;
}

gchar *
wyl_session_dup_username (const WylSession *self)
{
  g_return_val_if_fail (WYL_IS_SESSION (self), NULL);
  if (self->username == NULL)
    return NULL;
  return g_strdup (self->username);
}

gchar *
wyl_session_dup_tenant (const WylSession *self)
{
  g_return_val_if_fail (WYL_IS_SESSION (self), NULL);
  if (self->tenant == NULL)
    return NULL;
  return g_strdup (self->tenant);
}
