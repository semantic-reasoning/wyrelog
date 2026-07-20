/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/handle.h"
#include "wyrelog/error.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/wyl-id-private.h"

G_BEGIN_DECLS typedef struct
{
  gchar *subject_id;
  gchar *display_name;
  gchar *state;
  guint64 generation;
  gchar *created_by;
  gint64 created_at_us;
  gint64 updated_at_us;
  gchar *disabled_by;
  gint64 disabled_at_us;
} wyl_service_principal_t;

typedef struct
{
  gchar *credential_id;
  guint32 credential_format_version;
  gchar *subject_id;
  gchar *tenant_id;
  guint64 generation;
  gchar *state;
  gchar *created_by;
  gint64 created_at_us;
  gint64 updated_at_us;
  gint64 expires_at_us;
  gint64 last_used_at_us;
  gchar *revoked_by;
  gint64 revoked_at_us;
  gchar *rotated_from_id;
} wyl_service_credential_t;

typedef struct
{
  wyl_service_credential_t credential;
  wyl_service_credential_secret_t *secret;
} wyl_service_credential_issue_result_t;

#define WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES 32u

/* Non-secret, owner-delivery binding supplied by the authenticated executor.
 * escrow_id and target_digest are borrowed only until the mutation returns. */
typedef struct
{
  const wyl_id_t *escrow_id;
  const guint8 *target_digest;
  gint64 deadline_at_us;
} wyl_service_credential_handoff_request_t;

/* Owned, non-secret description of material sealed in the policy store. */
typedef struct
{
  wyl_id_t escrow_id;
  gchar *operation;
  gchar *request_id;
  gchar *actor_subject_id;
  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  gchar *credential_id;
  guint64 credential_generation;
  gint64 deadline_at_us;
  guint8 binding_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
} wyl_service_credential_handoff_t;

typedef struct
{
  wyl_service_credential_t credential;
  wyl_service_credential_handoff_t handoff;
} wyl_service_credential_handoff_result_t;

typedef struct
{
  void (*before_gate) (gpointer data);
    gint64 (*now_us) (gpointer data);
  const wyl_service_credential_runtime_t *credential_runtime;
  gpointer data;
} wyl_service_credential_verify_runtime_t;

typedef wyrelog_error_t (*wyl_service_credential_mutation_authorize_fn)
  (gpointer data, const gchar * actor_subject_id);

/* Optional execution-boundary authorization, borrowed for one mutation call.
 * authorize runs exactly once after the service WRITE lease is acquired and
 * before fence lookup, CVK access, transaction start or credential RNG. It
 * MUST be non-reentrant and MUST NOT call service mutation APIs on handle. */
typedef struct
{
  wyl_service_credential_mutation_authorize_fn authorize;
  gpointer data;
} wyl_service_credential_mutation_authorization_t;

typedef struct
{
  const wyl_service_credential_mutation_authorization_t *authorization;
  /* Borrowed for the call; callback lifetime rules match the returned secret
   * contract documented for rotation below. */
  const wyl_service_credential_runtime_t *credential_runtime;
} wyl_service_credential_issue_runtime_t;

typedef struct
{
  gint64 (*now_us) (gpointer data);
  const wyl_service_credential_runtime_t *credential_runtime;
  gpointer data;
  /* Invoked after the authority commit and before lease release. */
    wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
  /* The observed active generation used by the authoritative rotate CAS.
   * Zero preserves callers that have no externally observed generation. */
  guint64 old_credential_generation;
  const wyl_service_credential_mutation_authorization_t *authorization;
} wyl_service_credential_rotate_runtime_t;

typedef struct
{
  /* Invoked after the authority commit and before lease release. */
  wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
} wyl_service_credential_revoke_runtime_t;

typedef struct
{
  const gchar *original_request_id;
  const wyl_id_t *escrow_id;
  guint8 binding_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  const gchar *successor_credential_id;
  guint64 successor_issuance_generation;
  const gchar *original_actor_subject_id;
} wyl_service_credential_handoff_exact_tuple_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_PREPARED = 1,
  WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_COMMITTED = 2,
  WYL_SERVICE_HANDOFF_CANCELLATION_OBSERVATION_TERMINAL_NOT_COMMITTED = 3,
} wyl_service_credential_handoff_cancellation_observation_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_CANCELLATION_COMMITTED_ATTENTION = 1,
  WYL_SERVICE_HANDOFF_CANCELLATION_TERMINAL_NOT_COMMITTED = 2,
} wyl_service_credential_handoff_cancellation_outcome_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_FENCE_ISSUE = 1,
  WYL_SERVICE_HANDOFF_FENCE_ROTATE = 2,
} wyl_service_credential_handoff_fence_operation_t;

typedef struct
{
  wyl_service_credential_handoff_fence_operation_t operation;
  const gchar *target_a;
  const gchar *target_b;
} wyl_service_credential_handoff_no_commit_evidence_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_DISPOSITION_NOT_COMMITTED = 1,
  WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED = 2,
  WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED = 3,
  WYL_SERVICE_HANDOFF_DISPOSITION_SUCCESSOR_EXPIRED = 4,
  WYL_SERVICE_HANDOFF_DISPOSITION_SUCCESSOR_REVOKED = 5,
  WYL_SERVICE_HANDOFF_DISPOSITION_DELIVERED = 6,
} wyl_service_credential_handoff_disposition_reason_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_OUTCOME_TERMINAL_NOT_COMMITTED = 1,
  WYL_SERVICE_HANDOFF_OUTCOME_ATTENTION_REQUIRED = 2,
  WYL_SERVICE_HANDOFF_OUTCOME_OPERATOR_ACTION_REQUIRED = 3,
  WYL_SERVICE_HANDOFF_OUTCOME_ESCROW_DELETED = 4,
} wyl_service_credential_handoff_disposition_outcome_t;

typedef struct
{
  const gchar *disposition_id;
  const gchar *audit_id;
  wyl_service_credential_handoff_exact_tuple_t tuple;
  const gchar *actor_subject_id;
  wyl_service_credential_handoff_disposition_reason_t reason;
  wyl_service_credential_handoff_disposition_outcome_t outcome;
  const wyl_service_credential_handoff_no_commit_evidence_t
      * no_commit_evidence;
} wyl_service_credential_handoff_disposition_input_t;

typedef struct
{
  gboolean replayed;
  gchar *disposition_id;
  gchar *audit_id;
} wyl_service_credential_handoff_disposition_result_t;

typedef struct
{
  const gchar *cancellation_request_id;
  const gchar *decision_request_id;
  const gchar *current_actor_subject_id;
  const gchar *disposition_id;
  const gchar *audit_id;
  wyl_service_credential_handoff_exact_tuple_t tuple;
  wyl_service_credential_handoff_cancellation_observation_t observation;
  wyl_service_credential_handoff_fence_operation_t operation;
  const gchar *target_a;
  const gchar *target_b;
  guint8 target_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  gint64 deadline_at_us;
} wyl_service_credential_handoff_cancellation_input_t;

typedef struct
{
  gboolean replayed;
  wyl_service_credential_handoff_cancellation_outcome_t outcome;
  gchar *disposition_id;
  gchar *audit_id;
  gint64 created_at_us;
  gchar successor_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint64 successor_issuance_generation;
  guint8 binding_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
} wyl_service_credential_handoff_cancellation_result_t;

typedef struct
{
  const wyl_service_credential_mutation_authorization_t *authorization;
} wyl_service_credential_handoff_cancellation_runtime_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_RESUME = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE = 2,
} wyl_service_credential_handoff_remediation_action_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_RECORDED = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_REVOKED_AND_WIPED = 2,
  WYL_SERVICE_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED = 3,
  WYL_SERVICE_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED = 4,
} wyl_service_credential_handoff_remediation_outcome_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED = 2,
} wyl_service_credential_handoff_remediation_source_kind_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PREPARED = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED = 2,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED = 3,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_FILE_PUBLISHED = 4,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_CLEANUP_REQUIRED = 5,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED = 6,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_TERMINAL = 7,
  WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED = 8,
} wyl_service_credential_handoff_remediation_journal_state_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_NONE = 0,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_RECEIPT_FOREIGN = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_RECEIPT_UNCERTAIN = 2,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_FOREIGN = 3,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_UNCERTAIN = 4,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_SUCCESSOR_REVOKED = 5,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_SUCCESSOR_EXPIRED = 6,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_EXPLICIT_HOLD = 7,
  WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING = 8,
} wyl_service_credential_handoff_remediation_oar_cause_t;

typedef enum
{
  WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_RETAINED = 1,
  WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_DELETED = 2,
  WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT = 3,
} wyl_service_credential_handoff_remediation_escrow_outcome_t;

typedef struct
{
  const gchar *remediation_request_id;
  const gchar *decision_request_id;
  const gchar *current_actor_subject_id;
  const gchar *audit_id;
  wyl_service_credential_handoff_exact_tuple_t tuple;
  wyl_service_credential_handoff_remediation_action_t action;
  guint32 confirmation_version;
  gboolean confirmed;
  wyl_service_credential_handoff_remediation_source_kind_t source_kind;
  guint8 journal_snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  wyl_service_credential_handoff_remediation_journal_state_t observed_state;
  const gchar *source_disposition_id;
  const gchar *source_audit_id;
  wyl_service_credential_handoff_disposition_reason_t source_reason;
  wyl_service_credential_handoff_remediation_journal_state_t oar_source_state;
  wyl_service_credential_handoff_remediation_oar_cause_t oar_cause;
    wyl_service_credential_handoff_remediation_journal_state_t
      resume_target_state;
} wyl_service_credential_handoff_remediation_input_t;

typedef struct
{
  gboolean replayed;
  gboolean revoked_now;
  gchar *remediation_request_id;
  wyl_service_credential_handoff_remediation_action_t action;
  guint32 confirmation_version;
  gboolean confirmed;
  gint64 created_at_us;
  wyl_service_credential_handoff_remediation_outcome_t outcome;
  wyl_service_credential_handoff_remediation_escrow_outcome_t escrow_outcome;
  guint64 invalidation_generation;
  guint64 credential_generation_after;
  gint64 revoke_event_id;
  guint64 revoke_event_generation;
  gchar *revoke_event_request_id;
  gchar *revoke_event_actor_subject_id;
  gint64 revoke_event_created_at_us;
  wyl_service_credential_handoff_remediation_source_kind_t source_kind;
  guint8 journal_snapshot_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  guint8 request_fingerprint[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  wyl_service_credential_handoff_remediation_journal_state_t observed_state;
  wyl_service_credential_handoff_remediation_journal_state_t oar_source_state;
  wyl_service_credential_handoff_remediation_oar_cause_t oar_cause;
    wyl_service_credential_handoff_remediation_journal_state_t
      resume_target_state;
  wyl_service_credential_handoff_disposition_reason_t source_reason;
  gchar *decision_request_id;
  gchar *current_actor_subject_id;
  gchar *original_request_id;
  gchar *original_actor_subject_id;
  gchar *source_disposition_id;
  gchar *source_audit_id;
  gchar escrow_id[WYL_ID_STRING_BUF];
  guint8 binding_digest[WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES];
  gchar successor_credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint64 successor_issuance_generation;
  gchar *audit_id;
} wyl_service_credential_handoff_remediation_result_t;

typedef struct
{
  const wyl_service_credential_mutation_authorization_t *authorization;
    wyrelog_error_t (*invalidate_credential) (gpointer data,
      const gchar * credential_id, guint64 generation);
  gpointer invalidation_data;
} wyl_service_credential_handoff_remediation_runtime_t;

typedef wyrelog_error_t (*wyl_service_principal_cb) (const
    wyl_service_principal_t * principal, gpointer user_data);
typedef wyrelog_error_t (*wyl_service_credential_cb) (const
    wyl_service_credential_t * credential, gpointer user_data);

/* Owned-output contract for create/get/disable:
 * - On first use, out MUST be initialized to { 0 }.
 * - A later call may reuse an object previously populated or cleared by one
 *   of these APIs; the API clears it before validating other arguments.
 * - Input strings MUST NOT alias strings currently owned by out.
 * - On success, all non-NULL strings in out are caller-owned and released by
 *   wyl_service_principal_clear(). Every failure leaves out cleared.
 *
 * The principal and all of its strings passed to a foreach callback are
 * borrowed only for the duration of that callback. Callers that retain any
 * value after returning MUST make a deep copy.
 */
void wyl_service_principal_clear (wyl_service_principal_t * principal);
wyrelog_error_t wyl_service_principal_create (WylHandle * handle,
    const gchar * subject_id, const gchar * display_name,
    const gchar * actor_subject_id, const gchar * request_id,
    wyl_service_principal_t * out);
wyrelog_error_t wyl_service_principal_get (WylHandle * handle,
    const gchar * subject_id, wyl_service_principal_t * out);
wyrelog_error_t wyl_service_principal_foreach (WylHandle * handle,
    wyl_service_principal_cb cb, gpointer user_data);
wyrelog_error_t wyl_service_principal_disable (WylHandle * handle,
    const gchar * subject_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_service_principal_t * out);

/* Credential outputs follow the same zero-init, non-aliasing, caller-owned,
 * reuse and failure-clears contract above. Issue or rotation success transfers
 * the opaque locked secret; clear the result to wipe and release it. Credential
 * DTOs deliberately contain no salt, verifier or CVK. Foreach DTOs and their
 * strings are borrowed only during the callback and require a deep copy to
 * retain. A successful issue or rotation is the only opportunity to obtain
 * the corresponding new secret. */
void wyl_service_credential_clear (wyl_service_credential_t * credential);
void wyl_service_credential_issue_result_clear
    (wyl_service_credential_issue_result_t * result);
void wyl_service_credential_handoff_clear
    (wyl_service_credential_handoff_t * handoff);
void wyl_service_credential_handoff_result_clear
    (wyl_service_credential_handoff_result_t * result);
wyrelog_error_t wyl_service_credential_issue (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us, wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_issue_with_runtime
    (WylHandle * handle, const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us,
    const wyl_service_credential_issue_runtime_t * runtime,
    wyl_service_credential_issue_result_t * out);
/* Creates or idempotently replays one credential into store-owned escrow.
 * No plaintext secret crosses this API. handoff and all runtime descriptors
 * are borrowed only until the call returns. */
wyrelog_error_t wyl_service_credential_issue_handoff_with_runtime
    (WylHandle * handle, const gchar * subject_id, const gchar * tenant_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 expires_at_us,
    const wyl_service_credential_handoff_request_t * handoff,
    const wyl_service_credential_issue_runtime_t * runtime,
    wyl_service_credential_handoff_result_t * out);
wyrelog_error_t wyl_service_credential_get (WylHandle * handle,
    const gchar * credential_id, wyl_service_credential_t * out);
wyrelog_error_t wyl_service_credential_foreach (WylHandle * handle,
    const gchar * subject_id, const gchar * tenant_id,
    wyl_service_credential_cb cb, gpointer user_data);
/* Named authoritative to avoid colliding with the lower-level codec symbol.
 * This API derives subject and tenant solely from the canonical credential ID.
 * It is read-only: no last-used, audit, session or token state is mutated.
 *
 * The optional runtime, its credential callback table and data are borrowed
 * only until the call returns. before_gate is a deterministic private test
 * checkpoint immediately before gate acquisition. Clock and credential
 * callbacks execute while the service-domain gate is held. All callbacks MUST
 * be non-reentrant and MUST NOT call APIs on the same handle, policy store or
 * service domain. */
wyrelog_error_t wyl_service_credential_verify_authoritative
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    gboolean * out_authenticated);
wyrelog_error_t wyl_service_credential_verify_authoritative_with_runtime
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    const wyl_service_credential_verify_runtime_t * runtime,
    gboolean * out_authenticated);
wyrelog_error_t wyl_service_credential_revoke (WylHandle * handle,
    const gchar * credential_id, const gchar * actor_subject_id,
    const gchar * request_id, wyl_service_credential_t * out);
wyrelog_error_t wyl_service_credential_revoke_with_runtime
    (WylHandle * handle, const gchar * credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    const wyl_service_credential_revoke_runtime_t * runtime,
    wyl_service_credential_t * out);
void wyl_service_credential_handoff_disposition_result_clear
    (wyl_service_credential_handoff_disposition_result_t * result);
G_GNUC_INTERNAL void wyl_service_credential_handoff_cancellation_result_clear
    (wyl_service_credential_handoff_cancellation_result_t * result);
G_GNUC_INTERNAL void wyl_service_credential_handoff_remediation_result_clear
    (wyl_service_credential_handoff_remediation_result_t * result);
wyrelog_error_t wyl_service_credential_handoff_record_disposition
    (WylHandle * handle,
    const wyl_service_credential_handoff_disposition_input_t * input,
    wyl_service_credential_handoff_disposition_result_t * out_result);
wyrelog_error_t wyl_service_credential_handoff_record_not_committed
    (WylHandle * handle,
    const wyl_service_credential_handoff_disposition_input_t * input,
    wyl_service_credential_handoff_disposition_result_t * out_result);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_claim_cancellation
    (WylHandle * handle,
    const wyl_service_credential_handoff_cancellation_input_t * input,
    const wyl_service_credential_handoff_cancellation_runtime_t * runtime,
    wyl_service_credential_handoff_cancellation_result_t * out_result);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_remediate_exact
    (WylHandle * handle,
    const wyl_service_credential_handoff_remediation_input_t * input,
    const wyl_service_credential_handoff_remediation_runtime_t * runtime,
    wyl_service_credential_handoff_remediation_result_t * out_result);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_resolve_remediation
    (WylHandle * handle, const gchar * remediation_request_id,
    const gchar * current_actor_subject_id,
    const wyl_service_credential_handoff_remediation_runtime_t * runtime,
    wyl_service_credential_handoff_remediation_result_t * out_result);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_resolve_remediation_incident
    (WylHandle * handle, const gchar * original_request_id,
    const guint8 journal_snapshot_digest
    [WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    wyl_service_credential_handoff_remediation_result_t * out_result);
/* Rotation derives subject and tenant from old_credential_id and returns the
 * successor secret exactly once, only after the local savepoint is released.
 *
 * The rotate runtime object, now_us callback and runtime->data are borrowed
 * and need remain valid only until this call returns. The nested
 * credential_runtime pointer is likewise borrowed only for the call, but its
 * callback table (including its own data pointer value) is copied into a
 * successfully returned secret. Consequently, credential callback code,
 * targets and credential_runtime->data MUST remain valid until that secret is
 * cleared. On failure or when no secret is returned, those lifetimes need only
 * extend through this call. rotate runtime has no before-gate/checkpoint
 * callback; the store-scoped fault seam owns no callback or data lifetime.
 *
 * Clock and credential callbacks may run under the domain gate, and credential
 * callbacks may also run under the lifecycle mutex. They MUST be non-reentrant
 * and MUST NOT call APIs on the same handle, store or service domain. The
 * optional authorization descriptor is borrowed only for the call and follows
 * the execution-boundary contract above. */
wyrelog_error_t wyl_service_credential_rotate (WylHandle * handle,
    const gchar * old_credential_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 new_expires_at_us,
    wyl_service_credential_issue_result_t * out);
wyrelog_error_t wyl_service_credential_rotate_with_runtime
    (WylHandle * handle, const gchar * old_credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 new_expires_at_us,
    const wyl_service_credential_rotate_runtime_t * runtime,
    wyl_service_credential_issue_result_t * out);
/* Escrow-backed checked rotation. runtime->old_credential_generation must be
 * non-zero and is used by the authoritative rotate CAS. No plaintext secret
 * crosses this API; handoff and runtime are borrowed only for the call. */
wyrelog_error_t wyl_service_credential_rotate_handoff_checked_with_runtime
    (WylHandle * handle, const gchar * old_credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 new_expires_at_us,
    const wyl_service_credential_handoff_request_t * handoff,
    const wyl_service_credential_rotate_runtime_t * runtime,
    wyl_service_credential_handoff_result_t * out);

G_END_DECLS
