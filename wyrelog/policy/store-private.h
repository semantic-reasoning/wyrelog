/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <sqlite3.h>

#include "wyrelog/decide.h"
#include "wyrelog/error.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/wyl-traits-private.h"

G_BEGIN_DECLS;

#define WYL_POLICY_FACT_QUERY_DEFAULT_MAX_ROWS 1000
#define WYL_POLICY_FACT_QUERY_MAX_ROWS 1000000

typedef struct wyl_policy_store_t wyl_policy_store_t;
typedef struct _WylServiceAuthorityTransaction WylServiceAuthorityTransaction;

typedef enum
{
  WYL_SERVICE_AUTHORITY_TXN_ACTIVE,
  WYL_SERVICE_AUTHORITY_TXN_COMMITTED,
  WYL_SERVICE_AUTHORITY_TXN_ROLLED_BACK,
  WYL_SERVICE_AUTHORITY_TXN_FAILED_COMMIT,
  WYL_SERVICE_AUTHORITY_TXN_FAILED_ROLLBACK,
} WylServiceAuthorityTransactionState;

typedef enum
{
  WYL_POLICY_AUTHORITY_TXN_FAIL_NONE,
  WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE,
  WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER,
  WYL_POLICY_AUTHORITY_TXN_FAIL_ROLLBACK,
  WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK,
} WylPolicyAuthorityTransactionFailStage;

typedef struct wyl_policy_store_cvk_runtime_t
{
  gpointer (*secure_alloc) (gpointer data, gsize size);
  int (*secure_lock) (gpointer data, gpointer ptr, gsize size);
  void (*secure_wipe) (gpointer data, gpointer ptr, gsize size);
  int (*secure_unlock) (gpointer data, gpointer ptr, gsize size);
  void (*secure_free) (gpointer data, gpointer ptr);
  int (*fill_random) (gpointer data, guint8 * out, gsize len);
    gint64 (*now_us) (gpointer data);
  gpointer data;
} wyl_policy_store_cvk_runtime_t;

typedef enum
{
  WYL_POLICY_ROTATION_BEFORE_CVK_CAS = 1,
  WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME = 2,
  WYL_POLICY_ROTATION_AFTER_CANONICAL_RENAME = 3,
} wyl_policy_store_rotation_stage_t;

typedef struct
{
  int (*checkpoint) (gpointer data, wyl_policy_store_rotation_stage_t stage);
  gpointer data;
} wyl_policy_store_rotation_runtime_t;

typedef enum
{
  WYL_POLICY_SERVICE_ROTATE_FAIL_NONE = 0,
  WYL_POLICY_SERVICE_ROTATE_FAIL_INSERT,
  WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_UPDATE,
  WYL_POLICY_SERVICE_ROTATE_FAIL_SUCCESSOR_EVENT,
  WYL_POLICY_SERVICE_ROTATE_FAIL_OLD_EVENT,
  WYL_POLICY_SERVICE_ROTATE_FAIL_AUDIT,
  WYL_POLICY_SERVICE_ROTATE_FAIL_INTENTION,
  WYL_POLICY_SERVICE_ROTATE_FAIL_VALIDATOR,
} wyl_policy_service_rotate_fail_stage_t;

/* rotation_runtime is a private, per-call fault seam. rotate_keyprovider uses
 * only old_opts->rotation_runtime and the CVK runtime snapshotted while opening
 * the old store. new_opts runtime pointers are neither adopted nor invoked. */

/* service_cvk_runtime is copied by value during open. Callback functions and
 * data are borrowed, not owned: their code and data context must remain valid
 * and callable until wyl_policy_store_close() has returned. */

/* KeyProvider configuration and ownership:
 *
 * When opts and out_store are both non-NULL, a non-NULL keyprovider_state is
 * transferred immediately on every return path. The caller MUST NOT invoke
 * provider operations or wipe it afterward. A successful open retains the
 * state until store close; a failed open releases it before returning. When
 * keyprovider_state_free is non-NULL, the caller also MUST NOT release it:
 * Wyrelog invokes wipe exactly once when that callback is available, then
 * invokes keyprovider_state_free exactly once.
 *
 * A providerless configuration has keyprovider_vtable, keyprovider_state, and
 * keyprovider_state_free all NULL. Any other configuration requires non-NULL
 * vtable and state plus probe, seal, unseal, derive, wipe, and
 * clear_sealed_blob callbacks; keyprovider_state_free remains optional. The
 * vtable is copied by value at adoption and may be mutated or released by its
 * caller after entry without affecting the store.
 *
 * A NULL keyprovider_state_free does not prevent transfer. Wyrelog still
 * invokes wipe exactly once when available but does not deallocate the backing
 * storage. That storage MUST outlive a successful store handle. The caller may
 * reclaim it only after store close, or after a failed open has returned; it
 * MUST NOT be reused as KeyProvider state. Invalid partial configurations are
 * also released using only their available lifecycle callbacks.
 *
 * If opts or out_store is NULL, entry validation fails without transfer or
 * lifecycle callbacks. A WYRELOG_E_BUSY return invokes none of the operational
 * callbacks (probe, seal, unseal, or derive), while still releasing the
 * transferred state before return using its available lifecycle callbacks.
 * For file-backed configured opens, lease acquisition precedes provider-shape
 * validation so BUSY retains precedence.
 * See "Policy-store provider ownership" in docs/developer-lifecycle.md.
 */
typedef struct
{
  const gchar *path;
  const wyl_keyprovider_vtable_t *keyprovider_vtable;
  gpointer keyprovider_state;
  void (*keyprovider_state_free) (gpointer state);
  gboolean require_encrypted;
  const wyl_policy_store_cvk_runtime_t *service_cvk_runtime;
  const wyl_policy_store_rotation_runtime_t *rotation_runtime;
} wyl_policy_store_open_options_t;

typedef wyrelog_error_t (*wyl_policy_role_permission_cb) (const gchar * role_id,
    const gchar * perm_id, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_inheritance_cb) (const gchar *
    child_role_id, const gchar * parent_role_id, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_membership_cb) (const gchar *
    subject_id, const gchar * role_id, const gchar * scope, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_membership_event_cb) (const gchar *
    subject_id, const gchar * role_id, const gchar * scope,
    const gchar * operation, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_direct_permission_cb) (const gchar *
    subject_id, const gchar * perm_id, const gchar * scope, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_direct_permission_event_cb) (const gchar *
    subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * operation, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_permission_state_cb) (const gchar *
    subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_permission_state_event_cb) (gint64
    event_id, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope, const gchar * event, const gchar * from_state,
    const gchar * to_state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_principal_state_cb) (const gchar *
    subject_id, const gchar * state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_principal_event_cb) (gint64 event_id,
    const gchar * subject_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_session_state_cb) (const gchar *
    session_id, const gchar * state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_session_event_cb) (gint64 event_id,
    const gchar * session_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_audit_event_cb) (const gchar * id,
    gint64 created_at_us, const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, const gchar * request_id,
    wyl_decision_t decision, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_audit_intention_cb) (const gchar * id,
    gint64 created_at_us, const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, const gchar * request_id,
    wyl_decision_t decision, const gchar * state, gint64 attempt_count,
    const gchar * last_error, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_tenant_cb) (const gchar * tenant_id,
    gboolean sealed, gpointer user_data);

typedef struct
{
  const gchar *column_name;
  const gchar *column_type;
} wyl_policy_fact_graph_column_t;

typedef struct
{
  const gchar *relation_name;
  const wyl_policy_fact_graph_column_t *columns;
  gsize n_columns;
} wyl_policy_fact_graph_relation_t;

typedef struct
{
  const gchar *query_name;
  const gchar *relation_name;
  const gchar *required_permission_id;
  guint max_rows;
} wyl_policy_fact_graph_query_t;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *fact_root;
  guint32 schema_version;
  const gchar *owner_scope;
  const wyl_policy_fact_graph_relation_t *relations;
  gsize n_relations;
  const wyl_policy_fact_graph_query_t *queries;
  gsize n_queries;
} wyl_policy_fact_graph_create_options_t;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *storage_uri;
  const gchar *storage_path;
  guint32 schema_version;
  const gchar *owner_scope;
  gboolean sealed;
} wyl_policy_fact_graph_info_t;

typedef wyrelog_error_t (*wyl_policy_fact_graph_cb) (const
    wyl_policy_fact_graph_info_t * info, gpointer user_data);

typedef struct
{
  const gchar *column_name;
  const gchar *column_type;
  gboolean nullable;
  gboolean visible;
} wyl_policy_fact_relation_schema_column_t;

typedef struct
{
  const gchar *query_name;
  const gchar *required_permission_id;
  guint max_rows;
} wyl_policy_fact_relation_schema_query_t;

typedef struct
{
  const gchar *tenant_id;
  const gchar *graph_id;
  const gchar *namespace_id;
  const gchar *relation_name;
  guint32 schema_version;
  gboolean relation_visible;
  const wyl_policy_fact_relation_schema_column_t *columns;
  gsize n_columns;
  const wyl_policy_fact_relation_schema_query_t *queries;
  gsize n_queries;
} wyl_policy_fact_relation_schema_options_t;

typedef struct
{
  gchar *column_name;
  gchar *column_type;
  gboolean nullable;
  gboolean visible;
} wyl_policy_fact_relation_schema_column_info_t;

typedef struct
{
  gchar *namespace_id;
  gchar *relation_name;
  guint32 schema_version;
  gchar *query_name;
  gchar *required_permission_id;
  guint max_rows;
} wyl_policy_fact_relation_query_info_t;

typedef enum
{
  WYL_POLICY_PRINCIPAL_KIND_UNKNOWN = 0,
  WYL_POLICY_PRINCIPAL_KIND_HUMAN,
  WYL_POLICY_PRINCIPAL_KIND_SERVICE,
} wyl_policy_principal_kind_t;

typedef struct
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
} wyl_policy_service_principal_info_t;

typedef struct
{
  gchar *credential_id;
  guint32 credential_format_version;
  gchar *subject_id;
  gchar *tenant_id;
  guint64 generation;
  gchar *state;
  guint32 verifier_version;
  guint8 salt[16];
  guint8 verifier[32];
  gchar *created_by;
  gint64 created_at_us;
  gint64 updated_at_us;
  gint64 expires_at_us;
  gint64 last_used_at_us;
  gchar *revoked_by;
  gint64 revoked_at_us;
  gchar *rotated_from_id;
} wyl_policy_service_credential_info_t;

typedef struct
{
  guint64 generation;
  guint32 envelope_format_version;
  guint8 provider_binding[32];
  guint8 *sealed_cvk;
  gsize sealed_cvk_len;
  gint64 created_at_us;
  gint64 updated_at_us;
} wyl_policy_service_cvk_info_t;

typedef struct
{
  gint64 event_id;
  gchar *subject_id;
  gchar *event;
  gchar *from_state;
  gchar *to_state;
  guint64 generation;
  gchar *actor_subject_id;
  gchar *request_id;
  gint64 created_at_us;
} wyl_policy_service_principal_event_info_t;

typedef struct
{
  gint64 event_id;
  gchar *credential_id;
  gchar *subject_id;
  gchar *tenant_id;
  gchar *event;
  gchar *from_state;
  gchar *to_state;
  guint64 generation;
  gchar *actor_subject_id;
  gchar *request_id;
  gchar *related_credential_id;
  gint64 created_at_us;
} wyl_policy_service_credential_event_info_t;

typedef wyrelog_error_t (*wyl_policy_service_principal_cb) (const
    wyl_policy_service_principal_info_t * info, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_service_credential_cb) (const
    wyl_policy_service_credential_info_t * info, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_service_principal_event_cb) (const
    wyl_policy_service_principal_event_info_t * info, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_service_credential_event_cb) (const
    wyl_policy_service_credential_event_info_t * info, gpointer user_data);

gboolean wyl_policy_service_subject_is_valid (const gchar * subject_id,
    gsize subject_id_len);
/* Lexical namespace reservation used by human-auth ingress.  This deliberately
 * recognizes malformed identifiers too: every lowercase `svc:` prefix belongs
 * to the service namespace and must never fall back to a human identity path. */
gboolean wyl_policy_subject_has_service_prefix (const gchar * subject_id);
void wyl_policy_service_principal_info_clear
    (wyl_policy_service_principal_info_t * info);
void wyl_policy_service_credential_info_clear
    (wyl_policy_service_credential_info_t * info);
void wyl_policy_service_cvk_info_clear (wyl_policy_service_cvk_info_t * info);
void wyl_policy_service_principal_event_info_clear
    (wyl_policy_service_principal_event_info_t * info);
void wyl_policy_service_credential_event_info_clear
    (wyl_policy_service_credential_event_info_t * info);

void wyl_policy_fact_relation_schema_columns_free
    (wyl_policy_fact_relation_schema_column_info_t * columns, gsize n_columns);
void wyl_policy_fact_relation_query_info_clear
    (wyl_policy_fact_relation_query_info_t * info);

/*
 * Policy authority store lifecycle wrapper.
 *
 * v0 uses SQLite directly so the handle owns a real ACID policy DB before
 * SQLCipher key negotiation is wired in. The private boundary keeps callers
 * out of the raw sqlite3 handle except for tests and future migrator code.
 */
wyrelog_error_t wyl_policy_store_open (const gchar * path,
    wyl_policy_store_t ** out_store);
/* Consumes opts->keyprovider_state according to the ownership contract on
 * wyl_policy_store_open_options_t above. */
wyrelog_error_t wyl_policy_store_open_with_options (const
    wyl_policy_store_open_options_t * opts, wyl_policy_store_t ** out_store);
/* Basic invalid rotation arguments (empty path, NULL options, or aliased
 * non-NULL old/new state) transfer neither state. Otherwise both states are
 * consumed on every outcome and released exactly once before return. */
wyrelog_error_t wyl_policy_store_rotate_keyprovider (const gchar * path,
    const wyl_policy_store_open_options_t * old_opts,
    const wyl_policy_store_open_options_t * new_opts);
void wyl_policy_store_close (wyl_policy_store_t * store);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_policy_store_t, wyl_policy_store_close);

sqlite3 *wyl_policy_store_get_db (wyl_policy_store_t * store);

wyrelog_error_t wyl_policy_store_begin_mutation (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_commit_mutation (wyl_policy_store_t * store);
void wyl_policy_store_rollback_mutation (wyl_policy_store_t * store);

wyrelog_error_t wyl_policy_store_create_schema (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_validate_service_schema
    (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_validate_snapshot (wyl_policy_store_t * store);

/*
 * Starts a non-nestable SQLite savepoint while claiming |write_lease| and
 * owning the store's service-domain gate and lifecycle lock. The lease, store,
 * and handle must all belong to the same live handle. Terminal transactions
 * retain their result metadata until freed, but own no locks or lease claim.
 */
wyrelog_error_t wyl_policy_store_service_authority_transaction_begin
    (wyl_policy_store_t * store, WylHandle * handle,
    WylServiceAuthWriteLease * write_lease,
    WylServiceAuthorityTransaction ** out_transaction);
wyrelog_error_t wyl_policy_store_service_authority_transaction_commit
    (WylServiceAuthorityTransaction * transaction);
wyrelog_error_t wyl_policy_store_service_authority_transaction_rollback
    (WylServiceAuthorityTransaction * transaction);
wyrelog_error_t wyl_policy_store_service_authority_transaction_abort
    (WylServiceAuthorityTransaction * transaction);
WylServiceAuthorityTransactionState
    wyl_policy_store_service_authority_transaction_get_state
    (const WylServiceAuthorityTransaction * transaction);
wyrelog_error_t
wyl_policy_store_service_authority_transaction_get_primary_result (const
    WylServiceAuthorityTransaction * transaction);
wyrelog_error_t
wyl_policy_store_service_authority_transaction_get_cleanup_result (const
    WylServiceAuthorityTransaction * transaction);
int
wyl_policy_store_service_authority_transaction_get_primary_sqlite_extended_error
    (const WylServiceAuthorityTransaction * transaction);
int
wyl_policy_store_service_authority_transaction_get_recovery_sqlite_extended_error
    (const WylServiceAuthorityTransaction * transaction);
void wyl_policy_store_service_authority_transaction_set_abort_checkpoint
    (WylServiceAuthorityTransaction * transaction,
    void (*checkpoint) (gpointer data), gpointer data);
void wyl_policy_store_service_authority_transaction_free
    (WylServiceAuthorityTransaction * transaction);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthorityTransaction,
    wyl_policy_store_service_authority_transaction_free);

/* Deterministic private fault and observation seams for transaction tests. */
void wyl_policy_store_service_authority_transaction_fail_once
    (wyl_policy_store_t * store, WylPolicyAuthorityTransactionFailStage stage);
gboolean wyl_policy_store_service_authority_transaction_is_poisoned
    (wyl_policy_store_t * store);

/* Owned-output contract for the service lookup/load APIs below:
 * - On first use, the caller MUST pass an output initialized to { 0 }.
 * - A later call may reuse an object previously populated by the matching API;
 *   the API clears its owned fields before validating any other argument.
 * - Input strings MUST NOT alias strings owned by the output object.
 * - Success transfers ownership of output fields to the caller. Every failure
 *   leaves the output cleared, including fixed and dynamically sized secrets.
 * Foreach callback rows are borrowed and remain valid only during the callback.
 */
wyrelog_error_t wyl_policy_store_get_principal_kind (wyl_policy_store_t * store,
    const gchar * subject_id, wyl_policy_principal_kind_t * out_kind);
/* Service lifecycle mutations are serialized against other service-domain
 * calls. Issuance additionally holds the domain gate across CVK initialization
 * and lifecycle-mutex acquisition so there is no cross-operation DB handoff
 * race. Concurrent entry by another policy
 * writer or reconciler on the same store violates the daemon single-writer /
 * caller-serialization contract. External mirrors must run only after the
 * domain mutation has returned successfully; they are not part of its local
 * SQLite savepoint.
 */
wyrelog_error_t wyl_policy_store_create_service_principal
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * display_name, const gchar * actor_subject_id,
    const gchar * request_id, wyl_policy_service_principal_info_t * out);
wyrelog_error_t wyl_policy_store_disable_service_principal
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * actor_subject_id, const gchar * request_id,
    wyl_policy_service_principal_info_t * out);
/* Test seam: fail the next service lifecycle operation after validation but
 * before savepoint release. The operation must roll all local rows back. */
void wyl_policy_store_service_lifecycle_fail_commit_once
    (wyl_policy_store_t * store);
void wyl_policy_store_service_rotate_fail_once (wyl_policy_store_t * store,
    wyl_policy_service_rotate_fail_stage_t stage);
wyrelog_error_t wyl_policy_store_lookup_service_principal (wyl_policy_store_t *
    store, const gchar * subject_id, wyl_policy_service_principal_info_t * out);
wyrelog_error_t wyl_policy_store_foreach_service_principal (wyl_policy_store_t *
    store, wyl_policy_service_principal_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_lookup_service_credential (wyl_policy_store_t *
    store, const gchar * credential_id, const gchar * subject_id,
    const gchar * tenant_id, wyl_policy_service_credential_info_t * out);
wyrelog_error_t wyl_policy_store_lookup_service_credential_by_id
    (wyl_policy_store_t * store, const gchar * credential_id,
    wyl_policy_service_credential_info_t * out);
wyrelog_error_t wyl_policy_store_foreach_service_credential (wyl_policy_store_t
    * store, const gchar * subject_id, const gchar * tenant_id,
    wyl_policy_service_credential_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_load_service_cvk (wyl_policy_store_t * store,
    wyl_policy_service_cvk_info_t * out);
wyrelog_error_t wyl_policy_store_materialize_service_cvk_existing
    (wyl_policy_store_t * store, const guint8 ** out_cvk, gsize * out_len);
wyrelog_error_t wyl_policy_store_ensure_service_cvk_for_issuance
    (wyl_policy_store_t * store, const guint8 ** out_cvk, gsize * out_len);
/* Issuance initializes/materializes the CVK before its lifecycle savepoint.
 * A later domain failure may therefore leave only the idempotent CVK row;
 * credential, event, ledger and audit rows still roll back together. */
wyrelog_error_t wyl_policy_store_issue_service_credential
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * tenant_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 expires_at_us,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret);
/* Deterministic private seam for collision/wipe and fault tests.
 *
 * runtime itself is borrowed only for this call; its callback table is copied
 * by value before use. The callback code and targets, plus runtime->data, MUST
 * remain valid until any successfully returned opaque secret has been fully
 * released with wyl_service_credential_secret_clear(). On failure, or when no
 * secret is returned, all generated secrets are synchronously cleared, so
 * these lifetimes need not extend past this function's return.
 *
 * Runtime callbacks may execute while the service-domain gate and lifecycle
 * mutex are held. They MUST be non-reentrant and MUST NOT call APIs on the same
 * store or service domain; doing so can deadlock.
 */
wyrelog_error_t wyl_policy_store_issue_service_credential_with_runtime
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * tenant_id, const gchar * actor_subject_id,
    const gchar * request_id, gint64 expires_at_us,
    const wyl_service_credential_runtime_t * runtime,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret);
/* Verification runtimes and their callback data are borrowed only for this
 * call. before_gate is a deterministic test checkpoint immediately before
 * gate acquisition. The clock and credential callbacks run under the
 * service-domain gate. All callbacks MUST be non-reentrant: calling the same
 * store or service-domain APIs from a callback can deadlock. */
wyrelog_error_t wyl_policy_store_verify_service_credential_by_id
    (wyl_policy_store_t * store, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    void (*before_gate) (gpointer data),
    gint64 (*now_us) (gpointer data), gpointer now_data,
    const wyl_service_credential_runtime_t * runtime,
    gboolean * out_authenticated);
wyrelog_error_t wyl_policy_store_revoke_service_credential
    (wyl_policy_store_t * store, const gchar * credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    wyl_policy_service_credential_info_t * out);
/* now_us and now_data are borrowed and need remain valid only until this call
 * returns. runtime itself is likewise borrowed only for the call. Its callback
 * table, including the runtime->data pointer value, is copied into a
 * successfully returned secret, so that callback code, targets and data MUST
 * remain valid until wyl_service_credential_secret_clear() releases the
 * secret. On failure or when no secret is returned, those lifetimes need only
 * extend through this call. The store-scoped rotate fault seam owns no callback
 * or data lifetime.
 *
 * Clock and credential callbacks execute under the service-domain gate;
 * credential generation also holds the lifecycle mutex. They MUST be
 * non-reentrant and MUST NOT call APIs on the same store or service domain. */
wyrelog_error_t wyl_policy_store_rotate_service_credential
    (wyl_policy_store_t * store, const gchar * old_credential_id,
    const gchar * actor_subject_id, const gchar * request_id,
    gint64 new_expires_at_us, gint64 (*now_us) (gpointer data),
    gpointer now_data, const wyl_service_credential_runtime_t * runtime,
    wyl_policy_service_credential_info_t * out,
    wyl_service_credential_secret_t ** out_secret);
wyrelog_error_t wyl_policy_store_verify_service_credential_secret
    (wyl_policy_store_t * store,
    const wyl_policy_service_credential_info_t * credential,
    const gchar * presented_secret, gsize presented_secret_len,
    gboolean * out_match);
wyrelog_error_t wyl_policy_store_foreach_service_principal_event
    (wyl_policy_store_t * store, const gchar * subject_id,
    wyl_policy_service_principal_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_foreach_service_credential_event
    (wyl_policy_store_t * store, const gchar * credential_id,
    const gchar * subject_id, const gchar * tenant_id,
    wyl_policy_service_credential_event_cb cb, gpointer user_data);
gsize wyl_policy_store_required_table_count (void);
const gchar *wyl_policy_store_required_table_name (gsize idx);
gsize wyl_policy_store_builtin_role_count (void);
const gchar *wyl_policy_store_builtin_role_id (gsize idx);
gsize wyl_policy_store_builtin_permission_count (void);
const gchar *wyl_policy_store_builtin_permission_id (gsize idx);
wyrelog_error_t wyl_policy_store_table_exists (wyl_policy_store_t * store,
    const gchar * table_name, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_set_deployment_mode (wyl_policy_store_t *
    store, const gchar * mode);
wyrelog_error_t wyl_policy_store_get_deployment_mode (wyl_policy_store_t *
    store, gchar ** out_mode);
gboolean wyl_policy_store_tenant_id_is_valid (const gchar * tenant_id);
wyrelog_error_t wyl_policy_store_ensure_default_tenant (wyl_policy_store_t *
    store);
wyrelog_error_t wyl_policy_store_create_tenant (wyl_policy_store_t * store,
    const gchar * tenant_id, gboolean * out_created);
wyrelog_error_t wyl_policy_store_set_tenant_sealed (wyl_policy_store_t * store,
    const gchar * tenant_id, gboolean sealed);
wyrelog_error_t wyl_policy_store_tenant_exists (wyl_policy_store_t * store,
    const gchar * tenant_id, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_tenant_is_active (wyl_policy_store_t * store,
    const gchar * tenant_id, gboolean * out_active);
wyrelog_error_t wyl_policy_store_foreach_tenant (wyl_policy_store_t * store,
    wyl_policy_tenant_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_create_fact_graph (wyl_policy_store_t * store,
    const wyl_policy_fact_graph_create_options_t * opts,
    gchar ** out_storage_uri);
wyrelog_error_t wyl_policy_store_foreach_fact_graph (wyl_policy_store_t *
    store, const gchar * tenant_id, wyl_policy_fact_graph_cb cb,
    gpointer user_data);
wyrelog_error_t wyl_policy_store_seal_fact_graph (wyl_policy_store_t * store,
    const gchar * tenant_id, const gchar * graph_id);
wyrelog_error_t wyl_policy_store_fact_graph_is_active (wyl_policy_store_t *
    store, const gchar * tenant_id, const gchar * graph_id,
    gboolean * out_active);
wyrelog_error_t wyl_policy_store_register_fact_relation_schema
    (wyl_policy_store_t * store,
    const wyl_policy_fact_relation_schema_options_t * opts);
wyrelog_error_t wyl_policy_store_load_fact_relation_schema_columns
    (wyl_policy_store_t * store, const gchar * tenant_id,
    const gchar * graph_id, const gchar * namespace_id,
    const gchar * relation_name, guint32 schema_version,
    gboolean * out_relation_visible,
    wyl_policy_fact_relation_schema_column_info_t ** out_columns,
    gsize * out_n_columns);
wyrelog_error_t wyl_policy_store_load_fact_relation_query
    (wyl_policy_store_t * store, const gchar * tenant_id,
    const gchar * graph_id, const gchar * query_name,
    wyl_policy_fact_relation_query_info_t * out_info);
wyrelog_error_t wyl_policy_store_upsert_role (wyl_policy_store_t * store,
    const gchar * role_id, const gchar * role_name);
wyrelog_error_t wyl_policy_store_upsert_permission (wyl_policy_store_t * store,
    const gchar * perm_id, const gchar * perm_name, const gchar * klass);
wyrelog_error_t wyl_policy_store_role_exists (wyl_policy_store_t * store,
    const gchar * role_id, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_permission_exists (wyl_policy_store_t * store,
    const gchar * perm_id, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_grant_role_permission (wyl_policy_store_t *
    store, const gchar * role_id, const gchar * perm_id);
wyrelog_error_t wyl_policy_store_foreach_role_permission (wyl_policy_store_t *
    store, wyl_policy_role_permission_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_role_inheritance (wyl_policy_store_t *
    store, const gchar * child_role_id, const gchar * parent_role_id);
wyrelog_error_t wyl_policy_store_foreach_role_inheritance (wyl_policy_store_t *
    store, wyl_policy_role_inheritance_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_role_membership (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope);
wyrelog_error_t wyl_policy_store_revoke_role_membership (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope);
wyrelog_error_t
wyl_policy_store_apply_role_membership_mutation (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * role_id, const gchar * scope,
    gboolean insert);
wyrelog_error_t
    wyl_policy_store_apply_role_membership_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * role_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, const gchar * audit_request_id,
    wyl_decision_t audit_decision);
wyrelog_error_t wyl_policy_store_role_membership_exists (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_foreach_role_membership (wyl_policy_store_t *
    store, wyl_policy_role_membership_cb cb, gpointer user_data);
wyrelog_error_t
wyl_policy_store_append_role_membership_event (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * role_id, const gchar * scope,
    const gchar * operation);
wyrelog_error_t
wyl_policy_store_foreach_role_membership_event (wyl_policy_store_t * store,
    wyl_policy_role_membership_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_direct_permission (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope);
wyrelog_error_t wyl_policy_store_revoke_direct_permission (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope);
wyrelog_error_t
wyl_policy_store_apply_direct_permission_mutation (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean insert);
wyrelog_error_t
    wyl_policy_store_apply_direct_permission_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, const gchar * audit_request_id,
    wyl_decision_t audit_decision);
wyrelog_error_t wyl_policy_store_direct_permission_exists (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean * out_exists);
wyrelog_error_t wyl_policy_store_subject_has_permission (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean * out_has_permission);
wyrelog_error_t wyl_policy_store_foreach_direct_permission (wyl_policy_store_t *
    store, wyl_policy_direct_permission_cb cb, gpointer user_data);
wyrelog_error_t
wyl_policy_store_append_direct_permission_event (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * operation);
wyrelog_error_t
wyl_policy_store_foreach_direct_permission_event (wyl_policy_store_t * store,
    wyl_policy_direct_permission_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_set_permission_state (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope, const gchar * state);
wyrelog_error_t wyl_policy_store_permission_state_exists (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean * out_exists);
wyrelog_error_t wyl_policy_store_permission_state_is (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * state, gboolean * out_matches);
wyrelog_error_t wyl_policy_store_foreach_permission_state (wyl_policy_store_t *
    store, wyl_policy_permission_state_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_permission_state_event
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, const gchar * event,
    const gchar * from_state, const gchar * to_state, gint64 * out_event_id);
wyrelog_error_t wyl_policy_store_apply_permission_state_transition
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, const gchar * event,
    gint64 * out_event_id);
wyrelog_error_t
    wyl_policy_store_apply_permission_state_transition_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, const gchar * event,
    gint64 * out_event_id, const gchar * audit_id,
    gint64 audit_created_at_us, const gchar * audit_subject_id,
    const gchar * audit_action, const gchar * audit_resource_id,
    const gchar * audit_deny_reason, const gchar * audit_deny_origin,
    const gchar * audit_request_id, wyl_decision_t audit_decision);
wyrelog_error_t wyl_policy_store_foreach_permission_state_event
    (wyl_policy_store_t * store, wyl_policy_permission_state_event_cb cb,
    gpointer user_data);
wyrelog_error_t wyl_policy_store_set_principal_state (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * state);
wyrelog_error_t wyl_policy_store_foreach_principal_state (wyl_policy_store_t *
    store, wyl_policy_principal_state_cb cb, gpointer user_data);
/* Look up the current principal_state for |subject_id|. On a row match,
 * *out_state is set to a g_strdup'd copy (caller frees with g_free) and
 * *out_found is set to TRUE. When no row exists, *out_state is set to
 * NULL and *out_found is set to FALSE; the return value is still
 * WYRELOG_E_OK. Returns WYRELOG_E_IO on an iteration error so callers
 * can distinguish "no row" from "store fault" without re-binding the
 * historical foreach-based two-step lookup (issue #331 commit-5). */
wyrelog_error_t wyl_policy_store_get_principal_state (wyl_policy_store_t *
    store, const gchar * subject_id, gchar ** out_state, gboolean * out_found);
/* Atomic single-row read of the principal_states row including the
 * lockout columns (failed_attempt_count, locked_at). out_state is
 * g_strdup'd; out_locked_at is INT64_MIN when the column is NULL.
 * out_found follows the same semantics as get_principal_state. */
wyrelog_error_t wyl_policy_store_get_principal_lock_info
    (wyl_policy_store_t * store, const gchar * subject_id,
    gchar ** out_state, gint64 * out_failed_count, gint64 * out_locked_at,
    gboolean * out_found);
/* Atomic mutation for a FAILED_ATTEMPT.  Inside a single savepoint:
 *   - reads the current row (state + counter)
 *   - if the row is missing, materialises mfa_required + counter=1
 *   - else increments the counter
 *   - if the resulting counter is >= |threshold|, transitions the row
 *     to LOCKED with locked_at = |now_secs| and appends a `lock`
 *     principal_event
 * Returns the resulting state name in *out_state (g_strdup'd; caller
 * frees), counter in *out_count, and locked_at in *out_locked_at
 * (INT64_MIN when the row is not locked). The atomicity guarantee
 * defeats the read-modify-write race on parallel verify attempts
 * (commit-5 footgun). */
wyrelog_error_t wyl_policy_store_apply_principal_failure
    (wyl_policy_store_t * store, const gchar * subject_id,
    gint64 threshold, gint64 now_secs, gchar ** out_state,
    gint64 * out_count, gint64 * out_locked_at);
/* Reset the failed_attempt_count to 0 and clear locked_at.  Called on a
 * successful TOTP verify and on auto-unlock. */
wyrelog_error_t wyl_policy_store_reset_principal_failure_counter
    (wyl_policy_store_t * store, const gchar * subject_id);
/* Atomic LOCKED -> UNVERIFIED transition: clears locked_at and the
 * counter, sets state='unverified', and appends an `unlock`
 * principal_event row in one savepoint. */
wyrelog_error_t wyl_policy_store_apply_principal_unlock
    (wyl_policy_store_t * store, const gchar * subject_id);
wyrelog_error_t wyl_policy_store_append_principal_event (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gint64 * out_event_id);
wyrelog_error_t wyl_policy_store_foreach_principal_event (wyl_policy_store_t *
    store, wyl_policy_principal_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_set_session_state (wyl_policy_store_t * store,
    const gchar * session_id, const gchar * state);
wyrelog_error_t wyl_policy_store_foreach_session_state (wyl_policy_store_t *
    store, wyl_policy_session_state_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_session_event (wyl_policy_store_t *
    store, const gchar * session_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gint64 * out_event_id);
wyrelog_error_t wyl_policy_store_foreach_session_event (wyl_policy_store_t *
    store, wyl_policy_session_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_audit_event (wyl_policy_store_t *
    store, const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, wyl_decision_t decision);
wyrelog_error_t wyl_policy_store_append_audit_event_full (wyl_policy_store_t *
    store, const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id,
    const gchar * deny_reason, const gchar * deny_origin,
    const gchar * request_id, wyl_decision_t decision, gboolean * out_inserted);
wyrelog_error_t wyl_policy_store_record_audit_intention_full
    (wyl_policy_store_t * store, const gchar * id, gint64 created_at_us,
    const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, const gchar * request_id,
    wyl_decision_t decision, gboolean * out_inserted);
wyrelog_error_t wyl_policy_store_mark_audit_intention_committed
    (wyl_policy_store_t * store, const gchar * id);
wyrelog_error_t wyl_policy_store_mark_audit_intention_failed
    (wyl_policy_store_t * store, const gchar * id, const gchar * last_error);
wyrelog_error_t wyl_policy_store_foreach_audit_intention
    (wyl_policy_store_t * store, const gchar * state,
    wyl_policy_audit_intention_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_delete_audit_event (wyl_policy_store_t *
    store, const gchar * id);
wyrelog_error_t wyl_policy_store_foreach_audit_event (wyl_policy_store_t *
    store, wyl_policy_audit_event_cb cb, gpointer user_data);

/* Bootstrap admin seal: a one-shot record that names which subject was
 * granted the initial wr.system_admin role membership on a fresh store.
 *
 * The marker lives in wyrelog_config under three keys:
 *   bootstrap_admin_subject       - subject id, or 'legacy-skip' sentinel
 *   bootstrap_admin_sealed_at_us  - wallclock microseconds at seal time
 *   bootstrap_admin_allow_skip_mfa - "0" or "1"
 *
 * The 'legacy-skip' sentinel exists so a dev/pre-#305 store that already
 * carries a wr.system_admin role membership is not silently re-bootstrapped
 * on upgrade. See the migration block in wyl_policy_store_create_schema. */

/* Returns the current bootstrap-admin marker state.
 *
 * On success *out_subject is either NULL (no marker yet) or a freshly
 * g_strdup'd subject id that the caller must free. *out_sealed_at_us is
 * 0 when no marker exists or when the marker is the 'legacy-skip'
 * sentinel. */
wyrelog_error_t wyl_policy_store_get_bootstrap_admin (wyl_policy_store_t *
    store, gchar ** out_subject, gint64 * out_sealed_at_us);

/* TRUE iff (a) no bootstrap_admin_subject row exists, AND
 * (b) role_memberships has no row for role_id='wr.system_admin'. */
wyrelog_error_t wyl_policy_store_bootstrap_admin_eligible (wyl_policy_store_t *
    store, gboolean * out_eligible);

/* Performs the bootstrap. Inside a BEGIN IMMEDIATE transaction:
 *  - re-checks eligibility (race-safe second read)
 *  - grants role membership: subject -> 'wr.system_admin' on WYL_TENANT_DEFAULT
 *  - marks WYL_TENANT_DEFAULT active for policy decisions on the bootstrap
 *    scope
 *  - if allow_login_skip_mfa: grants and arms direct permission
 *    subject + 'wr.login.skip_mfa' + 'login'
 *  - writes wyrelog_config rows:
 *      bootstrap_admin_subject       = <subject>
 *      bootstrap_admin_sealed_at_us  = <wallclock us>
 *      bootstrap_admin_allow_skip_mfa = "1" or "0"
 *  - COMMITs
 *
 * Idempotent: same subject already sealed -> WYRELOG_E_OK with
 *   *out_applied = FALSE, no writes.
 * Mismatch: different subject already sealed -> WYRELOG_E_POLICY with
 *   *out_existing_subject set to the existing string (caller frees).
 * Audit event row emission is the caller's responsibility (daemon
 * startup path). */
wyrelog_error_t wyl_policy_store_apply_bootstrap_admin (wyl_policy_store_t *
    store, const gchar * subject_id, gboolean allow_login_skip_mfa,
    gboolean * out_applied, gchar ** out_existing_subject);

/*
 * TOTP enrollment fact schema (issue #331).
 *
 * Per-subject row stored in the policy authority store carrying the
 * RFC 6238 seed plus the replay watermark and provenance:
 *   subject_id          - principal that owns the enrollment (PK)
 *   secret_blob         - raw 20-byte SHA-1 seed (BLOB)
 *   last_verified_step  - replay watermark; the integer step T that
 *                         was last accepted. Stored as INTEGER (gint64)
 *                         because SQLite has no native u64; callers
 *                         that need the u64 semantics cast at the
 *                         boundary.  The sentinel INT64_MIN means
 *                         "never verified" and is the value any fresh
 *                         enrollment is seeded with.
 *   enrolled_at         - unix seconds at enrollment time
 *   id_uuidv7           - libchronoid UUIDv7 minted via wyl_id_new;
 *                         this is the ONLY new persistent identifier
 *                         the TOTP feature introduces and is the
 *                         single fact provenance handle for the
 *                         enrollment row.
 *
 * Secret material lifecycle: callers MUST treat WylTotpEnrollment.secret
 * as sensitive.  wyl_totp_enrollment_clear zeroes the seed and frees
 * any owned strings; every helper below zeroes the secret buffer on
 * any error path that touched it.  No helper emits secret bytes to
 * the log or audit subsystems.
 */
#define WYL_TOTP_ENROLLMENT_SECRET_BYTES 20

typedef struct
{
  gchar *subject_id;
  guint8 secret[WYL_TOTP_ENROLLMENT_SECRET_BYTES];
  gint64 last_verified_step;    /* INT64_MIN sentinel = never verified */
  gint64 enrolled_at;
  gchar *id_uuidv7;
} WylTotpEnrollment;

/* Zero the secret buffer and free the owned string fields.  NULL-safe.
 * Always zeroes the secret bytes regardless of caller state, so it is
 * safe to call against a partially-populated stack struct from an
 * error path before bailing out. */
void wyl_totp_enrollment_clear (WylTotpEnrollment * enr);

/*
 * Insert (or replace, keyed on subject_id) a TOTP enrollment row.
 *
 * On entry enr->id_uuidv7 is ignored; the helper mints a fresh
 * UUIDv7 via wyl_id_new and writes it back into the caller's struct
 * on success so the audit/event layer in commit 3 can reference the
 * row by its persistent id without a follow-up SELECT.  enr->secret
 * is treated as the 20-byte SHA-1 seed and is bound as a BLOB; the
 * caller retains ownership and is responsible for zeroing its copy.
 *
 * Replacing an existing row resets last_verified_step and
 * enrolled_at from the supplied struct, so a re-enroll path naturally
 * starts the replay watermark over from INT64_MIN.
 *
 * Returns WYRELOG_E_INVALID for NULL inputs, empty subject_id, or
 * a NULL enr.
 */
wyrelog_error_t wyl_policy_store_totp_enrollment_insert (wyl_policy_store_t *
    store, WylTotpEnrollment * enr);

/*
 * Look up the TOTP enrollment for subject_id.  On hit, *out is
 * populated with a freshly owned copy (caller frees via
 * wyl_totp_enrollment_clear) and *out_found is set TRUE.  On miss,
 * *out_found is set FALSE and *out is left as a zero-initialised
 * shell that wyl_totp_enrollment_clear remains safe to call against.
 *
 * Missing rows are NOT an error.  Returns WYRELOG_E_INVALID for NULL
 * inputs.  The secret buffer in *out is zeroed before any error
 * return.
 */
wyrelog_error_t wyl_policy_store_totp_enrollment_lookup (wyl_policy_store_t *
    store, const gchar * subject_id, WylTotpEnrollment * out,
    gboolean * out_found);

/*
 * Atomically update the replay watermark for subject_id.  Intended as
 * the persistence primitive that the commit-3 verify path layers an
 * outer transaction on top of (mirroring the apply_login_state shape
 * in wyl-session.c).  No-op (returns WYRELOG_E_OK) if subject_id has
 * no enrollment row; callers that need a strict precondition should
 * combine with a prior lookup.
 */
wyrelog_error_t wyl_policy_store_totp_enrollment_update_step
    (wyl_policy_store_t * store, const gchar * subject_id, gint64 new_step);

/*
 * Remove the TOTP enrollment row for subject_id.  Idempotent: deleting
 * an absent row returns WYRELOG_E_OK.  Returns WYRELOG_E_INVALID for
 * NULL inputs.
 */
wyrelog_error_t wyl_policy_store_totp_enrollment_delete (wyl_policy_store_t *
    store, const gchar * subject_id);

G_END_DECLS;
