/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <sqlite3.h>

#include "wyrelog/decide.h"
#include "wyrelog/error.h"
#include "wyrelog/wyl-traits-private.h"

G_BEGIN_DECLS;

#define WYL_POLICY_FACT_QUERY_DEFAULT_MAX_ROWS 1000
#define WYL_POLICY_FACT_QUERY_MAX_ROWS 1000000

typedef struct wyl_policy_store_t wyl_policy_store_t;

typedef struct
{
  const gchar *path;
  const wyl_keyprovider_vtable_t *keyprovider_vtable;
  gpointer keyprovider_state;
  void (*keyprovider_state_free) (gpointer state);
  gboolean require_encrypted;
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
wyrelog_error_t wyl_policy_store_open_with_options (const
    wyl_policy_store_open_options_t * opts, wyl_policy_store_t ** out_store);
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
wyrelog_error_t wyl_policy_store_validate_snapshot (wyl_policy_store_t * store);
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
