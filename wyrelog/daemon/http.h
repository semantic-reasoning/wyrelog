/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "daemon/options.h"
#include "wyrelog/wyrelog.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>

#include "daemon/delta.h"
#ifdef WYL_TEST_DAEMON_HTTP
#include "daemon/auth-registry-private.h"
#include "daemon/service-credential-handoff-private.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/wyl-fsm-session-private.h"
#ifdef WYL_HAS_AUDIT
#include "wyrelog/auth/service-exchange-limiter-private.h"
#endif
#endif

SoupServer *wyl_daemon_start_http_server (const WylDaemonOptions * opts,
    WylHandle * handle, GError ** error);
SoupServer *wyl_daemon_start_http_server_with_runtime
  (const WylDaemonOptions * opts, WylHandle * handle,
    WylDaemonRuntime * runtime, GError ** error);
WylSession *wyl_daemon_http_ref_session (SoupServer * server,
    const gchar * session_token);
#ifdef WYL_TEST_DAEMON_HTTP
typedef enum
{
  WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED = 1,
  WYL_DAEMON_SERVICE_RESOLVER_RELEASED,
} WylDaemonServiceResolverPhase;
typedef void (*WylDaemonServiceResolverCheckpoint)
  (WylDaemonServiceResolverPhase phase, gpointer data);
typedef enum
{
  WYL_DAEMON_SERVICE_REGISTRY_RESERVE = 1,
  WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE,
  WYL_DAEMON_SERVICE_REGISTRY_REVOKE,
  WYL_DAEMON_SERVICE_REGISTRY_REMOVE,
} WylDaemonServiceRegistryOperation;
typedef enum
{
  WYL_DAEMON_SERVICE_AUTH_INVALIDATE_CREDENTIAL = 1,
  WYL_DAEMON_SERVICE_AUTH_INVALIDATE_PRINCIPAL,
  WYL_DAEMON_SERVICE_AUTH_INVALIDATE_TENANT,
} WylDaemonServiceAuthInvalidationKind;
typedef struct
{
  WylDaemonServiceAuthInvalidationKind kind;
  const gchar *credential_id;
  guint64 credential_generation;
  const gchar *principal;
  const gchar *tenant;
} WylDaemonServiceAuthInvalidation;
typedef enum
{
  WYL_DAEMON_SERVICE_SESSION_INACTIVE = 1,
  WYL_DAEMON_SERVICE_SESSION_AUTH_METHOD,
  WYL_DAEMON_SERVICE_SESSION_ID,
  WYL_DAEMON_SERVICE_SESSION_JTI,
  WYL_DAEMON_SERVICE_SESSION_SUBJECT,
  WYL_DAEMON_SERVICE_SESSION_TENANT,
  WYL_DAEMON_SERVICE_SESSION_CREDENTIAL,
  WYL_DAEMON_SERVICE_SESSION_GENERATION,
  WYL_DAEMON_SERVICE_SESSION_ISSUED_AT,
  WYL_DAEMON_SERVICE_SESSION_EXPIRES_AT,
} WylDaemonServiceSessionField;
typedef enum
{
  WYL_DAEMON_SERVICE_TOKEN_EXPIRES = 1,
  WYL_DAEMON_SERVICE_TOKEN_ISSUED_AT,
  WYL_DAEMON_SERVICE_TOKEN_SESSION_ID,
  WYL_DAEMON_SERVICE_TOKEN_JTI,
  WYL_DAEMON_SERVICE_TOKEN_SUBJECT,
  WYL_DAEMON_SERVICE_TOKEN_TENANT,
  WYL_DAEMON_SERVICE_TOKEN_KEY_ID,
  WYL_DAEMON_SERVICE_TOKEN_AUTH_METHOD,
  WYL_DAEMON_SERVICE_TOKEN_CREDENTIAL,
  WYL_DAEMON_SERVICE_TOKEN_GENERATION,
} WylDaemonServiceTokenField;
typedef struct
{
  gboolean transport_ok;
  gboolean body_oversize;
  const gchar *body_json;
  gsize body_len;
} WylDaemonServiceTokenRequest;
typedef struct
{
  guint created;
  guint complete;
  guint attached;
  guint finished;
  guint aborted;
  guint cleanup_failed;
  guint destroyed;
  guint duplicate_outcomes;
  guint unclaimed_fallbacks;
} WylDaemonServiceResponseAuthoritySnapshot;
typedef enum
{
  WYL_DAEMON_SERVICE_RESPONSE_PRE_HANDOFF = 1,
  WYL_DAEMON_SERVICE_RESPONSE_ACTIVE_PRE_HANDOFF_FAILURE,
  WYL_DAEMON_SERVICE_RESPONSE_FINISHED,
  WYL_DAEMON_SERVICE_RESPONSE_ABORTED,
  WYL_DAEMON_SERVICE_RESPONSE_CLEANUP_FAILED,
  WYL_DAEMON_SERVICE_RESPONSE_UNCLAIMED_FALLBACK,
  WYL_DAEMON_SERVICE_RESPONSE_AUTHORITY_DESTROYED,
  WYL_DAEMON_SERVICE_RESPONSE_BODY_WIPED,
} WylDaemonServiceResponsePhase;
typedef void (*WylDaemonServiceResponseCheckpoint) (gint phase,
    const gchar * session_id, const gchar * jti, gpointer data);
typedef enum
{
  WYL_DAEMON_SERVICE_RESPONSE_RETIRE_BEFORE_WRITE_ACQUIRE = 1,
  WYL_DAEMON_SERVICE_RESPONSE_RETIRE_WRITE_ACQUIRED,
} WylDaemonServiceResponseRetirePhase;
typedef void (*WylDaemonServiceResponseRetireCheckpoint) (gint phase,
    const gchar * session_id, const gchar * jti, gpointer data);
typedef enum
{
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_NONE = 0,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_RESPONSE_PREPARE,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_PRE_ACTIVE_CANCEL,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_AFTER_SESSION_INSERT,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_PRE_ACTIVE_DISCONNECT,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_SESSION_ROLLBACK_MISMATCH,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_SESSION_ROLLBACK_TUPLE_MUTATION,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ACCESS_ROLLBACK_MISMATCH,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ACCESS_ROLLBACK_IAT_MUTATION,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ROLLBACK_SECOND_REMOVE_FAILURE,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_POST_ACTIVE_PRE_HANDOFF,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_FORCE_RESPONSE_AUTHORITY_FALLBACK,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_EMIT_REQUEST_ABORTED_AFTER_HANDOFF,
  WYL_DAEMON_SERVICE_PUBLICATION_FAULT_TERMINAL_RELEASE,
} WylDaemonServicePublicationFault;
typedef enum
{
  WYL_DAEMON_REFRESH_BEFORE_CLAIM = 1,
  WYL_DAEMON_REFRESH_AFTER_CLAIM,
  WYL_DAEMON_REFRESH_AFTER_ACCESS_PREPARE,
  WYL_DAEMON_REFRESH_AFTER_REFRESH_PREPARE,
  WYL_DAEMON_REFRESH_BEFORE_PUBLICATION,
  WYL_DAEMON_REFRESH_AFTER_PUBLICATION,
} WylDaemonRefreshPhase;
typedef enum
{
  WYL_DAEMON_REFRESH_FAULT_NONE = 0,
  WYL_DAEMON_REFRESH_FAULT_ACCESS_PREPARE,
  WYL_DAEMON_REFRESH_FAULT_REFRESH_PREPARE,
  WYL_DAEMON_REFRESH_FAULT_RESULT_PREPARE,
  WYL_DAEMON_REFRESH_FAULT_PREPUBLICATION,
  WYL_DAEMON_REFRESH_FAULT_RESPONSE_BUILD,
} WylDaemonRefreshFault;
typedef enum
{
  WYL_DAEMON_RETIREMENT_PRINCIPAL_DISABLE = 1,
  WYL_DAEMON_RETIREMENT_CREDENTIAL_REVOKE,
  WYL_DAEMON_RETIREMENT_TENANT_SEAL,
  WYL_DAEMON_RETIREMENT_CREDENTIAL_ROTATE,
} WylDaemonRetirementOperation;
typedef void WylDaemonRetirementResponseCheckpoint
  (WylDaemonRetirementOperation operation, const gchar * caller_request_id,
    const gchar * decision_request_id, const gchar * response_json,
    gpointer data);
typedef struct
{
  guint handler_entries;
  guint wrong_context;
  guint access_id_successes;
  guint jwt_sign_attempts;
  guint jwt_sign_successes;
  guint refresh_id_successes;
  guint publications;
} WylDaemonRefreshCounters;
typedef struct
{
  guint64 selected;
  guint64 terminal_entries;
} WylDaemonExactRouteProbeSnapshot;
typedef struct
{
  guint sessions;
  guint access_tokens;
  guint refresh_tokens;
  guint mfa_enroll_challenges;
  guint revoked_sessions;
  guint login_entries;
  guint mfa_verify_entries;
  guint mfa_enroll_start_entries;
  guint mfa_enroll_confirm_entries;
  guint refresh_entries;
  guint logout_entries;
  guint profile_events_entries;
  guint profile_events_ingestions;
} WylDaemonExactRouteStateSnapshot;
typedef wyrelog_error_t
(*WylDaemonManagementReauthorizationCheckpoint) (WylHandle * handle,
    const gchar * actor, const gchar * action, const gchar * session_id,
    const gchar * target_tenant, gpointer data);
void wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
  (SoupServer * server,
    WylDaemonManagementReauthorizationCheckpoint checkpoint, gpointer data);
gboolean wyl_daemon_http_exact_route_probe_snapshot_for_test
  (SoupServer * server, const gchar * canonical_path,
    WylDaemonExactRouteProbeSnapshot * out_snapshot);
gboolean wyl_daemon_http_exact_route_state_snapshot_for_test
  (SoupServer * server, WylDaemonExactRouteStateSnapshot * out_snapshot);
void wyl_daemon_http_route_registration_counts_for_test
  (SoupServer * server, guint * out_total, guint * out_prefixes,
    guint * out_raw_singletons, guint * out_exact_singletons);
void wyl_daemon_http_set_retirement_response_checkpoint_for_test
  (SoupServer * server, WylDaemonRetirementResponseCheckpoint * checkpoint,
    gpointer data);
void wyl_daemon_http_set_rotate_write_checkpoint_for_test
  (SoupServer * server, void (*checkpoint) (gpointer data), gpointer data);
void wyl_daemon_http_fail_next_retirement_latch_for_test (SoupServer * server);
void wyl_daemon_http_set_service_resolver_checkpoint_for_test
  (SoupServer * server, WylDaemonServiceResolverCheckpoint checkpoint,
    gpointer data);
void wyl_daemon_http_fail_next_service_resolver_read_release_for_test
  (SoupServer * server);
guint wyl_daemon_http_service_resolver_terminal_entries_for_test
  (SoupServer * server);
wyrelog_error_t wyl_daemon_http_service_registry_transition_for_test
  (SoupServer * server, const gchar * session_id, const gchar * jti,
    const gchar * credential_id, guint64 generation, const gchar * principal,
    const gchar * tenant, gint operation, gboolean * out_changed);
wyrelog_error_t wyl_daemon_http_invalidate_service_auth_for_test
  (SoupServer * server,
    const WylDaemonServiceAuthInvalidation * invalidation,
    WylServiceAuthRevokeResult * out_result);
wyrelog_error_t wyl_daemon_http_disable_service_principal_for_test
  (SoupServer * server, const gchar * subject_id,
    const gchar * request_id, void (*after_write_acquired) (gpointer data),
    gpointer data);
WylHandle *wyl_daemon_http_get_handle_for_test (SoupServer * server);
wyrelog_error_t wyl_daemon_http_seal_tenant_for_test
  (SoupServer * server, const gchar * tenant_id,
    void (*after_write_acquired) (gpointer data), gpointer data);
wyrelog_error_t wyl_daemon_http_revoke_service_credential_for_test
  (SoupServer * server, const gchar * credential_id,
    const gchar * request_id,
    void (*after_write_acquired) (gpointer data), gpointer data);
wyrelog_error_t wyl_daemon_http_rotate_service_credential_for_test
  (SoupServer * server, const gchar * credential_id,
    guint64 credential_generation, const gchar * request_id,
    void (*after_write_acquired) (gpointer data), gpointer data);
gboolean wyl_daemon_http_replace_session_for_test
  (SoupServer * server, const gchar * session_id, WylSession * session);
gboolean wyl_daemon_http_seed_human_session_for_test
  (SoupServer * server, const gchar * session_id, const gchar * subject,
    const gchar * tenant);
gboolean wyl_daemon_http_seed_mfa_human_session_for_test
  (SoupServer * server, const gchar * session_id, const gchar * subject,
    const gchar * tenant);
gboolean wyl_daemon_http_seed_human_session_with_state_for_test
  (SoupServer * server, const gchar * session_id, const gchar * subject,
    const gchar * tenant, wyl_session_state_t state);
wyrelog_error_t wyl_daemon_http_configure_tenant_for_test
  (SoupServer * server, const gchar * tenant, gboolean create,
    gboolean sealed);
gboolean wyl_daemon_http_remove_access_token_for_test
  (SoupServer * server, const gchar * jti);
gboolean wyl_daemon_http_revoke_access_token_for_test
  (SoupServer * server, const gchar * jti);
gboolean wyl_daemon_http_mutate_access_token_for_test
  (SoupServer * server, const gchar * lookup_jti, gint field,
    const gchar * text, guint64 number);
void wyl_daemon_http_service_authority_snapshot_for_test
  (SoupServer * server, WylServiceAuthAuthoritySnapshot * out_snapshot);
wyrelog_error_t wyl_daemon_http_latch_service_unavailable_for_test
  (SoupServer * server);
wyrelog_error_t wyl_daemon_http_issue_service_token_for_test
  (SoupServer * server, gboolean transport_ok, const gchar * request_body,
    gsize request_body_len, guint * out_status, gchar ** out_body,
    guint * out_retry_after);
wyrelog_error_t wyl_daemon_http_publish_service_token_for_test
  (SoupServer * server, const gchar * credential_id,
    const gchar * credential_secret, gsize credential_secret_len,
    gchar ** out_body);
wyrelog_error_t wyl_daemon_http_lookup_service_registry_for_test
  (SoupServer * server, const gchar * session_id, const gchar * jti,
    gint * out_state, gboolean * out_found);
wyrelog_error_t wyl_daemon_http_retire_due_service_auth_for_test
  (SoupServer * server);
wyrelog_error_t wyl_daemon_http_retire_service_auth_exact_for_test
  (SoupServer * server, const gchar * session_id, const gchar * jti,
    const gchar * credential_id, guint64 generation, const gchar * principal,
    const gchar * tenant, gint64 expires_at);
gboolean wyl_daemon_http_mutate_service_session_for_test
  (SoupServer * server, const gchar * session_id, gint field,
    const gchar * text, guint64 number);
gboolean wyl_daemon_http_store_human_access_token_for_test
  (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, const gchar * key_id,
    gint64 issued_at, gint64 expires_at);
gboolean wyl_daemon_http_access_token_is_active_for_test
  (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, gint64 issued_at,
    gint64 expires_at, const gchar * auth_method,
    const gchar * credential_id, guint64 credential_generation, gint64 now);
wyrelog_error_t wyl_daemon_http_seed_service_session_for_test
  (SoupServer * server, WylSession * session, const gchar * session_id,
    const gchar * jti, const gchar * credential_id, guint64 generation,
    const gchar * principal, const gchar * tenant, gint registry_state);
wyrelog_error_t wyl_daemon_http_resolve_bearer_for_test
  (SoupServer * server, const gchar * token, gchar ** out_session_id,
    gchar ** out_actor, gchar ** out_tenant);
typedef struct wyl_daemon_access_token_snapshot_t
{
  gchar *jti;
  gchar *session_id;
  gchar *subject;
  gchar *tenant;
  gchar *key_id;
  gint auth_method;
  gchar *credential_id;
  guint64 credential_generation;
  gint64 issued_at;
  gint64 expires_at;
  gboolean revoked;
} wyl_daemon_access_token_snapshot_t;
void wyl_daemon_access_token_snapshot_clear
  (wyl_daemon_access_token_snapshot_t * snapshot);
gboolean wyl_daemon_http_store_service_access_token_for_test
  (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, const gchar * key_id,
    gint64 expires_at, gint auth_method, const gchar * credential_id,
    guint64 credential_generation, gboolean revoked);
gboolean wyl_daemon_http_snapshot_access_token_for_test
  (SoupServer * server, const gchar * jti,
    wyl_daemon_access_token_snapshot_t * out_snapshot);
gboolean wyl_daemon_http_service_access_token_is_exact_for_test
  (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, const gchar * key_id,
    gint64 expires_at, gint auth_method, const gchar * credential_id,
    guint64 credential_generation, gint64 now);
wyrelog_error_t wyl_daemon_http_copy_access_token_secret (SoupServer * server,
    guint8 * out_secret, gsize out_len);
gchar *wyl_daemon_http_dup_access_token_key_id (SoupServer * server);
wyrelog_error_t wyl_daemon_http_rotate_access_token_key_for_test
  (SoupServer * server);
gboolean wyl_daemon_http_remove_session_for_test (SoupServer * server,
    const gchar * session_token);
gboolean wyl_daemon_http_expire_refresh_grace_for_test (SoupServer * server,
    const gchar * refresh_token);
gboolean wyl_daemon_http_session_is_revoked (SoupServer * server,
    const gchar * session_token);
wyrelog_error_t wyl_daemon_http_issue_human_tokens_for_test
  (SoupServer * server, WylSession * session, const gchar * session_id,
    const gchar * subject, const gchar * tenant, gchar ** out_access,
    gchar ** out_refresh);
gboolean wyl_daemon_http_seed_refresh_for_test (SoupServer * server,
    WylSession * session, const gchar * token, const gchar * session_id,
    const gchar * subject, const gchar * tenant, gint auth_method,
    gboolean consumed, const gchar * successor_access,
    const gchar * successor_refresh);
gchar *wyl_daemon_http_dup_refresh_state_for_test (SoupServer * server,
    const gchar * token, guint * out_refresh_count, guint * out_access_count);
void wyl_daemon_http_reset_refresh_counters_for_test (SoupServer * server);
void wyl_daemon_http_refresh_counters_for_test (SoupServer * server,
    WylDaemonRefreshCounters * out_counters);
wyrelog_error_t wyl_daemon_http_service_token_exchange_for_test (SoupServer *
    server, const WylDaemonServiceTokenRequest * request, guint * out_status,
    gchar ** out_body, guint * out_retry_after);
void wyl_daemon_http_set_service_publication_fault_for_test
  (SoupServer * server, WylDaemonServicePublicationFault fault);
gchar *wyl_daemon_http_dup_last_service_publication_token_for_test
  (SoupServer * server);
void wyl_daemon_http_service_publication_counts_for_test
  (SoupServer * server, guint * out_sessions, guint * out_access_tokens);
void wyl_daemon_http_service_response_wipe_snapshot_for_test
  (SoupServer * server, guint * out_count, gboolean * out_canary_seen,
    gboolean * out_all_zero);
void wyl_daemon_http_reset_service_response_authority_for_test
  (SoupServer * server);
void wyl_daemon_http_set_service_response_checkpoint_for_test
  (SoupServer * server, WylDaemonServiceResponseCheckpoint checkpoint,
    gpointer data);
void wyl_daemon_http_set_service_response_retire_checkpoint_for_test
  (SoupServer * server,
    WylDaemonServiceResponseRetireCheckpoint checkpoint, gpointer data);
void wyl_daemon_http_set_service_due_write_checkpoint_for_test
  (SoupServer * server, void (*checkpoint) (gpointer data), gpointer data);
void wyl_daemon_http_service_response_authority_snapshot_for_test
  (SoupServer * server,
    WylDaemonServiceResponseAuthoritySnapshot * out_snapshot);
gboolean
wyl_daemon_http_service_publication_session_is_mutated_same_pointer_for_test
  (SoupServer * server, const gchar * session_id);
wyrelog_error_t wyl_daemon_http_profile_events_ingest_for_test (WylDaemonProfile
    profile, gboolean transport_ok, gboolean body_oversize, const gchar * body,
    gsize body_len, gint * out_status, const gchar ** out_token,
    gchar ** out_profile, gchar ** out_event, gint64 * out_timestamp_us);
#ifdef WYL_HAS_AUDIT
void wyl_daemon_http_service_exchange_limiter_snapshot_for_test
  (SoupServer * server, WylServiceExchangeLimiterSnapshot * out_snapshot);
#endif
void wyl_daemon_http_set_refresh_clock_for_test (SoupServer * server,
    gboolean enabled, gint64 now);
void wyl_daemon_http_set_service_auth_clock_for_test (SoupServer * server,
    gboolean enabled, gint64 now_seconds);
gboolean wyl_daemon_http_service_auth_maintenance_active_for_test
  (SoupServer * server, guint * out_ticks);
void wyl_daemon_http_suspend_service_auth_maintenance_for_test
  (SoupServer * server);
void wyl_daemon_http_shutdown_service_auth_maintenance_for_test
  (SoupServer * server);
gboolean wyl_daemon_http_set_refresh_times_for_test (SoupServer * server,
    const gchar * token, gint64 expires_at, gint64 consumed_at);
void wyl_daemon_http_fail_next_refresh_publication_for_test
  (SoupServer * server);
void wyl_daemon_http_set_refresh_fault_for_test (SoupServer * server,
    WylDaemonRefreshFault fault);
gchar **wyl_daemon_http_snapshot_session_access_ids_for_test
  (SoupServer * server, const gchar * session_id);
gchar **wyl_daemon_http_snapshot_session_refresh_ids_for_test
  (SoupServer * server, const gchar * session_id);
gchar **wyl_daemon_http_snapshot_generated_refresh_ids_for_test
  (SoupServer * server);
void wyl_daemon_http_sensitive_strv_free_for_test (gchar ** values);
void wyl_daemon_http_revoke_human_session_for_test (SoupServer * server,
    const gchar * session_id);
void wyl_daemon_http_terminalize_refreshes_for_test (SoupServer * server);
guint64 wyl_daemon_http_arm_refresh_latch_for_test (SoupServer * server,
    WylDaemonRefreshPhase phase);
gboolean wyl_daemon_http_wait_refresh_latch_for_test (SoupServer * server,
    guint64 generation, gint64 deadline_us);
void wyl_daemon_http_release_refresh_latch_for_test (SoupServer * server,
    guint64 generation);
void wyl_daemon_http_disarm_refresh_latch_for_test (SoupServer * server,
    guint64 generation);
void wyl_daemon_http_refresh_lifecycle_counts_for_test (SoupServer * server,
    guint * out_owned, guint * out_wrong);
gboolean wyl_daemon_http_refresh_context_owned_for_test (SoupServer * server);
gboolean wyl_daemon_http_refresh_context_is_for_test (SoupServer * server,
    GMainContext * expected);
gboolean wyl_daemon_http_test_human_refresh_classifier (SoupServer * server);
typedef void (*WylDaemonPolicyWriteCheckpoint) (gpointer data);
typedef enum
{
  WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_NONE = 0,
  WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION,
  WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_RANK_AFTER_POP,
  WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PIN_IDENTITY,
} WylDaemonPolicyWriteFinalizeFault;
typedef enum
{
  WYL_DAEMON_POLICY_WRITE_ACQUIRE_FAULT_NONE = 0,
  WYL_DAEMON_POLICY_WRITE_ACQUIRE_FAULT_AFTER_STORE,
} WylDaemonPolicyWriteAcquireFault;
typedef enum
{
  WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE = 1u << 0,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_TRANSACTION = 1u << 1,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_OPERATION_STORAGE = 1u << 2,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_OPERATION_LOCK = 1u << 3,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_FACT_STORE = 1u << 4,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_MAINTENANCE = 1u << 5,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_CONTEXT = 1u << 6,
  WYL_DAEMON_POLICY_WRITE_RESOURCE_REGISTRY = 1u << 7,
} WylDaemonPolicyWriteObservedResource;
typedef struct
{
  gboolean valid;
  guint64 generation;
  guint terminal_entries;
  guint diagnostic_count;
  guint primary_status;
  gchar primary_code[64];
  wyrelog_error_t primary_rc;
  gboolean primary_rc_recorded;
  wyrelog_error_t cleanup_rc;
  guint pre_finalize_status;
  guint pre_finalize_header_count;
  gsize pre_finalize_body_length;
  gboolean post_finalize_lease_live;
  gboolean post_finalize_store_live;
  guint post_finalize_total_pins;
  guint post_finalize_thread_pins;
  guint post_finalize_rank_mask;
  guint observed_cleanup_resources;
  guint acquire_fault_hits;
  gboolean post_finalize_transaction_active;
  guint owner;
  gchar owner_name[32];
} WylDaemonPolicyWriteFinalizeSnapshot;
/* Runs a representative daemon policy mutation while holding its WRITE lease. */
wyrelog_error_t wyl_daemon_http_policy_write_for_test (SoupServer * server,
    WylDaemonPolicyWriteCheckpoint checkpoint, gpointer data);
void wyl_daemon_http_fail_next_policy_write_finalize_for_test
  (SoupServer * server, WylDaemonPolicyWriteFinalizeFault fault);
void wyl_daemon_http_fail_next_policy_write_acquire_for_test
  (SoupServer * server, WylDaemonPolicyWriteAcquireFault fault);
/* Fail the next fact append/retract audit emission (issue #546), so a test can
 * prove that a durably committed batch is not reported as uncommitted. */
void wyl_daemon_http_fail_next_fact_op_audit_for_test (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_lifecycle_audit_insert_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_lifecycle_audit_append_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_creator_grant_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_creator_event_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_creator_receipt_verification_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_lifecycle_verification_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_seal_verification_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_seal_write_release_for_test
  (SoupServer * server);
void wyl_daemon_http_fail_next_tenant_recovery_repair_for_test
  (SoupServer * server);
gboolean wyl_daemon_http_take_tenant_recovery_repair_failure_for_test
  (SoupServer * server);
gboolean wyl_daemon_http_detach_tenant_recovery_slot_for_test
  (SoupServer * server);
wyrelog_error_t wyl_daemon_http_seal_tenant_recovery_for_test
  (SoupServer * server, const gchar * tenant, const gchar * request_id);
wyrelog_error_t wyl_daemon_http_attempt_seal_tenant_recovery_for_test
  (SoupServer * server, const gchar * tenant, const gchar * request_id);
void wyl_daemon_http_set_tenant_recovery_install_checkpoint_for_test
  (SoupServer * server, void (*checkpoint) (gpointer data), gpointer data);
void wyl_daemon_http_set_tenant_recovery_claim_checkpoint_for_test
  (SoupServer * server, void (*checkpoint) (gpointer data), gpointer data);
void wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
  (guint * out_allocations, guint * out_frees);
void wyl_daemon_http_tenant_create_publication_snapshot_for_test
  (SoupServer * server, guint * out_attempts,
    guint * out_noop_fault_discards);
/* Per-row precommit fault points in the self-arm publication bundle. */
typedef enum
{
  WYL_DAEMON_SELF_ARM_ROW_FAULT_NONE = 0,
  WYL_DAEMON_SELF_ARM_ROW_FAULT_GRANT,
  WYL_DAEMON_SELF_ARM_ROW_FAULT_DIRECT_EVENT,
  WYL_DAEMON_SELF_ARM_ROW_FAULT_SET_STATE,
  WYL_DAEMON_SELF_ARM_ROW_FAULT_STATE_EVENT,
  WYL_DAEMON_SELF_ARM_ROW_FAULT_AUDIT,
} WylDaemonSelfArmRowFault;
/* One-shot: fail the mutation of self-arm perm @perm_index (0 or 1) at @row so
 * the whole bundle rolls back cleanly before commit. */
void wyl_daemon_http_fail_next_self_arm_row_for_test (SoupServer * server,
    guint perm_index, WylDaemonSelfArmRowFault row);
/* One-shot: force the post-commit self-arm verify to fail.  When @persistent
 * the repair verify fails too, so the pair stays poisoned. */
void wyl_daemon_http_fail_next_self_arm_verify_for_test (SoupServer * server,
    gboolean persistent);
typedef enum
{
  WYL_DAEMON_TENANT_CREATE_OUTCOME_FAIL_CLOSED_UNKNOWN = 0,
  WYL_DAEMON_TENANT_CREATE_OUTCOME_INSTALL_ORIGINAL_DESCRIPTOR,
  WYL_DAEMON_TENANT_CREATE_OUTCOME_REPAIR_ABSENT_PAIR,
} WylDaemonTenantCreateOutcomeEffect;
typedef struct
{
  const gchar *tenant_id;
  const gchar *creator_subject_id;
  const gchar *audit_id;
  gint64 audit_created_at_us;
  const gchar *audit_subject_id;
  const gchar *audit_action;
  const gchar *audit_resource_id;
  const gchar *audit_deny_reason;
  const gchar *audit_deny_origin;
  const gchar *audit_request_id;
  wyl_decision_t audit_decision;
} WylDaemonTenantCreateOutcomeBundle;
wyrelog_error_t wyl_daemon_http_resolve_tenant_create_outcome_for_test
  (SoupServer * server, const WylDaemonTenantCreateOutcomeBundle * bundle,
    WylDaemonTenantCreateOutcomeEffect * out_effect);
guint wyl_daemon_http_policy_write_terminal_entries_for_test
  (SoupServer * server);
/* One-shot owner-9 barrier reached after the direct-permission WRITE has
 * acquired its policy-store pin but before the handler mutates policy. */
guint64 wyl_daemon_http_arm_policy_write_acquired_latch_for_test
  (SoupServer * server);
gboolean wyl_daemon_http_wait_policy_write_acquired_latch_for_test
  (SoupServer * server, guint64 generation, gint64 deadline_us);
void wyl_daemon_http_release_policy_write_acquired_latch_for_test
  (SoupServer * server, guint64 generation);
void wyl_daemon_http_disarm_policy_write_acquired_latch_for_test
  (SoupServer * server, guint64 generation);
/* Wait for publication of a finalize snapshot newer than @baseline_generation.
 * Publication follows terminal lease release, including policy-store unpin. */
gboolean wyl_daemon_http_wait_policy_write_finalize_for_test
  (SoupServer * server, guint64 baseline_generation, gint64 deadline_us,
    WylDaemonPolicyWriteFinalizeSnapshot * out_snapshot);
gboolean wyl_daemon_http_policy_write_finalize_snapshot_for_test
  (SoupServer * server, WylDaemonPolicyWriteFinalizeSnapshot * out_snapshot);
/* Reason (WylDaemonPolicyWriteCancel: 0 none, 1 client-disconnect, 2 shutdown)
 * of the most recent cancelled policy WRITE acquisition. */
gint wyl_daemon_http_policy_write_last_cancel_reason_for_test
  (SoupServer * server);
/* 1 when the most recent policy WRITE armed a disconnect watch, 0 when arming
 * bailed out early, -1 when the context is gone.  Distinguishes "never armed"
 * from "armed but never observed the peer's EOF". */
gint wyl_daemon_http_policy_write_last_watch_armed_for_test
  (SoupServer * server);
/*
 * Test seam: drive the tenant-gate cross-check between the tenant
 * declared by the request (request_tenant, may be NULL meaning "no
 * tenant query param", which causes lookup_request_tenant() to fall
 * back to the default tenant) and a synthesised authenticated
 * principal tenant (auth_tenant, may be NULL). Parameter order
 * mirrors decide_request_tenant_gate(): (request_tenant, auth_tenant).
 * Returns TRUE on pass and FALSE on rejection; on rejection out_status
 * / out_code (caller-owned, copy via g_strdup) are populated with the
 * wire-format response that the helper would have set on a real
 * SoupServerMessage.
 */
gboolean wyl_daemon_http_check_request_tenant_for_test
  (const gchar * request_tenant, const gchar * auth_tenant,
    guint * out_status, gchar ** out_code);
/*
 * Inject a mock owner-publication backend into the running daemon HTTP
 * context so the service credential issue/rotate handlers drive it through the
 * escrow handoff module instead of opening the real filesystem publication
 * backend. Passing NULL clears the override.
 */
void wyl_daemon_http_set_publication_override_for_test (SoupServer * server,
    const WyctlPublicationBackendVTable * vtable, gpointer vtable_data);
#endif
#endif
