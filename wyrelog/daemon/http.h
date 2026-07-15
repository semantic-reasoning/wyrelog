/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "daemon/options.h"
#include "wyrelog/wyrelog.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>

#include "daemon/delta.h"
#ifdef WYL_TEST_DAEMON_HTTP
#include "wyrelog/auth/service-auth-coordination-private.h"
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
  WYL_DAEMON_SERVICE_TOKEN_SESSION_ID,
  WYL_DAEMON_SERVICE_TOKEN_JTI,
  WYL_DAEMON_SERVICE_TOKEN_SUBJECT,
  WYL_DAEMON_SERVICE_TOKEN_TENANT,
  WYL_DAEMON_SERVICE_TOKEN_KEY_ID,
  WYL_DAEMON_SERVICE_TOKEN_AUTH_METHOD,
  WYL_DAEMON_SERVICE_TOKEN_CREDENTIAL,
  WYL_DAEMON_SERVICE_TOKEN_GENERATION,
} WylDaemonServiceTokenField;
typedef enum
{
  WYL_DAEMON_REFRESH_AFTER_DETACHED_PREPARE = 1,
} WylDaemonRefreshPhase;
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
gboolean wyl_daemon_http_replace_session_for_test
    (SoupServer * server, const gchar * session_id, WylSession * session);
gboolean wyl_daemon_http_seed_human_session_for_test
    (SoupServer * server, const gchar * session_id, const gchar * subject,
    const gchar * tenant);
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
gboolean wyl_daemon_http_mutate_service_session_for_test
    (SoupServer * server, const gchar * session_id, gint field,
    const gchar * text, guint64 number);
gboolean wyl_daemon_http_store_human_access_token_for_test
    (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, const gchar * key_id,
    gint64 expires_at);
gboolean wyl_daemon_http_access_token_is_active_for_test
    (SoupServer * server, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, gint64 expires_at,
    const gchar * auth_method, const gchar * credential_id,
    guint64 credential_generation, gint64 now);
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
void wyl_daemon_http_set_refresh_clock_for_test (SoupServer * server,
    gboolean enabled, gint64 now);
gboolean wyl_daemon_http_set_refresh_times_for_test (SoupServer * server,
    const gchar * token, gint64 expires_at, gint64 consumed_at);
void wyl_daemon_http_fail_next_refresh_publication_for_test
    (SoupServer * server);
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
/* Runs a representative daemon policy mutation while holding its WRITE lease. */
wyrelog_error_t wyl_daemon_http_policy_write_for_test (SoupServer * server,
    WylDaemonPolicyWriteCheckpoint checkpoint, gpointer data);
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
#endif
#endif
