/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <errno.h>
#include <sodium.h>
#include <string.h>
#ifdef G_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "daemon/auth-registry-private.h"
#include "daemon/http-guards-private.h"
#include "daemon/delta.h"
#include "daemon/fact-status.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/auth/mfa-enrollment-private.h"
#include "wyrelog/auth/service-exchange-limiter-private.h"
#include "wyrelog/auth/service-exchange-private.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/auth/totp.h"
#include "wyrelog/policy/store-private.h"
#ifdef WYL_TEST_DAEMON_HTTP
#include "wyrelog/wyl-session-layout-private.h"
#endif
#ifdef WYL_HAS_FACT_STORE
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/query-private.h"
#include "wyrelog/fact/schema-private.h"
#include "wyrelog/fact/store-private.h"
#endif
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"
#include "wyrelog/wyl-request-id-private.h"
#include "wyrelog/wyl-fsm-permission-scope-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

#define WYL_DAEMON_JWT_ISSUER "wyrelogd"
#define WYL_DAEMON_JWT_AUDIENCE "wyrelog-client"
#define WYL_DAEMON_JWT_KEY_ID "__wr_default_hs256"
#define WYL_DAEMON_JWT_KEY_LEN 32
#define WYL_DAEMON_JWT_EPOCH_LEN 16
#define WYL_DAEMON_JWT_KEYPROVIDER_LABEL "wyrelog.jwt.hs256.root.v1"
#define WYL_DAEMON_JWT_BOOT_EPOCH_CONTEXT "wyrelog.jwt.hs256.boot_epoch.v1"
#define WYL_DAEMON_REFRESH_TTL_SECONDS 86400
#define WYL_DAEMON_REFRESH_GRACE_SECONDS 30
#define WYL_DAEMON_MFA_ENROLL_TTL_SECONDS 300
#define WYL_DAEMON_REQUEST_ID_HEADER "X-Wyrelog-Request-Id"
#define WYL_DAEMON_REQUEST_ID_DATA "wyl-daemon-request-id"
#define WYL_DAEMON_REQUEST_ID_ATTEMPTED_DATA "wyl-daemon-request-id-attempted"

/*
 * Stable HTTP wire-format error codes for the tenant gate. They are
 * emitted as the "error" field of the JSON error body produced by
 * set_json_error():
 *
 *   tenant_invalid  - 400. The request carries a tenant query
 *                     parameter (or login body field) whose value is
 *                     not a tenant this daemon recognises.
 *   tenant_sealed   - 400. The request carries a tenant that exists
 *                     but is sealed and cannot accept new work.
 *   tenant_denied   - 403. The authenticated principal's tenant does
 *                     not match the tenant declared on the request.
 *                     Distinct from tenant_invalid so callers can
 *                     distinguish "your request was malformed" from
 *                     "your credentials are not for this tenant".
 *
 * These constants are HTTP wire strings only; they intentionally do
 * NOT extend the wyrelog_error_t enum.
 */
#define WYL_DAEMON_ERR_TENANT_INVALID "tenant_invalid"
#define WYL_DAEMON_ERR_TENANT_DENIED  "tenant_denied"
#define WYL_DAEMON_ERR_TENANT_SEALED  "tenant_sealed"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_AUTH_REQUIRED \
  "service_credential_operation_reconcile_auth_required"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_INVALID \
  "invalid_service_credential_operation_reconcile_request"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_DENIED \
  "service_credential_operation_reconcile_denied"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED \
  "service_credential_operation_reconcile_failed"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE \
  "service_credential_operation_reconcile_unavailable"
#define WYL_DAEMON_ERR_SERVICE_TOKEN_INVALID \
  "invalid_service_token_request"
#define WYL_DAEMON_ERR_SERVICE_TOKEN_DENIED \
  "service_token_denied"
#define WYL_DAEMON_ERR_SERVICE_TOKEN_AUTH_REQUIRED \
  "service_token_auth_required"
#define WYL_DAEMON_ERR_SERVICE_TOKEN_RATE_LIMITED \
  "service_token_rate_limited"
#define WYL_DAEMON_ERR_SERVICE_TOKEN_FAILED \
  "service_token_failed"
#define WYL_DAEMON_ERR_OPERATION_REQUEST_CONFLICT \
  "operation_request_conflict"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_AUTH_REQUIRED \
  "service_principal_auth_required"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID \
  "invalid_service_principal_request"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_DENIED \
  "service_principal_denied"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED \
  "service_principal_failed"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_NOT_FOUND \
  "service_principal_not_found"
#define WYL_DAEMON_ERR_SERVICE_PRINCIPAL_EXISTS \
  "service_principal_exists"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED \
  "service_credential_auth_required"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID \
  "invalid_service_credential_request"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED \
  "service_credential_denied"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED \
  "service_credential_failed"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_CONFLICT \
  "service_credential_conflict"
#define WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND \
  "service_credential_not_found"

typedef gchar WylSensitiveChar;

static void
wyl_sensitive_string_free (WylSensitiveChar *value)
{
  if (value == NULL)
    return;
  sodium_memzero (value, strlen (value));
  g_free (value);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylSensitiveChar, wyl_sensitive_string_free);

typedef struct
{
  gchar *jti;
  gchar *session_id;
  gchar *subject;
  gchar *tenant;
  gchar *key_id;
  wyl_session_auth_method_t auth_method;
  gchar *credential_id;
  guint64 credential_generation;
  gboolean revoked;
  gint64 expires_at;
} WylAccessTokenState;

typedef struct
{
  const gchar *session_id;
  GPtrArray *token_ids;
} WylSessionTokenCollect;

typedef struct
{
  gchar *session_id;
  gchar *actor;
  gchar *tenant;
  gboolean bearer;
} WylDaemonAuthContext;

typedef struct _WylHumanRefreshResult
{
  gint ref_count;
  gchar *access_token;
  gchar *refresh_token;
} WylHumanRefreshResult;

typedef struct
{
  gchar *token;
  gchar *session_id;
  gchar *subject;
  gchar *tenant;
  WylHumanRefreshResult *successor;
  gboolean consumed;
  gboolean rotating;
  gboolean revoked;
  guint64 epoch;
  guint64 rotation_claim;
  gint64 issued_at;
  gint64 expires_at;
  gint64 consumed_at;
  wyl_session_auth_method_t auth_method;
} WylRefreshTokenState;

typedef enum
{
  WYL_HUMAN_REFRESH_DECISION_DENY = 0,
  WYL_HUMAN_REFRESH_DECISION_AVAILABLE,
  WYL_HUMAN_REFRESH_DECISION_COMMITTED_GRACE,
  WYL_HUMAN_REFRESH_DECISION_REUSE,
} WylHumanRefreshDecision;

typedef struct
{
  gchar *challenge;
  gchar *session_id;
  gchar *actor;
  gchar *subject;
  guint8 secret[WYL_TOTP_SEED_BYTES];
  gint64 expires_at_monotonic_us;
} WylMfaEnrollChallenge;

#ifdef WYL_TEST_DAEMON_HTTP
typedef struct
{
  GMutex mutex;
  GCond changed;
  guint64 generation;
  WylDaemonRefreshPhase phase;
  gboolean armed;
  gboolean entered;
  gboolean released;
} WylHumanRefreshTestLatch;
#endif

typedef struct _WylDaemonHttpContext
{
  gint ref_count;
  WylHandle *handle;
  WylDaemonRuntime *runtime;
  WylServiceAuthRegistry *service_auth_registry;
  guint8 access_token_secret[WYL_DAEMON_JWT_KEY_LEN];
  gchar *access_token_key_id;
  gboolean access_token_secret_ready;
#ifdef WYL_HAS_AUDIT
  guint8 service_token_limiter_key[crypto_generichash_KEYBYTES];
  gboolean service_token_limiter_key_ready;
  WylServiceExchangeLimiter *service_token_limiter;
#endif
  gboolean production_mode;
  WylDaemonProfile profile;
  gchar *policy_keyprovider_path;
  gchar *fact_root;
  gchar *system_url;
  gchar *event_spool_dir;
  guint event_queue_limit;
  GHashTable *sessions_by_token;
  GHashTable *access_tokens_by_jti;
  GHashTable *refresh_tokens_by_token;
  GHashTable *mfa_enroll_challenges;
  GMainContext *dispatch_context;
#ifdef WYL_HAS_AUDIT
  WylServiceExchangeLimiter *service_exchange_limiter;
#endif
  /*
   * Set of session_token strings that have entered the logout
   * teardown path. Once a session is in this set, both
   * wyl_daemon_http_context_store_access_token and _store_refresh_token
   * refuse to insert any new state for that session, closing the
   * window in which an /auth/refresh that already passed the
   * lock-protected revoked-state check could mint a fresh access
   * or refresh token after the logout's revoke pass had already
   * snapshotted the existing tokens. Entries are added under
   * ctx->lock during logout teardown and live for the lifetime of
   * the context.
   */
  GHashTable *revoked_session_tokens;
  GMutex lock;
  guint64 auth_epoch;
  guint64 key_epoch;
  guint64 next_refresh_epoch;
  guint64 next_refresh_claim;
  gboolean shutting_down;
#ifdef WYL_TEST_DAEMON_HTTP
  gboolean refresh_clock_injected;
  gint64 refresh_clock_now;
  WylDaemonServiceResolverCheckpoint resolver_checkpoint;
  gpointer resolver_checkpoint_data;
  gboolean fail_next_resolver_read_release;
  guint resolver_terminal_entries;
  guint refresh_handler_entries;
  guint refresh_dispatch_owned;
  guint refresh_dispatch_wrong;
  guint refresh_access_id_successes;
  guint refresh_jwt_sign_attempts;
  guint refresh_jwt_sign_successes;
  guint refresh_token_id_successes;
  guint refresh_publications;
  gboolean fail_next_refresh_publication;
  WylDaemonRefreshFault refresh_fault;
  GPtrArray *refresh_generated_ids;
  WylHumanRefreshTestLatch refresh_latch;
#endif
} WylDaemonHttpContext;

typedef struct
{
  WylServiceAuthWriteLease *lease;
  wyl_policy_store_t *store;    /* borrowed from the lease-owned pin */
} WylDaemonPolicyWrite;

static guint64
human_refresh_next_nonzero (guint64 *counter)
{
  guint64 value = (*counter)++;
  if (value == 0)
    value = (*counter)++;
  return value;
}

static void
wyl_daemon_policy_write_clear (WylDaemonPolicyWrite *write)
{
  if (write->lease == NULL)
    return;
  g_assert_cmpint (wyl_service_auth_write_lease_release (write->lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (write->lease);
  write->lease = NULL;
  write->store = NULL;
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylDaemonPolicyWrite,
    wyl_daemon_policy_write_clear);

static wyrelog_error_t
wyl_daemon_policy_write_acquire (WylDaemonHttpContext *ctx,
    WylDaemonPolicyWrite *write)
{
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (ctx->handle), ctx->handle, NULL,
      &write->lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (write->lease,
        ctx->handle, &write->store);
  if (rc != WYRELOG_E_OK)
    wyl_daemon_policy_write_clear (write);
  return rc;
}

static WylDaemonHttpContext *wyl_daemon_http_get_context (SoupServer * server);
static gboolean mfa_code_is_well_formed (const gchar * code);
static void set_json_error (SoupServerMessage * msg, guint status,
    const gchar * code);
static void set_json_ok (SoupServerMessage * msg);

static wyrelog_error_t
tenant_active_status (WylDaemonHttpContext *ctx, const gchar *tenant,
    gboolean *out_active)
{
  if (out_active != NULL)
    *out_active = FALSE;
  if (ctx == NULL || ctx->handle == NULL || tenant == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant))
    return WYRELOG_E_INVALID;
  return wyl_policy_store_tenant_is_active
      (wyl_handle_get_policy_store (ctx->handle), tenant, out_active);
}

static gboolean
tenant_is_known (WylDaemonHttpContext *ctx, const gchar *tenant)
{
  gboolean exists = FALSE;
  if (ctx == NULL || ctx->handle == NULL || tenant == NULL ||
      !wyl_policy_store_tenant_id_is_valid (tenant))
    return FALSE;
  if (wyl_policy_store_tenant_exists (wyl_handle_get_policy_store
          (ctx->handle), tenant, &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static gboolean
tenant_is_active (WylDaemonHttpContext *ctx, const gchar *tenant)
{
  gboolean active = FALSE;
  return tenant_active_status (ctx, tenant, &active) == WYRELOG_E_OK && active;
}

static void
wyl_daemon_auth_context_clear (WylDaemonAuthContext *auth)
{
  if (auth == NULL)
    return;
  g_free (auth->session_id);
  g_free (auth->actor);
  g_free (auth->tenant);
  memset (auth, 0, sizeof *auth);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylDaemonAuthContext,
    wyl_daemon_auth_context_clear);

static void
wyl_access_token_state_free (gpointer data)
{
  WylAccessTokenState *state = data;

  if (state == NULL)
    return;

  g_free (state->jti);
  g_free (state->session_id);
  g_free (state->subject);
  g_free (state->tenant);
  g_free (state->key_id);
  g_free (state->credential_id);
  g_free (state);
}

static WylHumanRefreshResult *
wyl_human_refresh_result_ref (WylHumanRefreshResult *result)
{
  g_atomic_int_inc (&result->ref_count);
  return result;
}

static void
wyl_human_refresh_result_unref (gpointer data)
{
  WylHumanRefreshResult *result = data;
  if (result == NULL || !g_atomic_int_dec_and_test (&result->ref_count))
    return;
  wyl_sensitive_string_free (result->access_token);
  wyl_sensitive_string_free (result->refresh_token);
  g_free (result);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylHumanRefreshResult,
    wyl_human_refresh_result_unref);

static void
wyl_refresh_token_state_free (gpointer data)
{
  WylRefreshTokenState *state = data;

  if (state == NULL)
    return;

  wyl_sensitive_string_free (state->token);
  g_free (state->session_id);
  g_free (state->subject);
  g_free (state->tenant);
  wyl_human_refresh_result_unref (state->successor);
  g_free (state);
}

static void wyl_daemon_http_context_unref (gpointer data);
static gboolean human_refresh_dispatch_owned (WylDaemonHttpContext * ctx);

typedef struct
{
  gchar *token;
  gchar *map_key;
  gchar *cache_token;
  WylAccessTokenState *state;
} WylHumanAccessCandidate;

typedef struct
{
  gchar *token;
  gchar *map_key;
  gchar *cache_token;
  WylRefreshTokenState *state;
} WylHumanRefreshCandidate;

typedef struct
{
  WylDaemonHttpContext *ctx;
  WylSession *session;
  WylRefreshTokenState *predecessor_state;
  const gchar *predecessor;
  const gchar *session_id;
  const gchar *subject;
  const gchar *tenant;
  const gchar *key_id;
  guint64 predecessor_epoch;
  guint64 claim_epoch;
  guint64 auth_epoch;
  guint64 key_epoch;
} WylHumanRefreshClaim;

static void wyl_human_access_candidate_clear
    (WylHumanAccessCandidate * candidate);
static void wyl_human_refresh_candidate_clear
    (WylHumanRefreshCandidate * candidate);

static void
wyl_human_access_candidate_clear (WylHumanAccessCandidate *candidate)
{
  if (candidate == NULL)
    return;
  g_clear_pointer (&candidate->token, wyl_sensitive_string_free);
  g_clear_pointer (&candidate->map_key, g_free);
  g_clear_pointer (&candidate->cache_token, wyl_sensitive_string_free);
  g_clear_pointer (&candidate->state, wyl_access_token_state_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylHumanAccessCandidate,
    wyl_human_access_candidate_clear);

static void
wyl_human_refresh_candidate_clear (WylHumanRefreshCandidate *candidate)
{
  if (candidate == NULL)
    return;
  g_clear_pointer (&candidate->token, wyl_sensitive_string_free);
  g_clear_pointer (&candidate->map_key, g_free);
  g_clear_pointer (&candidate->cache_token, wyl_sensitive_string_free);
  g_clear_pointer (&candidate->state, wyl_refresh_token_state_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylHumanRefreshCandidate,
    wyl_human_refresh_candidate_clear);

static WylHumanRefreshResult *
wyl_human_refresh_result_new_take (gchar *access_token, gchar *refresh_token)
{
  WylHumanRefreshResult *result = g_new0 (WylHumanRefreshResult, 1);
  result->ref_count = 1;
  result->access_token = access_token;
  result->refresh_token = refresh_token;
  return result;
}

static void
wyl_mfa_enroll_challenge_free (gpointer data)
{
  WylMfaEnrollChallenge *challenge = data;
  if (challenge == NULL)
    return;
  sodium_memzero (challenge->secret, sizeof challenge->secret);
  g_free (challenge->challenge);
  g_free (challenge->session_id);
  g_free (challenge->actor);
  g_free (challenge->subject);
  g_free (challenge);
}

typedef struct
{
  const gchar *actor;
  const gchar *session_id;
  gint64 now_monotonic_us;
} WylMfaChallengePrune;

static gboolean
wyl_mfa_enroll_challenge_should_remove (gpointer key, gpointer value,
    gpointer user_data)
{
  (void) key;
  WylMfaEnrollChallenge *challenge = value;
  WylMfaChallengePrune *prune = user_data;
  return challenge->expires_at_monotonic_us <= prune->now_monotonic_us ||
      (g_strcmp0 (challenge->actor, prune->actor) == 0 &&
      g_strcmp0 (challenge->session_id, prune->session_id) == 0);
}

static void
wyl_daemon_http_context_unref (gpointer data)
{
  WylDaemonHttpContext *ctx = data;

  if (ctx == NULL || !g_atomic_int_dec_and_test (&ctx->ref_count))
    return;

  sodium_memzero (ctx->access_token_secret, sizeof ctx->access_token_secret);
  g_free (ctx->access_token_key_id);
#ifdef WYL_HAS_AUDIT
  sodium_memzero (ctx->service_token_limiter_key,
      sizeof ctx->service_token_limiter_key);
  g_clear_pointer (&ctx->service_token_limiter,
      wyl_service_exchange_limiter_free);
#endif
  g_free (ctx->policy_keyprovider_path);
  g_free (ctx->fact_root);
  g_free (ctx->system_url);
  g_free (ctx->event_spool_dir);
  g_hash_table_unref (ctx->sessions_by_token);
  g_hash_table_unref (ctx->access_tokens_by_jti);
  g_hash_table_unref (ctx->refresh_tokens_by_token);
  g_hash_table_unref (ctx->mfa_enroll_challenges);
  g_clear_pointer (&ctx->revoked_session_tokens, g_hash_table_unref);
  g_clear_pointer (&ctx->dispatch_context, g_main_context_unref);
#ifdef WYL_TEST_DAEMON_HTTP
  g_clear_pointer (&ctx->refresh_generated_ids, g_ptr_array_unref);
  g_mutex_clear (&ctx->refresh_latch.mutex);
  g_cond_clear (&ctx->refresh_latch.changed);
#endif
  g_mutex_clear (&ctx->lock);
  g_clear_pointer (&ctx->service_auth_registry,
      wyl_service_auth_registry_unref);
  g_free (ctx);
}

static void
wyl_daemon_http_context_terminalize (WylDaemonHttpContext *ctx,
    gboolean shutting_down)
{
  if (ctx == NULL)
    return;

  g_mutex_lock (&ctx->lock);
  if (shutting_down && !ctx->shutting_down) {
    ctx->shutting_down = TRUE;
    ctx->auth_epoch++;
  }
  g_mutex_unlock (&ctx->lock);
#ifdef WYL_TEST_DAEMON_HTTP
  if (shutting_down) {
    g_autoptr (GMutexLocker) locker = g_mutex_locker_new
        (&ctx->refresh_latch.mutex);
    ctx->refresh_latch.released = TRUE;
    ctx->refresh_latch.armed = FALSE;
    g_cond_broadcast (&ctx->refresh_latch.changed);
  }
#endif
}

static void
wyl_daemon_http_context_shutdown (gpointer data)
{
  WylDaemonHttpContext *ctx = data;
  wyl_daemon_http_context_terminalize (ctx, TRUE);
  wyl_daemon_http_context_unref (ctx);
}

static wyrelog_error_t
derive_access_token_secret (const WylDaemonOptions *opts,
    guint8 out_secret[WYL_DAEMON_JWT_KEY_LEN], gchar **out_key_id)
{
  if (opts == NULL || out_secret == NULL || out_key_id == NULL)
    return WYRELOG_E_INVALID;
  *out_key_id = NULL;

  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;

  guint8 epoch[WYL_DAEMON_JWT_EPOCH_LEN];
  randombytes_buf (epoch, sizeof epoch);
  g_autofree gchar *epoch_hex = g_malloc0 ((sizeof epoch * 2) + 1);
  sodium_bin2hex (epoch_hex, (sizeof epoch * 2) + 1, epoch, sizeof epoch);

  if (!opts->production_mode) {
    randombytes_buf (out_secret, WYL_DAEMON_JWT_KEY_LEN);
    *out_key_id = g_strdup_printf ("%s.%s", WYL_DAEMON_JWT_KEY_ID, epoch_hex);
    sodium_memzero (epoch, sizeof epoch);
    return WYRELOG_E_OK;
  }

  if (opts->policy_keyprovider_path == NULL
      || opts->policy_keyprovider_path[0] == '\0') {
    sodium_memzero (epoch, sizeof epoch);
    return WYRELOG_E_POLICY;
  }

  g_autoptr (wyl_keyprovider_file_t) keyprovider =
      wyl_keyprovider_file_new_from_spec (opts->policy_keyprovider_path);
  if (keyprovider == NULL) {
    sodium_memzero (epoch, sizeof epoch);
    return WYRELOG_E_CRYPTO;
  }

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  guint8 root[WYL_DAEMON_JWT_KEY_LEN];
  wyrelog_error_t rc = vt->derive (keyprovider,
      WYL_DAEMON_JWT_KEYPROVIDER_LABEL, root, sizeof root);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (epoch, sizeof epoch);
    return rc;
  }

  crypto_generichash_state state;
  if (crypto_generichash_init (&state, root, sizeof root,
          WYL_DAEMON_JWT_KEY_LEN) != 0) {
    sodium_memzero (root, sizeof root);
    sodium_memzero (epoch, sizeof epoch);
    return WYRELOG_E_CRYPTO;
  }
  crypto_generichash_update (&state,
      (const guint8 *) WYL_DAEMON_JWT_BOOT_EPOCH_CONTEXT,
      strlen (WYL_DAEMON_JWT_BOOT_EPOCH_CONTEXT));
  crypto_generichash_update (&state, epoch, sizeof epoch);
  crypto_generichash_final (&state, out_secret, WYL_DAEMON_JWT_KEY_LEN);

  sodium_memzero (root, sizeof root);
  sodium_memzero (epoch, sizeof epoch);
  *out_key_id = g_strdup_printf ("%s.%s", WYL_DAEMON_JWT_KEY_ID, epoch_hex);
  return WYRELOG_E_OK;
}

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t
derive_service_token_limiter_key (guint8 out_key[crypto_generichash_KEYBYTES])
{
  if (out_key == NULL)
    return WYRELOG_E_INVALID;
  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;
  randombytes_buf (out_key, crypto_generichash_KEYBYTES);
  return WYRELOG_E_OK;
}

static gint64
service_exchange_limiter_now_us (gpointer data)
{
  (void) data;
  return g_get_monotonic_time ();
}

static void
wyl_daemon_http_context_reset_service_token_limiter (WylDaemonHttpContext *ctx)
{
  if (ctx == NULL)
    return;
  g_clear_pointer (&ctx->service_token_limiter,
      wyl_service_exchange_limiter_free);
  sodium_memzero (ctx->service_token_limiter_key,
      sizeof ctx->service_token_limiter_key);
  ctx->service_token_limiter_key_ready = FALSE;
}

static wyrelog_error_t
    wyl_daemon_http_context_refresh_service_token_limiter
    (WylDaemonHttpContext * ctx)
{
  if (ctx == NULL)
    return WYRELOG_E_INVALID;

  guint8 next_key[crypto_generichash_KEYBYTES];
  wyrelog_error_t rc = derive_service_token_limiter_key (next_key);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylServiceExchangeLimiter *limiter = NULL;
  rc = wyl_service_exchange_limiter_new (next_key, sizeof next_key, 4096,
      service_exchange_limiter_now_us, NULL, &limiter);
  if (rc == WYRELOG_E_OK) {
    g_clear_pointer (&ctx->service_token_limiter,
        wyl_service_exchange_limiter_free);
    memcpy (ctx->service_token_limiter_key, next_key, sizeof next_key);
    ctx->service_token_limiter_key_ready = TRUE;
    ctx->service_token_limiter = limiter;
    limiter = NULL;
  }
  if (limiter != NULL)
    wyl_service_exchange_limiter_free (limiter);
  sodium_memzero (next_key, sizeof next_key);
  return rc;
}

#endif

static wyrelog_error_t
wyl_daemon_http_context_rotate_access_token_key (WylDaemonHttpContext *ctx)
{
  if (ctx == NULL)
    return WYRELOG_E_INVALID;

  WylDaemonOptions opts = {
    .production_mode = ctx->production_mode,
    .policy_keyprovider_path = ctx->policy_keyprovider_path,
  };
  guint8 next_secret[WYL_DAEMON_JWT_KEY_LEN];
  g_autofree gchar *next_key_id = NULL;
  wyrelog_error_t rc = derive_access_token_secret (&opts, next_secret,
      &next_key_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_mutex_lock (&ctx->lock);
  sodium_memzero (ctx->access_token_secret, sizeof ctx->access_token_secret);
  memcpy (ctx->access_token_secret, next_secret, sizeof next_secret);
  g_clear_pointer (&ctx->access_token_key_id, g_free);
  ctx->access_token_key_id = g_steal_pointer (&next_key_id);
  ctx->access_token_secret_ready = TRUE;
  ctx->auth_epoch++;
  ctx->key_epoch++;
  g_hash_table_remove_all (ctx->access_tokens_by_jti);
  g_hash_table_remove_all (ctx->refresh_tokens_by_token);
#ifdef WYL_HAS_AUDIT
  if (ctx->service_exchange_limiter != NULL) {
    if (wyl_service_exchange_limiter_reseed (ctx->service_exchange_limiter,
            ctx->access_token_secret, sizeof ctx->access_token_secret,
            4096, service_exchange_limiter_now_us, NULL) != WYRELOG_E_OK) {
      g_mutex_unlock (&ctx->lock);
      sodium_memzero (next_secret, sizeof next_secret);
      return WYRELOG_E_INTERNAL;
    }
  }
#endif
  g_mutex_unlock (&ctx->lock);
  sodium_memzero (next_secret, sizeof next_secret);
  return WYRELOG_E_OK;
}

static WylDaemonHttpContext *
wyl_daemon_http_context_new (const WylDaemonOptions *opts, WylHandle *handle,
    WylDaemonRuntime *runtime, GError **error)
{
  WylServiceAuthRegistry *service_auth_registry = NULL;
  wyrelog_error_t rc;

  rc = wyl_service_auth_registry_new (&service_auth_registry);
  if (rc != WYRELOG_E_OK) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
        "service auth registry initialization failed: %s",
        wyrelog_error_string (rc));
    return NULL;
  }

  WylDaemonHttpContext *ctx = g_new0 (WylDaemonHttpContext, 1);
  ctx->ref_count = 1;
  ctx->service_auth_registry = service_auth_registry;
  ctx->handle = handle;
  ctx->runtime = runtime;
  ctx->production_mode = opts->production_mode;
  ctx->profile = opts->profile;
  ctx->policy_keyprovider_path = g_strdup (opts->policy_keyprovider_path);
  ctx->fact_root = g_strdup (opts->fact_root);
  ctx->system_url = g_strdup (opts->system_url);
  ctx->event_spool_dir = g_strdup (opts->event_spool_dir);
  ctx->event_queue_limit = opts->event_queue_limit;
  ctx->dispatch_context = g_main_context_ref_thread_default ();
  ctx->sessions_by_token =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
  ctx->access_tokens_by_jti = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, wyl_access_token_state_free);
  ctx->refresh_tokens_by_token = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, wyl_refresh_token_state_free);
  ctx->mfa_enroll_challenges = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, wyl_mfa_enroll_challenge_free);
  ctx->revoked_session_tokens = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, NULL);
  g_mutex_init (&ctx->lock);
#ifdef WYL_TEST_DAEMON_HTTP
  g_mutex_init (&ctx->refresh_latch.mutex);
  g_cond_init (&ctx->refresh_latch.changed);
  ctx->refresh_generated_ids = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_sensitive_string_free);
#endif
  ctx->next_refresh_epoch = 1;
  ctx->next_refresh_claim = 1;
  rc = wyl_daemon_http_context_rotate_access_token_key (ctx);
  if (rc != WYRELOG_E_OK) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
        "JWT signing key initialization failed: %s", wyrelog_error_string (rc));
    wyl_daemon_http_context_unref (ctx);
    return NULL;
  }
#ifdef WYL_HAS_AUDIT
  rc = wyl_service_exchange_limiter_new (ctx->access_token_secret,
      sizeof ctx->access_token_secret, 4096, service_exchange_limiter_now_us,
      NULL, &ctx->service_exchange_limiter);
  if (rc != WYRELOG_E_OK) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
        "service exchange limiter initialization failed: %s",
        wyrelog_error_string (rc));
    wyl_daemon_http_context_unref (ctx);
    return NULL;
  }
#endif
  return ctx;
}

static void
wyl_daemon_http_context_mark_session_revoked (WylDaemonHttpContext *ctx,
    const gchar *session_token)
{
  if (ctx == NULL || session_token == NULL || session_token[0] == '\0')
    return;

  g_mutex_lock (&ctx->lock);
  g_hash_table_add (ctx->revoked_session_tokens, g_strdup (session_token));
  g_mutex_unlock (&ctx->lock);
}

static gboolean
human_session_matches (WylDaemonHttpContext *ctx, WylSession *session,
    const gchar *session_id, const gchar *subject, const gchar *tenant)
{
  if (ctx == NULL || session == NULL || !WYL_IS_SESSION (session)
      || session_id == NULL
      || session_id[0] == '\0' || subject == NULL || subject[0] == '\0'
      || tenant == NULL || tenant[0] == '\0'
      || wyl_policy_subject_has_service_prefix (subject)
      || wyl_session_get_auth_method_private (session)
      != WYL_SESSION_AUTH_METHOD_HUMAN
      || !wyl_session_is_active_private (session))
    return FALSE;

  g_autofree gchar *live_id = wyl_session_dup_id_string (session);
  g_autofree gchar *live_subject = wyl_session_dup_username (session);
  g_autofree gchar *live_tenant = wyl_session_dup_tenant (session);
  if (g_strcmp0 (live_id, session_id) != 0
      || g_strcmp0 (live_subject, subject) != 0
      || g_strcmp0 (live_tenant, tenant) != 0)
    return FALSE;
  g_autofree gchar *principal_state = NULL;
  gboolean found = FALSE;
  return wyl_policy_store_get_principal_state
      (wyl_handle_get_policy_store (ctx->handle), subject, &principal_state,
      &found) == WYRELOG_E_OK && found
      && g_strcmp0 (principal_state, "authenticated") == 0;
}

static gboolean
access_token_identity_is_valid (const gchar *jti, const gchar *session_id)
{
  wyl_id_t jti_id;
  wyl_id_t sid_id;
  gchar canonical_jti[WYL_ID_STRING_BUF];
  gchar canonical_sid[WYL_ID_STRING_BUF];
  return jti != NULL && session_id != NULL && g_strcmp0 (jti, session_id) != 0
      && wyl_id_parse (jti, &jti_id) == WYRELOG_E_OK
      && wyl_id_parse (session_id, &sid_id) == WYRELOG_E_OK
      && wyl_id_format (&jti_id, canonical_jti, sizeof canonical_jti)
      == WYRELOG_E_OK
      && wyl_id_format (&sid_id, canonical_sid, sizeof canonical_sid)
      == WYRELOG_E_OK && g_strcmp0 (jti, canonical_jti) == 0
      && g_strcmp0 (session_id, canonical_sid) == 0;
}

static gboolean
service_access_token_tuple_is_valid (const gchar *jti,
    const gchar *session_id, const gchar *subject, const gchar *tenant,
    const gchar *key_id, gint64 expires_at, const gchar *credential_id,
    guint64 credential_generation)
{
  return access_token_identity_is_valid (jti, session_id)
      && subject != NULL
      && wyl_policy_service_subject_is_valid (subject, strlen (subject))
      && wyl_policy_store_tenant_id_is_valid (tenant)
      && key_id != NULL && key_id[0] != '\0' && expires_at > 0
      && wyl_service_credential_id_is_canonical (credential_id,
      credential_id != NULL ? strlen (credential_id) : 0)
      && credential_generation > 0;
}

static gboolean
wyl_daemon_http_context_store_access_token_state (WylDaemonHttpContext *ctx,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at,
    wyl_session_auth_method_t auth_method, const gchar *credential_id,
    guint64 credential_generation, gboolean revoked)
{
  if (ctx == NULL || jti == NULL || jti[0] == '\0' || session_id == NULL
      || session_id[0] == '\0' || subject == NULL || subject[0] == '\0'
      || tenant == NULL || tenant[0] == '\0' || key_id == NULL
      || key_id[0] == '\0' || expires_at < 0
      || (auth_method == WYL_SESSION_AUTH_METHOD_HUMAN
          ? credential_id != NULL || credential_generation != 0
          : auth_method != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
          || !service_access_token_tuple_is_valid (jti, session_id, subject,
              tenant, key_id, expires_at, credential_id,
              credential_generation)))
    return FALSE;

  WylAccessTokenState *state = g_new0 (WylAccessTokenState, 1);
  state->jti = g_strdup (jti);
  state->session_id = g_strdup (session_id);
  state->subject = g_strdup (subject);
  state->tenant = g_strdup (tenant);
  state->key_id = g_strdup (key_id);
  state->expires_at = expires_at;
  state->auth_method = auth_method;
  state->credential_id = g_strdup (credential_id);
  state->credential_generation = credential_generation;
  state->revoked = revoked;

  g_mutex_lock (&ctx->lock);
  if (g_hash_table_contains (ctx->revoked_session_tokens, session_id)) {
    g_mutex_unlock (&ctx->lock);
    wyl_access_token_state_free (state);
    return FALSE;
  }
  g_hash_table_replace (ctx->access_tokens_by_jti, g_strdup (jti), state);
  g_mutex_unlock (&ctx->lock);
  return TRUE;
}

static gboolean
wyl_daemon_http_context_store_access_token (WylDaemonHttpContext *ctx,
    WylSession *session, const gchar *jti, const gchar *session_id,
    const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at)
{
  if (ctx == NULL || jti == NULL || jti[0] == '\0' || session_id == NULL ||
      session_id[0] == '\0' || subject == NULL || subject[0] == '\0' ||
      tenant == NULL || tenant[0] == '\0' || key_id == NULL ||
      key_id[0] == '\0' || expires_at < 0
      || !human_session_matches (ctx, session, session_id, subject, tenant))
    return FALSE;

  return wyl_daemon_http_context_store_access_token_state (ctx, jti,
      session_id, subject, tenant, key_id, expires_at,
      WYL_SESSION_AUTH_METHOD_HUMAN, NULL, 0, FALSE);
}

static wyrelog_error_t
new_token_id_string (gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;

  wyl_id_t id;
  wyrelog_error_t rc = wyl_id_new (&id);
  if (rc != WYRELOG_E_OK)
    return rc;

  gchar buf[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&id, buf, sizeof buf);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_token = g_strdup (buf);
  return WYRELOG_E_OK;
}

static gboolean
wyl_daemon_http_context_store_refresh_token (WylDaemonHttpContext *ctx,
    WylSession *session, const gchar *token, const gchar *session_id,
    const gchar *subject,
    const gchar *tenant, gint64 issued_at, gint64 expires_at)
{
  if (ctx == NULL || token == NULL || token[0] == '\0' ||
      session_id == NULL || session_id[0] == '\0' || subject == NULL ||
      subject[0] == '\0' || tenant == NULL || tenant[0] == '\0' ||
      issued_at < 0 || expires_at <= issued_at
      || !human_session_matches (ctx, session, session_id, subject, tenant))
    return FALSE;

  WylRefreshTokenState *state = g_new0 (WylRefreshTokenState, 1);
  state->token = g_strdup (token);
  state->session_id = g_strdup (session_id);
  state->subject = g_strdup (subject);
  state->tenant = g_strdup (tenant);
  state->issued_at = issued_at;
  state->expires_at = expires_at;
  state->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;

  g_mutex_lock (&ctx->lock);
  /*
   * Same revoked-session gate as the access-token store path: refuse
   * to register a refresh token for a session that has already
   * entered logout teardown. Pairs with /auth/refresh handling so
   * the rotation cannot mint a new refresh that survives logout.
   */
  if (g_hash_table_contains (ctx->revoked_session_tokens, session_id)) {
    g_mutex_unlock (&ctx->lock);
    wyl_refresh_token_state_free (state);
    return FALSE;
  }
  state->epoch = human_refresh_next_nonzero (&ctx->next_refresh_epoch);
  g_hash_table_replace (ctx->refresh_tokens_by_token, g_strdup (token), state);
  g_mutex_unlock (&ctx->lock);
  return TRUE;
}

static gboolean
wyl_daemon_http_context_access_token_is_active (WylDaemonHttpContext *ctx,
    const wyl_jwt_access_claims_t *claims, gint64 now)
{
  if (ctx == NULL || claims == NULL || claims->jti == NULL)
    return FALSE;

  g_mutex_lock (&ctx->lock);
  WylAccessTokenState *state = g_hash_table_lookup (ctx->access_tokens_by_jti,
      claims->jti);
  gboolean active = state != NULL && !state->revoked && now < state->expires_at
      && state->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN
      && state->credential_id == NULL && state->credential_generation == 0
      && claims->auth_method == NULL && claims->credential_id == NULL
      && claims->credential_generation == 0
      && g_strcmp0 (state->session_id, claims->session_id) == 0
      && g_strcmp0 (state->subject, claims->subject) == 0
      && g_strcmp0 (state->tenant, claims->tenant) == 0
      && g_strcmp0 (state->key_id, ctx->access_token_key_id) == 0
      && state->expires_at == claims->expires_at;
  g_mutex_unlock (&ctx->lock);
  return active;
}

static gboolean
    wyl_daemon_http_context_service_access_token_is_exact
    (WylDaemonHttpContext * ctx, const gchar * jti, const gchar * session_id,
    const gchar * subject, const gchar * tenant, const gchar * key_id,
    gint64 expires_at, wyl_session_auth_method_t auth_method,
    const gchar * credential_id, guint64 credential_generation, gint64 now)
{
  if (ctx == NULL || auth_method != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
      || !service_access_token_tuple_is_valid (jti, session_id, subject,
          tenant, key_id, expires_at, credential_id, credential_generation))
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylAccessTokenState *state = g_hash_table_lookup (ctx->access_tokens_by_jti,
      jti);
  gboolean exact = state != NULL && !state->revoked && now >= 0
      && now < state->expires_at
      && state->auth_method == WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
      && g_strcmp0 (state->jti, jti) == 0
      && g_strcmp0 (state->session_id, session_id) == 0
      && g_strcmp0 (state->subject, subject) == 0
      && g_strcmp0 (state->tenant, tenant) == 0
      && g_strcmp0 (state->key_id, key_id) == 0
      && state->expires_at == expires_at
      && g_strcmp0 (state->credential_id, credential_id) == 0
      && state->credential_generation == credential_generation;
  g_mutex_unlock (&ctx->lock);
  return exact;
}

static void
collect_session_access_token (gpointer key, gpointer value, gpointer data)
{
  WylAccessTokenState *state = value;
  WylSessionTokenCollect *collect = data;

  if (state == NULL || collect == NULL || collect->token_ids == NULL)
    return;
  if (g_strcmp0 (state->session_id, collect->session_id) == 0)
    g_ptr_array_add (collect->token_ids, g_strdup ((const gchar *) key));
}

static void
collect_session_refresh_token (gpointer key, gpointer value, gpointer data)
{
  WylRefreshTokenState *state = value;
  WylSessionTokenCollect *collect = data;

  if (state == NULL || collect == NULL || collect->token_ids == NULL)
    return;
  if (g_strcmp0 (state->session_id, collect->session_id) == 0)
    g_ptr_array_add (collect->token_ids, g_strdup ((const gchar *) key));
}

static void
wyl_daemon_http_context_revoke_session_access_tokens (WylDaemonHttpContext *ctx,
    const gchar *session_id)
{
  if (ctx == NULL || session_id == NULL || session_id[0] == '\0')
    return;

  g_autoptr (GPtrArray) token_ids = g_ptr_array_new_with_free_func (g_free);
  WylSessionTokenCollect collect = {
    .session_id = session_id,
    .token_ids = token_ids,
  };

  g_mutex_lock (&ctx->lock);
  g_hash_table_foreach (ctx->access_tokens_by_jti, collect_session_access_token,
      &collect);
  for (guint i = 0; i < token_ids->len; i++) {
    const gchar *jti = g_ptr_array_index (token_ids, i);
    WylAccessTokenState *state =
        g_hash_table_lookup (ctx->access_tokens_by_jti, jti);
    if (state != NULL)
      state->revoked = TRUE;
  }
  g_mutex_unlock (&ctx->lock);
}

static void
wyl_daemon_http_context_revoke_session_refresh_tokens (WylDaemonHttpContext
    *ctx, const gchar *session_id)
{
  if (ctx == NULL || session_id == NULL || session_id[0] == '\0')
    return;

  g_autoptr (GPtrArray) token_ids = g_ptr_array_new_with_free_func (g_free);
  WylSessionTokenCollect collect = {
    .session_id = session_id,
    .token_ids = token_ids,
  };

  g_mutex_lock (&ctx->lock);
  g_hash_table_foreach (ctx->refresh_tokens_by_token,
      collect_session_refresh_token, &collect);
  for (guint i = 0; i < token_ids->len; i++) {
    const gchar *token = g_ptr_array_index (token_ids, i);
    WylRefreshTokenState *state =
        g_hash_table_lookup (ctx->refresh_tokens_by_token, token);
    if (state != NULL)
      state->revoked = TRUE;
  }
  g_mutex_unlock (&ctx->lock);
}

#ifdef WYL_TEST_DAEMON_HTTP
gboolean
wyl_daemon_http_store_human_access_token_for_test (SoupServer *server,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_store_access_token_state (ctx, jti,
      session_id, subject, tenant, key_id, expires_at,
      WYL_SESSION_AUTH_METHOD_HUMAN, NULL, 0, FALSE);
}

gboolean
wyl_daemon_http_access_token_is_active_for_test (SoupServer *server,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, gint64 expires_at, const gchar *auth_method,
    const gchar *credential_id, guint64 credential_generation, gint64 now)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  wyl_jwt_access_claims_t claims = {
    .jti = (gchar *) jti,
    .session_id = (gchar *) session_id,
    .subject = (gchar *) subject,
    .tenant = (gchar *) tenant,
    .expires_at = expires_at,
    .auth_method = (gchar *) auth_method,
    .credential_id = (gchar *) credential_id,
    .credential_generation = credential_generation,
  };
  return wyl_daemon_http_context_access_token_is_active (ctx, &claims, now);
}

static gboolean
    service_auth_invalidation_validate_locked
    (const WylDaemonServiceAuthInvalidation * invalidation)
{
  if (invalidation == NULL)
    return FALSE;
  switch (invalidation->kind) {
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_CREDENTIAL:
      return invalidation->credential_id != NULL
          && invalidation->credential_generation > 0
          && wyl_service_credential_id_is_canonical
          (invalidation->credential_id, strlen (invalidation->credential_id));
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_PRINCIPAL:
      return invalidation->principal != NULL
          && wyl_policy_service_subject_is_valid (invalidation->principal,
          strlen (invalidation->principal));
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_TENANT:
      return wyl_policy_store_tenant_id_is_valid (invalidation->tenant);
    default:
      return FALSE;
  }
}

static wyrelog_error_t
service_auth_invalidation_execute_locked (WylDaemonHttpContext *ctx,
    const WylDaemonServiceAuthInvalidation *invalidation,
    WylServiceAuthRevokeResult *out_result)
{
  WylServiceAuthWriteLease *lease = NULL;
  wyrelog_error_t rc;

  if (ctx == NULL || invalidation == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  memset (out_result, 0, sizeof *out_result);
  if (!service_auth_invalidation_validate_locked (invalidation))
    return WYRELOG_E_INVALID;

  rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (ctx->handle), ctx->handle, NULL,
      &lease);
  if (rc != WYRELOG_E_OK)
    return rc;

  switch (invalidation->kind) {
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_CREDENTIAL:
      rc = wyl_service_auth_registry_revoke_credential_generation
          (ctx->service_auth_registry, invalidation->credential_id,
          invalidation->credential_generation, out_result);
      break;
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_PRINCIPAL:
      rc = wyl_service_auth_registry_revoke_principal
          (ctx->service_auth_registry, invalidation->principal, out_result);
      break;
    case WYL_DAEMON_SERVICE_AUTH_INVALIDATE_TENANT:
      rc = wyl_service_auth_registry_revoke_tenant
          (ctx->service_auth_registry, invalidation->tenant, out_result);
      break;
    default:
      rc = WYRELOG_E_INVALID;
      break;
  }

  if (rc != WYRELOG_E_OK)
    (void) wyl_service_auth_write_lease_mark_unavailable (lease, ctx->handle,
        WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT);
  if (wyl_service_auth_write_lease_release (lease) != WYRELOG_E_OK
      && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_IO;
  wyl_service_auth_write_lease_free (lease);
  return rc;
}

wyrelog_error_t
wyl_daemon_http_seed_service_session_for_test (SoupServer *server,
    WylSession *session, const gchar *session_id, const gchar *jti,
    const gchar *credential_id, guint64 generation, const gchar *principal,
    const gchar *tenant, gint registry_state)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session == NULL)
    return WYRELOG_E_INVALID;
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) session_id,
    .jti = (gchar *) jti,
    .credential_id = (gchar *) credential_id,
    .generation = generation,
    .principal = (gchar *) principal,
    .tenant = (gchar *) tenant,
  };
  wyrelog_error_t rc = wyl_service_auth_registry_reserve
      (ctx->service_auth_registry, &reservation);
  gboolean changed = FALSE;
  if (rc == WYRELOG_E_OK && registry_state >= WYL_SERVICE_AUTH_ACTIVE)
    rc = wyl_service_auth_registry_activate (ctx->service_auth_registry,
        &reservation, &changed);
  if (rc == WYRELOG_E_OK && registry_state == WYL_SERVICE_AUTH_REVOKED)
    rc = wyl_service_auth_registry_revoke_exact (ctx->service_auth_registry,
        &reservation, &changed);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_mutex_lock (&ctx->lock);
  g_hash_table_replace (ctx->sessions_by_token, g_strdup (session_id),
      g_object_ref (session));
  g_mutex_unlock (&ctx->lock);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_http_invalidate_service_auth_for_test (SoupServer *server,
    const WylDaemonServiceAuthInvalidation *invalidation,
    WylServiceAuthRevokeResult *out_result)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);

  if (out_result != NULL)
    memset (out_result, 0, sizeof *out_result);
  if (ctx == NULL || invalidation == NULL || out_result == NULL)
    return WYRELOG_E_INVALID;
  return service_auth_invalidation_execute_locked (ctx, invalidation,
      out_result);
}

void
wyl_daemon_http_set_service_resolver_checkpoint_for_test (SoupServer *server,
    WylDaemonServiceResolverCheckpoint checkpoint, gpointer data)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  ctx->resolver_checkpoint = checkpoint;
  ctx->resolver_checkpoint_data = data;
}

void wyl_daemon_http_fail_next_service_resolver_read_release_for_test
    (SoupServer * server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx != NULL)
    ctx->fail_next_resolver_read_release = TRUE;
}

guint wyl_daemon_http_service_resolver_terminal_entries_for_test
    (SoupServer * server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return ctx != NULL ? ctx->resolver_terminal_entries : 0;
}

static void
service_resolver_terminal_entry_for_test (gpointer data)
{
  guint *entries = data;
  (*entries)++;
}

wyrelog_error_t
wyl_daemon_http_service_registry_transition_for_test (SoupServer *server,
    const gchar *session_id, const gchar *jti, const gchar *credential_id,
    guint64 generation, const gchar *principal, const gchar *tenant,
    gint operation, gboolean *out_changed)
{
  if (out_changed != NULL)
    *out_changed = FALSE;
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || out_changed == NULL)
    return WYRELOG_E_INVALID;
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) session_id,.jti = (gchar *) jti,
    .credential_id = (gchar *) credential_id,.generation = generation,
    .principal = (gchar *) principal,.tenant = (gchar *) tenant,
  };
  switch (operation) {
    case WYL_DAEMON_SERVICE_REGISTRY_RESERVE:
      return wyl_service_auth_registry_reserve (ctx->service_auth_registry,
          &reservation);
    case WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE:
      return wyl_service_auth_registry_activate (ctx->service_auth_registry,
          &reservation, out_changed);
    case WYL_DAEMON_SERVICE_REGISTRY_REVOKE:
      return wyl_service_auth_registry_revoke_exact (ctx->service_auth_registry,
          &reservation, out_changed);
    case WYL_DAEMON_SERVICE_REGISTRY_REMOVE:
      return wyl_service_auth_registry_remove_exact (ctx->service_auth_registry,
          &reservation, out_changed);
    default:
      return WYRELOG_E_INVALID;
  }
}

gboolean
wyl_daemon_http_replace_session_for_test (SoupServer *server,
    const gchar *session_id, WylSession *session)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session_id == NULL || session == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  g_hash_table_replace (ctx->sessions_by_token, g_strdup (session_id),
      g_object_ref (session));
  g_mutex_unlock (&ctx->lock);
  return TRUE;
}

gboolean
wyl_daemon_http_seed_human_session_for_test (SoupServer *server,
    const gchar *session_id, const gchar *subject, const gchar *tenant)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  wyl_id_t id = WYL_ID_NIL;
  if (ctx == NULL || wyl_id_parse (session_id, &id) != WYRELOG_E_OK
      || subject == NULL || tenant == NULL)
    return FALSE;
  g_autoptr (WylSession) session = g_object_new (WYL_TYPE_SESSION, NULL);
  session->id = id;
  session->username = g_strdup (subject);
  session->tenant = g_strdup (tenant);
  session->state = WYL_SESSION_STATE_ACTIVE;
  session->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
  return wyl_daemon_http_replace_session_for_test (server, session_id, session);
}

wyrelog_error_t
wyl_daemon_http_configure_tenant_for_test (SoupServer *server,
    const gchar *tenant, gboolean create, gboolean sealed)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return WYRELOG_E_INVALID;
  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc == WYRELOG_E_OK && create) {
    gboolean created = FALSE;
    rc = wyl_policy_store_create_tenant (write.store, tenant, &created);
    if (rc == WYRELOG_E_OK && !created)
      rc = WYRELOG_E_POLICY;
  }
  return rc == WYRELOG_E_OK ? wyl_policy_store_set_tenant_sealed (write.store,
      tenant, sealed) : rc;
}

gboolean
wyl_daemon_http_remove_access_token_for_test (SoupServer *server,
    const gchar *jti)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || jti == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  gboolean removed = g_hash_table_remove (ctx->access_tokens_by_jti, jti);
  g_mutex_unlock (&ctx->lock);
  return removed;
}

gboolean
wyl_daemon_http_revoke_access_token_for_test (SoupServer *server,
    const gchar *jti)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || jti == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylAccessTokenState *state = g_hash_table_lookup
      (ctx->access_tokens_by_jti, jti);
  if (state != NULL)
    state->revoked = TRUE;
  g_mutex_unlock (&ctx->lock);
  return state != NULL;
}

gboolean
wyl_daemon_http_mutate_access_token_for_test (SoupServer *server,
    const gchar *lookup_jti, gint field, const gchar *text, guint64 number)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || lookup_jti == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylAccessTokenState *state = g_hash_table_lookup
      (ctx->access_tokens_by_jti, lookup_jti);
  if (state == NULL)
    goto invalid;
  gchar **slot = NULL;
  switch (field) {
    case WYL_DAEMON_SERVICE_TOKEN_EXPIRES:
      state->expires_at = (gint64) number;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_SESSION_ID:
      slot = &state->session_id;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_JTI:
      slot = &state->jti;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_SUBJECT:
      slot = &state->subject;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_TENANT:
      slot = &state->tenant;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_KEY_ID:
      slot = &state->key_id;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_AUTH_METHOD:
      state->auth_method = (wyl_session_auth_method_t) number;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_CREDENTIAL:
      slot = &state->credential_id;
      break;
    case WYL_DAEMON_SERVICE_TOKEN_GENERATION:
      state->credential_generation = number;
      break;
    default:
      goto invalid;
  }
  if (slot != NULL) {
    g_free (*slot);
    *slot = g_strdup (text);
  }
  g_mutex_unlock (&ctx->lock);
  return TRUE;
invalid:
  g_mutex_unlock (&ctx->lock);
  return FALSE;
}

void
wyl_daemon_http_service_authority_snapshot_for_test (SoupServer *server,
    WylServiceAuthAuthoritySnapshot *out_snapshot)
{
  memset (out_snapshot, 0, sizeof *out_snapshot);
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx != NULL)
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (ctx->handle), out_snapshot);
}

wyrelog_error_t
wyl_daemon_http_latch_service_unavailable_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return WYRELOG_E_INVALID;
  WylServiceAuthWriteLease *lease = NULL;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (ctx->handle), ctx->handle, NULL,
      &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_mark_unavailable (lease, ctx->handle,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (rc == WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  return rc;
}

gboolean
wyl_daemon_http_mutate_service_session_for_test (SoupServer *server,
    const gchar *session_id, gint field, const gchar *text, guint64 number)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session_id == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylSession *session = g_hash_table_lookup (ctx->sessions_by_token,
      session_id);
  if (session == NULL) {
    g_mutex_unlock (&ctx->lock);
    return FALSE;
  }
  switch (field) {
    case WYL_DAEMON_SERVICE_SESSION_INACTIVE:
      session->state = WYL_SESSION_STATE_CLOSED;
      break;
    case WYL_DAEMON_SERVICE_SESSION_AUTH_METHOD:
      session->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
      break;
    case WYL_DAEMON_SERVICE_SESSION_ID:
      if (text == NULL || wyl_id_parse (text, &session->id) != WYRELOG_E_OK)
        goto invalid;
      break;
    case WYL_DAEMON_SERVICE_SESSION_JTI:
      g_free (session->service_jti);
      session->service_jti = g_strdup (text);
      break;
    case WYL_DAEMON_SERVICE_SESSION_SUBJECT:
      g_free (session->service_subject_id);
      session->service_subject_id = g_strdup (text);
      break;
    case WYL_DAEMON_SERVICE_SESSION_TENANT:
      g_free (session->tenant);
      session->tenant = g_strdup (text);
      break;
    case WYL_DAEMON_SERVICE_SESSION_CREDENTIAL:
      g_free (session->service_credential_id);
      session->service_credential_id = g_strdup (text);
      break;
    case WYL_DAEMON_SERVICE_SESSION_GENERATION:
      session->service_credential_generation = number;
      break;
    case WYL_DAEMON_SERVICE_SESSION_ISSUED_AT:
      session->service_issued_at_seconds = (gint64) number;
      break;
    case WYL_DAEMON_SERVICE_SESSION_EXPIRES_AT:
      session->service_expires_at_seconds = (gint64) number;
      break;
    default:
      goto invalid;
  }
  g_mutex_unlock (&ctx->lock);
  return TRUE;
invalid:
  g_mutex_unlock (&ctx->lock);
  return FALSE;
}

void wyl_daemon_access_token_snapshot_clear
    (wyl_daemon_access_token_snapshot_t * snapshot)
{
  if (snapshot == NULL)
    return;
  g_free (snapshot->jti);
  g_free (snapshot->session_id);
  g_free (snapshot->subject);
  g_free (snapshot->tenant);
  g_free (snapshot->key_id);
  g_free (snapshot->credential_id);
  memset (snapshot, 0, sizeof *snapshot);
}

gboolean
wyl_daemon_http_store_service_access_token_for_test (SoupServer *server,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at,
    gint auth_method, const gchar *credential_id,
    guint64 credential_generation, gboolean revoked)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_store_access_token_state (ctx, jti,
      session_id, subject, tenant, key_id, expires_at,
      (wyl_session_auth_method_t) auth_method, credential_id,
      credential_generation, revoked);
}

gboolean
wyl_daemon_http_snapshot_access_token_for_test (SoupServer *server,
    const gchar *jti, wyl_daemon_access_token_snapshot_t *out_snapshot)
{
  if (out_snapshot == NULL)
    return FALSE;
  wyl_daemon_access_token_snapshot_clear (out_snapshot);
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || jti == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylAccessTokenState *state = g_hash_table_lookup (ctx->access_tokens_by_jti,
      jti);
  if (state != NULL) {
    out_snapshot->jti = g_strdup (state->jti);
    out_snapshot->session_id = g_strdup (state->session_id);
    out_snapshot->subject = g_strdup (state->subject);
    out_snapshot->tenant = g_strdup (state->tenant);
    out_snapshot->key_id = g_strdup (state->key_id);
    out_snapshot->auth_method = state->auth_method;
    out_snapshot->credential_id = g_strdup (state->credential_id);
    out_snapshot->credential_generation = state->credential_generation;
    out_snapshot->expires_at = state->expires_at;
    out_snapshot->revoked = state->revoked;
  }
  g_mutex_unlock (&ctx->lock);
  return state != NULL;
}

gboolean
wyl_daemon_http_service_access_token_is_exact_for_test (SoupServer *server,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at,
    gint auth_method, const gchar *credential_id,
    guint64 credential_generation, gint64 now)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_service_access_token_is_exact (ctx, jti,
      session_id, subject, tenant, key_id, expires_at,
      (wyl_session_auth_method_t) auth_method, credential_id,
      credential_generation, now);
}

wyrelog_error_t
wyl_daemon_http_copy_access_token_secret (SoupServer *server,
    guint8 *out_secret, gsize out_len)
{
  if (out_secret == NULL || out_len != WYL_DAEMON_JWT_KEY_LEN)
    return WYRELOG_E_INVALID;

  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return WYRELOG_E_INVALID;
  if (!ctx->access_token_secret_ready)
    return WYRELOG_E_INTERNAL;

  g_mutex_lock (&ctx->lock);
  memcpy (out_secret, ctx->access_token_secret, WYL_DAEMON_JWT_KEY_LEN);
  g_mutex_unlock (&ctx->lock);
  return WYRELOG_E_OK;
}

gchar *
wyl_daemon_http_dup_access_token_key_id (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return NULL;

  g_mutex_lock (&ctx->lock);
  gchar *key_id = g_strdup (ctx->access_token_key_id);
  g_mutex_unlock (&ctx->lock);
  return key_id;
}

wyrelog_error_t
wyl_daemon_http_rotate_access_token_key_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_rotate_access_token_key (ctx);
}

static wyrelog_error_t service_token_exchange_core (WylDaemonHttpContext * ctx,
    const WylDaemonServiceTokenRequest * request, guint * out_status,
    gchar ** out_body, guint * out_retry_after);

#ifdef WYL_HAS_AUDIT
void wyl_daemon_http_service_exchange_limiter_snapshot_for_test
    (SoupServer * server, WylServiceExchangeLimiterSnapshot * out_snapshot)
{
  if (out_snapshot == NULL)
    return;
  memset (out_snapshot, 0, sizeof *out_snapshot);
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || ctx->service_exchange_limiter == NULL)
    return;
  wyl_service_exchange_limiter_snapshot_for_test (ctx->service_exchange_limiter,
      out_snapshot);
}

wyrelog_error_t
wyl_daemon_http_service_token_exchange_for_test (SoupServer *server,
    const WylDaemonServiceTokenRequest *request, guint *out_status,
    gchar **out_body, guint *out_retry_after)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return WYRELOG_E_INVALID;
  return service_token_exchange_core (ctx, request, out_status, out_body,
      out_retry_after);
}
#endif

gboolean
wyl_daemon_http_session_is_revoked (SoupServer *server,
    const gchar *session_token)
{
  if (server == NULL || session_token == NULL || session_token[0] == '\0')
    return FALSE;

  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return FALSE;

  g_mutex_lock (&ctx->lock);
  gboolean revoked = g_hash_table_contains (ctx->revoked_session_tokens,
      session_token);
  g_mutex_unlock (&ctx->lock);
  return revoked;
}
#endif

static gboolean
wyl_daemon_http_context_store_session (WylDaemonHttpContext *ctx,
    const gchar *session_token, WylSession *session)
{
  if (ctx == NULL || session_token == NULL || session_token[0] == '\0' ||
      session == NULL || !WYL_IS_SESSION (session))
    return FALSE;

  g_mutex_lock (&ctx->lock);
  g_hash_table_replace (ctx->sessions_by_token, g_strdup (session_token),
      g_object_ref (session));
  g_mutex_unlock (&ctx->lock);
  return TRUE;
}

static gboolean
wyl_daemon_http_context_remove_session (WylDaemonHttpContext *ctx,
    const gchar *session_token)
{
  if (ctx == NULL || session_token == NULL || session_token[0] == '\0')
    return FALSE;

  g_mutex_lock (&ctx->lock);
  gboolean removed = g_hash_table_remove (ctx->sessions_by_token,
      session_token);
  g_mutex_unlock (&ctx->lock);
  return removed;
}

static WylDaemonHttpContext *
wyl_daemon_http_get_context (SoupServer *server)
{
  if (server == NULL || !SOUP_IS_SERVER (server))
    return NULL;
  return g_object_get_data (G_OBJECT (server), "wyl-daemon-http-context");
}

WylSession *
wyl_daemon_http_ref_session (SoupServer *server, const gchar *session_token)
{
  if (session_token == NULL || session_token[0] == '\0')
    return NULL;

  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return NULL;

  g_mutex_lock (&ctx->lock);
  WylSession *session = g_hash_table_lookup (ctx->sessions_by_token,
      session_token);
  if (session != NULL)
    g_object_ref (session);
  g_mutex_unlock (&ctx->lock);
  return session;
}

#ifdef WYL_TEST_DAEMON_HTTP
wyrelog_error_t
wyl_daemon_http_policy_write_for_test (SoupServer *server,
    WylDaemonPolicyWriteCheckpoint checkpoint, gpointer data)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return WYRELOG_E_INVALID;

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (checkpoint != NULL)
    checkpoint (data);
  return wyl_policy_store_set_tenant_sealed (write.store,
      WYL_TENANT_DEFAULT, FALSE);
}

gboolean
wyl_daemon_http_remove_session_for_test (SoupServer *server,
    const gchar *session_token)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_remove_session (ctx, session_token);
}

gboolean
wyl_daemon_http_expire_refresh_grace_for_test (SoupServer *server,
    const gchar *refresh_token)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || refresh_token == NULL || refresh_token[0] == '\0')
    return FALSE;

  gboolean updated = FALSE;
  g_mutex_lock (&ctx->lock);
  WylRefreshTokenState *state =
      g_hash_table_lookup (ctx->refresh_tokens_by_token, refresh_token);
  if (state != NULL && state->consumed) {
    state->consumed_at -= WYL_DAEMON_REFRESH_GRACE_SECONDS + 1;
    updated = TRUE;
  }
  g_mutex_unlock (&ctx->lock);
  return updated;
}
#endif

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", *p);
        else
          g_string_append_c (json, (gchar) * p);
        break;
    }
  }
  g_string_append_c (json, '"');
}

static void
append_json_nullable_string (GString *json, const gchar *name,
    const gchar *value)
{
  g_string_append_c (json, '"');
  g_string_append (json, name);
  g_string_append (json, "\":");
  if (value == NULL)
    g_string_append (json, "null");
  else
    append_json_string (json, value);
}

static gchar *
build_decide_json (const wyl_decide_resp_t *resp)
{
  g_autoptr (GString) json = g_string_new ("{");

  g_string_append_printf (json, "\"decision\":%d",
      (gint) wyl_decide_resp_get_decision (resp));
  g_string_append_c (json, ',');
  append_json_nullable_string (json, "deny_reason",
      wyl_decide_resp_get_deny_reason (resp));
  g_string_append_c (json, ',');
  append_json_nullable_string (json, "deny_origin",
      wyl_decide_resp_get_deny_origin (resp));
  g_string_append_c (json, '}');
  return g_string_free (g_steal_pointer (&json), FALSE);
}

static gchar *
build_login_json (const gchar *session_token, const gchar *username,
    const gchar *tenant, const gchar *principal_state,
    const gchar *access_token, const gchar *refresh_token)
{
  g_autoptr (GString) json = g_string_new ("{");

  g_string_append (json, "\"session_token\":");
  append_json_string (json, session_token);
  g_string_append (json, ",\"username\":");
  append_json_string (json, username);
  g_string_append (json, ",\"tenant\":");
  append_json_string (json, tenant);
  g_string_append (json, ",\"principal_state\":");
  append_json_string (json, principal_state);
  g_string_append (json, ",\"session_state\":\"active\"");
  if (access_token != NULL) {
    g_string_append (json, ",\"access_token\":");
    append_json_string (json, access_token);
  }
  if (refresh_token != NULL) {
    g_string_append (json, ",\"refresh_token\":");
    append_json_string (json, refresh_token);
  }
  g_string_append_c (json, '}');
  return g_string_free (g_steal_pointer (&json), FALSE);
}

static gchar *
build_service_token_json (const gchar *access_token)
{
  g_autoptr (GString) json = g_string_new ("{\"access_token\":");
  append_json_string (json, access_token);
  g_string_append_c (json, '}');
  return g_string_free (g_steal_pointer (&json), FALSE);
}

#ifndef WYL_TEST_DAEMON_HTTP
typedef struct
{
  gboolean transport_ok;
  gboolean body_oversize;
  const gchar *body_json;
  gsize body_len;
} WylDaemonServiceTokenRequest;
#endif

static void set_json_error_with_retry_after (SoupServerMessage * msg,
    guint status, const gchar * code, guint retry_after_seconds);
static wyrelog_error_t service_token_exchange_core (WylDaemonHttpContext * ctx,
    const WylDaemonServiceTokenRequest * request, guint * out_status,
    gchar ** out_body, guint * out_retry_after);
static wyrelog_error_t copy_access_token_secret (WylDaemonHttpContext * ctx,
    guint8 out_secret[WYL_DAEMON_JWT_KEY_LEN]);
static void attach_request_id_header (SoupServerMessage * msg);

#ifdef WYL_HAS_AUDIT
typedef struct
{
  wyrelog_error_t (*reserve) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant);
  wyrelog_error_t (*activate) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant, gboolean * out_changed);
  wyrelog_error_t (*remove_exact) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant, gboolean * out_removed);
  gpointer user_data;
} WylDaemonServiceTokenExchangeHooks;

static wyrelog_error_t
service_token_registry_reserve_hook (gpointer user_data,
    const gchar *session_id, const gchar *jti, const gchar *credential_id,
    guint64 generation, const gchar *principal, const gchar *tenant)
{
  return wyl_service_auth_registry_reserve (user_data,
      &(WylServiceAuthReservation) {
      .session_id = (gchar *) session_id,.jti = (gchar *) jti,.credential_id =
        (gchar *) credential_id,.generation = generation,.principal =
        (gchar *) principal,.tenant = (gchar *) tenant,}
  );
}

static wyrelog_error_t
service_token_registry_activate_hook (gpointer user_data,
    const gchar *session_id, const gchar *jti, const gchar *credential_id,
    guint64 generation, const gchar *principal, const gchar *tenant,
    gboolean *out_changed)
{
  return wyl_service_auth_registry_activate (user_data,
      &(WylServiceAuthReservation) {
      .session_id = (gchar *) session_id,.jti = (gchar *) jti,.credential_id =
        (gchar *) credential_id,.generation = generation,.principal =
        (gchar *) principal,.tenant = (gchar *) tenant,}
      , out_changed);
}

static wyrelog_error_t
service_token_registry_remove_hook (gpointer user_data,
    const gchar *session_id, const gchar *jti, const gchar *credential_id,
    guint64 generation, const gchar *principal, const gchar *tenant,
    gboolean *out_removed)
{
  return wyl_service_auth_registry_remove_exact (user_data,
      &(WylServiceAuthReservation) {
      .session_id = (gchar *) session_id,.jti = (gchar *) jti,.credential_id =
        (gchar *) credential_id,.generation = generation,.principal =
        (gchar *) principal,.tenant = (gchar *) tenant,}
      , out_removed);
}

static wyrelog_error_t
service_token_limiter_decide (WylDaemonHttpContext *ctx,
    WylServiceExchangeLimiterRequestKind kind, const gchar *credential_id,
    WylServiceExchangeLimiterDecision *out_decision)
{
  if (ctx == NULL || out_decision == NULL)
    return WYRELOG_E_INVALID;
  if (ctx->service_exchange_limiter == NULL)
    return WYRELOG_E_INTERNAL;
  return wyl_service_exchange_limiter_decide (ctx->service_exchange_limiter,
      kind, credential_id, out_decision);
}

static wyrelog_error_t
service_token_response_set_error (guint status, const gchar *code,
    guint retry_after_seconds, guint *out_status, gchar **out_body,
    guint *out_retry_after)
{
  if (out_status == NULL || out_body == NULL)
    return WYRELOG_E_INVALID;
  *out_status = status;
  if (out_retry_after != NULL)
    *out_retry_after = retry_after_seconds;
  *out_body = g_strdup_printf ("{\"error\":\"%s\"}", code);
  return *out_body != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

static wyrelog_error_t
service_token_exchange_prepare (WylDaemonHttpContext *ctx,
    const gchar *credential_id, const gchar *credential_secret,
    gsize credential_secret_len, gchar **out_body)
{
  if (out_body != NULL)
    *out_body = NULL;
  if (ctx == NULL || credential_id == NULL || credential_secret == NULL
      || credential_secret_len == 0 || out_body == NULL)
    return WYRELOG_E_INVALID;

  WylServiceExchangeAuthority authority = { 0 };
  wyrelog_error_t rc = wyl_service_exchange_authority_begin (ctx->handle,
      credential_id, credential_secret, credential_secret_len,
      g_get_real_time (), &authority);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_authority_clear (&authority);
    return rc;
  }

  guint8 token_secret[WYL_DAEMON_JWT_KEY_LEN];
  rc = copy_access_token_secret (ctx, token_secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylServiceExchangeRegistryHooks hooks = {
    .reserve = service_token_registry_reserve_hook,
    .activate = service_token_registry_activate_hook,
    .remove_exact = service_token_registry_remove_hook,
    .user_data = ctx->service_auth_registry,
  };
  WylServiceExchangePrepared prepared = { 0 };
  rc = wyl_service_exchange_authority_complete (&authority,
      ctx->access_token_key_id, WYL_DAEMON_JWT_ISSUER, WYL_DAEMON_JWT_AUDIENCE,
      g_get_real_time () / G_USEC_PER_SEC, token_secret,
      sizeof token_secret, &hooks, &prepared);
  sodium_memzero (token_secret, sizeof token_secret);
  if (rc != WYRELOG_E_OK) {
    wyl_service_exchange_authority_clear (&authority);
    return rc;
  }
  if (prepared.session == NULL || prepared.access_token == NULL) {
    wyl_service_exchange_prepared_clear (&prepared);
    wyl_service_exchange_authority_clear (&authority);
    return WYRELOG_E_INTERNAL;
  }

  g_autofree gchar *session_id = wyl_session_dup_id_string (prepared.session);
  g_autofree gchar *subject = wyl_session_dup_service_subject_private
      (prepared.session);
  g_autofree gchar *tenant = wyl_session_dup_service_tenant_private
      (prepared.session);
  if (session_id == NULL || subject == NULL || tenant == NULL) {
    wyl_service_exchange_prepared_clear (&prepared);
    wyl_service_exchange_authority_clear (&authority);
    return WYRELOG_E_INTERNAL;
  }

  *out_body = build_service_token_json (prepared.access_token);
  wyl_service_exchange_prepared_clear (&prepared);
  wyl_service_exchange_authority_clear (&authority);
  return *out_body != NULL ? WYRELOG_E_OK : WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
service_token_exchange_core (WylDaemonHttpContext *ctx,
    const WylDaemonServiceTokenRequest *request, guint *out_status,
    gchar **out_body, guint *out_retry_after)
{
  if (out_status != NULL)
    *out_status = 0;
  if (out_body != NULL)
    *out_body = NULL;
  if (out_retry_after != NULL)
    *out_retry_after = 0;
  if (ctx == NULL || request == NULL || out_status == NULL || out_body == NULL)
    return WYRELOG_E_INVALID;

  if (!request->transport_ok) {
    *out_status = 403;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_AUTH_REQUIRED);
    return WYRELOG_E_OK;
  }

  if (request->body_oversize) {
    WylServiceExchangeLimiterDecision decision = { 0 };
    wyrelog_error_t rc = service_token_limiter_decide (ctx,
        WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!decision.allowed) {
      *out_status = 429;
      if (out_retry_after != NULL)
        *out_retry_after = decision.retry_after_seconds;
      *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
          WYL_DAEMON_ERR_SERVICE_TOKEN_RATE_LIMITED);
      return WYRELOG_E_OK;
    }
    *out_status = 400;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_INVALID);
    return WYRELOG_E_OK;
  }

  static const WylDaemonHttpStrictJsonField fields[] = {
    {"credential_id", 4096},
    {"credential_secret", 16384},
  };
  g_auto (GStrv) values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
  gboolean parsed = wyl_daemon_http_dup_strict_json_object
      (request->body_json, request->body_len, fields, G_N_ELEMENTS (fields),
      values);
  if (!parsed) {
    WylServiceExchangeLimiterDecision decision = { 0 };
    wyrelog_error_t rc = service_token_limiter_decide (ctx,
        WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision);
    if (rc != WYRELOG_E_OK) {
      return rc;
    }
    if (!decision.allowed) {
      *out_status = 429;
      if (out_retry_after != NULL)
        *out_retry_after = decision.retry_after_seconds;
      *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
          WYL_DAEMON_ERR_SERVICE_TOKEN_RATE_LIMITED);
      return WYRELOG_E_OK;
    }
    *out_status = 400;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_INVALID);
    return WYRELOG_E_OK;
  }

  const gchar *credential_id = values[0];
  const gchar *credential_secret = values[1];
  if (credential_id == NULL || credential_secret == NULL
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id))) {
    WylServiceExchangeLimiterDecision decision = { 0 };
    wyrelog_error_t rc = service_token_limiter_decide (ctx,
        WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_MALFORMED, NULL, &decision);
    if (rc != WYRELOG_E_OK) {
      return rc;
    }
    if (!decision.allowed) {
      *out_status = 429;
      if (out_retry_after != NULL)
        *out_retry_after = decision.retry_after_seconds;
      *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
          WYL_DAEMON_ERR_SERVICE_TOKEN_RATE_LIMITED);
      return WYRELOG_E_OK;
    }
    *out_status = 400;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_INVALID);
    return WYRELOG_E_OK;
  }

  WylServiceExchangeLimiterDecision decision = { 0 };
  wyrelog_error_t rc = service_token_limiter_decide (ctx,
      WYL_SERVICE_EXCHANGE_LIMITER_REQUEST_CANONICAL, credential_id,
      &decision);
  if (rc != WYRELOG_E_OK) {
    return rc;
  }
  if (!decision.allowed) {
    *out_status = 429;
    if (out_retry_after != NULL)
      *out_retry_after = decision.retry_after_seconds;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_RATE_LIMITED);
    return WYRELOG_E_OK;
  }

  g_autofree gchar *body = NULL;
  rc = service_token_exchange_prepare (ctx, credential_id, credential_secret,
      strlen (credential_secret), &body);
  if (rc == WYRELOG_E_AUTH) {
    *out_status = 401;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_AUTH_REQUIRED);
    return WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_BUSY) {
    *out_status = 503;
    *out_body = g_strdup_printf ("{\"error\":\"service_token_unavailable\"}");
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_OK || body == NULL) {
    *out_status = 500;
    *out_body = g_strdup_printf ("{\"error\":\"%s\"}",
        WYL_DAEMON_ERR_SERVICE_TOKEN_FAILED);
    return WYRELOG_E_OK;
  }
  *out_body = g_steal_pointer (&body);
  *out_status = 200;
  return WYRELOG_E_OK;
}

static void
service_token_exchange_handle (SoupServerMessage *msg,
    WylDaemonHttpContext *ctx, const WylDaemonServiceTokenRequest *request)
{
  guint status = 0;
  guint retry_after = 0;
  g_autofree gchar *body = NULL;
  wyrelog_error_t rc = service_token_exchange_core (ctx, request, &status,
      &body, &retry_after);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_TOKEN_FAILED);
    return;
  }
  attach_request_id_header (msg);
  if (status == 429 && retry_after > 0) {
    g_autofree gchar *retry_after_str = g_strdup_printf ("%u", retry_after);
    soup_message_headers_replace (soup_server_message_get_response_headers
        (msg), "Retry-After", retry_after_str);
  }
  soup_server_message_set_status (msg, status, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body != NULL ? body : "{}", body != NULL ?
      strlen (body) : 2);
}

static void
service_token_exchange_http_handler (SoupServer *server,
    SoupServerMessage *msg, const char *path, GHashTable *query,
    gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  WylDaemonHttpContext *ctx = user_data;
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  SoupMessageBody *body = soup_server_message_get_request_body (msg);
  WylDaemonServiceTokenRequest request = {
    .transport_ok = wyl_daemon_http_message_has_actual_loopback_transport (msg),
    .body_oversize = body != NULL && body->length > 16 * 1024,
    .body_json = body != NULL && body->data != NULL ? body->data : "",
    .body_len = body != NULL ? (gsize) body->length : 0,
  };
  service_token_exchange_handle (msg, ctx, &request);
}

wyrelog_error_t
wyl_daemon_http_issue_service_token_for_test (SoupServer *server,
    gboolean transport_ok, const gchar *request_body, gsize request_body_len,
    guint *out_status, gchar **out_body, guint *out_retry_after)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || out_status == NULL || out_body == NULL)
    return WYRELOG_E_INVALID;

  WylDaemonServiceTokenRequest request = {
    .transport_ok = transport_ok,
    .body_oversize = request_body_len > 16 * 1024,
    .body_json = request_body,
    .body_len = request_body_len,
  };
  return service_token_exchange_core (ctx, &request, out_status, out_body,
      out_retry_after);
}
#endif

static wyrelog_error_t
copy_access_token_secret (WylDaemonHttpContext *ctx,
    guint8 out_secret[WYL_DAEMON_JWT_KEY_LEN])
{
  if (ctx == NULL || out_secret == NULL)
    return WYRELOG_E_INVALID;
  if (!ctx->access_token_secret_ready)
    return WYRELOG_E_INTERNAL;
  g_mutex_lock (&ctx->lock);
  memcpy (out_secret, ctx->access_token_secret, WYL_DAEMON_JWT_KEY_LEN);
  g_mutex_unlock (&ctx->lock);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
issue_access_token (WylDaemonHttpContext *ctx, WylSession *session,
    const gchar *session_token, const gchar *username, const gchar *tenant,
    const gchar *principal_state, gint64 issued_at, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (session_token == NULL || username == NULL || tenant == NULL
      || principal_state == NULL || issued_at < 0)
    return WYRELOG_E_INVALID;
  if (!human_session_matches (ctx, session, session_token, username, tenant))
    return WYRELOG_E_POLICY;

  guint8 secret[WYL_DAEMON_JWT_KEY_LEN];
  wyrelog_error_t rc = copy_access_token_secret (ctx, secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *token_id = NULL;
  rc = new_token_id_string (&token_id);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (secret, sizeof secret);
    return rc;
  }

  gint64 ttl = WYL_JWT_ACCESS_TTL_SECONDS;
  if (issued_at > G_MAXINT64 - ttl) {
    sodium_memzero (secret, sizeof secret);
    return WYRELOG_E_INVALID;
  }
  wyl_jwt_issue_input_t input = {
    .key_id = ctx->access_token_key_id,
    .jti = token_id,
    .subject = username,
    .issuer = WYL_DAEMON_JWT_ISSUER,
    .audience = WYL_DAEMON_JWT_AUDIENCE,
    .tenant = tenant,
    .principal_state_at_issue = principal_state,
    .session_id = session_token,
    .issued_at = issued_at,
    .ttl_seconds = ttl,
  };
  rc = wyl_jwt_sign_hs256 (&input, secret, sizeof secret, out_token);
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!wyl_daemon_http_context_store_access_token (ctx, session, token_id,
          session_token, username, tenant, ctx->access_token_key_id,
          issued_at + ttl)) {
    g_clear_pointer (out_token, g_free);
    return WYRELOG_E_INTERNAL;
  }
  return rc;
}

static wyrelog_error_t
issue_login_access_token (WylDaemonHttpContext *ctx, const gchar *session_token,
    WylSession *session, const gchar *username, const gchar *tenant,
    const gchar *principal_state, gchar **out_token)
{
  return issue_access_token (ctx, session, session_token, username, tenant,
      principal_state, g_get_real_time () / G_USEC_PER_SEC, out_token);
}

static wyrelog_error_t
issue_refresh_token (WylDaemonHttpContext *ctx, WylSession *session,
    const gchar *session_token, const gchar *username, const gchar *tenant,
    gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (ctx == NULL || session_token == NULL || username == NULL
      || tenant == NULL)
    return WYRELOG_E_INVALID;
  if (!human_session_matches (ctx, session, session_token, username, tenant))
    return WYRELOG_E_POLICY;

  g_autofree gchar *token = NULL;
  wyrelog_error_t rc = new_token_id_string (&token);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  if (now > G_MAXINT64 - WYL_DAEMON_REFRESH_TTL_SECONDS)
    return WYRELOG_E_INVALID;

  if (!wyl_daemon_http_context_store_refresh_token (ctx, session, token,
          session_token, username, tenant, now,
          now + WYL_DAEMON_REFRESH_TTL_SECONDS))
    return WYRELOG_E_INTERNAL;

  *out_token = g_steal_pointer (&token);
  return WYRELOG_E_OK;
}

#ifdef WYL_TEST_DAEMON_HTTP
wyrelog_error_t
wyl_daemon_http_issue_human_tokens_for_test (SoupServer *server,
    WylSession *session, const gchar *session_id, const gchar *subject,
    const gchar *tenant, gchar **out_access, gchar **out_refresh)
{
  if (out_access == NULL || out_refresh == NULL)
    return WYRELOG_E_INVALID;
  *out_access = NULL;
  *out_refresh = NULL;
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  wyrelog_error_t rc = issue_login_access_token (ctx, session_id, session,
      subject, tenant, "authenticated", out_access);
  if (rc == WYRELOG_E_OK)
    rc = issue_refresh_token (ctx, session, session_id, subject, tenant,
        out_refresh);
  if (rc != WYRELOG_E_OK) {
    g_clear_pointer (out_access, g_free);
    g_clear_pointer (out_refresh, g_free);
  }
  return rc;
}

gboolean
wyl_daemon_http_seed_refresh_for_test (SoupServer *server,
    WylSession *session, const gchar *token, const gchar *session_id,
    const gchar *subject, const gchar *tenant, gint auth_method,
    gboolean consumed, const gchar *successor_access,
    const gchar *successor_refresh)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session == NULL || token == NULL || session_id == NULL
      || subject == NULL || tenant == NULL)
    return FALSE;
  WylRefreshTokenState *state = g_new0 (WylRefreshTokenState, 1);
  state->token = g_strdup (token);
  state->session_id = g_strdup (session_id);
  state->subject = g_strdup (subject);
  state->tenant = g_strdup (tenant);
  state->auth_method = (wyl_session_auth_method_t) auth_method;
  state->issued_at = g_get_real_time () / G_USEC_PER_SEC;
  state->expires_at = state->issued_at + WYL_DAEMON_REFRESH_TTL_SECONDS;
  state->consumed = consumed;
  state->consumed_at = state->issued_at;
  if (successor_access != NULL && successor_refresh != NULL)
    state->successor = wyl_human_refresh_result_new_take
        (g_strdup (successor_access), g_strdup (successor_refresh));
  g_mutex_lock (&ctx->lock);
  state->epoch = human_refresh_next_nonzero (&ctx->next_refresh_epoch);
  g_hash_table_replace (ctx->sessions_by_token, g_strdup (session_id),
      g_object_ref (session));
  g_hash_table_replace (ctx->refresh_tokens_by_token, g_strdup (token), state);
  g_mutex_unlock (&ctx->lock);
  return TRUE;
}

gchar *
wyl_daemon_http_dup_refresh_state_for_test (SoupServer *server,
    const gchar *token, guint *out_refresh_count, guint *out_access_count)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || token == NULL || out_refresh_count == NULL
      || out_access_count == NULL)
    return NULL;
  g_mutex_lock (&ctx->lock);
  *out_refresh_count = g_hash_table_size (ctx->refresh_tokens_by_token);
  *out_access_count = g_hash_table_size (ctx->access_tokens_by_jti);
  WylRefreshTokenState *state =
      g_hash_table_lookup (ctx->refresh_tokens_by_token, token);
  gchar *snapshot =
      state ==
      NULL ? NULL : g_strdup_printf ("%s|%s|%s|%s|%d|%d|%d|%" G_GINT64_FORMAT
      "|%" G_GINT64_FORMAT "|%" G_GINT64_FORMAT "|%s|%s", state->token,
      state->session_id,
      state->subject, state->tenant, (gint) state->auth_method,
      state->consumed, state->revoked, state->issued_at, state->expires_at,
      state->consumed_at, state->successor != NULL
      ? state->successor->access_token : "", state->successor != NULL
      ? state->successor->refresh_token : "");
  g_mutex_unlock (&ctx->lock);
  return snapshot;
}

void
wyl_daemon_http_reset_refresh_counters_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  ctx->refresh_handler_entries = 0;
  ctx->refresh_dispatch_owned = 0;
  ctx->refresh_dispatch_wrong = 0;
  g_atomic_int_set ((gint *) & ctx->refresh_access_id_successes, 0);
  g_atomic_int_set ((gint *) & ctx->refresh_jwt_sign_attempts, 0);
  g_atomic_int_set ((gint *) & ctx->refresh_jwt_sign_successes, 0);
  g_atomic_int_set ((gint *) & ctx->refresh_token_id_successes, 0);
  g_atomic_int_set ((gint *) & ctx->refresh_publications, 0);
  g_ptr_array_set_size (ctx->refresh_generated_ids, 0);
  g_mutex_unlock (&ctx->lock);
}

void
wyl_daemon_http_refresh_counters_for_test (SoupServer *server,
    WylDaemonRefreshCounters *out_counters)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || out_counters == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  out_counters->handler_entries = ctx->refresh_handler_entries;
  out_counters->wrong_context = ctx->refresh_dispatch_wrong;
  g_mutex_unlock (&ctx->lock);
  out_counters->access_id_successes = g_atomic_int_get
      ((gint *) & ctx->refresh_access_id_successes);
  out_counters->jwt_sign_attempts = g_atomic_int_get
      ((gint *) & ctx->refresh_jwt_sign_attempts);
  out_counters->jwt_sign_successes = g_atomic_int_get
      ((gint *) & ctx->refresh_jwt_sign_successes);
  out_counters->refresh_id_successes = g_atomic_int_get
      ((gint *) & ctx->refresh_token_id_successes);
  out_counters->publications = g_atomic_int_get
      ((gint *) & ctx->refresh_publications);
}

void
wyl_daemon_http_set_refresh_clock_for_test (SoupServer *server,
    gboolean enabled, gint64 now)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  ctx->refresh_clock_injected = enabled;
  ctx->refresh_clock_now = now;
  g_mutex_unlock (&ctx->lock);
}

gboolean
wyl_daemon_http_set_refresh_times_for_test (SoupServer *server,
    const gchar *token, gint64 expires_at, gint64 consumed_at)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || token == NULL)
    return FALSE;
  g_mutex_lock (&ctx->lock);
  WylRefreshTokenState *state = g_hash_table_lookup
      (ctx->refresh_tokens_by_token, token);
  gboolean changed = state != NULL;
  if (changed) {
    state->expires_at = expires_at;
    state->consumed_at = consumed_at;
  }
  g_mutex_unlock (&ctx->lock);
  return changed;
}

void
wyl_daemon_http_fail_next_refresh_publication_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  ctx->fail_next_refresh_publication = TRUE;
  g_mutex_unlock (&ctx->lock);
}

void
wyl_daemon_http_set_refresh_fault_for_test (SoupServer *server,
    WylDaemonRefreshFault fault)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  ctx->refresh_fault = fault;
  g_mutex_unlock (&ctx->lock);
}

static gint
human_refresh_id_compare (gconstpointer left, gconstpointer right)
{
  return g_strcmp0 (*(const gchar * const *) left,
      *(const gchar * const *) right);
}

static gchar **
human_refresh_snapshot_ids_locked (WylDaemonHttpContext *ctx,
    const gchar *session_id, gboolean refresh_ids)
{
  GPtrArray *values = g_ptr_array_new_with_free_func (g_free);
  GHashTableIter iter;
  gpointer value = NULL;
  g_hash_table_iter_init (&iter, refresh_ids ? ctx->refresh_tokens_by_token
      : ctx->access_tokens_by_jti);
  while (g_hash_table_iter_next (&iter, NULL, &value)) {
    const gchar *owner = refresh_ids
        ? ((WylRefreshTokenState *) value)->session_id
        : ((WylAccessTokenState *) value)->session_id;
    const gchar *id = refresh_ids ? ((WylRefreshTokenState *) value)->token
        : ((WylAccessTokenState *) value)->jti;
    if (g_strcmp0 (owner, session_id) == 0)
      g_ptr_array_add (values, g_strdup (id));
  }
  g_ptr_array_sort (values, human_refresh_id_compare);
  g_ptr_array_add (values, NULL);
  return (gchar **) g_ptr_array_free (values, FALSE);
}

gchar **
wyl_daemon_http_snapshot_session_access_ids_for_test (SoupServer *server,
    const gchar *session_id)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session_id == NULL)
    return NULL;
  g_mutex_lock (&ctx->lock);
  gchar **values = human_refresh_snapshot_ids_locked (ctx, session_id, FALSE);
  g_mutex_unlock (&ctx->lock);
  return values;
}

gchar **
wyl_daemon_http_snapshot_session_refresh_ids_for_test (SoupServer *server,
    const gchar *session_id)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session_id == NULL)
    return NULL;
  g_mutex_lock (&ctx->lock);
  gchar **values = human_refresh_snapshot_ids_locked (ctx, session_id, TRUE);
  g_mutex_unlock (&ctx->lock);
  return values;
}

gchar **
wyl_daemon_http_snapshot_generated_refresh_ids_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return NULL;
  g_mutex_lock (&ctx->lock);
  gchar **values = g_new0 (gchar *, ctx->refresh_generated_ids->len + 1);
  for (guint i = 0; i < ctx->refresh_generated_ids->len; i++)
    values[i] = g_strdup (g_ptr_array_index (ctx->refresh_generated_ids, i));
  g_mutex_unlock (&ctx->lock);
  return values;
}

void
wyl_daemon_http_sensitive_strv_free_for_test (gchar **values)
{
  if (values == NULL)
    return;
  for (guint i = 0; values[i] != NULL; i++)
    wyl_sensitive_string_free (values[i]);
  g_free (values);
}

void
wyl_daemon_http_revoke_human_session_for_test (SoupServer *server,
    const gchar *session_id)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || session_id == NULL)
    return;
  wyl_daemon_http_context_revoke_session_refresh_tokens (ctx, session_id);
  wyl_daemon_http_context_revoke_session_access_tokens (ctx, session_id);
  wyl_daemon_http_context_mark_session_revoked (ctx, session_id);
  wyl_daemon_http_context_remove_session (ctx, session_id);
}

void
wyl_daemon_http_terminalize_refreshes_for_test (SoupServer *server)
{
  wyl_daemon_http_context_terminalize (wyl_daemon_http_get_context (server),
      TRUE);
}

guint64
wyl_daemon_http_arm_refresh_latch_for_test (SoupServer *server,
    WylDaemonRefreshPhase phase)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return 0;
  WylHumanRefreshTestLatch *latch = &ctx->refresh_latch;
  g_autoptr (GMutexLocker) locker = g_mutex_locker_new (&latch->mutex);
  latch->generation++;
  if (latch->generation == 0)
    latch->generation++;
  latch->phase = phase;
  latch->armed = TRUE;
  latch->entered = FALSE;
  latch->released = FALSE;
  guint64 generation = latch->generation;
  return generation;
}

gboolean
wyl_daemon_http_wait_refresh_latch_for_test (SoupServer *server,
    guint64 generation, gint64 deadline_us)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || generation == 0)
    return FALSE;
  WylHumanRefreshTestLatch *latch = &ctx->refresh_latch;
  g_autoptr (GMutexLocker) locker = g_mutex_locker_new (&latch->mutex);
  while (latch->generation == generation && latch->armed && !latch->entered)
    if (!g_cond_wait_until (&latch->changed, &latch->mutex, deadline_us))
      break;
  gboolean entered = latch->generation == generation && latch->entered;
  return entered;
}

void
wyl_daemon_http_release_refresh_latch_for_test (SoupServer *server,
    guint64 generation)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  WylHumanRefreshTestLatch *latch = &ctx->refresh_latch;
  g_autoptr (GMutexLocker) locker = g_mutex_locker_new (&latch->mutex);
  if (latch->generation == generation) {
    latch->released = TRUE;
    g_cond_broadcast (&latch->changed);
  }
}

void
wyl_daemon_http_disarm_refresh_latch_for_test (SoupServer *server,
    guint64 generation)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return;
  WylHumanRefreshTestLatch *latch = &ctx->refresh_latch;
  g_autoptr (GMutexLocker) locker = g_mutex_locker_new (&latch->mutex);
  if (latch->generation == generation) {
    latch->released = TRUE;
    latch->armed = FALSE;
    g_cond_broadcast (&latch->changed);
  }
}

void
wyl_daemon_http_refresh_lifecycle_counts_for_test (SoupServer *server,
    guint *out_owned, guint *out_wrong)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL || out_owned == NULL || out_wrong == NULL)
    return;
  g_mutex_lock (&ctx->lock);
  *out_owned = ctx->refresh_dispatch_owned;
  *out_wrong = ctx->refresh_dispatch_wrong;
  g_mutex_unlock (&ctx->lock);
}

gboolean
wyl_daemon_http_refresh_context_owned_for_test (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return ctx != NULL && human_refresh_dispatch_owned (ctx);
}

gboolean
wyl_daemon_http_refresh_context_is_for_test (SoupServer *server,
    GMainContext *expected)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return ctx != NULL && ctx->dispatch_context == expected;
}

#endif

static const gchar *
lookup_bearer_token (SoupServerMessage *msg)
{
  SoupMessageHeaders *headers = soup_server_message_get_request_headers (msg);
  const gchar *authorization = soup_message_headers_get_one (headers,
      "Authorization");
  if (authorization == NULL)
    return NULL;
  if (!g_str_has_prefix (authorization, "Bearer "))
    return "";
  const gchar *token = authorization + strlen ("Bearer ");
  if (token[0] == '\0')
    return "";
  return token;
}

/* Sole bearer resolver for human and service credentials. */
static wyrelog_error_t
resolve_bearer_session (SoupServer *server, WylDaemonHttpContext *ctx,
    const gchar *token, WylDaemonAuthContext *out_auth,
    const gchar **out_auth_error_code)
{
  if (out_auth_error_code != NULL)
    *out_auth_error_code = NULL;
  if (ctx == NULL || token == NULL || out_auth == NULL)
    return WYRELOG_E_INVALID;
  wyl_daemon_auth_context_clear (out_auth);

  guint8 secret[WYL_DAEMON_JWT_KEY_LEN];
  wyrelog_error_t rc = copy_access_token_secret (ctx, secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (GBytes) payload = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  rc = wyl_jwt_verify_hs256_access_token (token, secret, sizeof secret,
      ctx->access_token_key_id, WYL_DAEMON_JWT_ISSUER,
      WYL_DAEMON_JWT_AUDIENCE, now, &payload);
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  wyl_jwt_access_claims_t claims = { 0 };
  rc = wyl_jwt_parse_access_claims_json (payload, &claims);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  if (g_strcmp0 (claims.auth_method, "service_credential") == 0) {
    WylServiceAuthReadLease *lease = NULL;
    WylServiceAuthReservation reservation = { 0 };
    WylServiceAuthState registry_state = WYL_SERVICE_AUTH_PENDING;
    gboolean found = FALSE, tenant_exists = FALSE, tenant_active = FALSE;
    WylServiceAuthUnavailableReason unavailable_reason =
        WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    wyl_policy_store_t *store = NULL;
    g_autoptr (WylSession) service_session = NULL;
    g_autofree gchar *session_id = NULL;
    g_autofree gchar *actor = NULL;
    g_autofree gchar *tenant = NULL;
    g_autofree gchar *live_jti = NULL;
    g_autofree gchar *live_subject = NULL;
    g_autofree gchar *live_tenant = NULL;
    g_autofree gchar *live_credential = NULL;
    wyl_id_t persistent_id = WYL_ID_NIL;
    gchar persistent_text[WYL_ID_STRING_BUF];
#ifdef WYL_TEST_DAEMON_HTTP
    ctx->resolver_terminal_entries = 0;
#endif

    rc = wyl_service_auth_authority_acquire_read
        (wyl_handle_get_service_auth_authority (ctx->handle), ctx->handle,
        NULL, &lease);
    if (rc == WYRELOG_E_OK)
      rc = wyl_service_auth_authority_validate_available
          (wyl_handle_get_service_auth_authority (ctx->handle), ctx->handle,
          &unavailable_reason);
    if (rc == WYRELOG_E_OK)
      rc = wyl_service_auth_read_lease_get_policy_store (lease, ctx->handle,
          &store);
    if (rc == WYRELOG_E_OK) {
      rc = wyl_policy_store_tenant_exists (store, claims.tenant,
          &tenant_exists);
      if (rc != WYRELOG_E_OK || !tenant_exists) {
        if (out_auth_error_code != NULL)
          *out_auth_error_code = WYL_DAEMON_ERR_TENANT_INVALID;
        rc = WYRELOG_E_POLICY;
      }
    }
    if (rc == WYRELOG_E_OK) {
      rc = wyl_policy_store_tenant_is_active (store, claims.tenant,
          &tenant_active);
      if (rc != WYRELOG_E_OK || !tenant_active) {
        if (out_auth_error_code != NULL)
          *out_auth_error_code = WYL_DAEMON_ERR_TENANT_SEALED;
        rc = WYRELOG_E_POLICY;
      }
    }
    if (rc == WYRELOG_E_OK
        && !wyl_daemon_http_context_service_access_token_is_exact (ctx,
            claims.jti, claims.session_id, claims.subject, claims.tenant,
            ctx->access_token_key_id, claims.expires_at,
            WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, claims.credential_id,
            claims.credential_generation, now))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      service_session = wyl_daemon_http_ref_session (server, claims.session_id);
      if (service_session == NULL
          || wyl_session_get_auth_method_private (service_session)
          != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
          || !wyl_session_is_active_private (service_session))
        rc = WYRELOG_E_POLICY;
    }
    if (rc == WYRELOG_E_OK) {
      live_jti = wyl_session_dup_service_jti_private (service_session);
      live_subject = wyl_session_dup_service_subject_private (service_session);
      live_tenant = wyl_session_dup_service_tenant_private (service_session);
      live_credential = wyl_session_dup_service_credential_id_private
          (service_session);
      if (wyl_session_copy_persistent_id_private (service_session,
              &persistent_id) != WYRELOG_E_OK
          || wyl_id_format (&persistent_id, persistent_text,
              sizeof persistent_text) != WYRELOG_E_OK
          || g_strcmp0 (persistent_text, claims.session_id) != 0
          || g_strcmp0 (live_jti, claims.jti) != 0
          || g_strcmp0 (live_subject, claims.subject) != 0
          || g_strcmp0 (live_tenant, claims.tenant) != 0
          || g_strcmp0 (live_credential, claims.credential_id) != 0
          || wyl_session_get_service_credential_generation_private
          (service_session) != claims.credential_generation
          || wyl_session_get_service_issued_at_seconds_private
          (service_session) != claims.issued_at
          || wyl_session_get_service_expires_at_seconds_private
          (service_session) != claims.expires_at)
        rc = WYRELOG_E_POLICY;
    }
    if (rc == WYRELOG_E_OK) {
      rc = wyl_service_auth_registry_lookup (ctx->service_auth_registry,
          claims.session_id, claims.jti, &reservation, &registry_state, &found);
      if (rc != WYRELOG_E_OK || !found
          || registry_state != WYL_SERVICE_AUTH_ACTIVE
          || g_strcmp0 (reservation.session_id, claims.session_id) != 0
          || g_strcmp0 (reservation.jti, claims.jti) != 0
          || g_strcmp0 (reservation.credential_id, claims.credential_id) != 0
          || reservation.generation != claims.credential_generation
          || g_strcmp0 (reservation.principal, claims.subject) != 0
          || g_strcmp0 (reservation.tenant, claims.tenant) != 0)
        rc = WYRELOG_E_POLICY;
    }
    if (rc == WYRELOG_E_OK) {
      session_id = g_strdup (claims.session_id);
      actor = g_strdup (claims.subject);
      tenant = g_strdup (claims.tenant);
      out_auth->session_id = g_steal_pointer (&session_id);
      out_auth->actor = g_steal_pointer (&actor);
      out_auth->tenant = g_steal_pointer (&tenant);
      out_auth->bearer = TRUE;
#ifdef WYL_TEST_DAEMON_HTTP
      if (ctx->resolver_checkpoint != NULL)
        ctx->resolver_checkpoint (WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED,
            ctx->resolver_checkpoint_data);
#endif
    }
    if (lease != NULL) {
#ifdef WYL_TEST_DAEMON_HTTP
      wyl_service_auth_read_lease_test_set_terminal_checkpoint (lease,
          service_resolver_terminal_entry_for_test,
          &ctx->resolver_terminal_entries);
      if (ctx->fail_next_resolver_read_release) {
        ctx->fail_next_resolver_read_release = FALSE;
        wyl_service_auth_read_lease_test_fail_terminal_prevalidation (lease);
      }
#endif
      wyrelog_error_t release_rc =
          wyl_service_auth_read_lease_release_terminal (&lease);
      if (release_rc != WYRELOG_E_OK)
        rc = release_rc;
#ifdef WYL_TEST_DAEMON_HTTP
      if (ctx->resolver_checkpoint != NULL)
        ctx->resolver_checkpoint (WYL_DAEMON_SERVICE_RESOLVER_RELEASED,
            ctx->resolver_checkpoint_data);
#endif
    }
    wyl_service_auth_reservation_clear (&reservation);
    if (rc != WYRELOG_E_OK)
      wyl_daemon_auth_context_clear (out_auth);
    wyl_jwt_access_claims_clear (&claims);
    return rc == WYRELOG_E_OK ? WYRELOG_E_OK : WYRELOG_E_POLICY;
  }
  /*
   * Direct JWT-claims tenant gate (defense-in-depth, see function
   * header comment). Runs immediately after signature verify and
   * BEFORE the live-session comparison so a foreign-tenant claim
   * is rejected as a tenant violation even if the transitive check
   * below would also reject it.
   */
  if (!tenant_is_active (ctx, claims.tenant)) {
    if (out_auth_error_code != NULL)
      *out_auth_error_code = tenant_is_known (ctx, claims.tenant) ?
          WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID;
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }
  if (g_strcmp0 (claims.principal_state_at_issue, "authenticated") != 0) {
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }
  if (g_strcmp0 (claims.jti, claims.session_id) == 0) {
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }
  if (!wyl_daemon_http_context_access_token_is_active (ctx, &claims, now)) {
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }

  g_autoptr (WylSession) session =
      wyl_daemon_http_ref_session (server, claims.session_id);
  if (session == NULL) {
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }
  g_autofree gchar *live_username = wyl_session_dup_username (session);
  g_autofree gchar *live_tenant = wyl_session_dup_tenant (session);
  if (g_strcmp0 (live_username, claims.subject) != 0 ||
      g_strcmp0 (live_tenant, claims.tenant) != 0) {
    wyl_jwt_access_claims_clear (&claims);
    return WYRELOG_E_POLICY;
  }

  out_auth->session_id = g_steal_pointer (&claims.session_id);
  out_auth->actor = g_steal_pointer (&claims.subject);
  out_auth->tenant = g_steal_pointer (&claims.tenant);
  out_auth->bearer = TRUE;
  wyl_jwt_access_claims_clear (&claims);
  return WYRELOG_E_OK;
}

#ifdef WYL_TEST_DAEMON_HTTP
wyrelog_error_t
wyl_daemon_http_resolve_bearer_for_test (SoupServer *server,
    const gchar *token, gchar **out_session_id, gchar **out_actor,
    gchar **out_tenant)
{
  if (out_session_id == NULL || out_actor == NULL || out_tenant == NULL)
    return WYRELOG_E_INVALID;
  *out_session_id = NULL;
  *out_actor = NULL;
  *out_tenant = NULL;
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  WylDaemonAuthContext auth = { 0 };
  wyrelog_error_t rc = resolve_bearer_session (server, ctx, token, &auth,
      NULL);
  if (rc == WYRELOG_E_OK) {
    *out_session_id = g_steal_pointer (&auth.session_id);
    *out_actor = g_steal_pointer (&auth.actor);
    *out_tenant = g_steal_pointer (&auth.tenant);
  }
  wyl_daemon_auth_context_clear (&auth);
  return rc;
}
#endif

/*
 * Session-token (cookie-equivalent) auth resolver. Same
 * defense-in-depth tenant gate as resolve_bearer_session: the
 * live session's tenant must be one of the daemon's active tenants.
 * out_auth_error_code may be NULL.
 */
static wyrelog_error_t
resolve_session_token_auth (SoupServer *server, WylDaemonHttpContext *ctx,
    const gchar *session_token, WylDaemonAuthContext *out_auth,
    const gchar **out_auth_error_code)
{
  if (out_auth_error_code != NULL)
    *out_auth_error_code = NULL;
  if (server == NULL || ctx == NULL || session_token == NULL ||
      out_auth == NULL)
    return WYRELOG_E_INVALID;
  wyl_daemon_auth_context_clear (out_auth);

  g_autoptr (WylSession) session =
      wyl_daemon_http_ref_session (server, session_token);
  if (session == NULL)
    return WYRELOG_E_POLICY;

  g_autofree gchar *username = wyl_session_dup_username (session);
  g_autofree gchar *tenant = wyl_session_dup_tenant (session);
  if (username == NULL || username[0] == '\0' || tenant == NULL ||
      tenant[0] == '\0')
    return WYRELOG_E_POLICY;
  if (!tenant_is_active (ctx, tenant)) {
    if (out_auth_error_code != NULL)
      *out_auth_error_code = tenant_is_known (ctx, tenant) ?
          WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID;
    return WYRELOG_E_POLICY;
  }

  out_auth->session_id = g_strdup (session_token);
  out_auth->actor = g_steal_pointer (&username);
  out_auth->tenant = g_steal_pointer (&tenant);
  out_auth->bearer = FALSE;
  return WYRELOG_E_OK;
}

static const gchar *
lookup_request_tenant (GHashTable *query)
{
  if (query != NULL && g_hash_table_contains (query, "tenant"))
    return g_hash_table_lookup (query, "tenant");
  return WYL_TENANT_DEFAULT;
}

/*
 * Pure-decision form of the tenant gate: takes the request tenant and
 * the authenticated principal's tenant and returns 0 on pass, or the
 * HTTP status (400 / 403) that the gate would emit on failure. On
 * failure, *out_code points to one of the stable wire-format error
 * code constants (WYL_DAEMON_ERR_TENANT_INVALID /
 * WYL_DAEMON_ERR_TENANT_DENIED). Used by both the SoupServerMessage
 * wrapper below and the WYL_TEST_DAEMON_HTTP test seam.
 */
static guint
decide_request_tenant_gate (WylDaemonHttpContext *ctx,
    const gchar *request_tenant,
    const gchar *auth_tenant, const gchar **out_code)
{
  if (request_tenant == NULL || request_tenant[0] == '\0' ||
      !tenant_is_active (ctx, request_tenant)) {
    if (out_code != NULL)
      *out_code = tenant_is_known (ctx, request_tenant) ?
          WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID;
    return 400;
  }

  if (auth_tenant == NULL || g_strcmp0 (auth_tenant, request_tenant) != 0) {
    if (out_code != NULL)
      *out_code = WYL_DAEMON_ERR_TENANT_DENIED;
    return 403;
  }

  if (out_code != NULL)
    *out_code = NULL;
  return 0;
}

/*
 * Cross-check the request's declared tenant against the authenticated
 * principal's tenant and emit the stable tenant gate error codes
 * (WYL_DAEMON_ERR_TENANT_INVALID / WYL_DAEMON_ERR_TENANT_DENIED) on
 * failure. The codes are wire strings independent of the surrounding
 * handler family (decide / audit / policy / login) so that clients can
 * recognise a tenant-gate rejection regardless of which endpoint
 * produced it.
 */
static gboolean
ensure_auth_context_request_tenant (SoupServerMessage *msg, GHashTable *query,
    WylDaemonHttpContext *ctx, const WylDaemonAuthContext *auth)
{
  const gchar *request_tenant = lookup_request_tenant (query);
  const gchar *auth_tenant = (auth != NULL) ? auth->tenant : NULL;
  const gchar *code = NULL;
  guint status = decide_request_tenant_gate (ctx, request_tenant, auth_tenant,
      &code);
  if (status == 0)
    return TRUE;
  set_json_error (msg, status, code);
  return FALSE;
}

#ifdef WYL_TEST_DAEMON_HTTP
gboolean
wyl_daemon_http_check_request_tenant_for_test (const gchar *request_tenant,
    const gchar *auth_tenant, guint *out_status, gchar **out_code)
{
  /*
   * Mirrors lookup_request_tenant()'s NULL-query fallback: if the
   * caller passes request_tenant=NULL we treat that as "no tenant
   * query parameter" and fall back to the default tenant, exactly as
   * lookup_request_tenant() does inside a real handler.
   */
  const gchar *effective = request_tenant != NULL ? request_tenant
      : WYL_TENANT_DEFAULT;
  const gchar *code = NULL;
  guint status = 0;
  if (effective == NULL || effective[0] == '\0' ||
      g_strcmp0 (effective, WYL_TENANT_DEFAULT) != 0) {
    status = 400;
    code = WYL_DAEMON_ERR_TENANT_INVALID;
  } else if (auth_tenant == NULL || g_strcmp0 (auth_tenant, effective) != 0) {
    status = 403;
    code = WYL_DAEMON_ERR_TENANT_DENIED;
  }
  if (out_status != NULL)
    *out_status = status;
  if (out_code != NULL)
    *out_code = code != NULL ? g_strdup (code) : NULL;
  return status == 0;
}
#endif

static const gchar *
ensure_request_id_header (SoupServerMessage *msg)
{
  const gchar *existing = g_object_get_data (G_OBJECT (msg),
      WYL_DAEMON_REQUEST_ID_DATA);
  if (existing != NULL) {
    SoupMessageHeaders *headers =
        soup_server_message_get_response_headers (msg);
    soup_message_headers_replace (headers, WYL_DAEMON_REQUEST_ID_HEADER,
        existing);
    return existing;
  }

  if (g_object_get_data (G_OBJECT (msg),
          WYL_DAEMON_REQUEST_ID_ATTEMPTED_DATA) != NULL)
    return NULL;
  g_object_set_data (G_OBJECT (msg), WYL_DAEMON_REQUEST_ID_ATTEMPTED_DATA,
      GINT_TO_POINTER (1));

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (request_id, sizeof request_id) != WYRELOG_E_OK)
    return NULL;

  g_object_set_data_full (G_OBJECT (msg), WYL_DAEMON_REQUEST_ID_DATA,
      g_strdup (request_id), g_free);

  SoupMessageHeaders *headers = soup_server_message_get_response_headers (msg);
  soup_message_headers_replace (headers, WYL_DAEMON_REQUEST_ID_HEADER,
      request_id);
  return g_object_get_data (G_OBJECT (msg), WYL_DAEMON_REQUEST_ID_DATA);
}

static void
attach_request_id_header (SoupServerMessage *msg)
{
  (void) ensure_request_id_header (msg);
}

static void
set_json_error (SoupServerMessage *msg, guint status, const gchar *code)
{
  attach_request_id_header (msg);

  g_autoptr (GString) body = g_string_new ("{\"error\":");
  append_json_string (body, code);
  g_string_append_c (body, '}');

  soup_server_message_set_status (msg, status, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static gboolean
wants_json_format (GHashTable *query)
{
  const gchar *format = query != NULL ? g_hash_table_lookup (query,
      "format") : NULL;
  return g_strcmp0 (format, "json") == 0;
}

static void
set_status_json (SoupServerMessage *msg, guint status, const gchar *state,
    const gchar *reason)
{
  attach_request_id_header (msg);

  g_autoptr (GString) body = g_string_new ("{\"status\":");
  append_json_string (body, state);
  if (reason != NULL) {
    g_string_append (body, ",\"reason\":");
    append_json_string (body, reason);
  }
  g_string_append_c (body, '}');

  soup_server_message_set_status (msg, status, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
set_readyz_json (SoupServerMessage *msg, guint status, const gchar *state,
    const gchar *reason, WylHandle *handle)
{
  attach_request_id_header (msg);

  g_autofree gchar *facts = wyl_daemon_fact_status_json (handle, FALSE);
  g_autoptr (GString) body = g_string_new ("{\"status\":");
  append_json_string (body, state);
  if (reason != NULL) {
    g_string_append (body, ",\"reason\":");
    append_json_string (body, reason);
  }
  g_string_append (body, ",\"subsystems\":{\"facts\":");
  g_string_append (body, facts != NULL ? facts : "{\"status\":\"disabled\"}");
  g_string_append (body, "}}");

  soup_server_message_set_status (msg, status, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static gboolean
parse_int64_query_param (const gchar *value, gint64 *out_value)
{
  if (value == NULL || value[0] == '\0' || out_value == NULL)
    return FALSE;

  gchar *end = NULL;
  errno = 0;
  gint64 parsed = g_ascii_strtoll (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0')
    return FALSE;
  *out_value = parsed;
  return TRUE;
}

static void
healthz_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) user_data;

  if (wants_json_format (query)) {
    set_status_json (msg, 200, "ok", NULL);
    return;
  }

  const gchar *body = "ok\n";
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY, body,
      strlen (body));
}

#ifdef WYL_HAS_AUDIT
static void
mark_runtime_audit_degraded (WylDaemonRuntime *runtime, wyrelog_error_t rc)
{
  if (runtime == NULL || rc == WYRELOG_E_OK)
    return;

  g_atomic_int_set (&runtime->audit_degraded, TRUE);
  runtime->audit_errors++;
  runtime->last_audit_error = rc;
}
#endif

static wyrelog_error_t
check_runtime_ready (WylHandle *handle, const gchar **out_error)
{
  if (out_error != NULL)
    *out_error = "not_ready";

  gint64 row[1];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wr.audit.read", &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean ready = FALSE;
  rc = wyl_handle_engine_contains (handle, "guarded_perm", row, 1, &ready);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!ready)
    return WYRELOG_E_POLICY;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  for (gsize i = 0; i < wyl_policy_store_required_table_count (); i++) {
    gboolean found = FALSE;
    const gchar *table = wyl_policy_store_required_table_name (i);
    rc = wyl_policy_store_table_exists (store, table, &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!found)
      return WYRELOG_E_POLICY;
  }

#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  gboolean found = FALSE;
  rc = wyl_audit_conn_table_exists (conn, "audit_events", &found);
  if (rc != WYRELOG_E_OK) {
    if (out_error != NULL)
      *out_error = "audit_degraded";
    return rc;
  }
  if (!found) {
    if (out_error != NULL)
      *out_error = "audit_degraded";
    return WYRELOG_E_IO;
  }

  g_autofree gchar *json = NULL;
  rc = wyl_audit_conn_query_events_json (conn, NULL, &json);
  if (rc != WYRELOG_E_OK) {
    if (out_error != NULL)
      *out_error = "audit_degraded";
    return rc;
  }

  rc = wyl_audit_conn_verify_chain (conn, NULL);
  if (rc != WYRELOG_E_OK) {
    if (out_error != NULL)
      *out_error = "audit_degraded";
    return rc;
  }
#endif

  return WYRELOG_E_OK;
}

static const gchar *
check_runtime_liveness_ready (WylDaemonRuntime *runtime)
{
  if (runtime == NULL)
    return NULL;
  if (!g_atomic_int_get (&runtime->delta_session_live))
    return "delta_not_ready";
  if (runtime->last_delta_error != WYRELOG_E_OK)
    return "delta_not_ready";
  if (g_atomic_int_get (&runtime->audit_degraded))
    return "audit_degraded";

  return NULL;
}

static void
readyz_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  WylDaemonHttpContext *ctx = user_data;
  gboolean json = wants_json_format (query);
  const gchar *liveness_error = check_runtime_liveness_ready (ctx->runtime);
  if (liveness_error != NULL) {
    if (json)
      set_readyz_json (msg, 503, "not_ready", liveness_error, ctx->handle);
    else
      set_json_error (msg, 503, liveness_error);
    return;
  }

  const gchar *readiness_error = "not_ready";
  wyrelog_error_t rc = check_runtime_ready (ctx->handle, &readiness_error);
  if (rc != WYRELOG_E_OK) {
    if (json)
      set_readyz_json (msg, 503, "not_ready", readiness_error, ctx->handle);
    else
      set_json_error (msg, 503, readiness_error);
    return;
  }

  if (json) {
    set_readyz_json (msg, 200, "ready", NULL, ctx->handle);
    return;
  }

  const gchar *body = "ready\n";
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY, body,
      strlen (body));
}

static void
facts_status_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *body = wyl_daemon_fact_status_json (ctx->handle, TRUE);
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static void
profile_status_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;

  WylDaemonHttpContext *ctx = user_data;
  const gchar *profile =
      ctx->profile == WYL_DAEMON_PROFILE_SERVICE ? "service" : "system";
  g_autoptr (GString) body = g_string_new ("{\"profile\":");
  append_json_string (body, profile);
  g_string_append (body, ",\"system_url\":");
  if (ctx->system_url == NULL)
    g_string_append (body, "null");
  else
    append_json_string (body, ctx->system_url);
  g_string_append (body, ",\"event_spool_dir\":");
  if (ctx->event_spool_dir == NULL)
    g_string_append (body, "null");
  else
    append_json_string (body, ctx->event_spool_dir);
  g_string_append_printf (body, ",\"event_queue_limit\":%u}",
      ctx->event_queue_limit);

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
profile_events_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;

  WylDaemonHttpContext *ctx = user_data;
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  if (ctx->profile != WYL_DAEMON_PROFILE_SYSTEM) {
    set_json_error (msg, 403, "profile_event_ingest_denied");
    return;
  }

  set_json_ok (msg);
}

static gboolean
tenant_scope_is_allowed (const gchar * tenant, const gchar * scope);

static gboolean
authorize_guarded_session_action (SoupServer *server, SoupServerMessage *msg,
    GHashTable *query, WylDaemonHttpContext *ctx, const gchar *action,
    const gchar *resource, const gchar *auth_required_code,
    const gchar *invalid_code, const gchar *denied_code,
    const gchar *failed_code, gchar **out_actor)
{
  const gchar *session_token = NULL;
  const gchar *guard_timestamp = NULL;
  const gchar *guard_loc_class = NULL;
  const gchar *guard_risk = NULL;
  if (query != NULL) {
    session_token = g_hash_table_lookup (query, "session_token");
    guard_timestamp = g_hash_table_lookup (query, "guard_timestamp");
    guard_loc_class = g_hash_table_lookup (query, "guard_loc_class");
    guard_risk = g_hash_table_lookup (query, "guard_risk");
  }
  const gchar *bearer_token = lookup_bearer_token (msg);
  gboolean has_session_token = session_token != NULL
      && session_token[0] != '\0';
  gboolean has_bearer_token = bearer_token != NULL && bearer_token[0] != '\0';
  if (!has_session_token && !has_bearer_token) {
    set_json_error (msg, 401, auth_required_code);
    return FALSE;
  }
  if (has_session_token && bearer_token != NULL) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }
  if (bearer_token != NULL && !has_bearer_token) {
    set_json_error (msg, 401, auth_required_code);
    return FALSE;
  }
  if (guard_timestamp == NULL || guard_loc_class == NULL || guard_risk == NULL) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }

  gint64 timestamp = 0;
  gint64 risk = 0;
  if (!parse_int64_query_param (guard_timestamp, &timestamp) ||
      !parse_int64_query_param (guard_risk, &risk) || timestamp < 0 ||
      risk < 0 || risk > 100 ||
      !wyl_guard_loc_class_is_valid (guard_loc_class)) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }

  g_auto (WylDaemonAuthContext) auth = { 0 };
  const gchar *auth_tenant_error = NULL;
  if (has_session_token) {
    wyrelog_error_t auth_rc =
        resolve_session_token_auth (server, ctx, session_token, &auth,
        &auth_tenant_error);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401,
          auth_tenant_error != NULL ? auth_tenant_error : auth_required_code);
      return FALSE;
    }
  } else {
    wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
        bearer_token, &auth, &auth_tenant_error);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401,
          auth_tenant_error != NULL ? auth_tenant_error : auth_required_code);
      return FALSE;
    }
  }
  if (!ensure_auth_context_request_tenant (msg, query, ctx, &auth))
    return FALSE;
  if (resource != NULL &&
      !tenant_scope_is_allowed (lookup_request_tenant (query), resource)) {
    set_json_error (msg, 403, WYL_DAEMON_ERR_TENANT_DENIED);
    return FALSE;
  }

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, auth.actor);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req,
      resource != NULL ? resource : auth.session_id);
  wyl_decide_req_set_guard_context (req, timestamp, guard_loc_class, risk);
  wyl_decide_req_set_request_id (req, ensure_request_id_header (msg));

  wyrelog_error_t rc = wyl_decide (ctx->handle, req, resp);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, failed_code);
    return FALSE;
  }
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW) {
    set_json_error (msg, 403, denied_code);
    return FALSE;
  }

  if (out_actor != NULL)
    *out_actor = g_strdup (auth.actor);
  return TRUE;
}

typedef struct
{
  GString *json;
  gboolean first;
} ServicePrincipalListJsonCtx;

static void
append_service_principal_json_object (GString *json,
    const wyl_service_principal_t *info)
{
  g_string_append (json, "{\"subject_id\":");
  append_json_string (json, info->subject_id);
  g_string_append (json, ",\"display_name\":");
  append_json_string (json, info->display_name);
  g_string_append (json, ",\"state\":");
  append_json_string (json, info->state);
  g_string_append_printf (json, ",\"generation\":%" G_GUINT64_FORMAT,
      info->generation);
  g_string_append (json, ",\"created_by\":");
  append_json_string (json, info->created_by);
  g_string_append_printf (json, ",\"created_at_us\":%" G_GINT64_FORMAT,
      info->created_at_us);
  g_string_append_printf (json, ",\"updated_at_us\":%" G_GINT64_FORMAT,
      info->updated_at_us);
  g_string_append_c (json, ',');
  append_json_nullable_string (json, "disabled_by", info->disabled_by);
  g_string_append_printf (json, ",\"disabled_at_us\":%" G_GINT64_FORMAT,
      info->disabled_at_us);
  g_string_append_c (json, '}');
}

static wyrelog_error_t
append_service_principal_json (const wyl_service_principal_t *info,
    gpointer user_data)
{
  ServicePrincipalListJsonCtx *ctx = user_data;
  if (ctx == NULL || ctx->json == NULL || info == NULL)
    return WYRELOG_E_INVALID;
  if (!ctx->first)
    g_string_append_c (ctx->json, ',');
  ctx->first = FALSE;
  append_service_principal_json_object (ctx->json, info);
  return WYRELOG_E_OK;
}

static gboolean
service_principal_management_authorize (SoupServer *server,
    SoupServerMessage *msg, GHashTable *query, WylDaemonHttpContext *ctx,
    const gchar *action,
    const gchar *auth_required_code, const gchar *invalid_code,
    const gchar *denied_code, const gchar *failed_code,
    WylDaemonAuthContext *out_auth, gchar **out_actor)
{
  if (ctx == NULL || ctx->profile != WYL_DAEMON_PROFILE_SYSTEM
      || action == NULL || action[0] == '\0') {
    set_json_error (msg, 403, denied_code);
    return FALSE;
  }
  const gchar *session_token = NULL;
  const gchar *guard_timestamp = NULL;
  const gchar *guard_loc_class = NULL;
  const gchar *guard_risk = NULL;
  if (query != NULL) {
    session_token = g_hash_table_lookup (query, "session_token");
    guard_timestamp = g_hash_table_lookup (query, "guard_timestamp");
    guard_loc_class = g_hash_table_lookup (query, "guard_loc_class");
    guard_risk = g_hash_table_lookup (query, "guard_risk");
  }
  const gchar *bearer_token = lookup_bearer_token (msg);
  gboolean has_session_token = session_token != NULL
      && session_token[0] != '\0';
  gboolean has_bearer_token = bearer_token != NULL && bearer_token[0] != '\0';
  if (!has_session_token && !has_bearer_token) {
    set_json_error (msg, 401, auth_required_code);
    return FALSE;
  }
  if (has_session_token && has_bearer_token) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }
  if (guard_timestamp == NULL || guard_loc_class == NULL || guard_risk == NULL) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }

  gint64 timestamp = 0;
  gint64 risk = 0;
  if (!parse_int64_query_param (guard_timestamp, &timestamp) ||
      !parse_int64_query_param (guard_risk, &risk) || timestamp < 0 ||
      risk < 0 || risk > 100 ||
      !wyl_guard_loc_class_is_valid (guard_loc_class)) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }
  (void) timestamp;
  (void) risk;

  g_auto (WylDaemonAuthContext) auth = { 0 };
  const gchar *auth_tenant_error = NULL;
  if (has_session_token) {
    wyrelog_error_t auth_rc =
        resolve_session_token_auth (server, ctx, session_token, &auth,
        &auth_tenant_error);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401,
          auth_tenant_error != NULL ? auth_tenant_error : auth_required_code);
      return FALSE;
    }
  } else {
    wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
        bearer_token, &auth, &auth_tenant_error);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401,
          auth_tenant_error != NULL ? auth_tenant_error : auth_required_code);
      return FALSE;
    }
  }

  if (!ensure_auth_context_request_tenant (msg, query, ctx, &auth))
    return FALSE;

  g_autoptr (WylSession) session = wyl_daemon_http_ref_session (server,
      auth.session_id);
  if (session == NULL || !WYL_IS_SESSION (session)
      || !wyl_session_is_active_human_private (session)) {
    set_json_error (msg, 403, denied_code);
    return FALSE;
  }

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, auth.actor);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, auth.session_id);
  wyl_decide_req_set_guard_context (req, timestamp, guard_loc_class, risk);
  wyl_decide_req_set_request_id (req, ensure_request_id_header (msg));
  wyrelog_error_t decision_rc = wyl_decide (ctx->handle, req, resp);
  if (decision_rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }
  if (decision_rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, failed_code);
    return FALSE;
  }
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW) {
    set_json_error (msg, 403, denied_code);
    return FALSE;
  }

  gchar *actor_copy = g_strdup (auth.actor);
  if (out_auth != NULL) {
    out_auth->session_id = g_steal_pointer (&auth.session_id);
    out_auth->actor = g_steal_pointer (&auth.actor);
    out_auth->tenant = g_steal_pointer (&auth.tenant);
    out_auth->bearer = auth.bearer;
  }
  if (out_actor != NULL)
    *out_actor = actor_copy;
  else
    g_free (actor_copy);
  return TRUE;
}

static gchar *
service_principal_build_json (const wyl_service_principal_t *info)
{
  g_autoptr (GString) body = g_string_new ("{\"service_principal\":");
  append_service_principal_json_object (body, info);
  g_string_append_c (body, '}');
  return g_string_free (g_steal_pointer (&body), FALSE);
}

static void
append_service_credential_json_object (GString *json,
    const wyl_service_credential_t *info)
{
  g_string_append (json, "{\"credential_id\":");
  append_json_string (json, info->credential_id);
  g_string_append_printf (json, ",\"credential_format_version\":%u",
      info->credential_format_version);
  g_string_append (json, ",\"subject_id\":");
  append_json_string (json, info->subject_id);
  g_string_append (json, ",\"tenant_id\":");
  append_json_string (json, info->tenant_id);
  g_string_append_printf (json, ",\"generation\":%" G_GUINT64_FORMAT,
      info->generation);
  g_string_append (json, ",\"state\":");
  append_json_string (json, info->state);
  g_string_append (json, ",\"created_by\":");
  append_json_string (json, info->created_by);
  g_string_append_printf (json, ",\"created_at_us\":%" G_GINT64_FORMAT,
      info->created_at_us);
  g_string_append_printf (json, ",\"updated_at_us\":%" G_GINT64_FORMAT,
      info->updated_at_us);
  g_string_append_printf (json, ",\"expires_at_us\":%" G_GINT64_FORMAT,
      info->expires_at_us);
  g_string_append_printf (json, ",\"last_used_at_us\":%" G_GINT64_FORMAT,
      info->last_used_at_us);
  g_string_append_c (json, ',');
  append_json_nullable_string (json, "revoked_by", info->revoked_by);
  g_string_append_printf (json, ",\"revoked_at_us\":%" G_GINT64_FORMAT,
      info->revoked_at_us);
  g_string_append_c (json, ',');
  append_json_nullable_string (json, "rotated_from_id", info->rotated_from_id);
  g_string_append_c (json, '}');
}

static gchar *
service_credential_build_json (const wyl_service_credential_t *info)
{
  g_autoptr (GString) body = g_string_new ("{\"service_credential\":");
  append_service_credential_json_object (body, info);
  g_string_append_c (body, '}');
  return g_string_free (g_steal_pointer (&body), FALSE);
}

static gboolean
service_credential_request_id_is_valid (const gchar *request_id)
{
  if (request_id == NULL || strlen (request_id) != WYL_REQUEST_ID_STRING_LEN)
    return FALSE;
  for (gsize i = 0; i < WYL_REQUEST_ID_STRING_LEN; i++)
    if (!g_ascii_isalnum (request_id[i]))
      return FALSE;
  return TRUE;
}

static gboolean
service_credential_parse_expiry (const gchar *text, gint64 *out_expiry)
{
  gchar *end = NULL;
  gint64 expiry = 0;
  if (out_expiry == NULL)
    return FALSE;
  *out_expiry = 0;
  if (text == NULL || text[0] == '\0')
    return FALSE;
  errno = 0;
  expiry = g_ascii_strtoll (text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || expiry < 0)
    return FALSE;
  *out_expiry = expiry;
  return TRUE;
}

static gboolean
service_credential_subject_matches_tenant (const gchar *subject,
    const gchar *tenant)
{
  if (subject == NULL || tenant == NULL || !g_str_has_prefix (subject, "svc:"))
    return FALSE;
  const gchar *tenant_start = subject + strlen ("svc:");
  const gchar *tenant_end = strchr (tenant_start, ':');
  if (tenant_end == NULL || tenant_end == tenant_start)
    return FALSE;
  return strlen (tenant) == (gsize) (tenant_end - tenant_start)
      && memcmp (tenant_start, tenant,
      (gsize) (tenant_end - tenant_start)) == 0;
}

static wyrelog_error_t
service_credential_registry_invalidate (gpointer data,
    const gchar *credential_id, guint64 generation)
{
  WylDaemonHttpContext *ctx = data;
  if (ctx == NULL || ctx->service_auth_registry == NULL
      || credential_id == NULL || generation == 0)
    return WYRELOG_E_INVALID;
  WylServiceAuthRevokeResult result = { 0 };
  return wyl_service_auth_registry_revoke_credential_generation
      (ctx->service_auth_registry, credential_id, generation, &result);
}

static void
service_credential_issue_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_credential.manage",
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED, NULL, &actor))
    return;
  if (path == NULL || path[0] != '/') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  const gchar *tail = strchr (path + 1, '/');
  if (tail == NULL || g_strcmp0 (tail, "/credentials") != 0 || tail == path + 1) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  g_autofree gchar *subject = g_strndup (path + 1,
      (gsize) (tail - (path + 1)));
  if (subject == NULL || subject[0] == '\0') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }

  SoupMessageBody *request_body = soup_server_message_get_request_body (msg);
  if (request_body == NULL || request_body->data == NULL
      || request_body->length <= 0 || request_body->length > 4096) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  static const WylDaemonHttpStrictJsonField fields[] = {
    {"version", 8},
    {"tenant", 128},
    {"request_id", WYL_REQUEST_ID_STRING_LEN},
    {"expires_at_us", 32},
  };
  static const WylDaemonHttpStrictJsonField fields_without_expiry[] = {
    {"version", 8},
    {"tenant", 128},
    {"request_id", WYL_REQUEST_ID_STRING_LEN},
  };
  g_auto (GStrv) values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
  gboolean parsed = wyl_daemon_http_dup_strict_json_object
      (request_body->data, (gsize) request_body->length, fields,
      G_N_ELEMENTS (fields), values);
  if (!parsed) {
    wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (fields));
    values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
    parsed = wyl_daemon_http_dup_strict_json_object
        (request_body->data, (gsize) request_body->length,
        fields_without_expiry, G_N_ELEMENTS (fields_without_expiry), values);
  }
  if (!parsed || g_strcmp0 (values[0], "1") != 0
      || g_strcmp0 (values[1], lookup_request_tenant (query)) != 0
      || !service_credential_request_id_is_valid (values[2])
      || !service_credential_subject_matches_tenant (subject, values[1])) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  gint64 expires_at_us = 0;
  if (values[3] != NULL && !service_credential_parse_expiry (values[3],
          &expires_at_us)) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }

  wyl_service_credential_issue_result_t issued = { 0 };
  wyrelog_error_t rc = wyl_service_credential_issue (ctx->handle, subject,
      values[1], actor, values[2], expires_at_us, &issued);
  if (rc == WYRELOG_E_INVALID) {
    wyl_service_credential_issue_result_clear (&issued);
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    wyl_service_credential_issue_result_clear (&issued);
    set_json_error (msg, 409, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_CONFLICT);
    return;
  }
  if (rc != WYRELOG_E_OK || issued.secret == NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);
  g_autoptr (WylSensitiveChar) response = NULL;
  if (secret == NULL || secret_len == 0) {
    wyl_service_credential_issue_result_clear (&issued);
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  response = g_strdup_printf ("{\"service_credential\":");
  if (response != NULL) {
    g_autofree gchar *metadata = service_credential_build_json
        (&issued.credential);
    if (metadata != NULL) {
      g_autoptr (WylSensitiveChar) secret_json = g_strdup_printf
          (",\"credential_secret\":\"%.*s\"}", (gint) secret_len, secret);
      if (secret_json != NULL) {
        g_free (response);
        response = g_strdup_printf ("%.*s%s", (gint) (strlen (metadata) - 1),
            metadata, secret_json);
      }
    }
  }
  wyl_service_credential_issue_result_clear (&issued);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      response, strlen (response));
}

typedef struct
{
  GString *json;
  gboolean first;
} ServiceCredentialListJsonCtx;

static wyrelog_error_t
append_service_credential_json (const wyl_service_credential_t *info,
    gpointer user_data)
{
  ServiceCredentialListJsonCtx *ctx = user_data;
  if (ctx == NULL || ctx->json == NULL || info == NULL)
    return WYRELOG_E_INVALID;
  if (!ctx->first)
    g_string_append_c (ctx->json, ',');
  ctx->first = FALSE;
  append_service_credential_json_object (ctx->json, info);
  return WYRELOG_E_OK;
}

static void
service_credential_list_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;
  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_credential.manage",
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED, NULL, &actor))
    return;

  if (path == NULL || path[0] != '/') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  const gchar *tail = strchr (path + 1, '/');
  if (tail == NULL || g_strcmp0 (tail, "/credentials") != 0) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  g_autofree gchar *subject = g_strndup (path + 1,
      (gsize) (tail - (path + 1)));
  if (subject == NULL || subject[0] == '\0') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  const gchar *tenant = lookup_request_tenant (query);
  g_autoptr (GString) body = g_string_new ("{\"service_credentials\":[");
  ServiceCredentialListJsonCtx json_ctx = {.json = body,.first = TRUE };
  wyrelog_error_t rc = wyl_service_credential_foreach (ctx->handle, subject,
      tenant, append_service_credential_json, &json_ctx);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  g_string_append (body, "]}");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      body->str, body->len);
}

static void
service_credential_get_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_credential.manage",
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED, NULL, &actor))
    return;
  if (path == NULL || path[0] != '/' || path[1] == '\0'
      || strchr (path + 1, '/') != NULL) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  const gchar *credential_id = path + 1;
  wyl_service_credential_t credential = { 0 };
  wyrelog_error_t rc = wyl_service_credential_get (ctx->handle, credential_id,
      &credential);
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  if (g_strcmp0 (credential.tenant_id, lookup_request_tenant (query)) != 0) {
    wyl_service_credential_clear (&credential);
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  g_autofree gchar *response = service_credential_build_json (&credential);
  wyl_service_credential_clear (&credential);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      response, strlen (response));
}

static void
service_credential_rotate_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_credential.manage",
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED, NULL, &actor))
    return;
  if (path == NULL || path[0] != '/') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  const gchar *tail = strstr (path + 1, "/rotate");
  if (tail == NULL || tail[7] != '\0' || tail == path + 1
      || !wyl_service_credential_id_is_canonical (path + 1,
          (gsize) (tail - (path + 1)))) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  g_autofree gchar *credential_id = g_strndup (path + 1,
      (gsize) (tail - (path + 1)));
  static const WylDaemonHttpStrictJsonField fields[] = {
    {"version", 8},
    {"request_id", WYL_REQUEST_ID_STRING_LEN},
    {"expires_at_us", 32},
  };
  static const WylDaemonHttpStrictJsonField fields_without_expiry[] = {
    {"version", 8},
    {"request_id", WYL_REQUEST_ID_STRING_LEN},
  };
  g_auto (GStrv) values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
  gboolean parsed = wyl_daemon_http_request_body_dup_strict_json_object
      (msg, 4096, fields, G_N_ELEMENTS (fields), values);
  if (!parsed) {
    wyl_daemon_http_clear_strv (values, G_N_ELEMENTS (fields));
    parsed = wyl_daemon_http_request_body_dup_strict_json_object
        (msg, 4096, fields_without_expiry,
        G_N_ELEMENTS (fields_without_expiry), values);
  }
  if (!parsed || g_strcmp0 (values[0], "1") != 0
      || !service_credential_request_id_is_valid (values[1])) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  gint64 expires_at_us = 0;
  if (values[2] != NULL && !service_credential_parse_expiry (values[2],
          &expires_at_us)) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  wyl_service_credential_t current = { 0 };
  wyrelog_error_t rc = wyl_service_credential_get (ctx->handle, credential_id,
      &current);
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_service_credential_clear (&current);
    set_json_error (msg, rc == WYRELOG_E_INVALID ? 400 : 500,
        rc == WYRELOG_E_INVALID ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  if (g_strcmp0 (current.tenant_id, lookup_request_tenant (query)) != 0) {
    wyl_service_credential_clear (&current);
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  guint64 current_generation = current.generation;
  wyl_service_credential_clear (&current);

  wyl_service_credential_issue_result_t rotated = { 0 };
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .invalidate_credential = service_credential_registry_invalidate,
    .invalidation_data = ctx,
    .old_credential_generation = current_generation,
  };
  rc = wyl_service_credential_rotate_with_runtime (ctx->handle, credential_id,
      actor, values[1], expires_at_us, &rotate_runtime, &rotated);
  if (rc == WYRELOG_E_INVALID) {
    wyl_service_credential_issue_result_clear (&rotated);
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    wyl_service_credential_issue_result_clear (&rotated);
    set_json_error (msg, 409, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_CONFLICT);
    return;
  }
  if (rc != WYRELOG_E_OK || rotated.secret == NULL) {
    wyl_service_credential_issue_result_clear (&rotated);
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (rotated.secret, &secret_len);
  g_autoptr (WylSensitiveChar) response = NULL;
  g_autofree gchar *metadata = service_credential_build_json
      (&rotated.credential);
  if (secret != NULL && secret_len > 0 && metadata != NULL) {
    g_autoptr (WylSensitiveChar) secret_json = g_strdup_printf
        (",\"credential_secret\":\"%.*s\"}", (gint) secret_len, secret);
    if (secret_json != NULL) {
      response = g_strdup_printf ("%.*s%s", (gint) (strlen (metadata) - 1),
          metadata, secret_json);
    }
  }
  wyl_service_credential_issue_result_clear (&rotated);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      response, strlen (response));
}

static void
service_credential_revoke_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  if (g_strcmp0 (soup_server_message_get_method (msg), "DELETE") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_credential.manage",
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED, NULL, &actor))
    return;
  if (path == NULL || path[0] != '/' || path[1] == '\0'
      || strchr (path + 1, '/') != NULL
      || !wyl_service_credential_id_is_canonical (path + 1,
          strlen (path + 1))) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  static const WylDaemonHttpStrictJsonField fields[] = {
    {"version", 8},
    {"request_id", WYL_REQUEST_ID_STRING_LEN},
  };
  g_auto (GStrv) values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
  if (!wyl_daemon_http_request_body_dup_strict_json_object (msg, 1024, fields,
          G_N_ELEMENTS (fields), values)
      || g_strcmp0 (values[0], "1") != 0
      || !service_credential_request_id_is_valid (values[1])) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }

  wyl_service_credential_t current = { 0 };
  wyrelog_error_t rc = wyl_service_credential_get (ctx->handle, path + 1,
      &current);
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_service_credential_clear (&current);
    set_json_error (msg, rc == WYRELOG_E_INVALID ? 400 : 500,
        rc == WYRELOG_E_INVALID ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  if (g_strcmp0 (current.tenant_id, lookup_request_tenant (query)) != 0) {
    wyl_service_credential_clear (&current);
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_NOT_FOUND);
    return;
  }
  wyl_service_credential_clear (&current);

  wyl_service_credential_t revoked = { 0 };
  wyl_service_credential_revoke_runtime_t revoke_runtime = {
    .invalidate_credential = service_credential_registry_invalidate,
    .invalidation_data = ctx,
  };
  rc = wyl_service_credential_revoke_with_runtime (ctx->handle, path + 1,
      actor, values[1], &revoke_runtime, &revoked);
  if (rc == WYRELOG_E_INVALID) {
    wyl_service_credential_clear (&revoked);
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    wyl_service_credential_clear (&revoked);
    set_json_error (msg, 409, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_CONFLICT);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    wyl_service_credential_clear (&revoked);
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  g_autofree gchar *response = service_credential_build_json (&revoked);
  wyl_service_credential_clear (&revoked);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_FAILED);
    return;
  }
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      response, strlen (response));
}

static void
service_credential_management_handler (SoupServer *server,
    SoupServerMessage *msg, const char *path, GHashTable *query,
    gpointer user_data)
{
  if (path == NULL || path[0] == '\0' || g_strcmp0 (path, "/") == 0) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_CREDENTIAL_INVALID);
    return;
  }
  if (g_strcmp0 (soup_server_message_get_method (msg), "DELETE") == 0) {
    service_credential_revoke_handler (server, msg, path, query, user_data);
    return;
  }
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") == 0
      && g_str_has_suffix (path, "/rotate")) {
    service_credential_rotate_handler (server, msg, path, query, user_data);
    return;
  }
  service_credential_get_handler (server, msg, path, query, user_data);
}

static void
service_principal_create_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_principal.manage",
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED, NULL, &actor))
    return;

  SoupMessageBody *request_body = soup_server_message_get_request_body (msg);
  if (request_body == NULL || request_body->data == NULL
      || request_body->length <= 0 || request_body->length > 4096) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }

  static const WylDaemonHttpStrictJsonField fields[] = {
    {"subject_id", 128},
    {"display_name", 256},
  };
  g_auto (GStrv) values = g_new0 (gchar *, G_N_ELEMENTS (fields) + 1);
  if (!wyl_daemon_http_dup_strict_json_object (request_body->data,
          (gsize) request_body->length, fields,
          G_N_ELEMENTS (fields), values)) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }

  const gchar *subject_id = values[0];
  const gchar *display_name = values[1];
  if (subject_id == NULL || display_name == NULL || subject_id[0] == '\0'
      || display_name[0] == '\0') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }

  wyl_service_principal_t principal = { 0 };
  wyrelog_error_t rc = wyl_service_principal_create (ctx->handle, subject_id,
      display_name, actor, ensure_request_id_header (msg), &principal);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 409, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_EXISTS);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED);
    return;
  }

  g_autofree gchar *response = service_principal_build_json (&principal);
  wyl_service_principal_clear (&principal);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED);
    return;
  }

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, response, strlen (response));
}

static void
service_principal_list_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_principal.manage",
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED, NULL, &actor))
    return;

  g_autoptr (GString) body = g_string_new ("{\"service_principals\":[");
  ServicePrincipalListJsonCtx json_ctx = {
    .json = body,
    .first = TRUE,
  };
  wyrelog_error_t rc = wyl_service_principal_foreach (ctx->handle,
      append_service_principal_json, &json_ctx);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED);
    return;
  }
  g_string_append (body, "]}");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
service_principal_disable_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *subject_id = NULL;
  if (path == NULL || path[0] != '/') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }
  const gchar *tail = strchr (path + 1, '/');
  if (tail == NULL || g_strcmp0 (tail, "/disable") != 0) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }
  g_autofree gchar *subject_copy = g_strndup (path + 1,
      (gsize) (tail - (path + 1)));
  subject_id = subject_copy;
  if (subject_id == NULL || subject_id[0] == '\0') {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!service_principal_management_authorize (server, msg, query, ctx,
          "wr.service_principal.manage",
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_DENIED,
          WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED, NULL, &actor))
    return;

  wyl_service_principal_t principal = { 0 };
  wyrelog_error_t rc = wyl_service_principal_disable (ctx->handle, subject_id,
      actor, ensure_request_id_header (msg), &principal);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
    return;
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_NOT_FOUND);
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 409, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_DENIED);
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED);
    return;
  }

  g_autofree gchar *response = service_principal_build_json (&principal);
  wyl_service_principal_clear (&principal);
  if (response == NULL) {
    set_json_error (msg, 500, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_FAILED);
    return;
  }

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, response, strlen (response));
}

static void
service_principal_management_handler (SoupServer *server,
    SoupServerMessage *msg, const char *path, GHashTable *query,
    gpointer user_data)
{
  if (path == NULL || path[0] == '\0' || g_strcmp0 (path, "/") == 0) {
    if (g_strcmp0 (soup_server_message_get_method (msg), "GET") == 0) {
      service_principal_list_handler (server, msg, path, query, user_data);
      return;
    }
    if (g_strcmp0 (soup_server_message_get_method (msg), "POST") == 0) {
      service_principal_create_handler (server, msg, path, query, user_data);
      return;
    }
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") == 0
      && g_str_has_suffix (path, "/disable")) {
    service_principal_disable_handler (server, msg, path, query, user_data);
    return;
  }

  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") == 0
      && g_str_has_suffix (path, "/credentials")) {
    service_credential_list_handler (server, msg, path, query, user_data);
    return;
  }

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") == 0
      && g_str_has_suffix (path, "/credentials")) {
    service_credential_issue_handler (server, msg, path, query, user_data);
    return;
  }

  set_json_error (msg, 404, WYL_DAEMON_ERR_SERVICE_PRINCIPAL_INVALID);
}

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t
reconcile_audit_query_projection (WylHandle *handle)
{
  return wyl_handle_load_policy_store_audit_events (handle);
}
#endif

static void
audit_events_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

#ifdef WYL_HAS_AUDIT
  const gchar *filter = NULL;
  if (query != NULL)
    filter = g_hash_table_lookup (query, "filter");

  WylDaemonHttpContext *ctx = user_data;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.audit.read", NULL, "audit_auth_required",
          "invalid_audit_auth", "audit_denied", "audit_auth_failed", NULL))
    return;

  WylHandle *handle = ctx->handle;
  g_autofree gchar *body = NULL;
  wyrelog_error_t rc = reconcile_audit_query_projection (handle);
  if (rc == WYRELOG_E_OK)
    rc = wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
        filter, &body);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_filter");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    mark_runtime_audit_degraded (ctx->runtime, rc);
    set_json_error (msg, 500, "audit_query_failed");
    return;
  }
#else
  (void) query;
  (void) user_data;
  const gchar *body = "[]";
#endif

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static void
set_json_ok (SoupServerMessage *msg)
{
  const gchar *body = "{\"ok\":true}";
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static const gchar *
lookup_required_query_string (GHashTable *query, const gchar *name)
{
  const gchar *value = NULL;
  if (query != NULL)
    value = g_hash_table_lookup (query, name);
  if (value == NULL || value[0] == '\0')
    return NULL;
  return value;
}

typedef struct
{
  GString *json;
  gboolean first;
} TenantListJsonCtx;

static wyrelog_error_t
append_tenant_json (const gchar *tenant_id, gboolean sealed, gpointer user_data)
{
  TenantListJsonCtx *ctx = user_data;
  if (!ctx->first)
    g_string_append_c (ctx->json, ',');
  ctx->first = FALSE;
  g_string_append (ctx->json, "{\"tenant\":");
  append_json_string (ctx->json, tenant_id);
  g_string_append_printf (ctx->json, ",\"sealed\":%s}",
      sealed ? "true" : "false");
  return WYRELOG_E_OK;
}

static void
set_tenant_mutation_json (SoupServerMessage *msg, const gchar *tenant,
    gboolean changed)
{
  g_autoptr (GString) body = g_string_new ("{\"ok\":true,\"tenant\":");
  append_json_string (body, tenant);
  g_string_append_printf (body, ",\"changed\":%s}", changed ? "true" : "false");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static gboolean
tenant_scope_is_allowed (const gchar *tenant, const gchar *scope)
{
  if (g_strcmp0 (tenant, WYL_TENANT_DEFAULT) == 0)
    return TRUE;
  return g_strcmp0 (tenant, scope) == 0;
}

static wyrelog_error_t
emit_tenant_lifecycle_audit (WylDaemonHttpContext *ctx, const gchar *actor,
    const gchar *tenant, const gchar *action, const gchar *request_id)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, actor);
  wyl_audit_event_set_action (ev, action);
  wyl_audit_event_set_resource_id (ev, tenant);
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return wyl_audit_emit (ctx->handle, ev);
#else
  (void) ctx;
  (void) actor;
  (void) tenant;
  (void) action;
  (void) request_id;
  return WYRELOG_E_OK;
#endif
}

static void
set_policy_mutation_error (SoupServerMessage *msg, wyrelog_error_t rc)
{
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 403, "policy_mutation_denied");
    return;
  }
  set_json_error (msg, 500, "policy_mutation_failed");
}

static void
set_policy_transition_error (SoupServerMessage *msg, wyrelog_error_t rc)
{
  if (rc == WYRELOG_E_INVALID || rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return;
  }
  set_json_error (msg, 500, "policy_mutation_failed");
}

static gboolean
authorize_tenant_management (SoupServer *server, SoupServerMessage *msg,
    GHashTable *query, WylDaemonHttpContext *ctx, gchar **out_actor)
{
  return authorize_guarded_session_action (server, msg, query, ctx,
      "wr.tenant.manage", WYL_TENANT_DEFAULT, "tenant_auth_required",
      "invalid_tenant_auth", "tenant_denied", "tenant_auth_failed", out_actor);
}

static void
tenant_list_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  if (!authorize_tenant_management (server, msg, query, ctx, NULL))
    return;

  g_autoptr (GString) body = g_string_new ("{\"tenants\":[");
  TenantListJsonCtx json_ctx = {
    .json = body,
    .first = TRUE,
  };
  wyrelog_error_t rc = wyl_policy_store_foreach_tenant
      (wyl_handle_get_policy_store (ctx->handle), append_tenant_json,
      &json_ctx);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "tenant_query_failed");
    return;
  }
  g_string_append (body, "]}");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
tenant_mutation_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data,
    const gchar *action)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *tenant = lookup_required_query_string (query, "name");
  if (!wyl_policy_store_tenant_id_is_valid (tenant)) {
    set_json_error (msg, 400, "invalid_tenant_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!authorize_tenant_management (server, msg, query, ctx, &actor))
    return;

  if (g_strcmp0 (action, "create") != 0
      && g_strcmp0 (action, "seal") != 0 && g_strcmp0 (action, "unseal") != 0) {
    set_json_error (msg, 405, "tenant_delete_unsupported");
    return;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "tenant_mutation_failed");
    return;
  }

  gboolean changed = FALSE;
  if (g_strcmp0 (action, "create") == 0) {
    rc = wyl_policy_store_create_tenant (write.store, tenant, &changed);
  } else if (g_strcmp0 (action, "seal") == 0) {
    rc = wyl_policy_store_set_tenant_sealed (write.store, tenant, TRUE);
    changed = rc == WYRELOG_E_OK;
  } else if (g_strcmp0 (action, "unseal") == 0) {
    rc = wyl_policy_store_set_tenant_sealed (write.store, tenant, FALSE);
    changed = rc == WYRELOG_E_OK;
  }

  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_tenant_request");
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 403, "tenant_mutation_denied");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "tenant_mutation_failed");
    return;
  }

  if (changed) {
    g_autofree gchar *audit_action = g_strdup_printf ("tenant_%s", action);
    rc = emit_tenant_lifecycle_audit (ctx, actor, tenant, audit_action,
        ensure_request_id_header (msg));
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "tenant_mutation_failed");
      return;
    }
  }

  set_tenant_mutation_json (msg, tenant, changed);
}

static void
tenant_create_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  tenant_mutation_handler (server, msg, path, query, user_data, "create");
}

static void
tenant_seal_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  tenant_mutation_handler (server, msg, path, query, user_data, "seal");
}

static void
tenant_unseal_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  tenant_mutation_handler (server, msg, path, query, user_data, "unseal");
}

static void
tenant_delete_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  tenant_mutation_handler (server, msg, path, query, user_data, "delete");
}

#ifdef WYL_HAS_FACT_STORE
static GHashTable *
copy_query_with_tenant (GHashTable *query, const gchar *tenant)
{
  GHashTable *copy = g_hash_table_new (g_str_hash, g_str_equal);
  if (query != NULL) {
    GHashTableIter iter;
    gpointer key = NULL;
    gpointer value = NULL;
    g_hash_table_iter_init (&iter, query);
    while (g_hash_table_iter_next (&iter, &key, &value))
      g_hash_table_insert (copy, key, value);
  }
  g_hash_table_replace (copy, (gpointer) "tenant", (gpointer) tenant);
  return copy;
}

static gboolean
query_tenant_matches (SoupServerMessage *msg, GHashTable *query,
    const gchar *tenant)
{
  const gchar *declared = query != NULL ? g_hash_table_lookup (query,
      "tenant") : NULL;
  if (declared != NULL && !wyl_policy_store_tenant_id_is_valid (declared)) {
    set_json_error (msg, 400, WYL_DAEMON_ERR_TENANT_INVALID);
    return FALSE;
  }
  if (declared != NULL && g_strcmp0 (declared, tenant) != 0) {
    set_json_error (msg, 403, WYL_DAEMON_ERR_TENANT_DENIED);
    return FALSE;
  }
  return TRUE;
}

static gboolean
parse_uint32_query_param (const gchar *value, guint32 *out_value)
{
  gint64 parsed = 0;
  if (!parse_int64_query_param (value, &parsed) || parsed <= 0 ||
      parsed > G_MAXUINT32)
    return FALSE;
  *out_value = (guint32) parsed;
  return TRUE;
}

static gboolean
fact_http_component_is_valid (const gchar *component)
{
  if (component == NULL)
    return FALSE;
  gsize len = strlen (component);
  if (len == 0 || len > 128)
    return FALSE;
  if (g_strcmp0 (component, ".") == 0 || g_strcmp0 (component, "..") == 0)
    return FALSE;
  for (const gchar * p = component; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    if (g_ascii_isalnum (c) || c == '.' || c == '_' || c == ':' || c == '-')
      continue;
    return FALSE;
  }
  return TRUE;
}

static gboolean
fact_http_customer_name_is_valid (const gchar *name)
{
  return fact_http_component_is_valid (name) &&
      g_strcmp0 (name, "wr") != 0 && !g_str_has_prefix (name, "wr.") &&
      !g_str_has_prefix (name, "__wyrelog.");
}
#endif

typedef struct
{
  GString *json;
  gboolean first;
} GraphListJsonCtx;

static wyrelog_error_t
append_graph_json (const wyl_policy_fact_graph_info_t *info, gpointer user_data)
{
  GraphListJsonCtx *ctx = user_data;
  if (!ctx->first)
    g_string_append_c (ctx->json, ',');
  ctx->first = FALSE;
  g_string_append (ctx->json, "{\"tenant_id\":");
  append_json_string (ctx->json, info->tenant_id);
  g_string_append (ctx->json, ",\"graph_id\":");
  append_json_string (ctx->json, info->graph_id);
  g_string_append_printf (ctx->json,
      ",\"sealed\":%s,\"schema_version\":%u}",
      info->sealed ? "true" : "false", info->schema_version);
  return WYRELOG_E_OK;
}

static void
graphs_list_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "GET") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *tenant = lookup_required_query_string (query, "tenant");
  if (!wyl_policy_store_tenant_id_is_valid (tenant)) {
    set_json_error (msg, 400, "invalid_graph_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.graph.manage", tenant, "graph_auth_required",
          "invalid_graph_auth", "graph_denied", "graph_auth_failed", NULL))
    return;

  g_autoptr (GString) body = g_string_new ("{\"graphs\":[");
  GraphListJsonCtx json_ctx = {
    .json = body,
    .first = TRUE,
  };
  wyrelog_error_t rc = wyl_policy_store_foreach_fact_graph
      (wyl_handle_get_policy_store (ctx->handle), tenant, append_graph_json,
      &json_ctx);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "graph_query_failed");
    return;
  }
  g_string_append (body, "]}");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
set_graph_mutation_json (SoupServerMessage *msg, const gchar *tenant,
    const gchar *graph, const gchar *field, gboolean value)
{
  g_autoptr (GString) body = g_string_new ("{\"ok\":true,\"tenant_id\":");
  append_json_string (body, tenant);
  g_string_append (body, ",\"graph_id\":");
  append_json_string (body, graph);
  g_string_append_printf (body, ",\"%s\":%s}", field, value ? "true" : "false");
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
graph_create_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *tenant = lookup_required_query_string (query, "tenant");
  const gchar *graph = lookup_required_query_string (query, "graph");
  if (!wyl_policy_store_tenant_id_is_valid (tenant) ||
#ifdef WYL_HAS_FACT_STORE
      !fact_http_customer_name_is_valid (graph)
#else
      graph == NULL
#endif
      ) {
    set_json_error (msg, 400, "invalid_graph_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
#ifndef WYL_HAS_FACT_STORE
  (void) ctx;
  set_json_error (msg, 503, "fact_store_disabled");
  return;
#else
  if (ctx->fact_root == NULL || ctx->fact_root[0] == '\0') {
    set_json_error (msg, 503, "fact_store_disabled");
    return;
  }
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.graph.manage", tenant, "graph_auth_required",
          "invalid_graph_auth", "graph_denied", "graph_auth_failed", &actor))
    return;

  wyl_policy_fact_graph_create_options_t opts = {
    .tenant_id = tenant,
    .graph_id = graph,
    .fact_root = ctx->fact_root,
    .schema_version = 1,
    .owner_scope = tenant,
  };

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_fact_graph (write.store, &opts, NULL);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_graph_request");
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 409, "graph_exists");
    return;
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, "tenant_invalid");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "graph_mutation_failed");
    return;
  }

  (void) actor;
  set_graph_mutation_json (msg, tenant, graph, "created", TRUE);
#endif
}

static void
graph_seal_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *tenant = lookup_required_query_string (query, "tenant");
  const gchar *graph = lookup_required_query_string (query, "graph");
  if (!wyl_policy_store_tenant_id_is_valid (tenant) ||
#ifdef WYL_HAS_FACT_STORE
      !fact_http_customer_name_is_valid (graph)
#else
      graph == NULL
#endif
      ) {
    set_json_error (msg, 400, "invalid_graph_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.graph.manage", tenant, "graph_auth_required",
          "invalid_graph_auth", "graph_denied", "graph_auth_failed", NULL))
    return;

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_seal_fact_graph (write.store, tenant, graph);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_graph_request");
    return;
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, "graph_not_found");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "graph_mutation_failed");
    return;
  }
  set_graph_mutation_json (msg, tenant, graph, "sealed", TRUE);
}

#ifdef WYL_HAS_FACT_STORE
typedef struct
{
  const gchar *graph_id;
  gboolean found;
  wyl_policy_fact_graph_info_t info;
  gchar *tenant_id;
  gchar *graph_id_copy;
  gchar *storage_uri;
  gchar *storage_path;
  gchar *owner_scope;
} GraphLookupCtx;

static void
graph_lookup_clear (GraphLookupCtx *ctx)
{
  g_free (ctx->tenant_id);
  g_free (ctx->graph_id_copy);
  g_free (ctx->storage_uri);
  g_free (ctx->storage_path);
  g_free (ctx->owner_scope);
}

static wyrelog_error_t
lookup_graph_cb (const wyl_policy_fact_graph_info_t *info, gpointer user_data)
{
  GraphLookupCtx *ctx = user_data;
  if (g_strcmp0 (info->graph_id, ctx->graph_id) != 0)
    return WYRELOG_E_OK;
  ctx->found = TRUE;
  ctx->tenant_id = g_strdup (info->tenant_id);
  ctx->graph_id_copy = g_strdup (info->graph_id);
  ctx->storage_uri = g_strdup (info->storage_uri);
  ctx->storage_path = g_strdup (info->storage_path);
  ctx->owner_scope = g_strdup (info->owner_scope);
  ctx->info.tenant_id = ctx->tenant_id;
  ctx->info.graph_id = ctx->graph_id_copy;
  ctx->info.storage_uri = ctx->storage_uri;
  ctx->info.storage_path = ctx->storage_path;
  ctx->info.schema_version = info->schema_version;
  ctx->info.owner_scope = ctx->owner_scope;
  ctx->info.sealed = info->sealed;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
lookup_fact_graph (wyl_policy_store_t *store, const gchar *tenant,
    const gchar *graph, GraphLookupCtx *out)
{
  memset (out, 0, sizeof *out);
  out->graph_id = graph;
  return wyl_policy_store_foreach_fact_graph (store, tenant, lookup_graph_cb,
      out);
}

static gboolean
request_body_dup (SoupServerMessage *msg, gsize max_len, gchar **out_body)
{
  *out_body = NULL;
  SoupMessageBody *body = soup_server_message_get_request_body (msg);
  if (body == NULL || body->length <= 0 || body->data == NULL)
    return FALSE;
  if ((gsize) body->length > max_len)
    return FALSE;
  *out_body = g_strndup (body->data, (gsize) body->length);
  return *out_body != NULL;
}

static gboolean
parse_bool_token (const gchar *value, gboolean *out)
{
  if (g_strcmp0 (value, "true") == 0 || g_strcmp0 (value, "1") == 0) {
    *out = TRUE;
    return TRUE;
  }
  if (g_strcmp0 (value, "false") == 0 || g_strcmp0 (value, "0") == 0) {
    *out = FALSE;
    return TRUE;
  }
  return FALSE;
}

static void
schema_columns_clear (wyl_policy_fact_relation_schema_column_t *columns,
    gsize n_columns)
{
  if (columns == NULL)
    return;
  for (gsize i = 0; i < n_columns; i++) {
    g_free ((gchar *) columns[i].column_name);
    g_free ((gchar *) columns[i].column_type);
  }
  g_free (columns);
}

static void
schema_columns_clear_array (GArray **cols)
{
  if (cols == NULL || *cols == NULL)
    return;
  gsize n_columns = (*cols)->len;
  wyl_policy_fact_relation_schema_column_t *columns =
      (wyl_policy_fact_relation_schema_column_t *) g_array_free (*cols,
      FALSE);
  *cols = NULL;
  schema_columns_clear (columns, n_columns);
}

static gboolean
parse_schema_tsv (const gchar *body,
    wyl_policy_fact_relation_schema_column_t **out_columns,
    gsize *out_n_columns)
{
  *out_columns = NULL;
  *out_n_columns = 0;
  g_auto (GStrv) lines = g_strsplit (body, "\n", -1);
  g_autoptr (GArray) cols =
      g_array_new (FALSE, TRUE,
      sizeof (wyl_policy_fact_relation_schema_column_t));

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_strchomp (lines[i]);
    if (lines[i][0] == '\0')
      continue;
    if (g_strcmp0 (lines[i], "column_name\tcolumn_type\tnullable\tvisible")
        == 0)
      continue;
    g_auto (GStrv) fields = g_strsplit (lines[i], "\t", 5);
    if (g_strv_length (fields) != 4) {
      schema_columns_clear_array (&cols);
      return FALSE;
    }
    gboolean nullable = FALSE;
    gboolean visible = FALSE;
    if (!parse_bool_token (fields[2], &nullable) ||
        !parse_bool_token (fields[3], &visible)) {
      schema_columns_clear_array (&cols);
      return FALSE;
    }
    wyl_policy_fact_relation_schema_column_t col = {
      .column_name = g_strdup (fields[0]),
      .column_type = g_strdup (fields[1]),
      .nullable = nullable,
      .visible = visible,
    };
    g_array_append_val (cols, col);
  }
  if (cols->len == 0) {
    schema_columns_clear_array (&cols);
    return FALSE;
  }
  *out_n_columns = cols->len;
  *out_columns = (wyl_policy_fact_relation_schema_column_t *)
      g_array_free (g_steal_pointer (&cols), FALSE);
  return TRUE;
}

static void
fact_rows_clear (wyl_fact_row_t *rows, gsize n_rows)
{
  if (rows == NULL)
    return;
  for (gsize i = 0; i < n_rows; i++) {
    for (gsize j = 0; j < rows[i].n_values; j++) {
      if (rows[i].values[j].type == WYL_FACT_VALUE_SYMBOL ||
          rows[i].values[j].type == WYL_FACT_VALUE_STRING)
        g_free ((gchar *) rows[i].values[j].as.text);
    }
    g_free ((wyl_fact_value_t *) rows[i].values);
  }
  g_free (rows);
}

static void
fact_rows_clear_array (GArray **rows)
{
  if (rows == NULL || *rows == NULL)
    return;
  gsize n_rows = (*rows)->len;
  wyl_fact_row_t *row_data = (wyl_fact_row_t *) g_array_free (*rows, FALSE);
  *rows = NULL;
  fact_rows_clear (row_data, n_rows);
}

static gboolean
parse_fact_value (const gchar *text,
    const wyl_policy_fact_relation_schema_column_info_t *column,
    wyl_fact_value_t *out)
{
  if ((text == NULL || text[0] == '\0' || g_strcmp0 (text, "NULL") == 0)
      && column->nullable) {
    out->type = WYL_FACT_VALUE_NULL;
    return TRUE;
  }
  if (g_strcmp0 (column->column_type, "symbol") == 0) {
    out->type = WYL_FACT_VALUE_SYMBOL;
    out->as.text = g_strdup (text);
    return out->as.text != NULL;
  }
  if (g_strcmp0 (column->column_type, "string") == 0) {
    out->type = WYL_FACT_VALUE_STRING;
    out->as.text = g_strdup (text);
    return out->as.text != NULL;
  }
  if (g_strcmp0 (column->column_type, "int64") == 0) {
    gchar *end = NULL;
    errno = 0;
    gint64 parsed = g_ascii_strtoll (text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
      return FALSE;
    out->type = WYL_FACT_VALUE_INT64;
    out->as.int64_value = parsed;
    return TRUE;
  }
  if (g_strcmp0 (column->column_type, "bool") == 0) {
    gboolean parsed = FALSE;
    if (!parse_bool_token (text, &parsed))
      return FALSE;
    out->type = WYL_FACT_VALUE_BOOL;
    out->as.bool_value = parsed;
    return TRUE;
  }
  if (g_strcmp0 (column->column_type, "compound_ref") == 0) {
    gchar *end = NULL;
    errno = 0;
    gint64 parsed = g_ascii_strtoll (text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
      return FALSE;
    out->type = WYL_FACT_VALUE_COMPOUND_REF;
    out->as.compound_ref = parsed;
    return TRUE;
  }
  return FALSE;
}

static gboolean
line_is_fact_header (gchar **fields,
    const wyl_policy_fact_relation_schema_column_info_t *columns,
    gsize n_columns)
{
  if (g_strv_length (fields) != n_columns)
    return FALSE;
  for (gsize i = 0; i < n_columns; i++) {
    if (g_strcmp0 (fields[i], columns[i].column_name) != 0)
      return FALSE;
  }
  return TRUE;
}

static gboolean
parse_fact_tsv (const gchar *body,
    const wyl_policy_fact_relation_schema_column_info_t *columns,
    gsize n_columns, wyl_fact_row_t **out_rows, gsize *out_n_rows)
{
  *out_rows = NULL;
  *out_n_rows = 0;
  g_auto (GStrv) lines = g_strsplit (body, "\n", -1);
  g_autoptr (GArray) rows = g_array_new (FALSE, TRUE, sizeof (wyl_fact_row_t));
  gboolean first_data = TRUE;

  for (gsize i = 0; lines[i] != NULL; i++) {
    g_strchomp (lines[i]);
    if (lines[i][0] == '\0')
      continue;
    g_auto (GStrv) fields = g_strsplit (lines[i], "\t", n_columns + 2);
    if (first_data && line_is_fact_header (fields, columns, n_columns)) {
      first_data = FALSE;
      continue;
    }
    first_data = FALSE;
    if (g_strv_length (fields) != n_columns) {
      fact_rows_clear_array (&rows);
      return FALSE;
    }
    wyl_fact_value_t *values = g_new0 (wyl_fact_value_t, n_columns);
    wyl_fact_row_t row = {
      .values = values,
      .n_values = n_columns,
    };
    for (gsize j = 0; j < n_columns; j++) {
      if (!parse_fact_value (fields[j], &columns[j], &values[j])) {
        for (gsize k = 0; k < n_columns; k++) {
          if (values[k].type == WYL_FACT_VALUE_SYMBOL ||
              values[k].type == WYL_FACT_VALUE_STRING)
            g_free ((gchar *) values[k].as.text);
        }
        g_free (values);
        fact_rows_clear_array (&rows);
        return FALSE;
      }
    }
    g_array_append_val (rows, row);
  }
  if (rows->len == 0) {
    fact_rows_clear_array (&rows);
    return FALSE;
  }
  *out_n_rows = rows->len;
  *out_rows = (wyl_fact_row_t *) g_array_free (g_steal_pointer (&rows), FALSE);
  return TRUE;
}

static wyl_policy_fact_relation_schema_column_t *
copy_schema_columns (const wyl_policy_fact_relation_schema_column_info_t *info,
    gsize n_columns)
{
  wyl_policy_fact_relation_schema_column_t *columns =
      g_new0 (wyl_policy_fact_relation_schema_column_t, n_columns);
  for (gsize i = 0; i < n_columns; i++) {
    columns[i].column_name = g_strdup (info[i].column_name);
    columns[i].column_type = g_strdup (info[i].column_type);
    columns[i].nullable = info[i].nullable;
    columns[i].visible = info[i].visible;
  }
  return columns;
}

static void
set_schema_ok_json (SoupServerMessage *msg, const gchar *tenant,
    const gchar *graph, const gchar *namespace_id, const gchar *relation)
{
  g_autoptr (GString) body = g_string_new ("{\"ok\":true,\"tenant_id\":");
  append_json_string (body, tenant);
  g_string_append (body, ",\"graph_id\":");
  append_json_string (body, graph);
  g_string_append (body, ",\"namespace_id\":");
  append_json_string (body, namespace_id);
  g_string_append (body, ",\"relation_name\":");
  append_json_string (body, relation);
  g_string_append_c (body, '}');
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
schema_register_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  const gchar *tenant = lookup_required_query_string (query, "tenant");
  const gchar *graph = lookup_required_query_string (query, "graph");
  const gchar *namespace_id = lookup_required_query_string (query, "namespace");
  const gchar *relation = lookup_required_query_string (query, "relation");
  guint32 schema_version = 0;
  guint32 max_rows = 0;
  gboolean relation_visible = TRUE;
  const gchar *visible = query != NULL ? g_hash_table_lookup (query,
      "relation_visible") : NULL;
  const gchar *max_rows_text = query != NULL ? g_hash_table_lookup (query,
      "max_rows") : NULL;
  if (!wyl_policy_store_tenant_id_is_valid (tenant) ||
      !fact_http_customer_name_is_valid (graph) ||
      !fact_http_customer_name_is_valid (namespace_id) ||
      !fact_http_customer_name_is_valid (relation) ||
      !parse_uint32_query_param (lookup_required_query_string (query,
              "schema_version"), &schema_version) ||
      (max_rows_text != NULL &&
          !parse_uint32_query_param (max_rows_text, &max_rows)) ||
      (visible != NULL && !parse_bool_token (visible, &relation_visible))) {
    set_json_error (msg, 400, "invalid_schema_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.schema.manage", tenant, "schema_auth_required",
          "invalid_schema_auth", "schema_denied", "schema_auth_failed", NULL))
    return;

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "schema_register_failed");
    return;
  }

  GraphLookupCtx lookup = { 0 };
  rc = lookup_fact_graph (write.store, tenant, graph, &lookup);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "schema_register_failed");
    return;
  }
  if (!lookup.found) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 404, "graph_not_found");
    return;
  }
  if (lookup.info.sealed) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 409, "graph_sealed");
    return;
  }
  graph_lookup_clear (&lookup);

  g_autofree gchar *body = NULL;
  if (!request_body_dup (msg, 1024 * 1024, &body)) {
    set_json_error (msg, 400, "invalid_schema_payload");
    return;
  }
  wyl_policy_fact_relation_schema_column_t *columns = NULL;
  gsize n_columns = 0;
  if (!parse_schema_tsv (body, &columns, &n_columns)) {
    set_json_error (msg, 400, "invalid_schema_payload");
    return;
  }

  wyl_policy_fact_relation_schema_query_t schema_query = {
    .query_name = relation,
    .required_permission_id = "wr.datalog.query",
    .max_rows = max_rows,
  };
  wyl_policy_fact_relation_schema_options_t opts = {
    .tenant_id = tenant,
    .graph_id = graph,
    .namespace_id = namespace_id,
    .relation_name = relation,
    .schema_version = schema_version,
    .relation_visible = relation_visible,
    .columns = columns,
    .n_columns = n_columns,
    .queries = max_rows > 0 ? &schema_query : NULL,
    .n_queries = max_rows > 0 ? 1 : 0,
  };
  rc = wyl_policy_store_register_fact_relation_schema (write.store, &opts);
  schema_columns_clear (columns, n_columns);
  if (rc == WYRELOG_E_INVALID || rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 400, "invalid_schema_request");
    return;
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    set_json_error (msg, 404, "graph_not_found");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "schema_register_failed");
    return;
  }
  set_schema_ok_json (msg, tenant, graph, namespace_id, relation);
}

typedef enum
{
  FACT_HTTP_OP_APPEND = 0,
  FACT_HTTP_OP_RETRACT,
  FACT_HTTP_OP_FORGET,
} fact_http_op_t;

#ifdef WYL_HAS_FACT_STORE
#define WYL_FACT_HTTP_STORE_LOG_DOMAIN "wyrelog-fact-http-store"

static void
trace_http_fact_store (const gchar *stage, wyrelog_error_t rc)
{
  g_log (WYL_FACT_HTTP_STORE_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
      "stage=%s rc=%d", stage, (int) rc);
}

static wyrelog_error_t
resolve_http_fact_db_path (WylDaemonHttpContext *ctx,
    wyl_policy_store_t *policy_store, const gchar *tenant, const gchar *graph,
    gboolean writable, gchar **out_path, gboolean *out_needs_hardening)
{
  *out_path = NULL;
  *out_needs_hardening = FALSE;
  if (policy_store == NULL || ctx->fact_root == NULL
      || ctx->fact_root[0] == '\0')
    return WYRELOG_E_POLICY;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  wyrelog_error_t rc = wyl_policy_store_open_fact_graph_directory
      (policy_store, ctx->fact_root, tenant, graph, FALSE, &directory);
  gint fd = -1;
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_open_file (&directory, "facts.duckdb",
        writable, &fd);
  if (rc == WYRELOG_E_NOT_FOUND && writable) {
    *out_needs_hardening = TRUE;
    rc = WYRELOG_E_OK;
  }
  if (rc == WYRELOG_E_OK) {
    *out_path = wyl_fact_graph_directory_descriptive_file (&directory,
        "facts.duckdb");
    if (*out_path == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (fd >= 0)
#ifdef G_OS_WIN32
    _close (fd);
#else
    close (fd);
#endif
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

static wyrelog_error_t
secure_http_fact_db_mode (WylDaemonHttpContext *ctx,
    wyl_policy_store_t *policy_store, const gchar *tenant, const gchar *graph)
{
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  wyrelog_error_t rc = wyl_policy_store_open_fact_graph_directory
      (policy_store, ctx->fact_root, tenant, graph, FALSE, &directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_directory_secure_file_mode (&directory, "facts.duckdb");
  wyl_fact_graph_directory_clear (&directory);
  return rc;
}

static wyrelog_error_t
open_http_fact_store (WylDaemonHttpContext *ctx,
    wyl_policy_store_t *policy_store, const gchar *tenant, const gchar *graph,
    wyl_fact_store_t **out_store)
{
  *out_store = NULL;
  g_autofree gchar *path = NULL;
  gboolean needs_hardening = FALSE;
  wyrelog_error_t rc = resolve_http_fact_db_path (ctx, policy_store, tenant,
      graph, TRUE, &path, &needs_hardening);
  trace_http_fact_store ("resolve", rc);
  if (rc == WYRELOG_E_OK) {
    rc = wyl_fact_store_open (path, out_store);
    trace_http_fact_store ("duckdb-open", rc);
  }
  if (needs_hardening) {
    wyrelog_error_t materialize_rc = rc;
    if (rc == WYRELOG_E_OK)
      materialize_rc = wyl_fact_store_create_schema (*out_store);
    trace_http_fact_store ("materialize-schema", materialize_rc);
    g_clear_pointer (out_store, wyl_fact_store_close);

    wyrelog_error_t harden_rc = secure_http_fact_db_mode (ctx, policy_store,
        tenant, graph);
    trace_http_fact_store ("harden", harden_rc);
    if (harden_rc != WYRELOG_E_OK && harden_rc != WYRELOG_E_NOT_FOUND)
      return harden_rc;
    if (materialize_rc != WYRELOG_E_OK)
      return materialize_rc;
    if (harden_rc != WYRELOG_E_OK)
      return harden_rc;

    /* The creation handoff is re-anchored before the descriptive path is
     * given back to DuckDB.  A replacement or weak ACL fails closed. */
    g_clear_pointer (&path, g_free);
    gboolean still_missing = FALSE;
    rc = resolve_http_fact_db_path (ctx, policy_store, tenant, graph, TRUE,
        &path, &still_missing);
    if (rc == WYRELOG_E_OK && still_missing)
      rc = WYRELOG_E_POLICY;
    trace_http_fact_store ("strict-resolve", rc);
    if (rc == WYRELOG_E_OK) {
      rc = wyl_fact_store_open (path, out_store);
      trace_http_fact_store ("duckdb-reopen", rc);
    }
  }
  return rc;
}
#endif

static gboolean
parse_fact_op_path (const gchar *path, gchar **out_tenant,
    gchar **out_graph, gchar **out_relation, fact_http_op_t *out_op)
{
  *out_tenant = NULL;
  *out_graph = NULL;
  *out_relation = NULL;
  if (out_op != NULL)
    *out_op = FACT_HTTP_OP_APPEND;
  if (path == NULL || !g_str_has_prefix (path, "/facts/"))
    return FALSE;
  const gchar *tail = path + strlen ("/facts/");
  g_auto (GStrv) parts = g_strsplit (tail, "/", 3);
  if (g_strv_length (parts) != 3)
    return FALSE;
  fact_http_op_t op = FACT_HTTP_OP_APPEND;
  const gchar *suffix = NULL;
  if (g_str_has_suffix (parts[2], ":append")) {
    op = FACT_HTTP_OP_APPEND;
    suffix = ":append";
  } else if (g_str_has_suffix (parts[2], ":retract")) {
    op = FACT_HTTP_OP_RETRACT;
    suffix = ":retract";
  } else if (g_str_has_suffix (parts[2], ":forget")) {
    op = FACT_HTTP_OP_FORGET;
    suffix = ":forget";
  } else {
    return FALSE;
  }
  parts[2][strlen (parts[2]) - strlen (suffix)] = '\0';
  if (parts[0][0] == '\0' || parts[1][0] == '\0' || parts[2][0] == '\0')
    return FALSE;
  *out_tenant = g_strdup (parts[0]);
  *out_graph = g_strdup (parts[1]);
  *out_relation = g_strdup (parts[2]);
  if (out_op != NULL)
    *out_op = op;
  return *out_tenant != NULL && *out_graph != NULL && *out_relation != NULL;
}

static gboolean
parse_datalog_query_path (const gchar *path, gchar **out_tenant,
    gchar **out_graph)
{
  *out_tenant = NULL;
  *out_graph = NULL;
  if (path == NULL || !g_str_has_prefix (path, "/datalog/") ||
      !g_str_has_suffix (path, "/query"))
    return FALSE;
  const gchar *tail = path + strlen ("/datalog/");
  g_autofree gchar *inner = g_strndup (tail,
      strlen (tail) - strlen ("/query"));
  g_auto (GStrv) parts = g_strsplit (inner, "/", 2);
  if (g_strv_length (parts) != 2 || parts[0][0] == '\0' || parts[1][0] == '\0')
    return FALSE;
  *out_tenant = g_strdup (parts[0]);
  *out_graph = g_strdup (parts[1]);
  return *out_tenant != NULL && *out_graph != NULL;
}

static const gchar *
skip_ascii_spaces (const gchar *p)
{
  while (p != NULL && g_ascii_isspace (*p))
    p++;
  return p;
}

static gchar *
json_dup_simple_string_member (const gchar *json, const gchar *member)
{
  if (json == NULL || member == NULL)
    return NULL;
  g_autofree gchar *needle = g_strdup_printf ("\"%s\"", member);
  const gchar *p = strstr (json, needle);
  if (p == NULL)
    return NULL;
  p += strlen (needle);
  p = skip_ascii_spaces (p);
  if (*p != ':')
    return NULL;
  p = skip_ascii_spaces (p + 1);
  if (*p != '"')
    return NULL;
  p++;
  g_autoptr (GString) value = g_string_new (NULL);
  while (*p != '\0' && *p != '"') {
    if ((guchar) * p < 0x20)
      return NULL;
    if (*p == '\\') {
      p++;
      switch (*p) {
        case '"':
        case '\\':
        case '/':
          g_string_append_c (value, *p++);
          break;
        case 'n':
          g_string_append_c (value, '\n');
          p++;
          break;
        case 'r':
          g_string_append_c (value, '\r');
          p++;
          break;
        case 't':
          g_string_append_c (value, '\t');
          p++;
          break;
        default:
          return NULL;
      }
      continue;
    }
    g_string_append_c (value, *p++);
  }
  if (*p != '"')
    return NULL;
  return g_string_free (g_steal_pointer (&value), FALSE);
}

static gboolean
json_parse_simple_uint_member (const gchar *json, const gchar *member,
    guint *out_value, gboolean *out_present)
{
  if (out_present != NULL)
    *out_present = FALSE;
  if (json == NULL || member == NULL || out_value == NULL)
    return FALSE;
  g_autofree gchar *needle = g_strdup_printf ("\"%s\"", member);
  const gchar *p = strstr (json, needle);
  if (p == NULL)
    return TRUE;
  if (out_present != NULL)
    *out_present = TRUE;
  p += strlen (needle);
  p = skip_ascii_spaces (p);
  if (*p != ':')
    return FALSE;
  p = skip_ascii_spaces (p + 1);
  if (!g_ascii_isdigit (*p))
    return FALSE;
  errno = 0;
  gchar *end = NULL;
  guint64 parsed = g_ascii_strtoull (p, &end, 10);
  if (errno != 0 || end == p || parsed > G_MAXUINT)
    return FALSE;
  *out_value = (guint) parsed;
  return TRUE;
}

static wyrelog_error_t
emit_datalog_query_audit (WylDaemonHttpContext *ctx, const gchar *actor,
    const gchar *tenant, const gchar *graph, const gchar *query_name,
    const gchar *decision, guint row_count, gboolean truncated,
    const gchar *request_id)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  g_autofree gchar *resource = g_strdup_printf ("%s/%s/%s", tenant, graph,
      query_name != NULL ? query_name : "unknown");
  g_autofree gchar *origin = g_strdup_printf ("rows=%u truncated=%s",
      row_count, truncated ? "true" : "false");
  wyl_audit_event_set_subject_id (ev, actor);
  wyl_audit_event_set_action (ev, "datalog_query");
  wyl_audit_event_set_resource_id (ev, resource);
  wyl_audit_event_set_deny_reason (ev, decision);
  wyl_audit_event_set_deny_origin (ev, origin);
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev,
      g_strcmp0 (decision, "allow") == 0 ? WYL_DECISION_ALLOW :
      WYL_DECISION_DENY);
  return wyl_audit_emit (ctx->handle, ev);
#else
  (void) ctx;
  (void) actor;
  (void) tenant;
  (void) graph;
  (void) query_name;
  (void) decision;
  (void) row_count;
  (void) truncated;
  (void) request_id;
  return WYRELOG_E_OK;
#endif
}

static void
datalog_query_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  g_autofree gchar *tenant = NULL;
  g_autofree gchar *graph = NULL;
  if (!parse_datalog_query_path (path, &tenant, &graph) ||
      !wyl_policy_store_tenant_id_is_valid (tenant) ||
      !fact_http_customer_name_is_valid (graph)) {
    set_json_error (msg, 400, "invalid_datalog_request");
    return;
  }
  if (!query_tenant_matches (msg, query, tenant))
    return;

  WylDaemonHttpContext *ctx = user_data;
  g_autoptr (GHashTable) auth_query = copy_query_with_tenant (query, tenant);
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, auth_query, ctx,
          "wr.datalog.query", tenant, "datalog_auth_required",
          "invalid_datalog_auth", "datalog_denied", "datalog_auth_failed",
          &actor))
    return;

  GraphLookupCtx lookup = { 0 };
  wyrelog_error_t rc = lookup_fact_graph (wyl_handle_get_policy_store
      (ctx->handle), tenant, graph, &lookup);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "datalog_query_failed");
    return;
  }
  if (!lookup.found) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 404, "graph_not_found");
    return;
  }
  if (lookup.info.sealed) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 409, "graph_not_queryable");
    return;
  }
  graph_lookup_clear (&lookup);

  g_autofree gchar *body = NULL;
  if (!request_body_dup (msg, 16 * 1024, &body)) {
    set_json_error (msg, 400, "invalid_datalog_request");
    return;
  }
  g_autofree gchar *query_atom = json_dup_simple_string_member (body, "query");
  g_autofree gchar *output = json_dup_simple_string_member (body, "output");
  guint limit = 0;
  gboolean limit_present = FALSE;
  if (query_atom == NULL || (output != NULL && g_strcmp0 (output, "json") != 0)
      || !json_parse_simple_uint_member (body, "limit", &limit,
          &limit_present) || (limit_present && limit == 0)) {
    set_json_error (msg, 400, "invalid_datalog_request");
    return;
  }

  const gchar *request_id = ensure_request_id_header (msg);
  g_autofree gchar *json = NULL;
  g_autofree gchar *query_name = NULL;
  gboolean truncated = FALSE;
  guint row_count = 0;
  wyl_fact_datalog_query_options_t opts = {
    .tenant_id = tenant,
    .graph_id = graph,
    .query = query_atom,
    .limit = limit,
    .query_id = request_id,
  };
  rc = wyl_fact_datalog_query_json (ctx->handle, &opts, &json, &truncated,
      &row_count, &query_name);
  if (rc == WYRELOG_E_INVALID) {
    (void) emit_datalog_query_audit (ctx, actor, tenant, graph, query_name,
        "invalid", 0, FALSE, request_id);
    set_json_error (msg, 400, "invalid_datalog_request");
    return;
  }
  if (rc == WYRELOG_E_POLICY || rc == WYRELOG_E_NOT_FOUND) {
    (void) emit_datalog_query_audit (ctx, actor, tenant, graph, query_name,
        "deny", 0, FALSE, request_id);
    set_json_error (msg, 403, "datalog_relation_denied");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    (void) emit_datalog_query_audit (ctx, actor, tenant, graph, query_name,
        "failed", 0, FALSE, request_id);
    set_json_error (msg, 500, "datalog_query_failed");
    return;
  }
  rc = emit_datalog_query_audit (ctx, actor, tenant, graph, query_name,
      "allow", row_count, truncated, request_id);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "datalog_query_failed");
    return;
  }

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, json, strlen (json));
}

static wyrelog_error_t
emit_fact_op_audit (WylDaemonHttpContext *ctx, const gchar *actor,
    const gchar *tenant, const gchar *graph, const gchar *namespace_id,
    const gchar *relation, const gchar *batch_id, wyl_fact_store_op_t op,
    gboolean inserted, const gchar *request_id)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  g_autofree gchar *resource = g_strdup_printf ("%s/%s/%s/%s", tenant, graph,
      namespace_id, relation);
  const gchar *action = (op == WYL_FACT_STORE_OP_RETRACT) ? "fact_retract" :
      "fact_append";
  wyl_audit_event_set_subject_id (ev, actor);
  wyl_audit_event_set_action (ev, action);
  wyl_audit_event_set_resource_id (ev, resource);
  wyl_audit_event_set_deny_reason (ev, batch_id);
  wyl_audit_event_set_deny_origin (ev, inserted ? "inserted" : "duplicate");
  wyl_audit_event_set_request_id (ev, request_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return wyl_audit_emit (ctx->handle, ev);
#else
  (void) ctx;
  (void) actor;
  (void) tenant;
  (void) graph;
  (void) namespace_id;
  (void) relation;
  (void) batch_id;
  (void) op;
  (void) inserted;
  (void) request_id;
  return WYRELOG_E_OK;
#endif
}

static void
set_fact_op_json (SoupServerMessage *msg, const gchar *batch_id,
    gboolean inserted)
{
  g_autoptr (GString) body = g_string_new ("{\"ok\":true,\"inserted\":");
  g_string_append (body, inserted ? "true" : "false");
  g_string_append (body, ",\"batch_id\":");
  append_json_string (body, batch_id);
  g_string_append_c (body, '}');
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body->str, body->len);
}

static void
facts_route_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  const gchar *method = soup_server_message_get_method (msg);

  g_autofree gchar *tenant = NULL;
  g_autofree gchar *graph = NULL;
  g_autofree gchar *relation = NULL;
  fact_http_op_t op = FACT_HTTP_OP_APPEND;
  if (!parse_fact_op_path (path, &tenant, &graph, &relation, &op) ||
      !wyl_policy_store_tenant_id_is_valid (tenant) ||
      !fact_http_customer_name_is_valid (graph) ||
      !fact_http_customer_name_is_valid (relation)) {
    set_json_error (msg, 400, "invalid_fact_request");
    return;
  }

  /* :forget uses DELETE; :append/:retract use POST. */
  if (op == FACT_HTTP_OP_FORGET) {
    if (g_strcmp0 (method, "DELETE") != 0) {
      set_json_error (msg, 405, "method_not_allowed");
      return;
    }
  } else {
    if (g_strcmp0 (method, "POST") != 0) {
      set_json_error (msg, 405, "method_not_allowed");
      return;
    }
  }

  if (!query_tenant_matches (msg, query, tenant))
    return;

  /* --- :forget branch --- */
  if (op == FACT_HTTP_OP_FORGET) {
    const gchar *namespace_id =
        lookup_required_query_string (query, "namespace");
    guint32 schema_version = 0;
    if (!fact_http_customer_name_is_valid (namespace_id) ||
        !parse_uint32_query_param (lookup_required_query_string (query,
                "schema_version"), &schema_version)) {
      set_json_error (msg, 400, "invalid_fact_request");
      return;
    }

    WylDaemonHttpContext *ctx = user_data;
    g_autoptr (GHashTable) auth_query = copy_query_with_tenant (query, tenant);
    g_autofree gchar *actor = NULL;
    if (!authorize_guarded_session_action (server, msg, auth_query, ctx,
            "wr.fact.write", tenant, "fact_auth_required", "invalid_fact_auth",
            "fact_denied", "fact_auth_failed", &actor))
      return;

    g_auto (WylDaemonPolicyWrite) write = { 0 };
    wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "fact_forget_failed");
      return;
    }

    g_autofree gchar *body = NULL;
    if (!request_body_dup (msg, 4096, &body)) {
      set_json_error (msg, 400, "invalid_fact_request");
      return;
    }
    g_autofree gchar *batch_id = json_dup_simple_string_member (body,
        "batch_id");
    g_autofree gchar *operator_id = json_dup_simple_string_member (body,
        "operator");
    g_autofree gchar *reason = json_dup_simple_string_member (body, "reason");
    if (batch_id == NULL || operator_id == NULL || reason == NULL ||
        batch_id[0] == '\0' || operator_id[0] == '\0' || reason[0] == '\0') {
      set_json_error (msg, 400, "invalid_fact_request");
      return;
    }

    GraphLookupCtx lookup = { 0 };
    rc = lookup_fact_graph (write.store, tenant, graph, &lookup);
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "fact_forget_failed");
      return;
    }
    if (!lookup.found) {
      graph_lookup_clear (&lookup);
      set_json_error (msg, 404, "graph_not_found");
      return;
    }

    gboolean relation_visible = FALSE;
    wyl_policy_fact_relation_schema_column_info_t *loaded = NULL;
    gsize n_loaded = 0;
    rc = wyl_policy_store_load_fact_relation_schema_columns
        (write.store, tenant, graph, namespace_id,
        relation, schema_version, &relation_visible, &loaded, &n_loaded);
    if (rc != WYRELOG_E_OK) {
      graph_lookup_clear (&lookup);
      set_json_error (msg, rc == WYRELOG_E_NOT_FOUND ? 404 : 500,
          rc == WYRELOG_E_NOT_FOUND ? "fact_schema_not_found" :
          "fact_forget_failed");
      return;
    }

    wyl_policy_fact_relation_schema_column_t *schema_columns =
        copy_schema_columns (loaded, n_loaded);
    wyl_policy_fact_relation_schema_options_t schema = {
      .tenant_id = tenant,
      .graph_id = graph,
      .namespace_id = namespace_id,
      .relation_name = relation,
      .schema_version = schema_version,
      .relation_visible = relation_visible,
      .columns = schema_columns,
      .n_columns = n_loaded,
    };
    g_autoptr (wyl_fact_store_t) fact_store = NULL;
    rc = open_http_fact_store (ctx, write.store, tenant, graph, &fact_store);
    gsize rows_purged = 0;
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_store_create_schema (fact_store);
    if (rc == WYRELOG_E_OK) {
      const wyl_fact_store_forget_options_t fopts = {
        .batch_id = batch_id,
        .operator_id = operator_id,
        .reason = reason,
      };
      rc = wyl_fact_store_forget (fact_store, &schema, &fopts, &rows_purged);
    }
    if (rc == WYRELOG_E_OK)
      (void) wyl_handle_replay_fact_graphs (ctx->handle, NULL);

    graph_lookup_clear (&lookup);
    wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
    schema_columns_clear (schema_columns, n_loaded);
    if (rc == WYRELOG_E_NOT_FOUND) {
      set_json_error (msg, 404, "fact_batch_not_found");
      return;
    }
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "fact_forget_failed");
      return;
    }
    g_autoptr (GString) resp = g_string_new (NULL);
    g_string_printf (resp, "{\"ok\":true,\"rows_purged\":%zu}", rows_purged);
    const gchar *request_id = ensure_request_id_header (msg);
    (void) request_id;
    attach_request_id_header (msg);
    soup_server_message_set_status (msg, 200, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, resp->str, resp->len);
    return;
  }

  /* --- :append / :retract branch --- */
  const gchar *namespace_id = lookup_required_query_string (query, "namespace");
  const gchar *batch_id = lookup_required_query_string (query, "batch_id");
  const gchar *idempotency_key = lookup_required_query_string (query,
      "idempotency_key");
  guint32 schema_version = 0;
  if (!fact_http_customer_name_is_valid (namespace_id) || batch_id == NULL ||
      idempotency_key == NULL ||
      !parse_uint32_query_param (lookup_required_query_string (query,
              "schema_version"), &schema_version)) {
    set_json_error (msg, 400, "invalid_fact_request");
    return;
  }
  const gchar *op_param =
      query != NULL ? g_hash_table_lookup (query, "op") : NULL;
  if (op_param != NULL) {
    const gchar *expected_op =
        (op == FACT_HTTP_OP_RETRACT) ? "retract" : "assert";
    if (g_strcmp0 (op_param, expected_op) != 0) {
      set_json_error (msg, 400, "invalid_fact_request");
      return;
    }
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autoptr (GHashTable) auth_query = copy_query_with_tenant (query, tenant);
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, auth_query, ctx,
          "wr.fact.write", tenant, "fact_auth_required", "invalid_fact_auth",
          "fact_denied", "fact_auth_failed", &actor))
    return;

  const gchar *fail_code =
      (op == FACT_HTTP_OP_RETRACT) ? "fact_retract_failed" :
      "fact_append_failed";
  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, fail_code);
    return;
  }
  GraphLookupCtx lookup = { 0 };
  rc = lookup_fact_graph (write.store, tenant, graph, &lookup);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, fail_code);
    return;
  }
  if (!lookup.found) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 404, "graph_not_found");
    return;
  }
  if (lookup.info.sealed) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, 409, "graph_sealed");
    return;
  }

  gboolean relation_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *loaded = NULL;
  gsize n_loaded = 0;
  rc = wyl_policy_store_load_fact_relation_schema_columns
      (write.store, tenant, graph, namespace_id,
      relation, schema_version, &relation_visible, &loaded, &n_loaded);
  if (rc != WYRELOG_E_OK) {
    graph_lookup_clear (&lookup);
    set_json_error (msg, rc == WYRELOG_E_NOT_FOUND ? 404 : 500,
        rc == WYRELOG_E_NOT_FOUND ? "fact_schema_not_found" : fail_code);
    return;
  }

  g_autofree gchar *body = NULL;
  if (!request_body_dup (msg, 1024 * 1024, &body)) {
    graph_lookup_clear (&lookup);
    wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
    set_json_error (msg, 400, "invalid_fact_payload");
    return;
  }
  wyl_fact_row_t *rows = NULL;
  gsize n_rows = 0;
  if (!parse_fact_tsv (body, loaded, n_loaded, &rows, &n_rows)) {
    graph_lookup_clear (&lookup);
    wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
    set_json_error (msg, 400, "invalid_fact_payload");
    return;
  }

  wyl_policy_fact_relation_schema_column_t *schema_columns =
      copy_schema_columns (loaded, n_loaded);
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = tenant,
    .graph_id = graph,
    .namespace_id = namespace_id,
    .relation_name = relation,
    .schema_version = schema_version,
    .relation_visible = relation_visible,
    .columns = schema_columns,
    .n_columns = n_loaded,
  };
  wyl_fact_batch_t validation_batch = {
    .tenant_id = tenant,
    .graph_id = graph,
    .namespace_id = namespace_id,
    .relation_name = relation,
    .schema_version = schema_version,
    .rows = rows,
    .n_rows = n_rows,
  };
  rc = wyl_fact_schema_validate_batch (write.store, &validation_batch, NULL);
  if (rc != WYRELOG_E_OK) {
    graph_lookup_clear (&lookup);
    wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
    schema_columns_clear (schema_columns, n_loaded);
    fact_rows_clear (rows, n_rows);
    set_json_error (msg, 400, "invalid_fact_payload");
    return;
  }

  g_autoptr (wyl_fact_store_t) fact_store = NULL;
  rc = open_http_fact_store (ctx, write.store, tenant, graph, &fact_store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_store_create_schema (fact_store);
  gboolean inserted = FALSE;
  const gchar *request_id = ensure_request_id_header (msg);
  wyl_fact_store_op_t store_op = (op == FACT_HTTP_OP_RETRACT) ?
      WYL_FACT_STORE_OP_RETRACT : WYL_FACT_STORE_OP_ASSERT;
  wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = tenant,
    .graph_id = graph,
    .namespace_id = namespace_id,
    .relation_name = relation,
    .schema_version = schema_version,
    .source = "http",
    .request_id = idempotency_key,
    .idempotency_key = idempotency_key,
    .op = store_op,
    .rows = rows,
    .n_rows = n_rows,
  };
  if (rc == WYRELOG_E_OK) {
    if (op == FACT_HTTP_OP_RETRACT)
      rc = wyl_fact_store_retract_batch (fact_store, &schema, &batch,
          &inserted);
    else
      rc = wyl_fact_store_append_batch (fact_store, &schema, &batch, &inserted);
  }
  if (rc == WYRELOG_E_OK)
    (void) wyl_handle_replay_fact_graphs (ctx->handle, NULL);
  if (rc == WYRELOG_E_OK)
    rc = emit_fact_op_audit (ctx, actor, tenant, graph, namespace_id,
        relation, batch_id, store_op, inserted, request_id);

  graph_lookup_clear (&lookup);
  wyl_policy_fact_relation_schema_columns_free (loaded, n_loaded);
  schema_columns_clear (schema_columns, n_loaded);
  fact_rows_clear (rows, n_rows);
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 409, "fact_batch_conflict");
    return;
  }
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_fact_payload");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, fail_code);
    return;
  }
  set_fact_op_json (msg, batch_id, inserted);
}
#else
static void
schema_register_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  (void) user_data;
  set_json_error (msg, 503, "fact_store_disabled");
}

static void
facts_route_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  (void) user_data;
  set_json_error (msg, 503, "fact_store_disabled");
}

static void
datalog_query_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) msg;
  (void) path;
  (void) query;
  (void) user_data;
  set_json_error (msg, 503, "fact_store_disabled");
}
#endif

static gboolean
ensure_policy_permission_exists (SoupServerMessage *msg,
    wyl_policy_store_t *store, const gchar *perm)
{
  gboolean exists = FALSE;
  wyrelog_error_t rc =
      wyl_policy_store_permission_exists (store, perm, &exists);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "policy_mutation_failed");
    return FALSE;
  }
  if (!exists) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return FALSE;
  }
  return TRUE;
}

static gboolean
ensure_permission_transition_event (SoupServerMessage *msg, const gchar *event)
{
  if (wyl_perm_event_from_name (event) == WYL_PERM_EVENT_LAST_) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return FALSE;
  }
  return TRUE;
}

static gboolean
ensure_policy_role_exists (SoupServerMessage *msg, wyl_policy_store_t *store,
    const gchar *role)
{
  gboolean exists = FALSE;
  wyrelog_error_t rc = wyl_policy_store_role_exists (store, role, &exists);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "policy_mutation_failed");
    return FALSE;
  }
  if (!exists) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return FALSE;
  }
  return TRUE;
}

static void
direct_permission_mutation_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data, gboolean grant)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *subject = lookup_required_query_string (query, "subject");
  const gchar *perm = lookup_required_query_string (query, "perm");
  const gchar *scope = lookup_required_query_string (query, "scope");
  if (subject == NULL || perm == NULL || scope == NULL) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.policy.write", scope, "policy_auth_required",
          "invalid_policy_auth", "policy_denied", "policy_auth_failed", &actor))
    return;
  if (!tenant_scope_is_allowed (lookup_request_tenant (query), scope)) {
    set_json_error (msg, 403, WYL_DAEMON_ERR_TENANT_DENIED);
    return;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_policy_mutation_error (msg, rc);
    return;
  }

  if (!ensure_policy_permission_exists (msg, write.store, perm))
    return;

  if (grant) {
    g_autoptr (wyl_grant_req_t) req = wyl_grant_req_new ();
    wyl_grant_req_set_subject_id (req, subject);
    wyl_grant_req_set_action (req, perm);
    wyl_grant_req_set_resource_id (req, scope);
    wyl_grant_req_set_actor_id (req, actor);
    wyl_grant_req_set_request_id (req, ensure_request_id_header (msg));
    rc = wyl_perm_grant (ctx->handle, req);
  } else {
    g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
    wyl_revoke_req_set_subject_id (req, subject);
    wyl_revoke_req_set_action (req, perm);
    wyl_revoke_req_set_resource_id (req, scope);
    wyl_revoke_req_set_actor_id (req, actor);
    wyl_revoke_req_set_request_id (req, ensure_request_id_header (msg));
    rc = wyl_perm_revoke (ctx->handle, req);
  }
  if (rc != WYRELOG_E_OK) {
    set_policy_mutation_error (msg, rc);
    return;
  }

  set_json_ok (msg);
}

static void
policy_permission_grant_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  direct_permission_mutation_handler (server, msg, path, query, user_data,
      TRUE);
}

static void
policy_permission_revoke_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  direct_permission_mutation_handler (server, msg, path, query, user_data,
      FALSE);
}

static void
policy_permission_transition_handler (SoupServer *server,
    SoupServerMessage *msg, const char *path, GHashTable *query,
    gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *subject = lookup_required_query_string (query, "subject");
  const gchar *perm = lookup_required_query_string (query, "perm");
  const gchar *scope = lookup_required_query_string (query, "scope");
  const gchar *event = lookup_required_query_string (query, "event");
  if (subject == NULL || perm == NULL || scope == NULL || event == NULL) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return;
  }
  if (!ensure_permission_transition_event (msg, event))
    return;

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.policy.write", scope, "policy_auth_required",
          "invalid_policy_auth", "policy_denied", "policy_auth_failed", &actor))
    return;
  if (!tenant_scope_is_allowed (lookup_request_tenant (query), scope)) {
    set_json_error (msg, 403, WYL_DAEMON_ERR_TENANT_DENIED);
    return;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_policy_transition_error (msg, rc);
    return;
  }

  if (!ensure_policy_permission_exists (msg, write.store, perm))
    return;

  g_autoptr (WylAuditEvent) audit_event = NULL;
  g_autofree gchar *audit_action = NULL;

  audit_event = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (audit_event, actor);
  audit_action = g_strdup_printf ("permission_state.%s", event);
  wyl_audit_event_set_action (audit_event, audit_action);
  wyl_audit_event_set_resource_id (audit_event, perm);
  wyl_audit_event_set_deny_reason (audit_event, event);
  wyl_audit_event_set_deny_origin (audit_event, scope);
  wyl_audit_event_set_request_id (audit_event, ensure_request_id_header (msg));
  wyl_audit_event_set_decision (audit_event, WYL_DECISION_ALLOW);

  rc = wyl_handle_apply_permission_state_transition
      (ctx->handle, subject, perm, scope, event, audit_event, NULL);
  if (rc != WYRELOG_E_OK) {
    set_policy_transition_error (msg, rc);
    return;
  }

  set_json_ok (msg);
}

static void
role_membership_mutation_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data, gboolean grant)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *subject = lookup_required_query_string (query, "subject");
  const gchar *role = lookup_required_query_string (query, "role");
  const gchar *scope = lookup_required_query_string (query, "scope");
  if (subject == NULL || role == NULL || scope == NULL) {
    set_json_error (msg, 400, "invalid_policy_mutation");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.policy.grant_role", scope, "policy_auth_required",
          "invalid_policy_auth", "policy_denied", "policy_auth_failed", &actor))
    return;
  if (!tenant_scope_is_allowed (lookup_request_tenant (query), scope)) {
    set_json_error (msg, 403, WYL_DAEMON_ERR_TENANT_DENIED);
    return;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    set_policy_mutation_error (msg, rc);
    return;
  }

  if (!ensure_policy_role_exists (msg, write.store, role))
    return;

  if (grant) {
    g_autoptr (wyl_role_grant_req_t) req = wyl_role_grant_req_new ();
    wyl_role_grant_req_set_subject_id (req, subject);
    wyl_role_grant_req_set_role_id (req, role);
    wyl_role_grant_req_set_scope (req, scope);
    wyl_role_grant_req_set_actor_id (req, actor);
    wyl_role_grant_req_set_request_id (req, ensure_request_id_header (msg));
    rc = wyl_role_grant (ctx->handle, req);
  } else {
    g_autoptr (wyl_role_revoke_req_t) req = wyl_role_revoke_req_new ();
    wyl_role_revoke_req_set_subject_id (req, subject);
    wyl_role_revoke_req_set_role_id (req, role);
    wyl_role_revoke_req_set_scope (req, scope);
    wyl_role_revoke_req_set_actor_id (req, actor);
    wyl_role_revoke_req_set_request_id (req, ensure_request_id_header (msg));
    rc = wyl_role_revoke (ctx->handle, req);
  }
  if (rc != WYRELOG_E_OK) {
    set_policy_mutation_error (msg, rc);
    return;
  }

  set_json_ok (msg);
}

static void
policy_role_grant_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  role_membership_mutation_handler (server, msg, path, query, user_data, TRUE);
}

static void
policy_role_revoke_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  role_membership_mutation_handler (server, msg, path, query, user_data, FALSE);
}

static gchar *
mfa_enroll_build_otpauth_uri (const gchar *subject, const gchar *secret)
{
  g_autofree gchar *subject_encoded = g_uri_escape_string (subject, NULL,
      FALSE);
  return g_strdup_printf ("otpauth://totp/wyrelog:%s?secret=%s&issuer="
      "wyrelog&algorithm=SHA1&digits=6&period=30", subject_encoded, secret);
}

typedef struct
{
  const gchar *subject;
  gboolean found;
} MfaEnrollSubjectLookup;

static wyrelog_error_t
mfa_enroll_find_subject (const gchar *subject, const gchar *role,
    const gchar *scope, gpointer user_data)
{
  (void) role;
  (void) scope;
  MfaEnrollSubjectLookup *lookup = user_data;
  if (g_strcmp0 (subject, lookup->subject) == 0)
    lookup->found = TRUE;
  return WYRELOG_E_OK;
}

static gboolean
mfa_enroll_authorize (SoupServer *server, SoupServerMessage *msg,
    GHashTable *query, WylDaemonHttpContext *ctx,
    WylDaemonAuthContext *out_auth)
{
  const gchar *bearer = lookup_bearer_token (msg);
  if (bearer == NULL || bearer[0] == '\0' ||
      (query != NULL && g_hash_table_contains (query, "session_token"))) {
    set_json_error (msg, 401, "mfa_enroll_auth_required");
    return FALSE;
  }
  g_autofree gchar *actor = NULL;
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.policy.write", WYL_TENANT_DEFAULT, "mfa_enroll_auth_required",
          "invalid_mfa_enroll_request", "mfa_enroll_denied",
          "mfa_enroll_failed", &actor))
    return FALSE;
  const gchar *tenant_error = NULL;
  if (resolve_bearer_session (server, ctx, bearer, out_auth,
          &tenant_error) != WYRELOG_E_OK ||
      g_strcmp0 (actor, out_auth->actor) != 0) {
    set_json_error (msg, 401, "mfa_enroll_auth_required");
    return FALSE;
  }
  return TRUE;
}

static gboolean
mfa_enroll_subject_exists (wyl_policy_store_t *store, const gchar *subject)
{
  gboolean found = FALSE;
  g_autofree gchar *state = NULL;
  if (subject == NULL || subject[0] == '\0' || strlen (subject) > 256)
    return FALSE;
  if (wyl_policy_store_get_principal_state (store, subject, &state,
          &found) != WYRELOG_E_OK)
    return FALSE;
  if (found)
    return TRUE;
  MfaEnrollSubjectLookup lookup = {.subject = subject };
  return wyl_policy_store_foreach_role_membership (store,
      mfa_enroll_find_subject, &lookup) == WYRELOG_E_OK && lookup.found;
}

static gboolean
mfa_enroll_request_body_dup (SoupServerMessage *msg, gsize max_len,
    gchar **out_body)
{
  *out_body = NULL;
  SoupMessageBody *body = soup_server_message_get_request_body (msg);
  if (body == NULL || body->length <= 0 || body->data == NULL ||
      (gsize) body->length > max_len)
    return FALSE;
  *out_body = g_strndup (body->data, (gsize) body->length);
  return *out_body != NULL;
}

static const gchar *
mfa_enroll_skip_spaces (const gchar *cursor)
{
  while (cursor != NULL && g_ascii_isspace (*cursor))
    cursor++;
  return cursor;
}

static gboolean
mfa_enroll_parse_json_string (const gchar **cursor, gchar **out)
{
  const gchar *p = mfa_enroll_skip_spaces (*cursor);
  if (*p++ != '"')
    return FALSE;
  g_autoptr (GString) value = g_string_new (NULL);
  while (*p != '\0' && *p != '"') {
    if ((guchar) * p < 0x20)
      return FALSE;
    if (*p == '\\') {
      p++;
      if (*p != '"' && *p != '\\' && *p != '/')
        return FALSE;
    }
    g_string_append_c (value, *p++);
  }
  if (*p++ != '"')
    return FALSE;
  *cursor = p;
  *out = g_string_free (g_steal_pointer (&value), FALSE);
  return TRUE;
}

static gboolean
mfa_enroll_parse_json_object (const gchar *json, const gchar **names,
    gchar **values, gsize n_members)
{
  for (gsize i = 0; i < n_members; i++)
    values[i] = NULL;
  const gchar *p = mfa_enroll_skip_spaces (json);
  if (*p++ != '{')
    return FALSE;
  for (gsize parsed = 0; parsed < n_members; parsed++) {
    g_autofree gchar *key = NULL;
    g_autoptr (WylSensitiveChar) value = NULL;
    if (!mfa_enroll_parse_json_string (&p, &key))
      goto fail;
    p = mfa_enroll_skip_spaces (p);
    if (*p++ != ':' || !mfa_enroll_parse_json_string (&p, &value))
      goto fail;
    gsize slot = n_members;
    for (gsize i = 0; i < n_members; i++) {
      if (g_strcmp0 (key, names[i]) == 0) {
        slot = i;
        break;
      }
    }
    if (slot == n_members || values[slot] != NULL)
      goto fail;
    values[slot] = g_steal_pointer (&value);
    p = mfa_enroll_skip_spaces (p);
    if (parsed + 1 < n_members) {
      if (*p++ != ',')
        goto fail;
    } else if (*p++ != '}') {
      goto fail;
    }
  }
  if (*mfa_enroll_skip_spaces (p) == '\0')
    return TRUE;

fail:
  for (gsize i = 0; i < n_members; i++) {
    wyl_sensitive_string_free (values[i]);
    values[i] = NULL;
  }
  return FALSE;
}

#ifdef WYL_HAS_FACT_STORE
static const gchar *skip_ascii_spaces (const gchar * p);
static gboolean request_body_dup (SoupServerMessage * msg, gsize max_len,
    gchar ** out_body);

typedef struct
{
  gchar *request_id;
  gchar *operation;
  gchar *subject;
  gchar *tenant;
  gchar *old_credential_id;
} WylServiceCredentialOperationReconcileRequest;

static void
    service_credential_operation_reconcile_request_clear
    (WylServiceCredentialOperationReconcileRequest * request)
{
  if (request == NULL)
    return;
  g_free (request->request_id);
  g_free (request->operation);
  g_free (request->subject);
  g_free (request->tenant);
  g_free (request->old_credential_id);
  memset (request, 0, sizeof (*request));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylServiceCredentialOperationReconcileRequest,
    service_credential_operation_reconcile_request_clear);

static gboolean
    service_credential_operation_reconcile_request_id_is_canonical
    (const gchar * value)
{
  if (value == NULL || strlen (value) != WYL_REQUEST_ID_STRING_LEN)
    return FALSE;
  for (gsize i = 0; i < WYL_REQUEST_ID_STRING_LEN; i++) {
    if (!g_ascii_isalnum (value[i]))
      return FALSE;
  }
  return TRUE;
}

static gboolean
    service_credential_operation_reconcile_parse_json_string
    (const gchar ** cursor, gchar ** out)
{
  const gchar *p = skip_ascii_spaces (*cursor);
  if (*p++ != '"')
    return FALSE;
  g_autoptr (GString) value = g_string_new (NULL);
  while (*p != '\0' && *p != '"') {
    if ((guchar) * p < 0x20)
      return FALSE;
    if (*p == '\\') {
      p++;
      switch (*p) {
        case '"':
        case '\\':
        case '/':
          g_string_append_c (value, *p++);
          break;
        case 'n':
          g_string_append_c (value, '\n');
          p++;
          break;
        case 'r':
          g_string_append_c (value, '\r');
          p++;
          break;
        case 't':
          g_string_append_c (value, '\t');
          p++;
          break;
        default:
          return FALSE;
      }
      continue;
    }
    g_string_append_c (value, *p++);
  }
  if (*p != '"')
    return FALSE;
  p++;
  *cursor = p;
  *out = g_string_free (g_steal_pointer (&value), FALSE);
  return TRUE;
}

static gboolean
    service_credential_operation_reconcile_parse_json_uint
    (const gchar ** cursor, guint * out)
{
  const gchar *p = skip_ascii_spaces (*cursor);
  if (!g_ascii_isdigit (*p))
    return FALSE;
  errno = 0;
  gchar *end = NULL;
  guint64 parsed = g_ascii_strtoull (p, &end, 10);
  if (errno != 0 || end == p || parsed > G_MAXUINT)
    return FALSE;
  *cursor = end;
  *out = (guint) parsed;
  return TRUE;
}

static gboolean
    service_credential_operation_reconcile_parse_target_issue
    (const gchar ** cursor, gchar ** out_subject, gchar ** out_tenant)
{
  g_autofree gchar *key = NULL;
  if (!service_credential_operation_reconcile_parse_json_string (cursor, &key)
      || g_strcmp0 (key, "subject") != 0)
    return FALSE;
  const gchar *p = skip_ascii_spaces (*cursor);
  if (*p++ != ':')
    return FALSE;
  *cursor = p;
  if (!service_credential_operation_reconcile_parse_json_string (cursor,
          out_subject))
    return FALSE;
  p = skip_ascii_spaces (*cursor);
  if (*p++ != ',')
    return FALSE;
  *cursor = p;
  g_clear_pointer (&key, g_free);
  if (!service_credential_operation_reconcile_parse_json_string (cursor, &key)
      || g_strcmp0 (key, "tenant") != 0)
    return FALSE;
  p = skip_ascii_spaces (*cursor);
  if (*p++ != ':')
    return FALSE;
  *cursor = p;
  return service_credential_operation_reconcile_parse_json_string (cursor,
      out_tenant);
}

static gboolean
    service_credential_operation_reconcile_parse_target_rotate
    (const gchar ** cursor, gchar ** out_old_credential_id)
{
  g_autofree gchar *key = NULL;
  if (!service_credential_operation_reconcile_parse_json_string (cursor, &key)
      || g_strcmp0 (key, "old_credential_id") != 0)
    return FALSE;
  const gchar *p = skip_ascii_spaces (*cursor);
  if (*p++ != ':')
    return FALSE;
  *cursor = p;
  return service_credential_operation_reconcile_parse_json_string (cursor,
      out_old_credential_id);
}

static gboolean
    service_credential_operation_reconcile_parse_request
    (const gchar * json, WylServiceCredentialOperationReconcileRequest * out)
{
  if (json == NULL || out == NULL)
    return FALSE;
  service_credential_operation_reconcile_request_clear (out);

  const gchar *p = skip_ascii_spaces (json);
  if (*p++ != '{')
    return FALSE;

  g_autofree gchar *key = NULL;
  g_autofree gchar *operation = NULL;
  guint version = 0;

  if (!service_credential_operation_reconcile_parse_json_string (&p, &key)
      || g_strcmp0 (key, "version") != 0)
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ':')
    return FALSE;
  if (!service_credential_operation_reconcile_parse_json_uint (&p, &version)
      || version != 1)
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ',')
    return FALSE;

  g_clear_pointer (&key, g_free);
  if (!service_credential_operation_reconcile_parse_json_string (&p, &key)
      || g_strcmp0 (key, "request_id") != 0)
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ':')
    return FALSE;
  if (!service_credential_operation_reconcile_parse_json_string (&p,
          &out->request_id) ||
      !service_credential_operation_reconcile_request_id_is_canonical
      (out->request_id))
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ',')
    return FALSE;

  g_clear_pointer (&key, g_free);
  if (!service_credential_operation_reconcile_parse_json_string (&p, &key)
      || g_strcmp0 (key, "operation") != 0)
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ':')
    return FALSE;
  if (!service_credential_operation_reconcile_parse_json_string (&p,
          &operation))
    return FALSE;
  if (g_strcmp0 (operation, "issue") != 0 &&
      g_strcmp0 (operation, "rotate") != 0)
    return FALSE;
  out->operation = g_steal_pointer (&operation);
  p = skip_ascii_spaces (p);
  if (*p++ != ',')
    return FALSE;

  g_clear_pointer (&key, g_free);
  if (!service_credential_operation_reconcile_parse_json_string (&p, &key)
      || g_strcmp0 (key, "target") != 0)
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != ':')
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != '{')
    return FALSE;

  if (g_strcmp0 (out->operation, "issue") == 0) {
    if (!service_credential_operation_reconcile_parse_target_issue (&p,
            &out->subject, &out->tenant))
      return FALSE;
    if (out->subject == NULL || out->subject[0] == '\0' ||
        out->tenant == NULL || out->tenant[0] == '\0' ||
        !wyl_policy_service_subject_is_valid (out->subject,
            strlen (out->subject)) ||
        !wyl_policy_store_tenant_id_is_valid (out->tenant))
      return FALSE;
  } else {
    if (!service_credential_operation_reconcile_parse_target_rotate (&p,
            &out->old_credential_id))
      return FALSE;
    if (out->old_credential_id == NULL || out->old_credential_id[0] == '\0' ||
        !wyl_service_credential_id_is_canonical (out->old_credential_id,
            strlen (out->old_credential_id)))
      return FALSE;
  }

  p = skip_ascii_spaces (p);
  if (*p++ != '}')
    return FALSE;
  p = skip_ascii_spaces (p);
  if (*p++ != '}')
    return FALSE;
  if (*skip_ascii_spaces (p) != '\0')
    return FALSE;
  return TRUE;
}

static const gchar *service_credential_operation_reconcile_result_state_string
    (WylServiceCredentialFenceResultState state)
{
  switch (state) {
    case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED:
      return "committed";
    case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_NOT_COMMITTED_TERMINAL:
      return "not_committed_terminal";
    case WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT:
      return "conflict";
    default:
      return "failed";
  }
}

static gchar *service_credential_operation_reconcile_build_response
    (const WylServiceCredentialOperationReconcileRequest * request,
    const WylServiceCredentialFenceResult * result)
{
  g_autoptr (GString) body = g_string_new ("{\"version\":1,\"request_id\":");
  append_json_string (body, request->request_id);
  g_string_append (body, ",\"operation\":");
  append_json_string (body, request->operation);
  g_string_append (body, ",\"target\":{");
  if (g_strcmp0 (request->operation, "issue") == 0) {
    g_string_append (body, "\"subject\":");
    append_json_string (body, request->subject);
    g_string_append (body, ",\"tenant\":");
    append_json_string (body, request->tenant);
  } else {
    g_string_append (body, "\"old_credential_id\":");
    append_json_string (body, request->old_credential_id);
  }
  g_string_append (body, "},\"status\":");
  append_json_string (body,
      service_credential_operation_reconcile_result_state_string
      (result->state));
  if (result->state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_COMMITTED) {
    g_string_append (body, ",\"credential_id\":");
    append_json_string (body, result->successor_credential_id);
    g_string_append_printf (body, ",\"generation\":%" G_GUINT64_FORMAT,
        result->successor_generation);
  }
  g_string_append_c (body, '}');
  return g_string_free (g_steal_pointer (&body), FALSE);
}

static gboolean
service_credential_operation_reconcile_execute (SoupServer *server,
    SoupServerMessage *msg, GHashTable *query, WylDaemonHttpContext *ctx)
{
  if (ctx->profile != WYL_DAEMON_PROFILE_SYSTEM) {
    set_json_error (msg, 403,
        WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_DENIED);
    return FALSE;
  }
  if (!authorize_guarded_session_action (server, msg, query, ctx,
          "wr.service_credential.manage", NULL,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_AUTH_REQUIRED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_INVALID,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_DENIED,
          WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED, NULL))
    return FALSE;

  g_autofree gchar *body = NULL;
  if (!request_body_dup (msg, 4096, &body)) {
    set_json_error (msg, 400,
        WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_INVALID);
    return FALSE;
  }

  g_auto (WylServiceCredentialOperationReconcileRequest) request = { 0 };
  if (!service_credential_operation_reconcile_parse_request (body, &request)) {
    set_json_error (msg, 400,
        WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_INVALID);
    return FALSE;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    guint status = (rc == WYRELOG_E_BUSY) ? 503 : 500;
    set_json_error (msg, status, (rc == WYRELOG_E_BUSY)
        ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  g_autoptr (WylServiceAuthorityTransaction) txn = NULL;
  rc = wyl_policy_store_service_authority_transaction_begin (write.store,
      ctx->handle, write.lease, &txn);
  if (rc != WYRELOG_E_OK) {
    guint status = (rc == WYRELOG_E_BUSY) ? 503 : 500;
    set_json_error (msg, status, (rc == WYRELOG_E_BUSY)
        ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  g_autoptr (WylServiceAuthorityCommitEvidence) evidence = NULL;
  rc = wyl_policy_store_service_authority_prepare_commit_evidence (txn,
      write.store, &evidence);
  if (rc != WYRELOG_E_OK) {
    guint status = (rc == WYRELOG_E_BUSY) ? 503 : 500;
    set_json_error (msg, status, (rc == WYRELOG_E_BUSY)
        ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  WylServiceCredentialFenceResult fence = { 0 };
  WylServiceCredentialFenceOperation operation =
      g_strcmp0 (request.operation, "issue") == 0 ?
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ISSUE :
      WYL_SERVICE_CREDENTIAL_FENCE_OP_ROTATE;
  rc = wyl_policy_store_reconcile_service_credential_operation_fence (txn,
      write.store, NULL, operation, request.request_id, request.subject,
      request.tenant, request.old_credential_id, &fence);
  if (rc != WYRELOG_E_OK) {
    guint status = (rc == WYRELOG_E_BUSY) ? 503 : 500;
    set_json_error (msg, status, (rc == WYRELOG_E_BUSY)
        ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  rc = wyl_policy_store_service_authority_transaction_commit (txn);
  if (rc != WYRELOG_E_OK) {
    guint status = (rc == WYRELOG_E_BUSY) ? 503 : 500;
    set_json_error (msg, status, (rc == WYRELOG_E_BUSY)
        ? WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_UNAVAILABLE
        : WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  if (fence.state == WYL_SERVICE_CREDENTIAL_FENCE_RESULT_CONFLICT) {
    set_json_error (msg, 409, WYL_DAEMON_ERR_OPERATION_REQUEST_CONFLICT);
    return TRUE;
  }

  g_autofree gchar *response =
      service_credential_operation_reconcile_build_response (&request, &fence);
  if (response == NULL) {
    set_json_error (msg, 500,
        WYL_DAEMON_ERR_SERVICE_CREDENTIAL_OPERATION_RECONCILE_FAILED);
    return FALSE;
  }

  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, response, strlen (response));
  return TRUE;
}

static void
service_credential_operation_reconcile_handler (SoupServer *server,
    SoupServerMessage *msg, const char *path, GHashTable *query,
    gpointer user_data)
{
  (void) path;
  WylDaemonHttpContext *ctx = user_data;
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  (void) service_credential_operation_reconcile_execute (server, msg, query,
      ctx);
}
#endif /* WYL_HAS_FACT_STORE */

static void
mfa_enroll_start_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;
  WylDaemonHttpContext *ctx = user_data;
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  g_auto (WylDaemonAuthContext) auth = { 0 };
  if (!mfa_enroll_authorize (server, msg, query, ctx, &auth))
    return;
  g_autofree gchar *body = NULL;
  if (!mfa_enroll_request_body_dup (msg, 4096, &body)) {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }
  const gchar *member_names[] = { "subject" };
  gchar *member_values[1] = { NULL };
  if (!mfa_enroll_parse_json_object (body, member_names, member_values, 1)) {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }
  g_autofree gchar *subject = member_values[0];
  if (subject[0] == '\0') {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }
  if (!mfa_enroll_subject_exists (wyl_handle_get_policy_store (ctx->handle),
          subject)) {
    set_json_error (msg, 404, "mfa_enroll_subject_not_found");
    return;
  }

  WylMfaEnrollChallenge *challenge = g_new0 (WylMfaEnrollChallenge, 1);
  if (new_token_id_string (&challenge->challenge) != WYRELOG_E_OK ||
      wyl_totp_generate_seed (challenge->secret, sizeof challenge->secret,
          NULL) != WYRELOG_E_OK) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, 500, "mfa_enroll_failed");
    return;
  }
  challenge->session_id = g_strdup (auth.session_id);
  challenge->actor = g_strdup (auth.actor);
  challenge->subject = g_strdup (subject);
  challenge->expires_at_monotonic_us = g_get_monotonic_time () +
      WYL_DAEMON_MFA_ENROLL_TTL_SECONDS * G_USEC_PER_SEC;
  g_autoptr (WylSensitiveChar) base32 = NULL;
  if (wyl_totp_base32_encode (challenge->secret, sizeof challenge->secret,
          &base32, NULL) != WYRELOG_E_OK) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, 500, "mfa_enroll_failed");
    return;
  }
  g_autoptr (WylSensitiveChar) uri = mfa_enroll_build_otpauth_uri (subject,
      base32);
  g_autofree gchar *challenge_id = g_strdup (challenge->challenge);
  g_mutex_lock (&ctx->lock);
  WylMfaChallengePrune prune = {
    .actor = auth.actor,
    .session_id = auth.session_id,
    .now_monotonic_us = g_get_monotonic_time (),
  };
  g_hash_table_foreach_remove (ctx->mfa_enroll_challenges,
      wyl_mfa_enroll_challenge_should_remove, &prune);
  g_hash_table_replace (ctx->mfa_enroll_challenges,
      g_strdup (challenge->challenge), challenge);
  g_mutex_unlock (&ctx->lock);

  g_autoptr (GString) response = g_string_new ("{\"challenge\":");
  append_json_string (response, challenge_id);
  g_string_append (response, ",\"otpauth_uri\":");
  append_json_string (response, uri);
  g_string_append (response, ",\"secret_base32\":");
  append_json_string (response, base32);
  g_string_append_c (response, '}');
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      response->str, response->len);
  sodium_memzero (response->str, response->len);
}

static void
mfa_enroll_confirm_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;
  WylDaemonHttpContext *ctx = user_data;
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }
  g_auto (WylDaemonAuthContext) auth = { 0 };
  if (!mfa_enroll_authorize (server, msg, query, ctx, &auth))
    return;
  g_autoptr (WylSensitiveChar) body = NULL;
  if (!mfa_enroll_request_body_dup (msg, 4096, &body)) {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }
  const gchar *member_names[] = { "challenge", "code" };
  gchar *member_values[2] = { NULL, NULL };
  if (!mfa_enroll_parse_json_object (body, member_names, member_values, 2)) {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }
  g_autofree gchar *challenge_id = member_values[0];
  g_autoptr (WylSensitiveChar) code_text = member_values[1];
  if (strlen (challenge_id) > 128 || !mfa_code_is_well_formed (code_text)) {
    set_json_error (msg, 400, "invalid_mfa_enroll_request");
    return;
  }

  gpointer stolen_key = NULL;
  WylMfaEnrollChallenge *challenge = NULL;
  gboolean challenge_authorized = FALSE;
  g_mutex_lock (&ctx->lock);
  challenge = g_hash_table_lookup (ctx->mfa_enroll_challenges, challenge_id);
  if (challenge != NULL && challenge->expires_at_monotonic_us <=
      g_get_monotonic_time ()) {
    g_hash_table_remove (ctx->mfa_enroll_challenges, challenge_id);
    challenge = NULL;
  } else if (challenge != NULL &&
      g_strcmp0 (challenge->session_id, auth.session_id) == 0 &&
      g_strcmp0 (challenge->actor, auth.actor) == 0) {
    challenge_authorized = TRUE;
    g_hash_table_steal_extended (ctx->mfa_enroll_challenges, challenge_id,
        &stolen_key, (gpointer *) & challenge);
  }
  g_mutex_unlock (&ctx->lock);
  g_free (stolen_key);
  if (!challenge_authorized) {
    set_json_error (msg, 401, "invalid_mfa_enroll_challenge");
    return;
  }
  guint code = (guint) g_ascii_strtoull (code_text, NULL, 10);
  guint64 matched_step = 0;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  if (!wyl_totp_code_matches (challenge->secret, sizeof challenge->secret,
          now, code, &matched_step, NULL)) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, 401, "invalid_mfa_enroll_code");
    return;
  }

  g_auto (WylDaemonPolicyWrite) write = { 0 };
  wyrelog_error_t rc = wyl_daemon_policy_write_acquire (ctx, &write);
  if (rc != WYRELOG_E_OK) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, 500, "mfa_enroll_failed");
    return;
  }
  if (!mfa_enroll_subject_exists (write.store, challenge->subject)) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, 404, "mfa_enroll_subject_not_found");
    return;
  }
  WylTotpEnrollment existing = { 0 };
  gboolean already_enrolled = FALSE;
  rc = wyl_policy_store_totp_enrollment_lookup
      (write.store, challenge->subject, &existing, &already_enrolled);
  wyl_totp_enrollment_clear (&existing);
  if (rc != WYRELOG_E_OK || already_enrolled) {
    wyl_mfa_enroll_challenge_free (challenge);
    set_json_error (msg, already_enrolled ? 409 : 500,
        already_enrolled ? "mfa_already_enrolled" : "mfa_enroll_failed");
    return;
  }
  WylTotpEnrollment enrollment = { 0 };
  enrollment.subject_id = g_strdup (challenge->subject);
  memcpy (enrollment.secret, challenge->secret, sizeof enrollment.secret);
  enrollment.last_verified_step = (gint64) matched_step;
  enrollment.enrolled_at = now;
  rc = wyl_mfa_enrollment_commit
      (write.store, &enrollment, auth.actor,
      ensure_request_id_header (msg), "wyrelogd", FALSE);
  if (rc == WYRELOG_E_OK)
    rc = wyl_handle_reload_engine_pair (ctx->handle);
#ifdef WYL_HAS_AUDIT
  if (rc == WYRELOG_E_OK)
    rc = wyl_handle_load_policy_store_audit_events (ctx->handle);
#endif
  wyl_totp_enrollment_clear (&enrollment);
  wyl_mfa_enroll_challenge_free (challenge);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, rc == WYRELOG_E_POLICY ? 404 : 500,
        rc == WYRELOG_E_POLICY ? "mfa_enroll_subject_not_found" :
        "mfa_enroll_failed");
    return;
  }
  set_json_ok (msg);
}

static void
login_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *username = NULL;
  const gchar *tenant = WYL_TENANT_DEFAULT;
  const gchar *skip_mfa = NULL;
  const gchar *password = NULL;
  WylDaemonHttpContext *ctx = user_data;
  if (query != NULL) {
    username = g_hash_table_lookup (query, "username");
    if (g_hash_table_contains (query, "tenant"))
      tenant = g_hash_table_lookup (query, "tenant");
    skip_mfa = g_hash_table_lookup (query, "skip_mfa");
    password = g_hash_table_lookup (query, "password");
  }
  if (username == NULL || username[0] == '\0') {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }
  if (tenant == NULL || tenant[0] == '\0' || !tenant_is_active (ctx, tenant)) {
    set_json_error (msg, 400, tenant_is_known (ctx, tenant) ?
        WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID);
    return;
  }
  if (password != NULL) {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }
  gboolean skip_mfa_requested = FALSE;
  if (skip_mfa != NULL) {
    if (g_strcmp0 (skip_mfa, "true") == 0 || g_strcmp0 (skip_mfa, "1") == 0)
      skip_mfa_requested = TRUE;
    else if (g_strcmp0 (skip_mfa, "false") != 0
        && g_strcmp0 (skip_mfa, "0") != 0) {
      set_json_error (msg, 400, "invalid_login_request");
      return;
    }
  }
  WylHandle *handle = ctx->handle;
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);
  wyl_login_req_set_tenant (login, tenant);
  wyl_login_req_set_skip_mfa (login, skip_mfa_requested);
  wyl_login_req_set_request_id (login, ensure_request_id_header (msg));

  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    set_json_error (msg, 403, "login_denied");
    return;
  }
  if (rc != WYRELOG_E_OK || session == NULL) {
    set_json_error (msg, 500, "login_failed");
    return;
  }

  g_autofree gchar *session_token = wyl_session_dup_id_string (session);
  g_autofree gchar *session_tenant = wyl_session_dup_tenant (session);
  if (session_token == NULL) {
    set_json_error (msg, 500, "login_failed");
    return;
  }
  if (session_tenant == NULL || session_tenant[0] == '\0') {
    set_json_error (msg, 500, "login_failed");
    return;
  }
  const gchar *principal_state =
      skip_mfa_requested ? "authenticated" : "mfa_required";
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *refresh_token = NULL;
  if (skip_mfa_requested) {
    rc = issue_login_access_token (ctx, session_token, session, username,
        session_tenant, principal_state, &access_token);
    if (rc == WYRELOG_E_OK)
      rc = issue_refresh_token (ctx, session, session_token, username,
          session_tenant, &refresh_token);
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "login_failed");
      return;
    }
  }

  if (!wyl_daemon_http_context_store_session (ctx, session_token, session)) {
    set_json_error (msg, 500, "login_failed");
    return;
  }

  g_autofree gchar *body = build_login_json (session_token, username,
      session_tenant, principal_state, access_token, refresh_token);
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

/*
 * Exactly six ASCII digits 0-9.  Returns FALSE for NULL, any other
 * length, any non-digit byte, leading sign, or whitespace.  The
 * validator (commit 3) re-checks this with strnlen for defense in
 * depth; this is the HTTP-layer's first-line shape gate so the
 * route can emit invalid_mfa_request without ever touching the
 * policy store or the session registry.
 */
static gboolean
mfa_code_is_well_formed (const gchar *code)
{
  if (code == NULL)
    return FALSE;
  for (gsize i = 0; i < 6; i++) {
    if (code[i] < '0' || code[i] > '9')
      return FALSE;
  }
  return code[6] == '\0';
}

/*
 * Look up the current principal_state for |subject_id| in the
 * handle-owned policy store.  Returns NULL when the subject has no
 * principal_state row (a fail-closed signal: the caller may not
 * proceed without an explicit row).  Caller frees the returned string
 * with g_free / g_autofree.
 *
 * Issue #331 commit 5: migrated off the historical foreach-based two-
 * step lookup (which iterated the entire principal_states table) onto
 * the single-row accessor wyl_policy_store_get_principal_state.  The
 * accessor distinguishes "no row" (out_found=FALSE, returns OK) from
 * "iteration error" (returns non-OK) via the explicit |out_found|
 * boolean, so we surface the same NULL-on-miss-or-fault semantics to
 * the caller without ambiguity.
 */
static gchar *
mfa_lookup_principal_state (WylHandle *handle, const gchar *subject_id)
{
  if (handle == NULL || subject_id == NULL || subject_id[0] == '\0')
    return NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return NULL;
  gchar *state = NULL;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_state (store, subject_id, &state,
          &found) != WYRELOG_E_OK) {
    g_clear_pointer (&state, g_free);
    return NULL;
  }
  if (!found) {
    /* Defensive: get_principal_state already wrote NULL on miss, but
     * the contract is "NULL on no-row" and we want a single belt-and-
     * braces clear here too. */
    g_clear_pointer (&state, g_free);
    return NULL;
  }
  return state;
}

static void
mfa_verify_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  const gchar *session_token = NULL;
  const gchar *code = NULL;
  if (query != NULL) {
    session_token = g_hash_table_lookup (query, "session_token");
    code = g_hash_table_lookup (query, "code");
  }

  /*
   * F5 (enumeration): a missing or empty session_token funnels into
   * the same uniform mfa_auth_required surface that any non-resolving
   * token uses below.  An unauthenticated probe must not be able to
   * distinguish "no token" from "wrong token" from "stale token".
   */
  if (session_token == NULL || session_token[0] == '\0') {
    set_json_error (msg, 401, "mfa_auth_required");
    return;
  }

  /*
   * F2 (secret echo): the code is shape-validated before any policy
   * store work, and never logged, audited, or echoed in the response
   * body.  set_json_error emits only the error code.
   */
  if (!mfa_code_is_well_formed (code)) {
    set_json_error (msg, 400, "invalid_mfa_request");
    return;
  }

  g_autoptr (WylSession) session =
      wyl_daemon_http_ref_session (server, session_token);
  if (session == NULL) {
    set_json_error (msg, 401, "mfa_auth_required");
    return;
  }

  g_autofree gchar *username = wyl_session_dup_username (session);
  g_autofree gchar *session_tenant = wyl_session_dup_tenant (session);
  if (username == NULL || username[0] == '\0' || session_tenant == NULL ||
      session_tenant[0] == '\0') {
    set_json_error (msg, 401, "mfa_auth_required");
    return;
  }

  /*
   * Tenant gate.  Mirror /auth/login: if the session's tenant has
   * been sealed (or, defensively, removed) between login and verify,
   * fail closed with the canonical tenant-gate code.
   */
  if (!tenant_is_active (ctx, session_tenant)) {
    set_json_error (msg, 400, tenant_is_known (ctx, session_tenant) ?
        WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID);
    return;
  }

  /*
   * Principal-state gate.  The session's authoritative principal_state
   * lives in the policy store keyed by subject_id.  We require the
   * subject to be in mfa_required to proceed.  Three cases:
   *   - locked   -> 429 mfa_locked (issue #331 spec).
   *   - other    -> 401 mfa_auth_required, uniform (F5).
   *   - mfa_required -> proceed below.
   * Note: this lookup is the only place an unauthenticated probe can
   * influence behaviour via the session_token, and the leak surface is
   * already bounded by the live-session gate above.
   */
  g_autofree gchar *principal_state =
      mfa_lookup_principal_state (ctx->handle, username);
  if (g_strcmp0 (principal_state, "locked") == 0) {
    set_json_error (msg, 429, "mfa_locked");
    return;
  }
  if (g_strcmp0 (principal_state, "mfa_required") != 0) {
    set_json_error (msg, 401, "mfa_auth_required");
    return;
  }

  /*
   * Resolve the validator the daemon installed on this handle.  The
   * route refuses to mint tokens if no validator has been registered
   * - a misconfigured daemon must fail closed rather than fail open.
   */
  gpointer validator_user_data = NULL;
  WylMfaValidator validator =
      wyl_handle_get_mfa_validator (ctx->handle, &validator_user_data);
  if (validator == NULL) {
    set_json_error (msg, 500, "mfa_verify_failed");
    return;
  }

  /*
   * Drive the proof-bearing FSM primitive.  wyl_session_mfa_verify_with_proof
   * binds the verify to THE session's subject (F5 cross-session
   * takeover defense): we never accept a subject query parameter
   * here, and the validator only sees the session-derived username.
   * On success, the FSM is advanced to AUTHENTICATED before we
   * return, mirroring login_handler's order.
   */
  wyrelog_error_t rc = wyl_session_mfa_verify_with_proof (ctx->handle, session,
      code, validator, validator_user_data);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_mfa_request");
    return;
  }
  if (rc == WYRELOG_E_POLICY) {
    /*
     * The validator funnels enrollment-missing, wrong-code, and
     * replay through the same WYRELOG_E_POLICY (commit 3 contract).
     * The HTTP layer differentiates enrollment_required vs
     * mfa_invalid by inspecting the totp_enrollment row separately
     * (issue #331 decision 7).  This is the only place the
     * enrollment-vs-no-enrollment bit is surfaced to the caller.
     */
    wyl_policy_store_t *store = wyl_handle_get_policy_store (ctx->handle);
    if (store == NULL) {
      set_json_error (msg, 500, "mfa_verify_failed");
      return;
    }
    WylTotpEnrollment enr = { 0 };
    gboolean found = FALSE;
    wyrelog_error_t lookup_rc =
        wyl_policy_store_totp_enrollment_lookup (store, username, &enr,
        &found);
    wyl_totp_enrollment_clear (&enr);
    if (lookup_rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "mfa_verify_failed");
      return;
    }
    set_json_error (msg, 401, found ? "mfa_invalid" : "enrollment_required");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "mfa_verify_failed");
    return;
  }

  /*
   * FSM has advanced to AUTHENTICATED.  Mint access + refresh tokens
   * in the same order as login_handler's skip_mfa path so the wire
   * shape is identical between "login with skip_mfa" and "login then
   * verify".  Store the session-token registry row only after both
   * tokens succeed.
   */
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *refresh_token = NULL;
  rc = issue_login_access_token (ctx, session_token, session, username,
      session_tenant, "authenticated", &access_token);
  if (rc == WYRELOG_E_OK)
    rc = issue_refresh_token (ctx, session, session_token, username,
        session_tenant, &refresh_token);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "mfa_verify_failed");
    return;
  }
  if (!wyl_daemon_http_context_store_session (ctx, session_token, session)) {
    set_json_error (msg, 500, "mfa_verify_failed");
    return;
  }

  g_autofree gchar *body = build_login_json (session_token, username,
      session_tenant, "authenticated", access_token, refresh_token);
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static gint64
human_refresh_now_locked (WylDaemonHttpContext *ctx)
{
#ifndef WYL_TEST_DAEMON_HTTP
  (void) ctx;
#endif
#ifdef WYL_TEST_DAEMON_HTTP
  if (ctx->refresh_clock_injected)
    return ctx->refresh_clock_now;
#endif
  return g_get_real_time () / G_USEC_PER_SEC;
}

#ifdef WYL_TEST_DAEMON_HTTP
static gboolean
human_refresh_test_latch_reach (WylDaemonHttpContext *ctx,
    WylDaemonRefreshPhase phase)
{
  WylHumanRefreshTestLatch *latch = &ctx->refresh_latch;
  g_autoptr (GMutexLocker) locker = g_mutex_locker_new (&latch->mutex);
  if (!latch->armed || latch->phase != phase) {
    return TRUE;
  }
  guint64 generation = latch->generation;
  latch->entered = TRUE;
  g_cond_broadcast (&latch->changed);
  gint64 deadline = g_get_monotonic_time () + 10 * G_USEC_PER_SEC;
  while (latch->armed && latch->generation == generation && !latch->released)
    if (!g_cond_wait_until (&latch->changed, &latch->mutex, deadline)) {
      latch->armed = FALSE;
      g_cond_broadcast (&latch->changed);
      return FALSE;
    }
  gboolean released = latch->generation == generation && latch->released;
  return released;
}

static gboolean
human_refresh_test_fault_take (WylDaemonHttpContext *ctx,
    WylDaemonRefreshFault fault)
{
  g_mutex_lock (&ctx->lock);
  gboolean taken = ctx->refresh_fault == fault;
  if (taken)
    ctx->refresh_fault = WYL_DAEMON_REFRESH_FAULT_NONE;
  g_mutex_unlock (&ctx->lock);
  return taken;
}
#endif

static wyrelog_error_t
prepare_human_access_candidate (WylHumanRefreshClaim *claim,
    gint64 issued_at, WylHumanAccessCandidate *candidate)
{
  WylDaemonHttpContext *ctx = claim->ctx;
#ifdef WYL_TEST_DAEMON_HTTP
  if (human_refresh_test_fault_take (ctx,
          WYL_DAEMON_REFRESH_FAULT_ACCESS_PREPARE))
    return WYRELOG_E_INTERNAL;
#endif
  guint8 secret[WYL_DAEMON_JWT_KEY_LEN];
  g_mutex_lock (&ctx->lock);
  gboolean current = ctx->access_token_secret_ready
      && ctx->auth_epoch == claim->auth_epoch
      && ctx->key_epoch == claim->key_epoch
      && g_strcmp0 (ctx->access_token_key_id, claim->key_id) == 0;
  if (current) {
    memcpy (secret, ctx->access_token_secret, sizeof secret);
  }
  g_mutex_unlock (&ctx->lock);
  if (!current)
    return WYRELOG_E_POLICY;

  g_autofree gchar *jti = NULL;
  wyrelog_error_t rc = new_token_id_string (&jti);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (secret, sizeof secret);
    return rc;
  }
#ifdef WYL_TEST_DAEMON_HTTP
  g_atomic_int_inc ((gint *) & ctx->refresh_access_id_successes);
#endif
  if (issued_at > G_MAXINT64 - WYL_JWT_ACCESS_TTL_SECONDS) {
    sodium_memzero (secret, sizeof secret);
    return WYRELOG_E_INVALID;
  }
  wyl_jwt_issue_input_t input = {
    .key_id = claim->key_id,
    .jti = jti,
    .subject = claim->subject,
    .issuer = WYL_DAEMON_JWT_ISSUER,
    .audience = WYL_DAEMON_JWT_AUDIENCE,
    .tenant = claim->tenant,
    .principal_state_at_issue = "authenticated",
    .session_id = claim->session_id,
    .issued_at = issued_at,
    .ttl_seconds = WYL_JWT_ACCESS_TTL_SECONDS,
  };
#ifdef WYL_TEST_DAEMON_HTTP
  g_atomic_int_inc ((gint *) & ctx->refresh_jwt_sign_attempts);
#endif
  rc = wyl_jwt_sign_hs256 (&input, secret, sizeof secret, &candidate->token);
#ifdef WYL_TEST_DAEMON_HTTP
  if (rc == WYRELOG_E_OK)
    g_atomic_int_inc ((gint *) & ctx->refresh_jwt_sign_successes);
#endif
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  candidate->cache_token = g_strdup (candidate->token);
  candidate->map_key = g_strdup (jti);
  candidate->state = g_new0 (WylAccessTokenState, 1);
  candidate->state->jti = g_steal_pointer (&jti);
  candidate->state->session_id = g_strdup (claim->session_id);
  candidate->state->subject = g_strdup (claim->subject);
  candidate->state->tenant = g_strdup (claim->tenant);
  candidate->state->key_id = g_strdup (claim->key_id);
  candidate->state->expires_at = issued_at + WYL_JWT_ACCESS_TTL_SECONDS;
  candidate->state->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
prepare_human_refresh_candidate (WylHumanRefreshClaim *claim,
    gint64 issued_at, WylHumanRefreshCandidate *candidate)
{
#ifdef WYL_TEST_DAEMON_HTTP
  if (human_refresh_test_fault_take (claim->ctx,
          WYL_DAEMON_REFRESH_FAULT_REFRESH_PREPARE))
    return WYRELOG_E_INTERNAL;
#endif
  if (issued_at > G_MAXINT64 - WYL_DAEMON_REFRESH_TTL_SECONDS)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = new_token_id_string (&candidate->token);
  if (rc != WYRELOG_E_OK)
    return rc;
#ifdef WYL_TEST_DAEMON_HTTP
  WylDaemonHttpContext *ctx = claim->ctx;
  g_atomic_int_inc ((gint *) & ctx->refresh_token_id_successes);
  g_mutex_lock (&ctx->lock);
  g_ptr_array_add (ctx->refresh_generated_ids, g_strdup (candidate->token));
  g_mutex_unlock (&ctx->lock);
#endif
  candidate->cache_token = g_strdup (candidate->token);
  candidate->map_key = g_strdup (candidate->token);
  candidate->state = g_new0 (WylRefreshTokenState, 1);
  candidate->state->token = g_strdup (candidate->token);
  candidate->state->session_id = g_strdup (claim->session_id);
  candidate->state->subject = g_strdup (claim->subject);
  candidate->state->tenant = g_strdup (claim->tenant);
  candidate->state->issued_at = issued_at;
  candidate->state->expires_at = issued_at + WYL_DAEMON_REFRESH_TTL_SECONDS;
  candidate->state->auth_method = WYL_SESSION_AUTH_METHOD_HUMAN;
  return WYRELOG_E_OK;
}

static gboolean
human_refresh_candidates_publishable_at (const WylHumanAccessCandidate *access,
    const WylHumanRefreshCandidate *refresh, gint64 committed_at)
{
  return access != NULL && access->state != NULL && access->token != NULL
      && access->map_key != NULL && access->state->jti != NULL
      && refresh != NULL && refresh->state != NULL
      && refresh->token != NULL && refresh->map_key != NULL
      && refresh->state->token != NULL
      && committed_at >= refresh->state->issued_at
      && committed_at < access->state->expires_at
      && committed_at < refresh->state->expires_at;
}

static WylHumanRefreshDecision
human_refresh_classify_locked (WylRefreshTokenState *state,
    gboolean exact_current, guint64 epoch, gint64 now,
    WylHumanRefreshResult **result)
{
  g_assert (result != NULL && *result == NULL);
  if (!exact_current || state == NULL || state->epoch != epoch)
    return WYL_HUMAN_REFRESH_DECISION_DENY;
  if (state->consumed) {
    if (now <= state->consumed_at + WYL_DAEMON_REFRESH_GRACE_SECONDS
        && state->successor != NULL) {
      *result = wyl_human_refresh_result_ref (state->successor);
      return WYL_HUMAN_REFRESH_DECISION_COMMITTED_GRACE;
    }
    return WYL_HUMAN_REFRESH_DECISION_REUSE;
  }
  return !state->rotating ? WYL_HUMAN_REFRESH_DECISION_AVAILABLE
      : WYL_HUMAN_REFRESH_DECISION_DENY;
}

#ifdef WYL_TEST_DAEMON_HTTP
gboolean
wyl_daemon_http_test_human_refresh_classifier (SoupServer *server)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  if (ctx == NULL)
    return FALSE;
  guint refresh_before, access_before;
  gint access_ids = g_atomic_int_get
      ((gint *) & ctx->refresh_access_id_successes);
  gint refresh_ids = g_atomic_int_get
      ((gint *) & ctx->refresh_token_id_successes);
  g_mutex_lock (&ctx->lock);
  refresh_before = g_hash_table_size (ctx->refresh_tokens_by_token);
  access_before = g_hash_table_size (ctx->access_tokens_by_jti);
  g_mutex_unlock (&ctx->lock);

  const guint64 epoch = 7;
  const gint64 now = 1000;
  WylRefreshTokenState state = {
    .epoch = epoch,
    .expires_at = now + 100,
  };
  WylHumanRefreshResult *result = NULL;
  gboolean ok = human_refresh_classify_locked (&state, TRUE, epoch,
      now, &result) == WYL_HUMAN_REFRESH_DECISION_AVAILABLE && result == NULL;
  state.rotating = TRUE;
  if (ok)
    ok = human_refresh_classify_locked (&state, TRUE, epoch, now,
        &result) == WYL_HUMAN_REFRESH_DECISION_DENY && result == NULL;

  state.rotating = FALSE;
  state.consumed = TRUE;
  state.consumed_at = now;
  state.successor = g_new0 (WylHumanRefreshResult, 1);
  state.successor->ref_count = 1;
  state.successor->access_token = g_strdup ("retained-access");
  state.successor->refresh_token = g_strdup ("retained-refresh");
  WylHumanRefreshResult *owner = state.successor;
  if (ok)
    ok = human_refresh_classify_locked (&state, TRUE, epoch, now,
        &result) == WYL_HUMAN_REFRESH_DECISION_COMMITTED_GRACE
        && result == owner && g_atomic_int_get (&owner->ref_count) == 2;
  state.successor = NULL;
  wyl_human_refresh_result_unref (owner);
  if (ok)
    ok = result != NULL
        && g_strcmp0 (result->access_token, "retained-access") == 0
        && g_strcmp0 (result->refresh_token, "retained-refresh") == 0
        && g_atomic_int_get (&result->ref_count) == 1;
  g_clear_pointer (&result, wyl_human_refresh_result_unref);

  if (ok)
    ok = human_refresh_classify_locked (&state, TRUE, epoch,
        now + WYL_DAEMON_REFRESH_GRACE_SECONDS + 1,
        &result) == WYL_HUMAN_REFRESH_DECISION_REUSE && result == NULL;
  state.consumed = FALSE;
  if (ok)
    ok = human_refresh_classify_locked (&state, FALSE, epoch, now,
        &result) == WYL_HUMAN_REFRESH_DECISION_DENY
        && human_refresh_classify_locked (&state, TRUE, epoch + 1, now,
        &result) == WYL_HUMAN_REFRESH_DECISION_DENY;

  WylAccessTokenState access_state = {
    .jti = (gchar *) "access-jti",
    .expires_at = now + 10,
  };
  WylRefreshTokenState refresh_state = {
    .token = (gchar *) "refresh-token",
    .issued_at = now,
    .expires_at = now + 20,
  };
  WylHumanAccessCandidate access_candidate = {
    .token = (gchar *) "access",
    .map_key = (gchar *) "access-jti",
    .state = &access_state,
  };
  WylHumanRefreshCandidate refresh_candidate = {
    .token = (gchar *) "refresh",
    .map_key = (gchar *) "refresh-token",
    .state = &refresh_state,
  };
  if (ok)
    ok = human_refresh_candidates_publishable_at (&access_candidate,
        &refresh_candidate, now + 9);
  access_state.expires_at = now + 9;
  if (ok)
    ok = !human_refresh_candidates_publishable_at (&access_candidate,
        &refresh_candidate, now + 9);
  access_state.expires_at = now + 10;
  refresh_state.expires_at = now + 9;
  if (ok)
    ok = !human_refresh_candidates_publishable_at (&access_candidate,
        &refresh_candidate, now + 9);
  refresh_state.expires_at = now + 20;
  refresh_state.issued_at = now + 10;
  if (ok)
    ok = !human_refresh_candidates_publishable_at (&access_candidate,
        &refresh_candidate, now + 9);

  g_mutex_lock (&ctx->lock);
  ok = ok && refresh_before == g_hash_table_size (ctx->refresh_tokens_by_token)
      && access_before == g_hash_table_size (ctx->access_tokens_by_jti)
      && access_ids == g_atomic_int_get
      ((gint *) & ctx->refresh_access_id_successes)
      && refresh_ids == g_atomic_int_get
      ((gint *) & ctx->refresh_token_id_successes);
  g_mutex_unlock (&ctx->lock);
  guint64 wrapping_counter = G_MAXUINT64;
  ok = ok && human_refresh_next_nonzero (&wrapping_counter) == G_MAXUINT64
      && human_refresh_next_nonzero (&wrapping_counter) == 1
      && wrapping_counter == 2;
  return ok;
}
#endif

static gboolean
human_refresh_dispatch_owned (WylDaemonHttpContext *ctx)
{
  gboolean owned = g_main_context_is_owner (ctx->dispatch_context);
#ifdef WYL_TEST_DAEMON_HTTP
  g_mutex_lock (&ctx->lock);
  if (owned)
    ctx->refresh_dispatch_owned++;
  else
    ctx->refresh_dispatch_wrong++;
  g_mutex_unlock (&ctx->lock);
#endif
  return owned;
}

static void
refresh_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) path;
  WylDaemonHttpContext *ctx = user_data;
  gboolean dispatch_owned = human_refresh_dispatch_owned (ctx);
#ifdef WYL_TEST_DAEMON_HTTP
  g_mutex_lock (&ctx->lock);
  ctx->refresh_handler_entries++;
  g_mutex_unlock (&ctx->lock);
#endif
  if (!dispatch_owned) {
    set_json_error (msg, 503, "server_unavailable");
    return;
  }
  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *refresh_token = query != NULL
      ? g_hash_table_lookup (query, "refresh_token") : NULL;
  if (refresh_token == NULL || refresh_token[0] == '\0') {
    set_json_error (msg, 400, "invalid_refresh_request");
    return;
  }

  g_autofree gchar *session_id = NULL;
  g_autofree gchar *subject = NULL;
  g_autofree gchar *tenant = NULL;
  g_autofree gchar *key_id = NULL;
  guint64 predecessor_epoch = 0, auth_epoch = 0, key_epoch = 0;
  g_mutex_lock (&ctx->lock);
  gint64 observed_at = human_refresh_now_locked (ctx);
  WylRefreshTokenState *state = g_hash_table_lookup
      (ctx->refresh_tokens_by_token, refresh_token);
  if (ctx->shutting_down || state == NULL || state->revoked
      || observed_at >= state->expires_at
      || state->auth_method != WYL_SESSION_AUTH_METHOD_HUMAN
      || wyl_policy_subject_has_service_prefix (state->subject)) {
    g_mutex_unlock (&ctx->lock);
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }
  session_id = g_strdup (state->session_id);
  subject = g_strdup (state->subject);
  tenant = g_strdup (state->tenant);
  key_id = g_strdup (ctx->access_token_key_id);
  predecessor_epoch = state->epoch;
  auth_epoch = ctx->auth_epoch;
  key_epoch = ctx->key_epoch;
  g_mutex_unlock (&ctx->lock);

  g_autoptr (WylSession) session = wyl_daemon_http_ref_session (server,
      session_id);
  if (!human_session_matches (ctx, session, session_id, subject, tenant)) {
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }

  g_autoptr (WylHumanRefreshResult) replay = NULL;
  gboolean reuse = FALSE;
  gboolean claimed = FALSE;
  WylHumanRefreshClaim claim = {
    .ctx = ctx,
    .session = session,
    .predecessor = refresh_token,
    .session_id = session_id,
    .subject = subject,
    .tenant = tenant,
    .key_id = key_id,
    .predecessor_epoch = predecessor_epoch,
    .auth_epoch = auth_epoch,
    .key_epoch = key_epoch,
  };
#ifdef WYL_TEST_DAEMON_HTTP
  if (!human_refresh_test_latch_reach (ctx, WYL_DAEMON_REFRESH_BEFORE_CLAIM)) {
    set_json_error (msg, 500, "refresh_failed");
    return;
  }
#endif
  g_mutex_lock (&ctx->lock);
  gint64 claim_at = human_refresh_now_locked (ctx);
  state = g_hash_table_lookup (ctx->refresh_tokens_by_token, refresh_token);
  gboolean exact_current = state != NULL && state->epoch == predecessor_epoch
      && !state->revoked && !ctx->shutting_down
      && claim_at < state->expires_at
      && state->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN
      && g_strcmp0 (state->session_id, session_id) == 0
      && g_strcmp0 (state->subject, subject) == 0
      && g_strcmp0 (state->tenant, tenant) == 0
      && ctx->auth_epoch == auth_epoch && ctx->key_epoch == key_epoch
      && g_strcmp0 (ctx->access_token_key_id, key_id) == 0
      && g_hash_table_lookup (ctx->sessions_by_token, session_id) == session
      && !g_hash_table_contains (ctx->revoked_session_tokens, session_id);
  WylHumanRefreshDecision decision = human_refresh_classify_locked (state,
      exact_current, predecessor_epoch, claim_at, &replay);
  if (decision == WYL_HUMAN_REFRESH_DECISION_AVAILABLE) {
    claim.claim_epoch = human_refresh_next_nonzero (&ctx->next_refresh_claim);
    state->rotating = TRUE;
    state->rotation_claim = claim.claim_epoch;
    claim.predecessor_state = state;
    claimed = TRUE;
  } else if (decision == WYL_HUMAN_REFRESH_DECISION_REUSE) {
    state->revoked = TRUE;
    reuse = TRUE;
  }
  g_mutex_unlock (&ctx->lock);

  if (reuse) {
    wyl_daemon_http_context_revoke_session_access_tokens (ctx, session_id);
    wyl_daemon_http_context_revoke_session_refresh_tokens (ctx, session_id);
    set_json_error (msg, 401, "refresh_reuse_detected");
    return;
  }
  if (replay != NULL) {
    g_autofree gchar *body = build_login_json (session_id, subject, tenant,
        "authenticated", replay->access_token, replay->refresh_token);
    attach_request_id_header (msg);
    soup_server_message_set_status (msg, 200, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, body, strlen (body));
    return;
  }
  if (!claimed) {
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }
#ifdef WYL_TEST_DAEMON_HTTP
  gboolean test_latch_ok = human_refresh_test_latch_reach (ctx,
      WYL_DAEMON_REFRESH_AFTER_CLAIM);
#endif

  g_mutex_lock (&ctx->lock);
  gint64 issued_at = human_refresh_now_locked (ctx);
  g_mutex_unlock (&ctx->lock);
  g_auto (WylHumanAccessCandidate) access = { 0 };
  g_auto (WylHumanRefreshCandidate) refresh = { 0 };
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef WYL_TEST_DAEMON_HTTP
  if (!test_latch_ok)
    rc = WYRELOG_E_INTERNAL;
#endif
  if (rc == WYRELOG_E_OK)
    rc = prepare_human_access_candidate (&claim, issued_at, &access);
#ifdef WYL_TEST_DAEMON_HTTP
  if (!human_refresh_test_latch_reach (ctx,
          WYL_DAEMON_REFRESH_AFTER_ACCESS_PREPARE))
    rc = WYRELOG_E_INTERNAL;
#endif
  if (rc == WYRELOG_E_OK)
    rc = prepare_human_refresh_candidate (&claim, issued_at, &refresh);
#ifdef WYL_TEST_DAEMON_HTTP
  if (!human_refresh_test_latch_reach (ctx,
          WYL_DAEMON_REFRESH_AFTER_REFRESH_PREPARE))
    rc = WYRELOG_E_INTERNAL;
#endif
  g_autoptr (WylHumanRefreshResult) result = NULL;
#ifdef WYL_TEST_DAEMON_HTTP
  if (rc == WYRELOG_E_OK && human_refresh_test_fault_take (ctx,
          WYL_DAEMON_REFRESH_FAULT_RESULT_PREPARE))
    rc = WYRELOG_E_INTERNAL;
#endif
  if (rc == WYRELOG_E_OK)
    result = wyl_human_refresh_result_new_take
        (g_steal_pointer (&access.cache_token),
        g_steal_pointer (&refresh.cache_token));
#ifdef WYL_TEST_DAEMON_HTTP
  if (!human_refresh_test_latch_reach (ctx,
          WYL_DAEMON_REFRESH_BEFORE_PUBLICATION))
    rc = WYRELOG_E_INTERNAL;
  if (rc == WYRELOG_E_OK && human_refresh_test_fault_take (ctx,
          WYL_DAEMON_REFRESH_FAULT_PREPUBLICATION))
    rc = WYRELOG_E_INTERNAL;
#endif
  gboolean session_live = human_session_matches (ctx, session, session_id,
      subject, tenant);
  gboolean published = FALSE;
  gboolean shutting_down = FALSE;
  gboolean retryable_failure = FALSE;
  g_mutex_lock (&ctx->lock);
#ifdef WYL_TEST_DAEMON_HTTP
  if (rc == WYRELOG_E_OK && ctx->fail_next_refresh_publication) {
    ctx->fail_next_refresh_publication = FALSE;
    rc = WYRELOG_E_INTERNAL;
  }
#endif
  gint64 committed_at = human_refresh_now_locked (ctx);
  state = g_hash_table_lookup (ctx->refresh_tokens_by_token, refresh_token);
  WylSession *owner = g_hash_table_lookup (ctx->sessions_by_token, session_id);
  gboolean same_claim = state == claim.predecessor_state
      && state != NULL && state->epoch == predecessor_epoch
      && state->rotating && state->rotation_claim == claim.claim_epoch;
  shutting_down = ctx->shutting_down;
  gboolean exact = same_claim && !shutting_down && !state->consumed
      && !state->revoked && committed_at < state->expires_at
      && state->auth_method == WYL_SESSION_AUTH_METHOD_HUMAN
      && g_strcmp0 (state->session_id, session_id) == 0
      && g_strcmp0 (state->subject, subject) == 0
      && g_strcmp0 (state->tenant, tenant) == 0 && owner == session
      && ctx->auth_epoch == auth_epoch && ctx->key_epoch == key_epoch
      && g_strcmp0 (ctx->access_token_key_id, key_id) == 0
      && !g_hash_table_contains (ctx->revoked_session_tokens, session_id);
  retryable_failure = exact && session_live;
  /* HUMAN_REFRESH_PUBLICATION_BEGIN */
  if (rc == WYRELOG_E_OK && result != NULL && session_live && exact
      && human_refresh_candidates_publishable_at (&access, &refresh,
          committed_at)
      && !g_hash_table_contains (ctx->access_tokens_by_jti, access.state->jti)
      && !g_hash_table_contains (ctx->refresh_tokens_by_token,
          refresh.state->token)) {
    refresh.state->epoch = human_refresh_next_nonzero
        (&ctx->next_refresh_epoch);
    gchar *access_key = g_steal_pointer (&access.map_key);
    gchar *refresh_key = g_steal_pointer (&refresh.map_key);
    WylAccessTokenState *access_state = g_steal_pointer (&access.state);
    WylRefreshTokenState *refresh_state = g_steal_pointer (&refresh.state);
    WylHumanRefreshResult *committed = g_steal_pointer (&result);
    g_hash_table_insert (ctx->access_tokens_by_jti, access_key, access_state);
    g_hash_table_insert (ctx->refresh_tokens_by_token, refresh_key,
        refresh_state);
    state->successor = committed;
    state->consumed_at = committed_at;
    state->consumed = TRUE;
    state->rotating = FALSE;
    state->rotation_claim = 0;
    published = TRUE;
#ifdef WYL_TEST_DAEMON_HTTP
    g_atomic_int_inc ((gint *) & ctx->refresh_publications);
#endif
    /* HUMAN_REFRESH_PUBLICATION_END */
  } else if (same_claim) {
    state->rotating = FALSE;
    state->rotation_claim = 0;
  }
  g_mutex_unlock (&ctx->lock);

  if (!published) {
    if (shutting_down)
      set_json_error (msg, 503, "server_shutting_down");
    else if (retryable_failure)
      set_json_error (msg, 500, "refresh_failed");
    else
      set_json_error (msg, 401, "refresh_auth_required");
    return;
  }
#ifdef WYL_TEST_DAEMON_HTTP
  (void) human_refresh_test_latch_reach (ctx,
      WYL_DAEMON_REFRESH_AFTER_PUBLICATION);
  if (human_refresh_test_fault_take (ctx,
          WYL_DAEMON_REFRESH_FAULT_RESPONSE_BUILD)) {
    set_json_error (msg, 500, "refresh_response_failed");
    return;
  }
#endif
  g_autofree gchar *body = build_login_json (session_id, subject, tenant,
      "authenticated", access.token, refresh.token);
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static void
logout_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *session_token = NULL;
  if (query != NULL)
    session_token = g_hash_table_lookup (query, "session_token");
  gboolean has_session_token = session_token != NULL
      && session_token[0] != '\0';
  const gchar *bearer_token = lookup_bearer_token (msg);
  gboolean has_bearer_token = bearer_token != NULL && bearer_token[0] != '\0';
  if (!has_session_token && !has_bearer_token) {
    set_json_error (msg, 401, "logout_auth_required");
    return;
  }
  if (has_session_token && bearer_token != NULL) {
    set_json_error (msg, 400, "invalid_logout_auth");
    return;
  }
  if (bearer_token != NULL && !has_bearer_token) {
    set_json_error (msg, 401, "logout_auth_required");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  g_auto (WylDaemonAuthContext) bearer_auth = { 0 };
  if (has_bearer_token) {
    const gchar *auth_tenant_error = NULL;
    wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
        bearer_token, &bearer_auth, &auth_tenant_error);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401, auth_tenant_error != NULL
          ? auth_tenant_error : "logout_auth_required");
      return;
    }
    session_token = bearer_auth.session_id;
  }

  g_autoptr (WylSession) session =
      wyl_daemon_http_ref_session (server, session_token);
  if (session == NULL) {
    set_json_error (msg, 401, "logout_auth_required");
    return;
  }

  /*
   * Revoke refresh tokens FIRST so a concurrent /auth/refresh that
   * lands during teardown cannot rotate the refresh into a fresh
   * access/refresh pair bound to the now-being-killed session;
   * each revoke takes ctx->lock internally, so the window between
   * the two passes cannot mint a new refresh through the same
   * session_id (the rotation path will see a revoked refresh and
   * fail before issuing a new access token).
   *
   * Then revoke any access tokens already minted. After both
   * snapshot-walks complete, mark the session as revoked so the
   * store paths refuse any token state that an /auth/refresh which
   * already passed the lock-protected revoked-state check could
   * still try to insert after our snapshots ran. Returning to the
   * caller before token revocation completes would leave a replay
   * window during which a captured access token still resolves
   * against the registry; the order here closes that window.
   *
   * Drive the FSM through the public logout primitive (which
   * resolves the integer sid, runs the FSM transition, emits the
   * canonical session-state audit row, and tombstones the
   * handle's session registry) so HTTP and the core API converge
   * on a single FSM call site.
   */
  wyl_daemon_http_context_revoke_session_refresh_tokens (ctx, session_token);
  wyl_daemon_http_context_revoke_session_access_tokens (ctx, session_token);
  wyl_daemon_http_context_mark_session_revoked (ctx, session_token);

  const gchar *request_id = ensure_request_id_header (msg);
  wyrelog_error_t rc = wyl_session_logout_with_request_id (ctx->handle,
      wyl_session_get_id (session), request_id);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "logout_failed");
    return;
  }

  if (!wyl_daemon_http_context_remove_session (ctx, session_token)) {
    set_json_error (msg, 401, "logout_auth_required");
    return;
  }

  const gchar *body = "{\"ok\":true}";
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static void
decide_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *user = NULL;
  const gchar *perm = NULL;
  const gchar *session_token = NULL;
  const gchar *guard_timestamp = NULL;
  const gchar *guard_loc_class = NULL;
  const gchar *guard_risk = NULL;
  if (query != NULL) {
    user = g_hash_table_lookup (query, "user");
    perm = g_hash_table_lookup (query, "perm");
    session_token = g_hash_table_lookup (query, "session_token");
    guard_timestamp = g_hash_table_lookup (query, "guard_timestamp");
    guard_loc_class = g_hash_table_lookup (query, "guard_loc_class");
    guard_risk = g_hash_table_lookup (query, "guard_risk");
  }
  if (user == NULL || perm == NULL || session_token == NULL) {
    set_json_error (msg, 400, "invalid_decide_request");
    return;
  }
  WylDaemonHttpContext *ctx = user_data;
  const gchar *tenant = lookup_request_tenant (query);
  if (tenant == NULL || tenant[0] == '\0' || !tenant_is_active (ctx, tenant)) {
    set_json_error (msg, 400, tenant_is_known (ctx, tenant) ?
        WYL_DAEMON_ERR_TENANT_SEALED : WYL_DAEMON_ERR_TENANT_INVALID);
    return;
  }
  gboolean has_guard_context =
      guard_timestamp != NULL || guard_loc_class != NULL || guard_risk != NULL;
  if (has_guard_context &&
      (guard_timestamp == NULL || guard_loc_class == NULL ||
          guard_risk == NULL)) {
    set_json_error (msg, 400, "invalid_decide_request");
    return;
  }
  const gchar *bearer_token = lookup_bearer_token (msg);
  if (bearer_token == NULL || bearer_token[0] == '\0') {
    set_json_error (msg, 401, "decide_auth_required");
    return;
  }
  g_auto (WylDaemonAuthContext) auth = { 0 };
  const gchar *auth_tenant_error = NULL;
  wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
      bearer_token, &auth, &auth_tenant_error);
  if (auth_rc != WYRELOG_E_OK) {
    set_json_error (msg, 401, auth_tenant_error != NULL
        ? auth_tenant_error : "decide_auth_required");
    return;
  }
  if (!ensure_auth_context_request_tenant (msg, query, ctx, &auth))
    return;
  if (g_strcmp0 (auth.actor, user) != 0) {
    set_json_error (msg, 403, "decide_denied");
    return;
  }

  WylHandle *handle = ctx->handle;
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, user);
  wyl_decide_req_set_action (req, perm);
  wyl_decide_req_set_resource_id (req, session_token);
  wyl_decide_req_set_request_id (req, ensure_request_id_header (msg));
  if (has_guard_context) {
    gint64 timestamp = 0;
    gint64 risk = 0;
    if (!parse_int64_query_param (guard_timestamp, &timestamp) ||
        !parse_int64_query_param (guard_risk, &risk) || timestamp < 0 ||
        risk < 0 || risk > 100 ||
        !wyl_guard_loc_class_is_valid (guard_loc_class)) {
      set_json_error (msg, 400, "invalid_decide_request");
      return;
    }
    wyl_decide_req_set_guard_context (req, timestamp, guard_loc_class, risk);
  }

  wyrelog_error_t rc = wyl_decide (handle, req, resp);
  if (rc == WYRELOG_E_INVALID) {
    set_json_error (msg, 400, "invalid_decide_request");
    return;
  }
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "decide_failed");
    return;
  }

  g_autofree gchar *body = build_decide_json (resp);
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

SoupServer *
wyl_daemon_start_http_server_with_runtime (const WylDaemonOptions *opts,
    WylHandle *handle, WylDaemonRuntime *runtime, GError **error)
{
  g_return_val_if_fail (opts != NULL, NULL);
  g_return_val_if_fail (WYL_IS_HANDLE (handle), NULL);

  if (opts->listen_port < 0 || opts->listen_port > 65535) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "listen port must be between 0 and 65535");
    return NULL;
  }

  SoupServer *server = soup_server_new (NULL, NULL);
  WylDaemonHttpContext *ctx =
      wyl_daemon_http_context_new (opts, handle, runtime, error);
  if (ctx == NULL) {
    g_object_unref (server);
    return NULL;
  }
  g_object_set_data_full (G_OBJECT (server), "wyl-daemon-http-context", ctx,
      wyl_daemon_http_context_shutdown);
  soup_server_add_handler (server, "/healthz", healthz_handler, NULL, NULL);
  soup_server_add_handler (server, "/readyz", readyz_handler, ctx, NULL);
  soup_server_add_handler (server, "/facts/status", facts_status_handler, ctx,
      NULL);
  soup_server_add_handler (server, "/facts/schema/register",
      schema_register_handler, ctx, NULL);
  soup_server_add_handler (server, "/facts", facts_route_handler, ctx, NULL);
  soup_server_add_handler (server, "/datalog", datalog_query_handler, ctx,
      NULL);
  soup_server_add_handler (server, "/profile/status", profile_status_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/profile/events", profile_events_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/auth/login", login_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/mfa/verify", mfa_verify_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/auth/mfa/enroll/start",
      mfa_enroll_start_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/mfa/enroll/confirm",
      mfa_enroll_confirm_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/refresh", refresh_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/logout", logout_handler, ctx, NULL);
  soup_server_add_handler (server, "/tenants", tenant_list_handler, ctx, NULL);
  soup_server_add_handler (server, "/tenants/create", tenant_create_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/tenants/seal", tenant_seal_handler, ctx,
      NULL);
  soup_server_add_handler (server, "/tenants/unseal", tenant_unseal_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/tenants/delete", tenant_delete_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/graphs/create", graph_create_handler, ctx,
      NULL);
  soup_server_add_handler (server, "/graphs/seal", graph_seal_handler, ctx,
      NULL);
  soup_server_add_handler (server, "/graphs", graphs_list_handler, ctx, NULL);
  soup_server_add_handler (server, "/decide", decide_handler, ctx, NULL);
  soup_server_add_handler (server, "/policy/permissions/grant",
      policy_permission_grant_handler, ctx, NULL);
  soup_server_add_handler (server, "/policy/permissions/revoke",
      policy_permission_revoke_handler, ctx, NULL);
  soup_server_add_handler (server, "/policy/permissions/transition",
      policy_permission_transition_handler, ctx, NULL);
  soup_server_add_handler (server, "/policy/roles/grant",
      policy_role_grant_handler, ctx, NULL);
  soup_server_add_handler (server, "/policy/roles/revoke",
      policy_role_revoke_handler, ctx, NULL);
  soup_server_add_handler (server, "/audit/events", audit_events_handler,
      ctx, NULL);
  soup_server_add_handler (server, "/service-principals",
      service_principal_management_handler, ctx, NULL);
  soup_server_add_handler (server, "/service-credentials",
      service_credential_management_handler, ctx, NULL);
#ifdef WYL_HAS_FACT_STORE
  soup_server_add_handler (server, "/service-credential-operations/reconcile",
      service_credential_operation_reconcile_handler, ctx, NULL);
#endif
#ifdef WYL_HAS_AUDIT
  soup_server_add_handler (server, "/auth/service-token",
      service_token_exchange_http_handler, ctx, NULL);
#endif
#ifdef WYL_TEST_DAEMON_HTTP
#ifdef WYL_HAS_FACT_STORE
  soup_server_add_handler (server, "/__test/reconcile",
      service_credential_operation_reconcile_handler, ctx, NULL);
#endif
  soup_server_add_handler (server, "/" "__test/" "service-" "principals",
      service_principal_management_handler, ctx, NULL);
  soup_server_add_handler (server, "/" "__test/" "service-" "credentials",
      service_credential_management_handler, ctx, NULL);
#endif
  if (!soup_server_listen_local (server, (guint) opts->listen_port, 0, error)) {
    g_object_unref (server);
    return NULL;
  }

  return server;
}

SoupServer *
wyl_daemon_start_http_server (const WylDaemonOptions *opts, WylHandle *handle,
    GError **error)
{
  return wyl_daemon_start_http_server_with_runtime (opts, handle, NULL, error);
}
#endif
