/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <errno.h>
#include <sodium.h>
#include <string.h>

#include "daemon/auth-registry-private.h"
#include "daemon/delta.h"
#include "daemon/fact-status.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/auth/mfa-enrollment-private.h"
#include "wyrelog/auth/totp.h"
#ifdef WYL_HAS_FACT_STORE
#include "wyrelog/fact/query-private.h"
#include "wyrelog/fact/schema-private.h"
#include "wyrelog/fact/store-private.h"
#endif
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
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

typedef struct
{
  gchar *token;
  gchar *session_id;
  gchar *subject;
  gchar *tenant;
  gchar *successor_token;
  gchar *successor_access_token;
  gboolean consumed;
  gboolean revoked;
  gint64 issued_at;
  gint64 expires_at;
  gint64 consumed_at;
} WylRefreshTokenState;

typedef struct
{
  gchar *challenge;
  gchar *session_id;
  gchar *actor;
  gchar *subject;
  guint8 secret[WYL_TOTP_SEED_BYTES];
  gint64 expires_at_monotonic_us;
} WylMfaEnrollChallenge;

typedef struct
{
  WylHandle *handle;
  WylDaemonRuntime *runtime;
  WylServiceAuthRegistry *service_auth_registry;
  guint8 access_token_secret[WYL_DAEMON_JWT_KEY_LEN];
  gchar *access_token_key_id;
  gboolean access_token_secret_ready;
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
} WylDaemonHttpContext;

typedef struct
{
  WylServiceAuthWriteLease *lease;
  wyl_policy_store_t *store;    /* borrowed from the lease-owned pin */
} WylDaemonPolicyWrite;

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
  g_free (state);
}

static void
wyl_refresh_token_state_free (gpointer data)
{
  WylRefreshTokenState *state = data;

  if (state == NULL)
    return;

  g_free (state->token);
  g_free (state->session_id);
  g_free (state->subject);
  g_free (state->tenant);
  g_free (state->successor_token);
  g_free (state->successor_access_token);
  g_free (state);
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
wyl_daemon_http_context_free (gpointer data)
{
  WylDaemonHttpContext *ctx = data;

  if (ctx == NULL)
    return;

  sodium_memzero (ctx->access_token_secret, sizeof ctx->access_token_secret);
  g_free (ctx->access_token_key_id);
  g_free (ctx->policy_keyprovider_path);
  g_free (ctx->fact_root);
  g_free (ctx->system_url);
  g_free (ctx->event_spool_dir);
  g_hash_table_unref (ctx->sessions_by_token);
  g_hash_table_unref (ctx->access_tokens_by_jti);
  g_hash_table_unref (ctx->refresh_tokens_by_token);
  g_hash_table_unref (ctx->mfa_enroll_challenges);
  g_clear_pointer (&ctx->revoked_session_tokens, g_hash_table_unref);
  g_mutex_clear (&ctx->lock);
  g_clear_pointer (&ctx->service_auth_registry,
      wyl_service_auth_registry_unref);
  g_free (ctx);
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
  g_hash_table_remove_all (ctx->access_tokens_by_jti);
  g_hash_table_remove_all (ctx->refresh_tokens_by_token);
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
  rc = wyl_daemon_http_context_rotate_access_token_key (ctx);
  if (rc != WYRELOG_E_OK) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
        "JWT signing key initialization failed: %s", wyrelog_error_string (rc));
    wyl_daemon_http_context_free (ctx);
    return NULL;
  }
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
wyl_daemon_http_context_store_access_token (WylDaemonHttpContext *ctx,
    const gchar *jti, const gchar *session_id, const gchar *subject,
    const gchar *tenant, const gchar *key_id, gint64 expires_at)
{
  if (ctx == NULL || jti == NULL || jti[0] == '\0' || session_id == NULL ||
      session_id[0] == '\0' || subject == NULL || subject[0] == '\0' ||
      tenant == NULL || tenant[0] == '\0' || key_id == NULL ||
      key_id[0] == '\0' || expires_at < 0)
    return FALSE;

  WylAccessTokenState *state = g_new0 (WylAccessTokenState, 1);
  state->jti = g_strdup (jti);
  state->session_id = g_strdup (session_id);
  state->subject = g_strdup (subject);
  state->tenant = g_strdup (tenant);
  state->key_id = g_strdup (key_id);
  state->expires_at = expires_at;

  g_mutex_lock (&ctx->lock);
  /*
   * Refuse to register tokens for a session that has already entered
   * the logout teardown path. This closes the window in which a
   * concurrent /auth/refresh that snapshotted state->revoked == FALSE
   * before the teardown's revoke pass landed could otherwise insert
   * a freshly-minted access token whose jti the teardown's snapshot
   * never saw.
   */
  if (g_hash_table_contains (ctx->revoked_session_tokens, session_id)) {
    g_mutex_unlock (&ctx->lock);
    wyl_access_token_state_free (state);
    return FALSE;
  }
  g_hash_table_replace (ctx->access_tokens_by_jti, g_strdup (jti), state);
  g_mutex_unlock (&ctx->lock);
  return TRUE;
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
    const gchar *token, const gchar *session_id, const gchar *subject,
    const gchar *tenant, gint64 issued_at, gint64 expires_at)
{
  if (ctx == NULL || token == NULL || token[0] == '\0' ||
      session_id == NULL || session_id[0] == '\0' || subject == NULL ||
      subject[0] == '\0' || tenant == NULL || tenant[0] == '\0' ||
      issued_at < 0 || expires_at <= issued_at)
    return FALSE;

  WylRefreshTokenState *state = g_new0 (WylRefreshTokenState, 1);
  state->token = g_strdup (token);
  state->session_id = g_strdup (session_id);
  state->subject = g_strdup (subject);
  state->tenant = g_strdup (tenant);
  state->issued_at = issued_at;
  state->expires_at = expires_at;

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
      && g_strcmp0 (state->session_id, claims->session_id) == 0
      && g_strcmp0 (state->subject, claims->subject) == 0
      && g_strcmp0 (state->tenant, claims->tenant) == 0
      && g_strcmp0 (state->key_id, ctx->access_token_key_id) == 0
      && state->expires_at == claims->expires_at;
  g_mutex_unlock (&ctx->lock);
  return active;
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
issue_access_token (WylDaemonHttpContext *ctx, const gchar *session_token,
    const gchar *username, const gchar *tenant, const gchar *principal_state,
    gint64 issued_at, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (session_token == NULL || username == NULL || tenant == NULL ||
      principal_state == NULL || issued_at < 0)
    return WYRELOG_E_INVALID;

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
  if (!wyl_daemon_http_context_store_access_token (ctx, token_id,
          session_token, username, tenant, ctx->access_token_key_id,
          issued_at + ttl)) {
    g_clear_pointer (out_token, g_free);
    return WYRELOG_E_INTERNAL;
  }
  return rc;
}

static wyrelog_error_t
issue_login_access_token (WylDaemonHttpContext *ctx, const gchar *session_token,
    const gchar *username, const gchar *tenant, const gchar *principal_state,
    gchar **out_token)
{
  return issue_access_token (ctx, session_token, username, tenant,
      principal_state, g_get_real_time () / G_USEC_PER_SEC, out_token);
}

static wyrelog_error_t
issue_refresh_token (WylDaemonHttpContext *ctx, const gchar *session_token,
    const gchar *username, const gchar *tenant, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (ctx == NULL || session_token == NULL || username == NULL ||
      tenant == NULL)
    return WYRELOG_E_INVALID;

  g_autofree gchar *token = NULL;
  wyrelog_error_t rc = new_token_id_string (&token);
  if (rc != WYRELOG_E_OK)
    return rc;

  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  if (now > G_MAXINT64 - WYL_DAEMON_REFRESH_TTL_SECONDS)
    return WYRELOG_E_INVALID;

  if (!wyl_daemon_http_context_store_refresh_token (ctx, token, session_token,
          username, tenant, now, now + WYL_DAEMON_REFRESH_TTL_SECONDS))
    return WYRELOG_E_INTERNAL;

  *out_token = g_steal_pointer (&token);
  return WYRELOG_E_OK;
}

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

/*
 * Bearer-token auth resolver. Defense-in-depth tenant gate: after
 * the signature/issuer/audience/exp verifier passes and the access
 * claims are parsed, we directly require that the JWT's tenant
 * claim is one of the daemon's active tenants. On miss, we surface the
 * stable wire code
 * WYL_DAEMON_ERR_TENANT_INVALID through *out_auth_error_code so the
 * caller can emit it instead of the generic auth_required code.
 * out_auth_error_code may be NULL; callers that don't need the
 * specific reason still get WYRELOG_E_POLICY and can fall back to
 * their handler-family auth_required code.
 */
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
    g_autofree gchar *fact_db_path =
        g_build_filename (lookup.info.storage_path, "facts.duckdb", NULL);
    rc = wyl_fact_store_open (fact_db_path, &fact_store);
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
  g_autofree gchar *fact_db_path = g_build_filename (lookup.info.storage_path,
      "facts.duckdb", NULL);
  rc = wyl_fact_store_open (fact_db_path, &fact_store);
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
    rc = issue_login_access_token (ctx, session_token, username,
        session_tenant, principal_state, &access_token);
    if (rc == WYRELOG_E_OK)
      rc = issue_refresh_token (ctx, session_token, username, session_tenant,
          &refresh_token);
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
  rc = issue_login_access_token (ctx, session_token, username,
      session_tenant, "authenticated", &access_token);
  if (rc == WYRELOG_E_OK)
    rc = issue_refresh_token (ctx, session_token, username, session_tenant,
        &refresh_token);
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

static void
refresh_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) path;

  if (g_strcmp0 (soup_server_message_get_method (msg), "POST") != 0) {
    set_json_error (msg, 405, "method_not_allowed");
    return;
  }

  const gchar *refresh_token = NULL;
  if (query != NULL)
    refresh_token = g_hash_table_lookup (query, "refresh_token");
  if (refresh_token == NULL || refresh_token[0] == '\0') {
    set_json_error (msg, 400, "invalid_refresh_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  g_autofree gchar *session_id = NULL;
  g_autofree gchar *subject = NULL;
  g_autofree gchar *tenant = NULL;
  g_autofree gchar *cached_access_token = NULL;
  g_autofree gchar *cached_refresh_token = NULL;
  gboolean reuse_detected = FALSE;

  g_mutex_lock (&ctx->lock);
  WylRefreshTokenState *state =
      g_hash_table_lookup (ctx->refresh_tokens_by_token, refresh_token);
  if (state == NULL || state->revoked || now >= state->expires_at) {
    g_mutex_unlock (&ctx->lock);
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }
  session_id = g_strdup (state->session_id);
  subject = g_strdup (state->subject);
  tenant = g_strdup (state->tenant);
  if (state->consumed) {
    if (now <= state->consumed_at + WYL_DAEMON_REFRESH_GRACE_SECONDS &&
        state->successor_token != NULL
        && state->successor_access_token != NULL) {
      cached_refresh_token = g_strdup (state->successor_token);
      cached_access_token = g_strdup (state->successor_access_token);
    } else {
      state->revoked = TRUE;
      reuse_detected = TRUE;
    }
  }
  g_mutex_unlock (&ctx->lock);

  if (reuse_detected) {
    wyl_daemon_http_context_revoke_session_access_tokens (ctx, session_id);
    wyl_daemon_http_context_revoke_session_refresh_tokens (ctx, session_id);
    set_json_error (msg, 401, "refresh_reuse_detected");
    return;
  }

  g_autoptr (WylSession) session = wyl_daemon_http_ref_session (server,
      session_id);
  if (session == NULL) {
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }
  g_autofree gchar *live_username = wyl_session_dup_username (session);
  g_autofree gchar *live_tenant = wyl_session_dup_tenant (session);
  if (g_strcmp0 (live_username, subject) != 0 ||
      g_strcmp0 (live_tenant, tenant) != 0) {
    set_json_error (msg, 401, "refresh_auth_required");
    return;
  }

  g_autofree gchar *access_token = g_steal_pointer (&cached_access_token);
  g_autofree gchar *next_refresh_token =
      g_steal_pointer (&cached_refresh_token);
  wyrelog_error_t rc = WYRELOG_E_OK;
  if (access_token == NULL || next_refresh_token == NULL) {
    rc = issue_access_token (ctx, session_id, subject, tenant, "authenticated",
        now, &access_token);
    if (rc == WYRELOG_E_OK)
      rc = issue_refresh_token (ctx, session_id, subject, tenant,
          &next_refresh_token);
    if (rc != WYRELOG_E_OK) {
      set_json_error (msg, 500, "refresh_failed");
      return;
    }

    g_mutex_lock (&ctx->lock);
    state = g_hash_table_lookup (ctx->refresh_tokens_by_token, refresh_token);
    if (state != NULL && !state->consumed && !state->revoked) {
      state->consumed = TRUE;
      state->consumed_at = now;
      state->successor_token = g_strdup (next_refresh_token);
      state->successor_access_token = g_strdup (access_token);
    }
    g_mutex_unlock (&ctx->lock);
  }

  g_autofree gchar *body = build_login_json (session_id, subject, tenant,
      "authenticated", access_token, next_refresh_token);
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
      wyl_daemon_http_context_free);
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
