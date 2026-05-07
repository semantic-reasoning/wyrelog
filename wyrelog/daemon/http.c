/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <errno.h>
#include <sodium.h>
#include <string.h>

#include "daemon/delta.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-request-id-private.h"
#include "wyrelog/wyl-fsm-permission-scope-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

#define WYL_DAEMON_JWT_ISSUER "wyrelogd"
#define WYL_DAEMON_JWT_AUDIENCE "wyrelog-client"
#define WYL_DAEMON_JWT_KEY_ID "__wr_default_hs256"
#define WYL_DAEMON_DEFAULT_TENANT "__wr_default"
#define WYL_DAEMON_JWT_KEY_LEN 32
#define WYL_DAEMON_REQUEST_ID_HEADER "X-Wyrelog-Request-Id"
#define WYL_DAEMON_REQUEST_ID_DATA "wyl-daemon-request-id"
#define WYL_DAEMON_REQUEST_ID_ATTEMPTED_DATA "wyl-daemon-request-id-attempted"

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
  WylHandle *handle;
  WylDaemonRuntime *runtime;
  guint8 access_token_secret[WYL_DAEMON_JWT_KEY_LEN];
  gboolean access_token_secret_ready;
  GHashTable *sessions_by_token;
  GHashTable *access_tokens_by_jti;
  GMutex lock;
  GMutex policy_mutation_lock;
} WylDaemonHttpContext;

static WylDaemonHttpContext *wyl_daemon_http_get_context (SoupServer * server);
static void set_json_error (SoupServerMessage * msg, guint status,
    const gchar * code);

static gboolean
wyl_daemon_tenant_is_known (const gchar *tenant)
{
  return g_strcmp0 (tenant, WYL_DAEMON_DEFAULT_TENANT) == 0;
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
wyl_daemon_http_context_free (gpointer data)
{
  WylDaemonHttpContext *ctx = data;

  if (ctx == NULL)
    return;

  sodium_memzero (ctx->access_token_secret, sizeof ctx->access_token_secret);
  g_hash_table_unref (ctx->sessions_by_token);
  g_hash_table_unref (ctx->access_tokens_by_jti);
  g_mutex_clear (&ctx->lock);
  g_mutex_clear (&ctx->policy_mutation_lock);
  g_free (ctx);
}

static WylDaemonHttpContext *
wyl_daemon_http_context_new (WylHandle *handle, WylDaemonRuntime *runtime)
{
  WylDaemonHttpContext *ctx = g_new0 (WylDaemonHttpContext, 1);

  ctx->handle = handle;
  ctx->runtime = runtime;
  if (sodium_init () >= 0) {
    randombytes_buf (ctx->access_token_secret, sizeof ctx->access_token_secret);
    ctx->access_token_secret_ready = TRUE;
  }
  ctx->sessions_by_token =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
  ctx->access_tokens_by_jti = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, wyl_access_token_state_free);
  g_mutex_init (&ctx->lock);
  g_mutex_init (&ctx->policy_mutation_lock);
  return ctx;
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
  g_hash_table_replace (ctx->access_tokens_by_jti, g_strdup (jti), state);
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
      && g_strcmp0 (state->key_id, WYL_DAEMON_JWT_KEY_ID) == 0
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

  memcpy (out_secret, ctx->access_token_secret, WYL_DAEMON_JWT_KEY_LEN);
  return WYRELOG_E_OK;
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
gboolean
wyl_daemon_http_remove_session_for_test (SoupServer *server,
    const gchar *session_token)
{
  WylDaemonHttpContext *ctx = wyl_daemon_http_get_context (server);
  return wyl_daemon_http_context_remove_session (ctx, session_token);
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
    const gchar *access_token)
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
  memcpy (out_secret, ctx->access_token_secret, WYL_DAEMON_JWT_KEY_LEN);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
issue_login_access_token (WylDaemonHttpContext *ctx, const gchar *session_token,
    const gchar *username, const gchar *tenant, const gchar *principal_state,
    WylSession *session, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;
  if (session_token == NULL || username == NULL || tenant == NULL ||
      principal_state == NULL || session == NULL)
    return WYRELOG_E_INVALID;

  guint8 secret[WYL_DAEMON_JWT_KEY_LEN];
  wyrelog_error_t rc = copy_access_token_secret (ctx, secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_id_t token_id;
  rc = wyl_id_new (&token_id);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (secret, sizeof secret);
    return rc;
  }
  gchar token_id_buf[WYL_ID_STRING_BUF];
  rc = wyl_id_format (&token_id, token_id_buf, sizeof token_id_buf);
  if (rc != WYRELOG_E_OK) {
    sodium_memzero (secret, sizeof secret);
    return rc;
  }

  gint64 issued_at = wyl_session_get_created_at_us (session) / G_USEC_PER_SEC;
  gint64 ttl = WYL_JWT_ACCESS_TTL_SECONDS;
  if (issued_at > G_MAXINT64 - ttl) {
    sodium_memzero (secret, sizeof secret);
    return WYRELOG_E_INVALID;
  }
  wyl_jwt_issue_input_t input = {
    .key_id = WYL_DAEMON_JWT_KEY_ID,
    .jti = token_id_buf,
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
  if (!wyl_daemon_http_context_store_access_token (ctx, token_id_buf,
          session_token, username, tenant, WYL_DAEMON_JWT_KEY_ID,
          issued_at + ttl)) {
    g_clear_pointer (out_token, g_free);
    return WYRELOG_E_INTERNAL;
  }
  return rc;
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

static wyrelog_error_t
resolve_bearer_session (SoupServer *server, WylDaemonHttpContext *ctx,
    const gchar *token, WylDaemonAuthContext *out_auth)
{
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
      WYL_DAEMON_JWT_KEY_ID, WYL_DAEMON_JWT_ISSUER,
      WYL_DAEMON_JWT_AUDIENCE, now, &payload);
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;

  wyl_jwt_access_claims_t claims = { 0 };
  rc = wyl_jwt_parse_access_claims_json (payload, &claims);
  if (rc != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
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

static wyrelog_error_t
resolve_session_token_auth (SoupServer *server, const gchar *session_token,
    WylDaemonAuthContext *out_auth)
{
  if (server == NULL || session_token == NULL || out_auth == NULL)
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
  return WYL_DAEMON_DEFAULT_TENANT;
}

static gboolean
ensure_auth_context_request_tenant (SoupServerMessage *msg, GHashTable *query,
    const WylDaemonAuthContext *auth, const gchar *invalid_code,
    const gchar *denied_code)
{
  const gchar *request_tenant = lookup_request_tenant (query);
  if (request_tenant == NULL || request_tenant[0] == '\0' ||
      !wyl_daemon_tenant_is_known (request_tenant)) {
    set_json_error (msg, 400, invalid_code);
    return FALSE;
  }

  if (auth == NULL || auth->tenant == NULL ||
      g_strcmp0 (auth->tenant, request_tenant) != 0) {
    set_json_error (msg, 403, denied_code);
    return FALSE;
  }

  return TRUE;
}

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
  (void) query;
  (void) user_data;

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
  (void) query;

  WylDaemonHttpContext *ctx = user_data;
  const gchar *liveness_error = check_runtime_liveness_ready (ctx->runtime);
  if (liveness_error != NULL) {
    set_json_error (msg, 503, liveness_error);
    return;
  }

  const gchar *readiness_error = "not_ready";
  wyrelog_error_t rc = check_runtime_ready (ctx->handle, &readiness_error);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 503, readiness_error);
    return;
  }

  const gchar *body = "ready\n";
  attach_request_id_header (msg);
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY, body,
      strlen (body));
}

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
  if (has_session_token) {
    wyrelog_error_t auth_rc =
        resolve_session_token_auth (server, session_token, &auth);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401, auth_required_code);
      return FALSE;
    }
  } else {
    wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
        bearer_token, &auth);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401, auth_required_code);
      return FALSE;
    }
  }
  if (!ensure_auth_context_request_tenant (msg, query, &auth, invalid_code,
          denied_code))
    return FALSE;

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
ensure_policy_permission_exists (SoupServerMessage *msg,
    WylDaemonHttpContext *ctx, const gchar *perm)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (ctx->handle);
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
ensure_policy_role_exists (SoupServerMessage *msg, WylDaemonHttpContext *ctx,
    const gchar *role)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (ctx->handle);
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

  g_mutex_lock (&ctx->policy_mutation_lock);

  if (!ensure_policy_permission_exists (msg, ctx, perm)) {
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

  wyrelog_error_t rc;
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
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

  set_json_ok (msg);
  g_mutex_unlock (&ctx->policy_mutation_lock);
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

  g_mutex_lock (&ctx->policy_mutation_lock);

  if (!ensure_policy_permission_exists (msg, ctx, perm)) {
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

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

  wyrelog_error_t rc = wyl_handle_apply_permission_state_transition
      (ctx->handle, subject, perm, scope, event, audit_event, NULL);
  if (rc != WYRELOG_E_OK) {
    set_policy_transition_error (msg, rc);
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

  set_json_ok (msg);
  g_mutex_unlock (&ctx->policy_mutation_lock);
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

  g_mutex_lock (&ctx->policy_mutation_lock);

  if (!ensure_policy_role_exists (msg, ctx, role)) {
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

  wyrelog_error_t rc;
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
    g_mutex_unlock (&ctx->policy_mutation_lock);
    return;
  }

  set_json_ok (msg);
  g_mutex_unlock (&ctx->policy_mutation_lock);
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
  const gchar *tenant = WYL_DAEMON_DEFAULT_TENANT;
  const gchar *skip_mfa = NULL;
  const gchar *password = NULL;
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
  if (tenant == NULL || tenant[0] == '\0' ||
      !wyl_daemon_tenant_is_known (tenant)) {
    set_json_error (msg, 400, "invalid_login_request");
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

  WylDaemonHttpContext *ctx = user_data;
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
  if (skip_mfa_requested) {
    rc = issue_login_access_token (ctx, session_token, username,
        session_tenant, principal_state, session, &access_token);
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
      session_tenant, principal_state, access_token);
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
    wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
        bearer_token, &bearer_auth);
    if (auth_rc != WYRELOG_E_OK) {
      set_json_error (msg, 401, "logout_auth_required");
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

  const gchar *request_id = ensure_request_id_header (msg);
  wyrelog_error_t rc =
      wyl_session_close_with_request_id (ctx->handle, session, request_id);
  if (rc != WYRELOG_E_OK) {
    set_json_error (msg, 500, "logout_failed");
    return;
  }

  wyl_daemon_http_context_revoke_session_access_tokens (ctx, session_token);
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
  const gchar *tenant = lookup_request_tenant (query);
  if (tenant == NULL || tenant[0] == '\0' ||
      !wyl_daemon_tenant_is_known (tenant)) {
    set_json_error (msg, 400, "invalid_decide_request");
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

  WylDaemonHttpContext *ctx = user_data;
  const gchar *bearer_token = lookup_bearer_token (msg);
  if (bearer_token == NULL || bearer_token[0] == '\0') {
    set_json_error (msg, 401, "decide_auth_required");
    return;
  }
  g_auto (WylDaemonAuthContext) auth = { 0 };
  wyrelog_error_t auth_rc = resolve_bearer_session (server, ctx,
      bearer_token, &auth);
  if (auth_rc != WYRELOG_E_OK) {
    set_json_error (msg, 401, "decide_auth_required");
    return;
  }
  if (!ensure_auth_context_request_tenant (msg, query, &auth,
          "invalid_decide_request", "decide_denied"))
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
  WylDaemonHttpContext *ctx = wyl_daemon_http_context_new (handle, runtime);
  g_object_set_data_full (G_OBJECT (server), "wyl-daemon-http-context", ctx,
      wyl_daemon_http_context_free);
  soup_server_add_handler (server, "/healthz", healthz_handler, NULL, NULL);
  soup_server_add_handler (server, "/readyz", readyz_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/login", login_handler, ctx, NULL);
  soup_server_add_handler (server, "/auth/logout", logout_handler, ctx, NULL);
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
