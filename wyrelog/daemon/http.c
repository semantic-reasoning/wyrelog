/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <errno.h>
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

typedef struct
{
  WylHandle *handle;
  GHashTable *sessions_by_token;
  GMutex lock;
} WylDaemonHttpContext;

static void
wyl_daemon_http_context_free (gpointer data)
{
  WylDaemonHttpContext *ctx = data;

  if (ctx == NULL)
    return;

  g_hash_table_unref (ctx->sessions_by_token);
  g_mutex_clear (&ctx->lock);
  g_free (ctx);
}

static WylDaemonHttpContext *
wyl_daemon_http_context_new (WylHandle *handle)
{
  WylDaemonHttpContext *ctx = g_new0 (WylDaemonHttpContext, 1);

  ctx->handle = handle;
  ctx->sessions_by_token =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
  g_mutex_init (&ctx->lock);
  return ctx;
}

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
    const gchar *principal_state)
{
  g_autoptr (GString) json = g_string_new ("{");

  g_string_append (json, "\"session_token\":");
  append_json_string (json, session_token);
  g_string_append (json, ",\"username\":");
  append_json_string (json, username);
  g_string_append (json, ",\"principal_state\":");
  append_json_string (json, principal_state);
  g_string_append (json, ",\"session_state\":\"active\"}");
  return g_string_free (g_steal_pointer (&json), FALSE);
}

static void
set_json_error (SoupServerMessage *msg, guint status, const gchar *code)
{
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
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY, body,
      strlen (body));
}

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
  WylHandle *handle = ctx->handle;
  g_autofree gchar *body = NULL;
  wyrelog_error_t rc =
      wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
      filter, &body);
  if (rc == WYRELOG_E_INVALID) {
    const gchar *error_body = "{\"error\":\"invalid_filter\"}";
    soup_server_message_set_status (msg, 400, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, error_body, strlen (error_body));
    return;
  }
  if (rc != WYRELOG_E_OK) {
    const gchar *error_body = "{\"error\":\"audit_query_failed\"}";
    soup_server_message_set_status (msg, 500, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, error_body, strlen (error_body));
    return;
  }
#else
  (void) query;
  (void) user_data;
  const gchar *body = "[]";
#endif

  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
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
  const gchar *skip_mfa = NULL;
  const gchar *password = NULL;
  if (query != NULL) {
    username = g_hash_table_lookup (query, "username");
    skip_mfa = g_hash_table_lookup (query, "skip_mfa");
    password = g_hash_table_lookup (query, "password");
  }
  if (username == NULL || username[0] == '\0') {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }
  if (password != NULL) {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }
  if (skip_mfa != NULL) {
    set_json_error (msg, 400, "invalid_login_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  WylHandle *handle = ctx->handle;
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);

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
  if (session_token == NULL) {
    set_json_error (msg, 500, "login_failed");
    return;
  }
  if (!wyl_daemon_http_context_store_session (ctx, session_token, session)) {
    set_json_error (msg, 500, "login_failed");
    return;
  }

  g_autofree gchar *body =
      build_login_json (session_token, username, "mfa_required");
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
  gboolean has_guard_context =
      guard_timestamp != NULL || guard_loc_class != NULL || guard_risk != NULL;
  if (has_guard_context &&
      (guard_timestamp == NULL || guard_loc_class == NULL ||
          guard_risk == NULL)) {
    set_json_error (msg, 400, "invalid_decide_request");
    return;
  }

  WylDaemonHttpContext *ctx = user_data;
  WylHandle *handle = ctx->handle;
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, user);
  wyl_decide_req_set_action (req, perm);
  wyl_decide_req_set_resource_id (req, session_token);
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
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

SoupServer *
wyl_daemon_start_http_server (const WylDaemonOptions *opts, WylHandle *handle,
    GError **error)
{
  g_return_val_if_fail (opts != NULL, NULL);
  g_return_val_if_fail (WYL_IS_HANDLE (handle), NULL);

  if (opts->listen_port < 0 || opts->listen_port > 65535) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "listen port must be between 0 and 65535");
    return NULL;
  }

  SoupServer *server = soup_server_new (NULL, NULL);
  WylDaemonHttpContext *ctx = wyl_daemon_http_context_new (handle);
  g_object_set_data_full (G_OBJECT (server), "wyl-daemon-http-context", ctx,
      wyl_daemon_http_context_free);
  soup_server_add_handler (server, "/healthz", healthz_handler, NULL, NULL);
  soup_server_add_handler (server, "/auth/login", login_handler, ctx, NULL);
  soup_server_add_handler (server, "/decide", decide_handler, ctx, NULL);
  soup_server_add_handler (server, "/audit/events", audit_events_handler,
      ctx, NULL);
  if (!soup_server_listen_local (server, (guint) opts->listen_port, 0, error)) {
    g_object_unref (server);
    return NULL;
  }

  return server;
}
#endif
