/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

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

  WylHandle *handle = user_data;
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
  if (query != NULL) {
    user = g_hash_table_lookup (query, "user");
    perm = g_hash_table_lookup (query, "perm");
    session_token = g_hash_table_lookup (query, "session_token");
  }
  if (user == NULL || perm == NULL || session_token == NULL) {
    set_json_error (msg, 400, "invalid_decide_request");
    return;
  }

  WylHandle *handle = user_data;
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, user);
  wyl_decide_req_set_action (req, perm);
  wyl_decide_req_set_resource_id (req, session_token);

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
  soup_server_add_handler (server, "/healthz", healthz_handler, NULL, NULL);
  soup_server_add_handler (server, "/decide", decide_handler, handle, NULL);
  soup_server_add_handler (server, "/audit/events", audit_events_handler,
      handle, NULL);
  if (!soup_server_listen_local (server, (guint) opts->listen_port, 0, error)) {
    g_object_unref (server);
    return NULL;
  }

  return server;
}
#endif
