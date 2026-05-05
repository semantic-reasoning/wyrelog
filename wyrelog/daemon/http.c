/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/http.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <string.h>

#include "wyrelog/wyl-handle-private.h"

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
  soup_server_add_handler (server, "/audit/events", audit_events_handler,
      handle, NULL);
  if (!soup_server_listen_local (server, (guint) opts->listen_port, 0, error)) {
    g_object_unref (server);
    return NULL;
  }

  return server;
}
#endif
