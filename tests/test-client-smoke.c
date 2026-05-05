/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>

#include "wyrelog/audit/iter-private.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-client-private.h"

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;

  g_main_loop_run (http->loop);
  return NULL;
}

static void
test_http_server_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  (void) user_data;

  const gchar *body = "[]";
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      body, strlen (body));
}

int
main (void)
{
  const gchar *version = wyrelog_client_version_string ();
  if (version == NULL || version[0] == '\0')
    return 1;

  g_autoptr (WylClient) client = NULL;

  /* Input validation: NULL out_client must be rejected. */
  if (wyl_client_new ("http://example.invalid", NULL) != WYRELOG_E_INVALID)
    return 2;
  if (wyl_client_new (NULL, &client) != WYRELOG_E_INVALID)
    return 9;
  if (wyl_client_new ("", &client) != WYRELOG_E_INVALID)
    return 10;
  if (wyl_client_new ("file:///tmp/wyrelog.sock", &client) != WYRELOG_E_INVALID)
    return 11;

  /* Successful path returns a non-NULL WylClient. */
  client = NULL;
  if (wyl_client_new ("http://example.invalid", &client) != WYRELOG_E_OK)
    return 3;
  if (client == NULL)
    return 4;
  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (g_strcmp0 (base_url, "http://example.invalid") != 0)
    return 12;
  if (wyl_client_get_soup_session (client) == NULL)
    return 17;

  /* Audit iterator returns a non-NULL WylAuditIter on success and
   * yields no rows in the stub state. */
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (NULL, NULL, &iter) != WYRELOG_E_INVALID)
    return 13;
  if (wyl_client_audit_query (client, NULL, NULL) != WYRELOG_E_INVALID)
    return 14;
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return 5;
  if (iter == NULL)
    return 6;
  g_autofree gchar *query_filter = wyl_audit_iter_dup_query_filter (iter);
  if (g_strcmp0 (query_filter, "decision=deny") != 0)
    return 15;
  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  if (g_strcmp0 (request_uri,
          "http://example.invalid/audit/events?filter=decision%3Ddeny") != 0)
    return 16;
  g_autoptr (SoupMessage) message = wyl_audit_iter_new_request_message (iter);
  if (message == NULL)
    return 18;
  if (g_strcmp0 (soup_message_get_method (message), "GET") != 0)
    return 19;
  g_autofree gchar *message_uri =
      g_uri_to_string (soup_message_get_uri (message));
  if (g_strcmp0 (message_uri, request_uri) != 0)
    return 20;

  TestHttpServer http = { 0 };
  http.server = soup_server_new (NULL, NULL);
  http.loop = g_main_loop_new (NULL, FALSE);
  soup_server_add_handler (http.server, NULL, test_http_server_handler, NULL,
      NULL);
  g_autoptr (GError) listen_error = NULL;
  if (!soup_server_listen_local (http.server, 0, 0, &listen_error))
    return 21;
  GThread *thread = g_thread_new ("client-smoke-http",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 22;
  g_autofree gchar *local_base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) local_client = NULL;
  if (wyl_client_new (local_base_url, &local_client) != WYRELOG_E_OK)
    return 23;
  g_autoptr (WylAuditIter) local_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &local_iter) != WYRELOG_E_OK)
    return 24;
  g_autoptr (SoupMessage) local_message =
      wyl_audit_iter_new_request_message (local_iter);
  g_autoptr (GBytes) body = NULL;
  if (wyl_client_send_message (local_client, local_message, &body) !=
      WYRELOG_E_OK)
    return 25;
  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  if (body_size != 2 || memcmp (body_data, "[]", 2) != 0)
    return 26;

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return 7;
  if (has_next)
    return 8;
  has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return 27;
  if (has_next)
    return 28;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);

  return 0;
}
