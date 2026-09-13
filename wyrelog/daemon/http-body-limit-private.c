/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "http-body-limit-private.h"
#include <string.h>

#include "wyrelog/wyl-request-id-private.h"

#define BODY_LIMIT_KEY "wyl-http-body-limit"
#define DEFAULT_BODY_LIMIT (1024 * 1024)

static gboolean
under_path (const gchar *path, const gchar *prefix)
{
  gsize length = strlen (prefix);
  return g_str_has_prefix (path, prefix)
         && (path[length] == '\0' || path[length] == '/');
}

static gsize
body_limit (const gchar *path, const gchar *method)
{
  if (g_str_equal (path, "/profile/events")
      || g_str_equal (path, "/tenants/seal"))
    return 1024;
  if (under_path (path, "/datalog")
      || g_str_equal (path, "/auth/service-token"))
    return 16 * 1024;
  if (under_path (path, "/facts") && g_str_has_suffix (path, ":forget"))
    return 4096;
  if (g_str_equal (path, "/auth/mfa/enroll/start")
      || g_str_equal (path, "/auth/mfa/enroll/confirm")
      || under_path (path, "/service-credential-operations"))
    return 4096;
  if (under_path (path, "/service-credentials"))
    return g_str_equal (method, "DELETE") ? 1024 : 4096;
  if (under_path (path, "/service-principals"))
    return g_str_has_suffix (path, "/disable") ? 1024 : 4096;
  return DEFAULT_BODY_LIMIT;
}

gboolean
wyl_daemon_http_write_body_limit_response (GOutputStream *output,
    const gchar *response, gsize length)
{
  if (!G_IS_POLLABLE_OUTPUT_STREAM (output)
      || !g_pollable_output_stream_can_poll (G_POLLABLE_OUTPUT_STREAM (output)))
    return FALSE;
  gsize offset = 0;
  while (offset < length) {
    gssize written = g_pollable_output_stream_write_nonblocking (
      G_POLLABLE_OUTPUT_STREAM (output), response + offset,
      length - offset, NULL, NULL);
    if (written <= 0)
      return FALSE;
    offset += (gsize) written;
  }
  return TRUE;
}

static void
reject_body (SoupServerMessage *msg)
{
  /* This listener is plaintext HTTP/1. Stealing ends libsoup's reads even
   * without Expect: 100-continue, which setting a status alone does not do.
   * Capture everything first: stealing may release the message. */
  SoupHTTPVersion version = soup_server_message_get_http_version (msg);
  gboolean plaintext = g_strcmp0 (g_uri_get_scheme (
            soup_server_message_get_uri (msg)), "http") == 0;
  g_autoptr (GSocket) socket = g_object_ref (soup_server_message_get_socket (msg));
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gboolean have_id = wyl_request_id_new (request_id, sizeof request_id)
      == WYRELOG_E_OK;
  static const gchar body[] = "{\"error\":\"request_body_too_large\"}";
  g_autofree gchar *response = have_id ? g_strdup_printf (
    "%s 413 Content Too Large\r\n"
    "Connection: close\r\nContent-Type: application/json\r\n"
    "X-Wyrelog-Request-Id: %s\r\nContent-Length: %" G_GSIZE_FORMAT
    "\r\n\r\n%s", version == SOUP_HTTP_1_0 ? "HTTP/1.0" : "HTTP/1.1",
    request_id, sizeof body - 1, body) : NULL;
  SoupMessageBody *request = soup_server_message_get_request_body (msg);
  soup_message_body_truncate (request);
  soup_message_body_set_accumulate (request, FALSE);
  g_autoptr (GIOStream) stream = soup_server_message_steal_connection (msg);
  if (stream == NULL)
    return;

  /* Never wait for a client to read the error, nor retain pending writes.
   * Positive writes strictly advance through this bounded response. */
  GOutputStream *output = g_io_stream_get_output_stream (stream);
  if (response != NULL && plaintext
      && (version == SOUP_HTTP_1_0 || version == SOUP_HTTP_1_1))
    wyl_daemon_http_write_body_limit_response (output, response, strlen (response));
  /* Closing the socket directly cannot perform a blocking graceful/TLS
   * shutdown, including on response failure or an unsupported stream. */
  g_socket_close (socket, NULL);
}

static void
body_headers (SoupServerMessage *msg, gpointer unused)
{
  (void) unused;
  GUri *uri = soup_server_message_get_uri (msg);
  const gchar *path = g_uri_get_path (uri);
  g_autofree gchar *decoded = NULL;
  if (g_uri_get_flags (uri) & G_URI_FLAGS_ENCODED_PATH) {
    decoded = g_uri_unescape_string (path, NULL);
    if (decoded != NULL)
      path = decoded;
  }
  gsize limit = body_limit (path, soup_server_message_get_method (msg));
  g_object_set_data (G_OBJECT (msg), BODY_LIMIT_KEY, GSIZE_TO_POINTER (limit));
  SoupMessageHeaders *headers = soup_server_message_get_request_headers (msg);
  if (soup_message_headers_get_content_length (headers) > (goffset) limit)
    reject_body (msg);
}

static void
body_chunk (SoupServerMessage *msg, GBytes *chunk, gpointer unused)
{
  (void) chunk;
  (void) unused;
  gsize limit = GPOINTER_TO_SIZE (g_object_get_data (G_OBJECT (msg), BODY_LIMIT_KEY));
  if (soup_server_message_get_request_body (msg)->length > (goffset) limit)
    reject_body (msg);
}

static void
body_started (SoupServer *server, SoupServerMessage *msg, gpointer unused)
{
  (void) server;
  (void) unused;
  g_signal_connect (msg, "got-headers", G_CALLBACK (body_headers), NULL);
  g_signal_connect (msg, "got-chunk", G_CALLBACK (body_chunk), NULL);
}

void
wyl_daemon_http_install_body_limit (SoupServer *server)
{
  g_return_if_fail (SOUP_IS_SERVER (server));
  if (g_object_get_data (G_OBJECT (server), BODY_LIMIT_KEY) != NULL)
    return;
  g_object_set_data (G_OBJECT (server), BODY_LIMIT_KEY, GINT_TO_POINTER (1));
  g_signal_connect (server, "request-started", G_CALLBACK (body_started), NULL);
}
