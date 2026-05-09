/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <string.h>
#include <sys/wait.h>

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

static void
run_child (gchar **argv, gchar **stdout_buf, gchar **stderr_buf,
    gint *wait_status)
{
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

static gboolean
wait_status_is_success (gint wait_status)
{
  g_autoptr (GError) error = NULL;

  if (g_spawn_check_wait_status (wait_status, &error))
    return TRUE;

  g_clear_error (&error);
  return FALSE;
}

static void
test_version (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "--version", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (stdout_buf);
  g_assert_cmpstr (stdout_buf, !=, "");
  g_assert_null (strchr (stdout_buf, ' '));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_status_connection_failure (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "status",
    "--daemon-url",
    "http://127.0.0.1:1",
    "--timeout-ms",
    "100",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: daemon unavailable:"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "backtrace"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "assertion"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "tracker"));
}

static void
assert_status_invalid_timeout (const gchar *timeout_ms)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "--timeout-ms",
    (gchar *) timeout_ms,
    "status",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid timeout"));
}

static void
test_status_rejects_invalid_timeout (void)
{
  assert_status_invalid_timeout ("0");
  assert_status_invalid_timeout ("-1");
  assert_status_invalid_timeout ("abc");
  assert_status_invalid_timeout ("60001");
}

typedef struct
{
  GSocketListener *listener;
} SlowHealthzServer;

typedef struct
{
  GSocketListener *listener;
  guint status;
  const gchar *body;
  gchar *request;
} StatusProbeServer;

static gpointer
slow_healthz_server_thread (gpointer data)
{
  SlowHealthzServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, NULL, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[512];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));

  (void) g_input_stream_read (input, buffer, sizeof buffer, NULL, NULL);
  g_usleep (250 * 1000);
  (void) g_output_stream_write (output,
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 40, NULL, NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);

  return NULL;
}

static gpointer
status_probe_server_thread (gpointer data)
{
  StatusProbeServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, NULL, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[1024];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
  gssize n = g_input_stream_read (input, buffer, sizeof buffer - 1, NULL, NULL);
  if (n > 0) {
    buffer[n] = '\0';
    server->request = g_strdup (buffer);
  }

  const gchar *body = server->body != NULL ? server->body : "{}";
  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 %u OK\r\nContent-Type: application/json\r\n"
      "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
      server->status, strlen (body), body);
  (void) g_output_stream_write (output, response, strlen (response), NULL,
      NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static gchar *
listen_url_for_test_server (GSocketListener **out_listener)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
          G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
          &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
      (effective_address));
  *out_listener = g_steal_pointer (&listener);
  return g_strdup_printf ("http://127.0.0.1:%u", port);
}

static void
test_status_times_out (void)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
          G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
          &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
      (effective_address));
  g_autofree gchar *daemon_url = g_strdup_printf ("http://127.0.0.1:%u", port);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "50",
    "status",
    NULL,
  };
  SlowHealthzServer server = {.listener = listener };
  GThread *server_thread = g_thread_new ("slow-healthz",
      slow_healthz_server_thread, &server);
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: daemon unavailable:"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "backtrace"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "assertion"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "tracker"));
}

static void
run_status_readiness_case (guint status, const gchar *body,
    const gchar *expected_output, gboolean expect_success,
    const gchar *expected_error)
{
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_test_server (&listener);
  StatusProbeServer server = {
    .listener = listener,
    .status = status,
    .body = body,
  };
  GThread *server_thread = g_thread_new ("status-readiness",
      status_probe_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "status",
    "--readiness",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_cmpint (wait_status_is_success (wait_status), ==, expect_success);
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  if (expected_error == NULL)
    g_assert_cmpstr (stderr_buf, ==, "");
  else
    g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_error));
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "GET /readyz?format=json"));

  g_free (server.request);
}

static void
test_status_readiness (void)
{
  run_status_readiness_case (200, "{\"status\":\"ready\"}", "status=ready\n",
      TRUE, NULL);
  run_status_readiness_case (503,
      "{\"status\":\"not_ready\",\"reason\":\"delta_not_ready\"}",
      "status=not_ready reason=delta_not_ready\n", FALSE, NULL);
  run_status_readiness_case (200, "{\"status\":\"ok\"}", "",
      FALSE, "wyctl: daemon readiness failed");
  run_status_readiness_case (200, "not-json {\"status\":\"ready\"}", "",
      FALSE, "wyctl: daemon readiness failed");
  run_status_readiness_case (503,
      "{\"status\":\"not_ready\",\"reason\":\"unknown\"}", "",
      FALSE, "wyctl: daemon unavailable:");
}

static void
test_status_requires_daemon_url (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "status", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));
}

static void
test_status_rejects_invalid_daemon_url (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "not-a-url",
    "status",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (stderr_buf);
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));
}

static void
test_status_help_command_first (void)
{
  gchar *argv[] = { WYL_TEST_WYCTL_PATH, "status", "--help", NULL };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--daemon-url"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--readiness"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_policy_help (void)
{
  gchar *check_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--help",
    NULL,
  };
  gchar *explain_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "explain",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (check_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--permission"));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (explain_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--resource"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_audit_help (void)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "query",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
test_audit_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-audit-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "file:///tmp/wyrelog",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *invalid_limit_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--limit",
    "0",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *extra_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "extra",
    NULL,
  };
  gchar *valid_scaffold_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--filter",
    "decision=deny",
    "--limit",
    "10",
    NULL,
  };
  gchar *unknown_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "audit",
    "unknown",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_limit_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid --limit"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (extra_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: unexpected audit query argument"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (valid_scaffold_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: audit query failed"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unknown_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: unknown audit command"));

  g_unlink (token_path);
}

static void
test_policy_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autofree gchar *empty_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-empty-token-XXXXXX", &empty_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));

  g_autofree gchar *invalid_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-invalid-token-XXXXXX", &invalid_token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (invalid_token_path, "token-1\nbad\n",
          -1, &error));
  g_assert_no_error (error);

  g_autofree gchar *nul_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-nul-token-XXXXXX", &nul_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  {
    const gchar token_with_nul[] = { 't', 'o', 'k', 'e', 'n', '\0', 'b' };
    g_assert_true (g_file_set_contents (nul_token_path, token_with_nul,
            sizeof token_with_nul, &error));
    g_assert_no_error (error);
  }

  g_autofree gchar *leading_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-leading-token-XXXXXX", &leading_token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (leading_token_path, "\ntoken-1\n", -1,
          &error));
  g_assert_no_error (error);

  g_autofree gchar *trailing_blank_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-trailing-token-XXXXXX",
      &trailing_blank_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (trailing_blank_token_path,
          "token-1\n\n", -1, &error));
  g_assert_no_error (error);

  g_autofree gchar *space_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-space-token-XXXXXX", &space_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (space_token_path, " token-1\n", -1,
          &error));
  g_assert_no_error (error);

  gchar *missing_resource_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--access-token-file",
    token_path,
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    NULL,
  };
  gchar *unreadable_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    "/nonexistent/wyctl-token",
    NULL,
  };
  gchar *empty_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    empty_token_path,
    NULL,
  };
  gchar *invalid_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    invalid_token_path,
    NULL,
  };
  gchar *nul_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    nul_token_path,
    NULL,
  };
  gchar *leading_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    leading_token_path,
    NULL,
  };
  gchar *trailing_blank_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    trailing_blank_token_path,
    NULL,
  };
  gchar *space_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    space_token_path,
    NULL,
  };
  gchar *valid_scaffold_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    NULL,
  };
  gchar *unknown_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "unknown",
    NULL,
  };
  gchar *extra_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "check",
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    "extra",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_resource_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --resource"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unreadable_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: unable to read access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (empty_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: empty access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (leading_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (trailing_blank_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (space_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (nul_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid access token file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (valid_scaffold_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (unknown_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: unknown policy command"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (extra_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: unexpected policy check argument"));

  g_unlink (token_path);
  g_unlink (empty_token_path);
  g_unlink (invalid_token_path);
  g_unlink (nul_token_path);
  g_unlink (leading_token_path);
  g_unlink (trailing_blank_token_path);
  g_unlink (space_token_path);
}

typedef struct
{
  GSocketListener *listener;
  const gchar *response_body;
  guint delay_us;
  gchar *request;
} PolicyCheckServer;

static gpointer
policy_check_server_thread (gpointer data)
{
  PolicyCheckServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, NULL, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[4096];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
  gssize n = g_input_stream_read (input, buffer, sizeof buffer - 1, NULL, NULL);
  if (n > 0) {
    buffer[n] = '\0';
    server->request = g_strdup (buffer);
  }
  if (server->delay_us > 0)
    g_usleep (server->delay_us);

  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
      "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
      strlen (server->response_body), server->response_body);
  (void) g_output_stream_write (output, response, strlen (response), NULL,
      NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static gchar *
listen_url_for_policy_server (GSocketListener **out_listener)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketListener) listener = g_socket_listener_new ();
  g_autoptr (GInetAddress) address =
      g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);
  g_autoptr (GSocketAddress) socket_address =
      g_inet_socket_address_new (address, 0);
  g_autoptr (GSocketAddress) effective_address = NULL;

  g_assert_true (g_socket_listener_add_address (listener, socket_address,
          G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_TCP, NULL, &effective_address,
          &error));
  g_assert_no_error (error);

  guint16 port =
      g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS
      (effective_address));
  *out_listener = g_steal_pointer (&listener);
  return g_strdup_printf ("http://127.0.0.1:%u", port);
}

static void
run_policy_decision_case (const gchar *command, const gchar *response_body,
    const gchar *expected_output, gboolean expect_success, guint delay_us,
    const gchar *timeout_ms)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyCheckServer server = {
    .listener = listener,
    .response_body = response_body,
    .delay_us = delay_us,
  };
  GThread *server_thread = g_thread_new ("policy-check",
      policy_check_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    (gchar *) timeout_ms,
    "policy",
    (gchar *) command,
    "--user",
    "alice",
    "--permission",
    "wr.audit.read",
    "--resource",
    "doc/42",
    "--access-token-file",
    token_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_cmpint (wait_status_is_success (wait_status), ==, expect_success);
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  if (expected_output[0] != '\0')
    g_assert_cmpstr (stderr_buf, ==, "");
  else {
    g_autofree gchar *failure = g_strdup_printf ("wyctl: policy %s failed",
        command);
    g_assert_nonnull (g_strstr_len (stderr_buf, -1, failure));
  }
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1, "POST /decide?"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "user=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "perm=wr.audit.read"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "session_token=doc%2F42"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_check (void)
{
  run_policy_decision_case
      ("check", "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}",
      "allow\n", TRUE, 0, "1000");
  run_policy_decision_case ("check",
      "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}", "deny\n", FALSE, 0, "1000");
  run_policy_decision_case ("check",
      "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}", "", FALSE,
      250 * 1000, "50");
  run_policy_decision_case ("explain",
      "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}",
      "deny\nreason=missing_grant\norigin=policy\n", TRUE, 0, "1000");
}

static void
run_audit_query_case (const gchar *response_body, const gchar *expected_output,
    guint delay_us, const gchar *timeout_ms, const gchar *limit)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-audit-token-XXXXXX", &token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyCheckServer server = {
    .listener = listener,
    .response_body = response_body,
    .delay_us = delay_us,
  };
  GThread *server_thread = g_thread_new ("audit-query",
      policy_check_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    (gchar *) timeout_ms,
    "audit",
    "query",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    "--filter",
    "decision=deny",
    "--limit",
    (gchar *) limit,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_cmpint (wait_status_is_success (wait_status),
      ==, expected_output[0] != '\0');
  g_assert_cmpstr (stdout_buf, ==, expected_output);
  if (expected_output[0] != '\0')
    g_assert_cmpstr (stderr_buf, ==, "");
  else
    g_assert_nonnull (g_strstr_len (stderr_buf, -1,
            "wyctl: audit query failed"));
  g_assert_nonnull (server.request);
  g_assert_nonnull (g_strstr_len (server.request, -1, "GET /audit/events?"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "filter=decision%3Ddeny"));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_audit_query (void)
{
  run_audit_query_case
      ("[{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d001\","
      "\"created_at_us\":1234567,"
      "\"subject_id\":\"ali\\nce\","
      "\"action\":\"read\","
      "\"resource_id\":\"doc/42\","
      "\"deny_reason\":null,"
      "\"deny_origin\":null,"
      "\"request_id\":null,"
      "\"decision\":1},"
      "{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d002\","
      "\"created_at_us\":1234568,"
      "\"subject_id\":\"bob\","
      "\"action\":\"write\","
      "\"resource_id\":\"doc/43\","
      "\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\","
      "\"request_id\":\"req-audit\","
      "\"decision\":0}]",
      "[{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d001\","
      "\"created_at_us\":1234567,"
      "\"subject_id\":\"ali\\nce\","
      "\"action\":\"read\","
      "\"resource_id\":\"doc/42\","
      "\"deny_reason\":null,"
      "\"deny_origin\":null,"
      "\"request_id\":null," "\"decision\":1}]\n", 0, "1000", "1");
  run_audit_query_case ("[]", "[]\n", 0, "1000", "100");
  run_audit_query_case ("[]", "", 250 * 1000, "50", "100");
}

typedef struct
{
  GSocketListener *listener;
  guint status;
  const gchar *body;
  gchar *request;
} PolicyMutationServer;

static gpointer
policy_mutation_server_thread (gpointer data)
{
  PolicyMutationServer *server = data;
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) conn =
      g_socket_listener_accept (server->listener, NULL, NULL, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[4096];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
  gssize n = g_input_stream_read (input, buffer, sizeof buffer - 1, NULL, NULL);
  if (n > 0) {
    buffer[n] = '\0';
    server->request = g_strdup (buffer);
  }

  const gchar *body = server->body != NULL ? server->body : "{}";
  g_autofree gchar *response =
      g_strdup_printf ("HTTP/1.1 %u OK\r\nContent-Type: application/json\r\n"
      "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
      server->status, strlen (body), body);
  (void) g_output_stream_write (output, response, strlen (response), NULL,
      NULL);
  (void) g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
  return NULL;
}

static void
test_policy_permission_help (void)
{
  gchar *grant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-grant",
    "--help",
    NULL,
  };
  gchar *revoke_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-revoke",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (grant_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (revoke_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
run_policy_permission_success_case (const gchar *command, const gchar *path)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyMutationServer server = {
    .listener = listener,
    .status = 200,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
      policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "ok\n");
  g_assert_cmpstr (stderr_buf, ==, "");
  g_assert_nonnull (server.request);
  g_autofree gchar *expected_request_line = g_strdup_printf ("POST %s?", path);
  g_assert_nonnull (g_strstr_len (server.request, -1, expected_request_line));
  g_assert_nonnull (g_strstr_len (server.request, -1, "subject=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "perm=wr.audit.read"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "scope=tenant%2Fa"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_permission_grant_success (void)
{
  run_policy_permission_success_case ("permission-grant",
      "/policy/permissions/grant");
}

static void
test_policy_permission_revoke_success (void)
{
  run_policy_permission_success_case ("permission-revoke",
      "/policy/permissions/revoke");
}

static void
run_policy_permission_status_case (const gchar *command, guint status,
    gint expected_exit, const gchar *expected_stderr_marker)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyMutationServer server = {
    .listener = listener,
    .status = status,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
      policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_stderr_marker));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_permission_grant_status_errors (void)
{
  run_policy_permission_status_case ("permission-grant", 400, 3,
      "wyctl: policy permission-grant failed: invalid_policy_mutation");
  run_policy_permission_status_case ("permission-grant", 401, 6,
      "wyctl: policy permission-grant failed: policy_auth_required");
  run_policy_permission_status_case ("permission-grant", 403, 4,
      "wyctl: policy permission-grant failed: policy_mutation_denied");
  run_policy_permission_status_case ("permission-grant", 500, 5,
      "wyctl: policy permission-grant failed: policy_mutation_failed");
}

static void
test_policy_permission_revoke_status_errors (void)
{
  run_policy_permission_status_case ("permission-revoke", 400, 3,
      "wyctl: policy permission-revoke failed: invalid_policy_mutation");
  run_policy_permission_status_case ("permission-revoke", 401, 6,
      "wyctl: policy permission-revoke failed: policy_auth_required");
  run_policy_permission_status_case ("permission-revoke", 403, 4,
      "wyctl: policy permission-revoke failed: policy_mutation_denied");
  run_policy_permission_status_case ("permission-revoke", 500, 5,
      "wyctl: policy permission-revoke failed: policy_mutation_failed");
}

static void
test_policy_permission_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-perm-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_perm_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_scope_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "permission-grant",
    "--subject",
    "alice",
    "--perm",
    "wr.audit.read",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_subject_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --subject"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_perm_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --perm"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_scope_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --scope"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_unlink (token_path);
}

static void
test_policy_role_help (void)
{
  gchar *grant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-grant",
    "--help",
    NULL,
  };
  gchar *revoke_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-revoke",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (grant_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--role"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_cmpstr (stderr_buf, ==, "");

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (revoke_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--role"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--scope"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--access-token-file"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-timestamp"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-loc-class"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--guard-risk"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--access-token "));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--perm"));
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
run_policy_role_success_case (const gchar *command, const gchar *path)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyMutationServer server = {
    .listener = listener,
    .status = 200,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
      policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_true (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "ok\n");
  g_assert_cmpstr (stderr_buf, ==, "");
  g_assert_nonnull (server.request);
  g_autofree gchar *expected_request_line = g_strdup_printf ("POST %s?", path);
  g_assert_nonnull (g_strstr_len (server.request, -1, expected_request_line));
  g_assert_nonnull (g_strstr_len (server.request, -1, "subject=alice"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "role=wr.audit.reader"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "scope=tenant%2Fa"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "tenant=__wr_default"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_timestamp=123"));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "guard_loc_class=public"));
  g_assert_nonnull (g_strstr_len (server.request, -1, "guard_risk=69"));
  g_assert_null (g_strstr_len (server.request, -1, "session_token="));
  g_assert_nonnull (g_strstr_len (server.request, -1,
          "Authorization: Bearer token-1"));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_role_grant_success (void)
{
  run_policy_role_success_case ("role-grant", "/policy/roles/grant");
}

static void
test_policy_role_revoke_success (void)
{
  run_policy_role_success_case ("role-revoke", "/policy/roles/revoke");
}

static void
run_policy_role_status_case (const gchar *command, guint status,
    gint expected_exit, const gchar *expected_stderr_marker)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  PolicyMutationServer server = {
    .listener = listener,
    .status = status,
    .body = "{}",
  };
  GThread *server_thread = g_thread_new ("policy-mutation",
      policy_mutation_server_thread, &server);
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    daemon_url,
    "--timeout-ms",
    "1000",
    "policy",
    (gchar *) command,
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_thread_join (server_thread);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, expected_stderr_marker));

  g_free (server.request);
  g_unlink (token_path);
}

static void
test_policy_role_grant_status_errors (void)
{
  run_policy_role_status_case ("role-grant", 400, 3,
      "wyctl: policy role-grant failed: invalid_policy_mutation");
  run_policy_role_status_case ("role-grant", 401, 6,
      "wyctl: policy role-grant failed: policy_auth_required");
  run_policy_role_status_case ("role-grant", 403, 4,
      "wyctl: policy role-grant failed: policy_mutation_denied");
  run_policy_role_status_case ("role-grant", 500, 5,
      "wyctl: policy role-grant failed: policy_mutation_failed");
}

static void
test_policy_role_revoke_status_errors (void)
{
  run_policy_role_status_case ("role-revoke", 400, 3,
      "wyctl: policy role-revoke failed: invalid_policy_mutation");
  run_policy_role_status_case ("role-revoke", 401, 6,
      "wyctl: policy role-revoke failed: policy_auth_required");
  run_policy_role_status_case ("role-revoke", 403, 4,
      "wyctl: policy role-revoke failed: policy_mutation_denied");
  run_policy_role_status_case ("role-revoke", 500, 5,
      "wyctl: policy role-revoke failed: policy_mutation_failed");
}

static void
test_policy_role_validation (void)
{
  g_autofree gchar *token_path = NULL;
  g_autoptr (GError) error = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-role-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, "token-1\n", -1, &error));
  g_assert_no_error (error);

  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_role_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_scope_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_token_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *missing_timestamp_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_loc_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "unknown",
    "--guard-risk",
    "69",
    NULL,
  };
  gchar *invalid_risk_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url",
    "http://127.0.0.1:1",
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "101",
    NULL,
  };
  gchar *missing_daemon_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "policy",
    "role-grant",
    "--subject",
    "alice",
    "--role",
    "wr.audit.reader",
    "--scope",
    "tenant/a",
    "--access-token-file",
    token_path,
    "--guard-timestamp",
    "123",
    "--guard-loc-class",
    "public",
    "--guard-risk",
    "69",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (missing_subject_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --subject"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_role_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --role"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_scope_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing --scope"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_token_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: missing --access-token-file"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_timestamp_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-timestamp"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_loc_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-loc-class"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (invalid_risk_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "wyctl: invalid --guard-risk"));

  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (missing_daemon_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));

  g_unlink (token_path);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/wyctl/version", test_version);
  g_test_add_func ("/wyctl/status-connection-failure",
      test_status_connection_failure);
  g_test_add_func ("/wyctl/status-rejects-invalid-timeout",
      test_status_rejects_invalid_timeout);
  g_test_add_func ("/wyctl/status-times-out", test_status_times_out);
  g_test_add_func ("/wyctl/status-readiness", test_status_readiness);
  g_test_add_func ("/wyctl/status-requires-daemon-url",
      test_status_requires_daemon_url);
  g_test_add_func ("/wyctl/status-rejects-invalid-daemon-url",
      test_status_rejects_invalid_daemon_url);
  g_test_add_func ("/wyctl/status-help-command-first",
      test_status_help_command_first);
  g_test_add_func ("/wyctl/policy-help", test_policy_help);
  g_test_add_func ("/wyctl/policy-validation", test_policy_validation);
  g_test_add_func ("/wyctl/policy-check", test_policy_check);
  g_test_add_func ("/wyctl/policy-permission-help",
      test_policy_permission_help);
  g_test_add_func ("/wyctl/policy-permission-validation",
      test_policy_permission_validation);
  g_test_add_func ("/wyctl/policy-permission-grant-success",
      test_policy_permission_grant_success);
  g_test_add_func ("/wyctl/policy-permission-revoke-success",
      test_policy_permission_revoke_success);
  g_test_add_func ("/wyctl/policy-permission-grant-status-errors",
      test_policy_permission_grant_status_errors);
  g_test_add_func ("/wyctl/policy-permission-revoke-status-errors",
      test_policy_permission_revoke_status_errors);
  g_test_add_func ("/wyctl/policy-role-help", test_policy_role_help);
  g_test_add_func ("/wyctl/policy-role-validation",
      test_policy_role_validation);
  g_test_add_func ("/wyctl/policy-role-grant-success",
      test_policy_role_grant_success);
  g_test_add_func ("/wyctl/policy-role-revoke-success",
      test_policy_role_revoke_success);
  g_test_add_func ("/wyctl/policy-role-grant-status-errors",
      test_policy_role_grant_status_errors);
  g_test_add_func ("/wyctl/policy-role-revoke-status-errors",
      test_policy_role_revoke_status_errors);
  g_test_add_func ("/wyctl/audit-help", test_audit_help);
  g_test_add_func ("/wyctl/audit-validation", test_audit_validation);
  g_test_add_func ("/wyctl/audit-query", test_audit_query);

  return g_test_run ();
}
