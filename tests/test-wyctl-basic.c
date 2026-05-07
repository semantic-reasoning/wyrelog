/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <gio/gio.h>
#include <string.h>

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
    "--daemon-url",
    "http://127.0.0.1:1",
    "--timeout-ms",
    "100",
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
  g_test_add_func ("/wyctl/status-requires-daemon-url",
      test_status_requires_daemon_url);
  g_test_add_func ("/wyctl/status-rejects-invalid-daemon-url",
      test_status_rejects_invalid_daemon_url);

  return g_test_run ();
}
