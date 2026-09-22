/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 chmod-mode-t and the write(2)/symlink(2) syscalls
 * the resolver / token-file fan-out tests use under strict c_std=c17.
 * Must precede every system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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

static void
run_child_with_env (gchar **argv, gchar **envp, gchar **stdout_buf,
    gchar **stderr_buf, gint *wait_status)
{
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, envp, G_SPAWN_DEFAULT, NULL, NULL,
      stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

/* Report what the child actually printed when an expected diagnostic is
 * missing.  The bare assertion says only that a substring was absent, which
 * is the least useful half of the evidence (#1186). */
static void
assert_child_stderr_has (const gchar *stderr_buf, const gchar *needle)
{
  if (stderr_buf != NULL && g_strstr_len (stderr_buf, -1, needle) != NULL)
    return;
  g_printerr ("expected \"%s\" on the child's stderr, which was: %s\n",
      needle, stderr_buf != NULL ? stderr_buf : "(null)");
  g_assert_not_reached ();
}

/* A keyfile fixture only means anything if wyctl can find the
 * org.wyrelog.wyctl schema.  wyctl looks it up in the default schema source
 * without recursing into parent sources (wyctl_open_settings), so this
 * mirrors that lookup exactly; a recursive one would accept environments
 * wyctl itself rejects.  The source covers GSETTINGS_SCHEMA_DIR, which meson
 * points at this build's compiled schema, and the data dirs, where an
 * installed wyrelog ships one -- whichever of those it resolves to first.
 *
 * With no schema reachable there, wyctl reports "missing daemon URL" rather
 * than reading the fixture, and only status-gsettings-supplies-daemon-url
 * notices: it fails on its own downstream assertion, which reads as a
 * resolver bug and is what #1186 recorded as an unexplained failure.  Every
 * other fixture case passes while proving nothing -- the kill-switch case
 * because "missing daemon URL" is precisely what it asserts, the
 * CLI-override case because its URL comes from the command line either way,
 * and the four subcommand cases because they exit at option parsing before
 * any resolution.  Abort here instead, naming the cause: a skip would be
 * counted as a pass, and in a correct environment this cannot fire. */
static void
assert_wyctl_gsettings_schema_available (void)
{
  GSettingsSchemaSource *source = g_settings_schema_source_get_default ();
  g_autoptr (GSettingsSchema) schema = source != NULL
      ? g_settings_schema_source_lookup (source, "org.wyrelog.wyctl", FALSE)
      : NULL;
  if (schema != NULL)
    return;
  const gchar *dir = g_getenv ("GSETTINGS_SCHEMA_DIR");
  g_printerr ("wyctl cannot reach the org.wyrelog.wyctl GSettings schema in "
      "this environment, so the keyfile fixture below would prove nothing "
      "(GSETTINGS_SCHEMA_DIR=%s).  Run this test through meson, which points "
      "the schema source at the compiled schema.\n",
      dir != NULL ? dir : "(unset)");
  g_assert_not_reached ();
}

/* Build a temporary XDG_CONFIG_HOME directory that holds a GSettings
 * keyfile with the supplied org.wyrelog.wyctl values, and return the
 * directory path (owned by caller). Caller must remove the directory
 * tree when done. Both key and value arrays are NULL-terminated and
 * must have matching length; values are stringified GVariant
 * literals so the GSettings keyfile backend reads them as the
 * declared schema type. */
static gchar *
make_keyfile_xdg_dir (const gchar *const *keys, const gchar *const *values)
{
  assert_wyctl_gsettings_schema_available ();
  g_autoptr (GError) error = NULL;
  gchar *xdg = g_dir_make_tmp ("wyctl-xdg-XXXXXX", &error);
  g_assert_no_error (error);

  g_autofree gchar *settings_dir = g_build_filename (xdg, "glib-2.0",
          "settings", NULL);
  g_assert_cmpint (g_mkdir_with_parents (settings_dir, 0700), ==, 0);

  g_autofree gchar *keyfile_path = g_build_filename (settings_dir, "keyfile",
          NULL);
  g_autoptr (GKeyFile) keyfile = g_key_file_new ();
  for (gsize i = 0; keys != NULL && keys[i] != NULL; i++) {
    g_assert_nonnull (values[i]);
    g_key_file_set_string (keyfile, "org/wyrelog/wyctl", keys[i], values[i]);
  }
  g_assert_true (g_key_file_save_to_file (keyfile, keyfile_path, &error));
  g_assert_no_error (error);

  return xdg;
}

static gchar *
gvariant_literal_for_string (const gchar *value)
{
  g_autoptr (GVariant) variant = g_variant_new_string (value);
  return g_variant_print (variant, FALSE);
}

static void
remove_dir_recursive (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GFile) file = g_file_new_for_path (path);
  /* Walk and unlink children. Tests stage only files we wrote, so the
   * iteration is small. */
  g_autoptr (GFileEnumerator) en = g_file_enumerate_children (file,
          G_FILE_ATTRIBUTE_STANDARD_NAME ","
          G_FILE_ATTRIBUTE_STANDARD_TYPE, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
          NULL, &error);
  if (en != NULL) {
    while (TRUE) {
      g_autoptr (GFileInfo) info = g_file_enumerator_next_file (en, NULL,
              &error);
      if (info == NULL)
        break;
      g_autofree gchar *child = g_build_filename (path,
              g_file_info_get_name (info), NULL);
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        remove_dir_recursive (child);
      else
        g_unlink (child);
    }
  }
  g_clear_error (&error);
  g_rmdir (path);
}

/* Build an envp derived from the current process environment, with
 * GSettings pointed at the keyfile backend in xdg_dir. Caller frees
 * with g_strfreev. */
static gchar **
build_gsettings_envp (const gchar *xdg_dir, gboolean disable_gsettings)
{
  gchar **envp = g_get_environ ();
  envp = g_environ_setenv (envp, "XDG_CONFIG_HOME", xdg_dir, TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_BACKEND", "keyfile", TRUE);
  if (disable_gsettings)
    envp = g_environ_setenv (envp, "WYCTL_DISABLE_GSETTINGS", "1", TRUE);
  else
    envp = g_environ_unsetenv (envp, "WYCTL_DISABLE_GSETTINGS");
  return envp;
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

/*
 * Join a test server thread that may still be parked in
 * g_socket_listener_accept.  A server below returns on its own only once the
 * wyctl under test has connected.  The policy-check server, alone among
 * them, keeps accepting until a connection actually delivers a request; the
 * others answer whatever they get, so a bare connection is enough to let
 * them return with request still NULL.  The client need not connect at all:
 * one that fails locally, or that exhausts its request budget before the
 * connect completes, exits without ever touching the listener.  The accept
 * has no deadline of its own, so an unconditional join would block forever
 * and the whole binary would die on the meson timeout rather than fail a
 * case.  Cancelling first is what bounds it - the cancellable is the
 * documented, thread-safe way to break a blocking accept, whereas closing
 * the listener from another thread races with the accept itself.
 */
static void
stop_test_server (GThread *thread, GCancellable *cancel)
{
  g_cancellable_cancel (cancel);
  g_thread_join (thread);
}

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
} SlowHealthzServer;

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
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
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
  if (conn == NULL)
    return NULL;

  gchar buffer[512];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
  GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn));

  (void) g_input_stream_read (input, buffer, sizeof buffer, NULL, NULL);
  /* Longer than the client's budget below, so the case proves a wait for a
   * response that never came in time. wyctl reports a refused connect and a
   * cancelled request with the same "daemon unavailable" line, so only the
   * budget separates that proof from a child cancelled before it
   * connected. */
  g_usleep (1500 * 1000);
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
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
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
    "1000",
    "status",
    NULL,
  };
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  SlowHealthzServer server = {.listener = listener, .cancel = accept_cancel };
  GThread *server_thread = g_thread_new ("slow-healthz",
          slow_healthz_server_thread, &server);
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);

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
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  StatusProbeServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

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
  g_assert_cmpint (g_chmod (invalid_token_path, 0600), ==, 0);

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
    g_assert_cmpint (g_chmod (nul_token_path, 0600), ==, 0);
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
  g_assert_cmpint (g_chmod (leading_token_path, 0600), ==, 0);

  g_autofree gchar *trailing_blank_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-trailing-token-XXXXXX",
          &trailing_blank_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (trailing_blank_token_path,
      "token-1\n\n", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (trailing_blank_token_path, 0600), ==, 0);

  g_autofree gchar *space_token_path = NULL;
  fd = g_file_open_tmp ("wyctl-space-token-XXXXXX", &space_token_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (space_token_path, " token-1\n", -1,
      &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (space_token_path, 0600), ==, 0);

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
  /* Updated diagnostic from the typed token-file safety helper. */
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file not found"));

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
  GCancellable *cancel;
  const gchar *response_body;
  guint delay_us;
  gchar *request;
} PolicyCheckServer;

static gpointer
policy_check_server_thread (gpointer data)
{
  PolicyCheckServer *server = data;
  /*
   * The response below is written whether or not a request was captured, so
   * a connection that delivers nothing still lets the child succeed with
   * server->request left NULL -- which is how this raced in CI while every
   * earlier assertion in run_policy_decision_case passed. Keep accepting
   * until one connection actually delivers a request, and accumulate until
   * the header terminator arrives rather than trusting a single read to
   * return the whole thing.
   */
  gchar buffer[4096];
  gsize filled = 0;
  g_autoptr (GSocketConnection) conn = NULL;
  GInputStream *input = NULL;
  GOutputStream *output = NULL;
  while (filled == 0) {
    g_autoptr (GError) error = NULL;
    g_clear_object (&conn);
    conn = g_socket_listener_accept (server->listener, NULL, server->cancel,
            &error);
    if (conn == NULL)
      return NULL;
    input = g_io_stream_get_input_stream (G_IO_STREAM (conn));
    output = g_io_stream_get_output_stream (G_IO_STREAM (conn));
    while (filled < sizeof buffer - 1) {
      gssize n = g_input_stream_read (input, buffer + filled,
              sizeof buffer - 1 - filled, NULL, NULL);
      if (n <= 0)
        break;
      filled += (gsize) n;
      buffer[filled] = '\0';
      if (strstr (buffer, "\r\n\r\n") != NULL)
        break;
    }
  }
  buffer[filled] = '\0';
  server->request = g_strdup (buffer);
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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  /* This case asserts that the server recorded the request, so the child
   * needs a budget to connect and send on a contended runner: the client's
   * deadline starts before it connects and cancels the whole request, so a
   * 50 ms budget expired mid-connect under load and left nothing to record.
   * Give it the same 1000 ms the success cases assume and make the server
   * the slow side: it records the request first and only then delays past
   * that deadline. */
  run_policy_decision_case ("check",
      "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}", "", FALSE,
      1500 * 1000, "1000");
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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  /* Same budget rule as the policy-check timeout case: the server records
   * the request, then delays past the client's 1000 ms deadline. */
  run_audit_query_case ("[]", "", 1500 * 1000, "1000", "100");
}

typedef struct
{
  GSocketListener *listener;
  GCancellable *cancel;
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
      g_socket_listener_accept (server->listener, NULL, server->cancel, &error);
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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyMutationServer server = {
    .listener = listener,
    .cancel = accept_cancel,
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
  stop_test_server (server_thread, accept_cancel);

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
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);

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

static void
test_status_gsettings_supplies_daemon_url (void)
{
  /* When --daemon-url is omitted the resolver must read the URL from
   * GSettings and the daemon-unavailable diagnostic must reference
   * that URL (proving the resolver fed the probe). */
  g_autofree gchar *literal =
      gvariant_literal_for_string ("http://127.0.0.1:1");
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "status",
    "--timeout-ms",
    "100",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  remove_dir_recursive (xdg);

  g_assert_false (wait_status_is_success (wait_status));
  assert_child_stderr_has (stderr_buf,
      "wyctl: daemon unavailable: http://127.0.0.1:1");
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: missing daemon URL"));
}

/* The URL the two cases below put in the keyfile.  Loopback, so no name
 * resolution is involved; port 2 refuses at once, exactly as port 1 does for
 * the case above, which this suite has always depended on.  The path is
 * carried through verbatim by the daemon-unavailable diagnostic, which is
 * what makes the needle legible rather than a one-character difference from
 * the CLI URL. */
#define WYCTL_TEST_GSETTINGS_URL "http://127.0.0.1:2/from-gsettings"

/* Run `wyctl status' once against a keyfile holding
 * WYCTL_TEST_GSETTINGS_URL, with `extra_argv' spliced in after the
 * subcommand name, and hand back the child's stderr.  The fixture is torn
 * down before the caller asserts anything. */
static gchar *
run_status_against_gsettings_url (const gchar *const *extra_argv,
    gsize extra_argv_len, gboolean disable_gsettings, gint *wait_status)
{
  g_autofree gchar *literal =
      gvariant_literal_for_string (WYCTL_TEST_GSETTINGS_URL);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, disable_gsettings);

  GPtrArray *argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  g_ptr_array_add (argv, "status");
  for (gsize i = 0; i < extra_argv_len; i++)
    g_ptr_array_add (argv, (gpointer) extra_argv[i]);
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "100");
  g_ptr_array_add (argv, NULL);

  g_autofree gchar *stdout_buf = NULL;
  gchar *stderr_buf = NULL;
  run_child_with_env ((gchar **) argv->pdata, envp, &stdout_buf, &stderr_buf,
      wait_status);
  g_ptr_array_free (argv, TRUE);
  remove_dir_recursive (xdg);
  return stderr_buf;
}

static void
test_status_cli_overrides_gsettings (void)
{
  /* GSettings carries a URL we want to be ignored; the CLI value must win
   * and the diagnostic must mention the CLI URL.
   *
   * The control spawn is what makes that mean anything.  Asserting only
   * that the CLI URL appears and the GSettings one does not is satisfied
   * just as well by a keyfile nothing ever read, so the case used to pass
   * with the GSettings fallback deleted (#1189).  The control proves a
   * child of this test can read a keyfile built this way; the override
   * spawn then shows the CLI value displacing a value that was
   * demonstrably available.  Each spawn mints its own fixture directory
   * from the same keys, so what they share is the construction, not the
   * directory. */
  const gchar *override_argv[] = { "--daemon-url", "http://127.0.0.1:1" };
  gint control_status = 0;
  gint override_status = 0;

  g_autofree gchar *control_stderr =
      run_status_against_gsettings_url (NULL, 0, FALSE, &control_status);
  g_autofree gchar *override_stderr =
      run_status_against_gsettings_url (override_argv,
          G_N_ELEMENTS (override_argv), FALSE, &override_status);

  g_assert_false (wait_status_is_success (control_status));
  assert_child_stderr_has (control_stderr,
      "wyctl: daemon unavailable: " WYCTL_TEST_GSETTINGS_URL);

  g_assert_false (wait_status_is_success (override_status));
  assert_child_stderr_has (override_stderr,
      "wyctl: daemon unavailable: http://127.0.0.1:1");
  g_assert_null (g_strstr_len (override_stderr, -1, "from-gsettings"));
}

/* Build a temporary access-token file with the supplied contents and
* mode bits, returning the path. The caller g_unlinks and g_frees. */
static gchar *
write_token_with_mode (const gchar *contents, mode_t mode)
{
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-broad-token-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  if (contents != NULL && contents[0] != '\0') {
    gsize len = strlen (contents);
    gsize wrote = 0;
    while (wrote < len) {
      ssize_t n = write (fd, contents + wrote, len - wrote);
      g_assert_cmpint (n, >=, 0);
      wrote += (gsize) n;
    }
  }
  g_assert_true (g_close (fd, NULL));
  g_assert_cmpint (g_chmod (path, mode), ==, 0);
  return path;
}

/* One spawn for the helper below: write a keyfile fixture holding
 * `daemon_url', run the subcommand against it with no --daemon-url on the
 * command line, tear the fixture down, and hand back the child's stderr.
 *
 * The global flags lead the argv.  wyctl rejects --timeout-ms after a
 * subcommand name, which is what used to kill these children at option
 * parsing before any resolution (#1189).  --access-token-file is a
 * per-subcommand option, so it is appended instead; note that it is itself
 * a GSettings-resolved key, so a fixture that ever sets it would quietly
 * change what these cases cover. */
static gchar *
run_subcommand_against_gsettings_daemon_url (gchar **subcommand_argv,
    gsize subcommand_argv_len, const gchar *token_path,
    const gchar *daemon_url, gint *wait_status)
{
  g_autofree gchar *literal = gvariant_literal_for_string (daemon_url);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);

  GPtrArray *argv = g_ptr_array_new ();
  g_ptr_array_add (argv, WYL_TEST_WYCTL_PATH);
  g_ptr_array_add (argv, "--timeout-ms");
  g_ptr_array_add (argv, "100");
  for (gsize i = 0; i < subcommand_argv_len; i++)
    g_ptr_array_add (argv, subcommand_argv[i]);
  g_ptr_array_add (argv, "--access-token-file");
  g_ptr_array_add (argv, (gpointer) token_path);
  g_ptr_array_add (argv, NULL);

  g_autofree gchar *stdout_buf = NULL;
  gchar *stderr_buf = NULL;
  run_child_with_env ((gchar **) argv->pdata, envp, &stdout_buf, &stderr_buf,
      wait_status);
  g_ptr_array_free (argv, TRUE);
  remove_dir_recursive (xdg);
  return stderr_buf;
}

/* Drive a wyctl subcommand against a GSettings keyfile that supplies the
 * daemon URL, and prove the keyfile is what supplied it.
 *
 * Two spawns against two fixtures, because neither alone survives deleting
 * the GSettings fallback (#1189):
 *
 *   - an invalid URL in the keyfile must produce "invalid daemon URL".
 *     Nothing else in the child's environment can put an invalid URL in
 *     front of validation: there is no --daemon-url on the command line,
 *     the resolver reads the CLI value and GSettings and nothing else, and
 *     the schema default is the empty string, which yields "missing daemon
 *     URL" instead.  So this is the positive, fixture-only proof that the
 *     keyfile value was read.
 *   - a syntactically valid URL must carry the child past validation and
 *     on to its own operation-failed diagnostic, proving the resolved value
 *     cleared the URL-validation gate.
 *
 * That second spawn proves nothing beyond the gate, which is why its
 * argument is named for the diagnostic rather than for a transport.  The
 * URL it supplies is unreachable, but arriving there is not what is being
 * tested, and a shared helper could not test it: `fact put' with an empty
 * input fails locally and never opens a connection at all, and `datalog
 * query' pointed at a listener that answers succeeds, which the shared
 * exit-status assertion below forbids.  The claim that the resolved URL
 * was the request's target is made once, by
 * /wyctl/policy-check-gsettings-daemon-url-is-the-transport-target, where a
 * listener can witness it.
 *
 * Both fixtures are torn down before anything is asserted, and the token
 * file with them, so a failing run leaves nothing behind under TMPDIR. */
static void
assert_subcommand_consumes_gsettings_daemon_url (gchar **subcommand_argv,
    gsize subcommand_argv_len, const gchar *post_validation_diagnostic)
{
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);
  gint invalid_status = 0;
  gint resolved_status = 0;

  g_autofree gchar *invalid_stderr =
      run_subcommand_against_gsettings_daemon_url (subcommand_argv,
          subcommand_argv_len, token_path, "not a url", &invalid_status);
  g_autofree gchar *resolved_stderr =
      run_subcommand_against_gsettings_daemon_url (subcommand_argv,
          subcommand_argv_len, token_path, "http://127.0.0.1:1",
          &resolved_status);
  g_unlink (token_path);

  g_assert_false (wait_status_is_success (invalid_status));
  assert_child_stderr_has (invalid_stderr, "wyctl: invalid daemon URL");

  g_assert_false (wait_status_is_success (resolved_status));
  assert_child_stderr_has (resolved_stderr, post_validation_diagnostic);
  g_assert_null (g_strstr_len (resolved_stderr, -1,
      "wyctl: missing daemon URL"));
  g_assert_null (g_strstr_len (resolved_stderr, -1,
      "wyctl: invalid daemon URL"));
}

static void
test_policy_check_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "policy", "check",
    "--user", "alice",
    "--permission", "read",
    "--resource", "doc/1",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: policy check failed");
}

static void
test_audit_query_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "audit", "query",
    "--limit", "1",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: audit query failed");
}

static void
test_fact_put_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "fact", "put",
    "--tenant", "t",
    "--graph", "g",
    "--namespace", "ns",
    "--relation", "r",
    "--schema-version", "1",
    "--batch-id", "b",
    "--idempotency-key", "k",
    "--format", "csv",
    "--input", "/dev/null",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: fact put failed");
}

/* When the access-token file is unsafe, the safety check MUST fire
* before any HTTP request. Witness: the subcommand's own "<op>
* failed" diagnostic must be absent, because reaching it requires
* a successful wyl_client_new + daemon probe. The
* permissions-too-broad diagnostic must be present in its place. */
static void
test_policy_check_safety_reject_prevents_http (void)
{
  g_autofree gchar *broad_token = write_token_with_mode ("token-1", 0640);

  /* --daemon-url and --timeout-ms are global flags and must come
   * before the subcommand name, per wyctl's CLI grammar. */
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "--timeout-ms", "100",
    "policy", "check",
    "--user", "alice",
    "--permission", "wr.audit.read",
    "--resource", "doc/42",
    "--access-token-file", broad_token,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_unlink (broad_token);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file permissions too broad"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: policy check failed"));
}

static void
test_audit_query_safety_reject_prevents_http (void)
{
  g_autofree gchar *broad_token = write_token_with_mode ("token-1", 0644);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "--timeout-ms", "100",
    "audit", "query",
    "--limit", "1",
    "--access-token-file", broad_token,
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_unlink (broad_token);

  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: access token file permissions too broad"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "wyctl: audit query failed"));
}

static void
test_datalog_query_gsettings_supplies_daemon_url (void)
{
  gchar *subcommand[] = {
    "datalog", "query",
    "--tenant", "t",
    "--graph", "g",
    "--query", "rel()",
    "--limit", "1",
    "--guard-timestamp", "0",
    "--guard-loc-class", "trusted",
    "--guard-risk", "0",
  };
  assert_subcommand_consumes_gsettings_daemon_url (subcommand,
      G_N_ELEMENTS (subcommand),
      "wyctl: datalog query failed");
}

/* The four cases above prove the keyfile supplied the URL and that the
 * resolved value cleared validation.  Neither proves the URL was where the
 * request actually went.  Prove that once, here, by putting a real
 * listener's address in the keyfile and asserting the listener saw the
 * request.  It is done for policy check alone on purpose: `fact put' with
 * an empty input never opens a connection, and `datalog query' succeeds
 * against a canned 200, so a listener in the shared helper above would need
 * a response body and an exit-status rule per subcommand.
 *
 * The response body is a placeholder chosen so the decision parse fails,
 * which is what keeps the child's exit status non-zero;
 * policy_check_server_thread dereferences response_body unconditionally, so
 * it cannot be left out.  The 1000 ms budget is inherited from the
 * recorded-request case above, whose comment records a 50 ms budget
 * expiring mid-connect under load with nothing left to record.  It is a
 * ceiling rather than a cost: delay_us is zero, so the server answers at
 * once. */
static void
test_policy_check_gsettings_daemon_url_is_the_transport_target (void)
{
  g_autoptr (GSocketListener) listener = NULL;
  g_autofree gchar *daemon_url = listen_url_for_policy_server (&listener);
  g_autoptr (GCancellable) accept_cancel = g_cancellable_new ();
  PolicyCheckServer server = {
    .listener = listener,
    .cancel = accept_cancel,
    .response_body = "{}",
    .delay_us = 0,
  };
  GThread *server_thread = g_thread_new ("policy-check-gsettings",
          policy_check_server_thread, &server);

  g_autofree gchar *literal = gvariant_literal_for_string (daemon_url);
  const gchar *keys[] = { "daemon-url", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir (keys, values);
  g_auto (GStrv) envp = build_gsettings_envp (xdg, FALSE);
  g_autofree gchar *token_path = write_token_with_mode ("token-1", 0600);

  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--timeout-ms", "1000",
    "policy", "check",
    "--user", "alice",
    "--permission", "read",
    "--resource", "doc/1",
    "--access-token-file", token_path,
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child_with_env (argv, envp, &stdout_buf, &stderr_buf, &wait_status);
  stop_test_server (server_thread, accept_cancel);
  remove_dir_recursive (xdg);
  g_unlink (token_path);
  g_autofree gchar *request = server.request;

  /* Name the child's own diagnostic before asserting on the recording.
   * No sibling ever sees a reply; this one completes a round trip and
   * parses the answer, so a red here can have a cause that has nothing to
   * do with the resolver.  A bare "request != NULL" would print none of
   * it. */
  g_assert_false (wait_status_is_success (wait_status));
  assert_child_stderr_has (stderr_buf, "wyctl: policy check failed");
  g_assert_nonnull (request);
  g_assert_nonnull (g_strstr_len (request, -1, "POST /decide?"));
}

static void
test_status_kill_switch_disables_gsettings (void)
{
  /* GSettings carries a URL but WYCTL_DISABLE_GSETTINGS=1 must keep wyctl
   * from consulting it; with no CLI URL the existing missing-daemon-URL
   * diagnostic must fire.
   *
   * Breaking the kill switch has always reddened this case.  What it could
   * not tell apart was a suppressed fixture from one the child could never
   * have read, since both end in "missing daemon URL" (#1189).  The control
   * spawn settles that: a fixture built from the same keys, read by the
   * same binary, with the switch off. */
  gint control_status = 0;
  gint suppressed_status = 0;

  g_autofree gchar *control_stderr =
      run_status_against_gsettings_url (NULL, 0, FALSE, &control_status);
  g_autofree gchar *suppressed_stderr =
      run_status_against_gsettings_url (NULL, 0, TRUE, &suppressed_status);

  g_assert_false (wait_status_is_success (control_status));
  assert_child_stderr_has (control_stderr,
      "wyctl: daemon unavailable: " WYCTL_TEST_GSETTINGS_URL);

  g_assert_false (wait_status_is_success (suppressed_status));
  assert_child_stderr_has (suppressed_stderr, "wyctl: missing daemon URL");
  g_assert_null (g_strstr_len (suppressed_stderr, -1, "daemon unavailable:"));
}

static void
test_service_token_preflight_and_malformed_input (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *credential_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-service-credential-XXXXXX",
          &credential_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (credential_path,
      "credential-secret-canary", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (credential_path, 0600), ==, 0);
  g_autofree gchar *output_path = g_build_filename (g_get_tmp_dir (),
          "wyctl-service-token-no-output", NULL);
  g_unlink (output_path);
  gchar *non_loopback_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://example.invalid",
    "auth", "service-token", "--credential-file", credential_path,
    "--token-output", output_path, NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (non_loopback_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1, "wyctl: invalid daemon URL"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "credential-secret-canary"));
  g_assert_false (g_file_test (output_path, G_FILE_TEST_EXISTS));

  gchar *malformed_argv[] = {
    WYL_TEST_WYCTL_PATH, "--daemon-url", "http://127.0.0.1:1",
    "auth", "service-token", "--credential-file", credential_path,
    "--token-output", output_path, NULL,
  };
  g_clear_pointer (&stdout_buf, g_free);
  g_clear_pointer (&stderr_buf, g_free);
  run_child (malformed_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_false (wait_status_is_success (wait_status));
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
      "wyctl: invalid service credential file"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "credential-secret-canary"));
  g_assert_false (g_file_test (output_path, G_FILE_TEST_EXISTS));
  g_unlink (credential_path);
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
  g_test_add_func ("/wyctl/status-gsettings-supplies-daemon-url",
      test_status_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/status-cli-overrides-gsettings",
      test_status_cli_overrides_gsettings);
  g_test_add_func ("/wyctl/status-kill-switch-disables-gsettings",
      test_status_kill_switch_disables_gsettings);
  g_test_add_func ("/wyctl/policy-check-gsettings-supplies-daemon-url",
      test_policy_check_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/audit-query-gsettings-supplies-daemon-url",
      test_audit_query_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/fact-put-gsettings-supplies-daemon-url",
      test_fact_put_gsettings_supplies_daemon_url);
  g_test_add_func ("/wyctl/datalog-query-gsettings-supplies-daemon-url",
      test_datalog_query_gsettings_supplies_daemon_url);
  g_test_add_func (
    "/wyctl/policy-check-gsettings-daemon-url-is-the-transport-target",
    test_policy_check_gsettings_daemon_url_is_the_transport_target);
  g_test_add_func ("/wyctl/policy-check-safety-reject-prevents-http",
      test_policy_check_safety_reject_prevents_http);
  g_test_add_func ("/wyctl/audit-query-safety-reject-prevents-http",
      test_audit_query_safety_reject_prevents_http);
  g_test_add_func ("/wyctl/service-token-preflight-and-malformed-input",
      test_service_token_preflight_and_malformed_input);

  return wyl_test_normalize_exit_status (g_test_run ());
}
