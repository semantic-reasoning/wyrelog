/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Arg-validation harness for the `wyctl service-principal` noun. Spawns the
 * built wyctl binary with NO daemon and asserts the pure CLI-side exit codes
 * and diagnostics: noun/verb dispatch and required-flag presence. The
 * daemon-backed end-to-end wiring (auth + rc mapping) lives elsewhere. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <string.h>
#include <sys/wait.h>

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
  const gchar *body;
  guint status;
  guint request_count;
} TestHttpServer;

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;
  g_main_loop_run (http->loop);
  return NULL;
}

static void
test_http_server_handler (SoupServer *server, SoupServerMessage *message,
    const gchar *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  TestHttpServer *http = user_data;
  http->request_count++;
  soup_server_message_set_status (message, http->status, NULL);
  soup_server_message_set_response (message, "application/json",
      SOUP_MEMORY_COPY, http->body, strlen (http->body));
}

static void
run_child (gchar **argv, gchar **stdout_buf, gchar **stderr_buf,
    gint *wait_status)
{
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

/* Assert wyctl exited with |expected_exit|, wrote nothing to stdout, and
 * surfaced |marker| on stderr. A non-NULL marker is what makes each case
 * meaningful: before the command is registered the noun falls through to the
 * top-level "unknown command" diagnostic (also exit 2), so an exit-code-only
 * assertion would pass spuriously. */
static void
assert_exit_and_stderr (gchar **argv, int expected_exit, const gchar *marker)
{
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_exit);
  g_assert_cmpstr (stdout_buf, ==, "");
  if (marker != NULL)
    g_assert_nonnull (g_strstr_len (stderr_buf, -1, marker));
}

static gchar *
write_access_token_file (void)
{
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-principal-token-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (path, "access-token", -1, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);
  return path;
}

static void
test_service_principal_local_and_remote_invalid (void)
{
  g_autoptr (GError) error = NULL;
  TestHttpServer http = {
    .server = soup_server_new (NULL, NULL),
    .loop = g_main_loop_new (NULL, FALSE),
    .body = "{\"error\":\"remote_invalid\"}",
    .status = 400,
  };
  soup_server_add_handler (http.server, NULL, test_http_server_handler, &http,
      NULL);
  g_assert_true (soup_server_listen_local (http.server, 0, 0, &error));
  g_assert_no_error (error);
  GSList *uris = soup_server_get_uris (http.server);
  g_assert_nonnull (uris);
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  g_autoptr (GThread) thread = g_thread_new ("wyctl-principal-http",
      test_http_server_thread, &http);
  g_autofree gchar *token_path = write_access_token_file ();

  gchar *local_invalid_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-principal", "create",
    "--subject", "invalid",
    "--display-name", "Worker",
    "--tenant", "tenant-a",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (local_invalid_argv, 2,
      "service_principal_create_failed");
  g_assert_cmpuint (http.request_count, ==, 0);

  gchar *remote_invalid_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-principal", "create",
    "--subject", "svc:tenant-a:worker",
    "--display-name", "Worker",
    "--tenant", "tenant-a",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (remote_invalid_argv, 3, "remote_invalid");
  g_assert_cmpuint (http.request_count, ==, 1);

  http.body = "{\"error\":\"remote_invalid\nINJECTED_DIAGNOSTIC\"}";
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  run_child (remote_invalid_argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 3);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_nonnull (g_strstr_len (stderr_buf, -1,
          "service_principal_create_failed"));
  g_assert_null (g_strstr_len (stderr_buf, -1, "INJECTED_DIAGNOSTIC"));

  soup_server_disconnect (http.server);
  g_main_loop_quit (http.loop);
  g_thread_join (g_steal_pointer (&thread));
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_assert_cmpint (g_unlink (token_path), ==, 0);
}

static void
test_service_principal_dispatch (void)
{
  gchar *no_verb_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-principal",
    NULL,
  };
  assert_exit_and_stderr (no_verb_argv, 2,
      "wyctl: missing service-principal command");

  gchar *bogus_verb_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-principal",
    "bogus",
    NULL,
  };
  assert_exit_and_stderr (bogus_verb_argv, 2,
      "wyctl: unknown service-principal command: bogus");
}

static void
test_service_principal_create_missing_flags (void)
{
  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-principal", "create",
    "--display-name", "Worker",
    "--tenant", "__wr_default",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_subject_argv, 2, "wyctl: missing --subject");

  gchar *missing_display_name_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-principal", "create",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_display_name_argv, 2,
      "wyctl: missing --display-name");

  gchar *missing_tenant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-principal", "create",
    "--subject", "svc:__wr_default:worker",
    "--display-name", "Worker",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_tenant_argv, 2, "wyctl: missing --tenant");
}

static void
test_service_principal_create_help (void)
{
  gchar *help_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-principal", "create",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (help_argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 0);
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--subject"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--display-name"));
}

static void
test_service_principal_list_missing_tenant (void)
{
  gchar *missing_tenant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-principal", "list",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_tenant_argv, 2, "wyctl: missing --tenant");
}

static void
test_service_principal_list_help (void)
{
  gchar *help_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-principal", "list",
    "--help",
    NULL,
  };
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_child (help_argv, &stdout_buf, &stderr_buf, &wait_status);

  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 0);
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--tenant"));
  g_assert_null (g_strstr_len (stdout_buf, -1, "--subject"));
}

static void
test_service_principal_disable_missing_subject (void)
{
  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-principal", "disable",
    "--tenant", "__wr_default",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_subject_argv, 2, "wyctl: missing --subject");
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/service-principal/dispatch",
      test_service_principal_dispatch);
  g_test_add_func ("/wyctl/service-principal/create-missing-flags",
      test_service_principal_create_missing_flags);
  g_test_add_func ("/wyctl/service-principal/create-help",
      test_service_principal_create_help);
  g_test_add_func ("/wyctl/service-principal/list-missing-tenant",
      test_service_principal_list_missing_tenant);
  g_test_add_func ("/wyctl/service-principal/list-help",
      test_service_principal_list_help);
  g_test_add_func ("/wyctl/service-principal/disable-missing-subject",
      test_service_principal_disable_missing_subject);
  g_test_add_func ("/wyctl/service-principal/local-and-remote-invalid",
      test_service_principal_local_and_remote_invalid);
  return g_test_run ();
}
