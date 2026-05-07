/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
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
  g_test_add_func ("/wyctl/status-requires-daemon-url",
      test_status_requires_daemon_url);
  g_test_add_func ("/wyctl/status-rejects-invalid-daemon-url",
      test_status_rejects_invalid_daemon_url);

  return g_test_run ();
}
