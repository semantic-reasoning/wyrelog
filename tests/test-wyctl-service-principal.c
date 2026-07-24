/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Arg-validation harness for the `wyctl service-principal` noun. Spawns the
 * built wyctl binary with NO daemon and asserts the pure CLI-side exit codes
 * and diagnostics: noun/verb dispatch and required-flag presence. The
 * daemon-backed end-to-end wiring (auth + rc mapping) lives elsewhere. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <glib.h>
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
  return g_test_run ();
}
