/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Arg-validation harness for the `wyctl service-credential` noun. Spawns the
 * built wyctl binary with NO daemon and asserts the pure CLI-side exit codes
 * and diagnostics: noun/verb dispatch, required-flag presence, and the
 * expires-at-us > 0 rule. The daemon-backed end-to-end wiring (auth + rc
 * mapping) lives in test-wyctl-service-credential-daemon.c. */
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
test_service_credential_dispatch (void)
{
  gchar *no_verb_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-credential",
    NULL,
  };
  assert_exit_and_stderr (no_verb_argv, 2,
      "wyctl: missing service-credential command");

  gchar *bogus_verb_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-credential",
    "bogus",
    NULL,
  };
  assert_exit_and_stderr (bogus_verb_argv, 2,
      "wyctl: unknown service-credential command: bogus");
}

static void
test_service_credential_issue_missing_flags (void)
{
  gchar *missing_subject_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_subject_argv, 2, "wyctl: missing --subject");

  gchar *missing_destination_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_destination_argv, 2,
      "wyctl: missing --destination");

  gchar *missing_expires_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_expires_argv, 2,
      "wyctl: invalid --expires-at-us");

  gchar *missing_tenant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--destination", "worker.cred",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_tenant_argv, 2, "wyctl: missing --tenant");
}

static void
test_service_credential_issue_expires_bounds (void)
{
  gchar *zero_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "0",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (zero_argv, 2, "wyctl: invalid --expires-at-us");

  gchar *negative_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "-1",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (negative_argv, 2, "wyctl: invalid --expires-at-us");

  gchar *non_numeric_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "issue",
    "--subject", "svc:__wr_default:worker",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "soon",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (non_numeric_argv, 2,
      "wyctl: invalid --expires-at-us");
}

static void
test_service_credential_issue_help (void)
{
  gchar *help_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "service-credential", "issue",
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
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--destination"));
  g_assert_nonnull (g_strstr_len (stdout_buf, -1, "--expires-at-us"));
}

static void
test_service_credential_rotate_missing_flags (void)
{
  gchar *missing_credential_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_credential_argv, 2,
      "wyctl: missing --credential-id");

  gchar *missing_destination_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--credential-id", "cred-1",
    "--tenant", "__wr_default",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_destination_argv, 2,
      "wyctl: missing --destination");

  gchar *missing_expires_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--credential-id", "cred-1",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_expires_argv, 2,
      "wyctl: invalid --expires-at-us");

  gchar *missing_tenant_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--credential-id", "cred-1",
    "--destination", "worker.cred",
    "--expires-at-us", "1893456000000000",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (missing_tenant_argv, 2, "wyctl: missing --tenant");
}

static void
test_service_credential_rotate_expires_bounds (void)
{
  gchar *zero_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--credential-id", "cred-1",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "0",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (zero_argv, 2, "wyctl: invalid --expires-at-us");

  gchar *negative_argv[] = {
    WYL_TEST_WYCTL_PATH,
    "--daemon-url", "http://127.0.0.1:1",
    "service-credential", "rotate",
    "--credential-id", "cred-1",
    "--tenant", "__wr_default",
    "--destination", "worker.cred",
    "--expires-at-us", "-5",
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_exit_and_stderr (negative_argv, 2, "wyctl: invalid --expires-at-us");
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/service-credential/dispatch",
      test_service_credential_dispatch);
  g_test_add_func ("/wyctl/service-credential/issue-missing-flags",
      test_service_credential_issue_missing_flags);
  g_test_add_func ("/wyctl/service-credential/issue-expires-bounds",
      test_service_credential_issue_expires_bounds);
  g_test_add_func ("/wyctl/service-credential/issue-help",
      test_service_credential_issue_help);
  g_test_add_func ("/wyctl/service-credential/rotate-missing-flags",
      test_service_credential_rotate_missing_flags);
  g_test_add_func ("/wyctl/service-credential/rotate-expires-bounds",
      test_service_credential_rotate_expires_bounds);
  return g_test_run ();
}
