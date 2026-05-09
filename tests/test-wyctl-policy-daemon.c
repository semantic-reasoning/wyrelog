/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Drives wyctl as a child process against a wyrelogd HTTP server booted
 * in-process. The four mutation subcommands (permission-grant,
 * permission-revoke, role-grant, role-revoke) need a privileged
 * operator on the policy-write / role-grant authorities, which the
 * daemon CLI does not expose. The in-process pattern from
 * test-daemon-http-decide is reused here: seed the admin via the
 * library helpers, write its access token to a temp file, then exec
 * wyctl with the documented flags and assert ok output.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <string.h>
#include <sys/wait.h>

#include "daemon/delta.h"
#include "daemon/http.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH must be defined by the build."
#endif

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

static wyrelog_error_t
grant_policy_write_authority (WylHandle *handle, const gchar *subject,
    const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store, subject,
      "wr.policy.write", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
grant_policy_role_authority (WylHandle *handle, const gchar *subject,
    const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store, subject,
      "wr.policy.grant_role", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static gchar *
write_token_file (const gchar *token)
{
  g_autoptr (GError) error = NULL;
  gchar *token_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-policy-daemon-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, token, -1, &error));
  g_assert_no_error (error);
  return token_path;
}

static void
run_wyctl (gchar **argv, gchar **stdout_buf, gchar **stderr_buf,
    gint *wait_status)
{
  g_autoptr (GError) error = NULL;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          stdout_buf, stderr_buf, wait_status, &error));
  g_assert_no_error (error);
}

static void
assert_wyctl_ok (gchar **argv)
{
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  g_autoptr (GError) error = NULL;

  run_wyctl (argv, &stdout_buf, &stderr_buf, &wait_status);

  if (!g_spawn_check_wait_status (wait_status, &error)) {
    g_printerr ("wyctl exited with status %d\nstdout: %s\nstderr: %s\n",
        wait_status, stdout_buf ? stdout_buf : "(null)",
        stderr_buf ? stderr_buf : "(null)");
    g_clear_error (&error);
    g_assert_not_reached ();
  }
  g_assert_cmpstr (stdout_buf, ==, "ok\n");
  g_assert_cmpstr (stderr_buf, ==, "");
}

int
main (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 2;

  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("wyctl-policy-daemon",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  /* Login an operator with skip-mfa so we get a bearer access token, then
   * grant it both authorities the daemon mutation handlers require:
   * wr.policy.write for the permission grant/revoke handlers and
   * wr.policy.grant_role for the role grant/revoke handlers. */
  g_autoptr (WylClient) admin_client = NULL;
  if (wyl_client_new (base_url, &admin_client) != WYRELOG_E_OK)
    return 5;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (admin_client, "wyctl-policy-admin")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 6;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  g_autofree gchar *access_token = wyl_client_dup_access_token (admin_client);
  if (access_token == NULL)
    return 7;

  if (grant_policy_write_authority (handle, "wyctl-policy-admin", "tenant-x")
      != WYRELOG_E_OK)
    return 8;
  if (grant_policy_role_authority (handle, "wyctl-policy-admin", "tenant-x")
      != WYRELOG_E_OK)
    return 9;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "site.wyctl.read",
          "site wyctl read", "basic") != WYRELOG_E_OK)
    return 10;
  if (wyl_policy_store_upsert_role (store, "site.wyctl.reader",
          "site wyctl reader") != WYRELOG_E_OK)
    return 11;

  g_autofree gchar *token_path = write_token_file (access_token);

  /* Each mutation drives wyctl as a child against the in-process daemon. The
   * scope parameter (tenant-x) matches the authority granted above; the
   * guard-* triple is well below the deny threshold (loc=public, risk<=29
   * for role, risk<=49 for permission per templates). */
  gchar *permission_grant_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "policy", "permission-grant",
    "--subject", "wyctl-target",
    "--perm", "site.wyctl.read",
    "--scope", "tenant-x",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (permission_grant_argv);
  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, "wyctl-target",
          "site.wyctl.read", "tenant-x", &exists) != WYRELOG_E_OK || !exists)
    return 12;

  gchar *permission_revoke_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "policy", "permission-revoke",
    "--subject", "wyctl-target",
    "--perm", "site.wyctl.read",
    "--scope", "tenant-x",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (permission_revoke_argv);
  exists = TRUE;
  if (wyl_policy_store_direct_permission_exists (store, "wyctl-target",
          "site.wyctl.read", "tenant-x", &exists) != WYRELOG_E_OK || exists)
    return 13;

  gchar *role_grant_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "policy", "role-grant",
    "--subject", "wyctl-target",
    "--role", "site.wyctl.reader",
    "--scope", "tenant-x",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (role_grant_argv);
  exists = FALSE;
  if (wyl_policy_store_role_membership_exists (store, "wyctl-target",
          "site.wyctl.reader", "tenant-x", &exists) != WYRELOG_E_OK || !exists)
    return 14;

  gchar *role_revoke_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "policy", "role-revoke",
    "--subject", "wyctl-target",
    "--role", "site.wyctl.reader",
    "--scope", "tenant-x",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (role_revoke_argv);
  exists = TRUE;
  if (wyl_policy_store_role_membership_exists (store, "wyctl-target",
          "site.wyctl.reader", "tenant-x", &exists) != WYRELOG_E_OK || exists)
    return 15;

  g_unlink (token_path);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
