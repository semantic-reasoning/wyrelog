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
#ifdef WYL_HAS_FACT_STORE
#include <duckdb.h>
#include "wyrelog/fact/store-private.h"
#endif
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
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

#ifdef WYL_HAS_FACT_STORE
typedef struct
{
  const gchar *graph_id;
  gchar *storage_path;
} GraphPathProbe;

static wyrelog_error_t
grant_fact_authority (WylHandle *handle, const gchar *subject)
{
  static const gchar *const perms[] = {
    "wr.graph.manage",
    "wr.schema.manage",
    "wr.fact.write",
    "wr.datalog.query",
  };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  for (gsize i = 0; i < G_N_ELEMENTS (perms); i++) {
    wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store,
        subject, perms[i], WYL_TENANT_DEFAULT);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_policy_store_set_permission_state (store, subject, perms[i],
        WYL_TENANT_DEFAULT, "armed");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  wyrelog_error_t rc = wyl_policy_store_set_session_state (store,
      WYL_TENANT_DEFAULT, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
graph_path_cb (const wyl_policy_fact_graph_info_t *info, gpointer user_data)
{
  GraphPathProbe *probe = user_data;
  if (g_strcmp0 (info->graph_id, probe->graph_id) == 0)
    probe->storage_path = g_strdup (info->storage_path);
  return WYRELOG_E_OK;
}

static gchar *
capture_graph_path (WylHandle *handle, const gchar *graph_id)
{
  GraphPathProbe probe = {
    .graph_id = graph_id,
  };
  if (wyl_policy_store_foreach_fact_graph (wyl_handle_get_policy_store
          (handle), WYL_TENANT_DEFAULT, graph_path_cb, &probe) != WYRELOG_E_OK)
    return NULL;
  return probe.storage_path;
}

static gboolean
count_i64 (duckdb_connection conn, const gchar *sql, gint64 *out_value)
{
  duckdb_result result = { 0 };
  if (duckdb_query (conn, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return FALSE;
  }
  *out_value = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return TRUE;
}

static gint
check_fact_projection_count (WylHandle *handle, gint64 expected)
{
  g_autofree gchar *path = capture_graph_path (handle, "orders");
  if (path == NULL)
    return 100;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK)
    return 101;
  const WylClientFactColumn client_columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_column_t columns[] = {
    {client_columns[0].name, client_columns[0].type, FALSE, TRUE},
    {client_columns[1].name, client_columns[1].type, FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  if (table == NULL)
    return 102;
  gint64 count = 0;
  g_autofree gchar *sql = g_strdup_printf ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (wyl_fact_store_get_connection (store), sql, &count))
    return 103;
  return count == expected ? 0 : 104;
}

static void
remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name = NULL;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (path);
}
#endif

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
  /* g_file_set_contents atomically renames a fresh tmp file over the
   * original, applying the current umask to the new file. On CI runners
   * with umask 0022 that yields 0644, which fails the wyctl token-file
   * safety check. Force 0600 so the integration test continues to
   * exercise the daemon path, not the permissions diagnostic. */
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);
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

#ifdef WYL_HAS_FACT_STORE
static void
assert_wyctl_stdout (gchar **argv, const gchar *expected_stdout)
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
  g_assert_cmpstr (stdout_buf, ==, expected_stdout);
  g_assert_cmpstr (stderr_buf, ==, "");
}

static void
assert_wyctl_stdout_contains (gchar **argv, const gchar *needle)
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
  g_assert_nonnull (strstr (stdout_buf, needle));
  g_assert_cmpstr (stderr_buf, ==, "");
}
#endif

int
main (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;

#ifdef WYL_HAS_FACT_STORE
  g_autoptr (GError) fact_root_error = NULL;
  g_autofree gchar *fact_root = g_dir_make_tmp ("wyctl-facts-XXXXXX",
      &fact_root_error);
  if (fact_root == NULL)
    return 101;
  if (g_chmod (fact_root, 0700) != 0)
    return 102;
#endif

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
#ifdef WYL_HAS_FACT_STORE
    .fact_root = fact_root,
#endif
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
#ifdef WYL_HAS_FACT_STORE
  if (grant_fact_authority (handle, "wyctl-policy-admin") != WYRELOG_E_OK)
    return 103;
#endif

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

#ifdef WYL_HAS_FACT_STORE
  gchar *graph_create_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "graph", "create",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (graph_create_argv);

  gchar *schema_register_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "schema", "register",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--namespace", "shop",
    "--relation", "orders",
    "--schema-version", "1",
    "--columns", "order_id:symbol,amount:int64",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_ok (schema_register_argv);

  g_autoptr (GError) input_error = NULL;
  gchar *input_path = NULL;
  gint input_fd = g_file_open_tmp ("wyctl-facts-input-XXXXXX", &input_path,
      &input_error);
  g_assert_no_error (input_error);
  g_assert_cmpint (input_fd, >=, 0);
  g_assert_true (g_close (input_fd, NULL));
  g_assert_true (g_file_set_contents (input_path,
          "order_id,amount\no-1,42\n", -1, &input_error));
  g_assert_no_error (input_error);
  g_autofree gchar *input_path_autofree = input_path;

  gchar *fact_put_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "put",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--namespace", "shop",
    "--relation", "orders",
    "--schema-version", "1",
    "--batch-id", "batch-1",
    "--idempotency-key", "key-1",
    "--format", "csv",
    "--input", input_path,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_put_argv, "inserted\n");
  if (check_fact_projection_count (handle, 1) != 0)
    return 104;
  gchar *datalog_query_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "datalog", "query",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--query", "orders(O,A)",
    "--output", "json",
    "--limit", "10",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout_contains (datalog_query_argv,
      "\"rows\":[{\"O\":\"o-1\",\"A\":42}]");
  assert_wyctl_stdout (fact_put_argv, "duplicate\n");
  if (check_fact_projection_count (handle, 1) != 0)
    return 105;
  g_unlink (input_path);
#endif

  g_unlink (token_path);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
#ifdef WYL_HAS_FACT_STORE
  remove_tree (fact_root);
#endif
  return 0;
}
