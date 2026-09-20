/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

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
#include "test-exit-status.h"
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "daemon/delta.h"
#include "daemon/http.h"
#include "wyrelog/client.h"
#ifdef WYL_HAS_FACT_STORE
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

static gchar *
make_fact_root (const gchar *tmpl, GError **error)
{
  g_autofree gchar *created = g_dir_make_tmp (tmpl, error);
  if (created == NULL)
    return NULL;
  gchar *root = realpath (created, NULL);
  if (root != NULL)
    return root;

  gint saved_errno = errno;
  (void) g_rmdir (created);
  if (error != NULL && *error == NULL)
    g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
        "Failed to resolve temporary directory '%s': %s", created,
        g_strerror (saved_errno));
  return NULL;
}

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

static gint
check_fact_projection_batch_rows (WylHandle *handle, const gchar *batch_id,
    gint64 expected_rows)
{
  GraphPathProbe probe = {
    .graph_id = "orders",
  };
  if (wyl_policy_store_foreach_fact_graph (wyl_handle_get_policy_store
        (handle), WYL_TENANT_DEFAULT, graph_path_cb, &probe) != WYRELOG_E_OK
      || probe.storage_path == NULL)
    return 100;
  g_autofree gchar *path = probe.storage_path;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK)
    return 101;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  gint64 rows = 0;
  if (wyl_fact_store_count_projection_batch_rows (store, &schema, batch_id,
      &rows) != WYRELOG_E_OK)
    return 102;
  return rows == expected_rows ? 0 : 103;
}

/* The payload digest the daemon binds to a logical quota operation is the
 * store's canonical batch content hash, computed here with the same function
 * over the same schema-typed values so the test asks operation-status about
 * the identity the daemon actually recorded. The daemon hashes tenant, graph,
 * namespace, relation, schema version, op and the typed values; batch and
 * request identifiers are not part of it. Caller owns the result. */
static gchar *
fact_test_batch_payload_digest (wyl_fact_store_op_t op, const gchar *batch_id,
    const gchar *key, const gchar *order_id, gint64 amount)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  const wyl_fact_value_t values[] = {
    {.type = WYL_FACT_VALUE_SYMBOL,.as.text = order_id},
    {.type = WYL_FACT_VALUE_INT64,.as.int64_value = amount},
  };
  const wyl_fact_row_t rows[] = {
    {values, G_N_ELEMENTS (values)},
  };
  const wyl_fact_store_batch_t batch = {
    .batch_id = batch_id,
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .source = "http",
    .request_id = key,
    .idempotency_key = key,
    .op = op,
    .rows = rows,
    .n_rows = G_N_ELEMENTS (rows),
  };
  return wyl_fact_store_batch_content_hash (&schema, &batch);
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

static void
assert_wyctl_rejected (gchar **argv, const gchar *expected_stderr)
{
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_wyctl (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, 2);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_cmpstr (stderr_buf, ==, expected_stderr);
}

/* A remote failure: wyctl exits with the documented code for the daemon's
 * answer and names the daemon's error code on stderr. */
static void
assert_wyctl_failed (gchar **argv, gint expected_status,
    const gchar *expected_stderr)
{
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;

  run_wyctl (argv, &stdout_buf, &stderr_buf, &wait_status);
  g_assert_true (WIFEXITED (wait_status));
  g_assert_cmpint (WEXITSTATUS (wait_status), ==, expected_status);
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_cmpstr (stderr_buf, ==, expected_stderr);
}
#endif

int
main (void)
{
#ifdef WYL_HAS_FACT_STORE
  g_autoptr (GError) fact_root_error = NULL;
  g_autofree gchar *fact_root = make_fact_root ("wyctl-facts-XXXXXX",
          &fact_root_error);
  if (fact_root == NULL)
    return wyl_test_normalize_exit_status (101);
  if (g_chmod (fact_root, 0700) != 0)
    return wyl_test_normalize_exit_status (102);
#endif

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions open_opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
#ifdef WYL_HAS_FACT_STORE
    .fact_root = fact_root,
#endif
  };
  if (wyl_handle_open_with_options (&open_opts, &handle) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (1);

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
    return wyl_test_normalize_exit_status (2);

  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL)
    return wyl_test_normalize_exit_status (3);
  GThread *thread = g_thread_new ("wyctl-policy-daemon",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return wyl_test_normalize_exit_status (4);
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  /* Login an operator with skip-mfa so we get a bearer access token, then
   * grant it both authorities the daemon mutation handlers require:
   * wr.policy.write for the permission grant/revoke handlers and
   * wr.policy.grant_role for the role grant/revoke handlers. */
  g_autoptr (WylClient) admin_client = NULL;
  if (wyl_client_new (base_url, &admin_client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (5);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (admin_client, "wyctl-policy-admin")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return wyl_test_normalize_exit_status (6);
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  g_autofree gchar *access_token = wyl_client_dup_access_token (admin_client);
  if (access_token == NULL)
    return wyl_test_normalize_exit_status (7);

  if (grant_policy_write_authority (handle, "wyctl-policy-admin", "tenant-x")
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (8);
  if (grant_policy_role_authority (handle, "wyctl-policy-admin", "tenant-x")
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (9);
#ifdef WYL_HAS_FACT_STORE
  if (grant_fact_authority (handle, "wyctl-policy-admin") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (103);
  if (wyl_policy_store_grant_role_membership (
        wyl_handle_get_policy_store (handle), "wyctl-policy-admin",
        "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK ||
      wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (104);
#endif

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "site.wyctl.read",
      "site wyctl read", "basic") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (10);
  if (wyl_policy_store_upsert_role (store, "site.wyctl.reader",
      "site wyctl reader") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (11);

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
    return wyl_test_normalize_exit_status (12);

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
    return wyl_test_normalize_exit_status (13);

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
    return wyl_test_normalize_exit_status (14);

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
    return wyl_test_normalize_exit_status (15);

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

  gchar *fact_quota_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--limit", "2",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout_contains (fact_quota_configure_argv,
      "tenant=__wr_default dimension=graph_count limit=2 committed=1 pending=0");
  gchar *fact_quota_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout_contains (fact_quota_status_argv,
      "tenant=__wr_default dimension=graph_count limit=2 committed=1 pending=0");

  gchar *fact_write_rate_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "write_rate",
    "--rate-per-second", "7",
    "--burst", "11",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout_contains (fact_write_rate_configure_argv,
      "tenant=__wr_default dimension=write_rate rate_per_second=7 burst=11");
  gchar *fact_write_rate_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "write_rate",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout_contains (fact_write_rate_status_argv,
      "tenant=__wr_default dimension=write_rate rate_per_second=7 burst=11");

  gchar *fact_schema_quota_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "schema_count",
    "--limit", "2",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_schema_quota_configure_argv,
      "tenant=__wr_default dimension=schema_count limit=2 registered=0\n");
  gchar *fact_schema_quota_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "schema_count",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_schema_quota_status_argv,
      "tenant=__wr_default dimension=schema_count limit=2 registered=0\n");

  gchar *fact_physical_quota_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "physical_bytes",
    "--limit", "4096",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_physical_quota_configure_argv,
      "tenant=__wr_default dimension=physical_bytes limit=4096 committed_bytes=0 pending_bytes=0 reconciling_bytes=0\n");
  gchar *fact_physical_quota_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "physical_bytes",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_physical_quota_status_argv,
      "tenant=__wr_default dimension=physical_bytes limit=4096 committed_bytes=0 pending_bytes=0 reconciling_bytes=0\n");

  gchar *fact_concurrent_quota_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "concurrent_opens",
    "--limit", "2",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_concurrent_quota_configure_argv,
      "tenant=__wr_default dimension=concurrent_opens limit=2 pending=0 active=0 acquiring=0 cleanup_pending=0 charged=0\n");
  gchar *fact_concurrent_quota_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "concurrent_opens",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_concurrent_quota_status_argv,
      "tenant=__wr_default dimension=concurrent_opens limit=2 pending=0 active=0 acquiring=0 cleanup_pending=0 charged=0\n");

  /* logical_bytes is one paired dimension: configure takes both limits and
   * status reports both, so an operator can read the row and byte budget
   * from one line. The limits are large so the mutations below stay
   * admitted; committed usage is asserted after them. */
  gchar *fact_logical_quota_configure_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "logical_bytes",
    "--limit", "100000",
    "--row-limit", "10000",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_logical_quota_configure_argv,
      "tenant=__wr_default dimension=logical_bytes row_limit=10000 byte_limit=100000 committed_rows=0 committed_bytes=0 pending_rows=0 pending_bytes=0\n");
  gchar *fact_logical_quota_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "logical_bytes",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_logical_quota_status_argv,
      "tenant=__wr_default dimension=logical_bytes row_limit=10000 byte_limit=100000 committed_rows=0 committed_bytes=0 pending_rows=0 pending_bytes=0\n");
  gchar *fact_logical_quota_missing_row_limit_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "logical_bytes",
    "--limit", "100000",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_rejected (fact_logical_quota_missing_row_limit_argv,
      "wyctl: logical_bytes requires --limit and --row-limit when configuring\n");
  gchar *fact_logical_quota_status_with_limit_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "logical_bytes",
    "--limit", "100000",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_rejected (fact_logical_quota_status_with_limit_argv,
      "wyctl: logical_bytes requires --limit and --row-limit when configuring\n");

  gchar *fact_schema_quota_missing_limit_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "schema_count",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_rejected (fact_schema_quota_missing_limit_argv,
      "wyctl: schema_count requires --limit and rejects rate options\n");
  gchar *fact_schema_quota_rate_options_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "configure",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--dimension", "schema_count",
    "--limit", "2",
    "--rate-per-second", "1",
    "--burst", "1",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_rejected (fact_schema_quota_rate_options_argv,
      "wyctl: schema_count requires --limit and rejects rate options\n");

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
  assert_wyctl_stdout (fact_schema_quota_status_argv,
      "tenant=__wr_default dimension=schema_count limit=2 registered=1\n");

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
  if (check_fact_projection_batch_rows (handle, "batch-1", 1) != 0)
    return wyl_test_normalize_exit_status (104);
  /* One committed row priced at its schema values: "o-1" is 3 logical
   * bytes and the int64 amount is 8. Nothing is pending once settled. */
  assert_wyctl_stdout (fact_logical_quota_status_argv,
      "tenant=__wr_default dimension=logical_bytes row_limit=10000 byte_limit=100000 committed_rows=1 committed_bytes=11 pending_rows=0 pending_bytes=0\n");
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
  if (check_fact_projection_batch_rows (handle, "batch-1", 1) != 0)
    return wyl_test_normalize_exit_status (105);
  /* A replayed batch reports the stored cost and is not charged again. */
  assert_wyctl_stdout (fact_logical_quota_status_argv,
      "tenant=__wr_default dimension=logical_bytes row_limit=10000 byte_limit=100000 committed_rows=1 committed_bytes=11 pending_rows=0 pending_bytes=0\n");

  /* One settled operation, inspected by its complete identity: the
   * operation id is the mutation's idempotency key and the digest is the
   * daemon's content hash of batch-1. The row was priced at 1 row and 11
   * bytes and applied in full; the status read never reports a replay. */
  g_autofree gchar *batch_1_digest = fact_test_batch_payload_digest
        (WYL_FACT_STORE_OP_ASSERT, "batch-1", "key-1", "o-1", 42);
  g_assert_nonnull (batch_1_digest);
  gchar *fact_quota_operation_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "operation-status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--batch-id", "batch-1",
    "--operation-id", "key-1",
    "--payload-digest", batch_1_digest,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_quota_operation_status_argv,
      "tenant=__wr_default graph=orders batch_id=batch-1 operation_id=key-1 state=settled replay=false requested_rows=1 requested_bytes=11 applied_rows=1 applied_bytes=11\n");
  /* An unknown operation id is not found; a known one under another graph
   * is an identity conflict. Both are remote failures with exit 5. */
  gchar *fact_quota_operation_missing_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "operation-status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--batch-id", "batch-1",
    "--operation-id", "missing",
    "--payload-digest", batch_1_digest,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_failed (fact_quota_operation_missing_argv, 5,
      "wyctl: fact quota operation-status failed: fact_quota_operation_not_found\n");
  gchar *fact_quota_operation_conflict_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "operation-status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "other",
    "--batch-id", "batch-1",
    "--operation-id", "key-1",
    "--payload-digest", batch_1_digest,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_failed (fact_quota_operation_conflict_argv, 5,
      "wyctl: fact quota operation-status failed: fact_quota_operation_conflict\n");
  /* The digest is validated locally before any request is sent. */
  gchar *fact_quota_operation_bad_digest_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "operation-status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--batch-id", "batch-1",
    "--operation-id", "key-1",
    "--payload-digest", "abc",
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_rejected (fact_quota_operation_bad_digest_argv,
      "wyctl: invalid --payload-digest\n");
  gchar *fact_retract_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "retract",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--namespace", "shop",
    "--relation", "orders",
    "--schema-version", "1",
    "--batch-id", "retract-1",
    "--idempotency-key", "retract-key-1",
    "--format", "csv",
    "--input", input_path,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_retract_argv, "inserted\n");
  assert_wyctl_stdout_contains (datalog_query_argv, "\"rows\":[]");
  assert_wyctl_stdout (fact_retract_argv, "duplicate\n");

  /* #553: a committed-but-reconciling mutation prints the payload digest
   * that completes its operation identity, for put and retract alike. The
   * 202 is reached deterministically: the seam reservation is settled in
   * advance at a cost of nothing, the identical retract replays it, the
   * store commits, and settlement refuses the settled row whose applied cost
   * differs. A dedupe replay always reports the settled cost, so the state is
   * unreachable in production; the row and the uncharged tombstone batch are
   * test-only state, and nothing later reads them. */
  g_autoptr (GError) seam_error = NULL;
  gchar *seam_input_path = NULL;
  gint seam_fd = g_file_open_tmp ("wyctl-facts-seam-XXXXXX",
          &seam_input_path, &seam_error);
  g_assert_no_error (seam_error);
  g_assert_cmpint (seam_fd, >=, 0);
  g_assert_true (g_close (seam_fd, NULL));
  g_assert_true (g_file_set_contents (seam_input_path,
      "order_id,amount\no-9,9\n", -1, &seam_error));
  g_assert_no_error (seam_error);
  g_autofree gchar *seam_input_path_autofree = seam_input_path;
  g_autofree gchar *seam_digest = fact_test_batch_payload_digest
        (WYL_FACT_STORE_OP_RETRACT, "seam-1", "seam-key-1", "o-9", 9);
  g_assert_nonnull (seam_digest);
  const WylPolicyFactLogicalQuotaOperation seam_operation = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .batch_id = "seam-1",
    .request_id = "seam-key-1",
    .payload_digest = seam_digest,
  };
  WylPolicyFactLogicalOperationStatus seam_state = { 0 };
  g_assert_cmpint (wyl_policy_store_reserve_fact_logical_quota
        (wyl_handle_get_policy_store (handle), &seam_operation, 1, 11,
      &seam_state), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_settle_fact_logical_quota
        (wyl_handle_get_policy_store (handle), &seam_operation, 0, 0,
      &seam_state), ==, WYRELOG_E_OK);
  g_assert_cmpint (seam_state.state, ==,
      WYL_POLICY_FACT_LOGICAL_OPERATION_SETTLED);
  gchar *fact_seam_retract_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "retract",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--namespace", "shop",
    "--relation", "orders",
    "--schema-version", "1",
    "--batch-id", "seam-1",
    "--idempotency-key", "seam-key-1",
    "--format", "csv",
    "--input", seam_input_path,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  g_autofree gchar *seam_expected = g_strdup_printf
        ("committed-reconciling operation_id=seam-key-1 batch_id=seam-1 "
          "payload_digest=%s\n", seam_digest);
  assert_wyctl_stdout (fact_seam_retract_argv, seam_expected);
  /* The settled row reports the cost it was settled at, not the batch's. */
  gchar *fact_seam_status_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", (gchar *) base_url,
    "fact", "quota", "operation-status",
    "--tenant", (gchar *) WYL_TENANT_DEFAULT,
    "--graph", "orders",
    "--batch-id", "seam-1",
    "--operation-id", "seam-key-1",
    "--payload-digest", seam_digest,
    "--access-token-file", token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "trusted",
    "--guard-risk", "29",
    NULL,
  };
  assert_wyctl_stdout (fact_seam_status_argv,
      "tenant=__wr_default graph=orders batch_id=seam-1 operation_id=seam-key-1 state=settled replay=false requested_rows=1 requested_bytes=11 applied_rows=0 applied_bytes=0\n");
  g_unlink (seam_input_path);
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
  return wyl_test_normalize_exit_status (0);
}
