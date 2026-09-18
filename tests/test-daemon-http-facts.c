/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <duckdb.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include <string.h>

#include "daemon/delta.h"
#include "daemon/http.h"
#include "fact-test-support.h"
#include "wyrelog/client.h"
#include "wyrelog/fact/store-private.h"
#include "wyrelog/fact/store-test-seams-private.h"
#include "wyrelog/fact/replay-private.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/graph-seal-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-request-id-private.h"
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)
#include "wyrelog/fact/secure-duckdb-bridge-private.h"
G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);
#endif

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

#define FACT_GUARD "guard_timestamp=123&guard_loc_class=trusted&guard_risk=29"

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

static gboolean
is_request_id_shape (const gchar *request_id)
{
  if (request_id == NULL || strlen (request_id) != WYL_REQUEST_ID_STRING_LEN)
    return FALSE;
  for (gsize i = 0; i < WYL_REQUEST_ID_STRING_LEN; i++) {
    if (!g_ascii_isalnum (request_id[i]))
      return FALSE;
  }
  return TRUE;
}

static gint
check_response_request_id_header (SoupMessage *msg, gint failure_code)
{
  const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
  return is_request_id_shape (request_id) ? 0 : failure_code;
}

static gchar *
build_uri (const gchar *base_url, const gchar *path, const gchar *query)
{
  g_autofree gchar *trimmed = g_strdup (base_url);
  while (trimmed[0] != '\0' && g_str_has_suffix (trimmed, "/"))
    trimmed[strlen (trimmed) - 1] = '\0';
  if (query == NULL || query[0] == '\0')
    return g_strdup_printf ("%s%s", trimmed, path);
  return g_strdup_printf ("%s%s?%s", trimmed, path, query);
}

static gint
send_raw_with_request_id (SoupSession *session, const gchar *method, const gchar *base_url,
    const gchar *path, const gchar *query, const gchar *access_token,
    const gchar *request_body, guint *out_status, gchar **out_body,
    gchar **out_request_id, gchar **out_retry_after)
{
  /* The output pointers own the previous response.  Clear them before a
   * request so callers may safely reuse one response slot across requests;
   * otherwise assigning the new response leaks the old allocation. */
  if (out_body != NULL)
    g_clear_pointer (out_body, g_free);
  if (out_request_id != NULL)
    g_clear_pointer (out_request_id, g_free);
  if (out_retry_after != NULL)
    g_clear_pointer (out_retry_after, g_free);
  g_autofree gchar *uri = build_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 100;
  if (access_token != NULL) {
    g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
            access_token);
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "Authorization", authorization);
  }
  if (request_body != NULL) {
    g_autoptr (GBytes) bytes = g_bytes_new_static (request_body,
            strlen (request_body));
    soup_message_set_request_body_from_bytes (msg,
        "text/tab-separated-values", bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 101;
  gint rc = check_response_request_id_header (msg, 102);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL)
    *out_request_id = g_strdup (soup_message_headers_get_one (
              soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id"));
  if (out_retry_after != NULL)
    *out_retry_after = g_strdup (soup_message_headers_get_one (
              soup_message_get_response_headers (msg), "Retry-After"));
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw (SoupSession *session, const gchar *method, const gchar *base_url,
    const gchar *path, const gchar *query, const gchar *access_token,
    const gchar *request_body, guint *out_status, gchar **out_body)
{
  return send_raw_with_request_id (session, method, base_url, path, query,
             access_token, request_body, out_status, out_body, NULL, NULL);
}

typedef struct
{
  GMutex *lock;
  GCond *changed;
  guint ready;
  gboolean start;
  const gchar *base_url;
  const gchar *access_token;
  const gchar *graph;
  gint rc;
  guint status;
  gchar *body;
} QuotaCreateRace;

static gpointer
quota_create_race_thread (gpointer user_data)
{
  QuotaCreateRace *race = user_data;
  g_mutex_lock (race->lock);
  race->ready++;
  g_cond_broadcast (race->changed);
  while (!race->start)
    g_cond_wait (race->changed, race->lock);
  g_mutex_unlock (race->lock);

  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *query = g_strdup_printf ("tenant=%s&graph=%s&%s",
          WYL_TENANT_DEFAULT, race->graph, FACT_GUARD);
  race->rc = send_raw (session, "POST", race->base_url, "/graphs/create",
          query, race->access_token, NULL, &race->status, &race->body);
  return NULL;
}

static gchar *
dup_safe_api_error_code (const gchar *body)
{
  static const gchar marker[] = "\"error\":\"";
  const gchar *start = body != NULL ? strstr (body, marker) : NULL;
  if (start == NULL)
    return NULL;
  start += sizeof marker - 1;
  const gchar *end = strchr (start, '"');
  if (end == NULL || end == start || (gsize) (end - start) > 64)
    return NULL;
  gsize length = (gsize) (end - start);
  for (gsize i = 0; i < length; i++) {
    gchar c = start[i];
    if (!(g_ascii_isalnum (c) || c == '_' || c == '-' || c == '.'))
      return NULL;
  }
  return g_strndup (start, length);
}

#if defined(WYL_HAS_FACT_STORE) && defined(WYL_TEST_HANDLE_SEAMS)
/* Fails the S4 durable write with the rc the handler maps to 404.  The abort
 * path fills outcome.status before returning, so this is what puts owned
 * strings in the outcome on a route that answers an error. */
static wyrelog_error_t
seal_durable_write_not_found (const gchar *phase, gpointer user_data)
{
  (void) user_data;
  if (g_strcmp0 (phase, WYL_FACT_GRAPH_SEAL_PHASE_DURABLE_WRITE) == 0)
    return WYRELOG_E_NOT_FOUND;
  return WYRELOG_E_OK;
}
#endif

static wyrelog_error_t
grant_fact_http_authority (WylHandle *handle, const gchar *subject)
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

typedef struct
{
  const gchar *graph_id;
  gboolean found;
} GraphExistenceProbe;

static wyrelog_error_t
find_graph (const wyl_policy_fact_graph_info_t *info, gpointer user_data)
{
  GraphExistenceProbe *probe = user_data;
  if (g_strcmp0 (info->graph_id, probe->graph_id) == 0)
    probe->found = TRUE;
  return WYRELOG_E_OK;
}

static gboolean
graph_state_matches (wyl_policy_store_t *store, const gchar *tenant,
    const gchar *graph, gboolean expected_exists, gboolean expected_active)
{
  GraphExistenceProbe probe = {
    .graph_id = graph,
  };
  if (wyl_policy_store_foreach_fact_graph (store, tenant, find_graph, &probe)
      != WYRELOG_E_OK || probe.found != expected_exists)
    return FALSE;
  if (!probe.found)
    return TRUE;
  gboolean active = FALSE;
  return wyl_policy_store_fact_graph_is_active (store, tenant, graph, &active)
         == WYRELOG_E_OK && active == expected_active;
}

static gboolean
count_i64 (wyl_fact_store_t *store, const gchar *sql, gint64 *out_value)
{
  return wyl_fact_store_test_query_int64 (store, sql, out_value)
         == WYRELOG_E_OK;
}

#ifdef WYL_HAS_AUDIT
/* The control-plane record for a fact lifecycle operation.  Matched on the
 * four fields the emitter fills; deny_origin and request_id are checked
 * separately where they matter. */
typedef struct
{
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *request_id;
  gboolean require_allow;
  guint matches;
} LifecycleAuditProbe;

static wyrelog_error_t
lifecycle_audit_probe_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  (void) deny_origin;
  LifecycleAuditProbe *probe = user_data;
  if (g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (action, probe->action) == 0
      && g_strcmp0 (resource_id, probe->resource_id) == 0
      && (probe->deny_reason == NULL
      || g_strcmp0 (deny_reason, probe->deny_reason) == 0)
      && (probe->request_id == NULL
      || g_strcmp0 (request_id, probe->request_id) == 0)
      && (!probe->require_allow || decision == WYL_DECISION_ALLOW))
    probe->matches++;
  return WYRELOG_E_OK;
}

#endif

/* The response ID must identify the authorization and both deletion records.
 * Only actor_subject_id is authenticated; the distinct body label is not. */
static void
check_forget_attribution (const gchar *fact_root, wyl_policy_store_t *policy,
    const gchar *batch, const gchar *request_id, gboolean lifecycle_written)
{
  g_assert_true (is_request_id_shape (request_id));
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT,
      "orders"), ==, WYRELOG_E_OK);
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  g_assert_nonnull (path);
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  g_assert_cmpint (wyl_fact_store_open (db_path, &store), ==, WYRELOG_E_OK);
  const gchar *tables[] = { "fact_forget_intent", "fact_forget_audit" };
  for (guint i = 0; i < G_N_ELEMENTS (tables); i++) {
    g_autofree gchar *sql = g_strdup_printf (
      "SELECT COUNT(*) FROM %s WHERE batch_id = '%s' "
      "AND actor_subject_id = 'facts-admin' AND request_id = '%s' "
      "AND operator = 'spoofed-operator' "
      "AND operator_annotation = 'spoofed-operator'%s;",
      tables[i], batch, request_id, i == 0 ? " AND state = 'COMPLETED'" : "");
    gint64 count = -1;
    g_assert_true (count_i64 (store, sql, &count));
    g_assert_cmpint (count, ==, 1);
  }
#ifdef WYL_HAS_AUDIT
  LifecycleAuditProbe authorization = {
    .subject_id = "facts-admin",
    .action = "wr.fact.write",
    .resource_id = WYL_TENANT_DEFAULT,
    .request_id = request_id,
    .require_allow = TRUE,
  };
  LifecycleAuditProbe lifecycle = {
    .subject_id = "facts-admin",
    .action = "fact_forget",
    .resource_id = "__wr_default/orders",
    .deny_reason = batch,
    .request_id = request_id,
    .require_allow = TRUE,
  };
  g_assert_cmpint (wyl_policy_store_foreach_audit_event (policy,
      lifecycle_audit_probe_cb, &authorization), ==, WYRELOG_E_OK);
  g_assert_cmpuint (authorization.matches, ==, 1);
  g_assert_cmpint (wyl_policy_store_foreach_audit_event (policy,
      lifecycle_audit_probe_cb, &lifecycle), ==, WYRELOG_E_OK);
  g_assert_cmpuint (lifecycle.matches, ==, lifecycle_written ? 1 : 0);
#else
  (void) policy;
  (void) lifecycle_written;
#endif
}

static gint
read_fact_projection_row_count (const gchar *fact_root,
    const gchar *graph_id, gint64 *out_count)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 300;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 301;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK)
    return 302;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = graph_id,
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 1,
    .relation_visible = TRUE,
    .columns = columns,
    .n_columns = G_N_ELEMENTS (columns),
  };
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  if (table == NULL)
    return 302;
  gint64 count = 0;
  g_autofree gchar *sql = g_strdup_printf ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (store, sql, &count))
    return 303;
  *out_count = count;
  return 0;
}

static gint
read_write_rate_tokens (sqlite3 *db, const gchar *tenant, gboolean *out_exists,
    guint64 *out_tokens)
{
  sqlite3_stmt *statement = NULL;
  if (out_exists != NULL)
    *out_exists = FALSE;
  if (out_tokens != NULL)
    *out_tokens = 0;
  if (sqlite3_prepare_v2 (db,
      "SELECT tokens FROM fact_tenant_write_rate_state WHERE tenant_id=?;",
      -1, &statement, NULL) != SQLITE_OK)
    return 1;
  if (sqlite3_bind_text (statement, 1, tenant, -1, SQLITE_TRANSIENT)
      != SQLITE_OK) {
    sqlite3_finalize (statement);
    return 2;
  }
  int step_rc = sqlite3_step (statement);
  if (step_rc == SQLITE_ROW) {
    if (out_exists != NULL)
      *out_exists = TRUE;
    if (out_tokens != NULL)
      *out_tokens = (guint64) sqlite3_column_int64 (statement, 0);
  }
  sqlite3_finalize (statement);
  return step_rc == SQLITE_ROW || step_rc == SQLITE_DONE ? 0 : 3;
}

static gint
check_fact_projection_row_count (const gchar *fact_root,
    const gchar *graph_id, gint64 expected_rows)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 300;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 301;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  /* A rejected first append must not create the graph's fact store at all. */
  if (!g_file_test (db_path, G_FILE_TEST_EXISTS))
    return expected_rows == 0 ? 0 : 305;
  gint64 count = 0;
  gint rc = read_fact_projection_row_count (fact_root, graph_id, &count);
  if (rc != 0)
    return rc;
  return count == expected_rows ? 0 : 304;
}

static gint
check_fact_batch_absent (const gchar *fact_root, const gchar *graph_id,
    const gchar *batch_id)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 300;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 301;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  if (!g_file_test (db_path, G_FILE_TEST_EXISTS))
    return 0;

  duckdb_config config = NULL;
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  duckdb_result result = { 0 };
  duckdb_prepared_statement statement = NULL;
  char *open_error = NULL;
  gboolean have_result = FALSE;
  gint rc = 302;
  if (duckdb_create_config (&config) != DuckDBSuccess)
    goto out;
  if (duckdb_set_config (config, "access_mode", "READ_ONLY")
      != DuckDBSuccess
      || duckdb_set_config (config, "autoinstall_known_extensions", "false")
      != DuckDBSuccess)
    goto out;
  if (duckdb_open_ext (db_path, &database, config, &open_error)
      != DuckDBSuccess)
    goto out;
  if (duckdb_connect (database, &connection) != DuckDBSuccess) {
    rc = 303;
    goto out;
  }
  if (duckdb_query (connection,
      "SELECT COUNT(*) FROM information_schema.tables "
      "WHERE table_schema = 'main' AND table_name = 'fact_batches';",
      &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    rc = 304;
    goto out;
  }
  have_result = TRUE;
  gint64 table_count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  have_result = FALSE;
  /* Secure graph provisioning creates an identity-bearing store before any
   * fact batch or its metadata tables exist. */
  if (table_count == 0) {
    rc = 0;
    goto out;
  }
  if (duckdb_prepare (connection,
      "SELECT COUNT(*) FROM main.fact_batches WHERE batch_id = ?;",
      &statement) != DuckDBSuccess) {
    rc = 305;
    goto out;
  }
  if (duckdb_bind_varchar (statement, 1, batch_id) != DuckDBSuccess
      || duckdb_execute_prepared (statement, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    rc = 306;
    goto out;
  }
  have_result = TRUE;
  gint64 batch_count = duckdb_value_int64 (&result, 0, 0);
  rc = batch_count == 0 ? 0 : 307;

out:
  if (have_result)
    duckdb_destroy_result (&result);
  duckdb_destroy_prepare (&statement);
  duckdb_disconnect (&connection);
  duckdb_close (&database);
  duckdb_destroy_config (&config);
  duckdb_free (open_error);
  return rc;
}

static gint
check_fact_projection_batch_rows (const gchar *fact_root,
    const gchar *graph_id, const gchar *batch_id, gint64 expected_rows)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 300;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 301;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK)
    return 302;
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = graph_id,
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
    return 303;
  return rows == expected_rows ? 0 : 304;
}

#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
static gint
seed_legacy_fact_metadata (const gchar *fact_root, const gchar *graph_id,
    const gchar *sql)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 4100;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 4101;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  {
    g_autoptr (wyl_fact_store_t) store = NULL;
    if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK
        || wyl_fact_store_create_schema (store) != WYRELOG_E_OK)
      return 4102;
  }
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  duckdb_result result = { 0 };
  if (duckdb_open (db_path, &database) != DuckDBSuccess
      || duckdb_connect (database, &connection) != DuckDBSuccess
      || duckdb_query (connection, sql, &result) != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    duckdb_disconnect (&connection);
    duckdb_close (&database);
    return 4103;
  }
  duckdb_destroy_result (&result);
  duckdb_disconnect (&connection);
  duckdb_close (&database);
  g_autoptr (GError) error = NULL;
  if (!wyl_test_secure_regular_file (db_path, &error))
    return 4104;
  return 0;
}

static gint
check_legacy_metadata_key_count (const gchar *fact_root,
    const gchar *graph_id, const gchar *key, gint64 expected)
{
  WylFactGraphLocator locator = { 0 };
  if (wyl_fact_graph_locator_init (&locator, WYL_TENANT_DEFAULT, graph_id)
      != WYRELOG_E_OK)
    return 4110;
  g_autofree gchar *path =
      wyl_fact_graph_locator_descriptive_path (fact_root, &locator);
  wyl_fact_graph_locator_clear (&locator);
  if (path == NULL)
    return 4111;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  duckdb_database database = NULL;
  duckdb_connection connection = NULL;
  if (duckdb_open (db_path, &database) != DuckDBSuccess
      || duckdb_connect (database, &connection) != DuckDBSuccess) {
    duckdb_disconnect (&connection);
    duckdb_close (&database);
    return 4112;
  }
  duckdb_prepared_statement statement = NULL;
  duckdb_result result = { 0 };
  if (duckdb_prepare (connection,
      "SELECT COUNT(*) FROM fact_store_metadata WHERE key=?;", &statement)
      != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    duckdb_disconnect (&connection);
    duckdb_close (&database);
    return 4113;
  }
  if (duckdb_bind_varchar (statement, 1, key) != DuckDBSuccess
      || duckdb_execute_prepared (statement, &result) != DuckDBSuccess) {
    duckdb_destroy_prepare (&statement);
    duckdb_destroy_result (&result);
    duckdb_disconnect (&connection);
    duckdb_close (&database);
    return 4114;
  }
  duckdb_destroy_prepare (&statement);
  gint64 count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  duckdb_disconnect (&connection);
  duckdb_close (&database);
  return count == expected ? 0 : 4115;
}
#endif

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)
static void
identity_http_post (SoupSession *session, const gchar *base_url,
    const gchar *token, const gchar *path, const gchar *query,
    const gchar *payload, guint expected_status, const gchar *expected_body)
{
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_assert_cmpint (send_raw (session, "POST", base_url, path, query, token,
      payload, &status, &body), ==, 0);
  g_assert_cmpuint (status, ==, expected_status);
  g_assert_nonnull (strstr (body, expected_body));
}

static void
identity_http_post_committed (SoupSession *session, const gchar *base_url,
    const gchar *token, const gchar *path, const gchar *query,
    const gchar *payload)
{
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_assert_cmpint (send_raw (session, "POST", base_url, path, query, token,
      payload, &status, &body), ==, 0);
  g_assert_true (status == 200 || status == 202);
  g_assert_nonnull (strstr (body, "\"committed\":true"));
  if (status == 202) {
    g_assert_nonnull (strstr (body, "\"operation_id\":"));
    g_assert_nonnull (strstr (body, "\"quota_state\":\"reconciling\""));
  } else {
    g_assert_nonnull (strstr (body, "\"inserted\":true"));
  }
}

static gchar *
identity_http_snapshot (duckdb_connection conn, const gchar *table)
{
  g_autofree gchar *projection = g_strdup_printf
        ("SELECT * FROM %s ORDER BY 1;", table);
  const gchar *queries[] = {
    "SELECT key,value FROM fact_store_metadata ORDER BY key;",
    "SELECT * FROM fact_batches ORDER BY batch_id;", projection
  };
  GString *snapshot = g_string_new (NULL);
  for (gsize i = 0; i < G_N_ELEMENTS (queries); i++) {
    duckdb_result result;
    duckdb_state state = duckdb_query (conn, queries[i], &result);
    if (state != DuckDBSuccess)
      g_printerr ("identity snapshot query %s: %s\n", queries[i],
          duckdb_result_error (&result));
    g_assert_cmpint (state, ==, DuckDBSuccess);
    g_string_append_printf (snapshot, "%zu/%llu/%llu:", i,
        (unsigned long long) duckdb_row_count (&result),
        (unsigned long long) duckdb_column_count (&result));
    for (idx_t row = 0; row < duckdb_row_count (&result); row++)
      for (idx_t col = 0; col < duckdb_column_count (&result); col++) {
        gchar *value = duckdb_value_varchar (&result, col, row);
        g_string_append_printf (snapshot, "%d/%zu:%s;", value != NULL,
            value == NULL ? 0 : strlen (value), value == NULL ? "" : value);
        duckdb_free (value);
      }
    duckdb_destroy_result (&result);
  }
  return g_string_free (snapshot, FALSE);
}

static void
check_provisioned_http_identity (WylHandle *handle, SoupSession *session,
    const gchar *root, const gchar *base_url, const gchar *token,
    const gchar *schema_body)
{
  const gchar *graph = "identity-1000";
  const gchar *path = "/facts/__wr_default/identity-1000/orders:append";
  const gchar *create_query = "tenant=__wr_default&graph=identity-1000&" FACT_GUARD;
  const gchar *schema_query = "tenant=__wr_default&graph=identity-1000&"
      "namespace=shop&relation=orders&schema_version=1&" FACT_GUARD;
  const gchar *control_query = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=identity-control&idempotency_key=identity-control&" FACT_GUARD;
  const gchar *retry_query = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=identity-retry&idempotency_key=identity-retry&" FACT_GUARD;
  const gchar *payload = "order_id\tamount\nidentity-retry\t23\n";
  identity_http_post (session, base_url, token, "/graphs/create", create_query,
      NULL, 200, "\"created\":true");
  identity_http_post (session, base_url, token, "/facts/schema/register",
      schema_query, schema_body, 200, "\"ok\":true");
  identity_http_post_committed (session, base_url, token, path, control_query,
      "order_id\tamount\nidentity-control\t17\n");

  wyl_policy_store_t *policy = wyl_handle_get_policy_store (handle);
  GPtrArray *records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (policy,
      WYL_TENANT_DEFAULT, &records), ==, WYRELOG_E_OK);
  WylPolicyGraphProvisioningRecord *record = NULL;
  for (guint i = 0; i < records->len; i++) {
    WylPolicyGraphProvisioningRecord *item = g_ptr_array_index (records, i);
    if (g_strcmp0 (item->graph_id, graph) == 0) {
      g_assert_null (record);
      record = item;
    }
  }
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_policy_store_open_fact_graph_directory (policy, root,
      WYL_TENANT_DEFAULT, graph, FALSE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphProvisionedPair *pair = NULL;
#ifdef __APPLE__
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  gsize length = 0;
  const guint8 *bytes = g_bytes_get_data (record->darwin_operation_evidence,
          &length);
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode (bytes, length,
      record->op_uuid, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint
    (wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
        (&directory, record->op_uuid, &evidence, &pair), ==, WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&directory, record->op_uuid, &pair), ==, WYRELOG_E_OK);
#endif
  WylFactArtifactNamespace *namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (pair, &namespace_), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"order_id", "symbol", FALSE, TRUE},
    {"amount", "int64", FALSE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT, .graph_id = graph,
    .namespace_id = "shop", .relation_name = "orders", .schema_version = 1,
    .columns = columns, .n_columns = G_N_ELEMENTS (columns),
  };
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  g_assert_nonnull (table);
  WylFactGraphRuntimeStatus before = { 0 }, after = { 0 };
  g_assert_cmpint (wyl_handle_get_fact_graph_runtime_status (handle,
      WYL_TENANT_DEFAULT, graph, &before), ==, WYRELOG_E_OK);
  WylSecureDuckdbBridge *bridge = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      &bridge, &db, &conn), ==, WYRELOG_E_OK);
  duckdb_result result;
  g_assert_cmpint (duckdb_query (conn, "UPDATE fact_store_metadata SET "
      "value='01890f47-3c4b-7cc2-b8c4-dc0c0c079999' "
      "WHERE key='store_uuid';", &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
  g_autofree gchar *snapshot = identity_http_snapshot (conn, table);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);

  identity_http_post (session, base_url, token, path, retry_query, payload,
      409, "\"fact_batch_conflict\"");
  g_assert_cmpint (wyl_handle_get_fact_graph_runtime_status (handle,
      WYL_TENANT_DEFAULT, graph, &after), ==, WYRELOG_E_OK);
  g_assert_cmpuint (before.engine_generation, ==, after.engine_generation);
  g_assert_cmpuint (before.operation_generation, ==, after.operation_generation);
  wyl_fact_graph_runtime_status_clear (&before);
  wyl_fact_graph_runtime_status_clear (&after);
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      &bridge, &db, &conn), ==, WYRELOG_E_OK);
  g_autofree gchar *unchanged = identity_http_snapshot (conn, table);
  g_assert_cmpstr (snapshot, ==, unchanged);
  g_autofree gchar *restore = g_strdup_printf
        ("UPDATE fact_store_metadata SET value='%s' WHERE key='store_uuid';",
          record->store_uuid);
  g_assert_cmpint (duckdb_query (conn, restore, &result), ==, DuckDBSuccess);
  duckdb_destroy_result (&result);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);
  identity_http_post (session, base_url, token, path, retry_query, payload,
      200, "\"inserted\":true");
  g_assert_cmpint (wyl_secure_duckdb_bridge_open_live_pair (namespace_, TRUE,
      &bridge, &db, &conn), ==, WYRELOG_E_OK);
  g_autofree gchar *count_sql = g_strdup_printf
        ("SELECT (SELECT COUNT(*) FROM fact_batches),"
          "(SELECT COUNT(*) FROM %s);", table);
  g_assert_cmpint (duckdb_query (conn, count_sql, &result), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, 2);
  g_assert_cmpint (duckdb_value_int64 (&result, 1, 0), ==, 2);
  duckdb_destroy_result (&result);
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  g_assert_cmpint (wyl_secure_duckdb_bridge_release_live (bridge), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_provisioned_pair_free (pair);
  wyl_fact_graph_directory_clear (&directory);
  g_ptr_array_unref (records);
}
#endif

/* Explicit lengths are essential: strlen would hide the NUL regression. */
static void
tsv_post (SoupSession *session, const gchar *base_url, const gchar *token,
    const gchar *path, const gchar *query, const gchar *payload, gsize length,
    guint expected_status, const gchar *expected_body)
{
  g_autofree gchar *uri = build_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new ("POST", uri);
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s", token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);
  g_autoptr (GBytes) request = g_bytes_new (payload, length);
  soup_message_set_request_body_from_bytes (msg,
      "text/tab-separated-values", request);
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) response = soup_session_send_and_read (session, msg,
          NULL, &error);
  g_assert_no_error (error);
  g_assert_nonnull (response);
  gsize size = 0;
  const gchar *data = g_bytes_get_data (response, &size);
  g_autofree gchar *body = g_strndup (data, size);
  if (soup_message_get_status (msg) != expected_status
      || strstr (body, expected_body) == NULL)
    g_printerr ("TSV response: %s\n", body);
  g_assert_cmpuint (soup_message_get_status (msg), ==, expected_status);
  g_assert_nonnull (strstr (body, expected_body));
}

/* Read-only proof covers durable rows, events and batch accounting, without
 * provisioning a missing table as a side effect of the assertion. */
static void
tsv_check_store (const gchar *root, const gchar *relation,
    const gchar *expected_a, const gchar *expected_b, gint64 expected_rows,
    gint64 expected_batches)
{
  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator,
      WYL_TENANT_DEFAULT, "tsv"), ==, WYRELOG_E_OK);
  g_autofree gchar *path = wyl_fact_graph_locator_descriptive_path (root,
          &locator);
  wyl_fact_graph_locator_clear (&locator);
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  duckdb_config config = NULL;
  duckdb_database db = NULL;
  duckdb_connection conn = NULL;
  g_assert_cmpint (duckdb_create_config (&config), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_set_config (config, "access_mode", "READ_ONLY"),
      ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_open_ext (db_path, &db, config, NULL), ==,
      DuckDBSuccess);
  g_assert_cmpint (duckdb_connect (db, &conn), ==, DuckDBSuccess);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    { "a", "string", FALSE, TRUE }, { "b", "string", FALSE, TRUE }
  };
  const wyl_policy_fact_relation_schema_options_t schema = {
    .tenant_id = WYL_TENANT_DEFAULT, .graph_id = "tsv",
    .namespace_id = "shop", .relation_name = relation, .schema_version = 1,
    .columns = columns, .n_columns = 2, .relation_visible = TRUE,
  };
  g_autofree gchar *table = wyl_fact_store_projection_table_name (&schema);
  g_autofree gchar *sql = g_strdup_printf ("SELECT * FROM %s ORDER BY "
          "__wyl_batch_id, __wyl_row_index;", table);
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (conn, sql, &result), ==, DuckDBSuccess);
  g_assert_cmpuint (duckdb_row_count (&result), ==, expected_rows);
  if (expected_a != NULL) {
    gchar *a = duckdb_value_varchar (&result, 0, 0);
    g_assert_cmpstr (a, ==, expected_a);
    duckdb_free (a);
  }
  if (expected_b != NULL) {
    gchar *b = duckdb_value_varchar (&result, 1, 0);
    g_assert_cmpstr (b, ==, expected_b);
    duckdb_free (b);
  }
  if (g_strcmp0 (relation, "single") == 0) {
    const gchar *values[] = { "   ", "NULL", "v", "last\r" };
    for (gsize i = 0; i < G_N_ELEMENTS (values); i++) {
      gchar *value = duckdb_value_varchar (&result, 0, i);
      g_assert_cmpstr (value, ==, values[i]);
      duckdb_free (value);
    }
  }
  duckdb_destroy_result (&result);
  g_assert_cmpint (duckdb_query (conn,
      "SELECT (SELECT count(*) FROM fact_batches), "
      "(SELECT count(*) FROM fact_event_log);", &result), ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, expected_batches);
  g_assert_cmpint (duckdb_value_int64 (&result, 1, 0), ==,
      expected_rows + (g_strcmp0 (relation, "single") == 0 ? 2 : 0));
  duckdb_destroy_result (&result);
  /* Nullable writes are all rejected. Check their target projection directly,
   * including the legitimate case where no physical table was ever created. */
  wyl_policy_fact_relation_schema_options_t nullable_schema = schema;
  nullable_schema.relation_name = "nullable";
  g_autofree gchar *nullable_table =
      wyl_fact_store_projection_table_name (&nullable_schema);
  g_autofree gchar *exists_sql = g_strdup_printf (
    "SELECT count(*) FROM information_schema.tables WHERE "
    "table_schema='main' AND table_name='%s';", nullable_table);
  g_assert_cmpint (duckdb_query (conn, exists_sql, &result), ==, DuckDBSuccess);
  gboolean exists = duckdb_value_int64 (&result, 0, 0) != 0;
  duckdb_destroy_result (&result);
  if (exists) {
    g_autofree gchar *empty_sql = g_strdup_printf (
      "SELECT count(*) FROM %s;", nullable_table);
    g_assert_cmpint (duckdb_query (conn, empty_sql, &result), ==, DuckDBSuccess);
    g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, 0);
    duckdb_destroy_result (&result);
  }
  duckdb_disconnect (&conn);
  duckdb_close (&db);
  duckdb_destroy_config (&config);
}

static void
tsv_check_schema_absent (WylHandle *handle)
{
  wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
  gsize n_columns = 0;
  gboolean visible = FALSE;
  g_assert_cmpint (wyl_policy_store_load_fact_relation_schema_columns (
        wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "tsv",
        "shop", "single", 1, &visible, &columns, &n_columns), ==,
      WYRELOG_E_NOT_FOUND);
  wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
}

static void
check_tsv_fidelity (WylHandle *handle, SoupSession *session, const gchar *base_url,
    const gchar *token, const gchar *root)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  const gchar *create = "tenant=__wr_default&graph=tsv&" FACT_GUARD;
  tsv_post (session, base_url, token, "/graphs/create", create, "", 0,
      200, "\"created\":true");
  const gchar *schema_query = "tenant=__wr_default&graph=tsv&namespace=shop&"
      "relation=pair&schema_version=1&" FACT_GUARD;
  const gchar *schema = "column_name\tcolumn_type\tnullable\tvisible\r\n"
      "a\tstring\tfalse\ttrue\r\nb\tstring\tfalse\ttrue\r\n";
  tsv_post (session, base_url, token, "/facts/schema/register", schema_query,
      schema, strlen (schema), 200, "\"ok\":true");
  const gchar *append = "/facts/__wr_default/tsv/pair:append";
  const gchar *batch = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=pad&idempotency_key=pad&" FACT_GUARD;
  const gchar *padding = "a\tb\r\npad   \tpad   \r\n";
  tsv_post (session, base_url, token, append, batch, padding,
      strlen (padding), 200, "\"logical_byte_delta\":12");
  tsv_check_store (root, "pair", "pad   ", "pad   ", 1, 1);

  /*
   * Replaying the same batch reports the cost it committed, not zero, so a
   * client that lost its accounting to a crash can settle from the retry
   * response (#1013).  "inserted":false is what still marks it a replay, and
   * is what a client summing these must key on.  The store is unchanged: one
   * row, one batch.
   */
  tsv_post (session, base_url, token, append, batch, padding,
      strlen (padding), 200, "\"logical_byte_delta\":12");
  tsv_post (session, base_url, token, append, batch, padding,
      strlen (padding), 200, "\"inserted\":false");
  tsv_check_store (root, "pair", "pad   ", "pad   ", 1, 1);

  const gchar *bad_rows[] = { "a\tb\nok\tok\n\nbad\tbad\n",
                              "a\tb\nok\tok\n\n", "a\tb\r\nok\tok\r\n\r\n",
                              "a\tb\nok\tok\nwrong\twidth\textra\n" };
  const gchar *reject_batch = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=reject&idempotency_key=reject&" FACT_GUARD;
  for (gsize i = 0; i < G_N_ELEMENTS (bad_rows); i++) {
    tsv_post (session, base_url, token, append, reject_batch, bad_rows[i],
        strlen (bad_rows[i]), 400, "invalid_fact_payload");
    tsv_check_store (root, "pair", "pad   ", "pad   ", 1, 1);
  }
  static const gchar nul_rows[] = "a\tb\nok\tok\n\0ignored\trow\n";
  tsv_post (session, base_url, token, append, reject_batch, nul_rows,
      sizeof nul_rows - 1, 400, "invalid_fact_payload");
  tsv_check_store (root, "pair", "pad   ", "pad   ", 1, 1);

  /* Nullable text rejects ambiguous cells atomically, after a valid row. */
  const gchar *nullable_schema = "a\tstring\ttrue\ttrue\n"
      "b\tsymbol\ttrue\ttrue";
  const gchar *nullable_query = "tenant=__wr_default&graph=tsv&namespace=shop&"
      "relation=nullable&schema_version=1&" FACT_GUARD;
  tsv_post (session, base_url, token, "/facts/schema/register", nullable_query,
      nullable_schema, strlen (nullable_schema), 200, "\"ok\":true");
  const gchar *nullable_rows[] = { "a\tb\nok\tok\nNULL\tx\n",
                                   "a\tb\nok\tok\n\tx\n", "a\tb\nok\tok\nx\tNULL\n",
                                   "a\tb\nok\tok\nx\t\n" };
  for (gsize i = 0; i < G_N_ELEMENTS (nullable_rows); i++) {
    tsv_post (session, base_url, token,
        "/facts/__wr_default/tsv/nullable:append", reject_batch,
        nullable_rows[i], strlen (nullable_rows[i]), 400,
        "invalid_fact_payload");
    tsv_check_store (root, "pair", "pad   ", "pad   ", 1, 1);
  }

  const gchar *header_batch = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=header&idempotency_key=header&" FACT_GUARD;
  const gchar *header_rows = "a\tb\na\tb";
  tsv_post (session, base_url, token, append, header_batch, header_rows,
      strlen (header_rows), 200, "\"committed_row_delta\":1");
  tsv_check_store (root, "pair", "a", "b", 2, 2);

  /* Physical admission is implemented by the secure DuckDB bridge.  The
   * portable HTTP fixture also runs in builds without that bridge, where the
   * quota status API remains available but cannot reserve artifact evidence.
   * Keep this boundary assertion with the implementation it exercises. */
#ifdef WYL_HAS_SECURE_DUCKDB_BRIDGE
  WylPolicyFactPhysicalQuotaStatus physical_before_guard = { 0 };
  g_assert_cmpint (wyl_policy_store_get_fact_physical_quota_status (store,
      WYL_TENANT_DEFAULT, &physical_before_guard), ==, WYRELOG_E_OK);
  g_assert_true (physical_before_guard.has_limit);
  g_assert_cmpuint (physical_before_guard.pending_bytes, ==, 0);
  g_assert_cmpuint (physical_before_guard.reconciling_bytes, ==, 0);
  WylPolicyFactQuotaConfig physical_guard_quota = {
    .has_limit = TRUE,
    .hard_limit = physical_before_guard.committed_bytes,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (store,
      WYL_TENANT_DEFAULT, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES,
      &physical_guard_quota), ==, WYRELOG_E_OK);
  g_autofree gchar *physical_guard_query = g_strdup_printf (
    "tenant=%s&namespace=shop&schema_version=1&"
    "batch_id=quota-physical-boundary-9f4c&"
    "idempotency_key=quota-physical-boundary-9f4c&%s", WYL_TENANT_DEFAULT,
    FACT_GUARD);
  tsv_post (session, base_url, token, append, physical_guard_query,
      "a\tb\nphysical\tguard\n", strlen ("a\tb\nphysical\tguard\n"),
      429, "\"dimension\":\"physical_bytes\"");
  tsv_check_store (root, "pair", "a", "b", 2, 2);
  WylPolicyFactPhysicalQuotaStatus physical_after_guard = { 0 };
  g_assert_cmpint (wyl_policy_store_get_fact_physical_quota_status (store,
      WYL_TENANT_DEFAULT, &physical_after_guard), ==, WYRELOG_E_OK);
  g_assert_cmpuint (physical_after_guard.committed_bytes, ==,
      physical_before_guard.committed_bytes);
  g_assert_cmpuint (physical_after_guard.pending_bytes, ==, 0);
  g_assert_cmpuint (physical_after_guard.reconciling_bytes, ==, 0);
  WylPolicyFactQuotaConfig restore_physical_quota = {
    .has_limit = TRUE,
    .hard_limit = G_MAXINT64,
  };
  g_assert_cmpint (wyl_policy_store_set_fact_quota_config (store,
      WYL_TENANT_DEFAULT, WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES,
      &restore_physical_quota), ==, WYRELOG_E_OK);
#endif

  const gchar *bad_schemas[] = { "v\tstring\tfalse\ttrue   \n",
                                 "v\tstring\tfalse\ttrue\n\n", "\nv\tstring\tfalse\ttrue\n",
                                 "v\tstring\tfalse\ttrue\r\n\r\n",
                                 "v\tstring\tfalse\ttrue\ncolumn_name\tcolumn_type\tnullable\tvisible\n" };
  const gchar *single_query = "tenant=__wr_default&graph=tsv&namespace=shop&"
      "relation=single&schema_version=1&" FACT_GUARD;
  for (gsize i = 0; i < G_N_ELEMENTS (bad_schemas); i++) {
    tsv_post (session, base_url, token, "/facts/schema/register", single_query,
        bad_schemas[i], strlen (bad_schemas[i]), 400, "invalid_schema_payload");
    tsv_check_schema_absent (handle);
  }
  static const gchar nul_schema[] = "v\tstring\tfalse\ttrue\n\0ignored";
  tsv_post (session, base_url, token, "/facts/schema/register", single_query,
      nul_schema, sizeof nul_schema - 1, 400, "invalid_schema_payload");
  tsv_check_schema_absent (handle);
  const gchar *single_schema = "v\tstring\tfalse\ttrue";
  tsv_post (session, base_url, token, "/facts/schema/register", single_query,
      single_schema, strlen (single_schema), 200, "\"ok\":true");
  const gchar *single_path = "/facts/__wr_default/tsv/single:append";
  const gchar *single_rows = "v\n   \nNULL\nv\nlast\r";
  const gchar *single_batch = "tenant=__wr_default&namespace=shop&schema_version=1&"
      "batch_id=single&idempotency_key=single&" FACT_GUARD;
  tsv_post (session, base_url, token, single_path, single_batch, single_rows,
      strlen (single_rows), 200, "\"committed_row_delta\":4");
  tsv_check_store (root, "single", "   ", NULL, 4, 3);
}

static gint
check_fact_http_contract (WylHandle *handle, SoupServer *server,
    const gchar *fact_root, const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autoptr (WylClient) admin_client = NULL;
  g_autoptr (WylClient) deny_client = NULL;
  if (wyl_client_new (base_url, &admin_client) != WYRELOG_E_OK ||
      wyl_client_new (base_url, &deny_client) != WYRELOG_E_OK)
    return 10;

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (admin_client, "facts-admin")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 11;
  }
  if (wyl_client_login_skip_mfa (deny_client, "facts-deny")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 12;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  g_autofree gchar *admin_token = wyl_client_dup_access_token (admin_client);
  g_autofree gchar *deny_token = wyl_client_dup_access_token (deny_client);
  if (admin_token == NULL || deny_token == NULL)
    return 13;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean tenant_b_created = FALSE;
  if (wyl_policy_store_create_tenant (store, "tenant-b", &tenant_b_created)
      != WYRELOG_E_OK)
    return 131;
  WylPolicyFactQuotaConfig tenant_b_quota = {
    .has_limit = TRUE,
    .rate_per_second = 3,
    .burst = 4,
  };
  if (wyl_policy_store_set_fact_quota_config (store, "tenant-b",
      WYL_POLICY_FACT_QUOTA_WRITE_RATE, &tenant_b_quota) != WYRELOG_E_OK)
    return 132;

  /* Graph-management capability alone must not expose quota controls. */
  guint quota_status = 0;
  g_autofree gchar *quota_body = NULL;
  g_autofree gchar *quota_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  gint quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          quota_query, NULL, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 401 ||
      strstr (quota_body, "\"fact_quota_auth_required\"") == NULL)
    return 14;
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          quota_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 403 ||
      strstr (quota_body, "\"fact_quota_denied\"") == NULL)
    return 15;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *unauthorized_configure_query = g_strdup_printf (
    "tenant=%s&limit=1000&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          unauthorized_configure_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 403 ||
      strstr (quota_body, "\"fact_quota_denied\"") == NULL)
    return 151;

  /* The dedicated system-admin role is the only tested grant for quota
   * configuration; it is added after graph-only denial is established. */
  if (wyl_policy_store_grant_role_membership (store, "facts-admin",
      "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK ||
      wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 16;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *configure_query = g_strdup_printf (
    "tenant=%s&limit=1000&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          configure_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200 ||
      strstr (quota_body, "\"dimension\":\"graph_count\"") == NULL ||
      strstr (quota_body, "\"limit\":1000") == NULL ||
      strstr (quota_body, "\"committed\":0") == NULL ||
      strstr (quota_body, "\"pending\":0") == NULL)
    return 17;
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          quota_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200 ||
      strstr (quota_body, "\"limit\":1000") == NULL) {
    g_printerr ("quota GET mismatch rc=%d status=%u body=%s\n", quota_rc,
        quota_status, quota_body != NULL ? quota_body : "(null)");
    return 18;
  }
  g_clear_pointer (&quota_body, g_free);
  WylClientFactLogicalQuotaStatus logical_quota_status = { 0 };
  if (wyl_client_fact_logical_quota_configure (admin_client,
      WYL_TENANT_DEFAULT, 1000, 100000, 0, "trusted", 0,
      &logical_quota_status) != WYRELOG_E_OK
      || !logical_quota_status.has_limit
      || logical_quota_status.logical_row_limit != 1000
      || logical_quota_status.logical_byte_limit != 100000) {
    wyl_client_fact_logical_quota_status_clear (&logical_quota_status);
    return 182;
  }
  wyl_client_fact_logical_quota_status_clear (&logical_quota_status);
  if (wyl_client_fact_logical_quota_status (admin_client, WYL_TENANT_DEFAULT,
      0, "trusted", 0, &logical_quota_status) != WYRELOG_E_OK
      || logical_quota_status.committed_rows != 0
      || logical_quota_status.committed_bytes != 0) {
    wyl_client_fact_logical_quota_status_clear (&logical_quota_status);
    return 183;
  }
  wyl_client_fact_logical_quota_status_clear (&logical_quota_status);
  g_autofree gchar *graph_get_legacy_limit_query = g_strdup_printf (
    "tenant=%s&limit=1000&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          graph_get_legacy_limit_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"graph_count\"") == NULL)
    return 181;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *schema_quota_configure_query = g_strdup_printf (
    "tenant=%s&dimension=schema_count&limit=1000&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          schema_quota_configure_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"schema_count\"") == NULL
      || strstr (quota_body, "\"limit\":1000") == NULL
      || strstr (quota_body, "\"registered\":") == NULL)
    return 182;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *schema_quota_status_query = g_strdup_printf (
    "tenant=%s&dimension=schema_count&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          schema_quota_status_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"schema_count\"") == NULL
      || strstr (quota_body, "\"registered\":") == NULL)
    return 183;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *physical_quota_configure_query = g_strdup_printf (
    "tenant=%s&dimension=physical_bytes&limit=4096&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          physical_quota_configure_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"physical_bytes\"") == NULL
      || strstr (quota_body, "\"limit\":4096") == NULL
      || strstr (quota_body, "\"committed_bytes\":0") == NULL
      || strstr (quota_body, "\"pending_bytes\":0") == NULL
      || strstr (quota_body, "\"reconciling_bytes\":0") == NULL)
    return 184;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *physical_quota_status_query = g_strdup_printf (
    "tenant=%s&dimension=physical_bytes&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          physical_quota_status_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"physical_bytes\"") == NULL
      || strstr (quota_body, "\"limit\":4096") == NULL
      || strstr (quota_body, "\"reconciling_bytes\":0") == NULL)
    return 185;
  WylClientFactQuotaStatus quota_client_status = { 0 };
  if (wyl_client_fact_quota_status (admin_client, WYL_TENANT_DEFAULT,
      0, "trusted", 0, &quota_client_status) != WYRELOG_E_OK ||
      !quota_client_status.has_limit || quota_client_status.hard_limit != 1000 ||
      quota_client_status.committed != 0 || quota_client_status.pending != 0) {
    wyl_client_fact_quota_status_clear (&quota_client_status);
    return 19;
  }
  wyl_client_fact_quota_status_clear (&quota_client_status);
  WylClientFactPhysicalQuotaStatus physical_client_status = { 0 };
  if (wyl_client_fact_physical_quota_status (admin_client,
      WYL_TENANT_DEFAULT, 0, "trusted", 0, &physical_client_status)
      != WYRELOG_E_OK || !physical_client_status.has_limit
      || physical_client_status.hard_limit != 4096
      || physical_client_status.committed_bytes != 0
      || physical_client_status.pending_bytes != 0
      || physical_client_status.reconciling_bytes != 0) {
    wyl_client_fact_physical_quota_status_clear (&physical_client_status);
    return 186;
  }
  wyl_client_fact_physical_quota_status_clear (&physical_client_status);

  /* The fidelity fixture intentionally exercises many writes.  Keep the
   * endpoint contract assertion above at 4096, then give that fixture a
   * generous bound; the focused admission check below restores the boundary
   * against the actual committed usage. */
  WylPolicyFactQuotaConfig fidelity_physical_quota = {
    .has_limit = TRUE,
    .hard_limit = G_MAXINT64,
  };
  if (wyl_policy_store_set_fact_quota_config (store, WYL_TENANT_DEFAULT,
      WYL_POLICY_FACT_QUOTA_PHYSICAL_BYTES, &fidelity_physical_quota)
      != WYRELOG_E_OK)
    return 1861;

  /* Write-rate configuration uses the same guarded endpoint but a distinct
   * typed response and storage dimension. */
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_configure_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_configure_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"dimension\":\"write_rate\"") == NULL
      || strstr (quota_body, "\"rate_per_second\":7") == NULL
      || strstr (quota_body, "\"burst\":11") == NULL)
    return 191;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_status_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          rate_status_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200
      || strstr (quota_body, "\"rate_per_second\":7") == NULL
      || strstr (quota_body, "\"burst\":11") == NULL)
    return 192;
  WylClientFactWriteRateQuotaStatus write_rate_client_status = { 0 };
  if (wyl_client_fact_write_rate_quota_status (admin_client,
      WYL_TENANT_DEFAULT, 123, "trusted", 0, &write_rate_client_status)
      != WYRELOG_E_OK || !write_rate_client_status.has_limit
      || write_rate_client_status.rate_per_second != 7
      || write_rate_client_status.burst != 11) {
    wyl_client_fact_write_rate_quota_status_clear (&write_rate_client_status);
    return 1921;
  }
  wyl_client_fact_write_rate_quota_status_clear (&write_rate_client_status);
  if (wyl_client_fact_write_rate_quota_configure (admin_client,
      WYL_TENANT_DEFAULT, 8, 12, 123, "trusted", 0,
      &write_rate_client_status) != WYRELOG_E_OK
      || !write_rate_client_status.has_limit
      || write_rate_client_status.rate_per_second != 8
      || write_rate_client_status.burst != 12) {
    wyl_client_fact_write_rate_quota_status_clear (&write_rate_client_status);
    return 1922;
  }
  wyl_client_fact_write_rate_quota_status_clear (&write_rate_client_status);
  g_clear_pointer (&quota_body, g_free);
  if (sqlite3_exec (wyl_policy_store_get_db (store),
      "DROP TABLE fact_tenant_quota_limits;", NULL, NULL, NULL) != SQLITE_OK)
    return 1920;
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          quota_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 500
      || strstr (quota_body, "\"fact_quota_status_failed\"") == NULL)
    return 19201;
  g_clear_pointer (&quota_body, g_free);
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK)
    return 19202;
  WylPolicyFactQuotaConfig restore_graph_quota = {
    .has_limit = TRUE,
    .hard_limit = 1000,
  };
  WylPolicyFactQuotaConfig restore_rate_quota = {
    .has_limit = TRUE,
    .rate_per_second = 7,
    .burst = 11,
  };
  if (wyl_policy_store_set_fact_quota_config (store, WYL_TENANT_DEFAULT,
      WYL_POLICY_FACT_QUOTA_GRAPH_COUNT, &restore_graph_quota) != WYRELOG_E_OK
      || wyl_policy_store_set_fact_quota_config (store, WYL_TENANT_DEFAULT,
      WYL_POLICY_FACT_QUOTA_WRITE_RATE, &restore_rate_quota) != WYRELOG_E_OK)
    return 19203;
  if (wyl_policy_store_set_fact_quota_config (store, "tenant-b",
      WYL_POLICY_FACT_QUOTA_WRITE_RATE, &tenant_b_quota) != WYRELOG_E_OK)
    return 19204;
  g_autofree gchar *rate_max_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=%" G_GUINT64_FORMAT
    "&burst=%" G_GUINT64_FORMAT "&%s", WYL_TENANT_DEFAULT,
    (guint64) G_MAXINT64, (guint64) G_MAXINT64, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_max_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 1921;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_overflow_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=9223372036854775808"
    "&burst=11&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_overflow_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 1922;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *burst_overflow_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&"
    "burst=9223372036854775808&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          burst_overflow_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 1924;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_restore_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_restore_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 1923;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_invalid_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=0&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_invalid_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400
      || strstr (quota_body, "\"invalid_fact_quota_request\"") == NULL)
    return 193;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_mixed_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=11&limit=9&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_mixed_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400
      || strstr (quota_body, "\"invalid_fact_quota_request\"") == NULL)
    return 194;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *unknown_dimension_query = g_strdup_printf (
    "tenant=%s&dimension=unknown&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          unknown_dimension_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400
      || strstr (quota_body, "\"invalid_fact_quota_request\"") == NULL)
    return 195;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_negative_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=-1&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_negative_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 196;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_non_numeric_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=NaN&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_non_numeric_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 197;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_get_mixed_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=11&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          rate_get_mixed_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 198;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_burst_zero_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=0&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_burst_zero_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 199;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_burst_negative_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=-1&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_burst_negative_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 200;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_burst_non_numeric_query = g_strdup_printf (
    "tenant=%s&dimension=write_rate&rate_per_second=7&burst=NaN&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_burst_non_numeric_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 400)
    return 201;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_cross_tenant_query = g_strdup_printf (
    "tenant=tenant-b&dimension=write_rate&%s", FACT_GUARD);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          rate_cross_tenant_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 403
      || strstr (quota_body, "\"tenant_denied\"") == NULL) {
    g_printerr ("write-rate cross-tenant mismatch rc=%d status=%u body=%s\n",
        quota_rc, quota_status, quota_body != NULL ? quota_body : "(null)");
    return 202;
  }
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *rate_cross_tenant_post_query = g_strdup_printf (
    "tenant=tenant-b&dimension=write_rate&rate_per_second=99&burst=99&%s",
    FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_cross_tenant_post_query, admin_token, NULL, &quota_status,
          &quota_body);
  if (quota_rc != 0 || quota_status != 403
      || strstr (quota_body, "\"tenant_denied\"") == NULL)
    return 203;
  WylPolicyFactQuotaConfig cross_status = { 0 };
  wyrelog_error_t cross_status_rc = wyl_policy_store_get_fact_quota_config
        (store, "tenant-b", WYL_POLICY_FACT_QUOTA_WRITE_RATE, &cross_status);
  if (cross_status_rc != WYRELOG_E_OK || !cross_status.has_limit
      || cross_status.rate_per_second != 3 || cross_status.burst != 4) {
    g_printerr ("cross quota state rc=%d has=%d rate=%" G_GUINT64_FORMAT
        " burst=%" G_GUINT64_FORMAT "\n", cross_status_rc,
        cross_status.has_limit, cross_status.rate_per_second,
        cross_status.burst);
    return 2031;
  }
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          rate_status_query, NULL, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 401
      || strstr (quota_body, "\"fact_quota_auth_required\"") == NULL)
    return 204;
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          rate_restore_query, NULL, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 401
      || strstr (quota_body, "\"fact_quota_auth_required\"") == NULL)
    return 205;

  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = 0;
  check_tsv_fidelity (handle, session, base_url, admin_token, fact_root);

  g_autofree gchar *graphs_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "GET", base_url, "/graphs", graphs_query,
          NULL, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"graph_auth_required\"") == NULL)
    return 20;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/graphs", graphs_query,
          deny_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"graph_denied\"") == NULL)
    return 21;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *create_query = g_strdup_printf ("tenant=%s&graph=orders&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  static const gchar *const graph_create_aliases[] = {
    "/graphs/create/x",
    "/graphs/createx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (graph_create_aliases); i++) {
    rc = send_raw (session, "POST", base_url, graph_create_aliases[i],
            create_query, admin_token, NULL, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !graph_state_matches (store, WYL_TENANT_DEFAULT, "orders", FALSE,
        FALSE))
      return 520 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  rc = send_raw (session, "POST", base_url, "/graphs/create", create_query,
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL ||
      strstr (body, "storage_path") != NULL || strstr (body, "facts.duckdb")
      != NULL) {
    g_printerr ("quota-enabled graph create mismatch rc=%d status=%u body=%s\n",
        rc, status, body != NULL ? body : "(null)");
    return 22;
  }

  /* The admission check and durable graph row share one SQLite write
   * transaction. At the boundary, refusal is typed and no graph/artifact is
   * left behind. */
  WylPolicyGraphQuotaStatus admission_status = { 0 };
  if (wyl_policy_store_get_graph_quota_status (store, WYL_TENANT_DEFAULT,
      &admission_status) != WYRELOG_E_OK || !admission_status.has_limit)
    return 220;
  guint64 graph_count = admission_status.committed + admission_status.pending;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *boundary_limit_query = g_strdup_printf (
    "tenant=%s&limit=%" G_GUINT64_FORMAT "&%s", WYL_TENANT_DEFAULT,
    graph_count, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          boundary_limit_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 2201;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *overlimit_query = g_strdup_printf (
    "tenant=%s&graph=overlimit&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_autofree gchar *boundary_limit_json = g_strdup_printf
        ("\"limit\":%" G_GUINT64_FORMAT, graph_count);
  g_autofree gchar *boundary_observed_json = g_strdup_printf
        ("\"observed\":%" G_GUINT64_FORMAT, graph_count);
  rc = send_raw (session, "POST", base_url, "/graphs/create", overlimit_query,
          admin_token, NULL, &status, &body);
  if (rc != 0 || status != 429 ||
      strstr (body, "\"error\":\"fact_quota_exceeded\"") == NULL ||
      strstr (body, "\"dimension\":\"graph_count\"") == NULL ||
      strstr (body, boundary_limit_json) == NULL ||
      strstr (body, boundary_observed_json) == NULL ||
      !graph_state_matches (store, WYL_TENANT_DEFAULT, "overlimit", FALSE,
      FALSE)) {
    g_printerr ("quota admission mismatch rc=%d status=%u count=%" G_GUINT64_FORMAT
        " committed=%" G_GUINT64_FORMAT " pending=%" G_GUINT64_FORMAT
        " body=%s graph_exists=%u\n", rc, status, graph_count,
        admission_status.committed, admission_status.pending,
        body != NULL ? body : "(null)",
        (guint) !graph_state_matches (store, WYL_TENANT_DEFAULT, "overlimit",
        FALSE, FALSE));
    return 2202;
  }
  if (wyl_client_graph_create (admin_client, WYL_TENANT_DEFAULT,
      "client-overlimit", 0, "trusted", 0) != WYRELOG_E_BUSY
      || wyl_client_get_last_http_status (admin_client) != 429)
    return 22021;
  g_autofree gchar *quota_client_error =
      wyl_client_dup_last_error_code (admin_client);
  if (g_strcmp0 (quota_client_error, "fact_quota_exceeded") != 0
      || !graph_state_matches (store, WYL_TENANT_DEFAULT,
      "client-overlimit", FALSE, FALSE)) {
    g_printerr ("quota client mismatch status=%u code=%s exists=%u\n",
        wyl_client_get_last_http_status (admin_client),
        quota_client_error != NULL ? quota_client_error : "(null)",
        (guint) !graph_state_matches (store, WYL_TENANT_DEFAULT,
        "client-overlimit", FALSE, FALSE));
    return 22022;
  }
  g_clear_pointer (&body, g_free);
  g_autofree gchar *race_limit_query = g_strdup_printf (
    "tenant=%s&limit=%" G_GUINT64_FORMAT "&%s", WYL_TENANT_DEFAULT,
    graph_count + 1, FACT_GUARD);
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          race_limit_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 2204;

  QuotaCreateRace races[] = {
    {.base_url = base_url, .access_token = admin_token,
     .graph = "quota-race-a"},
    {.base_url = base_url, .access_token = admin_token,
     .graph = "quota-race-b"},
  };
  g_autofree gchar *race_limit_json = g_strdup_printf
        ("\"limit\":%" G_GUINT64_FORMAT, graph_count + 1);
  g_autofree gchar *race_observed_json = g_strdup_printf
        ("\"observed\":%" G_GUINT64_FORMAT, graph_count + 1);
  GThread *race_threads[G_N_ELEMENTS (races)];
  GMutex race_lock;
  GCond race_changed;
  g_mutex_init (&race_lock);
  g_cond_init (&race_changed);
  for (gsize i = 0; i < G_N_ELEMENTS (races); i++) {
    races[i].lock = &race_lock;
    races[i].changed = &race_changed;
    race_threads[i] = g_thread_new ("quota-create-race",
            quota_create_race_thread, &races[i]);
  }
  g_mutex_lock (&race_lock);
  while (races[0].ready + races[1].ready < G_N_ELEMENTS (races))
    g_cond_wait (&race_changed, &race_lock);
  races[0].start = TRUE;
  races[1].start = TRUE;
  g_cond_broadcast (&race_changed);
  g_mutex_unlock (&race_lock);
  for (gsize i = 0; i < G_N_ELEMENTS (races); i++)
    g_thread_join (race_threads[i]);
  guint admitted = 0;
  guint refused = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (races); i++) {
    if (races[i].rc == 0 && races[i].status == 200
        && races[i].body != NULL
        && strstr (races[i].body, "\"created\":true") != NULL)
      admitted++;
    else if (races[i].rc == 0 && races[i].status == 429
        && races[i].body != NULL
        && strstr (races[i].body, "\"fact_quota_exceeded\"") != NULL
        && strstr (races[i].body, race_limit_json) != NULL
        && strstr (races[i].body, race_observed_json) != NULL)
      refused++;
    g_free (races[i].body);
  }
  g_cond_clear (&race_changed);
  g_mutex_clear (&race_lock);
  if (admitted != 1 || refused != 1)
    return 2205;
  WylPolicyGraphQuotaStatus after_race = { 0 };
  if (wyl_policy_store_get_graph_quota_status (store, WYL_TENANT_DEFAULT,
      &after_race) != WYRELOG_E_OK || after_race.committed != graph_count + 1
      || after_race.pending != 0)
    return 2206;
  gboolean race_a_active = graph_state_matches (store, WYL_TENANT_DEFAULT,
          "quota-race-a", TRUE, TRUE);
  gboolean race_b_active = graph_state_matches (store, WYL_TENANT_DEFAULT,
          "quota-race-b", TRUE, TRUE);
  if (race_a_active == race_b_active)
    return 2207;

  /* A configured limit cannot be lowered below durable committed+pending
   * usage; the attempted change is typed and leaves the old limit intact. */
  g_autofree gchar *below_usage_query = g_strdup_printf (
    "tenant=%s&limit=%" G_GUINT64_FORMAT "&%s", WYL_TENANT_DEFAULT,
    graph_count, FACT_GUARD);
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          below_usage_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 409 ||
      strstr (quota_body, "\"fact_quota_limit_below_usage\"") == NULL)
    return 2208;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *preserved_limit_json = g_strdup_printf
        ("\"limit\":%" G_GUINT64_FORMAT, graph_count + 1);
  quota_rc = send_raw (session, "GET", base_url, "/facts/quota",
          quota_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200 ||
      strstr (quota_body, preserved_limit_json) == NULL)
    return 2210;

  const gchar *admitted_race_graph = race_a_active
      ? "quota-race-a" : "quota-race-b";
  g_clear_pointer (&body, g_free);
  g_autofree gchar *race_schema_query = g_strdup_printf (
    "tenant=%s&graph=%s&namespace=shop&relation=probe&schema_version=1&%s",
    WYL_TENANT_DEFAULT, admitted_race_graph, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          race_schema_query, admin_token,
          "column_name\tcolumn_type\tnullable\tvisible\n"
          "value\tstring\tfalse\ttrue\n", &status, &body);
  if (rc != 0 || status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 2211;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *race_append_query = g_strdup_printf (
    "tenant=%s&namespace=shop&schema_version=1&batch_id=quota-race&"
    "idempotency_key=quota-race&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_autofree gchar *race_append_path = g_strdup_printf (
    "/facts/%s/%s/probe:append", WYL_TENANT_DEFAULT, admitted_race_graph);
  rc = send_raw (session, "POST", base_url, race_append_path,
          race_append_query, admin_token, "value\nquota-race\n", &status,
          &body);
  if (rc != 0 || status != 200)
    return 2209;

  g_autofree gchar *restore_quota_query = g_strdup_printf (
    "tenant=%s&limit=1000&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_clear_pointer (&quota_body, g_free);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          restore_quota_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 2203;

  if (sqlite3_exec (wyl_policy_store_get_db (wyl_handle_get_policy_store
        (handle)),
      "UPDATE fact_graphs SET storage_path='/outside/redirect' "
      "WHERE tenant_id='__wr_default' AND graph_id='orders';",
      NULL, NULL, NULL) != SQLITE_OK)
    return 221;

  static const gchar *const graph_list_aliases[] = {
    "/graphs/x",
    "/graphsx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (graph_list_aliases); i++) {
    g_clear_pointer (&body, g_free);
    rc = send_raw (session, "GET", base_url, graph_list_aliases[i],
            graphs_query, admin_token, NULL, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !graph_state_matches (store, WYL_TENANT_DEFAULT, "orders", TRUE,
        TRUE))
      return 522 + (gint) i;
  }
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/graphs", graphs_query,
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"graph_id\":\"orders\"") == NULL
      || strstr (body, "storage_path") != NULL || strstr (body,
      "facts.duckdb") != NULL)
    return 23;

  const gchar *schema_body =
      "column_name\tcolumn_type\tnullable\tvisible\n"
      "order_id\tsymbol\ttrue\ttrue\n" "amount\tint64\ttrue\ttrue\n";
  g_clear_pointer (&body, g_free);
  g_autofree gchar *schema_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  static const gchar *const schema_aliases[] = {
    "/facts/schema/register/x",
    "/facts/schema/registerx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (schema_aliases); i++) {
    rc = send_raw (session, "POST", base_url, schema_aliases[i], schema_query,
            admin_token, schema_body, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
      return 222 + (gint) i;
    gboolean visible = FALSE;
    wyl_policy_fact_relation_schema_column_info_t *columns = NULL;
    gsize n_columns = 0;
    if (wyl_policy_store_load_fact_relation_schema_columns
          (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
        "shop", "orders", 1, &visible, &columns, &n_columns)
        != WYRELOG_E_NOT_FOUND) {
      wyl_policy_fact_relation_schema_columns_free (columns, n_columns);
      return 224 + (gint) i;
    }
    g_clear_pointer (&body, g_free);
  }
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 24;

  /* The relation accepts a first schema version of any positive value. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *first_v2_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=first_v2&"
          "schema_version=2&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          first_v2_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 240;

  /* A later version is rejected even before any facts have been appended. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *empty_schema_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=empty&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          empty_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 241;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *empty_evolution_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=empty&"
          "schema_version=2&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          empty_evolution_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"schema_already_registered\"") == NULL)
    return 242;
  gboolean schema_exists = FALSE;
  if (wyl_policy_store_fact_relation_schema_exists
        (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
      "shop", "empty", 2, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 243;

  /* Even an exact repeat is a typed conflict once the relation is registered.
   * Stage a hidden v2 internally to prove the public rule does not mistake an
   * activation-owned row for permission to register it again. */
  const wyl_policy_fact_relation_schema_column_t staged_columns[] = {
    {"order_id", "symbol", TRUE, TRUE},
    {"amount", "int64", TRUE, TRUE},
  };
  const wyl_policy_fact_relation_schema_options_t staged_schema = {
    .tenant_id = WYL_TENANT_DEFAULT,
    .graph_id = "orders",
    .namespace_id = "shop",
    .relation_name = "orders",
    .schema_version = 2,
    .relation_visible = FALSE,
    .columns = staged_columns,
    .n_columns = G_N_ELEMENTS (staged_columns),
  };
  if (wyl_policy_store_register_fact_relation_schema
        (wyl_handle_get_policy_store (handle), &staged_schema) != WYRELOG_E_OK)
    return 244;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *staged_version_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=orders&"
          "schema_version=2&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          staged_version_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"schema_already_registered\"") == NULL)
    return 245;
  if (wyl_policy_store_fact_relation_schema_exists
        (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
      "shop", "orders", 2, &schema_exists) != WYRELOG_E_OK
      || !schema_exists)
    return 246;

  /* Exact repeats are also rejected before reaching the store duplicate path. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"schema_already_registered\"") == NULL)
    return 247;

  /* The query allowlist has a graph-wide query-name key. A collision from a
   * distinct relation is a client conflict, not an internal-server error. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *query_name_collision = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=other&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          query_name_collision, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409
      || strstr (body, "\"schema_registration_conflict\"") == NULL)
    return 248;
  schema_exists = TRUE;
  if (wyl_policy_store_fact_relation_schema_exists
        (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
      "other", "orders", 1, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 249;
  sqlite3_stmt *rollback_stmt = NULL;
  sqlite3 *policy_db = wyl_policy_store_get_db
        (wyl_handle_get_policy_store (handle));
  const gchar *rollback_sql =
      "SELECT "
      " (SELECT count(*) FROM fact_namespaces WHERE tenant_id='__wr_default'"
      "  AND graph_id='orders' AND namespace_id='other') +"
      " (SELECT count(*) FROM fact_relation_schemas WHERE tenant_id='__wr_default'"
      "  AND graph_id='orders' AND namespace_id='other'"
      "  AND relation_name='orders' AND schema_version=1) +"
      " (SELECT count(*) FROM fact_relation_schema_columns WHERE tenant_id='__wr_default'"
      "  AND graph_id='orders' AND namespace_id='other'"
      "  AND relation_name='orders' AND schema_version=1) +"
      " (SELECT count(*) FROM fact_relation_query_allowlist WHERE tenant_id='__wr_default'"
      "  AND graph_id='orders' AND namespace_id='other'"
      "  AND relation_name='orders' AND schema_version=1),"
      " (SELECT count(*) FROM fact_relation_query_allowlist WHERE tenant_id='__wr_default'"
      "  AND graph_id='orders' AND namespace_id='shop' AND relation_name='orders'"
      "  AND schema_version=1 AND query_name='orders');";
  if (sqlite3_prepare_v2 (policy_db, rollback_sql, -1, &rollback_stmt, NULL)
      != SQLITE_OK)
    return 250;
  gint rollback_step = sqlite3_step (rollback_stmt);
  gboolean rollback_is_clean = rollback_step == SQLITE_ROW
      && sqlite3_column_int64 (rollback_stmt, 0) == 0
      && sqlite3_column_int64 (rollback_stmt, 1) == 1;
  sqlite3_finalize (rollback_stmt);
  if (!rollback_is_clean)
    return 251;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bad_schema_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=bad&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          bad_schema_query, admin_token, "column_name\tcolumn_type\nonly_name\n",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_schema_payload\"") == NULL)
    return 25;
  gboolean bad_visible = FALSE;
  wyl_policy_fact_relation_schema_column_info_t *bad_cols = NULL;
  gsize n_bad_cols = 0;
  if (wyl_policy_store_load_fact_relation_schema_columns
        (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
      "shop", "bad", 1, &bad_visible, &bad_cols, &n_bad_cols)
      != WYRELOG_E_NOT_FOUND)
    return 26;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bad_max_rows_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=bad_rows&"
          "schema_version=1&max_rows=0&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          bad_max_rows_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_schema_request\"") == NULL)
    return 260;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *too_many_max_rows_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=too_many_rows&"
          "schema_version=1&max_rows=1000001&%s", WYL_TENANT_DEFAULT,
          FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          too_many_max_rows_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_schema_request\"") == NULL)
    return 261;

  const gchar *fact_body = "order_id\tamount\no-1\t42\n";
  g_clear_pointer (&body, g_free);
  g_autofree gchar *append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-1&"
          "idempotency_key=key-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", append_query, admin_token,
          fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL) {
    g_printerr ("first fact append mismatch: status=%u body=%s\n", status,
        body != NULL ? body : "(null)");
    return 27;
  }
  rc = check_fact_projection_batch_rows (fact_root, "orders", "batch-1", 1);
  if (rc != 0)
    return rc;
  WylPolicyGraphMaterializationState materialization_state;
  if (wyl_policy_store_read_fact_graph_materialization (
        wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
        &materialization_state) != WYRELOG_E_OK
      || materialization_state
      != WYL_POLICY_GRAPH_MATERIALIZATION_MATERIALIZED)
    return 276;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *logical_tight_query = g_strdup_printf
        ("tenant=%s&dimension=logical_bytes&row_limit=1&limit=12&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/quota",
          logical_tight_query, admin_token, NULL, &status, &body);
  if (rc != 0 || status != 200)
    return 277;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *logical_over_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=logical-over&"
          "idempotency_key=logical-over&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", logical_over_query,
          admin_token, "order_id\tamount\no-2\t84\n", &status, &body);
  if (rc != 0 || status != 429
      || strstr (body, "\"dimension\":\"logical_bytes\"") == NULL)
    return 278;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *logical_restore_query = g_strdup_printf
        ("tenant=%s&dimension=logical_bytes&row_limit=10000&limit=100000&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/quota",
          logical_restore_query, admin_token, NULL, &status, &body);
  if (rc != 0 || status != 200)
    return 279;

  /* The same conflict remains typed after the relation contains facts. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *evolution_with_facts_query = g_strdup_printf
        ("tenant=%s&graph=orders&namespace=shop&relation=orders&"
          "schema_version=3&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          evolution_with_facts_query, admin_token, schema_body, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"schema_already_registered\"") == NULL)
    return 28;
  schema_exists = TRUE;
  if (wyl_policy_store_fact_relation_schema_exists
        (wyl_handle_get_policy_store (handle), WYL_TENANT_DEFAULT, "orders",
      "shop", "orders", 3, &schema_exists) != WYRELOG_E_OK
      || schema_exists)
    return 29;

  /* Nullable schema metadata is accepted, but NULL values cannot be encoded
   * in the logical tuple store. Refuse before creating a durable batch. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *null_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=null-one&"
          "idempotency_key=null-one-key&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", null_append_query,
          admin_token, "order_id\tamount\nnull-one\tNULL\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_fact_payload\"") == NULL)
    return 271;
  if (check_fact_projection_batch_rows (fact_root, "orders", "null-one", 0)
      != 0)
    return 272;

  if (wyl_handle_replay_fact_graphs (handle, NULL) != WYRELOG_E_OK)
    return 273;
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/facts/status", NULL, NULL,
          NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"status\":\"ready\"") == NULL) {
    g_printerr ("fact status after quota create race mismatch status=%u body=%s\n",
        status, body != NULL ? body : "(null)");
    return 274;
  }

  WylPolicyFactSchemaQuotaStatus schema_quota_status = { 0 };
  if (wyl_policy_store_get_fact_schema_quota_status (store,
      WYL_TENANT_DEFAULT, &schema_quota_status) != WYRELOG_E_OK)
    return 206;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *schema_quota_full_query = g_strdup_printf (
    "tenant=%s&dimension=schema_count&limit=%" G_GUINT64_FORMAT "&%s",
    WYL_TENANT_DEFAULT, schema_quota_status.registered, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          schema_quota_full_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 207;
  g_clear_pointer (&quota_body, g_free);
  /* Refusal happens before any durable row is written, so the exhausted quota
   * is exercised on the graph that already carries facts.  A graph created
   * only to be refused would never materialize, and would leave the tenant
   * status degraded for the readiness assertion above. */
  g_autofree gchar *schema_quota_register_query = g_strdup_printf (
    "tenant=%s&graph=orders&namespace=shop&"
    "relation=quota_full&schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          schema_quota_register_query, admin_token,
          "value\tstring\tfalse\ttrue\n", &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 429
      || strstr (quota_body, "\"error\":\"fact_quota_exceeded\"") == NULL
      || strstr (quota_body, "\"dimension\":\"schema_count\"") == NULL
      || strstr (quota_body, "\"observed\":\"") != NULL)
    return 208;
  gboolean schema_429_exists = FALSE;
  if (wyl_policy_store_fact_relation_schema_exists (store, WYL_TENANT_DEFAULT,
      "orders", "shop", "quota_full", 1, &schema_429_exists)
      != WYRELOG_E_OK || schema_429_exists)
    return 209;
  g_clear_pointer (&quota_body, g_free);
  g_autofree gchar *schema_quota_restore_query = g_strdup_printf (
    "tenant=%s&dimension=schema_count&limit=1000&%s",
    WYL_TENANT_DEFAULT, FACT_GUARD);
  quota_rc = send_raw (session, "POST", base_url, "/facts/quota",
          schema_quota_restore_query, admin_token, NULL, &quota_status, &quota_body);
  if (quota_rc != 0 || quota_status != 200)
    return 210;
  g_clear_pointer (&quota_body, g_free);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *null_verify_query = g_strdup_printf
        ("tenant=%s&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", null_verify_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":1") == NULL
      || strstr (body, "{\"O\":\"o-1\",\"A\":42}") == NULL)
    return 275;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", append_query, admin_token,
          fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":false") == NULL)
    return 28;
  rc = check_fact_projection_batch_rows (fact_root, "orders", "batch-1", 1);
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *datalog_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, NULL,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"datalog_auth_required\"") == NULL)
    return 330;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, deny_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"datalog_denied\"") == NULL)
    return 331;

  const gchar *invalid_datalog_bodies[] = {
    "{\"query\":\"orders(O,A) :- orders(O,A)\",\"output\":\"json\"}",
    "{\"query\":\".decl orders(O:symbol,A:int64)\",\"output\":\"json\"}",
    "{\"query\":\"orders(O,A);orders(O,A)\",\"output\":\"json\"}",
    "{\"query\":\"SELECT * FROM orders\",\"output\":\"json\"}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_datalog_bodies); i++) {
    g_clear_pointer (&body, g_free);
    rc = send_raw (session, "POST", base_url,
            "/datalog/__wr_default/orders/query", datalog_query, admin_token,
            invalid_datalog_bodies[i], &status, &body);
    if (rc != 0)
      return rc;
    if (status != 400 || strstr (body, "\"invalid_datalog_request\"") == NULL)
      return 340 + (gint) i;
  }

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  gboolean status_ok = status == 200;
  gboolean relation_ok = body != NULL
      && strstr (body, "\"relation\":\"orders\"") != NULL;
  gboolean columns_ok = body != NULL
      && strstr (body, "\"columns\":[\"O\",\"A\"]") != NULL;
  gboolean row_ok = body != NULL
      && strstr (body, "{\"O\":\"o-1\",\"A\":42}") != NULL;
  gboolean path_absent = body == NULL || strstr (body, "facts.duckdb") == NULL;
  if (!status_ok || !relation_ok || !columns_ok || !row_ok || !path_absent) {
    g_autofree gchar *error_code = dup_safe_api_error_code (body);
    g_printerr ("first authorized datalog query mismatch: status=%u "
        "status-ok=%u relation-ok=%u columns-ok=%u row-ok=%u "
        "path-absent=%u error=%s\n", status, (guint) status_ok,
        (guint) relation_ok, (guint) columns_ok, (guint) row_ok,
        (guint) path_absent, error_code != NULL ? error_code : "(none)");
    return 332;
  }

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, admin_token,
          "{\"query\":\"payments(P)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"datalog_relation_denied\"") == NULL)
    return 333;

  if (wyl_handle_replay_fact_graphs (handle, NULL) != WYRELOG_E_OK)
    return 334;
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, admin_token,
          "{\"query\":\"orders(\\\"o-1\\\",A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "{\"A\":42}") == NULL ||
      strstr (body, "\"row_count\":1") == NULL)
    return 335;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *append_query_2 = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-7&"
          "idempotency_key=key-7&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", append_query_2,
          admin_token, "order_id\tamount\no-2\t84\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 336;
  rc = check_fact_projection_batch_rows (fact_root, "orders", "batch-7", 1);
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":1}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":1") == NULL ||
      strstr (body, "\"truncated\":true") == NULL)
    return 337;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *create_bulk_query = g_strdup_printf
        ("tenant=%s&graph=bulk&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          create_bulk_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 350;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bulk_schema_query = g_strdup_printf
        ("tenant=%s&graph=bulk&namespace=shop&relation=orders&"
          "schema_version=1&max_rows=1100&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          bulk_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 351;

  g_autoptr (GString) bulk_rows = g_string_new ("order_id\tamount\n");
  for (guint i = 0; i < 1105; i++)
    g_string_append_printf (bulk_rows, "bulk-%u\t%u\n", i, i);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *bulk_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=bulk-1&"
          "idempotency_key=bulk-key-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/bulk/orders:append", bulk_append_query,
          admin_token, bulk_rows->str, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 352;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bulk_datalog_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/bulk/query", bulk_datalog_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":1005}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":1005") == NULL ||
      strstr (body, "\"truncated\":true") == NULL)
    return 353;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/bulk/query", bulk_datalog_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":1100") == NULL ||
      strstr (body, "\"truncated\":true") == NULL)
    return 354;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *create_null_bulk_query = g_strdup_printf
        ("tenant=%s&graph=null-bulk&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          create_null_bulk_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 355;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *null_bulk_schema_query = g_strdup_printf
        ("tenant=%s&graph=null-bulk&namespace=shop&relation=orders&"
          "schema_version=1&max_rows=2500&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          null_bulk_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 356;
  g_autoptr (GString) null_bulk_rows = g_string_new ("order_id\tamount\n");
  for (guint i = 0; i < 2000; i++)
    g_string_append (null_bulk_rows, "\t\n");
  g_clear_pointer (&body, g_free);
  g_autofree gchar *null_bulk_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=null-bulk-1&"
          "idempotency_key=null-bulk-key-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/null-bulk/orders:append", null_bulk_append_query,
          admin_token, null_bulk_rows->str, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_fact_payload\"") == NULL)
    return 357;
  if (check_fact_batch_absent (fact_root, "null-bulk", "null-bulk-1") != 0)
    return 358;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *create_unary_query = g_strdup_printf
        ("tenant=%s&graph=unary&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          create_unary_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 360;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *unary_missing_schema_query = g_strdup_printf
        ("tenant=%s&namespace=examples&schema_version=1&batch_id=fact-raw-1&"
          "idempotency_key=fact-raw-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/unary/fact:retract", unary_missing_schema_query,
          admin_token, "value\n1\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 404 || strstr (body, "\"fact_schema_not_found\"") == NULL)
    return 361;

  const gchar *unary_schema_body =
      "column_name\tcolumn_type\tnullable\tvisible\n"
      "value\tint64\tfalse\ttrue\n";
  g_clear_pointer (&body, g_free);
  g_autofree gchar *unary_schema_query = g_strdup_printf
        ("tenant=%s&graph=unary&namespace=examples&relation=fact&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          unary_schema_query, admin_token, unary_schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 362;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *unary_append_query = g_strdup_printf
        ("tenant=%s&namespace=examples&schema_version=1&batch_id=fact-1&"
          "idempotency_key=fact-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/unary/fact:append", unary_append_query,
          admin_token, "value\n1\n2\n3\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 363;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *unary_datalog_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/unary/query", unary_datalog_query, admin_token,
          "{\"query\":\"fact(V)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"relation\":\"fact\"") == NULL ||
      strstr (body, "\"columns\":[\"V\"]") == NULL ||
      strstr (body, "{\"V\":1}") == NULL ||
      strstr (body, "{\"V\":2}") == NULL ||
      strstr (body, "{\"V\":3}") == NULL ||
      strstr (body, "\"row_count\":3") == NULL)
    return 364;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *unary_retract_query = g_strdup_printf
        ("tenant=%s&namespace=examples&schema_version=1&batch_id=fact-r1&"
          "idempotency_key=fact-r1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/unary/fact:retract", unary_retract_query,
          admin_token, "value\n1\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 365;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/unary/query", unary_datalog_query, admin_token,
          "{\"query\":\"fact(V)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":2") == NULL ||
      strstr (body, "{\"V\":2}") == NULL ||
      strstr (body, "{\"V\":3}") == NULL || strstr (body, "{\"V\":1}") != NULL)
    return 366;

  /* Retract case 1: normal retract of o-2 -> 200 inserted=true. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *retract_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-r1&"
          "idempotency_key=key-r1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", retract_query,
          admin_token, "order_id\tamount\no-2\t84\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL ||
      strstr (body, "\"batch_id\":\"batch-r1\"") == NULL)
    return 400;
  if (wyl_handle_replay_fact_graphs (handle, NULL) != WYRELOG_E_OK)
    return 401;
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/datalog/__wr_default/orders/query", datalog_query, admin_token,
          "{\"query\":\"orders(O,A)\",\"output\":\"json\",\"limit\":10}",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"row_count\":1") == NULL ||
      strstr (body, "{\"O\":\"o-1\",\"A\":42}") == NULL ||
      strstr (body, "\"o-2\"") != NULL)
    return 402;

  /* Retract case 2: idempotent replay -> 200 inserted=false. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", retract_query,
          admin_token, "order_id\tamount\no-2\t84\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":false") == NULL)
    return 403;

  /* Retract case 3: content_hash mismatch (same batch_id, different rows). */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", retract_query,
          admin_token, "order_id\tamount\no-3\t99\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"fact_batch_conflict\"") == NULL)
    return 404;

  /* Retract case 4: op/path mismatch (path :retract + query op=assert). */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *mismatch_op_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-r4&"
          "idempotency_key=key-r4&op=assert&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", mismatch_op_query,
          admin_token, "order_id\tamount\no-1\t42\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_fact_request\"") == NULL)
    return 405;

  /* Retract case 5: no permission -> 403 fact_denied. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *retract_deny_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-r5&"
          "idempotency_key=key-r5&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", retract_deny_query,
          deny_token, "order_id\tamount\no-1\t42\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"fact_denied\"") == NULL)
    return 406;

  /* Retract case 7: missing schema -> 404 fact_schema_not_found.
   * (Case 6 sealed-graph retract is tested after seal_query below.) */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *retract_missing_schema_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=99&batch_id=batch-r7&"
          "idempotency_key=key-r7&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract",
          retract_missing_schema_query, admin_token,
          "order_id\tamount\no-1\t42\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 404 || strstr (body, "\"fact_schema_not_found\"") == NULL)
    return 407;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bad_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-2&"
          "idempotency_key=key-2&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", bad_append_query,
          admin_token, "order_id\tamount\no-2\tnot-int\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_fact_payload\"") == NULL)
    return 29;
  for (const gchar *const *batch = (const gchar *const[]) {
    "batch-1", "batch-7", "batch-r1", NULL
  }; *batch != NULL; batch++) {
    rc = check_fact_projection_batch_rows (fact_root, "orders", *batch, 1);
    if (rc != 0)
      return rc;
  }
  g_clear_pointer (&body, g_free);
  g_autofree gchar *bad_path_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-3&"
          "idempotency_key=key-3&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/wr.bad:append", bad_path_query,
          admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_fact_request\"") == NULL)
    return 306;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *malformed_tenant_query = g_strdup_printf
        ("tenant=bad%%20tenant&namespace=shop&schema_version=1&"
          "batch_id=batch-4&idempotency_key=key-4&%s", FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", malformed_tenant_query,
          admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 307;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *mismatch_query = g_strdup_printf
        ("tenant=tenant-b&namespace=shop&schema_version=1&batch_id=batch-5&"
          "idempotency_key=key-5&%s", FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", mismatch_query,
          admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"tenant_denied\"") == NULL)
    return 30;

#ifndef WYL_HAS_SECURE_DUCKDB_BRIDGE
  /* A malformed tenant-only legacy identity with durable batches is an
   * internal store invariant failure (500), not a complete identity conflict
   * (409).  The failed request must not repair graph_id. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *partial_create_query = g_strdup_printf
        ("tenant=%s&graph=partial-identity&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          partial_create_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 4120;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *partial_schema_query = g_strdup_printf
        ("tenant=%s&graph=partial-identity&namespace=shop&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          partial_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 4121;
  rc = seed_legacy_fact_metadata (fact_root, "partial-identity",
          "INSERT INTO fact_store_metadata VALUES "
          "('tenant_id','__wr_default');"
          "INSERT INTO fact_batches VALUES ('existing','__wr_default',"
          "'partial-identity','shop','orders',1,NULL,NULL,'existing:1',"
          "'assert',0,0,'hash',1);");
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *partial_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=partial-1&"
          "idempotency_key=partial:1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/partial-identity/orders:append",
          partial_append_query, admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 500 || strstr (body, "\"fact_append_failed\"") == NULL)
    return 4122;
  rc = check_legacy_metadata_key_count (fact_root, "partial-identity",
          "graph_id", 0);
  if (rc != 0)
    return rc;

  /* A complete but foreign legacy tuple remains a normal policy mismatch and
   * therefore keeps the established 409 fact_batch_conflict response. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *foreign_create_query = g_strdup_printf
        ("tenant=%s&graph=identity-mismatch&%s", WYL_TENANT_DEFAULT,
          FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          foreign_create_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 4123;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *foreign_schema_query = g_strdup_printf
        ("tenant=%s&graph=identity-mismatch&namespace=shop&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          foreign_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 4124;
  rc = seed_legacy_fact_metadata (fact_root, "identity-mismatch",
          "INSERT INTO fact_store_metadata VALUES "
          "('tenant_id','__wr_default'),('graph_id','other');");
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *foreign_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=foreign-1&"
          "idempotency_key=foreign:1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/identity-mismatch/orders:append",
          foreign_append_query, admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"fact_batch_conflict\"") == NULL)
    return 4125;
#endif
#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE) && !defined(G_OS_WIN32)
  check_provisioned_http_identity (handle, session, fact_root, base_url,
      admin_token, schema_body);
#endif
  /* Issue #546: a post-commit audit failure must not be reported as a failed
   * append.  The audit result used to overwrite the commit result and then
   * drive the 409/400/500 mapping, so a durably committed batch could be
   * answered with 409 fact_batch_conflict, 400 invalid_fact_payload, or 500
   * fact_append_failed -- all three claiming the mutation did not happen.
   *
   * Asserted as a DELTA rather than an absolute count: this runs after the
   * retract and forget cases above, so the running total is not a fixed
   * number and an absolute assertion here would be coupled to them. */
  g_clear_pointer (&body, g_free);
  gint64 rows_before_audit = 0;
  rc = read_fact_projection_row_count (fact_root, "orders",
          &rows_before_audit);
  if (rc != 0)
    return rc;

  const gchar *audit_fact_body = "order_id\tamount\no-audit\t77\n";
  g_autofree gchar *audit_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-audit-1&"
          "idempotency_key=key-audit-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  /* Readiness is clean before the fault: without this the assertion after it
   * would pass against a daemon that was already degraded for some other
   * reason, which is the vacuous version of this check. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/readyz", "format=json",
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || (body != NULL && strstr (body, "audit_degraded")
      != NULL)) {
    g_printerr ("readiness was not clean before the audit fault: status=%u "
        "body=%s\n", status, body != NULL ? body : "(null)");
    return 340;
  }

  g_clear_pointer (&body, g_free);
  wyl_daemon_http_fail_next_fact_op_audit_for_test (server);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", audit_query, admin_token,
          audit_fact_body, &status, &body);
  if (rc != 0)
    return rc;
  /* Still an error -- a product that cannot record what it did must not
   * answer 200 -- but it must admit the batch is durable. */
  if (status != 500 || strstr (body, "\"fact_audit_failed\"") == NULL) {
    g_printerr ("audit-failure status/code mismatch: status=%u body=%s\n",
        status, body != NULL ? body : "(null)");
    return 290;
  }
  if (strstr (body, "\"committed\":true") == NULL) {
    g_printerr ("audit failure denied the commit: body=%s\n",
        body != NULL ? body : "(null)");
    return 291;
  }
  /* A successful refresh whose audit failed leaves the engine READY, so the
   * class must not be downgraded to committed_degraded. */
  if (strstr (body, "\"mutation_class\":\"committed_ready\"") == NULL) {
    g_printerr ("audit failure mislabelled the mutation class: body=%s\n",
        body != NULL ? body : "(null)");
    return 293;
  }
  /* It really did commit: the row landed despite the 500. */
  gint64 rows_after_audit = 0;
  rc = read_fact_projection_row_count (fact_root, "orders",
          &rows_after_audit);
  if (rc != 0)
    return rc;
  if (rows_after_audit != rows_before_audit + 1) {
    g_printerr ("audit-failed append did not commit: before=%" G_GINT64_FORMAT
        " after=%" G_GINT64_FORMAT "\n", rows_before_audit, rows_after_audit);
    return 294;
  }

#ifdef WYL_HAS_AUDIT
  /* The count only moves where the audit subsystem is compiled in.  Without
   * it mark_runtime_audit_degraded does not exist, so the injected emission
   * failure still answers 500 -- the seam runs ahead of the audit guard --
   * but nothing increments audit_errors and these assertions would be
   * asserting the absence of a subsystem rather than its behaviour. */
  /* The client was told the audit was lost.  The operator must be told too --
   * but not by the status, because a one-shot emission failure self-heals and
   * the very next probe finds a healthy store and clears the flag.  What
   * carries a one-shot loss is the count, which is monotonic and never
   * cleared.  Asserting a 503 here would be asserting that the daemon stays
   * withdrawn after losing a single record, which is not the contract and
   * would be a worse one. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/readyz", "format=json",
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (body == NULL || strstr (body, "\"audit_errors\":0") != NULL
      || strstr (body, "\"audit_errors\":") == NULL) {
    g_printerr ("a lost fact audit was not counted: status=%u body=%s\n",
        status, body != NULL ? body : "(null)");
    return 341;
  }

  /* And it converges.  With the fault disarmed and the store healthy, the
   * next readiness probe clears the flag -- but audit_errors stays non-zero,
   * because a repaired store does not un-lose the record.  This is the
   * degrade-repair-recover sequence end to end, on the one path where the
   * count is genuinely non-zero: the fixtures that set the flag by hand can
   * only ever report it as zero. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "GET", base_url, "/readyz", "format=json",
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || body == NULL
      || strstr (body, "\"status\":\"ready\"") == NULL) {
    g_printerr ("readiness did not converge after the audit store recovered: "
        "status=%u body=%s\n", status, body != NULL ? body : "(null)");
    return 342;
  }
  if (strstr (body, "\"audit_errors\":0") != NULL) {
    g_printerr ("recovery erased the record of the loss: body=%s\n", body);
    return 343;
  }
#endif

  /* Retrying the same idempotency key cannot double-apply, and with the fault
   * disarmed the retry records the audit and reports success. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", audit_query, admin_token,
          audit_fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":false") == NULL) {
    g_printerr ("audit-failure retry mismatch: status=%u body=%s\n", status,
        body != NULL ? body : "(null)");
    return 292;
  }
  gint64 rows_after_retry = 0;
  rc = read_fact_projection_row_count (fact_root, "orders",
          &rows_after_retry);
  if (rc != 0)
    return rc;
  if (rows_after_retry != rows_after_audit) {
    g_printerr ("idempotent retry double-applied: %" G_GINT64_FORMAT " -> %"
        G_GINT64_FORMAT "\n", rows_after_audit, rows_after_retry);
    return 295;
  }

  g_clear_pointer (&body, g_free);
  g_autofree gchar *seal_query = g_strdup_printf ("tenant=%s&graph=orders&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  static const gchar *const graph_seal_aliases[] = {
    "/graphs/seal/x",
    "/graphs/sealx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (graph_seal_aliases); i++) {
    rc = send_raw (session, "POST", base_url, graph_seal_aliases[i],
            seal_query, admin_token, NULL, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !graph_state_matches (store, WYL_TENANT_DEFAULT, "orders", TRUE,
        TRUE))
      return 524 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  /* Forget case 1: normal forget of batch-1 -> 200 rows_purged 1.  This runs
   * BEFORE the seal: a sealed graph refuses forget and there is no graph
   * unseal API to undo it.  Cases 3 and 2 follow the seal below. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *forget_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&%s", WYL_TENANT_DEFAULT,
          FACT_GUARD);
  g_autofree gchar *forget_request_id = NULL;
  rc = send_raw_with_request_id (session, "DELETE", base_url,
          "/facts/__wr_default/orders/orders:forget", forget_query, admin_token,
          "{\"batch_id\":\"batch-1\",\"operator\":\"spoofed-operator\","
          "\"reason\":\"gdpr-erasure\"}", &status, &body, &forget_request_id,
          NULL);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL ||
      strstr (body, "\"rows_purged\":1") == NULL)
    return 500;
  /* Pin the post-state: Forget case 3 asserts this exact count, so a silent
   * change here would make that assertion meaningless.  The count includes
   * the row the audit-failure case above committed: that append really did
   * commit, which is the whole point of answering it 500 fact_audit_failed
   * with "committed":true rather than fact_append_failed. */
  rc = check_fact_projection_row_count (fact_root, "orders", 3);
  if (rc != 0)
    return rc;

  check_forget_attribution (fact_root, wyl_handle_get_policy_store (handle),
      "batch-1", forget_request_id, TRUE);

  /* The lifecycle event is a separate commit.  Losing it cannot erase or
   * misattribute the durable completion record, nor claim a rolled-back delete. */
  g_autofree gchar *lost_audit_query = g_strdup_printf (
    "tenant=%s&namespace=shop&schema_version=1&batch_id=forget-audit-failed&"
    "idempotency_key=forget-audit-failed&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_clear_pointer (&body, g_free);
  g_assert_cmpint (send_raw (session, "POST", base_url,
      "/facts/__wr_default/orders/orders:append", lost_audit_query,
      admin_token, "order_id\tamount\naudit-delete\t17\n", &status, &body), ==, 0);
  g_assert_cmpuint (status, ==, 200);
  g_assert_nonnull (strstr (body, "\"inserted\":true"));
  g_assert_cmpint (check_fact_projection_row_count (fact_root, "orders", 4), ==, 0);
  wyl_daemon_http_fail_next_fact_op_audit_for_test (server);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *failed_forget_request_id = NULL;
  g_assert_cmpint (send_raw_with_request_id (session, "DELETE", base_url,
      "/facts/__wr_default/orders/orders:forget", forget_query, admin_token,
      "{\"batch_id\":\"forget-audit-failed\",\"operator\":\"spoofed-operator\","
      "\"reason\":\"audit-failure-test\"}", &status, &body,
      &failed_forget_request_id, NULL), ==, 0);
  g_assert_cmpuint (status, ==, 500);
  g_assert_nonnull (strstr (body, "\"fact_forget_audit_failed\""));
  g_assert_nonnull (strstr (body, "\"purged\":true"));
  g_assert_nonnull (strstr (body, "\"rows_purged\":1"));
  g_assert_cmpint (check_fact_projection_row_count (fact_root, "orders", 3), ==, 0);
  check_forget_attribution (fact_root, wyl_handle_get_policy_store (handle),
      "forget-audit-failed", failed_forget_request_id, FALSE);

#if defined(WYL_HAS_FACT_STORE) && defined(WYL_TEST_HANDLE_SEAMS)
  /* A seal that answers 404 must still release the outcome it was handed.
   * The abort path fills outcome.status, whose key owns two strings, so a
   * return that skips the clear leaks them -- caught by the sanitizer job
   * rather than by an assertion here.  The durable write never commits, so
   * the graph is left admitting and the successful seal below is unaffected.
   */
  g_clear_pointer (&body, g_free);
  wyl_fact_graph_seal_set_test_hook (seal_durable_write_not_found, NULL);
  rc = send_raw (session, "POST", base_url, "/graphs/seal", seal_query,
          admin_token, NULL, &status, &body);
  wyl_fact_graph_seal_set_test_hook (NULL, NULL);
  if (rc != 0)
    return rc;
  if (status != 404) {
    g_printerr ("faulted seal returned HTTP %u: %s\n", status, body);
    return 121;
  }
  WylFactGraphRuntimeStatus aborted_status = { 0 };
  if (wyl_handle_get_fact_graph_runtime_status (handle, WYL_TENANT_DEFAULT,
      "orders", &aborted_status) != WYRELOG_E_OK
      || aborted_status.admission != WYL_FACT_GRAPH_ADMISSION_OPEN) {
    wyl_fact_graph_runtime_status_clear (&aborted_status);
    g_printerr ("faulted seal left the graph closed\n");
    return 122;
  }
  wyl_fact_graph_runtime_status_clear (&aborted_status);
#endif

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url, "/graphs/seal", seal_query,
          admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"sealed\":true") == NULL)
    return 31;
  /* The HTTP route must drive the handle lifecycle, not only flip the
   * durable policy bit.  A direct policy-store write leaves the runtime
   * admission barrier open, which is the regression covered by #973 AC6. */
  WylFactGraphRuntimeStatus sealed_status = { 0 };
  if (wyl_handle_get_fact_graph_runtime_status (handle, WYL_TENANT_DEFAULT,
      "orders", &sealed_status) != WYRELOG_E_OK
      || sealed_status.admission != WYL_FACT_GRAPH_ADMISSION_CLOSED
      || sealed_status.queryable) {
    wyl_fact_graph_runtime_status_clear (&sealed_status);
    return 108;
  }
  wyl_fact_graph_runtime_status_clear (&sealed_status);
#ifdef WYL_HAS_AUDIT
  /* Sealing is irreversible and closes the graph to every mutation, and it
   * emitted nothing.  wyl_decide does audit the authorization, but its record
   * names the tenant as the resource -- byte-identical for every graph in that
   * tenant, and for a list call using the same permission -- so the existing
   * stream cannot say which graph was sealed, or whether the seal completed.
   * There is no batch here, so deny_reason is empty. */
  {
    LifecycleAuditProbe seal_audit = {
      .subject_id = "facts-admin",
      .action = "graph_seal",
      .resource_id = "__wr_default/orders",
      .deny_reason = "",
    };
    if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), lifecycle_audit_probe_cb, &seal_audit) != WYRELOG_E_OK)
      return 106;
    if (seal_audit.matches != 1) {
      g_printerr ("graph seal left no control-plane record (matches=%u)\n",
          seal_audit.matches);
      return 107;
    }
  }
#endif

  g_clear_pointer (&body, g_free);
  g_autofree gchar *sealed_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-6&"
          "idempotency_key=key-6&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:append", sealed_append_query,
          admin_token, fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"graph_sealed\"") == NULL)
    return 32;

  /* Retract case 6: sealed graph -> 409 graph_sealed. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *sealed_retract_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=batch-r6&"
          "idempotency_key=key-r6&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/orders/orders:retract", sealed_retract_query,
          admin_token, "order_id\tamount\no-1\t42\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"graph_sealed\"") == NULL)
    return 408;

  /* Forget case 3: sealed graph -> 409 graph_sealed.  Before the gate this
   * returned 200 and destroyed rows, while the append and retract cases just
   * above were already refused -- the three differed only in which verb
   * reached the store.
   *
   * Absolute counts, not a delta: a delta is only evaluated once the status
   * check has passed, so it could never fail in the case it exists to catch. */
  g_clear_pointer (&body, g_free);
  rc = check_fact_projection_row_count (fact_root, "orders", 3);
  if (rc != 0)
    return rc;
  rc = send_raw (session, "DELETE", base_url,
          "/facts/__wr_default/orders/orders:forget", forget_query, admin_token,
          "{\"batch_id\":\"batch-7\",\"operator\":\"admin\","
          "\"reason\":\"sealed-should-refuse\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || strstr (body, "\"graph_sealed\"") == NULL) {
    g_printerr ("sealed forget not refused: status=%u body=%s\n", status,
        body != NULL ? body : "(null)");
    return 409;
  }
#ifdef WYL_HAS_AUDIT
  /* A refused hard delete against a sealed graph is a security-relevant
   * occurrence and left no trace.  It is emitted, unlike the other refusals
   * on this route, because it is the only one reachable solely by a caller
   * who already authenticated and passed authorization -- the 400s and 405s
   * ahead of it are pre-auth, and emitting there would let an unauthenticated
   * client drive audit writes. */
  {
    LifecycleAuditProbe refused_audit = {
      .subject_id = "facts-admin",
      .action = "fact_forget",
      .resource_id = "__wr_default/orders",
      .deny_reason = "batch-7",
    };
    if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), lifecycle_audit_probe_cb, &refused_audit) != WYRELOG_E_OK)
      return 104;
    if (refused_audit.matches != 1) {
      g_printerr ("a refused sealed forget left no record (matches=%u)\n",
          refused_audit.matches);
      return 105;
    }
  }
#endif
  /* The refusal destroyed nothing.  Only 304 means the count moved; the
   * helper's other codes are fixture failures and must not be reported as a
   * gate regression. */
  rc = check_fact_projection_row_count (fact_root, "orders", 3);
  if (rc == 304) {
    g_printerr ("sealed forget mutated the orders projection\n");
    return 410;
  }
  if (rc != 0)
    return rc;

  /* Forget case 2: no permission -> 403 fact_denied. */
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "DELETE", base_url,
          "/facts/__wr_default/orders/orders:forget", forget_query, deny_token,
          "{\"batch_id\":\"batch-1\",\"operator\":\"deny\","
          "\"reason\":\"test\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"fact_denied\"") == NULL)
    return 501;

  /* Use a separate graph so the barrier assertion cannot alter the durable
   * row counts and sealed-refusal checks above. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *barrier_create_query = g_strdup_printf
        ("tenant=%s&graph=barrier&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          barrier_create_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"created\":true") == NULL)
    return 502;
  g_autofree gchar *barrier_schema_query = g_strdup_printf
        ("tenant=%s&graph=barrier&namespace=shop&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          barrier_schema_query, admin_token, schema_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 503;
  g_autofree gchar *barrier_append_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=barrier-1&"
          "idempotency_key=barrier-key-1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/barrier/orders:append", barrier_append_query,
          admin_token, "order_id\tamount\nbarrier-1\t43\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 504;

  rc = wyl_handle_set_fact_graph_admission_for_test
        (handle, WYL_TENANT_DEFAULT, "barrier", FALSE);
  if (rc != WYRELOG_E_OK)
    return 505;
  gboolean barrier_graph_active = FALSE;
  if (wyl_policy_store_fact_graph_is_active (store, WYL_TENANT_DEFAULT,
      "barrier", &barrier_graph_active) != WYRELOG_E_OK
      || !barrier_graph_active)
    return 506;
  WylFactGraphRuntimeStatus barrier_status = { 0 };
  rc = wyl_handle_get_fact_graph_runtime_status (handle, WYL_TENANT_DEFAULT,
          "barrier", &barrier_status);
  if (rc != WYRELOG_E_OK || barrier_status.admission
      != WYL_FACT_GRAPH_ADMISSION_CLOSED) {
    wyl_fact_graph_runtime_status_clear (&barrier_status);
    return 507;
  }
  wyl_fact_graph_runtime_status_clear (&barrier_status);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *barrier_mutation_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=barrier-2&"
          "idempotency_key=barrier-key-2&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/barrier/orders:append",
          barrier_mutation_query, admin_token,
          "order_id\tamount\nbarrier-2\t44\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200) {
    g_printerr ("barrier mutation returned HTTP %u: %s\n", status, body);
    return 508;
  }
  if (strstr (body, "\"mutation_class\":\"committed_barrier\"")
      == NULL) {
    g_printerr ("barrier mutation class was not committed_barrier: %s\n",
        body);
    return 509;
  }
  if (strstr (body, "\"reconcile\":true") == NULL) {
    g_printerr ("barrier mutation omitted reconcile=true: %s\n", body);
    return 510;
  }
  if (strstr (body, "\"degraded_class\"") != NULL) {
    g_printerr ("barrier mutation exposed degraded_class: %s\n", body);
    return 511;
  }

  rc = wyl_handle_set_fact_graph_admission_for_test
        (handle, WYL_TENANT_DEFAULT, "barrier", TRUE);
  if (rc != WYRELOG_E_OK)
    return 545;
  barrier_status = (WylFactGraphRuntimeStatus) { 0 };
  rc = wyl_handle_get_fact_graph_runtime_status (handle, WYL_TENANT_DEFAULT,
          "barrier", &barrier_status);
  if (rc != WYRELOG_E_OK || barrier_status.admission
      != WYL_FACT_GRAPH_ADMISSION_OPEN || !barrier_status.queryable) {
    wyl_fact_graph_runtime_status_clear (&barrier_status);
    return 513;
  }
  wyl_fact_graph_runtime_status_clear (&barrier_status);

  gint64 rows_before_degraded = 0;
  rc = read_fact_projection_row_count (fact_root, "barrier",
          &rows_before_degraded);
  if (rc != 0)
    return rc;
  wyl_fact_replay_set_test_fault (
    WYL_FACT_REPLAY_TEST_FAULT_OPEN_GRAPH_ENGINE);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *degraded_mutation_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=barrier-3&"
          "idempotency_key=barrier-key-3&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/barrier/orders:append",
          degraded_mutation_query, admin_token,
          "order_id\tamount\nbarrier-3\t45\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200) {
    g_printerr ("degraded mutation returned HTTP %u: %s\n", status, body);
    return 514;
  }
  if (strstr (body, "\"committed\":true") == NULL) {
    g_printerr ("degraded mutation omitted committed=true: %s\n", body);
    return 515;
  }
  if (strstr (body, "\"inserted\":true") == NULL) {
    g_printerr ("degraded mutation omitted inserted=true: %s\n", body);
    return 516;
  }
  if (strstr (body, "\"mutation_class\":\"committed_degraded\"")
      == NULL) {
    g_printerr ("degraded mutation class was not committed_degraded: %s\n",
        body);
    return 517;
  }
  if (strstr (body, "\"degraded_class\":\"store_unavailable\"")
      == NULL) {
    g_printerr ("degraded mutation class was not store_unavailable: %s\n",
        body);
    return 518;
  }
  if (strstr (body, "\"reconcile\":true") == NULL) {
    g_printerr ("degraded mutation omitted reconcile=true: %s\n", body);
    return 519;
  }
  if (strstr (body, "\"mutation_class\":\"committed_barrier\"")
      != NULL) {
    g_printerr ("degraded mutation was also classified as barrier: %s\n",
        body);
    return 520;
  }
  gint64 rows_after_degraded = 0;
  rc = read_fact_projection_row_count (fact_root, "barrier",
          &rows_after_degraded);
  if (rc != 0)
    return rc;
  if (rows_after_degraded != rows_before_degraded + 1)
    return 521;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *recovered_mutation_query = g_strdup_printf
        ("tenant=%s&namespace=shop&schema_version=1&batch_id=barrier-4&"
          "idempotency_key=barrier-key-4&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/barrier/orders:append",
          recovered_mutation_query, admin_token,
          "order_id\tamount\nbarrier-4\t46\n", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200) {
    g_printerr ("recovered mutation returned HTTP %u: %s\n", status, body);
    return 522;
  }
  if (strstr (body, "\"mutation_class\":\"committed_ready\"")
      == NULL) {
    g_printerr ("recovered mutation was not committed_ready: %s\n", body);
    return 523;
  }
  WylPolicyFactQuotaConfig write_rate_config = {
    .has_limit = TRUE,
    .rate_per_second = 1,
    .burst = 3,
  };
  if (wyl_policy_store_set_fact_quota_config (store, WYL_TENANT_DEFAULT,
      WYL_POLICY_FACT_QUOTA_WRITE_RATE, &write_rate_config) != WYRELOG_E_OK)
    return 524;
  if (sqlite3_exec (wyl_policy_store_get_db (store),
      "DELETE FROM fact_tenant_write_rate_state WHERE tenant_id='"
      "__wr_default';", NULL, NULL, NULL) != SQLITE_OK)
    return 5241;
  g_autofree gchar *rate_graph_query = g_strdup_printf
        ("tenant=%s&graph=rate&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/create",
          rate_graph_query, admin_token, NULL, &status, &body);
  if (rc != 0 || status != 200)
    return 525;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *rate_schema_query = g_strdup_printf
        ("tenant=%s&graph=rate&namespace=shop&relation=orders&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/facts/schema/register",
          rate_schema_query, admin_token,
          "column_name\tcolumn_type\tnullable\tvisible\n"
          "value\tstring\tfalse\ttrue\n", &status, &body);
  if (rc != 0 || status != 200)
    return 526;
  g_clear_pointer (&body, g_free);
  const gchar *rate_append_path = "/facts/__wr_default/rate/orders:append";
  const gchar *rate_bad_query = "tenant=__wr_default&namespace=shop&"
      "schema_version=1&batch_id=rate-bad&idempotency_key=rate-bad&"
      FACT_GUARD;
  rc = send_raw (session, "POST", base_url, rate_append_path,
          rate_bad_query, admin_token, "wrong\twidth\textra\n", &status, &body);
  if (rc != 0 || status != 400)
    return 527;
  g_clear_pointer (&body, g_free);
  gboolean rate_state_exists = FALSE;
  guint64 rate_tokens = 0;
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || rate_state_exists)
    return 5270;
  rc = send_raw (session, "POST", base_url, rate_append_path,
          rate_bad_query, NULL, "value\nunauthenticated\n", &status, &body);
  if (rc != 0 || status != 401)
    return 5271;
  g_clear_pointer (&body, g_free);
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || rate_state_exists)
    return 52711;
  const gchar *forged_tenant_query = "tenant=tenant-b&namespace=shop&"
      "schema_version=1&batch_id=rate-forged&idempotency_key=rate-forged&"
      FACT_GUARD;
  rc = send_raw (session, "POST", base_url, rate_append_path,
          forged_tenant_query, admin_token, "value\nforged\n", &status, &body);
  if (rc != 0 || status != 403)
    return 5272;
  g_clear_pointer (&body, g_free);
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || rate_state_exists)
    return 52721;
  const gchar *rate_good_query = "tenant=__wr_default&namespace=shop&"
      "schema_version=1&batch_id=rate-good&idempotency_key=rate-good&"
      FACT_GUARD;
  rc = send_raw (session, "POST", base_url, rate_append_path,
          rate_good_query, admin_token, "value\nrate-good\n", &status, &body);
  if (rc != 0 || status != 200)
    return 528;
  g_clear_pointer (&body, g_free);
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || !rate_state_exists || rate_tokens != 2)
    return 5280;
  /* Keep the request sequence deterministic under sanitizer builds: the
   * admission clock is real, so a slow preceding HTTP request must not refill
   * a token before the next debit assertion. */
  g_autofree gchar *reset_rate_clock = g_strdup_printf
        ("UPDATE fact_tenant_write_rate_state SET last_refill_at=%" G_GINT64_FORMAT
          ",refill_remainder=0"
          " WHERE tenant_id='__wr_default';", g_get_real_time ()
          + G_GINT64_CONSTANT (3600) * G_USEC_PER_SEC);
  if (sqlite3_exec (wyl_policy_store_get_db (store), reset_rate_clock,
      NULL, NULL, NULL) != SQLITE_OK)
    return 52801;
  const gchar *rate_retract_query = "tenant=__wr_default&namespace=shop&"
      "schema_version=1&batch_id=rate-retract&idempotency_key=rate-retract&"
      FACT_GUARD;
  rc = send_raw (session, "POST", base_url,
          "/facts/__wr_default/rate/orders:retract", rate_retract_query,
          admin_token, "value\nrate-good\n", &status, &body);
  if (rc != 0 || status != 200)
    return 5281;
  g_clear_pointer (&body, g_free);
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || !rate_state_exists || rate_tokens != 1)
    return 52811;
  g_clear_pointer (&reset_rate_clock, g_free);
  reset_rate_clock = g_strdup_printf
        ("UPDATE fact_tenant_write_rate_state SET last_refill_at=%" G_GINT64_FORMAT
          ",refill_remainder=0"
          " WHERE tenant_id='__wr_default';", g_get_real_time ()
          + G_GINT64_CONSTANT (3600) * G_USEC_PER_SEC);
  if (sqlite3_exec (wyl_policy_store_get_db (store), reset_rate_clock,
      NULL, NULL, NULL) != SQLITE_OK)
    return 52812;
  const gchar *rate_second_query = "tenant=__wr_default&namespace=shop&"
      "schema_version=1&batch_id=rate-second&idempotency_key=rate-second&"
      FACT_GUARD;
  rc = send_raw (session, "POST", base_url, rate_append_path,
          rate_second_query, admin_token, "value\nrate-second\n", &status, &body);
  if (rc != 0 || status != 200)
    return 5282;
  g_clear_pointer (&body, g_free);
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || !rate_state_exists || rate_tokens != 0)
    return 52821;
  gint64 freeze_anchor_us = g_get_real_time ()
      + G_GINT64_CONSTANT (3600) * G_USEC_PER_SEC;
  g_autofree gchar *freeze_rate_state = g_strdup_printf
        ("UPDATE fact_tenant_write_rate_state SET tokens=0,"
          "last_refill_at=%" G_GINT64_FORMAT
          " WHERE tenant_id='%s';", freeze_anchor_us,
          WYL_TENANT_DEFAULT);
  if (sqlite3_exec (wyl_policy_store_get_db (store), freeze_rate_state, NULL,
      NULL, NULL) != SQLITE_OK)
    return 5281;
  const gchar *rate_excess_query = "tenant=__wr_default&namespace=shop&"
      "schema_version=1&batch_id=rate-excess&idempotency_key=rate-excess&"
      FACT_GUARD;
  gint64 request_started_us = g_get_real_time ();
  g_autofree gchar *retry_after = NULL;
  rc = send_raw_with_request_id (session, "POST", base_url, rate_append_path,
          rate_excess_query, admin_token, "value\nrate-excess\n", &status, &body,
          NULL, &retry_after);
  gint64 request_finished_us = g_get_real_time ();
  guint64 retry_after_seconds = retry_after == NULL ? 0
        : g_ascii_strtoull (retry_after, NULL, 10);
  guint64 retry_min_us = freeze_anchor_us > request_finished_us
        ? (guint64) (freeze_anchor_us - request_finished_us)
      + G_USEC_PER_SEC : G_USEC_PER_SEC;
  guint64 retry_max_us = freeze_anchor_us > request_started_us
        ? (guint64) (freeze_anchor_us - request_started_us)
      + G_USEC_PER_SEC : G_USEC_PER_SEC;
  guint64 retry_min_seconds = (retry_min_us + G_USEC_PER_SEC - 1)
      / G_USEC_PER_SEC;
  guint64 retry_max_seconds = (retry_max_us + G_USEC_PER_SEC - 1)
      / G_USEC_PER_SEC;
  if (rc != 0 || status != 429
      || strstr (body, "\"error\":\"fact_quota_exceeded\"") == NULL
      || strstr (body, "\"dimension\":\"write_rate\"") == NULL
      || retry_after_seconds < retry_min_seconds
      || retry_after_seconds > retry_max_seconds) {
    g_printerr ("write-rate response rc=%d status=%u retry=%s body=%s\n", rc,
        status, retry_after != NULL ? retry_after : "(null)",
        body != NULL ? body : "(null)");
    return 529;
  }
  if (check_fact_batch_absent (fact_root, "rate", "rate-excess") != 0)
    return 5291;
  if (read_write_rate_tokens (wyl_policy_store_get_db (store),
      WYL_TENANT_DEFAULT, &rate_state_exists, &rate_tokens) != 0
      || !rate_state_exists || rate_tokens != 0)
    return 5292;

  g_clear_pointer (&body, g_free);
  return 0;
}

int
main (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *fact_root = wyl_test_make_secure_fact_root
        ("wyl-daemon-facts-XXXXXX", &error);
  if (fact_root == NULL)
    return wyl_test_normalize_exit_status (1);

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions open_opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .fact_root = fact_root,
  };
  if (wyl_handle_open_with_options (&open_opts, &handle) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (3);
  if (grant_fact_http_authority (handle, "facts-admin") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (4);

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .fact_root = fact_root,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (5);
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL) {
    g_printerr ("daemon HTTP server start failed: %s\n",
        error != NULL ? error->message : "no error detail");
    return wyl_test_normalize_exit_status (6);
  }
  GThread *thread = g_thread_new ("daemon-http-facts",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return wyl_test_normalize_exit_status (7);
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint rc = check_fact_http_contract (handle, http.server, fact_root,
          base_url);
  if (rc != 0)
    g_printerr ("fact HTTP contract failed rc=%d\n", rc);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_clear_object (&handle);
  remove_tree (fact_root);
  return wyl_test_normalize_exit_status (rc);
}
