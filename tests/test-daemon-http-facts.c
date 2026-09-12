/* SPDX-License-Identifier: GPL-3.0-or-later */
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
    gchar **out_request_id)
{
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
             access_token, request_body, out_status, out_body, NULL);
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
  identity_http_post (session, base_url, token, path, control_query,
      "order_id\tamount\nidentity-control\t17\n", 200, "\"inserted\":true");

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

  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *graphs_query = g_strdup_printf ("tenant=%s&%s",
          WYL_TENANT_DEFAULT, FACT_GUARD);
  gint rc = send_raw (session, "GET", base_url, "/graphs", graphs_query,
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
      != NULL)
    return 22;
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
  if (status != 200 || strstr (body, "\"status\":\"ready\"") == NULL)
    return 274;
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
  if (check_fact_projection_row_count (fact_root, "null-bulk", 0) != 0)
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
          "'assert',0,'hash',1);");
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
          "\"reason\":\"gdpr-erasure\"}", &status, &body, &forget_request_id);
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
      &failed_forget_request_id), ==, 0);
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
    return 512;
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

  return 0;
}

int
main (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *fact_root = wyl_test_make_secure_fact_root
        ("wyl-daemon-facts-XXXXXX", &error);
  if (fact_root == NULL)
    return 1;

  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions open_opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .fact_root = fact_root,
  };
  if (wyl_handle_open_with_options (&open_opts, &handle) != WYRELOG_E_OK)
    return 3;
  if (grant_fact_http_authority (handle, "facts-admin") != WYRELOG_E_OK)
    return 4;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .fact_root = fact_root,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 5;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL)
    return 6;
  GThread *thread = g_thread_new ("daemon-http-facts",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 7;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint rc = check_fact_http_contract (handle, http.server, fact_root,
          base_url);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_clear_object (&handle);
  remove_tree (fact_root);
  return rc;
}
