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
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-request-id-private.h"

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
send_raw (SoupSession *session, const gchar *method, const gchar *base_url,
    const gchar *path, const gchar *query, const gchar *access_token,
    const gchar *request_body, guint *out_status, gchar **out_body)
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
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

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
    return 300;
  g_autofree gchar *db_path = g_build_filename (path, "facts.duckdb", NULL);
  g_autoptr (wyl_fact_store_t) store = NULL;
  if (wyl_fact_store_open (db_path, &store) != WYRELOG_E_OK)
    return 301;
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
  duckdb_connection conn = wyl_fact_store_get_connection (store);
  gint64 count = 0;
  g_autofree gchar *sql = g_strdup_printf ("SELECT COUNT(*) FROM %s;", table);
  if (!count_i64 (conn, sql, &count))
    return 303;
  return count == expected_rows ? 0 : 304;
}

static gint
check_fact_http_contract (WylHandle *handle, const gchar *fact_root,
    const gchar *base_url)
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
      "order_id\tsymbol\tfalse\ttrue\n" "amount\tint64\tfalse\ttrue\n";
  g_clear_pointer (&body, g_free);
  g_autofree gchar *schema_query = g_strdup_printf
      ("tenant=%s&graph=orders&namespace=shop&relation=orders&"
      "schema_version=1&%s", WYL_TENANT_DEFAULT, FACT_GUARD);
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
  if (status != 200 || strstr (body, "\"inserted\":true") == NULL)
    return 27;
  rc = check_fact_projection_row_count (fact_root, "orders", 1);
  if (rc != 0)
    return rc;

  g_clear_pointer (&body, g_free);
  rc = send_raw (session, "POST", base_url,
      "/facts/__wr_default/orders/orders:append", append_query, admin_token,
      fact_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"inserted\":false") == NULL)
    return 28;
  rc = check_fact_projection_row_count (fact_root, "orders", 1);
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
  if (status != 200 || strstr (body, "\"relation\":\"orders\"") == NULL ||
      strstr (body, "\"columns\":[\"O\",\"A\"]") == NULL ||
      strstr (body, "{\"O\":\"o-1\",\"A\":42}") == NULL ||
      strstr (body, "facts.duckdb") != NULL)
    return 332;

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
  rc = check_fact_projection_row_count (fact_root, "orders", 2);
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
  /* Projection table accumulates assert+retract ops: batch-1 (assert o-1),
   * batch-7 (assert o-2), batch-r1 (retract o-2) = 3 physical rows. */
  rc = check_fact_projection_row_count (fact_root, "orders", 3);
  if (rc != 0)
    return rc;

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

  g_clear_pointer (&body, g_free);
  g_autofree gchar *seal_query = g_strdup_printf ("tenant=%s&graph=orders&%s",
      WYL_TENANT_DEFAULT, FACT_GUARD);
  rc = send_raw (session, "POST", base_url, "/graphs/seal", seal_query,
      admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"sealed\":true") == NULL)
    return 31;

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

  /* Forget case 1: normal forget of batch-1 -> 200 rows_purged>=1. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *forget_query = g_strdup_printf
      ("tenant=%s&namespace=shop&schema_version=1&%s", WYL_TENANT_DEFAULT,
      FACT_GUARD);
  rc = send_raw (session, "DELETE", base_url,
      "/facts/__wr_default/orders/orders:forget", forget_query, admin_token,
      "{\"batch_id\":\"batch-1\",\"operator\":\"admin\","
      "\"reason\":\"gdpr-erasure\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL ||
      strstr (body, "\"rows_purged\":") == NULL)
    return 500;

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

  gint rc = check_fact_http_contract (handle, fact_root, base_url);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_clear_object (&handle);
  remove_tree (fact_root);
  return rc;
}
