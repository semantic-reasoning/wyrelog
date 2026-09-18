/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <string.h>

#include <glib.h>

#include "wyrelog/audit/iter-private.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-client-private.h"
#include "wyrelog/wyl-client-codec-private.h"
#include "wyrelog/wyl-client-url-private.h"

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
  const gchar *body;
  gsize body_size;
  guint status;
  guint request_count;
  gboolean truncate_response_body;
  gboolean oversized_chunked_response;
  gchar *last_method;
  gchar *last_path;
  gchar *last_body;
  gchar *last_user;
  gchar *last_subject;
  gchar *last_perm;
  gchar *last_role;
  gchar *last_scope;
  gchar *last_tenant;
  gchar *last_dimension;
  gchar *last_limit;
  gchar *last_event;
  gchar *last_session_token;
  gchar *last_refresh_token;
  gchar *last_query_refresh_token;
  gchar *last_authorization;
  gchar *last_password;
  gchar *last_skip_mfa;
  gchar *last_guard_timestamp;
  gchar *last_guard_loc_class;
  gchar *last_guard_risk;
} TestHttpServer;

static const gchar *two_event_body =
    "[{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d001\","
    "\"created_at_us\":1234567,"
    "\"subject_id\":\"alice\","
    "\"action\":\"read\","
    "\"resource_id\":\"doc/42\","
    "\"deny_reason\":null,"
    "\"deny_origin\":null,"
    "\"request_id\":null,"
    "\"decision\":1},"
    "{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d002\","
    "\"created_at_us\":1234568,"
    "\"subject_id\":\"bob\","
    "\"action\":\"write\","
    "\"resource_id\":\"doc/43\","
    "\"deny_reason\":\"missing_grant\","
    "\"deny_origin\":\"policy\","
    "\"request_id\":\"req-client-smoke\"," "\"decision\":0}]";

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;

  g_main_loop_run (http->loop);
  return NULL;
}

static void
test_http_server_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  TestHttpServer *http = user_data;

  http->request_count++;

  g_free (http->last_method);
  g_free (http->last_path);
  g_free (http->last_body);
  g_free (http->last_user);
  g_free (http->last_subject);
  g_free (http->last_perm);
  g_free (http->last_role);
  g_free (http->last_scope);
  g_free (http->last_tenant);
  g_free (http->last_dimension);
  g_free (http->last_limit);
  g_free (http->last_event);
  g_free (http->last_session_token);
  g_free (http->last_refresh_token);
  g_free (http->last_query_refresh_token);
  g_free (http->last_authorization);
  g_free (http->last_password);
  g_free (http->last_skip_mfa);
  g_free (http->last_guard_timestamp);
  g_free (http->last_guard_loc_class);
  g_free (http->last_guard_risk);
  http->last_method = g_strdup (soup_server_message_get_method (msg));
  http->last_path = g_strdup (path);
  SoupMessageBody *request_body = soup_server_message_get_request_body (msg);
  if (request_body != NULL && request_body->data != NULL &&
      request_body->length > 0)
    http->last_body = g_strndup (request_body->data, request_body->length);
  else
    http->last_body = NULL;
  if (query != NULL) {
    const gchar *user = g_hash_table_lookup (query, "user");
    if (user == NULL)
      user = g_hash_table_lookup (query, "username");
    http->last_user = g_strdup (user);
  } else {
    http->last_user = NULL;
  }
  http->last_subject =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "subject")) : NULL;
  http->last_perm =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "perm")) : NULL;
  http->last_role =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "role")) : NULL;
  http->last_scope =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "scope")) : NULL;
  http->last_tenant =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "tenant")) : NULL;
  http->last_dimension =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "dimension")) : NULL;
  http->last_limit =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "limit")) : NULL;
  http->last_event =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "event")) : NULL;
  http->last_session_token =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "session_token")) : NULL;
  http->last_query_refresh_token =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "refresh_token")) : NULL;
  http->last_refresh_token = g_strdup (http->last_query_refresh_token);
  /*
   * #1030: the client sends the refresh token in the body now, so a mock that
   * reads only the query would record NULL and every assertion on it would
   * pass vacuously.  The read is keyed on the field name rather than on "this
   * request had a body": other routes post bodies of their own -- the service
   * token exchange sends credential_id and credential_secret -- and those must
   * keep leaving this NULL, which is what the assertion at the /auth/service-
   * token call asserts.
   */
  if (http->last_refresh_token == NULL && http->last_body != NULL) {
    const gchar *found = strstr (http->last_body, "\"refresh_token\"");
    if (found != NULL) {
      found = strchr (found + strlen ("\"refresh_token\""), ':');
      const gchar *open = found != NULL ? strchr (found, '"') : NULL;
      const gchar *close = open != NULL ? strchr (open + 1, '"') : NULL;
      if (close != NULL)
        http->last_refresh_token = g_strndup (open + 1,
                (gsize) (close - open - 1));
    }
  }
  http->last_authorization = g_strdup (soup_message_headers_get_one
            (soup_server_message_get_request_headers (msg), "Authorization"));
  http->last_password =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "password")) : NULL;
  http->last_skip_mfa =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "skip_mfa")) : NULL;
  http->last_guard_timestamp =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "guard_timestamp")) : NULL;
  http->last_guard_loc_class =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "guard_loc_class")) : NULL;
  http->last_guard_risk =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "guard_risk")) : NULL;

  if (http->truncate_response_body) {
    static const gchar truncated_response[] =
        "HTTP/1.1 503 Service Unavailable\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 64\r\n" "Connection: close\r\n\r\n" "{\"error\":";
    g_autoptr (GIOStream) connection =
        soup_server_message_steal_connection (msg);
    if (connection != NULL) {
      GOutputStream *output = g_io_stream_get_output_stream (connection);
      g_output_stream_write_all (output, truncated_response,
          sizeof truncated_response - 1, NULL, NULL, NULL);
      g_output_stream_flush (output, NULL, NULL);
      g_io_stream_close (connection, NULL, NULL);
    }
    return;
  }

  if (http->oversized_chunked_response) {
    const gsize oversized_len = WYL_CLIENT_FACT_STATUS_MAX_DOCUMENT + 1u;
    g_autofree gchar *chunk_header = g_strdup_printf ("%zx\r\n",
            oversized_len);
    g_autofree guint8 *chunk = g_malloc (oversized_len);
    memset (chunk, 'x', oversized_len);
    static const gchar response_header[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n";
    static const gchar response_end[] = "\r\n0\r\n\r\n";
    g_autoptr (GIOStream) connection =
        soup_server_message_steal_connection (msg);
    if (connection != NULL) {
      GOutputStream *output = g_io_stream_get_output_stream (connection);
      g_output_stream_write_all (output, response_header,
          sizeof response_header - 1, NULL, NULL, NULL);
      g_output_stream_write_all (output, chunk_header, strlen (chunk_header),
          NULL, NULL, NULL);
      g_output_stream_write_all (output, chunk, oversized_len, NULL, NULL,
          NULL);
      g_output_stream_write_all (output, response_end,
          sizeof response_end - 1, NULL, NULL, NULL);
      g_output_stream_flush (output, NULL, NULL);
      g_io_stream_close (connection, NULL, NULL);
    }
    return;
  }

  const gchar *body = http->body != NULL ? http->body : "[]";
  soup_server_message_set_status (msg, http->status != 0 ? http->status : 200,
      NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      body, http->body_size > 0 ? http->body_size : strlen (body));
}

static gboolean
client_last_response_is (WylClient *client, guint expected_status,
    const gchar *expected_error_code)
{
  g_autofree gchar *error_code = wyl_client_dup_last_error_code (client);
  return wyl_client_get_last_http_status (client) == expected_status
         && g_strcmp0 (error_code, expected_error_code) == 0;
}

typedef wyrelog_error_t (*LocalInvalidServiceManagementCall) (WylClient *);

static wyrelog_error_t
local_invalid_principal_create (WylClient *client)
{
  return wyl_client_service_principal_create (client, "svc:test:worker",
             "Worker", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_principal_list (WylClient *client)
{
  return wyl_client_service_principal_list (client, 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_principal_disable (WylClient *client)
{
  return wyl_client_service_principal_disable (client, "invalid", 123,
             "public", 10);
}

static wyrelog_error_t
local_invalid_credential_get (WylClient *client)
{
  return wyl_client_service_credential_get (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_get_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_get_for_tenant (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "tenant-a", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_list (WylClient *client)
{
  return wyl_client_service_credential_list (client, "svc:test:worker", 123,
             "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_list_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_list_for_tenant (client,
             "svc:test:worker", "tenant-a", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_revoke (WylClient *client)
{
  return wyl_client_service_credential_revoke (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "222222222222222222222222222",
             123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_revoke_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_revoke_for_tenant (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "222222222222222222222222222",
             "tenant-a", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_issue (WylClient *client)
{
  return wyl_client_service_credential_issue (client, NULL, 123, "public",
             10, NULL);
}

static wyrelog_error_t
local_invalid_credential_rotate (WylClient *client)
{
  return wyl_client_service_credential_rotate (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "222222222222222222222222222",
             "issue.json", 4102444800000000, 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_credential_rotate_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_rotate_for_tenant (client,
             "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "222222222222222222222222222",
             "issue.json", 4102444800000000, "tenant-a", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_operation_reconcile (WylClient *client)
{
  return wyl_client_service_credential_operation_reconcile (client, NULL, NULL);
}

static wyrelog_error_t
local_invalid_operation_reconcile_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_operation_reconcile_for_tenant
           (client, "tenant-a", NULL, 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_operation_status (WylClient *client)
{
  return wyl_client_service_credential_operation_status_list (client, 123,
             "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_operation_status_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_operation_status_list_for_tenant
           (client, "tenant-a", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_operation_recover (WylClient *client)
{
  return wyl_client_service_credential_operation_recover (client,
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 10, NULL);
}

static wyrelog_error_t
local_invalid_operation_recover_for_tenant (WylClient *client)
{
  return wyl_client_service_credential_operation_recover_for_tenant (client,
             "tenant-a", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 10, NULL);
}

static gboolean
check_service_credential_codecs (void)
{
  WylClientServiceTokenResult token = { 0 };
  WylClientServiceCredentialHandoffReceipt receipt = { 0 };
  const gchar *token_json = " { \"access_token\": \"access-1\" } ";
  const gchar *receipt_json =
      "{\"state\":\"terminal\",\"request_id\":\"111111111111111111111111111\","
      "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\",\"generation\":7,"
      "\"destination\":\"issue.json\","
      "\"publication_receipt_id\":\"wpr_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"delivered\":true}";
  const gchar *receipt_pending_json =
      "{\"state\":\"server_committed\","
      "\"request_id\":\"222222222222222222222222222\","
      "\"credential_id\":null,\"generation\":0,\"destination\":\"issue.json\","
      "\"publication_receipt_id\":null,\"delivered\":false}";

  if (wyl_client_service_token_result_decode (token_json, strlen (token_json),
      &token) != WYRELOG_E_OK
      || g_strcmp0 (token.access_token.text, "access-1") != 0)
    return FALSE;
  wyl_client_service_token_result_clear (&token);
  if (token.access_token.text != NULL || token.access_token.len != 0)
    return FALSE;
  const gchar *invalid_token_json[] = {
    "{\"access_token\":\"access-1\",\"refresh_token\":\"refresh-1\"}",
    "{\"access_token\":\"access-1\",\"access_token\":\"access-2\"}",
    "{\"access_token\":\"access-1\"} trailing",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_token_json); i++) {
    if (wyl_client_service_token_result_decode (invalid_token_json[i],
        strlen (invalid_token_json[i]), &token) == WYRELOG_E_OK
        || token.access_token.text != NULL || token.access_token.len != 0)
      return FALSE;
  }

  if (wyl_client_service_credential_handoff_receipt_decode (receipt_json,
      strlen (receipt_json), &receipt) != WYRELOG_E_OK
      || g_strcmp0 (receipt.state, "terminal") != 0
      || g_strcmp0 (receipt.request_id, "111111111111111111111111111") != 0
      || g_strcmp0 (receipt.credential_id,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0
      || receipt.generation != 7
      || g_strcmp0 (receipt.destination, "issue.json") != 0
      || g_strcmp0 (receipt.publication_receipt_id,
      "wpr_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0 || !receipt.delivered)
    return FALSE;
  wyl_client_service_credential_handoff_receipt_clear (&receipt);
  if (receipt.state != NULL || receipt.request_id != NULL
      || receipt.credential_id != NULL || receipt.destination != NULL
      || receipt.publication_receipt_id != NULL
      || receipt.generation != 0 || receipt.delivered)
    return FALSE;
  if (wyl_client_service_credential_handoff_receipt_decode
        (receipt_pending_json, strlen (receipt_pending_json),
      &receipt) != WYRELOG_E_OK
      || g_strcmp0 (receipt.state, "server_committed") != 0
      || receipt.credential_id != NULL || receipt.generation != 0
      || receipt.publication_receipt_id != NULL || receipt.delivered)
    return FALSE;
  wyl_client_service_credential_handoff_receipt_clear (&receipt);

  WylClientServicePrincipal principal = { 0 };
  WylClientServicePrincipalList principal_list = { 0 };
  const gchar *principal_json =
      "{\"service_principal\":{\"state\":\"active\","
      "\"display_name\":\"Worker One\","
      "\"subject_id\":\"svc:tenant:worker\",\"generation\":1,"
      "\"created_by\":\"admin\",\"created_at_us\":1,"
      "\"updated_at_us\":1,\"disabled_by\":null," "\"disabled_at_us\":0}}";
  const gchar *principal_list_json =
      "{\"service_principals\":[{\"subject_id\":\"svc:tenant:worker\","
      "\"display_name\":\"Worker One\",\"state\":\"active\","
      "\"generation\":1,\"created_by\":\"admin\","
      "\"created_at_us\":1,\"updated_at_us\":1,"
      "\"disabled_by\":null,\"disabled_at_us\":0}]}";
  const gchar *incomplete_principal =
      "{\"subject_id\":\"svc:x:y\",\"display_name\":\"Worker X\","
      "\"state\":\"active\"}";
  const gchar *inconsistent_principal =
      "{\"subject_id\":\"svc:x:y\",\"display_name\":\"Worker X\","
      "\"state\":\"active\",\"generation\":1,"
      "\"created_by\":\"admin\",\"created_at_us\":1,"
      "\"updated_at_us\":2,\"disabled_by\":\"admin\","
      "\"disabled_at_us\":2}";
  g_autofree gchar *incomplete_principal_document =
      g_strdup_printf ("{\"service_principal\":%s}", incomplete_principal);
  g_autofree gchar *incomplete_principal_list =
      g_strdup_printf ("{\"service_principals\":[%s]}",
          incomplete_principal);
  g_autofree gchar *inconsistent_principal_document =
      g_strdup_printf ("{\"service_principal\":%s}",
          inconsistent_principal);
  g_autofree gchar *inconsistent_principal_list =
      g_strdup_printf ("{\"service_principals\":[%s]}",
          inconsistent_principal);
  if (wyl_client_service_principal_decode (principal_json,
      strlen (principal_json), &principal) != WYRELOG_E_OK
      || g_strcmp0 (principal.subject_id, "svc:tenant:worker") != 0
      || wyl_client_service_principal_list_decode (principal_list_json,
      strlen (principal_list_json), &principal_list) != WYRELOG_E_OK
      || principal_list.len != 1)
    return FALSE;
  wyl_client_service_principal_clear (&principal);
  wyl_client_service_principal_list_clear (&principal_list);
  const gchar *principal_invalid[] = {
    "{\"service_principal\":{\"subject_id\":\"svc:x:y\","
    "\"display_name\":\"x\",\"state\":\"active\"," "\"extra\":1}}",
    "{\"service_principals\":[{\"subject_id\":\"svc:x:y\","
    "\"display_name\":\"x\",\"state\":\"active\"}]} trailing",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (principal_invalid); i++) {
    if (wyl_client_service_principal_decode (principal_invalid[i],
        strlen (principal_invalid[i]), &principal) == WYRELOG_E_OK
        || wyl_client_service_principal_list_decode (principal_invalid[i],
        strlen (principal_invalid[i]), &principal_list) == WYRELOG_E_OK
        || principal.subject_id != NULL || principal_list.items != NULL)
      return FALSE;
  }
  if (wyl_client_service_principal_list_decode (incomplete_principal_list,
      strlen (incomplete_principal_list), &principal_list) != WYRELOG_E_INVALID
      || principal_list.items != NULL || principal_list.len != 0
      || wyl_client_service_principal_list_decode (inconsistent_principal_list,
      strlen (inconsistent_principal_list), &principal_list) != WYRELOG_E_INVALID
      || principal_list.items != NULL || principal_list.len != 0)
    return FALSE;
  if (wyl_client_service_principal_decode (incomplete_principal_document,
      strlen (incomplete_principal_document), &principal) != WYRELOG_E_INVALID
      || principal.subject_id != NULL || principal.display_name != NULL
      || principal.state != NULL
      || wyl_client_service_principal_decode (inconsistent_principal_document,
      strlen (inconsistent_principal_document), &principal) != WYRELOG_E_INVALID
      || principal.subject_id != NULL || principal.display_name != NULL
      || principal.state != NULL)
    return FALSE;
  WylClientServiceCredential credential = { 0 };
  WylClientServiceCredentialList credential_list = { 0 };
  const gchar *credential_json =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:tenant:worker\","
      "\"tenant_id\":\"tenant-a\",\"generation\":1,\"state\":\"active\","
      "\"created_by\":\"admin\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":3,\"last_used_at_us\":-9223372036854775808,\"revoked_by\":null,"
      "\"revoked_at_us\":0,\"rotated_from_id\":null}}";
  if (wyl_client_service_credential_decode (credential_json,
      strlen (credential_json), &credential) != WYRELOG_E_OK
      || credential.generation != 1 || credential.last_used_at_us != G_MININT64
      || credential.revoked_by != NULL)
    return FALSE;
  wyl_client_service_credential_clear (&credential);
  const gchar *credential_list_json = "{\"service_credentials\":[]}";
  if (wyl_client_service_credential_list_decode (credential_list_json,
      strlen (credential_list_json), &credential_list) != WYRELOG_E_OK
      || credential_list.len != 0)
    return FALSE;
  wyl_client_service_credential_list_clear (&credential_list);
  principal.subject_id = g_strdup ("svc:stale:value");
  principal_list.items = g_new0 (WylClientServicePrincipal, 1);
  principal_list.len = 1;
  principal_list.items[0].subject_id = g_strdup ("svc:stale:value");
  if (wyl_client_service_principal_decode (principal_json, 20000,
      &principal) != WYRELOG_E_INVALID
      || principal.subject_id != NULL
      || wyl_client_service_principal_list_decode (principal_list_json, 20000,
      &principal_list) != WYRELOG_E_INVALID
      || principal_list.items != NULL || principal_list.len != 0)
    return FALSE;

  const gchar *invalid_token[] = {
    "{\"access_token\":\"a\",\"access_token\":\"b\"}",
    "{\"access_token\":\"a\",\"unknown\":1}",
    "{\"access_token\":\"a\"} trailing",
    "{\"access_token\":\"a\\u0000b\"}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_token); i++) {
    if (wyl_client_service_token_result_decode (invalid_token[i],
        strlen (invalid_token[i]), &token) == WYRELOG_E_OK
        || token.access_token.text != NULL)
      return FALSE;
  }
  const gchar *invalid_receipt[] = {
    /* Missing the delivered field. */
    "{\"state\":\"terminal\",\"request_id\":\"111111111111111111111111111\","
    "\"credential_id\":null,\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null}",
    /* Duplicate state key. */
    "{\"state\":\"terminal\",\"state\":\"terminal\","
    "\"request_id\":\"111111111111111111111111111\",\"credential_id\":null,"
    "\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null,\"delivered\":true}",
    /* Trailing junk after the object. */
    "{\"state\":\"terminal\",\"request_id\":\"111111111111111111111111111\","
    "\"credential_id\":null,\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null,\"delivered\":true} trailing",
    /* Non-boolean delivered value. */
    "{\"state\":\"terminal\",\"request_id\":\"111111111111111111111111111\","
    "\"credential_id\":null,\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null,\"delivered\":\"true\"}",
    /* Unknown state literal. */
    "{\"state\":\"bogus\",\"request_id\":\"111111111111111111111111111\","
    "\"credential_id\":null,\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null,\"delivered\":false}",
    /* Non-canonical credential_id. */
    "{\"state\":\"terminal\",\"request_id\":\"111111111111111111111111111\","
    "\"credential_id\":\"bad\",\"generation\":0,\"destination\":\"issue.json\","
    "\"publication_receipt_id\":null,\"delivered\":true}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_receipt); i++) {
    if (wyl_client_service_credential_handoff_receipt_decode (invalid_receipt
        [i], strlen (invalid_receipt[i]), &receipt) == WYRELOG_E_OK
        || receipt.state != NULL || receipt.delivered)
      return FALSE;
  }
  return TRUE;
}

static gboolean
check_secret_url_preflight (void)
{
  static const gchar *accepted[] = {
    "http://127.0.0.1",
    "https://127.0.0.1:8443",
    "http://[::1]:8080",
  };
  static const gchar *rejected[] = {
    "http://localhost",
    "http://127.0.0.01",
    "http://0177.0.0.1",
    "http://127.0.0.1.example",
    "http://[::ffff:127.0.0.1]",
    "http://[::1%25lo0]",
    "http://user:pass@127.0.0.1",
    "http://127.0.0.1:0",
    "ftp://127.0.0.1",
    "http://192.0.2.1",
    "http://127.0.0.1:65536",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (accepted); i++)
    if (!wyl_client_secret_url_is_canonical_literal_loopback (accepted[i]))
      return FALSE;
  for (gsize i = 0; i < G_N_ELEMENTS (rejected); i++)
    if (wyl_client_secret_url_is_canonical_literal_loopback (rejected[i]))
      return FALSE;
  if (!wyl_client_secret_redirect_is_same_authority
        ("http://127.0.0.1:8080/api", "http://127.0.0.1:8080/other")
      || wyl_client_secret_redirect_is_same_authority
        ("http://127.0.0.1:8080/api", "http://127.0.0.1:8081/other")
      || wyl_client_secret_redirect_is_same_authority
        ("http://127.0.0.1:8080/api", "https://127.0.0.1:8080/other")
      || wyl_client_secret_redirect_is_same_authority
        ("http://127.0.0.1:8080/api", "/relative"))
    return FALSE;
  return TRUE;
}

static gboolean
check_fact_status_codec (void)
{
  WylClientFactStatus status = { 0 };
  const gchar *valid =
      "{\"status\":\"ready\",\"graphs_total\":2,"
      "\"graphs_ready\":1,\"graphs_degraded\":0,\"graphs_sealed\":1,"
      "\"\\u20ac\":null,\"graphs\":[{"
      "\"tenant_id\":\"tenant-a\",\"graph_id\":\"orders\","
      "\"state\":\"ready\",\"queryable\":true,"
      "\"last_error_class\":null,\"future\":{\"array\":[true,2,null],"
      "\"\\u20ac\":\"\\u0000\\uD83D\\uDE00\"},"
      "\"\\u20ac\":null},"
      "{\"tenant_id\":\"tenant-a\",\"graph_id\":\"sealed\","
      "\"state\":\"sealed\",\"queryable\":false,"
      "\"last_error_class\":null}],\"future_root\":[1,{\"x\":false}]}";
  if (wyl_client_fact_status_decode (valid, strlen (valid), &status)
      != WYRELOG_E_OK || status.status != WYL_CLIENT_FACT_STATUS_READY
      || g_strcmp0 (status.status_name, "ready") != 0
      || status.graphs_total != 2 || status.graphs_ready != 1
      || status.graphs_degraded != 0 || status.graphs_sealed != 1
      || !status.has_graphs || status.n_graphs != 2
      || status.graphs[0].state != WYL_CLIENT_FACT_GRAPH_STATE_READY
      || status.graphs[0].last_error_class != NULL
      || status.graphs[1].state != WYL_CLIENT_FACT_GRAPH_STATE_SEALED)
    return FALSE;
  wyl_client_fact_status_clear (&status);
  if (status.status_name != NULL || status.graphs != NULL
      || status.n_graphs != 0 || status.graphs_total != 0)
    return FALSE;

  const struct
  {
    const gchar *name;
    WylClientFactGraphState state;
  } current_states[] = {
    {"ready", WYL_CLIENT_FACT_GRAPH_STATE_READY},
    {"degraded", WYL_CLIENT_FACT_GRAPH_STATE_DEGRADED},
    {"schema_mismatch", WYL_CLIENT_FACT_GRAPH_STATE_SCHEMA_MISMATCH},
    {"replay_failed", WYL_CLIENT_FACT_GRAPH_STATE_REPLAY_FAILED},
    {"store_unavailable", WYL_CLIENT_FACT_GRAPH_STATE_STORE_UNAVAILABLE},
    {"forget_incomplete", WYL_CLIENT_FACT_GRAPH_STATE_FORGET_INCOMPLETE},
    {"sealed", WYL_CLIENT_FACT_GRAPH_STATE_SEALED},
    {"empty", WYL_CLIENT_FACT_GRAPH_STATE_EMPTY},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (current_states); i++) {
    gboolean ready = current_states[i].state ==
        WYL_CLIENT_FACT_GRAPH_STATE_READY;
    gboolean sealed = current_states[i].state ==
        WYL_CLIENT_FACT_GRAPH_STATE_SEALED;
    gboolean empty = current_states[i].state ==
        WYL_CLIENT_FACT_GRAPH_STATE_EMPTY;
    g_autofree gchar *document = g_strdup_printf
          ("{\"status\":\"%s\",\"graphs_total\":1,"
            "\"graphs_ready\":%u,\"graphs_degraded\":%u,"
            "\"graphs_provisioned\":%u,\"graphs_sealed\":%u,"
            "\"graphs\":[{"
            "\"tenant_id\":\"tenant-a\",\"graph_id\":\"g\","
            "\"state\":\"%s\",\"queryable\":false,"
            "\"last_error_class\":null}]}",
            ready || sealed || empty ? "ready" : "degraded",
            ready ? 1u : 0u, !ready && !sealed && !empty ? 1u : 0u,
            empty ? 1u : 0u, sealed ? 1u : 0u,
            current_states[i].name);
    if (wyl_client_fact_status_decode (document, strlen (document), &status)
        != WYRELOG_E_OK
        || status.graphs[0].state != current_states[i].state)
      return FALSE;
    wyl_client_fact_status_clear (&status);
  }
  const gchar *disabled =
      "{\"status\":\"disabled\",\"graphs_total\":0,"
      "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}";
  if (wyl_client_fact_status_decode (disabled, strlen (disabled), &status)
      != WYRELOG_E_OK
      || status.status != WYL_CLIENT_FACT_STATUS_DISABLED || status.has_graphs
      || status.n_graphs != 0)
    return FALSE;
  wyl_client_fact_status_clear (&status);

  const gchar *future =
      "{\"status\":\"partially_ready\",\"graphs_total\":1,"
      "\"graphs_ready\":0,\"graphs_degraded\":1,\"graphs_sealed\":0,"
      "\"graphs\":[{\"tenant_id\":\"tenant-a\",\"graph_id\":\"orders\","
      "\"state\":\"actively_reconciling\",\"queryable\":false,"
      "\"last_error_class\":\"future_reason\"}]}";
  if (wyl_client_fact_status_decode (future, strlen (future), &status)
      != WYRELOG_E_OK || status.status != WYL_CLIENT_FACT_STATUS_UNKNOWN
      || g_strcmp0 (status.status_name, "partially_ready") != 0
      || status.graphs[0].state != WYL_CLIENT_FACT_GRAPH_STATE_UNKNOWN
      || g_strcmp0 (status.graphs[0].state_name,
      "actively_reconciling") != 0)
    return FALSE;
  wyl_client_fact_status_clear (&status);

  const gchar *invalid[] = {
    /* Duplicate recognized key. */
    "{\"status\":\"ready\",\"status\":\"ready\",\"graphs_total\":0,"
    "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}",
    /* Duplicate graph identity. */
    "{\"status\":\"ready\",\"graphs_total\":2,\"graphs_ready\":2,"
    "\"graphs_degraded\":0,\"graphs_sealed\":0,\"graphs\":["
    "{\"tenant_id\":\"t\",\"graph_id\":\"g\",\"state\":\"ready\","
    "\"queryable\":true,\"last_error_class\":null},"
    "{\"tenant_id\":\"t\",\"graph_id\":\"g\",\"state\":\"ready\","
    "\"queryable\":true,\"last_error_class\":null}]}",
    /* Duplicate recognized graph member. */
    "{\"status\":\"ready\",\"graphs_total\":1,\"graphs_ready\":1,"
    "\"graphs_degraded\":0,\"graphs_sealed\":0,\"graphs\":[{"
    "\"tenant_id\":\"t\",\"graph_id\":\"g\",\"state\":\"ready\","
    "\"state\":\"sealed\",\"queryable\":true,"
    "\"last_error_class\":null}]}",
    /* Bucket mismatch. */
    "{\"status\":\"ready\",\"graphs_total\":1,\"graphs_ready\":0,"
    "\"graphs_degraded\":0,\"graphs_sealed\":1,\"graphs\":[]}",
    /* Wrong type and trailing junk. */
    "{\"status\":\"ready\",\"graphs_total\":\"0\",\"graphs_ready\":0,"
    "\"graphs_degraded\":0,\"graphs_sealed\":0}",
    /* VT and FF are accepted by generic ASCII whitespace helpers but not JSON. */
    "\v{\"status\":\"ready\",\"graphs_total\":0,"
    "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}",
    "{\"status\":\"ready\",\f\"graphs_total\":0,"
    "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}",
    "{\"status\":\"ready\",\"graphs_total\":0,\"graphs_ready\":0,"
    "\"graphs_degraded\":0,\"graphs_sealed\":0} trailing",
    /* Invalid additive JSON is not silently skipped. */
    "{\"status\":\"ready\",\"graphs_total\":0,\"graphs_ready\":0,"
    "\"graphs_degraded\":0,\"graphs_sealed\":0,\"new\":[1,]}",
    /* An unknown graph state still belongs to the server's degraded bucket. */
    "{\"status\":\"degraded\",\"graphs_total\":1,\"graphs_ready\":0,"
    "\"graphs_degraded\":0,\"graphs_sealed\":1,\"graphs\":["
    "{\"tenant_id\":\"t\",\"graph_id\":\"g\","
    "\"state\":\"future\",\"queryable\":false,"
    "\"last_error_class\":null}]}"
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    status.status_name = g_strdup ("stale");
    if (wyl_client_fact_status_decode (invalid[i], strlen (invalid[i]),
        &status) == WYRELOG_E_OK || status.status_name != NULL
        || status.graphs != NULL || status.n_graphs != 0
        || status.graphs_total != 0)
      return FALSE;
  }
  if (wyl_client_fact_status_decode ("x", (4u * 1024u * 1024u) + 1u,
      &status) != WYRELOG_E_INVALID || status.status_name != NULL
      || status.graphs != NULL)
    return FALSE;

  GString *nested = g_string_new ("{\"status\":\"ready\","
          "\"graphs_total\":0,\"graphs_ready\":0,\"graphs_degraded\":0,"
          "\"graphs_sealed\":0,\"future\":");
  for (guint i = 0; i < 32; i++)
    g_string_append_c (nested, '[');
  g_string_append_c (nested, '0');
  for (guint i = 0; i < 32; i++)
    g_string_append_c (nested, ']');
  g_string_append_c (nested, '}');
  if (wyl_client_fact_status_decode (nested->str, nested->len, &status)
      != WYRELOG_E_OK) {
    g_string_free (nested, TRUE);
    return FALSE;
  }
  wyl_client_fact_status_clear (&status);
  g_string_truncate (nested, 0);
  g_string_append (nested, "{\"status\":\"ready\","
      "\"graphs_total\":0,\"graphs_ready\":0,\"graphs_degraded\":0,"
      "\"graphs_sealed\":0,\"future\":");
  for (guint i = 0; i < 33; i++)
    g_string_append_c (nested, '[');
  g_string_append_c (nested, '0');
  for (guint i = 0; i < 33; i++)
    g_string_append_c (nested, ']');
  g_string_append_c (nested, '}');
  gboolean excessive_depth = wyl_client_fact_status_decode (nested->str,
          nested->len, &status) != WYRELOG_E_INVALID;
  g_string_free (nested, TRUE);
  if (excessive_depth || status.status_name != NULL)
    return FALSE;

  g_autofree gchar *long_name_64 = g_strnfill (64, 'x');
  g_autofree gchar *wire_name_64 = g_strdup_printf
        ("{\"status\":\"degraded\",\"graphs_total\":1,"
          "\"graphs_ready\":0,\"graphs_degraded\":1,\"graphs_sealed\":0,"
          "\"graphs\":[{\"tenant_id\":\"t\",\"graph_id\":\"g\","
          "\"state\":\"degraded\",\"queryable\":false,"
          "\"last_error_class\":\"%s\"}]}", long_name_64);
  if (wyl_client_fact_status_decode (wire_name_64, strlen (wire_name_64),
      &status) != WYRELOG_E_OK
      || status.graphs[0].reason_class != WYL_CLIENT_FACT_REASON_UNKNOWN)
    return FALSE;
  wyl_client_fact_status_clear (&status);
  g_autofree gchar *long_name_65 = g_strnfill (65, 'x');
  g_autofree gchar *wire_name_65 = g_strdup_printf
        ("{\"status\":\"degraded\",\"graphs_total\":1,"
          "\"graphs_ready\":0,\"graphs_degraded\":1,\"graphs_sealed\":0,"
          "\"graphs\":[{\"tenant_id\":\"t\",\"graph_id\":\"g\","
          "\"state\":\"degraded\",\"queryable\":false,"
          "\"last_error_class\":\"%s\"}]}", long_name_65);
  if (wyl_client_fact_status_decode (wire_name_65, strlen (wire_name_65),
      &status) != WYRELOG_E_INVALID || status.status_name != NULL)
    return FALSE;

  const gchar *max_document_prefix =
      "{\"status\":\"ready\",\"graphs_total\":0,"
      "\"graphs_ready\":0,\"graphs_degraded\":0,\"graphs_sealed\":0}";
  GString *max_document = g_string_new (max_document_prefix);
  gsize prefix_len = max_document->len;
  g_string_set_size (max_document, 4u * 1024u * 1024u);
  /* Replace the zero-filled extension with JSON whitespace, yielding a valid
   * document exactly at the decoder's size boundary. */
  memset (max_document->str + prefix_len, ' ',
      max_document->len - prefix_len);
  if (wyl_client_fact_status_decode (max_document->str, max_document->len,
      &status) != WYRELOG_E_OK) {
    g_string_free (max_document, TRUE);
    return FALSE;
  }
  wyl_client_fact_status_clear (&status);
  g_string_free (max_document, TRUE);

  GString *many_graphs = g_string_new ("{\"status\":\"degraded\","
          "\"graphs_total\":16385,\"graphs_ready\":0,"
          "\"graphs_degraded\":16385,\"graphs_sealed\":0,\"graphs\":[");
  for (guint i = 0; i < 16385; i++) {
    if (i > 0)
      g_string_append_c (many_graphs, ',');
    g_string_append_printf (many_graphs,
        "{\"tenant_id\":\"t\",\"graph_id\":\"g%u\","
        "\"state\":\"degraded\",\"queryable\":false,"
        "\"last_error_class\":\"degraded\"}", i);
  }
  g_string_append (many_graphs, "]}");
  gboolean too_many_graphs = wyl_client_fact_status_decode (many_graphs->str,
          many_graphs->len, &status) != WYRELOG_E_INVALID;
  g_string_free (many_graphs, TRUE);
  if (too_many_graphs || status.status_name != NULL || status.graphs != NULL)
    return FALSE;

  GString *max_graphs = g_string_new ("{\"status\":\"degraded\","
          "\"graphs_total\":16384,\"graphs_ready\":0,"
          "\"graphs_degraded\":16384,\"graphs_sealed\":0,\"graphs\":[");
  for (guint i = 0; i < 16384; i++) {
    if (i > 0)
      g_string_append_c (max_graphs, ',');
    g_string_append_printf (max_graphs,
        "{\"tenant_id\":\"t\",\"graph_id\":\"g%u\","
        "\"state\":\"degraded\",\"queryable\":false,"
        "\"last_error_class\":\"degraded\"}", i);
  }
  g_string_append (max_graphs, "]}");
  gboolean maximum_count_accepted = wyl_client_fact_status_decode
        (max_graphs->str, max_graphs->len, &status) != WYRELOG_E_OK
      || status.n_graphs != 16384;
  g_string_free (max_graphs, TRUE);
  wyl_client_fact_status_clear (&status);
  if (maximum_count_accepted)
    return FALSE;
  return TRUE;
}

int
main (void)
{
  if (!check_service_credential_codecs ())
    return wyl_test_normalize_exit_status (230);
  if (!check_fact_status_codec ())
    return wyl_test_normalize_exit_status (232);
  if (!check_secret_url_preflight ())
    return wyl_test_normalize_exit_status (231);
  const gchar *version = wyrelog_client_version_string ();
  if (version == NULL || version[0] == '\0')
    return wyl_test_normalize_exit_status (1);

  g_autoptr (WylClient) client = NULL;

  /* Input validation: NULL out_client must be rejected. */
  if (wyl_client_new ("http://example.invalid", NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (2);
  if (wyl_client_new (NULL, &client) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (9);
  if (wyl_client_new ("", &client) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (10);
  if (wyl_client_new ("file:///tmp/wyrelog.sock", &client) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (11);

  /* Successful path returns a non-NULL WylClient. */
  client = NULL;
  if (wyl_client_new ("http://example.invalid", &client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (3);
  if (client == NULL)
    return wyl_test_normalize_exit_status (4);
  g_auto (WylClientFactStatus) nonlocal_fact_status = { 0 };
  if (wyl_client_fact_status (client, NULL, NULL, &nonlocal_fact_status)
      != WYRELOG_E_INVALID || nonlocal_fact_status.status_name != NULL
      || nonlocal_fact_status.graphs != NULL)
    return wyl_test_normalize_exit_status (284);
  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (g_strcmp0 (base_url, "http://example.invalid") != 0)
    return wyl_test_normalize_exit_status (12);
  if (wyl_client_get_soup_session (client) == NULL)
    return wyl_test_normalize_exit_status (17);

  /* Audit iterator returns a non-NULL WylAuditIter on success and
   * yields no rows in the stub state. */
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (NULL, NULL, &iter) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (13);
  if (wyl_client_audit_query (client, NULL, NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (14);
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (5);
  if (iter == NULL)
    return wyl_test_normalize_exit_status (6);
  g_autofree gchar *query_filter = wyl_audit_iter_dup_query_filter (iter);
  if (g_strcmp0 (query_filter, "decision=deny") != 0)
    return wyl_test_normalize_exit_status (15);
  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  if (g_strcmp0 (request_uri,
      "http://example.invalid/audit/events?filter=decision%3Ddeny") != 0)
    return wyl_test_normalize_exit_status (16);
  g_autoptr (SoupMessage) message = wyl_audit_iter_new_request_message (iter);
  if (message == NULL)
    return wyl_test_normalize_exit_status (18);
  if (g_strcmp0 (soup_message_get_method (message), "GET") != 0)
    return wyl_test_normalize_exit_status (19);
  g_autofree gchar *message_uri =
      g_uri_to_string (soup_message_get_uri (message));
  if (g_strcmp0 (message_uri, request_uri) != 0)
    return wyl_test_normalize_exit_status (20);

  TestHttpServer http = { 0 };
  http.server = soup_server_new (NULL, NULL);
  http.loop = g_main_loop_new (NULL, FALSE);
  http.body = "[]";
  soup_server_add_handler (http.server, NULL, test_http_server_handler, &http,
      NULL);
  g_autoptr (GError) listen_error = NULL;
  if (!soup_server_listen_local (http.server, 0, 0, &listen_error))
    return wyl_test_normalize_exit_status (21);
  GThread *thread = g_thread_new ("client-smoke-http",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return wyl_test_normalize_exit_status (22);
  g_autofree gchar *local_base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) local_client = NULL;
  if (wyl_client_new (local_base_url, &local_client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (23);
  g_autoptr (WylAuditIter) local_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &local_iter) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (24);
  g_autoptr (SoupMessage) local_message =
      wyl_audit_iter_new_request_message (local_iter);
  g_autoptr (GBytes) body = NULL;
  if (wyl_client_send_message (local_client, local_message, &body) !=
      WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (25);
  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  if (body_size != 2 || memcmp (body_data, "[]", 2) != 0)
    return wyl_test_normalize_exit_status (26);
  if (wyl_client_send_message (local_client, NULL, &body) !=
      WYRELOG_E_INVALID || body != NULL)
    return wyl_test_normalize_exit_status (2611);

  if (wyl_client_login (NULL, "alice", NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (38);
  if (wyl_client_login (local_client, NULL, NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (39);
  if (wyl_client_login (local_client, "", NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (40);
  if (wyl_client_login (local_client, "alice", "secret") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (41);
  if (wyl_client_login_skip_mfa (NULL, "alice") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (143);
  if (wyl_client_login_skip_mfa (local_client, NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (144);
  if (wyl_client_login_skip_mfa (local_client, "") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (145);
  g_autoptr (WylAuditIter) missing_login_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
      "public", 69, &missing_login_iter) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (153);
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (510);

  http.body = "{\"session_token\":\"session-1\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"mfa_required\","
      "\"session_state\":\"active\"}";
  if (wyl_client_login (local_client, "alice", NULL) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (42);
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return wyl_test_normalize_exit_status (43);
  if (g_strcmp0 (http.last_path, "/auth/login") != 0)
    return wyl_test_normalize_exit_status (44);
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return wyl_test_normalize_exit_status (45);
  if (http.last_password != NULL)
    return wyl_test_normalize_exit_status (46);
  if (http.last_skip_mfa != NULL)
    return wyl_test_normalize_exit_status (146);
  g_autofree gchar *client_session_token =
      wyl_client_dup_session_token (local_client);
  g_autofree gchar *client_access_token =
      wyl_client_dup_access_token (local_client);
  g_autofree gchar *client_username = wyl_client_dup_username (local_client);
  g_autofree gchar *client_tenant = wyl_client_dup_tenant (local_client);
  g_autofree gchar *client_principal_state =
      wyl_client_dup_principal_state (local_client);
  g_autofree gchar *client_session_state =
      wyl_client_dup_session_state (local_client);
  if (g_strcmp0 (client_session_token, "session-1") != 0 ||
      client_access_token != NULL ||
      g_strcmp0 (client_username, "alice") != 0 ||
      g_strcmp0 (client_tenant, "__wr_default") != 0 ||
      g_strcmp0 (client_principal_state, "mfa_required") != 0 ||
      g_strcmp0 (client_session_state, "active") != 0)
    return wyl_test_normalize_exit_status (138);
  g_auto (WylClientServiceTokenResult)
  token_result = { 0 };
  WylClientSensitiveText credential_secret = {
    .text = (gchar *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
    .len = 43,
  };
  WylClientServiceTokenRequest token_request = {
    .credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
    .credential_secret = &credential_secret,
  };
  http.body = "{\"access_token\":\"access-token-1\"}";
  if (wyl_client_service_token_exchange (local_client, &token_request,
      &token_result) != WYRELOG_E_OK
      || g_strcmp0 (token_result.access_token.text, "access-token-1") != 0
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_path, "/auth/service-token") != 0
      || strstr (http.last_body,
      "{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\",\"credential_secret\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq\"}")
      == NULL || http.last_tenant != NULL || http.last_session_token != NULL
      || http.last_refresh_token != NULL || http.last_authorization != NULL)
    return wyl_test_normalize_exit_status (244);
  gchar bounded_secret[43];
  memcpy (bounded_secret, credential_secret.text, sizeof bounded_secret);
  credential_secret.text = bounded_secret;
  if (wyl_client_service_token_exchange (local_client, &token_request,
      &token_result) != WYRELOG_E_OK
      || g_strcmp0 (token_result.access_token.text, "access-token-1") != 0)
    return wyl_test_normalize_exit_status (247);
  credential_secret.text = (gchar *)
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
  WylClientSensitiveText invalid_secret = {
    .text = (gchar *) "bad",
    .len = 3,
  };
  token_request.credential_secret = &invalid_secret;
  if (wyl_client_service_token_exchange (local_client, &token_request,
      &token_result) != WYRELOG_E_INVALID
      || g_strcmp0 (http.last_path, "/auth/service-token") != 0)
    return wyl_test_normalize_exit_status (245);
  token_request.credential_secret = &credential_secret;
  http.status = 429;
  http.body = "{\"error\":\"rate_limited\"}";
  if (wyl_client_service_token_exchange (local_client, &token_request,
      &token_result) != WYRELOG_E_IO
      || token_result.access_token.text != NULL)
    return wyl_test_normalize_exit_status (246);
  http.status = 0;
  g_autoptr (WylClient) management_client = NULL;
  if (wyl_client_new (local_base_url, &management_client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (279);
  http.body = "{\"session_token\":\"management-session\","
      "\"username\":\"alice\",\"tenant\":\"__wr_default\","
      "\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\"," "\"access_token\":\"management-access\"}";
  if (wyl_client_login_skip_mfa (management_client, "alice") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (280);
  g_auto (WylClientFactStatus) fact_status = { 0 };
  http.body =
      "{\"status\":\"degraded\",\"graphs_total\":1,"
      "\"graphs_ready\":0,\"graphs_degraded\":1,\"graphs_sealed\":0,"
      "\"graphs\":[{\"tenant_id\":\"tenant-a\",\"graph_id\":\"orders\","
      "\"state\":\"forget_incomplete\",\"queryable\":true,"
      "\"last_error_class\":\"forget_incomplete\"}]}";
  if (wyl_client_fact_status (management_client, NULL, NULL, &fact_status)
      != WYRELOG_E_OK
      || fact_status.status != WYL_CLIENT_FACT_STATUS_DEGRADED
      || fact_status.n_graphs != 1
      || fact_status.graphs[0].state !=
      WYL_CLIENT_FACT_GRAPH_STATE_FORGET_INCOMPLETE
      || fact_status.graphs[0].reason_class !=
      WYL_CLIENT_FACT_REASON_FORGET_INCOMPLETE
      || !fact_status.graphs[0].queryable
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path, "/facts/status") != 0
      || http.last_authorization != NULL
      || !client_last_response_is (management_client, 200, NULL))
    return wyl_test_normalize_exit_status (281);
  http.body = "{\"status\":\"ready\",\"private_detail\":\"do-not-leak\"}";
  if (wyl_client_fact_status (management_client, NULL, NULL, &fact_status)
      != WYRELOG_E_IO
      || fact_status.status_name != NULL || fact_status.graphs != NULL
      || fact_status.n_graphs != 0
      || g_strcmp0 (http.body, "{\"status\":\"ready\",\"private_detail\":\"do-not-leak\"}") != 0)
    return wyl_test_normalize_exit_status (282);
  http.status = 503;
  http.body = "{\"error\":\"unavailable\"}";
  if (wyl_client_fact_status (management_client, NULL, NULL, &fact_status)
      != WYRELOG_E_BUSY
      || fact_status.status_name != NULL || fact_status.graphs != NULL
      || fact_status.n_graphs != 0
      || !client_last_response_is (management_client, 503, NULL))
    return wyl_test_normalize_exit_status (283);
  http.status = 0;
  http.oversized_chunked_response = TRUE;
  if (wyl_client_fact_status (management_client, NULL, NULL, &fact_status)
      != WYRELOG_E_IO
      || fact_status.status_name != NULL || fact_status.graphs != NULL
      || fact_status.n_graphs != 0)
    return wyl_test_normalize_exit_status (285);
  http.oversized_chunked_response = FALSE;

  WylClientFactGraphVerification verification = { 0 };
  http.body = "{\"ok\":true,\"verified\":true,"
      "\"tenant_id\":\"__wr_default\",\"graph_id\":\"orders\"}";
  if (wyl_client_fact_graph_verify (management_client, "__wr_default", "orders",
      123, "public", 49, &verification) != WYRELOG_E_OK
      || !verification.verified
      || g_strcmp0 (verification.tenant_id, "__wr_default") != 0
      || g_strcmp0 (verification.graph_id, "orders") != 0
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path, "/facts/verify") != 0
      || g_strcmp0 (http.last_tenant, "__wr_default") != 0
      || g_strcmp0 (http.last_authorization, "Bearer management-access") != 0)
    return wyl_test_normalize_exit_status (289);
  wyl_client_fact_graph_verification_clear (&verification);
  http.status = 404;
  http.body = "{\"error\":\"graph_not_found\"}";
  if (wyl_client_fact_graph_verify (management_client, "__wr_default", "orders",
      123, "public", 49, &verification) != WYRELOG_E_NOT_FOUND
      || verification.tenant_id != NULL || verification.graph_id != NULL
      || verification.verified)
    return wyl_test_normalize_exit_status (290);
  http.status = 503;
  http.body = "{\"error\":\"fact_graph_verification_unavailable\"}";
  if (wyl_client_fact_graph_verify (management_client, "__wr_default", "orders",
      123, "public", 49, &verification) != WYRELOG_E_BUSY
      || verification.tenant_id != NULL || verification.graph_id != NULL
      || verification.verified)
    return wyl_test_normalize_exit_status (291);
  http.status = 0;

  /* #1096: the schema-count quota client must keep its typed contract
   * distinct from graph-count and write-rate quotas. */
  WylClientFactSchemaQuotaStatus schema_quota = { 0 };
  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"schema_count\",\"limit\":3,\"registered\":2}";
  if (wyl_client_fact_schema_quota_status (management_client,
      "__wr_default", 123, "public", 49, &schema_quota) != WYRELOG_E_OK
      || !schema_quota.has_limit || schema_quota.hard_limit != 3
      || schema_quota.registered != 2
      || g_strcmp0 (schema_quota.tenant_id, "__wr_default") != 0
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path, "/facts/quota") != 0
      || g_strcmp0 (http.last_dimension, "schema_count") != 0
      || http.last_limit != NULL || http.last_body != NULL)
    return wyl_test_normalize_exit_status (286);

  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"schema_count\",\"limit\":4,\"registered\":2}";
  if (wyl_client_fact_schema_quota_configure (management_client,
      "__wr_default", 4, 123, "public", 49, &schema_quota) != WYRELOG_E_OK
      || !schema_quota.has_limit || schema_quota.hard_limit != 4
      || schema_quota.registered != 2
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_dimension, "schema_count") != 0
      || g_strcmp0 (http.last_limit, "4") != 0 || http.last_body != NULL)
    return wyl_test_normalize_exit_status (287);

  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"schema_count\",\"limit\":null,\"registered\":0}";
  if (wyl_client_fact_schema_quota_status (management_client,
      "__wr_default", 123, "public", 49, &schema_quota) != WYRELOG_E_OK
      || schema_quota.has_limit || schema_quota.hard_limit != 0
      || schema_quota.registered != 0)
    return wyl_test_normalize_exit_status (288);

  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"schema_count\",\"limit\":3,\"registered\":2}";
  if (wyl_client_fact_schema_quota_status (management_client,
      "__wr_default", 123, "public", 49, &schema_quota) != WYRELOG_E_OK
      || !schema_quota.has_limit || schema_quota.hard_limit != 3
      || schema_quota.registered != 2)
    return wyl_test_normalize_exit_status (289);

  /* A malformed replacement clears the previous typed result rather than
   * leaving stale quota data visible to the caller. */
  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"schema_count\",\"limit\":null}";
  if (wyl_client_fact_schema_quota_status (management_client,
      "__wr_default", 123, "public", 49, &schema_quota) != WYRELOG_E_IO
      || schema_quota.tenant_id != NULL || schema_quota.has_limit
      || schema_quota.hard_limit != 0 || schema_quota.registered != 0)
    return wyl_test_normalize_exit_status (290);
  wyl_client_fact_schema_quota_status_clear (&schema_quota);

  /* #1098: concurrent-open quota keeps all durable state counters typed. */
  WylClientFactConcurrentOpenQuotaStatus concurrent_quota = { 0 };
  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"concurrent_opens\",\"limit\":3,"
      "\"pending\":1,\"active\":2,\"acquiring\":1,"
      "\"cleanup_pending\":0,\"charged\":4}";
  if (wyl_client_fact_concurrent_open_quota_status (management_client,
      "__wr_default", 123, "public", 49, &concurrent_quota) != WYRELOG_E_OK
      || !concurrent_quota.has_limit || concurrent_quota.hard_limit != 3
      || concurrent_quota.pending != 1 || concurrent_quota.active != 2
      || concurrent_quota.acquiring != 1 || concurrent_quota.charged != 4
      || g_strcmp0 (http.last_dimension, "concurrent_opens") != 0
      || g_strcmp0 (http.last_method, "GET") != 0)
    return wyl_test_normalize_exit_status (292);
  http.body = "{\"tenant_id\":\"__wr_default\","
      "\"dimension\":\"concurrent_opens\",\"limit\":4,"
      "\"pending\":0,\"active\":0,\"acquiring\":0,"
      "\"cleanup_pending\":0,\"charged\":0}";
  if (wyl_client_fact_concurrent_open_quota_configure (management_client,
      "__wr_default", 4, 123, "public", 49, &concurrent_quota) != WYRELOG_E_OK
      || !concurrent_quota.has_limit || concurrent_quota.hard_limit != 4
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_dimension, "concurrent_opens") != 0
      || g_strcmp0 (http.last_limit, "4") != 0)
    return wyl_test_normalize_exit_status (293);
  wyl_client_fact_concurrent_open_quota_status_clear (&concurrent_quota);

  /* #1093: durable logical quota operations are queried with the complete
   * identity, and the typed result preserves reconciling's unknown byte
   * sentinel. */
  WylClientFactLogicalOperationStatus operation_status = { 0 };
  http.status = 200;
  http.body = "{\"ok\":true,\"tenant_id\":\"__wr_default\","
      "\"graph_id\":\"orders\",\"batch_id\":\"batch-1\","
      "\"operation_id\":\"request-1\",\"state\":\"reconciling\","
      "\"replay\":false,\"requested_rows\":3,\"requested_bytes\":12,"
      "\"applied_rows\":3,\"applied_bytes\":-1}";
  if (wyl_client_fact_logical_operation_status (management_client,
      "__wr_default", "orders", "batch-1", "request-1",
      "0000000000000000000000000000000000000000000000000000000000000000",
      123, "public", 49, &operation_status) != WYRELOG_E_OK
      || operation_status.state !=
      WYL_CLIENT_FACT_LOGICAL_OPERATION_RECONCILING
      || operation_status.applied_rows != 3
      || operation_status.applied_bytes != -1
      || g_strcmp0 (operation_status.graph_id, "orders") != 0
      || g_strcmp0 (operation_status.operation_id, "request-1") != 0
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path,
      "/facts/quota/operation-status") != 0)
    return wyl_test_normalize_exit_status (294);
  wyl_client_fact_logical_operation_status_clear (&operation_status);
  http.status = 404;
  http.body = "{\"error\":\"fact_quota_operation_not_found\"}";
  if (wyl_client_fact_logical_operation_status (management_client,
      "__wr_default", "orders", "batch-1", "missing",
      "0000000000000000000000000000000000000000000000000000000000000000",
      123, "public", 49, &operation_status) != WYRELOG_E_NOT_FOUND
      || operation_status.tenant_id != NULL)
    return wyl_test_normalize_exit_status (295);
  g_autoptr (WylClientFactAppendResult) mutation_result = NULL;
  http.status = 202;
  http.body = "{\"ok\":true,\"committed\":true,\"reconcile\":true,"
      "\"quota_state\":\"reconciling\",\"operation_id\":\"request-1\","
      "\"batch_id\":\"batch-1\",\"inserted\":true,"
      "\"mutation_class\":\"committed\",\"queryable\":false,"
      "\"committed_row_delta\":3,\"logical_byte_delta\":12,"
      "\"engine_generation\":7}";
  const guint8 mutation_payload[] = "value\n1\n";
  if (wyl_client_fact_put_batch (management_client, "__wr_default", "orders",
      "shop", "orders", 1, "batch-1", "request-1", mutation_payload,
      sizeof mutation_payload - 1, 123, "public", 49, &mutation_result)
      != WYRELOG_E_OK
      || !wyl_client_fact_append_result_get_committed (mutation_result)
      || !wyl_client_fact_append_result_get_reconcile (mutation_result)
      || wyl_client_fact_append_result_get_queryable (mutation_result)
      || g_strcmp0 (wyl_client_fact_append_result_get_operation_id
        (mutation_result), "request-1") != 0
      || wyl_client_fact_append_result_get_committed_row_delta
        (mutation_result) != 3
      || wyl_client_fact_append_result_get_logical_byte_delta
        (mutation_result) != 12
      || wyl_client_fact_append_result_get_engine_generation
        (mutation_result) != 7)
    return wyl_test_normalize_exit_status (296);
  http.status = 200;

  /*
   * #1031: with a token the request must carry the bearer AND name the
   * tenant, because the daemon resolves an unnamed request tenant to
   * __wr_default and refuses the mismatch for any other tenant.  Passing
   * only one of the two is a caller error, not a quiet downgrade to the
   * anonymous body.  Restore the stub's status and body first: the cases
   * above deliberately leave it mid-fault, and the checks that follow this
   * section read the same shared stub.
   */
  http.status = 200;
  http.body =
      "{\"status\":\"ready\",\"graphs_total\":0,\"graphs_ready\":0,"
      "\"graphs_degraded\":0,\"graphs_sealed\":0}";
  if (wyl_client_fact_status (management_client, "tok-a", NULL, &fact_status)
      != WYRELOG_E_INVALID
      || wyl_client_fact_status (management_client, NULL, "tenant-a",
      &fact_status) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (287);
  /* The token and the tenant must reach the wire, or the scoping this API
   * promises is silently absent and the caller still gets a 200. */
  if (wyl_client_fact_status (management_client, "tok-a", "tenant-a",
      &fact_status) != WYRELOG_E_OK
      || g_strcmp0 (http.last_path, "/facts/status") != 0
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0
      || g_strcmp0 (http.last_authorization, "Bearer tok-a") != 0)
    return wyl_test_normalize_exit_status (288);
  /* An empty token is dropped by client_fact_attach_auth, so accepting it
   * would send the tenant with no credential and return OK with no graphs --
   * the same silent-zero-graphs shape this API was changed to avoid. */
  if (wyl_client_fact_status (management_client, "", "tenant-a", &fact_status)
      != WYRELOG_E_INVALID
      || wyl_client_fact_status (management_client, "tok-a", "",
      &fact_status) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (289);
  g_auto (WylClientServicePrincipal)
  principal = { 0 };
  g_auto (WylClientServicePrincipalList)
  principal_list = { 0 };
  g_auto (WylClientServiceCredential)
  credential = { 0 };
  g_auto (WylClientServiceCredentialList)
  credential_list = { 0 };
  g_auto (WylClientServiceCredentialHandoffReceipt)
  issue_result = { 0 };

  /* Every typed service-management entry point owns request-boundary reset.
   * Seed a remote failure before each local-invalid call and prove that the
   * stale metadata is cleared without sending another HTTP request. */
  static const LocalInvalidServiceManagementCall local_invalid_calls[] = {
    local_invalid_principal_create,
    local_invalid_principal_list,
    local_invalid_principal_disable,
    local_invalid_credential_get,
    local_invalid_credential_get_for_tenant,
    local_invalid_credential_list,
    local_invalid_credential_list_for_tenant,
    local_invalid_credential_revoke,
    local_invalid_credential_revoke_for_tenant,
    local_invalid_credential_issue,
    local_invalid_credential_rotate,
    local_invalid_credential_rotate_for_tenant,
    local_invalid_operation_reconcile,
    local_invalid_operation_reconcile_for_tenant,
    local_invalid_operation_status,
    local_invalid_operation_status_for_tenant,
    local_invalid_operation_recover,
    local_invalid_operation_recover_for_tenant,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (local_invalid_calls); i++) {
    http.status = 400;
    http.body = "{\"error\":\"stale_remote_failure\"}";
    if (wyl_client_service_principal_list (management_client, 123, "public", 49,
        &principal_list) != WYRELOG_E_INVALID
        || !client_last_response_is (management_client, 400,
        "stale_remote_failure"))
      return wyl_test_normalize_exit_status (546);
    guint request_count = http.request_count;
    if (local_invalid_calls[i] (management_client) != WYRELOG_E_INVALID
        || !client_last_response_is (management_client, 0, NULL)
        || http.request_count != request_count)
      return wyl_test_normalize_exit_status (547);
  }
  http.status = 0;
  http.body_size = 0;

  http.body = "{\"service_principal\":{\"subject_id\":\"svc:alice:worker\","
      "\"display_name\":\"Worker\",\"state\":\"active\","
      "\"generation\":1,\"created_by\":\"admin\","
      "\"created_at_us\":1,\"updated_at_us\":1,"
      "\"disabled_by\":null,\"disabled_at_us\":0}}";
  if (wyl_client_service_principal_create (management_client,
      "svc:alice:worker", "Worker", 123, "public", 49,
      &principal) != WYRELOG_E_OK
      || g_strcmp0 (principal.subject_id, "svc:alice:worker") != 0
      || g_strcmp0 (principal.display_name, "Worker") != 0
      || g_strcmp0 (http.last_path, "/service-principals") != 0
      || g_strcmp0 (http.last_method, "POST") != 0
      || strstr (http.last_body, "svc:alice:worker") == NULL
      || http.last_session_token != NULL
      || g_strcmp0 (http.last_authorization, "Bearer management-access") != 0)
    return wyl_test_normalize_exit_status (232);
  if (!client_last_response_is (management_client, 200, NULL))
    return wyl_test_normalize_exit_status (539);

  /* A remote 400 records both pieces of response metadata. Reusing the same
   * client for a local validation failure must clear them without HTTP. */
  http.status = 400;
  http.body = "{\"error\":\"invalid_service_principal\"}";
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 400,
      "invalid_service_principal"))
    return wyl_test_normalize_exit_status (540);
  g_free (http.last_path);
  http.last_path = g_strdup ("__metadata_local_validation__");
  if (wyl_client_service_principal_create (management_client, "alice", "bad",
      123, "public", 49, &principal) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 0, NULL)
      || g_strcmp0 (http.last_path, "__metadata_local_validation__") != 0)
    return wyl_test_normalize_exit_status (541);

  /* The dedicated service-management parser accepts exactly one top-level,
   * bounded snake_case error string and rejects ambiguous or injectable
   * envelopes while retaining the received status. */
  const gchar *invalid_error_bodies[] = {
    "{\"error\":\"\"}",
    "{\"error\":\"Bad-code\"}",
    "{\"error\":\"bad\\ncode\"}",
    "{\"error\":\"bad\ncode\"}",
    "{\"error\":\"one\",\"error\":\"two\"}",
    "{\"wrapper\":{\"error\":\"nested\"}}",
    "{\"error\":\"one\"} trailing",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_error_bodies); i++) {
    http.body = invalid_error_bodies[i];
    if (wyl_client_service_principal_list (management_client, 123, "public", 49,
        &principal_list) != WYRELOG_E_INVALID
        || !client_last_response_is (management_client, 400, NULL))
      return wyl_test_normalize_exit_status (542);
  }

  static const gchar embedded_nul_error[] = "{\"error\":\"valid\0injected\"}";
  http.body = embedded_nul_error;
  http.body_size = sizeof embedded_nul_error - 1;
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 400, NULL))
    return wyl_test_normalize_exit_status (548);
  http.body_size = 0;

  g_autofree gchar *maximum_error_value = g_strnfill (127, 'x');
  g_autofree gchar *maximum_error_body = g_strdup_printf
        ("{\"error\":\"%s\"}", maximum_error_value);
  http.body = maximum_error_body;
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 400, maximum_error_value))
    return wyl_test_normalize_exit_status (549);

  g_autofree gchar *oversized_error_value = g_strnfill (128, 'x');
  g_autofree gchar *oversized_error_body = g_strdup_printf
        ("{\"error\":\"%s\"}", oversized_error_value);
  http.body = oversized_error_body;
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 400, NULL))
    return wyl_test_normalize_exit_status (542);

  g_autofree gchar *oversized_envelope_padding = g_strnfill (4096, ' ');
  g_autofree gchar *oversized_envelope = g_strdup_printf
        ("{\"error\":\"valid\"}%s", oversized_envelope_padding);
  http.body = oversized_envelope;
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 400, NULL))
    return wyl_test_normalize_exit_status (550);

  http.status = 0;
  http.body = "{\"service_principals\":[{\"subject_id\":\""
      "svc:alice:worker\",\"display_name\":\"Worker\","
      "\"state\":\"active\",\"generation\":1,"
      "\"created_by\":\"admin\",\"created_at_us\":1,"
      "\"updated_at_us\":1,\"disabled_by\":null," "\"disabled_at_us\":0}]}";
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_OK || principal_list.len != 1
      || g_strcmp0 (principal_list.items[0].subject_id,
      "svc:alice:worker") != 0
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path, "/service-principals") != 0
      || !client_last_response_is (management_client, 200, NULL))
    return wyl_test_normalize_exit_status (233);
  guint principal_success_request_count = http.request_count;
  if (wyl_client_service_principal_list (management_client, 123, "public", 49,
      NULL) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 0, NULL)
      || http.request_count != principal_success_request_count)
    return wyl_test_normalize_exit_status (553);
  http.body = "{\"service_principal\":{\"subject_id\":"
      "\"svc:alice:worker\",\"display_name\":\"Worker\","
      "\"state\":\"disabled\",\"generation\":2,"
      "\"created_by\":\"admin\",\"created_at_us\":1,"
      "\"updated_at_us\":2,\"disabled_by\":\"admin\"," "\"disabled_at_us\":2}}";
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "222222222222222222222222222", 123,
      "public", 49, &principal) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_path,
      "/service-principals/svc:alice:worker/disable") != 0
      || g_strcmp0 (http.last_body,
      "{\"version\":\"1\",\"request_id\":"
      "\"222222222222222222222222222\"}") != 0
      || g_strcmp0 (principal.subject_id, "svc:alice:worker") != 0
      || g_strcmp0 (principal.state, "disabled") != 0)
    return wyl_test_normalize_exit_status (234);
  wyl_client_service_principal_clear (&principal);
  guint keyed_disable_request_count = http.request_count;
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "bad", 123, "public", 49,
      &principal) != WYRELOG_E_INVALID
      || http.request_count != keyed_disable_request_count)
    return wyl_test_normalize_exit_status (555);
  if (wyl_client_service_principal_disable (management_client,
      "svc:alice:worker", 123, "public", 49) != WYRELOG_E_OK
      || http.last_body == NULL
      || strstr (http.last_body, "{\"version\":\"1\",\"request_id\":\"")
      != http.last_body)
    return wyl_test_normalize_exit_status (556);
  http.body = "{\"service_principal\":{\"subject_id\":"
      "\"svc:alice:worker\",\"display_name\":\"Worker\","
      "\"state\":\"disabled\",\"generation\":2,"
      "\"created_by\":\"admin\",\"created_at_us\":1,"
      "\"updated_at_us\":2,\"disabled_by\":\"admin\","
      "\"disabled_at_us\":2,\"extra\":true}}";
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "222222222222222222222222223", 123,
      "public", 49, &principal) != WYRELOG_E_INVALID
      || principal.subject_id != NULL)
    return wyl_test_normalize_exit_status (557);
  http.status = 409;
  http.body = "{\"error\":\"service_principal_conflict\"}";
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "222222222222222222222222224", 123,
      "public", 49, &principal) != WYRELOG_E_CONFLICT
      || principal.subject_id != NULL
      || !client_last_response_is (management_client, 409,
      "service_principal_conflict"))
    return wyl_test_normalize_exit_status (558);

  /*
   * #1061: the service-management routes answer 409 from two unrelated
   * sources.  A genuine conflict keeps CONFLICT, above; a sealed tenant
   * reaches the same status through service_management_front_door's
   * set_auth_failure_error and is an authority state, which error.h scopes
   * to POLICY.  Mapping it to CONFLICT told the caller to regenerate its
   * idempotency key and resubmit -- a recovery that cannot work.
   */
  http.status = 409;
  http.body = "{\"error\":\"tenant_sealed\"}";
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "222222222222222222222222226", 123,
      "public", 49, &principal) != WYRELOG_E_POLICY
      || principal.subject_id != NULL
      || !client_last_response_is (management_client, 409, "tenant_sealed"))
    return wyl_test_normalize_exit_status (573);
  http.status = 503;
  http.body = "{\"error\":\"service_principal_failed\"}";
  if (wyl_client_service_principal_disable_with_request_id (management_client,
      "svc:alice:worker", "222222222222222222222222225", 123,
      "public", 49, &principal) != WYRELOG_E_IO
      || principal.subject_id != NULL
      || !client_last_response_is (management_client, 503,
      "service_principal_failed"))
    return wyl_test_normalize_exit_status (559);
  http.status = 0;
  if (wyl_client_service_principal_create (management_client, "alice", "bad",
      123, "public", 49, &principal) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (235);
  const gchar *mock_credential_json =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:alice:worker\","
      "\"tenant_id\":\"__wr_default\",\"generation\":1,\"state\":\"revoked\","
      "\"created_by\":\"alice\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":3,\"last_used_at_us\":-1,\"revoked_by\":\"alice\","
      "\"revoked_at_us\":4,\"rotated_from_id\":null}}";
  http.body = mock_credential_json;
  if (wyl_client_service_credential_get_for_tenant (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "tenant-a", 123, "public", 49,
      &credential) != WYRELOG_E_OK
      || g_strcmp0 (http.last_path,
      "/service-credentials/wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0
      || g_strcmp0 (credential.state, "revoked") != 0
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0
      || !client_last_response_is (management_client, 200, NULL))
    return wyl_test_normalize_exit_status (236);

  http.status = 401;
  http.body = "{\"error\":\"service_credential_auth_required\"}";
  if (wyl_client_service_credential_get (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", 123, "public", 49,
      &credential) != WYRELOG_E_AUTH
      || !client_last_response_is (management_client, 401,
      "service_credential_auth_required"))
    return wyl_test_normalize_exit_status (543);
  http.status = 0;
  http.body = "{\"service_credentials\":[]}";
  if (wyl_client_service_credential_list_for_tenant (management_client,
      "svc:alice:worker", "tenant-a", 123, "public", 49,
      &credential_list) != WYRELOG_E_OK
      || credential_list.len != 0
      || g_strcmp0 (http.last_path,
      "/service-principals/svc:alice:worker/credentials") != 0
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0
      || !client_last_response_is (management_client, 200, NULL))
    return wyl_test_normalize_exit_status (237);
  guint credential_success_request_count = http.request_count;
  if (wyl_client_service_credential_get (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", 123, "public", 49,
      NULL) != WYRELOG_E_INVALID
      || !client_last_response_is (management_client, 0, NULL)
      || http.request_count != credential_success_request_count)
    return wyl_test_normalize_exit_status (554);
  http.body = mock_credential_json;
  if (wyl_client_service_credential_revoke_for_tenant (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
      "222222222222222222222222222", "tenant-a", 123, "public", 49,
      &credential) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "DELETE") != 0
      || strstr (http.last_body, "request_id") == NULL
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0)
    return wyl_test_normalize_exit_status (238);
  if (wyl_client_service_credential_revoke_for_tenant (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "bad", "tenant-a", 123,
      "public", 49, &credential) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (239);
  WylClientServiceCredentialIssueRequest issue_request = {
    .subject_id = "svc:alice:worker",
    .tenant_id = "tenant-a",
    .request_id = "333333333333333333333333333",
    .destination = "issue.json",
    .expires_at_us = 4102444800000000,
  };
  http.body =
      "{\"state\":\"terminal\",\"request_id\":\"333333333333333333333333333\","
      "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\",\"generation\":1,"
      "\"destination\":\"issue.json\","
      "\"publication_receipt_id\":\"wpr_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"delivered\":true}";
  wyrelog_error_t issue_rc = wyl_client_service_credential_issue
        (management_client, &issue_request, 123, "public", 49, &issue_result);
  if (issue_rc != WYRELOG_E_OK
      || g_strcmp0 (issue_result.state, "terminal") != 0
      || g_strcmp0 (issue_result.credential_id,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0
      || issue_result.generation != 1 || !issue_result.delivered) {
    return wyl_test_normalize_exit_status (240);
  }
  /*
   * Regression guard: the request body must carry a QUOTED expires_at_us
   * (colon-quote) and a destination field.  Asserting the bare substring
   * "expires_at_us" would be vacuous because the pre-fix builder already
   * emitted that token as a bare number.
   */
  if (strstr (http.last_body, "\"expires_at_us\":\"") == NULL
      || strstr (http.last_body, "\"destination\"") == NULL
      || strstr (http.last_body, "\"destination\":\"issue.json\"") == NULL
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0)
    return wyl_test_normalize_exit_status (244);
  http.status = 409;
  if (wyl_client_service_credential_issue (management_client, &issue_request,
      123, "public", 49, &issue_result) != WYRELOG_E_CONFLICT
      || issue_result.state != NULL || issue_result.credential_id != NULL)
    return wyl_test_normalize_exit_status (242);
  http.status = 0;
  issue_request.tenant_id = "bad tenant";
  if (wyl_client_service_credential_issue (management_client, &issue_request,
      123, "public", 49, &issue_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (243);
  issue_request.tenant_id = "tenant-a";
  /* A missing destination must fail closed before any request is sent. */
  issue_request.destination = NULL;
  if (wyl_client_service_credential_issue (management_client, &issue_request,
      123, "public", 49, &issue_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (245);
  issue_request.destination = "issue.json";
  http.body =
      "{\"state\":\"terminal\",\"request_id\":\"444444444444444444444444444\","
      "\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\",\"generation\":2,"
      "\"destination\":\"issue.json\","
      "\"publication_receipt_id\":\"wpr_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"delivered\":true}";
  if (wyl_client_service_credential_rotate_for_tenant (management_client,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
      "444444444444444444444444444", "issue.json", 4102444800000000,
      "tenant-a", 123, "public", 49, &issue_result) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_path,
      "/service-credentials/wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv/rotate") != 0
      || strstr (http.last_body, "\"expires_at_us\":\"") == NULL
      || strstr (http.last_body, "\"destination\":\"issue.json\"") == NULL
      || g_strcmp0 (http.last_tenant, "tenant-a") != 0
      || issue_result.generation != 2 || !issue_result.delivered
      || g_strcmp0 (issue_result.credential_id,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0)
    return wyl_test_normalize_exit_status (241);
  if (wyl_client_tenant_select (local_client, "unknown") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (90);
  /*
   * Tenant selection must match the tenant carried by the current
   * client credentials. A distinct literal fails closed and leaves
   * the existing binding unchanged.
   */
  if (wyl_client_tenant_select (local_client, "evil-co") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (96);
  if (wyl_client_tenant_select (local_client, "__wr_default") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (91);
  http.body = "{\"ok\":true}";
  if (wyl_client_policy_permission_grant (local_client, "fallback target",
      "site.policy.read", "tenant/fallback", 123, "public", 49)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (170);
  if (g_strcmp0 (http.last_session_token, "session-1") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_authorization != NULL)
    return wyl_test_normalize_exit_status (171);
  g_autoptr (WylAuditIter) fallback_guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
      "public", 69, &fallback_guarded_audit_iter) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (173);
  g_autofree gchar *fallback_guarded_audit_uri =
      wyl_audit_iter_dup_request_uri (fallback_guarded_audit_iter);
  if (strstr (fallback_guarded_audit_uri, "tenant=__wr_default") == NULL ||
      strstr (fallback_guarded_audit_uri, "session_token=session-1") == NULL)
    return wyl_test_normalize_exit_status (174);
  g_autoptr (SoupMessage) fallback_guarded_audit_message =
      wyl_audit_iter_new_request_message (fallback_guarded_audit_iter);
  if (soup_message_headers_get_one (soup_message_get_request_headers
        (fallback_guarded_audit_message), "Authorization") != NULL)
    return wyl_test_normalize_exit_status (175);

  http.body = "{\"session_token\":\"session-2\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-2\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (147);
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return wyl_test_normalize_exit_status (148);
  if (g_strcmp0 (http.last_path, "/auth/login") != 0)
    return wyl_test_normalize_exit_status (149);
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return wyl_test_normalize_exit_status (150);
  if (g_strcmp0 (http.last_skip_mfa, "true") != 0)
    return wyl_test_normalize_exit_status (151);
  g_clear_pointer (&client_session_token, g_free);
  g_clear_pointer (&client_access_token, g_free);
  g_clear_pointer (&client_username, g_free);
  g_clear_pointer (&client_tenant, g_free);
  g_clear_pointer (&client_principal_state, g_free);
  g_clear_pointer (&client_session_state, g_free);
  client_session_token = wyl_client_dup_session_token (local_client);
  client_access_token = wyl_client_dup_access_token (local_client);
  client_username = wyl_client_dup_username (local_client);
  client_tenant = wyl_client_dup_tenant (local_client);
  client_principal_state = wyl_client_dup_principal_state (local_client);
  client_session_state = wyl_client_dup_session_state (local_client);
  if (g_strcmp0 (client_session_token, "session-2") != 0 ||
      g_strcmp0 (client_access_token, "access-2") != 0 ||
      g_strcmp0 (client_username, "alice") != 0 ||
      g_strcmp0 (client_tenant, "__wr_default") != 0 ||
      g_strcmp0 (client_principal_state, "authenticated") != 0 ||
      g_strcmp0 (client_session_state, "active") != 0)
    return wyl_test_normalize_exit_status (152);

  g_auto (WylClientServiceCredentialOperationReconcileRequest)
  reconcile_request = { 0 };
  g_auto (WylClientServiceCredentialOperationReconcileResult)
  reconcile_result = { 0 };
  reconcile_request.operation =
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ISSUE;
  reconcile_request.request_id = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1";
  reconcile_request.subject_id = "svc:client:reconcile";
  reconcile_request.tenant_id = "tenant-a";

  http.status = 403;
  http.body = "{\"error\":\"service_credential_reconcile_denied\"}";
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_POLICY
      || !client_last_response_is (local_client, 403,
      "service_credential_reconcile_denied"))
    return wyl_test_normalize_exit_status (544);
  http.status = 0;

  const gchar *reconcile_issue_body =
      "{\"version\":1,\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"issue\",\"target\":{\"subject\":\"svc:client:reconcile\","
      "\"tenant\":\"tenant-a\"}}";
  const gchar *reconcile_issue_response =
      "{\"version\":1,\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"issue\",\"target\":{\"subject\":\"svc:client:reconcile\","
      "\"tenant\":\"tenant-a\"},\"status\":\"committed\","
      "\"credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"generation\":7}";
  if (wyl_client_service_credential_operation_reconcile (local_client,
      &reconcile_request, &reconcile_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (281);
  http.body = reconcile_issue_response;
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (210);
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_COMMITTED ||
      g_strcmp0 (reconcile_result.credential_id,
      "wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
      reconcile_result.generation != 7)
    return wyl_test_normalize_exit_status (211);
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path,
      "/service-credential-operations/reconcile") != 0 ||
      g_strcmp0 (http.last_tenant, "tenant-a") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "123") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "public") != 0 ||
      g_strcmp0 (http.last_guard_risk, "49") != 0 ||
      g_strcmp0 (http.last_body, reconcile_issue_body) != 0 ||
      !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (212);
  wyl_client_service_credential_operation_reconcile_result_clear
    (&reconcile_result);

  /* Shape alone is insufficient: this is 27 alphanumeric characters but is
   * outside the canonical KSUID range. After the remote failure and success,
   * reconcile must reject it locally, clear metadata, and avoid HTTP. */
  guint reconcile_success_request_count = http.request_count;
  reconcile_request.request_id = "abcdefghijklmnopqrstuvwxyz0";
  if (wyl_client_service_credential_operation_reconcile (local_client,
      &reconcile_request, &reconcile_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (209);
  if (http.request_count != reconcile_success_request_count
      || !client_last_response_is (local_client, 0, NULL))
    return wyl_test_normalize_exit_status (208);
  reconcile_request.request_id = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1";

  reconcile_request.operation =
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ROTATE;
  reconcile_request.request_id = "BCDEFGHIJKLMNOPQRSTUVWXYZ12";
  reconcile_request.subject_id = NULL;
  reconcile_request.tenant_id = NULL;
  reconcile_request.old_credential_id = "wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1";

  const gchar *reconcile_rotate_body =
      "{\"version\":1,\"request_id\":\"BCDEFGHIJKLMNOPQRSTUVWXYZ12\","
      "\"operation\":\"rotate\",\"target\":{"
      "\"old_credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\"}}";
  const gchar *reconcile_rotate_response =
      "{\"version\":1,\"request_id\":\"BCDEFGHIJKLMNOPQRSTUVWXYZ12\","
      "\"operation\":\"rotate\",\"target\":{"
      "\"old_credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\"},"
      "\"status\":\"not_committed_terminal\"}";
  http.body = reconcile_rotate_response;
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (213);
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_NOT_COMMITTED_TERMINAL
      || reconcile_result.credential_id != NULL
      || reconcile_result.generation != 0)
    return wyl_test_normalize_exit_status (214);
  if (g_strcmp0 (http.last_body, reconcile_rotate_body) != 0)
    return wyl_test_normalize_exit_status (215);
  wyl_client_service_credential_operation_reconcile_result_clear
    (&reconcile_result);

  const gchar *reconcile_conflict_body =
      "{\"error\":\"operation_request_conflict\"}";
  http.status = 409;
  http.body = reconcile_conflict_body;
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (216);
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_OPERATION_REQUEST_CONFLICT
      || reconcile_result.credential_id != NULL
      || reconcile_result.generation != 0
      || !client_last_response_is (local_client, 409,
      "operation_request_conflict"))
    return wyl_test_normalize_exit_status (217);
  if (g_strcmp0 (http.last_body, reconcile_rotate_body) != 0 ||
      http.status != 409)
    return wyl_test_normalize_exit_status (218);
  http.status = 0;
  wyl_client_service_credential_operation_reconcile_result_clear
    (&reconcile_result);

  /*
   * #1073: reconcile had no 404 or 503 arm, so both fell through to
   * WYRELOG_E_IO.  503 is the one status the daemon emits to mean "retry
   * later" -- wyl_daemon_policy_write_acquire answers it on WYRELOG_E_BUSY --
   * and WYRELOG_E_IO is its documented opposite, so a caller that should back
   * off was told it had hit a permanent transport fault.  Both siblings on
   * this route family already map these.
   */
  http.status = 503;
  http.body = "{\"error\":\"service_credential_operation_reconcile_unavailable\"}";
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_BUSY)
    return wyl_test_normalize_exit_status (318);
  http.status = 404;
  http.body = "{\"error\":\"service_credential_not_found\"}";
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_NOT_FOUND)
    return wyl_test_normalize_exit_status (319);
  http.status = 0;
  wyl_client_service_credential_operation_reconcile_result_clear
    (&reconcile_result);

  http.body = "{\"version\":1,\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"issue\",\"target\":{\"subject\":\"svc:client:reconcile\","
      "\"tenant\":\"tenant-a\",\"extra\":\"x\"}}";
  if (wyl_client_service_credential_operation_reconcile_for_tenant
        (local_client, "tenant-a", &reconcile_request, 123, "public", 49,
      &reconcile_result) != WYRELOG_E_IO
      || !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (219);
  if (reconcile_result.kind != 0 || reconcile_result.credential_id != NULL ||
      reconcile_result.generation != 0)
    return wyl_test_normalize_exit_status (220);
  http.body = reconcile_issue_response;

  /* Durable operation status-list and recover client APIs. */
  g_auto (WylClientServiceCredentialOperationStatusList) status_list = { 0 };
  if (wyl_client_service_credential_operation_status_list (NULL, 123, "public",
      69, &status_list) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (250);
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (251);

  /* Invalid guard context is rejected locally with no request sent. */
  g_free (http.last_path);
  http.last_path = g_strdup ("__unset__");
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 101, &status_list) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (272);
  if (wyl_client_service_credential_operation_status_list (local_client, -1,
      "public", 69, &status_list) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (273);
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "not-a-loc-class", 69, &status_list) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (274);
  if (g_strcmp0 (http.last_path, "__unset__") != 0)
    return wyl_test_normalize_exit_status (275);

  http.status = 0;
  http.body = "{\"version\":1,\"operations\":[]}";
  if (wyl_client_service_credential_operation_status_list_for_tenant
        (local_client, "tenant-a", 123, "public", 69,
      &status_list) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (252);
  if (status_list.n_entries != 0 || status_list.entries != NULL)
    return wyl_test_normalize_exit_status (253);
  if (g_strcmp0 (http.last_method, "GET") != 0 ||
      g_strcmp0 (http.last_path, "/service-credential-operations") != 0 ||
      g_strcmp0 (http.last_tenant, "tenant-a") != 0 ||
      http.last_session_token != NULL || http.last_body != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "123") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "public") != 0 ||
      g_strcmp0 (http.last_guard_risk, "69") != 0 ||
      !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (254);

  http.body =
      "{\"version\":1,\"operations\":["
      "{\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"issue\",\"state\":\"prepared\","
      "\"destination\":\"issue.json\",\"successor_credential_id\":null,"
      "\"expected_generation\":0,\"successor_generation\":0,"
      "\"created_at_us\":1000,\"updated_at_us\":2000,"
      "\"expires_at_us\":3000},"
      "{\"request_id\":\"BCDEFGHIJKLMNOPQRSTUVWXYZ12\","
      "\"operation\":\"rotate\",\"state\":\"server_committed\","
      "\"destination\":\"rotate.json\","
      "\"successor_credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"expected_generation\":7,\"successor_generation\":8,"
      "\"created_at_us\":1100,\"updated_at_us\":2100,"
      "\"expires_at_us\":3100}]}";
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, &status_list) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (255);
  if (status_list.n_entries != 2)
    return wyl_test_normalize_exit_status (318);
  {
    const WylClientServiceCredentialOperationStatusEntry *e0 =
        &status_list.entries[0];
    const WylClientServiceCredentialOperationStatusEntry *e1 =
        &status_list.entries[1];
    if (g_strcmp0 (e0->request_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
        e0->operation != WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ISSUE
        || g_strcmp0 (e0->state, "prepared") != 0 ||
        g_strcmp0 (e0->destination, "issue.json") != 0 ||
        e0->successor_credential_id != NULL ||
        e0->expected_generation != 0 || e0->successor_generation != 0 ||
        e0->created_at_us != 1000 || e0->updated_at_us != 2000 ||
        e0->expires_at_us != 3000 || e0->recovery != NULL)
      return wyl_test_normalize_exit_status (257);
    if (g_strcmp0 (e1->request_id, "BCDEFGHIJKLMNOPQRSTUVWXYZ12") != 0 ||
        e1->operation !=
        WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ROTATE ||
        g_strcmp0 (e1->state, "server_committed") != 0 ||
        g_strcmp0 (e1->destination, "rotate.json") != 0 ||
        g_strcmp0 (e1->successor_credential_id,
        "wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
        e1->expected_generation != 7 || e1->successor_generation != 8 ||
        e1->created_at_us != 1100 || e1->updated_at_us != 2100 ||
        e1->expires_at_us != 3100 || e1->recovery != NULL)
      return wyl_test_normalize_exit_status (258);
  }

  /* A malformed entry (unknown operation kind) fails closed as WYRELOG_E_IO
   * and leaves the caller's list empty. */
  http.body =
      "{\"version\":1,\"operations\":["
      "{\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"delete\",\"state\":\"prepared\","
      "\"destination\":\"issue.json\",\"successor_credential_id\":null,"
      "\"expected_generation\":0,\"successor_generation\":0,"
      "\"created_at_us\":1000,\"updated_at_us\":2000,"
      "\"expires_at_us\":3000}]}";
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, &status_list) != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (259);
  if (status_list.n_entries != 0 || status_list.entries != NULL)
    return wyl_test_normalize_exit_status (260);

  /* Non-200 status maps like reconcile: 400 -> INVALID. */
  http.status = 400;
  http.body = "{\"error\":\"invalid_service_credential_operation_status\"}";
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, &status_list) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (261);
  if (status_list.n_entries != 0 || status_list.entries != NULL
      || !client_last_response_is (local_client, 400,
      "invalid_service_credential_operation_status"))
    return wyl_test_normalize_exit_status (262);

  http.status = 503;
  http.body = "{\"error\":\"service_credential_operation_busy\"}";
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, &status_list) != WYRELOG_E_BUSY
      || !client_last_response_is (local_client, 503,
      "service_credential_operation_busy"))
    return wyl_test_normalize_exit_status (545);
  http.status = 0;
  http.body = "{\"version\":1,\"operations\":[]}";
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, &status_list) != WYRELOG_E_OK
      || !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (555);
  guint status_success_request_count = http.request_count;
  if (wyl_client_service_credential_operation_status_list (local_client, 123,
      "public", 69, NULL) != WYRELOG_E_INVALID
      || !client_last_response_is (local_client, 0, NULL)
      || http.request_count != status_success_request_count)
    return wyl_test_normalize_exit_status (556);

  g_auto (WylClientServiceCredentialOperationStatusEntry) recovered = { 0 };
  if (wyl_client_service_credential_operation_recover (NULL,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 69,
      &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (263);
  if (wyl_client_service_credential_operation_recover (local_client, NULL,
      123, "public", 69, &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (264);
  if (wyl_client_service_credential_operation_recover (local_client,
      "not-canonical", 123, "public", 69, &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (265);
  /* A 27-character alphanumeric non-KSUID must also fail before HTTP. */
  g_free (http.last_path);
  http.last_path = g_strdup ("__unset__");
  if (wyl_client_service_credential_operation_recover (local_client,
      "abcdefghijklmnopqrstuvwxyz0", 123, "public", 69,
      &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (279);
  if (g_strcmp0 (http.last_path, "__unset__") != 0)
    return wyl_test_normalize_exit_status (280);
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 69,
      NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (266);

  /* Invalid guard context is rejected locally with no request sent. */
  g_free (http.last_path);
  http.last_path = g_strdup ("__unset__");
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 101,
      &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (276);
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "not-a-loc-class", 69,
      &recovered) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (277);
  if (g_strcmp0 (http.last_path, "__unset__") != 0)
    return wyl_test_normalize_exit_status (278);

  http.body =
      "{\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"rotate\",\"state\":\"server_committed\","
      "\"destination\":\"rotate.json\","
      "\"successor_credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"expected_generation\":1,\"successor_generation\":2,"
      "\"created_at_us\":10,\"updated_at_us\":20,\"expires_at_us\":30,"
      "\"recovery\":\"server_committed\"}";
  if (wyl_client_service_credential_operation_recover_for_tenant
        (local_client, "tenant-a", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public",
      69, &recovered) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (267);
  if (g_strcmp0 (recovered.request_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
      recovered.operation !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ROTATE ||
      g_strcmp0 (recovered.state, "server_committed") != 0 ||
      g_strcmp0 (recovered.destination, "rotate.json") != 0 ||
      g_strcmp0 (recovered.successor_credential_id,
      "wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
      recovered.expected_generation != 1 ||
      recovered.successor_generation != 2 || recovered.created_at_us != 10 ||
      recovered.updated_at_us != 20 || recovered.expires_at_us != 30 ||
      g_strcmp0 (recovered.recovery, "server_committed") != 0)
    return wyl_test_normalize_exit_status (268);
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path,
      "/service-credential-operations/recover") != 0 ||
      g_strcmp0 (http.last_tenant, "tenant-a") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_body,
      "{\"version\":\"1\",\"request_id\":"
      "\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\"}") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "123") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "public") != 0 ||
      g_strcmp0 (http.last_guard_risk, "69") != 0 ||
      !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (269);
  wyl_client_service_credential_operation_status_entry_clear (&recovered);

  /* An unknown or cross-tenant id maps to 404 -> NOT_FOUND. */
  http.status = 404;
  http.body = "{\"error\":\"service_credential_operation_recover_not_found\"}";
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 69,
      &recovered) != WYRELOG_E_NOT_FOUND)
    return wyl_test_normalize_exit_status (270);
  if (recovered.request_id != NULL || recovered.recovery != NULL
      || !client_last_response_is (local_client, 404,
      "service_credential_operation_recover_not_found"))
    return wyl_test_normalize_exit_status (271);
  http.status = 0;
  http.body =
      "{\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"rotate\",\"state\":\"server_committed\","
      "\"destination\":\"rotate.json\","
      "\"successor_credential_id\":\"wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"expected_generation\":1,\"successor_generation\":2,"
      "\"created_at_us\":10,\"updated_at_us\":20,\"expires_at_us\":30,"
      "\"recovery\":\"server_committed\"}";
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 69,
      &recovered) != WYRELOG_E_OK
      || !client_last_response_is (local_client, 200, NULL))
    return wyl_test_normalize_exit_status (557);
  guint recover_success_request_count = http.request_count;
  if (wyl_client_service_credential_operation_recover (local_client,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ1", 123, "public", 69,
      NULL) != WYRELOG_E_INVALID
      || !client_last_response_is (local_client, 0, NULL)
      || http.request_count != recover_success_request_count)
    return wyl_test_normalize_exit_status (558);

  http.body = reconcile_issue_response;
  if (wyl_client_set_bearer_credentials (NULL, "access-ctl",
      "__wr_default") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (192);
  if (wyl_client_set_bearer_credentials (local_client, NULL,
      "__wr_default") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (193);
  if (wyl_client_set_bearer_credentials (local_client, "",
      "__wr_default") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (194);
  if (wyl_client_set_bearer_credentials (local_client, "access ctl",
      "__wr_default") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (195);
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
      NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (196);
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
      "") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (197);
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
      "__wr default") != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (198);

  if (wyl_client_policy_permission_grant (NULL, "target", "read", "scope",
      123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (511);
  if (wyl_client_policy_permission_grant (local_client, NULL, "read",
      "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (575);
  if (wyl_client_policy_permission_grant (local_client, "target", NULL,
      "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (513);
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      NULL, 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (514);
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", -1, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (515);
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "unknown", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (516);
  if (wyl_client_policy_permission_transition (NULL, "target", "read",
      "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (529);
  if (wyl_client_policy_permission_transition (local_client, NULL, "read",
      "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (530);
  if (wyl_client_policy_permission_transition (local_client, "target", NULL,
      "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (531);
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
      NULL, "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (532);
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
      "scope", NULL, 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (533);
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
      "scope", "", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (534);
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
      "scope", "grant", -1, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (535);
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
      "scope", "grant", 123, "unknown", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (536);

  http.body = "{\"ok\":true}";
  if (wyl_client_policy_permission_grant (local_client, "target user",
      "site.policy.read", "tenant/a", 123, "public", 49) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (517);
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path, "/policy/permissions/grant") != 0 ||
      g_strcmp0 (http.last_subject, "target user") != 0 ||
      g_strcmp0 (http.last_perm, "site.policy.read") != 0 ||
      g_strcmp0 (http.last_scope, "tenant/a") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "123") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "public") != 0 ||
      g_strcmp0 (http.last_guard_risk, "49") != 0)
    return wyl_test_normalize_exit_status (518);
  if (wyl_client_policy_permission_revoke (local_client, "target user",
      "site.policy.read", "tenant/a", 123, "public", 49) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (519);
  if (g_strcmp0 (http.last_path, "/policy/permissions/revoke") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return wyl_test_normalize_exit_status (520);
  if (wyl_client_policy_permission_transition (local_client, "target user",
      "site.policy.read", "tenant/a", "grant", 123, "public", 49)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (537);
  if (g_strcmp0 (http.last_path, "/policy/permissions/transition") != 0 ||
      g_strcmp0 (http.last_subject, "target user") != 0 ||
      g_strcmp0 (http.last_perm, "site.policy.read") != 0 ||
      g_strcmp0 (http.last_scope, "tenant/a") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      g_strcmp0 (http.last_event, "grant") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "123") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "public") != 0 ||
      g_strcmp0 (http.last_guard_risk, "49") != 0)
    return wyl_test_normalize_exit_status (538);
  if (wyl_client_policy_role_grant (local_client, "target user",
      "site.reader", "tenant/b", 123, "public", 29) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (521);
  if (g_strcmp0 (http.last_path, "/policy/roles/grant") != 0 ||
      g_strcmp0 (http.last_role, "site.reader") != 0 ||
      g_strcmp0 (http.last_scope, "tenant/b") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_risk, "29") != 0)
    return wyl_test_normalize_exit_status (522);
  if (wyl_client_policy_role_revoke (local_client, "target user",
      "site.reader", "tenant/b", 123, "public", 29) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (523);
  if (g_strcmp0 (http.last_path, "/policy/roles/revoke") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return wyl_test_normalize_exit_status (524);
  http.status = 400;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (525);
  http.status = 401;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_AUTH)
    return wyl_test_normalize_exit_status (526);
  http.status = 403;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_POLICY)
    return wyl_test_normalize_exit_status (527);
  /*
   * #1044: a sealed tenant answers 409 on these routes, and it used to fall
   * through to WYRELOG_E_IO -- a transport code, the class a caller retries,
   * on a condition that never clears.  POLICY, not CONFLICT: error.h scopes
   * CONFLICT to an idempotency-key collision and excludes authority
   * failures, and the daemon's only 409 here is tenant_sealed.  The body is
   * set for realism but not asserted: the mock supplies it, so checking it
   * would only confirm the fixture.
   *
   * Codes 64 and 65 are free in the modulo-256 space, not merely as
   * literals: this binary's exit status is truncated to 8 bits, so 562 would
   * have surfaced as 50 and been indistinguishable from the assertion that
   * already returns 50.
   */
  http.status = 409;
  http.body = "{\"error\":\"tenant_sealed\"}";
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_POLICY)
    return wyl_test_normalize_exit_status (64);
  /* The role path shares the helper; this guards a future split of it. */
  if (wyl_client_policy_role_grant (local_client, "target", "reader",
      "scope", 123, "public", 49) != WYRELOG_E_POLICY)
    return wyl_test_normalize_exit_status (65);
  http.body = NULL;
  http.status = 500;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
      "scope", 123, "public", 49) != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (528);
  http.status = 0;

  g_autoptr (WylAuditIter) guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client,
      "decision=deny", 123, "public", 69, &guarded_audit_iter)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (154);
  g_autoptr (WylAuditIter) invalid_guard_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
      "unknown", 69, &invalid_guard_iter) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (161);

  http.body = "{\"session_token\":\"session-3\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-3\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (162);

  g_autofree gchar *guarded_audit_uri =
      wyl_audit_iter_dup_request_uri (guarded_audit_iter);
  if (strstr (guarded_audit_uri, "/audit/events?") == NULL ||
      strstr (guarded_audit_uri, "tenant=__wr_default") == NULL ||
      strstr (guarded_audit_uri, "session_token=") != NULL ||
      strstr (guarded_audit_uri, "guard_timestamp=123") == NULL ||
      strstr (guarded_audit_uri, "guard_loc_class=public") == NULL ||
      strstr (guarded_audit_uri, "guard_risk=69") == NULL ||
      strstr (guarded_audit_uri, "filter=decision%3Ddeny") == NULL)
    return wyl_test_normalize_exit_status (155);
  g_autoptr (SoupMessage) guarded_audit_message =
      wyl_audit_iter_new_request_message (guarded_audit_iter);
  if (wyl_client_send_message (local_client, guarded_audit_message, &body) !=
      WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (156);
  if (http.last_session_token != NULL)
    return wyl_test_normalize_exit_status (157);
  if (g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return wyl_test_normalize_exit_status (172);
  if (g_strcmp0 (http.last_guard_timestamp, "123") != 0)
    return wyl_test_normalize_exit_status (158);
  if (g_strcmp0 (http.last_guard_loc_class, "public") != 0)
    return wyl_test_normalize_exit_status (159);
  if (g_strcmp0 (http.last_guard_risk, "69") != 0)
    return wyl_test_normalize_exit_status (160);

  if (wyl_client_mfa_verify (local_client, NULL) == WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (140);
  if (wyl_client_mfa_verify (local_client, "") == WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (141);
  if (wyl_client_mfa_verify (local_client, "123456") == WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (142);

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (163);

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":null}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (165);

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-a\","
      "\"access_token\":\"access-b\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (164);

  http.body = "{\"session_token\":\"session-1\"}";
  if (wyl_client_login (local_client, "alice", NULL) != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (47);
  g_clear_pointer (&client_session_token, g_free);
  client_session_token = wyl_client_dup_session_token (local_client);
  if (client_session_token != NULL)
    return wyl_test_normalize_exit_status (139);
  http.body = "[]";

  gint decision = -1;
  if (wyl_client_decide (NULL, "alice", "read", "doc/42", &decision)
      != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (51);
  if (wyl_client_decide (local_client, NULL, "read", "doc/42", &decision)
      != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (52);
  if (wyl_client_decide (local_client, "alice", "read", "doc/42", NULL)
      != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (53);
  g_autoptr (WylClientDecision) decision_result = NULL;
  if (wyl_client_decide_ex (local_client, "alice", "read", "doc/42", NULL)
      != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (177);
  if (wyl_client_decision_get_decision (NULL) != WYL_DECISION_DENY ||
      wyl_client_decision_get_deny_reason (NULL) != NULL ||
      wyl_client_decision_get_deny_origin (NULL) != NULL)
    return wyl_test_normalize_exit_status (178);

  http.body = "{\"session_token\":\"session-4\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-4\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (92);

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide (local_client, "alice", "wr.audit.read",
      "doc/42", &decision) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (54);
  if (decision != WYL_DECISION_ALLOW)
    return wyl_test_normalize_exit_status (55);
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return wyl_test_normalize_exit_status (56);
  if (g_strcmp0 (http.last_path, "/decide") != 0)
    return wyl_test_normalize_exit_status (57);
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return wyl_test_normalize_exit_status (58);
  if (g_strcmp0 (http.last_perm, "wr.audit.read") != 0)
    return wyl_test_normalize_exit_status (59);
  if (g_strcmp0 (http.last_session_token, "doc/42") != 0)
    return wyl_test_normalize_exit_status (60);
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return wyl_test_normalize_exit_status (93);
  if (g_strcmp0 (http.last_authorization, "Bearer access-4") != 0)
    return wyl_test_normalize_exit_status (176);
  if (http.last_guard_timestamp != NULL || http.last_guard_loc_class != NULL ||
      http.last_guard_risk != NULL)
    return wyl_test_normalize_exit_status (69);
  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_ex (local_client, "alice", "wr.audit.read",
      "doc/42", &decision_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (179);
  if (decision_result == NULL ||
      wyl_client_decision_get_decision (decision_result) != WYL_DECISION_ALLOW)
    return wyl_test_normalize_exit_status (180);
  if (wyl_client_decision_get_deny_reason (decision_result) != NULL ||
      wyl_client_decision_get_deny_origin (decision_result) != NULL)
    return wyl_test_normalize_exit_status (181);
  if (wyl_client_decide_ex (local_client, NULL, "wr.audit.read", "doc/42",
      &decision_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (186);
  if (decision_result != NULL)
    return wyl_test_normalize_exit_status (187);
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  if (wyl_client_decide_with_guard_context (NULL, "alice", "read", "doc/42",
      123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (70);
  if (wyl_client_decide_with_guard_context (local_client, NULL, "read",
      "doc/42", 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (71);
  if (wyl_client_decide_with_guard_context (local_client, "alice", NULL,
      "doc/42", 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (72);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      NULL, 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (73);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      "doc/42", 123, NULL, 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (74);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      "doc/42", -1, "public", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (75);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      "doc/42", 123, "public", 101, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (76);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      "doc/42", 123, "unknown", 69, &decision) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (77);
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
      "doc/42", 123, "public", 69, NULL) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (78);

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_with_guard_context (local_client, "alice",
      "wr.audit.read", "doc/42", 123, "semi_trusted", 69,
      &decision) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (79);
  if (decision != WYL_DECISION_ALLOW)
    return wyl_test_normalize_exit_status (80);
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return wyl_test_normalize_exit_status (81);
  if (g_strcmp0 (http.last_path, "/decide") != 0)
    return wyl_test_normalize_exit_status (82);
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return wyl_test_normalize_exit_status (94);
  if (g_strcmp0 (http.last_authorization, "Bearer access-4") != 0)
    return wyl_test_normalize_exit_status (95);
  if (g_strcmp0 (http.last_guard_timestamp, "123") != 0)
    return wyl_test_normalize_exit_status (83);
  if (g_strcmp0 (http.last_guard_loc_class, "semi_trusted") != 0)
    return wyl_test_normalize_exit_status (84);
  if (g_strcmp0 (http.last_guard_risk, "69") != 0)
    return wyl_test_normalize_exit_status (85);
  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_with_guard_context_ex (local_client, "alice",
      "wr.audit.read", "doc/42", 123, "semi_trusted", 69,
      &decision_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (188);
  if (decision_result == NULL)
    return wyl_test_normalize_exit_status (189);
  g_clear_pointer (&decision_result, wyl_client_decision_free);
  if (wyl_client_decide_with_guard_context_ex (local_client, "alice",
      "wr.audit.read", "doc/42", 123, NULL, 69,
      &decision_result) != WYRELOG_E_INVALID)
    return wyl_test_normalize_exit_status (190);
  if (decision_result != NULL)
    return wyl_test_normalize_exit_status (191);

  http.body = "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (86);
  if (decision != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (87);
  http.body = "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}";
  if (wyl_client_decide_ex (local_client, "bob", "write", "doc/43",
      &decision_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (182);
  if (decision_result == NULL ||
      wyl_client_decision_get_decision (decision_result) != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (183);
  if (g_strcmp0 (wyl_client_decision_get_deny_reason (decision_result),
      "missing_grant") != 0 ||
      g_strcmp0 (wyl_client_decision_get_deny_origin (decision_result),
      "policy") != 0)
    return wyl_test_normalize_exit_status (184);
  g_autofree gchar *dup_deny_reason =
      wyl_client_decision_dup_deny_reason (decision_result);
  g_autofree gchar *dup_deny_origin =
      wyl_client_decision_dup_deny_origin (decision_result);
  if (g_strcmp0 (dup_deny_reason, "missing_grant") != 0 ||
      g_strcmp0 (dup_deny_origin, "policy") != 0)
    return wyl_test_normalize_exit_status (185);
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  http.body = "not-json";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (88);
  if (decision != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (89);
  http.body = "{\"decision\":1x,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (90);
  if (decision != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (91);
  http.body = "{\"decision\":1}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (92);
  if (decision != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (93);
  http.body = "[]";

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (7);
  if (has_next)
    return wyl_test_normalize_exit_status (8);
  has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (27);
  if (has_next)
    return wyl_test_normalize_exit_status (28);
  if (wyl_audit_iter_ref_event (local_iter) != NULL)
    return wyl_test_normalize_exit_status (38);

  http.body = two_event_body;
  g_autoptr (WylAuditIter) rows_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &rows_iter) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (29);
  has_next = FALSE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (30);
  if (!has_next)
    return wyl_test_normalize_exit_status (31);
  g_autoptr (WylAuditEvent) first_event = wyl_audit_iter_ref_event (rows_iter);
  if (first_event == NULL)
    return wyl_test_normalize_exit_status (39);
  if (wyl_audit_event_get_created_at_us (first_event) != 1234567)
    return wyl_test_normalize_exit_status (40);
  if (g_strcmp0 (wyl_audit_event_get_subject_id (first_event), "alice") != 0)
    return wyl_test_normalize_exit_status (41);
  if (g_strcmp0 (wyl_audit_event_get_action (first_event), "read") != 0)
    return wyl_test_normalize_exit_status (42);
  if (g_strcmp0 (wyl_audit_event_get_resource_id (first_event), "doc/42") != 0)
    return wyl_test_normalize_exit_status (43);
  if (wyl_audit_event_get_request_id (first_event) != NULL)
    return wyl_test_normalize_exit_status (50);
  if (wyl_audit_event_get_decision (first_event) != WYL_DECISION_ALLOW)
    return wyl_test_normalize_exit_status (44);
  has_next = FALSE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (32);
  if (!has_next)
    return wyl_test_normalize_exit_status (33);
  g_autoptr (WylAuditEvent) second_event = wyl_audit_iter_ref_event (rows_iter);
  if (second_event == NULL)
    return wyl_test_normalize_exit_status (45);
  if (g_strcmp0 (wyl_audit_event_get_subject_id (second_event), "bob") != 0)
    return wyl_test_normalize_exit_status (46);
  if (g_strcmp0 (wyl_audit_event_get_deny_reason (second_event),
      "missing_grant") != 0)
    return wyl_test_normalize_exit_status (47);
  if (g_strcmp0 (wyl_audit_event_get_deny_origin (second_event), "policy") != 0)
    return wyl_test_normalize_exit_status (48);
  if (g_strcmp0 (wyl_audit_event_get_request_id (second_event),
      "req-client-smoke") != 0)
    return wyl_test_normalize_exit_status (51);
  if (wyl_audit_event_get_decision (second_event) != WYL_DECISION_DENY)
    return wyl_test_normalize_exit_status (49);
  has_next = TRUE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (34);
  if (has_next)
    return wyl_test_normalize_exit_status (35);
  if (wyl_audit_iter_ref_event (rows_iter) != NULL)
    return wyl_test_normalize_exit_status (50);

  http.body = "not-json";
  g_autoptr (WylAuditIter) invalid_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &invalid_iter)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (36);
  has_next = FALSE;
  if (wyl_audit_iter_next (invalid_iter, &has_next) == WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (37);

  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
      "__wr_default") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (199);
  g_clear_pointer (&client_access_token, g_free);
  client_access_token = wyl_client_dup_access_token (local_client);
  g_clear_pointer (&client_tenant, g_free);
  client_tenant = wyl_client_dup_tenant (local_client);
  g_clear_pointer (&client_session_token, g_free);
  client_session_token = wyl_client_dup_session_token (local_client);
  g_clear_pointer (&client_username, g_free);
  client_username = wyl_client_dup_username (local_client);
  if (g_strcmp0 (client_access_token, "access-ctl") != 0 ||
      g_strcmp0 (client_tenant, "__wr_default") != 0 ||
      client_session_token != NULL || client_username != NULL)
    return wyl_test_normalize_exit_status (200);

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_ex (local_client, "alice", "wr.audit.read",
      "doc/42", &decision_result) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (201);
  if (g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (202);
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return wyl_test_normalize_exit_status (203);
  if (g_strcmp0 (http.last_session_token, "doc/42") != 0)
    return wyl_test_normalize_exit_status (204);
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  g_autoptr (WylAuditIter) bearer_guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client,
      "decision=deny", 321, "semi_trusted", 89, &bearer_guarded_audit_iter)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (207);
  g_autofree gchar *bearer_guarded_audit_uri =
      wyl_audit_iter_dup_request_uri (bearer_guarded_audit_iter);
  if (strstr (bearer_guarded_audit_uri, "/audit/events?") == NULL ||
      strstr (bearer_guarded_audit_uri, "tenant=__wr_default") == NULL ||
      strstr (bearer_guarded_audit_uri, "session_token=") != NULL ||
      strstr (bearer_guarded_audit_uri, "guard_timestamp=321") == NULL ||
      strstr (bearer_guarded_audit_uri,
      "guard_loc_class=semi_trusted") == NULL ||
      strstr (bearer_guarded_audit_uri, "guard_risk=89") == NULL ||
      strstr (bearer_guarded_audit_uri, "filter=decision%3Ddeny") == NULL)
    return wyl_test_normalize_exit_status (208);
  g_autoptr (SoupMessage) bearer_guarded_audit_message =
      wyl_audit_iter_new_request_message (bearer_guarded_audit_iter);
  if (g_strcmp0 (soup_message_headers_get_one (soup_message_get_request_headers
        (bearer_guarded_audit_message), "Authorization"),
      "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (209);

  /*
   * Bearer-only policy mutation: with no session_token set, the
   * client must still emit the request using the access_token in the
   * Authorization header and omit session_token from the URI query.
   */
  http.body = "{\"ok\":true}";
  http.status = 0;
  if (wyl_client_policy_permission_grant (local_client, "bearer subject",
      "site.policy.read", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (220);
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path, "/policy/permissions/grant") != 0 ||
      g_strcmp0 (http.last_subject, "bearer subject") != 0 ||
      g_strcmp0 (http.last_perm, "site.policy.read") != 0 ||
      g_strcmp0 (http.last_scope, "tenant/bearer") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0 ||
      g_strcmp0 (http.last_guard_timestamp, "321") != 0 ||
      g_strcmp0 (http.last_guard_loc_class, "semi_trusted") != 0 ||
      g_strcmp0 (http.last_guard_risk, "89") != 0)
    return wyl_test_normalize_exit_status (221);
  if (wyl_client_policy_permission_revoke (local_client, "bearer subject",
      "site.policy.read", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (222);
  if (g_strcmp0 (http.last_path, "/policy/permissions/revoke") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (223);
  if (wyl_client_policy_role_grant (local_client, "bearer subject",
      "site.reader", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (224);
  if (g_strcmp0 (http.last_path, "/policy/roles/grant") != 0 ||
      g_strcmp0 (http.last_role, "site.reader") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (225);
  if (wyl_client_policy_role_revoke (local_client, "bearer subject",
      "site.reader", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (226);
  if (g_strcmp0 (http.last_path, "/policy/roles/revoke") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (227);
  if (wyl_client_policy_permission_transition (local_client, "bearer subject",
      "site.policy.read", "tenant/bearer", "grant", 321, "semi_trusted",
      89) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (228);
  if (g_strcmp0 (http.last_path, "/policy/permissions/transition") != 0 ||
      g_strcmp0 (http.last_event, "grant") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return wyl_test_normalize_exit_status (229);

  http.body = "{\"session_token\":\"session-relogin\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-relogin\","
      "\"refresh_token\":\"refresh-relogin\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (205);
  g_clear_pointer (&client_access_token, g_free);
  client_access_token = wyl_client_dup_access_token (local_client);
  if (g_strcmp0 (client_access_token, "access-relogin") != 0)
    return wyl_test_normalize_exit_status (206);
  http.body = "{\"session_token\":\"session-relogin\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-refresh\","
      "\"refresh_token\":\"refresh-next\"}";
  if (wyl_client_token_refresh (local_client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (210);
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path, "/auth/refresh") != 0 ||
      g_strcmp0 (http.last_refresh_token, "refresh-relogin") != 0)
    return wyl_test_normalize_exit_status (211);
  /*
   * #1030: assert the channel, not just the value.  The mock reads the query
   * parameter first and falls back to the body, so every check above would
   * still pass if the client went back to putting the token in the URL --
   * which is the half of this change that matters, since a token in a URL is
   * what reaches shell history and proxy logs.  Only the body carries it now.
   */
  if (http.last_body == NULL
      || strstr (http.last_body, "\"refresh_token\":\"refresh-relogin\"")
      == NULL)
    return wyl_test_normalize_exit_status (248);
  /*
   * And not in the URL.  Asserting only that the body carries it would still
   * pass for a client that sent both, which is the shape the comment in
   * wyl_client_token_refresh warns against and which the daemon refuses with
   * 400 -- so a both-channels client would break every refresh in production
   * while this test stayed green.  last_query_refresh_token records the query
   * separately for exactly this reason; last_refresh_token merges the two.
   */
  if (http.last_query_refresh_token != NULL)
    return wyl_test_normalize_exit_status (249);
  g_clear_pointer (&client_access_token, g_free);
  client_access_token = wyl_client_dup_access_token (local_client);
  if (g_strcmp0 (client_access_token, "access-refresh") != 0)
    return wyl_test_normalize_exit_status (212);

  /* Redirects and otherwise-unmapped responses preserve their metadata before
   * the established IO mapping is applied. */
  http.status = 302;
  http.body = "{\"error\":\"service_management_redirect\"}";
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_IO
      || !client_last_response_is (local_client, 302,
      "service_management_redirect"))
    return wyl_test_normalize_exit_status (559);

  http.status = 418;
  http.body = "{\"error\":\"service_management_unmapped\"}";
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_IO
      || !client_last_response_is (local_client, 418,
      "service_management_unmapped"))
    return wyl_test_normalize_exit_status (560);

  /* The peer sends a complete 503 header and then closes before the declared
   * response body length. The transport returns IO, but the received status
   * remains observable and no incomplete error code is retained. */
  http.truncate_response_body = TRUE;
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_IO
      || !client_last_response_is (local_client, 503, NULL))
    return wyl_test_normalize_exit_status (561);
  http.truncate_response_body = FALSE;

  /* A true pre-response transport failure must replace, not preserve, the
   * metadata from a preceding remote response. */
  http.status = 403;
  http.body = "{\"error\":\"remote_before_transport\"}";
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_POLICY
      || !client_last_response_is (local_client, 403,
      "remote_before_transport"))
    return wyl_test_normalize_exit_status (551);
  /* The server thread owns polling the listener. Stop and join that loop
   * before disconnect closes its file descriptors; otherwise poll can observe
   * a concurrently closed descriptor on platforms such as macOS. */
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
      &principal_list) != WYRELOG_E_IO
      || !client_last_response_is (local_client, 0, NULL))
    return wyl_test_normalize_exit_status (552);

  g_clear_object (&http.server);
  g_clear_pointer (&http.last_method, g_free);
  g_clear_pointer (&http.last_path, g_free);
  g_clear_pointer (&http.last_body, g_free);
  g_clear_pointer (&http.last_user, g_free);
  g_clear_pointer (&http.last_subject, g_free);
  g_clear_pointer (&http.last_perm, g_free);
  g_clear_pointer (&http.last_role, g_free);
  g_clear_pointer (&http.last_scope, g_free);
  g_clear_pointer (&http.last_tenant, g_free);
  g_clear_pointer (&http.last_dimension, g_free);
  g_clear_pointer (&http.last_limit, g_free);
  g_clear_pointer (&http.last_event, g_free);
  g_clear_pointer (&http.last_session_token, g_free);
  g_clear_pointer (&http.last_refresh_token, g_free);
  g_clear_pointer (&http.last_query_refresh_token, g_free);
  g_clear_pointer (&http.last_authorization, g_free);
  g_clear_pointer (&http.last_password, g_free);
  g_clear_pointer (&http.last_skip_mfa, g_free);
  g_clear_pointer (&http.last_guard_timestamp, g_free);
  g_clear_pointer (&http.last_guard_loc_class, g_free);
  g_clear_pointer (&http.last_guard_risk, g_free);
  g_clear_pointer (&http.loop, g_main_loop_unref);

  return wyl_test_normalize_exit_status (0);
}
