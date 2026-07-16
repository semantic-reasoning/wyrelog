/* SPDX-License-Identifier: GPL-3.0-or-later */
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
  guint status;
  gchar *last_method;
  gchar *last_path;
  gchar *last_body;
  gchar *last_user;
  gchar *last_subject;
  gchar *last_perm;
  gchar *last_role;
  gchar *last_scope;
  gchar *last_tenant;
  gchar *last_event;
  gchar *last_session_token;
  gchar *last_refresh_token;
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

  g_free (http->last_method);
  g_free (http->last_path);
  g_free (http->last_body);
  g_free (http->last_user);
  g_free (http->last_subject);
  g_free (http->last_perm);
  g_free (http->last_role);
  g_free (http->last_scope);
  g_free (http->last_tenant);
  g_free (http->last_event);
  g_free (http->last_session_token);
  g_free (http->last_refresh_token);
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
  http->last_event =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "event")) : NULL;
  http->last_session_token =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "session_token")) : NULL;
  http->last_refresh_token =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "refresh_token")) : NULL;
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

  const gchar *body = http->body != NULL ? http->body : "[]";
  soup_server_message_set_status (msg, http->status != 0 ? http->status : 200,
      NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      body, strlen (body));
}

static gboolean
check_service_credential_codecs (void)
{
  WylClientServiceTokenResult token = { 0 };
  WylClientServiceCredentialIssueResult issue = { 0 };
  const gchar *token_json = " { \"access_token\": \"access-1\" } ";
  const gchar *issue_json =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:tenant:worker\","
      "\"tenant_id\":\"tenant-a\",\"generation\":7,\"state\":\"active\","
      "\"created_by\":\"admin\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":3,\"last_used_at_us\":-1,\"revoked_by\":null,"
      "\"revoked_at_us\":0,\"rotated_from_id\":null,"
      "\"credential_secret\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopq\"}}";

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

  wyrelog_error_t issue_decode_rc =
      wyl_client_service_credential_issue_result_decode (issue_json,
      strlen (issue_json), &issue);
  if (issue_decode_rc != WYRELOG_E_OK
      || g_strcmp0 (issue.credential.credential_id,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0
      || issue.credential.generation != 7
      || issue.credential_secret.len != 43) {
    return FALSE;
  }
  wyl_client_service_credential_issue_result_clear (&issue);
  if (issue.credential.credential_id != NULL
      || issue.credential_secret.text != NULL)
    return FALSE;

  WylClientServicePrincipal principal = { 0 };
  WylClientServicePrincipalList principal_list = { 0 };
  const gchar *principal_json =
      "{\"service_principal\":{\"state\":\"active\","
      "\"display_name\":\"Worker One\","
      "\"subject_id\":\"svc:tenant:worker\"}}";
  const gchar *principal_list_json =
      "{\"service_principals\":[{\"subject_id\":\"svc:tenant:worker\","
      "\"display_name\":\"Worker One\",\"state\":\"active\"}]}";
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

  const gchar *invalid[] = {
    "{\"access_token\":\"a\",\"access_token\":\"b\"}",
    "{\"access_token\":\"a\",\"unknown\":1}",
    "{\"access_token\":\"a\"} trailing",
    "{\"access_token\":\"a\\u0000b\"}",
    "{\"service_credential\":{\"credential_id\":\"x\","
        "\"generation\":0,\"credential_secret\":\"bad\"}}",
    "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
        "\"generation\":01,\"credential_secret\":\"bad\"}}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    if (wyl_client_service_token_result_decode (invalid[i], strlen (invalid[i]),
            &token) == WYRELOG_E_OK
        || token.access_token.text != NULL
        || wyl_client_service_credential_issue_result_decode (invalid[i],
            strlen (invalid[i]), &issue) == WYRELOG_E_OK
        || issue.credential_secret.text != NULL)
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

int
main (void)
{
  if (!check_service_credential_codecs ())
    return 230;
  if (!check_secret_url_preflight ())
    return 231;
  const gchar *version = wyrelog_client_version_string ();
  if (version == NULL || version[0] == '\0')
    return 1;

  g_autoptr (WylClient) client = NULL;

  /* Input validation: NULL out_client must be rejected. */
  if (wyl_client_new ("http://example.invalid", NULL) != WYRELOG_E_INVALID)
    return 2;
  if (wyl_client_new (NULL, &client) != WYRELOG_E_INVALID)
    return 9;
  if (wyl_client_new ("", &client) != WYRELOG_E_INVALID)
    return 10;
  if (wyl_client_new ("file:///tmp/wyrelog.sock", &client) != WYRELOG_E_INVALID)
    return 11;

  /* Successful path returns a non-NULL WylClient. */
  client = NULL;
  if (wyl_client_new ("http://example.invalid", &client) != WYRELOG_E_OK)
    return 3;
  if (client == NULL)
    return 4;
  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (g_strcmp0 (base_url, "http://example.invalid") != 0)
    return 12;
  if (wyl_client_get_soup_session (client) == NULL)
    return 17;

  /* Audit iterator returns a non-NULL WylAuditIter on success and
   * yields no rows in the stub state. */
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (NULL, NULL, &iter) != WYRELOG_E_INVALID)
    return 13;
  if (wyl_client_audit_query (client, NULL, NULL) != WYRELOG_E_INVALID)
    return 14;
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return 5;
  if (iter == NULL)
    return 6;
  g_autofree gchar *query_filter = wyl_audit_iter_dup_query_filter (iter);
  if (g_strcmp0 (query_filter, "decision=deny") != 0)
    return 15;
  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  if (g_strcmp0 (request_uri,
          "http://example.invalid/audit/events?filter=decision%3Ddeny") != 0)
    return 16;
  g_autoptr (SoupMessage) message = wyl_audit_iter_new_request_message (iter);
  if (message == NULL)
    return 18;
  if (g_strcmp0 (soup_message_get_method (message), "GET") != 0)
    return 19;
  g_autofree gchar *message_uri =
      g_uri_to_string (soup_message_get_uri (message));
  if (g_strcmp0 (message_uri, request_uri) != 0)
    return 20;

  TestHttpServer http = { 0 };
  http.server = soup_server_new (NULL, NULL);
  http.loop = g_main_loop_new (NULL, FALSE);
  http.body = "[]";
  soup_server_add_handler (http.server, NULL, test_http_server_handler, &http,
      NULL);
  g_autoptr (GError) listen_error = NULL;
  if (!soup_server_listen_local (http.server, 0, 0, &listen_error))
    return 21;
  GThread *thread = g_thread_new ("client-smoke-http",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 22;
  g_autofree gchar *local_base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) local_client = NULL;
  if (wyl_client_new (local_base_url, &local_client) != WYRELOG_E_OK)
    return 23;
  g_autoptr (WylAuditIter) local_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &local_iter) != WYRELOG_E_OK)
    return 24;
  g_autoptr (SoupMessage) local_message =
      wyl_audit_iter_new_request_message (local_iter);
  g_autoptr (GBytes) body = NULL;
  if (wyl_client_send_message (local_client, local_message, &body) !=
      WYRELOG_E_OK)
    return 25;
  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  if (body_size != 2 || memcmp (body_data, "[]", 2) != 0)
    return 26;

  if (wyl_client_login (NULL, "alice", NULL) != WYRELOG_E_INVALID)
    return 38;
  if (wyl_client_login (local_client, NULL, NULL) != WYRELOG_E_INVALID)
    return 39;
  if (wyl_client_login (local_client, "", NULL) != WYRELOG_E_INVALID)
    return 40;
  if (wyl_client_login (local_client, "alice", "secret") != WYRELOG_E_INVALID)
    return 41;
  if (wyl_client_login_skip_mfa (NULL, "alice") != WYRELOG_E_INVALID)
    return 143;
  if (wyl_client_login_skip_mfa (local_client, NULL) != WYRELOG_E_INVALID)
    return 144;
  if (wyl_client_login_skip_mfa (local_client, "") != WYRELOG_E_INVALID)
    return 145;
  g_autoptr (WylAuditIter) missing_login_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
          "public", 69, &missing_login_iter) != WYRELOG_E_INVALID)
    return 153;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return 510;

  http.body = "{\"session_token\":\"session-1\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"mfa_required\","
      "\"session_state\":\"active\"}";
  if (wyl_client_login (local_client, "alice", NULL) != WYRELOG_E_OK)
    return 42;
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return 43;
  if (g_strcmp0 (http.last_path, "/auth/login") != 0)
    return 44;
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return 45;
  if (http.last_password != NULL)
    return 46;
  if (http.last_skip_mfa != NULL)
    return 146;
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
    return 138;
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
    return 244;
  WylClientSensitiveText invalid_secret = {
    .text = (gchar *) "bad",
    .len = 3,
  };
  token_request.credential_secret = &invalid_secret;
  if (wyl_client_service_token_exchange (local_client, &token_request,
          &token_result) != WYRELOG_E_INVALID
      || g_strcmp0 (http.last_path, "/auth/service-token") != 0)
    return 245;
  token_request.credential_secret = &credential_secret;
  http.status = 429;
  http.body = "{\"error\":\"rate_limited\"}";
  if (wyl_client_service_token_exchange (local_client, &token_request,
          &token_result) != WYRELOG_E_IO
      || token_result.access_token.text != NULL)
    return 246;
  http.status = 0;
  g_auto (WylClientServicePrincipal)
  principal = { 0 };
  g_auto (WylClientServicePrincipalList)
  principal_list = { 0 };
  g_auto (WylClientServiceCredential)
  credential = { 0 };
  g_auto (WylClientServiceCredentialList)
  credential_list = { 0 };
  g_auto (WylClientServiceCredentialIssueResult)
  issue_result = { 0 };
  http.body = "{\"service_principal\":{\"subject_id\":\"svc:alice:worker\","
      "\"display_name\":\"Worker\",\"state\":\"active\"}}";
  if (wyl_client_service_principal_create (local_client, "svc:alice:worker",
          "Worker", 123, "public", 49, &principal) != WYRELOG_E_OK
      || g_strcmp0 (principal.subject_id, "svc:alice:worker") != 0
      || g_strcmp0 (principal.display_name, "Worker") != 0
      || g_strcmp0 (http.last_path, "/service-principals") != 0
      || g_strcmp0 (http.last_method, "POST") != 0
      || strstr (http.last_body, "svc:alice:worker") == NULL
      || g_strcmp0 (http.last_session_token, "session-1") != 0)
    return 232;
  http.body = "{\"service_principals\":[{\"subject_id\":\""
      "svc:alice:worker\",\"display_name\":\"Worker\","
      "\"state\":\"active\"}]}";
  if (wyl_client_service_principal_list (local_client, 123, "public", 49,
          &principal_list) != WYRELOG_E_OK || principal_list.len != 1
      || g_strcmp0 (principal_list.items[0].subject_id,
          "svc:alice:worker") != 0
      || g_strcmp0 (http.last_method, "GET") != 0
      || g_strcmp0 (http.last_path, "/service-principals") != 0)
    return 233;
  http.body = "{\"ok\":true}";
  if (wyl_client_service_principal_disable (local_client,
          "svc:alice:worker", 123, "public", 49) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_path,
          "/service-principals/svc:alice:worker/disable") != 0)
    return 234;
  if (wyl_client_service_principal_create (local_client, "alice", "bad", 123,
          "public", 49, &principal) != WYRELOG_E_INVALID)
    return 235;
  const gchar *mock_credential_json =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:alice:worker\","
      "\"tenant_id\":\"__wr_default\",\"generation\":1,\"state\":\"revoked\","
      "\"created_by\":\"alice\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":3,\"last_used_at_us\":-1,\"revoked_by\":\"alice\","
      "\"revoked_at_us\":4,\"rotated_from_id\":null}}";
  http.body = mock_credential_json;
  if (wyl_client_service_credential_get (local_client,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", 123, "public", 49,
          &credential) != WYRELOG_E_OK
      || g_strcmp0 (http.last_path,
          "/service-credentials/wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv") != 0
      || g_strcmp0 (credential.state, "revoked") != 0)
    return 236;
  http.body = "{\"service_credentials\":[]}";
  if (wyl_client_service_credential_list (local_client, "svc:alice:worker",
          123, "public", 49, &credential_list) != WYRELOG_E_OK
      || credential_list.len != 0
      || g_strcmp0 (http.last_path,
          "/service-principals/svc:alice:worker/credentials") != 0)
    return 237;
  http.body = mock_credential_json;
  if (wyl_client_service_credential_revoke (local_client,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          "222222222222222222222222222", 123, "public", 49,
          &credential) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "DELETE") != 0
      || strstr (http.last_body, "request_id") == NULL)
    return 238;
  if (wyl_client_service_credential_revoke (local_client,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", "bad", 123, "public", 49,
          &credential) != WYRELOG_E_INVALID)
    return 239;
  WylClientServiceCredentialIssueRequest issue_request = {
    .subject_id = "svc:alice:worker",
    .tenant_id = "__wr_default",
    .request_id = "333333333333333333333333333",
    .expires_at_us = 0,
  };
  http.body =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:alice:worker\","
      "\"tenant_id\":\"__wr_default\",\"generation\":1,\"state\":\"active\","
      "\"created_by\":\"alice\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":0,\"last_used_at_us\":-1,\"revoked_by\":null,"
      "\"revoked_at_us\":0,\"rotated_from_id\":null,"
      "\"credential_secret\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopq\"}}";
  wyrelog_error_t issue_rc = wyl_client_service_credential_issue
      (local_client, &issue_request, 123, "public", 49, &issue_result);
  if (issue_rc != WYRELOG_E_OK) {
    return 240;
  }
  http.status = 409;
  if (wyl_client_service_credential_issue (local_client, &issue_request,
          123, "public", 49, &issue_result) != WYRELOG_E_POLICY
      || issue_result.credential_secret.text != NULL)
    return 242;
  http.status = 0;
  issue_request.tenant_id = "other-tenant";
  if (wyl_client_service_credential_issue (local_client, &issue_request,
          123, "public", 49, &issue_result) != WYRELOG_E_INVALID)
    return 243;
  issue_request.tenant_id = "__wr_default";
  http.body =
      "{\"service_credential\":{\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_format_version\":1,\"subject_id\":\"svc:alice:worker\","
      "\"tenant_id\":\"__wr_default\",\"generation\":2,\"state\":\"active\","
      "\"created_by\":\"alice\",\"created_at_us\":1,\"updated_at_us\":2,"
      "\"expires_at_us\":0,\"last_used_at_us\":-1,\"revoked_by\":null,"
      "\"revoked_at_us\":0,\"rotated_from_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\","
      "\"credential_secret\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopq\"}}";
  if (wyl_client_service_credential_rotate (local_client,
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          "444444444444444444444444444", 0, 123, "public", 49,
          &issue_result) != WYRELOG_E_OK
      || g_strcmp0 (http.last_method, "POST") != 0
      || g_strcmp0 (http.last_path,
          "/service-credentials/wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv/rotate") != 0
      || issue_result.credential.generation != 2
      || issue_result.credential_secret.len != 43)
    return 241;
  if (wyl_client_tenant_select (local_client, "unknown") != WYRELOG_E_INVALID)
    return 90;
  /*
   * Tenant selection must match the tenant carried by the current
   * client credentials. A distinct literal fails closed and leaves
   * the existing binding unchanged.
   */
  if (wyl_client_tenant_select (local_client, "evil-co") != WYRELOG_E_INVALID)
    return 96;
  if (wyl_client_tenant_select (local_client, "__wr_default") != WYRELOG_E_OK)
    return 91;
  http.body = "{\"ok\":true}";
  if (wyl_client_policy_permission_grant (local_client, "fallback target",
          "site.policy.read", "tenant/fallback", 123, "public", 49)
      != WYRELOG_E_OK)
    return 170;
  if (g_strcmp0 (http.last_session_token, "session-1") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_authorization != NULL)
    return 171;
  g_autoptr (WylAuditIter) fallback_guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
          "public", 69, &fallback_guarded_audit_iter) != WYRELOG_E_OK)
    return 173;
  g_autofree gchar *fallback_guarded_audit_uri =
      wyl_audit_iter_dup_request_uri (fallback_guarded_audit_iter);
  if (strstr (fallback_guarded_audit_uri, "tenant=__wr_default") == NULL ||
      strstr (fallback_guarded_audit_uri, "session_token=session-1") == NULL)
    return 174;
  g_autoptr (SoupMessage) fallback_guarded_audit_message =
      wyl_audit_iter_new_request_message (fallback_guarded_audit_iter);
  if (soup_message_headers_get_one (soup_message_get_request_headers
          (fallback_guarded_audit_message), "Authorization") != NULL)
    return 175;

  http.body = "{\"session_token\":\"session-2\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-2\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return 147;
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return 148;
  if (g_strcmp0 (http.last_path, "/auth/login") != 0)
    return 149;
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return 150;
  if (g_strcmp0 (http.last_skip_mfa, "true") != 0)
    return 151;
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
    return 152;

  g_auto (WylClientServiceCredentialOperationReconcileRequest)
  reconcile_request = { 0 };
  g_auto (WylClientServiceCredentialOperationReconcileResult)
  reconcile_result = { 0 };
  reconcile_request.operation =
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_ISSUE;
  reconcile_request.request_id = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1";
  reconcile_request.subject_id = "svc:client:reconcile";
  reconcile_request.tenant_id = "tenant-a";

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
  http.body = reconcile_issue_response;
  if (wyl_client_service_credential_operation_reconcile (local_client,
          &reconcile_request, &reconcile_result) != WYRELOG_E_OK)
    return 210;
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_COMMITTED ||
      g_strcmp0 (reconcile_result.credential_id,
          "wlc_ABCDEFGHIJKLMNOPQRSTUVWXYZ1") != 0 ||
      reconcile_result.generation != 7)
    return 211;
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path,
          "/service-credential-operations/reconcile") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_body, reconcile_issue_body) != 0)
    return 212;
  wyl_client_service_credential_operation_reconcile_result_clear
      (&reconcile_result);

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
  if (wyl_client_service_credential_operation_reconcile (local_client,
          &reconcile_request, &reconcile_result) != WYRELOG_E_OK)
    return 213;
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_NOT_COMMITTED_TERMINAL
      || reconcile_result.credential_id != NULL
      || reconcile_result.generation != 0)
    return 214;
  if (g_strcmp0 (http.last_body, reconcile_rotate_body) != 0)
    return 215;
  wyl_client_service_credential_operation_reconcile_result_clear
      (&reconcile_result);

  const gchar *reconcile_conflict_body =
      "{\"error\":\"operation_request_conflict\"}";
  http.status = 409;
  http.body = reconcile_conflict_body;
  if (wyl_client_service_credential_operation_reconcile (local_client,
          &reconcile_request, &reconcile_result) != WYRELOG_E_OK)
    return 216;
  if (reconcile_result.kind !=
      WYL_CLIENT_SERVICE_CREDENTIAL_OPERATION_RECONCILE_OPERATION_REQUEST_CONFLICT
      || reconcile_result.credential_id != NULL
      || reconcile_result.generation != 0)
    return 217;
  if (g_strcmp0 (http.last_body, reconcile_rotate_body) != 0 ||
      http.status != 409)
    return 218;
  http.status = 0;
  wyl_client_service_credential_operation_reconcile_result_clear
      (&reconcile_result);

  http.body = "{\"version\":1,\"request_id\":\"ABCDEFGHIJKLMNOPQRSTUVWXYZ1\","
      "\"operation\":\"issue\",\"target\":{\"subject\":\"svc:client:reconcile\","
      "\"tenant\":\"tenant-a\",\"extra\":\"x\"}}";
  if (wyl_client_service_credential_operation_reconcile (local_client,
          &reconcile_request, &reconcile_result) != WYRELOG_E_IO)
    return 219;
  if (reconcile_result.kind != 0 || reconcile_result.credential_id != NULL ||
      reconcile_result.generation != 0)
    return 220;
  http.body = reconcile_issue_response;
  if (wyl_client_set_bearer_credentials (NULL, "access-ctl",
          "__wr_default") != WYRELOG_E_INVALID)
    return 192;
  if (wyl_client_set_bearer_credentials (local_client, NULL,
          "__wr_default") != WYRELOG_E_INVALID)
    return 193;
  if (wyl_client_set_bearer_credentials (local_client, "",
          "__wr_default") != WYRELOG_E_INVALID)
    return 194;
  if (wyl_client_set_bearer_credentials (local_client, "access ctl",
          "__wr_default") != WYRELOG_E_INVALID)
    return 195;
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
          NULL) != WYRELOG_E_INVALID)
    return 196;
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
          "") != WYRELOG_E_INVALID)
    return 197;
  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
          "__wr default") != WYRELOG_E_INVALID)
    return 198;

  if (wyl_client_policy_permission_grant (NULL, "target", "read", "scope",
          123, "public", 49) != WYRELOG_E_INVALID)
    return 511;
  if (wyl_client_policy_permission_grant (local_client, NULL, "read",
          "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return 512;
  if (wyl_client_policy_permission_grant (local_client, "target", NULL,
          "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return 513;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          NULL, 123, "public", 49) != WYRELOG_E_INVALID)
    return 514;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", -1, "public", 49) != WYRELOG_E_INVALID)
    return 515;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "unknown", 49) != WYRELOG_E_INVALID)
    return 516;
  if (wyl_client_policy_permission_transition (NULL, "target", "read",
          "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return 529;
  if (wyl_client_policy_permission_transition (local_client, NULL, "read",
          "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return 530;
  if (wyl_client_policy_permission_transition (local_client, "target", NULL,
          "scope", "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return 531;
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
          NULL, "grant", 123, "public", 49) != WYRELOG_E_INVALID)
    return 532;
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
          "scope", NULL, 123, "public", 49) != WYRELOG_E_INVALID)
    return 533;
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
          "scope", "", 123, "public", 49) != WYRELOG_E_INVALID)
    return 534;
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
          "scope", "grant", -1, "public", 49) != WYRELOG_E_INVALID)
    return 535;
  if (wyl_client_policy_permission_transition (local_client, "target", "read",
          "scope", "grant", 123, "unknown", 49) != WYRELOG_E_INVALID)
    return 536;

  http.body = "{\"ok\":true}";
  if (wyl_client_policy_permission_grant (local_client, "target user",
          "site.policy.read", "tenant/a", 123, "public", 49) != WYRELOG_E_OK)
    return 517;
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
    return 518;
  if (wyl_client_policy_permission_revoke (local_client, "target user",
          "site.policy.read", "tenant/a", 123, "public", 49) != WYRELOG_E_OK)
    return 519;
  if (g_strcmp0 (http.last_path, "/policy/permissions/revoke") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return 520;
  if (wyl_client_policy_permission_transition (local_client, "target user",
          "site.policy.read", "tenant/a", "grant", 123, "public", 49)
      != WYRELOG_E_OK)
    return 537;
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
    return 538;
  if (wyl_client_policy_role_grant (local_client, "target user",
          "site.reader", "tenant/b", 123, "public", 29) != WYRELOG_E_OK)
    return 521;
  if (g_strcmp0 (http.last_path, "/policy/roles/grant") != 0 ||
      g_strcmp0 (http.last_role, "site.reader") != 0 ||
      g_strcmp0 (http.last_scope, "tenant/b") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0 ||
      g_strcmp0 (http.last_guard_risk, "29") != 0)
    return 522;
  if (wyl_client_policy_role_revoke (local_client, "target user",
          "site.reader", "tenant/b", 123, "public", 29) != WYRELOG_E_OK)
    return 523;
  if (g_strcmp0 (http.last_path, "/policy/roles/revoke") != 0 ||
      g_strcmp0 (http.last_tenant, "__wr_default") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return 524;
  http.status = 400;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "public", 49) != WYRELOG_E_INVALID)
    return 525;
  http.status = 401;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "public", 49) != WYRELOG_E_AUTH)
    return 526;
  http.status = 403;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "public", 49) != WYRELOG_E_POLICY)
    return 527;
  http.status = 500;
  if (wyl_client_policy_permission_grant (local_client, "target", "read",
          "scope", 123, "public", 49) != WYRELOG_E_IO)
    return 528;
  http.status = 0;

  g_autoptr (WylAuditIter) guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client,
          "decision=deny", 123, "public", 69, &guarded_audit_iter)
      != WYRELOG_E_OK)
    return 154;
  g_autoptr (WylAuditIter) invalid_guard_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client, NULL, 123,
          "unknown", 69, &invalid_guard_iter) != WYRELOG_E_INVALID)
    return 161;

  http.body = "{\"session_token\":\"session-3\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-3\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return 162;

  g_autofree gchar *guarded_audit_uri =
      wyl_audit_iter_dup_request_uri (guarded_audit_iter);
  if (strstr (guarded_audit_uri, "/audit/events?") == NULL ||
      strstr (guarded_audit_uri, "tenant=__wr_default") == NULL ||
      strstr (guarded_audit_uri, "session_token=") != NULL ||
      strstr (guarded_audit_uri, "guard_timestamp=123") == NULL ||
      strstr (guarded_audit_uri, "guard_loc_class=public") == NULL ||
      strstr (guarded_audit_uri, "guard_risk=69") == NULL ||
      strstr (guarded_audit_uri, "filter=decision%3Ddeny") == NULL)
    return 155;
  g_autoptr (SoupMessage) guarded_audit_message =
      wyl_audit_iter_new_request_message (guarded_audit_iter);
  g_clear_pointer (&body, g_bytes_unref);
  if (wyl_client_send_message (local_client, guarded_audit_message, &body) !=
      WYRELOG_E_OK)
    return 156;
  if (http.last_session_token != NULL)
    return 157;
  if (g_strcmp0 (http.last_authorization, "Bearer access-2") != 0)
    return 172;
  if (g_strcmp0 (http.last_guard_timestamp, "123") != 0)
    return 158;
  if (g_strcmp0 (http.last_guard_loc_class, "public") != 0)
    return 159;
  if (g_strcmp0 (http.last_guard_risk, "69") != 0)
    return 160;

  if (wyl_client_mfa_verify (local_client, NULL) == WYRELOG_E_OK)
    return 140;
  if (wyl_client_mfa_verify (local_client, "") == WYRELOG_E_OK)
    return 141;
  if (wyl_client_mfa_verify (local_client, "123456") == WYRELOG_E_OK)
    return 142;

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return 163;

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":null}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return 165;

  http.body = "{\"session_token\":\"session-bad\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-a\","
      "\"access_token\":\"access-b\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_IO)
    return 164;

  http.body = "{\"session_token\":\"session-1\"}";
  if (wyl_client_login (local_client, "alice", NULL) != WYRELOG_E_IO)
    return 47;
  g_clear_pointer (&client_session_token, g_free);
  client_session_token = wyl_client_dup_session_token (local_client);
  if (client_session_token != NULL)
    return 139;
  http.body = "[]";

  gint decision = -1;
  if (wyl_client_decide (NULL, "alice", "read", "doc/42", &decision)
      != WYRELOG_E_INVALID)
    return 51;
  if (wyl_client_decide (local_client, NULL, "read", "doc/42", &decision)
      != WYRELOG_E_INVALID)
    return 52;
  if (wyl_client_decide (local_client, "alice", "read", "doc/42", NULL)
      != WYRELOG_E_INVALID)
    return 53;
  g_autoptr (WylClientDecision) decision_result = NULL;
  if (wyl_client_decide_ex (local_client, "alice", "read", "doc/42", NULL)
      != WYRELOG_E_INVALID)
    return 177;
  if (wyl_client_decision_get_decision (NULL) != WYL_DECISION_DENY ||
      wyl_client_decision_get_deny_reason (NULL) != NULL ||
      wyl_client_decision_get_deny_origin (NULL) != NULL)
    return 178;

  http.body = "{\"session_token\":\"session-4\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-4\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return 92;

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide (local_client, "alice", "wr.audit.read",
          "doc/42", &decision) != WYRELOG_E_OK)
    return 54;
  if (decision != WYL_DECISION_ALLOW)
    return 55;
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return 56;
  if (g_strcmp0 (http.last_path, "/decide") != 0)
    return 57;
  if (g_strcmp0 (http.last_user, "alice") != 0)
    return 58;
  if (g_strcmp0 (http.last_perm, "wr.audit.read") != 0)
    return 59;
  if (g_strcmp0 (http.last_session_token, "doc/42") != 0)
    return 60;
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return 93;
  if (g_strcmp0 (http.last_authorization, "Bearer access-4") != 0)
    return 176;
  if (http.last_guard_timestamp != NULL || http.last_guard_loc_class != NULL ||
      http.last_guard_risk != NULL)
    return 69;
  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_ex (local_client, "alice", "wr.audit.read",
          "doc/42", &decision_result) != WYRELOG_E_OK)
    return 179;
  if (decision_result == NULL ||
      wyl_client_decision_get_decision (decision_result) != WYL_DECISION_ALLOW)
    return 180;
  if (wyl_client_decision_get_deny_reason (decision_result) != NULL ||
      wyl_client_decision_get_deny_origin (decision_result) != NULL)
    return 181;
  if (wyl_client_decide_ex (local_client, NULL, "wr.audit.read", "doc/42",
          &decision_result) != WYRELOG_E_INVALID)
    return 186;
  if (decision_result != NULL)
    return 187;
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  if (wyl_client_decide_with_guard_context (NULL, "alice", "read", "doc/42",
          123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return 70;
  if (wyl_client_decide_with_guard_context (local_client, NULL, "read",
          "doc/42", 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return 71;
  if (wyl_client_decide_with_guard_context (local_client, "alice", NULL,
          "doc/42", 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return 72;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          NULL, 123, "public", 69, &decision) != WYRELOG_E_INVALID)
    return 73;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          "doc/42", 123, NULL, 69, &decision) != WYRELOG_E_INVALID)
    return 74;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          "doc/42", -1, "public", 69, &decision) != WYRELOG_E_INVALID)
    return 75;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          "doc/42", 123, "public", 101, &decision) != WYRELOG_E_INVALID)
    return 76;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          "doc/42", 123, "unknown", 69, &decision) != WYRELOG_E_INVALID)
    return 77;
  if (wyl_client_decide_with_guard_context (local_client, "alice", "read",
          "doc/42", 123, "public", 69, NULL) != WYRELOG_E_INVALID)
    return 78;

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_with_guard_context (local_client, "alice",
          "wr.audit.read", "doc/42", 123, "semi_trusted", 69,
          &decision) != WYRELOG_E_OK)
    return 79;
  if (decision != WYL_DECISION_ALLOW)
    return 80;
  if (g_strcmp0 (http.last_method, "POST") != 0)
    return 81;
  if (g_strcmp0 (http.last_path, "/decide") != 0)
    return 82;
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return 94;
  if (g_strcmp0 (http.last_authorization, "Bearer access-4") != 0)
    return 95;
  if (g_strcmp0 (http.last_guard_timestamp, "123") != 0)
    return 83;
  if (g_strcmp0 (http.last_guard_loc_class, "semi_trusted") != 0)
    return 84;
  if (g_strcmp0 (http.last_guard_risk, "69") != 0)
    return 85;
  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_with_guard_context_ex (local_client, "alice",
          "wr.audit.read", "doc/42", 123, "semi_trusted", 69,
          &decision_result) != WYRELOG_E_OK)
    return 188;
  if (decision_result == NULL)
    return 189;
  if (wyl_client_decide_with_guard_context_ex (local_client, "alice",
          "wr.audit.read", "doc/42", 123, NULL, 69,
          &decision_result) != WYRELOG_E_INVALID)
    return 190;
  if (decision_result != NULL)
    return 191;

  http.body = "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_OK)
    return 86;
  if (decision != WYL_DECISION_DENY)
    return 87;
  http.body = "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}";
  if (wyl_client_decide_ex (local_client, "bob", "write", "doc/43",
          &decision_result) != WYRELOG_E_OK)
    return 182;
  if (decision_result == NULL ||
      wyl_client_decision_get_decision (decision_result) != WYL_DECISION_DENY)
    return 183;
  if (g_strcmp0 (wyl_client_decision_get_deny_reason (decision_result),
          "missing_grant") != 0 ||
      g_strcmp0 (wyl_client_decision_get_deny_origin (decision_result),
          "policy") != 0)
    return 184;
  g_autofree gchar *dup_deny_reason =
      wyl_client_decision_dup_deny_reason (decision_result);
  g_autofree gchar *dup_deny_origin =
      wyl_client_decision_dup_deny_origin (decision_result);
  if (g_strcmp0 (dup_deny_reason, "missing_grant") != 0 ||
      g_strcmp0 (dup_deny_origin, "policy") != 0)
    return 185;
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  http.body = "not-json";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return 88;
  if (decision != WYL_DECISION_DENY)
    return 89;
  http.body = "{\"decision\":1x,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return 90;
  if (decision != WYL_DECISION_DENY)
    return 91;
  http.body = "{\"decision\":1}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_IO)
    return 92;
  if (decision != WYL_DECISION_DENY)
    return 93;
  http.body = "[]";

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return 7;
  if (has_next)
    return 8;
  has_next = TRUE;
  if (wyl_audit_iter_next (local_iter, &has_next) != WYRELOG_E_OK)
    return 27;
  if (has_next)
    return 28;
  if (wyl_audit_iter_ref_event (local_iter) != NULL)
    return 38;

  http.body = two_event_body;
  g_autoptr (WylAuditIter) rows_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &rows_iter) != WYRELOG_E_OK)
    return 29;
  has_next = FALSE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return 30;
  if (!has_next)
    return 31;
  g_autoptr (WylAuditEvent) first_event = wyl_audit_iter_ref_event (rows_iter);
  if (first_event == NULL)
    return 39;
  if (wyl_audit_event_get_created_at_us (first_event) != 1234567)
    return 40;
  if (g_strcmp0 (wyl_audit_event_get_subject_id (first_event), "alice") != 0)
    return 41;
  if (g_strcmp0 (wyl_audit_event_get_action (first_event), "read") != 0)
    return 42;
  if (g_strcmp0 (wyl_audit_event_get_resource_id (first_event), "doc/42") != 0)
    return 43;
  if (wyl_audit_event_get_request_id (first_event) != NULL)
    return 50;
  if (wyl_audit_event_get_decision (first_event) != WYL_DECISION_ALLOW)
    return 44;
  has_next = FALSE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return 32;
  if (!has_next)
    return 33;
  g_autoptr (WylAuditEvent) second_event = wyl_audit_iter_ref_event (rows_iter);
  if (second_event == NULL)
    return 45;
  if (g_strcmp0 (wyl_audit_event_get_subject_id (second_event), "bob") != 0)
    return 46;
  if (g_strcmp0 (wyl_audit_event_get_deny_reason (second_event),
          "missing_grant") != 0)
    return 47;
  if (g_strcmp0 (wyl_audit_event_get_deny_origin (second_event), "policy") != 0)
    return 48;
  if (g_strcmp0 (wyl_audit_event_get_request_id (second_event),
          "req-client-smoke") != 0)
    return 51;
  if (wyl_audit_event_get_decision (second_event) != WYL_DECISION_DENY)
    return 49;
  has_next = TRUE;
  if (wyl_audit_iter_next (rows_iter, &has_next) != WYRELOG_E_OK)
    return 34;
  if (has_next)
    return 35;
  if (wyl_audit_iter_ref_event (rows_iter) != NULL)
    return 50;

  http.body = "not-json";
  g_autoptr (WylAuditIter) invalid_iter = NULL;
  if (wyl_client_audit_query (local_client, NULL, &invalid_iter)
      != WYRELOG_E_OK)
    return 36;
  has_next = FALSE;
  if (wyl_audit_iter_next (invalid_iter, &has_next) == WYRELOG_E_OK)
    return 37;

  if (wyl_client_set_bearer_credentials (local_client, "access-ctl",
          "__wr_default") != WYRELOG_E_OK)
    return 199;
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
    return 200;

  http.body = "{\"decision\":1,\"deny_reason\":null,\"deny_origin\":null}";
  if (wyl_client_decide_ex (local_client, "alice", "wr.audit.read",
          "doc/42", &decision_result) != WYRELOG_E_OK)
    return 201;
  if (g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return 202;
  if (g_strcmp0 (http.last_tenant, "__wr_default") != 0)
    return 203;
  if (g_strcmp0 (http.last_session_token, "doc/42") != 0)
    return 204;
  g_clear_pointer (&decision_result, wyl_client_decision_free);

  g_autoptr (WylAuditIter) bearer_guarded_audit_iter = NULL;
  if (wyl_client_audit_query_with_guard_context (local_client,
          "decision=deny", 321, "semi_trusted", 89, &bearer_guarded_audit_iter)
      != WYRELOG_E_OK)
    return 207;
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
    return 208;
  g_autoptr (SoupMessage) bearer_guarded_audit_message =
      wyl_audit_iter_new_request_message (bearer_guarded_audit_iter);
  if (g_strcmp0 (soup_message_headers_get_one (soup_message_get_request_headers
              (bearer_guarded_audit_message), "Authorization"),
          "Bearer access-ctl") != 0)
    return 209;

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
    return 220;
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
    return 221;
  if (wyl_client_policy_permission_revoke (local_client, "bearer subject",
          "site.policy.read", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return 222;
  if (g_strcmp0 (http.last_path, "/policy/permissions/revoke") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return 223;
  if (wyl_client_policy_role_grant (local_client, "bearer subject",
          "site.reader", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return 224;
  if (g_strcmp0 (http.last_path, "/policy/roles/grant") != 0 ||
      g_strcmp0 (http.last_role, "site.reader") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return 225;
  if (wyl_client_policy_role_revoke (local_client, "bearer subject",
          "site.reader", "tenant/bearer", 321, "semi_trusted", 89)
      != WYRELOG_E_OK)
    return 226;
  if (g_strcmp0 (http.last_path, "/policy/roles/revoke") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return 227;
  if (wyl_client_policy_permission_transition (local_client, "bearer subject",
          "site.policy.read", "tenant/bearer", "grant", 321, "semi_trusted",
          89) != WYRELOG_E_OK)
    return 228;
  if (g_strcmp0 (http.last_path, "/policy/permissions/transition") != 0 ||
      g_strcmp0 (http.last_event, "grant") != 0 ||
      http.last_session_token != NULL ||
      g_strcmp0 (http.last_authorization, "Bearer access-ctl") != 0)
    return 229;

  http.body = "{\"session_token\":\"session-relogin\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-relogin\","
      "\"refresh_token\":\"refresh-relogin\"}";
  if (wyl_client_login_skip_mfa (local_client, "alice") != WYRELOG_E_OK)
    return 205;
  g_clear_pointer (&client_access_token, g_free);
  client_access_token = wyl_client_dup_access_token (local_client);
  if (g_strcmp0 (client_access_token, "access-relogin") != 0)
    return 206;
  http.body = "{\"session_token\":\"session-relogin\",\"username\":\"alice\","
      "\"tenant\":\"__wr_default\",\"principal_state\":\"authenticated\","
      "\"session_state\":\"active\",\"access_token\":\"access-refresh\","
      "\"refresh_token\":\"refresh-next\"}";
  if (wyl_client_token_refresh (local_client) != WYRELOG_E_OK)
    return 210;
  if (g_strcmp0 (http.last_method, "POST") != 0 ||
      g_strcmp0 (http.last_path, "/auth/refresh") != 0 ||
      g_strcmp0 (http.last_refresh_token, "refresh-relogin") != 0)
    return 211;
  g_clear_pointer (&client_access_token, g_free);
  client_access_token = wyl_client_dup_access_token (local_client);
  if (g_strcmp0 (client_access_token, "access-refresh") != 0)
    return 212;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
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
  g_clear_pointer (&http.last_event, g_free);
  g_clear_pointer (&http.last_session_token, g_free);
  g_clear_pointer (&http.last_refresh_token, g_free);
  g_clear_pointer (&http.last_authorization, g_free);
  g_clear_pointer (&http.last_password, g_free);
  g_clear_pointer (&http.last_skip_mfa, g_free);
  g_clear_pointer (&http.last_guard_timestamp, g_free);
  g_clear_pointer (&http.last_guard_loc_class, g_free);
  g_clear_pointer (&http.last_guard_risk, g_free);
  g_clear_pointer (&http.loop, g_main_loop_unref);

  return 0;
}
