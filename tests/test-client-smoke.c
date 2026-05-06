/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>

#include "wyrelog/audit/iter-private.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-client-private.h"

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
  const gchar *body;
  gchar *last_method;
  gchar *last_path;
  gchar *last_user;
  gchar *last_perm;
  gchar *last_session_token;
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
    "\"decision\":1},"
    "{\"id\":\"018f3f9b-7f4d-7a2e-8a51-467a0bc7d002\","
    "\"created_at_us\":1234568,"
    "\"subject_id\":\"bob\","
    "\"action\":\"write\","
    "\"resource_id\":\"doc/43\","
    "\"deny_reason\":\"missing_grant\","
    "\"deny_origin\":\"policy\"," "\"decision\":0}]";

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
  g_free (http->last_user);
  g_free (http->last_perm);
  g_free (http->last_session_token);
  g_free (http->last_password);
  g_free (http->last_skip_mfa);
  g_free (http->last_guard_timestamp);
  g_free (http->last_guard_loc_class);
  g_free (http->last_guard_risk);
  http->last_method = g_strdup (soup_server_message_get_method (msg));
  http->last_path = g_strdup (path);
  if (query != NULL) {
    const gchar *user = g_hash_table_lookup (query, "user");
    if (user == NULL)
      user = g_hash_table_lookup (query, "username");
    http->last_user = g_strdup (user);
  } else {
    http->last_user = NULL;
  }
  http->last_perm =
      query != NULL ? g_strdup (g_hash_table_lookup (query, "perm")) : NULL;
  http->last_session_token =
      query != NULL ? g_strdup (g_hash_table_lookup (query,
          "session_token")) : NULL;
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
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
      body, strlen (body));
}

int
main (void)
{
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

  http.body = "{\"session_token\":\"session-1\",\"username\":\"alice\","
      "\"principal_state\":\"mfa_required\",\"session_state\":\"active\"}";
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
  g_autofree gchar *client_username = wyl_client_dup_username (local_client);
  g_autofree gchar *client_principal_state =
      wyl_client_dup_principal_state (local_client);
  g_autofree gchar *client_session_state =
      wyl_client_dup_session_state (local_client);
  if (g_strcmp0 (client_session_token, "session-1") != 0 ||
      g_strcmp0 (client_username, "alice") != 0 ||
      g_strcmp0 (client_principal_state, "mfa_required") != 0 ||
      g_strcmp0 (client_session_state, "active") != 0)
    return 138;

  http.body = "{\"session_token\":\"session-2\",\"username\":\"alice\","
      "\"principal_state\":\"authenticated\",\"session_state\":\"active\"}";
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
  g_clear_pointer (&client_username, g_free);
  g_clear_pointer (&client_principal_state, g_free);
  g_clear_pointer (&client_session_state, g_free);
  client_session_token = wyl_client_dup_session_token (local_client);
  client_username = wyl_client_dup_username (local_client);
  client_principal_state = wyl_client_dup_principal_state (local_client);
  client_session_state = wyl_client_dup_session_state (local_client);
  if (g_strcmp0 (client_session_token, "session-2") != 0 ||
      g_strcmp0 (client_username, "alice") != 0 ||
      g_strcmp0 (client_principal_state, "authenticated") != 0 ||
      g_strcmp0 (client_session_state, "active") != 0)
    return 152;

  if (wyl_client_mfa_verify (local_client, NULL) == WYRELOG_E_OK)
    return 140;
  if (wyl_client_mfa_verify (local_client, "") == WYRELOG_E_OK)
    return 141;
  if (wyl_client_mfa_verify (local_client, "123456") == WYRELOG_E_OK)
    return 142;

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
  if (http.last_guard_timestamp != NULL || http.last_guard_loc_class != NULL ||
      http.last_guard_risk != NULL)
    return 69;

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
  if (g_strcmp0 (http.last_guard_timestamp, "123") != 0)
    return 83;
  if (g_strcmp0 (http.last_guard_loc_class, "semi_trusted") != 0)
    return 84;
  if (g_strcmp0 (http.last_guard_risk, "69") != 0)
    return 85;

  http.body = "{\"decision\":0,\"deny_reason\":\"missing_grant\","
      "\"deny_origin\":\"policy\"}";
  if (wyl_client_decide (local_client, "bob", "write", "doc/43", &decision)
      != WYRELOG_E_OK)
    return 86;
  if (decision != WYL_DECISION_DENY)
    return 87;

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

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.last_method, g_free);
  g_clear_pointer (&http.last_path, g_free);
  g_clear_pointer (&http.last_user, g_free);
  g_clear_pointer (&http.last_perm, g_free);
  g_clear_pointer (&http.last_session_token, g_free);
  g_clear_pointer (&http.last_password, g_free);
  g_clear_pointer (&http.last_skip_mfa, g_free);
  g_clear_pointer (&http.last_guard_timestamp, g_free);
  g_clear_pointer (&http.last_guard_loc_class, g_free);
  g_clear_pointer (&http.last_guard_risk, g_free);
  g_clear_pointer (&http.loop, g_main_loop_unref);

  return 0;
}
