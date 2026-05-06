/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>

#include "daemon/http.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
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
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
}

static wyrelog_error_t
insert_symbol_row1 (WylHandle *handle, const gchar *relation,
    const gchar *value)
{
  gint64 row[1];
  wyrelog_error_t rc = intern_symbol (handle, value, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 1);
}

static wyrelog_error_t
insert_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b)
{
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 2);
}

static wyrelog_error_t
insert_symbol_row3 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 3);
}

static wyrelog_error_t
insert_symbol_row4 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c, const gchar *d)
{
  gint64 row[4];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 4);
}

static wyrelog_error_t
insert_allow_fixture (WylHandle *handle)
{
  const gchar *subject = "http-allow-user";
  const gchar *action = "http.allow";
  const gchar *resource = "http-allow-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-decide-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-decide-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row1 (handle, "session_active", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row4 (handle, "perm_state", subject, action, resource,
      "armed");
}

static wyrelog_error_t
insert_not_armed_fixture (WylHandle *handle)
{
  const gchar *subject = "http-deny-user";
  const gchar *action = "http.not_armed";
  const gchar *resource = "http-deny-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-deny-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-deny-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static wyrelog_error_t
insert_guarded_fixture (WylHandle *handle)
{
  const gchar *subject = "http-guard-user";
  const gchar *action = "wr.audit.read";
  const gchar *resource = "http-guard-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-guard-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-guard-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static gchar *
build_decide_uri (const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query)
{
  g_autofree gchar *base = g_strdup (base_url);
  while (base[0] != '\0' && g_str_has_suffix (base, "/"))
    base[strlen (base) - 1] = '\0';
  g_autofree gchar *escaped_user = g_uri_escape_string (user, NULL, TRUE);
  g_autofree gchar *escaped_perm = g_uri_escape_string (perm, NULL, TRUE);
  g_autofree gchar *escaped_scope = g_uri_escape_string (scope, NULL, TRUE);

  return g_strdup_printf ("%s/decide?user=%s&perm=%s&session_token=%s%s%s",
      base, escaped_user, escaped_perm, escaped_scope,
      extra_query != NULL ? "&" : "", extra_query != NULL ? extra_query : "");
}

static gint
send_raw_decide (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, guint *out_status,
    gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 30;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri =
      build_decide_uri (base_url, user, perm, scope, extra_query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 31;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (body == NULL)
    return 32;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (body_data, body_size);
  return 0;
}

static gint
check_raw_decide_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  gint rc = send_raw_decide (session, "GET", base_url, "http-deny-user",
      "http.not_armed", "http-deny-scope", NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"error\":\"method_not_allowed\"")
      == NULL)
    return 33;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-deny-user",
      "http.not_armed", "http-deny-scope", NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 34;
  if (strstr (body, "\"decision\":0") == NULL)
    return 35;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 36;
  if (strstr (body, "\"deny_origin\":\"perm_state\"") == NULL)
    return 37;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope", NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 38;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 39;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 40;
  if (strstr (body, "\"decision\":1") == NULL)
    return 41;
  if (strstr (body, "\"deny_reason\":null") == NULL)
    return 42;
  if (strstr (body, "\"deny_origin\":null") == NULL)
    return 43;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=70",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 44;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 45;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 46;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=101",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 47;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=abc&guard_loc_class=public&guard_risk=69",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 48;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=unknown&guard_risk=69",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 49;

  return 0;
}

static gint
send_raw_login (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = NULL;
  if (query != NULL)
    uri = g_strdup_printf ("%s/auth/login?%s", root, query);
  else
    uri = g_strdup_printf ("%s/auth/login", root);

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 2;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
check_raw_login_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  gint rc = send_raw_login (session, "GET", base_url,
      "username=login-user", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 470;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 471;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 472;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 473;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=1", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 474;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&password=secret", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 478;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=login-user",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"username\":\"login-user\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL ||
      strstr (body, "\"session_state\":\"active\"") == NULL)
    return 475;
  g_clear_pointer (&body, g_free);

  return 0;
}

#ifdef WYL_HAS_AUDIT
static gint
check_audit_event_present (WylClient *client, const gchar *filter,
    const gchar *subject, const gchar *action, const gchar *resource,
    wyl_decision_t decision, const gchar *deny_reason, const gchar *deny_origin)
{
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (client, filter, &iter) != WYRELOG_E_OK)
    return 80;

  while (TRUE) {
    gboolean has_next = FALSE;
    if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
      return 81;
    if (!has_next)
      return 82;

    g_autoptr (WylAuditEvent) event = wyl_audit_iter_ref_event (iter);
    if (event == NULL)
      return 83;
    if (g_strcmp0 (wyl_audit_event_get_subject_id (event), subject) == 0 &&
        g_strcmp0 (wyl_audit_event_get_action (event), action) == 0 &&
        g_strcmp0 (wyl_audit_event_get_resource_id (event), resource) == 0 &&
        wyl_audit_event_get_decision (event) == decision &&
        g_strcmp0 (wyl_audit_event_get_deny_reason (event), deny_reason) == 0 &&
        g_strcmp0 (wyl_audit_event_get_deny_origin (event), deny_origin) == 0)
      return 0;
  }
}
#endif

int
main (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 2;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return 10;
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 11;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server (&opts, handle, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (base_url, &client) != WYRELOG_E_OK)
    return 5;

  gint raw_rc = check_raw_decide_contract (base_url);
  if (raw_rc != 0)
    return raw_rc;
  gint decision = -1;
  if (wyl_client_decide (client, "http-allow-user", "http.allow",
          "http-allow-scope", &decision) != WYRELOG_E_OK)
    return 8;
  if (decision != WYL_DECISION_ALLOW)
    return 9;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
          "wr.audit.read", "http-guard-scope", 123, "public", 69,
          &decision) != WYRELOG_E_OK)
    return 10;
  if (decision != WYL_DECISION_ALLOW)
    return 11;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
          "wr.audit.read", "http-guard-scope", 123, "public", 70,
          &decision) != WYRELOG_E_OK)
    return 12;
  if (decision != WYL_DECISION_DENY)
    return 13;

#ifdef WYL_HAS_AUDIT
  gint audit_rc = check_audit_event_present (client,
      "action(\"http.not_armed\")",
      "http-deny-user", "http.not_armed", "http-deny-scope",
      WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"http.allow\")",
      "http-allow-user", "http.allow", "http-allow-scope",
      WYL_DECISION_ALLOW, NULL, NULL);
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"wr.audit.read\")",
      "http-guard-user", "wr.audit.read", "http-guard-scope",
      WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"wr.audit.read\")",
      "http-guard-user", "wr.audit.read", "http-guard-scope",
      WYL_DECISION_ALLOW, NULL, NULL);
  if (audit_rc != 0)
    return audit_rc;
#endif

  raw_rc = check_raw_login_contract (base_url);
  if (raw_rc != 0)
    return raw_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
