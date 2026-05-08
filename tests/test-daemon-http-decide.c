/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>
#ifdef WYL_HAS_AUDIT
#include <duckdb.h>
#endif

#include "daemon/delta.h"
#include "daemon/http.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-request-id-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

typedef struct
{
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  const gchar *request_id;
  gboolean check_decision;
  wyl_decision_t decision;
  guint matches;
} AuditEventProbe;

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *state;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PermissionStateProbe;

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t audit_event_probe_cb (const gchar * id,
    gint64 created_at_us, const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, const gchar * request_id,
    wyl_decision_t decision, gpointer user_data);
#endif

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
  if (!is_request_id_shape (request_id))
    return failure_code;
  return 0;
}

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
send_raw_path (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, guint *out_status,
    gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 1900;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  g_autofree gchar *uri = g_strdup_printf ("%s%s", root, path);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1901;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 1902;
  gint rc = check_response_request_id_header (msg, 1903);
  if (rc != 0)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (bytes, &body_size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (body_data, body_size);
  return 0;
}

static gint
check_readyz_runtime_liveness_contract (const gchar *base_url,
    WylDaemonRuntime *runtime)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (send_raw_path (session, "GET", base_url, "/healthz", &status, &body)
      != 0)
    return 1904;
  if (status != 200 || strstr (body, "ok") == NULL)
    return 1905;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/healthz?format=json", &status,
          &body) != 0)
    return 1921;
  if (status != 200 || strstr (body, "\"status\":\"ok\"") == NULL)
    return 1922;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1906;
  if (status != 200 || strstr (body, "ready") == NULL)
    return 1907;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
          &body) != 0)
    return 1923;
  if (status != 200 || strstr (body, "\"status\":\"ready\"") == NULL)
    return 1924;

  g_atomic_int_set (&runtime->delta_session_live, FALSE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1908;
  if (status != 503 || strstr (body, "\"delta_not_ready\"") == NULL)
    return 1909;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
          &body) != 0)
    return 1925;
  if (status != 503 || strstr (body, "\"status\":\"not_ready\"") == NULL ||
      strstr (body, "\"reason\":\"delta_not_ready\"") == NULL)
    return 1926;

  g_atomic_int_set (&runtime->delta_session_live, TRUE);
  g_atomic_int_set (&runtime->audit_degraded, TRUE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1910;
  if (status != 503 || strstr (body, "\"audit_degraded\"") == NULL)
    return 1911;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
          &body) != 0)
    return 1927;
  if (status != 503 || strstr (body, "\"status\":\"not_ready\"") == NULL ||
      strstr (body, "\"reason\":\"audit_degraded\"") == NULL)
    return 1928;

  g_atomic_int_set (&runtime->audit_degraded, FALSE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1912;
  return status == 200 ? 0 : 1913;
}

static gint
send_raw_decide_authorization_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, const gchar *authorization,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 30;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri =
      build_decide_uri (base_url, user, perm, scope, extra_query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 31;
  if (authorization != NULL)
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (body == NULL)
    return 32;
  gint rc = check_response_request_id_header (msg, 50);
  if (rc != 0)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (body_data, body_size);
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  return 0;
}

static gint
send_raw_decide_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  return send_raw_decide_authorization_full (session, method, base_url, user,
      perm, scope, extra_query, NULL, out_status, out_body, out_request_id);
}

static gint
send_raw_decide_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, const gchar *access_token,
    guint *out_status, gchar **out_body)
{
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
      access_token);
  return send_raw_decide_authorization_full (session, method, base_url, user,
      perm, scope, extra_query, authorization, out_status, out_body, NULL);
}

static gint
send_raw_decide (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, guint *out_status,
    gchar **out_body)
{
  return send_raw_decide_full (session, method, base_url, user, perm, scope,
      extra_query, out_status, out_body, NULL);
}

static gint
send_request_id_probe (SoupSession *session, const gchar *method,
    const gchar *uri, const gchar *inbound_request_id, guint *out_status,
    gchar **out_request_id)
{
  if (out_status == NULL || out_request_id == NULL)
    return 1800;
  *out_status = 0;
  *out_request_id = NULL;

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1801;
  if (inbound_request_id != NULL) {
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "X-Wyrelog-Request-Id", inbound_request_id);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (body == NULL)
    return 1802;
  *out_status = soup_message_get_status (msg);
  const gchar *request_id = soup_message_headers_get_one
      (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
  gint rc = check_response_request_id_header (msg, 1803);
  if (rc != 0)
    return rc;
  *out_request_id = g_strdup (request_id);
  return 0;
}

static gint
check_request_id_header_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  guint status = 0;
  g_autofree gchar *health_id = NULL;
  g_autofree gchar *health_uri = g_strdup_printf ("%s/healthz", root);
  gint rc = send_request_id_probe (session, "GET", health_uri, NULL, &status,
      &health_id);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1804;

  g_autofree gchar *bad_decide_id = NULL;
  g_autofree gchar *bad_decide_uri =
      g_strdup_printf ("%s/decide?user=request-id-user", root);
  rc = send_request_id_probe (session, "POST", bad_decide_uri, NULL, &status,
      &bad_decide_id);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 1805;
  if (g_strcmp0 (health_id, bad_decide_id) == 0)
    return 1806;

  g_autofree gchar *spoofed_id = NULL;
  g_autofree gchar *deny_uri =
      build_decide_uri (root, "request-id-user", "wr.audit.read",
      "request-id-scope", NULL);
  rc = send_request_id_probe (session, "POST", deny_uri, "attacker", &status,
      &spoofed_id);
  if (rc != 0)
    return rc;
  if (status != 401)
    return 1807;
  if (g_strcmp0 (spoofed_id, "attacker") == 0)
    return 1808;
  if (g_strcmp0 (bad_decide_id, spoofed_id) == 0)
    return 1809;

  return 0;
}

static gint
check_raw_decide_contract (WylHandle *handle, const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autoptr (WylClient) deny_client = NULL;
  g_autoptr (WylClient) guard_client = NULL;

  if (wyl_client_new (base_url, &deny_client) != WYRELOG_E_OK ||
      wyl_client_new (base_url, &guard_client) != WYRELOG_E_OK)
    return 1813;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (deny_client, "http-deny-user")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1814;
  }
  if (wyl_client_login_skip_mfa (guard_client, "http-guard-user")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1815;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  g_autofree gchar *deny_access_token =
      wyl_client_dup_access_token (deny_client);
  g_autofree gchar *guard_access_token =
      wyl_client_dup_access_token (guard_client);
  if (deny_access_token == NULL || guard_access_token == NULL)
    return 1816;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK ||
      insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1821;

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
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 1817;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-deny-user",
      "http.not_armed", "http-deny-scope", NULL, deny_access_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 34;
  if (strstr (body, "\"decision\":0") == NULL)
    return 35;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL &&
      strstr (body, "\"deny_reason\":null") == NULL)
    return 36;
  if (strstr (body, "\"deny_origin\":\"perm_state\"") == NULL &&
      strstr (body, "\"deny_origin\":null") == NULL)
    return 37;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-deny-user",
      "wr.audit.read", "http-guard-scope", NULL, guard_access_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"decide_denied\"") == NULL)
    return 1818;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope", NULL, guard_access_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 38;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL &&
      strstr (body, "\"deny_reason\":null") == NULL)
    return 39;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *allow_request_id = NULL;
  g_autofree gchar *guard_authorization = g_strdup_printf ("Bearer %s",
      guard_access_token);
  rc = send_raw_decide_authorization_full (session, "POST", base_url,
      "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      guard_authorization, &status, &body, &allow_request_id);
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
#ifdef WYL_HAS_AUDIT
  AuditEventProbe allow_audit = {
    .subject_id = "http-guard-user",
    .action = "wr.audit.read",
    .resource_id = "http-guard-scope",
    .request_id = allow_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &allow_audit) != WYRELOG_E_OK)
    return 1810;
  if (allow_audit.matches != 1)
    return 1811;
#else
  (void) handle;
#endif

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=70",
      guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 44;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 45;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public", guard_access_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 46;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=public&guard_risk=101",
      guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 47;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=abc&guard_loc_class=public&guard_risk=69",
      guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 48;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "guard_timestamp=123&guard_loc_class=unknown&guard_risk=69",
      guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 49;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "tenant=unknown&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=69", guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_decide_request\"") == NULL)
    return 1812;

  return 0;
}

static gint
send_raw_login_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (out_request_id != NULL)
    *out_request_id = NULL;
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
  gint rc = check_response_request_id_header (msg, 513);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  return 0;
}

static gint
send_raw_login (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body)
{
  return send_raw_login_full (session, method, base_url, query, out_status,
      out_body, NULL);
}

static gint
send_raw_refresh (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *refresh_token, guint *out_status,
    gchar **out_body)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = NULL;
  if (refresh_token != NULL) {
    g_autofree gchar *escaped = g_uri_escape_string (refresh_token, NULL, TRUE);
    uri = g_strdup_printf ("%s/auth/refresh?refresh_token=%s", root, escaped);
  } else {
    uri = g_strdup_printf ("%s/auth/refresh", root);
  }

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 2;
  gint rc = check_response_request_id_header (msg, 573);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gchar *
extract_json_string (const gchar *body, const gchar *name)
{
  g_autofree gchar *prefix = g_strdup_printf ("\"%s\":\"", name);
  const gchar *start = strstr (body, prefix);
  if (start == NULL)
    return NULL;
  start += strlen (prefix);
  const gchar *end = strchr (start, '"');
  if (end == NULL)
    return NULL;
  return g_strndup (start, (gsize) (end - start));
}

static gint
verify_login_access_token (const gchar *body, const gchar *session_token,
    const gchar *username, const gchar *principal_state, SoupServer *server)
{
  g_autofree gchar *access_token = extract_json_string (body, "access_token");
  if (access_token == NULL)
    return 530;

  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return 531;

  g_autoptr (GBytes) payload = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_access_token (access_token, secret,
      sizeof secret, "__wr_default_hs256", "wyrelogd", "wyrelog-client", now,
      &payload);
  memset (secret, 0, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return 532;

  gsize payload_len = 0;
  const gchar *payload_data = g_bytes_get_data (payload, &payload_len);
  g_autofree gchar *payload_text = g_strndup (payload_data, payload_len);
  g_autofree gchar *expected_sub = g_strdup_printf ("\"sub\":\"%s\"",
      username);
  g_autofree gchar *expected_state =
      g_strdup_printf ("\"principal_state_at_issue\":\"%s\"",
      principal_state);
  g_autofree gchar *expected_session =
      g_strdup_printf ("\"session_id\":\"%s\"", session_token);
  const gchar *expected_tenant = "\"tenant\":\"__wr_default\"";
  if (strstr (payload_text, expected_sub) == NULL ||
      strstr (payload_text, expected_state) == NULL ||
      strstr (payload_text, expected_session) == NULL ||
      strstr (payload_text, expected_tenant) == NULL)
    return 533;
  g_autofree gchar *jti = extract_json_string (payload_text, "jti");
  if (jti == NULL || g_strcmp0 (jti, session_token) == 0)
    return 534;
  return 0;
}

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t
sign_test_access_token_with_jti (SoupServer *server, const gchar *jti,
    const gchar *session_id, const gchar *subject,
    const gchar *principal_state, const gchar *issuer, const gchar *audience,
    gint64 issued_at, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;

  guint8 secret[32];
  wyrelog_error_t rc =
      wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_jwt_issue_input_t input = {
    .key_id = "__wr_default_hs256",
    .jti = jti,
    .subject = subject,
    .issuer = issuer,
    .audience = audience,
    .tenant = "__wr_default",
    .principal_state_at_issue = principal_state,
    .session_id = session_id,
    .issued_at = issued_at,
    .ttl_seconds = WYL_JWT_ACCESS_TTL_SECONDS,
  };
  rc = wyl_jwt_sign_hs256 (&input, secret, sizeof secret, out_token);
  memset (secret, 0, sizeof secret);
  return rc;
}

static wyrelog_error_t
sign_test_access_token (SoupServer *server, const gchar *session_id,
    const gchar *subject, const gchar *principal_state, const gchar *issuer,
    const gchar *audience, gint64 issued_at, gchar **out_token)
{
  return sign_test_access_token_with_jti (server, "test-access-token",
      session_id, subject, principal_state, issuer, audience, issued_at,
      out_token);
}
#endif

static gint
send_raw_logout_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 484;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = query != NULL ?
      g_strdup_printf ("%s/auth/logout?%s", root, query) :
      g_strdup_printf ("%s/auth/logout", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 485;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 486;
  gint rc = check_response_request_id_header (msg, 514);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_logout (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body)
{
  return send_raw_logout_full (session, method, base_url, query, out_status,
      out_body, NULL);
}

static gint
send_raw_logout_authorization_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *authorization,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 484;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = query != NULL ?
      g_strdup_printf ("%s/auth/logout?%s", root, query) :
      g_strdup_printf ("%s/auth/logout", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 485;
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 486;
  gint rc = check_response_request_id_header (msg, 515);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_logout_authorization (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *authorization,
    guint *out_status, gchar **out_body)
{
  return send_raw_logout_authorization_full (session, method, base_url, query,
      authorization, out_status, out_body, NULL);
}

static gint send_raw_policy_mutation (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, guint * out_status, gchar ** out_body);
static gint send_raw_policy_mutation_bearer (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, const gchar * access_token, guint * out_status,
    gchar ** out_body);
static wyrelog_error_t grant_policy_write_authority (WylHandle * handle,
    const gchar * subject, const gchar * scope);

typedef struct
{
  const gchar *session_id;
  const gchar *state;
  guint matches;
} SessionStateExpect;

static wyrelog_error_t
session_state_expect_cb (const gchar *session_id, const gchar *state,
    gpointer user_data)
{
  SessionStateExpect *expect = user_data;

  if (g_strcmp0 (session_id, expect->session_id) == 0 &&
      g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static gint
check_raw_login_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
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

  g_autofree gchar *denied_skip_request_id = NULL;
  rc = send_raw_login_full (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body,
      &denied_skip_request_id);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"login_denied\"") == NULL)
    return 473;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe denied_skip_audit = {
    .subject_id = "login-user",
    .action = "login_skip_mfa",
    .resource_id = "principal_state",
    .deny_reason = "skip_mfa_not_allowed",
    .deny_origin = "login_ingress",
    .request_id = denied_skip_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_DENY,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &denied_skip_audit) != WYRELOG_E_OK)
    return 1812;
  if (denied_skip_audit.matches != 1)
    return 1813;
#endif
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_grant_direct_permission (wyl_handle_get_policy_store
          (handle), "login-user", "wr.login.skip_mfa", "login")
      != WYRELOG_E_OK)
    return 484;
  if (wyl_policy_store_set_permission_state (wyl_handle_get_policy_store
          (handle), "login-user", "wr.login.skip_mfa", "login", "armed")
      != WYRELOG_E_OK)
    return 488;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 487;

  g_autofree gchar *skip_success_request_id = NULL;
  rc = send_raw_login_full (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body,
      &skip_success_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 485;
  g_autofree gchar *authenticated_session_token =
      extract_json_string (body, "session_token");
  if (authenticated_session_token == NULL)
    return 486;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe principal_skip_audit = {
    .subject_id = "login-user",
    .action = "login_skip_mfa",
    .resource_id = "principal_state",
    .request_id = skip_success_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &principal_skip_audit)
      != WYRELOG_E_OK)
    return 1814;
  if (principal_skip_audit.matches != 1)
    return 1815;
  AuditEventProbe session_skip_audit = {
    .subject_id = authenticated_session_token,
    .action = "session_state",
    .resource_id = "active",
    .deny_origin = "idle",
    .request_id = skip_success_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &session_skip_audit) != WYRELOG_E_OK)
    return 1816;
  if (session_skip_audit.matches != 1)
    return 1817;
#endif
  rc = verify_login_access_token (body, authenticated_session_token,
      "login-user", "authenticated", server);
  if (rc != 0)
    return rc;
  g_autofree gchar *login_access_token =
      extract_json_string (body, "access_token");
  g_autofree gchar *login_refresh_token =
      extract_json_string (body, "refresh_token");
  if (login_access_token == NULL || login_refresh_token == NULL)
    return 535;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "GET", base_url, login_refresh_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 536;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_refresh_request\"") == NULL)
    return 537;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL ||
      strstr (body, "\"access_token\":\"") == NULL ||
      strstr (body, "\"refresh_token\":\"") == NULL)
    return 538;
  g_autofree gchar *next_refresh_token =
      extract_json_string (body, "refresh_token");
  if (next_refresh_token == NULL ||
      g_strcmp0 (next_refresh_token, login_refresh_token) == 0)
    return 539;
  rc = verify_login_access_token (body, authenticated_session_token,
      "login-user", "authenticated", server);
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, next_refresh_token) == NULL)
    return 540;
  g_clear_pointer (&body, g_free);

  if (!wyl_daemon_http_expire_refresh_grace_for_test (server,
          login_refresh_token))
    return 541;
  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_reuse_detected\"") == NULL)
    return 542;
  g_clear_pointer (&body, g_free);

  rc = send_raw_decide_bearer (session, "POST", base_url, "login-user",
      "wr.login.skip_mfa", "login", NULL, login_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 543;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=false", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL ||
      strstr (body, "\"access_token\"") != NULL)
    return 474;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=maybe", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 481;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 482;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=1", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 483;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&password=secret", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 478;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&tenant=unknown", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 484;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=login-user",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"username\":\"login-user\"") == NULL ||
      strstr (body, "\"tenant\":\"__wr_default\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL ||
      strstr (body, "\"session_state\":\"active\"") == NULL)
    return 475;
  g_autofree gchar *session_token = extract_json_string (body, "session_token");
  if (session_token == NULL)
    return 476;
  g_autoptr (WylSession) stored_session =
      wyl_daemon_http_ref_session (server, session_token);
  if (stored_session == NULL)
    return 477;
  g_autofree gchar *stored_username = wyl_session_dup_username (stored_session);
  if (g_strcmp0 (stored_username, "login-user") != 0)
    return 479;
  g_autofree gchar *stored_tenant = wyl_session_dup_tenant (stored_session);
  if (g_strcmp0 (stored_tenant, "__wr_default") != 0)
    return 485;
  if (wyl_daemon_http_remove_session_for_test (server, "unknown-session"))
    return 481;
  if (!wyl_daemon_http_remove_session_for_test (server, session_token))
    return 482;
  g_autoptr (WylSession) removed_session =
      wyl_daemon_http_ref_session (server, session_token);
  if (removed_session != NULL)
    return 483;
  g_clear_pointer (&body, g_free);

  g_autoptr (WylSession) unknown_session =
      wyl_daemon_http_ref_session (server, "unknown-session");
  if (unknown_session != NULL)
    return 480;

  rc = send_raw_logout (session, "GET", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 487;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 488;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, "session_token=unknown",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 489;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=logout-user",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 490;
  g_autofree gchar *logout_session_token =
      extract_json_string (body, "session_token");
  if (logout_session_token == NULL)
    return 491;
  g_clear_pointer (&body, g_free);
  if (grant_policy_write_authority (handle, "logout-user",
          logout_session_token) != WYRELOG_E_OK)
    return 492;
  if (wyl_policy_store_upsert_permission (wyl_handle_get_policy_store (handle),
          "site.policy.read", "site policy read", "basic") != WYRELOG_E_OK)
    return 493;

  g_autofree gchar *logout_query = g_strdup_printf ("session_token=%s",
      logout_session_token);
  rc = send_raw_logout_authorization (session, "POST", base_url, logout_query,
      "Bearer ignored", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_logout_auth\"") == NULL)
    return 494;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *logout_request_id = NULL;
  rc = send_raw_logout_full (session, "POST", base_url, logout_query, &status,
      &body, &logout_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 495;
  g_autoptr (WylSession) logged_out_session =
      wyl_daemon_http_ref_session (server, logout_session_token);
  if (logged_out_session != NULL)
    return 496;
  SessionStateExpect closed_expect = {
    .session_id = logout_session_token,
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
          (handle), session_state_expect_cb, &closed_expect) != WYRELOG_E_OK)
    return 497;
  if (closed_expect.matches != 1)
    return 498;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe close_audit = {
    .subject_id = logout_session_token,
    .action = "session_state",
    .resource_id = "closed",
    .deny_origin = "active",
    .request_id = logout_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &close_audit) != WYRELOG_E_OK)
    return 1818;
  if (close_audit.matches != 1)
    return 1819;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *guarded_query = g_strdup_printf ("session_token=%s"
      "&subject=after-logout&perm=site.policy.read&scope=after-logout"
      "&guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      logout_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", guarded_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 499;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, logout_query, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 500;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
      "Bearer malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 501;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  rc = send_raw_login (session, "POST", base_url,
      "username=bearer-logout-user&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 502;
  g_autofree gchar *bearer_logout_session_token =
      extract_json_string (body, "session_token");
  if (bearer_logout_session_token == NULL)
    return 503;
  g_autofree gchar *bearer_logout_access_token =
      extract_json_string (body, "access_token");
  if (bearer_logout_access_token == NULL)
    return 504;
  g_autofree gchar *bearer_logout_refresh_token =
      extract_json_string (body, "refresh_token");
  if (bearer_logout_refresh_token == NULL)
    return 524;
  g_clear_pointer (&body, g_free);
  if (grant_policy_write_authority (handle, "bearer-logout-user",
          bearer_logout_session_token) != WYRELOG_E_OK)
    return 505;

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
      "Bearer", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 506;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_logout_query = g_strdup_printf ("session_token=%s",
      bearer_logout_session_token);
  g_autofree gchar *bearer_authorization = g_strdup_printf ("Bearer %s",
      bearer_logout_access_token);
  rc = send_raw_logout_authorization (session, "POST", base_url,
      bearer_logout_query, bearer_authorization, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_logout_auth\"") == NULL)
    return 507;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_logout_request_id = NULL;
  rc = send_raw_logout_authorization_full (session, "POST", base_url, NULL,
      bearer_authorization, &status, &body, &bearer_logout_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 508;
  g_autoptr (WylSession) bearer_logged_out_session =
      wyl_daemon_http_ref_session (server, bearer_logout_session_token);
  if (bearer_logged_out_session != NULL)
    return 509;
  /*
   * Refresh token captured at login must be rejected after the
   * bearer logout completes. The teardown order in logout_handler
   * revokes refresh tokens before driving the session FSM, so the
   * window during which a captured refresh could rotate into a
   * fresh access/refresh pair is closed before the public reply
   * lands at the caller.
   */
  g_clear_pointer (&body, g_free);
  rc = send_raw_refresh (session, "POST", base_url,
      bearer_logout_refresh_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 525;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe bearer_close_audit = {
    .subject_id = bearer_logout_session_token,
    .action = "session_state",
    .resource_id = "closed",
    .deny_origin = "active",
    .request_id = bearer_logout_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
          (handle), audit_event_probe_cb, &bearer_close_audit) != WYRELOG_E_OK)
    return 1820;
  if (bearer_close_audit.matches != 1)
    return 1821;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_guarded_query =
      g_strdup_printf ("subject=after-bearer-logout&perm=site.policy.read"
      "&scope=after-bearer-logout&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=69");
  rc = send_raw_policy_mutation_bearer (session, "POST", base_url,
      "/policy/permissions/grant", bearer_guarded_query,
      bearer_logout_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 510;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
      bearer_authorization, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 511;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, bearer_logout_query,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 512;

  return 0;
}

static gchar *
build_policy_mutation_uri (const gchar *base_url, const gchar *path,
    const gchar *query)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  if (query == NULL)
    return g_strdup_printf ("%s%s", root, path);
  return g_strdup_printf ("%s%s?%s", root, path, query);
}

static gint
send_raw_policy_mutation_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 177);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_policy_mutation (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    guint *out_status, gchar **out_body)
{
  return send_raw_policy_mutation_full (session, method, base_url, path, query,
      out_status, out_body, NULL);
}

static gint
send_raw_policy_mutation_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *access_token, guint *out_status, gchar **out_body)
{
  if (access_token == NULL)
    return 164;
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
      access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 178);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

typedef struct
{
  const gchar *base_url;
  gchar *query;
  gint rc;
  guint status;
  gchar *body;
} ConcurrentPolicyMutation;

static gpointer
concurrent_permission_grant_thread (gpointer user_data)
{
  ConcurrentPolicyMutation *mutation = user_data;
  g_autoptr (SoupSession) session = soup_session_new ();

  mutation->rc = send_raw_policy_mutation (session, "POST",
      mutation->base_url, "/policy/permissions/grant", mutation->query,
      &mutation->status, &mutation->body);
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

static gboolean
direct_permission_exists (WylHandle *handle, const gchar *subject,
    const gchar *perm, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_direct_permission_exists (store, subject, perm, scope,
          &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static gboolean
permission_state_exists (WylHandle *handle, const gchar *subject,
    const gchar *perm, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_permission_state_exists (store, subject, perm, scope,
          &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static wyrelog_error_t
audit_event_probe_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  AuditEventProbe *probe = user_data;

  if ((!probe->check_decision || decision == probe->decision)
      && g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (action, probe->action) == 0
      && g_strcmp0 (resource_id, probe->resource_id) == 0
      && g_strcmp0 (deny_reason, probe->deny_reason) == 0
      && g_strcmp0 (deny_origin, probe->deny_origin) == 0) {
    if (probe->request_id == NULL
        || g_strcmp0 (request_id, probe->request_id) == 0)
      probe->matches++;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
permission_state_probe_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, const gchar *state, gpointer user_data)
{
  PermissionStateProbe *probe = user_data;

  if (g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (perm_id, probe->perm_id) == 0
      && g_strcmp0 (scope, probe->scope) == 0
      && g_strcmp0 (state, probe->state) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
permission_state_event_probe_cb (gint64 event_id, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  (void) event_id;
  PermissionStateProbe *probe = user_data;

  if (g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (perm_id, probe->perm_id) == 0
      && g_strcmp0 (scope, probe->scope) == 0
      && g_strcmp0 (event, probe->event) == 0
      && g_strcmp0 (from_state, probe->from_state) == 0
      && g_strcmp0 (to_state, probe->to_state) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static gboolean
role_membership_exists (WylHandle *handle, const gchar *subject,
    const gchar *role, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_role_membership_exists (store, subject, role, scope,
          &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static gint
check_concurrent_permission_grants_serialize (WylHandle *handle,
    const gchar *base_url, const gchar *session_token)
{
  static const guint n_threads = 4;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (wyl_policy_store_upsert_permission (store, "site.concurrent.read",
          "site concurrent read", "basic") != WYRELOG_E_OK)
    return 204;

  ConcurrentPolicyMutation mutations[n_threads];
  GThread *threads[n_threads];
  gint result = 0;
  memset (mutations, 0, sizeof mutations);
  memset (threads, 0, sizeof threads);

  for (guint i = 0; i < n_threads; i++) {
    mutations[i].base_url = base_url;
    mutations[i].query =
        g_strdup_printf ("subject=concurrent-target"
        "&perm=site.concurrent.read&scope=tenant-a"
        "&session_token=%s&guard_timestamp=123"
        "&guard_loc_class=public&guard_risk=49", session_token);
    g_autofree gchar *name = g_strdup_printf ("policy-grant-%u", i);
    threads[i] = g_thread_new (name, concurrent_permission_grant_thread,
        &mutations[i]);
  }

  for (guint i = 0; i < n_threads; i++)
    g_thread_join (threads[i]);

  for (guint i = 0; i < n_threads; i++) {
    if (mutations[i].rc != 0) {
      result = 205;
      goto cleanup;
    }
    if (mutations[i].status != 200
        || strstr (mutations[i].body, "\"ok\":true") == NULL) {
      result = 206;
      goto cleanup;
    }
  }

  if (!direct_permission_exists (handle, "concurrent-target",
          "site.concurrent.read", "tenant-a")) {
    result = 207;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  AuditEventProbe grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_grant",
    .resource_id = "tenant-a",
    .deny_origin = "site.concurrent.read",
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &grant_audit) != WYRELOG_E_OK) {
    result = 208;
    goto cleanup;
  }
  if (grant_audit.matches != n_threads) {
    result = 209;
    goto cleanup;
  }
#endif

cleanup:
  for (guint i = 0; i < n_threads; i++) {
    g_free (mutations[i].query);
    g_free (mutations[i].body);
  }
  return result;
}

static gint
check_policy_permission_mutation_contract (WylHandle *handle,
    WylClient *client, const gchar *base_url)
{
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-policy-admin") != WYRELOG_E_OK)
    return 123;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  g_autofree gchar *session_token = wyl_client_dup_session_token (client);
  g_autofree gchar *access_token = wyl_client_dup_access_token (client);
  g_autofree gchar *client_tenant = wyl_client_dup_tenant (client);
  if (session_token == NULL)
    return 124;
  if (access_token == NULL)
    return 164;
  if (g_strcmp0 (client_tenant, "__wr_default") != 0)
    return 165;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "site.policy.read",
          "site policy read", "basic") != WYRELOG_E_OK)
    return 125;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  gint rc = send_raw_policy_mutation (session, "GET", base_url,
      "/policy/permissions/grant", "subject=target&perm=site.policy.read"
      "&scope=tenant-a", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 126;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "GET", base_url,
      "/policy/permissions/transition", "subject=state-target"
      "&perm=site.policy.read&scope=tenant-a&event=grant", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 167;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", "perm=site.policy.read&scope=tenant-a",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 127;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/transition",
      "subject=state-target&perm=site.policy.read&scope=tenant-a",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 168;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/transition",
      "subject=state-target&perm=site.policy.read&scope=tenant-a&event=nope",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 169;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", "subject=target&perm=site.policy.read"
      "&scope=tenant-a&session_token=unknown&guard_timestamp=abc"
      "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_auth\"") == NULL)
    return 128;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", "subject=target&perm=site.policy.read"
      "&scope=tenant-a&session_token=unknown&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 129;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", "subject=target&perm=site.missing"
      "&scope=tenant-a&session_token=unknown&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 153;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *denied_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 130;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a")) {
    return 131;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *unknown_tenant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&tenant=unknown&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", unknown_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_auth\"") == NULL)
    return 187;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a")) {
    return 188;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *transition_denied_query =
      g_strdup_printf ("subject=state-target&perm=site.policy.read"
      "&scope=tenant-a&event=grant&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/transition", transition_denied_query, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 170;
  if (permission_state_exists (handle, "state-target", "site.policy.read",
          "tenant-a"))
    return 171;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *missing_perm_grant_query =
      g_strdup_printf ("subject=target&perm=site.missing&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", missing_perm_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 154;
  g_clear_pointer (&body, g_free);

  if (grant_policy_write_authority (handle, "http-policy-admin",
          "tenant-a") != WYRELOG_E_OK)
    return 132;

  gint concurrent_rc = check_concurrent_permission_grants_serialize (handle,
      base_url, session_token);
  if (concurrent_rc != 0)
    return concurrent_rc;

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", missing_perm_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 155;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *missing_perm_transition_query =
      g_strdup_printf ("subject=state-target&perm=site.missing"
      "&scope=tenant-a&event=grant&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/transition", missing_perm_transition_query,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 172;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *invalid_edge_transition_query =
      g_strdup_printf ("subject=state-target&perm=site.policy.read"
      "&scope=tenant-a&event=revoke&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/transition", invalid_edge_transition_query,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 173;
  if (permission_state_exists (handle, "state-target", "site.policy.read",
          "tenant-a"))
    return 174;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *guard_denied_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=50", session_token);
  g_autofree gchar *guard_denied_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
      "/policy/permissions/grant", guard_denied_query, &status, &body,
      &guard_denied_request_id);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 133;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 134;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe guard_denied_audit = {
    .subject_id = "http-policy-admin",
    .action = "wr.policy.write",
    .resource_id = "tenant-a",
    .deny_reason = "not_armed",
    .deny_origin = "perm_state",
    .request_id = guard_denied_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_DENY,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &guard_denied_audit) != WYRELOG_E_OK)
    return 200;
  if (guard_denied_audit.matches != 1)
    return 201;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *transition_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
      "/policy/permissions/transition", transition_denied_query, &status,
      &body, &transition_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 175;
  if (!permission_state_exists (handle, "state-target", "site.policy.read",
          "tenant-a"))
    return 176;
  if (direct_permission_exists (handle, "state-target", "site.policy.read",
          "tenant-a"))
    return 177;
  AuditEventProbe transition_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_state.grant",
    .resource_id = "site.policy.read",
    .deny_reason = "grant",
    .deny_origin = "tenant-a",
    .request_id = transition_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &transition_audit) != WYRELOG_E_OK)
    return 178;
  if (transition_audit.matches != 1)
    return 179;
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_set_principal_state (store, "client-state-target",
          "authenticated") != WYRELOG_E_OK)
    return 180;
  if (wyl_policy_store_set_session_state (store, "tenant-a", "active")
      != WYRELOG_E_OK)
    return 181;
  if (wyl_client_policy_permission_transition (client, "client-state-target",
          "site.policy.read", "tenant-a", "grant", 123, "public", 49)
      != WYRELOG_E_OK)
    return 182;
  if (!permission_state_exists (handle, "client-state-target",
          "site.policy.read", "tenant-a"))
    return 183;
  if (direct_permission_exists (handle, "client-state-target",
          "site.policy.read", "tenant-a"))
    return 184;
  PermissionStateProbe state_probe = {
    .subject_id = "client-state-target",
    .perm_id = "site.policy.read",
    .scope = "tenant-a",
    .state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state (store,
          permission_state_probe_cb, &state_probe) != WYRELOG_E_OK)
    return 185;
  if (state_probe.matches != 1)
    return 186;
  PermissionStateProbe event_probe = {
    .subject_id = "client-state-target",
    .perm_id = "site.policy.read",
    .scope = "tenant-a",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
          permission_state_event_probe_cb, &event_probe) != WYRELOG_E_OK)
    return 187;
  if (event_probe.matches != 1)
    return 188;
  AuditEventProbe client_transition_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_state.grant",
    .resource_id = "site.policy.read",
    .deny_reason = "grant",
    .deny_origin = "tenant-a",
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &client_transition_audit) != WYRELOG_E_OK)
    return 194;
  if (client_transition_audit.matches != 2)
    return 195;
  g_autoptr (wyl_decide_req_t) client_state_decide = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) client_state_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (client_state_decide, "client-state-target");
  wyl_decide_req_set_action (client_state_decide, "site.policy.read");
  wyl_decide_req_set_resource_id (client_state_decide, "tenant-a");
  if (wyl_decide (handle, client_state_decide, client_state_resp)
      != WYRELOG_E_OK)
    return 189;
  if (wyl_decide_resp_get_decision (client_state_resp) != WYL_DECISION_DENY)
    return 190;
  if (wyl_client_policy_permission_grant (client, "client-state-target",
          "site.policy.read", "tenant-a", 123, "public", 49)
      != WYRELOG_E_OK)
    return 191;
  g_autoptr (wyl_decide_req_t) client_grant_decide = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) client_grant_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (client_grant_decide, "client-state-target");
  wyl_decide_req_set_action (client_grant_decide, "site.policy.read");
  wyl_decide_req_set_resource_id (client_grant_decide, "tenant-a");
  if (wyl_decide (handle, client_grant_decide, client_grant_resp)
      != WYRELOG_E_OK)
    return 192;
  if (wyl_decide_resp_get_decision (client_grant_resp) != WYL_DECISION_ALLOW)
    return 193;

  g_autofree gchar *grant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=49", session_token);
  g_autofree gchar *grant_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
      "/policy/permissions/grant", grant_query, &status, &body,
      &grant_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 135;
  if (!direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 136;
  if (permission_state_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 204;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_grant",
    .resource_id = "tenant-a",
    .deny_origin = "site.policy.read",
    .request_id = grant_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &grant_audit) != WYRELOG_E_OK)
    return 196;
  if (grant_audit.matches != 1)
    return 197;
  AuditEventProbe grant_auth_audit = {
    .subject_id = "http-policy-admin",
    .action = "wr.policy.write",
    .resource_id = "tenant-a",
    .request_id = grant_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &grant_auth_audit) != WYRELOG_E_OK)
    return 202;
  if (grant_auth_audit.matches != 1)
    return 203;
#endif
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation_bearer (session, "POST", base_url,
      "/policy/permissions/grant",
      "subject=bearer-target&perm=site.policy.read&scope=tenant-a"
      "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
      access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 165;
  if (!direct_permission_exists (handle, "bearer-target", "site.policy.read",
          "tenant-a"))
    return 166;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *builtin_grant_query =
      g_strdup_printf ("subject=builtin-target&perm=wr.stream.read"
      "&scope=tenant-a&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", builtin_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 156;
  if (!direct_permission_exists (handle, "builtin-target", "wr.stream.read",
          "tenant-a"))
    return 157;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/revoke", builtin_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 158;
  if (direct_permission_exists (handle, "builtin-target", "wr.stream.read",
          "tenant-a"))
    return 159;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/revoke", grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 137;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 138;

  g_autofree gchar *missing_perm_revoke_query =
      g_strdup_printf ("subject=target&perm=site.missing&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=49", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/revoke", missing_perm_revoke_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 149;

  if (wyl_policy_store_upsert_role (store, "site.reader",
          "site reader") != WYRELOG_E_OK)
    return 139;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", "subject=role-target&role=site.missing"
      "&scope=tenant-b&session_token=unknown&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=29", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 150;

  g_autofree gchar *role_denied_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", role_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 140;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 141;

  g_autofree gchar *role_missing_denied_query =
      g_strdup_printf ("subject=role-target&role=site.missing&scope=tenant-b"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", role_missing_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 151;

  if (grant_policy_role_authority (handle, "http-policy-admin",
          "tenant-b") != WYRELOG_E_OK)
    return 142;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", role_missing_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 152;

  g_autofree gchar *role_guard_denied_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=30", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", role_guard_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 143;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 144;

  g_autofree gchar *role_grant_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  g_autofree gchar *role_grant_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
      "/policy/roles/grant", role_grant_query, &status, &body,
      &role_grant_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 145;
  if (!role_membership_exists (handle, "role-target", "site.reader",
          "tenant-b"))
    return 146;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe role_grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "role_grant",
    .resource_id = "tenant-b",
    .deny_origin = "site.reader",
    .request_id = role_grant_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
          &role_grant_audit) != WYRELOG_E_OK)
    return 198;
  if (role_grant_audit.matches != 1)
    return 199;
#endif

  g_autofree gchar *builtin_role_query =
      g_strdup_printf ("subject=builtin-role-target&role=wr.auditor"
      "&scope=tenant-b&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", builtin_role_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 160;
  if (!role_membership_exists (handle, "builtin-role-target", "wr.auditor",
          "tenant-b"))
    return 161;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/revoke", builtin_role_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 162;
  if (role_membership_exists (handle, "builtin-role-target", "wr.auditor",
          "tenant-b"))
    return 163;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/revoke", role_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 147;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 148;

  return 0;
}

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t
grant_audit_read (WylHandle *handle, const gchar *subject_id,
    const gchar *scope)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-audit-role",
      "wr.audit.read");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject_id,
      "wr.http-audit-role", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject_id,
      "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static gchar *
build_audit_uri (const gchar *base_url, const gchar *query)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  if (query == NULL)
    return g_strdup_printf ("%s/audit/events", root);
  return g_strdup_printf ("%s/audit/events?%s", root, query);
}

static gint
send_raw_audit (SoupSession *session, const gchar *base_url,
    const gchar *query, guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 90;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_audit_uri (base_url, query);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL)
    return 91;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 92;
  gint rc = check_response_request_id_header (msg, 110);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_audit_bearer_full (SoupSession *session, const gchar *base_url,
    const gchar *query, const gchar *access_token, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (access_token == NULL)
    return 89;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri = build_audit_uri (base_url, query);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL)
    return 91;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
      access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 92;
  gint rc = check_response_request_id_header (msg, 111);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_audit_bearer (SoupSession *session, const gchar *base_url,
    const gchar *query, const gchar *access_token, guint *out_status,
    gchar **out_body)
{
  return send_raw_audit_bearer_full (session, base_url, query, access_token,
      out_status, out_body, NULL);
}

static gint
runtime_audit_events_table_exists (WylHandle *handle, gboolean *out_exists)
{
  if (handle == NULL || out_exists == NULL)
    return 102;

  *out_exists = FALSE;
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };
  duckdb_state rc = duckdb_query (conn,
      "SELECT COUNT(*) FROM audit_events;", &result);
  duckdb_destroy_result (&result);
  *out_exists = rc == DuckDBSuccess;
  return 0;
}

static gint
check_raw_audit_contract (SoupServer *server, WylHandle *handle,
    WylClient *client, const gchar *base_url, const gchar *session_token,
    const gchar *access_token)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  gboolean audit_table_exists = TRUE;

  gint rc = send_raw_audit (session, base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 93;
  if (runtime_audit_events_table_exists (handle, &audit_table_exists) != 0
      || audit_table_exists)
    return 103;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit (session, base_url,
      "session_token=unknown&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=69", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 94;
  if (runtime_audit_events_table_exists (handle, &audit_table_exists) != 0
      || audit_table_exists)
    return 104;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit (session, base_url,
      "session_token=unknown&guard_timestamp=abc&guard_loc_class=public"
      "&guard_risk=69", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 101;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *malformed =
      g_strdup_printf ("session_token=%s&guard_timestamp=abc"
      "&guard_loc_class=public&guard_risk=69", session_token);
  rc = send_raw_audit (session, base_url, malformed, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 95;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *denied =
      g_strdup_printf ("session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=70", session_token);
  rc = send_raw_audit (session, base_url, denied, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"audit_denied\"") == NULL)
    return 98;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bearer_allowed =
      g_strdup_printf ("guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=69");
  g_autofree gchar *bearer_allowed_request_id = NULL;
  rc = send_raw_audit_bearer_full (session, base_url, bearer_allowed,
      access_token, &status, &body, &bearer_allowed_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "[") == NULL)
    return 106;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bearer_unknown_tenant =
      g_strdup_printf ("tenant=unknown&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=69");
  rc = send_raw_audit_bearer (session, base_url, bearer_unknown_tenant,
      access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 163;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *request_filter =
      g_strdup_printf ("request_id(\"%s\")", bearer_allowed_request_id);
  g_autofree gchar *escaped_request_filter =
      g_uri_escape_string (request_filter, NULL, TRUE);
  g_autofree gchar *request_filter_query =
      g_strdup_printf ("filter=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=69", escaped_request_filter);
  rc = send_raw_audit_bearer (session, base_url, request_filter_query,
      access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"subject_id\":\"http-audit-user\"") == NULL ||
      strstr (body, "\"action\":\"wr.audit.read\"") == NULL ||
      strstr (body, "\"request_id\":\"") == NULL ||
      strstr (body, bearer_allowed_request_id) == NULL)
    return 160;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *mixed =
      g_strdup_printf ("session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=69", session_token);
  rc = send_raw_audit_bearer (session, base_url, mixed, access_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 107;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
      "guard_timestamp=abc&guard_loc_class=public&guard_risk=69",
      "malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 108;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
      "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      "malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 109;

  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  const struct
  {
    const gchar *session_id;
    const gchar *subject;
    const gchar *principal_state;
    const gchar *issuer;
    const gchar *audience;
    gint64 issued_at_delta;
    gint failure_code;
  } invalid_tokens[] = {
    {"unknown-session", "http-audit-user", "authenticated", "wyrelogd",
        "wyrelog-client", 0, 110},
    {session_token, "other-user", "authenticated", "wyrelogd",
        "wyrelog-client", 0, 111},
    {session_token, "http-audit-user", "mfa_required", "wyrelogd",
        "wyrelog-client", 0, 112},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
        "other-audience", 0, 113},
    {session_token, "http-audit-user", "authenticated", "other-issuer",
        "wyrelog-client", 0, 116},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
        "wyrelog-client", -1000, 114},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
        "wyrelog-client", 60, 115},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_tokens); i++) {
    g_autofree gchar *bad_token = NULL;
    if (sign_test_access_token (server, invalid_tokens[i].session_id,
            invalid_tokens[i].subject, invalid_tokens[i].principal_state,
            invalid_tokens[i].issuer, invalid_tokens[i].audience,
            now + invalid_tokens[i].issued_at_delta, &bad_token)
        != WYRELOG_E_OK)
      return invalid_tokens[i].failure_code + 40;

    g_clear_pointer (&body, g_free);
    rc = send_raw_audit_bearer (session, base_url,
        "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
        bad_token, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
      return invalid_tokens[i].failure_code;
  }

  g_autofree gchar *unregistered_token = NULL;
  if (sign_test_access_token_with_jti (server, "unregistered-access-token",
          session_token, "http-audit-user", "authenticated", "wyrelogd",
          "wyrelog-client", now, &unregistered_token) != WYRELOG_E_OK)
    return 161;
  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
      "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      unregistered_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 162;

  g_autofree gchar *session_jti_token = NULL;
  if (sign_test_access_token_with_jti (server, session_token, session_token,
          "http-audit-user", "authenticated", "wyrelogd", "wyrelog-client",
          now, &session_jti_token) != WYRELOG_E_OK)
    return 158;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
      "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
      session_jti_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 159;

  g_autoptr (WylAuditIter) invalid_filter = NULL;
  if (wyl_client_audit_query_with_guard_context (client, "action()", 123,
          "public", 69, &invalid_filter) != WYRELOG_E_OK)
    return 99;
  gboolean has_next = FALSE;
  if (wyl_audit_iter_next (invalid_filter, &has_next) != WYRELOG_E_IO)
    return 100;

  return 0;
}

static wyrelog_error_t
drop_runtime_audit_events_table (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };

  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
malform_runtime_audit_events_table (WylHandle *handle)
{
  wyrelog_error_t rc = drop_runtime_audit_events_table (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };
  if (duckdb_query (conn,
          "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static gint
check_readyz_malformed_audit_projection_contract (WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (malform_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 1914;
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1915;
  if (status != 503 || strstr (body, "\"audit_degraded\"") == NULL)
    return 1916;

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 1917;
  if (wyl_audit_conn_create_schema (wyl_handle_get_audit_conn (handle))
      != WYRELOG_E_OK)
    return 1918;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1919;
  return status == 200 ? 0 : 1920;
}

static gint
check_audit_event_present (WylClient *client, const gchar *filter,
    const gchar *subject, const gchar *action, const gchar *resource,
    wyl_decision_t decision, const gchar *deny_reason, const gchar *deny_origin)
{
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query_with_guard_context (client, filter, 123,
          "public", 69, &iter) != WYRELOG_E_OK)
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

/*
 * The daemon-http-decide test surface has been split across two binaries
 * compiled from this single translation unit:
 *
 *   - WYL_TEST_VARIANT_AUDIT undefined: HTTP-decide protocol contracts
 *     (readyz, request-id headers, raw decide, policy mutation, raw login)
 *     plus the login + decide and login + guarded-decide flows.
 *
 *   - WYL_TEST_VARIANT_AUDIT defined: end-to-end audit pipeline. Generates
 *     the decide and policy events the audit verification depends on, then
 *     verifies the audit log via raw HTTP, the readyz audit-projection
 *     contract, and a series of audit_event_present queries.
 *
 * Splitting was driven by Meson's per-test 30s timeout: under CI parallel
 * scheduling the merged test serialised on local TCP and DuckDB and crossed
 * the wall-clock ceiling. Both variants now run in parallel, each with its
 * own daemon, and each finishes well under the timeout. Variant-irrelevant
 * static helpers stay defined in this file; the build silences the
 * resulting -Wunused-function warnings.
 */
#ifndef WYL_TEST_VARIANT_AUDIT
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
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
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

  gint readyz_rc = check_readyz_runtime_liveness_contract (base_url, &runtime);
  if (readyz_rc != 0)
    return readyz_rc;

  gint request_id_rc = check_request_id_header_contract (base_url);
  if (request_id_rc != 0)
    return request_id_rc;

  gint raw_rc = check_raw_decide_contract (handle, base_url);
  if (raw_rc != 0)
    return raw_rc;
  gint decision = -1;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-allow-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1819;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 1822;
  if (wyl_client_decide (client, "http-allow-user", "http.allow",
          "http-allow-scope", &decision) != WYRELOG_E_OK)
    return 8;
  if (decision != WYL_DECISION_ALLOW)
    return 9;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-guard-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1820;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1823;
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

  raw_rc = check_raw_login_contract (http.server, handle, base_url);
  if (raw_rc != 0)
    return raw_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#else /* WYL_TEST_VARIANT_AUDIT */
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
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide-audit",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (base_url, &client) != WYRELOG_E_OK)
    return 5;

  gint readyz_rc = check_readyz_malformed_audit_projection_contract (handle,
      base_url);
  if (readyz_rc != 0)
    return readyz_rc;

  /* Seed http.not_armed (http-deny-user) and other negative-decide audit
   * events that the audit_event_present series below relies on. The full
   * raw decide protocol contract is exercised in the non-audit variant. */
  gint raw_rc = check_raw_decide_contract (handle, base_url);
  if (raw_rc != 0)
    return raw_rc;
  gint decision = -1;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-allow-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1819;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 1822;
  if (wyl_client_decide (client, "http-allow-user", "http.allow",
          "http-allow-scope", &decision) != WYRELOG_E_OK)
    return 8;
  if (decision != WYL_DECISION_ALLOW)
    return 9;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-guard-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1820;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1823;
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

  raw_rc = check_policy_permission_mutation_contract (handle, client, base_url);
  if (raw_rc != 0)
    return raw_rc;

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-audit-user") != WYRELOG_E_OK)
    return 84;
  g_autofree gchar *audit_session_token = wyl_client_dup_session_token (client);
  g_autofree gchar *audit_access_token = wyl_client_dup_access_token (client);
  if (audit_session_token == NULL)
    return 85;
  if (audit_access_token == NULL)
    return 89;
  if (grant_audit_read (handle, "http-audit-user", audit_session_token) !=
      WYRELOG_E_OK)
    return 86;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 87;

  gint audit_auth_rc = check_raw_audit_contract (http.server, handle, client,
      base_url, audit_session_token, audit_access_token);
  if (audit_auth_rc != 0)
    return audit_auth_rc;

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 88;

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
  audit_rc = check_audit_event_present (client,
      "deny_reason(\"not_armed\")",
      "http-deny-user", "http.not_armed", "http-deny-scope",
      WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
      "deny_origin(\"perm_state\")",
      "http-deny-user", "http.not_armed", "http-deny-scope",
      WYL_DECISION_DENY, "not_armed", "perm_state");
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
  audit_rc = check_audit_event_present (client,
      "action(\"permission_grant\")",
      "http-policy-admin", "permission_grant", "tenant-a",
      WYL_DECISION_ALLOW, NULL, "site.policy.read");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
      "action(\"permission_revoke\")",
      "http-policy-admin", "permission_revoke", "tenant-a",
      WYL_DECISION_ALLOW, NULL, "site.policy.read");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
      "action(\"permission_state.grant\")",
      "http-policy-admin", "permission_state.grant", "site.policy.read",
      WYL_DECISION_ALLOW, "grant", "tenant-a");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"role_grant\")",
      "http-policy-admin", "role_grant", "tenant-b",
      WYL_DECISION_ALLOW, NULL, "site.reader");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"role_revoke\")",
      "http-policy-admin", "role_revoke", "tenant-b",
      WYL_DECISION_ALLOW, NULL, "site.reader");
  if (audit_rc != 0)
    return audit_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#endif /* WYL_TEST_VARIANT_AUDIT */
