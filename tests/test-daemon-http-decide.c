/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include <stdio.h>

#include <glib.h>
#include <sodium.h>
#ifdef WYL_HAS_AUDIT
#include <duckdb.h>
#endif

#include "daemon/delta.h"
#include "daemon/auth-registry-private.h"
#include "daemon/http.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-request-id-private.h"
#include "wyrelog/wyl-session-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  GMutex mutex;
  GCond changed;
  guint started;
} RefreshThreadBarrier;

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

typedef struct
{
  GMutex mutex;
  GCond changed;
  SoupServer *server;
  WylHandle *handle;
  gboolean write_entered;
  gboolean close_entered;
  gboolean close_observed;
  gboolean allow_write;
  wyrelog_error_t write_rc;
  wyrelog_error_t shutdown_rc;
} DaemonPolicyShutdownRace;

static void
daemon_policy_write_checkpoint (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  g_mutex_lock (&race->mutex);
  race->write_entered = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->allow_write)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);
}

static void
daemon_policy_close_checkpoint (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (race->handle), &snapshot);
  g_mutex_lock (&race->mutex);
  race->close_observed = snapshot.closing;
  race->close_entered = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

static gpointer
daemon_policy_write_thread (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  race->write_rc = wyl_daemon_http_policy_write_for_test (race->server,
      daemon_policy_write_checkpoint, race);
  return NULL;
}

static gpointer
daemon_policy_shutdown_thread (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  race->shutdown_rc = wyl_handle_shutdown_ordered (race->handle);
  return NULL;
}

static gint
check_daemon_policy_write_shutdown_contract (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1900;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts,
      handle, &error);
  if (server == NULL)
    return 1901;

  DaemonPolicyShutdownRace race = {
    .server = server,
    .handle = handle,
    .write_rc = WYRELOG_E_INTERNAL,
    .shutdown_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("daemon-policy-write",
      daemon_policy_write_thread, &race);
  g_mutex_lock (&race.mutex);
  while (!race.write_entered)
    g_cond_wait (&race.changed, &race.mutex);
  g_mutex_unlock (&race.mutex);

  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  wyl_service_auth_authority_set_close_checkpoint (authority,
      daemon_policy_close_checkpoint, &race);
  g_autoptr (GThread) shutdown = g_thread_new ("daemon-policy-shutdown",
      daemon_policy_shutdown_thread, &race);
  g_mutex_lock (&race.mutex);
  while (!race.close_entered)
    g_cond_wait (&race.changed, &race.mutex);
  gboolean store_was_live = wyl_handle_get_policy_store (handle) != NULL;
  race.allow_write = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  g_thread_join (g_steal_pointer (&shutdown));
  gint rc = race.close_observed ? 0 : 1902;
  if (rc == 0 && !store_was_live)
    rc = 1903;
  if (rc == 0 && race.write_rc != WYRELOG_E_OK)
    rc = 1904;
  if (rc == 0 && race.shutdown_rc != WYRELOG_E_OK)
    rc = 1905;
  if (rc == 0 && wyl_handle_get_policy_store (handle) != NULL)
    rc = 1906;
  if (rc == 0 && wyl_handle_shutdown_ordered (handle) != WYRELOG_E_OK)
    rc = 1907;
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  soup_server_disconnect (server);
  return rc;
}

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
  if (strstr (body, "\"subsystems\"") == NULL
      || strstr (body, "\"facts\"") == NULL
      || strstr (body, "\"graphs_total\"") == NULL)
    return 1929;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/facts/status", &status,
          &body) != 0)
    return 1930;
  if (status != 200 || strstr (body, "\"graphs_total\"") == NULL
      || strstr (body, "\"graphs\"") == NULL)
    return 1931;

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
check_raw_decide_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
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
  /*
   * Tenant gate emits the stable wire code "tenant_invalid" rather
   * than the surrounding handler's generic shape error so callers
   * can recognise tenant rejections regardless of endpoint family.
   */
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1812;

  /*
   * Unregistered tenant literals such as "evil-co" fail closed
   * before the decision path can run.
   */
  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope",
      "tenant=evil-co&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=69", guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1813;

#ifdef WYL_HAS_AUDIT
  /*
   * Defense-in-depth tenant gate on the JWT claims themselves. Forge
   * a token with the daemon's secret carrying an unregistered tenant
   * in the access claims; the signature verifies but
   * resolve_bearer_session must reject the token before request
   * authorization. The wire code is "tenant_invalid" with HTTP 401
   * at the auth boundary.
   */
  g_autofree gchar *foreign_tenant_token = NULL;
  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return 1824;
  g_autofree gchar *foreign_tenant_key_id =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (foreign_tenant_key_id == NULL)
    return 1827;
  wyl_jwt_issue_input_t foreign_tenant_input = {
    .key_id = foreign_tenant_key_id,
    .jti = "foreign-tenant-jti",
    .subject = "http-guard-user",
    .issuer = "wyrelogd",
    .audience = "wyrelog-client",
    .tenant = "evil-co",
    .principal_state_at_issue = "authenticated",
    .session_id = "foreign-tenant-session",
    .issued_at = g_get_real_time () / G_USEC_PER_SEC,
    .ttl_seconds = WYL_JWT_ACCESS_TTL_SECONDS,
  };
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256 (&foreign_tenant_input, secret,
      sizeof secret, &foreign_tenant_token);
  memset (secret, 0, sizeof secret);
  if (sign_rc != WYRELOG_E_OK)
    return 1825;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
      "wr.audit.read", "http-guard-scope", NULL, foreign_tenant_token,
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1826;
#else
  (void) server;
#endif

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

static gchar *extract_json_string (const gchar * body, const gchar * name);

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

typedef struct
{
  const gchar *base_url;
  const gchar *refresh_token;
  gint rc;
  guint status;
  gchar *body;
  RefreshThreadBarrier *wire_barrier;
} RawHumanRefresh;

static gpointer raw_human_refresh_thread (gpointer data);

typedef struct
{
  const gchar *base_url;
  const gchar *refresh_token;
  GMutex mutex;
  GCond changed;
  gboolean close_now;
  gint rc;
} DroppedHumanRefresh;

static gpointer
dropped_human_refresh_thread (gpointer data)
{
  DroppedHumanRefresh *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
      NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
      g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_autofree gchar *escaped = g_uri_escape_string (request->refresh_token,
      NULL, TRUE);
  g_autofree gchar *wire = g_strdup_printf
      ("POST /auth/refresh?refresh_token=%s HTTP/1.1\r\n"
      "Host: %s:%d\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
      escaped, g_uri_get_host (uri), g_uri_get_port (uri));
  gsize written = 0;
  if (!g_output_stream_write_all (g_io_stream_get_output_stream
          (G_IO_STREAM (connection)), wire, strlen (wire), &written, NULL,
          &error) || written != strlen (wire)) {
    request->rc = 2;
    return NULL;
  }
  g_mutex_lock (&request->mutex);
  while (!request->close_now)
    g_cond_wait (&request->changed, &request->mutex);
  g_mutex_unlock (&request->mutex);
  if (!g_io_stream_close (G_IO_STREAM (connection), NULL, &error))
    request->rc = 3;
  return NULL;
}

static void
drop_human_refresh_response (DroppedHumanRefresh *request)
{
  g_mutex_lock (&request->mutex);
  request->close_now = TRUE;
  g_cond_broadcast (&request->changed);
  g_mutex_unlock (&request->mutex);
}


static gpointer
raw_human_refresh_thread (gpointer data)
{
  RawHumanRefresh *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
      NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
      g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_socket_set_timeout (g_socket_connection_get_socket (connection), 15);
  g_autofree gchar *escaped = g_uri_escape_string (request->refresh_token,
      NULL, TRUE);
  g_autofree gchar *wire = g_strdup_printf
      ("POST /auth/refresh?refresh_token=%s HTTP/1.1\r\n"
      "Host: %s:%d\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
      escaped, g_uri_get_host (uri), g_uri_get_port (uri));
  GOutputStream *output = g_io_stream_get_output_stream
      (G_IO_STREAM (connection));
  gsize written = 0;
  if (!g_output_stream_write_all (output, wire, strlen (wire), &written, NULL,
          &error) || written != strlen (wire)
      || !g_output_stream_flush (output, NULL, &error)) {
    request->rc = 2;
    return NULL;
  }
  if (request->wire_barrier != NULL) {
    g_mutex_lock (&request->wire_barrier->mutex);
    request->wire_barrier->started++;
    g_cond_broadcast (&request->wire_barrier->changed);
    g_mutex_unlock (&request->wire_barrier->mutex);
  }
  g_autoptr (GByteArray) response = g_byte_array_new ();
  guint8 chunk[1024];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  for (;;) {
    gssize count = g_input_stream_read (input, chunk, sizeof chunk, NULL,
        &error);
    if (count < 0) {
      request->rc = 3;
      return NULL;
    }
    if (count == 0)
      break;
    g_byte_array_append (response, chunk, (guint) count);
  }
  g_byte_array_append (response, (const guint8 *) "\0", 1);
  gchar *headers_end = strstr ((gchar *) response->data, "\r\n\r\n");
  if (headers_end == NULL
      || sscanf ((gchar *) response->data, "HTTP/1.1 %u", &request->status)
      != 1) {
    request->rc = 4;
    return NULL;
  }
  request->body = g_strdup (headers_end + 4);
  return NULL;
}

static gchar *
access_token_jti (SoupServer *server, const gchar *access_token)
{
  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return NULL;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  g_autoptr (GBytes) payload = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_access_token (access_token, secret,
      sizeof secret, key_id, "wyrelogd", "wyrelog-client", now, &payload);
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return NULL;
  gsize length = 0;
  const gchar *data = g_bytes_get_data (payload, &length);
  g_autofree gchar *json = g_strndup (data, length);
  return extract_json_string (json, "jti");
}

static gint
check_concurrent_human_refresh_single_flight (SoupServer *server,
    const gchar *base_url)
{
  g_autoptr (SoupSession) login = soup_session_new ();
  guint login_status = 0;
  g_autofree gchar *login_body = NULL;
  if (send_raw_login (login, "POST", base_url,
          "username=login-user&skip_mfa=true", &login_status, &login_body)
      != 0 || login_status != 200)
    return 2200;
  g_autofree gchar *session_id = extract_json_string (login_body,
      "session_token");
  g_autofree gchar *predecessor = extract_json_string (login_body,
      "refresh_token");
  if (session_id == NULL || predecessor == NULL)
    return 2201;

  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_before, &access_before);
  if (before == NULL)
    return 2202;
  gint result = 0;
  guint threads_started = 0;
  gboolean threads_joined = FALSE, latch_released = FALSE;
  g_autofree gchar *access_a = NULL, *access_b = NULL;
  g_autofree gchar *refresh_a = NULL, *refresh_b = NULL;
  g_autofree gchar *jti_a = NULL, *jti_b = NULL, *after = NULL;
  g_autofree gchar *refresh_lineage = NULL, *expected_refresh_lineage = NULL;
  g_autofree gchar *resolved_session = NULL, *resolved_actor = NULL;
  g_autofree gchar *resolved_tenant = NULL, *successor_body = NULL;
  wyl_daemon_access_token_snapshot_t lineage = { 0 };
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  guint64 latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
      (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  RefreshThreadBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  RawHumanRefresh requests[8] = { 0 };
  GThread *threads[8] = { 0 };
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++) {
    requests[i].base_url = base_url;
    requests[i].refresh_token = predecessor;
    requests[i].wire_barrier = i == 0 ? NULL : &barrier;
  }
  threads[0] = g_thread_new ("human-refresh-a",
      raw_human_refresh_thread, &requests[0]);
  threads_started = 1;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
          g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2210;
    goto cleanup;
  }
  for (guint i = 1; i < G_N_ELEMENTS (threads); i++) {
    threads[i] = g_thread_new ("human-refresh-queued",
        raw_human_refresh_thread, &requests[i]);
    threads_started++;
  }
  g_mutex_lock (&barrier.mutex);
  gint64 wire_deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  while (barrier.started < G_N_ELEMENTS (requests) - 1)
    if (!g_cond_wait_until (&barrier.changed, &barrier.mutex, wire_deadline))
      break;
  gboolean all_followers_written = barrier.started
      == G_N_ELEMENTS (requests) - 1;
  g_mutex_unlock (&barrier.mutex);
  WylDaemonRefreshCounters counters = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (!all_followers_written || counters.handler_entries != 1
      || counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 0) {
    result = 2211;
    goto cleanup;
  }
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  for (guint i = 0; i < G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);
  threads_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++)
    if (requests[i].rc != 0 || requests[i].status != 200
        || g_strcmp0 (requests[0].body, requests[i].body) != 0) {
      result = 2203;
      goto cleanup;
    }
  access_a = extract_json_string (requests[0].body, "access_token");
  access_b = extract_json_string (requests[1].body, "access_token");
  refresh_a = extract_json_string (requests[0].body, "refresh_token");
  refresh_b = extract_json_string (requests[1].body, "refresh_token");
  jti_a = access_token_jti (server, access_a);
  jti_b = access_token_jti (server, access_b);
  if (access_a == NULL || refresh_a == NULL || jti_a == NULL
      || g_strcmp0 (access_a, access_b) != 0
      || g_strcmp0 (refresh_a, refresh_b) != 0
      || g_strcmp0 (jti_a, jti_b) != 0) {
    result = 2204;
    goto cleanup;
  }

  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
      &refresh_after, &access_after);
  if (after == NULL || refresh_after != refresh_before + 1
      || access_after != access_before + 1
      || strstr (after, access_a) == NULL
      || strstr (after, refresh_a) == NULL) {
    result = 2205;
    goto cleanup;
  }
  guint successor_refresh_count = 0, successor_access_count = 0;
  refresh_lineage = wyl_daemon_http_dup_refresh_state_for_test (server,
      refresh_a, &successor_refresh_count, &successor_access_count);
  expected_refresh_lineage = g_strdup_printf
      ("%s|%s|login-user|__wr_default|%d|0|0|", refresh_a, session_id,
      WYL_SESSION_AUTH_METHOD_HUMAN);
  if (refresh_lineage == NULL
      || !g_str_has_prefix (refresh_lineage, expected_refresh_lineage)
      || successor_refresh_count != refresh_after
      || successor_access_count != access_after) {
    result = 2212;
    goto cleanup;
  }
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, jti_a, &lineage)
      || g_strcmp0 (lineage.jti, jti_a) != 0
      || g_strcmp0 (lineage.session_id, session_id) != 0
      || g_strcmp0 (lineage.subject, "login-user") != 0
      || g_strcmp0 (lineage.tenant, "__wr_default") != 0
      || lineage.auth_method != WYL_SESSION_AUTH_METHOD_HUMAN
      || lineage.credential_id != NULL || lineage.credential_generation != 0
      || lineage.revoked) {
    result = 2209;
    goto cleanup;
  }
  wyl_daemon_access_token_snapshot_clear (&lineage);
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.handler_entries != 8 || counters.access_id_successes != 1
      || counters.jwt_sign_attempts != 1 || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 1) {
    result = 2206;
    goto cleanup;
  }

  if (wyl_daemon_http_resolve_bearer_for_test (server, access_a,
          &resolved_session, &resolved_actor, &resolved_tenant)
      != WYRELOG_E_OK || g_strcmp0 (resolved_session, session_id) != 0
      || g_strcmp0 (resolved_actor, "login-user") != 0) {
    result = 2207;
    goto cleanup;
  }
  guint successor_status = 0;
  if (send_raw_refresh (login, "POST", base_url, refresh_a,
          &successor_status, &successor_body) != 0 || successor_status != 200)
    result = 2208;

cleanup:
  if (!latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (!threads_joined)
    for (guint i = 0; i < threads_started; i++)
      g_thread_join (threads[i]);
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  wyl_daemon_access_token_snapshot_clear (&lineage);
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++)
    g_free (requests[i].body);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return result;
}

static gint
check_human_refresh_response_loss (SoupServer *server, const gchar *base_url)
{
  gint result = 0;
  guint64 latch_generation = 0;
  gboolean sync_initialized = FALSE, thread_started = FALSE;
  gboolean thread_joined = FALSE, drop_signaled = FALSE, latch_released = FALSE;
  GThread *thread = NULL;
  g_autofree gchar *state = NULL;
  g_autofree gchar *access = NULL;
  g_autofree gchar *refresh = NULL;
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *after = NULL;
  if (send_raw_login (login, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2250;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  if (predecessor == NULL)
    return 2251;
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
      (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  DroppedHumanRefresh dropped = {
    .base_url = base_url,
    .refresh_token = predecessor,
  };
  g_mutex_init (&dropped.mutex);
  g_cond_init (&dropped.changed);
  sync_initialized = TRUE;
  thread = g_thread_new ("refresh-response-loss",
      dropped_human_refresh_thread, &dropped);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
          g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2252;
    goto cleanup;
  }
  WylDaemonRefreshCounters counters = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 0) {
    result = 2252;
    goto cleanup;
  }
  drop_human_refresh_response (&dropped);
  drop_signaled = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (dropped.rc != 0) {
    result = 2253;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (login, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 200) {
    result = 2254;
    goto cleanup;
  }
  guint refresh_count = 0, access_count = 0;
  state = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
      &refresh_count, &access_count);
  access = extract_json_string (body, "access_token");
  refresh = extract_json_string (body, "refresh_token");
  if (state == NULL || access == NULL || refresh == NULL
      || before == NULL || refresh_count != refresh_before + 1
      || access_count != access_before + 1 || strstr (state, access) == NULL
      || strstr (state, refresh) == NULL) {
    result = 2255;
    goto cleanup;
  }
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 1)
    result = 2255;
cleanup:
  if (thread_started && !thread_joined && !drop_signaled) {
    drop_human_refresh_response (&dropped);
    drop_signaled = TRUE;
  }
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (sync_initialized) {
    g_cond_clear (&dropped.changed);
    g_mutex_clear (&dropped.mutex);
  }
  return result;
}

static gint
check_human_refresh_prepared_expiry (SoupServer *server, const gchar *base_url)
{
  gint result = 0;
  gboolean clock_enabled = FALSE, thread_started = FALSE;
  gboolean thread_joined = FALSE, latch_released = FALSE;
  guint64 latch_generation = 0;
  GThread *thread = NULL;
  RawHumanRefresh request = { 0 };
  g_autofree gchar *predecessor = NULL;
  g_autofree gchar *before = NULL;
  g_autofree gchar *after = NULL;
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  const gint64 prepared_at = g_get_real_time () / G_USEC_PER_SEC;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, prepared_at);
  clock_enabled = TRUE;
  if (send_raw_login (login, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200) {
    result = 2256;
    goto cleanup;
  }
  predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  before = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
      &refresh_before, &access_before);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
      (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  request.base_url = base_url;
  request.refresh_token = predecessor;
  thread = g_thread_new ("refresh-prepared-expiry",
      raw_human_refresh_thread, &request);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
          g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2257;
    goto cleanup;
  }
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      prepared_at + WYL_JWT_ACCESS_TTL_SECONDS);
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
      &refresh_after, &access_after);
  if (request.status != 500 || before == NULL || after == NULL
      || refresh_after != refresh_before || access_after != access_before
      || strstr (after, "|0|0|") == NULL) {
    result = 2258;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (login, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 200)
    result = 2259;
cleanup:
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (clock_enabled)
    wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  g_free (request.body);
  return result;
}

static gint
check_human_refresh_logout_ordering (SoupServer *server, const gchar *base_url)
{
  const WylDaemonRefreshPhase phases[] = {
    WYL_DAEMON_REFRESH_BEFORE_PUBLICATION,
    WYL_DAEMON_REFRESH_AFTER_PUBLICATION,
  };
  g_autoptr (SoupSession) session = soup_session_new ();
  for (guint i = 0; i < G_N_ELEMENTS (phases); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_login (session, "POST", base_url,
            "username=login-user&skip_mfa=true", &status, &body) != 0
        || status != 200)
      return 2320 + (gint) i *10;
    g_autofree gchar *session_id = extract_json_string (body, "session_token");
    g_autofree gchar *predecessor = extract_json_string (body,
        "refresh_token");
    guint refresh_before = 0, access_before = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
    guint64 generation = wyl_daemon_http_arm_refresh_latch_for_test (server,
        phases[i]);
    RawHumanRefresh request = {
      .base_url = base_url,
      .refresh_token = predecessor,
    };
    GThread *thread = g_thread_new ("refresh-logout-order",
        raw_human_refresh_thread, &request);
    if (!wyl_daemon_http_wait_refresh_latch_for_test (server, generation,
            g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
      wyl_daemon_http_release_refresh_latch_for_test (server, generation);
      g_thread_join (thread);
      wyl_daemon_http_disarm_refresh_latch_for_test (server, generation);
      g_free (request.body);
      return 2321 + (gint) i *10;
    }
    wyl_daemon_http_revoke_human_session_for_test (server, session_id);
    wyl_daemon_http_release_refresh_latch_for_test (server, generation);
    g_thread_join (thread);
    wyl_daemon_http_disarm_refresh_latch_for_test (server, generation);
    guint refresh_after = 0, access_after = 0;
    g_autofree gchar *after = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_after, &access_after);
    if (i == 0) {
      if (request.status == 200 || before == NULL || after == NULL
          || refresh_after != refresh_before || access_after != access_before)
        return 2322;
    } else {
      g_autofree gchar *access = extract_json_string (request.body,
          "access_token");
      g_autofree gchar *refresh = extract_json_string (request.body,
          "refresh_token");
      g_autofree gchar *jti = access_token_jti (server, access);
      wyl_daemon_access_token_snapshot_t access_state = { 0 };
      guint successor_refresh_count = 0, successor_access_count = 0;
      g_autofree gchar *successor =
          wyl_daemon_http_dup_refresh_state_for_test (server, refresh,
          &successor_refresh_count, &successor_access_count);
      gboolean revoked = wyl_daemon_http_snapshot_access_token_for_test
          (server, jti, &access_state) && access_state.revoked;
      wyl_daemon_access_token_snapshot_clear (&access_state);
      if (request.status != 200 || access == NULL || refresh == NULL
          || refresh_after != refresh_before + 1
          || access_after != access_before + 1 || !revoked
          || successor == NULL || strstr (successor, "|0|1|") == NULL)
        return 2332;
    }
    g_free (request.body);
  }
  return 0;
}

static gint
check_human_refresh_shutdown_ordering (SoupServer *server,
    const gchar *base_url)
{
  gint result = 0;
  gboolean thread_started = FALSE, thread_joined = FALSE;
  gboolean latch_released = FALSE;
  guint64 latch_generation = 0;
  GThread *thread = NULL;
  RawHumanRefresh request = { 0 };
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *after = NULL;
  if (send_raw_login (login, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2260;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_before, &access_before);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
      (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  request.base_url = base_url;
  request.refresh_token = predecessor;
  thread = g_thread_new ("refresh-shutdown",
      raw_human_refresh_thread, &request);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
          g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2261;
    goto cleanup;
  }
  wyl_daemon_http_terminalize_refreshes_for_test (server);
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
      &refresh_after, &access_after);
  gboolean ok = request.status == 503 && request.body != NULL
      && strstr (request.body, "server_shutting_down") != NULL
      && before != NULL && after != NULL
      && refresh_after == refresh_before && access_after == access_before
      && strstr (after, "|0|0|") != NULL;
  if (!ok)
    result = 2262;
cleanup:
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  g_free (request.body);
  return result;
}

static gint
check_explicit_refresh_dispatch_context (WylHandle *handle,
    WylDaemonRuntime *runtime)
{
  g_autoptr (GMainContext) context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (context, FALSE);
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      runtime, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    return 2263;
  if (!wyl_daemon_http_refresh_context_is_for_test (http.server, context))
    return 2264;
  GThread *thread = g_thread_new ("refresh-explicit-context",
      test_http_server_thread, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 2265;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = send_raw_refresh (session, "POST", base_url, NULL, &status,
      &body);
  guint owned = 0, wrong = 0;
  wyl_daemon_http_refresh_lifecycle_counts_for_test (http.server, &owned,
      &wrong);
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return rc == 0 && status == 400 && owned == 1 && wrong == 0 ? 0 : 2266;
}

static gint
check_human_refresh_fault_matrix (SoupServer *server, const gchar *base_url)
{
  const WylDaemonRefreshFault faults[] = {
    WYL_DAEMON_REFRESH_FAULT_ACCESS_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_REFRESH_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_RESULT_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_PREPUBLICATION,
  };
  g_autoptr (SoupSession) session = soup_session_new ();
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_login (session, "POST", base_url,
            "username=login-user&skip_mfa=true", &status, &body) != 0
        || status != 200)
      return 2270 + (gint) i *10;
    g_autofree gchar *predecessor = extract_json_string (body,
        "refresh_token");
    g_autofree gchar *session_id = extract_json_string (body,
        "session_token");
    gchar **access_ids_before =
        wyl_daemon_http_snapshot_session_access_ids_for_test (server,
        session_id);
    gchar **refresh_ids_before =
        wyl_daemon_http_snapshot_session_refresh_ids_for_test (server,
        session_id);
    guint refresh_before = 0, access_before = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
    wyl_daemon_http_reset_refresh_counters_for_test (server);
    wyl_daemon_http_set_refresh_fault_for_test (server, faults[i]);
    g_clear_pointer (&body, g_free);
    if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
            &body) != 0 || status != 500)
      return 2271 + (gint) i *10;
    guint refresh_failed = 0, access_failed = 0;
    g_autofree gchar *failed = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_failed, &access_failed);
    gchar **access_ids_failed =
        wyl_daemon_http_snapshot_session_access_ids_for_test (server,
        session_id);
    gchar **refresh_ids_failed =
        wyl_daemon_http_snapshot_session_refresh_ids_for_test (server,
        session_id);
    gchar **generated_refresh =
        wyl_daemon_http_snapshot_generated_refresh_ids_for_test (server);
    if (before == NULL || failed == NULL || refresh_failed != refresh_before
        || access_failed != access_before || strstr (failed, "|0|0|") == NULL
        || !g_strv_equal ((const gchar * const *) access_ids_before,
            (const gchar * const *) access_ids_failed)
        || !g_strv_equal ((const gchar * const *) refresh_ids_before,
            (const gchar * const *) refresh_ids_failed))
      return 2272 + (gint) i *10;
    for (guint generated = 0; generated_refresh != NULL
        && generated_refresh[generated] != NULL; generated++)
      if (g_strv_contains ((const gchar * const *) refresh_ids_failed,
              generated_refresh[generated]))
        return 2274 + (gint) i *10;
    g_strfreev (access_ids_before);
    g_strfreev (access_ids_failed);
    wyl_daemon_http_sensitive_strv_free_for_test (refresh_ids_before);
    wyl_daemon_http_sensitive_strv_free_for_test (refresh_ids_failed);
    wyl_daemon_http_sensitive_strv_free_for_test (generated_refresh);
    g_clear_pointer (&body, g_free);
    if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
            &body) != 0 || status != 200)
      return 2273 + (gint) i *10;
  }

  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2310;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  wyl_daemon_http_set_refresh_fault_for_test (server,
      WYL_DAEMON_REFRESH_FAULT_RESPONSE_BUILD);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 500
      || strstr (body, "refresh_response_failed") == NULL)
    return 2311;
  guint refresh_after = 0, access_after = 0;
  g_autofree gchar *committed = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_after, &access_after);
  if (before == NULL || committed == NULL
      || refresh_after != refresh_before + 1
      || access_after != access_before + 1)
    return 2312;
  WylDaemonRefreshCounters counters_before = { 0 }, counters_after = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters_before);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 200)
    return 2313;
  wyl_daemon_http_refresh_counters_for_test (server, &counters_after);
  if (memcmp (&counters_before.access_id_successes,
          &counters_after.access_id_successes,
          sizeof counters_before - G_STRUCT_OFFSET (WylDaemonRefreshCounters,
              access_id_successes)) != 0)
    return 2314;
  return 0;
}

static gint
check_human_refresh_failure_and_clock_boundaries (SoupServer *server,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2212;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  if (predecessor == NULL)
    return 2213;
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_fail_next_refresh_publication_for_test (server);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 500
      || strstr (body, "\"refresh_failed\"") == NULL) {
    g_printerr ("refresh injected failure: status=%u body=%s\n", status,
        body != NULL ? body : "<null>");
    return 2214;
  }
  guint refresh_failed = 0, access_failed = 0;
  g_autofree gchar *failed = wyl_daemon_http_dup_refresh_state_for_test
      (server, predecessor, &refresh_failed, &access_failed);
  if (before == NULL || failed == NULL || refresh_failed != refresh_before
      || access_failed != access_before || strstr (failed, "|0|0|") == NULL)
    return 2215;
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
          &body) != 0 || status != 200)
    return 2216;

  gint64 boundary = g_get_real_time () / G_USEC_PER_SEC;
  const gint64 grace_seconds = 30;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, boundary);
  g_autofree gchar *boundary_predecessor = NULL;
  g_clear_pointer (&body, g_free);
  if (send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200
      || (boundary_predecessor = extract_json_string (body,
              "refresh_token")) == NULL)
    return 2217;
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
          &status, &body) != 0 || status != 200)
    return 2218;
  g_autofree gchar *committed_body = g_strdup (body);
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      boundary + grace_seconds);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
          &status, &body) != 0 || status != 200
      || g_strcmp0 (body, committed_body) != 0)
    return 2219;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      boundary + grace_seconds + 1);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
          &status, &body) != 0 || status != 401
      || strstr (body, "\"refresh_reuse_detected\"") == NULL)
    return 2220;

  g_autofree gchar *expiry_predecessor = NULL;
  wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  g_clear_pointer (&body, g_free);
  if (send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200
      || (expiry_predecessor = extract_json_string (body,
              "refresh_token")) == NULL
      || !wyl_daemon_http_set_refresh_times_for_test (server,
          expiry_predecessor, boundary, 0))
    return 2221;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, boundary);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, expiry_predecessor,
          &status, &body) != 0 || status != 401
      || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 2222;
  wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  return 0;
}

static gint
check_service_refresh_isolation (SoupServer *server, const gchar *base_url,
    const gchar *human_session_id)
{
  wyl_id_t session_id = WYL_ID_NIL, jti_id = WYL_ID_NIL;
  gchar session_text[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  if (wyl_id_new (&session_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&session_id, session_text, sizeof session_text)
      != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || wyl_service_credential_id_new (credential_id, sizeof credential_id)
      != WYRELOG_E_OK)
    return 1900;
  wyl_service_session_descriptor_t descriptor = {
    .session_id = session_id,
    .jti = jti,
    .subject_id = "svc:refresh:isolation",
    .tenant_id = "default",
    .credential_id = credential_id,
    .credential_generation = 1,
    .issued_at_seconds = 100,
    .expires_at_seconds = 400,
  };
  g_autoptr (WylSession) service = NULL;
  if (wyl_session_new_service_detached (&descriptor, &service)
      != WYRELOG_E_OK)
    return 1901;

  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *missing = wyl_daemon_http_dup_refresh_state_for_test
      (server, "missing-service-refresh", &refresh_before, &access_before);
  g_autofree gchar *access = (gchar *) 0x1;
  g_autofree gchar *refresh = (gchar *) 0x1;
  if (missing != NULL || wyl_daemon_http_issue_human_tokens_for_test (server,
          service, session_text, descriptor.subject_id, descriptor.tenant_id,
          &access, &refresh) != WYRELOG_E_POLICY || access != NULL
      || refresh != NULL)
    return 1902;
  guint refresh_after = 0, access_after = 0;
  missing = wyl_daemon_http_dup_refresh_state_for_test (server,
      "missing-service-refresh", &refresh_after, &access_after);
  if (missing != NULL || refresh_after != refresh_before
      || access_after != access_before)
    return 1903;

  g_autoptr (WylSession) human = wyl_daemon_http_ref_session (server,
      human_session_id);
  if (human == NULL)
    return 1904;
  typedef struct
  {
    const gchar *token;
    WylSession *session;
    const gchar *session_id;
    const gchar *subject;
    gint auth_method;
    gboolean consumed;
  } InvalidRefresh;
  const InvalidRefresh invalid[] = {
    {"seed-service", service, session_text, "svc:refresh:isolation",
        WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, FALSE},
    {"seed-human-cache", service, session_text, "human.cached",
        WYL_SESSION_AUTH_METHOD_HUMAN, FALSE},
    {"seed-svc-cache", human, human_session_id, "svc:cached",
        WYL_SESSION_AUTH_METHOD_HUMAN, FALSE},
    {"seed-service-consumed", service, session_text,
          "svc:refresh:isolation", WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
        TRUE},
  };
  g_autoptr (SoupSession) client = soup_session_new ();
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++) {
    const gchar *successor_access =
        invalid[i].consumed ? "cached-access" : NULL;
    const gchar *successor_refresh =
        invalid[i].consumed ? "cached-refresh" : NULL;
    if (!wyl_daemon_http_seed_refresh_for_test (server, invalid[i].session,
            invalid[i].token, invalid[i].session_id, invalid[i].subject,
            "default", invalid[i].auth_method, invalid[i].consumed,
            successor_access, successor_refresh))
      return 1910 + (gint) i;
    guint before_refresh = 0, before_access = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, invalid[i].token, &before_refresh, &before_access);
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (before == NULL || send_raw_refresh (client, "POST", base_url,
            invalid[i].token, &status, &body) != 0 || status != 401
        || strstr (body, "\"refresh_auth_required\"") == NULL
        || strstr (body, "access_token") != NULL
        || strstr (body, "refresh_token") != NULL)
      return 1920 + (gint) i;
    guint after_refresh = 0, after_access = 0;
    g_autofree gchar *after = wyl_daemon_http_dup_refresh_state_for_test
        (server, invalid[i].token, &after_refresh, &after_access);
    if (g_strcmp0 (after, before) != 0 || after_refresh != before_refresh
        || after_access != before_access)
      return 1930 + (gint) i;
    WylDaemonRefreshCounters counters = { 0 };
    wyl_daemon_http_refresh_counters_for_test (server, &counters);
    if (counters.access_id_successes != 0 || counters.jwt_sign_attempts != 0
        || counters.jwt_sign_successes != 0
        || counters.refresh_id_successes != 0 || counters.publications != 0)
      return 1940 + (gint) i;
  }
  return 0;
}

static gint
check_service_access_token_state_contract (SoupServer *server,
    wyl_daemon_access_token_snapshot_t *owned_after_teardown)
{
  wyl_id_t sid_id = WYL_ID_NIL, jti_id = WYL_ID_NIL, other_id = WYL_ID_NIL;
  gchar sid[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gchar other[WYL_ID_STRING_BUF];
  gchar credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  wyl_id_t human_sid_id = WYL_ID_NIL, human_jti_id = WYL_ID_NIL;
  gchar human_sid[WYL_ID_STRING_BUF], human_jti[WYL_ID_STRING_BUF];
  if (wyl_id_new (&sid_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_new (&other_id) != WYRELOG_E_OK
      || wyl_id_new (&human_sid_id) != WYRELOG_E_OK
      || wyl_id_new (&human_jti_id) != WYRELOG_E_OK
      || wyl_id_format (&sid_id, sid, sizeof sid) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || wyl_id_format (&other_id, other, sizeof other) != WYRELOG_E_OK
      || wyl_id_format (&human_sid_id, human_sid, sizeof human_sid)
      != WYRELOG_E_OK
      || wyl_id_format (&human_jti_id, human_jti, sizeof human_jti)
      != WYRELOG_E_OK
      || wyl_service_credential_id_new (credential, sizeof credential)
      != WYRELOG_E_OK)
    return 1940;

  g_autofree gchar *active_key =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (active_key == NULL
      || !wyl_daemon_http_store_human_access_token_for_test (server,
          human_jti, human_sid, "human-state", "tenant-state", active_key, 500)
      || !wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
          human_sid, "human-state", "tenant-state", 500, NULL, NULL, 0, 499))
    return 1958;
  wyl_daemon_access_token_snapshot_t human_snapshot = { 0 };
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, human_jti,
          &human_snapshot)
      || human_snapshot.auth_method != WYL_SESSION_AUTH_METHOD_HUMAN
      || human_snapshot.credential_id != NULL
      || human_snapshot.credential_generation != 0) {
    wyl_daemon_access_token_snapshot_clear (&human_snapshot);
    return 1959;
  }
  wyl_daemon_access_token_snapshot_clear (&human_snapshot);
  if (wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
          human_sid, "human-state", "tenant-state", 500,
          "service_credential", credential, 7, 499))
    return 1960;

  gchar mutable_subject[] = "svc:state:test";
  gchar mutable_tenant[] = "tenant-state";
  gchar mutable_key[] = "key-state";
  gchar mutable_credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  memcpy (mutable_credential, credential, sizeof credential);
  if (!wyl_daemon_http_store_service_access_token_for_test (server, jti, sid,
          mutable_subject, mutable_tenant, mutable_key, 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, mutable_credential, 7,
          FALSE))
    return 1941;
  mutable_subject[4] = 'X';
  mutable_tenant[0] = 'X';
  mutable_key[0] = 'X';
  mutable_credential[4] = mutable_credential[4] == '0' ? '1' : '0';

  wyl_daemon_access_token_snapshot_t snapshot = { 0 };
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, jti, &snapshot)
      || g_strcmp0 (snapshot.jti, jti) != 0
      || g_strcmp0 (snapshot.session_id, sid) != 0
      || g_strcmp0 (snapshot.subject, "svc:state:test") != 0
      || g_strcmp0 (snapshot.tenant, "tenant-state") != 0
      || g_strcmp0 (snapshot.key_id, "key-state") != 0
      || snapshot.auth_method != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
      || g_strcmp0 (snapshot.credential_id, credential) != 0
      || snapshot.credential_generation != 7 || snapshot.expires_at != 500
      || snapshot.revoked)
    return 1942;
  if (!wyl_daemon_http_service_access_token_is_exact_for_test (server, jti,
          sid, "svc:state:test", "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499))
    return 1943;

#define EXPECT_NOT_EXACT(j, s, sub, ten, key, exp, method, cred, gen, now, code) \
  G_STMT_START { \
    if (wyl_daemon_http_service_access_token_is_exact_for_test (server, (j), \
            (s), (sub), (ten), (key), (exp), (method), (cred), (gen), (now))) \
      return (code); \
  } G_STMT_END
  EXPECT_NOT_EXACT (other, sid, "svc:state:test", "tenant-state",
      "key-state", 500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
      credential, 7, 499, 1944);
  EXPECT_NOT_EXACT (jti, other, "svc:state:test", "tenant-state",
      "key-state", 500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
      credential, 7, 499, 1945);
  EXPECT_NOT_EXACT (jti, sid, "svc:other", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499, 1946);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-other", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1947);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-other",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1948);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      501, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1949);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_HUMAN, credential, 7, 499, 1950);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, "missing", 7, 499, 1951);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 8, 499,
      1952);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 500,
      1953);
#undef EXPECT_NOT_EXACT

  const gchar *missing[] = { NULL, "", "bad" };
  for (gsize i = 0; i < G_N_ELEMENTS (missing); i++) {
    if (wyl_daemon_http_store_service_access_token_for_test (server,
            missing[i], sid, "svc:state:test", "tenant-state", "key-state",
            500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7,
            FALSE)
        || wyl_daemon_http_store_service_access_token_for_test (server, jti,
            missing[i], "svc:state:test", "tenant-state", "key-state", 500,
            WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE))
      return 1954;
  }
  if (wyl_daemon_http_store_service_access_token_for_test (server, other, sid,
          NULL, "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
          sid, "svc:state:test", NULL, "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
          sid, "svc:state:test", "tenant-state", NULL, 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
          sid, "svc:state:test", "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, NULL, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
          sid, "svc:state:test", "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 0, FALSE))
    return 1955;

  if (!wyl_daemon_http_store_service_access_token_for_test (server, other,
          sid, "svc:revoked", "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, TRUE)
      || wyl_daemon_http_service_access_token_is_exact_for_test (server,
          other, sid, "svc:revoked", "tenant-state", "key-state", 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499))
    return 1956;

  static const gchar noncanonical_id[] = "01900000-0000-7000-8000-00000000000A";
  wyl_id_t parsed_noncanonical = WYL_ID_NIL;
  if (wyl_id_parse (noncanonical_id, &parsed_noncanonical) != WYRELOG_E_OK
      || wyl_daemon_http_store_service_access_token_for_test (server,
          noncanonical_id, sid, "svc:state:test", "tenant-state", active_key,
          500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, jti,
          noncanonical_id, "svc:state:test", "tenant-state", active_key, 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server,
          human_jti, human_sid, "svc:bad/subject", "tenant-state", active_key,
          500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server,
          human_jti, human_sid, "svc:state:test", "bad/tenant", active_key,
          500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7,
          FALSE))
    return 1961;

  if (!wyl_daemon_http_store_service_access_token_for_test (server, human_jti,
          human_sid, "svc:state:test", "tenant-state", active_key, 500,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
          human_sid, "svc:state:test", "tenant-state", 500, NULL, NULL, 0, 499))
    return 1962;

  *owned_after_teardown = snapshot;
  memset (&snapshot, 0, sizeof snapshot);
  return 0;
}

typedef struct
{
  gchar sid[WYL_ID_STRING_BUF];
  gchar jti[WYL_ID_STRING_BUF];
  gchar other_sid[WYL_ID_STRING_BUF];
  gchar other_jti[WYL_ID_STRING_BUF];
  gchar credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  gchar other_credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  gchar tenant[64];
  gchar *key_id;
  gchar *token;
  gint64 now;
} ServiceResolverFixture;

static void
service_resolver_fixture_clear (ServiceResolverFixture *fixture)
{
  g_clear_pointer (&fixture->key_id, g_free);
  g_clear_pointer (&fixture->token, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (ServiceResolverFixture,
    service_resolver_fixture_clear)
     static gboolean
         service_resolver_fixture_init_tenant (SoupServer *server,
    ServiceResolverFixture *fixture, gint registry_state,
    guint registry_mismatch, const gchar *tenant_id)
{
  memset (fixture, 0, sizeof *fixture);
  wyl_id_t sid = WYL_ID_NIL, jti = WYL_ID_NIL;
  wyl_id_t other_sid = WYL_ID_NIL, other_jti = WYL_ID_NIL;
  guint8 secret[32] = { 0 };
  fixture->now = g_get_real_time () / G_USEC_PER_SEC;
  g_strlcpy (fixture->tenant, tenant_id, sizeof fixture->tenant);
  fixture->key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (fixture->key_id == NULL || wyl_id_new (&sid) != WYRELOG_E_OK
      || wyl_id_new (&jti) != WYRELOG_E_OK
      || wyl_id_new (&other_sid) != WYRELOG_E_OK
      || wyl_id_new (&other_jti) != WYRELOG_E_OK
      || wyl_id_format (&sid, fixture->sid, sizeof fixture->sid)
      != WYRELOG_E_OK || wyl_id_format (&jti, fixture->jti, sizeof fixture->jti)
      != WYRELOG_E_OK
      || wyl_id_format (&other_sid, fixture->other_sid,
          sizeof fixture->other_sid) != WYRELOG_E_OK
      || wyl_id_format (&other_jti, fixture->other_jti,
          sizeof fixture->other_jti) != WYRELOG_E_OK
      || wyl_service_credential_id_new (fixture->credential,
          sizeof fixture->credential) != WYRELOG_E_OK
      || wyl_service_credential_id_new (fixture->other_credential,
          sizeof fixture->other_credential) != WYRELOG_E_OK)
    return FALSE;
  wyl_service_session_descriptor_t descriptor = {
    .session_id = sid,.jti = fixture->jti,
    .subject_id = "svc:resolver:test",.tenant_id = fixture->tenant,
    .credential_id = fixture->credential,.credential_generation = 9,
    .issued_at_seconds = fixture->now,
    .expires_at_seconds = fixture->now + 300,
  };
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_new_service_detached (&descriptor, &session)
      != WYRELOG_E_OK
      || !wyl_daemon_http_replace_session_for_test (server, fixture->sid,
          session)
      || !wyl_daemon_http_store_service_access_token_for_test (server,
          fixture->jti, fixture->sid, descriptor.subject_id,
          descriptor.tenant_id, fixture->key_id, fixture->now + 300,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, fixture->credential, 9,
          FALSE))
    return FALSE;
  const gchar *reg_sid = registry_mismatch == 1 ? fixture->other_sid
      : fixture->sid;
  const gchar *reg_jti = registry_mismatch == 2 ? fixture->other_jti
      : fixture->jti;
  const gchar *reg_cred = registry_mismatch == 3 ? fixture->other_credential
      : fixture->credential;
  guint64 reg_generation = registry_mismatch == 4 ? 10 : 9;
  const gchar *reg_subject = registry_mismatch == 5 ? "svc:resolver:other"
      : descriptor.subject_id;
  const gchar *reg_tenant = registry_mismatch == 6 ? "tenant-other"
      : descriptor.tenant_id;
  gboolean changed = FALSE;
  if (registry_state >= 0
      && wyl_daemon_http_service_registry_transition_for_test (server,
          reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
          WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (registry_state >= WYL_SERVICE_AUTH_ACTIVE
      && wyl_daemon_http_service_registry_transition_for_test (server,
          reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
          WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (registry_state == WYL_SERVICE_AUTH_REVOKED
      && wyl_daemon_http_service_registry_transition_for_test (server,
          reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
          WYL_DAEMON_SERVICE_REGISTRY_REVOKE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_service_issue_input_t input = {
    .key_id = fixture->key_id,.jti = fixture->jti,
    .subject = descriptor.subject_id,.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = descriptor.tenant_id,
    .session_id = fixture->sid,.credential_id = fixture->credential,
    .credential_generation = 9,.issued_at = fixture->now,
  };
  wyrelog_error_t rc = wyl_jwt_sign_hs256_service (&input, secret,
      sizeof secret, &fixture->token);
  sodium_memzero (secret, sizeof secret);
  return rc == WYRELOG_E_OK;
}

static gboolean
service_resolver_fixture_init (SoupServer *server,
    ServiceResolverFixture *fixture, gint registry_state,
    guint registry_mismatch)
{
  return service_resolver_fixture_init_tenant (server, fixture,
      registry_state, registry_mismatch, "__wr_default");
}

static gboolean
service_resolver_expect (SoupServer *server,
    const ServiceResolverFixture *fixture, const gchar *token, gboolean success)
{
  g_autofree gchar *sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  wyrelog_error_t rc = wyl_daemon_http_resolve_bearer_for_test (server,
      token, &sid, &actor, &tenant);
  if (!success)
    return rc == WYRELOG_E_POLICY && sid == NULL && actor == NULL
        && tenant == NULL;
  return rc == WYRELOG_E_OK && g_strcmp0 (sid, fixture->sid) == 0
      && g_strcmp0 (actor, "svc:resolver:test") == 0
      && g_strcmp0 (tenant, fixture->tenant) == 0;
}

static gchar *
service_resolver_sign_variant (SoupServer *server,
    const ServiceResolverFixture *fixture, guint field)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return NULL;
  wyl_jwt_service_issue_input_t input = {
    .key_id = field == 8 ? "wrong-key" : fixture->key_id,
    .jti = field == 2 ? fixture->other_jti : fixture->jti,
    .subject = field == 3 ? "svc:resolver:other" : "svc:resolver:test",
    .issuer = field == 9 ? "wrong-issuer" : "wyrelogd",
    .audience = field == 10 ? "wrong-audience" : "wyrelog-client",
    .tenant = field == 4 ? "tenant-unknown" : "__wr_default",
    .session_id = field == 1 ? fixture->other_sid : fixture->sid,
    .credential_id = field == 5 ? fixture->other_credential
        : fixture->credential,
    .credential_generation = field == 6 ? 10 : 9,
    .issued_at = field == 7 ? fixture->now - 301 : fixture->now,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256_service (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_sign_crossed (SoupServer *server,
    const ServiceResolverFixture *sid_source,
    const ServiceResolverFixture *jti_source)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return NULL;
  wyl_jwt_service_issue_input_t input = {
    .key_id = sid_source->key_id,.jti = jti_source->jti,
    .subject = "svc:resolver:test",.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = "__wr_default",
    .session_id = sid_source->sid,
    .credential_id = sid_source->credential,
    .credential_generation = 9,.issued_at = sid_source->now,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256_service (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_sign_json (SoupServer *server, const gchar *payload,
    const guint8 *secret_override)
{
  guint8 secret[32] = { 0 };
  if (secret_override != NULL)
    memcpy (secret, secret_override, sizeof secret);
  else if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return NULL;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  g_autofree gchar *header = g_strdup_printf
      ("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"%s\"}", key_id);
  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  g_autofree gchar *signing_input = NULL;
  g_autofree gchar *signature_segment = NULL;
  gchar *token = NULL;
  if (key_id == NULL
      || wyl_jwt_base64url_encode ((const guint8 *) header, strlen (header),
          &header_segment) != WYRELOG_E_OK
      || wyl_jwt_base64url_encode ((const guint8 *) payload, strlen (payload),
          &payload_segment) != WYRELOG_E_OK)
    goto out;
  signing_input = g_strdup_printf ("%s.%s", header_segment, payload_segment);
  guint8 signature[crypto_auth_hmacsha256_BYTES] = { 0 };
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init (&state, secret, sizeof secret);
  crypto_auth_hmacsha256_update (&state, (const guint8 *) signing_input,
      strlen (signing_input));
  crypto_auth_hmacsha256_final (&state, signature);
  if (wyl_jwt_base64url_encode (signature, sizeof signature,
          &signature_segment) == WYRELOG_E_OK)
    token = g_strdup_printf ("%s.%s", signing_input, signature_segment);
  sodium_memzero (signature, sizeof signature);
out:
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_json (const ServiceResolverFixture *fixture,
    const gchar *service_tail, gint64 nbf)
{
  return g_strdup_printf
      ("{\"jti\":\"%s\",\"sub\":\"svc:resolver:test\","
      "\"iss\":\"wyrelogd\",\"aud\":\"wyrelog-client\","
      "\"iat\":%" G_GINT64_FORMAT ",\"nbf\":%" G_GINT64_FORMAT ","
      "\"exp\":%" G_GINT64_FORMAT ",\"tenant\":\"__wr_default\","
      "\"principal_state_at_issue\":\"authenticated\",\"sid\":\"%s\"%s}",
      fixture->jti, fixture->now, nbf, fixture->now + 300, fixture->sid,
      service_tail);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  SoupServer *server;
  const ServiceResolverFixture *fixture;
  gboolean published;
  gboolean allow_release;
  gboolean released;
  gboolean allow_continue;
  gboolean writer_acquired;
  gboolean allow_writer_finish;
  gboolean inverse_mutation;
  gboolean mutate_requested;
  gboolean mutation_done;
  wyrelog_error_t mutation_rc;
  wyrelog_error_t resolver_rc;
  wyrelog_error_t writer_rc;
  gchar *sid;
  gchar *actor;
  gchar *tenant;
} ServiceResolverRace;

static void
service_resolver_race_checkpoint (WylDaemonServiceResolverPhase phase,
    gpointer data)
{
  ServiceResolverRace *race = data;
  g_mutex_lock (&race->mutex);
  if (phase == WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED) {
    race->published = TRUE;
    g_cond_broadcast (&race->changed);
    while (!race->allow_release)
      g_cond_wait (&race->changed, &race->mutex);
  } else {
    race->released = TRUE;
    g_cond_broadcast (&race->changed);
    while (!race->allow_continue)
      g_cond_wait (&race->changed, &race->mutex);
  }
  g_mutex_unlock (&race->mutex);
}

static gpointer
service_resolver_race_thread (gpointer data)
{
  ServiceResolverRace *race = data;
  race->resolver_rc = wyl_daemon_http_resolve_bearer_for_test (race->server,
      race->fixture->token, &race->sid, &race->actor, &race->tenant);
  return NULL;
}

static gpointer service_resolver_writer_thread (gpointer data);
static gboolean service_resolver_wait_flag (ServiceResolverRace * race,
    gboolean * flag);

static void
service_resolver_writer_checkpoint (gpointer data)
{
  ServiceResolverRace *race = data;
  g_mutex_lock (&race->mutex);
  race->writer_acquired = TRUE;
  g_cond_broadcast (&race->changed);
  while (race->inverse_mutation && !race->mutate_requested)
    g_cond_wait (&race->changed, &race->mutex);
  if (race->inverse_mutation) {
    g_mutex_unlock (&race->mutex);
    gboolean changed = FALSE;
    race->mutation_rc = wyl_daemon_http_service_registry_transition_for_test
        (race->server, race->fixture->sid, race->fixture->jti,
        race->fixture->credential, 9, "svc:resolver:test", "__wr_default",
        WYL_DAEMON_SERVICE_REGISTRY_REVOKE, &changed);
    if (race->mutation_rc == WYRELOG_E_OK && !changed)
      race->mutation_rc = WYRELOG_E_INTERNAL;
    g_mutex_lock (&race->mutex);
    race->mutation_done = TRUE;
    g_cond_broadcast (&race->changed);
  }
  while (!race->allow_writer_finish)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);
}

static gboolean
service_resolver_wait_reader_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.writer_active && snapshot.waiting_readers == 1
        && snapshot.active_readers == 0)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
check_service_resolver_inverse_barrier (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,.inverse_mutation = TRUE,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
    .mutation_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("inverse-write-holder",
      service_resolver_writer_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.writer_acquired);
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    resolver = g_thread_new ("inverse-service-resolver",
        service_resolver_race_thread, &race);
    ok = service_resolver_wait_reader_queued (server);
  }
  g_mutex_lock (&race.mutex);
  race.mutate_requested = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.mutation_done)
      && race.mutation_rc == WYRELOG_E_OK;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  ok = ok && race.writer_rc == WYRELOG_E_OK
      && race.resolver_rc == WYRELOG_E_POLICY && race.sid == NULL
      && race.actor == NULL && race.tenant == NULL
      && snapshot.active_readers == 0 && snapshot.waiting_readers == 0
      && !snapshot.writer_active;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gpointer
service_resolver_writer_thread (gpointer data)
{
  ServiceResolverRace *race = data;
  race->writer_rc = wyl_daemon_http_policy_write_for_test (race->server,
      service_resolver_writer_checkpoint, race);
  return NULL;
}

static gboolean
service_resolver_wait_flag (ServiceResolverRace *race, gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&race->mutex);
  while (!*flag && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  gboolean reached = *flag;
  g_mutex_unlock (&race->mutex);
  return reached;
}

static gboolean
service_resolver_wait_writer_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.waiting_writers == 1 && snapshot.active_readers == 1
        && !snapshot.writer_active)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
service_resolver_rejects_before_read (SoupServer *server, const gchar *token)
{
  ServiceResolverRace writer = {
    .server = server,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&writer.mutex);
  g_cond_init (&writer.changed);
  g_autoptr (GThread) thread = g_thread_new ("pre-read-write-holder",
      service_resolver_writer_thread, &writer);
  gboolean ok = service_resolver_wait_flag (&writer,
      &writer.writer_acquired);
  WylServiceAuthAuthoritySnapshot before = { 0 }, after = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &before);
  g_autofree gchar *sid = NULL, *actor = NULL, *tenant = NULL;
  wyrelog_error_t rc = wyl_daemon_http_resolve_bearer_for_test (server,
      token, &sid, &actor, &tenant);
  wyl_daemon_http_service_authority_snapshot_for_test (server, &after);
  ok = ok && rc == WYRELOG_E_POLICY && sid == NULL && actor == NULL
      && tenant == NULL && before.writer_active && after.writer_active
      && before.active_readers == 0 && after.active_readers == 0
      && before.waiting_readers == 0 && after.waiting_readers == 0;
  g_mutex_lock (&writer.mutex);
  writer.allow_writer_finish = TRUE;
  g_cond_broadcast (&writer.changed);
  g_mutex_unlock (&writer.mutex);
  g_thread_join (g_steal_pointer (&thread));
  ok = ok && writer.writer_rc == WYRELOG_E_OK;
  g_cond_clear (&writer.changed);
  g_mutex_clear (&writer.mutex);
  return ok;
}

static gboolean
check_service_resolver_crypto_pre_read (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  if (!service_resolver_expect (server, fixture, fixture->token, TRUE))
    return FALSE;
  g_autofree gchar *tampered = g_strdup (fixture->token);
  gchar *signature = strrchr (tampered, '.');
  if (signature == NULL || signature[1] == '\0')
    return FALSE;
  signature[1] = signature[1] == 'A' ? 'B' : 'A';
  guint8 wrong_secret[32];
  memset (wrong_secret, 0xa5, sizeof wrong_secret);
  g_autofree gchar *valid_tail = g_strdup_printf
      (",\"auth_method\":\"service_credential\",\"credential_id\":\"%s\","
      "\"credential_generation\":9", fixture->credential);
  g_autofree gchar *payload = service_resolver_json (fixture, valid_tail,
      fixture->now);
  g_autofree gchar *wrong_secret_token = service_resolver_sign_json (server,
      payload, wrong_secret);
  g_autofree gchar *future_payload = service_resolver_json (fixture,
      valid_tail, fixture->now + 60);
  g_autofree gchar *future_token = service_resolver_sign_json (server,
      future_payload, NULL);
  if (wrong_secret_token == NULL || future_token == NULL
      || !service_resolver_rejects_before_read (server, tampered)
      || !service_resolver_rejects_before_read (server, wrong_secret_token)
      || !service_resolver_rejects_before_read (server, future_token))
    return FALSE;

  const gchar *invalid_tails[] = {
    "",
    ",\"auth_method\":\"service_credential\"",
    ",\"credential_id\":\"placeholder\"",
    ",\"credential_generation\":9",
    ",\"auth_method\":\"service_credential\",\"credential_generation\":9",
    ",\"auth_method\":\"service_credential\",\"credential_id\":\"placeholder\"",
    ",\"credential_id\":\"placeholder\",\"credential_generation\":9",
    ",\"auth_method\":\"unknown\",\"credential_id\":\"placeholder\",\"credential_generation\":9",
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid_tails); i++) {
    g_autofree gchar *tail = g_strdup (invalid_tails[i]);
    if (strstr (tail, "placeholder") != NULL) {
      gchar **parts = g_strsplit (tail, "placeholder", -1);
      g_free (g_steal_pointer (&tail));
      tail = g_strjoinv (fixture->credential, parts);
      g_strfreev (parts);
    }
    g_autofree gchar *json = service_resolver_json (fixture, tail,
        fixture->now);
    g_autofree gchar *token = service_resolver_sign_json (server, json, NULL);
    if (token == NULL || !service_resolver_rejects_before_read (server, token))
      return FALSE;
  }
  const gchar *duplicates[] = { "auth_method", "credential_id",
    "credential_generation"
  };
  for (guint i = 0; i < G_N_ELEMENTS (duplicates); i++) {
    g_autofree gchar *duplicate_tail = NULL;
    if (i == 0)
      duplicate_tail =
          g_strdup_printf ("%s,\"auth_method\":\"service_credential\"",
          valid_tail);
    else if (i == 1)
      duplicate_tail = g_strdup_printf ("%s,\"credential_id\":\"%s\"",
          valid_tail, fixture->credential);
    else
      duplicate_tail = g_strdup_printf ("%s,\"credential_generation\":9",
          valid_tail);
    g_autofree gchar *json = service_resolver_json (fixture, duplicate_tail,
        fixture->now);
    g_autofree gchar *token = service_resolver_sign_json (server, json, NULL);
    if (token == NULL || !service_resolver_rejects_before_read (server, token))
      return FALSE;
  }
  g_autofree gchar *comment_json = g_strdup_printf
      ("{ /* auth_method */ \"jti\":\"%s\" }", fixture->jti);
  g_autofree gchar *comment_token = service_resolver_sign_json (server,
      comment_json, NULL);
  g_autofree gchar *note_tail = g_strdup
      (",\"note\":\"auth_method credential_id credential_generation\"");
  g_autofree gchar *note_json = service_resolver_json (fixture, note_tail,
      fixture->now);
  g_autofree gchar *note_token = service_resolver_sign_json (server,
      note_json, NULL);
  return comment_token != NULL
      && service_resolver_rejects_before_read (server, comment_token)
      && note_token != NULL
      && service_resolver_rejects_before_read (server, note_token)
      && service_resolver_expect (server, fixture, fixture->token, TRUE);
}

static gboolean
check_service_resolver_publication_barrier (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server,
      service_resolver_race_checkpoint, &race);
  g_autoptr (GThread) resolver = g_thread_new ("service-resolver",
      service_resolver_race_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.published);
  g_autoptr (GThread) writer = NULL;
  if (ok) {
    writer = g_thread_new ("service-writer", service_resolver_writer_thread,
        &race);
    ok = service_resolver_wait_writer_queued (server);
  }
  g_mutex_lock (&race.mutex);
  ok = ok && !race.writer_acquired;
  race.allow_release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.released)
      && service_resolver_wait_flag (&race, &race.writer_acquired);
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  ok = ok && snapshot.active_readers == 0 && snapshot.writer_active;
  g_mutex_lock (&race.mutex);
  race.allow_continue = TRUE;
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&resolver));
  if (writer != NULL)
    g_thread_join (g_steal_pointer (&writer));
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server, NULL, NULL);
  ok = ok && race.resolver_rc == WYRELOG_E_OK
      && race.writer_rc == WYRELOG_E_OK
      && g_strcmp0 (race.sid, fixture->sid) == 0
      && g_strcmp0 (race.actor, "svc:resolver:test") == 0
      && g_strcmp0 (race.tenant, "__wr_default") == 0;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

typedef struct
{
  SoupServer *server;
  const ServiceResolverFixture *fixture;
  wyrelog_error_t rc;
  gchar *sid;
  gchar *actor;
  gchar *tenant;
} ServiceResolverCall;

static gpointer
service_resolver_call_thread (gpointer data)
{
  ServiceResolverCall *call = data;
  call->rc = wyl_daemon_http_resolve_bearer_for_test (call->server,
      call->fixture->token, &call->sid, &call->actor, &call->tenant);
  return NULL;
}

static gboolean
service_resolver_wait_writer_and_reader (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.active_readers == 1 && snapshot.waiting_writers == 1
        && snapshot.waiting_readers == 1 && !snapshot.writer_active)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
check_service_resolver_writer_preference (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,.inverse_mutation = TRUE,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
    .mutation_rc = WYRELOG_E_INTERNAL,
  };
  ServiceResolverCall later = {
    .server = server,.fixture = fixture,.rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server,
      service_resolver_race_checkpoint, &race);
  g_autoptr (GThread) first = g_thread_new ("preferred-first-reader",
      service_resolver_race_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.published);
  g_autoptr (GThread) writer = NULL;
  g_autoptr (GThread) second = NULL;
  if (ok) {
    writer = g_thread_new ("preferred-writer", service_resolver_writer_thread,
        &race);
    ok = service_resolver_wait_writer_queued (server);
  }
  if (ok) {
    second = g_thread_new ("later-reader", service_resolver_call_thread,
        &later);
    ok = service_resolver_wait_writer_and_reader (server);
  }
  g_mutex_lock (&race.mutex);
  race.mutate_requested = TRUE;
  race.allow_release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.released)
      && service_resolver_wait_flag (&race, &race.writer_acquired)
      && service_resolver_wait_flag (&race, &race.mutation_done)
      && race.mutation_rc == WYRELOG_E_OK;
  WylServiceAuthAuthoritySnapshot during = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &during);
  ok = ok && during.writer_active && during.waiting_readers == 1
      && during.active_readers == 0;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  if (writer != NULL)
    g_thread_join (g_steal_pointer (&writer));
  g_mutex_lock (&race.mutex);
  race.allow_continue = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  if (second != NULL)
    g_thread_join (g_steal_pointer (&second));
  g_thread_join (g_steal_pointer (&first));
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server, NULL, NULL);
  WylServiceAuthAuthoritySnapshot final = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &final);
  ok = ok && race.resolver_rc == WYRELOG_E_OK
      && race.writer_rc == WYRELOG_E_OK && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && final.active_readers == 0 && final.waiting_readers == 0
      && final.waiting_writers == 0 && !final.writer_active;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gchar *
human_resolver_sign_variant (SoupServer *server, const gchar *sid,
    const gchar *jti, gint64 now, guint field)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return NULL;
  if (field == 5)
    memset (secret, 0xa5, sizeof secret);
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  wyl_jwt_issue_input_t input = {
    .key_id = field == 1 ? "wrong-key" : key_id,.jti = jti,
    .subject = "human-resolver",
    .issuer = field == 2 ? "wrong-issuer" : "wyrelogd",
    .audience = field == 3 ? "wrong-audience" : "wyrelog-client",
    .tenant = "__wr_default",.principal_state_at_issue = "authenticated",
    .session_id = sid,.issued_at = field == 4 ? now - 301 : now,
    .ttl_seconds = 300,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256 (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gboolean
check_human_resolver_while_write_held (SoupServer *server)
{
  wyl_id_t sid_id = WYL_ID_NIL, jti_id = WYL_ID_NIL;
  gchar sid[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  guint8 secret[32] = { 0 };
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL || wyl_id_new (&sid_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&sid_id, sid, sizeof sid) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || !wyl_daemon_http_seed_human_session_for_test (server, sid,
          "human-resolver", "__wr_default")
      || !wyl_daemon_http_store_human_access_token_for_test (server, jti, sid,
          "human-resolver", "__wr_default", key_id, now + 300)
      || wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_issue_input_t input = {
    .key_id = key_id,.jti = jti,.subject = "human-resolver",
    .issuer = "wyrelogd",.audience = "wyrelog-client",
    .tenant = "__wr_default",
    .principal_state_at_issue = "authenticated",.session_id = sid,
    .issued_at = now,.ttl_seconds = 300,
  };
  g_autofree gchar *token = NULL;
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256 (&input, secret,
      sizeof secret, &token);
  sodium_memzero (secret, sizeof secret);
  if (sign_rc != WYRELOG_E_OK)
    return FALSE;
  ServiceResolverRace race = {
    .server = server,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("human-write-holder",
      service_resolver_writer_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.writer_acquired);
  WylServiceAuthAuthoritySnapshot before = { 0 }, after = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &before);
  g_autofree gchar *resolved_sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  wyrelog_error_t resolve_rc = wyl_daemon_http_resolve_bearer_for_test (server,
      token, &resolved_sid, &actor, &tenant);
  wyl_daemon_http_service_authority_snapshot_for_test (server, &after);
  ok = ok && resolve_rc == WYRELOG_E_OK && before.writer_active
      && after.writer_active && before.active_readers == 0
      && after.active_readers == 0 && before.waiting_readers == 0
      && after.waiting_readers == 0 && g_strcmp0 (resolved_sid, sid) == 0
      && g_strcmp0 (actor, "human-resolver") == 0
      && g_strcmp0 (tenant, "__wr_default") == 0;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  ok = ok && race.writer_rc == WYRELOG_E_OK;
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  for (guint field = 1; ok && field <= 5; field++) {
    g_autofree gchar *variant = human_resolver_sign_variant (server, sid,
        jti, now, field);
    ok = variant != NULL
        && service_resolver_rejects_before_read (server, variant);
  }
  if (ok) {
    g_autofree gchar *tampered = g_strdup (token);
    gchar *signature = strrchr (tampered, '.');
    ok = signature != NULL && signature[1] != '\0';
    if (ok) {
      signature[1] = signature[1] == 'A' ? 'B' : 'A';
      ok = service_resolver_rejects_before_read (server, tampered);
    }
  }
  return ok;
}

static gboolean
check_service_resolver_prelatched_unavailable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return FALSE;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,.listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts, handle,
      &error);
  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (server == NULL || !service_resolver_fixture_init (server, &fixture,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &fixture, fixture.token, TRUE)
      || wyl_daemon_http_latch_service_unavailable_for_test (server)
      != WYRELOG_E_OK
      || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
    return FALSE;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  return snapshot.active_readers == 0 && !snapshot.writer_active;
}

static gboolean
check_service_resolver_terminal_failure (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return FALSE;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,.listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts, handle,
      &error);
  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (server == NULL || !service_resolver_fixture_init (server, &fixture,
          WYL_SERVICE_AUTH_ACTIVE, 0))
    return FALSE;
  wyl_daemon_http_fail_next_service_resolver_read_release_for_test (server);
  if (!service_resolver_expect (server, &fixture, fixture.token, FALSE)
      || wyl_daemon_http_service_resolver_terminal_entries_for_test
      (server) != 1)
    return FALSE;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  return snapshot.active_readers == 0 && !snapshot.writer_active
      && service_resolver_expect (server, &fixture, fixture.token, FALSE)
      && wyl_daemon_http_service_resolver_terminal_entries_for_test
      (server) == 0;
}

static gboolean
check_service_resolver_conflicting_candidate (SoupServer *server)
{
  g_auto (ServiceResolverFixture) original = { 0 };
  if (!service_resolver_fixture_init (server, &original,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &original, original.token, TRUE))
    return FALSE;
  wyl_id_t sid_id = WYL_ID_NIL;
  if (wyl_id_parse (original.sid, &sid_id) != WYRELOG_E_OK)
    return FALSE;
  wyl_service_session_descriptor_t candidate_descriptor = {
    .session_id = sid_id,.jti = original.other_jti,
    .subject_id = "svc:resolver:candidate",.tenant_id = "__wr_default",
    .credential_id = original.other_credential,.credential_generation = 10,
    .issued_at_seconds = original.now,.expires_at_seconds = original.now + 300,
  };
  g_autoptr (WylSession) candidate_session = NULL;
  gboolean changed = FALSE;
  if (wyl_daemon_http_service_registry_transition_for_test (server,
          original.sid, original.other_jti, original.other_credential, 10,
          candidate_descriptor.subject_id, candidate_descriptor.tenant_id,
          WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_POLICY
      || changed
      || wyl_session_new_service_detached (&candidate_descriptor,
          &candidate_session) != WYRELOG_E_OK
      || !wyl_daemon_http_replace_session_for_test (server, original.sid,
          candidate_session)
      || !wyl_daemon_http_store_service_access_token_for_test (server,
          original.other_jti, original.sid, candidate_descriptor.subject_id,
          candidate_descriptor.tenant_id, original.key_id, original.now + 300,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
          original.other_credential, 10, FALSE))
    return FALSE;
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
          sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_service_issue_input_t candidate_input = {
    .key_id = original.key_id,.jti = original.other_jti,
    .subject = candidate_descriptor.subject_id,.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = candidate_descriptor.tenant_id,
    .session_id = original.sid,.credential_id = original.other_credential,
    .credential_generation = 10,.issued_at = original.now,
  };
  g_autofree gchar *candidate_token = NULL;
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256_service (&candidate_input,
      secret, sizeof secret, &candidate_token);
  sodium_memzero (secret, sizeof secret);
  if (sign_rc != WYRELOG_E_OK
      || !service_resolver_expect (server, &original, candidate_token, FALSE))
    return FALSE;
  wyl_service_session_descriptor_t original_descriptor = {
    .session_id = sid_id,.jti = original.jti,
    .subject_id = "svc:resolver:test",.tenant_id = "__wr_default",
    .credential_id = original.credential,.credential_generation = 9,
    .issued_at_seconds = original.now,.expires_at_seconds = original.now + 300,
  };
  g_autoptr (WylSession) original_session = NULL;
  return wyl_session_new_service_detached (&original_descriptor,
      &original_session) == WYRELOG_E_OK
      && wyl_daemon_http_replace_session_for_test (server, original.sid,
      original_session)
      && service_resolver_expect (server, &original, original.token, TRUE);
}

static gint
check_service_bearer_resolver_contract (SoupServer *server)
{
  g_auto (ServiceResolverFixture) control = { 0 };
  if (!service_resolver_fixture_init (server, &control,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &control, control.token, TRUE))
    return 1970;
  if (!check_service_resolver_publication_barrier (server, &control))
    return 1971;
  g_auto (ServiceResolverFixture) preferred = { 0 };
  if (!service_resolver_fixture_init (server, &preferred,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &preferred, preferred.token, TRUE)
      || !check_service_resolver_writer_preference (server, &preferred))
    return 1976;
  g_auto (ServiceResolverFixture) inverse = { 0 };
  if (!service_resolver_fixture_init (server, &inverse,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &inverse, inverse.token, TRUE)
      || !check_service_resolver_inverse_barrier (server, &inverse))
    return 1972;
  if (!check_human_resolver_while_write_held (server))
    return 1973;
  if (!check_service_resolver_prelatched_unavailable ())
    return 1974;
  if (!check_service_resolver_terminal_failure ())
    return 1975;
  if (!check_service_resolver_crypto_pre_read (server, &control))
    return 1977;
  if (!check_service_resolver_conflicting_candidate (server))
    return 1978;

  /* Every signed-claim mutation has the exact ACTIVE fixture as its control. */
  for (guint field = 1; field <= 10; field++) {
    g_autofree gchar *variant = service_resolver_sign_variant (server,
        &control, field);
    if (variant == NULL || strcmp (variant, control.token) == 0
        || (field >= 7 ? !service_resolver_rejects_before_read (server, variant)
            : !service_resolver_expect (server, &control, variant, FALSE))
        || !service_resolver_expect (server, &control, control.token, TRUE))
      return 1971 + (gint) field;
  }

  /* Live access-token absence, revocation, expiry, and every tuple field. */
  for (guint field = 0; field < 11; field++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
            WYL_SERVICE_AUTH_ACTIVE, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
      return 1990 + (gint) field;
    if (field == 0) {
      if (!wyl_daemon_http_remove_access_token_for_test (server, fixture.jti))
        return 2010;
    } else if (field == 1) {
      if (!wyl_daemon_http_revoke_access_token_for_test (server, fixture.jti))
        return 2011;
    } else {
      gint token_field = field - 1;
      const gchar *text = field == 3 ? fixture.other_sid
          : field == 4 ? fixture.other_jti
          : field == 5 ? "svc:resolver:other"
          : field == 6 ? "tenant-other"
          : field == 7 ? "wrong-key"
          : field == 9 ? fixture.other_credential : NULL;
      guint64 number = field == 2 ? (guint64) (fixture.now - 1)
          : field == 8 ? WYL_SESSION_AUTH_METHOD_HUMAN : 10;
      if (!wyl_daemon_http_mutate_access_token_for_test (server, fixture.jti,
              token_field, text, number))
        return 2020 + (gint) field;
    }
    if (!service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2040 + (gint) field;
  }

  /* Live service-session absence/inactive and all immutable tuple/time fields. */
  const gint session_fields[] = {
    WYL_DAEMON_SERVICE_SESSION_INACTIVE,
    WYL_DAEMON_SERVICE_SESSION_AUTH_METHOD,
    WYL_DAEMON_SERVICE_SESSION_ID,
    WYL_DAEMON_SERVICE_SESSION_JTI,
    WYL_DAEMON_SERVICE_SESSION_SUBJECT,
    WYL_DAEMON_SERVICE_SESSION_TENANT,
    WYL_DAEMON_SERVICE_SESSION_CREDENTIAL,
    WYL_DAEMON_SERVICE_SESSION_GENERATION,
    WYL_DAEMON_SERVICE_SESSION_ISSUED_AT,
    WYL_DAEMON_SERVICE_SESSION_EXPIRES_AT,
  };
  for (guint i = 0; i <= G_N_ELEMENTS (session_fields); i++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
            WYL_SERVICE_AUTH_ACTIVE, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
      return 2060 + (gint) i;
    if (i == 0) {
      if (!wyl_daemon_http_remove_session_for_test (server, fixture.sid))
        return 2080;
    } else {
      gint field = session_fields[i - 1];
      const gchar *text = field == WYL_DAEMON_SERVICE_SESSION_ID
          ? fixture.other_sid
          : field == WYL_DAEMON_SERVICE_SESSION_JTI ? fixture.other_jti
          : field == WYL_DAEMON_SERVICE_SESSION_SUBJECT
          ? "svc:resolver:other"
          : field == WYL_DAEMON_SERVICE_SESSION_TENANT ? "tenant-other"
          : field == WYL_DAEMON_SERVICE_SESSION_CREDENTIAL
          ? fixture.other_credential : NULL;
      guint64 number = field == WYL_DAEMON_SERVICE_SESSION_GENERATION ? 10
          : (guint64) (fixture.now + 1);
      if (!wyl_daemon_http_mutate_service_session_for_test (server,
              fixture.sid, field, text, number))
        return 2080 + (gint) i;
    }
    if (!service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2100 + (gint) i;
  }

  /* Registry lifecycle and each exact reservation tuple component. */
  for (gint state = -1; state <= WYL_SERVICE_AUTH_REVOKED; state++) {
    if (state == WYL_SERVICE_AUTH_ACTIVE)
      continue;
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture, state, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2120 + state;
  }
  for (guint mismatch = 1; mismatch <= 6; mismatch++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
            WYL_SERVICE_AUTH_ACTIVE, mismatch)
        || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2130 + (gint) mismatch;
  }
  g_auto (ServiceResolverFixture) cross_a = { 0 };
  g_auto (ServiceResolverFixture) cross_b = { 0 };
  if (!service_resolver_fixture_init (server, &cross_a,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_fixture_init (server, &cross_b,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &cross_a, cross_a.token, TRUE)
      || !service_resolver_expect (server, &cross_b, cross_b.token, TRUE))
    return 2137;
  g_autofree gchar *crossed = service_resolver_sign_crossed (server,
      &cross_a, &cross_b);
  if (crossed == NULL
      || !wyl_daemon_http_store_service_access_token_for_test (server,
          cross_b.jti, cross_a.sid, "svc:resolver:test", "__wr_default",
          cross_a.key_id, cross_a.now + 300,
          WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, cross_a.credential, 9,
          FALSE)
      || !wyl_daemon_http_mutate_service_session_for_test (server,
          cross_a.sid, WYL_DAEMON_SERVICE_SESSION_JTI, cross_b.jti, 0)
      || !service_resolver_expect (server, &cross_a, crossed, FALSE))
    return 2138;
  g_auto (ServiceResolverFixture) removed = { 0 };
  gboolean changed = FALSE;
  if (!service_resolver_fixture_init (server, &removed,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &removed, removed.token, TRUE)
      || wyl_daemon_http_service_registry_transition_for_test (server,
          removed.sid, removed.jti, removed.credential, 9,
          "svc:resolver:test", "__wr_default",
          WYL_DAEMON_SERVICE_REGISTRY_REMOVE, &changed) != WYRELOG_E_OK
      || !changed
      || !service_resolver_expect (server, &removed, removed.token, FALSE))
    return 2140;
  g_auto (ServiceResolverFixture) duplicate = { 0 };
  if (!service_resolver_fixture_init (server, &duplicate,
          WYL_SERVICE_AUTH_ACTIVE, 0)
      || wyl_daemon_http_service_registry_transition_for_test (server,
          duplicate.sid, duplicate.jti, duplicate.other_credential, 10,
          "svc:resolver:other", "tenant-other",
          WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_POLICY
      || !service_resolver_expect (server, &duplicate, duplicate.token, TRUE))
    return 2141;

  g_auto (ServiceResolverFixture) sealed = { 0 };
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
          TRUE, FALSE) != WYRELOG_E_OK
      || !service_resolver_fixture_init_tenant (server, &sealed,
          WYL_SERVICE_AUTH_ACTIVE, 0, "tenant-sealed"))
    return 2144;
  if (!service_resolver_expect (server, &sealed, sealed.token, TRUE))
    return 2145;
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
          FALSE, TRUE)
      != WYRELOG_E_OK)
    return 2146;
  if (!service_resolver_expect (server, &sealed, sealed.token, FALSE))
    return 2147;
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
          FALSE, FALSE)
      != WYRELOG_E_OK)
    return 2148;
  if (!service_resolver_expect (server, &sealed, sealed.token, TRUE))
    return 2149;
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
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL)
    return 532;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_access_token (access_token, secret,
      sizeof secret, key_id, "wyrelogd", "wyrelog-client", now, &payload);
  memset (secret, 0, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return 536;

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
    return 537;
  g_autofree gchar *jti = extract_json_string (payload_text, "jti");
  if (jti == NULL || g_strcmp0 (jti, session_token) == 0)
    return 538;
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
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL) {
    memset (secret, 0, sizeof secret);
    return WYRELOG_E_INTERNAL;
  }

  wyl_jwt_issue_input_t input = {
    .key_id = key_id,
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
check_jwt_epoch_rotation_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  g_autofree gchar *key_id_before =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id_before == NULL)
    return 1840;

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  gint rc = send_raw_login (session, "POST", base_url,
      "username=rotation-user&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1841;

  g_autofree gchar *session_token = extract_json_string (body,
      "session_token");
  g_autofree gchar *access_token = extract_json_string (body, "access_token");
  g_autofree gchar *refresh_token = extract_json_string (body,
      "refresh_token");
  if (session_token == NULL || access_token == NULL || refresh_token == NULL)
    return 1842;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "rotation-user",
      "site.rotation.read", "rotation-scope", NULL, access_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1843;

  if (wyl_daemon_http_rotate_access_token_key_for_test (server)
      != WYRELOG_E_OK)
    return 1844;

  g_autofree gchar *key_id_after =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id_after == NULL || g_strcmp0 (key_id_before, key_id_after) == 0)
    return 1845;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "rotation-user",
      "site.rotation.read", "rotation-scope", NULL, access_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 1846;

  g_clear_pointer (&body, g_free);
  rc = send_raw_refresh (session, "POST", base_url, refresh_token, &status,
      &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 1847;

  return 0;
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

  rc = check_concurrent_human_refresh_single_flight (server, base_url);
  if (rc != 0)
    return rc;
  if (!wyl_daemon_http_test_human_refresh_classifier (server))
    return 2235;
  rc = check_human_refresh_response_loss (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_prepared_expiry (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_fault_matrix (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_failure_and_clock_boundaries (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_logout_ordering (server, base_url);
  if (rc != 0)
    return rc;

  rc = check_service_refresh_isolation (server, base_url,
      authenticated_session_token);
  if (rc != 0)
    return rc;

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
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 484;
  g_clear_pointer (&body, g_free);

  /*
   * A foreign-looking unregistered tenant literal on /auth/login
   * must fail closed with the stable wire code "tenant_invalid" and
   * HTTP 400, mirroring the /decide gate above.
   */
  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&tenant=evil-co", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 513;
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
  /*
   * The logout teardown must mark the session as revoked in the
   * daemon-side gate so the store paths refuse any token state an
   * in-flight /auth/refresh might still try to insert after the
   * snapshot-walking revoke pass returned. The revoked-session set
   * is the structural fix for the residual store-after-revoke
   * window the snapshot revoke alone leaves open.
   */
  if (!wyl_daemon_http_session_is_revoked (server, bearer_logout_session_token))
    return 526;
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

static wyrelog_error_t
grant_tenant_manage_authority (WylHandle *handle, const gchar *subject)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store,
      subject, "wr.tenant.manage", WYL_TENANT_DEFAULT);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_permission_state (store, subject,
      "wr.tenant.manage", WYL_TENANT_DEFAULT, "armed");
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
  if (grant_tenant_manage_authority (handle, "http-policy-admin")
      != WYRELOG_E_OK)
    return 189;

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
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 187;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a")) {
    return 188;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_create_query =
      g_strdup_printf ("name=tenant-a&tenant=%s&session_token=%s"
      "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
      WYL_TENANT_DEFAULT, session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/tenants/create", tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL ||
      strstr (body, "\"changed\":true") == NULL)
    return 190;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/tenants/create", tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL)
    return 191;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "GET", base_url, "/tenants",
      tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL ||
      strstr (body, "\"tenant\":\"__wr_default\"") == NULL)
    return 192;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  rc = send_raw_login (session, "POST", base_url,
      "username=tenant-user&tenant=tenant-a&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL)
    return 193;
  g_autofree gchar *tenant_session_token =
      extract_json_string (body, "session_token");
  if (tenant_session_token == NULL)
    return 194;
  g_clear_pointer (&body, g_free);

  if (grant_policy_write_authority (handle, "tenant-user", "tenant-a")
      != WYRELOG_E_OK)
    return 195;
  g_autofree gchar *cross_tenant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-b"
      "&tenant=tenant-a&session_token=%s&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", tenant_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", cross_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"tenant_denied\"") == NULL)
    return 196;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-b"))
    return 197;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_grant_query =
      g_strdup_printf ("subject=tenant-target&perm=site.policy.read"
      "&scope=tenant-a&tenant=tenant-a&session_token=%s"
      "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
      tenant_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", tenant_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 198;
  if (!direct_permission_exists (handle, "tenant-target", "site.policy.read",
          "tenant-a"))
    return 199;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_seal_query =
      g_strdup_printf ("name=tenant-a&tenant=%s&session_token=%s"
      "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
      WYL_TENANT_DEFAULT, session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url, "/tenants/seal",
      tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL)
    return 200;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=tenant-user&tenant=tenant-a&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_sealed\"") == NULL)
    return 201;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/tenants/unseal", tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 202;
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
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
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
 * Unit-style coverage for the tenant-gate wire codes. Drives the
 * http.c decision helper through the WYL_TEST_DAEMON_HTTP seam so
 * that both stable gate arms are exercised directly.
 */
static gint
check_tenant_gate_codes_contract (void)
{
  /* Pass: matching default tenant on both sides. */
  guint status = 0;
  g_autofree gchar *code = NULL;
  if (!wyl_daemon_http_check_request_tenant_for_test ("__wr_default",
          "__wr_default", &status, &code))
    return 1900;
  if (status != 0 || code != NULL)
    return 1901;

  /* Pass: NULL request tenant falls back to the default, matches auth. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (!wyl_daemon_http_check_request_tenant_for_test (NULL, "__wr_default",
          &status, &code))
    return 1902;
  if (status != 0 || code != NULL)
    return 1903;

  /* Reject: request tenant is not known to the test seam. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("unknown",
          "__wr_default", &status, &code))
    return 1904;
  if (status != 400 || g_strcmp0 (code, "tenant_invalid") != 0)
    return 1905;

  /* Reject: empty request tenant. 400 tenant_invalid. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("", "__wr_default",
          &status, &code))
    return 1906;
  if (status != 400 || g_strcmp0 (code, "tenant_invalid") != 0)
    return 1907;

  /*
   * Reject: request tenant is the known default but the authenticated
   * principal carries a different tenant. 403 tenant_denied.
   */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("__wr_default",
          "other-tenant", &status, &code))
    return 1908;
  if (status != 403 || g_strcmp0 (code, "tenant_denied") != 0)
    return 1909;

  /* Reject: missing auth tenant on a default-tenant request. 403 tenant_denied. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("__wr_default", NULL,
          &status, &code))
    return 1910;
  if (status != 403 || g_strcmp0 (code, "tenant_denied") != 0)
    return 1911;

  return 0;
}

/*
 * The daemon-http-decide test surface has been split across three binaries
 * compiled from this single translation unit:
 *
 *   - WYL_TEST_VARIANT_AUDIT undefined: HTTP-decide protocol contracts
 *     (readyz, request-id headers, raw decide, policy mutation, login + decide,
 *     and login + guarded-decide).
 *
 *   - WYL_TEST_VARIANT_REFRESH defined: the raw-login, JWT-rotation, and
 *     human-refresh shutdown flows that would otherwise push the non-audit
 *     binary over the wall-clock ceiling on slower CI runners.
 *
 *   - WYL_TEST_VARIANT_AUDIT defined: end-to-end audit pipeline. Generates
 *     the decide and policy events the audit verification depends on, then
 *     verifies the audit log via raw HTTP, the readyz audit-projection
 *     contract, and a series of audit_event_present queries.
 *
 * Splitting was driven by Meson's per-test timeout and the slower macOS CI
 * runner: the merged surface serialised on local TCP and DuckDB, and the
 * refresh-heavy tail could overrun the wall-clock ceiling. The binaries now
 * run in parallel, each with its own daemon, and each finishes well under
 * the timeout. Variant-irrelevant static helpers stay defined in this file;
 * the build silences the resulting -Wunused-function warnings.
 */
#if defined(WYL_TEST_VARIANT_REFRESH)
int
main (void)
{
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  gint policy_shutdown_rc = check_daemon_policy_write_shutdown_contract ();
  if (policy_shutdown_rc != 0)
    return policy_shutdown_rc;

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
  gint dispatch_context_rc = check_explicit_refresh_dispatch_context (handle,
      &runtime);
  if (dispatch_context_rc != 0)
    return dispatch_context_rc;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide-refresh",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint raw_login_rc = check_raw_login_contract (http.server, handle,
      base_url);
  if (raw_login_rc != 0)
    return raw_login_rc;
  gint jwt_rc = check_jwt_epoch_rotation_contract (http.server, handle,
      base_url);
  if (jwt_rc != 0)
    return jwt_rc;
  gint refresh_shutdown_rc = check_human_refresh_shutdown_ordering
      (http.server, base_url);
  if (refresh_shutdown_rc != 0)
    return refresh_shutdown_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#elif !defined(WYL_TEST_VARIANT_AUDIT)
int
main (void)
{
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  gint policy_shutdown_rc = check_daemon_policy_write_shutdown_contract ();
  if (policy_shutdown_rc != 0)
    return policy_shutdown_rc;

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
  gint dispatch_context_rc = check_explicit_refresh_dispatch_context (handle,
      &runtime);
  if (dispatch_context_rc != 0)
    return dispatch_context_rc;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 3;
  wyl_daemon_access_token_snapshot_t service_token_snapshot = { 0 };
  gint service_state_rc = check_service_access_token_state_contract
      (http.server, &service_token_snapshot);
  if (service_state_rc != 0)
    return service_state_rc;
  gint service_resolver_rc = check_service_bearer_resolver_contract
      (http.server);
  if (service_resolver_rc != 0)
    return service_resolver_rc;
  GThread *thread = g_thread_new ("daemon-http-decide",
      test_http_server_thread, &http);
  if (!wyl_daemon_http_refresh_context_is_for_test (http.server,
          g_main_context_default ()))
    return 2267;
  if (wyl_daemon_http_refresh_context_owned_for_test (http.server))
    return 2268;
  guint context_owned = 0, context_wrong = 0;
  wyl_daemon_http_refresh_lifecycle_counts_for_test (http.server,
      &context_owned, &context_wrong);
  if (context_owned != 0 || context_wrong != 1)
    return 2269;

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

  gint raw_rc = check_raw_decide_contract (http.server, handle, base_url);
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

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  if (g_strcmp0 (service_token_snapshot.subject, "svc:state:test") != 0
      || g_strcmp0 (service_token_snapshot.credential_id, NULL) == 0) {
    wyl_daemon_access_token_snapshot_clear (&service_token_snapshot);
    return 1957;
  }
  wyl_daemon_access_token_snapshot_clear (&service_token_snapshot);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#else /* WYL_TEST_VARIANT_AUDIT */
int
main (void)
{
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

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
  gint raw_rc = check_raw_decide_contract (http.server, handle, base_url);
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
