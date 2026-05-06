/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include <glib.h>

#include "daemon/http.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
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

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"login_denied\"") == NULL)
    return 473;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=false", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL)
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
  g_clear_pointer (&body, g_free);

  g_autoptr (WylSession) unknown_session =
      wyl_daemon_http_ref_session (server, "unknown-session");
  if (unknown_session != NULL)
    return 480;

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
send_raw_policy_mutation (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 122;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static wyrelog_error_t
grant_policy_write_authority (WylHandle *handle, const gchar *subject,
    const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_upsert_permission (store,
      "wr.policy.write", "policy write", "critical");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_direct_permission (store, subject,
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
  wyrelog_error_t rc = wyl_policy_store_upsert_permission (store,
      "wr.policy.grant_role", "policy grant role", "critical");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_direct_permission (store, subject,
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
check_policy_permission_mutation_contract (WylHandle *handle,
    WylClient *client, const gchar *base_url)
{
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-policy-admin") != WYRELOG_E_OK)
    return 123;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  g_autofree gchar *session_token = wyl_client_dup_session_token (client);
  if (session_token == NULL)
    return 124;

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

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", "perm=site.policy.read&scope=tenant-a",
      &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 127;
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
          "tenant-a"))
    return 131;
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

  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", missing_perm_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 155;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *guard_denied_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=50", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", guard_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 133;
  if (direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 134;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *grant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
      "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/permissions/grant", grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 135;
  if (!direct_permission_exists (handle, "target", "site.policy.read",
          "tenant-a"))
    return 136;
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
  rc = send_raw_policy_mutation (session, "POST", base_url,
      "/policy/roles/grant", role_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 145;
  if (!role_membership_exists (handle, "role-target", "site.reader",
          "tenant-b"))
    return 146;

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
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
check_raw_audit_contract (WylClient *client, const gchar *base_url,
    const gchar *session_token)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  gint rc = send_raw_audit (session, base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 93;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit (session, base_url,
      "session_token=unknown&guard_timestamp=123&guard_loc_class=public"
      "&guard_risk=69", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 94;

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

  g_autoptr (WylAuditIter) invalid_filter = NULL;
  if (wyl_client_audit_query_with_guard_context (client, "action()", 123,
          "public", 69, &invalid_filter) != WYRELOG_E_OK)
    return 99;
  gboolean has_next = FALSE;
  if (wyl_audit_iter_next (invalid_filter, &has_next) != WYRELOG_E_IO)
    return 100;

  return 0;
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

  raw_rc = check_policy_permission_mutation_contract (handle, client, base_url);
  if (raw_rc != 0)
    return raw_rc;

#ifdef WYL_HAS_AUDIT
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-audit-user") != WYRELOG_E_OK)
    return 84;
  g_autofree gchar *audit_session_token = wyl_client_dup_session_token (client);
  if (audit_session_token == NULL)
    return 85;
  if (grant_audit_read (handle, "http-audit-user", audit_session_token) !=
      WYRELOG_E_OK)
    return 86;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  gint audit_auth_rc = check_raw_audit_contract (client, base_url,
      audit_session_token);
  if (audit_auth_rc != 0)
    return audit_auth_rc;

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
#endif

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
