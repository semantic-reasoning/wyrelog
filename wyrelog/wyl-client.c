/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyl-client-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

struct _WylClient
{
  GObject parent_instance;
  gchar *base_url;
  gchar *session_token;
  gchar *access_token;
  gchar *refresh_token;
  gchar *username;
  gchar *tenant;
  gchar *selected_tenant;
  gchar *principal_state;
  gchar *session_state;
  SoupSession *session;
  guint timeout_ms;
};

struct _WylClientDecision
{
  gint decision;
  gchar *deny_reason;
  gchar *deny_origin;
};

G_DEFINE_FINAL_TYPE (WylClient, wyl_client, G_TYPE_OBJECT);

static gboolean parse_login_response_json (const gchar * data, gsize size,
    gchar ** out_session_token,
    gchar ** out_access_token, gchar ** out_refresh_token,
    gchar ** out_username, gchar ** out_tenant, gchar ** out_principal_state,
    gchar ** out_session_state);

static void
wyl_client_clear_login_state (WylClient *self)
{
  g_clear_pointer (&self->session_token, g_free);
  g_clear_pointer (&self->access_token, g_free);
  g_clear_pointer (&self->refresh_token, g_free);
  g_clear_pointer (&self->username, g_free);
  g_clear_pointer (&self->tenant, g_free);
  g_clear_pointer (&self->selected_tenant, g_free);
  g_clear_pointer (&self->principal_state, g_free);
  g_clear_pointer (&self->session_state, g_free);
}

static void
wyl_client_finalize (GObject *object)
{
  WylClient *self = WYL_CLIENT (object);

  g_free (self->base_url);
  wyl_client_clear_login_state (self);
  g_clear_object (&self->session);

  G_OBJECT_CLASS (wyl_client_parent_class)->finalize (object);
}

static void
wyl_client_class_init (WylClientClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_client_finalize;
}

static void
wyl_client_init (WylClient *self)
{
  (void) self;
}

static gboolean
credential_part_is_valid (const gchar *value)
{
  if (value == NULL || value[0] == '\0')
    return FALSE;

  for (const gchar * p = value; *p != '\0'; p++) {
    if (g_ascii_isspace (*p) || g_ascii_iscntrl (*p))
      return FALSE;
  }
  return TRUE;
}

wyrelog_error_t
wyl_client_new (const gchar *base_url, WylClient **out_client)
{
  if (out_client == NULL)
    return WYRELOG_E_INVALID;
  *out_client = NULL;
  if (base_url == NULL || base_url[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autoptr (GError) error = NULL;
  g_autoptr (GUri) uri = g_uri_parse (base_url, G_URI_FLAGS_NONE, &error);
  if (uri == NULL)
    return WYRELOG_E_INVALID;

  const gchar *scheme = g_uri_get_scheme (uri);
  if (g_strcmp0 (scheme, "http") != 0 && g_strcmp0 (scheme, "https") != 0)
    return WYRELOG_E_INVALID;

  WylClient *client = g_object_new (WYL_TYPE_CLIENT, NULL);
  client->base_url = g_strdup (base_url);
  client->session = soup_session_new ();
  *out_client = client;
  return WYRELOG_E_OK;
}

gchar *
wyl_client_dup_base_url (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->base_url);
}

gchar *
wyl_client_dup_session_token (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->session_token);
}

gchar *
wyl_client_dup_access_token (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->access_token);
}

gchar *
wyl_client_dup_username (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->username);
}

gchar *
wyl_client_dup_tenant (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->selected_tenant != NULL ? client->selected_tenant
      : client->tenant);
}

gchar *
wyl_client_dup_principal_state (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->principal_state);
}

gchar *
wyl_client_dup_session_state (const WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT ((WylClient *) client), NULL);
  return g_strdup (client->session_state);
}

SoupSession *
wyl_client_get_soup_session (WylClient *client)
{
  g_return_val_if_fail (WYL_IS_CLIENT (client), NULL);
  return client->session;
}

void
wyl_client_set_timeout_ms (WylClient *client, guint timeout_ms)
{
  g_return_if_fail (WYL_IS_CLIENT (client));
  client->timeout_ms = timeout_ms;
}

typedef struct
{
  GCancellable *cancellable;
  GCond cond;
  GMutex mutex;
  gboolean done;
  guint timeout_ms;
} WylClientTimeout;

static gpointer
client_timeout_thread_func (gpointer data)
{
  WylClientTimeout *timeout = data;

  g_mutex_lock (&timeout->mutex);
  gint64 deadline = g_get_monotonic_time () + (gint64) timeout->timeout_ms
      * 1000;
  while (!timeout->done) {
    if (!g_cond_wait_until (&timeout->cond, &timeout->mutex, deadline))
      break;
  }
  if (!timeout->done)
    g_cancellable_cancel (timeout->cancellable);
  g_mutex_unlock (&timeout->mutex);

  return NULL;
}

wyrelog_error_t
wyl_client_send_message (WylClient *client, SoupMessage *message,
    GBytes **out_body)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || message == NULL ||
      out_body == NULL)
    return WYRELOG_E_INVALID;
  *out_body = NULL;

  g_autoptr (GError) error = NULL;
  g_autoptr (GCancellable) cancellable =
      client->timeout_ms > 0 ? g_cancellable_new () : NULL;
  WylClientTimeout timeout = {
    .cancellable = cancellable,
    .timeout_ms = client->timeout_ms,
  };
  GThread *timeout_thread = NULL;
  if (cancellable != NULL) {
    g_cond_init (&timeout.cond);
    g_mutex_init (&timeout.mutex);
    timeout_thread = g_thread_new ("wyl-client-timeout",
        client_timeout_thread_func, &timeout);
  }

  GBytes *body = soup_session_send_and_read (client->session, message,
      cancellable, &error);
  if (timeout_thread != NULL) {
    g_mutex_lock (&timeout.mutex);
    timeout.done = TRUE;
    g_cond_signal (&timeout.cond);
    g_mutex_unlock (&timeout.mutex);
    g_thread_join (timeout_thread);
    g_mutex_clear (&timeout.mutex);
    g_cond_clear (&timeout.cond);
  }
  if (body == NULL)
    return WYRELOG_E_IO;

  guint status = soup_message_get_status (message);
  if (status < 200 || status >= 300) {
    g_bytes_unref (body);
    return WYRELOG_E_IO;
  }

  *out_body = body;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
client_login_internal (WylClient *client, const gchar *username,
    const gchar *password, gboolean skip_mfa)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || username == NULL ||
      username[0] == '\0')
    return WYRELOG_E_INVALID;
  if (skip_mfa && password != NULL)
    return WYRELOG_E_INVALID;
  if (password != NULL && password[0] != '\0')
    return WYRELOG_E_INVALID;

  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (base_url == NULL)
    return WYRELOG_E_INVALID;
  while (base_url[0] != '\0' && g_str_has_suffix (base_url, "/"))
    base_url[strlen (base_url) - 1] = '\0';

  g_autofree gchar *escaped_username =
      g_uri_escape_string (username, NULL, TRUE);
  g_autofree gchar *uri = NULL;
  if (skip_mfa) {
    uri = g_strdup_printf ("%s/auth/login?username=%s&skip_mfa=true",
        base_url, escaped_username);
  } else {
    uri = g_strdup_printf ("%s/auth/login?username=%s", base_url,
        escaped_username);
  }

  g_autoptr (SoupMessage) message = soup_message_new ("POST", uri);
  if (message == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GBytes) body = NULL;
  wyrelog_error_t rc = wyl_client_send_message (client, message, &body);
  if (rc != WYRELOG_E_OK) {
    wyl_client_clear_login_state (client);
    return rc;
  }

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  g_autofree gchar *session_token = NULL;
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *refresh_token = NULL;
  g_autofree gchar *parsed_username = NULL;
  g_autofree gchar *tenant = NULL;
  g_autofree gchar *principal_state = NULL;
  g_autofree gchar *session_state = NULL;
  if (!parse_login_response_json (body_data, body_size, &session_token,
          &access_token, &refresh_token, &parsed_username, &tenant,
          &principal_state, &session_state)) {
    wyl_client_clear_login_state (client);
    return WYRELOG_E_IO;
  }

  wyl_client_clear_login_state (client);
  client->session_token = g_steal_pointer (&session_token);
  client->access_token = g_steal_pointer (&access_token);
  client->refresh_token = g_steal_pointer (&refresh_token);
  client->username = g_steal_pointer (&parsed_username);
  client->tenant = g_steal_pointer (&tenant);
  client->selected_tenant = g_strdup (client->tenant);
  client->principal_state = g_steal_pointer (&principal_state);
  client->session_state = g_steal_pointer (&session_state);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_login (WylClient *client, const gchar *username,
    const gchar *password)
{
  return client_login_internal (client, username, password, FALSE);
}

wyrelog_error_t
wyl_client_login_skip_mfa (WylClient *client, const gchar *username)
{
  return client_login_internal (client, username, NULL, TRUE);
}

wyrelog_error_t
wyl_client_set_bearer_credentials (WylClient *client,
    const gchar *access_token, const gchar *tenant)
{
  if (client == NULL || !WYL_IS_CLIENT (client) ||
      !credential_part_is_valid (access_token) ||
      !credential_part_is_valid (tenant))
    return WYRELOG_E_INVALID;

  wyl_client_clear_login_state (client);
  client->access_token = g_strdup (access_token);
  client->tenant = g_strdup (tenant);
  client->selected_tenant = g_strdup (tenant);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_token_refresh (WylClient *client)
{
  if (client == NULL || !WYL_IS_CLIENT (client))
    return WYRELOG_E_INVALID;
  if (client->refresh_token == NULL || client->refresh_token[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (base_url == NULL)
    return WYRELOG_E_INVALID;
  while (base_url[0] != '\0' && g_str_has_suffix (base_url, "/"))
    base_url[strlen (base_url) - 1] = '\0';

  g_autofree gchar *escaped_refresh =
      g_uri_escape_string (client->refresh_token, NULL, TRUE);
  g_autofree gchar *uri = g_strdup_printf ("%s/auth/refresh?refresh_token=%s",
      base_url, escaped_refresh);
  g_autoptr (SoupMessage) message = soup_message_new ("POST", uri);
  if (message == NULL)
    return WYRELOG_E_INVALID;

  g_autoptr (GBytes) body = NULL;
  wyrelog_error_t rc = wyl_client_send_message (client, message, &body);
  if (rc != WYRELOG_E_OK)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  g_autofree gchar *session_token = NULL;
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *refresh_token = NULL;
  g_autofree gchar *parsed_username = NULL;
  g_autofree gchar *tenant = NULL;
  g_autofree gchar *principal_state = NULL;
  g_autofree gchar *session_state = NULL;
  if (!parse_login_response_json (body_data, body_size, &session_token,
          &access_token, &refresh_token, &parsed_username, &tenant,
          &principal_state, &session_state))
    return WYRELOG_E_IO;

  wyl_client_clear_login_state (client);
  client->session_token = g_steal_pointer (&session_token);
  client->access_token = g_steal_pointer (&access_token);
  client->refresh_token = g_steal_pointer (&refresh_token);
  client->username = g_steal_pointer (&parsed_username);
  client->tenant = g_steal_pointer (&tenant);
  client->selected_tenant = g_strdup (client->tenant);
  client->principal_state = g_steal_pointer (&principal_state);
  client->session_state = g_steal_pointer (&session_state);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_mfa_verify (WylClient *client, const gchar *otp)
{
  (void) client;
  (void) otp;
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
client_policy_mutation_request (WylClient *client, const gchar *path,
    const gchar *subject, const gchar *target_name, const gchar *target_value,
    const gchar *scope, const gchar *event, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || path == NULL ||
      subject == NULL || subject[0] == '\0' || target_name == NULL ||
      target_value == NULL || target_value[0] == '\0' || scope == NULL ||
      scope[0] == '\0')
    return WYRELOG_E_INVALID;
  if (event != NULL && event[0] == '\0')
    return WYRELOG_E_INVALID;
  if (guard_timestamp < 0 || guard_loc_class == NULL || guard_risk < 0 ||
      guard_risk > 100 || !wyl_guard_loc_class_is_valid (guard_loc_class))
    return WYRELOG_E_INVALID;

  g_autofree gchar *session_token = wyl_client_dup_session_token (client);
  g_autofree gchar *access_token = wyl_client_dup_access_token (client);
  gboolean has_session = session_token != NULL && session_token[0] != '\0';
  gboolean has_access = access_token != NULL && access_token[0] != '\0';
  if (!has_session && !has_access)
    return WYRELOG_E_INVALID;
  gboolean use_access_token = has_access;
  g_autofree gchar *tenant = wyl_client_dup_tenant (client);
  if (tenant == NULL || tenant[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (base_url == NULL)
    return WYRELOG_E_INVALID;
  while (base_url[0] != '\0' && g_str_has_suffix (base_url, "/"))
    base_url[strlen (base_url) - 1] = '\0';

  g_autofree gchar *escaped_subject = g_uri_escape_string (subject, NULL, TRUE);
  g_autofree gchar *escaped_target =
      g_uri_escape_string (target_value, NULL, TRUE);
  g_autofree gchar *escaped_scope = g_uri_escape_string (scope, NULL, TRUE);
  g_autofree gchar *escaped_tenant = g_uri_escape_string (tenant, NULL, TRUE);
  g_autofree gchar *escaped_event =
      event != NULL ? g_uri_escape_string (event, NULL, TRUE) : NULL;
  g_autofree gchar *escaped_loc =
      g_uri_escape_string (guard_loc_class, NULL, TRUE);
  g_autofree gchar *uri = NULL;
  if (use_access_token) {
    if (escaped_event != NULL) {
      uri = g_strdup_printf ("%s/%s?subject=%s&%s=%s&scope=%s&tenant=%s"
          "&event=%s"
          "&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          base_url, path, escaped_subject, target_name, escaped_target,
          escaped_scope, escaped_tenant, escaped_event, guard_timestamp,
          escaped_loc, guard_risk);
    } else {
      uri = g_strdup_printf ("%s/%s?subject=%s&%s=%s&scope=%s&tenant=%s"
          "&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          base_url, path, escaped_subject, target_name, escaped_target,
          escaped_scope, escaped_tenant, guard_timestamp, escaped_loc,
          guard_risk);
    }
  } else {
    g_autofree gchar *escaped_session =
        g_uri_escape_string (session_token, NULL, TRUE);
    if (escaped_event != NULL) {
      uri = g_strdup_printf ("%s/%s?subject=%s&%s=%s&scope=%s&event=%s"
          "&tenant=%s&session_token=%s&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          base_url, path, escaped_subject, target_name, escaped_target,
          escaped_scope, escaped_event, escaped_tenant, escaped_session,
          guard_timestamp, escaped_loc, guard_risk);
    } else {
      uri = g_strdup_printf ("%s/%s?subject=%s&%s=%s&scope=%s&tenant=%s"
          "&session_token=%s&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          base_url, path, escaped_subject, target_name, escaped_target,
          escaped_scope, escaped_tenant, escaped_session, guard_timestamp,
          escaped_loc, guard_risk);
    }
  }

  g_autoptr (SoupMessage) message = soup_message_new ("POST", uri);
  if (message == NULL)
    return WYRELOG_E_INVALID;
  if (use_access_token) {
    g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
        access_token);
    soup_message_headers_replace (soup_message_get_request_headers (message),
        "Authorization", authorization);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body =
      soup_session_send_and_read (client->session, message, NULL, &error);
  if (body == NULL)
    return WYRELOG_E_IO;

  guint status = soup_message_get_status (message);
  if (status >= 200 && status < 300)
    return WYRELOG_E_OK;
  if (status == 400)
    return WYRELOG_E_INVALID;
  if (status == 401)
    return WYRELOG_E_AUTH;
  if (status == 403)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_IO;
}

wyrelog_error_t
wyl_client_policy_permission_grant (WylClient *client, const gchar *subject,
    const gchar *perm, const gchar *scope, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk)
{
  return client_policy_mutation_request (client, "policy/permissions/grant",
      subject, "perm", perm, scope, NULL, guard_timestamp, guard_loc_class,
      guard_risk);
}

wyrelog_error_t
wyl_client_policy_permission_revoke (WylClient *client, const gchar *subject,
    const gchar *perm, const gchar *scope, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk)
{
  return client_policy_mutation_request (client, "policy/permissions/revoke",
      subject, "perm", perm, scope, NULL, guard_timestamp, guard_loc_class,
      guard_risk);
}

wyrelog_error_t
wyl_client_policy_permission_transition (WylClient *client,
    const gchar *subject, const gchar *perm, const gchar *scope,
    const gchar *event, gint64 guard_timestamp, const gchar *guard_loc_class,
    gint64 guard_risk)
{
  if (event == NULL)
    return WYRELOG_E_INVALID;
  return client_policy_mutation_request (client,
      "policy/permissions/transition", subject, "perm", perm, scope, event,
      guard_timestamp, guard_loc_class, guard_risk);
}

wyrelog_error_t
wyl_client_policy_role_grant (WylClient *client, const gchar *subject,
    const gchar *role, const gchar *scope, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk)
{
  return client_policy_mutation_request (client, "policy/roles/grant",
      subject, "role", role, scope, NULL, guard_timestamp, guard_loc_class,
      guard_risk);
}

wyrelog_error_t
wyl_client_policy_role_revoke (WylClient *client, const gchar *subject,
    const gchar *role, const gchar *scope, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk)
{
  return client_policy_mutation_request (client, "policy/roles/revoke",
      subject, "role", role, scope, NULL, guard_timestamp, guard_loc_class,
      guard_risk);
}

typedef struct
{
  const gchar *data;
  gsize size;
  gsize pos;
} JsonCursor;

static void
json_skip_ws (JsonCursor *cursor)
{
  while (cursor->pos < cursor->size &&
      g_ascii_isspace (cursor->data[cursor->pos]))
    cursor->pos++;
}

static gboolean
json_consume (JsonCursor *cursor, gchar ch)
{
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size || cursor->data[cursor->pos] != ch)
    return FALSE;
  cursor->pos++;
  return TRUE;
}

static gboolean
json_hex_is_valid (gchar ch)
{
  return g_ascii_isxdigit (ch);
}

static gboolean
json_parse_string (JsonCursor *cursor, gchar **out_string)
{
  if (out_string == NULL)
    return FALSE;
  *out_string = NULL;
  if (!json_consume (cursor, '"'))
    return FALSE;

  g_autoptr (GString) value = g_string_new (NULL);
  while (cursor->pos < cursor->size) {
    guchar ch = (guchar) cursor->data[cursor->pos++];
    if (ch == '"') {
      *out_string = g_string_free (g_steal_pointer (&value), FALSE);
      return TRUE;
    }
    if (ch < 0x20)
      return FALSE;
    if (ch != '\\') {
      g_string_append_c (value, (gchar) ch);
      continue;
    }
    if (cursor->pos >= cursor->size)
      return FALSE;
    ch = (guchar) cursor->data[cursor->pos++];
    switch (ch) {
      case '"':
      case '\\':
      case '/':
        g_string_append_c (value, (gchar) ch);
        break;
      case 'b':
        g_string_append_c (value, '\b');
        break;
      case 'f':
        g_string_append_c (value, '\f');
        break;
      case 'n':
        g_string_append_c (value, '\n');
        break;
      case 'r':
        g_string_append_c (value, '\r');
        break;
      case 't':
        g_string_append_c (value, '\t');
        break;
      case 'u':
        if (cursor->pos + 4 > cursor->size)
          return FALSE;
        for (guint i = 0; i < 4; i++) {
          if (!json_hex_is_valid (cursor->data[cursor->pos++]))
            return FALSE;
        }
        g_string_append_c (value, '?');
        break;
      default:
        return FALSE;
    }
  }
  return FALSE;
}

static gboolean
json_parse_nullable_string_value (JsonCursor *cursor, gchar **out_value)
{
  if (out_value == NULL)
    return FALSE;
  *out_value = NULL;

  json_skip_ws (cursor);
  if (cursor->pos + 4 <= cursor->size &&
      memcmp (cursor->data + cursor->pos, "null", 4) == 0) {
    cursor->pos += 4;
    return TRUE;
  }

  return json_parse_string (cursor, out_value);
}

static gboolean
json_parse_decision (JsonCursor *cursor, gint *out_decision)
{
  if (out_decision == NULL)
    return FALSE;
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size)
    return FALSE;
  gchar ch = cursor->data[cursor->pos++];
  if (ch != '0' && ch != '1')
    return FALSE;
  if (cursor->pos < cursor->size && g_ascii_isdigit (cursor->data[cursor->pos]))
    return FALSE;
  *out_decision = ch == '1' ? WYL_DECISION_ALLOW : WYL_DECISION_DENY;
  return TRUE;
}

static gboolean
parse_decide_response_json (const gchar *data, gsize size,
    WylClientDecision **out_result)
{
  if (data == NULL || out_result == NULL)
    return FALSE;
  *out_result = NULL;

  JsonCursor cursor = { data, size, 0 };
  if (!json_consume (&cursor, '{'))
    return FALSE;

  gboolean have_decision = FALSE;
  gboolean have_deny_reason = FALSE;
  gboolean have_deny_origin = FALSE;
  gint decision = WYL_DECISION_DENY;
  g_autofree gchar *deny_reason = NULL;
  g_autofree gchar *deny_origin = NULL;
  json_skip_ws (&cursor);
  if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}')
    return FALSE;

  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!json_parse_string (&cursor, &key) || !json_consume (&cursor, ':'))
      return FALSE;

    if (g_strcmp0 (key, "decision") == 0) {
      if (have_decision || !json_parse_decision (&cursor, &decision))
        return FALSE;
      have_decision = TRUE;
    } else if (g_strcmp0 (key, "deny_reason") == 0 ||
        g_strcmp0 (key, "deny_origin") == 0) {
      gboolean *seen = g_strcmp0 (key, "deny_reason") == 0 ?
          &have_deny_reason : &have_deny_origin;
      gchar **target = g_strcmp0 (key, "deny_reason") == 0 ?
          &deny_reason : &deny_origin;
      if (*seen)
        return FALSE;
      if (!json_parse_nullable_string_value (&cursor, target))
        return FALSE;
      *seen = TRUE;
    } else {
      return FALSE;
    }

    json_skip_ws (&cursor);
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == ',') {
      cursor.pos++;
      continue;
    }
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}') {
      cursor.pos++;
      break;
    }
    return FALSE;
  }

  json_skip_ws (&cursor);
  if (!have_decision || !have_deny_reason || !have_deny_origin ||
      cursor.pos != cursor.size)
    return FALSE;

  WylClientDecision *result = g_new0 (WylClientDecision, 1);
  result->decision = decision;
  result->deny_reason = g_steal_pointer (&deny_reason);
  result->deny_origin = g_steal_pointer (&deny_origin);
  *out_result = result;
  return TRUE;
}

void
wyl_client_decision_free (WylClientDecision *result)
{
  if (result == NULL)
    return;

  g_free (result->deny_reason);
  g_free (result->deny_origin);
  g_free (result);
}

gint
wyl_client_decision_get_decision (const WylClientDecision *result)
{
  return result != NULL ? result->decision : WYL_DECISION_DENY;
}

const gchar *
wyl_client_decision_get_deny_reason (const WylClientDecision *result)
{
  return result != NULL ? result->deny_reason : NULL;
}

const gchar *
wyl_client_decision_get_deny_origin (const WylClientDecision *result)
{
  return result != NULL ? result->deny_origin : NULL;
}

gchar *
wyl_client_decision_dup_deny_reason (const WylClientDecision *result)
{
  return g_strdup (wyl_client_decision_get_deny_reason (result));
}

gchar *
wyl_client_decision_dup_deny_origin (const WylClientDecision *result)
{
  return g_strdup (wyl_client_decision_get_deny_origin (result));
}

static gboolean
parse_login_response_json (const gchar *data, gsize size,
    gchar **out_session_token, gchar **out_access_token,
    gchar **out_refresh_token, gchar **out_username, gchar **out_tenant,
    gchar **out_principal_state, gchar **out_session_state)
{
  if (data == NULL || out_session_token == NULL || out_username == NULL ||
      out_access_token == NULL || out_refresh_token == NULL ||
      out_tenant == NULL ||
      out_principal_state == NULL || out_session_state == NULL)
    return FALSE;
  *out_session_token = NULL;
  *out_access_token = NULL;
  *out_refresh_token = NULL;
  *out_username = NULL;
  *out_tenant = NULL;
  *out_principal_state = NULL;
  *out_session_state = NULL;

  JsonCursor cursor = { data, size, 0 };
  if (!json_consume (&cursor, '{'))
    return FALSE;

  gboolean have_session_token = FALSE;
  gboolean have_access_token = FALSE;
  gboolean have_refresh_token = FALSE;
  gboolean have_username = FALSE;
  gboolean have_tenant = FALSE;
  gboolean have_principal_state = FALSE;
  gboolean have_session_state = FALSE;
  json_skip_ws (&cursor);
  if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}')
    return FALSE;

  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!json_parse_string (&cursor, &key) || !json_consume (&cursor, ':'))
      return FALSE;

    if (g_strcmp0 (key, "session_token") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_session_token || value[0] == '\0')
        return FALSE;
      have_session_token = TRUE;
      *out_session_token = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "access_token") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_access_token || value[0] == '\0')
        return FALSE;
      have_access_token = TRUE;
      *out_access_token = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "refresh_token") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_refresh_token || value[0] == '\0')
        return FALSE;
      have_refresh_token = TRUE;
      *out_refresh_token = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "username") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_username || value[0] == '\0')
        return FALSE;
      have_username = TRUE;
      *out_username = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "tenant") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_tenant || value[0] == '\0')
        return FALSE;
      have_tenant = TRUE;
      *out_tenant = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "principal_state") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_principal_state ||
          (g_strcmp0 (value, "mfa_required") != 0 &&
              g_strcmp0 (value, "authenticated") != 0))
        return FALSE;
      have_principal_state = TRUE;
      *out_principal_state = g_steal_pointer (&value);
    } else if (g_strcmp0 (key, "session_state") == 0) {
      g_autofree gchar *value = NULL;
      if (!json_parse_string (&cursor, &value))
        return FALSE;
      if (have_session_state || g_strcmp0 (value, "active") != 0)
        return FALSE;
      have_session_state = TRUE;
      *out_session_state = g_steal_pointer (&value);
    } else {
      return FALSE;
    }

    json_skip_ws (&cursor);
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == ',') {
      cursor.pos++;
      continue;
    }
    if (cursor.pos < cursor.size && cursor.data[cursor.pos] == '}') {
      cursor.pos++;
      break;
    }
    return FALSE;
  }

  json_skip_ws (&cursor);
  if (!have_session_token || !have_username || !have_tenant ||
      !have_principal_state || !have_session_state ||
      cursor.pos != cursor.size) {
    g_clear_pointer (out_session_token, g_free);
    g_clear_pointer (out_access_token, g_free);
    g_clear_pointer (out_refresh_token, g_free);
    g_clear_pointer (out_username, g_free);
    g_clear_pointer (out_tenant, g_free);
    g_clear_pointer (out_principal_state, g_free);
    g_clear_pointer (out_session_state, g_free);
    return FALSE;
  }
  return TRUE;
}

static wyrelog_error_t
client_decide_request (WylClient *client, const gchar *user, const gchar *perm,
    const gchar *session_token, gboolean has_guard_context,
    gint64 guard_timestamp, const gchar *guard_loc_class, gint64 guard_risk,
    WylClientDecision **out_result)
{
  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  *out_result = NULL;
  if (client == NULL || !WYL_IS_CLIENT (client) || user == NULL ||
      perm == NULL || session_token == NULL)
    return WYRELOG_E_INVALID;
  if (has_guard_context &&
      (guard_loc_class == NULL || guard_timestamp < 0 || guard_risk < 0 ||
          guard_risk > 100 || !wyl_guard_loc_class_is_valid (guard_loc_class)))
    return WYRELOG_E_INVALID;
  g_autofree gchar *access_token = wyl_client_dup_access_token (client);
  if (access_token == NULL || access_token[0] == '\0')
    return WYRELOG_E_INVALID;
  g_autofree gchar *tenant = wyl_client_dup_tenant (client);
  if (tenant == NULL || tenant[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (base_url == NULL)
    return WYRELOG_E_INVALID;
  while (base_url[0] != '\0' && g_str_has_suffix (base_url, "/"))
    base_url[strlen (base_url) - 1] = '\0';

  g_autofree gchar *escaped_user = g_uri_escape_string (user, NULL, TRUE);
  g_autofree gchar *escaped_perm = g_uri_escape_string (perm, NULL, TRUE);
  g_autofree gchar *escaped_session_token =
      g_uri_escape_string (session_token, NULL, TRUE);
  g_autofree gchar *escaped_tenant = g_uri_escape_string (tenant, NULL, TRUE);
  g_autofree gchar *escaped_guard_loc_class =
      has_guard_context ? g_uri_escape_string (guard_loc_class, NULL,
      TRUE) : NULL;
  g_autofree gchar *uri = NULL;
  if (has_guard_context) {
    uri = g_strdup_printf ("%s/decide?user=%s&perm=%s&session_token=%s"
        "&tenant=%s&guard_timestamp=%" G_GINT64_FORMAT
        "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT, base_url,
        escaped_user, escaped_perm, escaped_session_token, escaped_tenant,
        guard_timestamp, escaped_guard_loc_class, guard_risk);
  } else {
    uri = g_strdup_printf ("%s/decide?user=%s&perm=%s&session_token=%s"
        "&tenant=%s", base_url, escaped_user, escaped_perm,
        escaped_session_token, escaped_tenant);
  }

  g_autoptr (SoupMessage) message = soup_message_new ("POST", uri);
  if (message == NULL)
    return WYRELOG_E_INVALID;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
      access_token);
  soup_message_headers_replace (soup_message_get_request_headers (message),
      "Authorization", authorization);

  g_autoptr (GBytes) body = NULL;
  wyrelog_error_t rc = wyl_client_send_message (client, message, &body);
  if (rc != WYRELOG_E_OK)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  g_autoptr (WylClientDecision) result = NULL;
  if (!parse_decide_response_json (body_data, body_size, &result))
    return WYRELOG_E_IO;

  *out_result = g_steal_pointer (&result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_decide_ex (WylClient *client, const gchar *user, const gchar *perm,
    const gchar *session_token, WylClientDecision **out_result)
{
  return client_decide_request (client, user, perm, session_token, FALSE, 0,
      NULL, 0, out_result);
}

wyrelog_error_t
wyl_client_decide (WylClient *client, const gchar *user, const gchar *perm,
    const gchar *session_token, gint *out_decision)
{
  if (out_decision == NULL)
    return WYRELOG_E_INVALID;
  *out_decision = WYL_DECISION_DENY;

  g_autoptr (WylClientDecision) result = NULL;
  wyrelog_error_t rc =
      wyl_client_decide_ex (client, user, perm, session_token, &result);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_decision = wyl_client_decision_get_decision (result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_decide_with_guard_context_ex (WylClient *client, const gchar *user,
    const gchar *perm, const gchar *session_token, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk,
    WylClientDecision **out_result)
{
  return client_decide_request (client, user, perm, session_token, TRUE,
      guard_timestamp, guard_loc_class, guard_risk, out_result);
}

wyrelog_error_t
wyl_client_decide_with_guard_context (WylClient *client, const gchar *user,
    const gchar *perm, const gchar *session_token, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk, gint *out_decision)
{
  if (out_decision == NULL)
    return WYRELOG_E_INVALID;
  *out_decision = WYL_DECISION_DENY;

  g_autoptr (WylClientDecision) result = NULL;
  wyrelog_error_t rc =
      wyl_client_decide_with_guard_context_ex (client, user, perm,
      session_token, guard_timestamp, guard_loc_class, guard_risk, &result);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_decision = wyl_client_decision_get_decision (result);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_tenant_select (WylClient *client, const gchar *tenant)
{
  if (client == NULL || !WYL_IS_CLIENT (client) || tenant == NULL ||
      tenant[0] == '\0')
    return WYRELOG_E_INVALID;
  if (client->tenant == NULL || g_strcmp0 (tenant, WYL_TENANT_DEFAULT) != 0 ||
      g_strcmp0 (client->tenant, tenant) != 0)
    return WYRELOG_E_INVALID;

  g_free (client->selected_tenant);
  client->selected_tenant = g_strdup (tenant);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_event_emit (WylClient *client, const gchar *event_kind,
    const gchar *event_payload_json)
{
  (void) client;
  (void) event_kind;
  (void) event_payload_json;
  return WYRELOG_E_INTERNAL;
}

const gchar *
wyrelog_client_version_string (void)
{
  return "0.1.0";
}
