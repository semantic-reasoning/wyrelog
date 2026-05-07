/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/audit/iter-private.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-client-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

#include <string.h>

#include "audit/event-private.h"

struct _WylAuditIter
{
  GObject parent_instance;
  WylClient *client;
  gchar *query_filter;
  gchar *tenant;
  gchar *session_token;
  gchar *access_token;
  gboolean has_guard_context;
  gint64 guard_timestamp;
  gchar *guard_loc_class;
  gint64 guard_risk;
  GPtrArray *events;
  guint event_index;
  WylAuditEvent *current_event;
  gboolean exhausted;
};

G_DEFINE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, G_TYPE_OBJECT);

static void
wyl_audit_iter_finalize (GObject *object)
{
  WylAuditIter *self = WYL_AUDIT_ITER (object);

  g_clear_object (&self->client);
  g_clear_pointer (&self->events, g_ptr_array_unref);
  g_clear_object (&self->current_event);
  g_free (self->query_filter);
  g_free (self->tenant);
  g_free (self->session_token);
  g_free (self->access_token);
  g_free (self->guard_loc_class);

  G_OBJECT_CLASS (wyl_audit_iter_parent_class)->finalize (object);
}

static void
wyl_audit_iter_class_init (WylAuditIterClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_audit_iter_finalize;
}

static void
wyl_audit_iter_init (WylAuditIter *self)
{
  (void) self;
}

wyrelog_error_t
wyl_client_audit_query (WylClient *client, const gchar *query_filter,
    WylAuditIter **out_iter)
{
  if (out_iter == NULL)
    return WYRELOG_E_INVALID;
  *out_iter = NULL;
  if (client == NULL || !WYL_IS_CLIENT (client))
    return WYRELOG_E_INVALID;

  WylAuditIter *iter = g_object_new (WYL_TYPE_AUDIT_ITER, NULL);
  iter->client = g_object_ref (client);
  iter->query_filter = g_strdup (query_filter);
  *out_iter = iter;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_client_audit_query_with_guard_context (WylClient *client,
    const gchar *query_filter, gint64 guard_timestamp,
    const gchar *guard_loc_class, gint64 guard_risk, WylAuditIter **out_iter)
{
  if (out_iter == NULL)
    return WYRELOG_E_INVALID;
  *out_iter = NULL;
  if (client == NULL || !WYL_IS_CLIENT (client))
    return WYRELOG_E_INVALID;
  if (guard_timestamp < 0 || guard_loc_class == NULL || guard_risk < 0 ||
      guard_risk > 100 || !wyl_guard_loc_class_is_valid (guard_loc_class))
    return WYRELOG_E_INVALID;

  g_autofree gchar *access_token = wyl_client_dup_access_token (client);
  g_autofree gchar *session_token = wyl_client_dup_session_token (client);
  if ((access_token == NULL || access_token[0] == '\0') &&
      (session_token == NULL || session_token[0] == '\0'))
    return WYRELOG_E_INVALID;
  g_autofree gchar *tenant = wyl_client_dup_tenant (client);
  if (tenant == NULL || tenant[0] == '\0')
    return WYRELOG_E_INVALID;

  WylAuditIter *iter = g_object_new (WYL_TYPE_AUDIT_ITER, NULL);
  iter->client = g_object_ref (client);
  iter->query_filter = g_strdup (query_filter);
  iter->tenant = g_steal_pointer (&tenant);
  iter->session_token = g_steal_pointer (&session_token);
  iter->access_token = g_steal_pointer (&access_token);
  iter->has_guard_context = TRUE;
  iter->guard_timestamp = guard_timestamp;
  iter->guard_loc_class = g_strdup (guard_loc_class);
  iter->guard_risk = guard_risk;
  *out_iter = iter;
  return WYRELOG_E_OK;
}

gchar *
wyl_audit_iter_dup_query_filter (const WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER ((WylAuditIter *) iter), NULL);
  return g_strdup (iter->query_filter);
}

gchar *
wyl_audit_iter_dup_request_uri (const WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER ((WylAuditIter *) iter), NULL);

  g_autofree gchar *base_url = wyl_client_dup_base_url (iter->client);
  const gchar *separator = g_str_has_suffix (base_url, "/") ? "" : "/";
  g_autofree gchar *path =
      g_strdup_printf ("%s%saudit/events", base_url, separator);
  g_autoptr (GString) query = g_string_new (NULL);

  if (iter->has_guard_context) {
    g_autofree gchar *escaped_tenant =
        g_uri_escape_string (iter->tenant, NULL, TRUE);
    g_autofree gchar *escaped_loc =
        g_uri_escape_string (iter->guard_loc_class, NULL, TRUE);
    if (iter->access_token == NULL) {
      g_autofree gchar *escaped_session =
          g_uri_escape_string (iter->session_token, NULL, TRUE);
      g_string_append_printf (query,
          "tenant=%s&session_token=%s&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          escaped_tenant, escaped_session, iter->guard_timestamp, escaped_loc,
          iter->guard_risk);
    } else {
      g_string_append_printf (query,
          "tenant=%s&guard_timestamp=%" G_GINT64_FORMAT
          "&guard_loc_class=%s&guard_risk=%" G_GINT64_FORMAT,
          escaped_tenant, iter->guard_timestamp, escaped_loc, iter->guard_risk);
    }
  }

  if (iter->query_filter == NULL || iter->query_filter[0] == '\0') {
    if (query->len == 0)
      return g_steal_pointer (&path);
    return g_strdup_printf ("%s?%s", path, query->str);
  }

  if (query->len > 0)
    g_string_append_c (query, '&');

  g_autofree gchar *escaped =
      g_uri_escape_string (iter->query_filter, NULL, TRUE);
  g_string_append_printf (query, "filter=%s", escaped);
  return g_strdup_printf ("%s?%s", path, query->str);
}

SoupMessage *
wyl_audit_iter_new_request_message (WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER (iter), NULL);

  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  SoupMessage *message = soup_message_new ("GET", request_uri);
  if (message != NULL && iter->access_token != NULL) {
    g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
        iter->access_token);
    soup_message_headers_replace (soup_message_get_request_headers (message),
        "Authorization", authorization);
  }
  return message;
}

WylAuditEvent *
wyl_audit_iter_ref_event (const WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER ((WylAuditIter *) iter), NULL);
  if (iter->current_event == NULL)
    return NULL;
  return g_object_ref (iter->current_event);
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
  while (cursor->pos < cursor->size
      && g_ascii_isspace (cursor->data[cursor->pos]))
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

static gint
json_hex_value (gchar ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static gboolean
json_parse_string (JsonCursor *cursor, gchar **out_string)
{
  if (out_string == NULL)
    return FALSE;
  *out_string = NULL;
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size || cursor->data[cursor->pos] != '"')
    return FALSE;
  cursor->pos++;

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
      {
        gunichar codepoint = 0;
        for (guint i = 0; i < 4; i++) {
          if (cursor->pos >= cursor->size)
            return FALSE;
          gint nibble = json_hex_value (cursor->data[cursor->pos++]);
          if (nibble < 0)
            return FALSE;
          codepoint = (codepoint << 4) | (gunichar) nibble;
        }
        if (!g_unichar_validate (codepoint))
          return FALSE;
        g_string_append_unichar (value, codepoint);
        break;
      }
      default:
        return FALSE;
    }
  }

  return FALSE;
}

static gboolean
json_parse_nullable_string (JsonCursor *cursor, gchar **out_string)
{
  if (out_string == NULL)
    return FALSE;
  *out_string = NULL;
  json_skip_ws (cursor);
  if (cursor->pos + 4 <= cursor->size
      && memcmp (cursor->data + cursor->pos, "null", 4) == 0) {
    cursor->pos += 4;
    return TRUE;
  }
  return json_parse_string (cursor, out_string);
}

static gboolean
json_parse_int64 (JsonCursor *cursor, gint64 *out_value)
{
  json_skip_ws (cursor);
  if (cursor->pos >= cursor->size || out_value == NULL)
    return FALSE;

  gsize start = cursor->pos;
  if (cursor->data[cursor->pos] == '-')
    cursor->pos++;
  if (cursor->pos >= cursor->size
      || !g_ascii_isdigit (cursor->data[cursor->pos]))
    return FALSE;
  if (cursor->data[cursor->pos] == '0') {
    cursor->pos++;
  } else {
    while (cursor->pos < cursor->size
        && g_ascii_isdigit (cursor->data[cursor->pos]))
      cursor->pos++;
  }
  g_autofree gchar *text =
      g_strndup (cursor->data + start, cursor->pos - start);
  gchar *end = NULL;
  gint64 value = g_ascii_strtoll (text, &end, 10);
  if (end == NULL || *end != '\0')
    return FALSE;
  *out_value = value;
  return TRUE;
}

static wyrelog_error_t
parse_audit_event_object (JsonCursor *cursor, WylAuditEvent **out_event)
{
  g_autofree gchar *id = NULL;
  g_autofree gchar *subject_id = NULL;
  g_autofree gchar *action = NULL;
  g_autofree gchar *resource_id = NULL;
  g_autofree gchar *deny_reason = NULL;
  g_autofree gchar *deny_origin = NULL;
  g_autofree gchar *request_id = NULL;
  gint64 created_at_us = -1;
  gint64 decision_raw = -1;
  gboolean have_created_at = FALSE;
  gboolean have_decision = FALSE;

  if (out_event == NULL)
    return WYRELOG_E_INVALID;
  *out_event = NULL;
  if (!json_consume (cursor, '{'))
    return WYRELOG_E_IO;

  json_skip_ws (cursor);
  if (cursor->pos < cursor->size && cursor->data[cursor->pos] == '}') {
    cursor->pos++;
    return WYRELOG_E_IO;
  }

  while (TRUE) {
    g_autofree gchar *key = NULL;
    if (!json_parse_string (cursor, &key) || !json_consume (cursor, ':'))
      return WYRELOG_E_IO;

    if (g_strcmp0 (key, "id") == 0) {
      if (!json_parse_nullable_string (cursor, &id) || id == NULL)
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "created_at_us") == 0) {
      if (!json_parse_int64 (cursor, &created_at_us))
        return WYRELOG_E_IO;
      have_created_at = TRUE;
    } else if (g_strcmp0 (key, "subject_id") == 0) {
      if (!json_parse_nullable_string (cursor, &subject_id))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "action") == 0) {
      if (!json_parse_nullable_string (cursor, &action))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "resource_id") == 0) {
      if (!json_parse_nullable_string (cursor, &resource_id))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "deny_reason") == 0) {
      if (!json_parse_nullable_string (cursor, &deny_reason))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "deny_origin") == 0) {
      if (!json_parse_nullable_string (cursor, &deny_origin))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "request_id") == 0) {
      if (!json_parse_nullable_string (cursor, &request_id))
        return WYRELOG_E_IO;
    } else if (g_strcmp0 (key, "decision") == 0) {
      if (!json_parse_int64 (cursor, &decision_raw))
        return WYRELOG_E_IO;
      have_decision = TRUE;
    } else {
      return WYRELOG_E_IO;
    }

    json_skip_ws (cursor);
    if (cursor->pos >= cursor->size)
      return WYRELOG_E_IO;
    if (cursor->data[cursor->pos] == ',') {
      cursor->pos++;
      continue;
    }
    if (cursor->data[cursor->pos] == '}') {
      cursor->pos++;
      break;
    }
    return WYRELOG_E_IO;
  }

  if (id == NULL || !have_created_at || !have_decision)
    return WYRELOG_E_IO;

  return wyl_audit_event_new_from_fields (id, created_at_us, subject_id,
      action, resource_id, deny_reason, deny_origin, request_id,
      (wyl_decision_t) decision_raw, out_event);
}

static wyrelog_error_t
parse_audit_events_json (const gchar *data, gsize size, GPtrArray **out_events)
{
  if (data == NULL || out_events == NULL)
    return WYRELOG_E_INVALID;
  *out_events = NULL;

  JsonCursor cursor = { data, size, 0 };
  if (!json_consume (&cursor, '['))
    return WYRELOG_E_IO;

  g_autoptr (GPtrArray) events =
      g_ptr_array_new_with_free_func (g_object_unref);
  json_skip_ws (&cursor);
  if (cursor.pos < cursor.size && cursor.data[cursor.pos] == ']') {
    cursor.pos++;
  } else {
    while (TRUE) {
      g_autoptr (WylAuditEvent) event = NULL;
      wyrelog_error_t rc = parse_audit_event_object (&cursor, &event);
      if (rc != WYRELOG_E_OK)
        return rc == WYRELOG_E_INVALID ? WYRELOG_E_IO : rc;
      g_ptr_array_add (events, g_steal_pointer (&event));

      json_skip_ws (&cursor);
      if (cursor.pos >= cursor.size)
        return WYRELOG_E_IO;
      if (cursor.data[cursor.pos] == ',') {
        cursor.pos++;
        continue;
      }
      if (cursor.data[cursor.pos] == ']') {
        cursor.pos++;
        break;
      }
      return WYRELOG_E_IO;
    }
  }

  json_skip_ws (&cursor);
  if (cursor.pos != cursor.size)
    return WYRELOG_E_IO;

  *out_events = g_steal_pointer (&events);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_iter_next (WylAuditIter *iter, gboolean *out_has_next)
{
  if (iter == NULL || !WYL_IS_AUDIT_ITER (iter) || out_has_next == NULL)
    return WYRELOG_E_INVALID;

  g_clear_object (&iter->current_event);
  if (iter->events != NULL && iter->event_index < iter->events->len) {
    iter->current_event =
        g_object_ref (g_ptr_array_index (iter->events, iter->event_index++));
    *out_has_next = TRUE;
    return WYRELOG_E_OK;
  }

  if (iter->exhausted) {
    *out_has_next = FALSE;
    return WYRELOG_E_OK;
  }

  g_autoptr (SoupMessage) message = wyl_audit_iter_new_request_message (iter);
  g_autoptr (GBytes) body = NULL;
  wyrelog_error_t rc = wyl_client_send_message (iter->client, message, &body);
  if (rc != WYRELOG_E_OK)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  g_clear_pointer (&iter->events, g_ptr_array_unref);
  iter->event_index = 0;
  rc = parse_audit_events_json (body_data, body_size, &iter->events);
  if (rc != WYRELOG_E_OK)
    return rc;

  iter->exhausted = TRUE;
  if (iter->events->len == 0) {
    *out_has_next = FALSE;
    return WYRELOG_E_OK;
  }

  iter->current_event =
      g_object_ref (g_ptr_array_index (iter->events, iter->event_index++));
  *out_has_next = TRUE;
  return WYRELOG_E_OK;
}
