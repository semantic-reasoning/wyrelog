/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/audit/iter-private.h"
#include "wyrelog/client.h"
#include "wyrelog/wyl-client-private.h"

struct _WylAuditIter
{
  GObject parent_instance;
  WylClient *client;
  gchar *query_filter;
  guint pending_events;
  gboolean exhausted;
};

G_DEFINE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, G_TYPE_OBJECT);

static void
wyl_audit_iter_finalize (GObject *object)
{
  WylAuditIter *self = WYL_AUDIT_ITER (object);

  g_clear_object (&self->client);
  g_free (self->query_filter);

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
  if (iter->query_filter == NULL || iter->query_filter[0] == '\0')
    return g_steal_pointer (&path);

  g_autofree gchar *escaped =
      g_uri_escape_string (iter->query_filter, NULL, TRUE);
  return g_strdup_printf ("%s?filter=%s", path, escaped);
}

SoupMessage *
wyl_audit_iter_new_request_message (WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER (iter), NULL);

  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  return soup_message_new ("GET", request_uri);
}

static wyrelog_error_t
count_top_level_json_objects (const gchar *data, gsize size, guint *out_count)
{
  if (data == NULL || out_count == NULL)
    return WYRELOG_E_INVALID;

  gsize i = 0;
  while (i < size && g_ascii_isspace (data[i]))
    i++;
  if (i >= size || data[i] != '[')
    return WYRELOG_E_IO;
  i++;

  guint count = 0;
  gint depth = 1;
  gboolean in_string = FALSE;
  gboolean escaped = FALSE;

  for (; i < size; i++) {
    gchar ch = data[i];

    if (in_string) {
      if (escaped) {
        escaped = FALSE;
      } else if (ch == '\\') {
        escaped = TRUE;
      } else if (ch == '"') {
        in_string = FALSE;
      }
      continue;
    }

    if (ch == '"') {
      in_string = TRUE;
      continue;
    }
    if (g_ascii_isspace (ch) || ch == ',')
      continue;
    if (ch == '{') {
      if (depth == 1)
        count++;
      depth++;
      continue;
    }
    if (ch == '}') {
      depth--;
      if (depth < 1)
        return WYRELOG_E_IO;
      continue;
    }
    if (ch == '[') {
      depth++;
      continue;
    }
    if (ch == ']') {
      depth--;
      if (depth != 0)
        return WYRELOG_E_IO;
      i++;
      break;
    }

    if (depth == 1)
      return WYRELOG_E_IO;
  }

  while (i < size && g_ascii_isspace (data[i]))
    i++;
  if (depth != 0 || i != size || in_string || escaped)
    return WYRELOG_E_IO;

  *out_count = count;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_iter_next (WylAuditIter *iter, gboolean *out_has_next)
{
  if (iter == NULL || !WYL_IS_AUDIT_ITER (iter) || out_has_next == NULL)
    return WYRELOG_E_INVALID;

  if (iter->pending_events > 0) {
    iter->pending_events--;
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
  guint event_count = 0;
  rc = count_top_level_json_objects (body_data, body_size, &event_count);
  if (rc != WYRELOG_E_OK)
    return rc;

  iter->exhausted = TRUE;
  if (event_count == 0) {
    *out_has_next = FALSE;
    return WYRELOG_E_OK;
  }

  iter->pending_events = event_count - 1;
  *out_has_next = TRUE;
  return WYRELOG_E_OK;
}
