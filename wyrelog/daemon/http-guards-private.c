/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "daemon/http-guards-private.h"

#include <errno.h>
#include <string.h>

static const gchar *
skip_ws (const gchar *cursor)
{
  while (cursor != NULL && g_ascii_isspace ((guchar) * cursor))
    cursor++;
  return cursor;
}

static gboolean
parse_hex4 (const gchar **cursor, gunichar *out)
{
  guint value = 0;
  const gchar *p = *cursor;

  for (gsize i = 0; i < 4; i++) {
    gint digit = g_ascii_xdigit_value (p[i]);
    if (digit < 0)
      return FALSE;
    value = (value << 4) | (guint) digit;
  }
  *out = (gunichar) value;
  *cursor = p + 4;
  return TRUE;
}

static gboolean
append_codepoint (GString *out, gunichar c)
{
  gchar encoded[6];
  gint len = g_unichar_to_utf8 (c, encoded);
  if (len <= 0)
    return FALSE;
  g_string_append_len (out, encoded, (gssize) len);
  return TRUE;
}

static gboolean
parse_json_string (const gchar **cursor, gchar **out, gsize *out_len)
{
  const gchar *p = skip_ws (*cursor);
  if (*p++ != '"')
    return FALSE;

  g_autoptr (GString) value = g_string_new (NULL);
  if (value == NULL)
    return FALSE;
  while (*p != '\0' && *p != '"') {
    guchar ch = (guchar) * p++;
    if (ch < 0x20)
      return FALSE;
    if (ch == '\\') {
      gchar escaped = *p++;
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          g_string_append_c (value, escaped);
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
          if (!parse_hex4 (&p, &codepoint))
            return FALSE;
          if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
            gunichar low = 0;
            if (*p++ != '\\' || *p++ != 'u' || !parse_hex4 (&p, &low))
              return FALSE;
            if (low < 0xDC00 || low > 0xDFFF)
              return FALSE;
            codepoint = 0x10000 + (((codepoint - 0xD800) << 10)
                | (low - 0xDC00));
          } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
            return FALSE;
          }
          if (!append_codepoint (value, codepoint))
            return FALSE;
        }
          break;
        default:
          return FALSE;
      }
      continue;
    }
    g_string_append_c (value, (gchar) ch);
  }

  if (*p++ != '"')
    return FALSE;

  *cursor = p;
  gsize len = value->len;
  *out = g_string_free (g_steal_pointer (&value), FALSE);
  if (out_len != NULL)
    *out_len = len;
  return TRUE;
}

/* Scans a bare JSON non-negative integer token and stores its canonical
 * decimal representation in *out. The scan stops at the first non-digit;
 * the caller's trailing-delimiter check rejects fractional/exponent forms
 * (e.g. 1.0 / 1e5) and other junk. Rejects empty, leading sign, non-digit
 * lead, and out-of-range (> G_MAXINT64) values. */
static gboolean
parse_json_int64_token (const gchar **cursor, gchar **out)
{
  const gchar *p = skip_ws (*cursor);
  if (!g_ascii_isdigit ((guchar) * p))
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (p, &end, 10);
  if (end == p || errno == ERANGE || parsed < 0)
    return FALSE;

  *out = g_strdup_printf ("%" G_GINT64_FORMAT, parsed);
  if (*out == NULL)
    return FALSE;
  *cursor = end;
  return TRUE;
}

static void
clear_values (gchar **values, gsize n_values)
{
  if (values == NULL)
    return;
  for (gsize i = 0; i < n_values; i++) {
    g_clear_pointer (&values[i], g_free);
  }
}

void
wyl_daemon_http_clear_strv (gchar **values, gsize n_values)
{
  clear_values (values, n_values);
}

static gboolean
value_is_valid_utf8_and_bounded (const gchar *value, gsize len, gsize max_len)
{
  if (value == NULL)
    return FALSE;
  if (len > max_len || memchr (value, '\0', len) != NULL)
    return FALSE;
  return g_utf8_validate (value, len, NULL);
}

static gboolean
parse_json_object_values (const gchar *json, gsize json_len,
    const WylDaemonHttpStrictJsonField *fields, gsize n_fields,
    gchar **out_values)
{
  if (json == NULL || fields == NULL || out_values == NULL)
    return FALSE;
  for (gsize i = 0; i < n_fields; i++)
    out_values[i] = NULL;
  if (json_len == 0 || memchr (json, '\0', json_len) != NULL
      || !g_utf8_validate (json, json_len, NULL)) {
    clear_values (out_values, n_fields);
    return FALSE;
  }

  g_autofree gchar *owned = g_strndup (json, json_len);
  if (owned == NULL) {
    clear_values (out_values, n_fields);
    return FALSE;
  }

  const gchar *p = skip_ws (owned);
  if (*p++ != '{')
    goto fail;
  p = skip_ws (p);
  if (*p == '}') {
    p++;
    if (*skip_ws (p) == '\0' && n_fields == 0)
      return TRUE;
    goto fail;
  }

  for (gsize parsed = 0; parsed < n_fields; parsed++) {
    g_autofree gchar *key = NULL;
    g_autofree gchar *value = NULL;
    gsize key_len = 0;
    gsize value_len = 0;

    if (!parse_json_string (&p, &key, &key_len))
      goto fail;
    if (memchr (key, '\0', key_len) != NULL
        || !g_utf8_validate (key, key_len, NULL))
      goto fail;
    p = skip_ws (p);
    if (*p++ != ':')
      goto fail;

    gsize slot = n_fields;
    for (gsize i = 0; i < n_fields; i++) {
      if (g_strcmp0 (fields[i].name, key) == 0) {
        slot = i;
        break;
      }
    }
    if (slot == n_fields || out_values[slot] != NULL)
      goto fail;

    if (fields[slot].kind == WYL_DAEMON_HTTP_STRICT_JSON_INT64) {
      if (!parse_json_int64_token (&p, &value))
        goto fail;
    } else {
      if (!parse_json_string (&p, &value, &value_len))
        goto fail;
      if (!value_is_valid_utf8_and_bounded (value, value_len,
              fields[slot].max_len))
        goto fail;
    }
    out_values[slot] = g_steal_pointer (&value);
    p = skip_ws (p);
    if (parsed + 1 < n_fields) {
      if (*p++ != ',')
        goto fail;
      p = skip_ws (p);
    } else {
      if (*p++ != '}')
        goto fail;
      if (*skip_ws (p) != '\0')
        goto fail;
      return TRUE;
    }
  }

fail:
  clear_values (out_values, n_fields);
  return FALSE;
}

gboolean
wyl_daemon_http_dup_strict_json_object (const gchar *json, gsize json_len,
    const WylDaemonHttpStrictJsonField *fields, gsize n_fields,
    gchar **out_values)
{
  return parse_json_object_values (json, json_len, fields, n_fields,
      out_values);
}

gboolean
wyl_daemon_http_request_body_dup_strict_json_object (SoupServerMessage *msg,
    gsize max_len, const WylDaemonHttpStrictJsonField *fields, gsize n_fields,
    gchar **out_values)
{
  if (msg == NULL)
    return FALSE;

  SoupMessageBody *body = soup_server_message_get_request_body (msg);
  if (body == NULL || body->length <= 0 || body->data == NULL)
    return FALSE;
  if ((gsize) body->length > max_len)
    return FALSE;
  return parse_json_object_values (body->data, (gsize) body->length, fields,
      n_fields, out_values);
}

static gboolean
inet_address_is_actual_loopback (GInetAddress *address)
{
  return address != NULL && g_inet_address_get_is_loopback (address);
}

gboolean
    wyl_daemon_http_socket_addresses_are_actual_loopback
    (const GSocketAddress * local, const GSocketAddress * peer)
{
  if (!G_IS_INET_SOCKET_ADDRESS (local) || !G_IS_INET_SOCKET_ADDRESS (peer))
    return FALSE;

  GInetAddress *local_addr =
      g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (local));
  GInetAddress *peer_addr =
      g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (peer));
  return inet_address_is_actual_loopback (local_addr)
      && inet_address_is_actual_loopback (peer_addr);
}

gboolean
wyl_daemon_http_message_has_actual_loopback_transport (SoupServerMessage *msg)
{
  if (msg == NULL)
    return FALSE;
  return wyl_daemon_http_socket_addresses_are_actual_loopback
      (soup_server_message_get_local_address (msg),
      soup_server_message_get_remote_address (msg));
}
