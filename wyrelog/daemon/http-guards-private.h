/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>
#include <glib.h>
#include <libsoup/soup.h>

G_BEGIN_DECLS typedef enum
{
  WYL_DAEMON_HTTP_STRICT_JSON_STRING = 0,
  WYL_DAEMON_HTTP_STRICT_JSON_INT64 = 1,
} WylDaemonHttpStrictJsonFieldKind;

typedef struct
{
  const gchar *name;
  gsize max_len;
  WylDaemonHttpStrictJsonFieldKind kind;
} WylDaemonHttpStrictJsonField;

gboolean wyl_daemon_http_socket_addresses_are_actual_loopback
    (const GSocketAddress * local, const GSocketAddress * peer);
gboolean wyl_daemon_http_message_has_actual_loopback_transport
    (SoupServerMessage * msg);

void wyl_daemon_http_clear_strv (gchar ** values, gsize n_values);

gboolean wyl_daemon_http_dup_strict_json_object
    (const gchar * json, gsize json_len,
    const WylDaemonHttpStrictJsonField * fields, gsize n_fields,
    gchar ** out_values);
gboolean wyl_daemon_http_request_body_dup_strict_json_object
    (SoupServerMessage * msg, gsize max_len,
    const WylDaemonHttpStrictJsonField * fields, gsize n_fields,
    gchar ** out_values);

G_END_DECLS
