/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef WYL_CLIENT_PRIVATE_H
#define WYL_CLIENT_PRIVATE_H

#include <libsoup/soup.h>

#include "wyrelog/client.h"

SoupSession *wyl_client_get_soup_session (WylClient * client);
void wyl_client_set_timeout_ms (WylClient * client, guint timeout_ms);
/* `out_body` is an owned output slot: it may be NULL or point to a caller-
 * owned GBytes, which is released before every return path. */
wyrelog_error_t wyl_client_send_message (WylClient * client,
    SoupMessage * message, GBytes ** out_body);

/* Reset per-operation HTTP diagnostics, including lazy query validation. */
void wyl_client_clear_last_http_error (WylClient *client);
/* Distinguish a complete malformed reply from a body-read transport failure. */
gboolean wyl_client_last_response_is_complete (WylClient *client);
/* Decode the bounded daemon error envelope; never return a raw body. */
gchar *wyl_client_parse_remote_error_code (const gchar *data, gsize size);

#endif /* WYL_CLIENT_PRIVATE_H */
