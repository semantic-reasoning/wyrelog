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

#endif /* WYL_CLIENT_PRIVATE_H */
