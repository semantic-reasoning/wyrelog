/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <libsoup/soup.h>

G_BEGIN_DECLS

void wyl_daemon_http_install_body_limit (SoupServer *server);
gboolean wyl_daemon_http_write_body_limit_response (GOutputStream *output,
    const gchar *response, gsize length);

G_END_DECLS
