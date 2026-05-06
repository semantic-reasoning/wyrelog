/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "daemon/options.h"
#include "wyrelog/wyrelog.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>

SoupServer *wyl_daemon_start_http_server (const WylDaemonOptions * opts,
    WylHandle * handle, GError ** error);
WylSession *wyl_daemon_http_ref_session (SoupServer * server,
    const gchar * session_token);
#ifdef WYL_TEST_DAEMON_HTTP
wyrelog_error_t wyl_daemon_http_copy_access_token_secret (SoupServer * server,
    guint8 * out_secret, gsize out_len);
#endif
#endif
