/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "daemon/options.h"
#include "wyrelog/wyrelog.h"

#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>

#include "daemon/delta.h"

SoupServer *wyl_daemon_start_http_server (const WylDaemonOptions * opts,
    WylHandle * handle, GError ** error);
SoupServer *wyl_daemon_start_http_server_with_runtime
    (const WylDaemonOptions * opts, WylHandle * handle,
    WylDaemonRuntime * runtime, GError ** error);
WylSession *wyl_daemon_http_ref_session (SoupServer * server,
    const gchar * session_token);
#ifdef WYL_TEST_DAEMON_HTTP
wyrelog_error_t wyl_daemon_http_copy_access_token_secret (SoupServer * server,
    guint8 * out_secret, gsize out_len);
gboolean wyl_daemon_http_remove_session_for_test (SoupServer * server,
    const gchar * session_token);
#endif
#endif
