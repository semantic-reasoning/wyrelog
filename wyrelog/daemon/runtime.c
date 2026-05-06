/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/runtime.h"

#include <glib.h>

#include "daemon/checks.h"
#include "daemon/delta.h"
#include "daemon/http.h"
#include "daemon/signals.h"
#include "wyrelog/wyrelog.h"

int
wyl_daemon_run_runtime (const WylDaemonOptions *opts)
{
  g_autoptr (GError) error = NULL;

  if (!opts->check_only) {
    g_autoptr (WylHandle) readiness_handle = NULL;
    wyrelog_error_t readiness_rc =
        wyl_init (opts->template_dir, &readiness_handle);
    if (readiness_rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: init failed: %s\n",
          wyrelog_error_string (readiness_rc));
      return 1;
    }

    int checks_rc = wyl_daemon_run_checks (readiness_handle);
    if (checks_rc != 0)
      return checks_rc;
  }

  g_autoptr (WylHandle) handle = NULL;
  wyrelog_error_t rc = wyl_init (opts->template_dir, &handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: init failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }

  if (opts->check_only)
    return wyl_daemon_run_checks (handle);

  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  rc = wyl_daemon_start_delta_callbacks (handle, &runtime);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: delta callback setup failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_emit_start_event (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: audit start event failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
#ifdef WYL_HAS_DAEMON_HTTP
  g_autoptr (SoupServer) server =
      wyl_daemon_start_http_server (opts, handle, &error);
  if (server == NULL) {
    g_printerr ("wyrelogd: listen failed: %s\n", error->message);
    return 1;
  }
#endif

  guint sigint_id = 0;
  guint sigterm_id = 0;
  wyl_daemon_install_signal_handlers (loop, &sigint_id, &sigterm_id);
  g_main_loop_run (loop);
#ifdef WYL_HAS_DAEMON_HTTP
  soup_server_disconnect (server);
#endif
  wyl_daemon_remove_signal_handler (&sigterm_id);
  wyl_daemon_remove_signal_handler (&sigint_id);
  return 0;
}
