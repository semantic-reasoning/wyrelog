/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/runtime.h"

#include <glib.h>

#include "daemon/checks.h"
#include "daemon/delta.h"
#include "daemon/http.h"
#include "daemon/signals.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

static wyrelog_error_t
open_runtime_handle (const WylDaemonOptions *opts, WylHandle **out_handle)
{
  WylHandleOpenOptions open_opts = {
    .template_dir = opts->template_dir,
    .policy_store_path = opts->policy_store_path,
#ifdef WYL_HAS_AUDIT
    .audit_store_path = opts->audit_store_path,
#endif
  };

  return wyl_handle_open_with_options (&open_opts, out_handle);
}

static wyrelog_error_t
open_readiness_handle (const WylDaemonOptions *opts, WylHandle **out_handle)
{
  /* Readiness probes intentionally run against scratch stores: the checks
   * exercise mutation paths and must not seed configured authority data. */
  WylHandleOpenOptions open_opts = {
    .template_dir = opts->template_dir,
  };

  return wyl_handle_open_with_options (&open_opts, out_handle);
}

static gboolean
quit_loop_on_early_signal (gpointer user_data)
{
  if (!wyl_daemon_early_signal_received ())
    return G_SOURCE_CONTINUE;

  g_main_loop_quit (user_data);
  return G_SOURCE_CONTINUE;
}

int
wyl_daemon_run_runtime (const WylDaemonOptions *opts)
{
  g_autoptr (GError) error = NULL;

  if (!opts->check_only) {
    /* Install early signal handlers so SIGINT/SIGTERM arriving during
     * the readiness phase (before the GMainLoop and its glib-based
     * handlers exist) sets a flag we can observe instead of letting
     * the default disposition terminate the process. */
    wyl_daemon_install_early_signal_handlers ();

    g_autoptr (WylHandle) readiness_handle = NULL;
    wyrelog_error_t readiness_rc =
        open_readiness_handle (opts, &readiness_handle);
    if (readiness_rc != WYRELOG_E_OK) {
      if (wyl_daemon_early_signal_received ())
        return 0;
      g_printerr ("wyrelogd: init failed: %s\n",
          wyrelog_error_string (readiness_rc));
      return 1;
    }

    int checks_rc = wyl_daemon_run_checks (readiness_handle);
    if (wyl_daemon_early_signal_received ())
      return 0;
    if (checks_rc != 0)
      return checks_rc;
  }

  g_autoptr (WylHandle) handle = NULL;
  wyrelog_error_t rc = opts->check_only ?
      open_readiness_handle (opts, &handle) : open_runtime_handle (opts,
      &handle);
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
  guint early_signal_poll_id =
      g_timeout_add (100, quit_loop_on_early_signal, loop);
  /* If SIGTERM/SIGINT arrived during readiness or post-readiness setup,
   * the early handler captured it but the GMainLoop's signal source did
   * not. Quit the loop preemptively so we exit cleanly without serving
   * a single request. */
  if (wyl_daemon_early_signal_received ())
    g_main_loop_quit (loop);
  g_main_loop_run (loop);
#ifdef WYL_HAS_DAEMON_HTTP
  soup_server_disconnect (server);
#endif
  wyl_daemon_remove_signal_handler (&early_signal_poll_id);
  wyl_daemon_remove_signal_handler (&sigterm_id);
  wyl_daemon_remove_signal_handler (&sigint_id);
  return 0;
}
