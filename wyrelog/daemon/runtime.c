/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/runtime.h"

#include <errno.h>

#include <glib.h>
#include <glib/gstdio.h>
#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>
#endif

#include "daemon/checks.h"
#include "daemon/delta.h"
#include "daemon/http.h"
#include "daemon/signals.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

static gboolean
count_service_profile_spool_events (const WylDaemonOptions *opts,
    guint *out_pending, GError **error)
{
  g_return_val_if_fail (out_pending != NULL, FALSE);
  *out_pending = 0;

  g_autoptr (GError) open_error = NULL;
  g_autoptr (GDir) dir = g_dir_open (opts->event_spool_dir, 0, &open_error);
  if (dir == NULL) {
    g_propagate_prefixed_error (error, g_steal_pointer (&open_error),
        "failed to open event spool directory: ");
    return FALSE;
  }

  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    if (g_str_has_suffix (name, ".event"))
      (*out_pending)++;
  }
  return TRUE;
}

static gboolean
prepare_service_profile_spool (const WylDaemonOptions *opts, GError **error)
{
  if (opts->profile != WYL_DAEMON_PROFILE_SERVICE)
    return TRUE;
  if (opts->event_spool_dir == NULL || opts->event_spool_dir[0] == '\0') {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "service profile requires an event spool directory");
    return FALSE;
  }

  guint pending = 0;
  if (g_mkdir_with_parents (opts->event_spool_dir, 0700) != 0) {
    g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
        "failed to create event spool directory: %s", opts->event_spool_dir);
    return FALSE;
  }
  if (!count_service_profile_spool_events (opts, &pending, error))
    return FALSE;
  if (pending > opts->event_queue_limit) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "event spool contains %u files, exceeding queue limit %u", pending,
        opts->event_queue_limit);
    return FALSE;
  }

  return TRUE;
}

#ifdef WYL_HAS_DAEMON_HTTP
static gboolean
service_profile_forwarding_enabled (const WylDaemonOptions *opts)
{
  return opts->profile == WYL_DAEMON_PROFILE_SERVICE &&
      opts->system_url != NULL && opts->system_url[0] != '\0';
}

static gchar *
service_profile_events_url (const WylDaemonOptions *opts)
{
  return g_strconcat (opts->system_url,
      g_str_has_suffix (opts->system_url, "/") ? "profile/events" :
      "/profile/events", NULL);
}

static gboolean
post_service_profile_event (const WylDaemonOptions *opts,
    const gchar *contents, GError **error)
{
  g_autofree gchar *url = service_profile_events_url (opts);
  g_autoptr (SoupMessage) msg = soup_message_new ("POST", url);
  if (msg == NULL) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
        "invalid system profile URL");
    return FALSE;
  }

  g_autoptr (SoupSession) session = soup_session_new ();
  soup_session_set_timeout (session, 2);
  g_autoptr (GBytes) request = g_bytes_new_static (contents, strlen (contents));
  soup_message_set_request_body_from_bytes (msg, "application/json", request);

  g_autoptr (GBytes) response =
      soup_session_send_and_read (session, msg, NULL, error);
  if (response == NULL)
    return FALSE;

  guint status = soup_message_get_status (msg);
  if (status < 200 || status >= 300) {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
        "system profile event endpoint returned HTTP %u", status);
    return FALSE;
  }
  return TRUE;
}

static GPtrArray *
list_service_profile_spool_events (const WylDaemonOptions *opts, GError **error)
{
  g_autoptr (GDir) dir = g_dir_open (opts->event_spool_dir, 0, error);
  if (dir == NULL)
    return NULL;

  GPtrArray *paths = g_ptr_array_new_with_free_func (g_free);
  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    if (g_str_has_suffix (name, ".event"))
      g_ptr_array_add (paths, g_build_filename (opts->event_spool_dir, name,
              NULL));
  }
  return paths;
}

static gint
compare_spool_event_paths (gconstpointer a, gconstpointer b)
{
  const gchar *path_a = *(gchar * const *) a;
  const gchar *path_b = *(gchar * const *) b;
  return g_strcmp0 (path_a, path_b);
}

static gboolean
drain_service_profile_spool (const WylDaemonOptions *opts, GError **error)
{
  if (!service_profile_forwarding_enabled (opts))
    return TRUE;

  g_autoptr (GPtrArray) paths = list_service_profile_spool_events (opts, error);
  if (paths == NULL)
    return FALSE;
  g_ptr_array_sort (paths, compare_spool_event_paths);

  for (guint i = 0; i < paths->len; i++) {
    const gchar *path = g_ptr_array_index (paths, i);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    if (!g_file_get_contents (path, &contents, &len, error))
      return FALSE;
    (void) len;
    if (!post_service_profile_event (opts, contents, error))
      return FALSE;
    if (g_remove (path) != 0) {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
          "failed to remove drained event spool file: %s", path);
      return FALSE;
    }
  }
  return TRUE;
}

static gboolean
spool_service_profile_event (const WylDaemonOptions *opts,
    const gchar *contents, GError **error)
{
  guint pending = 0;
  if (!count_service_profile_spool_events (opts, &pending, error))
    return FALSE;
  if (pending >= opts->event_queue_limit) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "event spool queue limit reached: %u", opts->event_queue_limit);
    return FALSE;
  }

  g_autofree gchar *uuid = g_uuid_string_random ();
  g_autofree gchar *name = g_strdup_printf ("%020" G_GINT64_FORMAT "-%s.event",
      g_get_real_time (), uuid);
  g_autofree gchar *path = g_build_filename (opts->event_spool_dir, name, NULL);
  g_autofree gchar *tmp_path = g_strdup_printf ("%s.tmp", path);
  if (!g_file_set_contents (tmp_path, contents, -1, error))
    return FALSE;
  if (g_rename (tmp_path, path) != 0) {
    g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
        "failed to commit event spool file: %s", path);
    return FALSE;
  }
  return TRUE;
}

static gboolean
emit_service_profile_forwarding_event (const WylDaemonOptions *opts,
    const gchar *event, GError **error)
{
  if (!service_profile_forwarding_enabled (opts))
    return TRUE;

  g_autoptr (GError) drain_error = NULL;
  if (!drain_service_profile_spool (opts, &drain_error))
    g_clear_error (&drain_error);

  g_autofree gchar *contents =
      g_strdup_printf
      ("{\"profile\":\"service\",\"event\":\"%s\",\"timestamp_us\":%"
      G_GINT64_FORMAT "}",
      event, g_get_real_time ());
  g_autoptr (GError) post_error = NULL;
  if (post_service_profile_event (opts, contents, &post_error))
    return TRUE;

  return spool_service_profile_event (opts, contents, error);
}

static gboolean
drain_service_profile_spool_tick (gpointer user_data)
{
  const WylDaemonOptions *opts = user_data;
  g_autoptr (GError) error = NULL;
  if (!drain_service_profile_spool (opts, &error) && error != NULL)
    g_debug ("service profile event spool drain skipped: %s", error->message);
  return G_SOURCE_CONTINUE;
}
#endif

static void
cleanup_readiness_policy_db (gpointer data)
{
  gchar *path = data;
  if (path == NULL)
    return;

  g_autofree gchar *clear_path = g_strdup_printf ("%s.clear", path);
  (void) g_remove (path);
  (void) g_remove (clear_path);
  g_free (path);
}

static wyrelog_error_t
open_runtime_handle (const WylDaemonOptions *opts, WylHandle **out_handle)
{
  WylHandleOpenOptions open_opts = {
    .template_dir = opts->template_dir,
    .policy_store_path = opts->policy_store_path,
    .policy_keyprovider_path = opts->policy_keyprovider_path,
    .production_mode = opts->production_mode,
    .require_template_manifest = opts->production_mode,
#ifdef WYL_HAS_AUDIT
    .audit_store_path = opts->audit_store_path,
#endif
  };

  return wyl_handle_open_with_options (&open_opts, out_handle);
}

static wyrelog_error_t
open_readiness_handle (const WylDaemonOptions *opts, WylHandle **out_handle)
{
  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  *out_handle = NULL;

  g_autofree gchar *scratch_policy_store = NULL;
  if (opts->production_mode) {
    g_autoptr (GError) error = NULL;
    gint fd = g_file_open_tmp ("wyrelog-readiness-policy-XXXXXX.sqlite",
        &scratch_policy_store, &error);
    if (fd < 0)
      return WYRELOG_E_IO;
    (void) g_close (fd, NULL);
    (void) g_remove (scratch_policy_store);
  }

  /* Readiness probes intentionally run against scratch stores: the checks
   * exercise mutation paths and must not seed configured authority data. */
  WylHandleOpenOptions open_opts = {
    .template_dir = opts->template_dir,
    .policy_store_path = scratch_policy_store,
    .policy_keyprovider_path = opts->policy_keyprovider_path,
    .production_mode = opts->production_mode,
    .require_template_manifest = opts->production_mode,
  };

  wyrelog_error_t rc = wyl_handle_open_with_options (&open_opts, out_handle);
  if (rc == WYRELOG_E_OK && scratch_policy_store != NULL) {
    g_object_set_data_full (G_OBJECT (*out_handle),
        "wyl-readiness-policy-db", g_steal_pointer (&scratch_policy_store),
        cleanup_readiness_policy_db);
  }
  return rc;
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

  if (!prepare_service_profile_spool (opts, &error)) {
    g_printerr ("wyrelogd: profile setup failed: %s\n", error->message);
    return 1;
  }

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
#ifdef WYL_HAS_DAEMON_HTTP
  if (!emit_service_profile_forwarding_event (opts, "startup", &error)) {
    g_printerr ("wyrelogd: profile event spool failed: %s\n", error->message);
    return 1;
  }
#endif

  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
#ifdef WYL_HAS_DAEMON_HTTP
  g_autoptr (SoupServer) server =
      wyl_daemon_start_http_server_with_runtime (opts, handle, &runtime,
      &error);
  if (server == NULL) {
    g_printerr ("wyrelogd: listen failed: %s\n", error->message);
    return 1;
  }
#endif

  guint sigint_id = 0;
  guint sigterm_id = 0;
  wyl_daemon_install_signal_handlers (loop, &sigint_id, &sigterm_id);
  guint service_drain_id = 0;
#ifdef WYL_HAS_DAEMON_HTTP
  if (service_profile_forwarding_enabled (opts))
    service_drain_id = g_timeout_add_seconds (5,
        drain_service_profile_spool_tick, (gpointer) opts);
#endif
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
  wyl_daemon_remove_signal_handler (&service_drain_id);
  wyl_daemon_remove_signal_handler (&early_signal_poll_id);
  wyl_daemon_remove_signal_handler (&sigterm_id);
  wyl_daemon_remove_signal_handler (&sigint_id);
  return 0;
}
