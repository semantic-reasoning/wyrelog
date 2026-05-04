/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <signal.h>

#ifdef G_OS_UNIX
#include <glib-unix.h>
#endif

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_DEFAULT_TEMPLATE_DIR
#error "WYL_DEFAULT_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  const gchar *template_dir;
  gboolean check_only;
  gboolean show_version;
} WylDaemonOptions;

static gboolean
parse_options (gint *argc, gchar ***argv, WylDaemonOptions *opts,
    GError **error)
{
  GOptionEntry entries[] = {
    {"template-dir", 0, 0, G_OPTION_ARG_STRING, &opts->template_dir,
        "Access policy template directory", "DIR"},
    {"check", 0, 0, G_OPTION_ARG_NONE, &opts->check_only,
        "Load policy templates and exit", NULL},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts->show_version,
        "Print version and exit", NULL},
    {NULL}
  };

  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon");
  g_option_context_add_main_entries (context, entries, NULL);

  return g_option_context_parse (context, argc, argv, error);
}

static wyrelog_error_t
check_wirelog_policy_ready (WylHandle *handle)
{
  gint64 row[1];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wr.audit.read", &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_handle_engine_contains (handle, "guarded_perm", row, 1, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static void
daemon_delta_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  (void) relation;
  (void) row;
  (void) ncols;
  (void) kind;
  (void) user_data;
}

static wyrelog_error_t
start_wirelog_delta_callbacks (WylHandle *handle)
{
  return wyl_handle_engine_set_delta_callback (handle, daemon_delta_cb, NULL);
}

#ifdef G_OS_UNIX
static gboolean
quit_loop_from_signal (gpointer user_data)
{
  GMainLoop *loop = user_data;

  g_main_loop_quit (loop);
  return G_SOURCE_CONTINUE;
}

static void
install_signal_handlers (GMainLoop *loop, guint *sigint_id, guint *sigterm_id)
{
  *sigint_id = g_unix_signal_add (SIGINT, quit_loop_from_signal, loop);
  *sigterm_id = g_unix_signal_add (SIGTERM, quit_loop_from_signal, loop);
}

static void
remove_signal_handler (guint *source_id)
{
  if (*source_id != 0) {
    g_source_remove (*source_id);
    *source_id = 0;
  }
}
#else
static void
install_signal_handlers (GMainLoop *loop, guint *sigint_id, guint *sigterm_id)
{
  (void) loop;
  *sigint_id = 0;
  *sigterm_id = 0;
}

static void
remove_signal_handler (guint *source_id)
{
  (void) source_id;
}
#endif

int
main (int argc, char **argv)
{
  WylDaemonOptions opts = {
    .template_dir = WYL_DEFAULT_TEMPLATE_DIR,
  };
  g_autoptr (GError) error = NULL;

  if (!parse_options (&argc, &argv, &opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }

  if (opts.show_version) {
    g_print ("%s\n", wyrelog_version_string ());
    return 0;
  }

  g_autoptr (WylHandle) handle = NULL;
  wyrelog_error_t rc = wyl_init (opts.template_dir, &handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: init failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }

  if (opts.check_only) {
    rc = check_wirelog_policy_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: policy readiness check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    return 0;
  }

  rc = start_wirelog_delta_callbacks (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: delta callback setup failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  guint sigint_id = 0;
  guint sigterm_id = 0;
  install_signal_handlers (loop, &sigint_id, &sigterm_id);
  g_main_loop_run (loop);
  remove_signal_handler (&sigterm_id);
  remove_signal_handler (&sigint_id);
  return 0;
}
