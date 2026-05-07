/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <errno.h>
#include <string.h>

#include "wyrelog/version.h"

typedef struct
{
  gchar *daemon_url;
  gchar *timeout_ms_arg;
  gboolean show_version;
} WyctlOptions;

typedef struct
{
  gchar *user;
  gchar *permission;
  gchar *resource;
} WyctlPolicyOptions;

#define WYCTL_DEFAULT_TIMEOUT_MS 2000
#define WYCTL_MAX_TIMEOUT_MS 60000

typedef struct
{
  GCancellable *cancellable;
  GCond cond;
  GMutex mutex;
  gboolean done;
  guint timeout_ms;
} WyctlTimeout;

static gpointer
timeout_thread_func (gpointer data)
{
  WyctlTimeout *timeout = data;

  g_mutex_lock (&timeout->mutex);
  gint64 deadline = g_get_monotonic_time () + (gint64) timeout->timeout_ms
      * 1000;
  while (!timeout->done) {
    if (!g_cond_wait_until (&timeout->cond, &timeout->mutex, deadline))
      break;
  }
  if (!timeout->done)
    g_cancellable_cancel (timeout->cancellable);
  g_mutex_unlock (&timeout->mutex);

  return NULL;
}

static gboolean
parse_timeout_ms (const gchar *raw, guint *out_timeout_ms)
{
  if (raw == NULL) {
    *out_timeout_ms = WYCTL_DEFAULT_TIMEOUT_MS;
    return TRUE;
  }

  if (raw[0] == '\0')
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0')
    return FALSE;

  if (parsed < 1 || parsed > WYCTL_MAX_TIMEOUT_MS)
    return FALSE;

  *out_timeout_ms = (guint) parsed;
  return TRUE;
}

static gchar *
build_healthz_uri (const gchar *daemon_url)
{
  g_autofree gchar *root = g_strdup (daemon_url);

  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  return g_strdup_printf ("%s/healthz", root);
}

static gboolean
daemon_url_is_valid (const gchar *daemon_url)
{
  if (daemon_url == NULL || daemon_url[0] == '\0')
    return FALSE;

  g_autoptr (GError) error = NULL;
  g_autoptr (GUri) uri = g_uri_parse (daemon_url, G_URI_FLAGS_NONE, &error);
  if (uri == NULL)
    return FALSE;

  const gchar *scheme = g_uri_get_scheme (uri);
  return g_strcmp0 (scheme, "http") == 0 || g_strcmp0 (scheme, "https") == 0;
}

static int
run_status (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlOptions opts = {
    .daemon_url = global_opts->daemon_url,
    .timeout_ms_arg = global_opts->timeout_ms_arg,
  };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"timeout-ms", 0, 0, G_OPTION_ARG_STRING, &opts.timeout_ms_arg,
        "Daemon probe timeout in milliseconds", "N"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon status");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected status argument: %s\n", argv[1]);
    return 2;
  }

  if (opts.daemon_url == NULL || opts.daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }

  if (!daemon_url_is_valid (opts.daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (opts.timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  g_autofree gchar *uri = build_healthz_uri (opts.daemon_url);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  g_autoptr (SoupSession) session = soup_session_new ();
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  WyctlTimeout timeout = {
    .cancellable = cancellable,
    .timeout_ms = timeout_ms,
  };
  g_cond_init (&timeout.cond);
  g_mutex_init (&timeout.mutex);
  GThread *timeout_thread = g_thread_new ("wyctl-timeout", timeout_thread_func,
      &timeout);

  g_autoptr (GError) io_error = NULL;
  g_autoptr (GBytes) body =
      soup_session_send_and_read (session, msg, cancellable, &io_error);

  g_mutex_lock (&timeout.mutex);
  timeout.done = TRUE;
  g_cond_signal (&timeout.cond);
  g_mutex_unlock (&timeout.mutex);
  g_thread_join (timeout_thread);
  g_mutex_clear (&timeout.mutex);
  g_cond_clear (&timeout.cond);

  if (body == NULL) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts.daemon_url);
    return 1;
  }

  guint status = soup_message_get_status (msg);
  if (status < 200 || status >= 300) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts.daemon_url);
    return 1;
  }

  g_print ("ok\n");
  return 0;
}

static int
run_policy_decision_command (const gchar *command, gint argc, gchar **argv)
{
  WyctlPolicyOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"user", 0, 0, G_OPTION_ARG_STRING, &opts.user, "Decision user", "USER"},
    {"permission", 0, 0, G_OPTION_ARG_STRING, &opts.permission,
        "Decision permission", "PERMISSION"},
    {"resource", 0, 0, G_OPTION_ARG_STRING, &opts.resource,
        "Decision resource", "RESOURCE"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autofree gchar *summary = g_strdup_printf ("- wyrelog policy %s", command);
  g_autoptr (GOptionContext) context = g_option_context_new (summary);
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected policy %s argument: %s\n", command, argv[1]);
    return 2;
  }

  if (opts.user == NULL || opts.user[0] == '\0') {
    g_printerr ("wyctl: missing --user\n");
    return 2;
  }
  if (opts.permission == NULL || opts.permission[0] == '\0') {
    g_printerr ("wyctl: missing --permission\n");
    return 2;
  }
  if (opts.resource == NULL || opts.resource[0] == '\0') {
    g_printerr ("wyctl: missing --resource\n");
    return 2;
  }

  g_printerr ("wyctl: policy %s is not implemented\n", command);
  return 3;
}

static int
run_policy (gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing policy command\n");
    return 2;
  }

  if (g_strcmp0 (argv[1], "check") == 0 || g_strcmp0 (argv[1], "explain") == 0)
    return run_policy_decision_command (argv[1], argc - 1, argv + 1);

  g_printerr ("wyctl: unknown policy command: %s\n", argv[1]);
  return 2;
}

int
main (int argc, char **argv)
{
  WyctlOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"timeout-ms", 0, 0, G_OPTION_ARG_STRING, &opts.timeout_ms_arg,
        "Daemon probe timeout in milliseconds", "N"},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts.show_version,
        "Print version and exit", NULL},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("COMMAND - wyrelog control client");
  g_option_context_add_main_entries (context, entries, NULL);
  g_option_context_set_strict_posix (context, TRUE);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }

  if (opts.show_version) {
    g_print ("%s\n", wyrelog_version_string ());
    return 0;
  }

  if (argc < 2) {
    g_autofree gchar *help = g_option_context_get_help (context, TRUE, NULL);
    g_printerr ("%s", help);
    return 2;
  }

  if (g_strcmp0 (argv[1], "status") == 0)
    return run_status (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "policy") == 0)
    return run_policy (argc - 1, argv + 1);

  g_printerr ("wyctl: unknown command: %s\n", argv[1]);
  return 2;
}
