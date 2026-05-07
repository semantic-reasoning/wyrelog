/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <libsoup/soup.h>
#include <string.h>

#include "wyrelog/version.h"

typedef struct
{
  gchar *daemon_url;
  gboolean show_version;
} WyctlOptions;

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
run_status (const WyctlOptions *opts)
{
  if (opts->daemon_url == NULL || opts->daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }

  if (!daemon_url_is_valid (opts->daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  g_autofree gchar *uri = build_healthz_uri (opts->daemon_url);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  g_autoptr (SoupSession) session = soup_session_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body =
      soup_session_send_and_read (session, msg, NULL, &error);
  if (body == NULL) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts->daemon_url);
    return 1;
  }

  guint status = soup_message_get_status (msg);
  if (status < 200 || status >= 300) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts->daemon_url);
    return 1;
  }

  g_print ("ok\n");
  return 0;
}

int
main (int argc, char **argv)
{
  WyctlOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts.show_version,
        "Print version and exit", NULL},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("COMMAND - wyrelog control client");
  g_option_context_add_main_entries (context, entries, NULL);

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
    return run_status (&opts);

  g_printerr ("wyctl: unknown command: %s\n", argv[1]);
  return 2;
}
