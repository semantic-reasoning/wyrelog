/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/options.h"

gboolean
wyl_daemon_parse_options (gint *argc, gchar ***argv, WylDaemonOptions *opts,
    GError **error)
{
  GOptionEntry entries[] = {
    {"template-dir", 0, 0, G_OPTION_ARG_STRING, &opts->template_dir,
        "Access policy template directory", "DIR"},
    {"policy-db", 0, 0, G_OPTION_ARG_STRING, &opts->policy_store_path,
        "Policy authority database path", "PATH"},
#ifdef WYL_HAS_AUDIT
    {"audit-db", 0, 0, G_OPTION_ARG_STRING, &opts->audit_store_path,
        "Runtime audit sink database path", "PATH"},
#endif
#ifdef WYL_HAS_DAEMON_HTTP
    {"listen-port", 0, 0, G_OPTION_ARG_INT, &opts->listen_port,
        "HTTP listen port", "PORT"},
#endif
    {"check", 0, 0, G_OPTION_ARG_NONE, &opts->check_only,
        "Load policy templates and exit", NULL},
    {"production", 0, 0, G_OPTION_ARG_NONE, &opts->production_mode,
        "Enable production fail-closed startup gates", NULL},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts->show_version,
        "Print version and exit", NULL},
    {"template-version", 0, 0, G_OPTION_ARG_NONE,
          &opts->show_template_version,
        "Print access template version and exit", NULL},
    {NULL}
  };

  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon");
  g_option_context_add_main_entries (context, entries, NULL);

  return g_option_context_parse (context, argc, argv, error);
}
