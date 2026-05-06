/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

typedef struct
{
  const gchar *template_dir;
  const gchar *policy_store_path;
#ifdef WYL_HAS_AUDIT
  const gchar *audit_store_path;
#endif
  gint listen_port;
  gboolean check_only;
  gboolean show_version;
} WylDaemonOptions;

gboolean wyl_daemon_parse_options (gint * argc, gchar *** argv,
    WylDaemonOptions * opts, GError ** error);
