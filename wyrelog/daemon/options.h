/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

typedef struct
{
  const gchar *template_dir;
  gint listen_port;
  gboolean check_only;
  gboolean show_version;
} WylDaemonOptions;
