/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "daemon/options.h"
#include "daemon/runtime.h"
#include "wyrelog/wyrelog.h"

#ifndef WYL_DEFAULT_TEMPLATE_DIR
#error "WYL_DEFAULT_TEMPLATE_DIR must be defined by the build."
#endif

int
main (int argc, char **argv)
{
  WylDaemonOptions opts = {
    .template_dir = WYL_DEFAULT_TEMPLATE_DIR,
    .listen_port = 8765,
  };
  g_autoptr (GError) error = NULL;

  if (!wyl_daemon_parse_options (&argc, &argv, &opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }

  if (opts.show_version) {
    g_print ("%s\n", wyrelog_version_string ());
    return 0;
  }

  return wyl_daemon_run_runtime (&opts);
}
