/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "daemon/options.h"
#include "daemon/runtime.h"
#include "wyrelog/wyrelog.h"
#include "wyl-engine-private.h"

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

  if (opts.show_template_version) {
    gchar *dl_src = NULL;
    gsize dl_src_len = 0;
    wyrelog_error_t rc =
        wyl_engine_load_templates (opts.template_dir, &dl_src, &dl_src_len);
    guint32 template_version = 0;
    if (rc == WYRELOG_E_OK) {
      rc = wyl_engine_verify_template_manifest (opts.template_dir, dl_src,
          dl_src_len, TRUE, &template_version);
    }
    if (dl_src != NULL) {
      memset (dl_src, 0, dl_src_len);
      g_free (dl_src);
    }
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: template version unavailable: %s\n",
          wyrelog_error_string (rc));
      return 3;
    }
    g_print ("%u\n", template_version);
    return 0;
  }

  return wyl_daemon_run_runtime (&opts);
}
