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
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  if (!wyl_daemon_parse_options (&argc, &argv, &opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }
  if (!wyl_daemon_options_resolve (&opts, &error)) {
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

  if (opts.show_template_info) {
    gchar *dl_src = NULL;
    gsize dl_src_len = 0;
    wyrelog_error_t rc =
        wyl_engine_load_templates (opts.template_dir, &dl_src, &dl_src_len);
    WylTemplateArtifactInfo info = { 0 };
    if (rc == WYRELOG_E_OK) {
      rc = wyl_engine_inspect_template_artifact (opts.template_dir, dl_src,
          dl_src_len, TRUE, &info);
    }
    if (dl_src != NULL) {
      memset (dl_src, 0, dl_src_len);
      g_free (dl_src);
    }
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: template info unavailable: %s\n",
          wyrelog_error_string (rc));
      return 3;
    }
    g_print
        ("version=%u\nsha256=%s\nmigrations=%u\nlatest_migration_version=%u\n",
        info.version, info.sha256_hex, info.migration_count,
        info.latest_migration_version);
    return 0;
  }

  if (opts.show_profile_info) {
    g_print ("profile=%s\n", wyl_daemon_profile_name (opts.profile));
    g_print ("template_dir=%s\n", opts.template_dir);
    g_print ("policy_db=%s\n",
        opts.policy_store_path != NULL ? opts.policy_store_path : "");
    g_print ("policy_keyprovider=%s\n",
        opts.policy_keyprovider_path != NULL ? opts.policy_keyprovider_path :
        "");
    g_print ("audit_db=%s\n",
        opts.audit_store_path != NULL ? opts.audit_store_path : "");
    g_print ("fact_root=%s\n", opts.fact_root != NULL ? opts.fact_root : "");
    g_print ("fact_store_mode=%s\n",
        (opts.fact_root != NULL && opts.fact_root[0] != '\0' &&
            opts.fact_store_mode != NULL) ? opts.fact_store_mode : "");
    g_print ("listen_port=%d\n", opts.listen_port);
    g_print ("system_url=%s\n", opts.system_url != NULL ? opts.system_url : "");
    g_print ("event_spool_dir=%s\n",
        opts.event_spool_dir != NULL ? opts.event_spool_dir : "");
    g_print ("event_queue_limit=%u\n", opts.event_queue_limit);
    return 0;
  }

  return wyl_daemon_run_runtime (&opts);
}
