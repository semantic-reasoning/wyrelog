/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

typedef enum
{
  WYL_DAEMON_PROFILE_SYSTEM = 0,
  WYL_DAEMON_PROFILE_SERVICE = 1,
} WylDaemonProfile;

typedef struct
{
  gchar *config_path;
  gchar *profile_arg;
  WylDaemonProfile profile;
  const gchar *template_dir;
  const gchar *policy_store_path;
  const gchar *policy_keyprovider_path;
  const gchar *audit_store_path;
  const gchar *event_spool_dir;
  const gchar *system_url;
  gchar *listen_port_arg;
  gchar *event_queue_limit_arg;
  guint event_queue_limit;
  gint listen_port;
  gboolean check_only;
  gboolean production_mode;
  gboolean show_version;
  gboolean show_template_version;
  gboolean show_template_info;
  gboolean show_profile_info;
  const gchar *bootstrap_admin_subject;
  gboolean bootstrap_admin_allow_skip_mfa;
} WylDaemonOptions;

gboolean wyl_daemon_parse_options (gint * argc, gchar *** argv,
    WylDaemonOptions * opts, GError ** error);
gboolean wyl_daemon_options_resolve (WylDaemonOptions * opts, GError ** error);
const gchar *wyl_daemon_profile_name (WylDaemonProfile profile);
