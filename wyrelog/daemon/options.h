/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

typedef enum
{
  WYL_DAEMON_PROFILE_SYSTEM = 0,
  WYL_DAEMON_PROFILE_SERVICE = 1,
} WylDaemonProfile;

/* Initialize with wyl_daemon_options_init() or a zero/designated initializer.
 * Any string present before parsing is borrowed. Parsing and resolution own
 * only the strings they allocate, and wyl_daemon_options_clear() releases
 * exactly those strings before resetting the structure. Once parsing starts,
 * do not copy the structure; clear the original owner on every exit. */
typedef struct
{
  /* String fields supplied by a designated initializer are borrowed. The
   * parser and resolver record only the strings that they allocate in this
   * private mask so wyl_daemon_options_clear() never frees caller-owned or
   * static storage. */
  guint64 _owned_string_mask;
  gchar *config_path;
  gchar *profile_arg;
  WylDaemonProfile profile;
  const gchar *template_dir;
  const gchar *policy_store_path;
  const gchar *policy_keyprovider_path;
  const gchar *audit_store_path;
  const gchar *fact_root;
  const gchar *fact_store_mode;
  /* Owner-only root for the durable service-credential operation journal.
   * Optional: when unset the escrow handoff surface reports unavailable
   * instead of failing the daemon. */
  const gchar *operation_root;
  /* Owner-only root the publication backend delivers credential secrets
   * into. Optional, disjoint from every other daemon path. */
  const gchar *credential_publication_root;
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

void wyl_daemon_options_init (WylDaemonOptions * opts);
void wyl_daemon_options_clear (WylDaemonOptions * opts);
gboolean wyl_daemon_parse_options (gint * argc, gchar *** argv,
    WylDaemonOptions * opts, GError ** error);
gboolean wyl_daemon_options_resolve (WylDaemonOptions * opts, GError ** error);
const gchar *wyl_daemon_profile_name (WylDaemonProfile profile);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylDaemonOptions, wyl_daemon_options_clear)
