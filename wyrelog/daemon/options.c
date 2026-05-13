/* SPDX-License-Identifier: GPL-3.0-or-later */
#if defined(__unix__) || defined(__APPLE__)
#define _XOPEN_SOURCE 700
#endif
#include "daemon/options.h"

#include <errno.h>
#ifdef G_OS_UNIX
#include <stdlib.h>
#endif
#include <string.h>

#define WYL_DAEMON_DEFAULT_EVENT_QUEUE_LIMIT 1024

const gchar *
wyl_daemon_profile_name (WylDaemonProfile profile)
{
  switch (profile) {
    case WYL_DAEMON_PROFILE_SYSTEM:
      return "system";
    case WYL_DAEMON_PROFILE_SERVICE:
      return "service";
  }
  return "unknown";
}

static gboolean
parse_profile (const gchar *value, WylDaemonProfile *out_profile)
{
  if (value == NULL || value[0] == '\0' || out_profile == NULL)
    return FALSE;
  if (g_strcmp0 (value, "system") == 0) {
    *out_profile = WYL_DAEMON_PROFILE_SYSTEM;
    return TRUE;
  }
  if (g_strcmp0 (value, "service") == 0) {
    *out_profile = WYL_DAEMON_PROFILE_SERVICE;
    return TRUE;
  }
  return FALSE;
}

static gboolean
parse_uint_arg (const gchar *value, guint min_value, guint max_value,
    guint *out_value)
{
  if (out_value == NULL)
    return FALSE;
  if (value == NULL || value[0] == '\0')
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  guint64 parsed = g_ascii_strtoull (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < min_value ||
      parsed > max_value)
    return FALSE;

  *out_value = (guint) parsed;
  return TRUE;
}

static gchar *
path_resolve_existing_prefix (const gchar *path)
{
  g_autofree gchar *canon_path = g_canonicalize_filename (path, NULL);
#ifdef G_OS_UNIX
  g_autofree gchar *probe = g_strdup (canon_path);
  g_autoptr (GString) suffix = g_string_new (NULL);

  while (TRUE) {
    gchar *resolved = realpath (probe, NULL);
    if (resolved != NULL) {
      if (suffix->len == 0)
        return resolved;

      g_autofree gchar *resolved_owner = resolved;
      return g_build_filename (resolved_owner, suffix->str, NULL);
    }

    if (g_strcmp0 (probe, G_DIR_SEPARATOR_S) == 0)
      return g_strdup (canon_path);

    g_autofree gchar *basename = g_path_get_basename (probe);
    g_autofree gchar *dirname = g_path_get_dirname (probe);
    if (suffix->len == 0) {
      g_string_assign (suffix, basename);
    } else {
      g_string_prepend_c (suffix, G_DIR_SEPARATOR);
      g_string_prepend (suffix, basename);
    }
    g_free (probe);
    probe = g_steal_pointer (&dirname);
  }
#else
  return g_steal_pointer (&canon_path);
#endif
}

static gboolean
path_equal_or_contains (const gchar *root, const gchar *path)
{
  if (root == NULL || root[0] == '\0' || path == NULL || path[0] == '\0')
    return FALSE;

  g_autofree gchar *canon_root = path_resolve_existing_prefix (root);
  g_autofree gchar *canon_path = path_resolve_existing_prefix (path);
  if (g_strcmp0 (canon_root, canon_path) == 0)
    return TRUE;

  g_autofree gchar *root_prefix =
      g_strconcat (canon_root, G_DIR_SEPARATOR_S, NULL);
  return g_str_has_prefix (canon_path, root_prefix);
}

static void
keyfile_take_string (GKeyFile *key_file, const gchar *key, const gchar **target)
{
  if (*target != NULL)
    return;
  g_autoptr (GError) error = NULL;
  gchar *value = g_key_file_get_string (key_file, "daemon", key, &error);
  if (value == NULL || value[0] == '\0') {
    g_free (value);
    return;
  }
  *target = value;
}

static void
keyfile_take_owned_string (GKeyFile *key_file, const gchar *key, gchar **target)
{
  if (*target != NULL)
    return;
  g_autoptr (GError) error = NULL;
  gchar *value = g_key_file_get_string (key_file, "daemon", key, &error);
  if (value == NULL || value[0] == '\0') {
    g_free (value);
    return;
  }
  *target = value;
}

static void
load_config_defaults (WylDaemonOptions *opts, GKeyFile *key_file)
{
  keyfile_take_owned_string (key_file, "profile", &opts->profile_arg);
  keyfile_take_string (key_file, "template_dir", &opts->template_dir);
  keyfile_take_string (key_file, "policy_db", &opts->policy_store_path);
  keyfile_take_string (key_file, "policy_keyprovider",
      &opts->policy_keyprovider_path);
  keyfile_take_string (key_file, "audit_db", &opts->audit_store_path);
  keyfile_take_string (key_file, "fact_root", &opts->fact_root);
  keyfile_take_string (key_file, "fact_store_mode", &opts->fact_store_mode);
  keyfile_take_string (key_file, "event_spool_dir", &opts->event_spool_dir);
  keyfile_take_string (key_file, "system_url", &opts->system_url);
  keyfile_take_owned_string (key_file, "listen_port", &opts->listen_port_arg);
  keyfile_take_owned_string (key_file, "event_queue_limit",
      &opts->event_queue_limit_arg);
  keyfile_take_string (key_file, "bootstrap_admin_subject",
      &opts->bootstrap_admin_subject);

  if (!opts->production_mode && g_key_file_has_key (key_file, "daemon",
          "production", NULL)) {
    g_autoptr (GError) error = NULL;
    opts->production_mode =
        g_key_file_get_boolean (key_file, "daemon", "production", &error);
  }

  if (!opts->bootstrap_admin_allow_skip_mfa &&
      g_key_file_has_key (key_file, "daemon",
          "bootstrap_admin_allow_skip_mfa", NULL)) {
    g_autoptr (GError) error = NULL;
    opts->bootstrap_admin_allow_skip_mfa =
        g_key_file_get_boolean (key_file, "daemon",
        "bootstrap_admin_allow_skip_mfa", &error);
  }
}

static const gchar *
default_policy_path (WylDaemonProfile profile)
{
  return profile == WYL_DAEMON_PROFILE_SERVICE ?
      "/var/lib/wyrelog/service/policy.sqlite" :
      "/var/lib/wyrelog/system/policy.sqlite";
}

static const gchar *
default_keyprovider_path (WylDaemonProfile profile)
{
  return profile == WYL_DAEMON_PROFILE_SERVICE ?
      "systemd-creds:wyrelog-service-policy-key" :
      "systemd-creds:wyrelog-system-policy-key";
}

static const gchar *
default_audit_path (WylDaemonProfile profile)
{
  return profile == WYL_DAEMON_PROFILE_SERVICE ?
      "/var/log/wyrelog/service/audit.duckdb" :
      "/var/log/wyrelog/system/audit.duckdb";
}

#ifdef WYL_HAS_FACT_STORE
static const gchar *
default_fact_root (WylDaemonProfile profile)
{
  return profile == WYL_DAEMON_PROFILE_SERVICE ?
      "/var/lib/wyrelog/service/facts" : "/var/lib/wyrelog/system/facts";
}
#endif

static const gchar *
default_spool_dir (WylDaemonProfile profile)
{
  return profile == WYL_DAEMON_PROFILE_SERVICE ?
      "/var/lib/wyrelog/service/event-spool" : NULL;
}

gboolean
wyl_daemon_parse_options (gint *argc, gchar ***argv, WylDaemonOptions *opts,
    GError **error)
{
  GOptionEntry entries[] = {
    {"config", 0, 0, G_OPTION_ARG_STRING, &opts->config_path,
        "Daemon config file", "PATH"},
    {"profile", 0, 0, G_OPTION_ARG_STRING, &opts->profile_arg,
        "Daemon profile: system or service", "PROFILE"},
    {"template-dir", 0, 0, G_OPTION_ARG_STRING, &opts->template_dir,
        "Access policy template directory", "DIR"},
    {"policy-db", 0, 0, G_OPTION_ARG_STRING, &opts->policy_store_path,
        "Policy authority database path", "PATH"},
    {"policy-keyprovider", 0, 0, G_OPTION_ARG_STRING,
          &opts->policy_keyprovider_path,
        "Policy KeyProvider spec: systemd-creds:NAME or file:PATH", "SPEC"},
    {"audit-db", 0, 0, G_OPTION_ARG_STRING, &opts->audit_store_path,
        "Runtime audit sink database path", "PATH"},
    {"fact-root", 0, 0, G_OPTION_ARG_STRING, &opts->fact_root,
        "Datalog fact store root directory", "DIR"},
    {"fact-store-mode", 0, 0, G_OPTION_ARG_STRING,
          &opts->fact_store_mode,
        "Datalog fact store layout mode: per-tenant-graph", "MODE"},
    {"system-url", 0, 0, G_OPTION_ARG_STRING, &opts->system_url,
          "System-profile daemon URL for service-profile event forwarding",
        "URL"},
    {"event-spool-dir", 0, 0, G_OPTION_ARG_STRING, &opts->event_spool_dir,
        "Service-profile disk spool directory", "DIR"},
    {"event-queue-limit", 0, 0, G_OPTION_ARG_STRING,
          &opts->event_queue_limit_arg,
        "Maximum pending service-profile spool files", "N"},
#ifdef WYL_HAS_DAEMON_HTTP
    {"listen-port", 0, 0, G_OPTION_ARG_STRING, &opts->listen_port_arg,
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
    {"template-info", 0, 0, G_OPTION_ARG_NONE, &opts->show_template_info,
        "Print access template artifact identity and exit", NULL},
    {"profile-info", 0, 0, G_OPTION_ARG_NONE, &opts->show_profile_info,
        "Print resolved daemon profile configuration and exit", NULL},
    {"bootstrap-admin-subject", 0, 0, G_OPTION_ARG_STRING,
          &opts->bootstrap_admin_subject,
          "Grant the wr.system_admin role to SUBJECT on a fresh policy store",
        "SUBJECT"},
    {"bootstrap-admin-allow-skip-mfa", 0, 0, G_OPTION_ARG_NONE,
          &opts->bootstrap_admin_allow_skip_mfa,
          "Grant the wr.login.skip_mfa direct permission to the bootstrap "
          "admin so it can mint a first bearer token",
        NULL},
    {NULL}
  };

  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon");
  g_option_context_add_main_entries (context, entries, NULL);

  return g_option_context_parse (context, argc, argv, error);
}

gboolean
wyl_daemon_options_resolve (WylDaemonOptions *opts, GError **error)
{
  g_return_val_if_fail (opts != NULL, FALSE);

  if (opts->config_path != NULL && opts->config_path[0] != '\0') {
    g_autoptr (GKeyFile) key_file = g_key_file_new ();
    if (!g_key_file_load_from_file (key_file, opts->config_path,
            G_KEY_FILE_NONE, error))
      return FALSE;
    load_config_defaults (opts, key_file);
  }

  if (opts->profile_arg == NULL)
    opts->profile_arg = g_strdup ("system");
  if (!parse_profile (opts->profile_arg, &opts->profile)) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "profile must be system or service");
    return FALSE;
  }

  if (opts->event_queue_limit_arg == NULL)
    opts->event_queue_limit = WYL_DAEMON_DEFAULT_EVENT_QUEUE_LIMIT;
  else if (!parse_uint_arg (opts->event_queue_limit_arg, 1, G_MAXUINT,
          &opts->event_queue_limit)) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "event queue limit must be a positive integer");
    return FALSE;
  }

  if (opts->listen_port_arg != NULL) {
    guint listen_port = 0;
    if (!parse_uint_arg (opts->listen_port_arg, 0, 65535, &listen_port)) {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
          "listen port must be between 0 and 65535");
      return FALSE;
    }
    opts->listen_port = (gint) listen_port;
  } else if (opts->listen_port < 0) {
    opts->listen_port =
        opts->profile == WYL_DAEMON_PROFILE_SERVICE ? 8766 : 8765;
  }

  if (opts->production_mode || opts->show_profile_info) {
    if (opts->policy_store_path == NULL)
      opts->policy_store_path = default_policy_path (opts->profile);
    if (opts->policy_keyprovider_path == NULL)
      opts->policy_keyprovider_path = default_keyprovider_path (opts->profile);
    if (opts->audit_store_path == NULL)
      opts->audit_store_path = default_audit_path (opts->profile);
#ifdef WYL_HAS_FACT_STORE
    if (opts->fact_root == NULL)
      opts->fact_root = default_fact_root (opts->profile);
#endif
  }

  if (opts->fact_store_mode == NULL &&
      (opts->fact_root != NULL && opts->fact_root[0] != '\0'))
    opts->fact_store_mode = "per-tenant-graph";
  if (opts->fact_store_mode != NULL &&
      g_strcmp0 (opts->fact_store_mode, "per-tenant-graph") != 0) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "fact store mode must be per-tenant-graph");
    return FALSE;
  }

  if (opts->fact_root != NULL && opts->fact_root[0] != '\0') {
    if (path_equal_or_contains (opts->fact_root, opts->policy_store_path) ||
        path_equal_or_contains (opts->policy_store_path, opts->fact_root)) {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
          "fact root must be distinct from the policy database path");
      return FALSE;
    }
    if (path_equal_or_contains (opts->fact_root, opts->audit_store_path) ||
        path_equal_or_contains (opts->audit_store_path, opts->fact_root)) {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
          "fact root must be distinct from the audit database path");
      return FALSE;
    }
  }

  if (opts->profile == WYL_DAEMON_PROFILE_SERVICE) {
    if ((opts->production_mode || opts->show_profile_info) &&
        opts->event_spool_dir == NULL)
      opts->event_spool_dir = default_spool_dir (opts->profile);
    if (path_equal_or_contains (opts->fact_root, opts->event_spool_dir) ||
        path_equal_or_contains (opts->event_spool_dir, opts->fact_root)) {
      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
          "fact root must be distinct from the service event spool");
      return FALSE;
    }
  } else if (opts->system_url != NULL && opts->system_url[0] != '\0') {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "system-url is only valid for the service profile");
    return FALSE;
  }

  gboolean bootstrap_subject_set = opts->bootstrap_admin_subject != NULL &&
      opts->bootstrap_admin_subject[0] != '\0';
  if (bootstrap_subject_set && opts->check_only) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "--bootstrap-admin-subject must not be combined with --check; "
        "bootstrap requires the persistent policy store.");
    return FALSE;
  }
  if (opts->bootstrap_admin_allow_skip_mfa && !bootstrap_subject_set) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "--bootstrap-admin-allow-skip-mfa requires "
        "--bootstrap-admin-subject.");
    return FALSE;
  }

  return TRUE;
}
