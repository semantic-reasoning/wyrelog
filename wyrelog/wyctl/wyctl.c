/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <errno.h>
#include <string.h>

#include "wyrelog/client.h"
#include "wyrelog/decide.h"
#include "wyrelog/version.h"
#include "wyrelog/wyl-client-private.h"
#include "wyrelog/wyl-permission-scope-private.h"

typedef struct
{
  gchar *daemon_url;
  gchar *timeout_ms_arg;
  gboolean show_version;
} WyctlOptions;

typedef struct
{
  gchar *user;
  gchar *permission;
  gchar *resource;
  gchar *access_token_file;
} WyctlPolicyOptions;

typedef struct
{
  gchar *filter;
  gchar *limit_arg;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlAuditOptions;

#define WYCTL_DEFAULT_TIMEOUT_MS 2000
#define WYCTL_MAX_TIMEOUT_MS 60000
#define WYCTL_AUDIT_DEFAULT_LIMIT 100
#define WYCTL_AUDIT_MAX_LIMIT 100

typedef struct
{
  GCancellable *cancellable;
  GCond cond;
  GMutex mutex;
  gboolean done;
  guint timeout_ms;
} WyctlTimeout;

static gpointer
timeout_thread_func (gpointer data)
{
  WyctlTimeout *timeout = data;

  g_mutex_lock (&timeout->mutex);
  gint64 deadline = g_get_monotonic_time () + (gint64) timeout->timeout_ms
      * 1000;
  while (!timeout->done) {
    if (!g_cond_wait_until (&timeout->cond, &timeout->mutex, deadline))
      break;
  }
  if (!timeout->done)
    g_cancellable_cancel (timeout->cancellable);
  g_mutex_unlock (&timeout->mutex);

  return NULL;
}

static gboolean
parse_timeout_ms (const gchar *raw, guint *out_timeout_ms)
{
  if (raw == NULL) {
    *out_timeout_ms = WYCTL_DEFAULT_TIMEOUT_MS;
    return TRUE;
  }

  if (raw[0] == '\0')
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0')
    return FALSE;

  if (parsed < 1 || parsed > WYCTL_MAX_TIMEOUT_MS)
    return FALSE;

  *out_timeout_ms = (guint) parsed;
  return TRUE;
}

static gboolean
parse_nonnegative_int64 (const gchar *raw, gint64 *out_value)
{
  if (raw == NULL || raw[0] == '\0' || out_value == NULL)
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || parsed < 0)
    return FALSE;

  *out_value = parsed;
  return TRUE;
}

static gboolean
parse_audit_limit (const gchar *raw, guint *out_limit)
{
  if (out_limit == NULL)
    return FALSE;
  if (raw == NULL) {
    *out_limit = WYCTL_AUDIT_DEFAULT_LIMIT;
    return TRUE;
  }
  if (raw[0] == '\0')
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || parsed < 1 ||
      parsed > WYCTL_AUDIT_MAX_LIMIT)
    return FALSE;

  *out_limit = (guint) parsed;
  return TRUE;
}

static gboolean
normalize_access_token_file (gchar *access_token, gsize access_token_size)
{
  if (access_token_size == 0)
    return FALSE;

  for (gsize i = 0; i < access_token_size; i++) {
    if (access_token[i] == '\0')
      return FALSE;
  }

  gsize token_len = access_token_size;
  if (access_token[token_len - 1] == '\n') {
    token_len--;
    if (token_len > 0 && access_token[token_len - 1] == '\r')
      token_len--;
  }
  if (token_len == 0)
    return FALSE;

  for (gsize i = 0; i < token_len; i++) {
    if (g_ascii_isspace (access_token[i]) || g_ascii_iscntrl (access_token[i]))
      return FALSE;
  }
  for (gsize i = token_len; i < access_token_size; i++) {
    if (access_token[i] != '\r' && access_token[i] != '\n')
      return FALSE;
  }

  access_token[token_len] = '\0';
  return TRUE;
}

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
run_status (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlOptions opts = {
    .daemon_url = global_opts->daemon_url,
    .timeout_ms_arg = global_opts->timeout_ms_arg,
  };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"timeout-ms", 0, 0, G_OPTION_ARG_STRING, &opts.timeout_ms_arg,
        "Daemon probe timeout in milliseconds", "N"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon status");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected status argument: %s\n", argv[1]);
    return 2;
  }

  if (opts.daemon_url == NULL || opts.daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }

  if (!daemon_url_is_valid (opts.daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (opts.timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  g_autofree gchar *uri = build_healthz_uri (opts.daemon_url);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  g_autoptr (SoupSession) session = soup_session_new ();
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  WyctlTimeout timeout = {
    .cancellable = cancellable,
    .timeout_ms = timeout_ms,
  };
  g_cond_init (&timeout.cond);
  g_mutex_init (&timeout.mutex);
  GThread *timeout_thread = g_thread_new ("wyctl-timeout", timeout_thread_func,
      &timeout);

  g_autoptr (GError) io_error = NULL;
  g_autoptr (GBytes) body =
      soup_session_send_and_read (session, msg, cancellable, &io_error);

  g_mutex_lock (&timeout.mutex);
  timeout.done = TRUE;
  g_cond_signal (&timeout.cond);
  g_mutex_unlock (&timeout.mutex);
  g_thread_join (timeout_thread);
  g_mutex_clear (&timeout.mutex);
  g_cond_clear (&timeout.cond);

  if (body == NULL) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts.daemon_url);
    return 1;
  }

  guint status = soup_message_get_status (msg);
  if (status < 200 || status >= 300) {
    g_printerr ("wyctl: daemon unavailable: %s\n", opts.daemon_url);
    return 1;
  }

  g_print ("ok\n");
  return 0;
}

static int
load_access_token_file (const gchar *path, gchar **out_access_token)
{
  if (out_access_token == NULL)
    return 2;
  *out_access_token = NULL;

  if (path == NULL || path[0] == '\0') {
    g_printerr ("wyctl: missing --access-token-file\n");
    return 2;
  }

  g_autoptr (GError) error = NULL;
  g_autofree gchar *access_token = NULL;
  gsize access_token_size = 0;
  if (!g_file_get_contents (path, &access_token, &access_token_size, &error)) {
    g_printerr ("wyctl: unable to read access token file\n");
    return 2;
  }
  if (access_token_size == 0) {
    g_printerr ("wyctl: empty access token file\n");
    return 2;
  }
  if (!normalize_access_token_file (access_token, access_token_size)) {
    g_printerr ("wyctl: invalid access token file\n");
    return 2;
  }

  *out_access_token = g_steal_pointer (&access_token);
  return 0;
}

static int
run_policy_decide_request (const WyctlOptions *global_opts,
    const WyctlPolicyOptions *policy_opts, const gchar *access_token,
    const gchar *command, WylClientDecision **out_result)
{
  if (out_result == NULL)
    return 2;
  *out_result = NULL;

  if (global_opts->daemon_url == NULL || global_opts->daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (global_opts->daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (global_opts->timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (global_opts->daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token,
          "__wr_default") != WYRELOG_E_OK) {
    g_printerr ("wyctl: invalid policy credentials\n");
    return 2;
  }
  wyl_client_set_timeout_ms (client, timeout_ms);

  g_autoptr (WylClientDecision) result = NULL;
  wyrelog_error_t rc = wyl_client_decide_ex (client, policy_opts->user,
      policy_opts->permission, policy_opts->resource, &result);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: policy %s failed\n", command);
    return 3;
  }

  *out_result = g_steal_pointer (&result);
  return 0;
}

static int
run_policy_check (const WyctlOptions *global_opts,
    const WyctlPolicyOptions *policy_opts, const gchar *access_token)
{
  g_autoptr (WylClientDecision) result = NULL;
  int rc = run_policy_decide_request (global_opts, policy_opts, access_token,
      "check", &result);
  if (rc != 0)
    return rc;

  gint decision = wyl_client_decision_get_decision (result);
  if (decision == WYL_DECISION_ALLOW) {
    g_print ("allow\n");
    return 0;
  }

  g_print ("deny\n");
  return 1;
}

static int
run_policy_explain (const WyctlOptions *global_opts,
    const WyctlPolicyOptions *policy_opts, const gchar *access_token)
{
  g_autoptr (WylClientDecision) result = NULL;
  int rc = run_policy_decide_request (global_opts, policy_opts, access_token,
      "explain", &result);
  if (rc != 0)
    return rc;

  gint decision = wyl_client_decision_get_decision (result);
  if (decision == WYL_DECISION_ALLOW) {
    g_print ("allow\n");
    return 0;
  }

  g_print ("deny\n");
  const gchar *deny_reason = wyl_client_decision_get_deny_reason (result);
  const gchar *deny_origin = wyl_client_decision_get_deny_origin (result);
  if (deny_reason != NULL)
    g_print ("reason=%s\n", deny_reason);
  if (deny_origin != NULL)
    g_print ("origin=%s\n", deny_origin);
  return 0;
}

static int
run_policy_decision_command (const WyctlOptions *global_opts,
    const gchar *command, gint argc, gchar **argv)
{
  WyctlPolicyOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"user", 0, 0, G_OPTION_ARG_STRING, &opts.user, "Decision user", "USER"},
    {"permission", 0, 0, G_OPTION_ARG_STRING, &opts.permission,
        "Decision permission", "PERMISSION"},
    {"resource", 0, 0, G_OPTION_ARG_STRING, &opts.resource,
        "Decision resource", "RESOURCE"},
    {"access-token-file", 0, 0, G_OPTION_ARG_STRING, &opts.access_token_file,
        "Bearer access token file", "PATH"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autofree gchar *summary = g_strdup_printf ("- wyrelog policy %s", command);
  g_autoptr (GOptionContext) context = g_option_context_new (summary);
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected policy %s argument: %s\n", command, argv[1]);
    return 2;
  }

  if (opts.user == NULL || opts.user[0] == '\0') {
    g_printerr ("wyctl: missing --user\n");
    return 2;
  }
  if (opts.permission == NULL || opts.permission[0] == '\0') {
    g_printerr ("wyctl: missing --permission\n");
    return 2;
  }
  if (opts.resource == NULL || opts.resource[0] == '\0') {
    g_printerr ("wyctl: missing --resource\n");
    return 2;
  }
  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (opts.access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  if (g_strcmp0 (command, "check") == 0)
    return run_policy_check (global_opts, &opts, access_token);
  if (g_strcmp0 (command, "explain") == 0)
    return run_policy_explain (global_opts, &opts, access_token);

  g_printerr ("wyctl: policy %s is not implemented\n", command);
  return 3;
}

static int
run_policy (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing policy command\n");
    return 2;
  }

  if (g_strcmp0 (argv[1], "check") == 0 || g_strcmp0 (argv[1], "explain") == 0)
    return run_policy_decision_command (global_opts, argv[1], argc - 1,
        argv + 1);

  g_printerr ("wyctl: unknown policy command: %s\n", argv[1]);
  return 2;
}

static int
run_audit_query (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlAuditOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"filter", 0, 0, G_OPTION_ARG_STRING, &opts.filter,
        "Audit event filter", "FILTER"},
    {"limit", 0, 0, G_OPTION_ARG_STRING, &opts.limit_arg,
        "Maximum events to print", "N"},
    {"access-token-file", 0, 0, G_OPTION_ARG_STRING, &opts.access_token_file,
        "Bearer access token file", "PATH"},
    {"guard-timestamp", 0, 0, G_OPTION_ARG_STRING,
        &opts.guard_timestamp_arg, "Guard timestamp", "US"},
    {"guard-loc-class", 0, 0, G_OPTION_ARG_STRING, &opts.guard_loc_class,
        "Guard location class", "CLASS"},
    {"guard-risk", 0, 0, G_OPTION_ARG_STRING, &opts.guard_risk_arg,
        "Guard risk score", "N"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog audit query");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected audit query argument: %s\n", argv[1]);
    return 2;
  }

  if (global_opts->daemon_url == NULL || global_opts->daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (global_opts->daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (global_opts->timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  gint64 guard_timestamp = 0;
  if (!parse_nonnegative_int64 (opts.guard_timestamp_arg, &guard_timestamp)) {
    g_printerr ("wyctl: invalid --guard-timestamp\n");
    return 2;
  }
  if (opts.guard_loc_class == NULL ||
      !wyl_guard_loc_class_is_valid (opts.guard_loc_class)) {
    g_printerr ("wyctl: invalid --guard-loc-class\n");
    return 2;
  }
  gint64 guard_risk = 0;
  if (!parse_nonnegative_int64 (opts.guard_risk_arg, &guard_risk) ||
      guard_risk > 100) {
    g_printerr ("wyctl: invalid --guard-risk\n");
    return 2;
  }
  guint limit = 0;
  if (!parse_audit_limit (opts.limit_arg, &limit)) {
    g_printerr ("wyctl: invalid --limit\n");
    return 2;
  }

  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (opts.access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  (void) timeout_ms;
  (void) guard_timestamp;
  (void) guard_risk;
  (void) limit;
  (void) access_token;
  g_printerr ("wyctl: audit query is not implemented\n");
  return 3;
}

static int
run_audit (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing audit command\n");
    return 2;
  }

  if (g_strcmp0 (argv[1], "query") == 0)
    return run_audit_query (global_opts, argc - 1, argv + 1);

  g_printerr ("wyctl: unknown audit command: %s\n", argv[1]);
  return 2;
}

int
main (int argc, char **argv)
{
  WyctlOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"timeout-ms", 0, 0, G_OPTION_ARG_STRING, &opts.timeout_ms_arg,
        "Daemon probe timeout in milliseconds", "N"},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts.show_version,
        "Print version and exit", NULL},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("COMMAND - wyrelog control client");
  g_option_context_add_main_entries (context, entries, NULL);
  g_option_context_set_strict_posix (context, TRUE);

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
    return run_status (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "policy") == 0)
    return run_policy (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "audit") == 0)
    return run_audit (&opts, argc - 1, argv + 1);

  g_printerr ("wyctl: unknown command: %s\n", argv[1]);
  return 2;
}
