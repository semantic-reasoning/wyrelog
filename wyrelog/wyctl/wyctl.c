/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>
#include <sodium.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "auth/totp.h"
#include "auth/mfa-enrollment-private.h"
#include "wyrelog/client.h"
#include "wyrelog/decide.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/version.h"
#include "wyrelog/wyl-client-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"
#include "wyrelog/wyl-permission-scope-private.h"
#include "wyctl-config.h"
#include "wyctl-token-file.h"

typedef struct
{
  gchar *daemon_url;
  gchar *timeout_ms_arg;
  gboolean show_version;
  gboolean readiness;
  /* Borrowed pointer to the GSettings handle opened once in main().
   * NULL when the schema is not installed or the operator set
   * WYCTL_DISABLE_GSETTINGS=1; the resolver treats NULL as "no
   * fallback available". */
  GSettings *settings;
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

typedef struct
{
  gchar *subject;
  gchar *perm;
  gchar *scope;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlPolicyPermissionOptions;

typedef struct
{
  gchar *subject;
  gchar *role;
  gchar *scope;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlPolicyRoleOptions;

typedef struct
{
  gchar *tenant;
  gchar *graph;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlGraphOptions;

typedef struct
{
  gchar *tenant;
  gchar *graph;
  gchar *namespace_id;
  gchar *relation;
  gchar *schema_version_arg;
  gchar *columns_arg;
  gchar *max_rows_arg;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlFactSchemaOptions;

typedef struct
{
  gchar *tenant;
  gchar *graph;
  gchar *namespace_id;
  gchar *relation;
  gchar *schema_version_arg;
  gchar *batch_id;
  gchar *idempotency_key;
  gchar *format;
  gchar *input;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlFactPutOptions;

typedef struct
{
  gchar *tenant;
  gchar *graph;
  gchar *query;
  gchar *output;
  gchar *limit_arg;
  gchar *access_token_file;
  gchar *guard_timestamp_arg;
  gchar *guard_loc_class;
  gchar *guard_risk_arg;
} WyctlDatalogQueryOptions;

typedef struct
{
  gchar *keyprovider_path;
  gchar *store_path;
  gchar *from_keyprovider_path;
  gchar *to_keyprovider_path;
} WyctlKeyOptions;

typedef struct
{
  gchar *subject;
  gchar *store_path;
  gchar *keyprovider_path;
  gchar *access_token_file;
} WyctlMfaOptions;

#define WYCTL_DEFAULT_TIMEOUT_MS 2000
#define WYCTL_MAX_TIMEOUT_MS 60000
#define WYCTL_AUDIT_DEFAULT_LIMIT 100
#define WYCTL_AUDIT_MAX_LIMIT 100
#define WYCTL_KEYPROVIDER_FILE_BYTES 32

typedef gchar WyctlSensitiveChar;

static void
wyctl_sensitive_string_free (WyctlSensitiveChar *value)
{
  if (value == NULL)
    return;
  sodium_memzero (value, strlen (value));
  g_free (value);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WyctlSensitiveChar, wyctl_sensitive_string_free);

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
parse_positive_uint32 (const gchar *raw, guint32 *out_value)
{
  if (raw == NULL || raw[0] == '\0' || out_value == NULL)
    return FALSE;

  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || parsed < 1 ||
      parsed > G_MAXUINT32)
    return FALSE;

  *out_value = (guint32) parsed;
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

static void
append_json_string (GString *json, const gchar *value)
{
  g_string_append_c (json, '"');
  for (const guchar * p = (const guchar *)value; p != NULL && *p != '\0'; p++) {
    switch (*p) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\b':
        g_string_append (json, "\\b");
        break;
      case '\f':
        g_string_append (json, "\\f");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (*p < 0x20)
          g_string_append_printf (json, "\\u%04x", (guint) * p);
        else
          g_string_append_c (json, (gchar) * p);
        break;
    }
  }
  g_string_append_c (json, '"');
}

static void
append_json_nullable_string_member (GString *json, const gchar *name,
    const gchar *value)
{
  append_json_string (json, name);
  g_string_append_c (json, ':');
  if (value == NULL)
    g_string_append (json, "null");
  else
    append_json_string (json, value);
}

static void
append_audit_event_json (GString *json, const WylAuditEvent *event)
{
  g_autofree gchar *id = wyl_audit_event_dup_id_string (event);

  g_string_append_c (json, '{');
  append_json_nullable_string_member (json, "id", id);
  g_string_append_printf (json, ",\"created_at_us\":%" G_GINT64_FORMAT,
      wyl_audit_event_get_created_at_us (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "subject_id",
      wyl_audit_event_get_subject_id (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "action",
      wyl_audit_event_get_action (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "resource_id",
      wyl_audit_event_get_resource_id (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "deny_reason",
      wyl_audit_event_get_deny_reason (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "deny_origin",
      wyl_audit_event_get_deny_origin (event));
  g_string_append_c (json, ',');
  append_json_nullable_string_member (json, "request_id",
      wyl_audit_event_get_request_id (event));
  g_string_append_printf (json, ",\"decision\":%d}",
      wyl_audit_event_get_decision (event));
}

static gchar *
build_daemon_path_uri (const gchar *daemon_url, const gchar *path)
{
  g_autofree gchar *root = g_strdup (daemon_url);

  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  return g_strdup_printf ("%s%s", root, path);
}

static gchar *
build_healthz_uri (const gchar *daemon_url)
{
  return build_daemon_path_uri (daemon_url, "/healthz");
}

static gchar *
build_readyz_json_uri (const gchar *daemon_url)
{
  return build_daemon_path_uri (daemon_url, "/readyz?format=json");
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
send_status_probe (const gchar *uri, guint timeout_ms, guint *out_status,
    gchar **out_body)
{
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (out_status == NULL || out_body == NULL || msg == NULL)
    return 2;
  *out_status = 0;
  *out_body = NULL;

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

  if (body == NULL)
    return 1;

  *out_status = soup_message_get_status (msg);
  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  *out_body = g_strndup (body_data, body_size);
  return 0;
}

static const gchar *
skip_json_ws (const gchar *p)
{
  while (p != NULL && g_ascii_isspace (*p))
    p++;
  return p;
}

static gboolean
parse_json_code_string (const gchar **inout_p, gchar **out_value)
{
  const gchar *p = skip_json_ws (*inout_p);
  if (p == NULL || *p != '"' || out_value == NULL)
    return FALSE;
  p++;

  const gchar *start = p;
  while (g_ascii_isalnum (*p) || *p == '_')
    p++;
  if (p == start || *p != '"')
    return FALSE;

  *out_value = g_strndup (start, (gsize) (p - start));
  *inout_p = p + 1;
  return TRUE;
}

static gboolean
skip_json_string_value (const gchar **inout_p)
{
  const gchar *p = skip_json_ws (*inout_p);
  if (p == NULL || *p != '"')
    return FALSE;
  p++;
  while (*p != '\0') {
    if (*p == '\\') {
      p++;
      if (*p == '\0')
        return FALSE;
    } else if (*p == '"') {
      *inout_p = p + 1;
      return TRUE;
    }
    p++;
  }
  return FALSE;
}

static gboolean
skip_json_value (const gchar **inout_p)
{
  const gchar *p = skip_json_ws (*inout_p);
  if (p == NULL)
    return FALSE;
  if (*p == '"')
    return skip_json_string_value (inout_p);
  if (*p == '{' || *p == '[') {
    gchar open = *p;
    gchar close = open == '{' ? '}' : ']';
    guint depth = 1;
    p++;
    while (*p != '\0') {
      if (*p == '"') {
        const gchar *string = p;
        if (!skip_json_string_value (&string))
          return FALSE;
        p = string;
        continue;
      }
      if (*p == open)
        depth++;
      else if (*p == close) {
        depth--;
        if (depth == 0) {
          *inout_p = p + 1;
          return TRUE;
        }
      }
      p++;
    }
    return FALSE;
  }
  while (*p != '\0' && *p != ',' && *p != '}' && *p != ']')
    p++;
  *inout_p = p;
  return TRUE;
}

static gboolean
parse_readiness_json (const gchar *body, gchar **out_status, gchar **out_reason)
{
  if (body == NULL || out_status == NULL || out_reason == NULL)
    return FALSE;
  *out_status = NULL;
  *out_reason = NULL;

  const gchar *p = skip_json_ws (body);
  if (*p != '{')
    return FALSE;
  p++;

  g_autofree gchar *key = NULL;
  if (!parse_json_code_string (&p, &key) || g_strcmp0 (key, "status") != 0)
    return FALSE;
  p = skip_json_ws (p);
  if (*p != ':')
    return FALSE;
  p++;
  if (!parse_json_code_string (&p, out_status))
    return FALSE;

  p = skip_json_ws (p);
  while (*p == ',') {
    p++;
    g_clear_pointer (&key, g_free);
    if (!parse_json_code_string (&p, &key))
      return FALSE;
    p = skip_json_ws (p);
    if (*p != ':')
      return FALSE;
    p++;
    if (g_strcmp0 (key, "reason") == 0) {
      if (!parse_json_code_string (&p, out_reason))
        return FALSE;
    } else if (!skip_json_value (&p)) {
      return FALSE;
    }
    p = skip_json_ws (p);
  }

  if (*p != '}')
    return FALSE;
  p = skip_json_ws (p + 1);
  return *p == '\0';
}

static gboolean
readiness_reason_is_known (const gchar *reason)
{
  if (reason == NULL)
    return FALSE;
  return g_strcmp0 (reason, "delta_not_ready") == 0 ||
      g_strcmp0 (reason, "audit_degraded") == 0 ||
      g_strcmp0 (reason, "not_ready") == 0;
}

static const gchar *
readiness_reason_from_body (const gchar *body)
{
  g_autofree gchar *status = NULL;
  g_autofree gchar *reason = NULL;
  if (!parse_readiness_json (body, &status, &reason))
    return NULL;
  if (g_strcmp0 (status, "not_ready") != 0 ||
      !readiness_reason_is_known (reason))
    return NULL;
  if (g_strcmp0 (reason, "delta_not_ready") == 0)
    return "delta_not_ready";
  if (g_strcmp0 (reason, "audit_degraded") == 0)
    return "audit_degraded";
  if (g_strcmp0 (reason, "not_ready") == 0)
    return "not_ready";
  return NULL;
}

static int
run_status (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlOptions opts = {
    .daemon_url = global_opts->daemon_url,
    .timeout_ms_arg = global_opts->timeout_ms_arg,
    .readiness = global_opts->readiness,
  };
  GOptionEntry entries[] = {
    {"daemon-url", 0, 0, G_OPTION_ARG_STRING, &opts.daemon_url,
        "Daemon URL", "URL"},
    {"timeout-ms", 0, 0, G_OPTION_ARG_STRING, &opts.timeout_ms_arg,
        "Daemon probe timeout in milliseconds", "N"},
    {"readiness", 0, 0, G_OPTION_ARG_NONE, &opts.readiness,
        "Report daemon readiness", NULL},
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

  /* Resolve the CLI flags against GSettings defaults. The resolver
   * returns an owned copy or NULL; the original opts.* slots stay
   * owned by GOptionContext so we never assign back into them. */
  g_autofree gchar *daemon_url = wyctl_resolve_string_option (opts.daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (opts.timeout_ms_arg,
      global_opts->settings, "default-timeout-ms");

  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }

  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  g_autofree gchar *uri =
      opts.readiness ? build_readyz_json_uri (daemon_url) :
      build_healthz_uri (daemon_url);
  guint status = 0;
  g_autofree gchar *body = NULL;
  int probe_rc = send_status_probe (uri, timeout_ms, &status, &body);
  if (probe_rc == 2) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }
  if (probe_rc != 0) {
    g_printerr ("wyctl: daemon unavailable: %s\n", daemon_url);
    return 1;
  }

  if (status < 200 || status >= 300) {
    if (opts.readiness && status == 503) {
      const gchar *reason = readiness_reason_from_body (body);
      if (reason != NULL) {
        g_print ("status=not_ready reason=%s\n", reason);
        return 1;
      }
    }
    g_printerr ("wyctl: daemon unavailable: %s\n", daemon_url);
    return 1;
  }

  if (opts.readiness) {
    g_autofree gchar *ready_status = NULL;
    g_autofree gchar *ready_reason = NULL;
    if (!parse_readiness_json (body, &ready_status, &ready_reason) ||
        g_strcmp0 (ready_status, "ready") != 0 || ready_reason != NULL) {
      g_printerr ("wyctl: daemon readiness failed\n");
      return 1;
    }
    g_print ("status=ready\n");
    return 0;
  }

  g_print ("ok\n");
  return 0;
}

static void
emit_token_file_diagnostic (WyctlTokenFileStatus status, const gchar *path)
{
  const gchar *fmt = wyctl_token_file_status_message (status);
  if (fmt == NULL) {
    g_printerr ("wyctl: unable to read access token file: %s\n",
        path != NULL ? path : "(null)");
    return;
  }
  if (status == WYCTL_TOKEN_FILE_MISSING_PATH) {
    g_printerr ("%s\n", fmt);
    return;
  }
  g_printerr (fmt, path != NULL ? path : "(null)");
  g_printerr ("\n");
}

static int
load_access_token_file (const gchar *path, gchar **out_access_token)
{
  if (out_access_token == NULL)
    return 2;
  *out_access_token = NULL;

  /* Hand the path to the safety helper. The helper opens with
   * O_NOFOLLOW + O_CLOEXEC, fstat()s the resulting fd, checks owner
   * and mode bits against the calling euid, and only then reads
   * bytes from the same fd it validated. No daemon request is ever
   * sent on the failure path, because this function returns rc != 0
   * before any wyl_client_* call. */
  g_autofree gchar *raw = NULL;
  WyctlTokenFileStatus rc = wyctl_token_file_read (path, &raw);
  if (rc != WYCTL_TOKEN_FILE_OK) {
    emit_token_file_diagnostic (rc, path);
    return 2;
  }

  gsize size = strlen (raw);
  if (!normalize_access_token_file (raw, size)) {
    g_printerr ("wyctl: invalid access token file: %s\n",
        path != NULL ? path : "(null)");
    return 2;
  }

  *out_access_token = g_steal_pointer (&raw);
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

  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");

  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token,
          WYL_TENANT_DEFAULT) != WYRELOG_E_OK) {
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
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");
  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (access_token_file, &access_token);
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
run_policy_permission_mutation_command (const WyctlOptions *global_opts,
    const gchar *command, gint argc, gchar **argv)
{
  WyctlPolicyPermissionOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"subject", 0, 0, G_OPTION_ARG_STRING, &opts.subject,
        "Mutation subject", "SUBJECT_ID"},
    {"perm", 0, 0, G_OPTION_ARG_STRING, &opts.perm,
        "Mutation permission", "PERMISSION_ID"},
    {"scope", 0, 0, G_OPTION_ARG_STRING, &opts.scope,
        "Mutation scope", "SCOPE_ID"},
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

  if (opts.subject == NULL || opts.subject[0] == '\0') {
    g_printerr ("wyctl: missing --subject\n");
    return 2;
  }
  if (opts.perm == NULL || opts.perm[0] == '\0') {
    g_printerr ("wyctl: missing --perm\n");
    return 2;
  }
  if (opts.scope == NULL || opts.scope[0] == '\0') {
    g_printerr ("wyctl: missing --scope\n");
    return 2;
  }

  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
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

  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token,
          WYL_TENANT_DEFAULT) != WYRELOG_E_OK) {
    g_printerr ("wyctl: invalid policy credentials\n");
    return 2;
  }
  wyl_client_set_timeout_ms (client, timeout_ms);

  wyrelog_error_t rc = WYRELOG_E_INVALID;
  if (g_strcmp0 (command, "permission-grant") == 0) {
    rc = wyl_client_policy_permission_grant (client, opts.subject, opts.perm,
        opts.scope, guard_timestamp, opts.guard_loc_class, guard_risk);
  } else if (g_strcmp0 (command, "permission-revoke") == 0) {
    rc = wyl_client_policy_permission_revoke (client, opts.subject, opts.perm,
        opts.scope, guard_timestamp, opts.guard_loc_class, guard_risk);
  } else {
    g_printerr ("wyctl: policy %s is not implemented\n", command);
    return 3;
  }

  if (rc == WYRELOG_E_OK) {
    g_print ("ok\n");
    return 0;
  }
  if (rc == WYRELOG_E_INVALID) {
    g_printerr ("wyctl: policy %s failed: invalid_policy_mutation\n", command);
    return 3;
  }
  if (rc == WYRELOG_E_AUTH) {
    g_printerr ("wyctl: policy %s failed: policy_auth_required\n", command);
    return 6;
  }
  if (rc == WYRELOG_E_POLICY) {
    g_printerr ("wyctl: policy %s failed: policy_mutation_denied\n", command);
    return 4;
  }
  g_printerr ("wyctl: policy %s failed: policy_mutation_failed\n", command);
  return 5;
}

static int
run_policy_role_mutation_command (const WyctlOptions *global_opts,
    const gchar *command, gint argc, gchar **argv)
{
  WyctlPolicyRoleOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"subject", 0, 0, G_OPTION_ARG_STRING, &opts.subject,
        "Mutation subject", "SUBJECT_ID"},
    {"role", 0, 0, G_OPTION_ARG_STRING, &opts.role,
        "Mutation role", "ROLE_ID"},
    {"scope", 0, 0, G_OPTION_ARG_STRING, &opts.scope,
        "Mutation scope", "SCOPE_ID"},
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

  if (opts.subject == NULL || opts.subject[0] == '\0') {
    g_printerr ("wyctl: missing --subject\n");
    return 2;
  }
  if (opts.role == NULL || opts.role[0] == '\0') {
    g_printerr ("wyctl: missing --role\n");
    return 2;
  }
  if (opts.scope == NULL || opts.scope[0] == '\0') {
    g_printerr ("wyctl: missing --scope\n");
    return 2;
  }

  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
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

  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token,
          WYL_TENANT_DEFAULT) != WYRELOG_E_OK) {
    g_printerr ("wyctl: invalid policy credentials\n");
    return 2;
  }
  wyl_client_set_timeout_ms (client, timeout_ms);

  wyrelog_error_t rc = WYRELOG_E_INVALID;
  if (g_strcmp0 (command, "role-grant") == 0) {
    rc = wyl_client_policy_role_grant (client, opts.subject, opts.role,
        opts.scope, guard_timestamp, opts.guard_loc_class, guard_risk);
  } else if (g_strcmp0 (command, "role-revoke") == 0) {
    rc = wyl_client_policy_role_revoke (client, opts.subject, opts.role,
        opts.scope, guard_timestamp, opts.guard_loc_class, guard_risk);
  } else {
    g_printerr ("wyctl: policy %s is not implemented\n", command);
    return 3;
  }

  if (rc == WYRELOG_E_OK) {
    g_print ("ok\n");
    return 0;
  }
  if (rc == WYRELOG_E_INVALID) {
    g_printerr ("wyctl: policy %s failed: invalid_policy_mutation\n", command);
    return 3;
  }
  if (rc == WYRELOG_E_AUTH) {
    g_printerr ("wyctl: policy %s failed: policy_auth_required\n", command);
    return 6;
  }
  if (rc == WYRELOG_E_POLICY) {
    g_printerr ("wyctl: policy %s failed: policy_mutation_denied\n", command);
    return 4;
  }
  g_printerr ("wyctl: policy %s failed: policy_mutation_failed\n", command);
  return 5;
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
  if (g_strcmp0 (argv[1], "permission-grant") == 0 ||
      g_strcmp0 (argv[1], "permission-revoke") == 0)
    return run_policy_permission_mutation_command (global_opts, argv[1],
        argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "role-grant") == 0 ||
      g_strcmp0 (argv[1], "role-revoke") == 0)
    return run_policy_role_mutation_command (global_opts, argv[1],
        argc - 1, argv + 1);

  g_printerr ("wyctl: unknown policy command: %s\n", argv[1]);
  return 2;
}

static gboolean
parse_guard_options (const gchar *timestamp_arg, const gchar *loc_class,
    const gchar *risk_arg, gint64 *out_timestamp, gint64 *out_risk)
{
  if (!parse_nonnegative_int64 (timestamp_arg, out_timestamp)) {
    g_printerr ("wyctl: invalid --guard-timestamp\n");
    return FALSE;
  }
  if (loc_class == NULL || !wyl_guard_loc_class_is_valid (loc_class)) {
    g_printerr ("wyctl: invalid --guard-loc-class\n");
    return FALSE;
  }
  if (!parse_nonnegative_int64 (risk_arg, out_risk) || *out_risk > 100) {
    g_printerr ("wyctl: invalid --guard-risk\n");
    return FALSE;
  }
  return TRUE;
}

/* Build the bearer-authenticated WylClient used by the fact / graph /
 * datalog subcommands. All values are already resolved against
 * GSettings by the caller, so this helper does no fallback lookup. */
static int
create_fact_client (const gchar *daemon_url, const gchar *timeout_ms_arg,
    const gchar *tenant, const gchar *access_token_file, WylClient **out_client)
{
  if (out_client == NULL)
    return 2;
  *out_client = NULL;
  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }
  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
    g_printerr ("wyctl: invalid timeout\n");
    return 2;
  }
  if (tenant == NULL || tenant[0] == '\0') {
    g_printerr ("wyctl: missing --tenant\n");
    return 2;
  }

  g_autofree gchar *access_token = NULL;
  int token_rc = load_access_token_file (access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token, tenant)
      != WYRELOG_E_OK) {
    g_printerr ("wyctl: invalid fact credentials\n");
    return 2;
  }
  wyl_client_set_timeout_ms (client, timeout_ms);
  *out_client = g_steal_pointer (&client);
  return 0;
}

static int
fact_remote_exit (WylClient *client, const gchar *command,
    wyrelog_error_t rc, const gchar *fallback_code)
{
  if (rc == WYRELOG_E_OK)
    return 0;
  g_autofree gchar *code = client != NULL ?
      wyl_client_dup_last_error_code (client) : NULL;
  const gchar *shown = code != NULL ? code : fallback_code;
  if (shown == NULL)
    shown = "failed";
  g_printerr ("wyctl: %s failed: %s\n", command, shown);
  guint status = client != NULL ? wyl_client_get_last_http_status (client) : 0;
  if (rc == WYRELOG_E_INVALID)
    return status == 0 ? 2 : 3;
  if (rc == WYRELOG_E_AUTH)
    return 6;
  if (rc == WYRELOG_E_POLICY)
    return 4;
  return 5;
}

static int
run_graph_create (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlGraphOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"tenant", 0, 0, G_OPTION_ARG_STRING, &opts.tenant, "Tenant", "TENANT"},
    {"graph", 0, 0, G_OPTION_ARG_STRING, &opts.graph, "Graph", "GRAPH"},
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
      g_option_context_new ("- wyrelog graph create");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected graph create argument: %s\n", argv[1]);
    return 2;
  }
  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *tenant = wyctl_resolve_string_option (opts.tenant,
      global_opts->settings, "default-tenant");
  g_autofree gchar *graph = wyctl_resolve_string_option (opts.graph,
      global_opts->settings, "default-graph");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (graph == NULL || graph[0] == '\0') {
    g_printerr ("wyctl: missing --graph\n");
    return 2;
  }
  gint64 guard_timestamp = 0;
  gint64 guard_risk = 0;
  if (!parse_guard_options (opts.guard_timestamp_arg, opts.guard_loc_class,
          opts.guard_risk_arg, &guard_timestamp, &guard_risk))
    return 2;
  g_autoptr (WylClient) client = NULL;
  int client_rc = create_fact_client (daemon_url, timeout_ms_arg, tenant,
      access_token_file, &client);
  if (client_rc != 0)
    return client_rc;
  wyrelog_error_t rc = wyl_client_graph_create (client, tenant,
      graph, guard_timestamp, opts.guard_loc_class, guard_risk);
  int exit_rc = fact_remote_exit (client, "graph create", rc,
      "graph_create_failed");
  if (exit_rc == 0)
    g_print ("ok\n");
  return exit_rc;
}

static int
run_graph (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing graph command\n");
    return 2;
  }
  if (g_strcmp0 (argv[1], "create") == 0)
    return run_graph_create (global_opts, argc - 1, argv + 1);
  g_printerr ("wyctl: unknown graph command: %s\n", argv[1]);
  return 2;
}

static void
client_fact_columns_clear (WylClientFactColumn *columns, gsize n_columns)
{
  for (gsize i = 0; i < n_columns; i++) {
    g_free ((gchar *) columns[i].name);
    g_free ((gchar *) columns[i].type);
  }
  g_free (columns);
}

static gboolean
parse_columns_arg (const gchar *raw, WylClientFactColumn **out_columns,
    gsize *out_n_columns)
{
  if (out_columns == NULL || out_n_columns == NULL || raw == NULL ||
      raw[0] == '\0')
    return FALSE;
  *out_columns = NULL;
  *out_n_columns = 0;
  g_auto (GStrv) entries = g_strsplit (raw, ",", -1);
  g_autoptr (GArray) cols = g_array_new (FALSE, TRUE,
      sizeof (WylClientFactColumn));
  for (gsize i = 0; entries[i] != NULL; i++) {
    if (entries[i][0] == '\0')
      return FALSE;
    gchar *sep = strchr (entries[i], ':');
    if (sep == NULL || sep == entries[i] || sep[1] == '\0' ||
        strchr (sep + 1, ':') != NULL)
      return FALSE;
    *sep = '\0';
    WylClientFactColumn col = {
      .name = g_strdup (entries[i]),
      .type = g_strdup (sep + 1),
      .nullable = FALSE,
      .visible = TRUE,
    };
    g_array_append_val (cols, col);
  }
  if (cols->len == 0)
    return FALSE;
  *out_n_columns = cols->len;
  *out_columns = (WylClientFactColumn *) g_array_free (g_steal_pointer (&cols),
      FALSE);
  return TRUE;
}

static int
run_fact_schema_register (const WyctlOptions *global_opts, gint argc,
    gchar **argv)
{
  WyctlFactSchemaOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"tenant", 0, 0, G_OPTION_ARG_STRING, &opts.tenant, "Tenant", "TENANT"},
    {"graph", 0, 0, G_OPTION_ARG_STRING, &opts.graph, "Graph", "GRAPH"},
    {"namespace", 0, 0, G_OPTION_ARG_STRING, &opts.namespace_id, "Namespace",
        "NS"},
    {"relation", 0, 0, G_OPTION_ARG_STRING, &opts.relation, "Relation",
        "REL"},
    {"schema-version", 0, 0, G_OPTION_ARG_STRING, &opts.schema_version_arg,
        "Schema version", "N"},
    {"columns", 0, 0, G_OPTION_ARG_STRING, &opts.columns_arg,
        "Columns as name:type,...", "COLUMNS"},
    {"max-rows", 0, 0, G_OPTION_ARG_STRING, &opts.max_rows_arg,
        "Maximum rows authorized for the default relation query", "N"},
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
      g_option_context_new ("- wyrelog fact schema register");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected fact schema register argument: %s\n",
        argv[1]);
    return 2;
  }
  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *tenant = wyctl_resolve_string_option (opts.tenant,
      global_opts->settings, "default-tenant");
  g_autofree gchar *graph = wyctl_resolve_string_option (opts.graph,
      global_opts->settings, "default-graph");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (graph == NULL || graph[0] == '\0' || opts.namespace_id == NULL
      || opts.namespace_id[0] == '\0' || opts.relation == NULL ||
      opts.relation[0] == '\0') {
    g_printerr ("wyctl: missing fact schema target option\n");
    return 2;
  }
  guint32 schema_version = 0;
  if (!parse_positive_uint32 (opts.schema_version_arg, &schema_version)) {
    g_printerr ("wyctl: invalid --schema-version\n");
    return 2;
  }
  guint32 max_rows = 0;
  if (opts.max_rows_arg != NULL && !parse_positive_uint32 (opts.max_rows_arg,
          &max_rows)) {
    g_printerr ("wyctl: invalid --max-rows\n");
    return 2;
  }
  WylClientFactColumn *columns = NULL;
  gsize n_columns = 0;
  if (!parse_columns_arg (opts.columns_arg, &columns, &n_columns)) {
    g_printerr ("wyctl: invalid --columns\n");
    return 2;
  }
  gint64 guard_timestamp = 0;
  gint64 guard_risk = 0;
  if (!parse_guard_options (opts.guard_timestamp_arg, opts.guard_loc_class,
          opts.guard_risk_arg, &guard_timestamp, &guard_risk)) {
    client_fact_columns_clear (columns, n_columns);
    return 2;
  }
  g_autoptr (WylClient) client = NULL;
  int client_rc = create_fact_client (daemon_url, timeout_ms_arg, tenant,
      access_token_file, &client);
  if (client_rc != 0) {
    client_fact_columns_clear (columns, n_columns);
    return client_rc;
  }
  wyrelog_error_t rc = wyl_client_fact_schema_register_with_max_rows (client,
      tenant,
      graph, opts.namespace_id, opts.relation, schema_version, columns,
      n_columns, max_rows, guard_timestamp, opts.guard_loc_class, guard_risk);
  client_fact_columns_clear (columns, n_columns);
  int exit_rc = fact_remote_exit (client, "fact schema register", rc,
      "schema_register_failed");
  if (exit_rc == 0)
    g_print ("ok\n");
  return exit_rc;
}

static gchar *
convert_csv_to_tsv (const gchar *input, gsize size)
{
  g_autoptr (GString) out = g_string_sized_new (size);
  for (gsize i = 0; i < size; i++) {
    if (input[i] == '"' || input[i] == '\t')
      return NULL;
    g_string_append_c (out, input[i] == ',' ? '\t' : input[i]);
  }
  return g_string_free (g_steal_pointer (&out), FALSE);
}

static int
run_fact_put (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlFactPutOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"tenant", 0, 0, G_OPTION_ARG_STRING, &opts.tenant, "Tenant", "TENANT"},
    {"graph", 0, 0, G_OPTION_ARG_STRING, &opts.graph, "Graph", "GRAPH"},
    {"namespace", 0, 0, G_OPTION_ARG_STRING, &opts.namespace_id, "Namespace",
        "NS"},
    {"relation", 0, 0, G_OPTION_ARG_STRING, &opts.relation, "Relation",
        "REL"},
    {"schema-version", 0, 0, G_OPTION_ARG_STRING, &opts.schema_version_arg,
        "Schema version", "N"},
    {"batch-id", 0, 0, G_OPTION_ARG_STRING, &opts.batch_id, "Batch id",
        "ID"},
    {"idempotency-key", 0, 0, G_OPTION_ARG_STRING, &opts.idempotency_key,
        "Idempotency key", "KEY"},
    {"format", 0, 0, G_OPTION_ARG_STRING, &opts.format, "Input format",
        "csv|tsv"},
    {"input", 0, 0, G_OPTION_ARG_STRING, &opts.input, "Input file", "PATH"},
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
  g_autoptr (GOptionContext) context = g_option_context_new
      ("- wyrelog fact put");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected fact put argument: %s\n", argv[1]);
    return 2;
  }
  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *tenant = wyctl_resolve_string_option (opts.tenant,
      global_opts->settings, "default-tenant");
  g_autofree gchar *graph = wyctl_resolve_string_option (opts.graph,
      global_opts->settings, "default-graph");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (graph == NULL || graph[0] == '\0' || opts.namespace_id == NULL
      || opts.namespace_id[0] == '\0' || opts.relation == NULL ||
      opts.relation[0] == '\0' || opts.batch_id == NULL ||
      opts.batch_id[0] == '\0' || opts.idempotency_key == NULL ||
      opts.idempotency_key[0] == '\0') {
    g_printerr ("wyctl: missing fact put target option\n");
    return 2;
  }
  guint32 schema_version = 0;
  if (!parse_positive_uint32 (opts.schema_version_arg, &schema_version)) {
    g_printerr ("wyctl: invalid --schema-version\n");
    return 2;
  }
  if (opts.format == NULL || (g_strcmp0 (opts.format, "csv") != 0 &&
          g_strcmp0 (opts.format, "tsv") != 0)) {
    g_printerr ("wyctl: unsupported --format\n");
    return 2;
  }
  if (opts.input == NULL || opts.input[0] == '\0') {
    g_printerr ("wyctl: missing --input\n");
    return 2;
  }
  g_autofree gchar *input = NULL;
  gsize input_size = 0;
  if (!g_file_get_contents (opts.input, &input, &input_size, &error)) {
    g_printerr ("wyctl: unable to read fact input\n");
    return 2;
  }
  g_autofree gchar *payload = NULL;
  gsize payload_size = input_size;
  if (g_strcmp0 (opts.format, "csv") == 0) {
    payload = convert_csv_to_tsv (input, input_size);
    if (payload == NULL) {
      g_printerr ("wyctl: invalid csv input\n");
      return 2;
    }
    payload_size = strlen (payload);
  } else {
    payload = g_steal_pointer (&input);
  }
  gint64 guard_timestamp = 0;
  gint64 guard_risk = 0;
  if (!parse_guard_options (opts.guard_timestamp_arg, opts.guard_loc_class,
          opts.guard_risk_arg, &guard_timestamp, &guard_risk))
    return 2;
  g_autoptr (WylClient) client = NULL;
  int client_rc = create_fact_client (daemon_url, timeout_ms_arg, tenant,
      access_token_file, &client);
  if (client_rc != 0)
    return client_rc;
  g_autoptr (WylClientFactAppendResult) result = NULL;
  wyrelog_error_t rc = wyl_client_fact_put_batch (client, tenant,
      graph, opts.namespace_id, opts.relation, schema_version,
      opts.batch_id, opts.idempotency_key, (const guint8 *) payload,
      payload_size, guard_timestamp, opts.guard_loc_class, guard_risk,
      &result);
  int exit_rc = fact_remote_exit (client, "fact put", rc,
      "fact_append_failed");
  if (exit_rc == 0)
    g_print ("%s\n", wyl_client_fact_append_result_get_inserted (result) ?
        "inserted" : "duplicate");
  return exit_rc;
}

static int
run_fact_schema (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing fact schema command\n");
    return 2;
  }
  if (g_strcmp0 (argv[1], "register") == 0)
    return run_fact_schema_register (global_opts, argc - 1, argv + 1);
  g_printerr ("wyctl: unknown fact schema command: %s\n", argv[1]);
  return 2;
}

static int
run_fact (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing fact command\n");
    return 2;
  }
  if (g_strcmp0 (argv[1], "schema") == 0)
    return run_fact_schema (global_opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "put") == 0)
    return run_fact_put (global_opts, argc - 1, argv + 1);
  g_printerr ("wyctl: unknown fact command: %s\n", argv[1]);
  return 2;
}

static gboolean
parse_query_limit (const gchar *raw, guint *out_limit)
{
  if (out_limit == NULL)
    return FALSE;
  if (raw == NULL) {
    *out_limit = 0;
    return TRUE;
  }
  if (raw[0] == '\0')
    return FALSE;
  errno = 0;
  gchar *end = NULL;
  guint64 parsed = g_ascii_strtoull (raw, &end, 10);
  if (errno != 0 || end == raw || *end != '\0' || parsed == 0 ||
      parsed > G_MAXUINT)
    return FALSE;
  *out_limit = (guint) parsed;
  return TRUE;
}

static int
run_datalog_query (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlDatalogQueryOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"tenant", 0, 0, G_OPTION_ARG_STRING, &opts.tenant, "Tenant", "TENANT"},
    {"graph", 0, 0, G_OPTION_ARG_STRING, &opts.graph, "Graph", "GRAPH"},
    {"query", 0, 0, G_OPTION_ARG_STRING, &opts.query, "Relation query",
        "ATOM"},
    {"output", 0, 0, G_OPTION_ARG_STRING, &opts.output, "Output format",
        "json"},
    {"limit", 0, 0, G_OPTION_ARG_STRING, &opts.limit_arg, "Row limit", "N"},
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
      g_option_context_new ("- wyrelog datalog query");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected datalog query argument: %s\n", argv[1]);
    return 2;
  }
  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *tenant = wyctl_resolve_string_option (opts.tenant,
      global_opts->settings, "default-tenant");
  g_autofree gchar *graph = wyctl_resolve_string_option (opts.graph,
      global_opts->settings, "default-graph");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (graph == NULL || graph[0] == '\0' || opts.query == NULL ||
      opts.query[0] == '\0') {
    g_printerr ("wyctl: missing datalog query target option\n");
    return 2;
  }
  if (opts.output != NULL && g_strcmp0 (opts.output, "json") != 0) {
    g_printerr ("wyctl: unsupported --output\n");
    return 2;
  }
  guint limit = 0;
  if (!parse_query_limit (opts.limit_arg, &limit)) {
    g_printerr ("wyctl: invalid --limit\n");
    return 2;
  }
  gint64 guard_timestamp = 0;
  gint64 guard_risk = 0;
  if (!parse_guard_options (opts.guard_timestamp_arg, opts.guard_loc_class,
          opts.guard_risk_arg, &guard_timestamp, &guard_risk))
    return 2;
  g_autoptr (WylClient) client = NULL;
  int client_rc = create_fact_client (daemon_url, timeout_ms_arg, tenant,
      access_token_file, &client);
  if (client_rc != 0)
    return client_rc;
  g_autofree gchar *json = NULL;
  wyrelog_error_t rc = wyl_client_datalog_query_json (client, tenant,
      graph, opts.query, limit, guard_timestamp, opts.guard_loc_class,
      guard_risk, &json);
  int exit_rc = fact_remote_exit (client, "datalog query", rc,
      "datalog_query_failed");
  if (exit_rc == 0)
    g_print ("%s\n", json);
  return exit_rc;
}

static int
run_datalog (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing datalog command\n");
    return 2;
  }
  if (g_strcmp0 (argv[1], "query") == 0)
    return run_datalog_query (global_opts, argc - 1, argv + 1);
  g_printerr ("wyctl: unknown datalog command: %s\n", argv[1]);
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

  g_autofree gchar *daemon_url =
      wyctl_resolve_string_option (global_opts->daemon_url,
      global_opts->settings, "daemon-url");
  g_autofree gchar *timeout_ms_arg =
      wyctl_resolve_uint_option_as_string (global_opts->timeout_ms_arg,
      global_opts->settings,
      "default-timeout-ms");
  g_autofree gchar *access_token_file =
      wyctl_resolve_string_option (opts.access_token_file,
      global_opts->settings, "access-token-file");

  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }

  guint timeout_ms = 0;
  if (!parse_timeout_ms (timeout_ms_arg, &timeout_ms)) {
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
  int token_rc = load_access_token_file (access_token_file, &access_token);
  if (token_rc != 0)
    return token_rc;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (daemon_url, &client) != WYRELOG_E_OK ||
      wyl_client_set_bearer_credentials (client, access_token,
          WYL_TENANT_DEFAULT) != WYRELOG_E_OK) {
    g_printerr ("wyctl: invalid audit credentials\n");
    return 2;
  }
  wyl_client_set_timeout_ms (client, timeout_ms);

  g_autoptr (WylAuditIter) iter = NULL;
  wyrelog_error_t query_rc = wyl_client_audit_query_with_guard_context (client,
      opts.filter, guard_timestamp, opts.guard_loc_class, guard_risk, &iter);
  if (query_rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: audit query failed\n");
    return 3;
  }

  g_autoptr (GString) json = g_string_new ("[");
  guint emitted = 0;
  gboolean has_next = FALSE;
  while (emitted < limit) {
    wyrelog_error_t next_rc = wyl_audit_iter_next (iter, &has_next);
    if (next_rc != WYRELOG_E_OK) {
      g_printerr ("wyctl: audit query failed\n");
      return 3;
    }
    if (!has_next)
      break;

    g_autoptr (WylAuditEvent) event = wyl_audit_iter_ref_event (iter);
    if (event == NULL) {
      g_printerr ("wyctl: audit query failed\n");
      return 3;
    }
    if (emitted > 0)
      g_string_append_c (json, ',');
    append_audit_event_json (json, event);
    emitted++;
  }
  g_string_append (json, "]\n");
  g_print ("%s", json->str);
  return 0;
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

/* ----------------------------------------------------------------------
 * wyctl mfa enroll / mfa reset (issue #331 commit 6).
 *
 * These two subcommands are offline operator commands: they open the
 * policy authority store directly (mirroring `wyctl key rotate'), mint
 * a fresh TOTP seed, print the otpauth URI and base32 secret to stdout,
 * prompt the operator on stdin for the current 6-digit code, and only
 * persist the enrollment row after the code verifies.  Aborts before
 * verification (EOF / wrong code) leave the store untouched.
 *
 * The bootstrap auto-revoke: when the bootstrap admin enrolls for the
 * first time, the one-shot `wr.login.skip_mfa' direct permission that
 * the daemon armed at bootstrap is retracted in the same invocation —
 * the admin has now demonstrated possession of the TOTP factor, so the
 * "skip MFA" escape hatch must close.  This is the only host that
 * retracts that permission; the daemon's verify path never does.
 *
 * Audit-event vocabulary (action column in audit_events):
 *   mfa_enrolled            - successful enrollment.  resource_id carries
 *                             the enrollment row's uuidv7 id (not the
 *                             subject), so an auditor can correlate the
 *                             audit row 1:1 with the totp_enrollments row.
 *   mfa_reset               - successful reset (delete + re-enroll).
 *                             Same resource_id convention as mfa_enrolled.
 *   mfa_skip_mfa_revoked    - one-shot bootstrap auto-revoke side-effect.
 *                             resource_id carries the SUBJECT (not the
 *                             enrollment id) to match the rest of the
 *                             direct-permission mutation audit convention:
 *                             revokes name the principal whose grant was
 *                             pulled, not the enrollment that triggered
 *                             the side-effect.
 *
 * Footgun coverage (see #331 architect / critic brief):
 *   F2: the audit row carries only subject_id and the enrollment record
 *       UUIDv7 (as resource_id) — never the seed or the otpauth URI.
 *   F4: every error path that touched the in-memory secret runs
 *       wyl_totp_enrollment_clear before bailing, which calls
 *       sodium_memzero on the 20-byte seed buffer.
 */

#define WYCTL_MFA_OTPAUTH_ISSUER "wyrelog"

/* Per RFC 3986, percent-encode anything outside the unreserved set so
 * the label and query-parameter segments parse cleanly under the
 * Google Authenticator Key URI Format.  GLib's g_uri_escape_string
 * applies RFC 3986 percent-encoding for everything outside [A-Za-z0-9]
 * + the explicit unreserved set; we pass `reserved_chars_allowed = NULL'
 * so ':' and '/' are encoded even though the URI grammar permits them
 * in some contexts. */
static gchar *
wyctl_mfa_encode_uri_segment (const gchar *raw)
{
  return g_uri_escape_string (raw, NULL, FALSE);
}

/* Build the otpauth:// URI for `subject' with the given base32 secret.
 * The issuer is "wyrelog" (hardcoded to match the brand the daemon
 * stamps elsewhere).  Returns a freshly allocated string owned by the
 * caller. */
static gchar *
wyctl_mfa_build_otpauth_uri (const gchar *subject, const gchar *base32_secret)
{
  g_autofree gchar *issuer_enc =
      wyctl_mfa_encode_uri_segment (WYCTL_MFA_OTPAUTH_ISSUER);
  g_autofree gchar *subject_enc = wyctl_mfa_encode_uri_segment (subject);
  /* The base32 alphabet is already URL-safe; emit it verbatim so the
   * operator can paste it into authenticator apps that expect the
   * canonical base32 form. */
  return g_strdup_printf
      ("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
      issuer_enc, subject_enc, base32_secret, issuer_enc);
}

/* Read a single line from stdin and parse it as a 6-digit decimal code.
 * Returns FALSE on EOF, malformed input, or a value outside [0,999999].
 * The buffer is zeroed before return to keep the typed code out of
 * heap residue. */
static gboolean
wyctl_mfa_read_six_digit_code (guint *out_code)
{
  gchar buf[64];
  if (fgets (buf, (int) sizeof buf, stdin) == NULL)
    return FALSE;
  gsize len = strlen (buf);
  while (len > 0
      && (buf[len - 1] == '\n' || buf[len - 1] == '\r'
          || buf[len - 1] == ' ' || buf[len - 1] == '\t'))
    buf[--len] = '\0';
  if (len != WYL_TOTP_DIGITS) {
    sodium_memzero (buf, sizeof buf);
    return FALSE;
  }
  for (gsize i = 0; i < len; i++) {
    if (!g_ascii_isdigit (buf[i])) {
      sodium_memzero (buf, sizeof buf);
      return FALSE;
    }
  }
  errno = 0;
  gchar *end = NULL;
  gint64 parsed = g_ascii_strtoll (buf, &end, 10);
  sodium_memzero (buf, sizeof buf);
  if (errno != 0 || end == NULL || *end != '\0' || parsed < 0
      || parsed > 999999)
    return FALSE;
  *out_code = (guint) parsed;
  return TRUE;
}

/* Open the policy store named by --store and --keyprovider.  When
 * --keyprovider is absent the store is opened unencrypted; this is the
 * code path test harnesses exercise.  Production operators must
 * provide --keyprovider; the daemon refuses to load a store written
 * unencrypted on a host that expects encryption, so this command does
 * not enforce a policy of its own. */
static wyrelog_error_t
wyctl_mfa_open_store (const WyctlMfaOptions *opts, wyl_policy_store_t **out)
{
  if (opts->keyprovider_path != NULL && opts->keyprovider_path[0] != '\0') {
    wyl_keyprovider_file_t *kp =
        wyl_keyprovider_file_new_from_spec (opts->keyprovider_path);
    if (kp == NULL)
      return WYRELOG_E_IO;
    wyl_policy_store_open_options_t open_opts = {
      .path = opts->store_path,
      .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
      .keyprovider_state = kp,
      .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
      .require_encrypted = TRUE,
    };
    return wyl_policy_store_open_with_options (&open_opts, out);
  }
  return wyl_policy_store_open (opts->store_path, out);
}

/* Common enroll flow shared by `wyctl mfa enroll' and the post-delete
 * second half of `wyctl mfa reset'.  Owns the seed buffer for the
 * entire flow and zeroes it on every exit.  Returns 0 on success or a
 * non-zero exit code that wyctl propagates up to main().
 *
 * `reset_mode' selects between the mfa_enrolled and mfa_reset audit
 * action strings; the persisted row is identical in both cases.
 */
static int
wyctl_mfa_run_enroll_flow (wyl_policy_store_t *store, const gchar *subject,
    gboolean reset_mode)
{
  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup (subject);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = (gint64) (g_get_real_time () / G_USEC_PER_SEC);

  g_autoptr (GError) error = NULL;
  wyrelog_error_t rc = wyl_totp_generate_seed (enr.secret, sizeof enr.secret,
      &error);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: totp seed generation failed: %s\n",
        wyrelog_error_string (rc));
    wyl_totp_enrollment_clear (&enr);
    return 1;
  }

  g_autofree gchar *base32_secret = NULL;
  rc = wyl_totp_base32_encode (enr.secret, sizeof enr.secret, &base32_secret,
      &error);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: base32 encode failed: %s\n", wyrelog_error_string (rc));
    wyl_totp_enrollment_clear (&enr);
    return 1;
  }

  g_autofree gchar *otpauth = wyctl_mfa_build_otpauth_uri (subject,
      base32_secret);

  /* Secret-bearing output goes to stdout in a key=value format so an
   * operator can pipe it into a parser, but the help text warns
   * against piping to logs. */
  g_print ("otpauth_uri=%s\n", otpauth);
  g_print ("secret_base32=%s\n", base32_secret);
  /* Flush so the operator (and the test harness reading stdout) sees
   * the secret before we block on stdin. */
  (void) fflush (stdout);

  /* The prompt itself is interactive UX, not machine-parsed output:
   * route it to stderr so piping stdout still leaves a visible
   * prompt. */
  g_printerr ("Enter the current 6-digit code from the authenticator app: ");
  (void) fflush (stderr);

  guint code = 0;
  if (!wyctl_mfa_read_six_digit_code (&code)) {
    g_printerr ("\nwyctl: aborted (no valid code supplied; no enrollment "
        "written)\n");
    wyl_totp_enrollment_clear (&enr);
    return 1;
  }

  gint64 now_secs = (gint64) (g_get_real_time () / G_USEC_PER_SEC);
  guint64 matched_step = 0;
  gboolean matched = wyl_totp_code_matches (enr.secret, sizeof enr.secret,
      now_secs, code, &matched_step, &error);
  if (!matched) {
    g_printerr ("wyctl: code did not match; no enrollment written\n");
    g_clear_error (&error);
    wyl_totp_enrollment_clear (&enr);
    return 1;
  }
  /* Set the replay watermark to the verified step so the daemon
   * cannot accept the same code again on the very first verify. */
  enr.last_verified_step = (gint64) matched_step;

  /* Atomicity wrapper: the post-verify happy path performs up to four
   * mutations (enrollment insert, mfa_enrolled audit row, plus the
   * bootstrap auto-revoke's direct-permission mutation and the
   * permission-state FSM transition).  Wrap them in a single outer
   * savepoint so any partial failure rolls back the entire enrollment
   * — otherwise a prefix failure could leave the bootstrap admin
   * enrolled while wr.login.skip_mfa was still armed, creating an
   * auth-bypass window until the operator re-ran enroll.
   *
   * SQLite savepoints with the same name nest as a stack: each inner
   * `SAVEPOINT wyrelog_policy_mutation' (issued by the helpers below)
   * pushes a new frame, and the matching RELEASE / ROLLBACK TO pops
   * only that inner frame, leaving our outer frame intact.  See the
   * commit-5 atomicity test for the same primitive used in
   * apply_principal_failure. */
  rc = wyl_mfa_enrollment_commit (store, &enr, subject, NULL, "wyctl",
      reset_mode);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: enrollment mutation failed: %s\n",
        wyrelog_error_string (rc));
    wyl_totp_enrollment_clear (&enr);
    return 1;
  }

  g_print ("status=enrolled subject=%s enrollment_id=%s\n", subject,
      enr.id_uuidv7);
  wyl_totp_enrollment_clear (&enr);
  return 0;
}

static int
wyctl_mfa_validate_common_options (const WyctlMfaOptions *opts)
{
  if (opts->subject == NULL || opts->subject[0] == '\0') {
    g_printerr ("wyctl: missing --subject\n");
    return 2;
  }
  if (opts->store_path == NULL || opts->store_path[0] == '\0') {
    g_printerr ("wyctl: missing --store\n");
    return 2;
  }
  return 0;
}

static gchar *
wyctl_mfa_json_string (const gchar *json, const gchar *name)
{
  g_autofree gchar *needle = g_strdup_printf ("\"%s\":\"", name);
  const gchar *start = strstr (json, needle);
  if (start == NULL)
    return NULL;
  start += strlen (needle);
  const gchar *end = strchr (start, '"');
  if (end == NULL || end == start)
    return NULL;
  return g_strndup (start, (gsize) (end - start));
}

static int
wyctl_mfa_online_post (const gchar *daemon_url, const gchar *path,
    const gchar *access_token, const gchar *json, gchar **out_body)
{
  *out_body = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  g_autofree gchar *uri = g_strdup_printf
      ("%s%s?tenant=%s&guard_timestamp=%" G_GINT64_FORMAT
      "&guard_loc_class=public&guard_risk=0", daemon_url, path,
      WYL_TENANT_DEFAULT, now);
  g_autoptr (SoupMessage) msg = soup_message_new ("POST", uri);
  if (msg == NULL)
    return 1;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
      access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);
  g_autoptr (GBytes) request = g_bytes_new (json, strlen (json));
  soup_message_set_request_body_from_bytes (msg, "application/json", request);
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) response = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (response == NULL) {
    g_printerr ("wyctl: online MFA request failed: %s\n", error->message);
    return 1;
  }
  gsize size = 0;
  gpointer raw = g_bytes_unref_to_data (g_steal_pointer (&response), &size);
  if (size > 16 * 1024) {
    if (raw != NULL)
      sodium_memzero (raw, size);
    g_free (raw);
    g_printerr ("wyctl: online MFA response exceeded size limit\n");
    return 1;
  }
  gchar *terminated = g_malloc (size + 1);
  if (size > 0)
    memcpy (terminated, raw, size);
  terminated[size] = '\0';
  if (raw != NULL)
    sodium_memzero (raw, size);
  g_free (raw);
  *out_body = terminated;
  guint status = soup_message_get_status (msg);
  if (status < 200 || status >= 300) {
    g_printerr ("wyctl: online MFA request failed (HTTP %u): %s\n", status,
        *out_body);
    return 1;
  }
  return 0;
}

static int
wyctl_mfa_run_online_enroll (const WyctlOptions *global_opts,
    const WyctlMfaOptions *opts)
{
  g_autofree gchar *daemon_url = wyctl_resolve_string_option
      (global_opts->daemon_url, global_opts->settings, "daemon-url");
  if (daemon_url == NULL || daemon_url[0] == '\0') {
    g_printerr ("wyctl: missing daemon URL\n");
    return 2;
  }
  if (!daemon_url_is_valid (daemon_url)) {
    g_printerr ("wyctl: invalid daemon URL\n");
    return 2;
  }
  g_autofree gchar *access_token = NULL;
  int rc = load_access_token_file (opts->access_token_file, &access_token);
  if (rc != 0)
    return rc;
  g_autoptr (GString) start_json = g_string_new ("{\"subject\":");
  append_json_string (start_json, opts->subject);
  g_string_append_c (start_json, '}');
  g_autoptr (WyctlSensitiveChar) start_body = NULL;
  if (wyctl_mfa_online_post (daemon_url, "/auth/mfa/enroll/start",
          access_token, start_json->str, &start_body) != 0)
    return 1;
  g_autofree gchar *challenge = wyctl_mfa_json_string (start_body,
      "challenge");
  g_autoptr (WyctlSensitiveChar) uri = wyctl_mfa_json_string (start_body,
      "otpauth_uri");
  g_autoptr (WyctlSensitiveChar) secret = wyctl_mfa_json_string (start_body,
      "secret_base32");
  if (challenge == NULL || uri == NULL || secret == NULL) {
    g_printerr ("wyctl: invalid online MFA response\n");
    return 1;
  }
  g_print ("otpauth_uri=%s\nsecret_base32=%s\n", uri, secret);
  (void) fflush (stdout);
  g_printerr ("Enter the current 6-digit code from the authenticator app: ");
  (void) fflush (stderr);
  guint code = 0;
  if (!wyctl_mfa_read_six_digit_code (&code)) {
    g_printerr ("\nwyctl: aborted (no valid code supplied)\n");
    return 1;
  }
  gchar code_text[WYL_TOTP_DIGITS + 1];
  g_snprintf (code_text, sizeof code_text, "%06u", code);
  g_autoptr (GString) confirm_json = g_string_new ("{\"challenge\":");
  append_json_string (confirm_json, challenge);
  g_string_append (confirm_json, ",\"code\":");
  append_json_string (confirm_json, code_text);
  g_string_append_c (confirm_json, '}');
  sodium_memzero (code_text, sizeof code_text);
  g_autoptr (WyctlSensitiveChar) confirm_body = NULL;
  rc = wyctl_mfa_online_post (daemon_url, "/auth/mfa/enroll/confirm",
      access_token, confirm_json->str, &confirm_body);
  sodium_memzero (confirm_json->str, confirm_json->len);
  if (rc != 0)
    return rc;
  g_print ("status=enrolled subject=%s\n", opts->subject);
  return 0;
}

static int
run_mfa_enroll (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlMfaOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"subject", 0, 0, G_OPTION_ARG_STRING, &opts.subject,
        "Principal subject id to enroll", "SUBJECT"},
    {"store", 0, 0, G_OPTION_ARG_STRING, &opts.store_path,
        "Policy store path (SQLite file)", "PATH"},
    {"keyprovider", 0, 0, G_OPTION_ARG_STRING, &opts.keyprovider_path,
        "Optional KeyProvider spec for encrypted stores", "SPEC"},
    {"access-token-file", 0, 0, G_OPTION_ARG_STRING, &opts.access_token_file,
        "Bearer token file for online enrollment", "PATH"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context = g_option_context_new
      ("- enroll a subject for TOTP MFA. Output is sensitive: do NOT pipe "
      "stdout to logs.");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected mfa enroll argument: %s\n", argv[1]);
    return 2;
  }

  /* Resolve --store and --keyprovider from CLI / GSettings (CLI wins;
   * empty falls back to the default-policy-store / default-keyprovider
   * keys). The resolved values live in the g_autofree locals; we
   * overwrite opts.store_path / opts.keyprovider_path so downstream
   * validation/open sees the resolved value. The original
   * GOptionContext-owned strings in those slots are dropped (small
   * one-shot leak absorbed at CLI tear-down — same pattern as
   * elsewhere in wyctl). */
  gboolean online = opts.access_token_file != NULL &&
      opts.access_token_file[0] != '\0';
  gboolean explicit_store = opts.store_path != NULL
      && opts.store_path[0] != '\0';
  gboolean explicit_keyprovider = opts.keyprovider_path != NULL
      && opts.keyprovider_path[0] != '\0';
  g_autofree gchar *store_path =
      online ? g_strdup (opts.
      store_path) : wyctl_resolve_string_option (opts.store_path,
      global_opts->settings,
      "default-policy-store");
  g_autofree gchar *keyprovider_path = online ?
      g_strdup (opts.keyprovider_path) :
      wyctl_resolve_string_option (opts.keyprovider_path,
      global_opts->settings, "default-keyprovider");
  opts.store_path = store_path;
  opts.keyprovider_path = keyprovider_path;

  if (online) {
    if (explicit_store || explicit_keyprovider) {
      g_printerr ("wyctl: online enrollment cannot be combined with --store "
          "or --keyprovider\n");
      return 2;
    }
    if (opts.subject == NULL || opts.subject[0] == '\0') {
      g_printerr ("wyctl: missing --subject\n");
      return 2;
    }
    return wyctl_mfa_run_online_enroll (global_opts, &opts);
  }

  int validate_rc = wyctl_mfa_validate_common_options (&opts);
  if (validate_rc != 0)
    return validate_rc;

  g_autoptr (wyl_policy_store_t) store = NULL;
  wyrelog_error_t rc = wyctl_mfa_open_store (&opts, &store);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: open store failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }
  return wyctl_mfa_run_enroll_flow (store, opts.subject, FALSE);
}

static int
run_mfa_reset (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  WyctlMfaOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"subject", 0, 0, G_OPTION_ARG_STRING, &opts.subject,
        "Principal subject id to reset", "SUBJECT"},
    {"store", 0, 0, G_OPTION_ARG_STRING, &opts.store_path,
        "Policy store path (SQLite file)", "PATH"},
    {"keyprovider", 0, 0, G_OPTION_ARG_STRING, &opts.keyprovider_path,
        "Optional KeyProvider spec for encrypted stores", "SPEC"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context = g_option_context_new
      ("- reset a subject's TOTP enrollment: deletes the prior row, then "
      "runs the enroll flow.");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected mfa reset argument: %s\n", argv[1]);
    return 2;
  }

  /* Resolve --store and --keyprovider from CLI / GSettings (CLI wins;
   * empty falls back to the default-policy-store / default-keyprovider
   * keys). The resolved values live in the g_autofree locals; we
   * overwrite opts.store_path / opts.keyprovider_path so downstream
   * validation/open sees the resolved value. The original
   * GOptionContext-owned strings in those slots are dropped (small
   * one-shot leak absorbed at CLI tear-down — same pattern as
   * elsewhere in wyctl). */
  g_autofree gchar *store_path = wyctl_resolve_string_option (opts.store_path,
      global_opts->settings, "default-policy-store");
  g_autofree gchar *keyprovider_path =
      wyctl_resolve_string_option (opts.keyprovider_path,
      global_opts->settings, "default-keyprovider");
  opts.store_path = store_path;
  opts.keyprovider_path = keyprovider_path;

  int validate_rc = wyctl_mfa_validate_common_options (&opts);
  if (validate_rc != 0)
    return validate_rc;

  g_autoptr (wyl_policy_store_t) store = NULL;
  wyrelog_error_t rc = wyctl_mfa_open_store (&opts, &store);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: open store failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }
  /* Reset semantics: delete the existing enrollment row first.  If the
   * follow-on enroll is aborted, the subject ends up unenrolled — the
   * operator was explicit about resetting and the documented contract
   * is that the prior enrollment is gone the moment they confirm. */
  rc = wyl_policy_store_totp_enrollment_delete (store, opts.subject);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: prior enrollment delete failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }
  return wyctl_mfa_run_enroll_flow (store, opts.subject, TRUE);
}

static int
run_mfa (const WyctlOptions *global_opts, gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing mfa command (enroll | reset)\n");
    return 2;
  }
  if (g_strcmp0 (argv[1], "enroll") == 0)
    return run_mfa_enroll (global_opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "reset") == 0)
    return run_mfa_reset (global_opts, argc - 1, argv + 1);

  g_printerr ("wyctl: unknown mfa command: %s\n", argv[1]);
  return 2;
}

static int
run_key_status (gint argc, gchar **argv)
{
  WyctlKeyOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"keyprovider", 0, 0, G_OPTION_ARG_STRING, &opts.keyprovider_path,
        "Policy KeyProvider spec: systemd-creds:NAME or file:PATH", "SPEC"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog key status");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected key status argument: %s\n", argv[1]);
    return 2;
  }
  if (opts.keyprovider_path == NULL || opts.keyprovider_path[0] == '\0') {
    g_printerr ("wyctl: missing --keyprovider\n");
    return 2;
  }

  g_autoptr (wyl_keyprovider_file_t) keyprovider =
      wyl_keyprovider_file_new_from_spec (opts.keyprovider_path);
  if (keyprovider == NULL) {
    g_printerr ("wyctl: keyprovider unreadable\n");
    return 1;
  }
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  if (vt->probe (keyprovider) != WYRELOG_E_OK) {
    g_printerr ("wyctl: keyprovider invalid\n");
    return 1;
  }

  g_print ("status=ready type=%s bytes=%u\n",
      wyl_keyprovider_file_get_source_name (keyprovider),
      (guint) WYCTL_KEYPROVIDER_FILE_BYTES);
  return 0;
}

static int
run_key_rotate (gint argc, gchar **argv)
{
  WyctlKeyOptions opts = { 0 };
  GOptionEntry entries[] = {
    {"store", 0, 0, G_OPTION_ARG_STRING, &opts.store_path,
        "Encrypted policy store path", "PATH"},
    {"from-keyprovider", 0, 0, G_OPTION_ARG_STRING,
        &opts.from_keyprovider_path, "Current Policy KeyProvider spec", "SPEC"},
    {"to-keyprovider", 0, 0, G_OPTION_ARG_STRING,
        &opts.to_keyprovider_path, "New Policy KeyProvider spec", "SPEC"},
    {NULL}
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GOptionContext) context =
      g_option_context_new ("- rotate encrypted policy store key material");
  g_option_context_add_main_entries (context, entries, NULL);

  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_printerr ("wyctl: %s\n", error->message);
    return 2;
  }
  if (argc > 1) {
    g_printerr ("wyctl: unexpected key rotate argument: %s\n", argv[1]);
    return 2;
  }
  if (opts.store_path == NULL || opts.store_path[0] == '\0') {
    g_printerr ("wyctl: missing --store\n");
    return 2;
  }
  if (opts.from_keyprovider_path == NULL
      || opts.from_keyprovider_path[0] == '\0') {
    g_printerr ("wyctl: missing --from-keyprovider\n");
    return 2;
  }
  if (opts.to_keyprovider_path == NULL || opts.to_keyprovider_path[0] == '\0') {
    g_printerr ("wyctl: missing --to-keyprovider\n");
    return 2;
  }

  wyl_keyprovider_file_t *from_keyprovider =
      wyl_keyprovider_file_new_from_spec (opts.from_keyprovider_path);
  if (from_keyprovider == NULL) {
    g_printerr ("wyctl: current keyprovider unreadable\n");
    return 1;
  }
  wyl_keyprovider_file_t *to_keyprovider =
      wyl_keyprovider_file_new_from_spec (opts.to_keyprovider_path);
  if (to_keyprovider == NULL) {
    wyl_keyprovider_file_free (from_keyprovider);
    g_printerr ("wyctl: new keyprovider unreadable\n");
    return 1;
  }

  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  wyl_policy_store_open_options_t old_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = from_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_open_options_t new_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = to_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  wyrelog_error_t rc = wyl_policy_store_rotate_keyprovider (opts.store_path,
      &old_opts, &new_opts);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyctl: key rotation failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }

  g_print ("status=rotated store=%s\n", opts.store_path);
  return 0;
}

static int
run_key (gint argc, gchar **argv)
{
  if (argc < 2) {
    g_printerr ("wyctl: missing key command\n");
    return 2;
  }

  if (g_strcmp0 (argv[1], "status") == 0)
    return run_key_status (argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "rotate") == 0)
    return run_key_rotate (argc - 1, argv + 1);

  g_printerr ("wyctl: unknown key command: %s\n", argv[1]);
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

  /* Open the GSettings handle once and thread it into every
   * subcommand via WyctlOptions so the resolver can supply defaults
   * for unset CLI flags. NULL when the schema is missing or the
   * operator set WYCTL_DISABLE_GSETTINGS=1; the resolver tolerates
   * that and degrades to CLI-only. */
  g_autoptr (GSettings) settings = wyctl_open_settings ();
  opts.settings = settings;

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
  if (g_strcmp0 (argv[1], "graph") == 0)
    return run_graph (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "fact") == 0)
    return run_fact (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "datalog") == 0)
    return run_datalog (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "audit") == 0)
    return run_audit (&opts, argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "key") == 0)
    return run_key (argc - 1, argv + 1);
  if (g_strcmp0 (argv[1], "mfa") == 0)
    return run_mfa (&opts, argc - 1, argv + 1);

  g_printerr ("wyctl: unknown command: %s\n", argv[1]);
  return 2;
}
