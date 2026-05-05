/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <signal.h>

#ifdef WYL_HAS_DAEMON_HTTP
#include <libsoup/soup.h>
#include <string.h>
#endif

#ifdef G_OS_UNIX
#include <glib-unix.h>
#endif

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_DEFAULT_TEMPLATE_DIR
#error "WYL_DEFAULT_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  const gchar *template_dir;
  gint listen_port;
  gboolean check_only;
  gboolean show_version;
} WylDaemonOptions;

typedef struct
{
  WylHandle *handle;
  guint64 inserted;
  guint64 removed;
  gboolean expect_effective_member;
  gint64 expected_row[3];
  gboolean matched_expected_insert;
  gboolean matched_expected_remove;
} WylDaemonRuntime;

#ifdef WYL_HAS_AUDIT
static void
emit_wirelog_effective_member_audit (WylDaemonRuntime *runtime,
    const gint64 row[3], WylDeltaKind kind)
{
  if (runtime == NULL || runtime->handle == NULL)
    return;

  g_autofree gchar *user =
      wyl_handle_dup_engine_symbol (runtime->handle, row[0]);
  g_autofree gchar *role =
      wyl_handle_dup_engine_symbol (runtime->handle, row[1]);
  g_autofree gchar *scope =
      wyl_handle_dup_engine_symbol (runtime->handle, row[2]);
  if (user == NULL || role == NULL || scope == NULL)
    return;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, user);
  wyl_audit_event_set_action (ev, "effective_member_delta");
  wyl_audit_event_set_resource_id (ev, role);
  wyl_audit_event_set_deny_reason (ev,
      kind == WYL_DELTA_INSERT ? "insert" : "remove");
  wyl_audit_event_set_deny_origin (ev, scope);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  (void) wyl_audit_emit (runtime->handle, ev);
}

static wyrelog_error_t
check_wirelog_delta_audit_rows (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result;
  if (duckdb_query (conn,
          "SELECT COUNT(*) FROM audit_events "
          "WHERE action = 'effective_member_delta' "
          "AND subject_id = 'wyrelogd-check-user' "
          "AND resource_id = 'wr.viewer' "
          "AND deny_origin = 'wyrelogd-check-scope';", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  gint64 rows = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return rows == 2 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}
#endif

static gboolean
parse_options (gint *argc, gchar ***argv, WylDaemonOptions *opts,
    GError **error)
{
  GOptionEntry entries[] = {
    {"template-dir", 0, 0, G_OPTION_ARG_STRING, &opts->template_dir,
        "Access policy template directory", "DIR"},
#ifdef WYL_HAS_DAEMON_HTTP
    {"listen-port", 0, 0, G_OPTION_ARG_INT, &opts->listen_port,
        "HTTP listen port", "PORT"},
#endif
    {"check", 0, 0, G_OPTION_ARG_NONE, &opts->check_only,
        "Load policy templates and exit", NULL},
    {"version", 0, 0, G_OPTION_ARG_NONE, &opts->show_version,
        "Print version and exit", NULL},
    {NULL}
  };

  g_autoptr (GOptionContext) context =
      g_option_context_new ("- wyrelog daemon");
  g_option_context_add_main_entries (context, entries, NULL);

  return g_option_context_parse (context, argc, argv, error);
}

static wyrelog_error_t
check_wirelog_policy_ready (WylHandle *handle)
{
  gint64 row[1];
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wr.audit.read", &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_handle_engine_contains (handle, "guarded_perm", row, 1, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

#ifdef WYL_HAS_DAEMON_HTTP
static void
healthz_handler (SoupServer *server, SoupServerMessage *msg, const char *path,
    GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;
  (void) query;
  (void) user_data;

  const gchar *body = "ok\n";
  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY, body,
      strlen (body));
}

static void
audit_events_handler (SoupServer *server, SoupServerMessage *msg,
    const char *path, GHashTable *query, gpointer user_data)
{
  (void) server;
  (void) path;

#ifdef WYL_HAS_AUDIT
  const gchar *filter = NULL;
  if (query != NULL)
    filter = g_hash_table_lookup (query, "filter");

  WylHandle *handle = user_data;
  g_autofree gchar *body = NULL;
  wyrelog_error_t rc =
      wyl_audit_conn_query_events_json (wyl_handle_get_audit_conn (handle),
      filter, &body);
  if (rc == WYRELOG_E_INVALID) {
    const gchar *error_body = "{\"error\":\"invalid_filter\"}";
    soup_server_message_set_status (msg, 400, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, error_body, strlen (error_body));
    return;
  }
  if (rc != WYRELOG_E_OK) {
    const gchar *error_body = "{\"error\":\"audit_query_failed\"}";
    soup_server_message_set_status (msg, 500, NULL);
    soup_server_message_set_response (msg, "application/json",
        SOUP_MEMORY_COPY, error_body, strlen (error_body));
    return;
  }
#else
  (void) query;
  (void) user_data;
  const gchar *body = "[]";
#endif

  soup_server_message_set_status (msg, 200, NULL);
  soup_server_message_set_response (msg, "application/json",
      SOUP_MEMORY_COPY, body, strlen (body));
}

static SoupServer *
start_http_server (const WylDaemonOptions *opts, WylHandle *handle,
    GError **error)
{
  g_return_val_if_fail (opts != NULL, NULL);
  g_return_val_if_fail (WYL_IS_HANDLE (handle), NULL);

  if (opts->listen_port < 0 || opts->listen_port > 65535) {
    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
        "listen port must be between 0 and 65535");
    return NULL;
  }

  SoupServer *server = soup_server_new (NULL, NULL);
  soup_server_add_handler (server, "/healthz", healthz_handler, NULL, NULL);
  soup_server_add_handler (server, "/audit/events", audit_events_handler,
      handle, NULL);
  if (!soup_server_listen_local (server, (guint) opts->listen_port, 0, error)) {
    g_object_unref (server);
    return NULL;
  }

  return server;
}
#endif

static wyrelog_error_t
check_policy_store_ready (WylHandle *handle)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  const gchar *tables[] = {
    "roles",
    "permissions",
    "role_permissions",
    "direct_permissions",
    "direct_permission_events",
    "principal_events",
    "principal_states",
    "session_states",
    "policy_signatures",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (tables); i++) {
    gboolean found = FALSE;
    wyrelog_error_t rc =
        wyl_policy_store_table_exists (store, tables[i], &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!found)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

static wyrelog_error_t
check_audit_sink_ready (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  gboolean found = FALSE;

  wyrelog_error_t rc =
      wyl_audit_conn_table_exists (conn, "audit_events", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_IO;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_check");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  rc = wyl_audit_emit (handle, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
#else
  (void) handle;
#endif
  return WYRELOG_E_OK;
}

static wyrelog_error_t
check_policy_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "wyrelogd-snapshot-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-snapshot-user");
  wyl_grant_req_set_action (grant, "wyrelogd.snapshot.read");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-snapshot-user");
  wyl_decide_req_set_action (decide, "wyrelogd.snapshot.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
insert_symbol_row (WylHandle *handle, const gchar *relation,
    const gchar *const *symbols, gsize ncols)
{
  gint64 row[4];

  if (ncols == 0 || ncols > G_N_ELEMENTS (row))
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < ncols; i++) {
    wyrelog_error_t rc =
        wyl_handle_intern_engine_symbol (handle, symbols[i], &row[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  return wyl_handle_engine_insert (handle, relation, row, ncols);
}

static wyrelog_error_t
check_role_permission_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "wyrelogd-role-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  rc = wyl_policy_store_upsert_role (store, "wr.snapshot-role",
      "snapshot role");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_upsert_permission (store, "wyrelogd.role.read",
      "role read", "basic");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_role_permission (store, "wr.snapshot-role",
      "wyrelogd.role.read");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_reload_engine_pair (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *member_row[] = {
    "wyrelogd-role-user",
    "wr.snapshot-role",
    session_id,
  };
  rc = insert_symbol_row (handle, "member_of", member_row,
      G_N_ELEMENTS (member_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *perm_state_row[] = {
    "wyrelogd-role-user",
    "wyrelogd.role.read",
    session_id,
    "armed",
  };
  rc = insert_symbol_row (handle, "perm_state", perm_state_row,
      G_N_ELEMENTS (perm_state_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-role-user");
  wyl_decide_req_set_action (decide, "wyrelogd.role.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
emit_daemon_start_event (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_start");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return wyl_audit_emit (handle, ev);
#else
  (void) handle;
  return WYRELOG_E_OK;
#endif
}

static void
daemon_delta_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  WylDaemonRuntime *runtime = user_data;

  if (runtime == NULL)
    return;
  if (kind == WYL_DELTA_INSERT) {
    runtime->inserted++;
  } else if (kind == WYL_DELTA_REMOVE) {
    runtime->removed++;
  }

  if (g_strcmp0 (relation, "effective_member") != 0)
    return;
  if ((kind != WYL_DELTA_INSERT && kind != WYL_DELTA_REMOVE) || ncols != 3)
    return;

#ifdef WYL_HAS_AUDIT
  emit_wirelog_effective_member_audit (runtime, row, kind);
#endif

  if (!runtime->expect_effective_member)
    return;
  if (row[0] == runtime->expected_row[0]
      && row[1] == runtime->expected_row[1]
      && row[2] == runtime->expected_row[2]) {
    if (kind == WYL_DELTA_INSERT)
      runtime->matched_expected_insert = TRUE;
    else if (kind == WYL_DELTA_REMOVE)
      runtime->matched_expected_remove = TRUE;
  }
}

static wyrelog_error_t
start_wirelog_delta_callbacks (WylHandle *handle, WylDaemonRuntime *runtime)
{
  return wyl_handle_engine_set_delta_callback (handle, daemon_delta_cb,
      runtime);
}

static wyrelog_error_t
check_wirelog_delta_ready (WylHandle *handle)
{
  WylDaemonRuntime runtime = {
    .handle = handle,
    .expect_effective_member = TRUE,
  };

  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, "wyrelogd-check-user",
      &runtime.expected_row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "wr.viewer",
      &runtime.expected_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, "wyrelogd-check-scope",
      &runtime.expected_row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = start_wirelog_delta_callbacks (handle, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_engine_insert (handle, "member_of", runtime.expected_row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (runtime.inserted == 0 || !runtime.matched_expected_insert)
    return WYRELOG_E_POLICY;
  rc = wyl_handle_engine_remove (handle, "member_of", runtime.expected_row, 3);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (runtime.removed == 0 || !runtime.matched_expected_remove)
    return WYRELOG_E_POLICY;
#ifdef WYL_HAS_AUDIT
  rc = check_wirelog_delta_audit_rows (handle);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  return wyl_handle_engine_set_delta_callback (handle, NULL, NULL);
}

#ifdef G_OS_UNIX
static gboolean
quit_loop_from_signal (gpointer user_data)
{
  GMainLoop *loop = user_data;

  g_main_loop_quit (loop);
  return G_SOURCE_CONTINUE;
}

static void
install_signal_handlers (GMainLoop *loop, guint *sigint_id, guint *sigterm_id)
{
  *sigint_id = g_unix_signal_add (SIGINT, quit_loop_from_signal, loop);
  *sigterm_id = g_unix_signal_add (SIGTERM, quit_loop_from_signal, loop);
}

static void
remove_signal_handler (guint *source_id)
{
  if (*source_id != 0) {
    g_source_remove (*source_id);
    *source_id = 0;
  }
}
#else
static void
install_signal_handlers (GMainLoop *loop, guint *sigint_id, guint *sigterm_id)
{
  (void) loop;
  *sigint_id = 0;
  *sigterm_id = 0;
}

static void
remove_signal_handler (guint *source_id)
{
  (void) source_id;
}
#endif

int
main (int argc, char **argv)
{
  WylDaemonOptions opts = {
    .template_dir = WYL_DEFAULT_TEMPLATE_DIR,
    .listen_port = 8765,
  };
  g_autoptr (GError) error = NULL;

  if (!parse_options (&argc, &argv, &opts, &error)) {
    g_printerr ("wyrelogd: %s\n", error->message);
    return 2;
  }

  if (opts.show_version) {
    g_print ("%s\n", wyrelog_version_string ());
    return 0;
  }

  g_autoptr (WylHandle) handle = NULL;
  wyrelog_error_t rc = wyl_init (opts.template_dir, &handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: init failed: %s\n", wyrelog_error_string (rc));
    return 1;
  }

  if (opts.check_only) {
    rc = check_wirelog_delta_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: delta readiness check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    rc = check_wirelog_policy_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: policy readiness check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    rc = check_policy_store_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: policy store readiness check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    rc = check_policy_snapshot_reload_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: policy snapshot reload check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    rc = check_role_permission_snapshot_reload_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: role permission reload check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    rc = check_audit_sink_ready (handle);
    if (rc != WYRELOG_E_OK) {
      g_printerr ("wyrelogd: audit readiness check failed: %s\n",
          wyrelog_error_string (rc));
      return 1;
    }
    return 0;
  }

  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  rc = start_wirelog_delta_callbacks (handle, &runtime);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: delta callback setup failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }
  rc = emit_daemon_start_event (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: audit start event failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
#ifdef WYL_HAS_DAEMON_HTTP
  g_autoptr (SoupServer) server = start_http_server (&opts, handle, &error);
  if (server == NULL) {
    g_printerr ("wyrelogd: listen failed: %s\n", error->message);
    return 1;
  }
#endif

  guint sigint_id = 0;
  guint sigterm_id = 0;
  install_signal_handlers (loop, &sigint_id, &sigterm_id);
  g_main_loop_run (loop);
#ifdef WYL_HAS_DAEMON_HTTP
  soup_server_disconnect (server);
#endif
  remove_signal_handler (&sigterm_id);
  remove_signal_handler (&sigint_id);
  return 0;
}
