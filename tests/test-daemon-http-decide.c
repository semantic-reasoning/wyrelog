/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <string.h>
#include <stdio.h>
#ifndef _WIN32
#include <stdlib.h>
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#ifdef WYL_HAS_AUDIT
#include <duckdb.h>
#endif

#include "daemon/delta.h"
#include "daemon/auth-registry-private.h"
#include "daemon/http.h"
#include "wyrelog/auth/jwt-private.h"
#include "wyrelog/auth/totp.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/auth/service-credential-private.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-request-id-private.h"
#include "wyrelog/wyl-session-private.h"
#include "daemon/service-credential-handoff-private.h"
#include "../wyrelog/wyctl/wyctl-publication-private.h"
#include "test-service-credential-operation-root.h"
#ifdef WYL_HAS_FACT_STORE
#include "wyrelog/auth/service-credential-operation-coordinator-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/auth/service-credential-operation-storage-private.h"
#endif
#ifdef WYL_TEST_DAEMON_HTTP_SEED_HELPER_DSO
#include "test-daemon-http-decide-seed-helper.h"
#endif

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/* Far-future (year 2100) credential expiry for contract seeds.  The numeric
 * form types the guint64 expires_at_us argument; the string form seeds the
 * same value inside JSON request bodies. */
#define CONTRACT_FUTURE_EXPIRES_AT_US G_GUINT64_CONSTANT (4102444800000000)
#define CONTRACT_FUTURE_EXPIRES_AT_US_STR "4102444800000000"

static gboolean policy_write_fault_snapshot_is_clean
    (const WylDaemonPolicyWriteFinalizeSnapshot * snapshot,
    guint expected_primary_status, const gchar * expected_primary_code,
    guint expected_owner, const gchar * expected_owner_name,
    guint expected_cleanup_resources, guint expected_diagnostic_count,
    wyrelog_error_t expected_cleanup_rc, guint expected_acquire_fault_hits);

typedef struct
{
  GMutex mutex;
  GCond changed;
  guint started;
} RefreshThreadBarrier;

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

/* Credential issuance seals its CVK and consequently requires an owned
 * keyprovider.  Most daemon HTTP variants deliberately use wyl_init()'s
 * providerless in-memory store, but the fact-store service variant exercises
 * reconcile responses for real issue/rotate operations and the escrow-backed
 * service-principal contract test opens an encrypted store to issue and rotate
 * real credentials.  The fixture references only GLib symbols, so it lives
 * outside the WYL_HAS_FACT_STORE guard and is available in every SERVICE
 * build. */
typedef struct
{
  gchar *dir;
  gchar *policy_path;
  gchar *key_path;
  gchar *key_spec;
  gchar *audit_path;
} ServiceCredentialStoreFixture;

static void
service_credential_store_fixture_clear (ServiceCredentialStoreFixture *fixture)
{
  if (fixture == NULL)
    return;
  if (fixture->policy_path != NULL) {
    (void) g_remove (fixture->policy_path);
    g_autofree gchar *clear = g_strdup_printf ("%s.wyrelog-clear",
            fixture->policy_path);
    g_autofree gchar *lock = g_strdup_printf ("%s.wyrelog-lock",
            fixture->policy_path);
    (void) g_remove (clear);
    (void) g_remove (lock);
  }
  if (fixture->audit_path != NULL)
    (void) g_remove (fixture->audit_path);
  if (fixture->key_path != NULL)
    (void) g_remove (fixture->key_path);
  if (fixture->dir != NULL)
    (void) g_rmdir (fixture->dir);
  g_clear_pointer (&fixture->audit_path, g_free);
  g_clear_pointer (&fixture->key_spec, g_free);
  g_clear_pointer (&fixture->key_path, g_free);
  g_clear_pointer (&fixture->policy_path, g_free);
  g_clear_pointer (&fixture->dir, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (ServiceCredentialStoreFixture,
    service_credential_store_fixture_clear);

static gboolean
service_credential_store_fixture_init (ServiceCredentialStoreFixture *fixture)
{
  guint8 key[32];

  memset (fixture, 0, sizeof *fixture);
  fixture->dir = g_dir_make_tmp ("wyl-daemon-http-service-XXXXXX", NULL);
  if (fixture->dir == NULL)
    return FALSE;
  fixture->policy_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  if (fixture->policy_path == NULL || fixture->key_path == NULL
      || fixture->audit_path == NULL)
    return FALSE;
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  if (!g_file_set_contents (fixture->key_path, (const gchar *) key,
      sizeof key, NULL))
    return FALSE;
  fixture->key_spec = g_strdup_printf ("file:%s", fixture->key_path);
  return fixture->key_spec != NULL;
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean ready;
} MainLoopReadyBarrier;

#define POLICY_WRITE_TEST_WAIT_TIMEOUT_US (30 * G_TIME_SPAN_SECOND)

typedef struct
{
  GMutex mutex;
  GCond changed;
  SoupServer *server;
  WylHandle *handle;
  gboolean write_entered;
  gboolean close_entered;
  gboolean close_observed;
  gboolean allow_write;
  wyrelog_error_t write_rc;
  wyrelog_error_t shutdown_rc;
} DaemonPolicyShutdownRace;

static void
daemon_policy_write_checkpoint (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  g_mutex_lock (&race->mutex);
  race->write_entered = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->allow_write)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);
}

static void
daemon_policy_close_checkpoint (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_service_auth_authority_snapshot
    (wyl_handle_get_service_auth_authority (race->handle), &snapshot);
  g_mutex_lock (&race->mutex);
  race->close_observed = snapshot.closing;
  race->close_entered = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

static gpointer
daemon_policy_write_thread (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  race->write_rc = wyl_daemon_http_policy_write_for_test (race->server,
          daemon_policy_write_checkpoint, race);
  return NULL;
}

static gpointer
daemon_policy_shutdown_thread (gpointer data)
{
  DaemonPolicyShutdownRace *race = data;
  race->shutdown_rc = wyl_handle_shutdown_ordered (race->handle);
  return NULL;
}

static gint
check_daemon_policy_write_shutdown_contract (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1900;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts,
          handle, &error);
  if (server == NULL)
    return 1901;

  DaemonPolicyShutdownRace race = {
    .server = server,
    .handle = handle,
    .write_rc = WYRELOG_E_INTERNAL,
    .shutdown_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("daemon-policy-write",
          daemon_policy_write_thread, &race);
  g_mutex_lock (&race.mutex);
  while (!race.write_entered)
    g_cond_wait (&race.changed, &race.mutex);
  g_mutex_unlock (&race.mutex);

  WylServiceAuthAuthority *authority =
      wyl_handle_get_service_auth_authority (handle);
  wyl_service_auth_authority_set_close_checkpoint (authority,
      daemon_policy_close_checkpoint, &race);
  g_autoptr (GThread) shutdown = g_thread_new ("daemon-policy-shutdown",
          daemon_policy_shutdown_thread, &race);
  gint64 close_deadline =
      g_get_monotonic_time () + POLICY_WRITE_TEST_WAIT_TIMEOUT_US;
  g_mutex_lock (&race.mutex);
  while (!race.close_entered
      && g_cond_wait_until (&race.changed, &race.mutex, close_deadline))
    ;
  gboolean close_seen = race.close_entered;
  gboolean store_was_live = wyl_handle_get_policy_store (handle) != NULL;
  race.allow_write = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  g_thread_join (g_steal_pointer (&shutdown));
  if (!close_seen) {
    g_printerr ("WYRELOG_TEST_DIAG policy_write_shutdown_contract "
        "close_entered timed out after %ds\n",
        (gint) (POLICY_WRITE_TEST_WAIT_TIMEOUT_US / G_TIME_SPAN_SECOND));
    g_cond_clear (&race.changed);
    g_mutex_clear (&race.mutex);
    soup_server_disconnect (server);
    return 1899;
  }
  gint rc = race.close_observed ? 0 : 1902;
  if (rc == 0 && !store_was_live)
    rc = 1903;
  if (rc == 0 && race.write_rc != WYRELOG_E_OK)
    rc = 1904;
  if (rc == 0 && race.shutdown_rc != WYRELOG_E_OK)
    rc = 1905;
  if (rc == 0 && wyl_handle_get_policy_store (handle) != NULL)
    rc = 1906;
  if (rc == 0 && wyl_handle_shutdown_ordered (handle) != WYRELOG_E_OK)
    rc = 1907;
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  soup_server_disconnect (server);
  return rc;
}

static gint
check_daemon_policy_write_finalize_case (WylDaemonPolicyWriteFinalizeFault
    fault, wyrelog_error_t expected, gint base_error)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return base_error;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts,
          handle, &error);
  if (server == NULL)
    return base_error + 1;

  wyl_daemon_http_fail_next_policy_write_finalize_for_test (server, fault);
  guint before = wyl_daemon_http_policy_write_terminal_entries_for_test
        (server);
  wyrelog_error_t rc = wyl_daemon_http_policy_write_for_test (server, NULL,
          NULL);
  guint after = wyl_daemon_http_policy_write_terminal_entries_for_test (server);
  if (rc != expected)
    return base_error + 2;
  if (after != before + 1)
    return base_error + 3;

  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  if (snapshot.writer_active || snapshot.active_readers != 0
      || snapshot.waiting_readers != 0 || snapshot.waiting_writers != 0)
    return base_error + 4;
  guint total_pins = G_MAXUINT;
  guint thread_pins = G_MAXUINT;
  wyl_handle_policy_store_pin_snapshot_for_test (handle, &total_pins,
      &thread_pins);
  if (total_pins != 0 || thread_pins != 0)
    return base_error + 5;

  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  wyrelog_error_t available = wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason);
  if (fault == WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_NONE) {
    if (available != WYRELOG_E_OK
        || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE)
      return base_error + 6;
  } else {
    if (available != WYRELOG_E_BUSY
        || reason != WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT)
      return base_error + 7;
    if (wyl_daemon_http_policy_write_for_test (server, NULL, NULL)
        != WYRELOG_E_BUSY)
      return base_error + 8;
    if (wyl_daemon_http_policy_write_terminal_entries_for_test (server)
        != after)
      return base_error + 9;
  }
  if (wyl_handle_shutdown_ordered (handle) != WYRELOG_E_OK)
    return base_error + 10;
  soup_server_disconnect (server);
  return 0;
}

static gint
check_daemon_policy_write_finalize_contract (void)
{
  gint rc = check_daemon_policy_write_finalize_case
        (WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_NONE, WYRELOG_E_OK, 1910);
  if (rc != 0)
    return rc;
  rc = check_daemon_policy_write_finalize_case
        (WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION,
          WYRELOG_E_INTERNAL, 1930);
  if (rc != 0)
    return rc;
  rc = check_daemon_policy_write_finalize_case
        (WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_RANK_AFTER_POP,
          WYRELOG_E_INTERNAL, 1950);
  if (rc != 0)
    return rc;
  return check_daemon_policy_write_finalize_case
           (WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PIN_IDENTITY,
             WYRELOG_E_INVALID, 1970);
}

typedef struct
{
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  const gchar *request_id;
  gboolean check_decision;
  wyl_decision_t decision;
  guint matches;
} AuditEventProbe;

typedef struct
{
  const gchar *subject_id;
  const gchar *perm_id;
  const gchar *scope;
  const gchar *state;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PermissionStateProbe;

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t audit_event_probe_cb (const gchar * id,
    gint64 created_at_us, const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, const gchar * request_id,
    wyl_decision_t decision, gpointer user_data);
#endif

static gboolean
is_request_id_shape (const gchar *request_id)
{
  if (request_id == NULL || strlen (request_id) != WYL_REQUEST_ID_STRING_LEN)
    return FALSE;
  for (gsize i = 0; i < WYL_REQUEST_ID_STRING_LEN; i++) {
    if (!g_ascii_isalnum (request_id[i]))
      return FALSE;
  }
  return TRUE;
}

static gint
check_response_request_id_header (SoupMessage *msg, gint failure_code)
{
  const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
  if (!is_request_id_shape (request_id))
    return failure_code;
  return 0;
}

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;

  g_main_loop_run (http->loop);
  return NULL;
}

/* Like test_http_server_thread, but binds the loop's context as the
 * thread-default for the duration of the run. A SoupServer created on a
 * non-default GMainContext attaches each accepted connection's I/O to the
 * thread-default context in effect on the thread that drives the loop; if
 * that thread leaves the global-default context in place, the connection is
 * serviced by a context nobody iterates and the request stalls until the
 * client times out. */
static gpointer
test_http_server_thread_ctx (gpointer data)
{
  TestHttpServer *http = data;
  GMainContext *context = g_main_loop_get_context (http->loop);

  g_main_context_push_thread_default (context);
  g_main_loop_run (http->loop);
  g_main_context_pop_thread_default (context);
  return NULL;
}

static gboolean
mark_main_loop_ready (gpointer data)
{
  MainLoopReadyBarrier *barrier = data;

  g_mutex_lock (&barrier->mutex);
  barrier->ready = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
  return G_SOURCE_REMOVE;
}

static wyrelog_error_t
intern_symbol (WylEngineSession *session, const gchar *symbol, gint64 *out_id)
{
  return wyl_engine_session_intern_symbol (session, symbol, out_id);
}

static wyrelog_error_t
insert_symbol_row1 (WylHandle *handle, const gchar *relation,
    const gchar *value)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  gint64 row[1];
  wyrelog_error_t rc = intern_symbol (session, value, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_session_insert (session, relation, row, 1);
}

static wyrelog_error_t
insert_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (session, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_session_insert (session, relation, row, 2);
}

static wyrelog_error_t
insert_symbol_row3 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (session, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_session_insert (session, relation, row, 3);
}

static wyrelog_error_t
insert_symbol_row4 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c, const gchar *d)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_INVALID;
  gint64 row[4];
  wyrelog_error_t rc = intern_symbol (session, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (session, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_engine_session_insert (session, relation, row, 4);
}

static wyrelog_error_t
insert_allow_fixture (WylHandle *handle)
{
  const gchar *subject = "http-allow-user";
  const gchar *action = "http.allow";
  const gchar *resource = "http-allow-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-decide-role",
          action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-decide-role",
          resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row1 (handle, "session_active", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row4 (handle, "perm_state", subject, action, resource,
             "armed");
}

static wyrelog_error_t
insert_not_armed_fixture (WylHandle *handle)
{
  const gchar *subject = "http-deny-user";
  const gchar *action = "http.not_armed";
  const gchar *resource = "http-deny-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-deny-role",
          action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-deny-role",
          resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static wyrelog_error_t
insert_guarded_fixture (WylHandle *handle)
{
  const gchar *subject = "http-guard-user";
  const gchar *action = "wr.audit.read";
  const gchar *resource = "http-guard-scope";

  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-guard-role",
          action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.http-guard-role",
          resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static gchar *
build_decide_uri (const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query)
{
  g_autofree gchar *base = g_strdup (base_url);
  while (base[0] != '\0' && g_str_has_suffix (base, "/"))
    base[strlen (base) - 1] = '\0';
  g_autofree gchar *escaped_user = g_uri_escape_string (user, NULL, TRUE);
  g_autofree gchar *escaped_perm = g_uri_escape_string (perm, NULL, TRUE);
  g_autofree gchar *escaped_scope = g_uri_escape_string (scope, NULL, TRUE);

  return g_strdup_printf ("%s/decide?user=%s&perm=%s&session_token=%s%s%s",
             base, escaped_user, escaped_perm, escaped_scope,
             extra_query != NULL ? "&" : "", extra_query != NULL ? extra_query : "");
}

static gint
send_raw_path_probe (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *authorization,
    const gchar *request_body, guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 1900;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  g_autofree gchar *uri = g_strdup_printf ("%s%s", root, path);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1901;
  if (authorization != NULL) {
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "Authorization", authorization);
  }
  if (request_body != NULL) {
    g_autoptr (GBytes) request_bytes = g_bytes_new_static (request_body,
            strlen (request_body));
    soup_message_set_request_body_from_bytes (msg, "application/json",
        request_bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 1902;
  gint rc = check_response_request_id_header (msg, 1903);
  if (rc != 0)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (bytes, &body_size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (body_data, body_size);
  return 0;
}

static gint
send_raw_path (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, guint *out_status,
    gchar **out_body)
{
  return send_raw_path_probe (session, method, base_url, path, NULL, NULL,
             out_status, out_body);
}

static gint
check_read_only_method_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (send_raw_path (session, "POST", base_url, "/healthz", &status, &body)
      != 0)
    return 550;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 551;
  g_clear_pointer (&body, g_free);

  if (send_raw_path (session, "POST", base_url, "/readyz", &status, &body)
      != 0)
    return 552;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 553;
  g_clear_pointer (&body, g_free);

  if (send_raw_path (session, "POST", base_url, "/facts/status", &status,
      &body) != 0)
    return 554;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 555;
  g_clear_pointer (&body, g_free);

  if (send_raw_path (session, "POST", base_url, "/profile/status", &status,
      &body) != 0)
    return 556;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 557;
  g_clear_pointer (&body, g_free);

  if (send_raw_path (session, "POST", base_url, "/audit/events", &status,
      &body) != 0)
    return 558;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 559;
#ifndef WYL_HAS_AUDIT
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/audit/events", &status,
      &body) != 0)
    return 560;
  if (status != 200 || g_strcmp0 (body, "[]") != 0)
    return 561;
#endif

  return 0;
}

/*
 * Regression for the service-management HTTP dispatch routing bug. libsoup
 * 3.x delivers the full request path (including the registered prefix) to
 * soup_server_add_handler callbacks, so the service-principal and
 * service-credential dispatchers must strip their own route prefix before
 * delegating to the sub-handlers that expect the stripped remainder.
 *
 * Before the fix the base GET /service-principals request never matched the
 * dispatcher base check and fell through to a 404
 * invalid_service_principal_request, and a bare POST /service-credentials was
 * misrouted to the single-credential get handler, which answered 405. Prove
 * both dispatchers now route the base path to the correct handler.
 */
static gint
check_service_management_route_prefix_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  /*
   * GET /service-principals must reach the list handler, which then rejects
   * the unauthenticated request with 401 service_principal_auth_required,
   * rather than the pre-strip 404 dispatcher fall-through.
   */
  if (send_raw_path (session, "GET", base_url, "/service-principals",
      &status, &body) != 0)
    return 2200;
  if (status != 401
      || strstr (body, "\"service_principal_auth_required\"") == NULL)
    return 2201;
  g_clear_pointer (&body, g_free);

  /*
   * A bare POST /service-credentials has no canonical template and must be
   * rejected by the path classifier with the generic 404 before method or
   * terminal-handler selection.
   */
  if (send_raw_path (session, "POST", base_url, "/service-credentials",
      &status, &body) != 0)
    return 2202;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return 2203;
  g_clear_pointer (&body, g_free);

  /*
   * Sub-path coverage: the strip must map each dispatcher's own trailing-slash
   * prefix ("/service-credentials/", "/service-principals/") to the bare "/"
   * remainder so the base check fires, instead of leaking the full path to a
   * sub-handler. This exercises the strip's rest[0] == '/' branch, distinct
   * from the bare-prefix (rest[0] == '\0') cases proven above.
   *
   * GET /service-credentials/ is a trailing alias, not a credential item, and
   * must return the generic path-shape 404 before authentication.
   */
  if (send_raw_path (session, "GET", base_url, "/service-credentials/",
      &status, &body) != 0)
    return 2204;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return 2205;
  g_clear_pointer (&body, g_free);

  /*
   * Sub-path coverage: a real two-segment sub-route. The disable handler is
   * the one service sub-handler that parses the path before authenticating,
   * so it is the sub-route whose remainder mis-parse is observable without an
   * authenticated store fixture. POST /service-principals/{subject}/disable
   * must strip to /{subject}/disable, parse the "/disable" tail, then reject
   * the unauthenticated request with 401 service_principal_auth_required.
   * Pre-strip the handler saw /service-principals/{subject}/disable, whose
   * first '/' tail is "/{subject}/disable" != "/disable", so it returned 400
   * invalid_service_principal_request before ever reaching auth.
   */
  if (send_raw_path (session, "POST", base_url,
      "/service-principals/svc-alpha/disable", &status, &body) != 0)
    return 2206;
  if (status != 401
      || strstr (body, "\"service_principal_auth_required\"") == NULL)
    return 2207;
  g_clear_pointer (&body, g_free);

  /*
   * GET /service-principals/ is not the canonical collection path. It must be
   * classified as a trailing alias and return generic 404 before auth.
   */
  if (send_raw_path (session, "GET", base_url, "/service-principals/",
      &status, &body) != 0)
    return 2208;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return 2209;

  return 0;
}

typedef struct
{
  const gchar *method;
  const gchar *canonical_path;
  guint canonical_status;
  const gchar *canonical_error;
  const gchar *alias_path;
} ServiceRouteShapeCase;

/* Drive every enabled Service Credential method/template through the real
 * Soup listener.  Canonical wrong methods must stop at 405; canonical allowed
 * methods must reach their existing semantic/authentication contract; and a
 * malformed shape must remain the same generic 404 despite changing method,
 * Authorization, query, and body inputs. */
static gint
check_service_route_shape_matrix (const gchar *base_url)
{
  static const ServiceRouteShapeCase cases[] = {
    {"POST", "/service-principals", 401,
     "service_principal_auth_required", "/service-principals/"},
    {"GET", "/service-principals", 401,
     "service_principal_auth_required", "/service-principals//"},
    {"POST", "/service-principals/svc:shape:worker/disable", 401,
     "service_principal_auth_required",
     "/service-principals//disable?tenant=invalid"},
    {"POST", "/service-principals/svc:shape:worker/credentials", 401,
     "service_credential_auth_required",
     "/service-principals/svc:shape:worker/credentials/x"},
    {"GET", "/service-principals/svc:shape:worker/credentials", 401,
     "service_credential_auth_required",
     "/service-principals/svc:shape/worker/credentials"},
    {"GET", "/service-credentials/wlc_000000000000000000000000000", 401,
     "service_credential_auth_required", "/service-credentials/item/"},
    {"POST", "/service-credentials/wlc_000000000000000000000000000/rotate",
     401, "service_credential_auth_required",
     "/service-credentials/item/part/rotate"},
    {"DELETE", "/service-credentials/wlc_000000000000000000000000000",
     401, "service_credential_auth_required",
     "/service-credentials/item/rotate/x"},
#ifdef WYL_HAS_AUDIT
    {"POST", "/auth/service-token", 400, "invalid_service_token_request",
     "/auth/service-token/x?tenant=invalid"},
#endif
#ifdef WYL_HAS_FACT_STORE
    {"GET", "/service-credential-operations", 401,
     "service_credential_operation_status_auth_required",
     "/service-credential-operations/"},
    {"POST", "/service-credential-operations/reconcile", 401,
     "service_credential_operation_reconcile_auth_required",
     "/service-credential-operations/reconcile/x"},
    {"POST", "/service-credential-operations/recover", 401,
     "service_credential_operation_recover_auth_required",
     "/service-credential-operations/recover/"},
#endif
  };
#if defined(WYL_HAS_AUDIT) && defined(WYL_HAS_FACT_STORE)
  const gsize expected_count = 12;
#elif defined(WYL_HAS_FACT_STORE)
  const gsize expected_count = 11;
#elif defined(WYL_HAS_AUDIT)
  const gsize expected_count = 9;
#else
  const gsize expected_count = 8;
#endif
  if (G_N_ELEMENTS (cases) != expected_count)
    return 2210;

  g_autoptr (SoupSession) session = soup_session_new ();
  const gchar *generic_not_found = "{\"error\":\"not_found\"}";
  const gchar *poison_body =
      "{\"credential_secret\":\"must-not-be-parsed\",\"version\":false}";
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    const ServiceRouteShapeCase *test = &cases[i];
    guint status = 0;
    g_autofree gchar *body = NULL;

    if (send_raw_path_probe (session, "PATCH", base_url,
        test->canonical_path, "Bearer malformed-control", poison_body,
        &status, &body) != 0
        || status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
      return 2211 + (gint) i *4;

    g_clear_pointer (&body, g_free);
    if (send_raw_path (session, test->method, base_url, test->canonical_path,
        &status, &body) != 0
        || status != test->canonical_status
        || strstr (body, test->canonical_error) == NULL)
      return 2212 + (gint) i *4;

    g_clear_pointer (&body, g_free);
    if (send_raw_path_probe (session, test->method, base_url,
        test->alias_path, "Bearer malformed-alias", poison_body,
        &status, &body) != 0
        || status != 404 || g_strcmp0 (body, generic_not_found) != 0)
      return 2213 + (gint) i *4;

    g_clear_pointer (&body, g_free);
    if (send_raw_path_probe (session, "PATCH", base_url, test->alias_path,
        NULL, NULL, &status, &body) != 0
        || status != 404 || g_strcmp0 (body, generic_not_found) != 0)
      return 2214 + (gint) i *4;
  }

  /* Explicit suffix collisions complement the per-template trailing, deeper,
   * and doubled-separator cases above. */
  static const gchar *suffix_collisions[] = {
    "/service-principals/svc:shape:worker/credentialsx",
    "/service-principals/svc:shape:worker/disablex",
    "/service-credentials/item/rotatex",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (suffix_collisions); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_path_probe (session, "POST", base_url,
        suffix_collisions[i], "Bearer malformed-suffix", poison_body,
        &status, &body) != 0
        || status != 404 || g_strcmp0 (body, generic_not_found) != 0)
      return 2260 + (gint) i;
  }

  /* libsoup must not turn an encoded separator into authority for a path the
   * caller did not spell canonically. Cover encoded trailing, doubled,
   * deeper, and suffix-collision shapes through the real URI parser. Ordinary
   * percent normalization of unreserved bytes is intentionally out of scope. */
  static const gchar *encoded_separator_aliases[] = {
    "/service-management-authority/arm%2Fx",
    "/service-principals%2F",
    "/service-principals%2F%2Fdisable",
    "/service-principals/svc:shape%2Fworker/disable",
    "/service-principals/svc:shape:worker/credentials%2Fx",
    "/service-principals/svc:shape:worker%2Fcredentialsx",
    "/service-credentials/item%2Fpart%2Frotate",
    "/service-credentials/item%2Frotate%2Fx",
    "/service-credentials/item%2Frotatex",
#ifdef WYL_HAS_AUDIT
    "/auth/service-token%2Fx",
#endif
#ifdef WYL_HAS_FACT_STORE
    "/service-credential-operations%2F",
    "/service-credential-operations/reconcile%2Fx",
    "/service-credential-operations/recover%2F",
#endif
  };
  for (gsize i = 0; i < G_N_ELEMENTS (encoded_separator_aliases); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_path_probe (session, "POST", base_url,
        encoded_separator_aliases[i], "Bearer encoded-separator",
        poison_body, &status, &body) != 0
        || status != 404 || g_strcmp0 (body, generic_not_found) != 0)
      return 2263 + (gint) i;
  }
  return 0;
}

static gint
check_exact_route_shape (SoupServer *server, const gchar *base_url,
    const gchar *canonical_path, guint canonical_method_status, gint error_base)
{
  WylDaemonExactRouteProbeSnapshot before = { 0 };
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      canonical_path, &before))
    return error_base;
  g_autoptr (SoupSession) session = soup_session_new ();
  const gchar *poison = "{\"mutation\":\"must-not-run\"}";
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_path_probe (session, "PATCH", base_url, canonical_path,
      "Bearer exact-route-poison", poison, &status, &body) != 0
      || status != canonical_method_status)
    return error_base + 1;
  WylDaemonExactRouteProbeSnapshot after = { 0 };
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      canonical_path, &after)
      || after.selected != before.selected + 1
      || after.terminal_entries != before.terminal_entries + 1)
    return error_base + 2;

  g_autofree gchar *trailing = g_strconcat (canonical_path, "/", NULL);
  before = after;
  WylDaemonExactRouteStateSnapshot state_before = { 0 };
  WylDaemonExactRouteStateSnapshot state_after = { 0 };
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_before))
    return error_base + 3;
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "PATCH", base_url, trailing,
      "Bearer exact-route-poison", poison, &status, &body) != 0
      || status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return error_base + 4;
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      canonical_path, &after)
      || after.selected != before.selected + 1
      || after.terminal_entries != before.terminal_entries)
    return error_base + 5;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_after)
      || memcmp (&state_before, &state_after, sizeof state_before) != 0)
    return error_base + 6;

  g_autofree gchar *descendant = g_strconcat (canonical_path, "/x", NULL);
  before = after;
  state_before = state_after;
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "PATCH", base_url, descendant,
      "Bearer exact-route-poison", poison, &status, &body) != 0
      || status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return error_base + 7;
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      canonical_path, &after)
      || after.selected != before.selected + 1
      || after.terminal_entries != before.terminal_entries)
    return error_base + 8;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_after)
      || memcmp (&state_before, &state_after, sizeof state_before) != 0)
    return error_base + 9;

  g_autofree gchar *sibling = g_strconcat (canonical_path, "x", NULL);
  before = after;
  state_before = state_after;
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "PATCH", base_url, sibling,
      "Bearer exact-route-poison", poison, &status, &body) != 0
      || status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return error_base + 10;
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      canonical_path, &after)
      || after.selected != before.selected + 1
      || after.terminal_entries != before.terminal_entries)
    return error_base + 11;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_after)
      || memcmp (&state_before, &state_after, sizeof state_before) != 0)
    return error_base + 12;
  return 0;
}

static gint
check_exact_route_probe_framework (SoupServer *server, const gchar *base_url)
{
  guint total = 0;
  guint prefixes = 0;
  guint raw_singletons = 0;
  guint exact_singletons = 0;
  wyl_daemon_http_route_registration_counts_for_test (server, &total,
      &prefixes, &raw_singletons, &exact_singletons);
#if defined(WYL_HAS_AUDIT) && defined(WYL_HAS_FACT_STORE)
  const guint expected_total = 36;
  const guint expected_exact = 32;
#elif defined(WYL_HAS_FACT_STORE)
  const guint expected_total = 35;
  const guint expected_exact = 31;
#elif defined(WYL_HAS_AUDIT)
  const guint expected_total = 33;
  const guint expected_exact = 29;
#else
  const guint expected_total = 32;
  const guint expected_exact = 28;
#endif
  if (total != expected_total || prefixes != 4 || raw_singletons != 0
      || exact_singletons != expected_exact
      || total != prefixes + raw_singletons + exact_singletons)
    return 2280;
  static const gchar *exact_paths[] = {
    "/healthz",
    "/readyz",
    "/facts/status",
    "/facts/schema/register",
    "/profile/status",
    "/profile/events",
    "/service-management-authority/arm",
    "/auth/login",
    "/auth/mfa/verify",
    "/auth/mfa/enroll/start",
    "/auth/mfa/enroll/confirm",
    "/auth/refresh",
    "/auth/logout",
    "/tenants",
    "/tenants/create",
    "/tenants/seal",
    "/tenants/unseal",
    "/tenants/delete",
    "/graphs/create",
    "/graphs/seal",
    "/graphs",
    "/decide",
    "/policy/permissions/grant",
    "/policy/permissions/revoke",
    "/policy/permissions/transition",
    "/policy/roles/grant",
    "/policy/roles/revoke",
    "/audit/events",
#ifdef WYL_HAS_FACT_STORE
    "/service-credential-operations",
    "/service-credential-operations/reconcile",
    "/service-credential-operations/recover",
#endif
#ifdef WYL_HAS_AUDIT
    "/auth/service-token",
#endif
  };
  for (gsize i = 0; i < G_N_ELEMENTS (exact_paths); i++) {
    guint canonical_method_status = 405;
#ifndef WYL_HAS_FACT_STORE
    if (g_strcmp0 (exact_paths[i], "/facts/schema/register") == 0)
      canonical_method_status = 503;
#endif
    gint rc = check_exact_route_shape (server, base_url, exact_paths[i],
            canonical_method_status, 2281 + (gint) i * 13);
    if (rc != 0)
      return rc;
  }
  g_autoptr (SoupSession) session = soup_session_new ();
  WylDaemonExactRouteProbeSnapshot probe_before = { 0 }, probe_after = { 0 };
  WylDaemonExactRouteStateSnapshot state_before = { 0 }, state_after = { 0 };
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      "/healthz", &probe_before)
      || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_before)
      || send_raw_path_probe (session, "PATCH", base_url, "/healthz//x",
      "Bearer exact-route-poison", "{\"mutation\":\"must-not-run\"}",
      &status, &body) != 0
      || status != 404
      || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
      || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
      "/healthz", &probe_after)
      || probe_after.selected != probe_before.selected + 1
      || probe_after.terminal_entries != probe_before.terminal_entries
      || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
      &state_after)
      || memcmp (&state_before, &state_after, sizeof state_before) != 0)
    return 2750;
  return 0;
}

static gint
check_exact_facts_alias_canaries (SoupServer *server, const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  static const gchar *const status_aliases[] = {
    "/facts/status/x",
    "/facts/statusx",
  };
  static const gchar *const schema_aliases[] = {
    "/facts/schema/register/x?tenant=__wr_default&graph=orders&namespace=shop"
    "&relation=alias_probe&schema_version=1",
    "/facts/schema/registerx?tenant=__wr_default&graph=orders&namespace=shop"
    "&relation=alias_probe&schema_version=1",
  };
  const gchar *schema_body = "column_name\tcolumn_type\tnullable\tvisible\n"
      "order_id\tsymbol\tfalse\ttrue\n";
  for (gsize i = 0; i < G_N_ELEMENTS (status_aliases); i++) {
    WylDaemonExactRouteStateSnapshot before = { 0 }, after = { 0 };
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
        || send_raw_path_probe (session, "GET", base_url, status_aliases[i],
        NULL, NULL, &status, &body) != 0
        || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server, &after)
        || memcmp (&before, &after, sizeof before) != 0)
      return 2381 + (gint) i;
  }
  for (gsize i = 0; i < G_N_ELEMENTS (schema_aliases); i++) {
    WylDaemonExactRouteStateSnapshot before = { 0 }, after = { 0 };
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
        || send_raw_path_probe (session, "POST", base_url, schema_aliases[i],
        "Bearer exact-facts-valid-shape", schema_body, &status,
        &body) != 0 || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server, &after)
        || memcmp (&before, &after, sizeof before) != 0)
      return 2383 + (gint) i;
  }

  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_path_probe (session, "GET", base_url,
      "/facts/schema/register", NULL, NULL, &status, &body) != 0)
    return 2385;
#ifdef WYL_HAS_FACT_STORE
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 2386;
#else
  if (status != 503 || strstr (body, "\"fact_store_disabled\"") == NULL)
    return 2387;
#endif
  return 0;
}

static gint
check_readyz_runtime_liveness_contract (const gchar *base_url,
    WylDaemonRuntime *runtime)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (send_raw_path (session, "GET", base_url, "/healthz", &status, &body)
      != 0)
    return 1904;
  if (status != 200 || strstr (body, "ok") == NULL)
    return 1905;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/healthz?format=json", &status,
      &body) != 0)
    return 1921;
  if (status != 200 || strstr (body, "\"status\":\"ok\"") == NULL)
    return 1922;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1906;
  if (status != 200 || strstr (body, "ready") == NULL)
    return 1907;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
      &body) != 0)
    return 1923;
  if (status != 200 || strstr (body, "\"status\":\"ready\"") == NULL)
    return 1924;
  if (strstr (body, "\"subsystems\"") == NULL
      || strstr (body, "\"facts\"") == NULL
      || strstr (body, "\"graphs_total\"") == NULL)
    return 1929;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/facts/status", &status,
      &body) != 0)
    return 1930;
  if (status != 200 || strstr (body, "\"graphs_total\"") == NULL
      || strstr (body, "\"graphs\"") == NULL)
    return 1931;

  g_atomic_int_set (&runtime->delta_session_live, FALSE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1908;
  if (status != 503 || strstr (body, "\"delta_not_ready\"") == NULL)
    return 1909;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
      &body) != 0)
    return 1925;
  if (status != 503 || strstr (body, "\"status\":\"not_ready\"") == NULL ||
      strstr (body, "\"reason\":\"delta_not_ready\"") == NULL)
    return 1926;

  g_atomic_int_set (&runtime->delta_session_live, TRUE);
  g_atomic_int_set (&runtime->audit_degraded, TRUE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1910;
  if (status != 503 || strstr (body, "\"audit_degraded\"") == NULL)
    return 1911;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz?format=json", &status,
      &body) != 0)
    return 1927;
  if (status != 503 || strstr (body, "\"status\":\"not_ready\"") == NULL ||
      strstr (body, "\"reason\":\"audit_degraded\"") == NULL)
    return 1928;

  g_atomic_int_set (&runtime->audit_degraded, FALSE);
  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1912;
  return status == 200 ? 0 : 1913;
}

static gint
send_raw_decide_authorization_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, const gchar *authorization,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 30;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri =
      build_decide_uri (base_url, user, perm, scope, extra_query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 31;
  if (authorization != NULL)
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (body == NULL)
    return 32;
  gint rc = check_response_request_id_header (msg, 50);
  if (rc != 0)
    return rc;

  gsize body_size = 0;
  const gchar *body_data = g_bytes_get_data (body, &body_size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (body_data, body_size);
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  return 0;
}

static gint
send_raw_decide_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  return send_raw_decide_authorization_full (session, method, base_url, user,
             perm, scope, extra_query, NULL, out_status, out_body, out_request_id);
}

static gint
send_raw_decide_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, const gchar *access_token,
    guint *out_status, gchar **out_body)
{
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  return send_raw_decide_authorization_full (session, method, base_url, user,
             perm, scope, extra_query, authorization, out_status, out_body, NULL);
}

static gint
send_raw_decide (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, guint *out_status,
    gchar **out_body)
{
  return send_raw_decide_full (session, method, base_url, user, perm, scope,
             extra_query, out_status, out_body, NULL);
}

static gint
check_valid_decide_aliases (SoupServer *server, SoupSession *session,
    const gchar *base_url, const gchar *user, const gchar *perm,
    const gchar *scope, const gchar *extra_query, const gchar *access_token,
    gint error_base)
{
  static const gchar *const aliases[] = {
    "/decide/x",
    "/decidex",
  };
  g_autofree gchar *escaped_user = g_uri_escape_string (user, NULL, TRUE);
  g_autofree gchar *escaped_perm = g_uri_escape_string (perm, NULL, TRUE);
  g_autofree gchar *escaped_scope = g_uri_escape_string (scope, NULL, TRUE);
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  for (gsize i = 0; i < G_N_ELEMENTS (aliases); i++) {
    g_autofree gchar *path = g_strdup_printf
          ("%s?user=%s&perm=%s&session_token=%s%s%s", aliases[i], escaped_user,
            escaped_perm, escaped_scope, extra_query != NULL ? "&" : "",
            extra_query != NULL ? extra_query : "");
    WylDaemonExactRouteProbeSnapshot probe_before = { 0 }, probe_after = { 0 };
    WylDaemonExactRouteStateSnapshot state_before = { 0 }, state_after = { 0 };
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (!wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        "/decide", &probe_before)
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_before)
        || send_raw_path_probe (session, "POST", base_url, path,
        authorization, NULL, &status, &body) != 0
        || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        "/decide", &probe_after)
        || probe_after.selected != probe_before.selected + 1
        || probe_after.terminal_entries != probe_before.terminal_entries
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_after)
        || memcmp (&state_before, &state_after, sizeof state_before) != 0)
      return error_base + (gint) i;
  }
  return 0;
}

static gint
send_request_id_probe (SoupSession *session, const gchar *method,
    const gchar *uri, const gchar *inbound_request_id, guint *out_status,
    gchar **out_request_id)
{
  if (out_status == NULL || out_request_id == NULL)
    return 1800;
  *out_status = 0;
  *out_request_id = NULL;

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1801;
  if (inbound_request_id != NULL) {
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "X-Wyrelog-Request-Id", inbound_request_id);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) body = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (body == NULL)
    return 1802;
  *out_status = soup_message_get_status (msg);
  const gchar *request_id = soup_message_headers_get_one
        (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
  gint rc = check_response_request_id_header (msg, 1803);
  if (rc != 0)
    return rc;
  *out_request_id = g_strdup (request_id);
  return 0;
}

static gint
check_request_id_header_contract (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  guint status = 0;
  g_autofree gchar *health_id = NULL;
  g_autofree gchar *health_uri = g_strdup_printf ("%s/healthz", root);
  gint rc = send_request_id_probe (session, "GET", health_uri, NULL, &status,
          &health_id);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1804;

  g_autofree gchar *bad_decide_id = NULL;
  g_autofree gchar *bad_decide_uri =
      g_strdup_printf ("%s/decide?user=request-id-user", root);
  rc = send_request_id_probe (session, "POST", bad_decide_uri, NULL, &status,
          &bad_decide_id);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 1805;
  if (g_strcmp0 (health_id, bad_decide_id) == 0)
    return 1806;

  g_autofree gchar *spoofed_id = NULL;
  g_autofree gchar *deny_uri =
      build_decide_uri (root, "request-id-user", "wr.audit.read",
          "request-id-scope", NULL);
  rc = send_request_id_probe (session, "POST", deny_uri, "attacker", &status,
          &spoofed_id);
  if (rc != 0)
    return rc;
  if (status != 401)
    return 1807;
  if (g_strcmp0 (spoofed_id, "attacker") == 0)
    return 1808;
  if (g_strcmp0 (bad_decide_id, spoofed_id) == 0)
    return 1809;

  return 0;
}

static gint
check_raw_decide_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autoptr (WylClient) deny_client = NULL;
  g_autoptr (WylClient) guard_client = NULL;

  if (wyl_client_new (base_url, &deny_client) != WYRELOG_E_OK ||
      wyl_client_new (base_url, &guard_client) != WYRELOG_E_OK)
    return 1813;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (deny_client, "http-deny-user")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1814;
  }
  if (wyl_client_login_skip_mfa (guard_client, "http-guard-user")
      != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1815;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  g_autofree gchar *deny_access_token =
      wyl_client_dup_access_token (deny_client);
  g_autofree gchar *guard_access_token =
      wyl_client_dup_access_token (guard_client);
  if (deny_access_token == NULL || guard_access_token == NULL)
    return 1816;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK ||
      insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1821;

  gint rc = send_raw_decide (session, "GET", base_url, "http-deny-user",
          "http.not_armed", "http-deny-scope", NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"error\":\"method_not_allowed\"")
      == NULL)
    return 33;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide (session, "POST", base_url, "http-deny-user",
          "http.not_armed", "http-deny-scope", NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 1817;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-deny-user",
          "http.not_armed", "http-deny-scope", NULL, deny_access_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 34;
  if (strstr (body, "\"decision\":0") == NULL)
    return 35;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL &&
      strstr (body, "\"deny_reason\":null") == NULL)
    return 36;
  if (strstr (body, "\"deny_origin\":\"perm_state\"") == NULL &&
      strstr (body, "\"deny_origin\":null") == NULL)
    return 37;
  rc = check_valid_decide_aliases (server, session, base_url,
          "http-deny-user", "http.not_armed", "http-deny-scope", NULL,
          deny_access_token, 2670);
  if (rc != 0)
    return rc;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-deny-user",
          "wr.audit.read", "http-guard-scope", NULL, guard_access_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"decide_denied\"") == NULL)
    return 1818;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope", NULL, guard_access_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 38;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL &&
      strstr (body, "\"deny_reason\":null") == NULL)
    return 39;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *allow_request_id = NULL;
  g_autofree gchar *guard_authorization = g_strdup_printf ("Bearer %s",
          guard_access_token);
  rc = send_raw_decide_authorization_full (session, "POST", base_url,
          "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
          guard_authorization, &status, &body, &allow_request_id);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 40;
  if (strstr (body, "\"decision\":1") == NULL)
    return 41;
  if (strstr (body, "\"deny_reason\":null") == NULL)
    return 42;
  if (strstr (body, "\"deny_origin\":null") == NULL)
    return 43;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe allow_audit = {
    .subject_id = "http-guard-user",
    .action = "wr.audit.read",
    .resource_id = "http-guard-scope",
    .request_id = allow_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &allow_audit) != WYRELOG_E_OK)
    return 1810;
  if (allow_audit.matches != 1)
    return 1811;
#else
  (void) handle;
#endif

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=123&guard_loc_class=public&guard_risk=70",
          guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 44;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 45;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=123&guard_loc_class=public", guard_access_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 46;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=123&guard_loc_class=public&guard_risk=101",
          guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 47;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=abc&guard_loc_class=public&guard_risk=69",
          guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 48;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "guard_timestamp=123&guard_loc_class=unknown&guard_risk=69",
          guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400)
    return 49;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "tenant=unknown&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=69", guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  /*
   * Tenant gate emits the stable wire code "tenant_invalid" rather
   * than the surrounding handler's generic shape error so callers
   * can recognise tenant rejections regardless of endpoint family.
   */
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1812;

  /*
   * Unregistered tenant literals such as "evil-co" fail closed
   * before the decision path can run.
   */
  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope",
          "tenant=evil-co&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=69", guard_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1813;

#ifdef WYL_HAS_AUDIT
  /*
   * Defense-in-depth tenant gate on the JWT claims themselves. Forge
   * a token with the daemon's secret carrying an unregistered tenant
   * in the access claims; the signature verifies but
   * resolve_bearer_session must reject the token before request
   * authorization. The wire code is "tenant_invalid" with HTTP 401
   * at the auth boundary.
   */
  g_autofree gchar *foreign_tenant_token = NULL;
  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return 1824;
  g_autofree gchar *foreign_tenant_key_id =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (foreign_tenant_key_id == NULL)
    return 1827;
  wyl_jwt_issue_input_t foreign_tenant_input = {
    .key_id = foreign_tenant_key_id,
    .jti = "foreign-tenant-jti",
    .subject = "http-guard-user",
    .issuer = "wyrelogd",
    .audience = "wyrelog-client",
    .tenant = "evil-co",
    .principal_state_at_issue = "authenticated",
    .session_id = "foreign-tenant-session",
    .issued_at = g_get_real_time () / G_USEC_PER_SEC,
    .ttl_seconds = WYL_JWT_ACCESS_TTL_SECONDS,
  };
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256 (&foreign_tenant_input, secret,
          sizeof secret, &foreign_tenant_token);
  memset (secret, 0, sizeof secret);
  if (sign_rc != WYRELOG_E_OK)
    return 1825;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "http-guard-user",
          "wr.audit.read", "http-guard-scope", NULL, foreign_tenant_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 1826;
#else
  (void) server;
#endif

  return 0;
}

static gint
send_raw_login_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (out_request_id != NULL)
    *out_request_id = NULL;
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = NULL;
  if (query != NULL)
    uri = g_strdup_printf ("%s/auth/login?%s", root, query);
  else
    uri = g_strdup_printf ("%s/auth/login", root);

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 2;
  gint rc = check_response_request_id_header (msg, 513);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  return 0;
}

static gint
send_raw_login (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body)
{
  return send_raw_login_full (session, method, base_url, query, out_status,
             out_body, NULL);
}

static gchar *extract_json_string (const gchar * body, const gchar * name);

static gint
send_raw_refresh (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *refresh_token, guint *out_status,
    gchar **out_body)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = NULL;
  if (refresh_token != NULL) {
    g_autofree gchar *escaped = g_uri_escape_string (refresh_token, NULL, TRUE);
    uri = g_strdup_printf ("%s/auth/refresh?refresh_token=%s", root, escaped);
  } else {
    uri = g_strdup_printf ("%s/auth/refresh", root);
  }

  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 2;
  gint rc = check_response_request_id_header (msg, 573);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

typedef struct
{
  const gchar *base_url;
  const gchar *refresh_token;
  gint rc;
  guint status;
  gchar *body;
  RefreshThreadBarrier *wire_barrier;
} RawHumanRefresh;

static gpointer raw_human_refresh_thread (gpointer data);

typedef struct
{
  const gchar *base_url;
  const gchar *refresh_token;
  GMutex mutex;
  GCond changed;
  gboolean close_now;
  gint rc;
} DroppedHumanRefresh;

static gpointer
dropped_human_refresh_thread (gpointer data)
{
  DroppedHumanRefresh *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_autofree gchar *escaped = g_uri_escape_string (request->refresh_token,
          NULL, TRUE);
  g_autofree gchar *wire = g_strdup_printf
        ("POST /auth/refresh?refresh_token=%s HTTP/1.1\r\n"
          "Host: %s:%d\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
          escaped, g_uri_get_host (uri), g_uri_get_port (uri));
  gsize written = 0;
  if (!g_output_stream_write_all (g_io_stream_get_output_stream
        (G_IO_STREAM (connection)), wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)) {
    request->rc = 2;
    return NULL;
  }
  g_mutex_lock (&request->mutex);
  while (!request->close_now)
    g_cond_wait (&request->changed, &request->mutex);
  g_mutex_unlock (&request->mutex);
  if (!g_io_stream_close (G_IO_STREAM (connection), NULL, &error))
    request->rc = 3;
  return NULL;
}

static void
drop_human_refresh_response (DroppedHumanRefresh *request)
{
  g_mutex_lock (&request->mutex);
  request->close_now = TRUE;
  g_cond_broadcast (&request->changed);
  g_mutex_unlock (&request->mutex);
}

static gboolean
http_response_parse_content_length (const guint8 *data, gsize length,
    gsize *out_content_length)
{
  const gchar *text = (const gchar *) data;
  const gchar *headers_end = g_strstr_len (text, length, "\r\n\r\n");
  if (headers_end == NULL)
    return FALSE;

  gsize header_length = (gsize) (headers_end - text);
  const gchar *content_length = g_strstr_len (text, header_length,
          "\nContent-Length:");
  if (content_length == NULL) {
    if (header_length >= strlen ("Content-Length:")
        && g_ascii_strncasecmp (text, "Content-Length:",
        strlen ("Content-Length:")) == 0)
      content_length = text;
    else
      return FALSE;
  } else {
    content_length++;
  }

  content_length += strlen ("Content-Length:");
  while (content_length < text + header_length
      && g_ascii_isspace (*content_length))
    content_length++;

  gchar *end = NULL;
  guint64 parsed = g_ascii_strtoull (content_length, &end, 10);
  if (end == content_length)
    return FALSE;
  if (parsed > G_MAXSIZE)
    return FALSE;

  *out_content_length = (gsize) parsed;
  return TRUE;
}

static gpointer
raw_human_refresh_thread (gpointer data)
{
  RawHumanRefresh *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_socket_set_timeout (g_socket_connection_get_socket (connection), 15);
  g_autofree gchar *escaped = g_uri_escape_string (request->refresh_token,
          NULL, TRUE);
  g_autofree gchar *wire = g_strdup_printf
        ("POST /auth/refresh?refresh_token=%s HTTP/1.1\r\n"
          "Host: %s:%d\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
          escaped, g_uri_get_host (uri), g_uri_get_port (uri));
  GOutputStream *output = g_io_stream_get_output_stream
        (G_IO_STREAM (connection));
  gsize written = 0;
  if (!g_output_stream_write_all (output, wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)
      || !g_output_stream_flush (output, NULL, &error)) {
    request->rc = 2;
    return NULL;
  }
  if (request->wire_barrier != NULL) {
    g_mutex_lock (&request->wire_barrier->mutex);
    request->wire_barrier->started++;
    g_cond_broadcast (&request->wire_barrier->changed);
    g_mutex_unlock (&request->wire_barrier->mutex);
  }
  g_autoptr (GByteArray) response = g_byte_array_new ();
  guint8 chunk[1024];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  for (;;) {
    gssize count = g_input_stream_read (input, chunk, sizeof chunk, NULL,
            &error);
    if (count < 0) {
      request->rc = 3;
      return NULL;
    }
    if (count == 0)
      break;
    g_byte_array_append (response, chunk, (guint) count);

    gsize content_length = 0;
    if (http_response_parse_content_length (response->data, response->len,
        &content_length)) {
      const gchar *headers_end = g_strstr_len ((const gchar *) response->data,
              response->len, "\r\n\r\n");
      if (headers_end != NULL) {
        gsize header_length =
            (gsize) (headers_end - (const gchar *) response->data);
        if (response->len >= header_length + 4 + content_length)
          break;
      }
    }
  }
  g_byte_array_append (response, (const guint8 *) "\0", 1);
  gchar *headers_end = strstr ((gchar *) response->data, "\r\n\r\n");
  if (headers_end == NULL
      || sscanf ((gchar *) response->data, "HTTP/1.1 %u", &request->status)
      != 1) {
    request->rc = 4;
    return NULL;
  }
  request->body = g_strdup (headers_end + 4);
  return NULL;
}

static gchar *
access_token_jti (SoupServer *server, const gchar *access_token)
{
  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return NULL;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  g_autoptr (GBytes) payload = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_access_token (access_token, secret,
          sizeof secret, key_id, "wyrelogd", "wyrelog-client", now, &payload);
  sodium_memzero (secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return NULL;
  gsize length = 0;
  const gchar *data = g_bytes_get_data (payload, &length);
  g_autofree gchar *json = g_strndup (data, length);
  return extract_json_string (json, "jti");
}

static gint
check_concurrent_human_refresh_single_flight (SoupServer *server,
    const gchar *base_url)
{
  g_autoptr (SoupSession) login = soup_session_new ();
  guint login_status = 0;
  g_autofree gchar *login_body = NULL;
  if (send_raw_login (login, "POST", base_url,
      "username=login-user&skip_mfa=true", &login_status, &login_body)
      != 0 || login_status != 200)
    return 2200;
  g_autofree gchar *session_id = extract_json_string (login_body,
          "session_token");
  g_autofree gchar *predecessor = extract_json_string (login_body,
          "refresh_token");
  if (session_id == NULL || predecessor == NULL)
    return 2201;

  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
  if (before == NULL)
    return 2202;
  gint result = 0;
  guint threads_started = 0;
  gboolean threads_joined = FALSE, latch_released = FALSE;
  g_autofree gchar *access_a = NULL, *access_b = NULL;
  g_autofree gchar *refresh_a = NULL, *refresh_b = NULL;
  g_autofree gchar *jti_a = NULL, *jti_b = NULL, *after = NULL;
  g_autofree gchar *refresh_lineage = NULL, *expected_refresh_lineage = NULL;
  g_autofree gchar *resolved_session = NULL, *resolved_actor = NULL;
  g_autofree gchar *resolved_tenant = NULL, *successor_body = NULL;
  wyl_daemon_access_token_snapshot_t lineage = { 0 };
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  guint64 latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
        (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  RefreshThreadBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  RawHumanRefresh requests[8] = { 0 };
  GThread *threads[8] = { 0 };
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++) {
    requests[i].base_url = base_url;
    requests[i].refresh_token = predecessor;
    requests[i].wire_barrier = i == 0 ? NULL : &barrier;
  }
  threads[0] = g_thread_new ("human-refresh-a",
          raw_human_refresh_thread, &requests[0]);
  threads_started = 1;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
      g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2210;
    goto cleanup;
  }
  for (guint i = 1; i < G_N_ELEMENTS (threads); i++) {
    threads[i] = g_thread_new ("human-refresh-queued",
            raw_human_refresh_thread, &requests[i]);
    threads_started++;
  }
  g_mutex_lock (&barrier.mutex);
  gint64 wire_deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  while (barrier.started < G_N_ELEMENTS (requests) - 1)
    if (!g_cond_wait_until (&barrier.changed, &barrier.mutex, wire_deadline))
      break;
  gboolean all_followers_written = barrier.started
      == G_N_ELEMENTS (requests) - 1;
  g_mutex_unlock (&barrier.mutex);
  WylDaemonRefreshCounters counters = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (!all_followers_written || counters.handler_entries != 1
      || counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 0) {
    result = 2211;
    goto cleanup;
  }
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  for (guint i = 0; i < G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);
  threads_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++)
    if (requests[i].rc != 0 || requests[i].status != 200
        || g_strcmp0 (requests[0].body, requests[i].body) != 0) {
      result = 2203;
      goto cleanup;
    }
  access_a = extract_json_string (requests[0].body, "access_token");
  access_b = extract_json_string (requests[1].body, "access_token");
  refresh_a = extract_json_string (requests[0].body, "refresh_token");
  refresh_b = extract_json_string (requests[1].body, "refresh_token");
  jti_a = access_token_jti (server, access_a);
  jti_b = access_token_jti (server, access_b);
  if (access_a == NULL || refresh_a == NULL || jti_a == NULL
      || g_strcmp0 (access_a, access_b) != 0
      || g_strcmp0 (refresh_a, refresh_b) != 0
      || g_strcmp0 (jti_a, jti_b) != 0) {
    result = 2204;
    goto cleanup;
  }

  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
          &refresh_after, &access_after);
  if (after == NULL || refresh_after != refresh_before + 1
      || access_after != access_before + 1
      || strstr (after, access_a) == NULL
      || strstr (after, refresh_a) == NULL) {
    result = 2205;
    goto cleanup;
  }
  guint successor_refresh_count = 0, successor_access_count = 0;
  refresh_lineage = wyl_daemon_http_dup_refresh_state_for_test (server,
          refresh_a, &successor_refresh_count, &successor_access_count);
  expected_refresh_lineage = g_strdup_printf
        ("%s|%s|login-user|__wr_default|%d|0|0|", refresh_a, session_id,
          WYL_SESSION_AUTH_METHOD_HUMAN);
  if (refresh_lineage == NULL
      || !g_str_has_prefix (refresh_lineage, expected_refresh_lineage)
      || successor_refresh_count != refresh_after
      || successor_access_count != access_after) {
    result = 2212;
    goto cleanup;
  }
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, jti_a, &lineage)
      || g_strcmp0 (lineage.jti, jti_a) != 0
      || g_strcmp0 (lineage.session_id, session_id) != 0
      || g_strcmp0 (lineage.subject, "login-user") != 0
      || g_strcmp0 (lineage.tenant, "__wr_default") != 0
      || lineage.auth_method != WYL_SESSION_AUTH_METHOD_HUMAN
      || lineage.credential_id != NULL || lineage.credential_generation != 0
      || lineage.revoked) {
    result = 2209;
    goto cleanup;
  }
  wyl_daemon_access_token_snapshot_clear (&lineage);
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.handler_entries != 8 || counters.access_id_successes != 1
      || counters.jwt_sign_attempts != 1 || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 1) {
    result = 2206;
    goto cleanup;
  }

  if (wyl_daemon_http_resolve_bearer_for_test (server, access_a,
      &resolved_session, &resolved_actor, &resolved_tenant)
      != WYRELOG_E_OK || g_strcmp0 (resolved_session, session_id) != 0
      || g_strcmp0 (resolved_actor, "login-user") != 0) {
    result = 2207;
    goto cleanup;
  }
  guint successor_status = 0;
  if (send_raw_refresh (login, "POST", base_url, refresh_a,
      &successor_status, &successor_body) != 0 || successor_status != 200)
    result = 2208;

cleanup:
  if (!latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (!threads_joined)
    for (guint i = 0; i < threads_started; i++)
      g_thread_join (threads[i]);
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  wyl_daemon_access_token_snapshot_clear (&lineage);
  for (guint i = 0; i < G_N_ELEMENTS (requests); i++)
    g_free (requests[i].body);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return result;
}

static gint
check_human_refresh_response_loss (SoupServer *server, const gchar *base_url)
{
  gint result = 0;
  guint64 latch_generation = 0;
  gboolean sync_initialized = FALSE, thread_started = FALSE;
  gboolean thread_joined = FALSE, drop_signaled = FALSE, latch_released = FALSE;
  GThread *thread = NULL;
  g_autofree gchar *state = NULL;
  g_autofree gchar *access = NULL;
  g_autofree gchar *refresh = NULL;
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *after = NULL;
  if (send_raw_login (login, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2250;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  if (predecessor == NULL)
    return 2251;
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
        (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  DroppedHumanRefresh dropped = {
    .base_url = base_url,
    .refresh_token = predecessor,
  };
  g_mutex_init (&dropped.mutex);
  g_cond_init (&dropped.changed);
  sync_initialized = TRUE;
  thread = g_thread_new ("refresh-response-loss",
          dropped_human_refresh_thread, &dropped);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
      g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2252;
    goto cleanup;
  }
  WylDaemonRefreshCounters counters = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 0) {
    result = 2252;
    goto cleanup;
  }
  drop_human_refresh_response (&dropped);
  drop_signaled = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (dropped.rc != 0) {
    result = 2253;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (login, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 200) {
    result = 2254;
    goto cleanup;
  }
  guint refresh_count = 0, access_count = 0;
  state = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
          &refresh_count, &access_count);
  access = extract_json_string (body, "access_token");
  refresh = extract_json_string (body, "refresh_token");
  if (state == NULL || access == NULL || refresh == NULL
      || before == NULL || refresh_count != refresh_before + 1
      || access_count != access_before + 1 || strstr (state, access) == NULL
      || strstr (state, refresh) == NULL) {
    result = 2255;
    goto cleanup;
  }
  wyl_daemon_http_refresh_counters_for_test (server, &counters);
  if (counters.access_id_successes != 1 || counters.jwt_sign_attempts != 1
      || counters.jwt_sign_successes != 1
      || counters.refresh_id_successes != 1 || counters.publications != 1)
    result = 2255;
cleanup:
  if (thread_started && !thread_joined && !drop_signaled) {
    drop_human_refresh_response (&dropped);
    drop_signaled = TRUE;
  }
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (sync_initialized) {
    g_cond_clear (&dropped.changed);
    g_mutex_clear (&dropped.mutex);
  }
  return result;
}

static gint
check_human_refresh_prepared_expiry (SoupServer *server, const gchar *base_url)
{
  gint result = 0;
  gboolean clock_enabled = FALSE, thread_started = FALSE;
  gboolean thread_joined = FALSE, latch_released = FALSE;
  guint64 latch_generation = 0;
  GThread *thread = NULL;
  RawHumanRefresh request = { 0 };
  g_autofree gchar *predecessor = NULL;
  g_autofree gchar *before = NULL;
  g_autofree gchar *after = NULL;
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  const gint64 prepared_at = g_get_real_time () / G_USEC_PER_SEC;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, prepared_at);
  clock_enabled = TRUE;
  if (send_raw_login (login, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200) {
    result = 2256;
    goto cleanup;
  }
  predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  before = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
          &refresh_before, &access_before);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
        (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  request.base_url = base_url;
  request.refresh_token = predecessor;
  thread = g_thread_new ("refresh-prepared-expiry",
          raw_human_refresh_thread, &request);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
      g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2257;
    goto cleanup;
  }
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      prepared_at + WYL_JWT_ACCESS_TTL_SECONDS);
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
          &refresh_after, &access_after);
  if (request.status != 500 || before == NULL || after == NULL
      || refresh_after != refresh_before || access_after != access_before
      || strstr (after, "|0|0|") == NULL) {
    result = 2258;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (login, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 200)
    result = 2259;
cleanup:
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  if (clock_enabled)
    wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  g_free (request.body);
  return result;
}

static gint
check_human_refresh_logout_ordering (SoupServer *server, const gchar *base_url)
{
  const WylDaemonRefreshPhase phases[] = {
    WYL_DAEMON_REFRESH_BEFORE_PUBLICATION,
    WYL_DAEMON_REFRESH_AFTER_PUBLICATION,
  };
  g_autoptr (SoupSession) session = soup_session_new ();
  for (guint i = 0; i < G_N_ELEMENTS (phases); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_login (session, "POST", base_url,
        "username=login-user&skip_mfa=true", &status, &body) != 0
        || status != 200)
      return 2320 + (gint) i *10;
    g_autofree gchar *session_id = extract_json_string (body, "session_token");
    g_autofree gchar *predecessor = extract_json_string (body,
            "refresh_token");
    guint refresh_before = 0, access_before = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
          (server, predecessor, &refresh_before, &access_before);
    guint64 generation = wyl_daemon_http_arm_refresh_latch_for_test (server,
            phases[i]);
    RawHumanRefresh request = {
      .base_url = base_url,
      .refresh_token = predecessor,
    };
    GThread *thread = g_thread_new ("refresh-logout-order",
            raw_human_refresh_thread, &request);
    if (!wyl_daemon_http_wait_refresh_latch_for_test (server, generation,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
      wyl_daemon_http_release_refresh_latch_for_test (server, generation);
      g_thread_join (thread);
      wyl_daemon_http_disarm_refresh_latch_for_test (server, generation);
      g_free (request.body);
      return 2321 + (gint) i *10;
    }
    wyl_daemon_http_revoke_human_session_for_test (server, session_id);
    wyl_daemon_http_release_refresh_latch_for_test (server, generation);
    g_thread_join (thread);
    wyl_daemon_http_disarm_refresh_latch_for_test (server, generation);
    guint refresh_after = 0, access_after = 0;
    g_autofree gchar *after = wyl_daemon_http_dup_refresh_state_for_test
          (server, predecessor, &refresh_after, &access_after);
    if (i == 0) {
      if (request.status == 200 || before == NULL || after == NULL
          || refresh_after != refresh_before || access_after != access_before)
        return 2322;
    } else {
      g_autofree gchar *access = extract_json_string (request.body,
              "access_token");
      g_autofree gchar *refresh = extract_json_string (request.body,
              "refresh_token");
      g_autofree gchar *jti = access_token_jti (server, access);
      wyl_daemon_access_token_snapshot_t access_state = { 0 };
      guint successor_refresh_count = 0, successor_access_count = 0;
      g_autofree gchar *successor =
          wyl_daemon_http_dup_refresh_state_for_test (server, refresh,
              &successor_refresh_count, &successor_access_count);
      gboolean revoked = wyl_daemon_http_snapshot_access_token_for_test
            (server, jti, &access_state) && access_state.revoked;
      wyl_daemon_access_token_snapshot_clear (&access_state);
      if (request.status != 200 || access == NULL || refresh == NULL
          || refresh_after != refresh_before + 1
          || access_after != access_before + 1 || !revoked
          || successor == NULL || strstr (successor, "|0|1|") == NULL)
        return 2332;
    }
    g_free (request.body);
  }
  return 0;
}

static gint
check_human_refresh_shutdown_ordering (SoupServer *server,
    const gchar *base_url)
{
  gint result = 0;
  gboolean thread_started = FALSE, thread_joined = FALSE;
  gboolean latch_released = FALSE;
  guint64 latch_generation = 0;
  GThread *thread = NULL;
  RawHumanRefresh request = { 0 };
  g_autoptr (SoupSession) login = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *after = NULL;
  if (send_raw_login (login, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2260;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
  latch_generation = wyl_daemon_http_arm_refresh_latch_for_test
        (server, WYL_DAEMON_REFRESH_BEFORE_PUBLICATION);
  request.base_url = base_url;
  request.refresh_token = predecessor;
  thread = g_thread_new ("refresh-shutdown",
          raw_human_refresh_thread, &request);
  thread_started = TRUE;
  if (!wyl_daemon_http_wait_refresh_latch_for_test (server, latch_generation,
      g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
    result = 2261;
    goto cleanup;
  }
  wyl_daemon_http_terminalize_refreshes_for_test (server);
  wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  latch_released = TRUE;
  g_thread_join (thread);
  thread_joined = TRUE;
  wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  guint refresh_after = 0, access_after = 0;
  after = wyl_daemon_http_dup_refresh_state_for_test (server, predecessor,
          &refresh_after, &access_after);
  gboolean ok = request.status == 503 && request.body != NULL
      && strstr (request.body, "server_shutting_down") != NULL
      && before != NULL && after != NULL
      && refresh_after == refresh_before && access_after == access_before
      && strstr (after, "|0|0|") != NULL;
  if (!ok)
    result = 2262;
cleanup:
  if (latch_generation != 0 && !latch_released)
    wyl_daemon_http_release_refresh_latch_for_test (server, latch_generation);
  if (thread_started && !thread_joined)
    g_thread_join (thread);
  if (latch_generation != 0)
    wyl_daemon_http_disarm_refresh_latch_for_test (server, latch_generation);
  g_free (request.body);
  return result;
}

static gint
check_explicit_refresh_dispatch_context (WylHandle *handle,
    WylDaemonRuntime *runtime)
{
  g_autoptr (GMainContext) context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (context, FALSE);
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          runtime, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    return 2263;
  if (!wyl_daemon_http_refresh_context_is_for_test (http.server, context))
    return 2264;
  GThread *thread = g_thread_new ("refresh-explicit-context",
          test_http_server_thread_ctx, &http);
  MainLoopReadyBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  g_main_context_invoke_full (context, G_PRIORITY_DEFAULT,
      mark_main_loop_ready, &barrier, NULL);
  g_mutex_lock (&barrier.mutex);
  if (!barrier.ready) {
    if (!g_cond_wait_until (&barrier.changed, &barrier.mutex,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
      g_mutex_unlock (&barrier.mutex);
      g_main_loop_quit (http.loop);
      g_thread_join (thread);
      soup_server_disconnect (http.server);
      g_clear_object (&http.server);
      g_clear_pointer (&http.loop, g_main_loop_unref);
      g_cond_clear (&barrier.changed);
      g_mutex_clear (&barrier.mutex);
      return 2266;
    }
  }
  g_mutex_unlock (&barrier.mutex);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL) {
    g_main_loop_quit (http.loop);
    g_thread_join (thread);
    soup_server_disconnect (http.server);
    g_clear_object (&http.server);
    g_clear_pointer (&http.loop, g_main_loop_unref);
    g_cond_clear (&barrier.changed);
    g_mutex_clear (&barrier.mutex);
    return 2265;
  }
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = send_raw_refresh (session, "POST", base_url, NULL, &status,
          &body);
  guint owned = 0, wrong = 0;
  wyl_daemon_http_refresh_lifecycle_counts_for_test (http.server, &owned,
      &wrong);
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return rc == 0 && status == 400 && owned == 1 && wrong == 0 ? 0 : 2266;
}

static gint
check_human_refresh_fault_matrix (SoupServer *server, const gchar *base_url)
{
  const WylDaemonRefreshFault faults[] = {
    WYL_DAEMON_REFRESH_FAULT_ACCESS_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_REFRESH_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_RESULT_PREPARE,
    WYL_DAEMON_REFRESH_FAULT_PREPUBLICATION,
  };
  g_autoptr (SoupSession) session = soup_session_new ();
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_login (session, "POST", base_url,
        "username=login-user&skip_mfa=true", &status, &body) != 0
        || status != 200)
      return 2270 + (gint) i *10;
    g_autofree gchar *predecessor = extract_json_string (body,
            "refresh_token");
    g_autofree gchar *session_id = extract_json_string (body,
            "session_token");
    gchar **access_ids_before =
        wyl_daemon_http_snapshot_session_access_ids_for_test (server,
            session_id);
    gchar **refresh_ids_before =
        wyl_daemon_http_snapshot_session_refresh_ids_for_test (server,
            session_id);
    guint refresh_before = 0, access_before = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
          (server, predecessor, &refresh_before, &access_before);
    wyl_daemon_http_reset_refresh_counters_for_test (server);
    wyl_daemon_http_set_refresh_fault_for_test (server, faults[i]);
    g_clear_pointer (&body, g_free);
    if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
        &body) != 0 || status != 500)
      return 2271 + (gint) i *10;
    guint refresh_failed = 0, access_failed = 0;
    g_autofree gchar *failed = wyl_daemon_http_dup_refresh_state_for_test
          (server, predecessor, &refresh_failed, &access_failed);
    gchar **access_ids_failed =
        wyl_daemon_http_snapshot_session_access_ids_for_test (server,
            session_id);
    gchar **refresh_ids_failed =
        wyl_daemon_http_snapshot_session_refresh_ids_for_test (server,
            session_id);
    gchar **generated_refresh =
        wyl_daemon_http_snapshot_generated_refresh_ids_for_test (server);
    if (before == NULL || failed == NULL || refresh_failed != refresh_before
        || access_failed != access_before || strstr (failed, "|0|0|") == NULL
        || !g_strv_equal ((const gchar * const *) access_ids_before,
        (const gchar * const *) access_ids_failed)
        || !g_strv_equal ((const gchar * const *) refresh_ids_before,
        (const gchar * const *) refresh_ids_failed))
      return 2272 + (gint) i *10;
    for (guint generated = 0; generated_refresh != NULL
        && generated_refresh[generated] != NULL; generated++)
      if (g_strv_contains ((const gchar * const *) refresh_ids_failed,
          generated_refresh[generated]))
        return 2274 + (gint) i *10;
    g_strfreev (access_ids_before);
    g_strfreev (access_ids_failed);
    wyl_daemon_http_sensitive_strv_free_for_test (refresh_ids_before);
    wyl_daemon_http_sensitive_strv_free_for_test (refresh_ids_failed);
    wyl_daemon_http_sensitive_strv_free_for_test (generated_refresh);
    g_clear_pointer (&body, g_free);
    if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
        &body) != 0 || status != 200)
      return 2273 + (gint) i *10;
  }

  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2310;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  wyl_daemon_http_set_refresh_fault_for_test (server,
      WYL_DAEMON_REFRESH_FAULT_RESPONSE_BUILD);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 500
      || strstr (body, "refresh_response_failed") == NULL)
    return 2311;
  guint refresh_after = 0, access_after = 0;
  g_autofree gchar *committed = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_after, &access_after);
  if (before == NULL || committed == NULL
      || refresh_after != refresh_before + 1
      || access_after != access_before + 1)
    return 2312;
  WylDaemonRefreshCounters counters_before = { 0 }, counters_after = { 0 };
  wyl_daemon_http_refresh_counters_for_test (server, &counters_before);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 200)
    return 2313;
  wyl_daemon_http_refresh_counters_for_test (server, &counters_after);
  if (memcmp (&counters_before.access_id_successes,
      &counters_after.access_id_successes,
      sizeof counters_before - G_STRUCT_OFFSET (WylDaemonRefreshCounters,
      access_id_successes)) != 0)
    return 2314;
  return 0;
}

static gint
check_human_refresh_failure_and_clock_boundaries (SoupServer *server,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200)
    return 2212;
  g_autofree gchar *predecessor = extract_json_string (body, "refresh_token");
  if (predecessor == NULL)
    return 2213;
  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_before, &access_before);
  wyl_daemon_http_fail_next_refresh_publication_for_test (server);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 500
      || strstr (body, "\"refresh_failed\"") == NULL) {
    g_printerr ("refresh injected failure: status=%u body=%s\n", status,
        body != NULL ? body : "<null>");
    return 2214;
  }
  guint refresh_failed = 0, access_failed = 0;
  g_autofree gchar *failed = wyl_daemon_http_dup_refresh_state_for_test
        (server, predecessor, &refresh_failed, &access_failed);
  if (before == NULL || failed == NULL || refresh_failed != refresh_before
      || access_failed != access_before || strstr (failed, "|0|0|") == NULL)
    return 2215;
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, predecessor, &status,
      &body) != 0 || status != 200)
    return 2216;

  gint64 boundary = g_get_real_time () / G_USEC_PER_SEC;
  const gint64 grace_seconds = 30;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, boundary);
  g_autofree gchar *boundary_predecessor = NULL;
  g_clear_pointer (&body, g_free);
  if (send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200
      || (boundary_predecessor = extract_json_string (body,
      "refresh_token")) == NULL)
    return 2217;
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
      &status, &body) != 0 || status != 200)
    return 2218;
  g_autofree gchar *committed_body = g_strdup (body);
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      boundary + grace_seconds);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
      &status, &body) != 0 || status != 200
      || g_strcmp0 (body, committed_body) != 0)
    return 2219;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE,
      boundary + grace_seconds + 1);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, boundary_predecessor,
      &status, &body) != 0 || status != 401
      || strstr (body, "\"refresh_reuse_detected\"") == NULL)
    return 2220;

  g_autofree gchar *expiry_predecessor = NULL;
  wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  g_clear_pointer (&body, g_free);
  if (send_raw_login (session, "POST", base_url,
      "username=login-user&skip_mfa=true", &status, &body) != 0
      || status != 200
      || (expiry_predecessor = extract_json_string (body,
      "refresh_token")) == NULL
      || !wyl_daemon_http_set_refresh_times_for_test (server,
      expiry_predecessor, boundary, 0))
    return 2221;
  wyl_daemon_http_set_refresh_clock_for_test (server, TRUE, boundary);
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, expiry_predecessor,
      &status, &body) != 0 || status != 401
      || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 2222;
  wyl_daemon_http_set_refresh_clock_for_test (server, FALSE, 0);
  return 0;
}

static gint
check_service_refresh_isolation (SoupServer *server, const gchar *base_url,
    const gchar *human_session_id)
{
  wyl_id_t session_id = WYL_ID_NIL, jti_id = WYL_ID_NIL;
  gchar session_text[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  if (wyl_id_new (&session_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&session_id, session_text, sizeof session_text)
      != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || wyl_service_credential_id_new (credential_id, sizeof credential_id)
      != WYRELOG_E_OK)
    return 1900;
  wyl_service_session_descriptor_t descriptor = {
    .session_id = session_id,
    .jti = jti,
    .subject_id = "svc:refresh:isolation",
    .tenant_id = "default",
    .credential_id = credential_id,
    .credential_generation = 1,
    .issued_at_seconds = 100,
    .expires_at_seconds = 400,
  };
  g_autoptr (WylSession) service = NULL;
  if (wyl_session_new_service_detached (&descriptor, &service)
      != WYRELOG_E_OK)
    return 1901;

  guint refresh_before = 0, access_before = 0;
  g_autofree gchar *missing = wyl_daemon_http_dup_refresh_state_for_test
        (server, "missing-service-refresh", &refresh_before, &access_before);
  g_autofree gchar *access = (gchar *) 0x1;
  g_autofree gchar *refresh = (gchar *) 0x1;
  if (missing != NULL || wyl_daemon_http_issue_human_tokens_for_test (server,
      service, session_text, descriptor.subject_id, descriptor.tenant_id,
      &access, &refresh) != WYRELOG_E_POLICY || access != NULL
      || refresh != NULL)
    return 1902;
  guint refresh_after = 0, access_after = 0;
  missing = wyl_daemon_http_dup_refresh_state_for_test (server,
          "missing-service-refresh", &refresh_after, &access_after);
  if (missing != NULL || refresh_after != refresh_before
      || access_after != access_before)
    return 1903;

  g_autoptr (WylSession) human = wyl_daemon_http_ref_session (server,
          human_session_id);
  if (human == NULL)
    return 1904;
  typedef struct
  {
    const gchar *token;
    WylSession *session;
    const gchar *session_id;
    const gchar *subject;
    gint auth_method;
    gboolean consumed;
  } InvalidRefresh;
  const InvalidRefresh invalid[] = {
    {"seed-service", service, session_text, "svc:refresh:isolation",
     WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, FALSE},
    {"seed-human-cache", service, session_text, "human.cached",
     WYL_SESSION_AUTH_METHOD_HUMAN, FALSE},
    {"seed-svc-cache", human, human_session_id, "svc:cached",
     WYL_SESSION_AUTH_METHOD_HUMAN, FALSE},
    {"seed-service-consumed", service, session_text,
     "svc:refresh:isolation", WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
     TRUE},
  };
  g_autoptr (SoupSession) client = soup_session_new ();
  wyl_daemon_http_reset_refresh_counters_for_test (server);
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++) {
    const gchar *successor_access =
        invalid[i].consumed ? "cached-access" : NULL;
    const gchar *successor_refresh =
        invalid[i].consumed ? "cached-refresh" : NULL;
    if (!wyl_daemon_http_seed_refresh_for_test (server, invalid[i].session,
        invalid[i].token, invalid[i].session_id, invalid[i].subject,
        "default", invalid[i].auth_method, invalid[i].consumed,
        successor_access, successor_refresh))
      return 1910 + (gint) i;
    guint before_refresh = 0, before_access = 0;
    g_autofree gchar *before = wyl_daemon_http_dup_refresh_state_for_test
          (server, invalid[i].token, &before_refresh, &before_access);
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (before == NULL || send_raw_refresh (client, "POST", base_url,
        invalid[i].token, &status, &body) != 0 || status != 401
        || strstr (body, "\"refresh_auth_required\"") == NULL
        || strstr (body, "access_token") != NULL
        || strstr (body, "refresh_token") != NULL)
      return 1920 + (gint) i;
    guint after_refresh = 0, after_access = 0;
    g_autofree gchar *after = wyl_daemon_http_dup_refresh_state_for_test
          (server, invalid[i].token, &after_refresh, &after_access);
    if (g_strcmp0 (after, before) != 0 || after_refresh != before_refresh
        || after_access != before_access)
      return 1930 + (gint) i;
    WylDaemonRefreshCounters counters = { 0 };
    wyl_daemon_http_refresh_counters_for_test (server, &counters);
    if (counters.access_id_successes != 0 || counters.jwt_sign_attempts != 0
        || counters.jwt_sign_successes != 0
        || counters.refresh_id_successes != 0 || counters.publications != 0)
      return 1940 + (gint) i;
  }
  return 0;
}

static gint
check_service_access_token_state_contract (SoupServer *server,
    wyl_daemon_access_token_snapshot_t *owned_after_teardown)
{
  wyl_id_t sid_id = WYL_ID_NIL, jti_id = WYL_ID_NIL, other_id = WYL_ID_NIL;
  gchar sid[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gchar other[WYL_ID_STRING_BUF];
  gchar credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  wyl_id_t human_sid_id = WYL_ID_NIL, human_jti_id = WYL_ID_NIL;
  gchar human_sid[WYL_ID_STRING_BUF], human_jti[WYL_ID_STRING_BUF];
  if (wyl_id_new (&sid_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_new (&other_id) != WYRELOG_E_OK
      || wyl_id_new (&human_sid_id) != WYRELOG_E_OK
      || wyl_id_new (&human_jti_id) != WYRELOG_E_OK
      || wyl_id_format (&sid_id, sid, sizeof sid) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || wyl_id_format (&other_id, other, sizeof other) != WYRELOG_E_OK
      || wyl_id_format (&human_sid_id, human_sid, sizeof human_sid)
      != WYRELOG_E_OK
      || wyl_id_format (&human_jti_id, human_jti, sizeof human_jti)
      != WYRELOG_E_OK
      || wyl_service_credential_id_new (credential, sizeof credential)
      != WYRELOG_E_OK)
    return 1940;

  g_autofree gchar *active_key =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (active_key == NULL
      || !wyl_daemon_http_store_human_access_token_for_test (server,
      human_jti, human_sid, "human-state", "tenant-state", active_key, 100,
      500)
      || !wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
      human_sid, "human-state", "tenant-state", 100, 500, NULL, NULL, 0,
      499))
    return 1958;
  wyl_daemon_access_token_snapshot_t human_snapshot = { 0 };
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, human_jti,
      &human_snapshot)
      || human_snapshot.auth_method != WYL_SESSION_AUTH_METHOD_HUMAN
      || human_snapshot.credential_id != NULL
      || human_snapshot.credential_generation != 0
      || human_snapshot.issued_at != 100) {
    wyl_daemon_access_token_snapshot_clear (&human_snapshot);
    return 1959;
  }
  wyl_daemon_access_token_snapshot_clear (&human_snapshot);
  if (wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
      human_sid, "human-state", "tenant-state", 101, 500, NULL, NULL, 0,
      499))
    return 1963;
  if (wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
      human_sid, "human-state", "tenant-state", 100, 500,
      "service_credential", credential, 7, 499))
    return 1960;

  gchar mutable_subject[] = "svc:state:test";
  gchar mutable_tenant[] = "tenant-state";
  gchar mutable_key[] = "key-state";
  gchar mutable_credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  memcpy (mutable_credential, credential, sizeof credential);
  if (!wyl_daemon_http_store_service_access_token_for_test (server, jti, sid,
      mutable_subject, mutable_tenant, mutable_key, 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, mutable_credential, 7,
      FALSE))
    return 1941;
  mutable_subject[4] = 'X';
  mutable_tenant[0] = 'X';
  mutable_key[0] = 'X';
  mutable_credential[4] = mutable_credential[4] == '0' ? '1' : '0';

  wyl_daemon_access_token_snapshot_t snapshot = { 0 };
  if (!wyl_daemon_http_snapshot_access_token_for_test (server, jti, &snapshot)
      || g_strcmp0 (snapshot.jti, jti) != 0
      || g_strcmp0 (snapshot.session_id, sid) != 0
      || g_strcmp0 (snapshot.subject, "svc:state:test") != 0
      || g_strcmp0 (snapshot.tenant, "tenant-state") != 0
      || g_strcmp0 (snapshot.key_id, "key-state") != 0
      || snapshot.auth_method != WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL
      || g_strcmp0 (snapshot.credential_id, credential) != 0
      || snapshot.credential_generation != 7 || snapshot.issued_at != 200
      || snapshot.expires_at != 500 || snapshot.revoked)
    return 1942;
  if (!wyl_daemon_http_service_access_token_is_exact_for_test (server, jti,
      sid, "svc:state:test", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499))
    return 1943;

#define EXPECT_NOT_EXACT(j, s, sub, ten, key, exp, method, cred, gen, now, code) \
  G_STMT_START { \
    if (wyl_daemon_http_service_access_token_is_exact_for_test (server, (j), \
        (s), (sub), (ten), (key), (exp), (method), (cred), (gen), (now))) \
    return (code); \
  } G_STMT_END
  EXPECT_NOT_EXACT (other, sid, "svc:state:test", "tenant-state",
      "key-state", 500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
      credential, 7, 499, 1944);
  EXPECT_NOT_EXACT (jti, other, "svc:state:test", "tenant-state",
      "key-state", 500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
      credential, 7, 499, 1945);
  EXPECT_NOT_EXACT (jti, sid, "svc:other", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499, 1946);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-other", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1947);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-other",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1948);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      501, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499,
      1949);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_HUMAN, credential, 7, 499, 1950);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, "missing", 7, 499, 1951);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 8, 499,
      1952);
  EXPECT_NOT_EXACT (jti, sid, "svc:state:test", "tenant-state", "key-state",
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 500,
      1953);
#undef EXPECT_NOT_EXACT

  const gchar *missing[] = { NULL, "", "bad" };
  for (gsize i = 0; i < G_N_ELEMENTS (missing); i++) {
    if (wyl_daemon_http_store_service_access_token_for_test (server,
        missing[i], sid, "svc:state:test", "tenant-state", "key-state",
        500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7,
        FALSE)
        || wyl_daemon_http_store_service_access_token_for_test (server, jti,
        missing[i], "svc:state:test", "tenant-state", "key-state", 500,
        WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE))
      return 1954;
  }
  if (wyl_daemon_http_store_service_access_token_for_test (server, other, sid,
      NULL, "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
      sid, "svc:state:test", NULL, "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
      sid, "svc:state:test", "tenant-state", NULL, 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
      sid, "svc:state:test", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, NULL, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, other,
      sid, "svc:state:test", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 0, FALSE))
    return 1955;

  if (!wyl_daemon_http_store_service_access_token_for_test (server, other,
      sid, "svc:revoked", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, TRUE)
      || wyl_daemon_http_service_access_token_is_exact_for_test (server,
      other, sid, "svc:revoked", "tenant-state", "key-state", 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, 499))
    return 1956;

  static const gchar noncanonical_id[] = "01900000-0000-7000-8000-00000000000A";
  wyl_id_t parsed_noncanonical = WYL_ID_NIL;
  if (wyl_id_parse (noncanonical_id, &parsed_noncanonical) != WYRELOG_E_OK
      || wyl_daemon_http_store_service_access_token_for_test (server,
      noncanonical_id, sid, "svc:state:test", "tenant-state", active_key,
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server, jti,
      noncanonical_id, "svc:state:test", "tenant-state", active_key, 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server,
      human_jti, human_sid, "svc:bad/subject", "tenant-state", active_key,
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_store_service_access_token_for_test (server,
      human_jti, human_sid, "svc:state:test", "bad/tenant", active_key,
      500, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7,
      FALSE))
    return 1961;

  if (!wyl_daemon_http_store_service_access_token_for_test (server, human_jti,
      human_sid, "svc:state:test", "tenant-state", active_key, 500,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, credential, 7, FALSE)
      || wyl_daemon_http_access_token_is_active_for_test (server, human_jti,
      human_sid, "svc:state:test", "tenant-state", 200, 500, NULL, NULL, 0,
      499))
    return 1962;

  *owned_after_teardown = snapshot;
  memset (&snapshot, 0, sizeof snapshot);
  return 0;
}

typedef struct
{
  gchar sid[WYL_ID_STRING_BUF];
  gchar jti[WYL_ID_STRING_BUF];
  gchar other_sid[WYL_ID_STRING_BUF];
  gchar other_jti[WYL_ID_STRING_BUF];
  gchar credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  gchar other_credential[WYL_SERVICE_CREDENTIAL_ID_BUF];
  gchar tenant[64];
  gchar *key_id;
  gchar *token;
  gint64 now;
} ServiceResolverFixture;

static void
service_resolver_fixture_clear (ServiceResolverFixture *fixture)
{
  g_clear_pointer (&fixture->key_id, g_free);
  g_clear_pointer (&fixture->token, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (ServiceResolverFixture,
    service_resolver_fixture_clear)
static gboolean
service_resolver_fixture_init_tenant_credential (SoupServer *server,
    ServiceResolverFixture *fixture, gint registry_state,
    guint registry_mismatch, const gchar *tenant_id,
    const gchar *credential_id, guint64 credential_generation)
{
  memset (fixture, 0, sizeof *fixture);
  wyl_id_t sid = WYL_ID_NIL, jti = WYL_ID_NIL;
  wyl_id_t other_sid = WYL_ID_NIL, other_jti = WYL_ID_NIL;
  guint8 secret[32] = { 0 };
  fixture->now = g_get_real_time () / G_USEC_PER_SEC;
  g_strlcpy (fixture->tenant, tenant_id, sizeof fixture->tenant);
  fixture->key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (fixture->key_id == NULL || wyl_id_new (&sid) != WYRELOG_E_OK
      || wyl_id_new (&jti) != WYRELOG_E_OK
      || wyl_id_new (&other_sid) != WYRELOG_E_OK
      || wyl_id_new (&other_jti) != WYRELOG_E_OK
      || wyl_id_format (&sid, fixture->sid, sizeof fixture->sid)
      != WYRELOG_E_OK || wyl_id_format (&jti, fixture->jti, sizeof fixture->jti)
      != WYRELOG_E_OK
      || wyl_id_format (&other_sid, fixture->other_sid,
      sizeof fixture->other_sid) != WYRELOG_E_OK
      || wyl_id_format (&other_jti, fixture->other_jti,
      sizeof fixture->other_jti) != WYRELOG_E_OK
      || wyl_service_credential_id_new (fixture->other_credential,
      sizeof fixture->other_credential) != WYRELOG_E_OK)
    return FALSE;
  if (credential_id == NULL) {
    if (wyl_service_credential_id_new (fixture->credential,
        sizeof fixture->credential) != WYRELOG_E_OK)
      return FALSE;
    credential_generation = 9;
  } else if (!wyl_service_credential_id_is_canonical (credential_id,
      strlen (credential_id)) || credential_generation == 0) {
    return FALSE;
  } else {
    g_strlcpy (fixture->credential, credential_id, sizeof fixture->credential);
  }
  wyl_service_session_descriptor_t descriptor = {
    .session_id = sid,.jti = fixture->jti,
    .subject_id = "svc:resolver:test",.tenant_id = fixture->tenant,
    .credential_id = fixture->credential,
    .credential_generation = credential_generation,
    .issued_at_seconds = fixture->now,
    .expires_at_seconds = fixture->now + 300,
  };
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_new_service_detached (&descriptor, &session)
      != WYRELOG_E_OK
      || !wyl_daemon_http_replace_session_for_test (server, fixture->sid,
      session)
      || !wyl_daemon_http_store_service_access_token_for_test (server,
      fixture->jti, fixture->sid, descriptor.subject_id,
      descriptor.tenant_id, fixture->key_id, fixture->now + 300,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, fixture->credential,
      credential_generation, FALSE))
    return FALSE;
  const gchar *reg_sid = registry_mismatch == 1 ? fixture->other_sid
      : fixture->sid;
  const gchar *reg_jti = registry_mismatch == 2 ? fixture->other_jti
      : fixture->jti;
  const gchar *reg_cred = registry_mismatch == 3 ? fixture->other_credential
      : fixture->credential;
  guint64 reg_generation = registry_mismatch == 4 ?
      credential_generation + 1 : credential_generation;
  const gchar *reg_subject = registry_mismatch == 5 ? "svc:resolver:other"
      : descriptor.subject_id;
  const gchar *reg_tenant = registry_mismatch == 6 ? "tenant-other"
      : descriptor.tenant_id;
  gboolean changed = FALSE;
  if (registry_state >= 0
      && wyl_daemon_http_service_registry_transition_for_test (server,
      reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
      WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (registry_state >= WYL_SERVICE_AUTH_ACTIVE
      && wyl_daemon_http_service_registry_transition_for_test (server,
      reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
      WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (registry_state == WYL_SERVICE_AUTH_REVOKED
      && wyl_daemon_http_service_registry_transition_for_test (server,
      reg_sid, reg_jti, reg_cred, reg_generation, reg_subject, reg_tenant,
      WYL_DAEMON_SERVICE_REGISTRY_REVOKE, &changed) != WYRELOG_E_OK)
    return FALSE;
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_service_issue_input_t input = {
    .key_id = fixture->key_id,.jti = fixture->jti,
    .subject = descriptor.subject_id,.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = descriptor.tenant_id,
    .session_id = fixture->sid,.credential_id = fixture->credential,
    .credential_generation = credential_generation,.issued_at = fixture->now,
  };
  wyrelog_error_t rc = wyl_jwt_sign_hs256_service (&input, secret,
          sizeof secret, &fixture->token);
  sodium_memzero (secret, sizeof secret);
  return rc == WYRELOG_E_OK;
}

static gboolean
service_resolver_fixture_init_tenant (SoupServer *server,
    ServiceResolverFixture *fixture, gint registry_state,
    guint registry_mismatch, const gchar *tenant_id)
{
  return service_resolver_fixture_init_tenant_credential (server, fixture,
             registry_state, registry_mismatch, tenant_id, NULL, 0);
}

static gboolean
service_resolver_fixture_init (SoupServer *server,
    ServiceResolverFixture *fixture, gint registry_state,
    guint registry_mismatch)
{
  return service_resolver_fixture_init_tenant (server, fixture,
             registry_state, registry_mismatch, "__wr_default");
}

static gboolean
service_resolver_expect (SoupServer *server,
    const ServiceResolverFixture *fixture, const gchar *token, gboolean success)
{
  g_autofree gchar *sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  wyrelog_error_t rc = wyl_daemon_http_resolve_bearer_for_test (server,
          token, &sid, &actor, &tenant);
  if (!success)
    return rc == WYRELOG_E_POLICY && sid == NULL && actor == NULL
           && tenant == NULL;
  return rc == WYRELOG_E_OK && g_strcmp0 (sid, fixture->sid) == 0
         && g_strcmp0 (actor, "svc:resolver:test") == 0
         && g_strcmp0 (tenant, fixture->tenant) == 0;
}

static WylDaemonServiceAuthInvalidation
service_auth_invalidation_for_fixture (const ServiceResolverFixture *fixture,
    WylDaemonServiceAuthInvalidationKind kind)
{
  return (WylDaemonServiceAuthInvalidation) {
           .kind = kind,.credential_id = fixture->credential,.credential_generation =
               9,.principal = "svc:resolver:test",.tenant = fixture->tenant,
  };
}

static WylDaemonServiceAuthInvalidation
service_auth_invalidation_no_match (const ServiceResolverFixture *fixture,
    WylDaemonServiceAuthInvalidationKind kind)
{
  return (WylDaemonServiceAuthInvalidation) {
           .kind = kind,.credential_id =
               fixture->other_credential,.credential_generation = 10,.principal =
               "svc:resolver:other",.tenant = "tenant-other",
  };
}

typedef struct
{
  SoupServer *server;
  WylDaemonServiceAuthInvalidation invalidation;
  WylServiceAuthRevokeResult result;
  wyrelog_error_t rc;
} ServiceAuthInvalidationCall;

static gpointer
service_auth_invalidation_thread (gpointer data)
{
  ServiceAuthInvalidationCall *call = data;
  call->rc = wyl_daemon_http_invalidate_service_auth_for_test (call->server,
          &call->invalidation, &call->result);
  return NULL;
}

static gboolean
service_auth_invalidation_wait_writer_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.active_readers == 1 && snapshot.waiting_writers == 1
        && !snapshot.writer_active)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
check_service_auth_invalidator_contract (SoupServer *server)
{
  ServiceResolverFixture pending = { 0 };
  if (!service_resolver_fixture_init (server, &pending,
      WYL_SERVICE_AUTH_PENDING, 0))
    return FALSE;

  ServiceAuthInvalidationCall pending_call = {
    .server = server,
    .invalidation = service_auth_invalidation_for_fixture (&pending,
            WYL_DAEMON_SERVICE_AUTH_INVALIDATE_CREDENTIAL),
    .rc = WYRELOG_E_INTERNAL,
  };
  pending_call.result = (WylServiceAuthRevokeResult) {
    0
  };
  if (pending_call.invalidation.kind !=
      WYL_DAEMON_SERVICE_AUTH_INVALIDATE_CREDENTIAL)
    return FALSE;
  if (wyl_daemon_http_invalidate_service_auth_for_test (server, NULL,
      &pending_call.result) != WYRELOG_E_INVALID)
    return FALSE;
  return TRUE;
}

static gchar *
service_resolver_sign_variant (SoupServer *server,
    const ServiceResolverFixture *fixture, guint field)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return NULL;
  wyl_jwt_service_issue_input_t input = {
    .key_id = field == 8 ? "wrong-key" : fixture->key_id,
    .jti = field == 2 ? fixture->other_jti : fixture->jti,
    .subject = field == 3 ? "svc:resolver:other" : "svc:resolver:test",
    .issuer = field == 9 ? "wrong-issuer" : "wyrelogd",
    .audience = field == 10 ? "wrong-audience" : "wyrelog-client",
    .tenant = field == 4 ? "tenant-unknown" : "__wr_default",
    .session_id = field == 1 ? fixture->other_sid : fixture->sid,
    .credential_id = field == 5 ? fixture->other_credential
        : fixture->credential,
    .credential_generation = field == 6 ? 10 : 9,
    .issued_at = field == 7 ? fixture->now - 301 : fixture->now,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256_service (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_sign_crossed (SoupServer *server,
    const ServiceResolverFixture *sid_source,
    const ServiceResolverFixture *jti_source)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return NULL;
  wyl_jwt_service_issue_input_t input = {
    .key_id = sid_source->key_id,.jti = jti_source->jti,
    .subject = "svc:resolver:test",.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = "__wr_default",
    .session_id = sid_source->sid,
    .credential_id = sid_source->credential,
    .credential_generation = 9,.issued_at = sid_source->now,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256_service (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_sign_json (SoupServer *server, const gchar *payload,
    const guint8 *secret_override)
{
  guint8 secret[32] = { 0 };
  if (secret_override != NULL)
    memcpy (secret, secret_override, sizeof secret);
  else if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return NULL;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  g_autofree gchar *header = g_strdup_printf
        ("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"%s\"}", key_id);
  g_autofree gchar *header_segment = NULL;
  g_autofree gchar *payload_segment = NULL;
  g_autofree gchar *signing_input = NULL;
  g_autofree gchar *signature_segment = NULL;
  gchar *token = NULL;
  if (key_id == NULL
      || wyl_jwt_base64url_encode ((const guint8 *) header, strlen (header),
      &header_segment) != WYRELOG_E_OK
      || wyl_jwt_base64url_encode ((const guint8 *) payload, strlen (payload),
      &payload_segment) != WYRELOG_E_OK)
    goto out;
  signing_input = g_strdup_printf ("%s.%s", header_segment, payload_segment);
  guint8 signature[crypto_auth_hmacsha256_BYTES] = { 0 };
  crypto_auth_hmacsha256_state state;
  crypto_auth_hmacsha256_init (&state, secret, sizeof secret);
  crypto_auth_hmacsha256_update (&state, (const guint8 *) signing_input,
      strlen (signing_input));
  crypto_auth_hmacsha256_final (&state, signature);
  if (wyl_jwt_base64url_encode (signature, sizeof signature,
      &signature_segment) == WYRELOG_E_OK)
    token = g_strdup_printf ("%s.%s", signing_input, signature_segment);
  sodium_memzero (signature, sizeof signature);
out:
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gchar *
service_resolver_json (const ServiceResolverFixture *fixture,
    const gchar *service_tail, gint64 nbf)
{
  return g_strdup_printf
           ("{\"jti\":\"%s\",\"sub\":\"svc:resolver:test\","
             "\"iss\":\"wyrelogd\",\"aud\":\"wyrelog-client\","
             "\"iat\":%" G_GINT64_FORMAT ",\"nbf\":%" G_GINT64_FORMAT ","
             "\"exp\":%" G_GINT64_FORMAT ",\"tenant\":\"__wr_default\","
             "\"principal_state_at_issue\":\"authenticated\",\"sid\":\"%s\"%s}",
             fixture->jti, fixture->now, nbf, fixture->now + 300, fixture->sid,
             service_tail);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  SoupServer *server;
  const ServiceResolverFixture *fixture;
  gboolean published;
  gboolean allow_release;
  gboolean released;
  gboolean allow_continue;
  gboolean writer_acquired;
  gboolean allow_writer_finish;
  gboolean inverse_mutation;
  gboolean mutate_requested;
  gboolean mutation_done;
  wyrelog_error_t mutation_rc;
  wyrelog_error_t resolver_rc;
  wyrelog_error_t writer_rc;
  gchar *sid;
  gchar *actor;
  gchar *tenant;
} ServiceResolverRace;

#ifdef WYL_HAS_AUDIT
typedef struct
{
  wyl_service_credential_issue_result_t issued;
  gchar *token_a;
  gchar *token_b;
} ActualServiceTokens;

static void
actual_service_tokens_clear (ActualServiceTokens *tokens)
{
  if (tokens == NULL)
    return;
  wyl_service_credential_issue_result_clear (&tokens->issued);
  g_clear_pointer (&tokens->token_a, g_free);
  g_clear_pointer (&tokens->token_b, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (ActualServiceTokens,
    actual_service_tokens_clear);

static gboolean
actual_service_tokens_init (SoupServer *server, const gchar *subject,
    const gchar *tenant, const gchar *request_id, ActualServiceTokens *tokens)
{
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  if (handle == NULL || tokens == NULL
      || wyl_service_credential_issue (handle, subject, tenant, "admin",
      request_id, 0, &tokens->issued) != WYRELOG_E_OK)
    return FALSE;
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (tokens->issued.secret, &secret_len);
  g_autofree gchar *body_a = NULL;
  g_autofree gchar *body_b = NULL;
  if (secret == NULL || secret_len == 0
      || wyl_daemon_http_publish_service_token_for_test (server,
      tokens->issued.credential.credential_id, secret, secret_len,
      &body_a) != WYRELOG_E_OK
      || wyl_daemon_http_publish_service_token_for_test (server,
      tokens->issued.credential.credential_id, secret, secret_len,
      &body_b) != WYRELOG_E_OK)
    return FALSE;
  tokens->token_a = extract_json_string (body_a, "access_token");
  tokens->token_b = extract_json_string (body_b, "access_token");
  return tokens->token_a != NULL && tokens->token_b != NULL
         && g_strcmp0 (tokens->token_a, tokens->token_b) != 0;
}

static gboolean
actual_service_token_expect (SoupServer *server, const gchar *token,
    const gchar *subject, const gchar *tenant, gboolean success)
{
  g_autofree gchar *sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *resolved_tenant = NULL;
  wyrelog_error_t rc = wyl_daemon_http_resolve_bearer_for_test (server, token,
          &sid, &actor, &resolved_tenant);
  if (!success)
    return rc == WYRELOG_E_POLICY && sid == NULL && actor == NULL
           && resolved_tenant == NULL;
  return rc == WYRELOG_E_OK && sid != NULL
         && g_strcmp0 (actor, subject) == 0
         && g_strcmp0 (resolved_tenant, tenant) == 0;
}
#endif

typedef struct
{
  GMutex mutex;
  GCond changed;
  SoupServer *server;
  const gchar *request_id;
  const gchar *tenant_id;
  const gchar *credential_id;
  guint64 credential_generation;
  gboolean credential_rotate;
  gboolean tenant_mutation;
  gboolean acquired;
  gboolean release;
  wyrelog_error_t rc;
} CompoundDisableRace;

static void
compound_disable_after_write_acquired (gpointer data)
{
  CompoundDisableRace *race = data;
  g_mutex_lock (&race->mutex);
  race->acquired = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->release)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);
}

static gpointer
compound_disable_thread (gpointer data)
{
  CompoundDisableRace *race = data;
  if (race->credential_id != NULL && race->credential_rotate) {
    race->rc = wyl_daemon_http_rotate_service_credential_for_test
          (race->server, race->credential_id, race->credential_generation,
            race->request_id, compound_disable_after_write_acquired, race);
  } else if (race->credential_id != NULL)
    race->rc = wyl_daemon_http_revoke_service_credential_for_test
          (race->server, race->credential_id, race->request_id,
            compound_disable_after_write_acquired, race);
  else if (race->tenant_mutation)
    race->rc = wyl_daemon_http_seal_tenant_for_test (race->server,
            race->tenant_id, compound_disable_after_write_acquired, race);
  else
    race->rc = wyl_daemon_http_disable_service_principal_for_test
          (race->server, "svc:resolver:test", race->request_id,
            compound_disable_after_write_acquired, race);
  return NULL;
}

static void
service_resolver_race_checkpoint (WylDaemonServiceResolverPhase phase,
    gpointer data)
{
  ServiceResolverRace *race = data;
  g_mutex_lock (&race->mutex);
  if (phase == WYL_DAEMON_SERVICE_RESOLVER_PUBLISHED) {
    race->published = TRUE;
    g_cond_broadcast (&race->changed);
    while (!race->allow_release)
      g_cond_wait (&race->changed, &race->mutex);
  } else {
    race->released = TRUE;
    g_cond_broadcast (&race->changed);
    while (!race->allow_continue)
      g_cond_wait (&race->changed, &race->mutex);
  }
  g_mutex_unlock (&race->mutex);
}

static gpointer
service_resolver_race_thread (gpointer data)
{
  ServiceResolverRace *race = data;
  race->resolver_rc = wyl_daemon_http_resolve_bearer_for_test (race->server,
          race->fixture->token, &race->sid, &race->actor, &race->tenant);
  return NULL;
}

static gpointer service_resolver_writer_thread (gpointer data);
static gboolean service_resolver_wait_flag (ServiceResolverRace * race,
    gboolean * flag);

static void
service_resolver_writer_checkpoint (gpointer data)
{
  ServiceResolverRace *race = data;
  g_mutex_lock (&race->mutex);
  race->writer_acquired = TRUE;
  g_cond_broadcast (&race->changed);
  while (race->inverse_mutation && !race->mutate_requested)
    g_cond_wait (&race->changed, &race->mutex);
  if (race->inverse_mutation) {
    g_mutex_unlock (&race->mutex);
    gboolean changed = FALSE;
    race->mutation_rc = wyl_daemon_http_service_registry_transition_for_test
          (race->server, race->fixture->sid, race->fixture->jti,
            race->fixture->credential, 9, "svc:resolver:test", "__wr_default",
            WYL_DAEMON_SERVICE_REGISTRY_REVOKE, &changed);
    if (race->mutation_rc == WYRELOG_E_OK && !changed)
      race->mutation_rc = WYRELOG_E_INTERNAL;
    g_mutex_lock (&race->mutex);
    race->mutation_done = TRUE;
    g_cond_broadcast (&race->changed);
  }
  while (!race->allow_writer_finish)
    g_cond_wait (&race->changed, &race->mutex);
  g_mutex_unlock (&race->mutex);
}

static gboolean
service_resolver_wait_reader_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.writer_active && snapshot.waiting_readers == 1
        && snapshot.active_readers == 0)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
check_service_resolver_inverse_barrier (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,.inverse_mutation = TRUE,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
    .mutation_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("inverse-write-holder",
          service_resolver_writer_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.writer_acquired);
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    resolver = g_thread_new ("inverse-service-resolver",
            service_resolver_race_thread, &race);
    ok = service_resolver_wait_reader_queued (server);
  }
  g_mutex_lock (&race.mutex);
  race.mutate_requested = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.mutation_done)
      && race.mutation_rc == WYRELOG_E_OK;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  ok = ok && race.writer_rc == WYRELOG_E_OK
      && race.resolver_rc == WYRELOG_E_POLICY && race.sid == NULL
      && race.actor == NULL && race.tenant == NULL
      && snapshot.active_readers == 0 && snapshot.waiting_readers == 0
      && !snapshot.writer_active;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gpointer
service_resolver_writer_thread (gpointer data)
{
  ServiceResolverRace *race = data;
  race->writer_rc = wyl_daemon_http_policy_write_for_test (race->server,
          service_resolver_writer_checkpoint, race);
  return NULL;
}

static gboolean
service_resolver_wait_flag (ServiceResolverRace *race, gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&race->mutex);
  while (!*flag && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  gboolean reached = *flag;
  g_mutex_unlock (&race->mutex);
  return reached;
}

static gboolean
compound_disable_wait_acquired (CompoundDisableRace *race)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&race->mutex);
  while (!race->acquired
      && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  gboolean acquired = race->acquired;
  g_mutex_unlock (&race->mutex);
  return acquired;
}

typedef struct
{
  SoupServer *server;
  const gchar *token;
  wyrelog_error_t rc;
  gchar *sid;
  gchar *actor;
  gchar *tenant;
} ServiceResolverCall;

static gpointer
service_resolver_call_thread (gpointer data)
{
  ServiceResolverCall *call = data;
  call->rc = wyl_daemon_http_resolve_bearer_for_test (call->server,
          call->token, &call->sid, &call->actor, &call->tenant);
  return NULL;
}

#ifdef WYL_HAS_AUDIT
static gboolean
check_compound_disable_real_resolver_and_activation (SoupServer *server)
{
  g_auto (ActualServiceTokens) active = { 0 };
  if (!actual_service_tokens_init (server, "svc:resolver:test",
      "__wr_default", "resolver-compound-disable-credential", &active)
      || !actual_service_token_expect (server, active.token_a,
      "svc:resolver:test", "__wr_default", TRUE)
      || !actual_service_token_expect (server, active.token_b,
      "svc:resolver:test", "__wr_default", TRUE))
    return FALSE;
  g_auto (ServiceResolverFixture) transition_pending = { 0 };
  if (!service_resolver_fixture_init (server, &transition_pending,
      WYL_SERVICE_AUTH_PENDING, 0))
    return FALSE;
  CompoundDisableRace race = {
    .server = server,
    .request_id = "000000000000000000000000230",
    .rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) mutation = g_thread_new ("compound-disable",
          compound_disable_thread, &race);
  gboolean ok = compound_disable_wait_acquired (&race);
  ServiceResolverCall later = {
    .server = server,
    .token = active.token_a,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    resolver = g_thread_new ("compound-later-resolver",
            service_resolver_call_thread, &later);
    ok = service_resolver_wait_reader_queued (server);
  }
  g_mutex_lock (&race.mutex);
  race.release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&mutation));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  ok = ok && race.rc == WYRELOG_E_OK && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && actual_service_token_expect (server, active.token_a,
          "svc:resolver:test", "__wr_default", FALSE)
      && actual_service_token_expect (server, active.token_b,
          "svc:resolver:test", "__wr_default", FALSE);
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);

  gboolean changed = TRUE;
  if (!ok
      || wyl_daemon_http_service_registry_transition_for_test (server,
      transition_pending.sid, transition_pending.jti,
      transition_pending.credential, 9,
      "svc:resolver:test", "__wr_default",
      WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_POLICY
      || changed || !service_resolver_expect (server, &transition_pending,
      transition_pending.token, FALSE))
    return FALSE;

  /* A fresh keyed no-op against the already disabled principal must not arm
   * another selector.  This synthetic post-transition PENDING tuple can
   * therefore activate: test-only insertion bypasses #358's authority-checked
   * production publication boundary, while #372 owns first-transition
   * invalidation and deliberately does not turn no-op receipts into tombstones. */
  g_auto (ServiceResolverFixture) noop_pending = { 0 };
  changed = FALSE;
  if (!service_resolver_fixture_init (server, &noop_pending,
      WYL_SERVICE_AUTH_PENDING, 0)
      || wyl_daemon_http_disable_service_principal_for_test (server,
      "svc:resolver:test", "000000000000000000000000231", NULL,
      NULL) != WYRELOG_E_OK
      || wyl_daemon_http_service_registry_transition_for_test (server,
      noop_pending.sid, noop_pending.jti, noop_pending.credential, 9,
      "svc:resolver:test", "__wr_default",
      WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_OK
      || !changed || !service_resolver_expect (server, &noop_pending,
      noop_pending.token, TRUE))
    return FALSE;
  changed = FALSE;
  if (wyl_daemon_http_service_registry_transition_for_test (server,
      noop_pending.sid, noop_pending.jti, noop_pending.credential, 9,
      "svc:resolver:test", "__wr_default",
      WYL_DAEMON_SERVICE_REGISTRY_REMOVE, &changed) != WYRELOG_E_OK
      || !changed)
    return FALSE;
  return TRUE;
}

static gboolean
check_compound_tenant_real_resolver_and_activation (SoupServer *server)
{
  const gchar *tenant = "tenant-compound";
  const gchar *subject = "svc:tenant-compound:resolver";
  if (wyl_daemon_http_configure_tenant_for_test (server, tenant, TRUE,
      FALSE) != WYRELOG_E_OK)
    return FALSE;
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  wyl_service_principal_t principal = { 0 };
  wyrelog_error_t principal_rc = handle != NULL ?
      wyl_service_principal_create (handle, subject, "Tenant compound resolver",
          "admin", "resolver-compound-tenant-principal", &principal) :
      WYRELOG_E_INVALID;
  wyl_service_principal_clear (&principal);
  if (principal_rc != WYRELOG_E_OK)
    return FALSE;
  g_auto (ActualServiceTokens) active = { 0 };
  if (!actual_service_tokens_init (server, subject, tenant,
      "resolver-compound-tenant-credential", &active)
      || !actual_service_token_expect (server, active.token_a,
      subject, tenant, TRUE)
      || !actual_service_token_expect (server, active.token_b,
      subject, tenant, TRUE))
    return FALSE;
  /* A token that is still PENDING when the first sealing transition commits
   * must inherit that transition's selector.  A later ACTIVATE therefore
   * cannot escape the retirement barrier. */
  g_auto (ServiceResolverFixture) transition_pending = { 0 };
  if (!service_resolver_fixture_init_tenant (server, &transition_pending,
      WYL_SERVICE_AUTH_PENDING, 0, tenant))
    return FALSE;
  CompoundDisableRace race = {
    .server = server,
    .tenant_id = tenant,
    .tenant_mutation = TRUE,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) mutation = g_thread_new ("compound-tenant-seal",
          compound_disable_thread, &race);
  gboolean ok = compound_disable_wait_acquired (&race);
  ServiceResolverCall later = {
    .server = server,
    .token = active.token_a,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    resolver = g_thread_new ("compound-tenant-later-resolver",
            service_resolver_call_thread, &later);
    ok = service_resolver_wait_reader_queued (server);
  }
  g_mutex_lock (&race.mutex);
  race.release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&mutation));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  ok = ok && race.rc == WYRELOG_E_OK && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && actual_service_token_expect (server, active.token_a,
          subject, tenant, FALSE)
      && actual_service_token_expect (server, active.token_b,
          subject, tenant, FALSE);
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);

  gboolean changed = TRUE;
  if (!ok
      || wyl_daemon_http_service_registry_transition_for_test (server,
      transition_pending.sid, transition_pending.jti,
      transition_pending.credential, 9,
      "svc:resolver:test", tenant,
      WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_POLICY
      || changed || !service_resolver_expect (server, &transition_pending,
      transition_pending.token, FALSE))
    return FALSE;

  /* A fresh request key against an already sealed tenant is an authorized
   * no-op receipt and deliberately creates no new selector.  Prove that a
   * PENDING tuple introduced after the transition can still activate; bearer
   * resolution remains denied independently because the tenant is sealed. */
  g_auto (ServiceResolverFixture) noop_pending = { 0 };
  changed = FALSE;
  if (!service_resolver_fixture_init_tenant (server, &noop_pending,
      WYL_SERVICE_AUTH_PENDING, 0, tenant)
      || wyl_daemon_http_seal_tenant_for_test (server, tenant, NULL,
      NULL) != WYRELOG_E_OK
      || wyl_daemon_http_service_registry_transition_for_test (server,
      noop_pending.sid, noop_pending.jti, noop_pending.credential, 9,
      "svc:resolver:test", tenant,
      WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) != WYRELOG_E_OK
      || !changed || !service_resolver_expect (server, &noop_pending,
      noop_pending.token, FALSE))
    return FALSE;
  return TRUE;
}

static gboolean
check_compound_credential_real_resolver_operation (SoupServer *server,
    gboolean rotate)
{
  g_auto (ActualServiceTokens) active = { 0 };
  if (!actual_service_tokens_init (server, "svc:resolver:test",
      "__wr_default", rotate ? "resolver-credential-rotate-issue" :
      "resolver-credential-revoke-issue", &active)
      || !actual_service_token_expect (server, active.token_a,
      "svc:resolver:test", "__wr_default", TRUE)
      || !actual_service_token_expect (server, active.token_b,
      "svc:resolver:test", "__wr_default", TRUE))
    return FALSE;
  gboolean ok = TRUE;
  g_auto (ServiceResolverFixture) pending = { 0 };
  ok = ok && service_resolver_fixture_init_tenant_credential (server,
          &pending, WYL_SERVICE_AUTH_PENDING, 0, "__wr_default",
          active.issued.credential.credential_id,
          active.issued.credential.generation);
  CompoundDisableRace race = {
    .server = server,
    .request_id = rotate ? "resolver-credential-rotate" :
        "resolver-credential-revoke",
    .credential_id = active.issued.credential.credential_id,
    .credential_generation = active.issued.credential.generation,
    .credential_rotate = rotate,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) mutation = NULL;
  ServiceResolverCall later = {
    .server = server,
    .token = active.token_a,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    mutation = g_thread_new (rotate ? "compound-credential-rotate" :
            "compound-credential-revoke", compound_disable_thread, &race);
    ok = compound_disable_wait_acquired (&race);
  }
  if (ok) {
    resolver = g_thread_new ("compound-credential-later-resolver",
            service_resolver_call_thread, &later);
    ok = service_resolver_wait_reader_queued (server);
  }
  g_mutex_lock (&race.mutex);
  race.release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  if (mutation != NULL)
    g_thread_join (g_steal_pointer (&mutation));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  ok = ok && race.rc == WYRELOG_E_OK && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && actual_service_token_expect (server, active.token_a,
          "svc:resolver:test", "__wr_default", FALSE)
      && actual_service_token_expect (server, active.token_b,
          "svc:resolver:test", "__wr_default", FALSE);
  gboolean changed = TRUE;
  ok = ok
      && wyl_daemon_http_service_registry_transition_for_test (server,
          pending.sid, pending.jti, pending.credential,
          active.issued.credential.generation, "svc:resolver:test", "__wr_default",
          WYL_DAEMON_SERVICE_REGISTRY_ACTIVATE, &changed) == WYRELOG_E_POLICY
      && !changed
      && service_resolver_expect (server, &pending, pending.token, FALSE);
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gboolean
check_compound_credential_real_resolver (SoupServer *server)
{
  return check_compound_credential_real_resolver_operation (server, FALSE)
         && check_compound_credential_real_resolver_operation (server, TRUE);
}
#endif

static gboolean
service_resolver_wait_writer_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.waiting_writers == 1 && snapshot.active_readers == 1
        && !snapshot.writer_active)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
service_resolver_rejects_before_read (SoupServer *server, const gchar *token)
{
  ServiceResolverRace writer = {
    .server = server,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&writer.mutex);
  g_cond_init (&writer.changed);
  g_autoptr (GThread) thread = g_thread_new ("pre-read-write-holder",
          service_resolver_writer_thread, &writer);
  gboolean ok = service_resolver_wait_flag (&writer,
          &writer.writer_acquired);
  WylServiceAuthAuthoritySnapshot before = { 0 }, after = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &before);
  g_autofree gchar *sid = NULL, *actor = NULL, *tenant = NULL;
  wyrelog_error_t rc = wyl_daemon_http_resolve_bearer_for_test (server,
          token, &sid, &actor, &tenant);
  wyl_daemon_http_service_authority_snapshot_for_test (server, &after);
  ok = ok && rc == WYRELOG_E_POLICY && sid == NULL && actor == NULL
      && tenant == NULL && before.writer_active && after.writer_active
      && before.active_readers == 0 && after.active_readers == 0
      && before.waiting_readers == 0 && after.waiting_readers == 0;
  g_mutex_lock (&writer.mutex);
  writer.allow_writer_finish = TRUE;
  g_cond_broadcast (&writer.changed);
  g_mutex_unlock (&writer.mutex);
  g_thread_join (g_steal_pointer (&thread));
  ok = ok && writer.writer_rc == WYRELOG_E_OK;
  g_cond_clear (&writer.changed);
  g_mutex_clear (&writer.mutex);
  return ok;
}

static gboolean
check_service_resolver_crypto_pre_read (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  if (!service_resolver_expect (server, fixture, fixture->token, TRUE))
    return FALSE;
  g_autofree gchar *tampered = g_strdup (fixture->token);
  gchar *signature = strrchr (tampered, '.');
  if (signature == NULL || signature[1] == '\0')
    return FALSE;
  signature[1] = signature[1] == 'A' ? 'B' : 'A';
  guint8 wrong_secret[32];
  memset (wrong_secret, 0xa5, sizeof wrong_secret);
  g_autofree gchar *valid_tail = g_strdup_printf
        (",\"auth_method\":\"service_credential\",\"credential_id\":\"%s\","
          "\"credential_generation\":9", fixture->credential);
  g_autofree gchar *payload = service_resolver_json (fixture, valid_tail,
          fixture->now);
  g_autofree gchar *wrong_secret_token = service_resolver_sign_json (server,
          payload, wrong_secret);
  g_autofree gchar *future_payload = service_resolver_json (fixture,
          valid_tail, fixture->now + 60);
  g_autofree gchar *future_token = service_resolver_sign_json (server,
          future_payload, NULL);
  if (wrong_secret_token == NULL || future_token == NULL
      || !service_resolver_rejects_before_read (server, tampered)
      || !service_resolver_rejects_before_read (server, wrong_secret_token)
      || !service_resolver_rejects_before_read (server, future_token))
    return FALSE;

  const gchar *invalid_tails[] = {
    "",
    ",\"auth_method\":\"service_credential\"",
    ",\"credential_id\":\"placeholder\"",
    ",\"credential_generation\":9",
    ",\"auth_method\":\"service_credential\",\"credential_generation\":9",
    ",\"auth_method\":\"service_credential\",\"credential_id\":\"placeholder\"",
    ",\"credential_id\":\"placeholder\",\"credential_generation\":9",
    ",\"auth_method\":\"unknown\",\"credential_id\":\"placeholder\",\"credential_generation\":9",
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid_tails); i++) {
    g_autofree gchar *tail = g_strdup (invalid_tails[i]);
    if (strstr (tail, "placeholder") != NULL) {
      gchar **parts = g_strsplit (tail, "placeholder", -1);
      g_free (g_steal_pointer (&tail));
      tail = g_strjoinv (fixture->credential, parts);
      g_strfreev (parts);
    }
    g_autofree gchar *json = service_resolver_json (fixture, tail,
            fixture->now);
    g_autofree gchar *token = service_resolver_sign_json (server, json, NULL);
    if (token == NULL || !service_resolver_rejects_before_read (server, token))
      return FALSE;
  }
  const gchar *duplicates[] = { "auth_method", "credential_id",
                                "credential_generation"};
  for (guint i = 0; i < G_N_ELEMENTS (duplicates); i++) {
    g_autofree gchar *duplicate_tail = NULL;
    if (i == 0)
      duplicate_tail =
          g_strdup_printf ("%s,\"auth_method\":\"service_credential\"",
              valid_tail);
    else if (i == 1)
      duplicate_tail = g_strdup_printf ("%s,\"credential_id\":\"%s\"",
              valid_tail, fixture->credential);
    else
      duplicate_tail = g_strdup_printf ("%s,\"credential_generation\":9",
              valid_tail);
    g_autofree gchar *json = service_resolver_json (fixture, duplicate_tail,
            fixture->now);
    g_autofree gchar *token = service_resolver_sign_json (server, json, NULL);
    if (token == NULL || !service_resolver_rejects_before_read (server, token))
      return FALSE;
  }
  g_autofree gchar *comment_json = g_strdup_printf
        ("{ /* auth_method */ \"jti\":\"%s\" }", fixture->jti);
  g_autofree gchar *comment_token = service_resolver_sign_json (server,
          comment_json, NULL);
  g_autofree gchar *note_tail = g_strdup
        (",\"note\":\"auth_method credential_id credential_generation\"");
  g_autofree gchar *note_json = service_resolver_json (fixture, note_tail,
          fixture->now);
  g_autofree gchar *note_token = service_resolver_sign_json (server,
          note_json, NULL);
  return comment_token != NULL
         && service_resolver_rejects_before_read (server, comment_token)
         && note_token != NULL
         && service_resolver_rejects_before_read (server, note_token)
         && service_resolver_expect (server, fixture, fixture->token, TRUE);
}

static gboolean
check_service_resolver_publication_barrier (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server,
      service_resolver_race_checkpoint, &race);
  g_autoptr (GThread) resolver = g_thread_new ("service-resolver",
          service_resolver_race_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.published);
  g_autoptr (GThread) writer = NULL;
  if (ok) {
    writer = g_thread_new ("service-writer", service_resolver_writer_thread,
            &race);
    ok = service_resolver_wait_writer_queued (server);
  }
  g_mutex_lock (&race.mutex);
  ok = ok && !race.writer_acquired;
  race.allow_release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.released)
      && service_resolver_wait_flag (&race, &race.writer_acquired);
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  ok = ok && snapshot.active_readers == 0 && snapshot.writer_active;
  g_mutex_lock (&race.mutex);
  race.allow_continue = TRUE;
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&resolver));
  if (writer != NULL)
    g_thread_join (g_steal_pointer (&writer));
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server, NULL, NULL);
  ok = ok && race.resolver_rc == WYRELOG_E_OK
      && race.writer_rc == WYRELOG_E_OK
      && g_strcmp0 (race.sid, fixture->sid) == 0
      && g_strcmp0 (race.actor, "svc:resolver:test") == 0
      && g_strcmp0 (race.tenant, "__wr_default") == 0;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gboolean
service_resolver_wait_writer_and_reader (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.active_readers == 1 && snapshot.waiting_writers == 1
        && snapshot.waiting_readers == 1 && !snapshot.writer_active)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gboolean
check_service_resolver_writer_preference (SoupServer *server,
    const ServiceResolverFixture *fixture)
{
  ServiceResolverRace race = {
    .server = server,.fixture = fixture,.inverse_mutation = TRUE,
    .resolver_rc = WYRELOG_E_INTERNAL,.writer_rc = WYRELOG_E_INTERNAL,
    .mutation_rc = WYRELOG_E_INTERNAL,
  };
  ServiceResolverCall later = {
    .server = server,.token = fixture->token,.rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server,
      service_resolver_race_checkpoint, &race);
  g_autoptr (GThread) first = g_thread_new ("preferred-first-reader",
          service_resolver_race_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.published);
  g_autoptr (GThread) writer = NULL;
  g_autoptr (GThread) second = NULL;
  if (ok) {
    writer = g_thread_new ("preferred-writer", service_resolver_writer_thread,
            &race);
    ok = service_resolver_wait_writer_queued (server);
  }
  if (ok) {
    second = g_thread_new ("later-reader", service_resolver_call_thread,
            &later);
    ok = service_resolver_wait_writer_and_reader (server);
  }
  g_mutex_lock (&race.mutex);
  race.mutate_requested = TRUE;
  race.allow_release = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  ok = ok && service_resolver_wait_flag (&race, &race.released)
      && service_resolver_wait_flag (&race, &race.writer_acquired)
      && service_resolver_wait_flag (&race, &race.mutation_done)
      && race.mutation_rc == WYRELOG_E_OK;
  WylServiceAuthAuthoritySnapshot during = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &during);
  ok = ok && during.writer_active && during.waiting_readers == 1
      && during.active_readers == 0;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  if (writer != NULL)
    g_thread_join (g_steal_pointer (&writer));
  g_mutex_lock (&race.mutex);
  race.allow_continue = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  if (second != NULL)
    g_thread_join (g_steal_pointer (&second));
  g_thread_join (g_steal_pointer (&first));
  wyl_daemon_http_set_service_resolver_checkpoint_for_test (server, NULL, NULL);
  WylServiceAuthAuthoritySnapshot final = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &final);
  ok = ok && race.resolver_rc == WYRELOG_E_OK
      && race.writer_rc == WYRELOG_E_OK && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && final.active_readers == 0 && final.waiting_readers == 0
      && final.waiting_writers == 0 && !final.writer_active;
  g_free (race.sid);
  g_free (race.actor);
  g_free (race.tenant);
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return ok;
}

static gchar *
human_resolver_sign_variant (SoupServer *server, const gchar *sid,
    const gchar *jti, gint64 now, guint field)
{
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return NULL;
  if (field == 5)
    memset (secret, 0xa5, sizeof secret);
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  wyl_jwt_issue_input_t input = {
    .key_id = field == 1 ? "wrong-key" : key_id,.jti = jti,
    .subject = "human-resolver",
    .issuer = field == 2 ? "wrong-issuer" : "wyrelogd",
    .audience = field == 3 ? "wrong-audience" : "wyrelog-client",
    .tenant = "__wr_default",.principal_state_at_issue = "authenticated",
    .session_id = sid,.issued_at = field == 4 ? now - 301 : now,
    .ttl_seconds = 300,
  };
  gchar *token = NULL;
  if (wyl_jwt_sign_hs256 (&input, secret, sizeof secret, &token)
      != WYRELOG_E_OK)
    g_clear_pointer (&token, g_free);
  sodium_memzero (secret, sizeof secret);
  return token;
}

static gboolean
check_human_resolver_while_write_held (SoupServer *server)
{
  wyl_id_t sid_id = WYL_ID_NIL, jti_id = WYL_ID_NIL;
  gchar sid[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  guint8 secret[32] = { 0 };
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL || wyl_id_new (&sid_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&sid_id, sid, sizeof sid) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || !wyl_daemon_http_seed_human_session_for_test (server, sid,
      "human-resolver", "__wr_default")
      || !wyl_daemon_http_store_human_access_token_for_test (server, jti, sid,
      "human-resolver", "__wr_default", key_id, now, now + 300)
      || wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_issue_input_t input = {
    .key_id = key_id,.jti = jti,.subject = "human-resolver",
    .issuer = "wyrelogd",.audience = "wyrelog-client",
    .tenant = "__wr_default",
    .principal_state_at_issue = "authenticated",.session_id = sid,
    .issued_at = now,.ttl_seconds = 300,
  };
  g_autofree gchar *token = NULL;
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256 (&input, secret,
          sizeof secret, &token);
  sodium_memzero (secret, sizeof secret);
  if (sign_rc != WYRELOG_E_OK)
    return FALSE;
  ServiceResolverRace race = {
    .server = server,.writer_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  g_autoptr (GThread) writer = g_thread_new ("human-write-holder",
          service_resolver_writer_thread, &race);
  gboolean ok = service_resolver_wait_flag (&race, &race.writer_acquired);
  WylServiceAuthAuthoritySnapshot before = { 0 }, after = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &before);
  g_autofree gchar *resolved_sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  wyrelog_error_t resolve_rc = wyl_daemon_http_resolve_bearer_for_test (server,
          token, &resolved_sid, &actor, &tenant);
  wyl_daemon_http_service_authority_snapshot_for_test (server, &after);
  ok = ok && resolve_rc == WYRELOG_E_OK && before.writer_active
      && after.writer_active && before.active_readers == 0
      && after.active_readers == 0 && before.waiting_readers == 0
      && after.waiting_readers == 0 && g_strcmp0 (resolved_sid, sid) == 0
      && g_strcmp0 (actor, "human-resolver") == 0
      && g_strcmp0 (tenant, "__wr_default") == 0;
  g_mutex_lock (&race.mutex);
  race.allow_writer_finish = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  g_thread_join (g_steal_pointer (&writer));
  ok = ok && race.writer_rc == WYRELOG_E_OK;
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  for (guint field = 1; ok && field <= 5; field++) {
    g_autofree gchar *variant = human_resolver_sign_variant (server, sid,
            jti, now, field);
    ok = variant != NULL
        && service_resolver_rejects_before_read (server, variant);
  }
  if (ok) {
    g_autofree gchar *tampered = g_strdup (token);
    gchar *signature = strrchr (tampered, '.');
    ok = signature != NULL && signature[1] != '\0';
    if (ok) {
      signature[1] = signature[1] == 'A' ? 'B' : 'A';
      ok = service_resolver_rejects_before_read (server, tampered);
    }
  }
  return ok;
}

static gboolean
check_service_resolver_prelatched_unavailable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return FALSE;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,.listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts, handle,
          &error);
  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (server == NULL || !service_resolver_fixture_init (server, &fixture,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &fixture, fixture.token, TRUE)
      || wyl_daemon_http_latch_service_unavailable_for_test (server)
      != WYRELOG_E_OK
      || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
    return FALSE;

  wyl_id_t sid_id = WYL_ID_NIL, jti_id = WYL_ID_NIL;
  gchar sid[WYL_ID_STRING_BUF], jti[WYL_ID_STRING_BUF];
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  guint8 secret[32] = { 0 };
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL || wyl_id_new (&sid_id) != WYRELOG_E_OK
      || wyl_id_new (&jti_id) != WYRELOG_E_OK
      || wyl_id_format (&sid_id, sid, sizeof sid) != WYRELOG_E_OK
      || wyl_id_format (&jti_id, jti, sizeof jti) != WYRELOG_E_OK
      || !wyl_daemon_http_seed_human_session_for_test (server, sid,
      "human-after-latch", "__wr_default")
      || !wyl_daemon_http_store_human_access_token_for_test (server, jti, sid,
      "human-after-latch", "__wr_default", key_id, now, now + 300)
      || wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_issue_input_t input = {
    .key_id = key_id,.jti = jti,.subject = "human-after-latch",
    .issuer = "wyrelogd",.audience = "wyrelog-client",
    .tenant = "__wr_default",
    .principal_state_at_issue = "authenticated",.session_id = sid,
    .issued_at = now,.ttl_seconds = 300,
  };
  g_autofree gchar *human_token = NULL;
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256 (&input, secret,
          sizeof secret, &human_token);
  sodium_memzero (secret, sizeof secret);
  g_autofree gchar *resolved_sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  if (sign_rc != WYRELOG_E_OK
      || wyl_daemon_http_resolve_bearer_for_test (server, human_token,
      &resolved_sid, &actor, &tenant) != WYRELOG_E_OK
      || g_strcmp0 (resolved_sid, sid) != 0
      || g_strcmp0 (actor, "human-after-latch") != 0
      || g_strcmp0 (tenant, "__wr_default") != 0)
    return FALSE;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  return snapshot.active_readers == 0 && !snapshot.writer_active;
}

static gboolean
check_service_resolver_terminal_failure (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return FALSE;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,.listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts, handle,
          &error);
  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (server == NULL || !service_resolver_fixture_init (server, &fixture,
      WYL_SERVICE_AUTH_ACTIVE, 0))
    return FALSE;
  wyl_daemon_http_fail_next_service_resolver_read_release_for_test (server);
  if (!service_resolver_expect (server, &fixture, fixture.token, FALSE)
      || wyl_daemon_http_service_resolver_terminal_entries_for_test
        (server) != 1)
    return FALSE;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  return snapshot.active_readers == 0 && !snapshot.writer_active
         && service_resolver_expect (server, &fixture, fixture.token, FALSE)
         && wyl_daemon_http_service_resolver_terminal_entries_for_test
           (server) == 0;
}

static gboolean
check_service_resolver_conflicting_candidate (SoupServer *server)
{
  g_auto (ServiceResolverFixture) original = { 0 };
  if (!service_resolver_fixture_init (server, &original,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &original, original.token, TRUE))
    return FALSE;
  wyl_id_t sid_id = WYL_ID_NIL;
  if (wyl_id_parse (original.sid, &sid_id) != WYRELOG_E_OK)
    return FALSE;
  wyl_service_session_descriptor_t candidate_descriptor = {
    .session_id = sid_id,.jti = original.other_jti,
    .subject_id = "svc:resolver:candidate",.tenant_id = "__wr_default",
    .credential_id = original.other_credential,.credential_generation = 10,
    .issued_at_seconds = original.now,.expires_at_seconds = original.now + 300,
  };
  g_autoptr (WylSession) candidate_session = NULL;
  gboolean changed = FALSE;
  if (wyl_daemon_http_service_registry_transition_for_test (server,
      original.sid, original.other_jti, original.other_credential, 10,
      candidate_descriptor.subject_id, candidate_descriptor.tenant_id,
      WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_POLICY
      || changed
      || wyl_session_new_service_detached (&candidate_descriptor,
      &candidate_session) != WYRELOG_E_OK
      || !wyl_daemon_http_replace_session_for_test (server, original.sid,
      candidate_session)
      || !wyl_daemon_http_store_service_access_token_for_test (server,
      original.other_jti, original.sid, candidate_descriptor.subject_id,
      candidate_descriptor.tenant_id, original.key_id, original.now + 300,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
      original.other_credential, 10, FALSE))
    return FALSE;
  guint8 secret[32] = { 0 };
  if (wyl_daemon_http_copy_access_token_secret (server, secret,
      sizeof secret) != WYRELOG_E_OK)
    return FALSE;
  wyl_jwt_service_issue_input_t candidate_input = {
    .key_id = original.key_id,.jti = original.other_jti,
    .subject = candidate_descriptor.subject_id,.issuer = "wyrelogd",
    .audience = "wyrelog-client",.tenant = candidate_descriptor.tenant_id,
    .session_id = original.sid,.credential_id = original.other_credential,
    .credential_generation = 10,.issued_at = original.now,
  };
  g_autofree gchar *candidate_token = NULL;
  wyrelog_error_t sign_rc = wyl_jwt_sign_hs256_service (&candidate_input,
          secret, sizeof secret, &candidate_token);
  sodium_memzero (secret, sizeof secret);
  if (sign_rc != WYRELOG_E_OK
      || !service_resolver_expect (server, &original, candidate_token, FALSE))
    return FALSE;
  wyl_service_session_descriptor_t original_descriptor = {
    .session_id = sid_id,.jti = original.jti,
    .subject_id = "svc:resolver:test",.tenant_id = "__wr_default",
    .credential_id = original.credential,.credential_generation = 9,
    .issued_at_seconds = original.now,.expires_at_seconds = original.now + 300,
  };
  g_autoptr (WylSession) original_session = NULL;
  return wyl_session_new_service_detached (&original_descriptor,
             &original_session) == WYRELOG_E_OK
         && wyl_daemon_http_replace_session_for_test (server, original.sid,
             original_session)
         && service_resolver_expect (server, &original, original.token, TRUE);
}

#ifdef WYL_HAS_AUDIT
/* Retirement intentionally latches the service authority when an expired
 * registry tuple no longer has both live companions.  Exercise that
 * destructive fail-closed path on its own handle and daemon, so the shared
 * resolver server remains usable by the reconciliation contract that follows
 * this matrix.  `server` owns the context's retirement source and is declared
 * after `handle`, therefore the existing automatic cleanup tears it down
 * before releasing the isolated handle. */
static gint
check_service_auth_retirement_latch_isolated (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 2153;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,.listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts, handle,
          &error);
  g_auto (ServiceResolverFixture) missing = { 0 };
  if (server == NULL || !service_resolver_fixture_init (server, &missing,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !wyl_daemon_http_remove_access_token_for_test (server, missing.jti))
    return 2153;
  wyl_daemon_http_set_service_auth_clock_for_test (server, TRUE,
      missing.now + 300);
  if (wyl_daemon_http_retire_due_service_auth_for_test (server)
      == WYRELOG_E_OK)
    return 2154;
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason)
      == WYRELOG_E_OK
      || reason != WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT)
    return 2155;
  return 0;
}
#endif

static gint
check_service_bearer_resolver_contract (SoupServer *server)
{
  wyl_service_principal_t registered = { 0 };
  if (wyl_service_principal_create (wyl_daemon_http_get_handle_for_test
        (server), "svc:resolver:test", "resolver test", "admin",
      "resolver-principal-create", &registered) != WYRELOG_E_OK)
    return 1969;
  wyl_service_principal_clear (&registered);
  g_auto (ServiceResolverFixture) control = { 0 };
  if (!service_resolver_fixture_init (server, &control,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &control, control.token, TRUE))
    return 1970;
  if (!check_service_resolver_publication_barrier (server, &control))
    return 1971;
  g_auto (ServiceResolverFixture) preferred = { 0 };
  if (!service_resolver_fixture_init (server, &preferred,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &preferred, preferred.token, TRUE)
      || !check_service_resolver_writer_preference (server, &preferred))
    return 1976;
  g_auto (ServiceResolverFixture) inverse = { 0 };
  if (!service_resolver_fixture_init (server, &inverse,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &inverse, inverse.token, TRUE)
      || !check_service_resolver_inverse_barrier (server, &inverse))
    return 1972;
  if (!check_human_resolver_while_write_held (server))
    return 1973;
  if (!check_service_resolver_prelatched_unavailable ())
    return 1974;
  if (!check_service_resolver_terminal_failure ())
    return 1975;
  if (!check_service_resolver_crypto_pre_read (server, &control))
    return 1977;
  if (!check_service_resolver_conflicting_candidate (server))
    return 1978;

  /* Every signed-claim mutation has the exact ACTIVE fixture as its control. */
  for (guint field = 1; field <= 10; field++) {
    g_autofree gchar *variant = service_resolver_sign_variant (server,
            &control, field);
    if (variant == NULL || strcmp (variant, control.token) == 0
        || (field >= 7 ? !service_resolver_rejects_before_read (server, variant)
            : !service_resolver_expect (server, &control, variant, FALSE))
        || !service_resolver_expect (server, &control, control.token, TRUE))
      return 1971 + (gint) field;
  }

  /* Live access-token absence, revocation, expiry, and every tuple field. */
  for (guint field = 0; field < 12; field++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
        WYL_SERVICE_AUTH_ACTIVE, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
      return 1990 + (gint) field;
    if (field == 0) {
      if (!wyl_daemon_http_remove_access_token_for_test (server, fixture.jti))
        return 2010;
    } else if (field == 1) {
      if (!wyl_daemon_http_revoke_access_token_for_test (server, fixture.jti))
        return 2011;
    } else {
      gint token_field = field - 1;
      const gchar *text = field == 4 ? fixture.other_sid
          : field == 5 ? fixture.other_jti
          : field == 6 ? "svc:resolver:other"
          : field == 7 ? "tenant-other"
          : field == 8 ? "wrong-key"
          : field == 10 ? fixture.other_credential : NULL;
      guint64 number = field == 2 || field == 3 ? (guint64) (fixture.now - 1)
          : field == 9 ? WYL_SESSION_AUTH_METHOD_HUMAN : 10;
      if (!wyl_daemon_http_mutate_access_token_for_test (server, fixture.jti,
          token_field, text, number))
        return 2020 + (gint) field;
    }
    if (!service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2040 + (gint) field;
  }

  /* Live service-session absence/inactive and all immutable tuple/time fields. */
  const gint session_fields[] = {
    WYL_DAEMON_SERVICE_SESSION_INACTIVE,
    WYL_DAEMON_SERVICE_SESSION_AUTH_METHOD,
    WYL_DAEMON_SERVICE_SESSION_ID,
    WYL_DAEMON_SERVICE_SESSION_JTI,
    WYL_DAEMON_SERVICE_SESSION_SUBJECT,
    WYL_DAEMON_SERVICE_SESSION_TENANT,
    WYL_DAEMON_SERVICE_SESSION_CREDENTIAL,
    WYL_DAEMON_SERVICE_SESSION_GENERATION,
    WYL_DAEMON_SERVICE_SESSION_ISSUED_AT,
    WYL_DAEMON_SERVICE_SESSION_EXPIRES_AT,
  };
  for (guint i = 0; i <= G_N_ELEMENTS (session_fields); i++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
        WYL_SERVICE_AUTH_ACTIVE, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
      return 2060 + (gint) i;
    if (i == 0) {
      if (!wyl_daemon_http_remove_session_for_test (server, fixture.sid))
        return 2080;
    } else {
      gint field = session_fields[i - 1];
      const gchar *text = field == WYL_DAEMON_SERVICE_SESSION_ID
          ? fixture.other_sid
          : field == WYL_DAEMON_SERVICE_SESSION_JTI ? fixture.other_jti
          : field == WYL_DAEMON_SERVICE_SESSION_SUBJECT
          ? "svc:resolver:other"
          : field == WYL_DAEMON_SERVICE_SESSION_TENANT ? "tenant-other"
          : field == WYL_DAEMON_SERVICE_SESSION_CREDENTIAL
          ? fixture.other_credential : NULL;
      guint64 number = field == WYL_DAEMON_SERVICE_SESSION_GENERATION ? 10
          : (guint64) (fixture.now + 1);
      if (!wyl_daemon_http_mutate_service_session_for_test (server,
          fixture.sid, field, text, number))
        return 2080 + (gint) i;
    }
    if (!service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2100 + (gint) i;
  }

  /* Registry lifecycle and each exact reservation tuple component. */
  for (gint state = -1; state <= WYL_SERVICE_AUTH_REVOKED; state++) {
    if (state == WYL_SERVICE_AUTH_ACTIVE)
      continue;
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture, state, 0)
        || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2120 + state;
    /* A deliberately PENDING test tuple models an interrupted publication.
     * It has served its resolver assertion; remove it so later real exchanges
     * can correctly treat any remaining PENDING tuple as an invariant breach. */
    if (state == WYL_SERVICE_AUTH_PENDING) {
      gboolean removed_pending = FALSE;
      if (wyl_daemon_http_service_registry_transition_for_test (server,
          fixture.sid, fixture.jti, fixture.credential, 9,
          "svc:resolver:test", "__wr_default",
          WYL_DAEMON_SERVICE_REGISTRY_REMOVE, &removed_pending)
          != WYRELOG_E_OK || !removed_pending)
        return 2123;
    }
  }
  for (guint mismatch = 1; mismatch <= 6; mismatch++) {
    g_auto (ServiceResolverFixture) fixture = { 0 };
    if (!service_resolver_fixture_init (server, &fixture,
        WYL_SERVICE_AUTH_ACTIVE, mismatch)
        || !service_resolver_expect (server, &fixture, fixture.token, FALSE))
      return 2130 + (gint) mismatch;
  }
  g_auto (ServiceResolverFixture) cross_a = { 0 };
  g_auto (ServiceResolverFixture) cross_b = { 0 };
  if (!service_resolver_fixture_init (server, &cross_a,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_fixture_init (server, &cross_b,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &cross_a, cross_a.token, TRUE)
      || !service_resolver_expect (server, &cross_b, cross_b.token, TRUE))
    return 2137;
  g_autofree gchar *crossed = service_resolver_sign_crossed (server,
          &cross_a, &cross_b);
  if (crossed == NULL
      || !wyl_daemon_http_store_service_access_token_for_test (server,
      cross_b.jti, cross_a.sid, "svc:resolver:test", "__wr_default",
      cross_a.key_id, cross_a.now + 300,
      WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL, cross_a.credential, 9,
      FALSE)
      || !wyl_daemon_http_mutate_service_session_for_test (server,
      cross_a.sid, WYL_DAEMON_SERVICE_SESSION_JTI, cross_b.jti, 0)
      || !service_resolver_expect (server, &cross_a, crossed, FALSE))
    return 2138;
  g_auto (ServiceResolverFixture) removed = { 0 };
  gboolean changed = FALSE;
  if (!service_resolver_fixture_init (server, &removed,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || !service_resolver_expect (server, &removed, removed.token, TRUE)
      || wyl_daemon_http_service_registry_transition_for_test (server,
      removed.sid, removed.jti, removed.credential, 9,
      "svc:resolver:test", "__wr_default",
      WYL_DAEMON_SERVICE_REGISTRY_REMOVE, &changed) != WYRELOG_E_OK
      || !changed
      || !service_resolver_expect (server, &removed, removed.token, FALSE))
    return 2140;
  g_auto (ServiceResolverFixture) duplicate = { 0 };
  if (!service_resolver_fixture_init (server, &duplicate,
      WYL_SERVICE_AUTH_ACTIVE, 0)
      || wyl_daemon_http_service_registry_transition_for_test (server,
      duplicate.sid, duplicate.jti, duplicate.other_credential, 10,
      "svc:resolver:other", "tenant-other",
      WYL_DAEMON_SERVICE_REGISTRY_RESERVE, &changed) != WYRELOG_E_POLICY
      || !service_resolver_expect (server, &duplicate, duplicate.token, TRUE))
    return 2141;

  g_auto (ServiceResolverFixture) sealed = { 0 };
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
      TRUE, FALSE) != WYRELOG_E_OK
      || !service_resolver_fixture_init_tenant (server, &sealed,
      WYL_SERVICE_AUTH_ACTIVE, 0, "tenant-sealed"))
    return 2144;
  if (!service_resolver_expect (server, &sealed, sealed.token, TRUE))
    return 2145;
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
      FALSE, TRUE)
      != WYRELOG_E_OK)
    return 2146;
  if (!service_resolver_expect (server, &sealed, sealed.token, FALSE))
    return 2147;
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-sealed",
      FALSE, FALSE)
      != WYRELOG_E_OK)
    return 2148;
  if (!service_resolver_expect (server, &sealed, sealed.token, TRUE))
    return 2149;
#if defined(WYL_HAS_AUDIT) && !defined(WYL_TEST_VARIANT_SERVICE)
  /* The service variant deliberately forbids plaintext credential issuance
   * and covers production escrow rotation separately. */
  if (!check_compound_credential_real_resolver (server))
    return 2150;
#endif
#ifdef WYL_HAS_AUDIT
  if (!check_compound_tenant_real_resolver_and_activation (server))
    return 2151;
  if (!check_compound_disable_real_resolver_and_activation (server))
    return 2152;
#endif
#ifdef WYL_HAS_AUDIT
  gint retirement_latch_rc = check_service_auth_retirement_latch_isolated ();
  if (retirement_latch_rc != 0)
    return retirement_latch_rc;
#endif
  return 0;
}

/*
 * #740 WALL 1 end-to-end: a genuine, FULLY validated live service (svc:)
 * bearer authorises through the real HTTP /decide route only because the
 * daemon injects a transient principal_state fact for it. This mints a
 * real service bearer (live detached session + ACTIVE registry
 * reservation + stored access token + signed JWT, all asserted by
 * service_resolver_expect), seeds a role grant, an ACTIVE session scope,
 * and an armed permission for the service subject -- but NO
 * principal_state row (that fact is written only for human sessions).
 * Before the fix the decide returned decision 0 not_authenticated;
 * after the fix it returns decision 1. Validation is never faked: the
 * signal that gates the injection is set only by resolve_bearer_session's
 * fully validated service branch.
 *
 * SCOPE: the session scope is seeded active directly, so Wall 2
 * (fresh-tenant session_state seeding, #382) is deliberately not in play;
 * this asserts ONLY that the principal_state blocker (Wall 1) is cleared.
 */
static gint
check_service_bearer_decide_injects_principal_state (SoupServer *server,
    const gchar *base_url)
{
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  if (handle == NULL)
    return 2400;

  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (!service_resolver_fixture_init (server, &fixture, WYL_SERVICE_AUTH_ACTIVE,
      0)
      || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
    return 2401;

  const gchar *subject = "svc:resolver:test";
  const gchar *perm = "svc.decide.allow";
  /* Everything allow_guard_base needs EXCEPT principal_state. */
  if (insert_symbol_row2 (handle, "role_permission", "wr.svc-decide-role", perm)
      != WYRELOG_E_OK)
    return 2402;
  if (insert_symbol_row3 (handle, "member_of", subject, "wr.svc-decide-role",
      fixture.sid) != WYRELOG_E_OK)
    return 2403;
  if (insert_symbol_row2 (handle, "session_state", fixture.sid, "active")
      != WYRELOG_E_OK)
    return 2404;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 2405;
  if (insert_symbol_row4 (handle, "perm_state", subject, perm, fixture.sid,
      "armed") != WYRELOG_E_OK)
    return 2406;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* Established scope: after the fix, decision 1 (before the fix it was
   * decision 0 not_authenticated). */
  gint rc = send_raw_decide_bearer (session, "POST", base_url, subject, perm,
          fixture.sid, NULL, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 2407;
  if (strstr (body, "\"decision\":1") == NULL)
    return 2408;

  /* Freeze the scope -> still denied, on the freeze gate: the transient
   * fact clears only the authentication blocker, it never forces ALLOW. */
  if (insert_symbol_row1 (handle, "frozen", fixture.sid) != WYRELOG_E_OK)
    return 2409;
  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, subject, perm,
          fixture.sid, NULL, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 2410;
  if (strstr (body, "\"decision\":0") == NULL)
    return 2411;
  if (strstr (body, "\"deny_reason\":\"frozen\"") == NULL)
    return 2412;

  /* A revoked service token is rejected at resolve (401) and never reaches
   * decide, so no principal_state is ever asserted for it. */
  g_auto (ServiceResolverFixture) revoked = { 0 };
  if (!service_resolver_fixture_init (server, &revoked,
      WYL_SERVICE_AUTH_REVOKED, 0)
      || !service_resolver_expect (server, &revoked, revoked.token, FALSE))
    return 2413;
  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, subject, perm,
          fixture.sid, NULL, revoked.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401)
    return 2414;

  return 0;
}

/*
 * #744 Wall 2: a tenant created through the real public POST /tenants/create
 * path is now seeded with session_state(active) + wr.system_admin membership
 * for the creating admin at <tenant> scope, so the admin can grant a workload
 * role at <tenant> and a service bearer can then /decide ALLOW there -- the
 * deny->allow that #382 could not reach on the public path.  Asserts, on ONE
 * real server/handle:
 *   1. create fresh tenant (admin bearer) fires the seed;
 *   2. grant the service its workload role at <tenant> (200) -- exercises the
 *      seeded authority anchor (without the seed this decide DENIES 403);
 *   3. service bearer /decide at <tenant> -> decision:1 (deny->allow);
 *   4. cross-scope: same bearer, datalog scope __wr_default -> decision:0
 *      (the grant at <tenant> confers nothing at another scope);
 *   5. seal <tenant> -> same decide -> 400 tenant_sealed (the upstream
 *      tenant-active gate beats the seeded session_state).
 */
static gboolean seed_management_human_access_token (SoupServer * server,
    const gchar * session_id, const gchar * subject, gchar ** out_access_token);
static gint send_raw_service_principal_bearer (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, const gchar * access_token, const gchar * body,
    guint * out_status, gchar ** out_body);

static gint
check_fresh_tenant_activation_grants_and_decides (SoupServer *server,
    const gchar *base_url)
{
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  if (handle == NULL)
    return 4620;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return 4621;

  const gchar *fresh = "wl744-fresh";
  const gchar *admin = "fresh-tenant-admin";
  const gchar *svc = "svc:resolver:test";
  /* A non-"wr." role id: the reserved catalog namespace rejects upserts. */
  const gchar *role = "wl744-agent";
  /* Service-eligible: its only permission is an approved data-plane read. */
  const gchar *perm = "wr.svc.read_decision";

  /* An MFA human admin bearer at __wr_default. */
  wyl_id_t admin_sid_value = WYL_ID_NIL;
  gchar admin_session[WYL_ID_STRING_BUF] = { 0 };
  g_autofree gchar *admin_token = NULL;
  if (wyl_id_new (&admin_sid_value) != WYRELOG_E_OK
      || wyl_id_format (&admin_sid_value, admin_session, sizeof admin_session)
      != WYRELOG_E_OK
      || !seed_management_human_access_token (server, admin_session, admin,
      &admin_token))
    return 4622;

  /* Give the admin authority to CREATE a tenant: wr.system_admin carries
   * wr.tenant.manage; wr.tenant.manage is unguarded so it arms via perm_state,
   * and __wr_default needs the session anchor + authenticated principal. */
  if (wyl_policy_store_grant_role_membership (store, admin, "wr.system_admin",
      WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_policy_store_set_principal_state (store, admin, "authenticated")
      != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store, admin,
      "wr.tenant.manage", WYL_TENANT_DEFAULT, "armed") != WYRELOG_E_OK)
    return 4623;
  /* A service-eligible workload role that maps to the approved read perm. */
  if (wyl_policy_store_upsert_permission (store, perm, "service decision read",
      "basic") != WYRELOG_E_OK
      || wyl_policy_store_upsert_role (store, role, "wl744 agent")
      != WYRELOG_E_OK
      || wyl_policy_store_grant_role_permission (store, role, perm)
      != WYRELOG_E_OK || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 4624;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* (1) Create the fresh tenant through the real public path so the seed
   * fires. */
  g_autofree gchar *create_query = g_strdup_printf ("name=%s&guard_timestamp=1"
          "&guard_loc_class=trusted&guard_risk=0", fresh);
  gint rc = send_raw_service_principal_bearer (session, "POST", base_url,
          "/tenants/create", create_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL)
    return 4626;
  g_clear_pointer (&body, g_free);

  /* The validated service bearer for <tenant> (injects principal_state). The
   * tenant must already exist/be active for the resolver to bind it. */
  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (!service_resolver_fixture_init_tenant (server, &fixture,
      WYL_SERVICE_AUTH_ACTIVE, 0, fresh)
      || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
    return 4625;

  /* (2) Grant the service its workload role at <tenant> using the creating
   * admin's session.  This authorizes ONLY because the create seeded
   * wr.system_admin + session_state(active) for the admin at <tenant>; without
   * the seed the wr.policy.grant_role decide at <tenant> DENIES (403). */
  g_autofree gchar *grant_query = g_strdup_printf ("subject=%s&role=%s&scope=%s"
          "&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0", svc, role,
          fresh);
  rc = send_raw_service_principal_bearer (session, "POST", base_url,
          "/policy/roles/grant", grant_query, admin_token, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 4628;
  g_clear_pointer (&body, g_free);

  /* Make the store-durable role membership + role_permission visible to the
   * read engine. */
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 4629;

  /* #762: the service's workload perm arms with no manual perm_state row.
   * A service subject cannot hold a durable perm_state (the store rejects
   * svc:), and wr.svc.read_decision is an approved data-plane permission,
   * so wyl_decide injects the armed fact TRANSIENTLY for this validated
   * service bearer at decide -- the previous manual read-engine injection
   * is no longer needed. */

  /* (3) The service bearer now decides ALLOW at <tenant>: the seeded
   * session_state(active) is what makes <tenant> a valid decision scope,
   * and the #762 transient arming supplies the armed perm_state. */
  g_autofree gchar *fresh_tenant_query = g_strdup_printf ("tenant=%s", fresh);
  rc = send_raw_decide_bearer (session, "POST", base_url, svc, perm, fresh,
          fresh_tenant_query, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":1") == NULL)
    return 4630;
  g_clear_pointer (&body, g_free);

  /* (4) Cross-scope isolation: the SAME bearer at datalog scope __wr_default
   * has no membership there, so the grant at <tenant> confers nothing.  Keep
   * the request tenant at <tenant> so the request-tenant gate still passes. */
  rc = send_raw_decide_bearer (session, "POST", base_url, svc, perm,
          WYL_TENANT_DEFAULT, fresh_tenant_query, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"decision\":0") == NULL)
    return 4631;
  g_clear_pointer (&body, g_free);

  /* (5) Seal <tenant>: the upstream tenant-active gate returns 400 before any
   * datalog runs, even though session_state(active) is still seeded. */
  if (wyl_policy_store_set_tenant_sealed (store, fresh, TRUE) != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 4632;
  rc = send_raw_decide_bearer (session, "POST", base_url, svc, perm, fresh,
          fresh_tenant_query, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "tenant_sealed") == NULL)
    return 4633;
  g_clear_pointer (&body, g_free);

  return 0;
}

/*
 * #762 WALL 3 end-to-end: a genuine, FULLY validated live service (svc:)
 * bearer that holds an APPROVED data-plane grant authorises through the
 * real HTTP /decide route with NO durable or manually injected perm_state
 * -- the daemon-validated service branch arms the grant TRANSIENTLY at
 * decide because the action is on the approved data-plane C-list. The
 * same bearer holding a control-plane grant is NEVER armed (the C-list is
 * a closed data-plane set), so that decide denies not_armed. Nothing is
 * written to the store: the public perm_state transition path for svc:
 * still rejects, asserted separately.
 */
static gint
check_service_bearer_decide_arms_data_plane_permission (SoupServer *server,
    const gchar *base_url)
{
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  if (handle == NULL)
    return 2450;

  g_auto (ServiceResolverFixture) fixture = { 0 };
  if (!service_resolver_fixture_init (server, &fixture, WYL_SERVICE_AUTH_ACTIVE,
      0)
      || !service_resolver_expect (server, &fixture, fixture.token, TRUE))
    return 2451;

  const gchar *subject = "svc:resolver:test";
  const gchar *dp_perm = "wr.svc.read_decision";        /* approved data-plane */
  const gchar *cp_perm = "wr.policy.grant_role";        /* control-plane */
  const gchar *role = "wr.svc-762-role";
  /* Grant both perms at the fixture scope, active session, NO perm_state. */
  if (insert_symbol_row2 (handle, "role_permission", role, dp_perm)
      != WYRELOG_E_OK)
    return 2452;
  if (insert_symbol_row2 (handle, "role_permission", role, cp_perm)
      != WYRELOG_E_OK)
    return 2453;
  if (insert_symbol_row3 (handle, "member_of", subject, role, fixture.sid)
      != WYRELOG_E_OK)
    return 2454;
  if (insert_symbol_row2 (handle, "session_state", fixture.sid, "active")
      != WYRELOG_E_OK)
    return 2455;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 2456;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* (1) data-plane action -> decision:1, armed transiently by #762. */
  gint rc = send_raw_decide_bearer (session, "POST", base_url, subject, dp_perm,
          fixture.sid, NULL, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 2457;
  if (strstr (body, "\"decision\":1") == NULL)
    return 2458;
  g_clear_pointer (&body, g_free);

  /* (2) control-plane action -> decision:0 not_armed: the C-list gate
   * blocks arming even though has_permission holds. */
  rc = send_raw_decide_bearer (session, "POST", base_url, subject, cp_perm,
          fixture.sid, NULL, fixture.token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 2459;
  if (strstr (body, "\"decision\":0") == NULL)
    return 2460;
  if (strstr (body, "\"deny_reason\":\"not_armed\"") == NULL)
    return 2461;
  g_clear_pointer (&body, g_free);

  return 0;
}

static gchar *
extract_json_string (const gchar *body, const gchar *name)
{
  g_autofree gchar *prefix = g_strdup_printf ("\"%s\":\"", name);
  const gchar *start = strstr (body, prefix);
  if (start == NULL)
    return NULL;
  start += strlen (prefix);
  const gchar *end = strchr (start, '"');
  if (end == NULL)
    return NULL;
  return g_strndup (start, (gsize) (end - start));
}

static gint
verify_login_access_token (const gchar *body, const gchar *session_token,
    const gchar *username, const gchar *principal_state, SoupServer *server)
{
  g_autofree gchar *access_token = extract_json_string (body, "access_token");
  if (access_token == NULL)
    return 530;

  guint8 secret[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret)
      != WYRELOG_E_OK)
    return 531;

  g_autoptr (GBytes) payload = NULL;
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL)
    return 532;
  wyrelog_error_t rc = wyl_jwt_verify_hs256_access_token (access_token, secret,
          sizeof secret, key_id, "wyrelogd", "wyrelog-client", now, &payload);
  memset (secret, 0, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return 536;

  gsize payload_len = 0;
  const gchar *payload_data = g_bytes_get_data (payload, &payload_len);
  g_autofree gchar *payload_text = g_strndup (payload_data, payload_len);
  g_autofree gchar *expected_sub = g_strdup_printf ("\"sub\":\"%s\"",
          username);
  g_autofree gchar *expected_state =
      g_strdup_printf ("\"principal_state_at_issue\":\"%s\"",
          principal_state);
  g_autofree gchar *expected_session =
      g_strdup_printf ("\"session_id\":\"%s\"", session_token);
  const gchar *expected_tenant = "\"tenant\":\"__wr_default\"";
  if (strstr (payload_text, expected_sub) == NULL ||
      strstr (payload_text, expected_state) == NULL ||
      strstr (payload_text, expected_session) == NULL ||
      strstr (payload_text, expected_tenant) == NULL)
    return 537;
  g_autofree gchar *jti = extract_json_string (payload_text, "jti");
  if (jti == NULL || g_strcmp0 (jti, session_token) == 0)
    return 538;
  return 0;
}

static wyrelog_error_t
sign_test_access_token_with_jti (SoupServer *server, const gchar *jti,
    const gchar *session_id, const gchar *subject,
    const gchar *principal_state, const gchar *issuer, const gchar *audience,
    gint64 issued_at, gchar **out_token)
{
  if (out_token == NULL)
    return WYRELOG_E_INVALID;
  *out_token = NULL;

  guint8 secret[32];
  wyrelog_error_t rc =
      wyl_daemon_http_copy_access_token_secret (server, secret, sizeof secret);
  if (rc != WYRELOG_E_OK)
    return rc;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL) {
    memset (secret, 0, sizeof secret);
    return WYRELOG_E_INTERNAL;
  }

  wyl_jwt_issue_input_t input = {
    .key_id = key_id,
    .jti = jti,
    .subject = subject,
    .issuer = issuer,
    .audience = audience,
    .tenant = "__wr_default",
    .principal_state_at_issue = principal_state,
    .session_id = session_id,
    .issued_at = issued_at,
    .ttl_seconds = WYL_JWT_ACCESS_TTL_SECONDS,
  };
  rc = wyl_jwt_sign_hs256 (&input, secret, sizeof secret, out_token);
  memset (secret, 0, sizeof secret);
  return rc;
}

static wyrelog_error_t
sign_test_access_token (SoupServer *server, const gchar *session_id,
    const gchar *subject, const gchar *principal_state, const gchar *issuer,
    const gchar *audience, gint64 issued_at, gchar **out_token)
{
  return sign_test_access_token_with_jti (server, "test-access-token",
             session_id, subject, principal_state, issuer, audience, issued_at,
             out_token);
}

static gboolean
seed_management_human_access_token (SoupServer *server,
    const gchar *session_id, const gchar *subject, gchar **out_access_token)
{
  if (out_access_token == NULL)
    return FALSE;
  *out_access_token = NULL;
  wyl_id_t jti_id = WYL_ID_NIL;
  gchar jti[WYL_ID_STRING_BUF] = { 0 };
  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  return key_id != NULL && wyl_id_new (&jti_id) == WYRELOG_E_OK
         && wyl_id_format (&jti_id, jti, sizeof jti) == WYRELOG_E_OK
         && wyl_daemon_http_seed_mfa_human_session_for_test (server, session_id,
             subject, WYL_TENANT_DEFAULT)
         && wyl_daemon_http_store_human_access_token_for_test (server, jti,
             session_id, subject, WYL_TENANT_DEFAULT, key_id, now,
             now + WYL_JWT_ACCESS_TTL_SECONDS)
         && sign_test_access_token_with_jti (server, jti, session_id, subject,
             "authenticated", "wyrelogd", "wyrelog-client", now,
             out_access_token) == WYRELOG_E_OK;
}

static gboolean
seed_human_tokens_with_assurance (SoupServer *server, const gchar *session_id,
    const gchar *subject, const gchar *tenant, gboolean mfa_assured,
    gchar **out_access_token, gchar **out_refresh_token)
{
  if (out_access_token == NULL || out_refresh_token == NULL)
    return FALSE;
  *out_access_token = NULL;
  *out_refresh_token = NULL;
  gboolean seeded = mfa_assured ?
      wyl_daemon_http_seed_mfa_human_session_for_test (server, session_id,
          subject, tenant) :
      wyl_daemon_http_seed_human_session_for_test (server, session_id,
          subject, tenant);
  g_autoptr (WylSession) session = seeded ?
      wyl_daemon_http_ref_session (server, session_id) : NULL;
  return session != NULL
         && wyl_daemon_http_issue_human_tokens_for_test (server, session,
             session_id, subject, tenant, out_access_token, out_refresh_token)
         == WYRELOG_E_OK;
}

static gint
send_raw_logout_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 484;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = query != NULL ?
      g_strdup_printf ("%s/auth/logout?%s", root, query) :
      g_strdup_printf ("%s/auth/logout", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 485;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 486;
  gint rc = check_response_request_id_header (msg, 514);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_logout (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, guint *out_status,
    gchar **out_body)
{
  return send_raw_logout_full (session, method, base_url, query, out_status,
             out_body, NULL);
}

static gint
send_raw_logout_authorization_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *authorization,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 484;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = query != NULL ?
      g_strdup_printf ("%s/auth/logout?%s", root, query) :
      g_strdup_printf ("%s/auth/logout", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 485;
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 486;
  gint rc = check_response_request_id_header (msg, 515);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_logout_authorization (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *authorization,
    guint *out_status, gchar **out_body)
{
  return send_raw_logout_authorization_full (session, method, base_url, query,
             authorization, out_status, out_body, NULL);
}

static gint send_raw_policy_mutation (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, guint * out_status, gchar ** out_body);
static gint send_raw_policy_mutation_bearer (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, const gchar * access_token, guint * out_status,
    gchar ** out_body);
static gint send_raw_service_principal_bearer (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, const gchar * access_token, const gchar * body,
    guint * out_status, gchar ** out_body);
static wyrelog_error_t grant_policy_write_authority (WylHandle * handle,
    const gchar * subject, const gchar * scope);

typedef struct
{
  const gchar *session_id;
  const gchar *state;
  guint matches;
} SessionStateExpect;

static wyrelog_error_t
session_state_expect_cb (const gchar *session_id, const gchar *state,
    gpointer user_data)
{
  SessionStateExpect *expect = user_data;

  if (g_strcmp0 (session_id, expect->session_id) == 0 &&
      g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static gint
check_jwt_epoch_rotation_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  g_autofree gchar *key_id_before =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id_before == NULL)
    return 1840;

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  gint rc = send_raw_login (session, "POST", base_url,
          "username=rotation-user&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1841;

  g_autofree gchar *session_token = extract_json_string (body,
          "session_token");
  g_autofree gchar *access_token = extract_json_string (body, "access_token");
  g_autofree gchar *refresh_token = extract_json_string (body,
          "refresh_token");
  if (session_token == NULL || access_token == NULL || refresh_token == NULL)
    return 1842;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "rotation-user",
          "site.rotation.read", "rotation-scope", NULL, access_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 1843;

  if (wyl_daemon_http_rotate_access_token_key_for_test (server)
      != WYRELOG_E_OK)
    return 1844;

  g_autofree gchar *key_id_after =
      wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id_after == NULL || g_strcmp0 (key_id_before, key_id_after) == 0)
    return 1845;

  g_clear_pointer (&body, g_free);
  rc = send_raw_decide_bearer (session, "POST", base_url, "rotation-user",
          "site.rotation.read", "rotation-scope", NULL, access_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 1846;

  g_clear_pointer (&body, g_free);
  rc = send_raw_refresh (session, "POST", base_url, refresh_token, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 1847;

  return 0;
}

static gint
check_raw_login_contract (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  gint rc = send_raw_login (session, "GET", base_url,
          "username=login-user", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 470;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 471;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 472;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *denied_skip_request_id = NULL;
  rc = send_raw_login_full (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body,
          &denied_skip_request_id);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"login_denied\"") == NULL)
    return 473;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe denied_skip_audit = {
    .subject_id = "login-user",
    .action = "login_skip_mfa",
    .resource_id = "principal_state",
    .deny_reason = "skip_mfa_not_allowed",
    .deny_origin = "login_ingress",
    .request_id = denied_skip_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_DENY,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &denied_skip_audit) != WYRELOG_E_OK)
    return 1812;
  if (denied_skip_audit.matches != 1)
    return 1813;
#endif
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_grant_direct_permission (wyl_handle_get_policy_store
        (handle), "login-user", "wr.login.skip_mfa", "login")
      != WYRELOG_E_OK)
    return 484;
  if (wyl_policy_store_set_permission_state (wyl_handle_get_policy_store
        (handle), "login-user", "wr.login.skip_mfa", "login", "armed")
      != WYRELOG_E_OK)
    return 488;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 487;

  g_autofree gchar *skip_success_request_id = NULL;
  rc = send_raw_login_full (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body,
          &skip_success_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 485;
  g_autofree gchar *authenticated_session_token =
      extract_json_string (body, "session_token");
  if (authenticated_session_token == NULL)
    return 486;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe principal_skip_audit = {
    .subject_id = "login-user",
    .action = "login_skip_mfa",
    .resource_id = "principal_state",
    .request_id = skip_success_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &principal_skip_audit)
      != WYRELOG_E_OK)
    return 1814;
  if (principal_skip_audit.matches != 1)
    return 1815;
  AuditEventProbe session_skip_audit = {
    .subject_id = authenticated_session_token,
    .action = "session_state",
    .resource_id = "active",
    .deny_origin = "idle",
    .request_id = skip_success_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &session_skip_audit) != WYRELOG_E_OK)
    return 1816;
  if (session_skip_audit.matches != 1)
    return 1817;
#endif
  rc = verify_login_access_token (body, authenticated_session_token,
          "login-user", "authenticated", server);
  if (rc != 0)
    return rc;
  g_autofree gchar *login_access_token =
      extract_json_string (body, "access_token");
  g_autofree gchar *login_refresh_token =
      extract_json_string (body, "refresh_token");
  if (login_access_token == NULL || login_refresh_token == NULL)
    return 535;
  g_clear_pointer (&body, g_free);

  rc = check_concurrent_human_refresh_single_flight (server, base_url);
  if (rc != 0)
    return rc;
  if (!wyl_daemon_http_test_human_refresh_classifier (server))
    return 2235;
  rc = check_human_refresh_response_loss (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_prepared_expiry (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_fault_matrix (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_failure_and_clock_boundaries (server, base_url);
  if (rc != 0)
    return rc;
  rc = check_human_refresh_logout_ordering (server, base_url);
  if (rc != 0)
    return rc;

  rc = check_service_refresh_isolation (server, base_url,
          authenticated_session_token);
  if (rc != 0)
    return rc;

  rc = send_raw_refresh (session, "GET", base_url, login_refresh_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 536;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_refresh_request\"") == NULL)
    return 537;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL ||
      strstr (body, "\"access_token\":\"") == NULL ||
      strstr (body, "\"refresh_token\":\"") == NULL)
    return 538;
  g_autofree gchar *next_refresh_token =
      extract_json_string (body, "refresh_token");
  if (next_refresh_token == NULL ||
      g_strcmp0 (next_refresh_token, login_refresh_token) == 0)
    return 539;
  rc = verify_login_access_token (body, authenticated_session_token,
          "login-user", "authenticated", server);
  if (rc != 0)
    return rc;
  g_clear_pointer (&body, g_free);

  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, next_refresh_token) == NULL)
    return 540;
  g_clear_pointer (&body, g_free);

  if (!wyl_daemon_http_expire_refresh_grace_for_test (server,
      login_refresh_token))
    return 541;
  rc = send_raw_refresh (session, "POST", base_url, login_refresh_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_reuse_detected\"") == NULL)
    return 542;
  g_clear_pointer (&body, g_free);

  rc = send_raw_decide_bearer (session, "POST", base_url, "login-user",
          "wr.login.skip_mfa", "login", NULL, login_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"decide_auth_required\"") == NULL)
    return 543;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=false", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL ||
      strstr (body, "\"access_token\"") != NULL)
    return 474;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=maybe", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 481;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 482;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&skip_mfa=1", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 483;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&password=secret", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_login_request\"") == NULL)
    return 478;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&tenant=unknown", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 484;
  g_clear_pointer (&body, g_free);

  /*
   * A foreign-looking unregistered tenant literal on /auth/login
   * must fail closed with the stable wire code "tenant_invalid" and
   * HTTP 400, mirroring the /decide gate above.
   */
  rc = send_raw_login (session, "POST", base_url,
          "username=login-user&tenant=evil-co", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 513;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=login-user",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"session_token\":\"") == NULL ||
      strstr (body, "\"username\":\"login-user\"") == NULL ||
      strstr (body, "\"tenant\":\"__wr_default\"") == NULL ||
      strstr (body, "\"principal_state\":\"mfa_required\"") == NULL ||
      strstr (body, "\"session_state\":\"active\"") == NULL)
    return 475;
  g_autofree gchar *session_token = extract_json_string (body, "session_token");
  if (session_token == NULL)
    return 476;
  g_autoptr (WylSession) stored_session =
      wyl_daemon_http_ref_session (server, session_token);
  if (stored_session == NULL)
    return 477;
  g_autofree gchar *stored_username = wyl_session_dup_username (stored_session);
  if (g_strcmp0 (stored_username, "login-user") != 0)
    return 479;
  g_autofree gchar *stored_tenant = wyl_session_dup_tenant (stored_session);
  if (g_strcmp0 (stored_tenant, "__wr_default") != 0)
    return 485;
  if (wyl_daemon_http_remove_session_for_test (server, "unknown-session"))
    return 481;
  if (!wyl_daemon_http_remove_session_for_test (server, session_token))
    return 482;
  g_autoptr (WylSession) removed_session =
      wyl_daemon_http_ref_session (server, session_token);
  if (removed_session != NULL)
    return 483;
  g_clear_pointer (&body, g_free);

  g_autoptr (WylSession) unknown_session =
      wyl_daemon_http_ref_session (server, "unknown-session");
  if (unknown_session != NULL)
    return 480;

  rc = send_raw_logout (session, "GET", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 487;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 488;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, "session_token=unknown",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 489;
  g_clear_pointer (&body, g_free);

  rc = send_raw_login (session, "POST", base_url, "username=logout-user",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 490;
  g_autofree gchar *logout_session_token =
      extract_json_string (body, "session_token");
  if (logout_session_token == NULL)
    return 491;
  g_clear_pointer (&body, g_free);
  if (grant_policy_write_authority (handle, "logout-user",
      logout_session_token) != WYRELOG_E_OK)
    return 492;
  if (wyl_policy_store_upsert_permission (wyl_handle_get_policy_store (handle),
      "site.policy.read", "site policy read", "basic") != WYRELOG_E_OK)
    return 493;

  g_autofree gchar *logout_query = g_strdup_printf ("session_token=%s",
          logout_session_token);
  rc = send_raw_logout_authorization (session, "POST", base_url, logout_query,
          "Bearer ignored", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_logout_auth\"") == NULL)
    return 494;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *logout_request_id = NULL;
  rc = send_raw_logout_full (session, "POST", base_url, logout_query, &status,
          &body, &logout_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 495;
  g_autoptr (WylSession) logged_out_session =
      wyl_daemon_http_ref_session (server, logout_session_token);
  if (logged_out_session != NULL)
    return 496;
  SessionStateExpect closed_expect = {
    .session_id = logout_session_token,
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &closed_expect) != WYRELOG_E_OK)
    return 497;
  if (closed_expect.matches != 1)
    return 498;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe close_audit = {
    .subject_id = logout_session_token,
    .action = "session_state",
    .resource_id = "closed",
    .deny_origin = "active",
    .request_id = logout_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &close_audit) != WYRELOG_E_OK)
    return 1818;
  if (close_audit.matches != 1)
    return 1819;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *guarded_query = g_strdup_printf ("session_token=%s"
          "&subject=after-logout&perm=site.policy.read&scope=after-logout"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=69",
          logout_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", guarded_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 499;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, logout_query, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 500;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
          "Bearer malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 501;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  rc = send_raw_login (session, "POST", base_url,
          "username=bearer-logout-user&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 502;
  g_autofree gchar *bearer_logout_session_token =
      extract_json_string (body, "session_token");
  if (bearer_logout_session_token == NULL)
    return 503;
  g_autofree gchar *bearer_logout_access_token =
      extract_json_string (body, "access_token");
  if (bearer_logout_access_token == NULL)
    return 504;
  g_autofree gchar *bearer_logout_refresh_token =
      extract_json_string (body, "refresh_token");
  if (bearer_logout_refresh_token == NULL)
    return 524;
  g_clear_pointer (&body, g_free);
  if (grant_policy_write_authority (handle, "bearer-logout-user",
      bearer_logout_session_token) != WYRELOG_E_OK)
    return 505;

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
          "Bearer", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 506;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_logout_query = g_strdup_printf ("session_token=%s",
          bearer_logout_session_token);
  g_autofree gchar *bearer_authorization = g_strdup_printf ("Bearer %s",
          bearer_logout_access_token);
  rc = send_raw_logout_authorization (session, "POST", base_url,
          bearer_logout_query, bearer_authorization, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_logout_auth\"") == NULL)
    return 507;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_logout_request_id = NULL;
  rc = send_raw_logout_authorization_full (session, "POST", base_url, NULL,
          bearer_authorization, &status, &body, &bearer_logout_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 508;
  g_autoptr (WylSession) bearer_logged_out_session =
      wyl_daemon_http_ref_session (server, bearer_logout_session_token);
  if (bearer_logged_out_session != NULL)
    return 509;
  /*
   * Refresh token captured at login must be rejected after the
   * bearer logout completes. The teardown order in logout_handler
   * revokes refresh tokens before driving the session FSM, so the
   * window during which a captured refresh could rotate into a
   * fresh access/refresh pair is closed before the public reply
   * lands at the caller.
   */
  g_clear_pointer (&body, g_free);
  rc = send_raw_refresh (session, "POST", base_url,
          bearer_logout_refresh_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"refresh_auth_required\"") == NULL)
    return 525;
  /*
   * The logout teardown must mark the session as revoked in the
   * daemon-side gate so the store paths refuse any token state an
   * in-flight /auth/refresh might still try to insert after the
   * snapshot-walking revoke pass returned. The revoked-session set
   * is the structural fix for the residual store-after-revoke
   * window the snapshot revoke alone leaves open.
   */
  if (!wyl_daemon_http_session_is_revoked (server, bearer_logout_session_token))
    return 526;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe bearer_close_audit = {
    .subject_id = bearer_logout_session_token,
    .action = "session_state",
    .resource_id = "closed",
    .deny_origin = "active",
    .request_id = bearer_logout_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (wyl_handle_get_policy_store
        (handle), audit_event_probe_cb, &bearer_close_audit) != WYRELOG_E_OK)
    return 1820;
  if (bearer_close_audit.matches != 1)
    return 1821;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *bearer_guarded_query =
      g_strdup_printf ("subject=after-bearer-logout&perm=site.policy.read"
          "&scope=after-bearer-logout&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=69");
  rc = send_raw_policy_mutation_bearer (session, "POST", base_url,
          "/policy/permissions/grant", bearer_guarded_query,
          bearer_logout_access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 510;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout_authorization (session, "POST", base_url, NULL,
          bearer_authorization, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 511;
  g_clear_pointer (&body, g_free);

  rc = send_raw_logout (session, "POST", base_url, bearer_logout_query,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"logout_auth_required\"") == NULL)
    return 512;

  return 0;
}

static gchar *
build_policy_mutation_uri (const gchar *base_url, const gchar *path,
    const gchar *query)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  if (query == NULL)
    return g_strdup_printf ("%s%s", root, path);
  return g_strdup_printf ("%s%s?%s", root, path, query);
}

static gint
send_raw_policy_mutation_body_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *request_body, guint *out_status, gchar **out_body,
    gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;
  if (request_body != NULL) {
    g_autoptr (GBytes) bytes = g_bytes_new_static (request_body,
            strlen (request_body));
    soup_message_set_request_body_from_bytes (msg, "application/json", bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 177);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_policy_mutation_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    guint *out_status, gchar **out_body, gchar **out_request_id)
{
  return send_raw_policy_mutation_body_full (session, method, base_url, path,
             query, NULL, out_status, out_body, out_request_id);
}

static gint
send_raw_policy_mutation_body (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *request_body, guint *out_status, gchar **out_body)
{
  return send_raw_policy_mutation_body_full (session, method, base_url, path,
             query, request_body, out_status, out_body, NULL);
}

static gint
send_raw_policy_mutation (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    guint *out_status, gchar **out_body)
{
  return send_raw_policy_mutation_full (session, method, base_url, path, query,
             out_status, out_body, NULL);
}

static gint
send_raw_policy_mutation_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *access_token, guint *out_status, gchar **out_body)
{
  if (access_token == NULL)
    return 164;
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 178);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_service_principal_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *body, guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;
  if (body != NULL) {
    g_autoptr (GBytes) request_bytes = g_bytes_new_static (body, strlen (body));
    soup_message_set_request_body_from_bytes (msg, "application/json",
        request_bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 177);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

#ifdef WYL_HAS_AUDIT
typedef enum
{
  ACTUAL_ROUTE_DISABLE_PRINCIPAL,
  ACTUAL_ROUTE_SEAL_TENANT,
  ACTUAL_ROUTE_REVOKE_CREDENTIAL,
  ACTUAL_ROUTE_ROTATE_CREDENTIAL,
} ActualRetirementRoute;

typedef struct
{
  ActualRetirementRoute route;
  const gchar *base_url;
  const gchar *path;
  const gchar *query;
  const gchar *access_token;
  const gchar *request_body;
  gint rc;
  guint status;
  gchar *body;
} ActualRouteCall;

static gpointer
actual_route_call_thread (gpointer data)
{
  ActualRouteCall *call = data;
  g_autoptr (SoupSession) session = g_object_new (SOUP_TYPE_SESSION, NULL);
  if (call->route == ACTUAL_ROUTE_SEAL_TENANT)
    call->rc = send_raw_policy_mutation_body (session, "POST", call->base_url,
            call->path, call->query, call->request_body, &call->status,
            &call->body);
  else
    call->rc = send_raw_service_principal_bearer (session,
            call->route == ACTUAL_ROUTE_REVOKE_CREDENTIAL ? "DELETE" : "POST",
            call->base_url, call->path, call->query, call->access_token,
            call->request_body, &call->status, &call->body);
  return NULL;
}

static const gchar *
actual_retirement_request_body (ActualRetirementRoute route)
{
  switch (route) {
    case ACTUAL_ROUTE_DISABLE_PRINCIPAL:
      return "{\"version\":\"1\",\"request_id\":"
             "\"000000000000000000000000224\"}";
    case ACTUAL_ROUTE_SEAL_TENANT:
      return "{\"version\":\"1\",\"request_id\":"
             "\"000000000000000000000000221\"}";
    case ACTUAL_ROUTE_REVOKE_CREDENTIAL:
      return "{\"version\":\"1\",\"request_id\":"
             "\"000000000000000000000000226\"}";
    case ACTUAL_ROUTE_ROTATE_CREDENTIAL:
      return "{\"version\":\"1\",\"request_id\":"
             "\"000000000000000000000000227\","
             "\"destination\":\"route-rotate.json\","
             "\"expires_at_us\":\"" CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}";
    default:
      return NULL;
  }
}

static gboolean
actual_retirement_response_succeeded (ActualRetirementRoute route,
    const gchar *body)
{
  if (body == NULL)
    return FALSE;
  switch (route) {
    case ACTUAL_ROUTE_DISABLE_PRINCIPAL:
      return strstr (body, "\"state\":\"disabled\"") != NULL;
    case ACTUAL_ROUTE_SEAL_TENANT:
      return strstr (body, "\"changed\":true") != NULL;
    case ACTUAL_ROUTE_REVOKE_CREDENTIAL:
      return strstr (body, "\"state\":\"revoked\"") != NULL;
    case ACTUAL_ROUTE_ROTATE_CREDENTIAL:
      return strstr (body, "\"state\":\"terminal\"") != NULL
             && strstr (body, "\"delivered\":true") != NULL;
    default:
      return FALSE;
  }
}

static gboolean
actual_http_route_retirement_race (SoupServer *server, const gchar *base_url,
    const gchar *path, const gchar *query, ActualRetirementRoute route,
    const gchar *access_token, const ActualServiceTokens *tokens,
    const gchar *subject, const gchar *tenant,
    const ActualServiceTokens *unrelated, const gchar *unrelated_subject,
    const gchar *unrelated_tenant)
{
  WylHandle *handle = wyl_daemon_http_get_handle_for_test (server);
  WylServiceAuthReadLease *held = NULL;
  CompoundDisableRace write_barrier = {.server = server };
  g_mutex_init (&write_barrier.mutex);
  g_cond_init (&write_barrier.changed);
  if (handle == NULL || tokens == NULL) {
    g_cond_clear (&write_barrier.changed);
    g_mutex_clear (&write_barrier.mutex);
    return FALSE;
  }
  if (route == ACTUAL_ROUTE_ROTATE_CREDENTIAL) {
    wyl_daemon_http_set_rotate_write_checkpoint_for_test (server,
        compound_disable_after_write_acquired, &write_barrier);
  } else if (wyl_service_auth_authority_acquire_read
        (wyl_handle_get_service_auth_authority (handle), handle, NULL,
      &held) != WYRELOG_E_OK) {
    g_cond_clear (&write_barrier.changed);
    g_mutex_clear (&write_barrier.mutex);
    return FALSE;
  }
  ActualRouteCall call = {
    .route = route,
    .base_url = base_url,
    .path = path,
    .query = query,
    .access_token = access_token,
    .request_body = actual_retirement_request_body (route),
    .rc = -1,
  };
  g_autoptr (GThread) mutation = g_thread_new ("actual-http-retirement",
          actual_route_call_thread, &call);
  gboolean ok = route == ACTUAL_ROUTE_ROTATE_CREDENTIAL ?
      compound_disable_wait_acquired (&write_barrier) :
      service_resolver_wait_writer_queued (server);
  ServiceResolverCall later = {
    .server = server,
    .token = tokens->token_a,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_autoptr (GThread) resolver = NULL;
  if (ok) {
    resolver = g_thread_new ("actual-http-later-resolver",
            service_resolver_call_thread, &later);
    ok = route == ACTUAL_ROUTE_ROTATE_CREDENTIAL ?
        service_resolver_wait_reader_queued (server) :
        service_resolver_wait_writer_and_reader (server);
  }
  wyrelog_error_t release_rc = WYRELOG_E_OK;
  if (route == ACTUAL_ROUTE_ROTATE_CREDENTIAL) {
    g_mutex_lock (&write_barrier.mutex);
    write_barrier.release = TRUE;
    g_cond_broadcast (&write_barrier.changed);
    g_mutex_unlock (&write_barrier.mutex);
  } else {
    release_rc = wyl_service_auth_read_lease_release (held);
    wyl_service_auth_read_lease_free (held);
  }
  if (mutation != NULL)
    g_thread_join (g_steal_pointer (&mutation));
  if (resolver != NULL)
    g_thread_join (g_steal_pointer (&resolver));
  if (route == ACTUAL_ROUTE_ROTATE_CREDENTIAL)
    wyl_daemon_http_set_rotate_write_checkpoint_for_test (server, NULL, NULL);
  gboolean token_a_retired = actual_service_token_expect (server,
          tokens->token_a, subject, tenant, FALSE);
  gboolean token_b_retired = actual_service_token_expect (server,
          tokens->token_b, subject, tenant, FALSE);
  gboolean unrelated_a_active = unrelated == NULL
      || actual_service_token_expect (server, unrelated->token_a,
          unrelated_subject, unrelated_tenant, TRUE);
  gboolean unrelated_b_active = unrelated == NULL
      || actual_service_token_expect (server, unrelated->token_b,
          unrelated_subject, unrelated_tenant, TRUE);
  ok = ok && release_rc == WYRELOG_E_OK && call.rc == 0 && call.status == 200
      && actual_retirement_response_succeeded (route, call.body)
      && later.rc == WYRELOG_E_POLICY
      && later.sid == NULL && later.actor == NULL && later.tenant == NULL
      && token_a_retired && token_b_retired && unrelated_a_active
      && unrelated_b_active;
  ActualRouteCall replay = call;
  replay.rc = -1;
  replay.status = 0;
  replay.body = NULL;
  if (ok) {
    actual_route_call_thread (&replay);
    ok = replay.rc == 0 && replay.status == 200 && replay.body != NULL
        && g_strcmp0 (replay.body, call.body) == 0
        && (unrelated == NULL || actual_service_token_expect (server,
        unrelated->token_a, unrelated_subject, unrelated_tenant, TRUE))
        && (unrelated == NULL || actual_service_token_expect (server,
        unrelated->token_b, unrelated_subject, unrelated_tenant, TRUE));
  }
  if (!ok)
    g_printerr ("WYRELOG_TEST_DIAG retirement route=%d release=%d call_rc=%d "
        "status=%u body=%s later_rc=%d later_sid=%s later_actor=%s "
        "later_tenant=%s token_a_retired=%d token_b_retired=%d "
        "unrelated_a_active=%d unrelated_b_active=%d replay_rc=%d "
        "replay_status=%u replay_body=%s\n", route,
        release_rc, call.rc, call.status,
        call.body != NULL ? call.body : "(null)", later.rc,
        later.sid != NULL ? later.sid : "(null)",
        later.actor != NULL ? later.actor : "(null)",
        later.tenant != NULL ? later.tenant : "(null)", token_a_retired,
        token_b_retired, unrelated_a_active, unrelated_b_active, replay.rc,
        replay.status, replay.body != NULL ? replay.body : "(null)");
  g_free (later.sid);
  g_free (later.actor);
  g_free (later.tenant);
  g_free (replay.body);
  g_free (call.body);
  g_cond_clear (&write_barrier.changed);
  g_mutex_clear (&write_barrier.mutex);
  return ok;
}
#endif

#ifdef WYL_HAS_FACT_STORE
static gint
send_raw_reconcile_full (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *body,
    const gchar *access_token, guint *out_status, gchar **out_body,
    gchar **out_request_id)
{
  if (out_status == NULL || out_body == NULL)
    return 166;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  g_autofree gchar *uri = query != NULL ?
      g_strdup_printf ("%s/service-credential-operations/reconcile?%s", root,
          query) :
      g_strdup_printf ("%s/service-credential-operations/reconcile", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 167;
  if (access_token != NULL) {
    g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
            access_token);
    soup_message_headers_replace (soup_message_get_request_headers (msg),
        "Authorization", authorization);
  }
  g_autoptr (GBytes) request_bytes = g_bytes_new_static (body, strlen (body));
  soup_message_set_request_body_from_bytes (msg, "application/json",
      request_bytes);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) response_bytes = soup_session_send_and_read (session,
          msg, NULL, &error);
  if (response_bytes == NULL)
    return 168;
  gint rc = check_response_request_id_header (msg, 169);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (response_bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_reconcile (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *body,
    guint *out_status, gchar **out_body)
{
  return send_raw_reconcile_full (session, method, base_url, query, body,
             NULL, out_status, out_body, NULL);
}

static gint
send_raw_reconcile_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *query, const gchar *access_token,
    const gchar *body, guint *out_status, gchar **out_body)
{
  return send_raw_reconcile_full (session, method, base_url, query, body,
             access_token, out_status, out_body, NULL);
}
#endif

typedef struct
{
  const gchar *base_url;
  gchar *query;
  gint rc;
  guint status;
  gchar *body;
} ConcurrentPolicyMutation;

typedef struct
{
  GMutex mutex;
  GCond changed;
  guint ready;
  gboolean go;
} ConcurrentTenantMutationRace;

typedef struct
{
  ConcurrentTenantMutationRace *race;
  ConcurrentPolicyMutation mutation;
} ConcurrentTenantMutation;

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean entered;
  gboolean released;
} TenantRecoveryBarrier;

typedef struct
{
  const gchar *base_url;
  const gchar *query;
  const gchar *body;
  gint rc;
  guint status;
  gchar *response;
} TenantRecoveryRequest;

typedef struct
{
  SoupServer *server;
  const gchar *tenant;
  const gchar *request_id;
  wyrelog_error_t rc;
} TenantRecoveryOwnerRequest;

static gint tenant_recovery_detach_regression_executions;
static gint tenant_recovery_post_write_regression_executions;

static void
tenant_recovery_checkpoint (gpointer data)
{
  TenantRecoveryBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  barrier->entered = TRUE;
  g_cond_broadcast (&barrier->changed);
  while (!barrier->released)
    g_cond_wait (&barrier->changed, &barrier->mutex);
  g_mutex_unlock (&barrier->mutex);
}

static void
tenant_recovery_barrier_init (TenantRecoveryBarrier *barrier)
{
  g_mutex_init (&barrier->mutex);
  g_cond_init (&barrier->changed);
}

static gboolean
tenant_recovery_barrier_wait_entered (TenantRecoveryBarrier *barrier)
{
  gint64 deadline = g_get_monotonic_time () + 10 * G_USEC_PER_SEC;
  g_mutex_lock (&barrier->mutex);
  while (!barrier->entered)
    if (!g_cond_wait_until (&barrier->changed, &barrier->mutex, deadline))
      break;
  gboolean entered = barrier->entered;
  g_mutex_unlock (&barrier->mutex);
  return entered;
}

static void
tenant_recovery_barrier_release (TenantRecoveryBarrier *barrier)
{
  g_mutex_lock (&barrier->mutex);
  barrier->released = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
}

static void
tenant_recovery_barrier_clear (TenantRecoveryBarrier *barrier)
{
  g_cond_clear (&barrier->changed);
  g_mutex_clear (&barrier->mutex);
}

static gpointer
tenant_recovery_request_thread (gpointer data)
{
  TenantRecoveryRequest *request = data;
  g_autoptr (SoupSession) session = soup_session_new ();
  request->rc = send_raw_policy_mutation_body (session, "POST",
          request->base_url, "/tenants/seal", request->query, request->body,
          &request->status, &request->response);
  return NULL;
}

static gpointer
tenant_recovery_owner_request_thread (gpointer data)
{
  TenantRecoveryOwnerRequest *request = data;
  request->rc = wyl_daemon_http_seal_tenant_recovery_for_test
        (request->server, request->tenant, request->request_id);
  return NULL;
}

static gpointer
tenant_recovery_claim_request_thread (gpointer data)
{
  TenantRecoveryOwnerRequest *request = data;
  request->rc = wyl_daemon_http_attempt_seal_tenant_recovery_for_test
        (request->server, request->tenant, request->request_id);
  return NULL;
}

static gpointer
concurrent_permission_grant_thread (gpointer user_data)
{
  ConcurrentPolicyMutation *mutation = user_data;
  g_autoptr (SoupSession) session = soup_session_new ();

  mutation->rc = send_raw_policy_mutation (session, "POST",
          mutation->base_url, "/policy/permissions/grant", mutation->query,
          &mutation->status, &mutation->body);
  return NULL;
}

static gpointer
concurrent_tenant_create_thread (gpointer user_data)
{
  ConcurrentTenantMutation *thread = user_data;
  g_mutex_lock (&thread->race->mutex);
  thread->race->ready++;
  if (thread->race->ready == 2) {
    thread->race->go = TRUE;
    g_cond_broadcast (&thread->race->changed);
  }
  while (!thread->race->go)
    g_cond_wait (&thread->race->changed, &thread->race->mutex);
  g_mutex_unlock (&thread->race->mutex);

  g_autoptr (SoupSession) session = soup_session_new ();
  ConcurrentPolicyMutation *mutation = &thread->mutation;
  mutation->rc = send_raw_policy_mutation (session, "POST",
          mutation->base_url, "/tenants/create", mutation->query,
          &mutation->status, &mutation->body);
  return NULL;
}

static wyrelog_error_t
grant_policy_write_authority (WylHandle *handle, const gchar *subject,
    const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store, subject,
          "wr.policy.write", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
grant_policy_role_authority (WylHandle *handle, const gchar *subject,
    const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store, subject,
          "wr.policy.grant_role", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t grant_tenant_manage_authority
  (WylHandle * handle, const gchar * subject);

typedef enum
{
  POLICY_WRITE_FAULT_ROUTE_SUCCESS = 0,
  POLICY_WRITE_FAULT_ROUTE_PRIMARY_ERROR,
} PolicyWriteFaultRouteCase;

static gboolean
policy_write_fault_snapshot_is_clean
  (const WylDaemonPolicyWriteFinalizeSnapshot * snapshot,
    guint expected_primary_status, const gchar * expected_primary_code,
    guint expected_owner, const gchar * expected_owner_name,
    guint expected_cleanup_resources, guint expected_diagnostic_count,
    wyrelog_error_t expected_cleanup_rc, guint expected_acquire_fault_hits)
{
  return snapshot->diagnostic_count == expected_diagnostic_count
         && snapshot->primary_status == expected_primary_status
         && g_strcmp0 (snapshot->primary_code, expected_primary_code) == 0
         && snapshot->cleanup_rc == expected_cleanup_rc
         && snapshot->pre_finalize_status == 0
         && snapshot->pre_finalize_header_count == 0
         && snapshot->pre_finalize_body_length == 0
         && !snapshot->post_finalize_lease_live
         && !snapshot->post_finalize_store_live
         && snapshot->post_finalize_total_pins == 0
         && snapshot->post_finalize_thread_pins == 0
         && snapshot->post_finalize_rank_mask == 0
         && !snapshot->post_finalize_transaction_active
         && snapshot->observed_cleanup_resources == expected_cleanup_resources
         && snapshot->acquire_fault_hits == expected_acquire_fault_hits
         && snapshot->owner == expected_owner
         && g_strcmp0 (snapshot->owner_name, expected_owner_name) == 0;
}

static gint
check_policy_write_fault_human_surfaces (SoupServer *server,
    WylHandle *handle, const gchar *base_url, SoupSession *session,
    const gchar *actor, const gchar *session_token,
    const gchar *access_token, const gchar *refresh_token, gint error_base)
{
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (wyl_daemon_http_policy_write_for_test (server, NULL, NULL)
      != WYRELOG_E_BUSY)
    return error_base;
  if (send_raw_path (session, "GET", base_url, "/healthz", &status, &body)
      != 0 || status != 200)
    return error_base + 1;
  g_clear_pointer (&body, g_free);
  if (send_raw_decide_bearer (session, "POST", base_url, actor,
      "cleanup.unrelated.read", session_token,
      "tenant=__wr_default", access_token, &status, &body) != 0
      || status != 200)
    return error_base + 2;
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (session, "POST", base_url, refresh_token, &status,
      &body) != 0 || status != 200
      || strstr (body, "\"access_token\"") == NULL
      || strstr (body, "\"refresh_token\"") == NULL)
    return error_base + 3;
  g_clear_pointer (&body, g_free);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  gint login_rc = send_raw_login (session, "POST", base_url,
          "username=cleanup-post-fault-login&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (login_rc != 0 || status != 200
      || strstr (body, "cleanup-post-fault-login") == NULL)
    return error_base + 4;
  return 0;
}

static gint
check_policy_write_actual_route_finalize_fault
  (PolicyWriteFaultRouteCase route_case, gint error_base)
{
  static const gchar *const actor = "cleanup-route-secret-actor";
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = NULL;
  g_autoptr (SoupSession) session = NULL;
  g_autofree gchar *base_url = NULL;
  g_autofree gchar *body = NULL;
  g_autofree gchar *session_token = NULL;
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *refresh_token = NULL;
  g_autofree gchar *query = NULL;
  TestHttpServer http = { 0 };
  GThread *thread = NULL;
  gint result = error_base;

  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return result;
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  context = g_main_context_new ();
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server (&options, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    goto cleanup;
  thread = g_thread_new ("policy-write-route-fault",
          test_http_server_thread_ctx, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    goto cleanup;
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (base_url == NULL)
    goto cleanup;

  session = soup_session_new ();
  guint status = 0;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  gint login_rc = send_raw_login (session, "POST", base_url,
          "username=cleanup-route-secret-actor&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (login_rc != 0 || status != 200)
    goto cleanup;
  session_token = extract_json_string (body, "session_token");
  access_token = extract_json_string (body, "access_token");
  refresh_token = extract_json_string (body, "refresh_token");
  if (session_token == NULL || access_token == NULL || refresh_token == NULL)
    goto cleanup;
  g_clear_pointer (&body, g_free);

  const gchar *path = NULL;
  const gchar *expected_primary_code = NULL;
  const gchar *expected_owner = NULL;
  guint expected_primary_status = 0;
  if (route_case == POLICY_WRITE_FAULT_ROUTE_SUCCESS) {
    if (grant_tenant_manage_authority (handle, actor) != WYRELOG_E_OK)
      goto cleanup;
    path = "/tenants/create";
    expected_primary_status = 200;
    expected_primary_code = "success";
    expected_owner = "tenant";
    query = g_strdup_printf
          ("name=cleanup-route-secret-tenant&tenant=%s&session_token=%s"
            "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
            WYL_TENANT_DEFAULT, session_token);
  } else {
    if (grant_policy_write_authority (handle, actor, WYL_TENANT_DEFAULT)
        != WYRELOG_E_OK)
      goto cleanup;
    path = "/policy/permissions/grant";
    expected_primary_status = 400;
    expected_primary_code = "invalid_policy_mutation";
    expected_owner = "direct_permission";
    query = g_strdup_printf
          ("subject=cleanup-target&perm=cleanup.missing&scope=%s&tenant=%s"
            "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
            "&guard_risk=49", WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT,
            session_token);
  }

  guint terminal_before =
      wyl_daemon_http_policy_write_terminal_entries_for_test (http.server);
  wyl_daemon_http_fail_next_policy_write_finalize_for_test (http.server,
      WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION);
  if (send_raw_policy_mutation (session, "POST", base_url, path, query,
      &status, &body) != 0 || status != 500
      || g_strcmp0 (body, "{\"error\":\"policy_write_cleanup_failed\"}") != 0)
    goto cleanup;
  guint terminal_after =
      wyl_daemon_http_policy_write_terminal_entries_for_test (http.server);
  if (terminal_after != terminal_before + 1)
    goto cleanup;

  WylDaemonPolicyWriteFinalizeSnapshot snapshot = { 0 };
  if (!wyl_daemon_http_policy_write_finalize_snapshot_for_test (http.server,
      &snapshot)
      || !policy_write_fault_snapshot_is_clean (&snapshot,
      expected_primary_status, expected_primary_code,
      route_case == POLICY_WRITE_FAULT_ROUTE_SUCCESS ? 3 : 9,
      expected_owner,
      route_case == POLICY_WRITE_FAULT_ROUTE_SUCCESS ? 1 : 0,
      1, WYRELOG_E_INTERNAL, 0)
      || strstr (snapshot.primary_code, actor) != NULL
      || strstr (snapshot.primary_code, "cleanup-route-secret-tenant") != NULL
      || strstr (snapshot.primary_code, session_token) != NULL) {
    g_printerr ("WYRELOG_TEST_DIAG policy_write_route_snapshot "
        "case=%d diagnostics=%u primary_status=%u primary_code=%s "
        "primary_rc=%d recorded=%d cleanup=%d pre_status=%u "
        "pre_headers=%u pre_body=%zu lease=%d store=%d pins=%u/%u "
        "rank_mask=%u owner=%s\n", route_case, snapshot.diagnostic_count,
        snapshot.primary_status, snapshot.primary_code, snapshot.primary_rc,
        snapshot.primary_rc_recorded, snapshot.cleanup_rc,
        snapshot.pre_finalize_status, snapshot.pre_finalize_header_count,
        snapshot.pre_finalize_body_length, snapshot.post_finalize_lease_live,
        snapshot.post_finalize_store_live, snapshot.post_finalize_total_pins,
        snapshot.post_finalize_thread_pins, snapshot.post_finalize_rank_mask,
        snapshot.owner_name);
    goto cleanup;
  }
  if (route_case == POLICY_WRITE_FAULT_ROUTE_SUCCESS
      && (!snapshot.primary_rc_recorded || snapshot.primary_rc != WYRELOG_E_OK))
    goto cleanup;

  WylServiceAuthAuthoritySnapshot authority = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (http.server, &authority);
  if (authority.writer_active || authority.active_readers != 0
      || authority.waiting_readers != 0 || authority.waiting_writers != 0)
    goto cleanup;
  gint human_rc = check_policy_write_fault_human_surfaces (http.server,
          handle, base_url, session, actor, session_token, access_token,
          refresh_token, error_base + 10);
  if (human_rc != 0) {
    result = human_rc;
    goto cleanup;
  }
  if (wyl_daemon_http_policy_write_terminal_entries_for_test (http.server)
      != terminal_after)
    goto cleanup;
  result = 0;

cleanup:
  if (http.loop != NULL)
    g_main_loop_quit (http.loop);
  if (thread != NULL)
    g_thread_join (thread);
  if (http.server != NULL)
    soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return result;
}

static gint
check_policy_write_non_http_finalize_fault (gint error_base)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return error_base;
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&options,
          handle, &error);
  if (server == NULL)
    return error_base + 1;
  guint before = wyl_daemon_http_policy_write_terminal_entries_for_test
        (server);
  wyl_daemon_http_fail_next_policy_write_finalize_for_test (server,
      WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION);
  if (wyl_daemon_http_rotate_access_token_key_for_test (server)
      != WYRELOG_E_INTERNAL)
    return error_base + 2;
  guint after = wyl_daemon_http_policy_write_terminal_entries_for_test (server);
  WylDaemonPolicyWriteFinalizeSnapshot snapshot = { 0 };
  if (after != before + 1
      || !wyl_daemon_http_policy_write_finalize_snapshot_for_test (server,
      &snapshot)
      || !policy_write_fault_snapshot_is_clean (&snapshot, 0, "non_http",
      0, "key_rotation", WYL_DAEMON_POLICY_WRITE_RESOURCE_MAINTENANCE
      | WYL_DAEMON_POLICY_WRITE_RESOURCE_CONTEXT
      | WYL_DAEMON_POLICY_WRITE_RESOURCE_REGISTRY, 1, WYRELOG_E_INTERNAL, 0)
      || !snapshot.primary_rc_recorded || snapshot.primary_rc != WYRELOG_E_OK)
    return error_base + 3;
  if (wyl_daemon_http_policy_write_for_test (server, NULL, NULL)
      != WYRELOG_E_BUSY
      || wyl_daemon_http_policy_write_terminal_entries_for_test (server)
      != after)
    return error_base + 4;
  soup_server_disconnect (server);
  return 0;
}

static gint
check_policy_write_actual_owner_finalize_contract (void)
{
  /* Keep fast base/audit probes for a simple success, a primary error after
   * WRITE acquisition, and a higher-ranked non-HTTP owner. The fact-enabled
   * service variant runs the complete 16-owner dynamic matrix. */
  gint rc = check_policy_write_actual_route_finalize_fault
        (POLICY_WRITE_FAULT_ROUTE_SUCCESS, 2800);
  if (rc != 0)
    return rc;
  rc = check_policy_write_actual_route_finalize_fault
        (POLICY_WRITE_FAULT_ROUTE_PRIMARY_ERROR, 2820);
  if (rc != 0)
    return rc;
  rc = check_policy_write_non_http_finalize_fault (2840);
  if (rc != 0)
    return rc;
  /* A newly constructed handle/coordinator is the only recovery boundary. */
  return check_daemon_policy_write_finalize_case
           (WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_NONE, WYRELOG_E_OK, 2860);
}

/* ------------------------------------------------------------------------- */
/* #761: policy WRITE acquisition is request-cancellable.                     */
/*                                                                            */
/* WylDaemonPolicyWriteCancel is internal to http.c; its wire values are      */
/* frozen by the for-test getter contract (0 none, 1 client-disconnect,       */
/* 2 shutdown). */
#define POLICY_WRITE_CANCEL_NONE 0
#define POLICY_WRITE_CANCEL_CLIENT_DISCONNECT 1
#define POLICY_WRITE_CANCEL_SHUTDOWN 2

typedef struct
{
  const gchar *base_url;
  const gchar *path;
  const gchar *query;
  GMutex mutex;
  GCond changed;
  gboolean sent;                /* request written to the wire */
  gboolean release;             /* main loop said: proceed */
  gboolean read_response;       /* TRUE reads the reply, FALSE closes cold */
  gboolean done;
  guint status;
  gchar *body;
  gint rc;
} RawParkedRequest;

/* Drive one raw HTTP policy WRITE request that is expected to park behind an
 * active writer, then either drop the socket (client disconnect) or read the
 * terminal reply (shutdown).  Modelled on dropped_human_refresh_thread. */
static gpointer
raw_parked_request_thread (gpointer data)
{
  RawParkedRequest *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    g_mutex_lock (&request->mutex);
    request->rc = 1;
    request->sent = TRUE;
    request->done = TRUE;
    g_cond_broadcast (&request->changed);
    g_mutex_unlock (&request->mutex);
    return NULL;
  }
  g_socket_set_timeout (g_socket_connection_get_socket (connection), 15);
  g_autofree gchar *wire = g_strdup_printf
        ("POST %s?%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n"
          "Content-Length: 0\r\n\r\n", request->path, request->query,
          g_uri_get_host (uri), g_uri_get_port (uri));
  gsize written = 0;
  GOutputStream *ostream = g_io_stream_get_output_stream
        (G_IO_STREAM (connection));
  if (!g_output_stream_write_all (ostream, wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)) {
    g_mutex_lock (&request->mutex);
    request->rc = 2;
    request->sent = TRUE;
    request->done = TRUE;
    g_cond_broadcast (&request->changed);
    g_mutex_unlock (&request->mutex);
    return NULL;
  }

  g_mutex_lock (&request->mutex);
  request->sent = TRUE;
  g_cond_broadcast (&request->changed);
  while (!request->release)
    g_cond_wait (&request->changed, &request->mutex);
  gboolean read_response = request->read_response;
  g_mutex_unlock (&request->mutex);

  gchar *body = NULL;
  gint close_rc = 0;
  if (read_response) {
    GInputStream *istream = g_io_stream_get_input_stream
          (G_IO_STREAM (connection));
    g_autoptr (GString) reply = g_string_new (NULL);
    guint8 buffer[512];
    gssize got;
    while ((got = g_input_stream_read (istream, buffer, sizeof buffer, NULL,
        &error)) > 0)
      g_string_append_len (reply, (const gchar *) buffer, got);
    body = g_string_free (g_steal_pointer (&reply), FALSE);
  }
  if (!g_io_stream_close (G_IO_STREAM (connection), NULL, &error))
    close_rc = 3;

  /* Publish all results under the lock before signalling done so the joining
   * thread reads them with a clean happens-before edge. */
  g_mutex_lock (&request->mutex);
  request->body = body;
  if (close_rc != 0)
    request->rc = close_rc;
  request->done = TRUE;
  g_cond_broadcast (&request->changed);
  g_mutex_unlock (&request->mutex);
  return NULL;
}

static void
raw_parked_request_wait_sent (RawParkedRequest *request)
{
  g_mutex_lock (&request->mutex);
  while (!request->sent)
    g_cond_wait (&request->changed, &request->mutex);
  g_mutex_unlock (&request->mutex);
}

static void
raw_parked_request_release (RawParkedRequest *request, gboolean read_response)
{
  g_mutex_lock (&request->mutex);
  request->read_response = read_response;
  request->release = TRUE;
  g_cond_broadcast (&request->changed);
  g_mutex_unlock (&request->mutex);
}

static void
raw_parked_request_join (RawParkedRequest *request)
{
  g_mutex_lock (&request->mutex);
  while (!request->done)
    g_cond_wait (&request->changed, &request->mutex);
  g_mutex_unlock (&request->mutex);
}

/* Bounded poll for a waiting-writer count; returns TRUE once reached. */
static gboolean
poll_waiting_writers (SoupServer *server, guint target)
{
  for (guint attempt = 0; attempt < 2000; attempt++) {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.waiting_writers == target)
      return TRUE;
    g_usleep (5000);
  }
  return FALSE;
}

typedef struct
{
  WylHandle *handle;
  GError *error;
  GMainContext *context;
  SoupServer *server;
  GThread *thread;
  TestHttpServer http;
  gchar *base_url;
  gchar *session_token;
} PolicyWriteCancelFixture;

/* Stand up a real server on its own loop thread, log a policy-write actor in,
 * and grant it direct-permission authority so a POST /policy/permissions/grant
 * reaches the WRITE acquisition rather than an auth wall. */
static gint
policy_write_cancel_fixture_setup (PolicyWriteCancelFixture *fixture,
    const gchar *actor, gint base_error)
{
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &fixture->handle) != WYRELOG_E_OK)
    return base_error;
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  fixture->context = g_main_context_new ();
  fixture->http.loop = g_main_loop_new (fixture->context, FALSE);
  g_main_context_push_thread_default (fixture->context);
  fixture->http.server = wyl_daemon_start_http_server (&options,
          fixture->handle, &fixture->error);
  g_main_context_pop_thread_default (fixture->context);
  if (fixture->http.server == NULL)
    return base_error + 1;
  fixture->server = fixture->http.server;
  /* Stop the 1s service-auth retirement timer for the lifetime of this fixture.
   * It periodically takes the coordination WRITE lease, so leaving it running
   * lets an unrelated maintenance writer park behind the test's held writer in
   * the same window -- which would make the waiting-writer and quiesce
   * assertions below race daemon-internal work rather than the request under
   * test.  Suspending drains any in-flight pass, so after this the only WRITE
   * activity is the test's own. */
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (fixture->server);
  fixture->thread = g_thread_new ("policy-write-cancel",
          test_http_server_thread_ctx, &fixture->http);
  GSList *uris = soup_server_get_uris (fixture->server);
  if (uris == NULL)
    return base_error + 2;
  fixture->base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (fixture->base_url == NULL)
    return base_error + 2;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  wyl_handle_set_login_skip_mfa_allowed (fixture->handle, TRUE);
  g_autofree gchar *login =
      g_strdup_printf ("username=%s&skip_mfa=true", actor);
  gint login_rc = send_raw_login (session, "POST", fixture->base_url, login,
          &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (fixture->handle, FALSE);
  if (login_rc != 0 || status != 200)
    return base_error + 3;
  fixture->session_token = extract_json_string (body, "session_token");
  if (fixture->session_token == NULL)
    return base_error + 3;
  if (grant_policy_write_authority (fixture->handle, actor, WYL_TENANT_DEFAULT)
      != WYRELOG_E_OK)
    return base_error + 4;
  return 0;
}

static void
policy_write_cancel_fixture_teardown (PolicyWriteCancelFixture *fixture)
{
  if (fixture->http.loop != NULL)
    g_main_loop_quit (fixture->http.loop);
  if (fixture->thread != NULL)
    g_thread_join (fixture->thread);
  if (fixture->server != NULL)
    soup_server_disconnect (fixture->server);
  if (fixture->handle != NULL)
    (void) wyl_handle_shutdown_ordered (fixture->handle);
  g_clear_object (&fixture->http.server);
  g_clear_pointer (&fixture->http.loop, g_main_loop_unref);
  g_clear_pointer (&fixture->context, g_main_context_unref);
  g_clear_object (&fixture->handle);
  g_clear_error (&fixture->error);
  g_free (fixture->base_url);
  g_free (fixture->session_token);
}

static gint
policy_write_cancel_authority_is_clean (SoupServer *server, WylHandle *handle,
    gint failure)
{
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
  if (snapshot.writer_active || snapshot.active_readers != 0
      || snapshot.waiting_readers != 0 || snapshot.waiting_writers != 0)
    return failure;
  guint total_pins = G_MAXUINT;
  guint thread_pins = G_MAXUINT;
  wyl_handle_policy_store_pin_snapshot_for_test (handle, &total_pins,
      &thread_pins);
  if (total_pins != 0 || thread_pins != 0)
    return failure + 1;
  return 0;
}

/* A client that disconnects while its policy WRITE is parked behind an active
 * writer must be removed from the wait queue off the (frozen) main loop, with
 * no mutation and no response attached. */
static gint
check_daemon_policy_write_client_disconnect_cancellable (void)
{
  PolicyWriteCancelFixture fixture = { 0 };
  gint result = policy_write_cancel_fixture_setup (&fixture,
          "policy-write-disconnect-actor", 5200);
  if (result != 0) {
    /* Return directly rather than jumping to the shared cleanup: the label
     * sits past g_autoptr declarations, and Clang rejects a goto that skips
     * the initialization of a cleanup-attributed variable. */
    policy_write_cancel_fixture_teardown (&fixture);
    return result;
  }
  result = 5210;

  /* Hold the WRITE on a for-test thread so the real request must park. */
  DaemonPolicyShutdownRace holder = {
    .server = fixture.server,
    .handle = fixture.handle,
    .write_rc = WYRELOG_E_INTERNAL,
    .shutdown_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&holder.mutex);
  g_cond_init (&holder.changed);
  g_autoptr (GThread) writer = g_thread_new ("disconnect-write-holder",
          daemon_policy_write_thread, &holder);
  g_mutex_lock (&holder.mutex);
  while (!holder.write_entered)
    g_cond_wait (&holder.changed, &holder.mutex);
  g_mutex_unlock (&holder.mutex);

  guint terminal_before =
      wyl_daemon_http_policy_write_terminal_entries_for_test (fixture.server);
  g_autofree gchar *query = g_strdup_printf
        ("subject=disconnect-target&perm=cleanup.missing&scope=%s&tenant=%s"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT,
          fixture.session_token);
  RawParkedRequest request = {
    .base_url = fixture.base_url,
    .path = "/policy/permissions/grant",
    .query = query,
  };
  g_mutex_init (&request.mutex);
  g_cond_init (&request.changed);
  g_autoptr (GThread) client = g_thread_new ("disconnect-parked-request",
          raw_parked_request_thread, &request);
  raw_parked_request_wait_sent (&request);

  if (!poll_waiting_writers (fixture.server, 1)) {
    result = 5211;
    goto release_all;
  }
  /* Drop the socket: the off-thread watcher must observe the EOF and cancel. */
  raw_parked_request_release (&request, FALSE);
  if (!poll_waiting_writers (fixture.server, 0)) {
    g_printerr ("WYRELOG_TEST_DIAG policy_write_disconnect_cancel "
        "expected=%d observed=%d armed=%d\n",
        POLICY_WRITE_CANCEL_CLIENT_DISCONNECT,
        wyl_daemon_http_policy_write_last_cancel_reason_for_test
          (fixture.server),
        wyl_daemon_http_policy_write_last_watch_armed_for_test
          (fixture.server));
    result = 5212;
    goto release_all;
  }
  gint cancel_reason =
      wyl_daemon_http_policy_write_last_cancel_reason_for_test (fixture.server);
  if (cancel_reason != POLICY_WRITE_CANCEL_CLIENT_DISCONNECT) {
    /* 5213 truncates to the same exit status as the raw audit contract's 93,
     * so name the branch and the observed reason explicitly. */
    g_printerr ("WYRELOG_TEST_DIAG policy_write_disconnect_cancel "
        "expected=%d observed=%d armed=%d\n",
        POLICY_WRITE_CANCEL_CLIENT_DISCONNECT, cancel_reason,
        wyl_daemon_http_policy_write_last_watch_armed_for_test
          (fixture.server));
    result = 5213;
    goto release_all;
  }
  if (wyl_daemon_http_policy_write_terminal_entries_for_test (fixture.server)
      != terminal_before) {
    result = 5214;              /* cancelled request never mutated */
    goto release_all;
  }
  result = 0;

release_all:
  raw_parked_request_release (&request, FALSE);
  g_mutex_lock (&holder.mutex);
  holder.allow_write = TRUE;
  g_cond_broadcast (&holder.changed);
  g_mutex_unlock (&holder.mutex);
  g_thread_join (g_steal_pointer (&writer));
  raw_parked_request_join (&request);
  g_thread_join (g_steal_pointer (&client));
  if (result == 0)
    result = policy_write_cancel_authority_is_clean (fixture.server,
            fixture.handle, 5215);
  if (result == 0 && holder.write_rc != WYRELOG_E_OK)
    result = 5217;
  g_free (request.body);
  g_cond_clear (&request.changed);
  g_mutex_clear (&request.mutex);
  g_cond_clear (&holder.changed);
  g_mutex_clear (&holder.mutex);
  /* Reached by fall-through only: the setup-failure path returns directly, so
   * keeping a label here would just draw -Wunused-label. */
  policy_write_cancel_fixture_teardown (&fixture);
  return result;
}

/* A daemon shutdown must release every parked policy WRITE, latching the
 * SHUTDOWN reason and leaving no residual writer/lease/pin.  The parked writer
 * is a for-test WRITE so the shutdown cancellation is exercised deterministically
 * without a real client socket; the client-facing 503 mapping is covered by the
 * set_json_error() gate and the disconnect e2e's off-thread cancellation path. */
static gint
check_daemon_policy_write_shutdown_cancellable (void)
{
  PolicyWriteCancelFixture fixture = { 0 };
  gint result = policy_write_cancel_fixture_setup (&fixture,
          "policy-write-shutdown-actor", 5240);
  if (result != 0)
    goto cleanup;

  /* No HTTP loop is needed once the daemon is shutting down. */
  g_main_loop_quit (fixture.http.loop);
  g_thread_join (g_steal_pointer (&fixture.thread));

  /* Drive the shutdown lifecycle, then confirm a policy WRITE arriving after
   * shutdown began is refused-and-cancelled with the SHUTDOWN reason (the
   * registry's shutting-down self-cancel path).  The complementary "a WRITE
   * already parked behind an active writer is released on cancellation" path is
   * covered race-free by the disconnect e2e via the off-thread watcher. */
  wyl_daemon_http_terminalize_refreshes_for_test (fixture.server);

  wyrelog_error_t rc = wyl_daemon_http_policy_write_for_test (fixture.server,
          NULL, NULL);
  if (rc != WYRELOG_E_BUSY) {
    result = 5251;
    goto cleanup;
  }
  if (wyl_daemon_http_policy_write_last_cancel_reason_for_test (fixture.server)
      != POLICY_WRITE_CANCEL_SHUTDOWN) {
    result = 5252;
    goto cleanup;
  }
  result = policy_write_cancel_authority_is_clean (fixture.server,
          fixture.handle, 5253);

cleanup:
  policy_write_cancel_fixture_teardown (&fixture);
  return result;
}

/* A client that disconnects around an acquire-wins grant (no competing writer)
 * must not break exactly-once finalize or leak the writer/pin, regardless of
 * whether the disconnect is observed before or after the lease is granted. */
static gint
check_daemon_policy_write_acquire_wins_late_disconnect (void)
{
  PolicyWriteCancelFixture fixture = { 0 };
  gint result = policy_write_cancel_fixture_setup (&fixture,
          "policy-write-late-disconnect-actor", 5280);
  if (result != 0) {
    /* Direct return for the same reason as the disconnect case above. */
    policy_write_cancel_fixture_teardown (&fixture);
    return result;
  }

  g_autofree gchar *query = g_strdup_printf
        ("subject=late-target&perm=cleanup.missing&scope=%s&tenant=%s"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT,
          fixture.session_token);
  RawParkedRequest request = {
    .base_url = fixture.base_url,
    .path = "/policy/permissions/grant",
    .query = query,
  };
  g_mutex_init (&request.mutex);
  g_cond_init (&request.changed);
  g_autoptr (GThread) client = g_thread_new ("late-disconnect-request",
          raw_parked_request_thread, &request);
  raw_parked_request_wait_sent (&request);
  /* No competing writer: close immediately, racing the grant. */
  raw_parked_request_release (&request, FALSE);
  raw_parked_request_join (&request);
  g_thread_join (g_steal_pointer (&client));

  /* Whatever the race outcome, the authority must quiesce and a fresh WRITE
   * must still be grantable -- proving exactly-once finalize with no leak. */
  if (!poll_waiting_writers (fixture.server, 0)) {
    result = 5290;
    goto teardown_request;
  }
  result = policy_write_cancel_authority_is_clean (fixture.server,
          fixture.handle, 5291);
  if (result == 0
      && wyl_daemon_http_policy_write_for_test (fixture.server, NULL, NULL)
      != WYRELOG_E_OK)
    result = 5293;

teardown_request:
  g_free (request.body);
  g_cond_clear (&request.changed);
  g_mutex_clear (&request.mutex);
  /* The setup-failure path now returns directly, so nothing jumps here any
   * more; the teardown is reached by fall-through and the label would only
   * draw -Wunused-label. */
  policy_write_cancel_fixture_teardown (&fixture);
  return result;
}

static gint
check_daemon_policy_write_cancellable_contract (void)
{
  /* This contract is variant-independent: it stands up its own real daemon HTTP
   * servers to prove policy-WRITE cancellation, so it adds no coverage in the
   * refresh, service and audit variants -- it only exposes its strict park ->
   * disconnect -> CLIENT_DISCONNECT timing to those variants' much heavier
   * daemon activity (audit key rotation, service state, longer runs) under CI
   * sanitizer load, where it flakes.  Run it in the plain decide variant only,
   * which exercises the full contract in a controlled environment.  Keep the
   * helpers referenced below so they are not flagged unused elsewhere. */
#if defined(WYL_TEST_VARIANT_REFRESH) || defined(WYL_TEST_VARIANT_SERVICE) \
  || defined(WYL_TEST_VARIANT_AUDIT)
  if (0) {
    (void) check_daemon_policy_write_client_disconnect_cancellable;
    (void) check_daemon_policy_write_shutdown_cancellable;
    (void) check_daemon_policy_write_acquire_wins_late_disconnect;
  }
  return 0;
#else
  /* Only the first case needs the client-disconnect watch, which
   * wyl_daemon_policy_write_arm_socket_watch installs on POSIX alone: it
   * asserts the cancel reason is CLIENT_DISCONNECT, which nothing on Windows
   * can produce. The other two are platform-neutral and must keep running
   * everywhere -- the late-disconnect case deliberately accepts either race
   * outcome and only checks quiesce, a clean authority and a grantable fresh
   * WRITE, none of which depend on the watch existing. */
  gint rc;
#ifndef G_OS_WIN32
  rc = check_daemon_policy_write_client_disconnect_cancellable ();
  if (rc != 0)
    return rc;
#endif
  rc = check_daemon_policy_write_shutdown_cancellable ();
  if (rc != 0)
    return rc;
  return check_daemon_policy_write_acquire_wins_late_disconnect ();
#endif
}

static gboolean
exact_route_state_unchanged (SoupServer *server,
    const WylDaemonExactRouteStateSnapshot *before)
{
  WylDaemonExactRouteStateSnapshot after = { 0 };
  return wyl_daemon_http_exact_route_state_snapshot_for_test (server, &after)
         && memcmp (before, &after, sizeof after) == 0;
}

static gint
check_valid_exact_auth_alias_canaries (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  WylDaemonExactRouteStateSnapshot before = { 0 };
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw_path_probe (session, "POST", base_url,
      "/auth/login/x?username=exact-alias-login", NULL, NULL,
      &status, &body) != 0)
    return 2290;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
      || !exact_route_state_unchanged (server, &before))
    return 2291;

  wyl_id_t admin_id = WYL_ID_NIL;
  gchar admin_session[WYL_ID_STRING_BUF] = { 0 };
  g_autofree gchar *admin_access = NULL;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_id_new (&admin_id) != WYRELOG_E_OK
      || wyl_id_format (&admin_id, admin_session,
      sizeof admin_session) != WYRELOG_E_OK
      || !seed_management_human_access_token (server, admin_session,
      "exact-route-admin", &admin_access)
      || wyl_policy_store_set_principal_state (store, "exact-route-admin",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_principal_state (store, "exact-enroll-target",
      "authenticated") != WYRELOG_E_OK
      || grant_policy_write_authority (handle, "exact-route-admin",
      WYL_TENANT_DEFAULT) != WYRELOG_E_OK)
    return 2292;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s", admin_access);
  const gchar *guard = "?tenant=__wr_default&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=0";
  g_autofree gchar *start_path = g_strconcat
        ("/auth/mfa/enroll/start", guard, NULL);
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "GET", base_url, start_path,
      authorization, "{\"subject\":\"exact-enroll-target\"}",
      &status, &body) != 0
      || status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 2293;
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "POST", base_url, start_path,
      authorization, "{\"subject\":\"exact-enroll-target\"}",
      &status, &body) != 0 || status != 200)
    return 2294;
  g_autofree gchar *challenge = extract_json_string (body, "challenge");
  if (challenge == NULL)
    return 2295;

  g_autofree gchar *start_alias = g_strconcat
        ("/auth/mfa/enroll/start/x", guard, NULL);
  before = (WylDaemonExactRouteStateSnapshot) {
    0
  };
  g_clear_pointer (&body, g_free);
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw_path_probe (session, "POST", base_url, start_alias,
      authorization, "{\"subject\":\"exact-enroll-target\"}",
      &status, &body) != 0
      || status != 404 || !exact_route_state_unchanged (server, &before))
    return 2296;

  g_autofree gchar *confirm_body = g_strdup_printf
        ("{\"challenge\":\"%s\",\"code\":\"000000\"}", challenge);
  g_autofree gchar *confirm_alias = g_strconcat
        ("/auth/mfa/enroll/confirmx", guard, NULL);
  before = (WylDaemonExactRouteStateSnapshot) {
    0
  };
  g_clear_pointer (&body, g_free);
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw_path_probe (session, "POST", base_url, confirm_alias,
      authorization, confirm_body, &status, &body) != 0
      || status != 404 || !exact_route_state_unchanged (server, &before))
    return 2297;
  g_autofree gchar *confirm_path = g_strconcat
        ("/auth/mfa/enroll/confirm", guard, NULL);
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "POST", base_url, confirm_path,
      authorization,
      "{\"challenge\":\"missing\",\"code\":\"000000\"}",
      &status, &body) != 0 || status != 401
      || strstr (body, "\"invalid_mfa_enroll_challenge\"") == NULL)
    return 2298;

  g_autofree gchar *human_session = NULL;
  g_autofree gchar *access = NULL;
  g_autofree gchar *refresh = NULL;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_clear_pointer (&body, g_free);
  gint login_rc = send_raw_path_probe (session, "POST", base_url,
          "/auth/login?username=exact-refresh-user&skip_mfa=true", NULL, NULL,
          &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (login_rc != 0 || status != 200
      || (human_session = extract_json_string (body, "session_token")) == NULL
      || (access = extract_json_string (body, "access_token")) == NULL
      || (refresh = extract_json_string (body, "refresh_token")) == NULL)
    return 2299;
  g_autofree gchar *escaped_refresh = g_uri_escape_string (refresh, NULL, TRUE);
  g_autofree gchar *refresh_alias = g_strdup_printf
        ("/auth/refresh/x?refresh_token=%s", escaped_refresh);
  before = (WylDaemonExactRouteStateSnapshot) {
    0
  };
  g_clear_pointer (&body, g_free);
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw_path_probe (session, "POST", base_url, refresh_alias,
      NULL, NULL, &status, &body) != 0
      || status != 404 || !exact_route_state_unchanged (server, &before))
    return 2300;
  g_autofree gchar *human_authorization = g_strdup_printf ("Bearer %s", access);
  before = (WylDaemonExactRouteStateSnapshot) {
    0
  };
  g_clear_pointer (&body, g_free);
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw_path_probe (session, "POST", base_url, "/auth/logoutx",
      human_authorization, NULL, &status, &body) != 0
      || status != 404 || !exact_route_state_unchanged (server, &before))
    return 2301;
  g_autofree gchar *refresh_path = g_strdup_printf
        ("/auth/refresh?refresh_token=%s", escaped_refresh);
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "POST", base_url, refresh_path,
      NULL, NULL, &status, &body) != 0 || status != 200)
    return 2302;
  g_autofree gchar *logout_path = g_strdup_printf
        ("/auth/logout?session_token=%s", human_session);
  g_clear_pointer (&body, g_free);
  if (send_raw_path_probe (session, "POST", base_url, logout_path,
      NULL, NULL, &status, &body) != 0 || status != 200
      || strstr (body, "\"ok\":true") == NULL)
    return 2303;
  return 0;
}

static wyrelog_error_t
grant_tenant_manage_authority (WylHandle *handle, const gchar *subject)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store,
          subject, "wr.tenant.manage", WYL_TENANT_DEFAULT);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_permission_state (store, subject,
          "wr.tenant.manage", WYL_TENANT_DEFAULT, "armed");
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_reload_engine_pair (handle);
}

static gboolean
direct_permission_exists (WylHandle *handle, const gchar *subject,
    const gchar *perm, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_direct_permission_exists (store, subject, perm, scope,
      &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static gboolean
tenant_state_matches (wyl_policy_store_t *store, const gchar *tenant,
    gboolean expected_exists, gboolean expected_active)
{
  gboolean exists = FALSE;
  if (wyl_policy_store_tenant_exists (store, tenant, &exists) != WYRELOG_E_OK
      || exists != expected_exists)
    return FALSE;
  if (!exists)
    return TRUE;
  gboolean active = FALSE;
  return wyl_policy_store_tenant_is_active (store, tenant, &active)
         == WYRELOG_E_OK && active == expected_active;
}

static gint
run_tenant_recovery_slot_detach_interleaving (SoupServer *server,
    WylHandle *handle, const gchar *tenant, const gchar *request_id,
    gboolean detach_before_owner_release)
{
  /* The direct-detach phase isolates post-WRITE slot revalidation without
   * weakening the real release-failure contract.  The release-failure phase
   * separately proves that authority latching still safely drains B's ref. */
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (store == NULL)
    return 22480;
  if (wyl_daemon_http_configure_tenant_for_test (server, tenant, TRUE,
      FALSE) != WYRELOG_E_OK)
    return 22485;
  if (!tenant_state_matches (store, tenant, TRUE, TRUE)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 22481;

  guint recovery_allocations_before = 0;
  guint recovery_frees_before = 0;
  guint recovery_allocations_after_a = 0;
  guint recovery_frees_after_a = 0;
  guint recovery_allocations_after_b = 0;
  guint recovery_frees_after_b = 0;
  guint recovery_write_terminals_before =
      wyl_daemon_http_policy_write_terminal_entries_for_test (server);
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_allocations_before, &recovery_frees_before);

  TenantRecoveryBarrier install_barrier = { 0 };
  TenantRecoveryBarrier claim_barrier = { 0 };
  tenant_recovery_barrier_init (&install_barrier);
  tenant_recovery_barrier_init (&claim_barrier);
  TenantRecoveryOwnerRequest request_a = {
    .server = server,
    .tenant = tenant,
    .request_id = request_id,
  };
  TenantRecoveryOwnerRequest request_b = {
    .server = server,
    .tenant = tenant,
    .request_id = request_id,
  };
  wyl_daemon_http_fail_next_tenant_seal_verification_for_test (server);
  if (!detach_before_owner_release)
    wyl_daemon_http_fail_next_tenant_seal_write_release_for_test (server);
  wyl_daemon_http_set_tenant_recovery_install_checkpoint_for_test (server,
      tenant_recovery_checkpoint, &install_barrier);
  g_autoptr (GThread) thread_a = g_thread_new ("tenant-recovery-owner",
          tenant_recovery_owner_request_thread, &request_a);
  if (!tenant_recovery_barrier_wait_entered (&install_barrier)) {
    tenant_recovery_barrier_release (&install_barrier);
    g_thread_join (g_steal_pointer (&thread_a));
    tenant_recovery_barrier_clear (&install_barrier);
    tenant_recovery_barrier_clear (&claim_barrier);
    return 22489;
  }

  wyl_daemon_http_set_tenant_recovery_claim_checkpoint_for_test (server,
      tenant_recovery_checkpoint, &claim_barrier);
  g_autoptr (GThread) thread_b = g_thread_new ("tenant-recovery-claimant",
          tenant_recovery_claim_request_thread, &request_b);
  if (!tenant_recovery_barrier_wait_entered (&claim_barrier)) {
    tenant_recovery_barrier_release (&claim_barrier);
    tenant_recovery_barrier_release (&install_barrier);
    g_thread_join (g_steal_pointer (&thread_a));
    g_thread_join (g_steal_pointer (&thread_b));
    tenant_recovery_barrier_clear (&install_barrier);
    tenant_recovery_barrier_clear (&claim_barrier);
    return 22490;
  }

  /* If B reaches reconstruction despite the slot mismatch, this sentinel
   * changes its result from the expected BUSY to INTERNAL. */
  wyl_daemon_http_fail_next_tenant_recovery_repair_for_test (server);
  if (detach_before_owner_release
      && !wyl_daemon_http_detach_tenant_recovery_slot_for_test (server)) {
    tenant_recovery_barrier_release (&claim_barrier);
    tenant_recovery_barrier_release (&install_barrier);
    g_thread_join (g_steal_pointer (&thread_a));
    g_thread_join (g_steal_pointer (&thread_b));
    tenant_recovery_barrier_clear (&install_barrier);
    tenant_recovery_barrier_clear (&claim_barrier);
    return 22491;
  }
  tenant_recovery_barrier_release (&install_barrier);
  g_thread_join (g_steal_pointer (&thread_a));
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_allocations_after_a, &recovery_frees_after_a);
  gboolean request_a_detached = request_a.rc
      == (detach_before_owner_release ? WYRELOG_E_POLICY : WYRELOG_E_BUSY)
      && wyl_handle_engine_pair_is_poisoned (handle)
      && tenant_state_matches (store, tenant, TRUE, FALSE)
      && recovery_allocations_after_a == recovery_allocations_before + 1
      && recovery_frees_after_a == recovery_frees_before;

  tenant_recovery_barrier_release (&claim_barrier);
  g_thread_join (g_steal_pointer (&thread_b));
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_allocations_after_b, &recovery_frees_after_b);
  gboolean repair_failure_unconsumed =
      wyl_daemon_http_take_tenant_recovery_repair_failure_for_test (server);
  gboolean request_b_rejected = request_b.rc == WYRELOG_E_BUSY
      && wyl_handle_engine_pair_is_poisoned (handle)
      && tenant_state_matches (store, tenant, TRUE, FALSE)
      && wyl_daemon_http_policy_write_terminal_entries_for_test (server)
      == recovery_write_terminals_before + (detach_before_owner_release ? 1 : 0)
      && repair_failure_unconsumed
      && recovery_allocations_after_b == recovery_allocations_before + 1
      && recovery_frees_after_b == recovery_frees_before + 1;
  tenant_recovery_barrier_clear (&install_barrier);
  tenant_recovery_barrier_clear (&claim_barrier);
  if (!request_a_detached)
    return 22482;
  if (!request_b_rejected)
    return 22483;
  return 0;
}

static gint
check_tenant_recovery_post_write_revalidation_contract (void)
{
  g_atomic_int_inc (&tenant_recovery_post_write_regression_executions);
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 22492;
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&options,
          handle, &error);
  if (server == NULL)
    return 22493;
  gint rc = run_tenant_recovery_slot_detach_interleaving (server, handle,
          "tenant-recovery-post-write", "000000000000000000000000300", TRUE);
  soup_server_disconnect (server);
  return rc;
}

static gint
check_tenant_recovery_slot_detach_contract (SoupServer *server,
    WylHandle *handle)
{
  g_atomic_int_inc (&tenant_recovery_detach_regression_executions);
  return run_tenant_recovery_slot_detach_interleaving (server, handle,
             "tenant-recovery-detach", "000000000000000000000000301", FALSE);
}

static gboolean
tenant_metadata (wyl_policy_store_t *store, const gchar *tenant,
    gint64 *out_sealed_generation, gint64 *out_updated_at)
{
  if (store == NULL || tenant == NULL || out_sealed_generation == NULL
      || out_updated_at == NULL)
    return FALSE;
  *out_sealed_generation = -1;
  *out_updated_at = -1;
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *stmt = NULL;
  if (db == NULL || sqlite3_prepare_v2 (db,
      "SELECT sealed_generation,updated_at FROM tenants "
      "WHERE tenant_id=?;", -1, &stmt, NULL) != SQLITE_OK)
    return FALSE;
  gboolean ok = sqlite3_bind_text (stmt, 1, tenant, -1, SQLITE_TRANSIENT)
      == SQLITE_OK && sqlite3_step (stmt) == SQLITE_ROW;
  if (ok) {
    *out_sealed_generation = sqlite3_column_int64 (stmt, 0);
    *out_updated_at = sqlite3_column_int64 (stmt, 1);
  }
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
set_tenant_updated_at_for_test (wyl_policy_store_t *store,
    const gchar *tenant, gint64 updated_at)
{
  if (store == NULL || tenant == NULL)
    return FALSE;
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *stmt = NULL;
  if (db == NULL || sqlite3_prepare_v2 (db,
      "UPDATE tenants SET updated_at=? WHERE tenant_id=?;", -1, &stmt,
      NULL) != SQLITE_OK)
    return FALSE;
  gboolean ok = sqlite3_bind_int64 (stmt, 1, updated_at) == SQLITE_OK
      && sqlite3_bind_text (stmt, 2, tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
      && sqlite3_step (stmt) == SQLITE_DONE && sqlite3_changes (db) == 1;
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean
tenant_projection_decision_matches (WylHandle *handle, const gchar *tenant,
    wyl_decision_t expected)
{
  g_autoptr (wyl_decide_req_t) request = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) response = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (request, "tenant-target");
  wyl_decide_req_set_action (request, "site.policy.read");
  wyl_decide_req_set_resource_id (request, tenant);
  return wyl_decide (handle, request, response) == WYRELOG_E_OK
         && wyl_decide_resp_get_decision (response) == expected;
}

static gboolean
permission_state_exists (WylHandle *handle, const gchar *subject,
    const gchar *perm, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_permission_state_exists (store, subject, perm, scope,
      &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

static wyrelog_error_t
audit_event_probe_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  AuditEventProbe *probe = user_data;

  if ((!probe->check_decision || decision == probe->decision)
      && g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (action, probe->action) == 0
      && g_strcmp0 (resource_id, probe->resource_id) == 0
      && g_strcmp0 (deny_reason, probe->deny_reason) == 0
      && g_strcmp0 (deny_origin, probe->deny_origin) == 0) {
    if (probe->request_id == NULL
        || g_strcmp0 (request_id, probe->request_id) == 0)
      probe->matches++;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
audit_event_count_cb (const gchar *id, gint64 created_at_us,
    const gchar *subject_id, const gchar *action, const gchar *resource_id,
    const gchar *deny_reason, const gchar *deny_origin,
    const gchar *request_id, wyl_decision_t decision, gpointer user_data)
{
  (void) id;
  (void) created_at_us;
  (void) subject_id;
  (void) action;
  (void) resource_id;
  (void) deny_reason;
  (void) deny_origin;
  (void) request_id;
  (void) decision;
  guint64 *count = user_data;
  (*count)++;
  return WYRELOG_E_OK;
}

static gboolean
policy_audit_event_count (WylHandle *handle, guint64 *out_count)
{
  *out_count = 0;
  return wyl_policy_store_foreach_audit_event
           (wyl_handle_get_policy_store (handle), audit_event_count_cb, out_count)
         == WYRELOG_E_OK;
}

static gboolean
policy_lifecycle_audit_count (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *tenant, guint *out_count)
{
  if (out_count == NULL)
    return FALSE;
  AuditEventProbe probe = {
    .subject_id = subject,
    .action = action,
    .resource_id = tenant,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event
        (wyl_handle_get_policy_store (handle), audit_event_probe_cb, &probe)
      != WYRELOG_E_OK)
    return FALSE;
  *out_count = probe.matches;
  return TRUE;
}

typedef struct
{
  const gchar *subject;
  const gchar *tenant;
  WylDaemonTenantCreateOutcomeBundle *bundle;
  guint matches;
} TenantCreateOutcomeBundleProbe;

static void
tenant_create_outcome_bundle_clear (WylDaemonTenantCreateOutcomeBundle *bundle)
{
  if (bundle == NULL)
    return;
  g_free ((gpointer) bundle->tenant_id);
  g_free ((gpointer) bundle->creator_subject_id);
  g_free ((gpointer) bundle->audit_id);
  g_free ((gpointer) bundle->audit_subject_id);
  g_free ((gpointer) bundle->audit_action);
  g_free ((gpointer) bundle->audit_resource_id);
  g_free ((gpointer) bundle->audit_deny_reason);
  g_free ((gpointer) bundle->audit_deny_origin);
  g_free ((gpointer) bundle->audit_request_id);
  memset (bundle, 0, sizeof *bundle);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylDaemonTenantCreateOutcomeBundle,
    tenant_create_outcome_bundle_clear);

static wyrelog_error_t
tenant_create_outcome_bundle_probe_cb (const gchar *id,
    gint64 created_at_us, const gchar *subject_id, const gchar *action,
    const gchar *resource_id, const gchar *deny_reason,
    const gchar *deny_origin, const gchar *request_id,
    wyl_decision_t decision, gpointer user_data)
{
  TenantCreateOutcomeBundleProbe *probe = user_data;
  if (g_strcmp0 (subject_id, probe->subject) != 0
      || g_strcmp0 (action, "tenant_create") != 0
      || g_strcmp0 (resource_id, probe->tenant) != 0
      || decision != WYL_DECISION_ALLOW)
    return WYRELOG_E_OK;
  probe->matches++;
  if (probe->matches != 1)
    return WYRELOG_E_OK;
  *probe->bundle = (WylDaemonTenantCreateOutcomeBundle) {
    .tenant_id = g_strdup (probe->tenant),.creator_subject_id =
        g_strdup (probe->subject),.audit_id =
        g_strdup (id),.audit_created_at_us = created_at_us,.audit_subject_id =
        g_strdup (subject_id),.audit_action =
        g_strdup (action),.audit_resource_id =
        g_strdup (resource_id),.audit_deny_reason =
        g_strdup (deny_reason),.audit_deny_origin =
        g_strdup (deny_origin),.audit_request_id =
        g_strdup (request_id),.audit_decision = decision,
  };
  return WYRELOG_E_OK;
}

static gboolean
tenant_create_outcome_bundle_from_store (WylHandle *handle,
    const gchar *subject, const gchar *tenant,
    WylDaemonTenantCreateOutcomeBundle *out_bundle)
{
  if (out_bundle == NULL)
    return FALSE;
  *out_bundle = (WylDaemonTenantCreateOutcomeBundle) {
    0
  };
  TenantCreateOutcomeBundleProbe probe = {
    .subject = subject,
    .tenant = tenant,
    .bundle = out_bundle,
  };
  return wyl_policy_store_foreach_audit_event
           (wyl_handle_get_policy_store (handle),
             tenant_create_outcome_bundle_probe_cb, &probe) == WYRELOG_E_OK
         && probe.matches == 1 && out_bundle->audit_id != NULL;
}

static gboolean
tenant_create_outcome_bundle_new (const gchar *subject, const gchar *tenant,
    WylDaemonTenantCreateOutcomeBundle *out_bundle)
{
  if (out_bundle == NULL)
    return FALSE;
  g_autoptr (WylAuditEvent) event = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (event, subject);
  wyl_audit_event_set_action (event, "tenant_create");
  wyl_audit_event_set_resource_id (event, tenant);
  wyl_audit_event_set_request_id (event, "outcome-helper-request");
  wyl_audit_event_set_decision (event, WYL_DECISION_ALLOW);
  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (event);
  if (audit_id == NULL)
    return FALSE;
  *out_bundle = (WylDaemonTenantCreateOutcomeBundle) {
    .tenant_id = g_strdup (tenant),.creator_subject_id =
        g_strdup (subject),.audit_id =
        g_steal_pointer (&audit_id),.audit_created_at_us =
        wyl_audit_event_get_created_at_us (event),.audit_subject_id =
        g_strdup (subject),.audit_action =
        g_strdup ("tenant_create"),.audit_resource_id =
        g_strdup (tenant),.audit_request_id =
        g_strdup ("outcome-helper-request"),.audit_decision =
        WYL_DECISION_ALLOW,
  };
  return TRUE;
}

static gboolean
policy_lifecycle_audit_intention_count (WylHandle *handle,
    const gchar *subject, const gchar *action, const gchar *tenant,
    guint *out_count)
{
  if (out_count == NULL)
    return FALSE;
  sqlite3 *db = wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
  sqlite3_stmt *stmt = NULL;
  if (db == NULL || sqlite3_prepare_v2 (db,
      "SELECT COUNT(*) FROM audit_intentions WHERE subject_id=? "
      "AND action=? AND resource_id=?;", -1, &stmt, NULL) != SQLITE_OK)
    return FALSE;
  gboolean ok = sqlite3_bind_text (stmt, 1, subject, -1, SQLITE_TRANSIENT)
      == SQLITE_OK
      && sqlite3_bind_text (stmt, 2, action, -1, SQLITE_TRANSIENT) == SQLITE_OK
      && sqlite3_bind_text (stmt, 3, tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
      && sqlite3_step (stmt) == SQLITE_ROW;
  if (ok)
    *out_count = (guint) sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return ok;
}

static gboolean tenant_creator_anchor_matches (WylHandle * handle,
    const gchar * creator, const gchar * tenant, gboolean expected);
static gboolean tenant_has_no_human_session_row (WylHandle * handle,
    const gchar * tenant);

static gint
check_concurrent_tenant_creates_serialize (WylHandle *handle,
    const gchar *base_url, const gchar *const actors[2],
    const gchar *const session_tokens[2])
{
  ConcurrentTenantMutationRace race = { 0 };
  ConcurrentTenantMutation threads[2] = { 0 };
  GThread *workers[2] = { NULL, NULL };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  for (guint i = 0; i < G_N_ELEMENTS (threads); i++) {
    threads[i].race = &race;
    threads[i].mutation.base_url = base_url;
    threads[i].mutation.query = g_strdup_printf
          ("name=tenant-concurrent&tenant=%s&session_token=%s"
            "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
            WYL_TENANT_DEFAULT, session_tokens[i]);
    workers[i] = g_thread_new ("tenant-create",
            concurrent_tenant_create_thread, &threads[i]);
  }
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++)
    g_thread_join (workers[i]);

  guint changed_true = 0;
  guint changed_false = 0;
  gint winner = -1;
  gint result = 0;
  for (guint i = 0; i < G_N_ELEMENTS (threads); i++) {
    ConcurrentPolicyMutation *mutation = &threads[i].mutation;
    if (mutation->rc != 0 || mutation->status != 200 || mutation->body == NULL) {
      result = 2242;
      break;
    }
    if (strstr (mutation->body, "\"changed\":true") != NULL) {
      changed_true++;
      winner = (gint) i;
    }
    changed_false += strstr (mutation->body, "\"changed\":false") != NULL;
  }
  guint audit_count = 0;
  guint loser_audit_count = 0;
  if (result == 0 && (changed_true != 1 || changed_false != 1
      || winner < 0
      || !tenant_state_matches (wyl_handle_get_policy_store (handle),
      "tenant-concurrent", TRUE, TRUE)
      || !policy_lifecycle_audit_count (handle, actors[winner],
      "tenant_create", "tenant-concurrent", &audit_count)
      || audit_count != 1
      || !policy_lifecycle_audit_count (handle, actors[1 - winner],
      "tenant_create", "tenant-concurrent", &loser_audit_count)
      || loser_audit_count != 0
      || !tenant_creator_anchor_matches (handle, actors[winner],
      "tenant-concurrent", TRUE)
      || !tenant_creator_anchor_matches (handle, actors[1 - winner],
      "tenant-concurrent", FALSE)
      || !tenant_has_no_human_session_row (handle, "tenant-concurrent")
      || wyl_handle_engine_pair_is_poisoned (handle)))
    result = 2243;
  for (guint i = 0; i < G_N_ELEMENTS (threads); i++) {
    g_free (threads[i].mutation.query);
    g_free (threads[i].mutation.body);
  }
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  return result;
}

typedef void (*TenantCreateFaultArm) (SoupServer * server);

static gint
check_tenant_create_anchor_rollback_fault (SoupServer *server,
    WylHandle *handle, SoupSession *session, const gchar *base_url,
    const gchar *session_token, const gchar *tenant,
    TenantCreateFaultArm arm, gint error_base)
{
  g_autofree gchar *query = g_strdup_printf
        ("name=%s&tenant=%s&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", tenant, WYL_TENANT_DEFAULT,
          session_token);
  guint audit_before = 0;
  guint audit_after = 0;
  guint intention_before = 0;
  guint intention_after = 0;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", tenant, &audit_before)
      || !policy_lifecycle_audit_intention_count (handle,
      "http-policy-admin", "tenant_create", tenant, &intention_before))
    return error_base;
  arm (server);
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 500 || strstr (body, "tenant_mutation_failed") == NULL
      || !tenant_state_matches (wyl_handle_get_policy_store (handle), tenant,
      FALSE, FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin", tenant,
      FALSE)
      || !tenant_has_no_human_session_row (handle, tenant)
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", tenant, &audit_after)
      || audit_after != audit_before
      || !policy_lifecycle_audit_intention_count (handle,
      "http-policy-admin", "tenant_create", tenant, &intention_after)
      || intention_after != intention_before
      || wyl_handle_engine_pair_is_poisoned (handle))
    return error_base + 1;
  return 0;
}

static gint
check_valid_policy_aliases (SoupServer *server, WylHandle *handle,
    SoupSession *session, const gchar *base_url, const gchar *canonical_path,
    const gchar *query, gint error_base)
{
  g_autofree gchar *descendant = g_strconcat (canonical_path, "/x", NULL);
  g_autofree gchar *sibling = g_strconcat (canonical_path, "x", NULL);
  const gchar *aliases[] = { descendant, sibling };
  for (gsize i = 0; i < G_N_ELEMENTS (aliases); i++) {
    WylDaemonExactRouteProbeSnapshot probe_before = { 0 }, probe_after = { 0 };
    WylDaemonExactRouteStateSnapshot state_before = { 0 }, state_after = { 0 };
    guint64 audit_before = 0, audit_after = 0;
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (!policy_audit_event_count (handle, &audit_before)
        || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        canonical_path, &probe_before)
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_before)
        || send_raw_policy_mutation (session, "POST", base_url, aliases[i],
        query, &status, &body) != 0
        || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        canonical_path, &probe_after)
        || probe_after.selected != probe_before.selected + 1
        || probe_after.terminal_entries != probe_before.terminal_entries
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_after)
        || memcmp (&state_before, &state_after, sizeof state_before) != 0
        || !policy_audit_event_count (handle, &audit_after)
        || audit_after != audit_before)
      return error_base + (gint) i;
  }
  return 0;
}

static wyrelog_error_t
permission_state_probe_cb (const gchar *subject_id, const gchar *perm_id,
    const gchar *scope, const gchar *state, gpointer user_data)
{
  PermissionStateProbe *probe = user_data;

  if (g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (perm_id, probe->perm_id) == 0
      && g_strcmp0 (scope, probe->scope) == 0
      && g_strcmp0 (state, probe->state) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
permission_state_event_probe_cb (gint64 event_id, const gchar *subject_id,
    const gchar *perm_id, const gchar *scope, const gchar *event,
    const gchar *from_state, const gchar *to_state, gpointer user_data)
{
  (void) event_id;
  PermissionStateProbe *probe = user_data;

  if (g_strcmp0 (subject_id, probe->subject_id) == 0
      && g_strcmp0 (perm_id, probe->perm_id) == 0
      && g_strcmp0 (scope, probe->scope) == 0
      && g_strcmp0 (event, probe->event) == 0
      && g_strcmp0 (from_state, probe->from_state) == 0
      && g_strcmp0 (to_state, probe->to_state) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static gboolean
role_membership_exists (WylHandle *handle, const gchar *subject,
    const gchar *role, const gchar *scope)
{
  gboolean exists = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_role_membership_exists (store, subject, role, scope,
      &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

typedef struct
{
  const gchar *subject;
  const gchar *role;
  const gchar *scope;
  const gchar *operation;
  guint matches;
} RoleMembershipEventProbe;

static wyrelog_error_t
role_membership_event_probe_cb (const gchar *subject_id,
    const gchar *role_id, const gchar *scope, const gchar *operation,
    gpointer user_data)
{
  RoleMembershipEventProbe *probe = user_data;
  if (g_strcmp0 (subject_id, probe->subject) == 0
      && g_strcmp0 (role_id, probe->role) == 0
      && g_strcmp0 (scope, probe->scope) == 0
      && g_strcmp0 (operation, probe->operation) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static gboolean
role_membership_event_count (WylHandle *handle, const gchar *subject,
    const gchar *role, const gchar *scope, const gchar *operation,
    guint *out_count)
{
  if (out_count == NULL)
    return FALSE;
  RoleMembershipEventProbe probe = {
    .subject = subject,
    .role = role,
    .scope = scope,
    .operation = operation,
  };
  if (wyl_policy_store_foreach_role_membership_event
        (wyl_handle_get_policy_store (handle), role_membership_event_probe_cb,
      &probe) != WYRELOG_E_OK)
    return FALSE;
  *out_count = probe.matches;
  return TRUE;
}

typedef struct
{
  const gchar *scope;
  guint matches;
} TenantHumanSessionRowProbe;

static wyrelog_error_t
tenant_human_session_row_probe_cb (const gchar *session_id,
    const gchar *state, gpointer user_data)
{
  (void) state;
  TenantHumanSessionRowProbe *probe = user_data;
  if (g_strcmp0 (session_id, probe->scope) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
tenant_human_session_event_probe_cb (gint64 event_id,
    const gchar *session_id, const gchar *event, const gchar *from_state,
    const gchar *to_state, gpointer user_data)
{
  (void) event_id;
  (void) event;
  (void) from_state;
  (void) to_state;
  TenantHumanSessionRowProbe *probe = user_data;
  if (g_strcmp0 (session_id, probe->scope) == 0)
    probe->matches++;
  return WYRELOG_E_OK;
}

static gboolean
tenant_has_no_human_session_row (WylHandle *handle, const gchar *tenant)
{
  TenantHumanSessionRowProbe probe = {.scope = tenant };
  if (wyl_policy_store_foreach_session_state
        (wyl_handle_get_policy_store (handle), tenant_human_session_row_probe_cb,
      &probe) != WYRELOG_E_OK || probe.matches != 0)
    return FALSE;
  return wyl_policy_store_foreach_session_event
           (wyl_handle_get_policy_store (handle),
             tenant_human_session_event_probe_cb, &probe) == WYRELOG_E_OK
         && probe.matches == 0;
}

static gboolean
tenant_creator_permission_matches (WylHandle *handle, const gchar *creator,
    const gchar *permission, const gchar *tenant, gboolean expected)
{
  gint64 row[3] = { 0 };
  gboolean found = FALSE;
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  return session != NULL
         && wyl_engine_session_intern_symbol (session, creator, &row[0])
         == WYRELOG_E_OK
         && wyl_engine_session_intern_symbol (session, permission, &row[1])
         == WYRELOG_E_OK
         && wyl_engine_session_intern_symbol (session, tenant, &row[2])
         == WYRELOG_E_OK
         && wyl_engine_session_contains (session, "has_permission", row,
             G_N_ELEMENTS (row), &found) == WYRELOG_E_OK && found == expected;
}

static gboolean
tenant_creator_anchor_matches (WylHandle *handle, const gchar *creator,
    const gchar *tenant, gboolean expected)
{
  guint event_count = 0;
  gboolean durable = role_membership_exists (handle, creator,
          "wr.system_admin", tenant)
      == expected
      && role_membership_event_count (handle, creator, "wr.system_admin",
          tenant, "grant", &event_count)
      && event_count == (expected ? 1u : 0u);
  if (!durable || wyl_handle_engine_pair_is_poisoned (handle))
    return durable;
  return tenant_creator_permission_matches (handle, creator,
             "wr.policy.write", tenant, expected)
         && tenant_creator_permission_matches (handle, creator,
             "wr.policy.grant_role", tenant, expected);
}

static gboolean
tenant_creator_revoked_anchor_matches (WylHandle *handle,
    const gchar *creator, const gchar *tenant)
{
  guint grant_count = 0;
  guint revoke_count = 0;
  return !role_membership_exists (handle, creator, "wr.system_admin", tenant)
         && tenant_creator_permission_matches (handle, creator,
             "wr.policy.write", tenant, FALSE)
         && tenant_creator_permission_matches (handle, creator,
             "wr.policy.grant_role", tenant, FALSE)
         && role_membership_event_count (handle, creator, "wr.system_admin",
             tenant, "grant", &grant_count) && grant_count == 1
         && role_membership_event_count (handle, creator, "wr.system_admin",
             tenant, "revoke", &revoke_count) && revoke_count == 1;
}

static gint
check_unknown_tenant_create_outcome_isolated (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 2283;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (SoupServer) server = wyl_daemon_start_http_server (&opts,
          handle, &error);
  if (server == NULL)
    return 2283;
  guint descriptor_alloc_before = 0;
  guint descriptor_free_before = 0;
  guint descriptor_alloc_after = 0;
  guint descriptor_free_after = 0;
  guint audit_count = 0;
  g_auto (WylDaemonTenantCreateOutcomeBundle) bundle = { 0 };
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&descriptor_alloc_before, &descriptor_free_before);
  WylDaemonTenantCreateOutcomeEffect effect =
      WYL_DAEMON_TENANT_CREATE_OUTCOME_REPAIR_ABSENT_PAIR;
  if (wyl_daemon_http_configure_tenant_for_test (server,
      "tenant-outcome-unknown", TRUE, FALSE) != WYRELOG_E_OK
      || !tenant_create_outcome_bundle_new ("http-policy-admin",
      "tenant-outcome-unknown", &bundle)
      || wyl_handle_poison_engine_pair (handle) != WYRELOG_E_OK
      || wyl_daemon_http_resolve_tenant_create_outcome_for_test (server,
      &bundle, &effect)
      != WYRELOG_E_OK
      || effect != WYL_DAEMON_TENANT_CREATE_OUTCOME_FAIL_CLOSED_UNKNOWN
      || !wyl_handle_engine_pair_is_poisoned (handle)
      || !tenant_state_matches (wyl_handle_get_policy_store (handle),
      "tenant-outcome-unknown", TRUE, TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-outcome-unknown", FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-outcome-unknown", FALSE)
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-outcome-unknown", &audit_count)
      || audit_count != 0
      || !tenant_has_no_human_session_row (handle, "tenant-outcome-unknown"))
    return 2283;
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&descriptor_alloc_after, &descriptor_free_after);
  if (descriptor_alloc_after != descriptor_alloc_before
      || descriptor_free_after != descriptor_free_before)
    return 2284;
  soup_server_disconnect (server);
  return 0;
}

static gint
arm_tenant_creator_role_grant (SoupSession *session, WylHandle *handle,
    const gchar *base_url, const gchar *session_token, const gchar *tenant,
    gint error_base)
{
  g_autofree gchar *query = g_strdup_printf
        ("subject=http-policy-admin&perm=wr.policy.grant_role&scope=%s"
          "&event=grant&tenant=%s&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", tenant, WYL_TENANT_DEFAULT,
          session_token);
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition", query, &status, &body);
  if (rc != 0)
    return rc;
  return status == 200 && strstr (body, "\"ok\":true") != NULL
         && permission_state_exists (handle, "http-policy-admin",
             "wr.policy.grant_role", tenant) ? 0 : error_base;
}

static gint
check_concurrent_permission_grants_serialize (WylHandle *handle,
    const gchar *base_url, const gchar *session_token)
{
  static const guint n_threads = 4;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  if (wyl_policy_store_upsert_permission (store, "site.concurrent.read",
      "site concurrent read", "basic") != WYRELOG_E_OK)
    return 204;

  ConcurrentPolicyMutation mutations[n_threads];
  GThread *threads[n_threads];
  gint result = 0;
  memset (mutations, 0, sizeof mutations);
  memset (threads, 0, sizeof threads);

  for (guint i = 0; i < n_threads; i++) {
    mutations[i].base_url = base_url;
    mutations[i].query =
        g_strdup_printf ("subject=concurrent-target"
            "&perm=site.concurrent.read&scope=tenant-a"
            "&session_token=%s&guard_timestamp=123"
            "&guard_loc_class=public&guard_risk=49", session_token);
    g_autofree gchar *name = g_strdup_printf ("policy-grant-%u", i);
    threads[i] = g_thread_new (name, concurrent_permission_grant_thread,
            &mutations[i]);
  }

  for (guint i = 0; i < n_threads; i++)
    g_thread_join (threads[i]);

  for (guint i = 0; i < n_threads; i++) {
    if (mutations[i].rc != 0) {
      result = 205;
      goto cleanup;
    }
    if (mutations[i].status != 200
        || strstr (mutations[i].body, "\"ok\":true") == NULL) {
      result = 206;
      goto cleanup;
    }
  }

  if (!direct_permission_exists (handle, "concurrent-target",
      "site.concurrent.read", "tenant-a")) {
    result = 207;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  AuditEventProbe grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_grant",
    .resource_id = "tenant-a",
    .deny_origin = "site.concurrent.read",
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &grant_audit) != WYRELOG_E_OK) {
    result = 208;
    goto cleanup;
  }
  if (grant_audit.matches != n_threads) {
    result = 209;
    goto cleanup;
  }
#endif

cleanup:
  for (guint i = 0; i < n_threads; i++) {
    g_free (mutations[i].query);
    g_free (mutations[i].body);
  }
  return result;
}

static gint
check_policy_permission_mutation_contract (SoupServer *server,
    WylHandle *handle, WylClient *client, const gchar *base_url)
{
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-policy-admin") != WYRELOG_E_OK)
    return 123;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  g_autofree gchar *session_token = wyl_client_dup_session_token (client);
  g_autofree gchar *access_token = wyl_client_dup_access_token (client);
  g_autofree gchar *client_tenant = wyl_client_dup_tenant (client);
  if (session_token == NULL)
    return 124;
  if (access_token == NULL)
    return 164;
  if (g_strcmp0 (client_tenant, "__wr_default") != 0)
    return 165;
  /* Tenant management has historically accepted an active human session
   * created through the explicitly enabled skip-MFA login path.  Keep this
   * fixture visibly non-MFA so the WRITE-lease reauthorization cannot silently
   * strengthen the front-door contract. */
  g_autoptr (WylSession) management_session =
      wyl_daemon_http_ref_session (server, session_token);
  if (management_session == NULL
      || wyl_session_is_mfa_assured_private (management_session))
    return 2228;
  if (grant_tenant_manage_authority (handle, "http-policy-admin")
      != WYRELOG_E_OK)
    return 189;

  g_autoptr (WylClient) competing_creator = NULL;
  if (wyl_client_new (base_url, &competing_creator) != WYRELOG_E_OK)
    return 2250;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  wyrelog_error_t competing_login = wyl_client_login_skip_mfa
        (competing_creator, "http-policy-racer");
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (competing_login != WYRELOG_E_OK
      || grant_tenant_manage_authority (handle, "http-policy-racer")
      != WYRELOG_E_OK)
    return 2251;
  g_autofree gchar *competing_session_token =
      wyl_client_dup_session_token (competing_creator);
  if (competing_session_token == NULL)
    return 2252;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_upsert_permission (store, "site.policy.read",
      "site policy read", "basic") != WYRELOG_E_OK)
    return 125;

  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  guint anonymous_audit_count = 0;
  gint rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", "name=tenant-anonymous&tenant=__wr_default"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "tenant_auth_required") == NULL
      || !tenant_state_matches (store, "tenant-anonymous", FALSE, FALSE)
      || !policy_lifecycle_audit_count (handle, "anonymous",
      "tenant_create", "tenant-anonymous", &anonymous_audit_count)
      || anonymous_audit_count != 0
      || !tenant_has_no_human_session_row (handle, "tenant-anonymous"))
    return 2275;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "GET", base_url,
          "/policy/permissions/grant", "subject=target&perm=site.policy.read"
          "&scope=tenant-a", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 126;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "GET", base_url,
          "/policy/permissions/transition", "subject=state-target"
          "&perm=site.policy.read&scope=tenant-a&event=grant", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
    return 167;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", "perm=site.policy.read&scope=tenant-a",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 127;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition",
          "subject=state-target&perm=site.policy.read&scope=tenant-a",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 168;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition",
          "subject=state-target&perm=site.policy.read&scope=tenant-a&event=nope",
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 169;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", "subject=target&perm=site.policy.read"
          "&scope=tenant-a&session_token=unknown&guard_timestamp=abc"
          "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_auth\"") == NULL)
    return 128;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", "subject=target&perm=site.policy.read"
          "&scope=tenant-a&session_token=unknown&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 129;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", "subject=target&perm=site.missing"
          "&scope=tenant-a&session_token=unknown&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 153;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *denied_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 130;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a")) {
    return 131;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *unknown_tenant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
          "&tenant=unknown&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", unknown_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 187;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a")) {
    return 188;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_create_query =
      g_strdup_printf ("name=tenant-a&tenant=%s&session_token=%s"
          "&creator=spoofed-creator&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  g_autofree gchar *tenant_create_competing_query =
      g_strdup_printf ("name=tenant-a&tenant=%s&session_token=%s"
          "&creator=spoofed-creator&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", WYL_TENANT_DEFAULT,
          competing_session_token);
  static const gchar *const tenant_delete_aliases[] = {
    "/tenants/delete/x",
    "/tenants/deletex",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_delete_aliases); i++) {
    rc = send_raw_policy_mutation (session, "POST", base_url,
            tenant_delete_aliases[i], tenant_create_query, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !tenant_state_matches (store, "tenant-a", FALSE, FALSE))
      return 205 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/delete", "name=tenant-a", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 501 || strstr (body, "\"tenant_delete_unsupported\"") == NULL)
    return 204;
  g_clear_pointer (&body, g_free);

  static const gchar *const tenant_create_aliases[] = {
    "/tenants/create/x",
    "/tenants/createx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_create_aliases); i++) {
    rc = send_raw_policy_mutation (session, "POST", base_url,
            tenant_create_aliases[i], tenant_create_query, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !tenant_state_matches (store, "tenant-a", FALSE, FALSE))
      return 207 + (gint) i;
    g_clear_pointer (&body, g_free);
  }

  const gchar *const concurrent_actors[] = {
    "http-policy-admin", "http-policy-racer",
  };
  const gchar *const concurrent_tokens[] = {
    session_token, competing_session_token,
  };
  gint concurrent_tenant_rc = check_concurrent_tenant_creates_serialize
        (handle, base_url, concurrent_actors, concurrent_tokens);
  if (concurrent_tenant_rc != 0)
    return concurrent_tenant_rc;

  gint creator_fault_rc = check_tenant_create_anchor_rollback_fault (server,
          handle, session, base_url, session_token, "tenant-grant-rollback",
          wyl_daemon_http_fail_next_tenant_creator_grant_for_test, 2253);
  if (creator_fault_rc != 0)
    return creator_fault_rc;
  creator_fault_rc = check_tenant_create_anchor_rollback_fault (server,
          handle, session, base_url, session_token, "tenant-event-rollback",
          wyl_daemon_http_fail_next_tenant_creator_event_for_test, 2255);
  if (creator_fault_rc != 0)
    return creator_fault_rc;
  creator_fault_rc = check_tenant_create_anchor_rollback_fault (server,
          handle, session, base_url, session_token, "tenant-append-rollback",
          wyl_daemon_http_fail_next_tenant_lifecycle_audit_append_for_test, 2269);
  if (creator_fault_rc != 0)
    return creator_fault_rc;

  {
    guint descriptor_alloc_before = 0;
    guint descriptor_free_before = 0;
    guint descriptor_alloc_after = 0;
    guint descriptor_free_after = 0;
    guint outcome_audit_count = 0;
    g_auto (WylDaemonTenantCreateOutcomeBundle) outcome_absent_bundle = { 0 };
    WylDaemonTenantCreateOutcomeEffect outcome_effect =
        WYL_DAEMON_TENANT_CREATE_OUTCOME_FAIL_CLOSED_UNKNOWN;
    wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
      (&descriptor_alloc_before, &descriptor_free_before);
    if (!tenant_create_outcome_bundle_new ("http-policy-admin",
        "tenant-outcome-absent", &outcome_absent_bundle)
        || wyl_handle_poison_engine_pair (handle) != WYRELOG_E_OK
        || wyl_daemon_http_resolve_tenant_create_outcome_for_test (server,
        &outcome_absent_bundle, &outcome_effect)
        != WYRELOG_E_OK
        || outcome_effect !=
        WYL_DAEMON_TENANT_CREATE_OUTCOME_REPAIR_ABSENT_PAIR
        || wyl_handle_engine_pair_is_poisoned (handle)
        || !tenant_state_matches (store, "tenant-outcome-absent", FALSE, FALSE)
        || !tenant_creator_anchor_matches (handle, "http-policy-admin",
        "tenant-outcome-absent", FALSE)
        || !tenant_creator_anchor_matches (handle, "http-policy-racer",
        "tenant-outcome-absent", FALSE)
        || !policy_lifecycle_audit_count (handle, "http-policy-admin",
        "tenant_create", "tenant-outcome-absent", &outcome_audit_count)
        || outcome_audit_count != 0
        || !tenant_has_no_human_session_row (handle, "tenant-outcome-absent"))
      return 2277;
    wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
      (&descriptor_alloc_after, &descriptor_free_after);
    if (descriptor_alloc_after != descriptor_alloc_before
        || descriptor_free_after != descriptor_free_before)
      return 2278;

    g_autofree gchar *outcome_absent_query =
        g_strdup_printf ("name=tenant-outcome-absent&tenant=%s"
            "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
            "&guard_risk=49", WYL_TENANT_DEFAULT, competing_session_token);
    rc = send_raw_policy_mutation (session, "POST", base_url,
            "/tenants/create", outcome_absent_query, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 200 || strstr (body, "\"changed\":true") == NULL
        || wyl_handle_engine_pair_is_poisoned (handle)
        || !tenant_creator_anchor_matches (handle, "http-policy-admin",
        "tenant-outcome-absent", FALSE)
        || !tenant_creator_anchor_matches (handle, "http-policy-racer",
        "tenant-outcome-absent", TRUE)
        || !policy_lifecycle_audit_count (handle, "http-policy-racer",
        "tenant_create", "tenant-outcome-absent", &outcome_audit_count)
        || outcome_audit_count != 1
        || !tenant_has_no_human_session_row (handle, "tenant-outcome-absent"))
      return 2279;
    g_clear_pointer (&body, g_free);

    g_autofree gchar *outcome_present_initial_query =
        g_strdup_printf ("name=tenant-outcome-present&tenant=%s"
            "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
            "&guard_risk=49", WYL_TENANT_DEFAULT, session_token);
    rc = send_raw_policy_mutation (session, "POST", base_url,
            "/tenants/create", outcome_present_initial_query, &status, &body);
    if (rc != 0)
      return rc;
    g_auto (WylDaemonTenantCreateOutcomeBundle) outcome_present_bundle = { 0 };
    if (status != 200 || strstr (body, "\"changed\":true") == NULL
        || !tenant_create_outcome_bundle_from_store (handle,
        "http-policy-admin", "tenant-outcome-present",
        &outcome_present_bundle))
      return 2280;
    g_clear_pointer (&body, g_free);

    wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
      (&descriptor_alloc_before, &descriptor_free_before);
    outcome_effect = WYL_DAEMON_TENANT_CREATE_OUTCOME_FAIL_CLOSED_UNKNOWN;
    if (wyl_handle_poison_engine_pair (handle) != WYRELOG_E_OK
        || wyl_daemon_http_resolve_tenant_create_outcome_for_test (server,
        &outcome_present_bundle, &outcome_effect)
        != WYRELOG_E_OK
        || outcome_effect !=
        WYL_DAEMON_TENANT_CREATE_OUTCOME_INSTALL_ORIGINAL_DESCRIPTOR
        || !wyl_handle_engine_pair_is_poisoned (handle)
        || !tenant_state_matches (store, "tenant-outcome-present", TRUE, TRUE)
        || !tenant_creator_anchor_matches (handle, "http-policy-admin",
        "tenant-outcome-present", TRUE)
        || !tenant_creator_anchor_matches (handle, "http-policy-racer",
        "tenant-outcome-present", FALSE)
        || !policy_lifecycle_audit_count (handle, "http-policy-admin",
        "tenant_create", "tenant-outcome-present", &outcome_audit_count)
        || outcome_audit_count != 1
        || !tenant_has_no_human_session_row (handle, "tenant-outcome-present"))
      return 2280;
    wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
      (&descriptor_alloc_after, &descriptor_free_after);
    if (descriptor_alloc_after != descriptor_alloc_before + 1
        || descriptor_free_after != descriptor_free_before)
      return 2281;

    g_autofree gchar *outcome_present_query =
        g_strdup_printf ("name=tenant-outcome-present&tenant=%s"
            "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
            "&guard_risk=49", WYL_TENANT_DEFAULT, competing_session_token);
    rc = send_raw_policy_mutation (session, "POST", base_url,
            "/tenants/create", outcome_present_query, &status, &body);
    if (rc != 0)
      return rc;
    guint competing_outcome_audit_count = 0;
    wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
      (&descriptor_alloc_after, &descriptor_free_after);
    if (status != 200 || strstr (body, "\"changed\":false") == NULL
        || wyl_handle_engine_pair_is_poisoned (handle)
        || descriptor_alloc_after != descriptor_alloc_before + 1
        || descriptor_free_after != descriptor_free_before + 1
        || !tenant_creator_anchor_matches (handle, "http-policy-admin",
        "tenant-outcome-present", TRUE)
        || !tenant_creator_anchor_matches (handle, "http-policy-racer",
        "tenant-outcome-present", FALSE)
        || !policy_lifecycle_audit_count (handle, "http-policy-admin",
        "tenant_create", "tenant-outcome-present", &outcome_audit_count)
        || outcome_audit_count != 1
        || !policy_lifecycle_audit_count (handle, "http-policy-racer",
        "tenant_create", "tenant-outcome-present",
        &competing_outcome_audit_count)
        || competing_outcome_audit_count != 0
        || !tenant_has_no_human_session_row (handle, "tenant-outcome-present"))
      return 2282;
    g_clear_pointer (&body, g_free);
  }
  gint unknown_outcome_rc = check_unknown_tenant_create_outcome_isolated ();
  if (unknown_outcome_rc != 0)
    return unknown_outcome_rc;

  guint lifecycle_audit_before = 0;
  guint lifecycle_audit_after = 0;
  g_autofree gchar *rollback_tenant_query =
      g_strdup_printf ("name=tenant-rollback&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-rollback", &lifecycle_audit_before))
    return 2230;
  wyl_daemon_http_fail_next_tenant_lifecycle_audit_insert_for_test (server);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", rollback_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  gboolean rollback_tenant_absent = tenant_state_matches (store,
          "tenant-rollback", FALSE, FALSE);
  gboolean rollback_audit_counted = policy_lifecycle_audit_count (handle,
          "http-policy-admin", "tenant_create", "tenant-rollback",
          &lifecycle_audit_after);
  gboolean rollback_poisoned = wyl_handle_engine_pair_is_poisoned (handle);
  if (status != 500 || strstr (body, "tenant_mutation_failed") == NULL
      || !rollback_tenant_absent || !rollback_audit_counted
      || lifecycle_audit_after != lifecycle_audit_before || rollback_poisoned
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-rollback", FALSE)
      || !tenant_has_no_human_session_row (handle, "tenant-rollback")) {
    g_printerr ("WYRELOG_TEST_DIAG tenant_lifecycle_rollback status=%u "
        "body=%s absent=%d audit=%d before=%u after=%u poisoned=%d\n", status,
        body != NULL ? body : "(null)", rollback_tenant_absent,
        rollback_audit_counted, lifecycle_audit_before,
        lifecycle_audit_after, rollback_poisoned);
    return 2231;
  }
  g_clear_pointer (&body, g_free);

  g_autofree gchar *postcommit_tenant_query =
      g_strdup_printf ("name=tenant-postcommit&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-postcommit", &lifecycle_audit_before))
    return 2230;
  wyl_daemon_http_fail_next_tenant_creator_receipt_verification_for_test
    (server);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", postcommit_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 500 || strstr (body, "tenant_mutation_failed") == NULL
      || !tenant_state_matches (store, "tenant-postcommit", TRUE, TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-postcommit", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-postcommit", FALSE)
      || !tenant_has_no_human_session_row (handle, "tenant-postcommit")
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-postcommit", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before + 1
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 2232;
  g_clear_pointer (&body, g_free);
  lifecycle_audit_before = lifecycle_audit_after;
  g_autofree gchar *postcommit_competing_query =
      g_strdup_printf ("name=tenant-postcommit&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, competing_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", postcommit_competing_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-postcommit", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-postcommit", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-postcommit", FALSE)
      || wyl_handle_engine_pair_is_poisoned (handle))
    return 2234;
  g_clear_pointer (&body, g_free);

  guint competing_audit_count = 0;
  guint recovery_alloc_before = 0;
  guint recovery_free_before = 0;
  guint recovery_alloc_after = 0;
  guint recovery_free_after = 0;
  guint publication_attempts_before = 0;
  guint noop_fault_discards_before = 0;
  guint publication_attempts_after = 0;
  guint noop_fault_discards_after = 0;
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_alloc_before, &recovery_free_before);
  wyl_daemon_http_tenant_create_publication_snapshot_for_test (server,
      &publication_attempts_before, &noop_fault_discards_before);
  wyl_daemon_http_fail_next_tenant_lifecycle_audit_insert_for_test (server);
  wyl_daemon_http_fail_next_tenant_lifecycle_verification_for_test (server);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", postcommit_competing_query, &status, &body);
  if (rc != 0)
    return rc;
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_alloc_after, &recovery_free_after);
  wyl_daemon_http_tenant_create_publication_snapshot_for_test (server,
      &publication_attempts_after, &noop_fault_discards_after);
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || wyl_handle_engine_pair_is_poisoned (handle)
      || recovery_alloc_after != recovery_alloc_before
      || recovery_free_after != recovery_free_before
      || publication_attempts_after != publication_attempts_before
      || noop_fault_discards_after != noop_fault_discards_before + 2
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-postcommit", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-postcommit", FALSE)
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-postcommit", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before
      || !policy_lifecycle_audit_count (handle, "http-policy-racer",
      "tenant_create", "tenant-postcommit", &competing_audit_count)
      || competing_audit_count != 0
      || !tenant_has_no_human_session_row (handle, "tenant-postcommit"))
    return 2235;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *noop_followup_query =
      g_strdup_printf ("name=tenant-noop-followup&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, competing_session_token);
  guint followup_audit_count = 0;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", noop_followup_query, &status, &body);
  if (rc != 0)
    return rc;
  wyl_daemon_http_tenant_recovery_descriptor_counts_for_test
    (&recovery_alloc_after, &recovery_free_after);
  wyl_daemon_http_tenant_create_publication_snapshot_for_test (server,
      &publication_attempts_after, &noop_fault_discards_after);
  if (status != 200 || strstr (body, "\"changed\":true") == NULL
      || wyl_handle_engine_pair_is_poisoned (handle)
      || recovery_alloc_after != recovery_alloc_before
      || recovery_free_after != recovery_free_before
      || publication_attempts_after != publication_attempts_before + 1
      || noop_fault_discards_after != noop_fault_discards_before + 2
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-noop-followup", FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-noop-followup", TRUE)
      || !policy_lifecycle_audit_count (handle, "http-policy-racer",
      "tenant_create", "tenant-noop-followup", &followup_audit_count)
      || followup_audit_count != 1
      || !tenant_has_no_human_session_row (handle, "tenant-noop-followup"))
    return 2236;
  g_clear_pointer (&body, g_free);

  gboolean legacy_created = FALSE;
  if (wyl_policy_store_create_tenant (store, "tenant-legacy",
      &legacy_created) != WYRELOG_E_OK || !legacy_created
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 2257;
  g_autofree gchar *legacy_create_query =
      g_strdup_printf ("name=tenant-legacy&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, competing_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", legacy_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-legacy", FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-legacy", FALSE)
      || !tenant_has_no_human_session_row (handle, "tenant-legacy")
      || !policy_lifecycle_audit_count (handle, "http-policy-racer",
      "tenant_create", "tenant-legacy", &lifecycle_audit_after)
      || lifecycle_audit_after != 0)
    return 2258;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *default_create_query =
      g_strdup_printf ("name=%s&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT, competing_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", default_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      WYL_TENANT_DEFAULT, FALSE))
    return 2259;
  g_clear_pointer (&body, g_free);

  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-a", &lifecycle_audit_before))
    return 2235;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL ||
      strstr (body, "\"changed\":true") == NULL)
    return 190;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-a", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before + 1
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-a", FALSE)
      || !tenant_creator_anchor_matches (handle, "spoofed-creator",
      "tenant-a", FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      WYL_TENANT_DEFAULT, FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-b", FALSE)
      || !tenant_has_no_human_session_row (handle, "tenant-a"))
    return 2236;
  g_clear_pointer (&body, g_free);

  lifecycle_audit_before = lifecycle_audit_after;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", tenant_create_competing_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL)
    return 191;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-a", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-a", FALSE))
    return 2237;
  g_clear_pointer (&body, g_free);

  static const gchar *const tenant_list_aliases[] = {
    "/tenants/x",
    "/tenantsx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_list_aliases); i++) {
    rc = send_raw_policy_mutation (session, "GET", base_url,
            tenant_list_aliases[i], tenant_create_query, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !tenant_state_matches (store, "tenant-a", TRUE, TRUE))
      return 209 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  rc = send_raw_policy_mutation (session, "GET", base_url, "/tenants",
          tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL ||
      strstr (body, "\"tenant\":\"__wr_default\"") == NULL)
    return 192;
  g_clear_pointer (&body, g_free);

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  rc = send_raw_login (session, "POST", base_url,
          "username=tenant-user&tenant=tenant-a&skip_mfa=true", &status, &body);
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"tenant\":\"tenant-a\"") == NULL)
    return 193;
  g_autofree gchar *tenant_session_token =
      extract_json_string (body, "session_token");
  if (tenant_session_token == NULL)
    return 194;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *cross_tenant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-b"
          "&tenant=tenant-a&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", tenant_session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", cross_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"tenant_denied\"") == NULL)
    return 196;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-b"))
    return 197;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_grant_query =
      g_strdup_printf ("subject=tenant-target&perm=site.policy.read"
          "&scope=tenant-a&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", tenant_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 198;
  if (!direct_permission_exists (handle, "tenant-target", "site.policy.read",
      "tenant-a"))
    return 199;
  g_clear_pointer (&body, g_free);
  if (wyl_policy_store_upsert_role (store, "site.creator-role",
      "creator role") != WYRELOG_E_OK)
    return 2260;
  gint arm_creator_rc = arm_tenant_creator_role_grant (session, handle,
          base_url, session_token, "tenant-a", 2261);
  if (arm_creator_rc != 0)
    return arm_creator_rc;
  g_autofree gchar *tenant_role_grant_query =
      g_strdup_printf ("subject=creator-role-target&role=site.creator-role"
          "&scope=tenant-a&tenant=%s&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=29", WYL_TENANT_DEFAULT,
          session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", tenant_role_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || !role_membership_exists (handle,
      "creator-role-target", "site.creator-role", "tenant-a"))
    return 2262;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *revoked_tenant_create_query = g_strdup_printf
        ("name=tenant-revoke&tenant=%s&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", WYL_TENANT_DEFAULT,
          session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", revoked_tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-revoke", TRUE)
      || !tenant_has_no_human_session_row (handle, "tenant-revoke"))
    return 2264;
  g_clear_pointer (&body, g_free);

  arm_creator_rc = arm_tenant_creator_role_grant (session, handle, base_url,
          session_token, "tenant-revoke", 2265);
  if (arm_creator_rc != 0)
    return arm_creator_rc;

  g_autofree gchar *creator_self_revoke_query = g_strdup_printf
        ("subject=http-policy-admin&role=wr.system_admin&scope=tenant-revoke"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=29", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/revoke", creator_self_revoke_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL
      || !tenant_creator_revoked_anchor_matches (handle,
      "http-policy-admin", "tenant-revoke")
      || !tenant_has_no_human_session_row (handle, "tenant-revoke"))
    return 2266;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", revoked_tenant_create_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !tenant_creator_revoked_anchor_matches (handle,
      "http-policy-admin", "tenant-revoke")
      || !tenant_has_no_human_session_row (handle, "tenant-revoke"))
    return 2267;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *revoked_tenant_seal_query = g_strdup_printf
        ("name=tenant-revoke&tenant=%s&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", WYL_TENANT_DEFAULT,
          session_token);
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", revoked_tenant_seal_query,
          "{\"version\":\"1\",\"request_id\":"
          "\"000000000000000000000000231\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL
      || !tenant_creator_revoked_anchor_matches (handle,
      "http-policy-admin", "tenant-revoke"))
    return 2268;
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/unseal", revoked_tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL
      || !tenant_creator_revoked_anchor_matches (handle,
      "http-policy-admin", "tenant-revoke")
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK
      || !tenant_creator_revoked_anchor_matches (handle,
      "http-policy-admin", "tenant-revoke")
      || !tenant_has_no_human_session_row (handle, "tenant-revoke"))
    return 2269;
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_set_principal_state (store, "tenant-target",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store, "tenant-target",
      "site.policy.read", "tenant-a", "armed") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK
      || !tenant_projection_decision_matches (handle, "tenant-a",
      WYL_DECISION_ALLOW))
    return 1991;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *tenant_seal_query =
      g_strdup_printf ("name=tenant-a&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  static const gchar *tenant_seal_body =
      "{\"version\":\"1\",\"request_id\":" "\"000000000000000000000000222\"}";
  static const gchar *const tenant_seal_aliases[] = {
    "/tenants/seal/x",
    "/tenants/sealx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_seal_aliases); i++) {
    rc = send_raw_policy_mutation_body (session, "POST", base_url,
            tenant_seal_aliases[i], tenant_seal_query, tenant_seal_body,
            &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !tenant_state_matches (store, "tenant-a", TRUE, TRUE))
      return 211 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  static const gchar *invalid_tenant_seal_bodies[] = {
    NULL,
    "",
    "{}",
    "{\"version\":\"1\",\"request_id\":"
    "\"000000000000000000000000222\",\"extra\":true}",
    "{\"version\":\"1\",\"version\":\"1\",\"request_id\":"
    "\"000000000000000000000000222\"}",
    "{\"version\":1,\"request_id\":" "\"000000000000000000000000222\"}",
    "{\"version\":\"2\",\"request_id\":" "\"000000000000000000000000222\"}",
    "{\"version\":\"1\",\"request_id\":" "\"abcdefghijklmnopqrstuvwxyz0\"}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_tenant_seal_bodies); i++) {
    rc = send_raw_policy_mutation_body (session, "POST", base_url,
            "/tenants/seal", tenant_seal_query, invalid_tenant_seal_bodies[i],
            &status, &body);
    if (rc != 0)
      return rc;
    if (status != 400 || strstr (body, "invalid_tenant_request") == NULL)
      return 2001;
    g_clear_pointer (&body, g_free);
  }
  g_autofree gchar *oversized_tenant_seal_body = g_strnfill (1025, 'x');
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, oversized_tenant_seal_body,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "invalid_tenant_request") == NULL)
    return 2004;
  g_clear_pointer (&body, g_free);

  guint tenant_seal_audit_before = 0;
  guint tenant_seal_audit_after = 0;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_seal", "tenant-a", &tenant_seal_audit_before))
    return 2242;
  wyl_daemon_http_fail_next_tenant_seal_verification_for_test (server);
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, tenant_seal_body, &status, &body);
  WylServiceAuthUnavailableReason seal_unavailable =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (rc != 0)
    return rc;
  gboolean seal_state_closed = tenant_state_matches (store, "tenant-a",
          TRUE, FALSE);
  gboolean seal_pair_poisoned = wyl_handle_engine_pair_is_poisoned (handle);
  wyrelog_error_t seal_available_rc =
      wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
          &seal_unavailable);
  gboolean seal_audit_counted = policy_lifecycle_audit_count (handle,
          "http-policy-admin", "tenant_seal", "tenant-a",
          &tenant_seal_audit_after);
  if (status != 500 || strstr (body, "tenant_mutation_failed") == NULL
      || !seal_state_closed || !seal_pair_poisoned
      || seal_available_rc != WYRELOG_E_OK || !seal_audit_counted
      || tenant_seal_audit_after != tenant_seal_audit_before + 1
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_has_no_human_session_row (handle, "tenant-a")) {
    g_printerr ("WYRELOG_TEST_DIAG tenant_seal_recovery status=%u body=%s "
        "closed=%d poisoned=%d available=%d reason=%d audit=%d before=%u "
        "after=%u\n", status, body != NULL ? body : "(null)",
        seal_state_closed, seal_pair_poisoned, seal_available_rc,
        seal_unavailable, seal_audit_counted, tenant_seal_audit_before,
        tenant_seal_audit_after);
    return 2243;
  }
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query,
          "{\"version\":\"1\",\"request_id\":"
          "\"000000000000000000000000229\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 503 || strstr (body, "tenant_mutation_unavailable") == NULL
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 2245;
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/unseal", tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 503 || strstr (body, "tenant_mutation_unavailable") == NULL
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 2246;
  g_clear_pointer (&body, g_free);
  g_autofree gchar *wrong_recovery_tenant_query =
      g_strdup_printf ("name=tenant-wrong&tenant=%s&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          WYL_TENANT_DEFAULT, session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", wrong_recovery_tenant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 503 || strstr (body, "tenant_mutation_unavailable") == NULL
      || !wyl_handle_engine_pair_is_poisoned (handle))
    return 2247;
  g_clear_pointer (&body, g_free);

  /* The audit fixture serializes route dispatch, so the default fixture owns
   * the concurrent CLAIMED observation.  Audit still exercises the same
   * exact-request recovery synchronously below. */
#ifndef WYL_HAS_AUDIT
  TenantRecoveryBarrier recovery_barrier = { 0 };
  g_mutex_init (&recovery_barrier.mutex);
  g_cond_init (&recovery_barrier.changed);
  TenantRecoveryRequest recovery_request = {
    .base_url = base_url,
    .query = tenant_seal_query,
    .body = tenant_seal_body,
  };
  wyl_daemon_http_set_tenant_recovery_claim_checkpoint_for_test (server,
      tenant_recovery_checkpoint, &recovery_barrier);
  g_autoptr (GThread) recovery_thread = g_thread_new ("tenant-recovery",
          tenant_recovery_request_thread, &recovery_request);
  g_mutex_lock (&recovery_barrier.mutex);
  while (!recovery_barrier.entered)
    g_cond_wait (&recovery_barrier.changed, &recovery_barrier.mutex);
  g_mutex_unlock (&recovery_barrier.mutex);
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, tenant_seal_body, &status, &body);
  if (rc != 0 || status != 503
      || strstr (body, "tenant_mutation_unavailable") == NULL
      || !wyl_handle_engine_pair_is_poisoned (handle)) {
    g_mutex_lock (&recovery_barrier.mutex);
    recovery_barrier.released = TRUE;
    g_cond_broadcast (&recovery_barrier.changed);
    g_mutex_unlock (&recovery_barrier.mutex);
    g_thread_join (g_steal_pointer (&recovery_thread));
    g_free (recovery_request.response);
    g_cond_clear (&recovery_barrier.changed);
    g_mutex_clear (&recovery_barrier.mutex);
    return 2248;
  }
  g_clear_pointer (&body, g_free);
  g_mutex_lock (&recovery_barrier.mutex);
  recovery_barrier.released = TRUE;
  g_cond_broadcast (&recovery_barrier.changed);
  g_mutex_unlock (&recovery_barrier.mutex);
  g_thread_join (g_steal_pointer (&recovery_thread));
  if (recovery_request.rc != 0 || recovery_request.status != 200
      || recovery_request.response == NULL
      || strstr (recovery_request.response, "\"changed\":true") == NULL
      || wyl_handle_engine_pair_is_poisoned (handle)) {
    g_free (recovery_request.response);
    g_cond_clear (&recovery_barrier.changed);
    g_mutex_clear (&recovery_barrier.mutex);
    return 2249;
  }
  g_free (recovery_request.response);
  g_cond_clear (&recovery_barrier.changed);
  g_mutex_clear (&recovery_barrier.mutex);
#endif

  g_autofree gchar *tenant_seal_correlation = NULL;
  rc = send_raw_policy_mutation_body_full (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, tenant_seal_body, &status, &body,
          &tenant_seal_correlation);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL)
    return 200;
  if (wyl_handle_engine_pair_is_poisoned (handle)
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_seal", "tenant-a", &tenant_seal_audit_after)
      || tenant_seal_audit_after != tenant_seal_audit_before + 1
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_has_no_human_session_row (handle, "tenant-a"))
    return 2244;
  if (!tenant_projection_decision_matches (handle, "tenant-a",
      WYL_DECISION_DENY))
    return 2005;
  if (g_strcmp0 (tenant_seal_correlation, "000000000000000000000000222") == 0)
    return 2002;
  g_autofree gchar *first_tenant_seal_response = g_strdup (body);
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, tenant_seal_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || g_strcmp0 (body, first_tenant_seal_response) != 0)
    return 2003;
  g_clear_pointer (&body, g_free);

  guint sealed_create_audit_before = 0;
  guint sealed_create_audit_after = 0;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-a", &sealed_create_audit_before))
    return 2262;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/create", tenant_create_competing_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !tenant_state_matches (store, "tenant-a", TRUE, FALSE)
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_creator_anchor_matches (handle, "http-policy-racer",
      "tenant-a", FALSE)
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_create", "tenant-a", &sealed_create_audit_after)
      || sealed_create_audit_after != sealed_create_audit_before
      || wyl_handle_engine_pair_is_poisoned (handle)
      || !tenant_has_no_human_session_row (handle, "tenant-a"))
    return 2263;
  g_clear_pointer (&body, g_free);

  static const gchar *const tenant_unseal_aliases[] = {
    "/tenants/unseal/x",
    "/tenants/unsealx",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_unseal_aliases); i++) {
    rc = send_raw_policy_mutation (session, "POST", base_url,
            tenant_unseal_aliases[i], tenant_seal_query, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !tenant_state_matches (store, "tenant-a", TRUE, FALSE))
      return 213 + (gint) i;
    g_clear_pointer (&body, g_free);
  }
  rc = send_raw_login (session, "POST", base_url,
          "username=tenant-user&tenant=tenant-a&skip_mfa=true", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_sealed\"") == NULL)
    return 201;
  g_clear_pointer (&body, g_free);

  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_unseal", "tenant-a", &lifecycle_audit_before))
    return 2238;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/unseal", tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL)
    return 202;
  if (!tenant_projection_decision_matches (handle, "tenant-a",
      WYL_DECISION_ALLOW))
    return 2026;
  if (!policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_unseal", "tenant-a", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before + 1
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_has_no_human_session_row (handle, "tenant-a"))
    return 2239;
  g_clear_pointer (&body, g_free);

  static const gint64 no_op_updated_at = G_GINT64_CONSTANT (4102444800);
  gint64 unseal_generation_before = -1;
  gint64 unseal_updated_at_before = -1;
  gint64 unseal_generation_after = -1;
  gint64 unseal_updated_at_after = -1;
  if (!set_tenant_updated_at_for_test (store, "tenant-a", no_op_updated_at)
      || !tenant_metadata (store, "tenant-a", &unseal_generation_before,
      &unseal_updated_at_before)
      || unseal_updated_at_before != no_op_updated_at)
    return 2240;
  lifecycle_audit_before = lifecycle_audit_after;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/unseal", tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":false") == NULL
      || !tenant_metadata (store, "tenant-a", &unseal_generation_after,
      &unseal_updated_at_after)
      || unseal_generation_after != unseal_generation_before
      || unseal_updated_at_after != unseal_updated_at_before
      || !policy_lifecycle_audit_count (handle, "http-policy-admin",
      "tenant_unseal", "tenant-a", &lifecycle_audit_after)
      || lifecycle_audit_after != lifecycle_audit_before
      || !tenant_creator_anchor_matches (handle, "http-policy-admin",
      "tenant-a", TRUE)
      || !tenant_has_no_human_session_row (handle, "tenant-a"))
    return 2241;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", tenant_seal_query, tenant_seal_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 || body == NULL
      || strstr (body, "\"error\":\"tenant_seal_superseded\"") == NULL
      || strstr (body, "\"recorded_lifecycle_generation\":0") == NULL
      || strstr (body, "\"recorded_sealed_generation\":1") == NULL
      || strstr (body, "\"current_lifecycle_generation\":0") == NULL
      || strstr (body, "\"current_sealed_generation\":2") == NULL)
    return 2023;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *implicit_tenant_seal_query =
      g_strdup_printf ("name=tenant-a&session_token=%s"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          session_token);
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", implicit_tenant_seal_query,
          "{\"version\":\"1\",\"request_id\":"
          "\"000000000000000000000000223\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"changed\":true") == NULL)
    return 2021;
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/tenants/unseal", implicit_tenant_seal_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200)
    return 2022;
  g_clear_pointer (&body, g_free);

  WylPolicyAuthorityMutationResult tenant_promoted =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  if (wyl_policy_store_reconcile_tenant_authority
        (wyl_handle_get_policy_store (handle), "tenant-a",
      WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0,
      &tenant_promoted) != WYRELOG_E_OK
      || tenant_promoted != WYL_POLICY_AUTHORITY_MUTATION_APPLIED)
    return 2024;
  rc = send_raw_policy_mutation_body (session, "POST", base_url,
          "/tenants/seal", implicit_tenant_seal_query,
          "{\"version\":\"1\",\"request_id\":"
          "\"000000000000000000000000227\"}", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 503 || body == NULL
      || strstr (body, "tenant_lifecycle_coordination_required") == NULL)
    return 2025;
  g_clear_pointer (&body, g_free);

  /* tenant-b is deliberately legacy/test-configured and has no creator
   * anchor.  It preserves the pre-authority denial case now that tenant-a's
   * successful public create makes its creator authoritative there. */
  g_autofree gchar *transition_denied_query =
      g_strdup_printf ("subject=state-target&perm=site.policy.read"
          "&scope=tenant-b&event=grant&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition", transition_denied_query, &status,
          &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 170;
  if (permission_state_exists (handle, "state-target", "site.policy.read",
      "tenant-b"))
    return 171;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *missing_perm_grant_query =
      g_strdup_printf ("subject=target&perm=site.missing&scope=tenant-a"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", missing_perm_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 154;
  g_clear_pointer (&body, g_free);

  gint concurrent_rc = check_concurrent_permission_grants_serialize (handle,
          base_url, session_token);
  if (concurrent_rc != 0)
    return concurrent_rc;

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", missing_perm_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 155;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *missing_perm_transition_query =
      g_strdup_printf ("subject=state-target&perm=site.missing"
          "&scope=tenant-a&event=grant&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition", missing_perm_transition_query,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 172;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *invalid_edge_transition_query =
      g_strdup_printf ("subject=state-target&perm=site.policy.read"
          "&scope=tenant-a&event=revoke&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition", invalid_edge_transition_query,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 173;
  if (permission_state_exists (handle, "state-target", "site.policy.read",
      "tenant-a"))
    return 174;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *guard_denied_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=50", session_token);
  g_autofree gchar *guard_denied_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
          "/policy/permissions/grant", guard_denied_query, &status, &body,
          &guard_denied_request_id);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 133;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 134;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe guard_denied_audit = {
    .subject_id = "http-policy-admin",
    .action = "wr.policy.write",
    .resource_id = "tenant-a",
    .deny_reason = "not_armed",
    .deny_origin = "perm_state",
    .request_id = guard_denied_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_DENY,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &guard_denied_audit) != WYRELOG_E_OK)
    return 200;
  if (guard_denied_audit.matches != 1)
    return 201;
#endif
  g_clear_pointer (&body, g_free);

  g_autofree gchar *transition_allowed_query =
      g_strdup_printf ("subject=state-target&perm=site.policy.read"
          "&scope=tenant-a&event=grant&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = check_valid_policy_aliases (server, handle, session, base_url,
          "/policy/permissions/transition", transition_allowed_query, 2680);
  if (rc != 0)
    return rc;
  if (permission_state_exists (handle, "state-target", "site.policy.read",
      "tenant-a"))
    return 2682;
  g_autofree gchar *transition_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
          "/policy/permissions/transition", transition_allowed_query, &status,
          &body, &transition_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 175;
  if (!permission_state_exists (handle, "state-target", "site.policy.read",
      "tenant-a"))
    return 176;
  if (direct_permission_exists (handle, "state-target", "site.policy.read",
      "tenant-a"))
    return 177;
  AuditEventProbe transition_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_state.grant",
    .resource_id = "site.policy.read",
    .deny_reason = "grant",
    .deny_origin = "tenant-a",
    .request_id = transition_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &transition_audit) != WYRELOG_E_OK)
    return 178;
  if (transition_audit.matches != 1)
    return 179;
  g_clear_pointer (&body, g_free);

  /*
   * #762 unchanged: the public POST /policy/permissions/transition path
   * still rejects a svc: subject. The read-path transient arming does NOT
   * open a durable write path -- the store refuses perm_state for svc:
   * (WYRELOG_E_POLICY), surfaced as 400 invalid_policy_mutation. The same
   * authenticated admin/authority that just succeeded for a human subject
   * is used, so the rejection is the svc: subject, not an auth failure.
   */
  g_autofree gchar *svc_transition_query =
      g_strdup_printf ("subject=svc:transition-reject-762&perm=site.policy.read"
          "&scope=tenant-a&event=grant&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/transition", svc_transition_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 203;
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_set_principal_state (store, "client-state-target",
      "authenticated") != WYRELOG_E_OK)
    return 180;
  if (wyl_client_policy_permission_transition (client, "client-state-target",
      "site.policy.read", "tenant-a", "grant", 123, "public", 49)
      != WYRELOG_E_OK)
    return 182;
  if (!permission_state_exists (handle, "client-state-target",
      "site.policy.read", "tenant-a"))
    return 183;
  if (direct_permission_exists (handle, "client-state-target",
      "site.policy.read", "tenant-a"))
    return 184;
  PermissionStateProbe state_probe = {
    .subject_id = "client-state-target",
    .perm_id = "site.policy.read",
    .scope = "tenant-a",
    .state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state (store,
      permission_state_probe_cb, &state_probe) != WYRELOG_E_OK)
    return 185;
  if (state_probe.matches != 1)
    return 186;
  PermissionStateProbe event_probe = {
    .subject_id = "client-state-target",
    .perm_id = "site.policy.read",
    .scope = "tenant-a",
    .event = "grant",
    .from_state = "dormant",
    .to_state = "armed",
  };
  if (wyl_policy_store_foreach_permission_state_event (store,
      permission_state_event_probe_cb, &event_probe) != WYRELOG_E_OK)
    return 187;
  if (event_probe.matches != 1)
    return 188;
  AuditEventProbe client_transition_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_state.grant",
    .resource_id = "site.policy.read",
    .deny_reason = "grant",
    .deny_origin = "tenant-a",
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &client_transition_audit) != WYRELOG_E_OK)
    return 194;
  if (client_transition_audit.matches != 2)
    return 195;
  g_autoptr (wyl_decide_req_t) client_state_decide = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) client_state_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (client_state_decide, "client-state-target");
  wyl_decide_req_set_action (client_state_decide, "site.policy.read");
  wyl_decide_req_set_resource_id (client_state_decide, "tenant-a");
  if (wyl_decide (handle, client_state_decide, client_state_resp)
      != WYRELOG_E_OK)
    return 189;
  if (wyl_decide_resp_get_decision (client_state_resp) != WYL_DECISION_DENY)
    return 190;
  if (wyl_client_policy_permission_grant (client, "client-state-target",
      "site.policy.read", "tenant-a", 123, "public", 49)
      != WYRELOG_E_OK)
    return 191;
  g_autoptr (wyl_decide_req_t) client_grant_decide = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) client_grant_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (client_grant_decide, "client-state-target");
  wyl_decide_req_set_action (client_grant_decide, "site.policy.read");
  wyl_decide_req_set_resource_id (client_grant_decide, "tenant-a");
  if (wyl_decide (handle, client_grant_decide, client_grant_resp)
      != WYRELOG_E_OK)
    return 192;
  if (wyl_decide_resp_get_decision (client_grant_resp) != WYL_DECISION_ALLOW)
    return 193;

  g_autofree gchar *grant_query =
      g_strdup_printf ("subject=target&perm=site.policy.read&scope=tenant-a"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", session_token);
  rc = check_valid_policy_aliases (server, handle, session, base_url,
          "/policy/permissions/grant", grant_query, 2683);
  if (rc != 0)
    return rc;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 2685;
  g_autofree gchar *grant_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
          "/policy/permissions/grant", grant_query, &status, &body,
          &grant_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 135;
  if (!direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 136;
  if (permission_state_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 204;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "permission_grant",
    .resource_id = "tenant-a",
    .deny_origin = "site.policy.read",
    .request_id = grant_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &grant_audit) != WYRELOG_E_OK)
    return 196;
  if (grant_audit.matches != 1)
    return 197;
  AuditEventProbe grant_auth_audit = {
    .subject_id = "http-policy-admin",
    .action = "wr.policy.write",
    .resource_id = "tenant-a",
    .request_id = grant_request_id,
    .check_decision = TRUE,
    .decision = WYL_DECISION_ALLOW,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &grant_auth_audit) != WYRELOG_E_OK)
    return 202;
  if (grant_auth_audit.matches != 1)
    return 203;
#endif
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation_bearer (session, "POST", base_url,
          "/policy/permissions/grant",
          "subject=bearer-target&perm=site.policy.read&scope=tenant-a"
          "&guard_timestamp=123&guard_loc_class=public&guard_risk=49",
          access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 165;
  if (!direct_permission_exists (handle, "bearer-target", "site.policy.read",
      "tenant-a"))
    return 166;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *builtin_grant_query =
      g_strdup_printf ("subject=builtin-target&perm=wr.stream.read"
          "&scope=tenant-a&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=49", session_token);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/grant", builtin_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 156;
  if (!direct_permission_exists (handle, "builtin-target", "wr.stream.read",
      "tenant-a"))
    return 157;
  g_clear_pointer (&body, g_free);

  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/revoke", builtin_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 158;
  if (direct_permission_exists (handle, "builtin-target", "wr.stream.read",
      "tenant-a"))
    return 159;
  g_clear_pointer (&body, g_free);

  rc = check_valid_policy_aliases (server, handle, session, base_url,
          "/policy/permissions/revoke", grant_query, 2686);
  if (rc != 0)
    return rc;
  if (!direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 2688;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/revoke", grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 137;
  if (direct_permission_exists (handle, "target", "site.policy.read",
      "tenant-a"))
    return 138;

  g_autofree gchar *missing_perm_revoke_query =
      g_strdup_printf ("subject=target&perm=site.missing&scope=tenant-a"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=49", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/permissions/revoke", missing_perm_revoke_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 149;

  if (wyl_policy_store_upsert_role (store, "site.reader",
      "site reader") != WYRELOG_E_OK)
    return 139;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", "subject=role-target&role=site.missing"
          "&scope=tenant-b&session_token=unknown&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=29", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"policy_auth_required\"") == NULL)
    return 150;

  g_autofree gchar *role_denied_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", role_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 140;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 141;

  g_autofree gchar *role_missing_denied_query =
      g_strdup_printf ("subject=role-target&role=site.missing&scope=tenant-b"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", role_missing_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 151;

  if (grant_policy_role_authority (handle, "http-policy-admin",
      "tenant-b") != WYRELOG_E_OK)
    return 142;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", role_missing_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_policy_mutation\"") == NULL)
    return 152;

  g_autofree gchar *role_guard_denied_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=30", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", role_guard_denied_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"policy_denied\"") == NULL)
    return 143;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 144;

  g_autofree gchar *role_grant_query =
      g_strdup_printf ("subject=role-target&role=site.reader&scope=tenant-b"
          "&session_token=%s&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = check_valid_policy_aliases (server, handle, session, base_url,
          "/policy/roles/grant", role_grant_query, 2689);
  if (rc != 0)
    return rc;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 2691;
  g_autofree gchar *role_grant_request_id = NULL;
  rc = send_raw_policy_mutation_full (session, "POST", base_url,
          "/policy/roles/grant", role_grant_query, &status, &body,
          &role_grant_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 145;
  if (!role_membership_exists (handle, "role-target", "site.reader",
      "tenant-b"))
    return 146;
#ifdef WYL_HAS_AUDIT
  AuditEventProbe role_grant_audit = {
    .subject_id = "http-policy-admin",
    .action = "role_grant",
    .resource_id = "tenant-b",
    .deny_origin = "site.reader",
    .request_id = role_grant_request_id,
  };
  if (wyl_policy_store_foreach_audit_event (store, audit_event_probe_cb,
      &role_grant_audit) != WYRELOG_E_OK)
    return 198;
  if (role_grant_audit.matches != 1)
    return 199;
#endif

  g_autofree gchar *builtin_role_query =
      g_strdup_printf ("subject=builtin-role-target&role=wr.auditor"
          "&scope=tenant-b&session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=29", session_token);
  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/grant", builtin_role_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 160;
  if (!role_membership_exists (handle, "builtin-role-target", "wr.auditor",
      "tenant-b"))
    return 161;

  g_clear_pointer (&body, g_free);
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/revoke", builtin_role_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 162;
  if (role_membership_exists (handle, "builtin-role-target", "wr.auditor",
      "tenant-b"))
    return 163;

  g_clear_pointer (&body, g_free);
  rc = check_valid_policy_aliases (server, handle, session, base_url,
          "/policy/roles/revoke", role_grant_query, 2692);
  if (rc != 0)
    return rc;
  if (!role_membership_exists (handle, "role-target", "site.reader",
      "tenant-b"))
    return 2694;
  rc = send_raw_policy_mutation (session, "POST", base_url,
          "/policy/roles/revoke", role_grant_query, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 147;
  if (role_membership_exists (handle, "role-target", "site.reader", "tenant-b"))
    return 148;

  return 0;
}

#ifdef WYL_HAS_AUDIT
static wyrelog_error_t
grant_audit_read (WylHandle *handle, const gchar *subject_id,
    const gchar *scope)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.http-audit-role",
          "wr.audit.read");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject_id,
          "wr.http-audit-role", scope);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject_id,
          "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static gchar *
build_audit_uri (const gchar *base_url, const gchar *query)
{
  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';

  if (query == NULL)
    return g_strdup_printf ("%s/audit/events", root);
  return g_strdup_printf ("%s/audit/events?%s", root, query);
}

static gint
send_raw_audit (SoupSession *session, const gchar *base_url,
    const gchar *query, guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 90;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_audit_uri (base_url, query);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL)
    return 91;

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 92;
  gint rc = check_response_request_id_header (msg, 110);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_audit_bearer_full (SoupSession *session, const gchar *base_url,
    const gchar *query, const gchar *access_token, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (access_token == NULL)
    return 89;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri = build_audit_uri (base_url, query);
  g_autoptr (SoupMessage) msg = soup_message_new ("GET", uri);
  if (msg == NULL)
    return 91;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 92;
  gint rc = check_response_request_id_header (msg, 111);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_audit_bearer (SoupSession *session, const gchar *base_url,
    const gchar *query, const gchar *access_token, guint *out_status,
    gchar **out_body)
{
  return send_raw_audit_bearer_full (session, base_url, query, access_token,
             out_status, out_body, NULL);
}

static gint
runtime_audit_events_table_exists (WylHandle *handle, gboolean *out_exists)
{
  if (handle == NULL || out_exists == NULL)
    return 102;

  *out_exists = FALSE;
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };
  duckdb_state rc = duckdb_query (conn,
          "SELECT COUNT(*) FROM audit_events;", &result);
  duckdb_destroy_result (&result);
  *out_exists = rc == DuckDBSuccess;
  return 0;
}

static gint
check_valid_audit_aliases (SoupServer *server, WylHandle *handle,
    SoupSession *session, const gchar *base_url, const gchar *query,
    const gchar *access_token)
{
  static const gchar *const aliases[] = {
    "/audit/events/x",
    "/audit/eventsx",
  };
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  for (gsize i = 0; i < G_N_ELEMENTS (aliases); i++) {
    g_autofree gchar *path = g_strdup_printf ("%s?%s", aliases[i], query);
    WylDaemonExactRouteProbeSnapshot probe_before = { 0 }, probe_after = { 0 };
    WylDaemonExactRouteStateSnapshot state_before = { 0 }, state_after = { 0 };
    guint64 audit_before = 0, audit_after = 0;
    gboolean table_before = TRUE, table_after = TRUE;
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (!policy_audit_event_count (handle, &audit_before)
        || runtime_audit_events_table_exists (handle, &table_before) != 0
        || table_before
        || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        "/audit/events", &probe_before)
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_before)
        || send_raw_path_probe (session, "GET", base_url, path, authorization,
        NULL, &status, &body) != 0
        || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
        || !wyl_daemon_http_exact_route_probe_snapshot_for_test (server,
        "/audit/events", &probe_after)
        || probe_after.selected != probe_before.selected + 1
        || probe_after.terminal_entries != probe_before.terminal_entries
        || !wyl_daemon_http_exact_route_state_snapshot_for_test (server,
        &state_after)
        || memcmp (&state_before, &state_after, sizeof state_before) != 0
        || !policy_audit_event_count (handle, &audit_after)
        || audit_after != audit_before
        || runtime_audit_events_table_exists (handle, &table_after) != 0
        || table_after)
      return 2695 + (gint) i;
  }
  return 0;
}

static gint
check_raw_audit_contract (SoupServer *server, WylHandle *handle,
    WylClient *client, const gchar *base_url, const gchar *session_token,
    const gchar *access_token)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  gboolean audit_table_exists = TRUE;

  gint rc = send_raw_audit (session, base_url, NULL, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL) {
    g_printerr ("WYRELOG_TEST_DIAG raw_audit_unauthenticated status=%u "
        "body=%s\n", status, body != NULL ? body : "(null)");
    return 93;
  }
  if (runtime_audit_events_table_exists (handle, &audit_table_exists) != 0
      || audit_table_exists)
    return 103;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit (session, base_url,
          "session_token=unknown&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=69", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 94;
  if (runtime_audit_events_table_exists (handle, &audit_table_exists) != 0
      || audit_table_exists)
    return 104;

  g_autofree gchar *bearer_allowed =
      g_strdup_printf ("guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=69");
  rc = check_valid_audit_aliases (server, handle, session, base_url,
          bearer_allowed, access_token);
  if (rc != 0)
    return rc;
  g_autofree gchar *bearer_allowed_request_id = NULL;
  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer_full (session, base_url, bearer_allowed,
          access_token, &status, &body, &bearer_allowed_request_id);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "[") == NULL)
    return 106;
  if (runtime_audit_events_table_exists (handle, &audit_table_exists) != 0
      || !audit_table_exists)
    return 105;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit (session, base_url,
          "session_token=unknown&guard_timestamp=abc&guard_loc_class=public"
          "&guard_risk=69", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 101;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *malformed =
      g_strdup_printf ("session_token=%s&guard_timestamp=abc"
          "&guard_loc_class=public&guard_risk=69", session_token);
  rc = send_raw_audit (session, base_url, malformed, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 95;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *denied =
      g_strdup_printf ("session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=70", session_token);
  rc = send_raw_audit (session, base_url, denied, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 403 || strstr (body, "\"audit_denied\"") == NULL)
    return 98;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *bearer_unknown_tenant =
      g_strdup_printf ("tenant=unknown&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=69");
  rc = send_raw_audit_bearer (session, base_url, bearer_unknown_tenant,
          access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"tenant_invalid\"") == NULL)
    return 163;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *request_filter =
      g_strdup_printf ("request_id(\"%s\")", bearer_allowed_request_id);
  g_autofree gchar *escaped_request_filter =
      g_uri_escape_string (request_filter, NULL, TRUE);
  g_autofree gchar *request_filter_query =
      g_strdup_printf ("filter=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=69", escaped_request_filter);
  rc = send_raw_audit_bearer (session, base_url, request_filter_query,
          access_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"subject_id\":\"http-audit-user\"") == NULL ||
      strstr (body, "\"action\":\"wr.audit.read\"") == NULL ||
      strstr (body, "\"request_id\":\"") == NULL ||
      strstr (body, bearer_allowed_request_id) == NULL)
    return 160;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *mixed =
      g_strdup_printf ("session_token=%s&guard_timestamp=123"
          "&guard_loc_class=public&guard_risk=69", session_token);
  rc = send_raw_audit_bearer (session, base_url, mixed, access_token,
          &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 107;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
          "guard_timestamp=abc&guard_loc_class=public&guard_risk=69",
          "malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 || strstr (body, "\"invalid_audit_auth\"") == NULL)
    return 108;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
          "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
          "malformed.jwt", &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 109;

  gint64 now = g_get_real_time () / G_USEC_PER_SEC;
  const struct
  {
    const gchar *session_id;
    const gchar *subject;
    const gchar *principal_state;
    const gchar *issuer;
    const gchar *audience;
    gint64 issued_at_delta;
    gint failure_code;
  } invalid_tokens[] = {
    {"unknown-session", "http-audit-user", "authenticated", "wyrelogd",
     "wyrelog-client", 0, 110},
    {session_token, "other-user", "authenticated", "wyrelogd",
     "wyrelog-client", 0, 111},
    {session_token, "http-audit-user", "mfa_required", "wyrelogd",
     "wyrelog-client", 0, 112},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
     "other-audience", 0, 113},
    {session_token, "http-audit-user", "authenticated", "other-issuer",
     "wyrelog-client", 0, 116},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
     "wyrelog-client", -1000, 114},
    {session_token, "http-audit-user", "authenticated", "wyrelogd",
     "wyrelog-client", 60, 115},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_tokens); i++) {
    g_autofree gchar *bad_token = NULL;
    if (sign_test_access_token (server, invalid_tokens[i].session_id,
        invalid_tokens[i].subject, invalid_tokens[i].principal_state,
        invalid_tokens[i].issuer, invalid_tokens[i].audience,
        now + invalid_tokens[i].issued_at_delta, &bad_token)
        != WYRELOG_E_OK)
      return invalid_tokens[i].failure_code + 40;

    g_clear_pointer (&body, g_free);
    rc = send_raw_audit_bearer (session, base_url,
            "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
            bad_token, &status, &body);
    if (rc != 0)
      return rc;
    if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
      return invalid_tokens[i].failure_code;
  }

  g_autofree gchar *unregistered_token = NULL;
  if (sign_test_access_token_with_jti (server, "unregistered-access-token",
      session_token, "http-audit-user", "authenticated", "wyrelogd",
      "wyrelog-client", now, &unregistered_token) != WYRELOG_E_OK)
    return 161;
  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
          "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
          unregistered_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 162;

  g_autofree gchar *session_jti_token = NULL;
  if (sign_test_access_token_with_jti (server, session_token, session_token,
      "http-audit-user", "authenticated", "wyrelogd", "wyrelog-client",
      now, &session_jti_token) != WYRELOG_E_OK)
    return 158;

  g_clear_pointer (&body, g_free);
  rc = send_raw_audit_bearer (session, base_url,
          "guard_timestamp=123&guard_loc_class=public&guard_risk=69",
          session_jti_token, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 401 || strstr (body, "\"audit_auth_required\"") == NULL)
    return 159;

  g_autoptr (WylAuditIter) invalid_filter = NULL;
  if (wyl_client_audit_query_with_guard_context (client, "action()", 123,
      "public", 69, &invalid_filter) != WYRELOG_E_OK)
    return 99;
  gboolean has_next = FALSE;
  if (wyl_audit_iter_next (invalid_filter, &has_next) != WYRELOG_E_IO)
    return 100;

  return 0;
}

static wyrelog_error_t
drop_runtime_audit_events_table (WylHandle *handle)
{
  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };

  if (duckdb_query (conn, "DROP TABLE audit_events;", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
malform_runtime_audit_events_table (WylHandle *handle)
{
  wyrelog_error_t rc = drop_runtime_audit_events_table (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  duckdb_connection conn =
      wyl_audit_conn_get_connection (wyl_handle_get_audit_conn (handle));
  duckdb_result result = { 0 };
  if (duckdb_query (conn,
      "CREATE TABLE audit_events (id VARCHAR PRIMARY KEY);", &result)
      != DuckDBSuccess) {
    duckdb_destroy_result (&result);
    return WYRELOG_E_IO;
  }

  duckdb_destroy_result (&result);
  return WYRELOG_E_OK;
}

static gint
check_readyz_malformed_audit_projection_contract (WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (malform_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 1914;
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1915;
  if (status != 503 || strstr (body, "\"audit_degraded\"") == NULL)
    return 1916;

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 1917;
  if (wyl_audit_conn_create_schema (wyl_handle_get_audit_conn (handle))
      != WYRELOG_E_OK)
    return 1918;

  g_clear_pointer (&body, g_free);
  if (send_raw_path (session, "GET", base_url, "/readyz", &status, &body)
      != 0)
    return 1919;
  return status == 200 ? 0 : 1920;
}

static gint
check_audit_event_present (WylClient *client, const gchar *filter,
    const gchar *subject, const gchar *action, const gchar *resource,
    wyl_decision_t decision, const gchar *deny_reason, const gchar *deny_origin)
{
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query_with_guard_context (client, filter, 123,
      "public", 69, &iter) != WYRELOG_E_OK)
    return 80;

  while (TRUE) {
    gboolean has_next = FALSE;
    if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
      return 81;
    if (!has_next)
      return 82;

    g_autoptr (WylAuditEvent) event = wyl_audit_iter_ref_event (iter);
    if (event == NULL)
      return 83;
    if (g_strcmp0 (wyl_audit_event_get_subject_id (event), subject) == 0 &&
        g_strcmp0 (wyl_audit_event_get_action (event), action) == 0 &&
        g_strcmp0 (wyl_audit_event_get_resource_id (event), resource) == 0 &&
        wyl_audit_event_get_decision (event) == decision &&
        g_strcmp0 (wyl_audit_event_get_deny_reason (event), deny_reason) == 0 &&
        g_strcmp0 (wyl_audit_event_get_deny_origin (event), deny_origin) == 0)
      return 0;
  }
}

#endif /* WYL_HAS_AUDIT */

#ifdef WYL_HAS_FACT_STORE
typedef enum
{
  SERVICE_CREDENTIAL_SUBJECT_PREPARE_SETUP_FAILED,
  SERVICE_CREDENTIAL_SUBJECT_PREPARE_PRINCIPAL_CREATE_FAILED,
  SERVICE_CREDENTIAL_SUBJECT_PREPARE_TENANT_CREATE_FAILED,
} ServiceCredentialSubjectPrepareFailure;

static wyrelog_error_t
prepare_service_credential_subject (WylHandle *handle, const gchar *subject_id,
    ServiceCredentialSubjectPrepareFailure *out_failure)
{
  if (out_failure != NULL)
    *out_failure = SERVICE_CREDENTIAL_SUBJECT_PREPARE_SETUP_FAILED;
  wyl_service_principal_t principal = { 0 };
  g_autofree gchar *request_id = g_strdup_printf ("principal-create:%s",
          subject_id);
  if (request_id == NULL)
    return WYRELOG_E_INTERNAL;
  wyrelog_error_t rc = wyl_service_principal_create (handle, subject_id,
          subject_id, "admin", request_id, &principal);
  if (rc != WYRELOG_E_OK) {
    if (out_failure != NULL)
      *out_failure = SERVICE_CREDENTIAL_SUBJECT_PREPARE_PRINCIPAL_CREATE_FAILED;
    return rc;
  }
  wyl_service_principal_clear (&principal);
  gboolean created = FALSE;
  rc = wyl_policy_store_create_tenant (wyl_handle_get_policy_store (handle),
          "tenant-a", &created);
  if (rc != WYRELOG_E_OK) {
    if (out_failure != NULL)
      *out_failure = SERVICE_CREDENTIAL_SUBJECT_PREPARE_TENANT_CREATE_FAILED;
    return rc;
  }
  return WYRELOG_E_OK;
}

static gint
check_service_credential_operation_reconcile_contract (SoupServer *server,
    WylHandle *handle, const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* Keep the deterministic management session live while this fixture writes
   * permission facts directly; production retirement behavior is covered by
   * the dedicated authority-race tests. */
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (server);
  wyl_id_t session_id = WYL_ID_NIL;
  gchar session_token[WYL_ID_STRING_BUF] = { 0 };
  g_autofree gchar *access_token = NULL;
  if (wyl_id_new (&session_id) != WYRELOG_E_OK
      || wyl_id_format (&session_id, session_token,
      sizeof session_token) != WYRELOG_E_OK
      || !seed_management_human_access_token (server, session_token,
      "http-allow-user", &access_token))
    return 1922;
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK)
    return 1925;
  g_autofree gchar *issue_body =
      g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:reconcile:issue\",\"tenant\":\"tenant-a\"}}",
          issue_request_id);
  g_autofree gchar *query =
      g_strdup ("tenant=tenant-a&guard_timestamp=123&guard_loc_class=public"
          "&guard_risk=69");
  gint rc = send_raw_reconcile (session, "POST", base_url, NULL, issue_body,
          &status, &body);
  if (rc != 0 || status != 401)
    return 1923;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean tenant_created = FALSE;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &tenant_created)
      != WYRELOG_E_OK)
    return 1923;
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, issue_body, &status, &body);
  if (rc != 0 || status != 403)
    return 1923;
  wyrelog_error_t grant_rc = wyl_policy_store_set_principal_state (store,
          "http-allow-user", "authenticated");
  if (grant_rc != WYRELOG_E_OK)
    return 1923;
  grant_rc = wyl_policy_store_grant_direct_permission (store,
          "http-allow-user", "wr.service_credential.manage", session_token);
  if (grant_rc != WYRELOG_E_OK)
    return 1923;
  grant_rc = wyl_policy_store_set_session_state (store, session_token,
          "active");
  if (grant_rc != WYRELOG_E_OK)
    return 1923;
  grant_rc = wyl_policy_store_set_permission_state (store, "http-allow-user",
          "wr.service_credential.manage", session_token, "armed");
  if (grant_rc != WYRELOG_E_OK)
    return 1923;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 1923;

  ServiceCredentialSubjectPrepareFailure issue_prepare_failure =
      SERVICE_CREDENTIAL_SUBJECT_PREPARE_SETUP_FAILED;
  wyrelog_error_t issue_prepare_rc = prepare_service_credential_subject
        (handle, "svc:reconcile:issue", &issue_prepare_failure);
  if (issue_prepare_rc != WYRELOG_E_OK) {
    /*
     * Keep legacy 1924 for the principal write and use compact fallback
     * values for the other stages.  CI must use the structured
     * WYRELOG_TEST_DIAG line below as the authoritative discriminator: exit
     * status values alone are not globally unique across this test source.
     */
    if (issue_prepare_failure ==
        SERVICE_CREDENTIAL_SUBJECT_PREPARE_PRINCIPAL_CREATE_FAILED) {
      g_printerr ("WYRELOG_TEST_DIAG reconcile_subject_prepare "
          "phase=principal_create rc=%d\n", issue_prepare_rc);
      return 1924;
    }
    if (issue_prepare_failure ==
        SERVICE_CREDENTIAL_SUBJECT_PREPARE_TENANT_CREATE_FAILED) {
      g_printerr ("WYRELOG_TEST_DIAG reconcile_subject_prepare "
          "phase=tenant_create rc=%d\n", issue_prepare_rc);
      return 251;
    }
    g_printerr ("WYRELOG_TEST_DIAG reconcile_subject_prepare "
        "phase=setup rc=%d\n", issue_prepare_rc);
    return 252;
  }
  wyl_service_credential_issue_result_t issue_result = { 0 };
  if (wyl_service_credential_issue (handle, "svc:reconcile:issue",
      "tenant-a", "http-allow-user", issue_request_id,
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &issue_result)
      != WYRELOG_E_OK)
    return 1926;
  g_autofree gchar *issue_credential_id = g_strdup
        (issue_result.credential.credential_id);
  guint64 issue_generation = issue_result.credential.generation;
  wyl_service_credential_issue_result_clear (&issue_result);

  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, issue_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"status\":\"committed\"") == NULL ||
      strstr (body, "\"operation\":\"issue\"") == NULL)
    return 1927;
  g_autofree gchar *response_issue_credential_id = extract_json_string (body,
          "credential_id");
  if (response_issue_credential_id == NULL ||
      g_strcmp0 (response_issue_credential_id, issue_credential_id) != 0)
    return 1928;
  g_autofree gchar *issue_generation_needle =
      g_strdup_printf ("\"generation\":%" G_GUINT64_FORMAT, issue_generation);
  if (strstr (body, issue_generation_needle) == NULL)
    return 1929;

  g_autofree gchar *noncanonical_request_body = g_strdup
        ("{\"version\":1,\"request_id\":\"abcdefghijklmnopqrstuvwxyz0\","
          "\"operation\":\"issue\",\"target\":{\"subject\":"
          "\"svc:reconcile:issue\",\"tenant\":\"tenant-a\"}}");
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, noncanonical_request_body, &status, &body);
  if (rc != 0 || status != 400)
    return 1929;
  g_autofree gchar *unknown_operation_body = g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"revoke\","
          "\"target\":{\"subject\":\"svc:reconcile:issue\",\"tenant\":\"tenant-a\"}}",
          issue_request_id);
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, unknown_operation_body, &status, &body);
  if (rc != 0 || status != 400)
    return 1929;

  g_autofree gchar *mismatched_issue_body = g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:reconcile:issue\","
          "\"tenant\":\"__wr_default\"}}", issue_request_id);
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, mismatched_issue_body, &status, &body);
  if (rc != 0 || status != 400)
    return 1929;

  g_autofree gchar *unknown_rotate_body = g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"rotate\","
          "\"target\":{\"old_credential_id\":"
          "\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\"}}", issue_request_id);
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, unknown_rotate_body, &status, &body);
  if (rc != 0 || status != 404)
    return 1929;

  if (prepare_service_credential_subject (handle, "svc:reconcile:rotate",
      NULL) != WYRELOG_E_OK)
    return 1930;
  gchar rotate_seed_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (rotate_seed_request_id, sizeof rotate_seed_request_id)
      != WYRELOG_E_OK)
    return 1931;
  wyl_service_credential_issue_result_t rotate_seed = { 0 };
  if (wyl_service_credential_issue (handle, "svc:reconcile:rotate",
      "tenant-a", "http-allow-user", rotate_seed_request_id,
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &rotate_seed)
      != WYRELOG_E_OK)
    return 1932;
  g_autofree gchar *rotate_old_credential_id =
      g_strdup (rotate_seed.credential.credential_id);
  wyl_service_credential_issue_result_clear (&rotate_seed);

  gchar rotate_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (rotate_request_id, sizeof rotate_request_id)
      != WYRELOG_E_OK)
    return 1933;
  wyl_service_credential_issue_result_t rotate_result = { 0 };
  if (wyl_service_credential_rotate (handle, rotate_old_credential_id,
      "http-allow-user", rotate_request_id,
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &rotate_result)
      != WYRELOG_E_OK)
    return 1934;
  g_autofree gchar *rotate_credential_id =
      g_strdup (rotate_result.credential.credential_id);
  guint64 rotate_generation = rotate_result.credential.generation;
  wyl_service_credential_issue_result_clear (&rotate_result);

  g_autofree gchar *rotate_body =
      g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"rotate\","
          "\"target\":{\"old_credential_id\":\"%s\"}}",
          rotate_request_id, rotate_old_credential_id);
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, rotate_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 || strstr (body, "\"status\":\"committed\"") == NULL ||
      strstr (body, "\"operation\":\"rotate\"") == NULL)
    return 1935;
  g_autofree gchar *response_rotate_credential_id = extract_json_string (body,
          "credential_id");
  if (response_rotate_credential_id == NULL ||
      g_strcmp0 (response_rotate_credential_id, rotate_credential_id) != 0)
    return 1936;
  g_autofree gchar *rotate_generation_needle =
      g_strdup_printf ("\"generation\":%" G_GUINT64_FORMAT, rotate_generation);
  if (strstr (body, rotate_generation_needle) == NULL)
    return 1937;

  gchar pending_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (pending_request_id, sizeof pending_request_id)
      != WYRELOG_E_OK)
    return 1938;
  g_autofree gchar *pending_body =
      g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:reconcile:pending\",\"tenant\":\"tenant-a\"}}",
          pending_request_id);
  if (prepare_service_credential_subject (handle, "svc:reconcile:pending",
      NULL) != WYRELOG_E_OK)
    return 1939;

  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, pending_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"status\":\"not_committed_terminal\"") == NULL ||
      strstr (body, "\"operation\":\"issue\"") == NULL ||
      strstr (body, "\"credential_id\":") != NULL)
    return 1940;

  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, pending_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 200 ||
      strstr (body, "\"status\":\"not_committed_terminal\"") == NULL)
    return 1941;

  g_autofree gchar *conflict_body =
      g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:reconcile:conflict\",\"tenant\":\"tenant-a\"}}",
          pending_request_id);
  if (prepare_service_credential_subject (handle, "svc:reconcile:conflict",
      NULL) != WYRELOG_E_OK)
    return 1942;
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, conflict_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 409 ||
      strstr (body, "\"error\":\"operation_request_conflict\"") == NULL)
    return 1943;

  g_autofree gchar *invalid_body =
      g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:reconcile:bad\",\"tenant\":\"tenant-a\","
          "\"extra\":\"x\"}}", pending_request_id);
  g_clear_pointer (&body, g_free);
  rc = send_raw_reconcile_bearer (session, "POST", base_url, query,
          access_token, invalid_body, &status, &body);
  if (rc != 0)
    return rc;
  if (status != 400 ||
      strstr (body,
      "\"error\":\"invalid_service_credential_operation_reconcile_request\"")
      == NULL)
    return 1944;

  return 0;
}

static gint
check_service_profile_reconcile_denied (WylHandle *handle)
{
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .profile = WYL_DAEMON_PROFILE_SERVICE,
  };
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = g_main_context_new ();
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server (&opts, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL) {
    g_clear_pointer (&http.loop, g_main_loop_unref);
    return 1945;
  }
  GThread *thread = g_thread_new ("daemon-http-reconcile-service-profile",
          test_http_server_thread_ctx, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL) {
    g_main_loop_quit (http.loop);
    g_thread_join (thread);
    soup_server_disconnect (http.server);
    g_clear_object (&http.server);
    g_clear_pointer (&http.loop, g_main_loop_unref);
    return 1946;
  }
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = base_url == NULL ? 1947 : send_raw_reconcile (session, "POST",
          base_url, NULL, "{}", &status, &body);
  /* The status and recover endpoints deny a non-SYSTEM profile the same way,
   * before any body or session is inspected. */
  guint status_status = 0;
  guint recover_status = 0;
  g_autofree gchar *status_body = NULL;
  g_autofree gchar *recover_body = NULL;
  if (rc == 0 && status == 403) {
    if (send_raw_service_principal_full (session, "GET", base_url,
        "/service-credential-operations", "tenant=tenant-a", NULL,
        &status_status, &status_body) != 0 || status_status != 403)
      rc = 1949;
    else if (send_raw_service_principal_full (session, "POST", base_url,
        "/service-credential-operations/recover", "tenant=tenant-a",
        "{\"version\":\"1\",\"request_id\":\"111111111111111111111111111\"}",
        &recover_status, &recover_body) != 0 || recover_status != 403)
      rc = 1950;
  }
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return rc == 0 && status == 403 ? 0 : (rc != 0 ? rc : 1948);
}
#endif

#ifdef WYL_HAS_AUDIT
static void
prepare_service_token_subject (WylHandle *handle, const gchar *subject_id)
{
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, subject_id,
      subject_id, "admin", "principal-create", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (wyl_handle_get_policy_store (handle), "tenant-a", &created), ==,
      WYRELOG_E_OK);
  g_assert_true (created);
}

static void
issue_service_token_credential (WylHandle *handle, const gchar *subject_id,
    const gchar *tenant_id, const gchar *request_id, gint64 expires_at_us,
    wyl_service_credential_issue_result_t *out)
{
  g_assert_cmpint (wyl_service_credential_issue (handle, subject_id,
      tenant_id, "admin", request_id, expires_at_us, out), ==,
      WYRELOG_E_OK);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean pre_handoff;
  gboolean active_pre_handoff_failure;
  gboolean close_now;
  gboolean socket_closed;
  gboolean release_handler;
  gboolean terminal;
  gboolean body_wiped;
  gboolean unclaimed_fallback;
  gboolean authority_destroyed;
  gboolean shutdown_on_socket_close;
  gboolean shutdown_done;
  SoupServer *shutdown_server;
  gint terminal_phase;
  gchar *session_id;
  gchar *jti;
} ServiceResponseDeliveryBarrier;

typedef struct
{
  GMutex mutex;
  GCond changed;
  gboolean before_write;
  gboolean entered;
  gboolean release;
} ServiceResponseRetireBarrier;

typedef enum
{
  SERVICE_ABORT_RACE_CREDENTIAL_ROTATE = 1,
  SERVICE_ABORT_RACE_CREDENTIAL_REVOKE,
  SERVICE_ABORT_RACE_PRINCIPAL_DISABLE,
  SERVICE_ABORT_RACE_TENANT_SEAL,
  SERVICE_ABORT_RACE_EXPIRY,
  SERVICE_ABORT_PARTIAL_MISMATCH,
  SERVICE_ABORT_CROSSED_MISMATCH,
} ServiceAbortRaceKind;

typedef struct
{
  SoupServer *server;
  WylHandle *handle;
  ServiceAbortRaceKind kind;
  const gchar *subject;
  const gchar *tenant;
  const gchar *credential_id;
  guint64 credential_generation;
  GMutex mutex;
  GCond changed;
  gboolean acquired;
  gboolean release;
  wyrelog_error_t rc;
} ServiceAbortMutation;

typedef struct
{
  const gchar *base_url;
  const gchar *request_body;
  ServiceResponseDeliveryBarrier *barrier;
  gint rc;
} DroppedServiceTokenResponse;

typedef struct
{
  const gchar *base_url;
  const gchar *request_body;
  gint rc;
  guint status;
  gchar *body;
} FinishedServiceTokenResponse;

typedef struct
{
  GMainContext *context;
  TestHttpServer http;
  GThread *thread;
  gchar *base_url;
} ServiceResponseTestServer;

static gboolean
service_response_test_server_start (ServiceResponseTestServer *fixture,
    WylHandle *handle)
{
  g_autoptr (GError) error = NULL;
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  fixture->context = g_main_context_new ();
  fixture->http.loop = g_main_loop_new (fixture->context, FALSE);
  g_main_context_push_thread_default (fixture->context);
  fixture->http.server = wyl_daemon_start_http_server (&options, handle,
          &error);
  g_main_context_pop_thread_default (fixture->context);
  if (fixture->http.server == NULL)
    return FALSE;
  fixture->thread = g_thread_new ("service-response-server",
          test_http_server_thread_ctx, &fixture->http);
  GSList *uris = soup_server_get_uris (fixture->http.server);
  if (uris != NULL)
    fixture->base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  return fixture->base_url != NULL;
}

static void
service_response_test_server_stop (ServiceResponseTestServer *fixture)
{
  if (fixture->http.server != NULL)
    soup_server_disconnect (fixture->http.server);
  if (fixture->http.loop != NULL)
    g_main_loop_quit (fixture->http.loop);
  if (fixture->thread != NULL) {
    g_thread_join (fixture->thread);
    fixture->thread = NULL;
  }
  g_clear_object (&fixture->http.server);
  g_clear_pointer (&fixture->http.loop, g_main_loop_unref);
  g_clear_pointer (&fixture->context, g_main_context_unref);
  g_clear_pointer (&fixture->base_url, g_free);
}

static void
service_response_delivery_checkpoint (gint phase, const gchar *session_id,
    const gchar *jti, gpointer data)
{
  ServiceResponseDeliveryBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  if (phase == WYL_DAEMON_SERVICE_RESPONSE_PRE_HANDOFF) {
    g_free (barrier->session_id);
    g_free (barrier->jti);
    barrier->session_id = g_strdup (session_id);
    barrier->jti = g_strdup (jti);
    barrier->pre_handoff = TRUE;
    g_cond_broadcast (&barrier->changed);
    while (!barrier->release_handler) {
      if (barrier->shutdown_on_socket_close && barrier->socket_closed
          && !barrier->shutdown_done) {
        SoupServer *server = barrier->shutdown_server;
        g_mutex_unlock (&barrier->mutex);
        wyl_daemon_http_shutdown_service_auth_maintenance_for_test (server);
        soup_server_disconnect (server);
        g_mutex_lock (&barrier->mutex);
        barrier->shutdown_done = TRUE;
        g_cond_broadcast (&barrier->changed);
        continue;
      }
      g_cond_wait (&barrier->changed, &barrier->mutex);
    }
  } else if (phase == WYL_DAEMON_SERVICE_RESPONSE_ACTIVE_PRE_HANDOFF_FAILURE) {
    g_free (barrier->session_id);
    g_free (barrier->jti);
    barrier->session_id = g_strdup (session_id);
    barrier->jti = g_strdup (jti);
    barrier->active_pre_handoff_failure = TRUE;
    g_cond_broadcast (&barrier->changed);
    while (!barrier->release_handler)
      g_cond_wait (&barrier->changed, &barrier->mutex);
  } else if (phase == WYL_DAEMON_SERVICE_RESPONSE_BODY_WIPED) {
    barrier->body_wiped = TRUE;
    g_cond_broadcast (&barrier->changed);
  } else if (phase == WYL_DAEMON_SERVICE_RESPONSE_UNCLAIMED_FALLBACK
      && g_strcmp0 (barrier->session_id, session_id) == 0
      && g_strcmp0 (barrier->jti, jti) == 0) {
    barrier->unclaimed_fallback = TRUE;
    g_cond_broadcast (&barrier->changed);
  } else if (phase == WYL_DAEMON_SERVICE_RESPONSE_AUTHORITY_DESTROYED
      && g_strcmp0 (barrier->session_id, session_id) == 0
      && g_strcmp0 (barrier->jti, jti) == 0) {
    barrier->authority_destroyed = TRUE;
    g_cond_broadcast (&barrier->changed);
  } else if (g_strcmp0 (barrier->session_id, session_id) == 0
      && g_strcmp0 (barrier->jti, jti) == 0) {
    barrier->terminal = TRUE;
    barrier->terminal_phase = phase;
    g_cond_broadcast (&barrier->changed);
  }
  g_mutex_unlock (&barrier->mutex);
}

static void
service_response_retire_checkpoint (gint phase, const gchar *session_id,
    const gchar *jti, gpointer data)
{
  (void) session_id;
  (void) jti;
  ServiceResponseRetireBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  if (phase == WYL_DAEMON_SERVICE_RESPONSE_RETIRE_BEFORE_WRITE_ACQUIRE)
    barrier->before_write = TRUE;
  else
    barrier->entered = TRUE;
  g_cond_broadcast (&barrier->changed);
  while (phase == WYL_DAEMON_SERVICE_RESPONSE_RETIRE_WRITE_ACQUIRED
      && !barrier->release)
    g_cond_wait (&barrier->changed, &barrier->mutex);
  g_mutex_unlock (&barrier->mutex);
}

static void
service_abort_mutation_checkpoint (gpointer data)
{
  ServiceAbortMutation *mutation = data;
  g_mutex_lock (&mutation->mutex);
  mutation->acquired = TRUE;
  g_cond_broadcast (&mutation->changed);
  while (!mutation->release)
    g_cond_wait (&mutation->changed, &mutation->mutex);
  g_mutex_unlock (&mutation->mutex);
}

static gpointer
service_abort_mutation_thread (gpointer data)
{
  ServiceAbortMutation *mutation = data;
  switch (mutation->kind) {
    case SERVICE_ABORT_RACE_CREDENTIAL_ROTATE:
      mutation->rc = wyl_daemon_http_rotate_service_credential_for_test
            (mutation->server, mutation->credential_id,
              mutation->credential_generation, "000000000000000000000000240",
              service_abort_mutation_checkpoint, mutation);
      break;
    case SERVICE_ABORT_RACE_CREDENTIAL_REVOKE:
      mutation->rc = wyl_daemon_http_revoke_service_credential_for_test
            (mutation->server, mutation->credential_id,
              "000000000000000000000000241",
              service_abort_mutation_checkpoint, mutation);
      break;
    case SERVICE_ABORT_RACE_PRINCIPAL_DISABLE:
      mutation->rc = wyl_daemon_http_disable_service_principal_for_test
            (mutation->server, mutation->subject,
              "000000000000000000000000242",
              service_abort_mutation_checkpoint, mutation);
      break;
    case SERVICE_ABORT_RACE_TENANT_SEAL:
      mutation->rc = wyl_daemon_http_seal_tenant_for_test (mutation->server,
              mutation->tenant, service_abort_mutation_checkpoint, mutation);
      break;
    case SERVICE_ABORT_RACE_EXPIRY:
      mutation->rc = wyl_daemon_http_retire_due_service_auth_for_test
            (mutation->server);
      break;
    case SERVICE_ABORT_PARTIAL_MISMATCH:
    case SERVICE_ABORT_CROSSED_MISMATCH:
      mutation->rc = WYRELOG_E_INVALID;
      break;
  }
  return NULL;
}

static gpointer
dropped_service_token_response_thread (gpointer data)
{
  DroppedServiceTokenResponse *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_autofree gchar *wire = g_strdup_printf
        ("POST /auth/service-token HTTP/1.1\r\nHost: %s:%d\r\n"
          "Content-Type: application/json\r\nConnection: close\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
          g_uri_get_host (uri), g_uri_get_port (uri),
          strlen (request->request_body), request->request_body);
  gsize written = 0;
  GOutputStream *output = g_io_stream_get_output_stream
        (G_IO_STREAM (connection));
  if (!g_output_stream_write_all (output, wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)
      || !g_output_stream_flush (output, NULL, &error)) {
    request->rc = 2;
    return NULL;
  }

  g_mutex_lock (&request->barrier->mutex);
  while (!request->barrier->close_now)
    g_cond_wait (&request->barrier->changed, &request->barrier->mutex);
  g_mutex_unlock (&request->barrier->mutex);
  request->rc = g_io_stream_close (G_IO_STREAM (connection), NULL, &error)
      ? 0 : 3;
  g_mutex_lock (&request->barrier->mutex);
  request->barrier->socket_closed = TRUE;
  g_cond_broadcast (&request->barrier->changed);
  g_mutex_unlock (&request->barrier->mutex);
  return NULL;
}

static gpointer
finished_service_token_response_thread (gpointer data)
{
  FinishedServiceTokenResponse *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_socket_set_timeout (g_socket_connection_get_socket (connection), 15);
  g_autofree gchar *wire = g_strdup_printf
        ("POST /auth/service-token HTTP/1.1\r\nHost: %s:%d\r\n"
          "Content-Type: application/json\r\nConnection: close\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
          g_uri_get_host (uri), g_uri_get_port (uri),
          strlen (request->request_body), request->request_body);
  GOutputStream *output = g_io_stream_get_output_stream
        (G_IO_STREAM (connection));
  gsize written = 0;
  if (!g_output_stream_write_all (output, wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)
      || !g_output_stream_flush (output, NULL, &error)) {
    request->rc = 2;
    return NULL;
  }

  g_autoptr (GByteArray) response = g_byte_array_new ();
  guint8 chunk[1024];
  GInputStream *input = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  for (;;) {
    gssize count = g_input_stream_read (input, chunk, sizeof chunk, NULL,
            &error);
    if (count < 0) {
      request->rc = 3;
      return NULL;
    }
    if (count == 0)
      break;
    g_byte_array_append (response, chunk, (guint) count);
    gsize content_length = 0;
    if (http_response_parse_content_length (response->data, response->len,
        &content_length)) {
      const gchar *headers_end = g_strstr_len ((const gchar *) response->data,
              response->len, "\r\n\r\n");
      if (headers_end != NULL) {
        gsize header_length =
            (gsize) (headers_end - (const gchar *) response->data);
        if (response->len >= header_length + 4 + content_length)
          break;
      }
    }
  }
  g_byte_array_append (response, (const guint8 *) "\0", 1);
  gchar *headers_end = strstr ((gchar *) response->data, "\r\n\r\n");
  if (headers_end == NULL
      || sscanf ((gchar *) response->data, "HTTP/1.1 %u", &request->status)
      != 1) {
    request->rc = 4;
    return NULL;
  }
  request->body = g_strdup (headers_end + 4);
  return NULL;
}

static gboolean
service_response_delivery_wait (ServiceResponseDeliveryBarrier *barrier,
    gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  while (!*flag
      && g_cond_wait_until (&barrier->changed, &barrier->mutex, deadline));
  return *flag;
}

static gint
send_service_token_response_and_wait (SoupServer *server,
    SoupSession *session, const gchar *base_url, const gchar *request_body,
    guint *out_status, gchar **out_body, gboolean *out_completed)
{
  *out_completed = FALSE;
  ServiceResponseDeliveryBarrier *barrier =
      g_new0 (ServiceResponseDeliveryBarrier, 1);
  g_mutex_init (&barrier->mutex);
  g_cond_init (&barrier->changed);
  barrier->release_handler = TRUE;
  wyl_daemon_http_reset_service_response_authority_for_test (server);
  wyl_daemon_http_set_service_response_checkpoint_for_test (server,
      service_response_delivery_checkpoint, barrier);
  gint rc = send_raw_service_principal_full (session, "POST", base_url,
          "/auth/service-token", NULL, request_body, out_status, out_body);
  if (rc == 0) {
    g_mutex_lock (&barrier->mutex);
    gboolean terminal = service_response_delivery_wait (barrier,
            &barrier->terminal);
    gboolean body_wiped = service_response_delivery_wait (barrier,
            &barrier->body_wiped);
    gboolean destroyed = service_response_delivery_wait (barrier,
            &barrier->authority_destroyed);
    *out_completed = terminal && body_wiped && destroyed
        && barrier->terminal_phase == WYL_DAEMON_SERVICE_RESPONSE_FINISHED;
    g_mutex_unlock (&barrier->mutex);
  }
  wyl_daemon_http_set_service_response_checkpoint_for_test (server, NULL, NULL);
  if (*out_completed) {
    g_free (barrier->session_id);
    g_free (barrier->jti);
    g_cond_clear (&barrier->changed);
    g_mutex_clear (&barrier->mutex);
    g_free (barrier);
  }
  /* On a failing timeout, keep the test-only barrier alive: a callback may
   * already have copied its data pointer before the server unset above. */
  return rc;
}

static gboolean
service_response_retire_wait (ServiceResponseRetireBarrier *barrier)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  g_mutex_lock (&barrier->mutex);
  while (!barrier->entered
      && g_cond_wait_until (&barrier->changed, &barrier->mutex, deadline));
  gboolean entered = barrier->entered;
  g_mutex_unlock (&barrier->mutex);
  return entered;
}

static gboolean
service_response_retire_wait_before_write
  (ServiceResponseRetireBarrier * barrier)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  g_mutex_lock (&barrier->mutex);
  while (!barrier->before_write
      && g_cond_wait_until (&barrier->changed, &barrier->mutex, deadline));
  gboolean before_write = barrier->before_write;
  g_mutex_unlock (&barrier->mutex);
  return before_write;
}

static gboolean
service_abort_mutation_wait (ServiceAbortMutation *mutation)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  g_mutex_lock (&mutation->mutex);
  while (!mutation->acquired
      && g_cond_wait_until (&mutation->changed, &mutation->mutex, deadline));
  gboolean acquired = mutation->acquired;
  g_mutex_unlock (&mutation->mutex);
  return acquired;
}

static gboolean
service_abort_wait_writer_queued (SoupServer *server)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_USEC_PER_SEC;
  do {
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_daemon_http_service_authority_snapshot_for_test (server, &snapshot);
    if (snapshot.writer_active && snapshot.waiting_writers == 1)
      return TRUE;
    g_thread_yield ();
  } while (g_get_monotonic_time () < deadline);
  return FALSE;
}

static gint
check_service_response_delivery_finished (SoupServer *server,
    const gchar *base_url, const gchar *request_body)
{
  guint sessions_before = 0;
  guint access_before = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &sessions_before, &access_before);
  ServiceResponseDeliveryBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  FinishedServiceTokenResponse finished = {
    .base_url = base_url,
    .request_body = request_body,
  };
  wyl_daemon_http_reset_service_response_authority_for_test (server);
  wyl_daemon_http_set_service_response_checkpoint_for_test (server,
      service_response_delivery_checkpoint, &barrier);
  GThread *thread = g_thread_new ("finished-service-response",
          finished_service_token_response_thread, &finished);

  g_mutex_lock (&barrier.mutex);
  gboolean pre_handoff = service_response_delivery_wait (&barrier,
          &barrier.pre_handoff);
  barrier.release_handler = TRUE;
  g_cond_broadcast (&barrier.changed);
  gboolean terminal = service_response_delivery_wait (&barrier,
          &barrier.terminal);
  gboolean body_wiped = service_response_delivery_wait (&barrier,
          &barrier.body_wiped);
  gboolean destroyed = service_response_delivery_wait (&barrier,
          &barrier.authority_destroyed);
  g_mutex_unlock (&barrier.mutex);
  g_thread_join (thread);
  wyl_daemon_http_set_service_response_checkpoint_for_test (server, NULL, NULL);

  guint sessions_after = 0;
  guint access_after = 0;
  guint response_wipes = 0;
  gboolean response_canary = FALSE;
  gboolean response_all_zero = FALSE;
  WylDaemonServiceResponseAuthoritySnapshot authority = { 0 };
  wyl_daemon_http_service_publication_counts_for_test (server,
      &sessions_after, &access_after);
  wyl_daemon_http_service_response_authority_snapshot_for_test (server,
      &authority);
  wyl_daemon_http_service_response_wipe_snapshot_for_test (server,
      &response_wipes, &response_canary, &response_all_zero);
  gint result = 0;
  if (!pre_handoff || finished.rc != 0 || finished.status != 200
      || finished.body == NULL)
    result = 195912;
  else if (!terminal
      || barrier.terminal_phase != WYL_DAEMON_SERVICE_RESPONSE_FINISHED)
    result = 195913;
  else if (!body_wiped || !destroyed || response_wipes != 1 || !response_canary
      || !response_all_zero)
    result = 195914;
  else if (authority.created != 1 || authority.complete != 1
      || authority.attached != 1 || authority.finished != 1
      || authority.aborted != 0 || authority.cleanup_failed != 0
      || authority.destroyed != 1 || authority.duplicate_outcomes != 0
      || authority.unclaimed_fallbacks != 0)
    result = 195915;
  else if (sessions_after != sessions_before + 1
      || access_after != access_before + 1)
    result = 195916;
  if (result == 0) {
    g_autofree gchar *token = extract_json_string (finished.body,
            "access_token");
    g_autofree gchar *jti = token != NULL ? access_token_jti (server,
            token) : NULL;
    g_autofree gchar *session = NULL;
    g_autofree gchar *actor = NULL;
    g_autofree gchar *tenant = NULL;
    if (token == NULL || jti == NULL
        || wyl_daemon_http_resolve_bearer_for_test (server, token, &session,
        &actor, &tenant) != WYRELOG_E_OK
        || g_strcmp0 (session, barrier.session_id) != 0
        || g_strcmp0 (jti, barrier.jti) != 0
        || g_strcmp0 (actor, "svc:exchange:worker") != 0
        || g_strcmp0 (tenant, "tenant-a") != 0)
      result = 195917;
  }

  g_free (finished.body);
  g_free (barrier.session_id);
  g_free (barrier.jti);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return result;
}

static gint
check_service_response_delivery_abort (SoupServer *server,
    const gchar *base_url, const gchar *request_body)
{
  guint sessions_before = 0;
  guint access_before = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &sessions_before, &access_before);
  ServiceResponseDeliveryBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  DroppedServiceTokenResponse dropped = {
    .base_url = base_url,
    .request_body = request_body,
    .barrier = &barrier,
  };
  wyl_daemon_http_reset_service_response_authority_for_test (server);
  wyl_daemon_http_set_service_response_checkpoint_for_test (server,
      service_response_delivery_checkpoint, &barrier);
  /* A graceful client close can be classified as FINISHED or ABORTED by
   * different kernels before Soup observes it.  Keep the real raw close
   * handshake, then deterministically emit Soup's request-aborted terminal
   * signal after handoff so this test targets the portable Soup contract. */
  wyl_daemon_http_set_service_publication_fault_for_test (server,
      WYL_DAEMON_SERVICE_PUBLICATION_FAULT_EMIT_REQUEST_ABORTED_AFTER_HANDOFF);
  GThread *thread = g_thread_new ("dropped-service-response",
          dropped_service_token_response_thread, &dropped);

  g_mutex_lock (&barrier.mutex);
  gboolean pre_handoff = service_response_delivery_wait (&barrier,
          &barrier.pre_handoff);
  barrier.close_now = TRUE;
  g_cond_broadcast (&barrier.changed);
  gboolean socket_closed = service_response_delivery_wait (&barrier,
          &barrier.socket_closed);
  barrier.release_handler = TRUE;
  g_cond_broadcast (&barrier.changed);
  gboolean terminal = service_response_delivery_wait (&barrier,
          &barrier.terminal);
  gboolean body_wiped = service_response_delivery_wait (&barrier,
          &barrier.body_wiped);
  gboolean destroyed = service_response_delivery_wait (&barrier,
          &barrier.authority_destroyed);
  g_mutex_unlock (&barrier.mutex);
  g_thread_join (thread);
  wyl_daemon_http_set_service_response_checkpoint_for_test (server, NULL, NULL);

  guint sessions_after = 0;
  guint access_after = 0;
  guint response_wipes = 0;
  gboolean response_canary = FALSE;
  gboolean response_all_zero = FALSE;
  WylDaemonServiceResponseAuthoritySnapshot authority = { 0 };
  gboolean registry_found = TRUE;
  gint registry_state = WYL_SERVICE_AUTH_PENDING;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &sessions_after, &access_after);
  wyl_daemon_http_service_response_authority_snapshot_for_test (server,
      &authority);
  wyl_daemon_http_service_response_wipe_snapshot_for_test (server,
      &response_wipes, &response_canary, &response_all_zero);
  wyrelog_error_t lookup_rc = barrier.session_id != NULL && barrier.jti != NULL
      ? wyl_daemon_http_lookup_service_registry_for_test (server,
          barrier.session_id, barrier.jti, &registry_state, &registry_found)
      : WYRELOG_E_INVALID;
  gint result = 0;
  if (!pre_handoff || !socket_closed || dropped.rc != 0)
    result = 19592;
  else if (!terminal
      || barrier.terminal_phase != WYL_DAEMON_SERVICE_RESPONSE_ABORTED)
    result = 19593;
  else if (!body_wiped || !destroyed || response_wipes != 1 || !response_canary
      || !response_all_zero)
    result = 19594;
  else if (authority.created != 1 || authority.complete != 1
      || authority.attached != 1 || authority.finished != 0
      || authority.aborted != 1 || authority.cleanup_failed != 0
      || authority.destroyed != 1 || authority.duplicate_outcomes != 0
      || authority.unclaimed_fallbacks != 0)
    result = 19595;
  else if (sessions_after != sessions_before || access_after != access_before
      || lookup_rc != WYRELOG_E_OK || registry_found)
    result = 19596;

  if (result == 0) {
    g_autofree gchar *aborted_token =
        wyl_daemon_http_dup_last_service_publication_token_for_test (server);
    g_autofree gchar *aborted_session = NULL;
    g_autofree gchar *aborted_actor = NULL;
    g_autofree gchar *aborted_tenant = NULL;
    if (aborted_token == NULL
        || wyl_daemon_http_resolve_bearer_for_test (server, aborted_token,
        &aborted_session, &aborted_actor,
        &aborted_tenant) != WYRELOG_E_POLICY
        || aborted_session != NULL || aborted_actor != NULL
        || aborted_tenant != NULL)
      result = 195961;
  }

  if (result == 0) {
    g_autoptr (SoupSession) session = g_object_new (SOUP_TYPE_SESSION, NULL);
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_service_principal_full (session, "POST", base_url,
        "/auth/service-token", NULL, request_body, &status, &body) != 0
        || status != 200 || body == NULL) {
      result = 19597;
    } else {
      g_autofree gchar *token = extract_json_string (body, "access_token");
      g_autofree gchar *retry_jti = token != NULL
          ? access_token_jti (server, token) : NULL;
      g_autofree gchar *retry_session = NULL;
      g_autofree gchar *retry_actor = NULL;
      g_autofree gchar *retry_tenant = NULL;
      if (token == NULL || retry_jti == NULL
          || wyl_daemon_http_resolve_bearer_for_test (server, token,
          &retry_session, &retry_actor, &retry_tenant) != WYRELOG_E_OK
          || g_strcmp0 (retry_session, barrier.session_id) == 0
          || g_strcmp0 (retry_jti, barrier.jti) == 0)
        result = 19598;
    }
  }

  g_free (barrier.session_id);
  g_free (barrier.jti);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return result;
}

static gint
check_service_response_abort_invalidation_race (ServiceAbortRaceKind kind,
    gboolean invalidator_first)
{
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = NULL;
  g_autofree gchar *base_url = NULL;
  g_autofree gchar *request_body = NULL;
  g_autofree gchar *other_body = NULL;
  g_autofree gchar *other_token = NULL;
  g_autofree gchar *other_jti = NULL;
  g_autofree gchar *other_sid = NULL;
  g_autofree gchar *other_actor = NULL;
  g_autofree gchar *other_tenant = NULL;
  g_autofree gchar *token = NULL;
  g_autofree gchar *sid = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *tenant = NULL;
  wyl_service_credential_issue_result_t issued = { 0 };
  TestHttpServer http = { 0 };
  GThread *http_thread = NULL;
  GThread *drop_thread = NULL;
  GThread *mutation_thread = NULL;
  ServiceResponseDeliveryBarrier delivery = { 0 };
  ServiceResponseRetireBarrier retire = { 0 };
  ServiceAbortMutation mutation = { 0 };
  gboolean delivery_initialized = FALSE;
  gboolean retire_initialized = FALSE;
  gboolean mutation_initialized = FALSE;
  gint result_base = 196200 + (gint) kind * 100 + (invalidator_first ? 20 : 0);
  gint result = result_base;

  if (!service_credential_store_fixture_init (&credential_store))
    return result;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    return result;
  const gchar *subject = "svc:exchange:delivery-race";
  prepare_service_token_subject (handle, subject);
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    goto cleanup;
  issue_service_token_credential (handle, subject, "tenant-a",
      "delivery-race-credential",
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  request_body = g_strdup_printf
        ("{\"credential_id\":\"%s\",\"credential_secret\":\"%s\"}",
          issued.credential.credential_id, secret);
  context = g_main_context_new ();
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  http.server = wyl_daemon_start_http_server (&options, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    goto cleanup;
  http_thread = g_thread_new ("delivery-race-server",
          test_http_server_thread_ctx, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    goto cleanup;
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (base_url == NULL)
    goto cleanup;
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (http.server);
  if (kind == SERVICE_ABORT_CROSSED_MISMATCH) {
    if (wyl_daemon_http_publish_service_token_for_test (http.server,
        issued.credential.credential_id, secret, secret_len,
        &other_body) != WYRELOG_E_OK || other_body == NULL
        || (other_token = extract_json_string (other_body,
        "access_token")) == NULL
        || (other_jti = access_token_jti (http.server, other_token)) == NULL
        || wyl_daemon_http_resolve_bearer_for_test (http.server, other_token,
        &other_sid, &other_actor, &other_tenant) != WYRELOG_E_OK)
      goto cleanup;
  }

  g_mutex_init (&delivery.mutex);
  g_cond_init (&delivery.changed);
  delivery_initialized = TRUE;
  g_mutex_init (&retire.mutex);
  g_cond_init (&retire.changed);
  retire_initialized = TRUE;
  mutation.server = http.server;
  mutation.handle = handle;
  mutation.kind = kind;
  mutation.subject = subject;
  mutation.tenant = "tenant-a";
  mutation.credential_id = issued.credential.credential_id;
  mutation.credential_generation = issued.credential.generation;
  mutation.rc = WYRELOG_E_INTERNAL;
  g_mutex_init (&mutation.mutex);
  g_cond_init (&mutation.changed);
  mutation_initialized = TRUE;
  DroppedServiceTokenResponse dropped = {
    .base_url = base_url,
    .request_body = request_body,
    .barrier = &delivery,
  };
  wyl_daemon_http_reset_service_response_authority_for_test (http.server);
  wyl_daemon_http_set_service_response_checkpoint_for_test (http.server,
      service_response_delivery_checkpoint, &delivery);
  wyl_daemon_http_set_service_publication_fault_for_test (http.server,
      WYL_DAEMON_SERVICE_PUBLICATION_FAULT_FORCE_RESPONSE_AUTHORITY_FALLBACK);
  if (kind < SERVICE_ABORT_PARTIAL_MISMATCH)
    wyl_daemon_http_set_service_response_retire_checkpoint_for_test
      (http.server, service_response_retire_checkpoint, &retire);
  drop_thread = g_thread_new ("delivery-race-drop",
          dropped_service_token_response_thread, &dropped);

  g_mutex_lock (&delivery.mutex);
  gboolean pre_handoff = service_response_delivery_wait (&delivery,
          &delivery.pre_handoff);
  delivery.close_now = TRUE;
  g_cond_broadcast (&delivery.changed);
  gboolean socket_closed = service_response_delivery_wait (&delivery,
          &delivery.socket_closed);
  g_mutex_unlock (&delivery.mutex);
  if (!pre_handoff || !socket_closed) {
    result = result_base + 1;
    goto cleanup;
  }
  g_thread_join (drop_thread);
  drop_thread = NULL;
  if (dropped.rc != 0) {
    result = result_base + 2;
    goto cleanup;
  }
  if (kind >= SERVICE_ABORT_PARTIAL_MISMATCH) {
    gboolean mutated = kind == SERVICE_ABORT_PARTIAL_MISMATCH
        ? wyl_daemon_http_remove_access_token_for_test (http.server,
            delivery.jti)
        : wyl_daemon_http_mutate_service_session_for_test (http.server,
            delivery.session_id, WYL_DAEMON_SERVICE_SESSION_JTI, other_jti, 0);
    if (!mutated)
      goto cleanup;
    g_mutex_lock (&delivery.mutex);
    delivery.release_handler = TRUE;
    g_cond_broadcast (&delivery.changed);
    gboolean mismatch_terminal = service_response_delivery_wait (&delivery,
            &delivery.terminal);
    gboolean mismatch_wiped = service_response_delivery_wait (&delivery,
            &delivery.body_wiped);
    gboolean mismatch_fallback = service_response_delivery_wait (&delivery,
            &delivery.unclaimed_fallback);
    gboolean mismatch_destroyed = service_response_delivery_wait (&delivery,
            &delivery.authority_destroyed);
    g_mutex_unlock (&delivery.mutex);
    WylDaemonServiceResponseAuthoritySnapshot mismatch_authority = { 0 };
    wyl_daemon_http_service_response_authority_snapshot_for_test (http.server,
        &mismatch_authority);
    guint mismatch_sessions = 0;
    guint mismatch_access = 0;
    wyl_daemon_http_service_publication_counts_for_test (http.server,
        &mismatch_sessions, &mismatch_access);
    gboolean target_found = FALSE;
    gint target_state = WYL_SERVICE_AUTH_PENDING;
    WylServiceAuthUnavailableReason mismatch_reason =
        WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_autofree gchar *mismatch_token =
        wyl_daemon_http_dup_last_service_publication_token_for_test
          (http.server);
    g_autofree gchar *mismatch_sid = NULL;
    g_autofree gchar *mismatch_actor = NULL;
    g_autofree gchar *mismatch_tenant = NULL;
    if (!mismatch_terminal || !mismatch_wiped || !mismatch_fallback
        || !mismatch_destroyed
        || delivery.terminal_phase !=
        WYL_DAEMON_SERVICE_RESPONSE_CLEANUP_FAILED
        || mismatch_authority.cleanup_failed != 1
        || mismatch_authority.aborted != 0 || mismatch_authority.finished != 0
        || mismatch_authority.destroyed != 1
        || mismatch_authority.unclaimed_fallbacks != 1
        || mismatch_sessions != (kind == SERVICE_ABORT_PARTIAL_MISMATCH ? 1 : 2)
        || mismatch_access != (kind == SERVICE_ABORT_PARTIAL_MISMATCH ? 0 : 2)
        || wyl_daemon_http_lookup_service_registry_for_test (http.server,
        delivery.session_id, delivery.jti, &target_state,
        &target_found) != WYRELOG_E_OK
        || !target_found || target_state != WYL_SERVICE_AUTH_ACTIVE
        || mismatch_token == NULL
        || wyl_daemon_http_resolve_bearer_for_test (http.server,
        mismatch_token, &mismatch_sid, &mismatch_actor,
        &mismatch_tenant) != WYRELOG_E_POLICY
        || wyl_service_auth_authority_validate_available
          (wyl_handle_get_service_auth_authority (handle), handle,
        &mismatch_reason) == WYRELOG_E_OK
        || mismatch_reason != WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT)
      goto cleanup;
    if (kind == SERVICE_ABORT_CROSSED_MISMATCH) {
      gboolean other_found = FALSE;
      gint other_state = WYL_SERVICE_AUTH_PENDING;
      wyl_daemon_access_token_snapshot_t other_access = { 0 };
      gchar **other_session_access =
          wyl_daemon_http_snapshot_session_access_ids_for_test (http.server,
              other_sid);
      gboolean other_access_found =
          wyl_daemon_http_snapshot_access_token_for_test (http.server,
              other_jti, &other_access);
      gboolean other_exact = other_sid != NULL && other_jti != NULL
          && wyl_daemon_http_lookup_service_registry_for_test (http.server,
              other_sid, other_jti, &other_state, &other_found) == WYRELOG_E_OK
          && other_found && other_state == WYL_SERVICE_AUTH_ACTIVE
          && other_access_found && other_session_access != NULL
          && g_strcmp0 (other_session_access[0], other_jti) == 0
          && other_session_access[1] == NULL
          && g_strcmp0 (other_access.jti, other_jti) == 0
          && g_strcmp0 (other_access.session_id, other_sid) == 0
          && g_strcmp0 (other_access.subject, other_actor) == 0
          && g_strcmp0 (other_access.tenant, other_tenant) == 0
          && g_strcmp0 (other_access.credential_id,
              issued.credential.credential_id) == 0
          && other_access.credential_generation == issued.credential.generation;
      wyl_daemon_access_token_snapshot_clear (&other_access);
      wyl_daemon_http_sensitive_strv_free_for_test (other_session_access);
      if (!other_exact)
        goto cleanup;
    }
    result = 0;
    goto cleanup;
  }
  if (kind == SERVICE_ABORT_RACE_EXPIRY) {
    wyl_daemon_http_set_service_auth_clock_for_test (http.server, TRUE,
        G_MAXINT64);
    wyl_daemon_http_set_service_due_write_checkpoint_for_test (http.server,
        service_abort_mutation_checkpoint, &mutation);
  }

  if (invalidator_first) {
    mutation_thread = g_thread_new ("delivery-race-invalidator",
            service_abort_mutation_thread, &mutation);
    if (!service_abort_mutation_wait (&mutation)) {
      result = result_base + 3;
      goto cleanup;
    }
    g_mutex_lock (&delivery.mutex);
    delivery.release_handler = TRUE;
    g_cond_broadcast (&delivery.changed);
    g_mutex_unlock (&delivery.mutex);
    if (!service_response_retire_wait_before_write (&retire)) {
      result = result_base + 4;
      goto cleanup;
    }
    g_mutex_lock (&mutation.mutex);
    mutation.release = TRUE;
    g_cond_broadcast (&mutation.changed);
    g_mutex_unlock (&mutation.mutex);
    g_thread_join (mutation_thread);
    mutation_thread = NULL;
    if (!service_response_retire_wait (&retire)) {
      result = result_base + 5;
      goto cleanup;
    }
    g_mutex_lock (&retire.mutex);
    retire.release = TRUE;
    g_cond_broadcast (&retire.changed);
    g_mutex_unlock (&retire.mutex);
  } else {
    g_mutex_lock (&delivery.mutex);
    delivery.release_handler = TRUE;
    g_cond_broadcast (&delivery.changed);
    g_mutex_unlock (&delivery.mutex);
    if (!service_response_retire_wait (&retire)) {
      result = result_base + 6;
      goto cleanup;
    }
    mutation_thread = g_thread_new ("delivery-race-invalidator",
            service_abort_mutation_thread, &mutation);
    if (!service_abort_wait_writer_queued (http.server)) {
      result = result_base + 7;
      goto cleanup;
    }
    g_mutex_lock (&retire.mutex);
    retire.release = TRUE;
    g_cond_broadcast (&retire.changed);
    g_mutex_unlock (&retire.mutex);
    if (!service_abort_mutation_wait (&mutation)) {
      result = result_base + 8;
      goto cleanup;
    }
    g_mutex_lock (&mutation.mutex);
    mutation.release = TRUE;
    g_cond_broadcast (&mutation.changed);
    g_mutex_unlock (&mutation.mutex);
    g_thread_join (mutation_thread);
    mutation_thread = NULL;
  }

  g_mutex_lock (&delivery.mutex);
  gboolean terminal = service_response_delivery_wait (&delivery,
          &delivery.terminal);
  gboolean body_wiped = service_response_delivery_wait (&delivery,
          &delivery.body_wiped);
  gboolean fallback = service_response_delivery_wait (&delivery,
          &delivery.unclaimed_fallback);
  gboolean destroyed = service_response_delivery_wait (&delivery,
          &delivery.authority_destroyed);
  g_mutex_unlock (&delivery.mutex);
  if (!terminal || !body_wiped || !fallback || !destroyed) {
    result = result_base + (!terminal ? 9 : !body_wiped ? 10 : !fallback ? 11
        : 12);
    goto cleanup;
  }
  WylDaemonServiceResponseAuthoritySnapshot authority = { 0 };
  wyl_daemon_http_service_response_authority_snapshot_for_test (http.server,
      &authority);
  guint sessions = 0;
  guint access = 0;
  wyl_daemon_http_service_publication_counts_for_test (http.server, &sessions,
      &access);
  token = wyl_daemon_http_dup_last_service_publication_token_for_test
        (http.server);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (mutation.rc != WYRELOG_E_OK
      || delivery.terminal_phase != WYL_DAEMON_SERVICE_RESPONSE_ABORTED
      || authority.aborted != 1 || authority.cleanup_failed != 0
      || authority.finished != 0 || authority.destroyed != 1
      || authority.unclaimed_fallbacks != 1
      || sessions != 0 || access != 0 || token == NULL
      || wyl_daemon_http_resolve_bearer_for_test (http.server, token, &sid,
      &actor, &tenant) != WYRELOG_E_POLICY
      || wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
      &reason) != WYRELOG_E_OK
      || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE) {
    result = result_base + 13;
    goto cleanup;
  }
  result = 0;

cleanup:
  if (http.server != NULL) {
    wyl_daemon_http_set_service_response_checkpoint_for_test (http.server,
        NULL, NULL);
    wyl_daemon_http_set_service_response_retire_checkpoint_for_test
      (http.server, NULL, NULL);
    wyl_daemon_http_set_service_due_write_checkpoint_for_test (http.server,
        NULL, NULL);
  }
  if (delivery_initialized) {
    g_mutex_lock (&delivery.mutex);
    delivery.close_now = TRUE;
    delivery.release_handler = TRUE;
    g_cond_broadcast (&delivery.changed);
    g_mutex_unlock (&delivery.mutex);
  }
  if (retire_initialized) {
    g_mutex_lock (&retire.mutex);
    retire.release = TRUE;
    g_cond_broadcast (&retire.changed);
    g_mutex_unlock (&retire.mutex);
  }
  if (mutation_initialized) {
    g_mutex_lock (&mutation.mutex);
    mutation.release = TRUE;
    g_cond_broadcast (&mutation.changed);
    g_mutex_unlock (&mutation.mutex);
  }
  if (drop_thread != NULL)
    g_thread_join (drop_thread);
  if (mutation_thread != NULL)
    g_thread_join (mutation_thread);
  if (http.loop != NULL)
    g_main_loop_quit (http.loop);
  if (http_thread != NULL)
    g_thread_join (http_thread);
  if (http.server != NULL) {
    soup_server_disconnect (http.server);
    g_clear_object (&http.server);
  }
  if (mutation_initialized) {
    g_cond_clear (&mutation.changed);
    g_mutex_clear (&mutation.mutex);
  }
  if (retire_initialized) {
    g_cond_clear (&retire.changed);
    g_mutex_clear (&retire.mutex);
  }
  if (delivery_initialized) {
    g_clear_pointer (&delivery.session_id, g_free);
    g_clear_pointer (&delivery.jti, g_free);
    g_cond_clear (&delivery.changed);
    g_mutex_clear (&delivery.mutex);
  }
  g_clear_pointer (&http.loop, g_main_loop_unref);
  wyl_service_credential_issue_result_clear (&issued);
  return result;
}

static gint
check_service_response_shutdown_restart_contract (void)
{
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_autofree gchar *request_body = NULL;
  g_autofree gchar *fault_token = NULL;
  g_autofree gchar *fault_session_id = NULL;
  g_autofree gchar *fault_jti = NULL;
  g_autofree gchar *abort_token = NULL;
  g_autofree gchar *abort_session_id = NULL;
  g_autofree gchar *abort_jti = NULL;
  g_autofree gchar *finished_token = NULL;
  g_autofree gchar *finished_session_id = NULL;
  g_autofree gchar *finished_jti = NULL;
  g_autofree gchar *expiry_token = NULL;
  g_autofree gchar *expiry_session_id = NULL;
  g_autofree gchar *expiry_jti = NULL;
  g_autofree gchar *resolved_session = NULL;
  g_autofree gchar *resolved_actor = NULL;
  g_autofree gchar *resolved_tenant = NULL;
  wyl_service_credential_issue_result_t issued = { 0 };
  ServiceResponseTestServer first = { 0 };
  ServiceResponseTestServer second = { 0 };
  ServiceResponseTestServer third = { 0 };
  ServiceResponseDeliveryBarrier fault = { 0 };
  ServiceResponseDeliveryBarrier shutdown = { 0 };
  gboolean fault_initialized = FALSE;
  gboolean shutdown_initialized = FALSE;
  GThread *fault_thread = NULL;
  GThread *shutdown_thread = NULL;
  FinishedServiceTokenResponse fault_response = { 0 };
  DroppedServiceTokenResponse dropped = { 0 };
  gint result = 19680;

  if (!service_credential_store_fixture_init (&credential_store))
    return result;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    return result;
  prepare_service_token_subject (handle, "svc:exchange:worker");
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    goto cleanup;
  issue_service_token_credential (handle, "svc:exchange:worker", "tenant-a",
      "response-lifecycle-credential",
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  if (secret == NULL)
    goto cleanup;
  request_body = g_strdup_printf
        ("{\"credential_id\":\"%s\",\"credential_secret\":\"%s\"}",
          issued.credential.credential_id, secret);
  if (!service_response_test_server_start (&first, handle))
    goto cleanup;

  /* A post-ACTIVE fault is observable only through a raw response.  Hold the
   * fault immediately before exact retirement so the test proves that the
   * tuple was genuinely ACTIVE, then require the public 500 to leave no
   * bearer residue. */
  g_mutex_init (&fault.mutex);
  g_cond_init (&fault.changed);
  fault_initialized = TRUE;
  wyl_daemon_http_reset_service_response_authority_for_test (first.http.server);
  wyl_daemon_http_set_service_response_checkpoint_for_test
    (first.http.server, service_response_delivery_checkpoint, &fault);
  wyl_daemon_http_set_service_publication_fault_for_test (first.http.server,
      WYL_DAEMON_SERVICE_PUBLICATION_FAULT_POST_ACTIVE_PRE_HANDOFF);
  fault_response.base_url = first.base_url;
  fault_response.request_body = request_body;
  fault_thread = g_thread_new ("service-response-fault",
          finished_service_token_response_thread, &fault_response);
  g_mutex_lock (&fault.mutex);
  gboolean fault_active = service_response_delivery_wait (&fault,
          &fault.active_pre_handoff_failure);
  g_mutex_unlock (&fault.mutex);
  if (!fault_active)
    goto cleanup;
  fault_token =
      wyl_daemon_http_dup_last_service_publication_token_for_test
        (first.http.server);
  fault_session_id = g_strdup (fault.session_id);
  fault_jti = g_strdup (fault.jti);
  guint sessions = 0;
  guint access = 0;
  gboolean found = FALSE;
  gint state = WYL_SERVICE_AUTH_PENDING;
  wyl_daemon_http_service_publication_counts_for_test (first.http.server,
      &sessions, &access);
  if (fault_token == NULL || fault_session_id == NULL || fault_jti == NULL
      || sessions != 1 || access != 1
      || wyl_daemon_http_lookup_service_registry_for_test (first.http.server,
      fault_session_id, fault_jti, &state, &found) != WYRELOG_E_OK
      || !found || state != WYL_SERVICE_AUTH_ACTIVE
      || wyl_daemon_http_resolve_bearer_for_test (first.http.server,
      fault_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK)
    goto cleanup;
  g_mutex_lock (&fault.mutex);
  fault.release_handler = TRUE;
  g_cond_broadcast (&fault.changed);
  gboolean fault_terminal = service_response_delivery_wait (&fault,
          &fault.terminal);
  gboolean fault_wiped = service_response_delivery_wait (&fault,
          &fault.body_wiped);
  gboolean fault_destroyed = service_response_delivery_wait (&fault,
          &fault.authority_destroyed);
  g_mutex_unlock (&fault.mutex);
  g_thread_join (fault_thread);
  fault_thread = NULL;
  wyl_daemon_http_set_service_response_checkpoint_for_test
    (first.http.server, NULL, NULL);
  WylDaemonServiceResponseAuthoritySnapshot authority = { 0 };
  guint response_wipes = 0;
  gboolean response_canary = FALSE;
  gboolean response_all_zero = FALSE;
  wyl_daemon_http_service_response_authority_snapshot_for_test
    (first.http.server, &authority);
  wyl_daemon_http_service_response_wipe_snapshot_for_test
    (first.http.server, &response_wipes, &response_canary,
      &response_all_zero);
  sessions = G_MAXUINT;
  access = G_MAXUINT;
  found = TRUE;
  state = WYL_SERVICE_AUTH_ACTIVE;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  wyl_daemon_http_service_publication_counts_for_test (first.http.server,
      &sessions, &access);
  if (fault_response.rc != 0 || fault_response.status != 500
      || fault_response.body == NULL
      || strstr (fault_response.body, "\"error\":\"service_token_failed\"")
      == NULL || strstr (fault_response.body, "access_token") != NULL
      || !fault_terminal || !fault_wiped || !fault_destroyed
      || fault.terminal_phase != WYL_DAEMON_SERVICE_RESPONSE_ABORTED
      || response_wipes != 1 || !response_canary || !response_all_zero
      || authority.created != 1 || authority.complete != 1
      || authority.attached != 0 || authority.finished != 0
      || authority.aborted != 1 || authority.cleanup_failed != 0
      || authority.destroyed != 1 || authority.duplicate_outcomes != 0
      || authority.unclaimed_fallbacks != 0
      || sessions != 0 || access != 0
      || wyl_daemon_http_lookup_service_registry_for_test (first.http.server,
      fault_session_id, fault_jti, &state, &found) != WYRELOG_E_OK
      || found
      || wyl_daemon_http_resolve_bearer_for_test (first.http.server,
      fault_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_POLICY)
    goto cleanup;
  g_clear_pointer (&fault_response.body, g_free);

  /* Disconnect keeps the SoupServer and context references alive while the
   * already-closed request terminalizes.  Context shutdown only suspends
   * maintenance; exact abort retirement must still succeed before teardown. */
  g_mutex_init (&shutdown.mutex);
  g_cond_init (&shutdown.changed);
  shutdown_initialized = TRUE;
  wyl_daemon_http_reset_service_response_authority_for_test (first.http.server);
  wyl_daemon_http_set_service_response_checkpoint_for_test
    (first.http.server, service_response_delivery_checkpoint, &shutdown);
  wyl_daemon_http_set_service_publication_fault_for_test (first.http.server,
      WYL_DAEMON_SERVICE_PUBLICATION_FAULT_FORCE_RESPONSE_AUTHORITY_FALLBACK);
  dropped.base_url = first.base_url;
  dropped.request_body = request_body;
  dropped.barrier = &shutdown;
  shutdown.shutdown_on_socket_close = TRUE;
  shutdown.shutdown_server = first.http.server;
  shutdown_thread = g_thread_new ("service-response-shutdown",
          dropped_service_token_response_thread, &dropped);
  g_mutex_lock (&shutdown.mutex);
  gboolean shutdown_pre = service_response_delivery_wait (&shutdown,
          &shutdown.pre_handoff);
  shutdown.close_now = TRUE;
  g_cond_broadcast (&shutdown.changed);
  gboolean socket_closed = service_response_delivery_wait (&shutdown,
          &shutdown.socket_closed);
  gboolean shutdown_done = service_response_delivery_wait (&shutdown,
          &shutdown.shutdown_done);
  g_mutex_unlock (&shutdown.mutex);
  if (!shutdown_pre || !socket_closed || !shutdown_done)
    goto cleanup;
  g_thread_join (shutdown_thread);
  shutdown_thread = NULL;
  if (dropped.rc != 0)
    goto cleanup;
  abort_token =
      wyl_daemon_http_dup_last_service_publication_token_for_test
        (first.http.server);
  abort_session_id = g_strdup (shutdown.session_id);
  abort_jti = g_strdup (shutdown.jti);
  guint shutdown_ticks = 0;
  if (wyl_daemon_http_service_auth_maintenance_active_for_test
        (first.http.server, &shutdown_ticks))
    goto cleanup;
  g_mutex_lock (&shutdown.mutex);
  shutdown.release_handler = TRUE;
  g_cond_broadcast (&shutdown.changed);
  gboolean shutdown_terminal = service_response_delivery_wait (&shutdown,
          &shutdown.terminal);
  gboolean shutdown_wiped = service_response_delivery_wait (&shutdown,
          &shutdown.body_wiped);
  gboolean shutdown_fallback = service_response_delivery_wait (&shutdown,
          &shutdown.unclaimed_fallback);
  gboolean shutdown_destroyed = service_response_delivery_wait (&shutdown,
          &shutdown.authority_destroyed);
  g_mutex_unlock (&shutdown.mutex);
  wyl_daemon_http_set_service_response_checkpoint_for_test
    (first.http.server, NULL, NULL);
  memset (&authority, 0, sizeof authority);
  response_wipes = 0;
  response_canary = FALSE;
  response_all_zero = FALSE;
  wyl_daemon_http_service_response_authority_snapshot_for_test
    (first.http.server, &authority);
  wyl_daemon_http_service_response_wipe_snapshot_for_test
    (first.http.server, &response_wipes, &response_canary,
      &response_all_zero);
  sessions = G_MAXUINT;
  access = G_MAXUINT;
  found = TRUE;
  state = WYL_SERVICE_AUTH_ACTIVE;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  wyl_daemon_http_service_publication_counts_for_test (first.http.server,
      &sessions, &access);
  if (abort_token == NULL || abort_session_id == NULL || abort_jti == NULL
      || !shutdown_terminal || !shutdown_wiped || !shutdown_fallback
      || !shutdown_destroyed
      || shutdown.terminal_phase != WYL_DAEMON_SERVICE_RESPONSE_ABORTED
      || response_wipes != 1 || !response_canary || !response_all_zero
      || authority.created != 1 || authority.complete != 1
      || authority.attached != 1 || authority.finished != 0
      || authority.aborted != 1 || authority.cleanup_failed != 0
      || authority.destroyed != 1 || authority.duplicate_outcomes != 0
      || authority.unclaimed_fallbacks != 1
      || sessions != 0 || access != 0
      || wyl_daemon_http_lookup_service_registry_for_test (first.http.server,
      abort_session_id, abort_jti, &state, &found) != WYRELOG_E_OK
      || found
      || wyl_daemon_http_resolve_bearer_for_test (first.http.server,
      abort_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_POLICY)
    goto cleanup;

  service_response_test_server_stop (&first);
  if (wyl_handle_shutdown_ordered (handle) != WYRELOG_E_OK)
    goto cleanup;
  g_clear_object (&handle);
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    goto cleanup;
  if (!service_response_test_server_start (&second, handle))
    goto cleanup;
  sessions = G_MAXUINT;
  access = G_MAXUINT;
  found = TRUE;
  state = WYL_SERVICE_AUTH_ACTIVE;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  wyl_daemon_http_service_publication_counts_for_test (second.http.server,
      &sessions, &access);
  if (sessions != 0 || access != 0
      || wyl_daemon_http_lookup_service_registry_for_test (second.http.server,
      abort_session_id, abort_jti, &state, &found) != WYRELOG_E_OK
      || found
      || wyl_daemon_http_resolve_bearer_for_test (second.http.server,
      abort_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_POLICY)
    goto cleanup;
  gint finished_rc = check_service_response_delivery_finished
        (second.http.server, second.base_url, request_body);
  if (finished_rc != 0)
    goto cleanup;
  finished_token =
      wyl_daemon_http_dup_last_service_publication_token_for_test
        (second.http.server);
  finished_jti = finished_token != NULL
      ? access_token_jti (second.http.server, finished_token) : NULL;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  if (finished_token == NULL || finished_jti == NULL
      || wyl_daemon_http_resolve_bearer_for_test (second.http.server,
      finished_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK)
    goto cleanup;
  finished_session_id = g_strdup (resolved_session);
  service_response_test_server_stop (&second);

  if (!service_response_test_server_start (&third, handle))
    goto cleanup;
  sessions = G_MAXUINT;
  access = G_MAXUINT;
  found = TRUE;
  state = WYL_SERVICE_AUTH_ACTIVE;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  wyl_daemon_http_service_publication_counts_for_test (third.http.server,
      &sessions, &access);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (sessions != 0 || access != 0
      || finished_session_id == NULL
      || wyl_daemon_http_lookup_service_registry_for_test (third.http.server,
      finished_session_id, finished_jti, &state, &found)
      != WYRELOG_E_OK || found
      || wyl_daemon_http_resolve_bearer_for_test (third.http.server,
      finished_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_POLICY
      || wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
      &reason) != WYRELOG_E_OK
      || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE)
    goto cleanup;
  gint expiry_finished_rc = check_service_response_delivery_finished
        (third.http.server, third.base_url, request_body);
  if (expiry_finished_rc != 0)
    goto cleanup;
  expiry_token =
      wyl_daemon_http_dup_last_service_publication_token_for_test
        (third.http.server);
  expiry_jti = expiry_token != NULL
      ? access_token_jti (third.http.server, expiry_token) : NULL;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  if (expiry_token == NULL || expiry_jti == NULL
      || wyl_daemon_http_resolve_bearer_for_test (third.http.server,
      expiry_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK)
    goto cleanup;
  expiry_session_id = g_strdup (resolved_session);
  wyl_daemon_access_token_snapshot_t expiry_access = { 0 };
  if (!wyl_daemon_http_snapshot_access_token_for_test (third.http.server,
      expiry_jti, &expiry_access)) {
    wyl_daemon_access_token_snapshot_clear (&expiry_access);
    goto cleanup;
  }
  wyl_daemon_http_set_service_auth_clock_for_test (third.http.server, TRUE,
      expiry_access.expires_at);
  wyl_daemon_access_token_snapshot_clear (&expiry_access);
  if (wyl_daemon_http_retire_due_service_auth_for_test (third.http.server)
      != WYRELOG_E_OK)
    goto cleanup;
  sessions = G_MAXUINT;
  access = G_MAXUINT;
  found = TRUE;
  state = WYL_SERVICE_AUTH_ACTIVE;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  wyl_daemon_http_service_publication_counts_for_test (third.http.server,
      &sessions, &access);
  reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (expiry_session_id == NULL || sessions != 0 || access != 0
      || wyl_daemon_http_lookup_service_registry_for_test (third.http.server,
      expiry_session_id, expiry_jti, &state, &found) != WYRELOG_E_OK
      || found
      || wyl_daemon_http_resolve_bearer_for_test (third.http.server,
      expiry_token, &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_POLICY
      || wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
      &reason) != WYRELOG_E_OK
      || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE)
    goto cleanup;
  result = 0;

cleanup:
  if (first.http.server != NULL)
    wyl_daemon_http_set_service_response_checkpoint_for_test
      (first.http.server, NULL, NULL);
  if (fault_initialized) {
    g_mutex_lock (&fault.mutex);
    fault.release_handler = TRUE;
    g_cond_broadcast (&fault.changed);
    g_mutex_unlock (&fault.mutex);
  }
  if (shutdown_initialized) {
    g_mutex_lock (&shutdown.mutex);
    shutdown.close_now = TRUE;
    shutdown.release_handler = TRUE;
    g_cond_broadcast (&shutdown.changed);
    g_mutex_unlock (&shutdown.mutex);
  }
  if (fault_thread != NULL)
    g_thread_join (fault_thread);
  if (shutdown_thread != NULL)
    g_thread_join (shutdown_thread);
  service_response_test_server_stop (&first);
  service_response_test_server_stop (&second);
  service_response_test_server_stop (&third);
  if (shutdown_initialized) {
    g_free (shutdown.session_id);
    g_free (shutdown.jti);
    g_cond_clear (&shutdown.changed);
    g_mutex_clear (&shutdown.mutex);
  }
  if (fault_initialized) {
    g_free (fault.session_id);
    g_free (fault.jti);
    g_cond_clear (&fault.changed);
    g_mutex_clear (&fault.mutex);
  }
  g_free (fault_response.body);
  wyl_service_credential_issue_result_clear (&issued);
  return result;
}

static gint
check_service_token_exchange_contract_on_server (SoupServer *server,
    WylHandle *handle, const gchar *base_url)
{
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *route_access_token = NULL;
  prepare_service_token_subject (handle, "svc:exchange:worker");
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 1944;

  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK)
    return 1945;
  wyl_service_credential_issue_result_t issued = { 0 };
  issue_service_token_credential (handle, "svc:exchange:worker", "tenant-a",
      issue_request_id, g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC,
      &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  if (secret == NULL)
    return 1946;

  g_autofree gchar *request_body = g_strdup_printf
        ("{\"credential_id\":\"%s\",\"credential_secret\":\"%s\"}",
          issued.credential.credential_id, secret);
  guint status = 0;
  guint retry_after = 0;
  g_autofree gchar *body = NULL;
  if (wyl_daemon_http_issue_service_token_for_test (server, TRUE, request_body,
      strlen (request_body), &status, &body, &retry_after) != WYRELOG_E_OK)
    return 1947;
  if (status != 200 || body == NULL)
    return 1948;
  access_token = extract_json_string (body, "access_token");
  if (access_token == NULL ||
      strstr (body, "session_token") != NULL ||
      strstr (body, "username") != NULL ||
      strstr (body, "tenant") != NULL ||
      strstr (body, "principal_state") != NULL)
    return 1948;

  guint8 secret_key[32];
  if (wyl_daemon_http_copy_access_token_secret (server, secret_key,
      sizeof secret_key) != WYRELOG_E_OK)
    return 1950;
  g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (key_id == NULL)
    return 1951;
  g_autoptr (GBytes) payload = NULL;
  if (wyl_jwt_verify_hs256_access_token (access_token, secret_key,
      sizeof secret_key, key_id, "wyrelogd", "wyrelog-client",
      g_get_real_time () / G_USEC_PER_SEC, &payload) != WYRELOG_E_OK)
    return 1952;
  gsize payload_len = 0;
  const gchar *payload_data = g_bytes_get_data (payload, &payload_len);
  g_autofree gchar *payload_text = g_strndup (payload_data, payload_len);
  if (strstr (payload_text, "\"auth_method\":\"service_credential\"") == NULL)
    return 1953;
  if (strstr (payload_text, "\"credential_id\":\"") == NULL)
    return 1954;
  if (g_strstr_len (payload_text, -1, issued.credential.credential_id) == NULL)
    return 1955;

  g_autofree gchar *resolved_session = NULL;
  g_autofree gchar *resolved_actor = NULL;
  g_autofree gchar *resolved_tenant = NULL;
  if (wyl_daemon_http_resolve_bearer_for_test (server, access_token,
      &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK
      || resolved_session == NULL
      || g_strcmp0 (resolved_actor, "svc:exchange:worker") != 0
      || g_strcmp0 (resolved_tenant, "tenant-a") != 0)
    return 1956;

  g_autoptr (SoupSession) protected_session = soup_session_new ();
  guint protected_status = 0;
  g_autofree gchar *protected_body = NULL;
  if (send_raw_decide_bearer (protected_session, "POST", base_url,
      "svc:exchange:worker", "http.not_armed", "service-scope",
      "tenant=tenant-a", access_token, &protected_status,
      &protected_body) != 0 || protected_status != 200
      || protected_body == NULL
      || strstr (protected_body, "\"decision\":") == NULL)
    return 1957;
  gint decide_alias_rc = check_valid_decide_aliases (server,
          protected_session, base_url, "svc:exchange:worker", "http.not_armed",
          "service-scope", "tenant=tenant-a", access_token, 2672);
  if (decide_alias_rc != 0)
    return decide_alias_rc;

  WylServiceExchangeLimiterSnapshot limiter_snapshot = { 0 };
  wyl_daemon_http_service_exchange_limiter_snapshot_for_test (server,
      &limiter_snapshot);
  if (limiter_snapshot.global_tokens != 99 ||
      limiter_snapshot.credential_bucket_count != 1 ||
      limiter_snapshot.anonymous_tokens != 5)
    return 1958;

  /* Key rotation is a service-auth epoch transition, not merely a JWT key
   * swap: it retires every old service companion and leaves the authority
   * available for a fresh exchange of the still-valid credential. */
  wyl_jwt_access_claims_t pre_rotation_claims = { 0 };
  if (wyl_jwt_parse_access_claims_json (payload, &pre_rotation_claims)
      != WYRELOG_E_OK)
    return 19581;
  if (wyl_daemon_http_rotate_access_token_key_for_test (server)
      != WYRELOG_E_OK)
    return 19582;
  g_autofree gchar *old_rotation_session = NULL;
  g_autofree gchar *old_rotation_actor = NULL;
  g_autofree gchar *old_rotation_tenant = NULL;
  if (wyl_daemon_http_resolve_bearer_for_test (server, access_token,
      &old_rotation_session, &old_rotation_actor,
      &old_rotation_tenant) == WYRELOG_E_OK)
    return 19583;
  gint pre_rotation_state = WYL_SERVICE_AUTH_PENDING;
  gboolean pre_rotation_found = TRUE;
  if (wyl_daemon_http_lookup_service_registry_for_test (server,
      pre_rotation_claims.session_id, pre_rotation_claims.jti,
      &pre_rotation_state, &pre_rotation_found) != WYRELOG_E_OK
      || pre_rotation_found)
    return 19584;
  guint rotation_sessions = 0;
  guint rotation_access = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &rotation_sessions, &rotation_access);
  if (rotation_sessions != 0 || rotation_access != 0)
    return 19585;
  WylServiceAuthUnavailableReason rotation_reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  if (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
      &rotation_reason) != WYRELOG_E_OK
      || rotation_reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE)
    return 19586;
  g_clear_pointer (&body, g_free);
  if (wyl_daemon_http_issue_service_token_for_test (server, TRUE, request_body,
      strlen (request_body), &status, &body, &retry_after) != WYRELOG_E_OK
      || status != 200 || body == NULL)
    return 19587;
  g_autofree gchar *rotated_access = extract_json_string (body, "access_token");
  if (rotated_access == NULL)
    return 19588;
  g_clear_pointer (&access_token, g_free);
  access_token = g_steal_pointer (&rotated_access);
  wyl_jwt_access_claims_clear (&pre_rotation_claims);

  g_autoptr (SoupSession) session = g_object_new (SOUP_TYPE_SESSION, NULL);
  guint route_status = 0;
  g_autofree gchar *route_body = NULL;
  gboolean route_response_completed = FALSE;
  if (send_service_token_response_and_wait (server, session, base_url,
      request_body, &route_status, &route_body,
      &route_response_completed) != 0)
    return 1959;
  if (route_status != 200 || route_body == NULL)
    return 1959;
  route_access_token = extract_json_string (route_body, "access_token");
  if (route_access_token == NULL || strstr (route_body, "session_token") != NULL
      || strstr (route_body, "credential_secret") != NULL)
    return 1959;
  WylDaemonServiceResponseAuthoritySnapshot response_authority = { 0 };
  wyl_daemon_http_service_response_authority_snapshot_for_test (server,
      &response_authority);
  guint route_response_wipes = 0;
  gboolean route_response_canary = FALSE;
  gboolean route_response_all_zero = FALSE;
  wyl_daemon_http_service_response_wipe_snapshot_for_test (server,
      &route_response_wipes, &route_response_canary, &route_response_all_zero);
  if (!route_response_completed
      || response_authority.created != 1 || response_authority.complete != 1
      || response_authority.attached != 1
      || response_authority.finished != 1 || response_authority.aborted != 0
      || response_authority.cleanup_failed != 0
      || response_authority.destroyed != 1
      || response_authority.duplicate_outcomes != 0
      || response_authority.unclaimed_fallbacks != 0
      || route_response_wipes != 1 || !route_response_canary
      || !route_response_all_zero)
    return 19591;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  if (wyl_daemon_http_resolve_bearer_for_test (server, route_access_token,
      &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK
      || g_strcmp0 (resolved_actor, "svc:exchange:worker") != 0
      || g_strcmp0 (resolved_tenant, "tenant-a") != 0)
    return 195911;
  gint delivery_finished_rc = check_service_response_delivery_finished
        (server, base_url, request_body);
  if (delivery_finished_rc != 0)
    return delivery_finished_rc;
  gint delivery_abort_rc = check_service_response_delivery_abort (server,
          base_url, request_body);
  if (delivery_abort_rc != 0)
    return delivery_abort_rc;

  guint denied_status = 0;
  guint denied_retry_after = 0;
  g_autofree gchar *denied_body = NULL;
  if (wyl_daemon_http_issue_service_token_for_test (server, FALSE,
      request_body, strlen (request_body), &denied_status, &denied_body,
      &denied_retry_after) != WYRELOG_E_OK
      || denied_status != 403 || denied_body == NULL
      || strstr (denied_body, "access_token") != NULL
      || strstr (denied_body, "credential_secret") != NULL)
    return 1960;

  g_autofree gchar *malformed_body =
      g_strdup_printf ("{\"credential_id\":\"%s\",\"extra\":\"x\"}",
          issued.credential.credential_id);
  g_clear_pointer (&body, g_free);
  if (wyl_daemon_http_issue_service_token_for_test (server, TRUE,
      malformed_body, strlen (malformed_body), &status, &body,
      &retry_after) != WYRELOG_E_OK)
    return 1956;
  if (status != 400
      || strstr (body, "\"error\":\"invalid_service_token_request\"")
      == NULL)
    return 1958;

  /* Direct publication, two finished routes, the aborted route, and its retry
   * consume all five credential-bucket permits. An aborted delivery never
   * refunds admission, so the next exchange must be rate limited. */
  g_clear_pointer (&body, g_free);
  if (wyl_daemon_http_issue_service_token_for_test (server, TRUE, request_body,
      strlen (request_body), &status, &body, &retry_after) != WYRELOG_E_OK)
    return 1980;
  if (status != 429 || retry_after == 0 ||
      strstr (body, "\"error\":\"service_token_rate_limited\"") == NULL)
    return 1981;

  /* The exchange authority takes microseconds.  A seconds value beyond the
   * exact conversion bound must fail before it can reserve or expose a token;
   * no new live companion may appear before the deliberate retirement below. */
  guint pre_overflow_sessions = 0;
  guint pre_overflow_access = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &pre_overflow_sessions, &pre_overflow_access);
  wyl_daemon_http_set_service_auth_clock_for_test (server, TRUE,
      (G_MAXINT64 / G_USEC_PER_SEC) + 1);
  g_clear_pointer (&body, g_free);
  if (wyl_daemon_http_publish_service_token_for_test (server,
      issued.credential.credential_id, secret, secret_len, &body)
      != WYRELOG_E_INVALID || body != NULL)
    return 19811;
  guint post_overflow_sessions = 0;
  guint post_overflow_access = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &post_overflow_sessions, &post_overflow_access);
  if (post_overflow_sessions != pre_overflow_sessions
      || post_overflow_access != pre_overflow_access)
    return 19812;

  wyl_jwt_access_claims_t claims = { 0 };
  if (wyl_jwt_parse_access_claims_json (payload, &claims) != WYRELOG_E_OK)
    return 1982;
  if (wyl_daemon_http_revoke_service_credential_for_test (server,
      issued.credential.credential_id,
      "000000000000000000000000232", NULL, NULL)
      != WYRELOG_E_OK)
    return 1983;
  wyl_daemon_http_set_service_auth_clock_for_test (server, TRUE, G_MAXINT64);
  if (wyl_daemon_http_retire_due_service_auth_for_test (server)
      != WYRELOG_E_OK)
    return 1984;
  gint registry_state = WYL_SERVICE_AUTH_PENDING;
  gboolean registry_found = TRUE;
  if (wyl_daemon_http_lookup_service_registry_for_test (server,
      claims.session_id, claims.jti, &registry_state, &registry_found)
      != WYRELOG_E_OK || registry_found)
    return 1985;
  g_clear_pointer (&resolved_session, g_free);
  g_clear_pointer (&resolved_actor, g_free);
  g_clear_pointer (&resolved_tenant, g_free);
  if (wyl_daemon_http_resolve_bearer_for_test (server, access_token,
      &resolved_session, &resolved_actor, &resolved_tenant) == WYRELOG_E_OK)
    return 1986;
  guint retired_sessions = 0;
  guint retired_access_tokens = 0;
  wyl_daemon_http_service_publication_counts_for_test (server,
      &retired_sessions, &retired_access_tokens);
  if (retired_sessions != 0 || retired_access_tokens != 0)
    return 1987;
  wyl_jwt_access_claims_clear (&claims);

  wyl_service_credential_issue_result_clear (&issued);
  return 0;
}

static gint
check_service_tenant_create_rejected (void)
{
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = NULL;
  g_autofree gchar *base_url = NULL;
  TestHttpServer http = { 0 };
  GThread *thread = NULL;
  gint result = 2280;
  g_auto (ActualServiceTokens) tokens = { 0 };
  g_autoptr (SoupSession) session = NULL;
  g_autofree gchar *body = NULL;

  if (!service_credential_store_fixture_init (&credential_store))
    return result;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    return result;
  wyl_service_principal_t principal = { 0 };
  gchar principal_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_request_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (principal_request_id, sizeof principal_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (credential_request_id,
      sizeof credential_request_id) != WYRELOG_E_OK
      || wyl_service_principal_create (handle, "svc:tenant-create-negative",
      "tenant create negative", "admin", principal_request_id,
      &principal) != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK) {
    wyl_service_principal_clear (&principal);
    return 2281;
  }
  wyl_service_principal_clear (&principal);

  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  context = g_main_context_new ();
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server (&options, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    goto cleanup;
  thread = g_thread_new ("service-tenant-create", test_http_server_thread_ctx,
          &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    goto cleanup;
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (base_url == NULL)
    goto cleanup;

  if (!actual_service_tokens_init (http.server,
      "svc:tenant-create-negative", WYL_TENANT_DEFAULT,
      credential_request_id, &tokens)) {
    result = 2282;
    goto cleanup;
  }
  session = soup_session_new ();
  guint status = 0;
  if (send_raw_policy_mutation_bearer (session, "POST", base_url,
      "/tenants/create", "name=tenant-service-denied"
      "&tenant=__wr_default&guard_timestamp=123"
      "&guard_loc_class=public&guard_risk=49", tokens.token_a,
      &status, &body) != 0) {
    result = 2283;
    goto cleanup;
  }
  guint grant_events = 0;
  guint audit_events = 0;
  guint audit_intentions = 0;
  result = status == 403 && strstr (body, "tenant_denied") != NULL
      && tenant_state_matches (wyl_handle_get_policy_store (handle),
          "tenant-service-denied", FALSE, FALSE)
      && tenant_creator_anchor_matches (handle,
          "svc:tenant-create-negative", "tenant-service-denied", FALSE)
      && role_membership_event_count (handle, "svc:tenant-create-negative",
          "wr.system_admin", "tenant-service-denied", "grant", &grant_events)
      && grant_events == 0
      && policy_lifecycle_audit_count (handle, "svc:tenant-create-negative",
          "tenant_create", "tenant-service-denied", &audit_events)
      && audit_events == 0
      && policy_lifecycle_audit_intention_count (handle,
          "svc:tenant-create-negative", "tenant_create", "tenant-service-denied",
          &audit_intentions) && audit_intentions == 0
      && tenant_has_no_human_session_row (handle, "tenant-service-denied")
      ? 0 : 2284;

cleanup:
  if (http.loop != NULL)
    g_main_loop_quit (http.loop);
  if (thread != NULL)
    g_thread_join (thread);
  if (http.server != NULL) {
    soup_server_disconnect (http.server);
    g_object_unref (http.server);
  }
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return result;
}

static gint
check_service_token_exchange_contract (void)
{
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = NULL;
  g_autofree gchar *base_url = NULL;
  TestHttpServer http = { 0 };
  GThread *thread = NULL;
  gint result = 1990;

  if (!service_credential_store_fixture_init (&credential_store))
    return result;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK
      || insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return result;

  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  context = g_main_context_new ();
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server (&options, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    goto cleanup;
  thread = g_thread_new ("service-token-exchange",
          test_http_server_thread_ctx, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    goto cleanup;
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (base_url == NULL)
    goto cleanup;
  result = check_service_token_exchange_contract_on_server (http.server,
          handle, base_url);
  if (result == 0) {
    guint ticks = 0;
    if (!wyl_daemon_http_service_auth_maintenance_active_for_test (http.server,
        &ticks))
      result = 1988;
    else {
      wyl_daemon_http_shutdown_service_auth_maintenance_for_test (http.server);
      guint after_shutdown = 0;
      if (wyl_daemon_http_service_auth_maintenance_active_for_test
            (http.server, &after_shutdown) || after_shutdown != ticks)
        result = 1989;
    }
  }

cleanup:
  if (http.loop != NULL)
    g_main_loop_quit (http.loop);
  if (thread != NULL)
    g_thread_join (thread);
  if (http.server != NULL) {
    soup_server_disconnect (http.server);
    g_object_unref (http.server);
  }
  g_clear_pointer (&http.loop, g_main_loop_unref);
  for (gint kind = SERVICE_ABORT_RACE_CREDENTIAL_ROTATE;
      result == 0 && kind <= SERVICE_ABORT_RACE_EXPIRY; kind++)
    for (gint invalidator_first = 0;
        result == 0 && invalidator_first <= 1; invalidator_first++)
      result = check_service_response_abort_invalidation_race (kind,
              invalidator_first);
  if (result == 0)
    result = check_service_response_abort_invalidation_race
          (SERVICE_ABORT_PARTIAL_MISMATCH, FALSE);
  if (result == 0)
    result = check_service_response_abort_invalidation_race
          (SERVICE_ABORT_CROSSED_MISMATCH, FALSE);
  if (result == 0)
    result = check_service_response_shutdown_restart_contract ();
  if (result == 0)
    result = check_service_tenant_create_rejected ();
  return result;
}

static gint
check_service_publication_fault_matrix (void)
{
  static const struct
  {
    WylDaemonServicePublicationFault fault;
    guint sessions;
    guint access_tokens;
    gboolean registry_found;
    gboolean resolves;
    guint response_wipes;
    gboolean mutated_same_pointer;
    gboolean mutated_access_iat;
    gboolean registry_conflict_latched;
  } cases[] = {
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_RESPONSE_PREPARE, 0, 0, FALSE,
     FALSE, 0, FALSE, FALSE, FALSE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_PRE_ACTIVE_CANCEL, 0, 0, FALSE,
     FALSE, 1, FALSE, FALSE, FALSE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_AFTER_SESSION_INSERT, 0, 0, FALSE,
     FALSE, 1, FALSE, FALSE, FALSE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_PRE_ACTIVE_DISCONNECT, 0, 0, FALSE,
     FALSE, 1, FALSE, FALSE, FALSE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_SESSION_ROLLBACK_MISMATCH, 1, 1,
     FALSE, FALSE, 1, FALSE, FALSE, TRUE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_SESSION_ROLLBACK_TUPLE_MUTATION, 1,
     1, FALSE, FALSE, 1, TRUE, FALSE, TRUE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ACCESS_ROLLBACK_MISMATCH, 1, 1,
     FALSE, FALSE, 1, FALSE, FALSE, TRUE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ACCESS_ROLLBACK_IAT_MUTATION, 1, 1,
     FALSE, FALSE, 1, FALSE, TRUE, TRUE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_ROLLBACK_SECOND_REMOVE_FAILURE, 1, 1,
     FALSE, FALSE, 1, FALSE, FALSE, TRUE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_POST_ACTIVE_PRE_HANDOFF, 1, 1, FALSE,
     FALSE, 1, FALSE, FALSE, FALSE},
    {WYL_DAEMON_SERVICE_PUBLICATION_FAULT_TERMINAL_RELEASE, 1, 1, TRUE, FALSE,
     1, FALSE, FALSE, FALSE},
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
    g_autoptr (WylHandle) handle = NULL;
    if (!service_credential_store_fixture_init (&credential_store))
      return 2100 + (gint) i;
    WylHandleOpenOptions handle_options = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .policy_store_path = credential_store.policy_path,
      .policy_keyprovider_path = credential_store.key_spec,
      .audit_store_path = credential_store.audit_path,
      .production_mode = TRUE,
    };
    if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
      return 2100 + (gint) i;
    prepare_service_token_subject (handle, "svc:exchange:fault");
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 2110 + (gint) i;
    wyl_service_credential_issue_result_t issued = { 0 };
    issue_service_token_credential (handle, "svc:exchange:fault", "tenant-a",
        "fault-credential", g_get_real_time () + 60 * G_USEC_PER_SEC, &issued);
    gsize credential_secret_len = 0;
    const gchar *credential_secret =
        wyl_service_credential_secret_peek_encoded (issued.secret,
            &credential_secret_len);
    WylDaemonOptions opts = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .listen_port = 0,
    };
    g_autoptr (GError) error = NULL;
    SoupServer *server = wyl_daemon_start_http_server (&opts, handle, &error);
    if (server == NULL) {
      wyl_service_credential_issue_result_clear (&issued);
      return 2120 + (gint) i;
    }

    g_autofree gchar *unrelated_body = NULL;
    g_autofree gchar *unrelated_token = NULL;
    if (cases[i].fault ==
        WYL_DAEMON_SERVICE_PUBLICATION_FAULT_POST_ACTIVE_PRE_HANDOFF) {
      if (wyl_daemon_http_publish_service_token_for_test (server,
          issued.credential.credential_id, credential_secret,
          credential_secret_len, &unrelated_body) != WYRELOG_E_OK
          || unrelated_body == NULL
          || (unrelated_token = extract_json_string (unrelated_body,
          "access_token")) == NULL) {
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2130 + (gint) i;
      }
    }

    wyl_daemon_http_set_service_publication_fault_for_test (server,
        cases[i].fault);
    g_autofree gchar *body = NULL;
    wyrelog_error_t publish_rc =
        wyl_daemon_http_publish_service_token_for_test (server,
            issued.credential.credential_id, credential_secret,
            credential_secret_len, &body);
    g_autofree gchar *token =
        wyl_daemon_http_dup_last_service_publication_token_for_test (server);
    guint sessions = 0;
    guint access_tokens = 0;
    wyl_daemon_http_service_publication_counts_for_test (server, &sessions,
        &access_tokens);
    guint response_wipes = 0;
    gboolean response_canary_seen = FALSE;
    gboolean response_all_zero = FALSE;
    wyl_daemon_http_service_response_wipe_snapshot_for_test (server,
        &response_wipes, &response_canary_seen, &response_all_zero);
    if (publish_rc == WYRELOG_E_OK || body != NULL || token == NULL
        || sessions != cases[i].sessions
        || access_tokens != cases[i].access_tokens
        || response_wipes != cases[i].response_wipes
        || (response_wipes > 0
        && (!response_canary_seen || !response_all_zero))) {
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2140 + (gint) i;
    }
    WylDaemonServiceResponseAuthoritySnapshot response_authority = { 0 };
    wyl_daemon_http_service_response_authority_snapshot_for_test (server,
        &response_authority);
    if ((cases[i].fault ==
        WYL_DAEMON_SERVICE_PUBLICATION_FAULT_POST_ACTIVE_PRE_HANDOFF
        && (response_authority.created != 2
        || response_authority.complete != 2
        || response_authority.finished != 1
        || response_authority.aborted != 1
        || response_authority.cleanup_failed != 0
        || response_authority.destroyed != 2))
        || (cases[i].fault ==
        WYL_DAEMON_SERVICE_PUBLICATION_FAULT_TERMINAL_RELEASE
        && (response_authority.created != 1
        || response_authority.complete != 1
        || response_authority.finished != 0
        || response_authority.aborted != 0
        || response_authority.cleanup_failed != 1
        || response_authority.destroyed != 1))) {
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2150 + (gint) i;
    }

    guint8 token_secret[32];
    g_autofree gchar *key_id = wyl_daemon_http_dup_access_token_key_id (server);
    g_autoptr (GBytes) payload = NULL;
    if (key_id == NULL
        || wyl_daemon_http_copy_access_token_secret (server, token_secret,
        sizeof token_secret) != WYRELOG_E_OK
        || wyl_jwt_verify_hs256_access_token (token, token_secret,
        sizeof token_secret, key_id, "wyrelogd", "wyrelog-client",
        g_get_real_time () / G_USEC_PER_SEC, &payload) != WYRELOG_E_OK) {
      sodium_memzero (token_secret, sizeof token_secret);
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2160 + (gint) i;
    }
    sodium_memzero (token_secret, sizeof token_secret);
    wyl_jwt_access_claims_t claims = { 0 };
    if (wyl_jwt_parse_access_claims_json (payload, &claims) != WYRELOG_E_OK) {
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2180 + (gint) i;
    }
    gboolean mutated_same_pointer =
        wyl_daemon_http_service_publication_session_is_mutated_same_pointer_for_test
          (server, claims.session_id);
    wyl_daemon_access_token_snapshot_t access_snapshot = { 0 };
    gboolean has_access_snapshot =
        wyl_daemon_http_snapshot_access_token_for_test (server, claims.jti,
            &access_snapshot);
    gboolean mutated_access_iat = has_access_snapshot
        && access_snapshot.issued_at != claims.issued_at;
    wyl_daemon_access_token_snapshot_clear (&access_snapshot);
    if (mutated_same_pointer != cases[i].mutated_same_pointer
        || mutated_access_iat != cases[i].mutated_access_iat) {
      wyl_jwt_access_claims_clear (&claims);
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2190 + (gint) i;
    }
    WylServiceAuthUnavailableReason unavailable_reason =
        WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    wyrelog_error_t available_rc = wyl_service_auth_authority_validate_available
          (wyl_handle_get_service_auth_authority (handle), handle,
            &unavailable_reason);
    gboolean registry_conflict_latched =
        available_rc != WYRELOG_E_OK
        && unavailable_reason ==
        WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INDEX_CONFLICT;
    if (registry_conflict_latched != cases[i].registry_conflict_latched) {
      wyl_jwt_access_claims_clear (&claims);
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2195 + (gint) i;
    }
    gint registry_state = WYL_SERVICE_AUTH_PENDING;
    gboolean registry_found = FALSE;
    if (wyl_daemon_http_lookup_service_registry_for_test (server,
        claims.session_id, claims.jti, &registry_state,
        &registry_found) != WYRELOG_E_OK
        || registry_found != cases[i].registry_found
        || (registry_found && registry_state != WYL_SERVICE_AUTH_ACTIVE)) {
      wyl_jwt_access_claims_clear (&claims);
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2200 + (gint) i;
    }

    g_autofree gchar *resolved_session = NULL;
    g_autofree gchar *resolved_actor = NULL;
    g_autofree gchar *resolved_tenant = NULL;
    gboolean resolves = wyl_daemon_http_resolve_bearer_for_test (server, token,
            &resolved_session, &resolved_actor, &resolved_tenant) == WYRELOG_E_OK;
    if (resolves != cases[i].resolves) {
      wyl_jwt_access_claims_clear (&claims);
      soup_server_disconnect (server);
      g_object_unref (server);
      wyl_service_credential_issue_result_clear (&issued);
      return 2220 + (gint) i;
    }
    if (unrelated_token != NULL) {
      /* The response-loss path has already retired this exact authority.
       * Replaying that same authority cleanup is deliberately idempotent. */
      if (wyl_daemon_http_retire_service_auth_exact_for_test (server,
          claims.session_id, claims.jti, claims.credential_id,
          claims.credential_generation, claims.subject, claims.tenant,
          claims.expires_at) != WYRELOG_E_OK) {
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2225 + (gint) i;
      }
      g_clear_pointer (&resolved_session, g_free);
      g_clear_pointer (&resolved_actor, g_free);
      g_clear_pointer (&resolved_tenant, g_free);
      if (wyl_daemon_http_resolve_bearer_for_test (server, unrelated_token,
          &resolved_session, &resolved_actor,
          &resolved_tenant) != WYRELOG_E_OK) {
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2230 + (gint) i;
      }

      guint8 unrelated_secret[32];
      g_autoptr (GBytes) unrelated_payload = NULL;
      wyl_jwt_access_claims_t unrelated_claims = { 0 };
      if (wyl_daemon_http_copy_access_token_secret (server, unrelated_secret,
          sizeof unrelated_secret) != WYRELOG_E_OK
          || wyl_jwt_verify_hs256_access_token (unrelated_token,
          unrelated_secret, sizeof unrelated_secret, key_id, "wyrelogd",
          "wyrelog-client", g_get_real_time () / G_USEC_PER_SEC,
          &unrelated_payload) != WYRELOG_E_OK
          || wyl_jwt_parse_access_claims_json (unrelated_payload,
          &unrelated_claims) != WYRELOG_E_OK) {
        sodium_memzero (unrelated_secret, sizeof unrelated_secret);
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2235 + (gint) i;
      }
      sodium_memzero (unrelated_secret, sizeof unrelated_secret);

      g_autofree gchar *revoked_body = NULL;
      g_autofree gchar *revoked_token = NULL;
      g_autoptr (GBytes) revoked_payload = NULL;
      wyl_jwt_access_claims_t revoked_claims = { 0 };
      gboolean revoked_changed = FALSE;
      if (wyl_daemon_http_publish_service_token_for_test (server,
          issued.credential.credential_id, credential_secret,
          credential_secret_len, &revoked_body) != WYRELOG_E_OK
          || revoked_body == NULL
          || (revoked_token = extract_json_string (revoked_body,
          "access_token")) == NULL
          || wyl_daemon_http_copy_access_token_secret (server,
          unrelated_secret, sizeof unrelated_secret) != WYRELOG_E_OK
          || wyl_jwt_verify_hs256_access_token (revoked_token,
          unrelated_secret, sizeof unrelated_secret, key_id, "wyrelogd",
          "wyrelog-client", g_get_real_time () / G_USEC_PER_SEC,
          &revoked_payload) != WYRELOG_E_OK
          || wyl_jwt_parse_access_claims_json (revoked_payload,
          &revoked_claims) != WYRELOG_E_OK
          || wyl_daemon_http_service_registry_transition_for_test (server,
          revoked_claims.session_id, revoked_claims.jti,
          revoked_claims.credential_id,
          revoked_claims.credential_generation, revoked_claims.subject,
          revoked_claims.tenant, WYL_DAEMON_SERVICE_REGISTRY_REVOKE,
          &revoked_changed) != WYRELOG_E_OK
          || !revoked_changed
          || wyl_daemon_http_retire_service_auth_exact_for_test (server,
          revoked_claims.session_id, revoked_claims.jti,
          revoked_claims.credential_id,
          revoked_claims.credential_generation, revoked_claims.subject,
          revoked_claims.tenant,
          revoked_claims.expires_at) != WYRELOG_E_OK) {
        sodium_memzero (unrelated_secret, sizeof unrelated_secret);
        wyl_jwt_access_claims_clear (&revoked_claims);
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2237 + (gint) i;
      }
      sodium_memzero (unrelated_secret, sizeof unrelated_secret);
      gboolean revoked_found = TRUE;
      gint revoked_state = WYL_SERVICE_AUTH_PENDING;
      guint revoked_sessions = 0;
      guint revoked_access = 0;
      wyl_daemon_http_service_publication_counts_for_test (server,
          &revoked_sessions, &revoked_access);
      if (wyl_daemon_http_lookup_service_registry_for_test (server,
          revoked_claims.session_id, revoked_claims.jti, &revoked_state,
          &revoked_found) != WYRELOG_E_OK || revoked_found
          || revoked_sessions != 1 || revoked_access != 1) {
        wyl_jwt_access_claims_clear (&revoked_claims);
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2238 + (gint) i;
      }
      wyl_jwt_access_claims_clear (&revoked_claims);

      if (!wyl_daemon_http_mutate_service_session_for_test (server,
          unrelated_claims.session_id,
          WYL_DAEMON_SERVICE_SESSION_SUBJECT, "svc:exchange:mismatch", 0)
          || wyl_daemon_http_retire_service_auth_exact_for_test (server,
          unrelated_claims.session_id, unrelated_claims.jti,
          unrelated_claims.credential_id,
          unrelated_claims.credential_generation,
          unrelated_claims.subject, unrelated_claims.tenant,
          unrelated_claims.expires_at) != WYRELOG_E_POLICY) {
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2240 + (gint) i;
      }
      gboolean preserved_found = FALSE;
      gint preserved_state = WYL_SERVICE_AUTH_PENDING;
      guint preserved_sessions = 0;
      guint preserved_access = 0;
      wyl_daemon_access_token_snapshot_t preserved_snapshot = { 0 };
      wyl_daemon_http_service_publication_counts_for_test (server,
          &preserved_sessions, &preserved_access);
      gboolean access_preserved =
          wyl_daemon_http_snapshot_access_token_for_test (server,
              unrelated_claims.jti, &preserved_snapshot);
      if (wyl_daemon_http_lookup_service_registry_for_test (server,
          unrelated_claims.session_id, unrelated_claims.jti,
          &preserved_state, &preserved_found) != WYRELOG_E_OK
          || !preserved_found || preserved_state != WYL_SERVICE_AUTH_ACTIVE
          || preserved_sessions != 1 || preserved_access != 1
          || !access_preserved
          || g_strcmp0 (preserved_snapshot.jti, unrelated_claims.jti) != 0
          || g_strcmp0 (preserved_snapshot.session_id,
          unrelated_claims.session_id) != 0
          || g_strcmp0 (preserved_snapshot.subject,
          unrelated_claims.subject) != 0
          || g_strcmp0 (preserved_snapshot.tenant,
          unrelated_claims.tenant) != 0
          || g_strcmp0 (preserved_snapshot.credential_id,
          unrelated_claims.credential_id) != 0
          || preserved_snapshot.credential_generation !=
          unrelated_claims.credential_generation
          || preserved_snapshot.expires_at != unrelated_claims.expires_at) {
        wyl_daemon_access_token_snapshot_clear (&preserved_snapshot);
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2242 + (gint) i;
      }
      wyl_daemon_access_token_snapshot_clear (&preserved_snapshot);
      WylServiceAuthUnavailableReason mismatch_reason =
          WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
      if (wyl_service_auth_authority_validate_available
            (wyl_handle_get_service_auth_authority (handle), handle,
          &mismatch_reason) == WYRELOG_E_OK
          || mismatch_reason !=
          WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT) {
        wyl_jwt_access_claims_clear (&unrelated_claims);
        wyl_jwt_access_claims_clear (&claims);
        soup_server_disconnect (server);
        g_object_unref (server);
        wyl_service_credential_issue_result_clear (&issued);
        return 2245 + (gint) i;
      }
      wyl_jwt_access_claims_clear (&unrelated_claims);
    }
    wyl_jwt_access_claims_clear (&claims);
    soup_server_disconnect (server);
    g_object_unref (server);
    wyl_service_credential_issue_result_clear (&issued);
  }
  return 0;
}

static gint
check_service_terminal_release_restart_contract (void)
{
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) old_payload = NULL;
  g_autoptr (GBytes) fresh_payload = NULL;
  g_autofree gchar *failed_body = NULL;
  g_autofree gchar *old_token = NULL;
  g_autofree gchar *old_key_id = NULL;
  g_autofree gchar *resolved_session = NULL;
  g_autofree gchar *fresh_body = NULL;
  g_autofree gchar *fresh_token = NULL;
  g_autofree gchar *fresh_key_id = NULL;
  g_autofree gchar *resolved_actor = NULL;
  g_autofree gchar *resolved_tenant = NULL;
  wyl_service_credential_issue_result_t issued = { 0 };
  SoupServer *server = NULL;
  wyl_jwt_access_claims_t old_claims = { 0 };
  wyl_jwt_access_claims_t fresh_claims = { 0 };
  wyl_id_t canonical_session = WYL_ID_NIL;
  wyl_id_t canonical_jti = WYL_ID_NIL;
  gint result = 2250;

  if (!service_credential_store_fixture_init (&credential_store))
    return result;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    return result;
  prepare_service_token_subject (handle, "svc:exchange:restart");
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    goto cleanup;
  issue_service_token_credential (handle, "svc:exchange:restart", "tenant-a",
      "restart-credential",
      g_get_real_time () + (gint64) 3600 * G_USEC_PER_SEC, &issued);
  gsize credential_secret_len = 0;
  const gchar *credential_secret =
      wyl_service_credential_secret_peek_encoded (issued.secret,
          &credential_secret_len);
  WylDaemonOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  server = wyl_daemon_start_http_server (&options, handle, &error);
  if (server == NULL)
    goto cleanup;

  wyl_daemon_http_set_service_publication_fault_for_test (server,
      WYL_DAEMON_SERVICE_PUBLICATION_FAULT_TERMINAL_RELEASE);
  if (wyl_daemon_http_publish_service_token_for_test (server,
      issued.credential.credential_id, credential_secret,
      credential_secret_len, &failed_body) == WYRELOG_E_OK
      || failed_body != NULL)
    goto cleanup;
  old_token =
      wyl_daemon_http_dup_last_service_publication_token_for_test (server);
  guint sessions = 0;
  guint access_tokens = 0;
  wyl_daemon_http_service_publication_counts_for_test (server, &sessions,
      &access_tokens);
  if (old_token == NULL || sessions != 1 || access_tokens != 1)
    goto cleanup;

  guint8 old_secret[32];
  old_key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (old_key_id == NULL
      || wyl_daemon_http_copy_access_token_secret (server, old_secret,
      sizeof old_secret) != WYRELOG_E_OK
      || wyl_jwt_verify_hs256_access_token (old_token, old_secret,
      sizeof old_secret, old_key_id, "wyrelogd", "wyrelog-client",
      g_get_real_time () / G_USEC_PER_SEC, &old_payload) != WYRELOG_E_OK) {
    sodium_memzero (old_secret, sizeof old_secret);
    goto cleanup;
  }
  sodium_memzero (old_secret, sizeof old_secret);
  if (wyl_jwt_parse_access_claims_json (old_payload,
      &old_claims) != WYRELOG_E_OK)
    goto cleanup;
  gboolean old_registry_found = FALSE;
  gint old_registry_state = WYL_SERVICE_AUTH_PENDING;
  if (wyl_daemon_http_lookup_service_registry_for_test (server,
      old_claims.session_id, old_claims.jti, &old_registry_state,
      &old_registry_found) != WYRELOG_E_OK
      || !old_registry_found || old_registry_state != WYL_SERVICE_AUTH_ACTIVE)
    goto cleanup;
  if (wyl_daemon_http_resolve_bearer_for_test (server, old_token,
      &resolved_session, NULL, NULL) == WYRELOG_E_OK)
    goto cleanup;

  soup_server_disconnect (server);
  g_clear_object (&server);
  g_clear_object (&handle);
  g_clear_error (&error);

  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    goto cleanup;
  server = wyl_daemon_start_http_server (&options, handle, &error);
  if (server == NULL)
    goto cleanup;
  sessions = G_MAXUINT;
  access_tokens = G_MAXUINT;
  wyl_daemon_http_service_publication_counts_for_test (server, &sessions,
      &access_tokens);
  gboolean restarted_registry_found = TRUE;
  gint restarted_registry_state = WYL_SERVICE_AUTH_ACTIVE;
  if (sessions != 0 || access_tokens != 0
      || wyl_daemon_http_lookup_service_registry_for_test (server,
      old_claims.session_id, old_claims.jti, &restarted_registry_state,
      &restarted_registry_found) != WYRELOG_E_OK
      || restarted_registry_found)
    goto cleanup;
  g_clear_pointer (&resolved_session, g_free);
  if (wyl_daemon_http_resolve_bearer_for_test (server, old_token,
      &resolved_session, NULL, NULL) == WYRELOG_E_OK)
    goto cleanup;

  if (wyl_daemon_http_publish_service_token_for_test (server,
      issued.credential.credential_id, credential_secret,
      credential_secret_len, &fresh_body) != WYRELOG_E_OK
      || fresh_body == NULL)
    goto cleanup;
  fresh_token = extract_json_string (fresh_body, "access_token");
  guint8 fresh_secret[32];
  fresh_key_id = wyl_daemon_http_dup_access_token_key_id (server);
  if (fresh_token == NULL || fresh_key_id == NULL
      || wyl_daemon_http_copy_access_token_secret (server, fresh_secret,
      sizeof fresh_secret) != WYRELOG_E_OK
      || wyl_jwt_verify_hs256_access_token (fresh_token, fresh_secret,
      sizeof fresh_secret, fresh_key_id, "wyrelogd", "wyrelog-client",
      g_get_real_time () / G_USEC_PER_SEC,
      &fresh_payload) != WYRELOG_E_OK) {
    sodium_memzero (fresh_secret, sizeof fresh_secret);
    goto cleanup;
  }
  sodium_memzero (fresh_secret, sizeof fresh_secret);
  if (wyl_jwt_parse_access_claims_json (fresh_payload,
      &fresh_claims) != WYRELOG_E_OK
      || wyl_id_parse (fresh_claims.session_id,
      &canonical_session) != WYRELOG_E_OK
      || wyl_id_parse (fresh_claims.jti, &canonical_jti) != WYRELOG_E_OK
      || g_strcmp0 (fresh_claims.auth_method, "service_credential") != 0)
    goto cleanup;
  sessions = 0;
  access_tokens = 0;
  gboolean fresh_registry_found = FALSE;
  gint fresh_registry_state = WYL_SERVICE_AUTH_PENDING;
  guint fresh_response_wipes = G_MAXUINT;
  gboolean fresh_response_canary = TRUE;
  gboolean fresh_response_all_zero = TRUE;
  wyl_daemon_http_service_publication_counts_for_test (server, &sessions,
      &access_tokens);
  wyl_daemon_http_service_response_wipe_snapshot_for_test (server,
      &fresh_response_wipes, &fresh_response_canary, &fresh_response_all_zero);
  if (sessions != 1 || access_tokens != 1 || fresh_response_wipes != 0
      || fresh_response_canary || fresh_response_all_zero
      || wyl_daemon_http_lookup_service_registry_for_test (server,
      fresh_claims.session_id, fresh_claims.jti, &fresh_registry_state,
      &fresh_registry_found) != WYRELOG_E_OK
      || !fresh_registry_found
      || fresh_registry_state != WYL_SERVICE_AUTH_ACTIVE)
    goto cleanup;
  g_clear_pointer (&resolved_session, g_free);
  if (wyl_daemon_http_resolve_bearer_for_test (server, fresh_token,
      &resolved_session, &resolved_actor,
      &resolved_tenant) != WYRELOG_E_OK
      || g_strcmp0 (resolved_actor, "svc:exchange:restart") != 0
      || g_strcmp0 (resolved_tenant, "tenant-a") != 0)
    goto cleanup;
  result = 0;

cleanup:
  if (server != NULL) {
    soup_server_disconnect (server);
    g_object_unref (server);
  }
  wyl_jwt_access_claims_clear (&fresh_claims);
  wyl_jwt_access_claims_clear (&old_claims);
  wyl_service_credential_issue_result_clear (&issued);
  return result;
}
#endif

/* Best-effort recursive removal of a temporary handoff root created by the
 * service-principal contract test. */
static void
sp_remove_tree (const gchar *path)
{
  if (path == NULL)
    return;
  GDir *dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        sp_remove_tree (child);
      else
        (void) g_remove (child);
    }
    g_dir_close (dir);
  }
  (void) g_rmdir (path);
}

/* Mock owner-publication backend for the escrow credential handoff. It mirrors
 * the focused daemon-handoff test vtable so the shared HTTP contract can drive
 * the issue/rotate handlers through the real handoff module to a delivered
 * terminal without touching the real filesystem publication semantics. */
typedef struct
{
  guint plan_calls;
  guint stage_calls;
  guint preflight_calls;
  guint inspect_calls;
  guint commit_calls;
  guint active_leases;
  guint release_calls;
  gboolean published;
  gchar *staged_secret;
} SpPublication;

typedef struct
{
  SpPublication *owner;
  gboolean destination_target;
} SpTargetLease;

static void
sp_copy_plan (const WyctlPublicationPlan *source, WyctlPublicationPlan *out)
{
  *out = (WyctlPublicationPlan) {
    .version = source->version,.destination =
        g_strdup (source->destination),.reservation_id =
        g_strdup (source->reservation_id),.parent_identity =
        g_strdup (source->parent_identity),.stage_basename =
        g_strdup (source->stage_basename),
  };
}

static wyrelog_error_t
sp_plan (gpointer data, const WyctlPublicationPlan *request,
    WyctlPublicationPlan *out)
{
  SpPublication *backend = data;
  backend->plan_calls++;
  sp_copy_plan (request, out);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sp_stage (gpointer data, const WyctlPublicationPlan *plan,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationReceipt *out_receipt, WyctlPublicationResult *out_result,
    gboolean *out_replayed)
{
  SpPublication *backend = data;
  g_assert_nonnull (credential_id);
  g_assert_nonnull (secret);
  backend->stage_calls++;
  /* Capture the exact secret handed to the escrow backend so the contract can
   * prove that this value never appears in any HTTP response body. */
  g_free (backend->staged_secret);
  backend->staged_secret = g_strndup (secret->text, secret->len);
  *out_receipt = (WyctlPublicationReceipt) {
    .version = WYCTL_PUBLICATION_RECEIPT_VERSION,.destination =
        g_strdup (plan->destination),.reservation_id =
        g_strdup (plan->reservation_id),.parent_identity =
        g_strdup (plan->parent_identity),.stage_basename =
        g_strdup (plan->stage_basename),.stage_identity =
        g_strdup ("test-stage-identity"),
  };
  *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,.exact_identity = TRUE,
  };
  *out_replayed = FALSE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sp_target_acquire (gpointer data, const WyctlPublicationPlan *plan,
    const WyctlPublicationReceipt *receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease **out_lease,
    WyctlPublicationReceiptTargetKind *out_kind)
{
  SpPublication *backend = data;
  (void) plan;
  (void) receipt;
  backend->preflight_calls++;
  if (require_destination && !backend->published) {
    *out_lease = NULL;
    *out_kind = WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
    return WYRELOG_E_OK;
  }
  SpTargetLease *lease = g_new0 (SpTargetLease, 1);
  lease->owner = backend;
  lease->destination_target = backend->published;
  backend->active_leases++;
  *out_lease = (WyctlPublicationReceiptTargetLease *) lease;
  *out_kind = backend->published ?
      WYCTL_PUBLICATION_RECEIPT_TARGET_DESTINATION :
      WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sp_target_commit (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationResult *out_result)
{
  SpPublication *backend = data;
  SpTargetLease *lease = (SpTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_false (lease->destination_target);
  g_assert_nonnull (credential_id);
  (void) secret;
  backend->commit_calls++;
  backend->published = TRUE;
  lease->destination_target = TRUE;
  *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,.exact_identity = TRUE,
  };
  return WYRELOG_E_OK;
}

static wyrelog_error_t
sp_target_inspect (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease,
    const gchar *credential_id, const WyctlSensitiveText *secret,
    WyctlPublicationResult *out_result)
{
  SpPublication *backend = data;
  SpTargetLease *lease = (SpTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_nonnull (credential_id);
  (void) secret;
  backend->inspect_calls++;
  *out_result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        lease->destination_target ?
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE :
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,.exact_identity =
        TRUE,.cleanup_required = !lease->destination_target,
  };
  return WYRELOG_E_OK;
}

static void
sp_target_release (gpointer data,
    WyctlPublicationReceiptTargetLease *target_lease)
{
  SpPublication *backend = data;
  SpTargetLease *lease = (SpTargetLease *) target_lease;
  g_assert_true (lease->owner == backend);
  g_assert_cmpuint (backend->active_leases, >, 0);
  backend->active_leases--;
  backend->release_calls++;
  g_free (lease);
}

static wyrelog_error_t
sp_root_identity (gpointer data, gchar **out_identity)
{
  (void) data;
  *out_identity = g_strdup ("test-parent-identity");
  return WYRELOG_E_OK;
}

static const WyctlPublicationBackendVTable sp_publication_vtable = {
  .plan = sp_plan,
  .stage_exact = sp_stage,
  .receipt_target_acquire = sp_target_acquire,
  .receipt_target_inspect = sp_target_inspect,
  .receipt_target_commit = sp_target_commit,
  .receipt_target_release = sp_target_release,
  .root_identity = sp_root_identity,
};

/* #517 capstone: no issue/rotate response may echo an absolute filesystem
 * root.  The escrow receipt names only a validated basename destination and
 * opaque ids; any of the local handoff roots appearing verbatim in a body is
 * a redaction failure. */
static gboolean
sp_body_leaks_root (const gchar *body, const gchar *r1, const gchar *r2,
    const gchar *r3)
{
  return (r1 != NULL && strstr (body, r1) != NULL)
         || (r2 != NULL && strstr (body, r2) != NULL)
         || (r3 != NULL && strstr (body, r3) != NULL);
}

static gint send_raw_service_principal_bearer (SoupSession * session,
    const gchar * method, const gchar * base_url, const gchar * path,
    const gchar * query, const gchar * access_token, const gchar * body,
    guint * out_status, gchar ** out_body);

#ifdef WYL_HAS_FACT_STORE
/* Immediately after the seed helper returns, load through libwyrelog and
 * acquire/release the production lifecycle lock.  Besides validating the
 * durable tuple, this proves the executable consumes the library's storage,
 * load, and lock providers rather than definitions copied out of the helper
 * DSO. */
static gint
verify_seeded_prepared_operation (const gchar *operation_root,
    const gchar *request_id,
    WylServiceCredentialOperationKind kind, const gchar *subject_id,
    const gchar *tenant_id, const gchar *old_credential_id)
{
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gboolean lock_acquired = FALSE;
  gint rc_out = 0;

  if (wyl_service_credential_operation_storage_open (operation_root, &storage)
      != WYRELOG_E_OK) {
    rc_out = 2105;
    goto out;
  }
  if (wyl_service_credential_operation_storage_capture_anchor (&storage,
      &anchor) != WYRELOG_E_OK) {
    rc_out = 2106;
    goto out;
  }
  if (wyl_service_credential_operation_coordinator_load (&storage, &anchor,
      request_id, &loaded) != WYRELOG_E_OK) {
    rc_out = 2107;
    goto out;
  }
  if (loaded.state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      || loaded.kind != kind) {
    rc_out = 2170;
    goto out;
  }
  if (g_strcmp0 (loaded.request_id, request_id) != 0
      || g_strcmp0 (loaded.operation_id, request_id) != 0) {
    rc_out = 2171;
    goto out;
  }
  if (g_strcmp0 (loaded.subject_id, subject_id) != 0) {
    rc_out = 2172;
    goto out;
  }
  if ((tenant_id == NULL
      && loaded.tenant_id != NULL && loaded.tenant_id[0] != '\0')
      || (tenant_id != NULL && g_strcmp0 (loaded.tenant_id, tenant_id) != 0)) {
    rc_out = 2173;
    goto out;
  }
  if ((old_credential_id == NULL
      && loaded.old_credential_id != NULL
      && loaded.old_credential_id[0] != '\0')
      || (old_credential_id != NULL
      && g_strcmp0 (loaded.old_credential_id, old_credential_id) != 0)) {
    rc_out = 2174;
    goto out;
  }
  if (wyl_service_credential_operation_coordinator_lock_acquire (&storage,
      &anchor, request_id, &lifecycle_lock) != WYRELOG_E_OK) {
    rc_out = 2108;
    goto out;
  }
  lock_acquired = TRUE;

out:
  if (lock_acquired)
    wyl_service_credential_operation_coordinator_lock_release (&storage,
        &anchor, &lifecycle_lock);
  wyl_service_credential_operation_record_clear (&loaded);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
  return rc_out;
}

/* Seed one PREPARED durable operation straight into |operation_root|.  Shared
 * POSIX builds cross the scalar-only helper DSO API.  Windows and explicitly
 * static selections retain the existing in-executable friend path. */
static gint
seed_prepared_operation (const gchar *operation_root, const gchar *request_id,
    WylServiceCredentialOperationKind kind, const gchar *subject_id,
    const gchar *tenant_id, const gchar *old_credential_id)
{
  gint rc_out;

#ifdef WYL_TEST_DAEMON_HTTP_SEED_HELPER_DSO
  rc_out = wyl_test_daemon_http_seed_prepared_operation (operation_root,
          request_id, (guint32) kind, subject_id, tenant_id, old_credential_id);
#else
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;

  rc_out = 0;
  if (wyl_service_credential_operation_storage_open (operation_root, &storage)
      != WYRELOG_E_OK) {
    rc_out = 2101;
    goto direct_out;
  }
  if (wyl_service_credential_operation_storage_capture_anchor (&storage,
      &anchor) != WYRELOG_E_OK) {
    rc_out = 2102;
    goto direct_out;
  }
  request.kind = kind;
  request.request_id = (gchar *) request_id;
  request.subject_id = (gchar *) subject_id;
  request.tenant_id = (gchar *) tenant_id;
  request.destination = (gchar *) "credential";
  request.parent_identity = (gchar *) "parent";
  request.actor_subject_id = (gchar *) "admin";
  request.old_credential_id = (gchar *) old_credential_id;
  request.escrow_id = (gchar *) "01890f47-3c4b-7cc2-b8c4-dc0c0c073991";
  memset (request.escrow_binding_digest, 0x31,
      sizeof request.escrow_binding_digest);
  request.expires_at_us = 1;
  request.expected_generation =
      kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE ? 1 : 0;
  if (wyl_service_credential_operation_coordinator_begin_or_replay_for_test
        (&storage, &anchor, &request, 1, NULL, &begun) != WYRELOG_E_OK
      || begun.state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
    rc_out = 2103;
direct_out:
  wyl_service_credential_operation_record_clear (&begun);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
#endif

  if (rc_out == 0)
    rc_out = verify_seeded_prepared_operation (operation_root, request_id,
            kind, subject_id, tenant_id, old_credential_id);
  return rc_out;
}

/* Read back the durable record selected by |request_id| and capture the fields
 * a checkpoint would advance (state, updated_at_us, attempts).  Returns 0 on a
 * successful load so a caller can assert a record is byte-stable across an
 * operation that must not have written to it.  Returns non-zero on any load
 * failure. */
static gint
capture_operation_signature (const gchar *operation_root,
    const gchar *request_id, WylServiceCredentialOperationState *out_state,
    gint64 *out_updated_at_us, guint32 *out_attempts)
{
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gint rc_out = 0;
  if (wyl_service_credential_operation_storage_open (operation_root, &storage)
      != WYRELOG_E_OK)
    return 2130;
  if (wyl_service_credential_operation_storage_capture_anchor (&storage,
      &anchor) != WYRELOG_E_OK) {
    rc_out = 2131;
    goto out;
  }
  if (wyl_service_credential_operation_coordinator_load (&storage, &anchor,
      request_id, &record) != WYRELOG_E_OK) {
    rc_out = 2132;
    goto out;
  }
  *out_state = record.state;
  *out_updated_at_us = record.updated_at_us;
  *out_attempts = record.attempts;
out:
  wyl_service_credential_operation_record_clear (&record);
  wyl_service_credential_operation_storage_clear (&storage);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  return rc_out;
}

/* A serialized operation body must never carry any secret-adjacent field. */
static gboolean
status_body_leaks_secret (const gchar *body)
{
  return strstr (body, "escrow") != NULL
         || strstr (body, "binding") != NULL
         || strstr (body, "stage_") != NULL
         || strstr (body, "parent_identity") != NULL
         || strstr (body, "actor_subject") != NULL
         || strstr (body, "reservation") != NULL
         || strstr (body, "publication_receipt") != NULL
         || strstr (body, "remediation") != NULL
         || strstr (body, "credential_secret") != NULL
         || strstr (body, "subject_id") != NULL
         || strstr (body, "tenant_id") != NULL
         || strstr (body, "operation_id") != NULL
         || strstr (body, "old_credential_id") != NULL;
}

/* Drives the durable operation status + recover HTTP contract against the
 * SYSTEM-profile handoff server.  Seeds three PREPARED operations (a tenant-a
 * issue, a tenant-b issue, and a tenant-a rotate whose target is established
 * by the old credential) and asserts tenant scoping, non-secret output, and
 * recover classification. Returns 0 on success. */
static gint
check_service_credential_operation_status_recover (SoupServer *server,
    SoupSession *session, const gchar *base_url, const gchar *access_token,
    const gchar *operation_root, const gchar *rotate_old_credential_id)
{
  if (operation_root == NULL || access_token == NULL
      || rotate_old_credential_id == NULL)
    return 2110;

  gchar issue_a_id[WYL_REQUEST_ID_STRING_BUF];
  gchar issue_b_id[WYL_REQUEST_ID_STRING_BUF];
  gchar rotate_a_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (issue_a_id, sizeof issue_a_id) != WYRELOG_E_OK
      || wyl_request_id_new (issue_b_id, sizeof issue_b_id) != WYRELOG_E_OK
      || wyl_request_id_new (rotate_a_id, sizeof rotate_a_id) != WYRELOG_E_OK)
    return 2111;

  gint seed_rc = seed_prepared_operation (operation_root, issue_a_id,
          WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:tenant-a:worker", "tenant-a",
          NULL);
  if (seed_rc != 0)
    return seed_rc;
  seed_rc = seed_prepared_operation (operation_root, issue_b_id,
          WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:tenant-a:misleading",
          "tenant-b", NULL);
  if (seed_rc != 0)
    return seed_rc;
  seed_rc = seed_prepared_operation (operation_root, rotate_a_id,
          WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE, "svc:tenant-b:misleading",
          NULL, rotate_old_credential_id);
  if (seed_rc != 0)
    return seed_rc;

  /* The seeds bypass the authenticated path that normally registers a target,
   * so register tenant-b symmetrically with the already-active tenant-a. */
  if (wyl_daemon_http_configure_tenant_for_test (server, "tenant-b", TRUE,
      FALSE) != WYRELOG_E_OK)
    return 2128;

  g_autofree gchar *tenant_a_query = g_strdup
        ("tenant=tenant-a&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");

  guint status = 0;
  g_autofree gchar *body = NULL;

  /* Status listing for tenant-a includes its issue and the rotate resolved
   * through the old credential; subject_id is never used for scope. */
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-credential-operations", tenant_a_query, access_token,
      NULL, &status, &body) != 0 || status != 200 || body == NULL
      || strstr (body, issue_a_id) == NULL
      || strstr (body, rotate_a_id) == NULL
      || strstr (body, issue_b_id) != NULL
      || strstr (body, "\"operation\":\"issue\"") == NULL
      || strstr (body, "\"operation\":\"rotate\"") == NULL
      || strstr (body, "\"state\":\"prepared\"") == NULL
      || status_body_leaks_secret (body))
    return 2113;

  /* A tenant with no operations of its own lists an empty array, not an
   * error. */
  g_clear_pointer (&body, g_free);
  g_autofree gchar *default_query = g_strdup
        ("tenant=__wr_default&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-credential-operations", default_query, access_token,
      NULL, &status, &body) != 0 || status != 200 || body == NULL
      || strstr (body, "\"operations\":[]") == NULL)
    return 2115;

  /* The bare status collection rejects a POST; it must not shadow the recover
   * or reconcile sibling handlers. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations", default_query, access_token,
      "{}", &status, &body) != 0 || status != 405)
    return 2116;

  /* Recover the tenant-a issue: no server-side commit evidence exists yet, so
   * it classifies as pending and returns 200. */
  g_autofree gchar *recover_a_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", issue_a_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover", tenant_a_query,
      access_token, recover_a_body, &status, &body) != 0 || status != 200
      || body == NULL
      || strstr (body, "\"recovery\":\"pending\"") == NULL
      || strstr (body, issue_a_id) == NULL || status_body_leaks_secret (body))
    return 2118;

  /* An unknown request id is a 404. */
  gchar unknown_id[WYL_REQUEST_ID_STRING_BUF];
  if (wyl_request_id_new (unknown_id, sizeof unknown_id) != WYRELOG_E_OK)
    return 2119;
  g_autofree gchar *recover_unknown_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", unknown_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover", tenant_a_query,
      access_token, recover_unknown_body, &status, &body) != 0
      || status != 404)
    return 2120;

  /* A 27-character alphanumeric but noncanonical request id is a 400. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover", tenant_a_query,
      access_token,
      "{\"version\":\"1\",\"request_id\":"
      "\"abcdefghijklmnopqrstuvwxyz0\"}", &status, &body) != 0
      || status != 400)
    return 2121;

  /* Recovering another tenant's operation must not reveal it, AND must not
   * write to it: the tenant gate runs on a read-only load before any lock or
   * checkpoint.  Snapshot the tenant-b issue's mutable fields, recover it under
   * tenant-a (a 404 that is not a leak), then assert the durable record is
   * byte-stable (state/updated_at_us/attempts unchanged): no checkpoint ran. */
  WylServiceCredentialOperationState pre_state = 0;
  gint64 pre_updated_at_us = 0;
  guint32 pre_attempts = 0;
  if (capture_operation_signature (operation_root, issue_b_id, &pre_state,
      &pre_updated_at_us, &pre_attempts) != 0
      || pre_state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
    return 2122;
  g_autofree gchar *recover_cross_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", issue_b_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover", tenant_a_query,
      access_token, recover_cross_body, &status, &body) != 0
      || status != 404 || (body != NULL && strstr (body, issue_b_id) != NULL))
    return 2123;
  WylServiceCredentialOperationState post_state = 0;
  gint64 post_updated_at_us = 0;
  guint32 post_attempts = 0;
  if (capture_operation_signature (operation_root, issue_b_id, &post_state,
      &post_updated_at_us, &post_attempts) != 0
      || post_state != pre_state || post_updated_at_us != pre_updated_at_us
      || post_attempts != pre_attempts)
    return 2124;

  /* A legitimate tenant-b recover of the same operation still classifies as
   * pending: the cross-tenant attempt neither advanced nor consumed it. */
  g_autofree gchar *tenant_b_query = g_strdup
        ("tenant=tenant-b&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover", tenant_b_query,
      access_token, recover_cross_body, &status, &body) != 0
      || status != 200
      || body == NULL || strstr (body, "\"recovery\":\"pending\"") == NULL
      || strstr (body, issue_b_id) == NULL || status_body_leaks_secret (body))
    return 2126;

  /* The recover handler owns ONLY its exact path; a deeper subpath is unknown
   * and must 404 rather than be served by longest-prefix routing. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-credential-operations/recover/extra", tenant_a_query,
      access_token, recover_a_body, &status, &body) != 0 || status != 404)
    return 2127;

  return 0;
}
#endif /* WYL_HAS_FACT_STORE */

static gboolean
policy_count_rows (WylHandle *handle, const gchar *sql, gint64 *out_count)
{
  if (handle == NULL || sql == NULL || out_count == NULL)
    return FALSE;
  *out_count = -1;
  sqlite3 *db = wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
  sqlite3_stmt *stmt = NULL;
  if (db == NULL || sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return FALSE;
  gboolean ok = sqlite3_step (stmt) == SQLITE_ROW;
  if (ok)
    *out_count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return ok;
}

static gint
check_service_principal_management_contract (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_autofree gchar *base_url = NULL;
  g_autofree gchar *query = NULL;
  g_autoptr (SoupSession) session = g_object_new (SOUP_TYPE_SESSION, NULL);
  g_autofree gchar *body = NULL;
  GSList *uris = NULL;
  wyl_policy_store_t *policy_store = NULL;
  gboolean tenant_created = FALSE;
  wyl_service_credential_issue_result_t issued = { 0 };
  wyl_service_credential_issue_result_t rotate_seed = { 0 };
  g_autofree gchar *credential_path = NULL;
  g_autofree gchar *rotate_path = NULL;
  g_autofree gchar *cross_tenant_rotate_path = NULL;
  g_autofree gchar *tenant_query = NULL;
  g_autofree gchar *http_credential_id = NULL;
  g_autofree gchar *rotate_successor_id = NULL;
  g_autofree gchar *http_exchange_body = NULL;
  g_autofree gchar *first_revoke_response = NULL;
#ifdef WYL_HAS_AUDIT
  g_autofree gchar *denied_body = NULL;
  g_autofree gchar *http_exchange_access = NULL;
  g_autofree gchar *oversized_principal_disable_body = NULL;
  guint denied_status = 0;
  guint denied_retry_after = 0;
#endif
  g_autofree gchar *handoff_dir = NULL;
  g_autofree gchar *operation_root = NULL;
  g_autofree gchar *publication_root = NULL;
  SpPublication publication = { 0 };
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  MainLoopReadyBarrier barrier = { 0 };
  gchar session_token[WYL_ID_STRING_BUF];
  g_autofree gchar *access_token = NULL;
  wyl_id_t session_id_value = WYL_ID_NIL;
  guint status = 0;
  guint issue_stage_calls = 0;
  guint issue_commit_calls = 0;
  guint rotate_stage_calls = 0;
  guint rotate_commit_calls = 0;
#ifdef WYL_HAS_AUDIT
  g_auto (ActualServiceTokens) principal_route_tokens = { 0 };
  g_auto (ActualServiceTokens) principal_unrelated_tokens = { 0 };
  g_auto (ActualServiceTokens) tenant_route_tokens = { 0 };
  g_auto (ActualServiceTokens) revoke_route_tokens = { 0 };
  g_auto (ActualServiceTokens) revoke_unrelated_tokens = { 0 };
  g_auto (ActualServiceTokens) rotate_route_tokens = { 0 };
  g_auto (ActualServiceTokens) rotate_unrelated_tokens = { 0 };
  g_autofree gchar *revoke_route_path = NULL;
  g_autofree gchar *rotate_route_path = NULL;
  g_autofree gchar *tenant_route_query = NULL;
  wyl_service_principal_t tenant_route_principal = { 0 };
  wyl_service_principal_t principal_unrelated = { 0 };
#endif
  const gchar *create_body =
      "{\"subject_id\":\"svc:tenant-a:worker\",\"display_name\":\"Worker\"}";
  gint rc = 0;
  if (session == NULL)
    return 1976;
  /* Escrow issuance seals a service CVK and requires an owned keyprovider, so
   * open an encrypted production store instead of wyl_init()'s providerless
   * in-memory store (which would fail issuance with WYRELOG_E_POLICY). */
  if (!service_credential_store_fixture_init (&credential_store))
    return 1975;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &handle) != WYRELOG_E_OK)
    return 1975;
  /* Mint a canonical session id.  The seed helper parses this via
   * wyl_id_parse and the authorize path evaluates it as the decide resource,
   * so a literal username would fail to seed the session. */
  if (wyl_id_new (&session_id_value) != WYRELOG_E_OK
      || wyl_id_format (&session_id_value, session_token,
      sizeof session_token) != WYRELOG_E_OK)
    return 1973;

  /* The escrow handoff needs both opt-in roots configured; the publication
   * override then drives a mock backend instead of the real one at
   * publication_root. */
  handoff_dir = g_dir_make_tmp ("wyl-daemon-http-handoff-XXXXXX", NULL);
  if (handoff_dir == NULL)
    return 1974;
  operation_root = service_credential_operation_root_for_test (handoff_dir,
          "http-handoff-operations");
  publication_root = g_build_filename (handoff_dir, "publication", NULL);
  if (g_mkdir_with_parents (publication_root, 0700) != 0)
    return 1974;

  g_autoptr (GMainContext) context = g_main_context_new ();
  g_main_context_push_thread_default (context);
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .operation_root = operation_root,
    .credential_publication_root = publication_root,
  };
  g_autoptr (GError) error = NULL;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (context, FALSE);
  GThread *thread = NULL;
  http.server = wyl_daemon_start_http_server (&opts, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    return 1977;
  thread = g_thread_new ("daemon-http-service-principal",
          test_http_server_thread_ctx, &http);
  /* Barrier: wait until the worker thread is running g_main_loop_run before
   * issuing any request, so an early goto cleanup cannot quit the loop before
   * the worker enters it and hang g_thread_join. */
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  g_main_context_invoke_full (context, G_PRIORITY_DEFAULT,
      mark_main_loop_ready, &barrier, NULL);
  g_mutex_lock (&barrier.mutex);
  if (!barrier.ready)
    g_cond_wait_until (&barrier.changed, &barrier.mutex,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC);
  if (!barrier.ready) {
    /* Timed out before the worker entered g_main_loop_run.  Unlock first, then
     * route through cleanup, which quits the loop before joining the thread --
     * the same quit-before-join ordering the refresh-variant barrier-timeout
     * handler uses -- and also removes the handoff temp roots. */
    g_mutex_unlock (&barrier.mutex);
    rc = 2003;
    goto cleanup;
  }
  g_mutex_unlock (&barrier.mutex);

  /* This fixture mutates the service-authority store directly while testing
   * the management routes.  Keep its background retirement writer out of
   * those deterministic mutations; suspend waits for any in-flight tick. */
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (http.server);
  guint maintenance_ticks = 0;
  if (wyl_daemon_http_service_auth_maintenance_active_for_test (http.server,
      &maintenance_ticks)) {
    rc = 2164;
    goto cleanup;
  }

  uris = soup_server_get_uris (http.server);
  if (uris == NULL) {
    rc = 1978;
    goto cleanup;
  }
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  wyl_daemon_http_set_publication_override_for_test (http.server,
      &sp_publication_vtable, &publication);

  if (!seed_management_human_access_token (http.server, session_token,
      "human-principal-admin", &access_token)) {
    rc = 1979;
    goto cleanup;
  }
  policy_store = wyl_handle_get_policy_store (handle);
  /* The datalog allow rules require an authenticated principal and an active
   * session (templates/access/decision.dl); the session seed only marks the
   * in-memory session active, so set both facts here.  The session-state
   * scope must be the canonical session id because
   * service_principal_management_authorize_session evaluates the session id as
   * the decide resource. */
  if (wyl_policy_store_set_principal_state (policy_store,
      "human-principal-admin", "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (policy_store, session_token,
      "active") != WYRELOG_E_OK) {
    rc = 1971;
    goto cleanup;
  }
  if (wyl_policy_store_grant_direct_permission (policy_store,
      "human-principal-admin", "wr.service_principal.manage",
      session_token) != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (policy_store,
      "human-principal-admin", "wr.service_principal.manage",
      session_token, "armed") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (policy_store,
      "human-principal-admin", "wr.service_credential.manage",
      session_token) != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (policy_store,
      "human-principal-admin", "wr.service_credential.manage",
      session_token, "armed") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (policy_store,
      "human-principal-admin", "wr.tenant.manage",
      WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (policy_store,
      "human-principal-admin", "wr.tenant.manage",
      WYL_TENANT_DEFAULT, "armed") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (policy_store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK) {
    rc = 1989;
    goto cleanup;
  }
  query = g_strdup ("guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals", query, access_token, create_body, &status,
      &body) != 0
      || status != 200 || body == NULL
      || strstr (body, "\"service_principal\":") == NULL
      || strstr (body, "\"subject_id\":\"svc:tenant-a:worker\"") == NULL
      || strstr (body, "\"display_name\":\"Worker\"") == NULL
      || strstr (body, "\"state\":\"active\"") == NULL
      || strstr (body, "credential_id") != NULL) {
    rc = 1980;
    goto cleanup;
  }

  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-principals", query, access_token, NULL, &status,
      &body) != 0
      || status != 200 || body == NULL
      || strstr (body, "\"service_principals\":[") == NULL
      || strstr (body, "\"subject_id\":\"svc:tenant-a:worker\"") == NULL
      || strstr (body, "\"state\":\"active\"") == NULL) {
    rc = 1981;
    goto cleanup;
  }

  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-principals/svc:tenant-a:worker/credentials",
      query, access_token, NULL, &status, &body) != 0 || status != 200
      || body == NULL
      || strstr (body, "\"service_credentials\":[") == NULL
      || strstr (body, "credential_secret") != NULL) {
    rc = 1984;
    goto cleanup;
  }

  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-credentials/wlc_000000000000000000000000000",
      query, access_token, NULL, &status, &body) != 0 || status != 404
      || body == NULL
      || strstr (body, "service_credential_not_found") == NULL) {
    rc = 1985;
    goto cleanup;
  }

  if (wyl_policy_store_create_tenant (wyl_handle_get_policy_store (handle),
      "tenant-a", &tenant_created) != WYRELOG_E_OK || !tenant_created) {
    rc = 1986;
    goto cleanup;
  }
  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    rc = 1988;
    goto cleanup;
  }
  g_clear_pointer (&query, g_free);
  tenant_query = g_strdup
        ("tenant=tenant-a&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-b:worker/credentials",
      tenant_query, access_token,
      "{\"version\":\"1\",\"tenant\":\"tenant-a\","
      "\"request_id\":\"000000000000000000000000000\"}",
      &status, &body) != 0 || status != 400 || body == NULL
      || strstr (body, "credential_secret") != NULL) {
    rc = 1987;
    goto cleanup;
  }
  const gchar *issue_body =
      "{\"version\":\"1\",\"tenant\":\"tenant-a\","
      "\"request_id\":\"111111111111111111111111111\","
      "\"destination\":\"issue.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}";
  g_clear_pointer (&body, g_free);
  g_clear_pointer (&publication.staged_secret, g_free);
  memset (&publication, 0, sizeof publication);
  gint64 issue_credentials_before = 0;
  gint64 issue_credentials_after = 0;
  if (!policy_count_rows (handle, "SELECT count(*) FROM service_credentials;",
      &issue_credentials_before)) {
    rc = 2170;
    goto cleanup;
  }
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-a:worker/credentials",
      tenant_query, access_token,
      "{\"version\":\"1\",\"tenant\":\"tenant-a\","
      "\"request_id\":\"abcdefghijklmnopqrstuvwxyz0\","
      "\"destination\":\"issue.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}", &status, &body) != 0
      || status != 400 || body == NULL
      || strstr (body, "invalid_service_credential_request") == NULL
      || strstr (body, "credential_secret") != NULL
      || publication.stage_calls != 0 || publication.commit_calls != 0
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credentials;", &issue_credentials_after)
      || issue_credentials_after != issue_credentials_before) {
    rc = 2171;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  /* Issue now delivers the secret out-of-band via the escrow file; the HTTP
   * response is the module's non-secret receipt.  This E2E test exercises the
   * loopback-permitted arm: both the client and server addresses are always
   * loopback in-process, and there is no seam to spoof a non-loopback peer, so
   * the production 403 loopback gate is covered at the module level rather
   * than here. */
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-a:worker/credentials",
      tenant_query, access_token, issue_body, &status, &body) != 0
      || status != 200
      || body == NULL || strstr (body, "credential_secret") != NULL
      || strstr (body, "\"state\":\"terminal\"") == NULL
      || strstr (body, "\"delivered\":true") == NULL
      || strstr (body, "\"destination\":\"issue.json\"") == NULL
      || (http_credential_id =
      extract_json_string (body, "credential_id")) == NULL) {
    rc = 1990;
    goto cleanup;
  }
  /* #517 capstone: the issue receipt must not echo any absolute handoff
   * root, and its destination must be the bare basename it was asked for --
   * never a path (no '/'). */
  if (sp_body_leaks_root (body, handoff_dir, operation_root, publication_root)) {
    rc = 2010;
    goto cleanup;
  }
  {
    g_autofree gchar *issue_destination =
        extract_json_string (body, "destination");
    if (issue_destination == NULL
        || g_strcmp0 (issue_destination, "issue.json") != 0
        || strchr (issue_destination, '/') != NULL) {
      rc = 2011;
      goto cleanup;
    }
  }
  /* #517: the first successful issue must actually stage the CVK into escrow
   * and commit it -- one real secret written.  Capture the counts so the
   * replay arm can prove no second secret is staged. */
  issue_stage_calls = publication.stage_calls;
  issue_commit_calls = publication.commit_calls;
  if (issue_stage_calls == 0 || issue_commit_calls == 0) {
    rc = 2004;
    goto cleanup;
  }
  /* #517 capstone: the actual one-time secret staged into escrow must never
  * appear anywhere in the HTTP response body -- not merely the key name. */
  if (publication.staged_secret == NULL || publication.staged_secret[0] == '\0'
      || strstr (body, publication.staged_secret) != NULL) {
    rc = 2016;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  /* The service-token exchange is decoupled from the receipt path: seed a
   * credential secret directly through the library and exchange that. */
  {
    wyl_service_credential_issue_result_t exchange_seed = { 0 };
    if (wyl_service_credential_issue (handle, "svc:tenant-a:worker", "tenant-a",
        "human-principal-admin", "http-exchange-seed",
        CONTRACT_FUTURE_EXPIRES_AT_US,
        &exchange_seed) != WYRELOG_E_OK || exchange_seed.secret == NULL
        || exchange_seed.credential.credential_id == NULL) {
      wyl_service_credential_issue_result_clear (&exchange_seed);
      rc = 1993;
      goto cleanup;
    }
    gsize exchange_secret_len = 0;
    const gchar *exchange_secret = wyl_service_credential_secret_peek_encoded
          (exchange_seed.secret, &exchange_secret_len);
    http_exchange_body = g_strdup_printf
          ("{\"credential_id\":\"%s\",\"credential_secret\":\"%.*s\"}",
            exchange_seed.credential.credential_id, (gint) exchange_secret_len,
            exchange_secret);
    wyl_service_credential_issue_result_clear (&exchange_seed);
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_full (session, "POST", base_url,
      "/auth/service-token", NULL, http_exchange_body, &status, &body)
      != 0) {
    rc = 1993;
    goto cleanup;
  }
  if (status != 200 || body == NULL) {
    rc = 1993;
    goto cleanup;
  }
  http_exchange_access = extract_json_string (body, "access_token");
  if (http_exchange_access == NULL || strstr (body, "session_token") != NULL
      || strstr (body, "credential_secret") != NULL) {
    rc = 1993;
    goto cleanup;
  }
  denied_status = 0;
  denied_retry_after = 0;
  g_clear_pointer (&denied_body, g_free);
  if (wyl_daemon_http_issue_service_token_for_test (http.server, FALSE,
      http_exchange_body, strlen (http_exchange_body), &denied_status,
      &denied_body, &denied_retry_after) != WYRELOG_E_OK
      || denied_status != 403 || denied_body == NULL
      || strstr (denied_body, "access_token") != NULL
      || strstr (denied_body, "credential_secret") != NULL) {
    rc = 1994;
    goto cleanup;
  }
#endif
  g_clear_pointer (&body, g_free);
  /* Re-submitting the identical request_id replays the escrow handoff to the
   * same non-secret receipt (idempotency), rather than the pre-escrow 409
   * conflict which came from the library request_id fence. */
  {
    g_autofree gchar *replay_id = NULL;
    if (send_raw_service_principal_bearer (session, "POST", base_url,
        "/service-principals/svc:tenant-a:worker/credentials",
        tenant_query, access_token, issue_body, &status, &body) != 0
        || status != 200
        || body == NULL || strstr (body, "credential_secret") != NULL
        || strstr (body, "\"state\":\"terminal\"") == NULL
        || strstr (body, "\"delivered\":true") == NULL
        || (replay_id = extract_json_string (body, "credential_id")) == NULL
        || g_strcmp0 (replay_id, http_credential_id) != 0) {
      rc = 1992;
      goto cleanup;
    }
    if (sp_body_leaks_root (body, handoff_dir, operation_root,
        publication_root)) {
      rc = 2012;
      goto cleanup;
    }
  }
  /* #517: the replay must return the same receipt WITHOUT re-staging or
   * re-committing -- no second secret written to escrow. */
  if (publication.stage_calls != issue_stage_calls
      || publication.commit_calls != issue_commit_calls) {
    rc = 2005;
    goto cleanup;
  }
  g_clear_pointer (&query, g_free);
  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    rc = 1989;
    goto cleanup;
  }
  query = g_strdup ("guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  if (wyl_service_credential_issue (handle, "svc:tenant-a:worker", "tenant-a",
      "human-principal-admin", "http-credential-read",
      CONTRACT_FUTURE_EXPIRES_AT_US,
      &issued) != WYRELOG_E_OK || issued.credential.credential_id == NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 1987;
    goto cleanup;
  }
  if (wyl_service_credential_issue (handle, "svc:tenant-a:worker", "tenant-a",
      "human-principal-admin", "http-credential-rotate",
      CONTRACT_FUTURE_EXPIRES_AT_US,
      &rotate_seed) != WYRELOG_E_OK
      || rotate_seed.credential.credential_id == NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 1997;
    goto cleanup;
  }
  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 1998;
    goto cleanup;
  }
  g_clear_pointer (&query, g_free);
  query = g_strdup
        ("tenant=tenant-a&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  rotate_path = g_strdup_printf ("/service-credentials/%s/rotate",
          rotate_seed.credential.credential_id);
  g_clear_pointer (&body, g_free);
  g_clear_pointer (&publication.staged_secret, g_free);
  memset (&publication, 0, sizeof publication);
  gint64 rotate_credentials_before = 0;
  gint64 rotate_credentials_after = 0;
  if (!policy_count_rows (handle, "SELECT count(*) FROM service_credentials;",
      &rotate_credentials_before)) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2172;
    goto cleanup;
  }
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      rotate_path, query, access_token,
      "{\"version\":\"1\",\"request_id\":\"abcdefghijklmnopqrstuvwxyz0\","
      "\"destination\":\"rotate.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}", &status, &body) != 0
      || status != 400 || body == NULL
      || strstr (body, "invalid_service_credential_request") == NULL
      || strstr (body, "credential_secret") != NULL
      || publication.stage_calls != 0 || publication.commit_calls != 0
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credentials;",
      &rotate_credentials_after)
      || rotate_credentials_after != rotate_credentials_before) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2173;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  /* Rotate delivers the successor secret via the escrow file too; assert the
   * non-secret receipt naming a fresh successor credential. */
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      rotate_path, query, access_token,
      "{\"version\":\"1\",\"request_id\":\"333333333333333333333333333\","
      "\"destination\":\"rotate.json\","
      "\"expires_at_us\":\"" CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}",
      &status, &body) != 0 || status != 200 || body == NULL
      || strstr (body, "credential_secret") != NULL
      || strstr (body, "\"state\":\"terminal\"") == NULL
      || strstr (body, "\"delivered\":true") == NULL
      || strstr (body, "\"destination\":\"rotate.json\"") == NULL
      || (rotate_successor_id = extract_json_string (body, "credential_id"))
      == NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 1999;
    goto cleanup;
  }
  /* #517 capstone: the rotate receipt must not echo any absolute handoff
   * root either. */
  if (sp_body_leaks_root (body, handoff_dir, operation_root, publication_root)) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2013;
    goto cleanup;
  }
  /* #517: the first rotate stages+commits the successor secret exactly once
   * (publication was reset just above), so both counts must be positive. */
  rotate_stage_calls = publication.stage_calls;
  rotate_commit_calls = publication.commit_calls;
  if (rotate_stage_calls == 0 || rotate_commit_calls == 0) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2006;
    goto cleanup;
  }
  /* #517 capstone: the successor secret staged into escrow must likewise never
   * surface in the rotate response body. */
  if (publication.staged_secret == NULL || publication.staged_secret[0] == '\0'
      || strstr (body, publication.staged_secret) != NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2017;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  /* Re-submitting the identical rotate request_id replays the handoff to the
   * same non-secret successor receipt (idempotency), not a 409 conflict. */
  {
    g_autofree gchar *replay_rotate_id = NULL;
    if (send_raw_service_principal_bearer (session, "POST", base_url,
        rotate_path, query, access_token,
        "{\"version\":\"1\",\"request_id\":\"333333333333333333333333333\","
        "\"destination\":\"rotate.json\","
        "\"expires_at_us\":\"" CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}",
        &status, &body) != 0 || status != 200 || body == NULL
        || strstr (body, "credential_secret") != NULL
        || strstr (body, "\"state\":\"terminal\"") == NULL
        || strstr (body, "\"delivered\":true") == NULL
        || (replay_rotate_id = extract_json_string (body, "credential_id"))
        == NULL || g_strcmp0 (replay_rotate_id, rotate_successor_id) != 0) {
      wyl_service_credential_issue_result_clear (&issued);
      wyl_service_credential_issue_result_clear (&rotate_seed);
      rc = 2000;
      goto cleanup;
    }
    if (sp_body_leaks_root (body, handoff_dir, operation_root,
        publication_root)) {
      wyl_service_credential_issue_result_clear (&issued);
      wyl_service_credential_issue_result_clear (&rotate_seed);
      rc = 2014;
      goto cleanup;
    }
  }
  /* #517: the rotate replay returns the same successor WITHOUT re-staging or
   * re-committing -- no second successor secret written to escrow. */
  if (publication.stage_calls != rotate_stage_calls
      || publication.commit_calls != rotate_commit_calls) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    rc = 2007;
    goto cleanup;
  }
  wyl_service_credential_issue_result_clear (&rotate_seed);
  cross_tenant_rotate_path = g_strdup_printf
        ("/service-credentials/%s/rotate", issued.credential.credential_id);
  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 2001;
    goto cleanup;
  }
  g_clear_pointer (&query, g_free);
  query = g_strdup ("guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      cross_tenant_rotate_path, query, access_token,
      "{\"version\":\"1\",\"request_id\":\"444444444444444444444444444\","
      "\"destination\":\"rotate.json\","
      "\"expires_at_us\":\"" CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}",
      &status, &body) != 0 || status != 404 || body == NULL
      || strstr (body, "service_credential_not_found") == NULL
      || strstr (body, "credential_secret") != NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 2002;
    goto cleanup;
  }
  /* #517 capstone: an ERROR body must not leak a root or a secret either;
   * error bodies are fixed constants, so a root here would be a regression. */
  if (sp_body_leaks_root (body, handoff_dir, operation_root, publication_root)) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 2015;
    goto cleanup;
  }
  credential_path = g_strdup_printf
        ("/service-credentials/%s", issued.credential.credential_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      credential_path, query, access_token, NULL, &status, &body) != 0
      || status != 404
      || body == NULL || strstr (body, "service_credential_not_found") == NULL
      || strstr (body, "credential_secret") != NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 1988;
    goto cleanup;
  }
  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 1993;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  wyl_service_credential_t revoke_before = { 0 };
  wyl_service_credential_t revoke_after = { 0 };
  gint64 requests_before = 0;
  gint64 requests_after = 0;
  gint64 revoke_events_before = 0;
  gint64 revoke_events_after = 0;
  gint64 revoke_audits_before = 0;
  gint64 revoke_audits_after = 0;
  gint64 revoke_outbox_before = 0;
  gint64 revoke_outbox_after = 0;
  gint64 noncanonical_artifacts = 0;
  gsize revoke_secret_len = 0;
  const gchar *revoke_secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &revoke_secret_len);
  if (revoke_secret == NULL || revoke_secret_len == 0
      || wyl_service_credential_get (handle,
      issued.credential.credential_id, &revoke_before) != WYRELOG_E_OK
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_domain_requests;", &requests_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credential_events "
      "WHERE event='revoked';", &revoke_events_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_events "
      "WHERE action='service.credential.revoke';", &revoke_audits_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_intentions i JOIN audit_events a "
      "ON a.id=i.audit_id WHERE a.action='service.credential.revoke';",
      &revoke_outbox_before)) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_clear (&revoke_before);
    rc = 2174;
    goto cleanup;
  }
  if (send_raw_service_principal_bearer (session, "DELETE", base_url,
      credential_path, tenant_query, access_token,
      "{\"version\":\"1\",\"request_id\":\"abcdefghijklmnopqrstuvwxyz0\"}",
      &status, &body) != 0 || status != 400 || body == NULL
      || strstr (body, "invalid_service_credential_request") == NULL
      || strstr (body, "credential_secret") != NULL
      || strstr (body, revoke_secret) != NULL
      || wyl_service_credential_get (handle,
      issued.credential.credential_id, &revoke_after) != WYRELOG_E_OK
      || g_strcmp0 (revoke_after.state, revoke_before.state) != 0
      || revoke_after.generation != revoke_before.generation
      || revoke_after.updated_at_us != revoke_before.updated_at_us
      || revoke_after.revoked_at_us != revoke_before.revoked_at_us
      || g_strcmp0 (revoke_after.revoked_by, revoke_before.revoked_by) != 0
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_domain_requests;", &requests_after)
      || requests_after != requests_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credential_events "
      "WHERE event='revoked';", &revoke_events_after)
      || revoke_events_after != revoke_events_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_events "
      "WHERE action='service.credential.revoke';", &revoke_audits_after)
      || revoke_audits_after != revoke_audits_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_intentions i JOIN audit_events a "
      "ON a.id=i.audit_id WHERE a.action='service.credential.revoke';",
      &revoke_outbox_after)
      || revoke_outbox_after != revoke_outbox_before
      || !policy_count_rows (handle,
      "SELECT (SELECT count(*) FROM service_domain_requests "
      "WHERE request_id='abcdefghijklmnopqrstuvwxyz0') + "
      "(SELECT count(*) FROM service_credential_events "
      "WHERE request_id='abcdefghijklmnopqrstuvwxyz0') + "
      "(SELECT count(*) FROM audit_events "
      "WHERE request_id='abcdefghijklmnopqrstuvwxyz0');",
      &noncanonical_artifacts)
      || noncanonical_artifacts != 0) {
    wyl_service_credential_issue_result_clear (&issued);
    wyl_service_credential_clear (&revoke_before);
    wyl_service_credential_clear (&revoke_after);
    rc = 2175;
    goto cleanup;
  }
  wyl_service_credential_clear (&revoke_before);
  wyl_service_credential_clear (&revoke_after);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "DELETE", base_url,
      credential_path, tenant_query, access_token,
      "{\"version\":\"1\",\"request_id\":\"222222222222222222222222222\"}",
      &status, &body) != 0 || status != 200 || body == NULL
      || strstr (body, "\"state\":\"revoked\"") == NULL
      || strstr (body, "credential_secret") != NULL) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 1994;
    goto cleanup;
  }
  first_revoke_response = g_strdup (body);
  if (!policy_count_rows (handle,
      "SELECT count(*) FROM service_domain_requests;", &requests_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credential_events "
      "WHERE event='revoked';", &revoke_events_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_events "
      "WHERE action='service.credential.revoke';", &revoke_audits_before)
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_intentions i JOIN audit_events a "
      "ON a.id=i.audit_id WHERE a.action='service.credential.revoke';",
      &revoke_outbox_before)) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 2176;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "DELETE", base_url,
      credential_path, tenant_query, access_token,
      "{\"version\":\"1\",\"request_id\":\"222222222222222222222222222\"}",
      &status, &body) != 0 || status != 200 || body == NULL
      || g_strcmp0 (body, first_revoke_response) != 0
      || strstr (body, "credential_secret") != NULL
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_domain_requests;", &requests_after)
      || requests_after != requests_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM service_credential_events "
      "WHERE event='revoked';", &revoke_events_after)
      || revoke_events_after != revoke_events_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_events "
      "WHERE action='service.credential.revoke';", &revoke_audits_after)
      || revoke_audits_after != revoke_audits_before
      || !policy_count_rows (handle,
      "SELECT count(*) FROM audit_intentions i JOIN audit_events a "
      "ON a.id=i.audit_id WHERE a.action='service.credential.revoke';",
      &revoke_outbox_after)
      || revoke_outbox_after != revoke_outbox_before) {
    wyl_service_credential_issue_result_clear (&issued);
    rc = 1995;
    goto cleanup;
  }
  wyl_service_credential_issue_result_clear (&issued);

  if (!wyl_daemon_http_seed_mfa_human_session_for_test (http.server,
      session_token, "human-principal-admin", WYL_TENANT_DEFAULT)) {
    rc = 1996;
    goto cleanup;
  }

#ifdef WYL_HAS_AUDIT
  if (wyl_service_principal_create (handle, "svc:tenant-a:observer",
      "Unrelated route observer", "human-principal-admin",
      "http-route-unrelated-principal", &principal_unrelated)
      != WYRELOG_E_OK
      || !actual_service_tokens_init (http.server, "svc:tenant-a:worker",
      "tenant-a", "http-route-disable-token", &principal_route_tokens)
      || !actual_service_tokens_init (http.server, "svc:tenant-a:observer",
      "tenant-a", "http-route-disable-unrelated-token",
      &principal_unrelated_tokens)
      || !actual_service_tokens_init (http.server, "svc:tenant-a:worker",
      "tenant-a", "http-route-revoke-token", &revoke_route_tokens)
      || !actual_service_tokens_init (http.server, "svc:tenant-a:worker",
      "tenant-a", "http-route-revoke-unrelated-token",
      &revoke_unrelated_tokens)
      || !actual_service_tokens_init (http.server, "svc:tenant-a:worker",
      "tenant-a", "http-route-rotate-token", &rotate_route_tokens)
      || !actual_service_tokens_init (http.server, "svc:tenant-a:worker",
      "tenant-a", "http-route-rotate-unrelated-token",
      &rotate_unrelated_tokens)) {
    rc = 2160;
    goto cleanup;
  }
  revoke_route_path = g_strdup_printf
        ("/service-credentials/%s",
          revoke_route_tokens.issued.credential.credential_id);
  rotate_route_path = g_strdup_printf
        ("/service-credentials/%s/rotate",
          rotate_route_tokens.issued.credential.credential_id);
  if (!actual_http_route_retirement_race (http.server, base_url,
      revoke_route_path, tenant_query, ACTUAL_ROUTE_REVOKE_CREDENTIAL,
      access_token, &revoke_route_tokens, "svc:tenant-a:worker", "tenant-a",
      &revoke_unrelated_tokens, "svc:tenant-a:worker", "tenant-a")) {
    rc = 2167;
    goto cleanup;
  }
  if (!actual_http_route_retirement_race (http.server, base_url,
      rotate_route_path, tenant_query, ACTUAL_ROUTE_ROTATE_CREDENTIAL,
      access_token, &rotate_route_tokens, "svc:tenant-a:worker", "tenant-a",
      &rotate_unrelated_tokens, "svc:tenant-a:worker", "tenant-a")) {
    rc = 2168;
    goto cleanup;
  }
  tenant_created = FALSE;
  if (wyl_policy_store_create_tenant (policy_store, "tenant-route",
      &tenant_created) != WYRELOG_E_OK || !tenant_created
      || wyl_service_principal_create (handle, "svc:tenant-route:worker",
      "Tenant route worker", "human-principal-admin",
      "http-route-tenant-principal",
      &tenant_route_principal) != WYRELOG_E_OK
      || !actual_service_tokens_init (http.server,
      "svc:tenant-route:worker", "tenant-route",
      "http-route-tenant-token", &tenant_route_tokens)) {
    rc = 2161;
    goto cleanup;
  }
  /* Tenant lifecycle routes retain their session-token authorization
   * contract; do not inherit the Bearer-only management query above. */
  tenant_route_query = g_strdup_printf ("name=tenant-route&session_token=%s&%s",
          session_token, query);
  if (!actual_http_route_retirement_race (http.server, base_url,
      "/tenants/seal", tenant_route_query, ACTUAL_ROUTE_SEAL_TENANT,
      NULL, &tenant_route_tokens, "svc:tenant-route:worker",
      "tenant-route", &principal_route_tokens, "svc:tenant-a:worker",
      "tenant-a")) {
    rc = 2162;
    goto cleanup;
  }
  static const gchar *invalid_principal_disable_bodies[] = {
    NULL,
    "",
    "{}",
    "{\"version\":\"1\",\"request_id\":"
    "\"000000000000000000000000224\",\"extra\":true}",
    "{\"version\":\"1\",\"request_id\":"
    "\"000000000000000000000000224\",\"request_id\":"
    "\"000000000000000000000000224\"}",
    "{\"version\":1,\"request_id\":" "\"000000000000000000000000224\"}",
    "{\"version\":\"2\",\"request_id\":" "\"000000000000000000000000224\"}",
    "{\"version\":\"1\",\"request_id\":" "\"abcdefghijklmnopqrstuvwxyz0\"}",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_principal_disable_bodies); i++) {
    g_clear_pointer (&body, g_free);
    if (send_raw_service_principal_bearer (session, "POST", base_url,
        "/service-principals/svc:tenant-a:worker/disable", query,
        access_token, invalid_principal_disable_bodies[i], &status,
        &body) != 0 || status != 400 || body == NULL
        || strstr (body, "invalid_service_principal_request") == NULL) {
      rc = 2164;
      goto cleanup;
    }
  }
  g_clear_pointer (&body, g_free);
  oversized_principal_disable_body = g_strnfill (1025, 'x');
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-a:worker/disable", query,
      access_token, oversized_principal_disable_body, &status,
      &body) != 0 || status != 400 || body == NULL
      || strstr (body, "invalid_service_principal_request") == NULL) {
    rc = 2166;
    goto cleanup;
  }
  if (!actual_http_route_retirement_race (http.server, base_url,
      "/service-principals/svc:tenant-a:worker/disable", query,
      ACTUAL_ROUTE_DISABLE_PRINCIPAL, access_token,
      &principal_route_tokens, "svc:tenant-a:worker", "tenant-a",
      &principal_unrelated_tokens, "svc:tenant-a:observer", "tenant-a")) {
    rc = 2163;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-route:worker/disable", query,
      access_token,
      "{\"version\":\"1\",\"request_id\":"
      "\"000000000000000000000000224\"}", &status, &body) != 0
      || status != 409 || body == NULL
      || strstr (body, "service_principal_conflict") == NULL) {
    rc = 2165;
    goto cleanup;
  }
#else
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "POST", base_url,
      "/service-principals/svc:tenant-a:worker/disable", query,
      access_token,
      "{\"version\":\"1\",\"request_id\":"
      "\"000000000000000000000000225\"}", &status, &body) != 0
      || status != 200
      || body == NULL
      || strstr (body, "\"service_principal\":") == NULL
      || strstr (body, "\"subject_id\":\"svc:tenant-a:worker\"") == NULL
      || strstr (body, "\"state\":\"disabled\"") == NULL
      || strstr (body, "\"disabled_by\":\"human-principal-admin\"")
      == NULL) {
    rc = 1982;
    goto cleanup;
  }
#endif

  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (session, "GET", base_url,
      "/service-principals", query, access_token, NULL, &status,
      &body) != 0
      || status != 200 || body == NULL
      || strstr (body, "\"state\":\"disabled\"") == NULL
      || strstr (body, "\"disabled_by\":\"human-principal-admin\"")
      == NULL) {
    rc = 1983;
    goto cleanup;
  }

#ifdef WYL_HAS_FACT_STORE
  {
    gint status_recover_rc = check_service_credential_operation_status_recover
          (http.server, session, base_url, access_token, operation_root,
            rotate_successor_id);
    if (status_recover_rc != 0) {
      rc = status_recover_rc;
      goto cleanup;
    }
  }
#endif

cleanup:
#ifdef WYL_HAS_AUDIT
  wyl_service_principal_clear (&tenant_route_principal);
  wyl_service_principal_clear (&principal_unrelated);
#endif
  g_free (publication.staged_secret);
  g_main_loop_quit (http.loop);
  if (thread != NULL)
    g_thread_join (thread);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  if (handoff_dir != NULL) {
    sp_remove_tree (operation_root);
    sp_remove_tree (publication_root);
    (void) g_rmdir (handoff_dir);
  }
  return rc;
}

/*
 * Unit 1 (#374 gap 1c): a non-SYSTEM daemon profile denies every
 * service-principal and service-credential management endpoint at the
 * profile gate (http.c service_principal_management_authorize_session), which
 * fires before any body validation, session lookup, or store row is touched.
 * A principal write and a credential read must both return 403 with the wire
 * denial token, and neither body may carry a credential secret.
 */
static gint
check_service_management_profile_denied (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = NULL;
  g_autoptr (SoupSession) session = NULL;
  g_autofree gchar *body = NULL;
  g_autofree gchar *base_url = NULL;
  gint rc = 0;
  guint status = 0;
  GThread *thread = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 2200;
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .profile = WYL_DAEMON_PROFILE_SERVICE,
  };
  context = g_main_context_new ();
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server (&opts, handle, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL) {
    g_clear_pointer (&http.loop, g_main_loop_unref);
    return 2201;
  }
  thread = g_thread_new ("daemon-http-profile-denied",
          test_http_server_thread_ctx, &http);
  session = g_object_new (SOUP_TYPE_SESSION, NULL);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL) {
    rc = 2202;
    goto cleanup;
  }
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  const gchar *guard_query =
      "guard_timestamp=1&guard_loc_class=trusted&guard_risk=0";
  /* Principal write: the profile gate fires before body validation. */
  if (send_raw_service_principal_full (session, "POST", base_url,
      "/service-principals", guard_query,
      "{\"subject_id\":\"svc:tenant-a:worker\",\"display_name\":\"x\"}",
      &status, &body) != 0 || status != 403 || body == NULL
      || strstr (body, "service_principal_denied") == NULL) {
    rc = 2203;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  /* Credential read: same profile gate, distinct wire token. */
  if (send_raw_service_principal_full (session, "GET", base_url,
      "/service-credentials/wlc_000000000000000000000000000",
      guard_query, NULL, &status, &body) != 0 || status != 403
      || body == NULL || strstr (body, "service_credential_denied") == NULL) {
    rc = 2204;
    goto cleanup;
  }
cleanup:
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return rc;
}

static wyrelog_error_t
count_service_principals_cb (const wyl_policy_service_principal_info_t *info,
    gpointer user_data)
{
  (void) info;
  (*(guint *) user_data)++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
count_service_credentials_cb (const wyl_policy_service_credential_info_t *info,
    gpointer user_data)
{
  (void) info;
  (*(guint *) user_data)++;
  return WYRELOG_E_OK;
}

/*
 * Shared bring-up for the SYSTEM-profile service-management denial units.
 * Mirrors check_service_principal_management_contract's encrypted production
 * store, threaded server with a main-loop-ready barrier, publication override,
 * and a seeded human SYSTEM session scoped to tenant-a.  The three flags let
 * each unit choose which denial arm to exercise: session_active toggles the
 * policy-store session-active fact (its absence makes wyl_decide DENY), and
 * arm_principal / arm_credential toggle the armed state of the two management
 * permissions.  On any failure the caller must still call
 * service_denial_env_clear to tear the partially-built environment down.
 */
typedef struct
{
  ServiceCredentialStoreFixture credential_store;
  WylHandle *handle;
  gchar *handoff_dir;
  gchar *fact_root;
  gchar *operation_root;
  gchar *publication_root;
  SpPublication publication;
  GMainContext *context;
  TestHttpServer http;
  GThread *thread;
  MainLoopReadyBarrier barrier;
  SoupSession *session;
  gchar *base_url;
  gchar *query;
  gchar *tenant_query;
  gchar *access_token;
  gchar session_token[WYL_ID_STRING_BUF];
} ServiceDenialEnv;

static gint
service_denial_env_init (ServiceDenialEnv *env, gboolean session_active,
    gboolean arm_principal, gboolean arm_credential)
{
  g_mutex_init (&env->barrier.mutex);
  g_cond_init (&env->barrier.changed);
  env->session = g_object_new (SOUP_TYPE_SESSION, NULL);
  if (env->session == NULL)
    return 2100;
  if (!service_credential_store_fixture_init (&env->credential_store))
    return 2101;
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = env->credential_store.policy_path,
    .policy_keyprovider_path = env->credential_store.key_spec,
    .audit_store_path = env->credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&handle_options, &env->handle)
      != WYRELOG_E_OK)
    return 2102;
  wyl_id_t session_id_value = WYL_ID_NIL;
  if (wyl_id_new (&session_id_value) != WYRELOG_E_OK
      || wyl_id_format (&session_id_value, env->session_token,
      sizeof env->session_token) != WYRELOG_E_OK)
    return 2103;
  g_autofree gchar *created_handoff_dir = g_dir_make_tmp
        ("wyl-daemon-http-denial-XXXXXX", NULL);
  if (created_handoff_dir == NULL)
    return 2104;
#ifdef G_OS_WIN32
  env->handoff_dir = g_steal_pointer (&created_handoff_dir);
#else
  /* The POSIX graph resolver rejects symlink path components.  macOS commonly
   * spells TMPDIR through /var -> /private/var, so retain the owned directory
   * by its resolved path before deriving the fact root. */
  env->handoff_dir = realpath (created_handoff_dir, NULL);
  if (env->handoff_dir == NULL) {
    (void) g_rmdir (created_handoff_dir);
    return 2104;
  }
#endif
  env->operation_root = service_credential_operation_root_for_test
        (env->handoff_dir, "denial-operations");
  env->fact_root = g_build_filename (env->handoff_dir, "facts", NULL);
  env->publication_root = g_build_filename (env->handoff_dir, "publication",
          NULL);
  if (g_mkdir_with_parents (env->publication_root, 0700) != 0
      || g_mkdir_with_parents (env->fact_root, 0700) != 0)
    return 2105;

  env->context = g_main_context_new ();
  g_main_context_push_thread_default (env->context);
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .fact_root = env->fact_root,
    .operation_root = env->operation_root,
    .credential_publication_root = env->publication_root,
  };
  g_autoptr (GError) error = NULL;
  env->http.loop = g_main_loop_new (env->context, FALSE);
  env->http.server = wyl_daemon_start_http_server (&opts, env->handle, &error);
  g_main_context_pop_thread_default (env->context);
  if (env->http.server == NULL)
    return 2106;
  env->thread = g_thread_new ("daemon-http-denial",
          test_http_server_thread_ctx, &env->http);
  g_main_context_invoke_full (env->context, G_PRIORITY_DEFAULT,
      mark_main_loop_ready, &env->barrier, NULL);
  g_mutex_lock (&env->barrier.mutex);
  if (!env->barrier.ready)
    g_cond_wait_until (&env->barrier.changed, &env->barrier.mutex,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC);
  gboolean ready = env->barrier.ready;
  g_mutex_unlock (&env->barrier.mutex);
  if (!ready)
    return 2107;

  GSList *uris = soup_server_get_uris (env->http.server);
  if (uris == NULL)
    return 2108;
  env->base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (env->base_url == NULL)
    return 2109;

  wyl_daemon_http_set_publication_override_for_test (env->http.server,
      &sp_publication_vtable, &env->publication);

  if (!seed_management_human_access_token (env->http.server,
      env->session_token, "human-principal-admin", &env->access_token))
    return 2110;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env->handle);
  gboolean tenant_created = FALSE;
  if (wyl_policy_store_create_tenant (store, "tenant-a", &tenant_created)
      != WYRELOG_E_OK || !tenant_created)
    return 2111;
  if (wyl_policy_store_set_principal_state (store, "human-principal-admin",
      "authenticated") != WYRELOG_E_OK)
    return 2112;
  if (wyl_policy_store_grant_direct_permission (store, "human-principal-admin",
      "wr.service_principal.manage", env->session_token) != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.service_credential.manage",
      env->session_token) != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.tenant.manage", "tenant-a")
      != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store, "human-principal-admin",
      "wr.tenant.manage", "tenant-a", "armed") != WYRELOG_E_OK)
    return 2113;
  if (arm_principal
      && wyl_policy_store_set_permission_state (store, "human-principal-admin",
      "wr.service_principal.manage", env->session_token, "armed")
      != WYRELOG_E_OK)
    return 2114;
  if (arm_credential
      && wyl_policy_store_set_permission_state (store, "human-principal-admin",
      "wr.service_credential.manage", env->session_token, "armed")
      != WYRELOG_E_OK)
    return 2115;
  if (session_active
      && (wyl_policy_store_set_session_state (store, env->session_token,
      "active") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, "tenant-a", "active")
      != WYRELOG_E_OK))
    return 2116;
  if (wyl_handle_reload_engine_pair (env->handle) != WYRELOG_E_OK)
    return 2117;
  env->query = g_strdup
        ("guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");
  env->tenant_query = g_strdup ("tenant=tenant-a&guard_timestamp=1&"
          "guard_loc_class=trusted&guard_risk=0");
  return 0;
}

static void
service_denial_env_stop_runtime (ServiceDenialEnv *env)
{
  if (env->http.loop != NULL)
    g_main_loop_quit (env->http.loop);
  if (env->thread != NULL) {
    g_thread_join (env->thread);
    env->thread = NULL;
  }
  g_cond_clear (&env->barrier.changed);
  g_mutex_clear (&env->barrier.mutex);
  if (env->http.server != NULL) {
    soup_server_disconnect (env->http.server);
    g_clear_object (&env->http.server);
  }
  g_clear_pointer (&env->http.loop, g_main_loop_unref);
  g_clear_pointer (&env->context, g_main_context_unref);
  g_clear_object (&env->session);
  g_clear_object (&env->handle);
  g_clear_pointer (&env->base_url, g_free);
  g_clear_pointer (&env->access_token, g_free);
  memset (env->session_token, 0, sizeof env->session_token);
}

static gint
service_denial_env_restart (ServiceDenialEnv *env)
{
  service_denial_env_stop_runtime (env);
  g_mutex_init (&env->barrier.mutex);
  g_cond_init (&env->barrier.changed);
  env->session = g_object_new (SOUP_TYPE_SESSION, NULL);
  WylHandleOpenOptions handle_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = env->credential_store.policy_path,
    .policy_keyprovider_path = env->credential_store.key_spec,
    .audit_store_path = env->credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (env->session == NULL
      || wyl_handle_open_with_options (&handle_options, &env->handle)
      != WYRELOG_E_OK)
    return 2600;
  wyl_id_t session_id = WYL_ID_NIL;
  if (wyl_id_new (&session_id) != WYRELOG_E_OK
      || wyl_id_format (&session_id, env->session_token,
      sizeof env->session_token) != WYRELOG_E_OK)
    return 2601;
  env->context = g_main_context_new ();
  g_main_context_push_thread_default (env->context);
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .fact_root = env->fact_root,
    .operation_root = env->operation_root,
    .credential_publication_root = env->publication_root,
  };
  g_autoptr (GError) error = NULL;
  env->http.loop = g_main_loop_new (env->context, FALSE);
  env->http.server = wyl_daemon_start_http_server (&opts, env->handle, &error);
  g_main_context_pop_thread_default (env->context);
  if (env->http.server == NULL)
    return 2602;
  env->thread = g_thread_new ("daemon-http-retirement-restart",
          test_http_server_thread_ctx, &env->http);
  g_main_context_invoke_full (env->context, G_PRIORITY_DEFAULT,
      mark_main_loop_ready, &env->barrier, NULL);
  g_mutex_lock (&env->barrier.mutex);
  if (!env->barrier.ready)
    g_cond_wait_until (&env->barrier.changed, &env->barrier.mutex,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC);
  gboolean ready = env->barrier.ready;
  g_mutex_unlock (&env->barrier.mutex);
  if (!ready)
    return 2603;
  GSList *uris = soup_server_get_uris (env->http.server);
  if (uris == NULL)
    return 2604;
  env->base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  wyl_daemon_http_set_publication_override_for_test (env->http.server,
      &sp_publication_vtable, &env->publication);
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (env->http.server);
  if (env->base_url == NULL
      || !seed_management_human_access_token (env->http.server,
      env->session_token, "human-principal-admin", &env->access_token))
    return 2605;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env->handle);
  if (wyl_policy_store_set_principal_state (store, "human-principal-admin",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, env->session_token,
      "active") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.service_principal.manage",
      env->session_token) != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store,
      "human-principal-admin", "wr.service_principal.manage",
      env->session_token, "armed") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.service_credential.manage",
      env->session_token) != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store,
      "human-principal-admin", "wr.service_credential.manage",
      env->session_token, "armed") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.tenant.manage", WYL_TENANT_DEFAULT)
      != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store,
      "human-principal-admin", "wr.tenant.manage", WYL_TENANT_DEFAULT,
      "armed") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env->handle) != WYRELOG_E_OK)
    return 2606;
  return 0;
}

static void
service_denial_env_clear (ServiceDenialEnv *env)
{
  service_denial_env_stop_runtime (env);
  g_free (env->publication.staged_secret);
  g_free (env->query);
  g_free (env->tenant_query);
  if (env->handoff_dir != NULL) {
    sp_remove_tree (env->fact_root);
    sp_remove_tree (env->operation_root);
    sp_remove_tree (env->publication_root);
    (void) g_rmdir (env->handoff_dir);
  }
  g_free (env->operation_root);
  g_free (env->fact_root);
  g_free (env->publication_root);
  g_free (env->handoff_dir);
  service_credential_store_fixture_clear (&env->credential_store);
}

static gint
send_raw_service_principal_bearer_full (SoupSession *session,
    const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *access_token, const gchar *body, guint *out_status,
    gchar **out_body, gchar **out_request_id)
{
  if (access_token == NULL)
    return 164;
  if (out_status == NULL || out_body == NULL)
    return 120;
  *out_status = 0;
  *out_body = NULL;
  if (out_request_id != NULL)
    *out_request_id = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 121;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  soup_message_headers_replace (soup_message_get_request_headers (msg),
      "Authorization", authorization);
  if (body != NULL) {
    g_autoptr (GBytes) request_bytes = g_bytes_new_static (body, strlen (body));
    soup_message_set_request_body_from_bytes (msg, "application/json",
        request_bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 122;
  gint rc = check_response_request_id_header (msg, 178);
  if (rc != 0)
    return rc;
  if (out_request_id != NULL) {
    const gchar *request_id = soup_message_headers_get_one
          (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
    *out_request_id = g_strdup (request_id);
  }
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
send_raw_service_principal_bearer (SoupSession *session, const gchar *method,
    const gchar *base_url, const gchar *path, const gchar *query,
    const gchar *access_token, const gchar *body, guint *out_status,
    gchar **out_body)
{
  return send_raw_service_principal_bearer_full (session, method, base_url,
             path, query, access_token, body, out_status, out_body, NULL);
}

#ifdef WYL_HAS_FACT_STORE
typedef enum
{
  POLICY_WRITE_OWNER_FAULT_FINALIZE = 0,
  POLICY_WRITE_OWNER_FAULT_ACQUIRE_AFTER_STORE,
  POLICY_WRITE_OWNER_FAULT_MODE_COUNT,
} PolicyWriteOwnerFaultMode;

typedef struct
{
  guint owner;
  const gchar *name;
  guint resources;
  guint acquire_status;
  const gchar *acquire_code;
} PolicyWriteOwnerFaultCase;

typedef struct
{
  const gchar *graph_id;
  gboolean found;
} PolicyWriteOwnerGraphProbe;

static wyrelog_error_t
policy_write_owner_graph_probe_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  PolicyWriteOwnerGraphProbe *probe = user_data;
  if (g_strcmp0 (info->graph_id, probe->graph_id) == 0)
    probe->found = TRUE;
  return WYRELOG_E_OK;
}

static const PolicyWriteOwnerFaultCase policy_write_owner_fault_cases[] = {
  {0, "key_rotation", WYL_DAEMON_POLICY_WRITE_RESOURCE_MAINTENANCE
   | WYL_DAEMON_POLICY_WRITE_RESOURCE_CONTEXT
   | WYL_DAEMON_POLICY_WRITE_RESOURCE_REGISTRY, 0, "non_http"},
  {1, "test_configure", 0, 0, "non_http"},
  {2, "test_policy_write", 0, 0, "non_http"},
  {3, "tenant", 1, 500, "tenant_mutation_failed"},
  {4, "graph_create", 0, 500, "graph_mutation_failed"},
  {5, "graph_seal", 0, 500, "graph_mutation_failed"},
  {6, "schema_register", 0, 500, "schema_register_failed"},
  {7, "fact_forget", WYL_DAEMON_POLICY_WRITE_RESOURCE_FACT_STORE,
   500, "fact_forget_failed"},
  {8, "fact_publication", WYL_DAEMON_POLICY_WRITE_RESOURCE_FACT_STORE,
   500, "fact_append_failed"},
  {9, "direct_permission", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE,
   500, "policy_mutation_failed"},
  {10, "permission_transition", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE,
   500, "policy_mutation_failed"},
  {11, "role_membership", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE,
   500, "policy_mutation_failed"},
  {12, "operation_reconcile",
   WYL_DAEMON_POLICY_WRITE_RESOURCE_TRANSACTION, 500,
   "service_credential_operation_reconcile_failed"},
  {13, "operation_recover",
   WYL_DAEMON_POLICY_WRITE_RESOURCE_OPERATION_STORAGE
   | WYL_DAEMON_POLICY_WRITE_RESOURCE_OPERATION_LOCK, 500,
   "service_credential_operation_recover_failed"},
  {14, "mfa_confirm", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE,
   500, "mfa_enroll_failed"},
  {15, "self_arm", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE,
   500, "service_authority_failed"},
};

static wyrelog_error_t
policy_write_owner_fault_prepare_authority (ServiceDenialEnv *env)
{
  static const gchar *const permissions[] = {
    "wr.tenant.manage",
    "wr.graph.manage",
    "wr.schema.manage",
    "wr.fact.write",
    "wr.policy.write",
    "wr.policy.grant_role",
  };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env->handle);
  for (gsize i = 0; i < G_N_ELEMENTS (permissions); i++) {
    wyrelog_error_t rc = wyl_policy_store_grant_direct_permission (store,
            "human-principal-admin", permissions[i], WYL_TENANT_DEFAULT);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_policy_store_set_permission_state (store,
            "human-principal-admin", permissions[i], WYL_TENANT_DEFAULT, "armed");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  if (wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT, "active")
      != WYRELOG_E_OK
      || wyl_policy_store_set_principal_state (store, "owner-mfa-target",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_upsert_permission (store, "owner.policy.read",
      "owner policy read", "basic") != WYRELOG_E_OK
      || wyl_policy_store_upsert_role (store, "owner.reader", "owner reader")
      != WYRELOG_E_OK
      || wyl_policy_store_grant_role_membership (store,
      "human-principal-admin", "wr.system_admin", WYL_TENANT_DEFAULT)
      != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;
  return wyl_handle_reload_engine_pair (env->handle);
}

static gint
policy_write_owner_fault_send_expect_ok (ServiceDenialEnv *env,
    const gchar *method, const gchar *path, const gchar *query,
    const gchar *body)
{
  guint status = 0;
  g_autofree gchar *response = NULL;
  return send_raw_service_principal_bearer (env->session, method,
             env->base_url, path, query, env->access_token, body, &status,
             &response) == 0 && status == 200 ? 0 : 1;
}

static gint
policy_write_owner_fault_prepare_facts (ServiceDenialEnv *env,
    gboolean schema, gboolean append)
{
  const gchar *guard = "guard_timestamp=1&guard_loc_class=trusted&guard_risk=0";
  g_autofree gchar *graph_query = g_strdup_printf
        ("tenant=%s&graph=owner-fault&%s", WYL_TENANT_DEFAULT, guard);
  if (policy_write_owner_fault_send_expect_ok (env, "POST", "/graphs/create",
      graph_query, NULL) != 0)
    return 1;
  if (!schema)
    return 0;
  g_autofree gchar *schema_query = g_strdup_printf
        ("tenant=%s&graph=owner-fault&namespace=owner&relation=rows&"
          "schema_version=1&%s", WYL_TENANT_DEFAULT, guard);
  const gchar *schema_body =
      "column_name\tcolumn_type\tnullable\tvisible\n"
      "row_id\tsymbol\tfalse\ttrue\n" "amount\tint64\tfalse\ttrue\n";
  if (policy_write_owner_fault_send_expect_ok (env, "POST",
      "/facts/schema/register", schema_query, schema_body) != 0)
    return 2;
  if (!append)
    return 0;
  g_autofree gchar *append_query = g_strdup_printf
        ("tenant=%s&namespace=owner&schema_version=1&batch_id=owner-batch&"
          "idempotency_key=owner-key&%s", WYL_TENANT_DEFAULT, guard);
  return policy_write_owner_fault_send_expect_ok (env, "POST",
             "/facts/__wr_default/owner-fault/rows:append", append_query,
             "row_id\tamount\nrow-1\t42\n") == 0 ? 0 : 3;
}

static gint
policy_write_owner_fault_prepare_mfa (ServiceDenialEnv *env,
    gchar **out_challenge, gchar **out_confirm_body)
{
  const gchar *guard = "tenant=__wr_default&guard_timestamp=1&"
      "guard_loc_class=trusted&guard_risk=0";
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_service_principal_bearer (env->session, "POST", env->base_url,
      "/auth/mfa/enroll/start", guard, env->access_token,
      "{\"subject\":\"owner-mfa-target\"}", &status, &body) != 0
      || status != 200)
    return 1;
  g_autofree gchar *challenge = extract_json_string (body, "challenge");
  g_autofree gchar *base32 = extract_json_string (body, "secret_base32");
  guint8 *seed = NULL;
  gsize seed_len = 0;
  guint code = 0;
  if (challenge == NULL || base32 == NULL
      || wyl_totp_base32_decode (base32, &seed, &seed_len, NULL)
      != WYRELOG_E_OK || seed_len != WYL_TOTP_SEED_BYTES
      || wyl_totp_code_at_step (seed, seed_len,
      (guint64) (g_get_real_time () / G_USEC_PER_SEC
      / WYL_TOTP_STEP_SECONDS), &code, NULL) != WYRELOG_E_OK) {
    if (seed != NULL) {
      sodium_memzero (seed, seed_len);
      g_free (seed);
    }
    return 2;
  }
  *out_challenge = g_steal_pointer (&challenge);
  *out_confirm_body = g_strdup_printf
        ("{\"challenge\":\"%s\",\"code\":\"%06u\"}", *out_challenge, code);
  sodium_memzero (seed, seed_len);
  g_free (seed);
  return *out_confirm_body != NULL ? 0 : 3;
}

static gint
policy_write_owner_fault_invoke_http (ServiceDenialEnv *env,
    const PolicyWriteOwnerFaultCase *test_case, PolicyWriteOwnerFaultMode mode,
    guint *out_terminal_before)
{
  const gchar *guard = "guard_timestamp=1&guard_loc_class=trusted&guard_risk=0";
  const gchar *method = "POST";
  const gchar *path = NULL;
  const gchar *body = NULL;
  g_autofree gchar *query = NULL;
  g_autofree gchar *owned_body = NULL;
  g_autofree gchar *challenge = NULL;
  gchar request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };

  switch (test_case->owner) {
    case 3:
      path = "/tenants/create";
      query = g_strdup_printf ("name=owner-fault-tenant&tenant=%s&%s",
              WYL_TENANT_DEFAULT, guard);
      break;
    case 4:
    {
      gboolean tenant_active = FALSE;
      PolicyWriteOwnerGraphProbe probe = {.graph_id = "owner-fault" };
      wyl_policy_store_t *store = wyl_handle_get_policy_store (env->handle);
      if (wyl_policy_store_tenant_is_active (store, WYL_TENANT_DEFAULT,
          &tenant_active) != WYRELOG_E_OK || !tenant_active) {
        g_printerr ("WYRELOG_TEST_DIAG owner_fault graph_precondition="
            "tenant_inactive\n");
        return 10;
      }
      if (wyl_policy_store_foreach_fact_graph (store, WYL_TENANT_DEFAULT,
          policy_write_owner_graph_probe_cb, &probe) != WYRELOG_E_OK
          || probe.found) {
        g_printerr ("WYRELOG_TEST_DIAG owner_fault graph_precondition="
            "registry_present\n");
        return 11;
      }
      WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
      WylFactGraphLocator locator = { 0 };
      WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
      wyrelog_error_t directory_rc = wyl_fact_graph_resolver_open
            (env->fact_root, &resolver);
      if (directory_rc == WYRELOG_E_OK)
        directory_rc = wyl_fact_graph_locator_init (&locator,
                WYL_TENANT_DEFAULT, "owner-fault");
      if (directory_rc == WYRELOG_E_OK)
        directory_rc = wyl_fact_graph_resolver_open_directory (&resolver,
                &locator, FALSE, &directory);
      wyl_fact_graph_directory_clear (&directory);
      wyl_fact_graph_locator_clear (&locator);
      wyl_fact_graph_resolver_clear (&resolver);
      if (directory_rc == WYRELOG_E_OK) {
        g_printerr ("WYRELOG_TEST_DIAG owner_fault graph_precondition="
            "storage_present\n");
        return 12;
      }
      if (directory_rc != WYRELOG_E_NOT_FOUND) {
        g_printerr ("WYRELOG_TEST_DIAG owner_fault graph_precondition="
            "storage_error rc=%d\n", directory_rc);
        return 13;
      }
    }
      path = "/graphs/create";
      query = g_strdup_printf ("tenant=%s&graph=owner-fault&%s",
              WYL_TENANT_DEFAULT, guard);
      break;
    case 5:
      if (policy_write_owner_fault_prepare_facts (env, FALSE, FALSE) != 0)
        return 1;
      path = "/graphs/seal";
      query = g_strdup_printf ("tenant=%s&graph=owner-fault&%s",
              WYL_TENANT_DEFAULT, guard);
      break;
    case 6:
      if (policy_write_owner_fault_prepare_facts (env, FALSE, FALSE) != 0)
        return 2;
      path = "/facts/schema/register";
      query = g_strdup_printf
            ("tenant=%s&graph=owner-fault&namespace=owner&relation=rows&"
              "schema_version=1&%s", WYL_TENANT_DEFAULT, guard);
      body = "column_name\tcolumn_type\tnullable\tvisible\n"
          "row_id\tsymbol\tfalse\ttrue\n" "amount\tint64\tfalse\ttrue\n";
      break;
    case 7:
      if (policy_write_owner_fault_prepare_facts (env, TRUE, TRUE) != 0)
        return 3;
      method = "DELETE";
      path = "/facts/__wr_default/owner-fault/rows:forget";
      query = g_strdup_printf
            ("tenant=%s&namespace=owner&schema_version=1&%s",
              WYL_TENANT_DEFAULT, guard);
      body = "{\"batch_id\":\"owner-batch\",\"operator\":\"owner-admin\","
          "\"reason\":\"owner-cleanup-test\"}";
      break;
    case 8:
      if (policy_write_owner_fault_prepare_facts (env, TRUE, FALSE) != 0)
        return 4;
      path = "/facts/__wr_default/owner-fault/rows:append";
      query = g_strdup_printf
            ("tenant=%s&namespace=owner&schema_version=1&batch_id=owner-batch&"
              "idempotency_key=owner-key&%s", WYL_TENANT_DEFAULT, guard);
      body = "row_id\tamount\nrow-1\t42\n";
      break;
    case 9:
      path = "/policy/permissions/grant";
      query = g_strdup_printf
            ("subject=owner-permission-target&perm=owner.policy.read&scope=%s&"
              "tenant=%s&%s", WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT, guard);
      break;
    case 10:
      path = "/policy/permissions/transition";
      query = g_strdup_printf
            ("subject=owner-transition-target&perm=owner.policy.read&scope=%s&"
              "event=grant&tenant=%s&%s", WYL_TENANT_DEFAULT,
              WYL_TENANT_DEFAULT, guard);
      break;
    case 11:
      path = "/policy/roles/grant";
      query = g_strdup_printf
            ("subject=owner-role-target&role=owner.reader&scope=%s&tenant=%s&%s",
              WYL_TENANT_DEFAULT, WYL_TENANT_DEFAULT, guard);
      break;
    case 12:
      if (prepare_service_credential_subject (env->handle,
          "svc:owner:reconcile", NULL) != WYRELOG_E_OK
          || wyl_request_id_new (request_id, sizeof request_id)
          != WYRELOG_E_OK)
        return 5;
      path = "/service-credential-operations/reconcile";
      query = g_strdup_printf ("tenant=tenant-a&%s", guard);
      owned_body = g_strdup_printf
            ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
              "\"target\":{\"subject\":\"svc:owner:reconcile\","
              "\"tenant\":\"tenant-a\"}}", request_id);
      body = owned_body;
      break;
    case 13:
      if (prepare_service_credential_subject (env->handle,
          "svc:owner:recover", NULL) != WYRELOG_E_OK
          || wyl_request_id_new (request_id, sizeof request_id)
          != WYRELOG_E_OK
          || seed_prepared_operation (env->operation_root, request_id,
          WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:owner:recover",
          "tenant-a", NULL) != 0)
        return 6;
      path = "/service-credential-operations/recover";
      query = g_strdup_printf ("tenant=tenant-a&%s", guard);
      owned_body = g_strdup_printf
            ("{\"version\":\"1\",\"request_id\":\"%s\"}", request_id);
      body = owned_body;
      break;
    case 14:
      if (policy_write_owner_fault_prepare_mfa (env, &challenge,
          &owned_body) != 0)
        return 7;
      path = "/auth/mfa/enroll/confirm";
      query = g_strdup_printf ("tenant=%s&%s", WYL_TENANT_DEFAULT, guard);
      body = owned_body;
      break;
    case 15:
      path = "/service-management-authority/arm";
      query = g_strdup (guard);
      body = "{}";
      break;
    default:
      return 8;
  }

  guint status = 0;
  g_autofree gchar *response = NULL;
  *out_terminal_before =
      wyl_daemon_http_policy_write_terminal_entries_for_test (env->http.server);
  if (mode == POLICY_WRITE_OWNER_FAULT_FINALIZE)
    wyl_daemon_http_fail_next_policy_write_finalize_for_test
      (env->http.server,
        WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION);
  else
    wyl_daemon_http_fail_next_policy_write_acquire_for_test (env->http.server,
        WYL_DAEMON_POLICY_WRITE_ACQUIRE_FAULT_AFTER_STORE);
  g_autofree gchar *expected_response =
      mode ==
      POLICY_WRITE_OWNER_FAULT_FINALIZE ?
      g_strdup ("{\"error\":\"policy_write_cleanup_failed\"}")
      : g_strdup_printf ("{\"error\":\"%s\"}", test_case->acquire_code);
  if (send_raw_service_principal_bearer (env->session, method, env->base_url,
      path, query, env->access_token, body, &status, &response) != 0
      || status != (mode == POLICY_WRITE_OWNER_FAULT_FINALIZE ? 500 :
      test_case->acquire_status)
      || g_strcmp0 (response, expected_response) != 0)
    return 9;
  return 0;
}

static gint
check_policy_write_all_owner_faults (void)
{
  G_STATIC_ASSERT (G_N_ELEMENTS (policy_write_owner_fault_cases) == 16);
  G_STATIC_ASSERT (POLICY_WRITE_OWNER_FAULT_MODE_COUNT == 2);
  for (guint mode = 0; mode < POLICY_WRITE_OWNER_FAULT_MODE_COUNT; mode++) {
    for (gsize i = 0; i < G_N_ELEMENTS (policy_write_owner_fault_cases); i++) {
      const PolicyWriteOwnerFaultCase *test_case =
          &policy_write_owner_fault_cases[i];
      if (test_case->owner != i || test_case->name == NULL
          || test_case->acquire_code == NULL)
        return 2999;
      ServiceDenialEnv env = { 0 };
      gint error_base = 3000 + (gint) mode * 400 + (gint) i * 20;
      gint result = service_denial_env_init (&env, TRUE,
              test_case->owner != 15, test_case->owner != 15);
      if (result != 0) {
        service_denial_env_clear (&env);
        return error_base;
      }
      wyl_daemon_http_suspend_service_auth_maintenance_for_test
        (env.http.server);
      if (policy_write_owner_fault_prepare_authority (&env) != WYRELOG_E_OK) {
        service_denial_env_clear (&env);
        return error_base + 1;
      }
      guint before = wyl_daemon_http_policy_write_terminal_entries_for_test
            (env.http.server);
      wyrelog_error_t non_http_rc = WYRELOG_E_OK;
      if (test_case->owner <= 2) {
        if (mode == POLICY_WRITE_OWNER_FAULT_FINALIZE)
          wyl_daemon_http_fail_next_policy_write_finalize_for_test
            (env.http.server,
              WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION);
        else
          wyl_daemon_http_fail_next_policy_write_acquire_for_test
            (env.http.server,
              WYL_DAEMON_POLICY_WRITE_ACQUIRE_FAULT_AFTER_STORE);
        if (test_case->owner == 0)
          non_http_rc = wyl_daemon_http_rotate_access_token_key_for_test
                (env.http.server);
        else if (test_case->owner == 1)
          non_http_rc = wyl_daemon_http_configure_tenant_for_test
                (env.http.server, "owner-configure-tenant", TRUE, FALSE);
        else
          non_http_rc = wyl_daemon_http_policy_write_for_test
                (env.http.server, NULL, NULL);
      } else {
        result = policy_write_owner_fault_invoke_http (&env, test_case,
                (PolicyWriteOwnerFaultMode) mode, &before);
        if (result != 0) {
          g_printerr ("WYRELOG_TEST_DIAG owner_fault invoke mode=%u owner=%u "
              "name=%s stage=%d\n", mode, test_case->owner, test_case->name,
              result);
          service_denial_env_clear (&env);
          return error_base + 2;
        }
      }

      guint after = wyl_daemon_http_policy_write_terminal_entries_for_test
            (env.http.server);
      gboolean acquire_mode =
          mode == POLICY_WRITE_OWNER_FAULT_ACQUIRE_AFTER_STORE;
      WylDaemonPolicyWriteFinalizeSnapshot snapshot = { 0 };
      gboolean snapshot_ok =
          wyl_daemon_http_policy_write_finalize_snapshot_for_test
            (env.http.server, &snapshot)
          && policy_write_fault_snapshot_is_clean (&snapshot,
              acquire_mode ? test_case->acquire_status :
              test_case->owner <= 2 ? 0 : 200,
              acquire_mode ? test_case->acquire_code :
              test_case->owner <= 2 ? "non_http" : "success", test_case->owner,
              test_case->name, acquire_mode ? 0 : test_case->resources,
              acquire_mode ? 0 : 1,
              acquire_mode ? WYRELOG_E_OK : WYRELOG_E_INTERNAL,
              acquire_mode ? 1 : 0);
      if ((test_case->owner <= 2
          && (non_http_rc != WYRELOG_E_INTERNAL
          || (!acquire_mode && (!snapshot.primary_rc_recorded
          || snapshot.primary_rc != WYRELOG_E_OK))))
          || (acquire_mode && (!snapshot.primary_rc_recorded
          || snapshot.primary_rc != WYRELOG_E_INTERNAL))
          || after != before + 1 || !snapshot_ok) {
        g_printerr ("WYRELOG_TEST_DIAG owner_fault snapshot mode=%u owner=%u "
            "name=%s non_http_rc=%d terminal=%u/%u observed=%u expected=%u "
            "snapshot_owner=%u snapshot_name=%s primary=%d/%d cleanup=%d "
            "hits=%u txn=%d rank=%u pins=%u/%u pre=%u/%u/%zu\n", mode,
            test_case->owner, test_case->name, non_http_rc, before, after,
            snapshot.observed_cleanup_resources,
            acquire_mode ? 0 : test_case->resources, snapshot.owner,
            snapshot.owner_name, snapshot.primary_rc,
            snapshot.primary_rc_recorded, snapshot.cleanup_rc,
            snapshot.acquire_fault_hits,
            snapshot.post_finalize_transaction_active,
            snapshot.post_finalize_rank_mask,
            snapshot.post_finalize_total_pins,
            snapshot.post_finalize_thread_pins, snapshot.pre_finalize_status,
            snapshot.pre_finalize_header_count,
            snapshot.pre_finalize_body_length);
        service_denial_env_clear (&env);
        return error_base + 3;
      }
      WylServiceAuthAuthoritySnapshot authority = { 0 };
      wyl_daemon_http_service_authority_snapshot_for_test (env.http.server,
          &authority);
      WylServiceAuthUnavailableReason reason =
          WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
      wyrelog_error_t available =
          wyl_service_auth_authority_validate_available
            (wyl_handle_get_service_auth_authority (env.handle), env.handle,
              &reason);
      wyrelog_error_t subsequent = wyl_daemon_http_policy_write_for_test
            (env.http.server, NULL, NULL);
      guint subsequent_after =
          wyl_daemon_http_policy_write_terminal_entries_for_test
            (env.http.server);
      if (authority.writer_active || authority.active_readers != 0
          || authority.waiting_readers != 0 || authority.waiting_writers != 0
          || (acquire_mode && (available != WYRELOG_E_OK
          || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE
          || subsequent != WYRELOG_E_OK
          || subsequent_after != after + 1))
          || (!acquire_mode && (available != WYRELOG_E_BUSY
          || reason !=
          WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT
          || subsequent != WYRELOG_E_BUSY
          || subsequent_after != after))) {
        service_denial_env_clear (&env);
        return error_base + 4;
      }
      memset (&authority, 0, sizeof authority);
      wyl_daemon_http_service_authority_snapshot_for_test (env.http.server,
          &authority);
      if (authority.writer_active || authority.active_readers != 0
          || authority.waiting_readers != 0 || authority.waiting_writers != 0) {
        service_denial_env_clear (&env);
        return error_base + 5;
      }
      service_denial_env_clear (&env);
    }
  }
  return 0;
}
#endif

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylDaemonRetirementOperation expected_operation;
  const gchar *expected_request_id;
  gboolean entered;
  gboolean released;
  gboolean exited;
  gboolean mismatch;
  gchar *captured_decision_request_id;
  gchar *captured_response;
} RetirementResponseBarrier;

typedef struct
{
  const gchar *base_url;
  const gchar *method;
  const gchar *path;
  const gchar *query;
  const gchar *access_token;
  const gchar *body;
  GMutex mutex;
  GCond changed;
  gboolean close_now;
  gint rc;
  gchar *captured_decision_request_id;
  gchar *captured_response;
} DroppedManagementRequest;

static void
retirement_response_checkpoint (WylDaemonRetirementOperation operation,
    const gchar *request_id, const gchar *decision_request_id,
    const gchar *response_json, gpointer data)
{
  RetirementResponseBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  barrier->mismatch = operation != barrier->expected_operation
      || g_strcmp0 (request_id, barrier->expected_request_id) != 0;
  barrier->captured_decision_request_id = g_strdup (decision_request_id);
  barrier->captured_response = g_strdup (response_json);
  barrier->entered = TRUE;
  g_cond_broadcast (&barrier->changed);
  while (!barrier->released)
    g_cond_wait (&barrier->changed, &barrier->mutex);
  barrier->exited = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
}

static gpointer
dropped_management_request_thread (gpointer data)
{
  DroppedManagementRequest *request = data;
  g_autoptr (GUri) uri = g_uri_parse (request->base_url, G_URI_FLAGS_NONE,
          NULL);
  g_autoptr (GSocketClient) client = g_socket_client_new ();
  g_autoptr (GError) error = NULL;
  g_autoptr (GSocketConnection) connection = uri != NULL
      ? g_socket_client_connect_to_host (client, g_uri_get_host (uri),
          g_uri_get_port (uri), NULL, &error) : NULL;
  if (connection == NULL) {
    request->rc = 1;
    return NULL;
  }
  g_autofree gchar *target = request->query == NULL ? g_strdup (request->path)
      : g_strdup_printf ("%s?%s", request->path, request->query);
  g_autofree gchar *wire = g_strdup_printf
        ("%s %s HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: Bearer %s\r\n"
          "Content-Type: application/json\r\nConnection: close\r\n"
          "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s", request->method,
          target, g_uri_get_host (uri), g_uri_get_port (uri),
          request->access_token, strlen (request->body), request->body);
  gsize written = 0;
  GOutputStream *output = g_io_stream_get_output_stream
        (G_IO_STREAM (connection));
  if (!g_output_stream_write_all (output, wire, strlen (wire), &written, NULL,
      &error) || written != strlen (wire)
      || !g_output_stream_flush (output, NULL, &error)) {
    request->rc = 2;
    return NULL;
  }
  g_mutex_lock (&request->mutex);
  while (!request->close_now)
    g_cond_wait (&request->changed, &request->mutex);
  g_mutex_unlock (&request->mutex);
  if (!g_io_stream_close (G_IO_STREAM (connection), NULL, &error))
    request->rc = 3;
  else
    request->rc = 0;
  return NULL;
}

static gboolean
drop_management_response (SoupServer *server,
    WylDaemonRetirementOperation operation, const gchar *request_id,
    DroppedManagementRequest *request)
{
  RetirementResponseBarrier barrier = {
    .expected_operation = operation,
    .expected_request_id = request_id,
  };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  g_mutex_init (&request->mutex);
  g_cond_init (&request->changed);
  request->rc = -1;
  wyl_daemon_http_set_retirement_response_checkpoint_for_test (server,
      retirement_response_checkpoint, &barrier);
  GThread *thread = g_thread_new ("drop-retirement-response",
          dropped_management_request_thread, request);
  g_mutex_lock (&barrier.mutex);
  if (!barrier.entered)
    g_cond_wait_until (&barrier.changed, &barrier.mutex,
        g_get_monotonic_time () + 30 * G_USEC_PER_SEC);
  gboolean entered = barrier.entered;
  g_mutex_unlock (&barrier.mutex);
  g_mutex_lock (&request->mutex);
  request->close_now = TRUE;
  g_cond_broadcast (&request->changed);
  g_mutex_unlock (&request->mutex);
  g_thread_join (thread);
  g_mutex_lock (&barrier.mutex);
  barrier.released = TRUE;
  g_cond_broadcast (&barrier.changed);
  while (entered && !barrier.exited)
    g_cond_wait (&barrier.changed, &barrier.mutex);
  g_mutex_unlock (&barrier.mutex);
  wyl_daemon_http_set_retirement_response_checkpoint_for_test (server, NULL,
      NULL);
  gboolean ok = entered && !barrier.mismatch && request->rc == 0;
  request->captured_decision_request_id =
      g_steal_pointer (&barrier.captured_decision_request_id);
  if (barrier.captured_response != NULL) {
    g_free (request->captured_response);
    request->captured_response = g_steal_pointer (&barrier.captured_response);
  }
  g_cond_clear (&request->changed);
  g_mutex_clear (&request->mutex);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return ok;
}

static gboolean
replay_retirement_response (ServiceDenialEnv *env, const gchar *method,
    const gchar *path, const gchar *query, const gchar *body,
    const gchar *caller_request_id, const DroppedManagementRequest *dropped,
    const gchar *expected_fragment)
{
  guint status = 0;
  g_autofree gchar *response_a = NULL;
  g_autofree gchar *response_b = NULL;
  g_autofree gchar *correlation_a = NULL;
  g_autofree gchar *correlation_b = NULL;
  if (dropped->captured_response == NULL
      || dropped->captured_decision_request_id == NULL
      || !wyl_request_id_is_canonical (dropped->captured_decision_request_id)
      || g_strcmp0 (dropped->captured_decision_request_id,
      caller_request_id) == 0)
    return FALSE;
  if (send_raw_service_principal_bearer_full (env->session, method,
      env->base_url, path, query, env->access_token, body, &status,
      &response_a, &correlation_a) != 0 || status != 200
      || response_a == NULL || correlation_a == NULL
      || g_strcmp0 (response_a, dropped->captured_response) != 0
      || strstr (response_a, expected_fragment) == NULL
      || !wyl_request_id_is_canonical (correlation_a)
      || g_strcmp0 (correlation_a, caller_request_id) == 0)
    return FALSE;
  if (send_raw_service_principal_bearer_full (env->session, method,
      env->base_url, path, query, env->access_token, body, &status,
      &response_b, &correlation_b) != 0 || status != 200
      || response_b == NULL || correlation_b == NULL
      || g_strcmp0 (response_b, response_a) != 0
      || !wyl_request_id_is_canonical (correlation_b)
      || g_strcmp0 (correlation_b, caller_request_id) == 0
      || g_strcmp0 (correlation_b, correlation_a) == 0)
    return FALSE;
  return TRUE;
}

typedef enum
{
  MANAGEMENT_CHECKPOINT_NOOP,
  MANAGEMENT_CHECKPOINT_PERMISSION_DORMANT,
  MANAGEMENT_CHECKPOINT_TARGET_SEALED,
  MANAGEMENT_CHECKPOINT_SESSION_LOGGED_OUT,
} ManagementCheckpointMutation;

typedef struct
{
  ManagementCheckpointMutation mutation;
  guint calls;
  SoupServer *server;
} ManagementCheckpointProbe;

static wyrelog_error_t management_checkpoint_mutate_authority
    (WylHandle * handle, const gchar * actor, const gchar * action,
    const gchar * session_id, const gchar * target_tenant, gpointer data);

/* #729: the self-arm route (POST /service-management-authority/arm) lets a
 * live MFA SYSTEM admin arm the two service-management permissions at ITS OWN
 * session, with no store-seam pre-arming. Covers the happy path (self-arm ->
 * management verbs authorize), the un-armed regression, durable arming, and
 * post-logout inertness. */
static gint
check_service_management_self_arm_reauthorization_zero_write (void)
{
  ServiceDenialEnv env = { 0 };
  ManagementCheckpointProbe probe = {
    .mutation = MANAGEMENT_CHECKPOINT_SESSION_LOGGED_OUT,
  };
  guint status = 0;
  g_autofree gchar *body = NULL;
  gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
  if (rc != 0)
    return rc;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  probe.server = env.http.server;
  if (wyl_policy_store_grant_role_membership (store, "human-principal-admin",
          "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
          "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2730;
  }
  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
      (env.http.server, management_checkpoint_mutate_authority, &probe);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
          "/service-management-authority/arm", env.query, env.access_token,
          "{}", &status, &body) != 0 || status != 403 || probe.calls != 1) {
    service_denial_env_clear (&env);
    return 2731;
  }

  /* The race loses after front-door ALLOW but before the decisive write gate;
   * all six self-arm-owned row families must remain untouched. */
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *stmt = NULL;
  static const gchar *sql =
      "SELECT (SELECT count(*) FROM service_management_self_arm_receipts"
      " WHERE tenant_id=? AND actor_subject_id=? AND session_id=?),"
      "(SELECT count(*) FROM direct_permissions WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM direct_permission_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_states WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_state_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM audit_events WHERE subject_id=? AND deny_origin=?);";
  const gchar *args[] = {
    WYL_TENANT_DEFAULT, "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token,
  };
  gboolean zero = db != NULL
      && sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK;
  if (zero) {
    for (guint i = 0; i < G_N_ELEMENTS (args); i++)
      if (sqlite3_bind_text (stmt, (int) i + 1, args[i], -1,
              SQLITE_TRANSIENT) != SQLITE_OK)
        zero = FALSE;
  }
  if (zero && sqlite3_step (stmt) == SQLITE_ROW) {
    for (guint i = 0; i < 6; i++)
      zero = zero && sqlite3_column_int64 (stmt, (int) i) == 0;
  } else {
    zero = FALSE;
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  service_denial_env_clear (&env);
  return zero ? 0 : 2732;
}

#ifdef WYL_TEST_HANDLE_SEAMS
typedef struct
{
  wyl_policy_store_t *store;
  const gchar *actor;
  const gchar *session_id;
  gboolean called;
  gboolean tampered;
} SelfArmProjectionTamper;

static void
self_arm_projection_tamper_checkpoint (gpointer data)
{
  SelfArmProjectionTamper *tamper = data;
  sqlite3_stmt *stmt = NULL;
  sqlite3 *db = tamper != NULL && tamper->store != NULL
      ? wyl_policy_store_get_db (tamper->store) : NULL;
  if (tamper == NULL || db == NULL)
    return;
  tamper->called = TRUE;
  if (sqlite3_prepare_v2 (db,
          "UPDATE permission_states SET state='tampered' "
          "WHERE subject_id=? AND perm_id=? AND scope=?", -1, &stmt,
          NULL) != SQLITE_OK)
    return;
  sqlite3_bind_text (stmt, 1, tamper->actor, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt, 2, "wr.service_credential.manage", -1,
      SQLITE_STATIC);
  sqlite3_bind_text (stmt, 3, tamper->session_id, -1, SQLITE_TRANSIENT);
  tamper->tampered = sqlite3_step (stmt) == SQLITE_DONE
      && sqlite3_changes (db) == 1;
  sqlite3_finalize (stmt);
}

static gboolean
self_arm_bundle_counts (ServiceDenialEnv *env, guint64 expected_receipt,
    guint64 expected_rows)
{
  static const gchar *sql =
      "SELECT (SELECT count(*) FROM service_management_self_arm_receipts "
      "WHERE tenant_id=? AND actor_subject_id=? AND session_id=?),"
      "(SELECT count(*) FROM direct_permissions WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM direct_permission_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_states WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_state_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM audit_events WHERE subject_id=? AND deny_origin=?);";
  const gchar *args[] = {
    WYL_TENANT_DEFAULT, "human-principal-admin", env->session_token,
    "human-principal-admin", env->session_token,
    "human-principal-admin", env->session_token,
    "human-principal-admin", env->session_token,
    "human-principal-admin", env->session_token,
    "human-principal-admin", env->session_token,
  };
  sqlite3 *db = wyl_policy_store_get_db (wyl_handle_get_policy_store
      (env->handle));
  sqlite3_stmt *stmt = NULL;
  gboolean ok = db != NULL && sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL)
      == SQLITE_OK;
  if (ok) {
    for (guint i = 0; i < G_N_ELEMENTS (args); i++)
      if (sqlite3_bind_text (stmt, (int) i + 1, args[i], -1,
              SQLITE_TRANSIENT) != SQLITE_OK)
        ok = FALSE;
  }
  if (ok && sqlite3_step (stmt) == SQLITE_ROW) {
    for (guint i = 0; i < 6; i++) {
      guint64 expected = i == 0 ? expected_receipt : expected_rows;
      ok = ok && (guint64) sqlite3_column_int64 (stmt, (int) i) == expected;
    }
  } else {
    ok = FALSE;
  }
  if (stmt != NULL)
    sqlite3_finalize (stmt);
  return ok;
}

static gint
check_service_management_self_arm_projection_and_replacement_faults (void)
{
  for (guint replacement = 0; replacement < 2; replacement++) {
    ServiceDenialEnv env = { 0 };
    gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
    if (rc != 0) {
      service_denial_env_clear (&env);
      return 2780 + (gint) replacement;
    }
    wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
    if (wyl_policy_store_grant_role_membership (store,
            "human-principal-admin", "wr.system_admin", WYL_TENANT_DEFAULT)
        != WYRELOG_E_OK
        || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
            "active") != WYRELOG_E_OK
        || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
      service_denial_env_clear (&env);
      return 2782 + (gint) replacement;
    }

    SelfArmProjectionTamper tamper = {
      .store = store,
      .actor = "human-principal-admin",
      .session_id = env.session_token,
    };
    if (!replacement)
      wyl_handle_set_committed_publication_checkpoint_for_test (env.handle,
          self_arm_projection_tamper_checkpoint, &tamper);
    else {
      wyl_handle_set_engine_replacement_fault_once_for_test (env.handle,
          WYL_ENGINE_REPLACEMENT_FAULT_READBACK);
      wyl_handle_set_committed_publication_fault_once_for_test (env.handle,
          WYL_COMMITTED_PUBLICATION_FAULT_COMMIT_APPLIED_ERROR);
    }

    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
            "/service-management-authority/arm", env.query,
            env.access_token, "{}", &status, &body) != 0 || status != 500
        || body == NULL
        || strstr (body, "service_authority_failed") == NULL
        || !self_arm_bundle_counts (&env, 1, 2)
        || (!replacement && (!tamper.called || !tamper.tampered))
        || !wyl_handle_engine_pair_is_poisoned (env.handle)
        || wyl_handle_engine_pair_is_ready (env.handle)
        || wyl_handle_engine_terminal_get_state (env.handle)
        != WYL_ENGINE_TERMINAL_FAILED) {
      service_denial_env_clear (&env);
      return 2785 + (gint) replacement;
    }
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    if (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (env.handle), env.handle,
            &reason) != WYRELOG_E_BUSY
        || reason != WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT
        || wyl_daemon_http_policy_write_for_test (env.http.server, NULL, NULL)
        != WYRELOG_E_BUSY) {
      service_denial_env_clear (&env);
      return 2790 + (gint) replacement;
    }
    service_denial_env_clear (&env);
  }
  return 0;
}

static gint
check_service_management_self_arm_finalize_snapshot (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return 2800;
  }
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_grant_role_membership (store,
          "human-principal-admin", "wr.system_admin", WYL_TENANT_DEFAULT)
      != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
          "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2801;
  }
  guint before = wyl_daemon_http_policy_write_terminal_entries_for_test
      (env.http.server);
  wyl_daemon_http_fail_next_policy_write_finalize_for_test (env.http.server,
      WYL_DAEMON_POLICY_WRITE_FINALIZE_FAULT_PREVALIDATION);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
          "/service-management-authority/arm", env.query, env.access_token,
          "{}", &status, &body) != 0 || status != 500 || body == NULL
      || g_strcmp0 (body, "{\"error\":\"policy_write_cleanup_failed\"}") != 0
      || wyl_daemon_http_policy_write_terminal_entries_for_test
      (env.http.server) != before + 1 || !self_arm_bundle_counts (&env, 1, 2)) {
    service_denial_env_clear (&env);
    return 2802;
  }
  WylDaemonPolicyWriteFinalizeSnapshot snapshot = { 0 };
  if (!wyl_daemon_http_policy_write_finalize_snapshot_for_test (env.http.server,
          &snapshot)
      || !policy_write_fault_snapshot_is_clean (&snapshot, 200, "success",
          15, "self_arm", WYL_DAEMON_POLICY_WRITE_RESOURCE_ENGINE, 1,
          WYRELOG_E_INTERNAL, 0)
      || wyl_handle_engine_pair_is_poisoned (env.handle)
      || !wyl_handle_engine_pair_is_ready (env.handle)) {
    service_denial_env_clear (&env);
    return 2803;
  }
  service_denial_env_clear (&env);
  return 0;
}

#endif

#ifdef WYL_TEST_HANDLE_SEAMS
static gint
check_service_management_self_arm_commit_faults (void)
{
  static const WylCommittedPublicationFault faults[] = {
    WYL_COMMITTED_PUBLICATION_FAULT_COMMIT,
    WYL_COMMITTED_PUBLICATION_FAULT_COMMIT_APPLIED_ERROR,
  };
  static const guint expected_status[] = { 500, 200 };
  static const gint64 expected_receipts[] = { 0, 1 };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    ServiceDenialEnv env = { 0 };
    guint status = 0;
    g_autofree gchar *body = NULL;
    gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
    if (rc != 0)
      return rc;
    wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
    if (wyl_policy_store_grant_role_membership (store,
            "human-principal-admin", "wr.system_admin", WYL_TENANT_DEFAULT)
        != WYRELOG_E_OK
        || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
            "active") != WYRELOG_E_OK
        || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
      service_denial_env_clear (&env);
      return 2740 + (gint) i;
    }
    wyl_handle_set_committed_publication_fault_once_for_test (env.handle,
        faults[i]);
    if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
            "/service-management-authority/arm", env.query, env.access_token,
            "{}", &status, &body) != 0 || status != expected_status[i]) {
      service_denial_env_clear (&env);
      return 2750 + (gint) i;
    }
    sqlite3 *db = wyl_policy_store_get_db (store);
    sqlite3_stmt *stmt = NULL;
    static const gchar *sql =
        "SELECT (SELECT count(*) FROM service_management_self_arm_receipts"
        " WHERE tenant_id=? AND actor_subject_id=? AND session_id=?),"
        "(SELECT count(*) FROM direct_permissions WHERE subject_id=? AND scope=?),"
        "(SELECT count(*) FROM direct_permission_events WHERE subject_id=? AND scope=?),"
        "(SELECT count(*) FROM permission_states WHERE subject_id=? AND scope=?),"
        "(SELECT count(*) FROM permission_state_events WHERE subject_id=? AND scope=?),"
        "(SELECT count(*) FROM audit_events WHERE subject_id=? AND deny_origin=?);";
    const gchar *args[] = {
      WYL_TENANT_DEFAULT, "human-principal-admin", env.session_token,
      "human-principal-admin", env.session_token,
      "human-principal-admin", env.session_token,
      "human-principal-admin", env.session_token,
      "human-principal-admin", env.session_token,
      "human-principal-admin", env.session_token,
    };
    gboolean queried = db != NULL
        && sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK;
    if (queried) {
      for (guint j = 0; j < G_N_ELEMENTS (args); j++)
        if (sqlite3_bind_text (stmt, (int) j + 1, args[j], -1,
                SQLITE_TRANSIENT) != SQLITE_OK)
          queried = FALSE;
    }
    gboolean rows_ok = queried && sqlite3_step (stmt) == SQLITE_ROW;
    if (rows_ok) {
      for (guint j = 0; j < 6; j++) {
        gint64 value = sqlite3_column_int64 (stmt, (int) j);
        gint64 expected = j == 0 ? expected_receipts[i] :
            expected_receipts[i] == 0 ? 0 : (j == 1 || j == 2 || j == 3
            || j == 4 || j == 5 ? 2 : 0);
        rows_ok = rows_ok && value == expected;
      }
    }
    if (stmt != NULL)
      sqlite3_finalize (stmt);
    if (!rows_ok) {
      service_denial_env_clear (&env);
      return 2760 + (gint) i;
    }
    if (i == 1) {
      WylServiceAuthUnavailableReason reason =
          WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
      if (wyl_service_auth_authority_validate_available
          (wyl_handle_get_service_auth_authority (env.handle), env.handle,
              &reason) != WYRELOG_E_OK
          || reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE) {
        service_denial_env_clear (&env);
        return 2770;
      }
    }
    service_denial_env_clear (&env);
  }
  return 0;
}
#endif

static gint
check_service_management_self_arm_end_to_end (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  /* Eligibility is carried by the wr.system_admin role (SoD), never a direct
   * grant of the manage permissions. The session_state("__wr_default","active")
   * anchor is what a real daemon's bootstrap-admin provisioning
   * (wyl_policy_store_apply_bootstrap_admin) seeds; mirror that here so the
   * eligibility decide at __wr_default can be satisfied. */
  if (wyl_policy_store_grant_role_membership (store, "human-principal-admin",
      "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2700;
  }

  const gchar *create_body =
      "{\"subject_id\":\"svc:tenant-a:worker\",\"display_name\":\"Worker\"}";
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* (b) Without self-arm the management verb is denied. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-principals", env.query, env.access_token, create_body,
      &status, &body) != 0 || status != 403) {
    service_denial_env_clear (&env);
    return 2701;
  }
  g_clear_pointer (&body, g_free);

  /* (a) Self-arm at the caller's own session. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-management-authority/arm", env.query, env.access_token,
      "{}", &status, &body) != 0 || status != 200) {
    service_denial_env_clear (&env);
    return 2702;
  }
  g_clear_pointer (&body, g_free);

  /* Both management permissions are durably armed at the caller's session. */
  gboolean armed_p = FALSE;
  gboolean armed_c = FALSE;
  if (wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_principal.manage", env.session_token, "armed", &armed_p)
      != WYRELOG_E_OK || !armed_p
      || wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_credential.manage", env.session_token, "armed", &armed_c)
      != WYRELOG_E_OK || !armed_c) {
    service_denial_env_clear (&env);
    return 2703;
  }

  /* create (wr.service_principal.manage) now authorizes. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-principals", env.query, env.access_token, create_body,
      &status, &body) != 0 || status != 200 || body == NULL
      || strstr (body, "\"subject_id\":\"svc:tenant-a:worker\"") == NULL) {
    service_denial_env_clear (&env);
    return 2704;
  }
  g_clear_pointer (&body, g_free);

  /* issue (wr.service_credential.manage) now authorizes and delivers. */
  const gchar *issue_body =
      "{\"version\":\"1\",\"tenant\":\"tenant-a\","
      "\"request_id\":\"111111111111111111111111111\","
      "\"destination\":\"issue.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}";
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-principals/svc:tenant-a:worker/credentials",
      env.tenant_query, env.access_token, issue_body, &status, &body) != 0
      || status != 200 || body == NULL
      || strstr (body, "\"delivered\":true") == NULL) {
    service_denial_env_clear (&env);
    return 2705;
  }
  g_clear_pointer (&body, g_free);

  /* The second arm is a durable no-op: all bundle-owned rows and their
   * provenance must remain cardinality-stable. */
  guint64 counts_before[6] = { 0 };
  guint64 counts_after[6] = { 0 };
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *count_stmt = NULL;
  const gchar *count_sql =
      "SELECT (SELECT count(*) FROM service_management_self_arm_receipts "
      "WHERE tenant_id=? AND actor_subject_id=? AND session_id=?),"
      "(SELECT count(*) FROM direct_permissions WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM direct_permission_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_states WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM permission_state_events WHERE subject_id=? AND scope=?),"
      "(SELECT count(*) FROM audit_events WHERE subject_id=? AND deny_origin=?);";
  if (db == NULL || sqlite3_prepare_v2 (db, count_sql, -1, &count_stmt, NULL)
      != SQLITE_OK) {
    service_denial_env_clear (&env);
    return 2708;
  }
  const gchar *args[] = { WYL_TENANT_DEFAULT, "human-principal-admin",
    env.session_token, "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token, "human-principal-admin",
    env.session_token, "human-principal-admin", env.session_token,
    "human-principal-admin", env.session_token
  };
  for (guint i = 0; i < G_N_ELEMENTS (args); i++)
    sqlite3_bind_text (count_stmt, (int) i + 1, args[i], -1, SQLITE_TRANSIENT);
  if (sqlite3_step (count_stmt) != SQLITE_ROW) {
    sqlite3_finalize (count_stmt);
    service_denial_env_clear (&env);
    return 2709;
  }
  for (guint i = 0; i < 6; i++)
    counts_before[i] = (guint64) sqlite3_column_int64 (count_stmt, (int) i);
  sqlite3_finalize (count_stmt);
  if (counts_before[0] != 1 || counts_before[1] != 2
      || counts_before[2] != 2 || counts_before[3] != 2
      || counts_before[4] != 2 || counts_before[5] != 2) {
    service_denial_env_clear (&env);
    return 2714;
  }
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
          "/service-management-authority/arm", env.query, env.access_token,
          "{}", &status, &body) != 0 || status != 200) {
    service_denial_env_clear (&env);
    return 2710;
  }
  g_clear_pointer (&body, g_free);
  if (sqlite3_prepare_v2 (db, count_sql, -1, &count_stmt, NULL) != SQLITE_OK) {
    service_denial_env_clear (&env);
    return 2711;
  }
  for (guint i = 0; i < G_N_ELEMENTS (args); i++)
    sqlite3_bind_text (count_stmt, (int) i + 1, args[i], -1, SQLITE_TRANSIENT);
  if (sqlite3_step (count_stmt) != SQLITE_ROW) {
    sqlite3_finalize (count_stmt);
    service_denial_env_clear (&env);
    return 2712;
  }
  for (guint i = 0; i < 6; i++)
    counts_after[i] = (guint64) sqlite3_column_int64 (count_stmt, (int) i);
  sqlite3_finalize (count_stmt);
  if (memcmp (counts_before, counts_after, sizeof counts_before) != 0) {
    service_denial_env_clear (&env);
    return 2713;
  }

  /* (e) Post-logout inertness: revoke the human session; the management verb
   * no longer authorizes though the perm_state rows persist. */
  wyl_daemon_http_revoke_human_session_for_test (env.http.server,
      env.session_token);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-principals", env.query, env.access_token,
      "{\"subject_id\":\"svc:tenant-a:worker2\",\"display_name\":\"W2\"}",
      &status, &body) != 0 || (status != 403 && status != 401)) {
    service_denial_env_clear (&env);
    return 2706;
  }
  g_clear_pointer (&body, g_free);

  gboolean still_armed = FALSE;
  if (wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_principal.manage", env.session_token, "armed",
      &still_armed) != WYRELOG_E_OK || !still_armed) {
    service_denial_env_clear (&env);
    return 2707;
  }

  service_denial_env_clear (&env);
  return 0;
}

/* #729: front-door and eligibility rejections for the self-arm route. */
static gint
check_service_management_self_arm_rejections (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  guint status = 0;
  g_autofree gchar *body = NULL;

  /* Seed the __wr_default session anchor so the SoD denial below is
   * attributable to the missing wr.system_admin role, not a missing anchor. */
  if (wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT, "active")
      != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2709;
  }

  /* (f) SoD: before promotion the admin lacks wr.service.self_authorize, so
   * the eligibility decide denies the self-arm. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-management-authority/arm", env.query, env.access_token,
      "{}", &status, &body) != 0 || status != 403) {
    service_denial_env_clear (&env);
    return 2710;
  }
  g_clear_pointer (&body, g_free);

  if (wyl_policy_store_grant_role_membership (store, "human-principal-admin",
      "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2711;
  }

  /* (d) Non-POST -> 405. */
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-management-authority/arm", env.query, env.access_token,
      NULL, &status, &body) != 0 || status != 405) {
    service_denial_env_clear (&env);
    return 2712;
  }
  g_clear_pointer (&body, g_free);

  /* (d) Missing guard triple -> 400. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-management-authority/arm", "foo=bar", env.access_token,
      "{}", &status, &body) != 0 || status != 400) {
    service_denial_env_clear (&env);
    return 2713;
  }
  g_clear_pointer (&body, g_free);

  /* (d) Invalid guard (risk out of range) -> 400. */
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-management-authority/arm",
      "guard_timestamp=1&guard_loc_class=trusted&guard_risk=200",
      env.access_token, "{}", &status, &body) != 0 || status != 400) {
    service_denial_env_clear (&env);
    return 2714;
  }
  g_clear_pointer (&body, g_free);

  /* (d) A live but NON-MFA session for the same eligible admin cannot
   * self-arm: the human+MFA gate denies. */
  {
    wyl_id_t nonmfa_id = WYL_ID_NIL;
    gchar nonmfa_session[WYL_ID_STRING_BUF] = { 0 };
    g_autofree gchar *nonmfa_access = NULL;
    g_autofree gchar *nonmfa_refresh = NULL;
    if (wyl_id_new (&nonmfa_id) != WYRELOG_E_OK
        || wyl_id_format (&nonmfa_id, nonmfa_session, sizeof nonmfa_session)
        != WYRELOG_E_OK
        || !seed_human_tokens_with_assurance (env.http.server, nonmfa_session,
        "human-principal-admin", WYL_TENANT_DEFAULT, FALSE, &nonmfa_access,
        &nonmfa_refresh)) {
      service_denial_env_clear (&env);
      return 2715;
    }
    if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
        "/service-management-authority/arm", env.query, nonmfa_access,
        "{}", &status, &body) != 0 || status != 403) {
      service_denial_env_clear (&env);
      return 2716;
    }
    g_clear_pointer (&body, g_free);
  }

  /* Every failed attempt left the authority un-armed. */
  gboolean armed = TRUE;
  if (wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_principal.manage", env.session_token, "armed", &armed)
      != WYRELOG_E_OK || armed) {
    service_denial_env_clear (&env);
    return 2717;
  }

  service_denial_env_clear (&env);
  return 0;
}

/* #729: the route arms auth.session_id for auth.actor ONLY -- attacker-supplied
 * scope/subject query params are ignored. */
static gint
check_service_management_self_arm_scopes_to_session (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, FALSE, FALSE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_grant_role_membership (store, "human-principal-admin",
      "wr.system_admin", WYL_TENANT_DEFAULT) != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2720;
  }

  guint status = 0;
  g_autofree gchar *body = NULL;
  const gchar *steer_query =
      "guard_timestamp=1&guard_loc_class=trusted&guard_risk=0"
      "&scope=attacker-scope&subject=svc:tenant-a:evil";
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-management-authority/arm", steer_query, env.access_token,
      "{}", &status, &body) != 0 || status != 200) {
    service_denial_env_clear (&env);
    return 2721;
  }
  g_clear_pointer (&body, g_free);

  gboolean armed_self = FALSE;
  gboolean armed_injected_scope = TRUE;
  if (wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_principal.manage", env.session_token, "armed",
      &armed_self) != WYRELOG_E_OK || !armed_self
      || wyl_policy_store_permission_state_is (store, "human-principal-admin",
      "wr.service_principal.manage", "attacker-scope", "armed",
      &armed_injected_scope) != WYRELOG_E_OK || armed_injected_scope) {
    service_denial_env_clear (&env);
    return 2722;
  }
  /* The injected service-prefix subject holds no authority: the store rejects
   * or has no armed row for it. */
  gboolean armed_injected_subject = TRUE;
  wyrelog_error_t subj_rc = wyl_policy_store_permission_state_is (store,
          "svc:tenant-a:evil", "wr.service_principal.manage", "attacker-scope",
          "armed", &armed_injected_subject);
  if (subj_rc == WYRELOG_E_OK && armed_injected_subject) {
    service_denial_env_clear (&env);
    return 2723;
  }

  service_denial_env_clear (&env);
  return 0;
}

static gint
check_retirement_response_loss_restart_contract (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (env.http.server);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  gboolean seal_tenant_created = FALSE;
  if (wyl_policy_store_create_tenant (store, "tenant-drop-seal",
      &seal_tenant_created) != WYRELOG_E_OK || !seal_tenant_created
      || wyl_policy_store_grant_direct_permission (store,
      "human-principal-admin", "wr.tenant.manage", WYL_TENANT_DEFAULT)
      != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store,
      "human-principal-admin", "wr.tenant.manage", WYL_TENANT_DEFAULT,
      "armed") != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, WYL_TENANT_DEFAULT,
      "active") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2610;
  }

  const gchar *disable_subject = "svc:tenant-a:drop-disable";
  const gchar *revoke_subject = "svc:tenant-a:drop-revoke";
  const gchar *rotate_subject = "svc:tenant-a:drop-rotate";
  gchar seed_ids[5][WYL_REQUEST_ID_STRING_BUF] = { {0} };
  for (guint i = 0; i < G_N_ELEMENTS (seed_ids); i++)
    if (wyl_request_id_new (seed_ids[i], sizeof seed_ids[i]) != WYRELOG_E_OK) {
      service_denial_env_clear (&env);
      return 2611;
    }
  wyl_service_principal_t principal = { 0 };
  if (wyl_service_principal_create (env.handle, disable_subject,
      "Drop disable", "human-principal-admin", seed_ids[0], &principal)
      != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2612;
  }
  wyl_service_principal_clear (&principal);
  if (wyl_service_principal_create (env.handle, revoke_subject, "Drop revoke",
      "human-principal-admin", seed_ids[1], &principal) != WYRELOG_E_OK) {
    wyl_service_principal_clear (&principal);
    service_denial_env_clear (&env);
    return 2613;
  }
  wyl_service_principal_clear (&principal);
  if (wyl_service_principal_create (env.handle, rotate_subject, "Drop rotate",
      "human-principal-admin", seed_ids[2], &principal) != WYRELOG_E_OK) {
    wyl_service_principal_clear (&principal);
    service_denial_env_clear (&env);
    return 2614;
  }
  wyl_service_principal_clear (&principal);
  wyl_service_credential_issue_result_t revoke_seed = { 0 };
  wyl_service_credential_issue_result_t rotate_seed = { 0 };
  if (wyl_service_credential_issue (env.handle, revoke_subject, "tenant-a",
      "human-principal-admin", seed_ids[3],
      CONTRACT_FUTURE_EXPIRES_AT_US, &revoke_seed) != WYRELOG_E_OK
      || wyl_service_credential_issue (env.handle, rotate_subject, "tenant-a",
      "human-principal-admin", seed_ids[4],
      CONTRACT_FUTURE_EXPIRES_AT_US, &rotate_seed) != WYRELOG_E_OK) {
    wyl_service_credential_issue_result_clear (&revoke_seed);
    wyl_service_credential_issue_result_clear (&rotate_seed);
    service_denial_env_clear (&env);
    return 2615;
  }
  g_autofree gchar *revoke_credential =
      g_strdup (revoke_seed.credential.credential_id);
  g_autofree gchar *rotate_credential =
      g_strdup (rotate_seed.credential.credential_id);
  wyl_service_credential_issue_result_clear (&revoke_seed);
  wyl_service_credential_issue_result_clear (&rotate_seed);
  if (revoke_credential == NULL || rotate_credential == NULL) {
    service_denial_env_clear (&env);
    return 2616;
  }

  gchar caller_ids[4][WYL_REQUEST_ID_STRING_BUF] = { {0}};
  for (guint i = 0; i < G_N_ELEMENTS (caller_ids); i++)
    if (wyl_request_id_new (caller_ids[i], sizeof caller_ids[i])
        != WYRELOG_E_OK) {
      service_denial_env_clear (&env);
      return 2617;
    }
  g_autofree gchar *disable_path = g_strdup_printf
        ("/service-principals/%s/disable", disable_subject);
  g_autofree gchar *revoke_path = g_strdup_printf ("/service-credentials/%s",
          revoke_credential);
  g_autofree gchar *rotate_path = g_strdup_printf
        ("/service-credentials/%s/rotate", rotate_credential);
  g_autofree gchar *seal_query = g_strdup_printf ("name=tenant-drop-seal&%s",
          env.query);
  g_autofree gchar *disable_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", caller_ids[0]);
  g_autofree gchar *revoke_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", caller_ids[1]);
  g_autofree gchar *seal_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", caller_ids[3]);
  g_autofree gchar *rotate_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\","
          "\"destination\":\"drop-rotate.json\",\"expires_at_us\":\"%s\"}",
          caller_ids[2], CONTRACT_FUTURE_EXPIRES_AT_US_STR);
  DroppedManagementRequest dropped[4] = {
    {.base_url = env.base_url,.method = "POST",.path = disable_path,
     .query = env.query,.access_token = env.access_token,
     .body = disable_body},
    {.base_url = env.base_url,.method = "DELETE",.path = revoke_path,
     .query = env.tenant_query,.access_token = env.access_token,
     .body = revoke_body},
    {.base_url = env.base_url,.method = "POST",.path = rotate_path,
     .query = env.tenant_query,.access_token = env.access_token,
     .body = rotate_body},
    {.base_url = env.base_url,.method = "POST",.path = "/tenants/seal",
     .query = seal_query,.access_token = env.access_token,
     .body = seal_body},
  };
  const WylDaemonRetirementOperation operations[] = {
    WYL_DAEMON_RETIREMENT_PRINCIPAL_DISABLE,
    WYL_DAEMON_RETIREMENT_CREDENTIAL_REVOKE,
    WYL_DAEMON_RETIREMENT_CREDENTIAL_ROTATE,
    WYL_DAEMON_RETIREMENT_TENANT_SEAL,
  };
  g_autofree gchar *probe_body = NULL;
  for (guint i = 0; i < G_N_ELEMENTS (dropped); i++) {
    if (!drop_management_response (env.http.server, operations[i],
        caller_ids[i], &dropped[i])) {
      guint diagnostic_status = 0;
      g_autofree gchar *diagnostic_body = NULL;
      (void) send_raw_service_principal_bearer (env.session,
          dropped[i].method, env.base_url, dropped[i].path, dropped[i].query,
          env.access_token, dropped[i].body, &diagnostic_status,
          &diagnostic_body);
      g_printerr ("WYRELOG_TEST_DIAG retirement_drop route=%u socket_rc=%d "
          "captured_id=%s captured_body=%s status=%u body=%s\n", i,
          dropped[i].rc,
          dropped[i].captured_decision_request_id != NULL ?
          dropped[i].captured_decision_request_id : "(null)",
          dropped[i].captured_response != NULL ?
          dropped[i].captured_response : "(null)", diagnostic_status,
          diagnostic_body != NULL ? diagnostic_body : "(null)");
      g_printerr ("WYRELOG_TEST_DIAG retirement_publication stage=%u "
          "commit=%u published=%d leases=%u\n", env.publication.stage_calls,
          env.publication.commit_calls, env.publication.published,
          env.publication.active_leases);
      rc = 2618 + (gint) i;
      goto clear_dropped;
    }
  }
  guint status = 0;
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, env.access_token, NULL, &status,
      &probe_body) != 0 || status != 200) {
    rc = 2622;
    goto clear_dropped;
  }
  gint64 receipts_before = 0;
  gint64 credentials_before = 0;
  guint stage_before = env.publication.stage_calls;
  guint commit_before = env.publication.commit_calls;
  if (!policy_count_rows (env.handle,
      "SELECT count(*) FROM service_retirement_receipts;", &receipts_before)
      || receipts_before != 3
      || !policy_count_rows (env.handle,
      "SELECT count(*) FROM service_credentials;", &credentials_before)
      || credentials_before != 3 || stage_before == 0 || commit_before == 0) {
    rc = 2623;
    goto clear_dropped;
  }

  if ((rc = service_denial_env_restart (&env)) != 0)
    goto clear_dropped;
  if (!replay_retirement_response (&env, "POST", disable_path, env.query,
      disable_body, caller_ids[0], &dropped[0], "\"state\":\"disabled\"")) {
    rc = 2624;
    goto clear_dropped;
  }
  if (!replay_retirement_response (&env, "DELETE", revoke_path,
      env.tenant_query, revoke_body, caller_ids[1], &dropped[1],
      "\"state\":\"revoked\"")) {
    rc = 2625;
    goto clear_dropped;
  }
  if (!replay_retirement_response (&env, "POST", rotate_path,
      env.tenant_query, rotate_body, caller_ids[2], &dropped[2],
      "\"state\":\"terminal\"")) {
    rc = 2626;
    goto clear_dropped;
  }
  if (!replay_retirement_response (&env, "POST", "/tenants/seal",
      seal_query, seal_body, caller_ids[3], &dropped[3],
      "\"changed\":true")) {
    rc = 2627;
    goto clear_dropped;
  }
  gint64 receipts_after = 0;
  gint64 credentials_after = 0;
  if (!policy_count_rows (env.handle,
      "SELECT count(*) FROM service_retirement_receipts;", &receipts_after)
      || receipts_after != receipts_before
      || !policy_count_rows (env.handle,
      "SELECT count(*) FROM service_credentials;", &credentials_after)
      || credentials_after != credentials_before
      || env.publication.stage_calls != stage_before
      || env.publication.commit_calls != commit_before) {
    rc = 2628;
    goto clear_dropped;
  }

clear_dropped:
  for (guint i = 0; i < G_N_ELEMENTS (dropped); i++) {
    g_free (dropped[i].captured_decision_request_id);
    g_free (dropped[i].captured_response);
  }
  service_denial_env_clear (&env);
  return rc;
}

static gint
check_retirement_postcommit_http_fault (guint expected_status,
    gboolean fail_latch)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (env.http.server);
  gchar create_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar caller_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  wyl_service_principal_t principal = { 0 };
  const gchar *subject = fail_latch ? "svc:tenant-a:fault-500" :
      "svc:tenant-a:fault-503";
  if (wyl_request_id_new (create_id, sizeof create_id) != WYRELOG_E_OK
      || wyl_request_id_new (caller_id, sizeof caller_id) != WYRELOG_E_OK
      || wyl_service_principal_create (env.handle, subject, "Fault target",
      "human-principal-admin", create_id, &principal) != WYRELOG_E_OK) {
    wyl_service_principal_clear (&principal);
    service_denial_env_clear (&env);
    return 2630;
  }
  wyl_service_principal_clear (&principal);
  if (fail_latch)
    wyl_daemon_http_fail_next_retirement_latch_for_test (env.http.server);
  wyl_policy_store_service_authority_transaction_fail_once
    (wyl_handle_get_policy_store (env.handle),
      WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  g_autofree gchar *path = g_strdup_printf
        ("/service-principals/%s/disable", subject);
  g_autofree gchar *body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", caller_id);
  guint status = 0;
  g_autofree gchar *response = NULL;
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      path, env.query, env.access_token, body, &status, &response) != 0
      || status != expected_status || response == NULL
      || strstr (response, "service_principal_failed") == NULL) {
    service_denial_env_clear (&env);
    return fail_latch ? 2631 : 2632;
  }
  g_autofree gchar *receipt_sql = g_strdup_printf
        ("SELECT count(*) FROM service_retirement_receipts WHERE "
          "request_id='%s';", caller_id);
  g_autofree gchar *state_sql = g_strdup_printf
        ("SELECT count(*) FROM service_principals WHERE subject_id='%s' AND "
          "state='disabled';", subject);
  gint64 receipt_count = 0;
  gint64 disabled_count = 0;
  if (!policy_count_rows (env.handle, receipt_sql, &receipt_count)
      || receipt_count != 1
      || !policy_count_rows (env.handle, state_sql, &disabled_count)
      || disabled_count != 1) {
    service_denial_env_clear (&env);
    return fail_latch ? 2633 : 2634;
  }
  service_denial_env_clear (&env);
  return 0;
}

static gint
check_retirement_postcommit_http_fault_matrix (void)
{
  gint rc = check_retirement_postcommit_http_fault (503, FALSE);
  if (rc != 0)
    return rc;
  return check_retirement_postcommit_http_fault (500, TRUE);
}

static gint
retirement_http_exec (sqlite3 *db, const gchar *sql)
{
  return sqlite3_exec (db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : 1;
}

static gint
check_retirement_corruption_http_matrix (void)
{
  ServiceDenialEnv env = { 0 };
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0) {
    service_denial_env_clear (&env);
    return rc;
  }
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (env.http.server);
  wyl_service_principal_t principal = { 0 };
  if (wyl_service_principal_create (env.handle, "svc:tenant-a:corrupt-http",
      "Corruption HTTP", "human-principal-admin", "corrupt-http-create",
      &principal) != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2640;
  }
  wyl_service_principal_clear (&principal);
  wyl_service_credential_issue_result_t issued = { 0 };
  if (wyl_service_credential_issue (env.handle,
      "svc:tenant-a:corrupt-http", "tenant-a", "human-principal-admin",
      "corrupt-http-issue", CONTRACT_FUTURE_EXPIRES_AT_US, &issued)
      != WYRELOG_E_OK) {
    service_denial_env_clear (&env);
    return 2641;
  }
  g_autofree gchar *credential_id = g_strdup (issued.credential.credential_id);
  wyl_service_credential_issue_result_clear (&issued);
  g_autofree gchar *principal_path = g_strdup
        ("/service-principals/svc:tenant-a:corrupt-http/disable");
  g_autofree gchar *credential_path = g_strdup_printf
        ("/service-credentials/%s", credential_id);
  const gchar *principal_transition =
      "{\"version\":\"1\",\"request_id\":" "\"000000000000000000000000240\"}";
  const gchar *principal_terminal =
      "{\"version\":\"1\",\"request_id\":" "\"000000000000000000000000241\"}";
  const gchar *credential_transition =
      "{\"version\":\"1\",\"request_id\":" "\"000000000000000000000000242\"}";
  const gchar *credential_terminal =
      "{\"version\":\"1\",\"request_id\":" "\"000000000000000000000000243\"}";
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      principal_path, env.query, env.access_token, principal_transition,
      &status, &body) != 0 || status != 200) {
    rc = 2642;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      principal_path, env.query, env.access_token, principal_terminal,
      &status, &body) != 0 || status != 200) {
    rc = 2643;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "DELETE", env.base_url,
      credential_path, env.tenant_query, env.access_token,
      credential_transition, &status, &body) != 0 || status != 200) {
    rc = 2644;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "DELETE", env.base_url,
      credential_path, env.tenant_query, env.access_token,
      credential_terminal, &status, &body) != 0 || status != 200) {
    rc = 2645;
    goto cleanup;
  }
  sqlite3 *db = wyl_policy_store_get_db
        (wyl_handle_get_policy_store (env.handle));
  gint64 effects_before = 0;
  const gchar *effects_sql =
      "SELECT (SELECT count(*) FROM service_retirement_receipts)+"
      "(SELECT count(*) FROM service_principal_events)+"
      "(SELECT count(*) FROM service_credential_events)+"
      "(SELECT count(*) FROM audit_events WHERE action IN "
      "('service.principal.disable','service.credential.revoke'))+"
      "(SELECT count(*) FROM audit_intentions i JOIN audit_events a "
      "ON a.id=i.audit_id WHERE a.action IN "
      "('service.principal.disable','service.credential.revoke'));";
  if (!policy_count_rows (env.handle, effects_sql, &effects_before)) {
    rc = 2646;
    goto cleanup;
  }
  if (retirement_http_exec (db,
      "DROP TRIGGER trg_service_retirement_no_update;"
      "CREATE TEMP TABLE saved_http_principal AS SELECT disabled_by,"
      "disabled_at_us,updated_at_us FROM service_principals WHERE "
      "subject_id='svc:tenant-a:corrupt-http';"
      "UPDATE service_principals SET disabled_by='forged-http',"
      "disabled_at_us=disabled_at_us+1,updated_at_us=updated_at_us+1 WHERE "
      "subject_id='svc:tenant-a:corrupt-http';") != 0) {
    rc = 2652;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      principal_path, env.query, env.access_token, principal_terminal,
      &status, &body) != 0 || status != 500 || body == NULL
      || strstr (body, "service_principal_failed") == NULL) {
    rc = 2647;
    goto cleanup;
  }
  gint64 effects_after = 0;
  if (!policy_count_rows (env.handle, effects_sql, &effects_after)
      || effects_after != effects_before) {
    rc = 2648;
    goto cleanup;
  }
  if (retirement_http_exec (db,
      "UPDATE service_principals SET "
      "disabled_by=(SELECT disabled_by FROM saved_http_principal),"
      "disabled_at_us=(SELECT disabled_at_us FROM saved_http_principal),"
      "updated_at_us=(SELECT updated_at_us FROM saved_http_principal) WHERE "
      "subject_id='svc:tenant-a:corrupt-http';"
      "DROP TABLE saved_http_principal;"
      "CREATE TEMP TABLE saved_http_credential AS SELECT revoked_by,"
      "revoked_at_us,updated_at_us FROM service_credentials WHERE "
      "credential_id=(SELECT resource_id FROM service_retirement_receipts "
      "WHERE request_id='000000000000000000000000243');"
      "UPDATE service_credentials SET revoked_by='forged-http',"
      "revoked_at_us=revoked_at_us+1,updated_at_us=updated_at_us+1 WHERE "
      "credential_id=(SELECT resource_id FROM service_retirement_receipts "
      "WHERE request_id='000000000000000000000000243');") != 0) {
    rc = 2653;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "DELETE", env.base_url,
      credential_path, env.tenant_query, env.access_token,
      credential_terminal, &status, &body) != 0 || status != 500
      || body == NULL || strstr (body, "service_credential_failed") == NULL) {
    rc = 2649;
    goto cleanup;
  }
  if (!policy_count_rows (env.handle, effects_sql, &effects_after)
      || effects_after != effects_before) {
    rc = 2650;
    goto cleanup;
  }
  if (retirement_http_exec (db,
      "UPDATE service_credentials SET "
      "revoked_by=(SELECT revoked_by FROM saved_http_credential),"
      "revoked_at_us=(SELECT revoked_at_us FROM saved_http_credential),"
      "updated_at_us=(SELECT updated_at_us FROM saved_http_credential) WHERE "
      "credential_id=(SELECT resource_id FROM service_retirement_receipts "
      "WHERE request_id='000000000000000000000000243');"
      "DROP TABLE saved_http_credential;"
      "CREATE TEMP TABLE saved_http_fingerprint AS SELECT input_fingerprint "
      "FROM service_retirement_receipts WHERE "
      "request_id='000000000000000000000000241';"
      "UPDATE service_retirement_receipts SET input_fingerprint=zeroblob(32) "
      "WHERE request_id='000000000000000000000000241';") != 0) {
    rc = 2654;
    goto cleanup;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      principal_path, env.query, env.access_token, principal_terminal,
      &status, &body) != 0 || status != 500 || body == NULL
      || strstr (body, "service_principal_failed") == NULL
      || !policy_count_rows (env.handle, effects_sql, &effects_after)
      || effects_after != effects_before) {
    rc = 2651;
    goto cleanup;
  }

cleanup:
  service_denial_env_clear (&env);
  return rc;
}

static gint
send_raw_service_management_forwarded_spoof (SoupSession *session,
    const gchar *method, const gchar *base_url, const gchar *path,
    const gchar *query, const gchar *access_token, const gchar *body,
    guint *out_status, gchar **out_body)
{
  if (access_token == NULL || out_status == NULL || out_body == NULL)
    return 2520;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *uri = build_policy_mutation_uri (base_url, path, query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 2521;
  g_autofree gchar *authorization = g_strdup_printf ("Bearer %s",
          access_token);
  SoupMessageHeaders *headers = soup_message_get_request_headers (msg);
  soup_message_headers_replace (headers, "Authorization", authorization);
  /* These attacker-controlled forwarding claims must never replace the
   * listener and peer socket addresses consumed by the loopback gate. */
  soup_message_headers_replace (headers, "Forwarded",
      "for=203.0.113.9;proto=https;host=attacker.invalid");
  soup_message_headers_replace (headers, "X-Forwarded-For", "203.0.113.9");
  soup_message_headers_replace (headers, "X-Real-IP", "203.0.113.9");
  soup_message_headers_replace (headers, "Host", "attacker.invalid");
  if (body != NULL) {
    g_autoptr (GBytes) request_bytes = g_bytes_new_static (body, strlen (body));
    soup_message_set_request_body_from_bytes (msg, "application/json",
        request_bytes);
  }

  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
          &error);
  if (bytes == NULL)
    return 2522;
  gint rc = check_response_request_id_header (msg, 2523);
  if (rc != 0)
    return rc;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

/* The shared envelope accepts only a default-resolver Bearer whose exact live
 * human session has completed MFA. Exercise caller classes that can otherwise
 * look superficially valid, including refresh of an unassured session. */
static gint
check_service_management_caller_and_refresh_matrix (void)
{
  ServiceDenialEnv env = { 0 };
  g_autofree gchar *body = NULL;
  g_autofree gchar *tenant_access = NULL;
  g_autofree gchar *tenant_refresh = NULL;
  g_autofree gchar *session_query = NULL;
  g_autofree gchar *skip_access = NULL;
  g_autofree gchar *skip_refresh = NULL;
  g_autofree gchar *skip_refreshed_access = NULL;
  g_autofree gchar *assured_access = NULL;
  g_autofree gchar *assured_refresh = NULL;
  g_autofree gchar *assured_refreshed_access = NULL;
  wyl_id_t tenant_id = WYL_ID_NIL;
  wyl_id_t skip_id = WYL_ID_NIL;
  wyl_id_t assured_id = WYL_ID_NIL;
  gchar tenant_session[WYL_ID_STRING_BUF] = { 0 };
  gchar skip_session[WYL_ID_STRING_BUF] = { 0 };
  gchar assured_session[WYL_ID_STRING_BUF] = { 0 };
  wyl_policy_store_t *store = NULL;
  guint status = 0;
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;

  if (wyl_id_new (&tenant_id) != WYRELOG_E_OK
      || wyl_id_new (&skip_id) != WYRELOG_E_OK
      || wyl_id_new (&assured_id) != WYRELOG_E_OK
      || wyl_id_format (&tenant_id, tenant_session, sizeof tenant_session)
      != WYRELOG_E_OK
      || wyl_id_format (&skip_id, skip_session, sizeof skip_session)
      != WYRELOG_E_OK
      || wyl_id_format (&assured_id, assured_session, sizeof assured_session)
      != WYRELOG_E_OK) {
    rc = 2530;
    goto out;
  }
  store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_set_principal_state (store, "tenant-local-admin",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_principal_state (store, "skip-mfa-admin",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_set_principal_state (store, "refresh-mfa-admin",
      "authenticated") != WYRELOG_E_OK) {
    rc = 2541;
    goto out;
  }

  if (!seed_human_tokens_with_assurance (env.http.server, tenant_session,
      "tenant-local-admin", "tenant-a", TRUE, &tenant_access,
      &tenant_refresh)
      || send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, tenant_access, NULL, &status,
      &body) != 0 || status != 403
      || body == NULL || strstr (body, "service_principal_denied") == NULL) {
    g_printerr ("WYRELOG_TEST_DIAG management_caller tenant_local status=%u "
        "body=%s\n", status, body != NULL ? body : "(null)");
    rc = 2531;
    goto out;
  }

  /* A valid live session id in the query never substitutes for Bearer. */
  g_clear_pointer (&body, g_free);
  session_query = g_strdup_printf
        ("session_token=%s&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0",
          env.session_token);
  if (send_raw_service_principal_full (env.session, "GET", env.base_url,
      "/service-principals", session_query, NULL, &status, &body) != 0
      || status != 401 || body == NULL
      || strstr (body, "service_principal_auth_required") == NULL) {
    rc = 2532;
    goto out;
  }

  if (!seed_human_tokens_with_assurance (env.http.server, skip_session,
      "skip-mfa-admin", WYL_TENANT_DEFAULT, FALSE, &skip_access,
      &skip_refresh)) {
    rc = 2533;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, skip_access, NULL, &status,
      &body) != 0 || status != 403 || body == NULL
      || strstr (body, "service_principal_denied") == NULL) {
    rc = 2534;
    goto out;
  }

  /* Refresh rotates tokens but cannot mint MFA assurance for a skip-MFA
   * session. The successor bearer remains denied by the live-session gate. */
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (env.session, "POST", env.base_url, skip_refresh,
      &status, &body) != 0 || status != 200 || body == NULL) {
    rc = 2535;
    goto out;
  }
  skip_refreshed_access = extract_json_string (body, "access_token");
  g_clear_pointer (&body, g_free);
  if (skip_refreshed_access == NULL
      || send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, skip_refreshed_access, NULL,
      &status, &body) != 0 || status != 403) {
    rc = 2536;
    goto out;
  }

  /* Conversely, refresh of an already MFA-assured live session preserves the
   * live assurance bit; the rotated token itself carries no authority to
   * elevate a different session. */
  if (!seed_human_tokens_with_assurance (env.http.server, assured_session,
      "refresh-mfa-admin", WYL_TENANT_DEFAULT, TRUE, &assured_access,
      &assured_refresh)) {
    rc = 2537;
    goto out;
  }
  if (wyl_policy_store_set_principal_state (store, "refresh-mfa-admin",
      "authenticated") != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (store, "refresh-mfa-admin",
      "wr.service_principal.manage", assured_session) != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (store, assured_session, "active")
      != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (store, "refresh-mfa-admin",
      "wr.service_principal.manage", assured_session, "armed")
      != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    rc = 2538;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_refresh (env.session, "POST", env.base_url, assured_refresh,
      &status, &body) != 0 || status != 200 || body == NULL) {
    rc = 2539;
    goto out;
  }
  assured_refreshed_access = extract_json_string (body, "access_token");
  g_clear_pointer (&body, g_free);
  if (assured_refreshed_access == NULL
      || send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, assured_refreshed_access, NULL,
      &status, &body) != 0 || status != 200) {
    rc = 2540;
    goto out;
  }

  rc = 0;
out:
  service_denial_env_clear (&env);
  return rc;
}

static wyrelog_error_t
management_checkpoint_mutate_authority (WylHandle *handle,
    const gchar *actor, const gchar *action, const gchar *session_id,
    const gchar *target_tenant, gpointer data)
{
  ManagementCheckpointProbe *probe = data;
  if (handle == NULL || actor == NULL || action == NULL || session_id == NULL
      || probe == NULL)
    return WYRELOG_E_INVALID;
  probe->calls++;
  if (probe->mutation == MANAGEMENT_CHECKPOINT_NOOP)
    return WYRELOG_E_OK;
  if (probe->mutation == MANAGEMENT_CHECKPOINT_SESSION_LOGGED_OUT) {
    /* Drive a full logout of the acting session to completion between the
     * front-door ALLOW and the decisive liveness load, flipping the atomic
     * lifecycle word to CLOSED so the relocated gate must fail closed. */
    if (probe->server == NULL
        || !wyl_daemon_http_mutate_service_session_for_test (probe->server,
        session_id, WYL_DAEMON_SERVICE_SESSION_INACTIVE, NULL, 0))
      return WYRELOG_E_INVALID;
    return WYRELOG_E_OK;
  }
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (probe->mutation == MANAGEMENT_CHECKPOINT_PERMISSION_DORMANT) {
    wyrelog_error_t rc = wyl_policy_store_set_permission_state (store, actor,
            action, session_id, "dormant");
    return rc == WYRELOG_E_OK ? wyl_handle_reload_engine_pair (handle) : rc;
  }
  if (target_tenant == NULL)
    return WYRELOG_E_INVALID;
  return wyl_policy_store_set_tenant_sealed (store, target_tenant, TRUE);
}

/* Pair the table-driven response matrix with observable no-effect canaries.
* These requests carry valid human authority and mutation-shaped bodies, so
* any accidental delegation would be able to consume limiter capacity,
* publish escrow material, advance an operation, or change service state. */
static gint
check_service_route_alias_no_effects (void)
{
  ServiceDenialEnv env = { 0 };
  wyl_service_principal_t principal = { 0 };
  wyl_service_credential_issue_result_t issued = { 0 };
  wyl_service_credential_t after = { 0 };
  g_autofree gchar *body = NULL;
  g_autofree gchar *issue_body = NULL;
  g_autofree gchar *rotate_body = NULL;
  g_autofree gchar *revoke_body = NULL;
  g_autofree gchar *token_body = NULL;
  g_autofree gchar *credential_id = NULL;
  g_autofree gchar *rotate_alias = NULL;
  g_autofree gchar *rotate_encoded_alias = NULL;
  g_autofree gchar *revoke_alias = NULL;
  g_autofree gchar *revoke_encoded_alias = NULL;
#ifdef WYL_HAS_FACT_STORE
  g_autofree gchar *reconcile_body = NULL;
#endif
  gchar principal_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar alias_issue_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar rotate_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar revoke_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  guint principal_before = 0;
  guint principal_after = 0;
  guint credential_before = 0;
  guint credential_after = 0;
  guint status = 0;
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;

  if (wyl_request_id_new (principal_request_id, sizeof principal_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (alias_issue_request_id,
      sizeof alias_issue_request_id) != WYRELOG_E_OK
      || wyl_request_id_new (rotate_request_id, sizeof rotate_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (revoke_request_id, sizeof revoke_request_id)
      != WYRELOG_E_OK
      || wyl_service_principal_create (env.handle, "svc:tenant-a:alias",
      "Alias canary", "human-principal-admin", principal_request_id,
      &principal) != WYRELOG_E_OK
      || wyl_service_credential_issue (env.handle, "svc:tenant-a:alias",
      "tenant-a", "human-principal-admin", issue_request_id,
      CONTRACT_FUTURE_EXPIRES_AT_US, &issued) != WYRELOG_E_OK
      || issued.credential.credential_id == NULL || issued.secret == NULL) {
    rc = 2270;
    goto out;
  }
  credential_id = g_strdup (issued.credential.credential_id);
  rotate_alias = g_strdup_printf ("/service-credentials/%s/rotate/x",
          credential_id);
  rotate_encoded_alias = g_strdup_printf
        ("/service-credentials/%s/rotate%%2Fx", credential_id);
  revoke_alias = g_strdup_printf ("/service-credentials/%s/x", credential_id);
  revoke_encoded_alias = g_strdup_printf ("/service-credentials/%s%%2Fx",
          credential_id);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  if (secret == NULL || secret_len == 0) {
    rc = 2271;
    goto out;
  }
  token_body = g_strdup_printf
        ("{\"credential_id\":\"%s\",\"credential_secret\":\"%.*s\"}",
          credential_id, (gint) secret_len, secret);
  issue_body = g_strdup_printf
        ("{\"version\":\"1\",\"tenant\":\"tenant-a\","
          "\"request_id\":\"%s\",\"destination\":\"alias-issue.json\","
          "\"expires_at_us\":\"%s\"}", alias_issue_request_id,
          CONTRACT_FUTURE_EXPIRES_AT_US_STR);
  rotate_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\","
          "\"destination\":\"alias-rotate.json\",\"expires_at_us\":\"%s\"}",
          rotate_request_id, CONTRACT_FUTURE_EXPIRES_AT_US_STR);
  revoke_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", revoke_request_id);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_before) != WYRELOG_E_OK
      || wyl_policy_store_foreach_service_credential (store,
      "svc:tenant-a:alias", "tenant-a", count_service_credentials_cb,
      &credential_before) != WYRELOG_E_OK) {
    rc = 2272;
    goto out;
  }
  const struct
  {
    const gchar *method;
    const gchar *path;
    const gchar *query;
    const gchar *body;
  } mutation_aliases[] = {
    {"POST", "/service-principals/", env.query,
     "{\"subject_id\":\"svc:tenant-a:unexpected\","
     "\"display_name\":\"Unexpected\"}"},
    {"POST", "/service-principals/svc:tenant-a:alias/credentials/x",
     env.tenant_query, issue_body},
    {"POST", "/service-principals/svc:tenant-a:alias/disable/x", env.query,
     revoke_body},
    {"POST", rotate_alias, env.tenant_query, rotate_body},
    {"DELETE", revoke_alias, env.tenant_query, revoke_body},
    {"POST", "/service-principals%2F", env.query,
     "{\"subject_id\":\"svc:tenant-a:unexpected-encoded\","
     "\"display_name\":\"Unexpected encoded\"}"},
    {"POST", "/service-principals/svc:tenant-a:alias/credentials%2Fx",
     env.tenant_query, issue_body},
    {"POST", "/service-principals/svc:tenant-a:alias/disable%2Fx", env.query,
     revoke_body},
    {"POST", rotate_encoded_alias, env.tenant_query, rotate_body},
    {"DELETE", revoke_encoded_alias, env.tenant_query, revoke_body},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (mutation_aliases); i++) {
    g_clear_pointer (&body, g_free);
    if (send_raw_service_principal_bearer (env.session,
        mutation_aliases[i].method, env.base_url, mutation_aliases[i].path,
        mutation_aliases[i].query, env.access_token,
        mutation_aliases[i].body, &status, &body) != 0
        || status != 404
        || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0) {
      rc = 2273 + (gint) i;
      goto out;
    }
  }

#ifdef WYL_HAS_AUDIT
  WylServiceExchangeLimiterSnapshot limiter_before = { 0 };
  WylServiceExchangeLimiterSnapshot limiter_after = { 0 };
  wyl_daemon_http_service_exchange_limiter_snapshot_for_test
    (env.http.server, &limiter_before);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/auth/service-token%2Fx", NULL, env.access_token, token_body,
      &status, &body) != 0 || status != 404
      || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0) {
    rc = 2280;
    goto out;
  }
  wyl_daemon_http_service_exchange_limiter_snapshot_for_test
    (env.http.server, &limiter_after);
  if (limiter_after.credential_bucket_count
      != limiter_before.credential_bucket_count
      || limiter_after.full_credential_bucket_count
      != limiter_before.full_credential_bucket_count
      || limiter_after.global_tokens != limiter_before.global_tokens
      || limiter_after.anonymous_tokens != limiter_before.anonymous_tokens) {
    rc = 2281;
    goto out;
  }
#endif

#ifdef WYL_HAS_FACT_STORE
  gchar operation_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  WylServiceCredentialOperationState state_before = 0;
  WylServiceCredentialOperationState state_after = 0;
  gint64 updated_before = 0;
  gint64 updated_after = 0;
  guint32 attempts_before = 0;
  guint32 attempts_after = 0;
  if (wyl_request_id_new (operation_request_id, sizeof operation_request_id)
      != WYRELOG_E_OK
      || seed_prepared_operation (env.operation_root, operation_request_id,
      WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:tenant-a:alias",
      "tenant-a", NULL) != 0
      || capture_operation_signature (env.operation_root,
      operation_request_id, &state_before, &updated_before,
      &attempts_before) != 0) {
    rc = 2282;
    goto out;
  }
  reconcile_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\","
          "\"operation\":\"issue\",\"target\":{"
          "\"subject\":\"svc:tenant-a:alias\",\"tenant\":\"tenant-a\"}}",
          operation_request_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-credential-operations/reconcile%2Fx", env.tenant_query,
      env.access_token, reconcile_body, &status, &body) != 0
      || status != 404
      || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0
      || capture_operation_signature (env.operation_root,
      operation_request_id, &state_after, &updated_after,
      &attempts_after) != 0
      || state_after != state_before || updated_after != updated_before
      || attempts_after != attempts_before) {
    rc = 2283;
    goto out;
  }
#endif

  if (wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK
      || wyl_policy_store_foreach_service_credential (store,
      "svc:tenant-a:alias", "tenant-a", count_service_credentials_cb,
      &credential_after) != WYRELOG_E_OK
      || principal_after != principal_before
      || credential_after != credential_before
      || env.publication.plan_calls != 0 || env.publication.stage_calls != 0
      || env.publication.commit_calls != 0
      || wyl_service_credential_get (env.handle, credential_id, &after)
      != WYRELOG_E_OK
      || g_strcmp0 (after.state, "active") != 0
      || after.revoked_at_us != 0 || after.revoked_by != NULL) {
    rc = 2284;
    goto out;
  }
  rc = 0;
out:
  wyl_service_credential_clear (&after);
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_principal_clear (&principal);
  service_denial_env_clear (&env);
  return rc;
}

/* Prove the WRITE-lease callback is not ceremonial: authority changes after
* the front-door ALLOW are observed synchronously before domain mutation. */
static gint
check_service_management_write_reauthorization_matrix (void)
{
  ServiceDenialEnv permission_env = { 0 };
  ServiceDenialEnv tenant_env = { 0 };
  g_autofree gchar *body = NULL;
  g_autofree gchar *credential_id = NULL;
  g_autofree gchar *credential_path = NULL;
  g_autofree gchar *revoke_body = NULL;
  wyl_service_principal_t principal = { 0 };
  wyl_service_credential_issue_result_t issued = { 0 };
  wyl_service_credential_t after = { 0 };
  gchar principal_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar revoke_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  ManagementCheckpointProbe permission_probe = {
    .mutation = MANAGEMENT_CHECKPOINT_PERMISSION_DORMANT,
  };
  ManagementCheckpointProbe tenant_probe = {
    .mutation = MANAGEMENT_CHECKPOINT_TARGET_SEALED,
  };
  guint principal_before = 0;
  guint principal_after = 0;
  wyl_policy_store_t *permission_store = NULL;
  guint status = 0;
  gint rc = service_denial_env_init (&permission_env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;

  permission_store = wyl_handle_get_policy_store (permission_env.handle);
  if (wyl_policy_store_foreach_service_principal (permission_store,
      count_service_principals_cb, &principal_before) != WYRELOG_E_OK) {
    rc = 2550;
    goto out;
  }
  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
    (permission_env.http.server, management_checkpoint_mutate_authority,
      &permission_probe);
  if (send_raw_service_principal_bearer (permission_env.session, "POST",
      permission_env.base_url, "/service-principals", permission_env.query,
      permission_env.access_token,
      "{\"subject_id\":\"svc:checkpoint:permission\","
      "\"display_name\":\"Denied\"}", &status, &body) != 0
      || status != 403 || body == NULL
      || strstr (body, "service_principal_denied") == NULL
      || permission_probe.calls != 1
      || wyl_policy_store_foreach_service_principal (permission_store,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK
      || principal_after != principal_before) {
    rc = 2551;
    goto out;
  }

  rc = service_denial_env_init (&tenant_env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  if (wyl_request_id_new (principal_request_id,
      sizeof principal_request_id) != WYRELOG_E_OK
      || wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (revoke_request_id, sizeof revoke_request_id)
      != WYRELOG_E_OK
      || wyl_service_principal_create (tenant_env.handle,
      "svc:checkpoint:tenant", "Tenant checkpoint",
      "human-principal-admin", principal_request_id, &principal)
      != WYRELOG_E_OK
      || wyl_service_credential_issue (tenant_env.handle,
      "svc:checkpoint:tenant", "tenant-a", "human-principal-admin",
      issue_request_id, CONTRACT_FUTURE_EXPIRES_AT_US, &issued)
      != WYRELOG_E_OK || issued.credential.credential_id == NULL) {
    rc = 2552;
    goto out;
  }
  credential_id = g_strdup (issued.credential.credential_id);
  credential_path = g_strdup_printf ("/service-credentials/%s", credential_id);
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_principal_clear (&principal);

  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
    (tenant_env.http.server, management_checkpoint_mutate_authority,
      &tenant_probe);
  revoke_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", revoke_request_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (tenant_env.session, "DELETE",
      tenant_env.base_url, credential_path, tenant_env.tenant_query,
      tenant_env.access_token, revoke_body, &status, &body) != 0
      || status != 404 || tenant_probe.calls != 1) {
    rc = 2553;
    goto out;
  }
  if (wyl_service_credential_get (tenant_env.handle, credential_id, &after)
      != WYRELOG_E_OK || g_strcmp0 (after.state, "active") != 0
      || after.revoked_at_us != 0 || after.revoked_by != NULL) {
    rc = 2554;
    goto out;
  }
  rc = 0;
out:
  wyl_service_credential_clear (&after);
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_principal_clear (&principal);
  service_denial_env_clear (&tenant_env);
  service_denial_env_clear (&permission_env);
  return rc;
}

/* Issue #758 deterministic barrier.  The one-shot reauthorization checkpoint
 * fires between the front-door ALLOW and the relocated decisive liveness load.
 * (a) logout-wins: the checkpoint drives a full logout of the acting session
 * (atomic flip to CLOSED); the management request must fail closed with ZERO
 * durable work, and a plain follow-up stays denied against the now-CLOSED word.
 * (b) mutation-wins: the checkpoint is a no-op; the mutation commits exactly
 * once.  (Post-commit re-authorization is a separate arming concern; #758's
 * word-level consistency after logout is proven by (a) here and by the
 * multithreaded session-liveness-race postcondition.) */
static gint
check_service_management_logout_liveness_barrier (void)
{
  ServiceDenialEnv logout_env = { 0 };
  ServiceDenialEnv commit_env = { 0 };
  g_autofree gchar *body = NULL;
  guint principal_before = 0;
  guint principal_after = 0;
  guint status = 0;
  wyl_policy_store_t *store = NULL;
  ManagementCheckpointProbe logout_probe = {
    .mutation = MANAGEMENT_CHECKPOINT_SESSION_LOGGED_OUT,
  };
  ManagementCheckpointProbe commit_probe = {
    .mutation = MANAGEMENT_CHECKPOINT_NOOP,
  };
  gint rc = service_denial_env_init (&logout_env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;

  /* (a) logout-wins. */
  logout_probe.server = logout_env.http.server;
  store = wyl_handle_get_policy_store (logout_env.handle);
  if (wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_before) != WYRELOG_E_OK) {
    rc = 2560;
    goto out;
  }
  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
    (logout_env.http.server, management_checkpoint_mutate_authority,
      &logout_probe);
  if (send_raw_service_principal_bearer (logout_env.session, "POST",
      logout_env.base_url, "/service-principals", logout_env.query,
      logout_env.access_token,
      "{\"subject_id\":\"svc:barrier:loser\","
      "\"display_name\":\"LogoutWins\"}", &status, &body) != 0
      || status != 403 || body == NULL || logout_probe.calls != 1
      || wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK
      || principal_after != principal_before) {
    rc = 2561;
    goto out;
  }

  /* The seam is one-shot; a follow-up request now sees a genuinely CLOSED
   * session and stays denied without any checkpoint at all. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (logout_env.session, "POST",
      logout_env.base_url, "/service-principals", logout_env.query,
      logout_env.access_token,
      "{\"subject_id\":\"svc:barrier:loser2\","
      "\"display_name\":\"StillOut\"}", &status, &body) != 0
      || status == 200
      || wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK
      || principal_after != principal_before) {
    rc = 2562;
    goto out;
  }

  /* (b) mutation-wins on a fresh env: the checkpoint no-ops, so the mutation
   * commits exactly once. */
  rc = service_denial_env_init (&commit_env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  commit_probe.server = commit_env.http.server;
  store = wyl_handle_get_policy_store (commit_env.handle);
  if (wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_before) != WYRELOG_E_OK) {
    rc = 2563;
    goto out;
  }
  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
    (commit_env.http.server, management_checkpoint_mutate_authority,
      &commit_probe);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (commit_env.session, "POST",
      commit_env.base_url, "/service-principals", commit_env.query,
      commit_env.access_token,
      "{\"subject_id\":\"svc:barrier:winner\","
      "\"display_name\":\"MutationWins\"}", &status, &body) != 0
      || status != 200 || body == NULL || commit_probe.calls != 1
      || strstr (body, "\"service_principal\":") == NULL
      || strstr (body, "\"subject_id\":\"svc:barrier:winner\"") == NULL
      || wyl_policy_store_foreach_service_principal (store,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK
      || principal_after != principal_before + 1) {
    rc = 2564;
    goto out;
  }
  rc = 0;
out:
  service_denial_env_clear (&commit_env);
  service_denial_env_clear (&logout_env);
  return rc;
}

static gboolean
service_management_body_leaks_secret (const gchar *body,
    const gchar *first_canary, const gchar *second_canary)
{
  return body == NULL || strstr (body, "credential_secret") != NULL
         || strstr (body, "secret=") != NULL
         || (first_canary != NULL && strstr (body, first_canary) != NULL)
         || (second_canary != NULL && strstr (body, second_canary) != NULL);
}

/* Every exact management route must consume the real loopback listener/peer
 * tuple and ignore proxy-controlled address headers. The fact-enabled build
 * adds the three operation routes, completing the eleven-route matrix. */
static gint
check_service_management_loopback_forwarded_matrix (void)
{
  ServiceDenialEnv env = { 0 };
  g_autofree gchar *body = NULL;
  g_autofree gchar *issue_body = NULL;
  g_autofree gchar *rotate_body = NULL;
  g_autofree gchar *revoke_body = NULL;
  g_autofree gchar *credential_id = NULL;
  g_autofree gchar *credential_path = NULL;
  g_autofree gchar *rotate_path = NULL;
  g_autofree gchar *successor_id = NULL;
  g_autofree gchar *successor_path = NULL;
  g_autofree gchar *issue_secret = NULL;
  g_autofree gchar *rotate_secret = NULL;
#ifdef WYL_HAS_FACT_STORE
  g_autofree gchar *reconcile_body = NULL;
  g_autofree gchar *recover_body = NULL;
  g_autofree gchar *recover_access = NULL;
  g_autofree gchar *recover_refresh = NULL;
  wyl_id_t recover_session_id = WYL_ID_NIL;
  gchar recover_session[WYL_ID_STRING_BUF] = { 0 };
  gchar recover_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  ManagementCheckpointProbe recover_probe = {
    .mutation = MANAGEMENT_CHECKPOINT_NOOP,
  };
#endif
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar rotate_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar revoke_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  guint status = 0;
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  if (wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (rotate_request_id, sizeof rotate_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (revoke_request_id, sizeof revoke_request_id)
      != WYRELOG_E_OK) {
    rc = 2560;
    goto out;
  }

  /* 1: principal create. */
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url, "/service-principals", env.query, env.access_token,
      "{\"subject_id\":\"svc:forwarded:matrix\","
      "\"display_name\":\"Forwarded matrix\"}", &status, &body) != 0
      || status != 200 || service_management_body_leaks_secret (body, NULL,
      NULL)) {
    rc = 2561;
    goto out;
  }

  /* 2: global principal list. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "GET",
      env.base_url, "/service-principals", env.query, env.access_token,
      NULL, &status, &body) != 0 || status != 200
      || strstr (body, "svc:forwarded:matrix") == NULL
      || service_management_body_leaks_secret (body, NULL, NULL)) {
    rc = 2562;
    goto out;
  }

  /* 4: credential issue (disable is ordered last so the principal remains
   * active for the credential matrix). */
  issue_body = g_strdup_printf
        ("{\"version\":\"1\",\"tenant\":\"tenant-a\","
          "\"request_id\":\"%s\",\"destination\":\"forwarded-issue.json\","
          "\"expires_at_us\":\"%s\"}", issue_request_id,
          CONTRACT_FUTURE_EXPIRES_AT_US_STR);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url,
      "/service-principals/svc:forwarded:matrix/credentials",
      env.tenant_query, env.access_token, issue_body, &status, &body) != 0
      || status != 200 || env.publication.staged_secret == NULL
      || service_management_body_leaks_secret (body,
      env.publication.staged_secret, NULL)) {
    rc = 2563;
    goto out;
  }
  issue_secret = g_strdup (env.publication.staged_secret);
  credential_id = extract_json_string (body, "credential_id");
  if (credential_id == NULL) {
    rc = 2564;
    goto out;
  }
  credential_path = g_strdup_printf ("/service-credentials/%s", credential_id);

  /* 5: principal credential list. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "GET",
      env.base_url,
      "/service-principals/svc:forwarded:matrix/credentials",
      env.tenant_query, env.access_token, NULL, &status, &body) != 0
      || status != 200 || strstr (body, credential_id) == NULL
      || service_management_body_leaks_secret (body, issue_secret, NULL)) {
    rc = 2565;
    goto out;
  }

  /* 6: credential metadata. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "GET",
      env.base_url, credential_path, env.tenant_query, env.access_token,
      NULL, &status, &body) != 0 || status != 200
      || strstr (body, credential_id) == NULL
      || service_management_body_leaks_secret (body, issue_secret, NULL)) {
    rc = 2566;
    goto out;
  }

  /* 7: rotate. Reset only the mock publication observation; durable operation
   * and policy state remain untouched. */
  g_clear_pointer (&env.publication.staged_secret, g_free);
  memset (&env.publication, 0, sizeof env.publication);
  rotate_path = g_strdup_printf ("/service-credentials/%s/rotate",
          credential_id);
  rotate_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\","
          "\"destination\":\"forwarded-rotate.json\","
          "\"expires_at_us\":\"%s\"}", rotate_request_id,
          CONTRACT_FUTURE_EXPIRES_AT_US_STR);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url, rotate_path, env.tenant_query, env.access_token,
      rotate_body, &status, &body) != 0 || status != 200
      || env.publication.staged_secret == NULL
      || service_management_body_leaks_secret (body, issue_secret,
      env.publication.staged_secret)) {
    rc = 2567;
    goto out;
  }
  rotate_secret = g_strdup (env.publication.staged_secret);
  successor_id = extract_json_string (body, "credential_id");
  if (successor_id == NULL) {
    rc = 2568;
    goto out;
  }
  successor_path = g_strdup_printf ("/service-credentials/%s", successor_id);

#ifdef WYL_HAS_FACT_STORE
  /* 9: operation status collection. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "GET",
      env.base_url, "/service-credential-operations", env.tenant_query,
      env.access_token, NULL, &status, &body) != 0 || status != 200
      || strstr (body, issue_request_id) == NULL
      || strstr (body, rotate_request_id) == NULL
      || service_management_body_leaks_secret (body, issue_secret,
      rotate_secret)) {
    rc = 2569;
    goto out;
  }

  /* 10: exact reconcile. */
  reconcile_body = g_strdup_printf
        ("{\"version\":1,\"request_id\":\"%s\",\"operation\":\"issue\","
          "\"target\":{\"subject\":\"svc:forwarded:matrix\","
          "\"tenant\":\"tenant-a\"}}", issue_request_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url, "/service-credential-operations/reconcile",
      env.tenant_query, env.access_token, reconcile_body, &status, &body)
      != 0 || status != 200 || strstr (body, issue_request_id) == NULL
      || service_management_body_leaks_secret (body, issue_secret,
      rotate_secret)) {
    rc = 2570;
    goto out;
  }

  /* 11: durable operation recovery. */
  if (wyl_request_id_new (recover_request_id, sizeof recover_request_id)
      != WYRELOG_E_OK
      || seed_prepared_operation (env.operation_root, recover_request_id,
      WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:forwarded:matrix",
      "tenant-a", NULL) != 0) {
    rc = 2576;
    goto out;
  }
  recover_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", recover_request_id);
  /* Reconcile performs both its front-door and WRITE-lease decisions. Rearm
   * the deterministic permission fixture so recover independently proves its
   * own envelope rather than inheriting the decision-state transition. */
  wyl_policy_store_t *matrix_store = wyl_handle_get_policy_store (env.handle);
  if (wyl_id_new (&recover_session_id) != WYRELOG_E_OK
      || wyl_id_format (&recover_session_id, recover_session,
      sizeof recover_session) != WYRELOG_E_OK
      || wyl_policy_store_grant_direct_permission (matrix_store,
      "human-principal-admin", "wr.service_credential.manage",
      recover_session) != WYRELOG_E_OK
      || wyl_policy_store_set_session_state (matrix_store, recover_session,
      "active") != WYRELOG_E_OK
      || wyl_policy_store_set_permission_state (matrix_store,
      "human-principal-admin", "wr.service_credential.manage",
      recover_session, "armed") != WYRELOG_E_OK
      || wyl_handle_reload_engine_pair (env.handle) != WYRELOG_E_OK) {
    rc = 2574;
    goto out;
  }
  if (!seed_human_tokens_with_assurance (env.http.server, recover_session,
      "human-principal-admin", WYL_TENANT_DEFAULT, TRUE, &recover_access,
      &recover_refresh)) {
    rc = 2575;
    goto out;
  }
  wyl_daemon_http_set_management_reauthorization_checkpoint_for_test
    (env.http.server, management_checkpoint_mutate_authority, &recover_probe);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url, "/service-credential-operations/recover",
      env.tenant_query, recover_access, recover_body, &status, &body)
      != 0 || status != 200 || strstr (body, recover_request_id) == NULL
      || recover_probe.calls != 1
      || service_management_body_leaks_secret (body, issue_secret,
      rotate_secret)) {
    g_printerr ("WYRELOG_TEST_DIAG management_forwarded recover status=%u "
        "checkpoint_calls=%u body=%s\n", status, recover_probe.calls,
        body != NULL ? body : "(null)");
    rc = 2571;
    goto out;
  }
#endif

  /* 8: revoke the successor. */
  revoke_body = g_strdup_printf
        ("{\"version\":\"1\",\"request_id\":\"%s\"}", revoke_request_id);
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "DELETE",
      env.base_url, successor_path, env.tenant_query, env.access_token,
      revoke_body, &status, &body) != 0 || status != 200
      || service_management_body_leaks_secret (body, issue_secret,
      rotate_secret)) {
    rc = 2572;
    goto out;
  }

  /* 3: principal disable. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_management_forwarded_spoof (env.session, "POST",
      env.base_url, "/service-principals/svc:forwarded:matrix/disable",
      env.query, env.access_token,
      "{\"version\":\"1\",\"request_id\":"
      "\"000000000000000000000000226\"}", &status, &body) != 0
      || status != 200 || strstr (body, "\"state\":\"disabled\"") == NULL
      || service_management_body_leaks_secret (body, issue_secret,
      rotate_secret)) {
    rc = 2573;
    goto out;
  }
  rc = 0;
out:
  service_denial_env_clear (&env);
  return rc;
}

/* Principal identity is global. A subject string that looks tenant-scoped may
 * own credentials in multiple targets; only stored tenant_id controls list and
 * metadata visibility. */
static gint
check_service_management_global_principal_cross_tenant (void)
{
  ServiceDenialEnv env = { 0 };
  wyl_service_principal_t principal = { 0 };
  wyl_service_credential_issue_result_t tenant_a = { 0 };
  wyl_service_credential_issue_result_t tenant_b = { 0 };
  g_autofree gchar *body = NULL;
  g_autofree gchar *tenant_b_query = NULL;
  g_autofree gchar *tenant_a_id = NULL;
  g_autofree gchar *tenant_b_id = NULL;
  g_autofree gchar *tenant_b_path = NULL;
  gchar principal_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar tenant_a_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  gchar tenant_b_request_id[WYL_REQUEST_ID_STRING_BUF] = { 0 };
  guint status = 0;
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;

  gboolean created = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_create_tenant (store, "tenant-b", &created)
      != WYRELOG_E_OK || !created
      || wyl_request_id_new (principal_request_id,
      sizeof principal_request_id) != WYRELOG_E_OK
      || wyl_request_id_new (tenant_a_request_id,
      sizeof tenant_a_request_id) != WYRELOG_E_OK
      || wyl_request_id_new (tenant_b_request_id,
      sizeof tenant_b_request_id) != WYRELOG_E_OK
      || wyl_service_principal_create (env.handle,
      "svc:tenant-a:misleading-global", "Global principal",
      "human-principal-admin", principal_request_id, &principal)
      != WYRELOG_E_OK
      || wyl_service_credential_issue (env.handle,
      "svc:tenant-a:misleading-global", "tenant-a",
      "human-principal-admin", tenant_a_request_id,
      CONTRACT_FUTURE_EXPIRES_AT_US, &tenant_a) != WYRELOG_E_OK
      || wyl_service_credential_issue (env.handle,
      "svc:tenant-a:misleading-global", "tenant-b",
      "human-principal-admin", tenant_b_request_id,
      CONTRACT_FUTURE_EXPIRES_AT_US, &tenant_b) != WYRELOG_E_OK
      || tenant_a.credential.credential_id == NULL
      || tenant_b.credential.credential_id == NULL) {
    rc = 2580;
    goto out;
  }
  tenant_a_id = g_strdup (tenant_a.credential.credential_id);
  tenant_b_id = g_strdup (tenant_b.credential.credential_id);
  tenant_b_path = g_strdup_printf ("/service-credentials/%s", tenant_b_id);
  tenant_b_query = g_strdup
        ("tenant=tenant-b&guard_timestamp=1&guard_loc_class=trusted&guard_risk=0");

  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, env.access_token, NULL, &status,
      &body) != 0 || status != 200
      || strstr (body, "svc:tenant-a:misleading-global") == NULL) {
    rc = 2581;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals/svc:tenant-a:misleading-global/credentials",
      env.tenant_query, env.access_token, NULL, &status, &body) != 0
      || status != 200 || strstr (body, tenant_a_id) == NULL
      || strstr (body, tenant_b_id) != NULL) {
    rc = 2582;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals/svc:tenant-a:misleading-global/credentials",
      tenant_b_query, env.access_token, NULL, &status, &body) != 0
      || status != 200 || strstr (body, tenant_b_id) == NULL
      || strstr (body, tenant_a_id) != NULL) {
    rc = 2583;
    goto out;
  }

  /* Known credential plus wrong target collapses to the same 404 family as an
   * unknown id; the response does not echo the known id. */
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      tenant_b_path, env.tenant_query, env.access_token, NULL, &status,
      &body) != 0 || status != 404 || body == NULL
      || strstr (body, "service_credential_not_found") == NULL
      || strstr (body, tenant_b_id) != NULL) {
    rc = 2584;
    goto out;
  }
  rc = 0;
out:
  wyl_service_credential_issue_result_clear (&tenant_b);
  wyl_service_credential_issue_result_clear (&tenant_a);
  wyl_service_principal_clear (&principal);
  service_denial_env_clear (&env);
  return rc;
}

#ifdef WYL_HAS_AUDIT
/*
 * Unit 2 (#374 gap 1a): a valid service bearer -- the credential's own
 * access token -- is not an active human session, so every management
 * endpoint denies it at the is_active_human gate.  The bearer carries the
 * credential's tenant, so &tenant=tenant-a clears the request-tenant gate
 * and the request reaches the is_active_human 403 (rather than tenant_denied).
 * A principal disable and a credential rotate must both 403 with the wire
 * denial token.  The rotate is the mutating op whose credential row count is
 * snapshotted (the disable mutates principal STATE, not row count, so a count
 * around it would be illusory -- the 403 token is its proof).
 */
static gint
check_service_management_bearer_denied (void)
{
  ServiceDenialEnv env = { 0 };
  wyl_service_principal_t principal = { 0 };
  wyl_service_credential_issue_result_t issued = { 0 };
  g_autofree gchar *pub_body = NULL;
  g_autofree gchar *access_token = NULL;
  g_autofree gchar *body = NULL;
  g_autofree gchar *rotate_path = NULL;
  g_autofree gchar *bearer_query = NULL;
  guint status = 0;
  guint credential_before = 0;
  guint credential_after = 0;
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF];
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  if (wyl_request_id_new (request_id, sizeof request_id) != WYRELOG_E_OK
      || wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK) {
    rc = 2210;
    goto out;
  }
  if (wyl_service_principal_create (env.handle, "svc:tenant-a:worker",
      "Worker", "human-principal-admin", request_id, &principal)
      != WYRELOG_E_OK) {
    rc = 2211;
    goto out;
  }
  if (wyl_service_credential_issue (env.handle, "svc:tenant-a:worker",
      "tenant-a", "human-principal-admin", issue_request_id,
      CONTRACT_FUTURE_EXPIRES_AT_US, &issued) != WYRELOG_E_OK
      || issued.credential.credential_id == NULL || issued.secret == NULL) {
    rc = 2212;
    goto out;
  }
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  if (secret == NULL) {
    rc = 2213;
    goto out;
  }
  if (wyl_daemon_http_publish_service_token_for_test (env.http.server,
      issued.credential.credential_id, secret, secret_len, &pub_body)
      != WYRELOG_E_OK || pub_body == NULL
      || (access_token = extract_json_string (pub_body, "access_token"))
      == NULL) {
    rc = 2214;
    goto out;
  }

  wyl_policy_store_t *store = wyl_handle_get_policy_store (env.handle);
  if (wyl_policy_store_foreach_service_credential (store,
      "svc:tenant-a:worker", "tenant-a", count_service_credentials_cb,
      &credential_before) != WYRELOG_E_OK) {
    rc = 2215;
    goto out;
  }

  bearer_query = g_strdup_printf ("tenant=tenant-a&guard_timestamp=1&"
          "guard_loc_class=trusted&guard_risk=0");
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      "/service-principals/svc:tenant-a:worker/disable", bearer_query,
      access_token, NULL, &status, &body) != 0 || status != 403
      || body == NULL || strstr (body, "service_principal_denied") == NULL) {
    rc = 2216;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  rotate_path = g_strdup_printf ("/service-credentials/%s/rotate",
          issued.credential.credential_id);
  if (send_raw_service_principal_bearer (env.session, "POST", env.base_url,
      rotate_path, bearer_query, access_token,
      "{\"version\":\"1\",\"request_id\":\"333333333333333333333333333\","
      "\"destination\":\"rotate.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}", &status, &body) != 0
      || status != 403 || body == NULL
      || strstr (body, "service_credential_denied") == NULL) {
    rc = 2217;
    goto out;
  }

  if (wyl_policy_store_foreach_service_credential (store,
      "svc:tenant-a:worker", "tenant-a", count_service_credentials_cb,
      &credential_after) != WYRELOG_E_OK) {
    rc = 2218;
    goto out;
  }
  if (credential_after != credential_before) {
    rc = 2219;
    goto out;
  }
out:
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_principal_clear (&principal);
  service_denial_env_clear (&env);
  return rc;
}
#endif

/*
 * Unit 3 (#374 gap 1b): a resolvable human session whose in-memory state is
 * not ACTIVE must be denied at the is_active_human gate (http.c:~5052,
 * wyl_session_is_active_human_private requires state == ACTIVE && auth_method
 * == HUMAN).  The environment is fully armed with the session-active fact set,
 * so wyl_decide would ALLOW; the sole cause of denial is re-seeding the
 * in-memory human session into a non-ACTIVE (CLOSED) state via the
 * seed_human_session_with_state seam.  resolve_session_token_auth still
 * resolves it (username and tenant are present and it ignores session state),
 * so the request reaches -- and 403s at -- the is_active_human gate rather
 * than the decide gate.  A principal list and a credential read must both 403
 * with the wire denial token.
 */
static gint
check_service_management_inactive_session_denied (void)
{
  ServiceDenialEnv env = { 0 };
  g_autofree gchar *body = NULL;
  guint status = 0;
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  /* Force the resolvable human session into a non-ACTIVE in-memory state so
   * the only remaining denial is the is_active_human gate. */
  if (!wyl_daemon_http_seed_human_session_with_state_for_test (env.http.server,
      env.session_token, "human-principal-admin", WYL_TENANT_DEFAULT,
      WYL_SESSION_STATE_CLOSED)) {
    rc = 2300;
    goto out;
  }
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals", env.query, env.access_token, NULL, &status,
      &body) != 0
      || status != 403 || body == NULL
      || strstr (body, "service_principal_denied") == NULL) {
    rc = 2301;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-credentials/wlc_000000000000000000000000000",
      env.tenant_query, env.access_token, NULL, &status, &body) != 0
      || status != 403
      || body == NULL || strstr (body, "service_credential_denied") == NULL) {
    rc = 2302;
    goto out;
  }
out:
  service_denial_env_clear (&env);
  return rc;
}

/*
 * Unit 4 (#374 gaps 1d + 2): the two management actions map to distinct
 * permissions -- wr.service_principal.manage and wr.service_credential.manage
 * -- and arming one must never authorize the other.  Direction A arms only
 * credential.manage: a principal write is denied (service_principal_denied)
 * while a credential read is authorized (not 403, not service_credential_
 * denied).  Direction B arms only principal.manage and inverts the roles.  No
 * body leaks a secret and the denied mutating op changes no row count.
 */
static gint
check_service_management_permission_mapping (void)
{
  ServiceDenialEnv env_a = { 0 };
  ServiceDenialEnv env_b = { 0 };
  g_autofree gchar *body = NULL;
  guint status = 0;
  guint principal_before = 0;
  guint principal_after = 0;
  guint credential_before = 0;
  guint credential_after = 0;
  gint rc = 0;

  /* Direction A: principal.manage granted-unarmed, credential.manage armed. */
  rc = service_denial_env_init (&env_a, TRUE, FALSE, TRUE);
  if (rc != 0)
    goto out;
  wyl_policy_store_t *store_a = wyl_handle_get_policy_store (env_a.handle);
  if (wyl_policy_store_foreach_service_principal (store_a,
      count_service_principals_cb, &principal_before) != WYRELOG_E_OK) {
    rc = 2400;
    goto out;
  }
  if (send_raw_service_principal_bearer (env_a.session, "POST", env_a.base_url,
      "/service-principals", env_a.query,
      env_a.access_token,
      "{\"subject_id\":\"svc:tenant-a:worker\",\"display_name\":\"x\"}",
      &status, &body) != 0 || status != 403 || body == NULL
      || strstr (body, "service_principal_denied") == NULL) {
    rc = 2401;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  /* Control: the credential action is authorized (404 not-found, never a
   * 403 denial), proving the armed principal permission is not consulted. */
  if (send_raw_service_principal_bearer (env_a.session, "GET", env_a.base_url,
      "/service-credentials/wlc_000000000000000000000000000",
      env_a.tenant_query, env_a.access_token, NULL, &status, &body) != 0
      || status == 403
      || body == NULL || strstr (body, "service_credential_denied") != NULL) {
    rc = 2402;
    goto out;
  }
  if (wyl_policy_store_foreach_service_principal (store_a,
      count_service_principals_cb, &principal_after) != WYRELOG_E_OK) {
    rc = 2403;
    goto out;
  }
  if (principal_after != principal_before) {
    rc = 2404;
    goto out;
  }

  /* Direction B: principal.manage armed, credential.manage granted-unarmed. */
  rc = service_denial_env_init (&env_b, TRUE, TRUE, FALSE);
  if (rc != 0)
    goto out;
  wyl_policy_store_t *store_b = wyl_handle_get_policy_store (env_b.handle);
  if (wyl_policy_store_foreach_service_credential (store_b,
      "svc:tenant-a:worker", "tenant-a", count_service_credentials_cb,
      &credential_before) != WYRELOG_E_OK) {
    rc = 2405;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  if (send_raw_service_principal_bearer (env_b.session, "POST", env_b.base_url,
      "/service-credentials/wlc_000000000000000000000000000/rotate",
      env_b.tenant_query, env_b.access_token,
      "{\"version\":\"1\",\"request_id\":\"333333333333333333333333333\","
      "\"destination\":\"rotate.json\",\"expires_at_us\":\""
      CONTRACT_FUTURE_EXPIRES_AT_US_STR "\"}", &status, &body) != 0
      || status != 403 || body == NULL
      || strstr (body, "service_credential_denied") == NULL) {
    rc = 2406;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  /* Control: the principal action is authorized (200 list, never a 403). */
  if (send_raw_service_principal_bearer (env_b.session, "GET", env_b.base_url,
      "/service-principals", env_b.query, env_b.access_token, NULL,
      &status, &body) != 0
      || status == 403 || body == NULL
      || strstr (body, "service_principal_denied") != NULL) {
    rc = 2407;
    goto out;
  }
  if (wyl_policy_store_foreach_service_credential (store_b,
      "svc:tenant-a:worker", "tenant-a", count_service_credentials_cb,
      &credential_after) != WYRELOG_E_OK) {
    rc = 2408;
    goto out;
  }
  if (credential_after != credential_before) {
    rc = 2409;
    goto out;
  }
out:
  service_denial_env_clear (&env_b);
  service_denial_env_clear (&env_a);
  return rc;
}

/*
 * Unit 5 (#374 gap 3): the read endpoints must surface a live credential's
 * metadata without ever echoing its one-time secret.  Issue a real,
 * non-revoked credential and capture its plaintext, then read it back two
 * ways -- the single-credential GET and the per-principal credentials list.
 * Both must return 200 with the credential id present (proving the payload is
 * populated, not empty), yet never contain the plaintext secret bytes.
 */
static gint
check_service_management_populated_secret_leak (void)
{
  ServiceDenialEnv env = { 0 };
  wyl_service_principal_t principal = { 0 };
  wyl_service_credential_issue_result_t issued = { 0 };
  g_autofree gchar *plaintext = NULL;
  g_autofree gchar *credential_path = NULL;
  g_autofree gchar *body = NULL;
  guint status = 0;
  gchar principal_request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar issue_request_id[WYL_REQUEST_ID_STRING_BUF];
  gint rc = service_denial_env_init (&env, TRUE, TRUE, TRUE);
  if (rc != 0)
    goto out;
  if (wyl_request_id_new (principal_request_id, sizeof principal_request_id)
      != WYRELOG_E_OK
      || wyl_request_id_new (issue_request_id, sizeof issue_request_id)
      != WYRELOG_E_OK) {
    rc = 2500;
    goto out;
  }
  if (wyl_service_principal_create (env.handle, "svc:tenant-a:worker",
      "Worker", "human-principal-admin", principal_request_id, &principal)
      != WYRELOG_E_OK) {
    rc = 2501;
    goto out;
  }
  if (wyl_service_credential_issue (env.handle, "svc:tenant-a:worker",
      "tenant-a", "human-principal-admin", issue_request_id,
      CONTRACT_FUTURE_EXPIRES_AT_US, &issued) != WYRELOG_E_OK
      || issued.credential.credential_id == NULL || issued.secret == NULL) {
    rc = 2502;
    goto out;
  }
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
  if (secret == NULL || secret_len == 0) {
    rc = 2503;
    goto out;
  }
  plaintext = g_strndup (secret, secret_len);

  /* Single-credential read: populated 200 that never carries the secret. */
  credential_path = g_strdup_printf ("/service-credentials/%s",
          issued.credential.credential_id);
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      credential_path, env.tenant_query, env.access_token, NULL, &status,
      &body) != 0
      || status != 200 || body == NULL
      || strstr (body, issued.credential.credential_id) == NULL
      || strstr (body, plaintext) != NULL) {
    rc = 2504;
    goto out;
  }
  g_clear_pointer (&body, g_free);
  /* Per-principal credentials list: a non-empty array naming the credential,
   * still with no secret anywhere in the body. */
  if (send_raw_service_principal_bearer (env.session, "GET", env.base_url,
      "/service-principals/svc:tenant-a:worker/credentials",
      env.tenant_query, env.access_token, NULL, &status, &body) != 0
      || status != 200
      || body == NULL
      || strstr (body, "\"service_credentials\":[") == NULL
      || strstr (body, issued.credential.credential_id) == NULL
      || strstr (body, plaintext) != NULL) {
    rc = 2505;
    goto out;
  }
out:
  wyl_service_credential_issue_result_clear (&issued);
  wyl_service_principal_clear (&principal);
  service_denial_env_clear (&env);
  return rc;
}

/*
 * Unit-style coverage for the tenant-gate wire codes. Drives the
 * http.c decision helper through the WYL_TEST_DAEMON_HTTP seam so
 * that both stable gate arms are exercised directly.
 */
static gint
check_tenant_gate_codes_contract (void)
{
  /* Pass: matching default tenant on both sides. */
  guint status = 0;
  g_autofree gchar *code = NULL;
  if (!wyl_daemon_http_check_request_tenant_for_test ("__wr_default",
      "__wr_default", &status, &code))
    return 1900;
  if (status != 0 || code != NULL)
    return 1901;

  /* Pass: NULL request tenant falls back to the default, matches auth. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (!wyl_daemon_http_check_request_tenant_for_test (NULL, "__wr_default",
      &status, &code))
    return 1902;
  if (status != 0 || code != NULL)
    return 1903;

  /* Reject: request tenant is not known to the test seam. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("unknown",
      "__wr_default", &status, &code))
    return 1904;
  if (status != 400 || g_strcmp0 (code, "tenant_invalid") != 0)
    return 1905;

  /* Reject: empty request tenant. 400 tenant_invalid. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("", "__wr_default",
      &status, &code))
    return 1906;
  if (status != 400 || g_strcmp0 (code, "tenant_invalid") != 0)
    return 1907;

  /*
   * Reject: request tenant is the known default but the authenticated
   * principal carries a different tenant. 403 tenant_denied.
   */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("__wr_default",
      "other-tenant", &status, &code))
    return 1908;
  if (status != 403 || g_strcmp0 (code, "tenant_denied") != 0)
    return 1909;

  /* Reject: missing auth tenant on a default-tenant request. 403 tenant_denied. */
  g_clear_pointer (&code, g_free);
  status = 0;
  if (wyl_daemon_http_check_request_tenant_for_test ("__wr_default", NULL,
      &status, &code))
    return 1910;
  if (status != 403 || g_strcmp0 (code, "tenant_denied") != 0)
    return 1911;

  return 0;
}

/*
 * The daemon-http-decide test surface has been split across four binaries
 * compiled from this single translation unit:
 *
 *   - WYL_TEST_VARIANT_AUDIT undefined: HTTP-decide protocol contracts
 *     (readyz, request-id headers, raw decide, policy mutation, login + decide,
 *     and login + guarded-decide).
 *
 *   - WYL_TEST_VARIANT_REFRESH defined: the explicit refresh dispatch-context
 *     check plus the raw-login, JWT-rotation, and human-refresh shutdown
 *     flows that would otherwise push the non-audit binary over the wall-clock
 *     ceiling on slower CI runners.
 *
 *   - WYL_TEST_VARIANT_SERVICE defined: the service access-token state and
 *     bearer-resolver contracts that are heavy enough to deserve their own
 *     binary on slower CI runners.
 *
 *   - WYL_TEST_VARIANT_AUDIT defined: end-to-end audit pipeline. Generates
 *     the decide and policy events the audit verification depends on, then
 *     verifies the audit log via raw HTTP, the readyz audit-projection
 *     contract, and a series of audit_event_present queries.
 *
 * Splitting was driven by Meson's per-test timeout and the slower macOS CI
 * runner: the merged surface serialised on local TCP and DuckDB, and the
 * refresh-heavy tail could overrun the wall-clock ceiling. The binaries now
 * run in parallel, each with its own daemon, and each finishes well under
 * the timeout. Variant-irrelevant static helpers stay defined in this file;
 * the build silences the resulting -Wunused-function warnings.
 */
#if defined(WYL_TEST_VARIANT_REFRESH)
int
main (void)
{
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  gint policy_shutdown_rc = check_daemon_policy_write_shutdown_contract ();
  if (policy_shutdown_rc != 0)
    return policy_shutdown_rc;

  gint policy_cancellable_rc =
      check_daemon_policy_write_cancellable_contract ();
  if (policy_cancellable_rc != 0)
    return policy_cancellable_rc;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 2;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return 10;
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 11;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  gint dispatch_context_rc = check_explicit_refresh_dispatch_context (handle,
          &runtime);
  if (dispatch_context_rc != 0)
    return dispatch_context_rc;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide-refresh",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint read_only_method_rc = check_read_only_method_contract (base_url);
  if (read_only_method_rc != 0)
    return read_only_method_rc;

  if (wyl_policy_store_grant_direct_permission (wyl_handle_get_policy_store
        (handle), "login-user", "wr.login.skip_mfa", "login")
      != WYRELOG_E_OK)
    return 15;
  if (wyl_policy_store_set_permission_state (wyl_handle_get_policy_store
        (handle), "login-user", "wr.login.skip_mfa", "login", "armed")
      != WYRELOG_E_OK)
    return 16;
  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 17;

  g_autoptr (SoupSession) login = soup_session_new ();
  guint login_status = 0;
  g_autofree gchar *login_body = NULL;
  if (send_raw_login (login, "POST", base_url,
      "username=login-user&skip_mfa=true", &login_status, &login_body)
      != 0 || login_status != 200)
    return 18;

  gint jwt_rc = check_jwt_epoch_rotation_contract (http.server, handle,
          base_url);
  if (jwt_rc != 0)
    return jwt_rc;
  gint refresh_shutdown_rc = check_human_refresh_shutdown_ordering
        (http.server, base_url);
  if (refresh_shutdown_rc != 0)
    return refresh_shutdown_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#elif !defined(WYL_TEST_VARIANT_AUDIT) && !defined(WYL_TEST_VARIANT_SERVICE)
int
main (void)
{
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  gint policy_shutdown_rc = check_daemon_policy_write_shutdown_contract ();
  if (policy_shutdown_rc != 0)
    return policy_shutdown_rc;

  gint policy_cancellable_rc =
      check_daemon_policy_write_cancellable_contract ();
  if (policy_cancellable_rc != 0)
    return policy_cancellable_rc;

  gint policy_finalize_rc = check_daemon_policy_write_finalize_contract ();
  if (policy_finalize_rc != 0)
    return policy_finalize_rc;
  gint actual_owner_finalize_rc =
      check_policy_write_actual_owner_finalize_contract ();
  if (actual_owner_finalize_rc != 0)
    return actual_owner_finalize_rc;

  gint recovery_post_write_rc =
      check_tenant_recovery_post_write_revalidation_contract ();
  if (recovery_post_write_rc != 0)
    return recovery_post_write_rc;
  if (g_atomic_int_get (&tenant_recovery_post_write_regression_executions)
      != 1)
    return 22495;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 2;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return 10;
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 11;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide",
          test_http_server_thread, &http);
  MainLoopReadyBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  g_main_context_invoke_full (g_main_context_default (),
      G_PRIORITY_DEFAULT, mark_main_loop_ready, &barrier, NULL);
  g_mutex_lock (&barrier.mutex);
  if (!barrier.ready) {
    if (!g_cond_wait_until (&barrier.changed, &barrier.mutex,
        g_get_monotonic_time () + 5 * G_USEC_PER_SEC)) {
      g_mutex_unlock (&barrier.mutex);
      g_main_loop_quit (http.loop);
      g_thread_join (thread);
      soup_server_disconnect (http.server);
      g_clear_object (&http.server);
      g_clear_pointer (&http.loop, g_main_loop_unref);
      g_cond_clear (&barrier.changed);
      g_mutex_clear (&barrier.mutex);
      return 2270;
    }
  }
  g_mutex_unlock (&barrier.mutex);
  if (!wyl_daemon_http_refresh_context_is_for_test (http.server,
      g_main_context_default ()))
    return 2267;
  if (wyl_daemon_http_refresh_context_owned_for_test (http.server))
    return 2268;
  guint context_owned = 0, context_wrong = 0;
  wyl_daemon_http_refresh_lifecycle_counts_for_test (http.server,
      &context_owned, &context_wrong);
  if (context_owned != 0 || context_wrong != 1)
    return 2269;

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint exact_probe_rc = check_exact_route_probe_framework (http.server,
          base_url);
  if (exact_probe_rc != 0)
    return exact_probe_rc;
  gint exact_facts_rc = check_exact_facts_alias_canaries (http.server,
          base_url);
  if (exact_facts_rc != 0)
    return exact_facts_rc;
  gint exact_alias_rc = check_valid_exact_auth_alias_canaries
        (http.server, handle, base_url);
  if (exact_alias_rc != 0)
    return exact_alias_rc;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (base_url, &client) != WYRELOG_E_OK)
    return 5;

  gint read_only_method_rc = check_read_only_method_contract (base_url);
  if (read_only_method_rc != 0)
    return read_only_method_rc;

  gint readyz_rc = check_readyz_runtime_liveness_contract (base_url, &runtime);
  if (readyz_rc != 0)
    return readyz_rc;

  gint request_id_rc = check_request_id_header_contract (base_url);
  if (request_id_rc != 0)
    return request_id_rc;

  gint raw_rc = check_raw_decide_contract (http.server, handle, base_url);
  if (raw_rc != 0)
    return raw_rc;
  gint decision = -1;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-allow-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1819;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 1822;
  if (wyl_client_decide (client, "http-allow-user", "http.allow",
      "http-allow-scope", &decision) != WYRELOG_E_OK)
    return 8;
  if (decision != WYL_DECISION_ALLOW)
    return 9;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-guard-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1820;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1823;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
      "wr.audit.read", "http-guard-scope", 123, "public", 69,
      &decision) != WYRELOG_E_OK)
    return 10;
  if (decision != WYL_DECISION_ALLOW)
    return 11;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
      "wr.audit.read", "http-guard-scope", 123, "public", 70,
      &decision) != WYRELOG_E_OK)
    return 12;
  if (decision != WYL_DECISION_DENY)
    return 13;

  gint recovery_detach_rc = check_tenant_recovery_slot_detach_contract
        (http.server, handle);
  if (recovery_detach_rc != 0)
    return recovery_detach_rc;
  if (g_atomic_int_get (&tenant_recovery_detach_regression_executions) != 1)
    return 22484;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  return 0;
}
#elif defined(WYL_TEST_VARIANT_SERVICE)
int
main (void)
{
  gint result = 0;
  GThread *thread = NULL;
  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  gint policy_shutdown_rc = check_daemon_policy_write_shutdown_contract ();
  if (policy_shutdown_rc != 0)
    return policy_shutdown_rc;

  gint policy_cancellable_rc =
      check_daemon_policy_write_cancellable_contract ();
  if (policy_cancellable_rc != 0)
    return policy_cancellable_rc;

#ifdef WYL_HAS_FACT_STORE
#ifndef G_OS_WIN32
  /* This matrix provisions POSIX owner-mode fact roots.  Windows fact roots
  * require the separate fixed-volume, owner-only ACL fixture contract; #757
  * deliberately validates the complete 16x2 owner matrix on POSIX lanes. */
  gint all_owner_fault_rc = check_policy_write_all_owner_faults ();
  if (all_owner_fault_rc != 0)
    return all_owner_fault_rc;
#endif
#endif

#if defined(WYL_HAS_FACT_STORE) || defined(WYL_HAS_AUDIT)
  g_auto (ServiceCredentialStoreFixture) credential_store = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  if (!service_credential_store_fixture_init (&credential_store))
    return 1;
  WylHandleOpenOptions credential_options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = credential_store.policy_path,
    .policy_keyprovider_path = credential_store.key_spec,
    .audit_store_path = credential_store.audit_path,
    .production_mode = TRUE,
  };
  if (wyl_handle_open_with_options (&credential_options, &handle)
      != WYRELOG_E_OK)
    return 1;
#else
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;
#endif
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 2;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return 10;
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 11;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  g_autoptr (GError) error = NULL;
  g_autoptr (GMainContext) context = g_main_context_new ();
  TestHttpServer http = { 0 };
  wyl_daemon_access_token_snapshot_t service_token_snapshot = { 0 };
  g_autofree gchar *base_url = NULL;
  http.loop = g_main_loop_new (context, FALSE);
  g_main_context_push_thread_default (context);
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  g_main_context_pop_thread_default (context);
  if (http.server == NULL)
    return 3;
  thread = g_thread_new ("daemon-http-decide-service",
          test_http_server_thread_ctx, &http);
  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL) {
    result = 4;
    goto cleanup;
  }
  base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (base_url == NULL) {
    result = 5;
    goto cleanup;
  }
  gint read_only_method_rc = check_read_only_method_contract (base_url);
  if (read_only_method_rc != 0) {
    result = read_only_method_rc;
    goto cleanup;
  }
  gint route_prefix_rc =
      check_service_management_route_prefix_contract (base_url);
  if (route_prefix_rc != 0) {
    result = route_prefix_rc;
    goto cleanup;
  }
  gint route_shape_rc = check_service_route_shape_matrix (base_url);
  if (route_shape_rc != 0) {
    result = route_shape_rc;
    goto cleanup;
  }
  gint service_state_rc = check_service_access_token_state_contract
        (http.server, &service_token_snapshot);
  if (service_state_rc != 0) {
    result = service_state_rc;
    goto cleanup;
  }
  wyl_daemon_access_token_snapshot_clear (&service_token_snapshot);
  /* The resolver matrix deliberately constructs PENDING registry tuples to
   * prove that they cannot authenticate.  Production maintenance correctly
   * treats an observed PENDING tuple as an escaped publication and permanently
   * latches the authority, so isolate those synthetic fixtures from its
   * asynchronous source in every service-test feature combination.  Suspension
   * waits for an in-flight tick without terminalizing this server; dedicated
   * exchange-server tests continue to own the scheduler lifecycle contract. */
  guint maintenance_ticks_pre_suspend = 0;
  if (!wyl_daemon_http_service_auth_maintenance_active_for_test (http.server,
      &maintenance_ticks_pre_suspend)) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=pre_suspend source_active=0 ticks_pre=%u\n",
        maintenance_ticks_pre_suspend);
    result = 2660;
    goto cleanup;
  }
  wyl_daemon_http_suspend_service_auth_maintenance_for_test (http.server);
  guint maintenance_ticks_drained = 0;
  if (wyl_daemon_http_service_auth_maintenance_active_for_test (http.server,
      &maintenance_ticks_drained)) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=post_drain source_active=1 ticks_pre=%u ticks_drained=%u\n",
        maintenance_ticks_pre_suspend, maintenance_ticks_drained);
    result = 2661;
    goto cleanup;
  }
  if (maintenance_ticks_drained < maintenance_ticks_pre_suspend) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=post_drain_tick_regression ticks_pre=%u ticks_drained=%u\n",
        maintenance_ticks_pre_suspend, maintenance_ticks_drained);
    result = 2662;
    goto cleanup;
  }
  WylServiceAuthUnavailableReason resolver_authority_reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  wyrelog_error_t resolver_authority_rc =
      wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
          &resolver_authority_reason);
  if (resolver_authority_rc != WYRELOG_E_OK
      || resolver_authority_reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=pre_resolver_authority validation_rc=%d reason=%d "
        "ticks_pre=%u ticks_drained=%u\n", resolver_authority_rc,
        resolver_authority_reason, maintenance_ticks_pre_suspend,
        maintenance_ticks_drained);
    result = 2663;
    goto cleanup;
  }
  gint service_resolver_rc = check_service_bearer_resolver_contract
        (http.server);
  if (service_resolver_rc != 0) {
    result = service_resolver_rc;
    goto cleanup;
  }
  guint maintenance_ticks_final = 0;
  if (wyl_daemon_http_service_auth_maintenance_active_for_test (http.server,
      &maintenance_ticks_final)) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=post_resolver source_active=1 ticks_pre=%u ticks_drained=%u "
        "ticks_final=%u\n", maintenance_ticks_pre_suspend,
        maintenance_ticks_drained, maintenance_ticks_final);
    result = 2664;
    goto cleanup;
  }
  if (maintenance_ticks_final != maintenance_ticks_drained) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=post_resolver_tick_changed ticks_pre=%u ticks_drained=%u "
        "ticks_final=%u\n", maintenance_ticks_pre_suspend,
        maintenance_ticks_drained, maintenance_ticks_final);
    result = 2665;
    goto cleanup;
  }
  resolver_authority_reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  resolver_authority_rc = wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle,
          &resolver_authority_reason);
  if (resolver_authority_rc != WYRELOG_E_OK
      || resolver_authority_reason != WYL_SERVICE_AUTH_UNAVAILABLE_NONE) {
    g_printerr ("WYRELOG_TEST_DIAG service_resolver_isolation "
        "stage=post_resolver_authority validation_rc=%d reason=%d "
        "ticks_pre=%u ticks_drained=%u ticks_final=%u\n",
        resolver_authority_rc, resolver_authority_reason,
        maintenance_ticks_pre_suspend, maintenance_ticks_drained,
        maintenance_ticks_final);
    result = 2666;
    goto cleanup;
  }
  gint service_decide_rc =
      check_service_bearer_decide_injects_principal_state (http.server,
          base_url);
  if (service_decide_rc != 0) {
    result = service_decide_rc;
    goto cleanup;
  }
  gint fresh_tenant_rc =
      check_fresh_tenant_activation_grants_and_decides (http.server, base_url);
  if (fresh_tenant_rc != 0) {
    result = fresh_tenant_rc;
    goto cleanup;
  }
  gint service_data_plane_rc =
      check_service_bearer_decide_arms_data_plane_permission (http.server,
          base_url);
  if (service_data_plane_rc != 0) {
    result = service_data_plane_rc;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  gint service_exchange_rc = check_service_token_exchange_contract ();
  if (service_exchange_rc != 0) {
    result = service_exchange_rc;
    goto cleanup;
  }
  gint service_publication_fault_rc = check_service_publication_fault_matrix ();
  if (service_publication_fault_rc != 0) {
    result = service_publication_fault_rc;
    goto cleanup;
  }
  gint service_terminal_restart_rc =
      check_service_terminal_release_restart_contract ();
  if (service_terminal_restart_rc != 0) {
    result = service_terminal_restart_rc;
    goto cleanup;
  }
#endif
  gint profile_denied_rc = check_service_management_profile_denied ();
  if (profile_denied_rc != 0) {
    result = profile_denied_rc;
    goto cleanup;
  }
#ifdef WYL_HAS_AUDIT
  gint bearer_denied_rc = check_service_management_bearer_denied ();
  if (bearer_denied_rc != 0) {
    result = bearer_denied_rc;
    goto cleanup;
  }
#endif
  gint inactive_denied_rc = check_service_management_inactive_session_denied ();
  if (inactive_denied_rc != 0) {
    result = inactive_denied_rc;
    goto cleanup;
  }
  gint self_arm_e2e_rc = check_service_management_self_arm_end_to_end ();
  if (self_arm_e2e_rc != 0) {
    result = self_arm_e2e_rc;
    goto cleanup;
  }
  gint self_arm_race_rc =
      check_service_management_self_arm_reauthorization_zero_write ();
  if (self_arm_race_rc != 0) {
    result = self_arm_race_rc;
    goto cleanup;
  }
#ifdef WYL_TEST_HANDLE_SEAMS
  gint self_arm_fault_rc = check_service_management_self_arm_commit_faults ();
  if (self_arm_fault_rc != 0) {
    result = self_arm_fault_rc;
    goto cleanup;
  }
  gint self_arm_projection_rc =
      check_service_management_self_arm_projection_and_replacement_faults ();
  if (self_arm_projection_rc != 0) {
    result = self_arm_projection_rc;
    goto cleanup;
  }
  gint self_arm_finalize_rc =
      check_service_management_self_arm_finalize_snapshot ();
  if (self_arm_finalize_rc != 0) {
    result = self_arm_finalize_rc;
    goto cleanup;
  }
#endif
  gint self_arm_reject_rc = check_service_management_self_arm_rejections ();
  if (self_arm_reject_rc != 0) {
    result = self_arm_reject_rc;
    goto cleanup;
  }
  gint self_arm_scope_rc =
      check_service_management_self_arm_scopes_to_session ();
  if (self_arm_scope_rc != 0) {
    result = self_arm_scope_rc;
    goto cleanup;
  }
  gint caller_matrix_rc = check_service_management_caller_and_refresh_matrix ();
  if (caller_matrix_rc != 0) {
    result = caller_matrix_rc;
    goto cleanup;
  }
  gint permission_mapping_rc = check_service_management_permission_mapping ();
  if (permission_mapping_rc != 0) {
    result = permission_mapping_rc;
    goto cleanup;
  }
  gint write_reauthorization_rc =
      check_service_management_write_reauthorization_matrix ();
  if (write_reauthorization_rc != 0) {
    result = write_reauthorization_rc;
    goto cleanup;
  }
  gint logout_liveness_barrier_rc =
      check_service_management_logout_liveness_barrier ();
  if (logout_liveness_barrier_rc != 0) {
    result = logout_liveness_barrier_rc;
    goto cleanup;
  }
  gint route_alias_effect_rc = check_service_route_alias_no_effects ();
  if (route_alias_effect_rc != 0) {
    result = route_alias_effect_rc;
    goto cleanup;
  }
  gint loopback_forwarded_rc =
      check_service_management_loopback_forwarded_matrix ();
  if (loopback_forwarded_rc != 0) {
    result = loopback_forwarded_rc;
    goto cleanup;
  }
  gint cross_tenant_rc =
      check_service_management_global_principal_cross_tenant ();
  if (cross_tenant_rc != 0) {
    result = cross_tenant_rc;
    goto cleanup;
  }
  gint secret_leak_rc = check_service_management_populated_secret_leak ();
  if (secret_leak_rc != 0) {
    result = secret_leak_rc;
    goto cleanup;
  }
  gint retirement_restart_rc =
      check_retirement_response_loss_restart_contract ();
  if (retirement_restart_rc != 0) {
    result = retirement_restart_rc;
    goto cleanup;
  }
  gint retirement_fault_rc = check_retirement_postcommit_http_fault_matrix ();
  if (retirement_fault_rc != 0) {
    result = retirement_fault_rc;
    goto cleanup;
  }
  gint retirement_corruption_rc = check_retirement_corruption_http_matrix ();
  if (retirement_corruption_rc != 0) {
    result = retirement_corruption_rc;
    goto cleanup;
  }
  /* Real end-to-end escrow issue/rotate contract over loopback HTTP. It
   * stands up its own encrypted-store handle and server, so run it as a
   * self-contained check and propagate its return code. */
  gint service_principal_rc = check_service_principal_management_contract ();
  if (service_principal_rc != 0) {
    result = service_principal_rc;
    goto cleanup;
  }
#ifdef WYL_HAS_FACT_STORE
  gint reconcile_rc = check_service_credential_operation_reconcile_contract
        (http.server, handle, base_url);
  if (reconcile_rc != 0) {
    result = reconcile_rc;
    goto cleanup;
  }
#endif
cleanup:
  wyl_daemon_access_token_snapshot_clear (&service_token_snapshot);
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
#ifdef WYL_HAS_FACT_STORE
  if (result == 0)
    result = check_service_profile_reconcile_denied (handle);
#endif
  if (result != 0)
    g_printerr ("WYRELOG_TEST_DIAG service_variant result=%d\n", result);
  return result;
}
#else /* WYL_TEST_VARIANT_AUDIT */
int
main (void)
{
  gint actual_owner_finalize_rc =
      check_policy_write_actual_owner_finalize_contract ();
  if (actual_owner_finalize_rc != 0)
    return actual_owner_finalize_rc;

  gint policy_cancellable_rc =
      check_daemon_policy_write_cancellable_contract ();
  if (policy_cancellable_rc != 0)
    return policy_cancellable_rc;

  gint tenant_gate_rc = check_tenant_gate_codes_contract ();
  if (tenant_gate_rc != 0)
    return tenant_gate_rc;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 2;
  if (insert_not_armed_fixture (handle) != WYRELOG_E_OK)
    return 10;
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 11;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 14;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
          &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-decide-audit",
          test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (base_url, &client) != WYRELOG_E_OK)
    return 5;

  gint read_only_method_rc = check_read_only_method_contract (base_url);
  if (read_only_method_rc != 0)
    return read_only_method_rc;

  gint readyz_rc = check_readyz_malformed_audit_projection_contract (handle,
          base_url);
  if (readyz_rc != 0)
    return readyz_rc;

  /* Seed http.not_armed (http-deny-user) and other negative-decide audit
   * events that the audit_event_present series below relies on. The full
   * raw decide protocol contract is exercised in the non-audit variant. */
  gint raw_rc = check_raw_decide_contract (http.server, handle, base_url);
  if (raw_rc != 0)
    return raw_rc;
  gint decision = -1;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-allow-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1819;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_allow_fixture (handle) != WYRELOG_E_OK)
    return 1822;
  if (wyl_client_decide (client, "http-allow-user", "http.allow",
      "http-allow-scope", &decision) != WYRELOG_E_OK)
    return 8;
  if (decision != WYL_DECISION_ALLOW)
    return 9;
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-guard-user") != WYRELOG_E_OK) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 1820;
  }
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (insert_guarded_fixture (handle) != WYRELOG_E_OK)
    return 1823;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
      "wr.audit.read", "http-guard-scope", 123, "public", 69,
      &decision) != WYRELOG_E_OK)
    return 10;
  if (decision != WYL_DECISION_ALLOW)
    return 11;
  if (wyl_client_decide_with_guard_context (client, "http-guard-user",
      "wr.audit.read", "http-guard-scope", 123, "public", 70,
      &decision) != WYRELOG_E_OK)
    return 12;
  if (decision != WYL_DECISION_DENY)
    return 13;

  raw_rc = check_policy_permission_mutation_contract (http.server, handle,
          client, base_url);
  if (raw_rc != 0)
    return raw_rc;

  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  if (wyl_client_login_skip_mfa (client, "http-audit-user") != WYRELOG_E_OK)
    return 84;
  g_autofree gchar *audit_session_token = wyl_client_dup_session_token (client);
  g_autofree gchar *audit_access_token = wyl_client_dup_access_token (client);
  if (audit_session_token == NULL)
    return 85;
  if (audit_access_token == NULL)
    return 89;
  if (grant_audit_read (handle, "http-audit-user", audit_session_token) !=
      WYRELOG_E_OK)
    return 86;
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 87;

  gint audit_auth_rc = check_raw_audit_contract (http.server, handle, client,
          base_url, audit_session_token, audit_access_token);
  if (audit_auth_rc != 0)
    return audit_auth_rc;

  if (drop_runtime_audit_events_table (handle) != WYRELOG_E_OK)
    return 88;

  gint audit_rc = check_audit_event_present (client,
          "action(\"http.not_armed\")",
          "http-deny-user", "http.not_armed", "http-deny-scope",
          WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"http.allow\")",
          "http-allow-user", "http.allow", "http-allow-scope",
          WYL_DECISION_ALLOW, NULL, NULL);
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
          "deny_reason(\"not_armed\")",
          "http-deny-user", "http.not_armed", "http-deny-scope",
          WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
          "deny_origin(\"perm_state\")",
          "http-deny-user", "http.not_armed", "http-deny-scope",
          WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"wr.audit.read\")",
          "http-guard-user", "wr.audit.read", "http-guard-scope",
          WYL_DECISION_DENY, "not_armed", "perm_state");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"wr.audit.read\")",
          "http-guard-user", "wr.audit.read", "http-guard-scope",
          WYL_DECISION_ALLOW, NULL, NULL);
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
          "action(\"permission_grant\")",
          "http-policy-admin", "permission_grant", "tenant-a",
          WYL_DECISION_ALLOW, NULL, "site.policy.read");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
          "action(\"permission_revoke\")",
          "http-policy-admin", "permission_revoke", "tenant-a",
          WYL_DECISION_ALLOW, NULL, "site.policy.read");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client,
          "action(\"permission_state.grant\")",
          "http-policy-admin", "permission_state.grant", "site.policy.read",
          WYL_DECISION_ALLOW, "grant", "tenant-a");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"role_grant\")",
          "http-policy-admin", "role_grant", "tenant-b",
          WYL_DECISION_ALLOW, NULL, "site.reader");
  if (audit_rc != 0)
    return audit_rc;
  audit_rc = check_audit_event_present (client, "action(\"role_revoke\")",
          "http-policy-admin", "role_revoke", "tenant-b",
          WYL_DECISION_ALLOW, NULL, "site.reader");
  if (audit_rc != 0)
    return audit_rc;

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
#endif /* WYL_TEST_VARIANT_AUDIT */
