/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include "test-exit-status.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-private.h"
#include "wyrelog/wyl-common-private.h"
#include "human-user-test-support.h"

static gint64
rows (WylHandle *handle, const gchar *sql)
{
  sqlite3_stmt *statement = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (
        wyl_handle_get_policy_store (handle)), sql, -1, &statement, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (statement), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (statement, 0);
  sqlite3_finalize (statement);
  return count;
}

static wyrelog_error_t
authorize (gpointer data, const gchar *actor, gboolean *admin)
{
  wyrelog_error_t rc = wyl_policy_store_user_require_admin (
    wyl_handle_get_policy_store (data), actor);
  *admin = rc == WYRELOG_E_OK;
  return rc;
}

static wyrelog_error_t
validate (gpointer data)
{
  return wyl_policy_store_user_require_admin (
    wyl_handle_get_policy_store (data), "admin");
}

static wyrelog_error_t
mutate (WylHandle *handle, const gchar *subject, const gchar *action)
{
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  WylTenantDeleteRuntime runtime = {.authorize = authorize, .validate = validate, .data = handle};
  g_auto (WylUserDeletePreview) preview = {0};
  if (g_str_equal (action, "delete"))
    g_assert_cmpint (wyl_handle_user_preview (handle, subject, "admin", &runtime, &preview), ==, WYRELOG_E_OK);
  g_auto (WylUserOperation) operation = {0};
  return wyl_handle_user_mutate (handle, subject, "admin", action, request,
             preview.fingerprint, &runtime, &operation);
}

static WylHandle *
fixture (void)
{
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  register_test_human (store, "admin");
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "admin",
      "wr.system_admin", WYL_TENANT_DEFAULT), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  return handle;
}

static void
deny_login (WylHandle *handle, const gchar *subject, gboolean skip)
{
  g_autoptr (wyl_login_req_t) request = wyl_login_req_new ();
  wyl_login_req_set_username (request, subject);
  wyl_login_req_set_skip_mfa (request, skip);
  g_autoptr (WylSession) session = NULL;
  g_assert_cmpint (wyl_session_login (handle, request, &session), ==, WYRELOG_E_POLICY);
  g_assert_null (session);
}

static void
check_denial_is_audit_only (void)
{
  g_autoptr (WylHandle) handle = fixture ();
  deny_login (handle, "unknown", FALSE);
  deny_login (handle, "unknown", TRUE);
  g_assert_cmpint (mutate (handle, "disabled", "create"), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutate (handle, "disabled", "disable"), ==, WYRELOG_E_OK);
  deny_login (handle, "disabled", FALSE);
  deny_login (handle, "disabled", TRUE);
  g_assert_cmpint (mutate (handle, "deleted", "create"), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutate (handle, "deleted", "delete"), ==, WYRELOG_E_OK);
  deny_login (handle, "deleted", FALSE);
  deny_login (handle, "deleted", TRUE);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM principal_states"), ==, 0);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM principal_events"), ==, 0);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM session_states"), ==, 0);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM session_events"), ==, 0);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM audit_events WHERE action='login_denied'"), ==, 6);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_sessions"), ==, 0);
}

typedef struct
{
  WylHandle *handle;
  GMutex lock;
  GCond started;
  gboolean running;
  wyrelog_error_t result;
  WylSession *session;
} LoginRace;

static gpointer
login_thread (gpointer data)
{
  LoginRace *race = data;
  g_autoptr (wyl_login_req_t) request = wyl_login_req_new ();
  wyl_login_req_set_username (request, "racer");
  g_mutex_lock (&race->lock);
  race->running = TRUE;
  g_cond_signal (&race->started);
  g_mutex_unlock (&race->lock);
  race->result = wyl_session_login (race->handle, request, &race->session);
  return NULL;
}

static void
check_disable_login_order (void)
{
  g_autoptr (WylHandle) handle = fixture ();
  g_assert_cmpint (mutate (handle, "racer", "create"), ==, WYRELOG_E_OK);
  LoginRace race = {.handle = handle};
  g_mutex_init (&race.lock);
  g_cond_init (&race.started);
  WylHumanLifecycleLease lease = wyl_handle_human_lifecycle_acquire (handle);
  GThread *thread = g_thread_new ("login-after-disable", login_thread, &race);
  g_mutex_lock (&race.lock);
  while (!race.running) g_cond_wait (&race.started, &race.lock);
  g_mutex_unlock (&race.lock);
  g_assert_cmpint (mutate (handle, "racer", "disable"), ==, WYRELOG_E_OK);
  wyl_handle_human_lifecycle_clear (&lease);
  g_thread_join (thread);
  g_assert_cmpint (race.result, ==, WYRELOG_E_POLICY);
  g_assert_null (race.session);
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM principal_states WHERE subject_id='racer'"), ==, 0);
  g_cond_clear (&race.started);
  g_mutex_clear (&race.lock);

  g_assert_cmpint (mutate (handle, "login-first", "create"), ==, WYRELOG_E_OK);
  g_autoptr (wyl_login_req_t) request = wyl_login_req_new ();
  wyl_login_req_set_username (request, "login-first");
  g_autoptr (WylSession) session = NULL;
  g_assert_cmpint (wyl_session_login (handle, request, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutate (handle, "login-first", "disable"), ==, WYRELOG_E_OK);
  g_assert_false (wyl_session_is_active_human_private (session));
  g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_sessions"), ==, 0);
}

static void
count_revocation (gpointer data, const gchar *subject)
{
  guint *count = data;
  g_assert_nonnull (subject);
  (*count)++;
}

static void
check_conflicting_receipt_preserves_sessions (void)
{
  g_autoptr (WylHandle) handle = fixture ();
  g_assert_cmpint (mutate (handle, "other", "create"), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutate (handle, "second-admin", "create"), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_policy_store_grant_role_membership (store, "second-admin",
      "wr.system_admin", WYL_TENANT_DEFAULT), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
  WylTenantDeleteRuntime runtime = {.authorize = authorize, .validate = validate, .data = handle};
  g_auto (WylUserOperation) receipt = {0};
  g_assert_cmpint (wyl_handle_user_mutate (handle, "victim", "admin", "create",
      request, NULL, &runtime, &receipt), ==, WYRELOG_E_OK);
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  g_autoptr (WylSession) victim = NULL;
  g_autoptr (WylSession) other = NULL;
  wyl_login_req_set_username (login, "victim");
  g_assert_cmpint (wyl_session_login (handle, login, &victim), ==, WYRELOG_E_OK);
  wyl_login_req_set_username (login, "other");
  g_assert_cmpint (wyl_session_login (handle, login, &other), ==, WYRELOG_E_OK);
  guint revoked = 0;
  wyl_handle_set_human_revocation_callback (handle, &revoked, count_revocation);
  gint64 audit_count = rows (handle, "SELECT COUNT(*) FROM audit_events");
  gint64 operation_count = rows (handle, "SELECT COUNT(*) FROM human_user_operations");
  const gchar *cases[][4] = {
    {"victim", "admin", "disable", NULL},
    {"other", "admin", "create", NULL},
    {"victim", "second-admin", "create", NULL},
    {"victim", "admin", "create", "different-fingerprint"},
    {"other", "admin", "disable", NULL},
    {"victim", "admin", "delete", "different-fingerprint"},
  };
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_auto (WylUserOperation) conflict = {0};
    g_assert_cmpint (wyl_handle_user_mutate (handle, cases[i][0], cases[i][1], cases[i][2],
        request, cases[i][3], &runtime, &conflict), ==, WYRELOG_E_CONFLICT);
    g_assert_false (conflict.committed);
    g_assert_false (conflict.complete);
    g_assert_true (wyl_session_is_active_human_private (victim));
    g_assert_true (wyl_session_is_active_human_private (other));
    g_assert_cmpuint (revoked, ==, 0);
    g_assert_cmpint (wyl_policy_store_user_require (store, "victim", TRUE), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_user_require (store, "other", TRUE), ==, WYRELOG_E_OK);
    g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_sessions"), ==, 2);
    g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM audit_events"), ==, audit_count);
    g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_operations"), ==, operation_count);
  }
  g_auto (WylUserOperation) replay = {0};
  g_assert_cmpint (wyl_handle_user_mutate (handle, "victim", "admin", "create",
      request, NULL, &runtime, &replay), ==, WYRELOG_E_OK);
  g_assert_true (replay.committed);
  g_assert_true (wyl_session_is_active_human_private (victim));
  g_assert_cmpuint (revoked, ==, 0);
  g_assert_cmpint (mutate (handle, "victim", "disable"), ==, WYRELOG_E_OK);
  g_assert_cmpuint (revoked, ==, 1);
  g_assert_false (wyl_session_is_active_human_private (victim));
  g_assert_true (wyl_session_is_active_human_private (other));
  wyl_handle_set_human_revocation_callback (handle, &revoked, NULL);
}

typedef struct
{
  WylHandle *handle;
  const gchar *point;
  guint hits;
} UserFault;

static wyrelog_error_t
fault_authorize (gpointer data, const gchar *actor, gboolean *admin)
{
  return authorize (((UserFault *) data)->handle, actor, admin);
}

static wyrelog_error_t
fault_validate (gpointer data)
{
  return validate (((UserFault *) data)->handle);
}

static wyrelog_error_t
fault_checkpoint (const gchar *point, gpointer data)
{
  UserFault *fault = data;
  if (g_strcmp0 (point, fault->point) != 0) return WYRELOG_E_OK;
  fault->hits++;
  return WYRELOG_E_IO;
}

static void
check_mutation_commit_faults (void)
{
  const gchar *points[] = {"before_user_commit", "after_user_commit"};
  const gchar *actions[] = {"disable", "delete"};
  for (guint a = 0; a < G_N_ELEMENTS (actions); a++) {
    for (guint p = 0; p < G_N_ELEMENTS (points); p++) {
      g_autoptr (WylHandle) handle = fixture ();
      g_assert_cmpint (mutate (handle, "fault-user", "create"), ==, WYRELOG_E_OK);
      g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
      wyl_login_req_set_username (login, "fault-user");
      g_autoptr (WylSession) session = NULL;
      g_assert_cmpint (wyl_session_login (handle, login, &session), ==, WYRELOG_E_OK);
      UserFault fault = {handle, points[p], 0};
      WylTenantDeleteRuntime runtime = {fault_authorize, fault_validate, fault_checkpoint, &fault};
      g_auto (WylUserDeletePreview) preview = {0};
      if (a == 1)
        g_assert_cmpint (wyl_handle_user_preview (handle, "fault-user", "admin", &runtime, &preview), ==, WYRELOG_E_OK);
      gchar request[WYL_REQUEST_ID_STRING_BUF];
      g_assert_cmpint (wyl_request_id_new (request, sizeof request), ==, WYRELOG_E_OK);
      g_auto (WylUserOperation) operation = {0};
      g_assert_cmpint (wyl_handle_user_mutate (handle, "fault-user", "admin",
          actions[a], request, preview.fingerprint, &runtime, &operation), ==, WYRELOG_E_IO);
      g_assert_cmpuint (fault.hits, ==, 1);
      g_assert_cmpint (operation.committed, ==, p == 1);
      g_assert_cmpint (wyl_session_is_active_human_private (session), ==, p == 0);
      g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_sessions"), ==, p == 0 ? 1 : 0);
      g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM audit_events WHERE action IN ('user_disable','user_delete')"), ==, p == 1 ? 1 : 0);
      if (p == 0) g_assert_cmpint (wyl_policy_store_user_require (wyl_handle_get_policy_store (handle), "fault-user", TRUE), ==, WYRELOG_E_OK);
      else deny_login (handle, "fault-user", FALSE);
      fault.point = NULL;
      for (guint retry = 0; retry < 2; retry++) {
        g_assert_cmpint (wyl_handle_user_mutate (handle, "fault-user", "admin",
            actions[a], request, preview.fingerprint, &runtime, &operation), ==, WYRELOG_E_OK);
        g_assert_true (operation.committed);
        g_assert_true (operation.complete);
      }
      g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM audit_events WHERE action IN ('user_disable','user_delete')"), ==, 1);
      g_assert_cmpint (rows (handle, "SELECT COUNT(*) FROM human_user_operations WHERE phase='cleanup'"), ==, 0);
    }
  }
}

int
main (void)
{
  check_denial_is_audit_only ();
  check_disable_login_order ();
  check_mutation_commit_faults ();
  check_conflicting_receipt_preserves_sessions ();
  return wyl_test_normalize_exit_status (0);
}
