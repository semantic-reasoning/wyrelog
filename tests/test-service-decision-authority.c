/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-decide-private.h"
#include "wyrelog/wyl-engine-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) dir = g_dir_open (path, 0, NULL);

  if (dir == NULL) {
    g_remove (path);
    return;
  }
  const gchar *name = NULL;
  while ((name = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *child = g_build_filename (path, name, NULL);
    if (g_file_test (child, G_FILE_TEST_IS_DIR))
      remove_tree (child);
    else
      g_remove (child);
  }
  g_rmdir (path);
}

static gchar *
copy_unsigned_template_tree (void)
{
  static const gchar *const files[] = {
    "bootstrap.dl",
    "fsm/principal.dl",
    "fsm/session.dl",
    "fsm/permission_scope.dl",
    "lobac/decision.dl",
  };
  g_autofree gchar *dir =
      g_dir_make_tmp ("wyl-service-decision-template-XXXXXX", NULL);
  if (dir == NULL)
    return NULL;
  g_autofree gchar *fsm = g_build_filename (dir, "fsm", NULL);
  g_autofree gchar *lobac = g_build_filename (dir, "lobac", NULL);
  if (g_mkdir (fsm, 0700) != 0 || g_mkdir (lobac, 0700) != 0) {
    remove_tree (dir);
    return NULL;
  }

  for (gsize i = 0; i < G_N_ELEMENTS (files); i++) {
    g_autofree gchar *source =
        g_build_filename (WYL_TEST_TEMPLATE_DIR, files[i], NULL);
    g_autofree gchar *target = g_build_filename (dir, files[i], NULL);
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    if (!g_file_get_contents (source, &contents, &len, NULL)
        || !g_file_set_contents (target, contents, (gssize) len, NULL)) {
      remove_tree (dir);
      return NULL;
    }
  }
  return g_steal_pointer (&dir);
}

static void
remove_store_files (const gchar *path)
{
  g_autofree gchar *wal = g_strconcat (path, "-wal", NULL);
  g_autofree gchar *shm = g_strconcat (path, "-shm", NULL);
  g_remove (wal);
  g_remove (shm);
  g_remove (path);
}

static gboolean
contains_state (WylHandle *handle, const gchar *relation,
    const gchar *subject, const gchar *state)
{
  gint64 row[2];
  gboolean contains = FALSE;

  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, subject, &row[0]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, state, &row[1]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_engine_contains (handle, relation, row, 2,
          &contains), ==, WYRELOG_E_OK);
  return contains;
}

static WylServiceDecisionAuthority *
new_service_authority (WylHandle *handle, const gchar *subject,
    const gchar *tenant)
{
  WylServiceAuthReadLease *lease = NULL;
  WylServiceDecisionAuthority *authority = NULL;

  g_assert_cmpint (wyl_service_auth_authority_acquire_read
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_decision_authority_new_resolved (handle,
          &lease, subject, tenant, &authority), ==, WYRELOG_E_OK);
  g_assert_null (lease);
  g_assert_nonnull (authority);
  return authority;
}

static wyl_decision_t
service_decide (WylHandle *handle, const gchar *subject,
    const gchar *credential_tenant, const gchar *action,
    const gchar *scope, wyrelog_error_t expected_rc)
{
  g_autoptr (WylServiceDecisionAuthority) authority =
      new_service_authority (handle, subject, credential_tenant);
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, scope);
  g_assert_cmpint (wyl_decide_with_service_authority (handle, req, authority,
          resp), ==, expected_rc);
  return wyl_decide_resp_get_decision (resp);
}

static void
count_rows (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  guint *count = user_data;
  (void) relation;
  (void) row;
  (void) ncols;
  (*count)++;
}

static guint
request_context_count (WylHandle *handle)
{
  guint count = 0;
  g_assert_cmpint (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          "service_request_auth_observed", count_rows, &count), ==,
      WYRELOG_E_OK);
  return count;
}

static WylHandle *
new_service_decision_handle (const gchar *templates, const gchar *subject,
    gboolean grant_read)
{
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, subject, "worker",
          "admin", "authority-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  if (grant_read)
    g_assert_cmpint (wyl_policy_store_grant_direct_permission
        (wyl_handle_get_policy_store (handle), subject, "wr.stream.read",
            WYL_TENANT_DEFAULT), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_open_engine_pair (handle, templates), ==,
      WYRELOG_E_OK);
  return handle;
}

static void
test_service_lifecycle_projection (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);

  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:projection",
          "projection", "admin", "projection-create", &principal), ==,
      WYRELOG_E_OK);
  g_assert_true (contains_state (handle, "service_principal_state",
          principal.subject_id, "active"));
  g_assert_false (contains_state (handle, "principal_state",
          principal.subject_id, "authenticated"));
  wyl_service_principal_clear (&principal);

  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:projection",
          "admin", "00000000000000000000000725A", &principal), ==,
      WYRELOG_E_OK);
  g_assert_false (contains_state (handle, "service_principal_state",
          principal.subject_id, "active"));
  g_assert_true (contains_state (handle, "service_principal_state",
          principal.subject_id, "disabled"));
  g_assert_false (contains_state (handle, "principal_state",
          principal.subject_id, "authenticated"));
  wyl_service_principal_clear (&principal);

  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_service_lifecycle_restart_projection (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_autofree gchar *dir =
      g_dir_make_tmp ("wyl-service-decision-store-XXXXXX", NULL);
  g_assert_nonnull (templates);
  g_assert_nonnull (dir);
  g_autofree gchar *store = g_build_filename (dir, "policy.db", NULL);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .policy_store_path = store,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:restart:725",
          "restart", "admin", "restart-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:restart:725",
          "admin", "00000000000000000000000725B", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  g_clear_object (&handle);

  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_true (contains_state (handle, "service_principal_state",
          "svc:restart:725", "disabled"));
  g_assert_false (contains_state (handle, "principal_state",
          "svc:restart:725", "authenticated"));
  g_clear_object (&handle);

  remove_store_files (store);
  g_rmdir (dir);
  remove_tree (templates);
}

static void
test_service_lifecycle_projection_failure_latches (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);

  wyl_handle_set_engine_insert_fault_once (handle,
      "service_principal_state", WYRELOG_E_IO);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:projection:fault", "fault", "admin", "projection-fault",
          &principal), ==, WYRELOG_E_BUSY);
  g_assert_null (principal.subject_id);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  g_assert_false (contains_state (handle, "service_principal_state",
          "svc:projection:fault", "active"));

  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_service_authority_allow_deny_and_binding (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
      "svc:authority:allow", TRUE);

  g_autoptr (wyl_decide_req_t) bare = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) bare_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (bare, "svc:authority:allow");
  wyl_decide_req_set_action (bare, "wr.stream.read");
  wyl_decide_req_set_resource_id (bare, WYL_TENANT_DEFAULT);
  g_assert_cmpint (wyl_decide (handle, bare, bare_resp), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_decide_resp_get_decision (bare_resp), ==,
      WYL_DECISION_DENY);

  g_assert_cmpint (service_decide (handle, "svc:authority:allow",
          WYL_TENANT_DEFAULT, "wr.stream.read", WYL_TENANT_DEFAULT,
          WYRELOG_E_OK), ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (request_context_count (handle), ==, 0);
  g_assert_cmpint (service_decide (handle, "svc:authority:allow",
          WYL_TENANT_DEFAULT, "wr.stream.read", "tenant-b",
          WYRELOG_E_OK), ==, WYL_DECISION_DENY);
  g_assert_cmpint (service_decide (handle, "svc:authority:allow",
          WYL_TENANT_DEFAULT, "wr.policy.write", WYL_TENANT_DEFAULT,
          WYRELOG_E_OK), ==, WYL_DECISION_DENY);

  g_autoptr (WylServiceDecisionAuthority) one_shot =
      new_service_authority (handle, "svc:authority:allow", WYL_TENANT_DEFAULT);
  g_autoptr (wyl_decide_resp_t) first = wyl_decide_resp_new ();
  g_assert_cmpint (wyl_decide_with_service_authority (handle, bare, one_shot,
          first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_decide_with_service_authority (handle, bare, one_shot,
          first), ==, WYRELOG_E_INVALID);

  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_service_authority_zero_role_and_forged_subject_deny (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
      "svc:authority:zero", FALSE);
  g_assert_cmpint (service_decide (handle, "svc:authority:zero",
          WYL_TENANT_DEFAULT, "wr.stream.read", WYL_TENANT_DEFAULT,
          WYRELOG_E_OK), ==, WYL_DECISION_DENY);

  g_autoptr (WylServiceDecisionAuthority) authority =
      new_service_authority (handle, "svc:authority:zero", WYL_TENANT_DEFAULT);
  g_autoptr (wyl_decide_req_t) forged = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) response = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (forged, "svc:authority:other");
  wyl_decide_req_set_action (forged, "wr.stream.read");
  wyl_decide_req_set_resource_id (forged, WYL_TENANT_DEFAULT);
  g_assert_cmpint (wyl_decide_with_service_authority (handle, forged,
          authority, response), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_decide_resp_get_decision (response), ==,
      WYL_DECISION_DENY);
  g_assert_cmpint (request_context_count (handle), ==, 0);

  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_service_authority_faults_fail_closed (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);

  {
    g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
        "svc:authority:insert-fault", TRUE);
    wyl_handle_set_engine_insert_fault_once (handle, "service_request_auth",
        WYRELOG_E_IO);
    g_assert_cmpint (service_decide (handle, "svc:authority:insert-fault",
            WYL_TENANT_DEFAULT, "wr.stream.read", WYL_TENANT_DEFAULT,
            WYRELOG_E_IO), ==, WYL_DECISION_DENY);
    g_assert_cmpint (request_context_count (handle), ==, 0);
  }
  {
    g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
        "svc:authority:query-fault", TRUE);
    wyl_handle_set_engine_contains_fault_once (handle, "service_allow_bool",
        WYRELOG_E_IO);
    g_assert_cmpint (service_decide (handle, "svc:authority:query-fault",
            WYL_TENANT_DEFAULT, "wr.stream.read", WYL_TENANT_DEFAULT,
            WYRELOG_E_IO), ==, WYL_DECISION_DENY);
    g_assert_cmpint (request_context_count (handle), ==, 0);
  }
  {
    g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
        "svc:authority:cleanup-fault", TRUE);
    wyl_handle_set_engine_remove_fault_once (handle, "service_request_auth",
        WYRELOG_E_IO);
    g_assert_cmpint (service_decide (handle, "svc:authority:cleanup-fault",
            WYL_TENANT_DEFAULT, "wr.stream.read", WYL_TENANT_DEFAULT,
            WYRELOG_E_IO), ==, WYL_DECISION_DENY);
    g_assert_null (wyl_handle_get_read_engine (handle));
    g_assert_null (wyl_handle_get_delta_engine (handle));
  }
  {
    g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
        "svc:authority:terminal-fault", TRUE);
    WylServiceAuthReadLease *lease = NULL;
    g_assert_cmpint (wyl_service_auth_authority_acquire_read
        (wyl_handle_get_service_auth_authority (handle), handle, NULL,
            &lease), ==, WYRELOG_E_OK);
    wyl_service_auth_read_lease_test_fail_terminal_prevalidation (lease);
    g_autoptr (WylServiceDecisionAuthority) authority = NULL;
    g_assert_cmpint (wyl_service_decision_authority_new_resolved (handle,
            &lease, "svc:authority:terminal-fault", WYL_TENANT_DEFAULT,
            &authority), ==, WYRELOG_E_OK);
    g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
    g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
    wyl_decide_req_set_subject_id (req, "svc:authority:terminal-fault");
    wyl_decide_req_set_action (req, "wr.stream.read");
    wyl_decide_req_set_resource_id (req, WYL_TENANT_DEFAULT);
    g_assert_cmpint (wyl_decide_with_service_authority (handle, req, authority,
            resp), ==, WYRELOG_E_INTERNAL);
    g_assert_cmpint (wyl_decide_resp_get_decision (resp), ==,
        WYL_DECISION_DENY);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  }
  remove_tree (templates);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  guint ready;
} DecisionBarrier;

typedef struct
{
  WylHandle *handle;
  DecisionBarrier *barrier;
  const gchar *scope;
  wyrelog_error_t rc;
  wyl_decision_t decision;
} ConcurrentDecision;

static gpointer
concurrent_service_decide (gpointer data)
{
  ConcurrentDecision *decision = data;
  g_autoptr (WylServiceDecisionAuthority) authority =
      new_service_authority (decision->handle, "svc:authority:concurrent",
      WYL_TENANT_DEFAULT);
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, "svc:authority:concurrent");
  wyl_decide_req_set_action (req, "wr.stream.read");
  wyl_decide_req_set_resource_id (req, decision->scope);

  g_mutex_lock (&decision->barrier->mutex);
  decision->barrier->ready++;
  g_cond_broadcast (&decision->barrier->changed);
  while (decision->barrier->ready < 2)
    g_cond_wait (&decision->barrier->changed, &decision->barrier->mutex);
  g_mutex_unlock (&decision->barrier->mutex);

  decision->rc = wyl_decide_with_service_authority (decision->handle, req,
      authority, resp);
  decision->decision = wyl_decide_resp_get_decision (resp);
  return NULL;
}

static void
test_service_authority_concurrent_context_isolation (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
      "svc:authority:concurrent", TRUE);
  DecisionBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  ConcurrentDecision allowed = {
    .handle = handle,
    .barrier = &barrier,
    .scope = WYL_TENANT_DEFAULT,
  };
  ConcurrentDecision foreign = {
    .handle = handle,
    .barrier = &barrier,
    .scope = "tenant-b",
  };
  GThread *allowed_thread = g_thread_new ("service-allow",
      concurrent_service_decide, &allowed);
  GThread *foreign_thread = g_thread_new ("service-foreign",
      concurrent_service_decide, &foreign);
  g_thread_join (allowed_thread);
  g_thread_join (foreign_thread);
  g_assert_cmpint (allowed.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (allowed.decision, ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (foreign.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (foreign.decision, ==, WYL_DECISION_DENY);
  g_assert_cmpint (request_context_count (handle), ==, 0);

  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  g_clear_object (&handle);
  remove_tree (templates);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-decision/lifecycle/live",
      test_service_lifecycle_projection);
  g_test_add_func ("/service-decision/lifecycle/restart",
      test_service_lifecycle_restart_projection);
  g_test_add_func ("/service-decision/lifecycle/projection-failure",
      test_service_lifecycle_projection_failure_latches);
  g_test_add_func ("/service-decision/authority/allow-deny-binding",
      test_service_authority_allow_deny_and_binding);
  g_test_add_func ("/service-decision/authority/zero-role-forged-subject",
      test_service_authority_zero_role_and_forged_subject_deny);
  g_test_add_func ("/service-decision/authority/faults",
      test_service_authority_faults_fail_closed);
  g_test_add_func ("/service-decision/authority/concurrent-isolation",
      test_service_authority_concurrent_context_isolation);
  return g_test_run ();
}
