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

typedef enum
{
  SERVICE_PROJECTION_CREATE,
  SERVICE_PROJECTION_DISABLE,
} ServiceProjectionOperation;

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  const gchar *subject;
  ServiceProjectionOperation operation;
  gboolean completed;
  wyrelog_error_t rc;
} ServiceProjectionFaultWorker;

typedef struct
{
  guint total;
  guint service_principal_state;
} ServiceProjectionDeltaWitness;

static void
service_projection_delta_witness (const gchar *relation, const gint64 *row,
    guint ncols, WylDeltaKind kind, gpointer user_data)
{
  ServiceProjectionDeltaWitness *witness = user_data;
  (void) row;
  (void) ncols;
  (void) kind;
  witness->total++;
  if (g_strcmp0 (relation, "service_principal_state") == 0)
    witness->service_principal_state++;
}

static void
emit_successful_delta_witness (WylHandle *handle, const gchar *suffix)
{
  gint64 row[3];
  g_autofree gchar *subject = g_strdup_printf ("delta-subject-%s", suffix);
  g_autofree gchar *role = g_strdup_printf ("delta-role-%s", suffix);
  g_autofree gchar *scope = g_strdup_printf ("delta-scope-%s", suffix);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, subject, &row[0]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, role, &row[1]), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, scope, &row[2]),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_engine_insert (handle, "member_of", row,
      G_N_ELEMENTS (row)), ==, WYRELOG_E_OK);
}

static gpointer
service_projection_fault_worker (gpointer data)
{
  ServiceProjectionFaultWorker *worker = data;
  wyl_service_principal_t principal = { 0 };
  if (worker->operation == SERVICE_PROJECTION_CREATE)
    worker->rc = wyl_service_principal_create (worker->handle,
            worker->subject, "projection-fault-worker", "admin",
            "projection-fault-create", &principal);
  else
    worker->rc = wyl_service_principal_disable (worker->handle,
            worker->subject, "admin", "00000000000000000000000725C", &principal);
  wyl_service_principal_clear (&principal);
  g_mutex_lock (&worker->mutex);
  worker->completed = TRUE;
  g_cond_broadcast (&worker->changed);
  g_mutex_unlock (&worker->mutex);
  return NULL;
}

static void
assert_service_projection_loader_fault (ServiceProjectionOperation operation)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_autofree gchar *dir =
      g_dir_make_tmp ("wyl-service-projection-fault-XXXXXX", NULL);
  g_assert_nonnull (templates);
  g_assert_nonnull (dir);
  g_autofree gchar *store_path = g_build_filename (dir, "policy.db", NULL);
  WylHandleOpenOptions options = {
    .template_dir = templates,
    .policy_store_path = store_path,
    .require_template_manifest = FALSE,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  const gchar *subject = operation == SERVICE_PROJECTION_CREATE
      ? "svc:projection:fault:create" : "svc:projection:fault:disable";
  if (operation == SERVICE_PROJECTION_DISABLE) {
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle, subject,
        "projection-fault-worker", "admin", "projection-disable-setup",
        &principal), ==, WYRELOG_E_OK);
    wyl_service_principal_clear (&principal);
  }

  ServiceProjectionDeltaWitness delta_witness = { 0 };
  g_assert_cmpint (wyl_handle_engine_set_delta_callback (handle,
      service_projection_delta_witness, &delta_witness), ==, WYRELOG_E_OK);

  /* The insert seam, not a delta seam.  service_principal_state resolves out
   * of the read engine alone -- it is deliberately absent from
   * relation_fans_out_to_delta, which is why the assertions below require it
   * to produce no deltas -- so wyl_handle_engine_insert_locked returns at the
   * fan-out check and never reaches the delta insert or the delta step.
   *
   * Those two seams did fire before the projection was routed through the
   * funnel: the hand-rolled body consumed both quarks for this relation
   * directly.  Routing it correctly is what made them unreachable, so the
   * arming had to move with it. */
  wyl_handle_set_engine_insert_fault_once (handle,
      "service_principal_state",
      WYRELOG_E_IO);

  ServiceProjectionFaultWorker worker = {
    .handle = handle,
    .subject = subject,
    .operation = operation,
    .rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&worker.mutex);
  g_cond_init (&worker.changed);
  GThread *thread = g_thread_new ("service-projection-fault",
          service_projection_fault_worker, &worker);
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&worker.mutex);
  while (!worker.completed
      && g_cond_wait_until (&worker.changed, &worker.mutex, deadline));
  gboolean completed = worker.completed;
  g_mutex_unlock (&worker.mutex);
  g_assert_true (completed);
  g_thread_join (thread);
  g_assert_cmpint (worker.rc, ==, WYRELOG_E_BUSY);
  /* Inspect before reload, callback reset, or another delta step can clear
   * pending state. A failed candidate must leave no buffered emission. */
  g_assert_cmpuint (wyl_handle_pending_delta_count_for_test (handle), ==, 0);

  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  WylServiceAuthReadLease *read_lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_read
        (wyl_handle_get_service_auth_authority (handle), handle, NULL,
      &read_lease), ==, WYRELOG_E_BUSY);
  g_assert_null (read_lease);
  g_assert_cmpuint (delta_witness.total, ==, 0);
  g_assert_cmpuint (delta_witness.service_principal_state, ==, 0);
  emit_successful_delta_witness (handle, "latched");
  g_assert_cmpuint (delta_witness.total, >, 0);
  g_assert_cmpuint (delta_witness.service_principal_state, ==, 0);

  wyl_service_principal_t durable = { 0 };
  g_assert_cmpint (wyl_service_principal_get (handle, subject, &durable), ==,
      WYRELOG_E_OK);
  const gchar *expected_state = operation == SERVICE_PROJECTION_CREATE
      ? "active" : "disabled";
  g_assert_cmpstr (durable.state, ==, expected_state);
  wyl_service_principal_clear (&durable);

  g_clear_object (&handle);
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_true (contains_state (handle, "service_principal_state", subject,
      expected_state));
  g_assert_false (contains_state (handle, "service_principal_state", subject,
      operation == SERVICE_PROJECTION_CREATE ? "disabled" : "active"));
  reason = WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
  memset (&delta_witness, 0, sizeof delta_witness);
  g_assert_cmpint (wyl_handle_engine_set_delta_callback (handle,
      service_projection_delta_witness, &delta_witness), ==, WYRELOG_E_OK);
  emit_successful_delta_witness (handle, "reopened");
  g_assert_cmpuint (delta_witness.total, >, 0);
  g_assert_cmpuint (delta_witness.service_principal_state, ==, 0);

  g_cond_clear (&worker.changed);
  g_mutex_clear (&worker.mutex);
  g_clear_object (&handle);
  remove_store_files (store_path);
  g_rmdir (dir);
  remove_tree (templates);
}

static void
test_service_lifecycle_projection_loader_faults (void)
{
  /* One invocation per operation.  The second dimension used to select
   * between the delta-step and delta-insert seams; both are unreachable for
   * this relation now, so both branches armed the same seam and differed
   * only in an error value the propagation path discards --
   * service_mutation_latch_unavailable returns BUSY regardless. */
  assert_service_projection_loader_fault (SERVICE_PROJECTION_CREATE);
  assert_service_projection_loader_fault (SERVICE_PROJECTION_DISABLE);
}

static void
test_service_authority_allow_deny_and_binding (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
          "svc:authority:allow", TRUE);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean tenant_created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-b",
      &tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store,
      "svc:authority:allow", "wr.stream.read", "tenant-b"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);

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
  g_assert_cmpint (service_decide (handle, "svc:authority:allow", "tenant-b",
      "wr.stream.read", "tenant-b", WYRELOG_E_OK), ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (service_decide (handle, "svc:authority:allow", "tenant-b",
      "wr.stream.read", WYL_TENANT_DEFAULT, WYRELOG_E_OK), ==,
      WYL_DECISION_DENY);
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
  guint target;
} DecisionBarrier;

typedef struct
{
  WylHandle *handle;
  DecisionBarrier *barrier;
  const gchar *authority_tenant;
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
          decision->authority_tenant);
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, "svc:authority:concurrent");
  wyl_decide_req_set_action (req, "wr.stream.read");
  wyl_decide_req_set_resource_id (req, decision->scope);

  g_mutex_lock (&decision->barrier->mutex);
  decision->barrier->ready++;
  g_cond_broadcast (&decision->barrier->changed);
  while (decision->barrier->ready < decision->barrier->target)
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
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean tenant_created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-b",
      &tenant_created), ==, WYRELOG_E_OK);
  g_assert_true (tenant_created);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store,
      "svc:authority:concurrent", "wr.stream.read", "tenant-b"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);
  DecisionBarrier barrier = {.target = 4 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  ConcurrentDecision a_own = {
    .handle = handle,
    .barrier = &barrier,
    .authority_tenant = WYL_TENANT_DEFAULT,
    .scope = WYL_TENANT_DEFAULT,
  };
  ConcurrentDecision a_cross_b = {
    .handle = handle,
    .barrier = &barrier,
    .authority_tenant = WYL_TENANT_DEFAULT,
    .scope = "tenant-b",
  };
  ConcurrentDecision b_own = {
    .handle = handle,
    .barrier = &barrier,
    .authority_tenant = "tenant-b",
    .scope = "tenant-b",
  };
  ConcurrentDecision b_cross_a = {
    .handle = handle,
    .barrier = &barrier,
    .authority_tenant = "tenant-b",
    .scope = WYL_TENANT_DEFAULT,
  };
  GThread *threads[] = {
    g_thread_new ("service-a-own", concurrent_service_decide, &a_own),
    g_thread_new ("service-a-cross-b", concurrent_service_decide,
        &a_cross_b),
    g_thread_new ("service-b-own", concurrent_service_decide, &b_own),
    g_thread_new ("service-b-cross-a", concurrent_service_decide,
        &b_cross_a),
  };
  for (gsize i = 0; i < G_N_ELEMENTS (threads); i++)
    g_thread_join (threads[i]);
  g_assert_cmpint (a_own.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (a_own.decision, ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (a_cross_b.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (a_cross_b.decision, ==, WYL_DECISION_DENY);
  g_assert_cmpint (b_own.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b_own.decision, ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (b_cross_a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b_cross_a.decision, ==, WYL_DECISION_DENY);
  g_assert_cmpint (request_context_count (handle), ==, 0);

  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
  g_clear_object (&handle);
  remove_tree (templates);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  gboolean decision_active;
  gboolean allow_decision;
  gboolean decision_released;
  gboolean reload_waiting;
  gboolean reload_acquired;
  gboolean reload_completed;
  wyrelog_error_t decision_rc;
  wyrelog_error_t mutation_rc;
  wyrelog_error_t reload_rc;
  wyrelog_error_t release_rc;
  wyl_decision_t decision;
} ReloadDecisionRace;

static gboolean
blocking_window_matcher (gint64 timestamp, const gchar *window_name,
    gpointer user_data)
{
  ReloadDecisionRace *race = user_data;
  g_assert_cmpint (timestamp, ==, 4242);
  g_assert_cmpstr (window_name, ==, "off_hours");
  g_mutex_lock (&race->mutex);
  race->decision_active = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->allow_decision)
    g_cond_wait (&race->changed, &race->mutex);
  race->decision_released = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
  return TRUE;
}

static gpointer
blocking_human_decide (gpointer data)
{
  ReloadDecisionRace *race = data;
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (req, "reload-human");
  wyl_decide_req_set_action (req, "wr.stream.write_reserved");
  wyl_decide_req_set_resource_id (req, "reload-scope");
  wyl_decide_req_set_guard_context (req, 4242, "trusted", 1);
  wyl_decide_req_set_guard_window_matcher (req, blocking_window_matcher, race);
  race->decision_rc = wyl_decide (race->handle, req, resp);
  race->decision = wyl_decide_resp_get_decision (resp);
  return NULL;
}

static void
nested_reload_checkpoint (WylEngineReplacementCheckpoint phase, gpointer data)
{
  ReloadDecisionRace *race = data;
  g_mutex_lock (&race->mutex);
  if (phase == WYL_ENGINE_REPLACEMENT_WAITING)
    race->reload_waiting = TRUE;
  else if (phase == WYL_ENGINE_REPLACEMENT_ACQUIRED) {
    g_assert_cmpint (phase, ==, WYL_ENGINE_REPLACEMENT_ACQUIRED);
    g_assert_true (race->decision_released);
    race->reload_acquired = TRUE;
  }
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

static gpointer
nested_write_reload (gpointer data)
{
  ReloadDecisionRace *race = data;
  WylServiceAuthWriteLease *lease = NULL;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_write
        (wyl_handle_get_service_auth_authority (race->handle), race->handle,
          NULL, &lease);
  wyl_policy_store_t *store = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (lease, race->handle,
            &store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_grant_direct_permission (store, "reload-witness",
            "wr.stream.read", "witness-scope");
  race->mutation_rc = rc;
  race->reload_rc = rc == WYRELOG_E_OK
      ? wyl_handle_reload_engine_pair (race->handle) : rc;
  race->release_rc = lease != NULL
      ? wyl_service_auth_write_lease_release (lease) : rc;
  wyl_service_auth_write_lease_free (lease);
  g_mutex_lock (&race->mutex);
  race->reload_completed = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
  return NULL;
}

static void
wait_for_race_flag (ReloadDecisionRace *race, gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&race->mutex);
  while (!*flag && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  gboolean reached = *flag;
  g_mutex_unlock (&race->mutex);
  g_assert_true (reached);
}

static void
test_nested_write_reload_serializes_with_human_decide (void)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
          "svc:reload:test", FALSE);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_policy_store_grant_direct_permission (store,
      "reload-human", "wr.stream.write_reserved", "reload-scope"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store,
      "reload-human", "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, "reload-scope",
      "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store,
      "reload-human", "wr.stream.write_reserved", "reload-scope",
      "armed"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store,
      "reload-witness", "authenticated"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_session_state (store,
      "witness-scope", "active"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_permission_state (store,
      "reload-witness", "wr.stream.read", "witness-scope", "armed"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_reload_engine_pair (handle), ==, WYRELOG_E_OK);

  ReloadDecisionRace race = {
    .handle = handle,
    .decision_rc = WYRELOG_E_INTERNAL,
    .mutation_rc = WYRELOG_E_INTERNAL,
    .reload_rc = WYRELOG_E_INTERNAL,
    .release_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  GThread *decision = g_thread_new ("blocking-human-decision",
          blocking_human_decide, &race);
  wait_for_race_flag (&race, &race.decision_active);

  wyl_handle_set_reload_decision_checkpoint_for_test (handle,
      nested_reload_checkpoint, &race);
  GThread *reload = g_thread_new ("nested-write-reload",
          nested_write_reload, &race);
  wait_for_race_flag (&race, &race.reload_waiting);
  g_mutex_lock (&race.mutex);
  g_assert_false (race.reload_acquired);
  race.allow_decision = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  wait_for_race_flag (&race, &race.reload_acquired);

  g_thread_join (decision);
  g_thread_join (reload);
  wyl_handle_set_reload_decision_checkpoint_for_test (handle, NULL, NULL);
  g_assert_cmpint (race.decision_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (race.decision, ==, WYL_DECISION_ALLOW);
  g_assert_cmpint (race.mutation_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (race.reload_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (race.release_rc, ==, WYRELOG_E_OK);

  g_autoptr (wyl_decide_req_t) witness_req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) witness_resp = wyl_decide_resp_new ();
  wyl_decide_req_set_subject_id (witness_req, "reload-witness");
  wyl_decide_req_set_action (witness_req, "wr.stream.read");
  wyl_decide_req_set_resource_id (witness_req, "witness-scope");
  g_assert_cmpint (wyl_decide (handle, witness_req, witness_resp), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_decide_resp_get_decision (witness_resp), ==,
      WYL_DECISION_ALLOW);

  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  g_clear_object (&handle);
  remove_tree (templates);
}

typedef enum
{
  ENGINE_OPERATION_AUDIT,
  ENGINE_OPERATION_DELTA,
} EngineOperationKind;

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  EngineOperationKind kind;
  gint64 delta_row[3];
  gboolean operation_entered;
  gboolean allow_operation;
  gboolean operation_released;
  gboolean reload_waiting;
  gboolean reload_acquired;
  wyrelog_error_t operation_rc;
  wyrelog_error_t reload_rc;
} EngineOperationReloadRace;

static void
blocking_engine_operation_checkpoint (gpointer data)
{
  EngineOperationReloadRace *race = data;
  g_mutex_lock (&race->mutex);
  race->operation_entered = TRUE;
  g_cond_broadcast (&race->changed);
  while (!race->allow_operation)
    g_cond_wait (&race->changed, &race->mutex);
  race->operation_released = TRUE;
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

static void
engine_operation_reload_checkpoint (WylEngineReplacementCheckpoint phase,
    gpointer data)
{
  EngineOperationReloadRace *race = data;
  g_mutex_lock (&race->mutex);
  if (phase == WYL_ENGINE_REPLACEMENT_WAITING)
    race->reload_waiting = TRUE;
  else if (phase == WYL_ENGINE_REPLACEMENT_ACQUIRED) {
    g_assert_cmpint (phase, ==, WYL_ENGINE_REPLACEMENT_ACQUIRED);
    g_assert_true (race->operation_released);
    race->reload_acquired = TRUE;
  }
  g_cond_broadcast (&race->changed);
  g_mutex_unlock (&race->mutex);
}

static gpointer
run_engine_operation (gpointer data)
{
  EngineOperationReloadRace *race = data;
  if (race->kind == ENGINE_OPERATION_AUDIT)
    race->operation_rc = wyl_handle_insert_audit_fact (race->handle,
            "engine-session-audit", 725, "audit-subject", "audit-action",
            "audit-resource", NULL, NULL, "audit-request", WYL_DECISION_DENY);
  else
    race->operation_rc = wyl_handle_engine_insert (race->handle, "member_of",
            race->delta_row, G_N_ELEMENTS (race->delta_row));
  return NULL;
}

static gpointer
reload_after_engine_operation (gpointer data)
{
  EngineOperationReloadRace *race = data;
  race->reload_rc = wyl_handle_reload_engine_pair (race->handle);
  return NULL;
}

static void
wait_for_engine_operation_flag (EngineOperationReloadRace *race, gboolean *flag)
{
  gint64 deadline = g_get_monotonic_time () + 5 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&race->mutex);
  while (!*flag && g_cond_wait_until (&race->changed, &race->mutex, deadline));
  gboolean reached = *flag;
  g_mutex_unlock (&race->mutex);
  g_assert_true (reached);
}

static void
assert_engine_operation_serializes_reload (EngineOperationKind kind)
{
  g_autofree gchar *templates = copy_unsigned_template_tree ();
  g_assert_nonnull (templates);
  g_autoptr (WylHandle) handle = new_service_decision_handle (templates,
          kind == ENGINE_OPERATION_AUDIT ? "svc:engine:audit" :
          "svc:engine:delta", FALSE);
  EngineOperationReloadRace race = {
    .handle = handle,
    .kind = kind,
    .operation_rc = WYRELOG_E_INTERNAL,
    .reload_rc = WYRELOG_E_INTERNAL,
  };
  g_mutex_init (&race.mutex);
  g_cond_init (&race.changed);
  const gchar *relation = "audit_event_input";
  if (kind == ENGINE_OPERATION_DELTA) {
    relation = "member_of";
    g_assert_cmpint (wyl_handle_intern_engine_symbol (handle,
        "engine-delta-subject", &race.delta_row[0]), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_handle_intern_engine_symbol (handle,
        "engine-delta-role", &race.delta_row[1]), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_handle_intern_engine_symbol (handle,
        "engine-delta-scope", &race.delta_row[2]), ==, WYRELOG_E_OK);
  }
  wyl_handle_set_engine_operation_checkpoint_for_test (handle, relation,
      blocking_engine_operation_checkpoint, &race);
  GThread *operation = g_thread_new ("engine-operation",
          run_engine_operation, &race);
  wait_for_engine_operation_flag (&race, &race.operation_entered);

  wyl_handle_set_reload_decision_checkpoint_for_test (handle,
      engine_operation_reload_checkpoint, &race);
  GThread *reload = g_thread_new ("engine-operation-reload",
          reload_after_engine_operation, &race);
  wait_for_engine_operation_flag (&race, &race.reload_waiting);
  g_mutex_lock (&race.mutex);
  g_assert_false (race.reload_acquired);
  race.allow_operation = TRUE;
  g_cond_broadcast (&race.changed);
  g_mutex_unlock (&race.mutex);
  wait_for_engine_operation_flag (&race, &race.reload_acquired);

  g_thread_join (operation);
  g_thread_join (reload);
  wyl_handle_set_reload_decision_checkpoint_for_test (handle, NULL, NULL);
  wyl_handle_set_engine_operation_checkpoint_for_test (handle, NULL, NULL,
      NULL);
  g_assert_cmpint (race.operation_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (race.reload_rc, ==, WYRELOG_E_OK);
  g_cond_clear (&race.changed);
  g_mutex_clear (&race.mutex);
  g_clear_object (&handle);
  remove_tree (templates);
}

static void
test_engine_operations_serialize_with_reload (void)
{
  assert_engine_operation_serializes_reload (ENGINE_OPERATION_AUDIT);
  assert_engine_operation_serializes_reload (ENGINE_OPERATION_DELTA);
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
  g_test_add_func ("/service-decision/lifecycle/projection-loader-faults",
      test_service_lifecycle_projection_loader_faults);
  g_test_add_func ("/service-decision/authority/allow-deny-binding",
      test_service_authority_allow_deny_and_binding);
  g_test_add_func ("/service-decision/authority/zero-role-forged-subject",
      test_service_authority_zero_role_and_forged_subject_deny);
  g_test_add_func ("/service-decision/authority/faults",
      test_service_authority_faults_fail_closed);
  g_test_add_func ("/service-decision/authority/concurrent-isolation",
      test_service_authority_concurrent_context_isolation);
  g_test_add_func ("/service-decision/reload/nested-write-human-serialization",
      test_nested_write_reload_serializes_with_human_decide);
  g_test_add_func ("/service-decision/reload/engine-operation-serialization",
      test_engine_operations_serialize_with_reload);
  return g_test_run ();
}
