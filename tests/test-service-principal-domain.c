/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "auth/service-credential-domain-private.h"
#include "daemon/auth-registry-private.h"
#include "wyrelog/wyl-handle-private.h"

#define SESSION_A "01890c10-2e3f-7000-8000-000000000201"
#define JTI_A "01890c10-2e3f-7000-8000-000000000202"
#define SESSION_B "01890c10-2e3f-7000-8000-000000000203"
#define JTI_B "01890c10-2e3f-7000-8000-000000000204"
#define CREDENTIAL_A "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"
#define RETIRE_REQUEST_COLLISION "000000000000000000000000101"
#define RETIRE_REQUEST_DISABLE "000000000000000000000000102"
#define RETIRE_REQUEST_NOOP "000000000000000000000000103"

static void
remove_store_files (const gchar *path)
{
  static const gchar *suffixes[] = {
    "", ".wyrelog-clear", ".wyrelog-lock", ".wyrelog-tmp", "-journal",
    "-wal", "-shm",
    ".wyrelog-clear-journal", ".wyrelog-clear-wal", ".wyrelog-clear-shm",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (suffixes); i++) {
    g_autofree gchar *candidate = g_strdup_printf ("%s%s", path, suffixes[i]);
    (void) g_remove (candidate);
  }
}

static sqlite3 *
handle_db (WylHandle *handle)
{
  return wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
}

static gint64
scalar_int64 (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static void
exec_ok (sqlite3 *db, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
exec_rejected (sqlite3 *db, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  sqlite3_free (message);
  g_assert_cmpint (rc, !=, SQLITE_OK);
}

static wyrelog_error_t
count_principal (const wyl_service_principal_t *principal, gpointer user_data)
{
  guint *count = user_data;
  g_assert_nonnull (principal->subject_id);
  (*count)++;
  return WYRELOG_E_OK;
}

static void
test_create_get_list_disable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  sqlite3 *db = handle_db (handle);
  wyl_service_principal_t principal = { 0 };

  g_assert_cmpint (wyl_service_principal_create (handle, "svc:jobs:worker",
          "jobs worker", "admin.root", RETIRE_REQUEST_COLLISION, &principal),
      ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.subject_id, ==, "svc:jobs:worker");
  g_assert_cmpstr (principal.display_name, ==, "jobs worker");
  g_assert_cmpstr (principal.state, ==, "active");
  g_assert_cmpuint (principal.generation, ==, 1);
  g_assert_null (principal.disabled_by);
  wyl_service_principal_clear (&principal);

  g_assert_cmpint (wyl_service_principal_get (handle, "svc:jobs:worker",
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.created_by, ==, "admin.root");
  wyl_service_principal_clear (&principal);
  guint count = 0;
  g_assert_cmpint (wyl_service_principal_foreach (handle, count_principal,
          &count), ==, WYRELOG_E_OK);
  g_assert_cmpuint (count, ==, 1);

  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events "
          "WHERE event='created' AND generation=1;"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events a JOIN audit_intentions i "
          "ON i.audit_id=a.id WHERE a.action='service.principal.create' "
          "AND a.resource_id='svc:jobs:worker' AND a.subject_id='admin.root' "
          "AND a.request_id='" RETIRE_REQUEST_COLLISION
          "' AND i.state='pending';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events WHERE "
          "coalesce(action,'')||coalesce(resource_id,'')||"
          "coalesce(subject_id,'')||coalesce(request_id,'') "
          "LIKE '%jobs worker%';"), ==, 0);

  wyl_service_principal_t failed = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:other",
          "other", "admin.root", RETIRE_REQUEST_COLLISION, &failed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (failed.subject_id);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", RETIRE_REQUEST_COLLISION, &failed), ==,
      WYRELOG_E_CONFLICT);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);

  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", RETIRE_REQUEST_DISABLE, &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  g_assert_cmpuint (principal.generation, ==, 2);
  g_assert_cmpstr (principal.disabled_by, ==, "admin.root");
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, 2);

  /* A fresh request against an already-disabled principal is a committed
   * no-op attempt: ledger + audit/outbox advance, lifecycle events do not. */
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", RETIRE_REQUEST_NOOP, &principal), ==, WYRELOG_E_OK);
  g_assert_cmpuint (principal.generation, ==, 2);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts;"), ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events;"), ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_intentions WHERE state='pending';"), ==,
      3);
  g_assert_cmpint (wyl_service_principal_disable (handle, "svc:jobs:worker",
          "admin.root", RETIRE_REQUEST_NOOP, &failed), ==, WYRELOG_E_OK);
  g_assert_cmpstr (failed.state, ==, "disabled");
  wyl_service_principal_clear (&failed);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts;"), ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events;"), ==, 3);
}

static void
assert_registry_state (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation, WylServiceAuthState expected)
{
  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState state = WYL_SERVICE_AUTH_PENDING;
  gboolean found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          reservation->session_id, reservation->jti, &snapshot, &state,
          &found), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpint (state, ==, expected);
  wyl_service_auth_reservation_clear (&snapshot);
}

static WylServiceAuthState
registry_state (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation)
{
  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState state = WYL_SERVICE_AUTH_PENDING;
  gboolean found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry,
          reservation->session_id, reservation->jti, &snapshot, &state,
          &found), ==, WYRELOG_E_OK);
  g_assert_true (found);
  wyl_service_auth_reservation_clear (&snapshot);
  return state;
}

static void
test_registry_expiry_index_returns_bounded_due_active_entries (void)
{
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation first = {
    .session_id = (gchar *) SESSION_A,.jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,.generation = 1,
    .principal = (gchar *) "svc:expiry:first",.tenant = (gchar *) "jobs",
    .expires_at = 100,
  };
  WylServiceAuthReservation second = first;
  second.session_id = (gchar *) SESSION_B;
  second.jti = (gchar *) JTI_B;
  second.principal = (gchar *) "svc:expiry:second";
  second.expires_at = 200;
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &second), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &first,
          &changed), ==, WYRELOG_E_OK);
  g_assert_true (changed);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &second,
          &changed), ==, WYRELOG_E_OK);

  GPtrArray *due = NULL;
  g_assert_cmpint (wyl_service_auth_registry_copy_due (registry, 100, 1,
          &due), ==, WYRELOG_E_OK);
  g_assert_nonnull (due);
  g_assert_cmpuint (due->len, ==, 1);
  WylServiceAuthReservation *snapshot = g_ptr_array_index (due, 0);
  g_assert_cmpstr (snapshot->session_id, ==, SESSION_A);
  g_assert_cmpint (snapshot->expires_at, ==, 100);
  g_ptr_array_unref (due);

  due = NULL;
  g_assert_cmpint (wyl_service_auth_registry_copy_due (registry, 199, 4,
          &due), ==, WYRELOG_E_OK);
  g_assert_cmpuint (due->len, ==, 1);
  g_ptr_array_unref (due);
  WylServiceAuthReservation pending = first;
  pending.session_id = (gchar *) "01890c10-2e3f-7000-8000-000000000205";
  pending.jti = (gchar *) "01890c10-2e3f-7000-8000-000000000206";
  pending.principal = (gchar *) "svc:expiry:pending";
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &pending), ==,
      WYRELOG_E_OK);
  due = NULL;
  g_assert_cmpint (wyl_service_auth_registry_copy_due (registry, 100, 4,
          &due), ==, WYRELOG_E_POLICY);
  g_assert_null (due);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==, 3);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_registry_capacity_rejects_without_partial_reservation (void)
{
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  for (guint i = 0; i < WYL_SERVICE_AUTH_REGISTRY_MAX_ENTRIES; i++) {
    wyl_id_t session_id;
    wyl_id_t jti;
    gchar session[WYL_ID_STRING_BUF];
    gchar jti_text[WYL_ID_STRING_BUF];
    g_assert_cmpint (wyl_id_new (&session_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_new (&jti), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_format (&session_id, session, sizeof session), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_format (&jti, jti_text, sizeof jti_text), ==,
        WYRELOG_E_OK);
    WylServiceAuthReservation reservation = {
      .session_id = session,.jti = jti_text,
      .credential_id = (gchar *) CREDENTIAL_A,.generation = 1,
      .principal = (gchar *) "svc:capacity",.tenant = (gchar *) "jobs",
      .expires_at = 100000,
    };
    g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
            &reservation), ==, WYRELOG_E_OK);
  }
  WylServiceAuthReservation overflow = {
    .session_id = (gchar *) "01890c10-2e3f-7000-8000-000000000201",
    .jti = (gchar *) "01890c10-2e3f-7000-8000-000000000202",
    .credential_id = (gchar *) CREDENTIAL_A,.generation = 1,
    .principal = (gchar *) "svc:capacity",.tenant = (gchar *) "jobs",
    .expires_at = 100000,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &overflow),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
      WYL_SERVICE_AUTH_REGISTRY_MAX_ENTRIES);
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_registry_expiry_churn_stays_bounded (void)
{
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  for (gint64 window = 1; window <= 128; window++) {
    wyl_id_t session_id;
    wyl_id_t jti;
    gchar session[WYL_ID_STRING_BUF];
    gchar jti_text[WYL_ID_STRING_BUF];
    g_assert_cmpint (wyl_id_new (&session_id), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_new (&jti), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_format (&session_id, session, sizeof session), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_id_format (&jti, jti_text, sizeof jti_text), ==,
        WYRELOG_E_OK);
    WylServiceAuthReservation reservation = {
      .session_id = session,.jti = jti_text,
      .credential_id = (gchar *) CREDENTIAL_A,.generation = 1,
      .principal = (gchar *) "svc:expiry:churn",.tenant = (gchar *) "jobs",
      .expires_at = window,
    };
    gboolean changed = FALSE;
    g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
            &reservation), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_auth_registry_activate (registry,
            &reservation, &changed), ==, WYRELOG_E_OK);
    GPtrArray *due = NULL;
    g_assert_cmpint (wyl_service_auth_registry_copy_due (registry, window, 4,
            &due), ==, WYRELOG_E_OK);
    g_assert_cmpuint (due->len, ==, 1);
    WylServiceAuthReservation *snapshot = g_ptr_array_index (due, 0);
    gboolean removed = FALSE;
    g_assert_cmpint (wyl_service_auth_registry_remove_exact (registry,
            snapshot, &removed), ==, WYRELOG_E_OK);
    g_assert_true (removed);
    g_ptr_array_unref (due);
    g_assert_cmpuint (wyl_service_auth_registry_size_for_test (registry), ==,
        0);
  }
  g_assert_true (wyl_service_auth_registry_check_invariants_for_test
      (registry));
  wyl_service_auth_registry_unref (registry);
}

static void
test_compound_disable_zero_survivors (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:jobs:worker",
          "worker", "admin", "compound-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);

  WylServiceAuthReservation pending = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:jobs:worker",
    .tenant = (gchar *) "jobs",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  WylServiceAuthReservation unrelated = pending;
  unrelated.session_id = (gchar *) SESSION_B;
  unrelated.jti = (gchar *) JTI_B;
  unrelated.principal = (gchar *) "svc:jobs:other";
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &pending), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &unrelated),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &unrelated,
          &changed), ==, WYRELOG_E_OK);

  wyl_service_principal_disable_runtime_t runtime = {
    .registry = registry,
  };
  g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
          "svc:jobs:worker", "admin", "000000000000000000000000104", &runtime,
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  assert_registry_state (registry, &pending, WYL_SERVICE_AUTH_REVOKED);
  assert_registry_state (registry, &unrelated, WYL_SERVICE_AUTH_ACTIVE);
  wyl_service_principal_clear (&principal);

  /* Exact replay is read-only and therefore does not re-run invalidation. */
  g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
          "svc:jobs:worker", "admin", "000000000000000000000000104", &runtime,
          &principal), ==, WYRELOG_E_OK);
  assert_registry_state (registry, &pending, WYL_SERVICE_AUTH_REVOKED);
  wyl_service_principal_clear (&principal);
  wyl_service_auth_registry_unref (registry);
}

static void
test_write_participant_registry_rank (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:rank:worker",
    .tenant = (gchar *) "rank",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &reservation),
      ==, WYRELOG_E_OK);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  g_autoptr (WylServiceAuthRegistryWriteParticipant) participant = NULL;
  g_assert_cmpint (wyl_service_auth_registry_write_participant_new (registry,
          handle, lease, &participant), ==, WYRELOG_E_OK);
  WylServiceAuthSelector selector = { 0 };
  g_assert_cmpint (wyl_service_auth_selector_init_principal (&selector,
          reservation.principal), ==, WYRELOG_E_OK);
  WylServiceAuthRevokeResult revoked = { 0 };
  g_assert_cmpint (wyl_service_auth_rank_enter (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);
  g_assert_cmpint
      (wyl_service_auth_registry_write_participant_revoke_zero_survivors
      (participant, &selector, &revoked), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_auth_rank_leave_expected (handle,
          WYL_SERVICE_AUTH_RANK_REGISTRY), ==, WYRELOG_E_OK);
  assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_PENDING);
  g_assert_cmpint
      (wyl_service_auth_registry_write_participant_revoke_zero_survivors
      (participant, &selector, &revoked), ==, WYRELOG_E_OK);
  g_assert_cmpuint (revoked.matched, ==, 1);
  g_assert_cmpuint (revoked.transitioned, ==, 1);
  assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_REVOKED);
  g_clear_pointer (&participant,
      wyl_service_auth_registry_write_participant_free);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  wyl_service_auth_registry_unref (registry);
}

static wyrelog_error_t
tenant_seal_authorize (gpointer data, const gchar *actor_subject_id)
{
  (void) data;
  (void) actor_subject_id;
  return WYRELOG_E_OK;
}

static void
test_compound_tenant_seal_zero_survivors (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-a", &created), ==,
      WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-b", &created), ==,
      WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation matching = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:tenant-a:worker",
    .tenant = (gchar *) "tenant-a",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  WylServiceAuthReservation unrelated = matching;
  unrelated.session_id = (gchar *) SESSION_B;
  unrelated.jti = (gchar *) JTI_B;
  unrelated.principal = (gchar *) "svc:tenant-b:worker";
  unrelated.tenant = (gchar *) "tenant-b";
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &matching),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &unrelated),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_activate (registry, &matching,
          &changed), ==, WYRELOG_E_OK);

  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = tenant_seal_authorize,
  };
  wyl_tenant_seal_runtime_t runtime = {
    .registry = registry,
    .authorization = &authorization,
  };
  WylServiceRetirementOutcome outcome = { 0 };
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle, "tenant-a",
          "operator", "000000000000000000000000201", 1, &runtime,
          &outcome), ==, WYRELOG_E_OK);
  g_assert_true (outcome.transitioned_now);
  assert_registry_state (registry, &matching, WYL_SERVICE_AUTH_REVOKED);
  assert_registry_state (registry, &unrelated, WYL_SERVICE_AUTH_PENDING);

  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle, "tenant-a",
          "operator", "000000000000000000000000201", 1, &runtime,
          &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_EXACT_REPLAY);
  assert_registry_state (registry, &matching, WYL_SERVICE_AUTH_REVOKED);
  wyl_service_auth_registry_unref (registry);
}

static void
test_compound_corruption_latches_unavailable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:fault:worker",
          "worker", "admin", "fault-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:fault:worker",
    .tenant = (gchar *) "fault",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &reservation),
      ==, WYRELOG_E_OK);
  WylServiceAuthSelector selector = { 0 };
  g_assert_cmpint (wyl_service_auth_selector_init_principal (&selector,
          reservation.principal), ==, WYRELOG_E_OK);
  g_assert_true (wyl_service_auth_registry_corrupt_selector_index_for_test
      (registry, &selector));

  wyl_service_principal_disable_runtime_t runtime = {
    .registry = registry,
  };
  g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
          reservation.principal, "admin", "000000000000000000000000105",
          &runtime, &principal), ==, WYRELOG_E_BUSY);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (wyl_service_principal_get (handle, reservation.principal,
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  wyl_service_principal_clear (&principal);
  assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_PENDING);

  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT);
  wyl_service_auth_registry_unref (registry);
}

static void
fail_mark_unavailable_once (WylServiceAuthWriteLease *lease, gpointer data)
{
  (void) data;
  wyl_service_auth_write_lease_test_fail_mark_unavailable_once (lease);
}

static void
fail_write_release_once (WylServiceAuthWriteLease *lease, gpointer data)
{
  (void) data;
  wyl_service_auth_write_lease_test_fail_release_once (lease);
}

static void
test_compound_terminalizes_latch_and_release_failures (void)
{
  for (guint fault = 0; fault < 2; fault++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    WylServiceAuthRegistry *registry = NULL;
    g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==,
        WYRELOG_E_OK);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:terminal:worker", "worker", "admin", "terminal-create",
            &principal), ==, WYRELOG_E_OK);
    wyl_service_principal_clear (&principal);
    WylServiceAuthReservation reservation = {
      .session_id = (gchar *) SESSION_A,
      .jti = (gchar *) JTI_A,
      .credential_id = (gchar *) CREDENTIAL_A,
      .generation = 1,
      .principal = (gchar *) "svc:terminal:worker",
      .tenant = (gchar *) "terminal",
      .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
    };
    g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
            &reservation), ==, WYRELOG_E_OK);
    if (fault == 0) {
      WylServiceAuthSelector selector = { 0 };
      g_assert_cmpint (wyl_service_auth_selector_init_principal (&selector,
              reservation.principal), ==, WYRELOG_E_OK);
      g_assert_true (wyl_service_auth_registry_corrupt_selector_index_for_test
          (registry, &selector));
    }
    wyl_service_principal_disable_runtime_t runtime = {
      .registry = registry,
      .before_invalidation = fault == 0 ? fail_mark_unavailable_once : NULL,
      .before_write_release = fault == 1 ? fail_write_release_once : NULL,
    };
    g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
            reservation.principal, "admin",
            "000000000000000000000000106", &runtime,
            &principal), ==, fault == 0 ? WYRELOG_E_INTERNAL : WYRELOG_E_BUSY);
    g_assert_null (principal.subject_id);
    g_assert_cmpint (wyl_service_principal_get (handle,
            reservation.principal, &principal), ==, WYRELOG_E_OK);
    g_assert_cmpstr (principal.state, ==, "disabled");
    wyl_service_principal_clear (&principal);
    if (fault == 0)
      assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_PENDING);
    else
      assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_REVOKED);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
    WylServiceAuthAuthoritySnapshot snapshot = { 0 };
    wyl_service_auth_authority_snapshot
        (wyl_handle_get_service_auth_authority (handle), &snapshot);
    g_assert_false (snapshot.writer_active);
    wyl_service_auth_registry_unref (registry);
  }
}

static void
test_compound_commit_outcomes (void)
{
  static const WylPolicyAuthorityTransactionFailStage stages[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AND_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_INSTALL,
    WYL_POLICY_AUTHORITY_TXN_FAIL_AUTHORIZER_REMOVE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_LEASE_SERIAL_AT_FINISH,
  };
  for (guint i = 0; i < G_N_ELEMENTS (stages); i++) {
    WylPolicyAuthorityTransactionFailStage stage = stages[i];
    g_test_message ("compound commit fault stage=%u", (guint) stage);
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    WylServiceAuthRegistry *registry = NULL;
    g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==,
        WYRELOG_E_OK);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:outcome:worker", "worker", "admin", "outcome-create",
            &principal), ==, WYRELOG_E_OK);
    wyl_service_principal_clear (&principal);
    WylServiceAuthReservation reservation = {
      .session_id = (gchar *) SESSION_A,
      .jti = (gchar *) JTI_A,
      .credential_id = (gchar *) CREDENTIAL_A,
      .generation = 1,
      .principal = (gchar *) "svc:outcome:worker",
      .tenant = (gchar *) "outcome",
      .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
    };
    g_assert_cmpint (wyl_service_auth_registry_reserve (registry,
            &reservation), ==, WYRELOG_E_OK);
    wyl_service_principal_disable_runtime_t runtime = {
      .registry = registry,
    };
    wyl_policy_store_service_authority_transaction_fail_once
        (wyl_handle_get_policy_store (handle),
        (WylPolicyAuthorityTransactionFailStage) stage);
    g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
            reservation.principal, "admin",
            "000000000000000000000000107", &runtime,
            &principal), !=, WYRELOG_E_OK);
    g_assert_null (principal.subject_id);
    WylServiceAuthState auth_state = registry_state (registry, &reservation);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    wyrelog_error_t available = wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason);
    wyrelog_error_t lookup = wyl_service_principal_get (handle,
        reservation.principal, &principal);
    if (lookup == WYRELOG_E_OK) {
      gboolean committed = g_str_equal (principal.state, "disabled");
      g_assert_true (committed || g_str_equal (principal.state, "active"));
      if (committed)
        g_assert_true (auth_state == WYL_SERVICE_AUTH_REVOKED
            || available == WYRELOG_E_BUSY);
      else
        g_assert_true ((auth_state == WYL_SERVICE_AUTH_PENDING
                && available == WYRELOG_E_OK)
            || available == WYRELOG_E_BUSY);
    } else
      g_assert_cmpint (available, ==, WYRELOG_E_BUSY);
    wyl_service_principal_clear (&principal);
    if (available == WYRELOG_E_OK)
      g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
    else {
      g_assert_cmpint (available, ==, WYRELOG_E_BUSY);
      g_assert_cmpint (reason, !=, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
    }
    wyl_service_auth_registry_unref (registry);
  }
}

static void
test_compound_rollback_fault (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:rollback:unrelated",
    .tenant = (gchar *) "rollback",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &reservation),
      ==, WYRELOG_E_OK);
  wyl_service_principal_disable_runtime_t runtime = {
    .registry = registry,
  };
  wyl_policy_store_service_authority_transaction_fail_once
      (wyl_handle_get_policy_store (handle),
      WYL_POLICY_AUTHORITY_TXN_FAIL_ROLLBACK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
          "svc:rollback:missing", "admin",
          "000000000000000000000000108", &runtime,
          &principal), !=, WYRELOG_E_OK);
  g_assert_null (principal.subject_id);
  assert_registry_state (registry, &reservation, WYL_SERVICE_AUTH_PENDING);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  wyl_service_auth_registry_unref (registry);
}

static void
test_collision_classes (void)
{
  static const gchar *const fixtures[] = {
    "INSERT INTO principal_states VALUES('svc:collision','unverified',1,0,NULL);",
    "INSERT INTO principal_events(subject_id,event,from_state,to_state,created_at) VALUES('svc:collision','login_ok','unverified','mfa_required',1);",
    "INSERT INTO totp_enrollments VALUES('svc:collision',zeroblob(20),0,1,'id');",
    "INSERT INTO wyrelog_config VALUES('bootstrap_admin_subject','svc:collision',1);",
    "INSERT INTO session_states VALUES('svc:collision','active',1);",
    "INSERT INTO session_events(session_id,event,from_state,to_state,created_at) VALUES('svc:collision','request','idle','active',1);",
    "INSERT INTO permission_states VALUES('svc:collision','app.read','tenant-a','armed',1);",
    "INSERT INTO permission_state_events(subject_id,perm_id,scope,event,from_state,to_state,created_at) VALUES('svc:collision','app.read','tenant-a','grant','dormant','armed',1);",
    "INSERT INTO role_memberships(subject_id,role_id,scope,granted_at) VALUES('svc:collision','app.reader','tenant-a',1);",
    "INSERT INTO role_membership_events(subject_id,role_id,scope,operation,created_at) VALUES('svc:collision','app.reader','tenant-a','revoke',1);",
    "INSERT INTO direct_permissions VALUES('svc:collision','app.read','tenant-a',1);",
    "INSERT INTO direct_permission_events(subject_id,perm_id,scope,operation,created_at) VALUES('svc:collision','app.read','tenant-a','revoke',1);",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (fixtures); i++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    g_assert_cmpint (wyl_policy_store_upsert_role (store, "app.reader",
            "reader"), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_upsert_permission (store, "app.read",
            "read", "basic"), ==, WYRELOG_E_OK);
    exec_ok (db, fixtures[i]);
    wyl_service_principal_t principal = { 0 };
    g_autofree gchar *request = g_strdup_printf ("collision-%u", (guint) i);
    g_assert_cmpint (wyl_service_principal_create (handle, "svc:collision",
            "collision", "admin", request, &principal), ==, WYRELOG_E_POLICY);
    g_assert_null (principal.subject_id);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
}

static void
test_owned_output_contract (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);

  /* First use is zero-initialized. A populated result can then be reused
   * directly by a matching API without an explicit clear. */
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:output-contract", "output contract", "admin",
          "output-contract-create", &principal), ==, WYRELOG_E_OK);
  g_assert_nonnull (principal.subject_id);
  g_assert_cmpint (wyl_service_principal_get (handle,
          "svc:output-contract", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.display_name, ==, "output contract");

  /* Every failure clears a previously populated output. */
  g_assert_cmpint (wyl_service_principal_get (handle, "human-subject",
          &principal), ==, WYRELOG_E_INVALID);
  g_assert_null (principal.subject_id);
  g_assert_null (principal.display_name);
  g_assert_null (principal.state);
  g_assert_null (principal.created_by);
  g_assert_null (principal.disabled_by);
  g_assert_cmpuint (principal.generation, ==, 0);
}

typedef struct
{
  WylHandle *handle;
  const gchar *subject_id;
  const gchar *request_id;
  wyrelog_error_t rc;
} CreateThread;

static gpointer
create_thread (gpointer data)
{
  CreateThread *thread = data;
  wyl_service_principal_t principal = { 0 };
  thread->rc = wyl_service_principal_create (thread->handle,
      thread->subject_id, thread->subject_id, "admin", thread->request_id,
      &principal);
  wyl_service_principal_clear (&principal);
  return NULL;
}

static void
test_concurrent_request_claim (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  CreateThread a = { handle, "svc:concurrent:a", "concurrent-request", -1 };
  CreateThread b = { handle, "svc:concurrent:b", "concurrent-request", -1 };
  GThread *ta = g_thread_new ("principal-a", create_thread, &a);
  GThread *tb = g_thread_new ("principal-b", create_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_true ((a.rc == WYRELOG_E_OK && b.rc == WYRELOG_E_POLICY)
      || (a.rc == WYRELOG_E_POLICY && b.rc == WYRELOG_E_OK));
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_principals;"), ==, 1);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
}

typedef struct
{
  WylHandle *handle;
  const gchar *request_id;
  wyrelog_error_t rc;
} DisableThread;

static gpointer
disable_thread (gpointer data)
{
  DisableThread *thread = data;
  wyl_service_principal_t principal = { 0 };
  thread->rc = wyl_service_principal_disable (thread->handle,
      "svc:concurrent:disable", "admin", thread->request_id, &principal);
  wyl_service_principal_clear (&principal);
  return NULL;
}

static void
test_concurrent_disable (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:concurrent:disable", "concurrent disable", "admin",
          "concurrent-disable-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);

  DisableThread a = { handle, "000000000000000000000000109", -1 };
  DisableThread b = { handle, "00000000000000000000000010A", -1 };
  GThread *ta = g_thread_new ("disable-a", disable_thread, &a);
  GThread *tb = g_thread_new ("disable-b", disable_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);

  g_assert_cmpint (a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_principal_get (handle,
          "svc:concurrent:disable", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  g_assert_cmpuint (principal.generation, ==, 2);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_principal_events;"), ==, 2);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_domain_requests;"), ==, 1);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_retirement_receipts;"), ==, 2);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM audit_events;"), ==, 3);
}

typedef struct
{
  WylHandle *handle;
  const gchar *tenant_id;
  const gchar *actor;
  const gchar *request_id;
  wyrelog_error_t rc;
  WylServiceRetirementOutcome outcome;
} TenantSealThread;

static gpointer
tenant_seal_thread (gpointer data)
{
  TenantSealThread *thread = data;
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = tenant_seal_authorize,
  };
  wyl_tenant_seal_runtime_t runtime = {
    .authorization = &authorization,
  };
  thread->rc = wyl_tenant_seal_keyed_with_runtime (thread->handle,
      thread->tenant_id, thread->actor, thread->request_id, 1, &runtime,
      &thread->outcome);
  return NULL;
}

static void
test_concurrent_keyed_tenant_seal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-concurrent",
          &created), ==, WYRELOG_E_OK);
  TenantSealThread a = {
    .handle = handle,
    .tenant_id = "tenant-concurrent",
    .actor = "operator",
    .request_id = "000000000000000000000000216",
  };
  TenantSealThread b = a;
  GThread *ta = g_thread_new ("tenant-seal-a", tenant_seal_thread, &a);
  GThread *tb = g_thread_new ("tenant-seal-b", tenant_seal_thread, &b);
  g_thread_join (ta);
  g_thread_join (tb);
  g_assert_cmpint (a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b.rc, ==, WYRELOG_E_OK);
  g_assert_true ((a.outcome.disposition ==
          WYL_SERVICE_RETIREMENT_FRESH_TRANSITION
          && b.outcome.disposition == WYL_SERVICE_RETIREMENT_EXACT_REPLAY)
      || (b.outcome.disposition ==
          WYL_SERVICE_RETIREMENT_FRESH_TRANSITION
          && a.outcome.disposition == WYL_SERVICE_RETIREMENT_EXACT_REPLAY));
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "request_id='000000000000000000000000216';"), ==, 1);

  g_assert_cmpint (wyl_policy_store_create_tenant (store,
          "tenant-concurrent-mismatch", &created), ==, WYRELOG_E_OK);
  TenantSealThread c = {
    .handle = handle,
    .tenant_id = "tenant-concurrent-mismatch",
    .actor = "operator-a",
    .request_id = "000000000000000000000000217",
  };
  TenantSealThread d = c;
  d.actor = "operator-b";
  GThread *tc = g_thread_new ("tenant-seal-c", tenant_seal_thread, &c);
  GThread *td = g_thread_new ("tenant-seal-d", tenant_seal_thread, &d);
  g_thread_join (tc);
  g_thread_join (td);
  g_assert_true ((c.rc == WYRELOG_E_OK && d.rc == WYRELOG_E_CONFLICT)
      || (d.rc == WYRELOG_E_OK && c.rc == WYRELOG_E_CONFLICT));
  TenantSealThread *conflict = c.rc == WYRELOG_E_CONFLICT ? &c : &d;
  g_assert_cmpint (conflict->outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_KEY_CONFLICT);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "request_id='000000000000000000000000217';"), ==, 1);
}

static void
test_local_failure_rolls_back (void)
{
  static const gchar *const targets[] = {
    "service_principal_events", "audit_events", "audit_intentions",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (targets); i++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    g_autofree gchar *trigger =
        g_strdup_printf ("CREATE TRIGGER fail_local BEFORE INSERT ON %s "
        "BEGIN SELECT RAISE(ABORT,'fault'); END;", targets[i]);
    exec_ok (db, trigger);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle, "svc:fault",
            "fault", "admin", "fault-request", &principal), !=, WYRELOG_E_OK);
    g_assert_null (principal.subject_id);
    exec_ok (db, "DROP TRIGGER fail_local;");
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principal_events;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM audit_events;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM audit_intentions;"), ==, 0);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:receipt-fault", "receipt fault", "admin",
            "receipt-fault-create", &principal), ==, WYRELOG_E_OK);
    wyl_service_principal_clear (&principal);
    exec_ok (db,
        "CREATE TRIGGER fail_retirement_receipt BEFORE INSERT ON "
        "service_retirement_receipts BEGIN SELECT RAISE(ABORT,'fault'); END;");
    g_assert_cmpint (wyl_service_principal_disable (handle,
            "svc:receipt-fault", "admin",
            "000000000000000000000000113", &principal), !=, WYRELOG_E_OK);
    g_assert_null (principal.subject_id);
    exec_ok (db, "DROP TRIGGER fail_retirement_receipt;");
    g_assert_cmpint (wyl_service_principal_get (handle, "svc:receipt-fault",
            &principal), ==, WYRELOG_E_OK);
    g_assert_cmpstr (principal.state, ==, "active");
    wyl_service_principal_clear (&principal);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_retirement_receipts;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principal_events WHERE "
            "event='disabled';"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM audit_events WHERE "
            "action='service.principal.disable';"), ==, 0);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    sqlite3 *db = handle_db (handle);
    exec_ok (db,
        "CREATE TRIGGER validation_fault AFTER INSERT "
        "ON service_domain_requests BEGIN SELECT 1; END;");
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:validation-fault", "fault", "admin", "validation-fault",
            &principal), ==, WYRELOG_E_POLICY);
    exec_ok (db, "DROP TRIGGER validation_fault;");
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (db,
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    wyl_policy_store_service_lifecycle_fail_commit_once (store);
    wyl_service_principal_t principal = { 0 };
    g_assert_cmpint (wyl_service_principal_create (handle,
            "svc:commit-fault", "fault", "admin", "commit-fault",
            &principal), ==, WYRELOG_E_IO);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_domain_requests;"), ==, 0);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_principals;"), ==, 0);
  }
}

static void
test_restart_replay_and_overflow (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-principal-domain-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (store,
          "svc:restart", "restart", "admin", "restart-request", &principal),
      ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_clear (&principal);
  g_assert_cmpint (wyl_policy_store_disable_service_principal (store,
          "svc:restart", "admin", "00000000000000000000000010B",
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  wyl_policy_service_principal_info_clear (&principal);
  wyl_policy_store_close (store);

  store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_disable_service_principal (store,
          "svc:restart", "admin", "00000000000000000000000010B",
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.subject_id, ==, "svc:restart");
  g_assert_cmpstr (principal.state, ==, "disabled");
  g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "request_id='00000000000000000000000010B';"), ==, 1);
  g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_principal_events WHERE "
          "event='disabled';"), ==, 1);
  wyl_policy_service_principal_info_clear (&principal);

  exec_ok (wyl_policy_store_get_db (store),
      "INSERT INTO service_principals(subject_id,display_name,state,"
      "generation,created_by,created_at_us,updated_at_us) VALUES("
      "'svc:overflow','overflow','active',9223372036854775807,'admin',1,1);");
  g_assert_cmpint (wyl_policy_store_disable_service_principal (store,
          "svc:overflow", "admin", "00000000000000000000000010C",
          &principal), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM service_retirement_receipts "
          "WHERE request_id='00000000000000000000000010C';"), ==, 0);
  wyl_policy_store_close (store);

  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_restart_after_latch_rebuilds_empty_registry (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-principal-latch-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  WylHandleOpenOptions options = {
    .policy_store_path = path,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:restart-latch:worker", "worker", "admin",
          "restart-latch-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  WylServiceAuthReservation disabled = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:restart-latch:worker",
    .tenant = (gchar *) "restart-latch",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &disabled),
      ==, WYRELOG_E_OK);
  WylServiceAuthSelector selector = { 0 };
  g_assert_cmpint (wyl_service_auth_selector_init_principal (&selector,
          disabled.principal), ==, WYRELOG_E_OK);
  g_assert_true (wyl_service_auth_registry_corrupt_selector_index_for_test
      (registry, &selector));
  wyl_service_principal_disable_runtime_t runtime = {
    .registry = registry,
  };
  g_assert_cmpint (wyl_service_principal_disable_with_runtime (handle,
          disabled.principal, "admin", "00000000000000000000000010D",
          &runtime, &principal), ==, WYRELOG_E_BUSY);
  wyl_service_principal_clear (&principal);
  wyl_service_auth_registry_unref (registry);
  registry = NULL;
  g_clear_object (&handle);

  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_principal_get (handle, disabled.principal,
          &principal), ==, WYRELOG_E_OK);
  g_assert_cmpstr (principal.state, ==, "disabled");
  wyl_service_principal_clear (&principal);
  WylServiceAuthUnavailableReason reason =
      WYL_SERVICE_AUTH_UNAVAILABLE_REGISTRY_INVARIANT;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (reason, ==, WYL_SERVICE_AUTH_UNAVAILABLE_NONE);
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:restart-latch:unrelated", "unrelated", "admin",
          "restart-latch-unrelated", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);

  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation unrelated = disabled;
  unrelated.session_id = (gchar *) SESSION_B;
  unrelated.jti = (gchar *) JTI_B;
  unrelated.principal = (gchar *) "svc:restart-latch:unrelated";
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WylServiceAuthRegistrySessionParticipant *participant = NULL;
  g_assert_cmpint
      (wyl_service_auth_registry_session_participant_new_for_write
      (registry, handle, lease, &participant), ==, WYRELOG_E_OK);
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_session_participant_reserve
      (participant, &unrelated), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_session_participant_activate
      (participant, &unrelated, &changed), ==, WYRELOG_E_OK);
  g_assert_true (changed);
  wyl_service_auth_registry_session_participant_free (participant);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  wyl_service_auth_registry_unref (registry);
  g_clear_object (&handle);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_ledger_integrity (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  sqlite3 *db = handle_db (handle);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, "svc:ledger",
          "ledger", "admin", "ledger-request", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  exec_rejected (db,
      "UPDATE service_domain_requests SET resource_id='svc:other';");
  exec_rejected (db, "DELETE FROM service_domain_requests;");
  exec_ok (db, "DROP TRIGGER trg_service_domain_requests_no_delete;");
  g_assert_cmpint (wyl_policy_store_validate_service_schema
      (wyl_handle_get_policy_store (handle)), ==, WYRELOG_E_POLICY);
}

static void
test_authority_core_owns_single_transaction (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  WylServiceAuthorityTransaction *transaction = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, lease, &transaction), ==, WYRELOG_E_OK);

  wyl_policy_service_principal_info_t principal = { 0 };
  g_assert_cmpint (wyl_policy_store_create_service_principal (store,
          "svc:authority:legacy", "legacy", "admin", "authority-legacy",
          &principal), ==, WYRELOG_E_BUSY);
  g_assert_null (principal.subject_id);
  g_assert_cmpint (wyl_policy_store_create_service_principal_core
      (transaction, store, "svc:authority:core", "core", "admin",
          "authority-core", &principal), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (transaction), ==, WYRELOG_E_OK);
  wyl_policy_service_principal_info_clear (&principal);
  principal.subject_id = g_strdup ("populated");
  g_assert_cmpint (wyl_policy_store_create_service_principal_core
      (transaction, store, "svc:authority:invalid", "invalid", "admin",
          "authority-invalid", &principal), ==, WYRELOG_E_INVALID);
  g_assert_null (principal.subject_id);
  wyl_policy_store_service_authority_transaction_free (transaction);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_principals WHERE subject_id LIKE "
          "'svc:authority:%';"), ==, 1);
}

typedef struct
{
  WylHandle *handle;
  guint authorization_calls;
  guint invalidation_calls;
} RetirementProbe;

static wyrelog_error_t
retirement_authorize (gpointer data, const gchar *actor_subject_id)
{
  RetirementProbe *probe = data;
  WylServiceAuthAuthoritySnapshot snapshot = { 0 };
  probe->authorization_calls++;
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (probe->handle), &snapshot);
  g_assert_true (snapshot.writer_active);
  g_assert_nonnull (actor_subject_id);
  return WYRELOG_E_OK;
}

static void
retirement_before_invalidation (WylServiceAuthWriteLease *lease, gpointer data)
{
  RetirementProbe *probe = data;
  g_assert_nonnull (lease);
  probe->invalidation_calls++;
}

static void
test_keyed_disable_receipt_semantics (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  sqlite3 *db = handle_db (handle);
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle,
          "svc:receipt:principal", "receipt principal", "creator",
          "receipt-principal-create", &principal), ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);

  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  WylServiceAuthReservation reservation = {
    .session_id = (gchar *) SESSION_A,
    .jti = (gchar *) JTI_A,
    .credential_id = (gchar *) CREDENTIAL_A,
    .generation = 1,
    .principal = (gchar *) "svc:receipt:principal",
    .tenant = (gchar *) "receipt",
    .expires_at = g_get_real_time () / G_USEC_PER_SEC + 3600,
  };
  g_assert_cmpint (wyl_service_auth_registry_reserve (registry, &reservation),
      ==, WYRELOG_E_OK);

  RetirementProbe probe = {.handle = handle };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = retirement_authorize,
    .data = &probe,
  };
  wyl_service_principal_disable_runtime_t runtime = {
    .registry = registry,
    .before_invalidation = retirement_before_invalidation,
    .authorization = &authorization,
    .data = &probe,
  };
  const gchar *transition_request = "000000000000000000000000110";
  const gchar *terminal_request = "000000000000000000000000111";
  WylServiceRetirementOutcome outcome = { 0 };
  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-a", transition_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_FRESH_TRANSITION);
  g_assert_true (outcome.transitioned_now);
  g_assert_false (outcome.replayed);
  g_assert_cmpuint (outcome.recorded_authority_generation, ==, 2);
  g_assert_cmpuint (outcome.current_authority_generation, ==, 2);
  g_assert_cmpuint (probe.authorization_calls, ==, 1);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  wyl_service_principal_clear (&principal);
  gint64 events = scalar_int64 (db,
      "SELECT count(*) FROM service_principal_events;");
  gint64 audits = scalar_int64 (db, "SELECT count(*) FROM audit_events;");
  gint64 intentions = scalar_int64 (db,
      "SELECT count(*) FROM audit_intentions;");
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts;"), ==, 1);

  WylServiceAuthSelector selector = { 0 };
  g_assert_cmpint (wyl_service_auth_selector_init_principal (&selector,
          reservation.principal), ==, WYRELOG_E_OK);
  g_assert_true (wyl_service_auth_registry_corrupt_selector_index_for_test
      (registry, &selector));
  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-a", transition_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_EXACT_REPLAY);
  g_assert_false (outcome.transitioned_now);
  g_assert_true (outcome.replayed);
  g_assert_cmpuint (probe.authorization_calls, ==, 2);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, events);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM audit_events;"), ==,
      audits);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_intentions;"), ==, intentions);

  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-a", transition_request, 2,
          &runtime, &outcome, &principal), ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_KEY_CONFLICT);
  g_assert_null (principal.subject_id);
  g_assert_cmpuint (probe.authorization_calls, ==, 3);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);

  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-b", transition_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_KEY_CONFLICT);
  g_assert_cmpuint (probe.authorization_calls, ==, 4);

  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-b",
          "000000000000000000000000112", 2, &runtime, &outcome,
          &principal), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_null (principal.subject_id);
  g_assert_cmpuint (probe.authorization_calls, ==, 5);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);

  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-b", terminal_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_FRESH_ALREADY_TERMINAL);
  g_assert_false (outcome.transitioned_now);
  g_assert_false (outcome.replayed);
  g_assert_cmpuint (probe.authorization_calls, ==, 6);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  wyl_service_principal_clear (&principal);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_principal_events;"), ==, events);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM audit_events;"), ==,
      audits + 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_intentions;"), ==, intentions + 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts;"), ==, 2);

  exec_ok (db,
      "UPDATE audit_events SET action=action||char(0)||'corrupt' "
      "WHERE request_id=" "'000000000000000000000000110';");
  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-a", transition_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_null (principal.subject_id);
  g_assert_cmpuint (probe.authorization_calls, ==, 7);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);

  exec_ok (db, "DROP TRIGGER trg_service_retirement_no_delete;");
  exec_ok (db,
      "DELETE FROM service_retirement_receipts WHERE request_id="
      "'000000000000000000000000110';");
  g_assert_cmpint (wyl_service_principal_disable_keyed_with_runtime (handle,
          reservation.principal, "operator-a", transition_request, 1,
          &runtime, &outcome, &principal), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_null (principal.subject_id);
  g_assert_cmpuint (probe.authorization_calls, ==, 8);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  wyl_service_auth_registry_unref (registry);
}

typedef struct
{
  guint authorization_calls;
  guint invalidation_calls;
  gboolean deny;
} TenantRetirementProbe;

static wyrelog_error_t
tenant_retirement_authorize (gpointer data, const gchar *actor_subject_id)
{
  TenantRetirementProbe *probe = data;
  g_assert_nonnull (actor_subject_id);
  probe->authorization_calls++;
  return probe->deny ? WYRELOG_E_AUTH : WYRELOG_E_OK;
}

static void
tenant_retirement_before_invalidation (WylServiceAuthWriteLease *lease,
    gpointer data)
{
  TenantRetirementProbe *probe = data;
  g_assert_nonnull (lease);
  probe->invalidation_calls++;
}

static void
test_keyed_tenant_seal_receipt_semantics (void)
{
  const gchar *request_a = "000000000000000000000000210";
  const gchar *request_b = "000000000000000000000000211";
  const gchar *request_c = "000000000000000000000000212";
  const gchar *request_denied = "000000000000000000000000213";
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = handle_db (handle);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-receipt",
          &created), ==, WYRELOG_E_OK);
  g_assert_true (created);

  WylServiceAuthRegistry *registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  TenantRetirementProbe probe = { 0 };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = tenant_retirement_authorize,
    .data = &probe,
  };
  wyl_tenant_seal_runtime_t runtime = {
    .registry = registry,
    .before_invalidation = tenant_retirement_before_invalidation,
    .authorization = &authorization,
    .data = &probe,
  };
  WylServiceRetirementOutcome outcome = { 0 };

  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_a, 1, &runtime, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_FRESH_TRANSITION);
  g_assert_true (outcome.transitioned_now);
  g_assert_cmpuint (outcome.recorded_tenant_lifecycle_generation, ==, 0);
  g_assert_cmpuint (outcome.recorded_tenant_sealed_generation, ==, 1);
  g_assert_cmpuint (outcome.recorded_authority_generation, ==, 1);
  g_assert_cmpuint (probe.authorization_calls, ==, 1);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "operation='tenant_seal';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events WHERE action='tenant_seal';"),
      ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_intentions WHERE action='tenant_seal';"),
      ==, 1);

  memset (&outcome, 0, sizeof outcome);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_a, 1, &runtime, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_EXACT_REPLAY);
  g_assert_true (outcome.replayed);
  g_assert_false (outcome.transitioned_now);
  g_assert_cmpuint (probe.authorization_calls, ==, 2);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events WHERE action='tenant_seal';"),
      ==, 1);

  memset (&outcome, 0xff, sizeof outcome);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a",
          "000000000000000000000000218", 2, &runtime, &outcome), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_cmpuint (probe.authorization_calls, ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "operation='tenant_seal';"), ==, 1);

  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-b", request_a, 1, &runtime, &outcome),
      ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_KEY_CONFLICT);
  g_assert_cmpuint (probe.authorization_calls, ==, 4);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);

  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store,
          "tenant-receipt", FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_a, 1, &runtime, &outcome),
      ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==, WYL_SERVICE_RETIREMENT_SUPERSEDED);
  g_assert_cmpuint (outcome.recorded_tenant_sealed_generation, ==, 1);
  g_assert_cmpuint (outcome.current_tenant_sealed_generation, ==, 2);
  g_assert_cmpuint (probe.invalidation_calls, ==, 1);

  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_b, 1, &runtime, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_FRESH_TRANSITION);
  g_assert_cmpuint (outcome.recorded_tenant_sealed_generation, ==, 3);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_a, 1, &runtime, &outcome),
      ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==, WYL_SERVICE_RETIREMENT_SUPERSEDED);
  g_assert_cmpuint (outcome.current_tenant_sealed_generation, ==, 3);

  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_FRESH_ALREADY_TERMINAL);
  g_assert_false (outcome.transitioned_now);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "operation='tenant_seal';"), ==, 3);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM audit_events WHERE action='tenant_seal';"),
      ==, 3);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_EXACT_REPLAY);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);

  probe.deny = TRUE;
  memset (&outcome, 0xff, sizeof outcome);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_denied, 1, &runtime,
          &outcome), ==, WYRELOG_E_AUTH);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_cmpint (scalar_int64 (db,
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "operation='tenant_seal';"), ==, 3);
  probe.deny = FALSE;

  WylPolicyAuthorityMutationResult authority_result =
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION;
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
          "tenant-receipt", WYL_POLICY_TENANT_LIFECYCLE_SEALED, 0, 0,
          &authority_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority_result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (outcome.disposition, ==, WYL_SERVICE_RETIREMENT_SUPERSEDED);
  g_assert_cmpuint (outcome.recorded_tenant_lifecycle_generation, ==, 0);
  g_assert_cmpuint (outcome.current_tenant_lifecycle_generation, ==, 1);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);

  exec_ok (db, "DROP TRIGGER trg_service_retirement_no_update;");
  exec_ok (db,
      "UPDATE service_retirement_receipts SET authority_generation=2 "
      "WHERE request_id='000000000000000000000000212';");
  probe.deny = TRUE;
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_AUTH);
  g_assert_cmpint (outcome.disposition, ==, 0);
  probe.deny = FALSE;
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);
  exec_ok (db, "DROP TRIGGER trg_service_retirement_no_delete;");
  exec_ok (db,
      "DELETE FROM service_retirement_receipts WHERE "
      "request_id='000000000000000000000000212';");
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt", "operator-a", request_c, 1, &runtime, &outcome),
      ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (outcome.disposition, ==, 0);
  g_assert_cmpuint (probe.invalidation_calls, ==, 2);
  wyl_service_auth_registry_unref (registry);
}

static void
test_keyed_tenant_seal_restart_and_commit_fault (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-tenant-receipt-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  WylHandleOpenOptions options = {
    .policy_store_path = path,
  };
  TenantRetirementProbe probe = { 0 };
  wyl_service_credential_mutation_authorization_t authorization = {
    .authorize = tenant_retirement_authorize,
    .data = &probe,
  };
  wyl_tenant_seal_runtime_t runtime = {
    .authorization = &authorization,
  };
  WylServiceRetirementOutcome outcome = { 0 };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-restart",
          &created), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-restart", "operator", "000000000000000000000000214", 1,
          &runtime, &outcome), ==, WYRELOG_E_OK);
  g_clear_object (&handle);

  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-restart", "operator", "000000000000000000000000214", 1,
          &runtime, &outcome), ==, WYRELOG_E_OK);
  g_assert_cmpint (outcome.disposition, ==,
      WYL_SERVICE_RETIREMENT_EXACT_REPLAY);
  g_assert_cmpuint (probe.authorization_calls, ==, 2);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM audit_events WHERE action='tenant_seal';"),
      ==, 1);

  store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-fault",
          &created), ==, WYRELOG_E_OK);
  wyl_policy_store_service_lifecycle_fail_commit_once (store);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-fault", "operator", "000000000000000000000000215", 1,
          &runtime, &outcome), ==, WYRELOG_E_IO);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT sealed FROM tenants WHERE tenant_id='tenant-fault';"), ==, 0);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM service_retirement_receipts WHERE "
          "request_id='000000000000000000000000215';"), ==, 0);

  exec_ok (handle_db (handle),
      "CREATE TRIGGER fail_tenant_seal_audit BEFORE INSERT ON audit_events "
      "WHEN NEW.action='tenant_seal' BEGIN SELECT RAISE(ABORT,'fault'); END;");
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-fault", "operator", "000000000000000000000000219", 1,
          &runtime, &outcome), !=, WYRELOG_E_OK);
  exec_ok (handle_db (handle), "DROP TRIGGER fail_tenant_seal_audit;");
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT sealed FROM tenants WHERE tenant_id='tenant-fault';"), ==, 0);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM audit_intentions WHERE "
          "request_id='000000000000000000000000219';"), ==, 0);
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-fault", "operator", "000000000000000000000000219", 1,
          &runtime, &outcome), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_policy_store_create_tenant (store,
          "tenant-receipt-fault", &created), ==, WYRELOG_E_OK);
  exec_ok (handle_db (handle),
      "CREATE TRIGGER fail_tenant_seal_receipt BEFORE INSERT ON "
      "service_retirement_receipts WHEN NEW.operation='tenant_seal' "
      "BEGIN SELECT RAISE(ABORT,'fault'); END;");
  g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
          "tenant-receipt-fault", "operator",
          "00000000000000000000000021A", 1, &runtime, &outcome), !=,
      WYRELOG_E_OK);
  exec_ok (handle_db (handle), "DROP TRIGGER fail_tenant_seal_receipt;");
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT sealed FROM tenants WHERE "
          "tenant_id='tenant-receipt-fault';"), ==, 0);
  g_assert_cmpint (scalar_int64 (handle_db (handle),
          "SELECT count(*) FROM audit_events WHERE "
          "request_id='00000000000000000000000021A';"), ==, 0);
  g_clear_object (&handle);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_retirement_postcommit_error_normalization (void)
{
  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (store,
            "tenant-no-selector", &created), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store,
            "tenant-no-selector", TRUE), ==, WYRELOG_E_OK);
    wyl_service_credential_mutation_authorization_t authorization = {
      .authorize = tenant_seal_authorize,
    };
    wyl_tenant_seal_runtime_t runtime = {
      .authorization = &authorization,
    };
    wyl_policy_store_service_authority_transaction_fail_once (store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
    WylServiceRetirementOutcome outcome = { 0 };
    g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
            "tenant-no-selector", "operator",
            "00000000000000000000000021B", 1, &runtime, &outcome), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (outcome.disposition, ==, 0);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_retirement_receipts WHERE "
            "request_id='00000000000000000000000021B';"), ==, 1);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM audit_events WHERE "
            "request_id='00000000000000000000000021B' AND "
            "action='tenant_seal';"), ==, 1);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (store,
            "tenant-uncertain", &created), ==, WYRELOG_E_OK);
    wyl_service_credential_mutation_authorization_t authorization = {
      .authorize = tenant_seal_authorize,
    };
    wyl_tenant_seal_runtime_t runtime = {
      .authorization = &authorization,
    };
    wyl_policy_store_service_authority_transaction_fail_once (store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AND_ROLLBACK);
    WylServiceRetirementOutcome outcome = { 0 };
    g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
            "tenant-uncertain", "operator",
            "00000000000000000000000021C", 1, &runtime, &outcome), ==,
        WYRELOG_E_BUSY);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (store,
            "tenant-replay-cleanup", &created), ==, WYRELOG_E_OK);
    wyl_service_credential_mutation_authorization_t authorization = {
      .authorize = tenant_seal_authorize,
    };
    wyl_tenant_seal_runtime_t runtime = {
      .authorization = &authorization,
    };
    const gchar *request_id = "00000000000000000000000021D";
    WylServiceRetirementOutcome outcome = { 0 };
    g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
            "tenant-replay-cleanup", "operator", request_id, 1, &runtime,
            &outcome), ==, WYRELOG_E_OK);
    gint64 receipt_count = scalar_int64 (handle_db (handle),
        "SELECT count(*) FROM service_retirement_receipts;");
    gint64 audit_count = scalar_int64 (handle_db (handle),
        "SELECT count(*) FROM audit_events WHERE action='tenant_seal';");
    runtime.before_write_release = fail_write_release_once;
    memset (&outcome, 0xff, sizeof outcome);
    g_assert_cmpint (wyl_tenant_seal_keyed_with_runtime (handle,
            "tenant-replay-cleanup", "operator", request_id, 1, &runtime,
            &outcome), ==, WYRELOG_E_BUSY);
    g_assert_cmpint (outcome.disposition, ==, 0);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM service_retirement_receipts;"), ==,
        receipt_count);
    g_assert_cmpint (scalar_int64 (handle_db (handle),
            "SELECT count(*) FROM audit_events WHERE action='tenant_seal';"),
        ==, audit_count);
    WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
    g_assert_cmpint (wyl_service_auth_authority_validate_available
        (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
        WYRELOG_E_BUSY);
    g_assert_cmpint (reason, ==,
        WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/auth/service-principal/create-get-list-disable",
      test_create_get_list_disable);
  g_test_add_func ("/auth/service-principal/owned-output-contract",
      test_owned_output_contract);
  g_test_add_func ("/auth/service-principal/compound-zero-survivors",
      test_compound_disable_zero_survivors);
  g_test_add_func ("/auth/service-principal/registry-expiry-index",
      test_registry_expiry_index_returns_bounded_due_active_entries);
  g_test_add_func ("/auth/service-principal/registry-capacity",
      test_registry_capacity_rejects_without_partial_reservation);
  g_test_add_func ("/auth/service-principal/registry-expiry-churn",
      test_registry_expiry_churn_stays_bounded);
  g_test_add_func ("/auth/service-principal/write-participant-registry-rank",
      test_write_participant_registry_rank);
  g_test_add_func ("/auth/service-principal/compound-tenant-seal",
      test_compound_tenant_seal_zero_survivors);
  g_test_add_func ("/auth/service-principal/compound-corruption-latch",
      test_compound_corruption_latches_unavailable);
  g_test_add_func ("/auth/service-principal/compound-terminal-faults",
      test_compound_terminalizes_latch_and_release_failures);
  g_test_add_func ("/auth/service-principal/compound-commit-outcomes",
      test_compound_commit_outcomes);
  g_test_add_func ("/auth/service-principal/compound-rollback-fault",
      test_compound_rollback_fault);
  g_test_add_func ("/auth/service-principal/collision-classes",
      test_collision_classes);
  g_test_add_func ("/auth/service-principal/concurrent-request",
      test_concurrent_request_claim);
  g_test_add_func ("/auth/service-principal/concurrent-disable",
      test_concurrent_disable);
  g_test_add_func ("/auth/tenant/concurrent-keyed-seal",
      test_concurrent_keyed_tenant_seal);
  g_test_add_func ("/auth/service-principal/local-failure-rollback",
      test_local_failure_rolls_back);
  g_test_add_func ("/auth/service-principal/ledger-integrity",
      test_ledger_integrity);
  g_test_add_func ("/auth/service-principal/authority-core-single-transaction",
      test_authority_core_owns_single_transaction);
  g_test_add_func ("/auth/service-principal/restart-replay-overflow",
      test_restart_replay_and_overflow);
  g_test_add_func ("/auth/service-principal/restart-after-latch",
      test_restart_after_latch_rebuilds_empty_registry);
  g_test_add_func ("/auth/service-principal/keyed-receipt-semantics",
      test_keyed_disable_receipt_semantics);
  g_test_add_func ("/auth/tenant/keyed-seal-receipt-semantics",
      test_keyed_tenant_seal_receipt_semantics);
  g_test_add_func ("/auth/tenant/keyed-seal-restart-commit-fault",
      test_keyed_tenant_seal_restart_and_commit_fault);
  g_test_add_func ("/auth/retirement/postcommit-error-normalization",
      test_retirement_postcommit_error_normalization);
  return g_test_run ();
}
