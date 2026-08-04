/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "daemon/checks.h"
#include "wyrelog/engine.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static gint64
query_count (wyl_policy_store_t *store, const gchar *sql, const gchar *argument)
{
  sqlite3_stmt *stmt = NULL;
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  if (argument != NULL)
    g_assert_cmpint (sqlite3_bind_text (stmt, 1, argument, -1,
            SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static gint64
readiness_event_count (wyl_policy_store_t *store)
{
  return query_count (store,
      "SELECT COUNT(*) FROM audit_events "
      "WHERE subject_id='wyrelogd' "
      "AND action='policy_audit_reload_check' "
      "AND resource_id='audit_event' "
      "AND deny_reason='readiness' "
      "AND deny_origin='policy_store' "
      "AND request_id='wyrelogd-readiness-request' AND decision=1;", NULL);
}

static gint64
readiness_intention_count (wyl_policy_store_t *store, const gchar *state)
{
  sqlite3_stmt *stmt = NULL;
  sqlite3 *db = wyl_policy_store_get_db (store);
  static const gchar *sql =
      "SELECT COUNT(*) FROM audit_intentions "
      "WHERE subject_id='wyrelogd' "
      "AND action='policy_audit_reload_check' "
      "AND resource_id='audit_event' "
      "AND deny_reason='readiness' "
      "AND deny_origin='policy_store' "
      "AND request_id='wyrelogd-readiness-request' AND decision=1 "
      "AND state=?;";
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, state, -1, SQLITE_TRANSIENT),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static void
assert_exact_durable_bundle (WylHandle *handle, const gchar *id,
    gint64 created_at_us, gboolean present)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  static const gchar *event_sql =
      "SELECT COUNT(*) FROM audit_events WHERE id=? AND created_at_us=? "
      "AND subject_id='wyrelogd' AND action='policy_audit_reload_check' "
      "AND resource_id='audit_event' AND deny_reason='readiness' "
      "AND deny_origin='policy_store' "
      "AND request_id='wyrelogd-readiness-request' AND decision=1;";
  static const gchar *intention_sql =
      "SELECT COUNT(*) FROM audit_intentions "
      "WHERE audit_id=? AND created_at_us=? "
      "AND subject_id='wyrelogd' AND action='policy_audit_reload_check' "
      "AND resource_id='audit_event' AND deny_reason='readiness' "
      "AND deny_origin='policy_store' "
      "AND request_id='wyrelogd-readiness-request' AND decision=1 "
      "AND state='committed' AND attempt_count=0 AND last_error IS NULL;";
  const gchar *queries[] = { event_sql, intention_sql };

  for (guint i = 0; i < G_N_ELEMENTS (queries); i++) {
    sqlite3_stmt *stmt = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (db, queries[i], -1, &stmt, NULL), ==,
        SQLITE_OK);
    g_assert_cmpint (sqlite3_bind_text (stmt, 1, id, -1, SQLITE_TRANSIENT),
        ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_bind_int64 (stmt, 2, created_at_us), ==,
        SQLITE_OK);
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    g_assert_cmpint (sqlite3_column_int64 (stmt, 0), ==, present ? 1 : 0);
    sqlite3_finalize (stmt);
  }
  if (!present) {
    g_assert_cmpint (query_count (store,
            "SELECT COUNT(*) FROM audit_events WHERE id=?;", id), ==, 0);
    g_assert_cmpint (query_count (store,
            "SELECT COUNT(*) FROM audit_intentions WHERE audit_id=?;", id),
        ==, 0);
  }
}

typedef struct
{
  gint64 key;
  const gint64 *expected;
  guint ncols;
  guint keyed_count;
  guint exact_count;
} ExactProjectionProbe;

static void
exact_projection_probe_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  (void) relation;
  ExactProjectionProbe *probe = user_data;
  if (ncols == 0 || row[0] != probe->key)
    return;
  probe->keyed_count++;
  if (ncols != probe->ncols)
    return;
  for (guint i = 0; i < ncols; i++) {
    if (row[i] != probe->expected[i])
      return;
  }
  probe->exact_count++;
}

static void
assert_exact_projection (WylHandle *handle, const gchar *id,
    gint64 created_at_us)
{
  gint64 event[3] = { 0 };
  gint64 action[2] = { 0 };
  gint64 request[2] = { 0 };
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, id, &event[0]),
      ==, WYRELOG_E_OK);
  event[1] = created_at_us;
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle, "allow",
          &event[2]), ==, WYRELOG_E_OK);
  action[0] = request[0] = event[0];
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle,
          "policy_audit_reload_check", &action[1]), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_handle_intern_engine_symbol (handle,
          "wyrelogd-readiness-request", &request[1]), ==, WYRELOG_E_OK);

  const gchar *relations[] = {
    "audit_event",
    "audit_event_action",
    "audit_event_request_id",
  };
  const gint64 *rows[] = { event, action, request };
  const guint widths[] = { 3, 2, 2 };
  for (guint i = 0; i < G_N_ELEMENTS (relations); i++) {
    ExactProjectionProbe probe = {
      .key = event[0],
      .expected = rows[i],
      .ncols = widths[i],
    };
    g_assert_cmpint (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
            relations[i], exact_projection_probe_cb, &probe), ==, WYRELOG_E_OK);
    g_assert_cmpuint (probe.keyed_count, ==, 1);
    g_assert_cmpuint (probe.exact_count, ==, 1);
  }
}

static void
assert_publication_resources_released (WylHandle *handle)
{
  guint total_pins = G_MAXUINT;
  guint current_thread_pins = G_MAXUINT;
  wyl_handle_policy_store_pin_snapshot_for_test (handle, &total_pins,
      &current_thread_pins);
  g_assert_cmpuint (total_pins, ==, 0);
  g_assert_cmpuint (current_thread_pins, ==, 0);
  g_assert_true (wyl_policy_store_is_autocommit
      (wyl_handle_get_policy_store (handle)));
  for (WylServiceAuthRank rank = WYL_SERVICE_AUTH_RANK_COORDINATION;
      rank <= WYL_SERVICE_AUTH_RANK_REGISTRY; rank++)
    g_assert_false (wyl_service_auth_rank_is_held (handle, rank));
  g_assert_cmpuint (wyl_handle_engine_session_depth_for_test (handle), ==, 0);
  g_assert_false (wyl_handle_engine_session_locked_for_test (handle));
  g_assert_cmpuint (wyl_handle_pending_delta_count_for_test (handle), ==, 0);
  g_assert_cmpuint (wyl_handle_engine_session_depth_for_test (handle), ==, 0);
  g_assert_false (wyl_handle_engine_session_locked_for_test (handle));
}

static void
test_success_repeats_and_public_emit_stays_disabled (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle), ==, WYRELOG_E_OK);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (readiness_event_count (store), ==, 0);

  g_autofree gchar *first_id = NULL;
  g_autofree gchar *second_id = NULL;
  gint64 first_time = -1, second_time = -1;
  WylCommittedPublicationStage stage =
      WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED;
  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &first_id, &first_time, &stage, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (stage, ==, WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED);
  g_assert_cmpint (readiness_event_count (store), ==, 1);
  g_assert_cmpint (readiness_intention_count (store, "committed"), ==, 1);
  g_assert_cmpint (readiness_intention_count (store, "pending"), ==, 0);
  g_assert_cmpint (readiness_intention_count (store, "failed"), ==, 0);
  assert_exact_durable_bundle (handle, first_id, first_time, TRUE);
  assert_exact_projection (handle, first_id, first_time);

  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &second_id, &second_time, &stage, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpstr (second_id, !=, first_id);
  g_assert_cmpint (readiness_event_count (store), ==, 2);
  g_assert_cmpint (readiness_intention_count (store, "committed"), ==, 2);
  assert_exact_durable_bundle (handle, second_id, second_time, TRUE);
  assert_exact_projection (handle, second_id, second_time);

  g_autoptr (WylAuditEvent) event = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (event, "no-audit-public-api");
  wyl_audit_event_set_action (event, "must-stay-disabled");
  wyl_audit_event_set_decision (event, WYL_DECISION_ALLOW);
  g_assert_cmpint (wyl_audit_emit (handle, event), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (readiness_event_count (store), ==, 2);
}

static void
test_durable_root_reopen_appends_fresh_event (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *directory = g_dir_make_tmp ("wyrelog-readiness-XXXXXX",
      &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (directory, "policy.sqlite", NULL);
  WylHandleOpenOptions options = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .policy_store_path = path,
  };

  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_autofree gchar *first_id = NULL;
  gint64 first_time = -1;
  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &first_id, &first_time, NULL, NULL), ==, WYRELOG_E_OK);
  g_clear_object (&handle);

  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (readiness_event_count (wyl_handle_get_policy_store (handle)),
      ==, 1);
  g_autofree gchar *second_id = NULL;
  gint64 second_time = -1;
  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &second_id, &second_time, NULL, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpstr (second_id, !=, first_id);
  g_assert_cmpint (readiness_event_count (wyl_handle_get_policy_store (handle)),
      ==, 2);
  g_assert_cmpint (readiness_intention_count (wyl_handle_get_policy_store
          (handle), "committed"), ==, 2);
  assert_exact_durable_bundle (handle, first_id, first_time, TRUE);
  assert_exact_durable_bundle (handle, second_id, second_time, TRUE);
  g_clear_object (&handle);

  g_assert_cmpint (g_remove (path), ==, 0);
  g_assert_cmpint (g_rmdir (directory), ==, 0);
}

static void
assert_precommit_fault (WylDaemonReadinessAuditFault mutation_fault,
    WylCommittedPublicationFault runner_fault)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle), ==, WYRELOG_E_OK);
  WylEngine *old_read = wyl_handle_get_read_engine (handle);
  WylEngine *old_delta = wyl_handle_get_delta_engine (handle);
  if (mutation_fault != WYL_DAEMON_READINESS_AUDIT_FAULT_NONE)
    wyl_daemon_check_set_policy_audit_fault_once_for_test (mutation_fault);
  if (runner_fault != WYL_COMMITTED_PUBLICATION_FAULT_NONE)
    wyl_handle_set_committed_publication_fault_once_for_test (handle,
        runner_fault);

  g_autofree gchar *id = NULL;
  gint64 created_at_us = -1;
  WylCommittedPublicationStage stage =
      WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED;
  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &id, &created_at_us, &stage, NULL), ==, WYRELOG_E_IO);
  g_assert_cmpint (stage, ==, WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED);
  assert_exact_durable_bundle (handle, id, created_at_us, FALSE);
  g_assert_true (wyl_handle_engine_pair_is_ready (handle));
  g_assert_false (wyl_handle_engine_pair_is_poisoned (handle));
  g_assert_true (wyl_handle_get_read_engine (handle) == old_read);
  g_assert_true (wyl_handle_get_delta_engine (handle) == old_delta);
  assert_publication_resources_released (handle);
}

static void
test_precommit_faults_roll_back (void)
{
  static const WylDaemonReadinessAuditFault mutation_faults[] = {
    WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_INTENTION,
    WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_EVENT,
    WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_COMMITTED,
  };
  for (guint i = 0; i < G_N_ELEMENTS (mutation_faults); i++)
    assert_precommit_fault (mutation_faults[i],
        WYL_COMMITTED_PUBLICATION_FAULT_NONE);
  assert_precommit_fault (WYL_DAEMON_READINESS_AUDIT_FAULT_NONE,
      WYL_COMMITTED_PUBLICATION_FAULT_VALIDATE);
  assert_precommit_fault (WYL_DAEMON_READINESS_AUDIT_FAULT_NONE,
      WYL_COMMITTED_PUBLICATION_FAULT_COMMIT);
}

static void
assert_postcommit_fault (WylCommittedPublicationFault publication_fault,
    WylEngineReplacementFault replacement_fault,
    WylCommittedPublicationStage expected_stage)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle), ==, WYRELOG_E_OK);
  if (publication_fault != WYL_COMMITTED_PUBLICATION_FAULT_NONE)
    wyl_handle_set_committed_publication_fault_once_for_test (handle,
        publication_fault);
  if (replacement_fault != WYL_ENGINE_REPLACEMENT_FAULT_NONE)
    wyl_handle_set_engine_replacement_fault_once_for_test (handle,
        replacement_fault);

  g_autofree gchar *id = NULL;
  gint64 created_at_us = -1;
  WylCommittedPublicationStage stage =
      WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED;
  g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
          &id, &created_at_us, &stage, NULL), ==, WYRELOG_E_IO);
  g_assert_cmpint (stage, ==, expected_stage);
  assert_exact_durable_bundle (handle, id, created_at_us, TRUE);
  g_assert_true (wyl_handle_engine_pair_is_poisoned (handle));
  g_assert_false (wyl_handle_engine_pair_is_ready (handle));
  g_assert_null (wyl_handle_get_read_engine (handle));
  g_assert_null (wyl_handle_get_delta_engine (handle));
  assert_publication_resources_released (handle);
}

static void
test_postcommit_faults_preserve_durable_bundle_and_poison (void)
{
  assert_postcommit_fault (WYL_COMMITTED_PUBLICATION_FAULT_COMMIT_APPLIED_ERROR,
      WYL_ENGINE_REPLACEMENT_FAULT_NONE,
      WYL_COMMITTED_PUBLICATION_COMMIT_AMBIGUOUS);
  assert_postcommit_fault (WYL_COMMITTED_PUBLICATION_FAULT_NONE,
      WYL_ENGINE_REPLACEMENT_FAULT_OPEN_READ,
      WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED);
  assert_postcommit_fault (WYL_COMMITTED_PUBLICATION_FAULT_NONE,
      WYL_ENGINE_REPLACEMENT_FAULT_AUDIT_FACTS,
      WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED);
  assert_postcommit_fault (WYL_COMMITTED_PUBLICATION_FAULT_NONE,
      WYL_ENGINE_REPLACEMENT_FAULT_READBACK,
      WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED);
}

static void
test_exact_verifier_rejects_extra_and_wrong_rows (void)
{
  static const WylDaemonReadinessVerifyFault faults[] = {
    WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_EXTRA,
    WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_WRONG,
    WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_EXTRA,
    WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_WRONG,
    WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_EXTRA,
    WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_WRONG,
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_autoptr (WylHandle) handle = NULL;
    g_assert_cmpint (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle), ==,
        WYRELOG_E_OK);
    wyl_daemon_check_set_policy_audit_verify_fault_once_for_test (faults[i]);

    g_autofree gchar *id = NULL;
    gint64 created_at_us = -1;
    WylCommittedPublicationStage stage =
        WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED;
    gboolean verify_exact = TRUE;
    g_assert_cmpint (wyl_daemon_check_policy_audit_facts_ready_for_test (handle,
            &id, &created_at_us, &stage, &verify_exact), ==, WYRELOG_E_POLICY);
    g_assert_false (verify_exact);
    g_assert_cmpint (stage, ==, WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED);
    assert_exact_durable_bundle (handle, id, created_at_us, TRUE);
    g_assert_true (wyl_handle_engine_pair_is_poisoned (handle));
    g_assert_false (wyl_handle_engine_pair_is_ready (handle));
    g_assert_null (wyl_handle_get_read_engine (handle));
    g_assert_null (wyl_handle_get_delta_engine (handle));
    assert_publication_resources_released (handle);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon/checks/noaudit/success-repeat",
      test_success_repeats_and_public_emit_stays_disabled);
  g_test_add_func ("/daemon/checks/noaudit/durable-reopen",
      test_durable_root_reopen_appends_fresh_event);
  g_test_add_func ("/daemon/checks/noaudit/precommit-faults",
      test_precommit_faults_roll_back);
  g_test_add_func ("/daemon/checks/noaudit/postcommit-faults",
      test_postcommit_faults_preserve_durable_bundle_and_poison);
  g_test_add_func ("/daemon/checks/noaudit/exact-verifier-negative",
      test_exact_verifier_rejects_extra_and_wrong_rows);
  return g_test_run ();
}
