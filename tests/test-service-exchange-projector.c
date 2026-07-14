/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "wyrelog/audit/conn-private.h"
#include "wyrelog/auth/service-exchange-projector-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  gchar *dir;
  gchar *policy_path;
  gchar *audit_path;
  WylHandle *handle;
} Fixture;

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthorityCommitEvidence *evidence;
  WylServiceExchangeReceipt *receipt;
} Committed;

static wyl_service_exchange_audit_input_t
input_at (const gchar *uuid, const gchar *request, gint64 created)
{
  wyl_service_exchange_audit_input_t input = {
    .request_id = {request, 27},
    .credential_id = {"wlc_000000000000000000000000000", 31},
    .credential_generation = 9,
    .service_principal = {"svc:test", 8},
    .tenant_id = {"tenant-a", 8},
    .session_id = {"01890f47-3c4b-7cc2-98c4-dc0c0c07398f", 36},
    .jti = {"01890f47-3c4b-7cc2-a8c4-dc0c0c073990", 36},
    .created_at_us = created,
  };
  g_assert_cmpint (wyl_id_parse (uuid, &input.intention_id), ==, WYRELOG_E_OK);
  return input;
}

static void
fixture_init (Fixture *f)
{
  memset (f, 0, sizeof *f);
  f->dir = g_dir_make_tmp ("wyl-projector-XXXXXX", NULL);
  g_assert_nonnull (f->dir);
  f->policy_path = g_build_filename (f->dir, "policy.db", NULL);
  f->audit_path = g_build_filename (f->dir, "audit.duckdb", NULL);
  WylHandleOpenOptions options = {
    .policy_store_path = f->policy_path,
    .audit_store_path = f->audit_path,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f->handle), ==,
      WYRELOG_E_OK);
}

static void
fixture_clear (Fixture *f)
{
  g_clear_object (&f->handle);
  g_remove (f->audit_path);
  g_remove (f->policy_path);
  g_rmdir (f->dir);
  g_clear_pointer (&f->audit_path, g_free);
  g_clear_pointer (&f->policy_path, g_free);
  g_clear_pointer (&f->dir, g_free);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static Committed
commit_receipt (WylHandle *handle,
    const wyl_service_exchange_audit_input_t *input,
    WylServiceExchangeIntentionClassification expected)
{
  Committed c = { 0 };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &c.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, c.lease, &c.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (c.txn, store, &c.evidence), ==, WYRELOG_E_OK);
  WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_acquire_write_intent
      (c.txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  WylServiceExchangeIntentionClassification classification =
      WYL_SERVICE_EXCHANGE_INTENTION_NONE;
  g_autoptr (WylServiceExchangeIntentionRecord) record = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (c.txn,
          store, input, &classification, &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (classification, ==, expected);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (c.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (c.txn,
          c.evidence, handle, store, &c.receipt), ==, WYRELOG_E_OK);
  return c;
}

static void
committed_clear (Committed *c)
{
  g_clear_pointer (&c->receipt, wyl_service_exchange_receipt_unref);
  g_clear_pointer (&c->txn,
      wyl_policy_store_service_authority_transaction_free);
  g_clear_pointer (&c->evidence,
      wyl_policy_store_service_authority_commit_evidence_unref);
  if (c->lease != NULL) {
    g_assert_cmpint (wyl_service_auth_write_lease_release (c->lease), ==,
        WYRELOG_E_OK);
    g_clear_pointer (&c->lease, wyl_service_auth_write_lease_free);
  }
}

static void
sink_identity (WylHandle *handle,
    gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM],
    gchar uuid[WYL_SERVICE_EXCHANGE_UUID_BUF])
{
  g_assert_cmpint (wyl_audit_conn_service_exchange_get_sink_identity
      (wyl_handle_get_audit_conn (handle), name, uuid), ==, WYRELOG_E_OK);
}

static void
assert_write_held (WylHandle *handle)
{
  WylServiceAuthAuthoritySnapshot snapshot;
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (handle), &snapshot);
  g_assert_true (snapshot.writer_active);
  g_assert_cmpuint (snapshot.active_readers, ==, 0);
}

static gint64
projection_count (WylHandle *handle)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection
          (wyl_handle_get_audit_conn (handle)),
          "SELECT count(*) FROM service_exchange_receipt_projections;",
          &result), ==, DuckDBSuccess);
  gint64 count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return count;
}

static gint64
projection_distinct_intention_count (WylHandle *handle)
{
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (wyl_audit_conn_get_connection
          (wyl_handle_get_audit_conn (handle)),
          "SELECT count(DISTINCT intention_id) "
          "FROM service_exchange_receipt_projections;", &result), ==,
      DuckDBSuccess);
  gint64 count = duckdb_value_int64 (&result, 0, 0);
  duckdb_destroy_result (&result);
  return count;
}

static guint64 sink_entries (WylHandle * handle);
static void assert_validator_control (WylServiceExchangeProjectionAck * ack,
    WylHandle * handle, WylServiceAuthWriteLease * lease,
    WylServiceExchangeReceipt * receipt, const gchar * name,
    const gchar * uuid);

static void
audit_sql_ok (WylHandle *handle, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (wyl_audit_conn_get_connection
      (wyl_handle_get_audit_conn (handle)), sql, &result);
  if (state != DuckDBSuccess)
    g_test_message ("duckdb: %s", duckdb_result_error (&result));
  duckdb_destroy_result (&result);
  g_assert_cmpint (state, ==, DuckDBSuccess);
}

static void
policy_sql_ok (WylHandle *handle, const gchar *sql)
{
  gchar *message = NULL;
  int rc = sqlite3_exec (wyl_policy_store_get_db
      (wyl_handle_get_policy_store (handle)), sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
assert_durable_mutation_denied (WylHandle *handle,
    WylServiceExchangeProjectionAck *ack, Committed *committed,
    const gchar *name, const gchar *uuid, const gchar *backup_sql,
    const gchar *mutation_sql, const gchar *restore_sql,
    gboolean reaches_atom_a)
{
  assert_validator_control (ack, handle, committed->lease,
      committed->receipt, name, uuid);
  audit_sql_ok (handle, backup_sql);
  audit_sql_ok (handle, mutation_sql);
  guint64 before = sink_entries (handle);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack,
          handle, committed->lease, committed->receipt, name, uuid), !=,
      WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (handle), ==,
      before + (reaches_atom_a ? 1 : 0));
  g_assert_cmpint (projection_count (handle), <=, 1);
  audit_sql_ok (handle, restore_sql);
  assert_validator_control (ack, handle, committed->lease,
      committed->receipt, name, uuid);
}

static guint64
sink_entries (WylHandle *handle)
{
  return wyl_audit_conn_service_exchange_get_entry_count_for_test
      (wyl_handle_get_audit_conn (handle));
}

static void
assert_validator_control (WylServiceExchangeProjectionAck *ack,
    WylHandle *handle, WylServiceAuthWriteLease *lease,
    WylServiceExchangeReceipt *receipt, const gchar *name, const gchar *uuid)
{
  guint64 before = sink_entries (handle);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack,
          handle, lease, receipt, name, uuid), ==, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (handle), ==, before + 1);
}

static void
assert_validator_presink_denied (WylHandle *counter_handle,
    WylServiceExchangeProjectionAck *ack, WylHandle *handle,
    WylServiceAuthWriteLease *lease, WylServiceExchangeReceipt *receipt,
    const gchar *name, const gchar *uuid)
{
  guint64 before = sink_entries (counter_handle);
  gint64 rows_before = projection_count (counter_handle);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack,
          handle, lease, receipt, name, uuid), !=, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (counter_handle), ==, before);
  g_assert_cmpint (projection_count (counter_handle), ==, rows_before);
}

/* Atom B deliberately has no activation path. This fixture models the sole
 * permission a later activation atom may consume: an exact ACK validation. */
static wyrelog_error_t
activation_fixture_attempt (WylServiceExchangeProjectionAck *ack,
    WylHandle *handle, WylServiceAuthWriteLease *lease,
    WylServiceExchangeReceipt *receipt, const gchar *name, const gchar *uuid,
    gboolean *active)
{
  *active = FALSE;
  wyrelog_error_t rc =
      wyl_service_exchange_projection_ack_validate_receipt (ack, handle,
      lease, receipt, name, uuid);
  if (rc == WYRELOG_E_OK)
    *active = TRUE;
  return rc;
}

static void
test_exact_success_replay_and_ack (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed created = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  gboolean active = TRUE;
  g_assert_cmpint (activation_fixture_attempt (NULL, f.handle, created.lease,
          created.receipt, name, uuid, &active), !=, WYRELOG_E_OK);
  g_assert_false (active);
  g_autoptr (WylServiceExchangeProjectionAck) ack = NULL;
  g_assert_cmpuint (sink_entries (f.handle), ==, 0);
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
          created.lease, created.receipt, name, uuid, &ack), ==, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (f.handle), ==, 1);
  g_assert_nonnull (ack);
  assert_write_held (f.handle);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, created.lease, created.receipt, name, uuid), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (activation_fixture_attempt (ack, f.handle, created.lease,
          created.receipt, name, uuid, &active), ==, WYRELOG_E_OK);
  g_assert_true (active);
  g_autoptr (WylServiceExchangeIntentionRecord) copy = NULL;
  g_assert_cmpint (wyl_service_exchange_projection_ack_dup_record (ack,
          &copy), ==, WYRELOG_E_OK);
  g_assert_cmpstr (copy->material.intention_id, ==,
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  copy->tenant_id[0] = 'X';
  g_clear_pointer (&copy, wyl_service_exchange_intention_record_free);
  g_assert_cmpint (wyl_service_exchange_projection_ack_dup_record (ack,
          &copy), ==, WYRELOG_E_OK);
  g_assert_cmpstr (copy->tenant_id, ==, "tenant-a");
  committed_clear (&created);

  Committed replay = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  g_autoptr (WylServiceExchangeProjectionAck) replay_ack = NULL;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
          replay.lease, replay.receipt, name, uuid, &replay_ack), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (replay_ack);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, replay.lease, replay.receipt, name, uuid), ==,
      WYRELOG_E_INVALID);
  assert_write_held (f.handle);
  committed_clear (&replay);
}

static void
test_stale_generation_and_unavailable (void)
{
  {
    g_auto (Fixture) f = { 0 };
    fixture_init (&f);
    gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
    sink_identity (f.handle, name, uuid);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    Committed c = commit_receipt (f.handle, &input,
        WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
    g_autoptr (WylServiceExchangeProjectionAck) exact = NULL;
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &exact), ==, WYRELOG_E_OK);
    assert_validator_control (exact, f.handle, c.lease, c.receipt, name, uuid);
    wyl_handle_policy_store_test_advance_generation (f.handle);
    assert_validator_presink_denied (f.handle, exact, f.handle, c.lease,
        c.receipt, name, uuid);
    guint64 before = sink_entries (f.handle);
    WylServiceExchangeProjectionAck *ack = (gpointer) 1;
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &ack), !=, WYRELOG_E_OK);
    g_assert_null (ack);
    g_assert_cmpuint (sink_entries (f.handle), ==, before);
    assert_write_held (f.handle);
    committed_clear (&c);
  }
  {
    g_auto (Fixture) f = { 0 };
    fixture_init (&f);
    gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
    sink_identity (f.handle, name, uuid);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    Committed c = commit_receipt (f.handle, &input,
        WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
    g_autoptr (WylServiceExchangeProjectionAck) exact = NULL;
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &exact), ==, WYRELOG_E_OK);
    assert_validator_control (exact, f.handle, c.lease, c.receipt, name, uuid);
    g_assert_cmpint (wyl_service_auth_write_lease_mark_unavailable (c.lease,
            f.handle, WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT),
        ==, WYRELOG_E_OK);
    assert_validator_presink_denied (f.handle, exact, f.handle, c.lease,
        c.receipt, name, uuid);
    guint64 before = sink_entries (f.handle);
    WylServiceExchangeProjectionAck *ack = (gpointer) 1;
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &ack), ==, WYRELOG_E_BUSY);
    g_assert_null (ack);
    g_assert_cmpuint (sink_entries (f.handle), ==, before);
    assert_write_held (f.handle);
    committed_clear (&c);
  }
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylServiceAuthAuthority *authority;
  gboolean closing;
  wyrelog_error_t rc;
} CloseBarrier;

static void
close_checkpoint (gpointer data)
{
  CloseBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  barrier->closing = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
}

static gpointer
close_authority (gpointer data)
{
  CloseBarrier *barrier = data;
  barrier->rc = wyl_service_auth_authority_close (barrier->authority);
  return NULL;
}

static void
test_closing_denies_before_sink (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_autoptr (WylServiceExchangeProjectionAck) exact = NULL;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &exact), ==, WYRELOG_E_OK);
  assert_validator_control (exact, f.handle, c.lease, c.receipt, name, uuid);
  CloseBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  barrier.authority = wyl_handle_get_service_auth_authority (f.handle);
  wyl_service_auth_authority_set_close_checkpoint (barrier.authority,
      close_checkpoint, &barrier);
  g_autoptr (GThread) closer = g_thread_new ("projector-close",
      close_authority, &barrier);
  g_mutex_lock (&barrier.mutex);
  while (!barrier.closing)
    g_cond_wait (&barrier.changed, &barrier.mutex);
  g_mutex_unlock (&barrier.mutex);
  assert_validator_presink_denied (f.handle, exact, f.handle, c.lease,
      c.receipt, name, uuid);
  guint64 before = sink_entries (f.handle);
  WylServiceExchangeProjectionAck *ack = (gpointer) 1;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), ==, WYRELOG_E_BUSY);
  g_assert_null (ack);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  assert_write_held (f.handle);
  g_clear_pointer (&c.txn, wyl_policy_store_service_authority_transaction_free);
  g_clear_pointer (&c.evidence,
      wyl_policy_store_service_authority_commit_evidence_unref);
  g_assert_cmpint (wyl_service_auth_write_lease_release (c.lease), ==,
      WYRELOG_E_OK);
  g_thread_join (g_steal_pointer (&closer));
  g_assert_cmpint (barrier.rc, ==, WYRELOG_E_OK);
  assert_validator_presink_denied (f.handle, exact, f.handle, c.lease,
      c.receipt, name, uuid);
  g_clear_pointer (&c.receipt, wyl_service_exchange_receipt_unref);
  g_clear_pointer (&c.lease, wyl_service_auth_write_lease_free);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
}

static void
test_guards_before_sink_and_write_lifetime (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  WylServiceExchangeProjectionAck *ack = (gpointer) 1;
#define DENY(expr) G_STMT_START { \
  guint64 denied_before = sink_entries (f.handle); \
  ack = (gpointer) 1; \
  g_assert_cmpint ((expr), !=, WYRELOG_E_OK); \
  g_assert_null (ack); \
  g_assert_cmpuint (sink_entries (f.handle), ==, denied_before); \
  assert_write_held (f.handle); \
} G_STMT_END
  DENY (wyl_service_exchange_project_committed (f.handle, c.lease, c.receipt,
          "decoy", uuid, &ack));
  DENY (wyl_service_exchange_project_committed (f.handle, c.lease, c.receipt,
          name, "01890f47-3c4b-7cc2-b8c4-dc0c0c073992", &ack));
  DENY (wyl_service_exchange_project_committed (f.handle, c.lease, NULL,
          name, uuid, &ack));
  DENY (wyl_service_exchange_project_committed (NULL, c.lease, c.receipt,
          name, uuid, &ack));
  DENY (wyl_service_exchange_project_committed (f.handle, NULL, c.receipt,
          name, uuid, &ack));
  guint64 denied_before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (sink_entries (f.handle), ==, denied_before);
  g_assert_cmpint (projection_count (f.handle), ==, 0);
  g_clear_pointer (&c.txn, wyl_policy_store_service_authority_transaction_free);
  g_clear_pointer (&c.evidence,
      wyl_policy_store_service_authority_commit_evidence_unref);
  g_assert_cmpint (wyl_service_auth_write_lease_release (c.lease), ==,
      WYRELOG_E_OK);
  ack = (gpointer) 1;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), !=, WYRELOG_E_OK);
  g_assert_null (ack);
  g_assert_cmpuint (sink_entries (f.handle), ==, denied_before);
  g_clear_pointer (&c.receipt, wyl_service_exchange_receipt_unref);
  g_clear_pointer (&c.lease, wyl_service_auth_write_lease_free);
#undef DENY
}

typedef struct
{
  WylHandle *handle;
  WylServiceAuthWriteLease *lease;
  WylServiceExchangeReceipt *receipt;
  const gchar *name;
  const gchar *uuid;
  wyrelog_error_t rc;
  WylServiceExchangeProjectionAck *ack;
  gboolean validate;
} ThreadAttempt;

static gpointer
wrong_thread_project (gpointer data)
{
  ThreadAttempt *a = data;
  if (a->validate) {
    a->rc = wyl_service_exchange_projection_ack_validate_receipt (a->ack,
        a->handle, a->lease, a->receipt, a->name, a->uuid);
  } else {
    WylServiceExchangeProjectionAck *ack = (gpointer) 1;
    a->rc = wyl_service_exchange_project_committed (a->handle, a->lease,
        a->receipt, a->name, a->uuid, &ack);
    g_assert_null (ack);
  }
  return NULL;
}

static void
test_wrong_thread_handle_and_active_transaction (void)
{
  g_auto (Fixture) f = { 0 }, alien = { 0 };
  fixture_init (&f);
  fixture_init (&alien);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  WylServiceExchangeProjectionAck *ack = (gpointer) 1;
  guint64 before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_project_committed (alien.handle,
          c.lease, c.receipt, name, uuid, &ack), !=, WYRELOG_E_OK);
  g_assert_null (ack);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  ThreadAttempt attempt = { f.handle, c.lease, c.receipt, name, uuid, 0,
    NULL, FALSE
  };
  g_autoptr (GThread) thread = g_thread_new ("project-wrong-thread",
      wrong_thread_project, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, !=, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  assert_write_held (f.handle);

  wyl_policy_store_t *store = wyl_handle_get_policy_store (f.handle);
  WylServiceAuthorityTransaction *active = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, f.handle, c.lease, &active), ==, WYRELOG_E_OK);
  ack = (gpointer) 1;
  before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), ==, WYRELOG_E_BUSY);
  g_assert_null (ack);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (active), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (active);
  committed_clear (&c);
}

static void
test_validator_argument_lease_store_matrix (void)
{
  g_auto (Fixture) f = { 0 }, alien = { 0 };
  fixture_init (&f);
  fixture_init (&alien);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_autoptr (WylServiceExchangeProjectionAck) ack = NULL;
  guint64 before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), ==, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (f.handle), ==, before + 1);

#define CONTROL_DENY(expr) G_STMT_START { \
  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid); \
  guint64 denied_before = sink_entries (f.handle); \
  gint64 rows_before = projection_count (f.handle); \
  g_assert_cmpint ((expr), !=, WYRELOG_E_OK); \
  g_assert_cmpuint (sink_entries (f.handle), ==, denied_before); \
  g_assert_cmpint (projection_count (f.handle), ==, rows_before); \
} G_STMT_END
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (NULL,
          f.handle, c.lease, c.receipt, name, uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          NULL, c.lease, c.receipt, name, uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, NULL, c.receipt, name, uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, c.lease, NULL, name, uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, c.lease, c.receipt, NULL, uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, c.lease, c.receipt, name, NULL));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, c.lease, c.receipt, "decoy", uuid));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          f.handle, c.lease, c.receipt, name,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073992"));
  CONTROL_DENY (wyl_service_exchange_projection_ack_validate_receipt (ack,
          alien.handle, c.lease, c.receipt, name, uuid));

  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid);
  ThreadAttempt thread_attempt = { f.handle, c.lease, c.receipt, name, uuid,
    WYRELOG_E_OK, ack, TRUE
  };
  before = sink_entries (f.handle);
  g_autoptr (GThread) thread = g_thread_new ("validate-wrong-thread",
      wrong_thread_project, &thread_attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (thread_attempt.rc, !=, WYRELOG_E_OK);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);

  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid);
  wyl_policy_store_t *original =
      wyl_service_auth_write_lease_test_swap_pinned_store (c.lease,
      wyl_handle_get_policy_store (alien.handle));
  g_assert_true (original == wyl_handle_get_policy_store (f.handle));
  assert_validator_presink_denied (f.handle, ack, f.handle, c.lease,
      c.receipt, name, uuid);
  g_assert_true (wyl_service_auth_write_lease_test_swap_pinned_store (c.lease,
          original) == wyl_handle_get_policy_store (alien.handle));

  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid);
  WylServiceAuthorityTransaction *active = NULL;
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (wyl_handle_get_policy_store (f.handle), f.handle, c.lease, &active),
      ==, WYRELOG_E_OK);
  assert_validator_presink_denied (f.handle, ack, f.handle, c.lease,
      c.receipt, name, uuid);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (active), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (active);

  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid);
  g_clear_pointer (&c.txn, wyl_policy_store_service_authority_transaction_free);
  g_clear_pointer (&c.evidence,
      wyl_policy_store_service_authority_commit_evidence_unref);
  g_assert_cmpint (wyl_service_auth_write_lease_release (c.lease), ==,
      WYRELOG_E_OK);
  assert_validator_presink_denied (f.handle, ack, f.handle, c.lease,
      c.receipt, name, uuid);
  g_clear_pointer (&c.receipt, wyl_service_exchange_receipt_unref);
  g_clear_pointer (&c.lease, wyl_service_auth_write_lease_free);
#undef CONTROL_DENY
}

static void
test_validator_durable_sink_mutation_matrix (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_autoptr (WylServiceExchangeProjectionAck) ack = NULL;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), ==, WYRELOG_E_OK);

  static const gchar *side_mutations[] = {
    "UPDATE service_exchange_receipt_projections SET intention_id="
        "'01890f47-3c4b-7cc2-b8c4-dc0c0c073992';",
    "UPDATE service_exchange_receipt_projections SET payload_digest="
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';",
    "UPDATE service_exchange_receipt_projections SET created_at_us=11;",
    "UPDATE service_exchange_receipt_projections SET request_id="
        "'111111111111111111111111111';",
    "UPDATE service_exchange_receipt_projections SET credential_id="
        "'wlc_111111111111111111111111111';",
    "UPDATE service_exchange_receipt_projections SET credential_generation="
        "CAST('abcdefgh' AS BLOB);",
    "UPDATE service_exchange_receipt_projections SET service_principal="
        "'svc:decoy';",
    "UPDATE service_exchange_receipt_projections SET tenant_id='tenant-b';",
    "UPDATE service_exchange_receipt_projections SET session_fingerprint="
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';",
    "UPDATE service_exchange_receipt_projections SET jti_fingerprint="
        "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';",
    "UPDATE service_exchange_receipt_projections SET canonical_payload="
        "CAST('x' AS BLOB);",
    "DELETE FROM service_exchange_receipt_projections;",
  };
  static const gchar *side_backup =
      "CREATE TEMP TABLE projector_side_backup AS SELECT * FROM "
      "service_exchange_receipt_projections;";
  static const gchar *side_restore =
      "DELETE FROM service_exchange_receipt_projections;"
      "INSERT INTO service_exchange_receipt_projections SELECT * FROM "
      "projector_side_backup;DROP TABLE projector_side_backup;";
  for (guint i = 0; i < G_N_ELEMENTS (side_mutations); i++)
    assert_durable_mutation_denied (f.handle, ack, &c, name, uuid,
        side_backup, side_mutations[i], side_restore, TRUE);

  static const gchar *metadata_mutations[] = {
    "UPDATE audit_sink_metadata SET sink_uuid="
        "'01890f47-3c4b-7cc2-b8c4-dc0c0c073992';",
    "UPDATE audit_sink_metadata SET logical_sink_name='decoy-sink';",
  };
  for (guint i = 0; i < G_N_ELEMENTS (metadata_mutations); i++)
    assert_durable_mutation_denied (f.handle, ack, &c, name, uuid,
        "CREATE TEMP TABLE projector_metadata_backup AS SELECT * FROM "
        "audit_sink_metadata;", metadata_mutations[i],
        "DELETE FROM audit_sink_metadata;INSERT INTO audit_sink_metadata "
        "SELECT * FROM projector_metadata_backup;"
        "DROP TABLE projector_metadata_backup;", FALSE);

  static const gchar *anchor_backup =
      "CREATE TEMP TABLE projector_anchor_backup AS SELECT * FROM "
      "audit_events;";
  static const gchar *anchor_restore =
      "DELETE FROM audit_events;INSERT INTO audit_events SELECT * FROM "
      "projector_anchor_backup;DROP TABLE projector_anchor_backup;";
  static const gchar *anchor_mutations[] = {
    "UPDATE audit_events SET subject_id='svc:decoy' WHERE stream_name='"
        WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';",
    "UPDATE audit_events SET record_hash="
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"
        "checkpoint_root="
        "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "
        "WHERE stream_name='" WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';",
    "DELETE FROM audit_events WHERE stream_name='"
        WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';",
  };
  for (guint i = 0; i < G_N_ELEMENTS (anchor_mutations); i++)
    assert_durable_mutation_denied (f.handle, ack, &c, name, uuid,
        anchor_backup, anchor_mutations[i], anchor_restore, TRUE);

  static const gchar *checkpoint_backup =
      "CREATE TEMP TABLE projector_checkpoint_backup AS SELECT * FROM "
      "audit_checkpoints;";
  static const gchar *checkpoint_restore =
      "DELETE FROM audit_checkpoints;INSERT INTO audit_checkpoints SELECT * "
      "FROM projector_checkpoint_backup;"
      "DROP TABLE projector_checkpoint_backup;";
  static const gchar *checkpoint_mutations[] = {
    "UPDATE audit_checkpoints SET root_hash="
        "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' "
        "WHERE " "stream_name='" WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';",
    "DELETE FROM audit_checkpoints WHERE stream_name='"
        WYL_AUDIT_SERVICE_EXCHANGE_STREAM "';",
  };
  for (guint i = 0; i < G_N_ELEMENTS (checkpoint_mutations); i++)
    assert_durable_mutation_denied (f.handle, ack, &c, name, uuid,
        checkpoint_backup, checkpoint_mutations[i], checkpoint_restore, TRUE);

  assert_validator_control (ack, f.handle, c.lease, c.receipt, name, uuid);
  committed_clear (&c);
}

static void
test_validator_distinct_receipt_crossover (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t a = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed first = commit_receipt (f.handle, &a,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_autoptr (WylServiceExchangeProjectionAck) ack_a = NULL;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
          first.lease, first.receipt, name, uuid, &ack_a), ==, WYRELOG_E_OK);
  assert_validator_control (ack_a, f.handle, first.lease, first.receipt, name,
      uuid);
  committed_clear (&first);

  wyl_service_exchange_audit_input_t b = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
      "222222222222222222222222222", 12);
  b.credential_id = (wyl_service_exchange_text_t) {
  "wlc_222222222222222222222222222", 31};
  b.credential_generation = 11;
  b.service_principal = (wyl_service_exchange_text_t) {
  "svc:other", 9};
  b.tenant_id = (wyl_service_exchange_text_t) {
  "tenant-b", 8};
  b.session_id = (wyl_service_exchange_text_t) {
  "01890f47-3c4b-7cc2-98c4-dc0c0c073994", 36};
  b.jti = (wyl_service_exchange_text_t) {
  "01890f47-3c4b-7cc2-a8c4-dc0c0c073995", 36};
  Committed seed = commit_receipt (f.handle, &b,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&seed);
  Committed second = commit_receipt (f.handle, &b,
      WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  guint64 before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_projection_ack_validate_receipt (ack_a,
          f.handle, second.lease, second.receipt, name, uuid), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  g_autoptr (WylServiceExchangeProjectionAck) ack_b = NULL;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
          second.lease, second.receipt, name, uuid, &ack_b), ==, WYRELOG_E_OK);
  assert_validator_control (ack_b, f.handle, second.lease, second.receipt,
      name, uuid);
  committed_clear (&second);
}

static void
test_faults_retry_and_exact_ack (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  wyl_audit_conn_service_exchange_fail_once
      (wyl_handle_get_audit_conn (f.handle),
      WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_PREFLIGHT);
  WylServiceExchangeProjectionAck *ack = (gpointer) 1;
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), !=, WYRELOG_E_OK);
  g_assert_null (ack);
  assert_write_held (f.handle);
  g_assert_cmpint (wyl_service_exchange_project_committed (f.handle, c.lease,
          c.receipt, name, uuid, &ack), ==, WYRELOG_E_OK);
  g_assert_nonnull (ack);
  wyl_service_exchange_projection_ack_unref (ack);

  for (guint fail_at = 1; fail_at <= 4; fail_at++) {
    wyl_service_exchange_projector_fail_allocation_for_test (fail_at);
    ack = (gpointer) 1;
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &ack), ==, WYRELOG_E_NOMEM);
    g_assert_null (ack);
    assert_write_held (f.handle);
    wyl_service_exchange_projector_fail_allocation_for_test (0);
    g_assert_cmpint (wyl_service_exchange_project_committed (f.handle,
            c.lease, c.receipt, name, uuid, &ack), ==, WYRELOG_E_OK);
    g_assert_nonnull (ack);
    wyl_service_exchange_projection_ack_unref (ack);
  }
  committed_clear (&c);
}

static void
test_recovery_idempotent_and_faults (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);

  WylServiceExchangeRecoverySummary summary = { 99, 99 };
  wyl_service_exchange_recovery_fail_allocation_for_test (1);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_NOMEM);
  g_assert_cmpuint (summary.enumerated, ==, 0);
  g_assert_cmpuint (summary.projected, ==, 0);
  g_assert_cmpint (projection_count (f.handle), ==, 0);

  g_autoptr (GCancellable) cancelled = g_cancellable_new ();
  g_cancellable_cancel (cancelled);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, cancelled, &summary), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (projection_count (f.handle), ==, 0);

  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpuint (summary.enumerated, ==, 1);
  g_assert_cmpuint (summary.projected, ==, 1);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpuint (summary.enumerated, ==, 1);
  g_assert_cmpuint (summary.projected, ==, 1);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  guint64 before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle,
          "decoy", uuid, NULL, &summary), ==, WYRELOG_E_INVALID);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          "01890f47-3c4b-7cc2-b8c4-dc0c0c073999", NULL, &summary), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpuint (sink_entries (f.handle), ==, before);
}

typedef struct
{
  WylHandle *handle;
  const gchar *name;
  const gchar *uuid;
  WylServiceExchangeRecoverySummary summary;
  wyrelog_error_t rc;
} RecoveryAttempt;

static gpointer
run_recovery (gpointer data)
{
  RecoveryAttempt *attempt = data;
  attempt->rc = wyl_service_exchange_recover_committed (attempt->handle,
      attempt->name, attempt->uuid, NULL, &attempt->summary);
  return NULL;
}

static void
test_recovery_projects_every_enumerated_record (void)
{
  static const gchar *intention_ids[] = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073992",
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073994",
  };
  static const gchar *request_ids[] = {
    "000000000000000000000000000",
    "000000000000000000000000001",
    "000000000000000000000000002",
    "000000000000000000000000003",
  };
  const guint original_count = G_N_ELEMENTS (intention_ids);
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);

  for (guint i = 0; i < original_count; i++) {
    wyl_service_exchange_audit_input_t input = input_at (intention_ids[i],
        request_ids[i], 10 + i);
    Committed committed = commit_receipt (f.handle, &input,
        WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
    committed_clear (&committed);
  }

  RecoveryAttempt a = { f.handle, name, uuid, {0}, 0 };
  RecoveryAttempt b = { f.handle, name, uuid, {0}, 0 };
  g_autoptr (GThread) ta = g_thread_new ("recovery-all-a", run_recovery, &a);
  g_autoptr (GThread) tb = g_thread_new ("recovery-all-b", run_recovery, &b);
  g_thread_join (g_steal_pointer (&ta));
  g_thread_join (g_steal_pointer (&tb));

  g_assert_cmpint (a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b.rc, ==, WYRELOG_E_OK);
  g_assert_cmpuint (a.summary.enumerated, ==, original_count);
  g_assert_cmpuint (a.summary.projected, ==, original_count);
  g_assert_cmpuint (b.summary.enumerated, ==, original_count);
  g_assert_cmpuint (b.summary.projected, ==, original_count);
  g_assert_cmpint (projection_count (f.handle), ==, original_count);
  g_assert_cmpint (projection_distinct_intention_count (f.handle), ==,
      original_count);
}

static void
test_recovery_response_loss_reopen_and_race (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);

  wyl_audit_conn_service_exchange_fail_once
      (wyl_handle_get_audit_conn (f.handle),
      WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_RESPONSE_LOST);
  WylServiceExchangeRecoverySummary summary = { 0 };
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_IO);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  RecoveryAttempt a = { f.handle, name, uuid, {0}, 0 };
  RecoveryAttempt b = { f.handle, name, uuid, {0}, 0 };
  g_autoptr (GThread) ta = g_thread_new ("recovery-a", run_recovery, &a);
  g_autoptr (GThread) tb = g_thread_new ("recovery-b", run_recovery, &b);
  g_thread_join (g_steal_pointer (&ta));
  g_thread_join (g_steal_pointer (&tb));
  g_assert_cmpint (a.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (b.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  g_clear_object (&f.handle);
  WylHandleOpenOptions options = {
    .policy_store_path = f.policy_path,.audit_store_path = f.audit_path,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f.handle), ==,
      WYRELOG_E_OK);
  gchar reopened_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM];
  gchar reopened_uuid[37];
  sink_identity (f.handle, reopened_name, reopened_uuid);
  g_assert_cmpstr (reopened_uuid, ==, uuid);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle,
          reopened_name, reopened_uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);

  g_autofree gchar *relocated = g_build_filename (f.dir,
      "relocated-audit.duckdb", NULL);
  g_clear_object (&f.handle);
  options.audit_store_path = relocated;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f.handle), ==,
      WYRELOG_E_OK);
  gchar relocated_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM];
  gchar relocated_uuid[37];
  sink_identity (f.handle, relocated_name, relocated_uuid);
  g_assert_cmpstr (relocated_uuid, !=, reopened_uuid);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle,
          relocated_name, reopened_uuid, NULL, &summary), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (projection_count (f.handle), ==, 0);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle,
          relocated_name, relocated_uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
  g_clear_object (&f.handle);
  g_remove (relocated);
  options.audit_store_path = f.audit_path;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f.handle), ==,
      WYRELOG_E_OK);
}

static void
advance_generation_at_gap (gpointer data)
{
  wyl_handle_policy_store_test_advance_generation (data);
}

static void
shutdown_at_gap (gpointer data)
{
  g_assert_cmpint (wyl_handle_shutdown_ordered (data), ==, WYRELOG_E_OK);
}

static void
mark_checkpoint_called (gpointer data)
{
  *(gboolean *) data = TRUE;
}

static void
test_recovery_gap_stale_and_artifact_corruption (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);
  WylServiceExchangeRecoverySummary summary = { 0 };
  wyl_service_exchange_recovery_set_gap_checkpoint_for_test
      (advance_generation_at_gap, f.handle);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (projection_count (f.handle), ==, 0);

  /* A new handle represents a new current generation and can recover. */
  g_clear_object (&f.handle);
  WylHandleOpenOptions options = {
    .policy_store_path = f.policy_path,.audit_store_path = f.audit_path,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &f.handle), ==,
      WYRELOG_E_OK);
  sink_identity (f.handle, name, uuid);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_OK);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
  audit_sql_ok (f.handle,
      "UPDATE service_exchange_receipt_projections SET tenant_id='corrupt';");
  guint64 before = sink_entries (f.handle);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (sink_entries (f.handle), ==, before + 1);
  g_assert_cmpint (projection_count (f.handle), ==, 1);
}

static void
test_recovery_gap_closing_presink (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);
  gboolean sink_entered = FALSE;
  wyl_audit_conn_service_exchange_set_entry_checkpoint_for_test
      (wyl_handle_get_audit_conn (f.handle), mark_checkpoint_called,
      &sink_entered);
  wyl_service_exchange_recovery_set_gap_checkpoint_for_test (shutdown_at_gap,
      f.handle);
  WylServiceExchangeRecoverySummary summary = { 0 };
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_BUSY);
  g_assert_false (sink_entered);
  g_assert_cmpuint (summary.enumerated, ==, 0);
  g_assert_cmpuint (summary.projected, ==, 0);
}

static void
cancel_at_gap (gpointer data)
{
  g_cancellable_cancel (data);
}

static void
test_recovery_presink_and_fault_matrix (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);
  WylServiceExchangeRecoverySummary summary = { 0 };

  for (gint stage = WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_PREPARE;
      stage <= WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_ALLOCATION;
      stage++) {
    wyl_service_exchange_recovery_fail_enumerate_for_test (stage);
    g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
            uuid, NULL, &summary), ==,
        stage == WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_ALLOCATION
        ? WYRELOG_E_NOMEM : WYRELOG_E_IO);
    g_assert_cmpuint (sink_entries (f.handle), ==, 0);
  }

  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  wyl_service_exchange_recovery_set_gap_checkpoint_for_test (cancel_at_gap,
      cancellable);
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, cancellable, &summary), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (sink_entries (f.handle), ==, 0);

  const WylAuditServiceExchangeFailStage faults[] = {
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_BEGIN,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_PREFLIGHT,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_SIDECAR,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_ANCHOR,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_AFTER_IN_TXN_READBACK,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_COMMIT_QUERY,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_CHECKPOINT,
    WYL_AUDIT_SERVICE_EXCHANGE_FAIL_POST_COMMIT_READBACK,
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_auto (Fixture) fault_fixture = { 0 };
    fixture_init (&fault_fixture);
    gchar fault_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM];
    gchar fault_uuid[37];
    sink_identity (fault_fixture.handle, fault_name, fault_uuid);
    Committed fault_committed = commit_receipt (fault_fixture.handle, &input,
        WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
    committed_clear (&fault_committed);
    wyl_audit_conn_service_exchange_fail_once
        (wyl_handle_get_audit_conn (fault_fixture.handle), faults[i]);
    g_assert_cmpint (wyl_service_exchange_recover_committed
        (fault_fixture.handle, fault_name, fault_uuid, NULL, &summary), !=,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_exchange_recover_committed
        (fault_fixture.handle, fault_name, fault_uuid, NULL, &summary), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (projection_count (fault_fixture.handle), ==, 1);
  }
}

static void
test_recovery_malformed_local_presink (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);
  policy_sql_ok (f.handle,
      "DROP TRIGGER trg_service_exchange_audit_no_update;"
      "PRAGMA ignore_check_constraints=ON;"
      "UPDATE service_exchange_audit_intentions SET outcome='deny';"
      "PRAGMA ignore_check_constraints=OFF;"
      "CREATE TRIGGER trg_service_exchange_audit_no_update BEFORE UPDATE ON"
      " service_exchange_audit_intentions BEGIN SELECT RAISE(ABORT,"
      " 'service exchange audit intentions are append-only'); END;");
  WylServiceExchangeRecoverySummary summary = { 0 };
  g_assert_cmpint (wyl_service_exchange_recover_committed (f.handle, name,
          uuid, NULL, &summary), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (sink_entries (f.handle), ==, 0);
  g_assert_cmpint (projection_count (f.handle), ==, 0);
}

static void
test_recovery_requires_persistent_sink (void)
{
  g_autoptr (WylHandle) handle = NULL;
  WylHandleOpenOptions options = { 0 };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);
  const gchar *name = WYL_AUDIT_SERVICE_EXCHANGE_STREAM;
  const gchar *uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c073999";
  WylServiceExchangeRecoverySummary summary = { 0 };
  g_assert_cmpint (wyl_service_exchange_recover_committed (handle, name, uuid,
          NULL, &summary), ==, WYRELOG_E_POLICY);
}

typedef struct
{
  GMutex mutex;
  GCond changed;
  WylHandle *handle;
  gboolean at_entry;
  gboolean shutdown_waiting;
  gboolean release_entry;
  gboolean entry_invariants;
  wyrelog_error_t shutdown_rc;
} RecoveryPinBarrier;

static void
shutdown_wait_checkpoint (gpointer data)
{
  RecoveryPinBarrier *barrier = data;
  g_mutex_lock (&barrier->mutex);
  barrier->shutdown_waiting = TRUE;
  g_cond_broadcast (&barrier->changed);
  g_mutex_unlock (&barrier->mutex);
}

static gpointer
shutdown_handle (gpointer data)
{
  RecoveryPinBarrier *barrier = data;
  barrier->shutdown_rc = wyl_handle_shutdown_ordered (barrier->handle);
  return NULL;
}

static void
recovery_entry_checkpoint (gpointer data)
{
  RecoveryPinBarrier *barrier = data;
  WylServiceAuthAuthoritySnapshot authority = { 0 };
  wyl_service_auth_authority_snapshot
      (wyl_handle_get_service_auth_authority (barrier->handle), &authority);
  guint total = 0, owner = 0;
  wyl_handle_policy_store_pin_snapshot_for_test (barrier->handle, &total,
      &owner);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (barrier->handle);
  barrier->entry_invariants = !authority.writer_active
      && authority.active_readers == 0
      && !wyl_policy_store_service_authority_transaction_is_active (store)
      && total == 1 && owner == 1;
  g_mutex_lock (&barrier->mutex);
  barrier->at_entry = TRUE;
  g_cond_broadcast (&barrier->changed);
  while (!barrier->release_entry)
    g_cond_wait (&barrier->changed, &barrier->mutex);
  g_mutex_unlock (&barrier->mutex);
}

static void
test_recovery_pin_held_through_atom_a (void)
{
  g_auto (Fixture) f = { 0 };
  fixture_init (&f);
  gchar name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM], uuid[37];
  sink_identity (f.handle, name, uuid);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Committed c = commit_receipt (f.handle, &input,
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  committed_clear (&c);

  RecoveryPinBarrier barrier = { 0 };
  g_mutex_init (&barrier.mutex);
  g_cond_init (&barrier.changed);
  barrier.handle = f.handle;
  wyl_audit_conn_service_exchange_set_entry_checkpoint_for_test
      (wyl_handle_get_audit_conn (f.handle), recovery_entry_checkpoint,
      &barrier);
  wyl_handle_policy_store_set_shutdown_wait_checkpoint_for_test (f.handle,
      shutdown_wait_checkpoint, &barrier);
  RecoveryAttempt recovery = { f.handle, name, uuid, {0}, 0 };
  g_autoptr (GThread) worker = g_thread_new ("recovery-pin", run_recovery,
      &recovery);
  g_mutex_lock (&barrier.mutex);
  while (!barrier.at_entry)
    g_cond_wait (&barrier.changed, &barrier.mutex);
  g_mutex_unlock (&barrier.mutex);
  g_assert_true (barrier.entry_invariants);

  g_autoptr (GThread) closer = g_thread_new ("recovery-close",
      shutdown_handle, &barrier);
  g_mutex_lock (&barrier.mutex);
  while (!barrier.shutdown_waiting)
    g_cond_wait (&barrier.changed, &barrier.mutex);
  barrier.release_entry = TRUE;
  g_cond_broadcast (&barrier.changed);
  g_mutex_unlock (&barrier.mutex);
  g_thread_join (g_steal_pointer (&worker));
  g_thread_join (g_steal_pointer (&closer));
  g_assert_cmpint (recovery.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (barrier.shutdown_rc, ==, WYRELOG_E_OK);
  g_cond_clear (&barrier.changed);
  g_mutex_clear (&barrier.mutex);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange/projector/exact-success-replay",
      test_exact_success_replay_and_ack);
  g_test_add_func ("/service-exchange/projector/guards-write-lifetime",
      test_guards_before_sink_and_write_lifetime);
  g_test_add_func ("/service-exchange/projector/identity-thread-active-txn",
      test_wrong_thread_handle_and_active_transaction);
  g_test_add_func ("/service-exchange/projector/validator-argument-lease-store",
      test_validator_argument_lease_store_matrix);
  g_test_add_func ("/service-exchange/projector/validator-durable-mutations",
      test_validator_durable_sink_mutation_matrix);
  g_test_add_func ("/service-exchange/projector/validator-receipt-crossover",
      test_validator_distinct_receipt_crossover);
  g_test_add_func ("/service-exchange/projector/faults-retry",
      test_faults_retry_and_exact_ack);
  g_test_add_func ("/service-exchange/projector/stale-unavailable",
      test_stale_generation_and_unavailable);
  g_test_add_func ("/service-exchange/projector/closing",
      test_closing_denies_before_sink);
  g_test_add_func ("/service-exchange/recovery/idempotent-faults",
      test_recovery_idempotent_and_faults);
  g_test_add_func ("/service-exchange/recovery/all-enumerated-records",
      test_recovery_projects_every_enumerated_record);
  g_test_add_func ("/service-exchange/recovery/response-loss-reopen-race",
      test_recovery_response_loss_reopen_and_race);
  g_test_add_func ("/service-exchange/recovery/stale-artifact",
      test_recovery_gap_stale_and_artifact_corruption);
  g_test_add_func ("/service-exchange/recovery/gap-closing",
      test_recovery_gap_closing_presink);
  g_test_add_func ("/service-exchange/recovery/presink-faults",
      test_recovery_presink_and_fault_matrix);
  g_test_add_func ("/service-exchange/recovery/malformed-local",
      test_recovery_malformed_local_presink);
  g_test_add_func ("/service-exchange/recovery/persistent-sink",
      test_recovery_requires_persistent_sink);
  g_test_add_func ("/service-exchange/recovery/pin-through-atom-a",
      test_recovery_pin_held_through_atom_a);
  return g_test_run ();
}
