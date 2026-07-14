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
  return g_test_run ();
}
