/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthorityCommitEvidence *evidence;
} Txn;

static WylHandle *
open_handle (const gchar *path)
{
  WylHandleOpenOptions options = {.policy_store_path = path };
  WylHandle *handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);
  return handle;
}

static Txn
begin_txn (WylHandle *handle, gboolean intent)
{
  Txn t = { 0 };
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_prepare_commit_evidence
      (t.txn, store, &t.evidence), ==, WYRELOG_E_OK);
  if (intent) {
    WylServiceAuthorityWriteIntentOutcome outcome = { 0 };
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_acquire_write_intent
        (t.txn, store, NULL, &outcome), ==, WYRELOG_E_OK);
  }
  return t;
}

static Txn
begin_read_txn_without_evidence (WylHandle *handle)
{
  Txn t = { 0 };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL,
          &t.lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_get_policy_store (t.lease,
          handle, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_begin
      (store, handle, t.lease, &t.txn), ==, WYRELOG_E_OK);
  return t;
}

static void
finish_txn (Txn *t, gboolean commit)
{
  g_assert_cmpint (commit ?
      wyl_policy_store_service_authority_transaction_commit (t->txn) :
      wyl_policy_store_service_authority_transaction_rollback (t->txn), ==,
      WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (t->txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t->lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t->lease);
  memset (t, 0, sizeof *t);
}

static void
sql_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static gint64
sql_scalar (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  return value;
}

static void
restore_exchange_triggers (sqlite3 *db)
{
  sql_ok (db,
      "CREATE TRIGGER trg_service_exchange_audit_no_update BEFORE UPDATE ON"
      " service_exchange_audit_intentions BEGIN SELECT RAISE(ABORT,"
      " 'service exchange audit intentions are append-only'); END;"
      "CREATE TRIGGER trg_service_exchange_audit_no_delete BEFORE DELETE ON"
      " service_exchange_audit_intentions BEGIN SELECT RAISE(ABORT,"
      " 'service exchange audit intentions are append-only'); END;");
}

static void
remove_exchange_triggers (sqlite3 *db)
{
  sql_ok (db,
      "DROP TRIGGER trg_service_exchange_audit_no_update;"
      "DROP TRIGGER trg_service_exchange_audit_no_delete;"
      "PRAGMA ignore_check_constraints=ON;");
}

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
test_commit_reopen_replay (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-exchange-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  gchar digest[65];
  {
    g_autoptr (WylHandle) handle = open_handle (path);
    Txn t = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (t.txn, wyl_handle_get_policy_store (handle), &input, &kind, &row), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
    g_strlcpy (digest, row->material.payload_digest, sizeof digest);
    finish_txn (&t, TRUE);
    g_assert_cmpstr (row->tenant_id, ==, "tenant-a");
  }
  {
    g_autoptr (WylHandle) handle = open_handle (path);
    Txn t = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (t.txn, wyl_handle_get_policy_store (handle), &input, &kind, &row), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
    g_assert_cmpstr (row->material.payload_digest, ==, digest);
    finish_txn (&t, FALSE);
  }
  g_remove (path);
  g_rmdir (dir);
}

static void
test_fault_atomicity (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn t = begin_txn (handle, TRUE);
  wyl_policy_store_service_exchange_intention_fail_preallocation_once (t.txn);
  WylServiceExchangeIntentionClassification kind;
  WylServiceExchangeIntentionRecord *row = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_NOMEM);
  g_assert_null (row);
  wyl_policy_store_service_exchange_intention_fail_readback_once (t.txn);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_IO);
  g_assert_null (row);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_BUSY);
  finish_txn (&t, FALSE);
  g_assert_cmpint (sqlite3_total_changes (wyl_policy_store_get_db (store)), >,
      0);
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  wyl_policy_store_t *store;
  wyl_id_t intention_id;
  gchar digest[65];
  wyrelog_error_t rc;
} ThreadRead;

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} ThreadEnumerate;

typedef struct
{
  sqlite3 *db;
  WylServiceAuthorityTransaction *txn;
  int total_changes;
  gint64 data_version;
} ReadInvariant;

static ReadInvariant
read_invariant_capture (sqlite3 *db, WylServiceAuthorityTransaction *txn)
{
  gboolean evidence = TRUE, intent = TRUE;
  wyl_policy_store_service_exchange_intention_typed_read_state_for_test (txn,
      &evidence, &intent);
  g_assert_false (evidence);
  g_assert_false (intent);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_state (txn), ==,
      WYL_SERVICE_AUTHORITY_TXN_ACTIVE);
  return (ReadInvariant) {
    db, txn, sqlite3_total_changes (db),
        sql_scalar (db, "PRAGMA main.data_version;")
  };
}

static void
assert_read_invariant (const ReadInvariant *invariant)
{
  gboolean evidence = TRUE, intent = TRUE;
  wyl_policy_store_service_exchange_intention_typed_read_state_for_test
      (invariant->txn, &evidence, &intent);
  g_assert_false (evidence);
  g_assert_false (intent);
  g_assert_cmpint
      (wyl_policy_store_service_authority_transaction_get_state
      (invariant->txn), ==, WYL_SERVICE_AUTHORITY_TXN_ACTIVE);
  g_assert_cmpint (sqlite3_total_changes (invariant->db), ==,
      invariant->total_changes);
  g_assert_cmpint (sql_scalar (invariant->db, "PRAGMA main.data_version;"), ==,
      invariant->data_version);
}

static gpointer
load_wrong_thread (gpointer data)
{
  ThreadRead *attempt = data;
  WylServiceExchangeIntentionRecord *row = (gpointer) 1;
  attempt->rc = wyl_policy_store_service_exchange_intention_load
      (attempt->txn, attempt->store, &attempt->intention_id, attempt->digest,
      &row);
  g_assert_null (row);
  return NULL;
}

static gpointer
enumerate_wrong_thread (gpointer data)
{
  ThreadEnumerate *attempt = data;
  GPtrArray *rows = (gpointer) 1;
  attempt->rc = wyl_policy_store_service_exchange_intention_enumerate
      (attempt->txn, attempt->store, &rows);
  g_assert_null (rows);
  return NULL;
}

static void
test_typed_recovery_reads_without_evidence (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  g_autoptr (WylHandle) other = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);

  gchar digest[65];
  Txn create = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (create.txn, store, &input, &kind, &created), ==, WYRELOG_E_OK);
  g_strlcpy (digest, created->material.payload_digest, sizeof digest);
  finish_txn (&create, TRUE);

  sqlite3 *db = wyl_policy_store_get_db (store);
  int changes_before = sqlite3_total_changes (db);
  gint64 data_version_before = sql_scalar (db, "PRAGMA main.data_version;");
  Txn read = begin_read_txn_without_evidence (handle);
  ReadInvariant invariant = read_invariant_capture (db, read.txn);
  g_autoptr (WylServiceExchangeIntentionRecord) loaded = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &input.intention_id, digest, &loaded), ==,
      WYRELOG_E_OK);
  g_autoptr (GPtrArray) rows = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, store, &rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (rows->len, ==, 1);
  g_assert_true (loaded != rows->pdata[0]);
  g_assert_cmpstr (loaded->tenant_id, ==, "tenant-a");
  g_assert_cmpint (sqlite3_total_changes (db), ==, changes_before);
  g_assert_cmpint (sql_scalar (db, "PRAGMA main.data_version;"), ==,
      data_version_before);
  assert_read_invariant (&invariant);

  WylServiceExchangeIntentionRecord *denied = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &input.intention_id, digest, NULL), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &WYL_ID_NIL, digest, &denied), ==, WYRELOG_E_INVALID);
  g_assert_null (denied);
  denied = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &input.intention_id, "bad", &denied), ==,
      WYRELOG_E_INVALID);
  g_assert_null (denied);
  assert_read_invariant (&invariant);
  denied = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, NULL, &input.intention_id, digest, &denied), ==,
      WYRELOG_E_INVALID);
  g_assert_null (denied);
  assert_read_invariant (&invariant);
  denied = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (NULL, store, &input.intention_id, digest, &denied), !=, WYRELOG_E_OK);
  g_assert_null (denied);
  assert_read_invariant (&invariant);
  denied = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, wyl_handle_get_policy_store (other), &input.intention_id,
          digest, &denied), ==, WYRELOG_E_INVALID);
  g_assert_null (denied);
  assert_read_invariant (&invariant);

  GPtrArray *denied_rows = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, store, NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, NULL, &denied_rows), ==, WYRELOG_E_INVALID);
  g_assert_null (denied_rows);
  assert_read_invariant (&invariant);
  denied_rows = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (NULL, store, &denied_rows), !=, WYRELOG_E_OK);
  g_assert_null (denied_rows);
  assert_read_invariant (&invariant);
  denied_rows = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, wyl_handle_get_policy_store (other), &denied_rows), ==,
      WYRELOG_E_INVALID);
  g_assert_null (denied_rows);
  assert_read_invariant (&invariant);

  ThreadRead attempt = { read.txn, store, input.intention_id, "", 0 };
  g_strlcpy (attempt.digest, digest, sizeof attempt.digest);
  g_autoptr (GThread) thread = g_thread_new ("typed-read-wrong-thread",
      load_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  assert_read_invariant (&invariant);
  ThreadEnumerate enumerate_attempt = { read.txn, store, WYRELOG_E_OK };
  thread = g_thread_new ("typed-enumerate-wrong-thread",
      enumerate_wrong_thread, &enumerate_attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (enumerate_attempt.rc, ==, WYRELOG_E_INVALID);
  assert_read_invariant (&invariant);

  WylServiceExchangeIntentionRecord *append_row = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (read.txn, store, &input, &kind, &append_row), ==, WYRELOG_E_POLICY);
  g_assert_null (append_row);
  assert_read_invariant (&invariant);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (read.txn), ==, WYRELOG_E_OK);
  WylServiceExchangeIntentionRecord *terminal = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &input.intention_id, digest, &terminal), !=,
      WYRELOG_E_OK);
  g_assert_null (terminal);
  GPtrArray *terminal_rows = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, store, &terminal_rows), !=, WYRELOG_E_OK);
  g_assert_null (terminal_rows);
  wyl_policy_store_service_authority_transaction_free (read.txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (read.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (read.lease);
  memset (&read, 0, sizeof read);

  /* Both outputs are independently owned beyond transaction teardown. */
  loaded->tenant_id[0] = 'X';
  g_assert_cmpstr (((WylServiceExchangeIntentionRecord *) rows->pdata[0])->
      tenant_id, ==, "tenant-a");
  g_assert_cmpint (sqlite3_total_changes (db), ==, changes_before);
  g_assert_cmpint (sql_scalar (db, "PRAGMA main.data_version;"), ==,
      data_version_before);
}

typedef void (*TypedReadFaultArm) (WylServiceAuthorityTransaction * txn);

static void
test_typed_recovery_read_fault_cleanup (void)
{
  static const TypedReadFaultArm faults[] = {
    wyl_policy_store_service_exchange_intention_fail_typed_read_prepare_once,
    wyl_policy_store_service_exchange_intention_fail_typed_read_step_once,
    wyl_policy_store_service_exchange_intention_fail_typed_read_allocation_once,
  };
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  gchar digest[65];
  Txn create = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (create.txn, store, &input, &kind, &created), ==, WYRELOG_E_OK);
  g_strlcpy (digest, created->material.payload_digest, sizeof digest);
  finish_txn (&create, TRUE);

  Txn read = begin_read_txn_without_evidence (handle);
  ReadInvariant invariant = read_invariant_capture (db, read.txn);
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    faults[i] (read.txn);
    WylServiceExchangeIntentionRecord *row = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
        (read.txn, store, &input.intention_id, digest, &row), ==,
        i == 2 ? WYRELOG_E_NOMEM : WYRELOG_E_IO);
    g_assert_null (row);
    assert_read_invariant (&invariant);
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
        (read.txn, store, &input.intention_id, digest, &row), ==, WYRELOG_E_OK);
    g_clear_pointer (&row, wyl_service_exchange_intention_record_free);
    assert_read_invariant (&invariant);

    faults[i] (read.txn);
    GPtrArray *rows = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
        (read.txn, store, &rows), ==, i == 2 ? WYRELOG_E_NOMEM : WYRELOG_E_IO);
    g_assert_null (rows);
    assert_read_invariant (&invariant);
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
        (read.txn, store, &rows), ==, WYRELOG_E_OK);
    g_clear_pointer (&rows, g_ptr_array_unref);
    assert_read_invariant (&invariant);
  }
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (read.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (read.txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (read.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (read.lease);
}

static void
test_typed_recovery_read_malformed_row (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  wyl_service_exchange_audit_input_t bad_input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  wyl_service_exchange_audit_input_t good_input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073992",
      "000000000000000000000000001", 11);
  gchar bad_digest[65], good_digest[65];
  for (guint i = 0; i < 2; i++) {
    wyl_service_exchange_audit_input_t *input = i == 0 ? &bad_input :
        &good_input;
    Txn create = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (create.txn, store, input, &kind, &row), ==, WYRELOG_E_OK);
    g_strlcpy (i == 0 ? bad_digest : good_digest,
        row->material.payload_digest, 65);
    finish_txn (&create, TRUE);
  }
  remove_exchange_triggers (db);
  sql_ok (db, "UPDATE service_exchange_audit_intentions SET outcome='deny'"
      " WHERE intention_id='01890f47-3c4b-7cc2-b8c4-dc0c0c073991';");
  sql_ok (db, "PRAGMA ignore_check_constraints=OFF;");
  restore_exchange_triggers (db);

  Txn read = begin_read_txn_without_evidence (handle);
  ReadInvariant invariant = read_invariant_capture (db, read.txn);
  WylServiceExchangeIntentionRecord *bad = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &bad_input.intention_id, bad_digest, &bad), ==,
      WYRELOG_E_POLICY);
  g_assert_null (bad);
  assert_read_invariant (&invariant);
  g_autoptr (WylServiceExchangeIntentionRecord) good = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &good_input.intention_id, good_digest, &good), ==,
      WYRELOG_E_OK);
  assert_read_invariant (&invariant);
  GPtrArray *rows = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (read.txn, store, &rows), ==, WYRELOG_E_POLICY);
  g_assert_null (rows);
  assert_read_invariant (&invariant);
  g_clear_pointer (&good, wyl_service_exchange_intention_record_free);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
      (read.txn, store, &good_input.intention_id, good_digest, &good), ==,
      WYRELOG_E_OK);
  assert_read_invariant (&invariant);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (read.txn), ==, WYRELOG_E_OK);
  wyl_policy_store_service_authority_transaction_free (read.txn);
  g_assert_cmpint (wyl_service_auth_write_lease_release (read.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (read.lease);
}

static void
test_guards_order_and_corruption (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t a = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 20);
  WylServiceExchangeIntentionClassification kind;
  WylServiceExchangeIntentionRecord *row = NULL;
  Txn no_intent = begin_txn (handle, FALSE);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (no_intent.txn, store, &a, &kind, &row), ==, WYRELOG_E_POLICY);
  g_assert_null (row);
  finish_txn (&no_intent, FALSE);

  Txn t = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) owned = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &a, &kind, &owned), ==, WYRELOG_E_OK);
  wyl_service_exchange_audit_input_t b = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073992",
      "000000000000000000000000001", 10);
  g_autoptr (WylServiceExchangeIntentionRecord) second = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &b, &kind, &second), ==, WYRELOG_E_POLICY);
  g_assert_null (second);
  g_autoptr (GPtrArray) rows = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (t.txn, store, &rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (rows->len, ==, 1);
  g_assert_cmpint (((WylServiceExchangeIntentionRecord *) rows->pdata[0])->
      created_at_us, ==, 20);
  a.created_at_us++;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &a, &kind, &row), ==, WYRELOG_E_POLICY);
  g_assert_null (row);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
          "DELETE FROM service_exchange_audit_intentions;", NULL, NULL, NULL),
      !=, SQLITE_OK);
  finish_txn (&t, FALSE);
}

static void
test_persisted_corruption_matrix (void)
{
  static const gchar *const mutations[] = {
    "payload_schema_version=2",
    "fingerprint_schema_version=2",
    "intention_id='01890f47-3c4b-6cc2-b8c4-dc0c0c073991'",
    "request_id='!!!!!!!!!!!!!!!!!!!!!!!!!!!'",
    "credential_id='bad_000000000000000000000000000'",
    "credential_generation=x'01'",
    "credential_generation=x'0000000000000000'",
    "credential_generation=x'8000000000000000'",
    "service_principal=substr(replace(hex(zeroblob(65)),'0','a'),1,129)",
    "service_principal=CAST(x'7376633aff' AS TEXT)",
    "tenant_id=substr(replace(hex(zeroblob(65)),'0','a'),1,129)",
    "tenant_id=CAST(x'ff' AS TEXT)",
    "payload_digest=upper(payload_digest)",
    "payload_digest=substr(payload_digest,1,63)",
    "session_fingerprint=upper(session_fingerprint)",
    "session_fingerprint=substr(session_fingerprint,1,63)",
    "jti_fingerprint=replace(jti_fingerprint,'a','g')",
    "canonical_payload=substr(canonical_payload,1,length(canonical_payload)-1)",
    "canonical_payload=canonical_payload||x'00'",
    "canonical_payload=x'00'",
  };

  for (guint i = 0; i < G_N_ELEMENTS (mutations); i++) {
    g_test_message ("mutation: %s", mutations[i]);
    g_autoptr (WylHandle) handle = open_handle (NULL);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    Txn create = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (create.txn, store, &input, &kind, &created), ==, WYRELOG_E_OK);
    gchar digest[65];
    g_strlcpy (digest, created->material.payload_digest, sizeof digest);
    finish_txn (&create, TRUE);

    sqlite3 *db = wyl_policy_store_get_db (store);
    remove_exchange_triggers (db);
    g_autofree gchar *update = g_strdup_printf
        ("UPDATE service_exchange_audit_intentions SET %s;", mutations[i]);
    sql_ok (db, update);
    sql_ok (db, "PRAGMA ignore_check_constraints=OFF;");
    restore_exchange_triggers (db);
    g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
        WYRELOG_E_OK);

    Txn read = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionRecord *row = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_load
        (read.txn, store, &input.intention_id, digest, &row), ==,
        WYRELOG_E_POLICY);
    g_assert_null (row);
    GPtrArray *rows = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
        (read.txn, store, &rows), ==, WYRELOG_E_POLICY);
    g_assert_null (rows);
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (read.txn, store, &input, &kind, &row), ==, WYRELOG_E_POLICY);
    g_assert_null (row);
    finish_txn (&read, FALSE);
  }

  g_autoptr (WylHandle) handle = open_handle (NULL);
  sqlite3 *db = wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO service_exchange_audit_intentions VALUES(NULL,NULL,"
          "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);",
          NULL, NULL, NULL), !=, SQLITE_OK);
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  wyl_policy_store_t *store;
  wyl_service_exchange_audit_input_t *input;
  wyrelog_error_t rc;
} ThreadAppend;

static gpointer
append_wrong_thread (gpointer data)
{
  ThreadAppend *attempt = data;
  WylServiceExchangeIntentionClassification kind;
  WylServiceExchangeIntentionRecord *row = NULL;
  attempt->rc = wyl_policy_store_service_exchange_intention_append
      (attempt->txn, attempt->store, attempt->input, &kind, &row);
  g_assert_null (row);
  return NULL;
}

static void
test_store_thread_terminal_and_uniqueness_guards (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  g_autoptr (WylHandle) other = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn t = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  WylServiceExchangeIntentionRecord *row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          wyl_handle_get_policy_store (other), &input, &kind, &row), ==,
      WYRELOG_E_INVALID);
  ThreadAppend attempt = { t.txn, store, &input, WYRELOG_E_OK };
  g_autoptr (GThread) thread = g_thread_new ("exchange-wrong-owner",
      append_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_rollback
      (t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_INVALID);
  wyl_policy_store_service_authority_transaction_free (t.txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t.evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t.lease);

  /* The UNIQUE payload digest invariant makes same-digest/different-ID and
   * two-row OR cross matches physically unrepresentable in a valid schema. */
  Txn create = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (create.txn, store, &input, &kind, &created), ==, WYRELOG_E_OK);
  finish_txn (&create, TRUE);
  sqlite3 *db = wyl_policy_store_get_db (store);
  sql_ok (db, "PRAGMA ignore_check_constraints=ON;");
  g_assert_cmpint (sqlite3_exec (db,
          "INSERT INTO service_exchange_audit_intentions SELECT"
          " '01890f47-3c4b-7cc2-b8c4-dc0c0c073992',payload_digest,"
          " payload_schema_version,event_type,outcome,created_at_us,request_id,"
          " credential_id,credential_generation,service_principal,tenant_id,"
          " fingerprint_schema_version,session_fingerprint,jti_fingerprint,"
          " canonical_payload FROM service_exchange_audit_intentions;",
          NULL, NULL, NULL), !=, SQLITE_OK);
  sql_ok (db, "PRAGMA ignore_check_constraints=OFF;");
}

static gint64
scalar (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static gchar *
scalar_text (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  const gchar *value = (const gchar *) sqlite3_column_text (stmt, 0);
  gchar *copy = g_strdup (value != NULL ? value : "");
  sqlite3_finalize (stmt);
  return copy;
}

static gchar *
table_shape (sqlite3 *db, const gchar *schema)
{
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT group_concat(cid||':'||name||':'||type||':'||\"notnull\"||':'||"
      "coalesce(dflt_value,'')||':'||pk,'|') FROM (SELECT * FROM"
      " pragma_table_info('service_exchange_audit_intentions','%s')"
      " ORDER BY cid);", schema);
  return scalar_text (db, sql);
}

static gchar *
index_shape (sqlite3 *db, const gchar *schema)
{
  g_autofree gchar *sql = g_strdup_printf
      ("SELECT group_concat(name||':'||\"unique\"||':'||origin||':'||partial,"
      "'|') FROM (SELECT * FROM pragma_index_list("
      "'service_exchange_audit_intentions','%s') ORDER BY name);", schema);
  return scalar_text (db, sql);
}

static void
test_hostile_trigger_canary (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t seed = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn create = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (create.txn, store, &seed, &kind, &row), ==, WYRELOG_E_OK);
  finish_txn (&create, TRUE);
  sqlite3 *db = wyl_policy_store_get_db (store);
  sql_ok (db, "CREATE TABLE trigger_canary(value INTEGER NOT NULL);"
      "INSERT INTO trigger_canary VALUES(0);"
      "CREATE TRIGGER hostile_exchange BEFORE INSERT ON"
      " service_exchange_audit_intentions BEGIN UPDATE trigger_canary"
      " SET value=value+1; END;");
  const gchar *probe =
      "INSERT INTO service_exchange_audit_intentions SELECT"
      " '01890f47-3c4b-7cc2-b8c4-dc0c0c073992',"
      " 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',"
      " payload_schema_version,event_type,outcome,created_at_us,request_id,"
      " credential_id,credential_generation,service_principal,tenant_id,"
      " fingerprint_schema_version,session_fingerprint,jti_fingerprint,"
      " canonical_payload FROM service_exchange_audit_intentions LIMIT 1;";
  sql_ok (db, "SAVEPOINT hostile_probe;");
  sql_ok (db, probe);
  g_assert_cmpint (scalar (db, "SELECT value FROM trigger_canary;"), ==, 1);
  sql_ok (db, "ROLLBACK TO hostile_probe; RELEASE hostile_probe;");
  wyl_service_exchange_audit_input_t fresh = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
      "000000000000000000000000002", 12);
  Txn guarded = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionRecord *out = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (guarded.txn, store, &fresh, &kind, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out);
  g_assert_cmpint (scalar (db, "SELECT value FROM trigger_canary;"), ==, 0);
  finish_txn (&guarded, FALSE);
  sql_ok (db, "DROP TRIGGER hostile_exchange;"
      "CREATE TEMP TRIGGER hostile_exchange_temp BEFORE INSERT ON"
      " main.service_exchange_audit_intentions BEGIN UPDATE trigger_canary"
      " SET value=value+1; END;");
  sql_ok (db, "SAVEPOINT hostile_probe;");
  sql_ok (db, probe);
  g_assert_cmpint (scalar (db, "SELECT value FROM trigger_canary;"), ==, 1);
  sql_ok (db, "ROLLBACK TO hostile_probe; RELEASE hostile_probe;");
  guarded = begin_txn (handle, TRUE);
  out = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (guarded.txn, store, &fresh, &kind, &out), ==, WYRELOG_E_POLICY);
  g_assert_null (out);
  g_assert_cmpint (scalar (db, "SELECT value FROM trigger_canary;"), ==, 0);
  finish_txn (&guarded, FALSE);
}

static void
test_temp_shadow_objects (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  sql_ok (db, "CREATE TEMP TABLE service_exchange_audit_intentions(value);"
      "INSERT INTO service_exchange_audit_intentions VALUES(1);");
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM temp.service_exchange_audit_intentions;"), ==,
      1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      0);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn t = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  WylServiceExchangeIntentionRecord *row = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_POLICY);
  g_assert_null (row);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM temp.service_exchange_audit_intentions;"), ==,
      1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      0);
  finish_txn (&t, FALSE);
  sql_ok (db, "DROP TABLE temp.service_exchange_audit_intentions;");
  t = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &created), ==, WYRELOG_E_OK);
  finish_txn (&t, FALSE);

  sql_ok (db, "CREATE TEMP TABLE shadow_canary(value INTEGER);"
      "INSERT INTO shadow_canary VALUES(0);"
      "CREATE TEMP VIEW service_exchange_audit_intentions AS SELECT value"
      " FROM shadow_canary;"
      "CREATE TEMP TRIGGER shadow_view_insert INSTEAD OF INSERT ON"
      " service_exchange_audit_intentions BEGIN UPDATE shadow_canary"
      " SET value=value+1; END;"
      "INSERT INTO service_exchange_audit_intentions VALUES(1);");
  g_assert_cmpint (scalar (db, "SELECT value FROM shadow_canary;"), ==, 1);
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  sql_ok (db, "DROP VIEW temp.service_exchange_audit_intentions;"
      "DROP TABLE temp.shadow_canary;");

  sql_ok (db, "CREATE TEMP TABLE service_authority_writer_gate("
      "singleton,lock_word); INSERT INTO service_authority_writer_gate"
      " VALUES(1,7); UPDATE service_authority_writer_gate SET lock_word=8;");
  g_assert_cmpint (scalar (db,
          "SELECT lock_word FROM temp.service_authority_writer_gate;"), ==, 8);
  g_assert_cmpint (scalar (db,
          "SELECT lock_word FROM main.service_authority_writer_gate;"), ==, 0);
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  sql_ok (db, "DROP TABLE temp.service_authority_writer_gate;"
      "CREATE TEMP TABLE unrelated(value);"
      "CREATE INDEX temp.idx_service_exchange_audit_created ON unrelated(value);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_POLICY);
  sql_ok (db, "DROP TABLE temp.unrelated; CREATE TEMP TABLE harmless(value);");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
}

static void
test_exact_temp_clone (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-clone-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.db", NULL);
  g_autoptr (WylHandle) handle = open_handle (path);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  sqlite3 *db = wyl_policy_store_get_db (store);
  wyl_service_exchange_audit_input_t seed = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn create = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) seed_row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (create.txn, store, &seed, &kind, &seed_row), ==, WYRELOG_E_OK);
  finish_txn (&create, TRUE);

  g_autofree gchar *main_sql = scalar_text (db,
      "SELECT sql FROM main.sqlite_schema WHERE type='table' AND"
      " name='service_exchange_audit_intentions';");
  g_assert_true (g_str_has_prefix (main_sql, "CREATE TABLE "));
  g_autofree gchar *temp_sql = g_strconcat ("CREATE TEMP TABLE ",
      main_sql + strlen ("CREATE TABLE "), NULL);
  sql_ok (db, temp_sql);
  g_autofree gchar *main_index_sql = scalar_text (db,
      "SELECT sql FROM main.sqlite_schema WHERE type='index' AND"
      " name='idx_service_exchange_audit_created';");
  g_assert_nonnull (strstr (main_index_sql,
          "service_exchange_audit_intentions"));
  sql_ok (db, "CREATE INDEX temp.idx_service_exchange_audit_created ON"
      " service_exchange_audit_intentions(created_at_us,intention_id);");

  g_autofree gchar *main_shape = table_shape (db, "main");
  g_autofree gchar *temp_shape = table_shape (db, "temp");
  g_assert_cmpstr (temp_shape, ==, main_shape);
  g_autofree gchar *main_indexes = index_shape (db, "main");
  g_autofree gchar *temp_indexes = index_shape (db, "temp");
  g_assert_cmpstr (temp_indexes, ==, main_indexes);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM pragma_foreign_key_list("
          "'service_exchange_audit_intentions','main');"), ==,
      scalar (db, "SELECT count(*) FROM pragma_foreign_key_list("
          "'service_exchange_audit_intentions','temp');"));
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM temp.sqlite_schema WHERE type='trigger' AND"
          " tbl_name='service_exchange_audit_intentions';"), ==, 0);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM pragma_index_xinfo("
          "'idx_service_exchange_audit_created','main');"), ==,
      scalar (db, "SELECT count(*) FROM pragma_index_xinfo("
          "'idx_service_exchange_audit_created','temp');"));

  sql_ok (db, "INSERT INTO service_exchange_audit_intentions"
      " SELECT * FROM main.service_exchange_audit_intentions;");
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM temp.service_exchange_audit_intentions;"), ==,
      1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      1);
  wyl_service_exchange_audit_input_t fresh = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073993",
      "000000000000000000000000002", 12);
  Txn guarded = begin_txn (handle, TRUE);
  gint changes = sqlite3_total_changes (db);
  kind = WYL_SERVICE_EXCHANGE_INTENTION_REPLAY;
  WylServiceExchangeIntentionRecord *out = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (guarded.txn, store, &fresh, &kind, &out), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_NONE);
  g_assert_null (out);
  g_assert_cmpint (sqlite3_total_changes (db), ==, changes);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM temp.service_exchange_audit_intentions;"), ==,
      1);
  g_assert_cmpint (scalar (db,
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      1);
  finish_txn (&guarded, FALSE);
  sql_ok (db, "DROP INDEX temp.idx_service_exchange_audit_created;"
      "DROP TABLE temp.service_exchange_audit_intentions;");
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);
  Txn normal = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) created = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (normal.txn, store, &fresh, &kind, &created), ==, WYRELOG_E_OK);
  finish_txn (&normal, TRUE);
  g_clear_object (&handle);
  handle = open_handle (path);
  Txn reopen = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) replay = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (reopen.txn, wyl_handle_get_policy_store (handle), &fresh, &kind,
          &replay), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  finish_txn (&reopen, FALSE);
  g_clear_object (&handle);
  g_remove (path);
  g_rmdir (dir);
}

static void
release_committed_txn (Txn *t)
{
  wyl_policy_store_service_authority_transaction_free (t->txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t->evidence);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t->lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t->lease);
  memset (t, 0, sizeof *t);
}

static gpointer
receipt_unref_thread (gpointer data)
{
  WylServiceExchangeReceipt *receipt = data;
  g_autoptr (WylServiceExchangeIntentionRecord) copy = NULL;
  g_assert_cmpint (wyl_service_exchange_receipt_dup_record (receipt, &copy),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (copy);
  copy->tenant_id[0] = 'X';
  wyl_service_exchange_receipt_unref (receipt);
  return NULL;
}

static void
test_receipt_created_take_once (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn t = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_OK);
  WylServiceExchangeReceipt *receipt = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
  g_assert_null (receipt);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, handle, store, &receipt), ==, WYRELOG_E_OK);
  g_assert_nonnull (receipt);
  g_assert_cmpint (wyl_service_exchange_receipt_get_classification (receipt),
      ==, WYL_SERVICE_EXCHANGE_INTENTION_CREATED);
  g_autoptr (WylServiceExchangeIntentionRecord) receipt_copy = NULL;
  g_assert_cmpint (wyl_service_exchange_receipt_dup_record (receipt,
          &receipt_copy), ==, WYRELOG_E_OK);
  g_assert_cmpstr (receipt_copy->tenant_id, ==, "tenant-a");
  receipt_copy->tenant_id[0] = 'X';
  g_autoptr (WylServiceExchangeIntentionRecord) independent = NULL;
  g_assert_cmpint (wyl_service_exchange_receipt_dup_record (receipt,
          &independent), ==, WYRELOG_E_OK);
  g_assert_cmpstr (independent->tenant_id, ==, "tenant-a");
  WylServiceExchangeReceipt *again = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, handle, store, &again), ==, WYRELOG_E_INVALID);
  g_assert_null (again);
  release_committed_txn (&t);
  g_clear_pointer (&receipt_copy, wyl_service_exchange_intention_record_free);
  g_assert_cmpint (wyl_service_exchange_receipt_dup_record (receipt,
          &receipt_copy), ==, WYRELOG_E_OK);
  g_assert_cmpstr (receipt_copy->tenant_id, ==, "tenant-a");
  wyl_service_exchange_receipt_unref (receipt);

  Txn replay_txn = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) replay_row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (replay_txn.txn, store, &input, &kind, &replay_row), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (replay_txn.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take
      (replay_txn.txn, replay_txn.evidence, handle, store, &receipt), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_receipt_get_classification (receipt),
      ==, WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  g_autoptr (WylServiceExchangeIntentionRecord) replay_copy = NULL;
  g_assert_cmpint (wyl_service_exchange_receipt_dup_record (receipt,
          &replay_copy), ==, WYRELOG_E_OK);
  g_assert_cmpstr (replay_copy->material.intention_id, ==,
      replay_row->material.intention_id);
  release_committed_txn (&replay_txn);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      1);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_receipt_validate_handle (receipt,
          handle, NULL), ==, WYRELOG_E_INVALID);
  GThread *copy_threads[3];
  for (guint i = 0; i < G_N_ELEMENTS (copy_threads); i++) {
    WylServiceExchangeReceipt *thread_ref =
        wyl_service_exchange_receipt_ref (receipt);
    g_assert_nonnull (thread_ref);
    copy_threads[i] = g_thread_new ("receipt-copy-unref",
        receipt_unref_thread, thread_ref);
  }
  for (guint i = 0; i < G_N_ELEMENTS (copy_threads); i++)
    g_thread_join (copy_threads[i]);
  g_autoptr (GThread) unref_thread = g_thread_new ("receipt-last-unref",
      receipt_unref_thread, receipt);
  g_thread_join (g_steal_pointer (&unref_thread));
}

static void
test_receipt_allocation_faults (void)
{
  for (guint fail_at = 1; fail_at <= 4; fail_at++) {
    g_autoptr (WylHandle) handle = open_handle (NULL);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    Txn t = begin_txn (handle, TRUE);
    wyl_policy_store_service_exchange_receipt_fail_allocation (t.txn, fail_at);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    WylServiceExchangeIntentionClassification kind =
        WYL_SERVICE_EXCHANGE_INTENTION_CREATED;
    WylServiceExchangeIntentionRecord *row = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (t.txn, store, &input, &kind, &row), ==, WYRELOG_E_NOMEM);
    g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_NONE);
    g_assert_null (row);
    g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
            "SELECT count(*) FROM main.service_exchange_audit_intentions;"),
        ==, 0);
    finish_txn (&t, FALSE);
  }
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  Txn created_fail = begin_txn (handle, TRUE);
  wyl_policy_store_service_exchange_receipt_fail_evidence_ref_once
      (created_fail.txn);
  WylServiceExchangeIntentionClassification kind =
      WYL_SERVICE_EXCHANGE_INTENTION_CREATED;
  WylServiceExchangeIntentionRecord *row = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (created_fail.txn, store, &input, &kind, &row), ==, WYRELOG_E_INTERNAL);
  g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_NONE);
  g_assert_null (row);
  finish_txn (&created_fail, FALSE);
  Txn seed = begin_txn (handle, TRUE);
  g_autoptr (WylServiceExchangeIntentionRecord) seeded = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (seed.txn, store, &input, &kind, &seeded), ==, WYRELOG_E_OK);
  finish_txn (&seed, TRUE);
  Txn replay_fail = begin_txn (handle, TRUE);
  wyl_policy_store_service_exchange_receipt_fail_evidence_ref_once
      (replay_fail.txn);
  row = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (replay_fail.txn, store, &input, &kind, &row), ==, WYRELOG_E_INTERNAL);
  g_assert_null (row);
  g_assert_cmpint (scalar (wyl_policy_store_get_db (store),
          "SELECT count(*) FROM main.service_exchange_audit_intentions;"), ==,
      1);
  finish_txn (&replay_fail, FALSE);
}

static void
test_receipt_generation_guard (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle, TRUE);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  wyl_handle_policy_store_test_advance_generation (handle);
  WylServiceExchangeReceipt *receipt = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
  g_assert_null (receipt);
  release_committed_txn (&t);
}

typedef struct
{
  WylServiceAuthorityTransaction *txn;
  WylServiceAuthorityCommitEvidence *evidence;
  WylHandle *handle;
  wyl_policy_store_t *store;
  wyrelog_error_t rc;
} ReceiptTakeThread;

static gpointer
receipt_take_wrong_thread (gpointer data)
{
  ReceiptTakeThread *attempt = data;
  WylServiceExchangeReceipt *receipt = (gpointer) 1;
  attempt->rc = wyl_policy_store_service_exchange_receipt_take (attempt->txn,
      attempt->evidence, attempt->handle, attempt->store, &receipt);
  g_assert_null (receipt);
  return NULL;
}

static void
test_receipt_identity_guards_no_detach (void)
{
  g_autoptr (WylHandle) handle = open_handle (NULL);
  g_autoptr (WylHandle) other = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  Txn t = begin_txn (handle, TRUE);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append (t.txn,
          store, &input, &kind, &row), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (t.txn), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_release (t.lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (t.lease);
  t.lease = NULL;
  Txn alien = begin_txn (other, TRUE);
  WylServiceExchangeReceipt *receipt = (gpointer) 1;
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          alien.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
  g_assert_null (receipt);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (alien.txn,
          t.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
  g_assert_null (receipt);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, other, wyl_handle_get_policy_store (other), &receipt),
      ==, WYRELOG_E_INVALID);
  g_assert_null (receipt);
  ReceiptTakeThread attempt = { t.txn, t.evidence, handle, store,
    WYRELOG_E_OK
  };
  g_autoptr (GThread) thread = g_thread_new ("receipt-wrong-owner",
      receipt_take_wrong_thread, &attempt);
  g_thread_join (g_steal_pointer (&thread));
  g_assert_cmpint (attempt.rc, ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
          t.evidence, handle, store, &receipt), ==, WYRELOG_E_OK);
  g_assert_nonnull (receipt);
  finish_txn (&alien, FALSE);
  wyl_policy_store_service_authority_transaction_free (t.txn);
  wyl_policy_store_service_authority_commit_evidence_unref (t.evidence);
  wyl_service_exchange_receipt_test_set_refcount_max (receipt);
  g_assert_null (wyl_service_exchange_receipt_ref (receipt));
  wyl_service_exchange_receipt_test_restore_refcount_one (receipt);
  wyl_service_exchange_receipt_unref (receipt);
}

static void
test_receipt_failure_withheld (void)
{
  const WylPolicyAuthorityTransactionFailStage faults[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER,
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_autoptr (WylHandle) handle = open_handle (NULL);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    wyl_policy_store_service_authority_transaction_fail_once (store, faults[i]);
    Txn t = begin_txn (handle, TRUE);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (t.txn, store, &input, &kind, &row), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (t.txn), !=, WYRELOG_E_OK);
    WylServiceExchangeReceipt *receipt = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
            t.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
    g_assert_null (receipt);
    release_committed_txn (&t);
  }

  g_autoptr (WylHandle) handle = open_handle (NULL);
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_service_exchange_audit_input_t input = input_at
      ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
      "000000000000000000000000000", 10);
  for (guint attempt = 0; attempt < 2; attempt++) {
    wyl_policy_store_service_authority_transaction_fail_once (store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
    Txn failed = begin_txn (handle, TRUE);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (failed.txn, store, &input, &kind, &row), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (failed.txn), !=, WYRELOG_E_OK);
    WylServiceExchangeReceipt *withheld = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take
        (failed.txn, failed.evidence, handle, store, &withheld), ==,
        WYRELOG_E_INVALID);
    g_assert_null (withheld);
    release_committed_txn (&failed);
  }
  Txn converge = begin_txn (handle, TRUE);
  WylServiceExchangeIntentionClassification kind;
  g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
      (converge.txn, store, &input, &kind, &row), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_SERVICE_EXCHANGE_INTENTION_REPLAY);
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
      (converge.txn), ==, WYRELOG_E_OK);
  WylServiceExchangeReceipt *receipt = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take
      (converge.txn, converge.evidence, handle, store, &receipt), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (receipt);
  release_committed_txn (&converge);
  wyl_service_exchange_receipt_unref (receipt);
}

static void
test_receipt_cleanup_faults (void)
{
  const WylPolicyAuthorityTransactionFailStage faults[] = {
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_BEFORE,
    WYL_POLICY_AUTHORITY_TXN_FAIL_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_RANK_AND_CLAIM_AFTER,
    WYL_POLICY_AUTHORITY_TXN_FAIL_LEASE_SERIAL_AT_FINISH,
  };
  for (guint i = 0; i < G_N_ELEMENTS (faults); i++) {
    g_autoptr (WylHandle) handle = open_handle (NULL);
    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    wyl_policy_store_service_authority_transaction_fail_once (store, faults[i]);
    Txn t = begin_txn (handle, TRUE);
    wyl_service_exchange_audit_input_t input = input_at
        ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991",
        "000000000000000000000000000", 10);
    WylServiceExchangeIntentionClassification kind;
    g_autoptr (WylServiceExchangeIntentionRecord) row = NULL;
    g_assert_cmpint (wyl_policy_store_service_exchange_intention_append
        (t.txn, store, &input, &kind, &row), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_service_authority_transaction_commit
        (t.txn), ==, WYRELOG_E_OK);
    g_assert_cmpint
        (wyl_policy_store_service_authority_transaction_get_cleanup_result
        (t.txn), !=, WYRELOG_E_OK);
    WylServiceExchangeReceipt *receipt = (gpointer) 1;
    g_assert_cmpint (wyl_policy_store_service_exchange_receipt_take (t.txn,
            t.evidence, handle, store, &receipt), ==, WYRELOG_E_INVALID);
    g_assert_null (receipt);
    release_committed_txn (&t);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange/store/commit-reopen-replay",
      test_commit_reopen_replay);
  g_test_add_func ("/service-exchange/store/fault-atomicity",
      test_fault_atomicity);
  g_test_add_func ("/service-exchange/store/typed-recovery-read",
      test_typed_recovery_reads_without_evidence);
  g_test_add_func ("/service-exchange/store/typed-recovery-read-faults",
      test_typed_recovery_read_fault_cleanup);
  g_test_add_func ("/service-exchange/store/typed-recovery-read-malformed",
      test_typed_recovery_read_malformed_row);
  g_test_add_func ("/service-exchange/store/guards-order-corruption",
      test_guards_order_and_corruption);
  g_test_add_func ("/service-exchange/store/persisted-corruption-matrix",
      test_persisted_corruption_matrix);
  g_test_add_func ("/service-exchange/store/store-thread-terminal-uniqueness",
      test_store_thread_terminal_and_uniqueness_guards);
  g_test_add_func ("/service-exchange/store/hostile-trigger-canary",
      test_hostile_trigger_canary);
  g_test_add_func ("/service-exchange/store/temp-shadow-objects",
      test_temp_shadow_objects);
  g_test_add_func ("/service-exchange/store/exact-temp-clone",
      test_exact_temp_clone);
  g_test_add_func ("/service-exchange/receipt/created-take-once",
      test_receipt_created_take_once);
  g_test_add_func ("/service-exchange/receipt/failure-withheld",
      test_receipt_failure_withheld);
  g_test_add_func ("/service-exchange/receipt/cleanup-faults",
      test_receipt_cleanup_faults);
  g_test_add_func ("/service-exchange/receipt/allocation-faults",
      test_receipt_allocation_faults);
  g_test_add_func ("/service-exchange/receipt/generation-guard",
      test_receipt_generation_guard);
  g_test_add_func ("/service-exchange/receipt/identity-guards-no-detach",
      test_receipt_identity_guards_no_detach);
  return g_test_run ();
}
