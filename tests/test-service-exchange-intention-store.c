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
          store, &b, &kind, &second), ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) rows = NULL;
  g_assert_cmpint (wyl_policy_store_service_exchange_intention_enumerate
      (t.txn, store, &rows), ==, WYRELOG_E_OK);
  g_assert_cmpuint (rows->len, ==, 2);
  g_assert_cmpint (((WylServiceExchangeIntentionRecord *) rows->pdata[0])->
      created_at_us, ==, 10);
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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange/store/commit-reopen-replay",
      test_commit_reopen_replay);
  g_test_add_func ("/service-exchange/store/fault-atomicity",
      test_fault_atomicity);
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
  return g_test_run ();
}
