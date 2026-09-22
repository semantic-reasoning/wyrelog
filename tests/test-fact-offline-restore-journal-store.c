/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#ifndef G_OS_WIN32
#include <errno.h>
#endif

#include "wyrelog/fact/offline-restore-journal-store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef G_OS_WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#define OP_A "018f22d0-7b6d-7a5b-8c31-123456789abc"
#define OP_B "018f22d0-7b6d-7a5b-8c31-123456789abd"
#define OP_C "018f22d0-7b6d-7a5b-8c31-123456789abe"
#define OP_D "018f22d0-7b6d-7a5b-8c31-123456789abf"
#define OP_E "018f22d0-7b6d-7a5b-8c31-123456789ac0"
#define OP_F "018f22d0-7b6d-7a5b-8c31-123456789ac1"

static void init_journal (WylFactOfflineRestoreJournal *journal,
    const gchar *operation_uuid);
static void clone_journal (const WylFactOfflineRestoreJournal *source,
    WylFactOfflineRestoreJournal *destination);

static gboolean
write_policy_key (const gchar *path)
{
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (17 + i);
  return g_file_set_contents (path, (const gchar *) key, sizeof key, NULL);
}

static wyrelog_error_t
open_encrypted_store (const gchar *path, const gchar *key_path,
    wyl_policy_store_t **out_store)
{
  wyl_keyprovider_file_t *provider = wyl_keyprovider_file_new (key_path);
  if (provider == NULL)
    return WYRELOG_E_IO;
  wyl_policy_store_open_options_t options = {
    .path = path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = provider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_open_with_options (&options, out_store);
}

static void
remove_test_directory (const gchar *path)
{
  GDir *directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *entry;
    while ((entry = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, entry, NULL);
      g_assert_cmpint (g_remove (child), ==, 0);
    }
    g_dir_close (directory);
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

#ifndef G_OS_WIN32
typedef enum
{
  ABRUPT_CREATE,
  ABRUPT_CAS,
  ABRUPT_RELEASE,
} AbruptMutation;

static gint
abrupt_mutation_child (const gchar *store_path, const gchar *key_path,
    AbruptMutation mutation)
{
  /* Deliberately leave the SQLite/key-provider handles open: the caller
   * terminates this process immediately after this function returns. */
  wyl_policy_store_t *store = NULL;
  if (open_encrypted_store (store_path, key_path, &store) != WYRELOG_E_OK)
    return 10;
  WylFactOfflineRestoreStoreResult result = 0;
  if (mutation == ABRUPT_CREATE) {
    WylFactOfflineRestoreJournal journal = { 0 };
    WylFactOfflineRestoreJournal committed = { 0 };
    init_journal (&journal, OP_A);
    wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_create
          (store, &journal, &result, &committed);
    wyl_fact_offline_restore_journal_clear (&committed);
    wyl_fact_offline_restore_journal_clear (&journal);
    return rc == WYRELOG_E_OK
           && result == WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED ? 0 : 11;
  }
  WylFactOfflineRestoreJournal current = { 0 };
  wyrelog_error_t rc = wyl_fact_offline_restore_journal_store_load (store,
          OP_A, &current);
  if (rc != WYRELOG_E_OK)
    return 12;
  if (mutation == ABRUPT_CAS) {
    WylFactOfflineRestoreJournal desired = { 0 };
    clone_journal (&current, &desired);
    rc = wyl_fact_offline_restore_journal_decide (&desired,
            WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK);
    WylFactOfflineRestoreJournal committed = { 0 };
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_offline_restore_journal_store_cas (store, 1, &desired,
              &result, &committed);
    wyl_fact_offline_restore_journal_clear (&committed);
    wyl_fact_offline_restore_journal_clear (&desired);
    wyl_fact_offline_restore_journal_clear (&current);
    return rc == WYRELOG_E_OK
           && result == WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED ? 0 : 13;
  }
  rc = wyl_fact_offline_restore_journal_store_release (store,
          current.revision, OP_A, &result);
  wyl_fact_offline_restore_journal_clear (&current);
  return rc == WYRELOG_E_OK
         && result == WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED ? 0 : 14;
}

static void
run_abrupt_mutation (const gchar *store_path, const gchar *key_path,
    AbruptMutation mutation)
{
  pid_t child = fork ();
  g_assert_cmpint (child, >=, 0);
  if (child == 0)
    WYL_TEST__EXIT (abrupt_mutation_child (store_path, key_path, mutation));
  gint status = 0;
  pid_t waited;
  do {
    waited = waitpid (child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  g_assert_cmpint (waited, ==, child);
  g_assert_true (WIFEXITED (status));
  g_assert_cmpint (WEXITSTATUS (status), ==, 0);
}

static void
encrypted_abrupt_exit (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *directory =
      g_dir_make_tmp ("wyl-restore-crash-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (directory);
  g_autofree gchar *store_path =
      g_build_filename (directory, "policy.store", NULL);
  g_autofree gchar *key_path =
      g_build_filename (directory, "policy.key", NULL);
  g_assert_true (write_policy_key (key_path));

  /* Seed the common encrypted database before any child inherits state. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  for (guint operation = ABRUPT_CREATE; operation <= ABRUPT_RELEASE;
      operation++) {
    g_clear_pointer (&store, wyl_policy_store_close);
    run_abrupt_mutation (store_path, key_path, (AbruptMutation) operation);
    g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
        WYRELOG_E_OK);
    g_auto (WylFactOfflineRestoreJournal) recovered = { 0 };
    if (operation == ABRUPT_RELEASE) {
      g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
            (store, OP_A, &recovered), ==, WYRELOG_E_NOT_FOUND);
    } else {
      g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
            (store, OP_A, &recovered), ==, WYRELOG_E_OK);
      g_assert_cmpuint (recovered.revision, ==,
          operation == ABRUPT_CAS ? 2 : 1);
      if (operation == ABRUPT_CAS)
        g_assert_cmpint (recovered.decision, ==,
            WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK);
    }
  }
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_test_directory (directory);
}
#endif

static GBytes *
manifest_bytes (const gchar *graph_id)
{
  WylFactOfflineBackupManifest manifest = { 0 };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_init
        (&manifest, "tenant-a", 7), ==, WYRELOG_E_OK);
  WylFactOfflineBackupArtifact artifact = {
    .graph_id = (gchar *) graph_id, .store_uuid = "store-restore",
    .format_version = 1, .path_encoding_version = 1,
    .schema_digest = "schema-alpha", .logical_bytes = 10,
    .physical_bytes = 4096, .checksum = "sha256:alpha",
  };
  g_assert_cmpint (wyl_fact_offline_backup_manifest_add
        (&manifest, &artifact), ==, WYRELOG_E_OK);
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_fact_offline_backup_manifest_encode
        (&manifest, &bytes), ==, WYRELOG_E_OK);
  wyl_fact_offline_backup_manifest_clear (&manifest);
  return bytes;
}

static GPtrArray *
target_graphs (const gchar *graph_id)
{
  GPtrArray *targets = g_ptr_array_new_with_free_func
        ((GDestroyNotify) wyl_fact_offline_restore_target_graph_free);
  WylFactOfflineRestoreTargetGraph *target = g_new0
        (WylFactOfflineRestoreTargetGraph, 1);
  target->graph_id = g_strdup (graph_id);
  target->lifecycle_generation = 11;
  target->reconciliation_generation = 12;
  target->expected_main_absent = TRUE;
  g_ptr_array_add (targets, target);
  return targets;
}

static void
init_journal (WylFactOfflineRestoreJournal *journal, const gchar *operation)
{
  g_autoptr (GBytes) manifest = manifest_bytes ("alpha");
  g_autoptr (GPtrArray) targets = target_graphs ("alpha");
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (journal, manifest,
      operation, WYL_FACT_OFFLINE_RESTORE_SCOPE_TENANT, NULL, 31, 32,
      targets, WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
}

static void
init_graph_journal (WylFactOfflineRestoreJournal *journal,
    const gchar *operation, const gchar *graph_id)
{
  g_autoptr (GBytes) manifest = manifest_bytes (graph_id);
  g_autoptr (GPtrArray) targets = target_graphs (graph_id);
  g_assert_cmpint (wyl_fact_offline_restore_journal_init (journal, manifest,
      operation, WYL_FACT_OFFLINE_RESTORE_SCOPE_GRAPH, graph_id, 31, 32,
      targets, WYL_FACT_OFFLINE_RESTORE_CONFIRMATION_EXPLICIT,
      WYL_FACT_OFFLINE_RESTORE_MANIFEST_AUTHENTICATED), ==, WYRELOG_E_OK);
}

static void
clone_journal (const WylFactOfflineRestoreJournal *source,
    WylFactOfflineRestoreJournal *destination)
{
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_encode
        (source, &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decode
        (encoded, destination), ==, WYRELOG_E_OK);
}

static gint
row_count (wyl_policy_store_t *store, const gchar *table)
{
  g_autofree gchar *sql = g_strdup_printf ("SELECT count(*) FROM %s;", table);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql,
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint count = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

typedef struct
{
  wyl_policy_store_t *store;
  const WylFactOfflineRestoreJournal *journal;
  wyrelog_error_t rc;
  WylFactOfflineRestoreStoreResult result;
  WylFactOfflineRestoreJournal committed;
} CreateThread;

static gpointer
create_thread (gpointer data)
{
  CreateThread *thread = data;
  thread->rc = wyl_fact_offline_restore_journal_store_create (thread->store,
          thread->journal, &thread->result, &thread->committed);
  return NULL;
}

static void
storage_contract (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);

  g_auto (WylFactOfflineRestoreJournal) initial = { 0 };
  init_journal (&initial, OP_A);
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  WylFactOfflineRestoreStoreResult result = 0;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &initial, &result, &committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);

  g_assert_cmpuint (committed.revision, ==, 1);

  g_auto (WylFactOfflineRestoreJournal) replay = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &initial, &result, &replay), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_FACT_OFFLINE_RESTORE_STORE_UNCHANGED_REPLAY);

  g_auto (WylFactOfflineRestoreJournal) same_operation_conflict = { 0 };
  clone_journal (&initial, &same_operation_conflict);
  same_operation_conflict.destination_tenant_lifecycle_generation++;
  g_auto (WylFactOfflineRestoreJournal) same_operation_winner = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &same_operation_conflict, &result, &same_operation_winner),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_cmpstr (same_operation_winner.operation_uuid, ==, OP_A);
  g_assert_cmpuint (same_operation_winner.
      destination_tenant_lifecycle_generation, ==,
      initial.destination_tenant_lifecycle_generation);

  g_auto (WylFactOfflineRestoreJournal) conflict = { 0 };
  init_journal (&conflict, OP_B);
  g_auto (WylFactOfflineRestoreJournal) conflict_committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &conflict, &result, &conflict_committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_cmpstr (conflict_committed.operation_uuid, ==, OP_A);

  g_autoptr (GPtrArray) listed = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, "tenant-a", 2, &listed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 1);

  g_assert_cmpint (wyl_fact_offline_restore_journal_store_release
        (store, 1, OP_A, &result), ==, WYRELOG_E_POLICY);
  g_clear_pointer (&listed, g_ptr_array_unref);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, "tenant-a", 2, &listed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 1);

  WylFactOfflineRestoreJournal malformed = initial;
  malformed.revision = 2;
  malformed.graphs = g_ptr_array_new ();
  g_ptr_array_add (malformed.graphs, g_ptr_array_index (initial.graphs, 0));
  g_ptr_array_add (malformed.graphs, g_ptr_array_index (initial.graphs, 0));
  g_assert_false (wyl_fact_offline_restore_journal_is_legal_successor
        (&initial, &malformed));
  g_ptr_array_unref (malformed.graphs);

  g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
  clone_journal (&committed, &desired);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&desired,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) updated = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (store, 1, &desired, &result, &updated), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpint (wyl_fact_offline_restore_journal_recovery (&updated), ==,
      WYL_FACT_OFFLINE_RESTORE_RECOVERY_COMPLETE);

  g_auto (WylFactOfflineRestoreJournal) stale_desired = { 0 };
  clone_journal (&initial, &stale_desired);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&stale_desired,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) stale_committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (store, 1, &stale_desired, &result, &stale_committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_STALE);
  g_assert_cmpuint (stale_committed.revision, ==, 2);

  g_assert_cmpint (wyl_fact_offline_restore_journal_store_release
        (store, 2, OP_A, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_auto (WylFactOfflineRestoreJournal) absent = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_A, &absent), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_release
        (store, 2, OP_A, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_NOT_FOUND);

  g_auto (WylFactOfflineRestoreJournal) width_16_zero = { 0 };
  init_journal (&width_16_zero, OP_B);
  WylFactOfflineRestoreJournalGraph *width_16_graph =
      g_ptr_array_index (width_16_zero.graphs, 0);
  width_16_graph->staged_main_identity.object_width = 16;
  g_auto (WylFactOfflineRestoreJournal) width_16_committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &width_16_zero, &result, &width_16_committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_assert_cmpuint (((WylFactOfflineRestoreJournalGraph *)
      g_ptr_array_index (width_16_committed.graphs, 0))->
      staged_main_identity.object_width, ==, 16);
}

static void
claim_matrix_and_schema_tamper (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_exec (db,
      "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
      "schema_version,owner_scope,created_at,updated_at) VALUES"
      "('tenant-a','alpha','file:///alpha','/alpha',1,'tenant-a',1,1),"
      "('tenant-a','beta','file:///beta','/beta',1,'tenant-a',1,1);",
      NULL, NULL, NULL), ==, SQLITE_OK);

  WylFactOfflineRestoreStoreResult result = 0;
  g_auto (WylFactOfflineRestoreJournal) alpha = { 0 };
  g_auto (WylFactOfflineRestoreJournal) alpha_committed = { 0 };
  init_graph_journal (&alpha, OP_C, "alpha");
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &alpha, &result, &alpha_committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  gint invalid_uuid_rc = sqlite3_exec (db,
          "INSERT INTO main.fact_offline_restore_journals SELECT "
          "'-18f22d0-7b6d-7a5b-8c31-123456789abc',tenant_id,scope,"
          "selected_graph_id,revision,manifest_sha256,graph_count,journal_blob,"
          "created_at,updated_at FROM main.fact_offline_restore_journals "
          "WHERE operation_uuid='" OP_C "';", NULL, NULL, NULL);
  g_assert_cmpint (invalid_uuid_rc & 0xff, ==, SQLITE_CONSTRAINT);
  g_assert_cmpint (sqlite3_exec (db,
      "CREATE TEMP VIEW FACT_OFFLINE_RESTORE_JOURNALS AS SELECT * FROM "
      "main.fact_offline_restore_journals;", NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) main_qualified = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_C, &main_qualified), ==, WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (db,
      "DROP VIEW temp.FACT_OFFLINE_RESTORE_JOURNALS;", NULL, NULL, NULL),
      ==, SQLITE_OK);

  g_auto (WylFactOfflineRestoreJournal) beta = { 0 };
  g_auto (WylFactOfflineRestoreJournal) beta_committed = { 0 };
  init_graph_journal (&beta, OP_D, "beta");
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &beta, &result, &beta_committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  GPtrArray *bounded = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, "tenant-a", 1, &bounded), ==, WYRELOG_E_RESOURCE_LIMIT);
  g_assert_null (bounded);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, "tenant-a", 2, &bounded), ==, WYRELOG_E_OK);
  g_assert_cmpuint (bounded->len, ==, 2);
  g_ptr_array_unref (bounded);

  g_auto (WylFactOfflineRestoreJournal) duplicate_alpha = { 0 };
  g_auto (WylFactOfflineRestoreJournal) alpha_winner = { 0 };
  init_graph_journal (&duplicate_alpha, OP_F, "alpha");
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &duplicate_alpha, &result, &alpha_winner), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_cmpstr (alpha_winner.operation_uuid, ==, OP_C);

  g_auto (WylFactOfflineRestoreJournal) tenant = { 0 };
  g_auto (WylFactOfflineRestoreJournal) tenant_winner = { 0 };
  init_journal (&tenant, OP_E);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &tenant, &result, &tenant_winner), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_cmpstr (tenant_winner.operation_uuid, ==, OP_C);

  g_assert_cmpint (sqlite3_exec (db,
      "DROP TRIGGER fact_offline_restore_tenant_claim_insert_guard;"
      "INSERT INTO fact_offline_restore_tenant_claims(tenant_id,operation_uuid)"
      "VALUES('tenant-a','" OP_C "');"
      "CREATE TRIGGER fact_offline_restore_tenant_claim_insert_guard "
      "BEFORE INSERT ON fact_offline_restore_tenant_claims BEGIN SELECT CASE "
      "WHEN NOT EXISTS(SELECT 1 FROM fact_offline_restore_journals WHERE "
      "operation_uuid=NEW.operation_uuid AND tenant_id=NEW.tenant_id AND "
      "scope='tenant' AND selected_graph_id IS NULL) OR EXISTS(SELECT 1 FROM "
      "fact_offline_restore_graph_claims WHERE tenant_id=NEW.tenant_id) THEN "
      "RAISE(ABORT,'invalid tenant restore claim') END; END;",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) overlapped = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_D, &overlapped), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);

  g_autoptr (wyl_policy_store_t) tenant_first = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &tenant_first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (tenant_first), ==,
      WYRELOG_E_OK);
  created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (tenant_first, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (tenant_first),
      "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
      "schema_version,owner_scope,created_at,updated_at) VALUES"
      "('tenant-a','alpha','file:///alpha','/alpha',1,'tenant-a',1,1);",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) tenant_first_journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) tenant_first_committed = { 0 };
  init_journal (&tenant_first_journal, OP_A);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (tenant_first, &tenant_first_journal, &result,
      &tenant_first_committed), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED);
  g_auto (WylFactOfflineRestoreJournal) graph_after_tenant = { 0 };
  g_auto (WylFactOfflineRestoreJournal) tenant_claim_winner = { 0 };
  init_graph_journal (&graph_after_tenant, OP_C, "alpha");
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (tenant_first, &graph_after_tenant, &result, &tenant_claim_winner),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT);
  g_assert_cmpstr (tenant_claim_winner.operation_uuid, ==, OP_A);

  g_autoptr (wyl_policy_store_t) temp_shadow = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &temp_shadow), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (temp_shadow),
      "CREATE TEMP TABLE FACT_OFFLINE_RESTORE_JOURNALS(x);", NULL, NULL,
      NULL), ==, SQLITE_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (temp_shadow), ==,
      WYRELOG_E_POLICY);

  g_autoptr (wyl_policy_store_t) attached_shadow = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &attached_shadow), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (attached_shadow),
      "ATTACH ':memory:' AS hostile; CREATE TABLE "
      "hostile.fact_offline_restore_journals(x);", NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (attached_shadow), ==,
      WYRELOG_E_POLICY);
}

static void
rollback_tamper_and_concurrency (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_exec (db,
      "CREATE TEMP TRIGGER fail_restore_claim BEFORE INSERT ON "
      "fact_offline_restore_tenant_claims BEGIN SELECT RAISE(ABORT,"
      "'injected claim failure'); END;", NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  init_journal (&journal, OP_A);
  WylFactOfflineRestoreStoreResult result = 0;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &journal, &result, &committed), ==, WYRELOG_E_IO);
  g_assert_cmpint (row_count (store, "fact_offline_restore_journals"), ==, 0);
  g_assert_cmpint (row_count (store, "fact_offline_restore_tenant_claims"),
      ==, 0);
  g_assert_cmpint (sqlite3_exec (db, "DROP TRIGGER fail_restore_claim;",
      NULL, NULL, NULL), ==, SQLITE_OK);

  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) complete = { 0 };
  clone_journal (&committed, &complete);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&complete,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) complete_committed = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (store, 1, &complete, &result, &complete_committed), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (db,
      "CREATE TEMP TRIGGER fail_restore_delete BEFORE DELETE ON "
      "fact_offline_restore_journals BEGIN SELECT RAISE(ABORT,"
      "'injected delete failure'); END;", NULL, NULL, NULL), ==, SQLITE_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_release
        (store, 2, OP_A, &result), ==, WYRELOG_E_IO);
  g_assert_cmpint (row_count (store, "fact_offline_restore_journals"), ==, 1);
  g_assert_cmpint (row_count (store, "fact_offline_restore_tenant_claims"),
      ==, 1);
  g_assert_cmpint (sqlite3_exec (db, "DROP TRIGGER fail_restore_delete;",
      NULL, NULL, NULL), ==, SQLITE_OK);

  g_assert_cmpint (sqlite3_exec (db,
      "UPDATE fact_offline_restore_journals SET revision=revision+1,"
      "journal_blob=x'00';", NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) tampered = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_A, &tampered), ==, WYRELOG_E_POLICY);
  g_autoptr (GPtrArray) listed = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, "tenant-a", 4, &listed), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_validate (store),
      ==, WYRELOG_E_POLICY);

  g_autoptr (wyl_policy_store_t) concurrent = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &concurrent), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (concurrent), ==,
      WYRELOG_E_OK);
  created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (concurrent, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (concurrent),
      "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
      "schema_version,owner_scope,created_at,updated_at) VALUES"
      "('tenant-a','alpha','file:///alpha','/alpha',1,'tenant-a',1,1);",
      NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) contender_a = { 0 };
  g_auto (WylFactOfflineRestoreJournal) contender_b = { 0 };
  init_graph_journal (&contender_a, OP_C, "alpha");
  init_graph_journal (&contender_b, OP_D, "alpha");
  CreateThread first = { .store = concurrent, .journal = &contender_a };
  CreateThread second = { .store = concurrent, .journal = &contender_b };
  GThread *first_thread = g_thread_new ("restore-create-a", create_thread,
          &first);
  GThread *second_thread = g_thread_new ("restore-create-b", create_thread,
          &second);
  g_thread_join (first_thread);
  g_thread_join (second_thread);
  g_assert_cmpint (first.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (second.rc, ==, WYRELOG_E_OK);
  g_assert_cmpint ((first.result == WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED)
      + (second.result == WYL_FACT_OFFLINE_RESTORE_STORE_APPLIED), ==, 1);
  g_assert_cmpint ((first.result == WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT)
      + (second.result == WYL_FACT_OFFLINE_RESTORE_STORE_CONFLICT), ==, 1);
  g_assert_cmpuint (first.committed.revision, ==, 1);
  g_assert_cmpuint (second.committed.revision, ==, 1);
  g_assert_cmpstr (first.committed.operation_uuid, ==,
      second.committed.operation_uuid);
  wyl_fact_offline_restore_journal_clear (&first.committed);
  wyl_fact_offline_restore_journal_clear (&second.committed);
}

static void
encrypted_publication_and_reopen (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *directory =
      g_dir_make_tmp ("wyl-restore-store-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (directory);
  g_autofree gchar *store_path =
      g_build_filename (directory, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (directory, "policy.key", NULL);
  g_assert_true (write_policy_key (key_path));

  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  init_journal (&journal, OP_A);
  WylFactOfflineRestoreStoreResult result = 0;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &journal, &result, &committed), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_policy_store_close);

  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) reopened = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_A, &reopened), ==, WYRELOG_E_OK);
  g_assert_cmpuint (reopened.revision, ==, 1);
  g_auto (WylFactOfflineRestoreJournal) desired = { 0 };
  clone_journal (&reopened, &desired);
  g_assert_cmpint (wyl_fact_offline_restore_journal_decide (&desired,
      WYL_FACT_OFFLINE_RESTORE_DECISION_ROLLBACK), ==, WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) updated = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_cas
        (store, 1, &desired, &result, &updated), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_policy_store_close);

  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) reopened_updated = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_A, &reopened_updated), ==, WYRELOG_E_OK);
  g_assert_cmpuint (reopened_updated.revision, ==, 2);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_release
        (store, 2, OP_A, &result), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_policy_store_close);

  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) released = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_A, &released), ==, WYRELOG_E_NOT_FOUND);
  g_auto (WylFactOfflineRestoreJournal) unpublished = { 0 };
  init_journal (&unpublished, OP_B);
  g_auto (WylFactOfflineRestoreJournal) unpublished_result = { 0 };
  wyl_policy_store_graph_authority_migration_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_COORDINATOR_PUBLICATION);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &unpublished, &result, &unpublished_result), ==,
      WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_terminal_result (store), ==,
      WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_B, &released), ==, WYRELOG_E_IO);
  g_autoptr (GPtrArray) poisoned_list = NULL;
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_list
        (store, NULL, 4, &poisoned_list), ==, WYRELOG_E_IO);
  g_clear_pointer (&store, wyl_policy_store_close);

  g_assert_cmpint (open_encrypted_store (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_B, &released), ==, WYRELOG_E_NOT_FOUND);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_test_directory (directory);
}

#ifdef WYL_TEST_HANDLE_SEAMS
static void
encrypted_commit_response_lost (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *directory =
      g_dir_make_tmp ("wyl-restore-commit-ambiguous-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (directory, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (directory, "policy.key", NULL);
  g_assert_true (write_policy_key (key_path));
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_policy_store_close);
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  init_journal (&journal, OP_F);
  WylFactOfflineRestoreStoreResult result = 0;
  wyl_policy_store_offline_restore_fail_once (store,
      WYL_POLICY_OFFLINE_RESTORE_FAIL_COMMIT_RESPONSE);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &journal, &result, &committed), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_terminal_result (store), ==, WYRELOG_E_IO);
  g_auto (WylFactOfflineRestoreJournal) refused = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_F, &refused), ==, WYRELOG_E_IO);
  g_clear_pointer (&store, wyl_policy_store_close);
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_F, &refused), ==, WYRELOG_E_NOT_FOUND);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_test_directory (directory);
}

static void
encrypted_rollback_failure (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *directory =
      g_dir_make_tmp ("wyl-restore-rollback-fail-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *path = g_build_filename (directory, "policy.store", NULL);
  g_autofree gchar *key_path = g_build_filename (directory, "policy.key", NULL);
  g_assert_true (write_policy_key (key_path));
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
        (store, "tenant-a", &created), ==, WYRELOG_E_OK);
  g_clear_pointer (&store, wyl_policy_store_close);
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store),
      "CREATE TEMP TRIGGER fail_restore_claim BEFORE INSERT ON "
      "fact_offline_restore_tenant_claims BEGIN SELECT RAISE(ABORT,"
      "'injected claim failure'); END;", NULL, NULL, NULL), ==, SQLITE_OK);
  g_auto (WylFactOfflineRestoreJournal) journal = { 0 };
  g_auto (WylFactOfflineRestoreJournal) committed = { 0 };
  init_journal (&journal, OP_F);
  WylFactOfflineRestoreStoreResult result = 0;
  wyl_policy_store_offline_restore_fail_once (store,
      WYL_POLICY_OFFLINE_RESTORE_FAIL_ROLLBACK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_create
        (store, &journal, &result, &committed), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_policy_store_terminal_result (store), ==, WYRELOG_E_IO);
  g_auto (WylFactOfflineRestoreJournal) refused = { 0 };
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_F, &refused), ==, WYRELOG_E_IO);
  g_clear_pointer (&store, wyl_policy_store_close);
  g_assert_cmpint (open_encrypted_store (path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_offline_restore_journal_store_load
        (store, OP_F, &refused), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (row_count (store, "fact_offline_restore_tenant_claims"),
      ==, 0);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_test_directory (directory);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/offline-restore-journal-store/contract",
      storage_contract);
  g_test_add_func ("/fact/offline-restore-journal-store/claim-matrix-tamper",
      claim_matrix_and_schema_tamper);
  g_test_add_func ("/fact/offline-restore-journal-store/rollback-concurrency",
      rollback_tamper_and_concurrency);
  g_test_add_func ("/fact/offline-restore-journal-store/encrypted-publication",
      encrypted_publication_and_reopen);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact/offline-restore-journal-store/encrypted-abrupt-exit",
      encrypted_abrupt_exit);
#endif
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_func ("/fact/offline-restore-journal-store/commit-response-lost",
      encrypted_commit_response_lost);
  g_test_add_func ("/fact/offline-restore-journal-store/rollback-failure",
      encrypted_rollback_failure);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}
