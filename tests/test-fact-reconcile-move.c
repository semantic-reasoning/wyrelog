/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fact-test-support.h"
#include "wyrelog/fact/graph-locator-private.h"
#include "wyrelog/fact/reconcile-move-private.h"
#include "wyrelog/policy/store-private.h"

#define MOVE_TENANT "tenant-journal"
#define MOVE_GRAPH "graph-journal"
#define MOVE_OP "01890f47-3c4b-7cc2-b8c4-dc0c0c073990"
#define MOVE_STORE_UUID "01890f47-3c4b-7cc2-b8c4-dc0c0c073991"
#define MOVE_SOURCE_BASENAME "legacy.duckdb"
#define MOVE_FINAL_BASENAME "facts.duckdb"

/* SHA-256 of the three bytes "abc" (FIPS-180 test vector). */
static const guint8 sha256_abc[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

static gchar *
make_root (void)
{
  g_autoptr (GError) error = NULL;
  gchar *root = wyl_test_make_secure_fact_root ("wyl-reconcile-move-XXXXXX",
      &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  return root;
}

static gchar *
write_secure_file (const gchar *root, const gchar *name, const gchar *bytes,
    gssize length)
{
  gchar *path = g_build_filename (root, name, NULL);
  g_assert_true (g_file_set_contents (path, bytes, length, NULL));
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (path, &error));
  g_assert_no_error (error);
  return path;
}

static gint
open_regular (const gchar *path)
{
  gint fd = open (path, O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (fd, >=, 0);
  return fd;
}

static void
test_capture_known_vector (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *path = write_secure_file (root, "abc.bin", "abc", 3);
  gint fd = open_regular (path);

  struct stat st;
  g_assert_cmpint (fstat (fd, &st), ==, 0);

  WylPolicyFactReconcileArtifactEvidence evidence;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd,
          &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpuint (evidence.version, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1);
  g_assert_cmpint (evidence.identity_kind, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_POSIX);
  g_assert_cmpuint (evidence.posix_device, ==, (guint64) st.st_dev);
  g_assert_cmpuint (evidence.posix_inode, ==, (guint64) st.st_ino);
  g_assert_cmpuint (evidence.size_bytes, ==, 3);
  g_assert_cmpint (evidence.digest_algorithm, ==,
      WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256);
  g_assert_cmpmem (evidence.digest, sizeof evidence.digest, sha256_abc,
      sizeof sha256_abc);
  g_assert_cmpuint (evidence.windows_volume_serial, ==, 0);

  g_assert_cmpint (close (fd), ==, 0);
  (void) g_remove (path);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

static void
test_capture_reproduces_across_inodes (void)
{
  g_autofree gchar *root = make_root ();
  g_autofree gchar *path_a = write_secure_file (root, "a.bin",
      "duckdb-payload", -1);
  g_autofree gchar *path_b = write_secure_file (root, "b.bin",
      "duckdb-payload", -1);
  gint fd_a = open_regular (path_a);
  gint fd_b = open_regular (path_b);

  WylPolicyFactReconcileArtifactEvidence ev_a;
  WylPolicyFactReconcileArtifactEvidence ev_b;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd_a, &ev_a),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd_b, &ev_b),
      ==, WYRELOG_E_OK);

  /* Different inodes, identical bytes: size and digest reproduce exactly. */
  g_assert_cmpuint (ev_a.posix_inode, !=, ev_b.posix_inode);
  g_assert_cmpuint (ev_a.size_bytes, ==, ev_b.size_bytes);
  g_assert_cmpmem (ev_a.digest, sizeof ev_a.digest, ev_b.digest,
      sizeof ev_b.digest);

  g_assert_cmpint (close (fd_a), ==, 0);
  g_assert_cmpint (close (fd_b), ==, 0);
  (void) g_remove (path_a);
  (void) g_remove (path_b);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

static void
test_capture_rejects_bad_input (void)
{
  WylPolicyFactReconcileArtifactEvidence evidence;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (-1,
          &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (0, NULL), ==,
      WYRELOG_E_INVALID);

  g_autofree gchar *root = make_root ();
  gint dir_fd = open (root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  g_assert_cmpint (dir_fd, >=, 0);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (dir_fd,
          &evidence), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (close (dir_fd), ==, 0);
  g_assert_true (wyl_test_remove_empty_directory (root, NULL));
}

typedef struct
{
  gchar *root;
  gchar *tenant_component;
  gchar *graph_component;
  gchar *graph_dir;
  gchar *source_abs;
  gchar *final_abs;
  gchar *source_rel;
  gchar *canonical_rel;
  wyl_policy_store_t *store;
  WylPolicyFactReconcileArtifactEvidence source_ev;
} MoveFixture;

static void
insert_graph (sqlite3 *db, const gchar *tenant_id, const gchar *graph_id)
{
  g_autofree gchar *sql = g_strdup_printf
      ("INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('%s',0,1,1);" "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
      "('%s','%s','file:///legacy','/legacy',1,'%s',0,1,1,NULL);", tenant_id,
      tenant_id, graph_id, tenant_id);
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
remove_directory_files (const gchar *path)
{
  GDir *dir = g_dir_open (path, 0, NULL);
  if (dir == NULL)
    return;
  const gchar *name;
  while ((name = g_dir_read_name (dir)) != NULL) {
    g_autofree gchar *child = g_build_filename (path, name, NULL);
    (void) g_remove (child);
  }
  g_dir_close (dir);
}

static void
move_fixture_setup (MoveFixture *fx, const gchar *payload, gssize payload_len)
{
  memset (fx, 0, sizeof *fx);
  fx->root = make_root ();

  WylFactGraphLocator locator = { 0 };
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, MOVE_TENANT,
          MOVE_GRAPH), ==, WYRELOG_E_OK);
  fx->tenant_component = g_strdup (locator.tenant_component);
  fx->graph_component = g_strdup (locator.graph_component);
  wyl_fact_graph_locator_clear (&locator);

  g_autoptr (GError) error = NULL;
  g_autofree gchar *tenant_dir = g_build_filename (fx->root,
      fx->tenant_component, NULL);
  g_assert_true (wyl_test_create_secure_directory (tenant_dir, &error));
  g_assert_no_error (error);
  fx->graph_dir = g_build_filename (tenant_dir, fx->graph_component, NULL);
  g_assert_true (wyl_test_create_secure_directory (fx->graph_dir, &error));
  g_assert_no_error (error);

  fx->source_abs = g_build_filename (fx->graph_dir, MOVE_SOURCE_BASENAME, NULL);
  g_assert_true (g_file_set_contents (fx->source_abs, payload, payload_len,
          NULL));
  g_assert_true (wyl_test_secure_regular_file (fx->source_abs, &error));
  g_assert_no_error (error);

  fx->final_abs = g_build_filename (fx->graph_dir, MOVE_FINAL_BASENAME, NULL);
  fx->source_rel = g_build_filename (fx->tenant_component, fx->graph_component,
      MOVE_SOURCE_BASENAME, NULL);
  fx->canonical_rel = g_build_filename (fx->tenant_component,
      fx->graph_component, MOVE_FINAL_BASENAME, NULL);

  gint fd = open_regular (fx->source_abs);
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd,
          &fx->source_ev), ==, WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);

  g_assert_cmpint (wyl_policy_store_open (NULL, &fx->store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (fx->store), ==,
      WYRELOG_E_OK);
  insert_graph (wyl_policy_store_get_db (fx->store), MOVE_TENANT, MOVE_GRAPH);
}

static void
move_fixture_seed_moving (MoveFixture *fx)
{
  WylPolicyFactReconcileJournalInput input = {
    MOVE_OP, MOVE_TENANT, MOVE_GRAPH, 0, 0, 1, 1, MOVE_STORE_UUID,
    fx->source_rel, fx->canonical_rel, fx->source_ev
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (fx->store,
          &input, &record, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  wyl_policy_fact_reconcile_journal_record_free (record);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (fx->store,
          MOVE_OP, WYL_POLICY_FACT_RECONCILE_PREPARED,
          WYL_POLICY_FACT_RECONCILE_MOVING, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
}

static void
move_fixture_teardown (MoveFixture *fx)
{
  g_clear_pointer (&fx->store, wyl_policy_store_close);
  remove_directory_files (fx->graph_dir);
  g_autofree gchar *tenant_dir = g_build_filename (fx->root,
      fx->tenant_component, NULL);
  (void) wyl_test_remove_empty_directory (fx->graph_dir, NULL);
  (void) wyl_test_remove_empty_directory (tenant_dir, NULL);
  (void) wyl_test_remove_empty_directory (fx->root, NULL);
  g_free (fx->root);
  g_free (fx->tenant_component);
  g_free (fx->graph_component);
  g_free (fx->graph_dir);
  g_free (fx->source_abs);
  g_free (fx->final_abs);
  g_free (fx->source_rel);
  g_free (fx->canonical_rel);
}

static WylFactReconcileMoveContext
move_context (const MoveFixture *fx)
{
  WylFactReconcileMoveContext ctx = {
    .fact_root = fx->root,
    .store = fx->store,
    .tenant_id = MOVE_TENANT,
    .graph_id = MOVE_GRAPH,
    .op_uuid = MOVE_OP,
  };
  return ctx;
}

static void
assert_journal_state (wyl_policy_store_t *store,
    WylPolicyFactReconcileJournalState expected)
{
  WylPolicyFactReconcileJournalRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_read (store, MOVE_OP,
          &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->state, ==, expected);
  wyl_policy_fact_reconcile_journal_record_free (record);
}

static void
assert_final_matches_source (const MoveFixture *fx)
{
  g_assert_true (g_file_test (fx->final_abs, G_FILE_TEST_IS_REGULAR));
  gint fd = open_regular (fx->final_abs);
  WylPolicyFactReconcileArtifactEvidence ev;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd, &ev), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);
  g_assert_cmpuint (ev.size_bytes, ==, fx->source_ev.size_bytes);
  g_assert_cmpmem (ev.digest, sizeof ev.digest, fx->source_ev.digest,
      sizeof fx->source_ev.digest);
}

static void
test_move_publish_happy_path (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome =
      WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_APPLIED);

  assert_final_matches_source (&fx);
  /* The source is copied, never removed. */
  g_assert_true (g_file_test (fx.source_abs, G_FILE_TEST_IS_REGULAR));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);

  move_fixture_teardown (&fx);
}

static void
test_move_publish_idempotent_replay (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome =
      WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_APPLIED);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);

  /* Re-running the terminal state is a no-op replay, not an error. */
  outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);
  assert_final_matches_source (&fx);

  move_fixture_teardown (&fx);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/reconcile-move/capture/known-vector",
      test_capture_known_vector);
  g_test_add_func ("/fact/reconcile-move/capture/reproduces-across-inodes",
      test_capture_reproduces_across_inodes);
  g_test_add_func ("/fact/reconcile-move/capture/rejects-bad-input",
      test_capture_rejects_bad_input);
  g_test_add_func ("/fact/reconcile-move/publish/happy-path",
      test_move_publish_happy_path);
  g_test_add_func ("/fact/reconcile-move/publish/idempotent-replay",
      test_move_publish_idempotent_replay);
  return g_test_run ();
}
