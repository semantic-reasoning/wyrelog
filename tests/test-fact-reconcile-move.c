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
#include "wyrelog/fact/root-writer-lease-private.h"
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
move_fixture_seed_moving_canonical (MoveFixture *fx, const gchar *canonical_rel)
{
  WylPolicyFactReconcileJournalInput input = {
    MOVE_OP, MOVE_TENANT, MOVE_GRAPH, 0, 0, 1, 1, MOVE_STORE_UUID,
    fx->source_rel, canonical_rel, fx->source_ev
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
move_fixture_seed_moving (MoveFixture *fx)
{
  move_fixture_seed_moving_canonical (fx, fx->canonical_rel);
}

/* Seed a MOVING record whose expected authority generations are |life_gen|
 * and |recon_gen|.  The prepare path stores the expected generations verbatim
 * and does not couple them to the graph's current generation, so a record can
 * be bound to a generation the graph no longer sits at. */
static void
move_fixture_seed_moving_generations (MoveFixture *fx, guint64 life_gen,
    guint64 recon_gen)
{
  WylPolicyFactReconcileJournalInput input = {
    MOVE_OP, MOVE_TENANT, MOVE_GRAPH, life_gen, recon_gen, 1, 1,
    MOVE_STORE_UUID, fx->source_rel, fx->canonical_rel, fx->source_ev
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
move_fixture_exec_sql (MoveFixture *fx, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (wyl_policy_store_get_db (fx->store), sql, NULL, NULL,
      &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
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

typedef struct
{
  const gchar *point;
  guint fired;
  wyrelog_error_t rc;
} CheckpointFault;

static wyrelog_error_t
fault_at_point (const gchar *point, gpointer user_data)
{
  CheckpointFault *fault = user_data;
  if (g_strcmp0 (point, fault->point) == 0) {
    fault->fired++;
    return fault->rc;
  }
  return WYRELOG_E_OK;
}

/*
 * Publish-then-CAS crux.  stage_create yields a non-exact stage whose publish
 * fires "stage-linked" then "stage-unlinked"; the latter fires after the
 * final is linked and the parent directory fsync'd, i.e. after the target is
 * durable.  Faulting there makes publish report failure with the target
 * present and the journal still MOVING; a clean re-run must converge on the
 * durable target with a CAS only.  (There is no "stage-parent-synced" point
 * on the non-exact path; that point belongs to the exact-provisioning path.)
 */
static void
test_move_publish_crux_target_durable_before_cas (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  CheckpointFault fault = {.point = "stage-unlinked",.fired = 0,.rc =
        WYRELOG_E_IO
  };
  WylFactReconcileMoveContext ctx = move_context (&fx);
  ctx.checkpoint = fault_at_point;
  ctx.checkpoint_data = &fault;

  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_IO);
  g_assert_cmpuint (fault.fired, ==, 1);
  /* Target is durable, journal has not advanced past MOVING. */
  assert_final_matches_source (&fx);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  WylFactReconcileMoveContext clean = move_context (&fx);
  outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&clean, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);
  assert_final_matches_source (&fx);

  move_fixture_teardown (&fx);
}

/* Interruption before any copy/publish: the move unit's own "source-verified"
 * point fires after the source is re-verified but before staging.  Faulting
 * there leaves no target and the journal at MOVING; a clean re-run applies. */
static void
test_move_publish_interrupt_before_copy (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  CheckpointFault fault = {.point = "source-verified",.fired = 0,.rc =
        WYRELOG_E_IO
  };
  WylFactReconcileMoveContext ctx = move_context (&fx);
  ctx.checkpoint = fault_at_point;
  ctx.checkpoint_data = &fault;

  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_IO);
  g_assert_cmpuint (fault.fired, ==, 1);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  WylFactReconcileMoveContext clean = move_context (&fx);
  outcome = WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&clean, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_APPLIED);
  assert_final_matches_source (&fx);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);

  move_fixture_teardown (&fx);
}

static void
test_move_publish_lease_contention (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  g_autoptr (WylFactRootWriterLease) held = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (fx.root, &held), ==,
      WYRELOG_E_OK);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_BUSY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/* Caller tenant identity must match the journal record before any fs work. */
static void
test_move_publish_tenant_mismatch (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  ctx.tenant_id = "tenant-other";
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/*
 * Basename authority: the publish name is the fixed "facts.duckdb".  A record
 * whose canonical path names a different basename in the correct graph dir is
 * accepted by the journal (which validates only path shape) but must be
 * rejected by the move phase, publishing nothing under either name.
 */
static void
test_move_publish_rejects_foreign_basename (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  g_autofree gchar *evil_rel = g_build_filename (fx.tenant_component,
      fx.graph_component, "evil.duckdb", NULL);
  move_fixture_seed_moving_canonical (&fx, evil_rel);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);

  g_autofree gchar *evil_abs = g_build_filename (fx.graph_dir, "evil.duckdb",
      NULL);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (evil_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/*
 * Copy-path source identity gate.  The recorded evidence pins the source
 * file's POSIX device+inode as well as its size+digest.  Re-creating the
 * source at a fresh inode with byte-identical content keeps the digest+size
 * pre-check happy but must still be rejected by the full evidence_equal
 * identity comparison, publishing nothing.
 */
static void
test_move_publish_source_identity_mismatch (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  /* Replace the source with a fresh inode holding identical bytes: create a
   * sibling then atomically rename it over the recorded source name. */
  g_autoptr (GError) error = NULL;
  g_autofree gchar *replacement = g_build_filename (fx.graph_dir,
      "legacy.new", NULL);
  g_assert_true (g_file_set_contents (replacement, "duckdb-artifact-payload",
          -1, NULL));
  g_assert_true (wyl_test_secure_regular_file (replacement, &error));
  g_assert_no_error (error);
  g_assert_cmpint (g_rename (replacement, fx.source_abs), ==, 0);

  /* Prove the digest+size still match but the inode identity changed. */
  gint fd = open_regular (fx.source_abs);
  WylPolicyFactReconcileArtifactEvidence fresh;
  g_assert_cmpint (wyl_fact_reconcile_capture_artifact_evidence (fd, &fresh),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (close (fd), ==, 0);
  g_assert_cmpuint (fresh.size_bytes, ==, fx.source_ev.size_bytes);
  g_assert_cmpmem (fresh.digest, sizeof fresh.digest, fx.source_ev.digest,
      sizeof fx.source_ev.digest);
  g_assert_cmpuint (fresh.posix_inode, !=, fx.source_ev.posix_inode);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/*
 * Authority-generation gate.  The graph authority sits at generation (0,0); a
 * record bound to a later generation is stale and must be rejected before any
 * filesystem work, leaving the journal at MOVING for a later legitimate run.
 */
static void
test_move_publish_rejects_generation_drift (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving_generations (&fx, 3, 5);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/*
 * Tenant existence gate.  The graph generations still agree, but the owning
 * tenant row is gone: the move must fail closed with E_POLICY and publish
 * nothing.  Foreign keys are relaxed only to remove the tenant while keeping
 * the graph row, reproducing the inconsistent state the defense-in-depth gate
 * guards against.
 */
static void
test_move_publish_rejects_missing_tenant (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  move_fixture_exec_sql (&fx, "PRAGMA foreign_keys=OFF;"
      "DELETE FROM tenants WHERE tenant_id='" MOVE_TENANT "';"
      "PRAGMA foreign_keys=ON;");

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

typedef struct
{
  const gchar *point;
  MoveFixture *fx;
  guint fired;
  gchar *aside;
} RootSwapFault;

static wyrelog_error_t
swap_root_at_point (const gchar *point, gpointer user_data)
{
  RootSwapFault *swap = user_data;
  if (g_strcmp0 (point, swap->point) == 0 && swap->fired == 0) {
    swap->fired++;
    /* Move the entire root aside and stand up a fresh secure directory at the
     * same path.  The resolver's pinned root inode no longer matches, so the
     * next lease reassert must fail closed. */
    g_assert_cmpint (g_rename (swap->fx->root, swap->aside), ==, 0);
    g_assert_true (wyl_test_create_secure_directory (swap->fx->root, NULL));
  }
  return WYRELOG_E_OK;
}

/*
 * Repeated revalidation.  A root-directory inode swap injected mid-flight (at
 * the unit's "source-verified" seam, before staging) must be caught by the
 * next lease reassert: the move fails closed with E_POLICY, publishes nothing
 * and leaves the journal MOVING with the source intact.  Restoring the real
 * root and replaying then converges.
 */
static void
test_move_publish_rejects_root_identity_drift (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  g_autofree gchar *aside = g_strconcat (fx.root, ".aside", NULL);
  RootSwapFault swap = {.point = "source-verified",.fx = &fx,.fired = 0,
    .aside = aside
  };
  WylFactReconcileMoveContext ctx = move_context (&fx);
  ctx.checkpoint = swap_root_at_point;
  ctx.checkpoint_data = &swap;

  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpuint (swap.fired, ==, 1);

  /* Restore the real root: drop the decoy and rename the aside copy back. */
  g_assert_true (wyl_test_remove_empty_directory (fx.root, NULL));
  g_assert_cmpint (g_rename (aside, fx.root), ==, 0);

  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_test (fx.source_abs, G_FILE_TEST_IS_REGULAR));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  WylFactReconcileMoveContext clean = move_context (&fx);
  outcome = WYL_FACT_RECONCILE_MOVE_UNCHANGED_REPLAY;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&clean, &outcome), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (outcome, ==, WYL_FACT_RECONCILE_MOVE_APPLIED);
  assert_final_matches_source (&fx);
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVED);

  move_fixture_teardown (&fx);
}

/* A record that has not reached MOVING must not authorize the move phase. */
static void
test_move_publish_rejects_prepared_state (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  /* Prepare only; leave the record in PREPARED (do not transition). */
  WylPolicyFactReconcileJournalInput input = {
    MOVE_OP, MOVE_TENANT, MOVE_GRAPH, 0, 0, 1, 1, MOVE_STORE_UUID,
    fx.source_rel, fx.canonical_rel, fx.source_ev
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (fx.store,
          &input, &record, &result), ==, WYRELOG_E_OK);
  wyl_policy_fact_reconcile_journal_record_free (record);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_PREPARED);

  move_fixture_teardown (&fx);
}

/*
 * Malformed arguments fail closed with E_INVALID and never touch the store or
 * filesystem.  (The move unit also carries a defense-in-depth evidence
 * validity guard, but the journal is immutable-by-trigger and its read path
 * already validates the V1 evidence contract, so a MOVING record with invalid
 * evidence cannot be constructed through the store to exercise that guard
 * directly.)
 */
static void
test_move_publish_rejects_invalid_arguments (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;

  g_assert_cmpint (wyl_fact_reconcile_move_publish (NULL, &outcome), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, NULL), ==,
      WYRELOG_E_INVALID);

  WylFactReconcileMoveContext no_store = ctx;
  no_store.store = NULL;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&no_store, &outcome), ==,
      WYRELOG_E_INVALID);

  WylFactReconcileMoveContext no_root = ctx;
  no_root.fact_root = NULL;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&no_root, &outcome), ==,
      WYRELOG_E_INVALID);

  WylFactReconcileMoveContext no_op = ctx;
  no_op.op_uuid = NULL;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&no_op, &outcome), ==,
      WYRELOG_E_INVALID);

  /* No filesystem work and no journal advance on any rejected call. */
  g_assert_false (g_file_test (fx.final_abs, G_FILE_TEST_EXISTS));
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

  move_fixture_teardown (&fx);
}

/*
 * Collision with an unknown artifact.  A pre-existing, secure facts.duckdb
 * whose content differs from the recorded source must never be overwritten;
 * the move fails closed and the journal stays MOVING.  (Source and target
 * share one graph directory, so a same-directory link can never cross
 * devices; this collision case stands in for cross-device failure.)
 */
static void
test_move_publish_rejects_unknown_target (void)
{
  MoveFixture fx;
  move_fixture_setup (&fx, "duckdb-artifact-payload", -1);
  move_fixture_seed_moving (&fx);

  g_assert_true (g_file_set_contents (fx.final_abs, "foreign-artifact", -1,
          NULL));
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_secure_regular_file (fx.final_abs, &error));
  g_assert_no_error (error);

  WylFactReconcileMoveContext ctx = move_context (&fx);
  WylFactReconcileMoveOutcome outcome = WYL_FACT_RECONCILE_MOVE_APPLIED;
  g_assert_cmpint (wyl_fact_reconcile_move_publish (&ctx, &outcome), ==,
      WYRELOG_E_POLICY);

  /* The foreign artifact is untouched and the journal is unchanged. */
  g_autofree gchar *contents = NULL;
  g_assert_true (g_file_get_contents (fx.final_abs, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, "foreign-artifact");
  assert_journal_state (fx.store, WYL_POLICY_FACT_RECONCILE_MOVING);

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
  g_test_add_func
      ("/fact/reconcile-move/publish/crux-target-durable-before-cas",
      test_move_publish_crux_target_durable_before_cas);
  g_test_add_func ("/fact/reconcile-move/publish/interrupt-before-copy",
      test_move_publish_interrupt_before_copy);
  g_test_add_func ("/fact/reconcile-move/publish/lease-contention",
      test_move_publish_lease_contention);
  g_test_add_func ("/fact/reconcile-move/publish/tenant-mismatch",
      test_move_publish_tenant_mismatch);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-foreign-basename",
      test_move_publish_rejects_foreign_basename);
  g_test_add_func ("/fact/reconcile-move/publish/source-identity-mismatch",
      test_move_publish_source_identity_mismatch);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-generation-drift",
      test_move_publish_rejects_generation_drift);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-missing-tenant",
      test_move_publish_rejects_missing_tenant);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-root-identity-drift",
      test_move_publish_rejects_root_identity_drift);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-prepared-state",
      test_move_publish_rejects_prepared_state);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-invalid-arguments",
      test_move_publish_rejects_invalid_arguments);
  g_test_add_func ("/fact/reconcile-move/publish/rejects-unknown-target",
      test_move_publish_rejects_unknown_target);
  return g_test_run ();
}
