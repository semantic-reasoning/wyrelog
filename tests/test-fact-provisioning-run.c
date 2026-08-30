/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <duckdb.h>

#include "fact-test-support.h"
#include "fact/provisioning-construct-private.h"
#include "fact/provisioning-run-private.h"
#include "fact/store-identity-private.h"
#include "fact/store-open-private.h"
#include "fact/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

static const gchar store_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070545";
static const gchar seam_op_uuid[] = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
static const gchar seam_stage_basename[] =
    "provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite";

static void
exec_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
seed_graph (sqlite3 *db, const gchar *tenant_id, const gchar *graph_id)
{
  g_autofree gchar *sql =
      g_strdup_printf
        ("INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
          "VALUES ('%s',0,1,1);" "INSERT INTO fact_graphs "
          "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
          "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
          "('%s','%s','file:///legacy','/legacy',1,'%s',0,1,1,NULL);",
          tenant_id, tenant_id, graph_id, tenant_id);
  exec_ok (db, sql);
}

static WylPolicyGraphProvisioningInput
make_input (const gchar *tenant_id, const gchar *graph_id)
{
  WylPolicyGraphProvisioningInput input = { 0 };
  input.tenant_id = tenant_id;
  input.graph_id = graph_id;
  input.store_uuid = store_uuid;
  input.format_version = 1;
  input.path_encoding_version = 1;
  input.expected_lifecycle_generation = 0;
  input.expected_reconciliation_generation = 0;
  return input;
}

static void
remove_root (const gchar *root)
{
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (root, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_root (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (root);
}

/* Assert the platform provisioning shape.  Linux retains the stage/final
 * nlink-2 pair.  Darwin binds authority to the single-link final with durable
 * operation evidence and requires the legacy stage to remain absent. */
static void
assert_retained_pair (const gchar *root, const gchar *tenant_id,
    const gchar *graph_id, const gchar *stage_basename)
{
  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode (tenant_id,
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode (graph_id,
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  g_autofree gchar *stage_path = g_build_filename (root, tenant_component,
          graph_component, stage_basename, NULL);
  struct stat final_status;
  g_assert_cmpint (stat (final_path, &final_status), ==, 0);
#ifdef __APPLE__
  g_assert_cmpuint (final_status.st_nlink, ==, 1);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_IS_SYMLINK));
#else
  struct stat stage_status;
  g_assert_cmpint (stat (stage_path, &stage_status), ==, 0);
  g_assert_cmpuint (final_status.st_nlink, ==, 2);
  g_assert_cmpuint (final_status.st_ino, ==, stage_status.st_ino);
  g_assert_cmpuint (final_status.st_dev, ==, stage_status.st_dev);
#endif
}

static void
assert_authority_active (wyl_policy_store_t *store, const gchar *tenant_id,
    const gchar *graph_id)
{
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_nonnull (authority);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  g_assert_true (authority->has_store_identity);
  wyl_policy_graph_authority_record_free (authority);
}

/* A fresh graph is reserved, staged, published, verified, and activated in one
 * call: the record reaches ACTIVE, the authority is ACTIVE with a bound
 * identity, and the on-disk store is the retained nlink-2 pair. */
static void
test_run_drives_fresh_graph_to_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-run", "graph-run");

  WylPolicyGraphProvisioningInput input = make_input ("tenant-run", "graph-run");
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
#ifdef __APPLE__
  g_assert_nonnull (record->darwin_operation_evidence);
  g_assert_cmpuint (g_bytes_get_size (record->darwin_operation_evidence), ==,
      WYL_FACT_GRAPH_DARWIN_OPERATION_EVIDENCE_SIZE);
#endif

  assert_retained_pair (root, "tenant-run", "graph-run", record->stage_basename);
  assert_authority_active (store, "tenant-run", "graph-run");

  wyl_policy_graph_provisioning_record_free (record);
  remove_root (root);
}

#ifdef __APPLE__
#ifdef WYL_TEST_HANDLE_SEAMS
static gboolean
write_policy_key (const gchar *path)
{
  guint8 key[32];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (0x51u + i);
  return g_file_set_contents (path, (const gchar *) key, sizeof key, NULL);
}

static wyrelog_error_t
open_encrypted_policy_store (const gchar *path, const gchar *key_path,
    wyl_policy_store_t **out_store)
{
  wyl_keyprovider_file_t *provider = wyl_keyprovider_file_new (key_path);
  if (provider == NULL)
    return WYRELOG_E_IO;
  wyl_policy_store_open_options_t options = {
    .path = path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = provider,
    .keyprovider_state_free =
        (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_open_with_options (&options, out_store);
}

static void
exit_at_darwin_coordinator_checkpoint (
  WylFactGraphDarwinCoordinatorCheckpoint checkpoint, const gchar *op_uuid,
  gpointer user_data)
{
  g_assert_nonnull (op_uuid);
  if (checkpoint == (WylFactGraphDarwinCoordinatorCheckpoint)
      GPOINTER_TO_INT (user_data))
    _Exit (0);
}

static void
assert_authority_for_checkpoint (wyl_policy_store_t *store,
    WylFactGraphDarwinCoordinatorCheckpoint checkpoint)
{
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store,
      "tenant-crash", "graph-crash", &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      checkpoint == WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_ACTIVE_PUBLICATION ?
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE :
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING);
  g_assert_true (authority->has_store_identity);
  g_assert_cmpstr (authority->store_uuid, ==, store_uuid);
  wyl_policy_graph_authority_record_free (authority);
}

static void
test_darwin_encrypted_crash_checkpoints (void)
{
  static const gchar env_store[] = "WYL_TEST_DARWIN_COORDINATOR_STORE";
  static const gchar env_key[] = "WYL_TEST_DARWIN_COORDINATOR_KEY";
  static const gchar env_root[] = "WYL_TEST_DARWIN_COORDINATOR_FACT_ROOT";
  static const gchar env_checkpoint[] =
      "WYL_TEST_DARWIN_COORDINATOR_CHECKPOINT";
  if (g_test_subprocess ()) {
    wyl_policy_store_t *store = NULL;
    if (open_encrypted_policy_store (g_getenv (env_store), g_getenv (env_key),
        &store) != WYRELOG_E_OK)
      _Exit (91);
    gint checkpoint = (gint) g_ascii_strtoll (g_getenv (env_checkpoint), NULL,
            10);
    wyl_fact_graph_darwin_coordinator_set_test_hook (
      exit_at_darwin_coordinator_checkpoint, GINT_TO_POINTER (checkpoint));
    WylPolicyGraphProvisioningInput input = make_input ("tenant-crash",
            "graph-crash");
    (void) wyl_fact_graph_provisioning_run (store, &input,
        g_getenv (env_root), NULL);
    _Exit (92);
  }

  const WylPolicyGraphProvisioningPhase expected_phases[] = {
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_STAGED,
    WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED,
    WYL_POLICY_GRAPH_PROVISIONING_VERIFIED,
    WYL_POLICY_GRAPH_PROVISIONING_ACTIVE,
  };
  for (gint checkpoint =
      WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_RESERVED_PUBLICATION;
      checkpoint <= WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_ACTIVE_PUBLICATION;
      checkpoint++) {
    g_autoptr (GError) error = NULL;
    g_autofree gchar *root = wyl_test_make_secure_fact_root
          ("wyl-fact-provisioning-crash-XXXXXX", &error);
    g_assert_no_error (error);
    g_autofree gchar *fact_root = g_build_filename (root, "facts", NULL);
    g_autofree gchar *policy_path = g_build_filename (root, "policy.enc", NULL);
    g_autofree gchar *key_path = g_build_filename (root, "policy.key", NULL);
    g_assert_cmpint (g_mkdir (fact_root, 0700), ==, 0);
    g_assert_true (write_policy_key (key_path));
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path,
        &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
        WYRELOG_E_OK);
    seed_graph (wyl_policy_store_get_db (store), "tenant-crash",
        "graph-crash");
    g_clear_pointer (&store, wyl_policy_store_close);

    g_autofree gchar *checkpoint_text = g_strdup_printf ("%d", checkpoint);
    g_setenv (env_store, policy_path, TRUE);
    g_setenv (env_key, key_path, TRUE);
    g_setenv (env_root, fact_root, TRUE);
    g_setenv (env_checkpoint, checkpoint_text, TRUE);
    g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
    g_test_trap_assert_passed ();
    g_unsetenv (env_checkpoint);
    g_unsetenv (env_root);
    g_unsetenv (env_key);
    g_unsetenv (env_store);

    g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path,
        &store), ==, WYRELOG_E_OK);
    g_autoptr (GPtrArray) records = NULL;
    g_assert_cmpint (wyl_policy_store_graph_provisioning_list (store,
        "tenant-crash", &records), ==, WYRELOG_E_OK);
    g_assert_cmpuint (records->len, ==, 1);
    WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, 0);
    g_assert_cmpint (record->phase, ==, expected_phases[checkpoint]);
    gboolean evidence_published = checkpoint >=
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_EVIDENCE_PUBLICATION;
    g_assert_cmpint (record->darwin_operation_evidence != NULL, ==,
        evidence_published);
    assert_authority_for_checkpoint (store, checkpoint);

    if (checkpoint ==
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_RESERVED_PUBLICATION) {
      g_autoptr (GDir) directory = g_dir_open (fact_root, 0, &error);
      g_assert_no_error (error);
      g_assert_null (g_dir_read_name (directory));
    } else {
      assert_retained_pair (fact_root, "tenant-crash", "graph-crash",
          record->stage_basename);
    }

    wyrelog_error_t recovery_rc = wyl_fact_graph_provisioning_recover (store,
            record->op_uuid, fact_root, NULL);
    if (checkpoint ==
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_FINAL_CREATION)
      g_assert_cmpint (recovery_rc, ==, WYRELOG_E_POLICY);
    else {
      g_assert_cmpint (recovery_rc, ==, WYRELOG_E_OK);
      assert_authority_active (store, "tenant-crash", "graph-crash");
    }
    g_clear_pointer (&store, wyl_policy_store_close);
    remove_root (root);
  }
}

static void
test_darwin_reserved_publication_failure_is_pre_filesystem (void)
{
  static const gchar env_store[] = "WYL_TEST_DARWIN_PUBLISH_FAIL_STORE";
  static const gchar env_key[] = "WYL_TEST_DARWIN_PUBLISH_FAIL_KEY";
  static const gchar env_root[] = "WYL_TEST_DARWIN_PUBLISH_FAIL_ROOT";
  if (g_test_subprocess ()) {
    wyl_policy_store_t *store = NULL;
    if (open_encrypted_policy_store (g_getenv (env_store), g_getenv (env_key),
        &store) != WYRELOG_E_OK)
      _Exit (93);
    wyl_policy_store_graph_authority_migration_fail_once (store,
        WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_COORDINATOR_PUBLICATION);
    WylPolicyGraphProvisioningInput input = make_input ("tenant-publish-fail",
            "graph-publish-fail");
    wyrelog_error_t rc = wyl_fact_graph_provisioning_run (store, &input,
            g_getenv (env_root), NULL);
    _Exit (rc == WYRELOG_E_IO ? 0 : 94);
  }

  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-publish-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *fact_root = g_build_filename (root, "facts", NULL);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.enc", NULL);
  g_autofree gchar *key_path = g_build_filename (root, "policy.key", NULL);
  g_assert_cmpint (g_mkdir (fact_root, 0700), ==, 0);
  g_assert_true (write_policy_key (key_path));
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path, &store),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-publish-fail",
      "graph-publish-fail");
  g_clear_pointer (&store, wyl_policy_store_close);

  g_setenv (env_store, policy_path, TRUE);
  g_setenv (env_key, key_path, TRUE);
  g_setenv (env_root, fact_root, TRUE);
  g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
  g_test_trap_assert_passed ();
  g_unsetenv (env_root);
  g_unsetenv (env_key);
  g_unsetenv (env_store);

  g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path, &store),
      ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (store,
      "tenant-publish-fail", &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 0);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store,
      "tenant-publish-fail", "graph-publish-fail", &authority), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  wyl_policy_graph_authority_record_free (authority);
  g_autoptr (GDir) directory = g_dir_open (fact_root, 0, &error);
  g_assert_no_error (error);
  g_assert_null (g_dir_read_name (directory));
  g_clear_pointer (&directory, g_dir_close);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_root (root);
}

static void
test_darwin_recover_publishes_prepared_reservation_before_filesystem (void)
{
  static const gchar env_store[] = "WYL_TEST_DARWIN_RECOVER_STORE";
  static const gchar env_key[] = "WYL_TEST_DARWIN_RECOVER_KEY";
  static const gchar env_root[] = "WYL_TEST_DARWIN_RECOVER_FACT_ROOT";
  if (g_test_subprocess ()) {
    wyl_policy_store_t *store = NULL;
    if (open_encrypted_policy_store (g_getenv (env_store), g_getenv (env_key),
        &store) != WYRELOG_E_OK)
      _Exit (95);
    WylPolicyGraphProvisioningInput input = make_input ("tenant-recover",
            "graph-recover");
    WylPolicyGraphProvisioningRecord *record = NULL;
    WylPolicyAuthorityMutationResult mutation;
    if (wyl_policy_store_graph_provisioning_prepare (store, &input, &record,
        &mutation) != WYRELOG_E_OK
        || mutation != WYL_POLICY_AUTHORITY_MUTATION_APPLIED)
      _Exit (96);
    wyl_fact_graph_darwin_coordinator_set_test_hook (
      exit_at_darwin_coordinator_checkpoint,
      GINT_TO_POINTER (
        WYL_FACT_GRAPH_DARWIN_COORDINATOR_AFTER_FINAL_CREATION));
    (void) wyl_fact_graph_provisioning_recover (store, record->op_uuid,
        g_getenv (env_root), NULL);
    _Exit (97);
  }

  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-recover-publish-XXXXXX", &error);
  g_assert_no_error (error);
  g_autofree gchar *fact_root = g_build_filename (root, "facts", NULL);
  g_autofree gchar *policy_path = g_build_filename (root, "policy.enc", NULL);
  g_autofree gchar *key_path = g_build_filename (root, "policy.key", NULL);
  g_assert_cmpint (g_mkdir (fact_root, 0700), ==, 0);
  g_assert_true (write_policy_key (key_path));
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path, &store),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-recover",
      "graph-recover");
  g_clear_pointer (&store, wyl_policy_store_close);

  g_setenv (env_store, policy_path, TRUE);
  g_setenv (env_key, key_path, TRUE);
  g_setenv (env_root, fact_root, TRUE);
  g_test_trap_subprocess (NULL, 30 * G_TIME_SPAN_SECOND, 0);
  g_test_trap_assert_passed ();
  g_unsetenv (env_root);
  g_unsetenv (env_key);
  g_unsetenv (env_store);

  g_assert_cmpint (open_encrypted_policy_store (policy_path, key_path, &store),
      ==, WYRELOG_E_OK);
  g_autoptr (GPtrArray) records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (store,
      "tenant-recover", &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 1);
  WylPolicyGraphProvisioningRecord *record = g_ptr_array_index (records, 0);
  g_assert_cmpint (record->phase, ==,
      WYL_POLICY_GRAPH_PROVISIONING_RESERVED);
  g_assert_null (record->darwin_operation_evidence);
  assert_retained_pair (fact_root, "tenant-recover", "graph-recover",
      record->stage_basename);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store,
      "tenant-recover", "graph-recover", &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING);
  g_assert_true (authority->has_store_identity);
  wyl_policy_graph_authority_record_free (authority);
  g_clear_pointer (&store, wyl_policy_store_close);
  remove_root (root);
}

typedef struct
{
  wyl_policy_store_t *store;
  const gchar *fact_root;
  gboolean fired;
} DarwinConcurrentFinalContext;

static void
publish_concurrent_darwin_final (
  WylFactGraphDarwinCoordinatorCheckpoint checkpoint, const gchar *op_uuid,
  gpointer user_data)
{
  if (checkpoint != WYL_FACT_GRAPH_DARWIN_COORDINATOR_BEFORE_FINAL_CREATION)
    return;
  DarwinConcurrentFinalContext *context = user_data;
  g_assert_false (context->fired);
  context->fired = TRUE;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (context->fact_root, &resolver),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-eexist",
      "graph-eexist"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_create_darwin_provisioned_final
        (&directory, op_uuid, &evidence, &final), ==, WYRELOG_E_OK);
  wyl_fact_graph_regular_file_clear (&final);
  g_autoptr (GBytes) bytes = g_bytes_new (evidence.bytes,
          sizeof evidence.bytes);
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_set_darwin_evidence
        (context->store, op_uuid, bytes, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
}

static void
test_darwin_eexist_uses_fresh_exact_evidence (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-eexist-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-eexist",
      "graph-eexist");
  DarwinConcurrentFinalContext context = {
    .store = store,
    .fact_root = root,
  };
  wyl_fact_graph_darwin_coordinator_set_test_hook (
    publish_concurrent_darwin_final, &context);
  WylPolicyGraphProvisioningInput input = make_input ("tenant-eexist",
          "graph-eexist");
  WylPolicyGraphProvisioningRecord *record = NULL;
  wyrelog_error_t rc = wyl_fact_graph_provisioning_run (store, &input, root,
          &record);
  wyl_fact_graph_darwin_coordinator_set_test_hook (NULL, NULL);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_true (context.fired);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  g_assert_nonnull (record->darwin_operation_evidence);
  assert_retained_pair (root, "tenant-eexist", "graph-eexist",
      record->stage_basename);
  assert_authority_active (store, "tenant-eexist", "graph-eexist");
  wyl_policy_graph_provisioning_record_free (record);
  remove_root (root);
}

static gchar *
prepare_darwin_published_operation (wyl_policy_store_t *store,
    const gchar *fact_root, const gchar *tenant_id, const gchar *graph_id)
{
  seed_graph (wyl_policy_store_get_db (store), tenant_id, graph_id);
  WylPolicyGraphProvisioningInput input = make_input (tenant_id, graph_id);
  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (store, &input,
      &record, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  gchar *op_uuid = g_strdup (record->op_uuid);

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (fact_root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, tenant_id, graph_id),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphDarwinOperationEvidence evidence = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_create_darwin_provisioned_final
        (&directory, op_uuid, &evidence, &final), ==, WYRELOG_E_OK);
  wyl_fact_graph_regular_file_clear (&final);
  g_autoptr (GBytes) bytes = g_bytes_new (evidence.bytes,
          sizeof evidence.bytes);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_set_darwin_evidence
        (store, op_uuid, bytes, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
      op_uuid, WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
      WYL_POLICY_GRAPH_PROVISIONING_STAGED, 0,
      WYL_POLICY_GRAPH_ERROR_NONE, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
      op_uuid, WYL_POLICY_GRAPH_PROVISIONING_STAGED,
      WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED, 0,
      WYL_POLICY_GRAPH_ERROR_NONE, &mutation), ==, WYRELOG_E_OK);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  wyl_policy_graph_provisioning_record_free (record);
  return op_uuid;
}

typedef enum
{
  DARWIN_ATTACK_FINAL,
  DARWIN_ATTACK_GRAPH,
} DarwinCoordinatorAttackKind;

typedef struct
{
  WylFactStorePinnedRendezvous target;
  DarwinCoordinatorAttackKind kind;
  const gchar *graph_path;
  const gchar *final_path;
  gboolean fired;
  gboolean restored;
  gboolean restore_before_r3;
} DarwinCoordinatorAttack;

static void
restore_darwin_coordinator_pair (DarwinCoordinatorAttack *attack)
{
  if (attack->kind == DARWIN_ATTACK_FINAL) {
    g_autofree gchar *saved = g_strconcat (attack->final_path, ".saved", NULL);
    g_assert_cmpint (g_remove (attack->final_path), ==, 0);
    g_assert_cmpint (g_rename (saved, attack->final_path), ==, 0);
  } else {
    g_autofree gchar *saved = g_strconcat (attack->graph_path, ".saved", NULL);
    g_assert_cmpint (g_remove (attack->final_path), ==, 0);
    g_assert_cmpint (g_rmdir (attack->graph_path), ==, 0);
    g_assert_cmpint (g_rename (saved, attack->graph_path), ==, 0);
  }
  attack->restored = TRUE;
}

static void
attack_darwin_coordinator_pair (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  DarwinCoordinatorAttack *attack = user_data;
  gboolean restore_now = attack->fired && !attack->restored
      && ((attack->restore_before_r3
      && rendezvous == WYL_FACT_STORE_PINNED_RENDEZVOUS_R3_POSTIDENTITY)
      || (!attack->restore_before_r3
      && rendezvous == WYL_FACT_STORE_PINNED_RENDEZVOUS_FAILURE_OBSERVED));
  if (restore_now) {
    restore_darwin_coordinator_pair (attack);
    return;
  }
  if (rendezvous != attack->target || attack->fired)
    return;
  attack->fired = TRUE;
  if (attack->kind == DARWIN_ATTACK_FINAL) {
    g_autofree gchar *saved = g_strconcat (attack->final_path, ".saved", NULL);
    g_assert_cmpint (g_rename (attack->final_path, saved), ==, 0);
    g_assert_true (g_file_set_contents (attack->final_path, "decoy", -1,
        NULL));
  } else {
    g_autofree gchar *saved = g_strconcat (attack->graph_path, ".saved", NULL);
    g_assert_cmpint (g_rename (attack->graph_path, saved), ==, 0);
    g_assert_cmpint (g_mkdir (attack->graph_path, 0700), ==, 0);
    g_assert_true (g_file_set_contents (attack->final_path, "decoy", -1,
        NULL));
  }
}

static void
assert_published_authority_unchanged (wyl_policy_store_t *store,
    const gchar *op_uuid, const gchar *tenant_id, const gchar *graph_id)
{
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->phase, ==,
      WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED);
  wyl_policy_graph_provisioning_record_free (record);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, tenant_id,
      graph_id, &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING);
  g_assert_cmpint (authority->last_error_class, ==,
      WYL_POLICY_GRAPH_ERROR_NONE);
  wyl_policy_graph_authority_record_free (authority);
}

static void
test_darwin_internal_provenance_restore_is_nonmutating (void)
{
  const WylFactStorePinnedRendezvous targets[] = {
    WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_POSTREVALIDATE_PRECONSTRUCT,
    WYL_FACT_STORE_PINNED_RENDEZVOUS_INTERNAL_PREIDENTITY,
  };
  for (gsize seam = 0; seam < G_N_ELEMENTS (targets); seam++) {
    for (gint kind = DARWIN_ATTACK_FINAL; kind <= DARWIN_ATTACK_GRAPH; kind++) {
      g_autoptr (GError) error = NULL;
      g_autofree gchar *root = wyl_test_make_secure_fact_root
            ("wyl-fact-provisioning-internal-attack-XXXXXX", &error);
      g_assert_no_error (error);
      g_autoptr (wyl_policy_store_t) store = NULL;
      g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
          WYRELOG_E_OK);
      g_autofree gchar *tenant = g_strdup_printf ("tenant-internal-s%zu-k%d",
              seam, kind);
      g_autofree gchar *graph = g_strdup_printf ("graph-internal-s%zu-k%d",
              seam, kind);
      g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
              root, tenant, graph);
      g_autofree gchar *tenant_component = NULL;
      g_autofree gchar *graph_component = NULL;
      g_assert_cmpint (wyl_fact_graph_component_encode (tenant,
          &tenant_component), ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_component_encode (graph,
          &graph_component), ==, WYRELOG_E_OK);
      g_autofree gchar *graph_path = g_build_filename (root, tenant_component,
              graph_component, NULL);
      g_autofree gchar *final_path = g_build_filename (graph_path,
              "facts.duckdb", NULL);
      DarwinCoordinatorAttack attack = {
        .target = targets[seam],
        .kind = (DarwinCoordinatorAttackKind) kind,
        .graph_path = graph_path,
        .final_path = final_path,
        .restore_before_r3 = seam != 0,
      };
      wyl_fact_store_pinned_set_pair_test_hook_for_test (
        attack_darwin_coordinator_pair, &attack);
      g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid,
          root, NULL), ==, WYRELOG_E_POLICY);
      g_assert_true (attack.fired);
      g_assert_true (attack.restored);
      assert_published_authority_unchanged (store, op_uuid, tenant, graph);
      g_clear_pointer (&store, wyl_policy_store_close);
      remove_root (root);
    }
  }
}

static void
test_darwin_r0_r5_provenance_is_nonmutating (void)
{
  for (gint rendezvous = WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT;
      rendezvous <= WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE;
      rendezvous++) {
    for (gint kind = DARWIN_ATTACK_FINAL; kind <= DARWIN_ATTACK_GRAPH; kind++) {
      g_autoptr (GError) error = NULL;
      g_autofree gchar *root = wyl_test_make_secure_fact_root
            ("wyl-fact-provisioning-attack-XXXXXX", &error);
      g_assert_no_error (error);
      g_autoptr (wyl_policy_store_t) store = NULL;
      g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
          WYRELOG_E_OK);
      g_autofree gchar *tenant = g_strdup_printf ("tenant-r%d-k%d", rendezvous,
              kind);
      g_autofree gchar *graph = g_strdup_printf ("graph-r%d-k%d", rendezvous,
              kind);
      g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
              root, tenant, graph);
      g_autofree gchar *tenant_component = NULL;
      g_autofree gchar *graph_component = NULL;
      g_assert_cmpint (wyl_fact_graph_component_encode (tenant,
          &tenant_component), ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_component_encode (graph,
          &graph_component), ==, WYRELOG_E_OK);
      g_autofree gchar *graph_path = g_build_filename (root, tenant_component,
              graph_component, NULL);
      g_autofree gchar *final_path = g_build_filename (graph_path,
              "facts.duckdb", NULL);
      DarwinCoordinatorAttack attack = {
        .target = (WylFactStorePinnedRendezvous) rendezvous,
        .kind = (DarwinCoordinatorAttackKind) kind,
        .graph_path = graph_path,
        .final_path = final_path,
      };
      wyl_fact_store_pinned_set_pair_test_hook_for_test (
        attack_darwin_coordinator_pair, &attack);
      g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid,
          root, NULL), ==, WYRELOG_E_POLICY);
      g_assert_true (attack.fired);
      g_assert_true (attack.restored);
      assert_published_authority_unchanged (store, op_uuid, tenant, graph);
      g_clear_pointer (&store, wyl_policy_store_close);
      remove_root (root);
    }
  }
}

static void
test_darwin_active_admission_rejects_replacement (void)
{
  for (gint rendezvous = WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT;
      rendezvous <= WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE;
      rendezvous++) {
    for (gint kind = DARWIN_ATTACK_FINAL; kind <= DARWIN_ATTACK_GRAPH; kind++) {
      g_autoptr (GError) error = NULL;
      g_autofree gchar *root = wyl_test_make_secure_fact_root
            ("wyl-fact-provisioning-active-XXXXXX", &error);
      g_assert_no_error (error);
      g_autoptr (wyl_policy_store_t) store = NULL;
      g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
          WYRELOG_E_OK);
      g_autofree gchar *tenant = g_strdup_printf ("tenant-a%d-k%d", rendezvous,
              kind);
      g_autofree gchar *graph = g_strdup_printf ("graph-a%d-k%d", rendezvous,
              kind);
      g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
              root, tenant, graph);
      g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid,
          root, NULL), ==, WYRELOG_E_OK);
      g_autofree gchar *tenant_component = NULL;
      g_autofree gchar *graph_component = NULL;
      g_assert_cmpint (wyl_fact_graph_component_encode (tenant,
          &tenant_component), ==, WYRELOG_E_OK);
      g_assert_cmpint (wyl_fact_graph_component_encode (graph,
          &graph_component), ==, WYRELOG_E_OK);
      g_autofree gchar *graph_path = g_build_filename (root, tenant_component,
              graph_component, NULL);
      g_autofree gchar *final_path = g_build_filename (graph_path,
              "facts.duckdb", NULL);
      DarwinCoordinatorAttack attack = {
        .target = (WylFactStorePinnedRendezvous) rendezvous,
        .kind = (DarwinCoordinatorAttackKind) kind,
        .graph_path = graph_path,
        .final_path = final_path,
      };
      wyl_fact_store_pinned_set_pair_test_hook_for_test (
        attack_darwin_coordinator_pair, &attack);
      g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid,
          root, NULL), ==, WYRELOG_E_POLICY);
      g_assert_true (attack.fired);
      g_assert_true (attack.restored);
      WylPolicyGraphProvisioningRecord *record = NULL;
      g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store,
          op_uuid, &record), ==, WYRELOG_E_OK);
      g_assert_cmpint (record->phase, ==,
          WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
      wyl_policy_graph_provisioning_record_free (record);
      assert_authority_active (store, tenant, graph);
      g_clear_pointer (&store, wyl_policy_store_close);
      remove_root (root);
    }
  }
}

static void
test_darwin_identity_faults_degrade_exactly (void)
{
  for (gint fault = WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE;
      fault <= WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT_AND_ROLLBACK;
      fault++) {
    g_autoptr (GError) error = NULL;
    g_autofree gchar *root = wyl_test_make_secure_fact_root
          ("wyl-fact-provisioning-fault-XXXXXX", &error);
    g_assert_no_error (error);
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
        WYRELOG_E_OK);
    g_autofree gchar *tenant = g_strdup_printf ("tenant-fault-%d", fault);
    g_autofree gchar *graph = g_strdup_printf ("graph-fault-%d", fault);
    g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
            root, tenant, graph);
    wyl_fact_store_identity_set_test_fault (
      (WylFactStoreIdentityTestFault) fault);
    g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
        NULL), !=, WYRELOG_E_OK);
    WylPolicyGraphProvisioningRecord *record = NULL;
    g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
        &record), ==, WYRELOG_E_OK);
    g_assert_cmpint (record->phase, ==,
        WYL_POLICY_GRAPH_PROVISIONING_DEGRADED);
    wyl_policy_graph_provisioning_record_free (record);
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (store, tenant,
        graph, &authority), ==, WYRELOG_E_OK);
    g_assert_cmpint (authority->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED);
    g_assert_cmpint (authority->last_error_class, ==,
        fault == WYL_FACT_STORE_IDENTITY_TEST_FAULT_COMMIT ?
        WYL_POLICY_GRAPH_ERROR_OPEN : WYL_POLICY_GRAPH_ERROR_INTERNAL);
    wyl_policy_graph_authority_record_free (authority);
    g_clear_pointer (&store, wyl_policy_store_close);
    remove_root (root);
  }
}

static void
test_darwin_failed_degradation_is_not_assumed (void)
{
  const WylPolicyGraphAuthorityMutationFailStage stages[] = {
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE,
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (stages); i++) {
    g_autoptr (GError) error = NULL;
    g_autofree gchar *root = wyl_test_make_secure_fact_root
          ("wyl-fact-provisioning-degrade-XXXXXX", &error);
    g_assert_no_error (error);
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
        WYRELOG_E_OK);
    g_autofree gchar *tenant = g_strdup_printf ("tenant-degrade-%zu", i);
    g_autofree gchar *graph = g_strdup_printf ("graph-degrade-%zu", i);
    g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
            root, tenant, graph);
    wyl_fact_store_identity_set_test_fault (
      WYL_FACT_STORE_IDENTITY_TEST_FAULT_AFTER_CREATE);
    wyl_policy_store_graph_authority_mutation_fail_once (store, stages[i]);
    g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
        NULL), ==, WYRELOG_E_IO);
    assert_published_authority_unchanged (store, op_uuid, tenant, graph);
    g_clear_pointer (&store, wyl_policy_store_close);
    remove_root (root);
  }
}

static void
test_darwin_bridge_cleanup_faults_degrade (void)
{
  for (gint seam = 0; seam < 3; seam++) {
    g_autoptr (GError) error = NULL;
    g_autofree gchar *root = wyl_test_make_secure_fact_root
          ("wyl-fact-provisioning-cleanup-XXXXXX", &error);
    g_assert_no_error (error);
    g_autoptr (wyl_policy_store_t) store = NULL;
    g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
        WYRELOG_E_OK);
    g_autofree gchar *tenant = g_strdup_printf ("tenant-cleanup-%d", seam);
    g_autofree gchar *graph = g_strdup_printf ("graph-cleanup-%d", seam);
    g_autofree gchar *op_uuid = prepare_darwin_published_operation (store,
            root, tenant, graph);
    wyl_fact_store_pinned_set_pair_test_stage_errors_for_test (
      seam == 0 ? WYRELOG_E_IO : WYRELOG_E_OK,
      seam == 1 ? WYRELOG_E_IO : WYRELOG_E_OK,
      seam == 2 ? WYRELOG_E_IO : WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
        NULL), ==, WYRELOG_E_IO);
    WylPolicyGraphProvisioningRecord *record = NULL;
    g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
        &record), ==, WYRELOG_E_OK);
    g_assert_cmpint (record->phase, ==,
        WYL_POLICY_GRAPH_PROVISIONING_DEGRADED);
    wyl_policy_graph_provisioning_record_free (record);
    WylPolicyGraphAuthorityRecord *authority = NULL;
    g_assert_cmpint (wyl_policy_store_read_graph_authority (store, tenant,
        graph, &authority), ==, WYRELOG_E_OK);
    g_assert_cmpint (authority->lifecycle_state, ==,
        WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED);
    g_assert_cmpint (authority->last_error_class, ==,
        WYL_POLICY_GRAPH_ERROR_INTERNAL);
    wyl_policy_graph_authority_record_free (authority);
    g_clear_pointer (&store, wyl_policy_store_close);
    remove_root (root);
  }
}
#endif

static void
test_run_refuses_outer_policy_transaction (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-outer", "graph-outer");
  WylPolicyGraphProvisioningInput input = make_input ("tenant-outer",
          "graph-outer");
  exec_ok (db, "BEGIN;");
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root, NULL),
      ==, WYRELOG_E_BUSY);
  exec_ok (db, "ROLLBACK;");

  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store,
      "tenant-outer", "graph-outer", &authority), ==, WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  g_assert_false (authority->has_store_identity);
  wyl_policy_graph_authority_record_free (authority);
  g_autoptr (GPtrArray) records = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_list (store,
      "tenant-outer", &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 0);
  g_autoptr (GDir) directory = g_dir_open (root, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (directory);
  g_assert_null (g_dir_read_name (directory));
  g_clear_pointer (&directory, g_dir_close);
  remove_root (root);
}

static void
test_recover_rejects_malformed_evidence_before_path (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-malformed", "graph-malformed");
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-malformed", "graph-malformed", store_uuid, 1, 1, 0, 0,
      &mutation), ==, WYRELOG_E_OK);
  const gchar *op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070548";
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at,darwin_operation_evidence) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070548','tenant-malformed',"
      "'graph-malformed','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070548.sqlite',1,0,"
      "'reserved',0,1,1,zeroblob(56));");

  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      NULL), ==, WYRELOG_E_POLICY);
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->phase, ==,
      WYL_POLICY_GRAPH_PROVISIONING_RESERVED);
  g_assert_nonnull (record->darwin_operation_evidence);
  wyl_policy_graph_provisioning_record_free (record);
  WylPolicyGraphAuthorityRecord *authority = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store,
      "tenant-malformed", "graph-malformed", &authority), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (authority->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING);
  wyl_policy_graph_authority_record_free (authority);
  g_autoptr (GDir) directory = g_dir_open (root, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (directory);
  g_assert_null (g_dir_read_name (directory));
  g_clear_pointer (&directory, g_dir_close);
  remove_root (root);
}

/* A final created before evidence publication is an intentional wedge.  The
 * coordinator cannot prove provenance, so recovery leaves both filesystem and
 * policy state untouched rather than adopting or deleting the final. */
static void
test_recover_preserves_final_without_evidence_wedge (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-wedge", "graph-wedge");
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-wedge", "graph-wedge", store_uuid, 1, 1, 0, 0, &mutation), ==,
      WYRELOG_E_OK);
  const gchar *op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070547";
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070547','tenant-wedge',"
      "'graph-wedge','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070547.sqlite',1,0,"
      "'reserved',0,1,1);");

  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant-wedge",
      "graph-wedge"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  WylFactGraphDarwinOperationEvidence discarded = { 0 };
  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (wyl_fact_graph_directory_create_darwin_provisioned_final
        (&directory, op_uuid, &discarded, &final), ==, WYRELOG_E_OK);
  struct stat before;
  g_assert_cmpint (fstat (final.fd, &before), ==, 0);
  wyl_fact_graph_regular_file_clear (&final);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);

  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      NULL), ==, WYRELOG_E_POLICY);
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->phase, ==,
      WYL_POLICY_GRAPH_PROVISIONING_RESERVED);
  g_assert_null (record->darwin_operation_evidence);
  wyl_policy_graph_provisioning_record_free (record);

  g_autofree gchar *tenant_component = NULL;
  g_autofree gchar *graph_component = NULL;
  g_assert_cmpint (wyl_fact_graph_component_encode ("tenant-wedge",
      &tenant_component), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_component_encode ("graph-wedge",
      &graph_component), ==, WYRELOG_E_OK);
  g_autofree gchar *final_path = g_build_filename (root, tenant_component,
          graph_component, "facts.duckdb", NULL);
  struct stat after;
  g_assert_cmpint (stat (final_path, &after), ==, 0);
  g_assert_cmpuint (after.st_dev, ==, before.st_dev);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_assert_cmpuint (after.st_size, ==, before.st_size);
  g_assert_cmpuint (after.st_nlink, ==, 1);
  remove_root (root);
}
#endif

/* A second run over an already-active graph never overwrites it: the authority
 * is no longer reservable, so run fails closed with WYRELOG_E_POLICY. */
static void
test_run_rejects_reprovision_of_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-run", "graph-run");

  WylPolicyGraphProvisioningInput input = make_input ("tenant-run", "graph-run");
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      &record), ==, WYRELOG_E_OK);
  wyl_policy_graph_provisioning_record_free (record);

  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root,
      NULL), ==, WYRELOG_E_POLICY);
  assert_authority_active (store, "tenant-run", "graph-run");

  remove_root (root);
}

/* Recovery resumes an operation left at RESERVED (reserved authority + record,
 * no store on disk) and drives it to ACTIVE with the retained pair. */
static void
test_recover_drives_reserved_to_active (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-recover", "graph-recover");

  /* Reserve the authority (PROVISIONING) and stamp a durable reserved record,
   * exactly as a crash after prepare would leave the store. */
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-recover", "graph-recover", store_uuid, 1, 1, 0, 0, &mutation),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  const gchar *op_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070544','tenant-recover',"
      "'graph-recover','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite',1,0,"
      "'reserved',0,1,1);");

  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);

  assert_retained_pair (root, "tenant-recover", "graph-recover",
      record->stage_basename);
  assert_authority_active (store, "tenant-recover", "graph-recover");

  /* Recovery is idempotent: replaying an ACTIVE operation is a no-op success. */
  wyl_policy_graph_provisioning_record_free (record);
  record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, op_uuid, root,
      &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  wyl_policy_graph_provisioning_record_free (record);

  remove_root (root);
}

#ifndef __APPLE__
/* Build the retained pair on disk with committed identity (as a crash after
 * publish/verify would leave it), then stamp a policy provisioning record at
 * |phase_sql| plus its reserved authority.  Recovery must then drive the durable
 * phase forward over the already-published pair to ACTIVE. */
static void
recover_over_published_pair (const gchar *phase_sql)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);

  /* Materialize the S2 pair + identity with the unit-1 construct. */
  WylPolicyGraphProvisioningRecord frecord = { 0 };
  frecord.op_uuid = (gchar *) seam_op_uuid;
  frecord.tenant_id = (gchar *) "tenant-seam";
  frecord.graph_id = (gchar *) "graph-seam";
  frecord.store_uuid = (gchar *) store_uuid;
  frecord.stage_basename = (gchar *) seam_stage_basename;
  frecord.expected_lifecycle_generation = 1;
  frecord.expected_reconciliation_generation = 0;
  frecord.phase = WYL_POLICY_GRAPH_PROVISIONING_RESERVED;
  WylPolicyGraphAuthorityRecord fauthority = { 0 };
  fauthority.tenant_id = (gchar *) "tenant-seam";
  fauthority.graph_id = (gchar *) "graph-seam";
  fauthority.lifecycle_state = WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING;
  fauthority.store_uuid = (gchar *) store_uuid;
  fauthority.format_version = 1;
  fauthority.path_encoding_version = 1;
  fauthority.lifecycle_generation = 1;
  fauthority.reconciliation_generation = 0;
  fauthority.has_store_identity = TRUE;
  g_assert_cmpint (wyl_fact_graph_provisioning_construct (root, &frecord,
      &fauthority), ==, WYRELOG_E_OK);

  /* Stamp the matching policy state: reserved authority + a record whose durable
   * phase trails the on-disk pair. */
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  seed_graph (db, "tenant-seam", "graph-seam");
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-seam", "graph-seam", store_uuid, 1, 1, 0, 0, &mutation), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_autofree gchar *sql = g_strdup_printf (
    "INSERT INTO fact_graph_provisioning "
    "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
    "expected_lifecycle_generation,expected_reconciliation_generation,"
    "phase,attempt,created_at,updated_at) VALUES "
    "('%s','tenant-seam','graph-seam','%s','%s',1,0,'%s',0,1,1);",
    seam_op_uuid, store_uuid, seam_stage_basename, phase_sql);
  exec_ok (db, sql);

  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_fact_graph_provisioning_recover (store, seam_op_uuid,
      root, &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE);
  assert_retained_pair (root, "tenant-seam", "graph-seam",
      record->stage_basename);
  assert_authority_active (store, "tenant-seam", "graph-seam");
  wyl_policy_graph_provisioning_record_free (record);

  remove_root (root);
}

/* Recovery over an already-published pair whose durable phase is PUBLISHED:
 * reopen, verify identity idempotently, then activate. */
static void
test_recover_from_published_pair (void)
{
  recover_over_published_pair ("published");
}

/* Write-behind: the pair is published on disk but the durable phase still trails
 * at STAGED (a crash between publish and the staged->published record).
 * stage_prepare reports the pair as E_POLICY; recovery resumes as published. */
static void
test_recover_from_staged_write_behind (void)
{
  recover_over_published_pair ("staged");
}

/* Recovery over a pair whose durable phase already reached VERIFIED only needs
 * the policy-side activation; the retained pair is untouched. */
static void
test_recover_from_verified (void)
{
  recover_over_published_pair ("verified");
}

static gboolean
run_exec (duckdb_connection conn, const gchar *sql)
{
  duckdb_result result = { 0 };
  duckdb_state state = duckdb_query (conn, sql, &result);
  duckdb_destroy_result (&result);
  return state == DuckDBSuccess;
}

/* The dispatch opens an active graph through the provisioned pair: writes via
 * the live handle persist across close and a fresh dispatch reopen. */
static void
test_open_for_graph_serves_active_graph (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-provisioning-run-XXXXXX", &error);
  g_assert_no_error (error);
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  seed_graph (wyl_policy_store_get_db (store), "tenant-run", "graph-run");
  WylPolicyGraphProvisioningInput input = make_input ("tenant-run", "graph-run");
  g_assert_cmpint (wyl_fact_graph_provisioning_run (store, &input, root, NULL),
      ==, WYRELOG_E_OK);

  wyl_fact_store_t *fact_store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (store, root,
      "tenant-run", "graph-run", TRUE, &fact_store), ==, WYRELOG_E_OK);
  g_assert_nonnull (fact_store);
  g_assert_cmpint (wyl_fact_store_create_schema (fact_store), ==, WYRELOG_E_OK);
  duckdb_connection conn = wyl_fact_store_get_connection (fact_store);
  g_assert_true (run_exec (conn, "CREATE TABLE probe (x INTEGER);"));
  g_assert_true (run_exec (conn, "INSERT INTO probe VALUES (1), (2), (3);"));
  wyl_fact_store_close (fact_store);

  fact_store = NULL;
  g_assert_cmpint (wyl_fact_store_open_provisioned_graph (store, root,
      "tenant-run", "graph-run", FALSE, &fact_store), ==, WYRELOG_E_OK);
  conn = wyl_fact_store_get_connection (fact_store);
  duckdb_result result = { 0 };
  g_assert_cmpint (duckdb_query (conn, "SELECT COUNT(*) FROM probe;", &result),
      ==, DuckDBSuccess);
  g_assert_cmpint (duckdb_value_int64 (&result, 0, 0), ==, 3);
  duckdb_destroy_result (&result);
  wyl_fact_store_close (fact_store);

  remove_root (root);
}
#endif

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/provisioning-run/drives-fresh-graph-to-active",
      test_run_drives_fresh_graph_to_active);
  g_test_add_func ("/fact/provisioning-run/rejects-reprovision-of-active",
      test_run_rejects_reprovision_of_active);
  g_test_add_func ("/fact/provisioning-run/recover-drives-reserved-to-active",
      test_recover_drives_reserved_to_active);
#ifdef __APPLE__
#ifdef WYL_TEST_HANDLE_SEAMS
  g_test_add_func ("/fact/provisioning-run/darwin-encrypted-crash-checkpoints",
      test_darwin_encrypted_crash_checkpoints);
  g_test_add_func ("/fact/provisioning-run/darwin-reserved-publish-failure",
      test_darwin_reserved_publication_failure_is_pre_filesystem);
  g_test_add_func ("/fact/provisioning-run/darwin-recover-publishes-reserved",
      test_darwin_recover_publishes_prepared_reservation_before_filesystem);
  g_test_add_func ("/fact/provisioning-run/darwin-eexist-fresh-evidence",
      test_darwin_eexist_uses_fresh_exact_evidence);
  g_test_add_func ("/fact/provisioning-run/darwin-r0-r5-nonmutating",
      test_darwin_r0_r5_provenance_is_nonmutating);
  g_test_add_func ("/fact/provisioning-run/darwin-internal-provenance-restore",
      test_darwin_internal_provenance_restore_is_nonmutating);
  g_test_add_func ("/fact/provisioning-run/darwin-active-admission",
      test_darwin_active_admission_rejects_replacement);
  g_test_add_func ("/fact/provisioning-run/darwin-identity-faults-degrade",
      test_darwin_identity_faults_degrade_exactly);
  g_test_add_func ("/fact/provisioning-run/darwin-failed-degrade-reread",
      test_darwin_failed_degradation_is_not_assumed);
  g_test_add_func ("/fact/provisioning-run/darwin-cleanup-faults-degrade",
      test_darwin_bridge_cleanup_faults_degrade);
#endif
  g_test_add_func ("/fact/provisioning-run/refuses-outer-policy-transaction",
      test_run_refuses_outer_policy_transaction);
  g_test_add_func ("/fact/provisioning-run/rejects-malformed-before-path",
      test_recover_rejects_malformed_evidence_before_path);
  g_test_add_func ("/fact/provisioning-run/recover-preserves-wedge",
      test_recover_preserves_final_without_evidence_wedge);
#else
  g_test_add_func ("/fact/provisioning-run/recover-from-published-pair",
      test_recover_from_published_pair);
  g_test_add_func ("/fact/provisioning-run/recover-from-staged-write-behind",
      test_recover_from_staged_write_behind);
  g_test_add_func ("/fact/provisioning-run/recover-from-verified",
      test_recover_from_verified);
  g_test_add_func ("/fact/provisioning-run/open-for-graph-serves-active-graph",
      test_open_for_graph_serves_active_graph);
#endif
  return g_test_run ();
}
