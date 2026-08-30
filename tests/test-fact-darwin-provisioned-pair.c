/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _DARWIN_C_SOURCE

#include <glib.h>
#include <glib/gstdio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fact/graph-locator-private.h"
#include "fact/store-identity-types-private.h"

G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
  (WylFactGraphProvisionedPair * pair, WylFactArtifactNamespace ** out);

static const gchar operation_uuid[] =
    "01890f47-3c4b-7cc2-b8c4-dc0c0c070544";
static const WylFactStoreIdentity identity = {
  "tenant",
  "graph",
  "01890f47-3c4b-7cc2-b8c4-dc0c0c073989",
  1,
  1,
};

typedef struct
{
  gchar *root;
  gchar *graph_path;
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory graph;
  WylFactGraphDarwinOperationEvidence evidence;
  WylFactGraphProvisionedPair *pair;
} DarwinPairFixture;

static gint
compare_names (gconstpointer left, gconstpointer right)
{
  return g_strcmp0 (*(gchar * const *) left, *(gchar * const *) right);
}

static GPtrArray *
snapshot_names (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GDir) directory = g_dir_open (path, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (directory);
  GPtrArray *names = g_ptr_array_new_with_free_func (g_free);
  const gchar *name;
  while ((name = g_dir_read_name (directory)) != NULL)
    g_ptr_array_add (names, g_strdup (name));
  g_ptr_array_sort (names, compare_names);
  return names;
}

static void
assert_names_equal (GPtrArray *left, GPtrArray *right)
{
  g_assert_cmpuint (left->len, ==, right->len);
  for (guint i = 0; i < left->len; i++)
    g_assert_cmpstr (g_ptr_array_index (left, i), ==,
        g_ptr_array_index (right, i));
}

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static DarwinPairFixture
fixture_create (void)
{
  DarwinPairFixture fixture = {
    .resolver = WYL_FACT_GRAPH_RESOLVER_INIT,
    .graph = WYL_FACT_GRAPH_DIRECTORY_INIT,
  };
  g_autoptr (GError) error = NULL;
  g_autofree gchar *created =
      g_dir_make_tmp ("wyl-darwin-pair-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (created);
  fixture.root = realpath (created, NULL);
  if (fixture.root == NULL) {
    gint saved_errno = errno;
    (void) g_rmdir (created);
    g_set_error (&error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
        "Failed to resolve temporary directory '%s': %s", created,
        g_strerror (saved_errno));
  }
  g_assert_no_error (error);
  g_assert_nonnull (fixture.root);
  g_assert_cmpint (g_chmod (fixture.root, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture.root,
      &fixture.resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture.locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture.resolver,
      &fixture.locator, TRUE, &fixture.graph), ==, WYRELOG_E_OK);
  fixture.graph_path =
      wyl_fact_graph_directory_descriptive_path (&fixture.graph);
  g_assert_nonnull (fixture.graph_path);

  WylFactGraphRegularFile final = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  g_assert_cmpint (
    wyl_fact_graph_directory_create_darwin_provisioned_final (&fixture.graph,
    operation_uuid, &fixture.evidence, &final), ==, WYRELOG_E_OK);
  struct stat status;
  g_assert_cmpint (fstat (final.fd, &status), ==, 0);
  g_assert_cmpuint (status.st_nlink, ==, 1);
  wyl_fact_graph_regular_file_clear (&final);

  WylFactGraphProvisionedPair *neutral = NULL;
  g_assert_cmpint (wyl_fact_graph_directory_open_provisioned_pair_exact
        (&fixture.graph, operation_uuid, &neutral), ==, WYRELOG_E_POLICY);
  g_assert_null (neutral);
  WylFactGraphDarwinOperationEvidence foreign_evidence = fixture.evidence;
  for (guint64 candidate = 1; candidate <= 3; candidate++) {
    guint64 encoded = GUINT64_TO_BE (candidate);
    if (memcmp (&encoded, foreign_evidence.bytes + 40, sizeof encoded) != 0
        && memcmp (&encoded, fixture.evidence.bytes + 48,
        sizeof encoded) != 0) {
      memcpy (foreign_evidence.bytes + 48, &encoded, sizeof encoded);
      break;
    }
  }
  WylFactGraphDarwinOperationEvidence decoded = { 0 };
  g_assert_cmpint (wyl_fact_graph_darwin_evidence_decode
        (foreign_evidence.bytes, sizeof foreign_evidence.bytes, operation_uuid,
      &decoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (
    wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
      (&fixture.graph, operation_uuid, &foreign_evidence, &neutral), ==,
    WYRELOG_E_POLICY);
  g_assert_null (neutral);
  g_assert_cmpint (
    wyl_fact_graph_directory_open_darwin_provisioned_pair_exact_with_evidence
      (&fixture.graph, operation_uuid, &fixture.evidence, &fixture.pair), ==,
    WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
      ==, WYRELOG_E_OK);
  return fixture;
}

static void
fixture_clear (DarwinPairFixture *fixture)
{
  wyl_fact_graph_provisioned_pair_free (fixture->pair);
  wyl_fact_graph_directory_clear (&fixture->graph);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  remove_tree (fixture->root);
  g_clear_pointer (&fixture->graph_path, g_free);
  g_clear_pointer (&fixture->root, g_free);
}

static void
test_pair_namespace_secure_bridge (void)
{
  DarwinPairFixture fixture = fixture_create ();
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  wyl_fact_artifact_namespace_pair_access_reset_for_test ();
  g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
        (WYL_FACT_ARTIFACT_PAIR_ACCESS_WRITER_BINDING, O_RDWR));
  g_autofree gchar *final_path = g_build_filename (fixture.graph_path,
          "facts.duckdb", NULL);
  g_autofree gchar *before_bytes = NULL;
  gsize before_size = 0;
  g_assert_true (g_file_get_contents (final_path, &before_bytes, &before_size,
      NULL));
  g_autoptr (GPtrArray) names_before = snapshot_names (fixture.graph_path);
  wyl_fact_artifact_namespace_pair_access_reset_for_test ();
  g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_STORE_IDENTITY_RESULT_NONE);
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
        (WYL_FACT_ARTIFACT_PAIR_ACCESS_READ_PIN, O_RDONLY));
  g_assert_true (wyl_fact_artifact_namespace_pair_access_observed_for_test
        (WYL_FACT_ARTIFACT_PAIR_ACCESS_READER_BINDING, O_RDONLY));
  g_autofree gchar *after_bytes = NULL;
  gsize after_size = 0;
  g_assert_true (g_file_get_contents (final_path, &after_bytes, &after_size,
      NULL));
  g_assert_cmpuint (after_size, ==, before_size);
  g_assert_cmpmem (after_bytes, after_size, before_bytes, before_size);
  g_autoptr (GPtrArray) names_after = snapshot_names (fixture.graph_path);
  assert_names_equal (names_before, names_after);
  g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
      ==, WYRELOG_E_OK);

  g_autofree gchar *stage = g_strdup_printf ("provision-%s.sqlite",
          operation_uuid);
  struct stat status;
  g_assert_cmpint (fstatat (fixture.graph.graph_fd, stage, &status,
      AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);
  g_assert_cmpint (fstatat (fixture.graph.graph_fd, "facts.duckdb", &status,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_assert_cmpuint (status.st_nlink, ==, 1);
  g_autofree gchar *wal = g_build_filename (fixture.graph_path,
          "facts.duckdb.wal", NULL);
  g_assert_false (g_file_test (wal, G_FILE_TEST_EXISTS));
  fixture_clear (&fixture);
}

static void
count_preflight (WylFactStorePairPreflightForTest seam, gpointer user_data)
{
  g_assert_cmpint (seam, ==, WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY);
  guint *calls = user_data;
  (*calls)++;
}

static void
test_pair_preflight_no_mutation (void)
{
  DarwinPairFixture fixture = fixture_create ();
  struct stat before;
  g_assert_cmpint (fstatat (fixture.graph.graph_fd, "facts.duckdb", &before,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_autoptr (GPtrArray) names_before = snapshot_names (fixture.graph_path);
  guint calls = 0;
  wyl_fact_store_pinned_set_pair_preflight_hook_for_test (count_preflight,
      &calls);
  wyl_fact_store_pinned_set_pair_preflight_error_for_test
    (WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY, WYRELOG_E_POLICY);
  WylFactStoreIdentityResult result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
        (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY,
      &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (calls, ==, 1);
  struct stat after;
  g_assert_cmpint (fstatat (fixture.graph.graph_fd, "facts.duckdb", &after,
      AT_SYMLINK_NOFOLLOW), ==, 0);
  g_assert_cmpuint (after.st_dev, ==, before.st_dev);
  g_assert_cmpuint (after.st_ino, ==, before.st_ino);
  g_assert_cmpuint (after.st_size, ==, before.st_size);
  g_autoptr (GPtrArray) names_after = snapshot_names (fixture.graph_path);
  assert_names_equal (names_before, names_after);
  struct stat absent;
  g_assert_cmpint (fstatat (fixture.graph.graph_fd, "facts.duckdb.lock",
      &absent, AT_SYMLINK_NOFOLLOW), ==, -1);
  g_assert_cmpint (errno, ==, ENOENT);
  g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate (fixture.pair),
      ==, WYRELOG_E_OK);
  fixture_clear (&fixture);
}

typedef enum
{
  ATTACK_FINAL,
  ATTACK_GRAPH,
} AttackKind;

typedef struct
{
  WylFactStorePinnedRendezvous target;
  AttackKind kind;
  DarwinPairFixture *fixture;
  gboolean fired;
} AttackContext;

static void
attack_rendezvous (WylFactStorePinnedRendezvous rendezvous,
    gpointer user_data)
{
  AttackContext *context = user_data;
  if (context->fired || rendezvous != context->target)
    return;
  context->fired = TRUE;
  DarwinPairFixture *fixture = context->fixture;
  if (context->kind == ATTACK_FINAL) {
    g_assert_cmpint (renameat (fixture->graph.graph_fd, "facts.duckdb",
        fixture->graph.graph_fd, "facts.duckdb.saved"), ==, 0);
    gint foreign = openat (fixture->graph.graph_fd, "facts.duckdb",
            O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    g_assert_cmpint (foreign, >=, 0);
    g_assert_cmpint (write (foreign, "foreign", 7), ==, 7);
    g_assert_cmpint (close (foreign), ==, 0);
  } else {
    g_autofree gchar *saved_component = g_strconcat (
      fixture->graph.graph_component, ".saved", NULL);
    g_assert_cmpint (renameat (fixture->graph.tenant_fd,
        fixture->graph.graph_component, fixture->graph.tenant_fd,
        saved_component), ==, 0);
    g_assert_cmpint (mkdirat (fixture->graph.tenant_fd,
        fixture->graph.graph_component, 0700), ==, 0);
  }
}

static void
test_pair_r0_r5_fail_closed (void)
{
  for (gint value = WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT;
      value <= WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE; value++) {
    for (gint kind = ATTACK_FINAL; kind <= ATTACK_GRAPH; kind++) {
      DarwinPairFixture fixture = fixture_create ();
      WylFactStoreIdentityResult result =
          WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
      g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
            (fixture.pair, &identity,
          WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
          WYRELOG_E_OK);
      g_autofree gchar *final_path = g_build_filename (fixture.graph_path,
              "facts.duckdb", NULL);
      g_autofree gchar *database_bytes = NULL;
      gsize database_size = 0;
      g_assert_true (g_file_get_contents (final_path, &database_bytes,
          &database_size, NULL));
      struct stat database_before;
      g_assert_cmpint (g_stat (final_path, &database_before), ==, 0);
      g_autoptr (GPtrArray) names_before =
          snapshot_names (fixture.graph_path);
      g_autofree gchar *lock_path = g_build_filename (fixture.graph_path,
              "facts.duckdb.lock", NULL);
      struct stat lock_before;
      g_assert_cmpint (g_stat (lock_path, &lock_before), ==, 0);
      g_autofree gchar *wal_path = g_build_filename (fixture.graph_path,
              "facts.duckdb.wal", NULL);
      g_assert_false (g_file_test (wal_path, G_FILE_TEST_EXISTS));

      AttackContext context = {
        .target = (WylFactStorePinnedRendezvous) value,
        .kind = (AttackKind) kind,
        .fixture = &fixture,
      };
      wyl_fact_store_pinned_set_pair_test_hook_for_test (attack_rendezvous,
          &context);
      result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
      g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
            (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
          &result), ==, WYRELOG_E_POLICY);
      g_assert_true (context.fired);
      g_assert_cmpint (wyl_fact_graph_provisioned_pair_revalidate
            (fixture.pair), ==, WYRELOG_E_POLICY);

      g_autofree gchar *authority_path = context.kind == ATTACK_GRAPH
          ? g_strdup_printf ("%s.saved", fixture.graph_path)
          : g_strdup (fixture.graph_path);
      g_autofree gchar *authority_main = g_build_filename (authority_path,
              context.kind == ATTACK_FINAL ? "facts.duckdb.saved"
          : "facts.duckdb", NULL);
      g_autofree gchar *authority_bytes = NULL;
      gsize authority_size = 0;
      g_assert_true (g_file_get_contents (authority_main, &authority_bytes,
          &authority_size, NULL));
      struct stat database_after;
      g_assert_cmpint (g_stat (authority_main, &database_after), ==, 0);
      g_assert_cmpuint (database_after.st_dev, ==, database_before.st_dev);
      g_assert_cmpuint (database_after.st_ino, ==, database_before.st_ino);
      g_assert_cmpuint (authority_size, ==, database_size);
      g_assert_cmpmem (authority_bytes, authority_size, database_bytes,
          database_size);
      g_autofree gchar *authority_lock = g_build_filename (authority_path,
              "facts.duckdb.lock", NULL);
      struct stat lock_after;
      g_assert_cmpint (g_stat (authority_lock, &lock_after), ==, 0);
      g_assert_cmpuint (lock_after.st_dev, ==, lock_before.st_dev);
      g_assert_cmpuint (lock_after.st_ino, ==, lock_before.st_ino);
      g_autofree gchar *authority_wal = g_build_filename (authority_path,
              "facts.duckdb.wal", NULL);
      g_assert_false (g_file_test (authority_wal, G_FILE_TEST_EXISTS));

      g_autoptr (GPtrArray) authority_names = snapshot_names (authority_path);
      if (context.kind == ATTACK_FINAL) {
        g_assert_cmpuint (authority_names->len, ==, names_before->len + 1);
        for (guint i = 0; i < names_before->len; i++)
          g_assert_true (g_ptr_array_find_with_equal_func (authority_names,
              g_ptr_array_index (names_before, i), g_str_equal, NULL));
        g_assert_true (g_ptr_array_find_with_equal_func (authority_names,
            "facts.duckdb.saved", g_str_equal, NULL));
        g_autofree gchar *foreign_bytes = NULL;
        gsize foreign_size = 0;
        g_assert_true (g_file_get_contents (final_path, &foreign_bytes,
            &foreign_size, NULL));
        g_assert_cmpuint (foreign_size, ==, 7);
        g_assert_cmpmem (foreign_bytes, foreign_size, "foreign", 7);
      } else {
        assert_names_equal (names_before, authority_names);
        g_autoptr (GPtrArray) replacement_names =
            snapshot_names (fixture.graph_path);
        g_assert_cmpuint (replacement_names->len, ==, 0);
      }
      fixture_clear (&fixture);
    }
  }
}

typedef struct
{
  guint calls;
  guint fired;
} ControlTrace;

static void
trace_control (WylFactStorePinnedRendezvous rendezvous, gpointer user_data)
{
  ControlTrace *trace = user_data;
  trace->calls++;
  trace->fired |= 1U << (guint) rendezvous;
}

static void
test_pair_control_isolation (void)
{
  {
    DarwinPairFixture fixture = fixture_create ();
    WylFactArtifactNamespace *namespace_ = NULL;
    g_assert_cmpint (
      wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (fixture.pair, &namespace_), ==, WYRELOG_E_OK);
    guint pair_calls = 0;
    wyl_fact_store_pinned_set_pair_preflight_hook_for_test (count_preflight,
        &pair_calls);
    wyl_fact_store_pinned_set_pair_preflight_error_for_test
      (WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY, WYRELOG_E_POLICY);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (namespace_,
        &identity, WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (pair_calls, ==, 0);
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
          (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
        &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpuint (pair_calls, ==, 1);
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
          (fixture.pair, &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
        &result), ==, WYRELOG_E_OK);
    g_assert_cmpuint (pair_calls, ==, 1);
    wyl_fact_artifact_namespace_free (namespace_);
    fixture_clear (&fixture);
  }

  {
    DarwinPairFixture fixture = fixture_create ();
    WylFactArtifactNamespace *namespace_ = NULL;
    g_assert_cmpint (
      wyl_fact_artifact_namespace_open_provisioned_pair_internal
        (fixture.pair, &namespace_), ==, WYRELOG_E_OK);
    ControlTrace generic_trace = { 0 };
    wyl_fact_store_pinned_set_test_hook (trace_control, &generic_trace);
    wyl_fact_store_pinned_set_test_stage_errors (WYRELOG_E_OK,
        WYRELOG_E_OK, WYRELOG_E_POLICY);
    WylFactStoreIdentityResult result =
        WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
    g_assert_cmpint (wyl_fact_store_open_identified_provisioned_pair_pinned
          (fixture.pair, &identity,
        WYL_FACT_STORE_IDENTITY_INITIALIZE_IF_EMPTY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (generic_trace.calls, ==, 0);
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (namespace_,
        &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (generic_trace.calls, ==, 6);
    g_assert_cmpuint (generic_trace.fired, ==, (1U << 6) - 1);
    g_assert_cmpint (wyl_fact_store_open_identified_pinned (namespace_,
        &identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, &result), ==,
        WYRELOG_E_OK);
    g_assert_cmpuint (generic_trace.calls, ==, 6);
    wyl_fact_artifact_namespace_free (namespace_);
    fixture_clear (&fixture);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/darwin-pair/namespace-secure-bridge",
      test_pair_namespace_secure_bridge);
  g_test_add_func ("/fact/darwin-pair/preflight-no-mutation",
      test_pair_preflight_no_mutation);
  g_test_add_func ("/fact/darwin-pair/r0-r5-fail-closed",
      test_pair_r0_r5_fail_closed);
  g_test_add_func ("/fact/darwin-pair/control-isolation",
      test_pair_control_isolation);
  return g_test_run ();
}
