/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <duckdb.hpp>
#include <glib.h>
#include <glib/gstdio.h>

#include <cstring>

#include "fact/graph-artifact-namespace-private.h"
#include "fact/graph-locator-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"
#include "fact-test-support.h"

#ifndef G_OS_WIN32
#error "the secure DuckDB temp-child ownership fixture is Windows-only"
#endif

extern "C"
{
G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal (
  WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);
}

static void
remove_tree_for_test (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, nullptr);
  if (directory != nullptr) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != nullptr) {
      g_autofree gchar *child = g_build_filename (path, name, nullptr);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree_for_test (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

struct ProvisionedPairFixture
{
  static constexpr const char *operation_uuid =
      "01890f47-3c4b-7cc2-b8c4-dc0c0c078820";

  gchar *root = nullptr;
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactGraphProvisionedPair *pair = nullptr;
  WylFactArtifactNamespace *namespace_ = nullptr;

  ProvisionedPairFixture ()
  {
    g_autoptr (GError) error = nullptr;
    g_autofree gchar *created_root =
        wyl_test_make_secure_fact_root ("wyl-secure-temp-child-XXXXXX",
            &error);
    g_assert_no_error (error);
    g_assert_nonnull (created_root);
    root = g_strdup (created_root);

    g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver,
        &locator, TRUE, &directory), ==, WYRELOG_E_OK);

    WylFactGraphStage stage = WYL_FACT_GRAPH_STAGE_INIT;
    WylFactGraphWinOperationEvidence evidence = { 0 };
    g_assert_cmpint (wyl_fact_graph_directory_stage_create_exact (&directory,
        operation_uuid, &stage), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_stage_sync (&stage), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_stage_get_windows_operation_evidence (
          &stage, &evidence), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_graph_stage_publish_with_evidence (&directory,
        &stage, &evidence), ==, WYRELOG_E_OK);
    g_assert_cmpint (
      wyl_fact_graph_directory_open_provisioned_pair_exact_with_evidence (
        &directory, operation_uuid, &evidence, &pair), ==, WYRELOG_E_OK);
    wyl_fact_graph_stage_clear (&stage);
    g_assert_nonnull (pair);

    g_assert_cmpint (wyl_fact_artifact_namespace_open_provisioned_pair_internal
          (pair, &namespace_), ==, WYRELOG_E_OK);
    g_assert_nonnull (namespace_);
  }

  ~ProvisionedPairFixture ()
  {
    wyl_fact_artifact_namespace_free (namespace_);
    wyl_fact_graph_provisioned_pair_free (pair);
    wyl_fact_graph_directory_clear (&directory);
    wyl_fact_graph_locator_clear (&locator);
    wyl_fact_graph_resolver_clear (&resolver);
    remove_tree_for_test (root);
    g_free (root);
  }
};

static void
test_secure_temp_child_lifecycle (void)
{
  ProvisionedPairFixture fixture;
  WylSecureDuckdbFileSystem filesystem (fixture.namespace_, false);
  const auto temp_path = filesystem.TemporaryDirectory ()
      + "/duckdb_temp_storage_S32K-0.tmp";
  auto temporary = filesystem.OpenFile (temp_path,
          duckdb::FileOpenFlags (11, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED), nullptr);
  const char expected[] = "secure-temp-child";
  char observed[sizeof expected] = { 0 };

  filesystem.Write (*temporary, const_cast<char *> (expected),
      static_cast<int64_t> (strlen (expected)), 0);
  filesystem.FileSync (*temporary);
  filesystem.Read (*temporary, observed,
      static_cast<int64_t> (strlen (expected)), 0);
  g_assert_cmpmem (observed, strlen (expected), expected, strlen (expected));
  temporary->Close ();

  /* FileHandle::Close performs the terminal wrapper finish. Retirement then
   * consumes the independently returned child authority, and destruction is
   * idempotent after the wrapper session has already been consumed. */
  g_assert_true (filesystem.TryRemoveFile (temp_path, nullptr));
  g_assert_cmpuint (filesystem.TempChildrenCreatedForTest (), ==, 1);
  temporary.reset ();
  g_assert_cmpint (filesystem.SharedHealth ()->Status (), ==, WYRELOG_E_OK);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
  g_test_add_func ("/secure-duckdb/windows/temp-child/ownership",
      test_secure_temp_child_lifecycle);
  return g_test_run ();
}
