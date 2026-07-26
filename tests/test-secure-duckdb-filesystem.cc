/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include <duckdb.hpp>
#include <glib.h>
#include <glib/gstdio.h>

#include <cstdlib>
#include <cstring>

#include "fact/secure-duckdb-filesystem-private.hpp"

#ifndef G_OS_WIN32
static gchar *
make_root ()
{
  g_autoptr (GError) error = nullptr;
  g_autofree gchar *created =
      g_dir_make_tmp ("wyl-secure-filesystem-XXXXXX", &error);
  g_assert_no_error (error);
  gchar *root = realpath (created, nullptr);
  g_assert_nonnull (root);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  return root;
}

static void
test_bounded_filesystem ()
{
  g_autofree gchar *root = make_root ();
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = nullptr;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&directory, &namespace_),
      ==, WYRELOG_E_OK);

  {
    WylSecureDuckdbFileSystem filesystem (namespace_);
    auto main = filesystem.OpenFile ("facts.duckdb",
        duckdb::FileFlags::FILE_FLAGS_READ
        | duckdb::FileFlags::FILE_FLAGS_WRITE
        | duckdb::FileFlags::FILE_FLAGS_FILE_CREATE
        | duckdb::FileLockType::WRITE_LOCK, nullptr);
    g_assert_nonnull (main.get ());
    char written[] = "duck";
    filesystem.Write (*main, written, 4, 0);
    filesystem.FileSync (*main);
    char read[5] = {};
    filesystem.Read (*main, read, 4, 0);
    g_assert_cmpstr (read, ==, "duck");
    g_assert_cmpint (filesystem.GetFileSize (*main), ==, 4);
    g_assert_cmpint (static_cast<int> (filesystem.GetFileType (*main)), ==,
        static_cast<int> (duckdb::FileType::FILE_TYPE_REGULAR));

    auto wal = filesystem.OpenFile ("facts.duckdb.wal",
        duckdb::FileFlags::FILE_FLAGS_READ
        | duckdb::FileFlags::FILE_FLAGS_WRITE
        | duckdb::FileFlags::FILE_FLAGS_FILE_CREATE
        | duckdb::FileLockType::WRITE_LOCK, nullptr);
    g_assert_nonnull (wal.get ());
    wal->Close ();
    filesystem.MoveFile ("facts.duckdb.wal",
        "facts.duckdb.wal.checkpoint", nullptr);
    g_assert_true (filesystem.FileExists ("facts.duckdb.wal.checkpoint",
            nullptr));
    g_assert_true (filesystem.TryRemoveFile (
            "facts.duckdb.wal.checkpoint", nullptr));
    g_assert_false (filesystem.FileExists ("facts.duckdb.wal.checkpoint",
            nullptr));
    auto temporary = filesystem.OpenFile ("tmp-spill-1",
        duckdb::FileFlags::FILE_FLAGS_READ
        | duckdb::FileFlags::FILE_FLAGS_WRITE
        | duckdb::FileFlags::FILE_FLAGS_FILE_CREATE, nullptr);
    g_assert_nonnull (temporary.get ());
    temporary->Close ();
    g_assert_true (filesystem.FileExists ("tmp-spill-1", nullptr));
    g_assert_false (filesystem.FileExists ("/proc/self/cgroup", nullptr));

    bool rejected = false;
    try {
      (void) filesystem.FileExists ("/tmp/facts.duckdb", nullptr);
    } catch (const duckdb::IOException &) {
      rejected = true;
    }
    g_assert_true (rejected);
    rejected = false;
    try {
      (void) filesystem.DirectoryExists (".", nullptr);
    } catch (const duckdb::NotImplementedException &) {
      rejected = true;
    }
    g_assert_true (rejected);
    main->Close ();
  }

  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&directory);
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_autofree gchar *main_path =
      g_build_filename (graph_path, "facts.duckdb", nullptr);
  g_assert_cmpint (g_remove (main_path), ==, 0);
  g_autofree gchar *lock_path =
      g_build_filename (graph_path, "facts.duckdb.lock", nullptr);
  if (g_file_test (lock_path, G_FILE_TEST_EXISTS))
    g_assert_cmpint (g_remove (lock_path), ==, 0);
  g_autofree gchar *temp_path =
      g_build_filename (graph_path, "tmp-spill-1", nullptr);
  g_assert_cmpint (g_remove (temp_path), ==, 0);
  g_autofree gchar *graph_parent = g_path_get_dirname (graph_path);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_assert_cmpint (g_rmdir (graph_parent), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
#ifndef G_OS_WIN32
  g_test_add_func ("/secure-duckdb-filesystem/bounded",
      test_bounded_filesystem);
#endif
  return g_test_run ();
}
