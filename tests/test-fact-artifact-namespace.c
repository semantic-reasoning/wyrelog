/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "fact/graph-artifact-namespace-private.h"

static void
test_namespace (void)
{
  WylFactGraphResolver r = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator l = { 0 };
  WylFactGraphDirectory d = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *n = NULL;
#ifdef G_OS_WIN32
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &n), ==,
      WYRELOG_E_POLICY);
#else
  gchar *root = g_dir_make_tmp ("wyl-namespace-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &r), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&l, "tenant", "graph"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&r, &l, TRUE, &d),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &n), ==, WYRELOG_E_OK);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_bind_main (n), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate_main (n), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_temp (n, "spill-1", TRUE,
          TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_temp (n, "../escape", TRUE,
          TRUE, &fd), ==, WYRELOG_E_INVALID);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path (&d);
  g_autofree gchar *wal_path =
      g_build_filename (graph_path, "facts.duckdb.wal", NULL);
  g_assert_cmpint (mkdir (wal_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (rmdir (wal_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_IO);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_autofree gchar *main_path =
      g_build_filename (graph_path, "facts.duckdb", NULL);
  g_assert_cmpint (link (main_path, wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_sync_directory (n), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          (WylFactArtifactName) 99, FALSE, FALSE, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_namespace_lock (n, TRUE, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_unlink (n,
          WYL_FACT_ARTIFACT_MAIN), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (n);
  wyl_fact_graph_directory_clear (&d);
  wyl_fact_graph_locator_clear (&l);
  wyl_fact_graph_resolver_clear (&r);
  g_rmdir (root);
  g_free (root);
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-artifact-namespace/basic", test_namespace);
  return g_test_run ();
}
