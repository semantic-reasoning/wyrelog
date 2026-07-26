/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include "fact/graph-artifact-namespace-private.h"

#ifndef G_OS_WIN32
static gchar *
make_root (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *created = g_dir_make_tmp ("wyl-namespace-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (created);
  gchar *root = realpath (created, NULL);
  g_assert_nonnull (root);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  return root;
}

typedef struct
{
  const WylFactGraphDirectory *directory;
  GMutex mutex;
  GCond condition;
  guint ready;
  gboolean start;
  WylFactArtifactNamespace *namespaces[2];
  wyrelog_error_t results[2];
} NamespaceOpenRace;

typedef struct
{
  NamespaceOpenRace *race;
  guint index;
} NamespaceOpenRaceWorker;

static gpointer
open_namespace_race_worker (gpointer data)
{
  NamespaceOpenRaceWorker *worker = data;
  NamespaceOpenRace *race = worker->race;
  g_mutex_lock (&race->mutex);
  race->ready++;
  g_cond_broadcast (&race->condition);
  while (!race->start)
    g_cond_wait (&race->condition, &race->mutex);
  g_mutex_unlock (&race->mutex);
  race->results[worker->index] = wyl_fact_artifact_namespace_open
      (race->directory, &race->namespaces[worker->index]);
  return NULL;
}

static void
test_mutation_leases (void)
{
#ifdef G_OS_WIN32
  WylFactArtifactMutationLease *lease = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (NULL,
          &lease), ==, WYRELOG_E_POLICY);
  g_assert_null (lease);
#else
  WylFactGraphResolver r = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator l = { 0 };
  WylFactGraphDirectory d = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *n = NULL;
  g_autofree gchar *root = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &r), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&l, "tenant", "graph"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&r, &l, TRUE, &d),
      ==, WYRELOG_E_OK);
  NamespaceOpenRace race = {.directory = &d };
  NamespaceOpenRaceWorker workers[] = { {&race, 0}, {&race, 1} };
  GThread *threads[] = {
    g_thread_new ("namespace-open-a", open_namespace_race_worker, &workers[0]),
    g_thread_new ("namespace-open-b", open_namespace_race_worker, &workers[1]),
  };
  g_mutex_lock (&race.mutex);
  while (race.ready != G_N_ELEMENTS (workers))
    g_cond_wait (&race.condition, &race.mutex);
  race.start = TRUE;
  g_cond_broadcast (&race.condition);
  g_mutex_unlock (&race.mutex);
  g_thread_join (threads[0]);
  g_thread_join (threads[1]);
  g_assert_cmpint (race.results[0], ==, WYRELOG_E_OK);
  g_assert_cmpint (race.results[1], ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (race.namespaces[0]);
  wyl_fact_artifact_namespace_free (race.namespaces[1]);
  g_cond_clear (&race.condition);
  g_mutex_clear (&race.mutex);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &n), ==, WYRELOG_E_OK);

  WylFactArtifactMutationLease *reader_a = NULL, *reader_b = NULL;
  WylFactArtifactMutationLease *writer = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (reader_a,
          WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  wyl_fact_artifact_mutation_lease_free (reader_b);

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (writer,
          WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (writer,
          "reader-temp", TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_unlink (writer,
          WYL_FACT_ARTIFACT_LOCK), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (writer,
          WYL_FACT_ARTIFACT_LOCK, WYL_FACT_ARTIFACT_MAIN), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (writer,
          WYL_FACT_ARTIFACT_MAIN, WYL_FACT_ARTIFACT_LOCK), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (writer);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_MAIN, FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_temp (n, "reader-temp",
          FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (reader_a,
          WYL_FACT_ARTIFACT_MAIN, FALSE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (reader_a,
          "reader-temp", FALSE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_mutation_lease_free (reader_a);

  /* A lease retains its namespace even when the caller releases its handle. */
  WylFactArtifactNamespace *lifetime = NULL;
  WylFactArtifactMutationLease *lifetime_guard = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &lifetime), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (lifetime,
          &lifetime_guard), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (lifetime);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (lifetime_guard),
      ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lifetime_guard);

  /* A process dying with a kernel lock does not strand the on-disk lock file. */
  pid_t child = fork ();
  g_assert_cmpint (child >= 0, ==, TRUE);
  if (child == 0) {
    WylFactArtifactMutationLease *child_writer = NULL;
    _exit (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
            &child_writer) == WYRELOG_E_OK ? 0 : 1);
  }
  gint status = 0;
  g_assert_cmpint (waitpid (child, &status, 0), ==, child);
  g_assert_true (WIFEXITED (status) && WEXITSTATUS (status) == 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (writer);

  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path (&d);
  g_autofree gchar *lock_path = g_build_filename (graph_path,
      "facts.duckdb.lock", NULL);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  fd = open (lock_path, O_RDWR | O_CREAT | O_EXCL, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (reader_a), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_a), ==, WYRELOG_E_POLICY);
  g_assert_null (reader_a);

  /* A live pin rejects a replacement for every namespace in this process. */
  WylFactArtifactNamespace *fresh = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
  wyl_fact_artifact_namespace_free (n);

  /* Once every old pin is gone, initial special-file substitutions are still
   * rejected and a regular crash-left lock can be reused. */
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_assert_cmpint (mkdir (lock_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (rmdir (lock_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", lock_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_autofree gchar *main_path = g_build_filename (graph_path,
      "facts.duckdb", NULL);
  g_assert_cmpint (link (main_path, lock_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_assert_cmpint (mkfifo (lock_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);

  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (fresh,
          &reader_a), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  wyl_fact_artifact_namespace_free (fresh);
  /* Test cleanup runs outside the production namespace authority. */
  g_assert_cmpint (unlink (lock_path), ==, 0);
  wyl_fact_graph_directory_clear (&d);
  wyl_fact_graph_locator_clear (&l);
  wyl_fact_graph_resolver_clear (&r);
#endif
}
#endif

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
  gchar *root = make_root ();
  g_assert_nonnull (root);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &r), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&l, "tenant", "graph"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&r, &l, TRUE, &d),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &n), ==, WYRELOG_E_OK);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_bind_main (n), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate_main (n), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "spill-1",
          TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "spill-1",
          TRUE, TRUE, &fd), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "../escape", TRUE, TRUE, &fd), ==, WYRELOG_E_INVALID);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path (&d);
  g_autofree gchar *wal_path =
      g_build_filename (graph_path, "facts.duckdb.wal", NULL);
  g_assert_cmpint (mkdir (wal_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_namespace_unlink (n,
          WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_namespace_rename (n,
          WYL_FACT_ARTIFACT_MAIN, WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_POLICY);
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
  g_assert_cmpint (wyl_fact_artifact_namespace_unlink (n,
          WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_sync_directory (n), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          (WylFactArtifactName) 99, FALSE, FALSE, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (lease,
          WYL_FACT_ARTIFACT_MAIN, WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (lease,
          WYL_FACT_ARTIFACT_WAL, WYL_FACT_ARTIFACT_MAIN), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_lock (n, TRUE, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_unlink (lease,
          WYL_FACT_ARTIFACT_MAIN), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
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
  g_test_add_func ("/fact-artifact-namespace/mutation-leases",
      test_mutation_leases);
  return g_test_run ();
}
