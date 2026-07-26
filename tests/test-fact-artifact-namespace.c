/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif
#include <glib.h>
#include <glib/gstdio.h>
#ifndef G_OS_WIN32
#include <errno.h>
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

static gint
count_open_fds (void)
{
  long limit = sysconf (_SC_OPEN_MAX);
  if (limit < 0 || limit > 4096)
    limit = 4096;
  gint count = 0;
  for (gint fd = 0; fd < limit; fd++) {
    errno = 0;
    if (fcntl (fd, F_GETFD) >= 0 || errno != EBADF)
      count++;
  }
  return count;
}

static gboolean
write_exact (gint fd, const void *data, gsize size)
{
  const guint8 *cursor = data;
  while (size > 0) {
    ssize_t written = write (fd, cursor, size);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return FALSE;
    cursor += written;
    size -= written;
  }
  return TRUE;
}

static gboolean
read_exact (gint fd, void *data, gsize size)
{
  guint8 *cursor = data;
  while (size > 0) {
    ssize_t consumed = read (fd, cursor, size);
    if (consumed < 0 && errno == EINTR)
      continue;
    if (consumed <= 0)
      return FALSE;
    cursor += consumed;
    size -= consumed;
  }
  return TRUE;
}

typedef struct
{
  pid_t pid;
  gint release_fd;
} LeaseHolderProcess;

static LeaseHolderProcess
start_lease_holder_process (const WylFactGraphDirectory *directory,
    gboolean exclusive, gboolean crash_after_ready)
{
  gint ready[2], release[2];
  g_assert_cmpint (pipe (ready), ==, 0);
  g_assert_cmpint (pipe (release), ==, 0);
  pid_t pid = fork ();
  g_assert_cmpint (pid >= 0, ==, TRUE);
  if (pid == 0) {
    close (ready[0]);
    close (release[1]);
    WylFactArtifactNamespace *namespace_ = NULL;
    WylFactArtifactMutationLease *lease = NULL;
    wyrelog_error_t result = wyl_fact_artifact_namespace_open (directory,
        &namespace_);
    if (result == WYRELOG_E_OK)
      result = exclusive
          ? wyl_fact_artifact_namespace_acquire_mutation_lease (namespace_,
          &lease) : wyl_fact_artifact_namespace_acquire_reader_guard
          (namespace_, &lease);
    if (!write_exact (ready[1], &result, sizeof result))
      _exit (91);
    close (ready[1]);
    if (result != WYRELOG_E_OK || crash_after_ready)
      _exit (result == WYRELOG_E_OK ? 0 : 92);
    guint8 token;
    if (!read_exact (release[0], &token, sizeof token))
      _exit (93);
    wyl_fact_artifact_mutation_lease_free (lease);
    wyl_fact_artifact_namespace_free (namespace_);
    _exit (0);
  }
  close (ready[1]);
  close (release[0]);
  wyrelog_error_t result = WYRELOG_E_INTERNAL;
  g_assert_true (read_exact (ready[0], &result, sizeof result));
  close (ready[0]);
  g_assert_cmpint (result, ==, WYRELOG_E_OK);
  if (crash_after_ready) {
    close (release[1]);
    release[1] = -1;
  }
  return (LeaseHolderProcess) {
  pid, release[1]};
}

static void
stop_lease_holder_process (LeaseHolderProcess holder)
{
  guint8 token = 1;
  g_assert_cmpint (holder.release_fd >= 0, ==, TRUE);
  g_assert_true (write_exact (holder.release_fd, &token, sizeof token));
  close (holder.release_fd);
  gint status = 0;
  g_assert_cmpint (waitpid (holder.pid, &status, 0), ==, holder.pid);
  g_assert_true (WIFEXITED (status) && WEXITSTATUS (status) == 0);
}

static wyrelog_error_t
attempt_lease_in_fresh_process (const WylFactGraphDirectory *directory,
    gboolean exclusive)
{
  gint result_pipe[2];
  g_assert_cmpint (pipe (result_pipe), ==, 0);
  pid_t pid = fork ();
  g_assert_cmpint (pid >= 0, ==, TRUE);
  if (pid == 0) {
    close (result_pipe[0]);
    WylFactArtifactNamespace *namespace_ = NULL;
    WylFactArtifactMutationLease *lease = NULL;
    wyrelog_error_t result = wyl_fact_artifact_namespace_open (directory,
        &namespace_);
    if (result == WYRELOG_E_OK)
      result = exclusive
          ? wyl_fact_artifact_namespace_acquire_mutation_lease (namespace_,
          &lease) : wyl_fact_artifact_namespace_acquire_reader_guard
          (namespace_, &lease);
    if (!write_exact (result_pipe[1], &result, sizeof result))
      _exit (94);
    wyl_fact_artifact_mutation_lease_free (lease);
    wyl_fact_artifact_namespace_free (namespace_);
    _exit (0);
  }
  close (result_pipe[1]);
  wyrelog_error_t result = WYRELOG_E_INTERNAL;
  g_assert_true (read_exact (result_pipe[0], &result, sizeof result));
  close (result_pipe[0]);
  gint status = 0;
  g_assert_cmpint (waitpid (pid, &status, 0), ==, pid);
  g_assert_true (WIFEXITED (status) && WEXITSTATUS (status) == 0);
  return result;
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

typedef struct
{
  WylFactArtifactMutationLease *lease;
  WylFactArtifactName name;
  wyrelog_error_t result;
} LeaseMutationWorker;

static gpointer
open_with_shared_lease_worker (gpointer data)
{
  LeaseMutationWorker *worker = data;
  gint fd = -1;
  worker->result = wyl_fact_artifact_mutation_lease_open_file (worker->lease,
      worker->name, TRUE, TRUE, &fd);
  if (fd >= 0)
    close (fd);
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
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path (&d);
  g_autofree gchar *lock_path = g_build_filename (graph_path,
      "facts.duckdb.lock", NULL);

  /* Initial lock publication failures are one-shot, leak no descriptors or
   * process-wide domain refs, and leave a reusable regular lock entry. */
  gint fd_count = count_open_fds ();
  WylFactArtifactNamespace *faulted = (gpointer) 0x1;
  mode_t old_umask = umask (0777);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_IO);
  umask (old_umask);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  struct stat lock_stat;
  g_assert_cmpint (lstat (lock_path, &lock_stat), ==, 0);
  g_assert_true (S_ISREG (lock_stat.st_mode));
  g_assert_cmpint (lock_stat.st_mode & 07777, ==, 0600);

  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (faulted);
  faulted = (gpointer) 0x1;
  fd_count = count_open_fds ();
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_IO);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (faulted);

  faulted = (gpointer) 0x1;
  fd_count = count_open_fds ();
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_POST_FSYNC_IDENTITY);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_POLICY);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &faulted), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (faulted);

  /* Run all fork coverage before creating any test threads and never inherit
   * a live lease into a child.  Remove the fault-test residue so the first
   * holder creates the lock and contenders exercise the EEXIST path. */
  g_assert_cmpint (unlink (lock_path), ==, 0);
  LeaseHolderProcess holder = start_lease_holder_process (&d, FALSE, FALSE);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, TRUE), ==,
      WYRELOG_E_BUSY);
  stop_lease_holder_process (holder);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, TRUE), ==, WYRELOG_E_OK);

  holder = start_lease_holder_process (&d, TRUE, FALSE);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, FALSE), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, TRUE), ==,
      WYRELOG_E_BUSY);
  stop_lease_holder_process (holder);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, FALSE), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, TRUE), ==, WYRELOG_E_OK);

  holder = start_lease_holder_process (&d, TRUE, TRUE);
  gint crash_status = 0;
  g_assert_cmpint (waitpid (holder.pid, &crash_status, 0), ==, holder.pid);
  g_assert_true (WIFEXITED (crash_status) && WEXITSTATUS (crash_status) == 0);
  g_assert_cmpint (attempt_lease_in_fresh_process (&d, TRUE), ==, WYRELOG_E_OK);

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
  gint fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_LOCK, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_namespace_sync (n,
          WYL_FACT_ARTIFACT_LOCK), ==, WYRELOG_E_POLICY);

  WylFactArtifactMutationLease *reader_a = NULL, *reader_b = NULL;
  WylFactArtifactMutationLease *writer = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (n,
          &reader_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (reader_a,
          WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (reader_a,
          WYL_FACT_ARTIFACT_LOCK, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  wyl_fact_artifact_mutation_lease_free (reader_b);

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (writer,
          WYL_FACT_ARTIFACT_LOCK, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  LeaseMutationWorker mutation_workers[] = {
    {writer, WYL_FACT_ARTIFACT_WAL, WYRELOG_E_IO},
    {writer, WYL_FACT_ARTIFACT_CHECKPOINT, WYRELOG_E_IO},
  };
  GThread *mutation_threads[] = {
    g_thread_new ("lease-mutation-a", open_with_shared_lease_worker,
        &mutation_workers[0]),
    g_thread_new ("lease-mutation-b", open_with_shared_lease_worker,
        &mutation_workers[1]),
  };
  g_thread_join (mutation_threads[0]);
  g_thread_join (mutation_threads[1]);
  g_assert_cmpint (mutation_workers[0].result, ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation_workers[1].result, ==, WYRELOG_E_OK);
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
  writer = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (reader_a,
          "reader-temp", FALSE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (writer);

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
  fd = open (lock_path, O_RDWR | O_CREAT | O_EXCL, 0644);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  g_assert_cmpint (fchmod (fd, 0644), ==, 0);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &fresh), ==,
      WYRELOG_E_POLICY);
  g_assert_null (fresh);
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
  const mode_t invalid_directory_modes[] = { 0755, 0770, 0777 };
  for (guint i = 0; i < G_N_ELEMENTS (invalid_directory_modes); i++) {
    g_assert_cmpint (chmod (graph_path, invalid_directory_modes[i]), ==, 0);
    g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (reader_a), ==,
        WYRELOG_E_POLICY);
    WylFactArtifactNamespace *rejected = (gpointer) 0x1;
    g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &rejected), ==,
        WYRELOG_E_POLICY);
    g_assert_null (rejected);
    g_assert_cmpint (chmod (graph_path, 0700), ==, 0);
    g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (reader_a), ==,
        WYRELOG_E_OK);
  }
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

#ifdef G_OS_WIN32
static void
test_mutation_leases (void)
{
  WylFactArtifactMutationLease *lease = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (NULL,
          &lease), ==, WYRELOG_E_POLICY);
  g_assert_null (lease);
  lease = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_MAIN, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "tmp",
          FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
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
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          (WylFactArtifactName) - 1, FALSE, FALSE, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_namespace_unlink (n,
          (WylFactArtifactName) - 1), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_namespace_rename (n,
          (WylFactArtifactName) - 1, WYL_FACT_ARTIFACT_MAIN), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          (WylFactArtifactName) - 1, FALSE, FALSE, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_unlink (lease,
          (WylFactArtifactName) - 1), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (lease,
          (WylFactArtifactName) - 1, WYL_FACT_ARTIFACT_MAIN), ==,
      WYRELOG_E_INVALID);
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
