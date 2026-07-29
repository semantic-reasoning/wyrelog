/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
/* Apple SDKs hide the BSD O_NOFOLLOW extension under strict C modes unless
 * this is set before system headers.  Keep the test's direct held-main
 * opens on the same no-follow contract as the namespace under test. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
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

static void
test_remove_fixed_artifact (const gchar *graph_path, WylFactArtifactName name)
{
  static const gchar *const names[] = { "facts.duckdb", "facts.duckdb.wal",
    "facts.duckdb.wal.checkpoint", "facts.duckdb.wal.recovery",
    "facts.duckdb.lock"
  };
  g_assert_cmpint (name >= WYL_FACT_ARTIFACT_MAIN
      && name <= WYL_FACT_ARTIFACT_LOCK, ==, TRUE);
  g_autofree gchar *path = g_build_filename (graph_path, names[name], NULL);
  g_assert_cmpint (unlink (path), ==, 0);
}

/* Tests model the caller's already-held canonical main artifact.  The
 * namespace must import a duplicate; this helper clears the caller handle
 * immediately after construction to prove ownership was not transferred. */
static wyrelog_error_t
open_namespace (const WylFactGraphDirectory *directory,
    WylFactArtifactNamespace **out_namespace)
{
  if (out_namespace)
    *out_namespace = NULL;
  if (!directory || !out_namespace)
    return WYRELOG_E_INVALID;
  gint fd = openat (directory->graph_fd, "facts.duckdb",
      O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return WYRELOG_E_IO;
  if (fchmod (fd, 0600) != 0) {
    close (fd);
    return WYRELOG_E_IO;
  }
  struct stat stat_;
  if (fstat (fd, &stat_) != 0 || !S_ISREG (stat_.st_mode)
      || stat_.st_nlink != 1 || (stat_.st_mode & 07777) != 0600) {
    close (fd);
    return WYRELOG_E_POLICY;
  }
  WylFactGraphRegularFile main = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  main.fd = fd;
  main.device = stat_.st_dev;
  main.inode = stat_.st_ino;
  main.size_bytes = stat_.st_size;
  wyrelog_error_t result = wyl_fact_artifact_namespace_open (directory,
      &main, out_namespace);
  wyl_fact_graph_regular_file_clear (&main);
  return result;
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
    wyrelog_error_t result = open_namespace (directory, &namespace_);
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
    wyrelog_error_t result = open_namespace (directory, &namespace_);
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
  race->results[worker->index] = open_namespace (race->directory,
      &race->namespaces[worker->index]);
  return NULL;
}

typedef struct
{
  WylFactArtifactTempBinding *binding;
  const gchar *destination;
  wyrelog_error_t result;
} TempBindingRenameWorker;

static gpointer
rename_temp_binding_worker (gpointer data)
{
  TempBindingRenameWorker *worker = data;
  worker->result = wyl_fact_artifact_temp_binding_rename (worker->binding,
      worker->destination);
  return NULL;
}

typedef struct
{
  WylFactArtifactTempBinding *binding;
  wyrelog_error_t result;
} TempBindingUnlinkWorker;

static gpointer
unlink_temp_binding_worker (gpointer data)
{
  TempBindingUnlinkWorker *worker = data;
  worker->result = wyl_fact_artifact_temp_binding_unlink (worker->binding);
  return NULL;
}

typedef struct
{
  WylFactArtifactSidecarBinding *binding;
  wyrelog_error_t error;
  WylFactArtifactSidecarRetireResult result;
} SidecarRetireWorker;

static gpointer
retire_sidecar_binding_worker (gpointer data)
{
  SidecarRetireWorker *worker = data;
  worker->result = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  worker->error = wyl_fact_artifact_sidecar_binding_retire (worker->binding,
      &worker->result);
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
  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_IO);
  umask (old_umask);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  struct stat lock_stat;
  g_assert_cmpint (lstat (lock_path, &lock_stat), ==, 0);
  g_assert_true (S_ISREG (lock_stat.st_mode));
  g_assert_cmpint (lock_stat.st_mode & 07777, ==, 0600);

  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (faulted);
  faulted = (gpointer) 0x1;
  fd_count = count_open_fds ();
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_DIRECTORY_FSYNC);
  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_IO);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (faulted);

  faulted = (gpointer) 0x1;
  fd_count = count_open_fds ();
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_INITIAL_LOCK_POST_FSYNC_IDENTITY);
  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_POLICY);
  g_assert_null (faulted);
  g_assert_cmpint (count_open_fds (), ==, fd_count);
  g_assert_cmpint (open_namespace (&d, &faulted), ==, WYRELOG_E_OK);
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
  g_assert_cmpint (open_namespace (&d, &n), ==, WYRELOG_E_OK);
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
  g_assert_cmpint (fd, ==, -1);
  fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (reader_a,
          "reader-guard-temp", TRUE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
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
  g_assert_cmpint (mutation_workers[0].result, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (mutation_workers[1].result, ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (writer,
          WYL_FACT_ARTIFACT_MAIN, FALSE, FALSE, &fd), ==, WYRELOG_E_OK);
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
          WYL_FACT_ARTIFACT_MAIN, FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  writer = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (reader_a,
          "reader-temp", FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &writer), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (writer);

  /* A lease retains its namespace even when the caller releases its handle. */
  WylFactArtifactNamespace *lifetime = NULL;
  WylFactArtifactMutationLease *lifetime_guard = NULL;
  g_assert_cmpint (open_namespace (&d, &lifetime), ==, WYRELOG_E_OK);
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
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  wyl_fact_artifact_namespace_free (n);

  /* Once every old pin is gone, initial special-file substitutions are still
   * rejected and a regular crash-left lock can be reused. */
  g_assert_cmpint (unlink (lock_path), ==, 0);
  fd = open (lock_path, O_RDWR | O_CREAT | O_EXCL, 0644);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  g_assert_cmpint (fchmod (fd, 0644), ==, 0);
  close (fd);
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_assert_cmpint (mkdir (lock_path, 0700), ==, 0);
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (rmdir (lock_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", lock_path), ==, 0);
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_autofree gchar *main_path = g_build_filename (graph_path,
      "facts.duckdb", NULL);
  g_assert_cmpint (link (main_path, lock_path), ==, 0);
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_assert_cmpint (mkfifo (lock_path, 0600), ==, 0);
  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_POLICY);
  g_assert_null (fresh);
  g_assert_cmpint (unlink (lock_path), ==, 0);

  g_assert_cmpint (open_namespace (&d, &fresh), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard (fresh,
          &reader_a), ==, WYRELOG_E_OK);
  const mode_t invalid_directory_modes[] = { 0755, 0770, 0777 };
  for (guint i = 0; i < G_N_ELEMENTS (invalid_directory_modes); i++) {
    g_assert_cmpint (chmod (graph_path, invalid_directory_modes[i]), ==, 0);
    g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (reader_a), ==,
        WYRELOG_E_POLICY);
    WylFactArtifactNamespace *rejected = (gpointer) 0x1;
    g_assert_cmpint (open_namespace (&d, &rejected), ==, WYRELOG_E_POLICY);
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

static void
test_sidecar_retirement_result_contract (void)
{
  WylFactArtifactSidecarRetireResult result =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (NULL, &result),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (NULL, NULL),
      ==, WYRELOG_E_POLICY);
}

#ifdef G_OS_WIN32
static void
test_mutation_leases (void)
{
  WylFactArtifactMutationLease *lease = (gpointer) 0x1;
  gint fd = 42;
  WylFactArtifactSidecarRetireResult retirement =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (NULL,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  retirement = WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire
      ((WylFactArtifactSidecarBinding *) 0x1, &retirement), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
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
  WylFactArtifactTempBinding *binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "tmp", FALSE, FALSE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (binding, "next"), ==,
      WYRELOG_E_POLICY);
  WylFactArtifactTempRecoveryEvidence *evidence = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
      (binding, &evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          evidence), ==, WYRELOG_E_POLICY);
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
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, NULL, &n), ==,
      WYRELOG_E_POLICY);
#else
  gchar *root = make_root ();
  g_assert_nonnull (root);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &r), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&l, "tenant", "graph"), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&r, &l, TRUE, &d),
      ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path (&d);
  g_assert_cmpint (open_namespace (&d, &n), ==, WYRELOG_E_OK);
  /* Construction imports, rather than consumes, a held canonical main fd;
   * declared identity must agree before the namespace becomes observable. */
  WylFactGraphRegularFile imported = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  imported.fd = openat (d.graph_fd, "facts.duckdb",
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  g_assert_cmpint (imported.fd >= 0, ==, TRUE);
  struct stat imported_stat;
  g_assert_cmpint (fstat (imported.fd, &imported_stat), ==, 0);
  imported.device = imported_stat.st_dev;
  imported.inode = imported_stat.st_ino;
  imported.size_bytes = imported_stat.st_size;
  WylFactGraphRegularFile forged = imported;
  forged.inode++;
  WylFactArtifactNamespace *rejected = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &forged, &rejected),
      ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_autofree gchar *main_alias = g_build_filename (graph_path,
      "facts.duckdb-import-alias", NULL);
  g_assert_cmpint (linkat (d.graph_fd, "facts.duckdb", d.graph_fd,
          "facts.duckdb-import-alias", 0), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &imported,
          &rejected), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (unlink (main_alias), ==, 0);
  WylFactArtifactNamespace *imported_namespace = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_open (&d, &imported,
          &imported_namespace), ==, WYRELOG_E_OK);
  wyl_fact_graph_regular_file_clear (&imported);
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate (imported_namespace),
      ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (imported_namespace);
  gint imported_fd = 42;
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (n,
          WYL_FACT_ARTIFACT_MAIN, FALSE, FALSE, &imported_fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (imported_fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate (n), ==,
      WYRELOG_E_OK);
  WylFactArtifactMutationLease *lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate (n), ==,
      WYRELOG_E_OK);
  fd = 42;
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_OPEN_ABA);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_MAIN, FALSE, FALSE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_revalidate (lease), ==,
      WYRELOG_E_OK);
  WylFactArtifactSidecarBinding *sidecar = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_MAIN, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_LOCK, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
#if defined(__linux__) || defined(__APPLE__)
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
#else
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
#endif
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  WylFactArtifactSidecarBinding *collision = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &collision, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_sidecar_binding_free (collision);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_PUBLISH_PRE_RENAME_INSERT);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
#if defined(__linux__) || defined(__APPLE__)
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_RECOVERY), ==, WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_RECOVERY);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
#endif
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *bound_main_path =
      g_build_filename (graph_path, "facts.duckdb", NULL);
  g_autofree gchar *saved_main_path =
      g_build_filename (graph_path, "facts.duckdb.saved", NULL);
  g_assert_cmpint (rename (bound_main_path, saved_main_path), ==, 0);
  fd = open (bound_main_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (bound_main_path), ==, 0);
  g_assert_cmpint (rename (saved_main_path, bound_main_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_revalidate (n), ==,
      WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  WylFactArtifactTempBinding *replace_source = NULL;
  WylFactArtifactSidecarBinding *replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-replace", TRUE, TRUE, &replace_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "sidecar-replace", FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_CHECKPOINT, FALSE, FALSE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &replace_destination, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-replace-wal", TRUE, TRUE, &replace_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-replace-fault", TRUE, TRUE, &replace_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_RECOVERY, FALSE, FALSE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_RECOVERY);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-source-substitution", TRUE, TRUE, &replace_source, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *substituted_source_path = g_build_filename
      (graph_path, "tmp-sidecar-source-substitution", NULL);
  g_assert_cmpint (unlink (substituted_source_path), ==, 0);
  fd = open (substituted_source_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC,
      0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (substituted_source_path), ==, 0);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_RECOVERY);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-destination-substitution", TRUE, TRUE, &replace_source,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *substituted_destination_path = g_build_filename
      (graph_path, "facts.duckdb.wal.checkpoint", NULL);
  g_assert_cmpint (unlink (substituted_destination_path), ==, 0);
  fd = open (substituted_destination_path, O_CREAT | O_EXCL | O_RDWR |
      O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (replace_source), ==,
      WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-pre-rename-substitution", TRUE, TRUE, &replace_source,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_PRE_RENAME_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (replace_source), ==,
      WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_RECOVERY);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE,
          &replace_destination, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "sidecar-post-rename-substitution", TRUE, TRUE, &replace_source,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_POST_RENAME_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
      (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "sidecar-post-rename-substitution", FALSE, FALSE, &fd), ==,
      WYRELOG_E_NOT_FOUND);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_temp_binding_free (replace_source);
  wyl_fact_artifact_sidecar_binding_free (replace_destination);
  replace_source = NULL;
  replace_destination = NULL;
  WylFactArtifactSidecarRetireResult retirement =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *missing_sidecar_path = g_build_filename (graph_path,
      "facts.duckdb.wal.checkpoint", NULL);
  g_assert_cmpint (unlink (missing_sidecar_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_IO);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_RECOVERY, FALSE, FALSE, &fd), ==,
      WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_POLICY);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
          WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  /* Any externally missing active binding is reconciliation, never an
   * idempotent successful cleanup claim. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *checkpoint_path = g_build_filename (graph_path,
      "facts.duckdb.wal.checkpoint", NULL);
  g_assert_cmpint (unlink (checkpoint_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", checkpoint_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (unlink (checkpoint_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *recovery_path = g_build_filename (graph_path,
      "facts.duckdb.wal.recovery", NULL);
  g_assert_cmpint (unlink (recovery_path), ==, 0);
  g_assert_cmpint (mkdir (recovery_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (rmdir (recovery_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *bound_wal_path = g_build_filename (graph_path,
      "facts.duckdb.wal", NULL);
  g_autofree gchar *wal_alias_path = g_build_filename (graph_path,
      "facts.duckdb.wal.alias", NULL);
  g_assert_cmpint (link (bound_wal_path, wal_alias_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (unlink (wal_alias_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  /* The deterministic substitutions are injected after the normal identity
   * check; the adjacent recheck must reject pre-unlink replacement, while a
   * post-unlink replacement makes the terminal result reconcile-required. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_PRE_UNLINK_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_RETIRE_POST_UNLINK_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  SidecarRetireWorker retire_workers[] = {
    {sidecar, WYRELOG_E_INTERNAL,
        WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED},
    {sidecar, WYRELOG_E_INTERNAL,
        WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED},
  };
  GThread *retire_threads[] = {
    g_thread_new ("sidecar-retire-a", retire_sidecar_binding_worker,
        &retire_workers[0]),
    g_thread_new ("sidecar-retire-b", retire_sidecar_binding_worker,
        &retire_workers[1]),
  };
  g_thread_join (retire_threads[0]);
  g_thread_join (retire_threads[1]);
  guint retire_successes = 0;
  guint retire_rejections = 0;
  for (guint i = 0; i < G_N_ELEMENTS (retire_workers); i++) {
    if (retire_workers[i].error == WYRELOG_E_OK
        && retire_workers[i].result
        == WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED)
      retire_successes++;
    if (retire_workers[i].error == WYRELOG_E_POLICY
        && retire_workers[i].result
        == WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED)
      retire_rejections++;
  }
  g_assert_cmpuint (retire_successes, ==, 1);
  g_assert_cmpuint (retire_rejections, ==, 1);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  WylFactArtifactMutationLease *contender = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &contender), ==, WYRELOG_E_BUSY);
  g_assert_null (contender);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  g_autofree gchar *sidecar_main_path = g_build_filename (graph_path,
      "facts.duckdb", NULL);
  g_autofree gchar *saved_sidecar_main_path = g_build_filename (graph_path,
      "facts.duckdb.sidecar-retire-saved", NULL);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (rename (sidecar_main_path, saved_sidecar_main_path), ==, 0);
  fd = open (sidecar_main_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (unlink (sidecar_main_path), ==, 0);
  g_assert_cmpint (rename (saved_sidecar_main_path, sidecar_main_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_autofree gchar *sidecar_lock_path = g_build_filename (graph_path,
      "facts.duckdb.lock", NULL);
  g_autofree gchar *saved_sidecar_lock_path = g_build_filename (graph_path,
      "facts.duckdb.lock.sidecar-retire-saved", NULL);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (rename (sidecar_lock_path, saved_sidecar_lock_path), ==, 0);
  fd = open (sidecar_lock_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (unlink (sidecar_lock_path), ==, 0);
  g_assert_cmpint (rename (saved_sidecar_lock_path, sidecar_lock_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
      (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (chmod (graph_path, 0755), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (chmod (graph_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (sidecar,
          &retirement), ==, WYRELOG_E_OK);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "spill-1",
          TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "spill-1",
          FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  WylFactArtifactTempBinding *writable_reopen = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "spill-1", FALSE, TRUE, &writable_reopen, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (writable_reopen);
  g_assert_cmpint (fd, ==, -1);
  WylFactArtifactTempBinding *binding = NULL;
  WylFactArtifactTempBinding *invalid_binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "../escape", TRUE, TRUE, &invalid_binding, &fd), ==,
      WYRELOG_E_INVALID);
  g_assert_null (invalid_binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "bound", TRUE, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (binding, TRUE, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  WylFactArtifactTempBinding *read_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "bound", FALSE, FALSE, &read_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (read_binding, TRUE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (read_binding, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (read_binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (read_binding,
          "read-moved"), ==, WYRELOG_E_POLICY);
  WylFactArtifactTempRecoveryEvidence *read_evidence = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
      (read_binding, &read_evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (read_evidence);
  wyl_fact_artifact_temp_binding_free (read_binding);
  WylFactArtifactTempBinding *unlink_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "unlink-owner", TRUE, TRUE, &unlink_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (unlink_binding), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (unlink_binding, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (unlink_binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "unlink-owner", FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_temp_binding_free (unlink_binding);
  WylFactArtifactTempBinding *fault_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "unlink-fault", TRUE, TRUE, &fault_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_UNLINK_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (fault_binding), ==,
      WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (fault_binding, FALSE,
          &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "unlink-fault", FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_temp_binding_free (fault_binding);
  WylFactArtifactTempBinding *rename_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "rename-source", TRUE, TRUE, &rename_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
          "rename-source"), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
          "../escape"), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
          "nested/token"), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
          "rename-destination"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (rename_binding, TRUE,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "rename-source", FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (rename_binding), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (rename_binding);
  WylFactArtifactTempBinding *overwrite_source = NULL;
  WylFactArtifactTempBinding *overwrite_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "overwrite-source", TRUE, TRUE, &overwrite_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "overwrite-destination", TRUE, TRUE, &overwrite_destination, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (overwrite_source,
          "overwrite-destination"), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (overwrite_source),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink
      (overwrite_destination), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (overwrite_source);
  wyl_fact_artifact_temp_binding_free (overwrite_destination);
  WylFactArtifactTempBinding *rename_fault = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "rename-fault-source", TRUE, TRUE, &rename_fault, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RENAME_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_fault,
          "rename-fault-destination"), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (rename_fault, FALSE,
          &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "rename-fault-source", FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (rename_fault), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (rename_fault);
  WylFactArtifactTempBinding *race_a = NULL;
  WylFactArtifactTempBinding *race_b = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "rename-race-a", TRUE, TRUE, &race_a, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "rename-race-b", TRUE, TRUE, &race_b, &fd), ==, WYRELOG_E_OK);
  close (fd);
  TempBindingRenameWorker rename_workers[] = {
    {race_a, "rename-race-destination", WYRELOG_E_INTERNAL},
    {race_b, "rename-race-destination", WYRELOG_E_INTERNAL},
  };
  GThread *rename_threads[] = {
    g_thread_new ("temp-rename-a", rename_temp_binding_worker,
        &rename_workers[0]),
    g_thread_new ("temp-rename-b", rename_temp_binding_worker,
        &rename_workers[1]),
  };
  g_thread_join (rename_threads[0]);
  g_thread_join (rename_threads[1]);
  g_assert_true ((rename_workers[0].result == WYRELOG_E_OK
          && rename_workers[1].result == WYRELOG_E_POLICY)
      || (rename_workers[1].result == WYRELOG_E_OK
          && rename_workers[0].result == WYRELOG_E_POLICY));
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (race_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (race_b), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (race_a);
  wyl_fact_artifact_temp_binding_free (race_b);
  WylFactArtifactTempBinding *linear_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "linear-race", TRUE, TRUE, &linear_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  TempBindingRenameWorker linear_rename = { linear_binding, "linear-moved",
    WYRELOG_E_INTERNAL
  };
  TempBindingUnlinkWorker linear_unlink =
      { linear_binding, WYRELOG_E_INTERNAL };
  GThread *linear_rename_thread = g_thread_new ("temp-linear-rename",
      rename_temp_binding_worker, &linear_rename);
  GThread *linear_unlink_thread = g_thread_new ("temp-linear-unlink",
      unlink_temp_binding_worker, &linear_unlink);
  g_thread_join (linear_rename_thread);
  g_thread_join (linear_unlink_thread);
  g_assert_true ((linear_rename.result == WYRELOG_E_OK
          && linear_unlink.result == WYRELOG_E_OK)
      || (linear_rename.result == WYRELOG_E_POLICY
          && linear_unlink.result == WYRELOG_E_OK));
  wyl_fact_artifact_temp_binding_free (linear_binding);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, "spill-1",
          TRUE, TRUE, &fd), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
          "../escape", TRUE, TRUE, &fd), ==, WYRELOG_E_INVALID);
  WylFactArtifactTempBinding *recovery_binding = NULL;
  WylFactArtifactTempRecoveryEvidence *evidence = NULL;
  WylFactArtifactTempRecoveryEvidence *decoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "recovery", TRUE, TRUE, &recovery_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
      (recovery_binding, &evidence), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_encode (evidence,
          &encoded), ==, WYRELOG_E_OK);
  gsize encoded_size = 0;
  const guint8 *encoded_data = g_bytes_get_data (encoded, &encoded_size);
  guint8 *tampered_data = g_memdup2 (encoded_data, encoded_size);
  tampered_data[5] ^= 1;
  g_autoptr (GBytes) tampered = g_bytes_new_take (tampered_data, encoded_size);
  WylFactArtifactTempRecoveryEvidence *tampered_evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode (tampered,
          &tampered_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          tampered_evidence), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_temp_recovery_evidence_free (tampered_evidence);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode (encoded,
          &decoded), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (recovery_binding);
  recovery_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          decoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          decoded), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_recovery_evidence_free (decoded);
  wyl_fact_artifact_temp_recovery_evidence_free (evidence);
  WylFactArtifactTempBinding *recovery_fault_binding = NULL;
  WylFactArtifactTempRecoveryEvidence *recovery_fault_evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "recovery-fault", TRUE, TRUE, &recovery_fault_binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
      (recovery_fault_binding, &recovery_fault_evidence), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (recovery_fault_binding);
  wyl_fact_artifact_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RECOVER_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          recovery_fault_evidence), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          recovery_fault_evidence), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_recovery_evidence_free (recovery_fault_evidence);
  WylFactArtifactTempBinding *wrong_binding = NULL;
  WylFactArtifactTempRecoveryEvidence *wrong_evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "recovery-wrong", TRUE, TRUE, &wrong_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
      (wrong_binding, &wrong_evidence), ==, WYRELOG_E_OK);
  g_autofree gchar *wrong_path =
      g_build_filename (graph_path, "tmp-recovery-wrong", NULL);
  /* Keep the binding's pin open while replacing the name.  Otherwise an
   * allocator may immediately recycle the unlinked inode, leaving this as a
   * same-identity replacement rather than the mismatch this test requires. */
  struct stat original_wrong, replacement_wrong;
  g_assert_cmpint (lstat (wrong_path, &original_wrong), ==, 0);
  g_assert_cmpint (unlink (wrong_path), ==, 0);
  fd = open (wrong_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (lstat (wrong_path, &replacement_wrong), ==, 0);
  g_assert_true (original_wrong.st_dev != replacement_wrong.st_dev
      || original_wrong.st_ino != replacement_wrong.st_ino);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp (lease,
          wrong_evidence), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_temp_binding_free (wrong_binding);
  wyl_fact_artifact_temp_recovery_evidence_free (wrong_evidence);
  g_assert_cmpint (unlink (wrong_path), ==, 0);
  WylFactArtifactTempBinding *substitution_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
          "substitute", TRUE, TRUE, &substitution_binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *substitution_path =
      g_build_filename (graph_path, "tmp-substitute", NULL);
  g_autofree gchar *protected_main_path =
      g_build_filename (graph_path, "facts.duckdb", NULL);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", substitution_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (substitution_binding),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  g_assert_cmpint (link (protected_main_path, substitution_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (substitution_binding,
          "substitute-moved"), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  wyl_fact_artifact_temp_binding_free (substitution_binding);
  g_autofree gchar *bound_path =
      g_build_filename (graph_path, "tmp-bound", NULL);
  /* An uncooperative pathname replacement cannot be adopted by the binding. */
  g_assert_cmpint (unlink (bound_path), ==, 0);
  fd = open (bound_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (binding, FALSE, &fd),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
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
          WYL_FACT_ARTIFACT_MAIN, WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_rename (lease,
          WYL_FACT_ARTIFACT_WAL, WYL_FACT_ARTIFACT_MAIN), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  /* The opaque binding retains the exclusive lease after its original owner
   * releases it; only releasing the binding makes a new writer admissible. */
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_BUSY);
  g_assert_null (lease);
  wyl_fact_artifact_temp_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (unlink (bound_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_lock (n, TRUE, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease (n,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_unlink (lease,
          WYL_FACT_ARTIFACT_MAIN), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_mutation_lease_free (lease);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
  wyl_fact_artifact_namespace_free (n);
  wyl_fact_graph_directory_clear (&d);
  wyl_fact_graph_locator_clear (&l);
  wyl_fact_graph_resolver_clear (&r);
  g_rmdir (root);
  g_free (root);
#endif
}

static void
test_duckdb_temp_root (void)
{
#ifdef G_OS_WIN32
  WylFactDuckdbTempRoot *root = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create (NULL, &root), ==,
      WYRELOG_E_POLICY);
  g_assert_null (root);
#else
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  WylFactDuckdbTempRoot *root = NULL;
  WylFactDuckdbTempChild *storage = NULL;
  g_autofree gchar *base = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (base, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
          TRUE, &directory), ==, WYRELOG_E_OK);
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
      (namespace_, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create (lease, &root), ==,
      WYRELOG_E_OK);
  /* Neither arbitrary descendants nor source-unsupported spellings acquire
   * creation authority. */
  gint fd = 42;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child (root, "other", NULL,
          &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child (root,
          "duckdb_temp_storage_S32K-0.tmp", &storage, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (fd, "x", 1), ==, 1);
  close (fd);
  fd = -1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child (root,
          "duckdb_temp_storage_S32K-0.tmp", NULL, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open (storage, FALSE, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  GPtrArray *listed = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 1);
  g_ptr_array_unref (listed);
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (retired, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_duckdb_temp_child_free (storage);
  storage = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (retired, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_duckdb_temp_root_free (root);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (wyl_fact_graph_directory_descriptive_path
      (&directory), WYL_FACT_ARTIFACT_MAIN);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_rmdir (base);
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func
      ("/fact-artifact-namespace/sidecar-retirement-result-contract",
      test_sidecar_retirement_result_contract);
  g_test_add_func ("/fact-artifact-namespace/basic", test_namespace);
  g_test_add_func ("/fact-artifact-namespace/mutation-leases",
      test_mutation_leases);
  g_test_add_func ("/fact-artifact-namespace/duckdb-temp-root",
      test_duckdb_temp_root);
  return g_test_run ();
}
