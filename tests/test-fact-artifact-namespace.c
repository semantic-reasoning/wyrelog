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
#include <sodium.h>
#endif
#include "fact/graph-artifact-namespace-private.h"

#define TOKEN_SIDE_REPLACE "00000000-0000-4000-8000-000000000001"
#define TOKEN_SIDE_REPLACE_WAL "00000000-0000-4000-8000-000000000002"
#define TOKEN_SIDE_REPLACE_FAULT "00000000-0000-4000-8000-000000000003"
#define TOKEN_SIDE_SOURCE "00000000-0000-4000-8000-000000000004"
#define TOKEN_SIDE_DEST "00000000-0000-4000-8000-000000000005"
#define TOKEN_SIDE_PRE "00000000-0000-4000-8000-000000000006"
#define TOKEN_SIDE_POST "00000000-0000-4000-8000-000000000007"
#define TOKEN_OVERWRITE_SOURCE "00000000-0000-4000-8000-000000000008"
#define TOKEN_OVERWRITE_DEST "00000000-0000-4000-8000-000000000009"
#define TOKEN_RENAME_FAULT_SOURCE "00000000-0000-4000-8000-00000000000a"
#define TOKEN_RENAME_FAULT_DEST "00000000-0000-4000-8000-00000000000b"
#define TOKEN_RENAME_RACE_A "00000000-0000-4000-8000-00000000000c"
#define TOKEN_RENAME_RACE_B "00000000-0000-4000-8000-00000000000d"
#define TOKEN_RENAME_RACE_DEST "00000000-0000-4000-8000-00000000000e"
#define TOKEN_LINEAR_RACE "00000000-0000-4000-8000-00000000000f"
#define TOKEN_LINEAR_MOVED "00000000-0000-4000-8000-000000000010"
#define TOKEN_RECOVERY "00000000-0000-4000-8000-000000000011"
#define TOKEN_RECOVERY_V2 "00000000-0000-4000-8000-00000000001e"
#define TOKEN_RECOVERY_FAULT "00000000-0000-4000-8000-000000000012"
#define TOKEN_RECOVERY_WRONG "00000000-0000-4000-8000-000000000013"
#define TOKEN_SUBSTITUTE "00000000-0000-4000-8000-000000000014"
#define TOKEN_SUBSTITUTE_MOVED "00000000-0000-4000-8000-000000000015"
#define TOKEN_UNLINK_OWNER "00000000-0000-4000-8000-000000000016"
#define TOKEN_UNLINK_FAULT "00000000-0000-4000-8000-000000000017"
#define TOKEN_SPILL "00000000-0000-4000-8000-000000000018"
#define TOKEN_BOUND "00000000-0000-4000-8000-000000000019"
#define TOKEN_READ_MOVED "00000000-0000-4000-8000-00000000001a"
#define TOKEN_RENAME_SOURCE "00000000-0000-4000-8000-00000000001b"
#define TOKEN_RENAME_DEST "00000000-0000-4000-8000-00000000001c"
#define TOKEN_READER "00000000-0000-4000-8000-00000000001d"
#include "fact/artifact-io-session-private.h"

#ifndef G_OS_WIN32
typedef struct
{
  guint8 key[32];
} RecoveryMacTestProvider;

static wyrelog_error_t
recovery_mac_test_compute (gpointer state, const guint8 *label, gsize label_len,
    const guint8 *payload, gsize payload_len,
    guint8 out_tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  RecoveryMacTestProvider *provider = state;
  g_autofree guint8 *input = g_malloc (label_len + payload_len);
  memcpy (input, label, label_len);
  memcpy (input + label_len, payload, payload_len);
  return crypto_generichash (out_tag, WYL_FACT_RECOVERY_MAC_TAG_BYTES, input,
             label_len + payload_len, provider->key, sizeof provider->key) == 0
      ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
recovery_mac_test_verify (gpointer state, const guint8 *label, gsize label_len,
    const guint8 *payload, gsize payload_len,
    const guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  guint8 expected[WYL_FACT_RECOVERY_MAC_TAG_BYTES];
  wyrelog_error_t r = recovery_mac_test_compute (state, label, label_len,
          payload, payload_len, expected);
  gboolean equal = sodium_memcmp (expected, tag, sizeof expected) == 0;
  sodium_memzero (expected, sizeof expected);
  return r == WYRELOG_E_OK && equal ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static void
recovery_mac_test_wipe (gpointer state)
{
  sodium_memzero (state, sizeof (RecoveryMacTestProvider));
}

static void
recovery_mac_test_free (gpointer state)
{
  g_free (state);
}

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
                                        "facts.duckdb.lock"};
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

static wyrelog_error_t
open_readonly_namespace (const WylFactGraphDirectory *directory,
    WylFactArtifactNamespace **out_namespace)
{
  if (out_namespace)
    *out_namespace = NULL;
  if (!directory || !out_namespace)
    return WYRELOG_E_INVALID;
  gint fd = openat (directory->graph_fd, "facts.duckdb",
          O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return WYRELOG_E_IO;
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
           pid, release[1]
  };
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

static LeaseHolderProcess
start_reader_binding_holder (const WylFactGraphDirectory *directory,
    gboolean crash_after_ready)
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
    WylFactArtifactMutationLease *reader = NULL;
    WylFactArtifactReaderMainBinding *main = NULL;
    WylFactArtifactReaderWalBinding *wal = NULL;
    gint main_fd = -1, wal_fd = -1;
    wyrelog_error_t result = open_namespace (directory, &namespace_);
    if (result == WYRELOG_E_OK)
      result = wyl_fact_artifact_namespace_acquire_reader_guard (namespace_,
              &reader);
    if (result == WYRELOG_E_OK)
      result = wyl_fact_artifact_reader_guard_open_main_binding (reader, &main,
              &main_fd);
    if (result == WYRELOG_E_OK)
      result = wyl_fact_artifact_reader_guard_open_existing_wal_binding (reader,
              &wal, &wal_fd);
    if (!write_exact (ready[1], &result, sizeof result))
      _exit (95);
    close (ready[1]);
    if (result != WYRELOG_E_OK || crash_after_ready)
      _exit (result == WYRELOG_E_OK ? 0 : 96);
    guint8 token;
    if (!read_exact (release[0], &token, sizeof token)) {
      close (release[0]);
      _exit (97);
    }
    close (release[0]);
    if (wyl_fact_artifact_reader_wal_binding_close (wal, &wal_fd)
        != WYRELOG_E_OK || wal_fd != -1
        || wyl_fact_artifact_reader_main_binding_close (main, &main_fd)
        != WYRELOG_E_OK || main_fd != -1)
      _exit (98);
    wyl_fact_artifact_reader_wal_binding_free (wal);
    wyl_fact_artifact_reader_main_binding_free (main);
    wyl_fact_artifact_mutation_lease_free (reader);
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
           pid, release[1]
  };
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
  WylFactArtifactSidecarBinding *binding;
  wyrelog_error_t result;
} SidecarRevalidateWorker;

static gpointer
revalidate_sidecar_binding_worker (gpointer data)
{
  SidecarRevalidateWorker *worker = data;
  worker->result = wyl_fact_artifact_sidecar_binding_revalidate
        (worker->binding);
  return NULL;
}

typedef struct
{
  WylFactGraphResolver resolver;
  WylFactGraphLocator locator;
  WylFactGraphDirectory directory;
  WylFactArtifactNamespace *namespace_;
  WylFactArtifactMutationLease *lease;
  gchar *base;
  gchar *graph_path;
} FixedSidecarReplaceFixture;

typedef struct
{
  WylFactArtifactSidecarBinding *source;
  WylFactArtifactSidecarBinding *destination;
  wyrelog_error_t error;
  WylFactArtifactSidecarReplaceResult result;
} FixedSidecarReplaceWorker;

static const gchar *
fixed_artifact_name_for_test (WylFactArtifactName name)
{
  static const gchar *const names[] = { "facts.duckdb", "facts.duckdb.wal",
                                        "facts.duckdb.wal.checkpoint", "facts.duckdb.wal.recovery",
                                        "facts.duckdb.lock"};
  g_assert_cmpint (name >= WYL_FACT_ARTIFACT_MAIN
      && name <= WYL_FACT_ARTIFACT_LOCK, ==, TRUE);
  return names[name];
}

static gchar *
fixed_artifact_path_for_test (FixedSidecarReplaceFixture *fixture,
    WylFactArtifactName name)
{
  return g_build_filename (fixture->graph_path,
             fixed_artifact_name_for_test (name), NULL);
}

static void
fixed_sidecar_replace_fixture_init (FixedSidecarReplaceFixture *fixture)
{
  *fixture = (FixedSidecarReplaceFixture) {
    .resolver = WYL_FACT_GRAPH_RESOLVER_INIT,.directory =
        WYL_FACT_GRAPH_DIRECTORY_INIT
  };
  fixture->base = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (fixture->base,
      &fixture->resolver), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&fixture->locator, "tenant",
      "graph"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&fixture->resolver,
      &fixture->locator, TRUE, &fixture->directory), ==, WYRELOG_E_OK);
  fixture->graph_path =
      wyl_fact_graph_directory_descriptive_path (&fixture->directory);
  g_assert_cmpint (open_namespace (&fixture->directory, &fixture->namespace_),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (fixture->namespace_, &fixture->lease), ==, WYRELOG_E_OK);
}

static void
fixed_sidecar_replace_fixture_reopen (FixedSidecarReplaceFixture *fixture)
{
  wyl_fact_artifact_mutation_lease_free (fixture->lease);
  fixture->lease = NULL;
  wyl_fact_artifact_namespace_free (fixture->namespace_);
  fixture->namespace_ = NULL;
  g_assert_cmpint (open_namespace (&fixture->directory, &fixture->namespace_),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (fixture->namespace_, &fixture->lease), ==, WYRELOG_E_OK);
}

static void
fixed_sidecar_replace_fixture_clear (FixedSidecarReplaceFixture *fixture)
{
  wyl_fact_artifact_mutation_lease_free (fixture->lease);
  wyl_fact_artifact_namespace_free (fixture->namespace_);
  for (WylFactArtifactName name = WYL_FACT_ARTIFACT_MAIN;
      name <= WYL_FACT_ARTIFACT_LOCK; name++) {
    g_autofree gchar *path = fixed_artifact_path_for_test (fixture, name);
    if (unlink (path) != 0)
      g_assert_cmpint (errno, ==, ENOENT);
  }
  wyl_fact_graph_directory_clear (&fixture->directory);
  wyl_fact_graph_locator_clear (&fixture->locator);
  wyl_fact_graph_resolver_clear (&fixture->resolver);
  g_autofree gchar *tenant_path = g_path_get_dirname (fixture->graph_path);
  g_assert_cmpint (g_rmdir (fixture->graph_path), ==, 0);
  g_assert_cmpint (g_rmdir (tenant_path), ==, 0);
  g_assert_cmpint (g_rmdir (fixture->base), ==, 0);
  g_clear_pointer (&fixture->graph_path, g_free);
  g_clear_pointer (&fixture->base, g_free);
}

static WylFactArtifactSidecarBinding *
create_closed_sidecar (FixedSidecarReplaceFixture *fixture,
    WylFactArtifactName name, const gchar *contents, struct stat *out_identity,
    gint *out_observer)
{
  WylFactArtifactSidecarBinding *binding = NULL;
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (fixture->lease, name, TRUE, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (ftruncate (fd, 0), ==, 0);
  g_assert_true (write_exact (fd, contents, strlen (contents)));
  g_assert_cmpint (fstat (fd, out_identity), ==, 0);
  if (out_observer) {
    *out_observer = fcntl (fd, F_DUPFD_CLOEXEC, 3);
    g_assert_cmpint (*out_observer, >=, 0);
  }
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (fd, ==, -1);
  return binding;
}

static void
assert_fixed_artifact (FixedSidecarReplaceFixture *fixture,
    WylFactArtifactName name, const struct stat *identity,
    const gchar *contents)
{
  g_autofree gchar *path = fixed_artifact_path_for_test (fixture, name);
  struct stat actual;
  g_assert_cmpint (lstat (path, &actual), ==, 0);
  g_assert_true (S_ISREG (actual.st_mode));
  g_assert_cmpuint ((guint64) actual.st_dev, ==, (guint64) identity->st_dev);
  g_assert_cmpuint ((guint64) actual.st_ino, ==, (guint64) identity->st_ino);
  g_autofree gchar *actual_contents = NULL;
  gsize actual_size = 0;
  g_assert_true (g_file_get_contents (path, &actual_contents, &actual_size,
      NULL));
  g_assert_cmpuint (actual_size, ==, strlen (contents));
  g_assert_cmpmem (actual_contents, actual_size, contents, strlen (contents));
}

static gpointer
replace_fixed_sidecar_worker (gpointer data)
{
  FixedSidecarReplaceWorker *worker = data;
  worker->result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
  worker->error = wyl_fact_artifact_sidecar_binding_replace_existing_wal
        (worker->source, worker->destination, &worker->result);
  return NULL;
}

static void
retire_closed_sidecar (WylFactArtifactSidecarBinding *binding)
{
  WylFactArtifactSidecarRetireResult result =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
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
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (writer, "low",
      TRUE, TRUE, &fd), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (fd, ==, -1);
  g_autofree gchar *legacy_path =
      g_build_filename (graph_path, "tmp-legacy-token", NULL);
  fd = open (legacy_path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  g_assert_cmpint (fd >= 0, ==, TRUE);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_namespace_open_temp (n, "legacy-token",
      FALSE, FALSE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (unlink (legacy_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (writer,
      TOKEN_READER, TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *generated_token = NULL;
  WylFactArtifactTempBinding *generated_binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_temp_binding_generated (writer,
      TRUE, &generated_token, &generated_binding, &fd), ==, WYRELOG_E_OK);
  g_assert_true (g_uuid_string_is_valid (generated_token));
  g_assert_cmphex (generated_token[14], ==, '4');
  g_assert_true (generated_token[19] == '8' || generated_token[19] == '9'
      || generated_token[19] == 'a' || generated_token[19] == 'b');
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (generated_binding),
      ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (generated_binding);
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
  g_assert_cmpint (wyl_fact_artifact_namespace_open_temp (n, TOKEN_READER,
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
      TOKEN_READER, FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
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

static void
test_main_binding (void)
{
#ifdef G_OS_WIN32
  WylFactArtifactMainBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (NULL,
      &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate (NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (NULL, 42), ==,
      WYRELOG_E_POLICY);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_main_binding_close (NULL, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, 42);
#else
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *reader = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  WylFactArtifactMainBinding *binding = NULL;
  g_autofree gchar *base = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (base, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path
        (&directory);
  /* First create the artifact, then import only a read-only caller fd. */
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_cmpint (open_readonly_namespace (&directory, &namespace_), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader), ==, WYRELOG_E_OK);
  gint fd = 42;
  WylFactArtifactMainBinding *rejected = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (reader,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader);
  reader = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (namespace_,
      WYL_FACT_ARTIFACT_MAIN, FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
      WYL_FACT_ARTIFACT_MAIN, FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  g_assert_cmpint (fcntl (fd, F_GETFD) & FD_CLOEXEC, !=, 0);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (pwrite (fd, "main", 4, 0), ==, 4);
  g_assert_cmpint (ftruncate (fd, 4), ==, 0);
  g_assert_cmpint (fsync (fd), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_OK);
  char contents[5] = { 0 };
  g_assert_cmpint (pread (fd, contents, 4, 0), ==, 4);
  g_assert_cmpstr (contents, ==, "main");
  /* The binding itself retains the lease after the caller drops its handle. */
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_OK);
  WylFactArtifactNamespace *contender = NULL;
  g_assert_cmpint (open_namespace (&directory, &contender), ==, WYRELOG_E_OK);
  WylFactArtifactMutationLease *contender_lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (contender, &contender_lease), ==, WYRELOG_E_BUSY);
  g_assert_null (contender_lease);
  wyl_fact_artifact_namespace_free (contender);
  g_assert_cmpint (wyl_fact_artifact_main_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_main_binding_free (binding);
  binding = NULL;

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &binding, &fd), ==, WYRELOG_E_OK);
  /* dup2 models close plus exact-number reuse without relying on allocator
   * behavior.  The provider must reject it rather than validating only pin. */
  gint foreign_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_fd, fd), ==, fd);
  if (foreign_fd != fd)
    close (foreign_fd);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_main_binding_free (binding);
  binding = NULL;

  /* A renamed/replaced canonical name revokes the capability permanently and
   * does not write the foreign replacement. */
  g_autofree gchar *main_path = g_build_filename (graph_path,
          "facts.duckdb", NULL);
  g_autofree gchar *saved_path = g_build_filename (graph_path,
          "facts.duckdb.saved", NULL);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (rename (main_path, saved_path), ==, 0);
  g_assert_true (g_file_set_contents (main_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (main_path), ==, 0);
  g_assert_cmpint (rename (saved_path, main_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (binding, fd),
      ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_main_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;

  /* Fresh namespace: links and mode changes prevent minting with no mutation
   * by the authority itself. */
  wyl_fact_artifact_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  g_autofree gchar *hard = g_build_filename (graph_path, "main-hard", NULL);
  g_assert_cmpint (link (main_path, hard), ==, 0);
  fd = 42;
  rejected = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (unlink (hard), ==, 0);
  g_assert_cmpint (g_chmod (main_path, 0644), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  /* A missing fixed name is distinguishable; malformed replacements are not
   * adopted and remain untouched by the binding authority. */
  g_assert_cmpint (rename (main_path, saved_path), ==, 0);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (rejected);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (rename (saved_path, main_path), ==, 0);
  g_assert_cmpint (rename (main_path, saved_path), ==, 0);
  g_assert_cmpint (symlink ("/dev/null", main_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (unlink (main_path), ==, 0);
  g_assert_cmpint (rename (saved_path, main_path), ==, 0);
  g_assert_cmpint (rename (main_path, saved_path), ==, 0);
  g_assert_cmpint (mkdir (main_path, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (rmdir (main_path), ==, 0);
  g_assert_cmpint (rename (saved_path, main_path), ==, 0);
  /* The deterministic post-open ABA seam replaces the pathname after the RW
   * descriptor exists.  Minting rejects it and has not written the foreign
   * replacement.  The original remains only in namespace-held descriptors. */
  fd = 42;
  rejected = (gpointer) 0x1;
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_MAIN_BINDING_POST_OPEN_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (lease,
      &rejected, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (fd, ==, -1);
  struct stat foreign_stat;
  g_assert_cmpint (stat (main_path, &foreign_stat), ==, 0);
  g_assert_cmpint (foreign_stat.st_size, ==, 0);
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_LOCK);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_autofree gchar *tenant_path = g_path_get_dirname (graph_path);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_assert_cmpint (g_rmdir (tenant_path), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
#endif
}

static void
test_reader_main_binding (void)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *reader_a = NULL;
  WylFactArtifactMutationLease *reader_b = NULL;
  WylFactArtifactMutationLease *writer = NULL;
  WylFactArtifactReaderMainBinding *binding = NULL;
  g_autofree gchar *base = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (base, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path
        (&directory);
  g_autofree gchar *main_path = g_build_filename (graph_path,
          "facts.duckdb", NULL);
  g_autofree gchar *saved_path = g_build_filename (graph_path,
          "facts.duckdb.saved", NULL);
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_true (g_file_set_contents (main_path, "read", 4, NULL));
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  g_assert_cmpint (open_readonly_namespace (&directory, &namespace_), ==,
      WYRELOG_E_OK);
  g_autofree gchar *wal_path = g_build_filename (graph_path,
          "facts.duckdb.wal", NULL);
  g_autofree gchar *saved_wal_path = g_build_filename (graph_path,
          "facts.duckdb.wal.saved", NULL);

  WylFactArtifactReaderWalBinding *reader_wal = (gpointer) 0x1;
  gint wal_fd = 42;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (reader_a, &reader_wal, &wal_fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (reader_wal);
  g_assert_cmpint (wal_fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_OK);
  WylFactArtifactSidecarBinding *writer_wal = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (writer, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &writer_wal, &wal_fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (pwrite (wal_fd, "wal", 3, 0), ==, 3);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (writer_wal,
      &wal_fd), ==, WYRELOG_E_OK);
  wyl_fact_artifact_sidecar_binding_free (writer_wal);
  wyl_fact_artifact_mutation_lease_free (writer);
  writer = NULL;
  LeaseHolderProcess holder = start_reader_binding_holder (&directory, FALSE);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  stop_lease_holder_process (holder);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (writer);
  writer = NULL;
  holder = start_reader_binding_holder (&directory, TRUE);
  gint child_status = 0;
  g_assert_cmpint (waitpid (holder.pid, &child_status, 0), ==, holder.pid);
  g_assert_true (WIFEXITED (child_status) && WEXITSTATUS (child_status) == 0);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (writer);
  writer = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (reader_a, &reader_wal, &wal_fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (fcntl (wal_fd, F_GETFL) & O_ACCMODE, ==, O_RDONLY);
  g_assert_cmpint (fcntl (wal_fd, F_GETFD) & FD_CLOEXEC, !=, 0);
  char wal_contents[4] = { 0 };
  g_assert_cmpint (pread (wal_fd, wal_contents, 3, 0), ==, 3);
  g_assert_cmpstr (wal_contents, ==, "wal");
  errno = 0;
  g_assert_cmpint (pwrite (wal_fd, "x", 1, 0), ==, -1);
  g_assert_cmpint (errno, ==, EBADF);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_close (reader_wal,
      &wal_fd), ==, WYRELOG_E_OK);
  wyl_fact_artifact_reader_wal_binding_free (reader_wal);
  reader_wal = NULL;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (reader_a, &reader_wal, &wal_fd), ==, WYRELOG_E_OK);
  gint foreign_wal_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_wal_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_wal_fd, wal_fd), ==, wal_fd);
  if (foreign_wal_fd != wal_fd)
    close (foreign_wal_fd);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_revalidate_fd
        (reader_wal, wal_fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_close (reader_wal,
      &wal_fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wal_fd, >=, 0);
  close (wal_fd);
  wyl_fact_artifact_reader_wal_binding_free (reader_wal);
  reader_wal = NULL;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (reader_a, &reader_wal, &wal_fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (rename (wal_path, saved_wal_path), ==, 0);
  g_assert_true (g_file_set_contents (wal_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (wal_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_revalidate_fd
        (reader_wal, wal_fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_close (reader_wal,
      &wal_fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wal_fd, >=, 0);
  close (wal_fd);
  wyl_fact_artifact_reader_wal_binding_free (reader_wal);
  reader_wal = NULL;
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (rename (saved_wal_path, wal_path), ==, 0);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  reader_wal = (gpointer) 0x1;
  wal_fd = 42;
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_READER_WAL_BINDING_PRE_OPEN_FIFO);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (reader_a, &reader_wal, &wal_fd), ==, WYRELOG_E_POLICY);
  g_assert_null (reader_wal);
  g_assert_cmpint (wal_fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_b), ==, WYRELOG_E_OK);
  gint fd = -1;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (reader_a,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (fcntl (fd, F_GETFL) & O_ACCMODE, ==, O_RDONLY);
  g_assert_cmpint (fcntl (fd, F_GETFD) & FD_CLOEXEC, !=, 0);
  char contents[5] = { 0 };
  g_assert_cmpint (pread (fd, contents, 4, 0), ==, 4);
  g_assert_cmpstr (contents, ==, "read");
  errno = 0;
  g_assert_cmpint (pwrite (fd, "x", 1, 0), ==, -1);
  g_assert_cmpint (errno, ==, EBADF);
  errno = 0;
  g_assert_cmpint (ftruncate (fd, 0), ==, -1);
  /* A valid read-only fd is rejected as EINVAL on Linux; some POSIX hosts
   * report EBADF instead. */
  g_assert_true (errno == EINVAL || errno == EBADF);
  /* fsync may legally succeed for a read-only descriptor; it has no mutation
   * authority, so the byte check below is the relevant contract. */
  (void) fsync (fd);
  memset (contents, 0, sizeof contents);
  g_assert_cmpint (pread (fd, contents, 4, 0), ==, 4);
  g_assert_cmpstr (contents, ==, "read");
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  wyl_fact_artifact_mutation_lease_free (reader_b);
  reader_b = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_close (binding, &fd),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_revalidate_fd
        (binding, fd), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_reader_main_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &writer), ==, WYRELOG_E_OK);
  binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (writer,
      &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (writer);
  writer = NULL;

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (reader_a,
      &binding, &fd), ==, WYRELOG_E_OK);
  gint foreign_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_fd, fd), ==, fd);
  if (foreign_fd != fd)
    close (foreign_fd);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_revalidate_fd
        (binding, fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_close (binding, &fd),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, >=, 0);
  close (fd);
  wyl_fact_artifact_reader_main_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;

  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (reader_a,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (rename (main_path, saved_path), ==, 0);
  g_assert_true (g_file_set_contents (main_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_revalidate_fd
        (binding, fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_close (binding, &fd),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, >=, 0);
  close (fd);
  wyl_fact_artifact_reader_main_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (unlink (main_path), ==, 0);
  g_assert_cmpint (rename (saved_path, main_path), ==, 0);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  reader_a = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader_a), ==, WYRELOG_E_OK);
  binding = (gpointer) 0x1;
  fd = 42;
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_READER_MAIN_BINDING_PRE_OPEN_FIFO);
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (reader_a,
      &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader_a);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_LOCK);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_autofree gchar *tenant_path = g_path_get_dirname (graph_path);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_assert_cmpint (g_rmdir (tenant_path), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
}

static void
test_existing_sidecar_reopen (void)
{
#ifdef G_OS_WIN32
  WylFactArtifactSidecarBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (NULL,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
#else
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  g_autofree gchar *root = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&directory);
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);

  /* A reader guard has no recovery mutation authority, even for a missing
   * sidecar; it must not acquire creation rights as a side effect. */
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  WylFactArtifactMutationLease *reader = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_reader_guard
        (namespace_, &reader), ==, WYRELOG_E_OK);
  WylFactArtifactSidecarBinding *reader_binding = (gpointer) 0x1;
  gint reader_fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (reader,
      WYL_FACT_ARTIFACT_WAL, TRUE, &reader_binding, &reader_fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (reader_binding);
  g_assert_cmpint (reader_fd, ==, -1);
  wyl_fact_artifact_mutation_lease_free (reader);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);

  WylFactArtifactSidecarBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_MAIN, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);

  const WylFactArtifactName sidecars[] = { WYL_FACT_ARTIFACT_WAL,
                                           WYL_FACT_ARTIFACT_CHECKPOINT, WYL_FACT_ARTIFACT_RECOVERY};
  g_autofree gchar *binding_wal_path = g_build_filename (graph_path,
          "facts.duckdb.wal", NULL);
  for (guint i = 0; i < G_N_ELEMENTS (sidecars); i++) {
    g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
          (lease, sidecars[i], TRUE, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
        fd), ==, WYRELOG_E_OK);
    g_assert_true (write_exact (fd, "c", 1));
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
        fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (fd, ==, -1);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
        fd), ==, WYRELOG_E_POLICY);
    wyl_fact_artifact_sidecar_binding_free (binding);
    binding = NULL;
    fd = -1;
    g_assert_cmpint
      (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
        sidecars[i], TRUE, &binding, &fd), ==, WYRELOG_E_OK);
    g_assert_true (write_exact (fd, "r", 1));
    g_assert_cmpint (fsync (fd), ==, 0);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
        fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (fd, ==, -1);
    wyl_fact_artifact_sidecar_binding_free (binding);
    binding = NULL;
    g_assert_cmpint
      (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
        sidecars[i], TRUE, &binding, &fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
        fd), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd),
        ==, WYRELOG_E_OK);
    SidecarRevalidateWorker workers[2] = { {binding, WYRELOG_E_INTERNAL},
                                           {binding, WYRELOG_E_INTERNAL}};
    GThread *first = g_thread_new ("sidecar-revalidate-a",
            revalidate_sidecar_binding_worker, &workers[0]);
    GThread *second = g_thread_new ("sidecar-revalidate-b",
            revalidate_sidecar_binding_worker, &workers[1]);
    g_thread_join (first);
    g_thread_join (second);
    g_assert_cmpint (workers[0].result, ==, WYRELOG_E_OK);
    g_assert_cmpint (workers[1].result, ==, WYRELOG_E_OK);
    WylFactArtifactSidecarRetireResult retired =
        WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding,
        &retired), ==, WYRELOG_E_OK);
    g_assert_cmpint (retired, ==,
        WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
    wyl_fact_artifact_sidecar_binding_free (binding);
    binding = NULL;
  }

  /* dup2 models close plus exact-number reuse.  Checked close must not close
   * the foreign replacement, and an I/O-boundary mismatch revokes the binding
   * even if the number later appears usable again. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding, &fd), ==,
      WYRELOG_E_OK);
  WylFactArtifactSidecarRetireResult live_retirement =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding,
      &live_retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (live_retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_true (g_file_test (binding_wal_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
        (binding, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  g_assert_true (g_file_test (binding_wal_path, G_FILE_TEST_EXISTS));
  gint foreign_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_fd, fd), ==, fd);
  if (foreign_fd != fd)
    close (foreign_fd);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding,
      &live_retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (live_retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
        (binding, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  g_assert_true (g_file_test (binding_wal_path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fcntl (fd, F_GETFD), !=, -1);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (unlink (binding_wal_path), ==, 0);

  /* Strict existing-entry validation rejects malformed filesystem objects;
   * the failed open never creates, replaces, or mutates them. */
  g_autofree gchar *wal_path = g_build_filename (graph_path,
          "facts.duckdb.wal", NULL);
  g_assert_cmpint (g_close (g_open (wal_path, O_CREAT | O_EXCL | O_RDWR,
      0600), NULL), ==, TRUE);
  g_assert_cmpint (g_chmod (wal_path, 0644), ==, 0);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (g_chmod (wal_path, 0600), ==, 0);
  g_autofree gchar *alias = g_build_filename (graph_path, "wal-alias", NULL);
  g_assert_cmpint (link (wal_path, alias), ==, 0);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (unlink (alias), ==, 0);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", wal_path), ==, 0);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (mkdir (wal_path, 0700), ==, 0);
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (rmdir (wal_path), ==, 0);

  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  /* Pin and named-entry policy both participate in every FD revalidation.
   * Restoration cannot reactivate a binding that observed a mode/link seam. */
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (fchmod (fd, 0644), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fchmod (fd, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_autofree gchar *terminal_alias = g_build_filename (graph_path,
          "wal-terminal-alias", NULL);
  g_assert_cmpint (link (wal_path, terminal_alias), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (terminal_alias), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_autofree gchar *saved = g_build_filename (graph_path, "wal-saved", NULL);
  g_assert_cmpint (rename (wal_path, saved), ==, 0);
  g_assert_cmpint (g_close (g_open (wal_path, O_CREAT | O_EXCL | O_RDWR,
      0600), NULL), ==, TRUE);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (rename (saved, wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  /* An existing recovery binding has no publication authority. */
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
        (binding, WYL_FACT_ARTIFACT_CHECKPOINT), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_OK);
  gint probe_fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &probe_fd), ==, WYRELOG_E_OK);
  close (probe_fd);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_file (lease,
      WYL_FACT_ARTIFACT_CHECKPOINT, FALSE, FALSE, &probe_fd), ==,
      WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_sidecar_binding_free (binding);

  /* A missing probe cannot turn an attacker-created, secure-looking sidecar
   * into a strict-create result.  The attempted creator gets no binding or
   * fd and leaves the attacker's bytes untouched. */
  g_assert_cmpint (unlink (wal_path), ==, 0);
  binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_true (g_file_set_contents (wal_path, "attacker", -1, NULL));
  g_assert_cmpint (g_chmod (wal_path, 0600), ==, 0);
  binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_autofree gchar *attacker_contents = NULL;
  g_assert_true (g_file_get_contents (wal_path, &attacker_contents, NULL,
      NULL));
  g_assert_cmpstr (attacker_contents, ==, "attacker");
  g_assert_cmpint (unlink (wal_path), ==, 0);

  /* Recreate a known binding, then prove each held namespace component is
   * checked at the explicit raw-FD I/O boundary. */
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_autofree gchar *main_path = g_build_filename (graph_path,
          "facts.duckdb", NULL);
  g_autofree gchar *saved_main = g_build_filename (graph_path,
          "facts.duckdb.saved", NULL);
  g_assert_cmpint (rename (main_path, saved_main), ==, 0);
  g_assert_true (g_file_set_contents (main_path, "foreign-main", -1, NULL));
  g_assert_cmpint (g_chmod (main_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  WylFactArtifactSidecarBinding *rejected = (gpointer) 0x1;
  gint rejected_fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &rejected, &rejected_fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (rejected_fd, ==, -1);
  g_autofree gchar *foreign_contents = NULL;
  g_assert_true (g_file_get_contents (main_path, &foreign_contents, NULL,
      NULL));
  g_assert_cmpstr (foreign_contents, ==, "foreign-main");
  g_assert_cmpint (unlink (main_path), ==, 0);
  g_assert_cmpint (rename (saved_main, main_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);

  g_autofree gchar *lock_path = g_build_filename (graph_path,
          "facts.duckdb.lock", NULL);
  g_autofree gchar *saved_lock = g_build_filename (graph_path,
          "facts.duckdb.lock.saved", NULL);
  g_assert_cmpint (rename (lock_path, saved_lock), ==, 0);
  g_assert_true (g_file_set_contents (lock_path, "foreign-lock", -1, NULL));
  g_assert_cmpint (g_chmod (lock_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  rejected = (gpointer) 0x1;
  rejected_fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &rejected, &rejected_fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (rejected_fd, ==, -1);
  g_clear_pointer (&foreign_contents, g_free);
  g_assert_true (g_file_get_contents (lock_path, &foreign_contents, NULL,
      NULL));
  g_assert_cmpstr (foreign_contents, ==, "foreign-lock");
  g_assert_cmpint (unlink (lock_path), ==, 0);
  g_assert_cmpint (rename (saved_lock, lock_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);

  /* The held graph directory is the authority, not its original spelling.
   * A replacement spelling cannot divert this binding; an observed invalid
   * held directory still fails closed without touching the foreign tree. */
  g_autofree gchar *parent_path = g_path_get_dirname (graph_path);
  g_autofree gchar *saved_graph = g_build_filename (parent_path,
          "graph-saved", NULL);
  g_assert_cmpint (rename (graph_path, saved_graph), ==, 0);
  g_assert_cmpint (mkdir (graph_path, 0700), ==, 0);
  g_autofree gchar *foreign_graph_file = g_build_filename (graph_path,
          "foreign", NULL);
  g_assert_true (g_file_set_contents (foreign_graph_file, "foreign-graph",
      -1, NULL));
  g_assert_cmpint (fchmod (directory.graph_fd, 0755), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  rejected = (gpointer) 0x1;
  rejected_fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &rejected, &rejected_fd), ==,
      WYRELOG_E_POLICY);
  g_assert_null (rejected);
  g_assert_cmpint (rejected_fd, ==, -1);
  g_clear_pointer (&foreign_contents, g_free);
  g_assert_true (g_file_get_contents (foreign_graph_file, &foreign_contents,
      NULL, NULL));
  g_assert_cmpstr (foreign_contents, ==, "foreign-graph");
  g_assert_cmpint (fchmod (directory.graph_fd, 0700), ==, 0);
  g_assert_cmpint (unlink (foreign_graph_file), ==, 0);
  g_assert_cmpint (rmdir (graph_path), ==, 0);
  g_assert_cmpint (rename (saved_graph, graph_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);

  g_assert_cmpint (rename (wal_path, saved), ==, 0);
  g_assert_true (g_file_set_contents (wal_path, "foreign-wal", -1, NULL));
  g_assert_cmpint (g_chmod (wal_path, 0600), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  g_clear_pointer (&foreign_contents, g_free);
  g_assert_true (g_file_get_contents (wal_path, &foreign_contents, NULL, NULL));
  g_assert_cmpstr (foreign_contents, ==, "foreign-wal");
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (rename (saved, wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  close (fd);
  g_assert_cmpint (unlink (wal_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  WylFactArtifactSidecarRetireResult reconciled =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding,
      &reconciled), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (reconciled, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_sidecar_binding_free (binding);

  /* The binding retains the exclusive lease until release, so it survives the
   * caller's lease reference and can still perform terminal retirement. */
  binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_sidecar_binding_free (binding);
  binding = NULL;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (binding), ==,
      WYRELOG_E_OK);
  WylFactArtifactSidecarRetireResult retired =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (binding, &retired),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (retired, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_sidecar_binding_free (binding);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_LOCK);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_autofree gchar *tenant_path = g_path_get_dirname (graph_path);
  g_assert_cmpint (g_rmdir (tenant_path), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
#endif
}
#endif

#ifndef G_OS_WIN32
/* The bounded session opener demultiplexes onto two mutually exclusive
 * artifact authorities: the recovery authority is writable-only and never
 * creates, while the general authority refuses a writable open that is not
 * also a create.  Pin every (create, writable) outcome so a dispatch that
 * sends a read-only reopen to the recovery authority -- which answers
 * WYRELOG_E_POLICY before it ever reaches the filesystem -- cannot regress
 * unnoticed behind the DuckDB integration suite. */
static void
test_io_session_sidecar_dispatch (void)
{
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  WylFactArtifactIoSession *session = NULL;
  g_autofree gchar *root = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path =
      wyl_fact_graph_directory_descriptive_path (&directory);
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);

  /* An absent sidecar reports absence, not a policy refusal: the adapter
   * relies on NOT_FOUND to fall through to its creating open. */
  g_assert_cmpint (wyl_fact_artifact_io_session_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &session), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (session);

  g_assert_cmpint (wyl_fact_artifact_io_session_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &session), ==, WYRELOG_E_OK);
  g_assert_nonnull (session);
  g_assert_cmpint (wyl_fact_artifact_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  /* The regression: a read-only reopen of an extant sidecar must reach the
   * general authority. */
  g_assert_cmpint (wyl_fact_artifact_io_session_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, FALSE, &session), ==, WYRELOG_E_OK);
  g_assert_nonnull (session);
  g_assert_cmpint (wyl_fact_artifact_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  /* A writable reopen without create is the recovery authority's one cell. */
  g_assert_cmpint (wyl_fact_artifact_io_session_open_sidecar (lease,
      WYL_FACT_ARTIFACT_WAL, FALSE, TRUE, &session), ==, WYRELOG_E_OK);
  g_assert_nonnull (session);
  g_assert_cmpint (wyl_fact_artifact_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  /* A read-only create stays with the general authority. */
  g_assert_cmpint (wyl_fact_artifact_io_session_open_sidecar (lease,
      WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, FALSE, &session), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (session);
  g_assert_cmpint (wyl_fact_artifact_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_CHECKPOINT);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_LOCK);
  wyl_fact_graph_directory_clear (&directory);
  wyl_fact_graph_locator_clear (&locator);
  wyl_fact_graph_resolver_clear (&resolver);
  g_assert_cmpint (g_rmdir (graph_path), ==, 0);
  g_autofree gchar *tenant_path = g_path_get_dirname (graph_path);
  g_assert_cmpint (g_rmdir (tenant_path), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}
#endif

#ifdef G_OS_WIN32
static void
test_existing_sidecar_reopen (void)
{
  WylFactArtifactSidecarBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (NULL,
      WYL_FACT_ARTIFACT_WAL, TRUE, &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate_fd (NULL, 42),
      ==, WYRELOG_E_POLICY);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (NULL, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, 42);
}

static void
test_main_binding (void)
{
  WylFactArtifactMainBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_main_binding (NULL,
      &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate (NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_main_binding_revalidate_fd (NULL, 42), ==,
      WYRELOG_E_POLICY);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_main_binding_close (NULL, &fd), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, 42);
}

static void
test_reader_main_binding (void)
{
  WylFactArtifactReaderMainBinding *binding = (gpointer) 0x1;
  gint fd = 42;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_main_binding (NULL,
      &binding, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_revalidate (NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_revalidate_fd (NULL,
      42), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_main_binding_close (NULL, &fd),
      ==, WYRELOG_E_POLICY);
  WylFactArtifactReaderWalBinding *wal = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_reader_guard_open_existing_wal_binding
        (NULL, &wal, &fd), ==, WYRELOG_E_POLICY);
  g_assert_null (wal);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_revalidate (NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_revalidate_fd (NULL,
      42), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_reader_wal_binding_close (NULL, &fd), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_reader_wal_binding_free (NULL);
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
  WylFactArtifactSidecarReplaceResult replacement =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (NULL, NULL,
      &replacement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replacement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (NULL, NULL,
      NULL), ==, WYRELOG_E_POLICY);
}

static void
test_fixed_sidecar_replacement_success (void)
{
#ifdef G_OS_WIN32
  WylFactArtifactSidecarReplaceResult result =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal
        ((WylFactArtifactSidecarBinding *) 0x1,
      (WylFactArtifactSidecarBinding *) 0x2, &result), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
#else
  gint baseline_fds = count_open_fds ();
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  const WylFactArtifactName sources[] = {
    WYL_FACT_ARTIFACT_CHECKPOINT, WYL_FACT_ARTIFACT_RECOVERY
  };
  const gchar *const contents[] = { "checkpoint-bytes", "recovery-bytes" };
  for (guint i = 0; i < G_N_ELEMENTS (sources); i++) {
    struct stat source_identity, old_wal_identity, unlinked_old_wal;
    gint old_wal_observer = -1;
    WylFactArtifactSidecarBinding *destination =
        create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old-wal",
            &old_wal_identity, &old_wal_observer);
    WylFactArtifactSidecarBinding *source =
        create_closed_sidecar (&fixture, sources[i], contents[i],
            &source_identity, NULL);
    WylFactArtifactSidecarReplaceResult result =
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
    g_assert_cmpint
      (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
        destination, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==,
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_REPLACED_DURABLE);
    g_assert_cmpint (fstat (old_wal_observer, &unlinked_old_wal), ==, 0);
    g_assert_cmpuint ((guint64) unlinked_old_wal.st_dev, ==,
        (guint64) old_wal_identity.st_dev);
    g_assert_cmpuint ((guint64) unlinked_old_wal.st_ino, ==,
        (guint64) old_wal_identity.st_ino);
    g_assert_cmpuint (unlinked_old_wal.st_nlink, ==, 0);
    close (old_wal_observer);
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL, &source_identity,
        contents[i]);
    g_autofree gchar *source_path =
        fixed_artifact_path_for_test (&fixture, sources[i]);
    g_assert_false (g_file_test (source_path, G_FILE_TEST_EXISTS));
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
        ==, WYRELOG_E_OK);
    result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
    g_assert_cmpint
      (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
        destination, &result), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (result, ==,
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
    wyl_fact_artifact_sidecar_binding_free (source);
    wyl_fact_artifact_sidecar_binding_free (destination);

    /* A fresh namespace classifies only the post-replacement WAL and can bind
     * the transferred identity; the fixed recovery source is not rediscovered. */
    fixed_sidecar_replace_fixture_reopen (&fixture);
    WylFactArtifactSidecarBinding *reopened = NULL;
    gint fd = -1;
    g_assert_cmpint
      (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
          (fixture.lease, WYL_FACT_ARTIFACT_WAL, TRUE, &reopened, &fd), ==,
        WYRELOG_E_OK);
    gchar actual[32] = { 0 };
    g_assert_cmpint (pread (fd, actual, strlen (contents[i]), 0), ==,
        (gssize) strlen (contents[i]));
    g_assert_cmpmem (actual, strlen (contents[i]), contents[i],
        strlen (contents[i]));
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (reopened, &fd),
        ==, WYRELOG_E_OK);
    WylFactArtifactSidecarBinding *absent = (gpointer) 0x1;
    fd = 42;
    g_assert_cmpint
      (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
          (fixture.lease, sources[i], TRUE, &absent, &fd), ==,
        WYRELOG_E_NOT_FOUND);
    g_assert_null (absent);
    g_assert_cmpint (fd, ==, -1);
    retire_closed_sidecar (reopened);
    wyl_fact_artifact_sidecar_binding_free (reopened);
  }
  fixed_sidecar_replace_fixture_clear (&fixture);
  g_assert_cmpint (count_open_fds (), ==, baseline_fds);
#endif
}

#ifndef G_OS_WIN32
static void
run_fixed_sidecar_replace_fault (WylFactArtifactNamespaceTestFault fault,
    gboolean after_linearization)
{
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  struct stat source_identity, destination_identity;
  WylFactArtifactSidecarBinding *destination =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old",
          &destination_identity, NULL);
  WylFactArtifactSidecarBinding *source =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_CHECKPOINT, "new",
          &source_identity, NULL);
  wyl_fact_artifact_namespace_set_test_fault (fault);
  WylFactArtifactSidecarReplaceResult result =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  wyrelog_error_t error =
      wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
          destination, &result);
  g_assert_cmpint (error, !=, WYRELOG_E_OK);
  if (after_linearization) {
    g_assert_cmpint (result, ==,
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
        ==, WYRELOG_E_OK);
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL, &source_identity,
        "new");
    g_autofree gchar *source_path = fixed_artifact_path_for_test (&fixture,
            WYL_FACT_ARTIFACT_CHECKPOINT);
    g_assert_false (g_file_test (source_path, G_FILE_TEST_EXISTS));
  } else {
    g_assert_cmpint (result, ==,
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
        ==, WYRELOG_E_OK);
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_CHECKPOINT,
        &source_identity, "new");
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL,
        &destination_identity, "old");
  }
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);

  /* Model process restart at every deterministic crash seam.  Re-minting
   * authority must classify exactly the complete pre-pair or the complete
   * post-replacement WAL, never an intermediate namespace. */
  fixed_sidecar_replace_fixture_reopen (&fixture);
  WylFactArtifactSidecarBinding *reopened_destination = NULL;
  gint fd = -1;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_WAL, TRUE, &reopened_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close
        (reopened_destination, &fd), ==, WYRELOG_E_OK);
  assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL,
      after_linearization ? &source_identity : &destination_identity,
      after_linearization ? "new" : "old");
  WylFactArtifactSidecarBinding *reopened_source = (gpointer) 0x1;
  fd = 42;
  wyrelog_error_t source_open =
      wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, &reopened_source,
          &fd);
  if (after_linearization) {
    g_assert_cmpint (source_open, ==, WYRELOG_E_NOT_FOUND);
    g_assert_null (reopened_source);
    g_assert_cmpint (fd, ==, -1);
  } else {
    g_assert_cmpint (source_open, ==, WYRELOG_E_OK);
    g_assert_nonnull (reopened_source);
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (reopened_source,
        &fd), ==, WYRELOG_E_OK);
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_CHECKPOINT,
        &source_identity, "new");
    retire_closed_sidecar (reopened_source);
    wyl_fact_artifact_sidecar_binding_free (reopened_source);
  }
  retire_closed_sidecar (reopened_destination);
  wyl_fact_artifact_sidecar_binding_free (reopened_destination);
  fixed_sidecar_replace_fixture_clear (&fixture);
}
#endif

static void
test_fixed_sidecar_replacement_faults (void)
{
#ifndef G_OS_WIN32
  const WylFactArtifactNamespaceTestFault before[] = {
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_SOURCE_FSYNC,
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_PRE_RENAME,
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_RENAME,
  };
  const WylFactArtifactNamespaceTestFault after[] = {
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_POST_LINEARIZATION,
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_DIRECTORY_FSYNC,
    WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_POST_VALIDATION,
  };
  for (guint i = 0; i < G_N_ELEMENTS (before); i++)
    run_fixed_sidecar_replace_fault (before[i], FALSE);
  for (guint i = 0; i < G_N_ELEMENTS (after); i++)
    run_fixed_sidecar_replace_fault (after[i], TRUE);
#endif
}

#ifndef G_OS_WIN32
static void
test_fixed_sidecar_replacement_ambiguous_rename_error (void)
{
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  struct stat source_identity, destination_identity;
  WylFactArtifactSidecarBinding *destination =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old",
          &destination_identity, NULL);
  WylFactArtifactSidecarBinding *source =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_CHECKPOINT, "new",
          &source_identity, NULL);

  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_SIDECAR_REPLACE_RENAME_AMBIGUOUS);
  WylFactArtifactSidecarReplaceResult result =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_IO);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
      ==, WYRELOG_E_POLICY);

  /* The terminal result revokes retry authority even though a fresh namespace
   * can later classify the exact source as intact. */
  result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);

  fixed_sidecar_replace_fixture_reopen (&fixture);
  WylFactArtifactSidecarBinding *reopened_source = NULL;
  gint fd = -1;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, &reopened_source,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (reopened_source,
      &fd), ==, WYRELOG_E_OK);
  assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_CHECKPOINT,
      &source_identity, "new");

  WylFactArtifactSidecarBinding *missing_wal = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint
    (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_WAL, TRUE, &missing_wal, &fd), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (missing_wal);
  g_assert_cmpint (fd, ==, -1);
  retire_closed_sidecar (reopened_source);
  wyl_fact_artifact_sidecar_binding_free (reopened_source);
  fixed_sidecar_replace_fixture_clear (&fixture);
}
#endif

#ifndef G_OS_WIN32
typedef enum
{
  FIXED_REPLACE_MALFORM_SOURCE_MODE,
  FIXED_REPLACE_MALFORM_SOURCE_HARD_LINK,
  FIXED_REPLACE_MALFORM_SOURCE_SUBSTITUTE,
  FIXED_REPLACE_MALFORM_SOURCE_SYMLINK,
  FIXED_REPLACE_MALFORM_SOURCE_DIRECTORY,
  FIXED_REPLACE_MALFORM_DESTINATION_MODE,
  FIXED_REPLACE_MALFORM_DESTINATION_HARD_LINK,
  FIXED_REPLACE_MALFORM_DESTINATION_SYMLINK,
  FIXED_REPLACE_MALFORM_DESTINATION_DIRECTORY,
  FIXED_REPLACE_MALFORM_DESTINATION_SUBSTITUTE,
  FIXED_REPLACE_MALFORM_DESTINATION_MISSING,
} FixedReplaceMalformation;

static void
run_fixed_sidecar_replace_malformation (FixedReplaceMalformation malformation)
{
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  struct stat source_identity, destination_identity;
  WylFactArtifactSidecarBinding *destination =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old",
          &destination_identity, NULL);
  WylFactArtifactSidecarBinding *source =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_RECOVERY, "new",
          &source_identity, NULL);
  g_autofree gchar *source_path = fixed_artifact_path_for_test (&fixture,
          WYL_FACT_ARTIFACT_RECOVERY);
  g_autofree gchar *destination_path = fixed_artifact_path_for_test (&fixture,
          WYL_FACT_ARTIFACT_WAL);
  g_autofree gchar *saved_path = g_build_filename (fixture.graph_path,
          "saved-fixed-sidecar", NULL);
  g_autofree gchar *alias_path = g_build_filename (fixture.graph_path,
          "fixed-sidecar-alias", NULL);

  switch (malformation) {
    case FIXED_REPLACE_MALFORM_SOURCE_MODE:
      g_assert_cmpint (chmod (source_path, 0644), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_HARD_LINK:
      g_assert_cmpint (link (source_path, alias_path), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_SUBSTITUTE:
      g_assert_cmpint (rename (source_path, saved_path), ==, 0);
      g_assert_true (g_file_set_contents (source_path, "foreign", -1, NULL));
      g_assert_cmpint (chmod (source_path, 0600), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_SYMLINK:
      g_assert_cmpint (rename (source_path, saved_path), ==, 0);
      g_assert_cmpint (symlink ("facts.duckdb", source_path), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_DIRECTORY:
      g_assert_cmpint (rename (source_path, saved_path), ==, 0);
      g_assert_cmpint (mkdir (source_path, 0700), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_MODE:
      g_assert_cmpint (chmod (destination_path, 0644), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_HARD_LINK:
      g_assert_cmpint (link (destination_path, alias_path), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_SYMLINK:
      g_assert_cmpint (rename (destination_path, saved_path), ==, 0);
      g_assert_cmpint (symlink ("facts.duckdb", destination_path), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_DIRECTORY:
      g_assert_cmpint (rename (destination_path, saved_path), ==, 0);
      g_assert_cmpint (mkdir (destination_path, 0700), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_SUBSTITUTE:
      g_assert_cmpint (rename (destination_path, saved_path), ==, 0);
      g_assert_true (g_file_set_contents (destination_path, "foreign", -1,
          NULL));
      g_assert_cmpint (chmod (destination_path, 0600), ==, 0);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_MISSING:
      g_assert_cmpint (unlink (destination_path), ==, 0);
      break;
  }

  WylFactArtifactSidecarReplaceResult result =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  if (malformation < FIXED_REPLACE_MALFORM_DESTINATION_MODE) {
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL,
        &destination_identity, "old");
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
        ==, WYRELOG_E_OK);
  } else {
    assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_RECOVERY,
        &source_identity, "new");
    g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
        WYRELOG_E_OK);
  }

  switch (malformation) {
    case FIXED_REPLACE_MALFORM_SOURCE_MODE:
      g_assert_cmpint (chmod (source_path, 0600), ==, 0);
      g_assert_cmpint (unlink (source_path), ==, 0);
      retire_closed_sidecar (destination);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_HARD_LINK:
      g_assert_cmpint (unlink (alias_path), ==, 0);
      g_assert_cmpint (unlink (source_path), ==, 0);
      retire_closed_sidecar (destination);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_SUBSTITUTE:
    case FIXED_REPLACE_MALFORM_SOURCE_SYMLINK:
      g_assert_cmpint (unlink (source_path), ==, 0);
      g_assert_cmpint (rename (saved_path, source_path), ==, 0);
      g_assert_cmpint (unlink (source_path), ==, 0);
      retire_closed_sidecar (destination);
      break;
    case FIXED_REPLACE_MALFORM_SOURCE_DIRECTORY:
      g_assert_cmpint (rmdir (source_path), ==, 0);
      g_assert_cmpint (rename (saved_path, source_path), ==, 0);
      g_assert_cmpint (unlink (source_path), ==, 0);
      retire_closed_sidecar (destination);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_MODE:
      g_assert_cmpint (chmod (destination_path, 0600), ==, 0);
      g_assert_cmpint (unlink (destination_path), ==, 0);
      retire_closed_sidecar (source);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_HARD_LINK:
      g_assert_cmpint (unlink (alias_path), ==, 0);
      g_assert_cmpint (unlink (destination_path), ==, 0);
      retire_closed_sidecar (source);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_SYMLINK:
      g_assert_cmpint (unlink (destination_path), ==, 0);
      g_assert_cmpint (rename (saved_path, destination_path), ==, 0);
      g_assert_cmpint (unlink (destination_path), ==, 0);
      retire_closed_sidecar (source);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_DIRECTORY:
      g_assert_cmpint (rmdir (destination_path), ==, 0);
      g_assert_cmpint (rename (saved_path, destination_path), ==, 0);
      g_assert_cmpint (unlink (destination_path), ==, 0);
      retire_closed_sidecar (source);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_SUBSTITUTE:
      g_assert_cmpint (unlink (destination_path), ==, 0);
      g_assert_cmpint (rename (saved_path, destination_path), ==, 0);
      g_assert_cmpint (unlink (destination_path), ==, 0);
      retire_closed_sidecar (source);
      break;
    case FIXED_REPLACE_MALFORM_DESTINATION_MISSING:
      retire_closed_sidecar (source);
      break;
  }
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);
}
#endif

static void
test_fixed_sidecar_replacement_rejections (void)
{
#ifndef G_OS_WIN32
  gint baseline_fds = count_open_fds ();
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  WylFactArtifactSidecarBinding *destination = NULL, *source = NULL;
  gint destination_fd = -1, source_fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &destination,
      &destination_fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &source,
      &source_fd), ==, WYRELOG_E_OK);
  g_assert_true (write_exact (destination_fd, "old", 3));
  g_assert_true (write_exact (source_fd, "new", 3));
  WylFactArtifactSidecarReplaceResult result =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  /* Both real working descriptors are still live. */
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (source, &source_fd),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (destination,
      &destination_fd), ==, WYRELOG_E_OK);
  result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  /* Argument identity and direction are closed: same binding and WAL as
   * source cannot accidentally become generic rename authority. */
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source, source,
      &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (destination,
      source, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  retire_closed_sidecar (source);
  retire_closed_sidecar (destination);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);

  /* Raw close plus exact descriptor-number reuse revokes the source without
   * closing the foreign descriptor or renaming either sidecar. */
  fixed_sidecar_replace_fixture_init (&fixture);
  struct stat ignored;
  destination = create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old",
          &ignored, NULL);
  source = NULL;
  source_fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, TRUE, &source,
      &source_fd), ==, WYRELOG_E_OK);
  g_assert_true (write_exact (source_fd, "new", 3));
  gint foreign_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_fd, source_fd), ==, source_fd);
  if (foreign_fd != source_fd)
    close (foreign_fd);
  result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  g_assert_cmpint (fcntl (source_fd, F_GETFD), !=, -1);
  close (source_fd);
  g_autofree gchar *source_path = fixed_artifact_path_for_test (&fixture,
          WYL_FACT_ARTIFACT_CHECKPOINT);
  g_assert_cmpint (unlink (source_path), ==, 0);
  retire_closed_sidecar (destination);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);

  /* The destination working descriptor has the same checked-close contract;
   * replacement must not close a reused foreign descriptor or consume source. */
  fixed_sidecar_replace_fixture_init (&fixture);
  source = create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_RECOVERY, "new",
          &ignored, NULL);
  destination = NULL;
  destination_fd = -1;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (fixture.lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &destination,
      &destination_fd), ==, WYRELOG_E_OK);
  g_assert_true (write_exact (destination_fd, "old", 3));
  foreign_fd = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  g_assert_cmpint (foreign_fd, >=, 0);
  g_assert_cmpint (dup2 (foreign_fd, destination_fd), ==, destination_fd);
  if (foreign_fd != destination_fd)
    close (foreign_fd);
  result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  g_assert_cmpint (fcntl (destination_fd, F_GETFD), !=, -1);
  close (destination_fd);
  g_autofree gchar *destination_path = fixed_artifact_path_for_test (&fixture,
          WYL_FACT_ARTIFACT_WAL);
  g_assert_cmpint (unlink (destination_path), ==, 0);
  retire_closed_sidecar (source);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);

  for (FixedReplaceMalformation malformation =
      FIXED_REPLACE_MALFORM_SOURCE_MODE;
      malformation <= FIXED_REPLACE_MALFORM_DESTINATION_MISSING; malformation++)
    run_fixed_sidecar_replace_malformation (malformation);

  /* Bindings from separate exact lease/namespace domains cannot be combined. */
  FixedSidecarReplaceFixture other;
  fixed_sidecar_replace_fixture_init (&fixture);
  fixed_sidecar_replace_fixture_init (&other);
  source = create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_RECOVERY, "new",
          &ignored, NULL);
  destination = create_closed_sidecar (&other, WYL_FACT_ARTIFACT_WAL, "old",
          &ignored, NULL);
  result = WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED;
  g_assert_cmpint
    (wyl_fact_artifact_sidecar_binding_replace_existing_wal (source,
      destination, &result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (result, ==,
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED);
  retire_closed_sidecar (source);
  retire_closed_sidecar (destination);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);
  fixed_sidecar_replace_fixture_clear (&other);
  g_assert_cmpint (count_open_fds (), ==, baseline_fds);
#endif
}

static void
test_fixed_sidecar_replacement_concurrency (void)
{
#ifndef G_OS_WIN32
  FixedSidecarReplaceFixture fixture;
  fixed_sidecar_replace_fixture_init (&fixture);
  struct stat source_identity, ignored;
  WylFactArtifactSidecarBinding *destination =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_WAL, "old", &ignored,
          NULL);
  WylFactArtifactSidecarBinding *source =
      create_closed_sidecar (&fixture, WYL_FACT_ARTIFACT_RECOVERY, "winner",
          &source_identity, NULL);
  FixedSidecarReplaceWorker workers[2] = {
    {source, destination, WYRELOG_E_INTERNAL,
     WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED},
    {source, destination, WYRELOG_E_INTERNAL,
     WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED},
  };
  GThread *first = g_thread_new ("fixed-replace-a",
          replace_fixed_sidecar_worker, &workers[0]);
  GThread *second = g_thread_new ("fixed-replace-b",
          replace_fixed_sidecar_worker, &workers[1]);
  g_thread_join (first);
  g_thread_join (second);
  guint replaced = 0, rejected = 0;
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++) {
    if (workers[i].error == WYRELOG_E_OK
        && workers[i].result ==
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_REPLACED_DURABLE)
      replaced++;
    else if (workers[i].error == WYRELOG_E_POLICY
        && workers[i].result ==
        WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED)
      rejected++;
  }
  g_assert_cmpuint (replaced, ==, 1);
  g_assert_cmpuint (rejected, ==, 1);
  assert_fixed_artifact (&fixture, WYL_FACT_ARTIFACT_WAL, &source_identity,
      "winner");
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (source), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_revalidate (destination),
      ==, WYRELOG_E_OK);
  retire_closed_sidecar (destination);
  wyl_fact_artifact_sidecar_binding_free (source);
  wyl_fact_artifact_sidecar_binding_free (destination);
  fixed_sidecar_replace_fixture_clear (&fixture);
#endif
}

#ifdef G_OS_WIN32
static void
test_mutation_leases (void)
{
  WylFactArtifactMutationLease *lease = (gpointer) 0x1;
  gint fd = 42;
  WylFactArtifactSidecarRetireResult retirement =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED;
  /* The missing-argument half of the neutral contract, which survives the
   * Windows implementation and is asserted for both platforms.
   *
   * What used to sit here was a second call passing (WylFactArtifactSidecarBinding *) 0x1
   * and expecting the same answer.  That held only while retirement was a stub
   * that ignored its argument; it is not a contract any implementation can
   * keep, because no function can tell an invalid pointer from a valid one.
   * The real refusals a caller can provoke -- a reader-guard lease, a live
   * session, an inactive binding -- are exercised against genuine bindings in
   * tests/test-fact-artifact-namespace-windows.c. */
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (NULL,
      &retirement), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (retirement, ==,
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_retire (NULL, NULL), ==,
      WYRELOG_E_POLICY);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
        (sidecar, WYL_FACT_ARTIFACT_RECOVERY), ==, WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_RECOVERY);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_RECOVERY, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_publish_no_replace
        (sidecar, WYL_FACT_ARTIFACT_WAL), ==, WYRELOG_E_OK);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_WAL);
  wyl_fact_artifact_sidecar_binding_free (sidecar);
  sidecar = NULL;
#endif
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_sidecar_binding
        (lease, WYL_FACT_ARTIFACT_WAL, TRUE, TRUE, &sidecar, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_REPLACE, TRUE, TRUE, &replace_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
        (replace_source, replace_destination), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_SIDE_REPLACE, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_REPLACE_WAL, TRUE, TRUE, &replace_source, &fd), ==,
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_REPLACE_FAULT, TRUE, TRUE, &replace_source, &fd), ==,
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_SOURCE, TRUE, TRUE, &replace_source, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *substituted_source_path = g_build_filename
        (graph_path, "tmp-" TOKEN_SIDE_SOURCE, NULL);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_DEST, TRUE, TRUE, &replace_source,
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
      TOKEN_SIDE_PRE, TRUE, TRUE, &replace_source,
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (replace_destination,
      &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SIDE_POST, TRUE, TRUE, &replace_source,
      &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_REPLACE_POST_RENAME_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_replace_sidecar
        (replace_source, replace_destination), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (replace_source, FALSE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_SIDE_POST, FALSE, FALSE, &fd), ==,
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_sidecar_binding_close (sidecar, &fd), ==,
      WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, TOKEN_SPILL,
      TRUE, TRUE, &fd), ==, WYRELOG_E_OK);
  close (fd);
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, TOKEN_SPILL,
      FALSE, TRUE, &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  WylFactArtifactTempBinding *writable_reopen = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_SPILL, FALSE, TRUE, &writable_reopen, &fd), ==, WYRELOG_E_POLICY);
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
      TOKEN_BOUND, TRUE, TRUE, &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (binding, TRUE, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  WylFactArtifactTempBinding *read_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_BOUND, FALSE, FALSE, &read_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (read_binding, TRUE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (read_binding, FALSE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (read_binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (read_binding,
      TOKEN_READ_MOVED), ==, WYRELOG_E_POLICY);
  WylFactArtifactTempRecoveryEvidence *read_evidence = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
        (read_binding, &read_evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (read_evidence);
  wyl_fact_artifact_temp_binding_free (read_binding);
  WylFactArtifactTempBinding *unlink_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_UNLINK_OWNER, TRUE, TRUE, &unlink_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (unlink_binding), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (unlink_binding, FALSE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (unlink_binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_UNLINK_OWNER, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_temp_binding_free (unlink_binding);
  WylFactArtifactTempBinding *fault_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_UNLINK_FAULT, TRUE, TRUE, &fault_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_UNLINK_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (fault_binding), ==,
      WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (fault_binding, FALSE,
      &fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_UNLINK_FAULT, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  wyl_fact_artifact_temp_binding_free (fault_binding);
  WylFactArtifactTempBinding *rename_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RENAME_SOURCE, TRUE, TRUE, &rename_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
      TOKEN_RENAME_SOURCE), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
      "../escape"), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
      "nested/token"), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_binding,
      TOKEN_RENAME_DEST), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (rename_binding, TRUE,
      &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_RENAME_SOURCE, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (rename_binding), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (rename_binding);
  WylFactArtifactTempBinding *overwrite_source = NULL;
  WylFactArtifactTempBinding *overwrite_destination = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_OVERWRITE_SOURCE, TRUE, TRUE, &overwrite_source, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_OVERWRITE_DEST, TRUE, TRUE, &overwrite_destination, &fd),
      ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (overwrite_source,
      TOKEN_OVERWRITE_DEST), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (overwrite_source),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink
        (overwrite_destination), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (overwrite_source);
  wyl_fact_artifact_temp_binding_free (overwrite_destination);
  WylFactArtifactTempBinding *rename_fault = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RENAME_FAULT_SOURCE, TRUE, TRUE, &rename_fault, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_TEMP_RENAME_DIRECTORY_FSYNC);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (rename_fault,
      TOKEN_RENAME_FAULT_DEST), ==, WYRELOG_E_IO);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_open (rename_fault, FALSE,
      &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      TOKEN_RENAME_FAULT_SOURCE, FALSE, FALSE, &fd), ==, WYRELOG_E_NOT_FOUND);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (rename_fault), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (rename_fault);
  WylFactArtifactTempBinding *race_a = NULL;
  WylFactArtifactTempBinding *race_b = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RENAME_RACE_A, TRUE, TRUE, &race_a, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RENAME_RACE_B, TRUE, TRUE, &race_b, &fd), ==, WYRELOG_E_OK);
  close (fd);
  TempBindingRenameWorker rename_workers[] = {
    {race_a, TOKEN_RENAME_RACE_DEST, WYRELOG_E_INTERNAL},
    {race_b, TOKEN_RENAME_RACE_DEST, WYRELOG_E_INTERNAL},
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
      TOKEN_LINEAR_RACE, TRUE, TRUE, &linear_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  TempBindingRenameWorker linear_rename = { linear_binding, TOKEN_LINEAR_MOVED,
                                            WYRELOG_E_INTERNAL};
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
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease, TOKEN_SPILL,
      TRUE, TRUE, &fd), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp (lease,
      "../escape", TRUE, TRUE, &fd), ==, WYRELOG_E_INVALID);
  WylFactArtifactTempBinding *recovery_binding = NULL;
  WylFactArtifactTempRecoveryEvidence *evidence = NULL;
  WylFactArtifactTempRecoveryEvidence *decoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RECOVERY, TRUE, TRUE, &recovery_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
        (recovery_binding, &evidence), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) encoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_encode (evidence,
      &encoded), ==, WYRELOG_E_OK);
  RecoveryMacTestProvider *mac_state = g_new0 (RecoveryMacTestProvider, 1);
  memset (mac_state->key, 0x5a, sizeof mac_state->key);
  WylFactRecoveryMacProvider mac_provider = {
    recovery_mac_test_compute, recovery_mac_test_verify,
    recovery_mac_test_wipe, recovery_mac_test_free, mac_state
  };
  g_autoptr (WylFactRecoveryMacHandle) mac_handle =
      wyl_fact_recovery_mac_handle_new (&mac_provider, "key-1", 7,
          "tenant-1", "graph-1", "operation-1");
  g_assert_nonnull (mac_handle);
  g_autoptr (GBytes) encoded_v2 = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_encode_v2
        (mac_handle, evidence, &encoded_v2), ==, WYRELOG_E_OK);
  WylFactArtifactTempRecoveryEvidence *decoded_v2 = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, encoded_v2, &decoded_v2), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_recovery_evidence_free (decoded_v2);
  gsize encoded_v2_size = 0;
  const guint8 *encoded_v2_data = g_bytes_get_data (encoded_v2, &encoded_v2_size);
  guint8 *tampered_v2_data = g_memdup2 (encoded_v2_data, encoded_v2_size);
  tampered_v2_data[10] ^= 1;
  g_autoptr (GBytes) tampered_v2 =
      g_bytes_new_take (tampered_v2_data, encoded_v2_size);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, tampered_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  g_autoptr (GBytes) truncated_v2 =
      g_bytes_new (encoded_v2_data, encoded_v2_size - 1);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, truncated_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  guint8 *extended_v2_data = g_malloc (encoded_v2_size + 1);
  memcpy (extended_v2_data, encoded_v2_data, encoded_v2_size);
  extended_v2_data[encoded_v2_size] = 0;
  g_autoptr (GBytes) extended_v2 =
      g_bytes_new_take (extended_v2_data, encoded_v2_size + 1);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, extended_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  RecoveryMacTestProvider *wrong_scope_state = g_new0
        (RecoveryMacTestProvider, 1);
  memset (wrong_scope_state->key, 0x5a, sizeof wrong_scope_state->key);
  WylFactRecoveryMacProvider wrong_scope_provider = {
    recovery_mac_test_compute, recovery_mac_test_verify,
    recovery_mac_test_wipe, recovery_mac_test_free, wrong_scope_state
  };
  g_autoptr (WylFactRecoveryMacHandle) wrong_scope_handle =
      wyl_fact_recovery_mac_handle_new (&wrong_scope_provider, "key-1", 7,
          "tenant-2", "graph-1", "operation-1");
  g_assert_nonnull (wrong_scope_handle);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (wrong_scope_handle, encoded_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  RecoveryMacTestProvider *wrong_key_state = g_new0
        (RecoveryMacTestProvider, 1);
  memset (wrong_key_state->key, 0x5a, sizeof wrong_key_state->key);
  WylFactRecoveryMacProvider wrong_key_provider = {
    recovery_mac_test_compute, recovery_mac_test_verify,
    recovery_mac_test_wipe, recovery_mac_test_free, wrong_key_state
  };
  g_autoptr (WylFactRecoveryMacHandle) wrong_key_handle =
      wyl_fact_recovery_mac_handle_new (&wrong_key_provider, "unknown-key", 7,
          "tenant-1", "graph-1", "operation-1");
  g_assert_nonnull (wrong_key_handle);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (wrong_key_handle, encoded_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  RecoveryMacTestProvider *rotated_state = g_new0
        (RecoveryMacTestProvider, 1);
  memset (rotated_state->key, 0x5a, sizeof rotated_state->key);
  WylFactRecoveryMacProvider rotated_provider = {
    recovery_mac_test_compute, recovery_mac_test_verify,
    recovery_mac_test_wipe, recovery_mac_test_free, rotated_state
  };
  g_autoptr (WylFactRecoveryMacHandle) rotated_handle =
      wyl_fact_recovery_mac_handle_new (&rotated_provider, "key-1", 8,
          "tenant-1", "graph-1", "operation-1");
  g_assert_nonnull (rotated_handle);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (rotated_handle, encoded_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  wyl_fact_recovery_mac_handle_close (mac_handle);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, encoded_v2, &decoded_v2), ==, WYRELOG_E_POLICY);
  g_assert_null (decoded_v2);
  g_autoptr (GBytes) wtr1_as_v2 = g_bytes_new_static ("WTR1", 4);
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode_v2
        (mac_handle, wtr1_as_v2, &decoded_v2), ==, WYRELOG_E_INVALID);
  g_assert_null (decoded_v2);
  WylFactArtifactTempBinding *recovery_v2_binding = NULL;
  WylFactArtifactTempRecoveryEvidence *recovery_v2_evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_open_temp_binding (lease,
      TOKEN_RECOVERY_V2, TRUE, TRUE, &recovery_v2_binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
        (recovery_v2_binding, &recovery_v2_evidence), ==, WYRELOG_E_OK);
  g_autoptr (GBytes) recovery_v2_encoded = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_encode_v2
        (mac_handle, recovery_v2_evidence, &recovery_v2_encoded), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_temp_binding_free (recovery_v2_binding);
  recovery_v2_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp_v2 (lease,
      mac_handle, recovery_v2_encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_mutation_lease_recover_temp_v2 (lease,
      mac_handle, recovery_v2_encoded), ==, WYRELOG_E_OK);
  wyl_fact_artifact_temp_recovery_evidence_free (recovery_v2_evidence);
  recovery_v2_evidence = NULL;
  gsize encoded_size = 0;
  const guint8 *encoded_data = g_bytes_get_data (encoded, &encoded_size);
  const gchar legacy_token[] = "legacy-token";
  guint8 *legacy_data = g_malloc (53 + sizeof legacy_token - 1);
  memcpy (legacy_data, "WTR1", 4);
  legacy_data[4] = sizeof legacy_token - 1;
  memcpy (legacy_data + 53, legacy_token, sizeof legacy_token - 1);
  g_autoptr (GBytes) legacy_encoded =
      g_bytes_new_take (legacy_data, 53 + sizeof legacy_token - 1);
  WylFactArtifactTempRecoveryEvidence *legacy_evidence = NULL;
  g_assert_cmpint (wyl_fact_artifact_temp_recovery_evidence_decode
        (legacy_encoded, &legacy_evidence), ==, WYRELOG_E_INVALID);
  g_assert_null (legacy_evidence);
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
      TOKEN_RECOVERY_FAULT, TRUE, TRUE, &recovery_fault_binding, &fd), ==,
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
      TOKEN_RECOVERY_WRONG, TRUE, TRUE, &wrong_binding, &fd), ==, WYRELOG_E_OK);
  close (fd);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_export_recovery_evidence
        (wrong_binding, &wrong_evidence), ==, WYRELOG_E_OK);
  g_autofree gchar *wrong_path =
      g_build_filename (graph_path, "tmp-" TOKEN_RECOVERY_WRONG, NULL);
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
      TOKEN_SUBSTITUTE, TRUE, TRUE, &substitution_binding, &fd), ==,
      WYRELOG_E_OK);
  close (fd);
  g_autofree gchar *substitution_path =
      g_build_filename (graph_path, "tmp-" TOKEN_SUBSTITUTE, NULL);
  g_autofree gchar *protected_main_path =
      g_build_filename (graph_path, "facts.duckdb", NULL);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  g_assert_cmpint (symlink ("facts.duckdb", substitution_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_unlink (substitution_binding),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  g_assert_cmpint (link (protected_main_path, substitution_path), ==, 0);
  g_assert_cmpint (wyl_fact_artifact_temp_binding_rename (substitution_binding,
      TOKEN_SUBSTITUTE_MOVED), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (unlink (substitution_path), ==, 0);
  wyl_fact_artifact_temp_binding_free (substitution_binding);
  g_autofree gchar *bound_path =
      g_build_filename (graph_path, "tmp-" TOKEN_BOUND, NULL);
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

typedef struct
{
  WylFactDuckdbTempRoot *root;
  guint seen;
} DuckdbTempForeachProbe;

static gboolean
duckdb_temp_reentrant_visitor (WylFactDuckdbTempChild *child,
    const gchar *name, gpointer data)
{
  DuckdbTempForeachProbe *probe = data;
  gboolean exists = FALSE;
  (void) child;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_child_exists (probe->root, name,
      &exists), ==, WYRELOG_E_OK);
  g_assert_true (exists);
  probe->seen++;
  return TRUE;
}

static void
test_duckdb_temp_root (void)
{
#ifdef G_OS_WIN32
  /* Windows now reaches the real temp-root authority rather than the
   * WYRELOG_E_POLICY placeholder that stood in while this surface was
   * unimplemented, so a NULL lease is an argument-shape error here exactly as
   * it is on POSIX. */
  WylFactDuckdbTempRoot *root = (gpointer) 0x1;
  WylFactDuckdbTempOrphanEvidence *evidence = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence
        (NULL, &root, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_null (root);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence
        (NULL, NULL, &evidence), ==, WYRELOG_E_INVALID);
#else
  WylFactGraphResolver resolver = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphLocator locator = { 0 };
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  WylFactDuckdbTempRoot *root = NULL;
  WylFactDuckdbTempChild *storage = NULL;
  WylFactDuckdbTempChildBinding *binding = NULL;
  WylFactDuckdbTempOrphanEvidence *evidence = NULL;
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  g_autofree gchar *base = make_root ();
  g_assert_cmpint (wyl_fact_graph_resolver_open (base, &resolver), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_locator_init (&locator, "tenant", "graph"),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open_directory (&resolver, &locator,
      TRUE, &directory), ==, WYRELOG_E_OK);
  g_autofree gchar *graph_path = wyl_fact_graph_directory_descriptive_path
        (&directory);
  g_assert_cmpint (open_namespace (&directory, &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_MKDIR);
  root = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease,
      &root, &evidence), ==, WYRELOG_E_IO);
  g_assert_null (root);
  g_assert_null (evidence);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_POST_OPEN_IDENTITY);
  root = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease,
      &root, &evidence), ==, WYRELOG_E_IO);
  g_assert_null (root);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease,
      &root, &evidence), ==, WYRELOG_E_OK);
  g_assert_null (evidence);
  gboolean exists = TRUE;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_child_exists (root,
      "duckdb_temp_storage_S32K-99.tmp", &exists), ==, WYRELOG_E_OK);
  g_assert_false (exists);
  exists = TRUE;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_child_exists (root,
      "duckdb_temp_block-99.block", &exists), ==, WYRELOG_E_OK);
  g_assert_false (exists);
  /* Neither arbitrary descendants nor source-unsupported spellings acquire
   * creation authority. */
  gint fd = 42;
  WylFactDuckdbTempChild *faulted_child = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
        (root, "other", NULL, &fd, &evidence), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_OPEN_IDENTITY);
  faulted_child = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
        (root, "duckdb_temp_storage_S64K-0.tmp", &faulted_child, &fd, &evidence),
      ==, WYRELOG_E_IO);
  g_assert_null (faulted_child);
  g_assert_cmpint (fd, ==, -1);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_POST_CREATE);
  faulted_child = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
        (root, "duckdb_temp_storage_S96K-0.tmp", &faulted_child, &fd, &evidence),
      ==, WYRELOG_E_IO);
  g_assert_null (faulted_child);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_binding (root,
      "duckdb_temp_storage_S32K-0.tmp", &storage, &binding, &fd, &evidence),
      ==, WYRELOG_E_OK);
  g_assert_null (evidence);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (write (fd, "x", 1), ==, 1);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (fd, ==, -1);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate (binding), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_POLICY);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
        (root, "duckdb_temp_storage_S32K-0.tmp", NULL, &fd, &evidence), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, FALSE,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding,
      fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  GPtrArray *listed = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 1);
  g_ptr_array_unref (listed);
  DuckdbTempForeachProbe probe = {.root = root };
  g_assert_cmpint (wyl_fact_duckdb_temp_root_foreach_child (root,
      duckdb_temp_reentrant_visitor, &probe), ==, WYRELOG_E_OK);
  g_assert_cmpuint (probe.seen, ==, 1);
  /* Test code may inspect the host spelling, but production authority cannot:
  * a broad DuckDB-looking/foreign entry must reject enumeration wholesale. */
  g_autoptr (GDir) graph_dir = g_dir_open (graph_path, 0, NULL);
  const gchar *entry;
  const gchar *temp_root_name = NULL;
  while ((entry = g_dir_read_name (graph_dir)) != NULL)
    if (g_str_has_prefix (entry, ".duckdb-private-temp-")) {
      temp_root_name = entry;
      break;
    }
  g_assert_nonnull (temp_root_name);
  g_autofree gchar *temp_root_path = g_build_filename (graph_path,
          temp_root_name, NULL);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_PRE_IDENTITY);
  faulted_child = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_with_orphan_evidence
        (root, "duckdb_temp_storage_S128K-1.tmp", &faulted_child, &fd,
      &evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (faulted_child);
  g_assert_cmpint (fd, ==, -1);
  g_autofree gchar *orphan_name =
      wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name (evidence);
  g_assert_true (g_str_has_suffix (orphan_name,
      "/duckdb_temp_storage_S128K-1.tmp"));
  wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
  evidence = NULL;
  listed = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (listed);
  g_autofree gchar *pre_identity = g_build_filename (temp_root_path,
          "duckdb_temp_storage_S128K-1.tmp", NULL);
  g_assert_cmpint (unlink (pre_identity), ==, 0);
  g_autofree gchar *foreign = g_build_filename (temp_root_path,
          "duckdb_temp_block-99.block", NULL);
  g_assert_cmpint (g_close (g_open (foreign, O_CREAT | O_EXCL | O_RDWR, 0600),
      NULL), ==, TRUE);
  listed = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (listed);
  exists = TRUE;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_child_exists (root,
      "duckdb_temp_block-99.block", &exists), ==, WYRELOG_E_POLICY);
  g_assert_false (exists);
  WylFactDuckdbTempRetireResult blocked_retire =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage,
      &blocked_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (blocked_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_true (g_file_test (foreign, G_FILE_TEST_EXISTS));
  g_assert_cmpint (unlink (foreign), ==, 0);
  g_autofree gchar *storage_path = g_build_filename (temp_root_path,
          "duckdb_temp_storage_S32K-0.tmp", NULL);
  g_autofree gchar *hard_link = g_build_filename (temp_root_path, "hard", NULL);
  g_assert_cmpint (link (storage_path, hard_link), ==, 0);
  listed = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (listed);
  exists = TRUE;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_child_exists (root,
      "duckdb_temp_storage_S32K-0.tmp", &exists), ==, WYRELOG_E_POLICY);
  g_assert_false (exists);
  g_assert_cmpint (unlink (hard_link), ==, 0);
  g_assert_cmpint (symlink ("/dev/null", foreign), ==, 0);
  listed = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (listed);
  g_assert_cmpint (unlink (foreign), ==, 0);
  g_autofree gchar *saved_storage = g_build_filename (temp_root_path,
          "saved-storage", NULL);
  g_assert_cmpint (rename (storage_path, saved_storage), ==, 0);
  g_assert_cmpint (g_close (g_open (storage_path, O_CREAT | O_EXCL | O_RDWR,
      0600), NULL), ==, TRUE);
  listed = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_list_children (root, &listed), ==,
      WYRELOG_E_POLICY);
  g_assert_null (listed);
  g_assert_cmpint (unlink (storage_path), ==, 0);
  g_assert_cmpint (rename (saved_storage, storage_path), ==, 0);
  /* A live issued descriptor blocks both child and root retirement.  Raw
   * close followed by same-number reuse revokes without touching foreign I/O. */
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, TRUE,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  /* The retirement audit must inspect every live binding: A remains valid
   * while B's raw-close/reuse is terminally revoked. */
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, TRUE,
      &binding, &fd), ==, WYRELOG_E_OK);
  WylFactDuckdbTempChildBinding *binding_b = NULL;
  gint fd_b = -1;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, TRUE,
      &binding_b, &fd_b), ==, WYRELOG_E_OK);
  gint reused = g_open ("/dev/null", O_RDWR, 0);
  g_assert_cmpint (reused, >=, 0);
  g_assert_cmpint (close (fd_b), ==, 0);
  g_assert_cmpint (dup2 (reused, fd_b), ==, fd_b);
  if (reused != fd_b)
    g_assert_cmpint (close (reused), ==, 0);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding_b,
      fd_b), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (write (fd_b, "z", 1), ==, 1);
  g_assert_cmpint (close (fd_b), ==, 0);
  fd_b = -1;
  wyl_fact_duckdb_temp_child_binding_free (binding_b);
  binding_b = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_POLICY);
  /* A fresh verified open/checked close re-establishes clean lifecycle state. */
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, TRUE,
      &binding, &fd), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd), ==,
      WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (retired, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_duckdb_temp_child_free (storage);
  storage = NULL;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (retired, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_duckdb_temp_root_free (root);
  root = NULL;
  /* Freeing a live binding releases its object but cannot prove that its
   * caller FD closed.  Even a later clean B binding must not clear A's
   * terminal barrier or permit retirement below A. */
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease,
      &root, &evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_binding (root,
      "duckdb_temp_storage_S192K-3.tmp", &storage, &binding, &fd,
      &evidence), ==, WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  gint fd_c = -1;
  g_assert_cmpint (wyl_fact_duckdb_temp_child_open_binding (storage, TRUE,
      &binding, &fd_c), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_binding_close (binding, &fd_c),
      ==, WYRELOG_E_OK);
  wyl_fact_duckdb_temp_child_binding_free (binding);
  binding = NULL;
  g_assert_cmpint (write (fd, "y", 1), ==, 1);
  g_assert_cmpint (wyl_fact_duckdb_temp_child_retire (storage, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_retire (root, &retired), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (close (fd), ==, 0);
  fd = -1;
  wyl_fact_duckdb_temp_child_free (storage);
  storage = NULL;
  wyl_fact_duckdb_temp_root_free (root);
  root = NULL;
  g_autoptr (GDir) free_barrier_dir = g_dir_open (graph_path, 0, NULL);
  const gchar *free_barrier_root_name = NULL;
  while ((entry = g_dir_read_name (free_barrier_dir)) != NULL)
    if (g_str_has_prefix (entry, ".duckdb-private-temp-")) {
      free_barrier_root_name = entry;
      break;
    }
  g_assert_nonnull (free_barrier_root_name);
  g_autofree gchar *free_barrier_root_path = g_build_filename (graph_path,
          free_barrier_root_name, NULL);
  g_autofree gchar *free_barrier_child_path =
      g_build_filename (free_barrier_root_path,
          "duckdb_temp_storage_S192K-3.tmp", NULL);
  g_assert_cmpint (unlink (free_barrier_child_path), ==, 0);
  g_assert_cmpint (g_rmdir (free_barrier_root_path), ==, 0);
  /* Once a child exists, a post-open binding validation failure cannot safely
  * adopt or unlink it.  The provider must return terminal orphan evidence. */
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease,
      &root, &evidence), ==, WYRELOG_E_OK);
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_CHILD_BINDING_POST_OPEN_IDENTITY);
  storage = (gpointer) 0x1;
  binding = (gpointer) 0x1;
  fd = 42;
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_child_binding (root,
      "duckdb_temp_storage_S160K-2.tmp", &storage, &binding, &fd,
      &evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (storage);
  g_assert_null (binding);
  g_assert_cmpint (fd, ==, -1);
  g_autofree gchar *binding_orphan_name =
      wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name (evidence);
  g_assert_true (g_str_has_suffix (binding_orphan_name,
      "/duckdb_temp_storage_S160K-2.tmp"));
  wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
  evidence = NULL;
  wyl_fact_duckdb_temp_root_free (root);
  root = NULL;
  /* Production has no adoption path; tests clean this intentionally retained
   * orphan through the host spelling before exercising the next root fault. */
  g_autoptr (GDir) orphan_root_dir = g_dir_open (graph_path, 0, NULL);
  const gchar *orphan_root_name = NULL;
  while ((entry = g_dir_read_name (orphan_root_dir)) != NULL)
    if (g_str_has_prefix (entry, ".duckdb-private-temp-")) {
      orphan_root_name = entry;
      break;
    }
  g_assert_nonnull (orphan_root_name);
  g_autofree gchar *orphan_root_path = g_build_filename (graph_path,
          orphan_root_name, NULL);
  g_autofree gchar *binding_orphan_path = g_build_filename (orphan_root_path,
          "duckdb_temp_storage_S160K-2.tmp", NULL);
  g_assert_cmpint (unlink (binding_orphan_path), ==, 0);
  g_assert_cmpint (g_rmdir (orphan_root_path), ==, 0);
  /* Before root identity is observable, only terminal evidence is exposed.
   * Test code may remove the residual directory; production has no adoption
   * or cleanup entry point for this name. */
  wyl_fact_artifact_namespace_set_test_fault
    (WYL_FACT_ARTIFACT_NAMESPACE_TEST_FAULT_DUCKDB_TEMP_ROOT_PRE_IDENTITY);
  g_assert_cmpint (wyl_fact_duckdb_temp_root_create_with_orphan_evidence
        (lease, &root, &evidence), ==, WYRELOG_E_POLICY);
  g_assert_null (root);
  g_autofree gchar *root_orphan_name =
      wyl_fact_duckdb_temp_orphan_evidence_dup_logical_name (evidence);
  g_assert_true (g_str_has_prefix (root_orphan_name, "wyrelog-duckdb-temp:"));
  wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
  evidence = NULL;
  g_autoptr (GDir) cleanup_dir = g_dir_open (graph_path, 0, NULL);
  const gchar *cleanup_name;
  while ((cleanup_name = g_dir_read_name (cleanup_dir)) != NULL)
    if (g_str_has_prefix (cleanup_name, ".duckdb-private-temp-")) {
      g_autofree gchar *cleanup_path = g_build_filename (graph_path,
              cleanup_name, NULL);
      g_assert_cmpint (g_rmdir (cleanup_path), ==, 0);
    }
  wyl_fact_artifact_mutation_lease_free (lease);
  wyl_fact_artifact_namespace_free (namespace_);
  test_remove_fixed_artifact (graph_path, WYL_FACT_ARTIFACT_MAIN);
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
  g_test_add_func ("/fact-artifact-namespace/fixed-sidecar-replacement/success",
      test_fixed_sidecar_replacement_success);
  g_test_add_func ("/fact-artifact-namespace/fixed-sidecar-replacement/faults",
      test_fixed_sidecar_replacement_faults);
#ifndef G_OS_WIN32
  g_test_add_func
    ("/fact-artifact-namespace/fixed-sidecar-replacement/ambiguous-rename-error",
      test_fixed_sidecar_replacement_ambiguous_rename_error);
#endif
  g_test_add_func
    ("/fact-artifact-namespace/fixed-sidecar-replacement/rejections",
      test_fixed_sidecar_replacement_rejections);
  g_test_add_func
    ("/fact-artifact-namespace/fixed-sidecar-replacement/concurrency",
      test_fixed_sidecar_replacement_concurrency);
  g_test_add_func ("/fact-artifact-namespace/basic", test_namespace);
  g_test_add_func ("/fact-artifact-namespace/mutation-leases",
      test_mutation_leases);
  g_test_add_func ("/fact-artifact-namespace/main-binding", test_main_binding);
  g_test_add_func ("/fact-artifact-namespace/reader-main-binding",
      test_reader_main_binding);
  g_test_add_func ("/fact-artifact-namespace/existing-sidecar-reopen",
      test_existing_sidecar_reopen);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-artifact-namespace/io-session-sidecar-dispatch",
      test_io_session_sidecar_dispatch);
#endif
  g_test_add_func ("/fact-artifact-namespace/duckdb-temp-root",
      test_duckdb_temp_root);
  return g_test_run ();
}
