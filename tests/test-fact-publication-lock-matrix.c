/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#ifndef G_OS_WIN32
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#endif

#include "fact/graph-artifact-namespace-private.h"
#include "fact/graph-locator-private.h"
#include "fact/publication-lock-event-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

wyrelog_error_t wyl_engine_open_source (const gchar *dl_src,
    guint32 num_workers, WylEngine **out);

#define CHILD_MODE "--hold-artifact-mutation-lease"
#define LEASE_READY "READY"
#define LEASE_ERROR_PREFIX "ERROR:"
#define TEST_DEADLINE_US (5 * G_TIME_SPAN_SECOND)
#define WATCHDOG_DEADLINE_US (100 * G_TIME_SPAN_MILLISECOND)

static const gchar *program_path;

static wyrelog_error_t count_target_graph_cb
  (const wyl_policy_fact_graph_info_t *info, gpointer user_data);

typedef struct
{
  GMutex mutex;
  GArray *events;
} LockTrace;

static void
lock_trace_event (const WylFactPublicationLockEvent *event, gpointer user_data)
{
  LockTrace *trace = user_data;
  g_mutex_lock (&trace->mutex);
  g_array_append_val (trace->events, *event);
  g_mutex_unlock (&trace->mutex);
}

static void
lock_trace_init (LockTrace *trace)
{
  g_mutex_init (&trace->mutex);
  trace->events = g_array_new (FALSE, FALSE,
          sizeof (WylFactPublicationLockEvent));
}

static void
lock_trace_clear (LockTrace *trace)
{
  g_array_free (trace->events, TRUE);
  g_mutex_clear (&trace->mutex);
}

#ifndef G_OS_WIN32
static gchar *
make_root (void)
{
  g_autoptr (GError) error = NULL;
  gchar *root = g_dir_make_tmp ("wyl-publication-lock-matrix-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  return root;
}

static wyrelog_error_t
open_namespace (const gchar *root, WylFactGraphResolver *resolver,
    WylFactGraphDirectory *directory, WylFactArtifactNamespace **out_namespace)
{
  WylFactGraphLocator locator = { 0 };
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  wyrelog_error_t result;
  gint fd = -1;

  *out_namespace = NULL;
  *resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  *directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  result = wyl_fact_graph_resolver_open (root, resolver);
  if (result != WYRELOG_E_OK)
    return result;
  result = wyl_fact_graph_locator_init (&locator, "tenant-a", "orders");
  if (result == WYRELOG_E_OK)
    result = wyl_fact_graph_resolver_open_directory (resolver, &locator, TRUE,
            directory);
  wyl_fact_graph_locator_clear (&locator);
  if (result != WYRELOG_E_OK)
    return result;

  fd = openat (directory->graph_fd, "facts.duckdb",
          O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return WYRELOG_E_IO;
  if (fchmod (fd, 0600) != 0){
    close (fd);
    return WYRELOG_E_IO;
  }
  struct stat stat_;
  if (fstat (fd, &stat_) != 0 || !S_ISREG (stat_.st_mode)
      || stat_.st_nlink != 1 || (stat_.st_mode & 07777) != 0600){
    close (fd);
    return WYRELOG_E_POLICY;
  }
  main_file.fd = fd;
  main_file.device = stat_.st_dev;
  main_file.inode = stat_.st_ino;
  main_file.size_bytes = stat_.st_size;
  result = wyl_fact_artifact_namespace_open (directory, &main_file,
          out_namespace);
  wyl_fact_graph_regular_file_clear (&main_file);
  return result;
}

static void
close_namespace (WylFactGraphResolver *resolver,
    WylFactGraphDirectory *directory, WylFactArtifactNamespace *namespace_)
{
  wyl_fact_artifact_namespace_free (namespace_);
  wyl_fact_graph_directory_clear (directory);
  wyl_fact_graph_resolver_clear (resolver);
}

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR))
        remove_tree (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (path);
}

static gboolean
write_all (gint fd, const gchar *data, gsize length)
{
  while (length > 0) {
    ssize_t written = write (fd, data, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return FALSE;
    data += written;
    length -= written;
  }
  return TRUE;
}

static gboolean
child_hold_lease (const gchar *root)
{
  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactArtifactNamespace *namespace_ = NULL;
  WylFactArtifactMutationLease *lease = NULL;
  wyrelog_error_t result = open_namespace (root, &resolver, &directory,
          &namespace_);
  if (result == WYRELOG_E_OK)
    result = wyl_fact_artifact_namespace_acquire_mutation_lease (namespace_,
            &lease);
  if (result != WYRELOG_E_OK) {
    g_autofree gchar *message = g_strdup_printf ("%s%d\n",
            LEASE_ERROR_PREFIX, result);
    (void) write_all (STDOUT_FILENO, message, strlen (message));
    close_namespace (&resolver, &directory, namespace_);
    return FALSE;
  }
  if (!write_all (STDOUT_FILENO, LEASE_READY "\n",
      strlen (LEASE_READY "\n"))) {
    wyl_fact_artifact_mutation_lease_free (lease);
    close_namespace (&resolver, &directory, namespace_);
    return FALSE;
  }

  /* The parent owns the lifetime of this process.  Do not use a forked live
   * lease; this process reached the lease through a fresh exec. */
  guint8 command = 0;
  (void) read (STDIN_FILENO, &command, sizeof command);
  return TRUE;
}

#if defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
static gboolean
readiness_read_line (gint fd, gint64 deadline, gchar **out_line)
{
  GString *line = g_string_new (NULL);
  guint8 byte = 0;
  while (g_get_monotonic_time () < deadline) {
    GPollFD poll_fd = {
      .fd = fd,
      .events = G_IO_IN | G_IO_HUP | G_IO_ERR,
    };
    gint64 remaining_us = deadline - g_get_monotonic_time ();
    gint timeout_ms = (gint) MIN ((guint64) G_MAXINT,
            ((guint64) MAX ((gint64) 0, remaining_us) + 999) / 1000);
    gint poll_result = g_poll (&poll_fd, 1, timeout_ms);
    if (poll_result <= 0)
      break;
    ssize_t read_count = read (fd, &byte, 1);
    if (read_count <= 0)
      break;
    if (byte == '\n') {
      *out_line = g_string_free (line, FALSE);
      return TRUE;
    }
    g_string_append_c (line, (gchar) byte);
  }
  g_string_free (line, TRUE);
  return FALSE;
}

static gboolean
reap_forced_child (GPid pid, gint64 deadline)
{
  (void) kill (pid, SIGKILL);
  int status = 0;
  pid_t result = -1;
  while (g_get_monotonic_time () < deadline) {
    result = waitpid (pid, &status, WNOHANG);
    if (result == pid) {
      g_spawn_close_pid (pid);
      return TRUE;
    }
    if (result < 0 && errno != EINTR)
      break;
    g_usleep (10 * 1000);
  }
  /* SIGKILL has already made the child non-running.  Finish the kernel reap
   * rather than returning with an orphaned GPid or a lease-holding process;
   * EINTR is the only expected interruption of this definitive cleanup. */
  do {
    result = waitpid (pid, &status, 0);
  } while (result < 0 && errno == EINTR);
  if (result == pid || (result < 0 && errno == ECHILD)) {
    g_spawn_close_pid (pid);
    return TRUE;
  }
  g_test_message ("forced artifact lease child could not be reaped: %s",
      g_strerror (errno));
  return FALSE;
}
#endif

static void
test_fresh_policy_after_child_exit (void)
{
#if !defined(WYL_TEST_HANDLE_SEAMS)
  g_test_skip ("publication lock hooks require test seams");
  return;
#elif defined(G_OS_WIN32)
  g_test_skip ("the neutral artifact namespace lease is POSIX-only");
  return;
#elif !defined(WYL_HAS_SECURE_DUCKDB_BRIDGE)
  g_test_skip ("fresh lease policy test requires the secure bridge build");
  return;
#else
  g_autofree gchar *root = make_root ();
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_autoptr (wyl_policy_store_t) initial_policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &initial_policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (initial_policy), ==,
      WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (initial_policy, "tenant-a",
      &created), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t columns[] = {
    {"value", "int64"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"orders", columns, G_N_ELEMENTS (columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = relations,
    .n_relations = G_N_ELEMENTS (relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (initial_policy, &graph,
      NULL), ==, WYRELOG_E_OK);
  g_clear_pointer (&initial_policy, wyl_policy_store_close);

  WylFactGraphResolver resolver;
  WylFactGraphDirectory directory;
  WylFactArtifactNamespace *namespace_ = NULL;
  g_assert_cmpint (open_namespace (root, &resolver, &directory, &namespace_),
      ==, WYRELOG_E_OK);
  close_namespace (&resolver, &directory, namespace_);

  gchar *argv[] = { (gchar *) program_path, (gchar *) CHILD_MODE, root, NULL };
  g_autoptr (GError) error = NULL;
  GPid child_pid = 0;
  gint child_stdin = -1;
  gint child_stdout = -1;
  g_assert_true (g_spawn_async_with_pipes (NULL, argv, NULL,
      G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDERR_TO_DEV_NULL,
      NULL, NULL, &child_pid, &child_stdin, &child_stdout, NULL, &error));
  g_assert_no_error (error);

  gint64 deadline = g_get_monotonic_time () + TEST_DEADLINE_US;
  g_autofree gchar *ready_line = NULL;
  gboolean readiness_ok = readiness_read_line (child_stdout, deadline,
          &ready_line) && g_strcmp0 (ready_line, LEASE_READY) == 0;
  if (!readiness_ok) {
    /* A failed readiness assertion must not strand a lease-holding child.
     * Give cleanup its own bounded monotonic window because the readiness
     * deadline may already have elapsed. */
    close (child_stdin);
    close (child_stdout);
    gboolean exited = reap_forced_child (child_pid,
            g_get_monotonic_time () + TEST_DEADLINE_US);
    g_test_message ("child readiness failed (line=%s, exited=%s)",
        ready_line != NULL ? ready_line : "<timeout/EOF>",
        exited ? "yes" : "no");
    g_test_fail ();
    if (exited)
      remove_tree (root);
    return;
  }
  /* The child intentionally holds the lease past this short deadline.  This
   * exercises the watchdog window before force-exit, rather than merely
   * testing that an already-terminating child can be waited for. */
  gint64 watchdog_deadline = g_get_monotonic_time () + WATCHDOG_DEADLINE_US;
  while (g_get_monotonic_time () < watchdog_deadline)
    g_usleep (10 * 1000);
  close (child_stdin);
  close (child_stdout);
  gboolean child_exited = reap_forced_child (child_pid,
          g_get_monotonic_time () + TEST_DEADLINE_US);
  if (!child_exited) {
    g_test_message ("artifact lease child did not exit before watchdog");
    g_test_fail ();
    return;
  }

  g_assert_cmpint (open_namespace (root, &resolver, &directory, &namespace_),
      ==, WYRELOG_E_OK);
  WylFactArtifactMutationLease *fresh_lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_namespace_acquire_mutation_lease
        (namespace_, &fresh_lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_mutation_lease_free (fresh_lease);
  close_namespace (&resolver, &directory, namespace_);

  g_autoptr (wyl_policy_store_t) fresh_policy = NULL;
  g_assert_cmpint (wyl_policy_store_open (policy_path, &fresh_policy), ==,
      WYRELOG_E_OK);
  WylPolicyGraphAuthorityRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (fresh_policy,
      "tenant-a", "orders", &record), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpstr (record->tenant_id, ==, "tenant-a");
  g_assert_cmpstr (record->graph_id, ==, "orders");
  /* create_fact_graph() intentionally leaves a graph without durable store
   * identity in the legacy-unclassified authority state.  The fresh read is
   * the evidence under test; do not promote that state to ACTIVE here. */
  g_assert_cmpint (record->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  gboolean active = FALSE;
  g_assert_cmpint (wyl_policy_store_fact_graph_is_active (fresh_policy,
      "tenant-a", "orders", &active), ==, WYRELOG_E_OK);
  g_assert_true (active);
  guint graph_count = 0;
  g_assert_cmpint (wyl_policy_store_foreach_fact_graph (fresh_policy,
      "tenant-a", count_target_graph_cb, &graph_count), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graph_count, ==, 1);
  wyl_policy_graph_authority_record_free (record);
  remove_tree (root);
#endif
}
#endif

static wyrelog_error_t
build_marker_engine (const WylFactGraphKey *key, WylEngine **out_engine,
    gpointer user_data)
{
  (void) key;
  (void) user_data;
  return wyl_engine_open_source (
    ".decl marker(value: int64)\nmarker(1).\n", 1, out_engine);
}

static guint
first_acquired (const LockTrace *trace, WylFactPublicationLockDomain domain,
    guint after)
{
  for (guint i = after; i < trace->events->len; i++) {
    WylFactPublicationLockEvent event = g_array_index (trace->events,
            WylFactPublicationLockEvent, i);
    if (event.phase == WYL_FACT_PUBLICATION_LOCK_ACQUIRED
        && event.domain == domain)
      return i;
  }
  return G_MAXUINT;
}

static wyrelog_error_t
count_target_graph_cb (const wyl_policy_fact_graph_info_t *info,
    gpointer user_data)
{
  guint *count = user_data;
  if (g_strcmp0 (info->tenant_id, "tenant-a") == 0
      && g_strcmp0 (info->graph_id, "orders") == 0)
    (*count)++;
  return WYRELOG_E_OK;
}

static void
test_runtime_policy_forward (void)
{
#if !defined(WYL_TEST_HANDLE_SEAMS)
  g_test_skip ("publication lock hooks require test seams");
  return;
#elif defined(G_OS_WIN32)
  g_test_skip ("this matrix unit uses the POSIX private policy substrate");
  return;
#else
  g_autoptr (wyl_policy_store_t) policy = NULL;
  g_autofree gchar *root = make_root ();
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite",
          NULL);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &policy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (policy), ==,
      WYRELOG_E_OK);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (policy, "tenant-a",
      &created), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t columns[] = {
    {"value", "int64"},
  };
  const wyl_policy_fact_graph_relation_t relations[] = {
    {"marker", columns, G_N_ELEMENTS (columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph = {
    .tenant_id = "tenant-a",
    .graph_id = "orders",
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = relations,
    .n_relations = G_N_ELEMENTS (relations),
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (policy, &graph, NULL),
      ==, WYRELOG_E_OK);

  WylFactGraphKey key = { 0 };
  g_assert_cmpint (wyl_fact_graph_key_init (&key, "tenant-a", "orders"),
      ==, WYRELOG_E_OK);
  WylFactGraphRuntimeManager *manager = NULL;
  g_assert_cmpint (wyl_fact_graph_runtime_manager_new (&manager), ==,
      WYRELOG_E_OK);
  WylFactGraphRuntimeStatus status = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_manager_refresh (manager, &key,
      build_marker_engine, NULL, &status), ==, WYRELOG_E_OK);
  wyl_fact_graph_runtime_status_clear (&status);
  g_assert_cmpint (wyl_fact_graph_runtime_manager_close_admission (manager,
      &key), ==, WYRELOG_E_OK);

  LockTrace trace = { 0 };
  lock_trace_init (&trace);
  wyl_fact_publication_lock_event_set_hook (lock_trace_event, &trace);
  WylFactGraphRuntimePublication publication = { 0 };
  g_assert_cmpint (wyl_fact_graph_runtime_publication_begin_closed (manager,
      &key, &publication), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_runtime_publication_refresh (&publication,
      build_marker_engine, NULL, NULL), ==, WYRELOG_E_OK);
  WylPolicyGraphPublicationFence fence =
      WYL_POLICY_GRAPH_PUBLICATION_FENCE_INIT;
  g_assert_cmpint (wyl_policy_store_graph_publication_fence_begin (policy,
      "tenant-a", "orders", &fence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_graph_publication_fence_commit (&fence),
      ==, WYRELOG_E_OK);
  wyl_policy_store_graph_publication_fence_clear (&fence);
  g_assert_cmpint (wyl_fact_graph_runtime_publication_open (&publication),
      ==, WYRELOG_E_OK);
  wyl_fact_publication_lock_event_set_hook (NULL, NULL);

  guint writer = first_acquired (&trace,
          WYL_FACT_PUBLICATION_LOCK_RUNTIME_WRITER, 0);
  guint state = first_acquired (&trace,
          WYL_FACT_PUBLICATION_LOCK_RUNTIME_STATE, writer + 1);
  guint policy_index = first_acquired (&trace,
          WYL_FACT_PUBLICATION_LOCK_POLICY_FENCE, state + 1);
  g_assert_cmpuint (writer, !=, G_MAXUINT);
  g_assert_cmpuint (state, !=, G_MAXUINT);
  g_assert_cmpuint (policy_index, !=, G_MAXUINT);
  g_assert_cmpuint (writer, <, state);
  g_assert_cmpuint (state, <, policy_index);

  lock_trace_clear (&trace);
  wyl_fact_graph_runtime_manager_shutdown (manager);
  wyl_fact_graph_runtime_manager_unref (manager);
  wyl_fact_graph_key_clear (&key);
  g_clear_pointer (&policy, wyl_policy_store_close);
  remove_tree (root);
#endif
}

int
main (int argc, char **argv)
{
  program_path = argv[0];
  if (argc == 3 && g_strcmp0 (argv[1], CHILD_MODE) == 0) {
#ifndef G_OS_WIN32
    return child_hold_lease (argv[2]) ? 0 : 1;
#else
    return 77;
#endif
  }
  g_test_init (&argc, &argv, NULL);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact/publication-lock-matrix/fresh-policy-after-child-exit",
      test_fresh_policy_after_child_exit);
  g_test_add_func ("/fact/publication-lock-matrix/runtime-policy-forward",
      test_runtime_policy_forward);
#endif
  return g_test_run ();
}
