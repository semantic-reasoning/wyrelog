/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#ifndef G_OS_WIN32
#include <sys/stat.h>
#endif

#include "fact-test-support.h"
#include "fact/root-writer-lease-private.h"
#include "wyrelog/wyl-handle-private.h"

#define HOLDER_ARG "--root-lease-holder"
#define LOCK_NAME ".wyrelog-writer-lock"

static const gchar *self_path;

#ifdef WYL_HAS_FACT_STORE
static void
remove_sqlite_store (const gchar *path)
{
  static const gchar *suffixes[] = {
    ".wyrelog-clear",
    ".wyrelog-lock",
    ".wyrelog-tmp",
    "-journal",
    "-shm",
    "-wal",
  };
  for (guint i = 0; i < G_N_ELEMENTS (suffixes); i++) {
    g_autofree gchar *sidecar = g_strconcat (path, suffixes[i], NULL);
    (void) g_remove (sidecar);
  }
  (void) g_remove (path);
}

static void
assert_sqlite_schema_empty (const gchar *path)
{
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open_v2 (path, &db, SQLITE_OPEN_READONLY, NULL), ==,
      SQLITE_OK);
  sqlite3_stmt *statement = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "SELECT count(*) FROM sqlite_master "
          "WHERE name NOT LIKE 'sqlite_%'", -1, &statement, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (statement), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (statement, 0), ==, 0);
  g_assert_cmpint (sqlite3_finalize (statement), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_close (db), ==, SQLITE_OK);
}
#endif

static gchar *
make_root (const gchar *name)
{
  g_autoptr (GError) error = NULL;
  gchar *root = wyl_test_make_secure_fact_root (name, &error);
  g_assert_no_error (error);
  g_assert_nonnull (root);
  return root;
}

static void
remove_root (const gchar *root)
{
  g_autofree gchar *lock = g_build_filename (root, LOCK_NAME, NULL);
  (void) g_remove (lock);
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_remove_empty_directory (root, &error));
  g_assert_no_error (error);
}

static gint
holder_main (const gchar *root)
{
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  wyrelog_error_t rc = wyl_fact_root_writer_lease_acquire (root, &lease);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_BUSY ? 73 : 74;
  g_print ("READY\n");
  fflush (stdout);
  (void) getchar ();
  return 0;
}

static GSubprocess *
spawn_holder (const gchar *root, GDataInputStream **out_stdout)
{
  const gchar *argv[] = { self_path, HOLDER_ARG, root, NULL };
  g_autoptr (GError) error = NULL;
  GSubprocess *process = g_subprocess_newv (argv,
      G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE
      | G_SUBPROCESS_FLAGS_STDERR_SILENCE, &error);
  g_assert_no_error (error);
  g_assert_nonnull (process);
  *out_stdout = g_data_input_stream_new
      (g_subprocess_get_stdout_pipe (process));
  g_autofree gchar *line = g_data_input_stream_read_line_utf8 (*out_stdout,
      NULL, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (line, ==, "READY");
  return process;
}

static void
stop_holder_orderly (GSubprocess *process)
{
  g_autoptr (GError) error = NULL;
  GOutputStream *input = g_subprocess_get_stdin_pipe (process);
  g_assert_true (g_output_stream_write_all (input, "\n", 1, NULL, NULL,
          &error));
  g_assert_no_error (error);
  g_assert_true (g_output_stream_close (input, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (g_subprocess_wait_check (process, NULL, &error));
  g_assert_no_error (error);
}

static void
test_same_process_identity_and_orderly_release (void)
{
  g_autofree gchar *root_a = make_root ("wyrelog-root-lease-a-XXXXXX");
  g_autofree gchar *root_b = make_root ("wyrelog-root-lease-b-XXXXXX");
  g_autoptr (WylFactRootWriterLease) lease_a = NULL;
  g_autoptr (WylFactRootWriterLease) duplicate = NULL;
  g_autoptr (WylFactRootWriterLease) lease_b = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root_a, &lease_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_verify (lease_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root_a, &duplicate),
      ==, WYRELOG_E_BUSY);
  g_assert_null (duplicate);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root_b, &lease_b), ==,
      WYRELOG_E_OK);

  WylFactGraphResolver resolver_a = WYL_FACT_GRAPH_RESOLVER_INIT;
  WylFactGraphResolver resolver_b = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root_a, &resolver_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_graph_resolver_open (root_b, &resolver_b), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_authorizes_resolver (lease_a,
          &resolver_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_authorizes_resolver (lease_a,
          &resolver_b), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_resolver_clear (&resolver_b);
  wyl_fact_graph_resolver_clear (&resolver_a);

  g_clear_pointer (&lease_a, wyl_fact_root_writer_lease_release);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root_a, &lease_a), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&lease_b, wyl_fact_root_writer_lease_release);
  g_clear_pointer (&lease_a, wyl_fact_root_writer_lease_release);
  remove_root (root_b);
  remove_root (root_a);
}

static void
test_cross_process_orderly_and_crash_recovery (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-lease-process-XXXXXX");
  g_autoptr (GDataInputStream) holder_stdout = NULL;
  g_autoptr (GSubprocess) holder = spawn_holder (root, &holder_stdout);
  g_autoptr (WylFactRootWriterLease) contender = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_BUSY);
  stop_holder_orderly (holder);
  g_clear_object (&holder_stdout);
  g_clear_object (&holder);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&contender, wyl_fact_root_writer_lease_release);

  holder = spawn_holder (root, &holder_stdout);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_BUSY);
  g_subprocess_force_exit (holder);
  g_autoptr (GError) error = NULL;
  g_assert_true (g_subprocess_wait (holder, NULL, &error));
  g_assert_no_error (error);
  g_clear_object (&holder_stdout);
  g_clear_object (&holder);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&contender, wyl_fact_root_writer_lease_release);
  remove_root (root);
}

#ifdef WYL_HAS_FACT_STORE
static void
test_handle_fails_before_policy_open (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-lease-order-XXXXXX");
  g_autofree gchar *policy = g_build_filename (root, "contender.sqlite",
      NULL);
  g_autoptr (WylFactRootWriterLease) holder = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &holder), ==,
      WYRELOG_E_OK);
  WylHandleOpenOptions options = {
    .policy_store_path = policy,
    .fact_root = root,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_BUSY);
  g_assert_null (handle);
  g_assert_false (g_file_test (policy, G_FILE_TEST_EXISTS));
  g_assert_cmpstr (wyrelog_error_string (WYRELOG_E_BUSY), ==,
      "resource is busy");
  g_assert_null (strstr (wyrelog_error_string (WYRELOG_E_BUSY), root));
  g_clear_pointer (&holder, wyl_fact_root_writer_lease_release);
  remove_root (root);
}

static void
test_handle_lifetime_owns_lease (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-handle-lease-XXXXXX");
  WylHandleOpenOptions options = {
    .fact_root = root,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_OK);

  g_autoptr (WylFactRootWriterLease) contender = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_OK);

  g_clear_pointer (&contender, wyl_fact_root_writer_lease_release);
  g_clear_object (&handle);
  remove_root (root);
}

static void
test_handle_init_failure_releases_lease (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-init-fail-XXXXXX");
  g_autofree gchar *missing = g_build_filename (root, "missing-templates",
      NULL);
  WylHandleOpenOptions options = {
    .template_dir = missing,
    .fact_root = root,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), !=,
      WYRELOG_E_OK);
  g_assert_null (handle);

  g_autoptr (WylFactRootWriterLease) contender = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&contender, wyl_fact_root_writer_lease_release);
  remove_root (root);
}

#ifndef G_OS_WIN32
typedef struct
{
  const gchar *root;
  const gchar *old_root;
  gboolean called;
} ReplaceRootCheckpoint;

static void
replace_root_after_lease_acquire (gpointer data)
{
  ReplaceRootCheckpoint *checkpoint = data;
  g_assert_false (checkpoint->called);
  checkpoint->called = TRUE;
  g_assert_cmpint (g_rename (checkpoint->root, checkpoint->old_root), ==, 0);
  g_autoptr (GError) error = NULL;
  g_assert_true (wyl_test_create_secure_directory (checkpoint->root, &error));
  g_assert_no_error (error);
}

static void
test_handle_rejects_replaced_root_before_schema (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-bind-race-XXXXXX");
  g_autofree gchar *old_root = g_strdup_printf ("%s-old", root);
  g_autoptr (GError) error = NULL;
  g_autofree gchar *base = g_dir_make_tmp ("wyrelog-root-bind-db-XXXXXX",
      &error);
  g_assert_no_error (error);
  g_assert_nonnull (base);
  g_autofree gchar *policy = g_build_filename (base, "policy.sqlite", NULL);
  ReplaceRootCheckpoint checkpoint = {
    .root = root,
    .old_root = old_root,
  };
  WylHandleOpenOptions options = {
    .policy_store_path = policy,
    .fact_root = root,
    .fact_root_lease_acquired_checkpoint = replace_root_after_lease_acquire,
    .fact_root_lease_acquired_checkpoint_data = &checkpoint,
  };
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_handle_open_with_options (&options, &handle), ==,
      WYRELOG_E_POLICY);
  g_assert_null (handle);
  g_assert_true (checkpoint.called);

  g_autoptr (GDir) replacement = g_dir_open (root, 0, &error);
  g_assert_no_error (error);
  g_assert_nonnull (replacement);
  g_assert_null (g_dir_read_name (replacement));
  assert_sqlite_schema_empty (policy);

  g_autoptr (WylFactRootWriterLease) contender = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &contender), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&contender, wyl_fact_root_writer_lease_release);
  g_clear_pointer (&replacement, g_dir_close);
  g_assert_cmpint (g_rmdir (root), ==, 0);
  g_assert_cmpint (g_rename (old_root, root), ==, 0);
  remove_sqlite_store (policy);
  g_assert_cmpint (g_rmdir (base), ==, 0);
  remove_root (root);
}
#endif

#ifdef WYL_TEST_WYRELOGD_PATH
static void
test_daemon_collision_is_path_free_and_nonmutating (void)
{
  static const gchar sentinel[] = "LEASE-COLLISION-SENTINEL-541";
  g_autofree gchar *root = make_root ("wyrelog-root-daemon-busy-XXXXXX");
  g_autoptr (GError) error = NULL;
  g_autofree gchar *base = g_dir_make_tmp ("wyrelog-daemon-busy-XXXXXX",
      &error);
  g_assert_no_error (error);
  g_assert_nonnull (base);
  g_autofree gchar *policy = g_build_filename (base, "policy.sqlite", NULL);
  g_autofree gchar *audit = g_build_filename (base, "audit.duckdb", NULL);
  g_autofree gchar *graph = g_build_filename (root, "graph.sentinel", NULL);
  g_assert_true (g_file_set_contents (policy, sentinel, -1, &error));
  g_assert_no_error (error);
  g_assert_true (g_file_set_contents (audit, sentinel, -1, &error));
  g_assert_no_error (error);
  g_assert_true (g_file_set_contents (graph, sentinel, -1, &error));
  g_assert_no_error (error);

  g_autoptr (WylFactRootWriterLease) holder = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &holder), ==,
      WYRELOG_E_OK);
  const gchar *argv[] = {
    WYL_TEST_WYRELOGD_PATH,
    "--template-dir", WYL_TEST_TEMPLATE_DIR,
    "--policy-db", policy,
    "--audit-db", audit,
    "--fact-root", root,
    NULL,
  };
  g_autoptr (GSubprocess) process = g_subprocess_newv (argv,
      G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
  g_assert_no_error (error);
  g_assert_nonnull (process);
  g_autofree gchar *stdout_text = NULL;
  g_autofree gchar *stderr_text = NULL;
  g_assert_true (g_subprocess_communicate_utf8 (process, NULL, NULL,
          &stdout_text, &stderr_text, &error));
  g_assert_no_error (error);
  g_assert_true (g_subprocess_get_if_exited (process));
  g_assert_cmpint (g_subprocess_get_exit_status (process), !=, 0);
  g_auto (GStrv) stderr_lines = g_strsplit_set (stderr_text, "\r\n", -1);
  gboolean found_busy_line = FALSE;
  for (guint i = 0; stderr_lines[i] != NULL; i++)
    if (g_str_equal (stderr_lines[i],
            "wyrelogd: init failed: resource is busy"))
      found_busy_line = TRUE;
  g_assert_true (found_busy_line);
  g_assert_null (strstr (stderr_text, root));
  g_assert_null (strstr (stderr_text, sentinel));

  const gchar *paths[] = { policy, audit, graph };
  for (guint i = 0; i < G_N_ELEMENTS (paths); i++) {
    g_autofree gchar *contents = NULL;
    gsize length = 0;
    g_assert_true (g_file_get_contents (paths[i], &contents, &length, &error));
    g_assert_no_error (error);
    g_assert_cmpuint (length, ==, strlen (sentinel));
    g_assert_cmpmem (contents, length, sentinel, strlen (sentinel));
  }

  g_clear_pointer (&holder, wyl_fact_root_writer_lease_release);
  g_assert_cmpint (g_remove (graph), ==, 0);
  g_assert_cmpint (g_remove (audit), ==, 0);
  g_assert_cmpint (g_remove (policy), ==, 0);
  g_assert_cmpint (g_rmdir (base), ==, 0);
  remove_root (root);
}
#endif
#endif

#ifndef G_OS_WIN32
static void
test_replacement_and_insecure_root_fail_closed (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-lease-replace-XXXXXX");
  g_autofree gchar *old_root = g_strdup_printf ("%s-old", root);
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (g_rename (root, old_root), ==, 0);
  g_assert_cmpint (g_mkdir (root, 0700), ==, 0);
  g_assert_cmpint (wyl_fact_root_writer_lease_verify (lease), ==,
      WYRELOG_E_POLICY);
  WylFactGraphResolver replacement = WYL_FACT_GRAPH_RESOLVER_INIT;
  g_assert_cmpint (wyl_fact_graph_resolver_open (root, &replacement), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_root_writer_lease_authorizes_resolver (lease,
          &replacement), ==, WYRELOG_E_POLICY);
  wyl_fact_graph_resolver_clear (&replacement);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  g_assert_cmpint (g_rmdir (root), ==, 0);
  g_assert_cmpint (g_rename (old_root, root), ==, 0);
  g_assert_cmpint (g_chmod (root, 0755), ==, 0);
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  remove_root (root);
}
#else
static void
test_lock_artifact_shape_is_enforced (void)
{
  g_autofree gchar *root = make_root ("wyrelog-root-lease-shape-XXXXXX");
  g_autofree gchar *lock = g_build_filename (root, LOCK_NAME, NULL);
  g_autoptr (WylFactRootWriterLease) lease = NULL;
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_OK);
  g_clear_pointer (&lease, wyl_fact_root_writer_lease_release);
  g_assert_true (g_file_set_contents (lock, "foreign", 7, NULL));
  g_assert_cmpint (wyl_fact_root_writer_lease_acquire (root, &lease), ==,
      WYRELOG_E_POLICY);
  remove_root (root);
}
#endif

int
main (int argc, char **argv)
{
  if (argc == 3 && g_strcmp0 (argv[1], HOLDER_ARG) == 0)
    return holder_main (argv[2]);
  self_path = argv[0];
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact-root-writer-lease/same-process",
      test_same_process_identity_and_orderly_release);
  g_test_add_func ("/fact-root-writer-lease/process-recovery",
      test_cross_process_orderly_and_crash_recovery);
#ifdef WYL_HAS_FACT_STORE
  g_test_add_func ("/fact-root-writer-lease/handle-order",
      test_handle_fails_before_policy_open);
  g_test_add_func ("/fact-root-writer-lease/handle-lifetime",
      test_handle_lifetime_owns_lease);
  g_test_add_func ("/fact-root-writer-lease/handle-init-failure",
      test_handle_init_failure_releases_lease);
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-root-writer-lease/handle-root-replacement",
      test_handle_rejects_replaced_root_before_schema);
#endif
#ifdef WYL_TEST_WYRELOGD_PATH
  g_test_add_func ("/fact-root-writer-lease/daemon-collision",
      test_daemon_collision_is_path_free_and_nonmutating);
#endif
#endif
#ifndef G_OS_WIN32
  g_test_add_func ("/fact-root-writer-lease/replacement",
      test_replacement_and_insecure_root_fail_closed);
#else
  g_test_add_func ("/fact-root-writer-lease/artifact-shape",
      test_lock_artifact_shape_is_enforced);
#endif
  return g_test_run ();
}
