/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <gio/gio.h>
#include <glib/gstdio.h>

#ifndef G_OS_WIN32
#include <sys/stat.h>
#endif

#include "fact-test-support.h"
#include "fact/root-writer-lease-private.h"
#include "wyrelog/wyl-handle-private.h"

#define HOLDER_ARG "--root-lease-holder"
#define LOCK_NAME ".wyrelog-writer-lock"

static const gchar *self_path;

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
