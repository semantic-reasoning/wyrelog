/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include <string.h>

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <windows.h>

#include "fact/graph-artifact-windows-handle-private.h"
#include "fact/graph-artifact-windows-locator-private.h"
#include "fact/graph-artifact-windows-lock-private.h"
#include "fact/graph-artifact-windows-namespace-private.h"
#include "fact/graph-windows-security-private.h"

static WylFactGraphWinIdentity
identity_for (HANDLE handle)
{
  FILE_ID_INFO info = { 0 };
  WylFactGraphWinIdentity identity = { 0 };

  g_assert_true (GetFileInformationByHandleEx (handle, FileIdInfo, &info,
          sizeof info));
  identity.volume_serial = info.VolumeSerialNumber;
  memcpy (identity.file_id, info.FileId.Identifier, sizeof identity.file_id);
  return identity;
}

typedef struct
{
  WylFactArtifactWinNamespace *namespace_;
} NamespaceReleaseProbe;

static WylFactArtifactWinNamespace *open_namespace_at_path (const gchar * path,
    gboolean create_main, HANDLE * out_graph);

static gpointer
release_namespace_thread (gpointer user_data)
{
  NamespaceReleaseProbe *probe = user_data;
  wyl_fact_artifact_win_namespace_free (probe->namespace_);
  return NULL;
}

static HANDLE
open_scratch_file (gchar **out_path)
{
  g_autoptr (GError) error = NULL;
  gchar *directory = g_dir_make_tmp ("wyl-win-artifact-XXXXXX", &error);
  gchar *path;
  wchar_t *wide;
  HANDLE handle;

  g_assert_no_error (error);
  g_assert_nonnull (directory);
  path = g_build_filename (directory, "facts.duckdb.wal", NULL);
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  g_free (wide);
  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  g_free (directory);
  *out_path = path;
  return handle;
}

static HANDLE
open_existing_scratch_file (const gchar *path)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE handle = CreateFileW (wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);
  return handle;
}

static void
remove_scratch_file (gchar *path)
{
  g_autofree gchar *directory = g_path_get_dirname (path);
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree wchar_t *wide_directory = g_utf8_to_utf16 (directory, -1, NULL,
      NULL, NULL);

  g_assert_true (DeleteFileW (wide));
  g_assert_true (RemoveDirectoryW (wide_directory));
  g_free (path);
}

/* The session, rather than a numeric HANDLE, is the externally visible I/O
 * capability.  Releasing the binding-side state first must not invalidate the
 * live private duplicate, and a second session must not bypass the lifecycle
 * barrier. */
static void
test_private_io_session_lifetime_and_singleton (void)
{
  gchar *path = NULL;
  HANDLE source = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (source);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *first = NULL;
  WylFactArtifactWinIoSession *second = NULL;
  gchar readback[4] = { 0 };
  gsize n = 0;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (source,
          &identity, &working), ==, WYRELOG_E_OK);
  source = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &second), ==,
      WYRELOG_E_BUSY);
  g_assert_null (second);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (first, 0, "abc",
          3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpuint (n, ==, 3);
  /* Drops the binding's reference. The active session owns the remaining
   * private state until finish. */
  wyl_fact_artifact_win_io_state_free (state);
  state = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (first, 0, readback,
          3, &n), ==, WYRELOG_E_OK);
  g_assert_cmpstr (readback, ==, "abc");
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (first), ==,
      WYRELOG_E_OK);
  remove_scratch_file (path);
}

static void
test_io_session_guardian_failure_is_policy (void)
{
  gchar *path = NULL;
  HANDLE source = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (source);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  g_autofree gchar *directory = NULL;
  g_autofree gchar *alternate_path = NULL;
  g_autofree wchar_t *source_wide = NULL;
  g_autofree wchar_t *alternate_wide = NULL;
  guint64 size = 0;
  gchar byte = 0;
  gsize read = 0;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (source,
          &identity, &working), ==, WYRELOG_E_OK);
  source = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session),
      ==, WYRELOG_E_OK);
  /* A hard-link changes the guardian's required single-link association.
   * Every typed I/O operation must preserve POLICY, not relabel this security
   * failure as INVALID (which is reserved for malformed arguments). */
  directory = g_path_get_dirname (path);
  alternate_path = g_build_filename (directory, "alternate", NULL);
  source_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  alternate_wide = g_utf8_to_utf16 (alternate_path, -1, NULL, NULL, NULL);
  g_assert_true (CreateHardLinkW (alternate_wide, source_wide, NULL));
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  /* The exact FileId/name may come back, but a session that observed an
   * association failure remains terminally revoked. */
  g_assert_true (MoveFileExW (outside_wide, wal_wide, MOVEFILE_WRITE_THROUGH));
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, &byte,
          1, &read), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0, NULL,
          1, &read), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_true (DeleteFileW (alternate_wide));
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_session_blocks_mutation_until_finish (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-session-XXXXXX", &error);
  WylFactArtifactWinNamespace *namespace_;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactArtifactWinMutationEffect effect;
  HANDLE graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  /* open_namespace_at_path owns only the graph HANDLE; its entries have been
   * retired from the test namespace by the OS directory teardown below. */
  CloseHandle (graph);
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *checkpoint_path = g_build_filename (path,
        "facts.duckdb.wal.checkpoint", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *checkpoint_wide =
        g_utf8_to_utf16 (checkpoint_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (checkpoint_wide));
    g_assert_true (RemoveDirectoryW (wide));
  }
}

static void
test_session_retains_mutation_lease_until_finish (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-session-lease-XXXXXX",
      &error);
  WylFactArtifactWinNamespace *first;
  WylFactArtifactWinNamespace *second;
  WylFactArtifactWinLease *held_lease = NULL;
  WylFactArtifactWinLease *fresh_lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE first_graph = INVALID_HANDLE_VALUE;
  HANDLE second_graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  first = open_namespace_at_path (path, TRUE, &first_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (first,
          &held_lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (held_lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  /* Releasing every public owner must not release the private session lease. */
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  wyl_fact_artifact_win_lease_free (held_lease);
  held_lease = NULL;
  wyl_fact_artifact_win_namespace_free (first);
  first = NULL;

  second = open_namespace_at_path (path, FALSE, &second_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (second,
          &fresh_lease), ==, WYRELOG_E_BUSY);
  g_assert_null (fresh_lease);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (second,
          &fresh_lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (fresh_lease);
  wyl_fact_artifact_win_namespace_free (second);
  CloseHandle (first_graph);
  CloseHandle (second_graph);
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *wal_path =
        g_build_filename (path, "facts.duckdb.wal", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wal_wide =
        g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *directory_wide =
        g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (wal_wide));
    g_assert_true (RemoveDirectoryW (directory_wide));
  }
}

/* These are namespace (not merely locator) adversaries.  The replacement is
 * performed through the native Win32 namespace after a binding was minted:
 * the retained graph HANDLE must not turn a hard link or reparse spelling
 * into authority over a different entry. */
static void
test_native_namespace_reparse_and_hardlink_substitution (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-substitute-XXXXXX", &error);
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *wal_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  HANDLE graph = INVALID_HANDLE_VALUE;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;

  main_path = g_build_filename (path, "facts.duckdb", NULL);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  wal_wide = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (wal_wide));
  g_assert_true (CreateHardLinkW (wal_wide, main_wide, NULL));
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_true (CloseHandle (graph));
  graph = INVALID_HANDLE_VALUE;
  g_assert_true (DeleteFileW (wal_wide));

  namespace_ = open_namespace_at_path (path, FALSE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  /* GitHub Windows runners permit unprivileged symlink creation.  A failure
   * is still a hard test failure: silently skipping would leave the reparse
   * substitution acceptance requirement unproven. */
  g_assert_true (CreateSymbolicLinkW (wal_wide, main_wide,
          SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE));
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, FALSE, &sidecar), ==, WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  g_assert_true (DeleteFileW (wal_wide));
  g_assert_true (DeleteFileW (main_wide));
  {
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (lock_wide));
  }
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
}

static HANDLE
open_scratch_directory (gchar **out_path)
{
  g_autoptr (GError) error = NULL;
  gchar *path = g_dir_make_tmp ("wyl-win-locator-XXXXXX", &error);
  g_autofree wchar_t *wide = NULL;
  HANDLE handle;

  g_assert_no_error (error);
  g_assert_nonnull (path);
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_nonnull (wide);
  handle = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
      | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE
      | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (handle != INVALID_HANDLE_VALUE);
  *out_path = path;
  return handle;
}

static WylFactArtifactWinLocator *
open_locator_for_test (HANDLE graph, WylFactGraphWinIdentity *out_identity)
{
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;

  *out_identity = identity_for (graph);
  directory.graph_handle = graph;
  directory.graph_identity = *out_identity;
  g_assert_cmpint (wyl_fact_artifact_win_locator_new (&directory, &locator),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (locator);
  return locator;
}

/* This opens the same graph from a fresh process.  It deliberately uses no
 * inherited HANDLE: the child must prove that the on-disk protected entries
 * and LockFileEx domain, rather than this test process' static domain table,
 * enforce the lease. */
static WylFactArtifactWinNamespace *
open_namespace_at_path (const gchar *path, gboolean create_main,
    HANDLE *out_graph)
{
  g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;
  WylFactArtifactWinEntry *entry = NULL;
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  HANDLE graph;
  HANDLE main = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  g_assert_nonnull (wide);
  graph = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
      | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (graph != INVALID_HANDLE_VALUE);
  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  locator = open_locator_for_test (graph, &directory.graph_identity);
  rc = wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
      GENERIC_READ | GENERIC_WRITE, create_main, &entry);
  if (rc == WYRELOG_E_BUSY && create_main)
    rc = wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
        GENERIC_READ | GENERIC_WRITE, FALSE, &entry);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
          entry, &main), ==, WYRELOG_E_OK);
  main_file.handle = main;
  main_file.identity = *wyl_fact_artifact_win_entry_identity (entry);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new_with_main (&directory,
          &main_file, &namespace_), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (main));
  wyl_fact_artifact_win_entry_free (entry);
  wyl_fact_artifact_win_locator_free (locator);
  *out_graph = graph;
  return namespace_;
}

enum
{
  LEASE_CHILD_OK = 0,
  LEASE_CHILD_BUSY = 42,
  LEASE_CHILD_ERROR = 43,
};

static int
run_lease_child (const gchar *mode, const gchar *path)
{
  HANDLE graph = INVALID_HANDLE_VALUE;
  WylFactArtifactWinNamespace *namespace_ = open_namespace_at_path (path,
      FALSE, &graph);
  WylFactArtifactWinLease *lease = NULL;
  wyrelog_error_t rc = strcmp (mode, "reader") == 0
      || strcmp (mode, "hold-reader") == 0
      ? wyl_fact_artifact_win_namespace_acquire_reader (namespace_, &lease)
      : strcmp (mode, "mutation") == 0
      ? wyl_fact_artifact_win_namespace_acquire_mutation (namespace_, &lease)
      : WYRELOG_E_INVALID;
  int result = rc == WYRELOG_E_OK ? LEASE_CHILD_OK
      : rc == WYRELOG_E_BUSY ? LEASE_CHILD_BUSY : LEASE_CHILD_ERROR;

  if (result == LEASE_CHILD_OK && strcmp (mode, "hold-reader") == 0)
    Sleep (INFINITE);           /* Parent proves crash-release via terminate. */
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  return result;
}

static HANDLE
spawn_lease_child (const gchar *mode, const gchar *path)
{
  wchar_t executable[MAX_PATH + 1] = { 0 };
  DWORD length = GetModuleFileNameW (NULL, executable,
      G_N_ELEMENTS (executable));
  g_autofree gchar *exe_utf8 = NULL;
  g_autofree gchar *command_utf8 = NULL;
  g_autofree wchar_t *command = NULL;
  STARTUPINFOW startup = {.cb = sizeof startup };
  PROCESS_INFORMATION process = { 0 };

  g_assert_cmpuint (length, >, 0);
  g_assert_cmpuint (length, <, G_N_ELEMENTS (executable));
  exe_utf8 = g_utf16_to_utf8 ((gunichar2 *) executable, -1, NULL, NULL, NULL);
  g_assert_nonnull (exe_utf8);
  command_utf8 = g_strdup_printf ("\"%s\" --win-lease-child %s \"%s\"",
      exe_utf8, mode, path);
  command = g_utf8_to_utf16 (command_utf8, -1, NULL, NULL, NULL);
  g_assert_nonnull (command);
  g_assert_true (CreateProcessW (NULL, command, NULL, NULL, FALSE,
          CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
  g_assert_true (CloseHandle (process.hThread));
  return process.hProcess;
}

static void
assert_child_exit (HANDLE process, DWORD expected)
{
  DWORD exit_code = STILL_ACTIVE;
  g_assert_cmpuint (WaitForSingleObject (process, 10000), ==, WAIT_OBJECT_0);
  g_assert_true (GetExitCodeProcess (process, &exit_code));
  g_assert_cmpuint (exit_code, ==, expected);
  g_assert_true (CloseHandle (process));
}

static void
test_native_namespace_cross_process_leases_and_crash_release (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  HANDLE child;
  gboolean observed_busy = FALSE;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;

  g_assert_true (CloseHandle (graph));
  graph = INVALID_HANDLE_VALUE;
  namespace_ = open_namespace_at_path (path, TRUE, &graph);

  /* These are independent processes, so success would prove that the native
   * lock is process-local rather than kernel-enforced. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_reader (namespace_,
          &lease), ==, WYRELOG_E_OK);
  child = spawn_lease_child ("mutation", path);
  assert_child_exit (child, LEASE_CHILD_BUSY);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
      (namespace_, &lease), ==, WYRELOG_E_OK);
  child = spawn_lease_child ("reader", path);
  assert_child_exit (child, LEASE_CHILD_BUSY);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  /* A killed reader has no finally block.  Poll until its real kernel lease
   * is observed, terminate it, then require a fresh mutation lease. */
  child = spawn_lease_child ("hold-reader", path);
  for (guint i = 0; i < 200; i++) {
    wyrelog_error_t rc = wyl_fact_artifact_win_namespace_acquire_mutation
        (namespace_, &lease);
    if (rc == WYRELOG_E_BUSY) {
      observed_busy = TRUE;
      break;
    }
    if (rc == WYRELOG_E_OK) {
      wyl_fact_artifact_win_lease_free (lease);
      lease = NULL;
    } else
      g_assert_cmpint (rc, ==, WYRELOG_E_BUSY);
    Sleep (25);
  }
  g_assert_true (observed_busy);
  g_assert_true (TerminateProcess (child, 0xC000013A));
  g_assert_cmpuint (WaitForSingleObject (child, 10000), ==, WAIT_OBJECT_0);
  g_assert_true (CloseHandle (child));
  child = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
      (namespace_, &lease), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_locator_directory_flush_capability_mapping (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph, &identity);
  g_autofree wchar_t *wide = NULL;

  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
      (ERROR_NOT_SUPPORTED);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
      (ERROR_INVALID_FUNCTION);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_win_locator_fail_next_directory_flush_for_test
      (ERROR_WRITE_FAULT);
  g_assert_cmpint (wyl_fact_artifact_win_locator_flush_directory (locator), ==,
      WYRELOG_E_IO);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (wide));
  g_free (path);
}

static void
test_locator_relative_entry_lifecycle (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph,
      &graph_identity);
  WylFactArtifactWinEntry *entry = NULL;
  WylFactArtifactWinEntry *occupied = NULL;
  WylFactArtifactWinEntry *replacement = NULL;
  HANDLE issued = INVALID_HANDLE_VALUE;
  DWORD flags = HANDLE_FLAG_INHERIT;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  wyrelog_error_t flush_rc;
  g_autofree gchar *renamed = g_build_filename (path, "facts.duckdb.wal", NULL);
  g_autofree gchar *outside = g_build_filename (path, "outside", NULL);
  g_autofree wchar_t *wide = NULL;
  g_autofree wchar_t *outside_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator,
          "tmp-source", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &entry),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "occupied",
          GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &occupied), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_rename_no_replace (locator,
          entry, "occupied", &effect), ==, WYRELOG_E_BUSY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator,
          occupied, &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (occupied);
  occupied = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
          entry, &issued), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (issued, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_true (CloseHandle (issued));
  g_assert_cmpint (wyl_fact_artifact_win_entry_rename_no_replace (locator,
          entry, "facts.duckdb.wal", &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_entry_revalidate (locator, entry),
      ==, WYRELOG_E_OK);
  /* Move the entry outside the canonical name and install a replacement.  A
   * stale entry's working-HANDLE issuance must validate the whole locator
   * hierarchy/name association, not only its retained HANDLE/FileId. */
  wide = g_utf8_to_utf16 (renamed, -1, NULL, NULL, NULL);
  outside_wide = g_utf8_to_utf16 (outside, -1, NULL, NULL, NULL);
  g_assert_true (MoveFileExW (wide, outside_wide, MOVEFILE_WRITE_THROUGH));
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator,
          "facts.duckdb.wal", GENERIC_READ | GENERIC_WRITE | DELETE, TRUE,
          &replacement), ==, WYRELOG_E_OK);
  issued = (HANDLE) 1;
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
          entry, &issued), ==, WYRELOG_E_POLICY);
  g_assert_true (issued == INVALID_HANDLE_VALUE);
  wyl_fact_artifact_win_entry_free (entry);
  entry = NULL;
  g_assert_true (DeleteFileW (wal_wide));
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator,
          replacement, &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (replacement);
  replacement = NULL;
  /* Filesystems that cannot flush a directory fail closed: the physical
   * operation is still independently proven by its explicit return value. */
  flush_rc = wyl_fact_artifact_win_locator_flush_directory (locator);
  g_assert_true (flush_rc == WYRELOG_E_OK || flush_rc == WYRELOG_E_IO
      || flush_rc == WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_clear_pointer (&wide, g_free);
  wide = g_utf8_to_utf16 (renamed, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (wide) != INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_locator_nested_directory_transport (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinLocator *locator = open_locator_for_test (graph,
      &graph_identity);
  WylFactArtifactWinDirectory *root = NULL;
  WylFactArtifactWinDirectory *stale_root = NULL;
  WylFactArtifactWinEntry *child = NULL;
  HANDLE issued = INVALID_HANDLE_VALUE;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  DWORD flags = HANDLE_FLAG_INHERIT;
  g_autofree gchar *root_path = g_build_filename (path, "duckdb-root", NULL);
  g_autofree gchar *child_path = g_build_filename (root_path,
      "duckdb_temp_storage_DEFAULT-1.tmp", NULL);
  g_autofree gchar *old_child_path = g_build_filename (root_path,
      "child-old", NULL);
  g_autofree gchar *stale_path = g_build_filename (path, "stale-root", NULL);
  g_autofree gchar *stale_old_path = g_build_filename (path,
      "stale-root-old", NULL);
  g_autofree wchar_t *root_wide = g_utf8_to_utf16 (root_path, -1, NULL, NULL,
      NULL);
  g_autofree wchar_t *child_wide = g_utf8_to_utf16 (child_path, -1, NULL,
      NULL, NULL);
  g_autofree wchar_t *old_child_wide = g_utf8_to_utf16 (old_child_path, -1,
      NULL, NULL, NULL);
  g_autofree wchar_t *stale_wide = g_utf8_to_utf16 (stale_path, -1, NULL,
      NULL, NULL);
  g_autofree wchar_t *stale_old_wide = g_utf8_to_utf16 (stale_old_path, -1,
      NULL, NULL, NULL);

  g_assert_cmpint (wyl_fact_artifact_win_locator_create_directory (locator,
          "duckdb-root", &root), ==, WYRELOG_E_OK);
  HANDLE root_handle = CreateFileW (root_wide, READ_CONTROL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  g_assert_true (root_handle != INVALID_HANDLE_VALUE);
  g_assert_cmpint (wyl_fact_graph_win_validate_protected_owner_acl (root_handle,
          0), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (root_handle));
  g_assert_cmpint (wyl_fact_artifact_win_directory_open_file (locator, root,
          "duckdb_temp_storage_DEFAULT-1.tmp",
          GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &child), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_issue_working_handle
      (locator, root, child, &issued), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (issued, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_cmpint (wyl_fact_graph_win_validate_protected_owner_acl (issued, 0),
      ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (issued));
  issued = INVALID_HANDLE_VALUE;

  /* Replacing a child's canonical name cannot turn the retained entry into a
   * new working capability.  The output is initialized on this failure. */
  g_assert_true (MoveFileExW (child_wide, old_child_wide,
          MOVEFILE_WRITE_THROUGH));
  HANDLE replacement = CreateFileW (child_wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (replacement != INVALID_HANDLE_VALUE);
  g_assert_true (CloseHandle (replacement));
  issued = (HANDLE) 1;
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_issue_working_handle
      (locator, root, child, &issued), ==, WYRELOG_E_POLICY);
  g_assert_true (issued == INVALID_HANDLE_VALUE);
  wyl_fact_artifact_win_entry_free (child);
  child = NULL;
  g_assert_true (DeleteFileW (old_child_wide));
  g_assert_true (DeleteFileW (child_wide));
  /* Reopen a fresh exact child, then prove child-before-root deletion. */
  g_assert_cmpint (wyl_fact_artifact_win_directory_open_file (locator, root,
          "duckdb_temp_storage_DEFAULT-1.tmp",
          GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, &child), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_directory_entry_delete_exact (locator,
          root, child, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  DWORD handles_before_child_free = 0;
  DWORD handles_after_child_free = 0;
  g_assert_true (GetProcessHandleCount (GetCurrentProcess (),
          &handles_before_child_free));
  wyl_fact_artifact_win_entry_free (child);
  child = NULL;
  g_assert_true (GetProcessHandleCount (GetCurrentProcess (),
          &handles_after_child_free));
  g_assert_cmpuint (handles_after_child_free + 1, ==,
      handles_before_child_free);
  DWORD handles_before_root_free = 0;
  DWORD handles_after_root_free = 0;
  g_assert_true (GetProcessHandleCount (GetCurrentProcess (),
          &handles_before_root_free));
  g_assert_cmpint (wyl_fact_artifact_win_directory_delete_empty (locator, root,
          &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  wyl_fact_artifact_win_directory_free (root);
  root = NULL;
  g_assert_true (GetProcessHandleCount (GetCurrentProcess (),
          &handles_after_root_free));
  /* DeletePending must not turn the owned directory handle into a destructor
   * leak: terminal cleanup closes exactly that retained handle. */
  g_assert_cmpuint (handles_after_root_free + 1, ==, handles_before_root_free);

  /* The root itself is also name-bound.  A raw name substitution revokes the
   * opaque directory capability, and free must leave the replacement alone. */
  g_assert_cmpint (wyl_fact_artifact_win_locator_create_directory (locator,
          "stale-root", &stale_root), ==, WYRELOG_E_OK);
  g_assert_true (MoveFileExW (stale_wide, stale_old_wide,
          MOVEFILE_WRITE_THROUGH));
  g_assert_true (CreateDirectoryW (stale_wide, NULL));
  g_assert_cmpint (wyl_fact_artifact_win_directory_revalidate (locator,
          stale_root), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_directory_free (stale_root);
  stale_root = NULL;
  g_assert_true (RemoveDirectoryW (stale_wide));
  g_assert_true (RemoveDirectoryW (stale_old_wide));

  wyl_fact_artifact_win_locator_free (locator);
  g_assert_true (CloseHandle (graph));
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL,
      NULL);
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_native_namespace_captured_owner_acl_binding (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinNamespace *owner = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinSidecarBinding *seed = NULL;
  WylFactArtifactWinBinding *binding = NULL;
  WylFactArtifactWinBinding *reopened = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE owner_graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *wal = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  /* Generic fixed I/O is reader-authorized only.  Provision the main and
   * sidecar through the normal imported-main/exclusive-lease path first. */
  owner = open_namespace_at_path (path, TRUE, &owner_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (owner,
          &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation,
          WYL_FACT_ARTIFACT_WAL, TRUE, &seed), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (seed);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (owner);
  owner = NULL;
  g_assert_true (CloseHandle (owner_graph));
  owner_graph = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
          &binding), ==, WYRELOG_E_OK);
  /* MAIN cannot be minted through the generic namespace, including strict
   * creation.  Only #615 evidence import plus an exclusive native lease may
   * issue a main HANDLE. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_MAIN, GENERIC_READ, FALSE,
          &reopened), ==, WYRELOG_E_POLICY);
  g_assert_null (reopened);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
          &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  /* Existing entries must prove the same captured-owner protected DACL before
   * they are re-issued through a new opaque binding. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
          &reopened), ==, WYRELOG_E_OK);
  /* The binding holds its own namespace reference; lifetime handoff must not
   * invalidate native revalidation between a caller releasing the namespace
   * and the final HANDLE close. */
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (reopened,
          &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  /* ACL substitution itself is covered by the locator's controlled native
   * hook. Artifact I/O intentionally has no HANDLE escape route. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
          &reopened), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (reopened,
          &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  /* The legacy gint API remains deliberately unavailable on Windows. */
  g_assert_cmpint (wyl_fact_artifact_namespace_open_file (NULL,
          WYL_FACT_ARTIFACT_WAL, FALSE, TRUE, NULL), ==, WYRELOG_E_POLICY);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  wal = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (wal));
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL,
      NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_native_namespace_release_binding_stress (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinNamespace *owner = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinSidecarBinding *seed = NULL;
  HANDLE owner_graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *wal = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  owner = open_namespace_at_path (path, TRUE, &owner_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (owner,
          &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation,
          WYL_FACT_ARTIFACT_WAL, TRUE, &seed), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (seed);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (owner);
  owner = NULL;
  g_assert_true (CloseHandle (owner_graph));
  owner_graph = INVALID_HANDLE_VALUE;
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  wal = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  for (guint i = 0; i < 64; i++) {
    WylFactArtifactWinNamespace *namespace_ = NULL;
    WylFactArtifactWinBinding *binding = NULL;
    NamespaceReleaseProbe probe = { 0 };
    WylFactArtifactWinIoSession *session = NULL;
    g_autoptr (GThread) releaser = NULL;

    g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
            &namespace_), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
            WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE,
            &binding), ==, WYRELOG_E_OK);
    probe.namespace_ = namespace_;
    releaser = g_thread_new ("namespace-release", release_namespace_thread,
        &probe);
    g_thread_join (g_steal_pointer (&releaser));
    g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
            &session), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
        WYRELOG_E_OK);
    wyl_fact_artifact_win_binding_free (binding);
  }
  g_assert_true (DeleteFileW (wal));
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL,
      NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_generic_reader_session_blocks_cross_namespace_mutation (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-reader-domain-XXXXXX",
      &error);
  WylFactArtifactWinNamespace *seed = NULL;
  WylFactArtifactWinNamespace *reader = NULL;
  WylFactArtifactWinNamespace *writer = NULL;
  WylFactArtifactWinLease *mutation = NULL;
  WylFactArtifactWinLease *writer_mutation = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinBinding *binding = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  HANDLE seed_graph = INVALID_HANDLE_VALUE;
  HANDLE reader_graph = INVALID_HANDLE_VALUE;
  HANDLE writer_graph = INVALID_HANDLE_VALUE;

  g_assert_no_error (error);
  seed = open_namespace_at_path (path, TRUE, &seed_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (seed,
          &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (mutation,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (mutation);
  wyl_fact_artifact_win_namespace_free (seed);
  g_assert_true (CloseHandle (seed_graph));

  {
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    reader_graph = CreateFileW (wide, FILE_LIST_DIRECTORY | FILE_ADD_FILE
        | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
  }
  g_assert_true (reader_graph != INVALID_HANDLE_VALUE);
  directory.graph_handle = reader_graph;
  directory.graph_identity = identity_for (reader_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory, &reader),
      ==, WYRELOG_E_OK);
  /* Failed generic opens must release their reader lease.  Otherwise a
   * missing sidecar would permanently strand an exclusive writer in BUSY. */
  binding = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (reader,
          WYL_FACT_ARTIFACT_CHECKPOINT, GENERIC_READ, FALSE, &binding), ==,
      WYRELOG_E_NOT_FOUND);
  g_assert_null (binding);
  writer = open_namespace_at_path (path, FALSE, &writer_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
          &writer_mutation), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (writer_mutation);
  writer_mutation = NULL;
  wyl_fact_artifact_win_namespace_free (writer);
  writer = NULL;
  g_assert_true (CloseHandle (writer_graph));
  writer_graph = INVALID_HANDLE_VALUE;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (reader,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ, FALSE, &binding), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_open_io_session (binding,
          &session), ==, WYRELOG_E_OK);
  /* The live reader session keeps its private reader lease after all public
   * reader handles are released.  A fresh namespace must still observe BUSY
   * when it asks for an exclusive mutation lease. */
  wyl_fact_artifact_win_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_win_namespace_free (reader);
  reader = NULL;
  writer = open_namespace_at_path (path, FALSE, &writer_graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
          &writer_mutation), ==, WYRELOG_E_BUSY);
  g_assert_null (writer_mutation);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (writer,
          &writer_mutation), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_lease_free (writer_mutation);
  wyl_fact_artifact_win_namespace_free (writer);
  g_assert_true (CloseHandle (reader_graph));
  g_assert_true (CloseHandle (writer_graph));
  {
    g_autofree gchar *main_path = g_build_filename (path, "facts.duckdb", NULL);
    g_autofree gchar *lock_path =
        g_build_filename (path, "facts.duckdb.lock", NULL);
    g_autofree gchar *wal_path =
        g_build_filename (path, "facts.duckdb.wal", NULL);
    g_autofree wchar_t *main_wide =
        g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *lock_wide =
        g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wal_wide =
        g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
    g_autofree wchar_t *wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (main_wide));
    g_assert_true (DeleteFileW (lock_wide));
    g_assert_true (DeleteFileW (wal_wide));
    g_assert_true (RemoveDirectoryW (wide));
  }
}

static void
test_live_session_source_substitution_is_policy (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *path = g_dir_make_tmp ("wyl-win-live-source-XXXXXX",
      &error);
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  HANDLE graph = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree gchar *outside_path = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree wchar_t *wal_wide = NULL;
  g_autofree wchar_t *outside_wide = NULL;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  guint64 size = 0;

  g_assert_no_error (error);
  namespace_ = open_namespace_at_path (path, TRUE, &graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  outside_path = g_build_filename (path, "outside-wal", NULL);
  wal_wide = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  outside_wide = g_utf8_to_utf16 (outside_path, -1, NULL, NULL, NULL);
  g_assert_true (MoveFileExW (wal_wide, outside_wide, MOVEFILE_WRITE_THROUGH));
  /* The private guardian still names the old object, but the session's
   * retained validator must fail the canonical source association before I/O. */
  g_assert_cmpint (wyl_fact_artifact_win_io_session_size (session, &size), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  wyl_fact_artifact_win_lease_free (lease);
  wyl_fact_artifact_win_namespace_free (namespace_);
  g_assert_true (CloseHandle (graph));
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (outside_wide));
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (RemoveDirectoryW (directory_wide));
}

static void
test_working_handle_adopt_noninherit_close_once (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_working_handle_identity_mismatch_initializes_output (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = (gpointer) 0x1;

  identity.file_id[0] ^= 0xff;
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_POLICY);
  g_assert_null (binding);
  g_assert_true (CloseHandle (issued));
  remove_scratch_file (path);
}

static void
test_working_handle_free_never_closes_reused_handle (void)
{
  gchar *path = NULL;
  gchar *foreign_path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE foreign;
  BY_HANDLE_FILE_INFORMATION info = { 0 };

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  /* Adoption consumed |issued| and retained only a private duplicate. */
  g_assert_false (CloseHandle (issued));
  foreign = open_scratch_file (&foreign_path);
  g_assert_true (foreign == issued);
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  remove_scratch_file (path);
}

static void
test_working_handle_source_reuse_cannot_revoke_guardian (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session), ==,
      WYRELOG_E_BUSY);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_session_abort_is_terminal (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *working = NULL;
  WylFactArtifactWinIoState *state = NULL;
  WylFactArtifactWinIoSession *session = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &working), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_state_new (working, &state), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_open (state, &session), ==,
      WYRELOG_E_BUSY);
  wyl_fact_artifact_win_io_state_free (state);
  remove_scratch_file (path);
}

static void
test_native_lock_domain_alias_reader_writer_contention (void)
{
  gchar *path = NULL;
  HANDLE pin = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (pin);
  WylFactGraphWinIdentity directory_identity = identity;
  WylFactArtifactWinLockDomain *domain = NULL;
  WylFactArtifactWinLockDomain *alias_domain = NULL;
  WylFactArtifactWinLockLease *reader_a = NULL;
  WylFactArtifactWinLockLease *reader_b = NULL;
  WylFactArtifactWinLockLease *writer = (gpointer) 0x1;
  HANDLE alias_pin = open_existing_scratch_file (path);
  HANDLE reader_a_handle = open_existing_scratch_file (path);
  HANDLE reader_b_handle = open_existing_scratch_file (path);
  HANDLE writer_handle = open_existing_scratch_file (path);

  /* The key is the graph-directory tuple, not a spelling of its path.  Use a
   * distinct fixture key so parallel tests cannot accidentally join. */
  directory_identity.file_id[0] ^= 0x80;
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
          &identity, pin, &domain), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
          &identity, alias_pin, &alias_domain), ==, WYRELOG_E_OK);
  g_assert_true (domain == alias_domain);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
          reader_a_handle, FALSE, &reader_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
          reader_b_handle, FALSE, &reader_b), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (domain,
          writer_handle, TRUE, &writer), ==, WYRELOG_E_BUSY);
  g_assert_null (writer);
  g_assert_true (CloseHandle (writer_handle));
  wyl_fact_artifact_win_lock_lease_free (reader_a);
  wyl_fact_artifact_win_lock_lease_free (reader_b);
  writer_handle = open_existing_scratch_file (path);
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_acquire (alias_domain,
          writer_handle, TRUE, &writer), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lock_lease_revalidate (writer), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_lock_lease_free (writer);
  wyl_fact_artifact_win_lock_domain_free (alias_domain);
  wyl_fact_artifact_win_lock_domain_free (domain);
  remove_scratch_file (path);
}

typedef struct
{
  WylFactArtifactWinLockDomain *domain;
  const gchar *path;
  gint failure;
} LockStress;

static gpointer
lock_stress_worker (gpointer user_data)
{
  LockStress *stress = user_data;

  for (guint i = 0; i < 200; i++) {
    HANDLE handle = open_existing_scratch_file (stress->path);
    WylFactArtifactWinLockLease *lease = NULL;
    wyrelog_error_t rc =
        wyl_fact_artifact_win_lock_domain_acquire (stress->domain, handle,
        FALSE, &lease);

    if (rc == WYRELOG_E_OK)
      wyl_fact_artifact_win_lock_lease_free (lease);
    else {
      /* Failed acquire retains caller ownership by contract. */
      CloseHandle (handle);
      g_atomic_int_set (&stress->failure, 1);
      break;
    }
  }
  return NULL;
}

static void
test_native_lock_domain_concurrent_acquire_release (void)
{
  gchar *path = NULL;
  HANDLE pin = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (pin);
  WylFactGraphWinIdentity directory_identity = identity;
  WylFactArtifactWinLockDomain *domain = NULL;
  LockStress stress = { 0 };
  GThread *workers[6] = { 0 };

  directory_identity.file_id[0] ^= 0x40;
  g_assert_cmpint (wyl_fact_artifact_win_lock_domain_open (&directory_identity,
          &identity, pin, &domain), ==, WYRELOG_E_OK);
  stress.domain = domain;
  stress.path = path;
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++)
    workers[i] = g_thread_new ("native-lock-stress", lock_stress_worker,
        &stress);
  for (guint i = 0; i < G_N_ELEMENTS (workers); i++)
    g_thread_join (workers[i]);
  g_assert_cmpint (g_atomic_int_get (&stress.failure), ==, 0);
  wyl_fact_artifact_win_lock_domain_free (domain);
  remove_scratch_file (path);
}

static void
test_native_namespace_main_sidecar_lifecycle (void)
{
  gchar *path = NULL;
  HANDLE graph = open_scratch_directory (&path);
  WylFactGraphDirectory directory = WYL_FACT_GRAPH_DIRECTORY_INIT;
  WylFactArtifactWinLocator *locator = NULL;
  WylFactGraphWinIdentity graph_identity = { 0 };
  WylFactArtifactWinEntry *main_entry = NULL;
  WylFactGraphRegularFile main_file = WYL_FACT_GRAPH_REGULAR_FILE_INIT;
  WylFactArtifactWinNamespace *namespace_ = NULL;
  WylFactArtifactWinLease *lease = NULL;
  WylFactArtifactWinMainBinding *main_binding = NULL;
  WylFactArtifactWinSidecarBinding *sidecar = NULL;
  WylFactArtifactWinTempBinding *replacement_source = NULL;
  WylFactArtifactWinTempRoot *temp_root = NULL;
  WylFactArtifactWinTempChild *temp_child = NULL;
  WylFactArtifactWinTempChildBinding *temp_binding = NULL;
  WylFactArtifactWinTempToken *temp_token = NULL;
  WylFactArtifactWinTempRecoveryEvidence *temp_evidence = NULL;
  WylFactArtifactWinIoSession *session = NULL;
  GBytes *temp_evidence_bytes = NULL;
  GBytes *mismatched_temp_evidence_bytes = NULL;
  HANDLE main_handle = INVALID_HANDLE_VALUE;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  WylFactArtifactSidecarRetireResult retire =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  WylFactArtifactWinSidecarReplaceResult replace_result =
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED;
  WylFactDuckdbTempRetireResult temp_retire =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  gsize written = 0;
  g_autofree wchar_t *main_wide = NULL;
  g_autofree wchar_t *lock_wide = NULL;
  g_autofree wchar_t *checkpoint_wide = NULL;
  g_autofree wchar_t *directory_wide = NULL;
  g_autofree wchar_t *old_lock_wide = NULL;
  g_autofree gchar *main_path = NULL;
  g_autofree gchar *lock_path = NULL;
  g_autofree gchar *old_lock_path = NULL;
  g_autofree gchar *checkpoint_path = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  locator = open_locator_for_test (graph, &graph_identity);
  g_assert_cmpint (wyl_fact_artifact_win_locator_open (locator, "facts.duckdb",
          GENERIC_READ | GENERIC_WRITE, TRUE, &main_entry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_entry_issue_working_handle (locator,
          main_entry, &main_handle), ==, WYRELOG_E_OK);
  main_file.handle = main_handle;
  main_file.identity = *wyl_fact_artifact_win_entry_identity (main_entry);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new_with_main (&directory,
          &main_file, &namespace_), ==, WYRELOG_E_OK);
  /* Import does not consume #615's caller-held authority. */
  g_assert_true (CloseHandle (main_handle));
  main_file.handle = NULL;
  wyl_fact_artifact_win_entry_free (main_entry);
  main_entry = NULL;
  wyl_fact_artifact_win_locator_free (locator);
  locator = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (lease, &main_binding),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_open_io_session
      (main_binding, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_main_binding_free (main_binding);
  main_binding = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  /* Checked close consumes only working I/O; the exact lifecycle authority
   * remains available for the one publication and later retirement. */
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_publish_no_replace
      (sidecar, WYL_FACT_ARTIFACT_CHECKPOINT, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
          &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;

  /* #609 replacement consumes only an owner staging binding and an existing
   * closed destination.  A live destination working HANDLE is a hard barrier;
   * after replacement the source is terminal and the destination owns
   * the source identity for its later lifecycle operation. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "old",
          3, &written), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
          "replace-sidecar", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
      (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_write (session, 0, "new",
          3, &written), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  replace_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED;
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
      (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
      (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED);
  {
    gchar replacement_readback[4] = { 0 };
    gsize replacement_read = 0;
    g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
        (sidecar, &session), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_io_session_read (session, 0,
            replacement_readback, 3, &replacement_read), ==, WYRELOG_E_OK);
    g_assert_cmpuint (replacement_read, ==, 3);
    g_assert_cmpstr (replacement_readback, ==, "new");
    g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
        WYRELOG_E_OK);
  }
  sidecar_handle = (HANDLE) 1;
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
      (replacement_source, &session), ==, WYRELOG_E_POLICY);
  g_assert_true (sidecar_handle == INVALID_HANDLE_VALUE);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
          &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;

  /* Abort is terminal before mutation; no external numeric HANDLE is part of
   * the artifact API. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_RECOVERY, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
          "raw-replace", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
      (replacement_source, &session), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  replace_result = WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_REPLACED;
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
      (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_retire (sidecar,
          &retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (retire, ==, WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_autofree gchar *raw_replace_path = g_build_filename (path,
      "tmp-raw-replace", NULL);
  g_autofree wchar_t *raw_replace_wide = g_utf8_to_utf16 (raw_replace_path,
      -1, NULL, NULL, NULL);
  g_assert_true (DeleteFileW (raw_replace_wide));

  /* Native Windows replacement has no target-FileId CAS.  The exclusive
   * lease serializes sanctioned writers, while a deterministic substitution
   * immediately before the final destination revalidation proves that the
   * sanctioned path fails closed without moving its source. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_CHECKPOINT, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
          "pre-final", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
      (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_PRE_FINAL_DESTINATION_SUBSTITUTE);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
      (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_NOT_REPLACED);
  g_autofree gchar *pre_source_path = g_build_filename (path, "tmp-pre-final",
      NULL);
  g_autofree gchar *pre_destination_path = g_build_filename (path,
      "facts.duckdb.wal.checkpoint", NULL);
  g_autofree wchar_t *pre_source_wide = g_utf8_to_utf16 (pre_source_path, -1,
      NULL, NULL, NULL);
  g_autofree wchar_t *pre_destination_wide = g_utf8_to_utf16
      (pre_destination_path, -1, NULL, NULL, NULL);
  g_assert_true (GetFileAttributesW (pre_source_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (GetFileAttributesW (pre_destination_wide) !=
      INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_true (DeleteFileW (pre_source_wide));
  g_assert_true (DeleteFileW (pre_destination_wide));

  /* Once rename linearizes, a later durability/reporting uncertainty is
   * terminal reconciliation evidence rather than a retryable failure. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_RECOVERY, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_open_io_session
      (sidecar, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_binding (lease,
          "post-rename", &replacement_source), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_open_io_session
      (replacement_source, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  wyl_fact_artifact_win_namespace_set_test_fault
      (WYL_FACT_ARTIFACT_WIN_NAMESPACE_TEST_FAULT_REPLACE_POST_RENAME_UNCERTAIN);
  g_assert_cmpint (wyl_fact_artifact_win_temp_binding_replace_sidecar
      (replacement_source, sidecar, &replace_result), ==, WYRELOG_E_IO);
  g_assert_cmpint (replace_result, ==,
      WYL_FACT_ARTIFACT_WIN_SIDECAR_REPLACE_RECONCILE_REQUIRED);
  g_autofree gchar *post_source_path = g_build_filename (path,
      "tmp-post-rename", NULL);
  g_autofree gchar *post_destination_path = g_build_filename (path,
      "facts.duckdb.wal.recovery", NULL);
  g_autofree wchar_t *post_source_wide = g_utf8_to_utf16 (post_source_path,
      -1, NULL, NULL, NULL);
  g_autofree wchar_t *post_destination_wide = g_utf8_to_utf16
      (post_destination_path, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (post_source_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (GetFileAttributesW (post_destination_wide) !=
      INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_temp_binding_free (replacement_source);
  replacement_source = NULL;
  wyl_fact_artifact_win_sidecar_binding_free (sidecar);
  sidecar = NULL;
  g_assert_true (DeleteFileW (post_destination_wide));

  /* Native spill roots are lease-bound virtual authorities: child I/O must
   * be closed through its binding before either child or root can retire. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_root (lease,
          &temp_root), ==, WYRELOG_E_OK);
  g_autofree gchar *temp_logical =
      wyl_fact_artifact_win_temp_root_dup_logical_name (temp_root);
  g_assert_nonnull (temp_logical);
  g_assert_true (g_str_has_prefix (temp_logical, "/wyrelog-duckdb-temp/"));
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
          "duckdb_temp_storage_DEFAULT-1.tmp", &temp_child), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_open (temp_child,
          &temp_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
      (temp_binding, &session), ==, WYRELOG_E_OK);
  WylFactArtifactWinIoSession *second_child_session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
      (temp_binding, &second_child_session), ==, WYRELOG_E_BUSY);
  g_assert_null (second_child_session);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (temp_retire, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_child_free (temp_child);
  temp_child = NULL;
  wyl_fact_artifact_win_temp_child_binding_free (temp_binding);
  temp_binding = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_retire (temp_root,
          &temp_retire), ==, WYRELOG_E_OK);
  g_assert_cmpint (temp_retire, ==, WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED);
  wyl_fact_artifact_win_temp_root_free (temp_root);
  temp_root = NULL;

  /* Adversarial lifecycle: no arbitrary child spelling is accepted and a
   * live opaque session prevents root retirement. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_root (lease,
          &temp_root), ==, WYRELOG_E_OK);
  g_autofree gchar *raw_logical =
      wyl_fact_artifact_win_temp_root_dup_logical_name (temp_root);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
          "../outside", &temp_child), ==, WYRELOG_E_INVALID);
  g_assert_null (temp_child);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_create_child (temp_root,
          "duckdb_temp_block-1.block", &temp_child), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_open (temp_child,
          &temp_binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_root_retire (temp_root,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_open_io_session
      (temp_binding, &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  wyl_fact_artifact_win_temp_child_binding_free (temp_binding);
  temp_binding = NULL;
  g_autofree gchar *raw_root_name = g_strdup (raw_logical
      + strlen ("/wyrelog-duckdb-temp/"));
  g_autofree gchar *raw_root_path = g_build_filename (path, raw_root_name,
      NULL);
  g_autofree gchar *raw_child_path = g_build_filename (raw_root_path,
      "duckdb_temp_block-1.block", NULL);
  g_autofree wchar_t *raw_root_wide = g_utf8_to_utf16 (raw_root_path, -1,
      NULL, NULL, NULL);
  g_autofree wchar_t *raw_child_wide = g_utf8_to_utf16 (raw_child_path, -1,
      NULL, NULL, NULL);
  wyl_fact_artifact_win_temp_child_free (temp_child);
  temp_child = NULL;
  wyl_fact_artifact_win_temp_root_free (temp_root);
  temp_root = NULL;
  /* An aborted session is terminal authority; only external test cleanup
   * removes the untouched child. */
  g_assert_true (DeleteFileW (raw_child_wide));
  g_assert_true (RemoveDirectoryW (raw_root_wide));

  /* #608-equivalent native temp-token lifecycle has no path or CRT-fd
   * escape.  A closed owner may move no-replace, export identity evidence,
   * and be recovered idempotently only through a matching exclusive lease. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_token (lease,
          "token-old", &temp_token), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_open_io_session (temp_token,
          &session), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_rename_no_replace
      (temp_token, "token-next", &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  g_assert_cmpint (wyl_fact_artifact_win_io_session_finish (session), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_rename_no_replace
      (temp_token, "token-next", &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* Unlike unlink, APPLIED rename preserves the same owner authority under
   * its new closed token spelling. */
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_export_recovery_evidence
      (temp_token, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_nonnull (temp_evidence);
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_encode
      (temp_evidence, &temp_evidence_bytes), ==, WYRELOG_E_OK);
  g_assert_nonnull (temp_evidence_bytes);
  /* Simulate process loss: only durable bytes and the artifact remain.
   * Reacquiring the native lease must prove directory + lock + FileId before
   * it can clean up the abandoned token. */
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  wyl_fact_artifact_win_temp_token_free (temp_token);
  temp_token = NULL;
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation
      (namespace_, &lease), ==, WYRELOG_E_OK);
  /* A record from a different graph namespace is likewise not authority in
   * this lease, even when its token spelling happens to collide. */
  {
    gsize evidence_size = 0;
    const guint8 *evidence_data = g_bytes_get_data (temp_evidence_bytes,
        &evidence_size);
    guint8 *mismatch = g_memdup2 (evidence_data, evidence_size);
    mismatch[5] ^= 0x01;        /* serialized graph-directory FileId volume */
    mismatched_temp_evidence_bytes = g_bytes_new_take (mismatch, evidence_size);
  }
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
      (mismatched_temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
          temp_evidence, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  g_bytes_unref (mismatched_temp_evidence_bytes);
  mismatched_temp_evidence_bytes = NULL;
  /* A durable record from another lock/domain cannot be replayed into this
   * otherwise valid lease; it must fail before touching the named artifact. */
  {
    gsize evidence_size = 0;
    const guint8 *evidence_data = g_bytes_get_data (temp_evidence_bytes,
        &evidence_size);
    guint8 *mismatch = g_memdup2 (evidence_data, evidence_size);
    mismatch[29] ^= 0x01;       /* serialized lock FileId volume byte */
    mismatched_temp_evidence_bytes = g_bytes_new_take (mismatch, evidence_size);
  }
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
      (mismatched_temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
          temp_evidence, &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  g_bytes_unref (mismatched_temp_evidence_bytes);
  mismatched_temp_evidence_bytes = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_recovery_evidence_decode
      (temp_evidence_bytes, &temp_evidence), ==, WYRELOG_E_OK);
  g_bytes_unref (temp_evidence_bytes);
  temp_evidence_bytes = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
          temp_evidence, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED);
  /* The same immutable evidence is safe after an already-applied recovery. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_recover_temp_token (lease,
          temp_evidence, &effect), ==, WYRELOG_E_OK);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_recovery_evidence_free (temp_evidence);
  temp_evidence = NULL;
  /* Abort terminally revokes the owner before unlink. */
  g_assert_cmpint (wyl_fact_artifact_win_lease_create_temp_token (lease,
          "token-raw", &temp_token), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_open_io_session (temp_token,
          &session), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_io_session_abort (session);
  session = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_temp_token_unlink (temp_token,
          &effect), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (effect, ==, WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED);
  wyl_fact_artifact_win_temp_token_free (temp_token);
  temp_token = NULL;
  g_autofree gchar *raw_token_path = g_build_filename (path, "tmp-token-raw",
      NULL);
  g_autofree wchar_t *raw_token_wide = g_utf8_to_utf16 (raw_token_path, -1,
      NULL, NULL, NULL);
  g_assert_true (DeleteFileW (raw_token_wide));
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;

  /* An exclusive lease is not authority over a renamed/replaced coordination
   * name.  Both main issuance and sidecar creation fail closed and the
   * replacement is left untouched. */
  main_path = g_build_filename (path, "facts.duckdb", NULL);
  lock_path = g_build_filename (path, "facts.duckdb.lock", NULL);
  old_lock_path = g_build_filename (path, "facts.duckdb.lock.old", NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  old_lock_wide = g_utf8_to_utf16 (old_lock_path, -1, NULL, NULL, NULL);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_acquire_mutation (namespace_,
          &lease), ==, WYRELOG_E_OK);
  g_assert_true (MoveFileExW (lock_wide, old_lock_wide,
          MOVEFILE_WRITE_THROUGH));
  HANDLE replacement = CreateFileW (lock_wide, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL, NULL);
  g_assert_true (replacement != INVALID_HANDLE_VALUE);
  g_assert_true (CloseHandle (replacement));
  main_binding = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_main (lease, &main_binding),
      ==, WYRELOG_E_POLICY);
  g_assert_null (main_binding);
  sidecar = (gpointer) 0x1;
  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_POLICY);
  g_assert_null (sidecar);
  g_assert_true (GetFileAttributesW (lock_wide) != INVALID_FILE_ATTRIBUTES);
  wyl_fact_artifact_win_lease_free (lease);
  lease = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;

  checkpoint_path =
      g_build_filename (path, "facts.duckdb.wal.checkpoint", NULL);
  main_wide = g_utf8_to_utf16 (main_path, -1, NULL, NULL, NULL);
  lock_wide = g_utf8_to_utf16 (lock_path, -1, NULL, NULL, NULL);
  checkpoint_wide = g_utf8_to_utf16 (checkpoint_path, -1, NULL, NULL, NULL);
  g_assert_false (GetFileAttributesW (checkpoint_wide) !=
      INVALID_FILE_ATTRIBUTES);
  g_assert_true (DeleteFileW (main_wide));
  g_assert_true (DeleteFileW (lock_wide));
  g_assert_true (DeleteFileW (old_lock_wide));
  directory_wide = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

int
main (int argc, char **argv)
{
  if (argc == 4 && strcmp (argv[1], "--win-lease-child") == 0)
    return run_lease_child (argv[2], argv[3]);
  g_test_init (&argc, &argv, NULL);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/adopt-close",
      test_working_handle_adopt_noninherit_close_once);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/lifetime-singleton",
      test_private_io_session_lifetime_and_singleton);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/guardian-policy",
      test_io_session_guardian_failure_is_policy);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/mutation-gate",
      test_session_blocks_mutation_until_finish);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/retains-lease",
      test_session_retains_mutation_lease_until_finish);
  g_test_add_func ("/fact/artifact-namespace/windows/locator/entry-lifecycle",
      test_locator_relative_entry_lifecycle);
  g_test_add_func ("/fact/artifact-namespace/windows/locator/nested-transport",
      test_locator_nested_directory_transport);
  g_test_add_func
      ("/fact/artifact-namespace/windows/namespace/captured-owner-binding",
      test_native_namespace_captured_owner_acl_binding);
  g_test_add_func
      ("/fact/artifact-namespace/windows/namespace/release-binding-stress",
      test_native_namespace_release_binding_stress);
  g_test_add_func
      ("/fact/artifact-namespace/windows/namespace/generic-reader-lock-domain",
      test_generic_reader_session_blocks_cross_namespace_mutation);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/source-substitution",
      test_live_session_source_substitution_is_policy);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/identity-output",
      test_working_handle_identity_mismatch_initializes_output);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/free-reused-handle",
      test_working_handle_free_never_closes_reused_handle);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/source-reuse-guardian",
      test_working_handle_source_reuse_cannot_revoke_guardian);
  g_test_add_func
      ("/fact/artifact-namespace/windows/io-session/abort-terminal",
      test_session_abort_is_terminal);
  g_test_add_func
      ("/fact/artifact-namespace/windows/lock-domain/alias-contention",
      test_native_lock_domain_alias_reader_writer_contention);
  g_test_add_func
      ("/fact/artifact-namespace/windows/lock-domain/concurrent-release",
      test_native_lock_domain_concurrent_acquire_release);
  g_test_add_func ("/fact/artifact-namespace/windows/lock-domain/cross-process",
      test_native_namespace_cross_process_leases_and_crash_release);
  g_test_add_func
      ("/fact/artifact-namespace/windows/locator/directory-flush-capability",
      test_locator_directory_flush_capability_mapping);
  g_test_add_func ("/fact/artifact-namespace/windows/namespace/main-sidecar",
      test_native_namespace_main_sidecar_lifecycle);
  g_test_add_func ("/fact/artifact-namespace/windows/namespace/substitution",
      test_native_namespace_reparse_and_hardlink_substitution);
  return g_test_run ();
}
#else
int
main (void)
{
  return 77;
}
#endif
