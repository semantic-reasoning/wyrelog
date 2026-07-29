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
  g_assert_true (DeleteFileW (outside_wide));
  g_assert_cmpint (wyl_fact_artifact_win_entry_delete_exact (locator,
          replacement, &effect), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_entry_free (replacement);
  replacement = NULL;
  /* Filesystems that cannot flush a directory fail closed: the physical
   * operation is still independently proven by its explicit return value. */
  flush_rc = wyl_fact_artifact_win_locator_flush_directory (locator);
  g_assert_true (flush_rc == WYRELOG_E_OK || flush_rc == WYRELOG_E_IO);
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
  WylFactArtifactWinBinding *binding = NULL;
  WylFactArtifactWinBinding *reopened = NULL;
  HANDLE borrowed = INVALID_HANDLE_VALUE;
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *wal = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ | GENERIC_WRITE, TRUE,
          &binding), ==, WYRELOG_E_OK);
  /* MAIN cannot be minted through the generic namespace, including strict
   * creation.  Only #615 evidence import plus an exclusive native lease may
   * issue a main HANDLE. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_MAIN, GENERIC_READ | GENERIC_WRITE, TRUE,
          &reopened), ==, WYRELOG_E_POLICY);
  g_assert_null (reopened);
  g_assert_cmpint (wyl_fact_artifact_win_binding_borrow (binding, &borrowed),
      ==, WYRELOG_E_OK);
  /* Creation must have used the owner captured at namespace construction,
   * rather than inherited ACLs from this intentionally ordinary test root. */
  g_assert_cmpint (wyl_fact_graph_win_validate_protected_owner_acl (borrowed,
          0), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_revalidate (binding), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_close (binding, &borrowed),
      ==, WYRELOG_E_OK);
  g_assert_true (borrowed == INVALID_HANDLE_VALUE);
  wyl_fact_artifact_win_binding_free (binding);
  binding = NULL;
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  /* Existing entries must prove the same captured-owner protected DACL before
   * they are re-issued through a new opaque binding. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ | GENERIC_WRITE, FALSE,
          &reopened), ==, WYRELOG_E_OK);
  /* The binding holds its own namespace reference; lifetime handoff must not
   * invalidate native revalidation between a caller releasing the namespace
   * and the final HANDLE close. */
  wyl_fact_artifact_win_namespace_free (namespace_);
  namespace_ = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_binding_borrow (reopened, &borrowed),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_close (reopened, &borrowed),
      ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  /* Reopen once more, then change the ACL behind the held entry.  This must
   * revoke the live binding and reject a later existing-entry issuance. */
  g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
          &namespace_), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ | GENERIC_WRITE, FALSE,
          &reopened), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_binding_borrow (reopened, &borrowed),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (SetSecurityInfo (borrowed, SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
          NULL, NULL, NULL, NULL), ==, ERROR_SUCCESS);
  g_assert_cmpint (wyl_fact_artifact_win_binding_revalidate (reopened), ==,
      WYRELOG_E_POLICY);
  wyl_fact_artifact_win_binding_free (reopened);
  reopened = NULL;
  g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
          WYL_FACT_ARTIFACT_WAL, GENERIC_READ | GENERIC_WRITE, FALSE,
          &reopened), ==, WYRELOG_E_POLICY);
  g_assert_null (reopened);
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
  g_autofree gchar *wal_path = NULL;
  g_autofree wchar_t *wal = NULL;

  directory.graph_handle = graph;
  directory.graph_identity = identity_for (graph);
  wal_path = g_build_filename (path, "facts.duckdb.wal", NULL);
  wal = g_utf8_to_utf16 (wal_path, -1, NULL, NULL, NULL);
  for (guint i = 0; i < 64; i++) {
    WylFactArtifactWinNamespace *namespace_ = NULL;
    WylFactArtifactWinBinding *binding = NULL;
    NamespaceReleaseProbe probe = { 0 };
    HANDLE borrowed = INVALID_HANDLE_VALUE;
    g_autoptr (GThread) releaser = NULL;

    g_assert_cmpint (wyl_fact_artifact_win_namespace_new (&directory,
            &namespace_), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_namespace_open_fixed (namespace_,
            WYL_FACT_ARTIFACT_WAL, GENERIC_READ | GENERIC_WRITE, TRUE,
            &binding), ==, WYRELOG_E_OK);
    probe.namespace_ = namespace_;
    releaser = g_thread_new ("namespace-release", release_namespace_thread,
        &probe);
    /* The binding's atomic retained reference keeps locator validation live
     * regardless of whether the release thread wins this race. */
    for (guint attempt = 0; attempt < 8; attempt++)
      g_assert_cmpint (wyl_fact_artifact_win_binding_revalidate (binding), ==,
          WYRELOG_E_OK);
    g_thread_join (g_steal_pointer (&releaser));
    g_assert_cmpint (wyl_fact_artifact_win_binding_borrow (binding, &borrowed),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_fact_artifact_win_binding_close (binding, &borrowed),
        ==, WYRELOG_E_OK);
    wyl_fact_artifact_win_binding_free (binding);
    g_assert_true (DeleteFileW (wal));
  }
  g_autofree wchar_t *directory_wide = g_utf8_to_utf16 (path, -1, NULL,
      NULL, NULL);
  g_assert_true (CloseHandle (graph));
  g_assert_true (RemoveDirectoryW (directory_wide));
  g_free (path);
}

static void
test_working_handle_adopt_noninherit_close_once (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE borrowed = INVALID_HANDLE_VALUE;
  DWORD flags = HANDLE_FLAG_INHERIT;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_nonnull (binding);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_OK);
  g_assert_true (GetHandleInformation (borrowed, &flags));
  g_assert_cmpuint (flags & HANDLE_FLAG_INHERIT, ==, 0);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &borrowed), ==, WYRELOG_E_OK);
  g_assert_cmpint (borrowed == INVALID_HANDLE_VALUE, ==, TRUE);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  wyl_fact_artifact_win_working_handle_free (binding);
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
  /* Deliberately violate ownership, then force the native handle table to
   * assign the stale numeric value to a distinct file.  Windows reuses a
   * just-closed value immediately; treating failure here as a skip would
   * make the safety regression non-evidence. */
  g_assert_true (CloseHandle (issued));
  foreign = open_scratch_file (&foreign_path);
  g_assert_true (foreign == issued);
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  remove_scratch_file (path);
}

static void
test_working_handle_raw_close_revokes_as_policy (void)
{
  gchar *path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE borrowed = (HANDLE) 1;

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_true (CloseHandle (issued));
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  g_assert_true (borrowed == INVALID_HANDLE_VALUE);
  /* There is no valid owned HANDLE after raw close; free only discards the
   * terminal binding and must not attempt CloseHandle on its stale value. */
  wyl_fact_artifact_win_working_handle_free (binding);
  remove_scratch_file (path);
}

static void
test_working_handle_close_mismatch_revokes_without_foreign_close (void)
{
  gchar *path = NULL;
  gchar *foreign_path = NULL;
  HANDLE issued = open_scratch_file (&path);
  WylFactGraphWinIdentity identity = identity_for (issued);
  WylFactArtifactWinWorkingHandle *binding = NULL;
  HANDLE foreign = open_scratch_file (&foreign_path);
  HANDLE supplied = foreign;
  HANDLE borrowed = (HANDLE) 1;
  BY_HANDLE_FILE_INFORMATION info = { 0 };

  g_assert_cmpint (wyl_fact_artifact_win_working_handle_adopt (issued,
          &identity, &binding), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_close (binding,
          &supplied), ==, WYRELOG_E_POLICY);
  g_assert_true (supplied == foreign);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_cmpint (wyl_fact_artifact_win_working_handle_borrow (binding,
          &borrowed), ==, WYRELOG_E_POLICY);
  g_assert_true (borrowed == INVALID_HANDLE_VALUE);
  /* _free may close only the still-exact owned value, never |foreign|. */
  wyl_fact_artifact_win_working_handle_free (binding);
  g_assert_true (GetFileInformationByHandle (foreign, &info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
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
  WylFactArtifactWinTempRoot *temp_root = NULL;
  WylFactArtifactWinTempChild *temp_child = NULL;
  WylFactArtifactWinTempChildBinding *temp_binding = NULL;
  HANDLE main_handle = INVALID_HANDLE_VALUE;
  HANDLE sidecar_handle = INVALID_HANDLE_VALUE;
  WylFactArtifactWinMutationEffect effect =
      WYL_FACT_ARTIFACT_WIN_MUTATION_UNKNOWN;
  WylFactArtifactSidecarRetireResult retire =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  WylFactDuckdbTempRetireResult temp_retire =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
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
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_borrow (main_binding,
          &main_handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_main_binding_close (main_binding,
          &main_handle), ==, WYRELOG_E_OK);
  wyl_fact_artifact_win_main_binding_free (main_binding);
  main_binding = NULL;

  g_assert_cmpint (wyl_fact_artifact_win_lease_open_sidecar (lease,
          WYL_FACT_ARTIFACT_WAL, TRUE, &sidecar), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_borrow (sidecar,
          &sidecar_handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_sidecar_binding_close (sidecar,
          &sidecar_handle), ==, WYRELOG_E_OK);
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
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_borrow
      (temp_binding, &sidecar_handle), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_close
      (temp_binding, &sidecar_handle), ==, WYRELOG_E_OK);
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

  /* Adversarial lifecycle: no arbitrary child spelling is accepted, a live
   * child prevents root retirement, and raw CloseHandle/reuse revokes before
   * deletion without ever closing the foreign replacement HANDLE. */
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
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_binding_borrow
      (temp_binding, &sidecar_handle), ==, WYRELOG_E_OK);
  HANDLE stale_temp_handle = sidecar_handle;
  g_assert_true (CloseHandle (sidecar_handle));
  g_autofree gchar *foreign_path = NULL;
  HANDLE foreign = open_scratch_file (&foreign_path);
  g_assert_true (foreign == stale_temp_handle);
  g_assert_cmpint (wyl_fact_artifact_win_temp_child_retire (temp_child,
          &temp_retire), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (temp_retire, ==,
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED);
  BY_HANDLE_FILE_INFORMATION foreign_info = { 0 };
  g_assert_true (GetFileInformationByHandle (foreign, &foreign_info));
  wyl_fact_artifact_win_temp_child_binding_free (temp_binding);
  temp_binding = NULL;
  g_assert_true (GetFileInformationByHandle (foreign, &foreign_info));
  g_assert_true (CloseHandle (foreign));
  remove_scratch_file (foreign_path);
  foreign_path = NULL;
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
  /* Terminal revoke deliberately leaves the original artifact untouched;
   * only the test's external cleanup (not provider authority) removes it. */
  g_assert_true (DeleteFileW (raw_child_wide));
  g_assert_true (RemoveDirectoryW (raw_root_wide));
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
  g_test_init (&argc, &argv, NULL);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/adopt-close",
      test_working_handle_adopt_noninherit_close_once);
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
      ("/fact/artifact-namespace/windows/working-handle/identity-output",
      test_working_handle_identity_mismatch_initializes_output);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/free-reused-handle",
      test_working_handle_free_never_closes_reused_handle);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/raw-close-policy",
      test_working_handle_raw_close_revokes_as_policy);
  g_test_add_func
      ("/fact/artifact-namespace/windows/working-handle/close-mismatch",
      test_working_handle_close_mismatch_revokes_without_foreign_close);
  g_test_add_func
      ("/fact/artifact-namespace/windows/lock-domain/alias-contention",
      test_native_lock_domain_alias_reader_writer_contention);
  g_test_add_func
      ("/fact/artifact-namespace/windows/lock-domain/concurrent-release",
      test_native_lock_domain_concurrent_acquire_release);
  g_test_add_func ("/fact/artifact-namespace/windows/namespace/main-sidecar",
      test_native_namespace_main_sidecar_lifecycle);
  return g_test_run ();
}
#else
int
main (void)
{
  return 77;
}
#endif
