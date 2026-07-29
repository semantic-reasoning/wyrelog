/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-windows-locator-private.h"
#include "fact/graph-windows-security-private.h"

#ifdef G_OS_WIN32
#include <winternl.h>
#include <stddef.h>
#include <string.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI * WylNtSetInformationFile) (HANDLE,
    PIO_STATUS_BLOCK, PVOID, ULONG, int);

#define WYL_NT_FILE_RENAME_INFO_CLASS 10
#define WYL_NT_FILE_DISPOSITION_INFO_CLASS 13
#define WYL_FILE_ID_EXTD_DIRECTORY_INFO 19
#define WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO 20

typedef struct
{
  BOOLEAN delete_file;
} WylFileDispositionInfo;
typedef struct
{
  BOOLEAN replace_if_exists;
  HANDLE root_directory;
  ULONG file_name_length;
  WCHAR file_name[1];
} WylFileRenameInfo;
typedef struct
{
  DWORD next_entry_offset;
  DWORD file_index;
  LARGE_INTEGER creation_time;
  LARGE_INTEGER last_access_time;
  LARGE_INTEGER last_write_time;
  LARGE_INTEGER change_time;
  LARGE_INTEGER end_of_file;
  LARGE_INTEGER allocation_size;
  DWORD file_attributes;
  DWORD file_name_length;
  DWORD ea_size;
  DWORD reparse_point_tag;
  FILE_ID_128 file_id;
  WCHAR file_name[1];
} WylFileIdExtdDirInfo;

struct WylFactArtifactWinLocator
{
  HANDLE directory;
  WylFactGraphWinIdentity identity;
  /* This is captured once, when the graph authority is imported.  Never
   * re-query the effective token at a later I/O boundary: impersonation or a
   * token change must not silently widen the authority of existing entries. */
  PSID owner;
};
struct WylFactArtifactWinEntry
{
  HANDLE handle;
  WylFactGraphWinIdentity identity;
  gchar *name;
};
struct WylFactArtifactWinDirectory
{
  HANDLE handle;
  WylFactGraphWinIdentity identity;
  gchar *name;
};

static WylNtCreateFile
nt_create_file (void)
{
  HMODULE module = GetModuleHandleW (L"ntdll.dll");
  return module == NULL ? NULL : (WylNtCreateFile) GetProcAddress (module,
      "NtCreateFile");
}

static WylNtSetInformationFile
nt_set_information_file (void)
{
  HMODULE module = GetModuleHandleW (L"ntdll.dll");
  return module == NULL ? NULL : (WylNtSetInformationFile) GetProcAddress
      (module, "NtSetInformationFile");
}

static gboolean
valid_handle (HANDLE handle)
{
  return handle != NULL && handle != INVALID_HANDLE_VALUE;
}

static gboolean
identity_equal (const WylFactGraphWinIdentity *a,
    const WylFactGraphWinIdentity *b)
{
  return a->volume_serial == b->volume_serial
      && memcmp (a->file_id, b->file_id, sizeof a->file_id) == 0;
}

static wyrelog_error_t
nt_error (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC0000034UL:
    case 0xC000003AUL:
      return WYRELOG_E_NOT_FOUND;
    case 0xC0000035UL:
    case 0xC0000043UL:
      return WYRELOG_E_BUSY;
    case 0xC0000022UL:
    case 0xC0000024UL:
    case 0xC00000BAUL:
    case 0xC0000103UL:
    case 0xC0000276UL:
    case 0xC0000277UL:
    case 0xC0000278UL:
    case 0xC0000279UL:
    case 0xC0000280UL:
    case 0xC0000281UL:
    case 0xC0000106UL:
    case 0xC0000368UL:
    case 0xC000050BUL:
    case 0x8000002DUL:
      return WYRELOG_E_POLICY;
    default:
      return WYRELOG_E_IO;
  }
}

/* NtSetInformationFile is an optional native primitive, not a best-effort
 * pathname fallback.  Unsupported information classes or filesystems must
 * fail closed: callers cannot infer whether a mutation linearized. */
static wyrelog_error_t
nt_mutation_error (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC00000BBUL:         /* STATUS_NOT_SUPPORTED */
    case 0xC00000C0UL:         /* STATUS_INVALID_PARAMETER */
    case 0xC0000003UL:         /* STATUS_INVALID_INFO_CLASS */
    case 0xC000000DUL:         /* STATUS_INVALID_PARAMETER */
    case 0xC0000010UL:         /* STATUS_INVALID_DEVICE_REQUEST */
      return WYRELOG_E_POLICY;
    default:
      return nt_error (status);
  }
}

static wyrelog_error_t
file_identity (HANDLE handle, gboolean directory,
    WylFactGraphWinIdentity *out_identity)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  if (!valid_handle (handle) || out_identity == NULL)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic) || !GetFileInformationByHandleEx (handle,
          FileStandardInfo, &standard, sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id))
    return WYRELOG_E_IO;
  if (((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || standard.DeletePending || (!directory && standard.NumberOfLinks != 1))
    return WYRELOG_E_POLICY;
  out_identity->volume_serial = id.VolumeSerialNumber;
  memcpy (out_identity->file_id, id.FileId.Identifier,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

/* Deletion is a terminal lifecycle transition.  The normal identity audit
 * rejects DeletePending so no live authority can be issued from it, but its
 * own retained HANDLE still has to be closed exactly once.  This narrower
 * destructor-only check permits DeletePending while proving the same native
 * object and rejecting a raw-close/reused foreign HANDLE. */
static gboolean
terminal_handle_matches_identity (HANDLE handle, gboolean directory,
    const WylFactGraphWinIdentity *expected)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO id = { 0 };
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  if (!valid_handle (handle) || expected == NULL
      || !GetHandleInformation (handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0
      || !GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic)
      || !GetFileInformationByHandleEx (handle, FileStandardInfo, &standard,
          sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &id, sizeof id)
      || ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || standard.Directory != directory)
    return FALSE;
  observed.volume_serial = id.VolumeSerialNumber;
  memcpy (observed.file_id, id.FileId.Identifier, sizeof observed.file_id);
  return identity_equal (&observed, expected);
}

static wyrelog_error_t
close_directory_if_exact (WylFactArtifactWinDirectory *directory)
{
  if (directory != NULL && valid_handle (directory->handle)
      && terminal_handle_matches_identity (directory->handle, TRUE,
          &directory->identity))
    CloseHandle (directory->handle);
  return WYRELOG_E_OK;
}

static gboolean
safe_component (const gchar *name)
{
  return name != NULL && name[0] != '\0' && g_utf8_validate (name, -1, NULL)
      && strcmp (name, ".") != 0 && strcmp (name, "..") != 0
      && strpbrk (name, "/\\:") == NULL;
}

static wyrelog_error_t
wide_component (const gchar *name, gunichar2 **out_wide, glong *out_units)
{
  if (out_wide != NULL)
    *out_wide = NULL;
  if (out_units != NULL)
    *out_units = 0;
  if (out_wide == NULL || out_units == NULL || !safe_component (name))
    return WYRELOG_E_INVALID;
  *out_wide = g_utf8_to_utf16 (name, -1, NULL, out_units, NULL);
  if (*out_wide == NULL)
    return WYRELOG_E_NOMEM;
  if (*out_units <= 0 || (gsize) * out_units > G_MAXUSHORT / sizeof (WCHAR)) {
    g_clear_pointer (out_wide, g_free);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_named_entry (HANDLE directory, const gchar *name,
    const WylFactGraphWinIdentity *identity)
{
  g_autofree gunichar2 *wanted = NULL;
  glong wanted_units = 0;
  BYTE buffer[64 * 1024];
  gboolean restart = TRUE;
  guint matches = 0;
  wyrelog_error_t rc = wide_component (name, &wanted, &wanted_units);
  if (rc != WYRELOG_E_OK)
    return rc;
  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS klass = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (directory, klass, buffer, sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      return error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *current = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      gsize units = current->file_name_length / sizeof (WCHAR);
      if (units == (gsize) wanted_units
          && CompareStringOrdinal (current->file_name, (int) units, wanted,
              (int) wanted_units, FALSE) == CSTR_EQUAL) {
        if (memcmp (&current->file_id, identity->file_id,
                sizeof current->file_id) != 0)
          return WYRELOG_E_POLICY;
        matches++;
      }
      if (current->next_entry_offset == 0)
        break;
      current = (WylFileIdExtdDirInfo *) ((BYTE *) current
          + current->next_entry_offset);
    }
  }
  return matches == 1 ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_new (const WylFactGraphDirectory *directory,
    WylFactArtifactWinLocator **out_locator)
{
  WylFactArtifactWinLocator *locator;
  WylFactGraphWinIdentity observed = { 0 };
  WylFactGraphWinTokenIdentity token = { 0 };
  HANDLE duplicate = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_locator != NULL)
    *out_locator = NULL;
  if (directory == NULL || out_locator == NULL
      || !valid_handle ((HANDLE) directory->graph_handle))
    return WYRELOG_E_INVALID;
  rc = wyl_fact_graph_win_token_identity_init (&token);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), (HANDLE) directory->graph_handle,
          GetCurrentProcess (), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
    rc = WYRELOG_E_IO;
    goto out_token;
  }
  if (!SetHandleInformation (duplicate, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (duplicate);
    rc = WYRELOG_E_IO;
    goto out_token;
  }
  rc = file_identity (duplicate, TRUE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed,
          &directory->graph_identity)) {
    CloseHandle (duplicate);
    rc = rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
    goto out_token;
  }
  locator = g_try_new0 (WylFactArtifactWinLocator, 1);
  if (locator == NULL) {
    CloseHandle (duplicate);
    rc = WYRELOG_E_NOMEM;
    goto out_token;
  }
  locator->directory = duplicate;
  locator->identity = observed;
  locator->owner = token.user;
  token.user = NULL;
  *out_locator = locator;
  wyl_fact_graph_win_token_identity_clear (&token);
  return WYRELOG_E_OK;

out_token:
  wyl_fact_graph_win_token_identity_clear (&token);
  return rc;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_revalidate (WylFactArtifactWinLocator *locator)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  if (locator == NULL || !valid_handle (locator->directory))
    return WYRELOG_E_INVALID;
  if (!GetHandleInformation (locator->directory, &flags))
    return WYRELOG_E_POLICY;
  if ((flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = file_identity (locator->directory, TRUE, &observed);
  return rc == WYRELOG_E_OK && !identity_equal (&observed, &locator->identity)
      ? WYRELOG_E_POLICY : rc;
}

const WylFactGraphWinIdentity *
wyl_fact_artifact_win_locator_identity (const WylFactArtifactWinLocator
    *locator)
{
  return locator != NULL ? &locator->identity : NULL;
}

void
wyl_fact_artifact_win_locator_free (WylFactArtifactWinLocator *locator)
{
  if (locator == NULL)
    return;
  /* A raw CloseHandle plus numeric reuse must not close a foreign directory
   * object during ordinary destructor cleanup. */
  if (valid_handle (locator->directory)
      && wyl_fact_artifact_win_locator_revalidate (locator) == WYRELOG_E_OK)
    CloseHandle (locator->directory);
  g_free (locator->owner);
  g_free (locator);
}

wyrelog_error_t
wyl_fact_artifact_win_locator_open (WylFactArtifactWinLocator *locator,
    const gchar *name, ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinEntry **out_entry)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactArtifactWinEntry *entry;
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  wyrelog_error_t rc;
  if (out_entry != NULL)
    *out_entry = NULL;
  if (out_entry == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_locator_revalidate (locator)) != WYRELOG_E_OK)
    return rc;
  if ((rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  if (create_new) {
    rc = wyl_fact_graph_win_owner_only_security_init_for_user (&security,
        locator->owner, 0);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = locator->directory;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create_new ? &security.descriptor : NULL;
  NTSTATUS status = create (&handle,
      access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &attributes,
      &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      create_new ? FILE_CREATE : FILE_OPEN,
      FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
      | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, FALSE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (locator->directory, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
        locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  entry = g_try_new0 (WylFactArtifactWinEntry, 1);
  if (entry == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  entry->name = g_strdup (name);
  if (entry->name == NULL) {
    CloseHandle (handle);
    g_free (entry);
    return WYRELOG_E_NOMEM;
  }
  entry->handle = handle;
  entry->identity = identity;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_revalidate (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (entry == NULL || !valid_handle (entry->handle))
    return WYRELOG_E_INVALID;
  if (!GetHandleInformation (entry->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT))
    return WYRELOG_E_POLICY;
  rc = file_identity (entry->handle, FALSE, &observed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!identity_equal (&observed, &entry->identity))
    return WYRELOG_E_POLICY;
  rc = validate_named_entry (locator->directory, entry->name, &entry->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
      (entry->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_flush (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_entry_revalidate (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  return FlushFileBuffers (entry->handle) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_issue_working_handle (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, HANDLE *out_handle)
{
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (locator == NULL || entry == NULL || out_handle == NULL)
    return WYRELOG_E_INVALID;
  /* Issuance is an I/O boundary, not merely a HANDLE duplication.  Retest
   * the retained directory and the current exact name before exposing an
   * owned duplicate: a source moved out and replaced at the canonical name
   * therefore fails closed. */
  wyrelog_error_t rc = wyl_fact_artifact_win_entry_revalidate (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), entry->handle,
          GetCurrentProcess (), out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return WYRELOG_E_IO;
  if (!SetHandleInformation (*out_handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (*out_handle);
    *out_handle = INVALID_HANDLE_VALUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
mutation_precondition (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry)
{
  return wyl_fact_artifact_win_entry_revalidate (locator, entry);
}

static wyrelog_error_t
entry_rename (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry, const gchar *destination,
    gboolean replace_existing, WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = mutation_precondition (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if ((rc = wide_component (destination, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  gsize bytes = (gsize) units * sizeof (WCHAR);
  gsize size = offsetof (WylFileRenameInfo, file_name) + bytes;
  WylFileRenameInfo *info = g_try_malloc0 (size);
  if (info == NULL)
    return WYRELOG_E_NOMEM;
  info->replace_if_exists = replace_existing;
  info->root_directory = locator->directory;
  info->file_name_length = (ULONG) bytes;
  memcpy (info->file_name, wide, bytes);
  IO_STATUS_BLOCK iosb = { 0 };
  NTSTATUS status = set (entry->handle, &iosb, info, (ULONG) size,
      WYL_NT_FILE_RENAME_INFO_CLASS);
  g_free (info);
  if (status < 0)
    return nt_mutation_error (status);
  g_free (entry->name);
  entry->name = g_strdup (destination);
  if (entry->name == NULL) {
    /* Rename already linearized; callers must reconcile through the applied
     * effect rather than treating allocation failure as an undoable retry. */
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
    return WYRELOG_E_NOMEM;
  }
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_entry_rename_no_replace (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, const gchar *destination,
    WylFactArtifactWinMutationEffect *out_effect)
{
  return entry_rename (locator, entry, destination, FALSE, out_effect);
}

wyrelog_error_t
wyl_fact_artifact_win_entry_rename_replace_verified (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinEntry *entry, const gchar *destination,
    WylFactArtifactWinMutationEffect *out_effect)
{
  return entry_rename (locator, entry, destination, TRUE, out_effect);
}

wyrelog_error_t
wyl_fact_artifact_win_entry_delete_exact (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinEntry *entry,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = mutation_precondition (locator, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  NTSTATUS status = set (entry->handle, &iosb, &info, sizeof info,
      WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_locator_flush_directory (WylFactArtifactWinLocator
    *locator)
{
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return rc;
  return FlushFileBuffers (locator->directory) ? WYRELOG_E_OK : WYRELOG_E_IO;
}

const WylFactGraphWinIdentity *
wyl_fact_artifact_win_entry_identity (const WylFactArtifactWinEntry *entry)
{
  return entry == NULL ? NULL : &entry->identity;
}

void
wyl_fact_artifact_win_entry_free (WylFactArtifactWinEntry *entry)
{
  if (entry == NULL)
    return;
  /* Do not close an externally-closed/reused numeric HANDLE.  The entry may
   * be stale after an ownership violation, but freeing its metadata must not
   * mutate a foreign object. */
  if (valid_handle (entry->handle)
      && terminal_handle_matches_identity (entry->handle, FALSE,
          &entry->identity))
    CloseHandle (entry->handle);
  g_free (entry->name);
  g_free (entry);
}

/* The temp root is intentionally opened through the held graph directory,
 * not through a path reconstructed from it.  The same owner-only descriptor
 * that protects fixed artifacts is stamped at creation and audited again
 * before every descendant operation. */
wyrelog_error_t
wyl_fact_artifact_win_locator_create_directory (WylFactArtifactWinLocator
    *locator, const gchar *name, WylFactArtifactWinDirectory **out_directory)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  WylFactArtifactWinDirectory *directory = NULL;
  WylFactGraphWinIdentity identity = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;

  if (out_directory != NULL)
    *out_directory = NULL;
  if (locator == NULL || out_directory == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_locator_revalidate (locator)) != WYRELOG_E_OK
      || (rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  rc = wyl_fact_graph_win_owner_only_security_init_for_user (&security,
      locator->owner, 0);
  if (rc != WYRELOG_E_OK)
    return rc;
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = locator->directory;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = &security.descriptor;
  NTSTATUS status = create (&handle,
      FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_READ_ATTRIBUTES | READ_CONTROL
      | DELETE | SYNCHRONIZE, &attributes, &iosb, NULL,
      FILE_ATTRIBUTE_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
      FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT |
      FILE_SYNCHRONOUS_IO_NONALERT,
      NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, TRUE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (locator->directory, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
        locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  directory = g_try_new0 (WylFactArtifactWinDirectory, 1);
  if (directory == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  directory->name = g_strdup (name);
  if (directory->name == NULL) {
    CloseHandle (handle);
    g_free (directory);
    return WYRELOG_E_NOMEM;
  }
  directory->handle = handle;
  directory->identity = identity;
  *out_directory = directory;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_revalidate (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinDirectory *directory)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_locator_revalidate (locator);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (directory == NULL || !valid_handle (directory->handle)
      || !GetHandleInformation (directory->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  rc = file_identity (directory->handle, TRUE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed, &directory->identity))
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = validate_named_entry (locator->directory, directory->name,
      &directory->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
      (directory->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_open_file (WylFactArtifactWinLocator *locator,
    WylFactArtifactWinDirectory *directory, const gchar *name,
    ACCESS_MASK access, gboolean create_new,
    WylFactArtifactWinEntry **out_entry)
{
  WylNtCreateFile create = nt_create_file ();
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING object_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  WylFactGraphWinOwnerOnlySecurity security = { 0 };
  WylFactArtifactWinEntry *entry = NULL;
  WylFactGraphWinIdentity identity = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_entry != NULL)
    *out_entry = NULL;
  if (out_entry == NULL || create == NULL)
    return WYRELOG_E_INVALID;
  if ((rc = wyl_fact_artifact_win_directory_revalidate (locator, directory))
      != WYRELOG_E_OK
      || (rc = wide_component (name, &wide, &units)) != WYRELOG_E_OK)
    return rc;
  if (create_new && (rc = wyl_fact_graph_win_owner_only_security_init_for_user
          (&security, locator->owner, 0)) != WYRELOG_E_OK)
    return rc;
  object_name.Length = (USHORT) (units * sizeof (WCHAR));
  object_name.MaximumLength = object_name.Length;
  object_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = directory->handle;
  attributes.ObjectName = &object_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create_new ? &security.descriptor : NULL;
  NTSTATUS status = create (&handle,
      access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, &attributes,
      &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      create_new ? FILE_CREATE : FILE_OPEN,
      FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
      | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  wyl_fact_graph_win_owner_only_security_clear (&security);
  if (status < 0 || !valid_handle (handle))
    return nt_error (status);
  if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (handle);
    return WYRELOG_E_IO;
  }
  rc = file_identity (handle, FALSE, &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_named_entry (directory->handle, name, &identity);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
        locator->owner, 0);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  entry = g_try_new0 (WylFactArtifactWinEntry, 1);
  if (entry == NULL || (entry->name = g_strdup (name)) == NULL) {
    CloseHandle (handle);
    g_free (entry);
    return WYRELOG_E_NOMEM;
  }
  entry->handle = handle;
  entry->identity = identity;
  *out_entry = entry;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_entry_revalidate (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinEntry *entry)
{
  WylFactGraphWinIdentity observed = { 0 };
  DWORD flags = 0;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_revalidate (locator,
      directory);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (entry == NULL || !valid_handle (entry->handle)
      || !GetHandleInformation (entry->handle, &flags)
      || (flags & HANDLE_FLAG_INHERIT) != 0)
    return WYRELOG_E_POLICY;
  rc = file_identity (entry->handle, FALSE, &observed);
  if (rc != WYRELOG_E_OK || !identity_equal (&observed, &entry->identity))
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  rc = validate_named_entry (directory->handle, entry->name, &entry->identity);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user
      (entry->handle, locator->owner, 0) : rc;
}

wyrelog_error_t
    wyl_fact_artifact_win_directory_entry_issue_working_handle
    (WylFactArtifactWinLocator * locator,
    WylFactArtifactWinDirectory * directory, WylFactArtifactWinEntry * entry,
    HANDLE * out_handle) {
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_entry_revalidate
      (locator, directory, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!DuplicateHandle (GetCurrentProcess (), entry->handle,
          GetCurrentProcess (), out_handle, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return WYRELOG_E_IO;
  if (!SetHandleInformation (*out_handle, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle (*out_handle);
    *out_handle = INVALID_HANDLE_VALUE;
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_entry_delete_exact (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinEntry *entry,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_entry_revalidate
      (locator, directory, entry);
  if (rc != WYRELOG_E_OK)
    return rc;
  NTSTATUS status = set (entry->handle, &iosb, &info, sizeof info,
      WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_win_directory_delete_empty (WylFactArtifactWinLocator
    *locator, WylFactArtifactWinDirectory *directory,
    WylFactArtifactWinMutationEffect *out_effect)
{
  WylNtSetInformationFile set = nt_set_information_file ();
  WylFileDispositionInfo info = { TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_NOT_APPLIED;
  if (out_effect == NULL)
    return WYRELOG_E_INVALID;
  if (set == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = wyl_fact_artifact_win_directory_revalidate (locator,
      directory);
  if (rc != WYRELOG_E_OK)
    return rc;
  NTSTATUS status = set (directory->handle, &iosb, &info, sizeof info,
      WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return nt_mutation_error (status);
  *out_effect = WYL_FACT_ARTIFACT_WIN_MUTATION_APPLIED;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_win_directory_free (WylFactArtifactWinDirectory *directory)
{
  if (directory == NULL)
    return;
  close_directory_if_exact (directory);
  g_free (directory->name);
  g_free (directory);
}
#endif
