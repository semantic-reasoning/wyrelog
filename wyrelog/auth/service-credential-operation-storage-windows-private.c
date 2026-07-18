/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-storage-windows-private.h"

#ifdef G_OS_WIN32
#include <winternl.h>
#include <stddef.h>
#include <string.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI * WylNtSetInformationFile) (HANDLE, PIO_STATUS_BLOCK,
    PVOID, ULONG, int);

/* FILE_INFORMATION_CLASS values not reliably exposed by winternl.h. */
#define WYL_NT_FILE_RENAME_INFO_CLASS 10
#define WYL_NT_FILE_DISPOSITION_INFO_CLASS 13

typedef struct
{
  BOOLEAN ReplaceIfExists;
  HANDLE RootDirectory;
  ULONG FileNameLength;
  WCHAR FileName[1];
} WylFileRenameInfo;

typedef struct
{
  BOOLEAN DeleteFile;
} WylFileDispositionInfo;

static WylNtSetInformationFile
wyl_win_nt_set_information (void)
{
  static WylNtSetInformationFile nt_set;
  if (nt_set == NULL) {
    HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
    if (ntdll != NULL)
      nt_set = (WylNtSetInformationFile) GetProcAddress (ntdll,
          "NtSetInformationFile");
  }
  return nt_set;
}

/* Mark an already-open child handle for deletion on last close.  Operating on
 * the held kernel object keeps the removal bound to the exact validated file,
 * never a re-resolved path. */
static wyrelog_error_t
wyl_win_set_delete_disposition (HANDLE handle)
{
  WylNtSetInformationFile nt_set = wyl_win_nt_set_information ();
  IO_STATUS_BLOCK iosb = { 0 };
  WylFileDispositionInfo disposition = {.DeleteFile = TRUE };
  NTSTATUS status;
  if (nt_set == NULL)
    return WYRELOG_E_POLICY;
  status = nt_set (handle, &iosb, &disposition, sizeof disposition,
      WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status < 0)
    return status == (NTSTATUS) 0xC0000121L || status == (NTSTATUS) 0xC0000022L
        ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

/* Best-effort durability of the directory index entry.  NTFS journals its
 * metadata for crash consistency, and some volumes reject flushing a directory
 * handle, so an unsupported flush does not fail an otherwise committed op. */
static void
wyl_win_flush_directory (HANDLE root)
{
  if (root != NULL && root != INVALID_HANDLE_VALUE)
    FlushFileBuffers (root);
}

/* Atomically bind `name` to an already-written temp handle, replacing any
 * existing record.  The destination is resolved relative to the pinned root
 * directory handle, never a re-walked path, so a substituted root or ancestor
 * cannot redirect the rename. */
static wyrelog_error_t
wyl_win_rename_relative (HANDLE handle, HANDLE root,
    const WylServiceCredentialOperationChildName *name)
{
  WylNtSetInformationFile nt_set = wyl_win_nt_set_information ();
  IO_STATUS_BLOCK iosb = { 0 };
  g_autofree gunichar2 *wide = NULL;
  g_autofree WylFileRenameInfo *info = NULL;
  glong units = 0;
  gsize name_bytes;
  gsize total;
  NTSTATUS status;
  if (nt_set == NULL || root == NULL || root == INVALID_HANDLE_VALUE
      || name == NULL || name->component == NULL)
    return WYRELOG_E_POLICY;
  wide = g_utf8_to_utf16 (name->component, -1, NULL, &units, NULL);
  if (wide == NULL || units <= 0
      || (gsize) units > G_MAXUSHORT / sizeof (gunichar2))
    return WYRELOG_E_POLICY;
  name_bytes = (gsize) units * sizeof (gunichar2);
  total = offsetof (WylFileRenameInfo, FileName) + name_bytes;
  info = g_malloc0 (total);
  if (info == NULL)
    return WYRELOG_E_NOMEM;
  info->ReplaceIfExists = TRUE;
  info->RootDirectory = root;
  info->FileNameLength = (ULONG) name_bytes;
  memcpy (info->FileName, wide, name_bytes);
  status = nt_set (handle, &iosb, info, (ULONG) total,
      WYL_NT_FILE_RENAME_INFO_CLASS);
  if (status < 0)
    return status == (NTSTATUS) 0xC0000022L || status == (NTSTATUS) 0xC0000035L
        || status == (NTSTATUS) 0xC00000D4L ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

BOOL
wyl_win_nt_create_relative (HANDLE root,
    const WylServiceCredentialOperationChildName *name,
    ACCESS_MASK access, WylWinChildDisposition disposition, ULONG share_mode,
    HANDLE *out_handle, WylWinChildIdentity *out_identity,
    wyrelog_error_t *out_error)
{
  static WylNtCreateFile nt_create;
  UNICODE_STRING unicode_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  ULONG create_disposition;
  NTSTATUS status;

  if (out_handle == NULL || out_error == NULL)
    return FALSE;
  *out_handle = INVALID_HANDLE_VALUE;
  *out_error = WYRELOG_E_INVALID;
  if (out_identity != NULL)
    memset (out_identity, 0, sizeof (*out_identity));
  if (root == NULL || root == INVALID_HANDLE_VALUE || name == NULL
      || name->component == NULL)
    return FALSE;
  if (disposition != WYL_WIN_CHILD_OPEN && disposition != WYL_WIN_CHILD_CREATE
      && disposition != WYL_WIN_CHILD_OPEN_ALWAYS)
    return FALSE;
  WylServiceCredentialOperationChildName canonical =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  if (wyl_service_credential_operation_child_name_validate (name->component,
          &canonical) != WYRELOG_E_OK
      || !g_str_equal (canonical.component, name->component)) {
    wyl_service_credential_operation_child_name_clear (&canonical);
    *out_error = WYRELOG_E_POLICY;
    return FALSE;
  }
  wyl_service_credential_operation_child_name_clear (&canonical);
  if (nt_create == NULL) {
    HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
    if (ntdll == NULL)
      return FALSE;
    nt_create = (WylNtCreateFile) GetProcAddress (ntdll, "NtCreateFile");
  }
  if (nt_create == NULL) {
    *out_error = WYRELOG_E_POLICY;
    return FALSE;
  }
  wide = g_utf8_to_utf16 (name->component, -1, NULL, &units, NULL);
  if (wide == NULL || units <= 0
      || (gsize) units > G_MAXUSHORT / sizeof (gunichar2)) {
    *out_error = WYRELOG_E_POLICY;
    return FALSE;
  }
  unicode_name.Length = (USHORT) (units * sizeof (gunichar2));
  unicode_name.MaximumLength = unicode_name.Length;
  unicode_name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof (attributes);
  attributes.RootDirectory = root;
  attributes.ObjectName = &unicode_name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  if (out_identity != NULL)
    access |= FILE_READ_ATTRIBUTES;
  switch (disposition) {
    case WYL_WIN_CHILD_CREATE:
      create_disposition = FILE_CREATE;
      break;
    case WYL_WIN_CHILD_OPEN_ALWAYS:
      create_disposition = FILE_OPEN_IF;
      break;
    default:
      create_disposition = FILE_OPEN;
      break;
  }
  status = nt_create (&handle, access | SYNCHRONIZE, &attributes, &iosb, NULL,
      FILE_ATTRIBUTE_NORMAL, share_mode, create_disposition,
      FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
      | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (status < 0 || handle == INVALID_HANDLE_VALUE) {
    *out_error = status == (NTSTATUS) 0xC0000034L
        ? WYRELOG_E_NOT_FOUND : status == (NTSTATUS) 0xC0000035L
        ? WYRELOG_E_POLICY : status == (NTSTATUS) 0xC0000022L
        ? WYRELOG_E_POLICY : status == (NTSTATUS) 0xC0000043L
        ? WYRELOG_E_BUSY : WYRELOG_E_IO;
    return FALSE;
  }
  if (out_identity != NULL) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle (handle, &info)) {
      CloseHandle (handle);
      *out_error = WYRELOG_E_IO;
      return FALSE;
    }
    out_identity->volume_serial = info.dwVolumeSerialNumber;
    out_identity->file_index_high = info.nFileIndexHigh;
    out_identity->file_index_low = info.nFileIndexLow;
  }
  *out_handle = handle;
  *out_error = WYRELOG_E_OK;
  return TRUE;
}

wyrelog_error_t
wyl_win_child_read (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes **out_bytes)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity = { 0 };
  wyrelog_error_t error = WYRELOG_E_INVALID;
  guint8 *data = NULL;
  DWORD got;
  BY_HANDLE_FILE_INFORMATION info;
  if (out_bytes == NULL)
    return WYRELOG_E_INVALID;
  *out_bytes = NULL;
  if (storage == NULL || anchor == NULL || name == NULL
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  if (!wyl_win_nt_create_relative (storage->root_handle, name, GENERIC_READ,
          WYL_WIN_CHILD_OPEN, FILE_SHARE_READ | FILE_SHARE_WRITE
          | FILE_SHARE_DELETE, &handle, &identity, &error))
    return error;
  if (!GetFileInformationByHandle (handle, &info)
      || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
      || info.nFileSizeHigh != 0 || info.nFileSizeLow > 64u * 1024u) {
    CloseHandle (handle);
    return WYRELOG_E_POLICY;
  }
  data = g_malloc (info.nFileSizeLow > 0 ? info.nFileSizeLow : 1);
  if (data == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  for (DWORD offset = 0; offset < info.nFileSizeLow;) {
    if (!ReadFile (handle, data + offset, info.nFileSizeLow - offset, &got,
            NULL) || got == 0) {
      g_free (data);
      CloseHandle (handle);
      return WYRELOG_E_IO;
    }
    offset += got;
  }
  BY_HANDLE_FILE_INFORMATION after;
  if (!GetFileInformationByHandle (handle, &after)
      || after.dwVolumeSerialNumber != identity.volume_serial
      || after.nFileIndexHigh != identity.file_index_high
      || after.nFileIndexLow != identity.file_index_low
      || (after.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
              | FILE_ATTRIBUTE_DIRECTORY))
      || after.nFileSizeHigh != info.nFileSizeHigh
      || after.nFileSizeLow != info.nFileSizeLow) {
    g_free (data);
    CloseHandle (handle);
    return WYRELOG_E_POLICY;
  }
  CloseHandle (handle);
  if (!wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)) {
    g_free (data);
    return WYRELOG_E_POLICY;
  }
  *out_bytes = g_bytes_new_take (data, info.nFileSizeLow);
  return *out_bytes == NULL ? WYRELOG_E_NOMEM : WYRELOG_E_OK;
}

wyrelog_error_t
wyl_win_child_create (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity = { 0 };
  wyrelog_error_t error = WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  gsize size = 0;
  const guint8 *data;
  BY_HANDLE_FILE_INFORMATION info;
  if (storage == NULL || anchor == NULL || name == NULL || bytes == NULL
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  data = g_bytes_get_data (bytes, &size);
  if (size > WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES)
    return WYRELOG_E_POLICY;
  if (!wyl_win_nt_create_relative (storage->root_handle, name,
          GENERIC_WRITE, WYL_WIN_CHILD_CREATE, FILE_SHARE_READ
          | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &handle, &identity, &error))
    return error;
  for (gsize offset = 0; rc == WYRELOG_E_OK && offset < size;) {
    DWORD written = 0;
    if (!WriteFile (handle, data + offset, (DWORD) (size - offset), &written,
            NULL) || written == 0)
      rc = WYRELOG_E_IO;
    else
      offset += written;
  }
  if (rc == WYRELOG_E_OK && !FlushFileBuffers (handle))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && (!GetFileInformationByHandle (handle, &info)
          || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
                  | FILE_ATTRIBUTE_DIRECTORY))
          || info.nFileSizeHigh != 0 || info.nFileSizeLow != size
          || info.dwVolumeSerialNumber != identity.volume_serial
          || info.nFileIndexHigh != identity.file_index_high
          || info.nFileIndexLow != identity.file_index_low
          || !wyl_service_credential_operation_storage_anchor_matches (storage,
              anchor)))
    rc = WYRELOG_E_POLICY;
  /* On any failure remove the file we exclusively created before closing.
   * The disposition acts on the held kernel object, so it targets exactly the
   * child we opened and never a substituted path. */
  if (rc == WYRELOG_E_OK)
    wyl_win_flush_directory (storage->root_handle);
  else
    wyl_win_set_delete_disposition (handle);
  CloseHandle (handle);
  return rc;
}

wyrelog_error_t
wyl_win_child_replace (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity = { 0 };
  wyrelog_error_t error = WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
  gsize size = 0;
  const guint8 *data;
  g_autofree gchar *digest = NULL;
  gboolean renamed = FALSE;
  WylServiceCredentialOperationChildName temporary =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  BY_HANDLE_FILE_INFORMATION info;
  if (storage == NULL || anchor == NULL || name == NULL || bytes == NULL
      || name->component == NULL
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  data = g_bytes_get_data (bytes, &size);
  if (size > WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_MAX_BYTES)
    return WYRELOG_E_POLICY;
  digest = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
      name->component, -1);
  temporary.component = g_strdup_printf (".replace-%s", digest);
  if (temporary.component == NULL)
    return WYRELOG_E_NOMEM;
  if (!wyl_win_nt_create_relative (storage->root_handle, &temporary,
          GENERIC_WRITE | DELETE, WYL_WIN_CHILD_CREATE, FILE_SHARE_READ
          | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &handle, &identity, &error)) {
    wyl_service_credential_operation_child_name_clear (&temporary);
    return error;
  }
  for (gsize offset = 0; rc == WYRELOG_E_OK && offset < size;) {
    DWORD written = 0;
    if (!WriteFile (handle, data + offset, (DWORD) (size - offset), &written,
            NULL) || written == 0)
      rc = WYRELOG_E_IO;
    else
      offset += written;
  }
  if (rc == WYRELOG_E_OK && !FlushFileBuffers (handle))
    rc = WYRELOG_E_IO;
  /* Verify the temp is the object we created and the root is unchanged before
   * the atomic rename linearization point. */
  if (rc == WYRELOG_E_OK
      && (!GetFileInformationByHandle (handle, &info)
          || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
                  | FILE_ATTRIBUTE_DIRECTORY))
          || info.nFileSizeHigh != 0 || info.nFileSizeLow != size
          || info.dwVolumeSerialNumber != identity.volume_serial
          || info.nFileIndexHigh != identity.file_index_high
          || info.nFileIndexLow != identity.file_index_low
          || !wyl_service_credential_operation_storage_anchor_matches (storage,
              anchor)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    rc = wyl_win_rename_relative (handle, storage->root_handle, name);
    if (rc == WYRELOG_E_OK)
      renamed = TRUE;
  }
  if (renamed) {
    wyl_win_flush_directory (storage->root_handle);
    if (!wyl_service_credential_operation_storage_anchor_matches (storage,
            anchor))
      rc = WYRELOG_E_POLICY;
  } else {
    /* The rename never took effect; the temp still exists under its own name,
     * so remove it through the held handle rather than by path. */
    wyl_win_set_delete_disposition (handle);
  }
  CloseHandle (handle);
  wyl_service_credential_operation_child_name_clear (&temporary);
  return rc;
}
#endif
