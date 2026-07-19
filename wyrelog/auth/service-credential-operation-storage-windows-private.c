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

static wyrelog_error_t
wyl_win_nt_create_error (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC0000034UL:         /* STATUS_OBJECT_NAME_NOT_FOUND */
      return WYRELOG_E_NOT_FOUND;
    case 0xC0000043UL:         /* STATUS_SHARING_VIOLATION */
      return WYRELOG_E_BUSY;
    case 0xC0000022UL:         /* STATUS_ACCESS_DENIED */
    case 0xC0000035UL:         /* STATUS_OBJECT_NAME_COLLISION */
    case 0xC0000024UL:         /* STATUS_OBJECT_TYPE_MISMATCH */
    case 0xC00000BAUL:         /* STATUS_FILE_IS_A_DIRECTORY */
    case 0xC0000103UL:         /* STATUS_NOT_A_DIRECTORY */
    case 0xC0000279UL:         /* STATUS_IO_REPARSE_TAG_NOT_HANDLED */
    case 0xC000050BUL:         /* STATUS_REPARSE_POINT_ENCOUNTERED */
    case 0x8000002DUL:         /* STATUS_STOPPED_ON_SYMLINK */
      return WYRELOG_E_POLICY;
    default:
      return WYRELOG_E_IO;
  }
}

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

static volatile LONG wyl_win_next_directory_flush_error = ERROR_SUCCESS;

void
wyl_win_child_fail_next_directory_flush_for_test (DWORD error)
{
  InterlockedExchange (&wyl_win_next_directory_flush_error, (LONG) error);
}

static wyrelog_error_t
wyl_win_directory_flush_error (DWORD error)
{
  switch (error) {
      /* A valid writable directory handle can still be rejected when the API
       * or backing file system does not implement directory flushing. */
    case ERROR_INVALID_FUNCTION:
    case ERROR_NOT_SUPPORTED:
      return WYRELOG_E_OK;
    default:
      return WYRELOG_E_IO;
  }
}

/* Make directory-index durability failures observable.  Only errors which
 * mean that this volume does not support flushing a directory handle are
 * accepted as the platform's documented best-effort case. */
static wyrelog_error_t
wyl_win_flush_directory (HANDLE root)
{
  LONG forced = InterlockedExchange (&wyl_win_next_directory_flush_error,
      ERROR_SUCCESS);
  if (root == NULL || root == INVALID_HANDLE_VALUE)
    return WYRELOG_E_POLICY;
  if (forced != ERROR_SUCCESS)
    return wyl_win_directory_flush_error ((DWORD) forced);
  return FlushFileBuffers (root) ? WYRELOG_E_OK
      : wyl_win_directory_flush_error (GetLastError ());
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
    *out_error = wyl_win_nt_create_error (status);
    return FALSE;
  }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (handle, &info)) {
    CloseHandle (handle);
    *out_error = WYRELOG_E_IO;
    return FALSE;
  }
  if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
              | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
    CloseHandle (handle);
    *out_error = WYRELOG_E_POLICY;
    return FALSE;
  }
  if (out_identity != NULL) {
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
          GENERIC_WRITE | DELETE, WYL_WIN_CHILD_CREATE, FILE_SHARE_READ
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
  if (rc == WYRELOG_E_OK && (!GetFileInformationByHandle (handle, &info)
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
    rc = wyl_win_flush_directory (storage->root_handle);
  if (rc != WYRELOG_E_OK)
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
  g_autofree gchar *nonce = NULL;
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
  nonce = g_uuid_string_random ();
  temporary.component = digest != NULL && nonce != NULL
      ? g_strdup_printf (".replace-%s-%s", digest, nonce) : NULL;
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
  if (rc == WYRELOG_E_OK && (!GetFileInformationByHandle (handle, &info)
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
    rc = wyl_win_flush_directory (storage->root_handle);
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

wyrelog_error_t
wyl_win_child_delete (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity = { 0 };
  wyrelog_error_t error = WYRELOG_E_INVALID;
  wyrelog_error_t rc;
  BY_HANDLE_FILE_INFORMATION info;
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  if (!wyl_win_nt_create_relative (storage->root_handle, name, DELETE,
          WYL_WIN_CHILD_OPEN, FILE_SHARE_READ | FILE_SHARE_WRITE
          | FILE_SHARE_DELETE, &handle, &identity, &error))
    return error;
  if (!GetFileInformationByHandle (handle, &info)
      || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
              | FILE_ATTRIBUTE_DIRECTORY))
      || info.dwVolumeSerialNumber != identity.volume_serial
      || info.nFileIndexHigh != identity.file_index_high
      || info.nFileIndexLow != identity.file_index_low) {
    CloseHandle (handle);
    return WYRELOG_E_POLICY;
  }
  rc = wyl_win_set_delete_disposition (handle);
  if (rc == WYRELOG_E_OK) {
    /* The delete disposition is committed by the last close.  Flush the
     * directory only after that metadata change has reached the namespace. */
    CloseHandle (handle);
    handle = INVALID_HANDLE_VALUE;
    rc = wyl_win_flush_directory (storage->root_handle);
    if (!wyl_service_credential_operation_storage_anchor_matches (storage,
            anchor))
      rc = WYRELOG_E_POLICY;
  }
  if (handle != INVALID_HANDLE_VALUE)
    CloseHandle (handle);
  return rc;
}

wyrelog_error_t
wyl_win_child_lock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, HANDLE *out_handle)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylWinChildIdentity identity = { 0 };
  wyrelog_error_t error = WYRELOG_E_INVALID;
  g_autofree gchar *digest = NULL;
  WylServiceCredentialOperationChildName lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  BY_HANDLE_FILE_INFORMATION info;
  if (out_handle == NULL)
    return WYRELOG_E_INVALID;
  *out_handle = INVALID_HANDLE_VALUE;
  if (storage == NULL || anchor == NULL || name == NULL
      || name->component == NULL
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    return WYRELOG_E_POLICY;
  digest = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
      name->component, -1);
  lock.component = g_strdup_printf (".lock-%s", digest);
  if (lock.component == NULL)
    return WYRELOG_E_NOMEM;
  /* Exclusive share mode makes a concurrent lock open fail with a sharing
   * violation, which the opener maps to WYRELOG_E_BUSY.  DELETE access lets
   * the matching unlock remove the lock file through the held handle. */
  if (!wyl_win_nt_create_relative (storage->root_handle, &lock,
          GENERIC_READ | GENERIC_WRITE | DELETE, WYL_WIN_CHILD_OPEN_ALWAYS, 0,
          &handle, &identity, &error)) {
    wyl_service_credential_operation_child_name_clear (&lock);
    return error;
  }
  if (!GetFileInformationByHandle (handle, &info)
      || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      || info.dwVolumeSerialNumber != identity.volume_serial
      || info.nFileIndexHigh != identity.file_index_high
      || info.nFileIndexLow != identity.file_index_low
      || !wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor)) {
    CloseHandle (handle);
    wyl_service_credential_operation_child_name_clear (&lock);
    return WYRELOG_E_POLICY;
  }
  wyl_service_credential_operation_child_name_clear (&lock);
  *out_handle = handle;
  return WYRELOG_E_OK;
}

void
wyl_win_child_unlock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, HANDLE handle)
{
  if (handle == NULL || handle == INVALID_HANDLE_VALUE)
    return;
  /* Remove the lock file through the held handle when the root still matches,
   * targeting the exact locked object rather than a re-resolved path.  Closing
   * releases the exclusive share and commits the removal. */
  if (storage != NULL && anchor != NULL && name != NULL
      && name->component != NULL
      && wyl_service_credential_operation_storage_anchor_matches (storage,
          anchor))
    wyl_win_set_delete_disposition (handle);
  CloseHandle (handle);
}
#endif
