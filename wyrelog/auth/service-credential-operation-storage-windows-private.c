/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-storage-windows-private.h"

#ifdef G_OS_WIN32
#include <winternl.h>
#include <string.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);

BOOL
wyl_win_nt_create_relative (HANDLE root,
    const WylServiceCredentialOperationChildName *name,
    ACCESS_MASK access, WylWinChildDisposition disposition,
    HANDLE *out_handle, WylWinChildIdentity *out_identity,
    wyrelog_error_t *out_error)
{
  static WylNtCreateFile nt_create;
  UNICODE_STRING unicode_name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  g_autofree gunichar2 *wide = NULL;
  gsize units = 0;
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
  if (disposition != WYL_WIN_CHILD_OPEN && disposition != WYL_WIN_CHILD_CREATE)
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
  if (wide == NULL || units == 0 || units > G_MAXUSHORT / sizeof (gunichar2)) {
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
  status = nt_create (&handle, access | SYNCHRONIZE, &attributes, &iosb, NULL,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE
      | FILE_SHARE_DELETE, disposition == WYL_WIN_CHILD_CREATE
      ? FILE_CREATE : FILE_OPEN, FILE_NON_DIRECTORY_FILE
      | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (status < 0 || handle == INVALID_HANDLE_VALUE) {
    *out_error = status == (NTSTATUS) 0xC0000034L
        ? WYRELOG_E_NOT_FOUND : status == (NTSTATUS) 0xC0000035L
        ? WYRELOG_E_POLICY : status == (NTSTATUS) 0xC0000022L
        ? WYRELOG_E_POLICY : WYRELOG_E_IO;
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
#endif
