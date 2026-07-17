/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-storage-windows-private.h"

#ifdef G_OS_WIN32
#include <winternl.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);

BOOL
wyl_win_nt_create_relative (HANDLE root,
    const WylServiceCredentialOperationChildName *name,
    ACCESS_MASK access, HANDLE *out_handle)
{
  static WylNtCreateFile nt_create;
  UNICODE_STRING name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  g_autofree gunichar2 *wide = NULL;
  gsize units = 0;
  NTSTATUS status;

  if (out_handle == NULL)
    return FALSE;
  *out_handle = INVALID_HANDLE_VALUE;
  if (root == NULL || root == INVALID_HANDLE_VALUE || name == NULL
      || name->component == NULL)
    return FALSE;
  WylServiceCredentialOperationChildName canonical =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  if (wyl_service_credential_operation_child_name_validate (name->component,
          &canonical) != WYRELOG_E_OK
      || !g_str_equal (canonical.component, name->component)) {
    wyl_service_credential_operation_child_name_clear (&canonical);
    return FALSE;
  }
  wyl_service_credential_operation_child_name_clear (&canonical);
  if (nt_create == NULL) {
    HMODULE ntdll = GetModuleHandleW (L"ntdll.dll");
    if (ntdll == NULL)
      return FALSE;
    nt_create = (WylNtCreateFile) GetProcAddress (ntdll, "NtCreateFile");
  }
  if (nt_create == NULL)
    return FALSE;
  wide = g_utf8_to_utf16 (name->component, -1, NULL, &units, NULL);
  if (wide == NULL || units == 0 || units > G_MAXUSHORT / sizeof (gunichar2))
    return FALSE;
  name.Length = (USHORT) (units * sizeof (gunichar2));
  name.MaximumLength = name.Length;
  name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof (attributes);
  attributes.RootDirectory = root;
  attributes.ObjectName = &name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  status = nt_create (&handle, access | SYNCHRONIZE, &attributes, &iosb, NULL,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE
      | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE
      | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (status < 0 || handle == INVALID_HANDLE_VALUE)
    return FALSE;
  *out_handle = handle;
  return TRUE;
}
#endif
