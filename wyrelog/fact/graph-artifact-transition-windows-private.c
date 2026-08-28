/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-artifact-transition-windows-private.h"
#include "fact/graph-artifact-transition-names-private.h"
#include "fact/graph-artifact-inventory-private.h"
#include "fact/graph-windows-security-private.h"
#include "wyrelog/wyl-log-private.h"

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI * WylNtSetInformationFile) (HANDLE,
    PIO_STATUS_BLOCK, PVOID, ULONG, int);

#define WYL_NT_FILE_RENAME_INFO_CLASS          10
#define WYL_NT_FILE_DISPOSITION_INFO_CLASS     13
#define WYL_FILE_ID_EXTD_DIRECTORY_INFO        19
#define WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO 20

#define WYL_STATUS_SUCCESS                     ((NTSTATUS) 0x00000000L)
#define WYL_STATUS_NOT_IMPLEMENTED             ((NTSTATUS) 0xC0000002L)
#define WYL_STATUS_INVALID_INFO_CLASS          ((NTSTATUS) 0xC0000003L)
#define WYL_STATUS_INVALID_PARAMETER           ((NTSTATUS) 0xC000000DL)
#define WYL_STATUS_NO_SUCH_FILE                ((NTSTATUS) 0xC000000FL)
#define WYL_STATUS_INVALID_DEVICE_REQUEST      ((NTSTATUS) 0xC0000010L)
#define WYL_STATUS_ACCESS_DENIED               ((NTSTATUS) 0xC0000022L)
#define WYL_STATUS_OBJECT_NAME_NOT_FOUND       ((NTSTATUS) 0xC0000034L)
#define WYL_STATUS_OBJECT_NAME_COLLISION       ((NTSTATUS) 0xC0000035L)
#define WYL_STATUS_OBJECT_PATH_NOT_FOUND       ((NTSTATUS) 0xC000003AL)
#define WYL_STATUS_SHARING_VIOLATION           ((NTSTATUS) 0xC0000043L)
#define WYL_STATUS_DELETE_PENDING              ((NTSTATUS) 0xC0000056L)
#define WYL_STATUS_PRIVILEGE_NOT_HELD          ((NTSTATUS) 0xC0000061L)
#define WYL_STATUS_CANNOT_DELETE               ((NTSTATUS) 0xC0000121L)
#define WYL_STATUS_FILE_IS_A_DIRECTORY         ((NTSTATUS) 0xC00000BAL)
#define WYL_STATUS_NOT_A_DIRECTORY             ((NTSTATUS) 0xC0000103L)
#define WYL_STATUS_NOT_SAME_DEVICE             ((NTSTATUS) 0xC00000D4L)
#define WYL_STATUS_MEDIA_WRITE_PROTECTED       ((NTSTATUS) 0xC00000A2L)
#define WYL_STATUS_NOT_SUPPORTED               ((NTSTATUS) 0xC00000BBL)
#define WYL_STATUS_UNEXPECTED_IO_ERROR         ((NTSTATUS) 0xC00000E5L)

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

struct WylFactArtifactTransitionWindows
{
  HANDLE graph_handle;
  WylFactGraphWinIdentity directory_identity;
  WylFactRootWriterLease *lease;
  guint8 operation_uuid[16];
  WylFactArtifactTransitionNames names;
  WylFactArtifactTransitionWindowsCapability capability;
  PSID owner;
};

static volatile LONG next_windows_fault;
static volatile LONG next_rename_status;
static volatile LONG next_flush_error;
static WylFactArtifactTransitionWindowsTestPostOpenHook test_post_open_hook;
static gpointer test_post_open_user_data;

void
wyl_fact_artifact_transition_windows_set_test_fault
  (WylFactArtifactTransitionWindowsTestFault fault)
{
  InterlockedExchange (&next_windows_fault, (LONG) fault);
}

static gboolean
windows_fault_take (WylFactArtifactTransitionWindowsTestFault fault)
{
  return InterlockedCompareExchange (&next_windows_fault,
             WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_NONE,
             (LONG) fault) == (LONG) fault;
}

gboolean
wyl_fact_artifact_transition_windows_test_fault_was_consumed
  (WylFactArtifactTransitionWindowsTestFault fault)
{
  return (LONG) fault != WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_NONE
         && InterlockedCompareExchange (&next_windows_fault,
             WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_NONE,
             WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_NONE)
         != (LONG) fault;
}

void
wyl_fact_artifact_transition_windows_set_test_rename_status (gint status_value)
{
  InterlockedExchange (&next_rename_status, (LONG) status_value);
}

static NTSTATUS
take_next_rename_status (void)
{
  return (NTSTATUS) InterlockedExchange (&next_rename_status, 0);
}

void
wyl_fact_artifact_transition_windows_set_test_flush_error (guint error_value)
{
  InterlockedExchange (&next_flush_error, (LONG) error_value);
}

static DWORD
take_next_flush_error (void)
{
  return (DWORD) InterlockedExchange (&next_flush_error, ERROR_SUCCESS);
}

void
wyl_fact_artifact_transition_windows_set_test_post_open_hook
  (WylFactArtifactTransitionWindowsTestPostOpenHook hook, gpointer user_data)
{
  test_post_open_hook = hook;
  test_post_open_user_data = user_data;
}

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
safe_component (const gchar *name)
{
  if (name == NULL || *name == '\0')
    return FALSE;
  if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
    return FALSE;
  for (const gchar *p = name; *p != '\0'; p++) {
    if (*p == '/' || *p == '\\' || *p == ':')
      return FALSE;
  }
  return TRUE;
}

static WCHAR *
wide_component (const gchar *name, ULONG *out_char_count)
{
  glong wide_len = 0;
  if (!safe_component (name))
    return NULL;
  WCHAR *wide = g_utf8_to_utf16 (name, -1, NULL, &wide_len, NULL);
  if (wide == NULL || wide_len <= 0) {
    g_free (wide);
    return NULL;
  }
  if (out_char_count != NULL)
    *out_char_count = (ULONG) wide_len;
  return wide;
}

static wyrelog_error_t
query_token_user_sid (PSID *out_user)
{
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *info = NULL;
  if (out_user == NULL)
    return WYRELOG_E_INVALID;
  *out_user = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return WYRELOG_E_IO;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
    CloseHandle (token);
    return WYRELOG_E_IO;
  }
  info = g_try_malloc (needed);
  if (info == NULL) {
    CloseHandle (token);
    return WYRELOG_E_NOMEM;
  }
  if (!GetTokenInformation (token, TokenUser, info, needed, &needed)
      || info->User.Sid == NULL || !IsValidSid (info->User.Sid)) {
    g_free (info);
    CloseHandle (token);
    return WYRELOG_E_IO;
  }
  DWORD len = GetLengthSid (info->User.Sid);
  PSID copy = g_try_malloc (len);
  if (copy == NULL) {
    g_free (info);
    CloseHandle (token);
    return WYRELOG_E_NOMEM;
  }
  if (!CopySid (len, copy, info->User.Sid)) {
    g_free (copy);
    g_free (info);
    CloseHandle (token);
    return WYRELOG_E_IO;
  }
  g_free (info);
  CloseHandle (token);
  *out_user = copy;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
query_file_id_identity (HANDLE handle, WylFactGraphWinIdentity *out_identity)
{
  FILE_ID_INFO info = { 0 };
  if (out_identity == NULL || handle == NULL || handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  memset (out_identity, 0, sizeof *out_identity);
  if (!GetFileInformationByHandleEx (handle, FileIdInfo, &info, sizeof info))
    return WYRELOG_E_IO;
  out_identity->volume_serial = info.VolumeSerialNumber;
  memcpy (out_identity->file_id, info.FileId.Identifier,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
query_file_links_and_reparse (HANDLE handle, guint *out_links,
    gboolean *out_reparse)
{
  FILE_STANDARD_INFO std = { 0 };
  FILE_ATTRIBUTE_TAG_INFO tag = { 0 };
  if (out_links != NULL)
    *out_links = 0;
  if (out_reparse != NULL)
    *out_reparse = FALSE;
  if (handle == NULL || handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileStandardInfo, &std, sizeof std))
    return WYRELOG_E_IO;
  if (!GetFileInformationByHandleEx (handle, FileAttributeTagInfo, &tag,
      sizeof tag))
    return WYRELOG_E_IO;
  if (out_links != NULL)
    *out_links = (guint) std.NumberOfLinks;
  if (out_reparse != NULL)
    *out_reparse = (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  return WYRELOG_E_OK;
}

static void
classify_owner_security (HANDLE handle, PSID token_user,
    WylFactArtifactMainTransitionOwnerState *out_owner_state)
{
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PSID owner = NULL;
  PACL dacl = NULL;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;

  if (out_owner_state == NULL)
    return;
  *out_owner_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN;
  if (handle == NULL || handle == INVALID_HANDLE_VALUE || token_user == NULL)
    return;

  DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
          &dacl, NULL, &descriptor);
  if (error != ERROR_SUCCESS)
    return;

  gboolean owner_match = owner != NULL && IsValidSid (owner)
      && EqualSid (owner, token_user);
  gboolean control_ok = GetSecurityDescriptorControl (descriptor, &control,
          &revision);
  gboolean dacl_ok = GetSecurityDescriptorDacl (descriptor, &present, &dacl,
          &defaulted);
  gboolean acl_info_ok = dacl_ok && present && dacl != NULL
      && GetAclInformation (dacl, &size, sizeof size, AclSizeInformation);
  gboolean ace_ok = acl_info_ok && size.AceCount == 1
      && GetAce (dacl, 0, (LPVOID *) &ace) && ace != NULL;
  gboolean allowed_ace = ace_ok
      && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
  PSID ace_sid = allowed_ace ? (PSID) &ace->SidStart : NULL;
  gboolean ace_sid_valid = ace_sid != NULL && IsValidSid (ace_sid);
  gboolean ace_sid_match = ace_sid_valid && EqualSid (ace_sid, token_user);

  if (!owner_match || (ace_ok && allowed_ace && !ace_sid_match)) {
    *out_owner_state
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_PRINCIPAL;
  } else if (!control_ok || (control & SE_DACL_PROTECTED) == 0) {
    *out_owner_state
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNPROTECTED_ACL;
  } else if (ace_ok && (ace->Header.AceFlags & INHERITED_ACE) != 0) {
    *out_owner_state
      = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_INHERITED_ACE;
  } else if (!dacl_ok || !present || dacl == NULL || defaulted || !acl_info_ok
      || size.AceCount != 1 || !ace_ok || !allowed_ace
      || ace->Header.AceFlags != 0 || ace->Mask != FILE_ALL_ACCESS) {
    *out_owner_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_WRONG_MODE;
  } else {
    *out_owner_state = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING;
  }
  LocalFree (descriptor);
}

static wyrelog_error_t
validate_named_directory_entry (HANDLE dir_handle, const gchar *name,
    const WylFactGraphWinIdentity *expected_identity)
{
  BYTE buffer[4096];
  ULONG wide_len = 0;
  g_autofree WCHAR *wide = wide_component (name, &wide_len);
  if (wide == NULL || dir_handle == NULL || dir_handle == INVALID_HANDLE_VALUE
      || expected_identity == NULL)
    return WYRELOG_E_INVALID;

  gboolean match_found = FALSE;
  gboolean restart = TRUE;
  while (TRUE) {
    memset (buffer, 0, sizeof buffer);
    if (!GetFileInformationByHandleEx (dir_handle,
        restart ? FileIdExtdDirectoryRestartInfo : FileIdExtdDirectoryInfo,
        buffer, sizeof buffer)) {
      DWORD err = GetLastError ();
      if (err == ERROR_NO_MORE_FILES)
        break;
      return WYRELOG_E_IO;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *info = (WylFileIdExtdDirInfo *) buffer;
    while (TRUE) {
      ULONG name_chars = info->file_name_length / sizeof (WCHAR);
      if (name_chars == wide_len && wcsncmp (info->file_name, wide,
          wide_len) == 0) {
        if (memcmp (info->file_id.Identifier, expected_identity->file_id,
            sizeof expected_identity->file_id) != 0)
          return WYRELOG_E_POLICY;
        match_found = TRUE;
        break;
      }
      if (info->next_entry_offset == 0)
        break;
      info = (WylFileIdExtdDirInfo *) ((BYTE *) info + info->next_entry_offset);
    }
    if (match_found)
      break;
  }
  return match_found ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static wyrelog_error_t
open_entry_handle (HANDLE dir_handle, const gchar *name, ACCESS_MASK access_mask,
    ULONG create_disposition, HANDLE *out_handle, NTSTATUS *out_status)
{
  WylNtCreateFile create_file = nt_create_file ();
  ULONG wide_len = 0;
  g_autofree WCHAR *wide = wide_component (name, &wide_len);
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (out_status != NULL)
    *out_status = WYL_STATUS_INVALID_PARAMETER;
  if (create_file == NULL || wide == NULL || dir_handle == NULL
      || dir_handle == INVALID_HANDLE_VALUE || out_handle == NULL)
    return WYRELOG_E_INVALID;

  UNICODE_STRING unicode_name = { 0 };
  unicode_name.Buffer = wide;
  unicode_name.Length = (USHORT) (wide_len * sizeof (WCHAR));
  unicode_name.MaximumLength = unicode_name.Length;

  OBJECT_ATTRIBUTES attr = { 0 };
  attr.Length = sizeof attr;
  attr.RootDirectory = dir_handle;
  attr.ObjectName = &unicode_name;
  attr.Attributes = OBJ_CASE_INSENSITIVE;

  IO_STATUS_BLOCK io_status = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = create_file (&handle, access_mask, &attr, &io_status,
          NULL, FILE_ATTRIBUTE_NORMAL,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          create_disposition,
          FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE
          | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (out_status != NULL)
    *out_status = status;
  if (!NT_SUCCESS (status))
    return WYRELOG_E_IO;
  SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0);
  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
delete_entry_by_name (HANDLE dir_handle, const gchar *name)
{
  WylNtSetInformationFile set_info = nt_set_information_file ();
  HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = WYL_STATUS_SUCCESS;
  if (set_info == NULL || dir_handle == NULL
      || dir_handle == INVALID_HANDLE_VALUE || name == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = open_entry_handle (dir_handle, name,
          DELETE | SYNCHRONIZE, FILE_OPEN, &handle, &status);
  if (rc != WYRELOG_E_OK) {
    if (status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
        || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
        || status == WYL_STATUS_NO_SUCH_FILE)
      return WYRELOG_E_OK;
    return rc;
  }

  WylFileDispositionInfo disp = { .delete_file = TRUE };
  IO_STATUS_BLOCK io_status = { 0 };
  status = set_info (handle, &io_status, &disp, sizeof disp,
          WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  CloseHandle (handle);
  if (!NT_SUCCESS (status) && status != WYL_STATUS_OBJECT_NAME_NOT_FOUND
      && status != WYL_STATUS_OBJECT_PATH_NOT_FOUND
      && status != WYL_STATUS_NO_SUCH_FILE)
    return WYRELOG_E_IO;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_transition_windows_probe_capability
  (const WylFactGraphDirectory *directory, const gchar *operation_uuid,
    WylFactArtifactTransitionWindowsCapability *out_capability)
{
  WylNtSetInformationFile set_info = nt_set_information_file ();
  WylFactArtifactTransitionNames names = { 0 };
  HANDLE probe_handle = INVALID_HANDLE_VALUE;
  NTSTATUS rename_status = WYL_STATUS_SUCCESS;

  if (out_capability != NULL)
    *out_capability = (WylFactArtifactTransitionWindowsCapability) { 0 };
  if (directory == NULL || directory->graph_handle == NULL
      || directory->graph_handle == INVALID_HANDLE_VALUE
      || operation_uuid == NULL || out_capability == NULL
      || set_info == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = wyl_fact_artifact_transition_names_derive
        (operation_uuid, &names);
  if (rc != WYRELOG_E_OK)
    return rc;

  /* Step 0: Preclean crash recovery */
  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_PRECLEAN)) {
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_IO;
  }
  if (delete_entry_by_name (directory->graph_handle, names.probe)
      != WYRELOG_E_OK
      || delete_entry_by_name (directory->graph_handle, names.probe_moved)
      != WYRELOG_E_OK) {
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_IO;
  }

  /* Step 1: Create probe source */
  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_CREATE)) {
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_IO;
  }
  rc = open_entry_handle (directory->graph_handle, names.probe,
          DELETE | SYNCHRONIZE, FILE_CREATE, &probe_handle, NULL);
  if (rc != WYRELOG_E_OK) {
    delete_entry_by_name (directory->graph_handle, names.probe);
    delete_entry_by_name (directory->graph_handle, names.probe_moved);
    wyl_fact_artifact_transition_names_clear (&names);
    return rc;
  }

  /* Step 2: No-replace rename probe */
  ULONG wide_len = 0;
  g_autofree WCHAR *wide_dest = wide_component (names.probe_moved, &wide_len);
  if (wide_dest == NULL) {
    CloseHandle (probe_handle);
    delete_entry_by_name (directory->graph_handle, names.probe);
    delete_entry_by_name (directory->graph_handle, names.probe_moved);
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_NOMEM;
  }

  ULONG rename_info_len = sizeof (WylFileRenameInfo)
      + (wide_len * sizeof (WCHAR));
  g_autofree WylFileRenameInfo *rename_info = g_try_malloc0 (rename_info_len);
  if (rename_info == NULL) {
    CloseHandle (probe_handle);
    delete_entry_by_name (directory->graph_handle, names.probe);
    delete_entry_by_name (directory->graph_handle, names.probe_moved);
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_NOMEM;
  }
  rename_info->replace_if_exists = FALSE;
  rename_info->root_directory = directory->graph_handle;
  rename_info->file_name_length = wide_len * sizeof (WCHAR);
  memcpy (rename_info->file_name, wide_dest, rename_info->file_name_length);

  IO_STATUS_BLOCK io_status = { 0 };
  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_RENAME)) {
    rename_status = take_next_rename_status ();
    if (rename_status == 0)
      rename_status = WYL_STATUS_NOT_SUPPORTED;
  } else {
    rename_status = set_info (probe_handle, &io_status, rename_info,
            rename_info_len, WYL_NT_FILE_RENAME_INFO_CLASS);
  }
  CloseHandle (probe_handle);

  gboolean no_replace_supported = FALSE;
  if (NT_SUCCESS (rename_status)) {
    no_replace_supported = TRUE;
  } else if (rename_status == WYL_STATUS_NOT_SUPPORTED
      || rename_status == WYL_STATUS_NOT_IMPLEMENTED
      || rename_status == WYL_STATUS_INVALID_INFO_CLASS
      || rename_status == WYL_STATUS_INVALID_DEVICE_REQUEST
      || rename_status == WYL_STATUS_INVALID_PARAMETER) {
    no_replace_supported = FALSE;
  } else {
    delete_entry_by_name (directory->graph_handle, names.probe);
    delete_entry_by_name (directory->graph_handle, names.probe_moved);
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_IO;
  }

  /* Step 3: Directory flush probe */
  WylFactArtifactMainTransitionDurability dir_flush
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_DIRECTORY_FSYNC)) {
    DWORD flush_err = take_next_flush_error ();
    if (flush_err == ERROR_SUCCESS)
      flush_err = ERROR_NOT_SUPPORTED;
    if (flush_err == ERROR_NOT_SUPPORTED || flush_err == ERROR_INVALID_FUNCTION
        || flush_err == ERROR_INVALID_HANDLE)
      dir_flush = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED;
    else
      rc = WYRELOG_E_IO;
  } else {
    if (FlushFileBuffers (directory->graph_handle)) {
      dir_flush = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN;
    } else {
      DWORD err = GetLastError ();
      if (err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_FUNCTION
          || err == ERROR_INVALID_HANDLE)
        dir_flush = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED;
      else
        rc = WYRELOG_E_IO;
    }
  }

  /* Step 4: Mandatory cleanup */
  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_PROBE_RETIRE))
    rc = WYRELOG_E_IO;
  if (delete_entry_by_name (directory->graph_handle, names.probe)
      != WYRELOG_E_OK
      || delete_entry_by_name (directory->graph_handle, names.probe_moved)
      != WYRELOG_E_OK) {
    rc = WYRELOG_E_IO;
  }
  wyl_fact_artifact_transition_names_clear (&names);

  if (rc != WYRELOG_E_OK)
    return rc;
  out_capability->no_replace_supported = no_replace_supported;
  out_capability->directory_flush = dir_flush;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_transition_windows_open
  (const WylFactGraphDirectory *directory, WylFactRootWriterLease *lease,
    const gchar *operation_uuid,
    const WylFactArtifactTransitionWindowsCapability *capability,
    WylFactArtifactTransitionWindows **out_provider)
{
  if (out_provider != NULL)
    *out_provider = NULL;
  if (directory == NULL || directory->graph_handle == NULL
      || directory->graph_handle == INVALID_HANDLE_VALUE || lease == NULL
      || operation_uuid == NULL || capability == NULL || out_provider == NULL)
    return WYRELOG_E_INVALID;

  WylFactGraphWinIdentity dir_identity = { 0 };
  wyrelog_error_t rc = query_file_id_identity (directory->graph_handle,
          &dir_identity);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_id_t op_id;
  rc = wyl_id_parse (operation_uuid, &op_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactTransitionNames names = { 0 };
  rc = wyl_fact_artifact_transition_names_derive (operation_uuid, &names);
  if (rc != WYRELOG_E_OK)
    return rc;

  PSID token_user = NULL;
  rc = query_token_user_sid (&token_user);
  if (rc != WYRELOG_E_OK) {
    wyl_fact_artifact_transition_names_clear (&names);
    return rc;
  }

  WylFactArtifactTransitionWindows *p
    = g_try_new0 (WylFactArtifactTransitionWindows, 1);
  if (p == NULL) {
    g_free (token_user);
    wyl_fact_artifact_transition_names_clear (&names);
    return WYRELOG_E_NOMEM;
  }
  p->graph_handle = directory->graph_handle;
  p->directory_identity = dir_identity;
  p->lease = lease;
  memcpy (p->operation_uuid, op_id.bytes, sizeof p->operation_uuid);
  p->names = names;
  p->capability = *capability;
  p->owner = token_user;

  *out_provider = p;
  return WYRELOG_E_OK;
}

void
wyl_fact_artifact_transition_windows_free
  (WylFactArtifactTransitionWindows *provider)
{
  if (provider == NULL)
    return;
  g_clear_pointer (&provider->owner, g_free);
  wyl_fact_artifact_transition_names_clear (&provider->names);
  g_free (provider);
}

static wyrelog_error_t
observe_slot (WylFactArtifactTransitionWindows *provider, const gchar *name,
    WylFactArtifactMainTransitionEntryEvidence *out_evidence)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = WYL_STATUS_SUCCESS;
  if (out_evidence != NULL)
    *out_evidence = (WylFactArtifactMainTransitionEntryEvidence) { 0 };
  if (provider == NULL || name == NULL || out_evidence == NULL)
    return WYRELOG_E_INVALID;

  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_SLOT_OPEN))
    return WYRELOG_E_IO;

  wyrelog_error_t rc = open_entry_handle (provider->graph_handle, name,
          READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          FILE_OPEN, &handle, &status);
  if (rc != WYRELOG_E_OK) {
    if (status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
        || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
        || status == WYL_STATUS_NO_SUCH_FILE) {
      out_evidence->present = FALSE;
      return WYRELOG_E_OK;
    }
    return rc;
  }

  WylFactGraphWinIdentity identity = { 0 };
  guint link_count = 0;
  gboolean reparse = FALSE;
  WylFactArtifactMainTransitionOwnerState owner_state
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN;

  rc = query_file_id_identity (handle, &identity);
  if (rc == WYRELOG_E_OK)
    rc = query_file_links_and_reparse (handle, &link_count, &reparse);
  if (rc == WYRELOG_E_OK)
    classify_owner_security (handle, provider->owner, &owner_state);

  if (rc == WYRELOG_E_OK && !reparse) {
    rc = validate_named_directory_entry (provider->graph_handle, name,
            &identity);
  }
  CloseHandle (handle);
  if (rc != WYRELOG_E_OK)
    return rc;

  out_evidence->present = TRUE;
  out_evidence->link_count = link_count;
  out_evidence->reparse = reparse;
  out_evidence->owner_state = owner_state;
  if (reparse) {
    memset (&out_evidence->identity, 0, sizeof out_evidence->identity);
  } else {
    out_evidence->identity.domain = identity.volume_serial;
    out_evidence->identity.object = 0;
    out_evidence->identity.object_width = 16;
    memcpy (out_evidence->identity.object_bytes, identity.file_id,
        sizeof identity.file_id);
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_transition_windows_observe
  (WylFactArtifactTransitionWindows *provider,
    const WylFactArtifactTransitionWindowsLifecycle *lifecycle,
    WylFactArtifactMainTransitionObservation *out_observation)
{
  if (out_observation != NULL)
    *out_observation = (WylFactArtifactMainTransitionObservation) { 0 };
  if (provider == NULL || lifecycle == NULL || out_observation == NULL
      || provider->graph_handle == NULL
      || provider->graph_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;

  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_DIRECTORY_FSTAT))
    return WYRELOG_E_IO;

  WylFactGraphWinIdentity dir_identity = { 0 };
  wyrelog_error_t rc = query_file_id_identity (provider->graph_handle,
          &dir_identity);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_LEASE_FSTAT))
    return WYRELOG_E_POLICY;

  rc = wyl_fact_root_writer_lease_verify (provider->lease);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactArtifactMainTransitionEntryEvidence main_ev = { 0 };
  WylFactArtifactMainTransitionEntryEvidence stage_ev = { 0 };
  WylFactArtifactMainTransitionEntryEvidence rollback_ev = { 0 };

  rc = observe_slot (provider, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME,
          &main_ev);
  if (rc == WYRELOG_E_OK)
    rc = observe_slot (provider, provider->names.stage, &stage_ev);
  if (rc == WYRELOG_E_OK)
    rc = observe_slot (provider, provider->names.rollback, &rollback_ev);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_OBSERVE_SLOT_SUBSTITUTE))
    stage_ev.identity.object_bytes[15] ^= 1;

  out_observation->directory_identity.domain = dir_identity.volume_serial;
  out_observation->directory_identity.object = 0;
  out_observation->directory_identity.object_width = 16;
  memcpy (out_observation->directory_identity.object_bytes,
      dir_identity.file_id, sizeof dir_identity.file_id);

  /* Lease lock identity */
  HANDLE lock_handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = WYL_STATUS_SUCCESS;
  rc = open_entry_handle (provider->graph_handle,
          WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME,
          READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          FILE_OPEN, &lock_handle, &status);
  if (rc == WYRELOG_E_OK) {
    WylFactGraphWinIdentity lock_id = { 0 };
    if (query_file_id_identity (lock_handle, &lock_id) == WYRELOG_E_OK) {
      out_observation->lease_identity.domain = lock_id.volume_serial;
      out_observation->lease_identity.object = 0;
      out_observation->lease_identity.object_width = 16;
      memcpy (out_observation->lease_identity.object_bytes, lock_id.file_id,
          sizeof lock_id.file_id);
    }
    CloseHandle (lock_handle);
  }

  memcpy (out_observation->operation_uuid, provider->operation_uuid,
      sizeof out_observation->operation_uuid);
  out_observation->sealed = lifecycle->sealed;
  out_observation->main_binding_live = lifecycle->main_binding_live;
  out_observation->entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN]
    = main_ev;
  out_observation->entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE]
    = stage_ev;
  out_observation->entries[WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK]
    = rollback_ev;
  out_observation->no_replace_supported = provider->capability.no_replace_supported;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_verify_authorization (const WylFactArtifactTransitionWindows *provider,
    const WylFactArtifactMainTransitionObservation *authorized)
{
  if (provider == NULL || authorized == NULL)
    return WYRELOG_E_INVALID;
  if (memcmp (provider->operation_uuid, authorized->operation_uuid,
      sizeof provider->operation_uuid) != 0)
    return WYRELOG_E_INVALID;

  WylFactGraphWinIdentity dir_identity = { 0 };
  wyrelog_error_t rc = query_file_id_identity (provider->graph_handle,
          &dir_identity);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (authorized->directory_identity.domain != dir_identity.volume_serial
      || authorized->directory_identity.object_width != 16
      || memcmp (authorized->directory_identity.object_bytes,
      dir_identity.file_id, sizeof dir_identity.file_id) != 0)
    return WYRELOG_E_POLICY;

  HANDLE lock_handle = INVALID_HANDLE_VALUE;
  rc = open_entry_handle (provider->graph_handle,
          WYL_FACT_ARTIFACT_TRANSITION_LOCK_NAME,
          READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          FILE_OPEN, &lock_handle, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;
  WylFactGraphWinIdentity lock_id = { 0 };
  rc = query_file_id_identity (lock_handle, &lock_id);
  CloseHandle (lock_handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (authorized->lease_identity.domain != lock_id.volume_serial
      || authorized->lease_identity.object_width != 16
      || memcmp (authorized->lease_identity.object_bytes, lock_id.file_id,
      sizeof lock_id.file_id) != 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_open_expected (const WylFactArtifactTransitionWindows *provider,
    const gchar *name, ACCESS_MASK access_mask,
    const WylFactArtifactMainTransitionEntryEvidence *expected,
    HANDLE *out_handle, WylFactArtifactMainTransitionEffect *out_effect)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = WYL_STATUS_SUCCESS;
  if (out_handle != NULL)
    *out_handle = INVALID_HANDLE_VALUE;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (provider == NULL || name == NULL || expected == NULL
      || out_handle == NULL || out_effect == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = open_entry_handle (provider->graph_handle, name,
          access_mask, FILE_OPEN, &handle, &status);
  if (rc != WYRELOG_E_OK) {
    if (status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
        || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
        || status == WYL_STATUS_NO_SUCH_FILE
        || status == WYL_STATUS_ACCESS_DENIED
        || status == WYL_STATUS_PRIVILEGE_NOT_HELD)
      *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
    else
      *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }

  if (test_post_open_hook != NULL)
    test_post_open_hook (provider->graph_handle, name,
        test_post_open_user_data);

  WylFactGraphWinIdentity identity = { 0 };
  guint link_count = 0;
  gboolean reparse = FALSE;
  WylFactArtifactMainTransitionOwnerState owner_state
    = WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_UNKNOWN;

  rc = query_file_id_identity (handle, &identity);
  if (rc == WYRELOG_E_OK)
    rc = query_file_links_and_reparse (handle, &link_count, &reparse);
  if (rc == WYRELOG_E_OK)
    classify_owner_security (handle, provider->owner, &owner_state);

  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }

  gboolean identity_match = expected->identity.domain == identity.volume_serial
      && expected->identity.object_width == 16
      && memcmp (expected->identity.object_bytes, identity.file_id,
          sizeof identity.file_id) == 0;
  if (!expected->present || !identity_match || link_count != 1 || reparse
      || owner_state != WYL_FACT_ARTIFACT_MAIN_TRANSITION_OWNER_CONFORMING) {
    CloseHandle (handle);
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
    return WYRELOG_E_OK;
  }

  rc = validate_named_directory_entry (provider->graph_handle, name,
          &identity);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
    return WYRELOG_E_OK;
  }

  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_rename (const WylFactArtifactTransitionWindows *provider,
    const gchar *source_name, const gchar *target_name,
    const WylFactArtifactMainTransitionEntryEvidence *expected_source,
    WylFactArtifactTransitionWindowsTestFault fault,
    WylFactArtifactMainTransitionEffect *out_effect)
{
  WylNtSetInformationFile set_info = nt_set_information_file ();
  HANDLE handle = INVALID_HANDLE_VALUE;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (provider == NULL || source_name == NULL || target_name == NULL
      || expected_source == NULL || out_effect == NULL || set_info == NULL)
    return WYRELOG_E_INVALID;

  wyrelog_error_t rc = execute_open_expected (provider, source_name,
          READ_CONTROL | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          expected_source, &handle, out_effect);
  if (rc != WYRELOG_E_OK || handle == INVALID_HANDLE_VALUE)
    return rc;

  ULONG wide_len = 0;
  g_autofree WCHAR *wide_target = wide_component (target_name, &wide_len);
  if (wide_target == NULL) {
    CloseHandle (handle);
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }

  ULONG rename_info_len = sizeof (WylFileRenameInfo)
      + (wide_len * sizeof (WCHAR));
  g_autofree WylFileRenameInfo *rename_info = g_try_malloc0 (rename_info_len);
  if (rename_info == NULL) {
    CloseHandle (handle);
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }
  rename_info->replace_if_exists = FALSE;
  rename_info->root_directory = provider->graph_handle;
  rename_info->file_name_length = wide_len * sizeof (WCHAR);
  memcpy (rename_info->file_name, wide_target, rename_info->file_name_length);

  IO_STATUS_BLOCK io_status = { 0 };
  NTSTATUS status = WYL_STATUS_SUCCESS;
  if (windows_fault_take (fault)) {
    status = take_next_rename_status ();
    if (status == 0)
      status = WYL_STATUS_OBJECT_NAME_COLLISION;
  } else {
    status = set_info (handle, &io_status, rename_info, rename_info_len,
            WYL_NT_FILE_RENAME_INFO_CLASS);
  }
  CloseHandle (handle);

  if (NT_SUCCESS (status)) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
  } else if (status == WYL_STATUS_OBJECT_NAME_COLLISION
      || status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
      || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
      || status == WYL_STATUS_NO_SUCH_FILE
      || status == WYL_STATUS_ACCESS_DENIED
      || status == WYL_STATUS_PRIVILEGE_NOT_HELD
      || status == WYL_STATUS_INVALID_PARAMETER
      || status == WYL_STATUS_FILE_IS_A_DIRECTORY
      || status == WYL_STATUS_NOT_A_DIRECTORY
      || status == WYL_STATUS_NOT_SAME_DEVICE
      || status == WYL_STATUS_MEDIA_WRITE_PROTECTED
      || status == WYL_STATUS_SHARING_VIOLATION
      || status == WYL_STATUS_NOT_SUPPORTED
      || status == WYL_STATUS_NOT_IMPLEMENTED) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  } else {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_sync_file (const WylFactArtifactTransitionWindows *provider,
    const gchar *name,
    const WylFactArtifactMainTransitionEntryEvidence *expected,
    WylFactArtifactTransitionWindowsTestFault open_fault,
    WylFactArtifactTransitionWindowsTestFault flush_fault,
    WylFactArtifactMainTransitionDurability *out_durability,
    WylFactArtifactMainTransitionEffect *out_effect)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  if (out_durability != NULL)
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (provider == NULL || name == NULL || expected == NULL
      || out_durability == NULL || out_effect == NULL)
    return WYRELOG_E_INVALID;

  if (windows_fault_take (open_fault)) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }

  wyrelog_error_t rc = execute_open_expected (provider, name,
          READ_CONTROL | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
          expected, &handle, out_effect);
  if (rc != WYRELOG_E_OK || handle == INVALID_HANDLE_VALUE)
    return rc;

  gboolean flush_ok = FALSE;
  DWORD flush_error = ERROR_SUCCESS;
  if (windows_fault_take (flush_fault)) {
    flush_error = take_next_flush_error ();
    if (flush_error == ERROR_SUCCESS)
      flush_error = ERROR_GEN_FAILURE;
    flush_ok = FALSE;
  } else {
    flush_ok = FlushFileBuffers (handle);
    flush_error = flush_ok ? ERROR_SUCCESS : GetLastError ();
  }
  CloseHandle (handle);

  if (flush_ok) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN;
  } else if (flush_error == ERROR_ACCESS_DENIED
      || flush_error == ERROR_PRIVILEGE_NOT_HELD
      || flush_error == ERROR_FILE_NOT_FOUND
      || flush_error == ERROR_PATH_NOT_FOUND
      || flush_error == ERROR_INVALID_PARAMETER) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  } else {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_sync_dir (const WylFactArtifactTransitionWindows *provider,
    WylFactArtifactTransitionWindowsTestFault flush_fault,
    WylFactArtifactMainTransitionDurability *out_durability,
    WylFactArtifactMainTransitionEffect *out_effect)
{
  if (out_durability != NULL)
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (provider == NULL || out_durability == NULL || out_effect == NULL
      || provider->graph_handle == NULL
      || provider->graph_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;

  gboolean flush_ok = FALSE;
  DWORD flush_error = ERROR_SUCCESS;
  if (windows_fault_take (flush_fault)) {
    flush_error = take_next_flush_error ();
    if (flush_error == ERROR_SUCCESS)
      flush_error = ERROR_GEN_FAILURE;
    flush_ok = FALSE;
  } else {
    flush_ok = FlushFileBuffers (provider->graph_handle);
    flush_error = flush_ok ? ERROR_SUCCESS : GetLastError ();
  }

  if (flush_ok) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_PROVEN;
  } else if (flush_error == ERROR_NOT_SUPPORTED
      || flush_error == ERROR_INVALID_FUNCTION
      || flush_error == ERROR_INVALID_HANDLE) {
    if (provider->capability.directory_flush
        == WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED) {
      *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
      *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNSUPPORTED;
    } else {
      *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
      *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
    }
  } else if (flush_error == ERROR_ACCESS_DENIED
      || flush_error == ERROR_PRIVILEGE_NOT_HELD
      || flush_error == ERROR_INVALID_PARAMETER) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  } else {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    *out_durability = WYL_FACT_ARTIFACT_MAIN_TRANSITION_DURABILITY_UNPROVEN;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
execute_unlink_entry (const WylFactArtifactTransitionWindows *provider,
    const gchar *name,
    const WylFactArtifactMainTransitionEntryEvidence *expected,
    gboolean absent_is_applied,
    WylFactArtifactTransitionWindowsTestFault verify_fault,
    WylFactArtifactTransitionWindowsTestFault unlink_fault,
    WylFactArtifactMainTransitionEffect *out_effect)
{
  WylNtSetInformationFile set_info = nt_set_information_file ();
  HANDLE handle = INVALID_HANDLE_VALUE;
  NTSTATUS status = WYL_STATUS_SUCCESS;
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (provider == NULL || name == NULL || expected == NULL || out_effect == NULL
      || set_info == NULL)
    return WYRELOG_E_INVALID;

  if (windows_fault_take (verify_fault)) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
    return WYRELOG_E_OK;
  }

  if (absent_is_applied && !expected->present) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
    return WYRELOG_E_OK;
  }

  wyrelog_error_t rc = execute_open_expected (provider, name,
          READ_CONTROL | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, expected,
          &handle, out_effect);
  if (rc != WYRELOG_E_OK || handle == INVALID_HANDLE_VALUE) {
    if (absent_is_applied
        && *out_effect == WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED)
      *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
    return rc;
  }

  WylFileDispositionInfo disp = { .delete_file = TRUE };
  IO_STATUS_BLOCK io_status = { 0 };
  if (windows_fault_take (unlink_fault)) {
    status = WYL_STATUS_UNEXPECTED_IO_ERROR;
  } else {
    status = set_info (handle, &io_status, &disp, sizeof disp,
            WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  }
  CloseHandle (handle);

  if (NT_SUCCESS (status)) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
  } else if (absent_is_applied
      && (status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
      || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
      || status == WYL_STATUS_NO_SUCH_FILE)) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_APPLIED;
  } else if (status == WYL_STATUS_OBJECT_NAME_NOT_FOUND
      || status == WYL_STATUS_OBJECT_PATH_NOT_FOUND
      || status == WYL_STATUS_NO_SUCH_FILE
      || status == WYL_STATUS_ACCESS_DENIED
      || status == WYL_STATUS_PRIVILEGE_NOT_HELD
      || status == WYL_STATUS_FILE_IS_A_DIRECTORY
      || status == WYL_STATUS_CANNOT_DELETE
      || status == WYL_STATUS_DELETE_PENDING
      || status == WYL_STATUS_MEDIA_WRITE_PROTECTED) {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  } else {
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_UNKNOWN;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_artifact_transition_windows_execute
  (WylFactArtifactTransitionWindows *provider,
    const WylFactArtifactMainTransitionObservation *authorized,
    WylFactArtifactMainTransitionOp op,
    WylFactArtifactMainTransitionEffect *out_effect,
    WylFactArtifactMainTransitionDurabilityEvidence *out_durability)
{
  if (out_effect != NULL)
    *out_effect = WYL_FACT_ARTIFACT_MAIN_TRANSITION_EFFECT_NOT_APPLIED;
  if (out_durability != NULL)
    *out_durability = (WylFactArtifactMainTransitionDurabilityEvidence) { 0 };
  if (provider == NULL || authorized == NULL || out_effect == NULL
      || out_durability == NULL || provider->graph_handle == NULL
      || provider->graph_handle == INVALID_HANDLE_VALUE)
    return WYRELOG_E_INVALID;
  if (op <= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_INSPECT
      || op >= WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_COUNT)
    return WYRELOG_E_INVALID;

  if (windows_fault_take (WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_LEASE_VERIFY))
    return WYRELOG_E_POLICY;

  wyrelog_error_t status = wyl_fact_root_writer_lease_verify (provider->lease);
  if (status != WYRELOG_E_OK)
    return status;
  status = execute_verify_authorization (provider, authorized);
  if (status != WYRELOG_E_OK)
    return status;

  switch (op) {
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_STAGED:
      return execute_sync_file (provider, provider->names.stage,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE],
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_STAGED_OPEN,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_STAGED_FSYNC,
                 &out_durability->staged_file, out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETAIN:
      return execute_rename (provider, WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME,
                 provider->names.rollback,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_MAIN],
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETAIN_RENAME,
                 out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_ROLLBACK_FILE:
      return execute_sync_file (provider, provider->names.rollback,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK],
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_OPEN,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_ROLLBACK_FSYNC,
                 &out_durability->rollback_file, out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_RETAIN_DIR:
      return execute_sync_dir (provider,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_RETAIN_DIR_FSYNC,
                 &out_durability->directory_after_retain, out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_PUBLISH:
      return execute_rename (provider, provider->names.stage,
                 WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE],
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_PUBLISH_RENAME,
                 out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_SYNC_PUBLISH_DIR:
      return execute_sync_dir (provider,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_SYNC_PUBLISH_DIR_FSYNC,
                 &out_durability->directory_after_publish, out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_ROLLBACK:
      return execute_rename (provider, provider->names.rollback,
                 WYL_FACT_ARTIFACT_TRANSITION_FINAL_NAME,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK],
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_ROLLBACK_RENAME,
                 out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_RETIRE_STAGE:
      return execute_unlink_entry (provider, provider->names.stage,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_STAGE], FALSE,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETIRE_STAGE_VERIFY,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_RETIRE_STAGE_UNLINK,
                 out_effect);
    case WYL_FACT_ARTIFACT_MAIN_TRANSITION_OP_FINALIZE:
      return execute_unlink_entry (provider, provider->names.rollback,
                 &authorized->entries
                 [WYL_FACT_ARTIFACT_MAIN_TRANSITION_SLOT_ROLLBACK], TRUE,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_FINALIZE_VERIFY,
                 WYL_FACT_ARTIFACT_TRANSITION_WINDOWS_TEST_FAULT_EXECUTE_FINALIZE_UNLINK,
                 out_effect);
    default:
      return WYRELOG_E_INVALID;
  }
}

#endif /* G_OS_WIN32 */
