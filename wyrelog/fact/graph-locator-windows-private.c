/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-locator-private.h"

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <winternl.h>

#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define WYL_FACT_GRAPH_LOG_DOMAIN "wyrelog-fact-resolver"

static void
trace_windows_failure (const gchar *stage, wyrelog_error_t rc,
    DWORD native_code)
{
  g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
      "stage=%s rc=%d native=0x%08lx", stage, (int) rc,
      (unsigned long) native_code);
}

static gchar *
try_strdup (const gchar *value)
{
  gsize len = strlen (value);
  gchar *copy = g_try_malloc (len + 1);
  if (copy != NULL)
    memcpy (copy, value, len + 1);
  return copy;
}

typedef NTSTATUS (NTAPI * WylNtCreateFile) (PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG,
    ULONG, ULONG, PVOID, ULONG);

typedef NTSTATUS (NTAPI * WylNtSetInformationFile) (HANDLE,
    PIO_STATUS_BLOCK, PVOID, ULONG, int);

#define WYL_NT_FILE_RENAME_INFO_CLASS 10
#define WYL_NT_FILE_DISPOSITION_INFO_CLASS 13

typedef struct
{
  BOOLEAN replace_if_exists;
  HANDLE root_directory;
  ULONG file_name_length;
  WCHAR file_name[1];
} WylFileRenameInfo;

typedef struct
{
  BOOLEAN delete_file;
} WylFileDispositionInfo;

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

enum
{
  WYL_FILE_ID_EXTD_DIRECTORY_INFO = 19,
  WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO = 20
};

typedef struct
{
  PSID user;
  PACL acl;
  SECURITY_DESCRIPTOR descriptor;
} WylOwnerOnlySecurity;

static WylNtCreateFile
nt_create_file (void)
{
  static WylNtCreateFile function;
  if (function == NULL) {
    HMODULE module = GetModuleHandleW (L"ntdll.dll");
    if (module != NULL)
      function = (WylNtCreateFile) GetProcAddress (module, "NtCreateFile");
  }
  return function;
}

static WylNtSetInformationFile
nt_set_information_file (void)
{
  static WylNtSetInformationFile function;
  if (function == NULL) {
    HMODULE module = GetModuleHandleW (L"ntdll.dll");
    if (module != NULL)
      function = (WylNtSetInformationFile) GetProcAddress (module,
          "NtSetInformationFile");
  }
  return function;
}

static wyrelog_error_t
ntstatus_to_error (NTSTATUS status)
{
  switch ((ULONG) status) {
    case 0xC0000034UL:         /* STATUS_OBJECT_NAME_NOT_FOUND */
    case 0xC000003AUL:         /* STATUS_OBJECT_PATH_NOT_FOUND */
      return WYRELOG_E_NOT_FOUND;
    case 0xC0000043UL:         /* STATUS_SHARING_VIOLATION */
      return WYRELOG_E_BUSY;
    case 0xC0000022UL:         /* STATUS_ACCESS_DENIED */
    case 0xC0000024UL:         /* STATUS_OBJECT_TYPE_MISMATCH */
    case 0xC0000035UL:         /* STATUS_OBJECT_NAME_COLLISION */
    case 0xC00000BAUL:         /* STATUS_FILE_IS_A_DIRECTORY */
    case 0xC0000103UL:         /* STATUS_NOT_A_DIRECTORY */
    case 0xC0000276UL:         /* STATUS_IO_REPARSE_TAG_INVALID */
    case 0xC0000277UL:         /* STATUS_IO_REPARSE_TAG_MISMATCH */
    case 0xC0000278UL:         /* STATUS_IO_REPARSE_DATA_INVALID */
    case 0xC0000279UL:         /* STATUS_IO_REPARSE_TAG_NOT_HANDLED */
    case 0xC0000280UL:         /* STATUS_REPARSE_POINT_NOT_RESOLVED */
    case 0xC0000281UL:         /* STATUS_DIRECTORY_IS_A_REPARSE_POINT */
    case 0xC0000106UL:         /* STATUS_NAME_TOO_LONG */
    case 0xC0000368UL:         /* STATUS_MOUNT_POINT_NOT_RESOLVED */
    case 0xC000050BUL:         /* STATUS_REPARSE_POINT_ENCOUNTERED */
    case 0x8000002DUL:         /* STATUS_STOPPED_ON_SYMLINK */
      return WYRELOG_E_POLICY;
    default:
      return WYRELOG_E_IO;
  }
}

static gboolean
handle_is_valid (HANDLE handle)
{
  return handle != NULL && handle != INVALID_HANDLE_VALUE;
}

static gboolean
identity_equal (const WylFactGraphWinIdentity *left,
    const WylFactGraphWinIdentity *right)
{
  return left->volume_serial == right->volume_serial
      && memcmp (left->file_id, right->file_id, sizeof left->file_id) == 0;
}

static wyrelog_error_t
query_directory_identity (HANDLE handle, WylFactGraphWinIdentity *out_identity)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_ID_INFO native_identity = { 0 };
  if (!handle_is_valid (handle) || out_identity == NULL)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic)) {
    trace_windows_failure ("identity-basic", WYRELOG_E_IO, GetLastError ());
    return WYRELOG_E_IO;
  }
  if (!GetFileInformationByHandleEx (handle, FileIdInfo, &native_identity,
          sizeof native_identity)) {
    trace_windows_failure ("identity-file-id", WYRELOG_E_IO, GetLastError ());
    return WYRELOG_E_IO;
  }
  if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    trace_windows_failure ("identity-attributes", WYRELOG_E_POLICY,
        basic.FileAttributes);
    return WYRELOG_E_POLICY;
  }
  out_identity->volume_serial = native_identity.VolumeSerialNumber;
  memcpy (out_identity->file_id, &native_identity.FileId,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

static gboolean
component_is_reserved_device (const WCHAR *component, gsize units)
{
  gsize base_units = 0;
  while (base_units < units && component[base_units] != L'.')
    base_units++;
  if ((base_units == 3 && (CompareStringOrdinal (component, 3, L"CON", 3, TRUE)
              == CSTR_EQUAL
              || CompareStringOrdinal (component, 3, L"PRN", 3, TRUE)
              == CSTR_EQUAL
              || CompareStringOrdinal (component, 3, L"AUX", 3, TRUE)
              == CSTR_EQUAL
              || CompareStringOrdinal (component, 3, L"NUL", 3, TRUE)
              == CSTR_EQUAL))
      || (base_units == 4
          && (CompareStringOrdinal (component, 3, L"COM", 3, TRUE)
              == CSTR_EQUAL
              || CompareStringOrdinal (component, 3, L"LPT", 3, TRUE)
              == CSTR_EQUAL)
          && ((component[3] >= L'1' && component[3] <= L'9')
              || component[3] == 0x00b9 || component[3] == 0x00b2
              || component[3] == 0x00b3)))
    return TRUE;
  return FALSE;
}

static gboolean
wide_component_is_safe (const WCHAR *component, gsize units)
{
  if (component == NULL || units == 0 || units > 255
      || (units == 1 && component[0] == L'.')
      || (units == 2 && component[0] == L'.' && component[1] == L'.')
      || component[units - 1] == L'.' || component[units - 1] == L' '
      || component_is_reserved_device (component, units))
    return FALSE;
  for (gsize i = 0; i < units; i++) {
    if (component[i] < 0x20 || component[i] == L':'
        || component[i] == L'/' || component[i] == L'\\')
      return FALSE;
  }
  return TRUE;
}

static gboolean
utf8_component_is_safe (const gchar *component)
{
  glong units = 0;
  g_autofree gunichar2 *wide = NULL;
  if (component == NULL || component[0] == '\0')
    return FALSE;
  wide = g_utf8_to_utf16 (component, -1, NULL, &units, NULL);
  return wide != NULL && units > 0
      && wide_component_is_safe ((WCHAR *) wide, (gsize) units);
}

static wyrelog_error_t
copy_token_user (PSID *out_user)
{
  HANDLE token = NULL;
  TOKEN_USER *info = NULL;
  DWORD needed = 0;
  PSID copy = NULL;
  if (out_user == NULL)
    return WYRELOG_E_INVALID;
  *out_user = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return WYRELOG_E_IO;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto out;
  info = g_try_malloc (needed);
  if (info == NULL) {
    CloseHandle (token);
    return WYRELOG_E_NOMEM;
  }
  if (!GetTokenInformation (token, TokenUser, info, needed, &needed)
      || info->User.Sid == NULL || !IsValidSid (info->User.Sid))
    goto out;
  needed = GetLengthSid (info->User.Sid);
  copy = g_try_malloc (needed);
  if (copy == NULL) {
    g_free (info);
    CloseHandle (token);
    return WYRELOG_E_NOMEM;
  }
  if (!CopySid (needed, copy, info->User.Sid))
    g_clear_pointer (&copy, g_free);
out:
  g_free (info);
  CloseHandle (token);
  *out_user = copy;
  return copy != NULL ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static void
owner_only_security_clear (WylOwnerOnlySecurity *security)
{
  g_free (security->acl);
  g_free (security->user);
  memset (security, 0, sizeof *security);
}

static wyrelog_error_t
owner_only_security_init (WylOwnerOnlySecurity *security, BYTE ace_flags)
{
  wyrelog_error_t rc;
  DWORD sid_length;
  DWORD acl_length;
  memset (security, 0, sizeof *security);
  rc = copy_token_user (&security->user);
  if (rc != WYRELOG_E_OK)
    return rc;
  sid_length = GetLengthSid (security->user);
  acl_length = sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD)
      + sid_length;
  security->acl = g_try_malloc0 (acl_length);
  if (security->acl == NULL) {
    owner_only_security_clear (security);
    return WYRELOG_E_NOMEM;
  }
  if (!InitializeAcl (security->acl, acl_length, ACL_REVISION)
      || !AddAccessAllowedAceEx (security->acl, ACL_REVISION, ace_flags,
          FILE_ALL_ACCESS, security->user)
      || !InitializeSecurityDescriptor (&security->descriptor,
          SECURITY_DESCRIPTOR_REVISION)
      || !SetSecurityDescriptorOwner (&security->descriptor, security->user,
          FALSE)
      || !SetSecurityDescriptorDacl (&security->descriptor, TRUE,
          security->acl, FALSE)
      || !SetSecurityDescriptorControl (&security->descriptor,
          SE_DACL_PROTECTED, SE_DACL_PROTECTED)) {
    owner_only_security_clear (security);
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_protected_owner_acl (HANDLE handle, BYTE ace_flags)
{
  g_autofree gpointer token_user = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PSID owner = NULL;
  PACL dacl = NULL;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  wyrelog_error_t rc = copy_token_user ((PSID *) & token_user);
  if (rc != WYRELOG_E_OK)
    return rc;
  DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
      &dacl, NULL, &descriptor);
  if (error != ERROR_SUCCESS) {
    trace_windows_failure ("acl-query", WYRELOG_E_IO, error);
    return WYRELOG_E_IO;
  }
  gboolean owner_match = owner != NULL && IsValidSid (owner)
      && EqualSid (owner, token_user);
  gboolean control_ok = GetSecurityDescriptorControl (descriptor, &control,
      &revision);
  gboolean dacl_ok = GetSecurityDescriptorDacl (descriptor, &present, &dacl,
      &defaulted);
  gboolean acl_info_ok = dacl_ok && present && dacl != NULL
      && GetAclInformation (dacl, &size, sizeof size, AclSizeInformation);
  gboolean ace_ok = acl_info_ok && size.AceCount == 1
      && GetAce (dacl, 0, (LPVOID *) & ace) && ace != NULL;
  gboolean allowed_ace = ace_ok
      && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
  PSID ace_sid = allowed_ace ? (PSID) & ace->SidStart : NULL;
  gboolean ace_sid_valid = ace_sid != NULL && IsValidSid (ace_sid);
  gboolean ace_sid_match = ace_sid_valid && EqualSid (ace_sid, token_user);
  gboolean valid = owner_match && control_ok
      && (control & SE_DACL_PROTECTED) != 0 && dacl_ok && present
      && dacl != NULL && !defaulted && acl_info_ok && size.AceCount == 1
      && ace_ok && allowed_ace && ace->Header.AceFlags == ace_flags
      && ace->Mask == FILE_ALL_ACCESS && ace_sid_match;
  if (!valid)
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=acl-validate rc=%d owner-match=%u control-ok=%u "
        "control=0x%04x dacl-ok=%u present=%u defaulted=%u acl-info-ok=%u "
        "ace-count=%lu ace-ok=%u ace-type=%u ace-flags=0x%02x "
        "ace-mask=0x%08lx ace-sid-valid=%u ace-sid-match=%u",
        (int) WYRELOG_E_POLICY, (unsigned int) owner_match,
        (unsigned int) control_ok, (unsigned int) control,
        (unsigned int) dacl_ok,
        (unsigned int) present, (unsigned int) defaulted,
        (unsigned int) acl_info_ok, (unsigned long) size.AceCount,
        (unsigned int) ace_ok,
        ace != NULL ? (unsigned int) ace->Header.AceType : 0,
        ace != NULL ? (unsigned int) ace->Header.AceFlags : 0,
        allowed_ace ? (unsigned long) ace->Mask : 0,
        (unsigned int) ace_sid_valid, (unsigned int) ace_sid_match);
  LocalFree (descriptor);
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
validate_owner_only_acl (HANDLE handle)
{
  return validate_protected_owner_acl (handle,
      OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
}

static wyrelog_error_t
validate_directory (HANDLE handle, const WylFactGraphWinIdentity *expected,
    gboolean validate_acl)
{
  WylFactGraphWinIdentity current = { 0 };
  wyrelog_error_t rc = query_directory_identity (handle, &current);
  if (rc == WYRELOG_E_OK && expected != NULL
      && !identity_equal (&current, expected))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && validate_acl)
    rc = validate_owner_only_acl (handle);
  return rc;
}

static gboolean
directory_name_is_alias (const WCHAR *actual, gsize actual_units,
    const WCHAR *wanted, gsize wanted_units)
{
  while (actual_units > 0
      && (actual[actual_units - 1] == L'.' || actual[actual_units - 1] == L' '))
    actual_units--;
  while (wanted_units > 0
      && (wanted[wanted_units - 1] == L'.' || wanted[wanted_units - 1] == L' '))
    wanted_units--;
  return actual_units == wanted_units
      && CompareStringOrdinal (actual, (int) actual_units, wanted,
      (int) wanted_units, TRUE) == CSTR_EQUAL;
}

static wyrelog_error_t
validate_parent_entry (HANDLE parent, const WCHAR *wanted,
    gsize wanted_units, const WylFactGraphWinIdentity *identity)
{
  BYTE buffer[64 * 1024];
  gboolean restart = TRUE;
  guint alias_equivalent_count = 0;
  guint exact_spelling_count = 0;
  guint exact_identity_count = 0;
  guint alias_spelling_count = 0;
  guint identity_mismatch_count = 0;
  guint rejected_count = 0;
  for (;;) {
    FILE_INFO_BY_HANDLE_CLASS info_class = (FILE_INFO_BY_HANDLE_CLASS)
        (restart ? WYL_FILE_ID_EXTD_DIRECTORY_RESTART_INFO
        : WYL_FILE_ID_EXTD_DIRECTORY_INFO);
    if (!GetFileInformationByHandleEx (parent, info_class, buffer,
            sizeof buffer)) {
      DWORD error = GetLastError ();
      if (error == ERROR_NO_MORE_FILES)
        break;
      trace_windows_failure ("parent-enumerate",
          error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO, error);
      return error == ERROR_MORE_DATA ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    }
    restart = FALSE;
    WylFileIdExtdDirInfo *entry = (WylFileIdExtdDirInfo *) buffer;
    for (;;) {
      gsize entry_units = entry->file_name_length / sizeof (WCHAR);
      if (directory_name_is_alias (entry->file_name, entry_units, wanted,
              wanted_units)) {
        gboolean exact = entry_units == wanted_units
            && memcmp (entry->file_name, wanted,
            wanted_units * sizeof (WCHAR)) == 0;
        gboolean identity_match = memcmp (&entry->file_id, identity->file_id,
            sizeof entry->file_id) == 0;
        alias_equivalent_count++;
        if (exact)
          exact_spelling_count++;
        else
          alias_spelling_count++;
        if (exact && identity_match)
          exact_identity_count++;
        else
          rejected_count++;
        if (!identity_match)
          identity_mismatch_count++;
      }
      if (entry->next_entry_offset == 0)
        break;
      entry = (WylFileIdExtdDirInfo *) ((BYTE *) entry
          + entry->next_entry_offset);
    }
  }
  if (exact_identity_count != 1 || rejected_count != 0) {
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=parent-entry rc=%d alias-equivalent=%u exact-spelling=%u "
        "exact-identity=%u alias-spelling=%u identity-mismatch=%u "
        "rejected=%u", (int) WYRELOG_E_POLICY, alias_equivalent_count,
        exact_spelling_count, exact_identity_count, alias_spelling_count,
        identity_mismatch_count, rejected_count);
    return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
open_relative_directory (HANDLE parent, const WCHAR *component, gsize units,
    gboolean create, gboolean secured_handle, HANDLE *out_handle,
    WylFactGraphWinIdentity *out_identity)
{
  WylNtCreateFile nt_create = nt_create_file ();
  WylOwnerOnlySecurity security;
  UNICODE_STRING name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_handle == NULL || out_identity == NULL || nt_create == NULL
      || !wide_component_is_safe (component, units)
      || units > G_MAXUSHORT / sizeof (WCHAR)) {
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=relative-precondition rc=%d units=%lu nt-create=%u",
        (int) WYRELOG_E_POLICY, (unsigned long) units,
        (unsigned int) (nt_create != NULL));
    return WYRELOG_E_POLICY;
  }
  *out_handle = INVALID_HANDLE_VALUE;
  memset (out_identity, 0, sizeof *out_identity);
  memset (&security, 0, sizeof security);
  if (create) {
    rc = owner_only_security_init (&security,
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  name.Length = (USHORT) (units * sizeof (WCHAR));
  name.MaximumLength = name.Length;
  name.Buffer = (PWSTR) component;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = parent;
  attributes.ObjectName = &name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create ? &security.descriptor : NULL;
  ACCESS_MASK access = FILE_LIST_DIRECTORY | FILE_TRAVERSE
      | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
  if (secured_handle)
    access |= GENERIC_WRITE | FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE;
  NTSTATUS status = nt_create (&handle, access,
      &attributes, &iosb, NULL, FILE_ATTRIBUTE_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      create ? FILE_OPEN_IF : FILE_OPEN,
      FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
      | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  owner_only_security_clear (&security);
  if (status < 0 || !handle_is_valid (handle)) {
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=relative-open rc=%d ntstatus=0x%08lx iosb=0x%08lx",
        (int) ntstatus_to_error (status), (unsigned long) (ULONG) status,
        (unsigned long) (ULONG) iosb.Status);
    return ntstatus_to_error (status);
  }
  rc = query_directory_identity (handle, out_identity);
  if (rc == WYRELOG_E_OK && secured_handle)
    rc = validate_owner_only_acl (handle);
  if (rc == WYRELOG_E_OK)
    rc = validate_parent_entry (parent, component, units, out_identity);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (handle);
    return rc;
  }
  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_remote_volume (HANDLE root)
{
  FILE_REMOTE_PROTOCOL_INFO remote = { 0 };
  G_STATIC_ASSERT (sizeof remote <= G_MAXUSHORT);
  remote.StructureVersion = 2;
  remote.StructureSize = (USHORT) sizeof remote;
  if (GetFileInformationByHandleEx (root, FileRemoteProtocolInfo, &remote,
          sizeof remote)) {
    trace_windows_failure ("remote-detected", WYRELOG_E_POLICY,
        remote.Protocol);
    return WYRELOG_E_POLICY;
  }
  DWORD error = GetLastError ();
  if (error == ERROR_INVALID_PARAMETER || error == ERROR_NOT_SUPPORTED
      || error == ERROR_INVALID_FUNCTION)
    return WYRELOG_E_OK;
  trace_windows_failure ("remote-query", WYRELOG_E_POLICY, error);
  return WYRELOG_E_POLICY;
}

static wyrelog_error_t
walk_absolute_directory (const gchar *path, HANDLE *out_handle,
    WylFactGraphWinIdentity *out_identity, gboolean validate_final_acl)
{
  glong units = 0;
  g_autofree gunichar2 *wide = NULL;
  WCHAR volume_root[] = L"C:\\";
  HANDLE current = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity current_identity = { 0 };
  if (out_handle == NULL || out_identity == NULL || path == NULL
      || path[0] == '\0')
    return WYRELOG_E_INVALID;
  *out_handle = INVALID_HANDLE_VALUE;
  memset (out_identity, 0, sizeof *out_identity);
  wide = g_utf8_to_utf16 (path, -1, NULL, &units, NULL);
  if (wide == NULL || units < 4
      || !g_ascii_isalpha ((gchar) wide[0]) || wide[1] != L':'
      || wide[2] != L'\\' || wide[3] == L'\\') {
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=absolute-path rc=%d units=%ld", (int) WYRELOG_E_POLICY,
        (long) units);
    return WYRELOG_E_POLICY;
  }
  volume_root[0] = (WCHAR) g_ascii_toupper ((gchar) wide[0]);
  UINT drive_type = GetDriveTypeW (volume_root);
  if (drive_type != DRIVE_FIXED) {
    trace_windows_failure ("drive-type", WYRELOG_E_POLICY, drive_type);
    return WYRELOG_E_POLICY;
  }
  current = CreateFileW (volume_root,
      FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES
      | READ_CONTROL | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  if (!handle_is_valid (current)) {
    trace_windows_failure ("volume-open", WYRELOG_E_IO, GetLastError ());
    return WYRELOG_E_IO;
  }
  wyrelog_error_t rc = reject_remote_volume (current);
  if (rc == WYRELOG_E_OK)
    rc = query_directory_identity (current, &current_identity);
  guint component_index = 0;
  for (gsize start = 3; rc == WYRELOG_E_OK && start < (gsize) units;
      component_index++) {
    gsize end = start;
    while (end < (gsize) units && wide[end] != L'\\')
      end++;
    if (end == start || (end < (gsize) units && end + 1 == (gsize) units)) {
      g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
          "stage=path-component rc=%d index=%u units=%lu",
          (int) WYRELOG_E_POLICY, component_index,
          (unsigned long) (end - start));
      rc = WYRELOG_E_POLICY;
      break;
    }
    HANDLE next = INVALID_HANDLE_VALUE;
    WylFactGraphWinIdentity next_identity = { 0 };
    rc = open_relative_directory (current, (WCHAR *) wide + start,
        end - start, FALSE, end == (gsize) units, &next, &next_identity);
    if (rc != WYRELOG_E_OK) {
      g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
          "stage=walk-component rc=%d index=%u units=%lu final=%u", (int) rc,
          component_index, (unsigned long) (end - start),
          (unsigned int) (end == (gsize) units));
      break;
    }
    CloseHandle (current);
    current = next;
    current_identity = next_identity;
    start = end + 1;
  }
  if (rc == WYRELOG_E_OK && validate_final_acl)
    rc = validate_owner_only_acl (current);
  if (rc != WYRELOG_E_OK) {
    if (handle_is_valid (current))
      CloseHandle (current);
    return rc;
  }
  *out_handle = current;
  *out_identity = current_identity;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reopen_root (const gchar *path, const WylFactGraphWinIdentity *expected,
    HANDLE *out_handle)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  wyrelog_error_t rc = walk_absolute_directory (path, &handle, &identity, TRUE);
  if (rc == WYRELOG_E_NOT_FOUND)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && !identity_equal (&identity, expected))
    rc = WYRELOG_E_POLICY;
  if (rc != WYRELOG_E_OK || out_handle == NULL)
    CloseHandle (handle);
  else
    *out_handle = handle;
  return rc;
}

static gboolean
locator_is_valid_for_windows (const WylFactGraphLocator *locator)
{
  g_autofree gchar *tenant = NULL;
  g_autofree gchar *graph = NULL;
  g_autofree gchar *tenant_encoded = NULL;
  g_autofree gchar *graph_encoded = NULL;
  return locator != NULL && locator->version == WYL_FACT_GRAPH_PATH_VERSION
      && wyl_fact_graph_component_decode (locator->tenant_component,
      &tenant) == WYRELOG_E_OK
      && wyl_fact_graph_component_decode (locator->graph_component,
      &graph) == WYRELOG_E_OK
      && wyl_fact_graph_component_encode (tenant,
      &tenant_encoded) == WYRELOG_E_OK
      && wyl_fact_graph_component_encode (graph,
      &graph_encoded) == WYRELOG_E_OK
      && g_str_equal (locator->tenant_component, tenant_encoded)
      && g_str_equal (locator->graph_component, graph_encoded)
      && utf8_component_is_safe (locator->tenant_component)
      && utf8_component_is_safe (locator->graph_component);
}

wyrelog_error_t
wyl_fact_graph_resolver_open (const gchar *fact_root,
    WylFactGraphResolver *out_resolver)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  if (out_resolver == NULL)
    return WYRELOG_E_INVALID;
  *out_resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
  wyrelog_error_t rc = walk_absolute_directory (fact_root, &handle, &identity,
      TRUE);
  if (rc != WYRELOG_E_OK)
    return rc;
  gchar *path = try_strdup (fact_root);
  if (path == NULL) {
    CloseHandle (handle);
    return WYRELOG_E_NOMEM;
  }
  out_resolver->handle = handle;
  out_resolver->identity = identity;
  out_resolver->path = path;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_resolver_revalidate (WylFactGraphResolver *resolver)
{
  if (resolver == NULL || !handle_is_valid (resolver->handle)
      || resolver->path == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_directory (resolver->handle,
      &resolver->identity, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = reopen_root (resolver->path, &resolver->identity, NULL);
  return rc;
}

void
wyl_fact_graph_resolver_clear (WylFactGraphResolver *resolver)
{
  if (resolver == NULL)
    return;
  if (handle_is_valid (resolver->handle))
    CloseHandle (resolver->handle);
  g_free (resolver->path);
  *resolver = (WylFactGraphResolver) WYL_FACT_GRAPH_RESOLVER_INIT;
}

void wyl_fact_graph_resolver_set_checkpoint_for_test
    (WylFactGraphResolver * resolver,
    wyrelog_error_t (*checkpoint) (const gchar * point, gpointer user_data),
    gpointer user_data)
{
  if (resolver == NULL)
    return;
  resolver->checkpoint = checkpoint;
  resolver->checkpoint_data = user_data;
}

static wyrelog_error_t directory_revalidate (WylFactGraphDirectory * directory);

wyrelog_error_t
wyl_fact_graph_resolver_open_directory (WylFactGraphResolver *resolver,
    const WylFactGraphLocator *locator, gboolean create,
    WylFactGraphDirectory *out_directory)
{
  HANDLE root = INVALID_HANDLE_VALUE;
  HANDLE tenant = INVALID_HANDLE_VALUE;
  HANDLE graph = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity tenant_identity = { 0 };
  WylFactGraphWinIdentity graph_identity = { 0 };
  if (out_directory == NULL)
    return WYRELOG_E_INVALID;
  *out_directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
  if (resolver == NULL || !handle_is_valid (resolver->handle)
      || resolver->path == NULL || !locator_is_valid_for_windows (locator))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = reopen_root (resolver->path, &resolver->identity,
      &root);
  if (rc == WYRELOG_E_OK && resolver->checkpoint != NULL)
    rc = resolver->checkpoint ("root-opened", resolver->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = reopen_root (resolver->path, &resolver->identity, NULL);
  g_autofree gunichar2 *tenant_wide = NULL;
  g_autofree gunichar2 *graph_wide = NULL;
  glong tenant_units = 0;
  glong graph_units = 0;
  if (rc == WYRELOG_E_OK) {
    tenant_wide = g_utf8_to_utf16 (locator->tenant_component, -1, NULL,
        &tenant_units, NULL);
    graph_wide = g_utf8_to_utf16 (locator->graph_component, -1, NULL,
        &graph_units, NULL);
    if (tenant_wide == NULL || graph_wide == NULL)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = open_relative_directory (root, (WCHAR *) tenant_wide,
        (gsize) tenant_units, create, TRUE, &tenant, &tenant_identity);
  if (rc == WYRELOG_E_OK && resolver->checkpoint != NULL)
    rc = resolver->checkpoint ("tenant-opened", resolver->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = open_relative_directory (tenant, (WCHAR *) graph_wide,
        (gsize) graph_units, create, TRUE, &graph, &graph_identity);
  if (rc == WYRELOG_E_OK && resolver->checkpoint != NULL)
    rc = resolver->checkpoint ("graph-opened", resolver->checkpoint_data);
  if (rc != WYRELOG_E_OK)
    goto fail;
  out_directory->root_path = try_strdup (resolver->path);
  out_directory->tenant_component = try_strdup (locator->tenant_component);
  out_directory->graph_component = try_strdup (locator->graph_component);
  if (out_directory->root_path == NULL
      || out_directory->tenant_component == NULL
      || out_directory->graph_component == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto fail;
  }
  out_directory->root_handle = root;
  out_directory->tenant_handle = tenant;
  out_directory->graph_handle = graph;
  out_directory->root_identity = resolver->identity;
  out_directory->tenant_identity = tenant_identity;
  out_directory->graph_identity = graph_identity;
  out_directory->checkpoint = resolver->checkpoint;
  out_directory->checkpoint_data = resolver->checkpoint_data;
  rc = directory_revalidate (out_directory);
  if (rc == WYRELOG_E_OK)
    return WYRELOG_E_OK;
  wyl_fact_graph_directory_clear (out_directory);
  return rc;
fail:
  if (handle_is_valid (graph))
    CloseHandle (graph);
  if (handle_is_valid (tenant))
    CloseHandle (tenant);
  if (handle_is_valid (root))
    CloseHandle (root);
  wyl_fact_graph_directory_clear (out_directory);
  return rc;
}

void
wyl_fact_graph_directory_clear (WylFactGraphDirectory *directory)
{
  if (directory == NULL)
    return;
  if (handle_is_valid (directory->graph_handle))
    CloseHandle (directory->graph_handle);
  if (handle_is_valid (directory->tenant_handle))
    CloseHandle (directory->tenant_handle);
  if (handle_is_valid (directory->root_handle))
    CloseHandle (directory->root_handle);
  g_free (directory->root_path);
  g_free (directory->tenant_component);
  g_free (directory->graph_component);
  *directory = (WylFactGraphDirectory) WYL_FACT_GRAPH_DIRECTORY_INIT;
}

static wyrelog_error_t
revalidate_named_child (HANDLE parent, const gchar *component,
    HANDLE held, const WylFactGraphWinIdentity *identity)
{
  glong units = 0;
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (component, -1, NULL, &units,
      NULL);
  HANDLE reopened = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity reopened_identity = { 0 };
  if (wide == NULL)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = validate_directory (held, identity, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = open_relative_directory (parent, (WCHAR *) wide, (gsize) units,
        FALSE, TRUE, &reopened, &reopened_identity);
  if (rc == WYRELOG_E_OK && !identity_equal (&reopened_identity, identity))
    rc = WYRELOG_E_POLICY;
  if (handle_is_valid (reopened))
    CloseHandle (reopened);
  return rc;
}

static wyrelog_error_t
directory_revalidate (WylFactGraphDirectory *directory)
{
  if (directory == NULL || !handle_is_valid (directory->root_handle)
      || !handle_is_valid (directory->tenant_handle)
      || !handle_is_valid (directory->graph_handle)
      || directory->root_path == NULL)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = reopen_root (directory->root_path,
      &directory->root_identity, NULL);
  if (rc == WYRELOG_E_OK)
    rc = validate_directory (directory->root_handle,
        &directory->root_identity, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_child (directory->root_handle,
        directory->tenant_component, directory->tenant_handle,
        &directory->tenant_identity);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_child (directory->tenant_handle,
        directory->graph_component, directory->graph_handle,
        &directory->graph_identity);
  return rc;
}

gchar *
wyl_fact_graph_directory_descriptive_path (const WylFactGraphDirectory
    *directory)
{
  if (directory == NULL || directory->root_path == NULL)
    return NULL;
  return g_build_filename (directory->root_path, directory->tenant_component,
      directory->graph_component, NULL);
}

gchar *
wyl_fact_graph_directory_descriptive_file (const WylFactGraphDirectory
    *directory, const gchar *basename)
{
  if (!utf8_component_is_safe (basename))
    return NULL;
  g_autofree gchar *path =
      wyl_fact_graph_directory_descriptive_path (directory);
  return path == NULL ? NULL : g_build_filename (path, basename, NULL);
}

static wyrelog_error_t
query_regular_identity (HANDLE handle, WylFactGraphWinIdentity *out_identity)
{
  FILE_BASIC_INFO basic = { 0 };
  FILE_STANDARD_INFO standard = { 0 };
  FILE_ID_INFO native_identity = { 0 };
  if (!handle_is_valid (handle) || out_identity == NULL)
    return WYRELOG_E_INVALID;
  if (!GetFileInformationByHandleEx (handle, FileBasicInfo, &basic,
          sizeof basic)
      || !GetFileInformationByHandleEx (handle, FileStandardInfo, &standard,
          sizeof standard)
      || !GetFileInformationByHandleEx (handle, FileIdInfo, &native_identity,
          sizeof native_identity))
    return WYRELOG_E_IO;
  if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
      || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
      || standard.Directory || standard.DeletePending
      || standard.NumberOfLinks != 1)
    return WYRELOG_E_POLICY;
  out_identity->volume_serial = native_identity.VolumeSerialNumber;
  memcpy (out_identity->file_id, &native_identity.FileId,
      sizeof out_identity->file_id);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
validate_regular_file (HANDLE handle,
    const WylFactGraphWinIdentity *expected, gboolean strict_acl)
{
  WylFactGraphWinIdentity identity = { 0 };
  wyrelog_error_t rc = query_regular_identity (handle, &identity);
  if (rc == WYRELOG_E_OK && expected != NULL
      && !identity_equal (&identity, expected))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && strict_acl)
    rc = validate_protected_owner_acl (handle, 0);
  return rc;
}

static wyrelog_error_t
validate_upgradeable_file_acl (HANDLE handle)
{
  g_autofree gpointer token_user = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PSID owner = NULL;
  PACL dacl = NULL;
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  wyrelog_error_t rc = copy_token_user ((PSID *) & token_user);
  if (rc != WYRELOG_E_OK)
    return rc;
  DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
      &dacl, NULL, &descriptor);
  if (error != ERROR_SUCCESS)
    return WYRELOG_E_IO;
  gboolean valid = owner != NULL && EqualSid (owner, token_user)
      && GetSecurityDescriptorDacl (descriptor, &present, &dacl, &defaulted)
      && present && dacl != NULL && !defaulted
      && GetAclInformation (dacl, &size, sizeof size, AclSizeInformation)
      && size.AceCount == 1 && GetAce (dacl, 0, (LPVOID *) & ace)
      && ace != NULL && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE
      && (ace->Header.AceFlags & ~INHERITED_ACE) == 0
      && ace->Mask == FILE_ALL_ACCESS
      && EqualSid ((PSID) & ace->SidStart, token_user);
  LocalFree (descriptor);
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t set_delete_disposition (HANDLE handle);

static wyrelog_error_t
open_relative_regular (HANDLE parent, const gchar *basename,
    ACCESS_MASK access, gboolean create, gboolean strict_acl,
    HANDLE *out_handle, WylFactGraphWinIdentity *out_identity)
{
  WylNtCreateFile nt_create = nt_create_file ();
  WylOwnerOnlySecurity security;
  g_autofree gunichar2 *wide = NULL;
  glong units = 0;
  UNICODE_STRING name = { 0 };
  OBJECT_ATTRIBUTES attributes = { 0 };
  IO_STATUS_BLOCK iosb = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  wyrelog_error_t rc;
  if (out_handle == NULL || out_identity == NULL || nt_create == NULL
      || !utf8_component_is_safe (basename))
    return WYRELOG_E_INVALID;
  *out_handle = INVALID_HANDLE_VALUE;
  memset (out_identity, 0, sizeof *out_identity);
  wide = g_utf8_to_utf16 (basename, -1, NULL, &units, NULL);
  if (wide == NULL || units <= 0
      || (gsize) units > G_MAXUSHORT / sizeof (WCHAR))
    return WYRELOG_E_POLICY;
  memset (&security, 0, sizeof security);
  if (create) {
    rc = owner_only_security_init (&security, 0);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  name.Length = (USHORT) (units * sizeof (WCHAR));
  name.MaximumLength = name.Length;
  name.Buffer = (PWSTR) wide;
  attributes.Length = sizeof attributes;
  attributes.RootDirectory = parent;
  attributes.ObjectName = &name;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = create ? &security.descriptor : NULL;
  NTSTATUS status = nt_create (&handle,
      access | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
      &attributes, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      create ? FILE_CREATE : FILE_OPEN,
      FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
      | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  owner_only_security_clear (&security);
  if (status < 0 || !handle_is_valid (handle))
    return ntstatus_to_error (status);
  rc = query_regular_identity (handle, out_identity);
  if (rc == WYRELOG_E_OK && strict_acl)
    rc = validate_protected_owner_acl (handle, 0);
  if (rc == WYRELOG_E_OK)
    rc = validate_parent_entry (parent, (WCHAR *) wide, (gsize) units,
        out_identity);
  if (rc != WYRELOG_E_OK) {
    if (create)
      (void) set_delete_disposition (handle);
    CloseHandle (handle);
    return rc;
  }
  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
revalidate_named_regular (WylFactGraphDirectory *directory,
    const gchar *basename, HANDLE held,
    const WylFactGraphWinIdentity *identity, gboolean strict_acl)
{
  glong units = 0;
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (basename, -1, NULL, &units,
      NULL);
  if (wide == NULL || units <= 0)
    return WYRELOG_E_POLICY;
  wyrelog_error_t rc = validate_regular_file (held, identity, strict_acl);
  if (rc == WYRELOG_E_OK)
    rc = validate_parent_entry (directory->graph_handle, (WCHAR *) wide,
        (gsize) units, identity);
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  return rc;
}

static wyrelog_error_t
flush_directory (HANDLE directory)
{
  if (FlushFileBuffers (directory))
    return WYRELOG_E_OK;
  DWORD error = GetLastError ();
  return error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED
      ? WYRELOG_E_OK : WYRELOG_E_IO;
}

static HANDLE
borrow_stage_handle (const WylFactGraphStage *stage)
{
  if (stage == NULL || stage->fd < 0)
    return INVALID_HANDLE_VALUE;
  intptr_t value = _get_osfhandle (stage->fd);
  return value == -1 ? INVALID_HANDLE_VALUE : (HANDLE) value;
}

static wyrelog_error_t
set_delete_disposition (HANDLE handle)
{
  WylNtSetInformationFile nt_set = nt_set_information_file ();
  if (nt_set == NULL || !handle_is_valid (handle))
    return WYRELOG_E_POLICY;
  WylFileDispositionInfo disposition = {.delete_file = TRUE };
  IO_STATUS_BLOCK iosb = { 0 };
  NTSTATUS status = nt_set (handle, &iosb, &disposition, sizeof disposition,
      WYL_NT_FILE_DISPOSITION_INFO_CLASS);
  if (status >= 0)
    return WYRELOG_E_OK;
  return (ULONG) status == 0xC0000022UL || (ULONG) status == 0xC0000121UL
      ? WYRELOG_E_POLICY : WYRELOG_E_IO;
}

wyrelog_error_t
wyl_fact_graph_directory_open_file (WylFactGraphDirectory *directory,
    const gchar *basename, gboolean writable, gint *out_fd)
{
  if (out_fd != NULL)
    *out_fd = -1;
  if (out_fd == NULL || !utf8_component_is_safe (basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  HANDLE opened = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = open_relative_regular (directory->graph_handle, basename,
        GENERIC_READ | (writable ? GENERIC_WRITE : 0), FALSE, TRUE, &opened,
        &identity);
  if (rc == WYRELOG_E_OK && directory->checkpoint != NULL)
    rc = directory->checkpoint ("file-opened", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_regular (directory, basename, opened, &identity,
        TRUE);
  HANDLE duplicate = INVALID_HANDLE_VALUE;
  if (rc == WYRELOG_E_OK
      && !DuplicateHandle (GetCurrentProcess (), opened, GetCurrentProcess (),
          &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
    rc = WYRELOG_E_IO;
  if (handle_is_valid (opened))
    CloseHandle (opened);
  if (rc != WYRELOG_E_OK) {
    if (handle_is_valid (duplicate))
      CloseHandle (duplicate);
    return rc;
  }
  gint flags = _O_BINARY | (writable ? _O_RDWR : _O_RDONLY);
  gint fd = _open_osfhandle ((intptr_t) duplicate, flags);
  if (fd < 0) {
    CloseHandle (duplicate);
    return WYRELOG_E_IO;
  }
  *out_fd = fd;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_directory_secure_file_mode (WylFactGraphDirectory *directory,
    const gchar *basename)
{
  if (!utf8_component_is_safe (basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = open_relative_regular (directory->graph_handle, basename,
        GENERIC_READ | GENERIC_WRITE | WRITE_DAC, FALSE, FALSE, &handle,
        &identity);
  if (rc == WYRELOG_E_OK)
    rc = validate_upgradeable_file_acl (handle);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_regular (directory, basename, handle, &identity,
        FALSE);
  WylOwnerOnlySecurity security;
  memset (&security, 0, sizeof security);
  if (rc == WYRELOG_E_OK)
    rc = owner_only_security_init (&security, 0);
  if (rc == WYRELOG_E_OK) {
    DWORD error = SetSecurityInfo (handle, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        NULL, NULL, security.acl, NULL);
    if (error != ERROR_SUCCESS)
      rc = error == ERROR_ACCESS_DENIED ? WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  owner_only_security_clear (&security);
  if (rc == WYRELOG_E_OK && !FlushFileBuffers (handle))
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_regular (directory, basename, handle, &identity,
        TRUE);
  if (handle_is_valid (handle))
    CloseHandle (handle);
  return rc;
}

wyrelog_error_t
wyl_fact_graph_directory_stage_create (WylFactGraphDirectory *directory,
    const gchar *final_basename, WylFactGraphStage *out_stage)
{
  if (out_stage != NULL)
    *out_stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
  if (out_stage == NULL || !utf8_component_is_safe (final_basename))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  g_autofree gchar *uuid = g_uuid_string_random ();
  g_autofree gchar *stage_name = uuid == NULL ? NULL
      : g_strdup_printf (".%s.stage-%s", final_basename, uuid);
  if (rc == WYRELOG_E_OK && !utf8_component_is_safe (stage_name))
    rc = WYRELOG_E_POLICY;
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = open_relative_regular (directory->graph_handle, stage_name,
        GENERIC_READ | GENERIC_WRITE | DELETE, TRUE, TRUE, &handle, &identity);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_regular (directory, stage_name, handle, &identity,
        TRUE);
  gchar *stage_copy = NULL;
  gchar *final_copy = NULL;
  if (rc == WYRELOG_E_OK) {
    stage_copy = try_strdup (stage_name);
    final_copy = try_strdup (final_basename);
    if (stage_copy == NULL || final_copy == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  gint fd = -1;
  if (rc == WYRELOG_E_OK) {
    fd = _open_osfhandle ((intptr_t) handle, _O_BINARY | _O_RDWR);
    if (fd < 0)
      rc = WYRELOG_E_IO;
    else
      handle = INVALID_HANDLE_VALUE;
  }
  if (rc != WYRELOG_E_OK) {
    if (handle_is_valid (handle)) {
      (void) set_delete_disposition (handle);
      CloseHandle (handle);
    }
    g_free (stage_copy);
    g_free (final_copy);
    return rc;
  }
  out_stage->fd = fd;
  out_stage->stage_basename = stage_copy;
  out_stage->final_basename = final_copy;
  out_stage->identity = identity;
  out_stage->graph_identity = directory->graph_identity;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_stage_sync (WylFactGraphStage *stage)
{
  HANDLE handle = borrow_stage_handle (stage);
  if (!handle_is_valid (handle))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = validate_regular_file (handle, &stage->identity, TRUE);
  if (rc == WYRELOG_E_OK && !FlushFileBuffers (handle))
    rc = WYRELOG_E_IO;
  return rc;
}

static gboolean
stage_is_bound (WylFactGraphDirectory *directory, WylFactGraphStage *stage)
{
  return directory != NULL && stage != NULL && stage->fd >= 0
      && utf8_component_is_safe (stage->stage_basename)
      && utf8_component_is_safe (stage->final_basename)
      && identity_equal (&stage->graph_identity, &directory->graph_identity);
}

static wyrelog_error_t
named_file_state (WylFactGraphDirectory *directory, const gchar *basename,
    const WylFactGraphWinIdentity *identity, gboolean *out_present,
    gboolean *out_exact)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  WylFactGraphWinIdentity opened_identity = { 0 };
  *out_present = FALSE;
  *out_exact = FALSE;
  wyrelog_error_t rc = open_relative_regular (directory->graph_handle,
      basename, GENERIC_READ, FALSE, TRUE, &handle, &opened_identity);
  if (rc == WYRELOG_E_NOT_FOUND)
    return WYRELOG_E_OK;
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_present = TRUE;
  *out_exact = identity_equal (&opened_identity, identity);
  CloseHandle (handle);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rename_stage_relative (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
  WylNtSetInformationFile nt_set = nt_set_information_file ();
  HANDLE handle = borrow_stage_handle (stage);
  glong units = 0;
  g_autofree gunichar2 *wide = g_utf8_to_utf16 (stage->final_basename, -1,
      NULL, &units, NULL);
  if (nt_set == NULL || !handle_is_valid (handle) || wide == NULL
      || units <= 0 || (gsize) units > G_MAXULONG / sizeof (WCHAR))
    return WYRELOG_E_POLICY;
  gsize bytes = (gsize) units * sizeof (WCHAR);
  gsize total = offsetof (WylFileRenameInfo, file_name) + bytes;
  WylFileRenameInfo *info = g_try_malloc0 (total);
  if (info == NULL)
    return WYRELOG_E_NOMEM;
  info->replace_if_exists = FALSE;
  info->root_directory = directory->graph_handle;
  info->file_name_length = (ULONG) bytes;
  memcpy (info->file_name, wide, bytes);
  IO_STATUS_BLOCK iosb = { 0 };
  NTSTATUS status = nt_set (handle, &iosb, info, (ULONG) total,
      WYL_NT_FILE_RENAME_INFO_CLASS);
  g_free (info);
  return status < 0 ? ntstatus_to_error (status) : WYRELOG_E_OK;
}

static void
stage_forget (WylFactGraphStage *stage)
{
  g_clear_pointer (&stage->stage_basename, g_free);
  g_clear_pointer (&stage->final_basename, g_free);
  memset (&stage->identity, 0, sizeof stage->identity);
  memset (&stage->graph_identity, 0, sizeof stage->graph_identity);
}

static void
stage_mark_complete (WylFactGraphStage *stage)
{
  if (stage->fd >= 0)
    _close (stage->fd);
  stage->fd = -1;
  stage_forget (stage);
}

wyrelog_error_t
wyl_fact_graph_stage_publish (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
  if (!stage_is_bound (directory, stage))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    rc = wyl_fact_graph_stage_sync (stage);
  gboolean stage_present = FALSE;
  gboolean stage_exact = FALSE;
  gboolean final_present = FALSE;
  gboolean final_exact = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->stage_basename, &stage->identity,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->final_basename, &stage->identity,
        &final_present, &final_exact);
  gboolean needs_rename = stage_present && stage_exact && !final_present;
  gboolean converged = !stage_present && final_present && final_exact;
  if (rc == WYRELOG_E_OK && !needs_rename && !converged)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && needs_rename)
    rc = rename_stage_relative (directory, stage);
  if (rc == WYRELOG_E_OK && needs_rename && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-linked", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->stage_basename, &stage->identity,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->final_basename, &stage->identity,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && (stage_present || !final_present || !final_exact))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK && needs_rename && directory->checkpoint != NULL)
    rc = directory->checkpoint ("stage-unlinked", directory->checkpoint_data);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->stage_basename, &stage->identity,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->final_basename, &stage->identity,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && (stage_present || !final_present || !final_exact))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = flush_directory (directory->graph_handle);
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  if (rc == WYRELOG_E_OK)
    stage_mark_complete (stage);
  return rc;
}

static wyrelog_error_t
delete_stage_exact (WylFactGraphStage *stage)
{
  HANDLE handle = borrow_stage_handle (stage);
  return set_delete_disposition (handle);
}

wyrelog_error_t
wyl_fact_graph_stage_abort (WylFactGraphDirectory *directory,
    WylFactGraphStage *stage)
{
  if (!stage_is_bound (directory, stage))
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = directory_revalidate (directory);
  gboolean stage_present = FALSE;
  gboolean stage_exact = FALSE;
  gboolean final_present = FALSE;
  gboolean final_exact = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->stage_basename, &stage->identity,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->final_basename, &stage->identity,
        &final_present, &final_exact);
  if (rc == WYRELOG_E_OK && (!stage_present || !stage_exact || final_present))
    rc = WYRELOG_E_POLICY;
  HANDLE handle = borrow_stage_handle (stage);
  if (rc == WYRELOG_E_OK)
    rc = revalidate_named_regular (directory, stage->stage_basename, handle,
        &stage->identity, TRUE);
  if (rc == WYRELOG_E_OK)
    rc = delete_stage_exact (stage);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (_close (stage->fd) != 0)
    rc = WYRELOG_E_IO;
  stage->fd = -1;
  if (rc == WYRELOG_E_OK)
    rc = named_file_state (directory, stage->stage_basename, &stage->identity,
        &stage_present, &stage_exact);
  if (rc == WYRELOG_E_OK && stage_present)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = flush_directory (directory->graph_handle);
  if (rc == WYRELOG_E_OK)
    rc = directory_revalidate (directory);
  stage_forget (stage);
  return rc;
}

void
wyl_fact_graph_stage_clear (WylFactGraphStage *stage)
{
  if (stage == NULL)
    return;
  if (stage->fd >= 0)
    _close (stage->fd);
  g_free (stage->stage_basename);
  g_free (stage->final_basename);
  *stage = (WylFactGraphStage) WYL_FACT_GRAPH_STAGE_INIT;
}
#endif
