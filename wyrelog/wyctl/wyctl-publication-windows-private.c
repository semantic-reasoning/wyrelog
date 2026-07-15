/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyctl-publication-windows-private.h"

#ifdef G_OS_WIN32

#include <errno.h>
#include <string.h>

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

typedef struct
{
  SECURITY_ATTRIBUTES attrs;
  PSECURITY_DESCRIPTOR descriptor;
} WinOwnerOnlySecurityAttributes;

typedef struct
{
  HANDLE dir_handle;
  gchar *root_dir;
} WyctlPublicationWindowsAnchor;

static gboolean
backend_is_valid (const WyctlPublicationWindowsBackend *backend)
{
  return backend != NULL && backend->root_dir != NULL
      && backend->root_dir[0] != '\0';
}

static gboolean
string_is_present (const gchar *value)
{
  return value != NULL && value[0] != '\0';
}

static void
    win_owner_only_security_attributes_clear
    (WinOwnerOnlySecurityAttributes * attrs)
{
  if (attrs == NULL)
    return;
  if (attrs->descriptor != NULL)
    LocalFree (attrs->descriptor);
  memset (attrs, 0, sizeof *attrs);
}

static wyrelog_error_t
win_owner_only_security_attributes_init (WinOwnerOnlySecurityAttributes *attrs)
{
  static const wchar_t sddl[] = L"D:P(A;;FA;;;OW)";

  if (attrs == NULL)
    return WYRELOG_E_INVALID;
  memset (attrs, 0, sizeof *attrs);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl,
          SDDL_REVISION_1, &attrs->descriptor, NULL))
    return WYRELOG_E_IO;
  attrs->attrs.nLength = sizeof attrs->attrs;
  attrs->attrs.lpSecurityDescriptor = attrs->descriptor;
  attrs->attrs.bInheritHandle = FALSE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
map_win32_error (DWORD error)
{
  switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_NAME:
      return WYRELOG_E_NOT_FOUND;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:
      return WYRELOG_E_POLICY;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
      return WYRELOG_E_POLICY;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
      return WYRELOG_E_NOMEM;
    default:
      return WYRELOG_E_IO;
  }
}

static wchar_t *
utf8_to_wide (const gchar *path)
{
  return (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
}

static gboolean
wide_path_exists (const gchar *path, DWORD *out_attrs, DWORD *out_error)
{
  wchar_t *wpath = utf8_to_wide (path);
  DWORD attrs;
  if (wpath == NULL)
    return FALSE;
  attrs = GetFileAttributesW (wpath);
  if (out_attrs != NULL)
    *out_attrs = attrs;
  if (out_error != NULL)
    *out_error = attrs == INVALID_FILE_ATTRIBUTES ? GetLastError () : 0;
  g_free (wpath);
  return attrs != INVALID_FILE_ATTRIBUTES;
}

static gboolean info_is_reparse_point (const BY_HANDLE_FILE_INFORMATION * info);

static wyrelog_error_t
open_root_anchor (const WyctlPublicationWindowsBackend *backend,
    WyctlPublicationWindowsAnchor *anchor)
{
  wchar_t *wroot = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };

  if (!backend_is_valid (backend) || anchor == NULL)
    return WYRELOG_E_INVALID;
  memset (anchor, 0, sizeof *anchor);
  wroot = utf8_to_wide (backend->root_dir);
  if (wroot == NULL)
    return WYRELOG_E_NOMEM;
  handle = CreateFileW (wroot, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
      | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      NULL);
  g_free (wroot);
  if (handle == INVALID_HANDLE_VALUE)
    return map_win32_error (GetLastError ());
  if (!GetFileInformationByHandle (handle, &info)) {
    wyrelog_error_t rc = map_win32_error (GetLastError ());
    CloseHandle (handle);
    return rc;
  }
  if (info_is_reparse_point (&info)) {
    CloseHandle (handle);
    return WYRELOG_E_POLICY;
  }
  anchor->dir_handle = handle;
  anchor->root_dir = g_strdup (backend->root_dir);
  if (anchor->root_dir == NULL) {
    CloseHandle (handle);
    memset (anchor, 0, sizeof *anchor);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

static void
close_root_anchor (WyctlPublicationWindowsAnchor *anchor)
{
  if (anchor == NULL)
    return;
  if (anchor->dir_handle != INVALID_HANDLE_VALUE && anchor->dir_handle != NULL)
    CloseHandle (anchor->dir_handle);
  g_clear_pointer (&anchor->root_dir, g_free);
  memset (anchor, 0, sizeof *anchor);
}

static gchar *
path_for_plan (const WyctlPublicationWindowsBackend *backend,
    const WyctlPublicationPlan *plan, const gchar *basename)
{
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !string_is_present (basename))
    return NULL;
  return g_build_filename (backend->root_dir, basename, NULL);
}

static wyrelog_error_t
directory_flush (HANDLE dir_handle)
{
  if (dir_handle == INVALID_HANDLE_VALUE || dir_handle == NULL)
    return WYRELOG_E_INVALID;
  if (!FlushFileBuffers (dir_handle))
    return map_win32_error (GetLastError ());
  return WYRELOG_E_OK;
}

static gchar *
identity_from_info (const BY_HANDLE_FILE_INFORMATION *info)
{
  if (info == NULL)
    return NULL;
  return g_strdup_printf ("win:%08lx:%08lx:%08lx",
      (gulong) info->dwVolumeSerialNumber,
      (gulong) info->nFileIndexHigh, (gulong) info->nFileIndexLow);
}

static gboolean
identity_matches_info (const gchar *identity,
    const BY_HANDLE_FILE_INFORMATION *info)
{
  g_autofree gchar *expected = identity_from_info (info);
  return string_is_present (identity) && expected != NULL
      && g_strcmp0 (identity, expected) == 0;
}

static gboolean
info_is_reparse_point (const BY_HANDLE_FILE_INFORMATION *info)
{
  return info != NULL
      && (info->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static gboolean
sid_matches_current_user (PSID sid)
{
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  gboolean matches = FALSE;

  if (sid == NULL || !OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY,
          &token))
    return FALSE;
  if (!GetTokenInformation (token, TokenUser, NULL, 0, &needed)
      && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle (token);
    return FALSE;
  }
  user = g_malloc0 (needed);
  if (user == NULL) {
    CloseHandle (token);
    return FALSE;
  }
  if (!GetTokenInformation (token, TokenUser, user, needed, &needed)) {
    g_free (user);
    CloseHandle (token);
    return FALSE;
  }
  matches = EqualSid (sid, user->User.Sid);
  g_free (user);
  CloseHandle (token);
  return matches;
}

static gboolean
security_descriptor_is_owner_only (PSECURITY_DESCRIPTOR descriptor)
{
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  PACL dacl = NULL;
  PSID owner = NULL;
  ACL_SIZE_INFORMATION size_info = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;

  if (descriptor == NULL
      || !GetSecurityDescriptorControl (descriptor, &control, NULL)
      || (control & SE_DACL_PROTECTED) == 0
      || !GetSecurityDescriptorOwner (descriptor, &owner, NULL)
      || owner == NULL || !sid_matches_current_user (owner)
      || !GetSecurityDescriptorDacl (descriptor, &dacl_present, &dacl,
          &dacl_defaulted)
      || !dacl_present || dacl == NULL || dacl_defaulted)
    return FALSE;
  if (!GetAclInformation (dacl, &size_info, sizeof size_info,
          AclSizeInformation) || size_info.AceCount != 1)
    return FALSE;
  if (!GetAce (dacl, 0, (LPVOID *) & ace) || ace == NULL
      || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
    return FALSE;
  return EqualSid ((PSID) & ace->SidStart, owner)
      && ace->Mask == FILE_ALL_ACCESS;
}

#ifdef WYL_TEST_WYCTL_PUBLICATION_WINDOWS
gboolean
    wyctl_publication_windows_test_security_descriptor_is_owner_only
    (const gchar * sddl)
{
  PSECURITY_DESCRIPTOR descriptor = NULL;
  gboolean result = FALSE;
  wchar_t *wsddl = NULL;

  if (sddl == NULL)
    return FALSE;
  wsddl = utf8_to_wide (sddl);
  if (wsddl == NULL)
    return FALSE;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW (wsddl,
          SDDL_REVISION_1, &descriptor, NULL)) {
    g_free (wsddl);
    return FALSE;
  }
  result = security_descriptor_is_owner_only (descriptor);
  LocalFree (descriptor);
  g_free (wsddl);
  return result;
}
#endif

static wyrelog_error_t
read_all_handle (HANDLE handle, gchar **out_text, gsize *out_len)
{
  gsize cap = 4096;
  gsize total = 0;
  gchar *buf = g_malloc0 (cap + 1);
  if (buf == NULL)
    return WYRELOG_E_NOMEM;
  for (;;) {
    DWORD got = 0;
    if (!ReadFile (handle, buf + total, (DWORD) (cap - total), &got, NULL)) {
      g_free (buf);
      return map_win32_error (GetLastError ());
    }
    if (got == 0)
      break;
    total += got;
    if (total == cap) {
      gsize next = cap * 2;
      gchar *grown = g_realloc (buf, next + 1);
      if (grown == NULL) {
        g_free (buf);
        return WYRELOG_E_NOMEM;
      }
      buf = grown;
      cap = next;
    }
  }
  buf[total] = '\0';
  if (out_text != NULL)
    *out_text = buf;
  else
    g_free (buf);
  if (out_len != NULL)
    *out_len = total;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_all_handle (HANDLE handle, const guint8 *bytes, gsize len)
{
  gsize total = 0;
  while (total < len) {
    DWORD chunk = (DWORD) MIN ((gsize) 0x10000, len - total);
    DWORD put = 0;
    if (!WriteFile (handle, bytes + total, chunk, &put, NULL) || put == 0)
      return map_win32_error (GetLastError ());
    total += put;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_credential_document_to_handle (HANDLE handle, const gchar *credential_id,
    const gchar *credential_secret)
{
  g_autofree gchar *document = NULL;
  wyrelog_error_t rc = wyctl_publication_credential_document_encode
      (credential_id, credential_secret, &document);
  if (rc != WYRELOG_E_OK)
    return rc;
  LARGE_INTEGER zero = { 0 };
  if (!SetFilePointerEx (handle, zero, NULL, FILE_BEGIN))
    return map_win32_error (GetLastError ());
  if (!SetEndOfFile (handle))
    return map_win32_error (GetLastError ());
  rc = write_all_handle (handle, (const guint8 *) document, strlen (document));
  if (rc != WYRELOG_E_OK)
    return rc;
  return FlushFileBuffers (handle) ? WYRELOG_E_OK :
      map_win32_error (GetLastError ());
}

static wyrelog_error_t
file_info_for_path (const gchar *path, DWORD desired_access,
    DWORD share_mode, DWORD creation_disposition, DWORD flags,
    HANDLE *out_handle, BY_HANDLE_FILE_INFORMATION *out_info)
{
  wchar_t *wpath = utf8_to_wide (path);
  HANDLE handle;
  wyrelog_error_t rc;
  if (wpath == NULL || out_handle == NULL || out_info == NULL)
    return WYRELOG_E_INVALID;
  handle = CreateFileW (wpath, desired_access, share_mode, NULL,
      creation_disposition, flags, NULL);
  g_free (wpath);
  if (handle == INVALID_HANDLE_VALUE)
    return map_win32_error (GetLastError ());
  if (!GetFileInformationByHandle (handle, out_info)) {
    rc = map_win32_error (GetLastError ());
    CloseHandle (handle);
    return rc;
  }
  *out_handle = handle;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
file_identity_for_path (const gchar *path, gboolean allow_missing,
    gchar **out_identity, HANDLE *out_handle,
    BY_HANDLE_FILE_INFORMATION *out_info)
{
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info;
  wyrelog_error_t rc = file_info_for_path (path, FILE_READ_ATTRIBUTES,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, &handle, &info);
  if (rc == WYRELOG_E_NOT_FOUND && allow_missing)
    return WYRELOG_E_NOT_FOUND;
  if (rc != WYRELOG_E_OK)
    return rc;
  if (info_is_reparse_point (&info)) {
    CloseHandle (handle);
    return WYRELOG_E_POLICY;
  }
  if (out_identity != NULL)
    *out_identity = identity_from_info (&info);
  if (out_handle != NULL)
    *out_handle = handle;
  else
    CloseHandle (handle);
  if (out_info != NULL)
    *out_info = info;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
delete_path_exact (const gchar *path)
{
  wchar_t *wpath = utf8_to_wide (path);
  if (wpath == NULL)
    return WYRELOG_E_NOMEM;
  if (!DeleteFileW (wpath)) {
    wyrelog_error_t rc = map_win32_error (GetLastError ());
    g_free (wpath);
    return rc;
  }
  g_free (wpath);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
move_stage_to_destination (const gchar *stage_path, const gchar *destination)
{
  wchar_t *wstage = utf8_to_wide (stage_path);
  wchar_t *wdst = utf8_to_wide (destination);
  BOOL moved;

  if (wstage == NULL || wdst == NULL) {
    g_free (wstage);
    g_free (wdst);
    return WYRELOG_E_NOMEM;
  }
  moved = MoveFileExW (wstage, wdst, MOVEFILE_WRITE_THROUGH);
  g_free (wstage);
  g_free (wdst);
  if (!moved)
    return map_win32_error (GetLastError ());
  return WYRELOG_E_OK;
}

static wyrelog_error_t
windows_result_fill (WyctlPublicationResult *out_result,
    WyctlPublicationResultKind kind, gboolean exact_identity,
    gboolean cleanup_required)
{
  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind = kind,.exact_identity =
        exact_identity,.cleanup_required = cleanup_required,};
  return WYRELOG_E_OK;
}

void wyctl_publication_windows_backend_init
    (WyctlPublicationWindowsBackend * backend, const gchar * root_dir)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
  backend->root_dir = g_strdup (root_dir);
}

void wyctl_publication_windows_backend_clear
    (WyctlPublicationWindowsBackend * backend)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
}

wyrelog_error_t
wyctl_publication_windows_plan (const WyctlPublicationWindowsBackend *backend,
    const WyctlPublicationPlan *request, WyctlPublicationPlan *out_plan)
{
  g_autofree gchar *destination_path = NULL;
  DWORD error = 0;

  if (out_plan == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_plan_clear (out_plan);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (request))
    return WYRELOG_E_INVALID;

  destination_path = path_for_plan (backend, request, request->destination);
  if (destination_path == NULL)
    return WYRELOG_E_NOMEM;
  if (wide_path_exists (destination_path, NULL, &error))
    return WYRELOG_E_POLICY;
  if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND
      && error != 0)
    return map_win32_error (error);
  return wyctl_publication_plan_clone (request, out_plan);
}

wyrelog_error_t
wyctl_publication_windows_prepare (const WyctlPublicationWindowsBackend
    *backend, const WyctlPublicationPlan *plan,
    WyctlPublicationReceipt *out_receipt)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  HANDLE stage_handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  WinOwnerOnlySecurityAttributes sa = { 0 };
  gchar *identity = NULL;
  wyrelog_error_t rc = WYRELOG_E_OK;

  if (out_receipt == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_receipt_clear (out_receipt);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  if (stage_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = win_owner_only_security_attributes_init (&sa);
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    return rc;
  }

  {
    wchar_t *wstage = utf8_to_wide (stage_path);
    if (wstage == NULL) {
      win_owner_only_security_attributes_clear (&sa);
      close_root_anchor (&anchor);
      return WYRELOG_E_NOMEM;
    }
    stage_handle = CreateFileW (wstage, GENERIC_READ | GENERIC_WRITE, 0,
        &sa.attrs, CREATE_NEW, FILE_ATTRIBUTE_NORMAL
        | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    g_free (wstage);
  }
  win_owner_only_security_attributes_clear (&sa);
  if (stage_handle == INVALID_HANDLE_VALUE) {
    rc = map_win32_error (GetLastError ());
    close_root_anchor (&anchor);
    return rc;
  }

  if (!GetFileInformationByHandle (stage_handle, &info)
      || info_is_reparse_point (&info)) {
    CloseHandle (stage_handle);
    delete_path_exact (stage_path);
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  {
    DWORD sec_len = 0;
    PSECURITY_DESCRIPTOR sec = NULL;
    if (!GetKernelObjectSecurity (stage_handle,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0,
            &sec_len) && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
      CloseHandle (stage_handle);
      delete_path_exact (stage_path);
      close_root_anchor (&anchor);
      return WYRELOG_E_POLICY;
    }
    sec = g_malloc0 (sec_len);
    if (sec == NULL) {
      CloseHandle (stage_handle);
      delete_path_exact (stage_path);
      close_root_anchor (&anchor);
      return WYRELOG_E_NOMEM;
    }
    if (!GetKernelObjectSecurity (stage_handle,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sec,
            sec_len, &sec_len) || !security_descriptor_is_owner_only (sec)) {
      g_free (sec);
      CloseHandle (stage_handle);
      delete_path_exact (stage_path);
      close_root_anchor (&anchor);
      return WYRELOG_E_POLICY;
    }
    g_free (sec);
  }

  identity = identity_from_info (&info);
  CloseHandle (stage_handle);
  close_root_anchor (&anchor);
  if (identity == NULL)
    return WYRELOG_E_NOMEM;
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  g_free (identity);
  return rc;
}

static wyrelog_error_t
commit_stage_to_destination (const WyctlPublicationWindowsBackend *backend,
    const WyctlPublicationPlan *plan, const WyctlPublicationReceipt *receipt,
    const gchar *credential_id, const gchar *credential_secret,
    WyctlPublicationResult *out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  HANDLE stage_handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !string_is_present (credential_id)
      || !string_is_present (credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = file_info_for_path (stage_path, FILE_READ_ATTRIBUTES | GENERIC_READ
      | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
      &stage_handle, &info);
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    return rc;
  }
  if (!identity_matches_info (receipt->stage_identity, &info)) {
    CloseHandle (stage_handle);
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = write_credential_document_to_handle (stage_handle, credential_id,
      credential_secret);
  if (rc != WYRELOG_E_OK) {
    CloseHandle (stage_handle);
    close_root_anchor (&anchor);
    windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
    return rc;
  }
  CloseHandle (stage_handle);
  stage_handle = INVALID_HANDLE_VALUE;

  rc = move_stage_to_destination (stage_path, destination_path);
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
    return rc;
  }
  rc = directory_flush (anchor.dir_handle);
  close_root_anchor (&anchor);
  if (rc != WYRELOG_E_OK) {
    windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, FALSE);
    return WYRELOG_E_OK;
  }
  windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyctl_publication_windows_commit
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result)
{
  return commit_stage_to_destination (backend, plan, receipt, credential_id,
      credential_secret, out_result);
}

wyrelog_error_t
    wyctl_publication_windows_inspect
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  DWORD attrs = 0;
  DWORD error = 0;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  g_autofree gchar *content = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };
  gsize content_len = 0;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;

  if (wide_path_exists (destination_path, &attrs, &error)) {
    rc = file_info_for_path (destination_path,
        FILE_READ_ATTRIBUTES | GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, &handle, &info);
    if (rc == WYRELOG_E_OK && info_is_reparse_point (&info)) {
      CloseHandle (handle);
      return WYRELOG_E_POLICY;
    }
    if (rc == WYRELOG_E_OK
        && identity_matches_info (receipt->stage_identity, &info)) {
      rc = read_all_handle (handle, &content, &content_len);
      CloseHandle (handle);
      if (rc != WYRELOG_E_OK)
        return rc;
      rc = wyctl_publication_credential_document_decode (content, content_len,
          &decoded_id, &decoded_secret);
      wyctl_sensitive_text_clear (&decoded_secret);
      if (rc == WYRELOG_E_OK)
        return windows_result_fill (out_result,
            WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, FALSE);
    }
    if (rc != WYRELOG_E_OK && rc != WYRELOG_E_POLICY)
      return rc;
  }

  rc = file_identity_for_path (stage_path, TRUE, NULL, &handle, &info);
  if (rc == WYRELOG_E_NOT_FOUND) {
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!identity_matches_info (receipt->stage_identity, &info)) {
    CloseHandle (handle);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  rc = read_all_handle (handle, &content, &content_len);
  CloseHandle (handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (content_len == 0)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
  rc = wyctl_publication_credential_document_decode (content, content_len,
      &decoded_id, &decoded_secret);
  wyctl_sensitive_text_clear (&decoded_secret);
  if (rc == WYRELOG_E_OK)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, TRUE);
}

wyrelog_error_t
    wyctl_publication_windows_resync
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  g_autofree gchar *content = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };
  gsize content_len = 0;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = file_identity_for_path (destination_path, TRUE, NULL, &handle, &info);
  if (rc == WYRELOG_E_OK && identity_matches_info (receipt->stage_identity,
          &info)) {
    CloseHandle (handle);
    close_root_anchor (&anchor);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = file_identity_for_path (stage_path, TRUE, NULL, &handle, &info);
    if (rc == WYRELOG_E_NOT_FOUND) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    if (!identity_matches_info (receipt->stage_identity, &info)) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = read_all_handle (handle, &content, &content_len);
    CloseHandle (handle);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    if (content_len == 0) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
    }
    rc = wyctl_publication_credential_document_decode (content, content_len,
        &decoded_id, &decoded_secret);
    wyctl_sensitive_text_clear (&decoded_secret);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, TRUE);
    }
    rc = move_stage_to_destination (stage_path, destination_path);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, TRUE);
    }
    rc = directory_flush (anchor.dir_handle);
    close_root_anchor (&anchor);
    if (rc != WYRELOG_E_OK)
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, FALSE);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
  }
  close_root_anchor (&anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!identity_matches_info (receipt->stage_identity, &info)) {
    CloseHandle (handle);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  rc = read_all_handle (handle, &content, &content_len);
  CloseHandle (handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (content_len == 0)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
  rc = wyctl_publication_credential_document_decode (content, content_len,
      &decoded_id, &decoded_secret);
  wyctl_sensitive_text_clear (&decoded_secret);
  if (rc != WYRELOG_E_OK)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, TRUE);
  rc = move_stage_to_destination (stage_path, destination_path);
  if (rc != WYRELOG_E_OK)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN, TRUE, TRUE);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
}

wyrelog_error_t
    wyctl_publication_windows_cleanup
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = file_identity_for_path (stage_path, TRUE, NULL, &handle, &info);
  if (rc == WYRELOG_E_OK && identity_matches_info (receipt->stage_identity,
          &info)) {
    CloseHandle (handle);
    rc = delete_path_exact (stage_path);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    rc = directory_flush (anchor.dir_handle);
    close_root_anchor (&anchor);
    if (rc != WYRELOG_E_OK)
      return rc;
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, FALSE);
  }
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = file_identity_for_path (destination_path, TRUE, NULL, &handle, &info);
    if (rc == WYRELOG_E_NOT_FOUND) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    CloseHandle (handle);
    if (!identity_matches_info (receipt->stage_identity, &info)) {
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    close_root_anchor (&anchor);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
  }
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    return rc;
  }
  CloseHandle (handle);
  close_root_anchor (&anchor);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
}

#else

void wyctl_publication_windows_backend_init
    (WyctlPublicationWindowsBackend * backend, const gchar * root_dir)
{
  (void) backend;
  (void) root_dir;
}

void wyctl_publication_windows_backend_clear
    (WyctlPublicationWindowsBackend * backend)
{
  (void) backend;
}

wyrelog_error_t
wyctl_publication_windows_plan (const WyctlPublicationWindowsBackend *backend,
    const WyctlPublicationPlan *request, WyctlPublicationPlan *out_plan)
{
  (void) backend;
  (void) request;
  (void) out_plan;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
wyctl_publication_windows_prepare (const WyctlPublicationWindowsBackend
    *backend, const WyctlPublicationPlan *plan,
    WyctlPublicationReceipt *out_receipt)
{
  (void) backend;
  (void) plan;
  (void) out_receipt;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_commit
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) credential_id;
  (void) credential_secret;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_inspect
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_resync
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_cleanup
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

#endif
