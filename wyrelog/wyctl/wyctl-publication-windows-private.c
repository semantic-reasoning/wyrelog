/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyctl-publication-windows-private.h"

#ifdef G_OS_WIN32

#include <errno.h>
#include <stddef.h>
#include <sodium.h>
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
  BY_HANDLE_FILE_INFORMATION dir_info;
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
  handle = CreateFileW (wroot, FILE_LIST_DIRECTORY | FILE_ADD_FILE
      | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
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
  anchor->dir_info = info;
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
plan_matches_anchor (const WyctlPublicationPlan *plan,
    const WyctlPublicationWindowsAnchor *anchor)
{
  return plan != NULL && anchor != NULL
      && identity_matches_info (plan->parent_identity, &anchor->dir_info);
}

static gboolean
receipt_matches_plan_anchor (const WyctlPublicationReceipt *receipt,
    const WyctlPublicationPlan *plan,
    const WyctlPublicationWindowsAnchor *anchor)
{
  return receipt != NULL && plan_matches_anchor (plan, anchor)
      && g_strcmp0 (receipt->parent_identity, plan->parent_identity) == 0;
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

static gboolean
handle_is_owner_only_regular (HANDLE handle,
    const BY_HANDLE_FILE_INFORMATION *info, gboolean require_empty)
{
  DWORD sec_len = 0;
  PSECURITY_DESCRIPTOR sec = NULL;
  LARGE_INTEGER size = { 0 };
  gboolean valid = FALSE;

  if (handle == INVALID_HANDLE_VALUE || handle == NULL || info == NULL
      || info_is_reparse_point (info)
      || (info->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
      || info->nNumberOfLinks != 1 || !GetFileSizeEx (handle, &size)
      || size.QuadPart < 0 || (require_empty && size.QuadPart != 0))
    return FALSE;
  if (!GetKernelObjectSecurity (handle,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0,
          &sec_len) && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
    return FALSE;
  sec = g_malloc0 (sec_len);
  if (sec == NULL)
    return FALSE;
  valid = GetKernelObjectSecurity (handle,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sec, sec_len,
      &sec_len) && security_descriptor_is_owner_only (sec);
  g_free (sec);
  return valid;
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
      sodium_memzero (buf, cap + 1);
      g_free (buf);
      return map_win32_error (GetLastError ());
    }
    if (got == 0)
      break;
    total += got;
    if (total == cap) {
      gsize next = cap * 2;
      gchar *grown = g_malloc0 (next + 1);
      if (grown == NULL) {
        sodium_memzero (buf, cap + 1);
        g_free (buf);
        return WYRELOG_E_NOMEM;
      }
      memcpy (grown, buf, total);
      sodium_memzero (buf, cap + 1);
      g_free (buf);
      buf = grown;
      cap = next;
    }
  }
  buf[total] = '\0';
  if (out_text != NULL)
    *out_text = buf;
  else {
    sodium_memzero (buf, cap + 1);
    g_free (buf);
  }
  if (out_len != NULL)
    *out_len = total;
  return WYRELOG_E_OK;
}

/* Documents contain the credential secret, so do not leave their plaintext in
 * a normal allocator buffer after inspection. */
static wyrelog_error_t
credential_document_matches_handle (HANDLE handle,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    gboolean *out_empty, gboolean *out_matches)
{
  gchar *document = NULL;
  g_autofree gchar *credential_id = NULL;
  WyctlSensitiveText credential_secret = { 0 };
  gsize document_len = 0;
  wyrelog_error_t rc;

  if (out_empty == NULL || out_matches == NULL)
    return WYRELOG_E_INVALID;
  *out_empty = FALSE;
  *out_matches = FALSE;
  {
    LARGE_INTEGER size = { 0 };
    LARGE_INTEGER zero = { 0 };
    if (!GetFileSizeEx (handle, &size) || size.QuadPart < 0
        || size.QuadPart > 1024
        || !SetFilePointerEx (handle, zero, NULL, FILE_BEGIN))
      return WYRELOG_E_POLICY;
  }
  rc = read_all_handle (handle, &document, &document_len);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (document_len == 0) {
    *out_empty = TRUE;
    sodium_memzero (document, document_len + 1);
    g_free (document);
    return WYRELOG_E_OK;
  }
  rc = wyctl_publication_credential_document_decode (document, document_len,
      &credential_id, &credential_secret);
  if (rc == WYRELOG_E_OK)
    *out_matches = wyctl_publication_credential_document_matches
        (credential_id, &credential_secret, expected_credential_id,
        expected_credential_secret);
  wyctl_sensitive_text_clear (&credential_secret);
  sodium_memzero (document, document_len + 1);
  g_free (document);
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
  gchar *document = NULL;
  gsize document_len = 0;
  wyrelog_error_t rc = wyctl_publication_credential_document_encode
      (credential_id, credential_secret, &document);
  if (rc != WYRELOG_E_OK)
    return rc;
  document_len = strlen (document);
  LARGE_INTEGER zero = { 0 };
  if (!SetFilePointerEx (handle, zero, NULL, FILE_BEGIN))
    rc = map_win32_error (GetLastError ());
  else if (!SetEndOfFile (handle))
    rc = map_win32_error (GetLastError ());
  else {
    rc = write_all_handle (handle, (const guint8 *) document, document_len);
    if (rc == WYRELOG_E_OK && !FlushFileBuffers (handle))
      rc = map_win32_error (GetLastError ());
  }
  sodium_memzero (document, document_len + 1);
  g_free (document);
  return rc;
}

static wyrelog_error_t
write_credential_document_unsynced_to_handle (HANDLE handle,
    const gchar *credential_id, const gchar *credential_secret)
{
  gchar *document = NULL;
  gsize document_len = 0;
  LARGE_INTEGER zero = { 0 };
  wyrelog_error_t rc = wyctl_publication_credential_document_encode
      (credential_id, credential_secret, &document);

  if (rc != WYRELOG_E_OK)
    return rc;
  document_len = strlen (document);
  if (!SetFilePointerEx (handle, zero, NULL, FILE_BEGIN)
      || !SetEndOfFile (handle))
    rc = map_win32_error (GetLastError ());
  else
    rc = write_all_handle (handle, (const guint8 *) document, document_len);
  sodium_memzero (document, document_len + 1);
  g_free (document);
  return rc;
}

static wyrelog_error_t delete_handle_exact (HANDLE handle);
static wyrelog_error_t windows_result_fill (WyctlPublicationResult * out_result,
    WyctlPublicationResultKind kind, gboolean exact_identity,
    gboolean cleanup_required);
static wyrelog_error_t rename_handle_to_destination (HANDLE stage_handle,
    HANDLE root_handle, const gchar * destination);

static gboolean
cleanup_created_handle_durable (HANDLE *stage_handle,
    WyctlPublicationWindowsAnchor *anchor)
{
  if (stage_handle == NULL || *stage_handle == INVALID_HANDLE_VALUE
      || *stage_handle == NULL
      || delete_handle_exact (*stage_handle) != WYRELOG_E_OK)
    return FALSE;
  CloseHandle (*stage_handle);
  *stage_handle = INVALID_HANDLE_VALUE;
  return directory_flush (anchor->dir_handle) == WYRELOG_E_OK;
}

static WyctlPublicationStageExactAction
stage_exact_hook (const WyctlPublicationWindowsBackend *backend,
    WyctlPublicationStageExactPoint point)
{
  if (backend->stage_exact_hook == NULL)
    return WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE;
  return backend->stage_exact_hook (backend->stage_exact_hook_data, point);
}

static gchar *
stage_temp_prefix (const WyctlPublicationPlan *plan)
{
  return g_strdup_printf (".%s.tmp-", plan->stage_basename);
}

static gchar *
stage_temp_basename (const WyctlPublicationPlan *plan)
{
  wyl_id_t nonce;
  gchar nonce_buf[WYL_ID_STRING_BUF];

  if (wyl_id_new (&nonce) != WYRELOG_E_OK
      || wyl_id_format (&nonce, nonce_buf, sizeof nonce_buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup_printf (".%s.tmp-%s", plan->stage_basename, nonce_buf);
}

static gboolean
cleanup_stage_temp_orphans (const WyctlPublicationWindowsBackend *backend,
    WyctlPublicationWindowsAnchor *anchor, const WyctlPublicationPlan *plan)
{
  g_autofree gchar *prefix = stage_temp_prefix (plan);
  g_autofree gchar *glob_basename = NULL;
  g_autofree gchar *pattern = NULL;
  g_autofree wchar_t *wpattern = NULL;
  WIN32_FIND_DATAW data = { 0 };
  HANDLE find = INVALID_HANDLE_VALUE;
  gboolean removed = FALSE;
  gboolean safe = TRUE;

  if (prefix == NULL)
    return FALSE;
  glob_basename = g_strconcat (prefix, "*", NULL);
  pattern = glob_basename != NULL ?
      g_build_filename (backend->root_dir, glob_basename, NULL) : NULL;
  if (pattern == NULL)
    return FALSE;
  wpattern = utf8_to_wide (pattern);
  if (wpattern == NULL)
    return FALSE;
  find = FindFirstFileW (wpattern, &data);
  if (find == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError ();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
  }
  do {
    g_autofree gchar *basename = g_utf16_to_utf8 ((const gunichar2 *)
        data.cFileName, -1, NULL, NULL, NULL);
    g_autofree gchar *path = NULL;
    const gchar *nonce_text;
    wyl_id_t nonce;
    HANDLE handle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info = { 0 };
    wchar_t *wpath;

    if (basename == NULL || !g_str_has_prefix (basename, prefix)) {
      safe = FALSE;
      break;
    }
    nonce_text = basename + strlen (prefix);
    if (wyl_id_parse (nonce_text, &nonce) != WYRELOG_E_OK) {
      safe = FALSE;
      break;
    }
    path = g_build_filename (backend->root_dir, basename, NULL);
    wpath = utf8_to_wide (path);
    if (wpath == NULL) {
      safe = FALSE;
      break;
    }
    handle = CreateFileW (wpath,
        GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    g_free (wpath);
    if (handle == INVALID_HANDLE_VALUE
        || !GetFileInformationByHandle (handle, &info)
        || !handle_is_owner_only_regular (handle, &info, FALSE)
        || delete_handle_exact (handle) != WYRELOG_E_OK) {
      if (handle != INVALID_HANDLE_VALUE)
        CloseHandle (handle);
      safe = FALSE;
      break;
    }
    CloseHandle (handle);
    removed = TRUE;
  } while (FindNextFileW (find, &data));
  if (safe && GetLastError () != ERROR_NO_MORE_FILES)
    safe = FALSE;
  FindClose (find);
  return safe && (!removed
      || directory_flush (anchor->dir_handle) == WYRELOG_E_OK);
}

static wyrelog_error_t
inspect_exact_stage (const WyctlPublicationWindowsBackend *backend,
    WyctlPublicationWindowsAnchor *anchor,
    const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_present)
{
  g_autofree gchar *stage_path = path_for_plan (backend, plan,
      plan->stage_basename);
  g_autofree gchar *identity = NULL;
  g_autofree wchar_t *wstage = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  gboolean empty = FALSE;
  gboolean matches = FALSE;
  wyrelog_error_t rc;

  *out_present = FALSE;
  if (stage_path == NULL)
    return WYRELOG_E_NOMEM;
  wstage = utf8_to_wide (stage_path);
  if (wstage == NULL)
    return WYRELOG_E_NOMEM;
  handle = CreateFileW (wstage,
      GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL,
      FILE_SHARE_READ, NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError ();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
      return WYRELOG_E_OK;
    *out_present = TRUE;
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  *out_present = TRUE;
  if (!GetFileInformationByHandle (handle, &info)
      || !handle_is_owner_only_regular (handle, &info, FALSE)
      || !FlushFileBuffers (handle)
      || directory_flush (anchor->dir_handle) != WYRELOG_E_OK
      || (identity = identity_from_info (&info)) == NULL) {
    CloseHandle (handle);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  rc = credential_document_matches_handle (handle, credential_id,
      credential_secret, &empty, &matches);
  CloseHandle (handle);
  if (rc != WYRELOG_E_OK || empty || !matches)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  if (rc != WYRELOG_E_OK)
    return rc;
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
}

wyrelog_error_t
wyctl_publication_windows_stage_exact (const WyctlPublicationWindowsBackend
    *backend, const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_replayed)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  HANDLE temp_handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  WinOwnerOnlySecurityAttributes sa = { 0 };
  gboolean empty = FALSE;
  gboolean matches = FALSE;
  gboolean cleanup_durable;
  gboolean present = FALSE;
  g_autofree gchar *temp_basename = NULL;
  g_autofree gchar *temp_path = NULL;
  g_autofree gchar *identity = NULL;
  wchar_t *wtemp = NULL;
  wyrelog_error_t rc;

  if (out_receipt == NULL || out_result == NULL || out_replayed == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_receipt_clear (out_receipt);
  wyctl_publication_result_clear (out_result);
  *out_replayed = FALSE;
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_expected_credential_is_valid (credential_id,
          credential_secret))
    return WYRELOG_E_INVALID;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!plan_matches_anchor (plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  if (!cleanup_stage_temp_orphans (backend, &anchor, plan)) {
    close_root_anchor (&anchor);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  rc = inspect_exact_stage (backend, &anchor, plan, credential_id,
      credential_secret, out_receipt, out_result, &present);
  if (rc != WYRELOG_E_OK || present) {
    close_root_anchor (&anchor);
    if (rc == WYRELOG_E_OK && out_result->kind ==
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE)
      *out_replayed = TRUE;
    return rc;
  }

  rc = win_owner_only_security_attributes_init (&sa);
  if (rc != WYRELOG_E_OK) {
    close_root_anchor (&anchor);
    return rc;
  }
  for (guint attempt = 0; attempt < 8
      && temp_handle == INVALID_HANDLE_VALUE; attempt++) {
    g_clear_pointer (&temp_basename, g_free);
    g_clear_pointer (&temp_path, g_free);
    temp_basename = stage_temp_basename (plan);
    temp_path = temp_basename != NULL ?
        g_build_filename (backend->root_dir, temp_basename, NULL) : NULL;
    if (temp_path == NULL) {
      win_owner_only_security_attributes_clear (&sa);
      close_root_anchor (&anchor);
      return WYRELOG_E_CRYPTO;
    }
    wtemp = utf8_to_wide (temp_path);
    if (wtemp == NULL) {
      win_owner_only_security_attributes_clear (&sa);
      close_root_anchor (&anchor);
      return WYRELOG_E_NOMEM;
    }
    temp_handle = CreateFileW (wtemp,
        GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL
        | DELETE, 0, &sa.attrs, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (temp_handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError ();
      g_free (wtemp);
      wtemp = NULL;
      if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) {
        win_owner_only_security_attributes_clear (&sa);
        close_root_anchor (&anchor);
        return map_win32_error (error);
      }
    }
  }
  g_free (wtemp);
  win_owner_only_security_attributes_clear (&sa);
  if (temp_handle == INVALID_HANDLE_VALUE) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  if (!GetFileInformationByHandle (temp_handle, &info)
      || !handle_is_owner_only_regular (temp_handle, &info, TRUE)) {
    rc = WYRELOG_E_POLICY;
    goto temp_failure;
  }
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_TEMP_CREATED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }
  {
    gchar *secret_copy = g_strndup (credential_secret->text,
        credential_secret->len);
    if (secret_copy == NULL) {
      rc = WYRELOG_E_NOMEM;
      goto temp_failure;
    }
    rc = write_credential_document_unsynced_to_handle (temp_handle,
        credential_id, secret_copy);
    sodium_memzero (secret_copy, credential_secret->len + 1);
    g_free (secret_copy);
    if (rc != WYRELOG_E_OK)
      goto temp_failure;
  }
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_DOCUMENT_WRITTEN)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }
  if (!FlushFileBuffers (temp_handle)) {
    rc = map_win32_error (GetLastError ());
    goto temp_failure;
  }
  switch (stage_exact_hook (backend, WYCTL_PUBLICATION_STAGE_EXACT_FILE_SYNCED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
      goto simulated_crash;
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      rc = WYRELOG_E_IO;
      goto temp_failure;
    default:
      break;
  }

  rc = rename_handle_to_destination (temp_handle, anchor.dir_handle,
      plan->stage_basename);
  if (rc != WYRELOG_E_OK) {
    cleanup_durable = cleanup_created_handle_durable (&temp_handle, &anchor);
    if (!cleanup_durable) {
      if (temp_handle != INVALID_HANDLE_VALUE)
        CloseHandle (temp_handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = inspect_exact_stage (backend, &anchor, plan, credential_id,
        credential_secret, out_receipt, out_result, &present);
    close_root_anchor (&anchor);
    if (rc == WYRELOG_E_OK && present && out_result->kind ==
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE)
      *out_replayed = TRUE;
    else if (rc == WYRELOG_E_OK && !present)
      windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    return rc;
  }
  switch (stage_exact_hook (backend, WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      goto simulated_crash;
    default:
      break;
  }
  if (directory_flush (anchor.dir_handle) != WYRELOG_E_OK)
    goto published_uncertain;
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_DIRECTORY_SYNCED)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      goto simulated_crash;
    default:
      break;
  }

  rc = credential_document_matches_handle (temp_handle, credential_id,
      credential_secret, &empty, &matches);
  if (rc != WYRELOG_E_OK || empty || !matches
      || !GetFileInformationByHandle (temp_handle, &info)
      || !handle_is_owner_only_regular (temp_handle, &info, FALSE))
    goto published_uncertain;
  identity = identity_from_info (&info);
  if (identity == NULL)
    goto published_uncertain;
  rc = wyctl_publication_receipt_create (plan, identity, out_receipt);
  if (rc != WYRELOG_E_OK)
    goto published_uncertain;
  switch (stage_exact_hook (backend,
          WYCTL_PUBLICATION_STAGE_EXACT_BEFORE_SUCCESS_RETURN)) {
    case WYCTL_PUBLICATION_STAGE_EXACT_CRASH:
    case WYCTL_PUBLICATION_STAGE_EXACT_FAIL:
      wyctl_publication_receipt_clear (out_receipt);
      goto simulated_crash;
    default:
      break;
  }
  CloseHandle (temp_handle);
  close_root_anchor (&anchor);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);

temp_failure:
  cleanup_durable = cleanup_created_handle_durable (&temp_handle, &anchor);
  if (temp_handle != INVALID_HANDLE_VALUE)
    CloseHandle (temp_handle);
  close_root_anchor (&anchor);
  if (!cleanup_durable) {
    wyctl_publication_receipt_clear (out_receipt);
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  }
  windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, FALSE, FALSE);
  return rc;

published_uncertain:
  wyctl_publication_receipt_clear (out_receipt);
  CloseHandle (temp_handle);
  close_root_anchor (&anchor);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);

simulated_crash:
  wyctl_publication_receipt_clear (out_receipt);
  CloseHandle (temp_handle);
  close_root_anchor (&anchor);
  windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
  return WYRELOG_E_IO;
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
  wyrelog_error_t rc = file_info_for_path (path,
      FILE_READ_ATTRIBUTES | GENERIC_READ | DELETE,
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
delete_handle_exact (HANDLE handle)
{
  FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE };

  if (handle == INVALID_HANDLE_VALUE || handle == NULL)
    return WYRELOG_E_INVALID;
  if (!SetFileInformationByHandle (handle, FileDispositionInfo, &disposition,
          sizeof disposition))
    return map_win32_error (GetLastError ());
  return WYRELOG_E_OK;
}

static wyrelog_error_t
rename_handle_to_destination (HANDLE stage_handle, HANDLE root_handle,
    const gchar *destination)
{
  wchar_t *wdestination = utf8_to_wide (destination);
  FILE_RENAME_INFO *rename_info;
  gsize name_bytes;
  gsize info_size;
  gboolean renamed;

  if (stage_handle == INVALID_HANDLE_VALUE || stage_handle == NULL
      || root_handle == INVALID_HANDLE_VALUE || root_handle == NULL) {
    g_free (wdestination);
    return WYRELOG_E_INVALID;
  }
  if (wdestination == NULL)
    return WYRELOG_E_NOMEM;
  name_bytes = wcslen (wdestination) * sizeof *wdestination;
  info_size = offsetof (FILE_RENAME_INFO, FileName) + name_bytes;
  rename_info = g_malloc0 (info_size);
  if (rename_info == NULL) {
    g_free (wdestination);
    return WYRELOG_E_NOMEM;
  }
  rename_info->ReplaceIfExists = FALSE;
  rename_info->RootDirectory = root_handle;
  rename_info->FileNameLength = (DWORD) name_bytes;
  memcpy (rename_info->FileName, wdestination, name_bytes);
  renamed = SetFileInformationByHandle (stage_handle, FileRenameInfo,
      rename_info, (DWORD) info_size);
  g_free (rename_info);
  g_free (wdestination);
  if (!renamed)
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
  backend->stage_exact_hook = NULL;
  backend->stage_exact_hook_data = NULL;
}

void wyctl_publication_windows_backend_clear
    (WyctlPublicationWindowsBackend * backend)
{
  if (backend == NULL)
    return;
  g_clear_pointer (&backend->root_dir, g_free);
  backend->stage_exact_hook = NULL;
  backend->stage_exact_hook_data = NULL;
}

void wyctl_publication_windows_backend_set_stage_exact_hook
    (WyctlPublicationWindowsBackend * backend,
    WyctlPublicationStageExactHook hook, gpointer data)
{
  if (backend == NULL)
    return;
  backend->stage_exact_hook = hook;
  backend->stage_exact_hook_data = data;
}

wyrelog_error_t
wyctl_publication_windows_plan (const WyctlPublicationWindowsBackend *backend,
    const WyctlPublicationPlan *request, WyctlPublicationPlan *out_plan)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *destination_path = NULL;
  DWORD error = 0;
  wyrelog_error_t rc;

  if (out_plan == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_plan_clear (out_plan);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (request))
    return WYRELOG_E_INVALID;

  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;

  destination_path = path_for_plan (backend, request, request->destination);
  if (destination_path == NULL) {
    close_root_anchor (&anchor);
    return WYRELOG_E_NOMEM;
  }
  if (wide_path_exists (destination_path, NULL, &error)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND
      && error != 0) {
    close_root_anchor (&anchor);
    return map_win32_error (error);
  }
  rc = wyctl_publication_plan_clone (request, out_plan);
  if (rc == WYRELOG_E_OK) {
    g_free (out_plan->parent_identity);
    out_plan->parent_identity = identity_from_info (&anchor.dir_info);
    if (out_plan->parent_identity == NULL) {
      wyctl_publication_plan_clear (out_plan);
      rc = WYRELOG_E_NOMEM;
    }
  }
  close_root_anchor (&anchor);
  return rc;
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
  if (!plan_matches_anchor (plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
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
    delete_handle_exact (stage_handle);
    CloseHandle (stage_handle);
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  {
    DWORD sec_len = 0;
    PSECURITY_DESCRIPTOR sec = NULL;
    if (!GetKernelObjectSecurity (stage_handle,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0,
            &sec_len) && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
      delete_handle_exact (stage_handle);
      CloseHandle (stage_handle);
      close_root_anchor (&anchor);
      return WYRELOG_E_POLICY;
    }
    sec = g_malloc0 (sec_len);
    if (sec == NULL) {
      delete_handle_exact (stage_handle);
      CloseHandle (stage_handle);
      close_root_anchor (&anchor);
      return WYRELOG_E_NOMEM;
    }
    if (!GetKernelObjectSecurity (stage_handle,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sec,
            sec_len, &sec_len) || !security_descriptor_is_owner_only (sec)) {
      g_free (sec);
      delete_handle_exact (stage_handle);
      CloseHandle (stage_handle);
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
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = file_info_for_path (stage_path, FILE_READ_ATTRIBUTES | GENERIC_READ
      | GENERIC_WRITE | DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
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
  rc = rename_handle_to_destination (stage_handle, anchor.dir_handle,
      plan->destination);
  CloseHandle (stage_handle);
  stage_handle = INVALID_HANDLE_VALUE;
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
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  DWORD attrs = 0;
  DWORD error = 0;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  HANDLE handle = INVALID_HANDLE_VALUE;
  gboolean empty = FALSE;
  gboolean matches = FALSE;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }
  close_root_anchor (&anchor);

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
      rc = credential_document_matches_handle (handle,
          expected_credential_id, expected_credential_secret, &empty, &matches);
      CloseHandle (handle);
      if (rc != WYRELOG_E_OK)
        return rc;
      if (matches)
        return windows_result_fill (out_result,
            WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE, TRUE, FALSE);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    if (rc == WYRELOG_E_OK)
      CloseHandle (handle);
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
  rc = credential_document_matches_handle (handle, expected_credential_id,
      expected_credential_secret, &empty, &matches);
  CloseHandle (handle);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (empty)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
  if (matches)
    return windows_result_fill (out_result,
        WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
  return windows_result_fill (out_result,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
}

wyrelog_error_t
    wyctl_publication_windows_resync
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  gboolean empty = FALSE;
  gboolean matches = FALSE;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = file_identity_for_path (destination_path, TRUE, NULL, &handle, &info);
  if (rc == WYRELOG_E_OK) {
    if (!identity_matches_info (receipt->stage_identity, &info)) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = credential_document_matches_handle (handle, expected_credential_id,
        expected_credential_secret, &empty, &matches);
    CloseHandle (handle);
    close_root_anchor (&anchor);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!matches)
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
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
    rc = credential_document_matches_handle (handle, expected_credential_id,
        expected_credential_secret, &empty, &matches);
    if (rc != WYRELOG_E_OK) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return rc;
    }
    if (empty) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED, TRUE, TRUE);
    }
    if (!matches) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = rename_handle_to_destination (handle, anchor.dir_handle,
        plan->destination);
    CloseHandle (handle);
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
  return rc;
}

wyrelog_error_t
    wyctl_publication_windows_cleanup
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationWindowsAnchor anchor = { 0 };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  HANDLE handle = INVALID_HANDLE_VALUE;
  BY_HANDLE_FILE_INFORMATION info = { 0 };
  gboolean empty = FALSE;
  gboolean matches = FALSE;
  wyrelog_error_t rc;

  if (out_result == NULL)
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);
  if (!backend_is_valid (backend) || !wyctl_publication_plan_is_valid (plan)
      || !wyctl_publication_receipt_is_valid (receipt)
      || !wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret))
    return WYRELOG_E_INVALID;

  stage_path = path_for_plan (backend, plan, plan->stage_basename);
  destination_path = path_for_plan (backend, plan, plan->destination);
  if (stage_path == NULL || destination_path == NULL)
    return WYRELOG_E_NOMEM;
  rc = open_root_anchor (backend, &anchor);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!receipt_matches_plan_anchor (receipt, plan, &anchor)) {
    close_root_anchor (&anchor);
    return WYRELOG_E_POLICY;
  }

  rc = file_identity_for_path (stage_path, TRUE, NULL, &handle, &info);
  if (rc == WYRELOG_E_OK && identity_matches_info (receipt->stage_identity,
          &info)) {
    rc = credential_document_matches_handle (handle, expected_credential_id,
        expected_credential_secret, &empty, &matches);
    if (rc != WYRELOG_E_OK) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return rc;
    }
    if (empty || !matches) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = delete_handle_exact (handle);
    CloseHandle (handle);
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
    if (!identity_matches_info (receipt->stage_identity, &info)) {
      CloseHandle (handle);
      close_root_anchor (&anchor);
      return windows_result_fill (out_result,
          WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN, FALSE, FALSE);
    }
    rc = credential_document_matches_handle (handle, expected_credential_id,
        expected_credential_secret, &empty, &matches);
    CloseHandle (handle);
    if (rc != WYRELOG_E_OK) {
      close_root_anchor (&anchor);
      return rc;
    }
    if (empty || !matches) {
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

void wyctl_publication_windows_backend_set_stage_exact_hook
    (WyctlPublicationWindowsBackend * backend,
    WyctlPublicationStageExactHook hook, gpointer data)
{
  (void) backend;
  (void) hook;
  (void) data;
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
wyctl_publication_windows_stage_exact (const WyctlPublicationWindowsBackend
    *backend, const WyctlPublicationPlan *plan, const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    WyctlPublicationReceipt *out_receipt,
    WyctlPublicationResult *out_result, gboolean *out_replayed)
{
  (void) backend;
  (void) plan;
  (void) credential_id;
  (void) credential_secret;
  (void) out_receipt;
  (void) out_result;
  (void) out_replayed;
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
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) expected_credential_id;
  (void) expected_credential_secret;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_resync
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) expected_credential_id;
  (void) expected_credential_secret;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

wyrelog_error_t
    wyctl_publication_windows_cleanup
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result)
{
  (void) backend;
  (void) plan;
  (void) receipt;
  (void) expected_credential_id;
  (void) expected_credential_secret;
  (void) out_result;
  return WYRELOG_E_INVALID;
}

#endif
