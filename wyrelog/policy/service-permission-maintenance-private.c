/* SPDX-License-Identifier: GPL-3.0-or-later */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__unix__) || defined(__APPLE__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#endif

#include "service-permission-maintenance-private.h"

#include <chronoid/ksuid.h>
#include <sodium.h>
#include <string.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-id-private.h"

#ifdef G_OS_WIN32
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

struct WylServicePermissionReceiptReservation
{
  gchar *path;
  gboolean fail_finalize_once;
  gboolean created;
  void (*before_abort_close_hook) (gpointer data);
  gpointer before_abort_close_data;
#ifdef G_OS_WIN32
  HANDLE file;
  wchar_t *wide_path;
#else
  int dirfd;
  int fd;
  gchar *basename;
  gchar *parent_path;
  dev_t parent_dev;
  ino_t parent_ino;
  dev_t target_dev;
  ino_t target_ino;
#endif
};

static gboolean
request_id_is_canonical (const gchar *value)
{
  chronoid_ksuid_t parsed;
  gchar canonical[CHRONOID_KSUID_STRING_LEN + 1];
  if (value == NULL || strlen (value) != CHRONOID_KSUID_STRING_LEN
      || chronoid_ksuid_parse (&parsed, value, CHRONOID_KSUID_STRING_LEN)
      != CHRONOID_KSUID_OK)
    return FALSE;
  chronoid_ksuid_format (&parsed, canonical);
  return memcmp (value, canonical, CHRONOID_KSUID_STRING_LEN) == 0;
}

static gboolean
field_is_valid (const gchar *value)
{
  return value != NULL && value[0] != '\0' && strlen (value) <= 1024
      && g_utf8_validate (value, -1, NULL);
}

static WylPolicyPermissionClosureRemoval *
removal_copy (const WylPolicyPermissionClosureRemoval *source)
{
  WylPolicyPermissionClosureRemoval *copy =
      g_try_new0 (WylPolicyPermissionClosureRemoval, 1);
  if (copy == NULL)
    return NULL;
  copy->action = source->action;
  copy->reason = source->reason;
  copy->subject_id = g_strdup (source->subject_id);
  copy->right_id = g_strdup (source->right_id);
  copy->scope = g_strdup (source->scope);
  if (copy->subject_id == NULL || copy->right_id == NULL || copy->scope == NULL) {
    wyl_policy_permission_closure_removal_free (copy);
    return NULL;
  }
  return copy;
}

void
wyl_service_permission_manifest_clear (WylServicePermissionManifest *manifest)
{
  if (manifest == NULL)
    return;
  g_free (manifest->request_id);
  g_clear_pointer (&manifest->operations, g_ptr_array_unref);
  memset (manifest, 0, sizeof *manifest);
}

wyrelog_error_t
    wyl_service_permission_manifest_from_analysis
    (const WylPolicyPermissionClosureAnalysis * analysis,
    const gchar * request_id, WylServicePermissionManifest * out_manifest)
{
  if (analysis == NULL || analysis->removals == NULL
      || analysis->removals->len == 0
      || analysis->removals->len >
      WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_OPERATIONS
      || !request_id_is_canonical (request_id) || out_manifest == NULL)
    return WYRELOG_E_INVALID;
  memset (out_manifest, 0, sizeof *out_manifest);
  out_manifest->version = 1;
  out_manifest->request_id = g_strdup (request_id);
  out_manifest->store_generation = analysis->generation;
  memcpy (out_manifest->store_digest, analysis->digest, 32);
  out_manifest->operations = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  for (guint i = 0; i < analysis->removals->len; i++) {
    WylPolicyPermissionClosureRemoval *copy =
        removal_copy (g_ptr_array_index (analysis->removals, i));
    if (copy == NULL) {
      wyl_service_permission_manifest_clear (out_manifest);
      return WYRELOG_E_NOMEM;
    }
    g_ptr_array_add (out_manifest->operations, copy);
  }
  return WYRELOG_E_OK;
}

static void
append_json_string (GString *out, const gchar *value)
{
  g_string_append_c (out, '"');
  for (const guchar * p = (const guchar *)value; *p != '\0'; p++) {
    if (*p == '"' || *p == '\\')
      g_string_append_c (out, '\\');
    if (*p < 0x20)
      g_string_append_printf (out, "\\u%04x", *p);
    else
      g_string_append_c (out, *p);
  }
  g_string_append_c (out, '"');
}

static gboolean
manifest_shape_valid (const WylServicePermissionManifest *manifest)
{
  if (manifest == NULL || manifest->version != 1
      || !request_id_is_canonical (manifest->request_id)
      || manifest->store_generation == 0 || manifest->operations == NULL
      || manifest->operations->len == 0
      || manifest->operations->len >
      WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_OPERATIONS)
    return FALSE;
  guint8 digest_nonzero = 0;
  for (guint i = 0; i < 32; i++)
    digest_nonzero |= manifest->store_digest[i];
  if (digest_nonzero == 0)
    return FALSE;
  for (guint i = 0; i < manifest->operations->len; i++) {
    const WylPolicyPermissionClosureRemoval *operation =
        g_ptr_array_index (manifest->operations, i);
    if (operation == NULL
        || operation->action >
        WYL_POLICY_PERMISSION_CLOSURE_REMOVE_MEMBERSHIP
        || !field_is_valid (operation->subject_id)
        || !g_str_has_prefix (operation->subject_id, "svc:")
        || !field_is_valid (operation->right_id)
        || !field_is_valid (operation->scope))
      return FALSE;
    if (i > 0) {
      const WylPolicyPermissionClosureRemoval *previous =
          g_ptr_array_index (manifest->operations, i - 1);
      gint order = previous->action == operation->action ? 0 :
          previous->action < operation->action ? -1 : 1;
      if (order == 0)
        order = strcmp (previous->subject_id, operation->subject_id);
      if (order == 0)
        order = strcmp (previous->right_id, operation->right_id);
      if (order == 0)
        order = strcmp (previous->scope, operation->scope);
      if (order >= 0)
        return FALSE;
    }
  }
  return TRUE;
}

wyrelog_error_t
    wyl_service_permission_manifest_encode
    (const WylServicePermissionManifest * manifest, gchar ** out_document,
    gsize * out_len)
{
  if (out_document == NULL || out_len == NULL)
    return WYRELOG_E_INVALID;
  *out_document = NULL;
  *out_len = 0;
  if (!manifest_shape_valid (manifest))
    return WYRELOG_E_INVALID;
  gchar digest_hex[65];
  for (guint i = 0; i < 32; i++)
    g_snprintf (digest_hex + i * 2, 3, "%02x", manifest->store_digest[i]);
  GString *out = g_string_sized_new (512);
  g_string_append (out, "{\"version\":1,\"request_id\":");
  append_json_string (out, manifest->request_id);
  g_string_append_printf (out, ",\"store_generation\":%" G_GUINT64_FORMAT
      ",\"store_digest\":\"%s\",\"operations\":[",
      manifest->store_generation, digest_hex);
  for (guint i = 0; i < manifest->operations->len; i++) {
    const WylPolicyPermissionClosureRemoval *operation =
        g_ptr_array_index (manifest->operations, i);
    if (i > 0)
      g_string_append_c (out, ',');
    g_string_append (out, "{\"action\":\"");
    g_string_append (out, operation->action ==
        WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT ?
        "revoke_direct_permission\",\"subject_id\":" :
        "remove_service_role_membership\",\"subject_id\":");
    append_json_string (out, operation->subject_id);
    g_string_append (out, operation->action ==
        WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT ?
        ",\"permission_id\":" : ",\"role_id\":");
    append_json_string (out, operation->right_id);
    g_string_append (out, ",\"scope\":");
    append_json_string (out, operation->scope);
    g_string_append_c (out, '}');
  }
  g_string_append (out, "]}\n");
  if (out->len > WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES) {
    g_string_free (out, TRUE);
    return WYRELOG_E_INVALID;
  }
  *out_len = out->len;
  *out_document = g_string_free (out, FALSE);
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *p;
  const gchar *end;
} Cursor;

static gboolean
take (Cursor *cursor, const gchar *literal)
{
  gsize len = strlen (literal);
  if ((gsize) (cursor->end - cursor->p) < len
      || memcmp (cursor->p, literal, len) != 0)
    return FALSE;
  cursor->p += len;
  return TRUE;
}

static gboolean
parse_json_string (Cursor *cursor, gchar **out)
{
  *out = NULL;
  if (cursor->p == cursor->end || *cursor->p++ != '"')
    return FALSE;
  GString *value = g_string_sized_new (32);
  while (cursor->p < cursor->end && *cursor->p != '"') {
    guchar ch = *cursor->p++;
    if (ch < 0x20) {
      g_string_free (value, TRUE);
      return FALSE;
    }
    if (ch == '\\') {
      if (cursor->p == cursor->end) {
        g_string_free (value, TRUE);
        return FALSE;
      }
      ch = *cursor->p++;
      if (ch == '"' || ch == '\\')
        g_string_append_c (value, ch);
      else if (ch == 'u' && cursor->end - cursor->p >= 4
          && cursor->p[0] == '0' && cursor->p[1] == '0'
          && g_ascii_isxdigit (cursor->p[2])
          && g_ascii_isxdigit (cursor->p[3])) {
        gint hi = g_ascii_xdigit_value (cursor->p[2]);
        gint lo = g_ascii_xdigit_value (cursor->p[3]);
        ch = (guchar) ((hi << 4) | lo);
        cursor->p += 4;
        if (ch >= 0x20)
          g_string_append_c (value, ch);
        else
          g_string_append_c (value, ch);
      } else {
        g_string_free (value, TRUE);
        return FALSE;
      }
    } else {
      g_string_append_c (value, ch);
    }
  }
  if (cursor->p == cursor->end || *cursor->p++ != '"'
      || !g_utf8_validate (value->str, value->len, NULL)
      || value->len == 0 || value->len > 1024) {
    g_string_free (value, TRUE);
    return FALSE;
  }
  *out = g_string_free (value, FALSE);
  return TRUE;
}

static gboolean
parse_u64 (Cursor *cursor, guint64 *out)
{
  if (cursor->p == cursor->end || *cursor->p < '1' || *cursor->p > '9')
    return FALSE;
  guint64 value = 0;
  do {
    guint digit = (guint) (*cursor->p - '0');
    if (value > (G_MAXUINT64 - digit) / 10)
      return FALSE;
    value = value * 10 + digit;
    cursor->p++;
  } while (cursor->p < cursor->end && *cursor->p >= '0' && *cursor->p <= '9');
  *out = value;
  return TRUE;
}

wyrelog_error_t
    wyl_service_permission_manifest_decode
    (const gchar * document, gsize len,
    WylServicePermissionManifest * out_manifest)
{
  if (document == NULL || len == 0
      || len > WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES
      || out_manifest == NULL || memchr (document, '\0', len) != NULL
      || !g_utf8_validate (document, len, NULL))
    return WYRELOG_E_INVALID;
  memset (out_manifest, 0, sizeof *out_manifest);
  g_autofree gchar *canonical = NULL;
  gsize canonical_len = 0;
  Cursor cursor = {
    document, document + len
  };
  if (!take (&cursor, "{\"version\":1,\"request_id\":")
      || !parse_json_string (&cursor, &out_manifest->request_id)
      || !take (&cursor, ",\"store_generation\":")
      || !parse_u64 (&cursor, &out_manifest->store_generation)
      || !take (&cursor, ",\"store_digest\":\"")
      || cursor.end - cursor.p < 65)
    goto invalid;
  for (guint i = 0; i < 32; i++) {
    gint hi = g_ascii_xdigit_value (cursor.p[i * 2]);
    gint lo = g_ascii_xdigit_value (cursor.p[i * 2 + 1]);
    if (hi < 0 || lo < 0 || g_ascii_isupper (cursor.p[i * 2])
        || g_ascii_isupper (cursor.p[i * 2 + 1]))
      goto invalid;
    out_manifest->store_digest[i] = (guint8) ((hi << 4) | lo);
  }
  cursor.p += 64;
  if (!take (&cursor, "\",\"operations\":["))
    goto invalid;
  out_manifest->version = 1;
  out_manifest->operations = g_ptr_array_new_with_free_func
      ((GDestroyNotify) wyl_policy_permission_closure_removal_free);
  do {
    if (out_manifest->operations->len >=
        WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_OPERATIONS
        || !take (&cursor, "{\"action\":\""))
      goto invalid;
    WylPolicyPermissionClosureRemoval *operation =
        g_try_new0 (WylPolicyPermissionClosureRemoval, 1);
    if (operation == NULL) {
      wyl_service_permission_manifest_clear (out_manifest);
      return WYRELOG_E_NOMEM;
    }
    if (take (&cursor, "revoke_direct_permission\",\"subject_id\":"))
      operation->action = WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT;
    else if (take (&cursor, "remove_service_role_membership\",\"subject_id\":"))
      operation->action = WYL_POLICY_PERMISSION_CLOSURE_REMOVE_MEMBERSHIP;
    else {
      wyl_policy_permission_closure_removal_free (operation);
      goto invalid;
    }
    if (!parse_json_string (&cursor, &operation->subject_id)
        || !take (&cursor, operation->action ==
            WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT ?
            ",\"permission_id\":" : ",\"role_id\":")
        || !parse_json_string (&cursor, &operation->right_id)
        || !take (&cursor, ",\"scope\":")
        || !parse_json_string (&cursor, &operation->scope)
        || !take (&cursor, "}")) {
      wyl_policy_permission_closure_removal_free (operation);
      goto invalid;
    }
    g_ptr_array_add (out_manifest->operations, operation);
    if (take (&cursor, ","))
      continue;
    break;
  } while (TRUE);
  if (!take (&cursor, "]}\n") || cursor.p != cursor.end
      || !manifest_shape_valid (out_manifest))
    goto invalid;
  if (wyl_service_permission_manifest_encode (out_manifest, &canonical,
          &canonical_len) != WYRELOG_E_OK || canonical_len != len
      || memcmp (canonical, document, len) != 0)
    goto invalid;
  return WYRELOG_E_OK;

invalid:
  wyl_service_permission_manifest_clear (out_manifest);
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
    wyl_service_permission_manifest_matches_analysis
    (const WylServicePermissionManifest * manifest,
    const WylPolicyPermissionClosureAnalysis * analysis)
{
  if (!manifest_shape_valid (manifest) || analysis == NULL
      || analysis->removals == NULL)
    return WYRELOG_E_INVALID;
  if (manifest->store_generation != analysis->generation
      || memcmp (manifest->store_digest, analysis->digest, 32) != 0
      || manifest->operations->len != analysis->removals->len)
    return WYRELOG_E_POLICY;
  for (guint i = 0; i < manifest->operations->len; i++) {
    const WylPolicyPermissionClosureRemoval *actual =
        g_ptr_array_index (manifest->operations, i);
    const WylPolicyPermissionClosureRemoval *expected =
        g_ptr_array_index (analysis->removals, i);
    if (actual->action != expected->action
        || g_strcmp0 (actual->subject_id, expected->subject_id) != 0
        || g_strcmp0 (actual->right_id, expected->right_id) != 0
        || g_strcmp0 (actual->scope, expected->scope) != 0)
      return WYRELOG_E_POLICY;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
write_new_owner_only_document (const gchar *path, const gchar *document,
    gsize len)
{
  if (path == NULL || path[0] == '\0' || document == NULL || len == 0)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef G_OS_WIN32
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  LPWSTR sid_text = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  wchar_t *wide_path = NULL;
  wchar_t *sddl = NULL;
  HANDLE file = INVALID_HANDLE_VALUE;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    goto win_io;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto win_io;
  user = g_malloc (needed);
  if (user == NULL || !GetTokenInformation (token, TokenUser, user, needed,
          &needed) || !ConvertSidToStringSidW (user->User.Sid, &sid_text))
    goto win_io;
  gsize sid_len = wcslen (sid_text);
  sddl = g_new (wchar_t, 32 + sid_len * 2);
  if (sddl == NULL
      || swprintf (sddl, 32 + sid_len * 2, L"O:%lsD:P(A;;FA;;;%ls)",
          sid_text, sid_text) < 0
      || !ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl,
          SDDL_REVISION_1, &descriptor, NULL))
    goto win_io;
  SECURITY_ATTRIBUTES attrs = {
    sizeof attrs, descriptor, FALSE
  };
  wide_path = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wide_path == NULL)
    goto win_invalid;
  file = CreateFileW (wide_path, GENERIC_WRITE, 0, &attrs, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    rc = GetLastError () == ERROR_FILE_EXISTS
        || GetLastError () == ERROR_ALREADY_EXISTS ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto win_out;
  }
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (file, &info)
      || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
              | FILE_ATTRIBUTE_DIRECTORY)) || info.nNumberOfLinks != 1) {
    rc = WYRELOG_E_POLICY;
    goto win_cleanup;
  }
  gsize total = 0;
  while (total < len) {
    DWORD chunk = len - total > 0x10000 ? 0x10000 : (DWORD) (len - total);
    DWORD written = 0;
    if (!WriteFile (file, document + total, chunk, &written, NULL)
        || written == 0) {
      rc = WYRELOG_E_IO;
      goto win_cleanup;
    }
    total += written;
  }
  if (!FlushFileBuffers (file)) {
    rc = WYRELOG_E_IO;
    goto win_cleanup;
  }
  rc = WYRELOG_E_OK;
  goto win_out;

win_invalid:
  rc = WYRELOG_E_INVALID;
  goto win_out;
win_io:
  rc = WYRELOG_E_IO;
  goto win_out;
win_cleanup:
  CloseHandle (file);
  file = INVALID_HANDLE_VALUE;
  if (wide_path != NULL)
    (void) DeleteFileW (wide_path);
win_out:
  if (file != INVALID_HANDLE_VALUE)
    CloseHandle (file);
  g_free (wide_path);
  g_free (sddl);
  if (descriptor != NULL)
    LocalFree (descriptor);
  if (sid_text != NULL)
    LocalFree (sid_text);
  g_free (user);
  if (token != NULL)
    CloseHandle (token);
  return rc;
#else
  g_autofree gchar *absolute = g_canonicalize_filename (path, NULL);
  g_autofree gchar *parent = g_path_get_dirname (absolute);
  g_autofree gchar *basename = g_path_get_basename (absolute);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL)
    return errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
  int dirfd = open (resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  g_free (resolved_parent);
  if (dirfd < 0)
    return WYRELOG_E_IO;
  struct stat parent_stat;
  if (fstat (dirfd, &parent_stat) != 0 || !S_ISDIR (parent_stat.st_mode)
      || parent_stat.st_uid != geteuid ()
      || (parent_stat.st_mode & 0077) != 0) {
    close (dirfd);
    return WYRELOG_E_POLICY;
  }
  int fd = openat (dirfd, basename,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    int open_errno = errno;
    close (dirfd);
    return open_errno == EEXIST || open_errno == ELOOP ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  struct stat file_stat;
  if (fstat (fd, &file_stat) != 0 || !S_ISREG (file_stat.st_mode)
      || file_stat.st_nlink != 1 || file_stat.st_uid != geteuid ()
      || (file_stat.st_mode & 0077) != 0)
    rc = WYRELOG_E_POLICY;
  gsize total = 0;
  while (rc == WYRELOG_E_OK && total < len) {
    ssize_t written = write (fd, document + total, len - total);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      rc = WYRELOG_E_IO;
    else
      total += (gsize) written;
  }
  if (rc == WYRELOG_E_OK && fsync (fd) != 0)
    rc = WYRELOG_E_IO;
  if (close (fd) != 0 && rc == WYRELOG_E_OK)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK && fsync (dirfd) != 0)
    rc = WYRELOG_E_IO;
  if (rc != WYRELOG_E_OK)
    (void) unlinkat (dirfd, basename, 0);
  close (dirfd);
  return rc;
#endif
}

wyrelog_error_t
    wyl_service_permission_manifest_write_new_owner_only
    (const gchar * path, const WylServicePermissionManifest * manifest)
{
  g_autofree gchar *document = NULL;
  gsize len = 0;
  wyrelog_error_t rc =
      wyl_service_permission_manifest_encode (manifest, &document, &len);
  return rc == WYRELOG_E_OK ?
      write_new_owner_only_document (path, document, len) : rc;
}

wyrelog_error_t
wyl_service_permission_manifest_read_owner_only (const gchar *path,
    WylServicePermissionManifest *out_manifest)
{
  if (path == NULL || path[0] == '\0' || out_manifest == NULL)
    return WYRELOG_E_INVALID;
  memset (out_manifest, 0, sizeof *out_manifest);
  gchar *document = g_malloc (WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES + 1);
  if (document == NULL)
    return WYRELOG_E_NOMEM;
  gsize len = 0;
  wyrelog_error_t rc = WYRELOG_E_OK;
#ifdef G_OS_WIN32
  g_autofree wchar_t *wide_path =
      (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wide_path == NULL) {
    rc = WYRELOG_E_INVALID;
    goto out;
  }
  HANDLE file =
      CreateFileW (wide_path, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
      NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    rc = GetLastError () == ERROR_FILE_NOT_FOUND ? WYRELOG_E_NOT_FOUND :
        WYRELOG_E_IO;
    goto out;
  }
  BY_HANDLE_FILE_INFORMATION info;
  PSID owner = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  if (!GetFileInformationByHandle (file, &info)
      || (info.dwFileAttributes &
          (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
      || info.nNumberOfLinks != 1
      || GetSecurityInfo (file, SE_FILE_OBJECT,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
          &owner, NULL, &dacl, NULL, &descriptor) != ERROR_SUCCESS
      || !OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token)) {
    rc = WYRELOG_E_POLICY;
    goto win_out;
  }
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
    rc = WYRELOG_E_POLICY;
    goto win_out;
  }
  user = g_malloc (needed);
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION acl_info = { 0 };
  LPVOID ace = NULL;
  if (user == NULL
      || !GetTokenInformation (token, TokenUser, user, needed, &needed)
      || !EqualSid (owner, user->User.Sid)
      || !GetSecurityDescriptorControl (descriptor, &control, &revision)
      || (control & SE_DACL_PROTECTED) == 0 || dacl == NULL
      || !GetAclInformation (dacl, &acl_info, sizeof acl_info,
          AclSizeInformation) || acl_info.AceCount != 1
      || !GetAce (dacl, 0, &ace)
      || ((ACE_HEADER *) ace)->AceType != ACCESS_ALLOWED_ACE_TYPE
      || !EqualSid (&((ACCESS_ALLOWED_ACE *) ace)->SidStart, owner)) {
    rc = WYRELOG_E_POLICY;
    goto win_out;
  }
  while (len <= WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES) {
    DWORD got = 0;
    DWORD capacity = (DWORD) MIN ((gsize) 0x10000,
        WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES + 1 - len);
    if (!ReadFile (file, document + len, capacity, &got, NULL)) {
      rc = WYRELOG_E_IO;
      goto win_out;
    }
    if (got == 0)
      break;
    len += got;
  }
win_out:
  g_free (user);
  if (token != NULL)
    CloseHandle (token);
  if (descriptor != NULL)
    LocalFree (descriptor);
  CloseHandle (file);
#else
  g_autofree gchar *absolute = g_canonicalize_filename (path, NULL);
  g_autofree gchar *parent = g_path_get_dirname (absolute);
  g_autofree gchar *basename = g_path_get_basename (absolute);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL) {
    rc = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
    goto out;
  }
  int dirfd = open (resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  g_free (resolved_parent);
  if (dirfd < 0) {
    rc = WYRELOG_E_IO;
    goto out;
  }
  struct stat parent_stat;
  if (fstat (dirfd, &parent_stat) != 0 || !S_ISDIR (parent_stat.st_mode)
      || parent_stat.st_uid != geteuid ()
      || (parent_stat.st_mode & 0077) != 0) {
    close (dirfd);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  int fd = openat (dirfd, basename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  close (dirfd);
  if (fd < 0) {
    rc = errno == ENOENT ? WYRELOG_E_NOT_FOUND :
        errno == ELOOP ? WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto out;
  }
  struct stat file_stat;
  if (fstat (fd, &file_stat) != 0 || !S_ISREG (file_stat.st_mode)
      || file_stat.st_nlink != 1 || file_stat.st_uid != geteuid ()
      || (file_stat.st_mode & 0077) != 0) {
    close (fd);
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  while (len <= WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES) {
    ssize_t got = read (fd, document + len,
        WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES + 1 - len);
    if (got < 0 && errno == EINTR)
      continue;
    if (got < 0) {
      rc = WYRELOG_E_IO;
      break;
    }
    if (got == 0)
      break;
    len += (gsize) got;
  }
  close (fd);
#endif
  if (rc == WYRELOG_E_OK
      && (len == 0 || len > WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_permission_manifest_decode (document, len, out_manifest);
out:
  sodium_memzero (document, WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES + 1);
  g_free (document);
  return rc;
}

wyrelog_error_t
wyl_service_permission_maintenance_dry_run (wyl_policy_store_t *store,
    const WylServicePermissionManifest *manifest)
{
  if (store == NULL || manifest == NULL)
    return WYRELOG_E_INVALID;
  WylPolicyPermissionClosureAnalysis analysis = {
    0
  };
  wyrelog_error_t rc =
      wyl_policy_store_analyze_service_permission_closure (store, &analysis);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_permission_manifest_matches_analysis (manifest, &analysis);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_dry_run_service_permission_closure (store,
        manifest->operations);
  wyl_policy_permission_closure_analysis_clear (&analysis);
  return rc;
}

#define REMEDIATION_RECEIPT_ACTION \
  "service.permission_closure.remediation_receipt"
#define REMEDIATION_OPERATION_ACTION \
  "service.permission_closure.remediation_operation"
#define REMEDIATION_MUTATION_ACTION \
  "service.permission_closure.remediate"
#define REMEDIATION_RECEIPT_UPDATE_TRIGGER \
  "trg_service_permission_remediation_receipt_no_update"
#define REMEDIATION_RECEIPT_DELETE_TRIGGER \
  "trg_service_permission_remediation_receipt_no_delete"

void wyl_service_permission_apply_receipt_clear
    (WylServicePermissionApplyReceipt * receipt)
{
  if (receipt == NULL)
    return;
  g_free (receipt->request_id);
  g_free (receipt->actor_identity);
  g_free (receipt->audit_id);
  memset (receipt, 0, sizeof *receipt);
}

static wyrelog_error_t
manifest_fingerprint (const WylServicePermissionManifest *manifest,
    gchar out_hex[65])
{
  g_autofree gchar *document = NULL;
  gsize len = 0;
  wyrelog_error_t rc =
      wyl_service_permission_manifest_encode (manifest, &document, &len);
  guint8 digest[32];
  if (rc == WYRELOG_E_OK
      && crypto_generichash (digest, sizeof digest,
          (const guint8 *) document, len, NULL, 0) != 0)
    rc = WYRELOG_E_CRYPTO;
  if (rc == WYRELOG_E_OK) {
    for (guint i = 0; i < sizeof digest; i++)
      g_snprintf (out_hex + i * 2, 3, "%02x", digest[i]);
  }
  sodium_memzero (digest, sizeof digest);
  return rc;
}

static void
digest_to_hex (const guint8 digest[32], gchar out_hex[65])
{
  for (guint i = 0; i < 32; i++)
    g_snprintf (out_hex + i * 2, 3, "%02x", digest[i]);
}

static gboolean
hex_to_digest (const gchar *hex, guint8 out_digest[32])
{
  if (hex == NULL || strlen (hex) != 64)
    return FALSE;
  for (guint i = 0; i < 32; i++) {
    gint high = g_ascii_xdigit_value (hex[i * 2]);
    gint low = g_ascii_xdigit_value (hex[i * 2 + 1]);
    if (high < 0 || low < 0 || g_ascii_isupper (hex[i * 2])
        || g_ascii_isupper (hex[i * 2 + 1]))
      return FALSE;
    out_digest[i] = (guint8) ((high << 4) | low);
  }
  return TRUE;
}

static wyrelog_error_t
operation_fingerprint (const WylPolicyPermissionClosureRemoval *operation,
    gchar out_hex[65])
{
  g_autofree gchar *canonical = g_strdup_printf ("%u\n%s\n%s\n%s\n",
      operation->action, operation->subject_id, operation->right_id,
      operation->scope);
  guint8 digest[32];
  if (canonical == NULL)
    return WYRELOG_E_NOMEM;
  if (crypto_generichash (digest, sizeof digest,
          (const guint8 *) canonical, strlen (canonical), NULL, 0) != 0)
    return WYRELOG_E_CRYPTO;
  digest_to_hex (digest, out_hex);
  sodium_memzero (digest, sizeof digest);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
maintenance_actor_identity (gchar **out_actor)
{
  *out_actor = NULL;
#ifdef G_OS_WIN32
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return WYRELOG_E_IO;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
    CloseHandle (token);
    return WYRELOG_E_IO;
  }
  user = g_malloc (needed);
  if (user == NULL || !GetTokenInformation (token, TokenUser, user, needed,
          &needed)) {
    g_free (user);
    CloseHandle (token);
    return WYRELOG_E_IO;
  }
  DWORD sid_len = GetLengthSid (user->User.Sid);
  guint8 digest[32];
  gboolean ok = sid_len > 0 && crypto_generichash (digest, sizeof digest,
      user->User.Sid, sid_len, NULL, 0) == 0;
  g_free (user);
  CloseHandle (token);
  if (!ok)
    return WYRELOG_E_CRYPTO;
  gchar hex[65];
  for (guint i = 0; i < sizeof digest; i++)
    g_snprintf (hex + i * 2, 3, "%02x", digest[i]);
  sodium_memzero (digest, sizeof digest);
  *out_actor = g_strdup_printf ("windows-sid-sha256:%s", hex);
#else
  *out_actor = g_strdup_printf ("posix-uid:%" G_GUINT64_FORMAT,
      (guint64) geteuid ());
#endif
  return *out_actor == NULL ? WYRELOG_E_NOMEM : WYRELOG_E_OK;
}

static wyrelog_error_t
receipt_guards_present (wyl_policy_store_t *store)
{
  sqlite3_stmt *stmt = NULL;
  int sql_rc = sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
      "SELECT count(*) FROM sqlite_master WHERE type='trigger'"
      " AND name IN (?,?);", -1, &stmt, NULL);
  if (sql_rc != SQLITE_OK)
    return WYRELOG_E_IO;
  sqlite3_bind_text (stmt, 1, REMEDIATION_RECEIPT_UPDATE_TRIGGER, -1,
      SQLITE_STATIC);
  sqlite3_bind_text (stmt, 2, REMEDIATION_RECEIPT_DELETE_TRIGGER, -1,
      SQLITE_STATIC);
  int step_rc = sqlite3_step (stmt);
  gboolean present = step_rc == SQLITE_ROW && sqlite3_column_int (stmt, 0) == 2;
  sqlite3_finalize (stmt);
  return present ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
install_receipt_guards (wyl_policy_store_t *store)
{
  static const gchar *sql =
      "CREATE TRIGGER IF NOT EXISTS "
      REMEDIATION_RECEIPT_UPDATE_TRIGGER
      " BEFORE UPDATE ON audit_events"
      " WHEN OLD.action IN ('" REMEDIATION_RECEIPT_ACTION "','"
      REMEDIATION_OPERATION_ACTION "','" REMEDIATION_MUTATION_ACTION
      "') OR NEW.action IN ('" REMEDIATION_RECEIPT_ACTION "','"
      REMEDIATION_OPERATION_ACTION "','" REMEDIATION_MUTATION_ACTION
      "') BEGIN SELECT RAISE(ABORT,"
      " 'service permission remediation receipts are immutable'); END;"
      "CREATE TRIGGER IF NOT EXISTS "
      REMEDIATION_RECEIPT_DELETE_TRIGGER
      " BEFORE DELETE ON audit_events"
      " WHEN OLD.action IN ('" REMEDIATION_RECEIPT_ACTION "','"
      REMEDIATION_OPERATION_ACTION "','" REMEDIATION_MUTATION_ACTION
      "') BEGIN SELECT RAISE(ABORT,"
      " 'service permission remediation receipts are permanent'); END;";
  return sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL, NULL,
      NULL) == SQLITE_OK ? receipt_guards_present (store) : WYRELOG_E_IO;
}

static gboolean
parse_uint64_field (const gchar *field, const gchar *prefix, guint64 *out)
{
  if (field == NULL || !g_str_has_prefix (field, prefix))
    return FALSE;
  return g_ascii_string_to_unsigned (field + strlen (prefix), 10, 0,
      G_MAXUINT64, out, NULL);
}

static gboolean
receipt_summary_parse (const gchar *summary,
    WylServicePermissionApplyReceipt *receipt)
{
  g_auto (GStrv) fields = g_strsplit (summary, ";", -1);
  guint64 operations = 0;
  if (g_strv_length (fields) != 5
      || !parse_uint64_field (fields[0], "pre_generation:",
          &receipt->pre_generation)
      || !g_str_has_prefix (fields[1], "pre_digest:")
      || !hex_to_digest (fields[1] + strlen ("pre_digest:"),
          receipt->pre_digest)
      || !parse_uint64_field (fields[2], "post_generation:",
          &receipt->post_generation)
      || !g_str_has_prefix (fields[3], "post_digest:")
      || !hex_to_digest (fields[3] + strlen ("post_digest:"),
          receipt->post_digest)
      || !parse_uint64_field (fields[4], "operations:", &operations)
      || operations > G_MAXUINT)
    return FALSE;
  receipt->operation_count = (guint) operations;
  return TRUE;
}

static wyrelog_error_t
validate_operation_evidence (wyl_policy_store_t *store,
    const WylServicePermissionManifest *manifest)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  sqlite3_stmt *evidence = NULL;
  sqlite3_stmt *mutation = NULL;
  int sql_rc = sqlite3_prepare_v2 (db,
      "SELECT resource_id,deny_reason,deny_origin FROM audit_events"
      " WHERE action=? AND request_id=? ORDER BY deny_reason;", -1,
      &evidence, NULL);
  if (sql_rc == SQLITE_OK)
    sql_rc = sqlite3_prepare_v2 (db,
        "SELECT resource_id,deny_reason,deny_origin FROM audit_events"
        " WHERE id=? AND action=? AND request_id=?;", -1, &mutation, NULL);
  if (sql_rc != SQLITE_OK) {
    if (evidence != NULL)
      sqlite3_finalize (evidence);
    if (mutation != NULL)
      sqlite3_finalize (mutation);
    return WYRELOG_E_IO;
  }
  sqlite3_bind_text (evidence, 1, REMEDIATION_OPERATION_ACTION, -1,
      SQLITE_STATIC);
  sqlite3_bind_text (evidence, 2, manifest->request_id, -1, SQLITE_STATIC);
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (guint i = 0; rc == WYRELOG_E_OK && i < manifest->operations->len; i++) {
    if (sqlite3_step (evidence) != SQLITE_ROW) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    const gchar *mutation_id =
        (const gchar *) sqlite3_column_text (evidence, 0);
    const gchar *ordinal = (const gchar *) sqlite3_column_text (evidence, 1);
    const gchar *stored_fingerprint =
        (const gchar *) sqlite3_column_text (evidence, 2);
    const WylPolicyPermissionClosureRemoval *operation =
        g_ptr_array_index (manifest->operations, i);
    gchar expected_ordinal[32];
    gchar expected_fingerprint[65];
    g_snprintf (expected_ordinal, sizeof expected_ordinal, "ordinal:%010u", i);
    rc = operation_fingerprint (operation, expected_fingerprint);
    if (rc != WYRELOG_E_OK || mutation_id == NULL || ordinal == NULL
        || stored_fingerprint == NULL
        || !g_str_equal (ordinal, expected_ordinal)
        || !g_str_equal (stored_fingerprint, expected_fingerprint)) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    sqlite3_reset (mutation);
    sqlite3_clear_bindings (mutation);
    sqlite3_bind_text (mutation, 1, mutation_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (mutation, 2, REMEDIATION_MUTATION_ACTION, -1,
        SQLITE_STATIC);
    sqlite3_bind_text (mutation, 3, manifest->request_id, -1, SQLITE_STATIC);
    if (sqlite3_step (mutation) != SQLITE_ROW) {
      rc = WYRELOG_E_POLICY;
      break;
    }
    const gchar *subject = (const gchar *) sqlite3_column_text (mutation, 0);
    const gchar *action = (const gchar *) sqlite3_column_text (mutation, 1);
    const gchar *tuple = (const gchar *) sqlite3_column_text (mutation, 2);
    g_autofree gchar *expected_tuple =
        g_strdup_printf ("right=%s;scope=%s", operation->right_id,
        operation->scope);
    const gchar *expected_action =
        operation->action == WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT ?
        "revoke_direct" : "remove_membership";
    if (subject == NULL || action == NULL || tuple == NULL
        || g_strcmp0 (subject, operation->subject_id) != 0
        || !g_str_equal (action, expected_action)
        || g_strcmp0 (tuple, expected_tuple) != 0
        || sqlite3_step (mutation) != SQLITE_DONE)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK && sqlite3_step (evidence) != SQLITE_DONE)
    rc = WYRELOG_E_POLICY;
  sqlite3_finalize (mutation);
  sqlite3_finalize (evidence);
  return rc;
}

static wyrelog_error_t
receipt_lookup (wyl_policy_store_t *store,
    const WylServicePermissionManifest *manifest, const gchar *fingerprint,
    WylServicePermissionApplyReceipt *out_receipt)
{
  sqlite3_stmt *stmt = NULL;
  int sql_rc = sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
      "SELECT id,created_at_us,subject_id,deny_reason,deny_origin"
      " FROM audit_events WHERE action=? AND request_id=? ORDER BY id;",
      -1, &stmt, NULL);
  if (sql_rc != SQLITE_OK)
    return WYRELOG_E_IO;
  sqlite3_bind_text (stmt, 1, REMEDIATION_RECEIPT_ACTION, -1, SQLITE_STATIC);
  sqlite3_bind_text (stmt, 2, manifest->request_id, -1, SQLITE_STATIC);
  int step_rc = sqlite3_step (stmt);
  if (step_rc == SQLITE_DONE) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_NOT_FOUND;
  }
  if (step_rc != SQLITE_ROW) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_IO;
  }
  if (receipt_guards_present (store) != WYRELOG_E_OK) {
    sqlite3_finalize (stmt);
    return WYRELOG_E_POLICY;
  }
  const gchar *audit_id = (const gchar *) sqlite3_column_text (stmt, 0);
  gint64 applied_at = sqlite3_column_int64 (stmt, 1);
  const gchar *actor = (const gchar *) sqlite3_column_text (stmt, 2);
  const gchar *stored_fingerprint =
      (const gchar *) sqlite3_column_text (stmt, 3);
  const gchar *summary = (const gchar *) sqlite3_column_text (stmt, 4);
  gboolean valid = audit_id != NULL && actor != NULL && applied_at > 0
      && stored_fingerprint != NULL && summary != NULL
      && g_str_equal (stored_fingerprint, fingerprint)
      && receipt_summary_parse (summary, out_receipt)
      && out_receipt->operation_count == manifest->operations->len
      && out_receipt->pre_generation == manifest->store_generation
      && memcmp (out_receipt->pre_digest, manifest->store_digest, 32) == 0;
  g_autofree gchar *audit_copy = g_strdup (audit_id);
  g_autofree gchar *actor_copy = g_strdup (actor);
  int final_step = sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  if (!valid || final_step != SQLITE_DONE
      || validate_operation_evidence (store, manifest) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  out_receipt->state = WYL_SERVICE_PERMISSION_APPLY_REPLAYED;
  out_receipt->request_id = g_strdup (manifest->request_id);
  out_receipt->actor_identity = g_steal_pointer (&actor_copy);
  out_receipt->audit_id = g_steal_pointer (&audit_copy);
  out_receipt->applied_at_us = applied_at;
  memcpy (out_receipt->manifest_fingerprint, fingerprint, 65);
  return out_receipt->request_id != NULL && out_receipt->actor_identity != NULL
      && out_receipt->audit_id != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

static wyrelog_error_t
new_audit_id (gchar out[WYL_ID_STRING_BUF])
{
  wyl_id_t id = WYL_ID_NIL;
  wyrelog_error_t rc = wyl_id_new (&id);
  return rc == WYRELOG_E_OK ? wyl_id_format (&id, out, WYL_ID_STRING_BUF) : rc;
}

wyrelog_error_t
wyl_service_permission_maintenance_apply (wyl_policy_store_t *store,
    const WylServicePermissionManifest *manifest,
    WylServicePermissionApplyReceipt *out_receipt)
{
  if (store == NULL || manifest == NULL || out_receipt == NULL)
    return WYRELOG_E_INVALID;
  memset (out_receipt, 0, sizeof *out_receipt);
  WylHandle *handle = NULL;
  g_autofree gchar *actor = NULL;
  g_autofree gchar *receipt_summary = NULL;
  guint64 pre_generation = 0;
  guint8 pre_digest[32] = { 0 };
  guint64 post_generation = 0;
  guint8 post_digest[32] = { 0 };
  WylServicePermissionMaintenanceFailStage fail_stage =
      wyl_policy_store_service_permission_maintenance_take_failure (store);
  wyrelog_error_t rc =
      wyl_handle_adopt_offline_maintenance_store (store, &handle);
  if (rc != WYRELOG_E_OK)
    return rc;                  /* adopt consumes store on every outcome */
  store = wyl_handle_get_policy_store (handle);

  gchar fingerprint[65];
  rc = manifest_fingerprint (manifest, fingerprint);
  if (rc == WYRELOG_E_OK)
    rc = receipt_lookup (store, manifest, fingerprint, out_receipt);
  if (rc == WYRELOG_E_OK) {
    g_object_unref (handle);
    return WYRELOG_E_OK;
  }
  if (rc != WYRELOG_E_NOT_FOUND)
    goto out;

  WylPolicyPermissionClosureAnalysis analysis = {
    0
  };
  rc = wyl_policy_store_analyze_service_permission_closure (store, &analysis);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_permission_manifest_matches_analysis (manifest, &analysis);
  if (rc == WYRELOG_E_OK) {
    pre_generation = analysis.generation;
    memcpy (pre_digest, analysis.digest, sizeof pre_digest);
  }
  wyl_policy_permission_closure_analysis_clear (&analysis);
  if (rc != WYRELOG_E_OK)
    goto out;

  rc = maintenance_actor_identity (&actor);
  WylServiceAuthWriteLease *lease = NULL;
  WylServiceAuthorityTransaction *transaction = NULL;
  WylServiceAuthorityCommitEvidence *evidence = NULL;
  if (fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_COMMIT)
    wyl_policy_store_service_authority_transaction_fail_once (store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_BEFORE);
  if (fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_COMMIT_UNCERTAIN)
    wyl_policy_store_service_authority_transaction_fail_once (store,
        WYL_POLICY_AUTHORITY_TXN_FAIL_RELEASE_AFTER);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_authority_acquire_permission_remediation_write
        (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_transaction_begin (store, handle,
        lease, &transaction);
  if (rc == WYRELOG_E_OK)
    rc = install_receipt_guards (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_prepare_commit_evidence
        (transaction, store, &evidence);
  if (rc == WYRELOG_E_OK
      && fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_WRITE_INTENT)
    wyl_policy_store_service_authority_transaction_test_fail_intent_once
        (transaction, SQLITE_LOCKED);
  WylServiceAuthorityWriteIntentOutcome intent = {
    0
  };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_transaction_acquire_write_intent
        (transaction, store, NULL, &intent);

  gint64 applied_at = g_get_real_time ();
  if (rc == WYRELOG_E_OK
      && fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_PARTICIPANT)
    rc = WYRELOG_E_IO;
  for (guint i = 0; rc == WYRELOG_E_OK && i < manifest->operations->len; i++) {
    const WylPolicyPermissionClosureRemoval *operation =
        g_ptr_array_index (manifest->operations, i);
    gchar audit_id[WYL_ID_STRING_BUF];
    rc = new_audit_id (audit_id);
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_service_authority_remediate_permission_closure
          (transaction, store,
          operation->action ==
          WYL_POLICY_PERMISSION_CLOSURE_REVOKE_DIRECT ?
          WYL_POLICY_PERMISSION_REMEDIATION_REVOKE_DIRECT :
          WYL_POLICY_PERMISSION_REMEDIATION_REMOVE_MEMBERSHIP,
          operation->subject_id, operation->right_id, operation->scope,
          audit_id, applied_at, actor, manifest->request_id);
    if (rc == WYRELOG_E_OK
        && fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_AUDIT)
      rc = WYRELOG_E_IO;
    gchar evidence_id[WYL_ID_STRING_BUF];
    gchar operation_digest[65];
    if (rc == WYRELOG_E_OK)
      rc = new_audit_id (evidence_id);
    if (rc == WYRELOG_E_OK)
      rc = operation_fingerprint (operation, operation_digest);
    g_autofree gchar *ordinal = g_strdup_printf ("ordinal:%010u", i);
    gboolean operation_inserted = FALSE;
    if (rc == WYRELOG_E_OK)
      rc = wyl_policy_store_append_audit_event_full (store, evidence_id,
          applied_at, actor, REMEDIATION_OPERATION_ACTION, audit_id, ordinal,
          operation_digest, manifest->request_id, WYL_DECISION_ALLOW,
          &operation_inserted);
    if (rc == WYRELOG_E_OK && !operation_inserted)
      rc = WYRELOG_E_POLICY;
  }

  WylPolicyPermissionClosureAnalysis post_analysis = {
    0
  };
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_analyze_service_permission_closure (store,
        &post_analysis);
  if (rc == WYRELOG_E_OK
      && (post_analysis.removals == NULL || post_analysis.removals->len != 0
          || post_analysis.unsafe_permission_count != 0
          || post_analysis.dangling_subject_count != 0
          || post_analysis.dangling_role_count != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    rc = wyl_policy_store_service_permission_authority_snapshot (store,
        &post_generation, post_digest);
  }
  wyl_policy_permission_closure_analysis_clear (&post_analysis);

  gchar receipt_audit_id[WYL_ID_STRING_BUF];
  if (rc == WYRELOG_E_OK)
    rc = new_audit_id (receipt_audit_id);
  gchar pre_digest_hex[65];
  gchar post_digest_hex[65];
  digest_to_hex (pre_digest, pre_digest_hex);
  digest_to_hex (post_digest, post_digest_hex);
  receipt_summary = g_strdup_printf ("pre_generation:%" G_GUINT64_FORMAT
      ";pre_digest:%s;post_generation:%" G_GUINT64_FORMAT
      ";post_digest:%s;operations:%u", pre_generation, pre_digest_hex,
      post_generation, post_digest_hex, manifest->operations->len);
  gboolean inserted = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_append_audit_event_full (store, receipt_audit_id,
        applied_at, actor, REMEDIATION_RECEIPT_ACTION, manifest->request_id,
        fingerprint, receipt_summary, manifest->request_id, WYL_DECISION_ALLOW,
        &inserted);
  if (rc == WYRELOG_E_OK && !inserted)
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_authority_transaction_commit (transaction);
  else if (transaction != NULL)
    (void) wyl_policy_store_service_authority_transaction_rollback
        (transaction);

  if (evidence != NULL)
    wyl_policy_store_service_authority_commit_evidence_unref (evidence);
  if (transaction != NULL)
    wyl_policy_store_service_authority_transaction_free (transaction);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_write_lease_release (lease);
    if (release_rc == WYRELOG_E_OK
        && fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_LEASE_RELEASE)
      release_rc = WYRELOG_E_IO;
    if (rc == WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_write_lease_free (lease);
  }
  if (rc == WYRELOG_E_OK
      && fail_stage == WYL_SERVICE_PERMISSION_MAINTENANCE_FAIL_PUBLISH)
    wyl_policy_store_maintenance_publish_fail_once (store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_maintenance_publish (store);
  if (rc == WYRELOG_E_OK) {
    out_receipt->state = WYL_SERVICE_PERMISSION_APPLY_APPLIED;
    out_receipt->request_id = g_strdup (manifest->request_id);
    out_receipt->actor_identity = g_strdup (actor);
    out_receipt->audit_id = g_strdup (receipt_audit_id);
    memcpy (out_receipt->manifest_fingerprint, fingerprint, 65);
    out_receipt->operation_count = manifest->operations->len;
    out_receipt->applied_at_us = applied_at;
    out_receipt->pre_generation = pre_generation;
    memcpy (out_receipt->pre_digest, pre_digest, sizeof pre_digest);
    out_receipt->post_generation = post_generation;
    memcpy (out_receipt->post_digest, post_digest, sizeof post_digest);
    if (out_receipt->request_id == NULL
        || out_receipt->actor_identity == NULL || out_receipt->audit_id == NULL)
      rc = WYRELOG_E_NOMEM;
  }

out:
  sodium_memzero (fingerprint, sizeof fingerprint);
  sodium_memzero (pre_digest, sizeof pre_digest);
  sodium_memzero (post_digest, sizeof post_digest);
  if (rc != WYRELOG_E_OK)
    wyl_service_permission_apply_receipt_clear (out_receipt);
  g_object_unref (handle);
  return rc;
}

static wyrelog_error_t
apply_receipt_encode (const WylServicePermissionApplyReceipt *receipt,
    gchar **out_document, gsize *out_len)
{
  wyl_id_t parsed_audit_id = WYL_ID_NIL;
  if (out_document == NULL || out_len == NULL || receipt == NULL
      || !request_id_is_canonical (receipt->request_id)
      || receipt->actor_identity == NULL || receipt->actor_identity[0] == '\0'
      || receipt->audit_id == NULL
      || wyl_id_parse (receipt->audit_id, &parsed_audit_id) != WYRELOG_E_OK
      || strlen (receipt->manifest_fingerprint) != 64
      || receipt->pre_generation == 0 || receipt->post_generation == 0
      || receipt->operation_count == 0)
    return WYRELOG_E_INVALID;
  guint8 fingerprint_bytes[32];
  if (!hex_to_digest (receipt->manifest_fingerprint, fingerprint_bytes))
    return WYRELOG_E_INVALID;
  sodium_memzero (fingerprint_bytes, sizeof fingerprint_bytes);
  gchar pre_digest[65];
  gchar post_digest[65];
  digest_to_hex (receipt->pre_digest, pre_digest);
  digest_to_hex (receipt->post_digest, post_digest);
  GString *document = g_string_new ("{\"version\":1,\"request_id\":");
  append_json_string (document, receipt->request_id);
  g_string_append (document, ",\"manifest_fingerprint\":");
  append_json_string (document, receipt->manifest_fingerprint);
  g_string_append (document, ",\"actor\":");
  append_json_string (document, receipt->actor_identity);
  g_string_append (document, ",\"audit_id\":");
  append_json_string (document, receipt->audit_id);
  g_string_append_printf (document, ",\"applied_at_us\":%" G_GINT64_FORMAT
      ",\"operation_count\":%u,\"pre_generation\":%" G_GUINT64_FORMAT
      ",\"pre_digest\":\"%s\",\"post_generation\":%" G_GUINT64_FORMAT
      ",\"post_digest\":\"%s\"}\n", receipt->applied_at_us,
      receipt->operation_count, receipt->pre_generation, pre_digest,
      receipt->post_generation, post_digest);
  *out_len = document->len;
  *out_document = g_string_free (document, FALSE);
  sodium_memzero (pre_digest, sizeof pre_digest);
  sodium_memzero (post_digest, sizeof post_digest);
  return *out_document != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}

wyrelog_error_t
wyl_service_permission_apply_receipt_reserve_owner_only (const gchar *path,
    WylServicePermissionReceiptReservation **out_reservation)
{
  if (path == NULL || path[0] == '\0' || out_reservation == NULL)
    return WYRELOG_E_INVALID;
  *out_reservation = NULL;
  WylServicePermissionReceiptReservation *reservation =
      g_new0 (WylServicePermissionReceiptReservation, 1);
  if (reservation == NULL)
    return WYRELOG_E_NOMEM;
  reservation->path = g_strdup (path);
#ifdef G_OS_WIN32
  reservation->file = INVALID_HANDLE_VALUE;
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;
  LPWSTR sid_text = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  wchar_t *sddl = NULL;
  wyrelog_error_t rc = WYRELOG_E_IO;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    goto win_out;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    goto win_out;
  user = g_malloc (needed);
  if (user == NULL || !GetTokenInformation (token, TokenUser, user, needed,
          &needed) || !ConvertSidToStringSidW (user->User.Sid, &sid_text))
    goto win_out;
  gsize sid_len = wcslen (sid_text);
  sddl = g_new (wchar_t, 32 + sid_len * 2);
  if (sddl == NULL
      || swprintf (sddl, 32 + sid_len * 2, L"O:%lsD:P(A;;FA;;;%ls)",
          sid_text, sid_text) < 0
      || !ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl,
          SDDL_REVISION_1, &descriptor, NULL))
    goto win_out;
  SECURITY_ATTRIBUTES attrs = { sizeof attrs, descriptor, FALSE };
  reservation->wide_path =
      (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (reservation->wide_path == NULL) {
    rc = WYRELOG_E_INVALID;
    goto win_out;
  }
  reservation->file = CreateFileW (reservation->wide_path, GENERIC_WRITE, 0,
      &attrs, CREATE_NEW,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (reservation->file == INVALID_HANDLE_VALUE) {
    rc = GetLastError () == ERROR_FILE_EXISTS
        || GetLastError () == ERROR_ALREADY_EXISTS ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
    goto win_out;
  }
  reservation->created = TRUE;
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle (reservation->file, &info)
      || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT
              | FILE_ATTRIBUTE_DIRECTORY)) || info.nNumberOfLinks != 1) {
    rc = WYRELOG_E_POLICY;
    goto win_out;
  }
  rc = WYRELOG_E_OK;
win_out:
  g_free (sddl);
  if (descriptor != NULL)
    LocalFree (descriptor);
  if (sid_text != NULL)
    LocalFree (sid_text);
  g_free (user);
  if (token != NULL)
    CloseHandle (token);
  if (rc != WYRELOG_E_OK) {
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return rc;
  }
#else
  reservation->dirfd = -1;
  reservation->fd = -1;
  g_autofree gchar *absolute = g_canonicalize_filename (path, NULL);
  g_autofree gchar *parent = g_path_get_dirname (absolute);
  reservation->basename = g_path_get_basename (absolute);
  gchar *resolved_parent = realpath (parent, NULL);
  if (resolved_parent == NULL) {
    wyrelog_error_t rc = errno == ENOENT ? WYRELOG_E_NOT_FOUND : WYRELOG_E_IO;
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return rc;
  }
  reservation->parent_path = g_strdup (resolved_parent);
  reservation->dirfd =
      open (resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  g_free (resolved_parent);
  struct stat parent_stat;
  if (reservation->dirfd < 0
      || fstat (reservation->dirfd, &parent_stat) != 0
      || !S_ISDIR (parent_stat.st_mode) || parent_stat.st_uid != geteuid ()
      || (parent_stat.st_mode & 0077) != 0) {
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return WYRELOG_E_POLICY;
  }
  reservation->parent_dev = parent_stat.st_dev;
  reservation->parent_ino = parent_stat.st_ino;
  reservation->fd = openat (reservation->dirfd, reservation->basename,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (reservation->fd < 0) {
    int open_errno = errno;
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return open_errno == EEXIST || open_errno == ELOOP ?
        WYRELOG_E_POLICY : WYRELOG_E_IO;
  }
  reservation->created = TRUE;
  struct stat file_stat;
  if (fstat (reservation->fd, &file_stat) != 0
      || !S_ISREG (file_stat.st_mode) || file_stat.st_nlink != 1
      || file_stat.st_uid != geteuid () || (file_stat.st_mode & 0077) != 0) {
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return WYRELOG_E_POLICY;
  }
  reservation->target_dev = file_stat.st_dev;
  reservation->target_ino = file_stat.st_ino;
#endif
  *out_reservation = reservation;
  return WYRELOG_E_OK;
}

#ifndef G_OS_WIN32
static gboolean
    receipt_reservation_named_target_matches
    (const WylServicePermissionReceiptReservation * reservation)
{
  struct stat pinned_parent;
  struct stat named_parent;
  struct stat named_target;
  int named_parent_fd = open (reservation->parent_path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  gboolean matches = fstat (reservation->dirfd, &pinned_parent) == 0
      && pinned_parent.st_dev == reservation->parent_dev
      && pinned_parent.st_ino == reservation->parent_ino
      && named_parent_fd >= 0
      && fstat (named_parent_fd, &named_parent) == 0
      && named_parent.st_dev == reservation->parent_dev
      && named_parent.st_ino == reservation->parent_ino
      && fstatat (reservation->dirfd, reservation->basename, &named_target,
      AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG (named_target.st_mode)
      && named_target.st_dev == reservation->target_dev
      && named_target.st_ino == reservation->target_ino;
  if (named_parent_fd >= 0)
    close (named_parent_fd);
  return matches;
}
#endif

void wyl_service_permission_apply_receipt_reservation_abort
    (WylServicePermissionReceiptReservation * reservation)
{
  if (reservation == NULL)
    return;
#ifdef G_OS_WIN32
  if (reservation->before_abort_close_hook != NULL)
    reservation->before_abort_close_hook (reservation->before_abort_close_data);
  if (reservation->file != INVALID_HANDLE_VALUE)
    CloseHandle (reservation->file);
  g_free (reservation->wide_path);
#else
  if (reservation->created)
    (void) receipt_reservation_named_target_matches (reservation);
  if (reservation->before_abort_close_hook != NULL)
    reservation->before_abort_close_hook (reservation->before_abort_close_data);
  if (reservation->fd >= 0)
    close (reservation->fd);
  if (reservation->dirfd >= 0)
    close (reservation->dirfd);
  g_free (reservation->basename);
  g_free (reservation->parent_path);
#endif
  g_free (reservation->path);
  g_free (reservation);
}

void wyl_service_permission_apply_receipt_reservation_set_before_abort_hook
    (WylServicePermissionReceiptReservation * reservation,
    void (*hook) (gpointer data), gpointer data)
{
  if (reservation != NULL) {
    reservation->before_abort_close_hook = hook;
    reservation->before_abort_close_data = data;
  }
}

void wyl_service_permission_apply_receipt_reservation_fail_finalize_once
    (WylServicePermissionReceiptReservation * reservation)
{
  if (reservation != NULL)
    reservation->fail_finalize_once = TRUE;
}

wyrelog_error_t
    wyl_service_permission_apply_receipt_finalize
    (WylServicePermissionReceiptReservation * reservation,
    const WylServicePermissionApplyReceipt * receipt)
{
  if (reservation == NULL)
    return WYRELOG_E_INVALID;
  g_autofree gchar *document = NULL;
  gsize len = 0;
  wyrelog_error_t rc = apply_receipt_encode (receipt, &document, &len);
  if (rc == WYRELOG_E_OK && reservation->fail_finalize_once)
    rc = WYRELOG_E_IO;
  gsize total = 0;
#ifdef G_OS_WIN32
  while (rc == WYRELOG_E_OK && total < len) {
    DWORD written = 0;
    DWORD chunk = len - total > 0x10000 ? 0x10000 : (DWORD) (len - total);
    if (!WriteFile (reservation->file, document + total, chunk, &written, NULL)
        || written == 0)
      rc = WYRELOG_E_IO;
    else
      total += written;
  }
  if (rc == WYRELOG_E_OK && !FlushFileBuffers (reservation->file))
    rc = WYRELOG_E_IO;
  if (reservation->file != INVALID_HANDLE_VALUE) {
    CloseHandle (reservation->file);
    reservation->file = INVALID_HANDLE_VALUE;
  }
#else
  while (rc == WYRELOG_E_OK && total < len) {
    ssize_t written = write (reservation->fd, document + total, len - total);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      rc = WYRELOG_E_IO;
    else
      total += (gsize) written;
  }
  if (rc == WYRELOG_E_OK && fsync (reservation->fd) != 0)
    rc = WYRELOG_E_IO;
  if (rc == WYRELOG_E_OK
      && !receipt_reservation_named_target_matches (reservation))
    rc = WYRELOG_E_POLICY;
  if (reservation->fd >= 0) {
    if (close (reservation->fd) != 0 && rc == WYRELOG_E_OK)
      rc = WYRELOG_E_IO;
    reservation->fd = -1;
  }
  if (rc == WYRELOG_E_OK && fsync (reservation->dirfd) != 0)
    rc = WYRELOG_E_IO;
#endif
  if (rc != WYRELOG_E_OK) {
    wyl_service_permission_apply_receipt_reservation_abort (reservation);
    return rc;
  }
#ifdef G_OS_WIN32
  g_free (reservation->wide_path);
#else
  close (reservation->dirfd);
  g_free (reservation->basename);
  g_free (reservation->parent_path);
#endif
  g_free (reservation->path);
  g_free (reservation);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_permission_apply_receipt_write_new_owner_only (const gchar *path,
    const WylServicePermissionApplyReceipt *receipt)
{
  WylServicePermissionReceiptReservation *reservation = NULL;
  wyrelog_error_t rc =
      wyl_service_permission_apply_receipt_reserve_owner_only (path,
      &reservation);
  return rc == WYRELOG_E_OK ?
      wyl_service_permission_apply_receipt_finalize (reservation, receipt) : rc;
}
