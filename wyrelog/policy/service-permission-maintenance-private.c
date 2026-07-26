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
#include <string.h>

#ifdef G_OS_WIN32
#include <sddl.h>
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

wyrelog_error_t
    wyl_service_permission_manifest_write_new_owner_only
    (const gchar * path, const WylServicePermissionManifest * manifest)
{
  if (path == NULL || path[0] == '\0')
    return WYRELOG_E_INVALID;
  g_autofree gchar *document = NULL;
  gsize len = 0;
  wyrelog_error_t rc =
      wyl_service_permission_manifest_encode (manifest, &document, &len);
  if (rc != WYRELOG_E_OK)
    return rc;
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
