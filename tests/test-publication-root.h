/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

/* The Windows publication backend requires a root owned by the token user
 * under a protected, owner-only DACL (full access to OWNER RIGHTS);
 * g_dir_make_tmp and g_mkdir_with_parents leave the inherited parent DACL and
 * an owner taken from the token's TokenOwner field, which is
 * BUILTIN\Administrators under an administrator token UAC has not filtered. */
static inline TOKEN_USER *
publication_root_token_user (void)
{
  HANDLE token = NULL;
  DWORD needed = 0;
  TOKEN_USER *user = NULL;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return NULL;
  if (!GetTokenInformation (token, TokenUser, NULL, 0, &needed)
      && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle (token);
    return NULL;
  }
  user = g_malloc0 (needed);
  if (user != NULL && !GetTokenInformation (token, TokenUser, user, needed,
          &needed))
    g_clear_pointer (&user, g_free);
  CloseHandle (token);
  return user;
}
#endif

/* Stamp the token user as owner alongside the protected owner-only DACL. A
 * single call applies the owner before the DACL, so the WRITE_OWNER check
 * still runs against the inherited parent DACL; stamping the DACL first would
 * instead depend on the OWNER RIGHTS ACE, which suppresses the implicit owner
 * READ_CONTROL|WRITE_DAC grant. Off Windows the caller's 0700 root already
 * carries owner-private semantics and nothing needs stamping. */
static inline void
publication_root_stamp_owner_only (const gchar *path)
{
#ifdef G_OS_WIN32
  g_autofree wchar_t *wpath = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree TOKEN_USER *user = publication_root_token_user ();
  PSECURITY_DESCRIPTOR descriptor = NULL;
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  PACL dacl = NULL;
  DWORD status;

  g_assert_nonnull (wpath);
  g_assert_nonnull (user);
  g_assert_true (ConvertStringSecurityDescriptorToSecurityDescriptorW
      (L"D:P(A;;FA;;;OW)", SDDL_REVISION_1, &descriptor, NULL));
  g_assert_true (GetSecurityDescriptorDacl (descriptor, &dacl_present, &dacl,
          &dacl_defaulted));
  g_assert_true (dacl_present);
  status = SetNamedSecurityInfoW ((LPWSTR) wpath, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
      | PROTECTED_DACL_SECURITY_INFORMATION, user->User.Sid, NULL, dacl, NULL);
  LocalFree (descriptor);
  g_assert_cmpuint (status, ==, ERROR_SUCCESS);
#else
  (void) path;
#endif
}
