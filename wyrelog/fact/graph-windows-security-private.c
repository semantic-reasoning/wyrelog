/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-windows-security-private.h"

#ifdef G_OS_WIN32
#include <aclapi.h>

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

static wyrelog_error_t
copy_sid (PSID source, PSID *out_sid)
{
  DWORD length;
  PSID copy;
  if (out_sid == NULL)
    return WYRELOG_E_INVALID;
  *out_sid = NULL;
  if (source == NULL || !IsValidSid (source))
    return WYRELOG_E_IO;
  length = GetLengthSid (source);
  copy = g_try_malloc (length);
  if (copy == NULL)
    return WYRELOG_E_NOMEM;
  if (!CopySid (length, copy, source)) {
    g_free (copy);
    return WYRELOG_E_IO;
  }
  *out_sid = copy;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
query_token_user (HANDLE token, PSID *out_user)
{
  TOKEN_USER *info = NULL;
  DWORD needed = 0;
  if (out_user == NULL)
    return WYRELOG_E_INVALID;
  *out_user = NULL;
  GetTokenInformation (token, TokenUser, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    return WYRELOG_E_IO;
  info = g_try_malloc (needed);
  if (info == NULL)
    return WYRELOG_E_NOMEM;
  if (!GetTokenInformation (token, TokenUser, info, needed, &needed)
      || info->User.Sid == NULL) {
    g_free (info);
    return WYRELOG_E_IO;
  }
  wyrelog_error_t rc = copy_sid (info->User.Sid, out_user);
  g_free (info);
  return rc;
}

static wyrelog_error_t
query_token_owner (HANDLE token, PSID *out_owner)
{
  TOKEN_OWNER *info = NULL;
  DWORD needed = 0;
  if (out_owner == NULL)
    return WYRELOG_E_INVALID;
  *out_owner = NULL;
  GetTokenInformation (token, TokenOwner, NULL, 0, &needed);
  if (GetLastError () != ERROR_INSUFFICIENT_BUFFER || needed == 0)
    return WYRELOG_E_IO;
  info = g_try_malloc (needed);
  if (info == NULL)
    return WYRELOG_E_NOMEM;
  if (!GetTokenInformation (token, TokenOwner, info, needed, &needed)
      || info->Owner == NULL) {
    g_free (info);
    return WYRELOG_E_IO;
  }
  wyrelog_error_t rc = copy_sid (info->Owner, out_owner);
  g_free (info);
  return rc;
}

static wyrelog_error_t
copy_token_user (PSID *out_user)
{
  HANDLE token = NULL;
  wyrelog_error_t rc;
  if (out_user == NULL)
    return WYRELOG_E_INVALID;
  *out_user = NULL;
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return WYRELOG_E_IO;
  rc = query_token_user (token, out_user);
  CloseHandle (token);
  return rc;
}

void
wyl_fact_graph_win_token_identity_clear (WylFactGraphWinTokenIdentity *identity)
{
  g_free (identity->owner);
  g_free (identity->user);
  memset (identity, 0, sizeof *identity);
}

wyrelog_error_t
wyl_fact_graph_win_token_identity_init (WylFactGraphWinTokenIdentity *identity)
{
  HANDLE token = NULL;
  wyrelog_error_t rc;
  if (identity == NULL)
    return WYRELOG_E_INVALID;
  memset (identity, 0, sizeof *identity);
  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token))
    return WYRELOG_E_IO;
  rc = query_token_user (token, &identity->user);
  if (rc == WYRELOG_E_OK)
    rc = query_token_owner (token, &identity->owner);
  CloseHandle (token);
  if (rc != WYRELOG_E_OK)
    wyl_fact_graph_win_token_identity_clear (identity);
  return rc;
}

void
wyl_fact_graph_win_owner_only_security_clear (WylFactGraphWinOwnerOnlySecurity
    *security)
{
  g_free (security->acl);
  g_free (security->user);
  memset (security, 0, sizeof *security);
}

wyrelog_error_t
    wyl_fact_graph_win_owner_only_security_init_for_user
    (WylFactGraphWinOwnerOnlySecurity * security, PSID user, BYTE ace_flags) {
  wyrelog_error_t rc;
  DWORD sid_length;
  DWORD acl_length;
  memset (security, 0, sizeof *security);
  rc = copy_sid (user, &security->user);
  if (rc != WYRELOG_E_OK)
    return rc;
  sid_length = GetLengthSid (security->user);
  acl_length = sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE) - sizeof (DWORD)
      + sid_length;
  security->acl = g_try_malloc0 (acl_length);
  if (security->acl == NULL) {
    wyl_fact_graph_win_owner_only_security_clear (security);
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
    wyl_fact_graph_win_owner_only_security_clear (security);
    return WYRELOG_E_IO;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_graph_win_owner_only_security_init (WylFactGraphWinOwnerOnlySecurity
    *security, BYTE ace_flags)
{
  g_autofree gpointer token_user = NULL;
  wyrelog_error_t rc = copy_token_user ((PSID *) & token_user);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_owner_only_security_init_for_user (security,
      token_user, ace_flags) : rc;
}

wyrelog_error_t
wyl_fact_graph_win_validate_protected_owner_acl_for_user (HANDLE handle,
    PSID token_user, BYTE ace_flags)
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

wyrelog_error_t
wyl_fact_graph_win_validate_protected_owner_acl (HANDLE handle, BYTE ace_flags)
{
  g_autofree gpointer token_user = NULL;
  wyrelog_error_t rc = copy_token_user ((PSID *) & token_user);
  return rc == WYRELOG_E_OK
      ? wyl_fact_graph_win_validate_protected_owner_acl_for_user (handle,
      token_user, ace_flags) : rc;
}

wyrelog_error_t
wyl_fact_graph_win_validate_owner_only_acl (HANDLE handle)
{
  return wyl_fact_graph_win_validate_protected_owner_acl (handle,
      OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
}

wyrelog_error_t
wyl_fact_graph_win_validate_upgradeable_file_acl (HANDLE handle,
    const WylFactGraphWinTokenIdentity *identity)
{
  PSECURITY_DESCRIPTOR descriptor = NULL;
  PSID owner = NULL;
  PACL dacl = NULL;
  BOOL present = FALSE;
  BOOL defaulted = FALSE;
  ACL_SIZE_INFORMATION size = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;
  DWORD error = GetSecurityInfo (handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, NULL,
      &dacl, NULL, &descriptor);
  if (error != ERROR_SUCCESS) {
    trace_windows_failure ("upgradeable-acl-query", WYRELOG_E_IO, error);
    return WYRELOG_E_IO;
  }
  gboolean descriptor_ok = descriptor != NULL;
  gboolean owner_valid = owner != NULL && IsValidSid (owner);
  gboolean owner_user_match = owner_valid && EqualSid (owner, identity->user);
  gboolean owner_token_owner_match = owner_valid
      && EqualSid (owner, identity->owner);
  gboolean dacl_ok = descriptor_ok
      && GetSecurityDescriptorDacl (descriptor, &present, &dacl, &defaulted);
  gboolean acl_info_ok = dacl_ok && present && dacl != NULL
      && GetAclInformation (dacl, &size, sizeof size, AclSizeInformation);
  gboolean ace_ok = acl_info_ok && size.AceCount == 1
      && GetAce (dacl, 0, (LPVOID *) & ace) && ace != NULL;
  gboolean allowed_ace = ace_ok
      && ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE;
  gboolean ace_flags_ok = allowed_ace
      && (ace->Header.AceFlags & ~INHERITED_ACE) == 0;
  gboolean ace_mask_ok = allowed_ace && ace->Mask == FILE_ALL_ACCESS;
  PSID ace_sid = allowed_ace ? (PSID) & ace->SidStart : NULL;
  gboolean ace_sid_valid = ace_sid != NULL && IsValidSid (ace_sid);
  gboolean ace_sid_match = ace_sid_valid && EqualSid (ace_sid, identity->user);
  gboolean valid = descriptor_ok
      && (owner_user_match || owner_token_owner_match) && dacl_ok && present
      && dacl != NULL && !defaulted && acl_info_ok
      && size.AceCount == 1 && ace_ok && allowed_ace && ace_flags_ok
      && ace_mask_ok && ace_sid_match;
  if (!valid)
    g_log (WYL_FACT_GRAPH_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,
        "stage=upgradeable-acl-validate rc=%d descriptor-ok=%u "
        "owner-user-match=%u owner-token-owner-match=%u "
        "dacl-ok=%u present=%u defaulted=%u "
        "acl-info-ok=%u ace-count=%lu ace-ok=%u ace-type=%u "
        "ace-flags=0x%02x ace-flags-ok=%u ace-mask=0x%08lx "
        "ace-mask-ok=%u ace-sid-valid=%u ace-sid-match=%u",
        (int) WYRELOG_E_POLICY, (unsigned int) descriptor_ok,
        (unsigned int) owner_user_match,
        (unsigned int) owner_token_owner_match, (unsigned int) dacl_ok,
        (unsigned int) present, (unsigned int) defaulted,
        (unsigned int) acl_info_ok, (unsigned long) size.AceCount,
        (unsigned int) ace_ok,
        ace != NULL ? (unsigned int) ace->Header.AceType : 0,
        ace != NULL ? (unsigned int) ace->Header.AceFlags : 0,
        (unsigned int) ace_flags_ok,
        allowed_ace ? (unsigned long) ace->Mask : 0,
        (unsigned int) ace_mask_ok, (unsigned int) ace_sid_valid,
        (unsigned int) ace_sid_match);
  LocalFree (descriptor);
  return valid ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}
#endif
