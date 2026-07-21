/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>

#include "../wyrelog/wyctl/wyctl-publication-private.h"
#include "../wyrelog/wyctl/wyctl-publication-windows-private.h"

#ifdef G_OS_WIN32

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

static TOKEN_USER *
current_token_user (void)
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

static gboolean
sid_matches_current_user (PSID sid)
{
  g_autofree TOKEN_USER *user = current_token_user ();

  return sid != NULL && user != NULL && EqualSid (sid, user->User.Sid);
}

static gboolean
sid_is_owner_rights (PSID sid)
{
  BYTE buffer[SECURITY_MAX_SID_SIZE];
  DWORD size = sizeof buffer;

  return sid != NULL
      && CreateWellKnownSid (WinCreatorOwnerRightsSid, NULL, buffer, &size)
      && EqualSid (sid, buffer);
}

static gboolean
security_descriptor_is_owner_only (PSECURITY_DESCRIPTOR descriptor)
{
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  BOOL owner_defaulted = FALSE;
  DWORD revision = 0;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  PACL dacl = NULL;
  PSID owner = NULL;
  ACL_SIZE_INFORMATION size_info = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;

  if (descriptor == NULL
      || !GetSecurityDescriptorControl (descriptor, &control, &revision)
      || (control & SE_DACL_PROTECTED) == 0
      || !GetSecurityDescriptorOwner (descriptor, &owner, &owner_defaulted)
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
  return sid_is_owner_rights ((PSID) & ace->SidStart)
      && ace->Mask == FILE_ALL_ACCESS;
}

static void
assert_path_owner_only_acl (const gchar *path)
{
  g_autofree wchar_t *wpath = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  HANDLE handle = INVALID_HANDLE_VALUE;
  DWORD sec_len = 0;
  PSECURITY_DESCRIPTOR sec = NULL;

  g_assert_nonnull (wpath);
  handle = CreateFileW (wpath, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE
      | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  g_assert_cmpint (handle != INVALID_HANDLE_VALUE, !=, FALSE);

  g_assert_false (GetKernelObjectSecurity (handle,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, 0,
          &sec_len));
  g_assert_cmpuint (GetLastError (), ==, ERROR_INSUFFICIENT_BUFFER);
  sec = g_malloc0 (sec_len);
  g_assert_nonnull (sec);
  g_assert_true (GetKernelObjectSecurity (handle,
          OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, sec,
          sec_len, &sec_len));
  g_assert_true (security_descriptor_is_owner_only (sec));

  g_free (sec);
  CloseHandle (handle);
}

typedef struct
{
  WyctlPublicationWindowsBackend backend;
  gchar *root_dir;
} WindowsFixture;

/* Stamp the token user as owner alongside the protected owner-only DACL. A
 * single call applies the owner before the DACL, so the WRITE_OWNER check
 * still runs against the inherited parent DACL; stamping the DACL first would
 * instead depend on the OWNER RIGHTS ACE, which suppresses the implicit owner
 * READ_CONTROL|WRITE_DAC grant. */
static void
stamp_owner_only_root (const gchar *path)
{
  g_autofree wchar_t *wpath = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  g_autofree TOKEN_USER *user = current_token_user ();
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
}

/* Publication roots in production are created by the caller and are never
 * owner-stamped by the backend, so an elevated caller's root still arrives
 * owned by BUILTIN\Administrators and is rejected with WYRELOG_E_POLICY. That
 * path is deliberately left uncovered: producing such a root requires
 * elevation, and an elevation-dependent test is the failure mode #559 came
 * from. */
static void
windows_fixture_setup (WindowsFixture *fixture)
{
  fixture->root_dir = g_dir_make_tmp ("wyctl-publication-windows-XXXXXX", NULL);
  g_assert_nonnull (fixture->root_dir);
  stamp_owner_only_root (fixture->root_dir);
  wyctl_publication_windows_backend_init (&fixture->backend, fixture->root_dir);
}

static void
windows_fixture_teardown (WindowsFixture *fixture)
{
  wyctl_publication_windows_backend_clear (&fixture->backend);
  g_clear_pointer (&fixture->root_dir, g_free);
}

static void
write_credential_document (const gchar *path, const gchar *credential_id,
    const gchar *credential_secret)
{
  gchar *document = NULL;
  WyctlSensitiveText sensitive_document = { 0 };

  g_assert_cmpint (wyctl_publication_credential_document_encode (credential_id,
          credential_secret, &document), ==, WYRELOG_E_OK);
  sensitive_document.text = document;
  sensitive_document.len = strlen (document);
  g_assert_true (g_file_set_contents (path, document, -1, NULL));
  wyctl_sensitive_text_clear (&sensitive_document);
}

static void
assert_path_contents (const gchar *path, const gchar *expected)
{
  g_autofree gchar *contents = NULL;

  g_assert_true (g_file_get_contents (path, &contents, NULL, NULL));
  g_assert_cmpstr (contents, ==, expected);
}

static void
test_plan_prepare_commit_roundtrip (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlPublicationResult inspect = { 0 };
  WyctlPublicationResult resynced = { 0 };
  WyctlPublicationReceiptTargetLease *lease = NULL;
  WyctlPublicationReceiptTargetKind kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  gboolean replayed = FALSE;
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText expected_secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
          &planned, credential_id, &expected_secret, &receipt, &result,
          &replayed), ==, WYRELOG_E_OK);
  wyctl_publication_result_clear (&result);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));
  {
    g_autofree gchar *stage = g_build_filename (fixture.root_dir,
        planned.stage_basename, NULL);
    assert_path_owner_only_acl (stage);
  }
  g_assert_cmpint (wyctl_publication_windows_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, FALSE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (lease);
  g_assert_cmpint (kind, ==, WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE);
  g_assert_cmpint (wyctl_publication_windows_receipt_target_inspect
      (&fixture.backend, lease, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);
  g_assert_cmpint (wyctl_publication_windows_receipt_target_commit
      (&fixture.backend, lease, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);
  g_assert_cmpint (wyctl_publication_windows_receipt_target_inspect
      (&fixture.backend, lease, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (result.exact_identity);
  wyctl_publication_windows_receipt_target_release (&fixture.backend, lease);
  lease = NULL;

  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &inspect), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&inspect));
  g_assert_true (inspect.exact_identity);

  g_assert_cmpint (wyctl_publication_windows_resync (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &resynced), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&resynced));
  g_assert_true (resynced.exact_identity);

  wyctl_publication_result_clear (&resynced);
  wyctl_publication_result_clear (&inspect);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_receipt_target_lease_blocks_namespace_replacement (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlPublicationReceiptTargetLease *lease = NULL;
  WyctlPublicationReceiptTargetKind kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };
  g_autofree gchar *stage = NULL;
  g_autofree gchar *moved = NULL;
  g_autofree wchar_t *wstage = NULL;
  g_autofree wchar_t *wmoved = NULL;
  gboolean replayed = FALSE;
  DWORD error;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
          &planned, credential_id, &secret, &receipt, &result, &replayed), ==,
      WYRELOG_E_OK);
  wyctl_publication_result_clear (&result);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);
  moved = g_build_filename (fixture.root_dir, "pinned-original", NULL);
  wstage = g_utf8_to_utf16 (stage, -1, NULL, NULL, NULL);
  wmoved = g_utf8_to_utf16 (moved, -1, NULL, NULL, NULL);
  g_assert_nonnull (wstage);
  g_assert_nonnull (wmoved);

  g_assert_cmpint (wyctl_publication_windows_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, FALSE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (lease);
  g_assert_cmpint (kind, ==, WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE);

  g_assert_false (MoveFileExW (wstage, wmoved, MOVEFILE_WRITE_THROUGH));
  error = GetLastError ();
  g_assert_true (error == ERROR_SHARING_VIOLATION
      || error == ERROR_ACCESS_DENIED);
  g_assert_false (DeleteFileW (wstage));
  error = GetLastError ();
  g_assert_true (error == ERROR_SHARING_VIOLATION
      || error == ERROR_ACCESS_DENIED);
  g_assert_cmpint (wyctl_publication_windows_receipt_target_inspect
      (&fixture.backend, lease, credential_id, &secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED);
  g_assert_true (result.exact_identity);

  wyctl_publication_windows_receipt_target_release (&fixture.backend, lease);
  lease = NULL;
  g_assert_true (MoveFileExW (wstage, wmoved, MOVEFILE_WRITE_THROUGH));
  g_assert_true (DeleteFileW (wmoved));
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_plan_rejects_existing_destination (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  g_autofree gchar *destination = NULL;

  windows_fixture_setup (&fixture);
  destination = g_build_filename (fixture.root_dir, "credential.txt", NULL);
  g_file_set_contents (destination, "existing", -1, NULL);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_POLICY);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_cleanup_refuses_foreign_stage (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  g_autofree gchar *stage = NULL;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);
  {
    g_autofree wchar_t *wstage = g_utf8_to_utf16 (stage, -1, NULL, NULL, NULL);
    g_assert_nonnull (wstage);
    g_assert_true (DeleteFileW (wstage));
  }
  g_assert_true (g_file_set_contents (stage, "foreign", -1, NULL));
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText expected_secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };
  g_assert_cmpint (wyctl_publication_windows_cleanup (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_inspect_rejects_wrong_tuple_and_malformed_final (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlPublicationResult inspect = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *other_credential_id = "wlc_1ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const gchar *other_credential_secret =
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  WyctlSensitiveText expected_secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };
  WyctlSensitiveText other_secret = {.text = (gchar *) other_credential_secret,
    .len = strlen (other_credential_secret)
  };
  g_autofree gchar *destination = NULL;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_commit (&fixture.backend, &planned,
          &receipt, credential_id, credential_secret, &result), ==,
      WYRELOG_E_OK);
  destination = g_build_filename (fixture.root_dir, planned.destination, NULL);

  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, other_credential_id, &expected_secret,
          &inspect), ==, WYRELOG_E_OK);
  g_assert_cmpint (inspect.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect.exact_identity);
  wyctl_publication_result_clear (&inspect);

  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, credential_id, &other_secret, &inspect), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect.exact_identity);
  wyctl_publication_result_clear (&inspect);

  g_assert_true (g_file_set_contents (destination, "malformed", -1, NULL));
  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &inspect), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect.exact_identity);

  wyctl_publication_result_clear (&inspect);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_foreign_stage_resync_and_cleanup_do_not_mutate (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *other_credential_id = "wlc_1ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const gchar *other_credential_secret =
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
  WyctlSensitiveText expected_secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };
  WyctlSensitiveText other_secret = {.text = (gchar *) other_credential_secret,
    .len = strlen (other_credential_secret)
  };
  g_autofree gchar *stage = NULL;
  g_autofree gchar *destination = NULL;
  gchar *expected_document = NULL;
  WyctlSensitiveText sensitive_document = { 0 };

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);
  destination = g_build_filename (fixture.root_dir, planned.destination, NULL);
  write_credential_document (stage, credential_id, credential_secret);
  g_assert_cmpint (wyctl_publication_credential_document_encode (credential_id,
          credential_secret, &expected_document), ==, WYRELOG_E_OK);
  sensitive_document.text = expected_document;
  sensitive_document.len = strlen (expected_document);

  g_assert_cmpint (wyctl_publication_windows_resync (&fixture.backend,
          &planned, &receipt, other_credential_id, &expected_secret,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (result.exact_identity);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (destination, G_FILE_TEST_EXISTS));
  assert_path_contents (stage, expected_document);
  wyctl_publication_result_clear (&result);

  g_assert_cmpint (wyctl_publication_windows_cleanup (&fixture.backend,
          &planned, &receipt, credential_id, &other_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (result.exact_identity);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  assert_path_contents (stage, expected_document);

  wyctl_sensitive_text_clear (&sensitive_document);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_malformed_stage_is_foreign_and_not_mutated (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *credential_secret =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText expected_secret = {.text = (gchar *) credential_secret,
    .len = strlen (credential_secret)
  };
  g_autofree gchar *stage = NULL;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);
  g_assert_true (g_file_set_contents (stage, "malformed", -1, NULL));

  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (result.exact_identity);
  wyctl_publication_result_clear (&result);

  g_assert_cmpint (wyctl_publication_windows_resync (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  assert_path_contents (stage, "malformed");
  wyctl_publication_result_clear (&result);

  g_assert_cmpint (wyctl_publication_windows_cleanup (&fixture.backend,
          &planned, &receipt, credential_id, &expected_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_true (g_file_test (stage, G_FILE_TEST_EXISTS));
  assert_path_contents (stage, "malformed");

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_stage_exact_crash_retry_returns_same_receipt (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt first = { 0 };
  WyctlPublicationReceipt replay = { 0 };
  WyctlPublicationResult result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  gchar *credential_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText secret = {.text = credential_secret,.len =
        strlen (credential_secret)
  };
  g_autofree gchar *stage = NULL;
  g_autofree gchar *before = NULL;
  g_autofree gchar *after = NULL;
  gsize before_len = 0;
  gsize after_len = 0;
  gboolean replayed = TRUE;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);

  g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
          &planned, credential_id, &secret, &first, &result, &replayed), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  assert_path_owner_only_acl (stage);
  g_assert_true (g_file_get_contents (stage, &before, &before_len, NULL));

  wyctl_publication_result_clear (&result);
  g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
          &planned, credential_id, &secret, &replay, &result, &replayed), ==,
      WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_cmpstr (replay.stage_identity, ==, first.stage_identity);
  g_assert_true (g_file_get_contents (stage, &after, &after_len, NULL));
  g_assert_cmpuint (after_len, ==, before_len);
  g_assert_cmpmem (after, after_len, before, before_len);

  {
    g_autofree wchar_t *wstage = g_utf8_to_utf16 (stage, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (wstage));
  }
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&replay);
  wyctl_publication_receipt_clear (&first);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

static void
test_stage_exact_partial_stage_is_never_overwritten (void)
{
  WindowsFixture fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt prepared = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  gchar *credential_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  WyctlSensitiveText secret = {.text = credential_secret,.len =
        strlen (credential_secret)
  };
  g_autofree gchar *stage = NULL;
  gboolean replayed = TRUE;

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &prepared), ==, WYRELOG_E_OK);
  stage = g_build_filename (fixture.root_dir, planned.stage_basename, NULL);
  g_assert_true (g_file_set_contents (stage, "partial", -1, NULL));

  g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
          &planned, credential_id, &secret, &receipt, &result, &replayed), ==,
      WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (wyctl_publication_receipt_is_valid (&receipt));
  assert_path_contents (stage, "partial");

  {
    g_autofree wchar_t *wstage = g_utf8_to_utf16 (stage, -1, NULL, NULL, NULL);
    g_assert_true (DeleteFileW (wstage));
  }
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_receipt_clear (&prepared);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

typedef struct
{
  WyctlPublicationStageExactPoint target;
  WyctlPublicationStageExactAction action;
  guint hits[WYCTL_PUBLICATION_STAGE_EXACT_BEFORE_SUCCESS_RETURN + 1];
} StageFault;

static WyctlPublicationStageExactAction
stage_fault_hook (gpointer data, WyctlPublicationStageExactPoint point)
{
  StageFault *fault = data;

  fault->hits[point]++;
  if (point == fault->target && fault->action !=
      WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE) {
    WyctlPublicationStageExactAction action = fault->action;
    fault->action = WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE;
    return action;
  }
  return WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE;
}

static guint
count_stage_temps (const gchar *dir, const WyctlPublicationPlan *plan)
{
  g_autofree gchar *prefix = g_strdup_printf (".%s.tmp-",
      plan->stage_basename);
  g_autoptr (GDir) entries = g_dir_open (dir, 0, NULL);
  const gchar *name;
  guint count = 0;

  g_assert_nonnull (entries);
  while ((name = g_dir_read_name (entries)) != NULL) {
    if (g_str_has_prefix (name, prefix))
      count++;
  }
  return count;
}

static void
test_stage_exact_fault_barriers_recover_without_partial_stage (void)
{
  const WyctlPublicationStageExactPoint points[] = {
    WYCTL_PUBLICATION_STAGE_EXACT_TEMP_CREATED,
    WYCTL_PUBLICATION_STAGE_EXACT_DOCUMENT_WRITTEN,
    WYCTL_PUBLICATION_STAGE_EXACT_FILE_SYNCED,
    WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED,
    WYCTL_PUBLICATION_STAGE_EXACT_DIRECTORY_SYNCED,
    WYCTL_PUBLICATION_STAGE_EXACT_BEFORE_SUCCESS_RETURN,
  };

  for (guint i = 0; i < G_N_ELEMENTS (points); i++) {
    WindowsFixture fixture = { 0 };
    WyctlPublicationPlan request = { 0 };
    WyctlPublicationPlan planned = { 0 };
    WyctlPublicationReceipt receipt = { 0 };
    WyctlPublicationResult result = { 0 };
    gchar *credential_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    WyctlSensitiveText secret = {.text = credential_secret,.len =
          strlen (credential_secret)
    };
    StageFault fault = {.target = points[i],.action =
          WYCTL_PUBLICATION_STAGE_EXACT_CRASH
    };
    g_autofree gchar *stage_path = NULL;
    gboolean replayed = FALSE;

    windows_fixture_setup (&fixture);
    g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
            "parent-identity", &request), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend,
            &request, &planned), ==, WYRELOG_E_OK);
    stage_path = g_build_filename (fixture.root_dir, planned.stage_basename,
        NULL);
    wyctl_publication_windows_backend_set_stage_exact_hook (&fixture.backend,
        stage_fault_hook, &fault);

    g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
            &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &receipt,
            &result, &replayed), ==, WYRELOG_E_IO);
    g_assert_cmpuint (fault.hits[points[i]], ==, 1);
    g_assert_false (wyctl_publication_receipt_is_valid (&receipt));
    if (points[i] < WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED) {
      g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
      g_assert_cmpuint (count_stage_temps (fixture.root_dir, &planned), ==, 1);
    } else {
      g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
    }

    wyctl_publication_windows_backend_set_stage_exact_hook (&fixture.backend,
        NULL, NULL);
    wyctl_publication_result_clear (&result);
    g_assert_cmpint (wyctl_publication_windows_stage_exact (&fixture.backend,
            &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &receipt,
            &result, &replayed), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.kind, ==,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
    g_assert_cmpuint (count_stage_temps (fixture.root_dir, &planned), ==, 0);
    g_assert_cmpint (replayed, ==,
        points[i] >= WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED);

    {
      g_autofree wchar_t *wstage = g_utf8_to_utf16 (stage_path, -1, NULL,
          NULL, NULL);
      g_assert_true (DeleteFileW (wstage));
    }
    wyctl_publication_result_clear (&result);
    wyctl_publication_receipt_clear (&receipt);
    wyctl_publication_plan_clear (&planned);
    wyctl_publication_plan_clear (&request);
    windows_fixture_teardown (&fixture);
  }
}

#ifdef WYL_TEST_WYCTL_PUBLICATION_WINDOWS
static void
test_owner_only_security_descriptor_predicate (void)
{
  g_assert_true
      (wyctl_publication_windows_test_security_descriptor_is_owner_only
      ("D:P(A;;FA;;;OW)"));
  g_assert_false
      (wyctl_publication_windows_test_security_descriptor_is_owner_only
      ("D:(A;;FA;;;OW)"));
  g_assert_false
      (wyctl_publication_windows_test_security_descriptor_is_owner_only
      ("D:P(A;;FA;;;WD)"));
}

/* The predicate test above wraps every input in an owner the harness supplies,
 * so it passes whether or not the backend stamps one. Assert instead on the
 * descriptor the backend attaches to the objects it creates: with no owner in
 * it, Windows takes the owner from the creating token's TokenOwner field,
 * which is BUILTIN\Administrators under an administrator token UAC has not
 * filtered, and the backend then rejects its own stage file (issue #559).
 *
 * Parse the rendered descriptor back and compare SIDs rather than SDDL text:
 * the renderer abbreviates well-known owners to two-letter aliases, so
 * LocalSystem renders as "O:SY" and the built-in Administrator as "O:LA",
 * while ConvertSidToStringSidW always renders numerically. Comparing the
 * strings would fail on correct output whenever the test runs under such an
 * account, and would fail looking exactly like the defect this test exists to
 * catch. */
static void
test_creation_security_descriptor_names_token_user_owner (void)
{
  g_autofree gchar *sddl =
      wyctl_publication_windows_test_creation_security_descriptor_sddl ();
  g_autofree wchar_t *wsddl = NULL;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  BOOL owner_defaulted = FALSE;
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  PSID owner = NULL;
  PACL dacl = NULL;
  ACL_SIZE_INFORMATION size_info = { 0 };
  ACCESS_ALLOWED_ACE *ace = NULL;

  g_assert_nonnull (sddl);
  wsddl = g_utf8_to_utf16 (sddl, -1, NULL, NULL, NULL);
  g_assert_nonnull (wsddl);
  g_assert_true (ConvertStringSecurityDescriptorToSecurityDescriptorW (wsddl,
          SDDL_REVISION_1, &descriptor, NULL));

  g_assert_true (GetSecurityDescriptorOwner (descriptor, &owner,
          &owner_defaulted));
  g_assert_nonnull (owner);
  g_assert_true (sid_matches_current_user (owner));

  g_assert_true (GetSecurityDescriptorControl (descriptor, &control,
          &revision));
  g_assert_cmpuint (control & SE_DACL_PROTECTED, ==, SE_DACL_PROTECTED);

  g_assert_true (GetSecurityDescriptorDacl (descriptor, &dacl_present, &dacl,
          &dacl_defaulted));
  g_assert_true (dacl_present);
  g_assert_nonnull (dacl);
  g_assert_true (GetAclInformation (dacl, &size_info, sizeof size_info,
          AclSizeInformation));
  g_assert_cmpuint (size_info.AceCount, ==, 1);
  g_assert_true (GetAce (dacl, 0, (LPVOID *) & ace));
  g_assert_cmpuint (ace->Header.AceType, ==, ACCESS_ALLOWED_ACE_TYPE);
  g_assert_true (sid_is_owner_rights ((PSID) & ace->SidStart));
  g_assert_cmpuint (ace->Mask, ==, FILE_ALL_ACCESS);

  LocalFree (descriptor);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/publication/windows/roundtrip",
      test_plan_prepare_commit_roundtrip);
  g_test_add_func ("/wyctl/publication/windows/receipt-target-pin",
      test_receipt_target_lease_blocks_namespace_replacement);
  g_test_add_func ("/wyctl/publication/windows/rejects-existing-destination",
      test_plan_rejects_existing_destination);
  g_test_add_func ("/wyctl/publication/windows/refuses-foreign-cleanup",
      test_cleanup_refuses_foreign_stage);
  g_test_add_func
      ("/wyctl/publication/windows/inspect-rejects-wrong-tuple-final",
      test_inspect_rejects_wrong_tuple_and_malformed_final);
  g_test_add_func ("/wyctl/publication/windows/foreign-stage-no-mutation",
      test_foreign_stage_resync_and_cleanup_do_not_mutate);
  g_test_add_func ("/wyctl/publication/windows/malformed-stage-no-mutation",
      test_malformed_stage_is_foreign_and_not_mutated);
  g_test_add_func ("/wyctl/publication/windows/stage-exact-crash-retry",
      test_stage_exact_crash_retry_returns_same_receipt);
  g_test_add_func
      ("/wyctl/publication/windows/stage-exact-partial-no-overwrite",
      test_stage_exact_partial_stage_is_never_overwritten);
  g_test_add_func ("/wyctl/publication/windows/stage-exact-fault-barriers",
      test_stage_exact_fault_barriers_recover_without_partial_stage);
#ifdef WYL_TEST_WYCTL_PUBLICATION_WINDOWS
  g_test_add_func ("/wyctl/publication/windows/owner-only-security-descriptor",
      test_owner_only_security_descriptor_predicate);
  g_test_add_func ("/wyctl/publication/windows/creation-descriptor-owner",
      test_creation_security_descriptor_names_token_user_owner);
#endif
  return g_test_run ();
}

#else

int
main (int argc, char **argv)
{
  (void) argc;
  (void) argv;
  return 77;
}

#endif
