/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>

#include "../wyrelog/wyctl/wyctl-publication-private.h"
#include "../wyrelog/wyctl/wyctl-publication-windows-private.h"

#ifdef G_OS_WIN32

#include <windows.h>
#include <aclapi.h>

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

static void
windows_fixture_setup (WindowsFixture *fixture)
{
  fixture->root_dir = g_dir_make_tmp ("wyctl-publication-windows-XXXXXX", NULL);
  g_assert_nonnull (fixture->root_dir);
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
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));
  {
    g_autofree gchar *stage = g_build_filename (fixture.root_dir,
        planned.stage_basename, NULL);
    assert_path_owner_only_acl (stage);
  }

  g_assert_cmpint (wyctl_publication_windows_commit (&fixture.backend, &planned,
          &receipt, credential_id, credential_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_true (result.exact_identity);

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
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/publication/windows/roundtrip",
      test_plan_prepare_commit_roundtrip);
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
#ifdef WYL_TEST_WYCTL_PUBLICATION_WINDOWS
  g_test_add_func ("/wyctl/publication/windows/owner-only-security-descriptor",
      test_owner_only_security_descriptor_predicate);
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
