/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>

#include "../wyrelog/wyctl/wyctl-publication-private.h"
#include "../wyrelog/wyctl/wyctl-publication-windows-private.h"

#ifdef G_OS_WIN32

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

  windows_fixture_setup (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          "parent-identity", &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_windows_prepare (&fixture.backend,
          &planned, &receipt), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));

  g_assert_cmpint (wyctl_publication_windows_commit (&fixture.backend, &planned,
          &receipt, credential_id, credential_secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_true (result.exact_identity);

  g_assert_cmpint (wyctl_publication_windows_inspect (&fixture.backend,
          &planned, &receipt, &inspect), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&inspect));
  g_assert_true (inspect.exact_identity);

  g_assert_cmpint (wyctl_publication_windows_resync (&fixture.backend,
          &planned, &receipt, &resynced), ==, WYRELOG_E_OK);
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
  g_assert_true (g_file_set_contents (stage, "foreign", -1, NULL));
  g_assert_cmpint (wyctl_publication_windows_cleanup (&fixture.backend,
          &planned, &receipt, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  windows_fixture_teardown (&fixture);
}

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
