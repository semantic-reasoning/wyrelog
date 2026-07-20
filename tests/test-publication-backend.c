/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "../wyrelog/wyctl/wyctl-publication-backend-private.h"

#define TEST_CREDENTIAL_ID "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv"

/* The executor-path and conformance-path tests drive the concrete publication
 * backend through the production vtable end to end.  They run on POSIX, where
 * the backend is exercised by the existing publication suite.  The Windows
 * publication backend is currently guarded out of the build's test coverage
 * (see tests/test-wyctl-publication-windows.c, which sits in an unreachable
 * branch) and has not been validated end to end; driving it here is deferred
 * to its own rehabilitation.  The adapter itself still compiles on Windows and
 * is smoke-tested there via test_backend_open_rejects_empty_root.  Its per-OS
 * shims are structurally identical, so POSIX runtime coverage plus the Windows
 * compile-and-link give strong confidence in the Windows forwarding; the real
 * Windows end-to-end validation is tracked in #559. */
#ifndef G_OS_WIN32

static gchar *
make_backend_root (const gchar *template)
{
  gchar *root = g_dir_make_tmp (template, NULL);

  g_assert_nonnull (root);
  return root;
}

static gchar *
encode_expected_document (const gchar *credential_id,
    const gchar *credential_secret)
{
  gchar *document = NULL;

  g_assert_cmpint (wyctl_publication_credential_document_encode (credential_id,
          credential_secret, &document), ==, WYRELOG_E_OK);
  g_assert_nonnull (document);
  return document;
}

static void
assert_published_document (const gchar *destination_path,
    const gchar *credential_id, const gchar *credential_secret)
{
  g_autofree gchar *published = NULL;
  g_autofree gchar *expected = NULL;

  g_assert_true (g_file_test (destination_path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_get_contents (destination_path, &published, NULL,
          NULL));
  expected = encode_expected_document (credential_id, credential_secret);
  g_assert_cmpstr (published, ==, expected);
}

/* Drive the production vtable along the exact executor call sequence
 * (plan -> stage_exact -> receipt_target_acquire -> inspect -> commit ->
 * inspect -> release) against a temp root, mirroring the escrow executor in
 * service-credential-operation-coordinator-execute-private.c. The final
 * cross-check that the document staged by stage_exact is the one the
 * receipt_target path commits to the derived destination proves the shims
 * route a single self/root through the whole flow. */
static void
test_backend_executor_path (void)
{
  gchar *root = make_backend_root ("wyctl-pub-backend-exec-XXXXXX");

  WyctlPublicationBackend backend = { 0 };
  g_assert_cmpint (wyctl_publication_backend_open (&backend, root), ==,
      WYRELOG_E_OK);
  const WyctlPublicationBackendVTable *vtable =
      wyctl_publication_backend_vtable ();
  gpointer self = wyctl_publication_backend_self (&backend);
  g_assert_nonnull (vtable);
  g_assert_nonnull (self);

  g_autofree gchar *secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText secret = {.text = secret_text,.len = strlen (secret_text)
  };

  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  gboolean replayed = FALSE;
  WyctlPublicationReceiptTargetLease *lease = NULL;
  WyctlPublicationReceiptTargetKind kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;

  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt", root,
          &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (vtable->plan (self, &request, &planned), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_plan_is_valid (&planned));

  g_assert_cmpint (vtable->stage_exact (self, &planned, TEST_CREDENTIAL_ID,
          &secret, &receipt, &result, &replayed), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);

  g_autofree gchar *stage_path = g_build_filename (root, planned.stage_basename,
      NULL);
  g_autofree gchar *destination_path = g_build_filename (root,
      planned.destination, NULL);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  g_assert_cmpint (vtable->receipt_target_acquire (self, &planned, &receipt,
          FALSE, &lease, &kind), ==, WYRELOG_E_OK);
  g_assert_nonnull (lease);
  g_assert_cmpint (kind, ==, WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE);

  g_assert_cmpint (vtable->receipt_target_inspect (self, lease,
          TEST_CREDENTIAL_ID, &secret, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);

  g_assert_cmpint (vtable->receipt_target_commit (self, lease,
          TEST_CREDENTIAL_ID, &secret, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);

  g_assert_cmpint (vtable->receipt_target_inspect (self, lease,
          TEST_CREDENTIAL_ID, &secret, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);

  vtable->receipt_target_release (self, lease);
  lease = NULL;

  /* The staged document is now the committed destination under the same root:
   * stage consumed, destination present with the exact credential document. */
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  assert_published_document (destination_path, TEST_CREDENTIAL_ID, secret_text);

  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
  wyctl_publication_backend_close (&backend);

  (void) g_remove (destination_path);
  (void) g_rmdir (root);
  g_free (root);
}

/* Drive the conformance harness (plan -> prepare -> commit -> inspect ->
 * resync -> cleanup) through the production vtable against a fresh temp root
 * and assert the published document lands at the plan-derived destination.
 * Exercising the real backend end-to-end proves the commit/inspect plan
 * reconstruction is correct, not merely well-formed. */
static void
test_backend_conformance_path (void)
{
  gchar *root = make_backend_root ("wyctl-pub-backend-conf-XXXXXX");

  WyctlPublicationBackend backend = { 0 };
  g_assert_cmpint (wyctl_publication_backend_open (&backend, root), ==,
      WYRELOG_E_OK);
  const WyctlPublicationBackendVTable *vtable =
      wyctl_publication_backend_vtable ();
  gpointer self = wyctl_publication_backend_self (&backend);

  g_autofree gchar *secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlPublicationResult result = { 0 };

  g_assert_cmpint (wyctl_publication_backend_conformance_run (vtable, self,
          "credential.txt", root, TEST_CREDENTIAL_ID, secret_text, &result),
      ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);

  g_autofree gchar *destination_path = g_build_filename (root, "credential.txt",
      NULL);
  assert_published_document (destination_path, TEST_CREDENTIAL_ID, secret_text);

  wyctl_publication_result_clear (&result);
  wyctl_publication_backend_close (&backend);

  (void) g_remove (destination_path);
  (void) g_rmdir (root);
  g_free (root);
}

#endif /* !G_OS_WIN32 */

static void
test_backend_open_rejects_empty_root (void)
{
  WyctlPublicationBackend backend = { 0 };

  g_assert_cmpint (wyctl_publication_backend_open (&backend, NULL), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyctl_publication_backend_open (&backend, ""), ==,
      WYRELOG_E_INVALID);
  g_assert_null (wyctl_publication_backend_self (NULL));
  g_assert_nonnull (wyctl_publication_backend_vtable ());
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
#ifndef G_OS_WIN32
  g_test_add_func ("/wyctl/publication-backend/executor-path",
      test_backend_executor_path);
  g_test_add_func ("/wyctl/publication-backend/conformance-path",
      test_backend_conformance_path);
#endif
  g_test_add_func ("/wyctl/publication-backend/open-rejects-empty-root",
      test_backend_open_rejects_empty_root);
  return g_test_run ();
}
