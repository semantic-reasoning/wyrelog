/* SPDX-License-Identifier: GPL-3.0-or-later */

#include <glib.h>
#include <string.h>

#include "../wyrelog/wyctl/wyctl-publication-private.h"

typedef struct
{
  GPtrArray *calls;
  gchar *seen_credential_id;
  gchar *seen_secret;
} FakeBackend;

typedef enum
{
  FAKE_PLAN = 1,
  FAKE_PREPARE,
  FAKE_COMMIT,
  FAKE_INSPECT,
  FAKE_RESYNC,
  FAKE_CLEANUP,
} FakeCall;

static void
fake_backend_init (FakeBackend *backend)
{
  backend->calls = g_ptr_array_new_with_free_func (NULL);
}

static void
fake_backend_clear (FakeBackend *backend)
{
  g_clear_pointer (&backend->seen_credential_id, g_free);
  g_clear_pointer (&backend->seen_secret, g_free);
  g_clear_pointer (&backend->calls, g_ptr_array_unref);
}

static void
fake_backend_add_call (FakeBackend *backend, FakeCall call)
{
  g_ptr_array_add (backend->calls, GINT_TO_POINTER (call));
}

static wyrelog_error_t
fake_plan (gpointer self, const WyctlPublicationPlan *request,
    WyctlPublicationPlan *out_plan)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_PLAN);
  g_assert_true (wyctl_publication_plan_is_valid (request));
  return wyctl_publication_plan_clone (request, out_plan);
}

static wyrelog_error_t
fake_prepare (gpointer self, const WyctlPublicationPlan *plan,
    WyctlPublicationReceipt *out_receipt)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_PREPARE);
  g_assert_true (wyctl_publication_plan_is_valid (plan));
  return wyctl_publication_receipt_create (plan, "stage-identity", out_receipt);
}

static wyrelog_error_t
fake_commit (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *credential_id, const WyctlSensitiveText *credential_secret,
    WyctlPublicationResult *out_result)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_COMMIT);
  g_assert_true (wyctl_publication_receipt_is_valid (receipt));
  g_assert_nonnull (credential_secret);
  g_assert_cmpuint (credential_secret->len, ==,
      WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  g_assert_nonnull (credential_secret->text);
  backend->seen_credential_id = g_strdup (credential_id);
  backend->seen_secret = g_strndup (credential_secret->text,
      credential_secret->len);
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,.exact_identity =
        TRUE,.cleanup_required = FALSE,};
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fake_inspect (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_INSPECT);
  g_assert_true (wyctl_publication_receipt_is_valid (receipt));
  g_assert_true (wyl_service_credential_id_is_canonical
      (expected_credential_id, strlen (expected_credential_id)));
  g_assert_nonnull (expected_credential_secret);
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,.exact_identity =
        TRUE,.cleanup_required = TRUE,};
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fake_resync (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_RESYNC);
  g_assert_true (wyctl_publication_receipt_is_valid (receipt));
  g_assert_true (wyl_service_credential_id_is_canonical
      (expected_credential_id, strlen (expected_credential_id)));
  g_assert_nonnull (expected_credential_secret);
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN,.exact_identity
        = TRUE,.cleanup_required = FALSE,};
  return WYRELOG_E_OK;
}

static wyrelog_error_t
fake_cleanup (gpointer self, const WyctlPublicationReceipt *receipt,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret,
    WyctlPublicationResult *out_result)
{
  FakeBackend *backend = self;
  fake_backend_add_call (backend, FAKE_CLEANUP);
  g_assert_true (wyctl_publication_receipt_is_valid (receipt));
  g_assert_true (wyl_service_credential_id_is_canonical
      (expected_credential_id, strlen (expected_credential_id)));
  g_assert_nonnull (expected_credential_secret);
  *out_result = (WyctlPublicationResult) {
  .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN,.exact_identity
        = TRUE,.cleanup_required = FALSE,};
  return WYRELOG_E_OK;
}

static void
test_plan_create_and_validate (void)
{
  WyctlPublicationPlan plan = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("dest/file",
          "parent-identity", &plan), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_plan_is_valid (&plan));
  g_assert_nonnull (plan.reservation_id);
  g_assert_cmpuint (strlen (plan.reservation_id), ==, WYL_ID_STRING_LEN);
  g_assert_true (g_str_has_prefix (plan.stage_basename, "wypub-"));

  WyctlPublicationPlan clone = { 0 };
  g_assert_cmpint (wyctl_publication_plan_clone (&plan, &clone), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_plan_is_valid (&clone));
  g_assert_cmpstr (clone.destination, ==, plan.destination);
  g_assert_cmpstr (clone.reservation_id, ==, plan.reservation_id);
  g_assert_cmpstr (clone.parent_identity, ==, plan.parent_identity);
  g_assert_cmpstr (clone.stage_basename, ==, plan.stage_basename);

  wyctl_publication_plan_clear (&clone);
  wyctl_publication_plan_clear (&plan);
}

static void
test_receipt_create_and_validate (void)
{
  WyctlPublicationPlan plan = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("dest/file",
          "parent-identity", &plan), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_receipt_create (&plan,
          "stage-identity", &receipt), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));
  g_assert_cmpstr (receipt.destination, ==, plan.destination);
  g_assert_cmpstr (receipt.reservation_id, ==, plan.reservation_id);
  g_assert_cmpstr (receipt.parent_identity, ==, plan.parent_identity);
  g_assert_cmpstr (receipt.stage_basename, ==, plan.stage_basename);
  g_assert_cmpstr (receipt.stage_identity, ==, "stage-identity");

  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&plan);
}

static void
test_credential_document_roundtrip (void)
{
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  g_autofree gchar *document = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };

  g_assert_cmpint (wyctl_publication_credential_document_encode (credential_id,
          secret, &document), ==, WYRELOG_E_OK);
  g_assert_nonnull (document);
  g_assert_cmpstr (document,
      ==,
      "{\"version\":1,\"credential_id\":\"wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv\",\"credential_secret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}\n");

  g_assert_cmpint (wyctl_publication_credential_document_decode (document,
          strlen (document), &decoded_id, &decoded_secret), ==, WYRELOG_E_OK);
  g_assert_cmpstr (decoded_id, ==, credential_id);
  g_assert_cmpuint (decoded_secret.len, ==,
      WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  g_assert_cmpstr (decoded_secret.text, ==, secret);

  wyctl_sensitive_text_clear (&decoded_secret);
  g_assert_null (decoded_secret.text);
  g_assert_cmpuint (decoded_secret.len, ==, 0);
}

static void
test_credential_document_rejects_noncanonical_form (void)
{
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  g_autofree gchar *document = NULL;
  g_autofree gchar *decoded_id = NULL;
  WyctlSensitiveText decoded_secret = { 0 };

  g_assert_cmpint (wyctl_publication_credential_document_encode
      ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", secret, &document), ==, WYRELOG_E_OK);
  g_autofree gchar *mutated = g_strdup (document);
  mutated[0] = ' ';
  g_assert_cmpint (wyctl_publication_credential_document_decode (mutated,
          strlen (mutated), &decoded_id, &decoded_secret), ==,
      WYRELOG_E_INVALID);
  g_assert_null (decoded_id);
  g_assert_null (decoded_secret.text);
}

static void
test_result_validation (void)
{
  WyctlPublicationResult result = {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,
    .kind = WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,
    .exact_identity = TRUE,
    .cleanup_required = FALSE,
  };
  g_assert_true (wyctl_publication_result_is_valid (&result));
  result.kind = 99;
  g_assert_false (wyctl_publication_result_is_valid (&result));
}

static void
test_backend_conformance_harness (void)
{
  FakeBackend backend = { 0 };
  WyctlPublicationBackendVTable vtable = {
    .plan = fake_plan,
    .prepare = fake_prepare,
    .commit = fake_commit,
    .inspect = fake_inspect,
    .resync = fake_resync,
    .cleanup = fake_cleanup,
  };
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  WyctlPublicationResult result = { 0 };

  fake_backend_init (&backend);
  g_assert_cmpint (wyctl_publication_backend_conformance_run (&vtable,
          &backend, "dest/file", "parent-identity",
          "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN);
  g_assert_cmpuint (backend.calls->len, ==, 6);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 0)), ==,
      FAKE_PLAN);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 1)), ==,
      FAKE_PREPARE);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 2)), ==,
      FAKE_COMMIT);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 3)), ==,
      FAKE_INSPECT);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 4)), ==,
      FAKE_RESYNC);
  g_assert_cmpint (GPOINTER_TO_INT (g_ptr_array_index (backend.calls, 5)), ==,
      FAKE_CLEANUP);
  g_assert_cmpstr (backend.seen_credential_id, ==,
      "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv");
  g_assert_cmpstr (backend.seen_secret, ==, secret);

  fake_backend_clear (&backend);
  wyctl_publication_result_clear (&result);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/publication/plan-create",
      test_plan_create_and_validate);
  g_test_add_func ("/wyctl/publication/receipt-create",
      test_receipt_create_and_validate);
  g_test_add_func ("/wyctl/publication/document-roundtrip",
      test_credential_document_roundtrip);
  g_test_add_func ("/wyctl/publication/document-rejects-noncanonical",
      test_credential_document_rejects_noncanonical_form);
  g_test_add_func ("/wyctl/publication/result-validation",
      test_result_validation);
  g_test_add_func ("/wyctl/publication/harness",
      test_backend_conformance_harness);
  return g_test_run ();
}
