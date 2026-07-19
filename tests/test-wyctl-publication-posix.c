#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#include "../wyrelog/wyctl/wyctl-publication-posix-private.h"

typedef struct
{
  gchar *dir;
  WyctlPublicationPosixBackend backend;
} Fixture;

static void
fixture_clear (Fixture *fixture)
{
  if (fixture == NULL)
    return;
  wyctl_publication_posix_backend_clear (&fixture->backend);
  if (fixture->dir != NULL)
    (void) g_rmdir (fixture->dir);
  g_free (fixture->dir);
  memset (fixture, 0, sizeof (*fixture));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static void
fixture_init (Fixture *fixture)
{
  fixture->dir = g_dir_make_tmp ("wyctl-pub-posix-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  wyctl_publication_posix_backend_init (&fixture->backend, fixture->dir);
}

static gchar *
encode_identity_for_test (const struct stat *st)
{
  return g_strdup_printf ("%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT ":"
      "%" G_GUINT64_FORMAT ":%" G_GUINT64_FORMAT ":"
      "%" G_GUINT64_FORMAT,
      (guint64) st->st_dev,
      (guint64) st->st_ino,
      (guint64) st->st_uid, (guint64) st->st_gid, (guint64) st->st_mode);
}

static void
write_credential_document_for_test (const gchar *path,
    const gchar *credential_id, const gchar *credential_secret)
{
  g_autofree gchar *document = NULL;

  g_assert_cmpint (wyctl_publication_credential_document_encode (credential_id,
          credential_secret, &document), ==, WYRELOG_E_OK);
  g_assert_true (g_file_set_contents (path, document, -1, NULL));
}

static void
write_malformed_document_for_test (const gchar *path)
{
  g_assert_true (g_file_set_contents (path, "not a credential document", -1,
          NULL));
}

static void
test_plan_and_prepare (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);

  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_plan_is_valid (&planned));
  g_assert_cmpstr (planned.destination, ==, request.destination);
  g_assert_cmpstr (planned.stage_basename, ==, request.stage_basename);

  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_assert_true (wyctl_publication_receipt_is_valid (&receipt));
  g_assert_cmpstr (receipt.destination, ==, planned.destination);
  g_assert_cmpstr (receipt.stage_basename, ==, planned.stage_basename);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  struct stat st = { 0 };
  g_assert_cmpint (g_stat (stage_path, &st), ==, 0);
  g_assert_true (S_ISREG (st.st_mode));
  g_assert_cmpint (st.st_size, ==, 0);
  g_autofree gchar *expected_identity = encode_identity_for_test (&st);
  g_assert_cmpstr (receipt.stage_identity, ==, expected_identity);

  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_commit_inspect_cleanup_roundtrip (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);

  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);

  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      planned.destination, NULL);
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };

  WyctlPublicationResult result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_commit (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", secret, &result), ==,
      WYRELOG_E_OK);
  g_assert_true (wyctl_publication_result_is_valid (&result));
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_test (destination_path, G_FILE_TEST_EXISTS));

  struct stat st = { 0 };
  g_assert_cmpint (g_stat (destination_path, &st), ==, 0);
  g_autofree gchar *expected_identity = encode_identity_for_test (&st);
  g_assert_cmpstr (receipt.stage_identity, ==, expected_identity);

  WyctlPublicationResult inspect_result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_inspect (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &expected_secret,
          &inspect_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (inspect_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (inspect_result.exact_identity);

  WyctlPublicationResult cleanup_result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_cleanup (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &expected_secret,
          &cleanup_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (cleanup_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);

  wyctl_publication_result_clear (&cleanup_result);
  wyctl_publication_result_clear (&inspect_result);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_commit_rejects_existing_destination (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);

  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      planned.destination, NULL);
  g_assert_cmpint (g_file_set_contents (destination_path, "foreign", -1, NULL),
      ==, TRUE);

  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  WyctlPublicationResult result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_commit (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", secret, &result),
      ==, WYRELOG_E_POLICY);
  g_assert_true (g_file_test (destination_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_resync_publishes_exact_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);

  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      planned.destination, NULL);
  g_autofree gchar *doc = NULL;
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };
  g_assert_cmpint (wyctl_publication_credential_document_encode
      ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", secret, &doc), ==, WYRELOG_E_OK);
  int fd = open (stage_path, O_WRONLY | O_TRUNC);
  g_assert_cmpint (fd, >=, 0);
  g_assert_cmpint (write (fd, doc, strlen (doc)), ==, (gssize) strlen (doc));
  g_assert_cmpint (close (fd), ==, 0);

  WyctlPublicationResult result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_resync (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &expected_secret,
          &result), ==, WYRELOG_E_OK);
  g_assert_true (result.kind == WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE
      || result.kind ==
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN);
  g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_test (destination_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_resync_refuses_wrong_secret_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  g_autofree gchar *expected_secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  g_autofree gchar *foreign_secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'B');
  WyctlSensitiveText expected_secret = {.text = expected_secret_text,
    .len = strlen (expected_secret_text)
  };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *destination_path = NULL;
  g_autofree gchar *document = NULL;

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  stage_path = g_build_filename (fixture.dir, planned.stage_basename, NULL);
  destination_path = g_build_filename (fixture.dir, planned.destination, NULL);
  g_assert_cmpint (wyctl_publication_credential_document_encode
      ("wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", foreign_secret_text, &document),
      ==, WYRELOG_E_OK);
  g_assert_true (g_file_set_contents (stage_path, document, -1, NULL));

  g_assert_cmpint (wyctl_publication_posix_resync (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &expected_secret,
          &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (destination_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_resync_refuses_wrong_id_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  const gchar *expected_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *foreign_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOw";
  g_autofree gchar *secret = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      planned.destination, NULL);
  write_credential_document_for_test (stage_path, foreign_id, secret);

  g_assert_cmpint (wyctl_publication_posix_resync (&fixture.backend, &planned,
          &receipt, expected_id, &expected_secret, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (result.exact_identity);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (destination_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_inspect_refuses_wrong_credential_final (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult commit_result = { 0 };
  WyctlPublicationResult inspect_result = { 0 };
  const gchar *expected_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *foreign_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOw";
  g_autofree gchar *expected_secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  g_autofree gchar *foreign_secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'B');
  WyctlSensitiveText expected_secret = {.text = expected_secret_text,
    .len = strlen (expected_secret_text)
  };

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_commit (&fixture.backend, &planned,
          &receipt, expected_id, expected_secret_text, &commit_result), ==,
      WYRELOG_E_OK);
  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      planned.destination, NULL);

  write_credential_document_for_test (destination_path, foreign_id,
      expected_secret_text);
  g_assert_cmpint (wyctl_publication_posix_inspect (&fixture.backend, &planned,
          &receipt, expected_id, &expected_secret, &inspect_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect_result.exact_identity);
  wyctl_publication_result_clear (&inspect_result);

  write_credential_document_for_test (destination_path, expected_id,
      foreign_secret_text);
  g_assert_cmpint (wyctl_publication_posix_inspect (&fixture.backend, &planned,
          &receipt, expected_id, &expected_secret, &inspect_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect_result.exact_identity);

  wyctl_publication_result_clear (&inspect_result);
  wyctl_publication_result_clear (&commit_result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_inspect_and_cleanup_refuse_malformed_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult inspect_result = { 0 };
  WyctlPublicationResult cleanup_result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  g_autofree gchar *secret = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  write_malformed_document_for_test (stage_path);

  g_assert_cmpint (wyctl_publication_posix_inspect (&fixture.backend, &planned,
          &receipt, credential_id, &expected_secret, &inspect_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect_result.exact_identity);
  g_assert_false (inspect_result.cleanup_required);

  g_assert_cmpint (wyctl_publication_posix_cleanup (&fixture.backend, &planned,
          &receipt, credential_id, &expected_secret, &cleanup_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (cleanup_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (cleanup_result.exact_identity);
  g_assert_false (cleanup_result.cleanup_required);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&cleanup_result);
  wyctl_publication_result_clear (&inspect_result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_cleanup_refuses_wrong_credential_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult cleanup_result = { 0 };
  const gchar *expected_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  const gchar *foreign_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOw";
  g_autofree gchar *expected_secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText expected_secret = {.text = expected_secret_text,
    .len = strlen (expected_secret_text)
  };

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  write_credential_document_for_test (stage_path, foreign_id,
      expected_secret_text);

  g_assert_cmpint (wyctl_publication_posix_cleanup (&fixture.backend, &planned,
          &receipt, expected_id, &expected_secret, &cleanup_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (cleanup_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (cleanup_result.exact_identity);
  g_assert_false (cleanup_result.cleanup_required);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&cleanup_result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_inspect_refuses_foreign_replacement (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult inspect_result = { 0 };
  const gchar *credential_id = "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";
  g_autofree gchar *secret = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);
  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_assert_cmpint (g_remove (stage_path), ==, 0);
  write_credential_document_for_test (stage_path, credential_id, secret);

  g_assert_cmpint (wyctl_publication_posix_inspect (&fixture.backend, &planned,
          &receipt, credential_id, &expected_secret, &inspect_result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (inspect_result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (inspect_result.exact_identity);
  g_assert_false (inspect_result.cleanup_required);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&inspect_result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_plan_rejects_existing_symlink_destination (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);

  g_autofree gchar *destination_path = g_build_filename (fixture.dir,
      request.destination, NULL);
  g_assert_cmpint (symlink ("/tmp/foreign", destination_path), ==, 0);

  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_POLICY);

  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_cleanup_refuses_foreign_stage (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);

  WyctlPublicationPlan request = { 0 };
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);

  WyctlPublicationPlan planned = { 0 };
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);

  WyctlPublicationReceipt receipt = { 0 };
  g_assert_cmpint (wyctl_publication_posix_prepare (&fixture.backend, &planned,
          &receipt), ==, WYRELOG_E_OK);

  g_autofree gchar *stage_path = g_build_filename (fixture.dir,
      planned.stage_basename, NULL);
  g_assert_cmpint (g_remove (stage_path), ==, 0);
  g_assert_cmpint (g_file_set_contents (stage_path, "foreign", -1, NULL), ==,
      TRUE);
  g_autofree gchar *secret = g_strnfill (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN,
      'A');
  WyctlSensitiveText expected_secret = {.text = secret,.len = strlen (secret) };

  WyctlPublicationResult cleanup_result = { 0 };
  g_assert_cmpint (wyctl_publication_posix_cleanup (&fixture.backend, &planned,
          &receipt, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &expected_secret,
          &cleanup_result), ==, WYRELOG_E_OK);
  g_assert_cmpint (cleanup_result.kind,
      ==, WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));

  wyctl_publication_result_clear (&cleanup_result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_plan_rejects_nonprivate_root (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };

  fixture_init (&fixture);
  g_assert_cmpint (g_chmod (fixture.dir, 0750), ==, 0);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (g_chmod (fixture.dir, 0700), ==, 0);

  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/publication/posix/plan-prepare",
      test_plan_and_prepare);
  g_test_add_func ("/wyctl/publication/posix/roundtrip",
      test_commit_inspect_cleanup_roundtrip);
  g_test_add_func ("/wyctl/publication/posix/rejects-existing-destination",
      test_commit_rejects_existing_destination);
  g_test_add_func ("/wyctl/publication/posix/resyncs-exact-stage",
      test_resync_publishes_exact_stage);
  g_test_add_func ("/wyctl/publication/posix/refuses-wrong-secret-stage",
      test_resync_refuses_wrong_secret_stage);
  g_test_add_func ("/wyctl/publication/posix/refuses-wrong-id-stage",
      test_resync_refuses_wrong_id_stage);
  g_test_add_func ("/wyctl/publication/posix/refuses-wrong-credential-final",
      test_inspect_refuses_wrong_credential_final);
  g_test_add_func ("/wyctl/publication/posix/refuses-malformed-stage",
      test_inspect_and_cleanup_refuse_malformed_stage);
  g_test_add_func ("/wyctl/publication/posix/cleanup-refuses-wrong-credential",
      test_cleanup_refuses_wrong_credential_stage);
  g_test_add_func ("/wyctl/publication/posix/refuses-foreign-replacement",
      test_inspect_refuses_foreign_replacement);
  g_test_add_func ("/wyctl/publication/posix/rejects-symlink",
      test_plan_rejects_existing_symlink_destination);
  g_test_add_func ("/wyctl/publication/posix/refuses-foreign-cleanup",
      test_cleanup_refuses_foreign_stage);
  g_test_add_func ("/wyctl/publication/posix/rejects-nonprivate-root",
      test_plan_rejects_nonprivate_root);
  return g_test_run ();
}
