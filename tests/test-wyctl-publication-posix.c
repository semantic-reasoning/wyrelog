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

typedef struct
{
  WyctlPublicationReceiptTargetSyncPoint fail_point;
  guint hits[WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY + 1];
} ReceiptTargetSyncFault;

static wyrelog_error_t
receipt_target_sync_fault (gpointer data,
    WyctlPublicationReceiptTargetSyncPoint point)
{
  ReceiptTargetSyncFault *fault = data;
  fault->hits[point]++;
  return point == fault->fail_point ? WYRELOG_E_IO : WYRELOG_E_OK;
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
test_receipt_target_lease_roundtrip_and_foreign_identity (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlPublicationReceiptTargetLease *lease = NULL;
  WyctlPublicationReceiptTargetKind kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  g_autofree gchar *destination_path = NULL;
  g_autofree gchar *secret = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText sensitive = {.text = secret,.len = strlen (secret) };
  gboolean replayed = FALSE;
  ReceiptTargetSyncFault sync_fault = {
    .fail_point = WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE,
  };

  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
          &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &sensitive, &receipt,
          &result, &replayed), ==, WYRELOG_E_OK);
  wyctl_publication_result_clear (&result);
  destination_path = g_build_filename (fixture.dir, planned.destination, NULL);

  g_assert_cmpint (wyctl_publication_posix_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, FALSE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (lease);
  g_assert_cmpint (kind, ==, WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_inspect
      (&fixture.backend, lease, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          &sensitive, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);
  wyctl_publication_posix_backend_set_receipt_target_sync_hook
      (&fixture.backend, receipt_target_sync_fault, &sync_fault);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_commit
      (&fixture.backend, lease, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          &sensitive, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN);
  g_assert_cmpuint
      (sync_fault.hits[WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE], ==, 1);
  g_assert_cmpuint
      (sync_fault.hits[WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY], ==, 1);
  wyctl_publication_posix_backend_set_receipt_target_sync_hook
      (&fixture.backend, NULL, NULL);
  wyctl_publication_result_clear (&result);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_inspect
      (&fixture.backend, lease, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          &sensitive, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (result.exact_identity);
  wyctl_publication_result_clear (&result);

  memset (&sync_fault, 0, sizeof sync_fault);
  sync_fault.fail_point = WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY;
  wyctl_publication_posix_backend_set_receipt_target_sync_hook
      (&fixture.backend, receipt_target_sync_fault, &sync_fault);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_inspect
      (&fixture.backend, lease, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          &sensitive, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN);
  g_assert_true (result.exact_identity);
  g_assert_cmpuint
      (sync_fault.hits[WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE], ==, 1);
  g_assert_cmpuint
      (sync_fault.hits[WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY], ==, 1);
  wyctl_publication_posix_backend_set_receipt_target_sync_hook
      (&fixture.backend, NULL, NULL);
  wyctl_publication_posix_receipt_target_release (&fixture.backend, lease);
  lease = NULL;

  g_assert_cmpint (g_remove (destination_path), ==, 0);
  g_assert_true (g_file_set_contents (destination_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (destination_path, 0600), ==, 0);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, TRUE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_null (lease);
  g_assert_cmpint (kind, ==,
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN);

  g_assert_cmpint (g_remove (destination_path), ==, 0);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_receipt_target_pin_rejects_namespace_replacement (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlPublicationReceiptTargetLease *lease = NULL;
  WyctlPublicationReceiptTargetKind kind =
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN;
  g_autofree gchar *secret = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText sensitive = {.text = secret,.len = strlen (secret) };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *moved_path = NULL;
  g_autofree gchar *destination_path = NULL;
  g_autofree gchar *foreign_contents = NULL;
  gboolean replayed = FALSE;

  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
          &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &sensitive, &receipt,
          &result, &replayed), ==, WYRELOG_E_OK);
  wyctl_publication_result_clear (&result);
  stage_path = g_build_filename (fixture.dir, planned.stage_basename, NULL);
  moved_path = g_build_filename (fixture.dir, "pinned-original", NULL);
  destination_path = g_build_filename (fixture.dir, planned.destination, NULL);

  g_assert_cmpint (wyctl_publication_posix_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, FALSE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (lease);
  g_assert_cmpint (kind, ==, WYCTL_PUBLICATION_RECEIPT_TARGET_STAGE);

  /* Pin-first barrier: replace the basename only after the exact inode is
   * retained by the lease.  Inspect reads the pinned inode, then rejects the
   * changed namespace binding without mutating either file. */
  g_assert_cmpint (g_rename (stage_path, moved_path), ==, 0);
  g_assert_true (g_file_set_contents (stage_path, "foreign", -1, NULL));
  g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);
  g_assert_cmpint (wyctl_publication_posix_receipt_target_inspect
      (&fixture.backend, lease, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
          &sensitive, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (g_file_test (destination_path, G_FILE_TEST_EXISTS));
  g_assert_true (g_file_get_contents (stage_path, &foreign_contents, NULL,
          NULL));
  g_assert_cmpstr (foreign_contents, ==, "foreign");
  wyctl_publication_posix_receipt_target_release (&fixture.backend, lease);
  lease = NULL;

  /* Replacement-first barrier: the same foreign basename is rejected before
   * any lease can be returned. */
  g_assert_cmpint (wyctl_publication_posix_receipt_target_acquire
      (&fixture.backend, &planned, &receipt, FALSE, &lease, &kind), ==,
      WYRELOG_E_OK);
  g_assert_null (lease);
  g_assert_cmpint (kind, ==,
      WYCTL_PUBLICATION_RECEIPT_TARGET_FOREIGN_OR_UNCERTAIN);

  g_assert_cmpint (g_remove (stage_path), ==, 0);
  g_assert_cmpint (g_remove (moved_path), ==, 0);
  wyctl_publication_result_clear (&result);
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

static void
test_stage_exact_crash_retry_returns_same_receipt (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt first = { 0 };
  WyctlPublicationReceipt replay = { 0 };
  WyctlPublicationResult result = { 0 };
  g_autofree gchar *secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText secret = {.text = secret_text,.len = strlen (secret_text)
  };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *before = NULL;
  g_autofree gchar *after = NULL;
  gsize before_len = 0;
  gsize after_len = 0;
  struct stat before_st = { 0 };
  struct stat after_st = { 0 };
  gboolean replayed = TRUE;

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  stage_path = g_build_filename (fixture.dir, planned.stage_basename, NULL);

  g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
          &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &first,
          &result, &replayed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_true (wyctl_publication_receipt_is_valid (&first));
  g_assert_cmpint (g_stat (stage_path, &before_st), ==, 0);
  g_assert_true (g_file_get_contents (stage_path, &before, &before_len, NULL));

  wyctl_publication_result_clear (&result);
  g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
          &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &replay,
          &result, &replayed), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_cmpint (result.kind, ==, WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
  g_assert_cmpstr (replay.stage_identity, ==, first.stage_identity);
  g_assert_cmpint (g_stat (stage_path, &after_st), ==, 0);
  g_assert_cmpuint ((guint64) after_st.st_ino, ==, (guint64) before_st.st_ino);
  g_assert_true (g_file_get_contents (stage_path, &after, &after_len, NULL));
  g_assert_cmpuint (after_len, ==, before_len);
  g_assert_cmpmem (after, after_len, before, before_len);

  g_assert_cmpint (g_remove (stage_path), ==, 0);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&replay);
  wyctl_publication_receipt_clear (&first);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
}

static void
test_stage_exact_partial_stage_is_never_overwritten (void)
{
  g_auto (Fixture) fixture = { 0 };
  WyctlPublicationPlan request = { 0 };
  WyctlPublicationPlan planned = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  g_autofree gchar *secret_text = g_strnfill
      (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
  WyctlSensitiveText secret = {.text = secret_text,.len = strlen (secret_text)
  };
  g_autofree gchar *stage_path = NULL;
  g_autofree gchar *contents = NULL;
  gsize contents_len = 0;
  gboolean replayed = TRUE;

  fixture_init (&fixture);
  g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
          fixture.dir, &request), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
          &planned), ==, WYRELOG_E_OK);
  stage_path = g_build_filename (fixture.dir, planned.stage_basename, NULL);
  g_assert_true (g_file_set_contents (stage_path, "partial", -1, NULL));
  g_assert_cmpint (g_chmod (stage_path, 0600), ==, 0);

  g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
          &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &receipt,
          &result, &replayed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_cmpint (result.kind, ==,
      WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN);
  g_assert_false (wyctl_publication_receipt_is_valid (&receipt));
  g_assert_true (g_file_get_contents (stage_path, &contents, &contents_len,
          NULL));
  g_assert_cmpuint (contents_len, ==, strlen ("partial"));
  g_assert_cmpmem (contents, contents_len, "partial", strlen ("partial"));

  g_assert_cmpint (g_remove (stage_path), ==, 0);
  wyctl_publication_result_clear (&result);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_publication_plan_clear (&planned);
  wyctl_publication_plan_clear (&request);
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
    g_auto (Fixture) fixture = { 0 };
    WyctlPublicationPlan request = { 0 };
    WyctlPublicationPlan planned = { 0 };
    WyctlPublicationReceipt receipt = { 0 };
    WyctlPublicationResult result = { 0 };
    g_autofree gchar *secret_text = g_strnfill
        (WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN, 'A');
    WyctlSensitiveText secret = {.text = secret_text,.len = strlen (secret_text)
    };
    StageFault fault = {.target = points[i],.action =
          WYCTL_PUBLICATION_STAGE_EXACT_CRASH
    };
    g_autofree gchar *stage_path = NULL;
    gboolean replayed = FALSE;

    fixture_init (&fixture);
    g_assert_cmpint (wyctl_publication_plan_create ("credential.txt",
            fixture.dir, &request), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyctl_publication_posix_plan (&fixture.backend, &request,
            &planned), ==, WYRELOG_E_OK);
    stage_path = g_build_filename (fixture.dir, planned.stage_basename, NULL);
    wyctl_publication_posix_backend_set_stage_exact_hook (&fixture.backend,
        stage_fault_hook, &fault);

    g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
            &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &receipt,
            &result, &replayed), ==, WYRELOG_E_IO);
    g_assert_cmpuint (fault.hits[points[i]], ==, 1);
    g_assert_false (wyctl_publication_receipt_is_valid (&receipt));
    if (points[i] < WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED) {
      g_assert_false (g_file_test (stage_path, G_FILE_TEST_EXISTS));
      g_assert_cmpuint (count_stage_temps (fixture.dir, &planned), ==, 1);
    } else {
      g_assert_true (g_file_test (stage_path, G_FILE_TEST_EXISTS));
    }

    wyctl_publication_posix_backend_set_stage_exact_hook (&fixture.backend,
        NULL, NULL);
    wyctl_publication_result_clear (&result);
    g_assert_cmpint (wyctl_publication_posix_stage_exact (&fixture.backend,
            &planned, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv", &secret, &receipt,
            &result, &replayed), ==, WYRELOG_E_OK);
    g_assert_cmpint (result.kind, ==,
        WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE);
    g_assert_cmpuint (count_stage_temps (fixture.dir, &planned), ==, 0);
    g_assert_cmpint (replayed, ==,
        points[i] >= WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED);

    g_assert_cmpint (g_remove (stage_path), ==, 0);
    wyctl_publication_result_clear (&result);
    wyctl_publication_receipt_clear (&receipt);
    wyctl_publication_plan_clear (&planned);
    wyctl_publication_plan_clear (&request);
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/publication/posix/plan-prepare",
      test_plan_and_prepare);
  g_test_add_func ("/wyctl/publication/posix/roundtrip",
      test_commit_inspect_cleanup_roundtrip);
  g_test_add_func ("/wyctl/publication/posix/receipt-target-lease",
      test_receipt_target_lease_roundtrip_and_foreign_identity);
  g_test_add_func ("/wyctl/publication/posix/receipt-target-replacement-race",
      test_receipt_target_pin_rejects_namespace_replacement);
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
  g_test_add_func ("/wyctl/publication/posix/stage-exact-crash-retry",
      test_stage_exact_crash_retry_returns_same_receipt);
  g_test_add_func ("/wyctl/publication/posix/stage-exact-partial-no-overwrite",
      test_stage_exact_partial_stage_is_never_overwritten);
  g_test_add_func ("/wyctl/publication/posix/stage-exact-fault-barriers",
      test_stage_exact_fault_barriers_recover_without_partial_stage);
  return g_test_run ();
}
