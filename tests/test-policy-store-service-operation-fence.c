/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"

static const guint8 issue_expected_transcript[] =
    "\x00\x00\x00\x2d"
    "wyrelog.service-credential-operation-fence.v1"
    "\x01\x01"
    "\x00\x00\x00\x0f" "svc:jobs:worker" "\x00\x00\x00\x08" "tenant-a";

static const guint8 issue_expected_fingerprint[] = {
  0x83, 0x7c, 0xd3, 0x54, 0xec, 0xae, 0x23, 0x55,
  0x4b, 0xba, 0x18, 0xf8, 0x89, 0x77, 0xac, 0xe6,
  0x5c, 0x57, 0x3d, 0x16, 0x38, 0x27, 0x42, 0x22,
  0xa2, 0x63, 0xf0, 0x8a, 0x90, 0xac, 0xb3, 0xd4,
};

static const guint8 rotate_expected_transcript[] =
    "\x00\x00\x00\x2d"
    "wyrelog.service-credential-operation-fence.v1"
    "\x01\x02" "\x00\x00\x00\x1f" "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv";

static const guint8 rotate_expected_fingerprint[] = {
  0x09, 0x20, 0x63, 0xea, 0xaa, 0x86, 0x52, 0x6c,
  0x6b, 0x25, 0xa5, 0x26, 0xf9, 0xd6, 0x94, 0x76,
  0xb9, 0x4f, 0x95, 0xd2, 0x6f, 0x0a, 0xdf, 0xc9,
  0xbc, 0xa1, 0x19, 0x04, 0x86, 0x96, 0xee, 0xb2,
};

static void
assert_vector (WylServiceCredentialOperationKind operation,
    const gchar *subject_id, const gchar *tenant_id,
    const gchar *old_credential_id, const guint8 *expected_transcript,
    gsize expected_transcript_len, const guint8 *expected_fingerprint)
{
  g_autoptr (GBytes) transcript = NULL;
  guint8 fingerprint[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES];
  wyrelog_error_t rc;
  if (operation == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    rc = wyl_policy_store_service_credential_operation_fingerprint
        (1, 1, subject_id, strlen (subject_id), tenant_id, strlen (tenant_id),
        NULL, 0, &transcript, fingerprint);
  } else {
    rc = wyl_policy_store_service_credential_operation_fingerprint
        (1, 2, NULL, 0, NULL, 0, old_credential_id,
        strlen (old_credential_id), &transcript, fingerprint);
  }
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);

  gsize transcript_len = 0;
  const guint8 *transcript_bytes = g_bytes_get_data (transcript,
      &transcript_len);
  g_assert_cmpuint (transcript_len, ==, expected_transcript_len);
  g_assert_cmpmem (transcript_bytes, transcript_len, expected_transcript,
      expected_transcript_len);
  g_assert_cmpmem (fingerprint, sizeof fingerprint, expected_fingerprint,
      WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES);

  guint8 direct_fingerprint[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES];
  if (operation == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    g_assert_cmpint (wyl_policy_store_service_credential_operation_fingerprint
        (1, 1, subject_id, strlen (subject_id), tenant_id,
            strlen (tenant_id), NULL, 0, NULL, direct_fingerprint), ==,
        WYRELOG_E_OK);
  } else {
    g_assert_cmpint (wyl_policy_store_service_credential_operation_fingerprint
        (1, 2, NULL, 0, NULL, 0, old_credential_id,
            strlen (old_credential_id), NULL, direct_fingerprint), ==,
        WYRELOG_E_OK);
  }
  g_assert_cmpmem (direct_fingerprint, sizeof direct_fingerprint,
      expected_fingerprint, WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES);
}

static void
test_issue_and_rotate_vectors (void)
{
  assert_vector (WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE, "svc:jobs:worker",
      "tenant-a", NULL, issue_expected_transcript,
      sizeof issue_expected_transcript - 1, issue_expected_fingerprint);
  assert_vector (WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE,
      NULL, NULL, "wlc_0ujtsYcgvSTl8PAuAdqWYSMnLOv",
      rotate_expected_transcript, sizeof rotate_expected_transcript - 1,
      rotate_expected_fingerprint);
}

static void
test_framed_collision_pair (void)
{
  guint8 first[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES];
  guint8 second[WYL_POLICY_STORE_OPERATION_FINGERPRINT_BYTES];
  g_assert_cmpint (wyl_policy_store_service_credential_operation_fingerprint
      (1, 1, "svc:jobs:worker", strlen ("svc:jobs:worker"), "tenant-a",
          strlen ("tenant-a"), NULL, 0, NULL, first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_service_credential_operation_fingerprint
      (1, 1, "svc:jobs:worke", strlen ("svc:jobs:worke"), "rtenant-a",
          strlen ("rtenant-a"), NULL, 0, NULL, second), ==, WYRELOG_E_OK);
  g_assert_false (memcmp (first, second, sizeof first) == 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/service-operation-fence/vectors",
      test_issue_and_rotate_vectors);
  g_test_add_func ("/policy/service-operation-fence/collision-pair",
      test_framed_collision_pair);
  return g_test_run ();
}
