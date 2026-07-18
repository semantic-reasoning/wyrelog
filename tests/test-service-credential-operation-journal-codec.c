/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "auth/service-credential-operation-journal-private.h"
#include "auth/service-credential-private.h"
#include "wyl-request-id-private.h"

static WylServiceCredentialOperationRecord
record_new (gchar request_id[WYL_REQUEST_ID_STRING_BUF],
    gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  g_assert_cmpint (wyl_request_id_new (request_id, WYL_REQUEST_ID_STRING_BUF),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_id_new (credential_id,
          WYL_SERVICE_CREDENTIAL_ID_BUF), ==, WYRELOG_E_OK);
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    .operation_id = g_strdup ("operation-1"),
    .request_id = g_strdup (request_id),
    .subject_id = g_strdup ("user-1"),
    .tenant_id = g_strdup ("tenant-1"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup ("admin"),
    .stage_identity = g_strdup (""),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup (credential_id),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 1,
    .expires_at_us = 200,
    .created_at_us = 100,
    .updated_at_us = 100,
    .attempts = 0,
  };
  return record;
}

static void
test_roundtrip (void)
{
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  GBytes *bytes = NULL;
  g_assert_true (wyl_service_credential_operation_record_is_valid (&input));
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &bytes), ==, WYRELOG_E_OK);
  g_assert_nonnull (bytes);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (bytes,
          &output), ==, WYRELOG_E_OK);
  g_assert_cmpstr (output.request_id, ==, input.request_id);
  g_assert_cmpstr (output.destination, ==, input.destination);
  g_assert_cmpstr (output.actor_subject_id, ==, input.actor_subject_id);
  g_assert_cmpuint (output.successor_generation, ==, 1);
  g_assert_cmpuint (output.expected_generation, ==, 0);
  g_assert_cmpint (output.expires_at_us, ==, input.expires_at_us);
  g_assert_cmpint (output.state, ==, input.state);
  g_assert_true (g_bytes_get_size (bytes) <
      WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES);
  wyl_service_credential_operation_record_clear (&input);
  wyl_service_credential_operation_record_clear (&output);
  g_bytes_unref (bytes);
}

static void
test_rejects_trailing_and_unknown (void)
{
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  GBytes *encoded = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  gsize len = 0;
  const guint8 *data = g_bytes_get_data (encoded, &len);
  guint8 *trailing = g_malloc (len + 1);
  memcpy (trailing, data, len);
  trailing[len] = 0xff;
  GBytes *bad = g_bytes_new_take (trailing, len + 1);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_assert_cmpint (wyl_service_credential_operation_record_decode (bad,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  guint8 *prior_version = g_memdup2 (data, len);
  prior_version[8] = 0;
  prior_version[9] = 0;
  prior_version[10] = 0;
  prior_version[11] = 1;
  GBytes *prior = g_bytes_new_take (prior_version, len);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (prior,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  prior_version = g_memdup2 (data, len);
  prior_version[8] = 0;
  prior_version[9] = 0;
  prior_version[10] = 0;
  prior_version[11] = 2;
  GBytes *v2 = g_bytes_new_take (prior_version, len);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (v2,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  prior_version = g_memdup2 (data, len);
  prior_version[8] = 0;
  prior_version[9] = 0;
  prior_version[10] = 0;
  prior_version[11] = 3;
  GBytes *v3 = g_bytes_new_take (prior_version, len);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (v3,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  g_bytes_unref (v3);
  g_bytes_unref (v2);
  g_bytes_unref (prior);
  g_bytes_unref (bad);
  g_bytes_unref (encoded);
  wyl_service_credential_operation_record_clear (&input);
}

static void
test_rejects_invalid_record (void)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED,
    .operation_id = (gchar *) "operation-1",
    .request_id = (gchar *) "not-a-request-id",
    .subject_id = (gchar *) "user-1",
    .tenant_id = (gchar *) "tenant-1",
    .destination = (gchar *) "credentials.json",
    .parent_identity = (gchar *) "parent",
    .actor_subject_id = (gchar *) "admin",
    .expires_at_us = 1,
    .created_at_us = 1,
    .updated_at_us = 1,
  };
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
  GBytes *bytes = NULL;
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&record,
          &bytes), ==, WYRELOG_E_INVALID);
  g_assert_null (bytes);

  record.request_id = (gchar *) "000000000000000000000000000";
  record.destination = (gchar *) "../outside";
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
  record.request_id = (gchar *) "000000000000000000000000000";
  record.destination = (gchar *) "nested\\file";
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
  record.destination = (gchar *) "credentials.json";
  record.actor_subject_id = (gchar *) "";
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
  g_autofree gchar *long_actor = g_strnfill (129, 'a');
  record.actor_subject_id = long_actor;
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
  gchar malformed_actor[] = { (gchar) 0xff, '\0' };
  record.actor_subject_id = malformed_actor;
  g_assert_false (wyl_service_credential_operation_record_is_valid (&record));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-journal/roundtrip", test_roundtrip);
  g_test_add_func ("/operation-journal/rejects-trailing",
      test_rejects_trailing_and_unknown);
  g_test_add_func ("/operation-journal/rejects-invalid",
      test_rejects_invalid_record);
  return g_test_run ();
}
