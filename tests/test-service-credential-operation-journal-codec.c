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
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .expected_generation = 0,
    .successor_generation = 1,
    .expires_at_us = 200,
    .created_at_us = 100,
    .updated_at_us = 100,
    .attempts = 0,
  };
  for (guint i = 0; i < sizeof record.escrow_binding_digest; i++)
    record.escrow_binding_digest[i] = (guint8) (i + 1);
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
test_publication_planned_roundtrip (void)
{
  g_assert_cmpint (WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED, ==,
      3);
  g_assert_cmpint (WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL, ==, 7);
  g_assert_cmpint (WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED, ==, 8);
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) replay = NULL;
  input.state = WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED;
  input.publication_receipt_version = 1;
  input.reservation_id = g_strdup ("reservation");
  input.stage_basename = g_strdup ("stage");
  input.publication_receipt_id = g_strdup ("receipt-protocol-id");
  g_assert_cmpstr (input.stage_identity, ==, "");
  g_assert_true (wyl_service_credential_operation_record_is_valid (&input));
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  g_assert_cmpint (output.state, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED);
  g_assert_cmpstr (output.parent_identity, ==, input.parent_identity);
  g_assert_cmpstr (output.reservation_id, ==, input.reservation_id);
  g_assert_cmpstr (output.stage_basename, ==, input.stage_basename);
  g_assert_cmpstr (output.stage_identity, ==, "");
  g_assert_cmpstr (output.publication_receipt_id, ==,
      input.publication_receipt_id);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&output,
          &replay), ==, WYRELOG_E_OK);
  g_assert_true (g_bytes_equal (encoded, replay));

  g_clear_pointer (&output.stage_identity, g_free);
  output.stage_identity = g_strdup ("too-early");
  g_assert_false (wyl_service_credential_operation_record_is_valid (&output));
  g_clear_pointer (&output.stage_identity, g_free);
  output.state = WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED;
  g_assert_false (wyl_service_credential_operation_record_is_valid (&output));
  wyl_service_credential_operation_record_clear (&output);
  wyl_service_credential_operation_record_clear (&input);
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
  prior_version = g_memdup2 (data, len);
  prior_version[8] = 0;
  prior_version[9] = 0;
  prior_version[10] = 0;
  prior_version[11] = 4;
  GBytes *v4 = g_bytes_new_take (prior_version, len);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (v4,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  g_bytes_unref (v4);
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

static void
test_decode_rejects_malformed_destination (void)
{
  static const gchar valid[] = "credentials.json";
  static const gchar invalid[] = "nested/file.json";
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) malformed = NULL;
  gsize len;
  const guint8 *data;
  guint8 *copy;
  gboolean replaced = FALSE;

  G_STATIC_ASSERT (sizeof valid == sizeof invalid);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  data = g_bytes_get_data (encoded, &len);
  copy = g_memdup2 (data, len);
  for (gsize i = 0; i + sizeof valid - 1 <= len; i++) {
    if (memcmp (copy + i, valid, sizeof valid - 1) == 0) {
      memcpy (copy + i, invalid, sizeof invalid - 1);
      replaced = TRUE;
      break;
    }
  }
  g_assert_true (replaced);
  malformed = g_bytes_new_take (copy, len);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (malformed,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  g_assert_null (output.destination);

  wyl_service_credential_operation_record_clear (&output);
  wyl_service_credential_operation_record_clear (&input);
}

static guint32
test_get_u32 (const guint8 *value)
{
  return ((guint32) value[0] << 24) | ((guint32) value[1] << 16)
      | ((guint32) value[2] << 8) | value[3];
}

static void
test_decode_accepts_255_and_rejects_256_byte_destination (void)
{
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autofree gchar *max_leaf = g_strnfill (255, 'a');
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) oversized = NULL;
  g_autoptr (GByteArray) bytes = g_byte_array_new ();
  const guint8 *data;
  gsize destination_length_offset;
  gsize len;
  gsize offset = 24;

  g_free (input.destination);
  input.destination = g_strdup (max_leaf);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  g_assert_cmpstr (output.destination, ==, max_leaf);
  wyl_service_credential_operation_record_clear (&output);

  data = g_bytes_get_data (encoded, &len);
  for (guint field = 0; field < 4; field++) {
    guint32 field_len = test_get_u32 (data + offset);
    offset += 4 + field_len;
  }
  destination_length_offset = offset;
  g_assert_cmpuint (test_get_u32 (data + destination_length_offset), ==, 255);
  g_byte_array_append (bytes, data, destination_length_offset);
  {
    const guint8 length_256[4] = { 0, 0, 1, 0 };
    g_byte_array_append (bytes, length_256, sizeof length_256);
  }
  g_byte_array_append (bytes, data + destination_length_offset + 4, 255);
  g_byte_array_append (bytes, (const guint8 *) "a", 1);
  g_byte_array_append (bytes, data + destination_length_offset + 4 + 255,
      len - destination_length_offset - 4 - 255);
  oversized = g_byte_array_free_to_bytes (g_steal_pointer (&bytes));
  g_assert_cmpint (wyl_service_credential_operation_record_decode (oversized,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.destination);

  wyl_service_credential_operation_record_clear (&output);
  wyl_service_credential_operation_record_clear (&input);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/operation-journal/roundtrip", test_roundtrip);
  g_test_add_func ("/operation-journal/publication-planned-roundtrip",
      test_publication_planned_roundtrip);
  g_test_add_func ("/operation-journal/rejects-trailing",
      test_rejects_trailing_and_unknown);
  g_test_add_func ("/operation-journal/rejects-invalid",
      test_rejects_invalid_record);
  g_test_add_func ("/operation-journal/rejects-malformed-destination-decode",
      test_decode_rejects_malformed_destination);
  g_test_add_func ("/operation-journal/destination-length-boundary",
      test_decode_accepts_255_and_rejects_256_byte_destination);
  return g_test_run ();
}
