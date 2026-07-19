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
test_put_u32 (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static void
golden_append_u32 (GByteArray *bytes, guint32 value)
{
  guint8 encoded[4];
  test_put_u32 (encoded, value);
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
golden_append_u64 (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8] = {
    (guint8) (value >> 56), (guint8) (value >> 48),
    (guint8) (value >> 40), (guint8) (value >> 32),
    (guint8) (value >> 24), (guint8) (value >> 16),
    (guint8) (value >> 8), (guint8) value,
  };
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
golden_append_text (GByteArray *bytes, const gchar *value)
{
  guint32 len = (guint32) strlen (value);
  golden_append_u32 (bytes, len);
  g_byte_array_append (bytes, (const guint8 *) value, len);
}

static GBytes *
golden_nonterminal_v5_fixture (guint32 state)
{
  const gboolean prepared = state == 1;
  const gboolean receipt = state == 8 || state == 3 || state == 4 || state == 5;
  const gboolean staged = state == 3 || state == 4 || state == 5;
  GByteArray *bytes = g_byte_array_new ();
  static const guint8 digest[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  };

  /* Frozen origin/main v5 wire contract: magic, version, kind, durable state,
   * field count, then the exact 17-field order and scalar trailer. */
  g_byte_array_append (bytes, (const guint8 *) "WYLJNL01", 8);
  golden_append_u32 (bytes, 5);
  golden_append_u32 (bytes, 1);
  golden_append_u32 (bytes, state);
  golden_append_u32 (bytes, 17);
  golden_append_text (bytes, "operation-1");
  golden_append_text (bytes, "000000000000000000000000000");
  golden_append_text (bytes, "user-1");
  golden_append_text (bytes, "tenant-1");
  golden_append_text (bytes, "credentials.json");
  golden_append_text (bytes, "parent-fingerprint");
  golden_append_text (bytes, "admin");
  golden_append_u32 (bytes, receipt ? 1 : 0);
  golden_append_text (bytes, receipt ? "reservation" : "");
  golden_append_text (bytes, receipt ? "stage" : "");
  golden_append_text (bytes, staged ? "stage-identity" : "");
  golden_append_text (bytes, "");
  golden_append_text (bytes, prepared ? "" : "wlc_000000000000000000000000000");
  golden_append_text (bytes, "01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  g_byte_array_append (bytes, digest, sizeof digest);
  golden_append_text (bytes, receipt ? "receipt" : "");
  golden_append_text (bytes, "");
  golden_append_u64 (bytes, 0);
  golden_append_u64 (bytes, prepared ? 0 : 1);
  golden_append_u64 (bytes, 200);
  golden_append_u64 (bytes, 100);
  golden_append_u64 (bytes, 100);
  golden_append_u32 (bytes, 0);
  return g_byte_array_free_to_bytes (bytes);
}

static WylServiceCredentialOperationRecord
golden_nonterminal_v5_record (WylServiceCredentialOperationState state)
{
  WylServiceCredentialOperationRecord record = {
    .version = WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION,
    .kind = WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE,
    .state = state,
    .operation_id = g_strdup ("operation-1"),
    .request_id = g_strdup ("000000000000000000000000000"),
    .subject_id = g_strdup ("user-1"),
    .tenant_id = g_strdup ("tenant-1"),
    .destination = g_strdup ("credentials.json"),
    .parent_identity = g_strdup ("parent-fingerprint"),
    .actor_subject_id = g_strdup ("admin"),
    .stage_identity = g_strdup (""),
    .old_credential_id = g_strdup (""),
    .successor_credential_id = g_strdup ("wlc_000000000000000000000000000"),
    .escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991"),
    .publication_receipt_id = g_strdup (""),
    .successor_generation = 1,
    .expires_at_us = 200,
    .created_at_us = 100,
    .updated_at_us = 100,
  };
  for (guint i = 0; i < sizeof record.escrow_binding_digest; i++)
    record.escrow_binding_digest[i] = (guint8) (i + 1);
  if (state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED) {
    g_clear_pointer (&record.successor_credential_id, g_free);
    record.successor_generation = 0;
  } else if (state != WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED) {
    record.publication_receipt_version = 1;
    record.reservation_id = g_strdup ("reservation");
    record.stage_basename = g_strdup ("stage");
    g_free (record.publication_receipt_id);
    record.publication_receipt_id = g_strdup ("receipt");
    if (state != WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED) {
      g_free (record.stage_identity);
      record.stage_identity = g_strdup ("stage-identity");
    }
  }
  return record;
}

static gsize
terminal_reason_length_offset (const guint8 *data, gsize len)
{
  gsize offset = 24;
  for (guint field = 0; field < 7; field++) {
    g_assert_cmpuint (len - offset, >=, 4);
    guint32 field_len = test_get_u32 (data + offset);
    offset += 4 + field_len;
    g_assert_cmpuint (offset, <=, len);
  }
  g_assert_cmpuint (len - offset, >=, 4);
  offset += 4;                  /* publication_receipt_version */
  for (guint field = 0; field < 6; field++) {
    g_assert_cmpuint (len - offset, >=, 4);
    guint32 field_len = test_get_u32 (data + offset);
    offset += 4 + field_len;
    g_assert_cmpuint (offset, <=, len);
  }
  g_assert_cmpuint (len - offset, >=, 32);
  offset += 32;                 /* escrow_binding_digest */
  g_assert_cmpuint (len - offset, >=, 4);
  guint32 receipt_len = test_get_u32 (data + offset);
  offset += 4 + receipt_len;
  g_assert_cmpuint (len - offset, >=, 4);
  return offset;
}

static GBytes *
replace_terminal_reason (GBytes *encoded, const guint8 *reason,
    guint32 reason_len)
{
  gsize len = 0;
  const guint8 *data = g_bytes_get_data (encoded, &len);
  gsize length_offset = terminal_reason_length_offset (data, len);
  guint32 old_len = test_get_u32 (data + length_offset);
  g_assert_cmpuint (length_offset + 4 + old_len, <=, len);
  GByteArray *bytes = g_byte_array_sized_new (len - old_len + reason_len);
  g_byte_array_append (bytes, data, length_offset);
  guint8 encoded_len[4];
  test_put_u32 (encoded_len, reason_len);
  g_byte_array_append (bytes, encoded_len, sizeof encoded_len);
  if (reason_len != 0)
    g_byte_array_append (bytes, reason, reason_len);
  g_byte_array_append (bytes, data + length_offset + 4 + old_len,
      len - length_offset - 4 - old_len);
  return g_byte_array_free_to_bytes (bytes);
}

static void
test_typed_reason_codec (void)
{
  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord input = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded = NULL;
  input.state = WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED;
  input.terminal_reason = g_strdup
      ("oar.v1:server-committed:successor-expired");
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  g_assert_cmpstr (output.terminal_reason, ==, input.terminal_reason);
  wyl_service_credential_operation_record_clear (&output);

  const guint8 malformed[] = { 0xff };
  g_autoptr (GBytes) malformed_encoded = replace_terminal_reason (encoded,
      malformed, sizeof malformed);
  g_assert_cmpint (wyl_service_credential_operation_record_decode
      (malformed_encoded, &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);

  g_autofree guint8 *oversized_reason = g_malloc0 (4097);
  memset (oversized_reason, 'x', 4097);
  g_autoptr (GBytes) oversized_encoded = replace_terminal_reason (encoded,
      oversized_reason, 4097);
  g_assert_cmpint (wyl_service_credential_operation_record_decode
      (oversized_encoded, &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);

  static const guint8 legacy_reason[] = "receipt-uncertain";
  g_autoptr (GBytes) legacy_encoded = replace_terminal_reason (encoded,
      legacy_reason, sizeof legacy_reason - 1);
  g_assert_cmpint (wyl_service_credential_operation_record_decode
      (legacy_encoded, &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);

  g_free (input.terminal_reason);
  input.terminal_reason = g_strdup
      ("oar.v1:publication-prepared:receipt-uncertain");
  g_assert_false (wyl_service_credential_operation_record_is_valid (&input));
  g_free (input.terminal_reason);
  input.terminal_reason = NULL;
  input.state = WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
  gchar terminal_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (terminal_request,
          sizeof terminal_request), ==, WYRELOG_E_OK);
  input.terminal_reason =
      wyl_service_credential_operation_terminal_reason_format
      (WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
      terminal_request);
  g_clear_pointer (&encoded, g_bytes_unref);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  g_assert_cmpstr (output.terminal_reason, ==, input.terminal_reason);
  wyl_service_credential_operation_record_clear (&output);
  g_free (input.terminal_reason);
  input.terminal_reason = g_strdup ("terminal.v1:not-committed");
  g_assert_false (wyl_service_credential_operation_record_is_valid (&input));

  g_autofree gchar *giant = g_strnfill (4097, 'x');
  WylServiceCredentialOperationState source =
      WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED;
  WylServiceCredentialOperationOarCause cause =
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD;
  g_assert_false (wyl_service_credential_operation_oar_reason_parse (giant,
          &source, &cause));
  g_assert_cmpint (source, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED);
  g_assert_cmpint (cause, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD);
  g_assert_false (wyl_service_credential_operation_oar_reason_parse
      ("oar.v1:prepared:receipt-foreign", &source, &cause));
  g_assert_false (wyl_service_credential_operation_oar_reason_parse
      ("oar.v1:server-committed:receipt-foreign", &source, &cause));
  g_assert_false (wyl_service_credential_operation_oar_reason_parse
      ("oar.v1:server-committed:successor-expired:extra", &source, &cause));

  const WylServiceCredentialOperationState sources[] = {
    WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED,
    WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED,
    WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED,
    WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED,
  };
  for (guint s = 0; s < G_N_ELEMENTS (sources); s++) {
    for (guint c = WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN;
        c <= WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING; c++) {
      WylServiceCredentialOperationOarCause matrix_cause =
          (WylServiceCredentialOperationOarCause) c;
      gboolean legal = sources[s] !=
          WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
          || (matrix_cause !=
          WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN
          && matrix_cause !=
          WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN);
      g_autofree gchar *reason =
          wyl_service_credential_operation_oar_reason_format (sources[s],
          matrix_cause);
      g_assert_cmpint (reason != NULL, ==, legal);
      if (legal) {
        WylServiceCredentialOperationState parsed_source = 0;
        WylServiceCredentialOperationOarCause parsed_cause = 0;
        g_assert_true (wyl_service_credential_operation_oar_reason_parse
            (reason, &parsed_source, &parsed_cause));
        g_assert_cmpint (parsed_source, ==, sources[s]);
        g_assert_cmpint (parsed_cause, ==, matrix_cause);
      }
    }
  }

  WylServiceCredentialOperationTerminalKind preserved_kind =
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED;
  g_autofree gchar *preserved_request = g_strdup ("preserved");
  g_assert_false (wyl_service_credential_operation_terminal_reason_parse
      ("terminal.v1:operator-revoke-and-wipe:not-canonical", &preserved_kind,
          &preserved_request));
  g_assert_cmpint (preserved_kind, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED);
  g_assert_cmpstr (preserved_request, ==, "preserved");
  gchar remediation_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (remediation_request,
          sizeof remediation_request), ==, WYRELOG_E_OK);
  g_autofree gchar *terminal_reason =
      wyl_service_credential_operation_terminal_reason_format
      (WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
      remediation_request);
  g_assert_true (wyl_service_credential_operation_terminal_reason_parse
      (terminal_reason, &preserved_kind, &preserved_request));
  g_assert_cmpint (preserved_kind, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE);
  g_assert_cmpstr (preserved_request, ==, remediation_request);

  g_clear_pointer (&preserved_request, g_free);
  preserved_request = g_strdup ("owned-not-committed-sentinel");
  g_assert_true (wyl_service_credential_operation_terminal_reason_parse
      ("terminal.v1:not-committed", &preserved_kind, &preserved_request));
  g_assert_cmpint (preserved_kind, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED);
  g_assert_null (preserved_request);
  preserved_request = g_strdup ("owned-file-published-sentinel");
  g_assert_true (wyl_service_credential_operation_terminal_reason_parse
      ("terminal.v1:file-published", &preserved_kind, &preserved_request));
  g_assert_cmpint (preserved_kind, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED);
  g_assert_null (preserved_request);

  g_free (input.terminal_reason);
  input.terminal_reason = g_malloc0 (2);
  input.terminal_reason[0] = (gchar) 0xff;
  input.state = WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
  g_assert_false (wyl_service_credential_operation_record_is_valid (&input));
  source = WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED;
  cause = WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD;
  g_assert_false (wyl_service_credential_operation_oar_reason_parse
      (input.terminal_reason, &source, &cause));
  g_assert_cmpint (source, ==, WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED);
  g_assert_cmpint (cause, ==,
      WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD);
  wyl_service_credential_operation_record_clear (&input);
}

static void
test_nonterminal_v5_byte_compatibility (void)
{
  const struct
  {
    WylServiceCredentialOperationState state;
    guint32 frozen_wire_state;
  } fixtures[] = {
    {WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED, 1},
    {WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED, 2},
    {WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED, 8},
    {WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED, 3},
    {WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED, 4},
    {WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED, 5},
  };
  for (guint i = 0; i < G_N_ELEMENTS (fixtures); i++) {
    WylServiceCredentialOperationRecord input =
        golden_nonterminal_v5_record (fixtures[i].state);
    WylServiceCredentialOperationRecord output =
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    g_autoptr (GBytes) encoded = NULL;
    g_autoptr (GBytes) expected =
        golden_nonterminal_v5_fixture (fixtures[i].frozen_wire_state);
    g_assert_cmpint (wyl_service_credential_operation_record_encode (&input,
            &encoded), ==, WYRELOG_E_OK);
    g_assert_true (g_bytes_equal (encoded, expected));
    g_assert_cmpint (wyl_service_credential_operation_record_decode (expected,
            &output), ==, WYRELOG_E_OK);
    g_assert_cmpuint (output.version, ==, 5);
    g_assert_cmpint (output.kind, ==, 1);
    g_assert_cmpint (output.state, ==, fixtures[i].state);
    wyl_service_credential_operation_record_clear (&output);
    wyl_service_credential_operation_record_clear (&input);
  }
}

static void
test_terminal_reason_shapes (void)
{
  static const guint8 not_committed_reason[] = "terminal.v1:not-committed";
  static const guint8 file_published_reason[] = "terminal.v1:file-published";

  gchar request_id[WYL_REQUEST_ID_STRING_BUF];
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  WylServiceCredentialOperationRecord record = record_new (request_id,
      credential_id);
  WylServiceCredentialOperationRecord output =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  g_autoptr (GBytes) encoded = NULL;
  g_autoptr (GBytes) malformed = NULL;

  record.state = WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
  g_clear_pointer (&record.successor_credential_id, g_free);
  record.successor_generation = 0;
  record.terminal_reason = g_strdup ((const gchar *) not_committed_reason);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&record,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_record_clear (&output);
  malformed = replace_terminal_reason (encoded, file_published_reason,
      sizeof file_published_reason - 1);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (malformed,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  wyl_service_credential_operation_record_clear (&record);

  record = record_new (request_id, credential_id);
  record.state = WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
  record.publication_receipt_version = 1;
  record.reservation_id = g_strdup ("reservation");
  record.stage_basename = g_strdup ("stage");
  g_free (record.stage_identity);
  record.stage_identity = g_strdup ("stage-identity");
  g_free (record.publication_receipt_id);
  record.publication_receipt_id = g_strdup ("receipt");
  record.terminal_reason = g_strdup ((const gchar *) file_published_reason);
  g_clear_pointer (&encoded, g_bytes_unref);
  g_clear_pointer (&malformed, g_bytes_unref);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&record,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_record_clear (&output);
  malformed = replace_terminal_reason (encoded, not_committed_reason,
      sizeof not_committed_reason - 1);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (malformed,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  wyl_service_credential_operation_record_clear (&record);

  record = record_new (request_id, credential_id);
  record.state = WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
  gchar remediation_request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (wyl_request_id_new (remediation_request,
          sizeof remediation_request), ==, WYRELOG_E_OK);
  record.terminal_reason =
      wyl_service_credential_operation_terminal_reason_format
      (WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE,
      remediation_request);
  g_clear_pointer (&encoded, g_bytes_unref);
  g_clear_pointer (&malformed, g_bytes_unref);
  g_assert_cmpint (wyl_service_credential_operation_record_encode (&record,
          &encoded), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (encoded,
          &output), ==, WYRELOG_E_OK);
  wyl_service_credential_operation_record_clear (&output);
  malformed = replace_terminal_reason (encoded, not_committed_reason,
      sizeof not_committed_reason - 1);
  g_assert_cmpint (wyl_service_credential_operation_record_decode (malformed,
          &output), ==, WYRELOG_E_POLICY);
  g_assert_null (output.request_id);
  wyl_service_credential_operation_record_clear (&record);
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
  g_test_add_func ("/operation-journal/typed-reason-codec",
      test_typed_reason_codec);
  g_test_add_func ("/operation-journal/nonterminal-v5-byte-compatibility",
      test_nonterminal_v5_byte_compatibility);
  g_test_add_func ("/operation-journal/terminal-reason-shapes",
      test_terminal_reason_shapes);
  return g_test_run ();
}
