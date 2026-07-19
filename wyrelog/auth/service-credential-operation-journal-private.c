/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-journal-private.h"

#include <chronoid/ksuid.h>
#include <sodium.h>
#include <string.h>

#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-id-private.h"

#define JOURNAL_MAGIC "WYLJNL01"
#define JOURNAL_MAGIC_LEN 8u
#define JOURNAL_FIELD_COUNT 17u

static void
put_u32 (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static void
put_u64 (guint8 out[8], guint64 value)
{
  for (guint i = 0; i < 8; i++)
    out[i] = (guint8) (value >> (56u - 8u * i));
}

static guint32
get_u32 (const guint8 *in)
{
  return ((guint32) in[0] << 24) | ((guint32) in[1] << 16)
      | ((guint32) in[2] << 8) | in[3];
}

static guint64
get_u64 (const guint8 *in)
{
  guint64 value = 0;
  for (guint i = 0; i < 8; i++)
    value = (value << 8) | in[i];
  return value;
}

static gboolean
text_is_valid (const gchar *value, gboolean required)
{
  if (value == NULL)
    return !required;
  gsize len = strlen (value);
  return (!required || len > 0)
      && len <= WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_TEXT
      && g_utf8_validate (value, len, NULL);
}

static gboolean
request_id_is_canonical (const gchar *value)
{
  if (value == NULL || strlen (value) != 27)
    return FALSE;
  chronoid_ksuid_t parsed;
  if (chronoid_ksuid_parse (&parsed, value, 27) != CHRONOID_KSUID_OK)
    return FALSE;
  gchar canonical[28];
  chronoid_ksuid_format (&parsed, canonical);
  canonical[27] = '\0';
  return memcmp (canonical, value, 27) == 0;
}

static gboolean
kind_is_valid (WylServiceCredentialOperationKind kind)
{
  return kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
      || kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE;
}

static gboolean
state_is_valid (WylServiceCredentialOperationState state)
{
  return state >= WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
      && state <= WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
}

static gboolean
escrow_id_is_canonical (const gchar *value)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return value != NULL && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_str_equal (value, canonical);
}

static gboolean
digest_is_zero (const guint8
    digest[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES])
{
  static const guint8
      zero[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES] =
      { 0 };
  return sodium_memcmp (digest, zero, sizeof zero) == 0;
}

static gboolean
destination_is_safe_relative_path (const gchar *value)
{
  if (value == NULL || value[0] == '\0' || value[0] == '/'
      || value[0] == '\\' || strchr (value, '\\') != NULL
      || strchr (value, ':') != NULL)
    return FALSE;
  const gchar *cursor = value;
  while (*cursor != '\0') {
    const gchar *slash = strchr (cursor, '/');
    gsize component_len = slash == NULL ? strlen (cursor)
        : (gsize) (slash - cursor);
    if (component_len == 0 || (component_len == 1 && cursor[0] == '.')
        || (component_len == 2 && cursor[0] == '.' && cursor[1] == '.'))
      return FALSE;
    cursor = slash == NULL ? cursor + component_len : slash + 1;
  }
  return TRUE;
}

gboolean
    wyl_service_credential_operation_record_is_valid
    (const WylServiceCredentialOperationRecord * record)
{
  if (record == NULL
      || record->version != WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION
      || !kind_is_valid (record->kind) || !state_is_valid (record->state)
      || !text_is_valid (record->operation_id, TRUE)
      || !request_id_is_canonical (record->request_id)
      || !text_is_valid (record->subject_id, TRUE)
      || !text_is_valid (record->tenant_id,
          record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE)
      || !text_is_valid (record->destination, TRUE)
      || !destination_is_safe_relative_path (record->destination)
      || !text_is_valid (record->parent_identity, TRUE)
      || !wyl_policy_service_actor_subject_is_valid (record->actor_subject_id)
      || record->publication_receipt_version > 1
      || !text_is_valid (record->reservation_id, FALSE)
      || !text_is_valid (record->stage_basename, FALSE)
      || !text_is_valid (record->stage_identity, FALSE)
      || !text_is_valid (record->old_credential_id,
          record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE)
      || !text_is_valid (record->successor_credential_id, FALSE)
      || !text_is_valid (record->publication_receipt_id, FALSE)
      || record->attempts > G_MAXINT32 || record->expires_at_us <= 0
      || record->created_at_us <= 0
      || record->updated_at_us < record->created_at_us)
    return FALSE;
  if (record->publication_receipt_version == 0
      && ((record->reservation_id != NULL && record->reservation_id[0] != '\0')
          || (record->stage_basename != NULL
              && record->stage_basename[0] != '\0')
          || (record->stage_identity != NULL
              && record->stage_identity[0] != '\0')
          || (record->publication_receipt_id != NULL
              && record->publication_receipt_id[0] != '\0')))
    return FALSE;
  if (record->publication_receipt_version == 1
      && (!text_is_valid (record->reservation_id, TRUE)
          || !text_is_valid (record->stage_basename, TRUE)
          || !text_is_valid (record->stage_identity, TRUE)
          || !text_is_valid (record->publication_receipt_id, TRUE)))
    return FALSE;
  if ((record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED
          || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED)
      && record->publication_receipt_version != 0)
    return FALSE;
  if ((record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
          || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
          || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED)
      && record->publication_receipt_version != 1)
    return FALSE;
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE
      && !wyl_service_credential_id_is_canonical (record->old_credential_id,
          strlen (record->old_credential_id)))
    return FALSE;
  if (record->successor_credential_id != NULL
      && record->successor_credential_id[0] != '\0'
      &&
      !wyl_service_credential_id_is_canonical (record->successor_credential_id,
          strlen (record->successor_credential_id)))
    return FALSE;
  if (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
      && record->old_credential_id != NULL
      && record->old_credential_id[0] != '\0')
    return FALSE;
  if (record->expected_generation > G_MAXINT64
      || record->successor_generation > G_MAXINT64)
    return FALSE;
  if ((record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
          && record->expected_generation != 0)
      || (record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE
          && record->expected_generation == 0))
    return FALSE;
  if (!escrow_id_is_canonical (record->escrow_id))
    return FALSE;
  if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED)
    return (record->successor_credential_id == NULL
        || record->successor_credential_id[0] == '\0')
        && record->successor_generation == 0
        && !text_is_valid (record->terminal_reason, TRUE);
  if (record->state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL
      && text_is_valid (record->terminal_reason, TRUE))
    return (record->successor_credential_id == NULL
        || record->successor_credential_id[0] == '\0')
        && record->successor_generation == 0;
  if (record->state >= WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED)
    return record->successor_credential_id != NULL
        && record->successor_credential_id[0] != '\0'
        && record->successor_generation > 0
        && !digest_is_zero (record->escrow_binding_digest)
        && ((record->state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL
            || record->state
            == WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED)
        == text_is_valid (record->terminal_reason, TRUE));
  return TRUE;
}

void wyl_service_credential_operation_record_clear
    (WylServiceCredentialOperationRecord * record)
{
  if (record == NULL)
    return;
  g_clear_pointer (&record->operation_id, g_free);
  g_clear_pointer (&record->request_id, g_free);
  g_clear_pointer (&record->subject_id, g_free);
  g_clear_pointer (&record->tenant_id, g_free);
  g_clear_pointer (&record->destination, g_free);
  g_clear_pointer (&record->parent_identity, g_free);
  g_clear_pointer (&record->actor_subject_id, g_free);
  g_clear_pointer (&record->reservation_id, g_free);
  g_clear_pointer (&record->stage_basename, g_free);
  g_clear_pointer (&record->stage_identity, g_free);
  g_clear_pointer (&record->old_credential_id, g_free);
  g_clear_pointer (&record->successor_credential_id, g_free);
  g_clear_pointer (&record->escrow_id, g_free);
  g_clear_pointer (&record->publication_receipt_id, g_free);
  g_clear_pointer (&record->terminal_reason, g_free);
  memset (record, 0, sizeof *record);
}

static void
append_u32 (GByteArray *bytes, guint32 value)
{
  guint8 encoded[4];
  put_u32 (encoded, value);
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_u64 (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8];
  put_u64 (encoded, value);
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_text (GByteArray *bytes, const gchar *value)
{
  guint32 len = value == NULL ? 0 : (guint32) strlen (value);
  append_u32 (bytes, len);
  if (len != 0)
    g_byte_array_append (bytes, (const guint8 *) value, len);
}

static void
append_fixed (GByteArray *bytes, const guint8 *value, gsize len)
{
  g_byte_array_append (bytes, value, len);
}

wyrelog_error_t
    wyl_service_credential_operation_record_encode
    (const WylServiceCredentialOperationRecord * record, GBytes ** out_bytes)
{
  if (out_bytes != NULL)
    *out_bytes = NULL;
  if (out_bytes == NULL
      || !wyl_service_credential_operation_record_is_valid (record))
    return WYRELOG_E_INVALID;
  GByteArray *bytes = g_byte_array_new ();
  g_byte_array_append (bytes, (const guint8 *) JOURNAL_MAGIC,
      JOURNAL_MAGIC_LEN);
  append_u32 (bytes, record->version);
  append_u32 (bytes, record->kind);
  append_u32 (bytes, record->state);
  append_u32 (bytes, JOURNAL_FIELD_COUNT);
  append_text (bytes, record->operation_id);
  append_text (bytes, record->request_id);
  append_text (bytes, record->subject_id);
  append_text (bytes, record->tenant_id);
  append_text (bytes, record->destination);
  append_text (bytes, record->parent_identity);
  append_text (bytes, record->actor_subject_id);
  append_u32 (bytes, record->publication_receipt_version);
  append_text (bytes, record->reservation_id);
  append_text (bytes, record->stage_basename);
  append_text (bytes, record->stage_identity);
  append_text (bytes, record->old_credential_id);
  append_text (bytes, record->successor_credential_id);
  append_text (bytes, record->escrow_id);
  append_fixed (bytes, record->escrow_binding_digest,
      sizeof record->escrow_binding_digest);
  append_text (bytes, record->publication_receipt_id);
  append_text (bytes, record->terminal_reason);
  append_u64 (bytes, record->expected_generation);
  append_u64 (bytes, record->successor_generation);
  append_u64 (bytes, (guint64) record->expires_at_us);
  append_u64 (bytes, (guint64) record->created_at_us);
  append_u64 (bytes, (guint64) record->updated_at_us);
  append_u32 (bytes, record->attempts);
  if (bytes->len > WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES) {
    g_byte_array_unref (bytes);
    return WYRELOG_E_INVALID;
  }
  *out_bytes = g_byte_array_free_to_bytes (bytes);
  return WYRELOG_E_OK;
}

static gboolean
read_text (const guint8 *data, gsize len, gsize *offset, gchar **out)
{
  if (*offset > len || len - *offset < 4)
    return FALSE;
  guint32 text_len = get_u32 (data + *offset);
  *offset += 4;
  if (text_len > WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_TEXT
      || text_len > len - *offset
      || memchr (data + *offset, '\0', text_len) != NULL
      || !g_utf8_validate ((const gchar *) data + *offset, text_len, NULL))
    return FALSE;
  *out = g_strndup ((const gchar *) data + *offset, text_len);
  *offset += text_len;
  return TRUE;
}

wyrelog_error_t
    wyl_service_credential_operation_record_decode
    (GBytes * bytes, WylServiceCredentialOperationRecord * out_record) {
  if (bytes == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;
  gsize len = 0;
  const guint8 *data = g_bytes_get_data (bytes, &len);
  if (data == NULL || len > WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES
      || len < JOURNAL_MAGIC_LEN + 20
      || memcmp (data, JOURNAL_MAGIC, JOURNAL_MAGIC_LEN) != 0)
    return WYRELOG_E_POLICY;
  WylServiceCredentialOperationRecord decoded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  gsize offset = JOURNAL_MAGIC_LEN;
  decoded.version = get_u32 (data + offset);
  offset += 4;
  decoded.kind = get_u32 (data + offset);
  offset += 4;
  decoded.state = get_u32 (data + offset);
  offset += 4;
  if (get_u32 (data + offset) != JOURNAL_FIELD_COUNT)
    goto invalid;
  offset += 4;
  if (!read_text (data, len, &offset, &decoded.operation_id)
      || !read_text (data, len, &offset, &decoded.request_id)
      || !read_text (data, len, &offset, &decoded.subject_id)
      || !read_text (data, len, &offset, &decoded.tenant_id)
      || !read_text (data, len, &offset, &decoded.destination)
      || !read_text (data, len, &offset, &decoded.parent_identity)
      || !read_text (data, len, &offset, &decoded.actor_subject_id)
      || len - offset < 4)
    goto invalid;
  decoded.publication_receipt_version = get_u32 (data + offset);
  offset += 4;
  if (!read_text (data, len, &offset, &decoded.reservation_id)
      || !read_text (data, len, &offset, &decoded.stage_basename)
      || !read_text (data, len, &offset, &decoded.stage_identity)
      || !read_text (data, len, &offset, &decoded.old_credential_id)
      || !read_text (data, len, &offset, &decoded.successor_credential_id)
      || !read_text (data, len, &offset, &decoded.escrow_id)
      || len - offset < sizeof decoded.escrow_binding_digest)
    goto invalid;
  memcpy (decoded.escrow_binding_digest, data + offset,
      sizeof decoded.escrow_binding_digest);
  offset += sizeof decoded.escrow_binding_digest;
  if (!read_text (data, len, &offset, &decoded.publication_receipt_id)
      || !read_text (data, len, &offset, &decoded.terminal_reason)
      || len - offset < 44)
    goto invalid;
  decoded.expected_generation = get_u64 (data + offset);
  offset += 8;
  decoded.successor_generation = get_u64 (data + offset);
  offset += 8;
  guint64 expires_raw = get_u64 (data + offset);
  offset += 8;
  guint64 created_raw = get_u64 (data + offset);
  offset += 8;
  guint64 updated_raw = get_u64 (data + offset);
  offset += 8;
  decoded.attempts = get_u32 (data + offset);
  offset += 4;
  if (expires_raw > G_MAXINT64 || created_raw > G_MAXINT64
      || updated_raw > G_MAXINT64)
    goto invalid;
  decoded.expires_at_us = (gint64) expires_raw;
  decoded.created_at_us = (gint64) created_raw;
  decoded.updated_at_us = (gint64) updated_raw;
  if (offset != len
      || !wyl_service_credential_operation_record_is_valid (&decoded))
    goto invalid;
  *out_record = decoded;
  return WYRELOG_E_OK;
invalid:
  wyl_service_credential_operation_record_clear (&decoded);
  return WYRELOG_E_POLICY;
}
