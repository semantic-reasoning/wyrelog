/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-journal-private.h"

#include <chronoid/ksuid.h>
#include <string.h>

#include "auth/service-credential-private.h"

#define JOURNAL_MAGIC "WYLJNL01"
#define JOURNAL_MAGIC_LEN 8u
#define JOURNAL_FIELD_COUNT 10u

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
destination_is_safe_basename (const gchar *value)
{
  return value != NULL && value[0] != '\0' && strcmp (value, ".") != 0
      && strcmp (value, "..") != 0 && strchr (value, '/') == NULL
      && strchr (value, '\\') == NULL;
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
      || !destination_is_safe_basename (record->destination)
      || !text_is_valid (record->parent_identity, TRUE)
      || !text_is_valid (record->stage_identity, FALSE)
      || !text_is_valid (record->old_credential_id,
          record->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE)
      || !text_is_valid (record->successor_credential_id, FALSE)
      || !text_is_valid (record->publication_receipt_id, FALSE)
      || record->attempts > G_MAXINT32 || record->created_at_us <= 0
      || record->updated_at_us < record->created_at_us)
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
  if (record->successor_generation > G_MAXINT64)
    return FALSE;
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
  g_clear_pointer (&record->stage_identity, g_free);
  g_clear_pointer (&record->old_credential_id, g_free);
  g_clear_pointer (&record->successor_credential_id, g_free);
  g_clear_pointer (&record->publication_receipt_id, g_free);
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
  append_text (bytes, record->stage_identity);
  append_text (bytes, record->old_credential_id);
  append_text (bytes, record->successor_credential_id);
  append_text (bytes, record->publication_receipt_id);
  append_u64 (bytes, record->successor_generation);
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
  if (out_record != NULL)
    wyl_service_credential_operation_record_clear (out_record);
  if (bytes == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;
  gsize len = 0;
  const guint8 *data = g_bytes_get_data (bytes, &len);
  if (data == NULL || len > WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES
      || len < JOURNAL_MAGIC_LEN + 20
      || memcmp (data, JOURNAL_MAGIC, JOURNAL_MAGIC_LEN) != 0)
    return WYRELOG_E_POLICY;
  gsize offset = JOURNAL_MAGIC_LEN;
  out_record->version = get_u32 (data + offset);
  offset += 4;
  out_record->kind = get_u32 (data + offset);
  offset += 4;
  out_record->state = get_u32 (data + offset);
  offset += 4;
  if (get_u32 (data + offset) != JOURNAL_FIELD_COUNT)
    goto invalid;
  offset += 4;
  if (!read_text (data, len, &offset, &out_record->operation_id)
      || !read_text (data, len, &offset, &out_record->request_id)
      || !read_text (data, len, &offset, &out_record->subject_id)
      || !read_text (data, len, &offset, &out_record->tenant_id)
      || !read_text (data, len, &offset, &out_record->destination)
      || !read_text (data, len, &offset, &out_record->parent_identity)
      || !read_text (data, len, &offset, &out_record->stage_identity)
      || !read_text (data, len, &offset, &out_record->old_credential_id)
      || !read_text (data, len, &offset, &out_record->successor_credential_id)
      || !read_text (data, len, &offset, &out_record->publication_receipt_id)
      || len - offset < 28)
    goto invalid;
  out_record->successor_generation = get_u64 (data + offset);
  offset += 8;
  out_record->created_at_us = (gint64) get_u64 (data + offset);
  offset += 8;
  out_record->updated_at_us = (gint64) get_u64 (data + offset);
  offset += 8;
  out_record->attempts = get_u32 (data + offset);
  offset += 4;
  if (offset != len
      || !wyl_service_credential_operation_record_is_valid (out_record))
    goto invalid;
  return WYRELOG_E_OK;
invalid:
  wyl_service_credential_operation_record_clear (out_record);
  return WYRELOG_E_POLICY;
}
