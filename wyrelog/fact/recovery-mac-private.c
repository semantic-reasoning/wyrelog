/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/recovery-mac-private.h"

#include <string.h>

struct WylFactRecoveryMacHandle
{
  gint references;
  GMutex mutex;
  gboolean closed;
  WylFactRecoveryMacProvider provider;
  gchar *key_id;
  guint64 key_generation;
  gchar *tenant_id;
  gchar *graph_id;
  gchar *operation_id;
  GBytes *label;
};

static gboolean
valid_field (const gchar *value)
{
  gsize length;
  return value != NULL && value[0] != '\0'
         && g_utf8_validate (value, -1, NULL)
         && strchr (value, '\0') == value + strlen (value)
         && (length = strlen (value)) <= G_MAXUINT16;
}

static void
append_u16_be (GByteArray *bytes, guint16 value)
{
  guint8 encoded[2] = { (guint8) (value >> 8), (guint8) value };
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_u64_be (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8];
  for (guint i = 0; i < G_N_ELEMENTS (encoded); i++)
    encoded[i] = (guint8) (value >> (56u - (i * 8u)));
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
append_field (GByteArray *bytes, const gchar *value)
{
  const gsize length = strlen (value);
  append_u16_be (bytes, (guint16) length);
  g_byte_array_append (bytes, (const guint8 *) value, length);
}

static GBytes *
make_label (const gchar *key_id, guint64 generation, const gchar *tenant_id,
    const gchar *graph_id, const gchar *operation_id)
{
  static const gchar purpose[] = "wyrelog.fact.recovery-evidence.mac.v1";
  GByteArray *bytes = g_byte_array_new ();
  append_field (bytes, purpose);
  append_field (bytes, key_id);
  append_u64_be (bytes, generation);
  append_field (bytes, tenant_id);
  append_field (bytes, graph_id);
  append_field (bytes, operation_id);
  return g_byte_array_free_to_bytes (bytes);
}

WylFactRecoveryMacHandle *
wyl_fact_recovery_mac_handle_new (const WylFactRecoveryMacProvider *provider,
    const gchar *key_id, guint64 key_generation, const gchar *tenant_id,
    const gchar *graph_id, const gchar *operation_id)
{
  if (provider == NULL || provider->compute == NULL || provider->verify == NULL
      || provider->state == NULL || key_generation == 0
      || !valid_field (key_id) || !valid_field (tenant_id)
      || !valid_field (graph_id) || !valid_field (operation_id))
    return NULL;

  WylFactRecoveryMacHandle *handle = g_try_new0
        (WylFactRecoveryMacHandle, 1);
  if (handle == NULL) {
    if (provider->wipe != NULL)
      provider->wipe (provider->state);
    if (provider->free != NULL)
      provider->free (provider->state);
    return NULL;
  }
  handle->key_id = g_strdup (key_id);
  handle->tenant_id = g_strdup (tenant_id);
  handle->graph_id = g_strdup (graph_id);
  handle->operation_id = g_strdup (operation_id);
  handle->label = make_label (key_id, key_generation, tenant_id, graph_id,
          operation_id);
  if (handle->key_id == NULL || handle->tenant_id == NULL
      || handle->graph_id == NULL || handle->operation_id == NULL
      || handle->label == NULL) {
    g_free (handle->key_id);
    g_free (handle->tenant_id);
    g_free (handle->graph_id);
    g_free (handle->operation_id);
    g_clear_pointer (&handle->label, g_bytes_unref);
    g_free (handle);
    if (provider->wipe != NULL)
      provider->wipe (provider->state);
    if (provider->free != NULL)
      provider->free (provider->state);
    return NULL;
  }
  handle->provider = *provider;
  handle->key_generation = key_generation;
  g_mutex_init (&handle->mutex);
  g_atomic_int_set (&handle->references, 1);
  return handle;
}

WylFactRecoveryMacHandle *
wyl_fact_recovery_mac_handle_ref (WylFactRecoveryMacHandle *handle)
{
  if (handle != NULL)
    g_atomic_int_inc (&handle->references);
  return handle;
}

void
wyl_fact_recovery_mac_handle_close (WylFactRecoveryMacHandle *handle)
{
  WylFactRecoveryMacProvider provider = { 0 };
  if (handle == NULL)
    return;
  g_mutex_lock (&handle->mutex);
  if (!handle->closed) {
    handle->closed = TRUE;
    provider = handle->provider;
    handle->provider = (WylFactRecoveryMacProvider) { 0 };
  }
  g_mutex_unlock (&handle->mutex);
  if (provider.wipe != NULL)
    provider.wipe (provider.state);
  if (provider.free != NULL)
    provider.free (provider.state);
}

void
wyl_fact_recovery_mac_handle_unref (WylFactRecoveryMacHandle *handle)
{
  if (handle == NULL || !g_atomic_int_dec_and_test (&handle->references))
    return;
  wyl_fact_recovery_mac_handle_close (handle);
  g_clear_pointer (&handle->label, g_bytes_unref);
  g_clear_pointer (&handle->key_id, g_free);
  g_clear_pointer (&handle->tenant_id, g_free);
  g_clear_pointer (&handle->graph_id, g_free);
  g_clear_pointer (&handle->operation_id, g_free);
  g_mutex_clear (&handle->mutex);
  g_free (handle);
}

guint64
wyl_fact_recovery_mac_handle_get_generation
  (const WylFactRecoveryMacHandle *handle)
{
  return handle == NULL ? 0 : handle->key_generation;
}

const gchar *
wyl_fact_recovery_mac_handle_get_key_id (const WylFactRecoveryMacHandle *handle)
{
  return handle == NULL ? NULL : handle->key_id;
}

gboolean
wyl_fact_recovery_mac_handle_scope_matches
  (const WylFactRecoveryMacHandle *handle, const gchar *tenant_id,
    const gchar *graph_id, const gchar *operation_id, guint64 key_generation)
{
  return handle != NULL && key_generation == handle->key_generation
         && g_strcmp0 (tenant_id, handle->tenant_id) == 0
         && g_strcmp0 (graph_id, handle->graph_id) == 0
         && g_strcmp0 (operation_id, handle->operation_id) == 0;
}

wyrelog_error_t
wyl_fact_recovery_mac_handle_dup_label
  (const WylFactRecoveryMacHandle *handle, GBytes **out_label)
{
  if (out_label != NULL)
    *out_label = NULL;
  if (handle == NULL || out_label == NULL)
    return WYRELOG_E_INVALID;
  g_mutex_lock ((GMutex *) &handle->mutex);
  if (!handle->closed)
    *out_label = g_bytes_ref (handle->label);
  g_mutex_unlock ((GMutex *) &handle->mutex);
  return *out_label == NULL ? WYRELOG_E_POLICY : WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_recovery_mac_compute (WylFactRecoveryMacHandle *handle,
    const guint8 *payload, gsize payload_len,
    guint8 out_tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  if (out_tag != NULL)
    memset (out_tag, 0, WYL_FACT_RECOVERY_MAC_TAG_BYTES);
  if (handle == NULL || out_tag == NULL || (payload == NULL && payload_len > 0))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&handle->mutex);
  wyrelog_error_t rc = handle->closed ? WYRELOG_E_POLICY :
      handle->provider.compute (handle->provider.state,
          g_bytes_get_data (handle->label, NULL), g_bytes_get_size (handle->label),
          payload, payload_len, out_tag);
  g_mutex_unlock (&handle->mutex);
  if (rc != WYRELOG_E_OK)
    memset (out_tag, 0, WYL_FACT_RECOVERY_MAC_TAG_BYTES);
  return rc;
}

wyrelog_error_t
wyl_fact_recovery_mac_verify (WylFactRecoveryMacHandle *handle,
    const guint8 *payload, gsize payload_len,
    const guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  if (handle == NULL || tag == NULL || (payload == NULL && payload_len > 0))
    return WYRELOG_E_INVALID;
  g_mutex_lock (&handle->mutex);
  wyrelog_error_t rc = handle->closed ? WYRELOG_E_POLICY :
      handle->provider.verify (handle->provider.state,
          g_bytes_get_data (handle->label, NULL), g_bytes_get_size (handle->label),
          payload, payload_len, tag);
  g_mutex_unlock (&handle->mutex);
  return rc;
}
