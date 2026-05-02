/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * DEVELOPMENT ONLY -- NOT FOR PRODUCTION USE
 *
 * Deterministic XOR-based stub of the key-provider trait. See
 * wyl-keyprovider-dev-private.h for the security disclaimer and
 * the lifecycle / wipe / blob-layout contracts.
 */
#include "wyl-keyprovider-dev-private.h"

#include <string.h>

#define WYL_KEYPROVIDER_DEV_KEY_LEN 32

struct wyl_keyprovider_dev_t
{
  guint8 key[WYL_KEYPROVIDER_DEV_KEY_LEN];
  gboolean wiped;
};

static void
fill_default_key (guint8 *out)
{
  /* Compile-time constant pattern; no RNG. The byte values are
   * not cryptographically meaningful. */
  for (gsize i = 0; i < WYL_KEYPROVIDER_DEV_KEY_LEN; i++)
    out[i] = (guint8) (0xA5 ^ (guint8) i);
}

wyl_keyprovider_dev_t *
wyl_keyprovider_dev_new (void)
{
  wyl_keyprovider_dev_t *self = g_new0 (wyl_keyprovider_dev_t, 1);
  fill_default_key (self->key);
  self->wiped = FALSE;
  return self;
}

void
wyl_keyprovider_dev_free (wyl_keyprovider_dev_t *self)
{
  if (self == NULL)
    return;
  memset (self->key, 0, WYL_KEYPROVIDER_DEV_KEY_LEN);
  self->wiped = TRUE;
  g_free (self);
}

/* --- vtable bodies ----------------------------------------------- */

static wyrelog_error_t
dev_probe (gpointer self_p)
{
  wyl_keyprovider_dev_t *self = (wyl_keyprovider_dev_t *) self_p;
  if (self == NULL)
    return WYRELOG_E_INVALID;
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
dev_seal (gpointer self_p, const guint8 *plaintext, gsize plaintext_len,
    wyl_sealed_blob_t *out_blob)
{
  wyl_keyprovider_dev_t *self = (wyl_keyprovider_dev_t *) self_p;
  if (self == NULL || out_blob == NULL)
    return WYRELOG_E_INVALID;
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
  if (plaintext_len > 0 && plaintext == NULL)
    return WYRELOG_E_INVALID;

  guint8 *bytes = g_malloc (plaintext_len);
  for (gsize i = 0; i < plaintext_len; i++)
    bytes[i] = plaintext[i] ^ self->key[i % WYL_KEYPROVIDER_DEV_KEY_LEN];
  out_blob->bytes = bytes;
  out_blob->len = plaintext_len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
dev_unseal (gpointer self_p, const wyl_sealed_blob_t *blob,
    guint8 *out_plaintext, gsize out_capacity, gsize *out_written)
{
  wyl_keyprovider_dev_t *self = (wyl_keyprovider_dev_t *) self_p;
  if (self == NULL || blob == NULL || out_written == NULL)
    return WYRELOG_E_INVALID;
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
  if (blob->len > 0 && blob->bytes == NULL)
    return WYRELOG_E_INVALID;
  if (out_capacity < blob->len)
    return WYRELOG_E_INVALID;
  if (blob->len > 0 && out_plaintext == NULL)
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < blob->len; i++) {
    out_plaintext[i] =
        blob->bytes[i] ^ self->key[i % WYL_KEYPROVIDER_DEV_KEY_LEN];
  }
  *out_written = blob->len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
dev_derive (gpointer self_p, const gchar *label, guint8 *out_key, gsize out_len)
{
  wyl_keyprovider_dev_t *self = (wyl_keyprovider_dev_t *) self_p;
  if (self == NULL || label == NULL || (out_len > 0 && out_key == NULL))
    return WYRELOG_E_INVALID;
  if (self->wiped)
    return WYRELOG_E_INTERNAL;

  guint32 seed = g_str_hash (label);
  for (gsize i = 0; i < out_len; i++) {
    guint8 seed_byte = (guint8) (seed >> ((i & 3) * 8));
    out_key[i] = seed_byte ^ self->key[i % WYL_KEYPROVIDER_DEV_KEY_LEN];
  }
  return WYRELOG_E_OK;
}

static void
dev_wipe (gpointer self_p)
{
  wyl_keyprovider_dev_t *self = (wyl_keyprovider_dev_t *) self_p;
  if (self == NULL)
    return;
  memset (self->key, 0, WYL_KEYPROVIDER_DEV_KEY_LEN);
  self->wiped = TRUE;
}

static const wyl_keyprovider_vtable_t dev_vtable = {
  .probe = dev_probe,
  .seal = dev_seal,
  .unseal = dev_unseal,
  .derive = dev_derive,
  .wipe = dev_wipe,
};

const wyl_keyprovider_vtable_t *
wyl_keyprovider_dev_get_vtable (void)
{
  return &dev_vtable;
}
