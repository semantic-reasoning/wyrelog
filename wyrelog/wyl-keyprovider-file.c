/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-keyprovider-file-private.h"

#include <string.h>

#include <sodium.h>

#define WYL_KEYPROVIDER_FILE_KEY_LEN crypto_secretbox_KEYBYTES

struct wyl_keyprovider_file_t
{
  gchar *path;
  guint8 key[WYL_KEYPROVIDER_FILE_KEY_LEN];
};

static wyrelog_error_t
read_file_key (const gchar *path, guint8 out_key[WYL_KEYPROVIDER_FILE_KEY_LEN])
{
  g_autofree char *contents = NULL;
  gsize contents_len = 0;

  if (!g_file_get_contents (path, &contents, &contents_len, NULL))
    return WYRELOG_E_IO;
  if (contents_len != WYL_KEYPROVIDER_FILE_KEY_LEN)
    return WYRELOG_E_POLICY;
  memcpy (out_key, contents, WYL_KEYPROVIDER_FILE_KEY_LEN);
  return WYRELOG_E_OK;
}

wyl_keyprovider_file_t *
wyl_keyprovider_file_new (const gchar *path)
{
  if (path == NULL || path[0] == '\0')
    return NULL;

  wyl_keyprovider_file_t *self = g_new0 (wyl_keyprovider_file_t, 1);
  self->path = g_strdup (path);
  if (read_file_key (self->path, (guint8 *) self->key) != WYRELOG_E_OK) {
    g_clear_pointer (&self, wyl_keyprovider_file_free);
    return NULL;
  }

  return self;
}

void
wyl_keyprovider_file_free (wyl_keyprovider_file_t *self)
{
  if (self == NULL)
    return;

  if (self->path != NULL)
    g_free (self->path);
  sodium_memzero (self->key, sizeof self->key);
  g_free (self);
}

static wyrelog_error_t
file_probe (gpointer self_p)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL || self->path == NULL)
    return WYRELOG_E_INVALID;
  if (!g_file_test (self->path, G_FILE_TEST_EXISTS))
    return WYRELOG_E_INTERNAL;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
file_seal (gpointer self_p, const guint8 *plaintext, gsize plaintext_len,
    wyl_sealed_blob_t *out_blob)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL || out_blob == NULL)
    return WYRELOG_E_INVALID;
  if (self->path == NULL)
    return WYRELOG_E_INTERNAL;
  if (plaintext_len > 0 && plaintext == NULL)
    return WYRELOG_E_INVALID;

  guint8 *bytes = g_malloc (plaintext_len);
  memcpy (bytes, plaintext, plaintext_len);
  out_blob->bytes = bytes;
  out_blob->len = plaintext_len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
file_unseal (gpointer self_p, const wyl_sealed_blob_t *blob,
    guint8 *out_plaintext, gsize out_capacity, gsize *out_written)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL || blob == NULL || out_written == NULL)
    return WYRELOG_E_INVALID;
  if (self->path == NULL)
    return WYRELOG_E_INTERNAL;
  if (blob->len > 0 && blob->bytes == NULL)
    return WYRELOG_E_INVALID;
  if (out_capacity < blob->len)
    return WYRELOG_E_INVALID;
  if (out_plaintext == NULL && blob->len > 0)
    return WYRELOG_E_INVALID;

  memcpy (out_plaintext, blob->bytes, blob->len);
  *out_written = blob->len;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
file_derive (gpointer self_p, const gchar *label, guint8 *out_key,
    gsize out_len)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL || out_key == NULL || label == NULL)
    return WYRELOG_E_INVALID;
  if (self->path == NULL)
    return WYRELOG_E_INTERNAL;

  if (crypto_generichash (out_key, out_len, (const guint8 *) label,
          strlen (label), self->key, sizeof self->key) != 0)
    return WYRELOG_E_CRYPTO;

  return WYRELOG_E_OK;
}

static void
file_wipe (gpointer self_p)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL)
    return;
  sodium_memzero (self->key, sizeof self->key);
}

static const wyl_keyprovider_vtable_t file_vtable = {
  .probe = file_probe,
  .seal = file_seal,
  .unseal = file_unseal,
  .derive = file_derive,
  .wipe = file_wipe,
};

const wyl_keyprovider_vtable_t *
wyl_keyprovider_file_get_vtable (void)
{
  return &file_vtable;
}
