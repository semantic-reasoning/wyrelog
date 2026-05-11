/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-keyprovider-file-private.h"

#include <string.h>

#include <sodium.h>

#define WYL_KEYPROVIDER_FILE_KEY_LEN crypto_secretbox_KEYBYTES
#define WYL_KEYPROVIDER_SEAL_MAGIC "WYLKPF1"
#define WYL_KEYPROVIDER_SEAL_MAGIC_LEN 7
#define WYL_KEYPROVIDER_SEAL_HEADER_LEN \
  (WYL_KEYPROVIDER_SEAL_MAGIC_LEN + crypto_secretbox_NONCEBYTES)

typedef enum
{
  WYL_KEYPROVIDER_FILE_SOURCE_FILE = 0,
  WYL_KEYPROVIDER_FILE_SOURCE_SYSTEMD_CREDS = 1,
} WylKeyProviderFileSource;

struct wyl_keyprovider_file_t
{
  WylKeyProviderFileSource source;
  gchar *path;
  gchar *credential_name;
  guint8 key[WYL_KEYPROVIDER_FILE_KEY_LEN];
  gboolean wiped;
};

static wyrelog_error_t
ensure_sodium (void)
{
  return sodium_init () < 0 ? WYRELOG_E_CRYPTO : WYRELOG_E_OK;
}

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

static gboolean
credential_name_is_valid (const gchar *name)
{
  if (name == NULL || name[0] == '\0')
    return FALSE;
  if (g_path_is_absolute (name) || strstr (name, "..") != NULL ||
      strchr (name, '/') != NULL || strchr (name, '\\') != NULL)
    return FALSE;
  return TRUE;
}

static wyl_keyprovider_file_t *
new_resolved (WylKeyProviderFileSource source, const gchar *path,
    const gchar *credential_name)
{
  if (path == NULL || path[0] == '\0')
    return NULL;
  if (ensure_sodium () != WYRELOG_E_OK)
    return NULL;

  wyl_keyprovider_file_t *self = g_new0 (wyl_keyprovider_file_t, 1);
  self->source = source;
  self->path = g_strdup (path);
  self->credential_name = g_strdup (credential_name);
  if (read_file_key (self->path, (guint8 *) self->key) != WYRELOG_E_OK) {
    g_clear_pointer (&self, wyl_keyprovider_file_free);
    return NULL;
  }
  self->wiped = FALSE;

  return self;
}

wyl_keyprovider_file_t *
wyl_keyprovider_file_new (const gchar *path)
{
  return new_resolved (WYL_KEYPROVIDER_FILE_SOURCE_FILE, path, NULL);
}

wyl_keyprovider_file_t *
wyl_keyprovider_file_new_from_spec (const gchar *spec)
{
  if (spec == NULL || spec[0] == '\0')
    return NULL;

  static const gchar *file_prefix = "file:";
  static const gchar *creds_prefix = "systemd-creds:";
  if (g_str_has_prefix (spec, file_prefix))
    return new_resolved (WYL_KEYPROVIDER_FILE_SOURCE_FILE,
        spec + strlen (file_prefix), NULL);

  if (g_str_has_prefix (spec, creds_prefix)) {
    const gchar *name = spec + strlen (creds_prefix);
    if (!credential_name_is_valid (name))
      return NULL;
    const gchar *dir = g_getenv ("CREDENTIALS_DIRECTORY");
    if (dir == NULL || dir[0] == '\0')
      return NULL;
    g_autofree gchar *path = g_build_filename (dir, name, NULL);
    return new_resolved (WYL_KEYPROVIDER_FILE_SOURCE_SYSTEMD_CREDS, path, name);
  }

  return wyl_keyprovider_file_new (spec);
}

void
wyl_keyprovider_file_free (wyl_keyprovider_file_t *self)
{
  if (self == NULL)
    return;

  if (self->path != NULL)
    g_free (self->path);
  if (self->credential_name != NULL)
    g_free (self->credential_name);
  sodium_memzero (self->key, sizeof self->key);
  g_free (self);
}

static wyrelog_error_t
file_probe (gpointer self_p)
{
  wyl_keyprovider_file_t *self = self_p;
  if (self == NULL || self->path == NULL)
    return WYRELOG_E_INVALID;
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
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
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
  if (plaintext_len > 0 && plaintext == NULL)
    return WYRELOG_E_INVALID;

  gsize ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
  gsize total_len = WYL_KEYPROVIDER_SEAL_HEADER_LEN + ciphertext_len;
  guint8 *bytes = g_malloc0 (total_len);
  memcpy (bytes, WYL_KEYPROVIDER_SEAL_MAGIC, WYL_KEYPROVIDER_SEAL_MAGIC_LEN);
  guint8 *nonce = bytes + WYL_KEYPROVIDER_SEAL_MAGIC_LEN;
  randombytes_buf (nonce, crypto_secretbox_NONCEBYTES);
  guint8 *ciphertext = bytes + WYL_KEYPROVIDER_SEAL_HEADER_LEN;
  const guint8 empty_plaintext = 0;
  const guint8 *message = plaintext_len > 0 ? plaintext : &empty_plaintext;
  if (crypto_secretbox_easy (ciphertext, message, plaintext_len, nonce,
          self->key) != 0) {
    sodium_memzero (bytes, total_len);
    g_free (bytes);
    return WYRELOG_E_CRYPTO;
  }
  out_blob->bytes = bytes;
  out_blob->len = total_len;
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
  if (self->wiped)
    return WYRELOG_E_INTERNAL;
  if (blob->len > 0 && blob->bytes == NULL)
    return WYRELOG_E_INVALID;
  if (blob->len < WYL_KEYPROVIDER_SEAL_HEADER_LEN + crypto_secretbox_MACBYTES)
    return WYRELOG_E_INVALID;
  if (memcmp (blob->bytes, WYL_KEYPROVIDER_SEAL_MAGIC,
          WYL_KEYPROVIDER_SEAL_MAGIC_LEN) != 0)
    return WYRELOG_E_INVALID;

  gsize ciphertext_len = blob->len - WYL_KEYPROVIDER_SEAL_HEADER_LEN;
  gsize plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
  if (out_capacity < plaintext_len)
    return WYRELOG_E_INVALID;
  if (out_plaintext == NULL && plaintext_len > 0)
    return WYRELOG_E_INVALID;

  const guint8 *nonce = blob->bytes + WYL_KEYPROVIDER_SEAL_MAGIC_LEN;
  const guint8 *ciphertext = blob->bytes + WYL_KEYPROVIDER_SEAL_HEADER_LEN;
  guint8 empty_plaintext = 0;
  guint8 *output = plaintext_len > 0 ? out_plaintext : &empty_plaintext;
  if (crypto_secretbox_open_easy (output, ciphertext, ciphertext_len,
          nonce, self->key) != 0)
    return WYRELOG_E_CRYPTO;

  *out_written = plaintext_len;
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
  if (self->wiped)
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
  self->wiped = TRUE;
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

const gchar *
wyl_keyprovider_file_get_source_name (const wyl_keyprovider_file_t *self)
{
  if (self == NULL)
    return NULL;
  return self->source == WYL_KEYPROVIDER_FILE_SOURCE_SYSTEMD_CREDS ?
      "systemd-creds" : "file";
}
