/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-private.h"

#include <chronoid/ksuid.h>
#include <sodium.h>
#include <string.h>

#define VERIFIER_DOMAIN "wyrelog.service-credential.verifier"
#define VERIFIER_DOMAIN_LEN 35u
#define DATA_VERIFIER_DOMAIN "wyrelog.data-credential.verifier"
#define DATA_VERIFIER_DOMAIN_LEN 32u
#define DATA_ID_PREFIX "wdc_"
#define VERIFIER_TLV_HEADER_LEN 5u
#define ENTROPY_BYTES (WYL_SERVICE_CREDENTIAL_SALT_BYTES \
  + WYL_SERVICE_CREDENTIAL_SECRET_BYTES)

G_STATIC_ASSERT (CHRONOID_KSUID_STRING_LEN == 27);
G_STATIC_ASSERT (sizeof (VERIFIER_DOMAIN) - 1 == VERIFIER_DOMAIN_LEN);
G_STATIC_ASSERT (sizeof (DATA_VERIFIER_DOMAIN) - 1 == DATA_VERIFIER_DOMAIN_LEN);
G_STATIC_ASSERT (DATA_VERIFIER_DOMAIN_LEN <= VERIFIER_DOMAIN_LEN);
G_STATIC_ASSERT (sizeof (DATA_ID_PREFIX) - 1
    == WYL_SERVICE_CREDENTIAL_ID_PREFIX_LEN);
G_STATIC_ASSERT (WYL_SERVICE_CREDENTIAL_KSUID_LEN == 27);
G_STATIC_ASSERT (WYL_SERVICE_CREDENTIAL_ID_LEN
    == WYL_SERVICE_CREDENTIAL_ID_PREFIX_LEN + CHRONOID_KSUID_STRING_LEN);
G_STATIC_ASSERT (sodium_base64_ENCODED_LEN (WYL_SERVICE_CREDENTIAL_SECRET_BYTES,
    sodium_base64_VARIANT_URLSAFE_NO_PADDING)
    == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_BUF);

struct wyl_service_credential_secret_t
{
  wyl_service_credential_runtime_t runtime;
  guint8 raw[WYL_SERVICE_CREDENTIAL_SECRET_BYTES];
  gchar encoded[WYL_SERVICE_CREDENTIAL_SECRET_TEXT_BUF];
};

static gpointer
default_alloc (gpointer data, gsize size)
{
  (void) data;
  return sodium_malloc (size);
}

static int
default_lock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  return sodium_mlock (ptr, size);
}

static void
default_wipe (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  sodium_memzero (ptr, size);
}

static int
default_unlock (gpointer data, gpointer ptr, gsize size)
{
  (void) data;
  return sodium_munlock (ptr, size);
}

static void
default_free (gpointer data, gpointer ptr)
{
  (void) data;
  sodium_free (ptr);
}

static wyrelog_error_t
default_new_id (gpointer data, gchar out_id[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  (void) data;
  return wyl_service_credential_id_new (out_id, WYL_SERVICE_CREDENTIAL_ID_BUF);
}

static wyrelog_error_t
default_data_new_id (gpointer data,
    gchar out_id[WYL_SERVICE_CREDENTIAL_ID_BUF])
{
  (void) data;
  return wyl_data_credential_id_new (out_id, WYL_SERVICE_CREDENTIAL_ID_BUF);
}

/* A credential kind fixes what its verifier is bound to.  The two kinds share
 * the secret format, the salt and the verifier construction; a distinct domain
 * string and id prefix keep a verifier of one kind from verifying as the
 * other. */
typedef struct
{
  const gchar *domain;
  gsize domain_len;
  const gchar *id_prefix;
  gsize subject_min_len;
  wyrelog_error_t (*default_new_id) (gpointer data,
      gchar out_id[WYL_SERVICE_CREDENTIAL_ID_BUF]);
} CredentialKind;

static const CredentialKind service_kind = {
  VERIFIER_DOMAIN, VERIFIER_DOMAIN_LEN, WYL_SERVICE_CREDENTIAL_ID_PREFIX, 5,
  default_new_id,
};

static const CredentialKind data_kind = {
  DATA_VERIFIER_DOMAIN, DATA_VERIFIER_DOMAIN_LEN, DATA_ID_PREFIX, 1,
  default_data_new_id,
};

static int
default_fill_random (gpointer data, guint8 *out, gsize len)
{
  (void) data;
  randombytes_buf (out, len);
  return 0;
}

static wyrelog_error_t
runtime_snapshot_kind (const CredentialKind *kind,
    const wyl_service_credential_runtime_t *runtime,
    wyl_service_credential_runtime_t *out)
{
  if (out == NULL)
    return WYRELOG_E_INVALID;
  if (sodium_init () < 0)
    return WYRELOG_E_CRYPTO;

  if (runtime == NULL) {
    *out = (wyl_service_credential_runtime_t) {
      .secure_alloc = default_alloc,.secure_lock = default_lock,.secure_wipe =
          default_wipe,.secure_unlock = default_unlock,.secure_free =
          default_free,.new_id = kind->default_new_id,.fill_random =
          default_fill_random,
    };
  } else {
    *out = *runtime;
  }

  if (out->secure_alloc == NULL || out->secure_lock == NULL
      || out->secure_wipe == NULL || out->secure_unlock == NULL
      || out->secure_free == NULL || out->new_id == NULL
      || out->fill_random == NULL)
    return WYRELOG_E_INVALID;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
runtime_snapshot (const wyl_service_credential_runtime_t *runtime,
    wyl_service_credential_runtime_t *out)
{
  return runtime_snapshot_kind (&service_kind, runtime, out);
}

static gpointer
locked_alloc (const wyl_service_credential_runtime_t *runtime, gsize size)
{
  gpointer ptr = runtime->secure_alloc (runtime->data, size);
  if (ptr == NULL)
    return NULL;
  if (runtime->secure_lock (runtime->data, ptr, size) != 0) {
    runtime->secure_wipe (runtime->data, ptr, size);
    runtime->secure_free (runtime->data, ptr);
    return NULL;
  }
  runtime->secure_wipe (runtime->data, ptr, size);
  return ptr;
}

static void
locked_free (const wyl_service_credential_runtime_t *runtime, gpointer ptr,
    gsize size)
{
  if (ptr == NULL)
    return;
  runtime->secure_wipe (runtime->data, ptr, size);
  (void) runtime->secure_unlock (runtime->data, ptr, size);
  runtime->secure_free (runtime->data, ptr);
}

static gboolean
binding_is_valid (const gchar *value, gsize len)
{
  return value != NULL && len > 0
         && len <= WYL_SERVICE_CREDENTIAL_BINDING_MAX_BYTES
         && memchr (value, '\0', len) == NULL
         && g_utf8_validate (value, len, NULL);
}

static gboolean
id_is_canonical (const CredentialKind *kind, const gchar *id, gsize id_len);

static gboolean
verifier_inputs_are_valid (const CredentialKind *kind,
    guint32 verifier_version, const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len, const guint8 *salt,
    gsize salt_len)
{
  return verifier_version == WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION
         && cvk != NULL && cvk_len == WYL_SERVICE_CREDENTIAL_CVK_BYTES
         && id_is_canonical (kind, id, id_len)
         && binding_is_valid (tenant, tenant_len)
         && binding_is_valid (subject, subject_len)
         && subject_len >= kind->subject_min_len
         && salt != NULL && salt_len == WYL_SERVICE_CREDENTIAL_SALT_BYTES;
}

static wyrelog_error_t
id_new (const CredentialKind *kind, gchar *out, gsize out_len)
{
  if (out == NULL || out_len < WYL_SERVICE_CREDENTIAL_ID_BUF)
    return WYRELOG_E_INVALID;

  chronoid_ksuid_t ksuid;
  chronoid_ksuid_err_t crc = chronoid_ksuid_new (&ksuid);
  if (crc == CHRONOID_KSUID_ERR_RNG)
    return WYRELOG_E_CRYPTO;
  if (crc != CHRONOID_KSUID_OK)
    return WYRELOG_E_INTERNAL;

  gchar tmp[WYL_SERVICE_CREDENTIAL_ID_BUF];
  memcpy (tmp, kind->id_prefix, WYL_SERVICE_CREDENTIAL_ID_PREFIX_LEN);
  chronoid_ksuid_format (&ksuid, tmp + 4);
  tmp[WYL_SERVICE_CREDENTIAL_ID_LEN] = '\0';
  memcpy (out, tmp, sizeof tmp);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_credential_id_new (gchar *out, gsize out_len)
{
  return id_new (&service_kind, out, out_len);
}

wyrelog_error_t
wyl_data_credential_id_new (gchar *out, gsize out_len)
{
  return id_new (&data_kind, out, out_len);
}

static gboolean
id_is_canonical (const CredentialKind *kind, const gchar *id, gsize id_len)
{
  if (id == NULL || id_len != WYL_SERVICE_CREDENTIAL_ID_LEN
      || memcmp (id, kind->id_prefix,
      WYL_SERVICE_CREDENTIAL_ID_PREFIX_LEN) != 0
      || memchr (id, '\0', id_len) != NULL)
    return FALSE;

  chronoid_ksuid_t ksuid;
  if (chronoid_ksuid_parse (&ksuid, id + 4, CHRONOID_KSUID_STRING_LEN)
      != CHRONOID_KSUID_OK)
    return FALSE;
  gchar canonical[CHRONOID_KSUID_STRING_LEN + 1];
  chronoid_ksuid_format (&ksuid, canonical);
  canonical[CHRONOID_KSUID_STRING_LEN] = '\0';
  return memcmp (canonical, id + 4, CHRONOID_KSUID_STRING_LEN) == 0;
}

gboolean
wyl_service_credential_id_is_canonical (const gchar *id, gsize id_len)
{
  return id_is_canonical (&service_kind, id, id_len);
}

gboolean
wyl_data_credential_id_is_canonical (const gchar *id, gsize id_len)
{
  return id_is_canonical (&data_kind, id, id_len);
}

const gchar *
wyl_service_credential_secret_peek_encoded (const
    wyl_service_credential_secret_t *secret, gsize *out_len)
{
  if (secret == NULL)
    return NULL;
  if (out_len != NULL)
    *out_len = WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN;
  return secret->encoded;
}

const guint8 *
wyl_service_credential_secret_peek_raw (const
    wyl_service_credential_secret_t *secret, gsize *out_len)
{
  if (secret == NULL)
    return NULL;
  if (out_len != NULL)
    *out_len = sizeof secret->raw;
  return secret->raw;
}

void
wyl_service_credential_secret_clear (wyl_service_credential_secret_t **secret)
{
  if (secret == NULL || *secret == NULL)
    return;
  wyl_service_credential_secret_t *owned = *secret;
  wyl_service_credential_runtime_t runtime = owned->runtime;
  *secret = NULL;
  locked_free (&runtime, owned, sizeof *owned);
}

static wyrelog_error_t
secret_from_raw (const wyl_service_credential_runtime_t *runtime,
    const guint8 raw[WYL_SERVICE_CREDENTIAL_SECRET_BYTES],
    wyl_service_credential_secret_t **out)
{
  wyl_service_credential_secret_t *secret = locked_alloc (runtime,
          sizeof *secret);
  if (secret == NULL)
    return WYRELOG_E_NOMEM;
  secret->runtime = *runtime;
  memcpy (secret->raw, raw, sizeof secret->raw);
  if (sodium_bin2base64 (secret->encoded, sizeof secret->encoded, secret->raw,
      sizeof secret->raw, sodium_base64_VARIANT_URLSAFE_NO_PADDING)
      == NULL) {
    wyl_service_credential_secret_clear (&secret);
    return WYRELOG_E_CRYPTO;
  }
  *out = secret;
  return WYRELOG_E_OK;
}

static gboolean
secret_text_is_well_formed (guint32 format_version, const gchar *text,
    gsize text_len, wyl_service_credential_secret_t **out_secret)
{
  return format_version == WYL_SERVICE_CREDENTIAL_FORMAT_VERSION
         && text != NULL && text_len == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN
         && memchr (text, '\0', text_len) == NULL && out_secret != NULL
         && *out_secret == NULL;
}

static wyrelog_error_t
secret_parse_snapshot (const gchar *text, gsize text_len,
    const wyl_service_credential_runtime_t *runtime,
    wyl_service_credential_secret_t **out_secret)
{
  wyl_service_credential_secret_t *secret = locked_alloc (runtime,
          sizeof *secret);
  if (secret == NULL)
    return WYRELOG_E_NOMEM;
  secret->runtime = *runtime;

  size_t decoded_len = 0;
  const char *end = NULL;
  if (sodium_base642bin (secret->raw, sizeof secret->raw, text, text_len,
      NULL, &decoded_len, &end,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
      || decoded_len != sizeof secret->raw || end != text + text_len
      || sodium_bin2base64 (secret->encoded, sizeof secret->encoded,
      secret->raw, sizeof secret->raw,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL
      || memcmp (secret->encoded, text, text_len) != 0) {
    wyl_service_credential_secret_clear (&secret);
    return WYRELOG_E_INVALID;
  }

  *out_secret = secret;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_service_credential_secret_parse_with_runtime (guint32 format_version,
    const gchar *text, gsize text_len,
    const wyl_service_credential_runtime_t *runtime_arg,
    wyl_service_credential_secret_t **out_secret)
{
  if (!secret_text_is_well_formed (format_version, text, text_len, out_secret))
    return WYRELOG_E_INVALID;
  wyl_service_credential_runtime_t runtime;
  wyrelog_error_t rc = runtime_snapshot (runtime_arg, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;
  return secret_parse_snapshot (text, text_len, &runtime, out_secret);
}

wyrelog_error_t
wyl_service_credential_secret_parse (guint32 format_version,
    const gchar *text, gsize text_len,
    wyl_service_credential_secret_t **out_secret)
{
  return wyl_service_credential_secret_parse_with_runtime (format_version,
             text, text_len, NULL, out_secret);
}

void
wyl_service_credential_material_clear (wyl_service_credential_material_t
    *material)
{
  if (material != NULL)
    sodium_memzero (material, sizeof *material);
}

static void
put_u32_be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static int
hash_tlv (crypto_generichash_state *state, guint8 framing[5], guint8 tag,
    const void *value, gsize len)
{
  if (len > G_MAXUINT32)
    return -1;
  framing[0] = tag;
  put_u32_be (framing + 1, (guint32) len);
  if (crypto_generichash_update (state, framing,
      VERIFIER_TLV_HEADER_LEN) != 0
      || crypto_generichash_update (state, value, len) != 0)
    return -1;
  return 0;
}

static wyrelog_error_t
verifier_compute_runtime (const CredentialKind *kind,
    const wyl_service_credential_runtime_t *runtime, guint32 verifier_version,
    const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len, const guint8 *salt,
    gsize salt_len, const wyl_service_credential_secret_t *secret,
    guint8 out[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES])
{
  if (!verifier_inputs_are_valid (kind, verifier_version, cvk, cvk_len, id,
      id_len, tenant, tenant_len, subject, subject_len, salt, salt_len)
      || secret == NULL)
    return WYRELOG_E_INVALID;

  gsize state_len = crypto_generichash_statebytes ();
  gsize scratch_len = state_len + WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES
      + VERIFIER_DOMAIN_LEN + 2;
  guint8 *scratch = locked_alloc (runtime, scratch_len);
  if (scratch == NULL)
    return WYRELOG_E_NOMEM;
  crypto_generichash_state *state = (crypto_generichash_state *) scratch;
  guint8 *digest = scratch + state_len;
  guint8 *framing = digest + WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES;
  memcpy (framing, kind->domain, kind->domain_len);
  framing[kind->domain_len] = 0x00;
  framing[kind->domain_len + 1] = 0x01;

  int failed = crypto_generichash_init (state, cvk, cvk_len,
          WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES);
  failed |= crypto_generichash_update (state, framing, kind->domain_len + 2);
  failed |= hash_tlv (state, framing, 0x01, id, id_len);
  failed |= hash_tlv (state, framing, 0x02, tenant, tenant_len);
  failed |= hash_tlv (state, framing, 0x03, subject, subject_len);
  failed |= hash_tlv (state, framing, 0x04, salt, salt_len);
  failed |= hash_tlv (state, framing, 0x05, secret->raw, sizeof secret->raw);
  failed |= crypto_generichash_final (state, digest,
          WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES);
  if (failed == 0)
    memcpy (out, digest, WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES);
  locked_free (runtime, scratch, scratch_len);
  return failed == 0 ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

wyrelog_error_t
wyl_service_credential_verifier_compute (guint32 verifier_version,
    const guint8 *cvk, gsize cvk_len, const gchar *id, gsize id_len,
    const gchar *tenant, gsize tenant_len, const gchar *subject,
    gsize subject_len, const guint8 *salt, gsize salt_len,
    const wyl_service_credential_secret_t *secret, guint8 *out, gsize out_len)
{
  if (out == NULL || out_len != WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES
      || secret == NULL || !verifier_inputs_are_valid (&service_kind,
      verifier_version, cvk, cvk_len, id, id_len, tenant, tenant_len, subject,
      subject_len, salt, salt_len))
    return WYRELOG_E_INVALID;
  wyl_service_credential_runtime_t runtime;
  wyrelog_error_t rc = runtime_snapshot (NULL, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;
  return verifier_compute_runtime (&service_kind, &runtime, verifier_version,
             cvk, cvk_len, id, id_len, tenant, tenant_len, subject, subject_len,
             salt, salt_len, secret, out);
}

static wyrelog_error_t
generate_kind (const CredentialKind *kind, const guint8 *cvk, gsize cvk_len,
    const gchar *tenant, gsize tenant_len, const gchar *subject,
    gsize subject_len, const wyl_service_credential_runtime_t *runtime_arg,
    wyl_service_credential_material_t *out_material,
    wyl_service_credential_secret_t **out_secret)
{
  if (cvk == NULL || cvk_len != WYL_SERVICE_CREDENTIAL_CVK_BYTES
      || !binding_is_valid (tenant, tenant_len)
      || !binding_is_valid (subject, subject_len)
      || subject_len < kind->subject_min_len
      || out_material == NULL || out_secret == NULL || *out_secret != NULL)
    return WYRELOG_E_INVALID;
  wyl_service_credential_runtime_t runtime;
  wyrelog_error_t rc = runtime_snapshot_kind (kind, runtime_arg, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;

  wyl_service_credential_material_t material = {
    .credential_format_version = WYL_SERVICE_CREDENTIAL_FORMAT_VERSION,
    .verifier_version = WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION,
  };
  guint8 *entropy = NULL;
  wyl_service_credential_secret_t *secret = NULL;
  rc = runtime.new_id (runtime.data, material.credential_id);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  if (material.credential_id[WYL_SERVICE_CREDENTIAL_ID_LEN] != '\0'
      || !id_is_canonical (kind, material.credential_id,
      WYL_SERVICE_CREDENTIAL_ID_LEN)) {
    rc = WYRELOG_E_INVALID;
    goto cleanup;
  }

  entropy = locked_alloc (&runtime, ENTROPY_BYTES);
  if (entropy == NULL) {
    rc = WYRELOG_E_NOMEM;
    goto cleanup;
  }
  if (runtime.fill_random (runtime.data, entropy, ENTROPY_BYTES) != 0) {
    rc = WYRELOG_E_CRYPTO;
    goto cleanup;
  }
  rc = secret_from_raw (&runtime, entropy, &secret);
  memcpy (material.salt, entropy + WYL_SERVICE_CREDENTIAL_SECRET_BYTES,
      sizeof material.salt);
  locked_free (&runtime, entropy, ENTROPY_BYTES);
  entropy = NULL;
  if (rc != WYRELOG_E_OK)
    goto cleanup;

  rc = verifier_compute_runtime (kind, &runtime, material.verifier_version,
          cvk, cvk_len, material.credential_id, WYL_SERVICE_CREDENTIAL_ID_LEN,
          tenant, tenant_len, subject, subject_len, material.salt,
          sizeof material.salt, secret, material.verifier);
  if (rc != WYRELOG_E_OK)
    goto cleanup;
  *out_material = material;
  *out_secret = secret;
  secret = NULL;

cleanup:
  locked_free (&runtime, entropy, ENTROPY_BYTES);
  wyl_service_credential_secret_clear (&secret);
  wyl_service_credential_material_clear (&material);
  return rc;
}

wyrelog_error_t
wyl_service_credential_generate_with_runtime (const guint8 *cvk,
    gsize cvk_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len,
    const wyl_service_credential_runtime_t *runtime,
    wyl_service_credential_material_t *out_material,
    wyl_service_credential_secret_t **out_secret)
{
  return generate_kind (&service_kind, cvk, cvk_len, tenant, tenant_len,
             subject, subject_len, runtime, out_material, out_secret);
}

wyrelog_error_t
wyl_data_credential_generate_with_runtime (const guint8 *cvk, gsize cvk_len,
    const gchar *tenant, gsize tenant_len, const gchar *issuer,
    gsize issuer_len, const wyl_service_credential_runtime_t *runtime,
    wyl_service_credential_material_t *out_material,
    wyl_service_credential_secret_t **out_secret)
{
  return generate_kind (&data_kind, cvk, cvk_len, tenant, tenant_len, issuer,
             issuer_len, runtime, out_material, out_secret);
}

wyrelog_error_t
wyl_service_credential_generate (const guint8 *cvk, gsize cvk_len,
    const gchar *tenant, gsize tenant_len, const gchar *subject,
    gsize subject_len, wyl_service_credential_material_t *out_material,
    wyl_service_credential_secret_t **out_secret)
{
  return wyl_service_credential_generate_with_runtime (cvk, cvk_len, tenant,
             tenant_len, subject, subject_len, NULL, out_material, out_secret);
}

static wyrelog_error_t
verify_kind (const CredentialKind *kind, guint32 format_version,
    guint32 verifier_version, const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len, const guint8 *salt,
    gsize salt_len, const guint8 *expected, gsize expected_len,
    const gchar *presented_secret, gsize presented_secret_len,
    const wyl_service_credential_runtime_t *runtime_arg, gboolean *out_match)
{
  if (format_version != WYL_SERVICE_CREDENTIAL_FORMAT_VERSION
      || !verifier_inputs_are_valid (kind, verifier_version, cvk, cvk_len, id,
      id_len, tenant, tenant_len, subject, subject_len, salt, salt_len)
      || expected == NULL
      || expected_len != WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES
      || presented_secret == NULL
      || presented_secret_len != WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN
      || memchr (presented_secret, '\0', presented_secret_len) != NULL
      || out_match == NULL)
    return WYRELOG_E_INVALID;
  wyl_service_credential_runtime_t runtime;
  wyrelog_error_t rc = runtime_snapshot_kind (kind, runtime_arg, &runtime);
  if (rc != WYRELOG_E_OK)
    return rc;
  wyl_service_credential_secret_t *presented = NULL;
  rc = secret_parse_snapshot (presented_secret, presented_secret_len,
          &runtime, &presented);
  if (rc != WYRELOG_E_OK)
    return rc;
  guint8 *actual = locked_alloc (&runtime,
          WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES);
  if (actual == NULL) {
    wyl_service_credential_secret_clear (&presented);
    return WYRELOG_E_NOMEM;
  }
  rc = verifier_compute_runtime (kind, &runtime, verifier_version, cvk,
          cvk_len, id, id_len, tenant, tenant_len, subject, subject_len, salt,
          salt_len, presented, actual);
  if (rc == WYRELOG_E_OK) {
    /* This is deliberately the sole production verifier comparison site.
     * The operands are fixed-size and every well-formed wrong secret reaches
     * the same constant-time primitive exactly once. */
    gboolean match = sodium_memcmp (actual, expected,
            WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES) == 0;
    *out_match = match;
  }
  locked_free (&runtime, actual, WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES);
  wyl_service_credential_secret_clear (&presented);
  return rc;
}

wyrelog_error_t
wyl_service_credential_verify_with_runtime (guint32 format_version,
    guint32 verifier_version, const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len, const guint8 *salt,
    gsize salt_len, const guint8 *expected, gsize expected_len,
    const gchar *presented_secret, gsize presented_secret_len,
    const wyl_service_credential_runtime_t *runtime, gboolean *out_match)
{
  return verify_kind (&service_kind, format_version, verifier_version, cvk,
             cvk_len, id, id_len, tenant, tenant_len, subject, subject_len,
             salt, salt_len, expected, expected_len, presented_secret,
             presented_secret_len, runtime, out_match);
}

wyrelog_error_t
wyl_data_credential_verify_with_runtime (guint32 format_version,
    guint32 verifier_version, const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *issuer, gsize issuer_len, const guint8 *salt,
    gsize salt_len, const guint8 *expected, gsize expected_len,
    const gchar *presented_secret, gsize presented_secret_len,
    const wyl_service_credential_runtime_t *runtime, gboolean *out_match)
{
  return verify_kind (&data_kind, format_version, verifier_version, cvk,
             cvk_len, id, id_len, tenant, tenant_len, issuer, issuer_len, salt,
             salt_len, expected, expected_len, presented_secret,
             presented_secret_len, runtime, out_match);
}

wyrelog_error_t
wyl_service_credential_verify (guint32 format_version,
    guint32 verifier_version, const guint8 *cvk, gsize cvk_len,
    const gchar *id, gsize id_len, const gchar *tenant, gsize tenant_len,
    const gchar *subject, gsize subject_len, const guint8 *salt,
    gsize salt_len, const guint8 *expected, gsize expected_len,
    const gchar *presented_secret, gsize presented_secret_len,
    gboolean *out_match)
{
  return wyl_service_credential_verify_with_runtime (format_version,
             verifier_version, cvk, cvk_len, id, id_len, tenant, tenant_len,
             subject, subject_len, salt, salt_len, expected, expected_len,
             presented_secret, presented_secret_len, NULL, out_match);
}
