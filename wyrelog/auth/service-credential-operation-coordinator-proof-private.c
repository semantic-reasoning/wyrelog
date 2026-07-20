/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-proof-private.h"

#include <sodium.h>
#include <string.h>

static void
put_u32be (guint8 out[4], guint32 value)
{
  out[0] = (guint8) (value >> 24);
  out[1] = (guint8) (value >> 16);
  out[2] = (guint8) (value >> 8);
  out[3] = (guint8) value;
}

static wyrelog_error_t
target_digest_update_text (crypto_generichash_state *state, const gchar *value)
{
  guint8 encoded_len[4];
  gsize len;

  if (value == NULL)
    return WYRELOG_E_POLICY;
  len = strlen (value);
  if (len > G_MAXUINT32)
    return WYRELOG_E_POLICY;
  put_u32be (encoded_len, (guint32) len);
  return crypto_generichash_update (state, encoded_len, sizeof encoded_len) == 0
      && crypto_generichash_update (state, (const guint8 *) value, len) == 0 ?
      WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

wyrelog_error_t
    wyl_service_credential_operation_handoff_target_digest
    (const WylServiceCredentialOperationRecord * record,
    guint8
    out_digest[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES])
{
  static const gchar domain[] =
      "wyrelog.service-credential-owner-publication-target.v1";
  crypto_generichash_state state;
  wyrelog_error_t rc;

  if (record == NULL || out_digest == NULL)
    return WYRELOG_E_INVALID;
  if (crypto_generichash_init (&state, NULL, 0,
          WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES) != 0)
    return WYRELOG_E_CRYPTO;
  rc = target_digest_update_text (&state, domain);
  if (rc == WYRELOG_E_OK)
    rc = target_digest_update_text (&state, record->destination);
  if (rc == WYRELOG_E_OK)
    rc = target_digest_update_text (&state, record->parent_identity);
  if (rc == WYRELOG_E_OK
      && crypto_generichash_final (&state, out_digest,
          WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES) != 0)
    rc = WYRELOG_E_CRYPTO;
  sodium_memzero (&state, sizeof state);
  if (rc != WYRELOG_E_OK)
    sodium_memzero (out_digest,
        WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES);
  return rc;
}
