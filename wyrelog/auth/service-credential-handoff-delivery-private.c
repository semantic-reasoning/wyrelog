/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The opaque types in this translation unit are deliberately not shared. */
#include "auth/service-credential-handoff-delivery-private.h"
#include "policy/store-handoff-delivery-private.h"

#include <sodium.h>
#include <string.h>

struct _WylServiceCredentialHandoffDeliveryPreflight
{
  wyl_policy_store_t *store;
  gboolean consumed;
  WylServiceCredentialHandoffDeliverySource source;
  wyl_id_t escrow_id;
  gchar *original_request_id;
  guint8 binding_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gchar *successor_credential_id;
  guint64 successor_issuance_generation;
  gchar *original_actor_subject_id;
  gchar *actor_subject_id;
  gchar *operation;
  guint8 target_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gint64 deadline_at_us;
  guint32 receipt_version;
  gchar *destination;
  gchar *reservation_id;
  gchar *parent_identity;
  gchar *stage_basename;
  gchar *stage_identity;
  gchar *publication_receipt_id;
  guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
};

struct _WylServiceCredentialHandoffDeliveryCapability
{
  WylServiceCredentialHandoffDeliveryPreflight *proof;
  gboolean consumed;
};

static WylPolicyServiceHandoffExactTuple
delivery_tuple (WylServiceCredentialHandoffDeliveryPreflight *preflight)
{
  WylPolicyServiceHandoffExactTuple tuple = {
    .original_request_id = preflight->original_request_id,
    .escrow_id = &preflight->escrow_id,
    .successor_credential_id = preflight->successor_credential_id,
    .successor_issuance_generation = preflight->successor_issuance_generation,
    .original_actor_subject_id = preflight->original_actor_subject_id,
  };
  memcpy (tuple.binding_digest, preflight->binding_digest,
      sizeof tuple.binding_digest);
  return tuple;
}

void wyl_service_credential_handoff_delivery_preflight_free
    (WylServiceCredentialHandoffDeliveryPreflight * preflight)
{
  if (preflight == NULL)
    return;
  g_free (preflight->original_request_id);
  g_free (preflight->successor_credential_id);
  g_free (preflight->original_actor_subject_id);
  g_free (preflight->actor_subject_id);
  g_free (preflight->operation);
  g_free (preflight->destination);
  g_free (preflight->reservation_id);
  g_free (preflight->parent_identity);
  g_free (preflight->stage_basename);
  g_free (preflight->stage_identity);
  g_free (preflight->publication_receipt_id);
  sodium_memzero (preflight, sizeof *preflight);
  g_free (preflight);
}

void wyl_service_credential_handoff_delivery_capability_free
    (WylServiceCredentialHandoffDeliveryCapability * capability)
{
  if (capability == NULL)
    return;
  wyl_service_credential_handoff_delivery_preflight_free (capability->proof);
  sodium_memzero (capability, sizeof *capability);
  g_free (capability);
}

static void
delivery_hash_u32 (crypto_generichash_state *state, guint32 value)
{
  guint8 encoded[4] = {
    (guint8) (value >> 24), (guint8) (value >> 16),
    (guint8) (value >> 8), (guint8) value,
  };
  crypto_generichash_update (state, encoded, sizeof encoded);
}

static gboolean
delivery_hash_text (crypto_generichash_state *state, const gchar *value)
{
  gsize len = value == NULL ? 0 : strlen (value);
  if (len > G_MAXUINT32)
    return FALSE;
  delivery_hash_u32 (state, (guint32) len);
  return len == 0 || crypto_generichash_update (state,
      (const guint8 *) value, len) == 0;
}

static wyrelog_error_t
delivery_proof_digest (const WylServiceCredentialHandoffDeliveryProof *proof,
    guint8 out[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES])
{
  gchar escrow[WYL_ID_STRING_BUF];
  gchar generation[32];
  gchar deadline[32];
  gchar receipt_version[16];
  if (wyl_id_format (proof->tuple.escrow_id, escrow, sizeof escrow)
      != WYRELOG_E_OK)
    return WYRELOG_E_INVALID;
  g_snprintf (generation, sizeof generation, "%" G_GUINT64_FORMAT,
      proof->tuple.successor_issuance_generation);
  g_snprintf (deadline, sizeof deadline, "%" G_GINT64_FORMAT,
      proof->deadline_at_us);
  g_snprintf (receipt_version, sizeof receipt_version, "%u",
      proof->receipt_version);
  crypto_generichash_state state;
  static const gchar domain[] = "wyrelog.service-handoff-delivery-proof.v1";
  if (crypto_generichash_init (&state, NULL, 0,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) != 0
      || !delivery_hash_text (&state, domain))
    return WYRELOG_E_CRYPTO;
  const gchar *fields[] = {
    "published-or-cleanup", proof->tuple.original_request_id, escrow,
    proof->tuple.successor_credential_id, generation,
    proof->tuple.original_actor_subject_id, proof->actor_subject_id,
    proof->operation, deadline, receipt_version, proof->destination,
    proof->parent_identity, proof->reservation_id, proof->stage_basename,
    proof->stage_identity, proof->publication_receipt_id,
  };
  for (guint i = 0; i < G_N_ELEMENTS (fields); i++)
    if (!delivery_hash_text (&state, fields[i])) {
      sodium_memzero (&state, sizeof state);
      return WYRELOG_E_CRYPTO;
    }
  delivery_hash_u32 (&state, sizeof proof->tuple.binding_digest);
  if (crypto_generichash_update (&state, proof->tuple.binding_digest,
          sizeof proof->tuple.binding_digest) != 0) {
    sodium_memzero (&state, sizeof state);
    return WYRELOG_E_CRYPTO;
  }
  delivery_hash_u32 (&state, sizeof proof->target_digest);
  if (crypto_generichash_update (&state, proof->target_digest,
          sizeof proof->target_digest) != 0
      || crypto_generichash_final (&state, out,
          WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES) != 0) {
    sodium_memzero (&state, sizeof state);
    return WYRELOG_E_CRYPTO;
  }
  sodium_memzero (&state, sizeof state);
  return WYRELOG_E_OK;
}

static gboolean
delivery_proof_is_valid (const WylServiceCredentialHandoffDeliveryProof *proof)
{
  return proof != NULL && proof->tuple.escrow_id != NULL
      && proof->tuple.original_request_id != NULL
      && proof->tuple.successor_credential_id != NULL
      && proof->tuple.successor_issuance_generation > 0
      && proof->tuple.original_actor_subject_id != NULL
      && wyl_policy_service_actor_subject_is_valid (proof->actor_subject_id)
      && (g_strcmp0 (proof->operation, "issue") == 0
      || g_strcmp0 (proof->operation, "rotate") == 0)
      && !sodium_is_zero (proof->tuple.binding_digest,
      sizeof proof->tuple.binding_digest)
      && !sodium_is_zero (proof->target_digest, sizeof proof->target_digest)
      && proof->deadline_at_us > 0 && proof->receipt_version == 1
      && proof->destination != NULL && proof->destination[0] != '\0'
      && proof->reservation_id != NULL && proof->reservation_id[0] != '\0'
      && proof->parent_identity != NULL && proof->parent_identity[0] != '\0'
      && proof->stage_basename != NULL && proof->stage_basename[0] != '\0'
      && proof->stage_identity != NULL && proof->stage_identity[0] != '\0'
      && g_strcmp0 (proof->publication_receipt_id,
      proof->reservation_id) == 0
      && (proof->source ==
      WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_FILE_PUBLISHED
      || proof->source == WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_CLEANUP_REQUIRED);
}

static gboolean
    delivery_escrow_matches
    (const wyl_policy_service_handoff_escrow_info_t * escrow,
    const WylServiceCredentialHandoffDeliveryProof * proof)
{
  return wyl_id_equal (&escrow->escrow_id, proof->tuple.escrow_id)
      && g_strcmp0 (escrow->operation, proof->operation) == 0
      && g_strcmp0 (escrow->request_id, proof->tuple.original_request_id) == 0
      && g_strcmp0 (escrow->actor_subject_id,
      proof->tuple.original_actor_subject_id) == 0
      && sodium_memcmp (escrow->target_digest, proof->target_digest,
      sizeof proof->target_digest) == 0
      && g_strcmp0 (escrow->credential_id,
      proof->tuple.successor_credential_id) == 0
      && escrow->credential_generation ==
      proof->tuple.successor_issuance_generation
      && escrow->deadline_at_us == proof->deadline_at_us
      && sodium_memcmp (escrow->binding_digest, proof->tuple.binding_digest,
      sizeof proof->tuple.binding_digest) == 0;
}

static WylServiceCredentialHandoffDeliveryPreflight *
delivery_preflight_new (wyl_policy_store_t *store,
    const WylServiceCredentialHandoffDeliveryProof *proof,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES])
{
  WylServiceCredentialHandoffDeliveryPreflight *preflight =
      g_try_new0 (WylServiceCredentialHandoffDeliveryPreflight, 1);
  if (preflight == NULL)
    return NULL;
  preflight->store = store;
  preflight->source = proof->source;
  preflight->escrow_id = *proof->tuple.escrow_id;
  preflight->original_request_id = g_strdup (proof->tuple.original_request_id);
  memcpy (preflight->binding_digest, proof->tuple.binding_digest, 32);
  preflight->successor_credential_id =
      g_strdup (proof->tuple.successor_credential_id);
  preflight->successor_issuance_generation =
      proof->tuple.successor_issuance_generation;
  preflight->original_actor_subject_id =
      g_strdup (proof->tuple.original_actor_subject_id);
  preflight->actor_subject_id = g_strdup (proof->actor_subject_id);
  preflight->operation = g_strdup (proof->operation);
  memcpy (preflight->target_digest, proof->target_digest, 32);
  preflight->deadline_at_us = proof->deadline_at_us;
  preflight->receipt_version = proof->receipt_version;
  preflight->destination = g_strdup (proof->destination);
  preflight->reservation_id = g_strdup (proof->reservation_id);
  preflight->parent_identity = g_strdup (proof->parent_identity);
  preflight->stage_basename = g_strdup (proof->stage_basename);
  preflight->stage_identity = g_strdup (proof->stage_identity);
  preflight->publication_receipt_id = g_strdup (proof->publication_receipt_id);
  memcpy (preflight->proof_digest, proof_digest, 32);
  if (preflight->original_request_id == NULL
      || preflight->successor_credential_id == NULL
      || preflight->original_actor_subject_id == NULL
      || preflight->actor_subject_id == NULL || preflight->operation == NULL
      || preflight->destination == NULL || preflight->reservation_id == NULL
      || preflight->parent_identity == NULL
      || preflight->stage_basename == NULL
      || preflight->stage_identity == NULL
      || preflight->publication_receipt_id == NULL) {
    wyl_service_credential_handoff_delivery_preflight_free (preflight);
    return NULL;
  }
  return preflight;
}

wyrelog_error_t
    wyl_service_credential_handoff_prepare_delivery_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    const WylServiceCredentialHandoffDeliveryProof * proof,
    WylServiceCredentialHandoffDeliveryOutcome * out_outcome,
    WylServiceCredentialHandoffDeliveryPreflight ** out_preflight,
    WylPolicyServiceHandoffDispositionResult * out_disposition)
{
  if (out_preflight != NULL)
    *out_preflight = NULL;
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || out_outcome == NULL || out_preflight == NULL
      || out_disposition == NULL || !delivery_proof_is_valid (proof))
    return WYRELOG_E_INVALID;
  guint8 digest[32] = { 0 };
  wyrelog_error_t rc = delivery_proof_digest (proof, digest);
  gboolean found = FALSE;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_handoff_lookup_delivered_core (transaction, store,
        &proof->tuple, proof->actor_subject_id, digest, &found,
        out_disposition);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (found) {
    *out_outcome = WYL_SERVICE_HANDOFF_DELIVERY_REPLAYED;
    goto out;
  }
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  rc = wyl_policy_store_service_handoff_escrow_load (store,
      proof->tuple.escrow_id, &escrow);
  if (rc == WYRELOG_E_NOT_FOUND
      && proof->source == WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_FILE_PUBLISHED) {
    rc = wyl_policy_store_handoff_backfill_delivered_core (transaction, store,
        &proof->tuple, proof->actor_subject_id, digest, out_disposition);
    if (rc == WYRELOG_E_OK)
      *out_outcome = WYL_SERVICE_HANDOFF_DELIVERY_LEGACY_BACKFILLED;
    goto clear_escrow;
  }
  if (rc != WYRELOG_E_OK) {
    rc = rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
    goto clear_escrow;
  }
  if (!delivery_escrow_matches (&escrow, proof)) {
    rc = WYRELOG_E_POLICY;
    goto clear_escrow;
  }
  WylPolicyServiceHandoffPublicationOutcome publication_outcome = 0;
  rc = wyl_policy_store_handoff_classify_for_publication_core (transaction,
      store, &proof->tuple, proof->actor_subject_id,
      &publication_outcome, out_disposition);
  if (rc == WYRELOG_E_OK
      && publication_outcome == WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE) {
    *out_preflight = delivery_preflight_new (store, proof, digest);
    rc = *out_preflight == NULL ? WYRELOG_E_NOMEM : WYRELOG_E_OK;
    if (rc == WYRELOG_E_OK)
      *out_outcome = WYL_SERVICE_HANDOFF_DELIVERY_ACTIVE;
  } else if (rc == WYRELOG_E_OK) {
    *out_outcome = publication_outcome ==
        WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED ?
        WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_EXPIRED :
        WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_REVOKED;
  }
clear_escrow:
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
out:
  sodium_memzero (digest, sizeof digest);
  return rc;
}

wyrelog_error_t
wyl_service_credential_handoff_delivery_unseal (wyl_policy_store_t *store,
    WylServiceCredentialHandoffDeliveryPreflight *preflight,
    wyl_policy_service_handoff_secret_t **out_secret)
{
  if (out_secret != NULL)
    *out_secret = NULL;
  if (store == NULL || preflight == NULL || out_secret == NULL
      || preflight->store != store || preflight->consumed)
    return WYRELOG_E_INVALID;
  WylPolicyServiceHandoffExactTuple tuple = delivery_tuple (preflight);
  wyl_policy_service_handoff_escrow_info_t escrow = { 0 };
  wyrelog_error_t rc = wyl_policy_store_service_handoff_escrow_load (store,
      tuple.escrow_id, &escrow);
  WylServiceCredentialHandoffDeliveryProof proof = {
    .source = preflight->source,
    .tuple = tuple,
    .actor_subject_id = preflight->actor_subject_id,
    .operation = preflight->operation,
    .deadline_at_us = preflight->deadline_at_us,
    .receipt_version = preflight->receipt_version,
    .destination = preflight->destination,
    .reservation_id = preflight->reservation_id,
    .parent_identity = preflight->parent_identity,
    .stage_basename = preflight->stage_basename,
    .stage_identity = preflight->stage_identity,
    .publication_receipt_id = preflight->publication_receipt_id,
  };
  memcpy (proof.target_digest, preflight->target_digest, 32);
  if (rc == WYRELOG_E_OK && !delivery_escrow_matches (&escrow, &proof))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_service_handoff_escrow_unseal (store, &escrow,
        out_secret);
  wyl_policy_service_handoff_escrow_info_clear (&escrow);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_handoff_delivery_confirm_inspection
    (WylServiceCredentialHandoffDeliveryPreflight * preflight,
    const WyctlPublicationResult * exact_result,
    WylServiceCredentialHandoffDeliveryCapability ** out_capability)
{
  if (out_capability != NULL)
    *out_capability = NULL;
  if (preflight == NULL || exact_result == NULL || out_capability == NULL
      || preflight->consumed)
    return WYRELOG_E_INVALID;
  preflight->consumed = TRUE;
  if (exact_result->version != WYCTL_PUBLICATION_RESULT_VERSION
      || exact_result->kind != WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE
      || !exact_result->exact_identity || exact_result->cleanup_required)
    return WYRELOG_E_POLICY;
  WylServiceCredentialHandoffDeliveryCapability *capability =
      g_try_new0 (WylServiceCredentialHandoffDeliveryCapability, 1);
  if (capability == NULL)
    return WYRELOG_E_NOMEM;
  capability->proof = preflight;
  *out_capability = capability;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyl_service_credential_handoff_delivery_consume_core
    (WylServiceAuthorityTransaction * transaction, wyl_policy_store_t * store,
    WylServiceCredentialHandoffDeliveryCapability * capability,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition) {
  if (out_outcome != NULL)
    *out_outcome = 0;
  if (out_disposition != NULL)
    wyl_policy_service_handoff_disposition_result_clear (out_disposition);
  if (store == NULL || capability == NULL || capability->proof == NULL
      || out_outcome == NULL || out_disposition == NULL || capability->consumed
      || capability->proof->store != store)
    return WYRELOG_E_INVALID;
  capability->consumed = TRUE;
  WylPolicyServiceHandoffExactTuple tuple = delivery_tuple (capability->proof);
  return wyl_policy_store_handoff_consume_delivered_core (transaction, store,
      &tuple, capability->proof->actor_subject_id,
      capability->proof->proof_digest, out_outcome, out_disposition);
}
