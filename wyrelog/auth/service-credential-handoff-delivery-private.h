/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "policy/store-handoff-delivery-private.h"
#include "wyctl/wyctl-publication-private.h"

G_BEGIN_DECLS
    typedef struct _WylServiceCredentialHandoffDeliveryCapability
    WylServiceCredentialHandoffDeliveryCapability;
typedef struct _WylServiceCredentialHandoffDeliveryPreflight
    WylServiceCredentialHandoffDeliveryPreflight;

typedef enum
{
  WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_FILE_PUBLISHED = 1,
  WYL_SERVICE_HANDOFF_DELIVERY_SOURCE_CLEANUP_REQUIRED = 2,
} WylServiceCredentialHandoffDeliverySource;

typedef struct
{
  WylServiceCredentialHandoffDeliverySource source;
  WylPolicyServiceHandoffExactTuple tuple;
  const gchar *actor_subject_id;
  const gchar *operation;
  guint8 target_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES];
  gint64 deadline_at_us;
  guint32 receipt_version;
  const gchar *destination;
  const gchar *reservation_id;
  const gchar *parent_identity;
  const gchar *stage_basename;
  const gchar *stage_identity;
  const gchar *publication_receipt_id;
} WylServiceCredentialHandoffDeliveryProof;

typedef enum
{
  WYL_SERVICE_HANDOFF_DELIVERY_ACTIVE = 1,
  WYL_SERVICE_HANDOFF_DELIVERY_REPLAYED = 2,
  WYL_SERVICE_HANDOFF_DELIVERY_LEGACY_BACKFILLED = 3,
  WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_EXPIRED = 4,
  WYL_SERVICE_HANDOFF_DELIVERY_SUCCESSOR_REVOKED = 5,
} WylServiceCredentialHandoffDeliveryOutcome;

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_prepare_delivery_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylServiceCredentialHandoffDeliveryProof * proof,
    WylServiceCredentialHandoffDeliveryOutcome * out_outcome,
    WylServiceCredentialHandoffDeliveryPreflight ** out_preflight,
    WylPolicyServiceHandoffDispositionResult * out_disposition);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_delivery_unseal
    (wyl_policy_store_t * store,
    WylServiceCredentialHandoffDeliveryPreflight * preflight,
    wyl_policy_service_handoff_secret_t ** out_secret);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_delivery_confirm_inspection
    (WylServiceCredentialHandoffDeliveryPreflight * preflight,
    const WyctlPublicationResult * exact_result,
    WylServiceCredentialHandoffDeliveryCapability ** out_capability);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_handoff_delivery_consume_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    WylServiceCredentialHandoffDeliveryCapability * capability,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition);
G_GNUC_INTERNAL void wyl_service_credential_handoff_delivery_capability_free
    (WylServiceCredentialHandoffDeliveryCapability * capability);
G_GNUC_INTERNAL void wyl_service_credential_handoff_delivery_preflight_free
    (WylServiceCredentialHandoffDeliveryPreflight * preflight);

G_END_DECLS
