/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/* Narrow policy-store friend primitives for the auth handoff-delivery
 * authority.  General store consumers must use store-private.h instead. */
#include "policy/store-private.h"

G_BEGIN_DECLS typedef enum
{
  WYL_POLICY_HANDOFF_PUBLICATION_ACTIVE = 1,
  WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_EXPIRED = 2,
  WYL_POLICY_HANDOFF_PUBLICATION_SUCCESSOR_REVOKED = 3,
} WylPolicyServiceHandoffPublicationOutcome;

G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_classify_for_publication_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_lookup_delivered_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    gboolean * out_found,
    WylPolicyServiceHandoffDispositionResult * out_disposition);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_backfill_delivered_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    WylPolicyServiceHandoffDispositionResult * out_disposition);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_policy_store_handoff_consume_delivered_core
    (WylServiceAuthorityTransaction * transaction,
    wyl_policy_store_t * store,
    const WylPolicyServiceHandoffExactTuple * tuple,
    const gchar * actor_subject_id,
    const guint8 proof_digest[WYL_POLICY_SERVICE_HANDOFF_DIGEST_BYTES],
    WylPolicyServiceHandoffPublicationOutcome * out_outcome,
    WylPolicyServiceHandoffDispositionResult * out_disposition);

G_END_DECLS
