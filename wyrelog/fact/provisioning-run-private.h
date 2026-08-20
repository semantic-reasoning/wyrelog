/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/provisioning-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS;

/* Crash-safe provisioning coordinator: drives one per-graph store from
 * reservation to ACTIVE around the filesystem construct, keeping the policy
 * FSM (fact_graph_provisioning phase + coupled graph authority lifecycle) and
 * the on-disk retained pair consistent across every crash seam.  Still DARK:
 * no live create/open call path is rewired here.
 *
 * The coordinator drives ONLY wyl_policy_store_graph_provisioning_transition;
 * that primitive atomically couples the graph authority (PROVISIONING -> ACTIVE
 * on verified->active, or -> DEGRADED on any fault).  The persisted provisioning
 * phase is the single source of truth for where to resume; every filesystem
 * step is idempotent so a resume re-executes the step for the persisted phase.
 * A step commits its filesystem effect first, then records the phase, so the
 * durable phase lags true progress by at most one seam. */

/* Reserve (mints the operation UUID + moves the authority to PROVISIONING) and
 * drive a fresh provisioning to ACTIVE.  If an in-flight operation already
 * matches the input, attaches to it and drives it to completion (idempotent).
 * Returns WYRELOG_E_POLICY when the authority is not reservable (already active,
 * sealed, or otherwise non-legacy) or a foreign store already occupies the
 * final name; WYRELOG_E_BUSY on a lost phase-CAS race (retry via recover);
 * WYRELOG_E_IO and other faults after best-effort driving the record and coupled
 * authority to DEGRADED.  out_record is optional and receives the final record. */
wyrelog_error_t wyl_fact_graph_provisioning_run (wyl_policy_store_t * store,
    const WylPolicyGraphProvisioningInput * input, const gchar * fact_root,
    WylPolicyGraphProvisioningRecord ** out_record);

/* Resume one in-flight operation, addressed by its canonical operation UUID,
* from whatever durable (phase, filesystem-seam) a crash left, to ACTIVE (or
* DEGRADED on an unrecoverable fault).  Idempotent: replaying an ACTIVE
* operation returns WYRELOG_E_OK; a terminal DEGRADED record returns
* WYRELOG_E_POLICY.  out_record is optional and receives the final record. */
wyrelog_error_t wyl_fact_graph_provisioning_recover (wyl_policy_store_t * store,
    const gchar * op_uuid, const gchar * fact_root,
    WylPolicyGraphProvisioningRecord ** out_record);

/* Reconcile one relation reserved in ACTIVATING state.  The caller must hold
 * the writable, graph-scoped fact-store lease.  Projection preparation and
 * exact validation complete before the policy generation-CAS publishes ACTIVE;
 * failures retain the previous active version and mark the activation
 * DEGRADED.  This deliberately does not refresh replay state. */
wyrelog_error_t wyl_fact_relation_activation_reconcile
  (wyl_policy_store_t * policy_store, wyl_fact_store_t * fact_store,
    const gchar * tenant_id, const gchar * graph_id,
    const gchar * namespace_id, const gchar * relation_name,
    guint64 expected_activation_generation,
    WylPolicyAuthorityMutationResult * out_result);
G_END_DECLS;
