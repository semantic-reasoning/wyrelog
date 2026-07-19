/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/handle.h"
#include "wyrelog/error.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/auth/service-credential-operation-journal-private.h"

G_BEGIN_DECLS
/* Injected authority revalidation. Returns WYRELOG_E_OK to permit the bound
 * actor to proceed, or a denial code that the boundary propagates verbatim.
 * The actor_subject_id argument is always the durable record's bound actor. */
typedef wyrelog_error_t (*WylServiceCredentialOperationRevalidateFn)
  (gpointer data, const gchar * actor_subject_id);

/* Borrowed execution seam for a single authorize-and-execute call. All
 * pointers need only remain valid for the duration of that call.
 *   revalidate       required; runs immediately before the domain mutation.
 *   revalidate_data  opaque data forwarded to revalidate.
 *   rotate_runtime   required for a ROTATE record, NULL for ISSUE; its
 *                    old_credential_generation MUST equal the record's
 *                    expected_generation so the CAS can only bind the
 *                    generation the durable intent authorized. */
typedef struct
{
  WylServiceCredentialOperationRevalidateFn revalidate;
  gpointer revalidate_data;
  const wyl_service_credential_rotate_runtime_t *rotate_runtime;
} WylServiceCredentialOperationExecuteRuntime;

/* Authorize an already-loaded durable operation intent against the
 * authenticated caller and execute it through the checked service-credential
 * domain primitive.
 *
 * Design contract:
 *  - The caller is bound to the record: execution requires
 *    authenticated_actor_subject_id == record->actor_subject_id, and the
 *    domain primitive is always invoked with record->actor_subject_id so audit
 *    and event rows carry the durable bound actor, never a caller-supplied
 *    identity.
 *  - Authority is revalidated through runtime->revalidate immediately before
 *    delegating to the fenced/transactional domain primitive. In-transaction
 *    revalidation is out of scope for #508 (it would require a domain
 *    before-gate seam the issue's non-goals forbid); the domain call is itself
 *    fenced and transactional, and every denial precedes the single mutation
 *    so no side effect can occur before authorization completes.
 *  - The primitive persists no token, permission snapshot or authorization
 *    artifact and does not alter the record schema. Real wyl_decide wiring and
 *    end-to-end authority coverage belong to the daemon glue in #515; here
 *    revalidate is injected and unit-tested with a stub.
 *  - This primitive is NEVER called from recovery/replay; recovery stays
 *    metadata-only and reauth-free.
 *  - Expiry/freshness gating of committed-free intent is #515's recover-gating
 *    responsibility, not this boundary's.
 *  - out follows the issue-result owned-output contract: it is cleared on
 *    entry (when non-NULL) and left cleared on every failure; on success it
 *    carries the caller-owned successor secret and credential DTO.
 *
 * Returns WYRELOG_E_INVALID for malformed arguments or a record/actor that
 * fails validation, WYRELOG_E_POLICY for a state, actor-mismatch or
 * generation-binding denial, the domain rc on dispatch, or the revalidation rc
 * when authority is refused. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_authorize_and_execute
    (WylHandle * handle, const WylServiceCredentialOperationRecord * record,
    const gchar * authenticated_actor_subject_id,
    const WylServiceCredentialOperationExecuteRuntime * runtime,
    wyl_service_credential_issue_result_t * out);

G_END_DECLS
