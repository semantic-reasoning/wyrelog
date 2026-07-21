/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "wyrelog/handle.h"
#include "wyrelog/error.h"
#include "wyrelog/session.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-private.h"
#include "wyrelog/auth/service-credential-operation-journal-private.h"
#include "wyrelog/auth/service-credential-operation-storage-private.h"

G_BEGIN_DECLS
    typedef struct wyctl_publication_backend_vtable_t
    WyctlPublicationBackendVTable;
/* Injected authority revalidation. Returns WYRELOG_E_OK to permit the bound
 * actor to proceed, or a denial code that the boundary propagates verbatim.
 * The actor_subject_id argument is always the durable record's bound actor. */
typedef wyrelog_error_t (*WylServiceCredentialOperationRevalidateFn)
  (gpointer data, const gchar * actor_subject_id);

/* Borrowed execution seam for a single authorize-and-execute call. All
 * pointers need only remain valid for the duration of that call.
 *   revalidate       required; runs inside the domain WRITE lease before any
 *                    fence, CVK, transaction or RNG side effect.
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
 *  - Authority is revalidated through runtime->revalidate after the domain
 *    WRITE lease is acquired and before fence lookup, CVK access, transaction
 *    start or credential RNG. Every denial therefore shares the domain's
 *    terminal cleanup path without creating mutation side effects.
 *  - The primitive persists no token, permission snapshot or authorization
 *    artifact and does not alter the record schema. This injected callback
 *    proves the execution boundary but does not define whether a real
 *    wyl_decide denial emits its own audit record; production decision/audit
 *    wiring and end-to-end authority coverage belong to daemon glue #515.
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

/* Borrowed runtime for one authenticated escrow-backed invocation.  The
 * executor derives the authorization resource from session; callers cannot
 * substitute a resource or policy scope. */
typedef struct
{
  WylSession *session;
  const gchar *authenticated_actor_subject_id;
  gint64 guard_timestamp;
  const gchar *guard_loc_class;
  gint64 guard_risk;
  const gchar *decision_request_id;
  const WyctlPublicationBackendVTable *publication;
  gpointer publication_data;
  const wyl_service_credential_rotate_runtime_t *rotate_runtime;
    gint64 (*now_us) (gpointer data);
  gpointer clock_data;
  GCancellable *cancellable;
  /* Deterministic private test checkpoint immediately after an ALLOW while
   * the current service-auth WRITE lease is still held.  Non-reentrant. */
  void (*after_authorization) (gpointer data);
  gpointer authorization_checkpoint_data;
} WylServiceCredentialOperationHandoffExecuteRuntime;

/* Execute or resume one v5 journal operation without returning credential
 * material.  The request lifecycle lock is held from the initial load through
 * the final checkpoint/delete attempt.  Each invocation performs a fresh
 * authoritative wr.service_credential.manage decision for every service
 * mutation lease it enters.  out_record is caller-owned and contains durable,
 * non-secret state only; it is unchanged on failure. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_execute_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationHandoffExecuteRuntime * runtime,
    WylServiceCredentialOperationRecord * out_record);

/* Exported escrow-handoff front door.  It takes an operation request whose
 * escrow_id is derived deterministically here from request_id (any
 * caller-supplied escrow_id is ignored, and escrow_binding_digest is forced to
 * zero because the real binding is minted at server-commit), durably
 * begins-or-replays the operation, then drives it to a terminal or
 * operator-action state through execute_handoff.
 * out_record is caller-owned, cleared on entry, populated with durable,
 * non-secret state on success, and left cleared on failure.  Inner return
 * codes propagate verbatim.
 *
 * Idempotency contract: request->expires_at_us is the operator-chosen
 * ABSOLUTE credential expiry, and request->expected_generation is the rotate
 * CAS target.  Both are part of the immutable operation identity and MUST be
 * stable across retries: a well-behaved caller resends the identical absolute
 * expires_at_us so the operation replays.  The daemon MUST take expires_at_us
 * from the client request as an absolute value and MUST NOT server-recompute
 * now()+TTL, which would diverge retries and force a spurious conflict. */
wyrelog_error_t
    wyl_service_credential_operation_coordinator_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    const WylServiceCredentialOperationHandoffExecuteRuntime * runtime,
    WylServiceCredentialOperationRecord * out_record);

G_END_DECLS
