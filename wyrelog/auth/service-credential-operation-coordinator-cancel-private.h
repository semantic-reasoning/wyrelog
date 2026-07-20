/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "auth/service-credential-domain-private.h"
#include "auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/handle.h"
#include "wyrelog/session.h"

G_BEGIN_DECLS
/* Borrowed runtime for one authenticated durable cancellation claim.  The
 * coordinator derives the authorization resource from the active human
 * session; callers cannot substitute the resource or the policy scope. */
    typedef struct
{
  WylSession *session;
  const gchar *authenticated_actor_subject_id;
  gint64 guard_timestamp;
  const gchar *guard_loc_class;
  gint64 guard_risk;
  const gchar *decision_request_id;
  GCancellable *cancellable;
  /* Deterministic private test checkpoint immediately after an ALLOW while
   * the current service-auth WRITE lease is still held.  Non-reentrant. */
  void (*after_authorization) (gpointer data);
  gpointer authorization_checkpoint_data;
} WylServiceCredentialOperationHandoffCancelRuntime;

/* Caller-minted durable identities.  They remain explicit so a retry after an
 * ambiguous transport result can reproduce exactly the original claim. */
typedef struct
{
  const gchar *cancellation_request_id;
  const gchar *disposition_id;
  const gchar *audit_id;
} WylServiceCredentialOperationHandoffCancelRequest;

/* Append or exactly replay an authenticated cancellation claim for a v5
 * handoff in SERVER_COMMITTED, PUBLICATION_PLANNED, or
 * PUBLICATION_PREPARED. FILE_PUBLISHED and CLEANUP_REQUIRED are deliberately
 * ineligible: cancellation cannot suppress delivery proof or cleanup. The
 * per-operation lifecycle lock spans journal loading, tenant binding, fresh
 * wr.service_credential.manage authorization, and the atomic authority write.
 * This API never checkpoints or otherwise mutates the journal; subsequent
 * execution observes the ATTENTION disposition through the maintenance gate
 * before any publication or unseal callback.
 *
 * cancellation_request_id and decision_request_id are distinct canonical
 * KSUIDs, each distinct from original_request_id.  disposition_id and
 * audit_id are distinct canonical UUIDs.  The current authenticated actor
 * must be distinct from the durable original actor.  Exact replay still
 * performs fresh authorization. */
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_cancel_handoff
    (WylHandle * handle,
    const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * original_request_id,
    const WylServiceCredentialOperationHandoffCancelRequest * request,
    const WylServiceCredentialOperationHandoffCancelRuntime * runtime,
    wyl_service_credential_handoff_cancellation_result_t * out_result);

G_END_DECLS
