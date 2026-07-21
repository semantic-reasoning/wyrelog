/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"
#include "wyrelog/session.h"
#include "auth/service-credential-operation-journal-private.h"

G_BEGIN_DECLS;

typedef struct wyctl_publication_backend_vtable_t WyctlPublicationBackendVTable;

/* Immutable, caller-supplied identity of one escrow credential handoff.  These
 * fields describe WHAT the operation is; they must be resent verbatim on every
 * retry.  In particular expires_at_us is the operator-chosen ABSOLUTE credential
 * expiry and expected_generation is the rotate CAS target: the daemon takes them
 * from the client request and never server-recomputes now()+TTL, so retries do
 * not diverge.  The publication parent_identity is NOT a client input: the daemon
 * derives it from its own credential_publication_root via the publication
 * backend's root_identity accessor. */
typedef struct
{
  WylServiceCredentialOperationKind kind;
  const gchar *request_id;
  /* ISSUE only. */
  const gchar *subject_id;
  const gchar *tenant_id;
  /* ROTATE only. */
  const gchar *old_credential_id;
  guint64 expected_generation;
  const gchar *destination;
  gint64 expires_at_us;
} WylDaemonServiceCredentialHandoffInputs;

/* Borrowed authenticated caller context plus the two opt-in roots that gate the
 * handoff surface.  operation_root and credential_publication_root are the
 * daemon's optional operation-journal and owner-publication roots; when either
 * is NULL or empty the surface is unconfigured and the call returns
 * WYRELOG_E_NOT_FOUND (the route reports it unavailable). */
typedef struct
{
  WylHandle *handle;
  WylSession *session;
  const gchar *authenticated_actor_subject_id;
  gint64 guard_timestamp;
  const gchar *guard_loc_class;
  gint64 guard_risk;
  const gchar *decision_request_id;
  const gchar *operation_root;
  const gchar *credential_publication_root;
  GCancellable *cancellable;
#ifdef WYL_TEST_DAEMON_HTTP
  /* Test-only publication backend injection.  When publication_override is
   * non-NULL the module drives it (with publication_override_data) instead of
   * opening the production owner-publication backend from
   * credential_publication_root, so focused tests can exercise the handoff
   * without the real filesystem publication semantics.  Production callers leave
   * both NULL.  This seam is compiled only into test builds; the shipped daemon
   * never carries a publication-backend bypass. */
  const WyctlPublicationBackendVTable *publication_override;
  gpointer publication_override_data;
#endif
} WylDaemonServiceCredentialHandoffContext;

/* Run one authenticated escrow credential handoff to completion and, on
 * success, emit a non-secret JSON receipt describing the durable outcome
 * (state, request_id, credential_id, generation, destination,
 * publication_receipt_id, delivered).  The receipt never carries credential
 * material.  This entry point is NOT routed: it is the reusable core the future
 * HTTP handler and focused tests drive directly.
 *
 * out_json is caller-owned and set only on WYRELOG_E_OK; it is left NULL on any
 * failure.  Returns WYRELOG_E_NOT_FOUND when the handoff roots are unconfigured,
 * WYRELOG_E_INVALID for malformed arguments, and otherwise the front-door
 * return code verbatim. */
wyrelog_error_t
wyl_daemon_service_credential_handoff (const
    WylDaemonServiceCredentialHandoffContext * ctx,
    const WylDaemonServiceCredentialHandoffInputs * inputs, gchar ** out_json);

G_END_DECLS;
