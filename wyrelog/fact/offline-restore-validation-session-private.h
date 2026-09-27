/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "fact/offline-restore-validation-private.h"
#include "fact/replay-scheduler-private.h"
#include "fact/runtime-private.h"
#include "policy/store-private.h"

G_BEGIN_DECLS

typedef struct WylFactOfflineRestoreValidationSession
    WylFactOfflineRestoreValidationSession;

/* Tenant-wide, observational validation of a pristine all-bound journal.
 * Caller-established manifest authentication remains a prerequisite: neither
 * decoding nor the durable trust assertion authenticates the supplied bytes.
 * Borrows policy; references runtime and manifest. Owns root authority,
 * directories, readers, provisioning pairs and runtime quiescence until free
 * or failed run. Existing runtime entries are required (NOT_FOUND otherwise).
 * Constructor acquisition uses one monotonic timeout budget, is not
 * cancellable, and may establish the existing policy/root binding.
 *
 * No journal flags, publication, lifecycle changes or filesystem mutations
 * occur. Existing provisioning-pair constructors retain internal writable
 * main handles, but this session never uses them for mutation. Windows fails
 * closed before filesystem access. Calls are serialized and non-reentrant. */
wyrelog_error_t wyl_fact_offline_restore_validation_session_new
  (wyl_policy_store_t *policy, const gchar *fact_root,
    WylFactGraphRuntimeManager *runtime_manager, GBytes *canonical_manifest,
    const gchar *operation_uuid, guint64 expected_revision,
    gint64 drain_timeout_us,
    WylFactOfflineRestoreValidationSession **out_session);

/* Run directly on a replay worker; caller retains session and policy through
 * return. Every call repeats replay and final observations. Cancellation is
 * checked between bounded operations, not inside context-free content scans.
 * Failure clears success evidence, terminalizes the session and immediately
 * releases authority. Retry requires a new session. Success retains root and
 * runtime exclusion, NOT a freeze of independent policy/external writers and
 * NOT a publication permit. Later publication needs fresh authority checks
 * and its own durable recovery protocol. */
wyrelog_error_t wyl_fact_offline_restore_validation_session_run
  (WylFactOfflineRestoreValidationSession *session,
    WylFactReplayJobContext *job_context,
    WylFactOfflineRestoreValidationResult *out_result);
void wyl_fact_offline_restore_validation_session_free
  (WylFactOfflineRestoreValidationSession *session);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactOfflineRestoreValidationSession,
    wyl_fact_offline_restore_validation_session_free)

/* Deterministic validation-boundary seam, invoked after each graph's replay.
 * The callback must not reenter/free the session. No capability is exposed. */
void wyl_fact_offline_restore_validation_session_set_checkpoint_for_test
  (WylFactOfflineRestoreValidationSession *session,
    wyrelog_error_t (*checkpoint) (const gchar *graph_id, gpointer user_data),
    gpointer user_data);

G_END_DECLS
