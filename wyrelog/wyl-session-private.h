/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyl-id-private.h"
#include "wyrelog/session.h"

G_BEGIN_DECLS;

typedef enum wyl_session_auth_method_t
{
  WYL_SESSION_AUTH_METHOD_HUMAN = 0,
  WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
  WYL_SESSION_AUTH_METHOD_LAST_,
} wyl_session_auth_method_t;

typedef struct wyl_service_session_descriptor_t
{
  wyl_id_t session_id;
  const gchar *jti;
  const gchar *subject_id;
  const gchar *tenant_id;
  const gchar *credential_id;
  guint64 credential_generation;
  gint64 issued_at_seconds;
  gint64 expires_at_seconds;
} wyl_service_session_descriptor_t;

/*
 * Constructs detached metadata only. The returned session is internally
 * ACTIVE but is not registered or published and has no handle association.
 * Every string in |descriptor| is copied. The exact caller-supplied session
 * id and timestamps are retained unchanged.
 */
G_GNUC_INTERNAL wyrelog_error_t wyl_session_new_service_detached (const
    wyl_service_session_descriptor_t * descriptor, WylSession ** out_session);

/* String accessors return owned copies and the id accessor copies by value.
 * Service metadata itself is immutable after construction. */
G_GNUC_INTERNAL wyl_session_auth_method_t
wyl_session_get_auth_method_private (const WylSession * session);
G_GNUC_INTERNAL gboolean wyl_session_is_active_private (const
    WylSession * session);
G_GNUC_INTERNAL gboolean wyl_session_is_active_human_private (const
    WylSession * session);
/* TRUE only after this exact live human session completed an MFA transition.
 * Skip-MFA login, service sessions, and token refresh never set this bit. */
G_GNUC_INTERNAL gboolean wyl_session_is_mfa_assured_private (const
    WylSession * session);
/* Single coherent management liveness primitive.  Returns TRUE only when
 * |session| is an ACTIVE human session (decided by one atomic state load),
 * optionally MFA-assured, whose immutable identity (session id, actor,
 * tenant) matches the caller's expectation exactly.  This is the decisive
 * linearization gate: a logout that flips state to CLOSED before this load
 * makes it fail closed with zero durable work.  Fail-closed on any NULL or
 * mismatch. */
G_GNUC_INTERNAL gboolean wyl_session_liveness_check_private (const
    WylSession * session, const gchar * expect_session_id,
    const gchar * expect_actor, const gchar * expect_tenant,
    gboolean require_mfa);
G_GNUC_INTERNAL wyrelog_error_t wyl_session_copy_persistent_id_private (const
    WylSession * session, wyl_id_t * out_id);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_jti_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_subject_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_tenant_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_credential_id_private (const
    WylSession * session);
G_GNUC_INTERNAL guint64 wyl_session_get_service_credential_generation_private
  (const WylSession * session);
G_GNUC_INTERNAL gint64 wyl_session_get_service_issued_at_seconds_private (const
    WylSession * session);
G_GNUC_INTERNAL gint64 wyl_session_get_service_expires_at_seconds_private (const
    WylSession * session);
/* Allocation-free exact matcher for publication/rollback while the daemon
 * context lock is held. It includes ACTIVE state, auth method, session id,
 * JTI, subject, tenant, credential generation, and both timestamps. */
G_GNUC_INTERNAL gboolean wyl_session_matches_service_tuple_private (const
    WylSession * session, const gchar * session_id, const gchar * jti,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * credential_id, guint64 credential_generation,
    gint64 issued_at_seconds, gint64 expires_at_seconds);

/*
 * Typed receipt describing how a TOTP MFA_OK commit attempt resolved.
 * Derived from the committed-publication stage and return code so tests
 * can distinguish the exactly-one winner from a superseded replay and
 * the durable-uncertainty paths.  The public entry point still collapses
 * these to E_OK / E_POLICY / E_INTERNAL.
 */
typedef enum wyl_mfa_totp_receipt_t
{
  WYL_MFA_TOTP_RECEIPT_WON_COMMITTED = 0,
  WYL_MFA_TOTP_RECEIPT_REPLAY_SUPERSEDED,
  WYL_MFA_TOTP_RECEIPT_PRECOMMIT_STORE_FAILURE,
  WYL_MFA_TOTP_RECEIPT_COMMIT_UNCERTAIN,
  WYL_MFA_TOTP_RECEIPT_POSTCOMMIT_PUBLICATION_FAILURE,
} WylMfaTotpReceipt;

/*
 * Atomically consume a verified TOTP proof and publish the principal's
 * MFA_REQUIRED -> AUTHENTICATED transition (issue #751).  A single
 * committed-publication transaction performs the pre-state gate, the
 * compare-and-advance of the replay watermark, the failure-counter
 * reset, and the principal state+event mutation; concurrent callers
 * presenting the same matched_step therefore produce exactly one winner.
 * On the winning commit the session's mfa_assured bit is set.  @matched_step
 * is the TOTP step the validator already matched.  @out_receipt is
 * optional (pass NULL); when supplied it receives the typed resolution.
 * Returns E_OK on the winning commit, E_POLICY on a superseded/replayed
 * or non-mfa_required principal, E_INTERNAL on a store or durability
 * failure, E_BUSY if the engine session cannot be acquired.
 *
 * Exported (not G_GNUC_INTERNAL) so the dedicated concurrency test can
 * drive it directly, mirroring the policy/store-private.h helpers.
 */
wyrelog_error_t wyl_session_totp_commit_mfa_ok (WylHandle * handle,
    WylSession * session, gint64 matched_step, WylMfaTotpReceipt * out_receipt);

/*
 * Proof-bearing boundary for validators that publish the principal
 * transition THEMSELVES, atomically with consuming the proof (issue
 * #751).  Same guards as the public wyl_session_mfa_verify_with_proof,
 * but it does not drive mark_session_mfa_verified afterwards -- doing so
 * would re-append the MFA_OK event and could authenticate a superseded
 * attempt.
 *
 * Kept separate from the public entry point, which documents the
 * opposite contract (it applies the transition for the caller).  A
 * distinct typedef cannot express the split: in C a typedef is a
 * synonym, so both validator contracts share one type and the compiler
 * cannot tell them apart.  The boundary the caller picks is the contract.
 *
 * Exported (not G_GNUC_INTERNAL) so wyrelogd, which links libwyrelog as
 * a separate executable, can call it -- same reason as above.
 */
wyrelog_error_t wyl_session_mfa_verify_with_publishing_validator (WylHandle *
    handle, WylSession * session, const gchar * proof,
    WylMfaValidator validator, gpointer user_data);

G_END_DECLS;
