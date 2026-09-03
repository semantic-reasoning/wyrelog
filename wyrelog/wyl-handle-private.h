/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/handle.h"
#include "wyrelog/engine.h"
#include "wyrelog/audit.h"
#include "wyrelog/session.h"
#include "policy/store-private.h"
#include "auth/service-auth-coordination-private.h"

#ifdef WYL_HAS_FACT_STORE
#include "fact/graph-seal-private.h"
#include "fact/replay-private.h"
#endif

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif

G_BEGIN_DECLS;

typedef struct
{
  const gchar *template_dir;
  const gchar *policy_store_path;
  const gchar *policy_keyprovider_path;
  /* Consumed only by audit builds; unconditional to keep the layout stable. */
  const gchar *audit_store_path;
  /* Canonical authority root for graph-local fact stores. */
  const gchar *fact_root;
  /* Test-only deterministic seam immediately after writer-lease acquire. */
  void (*fact_root_lease_acquired_checkpoint) (gpointer data);
  gpointer fact_root_lease_acquired_checkpoint_data;
  gboolean production_mode;
  gboolean require_template_manifest;
} WylHandleOpenOptions;

/*
 * Opens a handle with private storage paths. Public wyl_init() keeps its
 * historical in-memory store contract and delegates here with NULL paths.
 * A non-NULL template_dir opens the read/delta engine pair after the policy
 * store is ready, then replays durable rows into wirelog facts.
 */
wyrelog_error_t wyl_handle_open_with_options (const WylHandleOpenOptions *
    opts, WylHandle ** out_handle);

#ifdef WYL_HAS_AUDIT
/*
 * Returns the borrowed audit connection owned by |self|. Lifetime
 * is tied to the WylHandle: the pointer is valid until wyl_shutdown
 * or g_object_unref. Available only when libwyrelog is built with
 * the audit feature option allowed; the function does not exist in
 * non-audit builds (and neither does the underlying type).
 */
wyl_audit_conn_t *wyl_handle_get_audit_conn (WylHandle * self);

/*
 * Replays persisted policy-store audit rows into the handle-owned runtime
 * audit connection. This follows the audit connection lifecycle and does not
 * append the replayed rows back into the policy store.
 */
wyrelog_error_t wyl_handle_load_policy_store_audit_events (WylHandle * self);
#endif

/*
 * Returns the borrowed policy authority store owned by |self|. The pointer is
 * valid until wyl_shutdown or g_object_unref.
 */
wyl_policy_store_t *wyl_handle_get_policy_store (WylHandle * self);

/*
 * Wraps an already-open policy |store| into a bare, offline maintenance
 * handle. The handle is constructed with only its service-auth authority (built
 * by the GObject constructor); no engine pair, audit connection, resolver,
 * exchange, or publication subsystem is started, and the #614 unsafe-closure
 * reload latch is never armed, so a plain acquire_write over the returned
 * handle succeeds. The handle takes ownership of |store| on every outcome and
 * closes it when the last reference is released (or immediately on a failure
 * that produced no handle). Reserved for the offline #618 service permission
 * remediation lane.
 */
wyrelog_error_t wyl_handle_adopt_offline_maintenance_store
  (wyl_policy_store_t * store, WylHandle ** out_handle);
/* Accessed only while the handle's service-auth authority monitor is held. */
WylServiceAuthUnavailableReason
wyl_handle_service_auth_unavailable_reason_locked (WylHandle * self);
void wyl_handle_service_auth_set_unavailable_reason_locked (WylHandle * self,
    WylServiceAuthUnavailableReason reason);
/*
 * Ordered private shutdown used by the public void wrapper and finalization.
 * Returns BUSY without changing lifecycle state when called by a thread that
 * owns a policy-store pin/service-auth lease, or when waiting behind another
 * shutdown could invert against an engine session owned by the caller.
 */
wyrelog_error_t wyl_handle_shutdown_ordered (WylHandle * self);
wyrelog_error_t wyl_handle_policy_store_pin_current (WylHandle * self,
    wyl_policy_store_t ** out_store);
void wyl_handle_policy_store_unpin (WylHandle * self,
    wyl_policy_store_t * expected_store);
/*
 * Terminal, non-asserting counterpart used when an authority owner must be
 * consumed even after detecting cleanup corruption.  If the calling thread
 * owns a pin, exactly one pin is released.  A store-identity mismatch is
 * reported after restoring that accounting; contradictory counter ownership
 * is reported without guessing at a repair.
 */
wyrelog_error_t wyl_handle_policy_store_unpin_terminal (WylHandle * self,
    wyl_policy_store_t * expected_store);
wyrelog_error_t wyl_handle_policy_store_capture_generation (WylHandle * self,
    wyl_policy_store_t * expected_store, guint64 * out_generation);
wyrelog_error_t wyl_handle_policy_store_validate_generation (WylHandle * self,
    wyl_policy_store_t * expected_store, guint64 generation);
void wyl_handle_policy_store_test_advance_generation (WylHandle * self);
void wyl_handle_policy_store_test_set_generation_max (WylHandle * self);
/* Test-only, one-shot checkpoint invoked under the lifecycle lock. */
void wyl_handle_policy_store_set_pin_checkpoint (WylHandle * self,
    void (*checkpoint) (gpointer data), gpointer data);
void wyl_handle_policy_store_set_shutdown_wait_checkpoint_for_test
  (WylHandle * self, void (*checkpoint) (gpointer data), gpointer data);
void wyl_handle_policy_store_pin_snapshot_for_test (WylHandle * self,
    guint * out_total_pins, guint * out_current_thread_pins);

/* Borrowed handle-owned service-auth coordination authority. */
WylServiceAuthAuthority *wyl_handle_get_service_auth_authority
  (WylHandle * self);
wyrelog_error_t wyl_handle_reload_engine_pair_with_service_auth_write
  (WylHandle * self, WylServiceAuthWriteLease * write_lease);

/* Private typed capability proving that the caller owns one recursive engine
 * session. Production consumers must use these operations instead of carrying
 * raw symbol ids across independently locked handle calls. */
typedef struct _WylEngineSession WylEngineSession;
WylEngineSession *wyl_engine_session_acquire (WylHandle * self);
void wyl_engine_session_release (WylEngineSession * session);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylEngineSession, wyl_engine_session_release);
/*
 * Starts the sole service-authority transaction allowed below a retained,
 * outermost engine session. The session, store generation and WRITE lease
 * must prove one exact COORDINATION -> ENGINE parent chain.
 */
wyrelog_error_t
wyl_engine_session_begin_external_service_authority_transaction
  (WylEngineSession * session, wyl_policy_store_t * expected_store,
    guint64 expected_generation, WylServiceAuthWriteLease * write_lease,
    WylServiceAuthorityTransaction ** out_transaction);
wyrelog_error_t wyl_engine_session_intern_symbol (WylEngineSession * session,
    const gchar * symbol, gint64 * out_id);
wyrelog_error_t wyl_engine_session_lookup_symbol (WylEngineSession * session,
    const gchar * symbol, gint64 * out_id);
gchar *wyl_engine_session_dup_symbol (WylEngineSession * session, gint64 id);
wyrelog_error_t wyl_engine_session_insert (WylEngineSession * session,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_engine_session_remove (WylEngineSession * session,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_engine_session_contains (WylEngineSession * session,
    const gchar * relation, const gint64 * row, gsize ncols,
    gboolean * out_contains);
wyrelog_error_t wyl_engine_session_decide (WylEngineSession * session,
    const gint64 row[3], gboolean * out_allowed);
wyrelog_error_t wyl_engine_session_step_delta (WylEngineSession * session);
wyrelog_error_t wyl_engine_session_set_delta_callback
  (WylEngineSession * session, WylDeltaCallback cb, gpointer user_data);
wyrelog_error_t wyl_engine_session_replay_delta_insert
  (WylEngineSession * session, const gchar * relation, const gint64 * row,
    gsize ncols);


#ifdef WYL_TEST_HANDLE_SEAMS
typedef enum
{
  WYL_COMMITTED_PUBLICATION_FAULT_NONE = 0,
  WYL_COMMITTED_PUBLICATION_FAULT_VALIDATE,
  WYL_COMMITTED_PUBLICATION_FAULT_COMMIT,
  WYL_COMMITTED_PUBLICATION_FAULT_COMMIT_APPLIED_ERROR,
} WylCommittedPublicationFault;
void wyl_handle_set_committed_publication_fault_once_for_test
  (WylHandle * self, WylCommittedPublicationFault fault);

typedef enum
{
  WYL_ENGINE_SESSION_WAITING,
  WYL_ENGINE_SESSION_ACQUIRED,
} WylEngineSessionCheckpoint;

void wyl_handle_set_engine_session_checkpoint_for_test (WylHandle * self,
    void (*checkpoint) (WylEngineSessionCheckpoint phase, gpointer data),
    gpointer data);
typedef enum
{
  WYL_ENGINE_REPLACEMENT_WAITING,
  WYL_ENGINE_REPLACEMENT_ACQUIRED,
  WYL_ENGINE_REPLACEMENT_CANDIDATE_READY,
  WYL_ENGINE_REPLACEMENT_PUBLISHED,
} WylEngineReplacementCheckpoint;

typedef enum
{
  WYL_ENGINE_PARTIAL_FAULT_NONE,
  WYL_ENGINE_PARTIAL_FAULT_DELTA_INTERN,
  WYL_ENGINE_PARTIAL_FAULT_INTERN_ID_MISMATCH,
  WYL_ENGINE_PARTIAL_FAULT_DELTA_COMPOUND,
  WYL_ENGINE_PARTIAL_FAULT_COMPOUND_ID_MISMATCH,
} WylEnginePartialFault;

typedef enum
{
  WYL_ENGINE_REPLACEMENT_FAULT_NONE,
  WYL_ENGINE_REPLACEMENT_FAULT_VALIDATE,
  WYL_ENGINE_REPLACEMENT_FAULT_OPEN_READ,
  WYL_ENGINE_REPLACEMENT_FAULT_OPEN_DELTA,
  WYL_ENGINE_REPLACEMENT_FAULT_INTERN,
  WYL_ENGINE_REPLACEMENT_FAULT_AUDIT_FACTS,
  WYL_ENGINE_REPLACEMENT_FAULT_ARM_RULES,
  WYL_ENGINE_REPLACEMENT_FAULT_SESSION_ACTIVE,
  WYL_ENGINE_REPLACEMENT_FAULT_ROLE_PERMISSIONS,
  WYL_ENGINE_REPLACEMENT_FAULT_ROLE_MEMBERSHIPS,
  WYL_ENGINE_REPLACEMENT_FAULT_DIRECT_PERMISSIONS,
  WYL_ENGINE_REPLACEMENT_FAULT_PERMISSION_STATES,
  WYL_ENGINE_REPLACEMENT_FAULT_PERMISSION_EVENTS,
  WYL_ENGINE_REPLACEMENT_FAULT_PRINCIPAL_STATES,
  WYL_ENGINE_REPLACEMENT_FAULT_PRINCIPAL_EVENTS,
  WYL_ENGINE_REPLACEMENT_FAULT_SESSION_STATES,
  WYL_ENGINE_REPLACEMENT_FAULT_SESSION_EVENTS,
  WYL_ENGINE_REPLACEMENT_FAULT_CALLBACK,
  WYL_ENGINE_REPLACEMENT_FAULT_READBACK,
  WYL_ENGINE_REPLACEMENT_FAULT_SWAP,
} WylEngineReplacementFault;

void wyl_handle_set_engine_partial_fault_once_for_test (WylHandle * self,
    WylEnginePartialFault fault);
void wyl_handle_set_engine_replacement_fault_once_for_test (WylHandle * self,
    WylEngineReplacementFault fault);
void wyl_handle_set_engine_replacement_checkpoint_for_test (WylHandle * self,
    void (*checkpoint) (WylEngineReplacementCheckpoint phase, gpointer data),
    gpointer data);
void wyl_handle_set_reload_decision_checkpoint_for_test (WylHandle * self,
    void (*checkpoint) (WylEngineReplacementCheckpoint phase, gpointer data),
    gpointer data);
void wyl_handle_set_engine_operation_checkpoint_for_test (WylHandle * self,
    const gchar * relation, void (*checkpoint) (gpointer data), gpointer data);
void wyl_handle_set_engine_snapshot_checkpoint_for_test (WylHandle * self,
    void (*checkpoint) (gpointer data), gpointer data);
void wyl_handle_set_audit_replay_checkpoint_for_test (WylHandle * self,
    void (*checkpoint) (gpointer data), gpointer data);
void wyl_handle_set_committed_publication_checkpoint_for_test
  (WylHandle * self, void (*checkpoint) (gpointer data), gpointer data);
gboolean wyl_handle_engine_session_locked_for_test (WylHandle * self);
guint wyl_handle_engine_session_depth_for_test (WylHandle * self);
guint wyl_handle_pending_delta_count_for_test (WylHandle * self);
wyrelog_error_t wyl_handle_buffer_delta_for_test (WylHandle * self,
    const gchar * relation, const gint64 * row, guint ncols, WylDeltaKind kind);
wyrelog_error_t wyl_handle_flush_pending_deltas_for_test (WylHandle * self);
#endif

#ifdef WYL_HAS_FACT_STORE
wyrelog_error_t wyl_handle_replay_fact_graphs (WylHandle * self,
    wyl_fact_replay_summary_t * out_summary);
/* Targeted single-graph refresh (issue #546): refresh only |graph_info|'s
 * runtime engine, leaving all other graphs untouched.  |out_status| receives
 * the post-refresh runtime status. */
wyrelog_error_t wyl_handle_refresh_fact_graph (WylHandle * self,
    const wyl_policy_fact_graph_info_t * graph_info,
    WylFactGraphRuntimeStatus * out_status);
/* Capture one graph's runtime status without refreshing it (issue #546).
 * This is how a caller observes a graph's engine/operation generations, which
 * wyl_fact_graph_status_t deliberately does not carry.  It takes no
 * coordinator lock: the runtime manager locks the entry internally, so an
 * unrelated graph's generations can be read while another graph refreshes.
 * |out_status| is cleared on every path and must be released with
 * wyl_fact_graph_runtime_status_clear on success. */
wyrelog_error_t wyl_handle_get_fact_graph_runtime_status (WylHandle * self,
    const gchar * tenant_id, const gchar * graph_id,
    WylFactGraphRuntimeStatus * out_status);
/*
 * Commit one fact mutation (append or retract) and refresh only the graph it
 * committed to (issue #546).  This is the single internal entry point for a
 * fact mutation; the daemon's HTTP route delegates to it rather than
 * re-implementing the sequence.
 *
 * Ordering and idempotency contract:
 *
 *   1. The store commit is the LINEARIZATION POINT.  Until it returns
 *      WYRELOG_E_OK nothing is durable, the outcome is PRECOMMIT_FAILED with a
 *      zero delta, and no graph's engine or operation generation moves.
 *   2. |store| is CONSUMED: it is closed and set to NULL before the refresh,
 *      because building the replacement engine reopens the same graph's store.
 *      The caller must not use it afterwards.  The sole exception is the
 *      WYRELOG_E_INVALID programming-error return, which leaves |*store|
 *      untouched -- the arguments may be garbage -- so the caller keeps
 *      responsibility for releasing it on that path.
 *   3. The refresh is POST-COMMIT and targeted at |graph_info| alone.  Its
 *      failure is COMMITTED_DEGRADED -- the batch stays durable and must never
 *      be reported as uncommitted -- and it leaves every other graph's
 *      generations untouched.
 *   4. A retried idempotency key is a committed no-op: rc is WYRELOG_E_OK,
 *      |out_inserted| is FALSE, the delta is the zero state, and the mutation
 *      is NOT applied a second time.  A refresh still runs, so the
 *      engine_generation still advances.
 *   5. Audit emission is the caller's, and happens AFTER this returns, and its
 *      result is kept SEPARATE from this function's.  An audit failure leaves
 *      the batch durable, so the caller must still report it as committed:
 *      the HTTP route answers 500 fact_audit_failed with "committed":true and
 *      the real mutation class, never a class downgraded to degraded, because
 *      a successful refresh whose audit failed leaves the engine READY.
 *
 * Serialization: the exact graph's runtime writer lease (entry->writer_lock in
 * fact/runtime-private.c) is held across the engine build and the generation
 * swap.  Note that the refresh ADDITIONALLY serializes on the handle-global
 * fact_replay_coordinator_lock taken by wyl_handle_refresh_fact_graph, so
 * distinct (tenant_id, graph_id) keys do NOT yet build concurrently -- the
 * per-key lease is nested inside the global one and is never the limiting
 * lock here.  Per-key independence is what #548/#549 are meant to unlock, and
 * bounded, tenant-fair replay scheduling is #554's.
 * This function is also the designated acquisition point for the graph-level
 * admission lease (#548) and the tenant admission read lease (#549); neither
 * exists yet.
 */
wyrelog_error_t wyl_handle_commit_fact_mutation (WylHandle * self,
    wyl_fact_store_t * *store,
    const wyl_policy_fact_relation_schema_options_t * schema,
    const wyl_fact_store_batch_t * batch,
    const wyl_policy_fact_graph_info_t * graph_info, gboolean * out_inserted,
    wyl_fact_mutation_outcome_t * out_outcome);
typedef void (*wyl_fact_graph_tuple_cb) (WylEngine * engine,
    const gchar * relation, const gint64 * row, guint ncols,
    gpointer user_data);
wyrelog_error_t wyl_handle_snapshot_fact_graph_relation (WylHandle * self,
    const gchar * tenant_id, const gchar * graph_id, const gchar * relation,
    wyl_fact_graph_tuple_cb cb, gpointer user_data);
typedef wyrelog_error_t (*wyl_fact_graph_status_cb) (const
    wyl_fact_graph_status_t * status, gpointer user_data);
wyrelog_error_t wyl_handle_foreach_fact_graph_status (WylHandle * self,
    wyl_fact_graph_status_cb cb, gpointer user_data);

#ifdef WYL_HAS_FACT_STORE
/*
 * Seal a graph as a runtime barrier and a durable bit, in that order.  Takes
 * the replay coordinator lock and a policy-store pin, the same way
 * wyl_handle_refresh_fact_graph does, so a seal cannot interleave with a
 * targeted refresh or with the boot replay pass.
 *
 * This performs a policy write while holding only the replay coordinator
 * lock and a store pin.  The CALLER must hold the daemon policy write lease
 * -- the sequencer's header states that precondition and this wrapper does
 * not acquire it, so a caller that skips it races the existing graph seal
 * route, which does take it.
 *
 * drain_timeout_us bounds the wait for work admitted before the close, and
 * must be finite.  This holds fact_replay_coordinator_lock for the whole
 * call -- the same lock every append and retract takes for its targeted
 * refresh -- so an indefinite drain here stalls every fact mutation in the
 * process, whatever locks the caller does or does not hold above it.
 *
 * No audit event is emitted here.  A useful one carries the actor and the
 * request id, which live in the HTTP context and not on the handle; the route
 * that gains those emits it.
 */
wyrelog_error_t wyl_handle_seal_fact_graph (WylHandle * self,
    const wyl_policy_fact_graph_info_t * graph_info, gint64 drain_timeout_us,
    WylFactGraphSealOutcome * out_outcome);
#endif
#endif

/*
 * Mints a fresh, handle-scoped wyl_session_id_t for |session| and stores
 * a strong reference in the handle's session registry so a subsequent
 * lookup by the integer id can resolve back to the live WylSession*. The
 * returned id is non-zero. The handle retains a reference for the
 * registry; callers must not unref the session below their own
 * reference count to compensate. Reserved for the wyl_session_login
 * success path.
 */
wyrelog_error_t wyl_handle_register_session (WylHandle * self,
    WylSession * session, wyl_session_id_t * out_sid);

/*
 * Returns a borrowed pointer to the WylSession previously registered
 * with |sid|, or NULL if no such session exists in this handle's
 * registry. The borrowed pointer is valid only until the next
 * registry mutation (wyl_handle_tombstone_session) or handle finalize,
 * whichever comes first. Internal call sites that need to outlive
 * the lookup must use wyl_handle_lookup_session_by_id_ref instead.
 * Callers of this borrowed-pointer variant must not unref it.
 */
WylSession *wyl_handle_lookup_session_by_id (WylHandle * self,
    wyl_session_id_t sid);

/*
 * Discriminant returned by wyl_handle_lookup_session_by_id_ref so
 * callers can distinguish "this sid was never registered" from
 * "this sid was registered but has since been torn down". The two
 * cases drive different return codes in wyl_session_logout.
 */
typedef enum
{
  WYL_SESSION_LOOKUP_UNKNOWN = 0,
  WYL_SESSION_LOOKUP_TOMBSTONED = 1,
  WYL_SESSION_LOOKUP_LIVE = 2,
} wyl_session_lookup_state_t;

/*
 * Race-safe variant of wyl_handle_lookup_session_by_id. On a live
 * lookup, |*out_session| is set to a fresh strong reference that
 * the caller must release with g_object_unref. On a tombstoned or
 * unknown lookup, |*out_session| is set to NULL and |*out_state|
 * disambiguates the two cases. Returns WYRELOG_E_INVALID for NULL
 * out-pointers or a NULL/non-WylHandle handle.
 */
wyrelog_error_t wyl_handle_lookup_session_by_id_ref (WylHandle * self,
    wyl_session_id_t sid, wyl_session_lookup_state_t * out_state,
    WylSession ** out_session);

/*
 * Marks the registry entry for |sid| as torn down: drops the strong
 * reference to the underlying WylSession while leaving the entry in
 * place so that subsequent lookups can distinguish "logged out" from
 * "never registered". Idempotent on an already-tombstoned entry.
 * Returns WYRELOG_E_NOT_FOUND when no entry exists for |sid|.
 */
wyrelog_error_t wyl_handle_tombstone_session (WylHandle * self,
    wyl_session_id_t sid);

/*
 * Host-side ingress guard for login requests that carry skip_mfa. Explicitly
 * setting this flag to TRUE allows skip-MFA independently of deployment mode.
 * When it is FALSE, the Policy DB deployment mode still allows skip-MFA for
 * non-production modes and rejects it for production or unreadable config.
 */
void wyl_handle_set_login_skip_mfa_allowed (WylHandle * self, gboolean allowed);
gboolean wyl_handle_get_login_skip_mfa_override_allowed (WylHandle * self);
gboolean wyl_handle_get_login_skip_mfa_allowed (WylHandle * self);

/*
 * Per-handle default WylMfaValidator pointer.  The daemon init path
 * (runtime.c) installs wyl_mfa_validator_totp here so the commit-4
 * HTTP /auth/mfa/verify route can resolve it without an out-of-band
 * registry.  Callers that want a different validator (e.g. tests)
 * override with wyl_handle_set_mfa_validator before the route fires.
 *
 * CONTRACT (issue #751): a validator registered here MUST publish the
 * MFA_REQUIRED -> AUTHENTICATED principal transition itself, atomically
 * with consuming the proof, the way wyl_mfa_validator_totp does.  The
 * HTTP route drives it through
 * wyl_session_mfa_verify_with_publishing_validator, which deliberately
 * does NOT apply the transition afterwards -- a second unconditional
 * transition would re-append the MFA_OK event.  A verify-only validator
 * installed here would therefore mint authenticated tokens while the
 * principal row stayed mfa_required.  Verify-only validators belong on
 * the public wyl_session_mfa_verify_with_proof boundary instead, which
 * applies the transition for the caller.
 *
 * The setter is NULL-safe; passing a NULL |validator| clears the slot.
 * The getter returns the registered pointer (or NULL when unset) and,
 * if |out_user_data| is non-NULL, copies the registered user_data
 * companion pointer.  The pointers are valid for the lifetime of the
 * handle; releasing |user_data| is the caller's responsibility.
 */
void wyl_handle_set_mfa_validator (WylHandle * self, WylMfaValidator validator,
    gpointer user_data);
WylMfaValidator wyl_handle_get_mfa_validator (WylHandle * self,
    gpointer * out_user_data);

/*
 * Applies a permission-state transition and publishes perm_state/4 and
 * perm_state_fired/7 while retaining one engine session. A pre-commit mutation
 * or validation failure rolls back, preserves the previous engine pair, and
 * leaves |out_event_id| at -1. Once the commit is confirmed, |out_event_id|
 * receives the durable event ID. A subsequent projection or read-back failure
 * preserves that output, poisons and discards the engine pair, and returns the
 * publication error.
 */
wyrelog_error_t wyl_handle_apply_permission_state_transition (WylHandle * self,
    const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * event, const WylAuditEvent * audit_event,
    gint64 * out_event_id);

/*
 * Opens the handle-owned policy engine pair from @template_dir.
 * Rejected if the pair is already present. On failure the handle is left
 * without policy engines.
 */
wyrelog_error_t wyl_handle_open_engine_pair (WylHandle * self,
    const gchar * template_dir);

/*
 * Replaces the handle-owned policy engine pair with a freshly opened pair
 * loaded from the same template directory and current policy store snapshot.
 * On failure, the existing pair remains installed.
 */
wyrelog_error_t wyl_handle_reload_engine_pair (WylHandle * self);

/* True only while one complete, non-poisoned engine pair is published.
 * Session-acquisition failure is reported fail-closed as not ready/poisoned
 * without reading the unlocked aggregate. */
gboolean wyl_handle_engine_pair_is_ready (WylHandle * self);
gboolean wyl_handle_engine_pair_is_poisoned (WylHandle * self);

/*
 * Fences every evaluator entry point after a durable mutation whose runtime
 * publication outcome is uncertain. Poisoning is idempotent and discards the
 * current pair; only committed reconciliation may publish a ready pair again.
 * The public helper returns BUSY without mutation when it cannot acquire the
 * engine session. A post-commit caller must retain its existing session and
 * use the committed-failure helper so fencing cannot silently be skipped.
 */
wyrelog_error_t wyl_handle_poison_engine_pair (WylHandle * self);
wyrelog_error_t wyl_handle_fail_committed_engine_projection
  (WylEngineSession * session, wyrelog_error_t failure);

typedef wyrelog_error_t (*WylEnginePairVerifier) (WylHandle * handle,
    gpointer data);

typedef wyrelog_error_t (*WylCommittedEngineMutationBody)
  (wyl_policy_store_t * store, gpointer data);
typedef struct _WylEngineVerification WylEngineVerification;
typedef wyrelog_error_t (*WylEnginePublicationVerifier)
  (WylEngineVerification * verification, gpointer data);
typedef wyrelog_error_t (*WylEnginePublicationDeltaProducer)
  (WylEngineVerification * verification, gpointer data);
typedef enum
{
  WYL_DURABLE_COMMIT_NOT_COMMITTED = 0,
  WYL_DURABLE_COMMIT_COMMITTED,
  WYL_DURABLE_COMMIT_UNCERTAIN,
} WylDurableCommitState;
wyrelog_error_t wyl_engine_verification_lookup_symbol
  (WylEngineVerification * verification, const gchar * symbol,
    gint64 * out_id);
wyrelog_error_t wyl_engine_verification_contains
  (WylEngineVerification * verification, const gchar * relation,
    const gint64 * row, gsize ncols, gboolean * out_contains);
/* Proves that exactly one row whose first column is @key exists in the
 * unpublished read candidate and that row exactly equals @expected. */
wyrelog_error_t wyl_engine_verification_has_exact_keyed_row
  (WylEngineVerification * verification, const gchar * relation,
    gint64 key, const gint64 * expected, gsize ncols, gboolean * out_exact);
#ifdef WYL_TEST_HANDLE_SEAMS
typedef enum
{
  WYL_ENGINE_VERIFICATION_CANDIDATE_EXTRA,
  WYL_ENGINE_VERIFICATION_CANDIDATE_WRONG,
} WylEngineVerificationCandidateMutation;
/* Mutates only the unpublished verification candidate so exact-cardinality
 * rejection can be tested without weakening durable-store constraints. */
wyrelog_error_t wyl_engine_verification_mutate_keyed_row_for_test
  (WylEngineVerification * verification, const gchar * relation,
    const gint64 * expected, const gint64 * mutant, gsize ncols,
    WylEngineVerificationCandidateMutation mutation);
#endif
/* Reads the host-accepted session_state input witness from the unpublished
 * read candidate. Success requires exactly one accepted row for @scope and
 * returns that row's state symbol. Inline template facts are forbidden. */
wyrelog_error_t wyl_engine_verification_get_accepted_session_state
  (WylEngineVerification * verification, gint64 scope, gint64 * out_state);
/* Proves that exactly one member_of/3 row with these symbols crossed the
 * owned insertion boundary into the unpublished read candidate. */
wyrelog_error_t wyl_engine_verification_has_exact_accepted_member_of
  (WylEngineVerification * verification, const gint64 row[3],
    gboolean * out_exact);
wyrelog_error_t wyl_engine_verification_enqueue_delta
  (WylEngineVerification * verification, const gchar * relation,
    const gint64 * row, gsize ncols, WylDeltaKind kind);

/*
 * Runs one durable mutation while @session keeps every evaluator outside the
 * commit/publication interval. A successful mutation is immediately followed
 * by a complete durable-snapshot rebuild and an exact verifier before the new
 * pair is published. Any post-commit failure poisons the pair before return.
 * @out_stage distinguishes a clean pre-commit rejection from commit
 * ambiguity and a confirmed durable commit. COMMIT_CONFIRMED remains
 * observable when later projection or verification fails.
 *
 * The caller acquires any service-auth lease first, then @session, and must not
 * open a second store/engine ownership scope inside @verify.
 */
typedef enum
{
  WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED = 0,
  WYL_COMMITTED_PUBLICATION_COMMIT_AMBIGUOUS,
  WYL_COMMITTED_PUBLICATION_COMMIT_CONFIRMED,
} WylCommittedPublicationStage;
wyrelog_error_t wyl_engine_session_run_committed_publication
  (WylEngineSession * session, WylCommittedEngineMutationBody mutate,
    gpointer mutate_data, WylEnginePublicationVerifier verify,
    gpointer verify_data, WylEnginePublicationDeltaProducer produce_deltas,
    gpointer delta_data, WylCommittedPublicationStage * out_stage);

/* Repairs only a poisoned pair from the durable snapshot while the caller
 * retains the same-handle service-auth WRITE lease and outermost engine
 * session. No transaction or delta callback may be active. The pair becomes
 * ready only after a complete rebuild and exact verification. */
wyrelog_error_t wyl_engine_session_repair_committed_publication
  (WylEngineSession * session, WylServiceAuthWriteLease * write_lease,
    wyl_policy_store_t * expected_store, guint64 expected_generation,
    WylEnginePublicationVerifier verify, gpointer verify_data);

/* Completes publication for a transaction committed by an enclosing owner
 * while that owner still retains both its store pin and @session. A confirmed
 * commit validates the exact store generation before rebuilding and verifying
 * the full pair. A known rollback preserves the published pair; uncertainty
 * poisons it immediately. */
wyrelog_error_t wyl_engine_session_finish_external_publication
  (WylEngineSession * session, wyl_policy_store_t * expected_store,
    guint64 expected_generation, WylDurableCommitState commit_state,
    WylEnginePublicationVerifier verify, gpointer verify_data);

#ifdef WYL_HAS_AUDIT
typedef struct
{
  const gchar *id;
  gint64 created_at_us;
  const gchar *subject_id;
  const gchar *action;
  const gchar *resource_id;
  const gchar *deny_reason;
  const gchar *deny_origin;
  const gchar *request_id;
  wyl_decision_t decision;
} WylCommittedAuditProjection;

/* Commits one audit mutation, then projects only that row into the current
 * pair.  Unlike the general publication runner this lane may re-enter from a
 * detached delta callback and never replaces the pair or replays history. */
wyrelog_error_t wyl_engine_session_run_committed_audit_publication
  (WylEngineSession * session, WylCommittedEngineMutationBody mutate,
    gpointer mutate_data, const WylCommittedAuditProjection * projection);
#ifdef WYL_TEST_HANDLE_SEAMS
wyrelog_error_t wyl_handle_classify_audit_projection_for_test
  (WylHandle * self, const WylCommittedAuditProjection * projection,
    gboolean * out_absent);
#endif
#endif

/*
 * Exclusively rebuilds the complete pair from durable state, then invokes
 * @verify while retaining the recursive engine session. Any rebuild or
 * verification failure leaves the handle poisoned. The caller must already
 * own any service-auth lease required by its enclosing committed operation.
 */
wyrelog_error_t wyl_handle_reconcile_committed_engine_pair (WylHandle * self,
    WylEnginePairVerifier verify, gpointer data);

/*
 * Interns @symbol into both handle-owned policy engines and returns the shared
 * integer id. Rejected unless the engine pair is already open.
 */
#ifdef WYL_TEST_HANDLE_SEAMS
wyrelog_error_t wyl_handle_intern_engine_symbol (WylHandle * self,
    const gchar * symbol, gint64 * out_id);
gchar *wyl_handle_dup_engine_symbol (WylHandle * self, gint64 id);

/*
 * Applies an EDB row update to both handle-owned policy engines. Rejected
 * unless the engine pair is already open. This helper is not transactional
 * across the two engines; callers must treat a non-OK return as terminal for
 * the pair.
 */
wyrelog_error_t wyl_handle_engine_insert (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_handle_engine_remove (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);
#endif

typedef struct
{
  gchar *relation;
  wyrelog_error_t rc;
} WylHandleEngineFaultOnce;

typedef WylHandleEngineFaultOnce WylHandleEngineInsertFaultOnce;
typedef WylHandleEngineFaultOnce WylHandleEngineRemoveFaultOnce;
typedef WylHandleEngineFaultOnce WylHandleEngineDeltaInsertFaultOnce;
typedef WylHandleEngineFaultOnce WylHandleEngineDeltaRemoveFaultOnce;
typedef WylHandleEngineFaultOnce WylHandleEngineDeltaStepFaultOnce;
typedef WylHandleEngineFaultOnce WylHandleEngineContainsFaultOnce;

static inline void
wyl_handle_engine_fault_once_free (gpointer data)
{
  WylHandleEngineFaultOnce *fault = data;

  if (fault == NULL)
    return;
  g_free (fault->relation);
  g_free (fault);
}

static inline GQuark
wyl_handle_engine_insert_fault_once_quark (void)
{
  return g_quark_from_static_string ("wyrelog-handle-engine-insert-fault-once");
}

static inline GQuark
wyl_handle_engine_remove_fault_once_quark (void)
{
  return g_quark_from_static_string ("wyrelog-handle-engine-remove-fault-once");
}

static inline GQuark
wyl_handle_engine_contains_fault_once_quark (void)
{
  return g_quark_from_static_string
           ("wyrelog-handle-engine-contains-fault-once");
}

static inline void
wyl_handle_set_engine_contains_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineContainsFaultOnce *fault;
  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);
  fault = g_new0 (WylHandleEngineContainsFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_contains_fault_once_quark (), fault,
      wyl_handle_engine_fault_once_free);
}

static inline GQuark
wyl_handle_engine_delta_insert_fault_once_quark (void)
{
  return g_quark_from_static_string ("wyl-delta-insert-fault-once");
}

static inline GQuark
wyl_handle_engine_delta_remove_fault_once_quark (void)
{
  return g_quark_from_static_string ("wyl-delta-remove-fault-once");
}

static inline GQuark
wyl_handle_engine_delta_step_fault_once_quark (void)
{
  return g_quark_from_static_string ("wyl-delta-step-fault-once");
}

static inline void
wyl_handle_engine_remove_fault_once_free (gpointer data)
{
  wyl_handle_engine_fault_once_free (data);
}

/*
 * Test-only fault hook for private insert-path coverage. The next
 * wyl_handle_engine_insert() call for @relation fails with @rc before the row
 * reaches the engine. The hook clears after one match.
 * @rc must be a non-OK error.
 */
static inline void
wyl_handle_set_engine_insert_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineInsertFaultOnce *fault;

  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);

  fault = g_new0 (WylHandleEngineInsertFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_insert_fault_once_quark (), fault,
      wyl_handle_engine_fault_once_free);
}

/*
 * Test-only fault hook for private cleanup-path coverage. The next
 * wyl_handle_engine_remove() call for @relation performs the remove, then
 * returns @rc if the remove itself succeeded. The hook clears after one match.
 * @rc must be a non-OK error.
 */
static inline void
wyl_handle_set_engine_remove_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineRemoveFaultOnce *fault;

  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);

  fault = g_new0 (WylHandleEngineRemoveFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_remove_fault_once_quark (), fault,
      wyl_handle_engine_remove_fault_once_free);
}

/*
 * Test-only hook for fanout coverage. The next delta-engine insert for
 * @relation fails after the read engine has accepted the row.
 */
static inline void
wyl_handle_set_engine_delta_insert_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineDeltaInsertFaultOnce *fault;

  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);

  fault = g_new0 (WylHandleEngineDeltaInsertFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_delta_insert_fault_once_quark (), fault,
      wyl_handle_engine_fault_once_free);
}

/*
 * Test-only hook for fanout coverage. The next delta-engine remove for
 * @relation fails after the read engine has accepted the removal.
 */
static inline void
wyl_handle_set_engine_delta_remove_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineDeltaRemoveFaultOnce *fault;

  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);

  fault = g_new0 (WylHandleEngineDeltaRemoveFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_delta_remove_fault_once_quark (), fault,
      wyl_handle_engine_fault_once_free);
}

/*
 * Test-only hook for fanout coverage. The next delta-engine step for
 * @relation fails after both engines have accepted the row.
 */
static inline void
wyl_handle_set_engine_delta_step_fault_once (WylHandle *self,
    const gchar *relation, wyrelog_error_t rc)
{
  WylHandleEngineDeltaStepFaultOnce *fault;

  g_return_if_fail (WYL_IS_HANDLE (self));
  g_return_if_fail (relation != NULL);
  g_return_if_fail (rc != WYRELOG_E_OK);

  fault = g_new0 (WylHandleEngineDeltaStepFaultOnce, 1);
  fault->relation = g_strdup (relation);
  fault->rc = rc;
  g_object_set_qdata_full (G_OBJECT (self),
      wyl_handle_engine_delta_step_fault_once_quark (), fault,
      wyl_handle_engine_fault_once_free);
}

/*
 * Advances the handle-owned delta engine by one logical step. Rejected unless
 * the engine pair is already open. The read engine is untouched so snapshot
 * decision probes remain available.
 */
#ifdef WYL_TEST_HANDLE_SEAMS
wyrelog_error_t wyl_handle_engine_step_delta (WylHandle * self);

/*
 * Installs or clears the handle-owned delta engine callback. Rejected unless
 * the engine pair is already open. Passing NULL for @cb clears the callback.
 */
wyrelog_error_t wyl_handle_engine_set_delta_callback (WylHandle * self,
    WylDeltaCallback cb, gpointer user_data);
#endif

/*
 * Loads effective role_permission rows from the handle-owned policy authority
 * store into the attached read/delta engine pair. Role inheritance edges are
 * flattened by the store iterator before they reach the engine.
 */
wyrelog_error_t wyl_handle_load_policy_store_role_permissions (WylHandle *
    self);

/*
 * Loads role_membership rows from the handle-owned policy authority store into
 * the attached read/delta engine pair as member_of/3 facts.
 */
wyrelog_error_t wyl_handle_load_policy_store_role_memberships (WylHandle *
    self);

/*
 * Loads direct_permission rows from the handle-owned policy authority store
 * into the attached read/delta engine pair, together with their "armed"
 * perm_state rows. Rejected unless both the store and engine pair are
 * available.
 */
wyrelog_error_t wyl_handle_load_policy_store_direct_permissions (WylHandle *
    self);

/*
 * Loads permission_states rows from the handle-owned policy authority store into
 * the attached read/delta engine pair as perm_state/4 facts. Rejected unless
 * both the store and engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_permission_states (WylHandle *
    self);

/*
 * Loads permission_state_event rows from the handle-owned policy authority
 * store into the attached read/delta engine pair as perm_state_event/7 facts.
 * Rejected unless both the store and engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_permission_state_events
  (WylHandle * self);

/*
 * Loads principal_state rows from the handle-owned policy authority store into
 * the attached read/delta engine pair. Rejected unless both the store and
 * engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_principal_states (WylHandle *
    self);

/*
 * Loads principal_event rows from the handle-owned policy authority store into
 * the attached read/delta engine pair as principal_event/5 facts. Rejected
 * unless both the store and engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_principal_events (WylHandle *
    self);

/*
 * Loads session_state rows from the handle-owned policy authority store into
 * the attached read/delta engine pair. Rejected unless both the store and
 * engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_session_states (WylHandle * self);

/*
 * Loads session_event rows from the handle-owned policy authority store into
 * the attached read/delta engine pair as session_event/5 facts. Rejected
 * unless both the store and engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_session_events (WylHandle * self);

/*
 * Loads persisted audit rows from the handle-owned policy authority store into
 * the read engine as private audit_event* facts. Optional audit fields are
 * projected through split predicates so NULL values do not need sentinel
 * symbols. Rejected unless both the store and engine pair are available.
 */
wyrelog_error_t wyl_handle_load_policy_store_audit_facts (WylHandle * self);

/*
 * Projects one durable audit row into the currently attached read engine as
 * private audit_event* facts. A handle without an open engine pair accepts the
 * row as already durable and performs no live projection.
 */
wyrelog_error_t wyl_handle_insert_audit_fact (WylHandle * self,
    const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id,
    const gchar * deny_reason, const gchar * deny_origin,
    const gchar * request_id, wyl_decision_t decision);

/*
 * Probes the read engine for an exact snapshot-visible row match. Rejected
 * unless the engine pair is already open. Durable authority rows should be
 * verified through the policy store, and LoBAC visibility should be verified
 * through decision relations.
 */
#ifdef WYL_TEST_HANDLE_SEAMS
wyrelog_error_t wyl_handle_engine_contains (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols,
    gboolean * out_contains);

/*
 * Reads allow_bool/3 from the handle-owned read engine for @row
 * (user, permission, scope). Rejected unless the engine pair is already open.
 */
wyrelog_error_t wyl_handle_engine_decide (WylHandle * self,
    const gint64 row[3], gboolean * out_allowed);

/* Test-only borrowed pointers; absent from shipped artifacts. */
WylEngine *wyl_handle_get_read_engine (WylHandle * self);
WylEngine *wyl_handle_get_delta_engine (WylHandle * self);
wyrelog_error_t wyl_handle_replay_delta_insert (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);
#endif

G_END_DECLS;
