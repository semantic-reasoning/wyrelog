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
/* Accessed only while the handle's service-auth authority monitor is held. */
WylServiceAuthUnavailableReason
wyl_handle_service_auth_unavailable_reason_locked (WylHandle * self);
void wyl_handle_service_auth_set_unavailable_reason_locked (WylHandle * self,
    WylServiceAuthUnavailableReason reason);
/*
 * Ordered private shutdown used by the public void wrapper and finalization.
 * Returns BUSY without changing lifecycle state when called by a thread that
 * owns a policy-store pin or service-auth lease.
 */
wyrelog_error_t wyl_handle_shutdown_ordered (WylHandle * self);
wyrelog_error_t wyl_handle_policy_store_pin_current (WylHandle * self,
    wyl_policy_store_t ** out_store);
void wyl_handle_policy_store_unpin (WylHandle * self,
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

#ifdef WYL_HAS_FACT_STORE
wyrelog_error_t wyl_handle_replay_fact_graphs (WylHandle * self,
    wyl_fact_replay_summary_t * out_summary);
WylEngine *wyl_handle_get_fact_graph_engine (WylHandle * self,
    const gchar * tenant_id, const gchar * graph_id);
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
 * Applies a permission-state transition to the handle-owned policy store, then
 * reloads the engine pair so perm_state/4 and perm_state_fired/7 reflect the
 * durable state. The policy store commit is the source of truth: if reload
 * fails, the previous engine pair remains installed and the returned error is
 * the reload failure.
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

/*
 * Interns @symbol into both handle-owned policy engines and returns the shared
 * integer id. Rejected unless the engine pair is already open.
 */
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
wyrelog_error_t wyl_handle_engine_step_delta (WylHandle * self);

/*
 * Installs or clears the handle-owned delta engine callback. Rejected unless
 * the engine pair is already open. Passing NULL for @cb clears the callback.
 */
wyrelog_error_t wyl_handle_engine_set_delta_callback (WylHandle * self,
    WylDeltaCallback cb, gpointer user_data);

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
wyrelog_error_t wyl_handle_engine_contains (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols,
    gboolean * out_contains);

/*
 * Reads allow_bool/3 from the handle-owned read engine for @row
 * (user, permission, scope). Rejected unless the engine pair is already open.
 */
wyrelog_error_t wyl_handle_engine_decide (WylHandle * self,
    const gint64 row[3], gboolean * out_allowed);

/*
 * Borrowed policy engine sessions owned by |self|. These are NULL when
 * no policy engine pair has been opened. The read engine is reserved for
 * snapshot-style reads; the delta engine is reserved for step/delta
 * processing.
 */
WylEngine *wyl_handle_get_read_engine (WylHandle * self);
WylEngine *wyl_handle_get_delta_engine (WylHandle * self);
wyrelog_error_t wyl_handle_replay_delta_insert (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);

G_END_DECLS;
