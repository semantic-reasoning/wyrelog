/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/handle.h"
#include "wyrelog/engine.h"
#include "wyrelog/audit.h"
#include "policy/store-private.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif

G_BEGIN_DECLS;

typedef struct
{
  const gchar *template_dir;
  const gchar *policy_store_path;
#ifdef WYL_HAS_AUDIT
  const gchar *audit_store_path;
#endif
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
 * Host-side ingress guard for login requests that carry skip_mfa. Explicitly
 * setting this flag to TRUE allows skip-MFA independently of deployment mode.
 * When it is FALSE, the Policy DB deployment mode still allows skip-MFA for
 * non-production modes and rejects it for production or unreadable config.
 */
void wyl_handle_set_login_skip_mfa_allowed (WylHandle * self, gboolean allowed);
gboolean wyl_handle_get_login_skip_mfa_allowed (WylHandle * self);

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
