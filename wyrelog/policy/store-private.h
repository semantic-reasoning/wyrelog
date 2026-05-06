/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <sqlite3.h>

#include "wyrelog/decide.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct wyl_policy_store_t wyl_policy_store_t;

typedef wyrelog_error_t (*wyl_policy_role_permission_cb) (const gchar * role_id,
    const gchar * perm_id, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_inheritance_cb) (const gchar *
    child_role_id, const gchar * parent_role_id, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_membership_cb) (const gchar *
    subject_id, const gchar * role_id, const gchar * scope, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_role_membership_event_cb) (const gchar *
    subject_id, const gchar * role_id, const gchar * scope,
    const gchar * operation, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_direct_permission_cb) (const gchar *
    subject_id, const gchar * perm_id, const gchar * scope, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_direct_permission_event_cb) (const gchar *
    subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * operation, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_principal_state_cb) (const gchar *
    subject_id, const gchar * state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_principal_event_cb) (gint64 event_id,
    const gchar * subject_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_session_state_cb) (const gchar *
    session_id, const gchar * state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_session_event_cb) (gint64 event_id,
    const gchar * session_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gpointer user_data);
typedef wyrelog_error_t (*wyl_policy_audit_event_cb) (const gchar * id,
    gint64 created_at_us, const gchar * subject_id, const gchar * action,
    const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, wyl_decision_t decision, gpointer user_data);

/*
 * Policy authority store lifecycle wrapper.
 *
 * v0 uses SQLite directly so the handle owns a real ACID policy DB before
 * SQLCipher key negotiation is wired in. The private boundary keeps callers
 * out of the raw sqlite3 handle except for tests and future migrator code.
 */
wyrelog_error_t wyl_policy_store_open (const gchar * path,
    wyl_policy_store_t ** out_store);
void wyl_policy_store_close (wyl_policy_store_t * store);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (wyl_policy_store_t, wyl_policy_store_close);

sqlite3 *wyl_policy_store_get_db (wyl_policy_store_t * store);

wyrelog_error_t wyl_policy_store_begin_mutation (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_commit_mutation (wyl_policy_store_t * store);
void wyl_policy_store_rollback_mutation (wyl_policy_store_t * store);

wyrelog_error_t wyl_policy_store_create_schema (wyl_policy_store_t * store);
wyrelog_error_t wyl_policy_store_validate_snapshot (wyl_policy_store_t * store);
gsize wyl_policy_store_builtin_role_count (void);
const gchar *wyl_policy_store_builtin_role_id (gsize idx);
gsize wyl_policy_store_builtin_permission_count (void);
const gchar *wyl_policy_store_builtin_permission_id (gsize idx);
wyrelog_error_t wyl_policy_store_table_exists (wyl_policy_store_t * store,
    const gchar * table_name, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_set_deployment_mode (wyl_policy_store_t *
    store, const gchar * mode);
wyrelog_error_t wyl_policy_store_get_deployment_mode (wyl_policy_store_t *
    store, gchar ** out_mode);
wyrelog_error_t wyl_policy_store_upsert_role (wyl_policy_store_t * store,
    const gchar * role_id, const gchar * role_name);
wyrelog_error_t wyl_policy_store_upsert_permission (wyl_policy_store_t * store,
    const gchar * perm_id, const gchar * perm_name, const gchar * klass);
wyrelog_error_t wyl_policy_store_role_exists (wyl_policy_store_t * store,
    const gchar * role_id, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_permission_exists (wyl_policy_store_t * store,
    const gchar * perm_id, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_grant_role_permission (wyl_policy_store_t *
    store, const gchar * role_id, const gchar * perm_id);
wyrelog_error_t wyl_policy_store_foreach_role_permission (wyl_policy_store_t *
    store, wyl_policy_role_permission_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_role_inheritance (wyl_policy_store_t *
    store, const gchar * child_role_id, const gchar * parent_role_id);
wyrelog_error_t wyl_policy_store_foreach_role_inheritance (wyl_policy_store_t *
    store, wyl_policy_role_inheritance_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_role_membership (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope);
wyrelog_error_t wyl_policy_store_revoke_role_membership (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope);
wyrelog_error_t
wyl_policy_store_apply_role_membership_mutation (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * role_id, const gchar * scope,
    gboolean insert);
wyrelog_error_t
    wyl_policy_store_apply_role_membership_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * role_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, wyl_decision_t audit_decision);
wyrelog_error_t wyl_policy_store_role_membership_exists (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * role_id,
    const gchar * scope, gboolean * out_exists);
wyrelog_error_t wyl_policy_store_foreach_role_membership (wyl_policy_store_t *
    store, wyl_policy_role_membership_cb cb, gpointer user_data);
wyrelog_error_t
wyl_policy_store_append_role_membership_event (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * role_id, const gchar * scope,
    const gchar * operation);
wyrelog_error_t
wyl_policy_store_foreach_role_membership_event (wyl_policy_store_t * store,
    wyl_policy_role_membership_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_grant_direct_permission (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope);
wyrelog_error_t wyl_policy_store_revoke_direct_permission (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id,
    const gchar * scope);
wyrelog_error_t
wyl_policy_store_apply_direct_permission_mutation (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean insert);
wyrelog_error_t
    wyl_policy_store_apply_direct_permission_mutation_with_audit
    (wyl_policy_store_t * store, const gchar * subject_id,
    const gchar * perm_id, const gchar * scope, gboolean insert,
    const gchar * audit_id, gint64 audit_created_at_us,
    const gchar * audit_subject_id, const gchar * audit_action,
    const gchar * audit_resource_id, const gchar * audit_deny_reason,
    const gchar * audit_deny_origin, wyl_decision_t audit_decision);
wyrelog_error_t wyl_policy_store_direct_permission_exists (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    gboolean * out_exists);
wyrelog_error_t wyl_policy_store_foreach_direct_permission (wyl_policy_store_t *
    store, wyl_policy_direct_permission_cb cb, gpointer user_data);
wyrelog_error_t
wyl_policy_store_append_direct_permission_event (wyl_policy_store_t * store,
    const gchar * subject_id, const gchar * perm_id, const gchar * scope,
    const gchar * operation);
wyrelog_error_t
wyl_policy_store_foreach_direct_permission_event (wyl_policy_store_t * store,
    wyl_policy_direct_permission_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_set_principal_state (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * state);
wyrelog_error_t wyl_policy_store_foreach_principal_state (wyl_policy_store_t *
    store, wyl_policy_principal_state_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_principal_event (wyl_policy_store_t *
    store, const gchar * subject_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gint64 * out_event_id);
wyrelog_error_t wyl_policy_store_foreach_principal_event (wyl_policy_store_t *
    store, wyl_policy_principal_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_set_session_state (wyl_policy_store_t * store,
    const gchar * session_id, const gchar * state);
wyrelog_error_t wyl_policy_store_foreach_session_state (wyl_policy_store_t *
    store, wyl_policy_session_state_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_session_event (wyl_policy_store_t *
    store, const gchar * session_id, const gchar * event,
    const gchar * from_state, const gchar * to_state, gint64 * out_event_id);
wyrelog_error_t wyl_policy_store_foreach_session_event (wyl_policy_store_t *
    store, wyl_policy_session_event_cb cb, gpointer user_data);
wyrelog_error_t wyl_policy_store_append_audit_event (wyl_policy_store_t *
    store, const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id, const gchar * deny_reason,
    const gchar * deny_origin, wyl_decision_t decision);
wyrelog_error_t wyl_policy_store_append_audit_event_full (wyl_policy_store_t *
    store, const gchar * id, gint64 created_at_us, const gchar * subject_id,
    const gchar * action, const gchar * resource_id,
    const gchar * deny_reason, const gchar * deny_origin,
    wyl_decision_t decision, gboolean * out_inserted);
wyrelog_error_t wyl_policy_store_delete_audit_event (wyl_policy_store_t *
    store, const gchar * id);
wyrelog_error_t wyl_policy_store_foreach_audit_event (wyl_policy_store_t *
    store, wyl_policy_audit_event_cb cb, gpointer user_data);

G_END_DECLS;
