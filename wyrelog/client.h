/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/audit.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * WylClient - HTTP client for talking to a remote wyrelog daemon.
 *
 * Owns the HTTP transport, the base URL, and the current
 * authentication state (access token, refresh token, MFA bind).
 * Created with wyl_client_new, released with g_object_unref or
 * g_autoptr.
 */
G_DECLARE_FINAL_TYPE (WylClient, wyl_client, WYL, CLIENT, GObject);
#define WYL_TYPE_CLIENT (wyl_client_get_type ())

/*
 * WylAuditIter - paginated audit query cursor.
 *
 * Issues one HTTP GET per page and yields events through
 * wyl_audit_iter_next until the server reports the end.
 */
G_DECLARE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, WYL, AUDIT_ITER, GObject);
#define WYL_TYPE_AUDIT_ITER (wyl_audit_iter_get_type ())

typedef struct _WylClientDecision WylClientDecision;
typedef struct _WylClientFactAppendResult WylClientFactAppendResult;

typedef struct
{
  const gchar *name;
  const gchar *type;
  gboolean nullable;
  gboolean visible;
} WylClientFactColumn;

/* Lifecycle */
wyrelog_error_t wyl_client_new (const gchar * base_url,
    WylClient ** out_client);
gchar *wyl_client_dup_base_url (const WylClient * client);

/* Authentication */
wyrelog_error_t wyl_client_login (WylClient * client,
    const gchar * username, const gchar * password);
/*
 * Requests a daemon-side skip-MFA login. The daemon remains authoritative and
 * may deny this request according to its deployment mode and ingress policy.
 */
wyrelog_error_t wyl_client_login_skip_mfa (WylClient * client,
    const gchar * username);
wyrelog_error_t wyl_client_set_bearer_credentials (WylClient * client,
    const gchar * access_token, const gchar * tenant);
gchar *wyl_client_dup_session_token (const WylClient * client);
gchar *wyl_client_dup_access_token (const WylClient * client);
gchar *wyl_client_dup_username (const WylClient * client);
/*
 * Returns a heap-allocated copy of the tenant currently bound to
 * |client|. Caller frees with g_free or g_autofree.
 */
gchar *wyl_client_dup_tenant (const WylClient * client);
gchar *wyl_client_dup_principal_state (const WylClient * client);
gchar *wyl_client_dup_session_state (const WylClient * client);
guint wyl_client_get_last_http_status (const WylClient * client);
gchar *wyl_client_dup_last_error_code (const WylClient * client);
wyrelog_error_t wyl_client_token_refresh (WylClient * client);
wyrelog_error_t wyl_client_mfa_verify (WylClient * client, const gchar * otp);

/* Decide */
wyrelog_error_t wyl_client_decide (WylClient * client,
    const gchar * user,
    const gchar * perm, const gchar * session_token, gint * out_decision);
wyrelog_error_t wyl_client_decide_ex (WylClient * client,
    const gchar * user,
    const gchar * perm,
    const gchar * session_token, WylClientDecision ** out_result);
wyrelog_error_t wyl_client_decide_with_guard_context (WylClient * client,
    const gchar * user,
    const gchar * perm,
    const gchar * session_token,
    gint64 guard_timestamp,
    const gchar * guard_loc_class, gint64 guard_risk, gint * out_decision);
wyrelog_error_t wyl_client_decide_with_guard_context_ex (WylClient * client,
    const gchar * user,
    const gchar * perm,
    const gchar * session_token,
    gint64 guard_timestamp,
    const gchar * guard_loc_class,
    gint64 guard_risk, WylClientDecision ** out_result);
void wyl_client_decision_free (WylClientDecision * result);
gint wyl_client_decision_get_decision (const WylClientDecision * result);
const gchar *wyl_client_decision_get_deny_reason (const WylClientDecision *
    result);
const gchar *wyl_client_decision_get_deny_origin (const WylClientDecision *
    result);
gchar *wyl_client_decision_dup_deny_reason (const WylClientDecision * result);
gchar *wyl_client_decision_dup_deny_origin (const WylClientDecision * result);

/* Audit query (iterator) */
wyrelog_error_t wyl_client_audit_query (WylClient * client,
    const gchar * query_filter, WylAuditIter ** out_iter);
/*
 * Builds an audit query that carries the current guarded credential and a
 * request guard context. The client prefers bearer access-token auth when
 * available and falls back to the current login session token.
 */
wyrelog_error_t wyl_client_audit_query_with_guard_context (WylClient * client,
    const gchar * query_filter,
    gint64 guard_timestamp,
    const gchar * guard_loc_class, gint64 guard_risk, WylAuditIter ** out_iter);

/* Policy mutation */
wyrelog_error_t wyl_client_policy_permission_grant (WylClient * client,
    const gchar * subject,
    const gchar * perm,
    const gchar * scope,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_policy_permission_revoke (WylClient * client,
    const gchar * subject,
    const gchar * perm,
    const gchar * scope,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_policy_permission_transition (WylClient * client,
    const gchar * subject,
    const gchar * perm,
    const gchar * scope,
    const gchar * event,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_policy_role_grant (WylClient * client,
    const gchar * subject,
    const gchar * role,
    const gchar * scope,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_policy_role_revoke (WylClient * client,
    const gchar * subject,
    const gchar * role,
    const gchar * scope,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);

/* Fact graph / schema / append */
wyrelog_error_t wyl_client_graph_create (WylClient * client,
    const gchar * tenant,
    const gchar * graph,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_fact_schema_register (WylClient * client,
    const gchar * tenant,
    const gchar * graph,
    const gchar * namespace_id,
    const gchar * relation,
    guint32 schema_version,
    const WylClientFactColumn * columns,
    gsize n_columns,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_fact_schema_register_with_max_rows
    (WylClient * client,
    const gchar * tenant,
    const gchar * graph,
    const gchar * namespace_id,
    const gchar * relation,
    guint32 schema_version,
    const WylClientFactColumn * columns,
    gsize n_columns,
    guint max_rows,
    gint64 guard_timestamp, const gchar * guard_loc_class, gint64 guard_risk);
wyrelog_error_t wyl_client_fact_put_batch (WylClient * client,
    const gchar * tenant,
    const gchar * graph,
    const gchar * namespace_id,
    const gchar * relation,
    guint32 schema_version,
    const gchar * batch_id,
    const gchar * idempotency_key,
    const guint8 * tsv_payload,
    gsize tsv_len,
    gint64 guard_timestamp,
    const gchar * guard_loc_class,
    gint64 guard_risk, WylClientFactAppendResult ** out_result);
wyrelog_error_t wyl_client_datalog_query_json (WylClient * client,
    const gchar * tenant,
    const gchar * graph,
    const gchar * query,
    guint limit,
    gint64 guard_timestamp,
    const gchar * guard_loc_class, gint64 guard_risk, gchar ** out_json);
void wyl_client_fact_append_result_free (WylClientFactAppendResult * result);
gboolean wyl_client_fact_append_result_get_inserted
    (const WylClientFactAppendResult * result);
const gchar *wyl_client_fact_append_result_get_batch_id
    (const WylClientFactAppendResult * result);
gchar *wyl_client_fact_append_result_dup_batch_id
    (const WylClientFactAppendResult * result);

gchar *wyl_audit_iter_dup_query_filter (const WylAuditIter * iter);
gchar *wyl_audit_iter_dup_request_uri (const WylAuditIter * iter);
WylAuditEvent *wyl_audit_iter_ref_event (const WylAuditIter * iter);
wyrelog_error_t wyl_audit_iter_next (WylAuditIter * iter,
    gboolean * out_has_next);

/* Tenant / event */
/*
 * Binds |client| to the named tenant for subsequent guarded HTTP
 * calls. The selected tenant must match the tenant already carried by
 * the authenticated client credentials; mismatches fail closed with
 * WYRELOG_E_INVALID and leave the client's tenant binding unchanged.
 */
wyrelog_error_t wyl_client_tenant_select (WylClient * client,
    const gchar * tenant);
wyrelog_error_t wyl_client_event_emit (WylClient * client,
    const gchar * event_kind, const gchar * event_payload_json);

/* Meta */
const gchar *wyrelog_client_version_string (void);

G_END_DECLS;

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylClientDecision, wyl_client_decision_free)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylClientFactAppendResult,
    wyl_client_fact_append_result_free)
