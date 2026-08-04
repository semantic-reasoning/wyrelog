/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/checks.h"

#include <glib.h>
#include <string.h>

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif
#include "daemon/delta.h"
#include "wyrelog/wyl-handle-private.h"

wyrelog_error_t
wyl_daemon_check_wirelog_policy_ready (WylHandle *handle)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  gint64 row[1];
  wyrelog_error_t rc =
      wyl_engine_session_intern_symbol (session, "wr.audit.read", &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_engine_session_contains (session, "guarded_perm", row, 1, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_policy_store_ready (WylHandle *handle)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  for (gsize i = 0; i < wyl_policy_store_required_table_count (); i++) {
    gboolean found = FALSE;
    const gchar *table = wyl_policy_store_required_table_name (i);
    wyrelog_error_t rc = wyl_policy_store_table_exists (store, table, &found);
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!found)
      return WYRELOG_E_POLICY;
  }

  return WYRELOG_E_OK;
}

typedef struct
{
  const WylAuditEvent *event;
  const gchar *id;
#ifdef WYL_TEST_DAEMON_CHECKS
  WylDaemonReadinessAuditFault fault;
  WylDaemonReadinessVerifyFault verify_fault;
  gboolean *out_verify_exact;
#endif
} WylPolicyAuditReadinessPublication;

#ifdef WYL_TEST_DAEMON_CHECKS
static gint policy_audit_fault_once;
static gint policy_audit_verify_fault_once;

void wyl_daemon_check_set_policy_audit_fault_once_for_test
    (WylDaemonReadinessAuditFault fault)
{
  g_return_if_fail (fault > WYL_DAEMON_READINESS_AUDIT_FAULT_NONE);
  g_return_if_fail (fault <= WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_COMMITTED);
  g_atomic_int_set (&policy_audit_fault_once, fault);
}

void wyl_daemon_check_set_policy_audit_verify_fault_once_for_test
    (WylDaemonReadinessVerifyFault fault)
{
  g_return_if_fail (fault > WYL_DAEMON_READINESS_VERIFY_FAULT_NONE);
  g_return_if_fail (fault <= WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_WRONG);
  g_atomic_int_set (&policy_audit_verify_fault_once, fault);
}
#endif

#ifdef WYL_TEST_DAEMON_CHECKS
static wyrelog_error_t
    mutate_exact_verification_candidate_for_test
    (WylPolicyAuditReadinessPublication * publication,
    WylEngineVerification * verification, WylDaemonReadinessVerifyFault extra,
    WylDaemonReadinessVerifyFault wrong, const gchar * relation,
    const gint64 * expected, const gint64 * mutant, gsize ncols,
    gboolean * out_targeted)
{
  *out_targeted = publication->verify_fault == extra
      || publication->verify_fault == wrong;
  if (!*out_targeted)
    return WYRELOG_E_OK;
  WylEngineVerificationCandidateMutation mutation =
      publication->verify_fault == extra ?
      WYL_ENGINE_VERIFICATION_CANDIDATE_EXTRA :
      WYL_ENGINE_VERIFICATION_CANDIDATE_WRONG;
  return wyl_engine_verification_mutate_keyed_row_for_test (verification,
      relation, expected, mutant, ncols, mutation);
}
#endif

static wyrelog_error_t
mutate_policy_audit_readiness_publication (wyl_policy_store_t *store,
    gpointer data)
{
  WylPolicyAuditReadinessPublication *publication = data;
  const WylAuditEvent *event = publication->event;
  gboolean inserted = FALSE;
  wyrelog_error_t rc = wyl_policy_store_record_audit_intention_full (store,
      publication->id, wyl_audit_event_get_created_at_us (event),
      wyl_audit_event_get_subject_id (event),
      wyl_audit_event_get_action (event),
      wyl_audit_event_get_resource_id (event),
      wyl_audit_event_get_deny_reason (event),
      wyl_audit_event_get_deny_origin (event),
      wyl_audit_event_get_request_id (event),
      wyl_audit_event_get_decision (event), &inserted);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!inserted)
    return WYRELOG_E_POLICY;
#ifdef WYL_TEST_DAEMON_CHECKS
  if (publication->fault == WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_INTENTION)
    return WYRELOG_E_IO;
#endif

  inserted = FALSE;
  rc = wyl_policy_store_append_audit_event_full (store, publication->id,
      wyl_audit_event_get_created_at_us (event),
      wyl_audit_event_get_subject_id (event),
      wyl_audit_event_get_action (event),
      wyl_audit_event_get_resource_id (event),
      wyl_audit_event_get_deny_reason (event),
      wyl_audit_event_get_deny_origin (event),
      wyl_audit_event_get_request_id (event),
      wyl_audit_event_get_decision (event), &inserted);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!inserted)
    return WYRELOG_E_POLICY;
#ifdef WYL_TEST_DAEMON_CHECKS
  if (publication->fault == WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_EVENT)
    return WYRELOG_E_IO;
#endif

  rc = wyl_policy_store_mark_audit_intention_committed (store, publication->id);
#ifdef WYL_TEST_DAEMON_CHECKS
  if (rc == WYRELOG_E_OK
      && publication->fault == WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_COMMITTED)
    return WYRELOG_E_IO;
#endif
  return rc;
}

static wyrelog_error_t
    verify_exact_policy_audit_readiness_publication
    (WylEngineVerification * verification, gpointer data)
{
  WylPolicyAuditReadinessPublication *publication = data;
  const WylAuditEvent *event = publication->event;
  gint64 event_row[3] = { 0 };
  wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
      publication->id, &event_row[0]);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  event_row[1] = wyl_audit_event_get_created_at_us (event);
  rc = wyl_engine_verification_lookup_symbol (verification, "allow",
      &event_row[2]);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;

  gboolean exact = FALSE;
#ifdef WYL_TEST_DAEMON_CHECKS
  gboolean targeted = FALSE;
  gint64 event_mutant[3] = { event_row[0], event_row[1], event_row[2] };
  if (publication->verify_fault ==
      WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_EXTRA
      || publication->verify_fault ==
      WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_WRONG) {
    rc = wyl_engine_verification_lookup_symbol (verification,
        wyl_audit_event_get_action (event), &event_mutant[2]);
    if (rc != WYRELOG_E_OK)
      return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  }
  rc = mutate_exact_verification_candidate_for_test (publication,
      verification, WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_EXTRA,
      WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_WRONG, "audit_event_input",
      event_row, event_mutant, G_N_ELEMENTS (event_row), &targeted);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  rc = wyl_engine_verification_has_exact_keyed_row (verification,
      "audit_event", event_row[0], event_row, G_N_ELEMENTS (event_row), &exact);
#ifdef WYL_TEST_DAEMON_CHECKS
  if (targeted && publication->out_verify_exact != NULL)
    *publication->out_verify_exact = exact;
#endif
  if (rc != WYRELOG_E_OK || !exact)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;

  gint64 attribute_row[2] = { event_row[0], 0 };
  rc = wyl_engine_verification_lookup_symbol (verification,
      wyl_audit_event_get_action (event), &attribute_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
#ifdef WYL_TEST_DAEMON_CHECKS
  const gint64 action_id = attribute_row[1];
  gint64 action_mutant[2] = { event_row[0], attribute_row[1] };
  if (publication->verify_fault ==
      WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_EXTRA
      || publication->verify_fault ==
      WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_WRONG) {
    rc = wyl_engine_verification_lookup_symbol (verification,
        wyl_audit_event_get_request_id (event), &action_mutant[1]);
    if (rc != WYRELOG_E_OK)
      return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
  }
  targeted = FALSE;
  rc = mutate_exact_verification_candidate_for_test (publication,
      verification, WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_EXTRA,
      WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_WRONG,
      "audit_event_action_input", attribute_row, action_mutant,
      G_N_ELEMENTS (attribute_row), &targeted);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  rc = wyl_engine_verification_has_exact_keyed_row (verification,
      "audit_event_action", event_row[0], attribute_row,
      G_N_ELEMENTS (attribute_row), &exact);
#ifdef WYL_TEST_DAEMON_CHECKS
  if (targeted && publication->out_verify_exact != NULL)
    *publication->out_verify_exact = exact;
#endif
  if (rc != WYRELOG_E_OK || !exact)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;

  rc = wyl_engine_verification_lookup_symbol (verification,
      wyl_audit_event_get_request_id (event), &attribute_row[1]);
  if (rc != WYRELOG_E_OK)
    return rc == WYRELOG_E_NOT_FOUND ? WYRELOG_E_POLICY : rc;
#ifdef WYL_TEST_DAEMON_CHECKS
  const gint64 request_mutant[2] = { event_row[0], action_id };
  targeted = FALSE;
  rc = mutate_exact_verification_candidate_for_test (publication,
      verification, WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_EXTRA,
      WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_WRONG,
      "audit_event_request_id_input", attribute_row, request_mutant,
      G_N_ELEMENTS (attribute_row), &targeted);
  if (rc != WYRELOG_E_OK)
    return rc;
#endif
  rc = wyl_engine_verification_has_exact_keyed_row (verification,
      "audit_event_request_id", event_row[0], attribute_row,
      G_N_ELEMENTS (attribute_row), &exact);
#ifdef WYL_TEST_DAEMON_CHECKS
  if (targeted && publication->out_verify_exact != NULL)
    *publication->out_verify_exact = exact;
#endif
  if (rc != WYRELOG_E_OK || !exact)
    return rc == WYRELOG_E_OK ? WYRELOG_E_POLICY : rc;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
check_policy_audit_facts_ready (WylHandle *handle, gchar **out_id,
    gint64 *out_created_at_us, WylCommittedPublicationStage *out_stage,
    gboolean *out_verify_exact)
{
  if (out_id != NULL)
    *out_id = NULL;
  if (out_created_at_us != NULL)
    *out_created_at_us = -1;
  if (out_stage != NULL)
    *out_stage = WYL_COMMITTED_PUBLICATION_PRECOMMIT_REJECTED;
  if (out_verify_exact != NULL)
    *out_verify_exact = TRUE;
  if (!WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();

  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "policy_audit_reload_check");
  wyl_audit_event_set_resource_id (ev, "audit_event");
  wyl_audit_event_set_deny_reason (ev, "readiness");
  wyl_audit_event_set_deny_origin (ev, "policy_store");
  wyl_audit_event_set_request_id (ev, "wyrelogd-readiness-request");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);

  g_autofree gchar *audit_id = wyl_audit_event_dup_id_string (ev);
  if (audit_id == NULL)
    return WYRELOG_E_INTERNAL;
  if (out_id != NULL)
    *out_id = g_strdup (audit_id);
  if (out_created_at_us != NULL)
    *out_created_at_us = wyl_audit_event_get_created_at_us (ev);

  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_BUSY;
  WylPolicyAuditReadinessPublication publication = {
    .event = ev,
    .id = audit_id,
#ifdef WYL_TEST_DAEMON_CHECKS
    .fault = g_atomic_int_get (&policy_audit_fault_once),
    .verify_fault = g_atomic_int_get (&policy_audit_verify_fault_once),
    .out_verify_exact = out_verify_exact,
#endif
  };
#ifdef WYL_TEST_DAEMON_CHECKS
  if (publication.fault != WYL_DAEMON_READINESS_AUDIT_FAULT_NONE)
    g_atomic_int_set (&policy_audit_fault_once,
        WYL_DAEMON_READINESS_AUDIT_FAULT_NONE);
  if (publication.verify_fault != WYL_DAEMON_READINESS_VERIFY_FAULT_NONE)
    g_atomic_int_set (&policy_audit_verify_fault_once,
        WYL_DAEMON_READINESS_VERIFY_FAULT_NONE);
#endif
  return wyl_engine_session_run_committed_publication (session,
      mutate_policy_audit_readiness_publication, &publication,
      verify_exact_policy_audit_readiness_publication, &publication, NULL,
      NULL, out_stage);
}

wyrelog_error_t
wyl_daemon_check_policy_audit_facts_ready (WylHandle *handle)
{
  return check_policy_audit_facts_ready (handle, NULL, NULL, NULL, NULL);
}

#ifdef WYL_TEST_DAEMON_CHECKS
wyrelog_error_t
wyl_daemon_check_policy_audit_facts_ready_for_test (WylHandle *handle,
    gchar **out_id, gint64 *out_created_at_us,
    WylCommittedPublicationStage *out_stage, gboolean *out_verify_exact)
{
  return check_policy_audit_facts_ready (handle, out_id, out_created_at_us,
      out_stage, out_verify_exact);
}
#endif

wyrelog_error_t
wyl_daemon_check_audit_sink_ready (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  gboolean found = FALSE;

  wyrelog_error_t rc =
      wyl_audit_conn_table_exists (conn, "audit_events", &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_IO;

  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  if (session == NULL)
    return WYRELOG_E_BUSY;
  rc = wyl_handle_load_policy_store_audit_events (handle);
  if (rc != WYRELOG_E_OK)
    return wyl_handle_fail_committed_engine_projection (session, rc);

  g_autofree gchar *json = NULL;
  rc = wyl_audit_conn_query_events_json (conn,
      "request_id(\"wyrelogd-readiness-request\")", &json);
  if (rc != WYRELOG_E_OK)
    return wyl_handle_fail_committed_engine_projection (session, rc);
  if (json == NULL || strstr (json, "policy_audit_reload_check") == NULL
      || strstr (json, "wyrelogd-readiness-request") == NULL)
    return wyl_handle_fail_committed_engine_projection (session,
        WYRELOG_E_POLICY);
  g_clear_pointer (&session, wyl_engine_session_release);

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_check");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  rc = wyl_audit_emit (handle, ev);
  if (rc != WYRELOG_E_OK)
    return rc;
#else
  (void) handle;
#endif
  return WYRELOG_E_OK;
}

static wyrelog_error_t
check_login_skip_mfa_override_ready (WylHandle *handle, gboolean restore)
{
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (wyl_login_req_t) override_login = wyl_login_req_new ();
  g_autoptr (WylSession) override_session = NULL;
  wyl_login_req_set_username (override_login,
      "wyrelogd-skip-mfa-override-user");
  wyl_login_req_set_skip_mfa (override_login, TRUE);
  wyrelog_error_t rc =
      wyl_session_login (handle, override_login, &override_session);
  wyl_handle_set_login_skip_mfa_allowed (handle, restore);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (override_session == NULL)
    return WYRELOG_E_POLICY;

  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_login_skip_mfa_ready (WylHandle *handle)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  g_autoptr (WylSession) session = NULL;

  wyl_login_req_set_username (login, "wyrelogd-skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  gboolean allowed = wyl_handle_get_login_skip_mfa_allowed (handle);
  gboolean override_allowed =
      wyl_handle_get_login_skip_mfa_override_allowed (handle);
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (!allowed && rc == WYRELOG_E_POLICY)
    return check_login_skip_mfa_override_ready (handle, override_allowed);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (session == NULL)
    return WYRELOG_E_POLICY;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-skip-mfa-user");
  wyl_grant_req_set_action (grant, "wyrelogd.skip_mfa.ready");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_handle_apply_permission_state_transition (handle,
      "wyrelogd-skip-mfa-user", "wyrelogd.skip_mfa.ready", session_id, "grant",
      NULL, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-skip-mfa-user");
  wyl_decide_req_set_action (decide, "wyrelogd.skip_mfa.ready");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return WYRELOG_E_POLICY;

  return check_login_skip_mfa_override_ready (handle, override_allowed);
}

static wyrelog_error_t
login_check_principal (WylHandle *handle, const gchar *username,
    WylSession **out_session)
{
  if (out_session == NULL)
    return WYRELOG_E_INVALID;
  *out_session = NULL;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);

  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc = wyl_session_login (handle, login, &session);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_session_mfa_verify (handle, session);
  if (rc != WYRELOG_E_OK)
    return rc;

  *out_session = g_steal_pointer (&session);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_daemon_check_policy_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-snapshot-user", &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-snapshot-user");
  wyl_grant_req_set_action (grant, "wyrelogd.snapshot.read");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  rc = wyl_handle_apply_permission_state_transition (handle,
      "wyrelogd-snapshot-user", "wyrelogd.snapshot.read", session_id, "grant",
      NULL, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-snapshot-user");
  wyl_decide_req_set_action (decide, "wyrelogd.snapshot.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_daemon_check_direct_permission_grant_ready (WylHandle *handle)
{
  /*
   * This readiness probe covers direct permission mutation, audit, reload,
   * and the decision path that requires durable permission-state arming.
   * The canonical stateful transition lifecycle probe is
   * wyl_daemon_check_permission_state_transition_ready().
   */
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-direct-grant-user", &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, "wyrelogd-direct-grant-user");
  wyl_grant_req_set_action (grant, "wyrelogd.direct_grant.read");
  wyl_grant_req_set_resource_id (grant, session_id);
  rc = wyl_perm_grant (handle, grant);
  if (rc != WYRELOG_E_OK)
    return rc;

  gboolean found = FALSE;
  rc = wyl_policy_store_direct_permission_exists (wyl_handle_get_policy_store
      (handle), "wyrelogd-direct-grant-user", "wyrelogd.direct_grant.read",
      session_id, &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;

  rc = wyl_handle_apply_permission_state_transition (handle,
      "wyrelogd-direct-grant-user", "wyrelogd.direct_grant.read", session_id,
      "grant", NULL, NULL);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-direct-grant-user");
  wyl_decide_req_set_action (decide, "wyrelogd.direct_grant.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_daemon_check_permission_state_transition_ready (WylHandle *handle)
{
  static const gchar *user = "wyrelogd-perm-state-user";
  static const gchar *perm = "wyrelogd.perm_state.read";
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  wyrelog_error_t rc = wyl_policy_store_upsert_permission (store, perm,
      "permission state readiness read", "basic");
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (WylSession) session = NULL;
  rc = login_check_principal (handle, user, &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  rc = wyl_policy_store_grant_direct_permission (store, user, perm, session_id);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (WylAuditEvent) audit_event = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (audit_event, "wyrelogd");
  wyl_audit_event_set_action (audit_event, "permission_state.grant");
  wyl_audit_event_set_resource_id (audit_event, perm);
  wyl_audit_event_set_deny_reason (audit_event, "daemon_check");
  wyl_audit_event_set_deny_origin (audit_event, "dormant");
  wyl_audit_event_set_decision (audit_event, WYL_DECISION_ALLOW);

  gint64 event_id = -1;
  rc = wyl_handle_apply_permission_state_transition (handle, user, perm,
      session_id, "grant", audit_event, &event_id);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (event_id <= 0)
    return WYRELOG_E_POLICY;

  gboolean found = FALSE;
  rc = wyl_policy_store_permission_state_exists (store, user, perm, session_id,
      &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!found)
    return WYRELOG_E_POLICY;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, user);
  wyl_decide_req_set_action (decide, perm);
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static wyrelog_error_t
insert_symbol_row (WylHandle *handle, const gchar *relation,
    const gchar *const *symbols, gsize ncols)
{
  g_autoptr (WylEngineSession) session = wyl_engine_session_acquire (handle);
  gint64 row[4];

  if (ncols == 0 || ncols > G_N_ELEMENTS (row))
    return WYRELOG_E_INVALID;

  for (gsize i = 0; i < ncols; i++) {
    wyrelog_error_t rc =
        wyl_engine_session_intern_symbol (session, symbols[i], &row[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }

  return wyl_engine_session_insert (session, relation, row, ncols);
}

static wyrelog_error_t
mutate_role_permission_snapshot (wyl_policy_store_t *store, gpointer data)
{
  (void) data;
  wyrelog_error_t rc = wyl_policy_store_upsert_role (store,
      "site.snapshot-child", "snapshot child");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_upsert_role (store, "site.snapshot-parent",
        "snapshot parent");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_upsert_permission (store, "wyrelogd.role.read",
        "role read", "basic");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_grant_role_permission (store,
        "site.snapshot-parent", "wyrelogd.role.read");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_grant_role_inheritance (store,
        "site.snapshot-child", "site.snapshot-parent");
  return rc;
}

static wyrelog_error_t
verify_role_permission_snapshot (WylEngineVerification *verification,
    gpointer data)
{
  (void) data;
  const gchar *symbols[] = {
    "site.snapshot-child",
    "wyrelogd.role.read",
  };
  gint64 row[2] = { 0 };
  for (guint i = 0; i < G_N_ELEMENTS (symbols); i++) {
    wyrelog_error_t rc = wyl_engine_verification_lookup_symbol (verification,
        symbols[i], &row[i]);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  gboolean found = FALSE;
  wyrelog_error_t rc = wyl_engine_verification_contains (verification,
      "effective_permission", row, G_N_ELEMENTS (row), &found);
  if (rc != WYRELOG_E_OK)
    return rc;
  return found ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_daemon_check_role_permission_snapshot_reload_ready (WylHandle *handle)
{
  g_autoptr (WylSession) session = NULL;
  wyrelog_error_t rc =
      login_check_principal (handle, "wyrelogd-role-user", &session);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return WYRELOG_E_INTERNAL;

  g_autoptr (WylEngineSession) engine_session =
      wyl_engine_session_acquire (handle);
  if (engine_session == NULL)
    return WYRELOG_E_BUSY;
  rc = wyl_engine_session_run_committed_publication (engine_session,
      mutate_role_permission_snapshot, NULL, verify_role_permission_snapshot,
      NULL, NULL, NULL, NULL);
  g_clear_pointer (&engine_session, wyl_engine_session_release);
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *member_row[] = {
    "wyrelogd-role-user",
    "site.snapshot-child",
    session_id,
  };
  rc = insert_symbol_row (handle, "member_of", member_row,
      G_N_ELEMENTS (member_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  const gchar *perm_state_row[] = {
    "wyrelogd-role-user",
    "wyrelogd.role.read",
    session_id,
    "armed",
  };
  rc = insert_symbol_row (handle, "perm_state", perm_state_row,
      G_N_ELEMENTS (perm_state_row));
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "wyrelogd-role-user");
  wyl_decide_req_set_action (decide, "wyrelogd.role.read");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  rc = wyl_decide (handle, decide, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_decide_resp_get_decision (resp) == WYL_DECISION_ALLOW ?
      WYRELOG_E_OK : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_daemon_emit_start_event (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "daemon_start");
  wyl_audit_event_set_resource_id (ev, "audit_events");
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  return wyl_audit_emit (handle, ev);
#else
  (void) handle;
  return WYRELOG_E_OK;
#endif
}

wyrelog_error_t
wyl_daemon_emit_bootstrap_admin_audit (WylHandle *handle,
    const gchar *subject_id, gboolean applied)
{
#ifdef WYL_HAS_AUDIT
  if (subject_id == NULL || subject_id[0] == '\0')
    return WYRELOG_E_INVALID;

  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "wyrelogd");
  wyl_audit_event_set_action (ev, "bootstrap_admin_apply");
  wyl_audit_event_set_resource_id (ev, subject_id);
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  if (!applied)
    wyl_audit_event_set_deny_reason (ev, "already_sealed_same_subject");
  return wyl_audit_emit (handle, ev);
#else
  (void) handle;
  (void) subject_id;
  (void) applied;
  return WYRELOG_E_OK;
#endif
}

int
wyl_daemon_run_checks (WylHandle *handle)
{
  wyrelog_error_t rc = wyl_daemon_check_delta_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: delta readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_wirelog_policy_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_store_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy store readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_audit_facts_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy audit fact readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_policy_snapshot_reload_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: policy snapshot reload check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_direct_permission_grant_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: direct permission grant check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_permission_state_transition_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: permission state transition check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_role_permission_snapshot_reload_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: role permission reload check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_audit_sink_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: audit readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  rc = wyl_daemon_check_login_skip_mfa_ready (handle);
  if (rc != WYRELOG_E_OK) {
    g_printerr ("wyrelogd: login skip-mfa readiness check failed: %s\n",
        wyrelog_error_string (rc));
    return 1;
  }

  return 0;
}
