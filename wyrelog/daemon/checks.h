/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/wyrelog.h"

#ifdef WYL_TEST_DAEMON_CHECKS
#include "wyrelog/wyl-handle-private.h"
#endif

wyrelog_error_t wyl_daemon_check_wirelog_policy_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_policy_store_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_policy_audit_facts_ready (WylHandle * handle);
#ifdef WYL_TEST_DAEMON_CHECKS
typedef enum
{
  WYL_DAEMON_READINESS_AUDIT_FAULT_NONE = 0,
  WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_INTENTION,
  WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_EVENT,
  WYL_DAEMON_READINESS_AUDIT_FAULT_AFTER_COMMITTED,
} WylDaemonReadinessAuditFault;
typedef enum
{
  WYL_DAEMON_READINESS_VERIFY_FAULT_NONE = 0,
  /* Model an extra or wrong same-key candidate row at each exact-verification
   * boundary without weakening the production SQLite constraints. */
  WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_EXTRA,
  WYL_DAEMON_READINESS_VERIFY_FAULT_EVENT_WRONG,
  WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_EXTRA,
  WYL_DAEMON_READINESS_VERIFY_FAULT_ACTION_WRONG,
  WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_EXTRA,
  WYL_DAEMON_READINESS_VERIFY_FAULT_REQUEST_WRONG,
} WylDaemonReadinessVerifyFault;
void wyl_daemon_check_set_policy_audit_fault_once_for_test
    (WylDaemonReadinessAuditFault fault);
void wyl_daemon_check_set_policy_audit_verify_fault_once_for_test
    (WylDaemonReadinessVerifyFault fault);
wyrelog_error_t wyl_daemon_check_policy_audit_facts_ready_for_test
    (WylHandle * handle, gchar ** out_id, gint64 * out_created_at_us,
    WylCommittedPublicationStage * out_stage, gboolean * out_verify_exact);
#endif
wyrelog_error_t wyl_daemon_check_audit_sink_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_login_skip_mfa_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_policy_snapshot_reload_ready (WylHandle *
    handle);
wyrelog_error_t
wyl_daemon_check_direct_permission_grant_ready (WylHandle * handle);
wyrelog_error_t
wyl_daemon_check_permission_state_transition_ready (WylHandle * handle);
wyrelog_error_t
wyl_daemon_check_role_permission_snapshot_reload_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_emit_start_event (WylHandle * handle);
wyrelog_error_t wyl_daemon_emit_bootstrap_admin_audit (WylHandle * handle,
    const gchar * subject_id, gboolean applied);
int wyl_daemon_run_checks (WylHandle * handle);
