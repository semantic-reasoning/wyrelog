/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/wyrelog.h"

wyrelog_error_t wyl_daemon_check_wirelog_policy_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_policy_store_ready (WylHandle * handle);
wyrelog_error_t wyl_daemon_check_policy_audit_facts_ready (WylHandle * handle);
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
int wyl_daemon_run_checks (WylHandle * handle);
