/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyrelog/wyrelog.h"

typedef struct
{
  WylHandle *handle;
  guint64 inserted;
  guint64 removed;
  guint64 audit_errors;
  wyrelog_error_t last_audit_error;
  gboolean expect_effective_member;
  gint64 expected_row[3];
  gboolean matched_expected_insert;
  gboolean matched_expected_remove;
  gboolean expect_principal_fired;
  gboolean expect_session_fired;
  gint64 expected_principal_fired[5];
  gint64 expected_session_fired[5];
  gboolean matched_principal_fired_insert;
  gboolean matched_session_fired_insert;
  gboolean matched_principal_fired_remove;
  gboolean matched_session_fired_remove;
} WylDaemonRuntime;

wyrelog_error_t wyl_daemon_start_delta_callbacks (WylHandle * handle,
    WylDaemonRuntime * runtime);
wyrelog_error_t wyl_daemon_check_delta_ready (WylHandle * handle);
