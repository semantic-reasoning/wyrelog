/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyl-fsm-session-private.h"
#include "wyl-session-private.h"

/* Single non-installed layout authority shared only by the core GType
 * implementation and the uninstalled service-session companion archive. */
struct _WylSession
{
  GObject parent_instance;
  wyl_id_t id;
  wyl_session_id_t sid;
  gint64 created_at_us;
  gchar *username;
  gchar *tenant;
  wyl_session_state_t state;
  wyl_session_auth_method_t auth_method;
  gchar *service_jti;
  gchar *service_subject_id;
  gchar *service_credential_id;
  guint64 service_credential_generation;
  gint64 service_issued_at_seconds;
  gint64 service_expires_at_seconds;
};
