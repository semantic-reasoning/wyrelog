/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib-object.h>

#include "wyrelog/error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * WylClient - HTTP client for talking to a remote wyrelog daemon.
 *
 * Owns the HTTP transport, the base URL, and the current
 * authentication state (access token, refresh token, MFA bind).
 * Created with wyl_client_new, released with g_object_unref or
 * g_autoptr.
 */
  G_DECLARE_FINAL_TYPE (WylClient, wyl_client, WYL, CLIENT, GObject)
#define WYL_TYPE_CLIENT (wyl_client_get_type ())
/*
 * WylAuditIter - paginated audit query cursor.
 *
 * Issues one HTTP GET per page and yields events through
 * wyl_audit_iter_next until the server reports the end.
 */
  G_DECLARE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, WYL, AUDIT_ITER, GObject)
#define WYL_TYPE_AUDIT_ITER (wyl_audit_iter_get_type ())
/* Lifecycle */
  wyrelog_error_t wyl_client_new (const char *base_url,
      WylClient ** out_client);

/* Authentication */
  wyrelog_error_t wyl_client_login (WylClient * client,
      const char *username, const char *password);
  wyrelog_error_t wyl_client_token_refresh (WylClient * client);
  wyrelog_error_t wyl_client_mfa_verify (WylClient * client, const char *otp);

/* Decide */
  wyrelog_error_t wyl_client_decide (WylClient * client,
      const char *user,
      const char *perm, const char *session_token, int *out_decision);

/* Audit query (iterator) */
  wyrelog_error_t wyl_client_audit_query (WylClient * client,
      const char *query_filter, WylAuditIter ** out_iter);
  wyrelog_error_t wyl_audit_iter_next (WylAuditIter * iter,
      gboolean * out_has_next);

/* Tenant / event */
  wyrelog_error_t wyl_client_tenant_select (WylClient * client,
      const char *tenant);
  wyrelog_error_t wyl_client_event_emit (WylClient * client,
      const char *event_kind, const char *event_payload_json);

/* Meta */
  const char *wyrelog_client_version_string (void);

#ifdef __cplusplus
}
#endif
