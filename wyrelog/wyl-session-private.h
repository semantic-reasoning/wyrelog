/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "wyl-id-private.h"
#include "wyrelog/session.h"

G_BEGIN_DECLS;

typedef enum wyl_session_auth_method_t
{
  WYL_SESSION_AUTH_METHOD_HUMAN = 0,
  WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL,
  WYL_SESSION_AUTH_METHOD_LAST_,
} wyl_session_auth_method_t;

typedef struct wyl_service_session_descriptor_t
{
  wyl_id_t session_id;
  const gchar *jti;
  const gchar *subject_id;
  const gchar *tenant_id;
  const gchar *credential_id;
  guint64 credential_generation;
  gint64 issued_at_seconds;
  gint64 expires_at_seconds;
} wyl_service_session_descriptor_t;

/*
 * Constructs detached metadata only. The returned session is internally
 * ACTIVE but is not registered or published and has no handle association.
 * Every string in |descriptor| is copied. The exact caller-supplied session
 * id and timestamps are retained unchanged.
 */
G_GNUC_INTERNAL wyrelog_error_t wyl_session_new_service_detached (const
    wyl_service_session_descriptor_t * descriptor, WylSession ** out_session);

/* String accessors return owned copies and the id accessor copies by value.
 * Service metadata itself is immutable after construction. */
G_GNUC_INTERNAL wyl_session_auth_method_t
wyl_session_get_auth_method_private (const WylSession * session);
G_GNUC_INTERNAL gboolean wyl_session_is_active_private (const
    WylSession * session);
G_GNUC_INTERNAL wyrelog_error_t wyl_session_copy_persistent_id_private (const
    WylSession * session, wyl_id_t * out_id);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_jti_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_subject_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_tenant_private (const
    WylSession * session);
G_GNUC_INTERNAL gchar *wyl_session_dup_service_credential_id_private (const
    WylSession * session);
G_GNUC_INTERNAL guint64 wyl_session_get_service_credential_generation_private
    (const WylSession * session);
G_GNUC_INTERNAL gint64 wyl_session_get_service_issued_at_seconds_private (const
    WylSession * session);
G_GNUC_INTERNAL gint64 wyl_session_get_service_expires_at_seconds_private (const
    WylSession * session);

G_END_DECLS;
