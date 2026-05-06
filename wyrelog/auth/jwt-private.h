/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_JWT_ACCESS_TTL_SECONDS 900

typedef struct
{
  const gchar *jti;
  const gchar *subject;
  const gchar *issuer;
  const gchar *audience;
  const gchar *tenant;
  const gchar *principal_state_at_issue;
  const gchar *session_id;
  gint64 issued_at;
  gint64 ttl_seconds;
} wyl_jwt_issue_input_t;

wyrelog_error_t wyl_jwt_base64url_encode (const guint8 * data, gsize len,
    gchar ** out_text);
wyrelog_error_t wyl_jwt_base64url_decode (const gchar * text,
    GBytes ** out_bytes);
wyrelog_error_t wyl_jwt_build_header_json (gchar ** out_json);
wyrelog_error_t wyl_jwt_build_payload_json (const wyl_jwt_issue_input_t *
    input, gchar ** out_json);
wyrelog_error_t wyl_jwt_build_unsigned_segments (const wyl_jwt_issue_input_t *
    input, gchar ** out_header_segment, gchar ** out_payload_segment);

G_END_DECLS;
