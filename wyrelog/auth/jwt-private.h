/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_JWT_ACCESS_TTL_SECONDS 900

typedef struct
{
  const gchar *key_id;
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

typedef struct
{
  gchar *jti;
  gchar *subject;
  gchar *issuer;
  gchar *audience;
  gchar *tenant;
  gchar *principal_state_at_issue;
  gchar *session_id;
  gint64 not_before;
  gint64 expires_at;
} wyl_jwt_access_claims_t;

void wyl_jwt_access_claims_clear (wyl_jwt_access_claims_t * claims);
wyrelog_error_t wyl_jwt_base64url_encode (const guint8 * data, gsize len,
    gchar ** out_text);
wyrelog_error_t wyl_jwt_base64url_decode (const gchar * text,
    GBytes ** out_bytes);
wyrelog_error_t wyl_jwt_build_header_json (const gchar * key_id,
    gchar ** out_json);
wyrelog_error_t wyl_jwt_build_payload_json (const wyl_jwt_issue_input_t *
    input, gchar ** out_json);
wyrelog_error_t wyl_jwt_build_unsigned_segments (const wyl_jwt_issue_input_t *
    input, gchar ** out_header_segment, gchar ** out_payload_segment);
wyrelog_error_t wyl_jwt_sign_hs256 (const wyl_jwt_issue_input_t * input,
    const guint8 * secret, gsize secret_len, gchar ** out_token);
wyrelog_error_t wyl_jwt_verify_hs256_signature (const gchar * token,
    const guint8 * secret, gsize secret_len, const gchar * expected_key_id,
    GBytes ** out_payload_json);
wyrelog_error_t wyl_jwt_parse_access_claims_json (GBytes * payload_json,
    wyl_jwt_access_claims_t * out_claims);
wyrelog_error_t wyl_jwt_verify_hs256_access_token (const gchar * token,
    const guint8 * secret, gsize secret_len, const gchar * expected_key_id,
    const gchar * expected_issuer, const gchar * expected_audience,
    gint64 now, GBytes ** out_payload_json);

G_END_DECLS;
