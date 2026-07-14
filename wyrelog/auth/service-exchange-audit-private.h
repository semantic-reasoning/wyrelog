/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/wyl-id-private.h"

G_BEGIN_DECLS;

#define WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION 1u
#define WYL_SERVICE_EXCHANGE_PAYLOAD_SCHEMA_VERSION 1u
#define WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_LEN 64u
#define WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF 65u
#define WYL_SERVICE_EXCHANGE_REQUEST_ID_LEN 27u
#define WYL_SERVICE_EXCHANGE_REQUEST_ID_BUF 28u
#define WYL_SERVICE_EXCHANGE_UUID_LEN 36u
#define WYL_SERVICE_EXCHANGE_UUID_BUF 37u
#define WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_LEN 64u
#define WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF 65u

typedef struct wyl_service_exchange_text_t
{
  const gchar *data;
  gsize len;
} wyl_service_exchange_text_t;

typedef struct wyl_service_exchange_audit_input_t
{
  wyl_id_t intention_id;
  wyl_service_exchange_text_t request_id;
  wyl_service_exchange_text_t credential_id;
  guint64 credential_generation;
  wyl_service_exchange_text_t service_principal;
  wyl_service_exchange_text_t tenant_id;
  wyl_service_exchange_text_t session_id;
  wyl_service_exchange_text_t jti;
  gint64 created_at_us;
} wyl_service_exchange_audit_input_t;

typedef struct wyl_service_exchange_audit_material_t
{
  gchar intention_id[WYL_SERVICE_EXCHANGE_UUID_BUF];
  gchar request_id[WYL_SERVICE_EXCHANGE_REQUEST_ID_BUF];
  gchar session_fingerprint[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF];
  gchar jti_fingerprint[WYL_SERVICE_EXCHANGE_FINGERPRINT_HEX_BUF];
  gchar payload_digest[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
  GBytes *canonical_payload;
} wyl_service_exchange_audit_material_t;

typedef struct wyl_service_exchange_audit_projection_t
{
  const gchar *intention_id;
  const gchar *payload_digest;
  const gchar *request_id;
  const gchar *credential_id;
  guint64 credential_generation;
  const gchar *service_principal;
  const gchar *tenant_id;
  gint64 created_at_us;
  guint32 payload_schema_version;
  guint32 fingerprint_schema_version;
  const gchar *session_fingerprint;
  const gchar *jti_fingerprint;
  GBytes *canonical_payload;
} wyl_service_exchange_audit_projection_t;

#define WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT { 0 }

/*
 * Fingerprint v1 hashes this exact transcript with SHA-256:
 *   ASCII "wyrelog.service-exchange.audit-fingerprint", NUL, u32be(1),
 *   u32be(kind length), kind, u64be(identifier length), identifier.
 * Kind is exactly "session_id" or "jti" and identifiers are canonical
 * lowercase UUIDv7 text. The result is lowercase 64-character hex.
 *
 * Payload v1 is:
 *   ASCII "wyrelog.service-exchange.intention-payload", NUL, u32be(1),
 *   canonical intention UUID as u32be(36)+bytes,
 *   each of fixed event type and outcome as u32be(length)+bytes,
 *   u64be(created_at_us),
 *   each of request ID and credential ID as u32be(length)+bytes,
 *   u64be(credential generation),
 *   each of service principal and tenant as u32be(length)+bytes,
 *   u32be(fingerprint version),
 *   u32be(32), 32 raw session fingerprint bytes,
 *   u32be(32), 32 raw jti fingerprint bytes.
 * The payload digest is SHA-256 over all those bytes, lowercase hex.
 * Raw session and jti identifiers never enter the payload.
 *
 * An output material passed to encode must equal
 * WYL_SERVICE_EXCHANGE_AUDIT_MATERIAL_INIT. A populated material must be
 * cleared before reuse. encode builds a temporary and moves it into the
 * caller's material only on success; failures leave the initialized output
 * empty and never attempt to release caller memory.
 */

G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_audit_encode (const
    wyl_service_exchange_audit_input_t * input,
    wyl_service_exchange_audit_material_t * out_material);

G_GNUC_INTERNAL void wyl_service_exchange_audit_material_clear
    (wyl_service_exchange_audit_material_t * material);

/* Validates a sanitized projection against the one frozen v1 transcript.
 * Every separately supplied field must be canonical and byte-for-byte equal
 * to its framed value in canonical_payload. */
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_audit_projection_validate
    (const wyl_service_exchange_audit_projection_t * projection);

G_END_DECLS;
