/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_SERVICE_CREDENTIAL_FORMAT_VERSION 1u
#define WYL_SERVICE_CREDENTIAL_VERIFIER_VERSION 1u
#define WYL_SERVICE_CREDENTIAL_ID_PREFIX "wlc_"
#define WYL_SERVICE_CREDENTIAL_ID_PREFIX_LEN 4u
#define WYL_SERVICE_CREDENTIAL_KSUID_LEN 27u
#define WYL_SERVICE_CREDENTIAL_ID_LEN 31u
#define WYL_SERVICE_CREDENTIAL_ID_BUF 32u
#define WYL_SERVICE_CREDENTIAL_SECRET_BYTES 32u
#define WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN 43u
#define WYL_SERVICE_CREDENTIAL_SECRET_TEXT_BUF 44u
#define WYL_SERVICE_CREDENTIAL_SALT_BYTES 16u
#define WYL_SERVICE_CREDENTIAL_CVK_BYTES 32u
#define WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES 32u
#define WYL_SERVICE_CREDENTIAL_BINDING_MAX_BYTES 128u

typedef struct wyl_service_credential_secret_t wyl_service_credential_secret_t;

typedef struct wyl_service_credential_material_t
{
  guint32 credential_format_version;
  guint32 verifier_version;
  gchar credential_id[WYL_SERVICE_CREDENTIAL_ID_BUF];
  guint8 salt[WYL_SERVICE_CREDENTIAL_SALT_BYTES];
  guint8 verifier[WYL_SERVICE_CREDENTIAL_VERIFIER_BYTES];
} wyl_service_credential_material_t;

typedef struct wyl_service_credential_runtime_t
{
  gpointer (*secure_alloc) (gpointer data, gsize size);
  int (*secure_lock) (gpointer data, gpointer ptr, gsize size);
  void (*secure_wipe) (gpointer data, gpointer ptr, gsize size);
  int (*secure_unlock) (gpointer data, gpointer ptr, gsize size);
  void (*secure_free) (gpointer data, gpointer ptr);
    wyrelog_error_t (*new_id) (gpointer data,
      gchar out_id[WYL_SERVICE_CREDENTIAL_ID_BUF]);
  int (*fill_random) (gpointer data, guint8 * out, gsize len);
  gpointer data;
} wyl_service_credential_runtime_t;

wyrelog_error_t wyl_service_credential_id_new (gchar * out, gsize out_len);
gboolean wyl_service_credential_id_is_canonical (const gchar * id,
    gsize id_len);

const gchar *wyl_service_credential_secret_peek_encoded (const
    wyl_service_credential_secret_t * secret, gsize * out_len);
void wyl_service_credential_secret_clear (wyl_service_credential_secret_t **
    secret);
wyrelog_error_t wyl_service_credential_secret_parse (guint32 format_version,
    const gchar * text, gsize text_len,
    wyl_service_credential_secret_t ** out_secret);
wyrelog_error_t wyl_service_credential_secret_parse_with_runtime (guint32
    format_version, const gchar * text, gsize text_len,
    const wyl_service_credential_runtime_t * runtime,
    wyl_service_credential_secret_t ** out_secret);

void wyl_service_credential_material_clear (wyl_service_credential_material_t *
    material);

wyrelog_error_t wyl_service_credential_verifier_compute (guint32
    verifier_version, const guint8 * cvk, gsize cvk_len, const gchar * id,
    gsize id_len, const gchar * tenant, gsize tenant_len, const gchar * subject,
    gsize subject_len, const guint8 * salt, gsize salt_len,
    const wyl_service_credential_secret_t * secret, guint8 * out,
    gsize out_len);

wyrelog_error_t wyl_service_credential_generate (const guint8 * cvk,
    gsize cvk_len, const gchar * tenant, gsize tenant_len,
    const gchar * subject, gsize subject_len,
    wyl_service_credential_material_t * out_material,
    wyl_service_credential_secret_t ** out_secret);
wyrelog_error_t wyl_service_credential_generate_with_runtime (const guint8 *
    cvk, gsize cvk_len, const gchar * tenant, gsize tenant_len,
    const gchar * subject, gsize subject_len,
    const wyl_service_credential_runtime_t * runtime,
    wyl_service_credential_material_t * out_material,
    wyl_service_credential_secret_t ** out_secret);

wyrelog_error_t wyl_service_credential_verify (guint32 format_version,
    guint32 verifier_version, const guint8 * cvk, gsize cvk_len,
    const gchar * id, gsize id_len, const gchar * tenant, gsize tenant_len,
    const gchar * subject, gsize subject_len, const guint8 * salt,
    gsize salt_len, const guint8 * expected, gsize expected_len,
    const gchar * presented_secret, gsize presented_secret_len,
    gboolean * out_match);
wyrelog_error_t wyl_service_credential_verify_with_runtime (guint32
    format_version, guint32 verifier_version, const guint8 * cvk, gsize cvk_len,
    const gchar * id, gsize id_len, const gchar * tenant, gsize tenant_len,
    const gchar * subject, gsize subject_len, const guint8 * salt,
    gsize salt_len, const guint8 * expected, gsize expected_len,
    const gchar * presented_secret, gsize presented_secret_len,
    const wyl_service_credential_runtime_t * runtime, gboolean * out_match);

G_END_DECLS;
