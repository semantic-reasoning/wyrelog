/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

#define WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_BYTES (1024u * 1024u)
#define WYL_SERVICE_PERMISSION_MANIFEST_V1_MAX_OPERATIONS 4096u

typedef struct
{
  guint version;
  gchar *request_id;
  guint64 store_generation;
  guint8 store_digest[32];
  GPtrArray *operations;
} WylServicePermissionManifest;

void wyl_service_permission_manifest_clear
    (WylServicePermissionManifest * manifest);
wyrelog_error_t wyl_service_permission_manifest_from_analysis
    (const WylPolicyPermissionClosureAnalysis * analysis,
    const gchar * request_id, WylServicePermissionManifest * out_manifest);
wyrelog_error_t wyl_service_permission_manifest_encode
    (const WylServicePermissionManifest * manifest, gchar ** out_document,
    gsize * out_len);
wyrelog_error_t wyl_service_permission_manifest_decode
    (const gchar * document, gsize len,
    WylServicePermissionManifest * out_manifest);
wyrelog_error_t wyl_service_permission_manifest_matches_analysis
    (const WylServicePermissionManifest * manifest,
    const WylPolicyPermissionClosureAnalysis * analysis);
wyrelog_error_t wyl_service_permission_manifest_write_new_owner_only
    (const gchar * path, const WylServicePermissionManifest * manifest);
wyrelog_error_t wyl_service_permission_maintenance_dry_run
    (wyl_policy_store_t * store, const WylServicePermissionManifest * manifest);

G_END_DECLS;
