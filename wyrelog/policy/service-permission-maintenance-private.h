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

typedef enum
{
  WYL_SERVICE_PERMISSION_APPLY_APPLIED,
  WYL_SERVICE_PERMISSION_APPLY_REPLAYED,
} WylServicePermissionApplyState;

typedef struct
{
  WylServicePermissionApplyState state;
  gchar *request_id;
  gchar *actor_identity;
  gchar *audit_id;
  guint operation_count;
  gint64 applied_at_us;
} WylServicePermissionApplyReceipt;

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
void wyl_service_permission_apply_receipt_clear
    (WylServicePermissionApplyReceipt * receipt);
/*
 * Always consumes store. Exact replay is resolved before requesting the
 * unsafe-only WRITE lease; an absent receipt proceeds through #371 and an
 * explicit encrypted publish.
 */
wyrelog_error_t wyl_service_permission_maintenance_apply
    (wyl_policy_store_t * store,
    const WylServicePermissionManifest * manifest,
    WylServicePermissionApplyReceipt * out_receipt);

G_END_DECLS;
