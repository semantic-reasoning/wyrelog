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
wyrelog_error_t wyl_service_permission_manifest_read_owner_only
    (const gchar * path, WylServicePermissionManifest * out_manifest);

/*
 * Canonical v1 JSON encoding of a durable remediation-apply receipt. A given
 * receipt encodes byte-for-byte identically on every call, so a replayed apply
 * (which returns the frozen receipt verbatim) serialises to the same document
 * as its original apply. Returns WYRELOG_E_INVALID for a receipt missing a
 * required field. On success *out_document is a NUL-terminated heap string of
 * *out_len bytes the caller frees with g_free.
 */
wyrelog_error_t wyl_service_permission_receipt_encode
    (const wyl_policy_service_permission_receipt_t * receipt,
    gchar ** out_document, gsize * out_len);

/*
 * Encode |receipt| and write it to |path| as a brand-new owner-only regular
 * file (O_CREAT | O_EXCL | O_NOFOLLOW, mode 0600) under an owner-only parent
 * directory, fail-closed on symlink/hardlink/pre-existing target. Never
 * overwrites: an existing |path| is WYRELOG_E_POLICY. This is the offline
 * apply's durable receipt sink; owner-only file access is the authz boundary.
 */
wyrelog_error_t wyl_service_permission_receipt_write_new_owner_only
    (const gchar * path,
    const wyl_policy_service_permission_receipt_t * receipt);

/*
 * Offline dry-run of a canonical removal manifest. Adopts a bare maintenance
 * handle over |store|, opens a maintenance-exclusive #371 authority
 * transaction, verifies the manifest's pre-state (store_generation +
 * store_digest) against a fresh authority snapshot (rejecting a stale manifest
 * before any mutation), applies the manifest removals inside the transaction,
 * re-analyzes and asserts the resulting service permission closure is clean,
 * then ALWAYS rolls back. No receipt is written and no durable state changes.
 * Returns WYRELOG_E_OK when the manifest is valid and would fully clean the
 * closure, a typed error otherwise. Consumes |store| on every outcome.
 */
wyrelog_error_t wyl_service_permission_maintenance_dry_run
    (wyl_policy_store_t * store, const WylServicePermissionManifest * manifest);

/*
 * Offline apply of a canonical removal manifest. Adopts a bare maintenance
 * handle over |store| and drives a maintenance-exclusive #371 write
 * transaction: idempotent replay by request_id (identical fingerprint replays
 * the frozen receipt and applies nothing; a different fingerprint under the
 * same request_id is a WYRELOG_E_POLICY conflict), pre-state verification
 * (stale manifest rejected before mutation), removal-only application, an
 * immutable remediation receipt bound to the pre/post generation+digest, and
 * commit at the #614 closure-validation choke point (a manifest that fails to
 * fully clean the closure rolls the whole transaction back with no receipt).
 * On success |out_receipt| owns freshly duplicated strings the caller releases
 * with wyl_policy_service_permission_receipt_clear. Consumes |store| on every
 * outcome. The durable write happens via persist-on-close by the caller.
 */
wyrelog_error_t wyl_service_permission_maintenance_apply
    (wyl_policy_store_t * store, const WylServicePermissionManifest * manifest,
    wyl_policy_service_permission_receipt_t * out_receipt);

G_END_DECLS;
