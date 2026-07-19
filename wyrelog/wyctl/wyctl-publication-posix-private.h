/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyctl-publication-private.h"

G_BEGIN_DECLS;

typedef enum
{
  WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_FILE = 1,
  WYCTL_PUBLICATION_RECEIPT_TARGET_SYNC_DIRECTORY,
} WyctlPublicationReceiptTargetSyncPoint;

typedef wyrelog_error_t (*WyctlPublicationReceiptTargetSyncHook) (gpointer data,
    WyctlPublicationReceiptTargetSyncPoint point);

typedef struct
{
  gchar *root_dir;
  WyctlPublicationStageExactHook stage_exact_hook;
  gpointer stage_exact_hook_data;
  WyctlPublicationReceiptTargetSyncHook receipt_target_sync_hook;
  gpointer receipt_target_sync_hook_data;
} WyctlPublicationPosixBackend;

void wyctl_publication_posix_backend_init
    (WyctlPublicationPosixBackend * backend, const gchar * root_dir);
void wyctl_publication_posix_backend_clear
    (WyctlPublicationPosixBackend * backend);
void wyctl_publication_posix_backend_set_stage_exact_hook
    (WyctlPublicationPosixBackend * backend,
    WyctlPublicationStageExactHook hook, gpointer data);
void wyctl_publication_posix_backend_set_receipt_target_sync_hook
    (WyctlPublicationPosixBackend * backend,
    WyctlPublicationReceiptTargetSyncHook hook, gpointer data);

wyrelog_error_t wyctl_publication_posix_plan
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * request, WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_posix_prepare
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, WyctlPublicationReceipt * out_receipt);
wyrelog_error_t wyctl_publication_posix_stage_exact
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const gchar * credential_id,
    const WyctlSensitiveText * credential_secret,
    WyctlPublicationReceipt * out_receipt,
    WyctlPublicationResult * out_result, gboolean * out_replayed);
wyrelog_error_t wyctl_publication_posix_receipt_target_acquire
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan,
    const WyctlPublicationReceipt * receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease ** out_lease,
    WyctlPublicationReceiptTargetKind * out_kind);
wyrelog_error_t wyctl_publication_posix_receipt_target_inspect
    (const WyctlPublicationPosixBackend * backend,
    WyctlPublicationReceiptTargetLease * lease,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_receipt_target_commit
    (const WyctlPublicationPosixBackend * backend,
    WyctlPublicationReceiptTargetLease * lease,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
void wyctl_publication_posix_receipt_target_release
    (const WyctlPublicationPosixBackend * backend,
    WyctlPublicationReceiptTargetLease * lease);
wyrelog_error_t wyctl_publication_posix_commit
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_inspect
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_resync
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_cleanup
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);

G_END_DECLS;
