/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyctl-publication-private.h"

G_BEGIN_DECLS;

typedef enum
{
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_DEFAULT = 0,
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_MISMATCH,
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_FAILURE,
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_REPARSE,
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_NON_PRIVATE,
  WYCTL_PUBLICATION_WINDOWS_TEST_OBSERVE_SECURITY_FAILURE,
} WyctlPublicationWindowsTestObservation;

typedef WyctlPublicationWindowsTestObservation
(*WyctlPublicationWindowsTestObservationHook) (gpointer data);

typedef struct
{
  gchar *root_dir;
  gchar *canonical_root_dir;
  gchar *root_identity;
  gpointer root_handle;
  WyctlPublicationStageExactHook stage_exact_hook;
  gpointer stage_exact_hook_data;
  WyctlPublicationWindowsTestObservationHook root_observation_hook;
  gpointer root_observation_hook_data;
} WyctlPublicationWindowsBackend;

wyrelog_error_t wyctl_publication_windows_backend_init
  (WyctlPublicationWindowsBackend * backend, const gchar * root_dir);
void wyctl_publication_windows_backend_clear
  (WyctlPublicationWindowsBackend * backend);
void wyctl_publication_windows_backend_set_stage_exact_hook
  (WyctlPublicationWindowsBackend * backend,
    WyctlPublicationStageExactHook hook, gpointer data);

wyrelog_error_t wyctl_publication_windows_plan
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * request, WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_windows_root_identity
  (const WyctlPublicationWindowsBackend * backend, gchar ** out_identity);
wyrelog_error_t wyctl_publication_windows_prepare
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, WyctlPublicationReceipt * out_receipt);
wyrelog_error_t wyctl_publication_windows_stage_exact
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const gchar * credential_id,
    const WyctlSensitiveText * credential_secret,
    WyctlPublicationReceipt * out_receipt,
    WyctlPublicationResult * out_result, gboolean * out_replayed);
wyrelog_error_t wyctl_publication_windows_receipt_target_acquire
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan,
    const WyctlPublicationReceipt * receipt, gboolean require_destination,
    WyctlPublicationReceiptTargetLease ** out_lease,
    WyctlPublicationReceiptTargetKind * out_kind);
wyrelog_error_t wyctl_publication_windows_receipt_target_inspect
  (const WyctlPublicationWindowsBackend * backend,
    WyctlPublicationReceiptTargetLease * lease,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_windows_receipt_target_commit
  (const WyctlPublicationWindowsBackend * backend,
    WyctlPublicationReceiptTargetLease * lease,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
void wyctl_publication_windows_receipt_target_release
  (const WyctlPublicationWindowsBackend * backend,
    WyctlPublicationReceiptTargetLease * lease);
wyrelog_error_t wyctl_publication_windows_commit
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_windows_inspect
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_windows_resync
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_windows_cleanup
  (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret,
    WyctlPublicationResult * out_result);

#ifdef WYL_TEST_WYCTL_PUBLICATION_WINDOWS
void wyctl_publication_windows_backend_set_test_observation_hook
  (WyctlPublicationWindowsBackend * backend,
    WyctlPublicationWindowsTestObservationHook hook, gpointer data);
gboolean wyctl_publication_windows_test_security_descriptor_is_owner_only
  (const gchar * sddl);
gchar *wyctl_publication_windows_test_creation_security_descriptor_sddl (void);
#endif

G_END_DECLS
