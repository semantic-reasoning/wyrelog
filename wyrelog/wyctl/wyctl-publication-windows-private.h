/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyctl-publication-private.h"

G_BEGIN_DECLS;

typedef struct
{
  gchar *root_dir;
} WyctlPublicationWindowsBackend;

void wyctl_publication_windows_backend_init
    (WyctlPublicationWindowsBackend * backend, const gchar * root_dir);
void wyctl_publication_windows_backend_clear
    (WyctlPublicationWindowsBackend * backend);

wyrelog_error_t wyctl_publication_windows_plan
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * request, WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_windows_prepare
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, WyctlPublicationReceipt * out_receipt);
wyrelog_error_t wyctl_publication_windows_stage_exact
    (const WyctlPublicationWindowsBackend * backend,
    const WyctlPublicationPlan * plan, const gchar * credential_id,
    const WyctlSensitiveText * credential_secret,
    WyctlPublicationReceipt * out_receipt,
    WyctlPublicationResult * out_result, gboolean * out_replayed);
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
gboolean wyctl_publication_windows_test_security_descriptor_is_owner_only
    (const gchar * sddl);
#endif

G_END_DECLS
