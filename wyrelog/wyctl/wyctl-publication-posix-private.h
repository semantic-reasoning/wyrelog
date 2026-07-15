/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyctl-publication-private.h"

G_BEGIN_DECLS;

typedef struct
{
  gchar *root_dir;
} WyctlPublicationPosixBackend;

void wyctl_publication_posix_backend_init
    (WyctlPublicationPosixBackend * backend, const gchar * root_dir);
void wyctl_publication_posix_backend_clear
    (WyctlPublicationPosixBackend * backend);

wyrelog_error_t wyctl_publication_posix_plan
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * request, WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_posix_prepare
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, WyctlPublicationReceipt * out_receipt);
wyrelog_error_t wyctl_publication_posix_commit
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_inspect
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_resync
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result);
wyrelog_error_t wyctl_publication_posix_cleanup
    (const WyctlPublicationPosixBackend * backend,
    const WyctlPublicationPlan * plan, const WyctlPublicationReceipt * receipt,
    WyctlPublicationResult * out_result);

G_END_DECLS;
