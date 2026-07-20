/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include "auth/service-credential-operation-journal-private.h"

G_BEGIN_DECLS
/* Frozen publication-target identity shared by execution, maintenance, and
 * authenticated cancellation. */
    G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_handoff_target_digest
    (const WylServiceCredentialOperationRecord * record,
    guint8
    out_digest[WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES]);

G_END_DECLS
