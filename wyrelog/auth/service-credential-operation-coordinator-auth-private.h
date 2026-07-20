/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "auth/service-credential-domain-private.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS
/* Load one credential while a pinned service-auth READ lease proves the
 * handle and policy-store identity cannot change underneath the lookup.
 * Shared by execution and authenticated cancellation tenant binding. */
    G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_credential_operation_coordinator_get_credential_pinned
    (WylHandle * handle, GCancellable * cancellable,
    const gchar * credential_id, wyl_service_credential_t * out);

G_END_DECLS
