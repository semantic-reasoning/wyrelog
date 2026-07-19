/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

G_BEGIN_DECLS;

#define WYL_SERVICE_CREDENTIAL_OPERATION_DESTINATION_MAX_BYTES 255u

/* Credential publication is intentionally restricted to one portable leaf
 * name.  Every durable admission, codec, and publication boundary must use
 * this predicate so an accepted operation cannot fail later on a stricter
 * platform path rule. */
gboolean wyl_service_credential_operation_destination_is_valid
    (const gchar * destination);

G_END_DECLS;
