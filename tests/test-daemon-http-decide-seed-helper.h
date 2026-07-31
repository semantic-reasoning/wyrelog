/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <gmodule.h>

G_BEGIN_DECLS;

/* Scalar/string-only boundary: storage, anchors, records, locks, and native
 * handles are created and destroyed entirely inside the helper DSO. */
G_MODULE_EXPORT gint wyl_test_daemon_http_seed_prepared_operation
    (const gchar * operation_root, const gchar * request_id, guint32 kind,
    const gchar * subject_id, const gchar * tenant_id,
    const gchar * old_credential_id);

G_END_DECLS;
