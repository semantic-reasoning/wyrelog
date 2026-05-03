/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/handle.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"
#endif

G_BEGIN_DECLS;

#ifdef WYL_HAS_AUDIT
/*
 * Returns the borrowed audit connection owned by |self|. Lifetime
 * is tied to the WylHandle: the pointer is valid until wyl_shutdown
 * or g_object_unref. Available only when libwyrelog is built with
 * the audit feature option allowed; the function does not exist in
 * non-audit builds (and neither does the underlying type).
 */
wyl_audit_conn_t *wyl_handle_get_audit_conn (WylHandle * self);
#endif

G_END_DECLS;
