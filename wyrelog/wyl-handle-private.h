/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/handle.h"
#include "wyrelog/engine.h"

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

/*
 * Opens the handle-owned policy engine pair from @template_dir.
 * Rejected if the pair is already present. On failure the handle is left
 * without policy engines.
 */
wyrelog_error_t wyl_handle_open_engine_pair (WylHandle * self,
    const gchar * template_dir);

/*
 * Interns @symbol into both handle-owned policy engines and returns the shared
 * integer id. Rejected unless the engine pair is already open.
 */
wyrelog_error_t wyl_handle_intern_engine_symbol (WylHandle * self,
    const gchar * symbol, gint64 * out_id);

/*
 * Applies an EDB row update to both handle-owned policy engines. Rejected
 * unless the engine pair is already open. This helper is not transactional
 * across the two engines; callers must treat a non-OK return as terminal for
 * the pair.
 */
wyrelog_error_t wyl_handle_engine_insert (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);
wyrelog_error_t wyl_handle_engine_remove (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols);

/*
 * Probes the read engine for an exact EDB/IDB row match. Rejected unless the
 * engine pair is already open.
 */
wyrelog_error_t wyl_handle_engine_contains (WylHandle * self,
    const gchar * relation, const gint64 * row, gsize ncols,
    gboolean * out_contains);

/*
 * Reads allow_bool/3 from the handle-owned read engine for @row
 * (user, permission, scope). Rejected unless the engine pair is already open.
 */
wyrelog_error_t wyl_handle_engine_decide (WylHandle * self,
    const gint64 row[3], gboolean * out_allowed);

/*
 * Borrowed policy engine sessions owned by |self|. These are NULL when
 * no policy engine pair has been opened. The read engine is reserved for
 * snapshot-style reads; the delta engine is reserved for step/delta
 * processing.
 */
WylEngine *wyl_handle_get_read_engine (WylHandle * self);
WylEngine *wyl_handle_get_delta_engine (WylHandle * self);

G_END_DECLS;
