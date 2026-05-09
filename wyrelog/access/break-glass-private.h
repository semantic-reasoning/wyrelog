/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/break-glass.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * The closed reason-code enumeration lives in the public header
 * wyrelog/break-glass.h so callers and audit consumers see one
 * authoritative vocabulary. This private header pulls it in for
 * library-internal helpers and adds the host-only ceilings and
 * lookup helpers the public surface does not need to expose.
 */

/*
 * Returns a stable, never-NULL human-readable name for |code|, or
 * "unknown" when |code| is out of range. The string lives in static
 * storage and must not be freed.
 */
const gchar *wyl_break_glass_reason_name (wyl_break_glass_reason_code_t code);

/*
 * Inverse of wyl_break_glass_reason_name: maps a stable name to its
 * enumerator. Returns WYRELOG_E_OK and writes the resolved code on
 * success, or WYRELOG_E_NOT_FOUND when |name| does not match any
 * known reason. NULL or empty |name| returns WYRELOG_E_INVALID.
 */
wyrelog_error_t wyl_break_glass_reason_from_name (const gchar * name,
    wyl_break_glass_reason_code_t * out_code);

/*
 * Compile-time ceiling on the per-arming TTL. Mirrors the
 * ttl("break_glass", 900) row in templates/access/bootstrap.dl so
 * the host-side TTL gate cannot exceed the DL self-disable horizon
 * that templates/access/bootstrap.dl:223-227 enforces.
 */
#define WYL_BREAK_GLASS_DEFAULT_TTL_SECONDS 900

#ifdef WYL_HAS_BREAK_GLASS

/*
 * Forward declaration so the helpers below can name WylHandle
 * without forcing every include path through handle-private.h.
 */
typedef struct _WylHandle WylHandle;

/*
 * Returns the operator-supplied reason code for the current
 * activation. |out_reason| is written only when the handle is in
 * an active break-glass window; on a NULL handle, an inactive
 * handle, or an expired activation the call returns
 * WYRELOG_E_INVALID and |*out_reason| is left untouched.
 */
wyrelog_error_t wyl_handle_break_glass_get_reason (WylHandle * handle,
    wyl_break_glass_reason_code_t * out_reason);

/*
 * Returns the wall-clock microsecond timestamp at which the
 * current activation was registered. NULL or inactive handle
 * returns WYRELOG_E_INVALID and leaves |*out_activated_at_us|
 * untouched.
 */
wyrelog_error_t wyl_handle_break_glass_get_activated_at_us (WylHandle * handle,
    gint64 * out_activated_at_us);

/*
 * Records that the active break-glass window has been observed by
 * a decide call so subsequent decides inject break_glass_used/1
 * for the DL self-disable rule. Idempotent; further calls after
 * the first do not advance the timestamp. Safe to call when the
 * handle is inactive: the call becomes a no-op.
 */
void wyl_handle_break_glass_mark_used (WylHandle * handle);

/*
 * Returns TRUE iff the handle has observed a break-glass-arm
 * decide at least once since the last disarm. Used by the decide
 * path to decide whether to inject break_glass_used/1 into the
 * engine.
 */
gboolean wyl_handle_break_glass_has_been_used (WylHandle * handle);

#endif

G_END_DECLS;
