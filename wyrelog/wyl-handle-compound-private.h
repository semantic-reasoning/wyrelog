/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/handle.h"
#include "wyl-engine-private.h"

G_BEGIN_DECLS;

/*
 * Allocates the same side-tier compound term in both handle-owned policy
 * engines and returns the shared handle. Rejected unless both engines are
 * open and both evaluators return the same session-local handle id. The
 * returned id is pair-local scratch state and must not be persisted.
 */
wyrelog_error_t wyl_handle_make_engine_compound (WylHandle * self,
    const gchar * functor, const wirelog_compound_arg_t * args, gsize nargs,
    gint64 * out_id);

/*
 * Allocates a side-tier compound term only in the handle-owned read engine.
 * This is intended for request-local snapshot bridge facts that are never
 * fanned out to the delta engine.
 */
wyrelog_error_t wyl_handle_make_read_engine_compound (WylHandle * self,
    const gchar * functor, const wirelog_compound_arg_t * args, gsize nargs,
    gint64 * out_id);

/*
 * Allocates the request-local guard context compound used as the bridge key
 * for context_now/guard_context/eval_guard facts. The returned side-tier
 * handle is read-engine-local scratch state and encodes:
 *
 *   scope(metadata(timestamp, loc_class, risk), scope)
 */
wyrelog_error_t wyl_handle_make_guard_context_compound (WylHandle * self,
    gint64 timestamp, gint64 loc_class_id, gint64 risk, gint64 scope_id,
    gint64 * out_id);

G_END_DECLS;
