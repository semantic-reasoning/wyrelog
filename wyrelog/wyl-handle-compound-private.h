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

G_END_DECLS;
