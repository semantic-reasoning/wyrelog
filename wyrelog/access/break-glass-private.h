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

G_END_DECLS;
