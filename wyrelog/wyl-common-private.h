/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-log-private.h"

/*
 * Single source of truth for the wyrelog v0 default tenant identifier.
 *
 * The v0 single-tenant contract (issue #273) keeps wyrelog deliberately
 * single-tenant: every authenticated principal is bound to this tenant
 * and the daemon's tenant gate accepts no other value. Callers that
 * mint, validate, or compare tenant strings MUST use this constant
 * rather than re-typing the literal so that any future widening of the
 * contract changes a single point.
 *
 * Wire format note: this string also appears in JWT claim bodies, in
 * HTTP request query parameters (?tenant=...), and in client-side
 * comparisons. Changing the value is an ABI / wire-compat break.
 */
#define WYL_TENANT_DEFAULT "__wr_default"
