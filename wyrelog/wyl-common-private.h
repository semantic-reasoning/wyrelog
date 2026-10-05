/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyl-log-private.h"

/*
 * Single source of truth for the wyrelog default tenant identifier.
 *
 * The default tenant is seeded into every policy store and remains the
 * compatibility tenant for deployments that do not create additional
 * tenant rows. Callers that mint, validate, or compare the default
 * tenant string MUST use this constant rather than re-typing the
 * literal.
 *
 * Wire format note: this string also appears in JWT claim bodies, in
 * HTTP request query parameters (?tenant=...), and in client-side
 * comparisons. Changing the value is an ABI / wire-compat break.
 */
#define WYL_TENANT_DEFAULT "__wr_default"

/* The reserved owner of built-in tenants (#1338).  Every tenant records an
 * owner; a built-in tenant is owned by the system, never by a person, and
 * no subject may claim the reserved "wr." namespace.  The value is durable
 * in the tenants table, so changing it is a store-compat break. */
#define WYL_TENANT_SYSTEM_OWNER "wr.system"
