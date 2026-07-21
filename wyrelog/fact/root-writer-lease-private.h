/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-locator-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct _WylFactRootWriterLease WylFactRootWriterLease;

/*
 * Acquires the one process-wide writer authority for a verified fact root.
 * The lease is non-blocking and remains owned until release.  A live owner is
 * reported as WYRELOG_E_BUSY; malformed or replaced authority is a policy
 * error.  No caller-visible path is retained for diagnostics.
 */
wyrelog_error_t wyl_fact_root_writer_lease_acquire (const gchar * fact_root,
    WylFactRootWriterLease ** out_lease);

/* Revalidates the pinned root and the native lease authority. */
wyrelog_error_t wyl_fact_root_writer_lease_verify
    (WylFactRootWriterLease * lease);

/*
 * Proves that a separately opened secure resolver names the exact root
 * covered by the lease.  This is the contract used by future maintenance
 * entry points before accepting a caller-supplied resolver.
 */
wyrelog_error_t wyl_fact_root_writer_lease_authorizes_resolver
    (WylFactRootWriterLease * lease, WylFactGraphResolver * resolver);

void wyl_fact_root_writer_lease_release (WylFactRootWriterLease * lease);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylFactRootWriterLease,
    wyl_fact_root_writer_lease_release);

G_END_DECLS;
