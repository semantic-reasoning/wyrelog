/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "fact/graph-locator-private.h"
#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef struct _WylFactRootWriterLease WylFactRootWriterLease;

typedef struct
{
  WylFactRootWriterLease *lease;
  WylFactRootWriterLease *previous;
  gboolean active;
} WylFactRootWriterLeaseBorrowScope;

/*
 * Acquires the one process-wide writer authority for a verified fact root.
 * The lease is non-blocking and remains owned until release.  A live owner is
 * reported as WYRELOG_E_BUSY; malformed or replaced authority is a policy
 * error.  No caller-visible path is retained for diagnostics.
 */
wyrelog_error_t wyl_fact_root_writer_lease_acquire (const gchar * fact_root,
    WylFactRootWriterLease ** out_lease);

/* Allows nested operations on the current request thread to borrow an
 * already-held handle lease for the same root. The borrow is thread-scoped;
 * unrelated callers still fail the process-wide writer exclusion check. */
wyrelog_error_t wyl_fact_root_writer_lease_borrow_scope_begin
  (WylFactRootWriterLease * lease,
    WylFactRootWriterLeaseBorrowScope * scope);
void wyl_fact_root_writer_lease_borrow_scope_end
  (WylFactRootWriterLeaseBorrowScope * scope);

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
