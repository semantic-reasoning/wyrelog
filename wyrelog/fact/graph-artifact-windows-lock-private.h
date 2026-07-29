/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "fact/graph-locator-private.h"

#ifdef G_OS_WIN32
#include <windows.h>

G_BEGIN_DECLS
    typedef struct WylFactArtifactWinLockDomain WylFactArtifactWinLockDomain;
typedef struct WylFactArtifactWinLockLease WylFactArtifactWinLockLease;

/* Mint or join the process-wide cooperative domain for one exact graph
 * directory identity.  |lock_handle| is a native handle for the named
 * coordination file and is consumed only on success.  It is never adapted to
 * a CRT descriptor or reopened by path. */
wyrelog_error_t wyl_fact_artifact_win_lock_domain_open (const
    WylFactGraphWinIdentity * directory_identity,
    const WylFactGraphWinIdentity * lock_identity, HANDLE lock_handle,
    WylFactArtifactWinLockDomain ** out_domain);
void wyl_fact_artifact_win_lock_domain_free (WylFactArtifactWinLockDomain *
    domain);

/* The caller transfers one separately opened native lock HANDLE on success.
 * Reader leases share; mutation leases are exclusive.  All contention is
 * non-blocking and returns BUSY. */
wyrelog_error_t
wyl_fact_artifact_win_lock_domain_acquire (WylFactArtifactWinLockDomain *
    domain, HANDLE lock_handle, gboolean exclusive,
    WylFactArtifactWinLockLease ** out_lease);
wyrelog_error_t
wyl_fact_artifact_win_lock_lease_revalidate (WylFactArtifactWinLockLease *
    lease);
void wyl_fact_artifact_win_lock_lease_free (WylFactArtifactWinLockLease *
    lease);

G_END_DECLS
#endif
