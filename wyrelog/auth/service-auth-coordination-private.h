/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS typedef struct _WylServiceAuthAuthority WylServiceAuthAuthority;
typedef struct _WylServiceAuthReadLease WylServiceAuthReadLease;
typedef struct _WylServiceAuthWriteLease WylServiceAuthWriteLease;

typedef struct
{
  guint active_readers;
  guint waiting_writers;
  gboolean writer_active;
  gboolean closing;
} WylServiceAuthAuthoritySnapshot;

WylServiceAuthAuthority *wyl_service_auth_authority_new (WylHandle * handle);
WylServiceAuthAuthority *wyl_service_auth_authority_ref
    (WylServiceAuthAuthority * authority);
void wyl_service_auth_authority_unref (WylServiceAuthAuthority * authority);

/*
 * Stops new acquisition, wakes queued callers and waits for live leases to
 * drain. Calling close from a thread that owns a lease returns BUSY without
 * changing the authority state, rather than waiting on itself.
 */
wyrelog_error_t wyl_service_auth_authority_close
    (WylServiceAuthAuthority * authority);

wyrelog_error_t wyl_service_auth_authority_acquire_read
    (WylServiceAuthAuthority * authority, GCancellable * cancellable,
    WylServiceAuthReadLease ** out_lease);
wyrelog_error_t wyl_service_auth_authority_acquire_write
    (WylServiceAuthAuthority * authority, GCancellable * cancellable,
    WylServiceAuthWriteLease ** out_lease);

wyrelog_error_t wyl_service_auth_read_lease_validate
    (WylServiceAuthReadLease * lease, WylHandle * handle);
wyrelog_error_t wyl_service_auth_write_lease_validate
    (WylServiceAuthWriteLease * lease, WylHandle * handle);
wyrelog_error_t wyl_service_auth_read_lease_release
    (WylServiceAuthReadLease * lease);
wyrelog_error_t wyl_service_auth_write_lease_release
    (WylServiceAuthWriteLease * lease);
void wyl_service_auth_read_lease_free (WylServiceAuthReadLease * lease);
void wyl_service_auth_write_lease_free (WylServiceAuthWriteLease * lease);

/* Private deterministic observation: no mutex or condition is exposed. */
void wyl_service_auth_authority_snapshot
    (WylServiceAuthAuthority * authority,
    WylServiceAuthAuthoritySnapshot * out_snapshot);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthAuthority,
    wyl_service_auth_authority_unref)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthReadLease,
    wyl_service_auth_read_lease_free)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthWriteLease,
    wyl_service_auth_write_lease_free)
    G_END_DECLS
