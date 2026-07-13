/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>

#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS typedef struct _WylServiceAuthAuthority WylServiceAuthAuthority;
typedef struct _WylServiceAuthReadLease WylServiceAuthReadLease;
typedef struct _WylServiceAuthWriteLease WylServiceAuthWriteLease;

typedef enum
{
  WYL_SERVICE_AUTH_RANK_COORDINATION = 1,
  WYL_SERVICE_AUTH_RANK_STORE = 2,
  WYL_SERVICE_AUTH_RANK_CONTEXT = 3,
  WYL_SERVICE_AUTH_RANK_REGISTRY = 4,
} WylServiceAuthRank;

typedef struct
{
  guint active_readers;
  guint waiting_readers;
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
    (WylServiceAuthAuthority * authority, WylHandle * handle,
    GCancellable * cancellable, WylServiceAuthReadLease ** out_lease);
wyrelog_error_t wyl_service_auth_authority_acquire_write
    (WylServiceAuthAuthority * authority, WylHandle * handle,
    GCancellable * cancellable, WylServiceAuthWriteLease ** out_lease);

/* Inner lock owners mark and unmark their rank around the real lock scope. */
wyrelog_error_t wyl_service_auth_rank_enter (WylHandle * handle,
    WylServiceAuthRank rank);
wyrelog_error_t wyl_service_auth_rank_leave (WylHandle * handle,
    WylServiceAuthRank rank);

wyrelog_error_t wyl_service_auth_read_lease_validate
    (WylServiceAuthReadLease * lease, WylHandle * handle);
wyrelog_error_t wyl_service_auth_write_lease_validate
    (WylServiceAuthWriteLease * lease, WylHandle * handle);
/*
 * A store authority transaction claims a live WRITE lease for its complete
 * lifetime. These helpers are private to that transaction implementation.
 * A claimed lease remains valid, but cannot be released or claimed again.
 */
wyrelog_error_t wyl_service_auth_write_lease_claim_transaction
    (WylServiceAuthWriteLease * lease, WylHandle * handle);
wyrelog_error_t wyl_service_auth_write_lease_unclaim_transaction
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

/* Private deterministic fault seams for serial-validation tests. */
void wyl_service_auth_read_lease_test_corrupt_serial
    (WylServiceAuthReadLease * lease);
void wyl_service_auth_write_lease_test_corrupt_serial
    (WylServiceAuthWriteLease * lease);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthAuthority,
    wyl_service_auth_authority_unref)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthReadLease,
    wyl_service_auth_read_lease_free)
    G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthWriteLease,
    wyl_service_auth_write_lease_free)
    G_END_DECLS
