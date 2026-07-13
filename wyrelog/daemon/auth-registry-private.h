/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_SERVICE_AUTH_PENDING = 0,
  WYL_SERVICE_AUTH_ACTIVE,
  WYL_SERVICE_AUTH_REVOKED,
} WylServiceAuthState;

typedef gpointer (*WylServiceAuthTryAllocFunc) (gsize size, gpointer user_data);
typedef void (*WylServiceAuthFreeFunc) (gpointer memory, gpointer user_data);

/*
 * Value supplied to reserve/transition calls and returned by lookup.
 * Registry entries are immutable deep copies: generation is a credential
 * generation snapshot, not a mutable registry revision.  A successful lookup
 * returns another deep copy that the caller releases with
 * wyl_service_auth_reservation_clear().
 *
 * A lookup output must be zero-initialised on first use.  It may then be
 * passed to lookup repeatedly: lookup releases its previous owned snapshot
 * after consuming query IDs, so session_id/jti may alias that snapshot.
 * Calling clear between uses is also valid.  Every failed/not-found lookup
 * leaves the reservation cleared, state PENDING, and found FALSE.
 * A default-allocator snapshot may outlive its registry.  With the test
 * allocator, callback state must additionally outlive every snapshot.
 */
typedef struct
{
  gchar *session_id;
  gchar *jti;
  gchar *credential_id;
  guint64 generation;
  gchar *principal;
  gchar *tenant;
  WylServiceAuthFreeFunc _free;
  gpointer _free_data;
} WylServiceAuthReservation;

typedef struct
{
  /* Callback state must outlive the registry and snapshots it allocated. */
  WylServiceAuthTryAllocFunc try_alloc;
  WylServiceAuthFreeFunc free;
  gpointer user_data;
} WylServiceAuthAllocator;

typedef struct _WylServiceAuthRegistry WylServiceAuthRegistry;

/*
 * Concurrency and ownership contract
 * ----------------------------------
 * One internal mutex protects both indexes and every state transition.
 * by_session is the sole container owner of entries and by_jti is a borrowed,
 * unique reverse index.  Allocator callbacks are never invoked while the
 * mutex is held.  A caller must hold a registry reference for the full
 * duration of every operation; final unref requires all operations to have
 * quiesced and is not itself a concurrency barrier.
 *
 * clear linearises by swapping both indexes under the mutex, then releases the
 * old borrowed index before the old owning index.  Operations therefore
 * observe either side of that swap, but clear is not a caller/thread lifetime
 * barrier and does not replace the final-unref quiescence requirement.
 *
 * reserve validates and allocates an entire immutable entry before mutation.
 * A duplicate session or jti returns WYRELOG_E_POLICY.  activate accepts only
 * an exact PENDING pair.  revoke_exact accepts exact PENDING or ACTIVE pairs
 * and is idempotent for REVOKED.  Exact transitions return
 * WYRELOG_E_NOT_FOUND only when both identifiers are absent; crossed IDs or
 * any other DTO mismatch return WYRELOG_E_POLICY.  remove_exact accepts all
 * states, returns OK/false when both identifiers are absent, and POLICY for a
 * crossed or mismatched pair.  Malformed input returns WYRELOG_E_INVALID.
 *
 * Entry preflight and lookup snapshots use the registry allocator and report
 * WYRELOG_E_NOMEM without partial mutation/output.  GLib hash-table internal
 * allocation is process-fatal on OOM and is outside this recoverable contract.
 */

wyrelog_error_t wyl_service_auth_registry_new
    (WylServiceAuthRegistry ** out_registry);
#ifdef WYL_AUTH_REGISTRY_TESTING
wyrelog_error_t wyl_service_auth_registry_new_with_allocator
    (const WylServiceAuthAllocator * allocator,
    WylServiceAuthRegistry ** out_registry);
#endif
WylServiceAuthRegistry *wyl_service_auth_registry_ref
    (WylServiceAuthRegistry * registry);
void wyl_service_auth_registry_unref (WylServiceAuthRegistry * registry);
void wyl_service_auth_registry_clear (WylServiceAuthRegistry * registry);

wyrelog_error_t wyl_service_auth_registry_reserve
    (WylServiceAuthRegistry * registry,
    const WylServiceAuthReservation * reservation);
wyrelog_error_t wyl_service_auth_registry_activate
    (WylServiceAuthRegistry * registry,
    const WylServiceAuthReservation * reservation, gboolean * out_changed);
wyrelog_error_t wyl_service_auth_registry_revoke_exact
    (WylServiceAuthRegistry * registry,
    const WylServiceAuthReservation * reservation, gboolean * out_changed);
wyrelog_error_t wyl_service_auth_registry_remove_exact
    (WylServiceAuthRegistry * registry,
    const WylServiceAuthReservation * reservation, gboolean * out_removed);

wyrelog_error_t wyl_service_auth_registry_lookup
    (WylServiceAuthRegistry * registry, const gchar * session_id,
    const gchar * jti, WylServiceAuthReservation * out_reservation,
    WylServiceAuthState * out_state, gboolean * out_found);
void wyl_service_auth_reservation_clear
    (WylServiceAuthReservation * reservation);

/* Test-only observations.  They never expose or mutate stored entries. */
#ifdef WYL_AUTH_REGISTRY_TESTING
gboolean wyl_service_auth_registry_check_invariants_for_test
    (WylServiceAuthRegistry * registry);
gsize wyl_service_auth_registry_size_for_test
    (WylServiceAuthRegistry * registry);
#endif

G_END_DECLS;
