/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/error.h"
#include "wyrelog/handle.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_SERVICE_AUTH_PENDING = 0,
  WYL_SERVICE_AUTH_ACTIVE,
  WYL_SERVICE_AUTH_REVOKED,
} WylServiceAuthState;

typedef struct
{
  gsize matched;
  gsize transitioned;
} WylServiceAuthRevokeResult;

#define WYL_SERVICE_AUTH_SELECTOR_BYTES 256u
/* Hard volatile-state ceiling; admission never evicts an unexpired pair. */
#define WYL_SERVICE_AUTH_REGISTRY_MAX_ENTRIES 4096u

typedef enum
{
  WYL_SERVICE_AUTH_SELECTOR_PRINCIPAL = 1,
  WYL_SERVICE_AUTH_SELECTOR_TENANT = 2,
  WYL_SERVICE_AUTH_SELECTOR_CREDENTIAL_GENERATION = 3,
} WylServiceAuthSelectorKind;

/*
 * Allocation-free authority selector.  The bytes are an authoritative value
 * copied before commit; callers must not retain a pointer into a mutable DTO.
 */
typedef struct
{
  WylServiceAuthSelectorKind kind;
  gsize length;
  guint64 generation;
  gchar bytes[WYL_SERVICE_AUTH_SELECTOR_BYTES];
} WylServiceAuthSelector;

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
  /* Immutable service JWT/session expiry in UTC seconds. */
  gint64 expires_at;
  WylServiceAuthFreeFunc _free;
  gpointer _free_data;
} WylServiceAuthReservation;

typedef struct
{
  /*
   * Callback state must outlive the registry and snapshots it allocated.
   * Callbacks must be thread-safe when registry operations are concurrent.
   */
  WylServiceAuthTryAllocFunc try_alloc;
  WylServiceAuthFreeFunc free;
  gpointer user_data;
} WylServiceAuthAllocator;

typedef struct _WylServiceAuthRegistry WylServiceAuthRegistry;
typedef struct _WylServiceAuthRegistrySessionParticipant
    WylServiceAuthRegistrySessionParticipant;
typedef struct _WylServiceAuthRegistryMaintenanceParticipant
    WylServiceAuthRegistryMaintenanceParticipant;
typedef struct _WylHandle WylHandle;
typedef struct _WylServiceAuthWriteLease WylServiceAuthWriteLease;
typedef struct _WylServiceAuthRegistrySessionParticipant
    WylServiceAuthRegistrySessionParticipant;
typedef struct _WylServiceAuthRegistryWriteParticipant
    WylServiceAuthRegistryWriteParticipant;

/*
 * Concurrency and ownership contract
 * ----------------------------------
 * One internal mutex protects all five indexes and every state transition.
 * by_session is the sole container owner of entries; by_jti and the three
 * selector buckets borrow entries.  Allocator callbacks are never invoked
 * while the mutex is held.  A caller must hold a registry reference for the full
 * duration of every operation; final unref requires all operations to have
 * quiesced and is not itself a concurrency barrier.
 *
 * clear linearises by swapping all five indexes under the mutex, then releases
 * every borrowed index before the old owning index.  Operations therefore
 * observe either side of that swap, but clear is not a caller/thread lifetime
 * barrier and does not replace the final-unref quiescence requirement.
 *
 * reserve validates and allocates an entire immutable entry plus candidate
 * credential-generation, principal, and tenant buckets before mutation.
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
 * Indexed revocation retains entries in their buckets until physical remove,
 * returns OK with matched/transitioned counts, and is idempotent for already
 * revoked members.  An absent valid selector returns OK with both counts zero.
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

#if defined(WYL_AUTH_REGISTRY_TESTING) || defined(WYL_TEST_DAEMON_HTTP)
/* Test adapters may exercise the state machine directly. Production
 * reserve/activate/cleanup callsites use a lease-bound participant. */
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
#endif
#if defined(WYL_AUTH_REGISTRY_TESTING) || defined(WYL_TEST_DAEMON_HTTP)
wyrelog_error_t wyl_service_auth_registry_revoke_credential_generation
    (WylServiceAuthRegistry * registry, const gchar * credential_id,
    guint64 generation, WylServiceAuthRevokeResult * out_result);
wyrelog_error_t wyl_service_auth_registry_revoke_principal
    (WylServiceAuthRegistry * registry, const gchar * principal,
    WylServiceAuthRevokeResult * out_result);
wyrelog_error_t wyl_service_auth_registry_revoke_tenant
    (WylServiceAuthRegistry * registry, const gchar * tenant,
    WylServiceAuthRevokeResult * out_result);
#endif
wyrelog_error_t wyl_service_auth_selector_init_principal
    (WylServiceAuthSelector * selector, const gchar * principal);
wyrelog_error_t wyl_service_auth_selector_init_tenant
    (WylServiceAuthSelector * selector, const gchar * tenant);
wyrelog_error_t wyl_service_auth_selector_init_credential_generation
    (WylServiceAuthSelector * selector, const gchar * credential_id,
    guint64 generation);
/*
 * Performs no recoverable allocation.  Under one registry mutex it validates
 * all owning/borrowed indexes, transitions the exact indexed set, and scans
 * the authoritative owning table to prove that no matching PENDING or ACTIVE
 * entry survives.  POLICY therefore means registry invariant corruption.
 */
#if defined(WYL_AUTH_REGISTRY_TESTING) || defined(WYL_TEST_DAEMON_HTTP)
wyrelog_error_t wyl_service_auth_registry_revoke_selector_zero_survivors
    (WylServiceAuthRegistry * registry,
    const WylServiceAuthSelector * selector,
    WylServiceAuthRevokeResult * out_result);
#endif
/*
 * Lease-bound mutation capability.  Construction is a fallible preflight;
 * execution validates that the same-handle WRITE lease remains the active
 * operation owner before entering the allocation-free registry boundary.
 */
wyrelog_error_t wyl_service_auth_registry_write_participant_new
    (WylServiceAuthRegistry * registry, WylHandle * handle,
    WylServiceAuthWriteLease * lease,
    WylServiceAuthRegistryWriteParticipant ** out_participant);
void wyl_service_auth_registry_write_participant_free
    (WylServiceAuthRegistryWriteParticipant * participant);
wyrelog_error_t
    wyl_service_auth_registry_write_participant_revoke_zero_survivors
    (WylServiceAuthRegistryWriteParticipant * participant,
    const WylServiceAuthSelector * selector,
    WylServiceAuthRevokeResult * out_result);
/* Exact retained WRITE -> ENGINE counterpart used only after a committed
 * external publication transaction has been consumed. */
wyrelog_error_t
    wyl_service_auth_registry_write_participant_revoke_retained_engine
    (WylServiceAuthRegistryWriteParticipant * participant,
    wyl_policy_store_t * expected_store,
    const WylServiceAuthSelector * selector,
    WylServiceAuthRevokeResult * out_result);
/*
 * Lease-bound session mutation capability. The participant retains the
 * registry and handle but borrows the WRITE lease; its owner must keep that
 * lease alive and release it independently.
 */
wyrelog_error_t wyl_service_auth_registry_session_participant_new_for_write
    (WylServiceAuthRegistry * registry, WylHandle * handle,
    WylServiceAuthWriteLease * lease,
    WylServiceAuthRegistrySessionParticipant ** out_participant);
void wyl_service_auth_registry_session_participant_free
    (WylServiceAuthRegistrySessionParticipant * participant);
wyrelog_error_t wyl_service_auth_registry_session_participant_reserve
    (WylServiceAuthRegistrySessionParticipant * participant,
    const WylServiceAuthReservation * reservation);
wyrelog_error_t wyl_service_auth_registry_session_participant_activate
    (WylServiceAuthRegistrySessionParticipant * participant,
    const WylServiceAuthReservation * reservation, gboolean * out_changed);
wyrelog_error_t wyl_service_auth_registry_session_participant_remove_exact
    (WylServiceAuthRegistrySessionParticipant * participant,
    const WylServiceAuthReservation * reservation, gboolean * out_removed);
wyrelog_error_t wyl_service_auth_registry_maintenance_participant_new_for_write
    (WylServiceAuthRegistry * registry, WylHandle * handle,
    WylServiceAuthWriteLease * lease,
    WylServiceAuthRegistryMaintenanceParticipant ** out_participant);
void wyl_service_auth_registry_maintenance_participant_free
    (WylServiceAuthRegistryMaintenanceParticipant * participant);
wyrelog_error_t wyl_service_auth_registry_maintenance_participant_clear
    (WylServiceAuthRegistryMaintenanceParticipant * participant);
wyrelog_error_t wyl_service_auth_registry_maintenance_participant_lookup_exact
    (WylServiceAuthRegistryMaintenanceParticipant * participant,
    const gchar * session_id, const gchar * jti,
    WylServiceAuthReservation * out_reservation,
    WylServiceAuthState * out_state, gboolean * out_found);
wyrelog_error_t wyl_service_auth_registry_maintenance_participant_remove_exact
    (WylServiceAuthRegistryMaintenanceParticipant * participant,
    const WylServiceAuthReservation * reservation, gboolean * out_removed);

wyrelog_error_t wyl_service_auth_registry_lookup
    (WylServiceAuthRegistry * registry, const gchar * session_id,
    const gchar * jti, WylServiceAuthReservation * out_reservation,
    WylServiceAuthState * out_state, gboolean * out_found);
void wyl_service_auth_reservation_clear
    (WylServiceAuthReservation * reservation);

/*
 * Returns at most max_entries immutable snapshots of due terminal/ACTIVE
 * pairs without walking the owning registry.  PENDING entries are never
 * returned.  The caller releases every returned snapshot and the array.
 */
wyrelog_error_t wyl_service_auth_registry_copy_due
    (WylServiceAuthRegistry * registry, gint64 now_seconds, gsize max_entries,
    GPtrArray ** out_reservations);
gboolean wyl_service_auth_registry_has_capacity
    (WylServiceAuthRegistry * registry);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthRegistrySessionParticipant,
    wyl_service_auth_registry_session_participant_free);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthRegistryWriteParticipant,
    wyl_service_auth_registry_write_participant_free)
/* Test-only observations.  They never expose or mutate stored entries. */
#ifdef WYL_AUTH_REGISTRY_TESTING
     typedef enum
     {
       WYL_SERVICE_AUTH_CORRUPT_PRINCIPAL_MEMBER = 1,
       WYL_SERVICE_AUTH_CORRUPT_TENANT_MEMBER,
       WYL_SERVICE_AUTH_CORRUPT_CREDENTIAL_MEMBER,
       WYL_SERVICE_AUTH_CORRUPT_JTI_INDEX,
       WYL_SERVICE_AUTH_CORRUPT_STATE,
       WYL_SERVICE_AUTH_CORRUPT_FOREIGN_PRINCIPAL_MEMBER,
       WYL_SERVICE_AUTH_CORRUPT_OWNING_SESSION_LINK,
     } WylServiceAuthRegistryCorruption;
     gboolean wyl_service_auth_registry_check_invariants_for_test
         (WylServiceAuthRegistry *registry);
     gsize wyl_service_auth_registry_size_for_test
         (WylServiceAuthRegistry *registry);
     gboolean wyl_service_auth_registry_corrupt_selector_index_for_test
         (WylServiceAuthRegistry *registry,
    const WylServiceAuthSelector *selector);
     gboolean wyl_service_auth_registry_corrupt_for_test
         (WylServiceAuthRegistry *registry,
    const WylServiceAuthReservation *reservation,
    WylServiceAuthRegistryCorruption corruption);
#endif

G_END_DECLS;
