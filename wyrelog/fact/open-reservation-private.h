/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/* The budget both sides of a reservation wait out when a durable transition
 * is refused with WYRELOG_E_BUSY: the acquisition in the legacy open, and the
 * unwind in begin(), abort() and the void store close.  A refusal is another
 * thread's short policy transaction on the shared connection, so a bounded
 * wait with backoff normally outlasts it.  Retries are the attempts after
 * the first; the delay doubles per retry up to 1 << 6 units, so the sum is
 * about 191 ms per unwind.  Shared here so the two sides cannot drift. */
#define WYL_FACT_OPEN_RESERVATION_BUSY_RETRIES 8u
#define WYL_FACT_OPEN_RESERVATION_BUSY_DELAY_US 1000u

/* Local ownership states mirror the durable fact_open_reservations FSM.  The
 * coordinator deliberately does not retain a policy-store pointer: its
 * persistence callbacks are owned by the caller and must outlive this object.
 * The adapter is synchronous, single-threaded, and non-reentrant. */
typedef enum
{
  WYL_FACT_OPEN_RESERVATION_PENDING = 0,
  WYL_FACT_OPEN_RESERVATION_ACQUIRING,
  WYL_FACT_OPEN_RESERVATION_ACTIVE,
  WYL_FACT_OPEN_RESERVATION_CLEANUP_PENDING,
  WYL_FACT_OPEN_RESERVATION_SETTLED,
} WylFactOpenReservationState;

typedef wyrelog_error_t (*WylFactOpenReservationTransitionFunc)
  (gpointer user_data, const gchar *reservation_id, const gchar *owner,
    WylFactOpenReservationState expected,
    WylFactOpenReservationState target);
/* Callbacks must return an error only when the requested durable operation is
 * definitely not committed; ambiguous outcomes require the caller to
 * reconcile before retrying. */
typedef wyrelog_error_t (*WylFactOpenReservationSettleFunc)
  (gpointer user_data, const gchar *reservation_id, const gchar *owner);
typedef wyrelog_error_t (*WylFactOpenReservationReleaseFunc)
  (gpointer user_data, gboolean *out_released);

typedef struct
{
  WylFactOpenReservationTransitionFunc transition;
  WylFactOpenReservationSettleFunc settle;
  WylFactOpenReservationReleaseFunc release;
  gpointer user_data;
} WylFactOpenReservationCallbacks;

typedef struct WylFactOpenReservation WylFactOpenReservation;

WylFactOpenReservation *wyl_fact_open_reservation_new
  (const gchar *reservation_id, const gchar *owner,
    const WylFactOpenReservationCallbacks *callbacks);
void wyl_fact_open_reservation_free (WylFactOpenReservation *reservation);
/* The object must be closed (or have fail() retried to success) before it is
 * freed.  free() refuses to discard an unsettled retry context. */
/* Release native resources once, without attempting the durable settlement.
 * This is used only while abandoning the local retry context; the durable row
 * remains in its last state for recovery. */
wyrelog_error_t wyl_fact_open_reservation_release_native
  (WylFactOpenReservation *reservation);
/* Abandon an unsettled local retry context after its callbacks are no longer
 * available.  The durable row is intentionally left for recovery. */
void wyl_fact_open_reservation_abandon (WylFactOpenReservation *reservation);
WylFactOpenReservationState wyl_fact_open_reservation_get_state
  (const WylFactOpenReservation *reservation);
const gchar *wyl_fact_open_reservation_get_id
  (const WylFactOpenReservation *reservation);

/* Each successful operation advances the durable FSM before changing local
 * state.  No SQLite transaction is held while release performs native or
 * filesystem work. */
wyrelog_error_t wyl_fact_open_reservation_begin_acquisition
  (WylFactOpenReservation *reservation);
/* Adopt a native resource immediately after acquisition, before any later
 * validation or durable transition can fail. */
wyrelog_error_t wyl_fact_open_reservation_adopt_native
  (WylFactOpenReservation *reservation);
wyrelog_error_t wyl_fact_open_reservation_mark_active
  (WylFactOpenReservation *reservation);

/* Failure and close are retryable.  A release failure leaves the reservation
 * charged in CLEANUP_PENDING; out_released must be TRUE only when all native
 * resources are fully released, even if the callback returns a diagnostic
 * error. */
wyrelog_error_t wyl_fact_open_reservation_fail
  (WylFactOpenReservation *reservation);
wyrelog_error_t wyl_fact_open_reservation_close
  (WylFactOpenReservation *reservation);

G_END_DECLS;
