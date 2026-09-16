/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "open-reservation-private.h"

struct WylFactOpenReservation
{
  gchar *reservation_id;
  gchar *owner;
  WylFactOpenReservationCallbacks callbacks;
  WylFactOpenReservationState state;
  gboolean native_acquired;
  gboolean native_released;
};

static gboolean
reservation_valid (const WylFactOpenReservation *reservation)
{
  return reservation != NULL && reservation->reservation_id != NULL
         && reservation->owner != NULL && reservation->callbacks.transition != NULL
         && reservation->callbacks.settle != NULL
         && reservation->callbacks.release != NULL;
}

static wyrelog_error_t
transition (WylFactOpenReservation *reservation,
    WylFactOpenReservationState target)
{
  WylFactOpenReservationState expected = reservation->state;
  wyrelog_error_t rc = reservation->callbacks.transition
        (reservation->callbacks.user_data, reservation->reservation_id,
          reservation->owner, expected, target);
  if (rc == WYRELOG_E_OK)
    reservation->state = target;
  return rc;
}

WylFactOpenReservation *
wyl_fact_open_reservation_new (const gchar *reservation_id,
    const gchar *owner, const WylFactOpenReservationCallbacks *callbacks)
{
  if (reservation_id == NULL || reservation_id[0] == '\0'
      || owner == NULL || owner[0] == '\0' || callbacks == NULL
      || callbacks->transition == NULL || callbacks->settle == NULL
      || callbacks->release == NULL)
    return NULL;
  WylFactOpenReservation *reservation = g_new0 (WylFactOpenReservation, 1);
  reservation->reservation_id = g_strdup (reservation_id);
  reservation->owner = g_strdup (owner);
  reservation->callbacks = *callbacks;
  reservation->state = WYL_FACT_OPEN_RESERVATION_PENDING;
  if (reservation->reservation_id == NULL || reservation->owner == NULL) {
    wyl_fact_open_reservation_free (reservation);
    return NULL;
  }
  return reservation;
}

void
wyl_fact_open_reservation_free (WylFactOpenReservation *reservation)
{
  if (reservation == NULL)
    return;
  g_return_if_fail (reservation->state == WYL_FACT_OPEN_RESERVATION_SETTLED);
  g_free (reservation->reservation_id);
  g_free (reservation->owner);
  g_free (reservation);
}

WylFactOpenReservationState
wyl_fact_open_reservation_get_state (const WylFactOpenReservation *reservation)
{
  return reservation == NULL ? WYL_FACT_OPEN_RESERVATION_CLEANUP_PENDING
                              : reservation->state;
}

const gchar *
wyl_fact_open_reservation_get_id (const WylFactOpenReservation *reservation)
{
  return reservation == NULL ? NULL : reservation->reservation_id;
}

wyrelog_error_t
wyl_fact_open_reservation_begin_acquisition (WylFactOpenReservation *reservation)
{
  if (!reservation_valid (reservation)
      || reservation->state != WYL_FACT_OPEN_RESERVATION_PENDING)
    return WYRELOG_E_INVALID;
  return transition (reservation, WYL_FACT_OPEN_RESERVATION_ACQUIRING);
}

wyrelog_error_t
wyl_fact_open_reservation_adopt_native (WylFactOpenReservation *reservation)
{
  if (!reservation_valid (reservation)
      || reservation->state != WYL_FACT_OPEN_RESERVATION_ACQUIRING
      || reservation->native_acquired)
    return WYRELOG_E_INVALID;
  reservation->native_acquired = TRUE;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_open_reservation_mark_active (WylFactOpenReservation *reservation)
{
  if (!reservation_valid (reservation)
      || reservation->state != WYL_FACT_OPEN_RESERVATION_ACQUIRING
      || !reservation->native_acquired)
    return WYRELOG_E_INVALID;
  wyrelog_error_t rc = transition (reservation,
          WYL_FACT_OPEN_RESERVATION_ACTIVE);
  return rc;
}

static wyrelog_error_t
cleanup (WylFactOpenReservation *reservation)
{
  if (reservation->state != WYL_FACT_OPEN_RESERVATION_CLEANUP_PENDING) {
    wyrelog_error_t rc = transition (reservation,
            WYL_FACT_OPEN_RESERVATION_CLEANUP_PENDING);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  if (reservation->native_acquired && !reservation->native_released) {
    gboolean released = FALSE;
    wyrelog_error_t rc = reservation->callbacks.release
          (reservation->callbacks.user_data, &released);
    if (released)
      reservation->native_released = TRUE;
    if (rc != WYRELOG_E_OK)
      return rc;
    if (!reservation->native_released)
      return WYRELOG_E_IO;
  }
  wyrelog_error_t rc = reservation->callbacks.settle
        (reservation->callbacks.user_data, reservation->reservation_id,
          reservation->owner);
  if (rc != WYRELOG_E_OK)
    return rc;
  reservation->state = WYL_FACT_OPEN_RESERVATION_SETTLED;
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_fact_open_reservation_fail (WylFactOpenReservation *reservation)
{
  if (!reservation_valid (reservation))
    return WYRELOG_E_INVALID;
  if (reservation->state == WYL_FACT_OPEN_RESERVATION_SETTLED)
    return WYRELOG_E_OK;
  return cleanup (reservation);
}

wyrelog_error_t
wyl_fact_open_reservation_close (WylFactOpenReservation *reservation)
{
  if (!reservation_valid (reservation))
    return WYRELOG_E_INVALID;
  if (reservation->state == WYL_FACT_OPEN_RESERVATION_SETTLED)
    return WYRELOG_E_OK;
  if (!reservation->native_acquired)
    return wyl_fact_open_reservation_fail (reservation);
  return cleanup (reservation);
}
