/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/store-open-private.h"

#include "fact/open-reservation-private.h"

wyrelog_error_t
wyl_fact_store_open_legacy_graph (wyl_policy_store_t *policy_store,
    const gchar *path, const gchar *fact_root, const gchar *tenant_id,
    const gchar *graph_id, gboolean writable, wyl_fact_store_t **out_store)
{
  if (out_store != NULL)
    *out_store = NULL;
  if (policy_store == NULL || path == NULL || path[0] == '\0'
      || fact_root == NULL || fact_root[0] == '\0'
      || tenant_id == NULL || graph_id == NULL || out_store == NULL)
    return WYRELOG_E_INVALID;

  /* Seal and unseal validate a legacy store from inside the publication
   * fence's transaction on this same thread, where starting the durable open
   * reservation would nest a transaction and be refused as WYRELOG_E_BUSY;
   * that path opens uncharged, serialized by the fence.  The question is
   * whether the calling thread owns the open transaction, not whether the
   * connection has one: another thread's transaction is waited out by the
   * reservation below and must not admit this open without a charge. */
  if (wyl_policy_store_transaction_owned_by_caller (policy_store))
    return wyl_fact_store_open (path, out_store);

  for (guint attempt = 0; attempt <= WYL_FACT_OPEN_RESERVATION_BUSY_RETRIES;
      attempt++) {
    WylFactOpenReservation *reservation = NULL;
    wyrelog_error_t reservation_rc = WYRELOG_E_OK;
    FactOpenReservationAdapter *adapter =
        wyl_fact_store_open_reservation_begin (policy_store, tenant_id,
            graph_id, fact_root, path, &reservation, &reservation_rc);
    if (adapter == NULL) {
      if (reservation_rc != WYRELOG_E_BUSY
          || attempt == WYL_FACT_OPEN_RESERVATION_BUSY_RETRIES)
        return reservation_rc;
      g_usleep (WYL_FACT_OPEN_RESERVATION_BUSY_DELAY_US << MIN (attempt, 6u));
      continue;
    }

    wyrelog_error_t rc = wyl_fact_store_open (path, out_store);
    gboolean attached = FALSE;
    if (rc == WYRELOG_E_OK) {
      wyl_fact_store_open_reservation_attach (*out_store, adapter,
          reservation);
      attached = TRUE;
      rc = wyl_fact_open_reservation_adopt_native (reservation);
    }
    if (rc == WYRELOG_E_OK)
      rc = wyl_fact_open_reservation_mark_active (reservation);
    if (rc == WYRELOG_E_OK)
      return WYRELOG_E_OK;

    if (*out_store != NULL) {
      wyl_fact_store_close (*out_store);
      *out_store = NULL;
    }
    if (!attached)
      wyl_fact_store_open_reservation_abort (adapter, reservation);
    if (rc != WYRELOG_E_BUSY
        || attempt == WYL_FACT_OPEN_RESERVATION_BUSY_RETRIES)
      return rc;
    g_usleep (WYL_FACT_OPEN_RESERVATION_BUSY_DELAY_US << MIN (attempt, 6u));
  }
  (void) writable;
  return WYRELOG_E_BUSY;
}
