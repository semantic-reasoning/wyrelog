/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-status-private.h"

void wyl_service_credential_operation_status_list_clear
    (WylServiceCredentialOperationStatusList * list)
{
  if (list == NULL)
    return;
  for (gsize i = 0; i < list->n_entries; i++)
    wyl_service_credential_operation_record_clear (&list->entries[i].record);
  g_clear_pointer (&list->entries, g_free);
  list->n_entries = 0;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_status_list
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    GCancellable * cancellable,
    WylServiceCredentialOperationStatusList * out_list)
{
  GPtrArray *ids = NULL;
  GArray *entries = NULL;
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || out_list == NULL
      || (cancellable != NULL && !G_IS_CANCELLABLE (cancellable)))
    return WYRELOG_E_INVALID;
  rc = wyl_service_credential_operation_storage_enumerate_request_ids (storage,
      anchor, cancellable, &ids);
  if (rc != WYRELOG_E_OK)
    return rc;
  entries = g_array_new (FALSE, TRUE,
      sizeof (WylServiceCredentialOperationStatusEntry));
  for (guint i = 0; i < ids->len; i++) {
    WylServiceCredentialOperationStatusEntry entry = { 0 };
    if (g_cancellable_is_cancelled (cancellable)) {
      rc = WYRELOG_E_CANCELLED;
      goto fail;
    }
    rc = wyl_service_credential_operation_coordinator_load (storage, anchor,
        g_ptr_array_index (ids, i), &entry.record);
    if (rc == WYRELOG_E_CANCELLED)
      goto fail;
    /* Skip ANY unreadable record (purged NOT_FOUND, or a malformed/undecodable
     * record surfacing e.g. WYRELOG_E_POLICY): a diagnostic listing stays
     * available and one bad record never blinds the rest.  load() leaves
     * entry.record untouched on failure, so nothing needs clearing here. */
    if (rc != WYRELOG_E_OK)
      continue;
    g_array_append_val (entries, entry);
  }
  g_ptr_array_unref (ids);
  out_list->n_entries = entries->len;
  out_list->entries = (WylServiceCredentialOperationStatusEntry *)
      g_array_free (g_steal_pointer (&entries), FALSE);
  return WYRELOG_E_OK;
fail:
  for (guint i = 0; i < entries->len; i++)
    wyl_service_credential_operation_record_clear
        (&g_array_index (entries, WylServiceCredentialOperationStatusEntry,
            i).record);
  g_array_free (entries, TRUE);
  g_ptr_array_unref (ids);
  return rc;
}
