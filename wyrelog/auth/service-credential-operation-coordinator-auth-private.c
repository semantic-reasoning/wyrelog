/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-auth-private.h"

#include "auth/service-auth-coordination-private.h"
#include "policy/store-private.h"
#include "wyl-handle-private.h"

wyrelog_error_t
    wyl_service_credential_operation_coordinator_get_credential_pinned
    (WylHandle * handle, GCancellable * cancellable,
    const gchar * credential_id, wyl_service_credential_t * out)
{
  WylServiceAuthReadLease *lease = NULL;
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_service_auth_authority_acquire_read
      (wyl_handle_get_service_auth_authority (handle), handle, cancellable,
      &lease);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_read_lease_get_policy_store (lease, handle, &store);
  if (rc == WYRELOG_E_OK && store != wyl_handle_get_policy_store (handle))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_get (handle, credential_id, out);
  if (lease != NULL) {
    wyrelog_error_t release_rc = wyl_service_auth_read_lease_release (lease);
    if (rc == WYRELOG_E_OK && release_rc != WYRELOG_E_OK)
      rc = release_rc;
    wyl_service_auth_read_lease_free (lease);
  }
  return rc;
}
