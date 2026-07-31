/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include "test-daemon-http-decide-seed-helper.h"

#include "wyrelog/auth/service-credential-operation-coordinator-private.h"
#include "wyrelog/auth/service-credential-operation-coordinator-storage-private.h"
#include "wyrelog/auth/service-credential-operation-storage-private.h"

G_MODULE_EXPORT gint
wyl_test_daemon_http_seed_prepared_operation (const gchar *operation_root,
    const gchar *request_id, guint32 kind, const gchar *subject_id,
    const gchar *tenant_id, const gchar *old_credential_id)
{
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WylServiceCredentialOperationCoordinatorLock lifecycle_lock =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_LOCK_INIT;
  WylServiceCredentialOperationRecord begun =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  gboolean lock_acquired = FALSE;
  gboolean replayed = FALSE;
  gint result = 2100;

  request.kind = (WylServiceCredentialOperationKind) kind;
  request.request_id = g_strdup (request_id);
  request.subject_id = g_strdup (subject_id);
  request.tenant_id = g_strdup (tenant_id);
  request.destination = g_strdup ("credential");
  request.parent_identity = g_strdup ("parent");
  request.actor_subject_id = g_strdup ("admin");
  request.old_credential_id = g_strdup (old_credential_id);
  request.escrow_id = g_strdup ("01890f47-3c4b-7cc2-b8c4-dc0c0c073991");
  memset (request.escrow_binding_digest, 0x31,
      sizeof request.escrow_binding_digest);
  request.expires_at_us = 1;
  request.expected_generation =
      request.kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE ? 1 : 0;
  if (!wyl_service_credential_operation_coordinator_request_is_valid (&request))
    goto out;
  if (wyl_service_credential_operation_storage_open (operation_root, &storage)
      != WYRELOG_E_OK) {
    result = 2101;
    goto out;
  }
  if (wyl_service_credential_operation_storage_capture_anchor (&storage,
          &anchor) != WYRELOG_E_OK) {
    result = 2102;
    goto out;
  }
  if (wyl_service_credential_operation_coordinator_lock_acquire (&storage,
          &anchor, request.request_id, &lifecycle_lock) != WYRELOG_E_OK) {
    result = 2103;
    goto out;
  }
  lock_acquired = TRUE;
  if (wyl_service_credential_operation_coordinator_begin_or_replay_locked_for_test (&storage, &anchor, &lifecycle_lock, &request, 1, &replayed, &begun) != WYRELOG_E_OK || replayed || begun.state != WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED) {
    result = 2104;
    goto out;
  }
  result = 0;

out:
  if (lock_acquired)
    wyl_service_credential_operation_coordinator_lock_release (&storage,
        &anchor, &lifecycle_lock);
  wyl_service_credential_operation_record_clear (&begun);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  wyl_service_credential_operation_storage_clear (&storage);
  wyl_service_credential_operation_coordinator_request_clear (&request);
  return result;
}
