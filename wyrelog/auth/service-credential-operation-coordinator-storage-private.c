/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-storage-private.h"

#include "auth/service-credential-operation-coordinator-journal-private.h"
#ifdef G_OS_WIN32
#include "auth/service-credential-operation-storage-windows-private.h"
#endif

static wyrelog_error_t
record_child_name (const gchar *request_id,
    WylServiceCredentialOperationChildName *out_name)
{
  g_autofree gchar *raw = NULL;
  if (request_id == NULL || out_name == NULL)
    return WYRELOG_E_INVALID;
  raw = g_strdup_printf ("op-%s", request_id);
  if (raw == NULL)
    return WYRELOG_E_NOMEM;
  return wyl_service_credential_operation_child_name_validate (raw, out_name);
}

static gboolean
same_nullable_text (const gchar *a, const gchar *b)
{
  if (a != NULL && a[0] == '\0')
    a = NULL;
  if (b != NULL && b[0] == '\0')
    b = NULL;
  return g_strcmp0 (a, b) == 0;
}

/* These values name the operation itself, rather than a mutable lifecycle
 * transition.  A request-id collision with any different value is fail-closed
 * and never replaces the existing journal bytes. */
static gboolean
same_immutable_identity (const WylServiceCredentialOperationRecord *existing,
    const WylServiceCredentialOperationRecord *prepared)
{
  return existing->kind == prepared->kind
      && same_nullable_text (existing->request_id, prepared->request_id)
      && same_nullable_text (existing->subject_id, prepared->subject_id)
      && same_nullable_text (existing->tenant_id, prepared->tenant_id)
      && same_nullable_text (existing->destination, prepared->destination)
      && same_nullable_text (existing->parent_identity,
      prepared->parent_identity)
      && same_nullable_text (existing->actor_subject_id,
      prepared->actor_subject_id)
      && same_nullable_text (existing->old_credential_id,
      prepared->old_credential_id)
      && existing->expected_generation == prepared->expected_generation
      && existing->expires_at_us == prepared->expires_at_us;
}

#ifndef G_OS_WIN32
typedef gint WylCoordinatorJournalLock;
#define WYL_COORDINATOR_JOURNAL_LOCK_INIT (-1)

static wyrelog_error_t
storage_child_read (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes **out_bytes)
{
  return wyl_service_credential_operation_child_read (storage, anchor, name,
      out_bytes);
}

static wyrelog_error_t
storage_child_create (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  return wyl_service_credential_operation_child_create (storage, anchor, name,
      bytes);
}

static wyrelog_error_t
storage_child_replace (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  return wyl_service_credential_operation_child_replace (storage, anchor, name,
      bytes);
}

static wyrelog_error_t
storage_child_lock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name,
    WylCoordinatorJournalLock *out_lock)
{
  return wyl_service_credential_operation_child_lock (storage, anchor, name,
      out_lock);
}

static void
storage_child_unlock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name,
    WylCoordinatorJournalLock lock)
{
  wyl_service_credential_operation_child_unlock (storage, anchor, name, lock);
}
#else
typedef HANDLE WylCoordinatorJournalLock;
#define WYL_COORDINATOR_JOURNAL_LOCK_INIT INVALID_HANDLE_VALUE

static wyrelog_error_t
storage_child_read (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes **out_bytes)
{
  return wyl_win_child_read (storage, anchor, name, out_bytes);
}

static wyrelog_error_t
storage_child_create (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  return wyl_win_child_create (storage, anchor, name, bytes);
}

static wyrelog_error_t
storage_child_replace (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name, GBytes *bytes)
{
  return wyl_win_child_replace (storage, anchor, name, bytes);
}

static wyrelog_error_t
storage_child_lock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name,
    WylCoordinatorJournalLock *out_lock)
{
  return wyl_win_child_lock (storage, anchor, name, out_lock);
}

static void
storage_child_unlock (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const WylServiceCredentialOperationChildName *name,
    WylCoordinatorJournalLock lock)
{
  wyl_win_child_unlock (storage, anchor, name, lock);
}
#endif

wyrelog_error_t
    wyl_service_credential_operation_coordinator_load
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  g_autoptr (GBytes) bytes = NULL;
  wyrelog_error_t rc;

  if (storage == NULL || anchor == NULL || out_record == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id))
    return WYRELOG_E_INVALID;
  rc = record_child_name (request_id, &name);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = storage_child_read (storage, anchor, &name, &bytes);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = wyl_service_credential_operation_record_decode (bytes, &loaded);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!g_str_equal (loaded.request_id, request_id)
      || !g_str_equal (loaded.operation_id, request_id)) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = loaded;
  loaded = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
out:
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&loaded);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_begin_or_replay
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const WylServiceCredentialOperationCoordinatorRequest * request,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord prepared =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock lock = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  g_autoptr (GBytes) bytes = NULL;
  wyrelog_error_t rc;
  gboolean replayed = FALSE;

  if (out_replayed != NULL)
    *out_replayed = FALSE;
  if (storage == NULL || anchor == NULL || request == NULL
      || out_record == NULL)
    return WYRELOG_E_INVALID;
  rc = wyl_service_credential_operation_coordinator_build_prepared (request,
      request->request_id, now_us, &prepared);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = record_child_name (prepared.request_id, &name);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = storage_child_lock (storage, anchor, &name, &lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = storage_child_read (storage, anchor, &name, &bytes);
  if (rc == WYRELOG_E_NOT_FOUND) {
    rc = wyl_service_credential_operation_record_encode (&prepared, &bytes);
    if (rc == WYRELOG_E_OK)
      rc = storage_child_create (storage, anchor, &name, bytes);
    if (rc == WYRELOG_E_OK) {
      wyl_service_credential_operation_record_clear (out_record);
      *out_record = prepared, prepared = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    }
  } else if (rc == WYRELOG_E_OK) {
    rc = wyl_service_credential_operation_record_decode (bytes, &existing);
    if (rc == WYRELOG_E_OK
        && (!g_str_equal (existing.operation_id, existing.request_id)
            || !same_immutable_identity (&existing, &prepared)))
      rc = WYRELOG_E_POLICY;
    if (rc == WYRELOG_E_OK) {
      replayed = TRUE;
      wyl_service_credential_operation_record_clear (out_record);
      *out_record = existing, existing = (WylServiceCredentialOperationRecord)
          WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    }
  }
out:
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&existing);
  wyl_service_credential_operation_record_clear (&prepared);
  if (rc == WYRELOG_E_OK && out_replayed != NULL)
    *out_replayed = replayed;
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_server_committed
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * successor_credential_id,
    guint64 successor_generation, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord committed =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock lock = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  g_autoptr (GBytes) bytes = NULL;
  gboolean replayed = FALSE;
  wyrelog_error_t rc;

  if (out_replayed != NULL)
    *out_replayed = FALSE;
  if (storage == NULL || anchor == NULL || out_record == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id))
    return WYRELOG_E_INVALID;
  rc = record_child_name (request_id, &name);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = storage_child_lock (storage, anchor, &name, &lock);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = storage_child_read (storage, anchor, &name, &bytes);
  if (rc != WYRELOG_E_OK)
    goto out;
  rc = wyl_service_credential_operation_record_decode (bytes, &existing);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!g_str_equal (existing.request_id, request_id)
      || !g_str_equal (existing.operation_id, request_id)) {
    rc = WYRELOG_E_POLICY;
    goto out;
  }
  replayed =
      existing.state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
  rc = wyl_service_credential_operation_coordinator_build_server_committed
      (&existing, successor_credential_id, successor_generation, now_us,
      &committed);
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!replayed) {
    g_clear_pointer (&bytes, g_bytes_unref);
    rc = wyl_service_credential_operation_record_encode (&committed, &bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = storage_child_replace (storage, anchor, &name, bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = committed;
  committed = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
out:
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&committed);
  wyl_service_credential_operation_record_clear (&existing);
  if (rc == WYRELOG_E_OK && out_replayed != NULL)
    *out_replayed = replayed;
  return rc;
}
