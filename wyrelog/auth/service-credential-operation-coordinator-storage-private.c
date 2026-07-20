/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-credential-operation-coordinator-storage-private.h"

#include "auth/service-credential-operation-coordinator-journal-private.h"
#include "policy/store-private.h"
#include "wyl-id-private.h"
#include <sodium.h>
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

static wyrelog_error_t
lifecycle_lock_child_name (const gchar *request_id,
    WylServiceCredentialOperationChildName *out_name)
{
  g_autofree gchar *raw = NULL;
  if (request_id == NULL || out_name == NULL)
    return WYRELOG_E_INVALID;
  raw = g_strdup_printf ("lifecycle-%s", request_id);
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
      && same_nullable_text (existing->escrow_id, prepared->escrow_id)
      && sodium_memcmp (existing->escrow_binding_digest,
      prepared->escrow_binding_digest,
      sizeof existing->escrow_binding_digest) == 0
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
    wyl_service_credential_operation_coordinator_lock_acquire
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    WylServiceCredentialOperationCoordinatorLock * out_lock)
{
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock native = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || out_lock == NULL
      || out_lock->native_handle != NULL
      || out_lock->child_name.component != NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id))
    return WYRELOG_E_INVALID;
  rc = lifecycle_lock_child_name (request_id, &name);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = storage_child_lock (storage, anchor, &name, &native);
  if (rc != WYRELOG_E_OK) {
    wyl_service_credential_operation_child_name_clear (&name);
    return rc;
  }
#ifndef G_OS_WIN32
  out_lock->native_handle = GINT_TO_POINTER (native + 1);
#else
  out_lock->native_handle = native;
#endif
  out_lock->child_name = name;
  return WYRELOG_E_OK;
}

void wyl_service_credential_operation_coordinator_lock_release
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    WylServiceCredentialOperationCoordinatorLock * lock)
{
  if (lock == NULL)
    return;
  if (lock->native_handle != NULL && lock->child_name.component != NULL) {
#ifndef G_OS_WIN32
    WylCoordinatorJournalLock native =
        GPOINTER_TO_INT (lock->native_handle) - 1;
#else
    WylCoordinatorJournalLock native = lock->native_handle;
#endif
    storage_child_unlock (storage, anchor, &lock->child_name, native);
  }
  lock->native_handle = NULL;
  wyl_service_credential_operation_child_name_clear (&lock->child_name);
}

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
    wyl_service_credential_operation_coordinator_load_snapshot
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    guint8 out_snapshot_digest
    [WYL_SERVICE_CREDENTIAL_HANDOFF_DIGEST_BYTES],
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord loaded =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock lock = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  g_autoptr (GBytes) bytes = NULL;
  guint8 digest[crypto_generichash_BYTES] = { 0 };
  wyrelog_error_t rc;
  if (storage == NULL || anchor == NULL || out_snapshot_digest == NULL
      || out_record == NULL
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id))
    return WYRELOG_E_INVALID;
  rc = record_child_name (request_id, &name);
  if (rc == WYRELOG_E_OK)
    rc = storage_child_lock (storage, anchor, &name, &lock);
  if (rc == WYRELOG_E_OK)
    rc = storage_child_read (storage, anchor, &name, &bytes);
  if (rc == WYRELOG_E_OK) {
    gsize len = 0;
    const guint8 *data = g_bytes_get_data (bytes, &len);
    if (data == NULL || crypto_generichash (digest, sizeof digest, data, len,
            NULL, 0) != 0)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_operation_record_decode (bytes, &loaded);
  if (rc == WYRELOG_E_OK
      && (g_strcmp0 (loaded.request_id, request_id) != 0
          || g_strcmp0 (loaded.operation_id, request_id) != 0))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK) {
    memcpy (out_snapshot_digest, digest, sizeof digest);
    wyl_service_credential_operation_record_clear (out_record);
    *out_record = loaded;
    loaded = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  }
  sodium_memzero (digest, sizeof digest);
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
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
    wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * successor_credential_id,
    guint64 successor_generation, const guint8 * binding_digest,
    gint64 now_us, gboolean * out_replayed,
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
  const guint8 *effective_binding = binding_digest != NULL ? binding_digest :
      existing.escrow_binding_digest;
  replayed =
      existing.state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED;
  rc = wyl_service_credential_operation_coordinator_build_server_committed_bound
      (&existing, successor_credential_id, successor_generation,
      effective_binding, now_us, &committed);
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

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_server_committed
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * successor_credential_id,
    guint64 successor_generation, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return
      wyl_service_credential_operation_coordinator_checkpoint_server_committed_bound
      (storage, anchor, request_id, successor_credential_id,
      successor_generation, NULL, now_us, out_replayed, out_record);
}

typedef enum
{
  CHECKPOINT_PUBLICATION_PLANNED,
  CHECKPOINT_PUBLICATION_PREPARED,
  CHECKPOINT_FILE_PUBLISHED,
} PublicationCheckpoint;

static wyrelog_error_t
checkpoint_publication (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id, PublicationCheckpoint checkpoint,
    const gchar *reservation_id, const gchar *stage_basename,
    const gchar *stage_identity, const gchar *publication_receipt_id,
    gint64 now_us, gboolean *out_replayed,
    WylServiceCredentialOperationRecord *out_record)
{
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock lock = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  g_autoptr (GBytes) bytes = NULL;
  WylServiceCredentialOperationState target_state;
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
  switch (checkpoint) {
    case CHECKPOINT_PUBLICATION_PLANNED:
      target_state = WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED;
      rc = wyl_service_credential_operation_coordinator_build_publication_planned (&existing, reservation_id, stage_basename, publication_receipt_id, now_us, &next);
      break;
    case CHECKPOINT_PUBLICATION_PREPARED:
      target_state = WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED;
      rc = wyl_service_credential_operation_coordinator_build_publication_prepared (&existing, reservation_id, stage_basename, stage_identity, publication_receipt_id, now_us, &next);
      break;
    case CHECKPOINT_FILE_PUBLISHED:
      target_state = WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED;
      rc = wyl_service_credential_operation_coordinator_build_file_published
          (&existing, reservation_id, stage_basename, stage_identity,
          publication_receipt_id, now_us, &next);
      break;
    default:
      rc = WYRELOG_E_INVALID;
      goto out;
  }
  if (rc != WYRELOG_E_OK)
    goto out;
  replayed = existing.state == target_state;
  if (!replayed) {
    g_clear_pointer (&bytes, g_bytes_unref);
    rc = wyl_service_credential_operation_record_encode (&next, &bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = storage_child_replace (storage, anchor, &name, bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = next;
  next = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
out:
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&next);
  wyl_service_credential_operation_record_clear (&existing);
  if (rc == WYRELOG_E_OK && out_replayed != NULL)
    *out_replayed = replayed;
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_publication_planned
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * publication_receipt_id,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_publication (storage, anchor, request_id,
      CHECKPOINT_PUBLICATION_PLANNED, reservation_id, stage_basename, NULL,
      publication_receipt_id, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_publication_prepared
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * stage_identity,
    const gchar * publication_receipt_id, gint64 now_us,
    gboolean * out_replayed, WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_publication (storage, anchor, request_id,
      CHECKPOINT_PUBLICATION_PREPARED, reservation_id, stage_basename,
      stage_identity, publication_receipt_id, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_file_published
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, const gchar * reservation_id,
    const gchar * stage_basename, const gchar * stage_identity,
    const gchar * publication_receipt_id, gint64 now_us,
    gboolean * out_replayed, WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_publication (storage, anchor, request_id,
      CHECKPOINT_FILE_PUBLISHED, reservation_id, stage_basename,
      stage_identity, publication_receipt_id, now_us, out_replayed, out_record);
}

typedef enum
{
  CHECKPOINT_CLEANUP_REQUIRED,
  CHECKPOINT_SUCCESSOR_INACTIVE_OAR,
  CHECKPOINT_RECEIPT_OAR,
  CHECKPOINT_ESCROW_OAR,
  CHECKPOINT_TERMINAL_NOT_COMMITTED,
  CHECKPOINT_TERMINAL_FILE_PUBLISHED,
} LifecycleCheckpoint;

static wyrelog_error_t
checkpoint_lifecycle (const WylServiceCredentialOperationStorage *storage,
    const WylServiceCredentialOperationRootAnchor *anchor,
    const gchar *request_id, LifecycleCheckpoint checkpoint,
    WylServiceCredentialOperationOarCause cause, gint64 now_us,
    gboolean *out_replayed, WylServiceCredentialOperationRecord *out_record)
{
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord next =
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
  if (checkpoint == CHECKPOINT_SUCCESSOR_INACTIVE_OAR
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED)
    return WYRELOG_E_INVALID;
  if (checkpoint == CHECKPOINT_RECEIPT_OAR
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN)
    return WYRELOG_E_INVALID;
  if (checkpoint == CHECKPOINT_ESCROW_OAR
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_FOREIGN
      && cause != WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_UNCERTAIN)
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
  switch (checkpoint) {
    case CHECKPOINT_CLEANUP_REQUIRED:
      replayed = existing.state ==
          WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED;
      rc = wyl_service_credential_operation_coordinator_build_cleanup_required
          (&existing, now_us, &next);
      break;
    case CHECKPOINT_SUCCESSOR_INACTIVE_OAR:
    case CHECKPOINT_RECEIPT_OAR:
    case CHECKPOINT_ESCROW_OAR:
      replayed = existing.state ==
          WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED;
      rc = wyl_service_credential_operation_coordinator_build_operator_action_required (&existing, cause, now_us, &next);
      break;
    case CHECKPOINT_TERMINAL_NOT_COMMITTED:
      replayed = existing.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
      rc = wyl_service_credential_operation_coordinator_build_terminal
          (&existing,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED, NULL,
          now_us, &next);
      break;
    case CHECKPOINT_TERMINAL_FILE_PUBLISHED:
      replayed = existing.state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
      rc = wyl_service_credential_operation_coordinator_build_terminal
          (&existing,
          WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED, NULL,
          now_us, &next);
      break;
    default:
      rc = WYRELOG_E_INVALID;
      goto out;
  }
  if (rc != WYRELOG_E_OK)
    goto out;
  if (!replayed) {
    g_clear_pointer (&bytes, g_bytes_unref);
    rc = wyl_service_credential_operation_record_encode (&next, &bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
    rc = storage_child_replace (storage, anchor, &name, bytes);
    if (rc != WYRELOG_E_OK)
      goto out;
  }
  wyl_service_credential_operation_record_clear (out_record);
  *out_record = next;
  next = (WylServiceCredentialOperationRecord)
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
out:
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&next);
  wyl_service_credential_operation_record_clear (&existing);
  if (rc == WYRELOG_E_OK && out_replayed != NULL)
    *out_replayed = replayed;
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_cleanup_required
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_CLEANUP_REQUIRED, 0, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_successor_inactive_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_SUCCESSOR_INACTIVE_OAR, cause, now_us, out_replayed,
      out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_receipt_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_RECEIPT_OAR, cause, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_escrow_oar
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, WylServiceCredentialOperationOarCause cause,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_ESCROW_OAR, cause, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_terminal_not_committed
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_TERMINAL_NOT_COMMITTED, 0, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_terminal_file_published
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_lifecycle (storage, anchor, request_id,
      CHECKPOINT_TERMINAL_FILE_PUBLISHED, 0, now_us, out_replayed, out_record);
}

static gboolean
remediation_id_is_canonical (const gchar *value)
{
  wyl_id_t parsed;
  gchar canonical[WYL_ID_STRING_BUF];
  return value != NULL && wyl_id_parse (value, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && g_strcmp0 (value, canonical) == 0;
}

static gboolean
    remediation_proof_common_is_valid
    (const WylServiceCredentialOperationRemediationProof * proof,
    const WylServiceCredentialOperationRecord * record)
{
  if (proof == NULL || record == NULL || proof->created_at_us <= 0
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (proof->remediation_request_id)
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (proof->decision_request_id)
      || !wyl_policy_service_actor_subject_is_valid
      (proof->current_actor_subject_id)
      || !remediation_id_is_canonical (proof->audit_id)
      || g_strcmp0 (proof->remediation_request_id,
          proof->decision_request_id) == 0
      || g_strcmp0 (proof->remediation_request_id,
          proof->original_request_id) == 0
      || g_strcmp0 (proof->decision_request_id,
          proof->original_request_id) == 0
      || g_strcmp0 (proof->current_actor_subject_id,
          proof->original_actor_subject_id) == 0
      || sodium_is_zero (proof->request_fingerprint,
          sizeof proof->request_fingerprint)
      || sodium_is_zero (proof->source_snapshot_digest,
          sizeof proof->source_snapshot_digest)
      || sodium_is_zero (proof->binding_digest, sizeof proof->binding_digest)
      || g_strcmp0 (proof->original_request_id, record->request_id) != 0
      || g_strcmp0 (proof->original_actor_subject_id,
          record->actor_subject_id) != 0
      || g_strcmp0 (proof->escrow_id, record->escrow_id) != 0
      || sodium_memcmp (proof->binding_digest,
          record->escrow_binding_digest, sizeof proof->binding_digest) != 0
      || g_strcmp0 (proof->successor_credential_id,
          record->successor_credential_id) != 0
      || proof->successor_issuance_generation != record->successor_generation)
    return FALSE;
  if (proof->source_kind ==
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION) {
    gboolean committed_state = proof->observed_state ==
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_SERVER_COMMITTED
        || proof->observed_state ==
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PLANNED
        || proof->observed_state ==
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_PUBLICATION_PREPARED
        || proof->observed_state ==
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_FILE_PUBLISHED
        || proof->observed_state ==
        WYL_SERVICE_HANDOFF_REMEDIATION_STATE_CLEANUP_REQUIRED;
    return committed_state
        && remediation_id_is_canonical (proof->source_disposition_id)
        && remediation_id_is_canonical (proof->source_audit_id)
        && (proof->source_reason ==
        WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_EXPIRED
        || proof->source_reason ==
        WYL_SERVICE_HANDOFF_DISPOSITION_OPERATION_CANCELLED)
        && proof->oar_source_state == 0 && proof->oar_cause == 0
        && proof->resume_target_state == 0;
  }
  WylServiceCredentialOperationState source =
      (WylServiceCredentialOperationState) proof->oar_source_state;
  WylServiceCredentialOperationOarCause cause =
      (WylServiceCredentialOperationOarCause) proof->oar_cause;
  g_autofree gchar *legal_oar =
      wyl_service_credential_operation_oar_reason_format (source, cause);
  return proof->source_kind ==
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
      && proof->source_disposition_id == NULL
      && proof->source_audit_id == NULL && proof->source_reason == 0
      && proof->observed_state ==
      WYL_SERVICE_HANDOFF_REMEDIATION_STATE_OPERATOR_ACTION_REQUIRED
      && proof->oar_source_state != 0 && proof->oar_cause != 0
      && proof->resume_target_state == proof->oar_source_state
      && legal_oar != NULL;
}

static gboolean
    remediation_proof_action_is_valid
    (const WylServiceCredentialOperationRemediationProof * proof)
{
  gboolean no_event = proof->revoke_event_id == 0
      && proof->revoke_event_generation == 0
      && proof->revoke_event_request_id == NULL
      && proof->revoke_event_actor_subject_id == NULL
      && proof->revoke_event_created_at_us == 0;
  if (proof->action == WYL_SERVICE_HANDOFF_REMEDIATION_RESUME) {
    return proof->confirmation_version == 0 && !proof->confirmed
        && proof->outcome == WYL_SERVICE_HANDOFF_REMEDIATION_RECORDED
        && proof->escrow_outcome ==
        WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_RETAINED
        && proof->credential_generation_after ==
        proof->successor_issuance_generation
        && proof->invalidation_generation == 0 && !proof->revoked_now
        && no_event
        && !(proof->source_kind ==
        WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
        && (proof->oar_cause ==
            WYL_SERVICE_HANDOFF_REMEDIATION_OAR_SUCCESSOR_REVOKED
            || proof->oar_cause ==
            WYL_SERVICE_HANDOFF_REMEDIATION_OAR_SUCCESSOR_EXPIRED
            || proof->oar_cause ==
            WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING));
  }
  if (proof->action !=
      WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE
      || proof->confirmation_version != 1 || !proof->confirmed
      || proof->invalidation_generation !=
      proof->successor_issuance_generation
      || (proof->escrow_outcome !=
          WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_DELETED
          && proof->escrow_outcome !=
          WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT)
      || (proof->escrow_outcome ==
          WYL_SERVICE_HANDOFF_REMEDIATION_ESCROW_ALREADY_ABSENT
          && (proof->source_kind !=
              WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED
              || proof->oar_cause !=
              WYL_SERVICE_HANDOFF_REMEDIATION_OAR_ESCROW_MISSING)))
    return FALSE;
  if (proof->outcome == WYL_SERVICE_HANDOFF_REMEDIATION_EXPIRED_AND_WIPED)
    return !proof->revoked_now && no_event
        && proof->credential_generation_after ==
        proof->successor_issuance_generation;
  if (proof->outcome !=
      WYL_SERVICE_HANDOFF_REMEDIATION_REVOKED_AND_WIPED
      && proof->outcome !=
      WYL_SERVICE_HANDOFF_REMEDIATION_ALREADY_REVOKED_AND_WIPED)
    return FALSE;
  if (proof->successor_issuance_generation >= G_MAXINT64
      || proof->credential_generation_after !=
      proof->successor_issuance_generation + 1
      || proof->revoke_event_id <= 0
      || proof->revoke_event_generation != proof->credential_generation_after
      || proof->revoke_event_request_id == NULL
      || proof->revoke_event_actor_subject_id == NULL
      || proof->revoke_event_created_at_us <= 0)
    return FALSE;
  if (proof->outcome == WYL_SERVICE_HANDOFF_REMEDIATION_REVOKED_AND_WIPED)
    return proof->revoked_now == !proof->authority_replayed
        && g_strcmp0 (proof->revoke_event_request_id,
        proof->remediation_request_id) == 0
        && g_strcmp0 (proof->revoke_event_actor_subject_id,
        proof->current_actor_subject_id) == 0
        && proof->revoke_event_created_at_us == proof->created_at_us;
  return !proof->revoked_now;
}

static gboolean
    remediation_source_matches_fresh_record
    (const WylServiceCredentialOperationRemediationProof * proof,
    const WylServiceCredentialOperationRecord * record)
{
  if ((guint) proof->observed_state != (guint) record->state)
    return FALSE;
  if (proof->source_kind ==
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_COMMITTED_ATTENTION)
    return record->state == WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED
        || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED
        || record->state ==
        WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED
        || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED
        || record->state == WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED;
  WylServiceCredentialOperationState source = 0;
  WylServiceCredentialOperationOarCause cause = 0;
  return wyl_service_credential_operation_oar_reason_parse
      (record->terminal_reason, &source, &cause)
      && (guint) source == (guint) proof->oar_source_state
      && (guint) cause == (guint) proof->oar_cause
      && (guint) source == (guint) proof->resume_target_state;
}

static gboolean
    remediation_marker_matches_proof
    (const WylServiceCredentialOperationRecord * record,
    const WylServiceCredentialOperationRemediationProof * proof)
{
  WylServiceCredentialOperationRemediationAction action =
      proof->action == WYL_SERVICE_HANDOFF_REMEDIATION_RESUME ?
      WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME :
      WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE;
  WylServiceCredentialOperationState target =
      action == WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME ?
      (WylServiceCredentialOperationState) (proof->source_kind ==
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED ?
      proof->resume_target_state : proof->observed_state) :
      WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL;
  return record->last_remediation_action == action
      && g_strcmp0 (record->last_remediation_request_id,
      proof->remediation_request_id) == 0
      && sodium_memcmp (record->last_remediation_source_snapshot_digest,
      proof->source_snapshot_digest,
      sizeof proof->source_snapshot_digest) == 0
      && record->last_remediation_applied_target_state == target
      && sodium_memcmp (record->last_remediation_request_fingerprint,
      proof->request_fingerprint, sizeof proof->request_fingerprint) == 0;
}

static wyrelog_error_t
    checkpoint_operator_remediation
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationRemediationProof * proof,
    gboolean resume, gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  WylServiceCredentialOperationRecord existing =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationRecord next =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  WylServiceCredentialOperationChildName name =
      WYL_SERVICE_CREDENTIAL_OPERATION_CHILD_NAME_INIT;
  WylCoordinatorJournalLock lock = WYL_COORDINATOR_JOURNAL_LOCK_INIT;
  g_autoptr (GBytes) bytes = NULL;
  guint8 raw_digest[crypto_generichash_BYTES] = { 0 };
  gboolean replayed = FALSE;
  wyrelog_error_t rc = WYRELOG_E_INVALID;
  if (out_replayed != NULL)
    *out_replayed = FALSE;
  if (storage == NULL || anchor == NULL || out_record == NULL || proof == NULL
      || now_us <= 0
      || !wyl_service_credential_operation_coordinator_request_id_is_valid
      (request_id)
      || (resume && proof->action != WYL_SERVICE_HANDOFF_REMEDIATION_RESUME)
      || (!resume && proof->action !=
          WYL_SERVICE_HANDOFF_REMEDIATION_REVOKE_AND_WIPE))
    return WYRELOG_E_INVALID;
  rc = record_child_name (request_id, &name);
  if (rc == WYRELOG_E_OK)
    rc = storage_child_lock (storage, anchor, &name, &lock);
  if (rc == WYRELOG_E_OK)
    rc = storage_child_read (storage, anchor, &name, &bytes);
  if (rc == WYRELOG_E_OK) {
    gsize len = 0;
    const guint8 *data = g_bytes_get_data (bytes, &len);
    if (data == NULL || crypto_generichash (raw_digest, sizeof raw_digest,
            data, len, NULL, 0) != 0)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_credential_operation_record_decode (bytes, &existing);
  if (rc == WYRELOG_E_OK
      && (g_strcmp0 (existing.request_id, request_id) != 0
          || g_strcmp0 (existing.operation_id, request_id) != 0
          || !remediation_proof_common_is_valid (proof, &existing)
          || !remediation_proof_action_is_valid (proof)))
    rc = WYRELOG_E_POLICY;
  if (rc == WYRELOG_E_OK)
    replayed = remediation_marker_matches_proof (&existing, proof);
  if (rc == WYRELOG_E_OK && !replayed
      && (sodium_memcmp (raw_digest, proof->source_snapshot_digest,
              sizeof raw_digest) != 0
          || !remediation_source_matches_fresh_record (proof, &existing)))
    rc = WYRELOG_E_POLICY;
  WylServiceCredentialOperationState target =
      (WylServiceCredentialOperationState) (proof->source_kind ==
      WYL_SERVICE_HANDOFF_REMEDIATION_SOURCE_OPERATOR_ACTION_REQUIRED ?
      proof->resume_target_state : proof->observed_state);
  if (rc == WYRELOG_E_OK)
    rc = resume ?
        wyl_service_credential_operation_coordinator_build_operator_resume_exact
        (&existing, proof->remediation_request_id,
        proof->source_snapshot_digest, target, proof->request_fingerprint,
        now_us, &next) :
        wyl_service_credential_operation_coordinator_build_operator_revoke_and_wipe
        (&existing, proof->remediation_request_id,
        proof->source_snapshot_digest, proof->request_fingerprint, now_us,
        &next);
  if (rc == WYRELOG_E_OK && !replayed) {
    g_clear_pointer (&bytes, g_bytes_unref);
    rc = wyl_service_credential_operation_record_encode (&next, &bytes);
    if (rc == WYRELOG_E_OK)
      rc = storage_child_replace (storage, anchor, &name, bytes);
  }
  if (rc == WYRELOG_E_OK) {
    wyl_service_credential_operation_record_clear (out_record);
    *out_record = next;
    next = (WylServiceCredentialOperationRecord)
        WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
    if (out_replayed != NULL)
      *out_replayed = replayed;
  }
  sodium_memzero (raw_digest, sizeof raw_digest);
  if (lock != WYL_COORDINATOR_JOURNAL_LOCK_INIT)
    storage_child_unlock (storage, anchor, &name, lock);
  wyl_service_credential_operation_child_name_clear (&name);
  wyl_service_credential_operation_record_clear (&next);
  wyl_service_credential_operation_record_clear (&existing);
  return rc;
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_operator_resume
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationRemediationProof * proof,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_operator_remediation (storage, anchor, request_id, proof,
      TRUE, now_us, out_replayed, out_record);
}

wyrelog_error_t
    wyl_service_credential_operation_coordinator_checkpoint_operator_revoke_and_wipe
    (const WylServiceCredentialOperationStorage * storage,
    const WylServiceCredentialOperationRootAnchor * anchor,
    const gchar * request_id,
    const WylServiceCredentialOperationRemediationProof * proof,
    gint64 now_us, gboolean * out_replayed,
    WylServiceCredentialOperationRecord * out_record)
{
  return checkpoint_operator_remediation (storage, anchor, request_id, proof,
      FALSE, now_us, out_replayed, out_record);
}
