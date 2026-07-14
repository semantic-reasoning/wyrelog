/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "auth/service-exchange-projector-private.h"

#ifdef WYL_HAS_AUDIT
#include <sodium.h>
#include <string.h>

#include "wyl-handle-private.h"

struct _WylServiceExchangeProjectionAck
{
  gint refs;
  gchar logical_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM];
  gchar sink_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF];
  WylServiceExchangeIntentionRecord *record;
  WylServiceExchangeReceiptIdentity receipt_identity;
  gint64 sequence_no;
  gchar record_hash[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
  gchar checkpoint_root[WYL_SERVICE_EXCHANGE_PAYLOAD_DIGEST_HEX_BUF];
};

static gint fail_allocation_at;
static gint allocation_count;

void
wyl_service_exchange_projector_fail_allocation_for_test (guint index)
{
  g_atomic_int_set (&allocation_count, 0);
  g_atomic_int_set (&fail_allocation_at, (gint) index);
}

static gboolean
allocation_allowed (void)
{
  gint count = g_atomic_int_add (&allocation_count, 1) + 1;
  gint fail = g_atomic_int_get (&fail_allocation_at);
  if (fail > 0 && count == fail) {
    g_atomic_int_set (&fail_allocation_at, 0);
    return FALSE;
  }
  return TRUE;
}

static WylServiceExchangeIntentionRecord *
record_clone (const WylServiceExchangeIntentionRecord *source)
{
  if (source == NULL || source->service_principal == NULL
      || source->tenant_id == NULL
      || source->material.canonical_payload == NULL)
    return NULL;
  WylServiceExchangeIntentionRecord *copy = allocation_allowed ()?
      g_try_new0 (WylServiceExchangeIntentionRecord, 1) : NULL;
  if (copy == NULL)
    return NULL;
  copy->service_principal = allocation_allowed ()?
      g_try_malloc (strlen (source->service_principal) + 1) : NULL;
  copy->tenant_id = allocation_allowed ()?
      g_try_malloc (strlen (source->tenant_id) + 1) : NULL;
  if (copy->service_principal == NULL || copy->tenant_id == NULL) {
    wyl_service_exchange_intention_record_free (copy);
    return NULL;
  }
  strcpy (copy->service_principal, source->service_principal);
  strcpy (copy->tenant_id, source->tenant_id);
  copy->material = source->material;
  copy->material.canonical_payload = g_bytes_ref
      (source->material.canonical_payload);
  memcpy (copy->credential_id, source->credential_id,
      sizeof copy->credential_id);
  copy->credential_generation = source->credential_generation;
  copy->created_at_us = source->created_at_us;
  return copy;
}

static gboolean
record_equal (const WylServiceExchangeIntentionRecord *a,
    const WylServiceExchangeIntentionRecord *b)
{
  return a != NULL && b != NULL
      && memcmp (&a->material.intention_id, &b->material.intention_id,
      sizeof a->material.intention_id) == 0
      && memcmp (&a->material.request_id, &b->material.request_id,
      sizeof a->material.request_id) == 0
      && memcmp (&a->material.session_fingerprint,
      &b->material.session_fingerprint,
      sizeof a->material.session_fingerprint) == 0
      && memcmp (&a->material.jti_fingerprint, &b->material.jti_fingerprint,
      sizeof a->material.jti_fingerprint) == 0
      && memcmp (&a->material.payload_digest, &b->material.payload_digest,
      sizeof a->material.payload_digest) == 0
      && g_bytes_equal (a->material.canonical_payload,
      b->material.canonical_payload)
      && memcmp (a->credential_id, b->credential_id,
      sizeof a->credential_id) == 0
      && a->credential_generation == b->credential_generation
      && strcmp (a->service_principal, b->service_principal) == 0
      && strcmp (a->tenant_id, b->tenant_id) == 0
      && a->created_at_us == b->created_at_us;
}

static WylAuditServiceExchangeProjection
projection_from_record (const WylServiceExchangeIntentionRecord *record)
{
  return (WylAuditServiceExchangeProjection) {
  .intention_id = record->material.intention_id,.payload_digest =
        record->material.payload_digest,.request_id =
        record->material.request_id,.credential_id =
        record->credential_id,.credential_generation =
        record->credential_generation,.service_principal =
        record->service_principal,.tenant_id =
        record->tenant_id,.created_at_us =
        record->created_at_us,.payload_schema_version =
        WYL_SERVICE_EXCHANGE_PAYLOAD_SCHEMA_VERSION,.fingerprint_schema_version
        =
        WYL_SERVICE_EXCHANGE_FINGERPRINT_SCHEMA_VERSION,.session_fingerprint =
        record->material.session_fingerprint,.jti_fingerprint =
        record->material.jti_fingerprint,.canonical_payload =
        record->material.canonical_payload,};
}

WylServiceExchangeProjectionAck *
wyl_service_exchange_projection_ack_ref (WylServiceExchangeProjectionAck *ack)
{
  if (ack == NULL)
    return NULL;
  gint refs;
  do {
    refs = g_atomic_int_get (&ack->refs);
    if (refs <= 0 || refs == G_MAXINT)
      return NULL;
  } while (!g_atomic_int_compare_and_exchange (&ack->refs, refs, refs + 1));
  return ack;
}

void
wyl_service_exchange_projection_ack_unref (WylServiceExchangeProjectionAck *ack)
{
  if (ack == NULL || !g_atomic_int_dec_and_test (&ack->refs))
    return;
  wyl_service_exchange_intention_record_free (ack->record);
  sodium_memzero (ack, sizeof *ack);
  g_free (ack);
}

static gboolean
expected_identity_valid (const gchar *name, const gchar *uuid)
{
  wyl_id_t parsed;
  gchar canonical[WYL_SERVICE_EXCHANGE_UUID_BUF];
  return name != NULL && strcmp (name, WYL_AUDIT_SERVICE_EXCHANGE_STREAM) == 0
      && uuid != NULL && strlen (uuid) == WYL_SERVICE_EXCHANGE_UUID_LEN
      && wyl_id_parse (uuid, &parsed) == WYRELOG_E_OK
      && wyl_id_format (&parsed, canonical, sizeof canonical) == WYRELOG_E_OK
      && strcmp (uuid, canonical) == 0;
}

wyrelog_error_t
wyl_service_exchange_project_committed (WylHandle *handle,
    WylServiceAuthWriteLease *write_lease,
    const WylServiceExchangeReceipt *receipt, const gchar *expected_name,
    const gchar *expected_uuid, WylServiceExchangeProjectionAck **out_ack)
{
  if (out_ack != NULL)
    *out_ack = NULL;
  if (out_ack == NULL || !WYL_IS_HANDLE (handle) || write_lease == NULL
      || receipt == NULL || !expected_identity_valid (expected_name,
          expected_uuid))
    return WYRELOG_E_INVALID;
  WylServiceExchangeIntentionClassification classification =
      wyl_service_exchange_receipt_get_classification (receipt);
  if (classification != WYL_SERVICE_EXCHANGE_INTENTION_CREATED
      && classification != WYL_SERVICE_EXCHANGE_INTENTION_REPLAY)
    return WYRELOG_E_INVALID;

  wyl_policy_store_t *leased_store = NULL;
  WylServiceAuthUnavailableReason unavailable =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  wyrelog_error_t rc = wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &unavailable);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store
        (write_lease, handle, &leased_store);
  if (rc == WYRELOG_E_OK
      && wyl_policy_store_service_authority_transaction_is_active
      (leased_store))
    rc = WYRELOG_E_BUSY;
  wyl_policy_store_t *fresh_store = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_handle_policy_store_pin_current (handle, &fresh_store);
  if (rc == WYRELOG_E_OK && fresh_store != leased_store)
    rc = WYRELOG_E_INVALID;
  WylServiceExchangeReceiptIdentity receipt_identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_exchange_receipt_snapshot_for_active_write (receipt,
        write_lease, handle, fresh_store, &receipt_identity);
  g_autoptr (WylServiceExchangeIntentionRecord) record = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_exchange_receipt_dup_record (receipt, &record);
  if (rc == WYRELOG_E_OK) {
    WylAuditServiceExchangeProjection projection =
        projection_from_record (record);
    rc = wyl_service_exchange_audit_projection_validate (&projection);
  }

  wyl_audit_conn_t *conn = NULL;
  gchar actual_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM] = { 0 };
  gchar actual_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF] = { 0 };
  if (rc == WYRELOG_E_OK) {
    conn = wyl_handle_get_audit_conn (handle);
    if (conn == NULL)
      rc = WYRELOG_E_INVALID;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_audit_conn_service_exchange_get_sink_identity (conn,
        actual_name, actual_uuid);
  if (rc == WYRELOG_E_OK && (strcmp (actual_name, expected_name) != 0
          || strcmp (actual_uuid, expected_uuid) != 0))
    rc = WYRELOG_E_INVALID;
  WylAuditServiceExchangeProjectionReadback readback = { 0 };
  if (rc == WYRELOG_E_OK) {
    WylAuditServiceExchangeProjection projection =
        projection_from_record (record);
    rc = wyl_audit_conn_service_exchange_project (conn, &projection, &readback);
  }
  WylServiceExchangeProjectionAck *ack = NULL;
  if (rc == WYRELOG_E_OK) {
    if (strcmp (readback.sink_uuid, expected_uuid) != 0
        || strcmp (readback.intention_id, record->material.intention_id) != 0
        || strcmp (readback.payload_digest,
            record->material.payload_digest) != 0 || readback.sequence_no <= 0
        || readback.record_hash[0] == '\0'
        || strcmp (readback.record_hash, readback.checkpoint_root) != 0)
      rc = WYRELOG_E_POLICY;
  }
  if (rc == WYRELOG_E_OK) {
    ack = allocation_allowed ()?
        g_try_new0 (WylServiceExchangeProjectionAck, 1) : NULL;
    if (ack == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc == WYRELOG_E_OK) {
    ack->record = record_clone (record);
    if (ack->record == NULL)
      rc = WYRELOG_E_NOMEM;
  }
  if (rc == WYRELOG_E_OK) {
    g_atomic_int_set (&ack->refs, 1);
    ack->receipt_identity = receipt_identity;
    memcpy (ack->logical_name, actual_name, sizeof ack->logical_name);
    memcpy (ack->sink_uuid, actual_uuid, sizeof ack->sink_uuid);
    ack->sequence_no = readback.sequence_no;
    memcpy (ack->record_hash, readback.record_hash, sizeof ack->record_hash);
    memcpy (ack->checkpoint_root, readback.checkpoint_root,
        sizeof ack->checkpoint_root);
    *out_ack = ack;
    ack = NULL;
  }
  if (ack != NULL) {
    wyl_service_exchange_intention_record_free (ack->record);
    sodium_memzero (ack, sizeof *ack);
    g_free (ack);
  }
  sodium_memzero (&readback, sizeof readback);
  sodium_memzero (actual_uuid, sizeof actual_uuid);
  if (fresh_store != NULL)
    wyl_handle_policy_store_unpin (handle, fresh_store);
  return rc;
}

wyrelog_error_t
    wyl_service_exchange_projection_ack_validate_receipt
    (const WylServiceExchangeProjectionAck * ack, WylHandle * handle,
    WylServiceAuthWriteLease * write_lease,
    const WylServiceExchangeReceipt * receipt, const gchar * expected_name,
    const gchar * expected_uuid)
{
  if (ack == NULL || !WYL_IS_HANDLE (handle) || write_lease == NULL
      || receipt == NULL
      || !expected_identity_valid (expected_name, expected_uuid)
      || strcmp (ack->logical_name, expected_name) != 0
      || strcmp (ack->sink_uuid, expected_uuid) != 0 || ack->sequence_no <= 0
      || strcmp (ack->record_hash, ack->checkpoint_root) != 0)
    return WYRELOG_E_INVALID;
  wyl_policy_store_t *store = NULL;
  WylServiceAuthUnavailableReason unavailable =
      WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  wyrelog_error_t rc = wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &unavailable);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_auth_write_lease_get_policy_store (write_lease, handle,
        &store);
  if (rc == WYRELOG_E_OK
      && wyl_policy_store_service_authority_transaction_is_active (store))
    rc = WYRELOG_E_BUSY;
  wyl_policy_store_t *fresh_store = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_handle_policy_store_pin_current (handle, &fresh_store);
  if (rc == WYRELOG_E_OK && fresh_store != store)
    rc = WYRELOG_E_INVALID;
  WylServiceExchangeReceiptIdentity identity = { 0 };
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_exchange_receipt_snapshot_for_active_write (receipt,
        write_lease, handle, fresh_store, &identity);
  g_autoptr (WylServiceExchangeIntentionRecord) record = NULL;
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_exchange_receipt_dup_record (receipt, &record);
  if (rc == WYRELOG_E_OK
      && (memcmp (&ack->receipt_identity, &identity, sizeof identity) != 0
          || !record_equal (ack->record, record)))
    rc = WYRELOG_E_INVALID;
  gchar actual_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM] = { 0 };
  gchar actual_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF] = { 0 };
  wyl_audit_conn_t *conn = NULL;
  if (rc == WYRELOG_E_OK) {
    conn = wyl_handle_get_audit_conn (handle);
    if (conn == NULL)
      rc = WYRELOG_E_INVALID;
  }
  if (rc == WYRELOG_E_OK)
    rc = wyl_audit_conn_service_exchange_get_sink_identity (conn,
        actual_name, actual_uuid);
  if (rc == WYRELOG_E_OK && (strcmp (actual_name, expected_name) != 0
          || strcmp (actual_uuid, expected_uuid) != 0))
    rc = WYRELOG_E_INVALID;
  WylAuditServiceExchangeProjectionReadback readback = { 0 };
  if (rc == WYRELOG_E_OK) {
    WylAuditServiceExchangeProjection projection =
        projection_from_record (record);
    rc = wyl_audit_conn_service_exchange_project (conn, &projection, &readback);
  }
  if (rc == WYRELOG_E_OK
      && (readback.sequence_no != ack->sequence_no
          || strcmp (readback.sink_uuid, ack->sink_uuid) != 0
          || strcmp (readback.intention_id,
              ack->record->material.intention_id) != 0
          || strcmp (readback.payload_digest,
              ack->record->material.payload_digest) != 0
          || strcmp (readback.record_hash, ack->record_hash) != 0
          || strcmp (readback.checkpoint_root, ack->checkpoint_root) != 0))
    rc = WYRELOG_E_POLICY;
  sodium_memzero (&readback, sizeof readback);
  sodium_memzero (actual_uuid, sizeof actual_uuid);
  if (fresh_store != NULL)
    wyl_handle_policy_store_unpin (handle, fresh_store);
  return rc;
}

wyrelog_error_t
    wyl_service_exchange_projection_ack_dup_record
    (const WylServiceExchangeProjectionAck * ack,
    WylServiceExchangeIntentionRecord ** out_record)
{
  if (out_record != NULL)
    *out_record = NULL;
  if (ack == NULL || out_record == NULL)
    return WYRELOG_E_INVALID;
  *out_record = record_clone (ack->record);
  return *out_record != NULL ? WYRELOG_E_OK : WYRELOG_E_NOMEM;
}
#endif
