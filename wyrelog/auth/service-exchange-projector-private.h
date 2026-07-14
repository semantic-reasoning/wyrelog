/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "auth/service-auth-coordination-private.h"
#include "policy/store-private.h"

#ifdef WYL_HAS_AUDIT
#include "audit/conn-private.h"

G_BEGIN_DECLS;

typedef struct _WylServiceExchangeProjectionAck WylServiceExchangeProjectionAck;

typedef struct
{
  guint64 enumerated;
  guint64 projected;
} WylServiceExchangeRecoverySummary;

typedef enum
{
  WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_NONE,
  WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_PREPARE,
  WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_STEP,
  WYL_SERVICE_EXCHANGE_RECOVERY_ENUMERATE_FAIL_ALLOCATION,
} WylServiceExchangeRecoveryEnumerateFail;

G_GNUC_INTERNAL WylServiceExchangeProjectionAck
    * wyl_service_exchange_projection_ack_ref
    (WylServiceExchangeProjectionAck * ack);
G_GNUC_INTERNAL void wyl_service_exchange_projection_ack_unref
    (WylServiceExchangeProjectionAck * ack);

G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_project_committed
    (WylHandle * handle, WylServiceAuthWriteLease * write_lease,
    const WylServiceExchangeReceipt * receipt,
    const gchar * expected_logical_name, const gchar * expected_sink_uuid,
    WylServiceExchangeProjectionAck ** out_ack);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_projection_ack_validate_receipt
    (const WylServiceExchangeProjectionAck * ack, WylHandle * handle,
    WylServiceAuthWriteLease * write_lease,
    const WylServiceExchangeReceipt * receipt,
    const gchar * expected_logical_name, const gchar * expected_sink_uuid);

G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_projection_ack_dup_record
    (const WylServiceExchangeProjectionAck * ack,
    WylServiceExchangeIntentionRecord ** out_record);

/* Deterministic one-shot allocation fault; zero disables. */
G_GNUC_INTERNAL void wyl_service_exchange_projector_fail_allocation_for_test
    (guint allocation_index);

/* Reconciles committed local intentions into the configured durable sink.
 * This is deliberately private: startup policy owns when it is scheduled. */
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_recover_committed
    (WylHandle * handle, const gchar * expected_logical_name,
    const gchar * expected_sink_uuid, GCancellable * cancellable,
    WylServiceExchangeRecoverySummary * out_summary);

/* Deterministic one-shot work-item allocation fault; zero disables. */
G_GNUC_INTERNAL void wyl_service_exchange_recovery_fail_allocation_for_test
    (guint allocation_index);
G_GNUC_INTERNAL void wyl_service_exchange_recovery_set_gap_checkpoint_for_test
    (void (*checkpoint) (gpointer data), gpointer data);
G_GNUC_INTERNAL void wyl_service_exchange_recovery_fail_enumerate_for_test
    (WylServiceExchangeRecoveryEnumerateFail stage);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangeProjectionAck,
    wyl_service_exchange_projection_ack_unref);

G_END_DECLS;
#endif
