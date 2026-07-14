/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/startup-recovery-private.h"

#ifdef WYL_HAS_AUDIT
#include <string.h>

#include "audit/conn-private.h"
#include "auth/service-exchange-projector-private.h"
#include "wyrelog/wyl-handle-private.h"
#endif

wyrelog_error_t
wyl_daemon_recover_service_exchange_on_startup (WylHandle *handle)
{
#ifdef WYL_HAS_AUDIT
  if (!WYL_IS_HANDLE (handle))
    return WYRELOG_E_INVALID;

  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  if (conn == NULL)
    return WYRELOG_E_INVALID;
  gchar sink_name[sizeof WYL_AUDIT_SERVICE_EXCHANGE_STREAM] = { 0 };
  gchar sink_uuid[WYL_SERVICE_EXCHANGE_UUID_BUF] = { 0 };
  WylServiceExchangeRecoverySummary summary = { 0 };
  wyrelog_error_t rc = wyl_audit_conn_service_exchange_get_sink_identity
      (conn, sink_name, sink_uuid);
  if (rc == WYRELOG_E_OK)
    rc = wyl_service_exchange_recover_committed (handle, sink_name, sink_uuid,
        NULL, &summary);
  memset (sink_uuid, 0, sizeof sink_uuid);
  return rc;
#else
  return WYL_IS_HANDLE (handle) ? WYRELOG_E_OK : WYRELOG_E_INVALID;
#endif
}
