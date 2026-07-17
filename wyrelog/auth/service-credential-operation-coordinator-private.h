/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include <glib.h>
#include "auth/service-credential-operation-journal-private.h"
#include "wyrelog/error.h"
G_BEGIN_DECLS;
#define WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_VERSION 1u
typedef struct
{
  guint32 version;
  WylServiceCredentialOperationKind kind;
  gchar *request_id;
  gchar *subject_id;
  gchar *tenant_id;
  /* Canonical slash-separated relative path; no backslash, absolute root,
   * drive prefix, empty, dot, or traversal component. */
  gchar *destination;
  gchar *parent_identity;
  gchar *old_credential_id;
  gint64 expires_at_us;
  guint64 expected_generation;
} WylServiceCredentialOperationCoordinatorRequest;
#define WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT { .version = WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_VERSION }
void wyl_service_credential_operation_coordinator_request_clear
    (WylServiceCredentialOperationCoordinatorRequest * request);
gboolean wyl_service_credential_operation_coordinator_request_is_valid (const
    WylServiceCredentialOperationCoordinatorRequest * request);
G_END_DECLS
