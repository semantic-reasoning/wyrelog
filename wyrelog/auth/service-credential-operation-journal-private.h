/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION 2u
#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES (64u * 1024u)
#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_TEXT 4096u

typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE = 2,
} WylServiceCredentialOperationKind;

typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED = 2,
  WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED = 3,
  WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED = 4,
  WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED = 5,
  WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL = 6,
} WylServiceCredentialOperationState;

typedef struct
{
  guint32 version;
  WylServiceCredentialOperationKind kind;
  WylServiceCredentialOperationState state;
  gchar *operation_id;
  gchar *request_id;
  gchar *subject_id;
  gchar *tenant_id;
  gchar *destination;
  gchar *parent_identity;
  guint32 publication_receipt_version;
  gchar *reservation_id;
  gchar *stage_basename;
  gchar *stage_identity;
  gchar *old_credential_id;
  gchar *successor_credential_id;
  gchar *publication_receipt_id;
  guint64 successor_generation;
  gint64 expires_at_us;
  gint64 created_at_us;
  gint64 updated_at_us;
  guint32 attempts;
} WylServiceCredentialOperationRecord;

#define WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT { 0 }

/* Inputs and outputs follow the private DTO convention: initialize a record
 * with WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT (or clear it) before
 * encoding/decoding, and clear populated records before reuse or release. */

void wyl_service_credential_operation_record_clear
    (WylServiceCredentialOperationRecord * record);
gboolean wyl_service_credential_operation_record_is_valid
    (const WylServiceCredentialOperationRecord * record);

wyrelog_error_t
    wyl_service_credential_operation_record_encode
    (const WylServiceCredentialOperationRecord * record, GBytes ** out_bytes);
wyrelog_error_t
    wyl_service_credential_operation_record_decode
    (GBytes * bytes, WylServiceCredentialOperationRecord * out_record);

G_END_DECLS;
