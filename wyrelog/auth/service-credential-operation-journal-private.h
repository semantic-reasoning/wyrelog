/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "auth/service-credential-operation-destination-private.h"

G_BEGIN_DECLS;

#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_LEGACY_VERSION 5u
#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_VERSION 6u
#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_BYTES (64u * 1024u)
#define WYL_SERVICE_CREDENTIAL_OPERATION_JOURNAL_MAX_TEXT 4096u
#define WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES 32u

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
  WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED = 6,
  WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL = 7,
  /* Appended without renumbering durable v5 state values. */
  WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED = 8,
} WylServiceCredentialOperationState;

/* OPERATOR_ACTION_REQUIRED preserves the exact state from which automatic
 * progress stopped.  The source and cause are encoded in terminal_reason by
 * the frozen oar.v1 grammar; they are never inferred from optional receipt
 * fields during resume. */
typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_FOREIGN = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_RECEIPT_UNCERTAIN = 2,
  /* Present escrow, but the exact committed tuple or binding mismatches. */
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_FOREIGN = 3,
  /* Escrow inspection is indeterminate or authoritatively unavailable. */
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_UNCERTAIN = 4,
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_REVOKED = 5,
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_SUCCESSOR_EXPIRED = 6,
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_EXPLICIT_HOLD = 7,
  /* Authoritative inspection found the exact committed escrow absent. */
  WYL_SERVICE_CREDENTIAL_OPERATION_OAR_ESCROW_MISSING = 8,
} WylServiceCredentialOperationOarCause;

typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_NOT_COMMITTED = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED = 2,
  WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_OPERATOR_REVOKE_AND_WIPE = 3,
} WylServiceCredentialOperationTerminalKind;

typedef enum
{
  WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_NONE = 0,
  WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_RESUME = 1,
  WYL_SERVICE_CREDENTIAL_OPERATION_REMEDIATION_REVOKE_AND_WIPE = 2,
} WylServiceCredentialOperationRemediationAction;

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
  /* Immutable execution identity; distinct from parent provenance. */
  gchar *actor_subject_id;
  guint32 publication_receipt_version;
  gchar *reservation_id;
  gchar *stage_basename;
  gchar *stage_identity;
  gchar *old_credential_id;
  gchar *successor_credential_id;
  /* Opaque provider-sealed escrow identity; journal bytes never carry its
   * ciphertext or the credential secret. */
  gchar *escrow_id;
    guint8
      escrow_binding_digest
      [WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES];
  gchar *publication_receipt_id;
  gchar *terminal_reason;
  /* Immutable request intent.  It never describes the successor. */
  guint64 expected_generation;
  /* Actual committed successor generation; zero before server commit. */
  guint64 successor_generation;
  gint64 expires_at_us;
  gint64 created_at_us;
  gint64 updated_at_us;
  guint32 attempts;
  /* Durable v6 proof marker.  These fields are appended to the frozen v5
   * payload and survive every transition after an explicit remediation. */
  WylServiceCredentialOperationRemediationAction last_remediation_action;
  gchar *last_remediation_request_id;
  guint8 last_remediation_source_snapshot_digest
      [WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES];
  WylServiceCredentialOperationState last_remediation_applied_target_state;
  guint8 last_remediation_request_fingerprint
      [WYL_SERVICE_CREDENTIAL_OPERATION_ESCROW_BINDING_DIGEST_BYTES];
} WylServiceCredentialOperationRecord;

#define WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT { 0 }

/* Inputs and outputs follow the private DTO convention: initialize a record
 * with WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT (or clear it) before
 * encoding/decoding, and clear populated records before reuse or release. */

void wyl_service_credential_operation_record_clear
    (WylServiceCredentialOperationRecord * record);
gboolean wyl_service_credential_operation_record_is_valid
    (const WylServiceCredentialOperationRecord * record);

gboolean wyl_service_credential_operation_oar_reason_parse
    (const gchar * reason, WylServiceCredentialOperationState * out_source,
    WylServiceCredentialOperationOarCause * out_cause);
gchar *wyl_service_credential_operation_oar_reason_format
    (WylServiceCredentialOperationState source,
    WylServiceCredentialOperationOarCause cause);
/* Outputs are unchanged on failure. out_remediation_request_id is optional;
 * on success it replaces any owned value and is non-NULL only for the
 * explicit remediation terminal kind. */
gboolean wyl_service_credential_operation_terminal_reason_parse
    (const gchar * reason, WylServiceCredentialOperationTerminalKind * out_kind,
    gchar ** out_remediation_request_id);
gchar *wyl_service_credential_operation_terminal_reason_format
    (WylServiceCredentialOperationTerminalKind kind,
    const gchar * remediation_request_id);

wyrelog_error_t
    wyl_service_credential_operation_record_encode
    (const WylServiceCredentialOperationRecord * record, GBytes ** out_bytes);
wyrelog_error_t
    wyl_service_credential_operation_record_decode
    (GBytes * bytes, WylServiceCredentialOperationRecord * out_record);

G_END_DECLS;
