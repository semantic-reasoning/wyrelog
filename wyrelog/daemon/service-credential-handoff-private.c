/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/service-credential-handoff-private.h"

#include "auth/service-credential-operation-coordinator-execute-private.h"
#include "auth/service-credential-operation-coordinator-private.h"
#include "auth/service-credential-operation-destination-private.h"
#include "auth/service-credential-operation-storage-private.h"
#include "wyctl/wyctl-publication-backend-private.h"

#include <string.h>

static gboolean
root_is_configured (const gchar *root)
{
  return root != NULL && root[0] != '\0';
}

static const gchar *
handoff_state_name (WylServiceCredentialOperationState state)
{
  switch (state) {
    case WYL_SERVICE_CREDENTIAL_OPERATION_PREPARED:
      return "prepared";
    case WYL_SERVICE_CREDENTIAL_OPERATION_SERVER_COMMITTED:
      return "server_committed";
    case WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PLANNED:
      return "publication_planned";
    case WYL_SERVICE_CREDENTIAL_OPERATION_PUBLICATION_PREPARED:
      return "publication_prepared";
    case WYL_SERVICE_CREDENTIAL_OPERATION_FILE_PUBLISHED:
      return "file_published";
    case WYL_SERVICE_CREDENTIAL_OPERATION_CLEANUP_REQUIRED:
      return "cleanup_required";
    case WYL_SERVICE_CREDENTIAL_OPERATION_OPERATOR_ACTION_REQUIRED:
      return "operator_action_required";
    case WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL:
      return "terminal";
    default:
      return "unknown";
  }
}

/* A handoff is delivered only when it reached the terminal state whose reason is
 * a durable file publication.  Every operator-action or non-delivered terminal
 * outcome reports delivered=false with its explicit state. */
static gboolean
handoff_record_delivered (const WylServiceCredentialOperationRecord *record)
{
  WylServiceCredentialOperationTerminalKind kind = 0;
  return record->state == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL
      && wyl_service_credential_operation_terminal_reason_parse
      (record->terminal_reason, &kind, NULL)
      && kind == WYL_SERVICE_CREDENTIAL_OPERATION_TERMINAL_FILE_PUBLISHED;
}

static void
handoff_append_json_string (GString *json, const gchar *value)
{
  if (value == NULL) {
    g_string_append (json, "null");
    return;
  }
  g_string_append_c (json, '"');
  for (const gchar * p = value; *p != '\0'; p++) {
    guchar c = (guchar) * p;
    switch (c) {
      case '"':
        g_string_append (json, "\\\"");
        break;
      case '\\':
        g_string_append (json, "\\\\");
        break;
      case '\n':
        g_string_append (json, "\\n");
        break;
      case '\r':
        g_string_append (json, "\\r");
        break;
      case '\t':
        g_string_append (json, "\\t");
        break;
      default:
        if (c < 0x20)
          g_string_append_printf (json, "\\u%04x", c);
        else
          g_string_append_c (json, (gchar) c);
        break;
    }
  }
  g_string_append_c (json, '"');
}

static gchar *
handoff_build_receipt (const WylServiceCredentialOperationRecord *record)
{
  GString *json = g_string_new ("{\"state\":");
  handoff_append_json_string (json, handoff_state_name (record->state));
  g_string_append (json, ",\"request_id\":");
  handoff_append_json_string (json, record->request_id);
  g_string_append (json, ",\"credential_id\":");
  handoff_append_json_string (json,
      record->successor_credential_id != NULL
      && record->successor_credential_id[0] != '\0' ?
      record->successor_credential_id : NULL);
  g_string_append_printf (json, ",\"generation\":%" G_GUINT64_FORMAT,
      record->successor_generation);
  g_string_append (json, ",\"destination\":");
  handoff_append_json_string (json, record->destination);
  g_string_append (json, ",\"publication_receipt_id\":");
  handoff_append_json_string (json,
      record->publication_receipt_id != NULL
      && record->publication_receipt_id[0] != '\0' ?
      record->publication_receipt_id : NULL);
  g_string_append_printf (json, ",\"delivered\":%s}",
      handoff_record_delivered (record) ? "true" : "false");
  return g_string_free (json, FALSE);
}

static void
handoff_build_request (const WylDaemonServiceCredentialHandoffContext *ctx,
    const WylDaemonServiceCredentialHandoffInputs *inputs,
    WylServiceCredentialOperationCoordinatorRequest *out)
{
  *out = (WylServiceCredentialOperationCoordinatorRequest)
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  out->kind = inputs->kind;
  out->request_id = g_strdup (inputs->request_id);
  out->destination = g_strdup (inputs->destination);
  out->parent_identity = g_strdup (inputs->parent_identity);
  out->actor_subject_id = g_strdup (ctx->authenticated_actor_subject_id);
  out->expires_at_us = inputs->expires_at_us;
  if (inputs->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE) {
    out->subject_id = g_strdup (inputs->subject_id);
    out->tenant_id = g_strdup (inputs->tenant_id);
  } else {
    out->old_credential_id = g_strdup (inputs->old_credential_id);
    out->expected_generation = inputs->expected_generation;
  }
  /* escrow_id and escrow_binding_digest are left unset: the front door derives
   * the escrow_id from request_id and the real binding is minted at
   * server-commit. */
}

wyrelog_error_t
wyl_daemon_service_credential_handoff (const
    WylDaemonServiceCredentialHandoffContext *ctx,
    const WylDaemonServiceCredentialHandoffInputs *inputs, gchar **out_json)
{
  WylServiceCredentialOperationStorage storage =
      WYL_SERVICE_CREDENTIAL_OPERATION_STORAGE_INIT;
  WylServiceCredentialOperationRootAnchor anchor =
      WYL_SERVICE_CREDENTIAL_OPERATION_ROOT_ANCHOR_INIT;
  WyctlPublicationBackend backend = { 0 };
  WylServiceCredentialOperationCoordinatorRequest request =
      WYL_SERVICE_CREDENTIAL_OPERATION_COORDINATOR_REQUEST_INIT;
  WylServiceCredentialOperationRecord record =
      WYL_SERVICE_CREDENTIAL_OPERATION_RECORD_INIT;
  wyl_service_credential_rotate_runtime_t rotate_runtime = {
    .old_credential_generation =
        inputs != NULL ? inputs->expected_generation : 0,
  };
  gboolean storage_opened = FALSE;
  gboolean backend_opened = FALSE;
  wyrelog_error_t rc;

  if (out_json != NULL)
    *out_json = NULL;
  if (ctx == NULL || inputs == NULL || out_json == NULL
      || ctx->handle == NULL || ctx->session == NULL
      || ctx->authenticated_actor_subject_id == NULL
      || ctx->guard_loc_class == NULL || ctx->decision_request_id == NULL)
    return WYRELOG_E_INVALID;

  /* Opt-in surface: an unconfigured deployment reports unavailable rather than
   * touching any state. */
  if (!root_is_configured (ctx->operation_root)
      || !root_is_configured (ctx->credential_publication_root))
    return WYRELOG_E_NOT_FOUND;

  if (inputs->kind != WYL_SERVICE_CREDENTIAL_OPERATION_ISSUE
      && inputs->kind != WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE)
    return WYRELOG_E_INVALID;
  if (!wyl_service_credential_operation_coordinator_request_id_is_valid
      (inputs->request_id)
      || !wyl_service_credential_operation_destination_is_valid
      (inputs->destination))
    return WYRELOG_E_INVALID;

  rc = wyl_service_credential_operation_storage_open (ctx->operation_root,
      &storage);
  if (rc != WYRELOG_E_OK)
    goto out;
  storage_opened = TRUE;
  rc = wyl_service_credential_operation_storage_capture_anchor (&storage,
      &anchor);
  if (rc != WYRELOG_E_OK)
    goto out;

  const WyctlPublicationBackendVTable *publication;
  gpointer publication_data;
  if (ctx->publication_override != NULL) {
    publication = ctx->publication_override;
    publication_data = ctx->publication_override_data;
  } else {
    rc = wyctl_publication_backend_open (&backend,
        ctx->credential_publication_root);
    if (rc != WYRELOG_E_OK)
      goto out;
    backend_opened = TRUE;
    publication = wyctl_publication_backend_vtable ();
    publication_data = wyctl_publication_backend_self (&backend);
  }

  handoff_build_request (ctx, inputs, &request);

  WylServiceCredentialOperationHandoffExecuteRuntime runtime = {
    .session = ctx->session,
    .authenticated_actor_subject_id = ctx->authenticated_actor_subject_id,
    .guard_timestamp = ctx->guard_timestamp,
    .guard_loc_class = ctx->guard_loc_class,
    .guard_risk = ctx->guard_risk,
    .decision_request_id = ctx->decision_request_id,
    .publication = publication,
    .publication_data = publication_data,
    .rotate_runtime = inputs->kind == WYL_SERVICE_CREDENTIAL_OPERATION_ROTATE ?
        &rotate_runtime : NULL,
    .cancellable = ctx->cancellable,
  };

  rc = wyl_service_credential_operation_coordinator_handoff (ctx->handle,
      &storage, &anchor, &request, &runtime, &record);
  if (rc == WYRELOG_E_OK)
    *out_json = handoff_build_receipt (&record);

out:
  wyl_service_credential_operation_record_clear (&record);
  wyl_service_credential_operation_coordinator_request_clear (&request);
  if (backend_opened)
    wyctl_publication_backend_close (&backend);
  if (storage_opened)
    wyl_service_credential_operation_storage_clear (&storage);
  wyl_service_credential_operation_root_anchor_clear (&anchor);
  return rc;
}
