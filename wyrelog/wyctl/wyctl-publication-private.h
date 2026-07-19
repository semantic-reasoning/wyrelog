/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/auth/service-credential-private.h"

G_BEGIN_DECLS;

#define WYCTL_PUBLICATION_PROTOCOL_VERSION 1u
#define WYCTL_PUBLICATION_PLAN_VERSION 1u
#define WYCTL_PUBLICATION_RECEIPT_VERSION 1u
#define WYCTL_PUBLICATION_RESULT_VERSION 1u

typedef struct wyctl_sensitive_text_t
{
  gchar *text;
  gsize len;
} WyctlSensitiveText;

typedef struct wyctl_publication_plan_t
{
  guint32 version;
  gchar *destination;
  gchar *reservation_id;
  gchar *parent_identity;
  gchar *stage_basename;
} WyctlPublicationPlan;

typedef struct wyctl_publication_receipt_t
{
  guint32 version;
  gchar *destination;
  gchar *reservation_id;
  gchar *parent_identity;
  gchar *stage_basename;
  gchar *stage_identity;
} WyctlPublicationReceipt;

typedef enum
{
  WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED = 0,
  WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE,
  WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN,
  WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN,
} WyctlPublicationResultKind;

typedef struct wyctl_publication_result_t
{
  guint32 version;
  WyctlPublicationResultKind kind;
  gboolean exact_identity;
  gboolean cleanup_required;
} WyctlPublicationResult;

typedef enum
{
  WYCTL_PUBLICATION_STAGE_EXACT_TEMP_CREATED = 0,
  WYCTL_PUBLICATION_STAGE_EXACT_DOCUMENT_WRITTEN,
  WYCTL_PUBLICATION_STAGE_EXACT_FILE_SYNCED,
  WYCTL_PUBLICATION_STAGE_EXACT_PUBLISHED,
  WYCTL_PUBLICATION_STAGE_EXACT_DIRECTORY_SYNCED,
  WYCTL_PUBLICATION_STAGE_EXACT_BEFORE_SUCCESS_RETURN,
} WyctlPublicationStageExactPoint;

typedef enum
{
  WYCTL_PUBLICATION_STAGE_EXACT_CONTINUE = 0,
  WYCTL_PUBLICATION_STAGE_EXACT_FAIL,
  /* Test-only process-loss simulation: abandon the exact current namespace
   * state without cleanup so the next invocation exercises recovery. */
  WYCTL_PUBLICATION_STAGE_EXACT_CRASH,
} WyctlPublicationStageExactAction;

typedef WyctlPublicationStageExactAction (*WyctlPublicationStageExactHook)
  (gpointer data, WyctlPublicationStageExactPoint point);

typedef struct wyctl_publication_backend_vtable_t
{
  wyrelog_error_t (*plan) (gpointer self,
      const WyctlPublicationPlan * request, WyctlPublicationPlan * out_plan);
  wyrelog_error_t (*prepare) (gpointer self,
      const WyctlPublicationPlan * plan, WyctlPublicationReceipt * out_receipt);
  /* Durably create the exact stage document, or verify an identical stage
   * left by an interrupted invocation.  A successful return with
   * COMMITTED_DURABLE is the stage commit point.  FOREIGN_OR_UNCERTAIN never
   * authorizes overwrite or cleanup. */
  wyrelog_error_t (*stage_exact) (gpointer self,
      const WyctlPublicationPlan * plan, const gchar * credential_id,
      const WyctlSensitiveText * credential_secret,
      WyctlPublicationReceipt * out_receipt,
      WyctlPublicationResult * out_result, gboolean * out_replayed);
  wyrelog_error_t (*commit) (gpointer self,
      const WyctlPublicationReceipt * receipt, const gchar * credential_id,
      const WyctlSensitiveText * credential_secret,
      WyctlPublicationResult * out_result);
  wyrelog_error_t (*inspect) (gpointer self,
      const WyctlPublicationReceipt * receipt,
      const gchar * expected_credential_id,
      const WyctlSensitiveText * expected_credential_secret,
      WyctlPublicationResult * out_result);
  wyrelog_error_t (*resync) (gpointer self,
      const WyctlPublicationReceipt * receipt,
      const gchar * expected_credential_id,
      const WyctlSensitiveText * expected_credential_secret,
      WyctlPublicationResult * out_result);
  wyrelog_error_t (*cleanup) (gpointer self,
      const WyctlPublicationReceipt * receipt,
      const gchar * expected_credential_id,
      const WyctlSensitiveText * expected_credential_secret,
      WyctlPublicationResult * out_result);
} WyctlPublicationBackendVTable;

void wyctl_sensitive_text_clear (WyctlSensitiveText * text);
gboolean wyctl_publication_expected_credential_is_valid
    (const gchar * credential_id, const WyctlSensitiveText * credential_secret);
gboolean wyctl_publication_credential_document_matches
    (const gchar * credential_id, const WyctlSensitiveText * credential_secret,
    const gchar * expected_credential_id,
    const WyctlSensitiveText * expected_credential_secret);
void wyctl_publication_plan_clear (WyctlPublicationPlan * plan);
void wyctl_publication_receipt_clear (WyctlPublicationReceipt * receipt);
void wyctl_publication_result_clear (WyctlPublicationResult * result);

gboolean wyctl_publication_plan_is_valid (const WyctlPublicationPlan * plan);
gboolean wyctl_publication_receipt_is_valid
    (const WyctlPublicationReceipt * receipt);
gboolean wyctl_publication_result_is_valid
    (const WyctlPublicationResult * result);

wyrelog_error_t wyctl_publication_plan_create (const gchar * destination,
    const gchar * parent_identity, WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_plan_clone (const WyctlPublicationPlan * plan,
    WyctlPublicationPlan * out_plan);
wyrelog_error_t wyctl_publication_receipt_create
    (const WyctlPublicationPlan * plan, const gchar * stage_identity,
    WyctlPublicationReceipt * out_receipt);
wyrelog_error_t wyctl_publication_receipt_clone
    (const WyctlPublicationReceipt * receipt,
    WyctlPublicationReceipt * out_receipt);

wyrelog_error_t wyctl_publication_backend_stage_exact
    (const WyctlPublicationBackendVTable * vtable, gpointer self,
    const WyctlPublicationPlan * plan, const gchar * credential_id,
    const WyctlSensitiveText * credential_secret,
    WyctlPublicationReceipt * out_receipt,
    WyctlPublicationResult * out_result, gboolean * out_replayed);

wyrelog_error_t wyctl_publication_credential_document_encode
    (const gchar * credential_id, const gchar * credential_secret,
    gchar ** out_document);
wyrelog_error_t wyctl_publication_credential_document_decode
    (const gchar * document, gsize document_len, gchar ** out_credential_id,
    WyctlSensitiveText * out_credential_secret);

wyrelog_error_t wyctl_publication_backend_conformance_run
    (const WyctlPublicationBackendVTable * vtable, gpointer self,
    const gchar * destination, const gchar * parent_identity,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result);

G_END_DECLS;
