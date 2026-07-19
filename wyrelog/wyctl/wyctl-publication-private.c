/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyctl-publication-private.h"

#include <sodium.h>
#include <string.h>

G_STATIC_ASSERT (WYCTL_PUBLICATION_PROTOCOL_VERSION
    == WYCTL_PUBLICATION_PLAN_VERSION);

static gboolean
string_is_present (const gchar *value)
{
  return value != NULL && value[0] != '\0' && memchr (value, '\0',
      strlen (value)) == NULL;
}

static gboolean
reservation_id_is_valid (const gchar *value)
{
  wyl_id_t id;
  return value != NULL && wyl_id_parse (value, &id) == WYRELOG_E_OK;
}

static gboolean
stage_basename_is_valid (const gchar *value)
{
  const gchar *p;

  if (!string_is_present (value))
    return FALSE;
  if (g_str_has_prefix (value, "."))
    return FALSE;
  if (strchr (value, '/') != NULL || strchr (value, '\\') != NULL)
    return FALSE;
  for (p = value; *p != '\0'; p++) {
    if (!g_ascii_isalnum (*p) && *p != '-' && *p != '_')
      return FALSE;
  }
  return TRUE;
}

static gboolean
credential_secret_is_valid (const gchar *value)
{
  static const gchar *allowed =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  if (value == NULL || strlen (value) != WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN)
    return FALSE;
  return strspn (value, allowed) == WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN;
}

static gboolean
credential_secret_text_is_valid (const gchar *value, gsize value_len)
{
  static const gchar *allowed =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  gsize i;

  if (value == NULL || value_len != WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN)
    return FALSE;
  for (i = 0; i < value_len; i++) {
    if (strchr (allowed, value[i]) == NULL)
      return FALSE;
  }
  return TRUE;
}

gboolean
wyctl_publication_expected_credential_is_valid (const gchar *credential_id,
    const WyctlSensitiveText *credential_secret)
{
  return string_is_present (credential_id)
      && wyl_service_credential_id_is_canonical (credential_id,
      strlen (credential_id))
      && credential_secret != NULL && credential_secret->text != NULL
      && credential_secret_text_is_valid (credential_secret->text,
      credential_secret->len);
}

gboolean
wyctl_publication_credential_document_matches (const gchar *credential_id,
    const WyctlSensitiveText *credential_secret,
    const gchar *expected_credential_id,
    const WyctlSensitiveText *expected_credential_secret)
{
  return wyctl_publication_expected_credential_is_valid (credential_id,
      credential_secret)
      && wyctl_publication_expected_credential_is_valid
      (expected_credential_id, expected_credential_secret)
      && g_strcmp0 (credential_id, expected_credential_id) == 0
      && sodium_memcmp (credential_secret->text,
      expected_credential_secret->text,
      WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN) == 0;
}

static gchar *
publication_stage_basename (const gchar *destination,
    const gchar *reservation_id)
{
  gchar *basename = NULL;
  g_autofree gchar *seed = g_strconcat (reservation_id, "\n", destination,
      NULL);
  if (seed == NULL)
    return NULL;
  g_autofree gchar *digest = g_compute_checksum_for_string (G_CHECKSUM_SHA256,
      seed, -1);
  if (digest == NULL)
    return NULL;
  basename = g_strdup_printf ("wypub-%.*s", 16, digest);
  return basename;
}

static void
publication_plan_reset (WyctlPublicationPlan *plan)
{
  if (plan == NULL)
    return;
  g_clear_pointer (&plan->destination, g_free);
  g_clear_pointer (&plan->reservation_id, g_free);
  g_clear_pointer (&plan->parent_identity, g_free);
  g_clear_pointer (&plan->stage_basename, g_free);
  memset (plan, 0, sizeof *plan);
}

static void
publication_receipt_reset (WyctlPublicationReceipt *receipt)
{
  if (receipt == NULL)
    return;
  g_clear_pointer (&receipt->destination, g_free);
  g_clear_pointer (&receipt->reservation_id, g_free);
  g_clear_pointer (&receipt->parent_identity, g_free);
  g_clear_pointer (&receipt->stage_basename, g_free);
  g_clear_pointer (&receipt->stage_identity, g_free);
  memset (receipt, 0, sizeof *receipt);
}

void
wyctl_sensitive_text_clear (WyctlSensitiveText *text)
{
  if (text == NULL)
    return;
  if (text->text != NULL && text->len > 0)
    sodium_memzero (text->text, text->len);
  g_clear_pointer (&text->text, g_free);
  text->len = 0;
}

void
wyctl_publication_plan_clear (WyctlPublicationPlan *plan)
{
  publication_plan_reset (plan);
}

void
wyctl_publication_receipt_clear (WyctlPublicationReceipt *receipt)
{
  publication_receipt_reset (receipt);
}

void
wyctl_publication_result_clear (WyctlPublicationResult *result)
{
  if (result == NULL)
    return;
  memset (result, 0, sizeof *result);
}

gboolean
wyctl_publication_plan_is_valid (const WyctlPublicationPlan *plan)
{
  g_autofree gchar *expected = NULL;

  return plan != NULL
      && plan->version == WYCTL_PUBLICATION_PLAN_VERSION
      && string_is_present (plan->destination)
      && reservation_id_is_valid (plan->reservation_id)
      && string_is_present (plan->parent_identity)
      && stage_basename_is_valid (plan->stage_basename)
      && (expected = publication_stage_basename (plan->destination,
          plan->reservation_id)) != NULL
      && g_strcmp0 (plan->stage_basename, expected) == 0;
}

gboolean
wyctl_publication_receipt_is_valid (const WyctlPublicationReceipt *receipt)
{
  g_autofree gchar *expected = NULL;

  return receipt != NULL
      && receipt->version == WYCTL_PUBLICATION_RECEIPT_VERSION
      && string_is_present (receipt->destination)
      && reservation_id_is_valid (receipt->reservation_id)
      && string_is_present (receipt->parent_identity)
      && stage_basename_is_valid (receipt->stage_basename)
      && (expected = publication_stage_basename (receipt->destination,
          receipt->reservation_id)) != NULL
      && g_strcmp0 (receipt->stage_basename, expected) == 0
      && string_is_present (receipt->stage_identity);
}

gboolean
wyctl_publication_result_is_valid (const WyctlPublicationResult *result)
{
  if (result == NULL || result->version != WYCTL_PUBLICATION_RESULT_VERSION)
    return FALSE;
  switch (result->kind) {
    case WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED:
    case WYCTL_PUBLICATION_RESULT_COMMITTED_DURABLE:
    case WYCTL_PUBLICATION_RESULT_COMMITTED_DURABILITY_UNCERTAIN:
    case WYCTL_PUBLICATION_RESULT_FOREIGN_OR_UNCERTAIN:
      return TRUE;
    default:
      return FALSE;
  }
}

static wyrelog_error_t
copy_plan_from (const WyctlPublicationPlan *src, WyctlPublicationPlan *dst)
{
  if (src == NULL || dst == NULL || !wyctl_publication_plan_is_valid (src))
    return WYRELOG_E_INVALID;
  *dst = (WyctlPublicationPlan) {
  .version = src->version,.destination =
        g_strdup (src->destination),.reservation_id =
        g_strdup (src->reservation_id),.parent_identity =
        g_strdup (src->parent_identity),.stage_basename =
        g_strdup (src->stage_basename),};
  if (dst->destination == NULL || dst->reservation_id == NULL
      || dst->parent_identity == NULL || dst->stage_basename == NULL) {
    wyctl_publication_plan_clear (dst);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

static wyrelog_error_t
copy_receipt_from (const WyctlPublicationReceipt *src,
    WyctlPublicationReceipt *dst)
{
  if (src == NULL || dst == NULL || !wyctl_publication_receipt_is_valid (src))
    return WYRELOG_E_INVALID;
  *dst = (WyctlPublicationReceipt) {
  .version = src->version,.destination =
        g_strdup (src->destination),.reservation_id =
        g_strdup (src->reservation_id),.parent_identity =
        g_strdup (src->parent_identity),.stage_basename =
        g_strdup (src->stage_basename),.stage_identity =
        g_strdup (src->stage_identity),};
  if (dst->destination == NULL || dst->reservation_id == NULL
      || dst->parent_identity == NULL || dst->stage_basename == NULL
      || dst->stage_identity == NULL) {
    wyctl_publication_receipt_clear (dst);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_plan_create (const gchar *destination,
    const gchar *parent_identity, WyctlPublicationPlan *out_plan)
{
  wyl_id_t reservation_id;
  gchar reservation_buf[WYL_ID_STRING_BUF];
  gchar *stage_basename = NULL;

  if (out_plan == NULL || !string_is_present (destination)
      || !string_is_present (parent_identity))
    return WYRELOG_E_INVALID;

  if (wyl_id_new (&reservation_id) != WYRELOG_E_OK)
    return WYRELOG_E_CRYPTO;
  if (wyl_id_format (&reservation_id, reservation_buf,
          sizeof reservation_buf) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;

  stage_basename = publication_stage_basename (destination, reservation_buf);
  if (stage_basename == NULL)
    return WYRELOG_E_NOMEM;

  publication_plan_reset (out_plan);
  *out_plan = (WyctlPublicationPlan) {
  .version = WYCTL_PUBLICATION_PLAN_VERSION,.destination =
        g_strdup (destination),.reservation_id =
        g_strdup (reservation_buf),.parent_identity =
        g_strdup (parent_identity),.stage_basename = stage_basename,};
  if (out_plan->destination == NULL || out_plan->reservation_id == NULL
      || out_plan->parent_identity == NULL
      || out_plan->stage_basename == NULL) {
    wyctl_publication_plan_clear (out_plan);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_plan_clone (const WyctlPublicationPlan *plan,
    WyctlPublicationPlan *out_plan)
{
  return copy_plan_from (plan, out_plan);
}

wyrelog_error_t
wyctl_publication_receipt_create (const WyctlPublicationPlan *plan,
    const gchar *stage_identity, WyctlPublicationReceipt *out_receipt)
{
  if (out_receipt == NULL || !wyctl_publication_plan_is_valid (plan)
      || !string_is_present (stage_identity))
    return WYRELOG_E_INVALID;

  publication_receipt_reset (out_receipt);
  *out_receipt = (WyctlPublicationReceipt) {
  .version = WYCTL_PUBLICATION_RECEIPT_VERSION,.destination =
        g_strdup (plan->destination),.reservation_id =
        g_strdup (plan->reservation_id),.parent_identity =
        g_strdup (plan->parent_identity),.stage_basename =
        g_strdup (plan->stage_basename),.stage_identity =
        g_strdup (stage_identity),};
  if (out_receipt->destination == NULL || out_receipt->reservation_id == NULL
      || out_receipt->parent_identity == NULL
      || out_receipt->stage_basename == NULL
      || out_receipt->stage_identity == NULL) {
    wyctl_publication_receipt_clear (out_receipt);
    return WYRELOG_E_NOMEM;
  }
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_receipt_clone (const WyctlPublicationReceipt *receipt,
    WyctlPublicationReceipt *out_receipt)
{
  return copy_receipt_from (receipt, out_receipt);
}

wyrelog_error_t
wyctl_publication_credential_document_encode (const gchar *credential_id,
    const gchar *credential_secret, gchar **out_document)
{
  g_autoptr (GString) document = NULL;

  if (out_document == NULL)
    return WYRELOG_E_INVALID;
  *out_document = NULL;
  if (!string_is_present (credential_id)
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id))
      || !credential_secret_is_valid (credential_secret))
    return WYRELOG_E_INVALID;

  document = g_string_new ("{\"version\":1,\"credential_id\":\"");
  g_string_append (document, credential_id);
  g_string_append (document, "\",\"credential_secret\":\"");
  g_string_append (document, credential_secret);
  g_string_append (document, "\"}\n");
  *out_document = g_string_free (g_steal_pointer (&document), FALSE);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyctl_publication_credential_document_decode (const gchar *document,
    gsize document_len, gchar **out_credential_id,
    WyctlSensitiveText *out_credential_secret)
{
  const gchar *p;
  const gchar *end;
  const gchar *id_start;
  const gchar *secret_start;
  gchar *credential_id = NULL;
  gchar *secret = NULL;

  if (out_credential_id == NULL || out_credential_secret == NULL)
    return WYRELOG_E_INVALID;
  *out_credential_id = NULL;
  wyctl_sensitive_text_clear (out_credential_secret);

  if (document == NULL || document_len == 0
      || document[document_len - 1] != '\n')
    return WYRELOG_E_INVALID;

  p = document;
  end = document + document_len - 1;
  if ((gsize) (end - p) < 2)
    return WYRELOG_E_INVALID;
  if (*p++ != '{')
    return WYRELOG_E_INVALID;
  if (g_str_has_prefix (p, "\"version\":1,\"credential_id\":\"") == FALSE)
    return WYRELOG_E_INVALID;
  p += strlen ("\"version\":1,\"credential_id\":\"");
  id_start = p;
  if ((gsize) (end - p) < WYL_SERVICE_CREDENTIAL_ID_LEN + 24)
    return WYRELOG_E_INVALID;
  if (p[WYL_SERVICE_CREDENTIAL_ID_LEN] != '"'
      || p[WYL_SERVICE_CREDENTIAL_ID_LEN + 1] != ','
      || g_str_has_prefix (p + WYL_SERVICE_CREDENTIAL_ID_LEN + 2,
          "\"credential_secret\":\"") == FALSE)
    return WYRELOG_E_INVALID;
  credential_id = g_strndup (id_start, WYL_SERVICE_CREDENTIAL_ID_LEN);
  if (credential_id == NULL)
    return WYRELOG_E_NOMEM;
  if (!wyl_service_credential_id_is_canonical (credential_id,
          WYL_SERVICE_CREDENTIAL_ID_LEN)) {
    g_free (credential_id);
    return WYRELOG_E_INVALID;
  }

  secret_start = p + WYL_SERVICE_CREDENTIAL_ID_LEN + 2
      + strlen ("\"credential_secret\":\"");
  if ((gsize) (end - secret_start) < WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN + 2
      || secret_start[WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN] != '"'
      || secret_start[WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN + 1] != '}') {
    g_free (credential_id);
    return WYRELOG_E_INVALID;
  }
  secret = g_strndup (secret_start, WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN);
  if (secret == NULL) {
    g_free (credential_id);
    return WYRELOG_E_NOMEM;
  }
  if (!credential_secret_is_valid (secret)) {
    sodium_memzero (secret, strlen (secret));
    g_free (secret);
    g_free (credential_id);
    return WYRELOG_E_INVALID;
  }

  *out_credential_id = credential_id;
  out_credential_secret->text = secret;
  out_credential_secret->len = WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN;
  return WYRELOG_E_OK;
}

wyrelog_error_t
    wyctl_publication_backend_conformance_run
    (const WyctlPublicationBackendVTable * vtable, gpointer self,
    const gchar * destination, const gchar * parent_identity,
    const gchar * credential_id, const gchar * credential_secret,
    WyctlPublicationResult * out_result)
{
  WyctlPublicationPlan plan = { 0 };
  WyctlPublicationReceipt receipt = { 0 };
  WyctlPublicationResult result = { 0 };
  WyctlSensitiveText *sensitive = NULL;
  wyrelog_error_t rc;

  if (out_result == NULL || vtable == NULL)
    return WYRELOG_E_INVALID;
  if (!string_is_present (credential_id)
      || !wyl_service_credential_id_is_canonical (credential_id,
          strlen (credential_id))
      || !credential_secret_is_valid (credential_secret))
    return WYRELOG_E_INVALID;
  wyctl_publication_result_clear (out_result);

  rc = wyctl_publication_plan_create (destination, parent_identity, &plan);
  if (rc != WYRELOG_E_OK)
    return rc;

  if (vtable->plan != NULL) {
    WyctlPublicationPlan planned = { 0 };
    rc = vtable->plan (self, &plan, &planned);
    if (rc != WYRELOG_E_OK) {
      wyctl_publication_plan_clear (&plan);
      return rc;
    }
    if (!wyctl_publication_plan_is_valid (&planned)) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_plan_clear (&planned);
      return WYRELOG_E_INVALID;
    }
    wyctl_publication_plan_clear (&plan);
    plan = planned;
  }

  if (vtable->prepare != NULL) {
    rc = vtable->prepare (self, &plan, &receipt);
    if (rc != WYRELOG_E_OK) {
      wyctl_publication_plan_clear (&plan);
      return rc;
    }
  } else {
    rc = wyctl_publication_receipt_create (&plan, "stage-identity", &receipt);
    if (rc != WYRELOG_E_OK) {
      wyctl_publication_plan_clear (&plan);
      return rc;
    }
  }
  if (!wyctl_publication_receipt_is_valid (&receipt)) {
    wyctl_publication_plan_clear (&plan);
    wyctl_publication_receipt_clear (&receipt);
    return WYRELOG_E_INVALID;
  }

  sensitive = g_new0 (WyctlSensitiveText, 1);
  if (sensitive == NULL) {
    wyctl_publication_plan_clear (&plan);
    wyctl_publication_receipt_clear (&receipt);
    return WYRELOG_E_NOMEM;
  }
  sensitive->text = g_strdup (credential_secret);
  sensitive->len = credential_secret != NULL ? strlen (credential_secret) : 0;
  if (sensitive->text == NULL) {
    wyctl_publication_plan_clear (&plan);
    wyctl_publication_receipt_clear (&receipt);
    wyctl_sensitive_text_clear (sensitive);
    g_free (sensitive);
    return WYRELOG_E_NOMEM;
  }

  if (vtable->commit != NULL) {
    rc = vtable->commit (self, &receipt, credential_id, sensitive, &result);
    if (rc != WYRELOG_E_OK) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_receipt_clear (&receipt);
      wyctl_sensitive_text_clear (sensitive);
      g_free (sensitive);
      return rc;
    }
    if (!wyctl_publication_result_is_valid (&result)) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_receipt_clear (&receipt);
      wyctl_sensitive_text_clear (sensitive);
      g_free (sensitive);
      return WYRELOG_E_INVALID;
    }
  }

  if (vtable->inspect != NULL) {
    WyctlPublicationResult inspect_result = { 0 };
    rc = vtable->inspect (self, &receipt, credential_id, sensitive,
        &inspect_result);
    if (rc != WYRELOG_E_OK
        || !wyctl_publication_result_is_valid (&inspect_result)) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_receipt_clear (&receipt);
      wyctl_sensitive_text_clear (sensitive);
      g_free (sensitive);
      return rc != WYRELOG_E_OK ? rc : WYRELOG_E_INVALID;
    }
  }
  if (vtable->resync != NULL) {
    WyctlPublicationResult resync_result = { 0 };
    rc = vtable->resync (self, &receipt, credential_id, sensitive,
        &resync_result);
    if (rc != WYRELOG_E_OK
        || !wyctl_publication_result_is_valid (&resync_result)) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_receipt_clear (&receipt);
      wyctl_sensitive_text_clear (sensitive);
      g_free (sensitive);
      return rc != WYRELOG_E_OK ? rc : WYRELOG_E_INVALID;
    }
  }
  if (vtable->cleanup != NULL) {
    WyctlPublicationResult cleanup_result = { 0 };
    rc = vtable->cleanup (self, &receipt, credential_id, sensitive,
        &cleanup_result);
    if (rc != WYRELOG_E_OK
        || !wyctl_publication_result_is_valid (&cleanup_result)) {
      wyctl_publication_plan_clear (&plan);
      wyctl_publication_receipt_clear (&receipt);
      wyctl_sensitive_text_clear (sensitive);
      g_free (sensitive);
      return rc != WYRELOG_E_OK ? rc : WYRELOG_E_INVALID;
    }
    result = cleanup_result;
  }

  if (result.version == 0) {
    result = (WyctlPublicationResult) {
    .version = WYCTL_PUBLICATION_RESULT_VERSION,.kind =
          WYCTL_PUBLICATION_RESULT_PRECOMMIT_FAILED,.exact_identity =
          FALSE,.cleanup_required = FALSE,};
  }

  *out_result = result;
  wyctl_publication_plan_clear (&plan);
  wyctl_publication_receipt_clear (&receipt);
  wyctl_sensitive_text_clear (sensitive);
  g_free (sensitive);
  return WYRELOG_E_OK;
}
