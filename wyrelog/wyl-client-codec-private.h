/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/client.h"

G_BEGIN_DECLS;

typedef struct
{
  gchar *text;
  gsize len;
} WylClientSensitiveText;

typedef struct
{
  gchar *credential_id;
  guint64 generation;
  WylClientSensitiveText credential_secret;
} WylClientServiceCredentialIssueResult;

typedef struct
{
  WylClientSensitiveText access_token;
} WylClientServiceTokenResult;

void wyl_client_sensitive_text_clear (WylClientSensitiveText * value);
void wyl_client_service_credential_issue_result_clear
    (WylClientServiceCredentialIssueResult * value);
void wyl_client_service_token_result_clear (WylClientServiceTokenResult *
    value);

wyrelog_error_t wyl_client_service_credential_issue_result_decode
    (const gchar * document, gsize document_len,
    WylClientServiceCredentialIssueResult * out_result);
wyrelog_error_t wyl_client_service_token_result_decode
    (const gchar * document, gsize document_len,
    WylClientServiceTokenResult * out_result);
wyrelog_error_t wyl_client_service_principal_decode
    (const gchar * document, gsize document_len,
    WylClientServicePrincipal * out_principal);
wyrelog_error_t wyl_client_service_principal_list_decode
    (const gchar * document, gsize document_len,
    WylClientServicePrincipalList * out_principals);
wyrelog_error_t wyl_client_service_credential_decode
    (const gchar * document, gsize document_len,
    WylClientServiceCredential * out_credential);
wyrelog_error_t wyl_client_service_credential_list_decode
    (const gchar * document, gsize document_len,
    WylClientServiceCredentialList * out_credentials);

G_END_DECLS;
