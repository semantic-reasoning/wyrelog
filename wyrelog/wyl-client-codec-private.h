/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/client.h"

G_BEGIN_DECLS;

void wyl_client_sensitive_text_clear (WylClientSensitiveText * value);
void wyl_client_service_credential_handoff_receipt_clear
    (WylClientServiceCredentialHandoffReceipt * value);

wyrelog_error_t wyl_client_service_credential_handoff_receipt_decode
    (const gchar * document, gsize document_len,
    WylClientServiceCredentialHandoffReceipt * out_receipt);
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
