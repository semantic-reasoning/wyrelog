/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/error.h"
#include "wyrelog/handle.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef enum
{
  WYL_SERVICE_EXCHANGE_DENIAL_NONE = 0,
  WYL_SERVICE_EXCHANGE_DENIAL_AUTH = 1,
  WYL_SERVICE_EXCHANGE_DENIAL_UNAVAILABLE = 2,
} WylServiceExchangeDenial;

typedef struct
{
  WylHandle *handle;
  wyl_policy_store_t *store;
  WylServiceAuthWriteLease *lease;
  WylServiceAuthorityTransaction *transaction;
  const guint8 *cvk;
  gsize cvk_len;
  WylServiceExchangeDenial denial;
  gboolean verified;
  wyl_policy_service_credential_info_t credential;
} WylServiceExchangeAuthority;

G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_begin
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    gint64 now_us, WylServiceExchangeAuthority * out_authority);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_rollback
    (WylServiceExchangeAuthority * authority);
G_GNUC_INTERNAL void wyl_service_exchange_authority_clear
    (WylServiceExchangeAuthority * authority);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangeAuthority,
    wyl_service_exchange_authority_clear)
    G_END_DECLS;
