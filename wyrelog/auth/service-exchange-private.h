/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/auth/service-auth-coordination-private.h"
#include "wyrelog/auth/service-credential-domain-private.h"
#include "wyrelog/daemon/auth-registry-private.h"
#include "wyrelog/error.h"
#include "wyrelog/handle.h"
#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

typedef struct _WylSession WylSession;
typedef struct _WylServiceExchangePublicationTicket
    WylServiceExchangePublicationTicket;

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

typedef struct
{
  WylSession *session;
  gchar *access_token;
} WylServiceExchangePrepared;

typedef enum
{
  WYL_SERVICE_EXCHANGE_TICKET_NEW = 0,
  WYL_SERVICE_EXCHANGE_TICKET_PENDING,
  WYL_SERVICE_EXCHANGE_TICKET_LIVE,
  WYL_SERVICE_EXCHANGE_TICKET_ACTIVE,
  WYL_SERVICE_EXCHANGE_TICKET_TERMINAL,
  WYL_SERVICE_EXCHANGE_TICKET_ABORTED,
} WylServiceExchangeTicketState;

typedef struct
{
  const gchar *session_id;
  const gchar *jti;
  const gchar *credential_id;
  guint64 generation;
  const gchar *principal;
  const gchar *tenant;
  const gchar *key_id;
  gint64 expires_at;
  WylSession *session;
  const gchar *access_token;
} WylServiceExchangePublicationView;

typedef struct
{
  wyrelog_error_t (*reserve) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant);
  wyrelog_error_t (*activate) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant, gboolean * out_changed);
  wyrelog_error_t (*remove_exact) (gpointer user_data, const gchar * session_id,
      const gchar * jti, const gchar * credential_id, guint64 generation,
      const gchar * principal, const gchar * tenant, gboolean * out_removed);
  gpointer user_data;
} WylServiceExchangeRegistryHooks;

G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_begin
    (WylHandle * handle, const gchar * credential_id,
    const gchar * presented_secret, gsize presented_secret_len,
    gint64 now_us, WylServiceExchangeAuthority * out_authority);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_prepare_token
    (WylServiceExchangeAuthority * authority, const gchar * key_id,
    const gchar * issuer, const gchar * audience, gint64 issued_at_seconds,
    const guint8 * token_secret, gsize token_secret_len,
    WylServiceExchangePrepared * out_prepared);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_complete
    (WylServiceExchangeAuthority * authority, const gchar * key_id,
    const gchar * issuer, const gchar * audience, gint64 issued_at_seconds,
    const guint8 * token_secret, gsize token_secret_len,
    const WylServiceExchangeRegistryHooks * hooks,
    WylServiceExchangePrepared * out_prepared);
G_GNUC_INTERNAL wyrelog_error_t wyl_service_exchange_authority_rollback
    (WylServiceExchangeAuthority * authority);
G_GNUC_INTERNAL void wyl_service_exchange_authority_clear
    (WylServiceExchangeAuthority * authority);
G_GNUC_INTERNAL void wyl_service_exchange_prepared_clear
    (WylServiceExchangePrepared * prepared);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_new_take
    (WylServiceExchangeAuthority * authority,
    WylServiceAuthRegistry * registry, gpointer publication_context,
    const gchar * key_id, WylServiceExchangePrepared * prepared,
    WylServiceExchangePublicationTicket ** out_ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_view
    (WylServiceExchangePublicationTicket * ticket, WylHandle * handle,
    WylServiceAuthRegistry * registry, gpointer publication_context,
    WylServiceExchangePublicationView * out_view);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_reserve
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_mark_live
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_activate
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_release_terminal
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_abort
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL wyrelog_error_t
    wyl_service_exchange_publication_ticket_abort_fail_stop
    (WylServiceExchangePublicationTicket * ticket,
    WylServiceAuthUnavailableReason reason);
G_GNUC_INTERNAL WylServiceExchangeTicketState
    wyl_service_exchange_publication_ticket_get_state
    (const WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL void
    wyl_service_exchange_publication_ticket_test_corrupt_lease_serial
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL void
    wyl_service_exchange_publication_ticket_test_fail_terminal_release
    (WylServiceExchangePublicationTicket * ticket);
G_GNUC_INTERNAL void wyl_service_exchange_publication_ticket_free
    (WylServiceExchangePublicationTicket * ticket);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangeAuthority,
    wyl_service_exchange_authority_clear);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangePrepared,
    wyl_service_exchange_prepared_clear);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceExchangePublicationTicket,
    wyl_service_exchange_publication_ticket_free);

G_END_DECLS;
