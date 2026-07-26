/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "auth/jwt-private.h"
#include "auth/service-credential-domain-private.h"
#include "wyrelog/daemon/auth-registry-private.h"
#include "wyrelog/auth/service-exchange-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-layout-private.h"
#include "wyrelog/wyl-session-private.h"

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
} Fixture;

G_DEFINE_AUTOPTR_CLEANUP_FUNC (WylServiceAuthRegistry,
    wyl_service_auth_registry_unref);

static void
fixture_clear (Fixture *fixture)
{
  g_clear_object (&fixture->handle);
  if (fixture->db_path != NULL) {
    (void) g_remove (fixture->db_path);
    g_autofree gchar *clear = g_strdup_printf ("%s.wyrelog-clear",
        fixture->db_path);
    g_autofree gchar *lock = g_strdup_printf ("%s.wyrelog-lock",
        fixture->db_path);
    (void) g_remove (clear);
    (void) g_remove (lock);
  }
  if (fixture->key_path != NULL)
    (void) g_remove (fixture->key_path);
  if (fixture->audit_path != NULL)
    (void) g_remove (fixture->audit_path);
  if (fixture->dir != NULL)
    (void) g_rmdir (fixture->dir);
  g_free (fixture->key_spec);
  g_free (fixture->key_path);
  g_free (fixture->audit_path);
  g_free (fixture->db_path);
  g_free (fixture->dir);
  memset (fixture, 0, sizeof (*fixture));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (Fixture, fixture_clear);

static void
fixture_init (Fixture *fixture)
{
  fixture->dir = g_dir_make_tmp ("wyl-exchange-private-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->db_path = g_build_filename (fixture->dir, "policy.db", NULL);
  fixture->key_path = g_build_filename (fixture->dir, "policy.key", NULL);
  fixture->audit_path = g_build_filename (fixture->dir, "audit.db", NULL);
  guint8 key[32];
  for (guint i = 0; i < sizeof key; i++)
    key[i] = (guint8) (i + 1);
  g_assert_true (g_file_set_contents (fixture->key_path,
          (const gchar *) key, sizeof key, NULL));
  fixture->key_spec = g_strdup_printf ("file:%s", fixture->key_path);
  WylHandleOpenOptions options = {
    .policy_store_path = fixture->db_path,
    .policy_keyprovider_path = fixture->key_spec,
    .audit_store_path = fixture->audit_path,
    .production_mode = TRUE,
  };
  g_assert_cmpint (wyl_handle_open_with_options (&options, &fixture->handle),
      ==, WYRELOG_E_OK);
}

static void
prepare_authority (WylHandle *handle, const gchar *subject_id)
{
  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_create (handle, subject_id,
          subject_id, "admin", "principal-create", &principal), ==,
      WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-a", &created), ==,
      WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (wyl_policy_store_create_tenant
      (wyl_handle_get_policy_store (handle), "tenant-b", &created), ==,
      WYRELOG_E_OK);
}

static void
issue_service_credential (WylHandle *handle, const gchar *subject_id,
    const gchar *tenant_id, const gchar *request_id, gint64 expires_at_us,
    wyl_service_credential_issue_result_t *out)
{
  g_assert_cmpint (wyl_service_credential_issue (handle, subject_id,
          tenant_id, "admin", request_id, expires_at_us, out), ==,
      WYRELOG_E_OK);
}

static void
reservation_clear_stack (WylServiceAuthReservation *reservation)
{
  if (reservation == NULL)
    return;
  wyl_service_auth_reservation_clear (reservation);
}

static void
assert_reacquire_write (WylHandle *handle)
{
  WylServiceAuthWriteLease *lease = NULL;
  g_assert_cmpint (wyl_service_auth_authority_acquire_write
      (wyl_handle_get_service_auth_authority (handle), handle, NULL, &lease),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_write_lease_release (lease), ==,
      WYRELOG_E_OK);
  wyl_service_auth_write_lease_free (lease);
}

static void
test_begin_success_and_rollback (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:exchange:worker");

  wyl_service_credential_issue_result_t issued = { 0 };
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  issue_service_credential (handle, "svc:exchange:worker", "tenant-a",
      "exchange-issue-a", expiry, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);

  WylServiceExchangeAuthority authority = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
          issued.credential.credential_id, secret, secret_len,
          g_get_real_time (), &authority), ==, WYRELOG_E_OK);
  g_assert_true (authority.verified);
  g_assert_cmpint (authority.denial, ==, WYL_SERVICE_EXCHANGE_DENIAL_NONE);
  g_assert_nonnull (authority.transaction);
  g_assert_nonnull (authority.lease);
  g_assert_cmpstr (authority.credential.subject_id, ==, "svc:exchange:worker");
  g_assert_cmpstr (authority.credential.tenant_id, ==, "tenant-a");
  g_assert_cmpstr (authority.credential.state, ==, "active");
  g_assert_cmpint (wyl_policy_store_service_authority_transaction_get_state
      (authority.transaction), ==, WYL_SERVICE_AUTHORITY_TXN_ACTIVE);

  g_assert_cmpint (wyl_service_exchange_authority_rollback (&authority), ==,
      WYRELOG_E_OK);
  g_assert_null (authority.transaction);
  g_assert_null (authority.lease);
  g_assert_cmpint (authority.denial, ==, WYL_SERVICE_EXCHANGE_DENIAL_NONE);
  assert_reacquire_write (handle);
  wyl_service_credential_issue_result_clear (&issued);
}

static void
assert_denied_case (WylHandle *handle, const gchar *credential_id,
    const gchar *presented_secret, gsize presented_secret_len, gint64 now_us)
{
  WylServiceExchangeAuthority authority = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
          credential_id, presented_secret, presented_secret_len, now_us,
          &authority), ==, WYRELOG_E_AUTH);
  g_assert_false (authority.verified);
  g_assert_cmpint (authority.denial, ==, WYL_SERVICE_EXCHANGE_DENIAL_AUTH);
  g_assert_null (authority.transaction);
  g_assert_null (authority.lease);
  assert_reacquire_write (handle);
  wyl_service_exchange_authority_clear (&authority);
}

static void
test_denials_share_one_category (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:exchange:worker");

  wyl_service_credential_issue_result_t issued = { 0 };
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  issue_service_credential (handle, "svc:exchange:worker", "tenant-a",
      "exchange-issue-a", expiry, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);

  g_autofree gchar *wrong_secret = g_strndup (secret, secret_len);
  wrong_secret[0] = wrong_secret[0] == 'A' ? 'B' : 'A';
  assert_denied_case (handle, issued.credential.credential_id, wrong_secret,
      secret_len, g_get_real_time ());
  assert_denied_case (handle, "wlc_000000000000000000000000000",
      wrong_secret, secret_len, g_get_real_time ());

  wyl_service_credential_t revoked = { 0 };
  g_assert_cmpint (wyl_service_credential_revoke (handle,
          issued.credential.credential_id, "admin", "exchange-revoke",
          &revoked), ==, WYRELOG_E_OK);
  wyl_service_credential_clear (&revoked);
  assert_denied_case (handle, issued.credential.credential_id, secret,
      secret_len, g_get_real_time ());

  wyl_service_credential_issue_result_clear (&issued);
  issue_service_credential (handle, "svc:exchange:worker", "tenant-b",
      "exchange-issue-b", g_get_real_time () + G_USEC_PER_SEC, &issued);
  secret = wyl_service_credential_secret_peek_encoded (issued.secret,
      &secret_len);
  assert_denied_case (handle, issued.credential.credential_id, secret,
      secret_len, g_get_real_time () + 5 * G_USEC_PER_SEC);

  wyl_service_principal_t principal = { 0 };
  g_assert_cmpint (wyl_service_principal_disable (handle,
          "svc:exchange:worker", "admin", "exchange-disable", &principal),
      ==, WYRELOG_E_OK);
  wyl_service_principal_clear (&principal);
  assert_denied_case (handle, issued.credential.credential_id, secret,
      secret_len, g_get_real_time ());

  g_assert_cmpint (wyl_policy_store_set_tenant_sealed
      (wyl_handle_get_policy_store (handle), "tenant-b", TRUE), ==,
      WYRELOG_E_OK);
  assert_denied_case (handle, issued.credential.credential_id, secret,
      secret_len, g_get_real_time ());
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed
      (wyl_handle_get_policy_store (handle), "tenant-b", FALSE), ==,
      WYRELOG_E_OK);

  wyl_service_credential_issue_result_clear (&issued);
}

static void
test_prepare_token_success (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:exchange:worker");

  wyl_service_credential_issue_result_t issued = { 0 };
  gint64 expiry = g_get_real_time () + 60 * G_USEC_PER_SEC;
  issue_service_credential (handle, "svc:exchange:worker", "tenant-a",
      "exchange-issue-a", expiry, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);

  WylServiceExchangeAuthority authority = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
          issued.credential.credential_id, secret, secret_len,
          g_get_real_time (), &authority), ==, WYRELOG_E_OK);

  WylServiceExchangePrepared prepared = { 0 };
  g_autofree guint8 *token_secret = g_memdup2 ("0123456789abcdef"
      "0123456789abcdef", 32);
  g_assert_cmpint (wyl_service_exchange_authority_prepare_token (&authority,
          "test-key", "wyrelogd", "wyrelog",
          g_get_real_time () / G_USEC_PER_SEC, token_secret, 32, &prepared), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (prepared.session);
  g_assert_nonnull (prepared.access_token);
  gboolean active = wyl_session_is_active_private (prepared.session);
  gint auth_method = wyl_session_get_auth_method_private (prepared.session);
  g_assert_true (active);
  g_assert_cmpint (auth_method, ==, WYL_SESSION_AUTH_METHOD_SERVICE_CREDENTIAL);
  g_autofree gchar *subject = wyl_session_dup_service_subject_private
      (prepared.session);
  g_autofree gchar *tenant = wyl_session_dup_service_tenant_private
      (prepared.session);
  g_autofree gchar *credential_id =
      wyl_session_dup_service_credential_id_private (prepared.session);
  guint64 generation = wyl_session_get_service_credential_generation_private
      (prepared.session);
  gint64 issued_at = wyl_session_get_service_issued_at_seconds_private
      (prepared.session);
  gint64 expires_at = wyl_session_get_service_expires_at_seconds_private
      (prepared.session);
  g_assert_cmpstr (subject, ==, "svc:exchange:worker");
  g_assert_cmpstr (tenant, ==, "tenant-a");
  g_assert_cmpstr (credential_id, ==, issued.credential.credential_id);
  g_assert_cmpuint (generation, ==, issued.credential.generation);
  g_assert_cmpint (expires_at - issued_at, ==, 300);

  g_autoptr (GBytes) payload = NULL;
  g_assert_cmpint (wyl_jwt_verify_hs256_signature (prepared.access_token,
          token_secret, 32, "test-key", &payload), ==, WYRELOG_E_OK);
  wyl_jwt_access_claims_t claims = { 0 };
  g_assert_cmpint (wyl_jwt_parse_access_claims_json (payload, &claims), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (claims.auth_method, ==, "service_credential");
  g_assert_cmpstr (claims.subject, ==, "svc:exchange:worker");
  g_assert_cmpstr (claims.tenant, ==, "tenant-a");
  g_assert_cmpstr (claims.credential_id, ==, issued.credential.credential_id);
  g_assert_cmpuint (claims.credential_generation, ==,
      issued.credential.generation);
  g_assert_cmpint (claims.expires_at - claims.issued_at, ==, 300);
  wyl_jwt_access_claims_clear (&claims);

  wyl_service_exchange_prepared_clear (&prepared);
  wyl_service_exchange_authority_rollback (&authority);
  wyl_service_credential_issue_result_clear (&issued);
}

static void
test_prepare_token_rejects_invalid_inputs (void)
{
  WylServiceExchangeAuthority authority = { 0 };
  WylServiceExchangePrepared prepared = { 0 };
  guint8 secret[32] = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_prepare_token (&authority,
          "test-key", "wyrelogd", "wyrelog", 1, secret, sizeof secret,
          &prepared), ==, WYRELOG_E_INVALID);
  g_assert_null (prepared.session);
  g_assert_null (prepared.access_token);
}

static void
test_publication_ticket_lifecycle_and_exact_binding (void)
{
  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:exchange:ticket");
  g_autoptr (WylServiceAuthRegistry) registry = NULL;
  g_autoptr (WylServiceAuthRegistry) other_registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_auth_registry_new (&other_registry), ==,
      WYRELOG_E_OK);

  wyl_service_credential_issue_result_t issued = { 0 };
  issue_service_credential (handle, "svc:exchange:ticket", "tenant-a",
      "exchange-ticket", g_get_real_time () + 60 * G_USEC_PER_SEC, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);
  WylServiceExchangeAuthority authority = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
          issued.credential.credential_id, secret, secret_len,
          g_get_real_time (), &authority), ==, WYRELOG_E_OK);
  WylServiceExchangePrepared prepared = { 0 };
  guint8 token_secret[32] = "0123456789abcdef0123456789abcde";
  g_assert_cmpint (wyl_service_exchange_authority_prepare_token (&authority,
          "ticket-key", "wyrelogd", "wyrelog",
          g_get_real_time () / G_USEC_PER_SEC, token_secret,
          sizeof token_secret, &prepared), ==, WYRELOG_E_OK);
  gint publication_context = 1;
  gint other_context = 2;
  g_autoptr (WylServiceExchangePublicationTicket) ticket = NULL;
  g_assert_cmpint (wyl_service_exchange_publication_ticket_new_take
      (&authority, registry, &publication_context, "ticket-key", &prepared,
          &ticket), ==, WYRELOG_E_OK);
  g_assert_null (authority.lease);
  g_assert_null (prepared.session);
  g_assert_null (prepared.access_token);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state (ticket),
      ==, WYL_SERVICE_EXCHANGE_TICKET_NEW);

  WylServiceExchangePublicationView view = { 0 };
  g_assert_cmpint (wyl_service_exchange_publication_ticket_view (ticket,
          handle, registry, &other_context, &view), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_view (ticket,
          handle, other_registry, &publication_context, &view), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_view (ticket,
          handle, registry, &publication_context, &view), ==, WYRELOG_E_OK);
  g_assert_cmpstr (view.credential_id, ==, issued.credential.credential_id);
  g_assert_cmpuint (view.generation, ==, issued.credential.generation);
  g_assert_cmpstr (view.principal, ==, "svc:exchange:ticket");
  g_assert_cmpstr (view.tenant, ==, "tenant-a");
  g_assert_cmpstr (view.key_id, ==, "ticket-key");
  g_assert_cmpint (view.issued_at, >=, 0);
  g_assert_cmpint (view.expires_at, ==, view.issued_at + 300);
  g_assert_nonnull (view.session);
  g_assert_nonnull (view.access_token);

  g_assert_cmpint (wyl_service_exchange_publication_ticket_mark_live (ticket),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_activate (ticket),
      ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_reserve (ticket),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state (ticket),
      ==, WYL_SERVICE_EXCHANGE_TICKET_PENDING);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_reserve (ticket),
      ==, WYRELOG_E_POLICY);

  WylServiceAuthReservation snapshot = { 0 };
  WylServiceAuthState registry_state = WYL_SERVICE_AUTH_ACTIVE;
  gboolean found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry, view.session_id,
          view.jti, &snapshot, &registry_state, &found), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpint (registry_state, ==, WYL_SERVICE_AUTH_PENDING);
  reservation_clear_stack (&snapshot);

  g_assert_cmpint (wyl_service_exchange_authority_rollback (&authority), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_mark_live (ticket),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_activate (ticket),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state (ticket),
      ==, WYL_SERVICE_EXCHANGE_TICKET_ACTIVE);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_release_terminal
      (ticket), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state (ticket),
      ==, WYL_SERVICE_EXCHANGE_TICKET_TERMINAL);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_release_terminal
      (ticket), ==, WYRELOG_E_INVALID);

  registry_state = WYL_SERVICE_AUTH_PENDING;
  found = FALSE;
  g_assert_cmpint (wyl_service_auth_registry_lookup (registry, view.session_id,
          view.jti, &snapshot, &registry_state, &found), ==, WYRELOG_E_OK);
  g_assert_true (found);
  g_assert_cmpint (registry_state, ==, WYL_SERVICE_AUTH_ACTIVE);
  reservation_clear_stack (&snapshot);
  assert_reacquire_write (handle);
  wyl_service_credential_issue_result_clear (&issued);
}

static void
test_publication_ticket_abort_and_anomaly (void)
{
  for (guint target = WYL_SERVICE_EXCHANGE_TICKET_NEW;
      target <= WYL_SERVICE_EXCHANGE_TICKET_LIVE; target++) {
    g_auto (Fixture) fixture = { 0 };
    fixture_init (&fixture);
    WylHandle *handle = fixture.handle;
    prepare_authority (handle, "svc:exchange:abort");
    g_autoptr (WylServiceAuthRegistry) registry = NULL;
    g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==,
        WYRELOG_E_OK);
    wyl_service_credential_issue_result_t issued = { 0 };
    issue_service_credential (handle, "svc:exchange:abort", "tenant-a",
        "exchange-abort", g_get_real_time () + 60 * G_USEC_PER_SEC, &issued);
    gsize secret_len = 0;
    const gchar *secret = wyl_service_credential_secret_peek_encoded
        (issued.secret, &secret_len);
    WylServiceExchangeAuthority authority = { 0 };
    g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
            issued.credential.credential_id, secret, secret_len,
            g_get_real_time (), &authority), ==, WYRELOG_E_OK);
    WylServiceExchangePrepared prepared = { 0 };
    guint8 token_secret[32] = "0123456789abcdef0123456789abcde";
    g_assert_cmpint (wyl_service_exchange_authority_prepare_token (&authority,
            "abort-key", "wyrelogd", "wyrelog",
            g_get_real_time () / G_USEC_PER_SEC, token_secret,
            sizeof token_secret, &prepared), ==, WYRELOG_E_OK);
    gint publication_context = 1;
    g_autoptr (WylServiceExchangePublicationTicket) ticket = NULL;
    g_assert_cmpint (wyl_service_exchange_publication_ticket_new_take
        (&authority, registry, &publication_context, "abort-key", &prepared,
            &ticket), ==, WYRELOG_E_OK);
    WylServiceExchangePublicationView view = { 0 };
    g_assert_cmpint (wyl_service_exchange_publication_ticket_view (ticket,
            handle, registry, &publication_context, &view), ==, WYRELOG_E_OK);
    g_autofree gchar *session_id = g_strdup (view.session_id);
    g_autofree gchar *jti = g_strdup (view.jti);
    if (target >= WYL_SERVICE_EXCHANGE_TICKET_PENDING)
      g_assert_cmpint (wyl_service_exchange_publication_ticket_reserve
          (ticket), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_exchange_authority_rollback (&authority), ==,
        WYRELOG_E_OK);
    if (target >= WYL_SERVICE_EXCHANGE_TICKET_LIVE)
      g_assert_cmpint (wyl_service_exchange_publication_ticket_mark_live
          (ticket), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_exchange_publication_ticket_abort (ticket),
        ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state
        (ticket), ==, WYL_SERVICE_EXCHANGE_TICKET_ABORTED);
    g_assert_cmpint (wyl_service_exchange_publication_ticket_abort (ticket),
        ==, WYRELOG_E_INVALID);
    WylServiceAuthReservation snapshot = { 0 };
    WylServiceAuthState registry_state = WYL_SERVICE_AUTH_ACTIVE;
    gboolean found = TRUE;
    g_assert_cmpint (wyl_service_auth_registry_lookup (registry, session_id,
            jti, &snapshot, &registry_state, &found), ==, WYRELOG_E_OK);
    g_assert_false (found);
    reservation_clear_stack (&snapshot);
    assert_reacquire_write (handle);
    wyl_service_credential_issue_result_clear (&issued);
  }

  g_auto (Fixture) fixture = { 0 };
  fixture_init (&fixture);
  WylHandle *handle = fixture.handle;
  prepare_authority (handle, "svc:exchange:anomaly");
  g_autoptr (WylServiceAuthRegistry) registry = NULL;
  g_assert_cmpint (wyl_service_auth_registry_new (&registry), ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_t issued = { 0 };
  issue_service_credential (handle, "svc:exchange:anomaly", "tenant-a",
      "exchange-anomaly", g_get_real_time () + 60 * G_USEC_PER_SEC, &issued);
  gsize secret_len = 0;
  const gchar *secret = wyl_service_credential_secret_peek_encoded
      (issued.secret, &secret_len);
  WylServiceExchangeAuthority authority = { 0 };
  g_assert_cmpint (wyl_service_exchange_authority_begin (handle,
          issued.credential.credential_id, secret, secret_len,
          g_get_real_time (), &authority), ==, WYRELOG_E_OK);
  WylServiceExchangePrepared prepared = { 0 };
  guint8 token_secret[32] = "0123456789abcdef0123456789abcde";
  g_assert_cmpint (wyl_service_exchange_authority_prepare_token (&authority,
          "anomaly-key", "wyrelogd", "wyrelog",
          g_get_real_time () / G_USEC_PER_SEC, token_secret,
          sizeof token_secret, &prepared), ==, WYRELOG_E_OK);
  gint publication_context = 1;
  g_autoptr (WylServiceExchangePublicationTicket) ticket = NULL;
  g_assert_cmpint (wyl_service_exchange_publication_ticket_new_take
      (&authority, registry, &publication_context, "anomaly-key", &prepared,
          &ticket), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_reserve (ticket),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_service_exchange_authority_rollback (&authority), ==,
      WYRELOG_E_OK);
  wyl_service_exchange_publication_ticket_test_corrupt_lease_serial (ticket);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_abort (ticket), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_service_exchange_publication_ticket_get_state (ticket),
      ==, WYL_SERVICE_EXCHANGE_TICKET_ABORTED);
  WylServiceAuthUnavailableReason reason = WYL_SERVICE_AUTH_UNAVAILABLE_NONE;
  g_assert_cmpint (wyl_service_auth_authority_validate_available
      (wyl_handle_get_service_auth_authority (handle), handle, &reason), ==,
      WYRELOG_E_BUSY);
  g_assert_cmpint (reason, ==,
      WYL_SERVICE_AUTH_UNAVAILABLE_COORDINATION_INVARIANT);
  g_assert_cmpint (wyl_handle_shutdown_ordered (handle), ==, WYRELOG_E_OK);
  wyl_service_credential_issue_result_clear (&issued);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange-private/begin-success-rollback",
      test_begin_success_and_rollback);
  g_test_add_func ("/service-exchange-private/denials-one-category",
      test_denials_share_one_category);
  g_test_add_func ("/service-exchange-private/prepare-token-success",
      test_prepare_token_success);
  g_test_add_func ("/service-exchange-private/prepare-token-invalid",
      test_prepare_token_rejects_invalid_inputs);
  g_test_add_func ("/service-exchange-private/publication-ticket-lifecycle",
      test_publication_ticket_lifecycle_and_exact_binding);
  g_test_add_func ("/service-exchange-private/publication-ticket-abort",
      test_publication_ticket_abort_and_anomaly);
  return g_test_run ();
}
