/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "auth/service-credential-domain-private.h"
#include "wyrelog/auth/service-exchange-private.h"
#include "wyrelog/wyl-handle-private.h"

typedef struct
{
  WylHandle *handle;
  gchar *dir;
  gchar *db_path;
  gchar *audit_path;
  gchar *key_path;
  gchar *key_spec;
} Fixture;

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

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/service-exchange-private/begin-success-rollback",
      test_begin_success_and_rollback);
  g_test_add_func ("/service-exchange-private/denials-one-category",
      test_denials_share_one_category);
  return g_test_run ();
}
