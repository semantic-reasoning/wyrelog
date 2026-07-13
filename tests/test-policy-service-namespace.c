/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <sqlite3.h>
#include <string.h>

#include "policy/store-private.h"
#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-handle-private.h"

static void
register_service (wyl_policy_store_t *store, const gchar *subject_id)
{
  sqlite3_stmt *stmt = NULL;
  sqlite3 *db = wyl_policy_store_get_db (store);
  g_assert_cmpint (sqlite3_prepare_v2 (db,
          "INSERT INTO service_principals "
          "(subject_id,display_name,state,generation,created_by,created_at_us,"
          "updated_at_us) VALUES (?,?,'active',1,'test-admin',1,1);",
          -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, subject_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 2, subject_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
}

static wyl_policy_store_t *
open_store (void)
{
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  return store;
}

static void
exec_fixture_sql (wyl_policy_store_t *store, const gchar *sql)
{
  gchar *message = NULL;
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL,
          NULL, &message), ==, SQLITE_OK);
  sqlite3_free (message);
}

static gint64
count_subject_rows (wyl_policy_store_t *store, const gchar *sql,
    const gchar *subject_id)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql,
          -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, subject_id, -1,
          SQLITE_TRANSIENT), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 count = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return count;
}

static void
test_lexical_guard (void)
{
  g_assert_true (wyl_policy_subject_has_service_prefix ("svc:registered"));
  g_assert_true (wyl_policy_subject_has_service_prefix ("svc:"));
  g_assert_true (wyl_policy_subject_has_service_prefix ("svc:bad/name"));
  g_assert_false (wyl_policy_subject_has_service_prefix ("human"));
  g_assert_false (wyl_policy_subject_has_service_prefix ("Svc:human"));
  g_assert_false (wyl_policy_subject_has_service_prefix (NULL));
}

static void
assert_login_rejected (WylHandle *handle, const gchar *subject_id,
    gboolean skip_mfa)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, subject_id);
  wyl_login_req_set_skip_mfa (req, skip_mfa);
  g_autoptr (WylSession) session = NULL;
  g_assert_cmpint (wyl_session_login (handle, req, &session), ==,
      WYRELOG_E_POLICY);
  g_assert_null (session);
}

static void
test_login_rejects_service_namespace (void)
{
  g_autoptr (WylHandle) handle = NULL;
  g_assert_cmpint (wyl_init (NULL, &handle), ==, WYRELOG_E_OK);
  register_service (wyl_handle_get_policy_store (handle), "svc:registered");

  const gchar *subjects[] = {
    "svc:registered", "svc:unregistered", "svc:bad/name", "svc:"
  };
  for (gsize i = 0; i < G_N_ELEMENTS (subjects); i++) {
    assert_login_rejected (handle, subjects[i], FALSE);
    assert_login_rejected (handle, subjects[i], TRUE);
  }

  g_autoptr (wyl_login_req_t) human_req = wyl_login_req_new ();
  wyl_login_req_set_username (human_req, "human.login");
  g_autoptr (WylSession) human_session = NULL;
  g_assert_cmpint (wyl_session_login (handle, human_req, &human_session), ==,
      WYRELOG_E_OK);
  g_assert_nonnull (human_session);
}

static void
test_bootstrap_rejects_service_namespace (void)
{
  wyl_policy_store_t *store = open_store ();
  register_service (store, "svc:registered");

  const gchar *subjects[] = {
    "svc:registered", "svc:unregistered", "svc:bad/name", "svc:"
  };
  for (gsize i = 0; i < G_N_ELEMENTS (subjects); i++) {
    gboolean applied = TRUE;
    gchar *existing = (gchar *) 0x1;
    g_assert_cmpint (wyl_policy_store_apply_bootstrap_admin (store,
            subjects[i], TRUE, &applied, &existing), ==, WYRELOG_E_POLICY);
    g_assert_false (applied);
    g_assert_null (existing);
  }

  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  g_assert_cmpint (wyl_policy_store_apply_bootstrap_admin (store,
          "human.bootstrap", FALSE, &applied, &existing), ==, WYRELOG_E_OK);
  g_assert_true (applied);
  g_assert_null (existing);
  wyl_policy_store_close (store);
}

static void
test_totp_rejects_service_namespace (void)
{
  wyl_policy_store_t *store = open_store ();
  register_service (store, "svc:registered");

  const gchar *subjects[] = {
    "svc:registered", "svc:unregistered", "svc:bad/name", "svc:"
  };
  for (gsize i = 0; i < G_N_ELEMENTS (subjects); i++) {
    WylTotpEnrollment enrollment = {
      .subject_id = g_strdup (subjects[i]),
      .last_verified_step = 1,
      .enrolled_at = 1,
    };
    memset (enrollment.secret, 0x5a, sizeof enrollment.secret);
    g_assert_cmpint (wyl_policy_store_totp_enrollment_insert (store,
            &enrollment), ==, WYRELOG_E_POLICY);
    wyl_totp_enrollment_clear (&enrollment);

    WylTotpEnrollment out = { 0 };
    gboolean found = TRUE;
    g_assert_cmpint (wyl_policy_store_totp_enrollment_lookup (store,
            subjects[i], &out, &found), ==, WYRELOG_E_POLICY);
    g_assert_false (found);
    g_assert_null (out.subject_id);
    g_assert_cmpint (wyl_policy_store_totp_enrollment_update_step (store,
            subjects[i], 2), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (wyl_policy_store_totp_enrollment_delete (store,
            subjects[i]), ==, WYRELOG_E_OK);
  }

  WylTotpEnrollment human = {
    .subject_id = g_strdup ("human.totp"),
    .last_verified_step = 1,
    .enrolled_at = 1,
  };
  memset (human.secret, 0x33, sizeof human.secret);
  g_assert_cmpint (wyl_policy_store_totp_enrollment_insert (store, &human), ==,
      WYRELOG_E_OK);
  wyl_totp_enrollment_clear (&human);
  g_assert_cmpint (wyl_policy_store_totp_enrollment_delete (store,
          "human.totp"), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);
}

static void
test_authorization_is_kind_aware (void)
{
  wyl_policy_store_t *store = open_store ();
  register_service (store, "svc:registered");
  g_assert_cmpint (wyl_policy_store_upsert_role (store, "app.reader",
          "application reader"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_upsert_permission (store, "app.read",
          "application read", "basic"), ==, WYRELOG_E_OK);

  g_assert_cmpint (wyl_policy_store_apply_role_membership_mutation (store,
          "svc:unregistered", "app.reader", "tenant-a", TRUE), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_apply_role_membership_mutation (store,
          "svc:", "app.reader", "tenant-a", TRUE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:unregistered", "app.read", "tenant-a", TRUE), ==,
      WYRELOG_E_POLICY);

  g_assert_cmpint (wyl_policy_store_apply_role_membership_mutation (store,
          "svc:registered", "app.reader", "tenant-a", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:registered", "app.read", "tenant-a", TRUE), ==, WYRELOG_E_OK);
  gboolean has_permission = FALSE;
  g_assert_cmpint (wyl_policy_store_subject_has_permission (store,
          "svc:registered", "app.read", "tenant-a", &has_permission), ==,
      WYRELOG_E_OK);
  g_assert_true (has_permission);
  g_assert_cmpint (wyl_policy_store_validate_service_schema (store), ==,
      WYRELOG_E_OK);

  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:registered", "wr.login.skip_mfa", "login", TRUE), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:unregistered", "wr.login.skip_mfa", "login", TRUE), ==,
      WYRELOG_E_POLICY);

  g_assert_cmpint (wyl_policy_store_apply_role_membership_mutation (store,
          "human.authz", "app.reader", "tenant-a", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "human.authz", "app.read", "tenant-a", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, "svc:bad",
          "unverified"), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_set_session_state (store, "svc:bad",
          "active"), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_apply_permission_state_transition (store,
          "svc:registered", "app.read", "tenant-a", "grant", NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_set_principal_state (store, "human.authz",
          "unverified"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_apply_permission_state_transition (store,
          "human.authz", "app.read", "tenant-a", "grant", NULL), ==,
      WYRELOG_E_OK);
  wyl_policy_store_close (store);
}

static void
test_destructive_remediation (void)
{
  wyl_policy_store_t *store = open_store ();
  register_service (store, "svc:registered");
  g_assert_cmpint (wyl_policy_store_upsert_role (store, "app.reader",
          "application reader"), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_upsert_permission (store, "app.read",
          "application read", "basic"), ==, WYRELOG_E_OK);

  exec_fixture_sql (store,
      "INSERT INTO role_memberships(subject_id,role_id,scope,granted_at) "
      "VALUES('svc:legacy','app.reader','tenant-a',unixepoch());"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at) "
      "VALUES('svc:legacy','app.read','tenant-a',unixepoch());");

  /* Preserved ordinary authorization does not register a service.  The
   * credential verify domain must require SERVICE kind before consulting any
   * general permission projection. */
  wyl_policy_principal_kind_t kind = WYL_POLICY_PRINCIPAL_KIND_HUMAN;
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store, "svc:legacy",
          &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_UNKNOWN);

  /* Audit failure occurs after delete + event append.  The wrapper must roll
   * both back so repair can be retried without a torn event. */
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation_with_audit
      (store, "svc:legacy", "app.read", "tenant-a", FALSE, "not-an-audit-id", 1,
          "repair-admin", "permission.revoke", "svc:legacy", NULL, NULL,
          "repair-request", WYL_DECISION_ALLOW), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permissions WHERE subject_id=?;",
          "svc:legacy"), ==, 1);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permission_events "
          "WHERE subject_id=? AND operation='revoke';", "svc:legacy"), ==, 0);

  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:legacy", "app.read", "tenant-a", FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permissions WHERE subject_id=?;",
          "svc:legacy"), ==, 0);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permission_events "
          "WHERE subject_id=? AND operation='revoke';", "svc:legacy"), ==, 1);

  g_assert_cmpint (wyl_policy_store_apply_role_membership_mutation (store,
          "svc:legacy", "app.reader", "tenant-a", FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM role_memberships WHERE subject_id=?;",
          "svc:legacy"), ==, 0);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM role_membership_events "
          "WHERE subject_id=? AND operation='revoke';", "svc:legacy"), ==, 1);

  exec_fixture_sql (store,
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at) "
      "VALUES('svc:registered','wr.login.skip_mfa','login',unixepoch());");
  kind = WYL_POLICY_PRINCIPAL_KIND_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:registered", &kind), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_apply_direct_permission_mutation (store,
          "svc:registered", "wr.login.skip_mfa", "login", FALSE), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permissions WHERE subject_id=? "
          "AND perm_id='wr.login.skip_mfa';", "svc:registered"), ==, 0);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM direct_permission_events "
          "WHERE subject_id=? AND perm_id='wr.login.skip_mfa' "
          "AND operation='revoke';", "svc:registered"), ==, 1);
  g_assert_cmpint (wyl_policy_store_get_principal_kind (store,
          "svc:registered", &kind), ==, WYRELOG_E_OK);
  g_assert_cmpint (kind, ==, WYL_POLICY_PRINCIPAL_KIND_SERVICE);

  exec_fixture_sql (store,
      "INSERT INTO totp_enrollments(subject_id,secret_blob,last_verified_step,"
      "enrolled_at,id_uuidv7) "
      "VALUES('svc:legacy-totp',zeroblob(20),0,1,'legacy-totp-id');");
  g_assert_cmpint (wyl_policy_store_totp_enrollment_delete (store,
          "svc:legacy-totp"), ==, WYRELOG_E_OK);
  g_assert_cmpint (count_subject_rows (store,
          "SELECT count(*) FROM totp_enrollments WHERE subject_id=?;",
          "svc:legacy-totp"), ==, 0);

  wyl_policy_store_close (store);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/service-namespace/lexical-guard",
      test_lexical_guard);
  g_test_add_func ("/policy/service-namespace/login",
      test_login_rejects_service_namespace);
  g_test_add_func ("/policy/service-namespace/bootstrap",
      test_bootstrap_rejects_service_namespace);
  g_test_add_func ("/policy/service-namespace/totp",
      test_totp_rejects_service_namespace);
  g_test_add_func ("/policy/service-namespace/authorization",
      test_authorization_is_kind_aware);
  g_test_add_func ("/policy/service-namespace/destructive-remediation",
      test_destructive_remediation);
  return g_test_run ();
}
