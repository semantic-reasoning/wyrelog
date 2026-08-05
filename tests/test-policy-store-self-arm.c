/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"

#define REQUEST_ID "000000000000000000000000001"
#define SERVER_ID "00000000-0000-7000-8000-000000000701"
#define SERVER_ID_2 "00000000-0000-7000-8000-000000000704"
#define AUDIT_P "00000000-0000-7000-8000-000000000702"
#define AUDIT_C "00000000-0000-7000-8000-000000000703"

static const WylPolicySelfArmBundle bundle = {
  .identity = {
        WYL_POLICY_SELF_ARM_TENANT,
        "self-arm-admin",
        "self-arm-session",
        REQUEST_ID,
      },
  .server_operation_id = SERVER_ID,
  .principal_audit_id = AUDIT_P,
  .credential_audit_id = AUDIT_C,
  .created_at_us = 1700000000123456,
};

static wyl_policy_store_t *
new_store (void)
{
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  return store;
}

static void
exec_ok (wyl_policy_store_t *store, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL, NULL,
      &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
exec_rejected (wyl_policy_store_t *store, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL, NULL,
      &message);
  sqlite3_free (message);
  g_assert_cmpint (rc, !=, SQLITE_OK);
}

static gint64
scalar (wyl_policy_store_t *store, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql,
          -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static void
assert_state_for (wyl_policy_store_t *store,
    const WylPolicySelfArmIdentity *identity,
    WylPolicySelfArmBundleState expected)
{
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
  sqlite3_int64 before =
      sqlite3_total_changes64 (wyl_policy_store_get_db (store));
  g_assert_cmpint (wyl_policy_store_classify_self_arm_bundle (store, identity,
          &state), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, expected);
  g_assert_cmpint (sqlite3_total_changes64 (wyl_policy_store_get_db (store)),
      ==, before);
}

static void
assert_state (wyl_policy_store_t *store, WylPolicySelfArmBundleState expected)
{
  assert_state_for (store, &bundle.identity, expected);
}

static void
assert_unknown_publish_no_write (wyl_policy_store_t *store)
{
  assert_state (store, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);
  sqlite3_int64 before =
      sqlite3_total_changes64 (wyl_policy_store_get_db (store));
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_PRESENT;
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (store, &bundle,
          &state), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (state, ==, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);
  g_assert_cmpint (sqlite3_total_changes64 (wyl_policy_store_get_db (store)),
      ==, before);
  g_assert_cmpint (wyl_policy_store_publication_transaction_rollback_checked
      (store), ==, WYRELOG_E_OK);
}

static void
publish_and_commit (wyl_policy_store_t *store)
{
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (store, &bundle,
          &state), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_SELF_ARM_BUNDLE_PRESENT);
  g_assert_cmpint (wyl_policy_store_publication_transaction_commit (store), ==,
      WYRELOG_E_OK);
}

static void
insert_legacy_bundle (wyl_policy_store_t *store)
{
  exec_ok (store,
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('self-arm-admin','wr.service_principal.manage',"
      " 'self-arm-session',1);"
      "INSERT INTO direct_permission_events(subject_id,perm_id,scope,"
      " operation,created_at) VALUES('self-arm-admin',"
      " 'wr.service_principal.manage','self-arm-session','grant',1);"
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('self-arm-admin','wr.service_credential.manage',"
      " 'self-arm-session',1);"
      "INSERT INTO direct_permission_events(subject_id,perm_id,scope,"
      " operation,created_at) VALUES('self-arm-admin',"
      " 'wr.service_credential.manage','self-arm-session','grant',1);"
      "INSERT INTO permission_states(subject_id,perm_id,scope,state,updated_at)"
      " VALUES('self-arm-admin','wr.service_principal.manage',"
      " 'self-arm-session','armed',1);"
      "INSERT INTO permission_state_events(subject_id,perm_id,scope,event,"
      " from_state,to_state,created_at) VALUES('self-arm-admin',"
      " 'wr.service_principal.manage','self-arm-session','grant','dormant',"
      " 'armed',1);"
      "INSERT INTO permission_states(subject_id,perm_id,scope,state,updated_at)"
      " VALUES('self-arm-admin','wr.service_credential.manage',"
      " 'self-arm-session','armed',1);"
      "INSERT INTO permission_state_events(subject_id,perm_id,scope,event,"
      " from_state,to_state,created_at) VALUES('self-arm-admin',"
      " 'wr.service_credential.manage','self-arm-session','grant','dormant',"
      " 'armed',1);"
      "INSERT INTO audit_events(id,created_at_us,subject_id,action,resource_id,"
      " deny_reason,deny_origin,request_id,decision) VALUES('" AUDIT_P
      "',100,'self-arm-admin','permission_state.grant',"
      " 'wr.service_principal.manage','grant','self-arm-session','" REQUEST_ID
      "',1);"
      "INSERT INTO audit_events(id,created_at_us,subject_id,action,resource_id,"
      " deny_reason,deny_origin,request_id,decision) VALUES('" AUDIT_C
      "',100,'self-arm-admin','permission_state.grant',"
      " 'wr.service_credential.manage','grant','self-arm-session','" REQUEST_ID
      "',1);");
}

static void
relax_legacy_timestamp_table (wyl_policy_store_t *store, const gchar *table)
{
  if (g_str_equal (table, "direct_permission_events")) {
    exec_ok (store,
        "ALTER TABLE direct_permission_events RENAME TO"
        " old_direct_permission_events;"
        "CREATE TABLE direct_permission_events("
        " event_id INTEGER PRIMARY KEY,subject_id TEXT,perm_id TEXT,"
        " scope TEXT,operation TEXT,created_at);"
        "INSERT INTO direct_permission_events SELECT *"
        " FROM old_direct_permission_events;");
  } else if (g_str_equal (table, "permission_state_events")) {
    exec_ok (store,
        "ALTER TABLE permission_state_events RENAME TO"
        " old_permission_state_events;"
        "CREATE TABLE permission_state_events("
        " event_id INTEGER PRIMARY KEY,subject_id TEXT,perm_id TEXT,"
        " scope TEXT,event TEXT,from_state TEXT,to_state TEXT,created_at);"
        "INSERT INTO permission_state_events SELECT *"
        " FROM old_permission_state_events;");
  } else if (g_str_equal (table, "audit_events")) {
    exec_ok (store,
        "ALTER TABLE audit_events RENAME TO old_audit_events;"
        "CREATE TABLE audit_events("
        " id TEXT PRIMARY KEY,created_at_us,subject_id TEXT,action TEXT,"
        " resource_id TEXT,deny_reason TEXT,deny_origin TEXT,request_id TEXT,"
        " decision INTEGER);"
        "INSERT INTO audit_events SELECT * FROM old_audit_events;");
  } else {
    g_assert_not_reached ();
  }
}

static void
test_digest_is_canonical_and_complete (void)
{
  guint8 digest[WYL_POLICY_SELF_ARM_DIGEST_BYTES] = { 0 };
  /* Independent Python/hashlib vector for LP(domain), u32be(version), then
   * each text as u32be(length)+UTF-8 bytes and each integer as u64be. */
  static const guint8 expected[WYL_POLICY_SELF_ARM_DIGEST_BYTES] = {
    0x63, 0xc0, 0xbb, 0x73, 0x30, 0xd2, 0x20, 0x1e,
    0x83, 0xca, 0xbf, 0x31, 0xf5, 0x68, 0x91, 0xb7,
    0x58, 0x54, 0x22, 0x62, 0x0b, 0xc6, 0xce, 0x02,
    0x13, 0x54, 0x3b, 0x43, 0x78, 0xd0, 0x1a, 0x42,
  };
  g_assert_cmpint (wyl_policy_store_self_arm_bundle_digest (&bundle, 1, 2, 1,
          2, digest), ==, WYRELOG_E_OK);
  g_assert_cmpmem (digest, sizeof digest, expected, sizeof expected);

  WylPolicySelfArmBundle changed = bundle;
  guint8 other[WYL_POLICY_SELF_ARM_DIGEST_BYTES] = { 0 };
#define ASSERT_CHANGED(p_direct, c_direct, p_state, c_state) \
  G_STMT_START { \
    g_assert_cmpint (wyl_policy_store_self_arm_bundle_digest (&changed, \
            (p_direct), (c_direct), (p_state), (c_state), other), ==, \
        WYRELOG_E_OK); \
    g_assert_cmpint (memcmp (digest, other, sizeof digest), !=, 0); \
    changed = bundle; \
  } G_STMT_END
  changed.server_operation_id = SERVER_ID_2;
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.identity.tenant_id = "other-tenant";
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.identity.actor_subject_id = "other-admin";
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.identity.session_id = "other-session";
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.identity.original_request_id = "000000000000000000000000002";
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.principal_audit_id = SERVER_ID_2;
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.credential_audit_id = SERVER_ID_2;
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.created_at_us++;
  ASSERT_CHANGED (1, 2, 1, 2);
  changed.created_at_us += G_USEC_PER_SEC;
  ASSERT_CHANGED (1, 2, 1, 2);
  ASSERT_CHANGED (3, 2, 1, 2);
  ASSERT_CHANGED (1, 3, 1, 2);
  ASSERT_CHANGED (1, 2, 3, 2);
  ASSERT_CHANGED (1, 2, 1, 3);
#undef ASSERT_CHANGED

  changed = bundle;
  changed.created_at_us = G_USEC_PER_SEC - 1;
  g_assert_cmpint (wyl_policy_store_self_arm_bundle_digest (&changed, 1, 2, 1,
          2, other), ==, WYRELOG_E_INVALID);
}

static void
test_present_and_immutable_noop (void)
{
  g_autoptr (wyl_policy_store_t) store = new_store ();
  assert_state (store, WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT);
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (store, &bundle,
          &state), ==, WYRELOG_E_BUSY);
  publish_and_commit (store);
  assert_state (store, WYL_POLICY_SELF_ARM_BUNDLE_PRESENT);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM direct_permissions WHERE subject_id="
          "'self-arm-admin' AND scope='self-arm-session';"), ==, 2);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM direct_permission_events WHERE subject_id="
          "'self-arm-admin' AND scope='self-arm-session';"), ==, 2);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM permission_states WHERE subject_id="
          "'self-arm-admin' AND scope='self-arm-session';"), ==, 2);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM permission_state_events WHERE subject_id="
          "'self-arm-admin' AND scope='self-arm-session';"), ==, 2);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM audit_events WHERE subject_id='self-arm-admin'"
          " AND deny_origin='self-arm-session';"), ==, 2);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM audit_intentions WHERE subject_id="
          "'self-arm-admin';"), ==, 0);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM service_management_self_arm_receipts;"), ==, 1);
  g_assert_cmpint (scalar (store,
          "SELECT count(*) FROM ("
          " SELECT granted_at AS timestamp FROM direct_permissions"
          "  WHERE subject_id='self-arm-admin' AND scope='self-arm-session'"
          " UNION ALL SELECT created_at FROM direct_permission_events"
          "  WHERE subject_id='self-arm-admin' AND scope='self-arm-session'"
          " UNION ALL SELECT updated_at FROM permission_states"
          "  WHERE subject_id='self-arm-admin' AND scope='self-arm-session'"
          " UNION ALL SELECT created_at FROM permission_state_events"
          "  WHERE subject_id='self-arm-admin' AND scope='self-arm-session'"
          ") WHERE typeof(timestamp)='integer'"
          " AND timestamp=1700000000;"), ==, 8);

  sqlite3_int64 before =
      sqlite3_total_changes64 (wyl_policy_store_get_db (store));
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (store, &bundle,
          &state), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_SELF_ARM_BUNDLE_PRESENT);
  g_assert_cmpint (sqlite3_total_changes64 (wyl_policy_store_get_db (store)),
      ==, before);
  g_assert_cmpint (wyl_policy_store_publication_transaction_commit (store), ==,
      WYRELOG_E_OK);

  exec_rejected (store,
      "UPDATE service_management_self_arm_receipts SET created_at_us=101;");
  exec_rejected (store, "DELETE FROM service_management_self_arm_receipts;");
}

static void
test_legacy_and_unknown_are_noops (void)
{
  g_autoptr (wyl_policy_store_t) legacy = new_store ();
  insert_legacy_bundle (legacy);
  assert_state (legacy, WYL_POLICY_SELF_ARM_BUNDLE_LEGACY_PRESENT);
  sqlite3_int64 before =
      sqlite3_total_changes64 (wyl_policy_store_get_db (legacy));
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (legacy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (legacy, &bundle,
          &state), ==, WYRELOG_E_OK);
  g_assert_cmpint (state, ==, WYL_POLICY_SELF_ARM_BUNDLE_LEGACY_PRESENT);
  g_assert_cmpint (sqlite3_total_changes64 (wyl_policy_store_get_db (legacy)),
      ==, before);
  g_assert_cmpint (wyl_policy_store_publication_transaction_commit (legacy), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (scalar (legacy,
          "SELECT count(*) FROM service_management_self_arm_receipts;"), ==, 0);

  g_autoptr (wyl_policy_store_t) partial = new_store ();
  exec_ok (partial,
      "INSERT INTO direct_permissions(subject_id,perm_id,scope,granted_at)"
      " VALUES('self-arm-admin','wr.service_principal.manage',"
      " 'self-arm-session',1);");
  assert_state (partial, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);
  before = sqlite3_total_changes64 (wyl_policy_store_get_db (partial));
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (partial), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (partial, &bundle,
          &state), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (sqlite3_total_changes64 (wyl_policy_store_get_db (partial)),
      ==, before);
  g_assert_cmpint (wyl_policy_store_publication_transaction_rollback_checked
      (partial), ==, WYRELOG_E_OK);
}

typedef struct
{
  const gchar *name;
  const gchar *nullable_table;
  const gchar *update_format;
} TimestampTamper;

static void
test_legacy_timestamp_storage_is_exact (void)
{
  static const TimestampTamper classes[] = {
    {"direct-grant", NULL,
        "UPDATE direct_permissions SET granted_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"direct-event", "direct_permission_events",
        "UPDATE direct_permission_events SET created_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"state", NULL,
        "UPDATE permission_states SET updated_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"state-event", "permission_state_events",
        "UPDATE permission_state_events SET created_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"audit", "audit_events",
        "UPDATE audit_events SET created_at_us=%s WHERE id='" AUDIT_P "';"},
  };
  static const gchar *const bad_values[] = { "NULL", "-1", "1.5" };

  for (guint i = 0; i < G_N_ELEMENTS (classes); i++) {
    for (guint j = 0; j < G_N_ELEMENTS (bad_values); j++) {
      g_test_message ("legacy %s timestamp=%s", classes[i].name, bad_values[j]);
      g_autoptr (wyl_policy_store_t) store = new_store ();
      insert_legacy_bundle (store);
      if (g_str_equal (bad_values[j], "NULL")
          && classes[i].nullable_table != NULL)
        relax_legacy_timestamp_table (store, classes[i].nullable_table);
      g_autofree gchar *sql =
          g_strdup_printf (classes[i].update_format, bad_values[j]);
      exec_ok (store, sql);
      assert_unknown_publish_no_write (store);
    }
  }
}

static void
test_receipt_backed_timestamp_provenance_is_exact (void)
{
  static const TimestampTamper authority_rows[] = {
    {"principal-grant", NULL,
        "UPDATE direct_permissions SET granted_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"credential-grant", NULL,
        "UPDATE direct_permissions SET granted_at=%s"
          " WHERE perm_id='wr.service_credential.manage';"},
    {"principal-direct-event", NULL,
        "UPDATE direct_permission_events SET created_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"credential-direct-event", NULL,
        "UPDATE direct_permission_events SET created_at=%s"
          " WHERE perm_id='wr.service_credential.manage';"},
    {"principal-state", NULL,
        "UPDATE permission_states SET updated_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"credential-state", NULL,
        "UPDATE permission_states SET updated_at=%s"
          " WHERE perm_id='wr.service_credential.manage';"},
    {"principal-state-event", NULL,
        "UPDATE permission_state_events SET created_at=%s"
          " WHERE perm_id='wr.service_principal.manage';"},
    {"credential-state-event", NULL,
        "UPDATE permission_state_events SET created_at=%s"
          " WHERE perm_id='wr.service_credential.manage';"},
  };
  static const gchar *const bad_values[] = {
    "1700000001", "1700000000.5"
  };

  for (guint i = 0; i < G_N_ELEMENTS (authority_rows); i++) {
    for (guint j = 0; j < G_N_ELEMENTS (bad_values); j++) {
      g_test_message ("receipt-backed %s timestamp=%s",
          authority_rows[i].name, bad_values[j]);
      g_autoptr (wyl_policy_store_t) store = new_store ();
      publish_and_commit (store);
      g_autofree gchar *sql =
          g_strdup_printf (authority_rows[i].update_format, bad_values[j]);
      exec_ok (store, sql);
      assert_unknown_publish_no_write (store);
    }
  }

  g_autoptr (wyl_policy_store_t) coordinated_real = new_store ();
  publish_and_commit (coordinated_real);
  exec_ok (coordinated_real,
      "DROP TRIGGER trg_service_self_arm_receipt_no_update;"
      "PRAGMA ignore_check_constraints=ON;"
      "UPDATE service_management_self_arm_receipts"
      " SET created_at_us=1700000000123456.5;"
      "UPDATE audit_events SET created_at_us=1700000000123456.5"
      " WHERE id IN ('" AUDIT_P "','" AUDIT_C "');"
      "PRAGMA ignore_check_constraints=OFF;");
  g_assert_cmpint (scalar (coordinated_real,
          "SELECT count(*) FROM service_management_self_arm_receipts"
          " WHERE typeof(created_at_us)='real';"), ==, 1);
  g_assert_cmpint (scalar (coordinated_real,
          "SELECT count(*) FROM audit_events"
          " WHERE typeof(created_at_us)='real';"), ==, 2);
  assert_unknown_publish_no_write (coordinated_real);
}

typedef struct
{
  const gchar *name;
  const gchar *trigger;
} FailureBoundary;

static void
test_every_insert_and_validation_boundary_rolls_back (void)
{
  static const FailureBoundary boundaries[] = {
    {"direct-principal", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " direct_permissions WHEN NEW.perm_id='wr.service_principal.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"direct-principal-event", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " direct_permission_events WHEN NEW.perm_id="
          "'wr.service_principal.manage' BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"direct-credential", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " direct_permissions WHEN NEW.perm_id='wr.service_credential.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"direct-credential-event", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " direct_permission_events WHEN NEW.perm_id="
          "'wr.service_credential.manage' BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"state-principal", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " permission_states WHEN NEW.perm_id='wr.service_principal.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"state-principal-event", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " permission_state_events WHEN NEW.perm_id="
          "'wr.service_principal.manage' BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"state-credential", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " permission_states WHEN NEW.perm_id='wr.service_credential.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"state-credential-event", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " permission_state_events WHEN NEW.perm_id="
          "'wr.service_credential.manage' BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"audit-principal", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " audit_events WHEN NEW.resource_id='wr.service_principal.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"audit-credential", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " audit_events WHEN NEW.resource_id='wr.service_credential.manage'"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
    {"receipt", "CREATE TRIGGER fail_self_arm BEFORE INSERT ON"
          " service_management_self_arm_receipts"
          " BEGIN SELECT RAISE(ABORT,'fault'); END;"},
  };
  for (guint i = 0; i < G_N_ELEMENTS (boundaries); i++) {
    g_test_message ("boundary: %s", boundaries[i].name);
    g_autoptr (wyl_policy_store_t) store = new_store ();
    exec_ok (store, boundaries[i].trigger);
    WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
    g_assert_cmpint (wyl_policy_store_publication_transaction_begin (store), ==,
        WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (store, &bundle,
            &state), !=, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_publication_transaction_rollback_checked
        (store), ==, WYRELOG_E_OK);
    exec_ok (store, "DROP TRIGGER fail_self_arm;");
    assert_state (store, WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT);
  }

  g_autoptr (wyl_policy_store_t) validation = new_store ();
  exec_ok (validation,
      "CREATE TRIGGER fail_self_arm_validation AFTER INSERT ON"
      " service_management_self_arm_receipts BEGIN"
      " INSERT INTO direct_permission_events(subject_id,perm_id,scope,"
      " operation,created_at) VALUES(NEW.actor_subject_id,"
      " 'wr.service_principal.manage',NEW.session_id,'revoke',1); END;");
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN;
  g_assert_cmpint (wyl_policy_store_publication_transaction_begin (validation),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_publish_self_arm_bundle (validation,
          &bundle, &state), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_policy_store_publication_transaction_rollback_checked
      (validation), ==, WYRELOG_E_OK);
  exec_ok (validation, "DROP TRIGGER fail_self_arm_validation;");
  assert_state (validation, WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT);
}

static int
interrupt_read (void *unused)
{
  (void) unused;
  return 1;
}

static void
test_tamper_extra_and_read_error_are_unknown (void)
{
  g_autoptr (wyl_policy_store_t) digest = new_store ();
  publish_and_commit (digest);
  exec_ok (digest,
      "DROP TRIGGER trg_service_self_arm_receipt_no_update;"
      "PRAGMA ignore_check_constraints=ON;"
      "UPDATE service_management_self_arm_receipts"
      " SET bundle_digest=zeroblob(32);"
      "PRAGMA ignore_check_constraints=OFF;");
  assert_state (digest, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) malformed = new_store ();
  publish_and_commit (malformed);
  exec_ok (malformed,
      "DROP TRIGGER trg_service_self_arm_receipt_no_update;"
      "PRAGMA ignore_check_constraints=ON;"
      "UPDATE service_management_self_arm_receipts"
      " SET operation_kind='not-self-arm';"
      "PRAGMA ignore_check_constraints=OFF;");
  assert_state (malformed, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) malformed_id = new_store ();
  publish_and_commit (malformed_id);
  exec_ok (malformed_id,
      "DROP TRIGGER trg_service_self_arm_receipt_no_update;"
      "PRAGMA ignore_check_constraints=ON;"
      "UPDATE service_management_self_arm_receipts"
      " SET principal_direct_event_id=0;"
      "PRAGMA ignore_check_constraints=OFF;");
  assert_state (malformed_id, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) request_tamper = new_store ();
  publish_and_commit (request_tamper);
  exec_ok (request_tamper,
      "UPDATE audit_events SET request_id="
      "'000000000000000000000000002' WHERE id='" AUDIT_P "';");
  assert_state (request_tamper, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) extra = new_store ();
  publish_and_commit (extra);
  exec_ok (extra,
      "INSERT INTO direct_permission_events(subject_id,perm_id,scope,"
      " operation,created_at) VALUES('self-arm-admin',"
      " 'wr.service_principal.manage','self-arm-session','revoke',1);");
  assert_state (extra, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) dormant = new_store ();
  insert_legacy_bundle (dormant);
  exec_ok (dormant,
      "UPDATE permission_states SET state='dormant'"
      " WHERE perm_id='wr.service_principal.manage';");
  assert_state (dormant, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  g_autoptr (wyl_policy_store_t) read_error = new_store ();
  sqlite3 *db = wyl_policy_store_get_db (read_error);
  sqlite3_progress_handler (db, 1, interrupt_read, NULL);
  WylPolicySelfArmBundleState state = WYL_POLICY_SELF_ARM_BUNDLE_PRESENT;
  g_assert_cmpint (wyl_policy_store_classify_self_arm_bundle (read_error,
          &bundle.identity, &state), ==, WYRELOG_E_IO);
  g_assert_cmpint (state, ==, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);
  sqlite3_progress_handler (db, 0, NULL, NULL);
}

static void
test_multiple_receipts_and_identity_isolation (void)
{
  g_autoptr (wyl_policy_store_t) store = new_store ();
  publish_and_commit (store);
  exec_ok (store,
      "DROP TRIGGER trg_service_self_arm_receipt_no_update;"
      "DROP TRIGGER trg_service_self_arm_receipt_no_delete;"
      "ALTER TABLE service_management_self_arm_receipts RENAME TO"
      " old_self_arm_receipts;"
      "CREATE TABLE service_management_self_arm_receipts("
      " server_operation_id TEXT,tenant_id TEXT,operation_kind TEXT,"
      " receipt_version INTEGER,actor_subject_id TEXT,session_id TEXT,"
      " bundle_digest BLOB,principal_permission_id TEXT,"
      " credential_permission_id TEXT,principal_direct_event_id INTEGER,"
      " credential_direct_event_id INTEGER,principal_state_event_id INTEGER,"
      " credential_state_event_id INTEGER,principal_audit_id TEXT,"
      " credential_audit_id TEXT,created_at_us INTEGER);"
      "INSERT INTO service_management_self_arm_receipts SELECT *"
      " FROM old_self_arm_receipts;"
      "INSERT INTO service_management_self_arm_receipts SELECT '" SERVER_ID_2
      "',tenant_id,operation_kind,receipt_version,actor_subject_id,session_id,"
      " bundle_digest,principal_permission_id,credential_permission_id,"
      " principal_direct_event_id,credential_direct_event_id,"
      " principal_state_event_id,credential_state_event_id,principal_audit_id,"
      " credential_audit_id,created_at_us FROM old_self_arm_receipts;");
  assert_state (store, WYL_POLICY_SELF_ARM_BUNDLE_UNKNOWN);

  WylPolicySelfArmIdentity other = bundle.identity;
  other.actor_subject_id = "other-admin";
  assert_state_for (store, &other, WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT);
  other = bundle.identity;
  other.session_id = "other-session";
  assert_state_for (store, &other, WYL_POLICY_SELF_ARM_BUNDLE_ALL_ABSENT);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/self-arm/digest",
      test_digest_is_canonical_and_complete);
  g_test_add_func ("/policy/self-arm/present-immutable-noop",
      test_present_and_immutable_noop);
  g_test_add_func ("/policy/self-arm/legacy-unknown-noop",
      test_legacy_and_unknown_are_noops);
  g_test_add_func ("/policy/self-arm/legacy-timestamp-storage",
      test_legacy_timestamp_storage_is_exact);
  g_test_add_func ("/policy/self-arm/receipt-timestamp-provenance",
      test_receipt_backed_timestamp_provenance_is_exact);
  g_test_add_func ("/policy/self-arm/rollback-boundaries",
      test_every_insert_and_validation_boundary_rolls_back);
  g_test_add_func ("/policy/self-arm/tamper-extra-read-error",
      test_tamper_extra_and_read_error_are_unknown);
  g_test_add_func ("/policy/self-arm/multiple-receipts-identity-isolation",
      test_multiple_receipts_and_identity_isolation);
  return g_test_run ();
}
