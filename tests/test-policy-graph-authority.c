/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include <sodium.h>
#include <string.h>

#include "fact/recovery-mac-private.h"
#include "wyrelog/policy/store-private.h"

typedef struct
{
  guint8 key[crypto_generichash_KEYBYTES];
  gboolean wiped;
  gboolean freed;
  gboolean fail_compute;
  guint compute_calls;
  GBytes *last_label;
} RecoveryMacFakeProvider;

static wyrelog_error_t
recovery_mac_fake_compute (gpointer state_p, const guint8 *label,
    gsize label_len, const guint8 *payload, gsize payload_len,
    guint8 out_tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  RecoveryMacFakeProvider *state = state_p;
  state->compute_calls++;
  g_clear_pointer (&state->last_label, g_bytes_unref);
  state->last_label = g_bytes_new (label, label_len);
  if (state->fail_compute)
    return WYRELOG_E_CRYPTO;
  return crypto_generichash (out_tag, WYL_FACT_RECOVERY_MAC_TAG_BYTES,
             payload, payload_len, state->key, sizeof state->key) == 0
      ? WYRELOG_E_OK : WYRELOG_E_CRYPTO;
}

static wyrelog_error_t
recovery_mac_fake_verify (gpointer state_p, const guint8 *label,
    gsize label_len, const guint8 *payload, gsize payload_len,
    const guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES])
{
  guint8 expected[WYL_FACT_RECOVERY_MAC_TAG_BYTES] = { 0 };
  RecoveryMacFakeProvider *state = state_p;
  wyrelog_error_t rc = recovery_mac_fake_compute (state, label, label_len,
          payload, payload_len, expected);
  if (rc == WYRELOG_E_OK
      && sodium_memcmp (expected, tag, sizeof expected) != 0)
    rc = WYRELOG_E_POLICY;
  sodium_memzero (expected, sizeof expected);
  return rc;
}

static void
recovery_mac_test_append_u16 (GByteArray *bytes, guint16 value)
{
  guint8 encoded[] = { (guint8) (value >> 8), (guint8) value };
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
recovery_mac_test_append_u64 (GByteArray *bytes, guint64 value)
{
  guint8 encoded[8];
  for (guint i = 0; i < G_N_ELEMENTS (encoded); i++)
    encoded[i] = (guint8) (value >> (56u - i * 8u));
  g_byte_array_append (bytes, encoded, sizeof encoded);
}

static void
recovery_mac_test_append_field (GByteArray *bytes, const gchar *value)
{
  recovery_mac_test_append_u16 (bytes, (guint16) strlen (value));
  g_byte_array_append (bytes, (const guint8 *) value, strlen (value));
}

static void
recovery_mac_fake_wipe (gpointer state_p)
{
  RecoveryMacFakeProvider *state = state_p;
  sodium_memzero (state->key, sizeof state->key);
  state->wiped = TRUE;
}

static void
recovery_mac_fake_free (gpointer state_p)
{
  RecoveryMacFakeProvider *state = state_p;
  state->freed = TRUE;
}

static void
exec_ok (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  if (rc != SQLITE_OK)
    g_test_message ("sqlite error: %s", message != NULL ? message : "unknown");
  sqlite3_free (message);
  g_assert_cmpint (rc, ==, SQLITE_OK);
}

static void
exec_rejected (sqlite3 *db, const gchar *sql)
{
  char *message = NULL;
  int rc = sqlite3_exec (db, sql, NULL, NULL, &message);
  sqlite3_free (message);
  g_assert_cmpint (rc, !=, SQLITE_OK);
}

static gint64
scalar_int64 (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 value = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  return value;
}

static gchar *
scalar_text (sqlite3 *db, const gchar *sql)
{
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  const gchar *value = (const gchar *) sqlite3_column_text (stmt, 0);
  g_assert_nonnull (value);
  gchar *copy = g_strdup (value);
  sqlite3_finalize (stmt);
  return copy;
}

static void
assert_column (sqlite3 *db, const gchar *table, const gchar *column)
{
  sqlite3_stmt *stmt = NULL;
  g_autofree gchar *sql = g_strdup_printf ("PRAGMA table_info(%s);", table);
  g_assert_cmpint (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL), ==,
      SQLITE_OK);
  gboolean found = FALSE;
  while (sqlite3_step (stmt) == SQLITE_ROW) {
    const gchar *name = (const gchar *) sqlite3_column_text (stmt, 1);
    if (g_strcmp0 (name, column) == 0) {
      found = TRUE;
      break;
    }
  }
  sqlite3_finalize (stmt);
  g_assert_true (found);
}

static void
insert_graph (sqlite3 *db, const gchar *tenant_id, const gchar *graph_id,
    gboolean sealed)
{
  g_autofree gchar *sql =
      g_strdup_printf
        ("INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
          "VALUES ('%s',%d,1,1);" "INSERT INTO fact_graphs "
          "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
          "owner_scope,sealed,created_at,updated_at,sealed_at) VALUES "
          "('%s','%s','file:///legacy','/legacy',1,'%s',%d,1,1,NULL);",
          tenant_id, sealed ? 1 : 0, tenant_id, graph_id, tenant_id,
          sealed ? 1 : 0);
  exec_ok (db, sql);
}

static WylPolicyFactReconcileArtifactEvidence
valid_reconcile_evidence (void)
{
  WylPolicyFactReconcileArtifactEvidence evidence = {
    .version = WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1,
    .identity_kind = WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_POSIX,
    .posix_device = 17,
    .posix_inode = 19,
    .size_bytes = 23,
    .digest_algorithm = WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (evidence.digest); i++)
    evidence.digest[i] = (guint8) (i + 1);
  return evidence;
}

static void
assert_reconcile_evidence_equal (const WylPolicyFactReconcileArtifactEvidence
    *a, const WylPolicyFactReconcileArtifactEvidence *b)
{
  g_assert_cmpuint (a->version, ==, b->version);
  g_assert_cmpint (a->identity_kind, ==, b->identity_kind);
  g_assert_cmpuint (a->posix_device, ==, b->posix_device);
  g_assert_cmpuint (a->posix_inode, ==, b->posix_inode);
  g_assert_cmpuint (a->windows_volume_serial, ==, b->windows_volume_serial);
  g_assert_cmpuint (a->size_bytes, ==, b->size_bytes);
  g_assert_cmpint (a->digest_algorithm, ==, b->digest_algorithm);
  g_assert_cmpmem (a->windows_file_id, sizeof a->windows_file_id,
      b->windows_file_id, sizeof b->windows_file_id);
  g_assert_cmpmem (a->digest, sizeof a->digest, b->digest, sizeof b->digest);
}

static void
test_recovery_mac_handle_contract (void)
{
  RecoveryMacFakeProvider fake = { 0 };
  for (gsize i = 0; i < sizeof fake.key; i++)
    fake.key[i] = (guint8) (i + 1);
  WylFactRecoveryMacProvider provider = {
    recovery_mac_fake_compute,
    recovery_mac_fake_verify,
    recovery_mac_fake_wipe,
    recovery_mac_fake_free,
    &fake,
  };
  g_autoptr (WylFactRecoveryMacHandle) handle =
      wyl_fact_recovery_mac_handle_new (&provider, "key-7", 7,
          "tenant-a", "graph-a", "operation-a");
  g_assert_nonnull (handle);
  g_assert_cmpuint (wyl_fact_recovery_mac_handle_get_generation (handle), ==,
      7);
  g_assert_cmpstr (wyl_fact_recovery_mac_handle_get_key_id (handle), ==,
      "key-7");
  g_assert_true (wyl_fact_recovery_mac_handle_scope_matches (handle,
      "tenant-a", "graph-a", "operation-a", 7));
  g_assert_false (wyl_fact_recovery_mac_handle_scope_matches (handle,
      "tenant-a", "graph-a", "operation-a", 6));
  g_assert_false (wyl_fact_recovery_mac_handle_scope_matches (handle,
      "tenant-b", "graph-a", "operation-a", 7));
  GBytes *label = NULL;
  g_assert_cmpint (wyl_fact_recovery_mac_handle_dup_label (handle, &label), ==,
      WYRELOG_E_OK);
  gsize label_len = 0;
  const guint8 *label_data = g_bytes_get_data (label, &label_len);
  g_assert_nonnull (label_data);
  g_assert_cmpuint (label_len, >, strlen ("wyrelog.fact.recovery-evidence.mac.v1"));
  g_autoptr (GByteArray) expected_label = g_byte_array_new ();
  recovery_mac_test_append_field (expected_label,
      "wyrelog.fact.recovery-evidence.mac.v1");
  recovery_mac_test_append_field (expected_label, "key-7");
  recovery_mac_test_append_u64 (expected_label, 7);
  recovery_mac_test_append_field (expected_label, "tenant-a");
  recovery_mac_test_append_field (expected_label, "graph-a");
  recovery_mac_test_append_field (expected_label, "operation-a");
  g_assert_cmpmem (label_data, label_len, expected_label->data,
      expected_label->len);
  g_bytes_unref (label);

  const guint8 payload[] = { 1, 2, 3, 4 };
  guint8 tag[WYL_FACT_RECOVERY_MAC_TAG_BYTES] = { 0 };
  g_assert_cmpint (wyl_fact_recovery_mac_compute (handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_recovery_mac_verify (handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_OK);
  tag[0] ^= 1;
  g_assert_cmpint (wyl_fact_recovery_mac_verify (handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_POLICY);
  g_assert_cmpuint (fake.compute_calls, ==, 3);
  wyl_fact_recovery_mac_handle_close (handle);
  g_assert_true (fake.wiped);
  g_assert_true (fake.freed);
  memset (tag, 0xaa, sizeof tag);
  g_assert_cmpint (wyl_fact_recovery_mac_compute (handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_POLICY);
  for (gsize i = 0; i < sizeof tag; i++)
    g_assert_cmpuint (tag[i], ==, 0);
  g_assert_cmpint (wyl_fact_recovery_mac_handle_dup_label (handle, &label), ==,
      WYRELOG_E_POLICY);
  g_clear_pointer (&fake.last_label, g_bytes_unref);

  RecoveryMacFakeProvider unavailable = { 0 };
  unavailable.fail_compute = TRUE;
  WylFactRecoveryMacProvider unavailable_provider = {
    recovery_mac_fake_compute,
    recovery_mac_fake_verify,
    recovery_mac_fake_wipe,
    recovery_mac_fake_free,
    &unavailable,
  };
  g_autoptr (WylFactRecoveryMacHandle) unavailable_handle =
      wyl_fact_recovery_mac_handle_new (&unavailable_provider, "key-8", 8,
          "tenant-a", "graph-a", "operation-a");
  g_assert_nonnull (unavailable_handle);
  memset (tag, 0xaa, sizeof tag);
  g_assert_cmpint (wyl_fact_recovery_mac_compute (unavailable_handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_CRYPTO);
  for (gsize i = 0; i < sizeof tag; i++)
    g_assert_cmpuint (tag[i], ==, 0);
  g_assert_cmpint (wyl_fact_recovery_mac_verify (unavailable_handle, payload,
      sizeof payload, tag), ==, WYRELOG_E_CRYPTO);
  wyl_fact_recovery_mac_handle_close (unavailable_handle);
  g_assert_true (unavailable.wiped);
  g_assert_true (unavailable.freed);
}

static void
test_fresh_schema_is_legacy_unclassified (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);

  const gchar *tenant_columns[] = {
    "lifecycle_state", "lifecycle_generation", "sealed_generation",
    "reconciliation_generation",
  };
  const gchar *graph_columns[] = {
    "lifecycle_state", "store_uuid", "format_version",
    "path_encoding_version", "lifecycle_generation",
    "reconciliation_generation", "last_error_class",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_columns); i++)
    assert_column (db, "tenants", tenant_columns[i]);
  for (gsize i = 0; i < G_N_ELEMENTS (graph_columns); i++)
    assert_column (db, "fact_graphs", graph_columns[i]);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM sqlite_master WHERE type='table' "
      "AND name='fact_graph_provisioning';"), ==, 1);

  insert_graph (db, "tenant-fresh", "graph-fresh", FALSE);
  g_autofree gchar *tenant_state = scalar_text (db,
          "SELECT lifecycle_state FROM tenants " "WHERE tenant_id='tenant-fresh';");
  g_autofree gchar *graph_state = scalar_text (db,
          "SELECT lifecycle_state FROM fact_graphs "
          "WHERE tenant_id='tenant-fresh' AND graph_id='graph-fresh';");
  g_assert_cmpstr (tenant_state, ==, "legacy_unclassified");
  g_assert_cmpstr (graph_state, ==, "legacy_unclassified");
  g_assert_cmpint (scalar_int64 (db,
      "SELECT lifecycle_generation + reconciliation_generation "
      "FROM fact_graphs WHERE tenant_id='tenant-fresh' "
      "AND graph_id='graph-fresh';"), ==, 0);
}

static void
test_provisioning_schema_is_fail_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-provision", "graph-provision", FALSE);
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-provision", "graph-provision",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070545", 1, 1, 0, 0,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070544','tenant-provision',"
      "'graph-provision','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070544.sqlite',1,0,"
      "'reserved',0,1,1);");
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graph_provisioning WHERE op_uuid="
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c070544';"), ==, 1);
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET stage_basename='foreign.sqlite';");
  exec_rejected (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070546','tenant-provision',"
      "'graph-other','01890f47-3c4b-7cc2-b8c4-dc0c0c070547','../foreign',"
      "0,0,'reserved',0,1,1);");
  insert_graph (db, "tenant-invalid-variant", "graph-invalid-variant", FALSE);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-invalid-variant", "graph-invalid-variant",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070549", 1, 1, 0, 0,
      &mutation), ==, WYRELOG_E_OK);
  exec_rejected (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-78c4-dc0c0c070548','tenant-invalid-variant',"
      "'graph-invalid-variant','01890f47-3c4b-7cc2-b8c4-dc0c0c070549',"
      "'provision-01890f47-3c4b-7cc2-78c4-dc0c0c070548.sqlite',"
      "1,0,'reserved',0,1,1);");
  exec_rejected (db, "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070552','tenant-provision',"
      "'graph-provision','01890f47-3c4b-7cc2-b8c4-dc0c0c070545',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070552.sqlite',0,0,"
      "'reserved',0,1,1);");
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='staged',updated_at=2;");
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET phase='verified',updated_at=3;");
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET phase='reserved',updated_at=3;");
  exec_ok (db, "UPDATE fact_graph_provisioning SET attempt=1,updated_at=3;");
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET attempt=0,updated_at=4;");
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET phase='published',"
      "attempt=2,updated_at=4;");
  exec_rejected (db, "UPDATE fact_graph_provisioning SET updated_at=2;");
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='published',updated_at=4;");
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='verified',updated_at=5;");
  exec_rejected (db,
      "UPDATE fact_graph_provisioning SET phase='active',updated_at=6;");
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision", "graph-provision",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  /* A direct graph transition leaves a detectable stranded operation until
   * recovery advances the operation's terminal phase. */
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='active',updated_at=6;");
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='active',updated_at=7;");
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision", "graph-provision",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
      &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==,
      WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision", "graph-provision",
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
      2, 0, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision", "graph-provision",
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE,
      3, 0, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision", "graph-provision",
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_OPEN,
      4, 0, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (store,
      "tenant-provision", "graph-provision", 5, 0, &mutation), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
}

static void
test_provisioning_degraded_terminal_coupling (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  WylPolicyAuthorityMutationResult mutation;
  insert_graph (db, "tenant-provision-degraded", "graph-provision-degraded",
      FALSE);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-provision-degraded", "graph-provision-degraded",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070553", 1, 1, 0, 0,
      &mutation), ==, WYRELOG_E_OK);
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070554','tenant-provision-degraded',"
      "'graph-provision-degraded','01890f47-3c4b-7cc2-b8c4-dc0c0c070553',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070554.sqlite',"
      "1,0,'reserved',0,1,1);");
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision-degraded", "graph-provision-degraded",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_OPEN,
      1, 0, &mutation), ==, WYRELOG_E_OK);
  g_assert_cmpint (mutation, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  exec_ok (db,
      "UPDATE fact_graph_provisioning SET phase='degraded',updated_at=2;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
}

static void
test_dangling_provisioning_record_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-dangling", "graph-dangling", FALSE);
  WylPolicyAuthorityMutationResult mutation;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-dangling", "graph-dangling",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070551", 1, 1, 0, 0,
      &mutation), ==, WYRELOG_E_OK);
  exec_ok (db,
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070550','tenant-dangling',"
      "'graph-dangling','01890f47-3c4b-7cc2-b8c4-dc0c0c070551',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070550.sqlite',"
      "1,0,'reserved',0,1,1);"
      "PRAGMA foreign_keys=OFF;"
      "DELETE FROM fact_graphs WHERE tenant_id='tenant-dangling' "
      "AND graph_id='graph-dangling';" "PRAGMA foreign_keys=ON;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
}

static void
test_malformed_provisioning_schema_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "CREATE TABLE fact_graph_provisioning (op_uuid TEXT PRIMARY KEY,"
      "tenant_id TEXT NOT NULL,graph_id TEXT NOT NULL,store_uuid TEXT NOT NULL,"
      "stage_basename TEXT NOT NULL,expected_lifecycle_generation INTEGER NOT NULL,"
      "expected_reconciliation_generation INTEGER NOT NULL,phase TEXT NOT NULL,"
      "attempt INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
      "name='fact_graph_provisioning';"), ==, 1);
}

static void
test_provisioning_immutable_trigger_is_verified (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER fact_graph_provisioning_immutable;"
      "CREATE TRIGGER fact_graph_provisioning_immutable "
      "BEFORE UPDATE ON fact_graph_provisioning BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
}

static void
create_pre_537_schema (sqlite3 *db)
{
  exec_ok (db,
      "PRAGMA foreign_keys=ON;"
      "CREATE TABLE tenants ("
      "tenant_id TEXT PRIMARY KEY, sealed INTEGER NOT NULL DEFAULT 0,"
      "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
      "CREATE TABLE fact_graphs ("
      "tenant_id TEXT NOT NULL, graph_id TEXT NOT NULL,"
      "storage_uri TEXT NOT NULL, storage_path TEXT NOT NULL,"
      "schema_version INTEGER NOT NULL, owner_scope TEXT NOT NULL,"
      "sealed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,"
      "updated_at INTEGER NOT NULL, sealed_at INTEGER,"
      "PRIMARY KEY (tenant_id,graph_id),"
      "FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id));");
}

static void
install_pre_sealed_generation_tenant_guards (sqlite3 *db,
    gboolean malformed_insert)
{
  exec_ok (db,
      "CREATE TRIGGER tenant_authority_insert_guard "
      "BEFORE INSERT ON tenants BEGIN "
      "SELECT CASE WHEN NOT ("
      "typeof(NEW.lifecycle_generation)='integer' AND "
      "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
      "typeof(NEW.reconciliation_generation)='integer' AND "
      "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807) "
      "THEN RAISE(ABORT,'invalid tenant generation domain') END; "
      "SELECT CASE WHEN NOT ("
      "NEW.lifecycle_state='legacy_unclassified' AND "
      "NEW.lifecycle_generation=0 AND NEW.reconciliation_generation=0) "
      "THEN RAISE(ABORT,'invalid tenant authority') END;" "END;");
  if (malformed_insert)
    exec_ok (db,
        "DROP TRIGGER tenant_authority_insert_guard;"
        "CREATE TRIGGER tenant_authority_insert_guard "
        "BEFORE INSERT ON tenants BEGIN "
        "SELECT RAISE(ABORT,'unowned tenant guard'); END;");
  exec_ok (db,
      "CREATE TRIGGER tenant_authority_update_guard "
      "BEFORE UPDATE ON tenants BEGIN "
      "SELECT CASE WHEN NOT ("
      "typeof(NEW.lifecycle_generation)='integer' AND "
      "NEW.lifecycle_generation BETWEEN 0 AND 9223372036854775807 AND "
      "typeof(NEW.reconciliation_generation)='integer' AND "
      "NEW.reconciliation_generation BETWEEN 0 AND 9223372036854775807) "
      "THEN RAISE(ABORT,'invalid tenant generation domain') END; "
      "SELECT CASE WHEN NOT ("
      "NEW.lifecycle_state='legacy_unclassified' OR "
      "(NEW.lifecycle_state IN ('active','sealing') AND NEW.sealed=0) OR "
      "(NEW.lifecycle_state IN ('sealed','unsealing') AND NEW.sealed=1)) "
      "THEN RAISE(ABORT,'invalid tenant authority') END; "
      "SELECT CASE WHEN NEW.lifecycle_state=OLD.lifecycle_state AND "
      "NEW.lifecycle_generation!=OLD.lifecycle_generation "
      "THEN RAISE(ABORT,'invalid tenant lifecycle generation') END; "
      "SELECT CASE WHEN NEW.lifecycle_state!=OLD.lifecycle_state AND ("
      "OLD.lifecycle_generation=9223372036854775807 OR "
      "NEW.lifecycle_generation!=OLD.lifecycle_generation+1 OR NOT ("
      "(OLD.lifecycle_state='legacy_unclassified' AND "
      " NEW.lifecycle_state IN ('active','sealed')) OR "
      "(OLD.lifecycle_state='active' AND NEW.lifecycle_state='sealing') OR "
      "(OLD.lifecycle_state='sealing' AND "
      " NEW.lifecycle_state IN ('active','sealed')) OR "
      "(OLD.lifecycle_state='sealed' AND NEW.lifecycle_state='unsealing') OR "
      "(OLD.lifecycle_state='unsealing' AND "
      " NEW.lifecycle_state IN ('active','sealed')))) "
      "THEN RAISE(ABORT,'illegal tenant lifecycle transition') END; "
      "SELECT CASE WHEN NEW.reconciliation_generation<"
      "OLD.reconciliation_generation OR "
      "NEW.reconciliation_generation>OLD.reconciliation_generation+1 "
      "THEN RAISE(ABORT,'invalid tenant reconciliation generation') END; "
      "SELECT CASE WHEN OLD.lifecycle_state='legacy_unclassified' AND "
      "NEW.lifecycle_state IN ('active','sealed') AND "
      "NEW.reconciliation_generation!=OLD.reconciliation_generation+1 "
      "THEN RAISE(ABORT,'tenant promotion requires reconciliation') END; "
      "SELECT CASE WHEN NOT (OLD.lifecycle_state='legacy_unclassified' AND "
      "NEW.lifecycle_state IN ('active','sealed')) AND "
      "NEW.reconciliation_generation!=OLD.reconciliation_generation "
      "THEN RAISE(ABORT,'unexpected tenant reconciliation generation') END; "
      "END;");
}

static void
test_pre_sealed_generation_guards_migrate (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER tenant_authority_update_guard;"
      "ALTER TABLE tenants DROP COLUMN sealed_generation;");
  install_pre_sealed_generation_tenant_guards (db, FALSE);
  exec_ok (db,
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) VALUES"
      "('pre-guard-open',0,1,1),('pre-guard-sealed',1,1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants WHERE "
      "(tenant_id='pre-guard-open' AND sealed_generation=0) OR "
      "(tenant_id='pre-guard-sealed' AND sealed_generation=1);"), ==, 2);
  exec_rejected (db,
      "UPDATE tenants SET sealed=0 WHERE tenant_id='pre-guard-sealed';");
  exec_rejected (db,
      "UPDATE tenants SET sealed_generation=2 "
      "WHERE tenant_id='pre-guard-open';");
}

static void
test_unknown_preexisting_tenant_guard_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER tenant_authority_update_guard;"
      "ALTER TABLE tenants DROP COLUMN sealed_generation;");
  install_pre_sealed_generation_tenant_guards (db, TRUE);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('tenants') "
      "WHERE name='sealed_generation';"), ==, 0);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND "
      "name='tenant_authority_insert_guard' AND "
      "sql LIKE '%unowned tenant guard%';"), ==, 1);
}

static void
test_pre_537_rows_migrate_idempotently (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  insert_graph (db, "tenant-open", "graph-open", FALSE);
  insert_graph (db, "tenant-sealed", "graph-sealed", TRUE);

  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM fact_graphs;"), ==,
      2);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graphs "
      "WHERE lifecycle_state='legacy_unclassified' "
      "AND lifecycle_generation=0 AND reconciliation_generation=0 "
      "AND store_uuid IS NULL AND format_version IS NULL "
      "AND path_encoding_version IS NULL AND last_error_class='none';"),
      ==, 2);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants "
      "WHERE tenant_id IN ('tenant-open','tenant-sealed') "
      "AND lifecycle_state='legacy_unclassified' "
      "AND lifecycle_generation=0 AND reconciliation_generation=0;"),
      ==, 2);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants WHERE"
      " (tenant_id='tenant-open' AND sealed=0 AND sealed_generation=0) OR"
      " (tenant_id='tenant-sealed' AND sealed=1 AND sealed_generation=1);"),
      ==, 2);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sum(sealed) FROM fact_graphs WHERE graph_id IN "
      "('graph-open','graph-sealed');"), ==, 1);
}

static void
test_graph_identity_and_state_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-a", "graph-a", FALSE);
  insert_graph (db, "tenant-b", "graph-b", FALSE);
  insert_graph (db, "tenant-sealed-bypass", "graph-sealed-bypass", TRUE);

  exec_rejected (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
      "path_encoding_version,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-a','graph-direct','file:///direct','/direct',1,"
      "'tenant-a',0,'active','01890f47-3c4b-7cc2-b8c4-dc0c0c073990',"
      "1,1,1,1,1);");
  const gchar *legacy_bypasses[] = {
    "lifecycle_state='active',last_error_class='none',sealed=0",
    "lifecycle_state='sealed',last_error_class='none',sealed=1",
    "lifecycle_state='degraded',last_error_class='replay',sealed=0",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (legacy_bypasses); i++) {
    g_autofree gchar *sql = g_strdup_printf ("UPDATE fact_graphs SET "
            "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c07398%" G_GSIZE_FORMAT
            "',format_version=1,path_encoding_version=1,%s,"
            "lifecycle_generation=1,reconciliation_generation=1 "
            "WHERE tenant_id='tenant-b' AND graph_id='graph-b';", i,
            legacy_bypasses[i]);
    exec_rejected (db, sql);
  }
  exec_rejected (db,
      "UPDATE fact_graphs SET sealed=0 "
      "WHERE tenant_id='tenant-sealed-bypass' "
      "AND graph_id='graph-sealed-bypass';");
  exec_rejected (db,
      "UPDATE fact_graphs SET sealed=0,"
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073989',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-sealed-bypass' "
      "AND graph_id='graph-sealed-bypass';");

  exec_rejected (db,
      "UPDATE fact_graphs SET store_uuid="
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073991' "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073992' "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET store_uuid=NULL "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET "
      "store_uuid='01890f47-3c4b-7cc2-b8c4-dc0c0c073991',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-b' AND graph_id='graph-b';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='replay',lifecycle_generation=2 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "lifecycle_generation=2 WHERE tenant_id='tenant-a' "
      "AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='degraded',"
      "last_error_class='replay',lifecycle_generation=3 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='none',lifecycle_generation=4 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='active',"
      "last_error_class='none',lifecycle_generation=4,"
      "reconciliation_generation=1 WHERE tenant_id='tenant-a' "
      "AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET reconciliation_generation=2 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_ok (db,
      "UPDATE fact_graphs SET lifecycle_state='degraded',"
      "last_error_class='replay',lifecycle_generation=5 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET last_error_class='recovery',"
      "reconciliation_generation=2 WHERE tenant_id='tenant-a' "
      "AND graph_id='graph-a';");
  exec_rejected (db,
      "UPDATE fact_graphs SET lifecycle_generation=9223372036854775807 "
      "WHERE tenant_id='tenant-a' AND graph_id='graph-a';");
}

static void
test_tenant_state_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-a',0,1,1);");
  exec_rejected (db,
      "INSERT INTO tenants (tenant_id,sealed,lifecycle_state,"
      "lifecycle_generation,reconciliation_generation,created_at,updated_at) "
      "VALUES ('tenant-direct',0,'active',1,1,1,1);");
  exec_rejected (db,
      "UPDATE tenants SET lifecycle_state='active',"
      "lifecycle_generation=1 WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='active',"
      "lifecycle_generation=1,reconciliation_generation=1 "
      "WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='sealing',"
      "lifecycle_generation=2 WHERE tenant_id='tenant-a';");
  exec_rejected (db,
      "UPDATE tenants SET lifecycle_state='unsealing',"
      "lifecycle_generation=3 WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='sealed',sealed=1,"
      "sealed_generation=1,lifecycle_generation=3 "
      "WHERE tenant_id='tenant-a';");
  exec_ok (db, "UPDATE tenants SET updated_at=2 WHERE tenant_id='tenant-a';");
  exec_rejected (db,
      "UPDATE tenants SET sealed_generation=2 WHERE tenant_id='tenant-a';");
  exec_rejected (db,
      "UPDATE tenants SET sealed=0,sealed_generation=1 "
      "WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='unsealing',lifecycle_generation=4 "
      "WHERE tenant_id='tenant-a';");
  exec_ok (db,
      "UPDATE tenants SET lifecycle_state='active',sealed=0,"
      "sealed_generation=2,lifecycle_generation=5 "
      "WHERE tenant_id='tenant-a';");
  exec_rejected (db,
      "UPDATE tenants SET reconciliation_generation=2 "
      "WHERE tenant_id='tenant-a';");

  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-generic",
      &created), ==, WYRELOG_E_OK);
  g_assert_true (created);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store,
      "tenant-generic", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sealed_generation FROM tenants"
      " WHERE tenant_id='tenant-generic';"), ==, 1);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store,
      "tenant-generic", TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sealed_generation FROM tenants"
      " WHERE tenant_id='tenant-generic';"), ==, 1);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store,
      "tenant-generic", FALSE), ==, WYRELOG_E_OK);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sealed_generation FROM tenants"
      " WHERE tenant_id='tenant-generic';"), ==, 2);
}

static void
test_tenant_sealed_generation_overflow (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db,
      "ALTER TABLE tenants ADD COLUMN sealed_generation INTEGER NOT NULL"
      " DEFAULT 0 CHECK(typeof(sealed_generation)='integer' AND"
      " sealed_generation BETWEEN 0 AND 9223372036854775807);"
      "INSERT INTO tenants"
      " (tenant_id,sealed,sealed_generation,created_at,updated_at)"
      " VALUES ('tenant-max',0,9223372036854775807,1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store, "tenant-max",
      TRUE), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sealed FROM tenants WHERE tenant_id='tenant-max';"), ==, 0);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT sealed_generation FROM tenants"
      " WHERE tenant_id='tenant-max';"), ==, G_MAXINT64);
}

static void
test_integer_domain_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);

  exec_rejected (db,
      "INSERT INTO tenants "
      "(tenant_id,sealed,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-text-generation',0,'not-an-integer',1,1);");
  exec_rejected (db,
      "INSERT INTO tenants "
      "(tenant_id,sealed,reconciliation_generation,created_at,updated_at) "
      "VALUES ('tenant-overflow-generation',0,9223372036854775808,1,1);");
  exec_ok (db,
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-canonical',0,1,1);");

  const gchar *invalid_graphs[] = {
    "'not-an-integer',1,0,0",
    "1,'not-an-integer',0,0",
    "1,1,9223372036854775808,0",
    "1,1,0,'not-an-integer'",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid_graphs); i++) {
    g_autofree gchar *sql = g_strdup_printf ("INSERT INTO fact_graphs "
            "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
            "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
            "path_encoding_version,lifecycle_generation,"
            "reconciliation_generation,created_at,updated_at) VALUES "
            "('tenant-canonical','graph-%" G_GSIZE_FORMAT "','file:///graph',"
            "'/graph',1,'tenant-canonical',0,'provisioning',"
            "'01890f47-3c4b-7cc2-b8c4-dc0c0c073%03" G_GSIZE_FORMAT "'," "%s,1,1);",
            i, i, invalid_graphs[i]);
    exec_rejected (db, sql);
  }
}

static void
test_typed_authority_reads_and_lists (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-b", "graph-b", FALSE);
  insert_graph (db, "tenant-a", "graph-a", TRUE);

  WylPolicyTenantAuthorityRecord *tenant = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, "tenant-a",
      &tenant), ==, WYRELOG_E_OK);
  g_assert_nonnull (tenant);
  g_assert_cmpstr (tenant->tenant_id, ==, "tenant-a");
  g_assert_cmpint (tenant->lifecycle_state, ==,
      WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED);
  g_assert_cmpuint (tenant->lifecycle_generation, ==, 0);
  g_assert_cmpuint (tenant->reconciliation_generation, ==, 0);
  g_assert_true (tenant->sealed_compatibility);
  wyl_policy_tenant_authority_record_free (tenant);

  tenant = GINT_TO_POINTER (1);
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, "missing",
      &tenant), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (tenant);

  WylPolicyGraphAuthorityRecord *graph = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
      "graph-b", &graph), ==, WYRELOG_E_OK);
  g_assert_nonnull (graph);
  g_assert_cmpstr (graph->tenant_id, ==, "tenant-b");
  g_assert_cmpstr (graph->graph_id, ==, "graph-b");
  g_assert_cmpint (graph->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  g_assert_false (graph->has_store_identity);
  g_assert_null (graph->store_uuid);
  g_assert_cmpint (graph->last_error_class, ==, WYL_POLICY_GRAPH_ERROR_NONE);
  wyl_policy_graph_authority_record_free (graph);

  GPtrArray *tenants = NULL;
  g_assert_cmpint (wyl_policy_store_list_tenant_authorities (store, &tenants),
      ==, WYRELOG_E_OK);
  g_assert_cmpuint (tenants->len, ==, 3);
  WylPolicyTenantAuthorityRecord *listed_tenant = g_ptr_array_index (tenants,
          1);
  g_assert_cmpstr (listed_tenant->tenant_id, ==, "tenant-a");
  g_ptr_array_unref (tenants);

  GPtrArray *graphs = NULL;
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (store, NULL,
      &graphs), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graphs->len, ==, 2);
  WylPolicyGraphAuthorityRecord *listed_graph = g_ptr_array_index (graphs, 0);
  g_assert_cmpstr (listed_graph->tenant_id, ==, "tenant-a");
  g_ptr_array_unref (graphs);
  graphs = NULL;
  g_assert_cmpint (wyl_policy_store_list_graph_authorities (store, "tenant-b",
      &graphs), ==, WYRELOG_E_OK);
  g_assert_cmpuint (graphs->len, ==, 1);
  listed_graph = g_ptr_array_index (graphs, 0);
  g_assert_cmpstr (listed_graph->graph_id, ==, "graph-b");
  g_ptr_array_unref (graphs);

  graph = GINT_TO_POINTER (1);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
      "missing", &graph), ==, WYRELOG_E_NOT_FOUND);
  g_assert_null (graph);
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "", "x",
      &graph), ==, WYRELOG_E_INVALID);

  exec_ok (db,
      "DROP TRIGGER fact_graph_authority_update_guard;"
      "UPDATE fact_graphs SET store_uuid='not-a-canonical-uuid',"
      "format_version=1,path_encoding_version=1,"
      "lifecycle_state='provisioning',lifecycle_generation=1 "
      "WHERE tenant_id='tenant-b' AND graph_id='graph-b';");
  g_assert_cmpint (wyl_policy_store_read_graph_authority (store, "tenant-b",
      "graph-b", &graph), ==, WYRELOG_E_POLICY);
  g_assert_null (graph);
}

static gchar *
make_store_path (gchar **out_root)
{
  g_autoptr (GError) error = NULL;
  *out_root = g_dir_make_tmp ("wyl-graph-authority-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (*out_root);
  return g_build_filename (*out_root, "policy.db", NULL);
}

static void
cleanup_store_path (const gchar *root, const gchar *path)
{
  g_autofree gchar *wal = g_strconcat (path, "-wal", NULL);
  g_autofree gchar *shm = g_strconcat (path, "-shm", NULL);
  (void) g_remove (wal);
  (void) g_remove (shm);
  (void) g_remove (path);
  (void) g_rmdir (root);
}

static void
test_reservation_and_cross_connection_cas (void)
{
  g_autofree gchar *root = NULL;
  g_autofree gchar *path = make_store_path (&root);
  g_autoptr (wyl_policy_store_t) first = NULL;
  g_autoptr (wyl_policy_store_t) second = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (first), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (first);
  insert_graph (db, "tenant-cas", "graph-cas", FALSE);
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at) VALUES "
      "('tenant-cas','graph-duplicate','file:///duplicate','/duplicate',1,"
      "'tenant-cas',0,1,1);");
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,created_at,updated_at) VALUES "
      "('tenant-cas','graph-sealed-legacy','file:///sealed','/sealed',1,"
      "'tenant-cas',1,1,1);");
  g_assert_cmpint (wyl_policy_store_open (path, &second), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (second), ==, WYRELOG_E_OK);

  WylPolicyAuthorityMutationResult result;
  exec_ok (db, "BEGIN IMMEDIATE;");
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
      "tenant-cas", "graph-cas",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_BUSY);
  exec_ok (db, "ROLLBACK;");
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (first,
      "tenant-cas", "graph-cas",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
      "tenant-cas", "graph-cas",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
      "tenant-cas", "graph-duplicate",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073101", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  WylPolicyGraphAuthorityRecord *duplicate = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (first, "tenant-cas",
      "graph-duplicate", &duplicate), ==, WYRELOG_E_OK);
  g_assert_false (duplicate->has_store_identity);
  g_assert_cmpint (duplicate->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED);
  wyl_policy_graph_authority_record_free (duplicate);
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (second,
      "tenant-cas", "graph-sealed-legacy",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073104", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
      "tenant-cas", "graph-cas",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1,
      0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (second,
      "tenant-cas", "graph-cas",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_REPLAY,
      1, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (second,
      "tenant-cas", "graph-cas",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1,
      0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
      "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_ERROR_NONE, 2, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
      "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_REPLAY,
      2, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
      "tenant-cas", "graph-cas", WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 3,
      0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (first,
      "tenant-cas", "graph-cas", 3, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (second,
      "tenant-cas", "graph-cas", 3, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (first,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (second,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (second,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_SEALING,
      WYL_POLICY_TENANT_LIFECYCLE_SEALED, 2, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (first,
      "tenant-cas", WYL_POLICY_TENANT_LIFECYCLE_SEALED,
      WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 3, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  exec_ok (db, "DROP TRIGGER fact_graph_authority_insert_guard;");
  exec_ok (db,
      "INSERT INTO fact_graphs "
      "(tenant_id,graph_id,storage_uri,storage_path,schema_version,"
      "owner_scope,sealed,lifecycle_state,store_uuid,format_version,"
      "path_encoding_version,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-cas','graph-max','file:///max','/max',1,"
      "'tenant-cas',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073102',1,1,"
      "9223372036854775807,1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (first,
      "tenant-cas", "graph-max", WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
      G_MAXINT64, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  WylPolicyGraphAuthorityRecord *max_graph = NULL;
  g_assert_cmpint (wyl_policy_store_read_graph_authority (first, "tenant-cas",
      "graph-max", &max_graph), ==, WYRELOG_E_OK);
  g_assert_cmpuint (max_graph->lifecycle_generation, ==, G_MAXINT64);
  g_assert_cmpint (max_graph->lifecycle_state, ==,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE);
  wyl_policy_graph_authority_record_free (max_graph);

  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (first,
      "tenant-cas", "missing",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073103", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND);

  g_clear_pointer (&second, wyl_policy_store_close);
  g_clear_pointer (&first, wyl_policy_store_close);
  cleanup_store_path (root, path);
}

static void
prepare_graph_matrix_state (wyl_policy_store_t *store, sqlite3 *db,
    const gchar *tenant_id, const gchar *graph_id, const gchar *store_uuid,
    WylPolicyGraphLifecycleState state, guint64 *out_lifecycle_generation,
    guint64 *out_reconciliation_generation)
{
  insert_graph (db, tenant_id, graph_id, FALSE);
  *out_lifecycle_generation = 0;
  *out_reconciliation_generation = 0;
  if (state == WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED)
    return;

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store, tenant_id,
      graph_id, store_uuid, 1, 1, 0, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 1;
  if (state == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING)
    return;

  WylPolicyGraphLifecycleState target =
      state == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED : WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE;
  WylPolicyGraphErrorClass error =
      target == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
      WYL_POLICY_GRAPH_ERROR_REPLAY : WYL_POLICY_GRAPH_ERROR_NONE;
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      target, error, 1, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 2;
  if (state != WYL_POLICY_GRAPH_LIFECYCLE_SEALED)
    return;

  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      tenant_id, graph_id, WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE, 2,
      0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 3;
}

static gboolean
graph_matrix_edge_is_legal (WylPolicyGraphLifecycleState from,
    WylPolicyGraphLifecycleState to)
{
  return (from == WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING
         && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
         || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
         || (from == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
         && (to == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
         || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED))
         || (from == WYL_POLICY_GRAPH_LIFECYCLE_SEALED
         && (to == WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE
         || to == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED));
}

static void
prepare_tenant_matrix_state (wyl_policy_store_t *store, sqlite3 *db,
    const gchar *tenant_id, WylPolicyTenantLifecycleState state,
    guint64 *out_lifecycle_generation, guint64 *out_reconciliation_generation)
{
  g_autofree gchar *insert = g_strdup_printf ("INSERT INTO tenants "
          "(tenant_id,sealed,created_at,updated_at) VALUES ('%s',0,1,1);",
          tenant_id);
  exec_ok (db, insert);
  *out_lifecycle_generation = 0;
  *out_reconciliation_generation = 0;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED)
    return;

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
      tenant_id, WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 1;
  *out_reconciliation_generation = 1;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
      tenant_id, WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      WYL_POLICY_TENANT_LIFECYCLE_SEALING, 1, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 2;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
      tenant_id, WYL_POLICY_TENANT_LIFECYCLE_SEALING,
      WYL_POLICY_TENANT_LIFECYCLE_SEALED, 2, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 3;
  if (state == WYL_POLICY_TENANT_LIFECYCLE_SEALED)
    return;

  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
      tenant_id, WYL_POLICY_TENANT_LIFECYCLE_SEALED,
      WYL_POLICY_TENANT_LIFECYCLE_UNSEALING, 3, 1, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  *out_lifecycle_generation = 4;
}

static gboolean
tenant_matrix_edge_is_legal (WylPolicyTenantLifecycleState from,
    WylPolicyTenantLifecycleState to)
{
  return (from == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
         && to == WYL_POLICY_TENANT_LIFECYCLE_SEALING)
         || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALING
         && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
         || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED))
         || (from == WYL_POLICY_TENANT_LIFECYCLE_SEALED
         && to == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING)
         || (from == WYL_POLICY_TENANT_LIFECYCLE_UNSEALING
         && (to == WYL_POLICY_TENANT_LIFECYCLE_ACTIVE
         || to == WYL_POLICY_TENANT_LIFECYCLE_SEALED));
}

static void
test_complete_transition_matrices (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  const WylPolicyGraphLifecycleState graph_states[] = {
    WYL_POLICY_GRAPH_LIFECYCLE_LEGACY_UNCLASSIFIED,
    WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
    WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
    WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
    WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
  };
  guint sequence = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (graph_states); i++) {
    for (gsize j = 0; j < G_N_ELEMENTS (graph_states); j++, sequence++) {
      g_autofree gchar *tenant = g_strdup_printf ("tenant-gmatrix-%u",
              sequence);
      g_autofree gchar *graph = g_strdup_printf ("graph-gmatrix-%u",
              sequence);
      g_autofree gchar *uuid =
          g_strdup_printf ("01890f47-3c4b-7cc2-b8c4-dc0c0c%06u", sequence);
      guint64 lifecycle_generation, reconciliation_generation;
      prepare_graph_matrix_state (store, db, tenant, graph, uuid,
          graph_states[i], &lifecycle_generation, &reconciliation_generation);
      WylPolicyGraphErrorClass error =
          graph_states[j] == WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED ?
          WYL_POLICY_GRAPH_ERROR_REPLAY : WYL_POLICY_GRAPH_ERROR_NONE;
      WylPolicyAuthorityMutationResult result;
      g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
          tenant, graph, graph_states[i], graph_states[j], error,
          lifecycle_generation, reconciliation_generation, &result), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (result, ==,
          graph_matrix_edge_is_legal (graph_states[i], graph_states[j]) ?
          WYL_POLICY_AUTHORITY_MUTATION_APPLIED :
          WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
    }
  }

  const WylPolicyTenantLifecycleState tenant_states[] = {
    WYL_POLICY_TENANT_LIFECYCLE_LEGACY_UNCLASSIFIED,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_states); i++) {
    for (gsize j = 0; j < G_N_ELEMENTS (tenant_states); j++, sequence++) {
      g_autofree gchar *tenant = g_strdup_printf ("tenant-tmatrix-%u",
              sequence);
      guint64 lifecycle_generation, reconciliation_generation;
      prepare_tenant_matrix_state (store, db, tenant, tenant_states[i],
          &lifecycle_generation, &reconciliation_generation);
      WylPolicyAuthorityMutationResult result;
      g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
          tenant, tenant_states[i], tenant_states[j],
          lifecycle_generation, reconciliation_generation, &result), ==,
          WYRELOG_E_OK);
      g_assert_cmpint (result, ==,
          tenant_matrix_edge_is_legal (tenant_states[i], tenant_states[j]) ?
          WYL_POLICY_AUTHORITY_MUTATION_APPLIED :
          WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
    }
  }
}

static void
test_complete_transition_tables_and_overflow (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER fact_graph_authority_insert_guard;");
  exec_ok (db,
      "INSERT INTO tenants(tenant_id,sealed,created_at,updated_at) "
      "VALUES('tenant-transitions',0,1,1);"
      "INSERT INTO tenants(tenant_id,sealed,reconciliation_generation,"
      "created_at,updated_at) VALUES"
      "('tenant-reconciliation-max',0,9223372036854775807,1,1);"
      "INSERT INTO tenants(tenant_id,sealed,lifecycle_state,"
      "lifecycle_generation,created_at,updated_at) VALUES"
      "('tenant-lifecycle-max',0,'active',9223372036854775807,1,1);"
      "INSERT INTO fact_graphs(tenant_id,graph_id,storage_uri,storage_path,"
      "schema_version,owner_scope,sealed,lifecycle_state,store_uuid,"
      "format_version,path_encoding_version,lifecycle_generation,"
      "reconciliation_generation,last_error_class,created_at,updated_at) "
      "VALUES"
      "('tenant-transitions','graph-pd','file:///pd','/pd',1,"
      "'tenant-transitions',0,'provisioning',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073201',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-as','file:///as','/as',1,"
      "'tenant-transitions',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073202',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-sd','file:///sd','/sd',1,"
      "'tenant-transitions',1,'sealed',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073203',1,1,0,0,'none',1,1),"
      "('tenant-transitions','graph-reconciliation-max','file:///rm','/rm',1,"
      "'tenant-transitions',0,'degraded',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073204',1,1,0,"
      "9223372036854775807,'recovery',1,1),"
      "('tenant-transitions','graph-lifecycle-max','file:///lm','/lm',1,"
      "'tenant-transitions',0,'active',"
      "'01890f47-3c4b-7cc2-b8c4-dc0c0c073205',1,1,"
      "9223372036854775807,0,'none',1,1);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);

  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-transitions", "graph-pd",
      WYL_POLICY_GRAPH_LIFECYCLE_PROVISIONING,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED, WYL_POLICY_GRAPH_ERROR_PATH, 0,
      0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-transitions", "graph-as",
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE, 0, 0,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-transitions", "graph-as",
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE, WYL_POLICY_GRAPH_ERROR_NONE, 1, 0,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-transitions", "graph-sd",
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED,
      WYL_POLICY_GRAPH_LIFECYCLE_DEGRADED,
      WYL_POLICY_GRAPH_ERROR_INTERNAL, 0, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_graph_authority (store,
      "tenant-transitions", "graph-reconciliation-max", 0, G_MAXINT64,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-transitions", "graph-lifecycle-max",
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
      G_MAXINT64, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);

  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
      "tenant-transitions", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0, 0,
      &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  const WylPolicyTenantLifecycleState tenant_path[] = {
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
    WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
    WYL_POLICY_TENANT_LIFECYCLE_SEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
    WYL_POLICY_TENANT_LIFECYCLE_UNSEALING,
    WYL_POLICY_TENANT_LIFECYCLE_SEALED,
  };
  WylPolicyTenantLifecycleState tenant_state =
      WYL_POLICY_TENANT_LIFECYCLE_ACTIVE;
  guint64 lifecycle_generation = 1;
  for (gsize i = 0; i < G_N_ELEMENTS (tenant_path); i++) {
    g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
        "tenant-transitions", tenant_state, tenant_path[i],
        lifecycle_generation, 1, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
    tenant_state = tenant_path[i];
    lifecycle_generation++;
  }
  g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
      "tenant-reconciliation-max", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE, 0,
      G_MAXINT64, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  g_assert_cmpint (wyl_policy_store_transition_tenant_authority (store,
      "tenant-lifecycle-max", WYL_POLICY_TENANT_LIFECYCLE_ACTIVE,
      WYL_POLICY_TENANT_LIFECYCLE_SEALING, G_MAXINT64, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
}

static void
test_nested_transaction_uses_savepoint (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-nested", "graph-nested", FALSE);

  exec_ok (db, "BEGIN;");
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-nested", "graph-nested",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073105", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graphs "
      "WHERE tenant_id='tenant-nested' AND graph_id='graph-nested' "
      "AND lifecycle_state='provisioning' AND lifecycle_generation=1;"),
      ==, 1);

  exec_ok (db, "ROLLBACK;");
  g_assert_true (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graphs "
      "WHERE tenant_id='tenant-nested' AND graph_id='graph-nested' "
      "AND lifecycle_state='legacy_unclassified' "
      "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 1);
}

static void
test_mutation_faults_roll_back (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-fault-a", "graph-fault-a", FALSE);
  insert_graph (db, "tenant-fault-b", "graph-fault-b", FALSE);
  insert_graph (db, "tenant-fault-nested", "graph-fault-nested", FALSE);

  const WylPolicyGraphAuthorityMutationFailStage stages[] = {
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE,
    WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_BEFORE_FINISH,
  };
  const gchar *tenants[] = { "tenant-fault-a", "tenant-fault-b" };
  const gchar *graphs[] = { "graph-fault-a", "graph-fault-b" };
  const gchar *uuids[] = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073301",
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073302",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (stages); i++) {
    wyl_policy_store_graph_authority_mutation_fail_once (store, stages[i]);
    WylPolicyAuthorityMutationResult result;
    g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
        tenants[i], graphs[i], uuids[i], 1, 1, 0, 0, &result), ==,
        WYRELOG_E_IO);
    g_assert_true (sqlite3_get_autocommit (db));
    g_assert_cmpint (scalar_int64 (db,
        "SELECT count(*) FROM fact_graphs WHERE "
        "lifecycle_state='legacy_unclassified' "
        "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 3);
  }

  exec_ok (db,
      "BEGIN;"
      "INSERT INTO tenants (tenant_id,sealed,created_at,updated_at) "
      "VALUES ('tenant-outer-marker',0,1,1);");
  wyl_policy_store_graph_authority_mutation_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-fault-nested", "graph-fault-nested",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c073303", 1, 1, 0, 0, &result), ==,
      WYRELOG_E_IO);
  g_assert_false (sqlite3_get_autocommit (db));
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants "
      "WHERE tenant_id='tenant-outer-marker';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graphs "
      "WHERE tenant_id='tenant-fault-nested' "
      "AND graph_id='graph-fault-nested' "
      "AND lifecycle_state='legacy_unclassified' "
      "AND lifecycle_generation=0 AND store_uuid IS NULL;"), ==, 1);
  exec_ok (db, "COMMIT;");
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants "
      "WHERE tenant_id='tenant-outer-marker';"), ==, 1);
}

static void
test_fresh_migration_failures_reopen_and_retry (void)
{
  for (WylPolicyGraphAuthorityMigrationFailStage stage =
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_BASE_DDL;
      stage < WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_COUNT; stage++) {
    g_autofree gchar *root = NULL;
    g_autofree gchar *path = make_store_path (&root);
    wyl_policy_store_t *store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    wyl_policy_store_graph_authority_migration_fail_once (store, stage);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_IO);
    g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
        "SELECT count(*) FROM sqlite_master WHERE name IN "
        "('idx_fact_graphs_store_uuid',"
        "'tenant_authority_insert_guard',"
        "'tenant_authority_update_guard',"
        "'fact_graph_authority_insert_guard',"
        "'fact_graph_authority_update_guard');"), ==, 0);
    g_assert_cmpint (scalar_int64 (wyl_policy_store_get_db (store),
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
        "name='tenants';"), ==, 0);
    wyl_policy_store_close (store);

    store = NULL;
    g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
    g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
    assert_column (wyl_policy_store_get_db (store), "fact_graphs",
        "store_uuid");
    wyl_policy_store_close (store);
    cleanup_store_path (root, path);
  }
}

static void
test_legacy_failure_preserves_rows_and_retries (void)
{
  g_autofree gchar *root = NULL;
  g_autofree gchar *path = make_store_path (&root);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  insert_graph (db, "tenant-legacy", "graph-legacy", TRUE);
  wyl_policy_store_graph_authority_migration_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MIGRATION_FAIL_AFTER_GRAPH_TRIGGERS);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_IO);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM fact_graphs;"), ==,
      1);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('fact_graphs') "
      "WHERE name='store_uuid';"), ==, 0);
  wyl_policy_store_close (store);

  store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  db = wyl_policy_store_get_db (store);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_graphs WHERE "
      "tenant_id='tenant-legacy' AND graph_id='graph-legacy' AND "
      "sealed=1 AND lifecycle_state='legacy_unclassified';"), ==, 1);
  wyl_policy_store_close (store);
  cleanup_store_path (root, path);
}

static void
test_malformed_preexisting_object_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db, "CREATE INDEX idx_fact_graphs_store_uuid "
      "ON fact_graphs(graph_id);");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('fact_graphs') "
      "WHERE name='store_uuid';"), ==, 0);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
      "name='idx_fact_graphs_store_uuid' AND "
      "sql LIKE '%graph_id%';"), ==, 1);
}

static void
test_preexisting_column_without_constraint_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db,
      "ALTER TABLE tenants ADD COLUMN lifecycle_state TEXT NOT NULL "
      "DEFAULT 'legacy_unclassified';");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('tenants') WHERE "
      "name='lifecycle_state';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('tenants') WHERE "
      "name='lifecycle_generation';"), ==, 0);
}

static void
test_constraint_comment_spoof_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  create_pre_537_schema (db);
  exec_ok (db,
      "ALTER TABLE tenants ADD COLUMN lifecycle_state TEXT NOT NULL "
      "DEFAULT 'legacy_unclassified' /* CHECK(lifecycle_state IN "
      "('legacy_unclassified','active','sealing','sealed','unsealing')) */;");
  g_assert_cmpint (scalar_int64 (db,
      "SELECT instr(sql,'CHECK(lifecycle_state IN') > 0 "
      "FROM sqlite_master WHERE type='table' AND name='tenants';"), ==, 1);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM pragma_table_info('tenants') WHERE "
      "name='lifecycle_generation';"), ==, 0);
}

static void
test_preexisting_invalid_row_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "DROP TRIGGER tenant_authority_update_guard;"
      "PRAGMA ignore_check_constraints=ON;"
      "INSERT INTO tenants "
      "(tenant_id,sealed,lifecycle_generation,created_at,updated_at) "
      "VALUES ('tenant-invalid',0,'not-an-integer',1,1);"
      "PRAGMA ignore_check_constraints=OFF;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM tenants WHERE tenant_id='tenant-invalid' "
      "AND typeof(lifecycle_generation)='text';"), ==, 1);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND "
      "name IN ('tenant_authority_insert_guard',"
      "'tenant_authority_update_guard');"), ==, 0);
}

static void
test_malformed_preexisting_trigger_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  exec_ok (db,
      "DROP TRIGGER tenant_authority_insert_guard;"
      "CREATE TRIGGER tenant_authority_insert_guard BEFORE INSERT ON tenants "
      "BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
}

static void
test_reconcile_journal_prepare_read_list_and_cas (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  insert_graph (wyl_policy_store_get_db (store), "tenant-journal",
      "graph-journal", FALSE);
  const gchar *op = "01890f47-3c4b-7cc2-b8c4-dc0c0c073990";
  const gchar *uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c073991";
  WylPolicyFactReconcileArtifactEvidence evidence = valid_reconcile_evidence ();
  WylPolicyFactReconcileJournalInput input = {
    op, "tenant-journal", "graph-journal", 0, 0, 1, 1, uuid,
    "legacy/graph/facts.duckdb", "v1/tenant/graph/facts.duckdb", evidence
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  wyrelog_error_t prepare_rc = wyl_policy_store_reconcile_journal_prepare
        (store, &input, &record, &result);
  g_assert_cmpint (prepare_rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_nonnull (record);
  g_assert_cmpint (record->state, ==, WYL_POLICY_FACT_RECONCILE_PREPARED);
  g_assert_cmpuint (record->attempt, ==, 0);
  assert_reconcile_evidence_equal (&record->source_evidence, &evidence);
  wyl_policy_fact_reconcile_journal_record_free (record);
  record = NULL;

  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  wyl_policy_fact_reconcile_journal_record_free (record);
  record = NULL;
#define ASSERT_EVIDENCE_STALE(value) G_STMT_START { \
    input.source_evidence = (value); \
    g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input, \
        &record, &result), ==, WYRELOG_E_OK); \
    g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE); \
    g_assert_null (record); \
} G_STMT_END
  WylPolicyFactReconcileArtifactEvidence changed = evidence;
  changed.version = 2;
  input.source_evidence = changed;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_INVALID);
  changed = evidence;
  changed.posix_device++;
  ASSERT_EVIDENCE_STALE (changed);
  changed = evidence;
  changed.posix_inode++;
  ASSERT_EVIDENCE_STALE (changed);
  changed = evidence;
  changed.size_bytes++;
  ASSERT_EVIDENCE_STALE (changed);
  changed = evidence;
  changed.digest_algorithm = 2;
  input.source_evidence = changed;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_INVALID);
  changed = evidence;
  changed.digest[0] ^= 1;
  ASSERT_EVIDENCE_STALE (changed);
  changed = evidence;
  changed.identity_kind = WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_WINDOWS;
  changed.posix_device = 0;
  changed.posix_inode = 0;
  changed.windows_volume_serial = 29;
  memset (changed.windows_file_id, 7, sizeof changed.windows_file_id);
  ASSERT_EVIDENCE_STALE (changed);
#undef ASSERT_EVIDENCE_STALE
  input.source_evidence = evidence;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (store, op,
      WYL_POLICY_FACT_RECONCILE_PREPARED,
      WYL_POLICY_FACT_RECONCILE_MOVING, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (store, op,
      WYL_POLICY_FACT_RECONCILE_PREPARED,
      WYL_POLICY_FACT_RECONCILE_MOVING, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (store, op,
      WYL_POLICY_FACT_RECONCILE_MOVING,
      WYL_POLICY_FACT_RECONCILE_DONE, 1, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==,
      WYL_POLICY_AUTHORITY_MUTATION_ILLEGAL_TRANSITION);
  GPtrArray *records = NULL;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_list (store,
      "tenant-journal", &records), ==, WYRELOG_E_OK);
  g_assert_cmpuint (records->len, ==, 1);
  g_ptr_array_unref (records);
  input.source_relative_path = "../escape/facts.duckdb";
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_INVALID);
  input.source_relative_path = "legacy/./facts.duckdb";
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (store, op,
      (WylPolicyFactReconcileJournalState) - 1,
      WYL_POLICY_FACT_RECONCILE_MOVING, 0, &result), ==, WYRELOG_E_INVALID);
}

static void
test_reconcile_journal_round_trips_high_bit_windows_serial (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  insert_graph (wyl_policy_store_get_db (store), "tenant-high-serial",
      "graph-high-serial", FALSE);
  WylPolicyFactReconcileArtifactEvidence evidence = {
    .version = WYL_POLICY_FACT_RECONCILE_ARTIFACT_EVIDENCE_V1,
    .identity_kind = WYL_POLICY_FACT_RECONCILE_ARTIFACT_IDENTITY_WINDOWS,
    .windows_volume_serial = G_GUINT64_CONSTANT (0x8000000000000001),
    .size_bytes = 23,
    .digest_algorithm = WYL_POLICY_FACT_RECONCILE_ARTIFACT_DIGEST_SHA256,
  };
  memset (evidence.windows_file_id, 7, sizeof evidence.windows_file_id);
  for (gsize i = 0; i < G_N_ELEMENTS (evidence.digest); i++)
    evidence.digest[i] = (guint8) (i + 1);
  WylPolicyFactReconcileJournalInput input = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073996", "tenant-high-serial",
    "graph-high-serial", 0, 0, 1, 1, NULL, "legacy/a/facts.duckdb",
    "v1/a/b/facts.duckdb", evidence
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  g_assert_nonnull (record);
  g_assert_cmpuint (record->source_evidence.windows_volume_serial, ==,
      evidence.windows_volume_serial);
  wyl_policy_fact_reconcile_journal_record_free (record);
}

static void
test_reconcile_journal_evidence_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-evidence", "graph-evidence", FALSE);
  WylPolicyFactReconcileJournalInput input = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073992", "tenant-evidence",
    "graph-evidence", 0, 0, 1, 1,
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073993", "legacy/a/facts.duckdb",
    "v1/a/b/facts.duckdb", valid_reconcile_evidence ()
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  wyl_policy_fact_reconcile_journal_record_free (record);
  exec_rejected (db, "UPDATE fact_reconcile_journal SET source_size_bytes=24;");
  exec_ok (db, "DROP TRIGGER fact_reconcile_evidence_immutable;"
      "UPDATE fact_reconcile_journal SET source_digest=NULL;");
  g_assert_cmpint (wyl_policy_store_reconcile_journal_read (store,
      input.op_uuid, &record), ==, WYRELOG_E_POLICY);
  GPtrArray *records = NULL;
  g_assert_cmpint (wyl_policy_store_reconcile_journal_list (store,
      "tenant-evidence", &records), ==, WYRELOG_E_POLICY);
  g_assert_null (records);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_transition (store,
      input.op_uuid, WYL_POLICY_FACT_RECONCILE_PREPARED,
      WYL_POLICY_FACT_RECONCILE_MOVING, 0, &result), ==, WYRELOG_E_POLICY);
}

static void
test_reconcile_evidence_trigger_is_verified (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  exec_ok (wyl_policy_store_get_db (store),
      "DROP TRIGGER fact_reconcile_evidence_immutable;"
      "CREATE TRIGGER fact_reconcile_evidence_immutable "
      "BEFORE UPDATE ON fact_reconcile_journal BEGIN SELECT 1; END;");
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==,
      WYRELOG_E_POLICY);
}

static void
test_reconcile_evidence_prepare_rolls_back (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-evidence-fault", "graph-evidence-fault", FALSE);
  WylPolicyFactReconcileJournalInput input = {
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073994", "tenant-evidence-fault",
    "graph-evidence-fault", 0, 0, 1, 1,
    "01890f47-3c4b-7cc2-b8c4-dc0c0c073995", "legacy/a/facts.duckdb",
    "v1/a/b/facts.duckdb", valid_reconcile_evidence ()
  };
  WylPolicyFactReconcileJournalRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  wyl_policy_store_graph_authority_mutation_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  g_assert_cmpint (wyl_policy_store_reconcile_journal_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_IO);
  g_assert_null (record);
  g_assert_cmpint (scalar_int64 (db,
      "SELECT count(*) FROM fact_reconcile_journal;"), ==, 0);
}

static void
test_graph_provisioning_private_api (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-provision-api", "graph-provision-api", FALSE);
  WylPolicyGraphProvisioningInput input = {
    .tenant_id = "tenant-provision-api",
    .graph_id = "graph-provision-api",
    .store_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070601",
    .format_version = 1,
    .path_encoding_version = 1,
    .expected_lifecycle_generation = 0,
    .expected_reconciliation_generation = 0,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_nonnull (record);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_RESERVED);
  g_assert_cmpuint (record->expected_lifecycle_generation, ==, 1);
  g_assert_cmpuint (record->attempt, ==, 0);
  g_assert_true (g_str_has_prefix (record->stage_basename, "provision-"));
  g_assert_true (g_str_has_suffix (record->stage_basename, ".sqlite"));
  gchar *op_uuid = g_strdup (record->op_uuid);
  wyl_policy_graph_provisioning_record_free (record);
  record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_assert_cmpstr (record->op_uuid, ==, op_uuid);
  wyl_policy_graph_provisioning_record_free (record);
  record = NULL;

  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpstr (record->op_uuid, ==, op_uuid);
  wyl_policy_graph_provisioning_record_free (record);
  record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store,
      "01890F47-3C4B-7CC2-B8C4-DC0C0C070601", &record), ==,
      WYRELOG_E_INVALID);

  const WylPolicyGraphProvisioningPhase phases[] = {
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_STAGED,
    WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED,
    WYL_POLICY_GRAPH_PROVISIONING_VERIFIED,
    WYL_POLICY_GRAPH_PROVISIONING_ACTIVE,
  };
  for (gsize i = 0; i + 1 < G_N_ELEMENTS (phases); i++) {
    g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
        op_uuid, phases[i], phases[i + 1], 0,
        WYL_POLICY_GRAPH_ERROR_NONE, &result), ==, WYRELOG_E_OK);
    g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  }
  g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
      op_uuid, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE,
      WYL_POLICY_GRAPH_PROVISIONING_ACTIVE, 0,
      WYL_POLICY_GRAPH_ERROR_NONE, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);
  g_autofree gchar *lifecycle_state = scalar_text (db,
          "SELECT lifecycle_state FROM fact_graphs "
          "WHERE tenant_id='tenant-provision-api' AND graph_id='graph-provision-api';");
  g_assert_cmpstr (lifecycle_state, ==, "active");
  g_assert_cmpint (wyl_policy_store_transition_graph_authority (store,
      "tenant-provision-api", "graph-provision-api",
      WYL_POLICY_GRAPH_LIFECYCLE_ACTIVE,
      WYL_POLICY_GRAPH_LIFECYCLE_SEALED, WYL_POLICY_GRAPH_ERROR_NONE,
      2, 0, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
      op_uuid, WYL_POLICY_GRAPH_PROVISIONING_ACTIVE,
      WYL_POLICY_GRAPH_PROVISIONING_ACTIVE, 0,
      WYL_POLICY_GRAPH_ERROR_NONE, &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE);
  g_free (op_uuid);
}

static void
test_graph_provisioning_blob_phase_fails_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-provision-blob", "graph-provision-blob", FALSE);
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_reserve_graph_authority (store,
      "tenant-provision-blob", "graph-provision-blob",
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070611", 1, 1, 0, 0,
      &result), ==, WYRELOG_E_OK);
  exec_ok (db, "DROP TRIGGER fact_graph_provisioning_insert_guard;"
      "PRAGMA ignore_check_constraints=ON;"
      "INSERT INTO fact_graph_provisioning "
      "(op_uuid,tenant_id,graph_id,store_uuid,stage_basename,"
      "expected_lifecycle_generation,expected_reconciliation_generation,"
      "phase,attempt,created_at,updated_at) VALUES "
      "('01890f47-3c4b-7cc2-b8c4-dc0c0c070610','tenant-provision-blob',"
      "'graph-provision-blob','01890f47-3c4b-7cc2-b8c4-dc0c0c070611',"
      "'provision-01890f47-3c4b-7cc2-b8c4-dc0c0c070610.sqlite',1,0,"
      "CAST('reserved' AS BLOB),0,1,1);");
  WylPolicyGraphProvisioningRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store,
      "01890f47-3c4b-7cc2-b8c4-dc0c0c070610", &record), ==,
      WYRELOG_E_POLICY);
  g_assert_null (record);
}

static void
test_graph_provisioning_prepare_rolls_back_reservation (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-provision-fault", "graph-provision-fault", FALSE);
  WylPolicyGraphProvisioningInput input = {
    .tenant_id = "tenant-provision-fault",.graph_id = "graph-provision-fault",
    .store_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070621",
    .format_version = 1,.path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  wyl_policy_store_graph_authority_mutation_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_IO);
  g_assert_null (record);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM "
      "fact_graph_provisioning;"), ==, 0);
  g_assert_cmpstr (scalar_text (db, "SELECT lifecycle_state FROM fact_graphs "
      "WHERE tenant_id='tenant-provision-fault' AND graph_id='graph-provision-fault';"),
      ==, "legacy_unclassified");
}

static void
test_graph_provisioning_terminal_rolls_back (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-provision-terminal", "graph-provision-terminal",
      FALSE);
  WylPolicyGraphProvisioningInput input = {
    .tenant_id = "tenant-provision-terminal",
    .graph_id = "graph-provision-terminal",
    .store_uuid = "01890f47-3c4b-7cc2-b8c4-dc0c0c070631",
    .format_version = 1,.path_encoding_version = 1,
  };
  WylPolicyGraphProvisioningRecord *record = NULL;
  WylPolicyAuthorityMutationResult result;
  g_assert_cmpint (wyl_policy_store_graph_provisioning_prepare (store, &input,
      &record, &result), ==, WYRELOG_E_OK);
  gchar *op_uuid = g_strdup (record->op_uuid);
  wyl_policy_graph_provisioning_record_free (record);
  const WylPolicyGraphProvisioningPhase phases[] = {
    WYL_POLICY_GRAPH_PROVISIONING_RESERVED,
    WYL_POLICY_GRAPH_PROVISIONING_STAGED,
    WYL_POLICY_GRAPH_PROVISIONING_PUBLISHED,
    WYL_POLICY_GRAPH_PROVISIONING_VERIFIED,
  };
  for (gsize i = 0; i + 1 < G_N_ELEMENTS (phases); i++)
    g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
        op_uuid, phases[i], phases[i + 1], 0,
        WYL_POLICY_GRAPH_ERROR_NONE, &result), ==, WYRELOG_E_OK);
  wyl_policy_store_graph_authority_mutation_fail_once (store,
      WYL_POLICY_GRAPH_AUTHORITY_MUTATION_FAIL_AFTER_UPDATE);
  g_assert_cmpint (wyl_policy_store_graph_provisioning_transition (store,
      op_uuid, WYL_POLICY_GRAPH_PROVISIONING_VERIFIED,
      WYL_POLICY_GRAPH_PROVISIONING_ACTIVE, 0,
      WYL_POLICY_GRAPH_ERROR_NONE, &result), ==, WYRELOG_E_IO);
  g_assert_cmpstr (scalar_text (db, "SELECT lifecycle_state FROM fact_graphs "
      "WHERE tenant_id='tenant-provision-terminal' AND graph_id='graph-provision-terminal';"),
      ==, "provisioning");
  g_assert_cmpint (wyl_policy_store_graph_provisioning_read (store, op_uuid,
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->phase, ==, WYL_POLICY_GRAPH_PROVISIONING_VERIFIED);
  wyl_policy_graph_provisioning_record_free (record);
  g_free (op_uuid);
}

/* #545: the relation-activation authority FSM is fail-closed. A row starts
 * unbound, transitions only along legal edges with generation+1, keeps exactly
 * one active schema version pinned within a state, and rejects illegal edges,
 * out-of-band generation moves, and non-unbound inserts. */
static void
test_relation_activation_fsm_is_fail_closed (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-a", "graph-a", FALSE);
  exec_ok (db, "INSERT INTO fact_namespaces "
      "(tenant_id,graph_id,namespace_id,created_at,updated_at) "
      "VALUES ('tenant-a','graph-a','ns',1,1);");
  exec_ok (db, "INSERT INTO fact_relation_schemas "
      "(tenant_id,graph_id,namespace_id,relation_name,schema_version,arity,"
      "created_at,updated_at) VALUES "
      "('tenant-a','graph-a','ns','rel',1,2,1,1),"
      "('tenant-a','graph-a','ns','rel',2,2,1,1);");

  /* Insert must start unbound. */
  exec_rejected (db, "INSERT INTO fact_relation_activation "
      "(tenant_id,graph_id,namespace_id,relation_name,lifecycle_state,"
      "active_schema_version,created_at,updated_at) VALUES "
      "('tenant-a','graph-a','ns','rel','active',1,1,1);");
  exec_ok (db, "INSERT INTO fact_relation_activation "
      "(tenant_id,graph_id,namespace_id,relation_name,created_at,updated_at) "
      "VALUES ('tenant-a','graph-a','ns','rel',1,1);");

  /* unbound -> active directly (skips activating) is an illegal edge. */
  exec_rejected (db, "UPDATE fact_relation_activation SET "
      "lifecycle_state='active',active_schema_version=1,"
      "activation_generation=1,updated_at=2 WHERE relation_name='rel';");
  /* unbound -> activating requires generation+1. */
  exec_ok (db, "UPDATE fact_relation_activation SET lifecycle_state='activating',"
      "pending_schema_version=1,activation_generation=1,updated_at=2 "
      "WHERE relation_name='rel';");
  /* Same-state generation bump is rejected. */
  exec_rejected (db, "UPDATE fact_relation_activation SET "
      "activation_generation=2,updated_at=3 WHERE relation_name='rel';");
  /* activating -> active binds the version. */
  exec_ok (db, "UPDATE fact_relation_activation SET lifecycle_state='active',"
      "active_schema_version=1,pending_schema_version=NULL,"
      "activation_generation=2,updated_at=3 WHERE relation_name='rel';");
  /* The active version is pinned while the state is unchanged. */
  exec_rejected (db, "UPDATE fact_relation_activation SET "
      "active_schema_version=2,updated_at=4 WHERE relation_name='rel';");
  /* Supersede active(1) -> activating(2) -> active(2). */
  exec_ok (db, "UPDATE fact_relation_activation SET lifecycle_state='activating',"
      "pending_schema_version=2,activation_generation=3,updated_at=4 "
      "WHERE relation_name='rel';");
  exec_ok (db, "UPDATE fact_relation_activation SET lifecycle_state='active',"
      "active_schema_version=2,pending_schema_version=NULL,"
      "activation_generation=4,updated_at=5 WHERE relation_name='rel';");

  g_assert_cmpint (scalar_int64 (db, "SELECT active_schema_version FROM "
      "fact_relation_activation WHERE relation_name='rel';"), ==, 2);
  g_assert_cmpint (scalar_int64 (db, "SELECT count(*) FROM "
      "fact_relation_activation WHERE lifecycle_state='active';"), ==, 1);
}

/* #545: the typed C API over the relation-activation FSM reserves, reads,
 * lists, and transitions with generation-CAS, classifying no-op updates as
 * replay/stale/not-found and refusing illegal edges fail-closed. */
static void
test_relation_activation_typed_api (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (NULL, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  sqlite3 *db = wyl_policy_store_get_db (store);
  insert_graph (db, "tenant-a", "graph-a", FALSE);
  exec_ok (db, "INSERT INTO fact_namespaces "
      "(tenant_id,graph_id,namespace_id,created_at,updated_at) "
      "VALUES ('tenant-a','graph-a','ns',1,1);");
  exec_ok (db, "INSERT INTO fact_relation_schemas "
      "(tenant_id,graph_id,namespace_id,relation_name,schema_version,arity,"
      "created_at,updated_at) VALUES "
      "('tenant-a','graph-a','ns','rel',1,2,1,1),"
      "('tenant-a','graph-a','ns','rel',2,2,1,1);");

  WylPolicyAuthorityMutationResult result;
  /* Reserve creates an unbound row; the second reserve is an idempotent
   * replay. */
  g_assert_cmpint (wyl_policy_store_reserve_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);
  g_assert_cmpint (wyl_policy_store_reserve_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  WylPolicyRelationActivationRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_read_relation_activation (store, "tenant-a",
      "graph-a", "ns", "rel", &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->lifecycle_state, ==,
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND);
  g_assert_false (record->has_active_schema_version);
  g_assert_cmpint (record->activation_generation, ==, 0);
  wyl_policy_relation_activation_record_free (record);

  /* No active relations are listed yet. */
  GPtrArray *listed = NULL;
  g_assert_cmpint (wyl_policy_store_list_active_fact_relations (store,
      "tenant-a", "graph-a", &listed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 0);
  g_ptr_array_unref (listed);

  /* unbound(gen0) -> activating pins the pending version and bumps to gen1. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel",
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
      "none", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);

  /* Replaying the same transition from the now-consumed expectation is an
   * idempotent replay, not a second apply. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel",
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
      "none", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_UNCHANGED_REPLAY);

  /* A stale expected generation is reported as STALE, not applied. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel",
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 7,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
      "none", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_STALE);

  /* activating(gen1) -> active binds the active version and bumps to gen2. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel",
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, 1,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE, TRUE, 1, FALSE, 0,
      "none", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_APPLIED);

  g_assert_cmpint (wyl_policy_store_read_relation_activation (store, "tenant-a",
      "graph-a", "ns", "rel", &record), ==, WYRELOG_E_OK);
  g_assert_cmpint (record->lifecycle_state, ==,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE);
  g_assert_true (record->has_active_schema_version);
  g_assert_cmpuint (record->active_schema_version, ==, 1);
  g_assert_false (record->has_pending_schema_version);
  g_assert_cmpint (record->activation_generation, ==, 2);
  wyl_policy_relation_activation_record_free (record);

  /* The active relation is now enumerated. */
  g_assert_cmpint (wyl_policy_store_list_active_fact_relations (store,
      "tenant-a", "graph-a", &listed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 1);
  WylPolicyRelationActivationRecord *first = g_ptr_array_index (listed, 0);
  g_assert_cmpstr (first->relation_name, ==, "rel");
  g_assert_cmpuint (first->active_schema_version, ==, 1);
  g_ptr_array_unref (listed);

  /* An illegal edge (active -> unbound) is refused fail-closed by the guard. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "rel",
      WYL_POLICY_RELATION_ACTIVATION_ACTIVE, 2,
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, FALSE, 0, FALSE, 0,
      "none", &result), ==, WYRELOG_E_POLICY);

  /* Transitioning an absent relation reports NOT_FOUND. */
  g_assert_cmpint (wyl_policy_store_transition_relation_activation (store,
      "tenant-a", "graph-a", "ns", "absent",
      WYL_POLICY_RELATION_ACTIVATION_UNBOUND, 0,
      WYL_POLICY_RELATION_ACTIVATION_ACTIVATING, FALSE, 0, TRUE, 1,
      "none", &result), ==, WYRELOG_E_OK);
  g_assert_cmpint (result, ==, WYL_POLICY_AUTHORITY_MUTATION_NOT_FOUND);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy/graph-authority/recovery-mac-handle-contract",
      test_recovery_mac_handle_contract);
  g_test_add_func ("/policy/graph-authority/fresh-schema",
      test_fresh_schema_is_legacy_unclassified);
  g_test_add_func ("/policy/graph-authority/provisioning-schema-fails-closed",
      test_provisioning_schema_is_fail_closed);
  g_test_add_func ("/policy/graph-authority/provisioning-degraded-terminal",
      test_provisioning_degraded_terminal_coupling);
  g_test_add_func ("/policy/graph-authority/malformed-provisioning-schema",
      test_malformed_provisioning_schema_fails_closed);
  g_test_add_func ("/policy/graph-authority/provisioning-trigger-verified",
      test_provisioning_immutable_trigger_is_verified);
  g_test_add_func ("/policy/graph-authority/provisioning-private-api",
      test_graph_provisioning_private_api);
  g_test_add_func ("/policy/graph-authority/provisioning-blob-phase",
      test_graph_provisioning_blob_phase_fails_closed);
  g_test_add_func ("/policy/graph-authority/provisioning-prepare-rollback",
      test_graph_provisioning_prepare_rolls_back_reservation);
  g_test_add_func ("/policy/graph-authority/provisioning-terminal-rollback",
      test_graph_provisioning_terminal_rolls_back);
  g_test_add_func ("/policy/graph-authority/dangling-provisioning-record",
      test_dangling_provisioning_record_fails_closed);
  g_test_add_func ("/policy/graph-authority/pre-537-idempotent",
      test_pre_537_rows_migrate_idempotently);
  g_test_add_func ("/policy/graph-authority/pre-sealed-guards",
      test_pre_sealed_generation_guards_migrate);
  g_test_add_func ("/policy/graph-authority/unknown-tenant-guard",
      test_unknown_preexisting_tenant_guard_fails_closed);
  g_test_add_func ("/policy/graph-authority/identity-state-constraints",
      test_graph_identity_and_state_constraints);
  g_test_add_func ("/policy/graph-authority/tenant-state-constraints",
      test_tenant_state_constraints);
  g_test_add_func ("/policy/graph-authority/tenant-sealed-overflow",
      test_tenant_sealed_generation_overflow);
  g_test_add_func ("/policy/graph-authority/integer-domain-constraints",
      test_integer_domain_constraints);
  g_test_add_func ("/policy/graph-authority/typed-read-list",
      test_typed_authority_reads_and_lists);
  g_test_add_func ("/policy/graph-authority/reservation-cross-connection-cas",
      test_reservation_and_cross_connection_cas);
  g_test_add_func ("/policy/graph-authority/complete-transition-matrices",
      test_complete_transition_matrices);
  g_test_add_func ("/policy/graph-authority/complete-transition-tables",
      test_complete_transition_tables_and_overflow);
  g_test_add_func ("/policy/graph-authority/nested-transaction-savepoint",
      test_nested_transaction_uses_savepoint);
  g_test_add_func ("/policy/graph-authority/mutation-fault-rollback",
      test_mutation_faults_roll_back);
  g_test_add_func ("/policy/graph-authority/fresh-fault-retry",
      test_fresh_migration_failures_reopen_and_retry);
  g_test_add_func ("/policy/graph-authority/legacy-fault-retry",
      test_legacy_failure_preserves_rows_and_retries);
  g_test_add_func ("/policy/graph-authority/malformed-object",
      test_malformed_preexisting_object_fails_closed);
  g_test_add_func ("/policy/graph-authority/missing-column-constraint",
      test_preexisting_column_without_constraint_fails_closed);
  g_test_add_func ("/policy/graph-authority/constraint-comment-spoof",
      test_constraint_comment_spoof_fails_closed);
  g_test_add_func ("/policy/graph-authority/preexisting-invalid-row",
      test_preexisting_invalid_row_fails_closed);
  g_test_add_func ("/policy/graph-authority/malformed-trigger",
      test_malformed_preexisting_trigger_fails_closed);
  g_test_add_func ("/policy/graph-authority/reconcile-journal-cas",
      test_reconcile_journal_prepare_read_list_and_cas);
  g_test_add_func
    ("/policy/graph-authority/reconcile-journal-high-bit-windows-serial",
      test_reconcile_journal_round_trips_high_bit_windows_serial);
  g_test_add_func
    ("/policy/graph-authority/reconcile-journal-evidence-fails-closed",
      test_reconcile_journal_evidence_fails_closed);
  g_test_add_func
    ("/policy/graph-authority/reconcile-evidence-trigger-verified",
      test_reconcile_evidence_trigger_is_verified);
  g_test_add_func
    ("/policy/graph-authority/reconcile-evidence-prepare-rolls-back",
      test_reconcile_evidence_prepare_rolls_back);
  g_test_add_func ("/policy/graph-authority/relation-activation-fsm",
      test_relation_activation_fsm_is_fail_closed);
  g_test_add_func ("/policy/graph-authority/relation-activation-typed-api",
      test_relation_activation_typed_api);
  return g_test_run ();
}
