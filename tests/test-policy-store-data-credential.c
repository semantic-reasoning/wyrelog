/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "human-user-test-support.h"
#include "test-exit-status.h"
#include <glib.h>
#include <glib/gstdio.h>
#include <sodium.h>
#include <sqlite3.h>
#include <string.h>

#include "audit.h"
#include "auth/service-credential-private.h"
#include "policy/store-private.h"
#include "wyl-request-id-private.h"

/* Owner-issued data credential storage (#1473). */

#define NOW G_GINT64_CONSTANT (1700000000000000)
#define HOUR (G_GINT64_CONSTANT (3600) * G_USEC_PER_SEC)
#define DAY (24 * HOUR)

typedef struct
{
  guint8 seed;
} TestProvider;

static wyrelog_error_t
provider_probe (gpointer data)
{
  (void) data;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provider_derive (gpointer data, const gchar *label, guint8 *out, gsize len)
{
  TestProvider *p = data;
  guint8 base = g_str_equal (label, "policy_store_v1") ? 0x40 : 0;
  for (gsize i = 0; i < len; i++)
    out[i] = (guint8) (base + p->seed + i);
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provider_seal (gpointer data, const guint8 *plaintext, gsize len,
    wyl_sealed_blob_t *out)
{
  (void) data;
  out->bytes = g_malloc (len);
  out->len = len;
  for (gsize i = 0; i < len; i++)
    out->bytes[i] = plaintext[i] ^ 0xa5;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
provider_unseal (gpointer data, const wyl_sealed_blob_t *blob, guint8 *out,
    gsize capacity, gsize *written)
{
  (void) data;
  if (capacity < blob->len)
    return WYRELOG_E_INVALID;
  for (gsize i = 0; i < blob->len; i++)
    out[i] = blob->bytes[i] ^ 0xa5;
  *written = blob->len;
  return WYRELOG_E_OK;
}

static void
provider_wipe (gpointer data)
{
  (void) data;
}

static void
provider_clear (gpointer data, wyl_sealed_blob_t *blob)
{
  (void) data;
  if (blob != NULL && blob->bytes != NULL) {
    sodium_memzero (blob->bytes, blob->len);
    g_free (blob->bytes);
  }
  if (blob != NULL)
    *blob = (wyl_sealed_blob_t) {
      0
    };
}

static const wyl_keyprovider_vtable_t provider_vtable = {
  .probe = provider_probe,
  .seal = provider_seal,
  .unseal = provider_unseal,
  .derive = provider_derive,
  .wipe = provider_wipe,
  .clear_sealed_blob = provider_clear,
};

static TestProvider fixture_provider = { 7 };

static wyl_policy_store_t *
open_store (const gchar *path, gboolean with_provider)
{
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = with_provider ? &provider_vtable : NULL,
    .keyprovider_state = with_provider ? &fixture_provider : NULL,
    .require_encrypted = path != NULL,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  return store;
}

static void
exec_ok (wyl_policy_store_t *store, const gchar *sql)
{
  g_assert_cmpint (sqlite3_exec (wyl_policy_store_get_db (store), sql, NULL,
      NULL, NULL), ==, SQLITE_OK);
}

/* SQLITE_OK, or the extended result code of the failure. */
static int
exec_rc (wyl_policy_store_t *store, const gchar *sql)
{
  sqlite3 *db = wyl_policy_store_get_db (store);
  if (sqlite3_exec (db, sql, NULL, NULL, NULL) == SQLITE_OK)
    return SQLITE_OK;
  return sqlite3_extended_errcode (db);
}

static void
remove_tree (const gchar *dir)
{
  g_autoptr (GDir) handle = g_dir_open (dir, 0, NULL);
  const gchar *name = NULL;
  while (handle != NULL && (name = g_dir_read_name (handle)) != NULL) {
    g_autofree gchar *child = g_build_filename (dir, name, NULL);
    g_remove (child);
  }
  g_rmdir (dir);
}

static void
add_graph (wyl_policy_store_t *store, const gchar *tenant, const gchar *graph)
{
  g_autofree gchar *sql = g_strdup_printf ("INSERT INTO fact_graphs("
          "tenant_id,graph_id,storage_uri,storage_path,schema_version,"
          "owner_scope,created_at,updated_at) VALUES('%s','%s',"
          "'wyrelog:test','test',1,'%s',1,1)", tenant, graph, tenant);
  exec_ok (store, sql);
}

/* Two tenants: tenant-a owned by alice with graphs g1 and g2, tenant-b owned
 * by bob with graph g3.  mallory is a registered human who owns nothing. */
static wyl_policy_store_t *
open_fixture (const gchar *path)
{
  wyl_policy_store_t *store = open_store (path, TRUE);
  register_test_human (store, "alice");
  register_test_human (store, "bob");
  register_test_human (store, "mallory");
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-a", "alice",
      &created), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-b", "bob",
      &created), ==, WYRELOG_E_OK);
  add_graph (store, "tenant-a", "g1");
  add_graph (store, "tenant-a", "g2");
  add_graph (store, "tenant-b", "g3");
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
      &cvk, &cvk_len), ==, WYRELOG_E_OK);
  return store;
}

static void
begin (wyl_policy_store_t *store)
{
  g_assert_cmpint (wyl_policy_store_begin_mutation (store), ==, WYRELOG_E_OK);
}

static void
commit (wyl_policy_store_t *store)
{
  g_assert_cmpint (wyl_policy_store_commit_mutation (store), ==, WYRELOG_E_OK);
}

static const gchar *
new_request (gchar buf[WYL_REQUEST_ID_STRING_BUF])
{
  g_assert_cmpint (wyl_request_id_new (buf, WYL_REQUEST_ID_STRING_BUF), ==,
      WYRELOG_E_OK);
  return buf;
}

/* Issues in its own transaction; the transaction rolls back on failure. */
static wyrelog_error_t
issue_full (wyl_policy_store_t *store, const gchar *tenant,
    const gchar *issuer, const gchar *request, guint32 operations,
    const gchar *const *graphs, gsize n_graphs, gint64 lifetime, gint64 now,
    WylDataCredentialInfo *info, wyl_service_credential_secret_t **secret)
{
  WylDataCredentialInfo scratch = { 0 };
  wyl_service_credential_secret_t *scratch_secret = NULL;
  gboolean replayed = FALSE;
  begin (store);
  wyrelog_error_t rc = wyl_policy_store_data_credential_issue (store, tenant,
          issuer, request, operations, graphs, n_graphs, lifetime, now,
          info != NULL ? info : &scratch,
          secret != NULL ? secret : &scratch_secret, &replayed);
  if (rc == WYRELOG_E_OK) {
    g_assert_false (replayed);
    commit (store);
  } else {
    wyl_policy_store_rollback_mutation (store);
  }
  wyl_data_credential_info_clear (&scratch);
  wyl_service_credential_secret_clear (&scratch_secret);
  return rc;
}

static wyrelog_error_t
issue (wyl_policy_store_t *store, guint32 operations, gint64 lifetime,
    gint64 now, WylDataCredentialInfo *info,
    wyl_service_credential_secret_t **secret)
{
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  return issue_full (store, "tenant-a", "alice", new_request (request),
             operations, NULL, 0, lifetime, now, info, secret);
}

static wyrelog_error_t
rotate (wyl_policy_store_t *store, const gchar *old_id, const gchar *actor,
    gint64 now, WylDataCredentialInfo *info,
    wyl_service_credential_secret_t **secret)
{
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  WylDataCredentialInfo scratch = { 0 };
  wyl_service_credential_secret_t *scratch_secret = NULL;
  gboolean replayed = FALSE;
  begin (store);
  wyrelog_error_t rc = wyl_policy_store_data_credential_rotate (store,
          "tenant-a", old_id, actor, new_request (request), now,
          info != NULL ? info : &scratch,
          secret != NULL ? secret : &scratch_secret, &replayed);
  if (rc == WYRELOG_E_OK)
    commit (store);
  else
    wyl_policy_store_rollback_mutation (store);
  wyl_data_credential_info_clear (&scratch);
  wyl_service_credential_secret_clear (&scratch_secret);
  return rc;
}

static void
set_settings (wyl_policy_store_t *store, gint64 max, guint32 live,
    guint32 write)
{
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_settings_set (store, max,
      live, write, "admin", NOW), ==, WYRELOG_E_OK);
  commit (store);
}

static wyrelog_error_t
verify (wyl_policy_store_t *store, const gchar *id, const gchar *secret,
    gint64 now, WylDataCredentialInfo *out)
{
  WylDataCredentialInfo scratch = { 0 };
  begin (store);
  wyrelog_error_t rc = wyl_policy_store_data_credential_verify (store, id,
          secret, secret != NULL ? strlen (secret) : 0, now,
          out != NULL ? out : &scratch);
  commit (store);
  wyl_data_credential_info_clear (&scratch);
  return rc;
}

static const gchar *
encoded (const wyl_service_credential_secret_t *secret)
{
  return wyl_service_credential_secret_peek_encoded (secret, NULL);
}

typedef struct
{
  const gchar *name;
  const gchar *type;
  int notnull;
  int pk;
} ExpectedColumn;

static void
assert_columns (wyl_policy_store_t *store, const gchar *table,
    const ExpectedColumn *expected, gsize n_expected)
{
  g_autofree gchar *sql = g_strdup_printf ("PRAGMA table_info(%s)", table);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), sql,
      -1, &stmt, NULL), ==, SQLITE_OK);
  gsize n = 0;
  while (sqlite3_step (stmt) == SQLITE_ROW) {
    g_assert_cmpuint (n, <, n_expected);
    g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 1), ==,
        expected[n].name);
    g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 2), ==,
        expected[n].type);
    g_assert_cmpint (sqlite3_column_int (stmt, 3), ==, expected[n].notnull);
    g_assert_cmpint (sqlite3_column_int (stmt, 5), ==, expected[n].pk);
    n++;
  }
  sqlite3_finalize (stmt);
  g_assert_cmpuint (n, ==, n_expected);
}

static void
test_column_roundtrip (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  static const ExpectedColumn credentials[] = {
    {"credential_id", "TEXT", 1, 1},
    {"credential_format_version", "INTEGER", 1, 0},
    {"tenant_id", "TEXT", 1, 0},
    {"issuer_subject_id", "TEXT", 1, 0},
    {"operations", "INTEGER", 1, 0}, {"graph_count", "INTEGER", 1, 0},
    {"generation", "INTEGER", 1, 0}, {"state", "TEXT", 1, 0},
    {"verifier_version", "INTEGER", 1, 0}, {"salt", "BLOB", 1, 0},
    {"verifier", "BLOB", 1, 0}, {"request_id", "TEXT", 1, 0},
    {"expires_in_us", "INTEGER", 1, 0}, {"created_at_us", "INTEGER", 1, 0},
    {"updated_at_us", "INTEGER", 1, 0}, {"expires_at_us", "INTEGER", 1, 0},
    {"last_used_at_us", "INTEGER", 0, 0}, {"revoked_by", "TEXT", 0, 0},
    {"revoked_at_us", "INTEGER", 0, 0}, {"revoked_reason", "TEXT", 0, 0},
    {"rotated_from_id", "TEXT", 0, 0},
  };
  static const ExpectedColumn graphs[] = {
    {"credential_id", "TEXT", 1, 1}, {"tenant_id", "TEXT", 1, 0},
    {"graph_id", "TEXT", 1, 2},
  };
  static const ExpectedColumn settings[] = {
    {"slot", "INTEGER", 0, 1}, {"max_expiry_us", "INTEGER", 1, 0},
    {"live_cap", "INTEGER", 1, 0}, {"write_cap", "INTEGER", 1, 0},
    {"updated_by", "TEXT", 1, 0}, {"updated_at_us", "INTEGER", 1, 0},
  };
  assert_columns (store, "data_credentials", credentials,
      G_N_ELEMENTS (credentials));
  assert_columns (store, "data_credential_graphs", graphs,
      G_N_ELEMENTS (graphs));
  assert_columns (store, "data_credential_settings", settings,
      G_N_ELEMENTS (settings));

  const gchar *scope[] = { "g2", "g1" };
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  new_request (request);
  g_auto (WylDataCredentialInfo) first = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-a", "alice", request,
      WYL_DATA_CREDENTIAL_OP_QUERY | WYL_DATA_CREDENTIAL_OP_INSERT, scope, 2,
      10 * DAY, NOW, &first, NULL), ==, WYRELOG_E_OK);
  g_assert_true (wyl_data_credential_id_is_canonical (first.credential_id,
      strlen (first.credential_id)));
  g_assert_cmpuint (first.credential_format_version, ==, 1);
  g_assert_cmpstr (first.tenant_id, ==, "tenant-a");
  g_assert_cmpstr (first.issuer_subject_id, ==, "alice");
  g_assert_cmpuint (first.operations, ==, 0x5);
  g_assert_cmpuint (first.graph_ids->len, ==, 2);
  g_assert_cmpstr (g_ptr_array_index (first.graph_ids, 0), ==, "g1");
  g_assert_cmpstr (g_ptr_array_index (first.graph_ids, 1), ==, "g2");
  g_assert_cmpuint (first.generation, ==, 1);
  g_assert_cmpstr (first.state, ==, "active");
  g_assert_cmpstr (first.request_id, ==, request);
  g_assert_cmpint (first.expires_in_us, ==, 10 * DAY);
  g_assert_cmpint (first.created_at_us, ==, NOW);
  g_assert_cmpint (first.updated_at_us, ==, NOW);
  g_assert_cmpint (first.expires_at_us, ==, NOW + 10 * DAY);
  g_assert_cmpint (first.last_used_at_us, ==, 0);
  g_assert_null (first.revoked_by);
  g_assert_cmpint (first.revoked_at_us, ==, 0);
  g_assert_null (first.revoked_reason);
  g_assert_null (first.rotated_from_id);

  g_auto (WylDataCredentialInfo) second = { 0 };
  g_assert_cmpint (rotate (store, first.credential_id, "alice", NOW + HOUR,
      &second, NULL), ==, WYRELOG_E_OK);

  /* Every stored column, read raw with its storage class. */
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
      "SELECT credential_id,typeof(credential_format_version),"
      "credential_format_version,tenant_id,issuer_subject_id,operations,"
      "graph_count,generation,state,verifier_version,typeof(salt),length(salt),"
      "typeof(verifier),length(verifier),request_id,expires_in_us,"
      "created_at_us,updated_at_us,expires_at_us,last_used_at_us,revoked_by,"
      "revoked_at_us,revoked_reason,rotated_from_id FROM data_credentials "
      "ORDER BY generation", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 0), ==,
      first.credential_id);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 1), ==,
      "integer");
  g_assert_cmpint (sqlite3_column_int (stmt, 2), ==, 1);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 3), ==,
      "tenant-a");
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 4), ==, "alice");
  g_assert_cmpint (sqlite3_column_int (stmt, 5), ==, 0x5);
  g_assert_cmpint (sqlite3_column_int (stmt, 6), ==, 2);
  g_assert_cmpint (sqlite3_column_int (stmt, 7), ==, 1);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 8), ==,
      "revoked");
  g_assert_cmpint (sqlite3_column_int (stmt, 9), ==, 1);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 10), ==, "blob");
  g_assert_cmpint (sqlite3_column_int (stmt, 11), ==, 16);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 12), ==, "blob");
  g_assert_cmpint (sqlite3_column_int (stmt, 13), ==, 32);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 14), ==,
      request);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 15), ==, 10 * DAY);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 16), ==, NOW);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 17), ==, NOW + HOUR);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 18), ==, NOW + 10 * DAY);
  g_assert_cmpint (sqlite3_column_type (stmt, 19), ==, SQLITE_NULL);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 20), ==,
      "alice");
  g_assert_cmpint (sqlite3_column_int64 (stmt, 21), ==, NOW + HOUR);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 22), ==,
      "rotated");
  g_assert_cmpint (sqlite3_column_type (stmt, 23), ==, SQLITE_NULL);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 0), ==,
      second.credential_id);
  g_assert_cmpint (sqlite3_column_int (stmt, 7), ==, 2);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 8), ==,
      "active");
  g_assert_cmpint (sqlite3_column_int64 (stmt, 16), ==, NOW + HOUR);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 18), ==, NOW + 10 * DAY);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 23), ==,
      first.credential_id);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);

  g_assert_cmpstr (second.rotated_from_id, ==, first.credential_id);
  g_assert_cmpuint (second.generation, ==, 2);
  g_assert_cmpuint (second.operations, ==, first.operations);
  g_assert_cmpint (second.expires_at_us, ==, first.expires_at_us);
  g_assert_cmpuint (second.graph_ids->len, ==, 2);

  /* Graph rows of both generations. */
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
      "SELECT credential_id,tenant_id,graph_id FROM data_credential_graphs "
      "ORDER BY credential_id=?1 DESC,graph_id", -1, &stmt, NULL), ==,
      SQLITE_OK);
  sqlite3_bind_text (stmt, 1, first.credential_id, -1, SQLITE_TRANSIENT);
  const gchar *expected_rows[4][3] = {
    {first.credential_id, "tenant-a", "g1"},
    {first.credential_id, "tenant-a", "g2"},
    {second.credential_id, "tenant-a", "g1"},
    {second.credential_id, "tenant-a", "g2"},
  };
  for (guint i = 0; i < 4; i++) {
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    for (guint c = 0; c < 3; c++)
      g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, (int) c),
          ==, expected_rows[i][c]);
  }
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_DONE);
  sqlite3_finalize (stmt);

  /* The settings row. */
  set_settings (store, 30 * DAY, 10, 4);
  WylDataCredentialSettings stored = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_settings_get (store,
      &stored), ==, WYRELOG_E_OK);
  g_assert_false (stored.is_default);
  g_assert_cmpint (stored.max_expiry_us, ==, 30 * DAY);
  g_assert_cmpuint (stored.live_cap, ==, 10);
  g_assert_cmpuint (stored.write_cap, ==, 4);
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
      "SELECT slot,max_expiry_us,live_cap,write_cap,updated_by,updated_at_us "
      "FROM data_credential_settings", -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 1);
  g_assert_cmpint (sqlite3_column_int64 (stmt, 1), ==, 30 * DAY);
  g_assert_cmpint (sqlite3_column_int (stmt, 2), ==, 10);
  g_assert_cmpint (sqlite3_column_int (stmt, 3), ==, 4);
  g_assert_cmpstr ((const gchar *) sqlite3_column_text (stmt, 4), ==, "admin");
  g_assert_cmpint (sqlite3_column_int64 (stmt, 5), ==, NOW);
  sqlite3_finalize (stmt);

  /* lookup and list agree with the issue results. */
  g_auto (WylDataCredentialInfo) looked = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_lookup (store,
      second.credential_id, &looked), ==, WYRELOG_E_OK);
  g_assert_cmpstr (looked.rotated_from_id, ==, first.credential_id);
  g_autoptr (GPtrArray) listed = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_list (store, "tenant-a",
      &listed), ==, WYRELOG_E_OK);
  g_assert_cmpuint (listed->len, ==, 2);
  WylDataCredentialInfo *l0 = g_ptr_array_index (listed, 0);
  g_assert_cmpstr (l0->credential_id, ==, first.credential_id);
  g_autoptr (GPtrArray) other = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_list (store, "tenant-b",
      &other), ==, WYRELOG_E_OK);
  g_assert_cmpuint (other->len, ==, 0);
}

static void
test_check_constraints (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  g_auto (WylDataCredentialInfo) info = { 0 };
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW,
      &info, NULL), ==, WYRELOG_E_OK);
  const gchar *row = "INSERT INTO data_credentials(credential_id,"
      "credential_format_version,tenant_id,issuer_subject_id,operations,"
      "graph_count,generation,state,verifier_version,salt,verifier,request_id,"
      "expires_in_us,created_at_us,updated_at_us,expires_at_us) VALUES("
      "'wdc_000000000000000000000000001',1,'tenant-a','alice',%s,0,1,'active',"
      "1,zeroblob(16),zeroblob(32),'raw-request',%s,1,1,%s)";
  struct
  {
    const gchar *operations;
    const gchar *lifetime;
    const gchar *expires;
    int expected;
  } cases[] = {
    {"32", "1", "2", SQLITE_CONSTRAINT_CHECK},
    {"0", "1", "2", SQLITE_CONSTRAINT_CHECK},
    {"1", "1", "NULL", SQLITE_CONSTRAINT_NOTNULL},
    {"1", "1", "'later'", SQLITE_CONSTRAINT_CHECK},
    {"'one'", "1", "2", SQLITE_CONSTRAINT_CHECK},
    {"1", "1", "2", SQLITE_OK},
  };
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_autofree gchar *sql = g_strdup_printf (row, cases[i].operations,
            cases[i].lifetime, cases[i].expires);
    g_assert_cmpint (exec_rc (store, sql), ==, cases[i].expected);
  }

  /* An unknown tenant is a foreign-key violation. */
  g_assert_cmpint (exec_rc (store, "INSERT INTO data_credentials("
      "credential_id,credential_format_version,tenant_id,issuer_subject_id,"
      "operations,graph_count,generation,state,verifier_version,salt,verifier,"
      "request_id,expires_in_us,created_at_us,updated_at_us,expires_at_us) "
      "VALUES('wdc_000000000000000000000000002',1,'no-tenant','alice',1,0,1,"
      "'active',1,zeroblob(16),zeroblob(32),'raw-request-2',1,1,1,2)"), ==,
      SQLITE_CONSTRAINT_FOREIGNKEY);

  /* A revoked row must say who revoked it, when and why. */
  g_autofree gchar *revoke = g_strdup_printf ("UPDATE data_credentials SET "
          "state='revoked',revoked_at_us=5,revoked_reason='revoked' "
          "WHERE credential_id='%s'", info.credential_id);
  g_assert_cmpint (exec_rc (store, revoke), ==, SQLITE_CONSTRAINT_CHECK);

  /* The settings singleton enforces its bounds. */
  g_assert_cmpint (exec_rc (store, "INSERT INTO data_credential_settings "
      "VALUES(1,86400000000,4,5,'admin',1)"), ==, SQLITE_CONSTRAINT_CHECK);
  g_assert_cmpint (exec_rc (store, "INSERT INTO data_credential_settings "
      "VALUES(1,0,4,1,'admin',1)"), ==, SQLITE_CONSTRAINT_CHECK);
  g_assert_cmpint (exec_rc (store, "INSERT INTO data_credential_settings "
      "VALUES(2,86400000000,4,1,'admin',1)"), ==, SQLITE_CONSTRAINT_CHECK);
}

static void
test_immutability (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  const gchar *scope[] = { "g1" };
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_auto (WylDataCredentialInfo) info = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (issue_full (store, "tenant-a", "alice",
      new_request (request), WYL_DATA_CREDENTIAL_OP_QUERY, scope, 1, DAY, NOW,
      &info, &secret), ==, WYRELOG_E_OK);
  g_assert_cmpint (verify (store, info.credential_id, encoded (secret),
      NOW + 10, NULL), ==, WYRELOG_E_OK);
  wyl_service_credential_secret_clear (&secret);
  const gchar *updates[] = {
    "operations=31", "expires_at_us=expires_at_us+1", "issuer_subject_id='bob'",
    "graph_count=2", "salt=zeroblob(16)", "tenant_id='tenant-b'",
    "generation=5", "last_used_at_us=NULL",
    "last_used_at_us=last_used_at_us-1", "request_id='other'",
  };
  for (guint i = 0; i < G_N_ELEMENTS (updates); i++) {
    g_autofree gchar *sql = g_strdup_printf ("UPDATE data_credentials SET %s "
            "WHERE credential_id='%s'", updates[i], info.credential_id);
    g_assert_cmpint (exec_rc (store, sql), !=, SQLITE_OK);
  }
  /* A scope cannot be widened, by insert or by update. */
  g_autofree gchar *widen = g_strdup_printf ("INSERT INTO "
          "data_credential_graphs VALUES('%s','tenant-a','g2')",
          info.credential_id);
  g_assert_cmpint (exec_rc (store, widen), !=, SQLITE_OK);
  g_assert_cmpint (exec_rc (store, "UPDATE data_credential_graphs SET "
      "graph_id='g2'"), !=, SQLITE_OK);

  /* Revoked is terminal. */
  begin (store);
  gboolean changed = FALSE;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      info.credential_id, "alice", NOW + 1, NULL, &changed), ==,
      WYRELOG_E_OK);
  commit (store);
  g_assert_true (changed);
  g_autofree gchar *revive = g_strdup_printf ("UPDATE data_credentials SET "
          "state='active',revoked_by=NULL,revoked_at_us=NULL,"
          "revoked_reason=NULL "
          "WHERE credential_id='%s'", info.credential_id);
  g_assert_cmpint (exec_rc (store, revive), !=, SQLITE_OK);
  g_autofree gchar *reason = g_strdup_printf ("UPDATE data_credentials SET "
          "revoked_reason='rotated' WHERE credential_id='%s'",
          info.credential_id);
  g_assert_cmpint (exec_rc (store, reason), !=, SQLITE_OK);

  /* A successor that changes the scope is refused by the schema itself. */
  g_autofree gchar *successor = g_strdup_printf ("INSERT INTO "
          "data_credentials(credential_id,credential_format_version,tenant_id,"
          "issuer_subject_id,operations,graph_count,generation,state,"
          "verifier_version,salt,verifier,request_id,expires_in_us,"
          "created_at_us,updated_at_us,expires_at_us,rotated_from_id) VALUES("
          "'wdc_000000000000000000000000003',1,'tenant-a','alice',31,1,2,"
          "'active',1,zeroblob(16),zeroblob(32),'raw-successor',"
          "%" G_GINT64_FORMAT ",%" G_GINT64_FORMAT ",%" G_GINT64_FORMAT
          ",%" G_GINT64_FORMAT ",'%s')",
          DAY, NOW + 2, NOW + 2, NOW + DAY, info.credential_id);
  g_assert_cmpint (exec_rc (store, successor), !=, SQLITE_OK);
}

static void
test_issue_validation (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  const gchar *missing[] = { "g9" };
  const gchar *foreign[] = { "g3" };
  const gchar *duplicate[] = { "g1", "g1" };
  struct
  {
    const gchar *tenant;
    const gchar *issuer;
    guint32 operations;
    const gchar *const *graphs;
    gsize n_graphs;
    gint64 lifetime;
    wyrelog_error_t expected;
  } cases[] = {
    {"tenant-a", "alice", 0, NULL, 0, DAY, WYRELOG_E_INVALID},
    {"tenant-a", "alice", 0x20, NULL, 0, DAY, WYRELOG_E_INVALID},
    {"tenant-a", "alice", 1, NULL, 0, 0, WYRELOG_E_INVALID},
    {"tenant-a", "alice", 1, NULL, 0, -1, WYRELOG_E_INVALID},
    {"tenant-a", "alice", 1, NULL, 0, 90 * DAY + 1, WYRELOG_E_INVALID},
    {"tenant-a", "alice", 1, duplicate, 2, DAY, WYRELOG_E_INVALID},
    {"no-tenant", "alice", 1, NULL, 0, DAY, WYRELOG_E_NOT_FOUND},
    {"tenant-a", "alice", 1, missing, 1, DAY, WYRELOG_E_NOT_FOUND},
    {"tenant-a", "alice", 1, foreign, 1, DAY, WYRELOG_E_NOT_FOUND},
    {"tenant-a", "bob", 1, NULL, 0, DAY, WYRELOG_E_AUTH},
    {"tenant-a", "mallory", 1, NULL, 0, DAY, WYRELOG_E_AUTH},
    {"tenant-a", "alice", 1, NULL, 0, 90 * DAY, WYRELOG_E_OK},
  };
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    g_assert_cmpint (issue_full (store, cases[i].tenant, cases[i].issuer,
        new_request (request), cases[i].operations, cases[i].graphs,
        cases[i].n_graphs, cases[i].lifetime, NOW, NULL, NULL), ==,
        cases[i].expected);

  /* The built-in tenant never holds data credentials. */
  g_assert_cmpint (wyl_policy_store_ensure_default_tenant (store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (issue_full (store, "__wr_default", "alice",
      new_request (request), 1, NULL, 0, DAY, NOW, NULL, NULL), ==,
      WYRELOG_E_POLICY);

  /* A sealed tenant refuses issue. */
  g_assert_cmpint (wyl_policy_store_set_tenant_sealed (store, "tenant-b",
      TRUE), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue_full (store, "tenant-b", "bob", new_request (request),
      1, NULL, 0, DAY, NOW, NULL, NULL), ==, WYRELOG_E_POLICY);

  /* Mutations are transaction bodies. */
  WylDataCredentialInfo info = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  gboolean replayed = FALSE;
  g_assert_cmpint (wyl_policy_store_data_credential_issue (store, "tenant-a",
      "alice", new_request (request), 1, NULL, 0, DAY, NOW, &info, &secret,
      &replayed), ==, WYRELOG_E_INVALID);
  g_assert_null (secret);
  g_assert_null (info.credential_id);
}

static void
test_caps (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  set_settings (store, 90 * DAY, 3, 1);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_INSERT, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_OK);
  /* The write cap refuses a second write-capable credential, for each write
   * operation, while a read-only one still fits. */
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_DELETE, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_RESOURCE_LIMIT);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_UPDATE
      | WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL, NULL), ==,
      WYRELOG_E_RESOURCE_LIMIT);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_INFER, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_OK);
  /* The live cap. */
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_RESOURCE_LIMIT);
  /* Caps are per tenant. */
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_assert_cmpint (issue_full (store, "tenant-b", "bob", new_request (request),
      WYL_DATA_CREDENTIAL_OP_INSERT, NULL, 0, DAY, NOW, NULL, NULL), ==,
      WYRELOG_E_OK);
}

static void
test_caps_exclude_inactive (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  set_settings (store, 90 * DAY, 2, 1);
  g_auto (WylDataCredentialInfo) writer = { 0 };
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_INSERT, DAY, NOW,
      &writer, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, HOUR, NOW,
      NULL, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_RESOURCE_LIMIT);
  /* An expired credential stops counting. */
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY,
      NOW + 2 * HOUR, NULL, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_DELETE, DAY,
      NOW + 2 * HOUR, NULL, NULL), ==, WYRELOG_E_RESOURCE_LIMIT);
  /* So does a revoked one, for both caps. */
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      writer.credential_id, "alice", NOW + 2 * HOUR, NULL, NULL), ==,
      WYRELOG_E_OK);
  commit (store);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_DELETE, DAY,
      NOW + 2 * HOUR, NULL, NULL), ==, WYRELOG_E_OK);
}

static void
test_settings (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  WylDataCredentialSettings settings = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_settings_get (store,
      &settings), ==, WYRELOG_E_OK);
  g_assert_true (settings.is_default);
  g_assert_cmpint (settings.max_expiry_us, ==, 90 * DAY);
  g_assert_cmpuint (settings.live_cap, ==, 32);
  g_assert_cmpuint (settings.write_cap, ==, 8);
  struct
  {
    gint64 max;
    guint32 live;
    guint32 write;
  } bad[] = {
    {90 * DAY, 4, 5}, {0, 4, 1}, {-1, 4, 1}, {G_MAXINT64, 4, 1},
    {3650 * DAY + 1, 4, 1}, {HOUR - 1, 4, 1}, {90 * DAY, 0, 0},
    {90 * DAY, 1025, 1},
  };
  begin (store);
  for (guint i = 0; i < G_N_ELEMENTS (bad); i++)
    g_assert_cmpint (wyl_policy_store_data_credential_settings_set (store,
        bad[i].max, bad[i].live, bad[i].write, "admin", NOW), ==,
        WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_policy_store_data_credential_settings_set (store,
      HOUR, 1, 0, "admin", NOW), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_data_credential_settings_set (store,
      3650 * DAY, 1024, 1024, "admin", NOW), ==, WYRELOG_E_OK);
  commit (store);
  g_assert_cmpint (wyl_policy_store_data_credential_settings_set (store,
      HOUR, 1, 0, "admin", NOW), ==, WYRELOG_E_INVALID);

  /* Lowering the maximum refuses a lifetime the old one allowed. */
  set_settings (store, 30 * DAY, 32, 8);
  g_assert_cmpint (issue (store, 1, 31 * DAY, NOW, NULL, NULL), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (issue (store, 1, 30 * DAY, NOW, NULL, NULL), ==,
      WYRELOG_E_OK);
}

static void
test_rotate (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  set_settings (store, 90 * DAY, 1, 1);
  g_auto (WylDataCredentialInfo) first = { 0 };
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_INSERT, 80 * DAY, NOW,
      &first, NULL), ==, WYRELOG_E_OK);

  /* At the cap, rotation still succeeds: the old credential is revoked
   * before the count. */
  g_auto (WylDataCredentialInfo) second = { 0 };
  g_assert_cmpint (rotate (store, first.credential_id, "alice", NOW + DAY,
      &second, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpstr (second.rotated_from_id, ==, first.credential_id);

  /* After the maximum is lowered, rotation keeps the original expiry. */
  set_settings (store, 30 * DAY, 1, 1);
  g_auto (WylDataCredentialInfo) third = { 0 };
  g_assert_cmpint (rotate (store, second.credential_id, "alice", NOW + 2 * DAY,
      &third, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (third.expires_at_us, ==, NOW + 80 * DAY);
  g_assert_cmpuint (third.generation, ==, 3);

  /* After a cap is lowered below the count, rotation still succeeds and
   * issuance is refused. */
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_RESOURCE_LIMIT);
  g_auto (WylDataCredentialInfo) fourth = { 0 };
  g_assert_cmpint (rotate (store, third.credential_id, "alice", NOW + 3 * DAY,
      &fourth, NULL), ==, WYRELOG_E_OK);

  /* Only an active credential can be rotated. */
  g_assert_cmpint (rotate (store, third.credential_id, "alice", NOW + 3 * DAY,
      NULL, NULL), ==, WYRELOG_E_CONFLICT);
  g_assert_cmpint (rotate (store, fourth.credential_id, "alice",
      NOW + 81 * DAY, NULL, NULL), ==, WYRELOG_E_CONFLICT);

  /* Only the owner who issued it can rotate it. */
  g_assert_cmpint (rotate (store, fourth.credential_id, "bob", NOW + 4 * DAY,
      NULL, NULL), ==, WYRELOG_E_AUTH);
  g_assert_cmpint (rotate (store, fourth.credential_id, "mallory",
      NOW + 4 * DAY, NULL, NULL), ==, WYRELOG_E_AUTH);
  g_assert_cmpint (rotate (store, "wdc_000000000000000000000000009", "alice",
      NOW + 4 * DAY, NULL, NULL), ==, WYRELOG_E_NOT_FOUND);

  /* An owner who is no longer an active human can neither rotate nor issue. */
  exec_ok (store, "UPDATE human_users SET state='disabled',"
      "generation=generation+1,updated_at_us=updated_at_us+1 "
      "WHERE subject_id='alice'");
  g_assert_cmpint (rotate (store, fourth.credential_id, "alice", NOW + 4 * DAY,
      NULL, NULL), ==, WYRELOG_E_SUBJECT_NOT_REGISTERED);
  set_settings (store, 90 * DAY, 8, 1);
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, NULL,
      NULL), ==, WYRELOG_E_SUBJECT_NOT_REGISTERED);
}

static void
test_verify (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  g_auto (WylDataCredentialInfo) info = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW, &info,
      &secret), ==, WYRELOG_E_OK);
  g_autofree gchar *text = g_strdup (encoded (secret));
  wyl_service_credential_secret_clear (&secret);

  g_auto (WylDataCredentialInfo) verified = { 0 };
  g_assert_cmpint (verify (store, info.credential_id, text, NOW + 10,
      &verified), ==, WYRELOG_E_OK);
  g_assert_cmpstr (verified.credential_id, ==, info.credential_id);
  g_assert_cmpint (verified.last_used_at_us, ==, NOW + 10);

  /* Last use never moves backwards. */
  g_assert_cmpint (verify (store, info.credential_id, text, NOW + 5, NULL), ==,
      WYRELOG_E_OK);
  g_auto (WylDataCredentialInfo) looked = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_lookup (store,
      info.credential_id, &looked), ==, WYRELOG_E_OK);
  g_assert_cmpint (looked.last_used_at_us, ==, NOW + 10);

  g_autofree gchar *wrong = g_strdup (text);
  wrong[0] = wrong[0] == 'A' ? 'B' : 'A';
  g_assert_cmpint (verify (store, info.credential_id, wrong, NOW + 20, NULL),
      ==, WYRELOG_E_AUTH);
  g_assert_cmpint (verify (store, "wdc_000000000000000000000000009", text,
      NOW + 20, NULL), ==, WYRELOG_E_AUTH);
  g_assert_cmpint (verify (store, info.credential_id, text, NOW + DAY, NULL),
      ==, WYRELOG_E_AUTH);
  g_assert_cmpint (verify (store, info.credential_id, "short", NOW + 20,
      NULL), ==, WYRELOG_E_INVALID);

  g_auto (WylDataCredentialInfo) successor = { 0 };
  wyl_service_credential_secret_t *successor_secret = NULL;
  g_assert_cmpint (rotate (store, info.credential_id, "alice", NOW + 30,
      &successor, &successor_secret), ==, WYRELOG_E_OK);
  g_assert_cmpint (verify (store, info.credential_id, text, NOW + 40, NULL),
      ==, WYRELOG_E_AUTH);
  g_assert_cmpint (verify (store, successor.credential_id, text, NOW + 40,
      NULL), ==, WYRELOG_E_AUTH);
  g_assert_cmpint (verify (store, successor.credential_id,
      encoded (successor_secret), NOW + 40, NULL), ==, WYRELOG_E_OK);
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      successor.credential_id, "alice", NOW + 50, NULL, NULL), ==,
      WYRELOG_E_OK);
  commit (store);
  g_assert_cmpint (verify (store, successor.credential_id,
      encoded (successor_secret), NOW + 60, NULL), ==, WYRELOG_E_AUTH);
  wyl_service_credential_secret_clear (&successor_secret);

  /* Refusals left last use where the last success put it. */
  g_auto (WylDataCredentialInfo) after = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_lookup (store,
      info.credential_id, &after), ==, WYRELOG_E_OK);
  g_assert_cmpint (after.last_used_at_us, ==, NOW + 10);
}

static void
test_revoke_and_bulk (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  g_auto (WylDataCredentialInfo) a1 = { 0 };
  g_auto (WylDataCredentialInfo) a2 = { 0 };
  g_auto (WylDataCredentialInfo) a3 = { 0 };
  g_assert_cmpint (issue (store, 1, DAY, NOW, &a1, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, 1, DAY, NOW, &a2, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, 1, HOUR, NOW, &a3, NULL), ==, WYRELOG_E_OK);
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  g_auto (WylDataCredentialInfo) b1 = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-b", "bob", new_request (request),
      1, NULL, 0, DAY, NOW, &b1, NULL), ==, WYRELOG_E_OK);

  /* A credential is revoked only through its own tenant; a repeat is a
   * no-op. */
  begin (store);
  gboolean changed = TRUE;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-b",
      a1.credential_id, "bob", NOW + 1, NULL, &changed), ==,
      WYRELOG_E_NOT_FOUND);
  g_auto (WylDataCredentialInfo) revoked = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      a1.credential_id, "admin", NOW + 1, &revoked, &changed), ==,
      WYRELOG_E_OK);
  g_assert_true (changed);
  g_assert_cmpstr (revoked.state, ==, "revoked");
  g_assert_cmpstr (revoked.revoked_by, ==, "admin");
  g_assert_cmpstr (revoked.revoked_reason, ==, "revoked");
  g_assert_cmpint (revoked.revoked_at_us, ==, NOW + 1);
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      a1.credential_id, "admin", NOW + 2, NULL, &changed), ==, WYRELOG_E_OK);
  g_assert_false (changed);
  commit (store);

  /* Bulk revocation by issuer returns exactly the active rows it revoked,
   * including an expired one, ordered by id. */
  begin (store);
  g_autoptr (GPtrArray) by_issuer = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke_issuer (store,
      "alice", NULL, "admin", WYL_DATA_CREDENTIAL_REVOKE_ISSUER_DISABLED,
      NOW + 2 * HOUR, &by_issuer), ==, WYRELOG_E_OK);
  commit (store);
  g_assert_cmpuint (by_issuer->len, ==, 2);
  const gchar *expected_first = g_strcmp0 (a2.credential_id,
          a3.credential_id) < 0 ? a2.credential_id : a3.credential_id;
  WylDataCredentialInfo *r0 = g_ptr_array_index (by_issuer, 0);
  g_assert_cmpstr (r0->credential_id, ==, expected_first);
  for (guint i = 0; i < by_issuer->len; i++) {
    WylDataCredentialInfo *r = g_ptr_array_index (by_issuer, i);
    g_assert_cmpstr (r->state, ==, "revoked");
    g_assert_cmpstr (r->revoked_reason, ==, "issuer_disabled");
    g_assert_cmpstr (r->revoked_by, ==, "admin");
    g_assert_cmpstr (r->issuer_subject_id, ==, "alice");
  }

  /* By tenant: tenant-b only. */
  begin (store);
  g_autoptr (GPtrArray) by_tenant = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke_tenant (store,
      "tenant-b", "admin", WYL_DATA_CREDENTIAL_REVOKE_TENANT_DELETED,
      NOW + 3 * HOUR, &by_tenant), ==, WYRELOG_E_OK);
  commit (store);
  g_assert_cmpuint (by_tenant->len, ==, 1);
  WylDataCredentialInfo *t0 = g_ptr_array_index (by_tenant, 0);
  g_assert_cmpstr (t0->credential_id, ==, b1.credential_id);
  g_assert_cmpstr (t0->revoked_reason, ==, "tenant_deleted");

  /* Nothing left: a second sweep revokes nothing. */
  begin (store);
  g_autoptr (GPtrArray) again = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke_issuer (store,
      "alice", "tenant-a", "admin",
      WYL_DATA_CREDENTIAL_REVOKE_OWNERSHIP_TRANSFER, NOW + 4 * HOUR, &again),
      ==, WYRELOG_E_OK);
  commit (store);
  g_assert_cmpuint (again->len, ==, 0);

  /* A lifecycle revocation never fails on a clock that reads earlier than
   * a credential's creation: its revocation time is clamped to it.  The
   * single revoke of the routes stays exact. */
  g_auto (WylDataCredentialInfo) later = { 0 };
  g_assert_cmpint (issue (store, 1, DAY, NOW + 6 * HOUR, &later, NULL), ==,
      WYRELOG_E_OK);
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      later.credential_id, "admin", NOW + 5 * HOUR, NULL, &changed), ==,
      WYRELOG_E_IO);
  wyl_policy_store_rollback_mutation (store);
  begin (store);
  g_autoptr (GPtrArray) clamped = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_revoke_issuer (store,
      "alice", NULL, "admin", WYL_DATA_CREDENTIAL_REVOKE_ISSUER_DISABLED,
      NOW + 5 * HOUR, &clamped), ==, WYRELOG_E_OK);
  commit (store);
  g_assert_cmpuint (clamped->len, ==, 1);
  WylDataCredentialInfo *c0 = g_ptr_array_index (clamped, 0);
  g_assert_cmpint (c0->revoked_at_us, ==, NOW + 6 * HOUR);
}

static void
lookup (wyl_policy_store_t *store, const gchar *id, WylDataCredentialInfo *out)
{
  g_assert_cmpint (wyl_policy_store_data_credential_lookup (store, id, out),
      ==, WYRELOG_E_OK);
}

static gboolean
transfer (wyl_policy_store_t *store, const gchar *tenant, const gchar *actor,
    const gchar *target, const gchar *request)
{
  gboolean changed = FALSE;
  begin (store);
  g_assert_cmpint (wyl_policy_store_transfer_tenant_owner (store, tenant,
      actor, target, request, FALSE, &changed), ==, WYRELOG_E_OK);
  commit (store);
  return changed;
}

static GPtrArray *
lifecycle_audits (wyl_policy_store_t *store, const gchar *request)
{
  GPtrArray *audits = NULL;
  g_assert_cmpint (wyl_policy_store_data_credential_lifecycle_audits (store,
      request, &audits), ==, WYRELOG_E_OK);
  g_assert_nonnull (audits);
  return audits;
}

/* An ownership transfer revokes the previous owner's credentials in that
 * tenant, in its own transaction, with one audit row each (#1476). */
static void
test_lifecycle_transfer (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  gboolean created = FALSE;
  g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-c", "alice",
      &created), ==, WYRELOG_E_OK);
  /* c1 comes from a clock ahead of the store's: its revocation is clamped
   * to its creation instead of failing the transfer. */
  gint64 ahead = g_get_real_time () + HOUR;
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  const gchar *const graphs[] = { "g1", "g2" };
  g_auto (WylDataCredentialInfo) c1 = { 0 };
  g_auto (WylDataCredentialInfo) c2 = { 0 };
  g_auto (WylDataCredentialInfo) c3 = { 0 };
  g_auto (WylDataCredentialInfo) c4 = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-a", "alice",
      new_request (request), WYL_DATA_CREDENTIAL_OPS_ALL, graphs, 2, DAY,
      ahead, &c1, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue (store, 1, DAY, NOW, &c2, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue_full (store, "tenant-b", "bob", new_request (request),
      1, NULL, 0, DAY, NOW, &c3, NULL), ==, WYRELOG_E_OK);
  g_assert_cmpint (issue_full (store, "tenant-c", "alice",
      new_request (request), 1, NULL, 0, DAY, NOW, &c4, NULL), ==,
      WYRELOG_E_OK);
  gboolean changed = FALSE;
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_revoke (store, "tenant-a",
      c2.credential_id, "alice", NOW + 1, NULL, &changed), ==, WYRELOG_E_OK);
  commit (store);

  gchar first[WYL_REQUEST_ID_STRING_BUF];
  g_assert_true (transfer (store, "tenant-a", "alice", "bob",
      new_request (first)));
  g_auto (WylDataCredentialInfo) now1 = { 0 };
  lookup (store, c1.credential_id, &now1);
  g_assert_cmpstr (now1.state, ==, "revoked");
  g_assert_cmpstr (now1.revoked_reason, ==, "ownership_transfer");
  g_assert_cmpstr (now1.revoked_by, ==, "alice");
  g_assert_cmpint (now1.revoked_at_us, ==, c1.created_at_us);
  /* An already revoked credential keeps its reason; another tenant's and
   * another issuer's stay active. */
  g_auto (WylDataCredentialInfo) now2 = { 0 };
  lookup (store, c2.credential_id, &now2);
  g_assert_cmpstr (now2.revoked_reason, ==, "revoked");
  g_auto (WylDataCredentialInfo) now3 = { 0 };
  lookup (store, c3.credential_id, &now3);
  g_assert_cmpstr (now3.state, ==, "active");
  g_auto (WylDataCredentialInfo) now4 = { 0 };
  lookup (store, c4.credential_id, &now4);
  g_assert_cmpstr (now4.state, ==, "active");

  /* One audit row, naming the credential's scope and the event. */
  g_autoptr (WylAuditEvent) event = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_transfer_audit (store, first,
      &event), ==, WYRELOG_E_OK);
  g_autofree gchar *event_id = wyl_audit_event_dup_id_string (event);
  g_autoptr (GPtrArray) audits = lifecycle_audits (store, first);
  g_assert_cmpuint (audits->len, ==, 1);
  WylAuditEvent *audit = g_ptr_array_index (audits, 0);
  g_assert_cmpstr (wyl_audit_event_get_action (audit), ==,
      "data_credential_lifecycle_revoke");
  g_assert_cmpstr (wyl_audit_event_get_subject_id (audit), ==, "alice");
  g_assert_cmpstr (wyl_audit_event_get_resource_id (audit), ==, "tenant-a");
  g_assert_cmpstr (wyl_audit_event_get_deny_origin (audit), ==,
      c1.credential_id);
  g_assert_cmpstr (wyl_audit_event_get_request_id (audit), ==, first);
  g_assert_cmpint (wyl_audit_event_get_decision (audit), ==,
      WYL_DECISION_ALLOW);
  g_assert_cmpint (wyl_audit_event_get_created_at_us (audit), ==,
      wyl_audit_event_get_created_at_us (event));
  g_autofree gchar *expected = g_strdup_printf ("credential=%s;issuer=alice;"
          "operations=query,infer,insert,delete,update;graphs=g1,g2;"
          "expires_at_us=%" G_GINT64_FORMAT ";capacity=owner;"
          "reason=ownership_transfer;event=tenant_transfer_owner;"
          "event_audit=%s", c1.credential_id, c1.expires_at_us, event_id);
  g_assert_cmpstr (wyl_audit_event_get_deny_reason (audit), ==, expected);

  /* A replay revokes nothing more. */
  g_assert_true (transfer (store, "tenant-a", "alice", "bob", first));
  g_autoptr (GPtrArray) replayed = lifecycle_audits (store, first);
  g_assert_cmpuint (replayed->len, ==, 1);

  /* bob's credential in tenant-a ends when he hands it back. */
  g_auto (WylDataCredentialInfo) c5 = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-a", "bob", new_request (request),
      1, NULL, 0, DAY, g_get_real_time (), &c5, NULL), ==, WYRELOG_E_OK);
  gchar back[WYL_REQUEST_ID_STRING_BUF];
  g_assert_true (transfer (store, "tenant-a", "bob", "alice",
      new_request (back)));
  g_auto (WylDataCredentialInfo) now5 = { 0 };
  lookup (store, c5.credential_id, &now5);
  g_assert_cmpstr (now5.revoked_reason, ==, "ownership_transfer");
  g_autoptr (GPtrArray) back_audits = lifecycle_audits (store, back);
  g_assert_cmpuint (back_audits->len, ==, 1);

  /* alice owns tenant-a again.  Replaying her first transfer must not
   * revoke what she issued since. */
  g_auto (WylDataCredentialInfo) c6 = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-a", "alice",
      new_request (request), 1, NULL, 0, DAY, g_get_real_time (), &c6, NULL),
      ==, WYRELOG_E_OK);
  g_assert_true (transfer (store, "tenant-a", "alice", "bob", first));
  g_auto (WylDataCredentialInfo) now6 = { 0 };
  lookup (store, c6.credential_id, &now6);
  g_assert_cmpstr (now6.state, ==, "active");
  g_autoptr (GPtrArray) after_replay = lifecycle_audits (store, first);
  g_assert_cmpuint (after_replay->len, ==, 1);

  /* A transfer to the current owner changes nothing and revokes nothing. */
  gchar same[WYL_REQUEST_ID_STRING_BUF];
  g_assert_false (transfer (store, "tenant-a", "alice", "alice",
      new_request (same)));
  g_auto (WylDataCredentialInfo) still6 = { 0 };
  lookup (store, c6.credential_id, &still6);
  g_assert_cmpstr (still6.state, ==, "active");
  g_autoptr (GPtrArray) same_audits = lifecycle_audits (store, same);
  g_assert_cmpuint (same_audits->len, ==, 0);
}

/* The lifecycle revocation runs in the transfer's transaction: when its
 * audit cannot be written, the transfer fails and nothing changes. */
static void
test_lifecycle_transfer_atomic (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  g_auto (WylDataCredentialInfo) c1 = { 0 };
  g_assert_cmpint (issue (store, 1, DAY, NOW, &c1, NULL), ==, WYRELOG_E_OK);
  exec_ok (store, "CREATE TEMP TRIGGER fail_lifecycle BEFORE INSERT ON "
      "audit_events WHEN NEW.action='data_credential_lifecycle_revoke' "
      "BEGIN SELECT RAISE(FAIL,'lifecycle audit refused'); END");
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  gboolean changed = FALSE;
  begin (store);
  g_assert_cmpint (wyl_policy_store_transfer_tenant_owner (store, "tenant-a",
      "alice", "bob", new_request (request), FALSE, &changed), !=,
      WYRELOG_E_OK);
  wyl_policy_store_rollback_mutation (store);
  exec_ok (store, "DROP TRIGGER fail_lifecycle");
  WylPolicyTenantAuthorityRecord *record = NULL;
  g_assert_cmpint (wyl_policy_store_read_tenant_authority (store, "tenant-a",
      &record), ==, WYRELOG_E_OK);
  g_assert_cmpstr (record->owner_subject_id, ==, "alice");
  wyl_policy_tenant_authority_record_free (record);
  g_auto (WylDataCredentialInfo) now1 = { 0 };
  lookup (store, c1.credential_id, &now1);
  g_assert_cmpstr (now1.state, ==, "active");
  g_autoptr (GPtrArray) audits = lifecycle_audits (store, request);
  g_assert_cmpuint (audits->len, ==, 0);
  /* The same request then applies. */
  g_assert_true (transfer (store, "tenant-a", "alice", "bob", request));
  g_auto (WylDataCredentialInfo) after = { 0 };
  lookup (store, c1.credential_id, &after);
  g_assert_cmpstr (after.revoked_reason, ==, "ownership_transfer");
}

static void
test_replay (void)
{
  g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
  const gchar *scope[] = { "g1" };
  gchar request[WYL_REQUEST_ID_STRING_BUF];
  new_request (request);
  g_auto (WylDataCredentialInfo) first = { 0 };
  g_assert_cmpint (issue_full (store, "tenant-a", "alice", request, 1, scope,
      1, DAY, NOW, &first, NULL), ==, WYRELOG_E_OK);

  /* A retry with the same request, later, replays without a secret. */
  begin (store);
  g_auto (WylDataCredentialInfo) again = { 0 };
  wyl_service_credential_secret_t *secret = NULL;
  gboolean replayed = FALSE;
  g_assert_cmpint (wyl_policy_store_data_credential_issue (store, "tenant-a",
      "alice", request, 1, scope, 1, DAY, NOW + HOUR, &again, &secret,
      &replayed), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_null (secret);
  g_assert_cmpstr (again.credential_id, ==, first.credential_id);
  g_assert_cmpint (again.expires_at_us, ==, first.expires_at_us);
  /* A different request under the same id conflicts. */
  g_assert_cmpint (wyl_policy_store_data_credential_issue (store, "tenant-a",
      "alice", request, 3, scope, 1, DAY, NOW + HOUR, &again, &secret,
      &replayed), ==, WYRELOG_E_CONFLICT);
  g_assert_null (secret);
  commit (store);

  /* Rotation replays the same way. */
  gchar rotation[WYL_REQUEST_ID_STRING_BUF];
  new_request (rotation);
  begin (store);
  g_auto (WylDataCredentialInfo) successor = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_rotate (store, "tenant-a",
      first.credential_id, "alice", rotation, NOW + HOUR, &successor, &secret,
      &replayed), ==, WYRELOG_E_OK);
  g_assert_false (replayed);
  g_assert_nonnull (secret);
  wyl_service_credential_secret_clear (&secret);
  g_auto (WylDataCredentialInfo) repeat = { 0 };
  g_assert_cmpint (wyl_policy_store_data_credential_rotate (store, "tenant-a",
      first.credential_id, "alice", rotation, NOW + 2 * HOUR, &repeat,
      &secret, &replayed), ==, WYRELOG_E_OK);
  g_assert_true (replayed);
  g_assert_null (secret);
  g_assert_cmpstr (repeat.credential_id, ==, successor.credential_id);
  commit (store);
  /* A rotation's request id is not an issue's, even when every other field
   * of the issue matches the successor. */
  begin (store);
  g_assert_cmpint (wyl_policy_store_data_credential_issue (store, "tenant-a",
      "alice", rotation, 1, scope, 1, DAY, NOW + 2 * HOUR, &again, &secret,
      &replayed), ==, WYRELOG_E_CONFLICT);
  g_assert_null (secret);
  wyl_policy_store_rollback_mutation (store);
}

static gboolean
contains_bytes (const guint8 *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle_len > haystack_len)
    return FALSE;
  for (gsize i = 0; i <= haystack_len - needle_len; i++)
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return TRUE;
  return FALSE;
}

typedef struct
{
  guint8 raw[2][WYL_SERVICE_CREDENTIAL_SECRET_BYTES];
  gchar text[2][WYL_SERVICE_CREDENTIAL_SECRET_TEXT_BUF];
  guint8 salt[16];
  guint8 verifier[32];
} SecretNeedles;

/* The policy store's plaintext image is exactly what an encrypted store seals
 * at commit.  The positive control proves the scan sees credential rows. */
static void
assert_image_omits_secrets (wyl_policy_store_t *store,
    const SecretNeedles *needles)
{
  sqlite3_int64 len = 0;
  guint8 *image = sqlite3_serialize (wyl_policy_store_get_db (store), "main",
          &len, 0);
  g_assert_nonnull (image);
  g_assert_true (contains_bytes (image, (gsize) len, needles->salt, 16));
  g_assert_true (contains_bytes (image, (gsize) len, needles->verifier, 32));
  for (guint i = 0; i < 2; i++) {
    g_assert_false (contains_bytes (image, (gsize) len, needles->raw[i],
        WYL_SERVICE_CREDENTIAL_SECRET_BYTES));
    g_assert_false (contains_bytes (image, (gsize) len,
        (const guint8 *) needles->text[i],
        WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN));
  }
  sqlite3_free (image);
}

static void
assert_directory_omits_secrets (const gchar *dir, const SecretNeedles *needles)
{
  g_autoptr (GDir) handle = g_dir_open (dir, 0, NULL);
  g_assert_nonnull (handle);
  const gchar *name = NULL;
  guint files = 0;
  while ((name = g_dir_read_name (handle)) != NULL) {
    g_autofree gchar *path = g_build_filename (dir, name, NULL);
    if (!g_file_test (path, G_FILE_TEST_IS_REGULAR))
      continue;
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    g_assert_true (g_file_get_contents (path, &contents, &len, NULL));
    for (guint i = 0; i < 2; i++) {
      g_assert_false (contains_bytes ((const guint8 *) contents, len,
          needles->raw[i], WYL_SERVICE_CREDENTIAL_SECRET_BYTES));
      g_assert_false (contains_bytes ((const guint8 *) contents, len,
          (const guint8 *) needles->text[i],
          WYL_SERVICE_CREDENTIAL_SECRET_TEXT_LEN));
    }
    files++;
  }
  g_assert_cmpuint (files, >, 0);
}

static void
test_secret_not_persisted (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-data-cred-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "policy.sqlite", NULL);
  SecretNeedles needles = { 0 };
  g_autofree gchar *first_id = NULL;
  {
    g_autoptr (wyl_policy_store_t) store = open_fixture (path);
    g_auto (WylDataCredentialInfo) first = { 0 };
    wyl_service_credential_secret_t *secret = NULL;
    g_assert_cmpint (issue (store, WYL_DATA_CREDENTIAL_OP_QUERY, DAY, NOW,
        &first, &secret), ==, WYRELOG_E_OK);
    memcpy (needles.raw[0], wyl_service_credential_secret_peek_raw (secret,
        NULL), WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
    g_strlcpy (needles.text[0], encoded (secret), sizeof needles.text[0]);
    wyl_service_credential_secret_clear (&secret);
    g_auto (WylDataCredentialInfo) second = { 0 };
    g_assert_cmpint (rotate (store, first.credential_id, "alice", NOW + 1,
        &second, &secret), ==, WYRELOG_E_OK);
    memcpy (needles.raw[1], wyl_service_credential_secret_peek_raw (secret,
        NULL), WYL_SERVICE_CREDENTIAL_SECRET_BYTES);
    g_strlcpy (needles.text[1], encoded (secret), sizeof needles.text[1]);
    wyl_service_credential_secret_clear (&secret);

    sqlite3_stmt *stmt = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
        "SELECT salt,verifier FROM data_credentials WHERE credential_id=?",
        -1, &stmt, NULL), ==, SQLITE_OK);
    sqlite3_bind_text (stmt, 1, second.credential_id, -1, SQLITE_TRANSIENT);
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    memcpy (needles.salt, sqlite3_column_blob (stmt, 0), 16);
    memcpy (needles.verifier, sqlite3_column_blob (stmt, 1), 32);
    sqlite3_finalize (stmt);
    first_id = g_strdup (second.credential_id);
    assert_image_omits_secrets (store, &needles);
  }
  assert_directory_omits_secrets (dir, &needles);
  {
    g_autoptr (wyl_policy_store_t) store = open_store (path, TRUE);
    assert_image_omits_secrets (store, &needles);
    const guint8 *cvk = NULL;
    gsize cvk_len = 0;
    g_assert_cmpint (wyl_policy_store_materialize_service_cvk_existing (store,
        &cvk, &cvk_len), ==, WYRELOG_E_OK);
    /* The reopened store still verifies the persisted credential. */
    g_assert_cmpint (verify (store, first_id, needles.text[1], NOW + 2, NULL),
        ==, WYRELOG_E_OK);
  }
  remove_tree (dir);
}

static void
test_tenant_delete_with_credentials (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-data-cred-del-XXXXXX", NULL);
  g_autofree gchar *path = g_build_filename (dir, "policy.sqlite", NULL);
  {
    g_autoptr (wyl_policy_store_t) store = open_fixture (path);
    const gchar *scope[] = { "g3" };
    gchar request[WYL_REQUEST_ID_STRING_BUF];
    g_auto (WylDataCredentialInfo) first = { 0 };
    g_assert_cmpint (issue_full (store, "tenant-b", "bob",
        new_request (request), 1, scope, 1, DAY, NOW, &first, NULL), ==,
        WYRELOG_E_OK);
    begin (store);
    g_auto (WylDataCredentialInfo) second = { 0 };
    wyl_service_credential_secret_t *secret = NULL;
    gboolean replayed = FALSE;
    g_assert_cmpint (wyl_policy_store_data_credential_rotate (store,
        "tenant-b", first.credential_id, "bob", new_request (request),
        NOW + 1, &second, &secret, &replayed), ==, WYRELOG_E_OK);
    wyl_service_credential_secret_clear (&secret);
    commit (store);

    WylPolicyAuthorityMutationResult result;
    g_assert_cmpint (wyl_policy_store_reconcile_tenant_authority (store,
        "tenant-b", WYL_POLICY_TENANT_LIFECYCLE_SEALED, 0, 0, &result), ==,
        WYRELOG_E_OK);
    /* The delete revokes, then purges, in one transaction. */
    begin (store);
    g_autoptr (GPtrArray) revoked = NULL;
    g_assert_cmpint (wyl_policy_store_data_credential_revoke_tenant (store,
        "tenant-b", "bob", WYL_DATA_CREDENTIAL_REVOKE_TENANT_DELETED, NOW + 2,
        &revoked), ==, WYRELOG_E_OK);
    g_assert_cmpuint (revoked->len, ==, 1);
    g_auto (WylTenantDeleteRecord) record = { 0 };
    g_assert_cmpint (wyl_policy_store_tenant_delete_commit (store, "tenant-b",
        "bob", new_request (request), FALSE, "none", &record), ==,
        WYRELOG_E_OK);
    commit (store);
    sqlite3_stmt *stmt = NULL;
    g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store),
        "SELECT (SELECT count(*) FROM data_credentials WHERE tenant_id="
        "'tenant-b'),(SELECT count(*) FROM data_credential_graphs WHERE "
        "tenant_id='tenant-b')", -1, &stmt, NULL), ==, SQLITE_OK);
    g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
    g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 0);
    g_assert_cmpint (sqlite3_column_int (stmt, 1), ==, 0);
    sqlite3_finalize (stmt);
  }
  remove_tree (dir);
}

static void
test_key_and_schema_guards (void)
{
  /* Without a key provider there is no verification key to issue under. */
  {
    g_autoptr (wyl_policy_store_t) store = open_store (NULL, FALSE);
    register_test_human (store, "alice");
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-a",
        "alice", &created), ==, WYRELOG_E_OK);
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_POLICY);
  }
  /* A key that was never materialized is reported, not created inside the
   * caller's transaction. */
  {
    g_autoptr (wyl_policy_store_t) store = open_store (NULL, TRUE);
    register_test_human (store, "alice");
    gboolean created = FALSE;
    g_assert_cmpint (wyl_policy_store_create_tenant (store, "tenant-a",
        "alice", &created), ==, WYRELOG_E_OK);
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_BUSY);
  }
  /* A data credential without its key row is an inconsistency, not a
   * fresh store. */
  {
    g_autofree gchar *dir = g_dir_make_tmp ("wyl-data-cred-cvk-XXXXXX", NULL);
    g_autofree gchar *path = g_build_filename (dir, "policy.sqlite", NULL);
    wyl_policy_store_t *store = open_fixture (path);
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_OK);
    exec_ok (store, "DELETE FROM service_credential_cvk");
    wyl_policy_store_close (store);
    store = open_store (path, TRUE);
    const guint8 *cvk = NULL;
    gsize cvk_len = 0;
    g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
        &cvk, &cvk_len), ==, WYRELOG_E_POLICY);
    wyl_policy_store_close (store);
    remove_tree (dir);
  }
  /* A drifted trigger is detected before any mutation. */
  {
    g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
    exec_ok (store, "DROP TRIGGER trg_data_credential_graphs_no_update");
    exec_ok (store, "CREATE TRIGGER trg_data_credential_graphs_no_update "
        "BEFORE UPDATE ON data_credential_graphs BEGIN SELECT 1; END");
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_POLICY);
  }
  /* So is a temporary trigger on a credential table. */
  {
    g_autoptr (wyl_policy_store_t) store = open_fixture (NULL);
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_OK);
    exec_ok (store, "CREATE TEMP TRIGGER trg_data_credentials_temp "
        "BEFORE INSERT ON main.data_credentials BEGIN SELECT 1; END");
    g_assert_cmpint (issue (store, 1, DAY, NOW, NULL, NULL), ==,
        WYRELOG_E_POLICY);
  }
}

static gsize
count_occurrences (const gchar *haystack, const gchar *needle)
{
  gsize n = 0;
  for (const gchar *p = strstr (haystack, needle); p != NULL;
      p = strstr (p + 1, needle))
    n++;
  return n;
}

static void
test_compare_site (void)
{
  g_autofree gchar *crypto_path = g_build_filename (WYL_TEST_SOURCE_ROOT,
          "wyrelog", "auth", "service-credential.c", NULL);
  g_autofree gchar *crypto = NULL;
  g_assert_true (g_file_get_contents (crypto_path, &crypto, NULL, NULL));
  g_assert_cmpuint (count_occurrences (crypto, "sodium_memcmp ("), ==, 1);

  g_autofree gchar *store_path = g_build_filename (WYL_TEST_SOURCE_ROOT,
          "wyrelog", "policy", "store.c", NULL);
  g_autofree gchar *store = NULL;
  g_assert_true (g_file_get_contents (store_path, &store, NULL, NULL));
  const gchar *begin_marker = "/* BEGIN data credential store */";
  const gchar *end_marker = "/* END data credential store */";
  const gchar *start = strstr (store, begin_marker);
  const gchar *end = strstr (store, end_marker);
  g_assert_nonnull (start);
  g_assert_nonnull (end);
  g_assert_true (start < end);
  g_autofree gchar *region = g_strndup (start, (gsize) (end - start));
  g_assert_null (strstr (region, "memcmp"));
}

/* The shipped schema template creates the same objects, byte for byte, as
 * the store's own migration. */
static void
test_template_matches (void)
{
  g_autofree gchar *template_path = g_build_filename (WYL_TEST_SOURCE_ROOT,
          "templates", "access", "sqlite-schema.sql", NULL);
  g_autofree gchar *template = NULL;
  g_assert_true (g_file_get_contents (template_path, &template, NULL, NULL));
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open (":memory:", &db), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_exec (db, template, NULL, NULL, NULL), ==,
      SQLITE_OK);
  g_autoptr (wyl_policy_store_t) store = open_store (NULL, FALSE);
  const gchar *query = "SELECT name,sql FROM sqlite_schema WHERE sql IS NOT "
      "NULL AND tbl_name IN ('data_credentials','data_credential_graphs',"
      "'data_credential_settings') ORDER BY name";
  sqlite3_stmt *from_template = NULL;
  sqlite3_stmt *from_store = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db, query, -1, &from_template, NULL),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_prepare_v2 (wyl_policy_store_get_db (store), query,
      -1, &from_store, NULL), ==, SQLITE_OK);
  guint n = 0;
  int step = SQLITE_ROW;
  while ((step = sqlite3_step (from_store)) == SQLITE_ROW) {
    g_assert_cmpint (sqlite3_step (from_template), ==, SQLITE_ROW);
    for (int c = 0; c < 2; c++)
      g_assert_cmpstr ((const gchar *) sqlite3_column_text (from_template, c),
          ==, (const gchar *) sqlite3_column_text (from_store, c));
    n++;
  }
  g_assert_cmpint (step, ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_step (from_template), ==, SQLITE_DONE);
  g_assert_cmpuint (n, ==, 10);
  sqlite3_finalize (from_template);
  sqlite3_finalize (from_store);
  sqlite3_close (db);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_assert_cmpint (sodium_init (), >=, 0);
  g_test_add_func ("/data-credential/column-roundtrip", test_column_roundtrip);
  g_test_add_func ("/data-credential/check-constraints",
      test_check_constraints);
  g_test_add_func ("/data-credential/immutability", test_immutability);
  g_test_add_func ("/data-credential/issue-validation", test_issue_validation);
  g_test_add_func ("/data-credential/caps", test_caps);
  g_test_add_func ("/data-credential/caps-exclude-inactive",
      test_caps_exclude_inactive);
  g_test_add_func ("/data-credential/settings", test_settings);
  g_test_add_func ("/data-credential/rotate", test_rotate);
  g_test_add_func ("/data-credential/verify", test_verify);
  g_test_add_func ("/data-credential/revoke-and-bulk", test_revoke_and_bulk);
  g_test_add_func ("/data-credential/lifecycle-transfer",
      test_lifecycle_transfer);
  g_test_add_func ("/data-credential/lifecycle-transfer-atomic",
      test_lifecycle_transfer_atomic);
  g_test_add_func ("/data-credential/replay", test_replay);
  g_test_add_func ("/data-credential/secret-not-persisted",
      test_secret_not_persisted);
  g_test_add_func ("/data-credential/tenant-delete",
      test_tenant_delete_with_credentials);
  g_test_add_func ("/data-credential/key-and-schema-guards",
      test_key_and_schema_guards);
  g_test_add_func ("/data-credential/compare-site", test_compare_site);
  g_test_add_func ("/data-credential/template-matches",
      test_template_matches);
  return wyl_test_normalize_exit_status (g_test_run ());
}
