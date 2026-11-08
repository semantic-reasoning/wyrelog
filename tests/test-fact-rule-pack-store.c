/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include "human-user-test-support.h"
#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>

#include "fact-test-support.h"
#include "wyrelog/fact/rule-pack-private.h"
#include "wyrelog/policy/store-private.h"

/* Known answer for RULES below, computed outside wyrelog as SHA-256 over
 * u32be-length-prefixed "wyrelog.fact.rule-pack.v1", u32be rule count, then
 * per rule u32be rule_index and u32be-length-prefixed rule text. */
#define RULES_DIGEST_HEX \
  "35360fef340241aa12cfb2c0a6c52c697262fdd7ec3a953c3715f0b650b3ede1"

static const gchar *const RULES[] = {
  "reach(X, Y) :- shop.edge(X, Y).",
  "reach2(X, Z) :- shop.edge(X, Y), shop.edge(Y, Z).",
  "unreached(X) :- shop.node(X), !shop.edge(X, _).",
};

static void
cleanup_fact_root (const gchar *root)
{
  if (root == NULL)
    return;
  g_autoptr (GDir) directory = g_dir_open (root, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (root, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR)
          && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        cleanup_fact_root (child);
      else
        (void) g_remove (child);
    }
  }
  (void) g_rmdir (root);
}

static wyrelog_error_t
open_store_with_graph (wyl_policy_store_t **out_store, gchar **out_root)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *root = wyl_test_make_secure_fact_root
        ("wyl-fact-rule-pack-store-XXXXXX", &error);
  if (root == NULL)
    return WYRELOG_E_IO;

  g_autoptr (wyl_policy_store_t) store = NULL;
  gboolean created = FALSE;
  wyrelog_error_t rc = wyl_policy_store_open (NULL, &store);
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_schema (store);
  if (rc == WYRELOG_E_OK) register_test_human (store, "tenant-owner");
  if (rc == WYRELOG_E_OK)
    rc = wyl_policy_store_create_tenant (store, "tenant-a", "tenant-owner",
            &created);
  if (rc != WYRELOG_E_OK) {
    cleanup_fact_root (root);
    return rc;
  }

  const wyl_policy_fact_graph_column_t graph_columns[] = {
    {"subject", "symbol"},
    {"object", "symbol"},
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    {"shop.edge", graph_columns, G_N_ELEMENTS (graph_columns)},
  };
  const wyl_policy_fact_graph_create_options_t graph_opts = {
    .tenant_id = "tenant-a",
    .graph_id = "graph-main",
    .fact_root = root,
    .schema_version = 1,
    .owner_scope = "tenant-a",
    .relations = graph_relations,
    .n_relations = G_N_ELEMENTS (graph_relations),
  };
  rc = wyl_policy_store_create_fact_graph (store, &graph_opts, NULL);
  if (rc != WYRELOG_E_OK) {
    cleanup_fact_root (root);
    return rc;
  }

  *out_store = g_steal_pointer (&store);
  *out_root = g_steal_pointer (&root);
  return WYRELOG_E_OK;
}

static sqlite3 *
raw_db (wyl_policy_store_t *store)
{
  return wyl_policy_store_get_db (store);
}

static gboolean
exec_sql (wyl_policy_store_t *store, const gchar *sql)
{
  return sqlite3_exec (raw_db (store), sql, NULL, NULL, NULL) == SQLITE_OK;
}

static gchar *
digest_hex (const guint8 *digest)
{
  GString *hex = g_string_sized_new (WYL_POLICY_FACT_RULE_PACK_DIGEST_SIZE * 2);
  for (gsize i = 0; i < WYL_POLICY_FACT_RULE_PACK_DIGEST_SIZE; i++)
    g_string_append_printf (hex, "%02x", digest[i]);
  return g_string_free (hex, FALSE);
}

/* Renders PRAGMA table_info as "name type notnull pk;" per column, in
 * declaration order, so the expected string pins every column. */
static gchar *
table_shape (wyl_policy_store_t *store, const gchar *table)
{
  g_autofree gchar *sql = g_strdup_printf ("PRAGMA table_info(%s);", table);
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (raw_db (store), sql, -1, &stmt, NULL) != SQLITE_OK)
    return NULL;
  GString *shape = g_string_new (NULL);
  while (sqlite3_step (stmt) == SQLITE_ROW)
    g_string_append_printf (shape, "%s %s %d %d;",
        (const gchar *) sqlite3_column_text (stmt, 1),
        (const gchar *) sqlite3_column_text (stmt, 2),
        sqlite3_column_int (stmt, 3), sqlite3_column_int (stmt, 5));
  sqlite3_finalize (stmt);
  return g_string_free (shape, FALSE);
}

static gint
check_table_columns (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 1;

  g_autofree gchar *packs = table_shape (store, "fact_rule_packs");
  g_autofree gchar *rules = table_shape (store, "fact_rule_pack_rules");
  gint rc = 0;
  if (g_strcmp0 (packs,
      "tenant_id TEXT 1 1;graph_id TEXT 1 2;pack_version INTEGER 1 3;"
      "rule_count INTEGER 1 0;pack_digest BLOB 1 0;"
      "created_at INTEGER 1 0;") != 0)
    rc = 2;
  else if (g_strcmp0 (rules,
      "tenant_id TEXT 1 1;graph_id TEXT 1 2;pack_version INTEGER 1 3;"
      "rule_index INTEGER 1 4;rule_text TEXT 1 0;") != 0)
    rc = 3;
  cleanup_fact_root (root);
  return rc;
}

static gint
check_digest_known_answer (void)
{
  guint8 digest[WYL_POLICY_FACT_RULE_PACK_DIGEST_SIZE] = { 0 };
  if (wyl_policy_fact_rule_pack_digest (RULES, G_N_ELEMENTS (RULES), digest)
      != WYRELOG_E_OK)
    return 10;
  g_autofree gchar *hex = digest_hex (digest);
  if (g_strcmp0 (hex, RULES_DIGEST_HEX) != 0)
    return 11;

  /* Order is part of the identity. */
  const gchar *const swapped[] = { RULES[1], RULES[0], RULES[2] };
  guint8 other[WYL_POLICY_FACT_RULE_PACK_DIGEST_SIZE] = { 0 };
  if (wyl_policy_fact_rule_pack_digest (swapped, G_N_ELEMENTS (swapped), other)
      != WYRELOG_E_OK || memcmp (digest, other, sizeof digest) == 0)
    return 12;
  return 0;
}

/* Reads every stored column back through raw SQL, including its storage
 * class, so a column the API never reads still has to hold the right value. */
static gint
check_stored_rows (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 20;
  g_autofree gchar *digest_upper = g_ascii_strup (RULES_DIGEST_HEX, -1);
  guint32 version = 0;
  gint rc = 0;
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_OK || version != 1) {
    rc = 21;
    goto out;
  }

  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (raw_db (store),
      "SELECT tenant_id, graph_id, pack_version, rule_count, "
      "hex(pack_digest), typeof(pack_digest), typeof(created_at), "
      "created_at > 0 FROM fact_rule_packs;", -1, &stmt, NULL)
      != SQLITE_OK) {
    rc = 22;
    goto out;
  }
  if (sqlite3_step (stmt) != SQLITE_ROW
      || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
      "tenant-a") != 0
      || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
      "graph-main") != 0
      || sqlite3_column_int64 (stmt, 2) != 1
      || sqlite3_column_int64 (stmt, 3) != 3
      || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
      digest_upper) != 0
      || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 5),
      "blob") != 0
      || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 6),
      "integer") != 0
      || sqlite3_column_int (stmt, 7) != 1
      || sqlite3_step (stmt) != SQLITE_DONE)
    rc = 23;
  sqlite3_finalize (stmt);
  if (rc != 0)
    goto out;

  if (sqlite3_prepare_v2 (raw_db (store),
      "SELECT tenant_id, graph_id, pack_version, rule_index, rule_text, "
      "typeof(rule_index) FROM fact_rule_pack_rules "
      "ORDER BY rule_index;", -1, &stmt, NULL) != SQLITE_OK) {
    rc = 24;
    goto out;
  }
  for (gsize i = 0; rc == 0 && i < G_N_ELEMENTS (RULES); i++) {
    if (sqlite3_step (stmt) != SQLITE_ROW
        || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 0),
        "tenant-a") != 0
        || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 1),
        "graph-main") != 0
        || sqlite3_column_int64 (stmt, 2) != 1
        || sqlite3_column_int64 (stmt, 3) != (gint64) i + 1
        || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 4),
        RULES[i]) != 0
        || g_strcmp0 ((const gchar *) sqlite3_column_text (stmt, 5),
        "integer") != 0)
      rc = 25;
  }
  if (rc == 0 && sqlite3_step (stmt) != SQLITE_DONE)
    rc = 26;
  sqlite3_finalize (stmt);

out:
  cleanup_fact_root (root);
  return rc;
}

static gint
check_load_round_trip (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 30;
  g_autofree gchar *hex = NULL;
  gint rc = 0;
  wyl_policy_fact_rule_pack_info_t info = { 0 };
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_NOT_FOUND || info.rules != NULL
      || info.n_rules != 0 || info.pack_version != 0) {
    rc = 31;
    goto out;
  }

  guint32 version = 0;
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_OK
      || wyl_policy_store_load_fact_rule_pack (store, "tenant-a",
      "graph-main", &info) != WYRELOG_E_OK) {
    rc = 32;
    goto out;
  }
  hex = digest_hex (info.digest);
  if (info.pack_version != 1 || info.n_rules != G_N_ELEMENTS (RULES)
      || g_strcmp0 (hex, RULES_DIGEST_HEX) != 0
      || info.rules[G_N_ELEMENTS (RULES)] != NULL) {
    rc = 33;
    goto out;
  }
  for (gsize i = 0; i < G_N_ELEMENTS (RULES); i++)
    if (g_strcmp0 (info.rules[i], RULES[i]) != 0)
      rc = 34;

out:
  wyl_policy_fact_rule_pack_info_clear (&info);
  cleanup_fact_root (root);
  return rc;
}

/* A second registration is a new version; the first stays stored unchanged
 * so anything that cited it can still be resolved. */
static gint
check_replacement_adds_version (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 40;
  gint rc = 0;
  const gchar *const second[] = { "only(X) :- shop.edge(X, _)." };
  guint32 v1 = 0;
  guint32 v2 = 0;
  wyl_policy_fact_rule_pack_info_t info = { 0 };
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, G_N_ELEMENTS (RULES), &v1) != WYRELOG_E_OK
      || wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", second, G_N_ELEMENTS (second), &v2) != WYRELOG_E_OK
      || v1 != 1 || v2 != 2) {
    rc = 41;
    goto out;
  }
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_OK || info.pack_version != 2
      || info.n_rules != 1 || g_strcmp0 (info.rules[0], second[0]) != 0) {
    rc = 42;
    goto out;
  }

  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (raw_db (store),
      "SELECT (SELECT count(*) FROM fact_rule_pack_rules "
      "WHERE pack_version=1), (SELECT rule_count FROM fact_rule_packs "
      "WHERE pack_version=1);", -1, &stmt, NULL) != SQLITE_OK
      || sqlite3_step (stmt) != SQLITE_ROW
      || sqlite3_column_int64 (stmt, 0) != 3
      || sqlite3_column_int64 (stmt, 1) != 3)
    rc = 43;
  sqlite3_finalize (stmt);

out:
  wyl_policy_fact_rule_pack_info_clear (&info);
  cleanup_fact_root (root);
  return rc;
}

static gint
check_rows_are_immutable (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 50;
  gint rc = 0;
  guint32 version = 0;
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_OK)
    rc = 51;
  else if (exec_sql (store, "UPDATE fact_rule_pack_rules "
      "SET rule_text='x(A) :- shop.edge(A, _).' WHERE rule_index=1;"))
    rc = 52;
  else if (exec_sql (store, "UPDATE fact_rule_packs SET rule_count=2;"))
    rc = 53;
  cleanup_fact_root (root);
  return rc;
}

/* The load recomputes the digest and the count rather than trusting the
 * header, so rows that disagree with it are refused, not returned. */
static gint
check_load_refuses_inconsistent_rows (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 60;
  gint rc = 0;
  guint32 version = 0;
  wyl_policy_fact_rule_pack_info_t info = { 0 };
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_OK) {
    rc = 61;
    goto out;
  }
  if (!exec_sql (store, "DELETE FROM fact_rule_pack_rules "
      "WHERE rule_index=3;")) {
    rc = 62;
    goto out;
  }
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_INTERNAL || info.rules != NULL) {
    rc = 63;
    goto out;
  }

  /* Same rule count, different text: only the digest can tell. */
  if (!exec_sql (store, "INSERT INTO fact_rule_pack_rules VALUES "
      "('tenant-a', 'graph-main', 1, 3, 'other(X) :- shop.edge(X, _).');")){
    rc = 64;
    goto out;
  }
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_INTERNAL || info.rules != NULL) {
    rc = 65;
    goto out;
  }

  /* Rows that match the digest under a header claiming a different count:
   * only the count comparison can tell. */
  if (!exec_sql (store, "INSERT INTO fact_rule_packs VALUES "
      "('tenant-a', 'graph-main', 2, 4, X'" RULES_DIGEST_HEX "', 0);"
      "INSERT INTO fact_rule_pack_rules SELECT tenant_id, graph_id, 2, "
      "rule_index, rule_text FROM fact_rule_pack_rules "
      "WHERE pack_version=1 AND rule_index<3;"
      "INSERT INTO fact_rule_pack_rules VALUES ('tenant-a', 'graph-main', "
      "2, 3, 'unreached(X) :- shop.node(X), !shop.edge(X, _).');")) {
    rc = 66;
    goto out;
  }
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_INTERNAL || info.rules != NULL) {
    rc = 67;
    goto out;
  }

  /* Right count, right texts, right digest, but rule_index skips 3: only
   * the index sequence can tell. */
  if (!exec_sql (store, "INSERT INTO fact_rule_packs VALUES "
      "('tenant-a', 'graph-main', 3, 3, X'" RULES_DIGEST_HEX "', 0);"
      "INSERT INTO fact_rule_pack_rules SELECT tenant_id, graph_id, 3, "
      "CASE rule_index WHEN 3 THEN 4 ELSE rule_index END, rule_text "
      "FROM fact_rule_pack_rules WHERE pack_version=2;")) {
    rc = 68;
    goto out;
  }
  if (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info) != WYRELOG_E_INTERNAL || info.rules != NULL)
    rc = 69;

  /* A digest of a C-string prefix must not authenticate bytes after NUL. */
  g_assert_true (exec_sql (store, "INSERT INTO fact_rule_packs VALUES "
      "('tenant-a','graph-main',4,3,X'" RULES_DIGEST_HEX "',0);"
      "INSERT INTO fact_rule_pack_rules SELECT tenant_id,graph_id,4,rule_index,"
      "CASE WHEN rule_index=1 THEN rule_text||char(0)||'ignored' ELSE rule_text END "
      "FROM fact_rule_pack_rules WHERE pack_version=2;"));
  g_assert_cmpint (wyl_policy_store_load_fact_rule_pack (store, "tenant-a", "graph-main",
      &info), ==, WYRELOG_E_INTERNAL);

out:
  wyl_policy_fact_rule_pack_info_clear (&info);
  cleanup_fact_root (root);
  return rc;
}

static gint
check_register_rejections (void)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  if (open_store_with_graph (&store, &root) != WYRELOG_E_OK)
    return 70;
  g_autoptr (GPtrArray) many = g_ptr_array_new ();
  g_autofree gchar *big = g_strnfill (WYL_FACT_RULE_PACK_MAX_BYTES / 2, 'a');
  gint rc = 0;
  guint32 version = 7;
  const gchar *const empty[] = { "" };
  const gchar *const newline[] = { "a(X) :- shop.edge(X, _).\nb(X) :- "
                                   "shop.edge(X, _)."};
  const gchar *const carriage[] = { "a(X) :- shop.edge(X, _).\r" };
  const gchar *const bad_utf8[] = { "a(\"\xff\") :- shop.edge(_, _)." };
  const gchar *const with_null[] = { RULES[0], NULL };

  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", RULES, 0, &version) != WYRELOG_E_POLICY
      || version != 0)
    rc = 71;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", empty, 1, &version) != WYRELOG_E_POLICY)
    rc = 72;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", newline, 1, &version) != WYRELOG_E_POLICY)
    rc = 73;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", carriage, 1, &version) != WYRELOG_E_POLICY)
    rc = 74;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", bad_utf8, 1, &version) != WYRELOG_E_POLICY)
    rc = 75;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", with_null, 2, &version) != WYRELOG_E_INVALID)
    rc = 76;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-other", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_NOT_FOUND)
    rc = 77;
  else if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "../graph", RULES, G_N_ELEMENTS (RULES), &version)
      != WYRELOG_E_INVALID)
    rc = 78;
  if (rc != 0)
    goto out;

  /* Count and byte limits are the compiler's, so storage cannot hold a pack
   * the compiler would never accept. */
  for (gsize i = 0; i <= WYL_FACT_RULE_PACK_MAX_RULES; i++)
    g_ptr_array_add (many, (gpointer) RULES[0]);
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", (const gchar *const *) many->pdata,
      WYL_FACT_RULE_PACK_MAX_RULES + 1, &version) != WYRELOG_E_POLICY) {
    rc = 79;
    goto out;
  }
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", (const gchar *const *) many->pdata,
      WYL_FACT_RULE_PACK_MAX_RULES, &version) != WYRELOG_E_OK
      || version != 1) {
    rc = 80;
    goto out;
  }
  const gchar *const too_big[] = { big, big, "c" };
  if (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", too_big, G_N_ELEMENTS (too_big), &version)
      != WYRELOG_E_POLICY) {
    rc = 81;
    goto out;
  }

  /* Nothing a rejection touched may have been stored. */
  sqlite3_stmt *stmt = NULL;
  if (sqlite3_prepare_v2 (raw_db (store),
      "SELECT (SELECT count(*) FROM fact_rule_packs), "
      "(SELECT count(*) FROM fact_rule_pack_rules);", -1, &stmt, NULL)
      != SQLITE_OK || sqlite3_step (stmt) != SQLITE_ROW
      || sqlite3_column_int64 (stmt, 0) != 1
      || sqlite3_column_int64 (stmt, 1) != WYL_FACT_RULE_PACK_MAX_RULES)
    rc = 82;
  sqlite3_finalize (stmt);

out:
  cleanup_fact_root (root);
  return rc;
}

static const gchar *const COMPAT_RULES[] = {
  "reachable(X,Y):-edge(X,Y).",
  "reachable(X,Z):-reachable(X,Y),edge(Y,Z).",
};
static const gchar *const COMPAT_ACYCLIC_RULES[] = {
  "reachable(X,Y):-edge(X,Y).",
  "reachable(X,Z):-edge(X,Y),edge(Y,Z).",
};

static void
backup_policy (wyl_policy_store_t *store, const gchar *path)
{
  sqlite3 *destination = NULL;
  g_assert_cmpint (sqlite3_open (path, &destination), ==, SQLITE_OK);
  sqlite3_backup *backup = sqlite3_backup_init (destination, "main",
          raw_db (store), "main");
  g_assert_nonnull (backup);
  g_assert_cmpint (sqlite3_backup_step (backup, -1), ==, SQLITE_DONE);
  g_assert_cmpint (sqlite3_backup_remaining (backup), ==, 0);
  g_assert_cmpint (sqlite3_backup_finish (backup), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_close (destination), ==, SQLITE_OK);
}

static void
assert_compat_pack (wyl_policy_store_t *store, const gchar *graph,
    guint version, gboolean recursive)
{
  wyl_policy_fact_rule_pack_info_t info = { 0 };
  g_assert_cmpint (wyl_policy_store_load_fact_rule_pack (store, "tenant-a",
      graph, &info), ==, WYRELOG_E_OK);
  g_assert_cmpuint (info.pack_version, ==, version);
  g_assert_cmpuint (info.n_rules, ==, 2);
  for (gsize i = 0; i < info.n_rules; i++)
    g_assert_cmpstr (info.rules[i], ==,
        recursive ? COMPAT_RULES[i] : COMPAT_ACYCLIC_RULES[i]);
  g_autofree gchar *hex = digest_hex (info.digest);
  /* Independent known answers for the v1 length-prefixed encoding. */
  g_assert_cmpstr (hex, ==, recursive
      ? "80458b32c06844c447c99be32275339df60cbf6f43a599446721ffd5497337e1"
      : "bb2e2c48aee52c1a447bf39e09fdb22c0d18f4f781ec92b9e68fd1201bbab737");
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    { "x", "int64", FALSE, TRUE }, { "y", "int64", FALSE, TRUE },
  };
  const wyl_fact_graph_program_relation_t schemas[] = {
    { "g", "edge", columns, 2 }, { "g", "reachable", columns, 2 },
  };
  g_autofree gchar *rules = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&info, schemas,
      G_N_ELEMENTS (schemas), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
      &rules, &rejection), ==, WYRELOG_E_OK);
  g_assert_nonnull (rules);
  g_clear_pointer (&rules, g_free);
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&info, schemas,
      G_N_ELEMENTS (schemas), WYL_FACT_RULE_PACK_ACYCLIC, &rules, &rejection),
      ==, recursive ? WYRELOG_E_POLICY : WYRELOG_E_OK);
  if (recursive) {
    g_assert_null (rules);
    g_assert_cmpint (rejection.reason, ==,
        WYL_FACT_RULE_PACK_REJECT_UNSUPPORTED_RECURSION);
  }
  wyl_fact_rule_pack_rejection_clear (&rejection);
  wyl_policy_fact_rule_pack_info_clear (&info);
}

static void
assert_legacy_reader (const gchar *executable, const gchar *path,
    const gchar *graph, gboolean recursive, guint version)
{
  gchar *argv[] = { (gchar *) executable, (gchar *) path, (gchar *) graph,
                    recursive ? "recursive" : "acyclic", NULL };
  g_autofree gchar *before = NULL;
  gsize before_size = 0;
  g_assert_true (g_file_get_contents (path, &before, &before_size, NULL));
  g_autofree gchar *output = NULL;
  g_autofree gchar *errors = NULL;
  gint status = 0;
  g_autoptr (GError) error = NULL;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
      &output, &errors, &status, &error));
  g_assert_no_error (error);
  if (!g_spawn_check_wait_status (status, &error))
    g_printerr ("legacy reader: %s\n%s", error->message, errors);
  g_assert_no_error (error);
  /* Windows text stdout translates the final LF to CRLF. Preserve all other
   * bytes so extra lines or changed result fields still fail the assertion. */
  gsize output_size = strlen (output);
  if (output_size >= 2 && output[output_size - 2] == '\r'
      && output[output_size - 1] == '\n') {
    output[output_size - 2] = '\n';
    output[output_size - 1] = '\0';
  }
  g_autofree gchar *expected = g_strdup_printf (
    "%s version=%u reason=%s rule=%u\n", graph, version,
    recursive ? "rule_pack_cycle" : "rule_pack_none", recursive ? 2 : 0);
  g_assert_cmpstr (output, ==, expected);
  g_autofree gchar *after = NULL;
  gsize after_size = 0;
  g_assert_true (g_file_get_contents (path, &after, &after_size, NULL));
  g_assert_cmpmem (before, before_size, after, after_size);
}

static void
check_recursive_compatibility (const gchar *legacy_reader)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_autofree gchar *root = NULL;
  g_assert_cmpint (open_store_with_graph (&store, &root), ==, WYRELOG_E_OK);
  const wyl_policy_fact_graph_column_t graph_columns[] = {
    { "x", "int64" }, { "y", "int64" },
  };
  const wyl_policy_fact_graph_relation_t graph_relations[] = {
    { "g.edge", graph_columns, 2 }, { "g.reachable", graph_columns, 2 },
  };
  const wyl_policy_fact_graph_create_options_t graph_options = {
    .tenant_id = "tenant-a", .graph_id = "ordinary", .fact_root = root,
    .schema_version = 1, .owner_scope = "tenant-a",
    .relations = graph_relations, .n_relations = 2,
  };
  g_assert_cmpint (wyl_policy_store_create_fact_graph (store, &graph_options,
      NULL), ==, WYRELOG_E_OK);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    { "x", "int64", FALSE, TRUE }, { "y", "int64", FALSE, TRUE },
  };
  const gchar *graphs[] = { "graph-main", "ordinary" };
  const gchar *relations[] = { "edge", "reachable" };
  for (guint g = 0; g < 2; g++) {
    for (guint r = 0; r < 2; r++) {
      const wyl_policy_fact_relation_schema_options_t schema = {
        .tenant_id = "tenant-a", .graph_id = graphs[g], .namespace_id = "g",
        .relation_name = relations[r], .schema_version = 1,
        .relation_visible = TRUE, .columns = columns, .n_columns = 2,
      };
      g_assert_cmpint (wyl_policy_store_register_fact_relation_schema (store,
          &schema), ==, WYRELOG_E_OK);
    }
  }
  guint32 version = 0;
  for (guint g = 0; g < 2; g++) {
    g_assert_cmpint (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
        graphs[g], COMPAT_ACYCLIC_RULES, 2, &version), ==, WYRELOG_E_OK);
    g_assert_cmpuint (version, ==, 1);
    assert_compat_pack (store, graphs[g], 1, FALSE);
  }
  g_autofree gchar *policy_path = g_build_filename (root, "policy.sqlite", NULL);
  g_autofree gchar *backup_path = g_build_filename (root, "backup.sqlite", NULL);
  backup_policy (store, policy_path);
  g_clear_pointer (&store, wyl_policy_store_close);
  assert_legacy_reader (legacy_reader, policy_path, "graph-main", FALSE, 1);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  assert_compat_pack (store, "graph-main", 1, FALSE);
  /* Test-authorized storage: public registration still refuses recursion. */
  g_assert_cmpint (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", COMPAT_RULES, 2, &version), ==, WYRELOG_E_OK);
  g_assert_cmpuint (version, ==, 2);
  assert_compat_pack (store, "graph-main", 2, TRUE);

  /* Failure between header and second row must expose neither partial header
   * nor partial rows, and must survive a real close/reopen. */
  g_assert_true (exec_sql (store,
      "CREATE TRIGGER fail_pack BEFORE INSERT ON fact_rule_pack_rules "
      "WHEN NEW.pack_version=3 AND NEW.rule_index=2 BEGIN "
      "SELECT RAISE(ABORT,'injected second rule failure'); END;"));
  g_assert_cmpint (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", COMPAT_RULES, 2, &version), !=, WYRELOG_E_OK);
  g_assert_cmpuint (version, ==, 0);
  g_assert_true (exec_sql (store, "DROP TRIGGER fail_pack;"));
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (raw_db (store),
      "SELECT (SELECT count(*) FROM fact_rule_packs WHERE pack_version=3),"
      "(SELECT count(*) FROM fact_rule_pack_rules WHERE pack_version=3)",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 0);
  g_assert_cmpint (sqlite3_column_int (stmt, 1), ==, 0);
  sqlite3_finalize (stmt);
  g_clear_pointer (&store, wyl_policy_store_close);
  assert_legacy_reader (legacy_reader, policy_path, "graph-main", TRUE, 2);
  assert_legacy_reader (legacy_reader, policy_path, "ordinary", FALSE, 1);
  g_assert_cmpint (wyl_policy_store_open (policy_path, &store), ==, WYRELOG_E_OK);
  assert_compat_pack (store, "graph-main", 2, TRUE);
  assert_compat_pack (store, "ordinary", 1, FALSE);
  backup_policy (store, backup_path);
  g_clear_pointer (&store, wyl_policy_store_close);
  assert_legacy_reader (legacy_reader, backup_path, "graph-main", TRUE, 2);
  assert_legacy_reader (legacy_reader, backup_path, "ordinary", FALSE, 1);
  g_assert_cmpint (wyl_policy_store_open (backup_path, &store), ==, WYRELOG_E_OK);
  assert_compat_pack (store, "graph-main", 2, TRUE);
  assert_compat_pack (store, "ordinary", 1, FALSE);

  const gchar *corruptions[] = {
    "DELETE FROM fact_rule_pack_rules WHERE graph_id='graph-main' AND pack_version=2 AND rule_index=1;",
    "UPDATE fact_rule_pack_rules SET rule_index=3 WHERE graph_id='graph-main' AND pack_version=2 AND rule_index=2;",
    "UPDATE fact_rule_packs SET pack_digest=zeroblob(32) WHERE graph_id='graph-main' AND pack_version=2;",
    "UPDATE fact_rule_pack_rules SET rule_text=printf('%.*c',70000,'x') WHERE graph_id='graph-main' AND pack_version=2 AND rule_index=1;",
    "UPDATE fact_rule_pack_rules SET rule_text=printf('%.*c',32768,'x') WHERE graph_id='graph-main' AND pack_version=2;",
  };
  for (guint i = 0; i < G_N_ELEMENTS (corruptions); i++) {
    g_assert_true (exec_sql (store, "SAVEPOINT corrupt; DROP TRIGGER fact_rule_packs_immutable; DROP TRIGGER fact_rule_pack_rules_immutable;"));
    g_assert_true (exec_sql (store, corruptions[i]));
    wyl_policy_fact_rule_pack_info_t info = { 0 };
    g_assert_cmpint (wyl_policy_store_load_fact_rule_pack (store, "tenant-a",
        "graph-main", &info), ==, WYRELOG_E_INTERNAL);
    g_assert_cmpuint (info.pack_version, ==, 0);
    g_assert_null (info.rules);
    assert_compat_pack (store, "ordinary", 1, FALSE);
    g_assert_true (exec_sql (store, "ROLLBACK TO corrupt; RELEASE corrupt;"));
    assert_compat_pack (store, "graph-main", 2, TRUE);
  }
  /* Replacement before downgrade appends a version; immutable history stays. */
  g_assert_cmpint (wyl_policy_store_register_fact_rule_pack (store, "tenant-a",
      "graph-main", COMPAT_ACYCLIC_RULES, 2, &version), ==, WYRELOG_E_OK);
  g_assert_cmpuint (version, ==, 3);
  assert_compat_pack (store, "graph-main", 3, FALSE);
  g_assert_cmpint (sqlite3_prepare_v2 (raw_db (store),
      "SELECT count(*) FROM fact_rule_pack_rules WHERE graph_id='graph-main' AND pack_version=2",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  g_assert_cmpint (sqlite3_column_int (stmt, 0), ==, 2);
  sqlite3_finalize (stmt);
  g_clear_pointer (&store, wyl_policy_store_close);
  assert_legacy_reader (legacy_reader, backup_path, "graph-main", FALSE, 3);
  assert_legacy_reader (legacy_reader, backup_path, "ordinary", FALSE, 1);
  cleanup_fact_root (root);
}

int
main (int argc, char **argv)
{
  gint (*const checks[]) (void) = {
    check_table_columns,
    check_digest_known_answer,
    check_stored_rows,
    check_load_round_trip,
    check_replacement_adds_version,
    check_rows_are_immutable,
    check_load_refuses_inconsistent_rows,
    check_register_rejections,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (checks); i++) {
    gint rc = checks[i] ();
    if (rc != 0)
      return wyl_test_normalize_exit_status (rc);
  }
  g_assert_cmpint (argc, ==, 2);
  check_recursive_compatibility (argv[1]);
  return wyl_test_normalize_exit_status (0);
}
