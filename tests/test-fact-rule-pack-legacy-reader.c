/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include "fact/rule-pack-private.h"
#include <sqlite3.h>
#include <string.h>

/* Read-only adapter for the frozen pre-1504 language reader. This is not a
 * historical daemon: the SQL/digest adapter is local and Wirelog is current. */
static void
checksum_u32 (GChecksum *checksum, guint32 value)
{
  guint32 be = GUINT32_TO_BE (value);
  g_checksum_update (checksum, (const guchar *) &be, sizeof be);
}

static void
checksum_text (GChecksum *checksum, const gchar *text)
{
  checksum_u32 (checksum, strlen (text));
  g_checksum_update (checksum, (const guchar *) text, strlen (text));
}

int
main (int argc, char **argv)
{
  g_assert_cmpint (argc, ==, 4);
  sqlite3 *db = NULL;
  g_assert_cmpint (sqlite3_open_v2 (argv[1], &db, SQLITE_OPEN_READONLY, NULL),
      ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_db_readonly (db, "main"), ==, 1);
  sqlite3_stmt *stmt = NULL;
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT pack_version,rule_count,pack_digest FROM fact_rule_packs "
      "WHERE tenant_id='tenant-a' AND graph_id=? ORDER BY pack_version DESC LIMIT 1",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, argv[2], -1, SQLITE_STATIC), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_step (stmt), ==, SQLITE_ROW);
  gint64 version = sqlite3_column_int64 (stmt, 0);
  gint64 count = sqlite3_column_int64 (stmt, 1);
  g_assert_cmpint (version, >, 0);
  g_assert_cmpint (count, >, 0);
  g_assert_cmpint (count, <=, WYL_FACT_RULE_PACK_MAX_RULES);
  guint8 expected[32];
  g_assert_cmpint (sqlite3_column_bytes (stmt, 2), ==, sizeof expected);
  memcpy (expected, sqlite3_column_blob (stmt, 2), sizeof expected);
  sqlite3_finalize (stmt);
  g_assert_cmpint (sqlite3_prepare_v2 (db,
      "SELECT rule_index,rule_text FROM fact_rule_pack_rules "
      "WHERE tenant_id='tenant-a' AND graph_id=? AND pack_version=? ORDER BY rule_index",
      -1, &stmt, NULL), ==, SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_text (stmt, 1, argv[2], -1, SQLITE_STATIC), ==,
      SQLITE_OK);
  g_assert_cmpint (sqlite3_bind_int64 (stmt, 2, version), ==, SQLITE_OK);
  g_autoptr (GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
  checksum_text (checksum, "wyrelog.fact.rule-pack.v1");
  checksum_u32 (checksum, count);
  g_autoptr (GPtrArray) rows = g_ptr_array_new_with_free_func (g_free);
  int step;
  while ((step = sqlite3_step (stmt)) == SQLITE_ROW) {
    g_assert_cmpuint (rows->len, <, count);
    g_assert_cmpint (sqlite3_column_int64 (stmt, 0), ==, rows->len + 1);
    const gchar *row = (const gchar *) sqlite3_column_text (stmt, 1);
    g_assert_nonnull (row);
    g_assert_cmpuint (strlen (row), ==, sqlite3_column_bytes (stmt, 1));
    checksum_u32 (checksum, rows->len + 1);
    checksum_text (checksum, row);
    g_ptr_array_add (rows, g_strdup (row));
  }
  g_assert_cmpint (step, ==, SQLITE_DONE);
  sqlite3_finalize (stmt);
  g_assert_cmpuint (rows->len, ==, count);
  guint8 actual[32];
  gsize digest_size = sizeof actual;
  g_checksum_get_digest (checksum, actual, &digest_size);
  g_assert_cmpmem (actual, sizeof actual, expected, sizeof expected);
  g_ptr_array_add (rows, NULL);
  g_autofree gchar *text = g_strjoinv ("\n", (gchar **) rows->pdata);
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    { "x", "int64", FALSE, TRUE }, { "y", "int64", FALSE, TRUE },
  };
  const wyl_fact_graph_program_relation_t schemas[] = {
    { "g", "edge", columns, 2 }, { "g", "reachable", columns, 2 },
  };
  g_autofree gchar *rendered = NULL;
  g_auto (GStrv) canonical = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  wyrelog_error_t rc = wyl_fact_rule_pack_compile_canonical (text, strlen (text),
          schemas, G_N_ELEMENTS (schemas), &rendered, &canonical, &rejection);
  if (strcmp (argv[3], "recursive") == 0) {
    g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
    g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_CYCLE);
    g_assert_cmpuint (rejection.rule_index, ==, 2);
    g_assert_cmpuint (rejection.n_cycle_rules, ==, 1);
    g_assert_cmpuint (rejection.cycle_rules[0], ==, 2);
    g_assert_null (rendered);
    g_assert_null (canonical);
  } else {
    g_assert_cmpstr (argv[3], ==, "acyclic");
    g_assert_cmpint (rc, ==, WYRELOG_E_OK);
    g_assert_true (g_strv_equal ((const gchar * const *) canonical,
        (const gchar * const *) rows->pdata));
  }
  g_print ("%s version=%" G_GINT64_FORMAT " reason=%s rule=%u\n", argv[2],
      version, wyl_fact_rule_pack_reject_name (rejection.reason), rejection.rule_index);
  wyl_fact_rule_pack_rejection_clear (&rejection);
  g_assert_cmpint (sqlite3_close (db), ==, SQLITE_OK);
  return wyl_test_normalize_exit_status (0);
}
