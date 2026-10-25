/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>

#include "fact/duckdb-temp-name-private.h"

typedef struct
{
  const gchar *name;
  WylDuckdbTempNameKind kind;
  gint64 pid;
} NameCase;

static void
test_classifies_duckdb_names (void)
{
  static const NameCase cases[] = {
    { "duckdb_temp_42_0_owner", WYL_DUCKDB_TEMP_NAME_OWNER, 42 },
    { "duckdb_temp_42_7_block-0.block", WYL_DUCKDB_TEMP_NAME_BLOCK, 42 },
    { "duckdb_temp_42_7_block-123.block", WYL_DUCKDB_TEMP_NAME_BLOCK, 42 },
    { "duckdb_temp_1_0_storage_DEFAULT-0.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE,
      1 },
    { "duckdb_temp_1_0_storage_S32K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S64K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S96K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S128K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S160K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S192K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_1_0_storage_S224K-9.tmp", WYL_DUCKDB_TEMP_NAME_STORAGE, 1 },
    { "duckdb_temp_9223372036854775807_0_owner", WYL_DUCKDB_TEMP_NAME_OWNER,
      G_MAXINT64 },
    { "duckdb_temp_1_99999999999999999999_owner", WYL_DUCKDB_TEMP_NAME_OWNER,
      1 },
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    gint64 pid = -1;
    g_assert_cmpint (wyl_duckdb_temp_name_classify (cases[i].name, &pid), ==,
        cases[i].kind);
    g_assert_cmpint (pid, ==, cases[i].pid);
    g_assert_cmpint (wyl_duckdb_temp_name_classify (cases[i].name, NULL), ==,
        cases[i].kind);
  }
}

static void
test_rejects_other_names (void)
{
  static const gchar *const invalid[] = {
    /* The 1.5.5 grammar carried no owner. */
    "duckdb_temp_storage_S32K-0.tmp",
    "duckdb_temp_block-0.block",
    /* Missing or non-canonical owner numbers. */
    "duckdb_temp__0_owner",
    "duckdb_temp_1__owner",
    "duckdb_temp_1_owner",
    "duckdb_temp_01_0_owner",
    "duckdb_temp_1_00_owner",
    "duckdb_temp_-1_0_owner",
    "duckdb_temp_+1_0_owner",
    /* A pid beyond gint64, and 21-digit numbers. */
    "duckdb_temp_9223372036854775808_0_owner",
    "duckdb_temp_100000000000000000000_0_owner",
    "duckdb_temp_1_100000000000000000000_owner",
    /* Unknown, misspelled or extended suffixes. */
    "duckdb_temp_1_2_",
    "duckdb_temp_1_2_owner.tmp",
    "duckdb_temp_1_2_ownerx",
    "duckdb_temp_1_2_storage_S16K-0.tmp",
    "duckdb_temp_1_2_storage_DEFAULTX-1.tmp",
    "duckdb_temp_1_2_storage_S32K0.tmp",
    "duckdb_temp_1_2_storage_S32K-.tmp",
    "duckdb_temp_1_2_storage_S32K-01.tmp",
    "duckdb_temp_1_2_storage_S32K-1.tmpx",
    "duckdb_temp_1_2_storage_S32K-100000000000000000000.tmp",
    "duckdb_temp_1_2_block-.block",
    "duckdb_temp_1_2_block-01.block",
    "duckdb_temp_1_2_block-1.blocks",
    "duckdb_temp_1_2_wal",
    /* Path separators never name a child. */
    "duckdb_temp_1_2_storage_S32K-1.tmp/",
    "../duckdb_temp_1_2_owner",
    "duckdb_temp_1_2_owner\\x",
    "",
    "facts.duckdb.wal",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    gint64 pid = -1;
    g_assert_cmpint (wyl_duckdb_temp_name_classify (invalid[i], &pid), ==,
        WYL_DUCKDB_TEMP_NAME_INVALID);
    g_assert_cmpint (pid, ==, 0);
  }
  g_assert_cmpint (wyl_duckdb_temp_name_classify (NULL, NULL), ==,
      WYL_DUCKDB_TEMP_NAME_INVALID);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/duckdb-temp-name/classifies", test_classifies_duckdb_names);
  g_test_add_func ("/duckdb-temp-name/rejects", test_rejects_other_names);
  return wyl_test_normalize_exit_status (g_test_run ());
}
