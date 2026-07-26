/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include "fact/secure-duckdb-artifact-contract-private.h"
int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
  WylFactArtifactName n;
  g_assert_true (wyl_secure_duckdb_artifact_name ("facts.duckdb", &n));
  g_assert_cmpint (n, ==, WYL_FACT_ARTIFACT_MAIN);
  g_assert_true (wyl_secure_duckdb_artifact_name ("facts.duckdb.wal", &n));
  g_assert_cmpint (n, ==, WYL_FACT_ARTIFACT_WAL);
  g_assert_false (wyl_secure_duckdb_artifact_name ("/tmp/facts.duckdb", &n));
  g_assert_false (wyl_secure_duckdb_artifact_name ("facts.duckdb.tmp", &n));
  return 0;
}
