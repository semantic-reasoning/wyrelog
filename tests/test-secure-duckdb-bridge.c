/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact/secure-duckdb-bridge-private.h"

static void
test_secure_duckdb_bridge_health (void)
{
  /* Both platforms now build the same source-pinned bridge, so this contract
   * is unconditional.  The Windows arm that expected WYRELOG_E_POLICY from
   * wyl_secure_duckdb_bridge_new described the placeholder backend that the
   * real one replaced; the bridge itself allocates an in-memory DuckDB and is
   * platform-neutral. */
  g_autoptr (WylSecureDuckdbBridge) bridge = NULL;
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (NULL), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (NULL), ==,
      WYRELOG_E_INVALID);
  wyl_secure_duckdb_bridge_free (NULL);
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (&bridge), ==, WYRELOG_E_OK);
  g_assert_nonnull (bridge);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_finalize (bridge), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==, WYRELOG_E_OK);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/secure-duckdb-bridge/health",
      test_secure_duckdb_bridge_health);
  return g_test_run ();
}
