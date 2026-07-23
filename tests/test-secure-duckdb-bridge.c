/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "fact/secure-duckdb-bridge-private.h"

static void
test_secure_duckdb_bridge_health (void)
{
  g_autoptr (WylSecureDuckdbBridge) bridge = NULL;
#ifndef G_OS_WIN32
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (NULL), ==,
      WYRELOG_E_POLICY);
  wyl_secure_duckdb_bridge_free (NULL);
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (&bridge), ==, WYRELOG_E_OK);
  g_assert_nonnull (bridge);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (bridge), ==, WYRELOG_E_OK);
#else
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (NULL), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_secure_duckdb_bridge_new (&bridge), ==,
      WYRELOG_E_POLICY);
  g_assert_null (bridge);
  g_assert_cmpint (wyl_secure_duckdb_bridge_health (NULL), ==,
      WYRELOG_E_POLICY);
  wyl_secure_duckdb_bridge_free (NULL);
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/secure-duckdb-bridge/health",
      test_secure_duckdb_bridge_health);
  return g_test_run ();
}
