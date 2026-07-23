/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"

#ifdef G_OS_WIN32
struct WylSecureDuckdbBridge
{
  gint unused;
};

wyrelog_error_t
wyl_secure_duckdb_bridge_new (WylSecureDuckdbBridge **out)
{
  if (out != NULL)
    *out = NULL;
  return out == NULL ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge *self)
{
  (void) self;
  return WYRELOG_E_POLICY;
}

void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  (void) self;
}
#endif
