/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"
#include "fact/store-identity-private.h"

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

wyrelog_error_t
wyl_secure_duckdb_bridge_new_with_namespace (WylFactArtifactNamespace
    *namespace_, WylSecureDuckdbMode mode, WylSecureDuckdbBridge **out)
{
  (void) namespace_;
  (void) mode;
  if (out != NULL)
    *out = NULL;
  return out == NULL ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_secure_duckdb_bridge_finalize (WylSecureDuckdbBridge *self)
{
  return self == NULL ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}

void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  (void) self;
}

void
wyl_fact_store_pinned_set_test_hook (WylFactStorePinnedTestHook hook,
    gpointer user_data)
{
  (void) hook;
  (void) user_data;
}

void wyl_fact_store_pinned_set_test_stage_errors
  (wyrelog_error_t authority_error, wyrelog_error_t finalize_error,
    wyrelog_error_t r5_error)
{
  (void) authority_error;
  (void) finalize_error;
  (void) r5_error;
}

wyrelog_error_t
wyl_fact_store_open_identified_pinned (WylFactArtifactNamespace *namespace_,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result)
{
  if (out_result != NULL)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (namespace_ == NULL || out_result == NULL
      || !wyl_fact_store_identity_input_is_valid (identity)
      || !wyl_fact_store_identity_mode_is_valid (mode))
    return WYRELOG_E_INVALID;
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_secure_duckdb_bridge_open_live_pair (WylFactArtifactNamespace *namespace_,
    gboolean writable, WylSecureDuckdbBridge **out_bridge,
    duckdb_database *out_db, duckdb_connection *out_conn)
{
  (void) namespace_;
  (void) writable;
  if (out_bridge != NULL)
    *out_bridge = NULL;
  if (out_db != NULL)
    *out_db = NULL;
  if (out_conn != NULL)
    *out_conn = NULL;
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
wyl_secure_duckdb_bridge_release_live (WylSecureDuckdbBridge *self)
{
  return self == NULL ? WYRELOG_E_INVALID : WYRELOG_E_POLICY;
}
#endif
