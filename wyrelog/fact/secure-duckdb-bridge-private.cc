/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"

#include <cstring>
#include <memory>
#include <string_view>

#include <duckdb.hpp>

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5",
    "secure DuckDB bridge requires DuckDB v1.5.5 headers");

struct WylSecureDuckdbBridge
{
  std::unique_ptr<duckdb::DuckDB> database;
  std::unique_ptr<duckdb::Connection> connection;
  WylFactArtifactNamespace *namespace_ = nullptr;
  WylSecureDuckdbMode mode = WYL_SECURE_DUCKDB_INIT_EMPTY;
};

static wyrelog_error_t
bridge_query_health (WylSecureDuckdbBridge *self)
{
  if (self == nullptr)
    return WYRELOG_E_POLICY;
  if (self->connection == nullptr
      || std::strcmp (duckdb_library_version (), "v1.5.5") != 0)
    return WYRELOG_E_POLICY;
  try {
    auto result = self->connection->Query ("SELECT 1");
    return result == nullptr || result->HasError () ? WYRELOG_E_IO
        : WYRELOG_E_OK;
  } catch (const std::exception &) {
    return WYRELOG_E_IO;
  } catch (...) {
    return WYRELOG_E_INTERNAL;
  }
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_new (WylSecureDuckdbBridge **out)
{
  if (out != nullptr)
    *out = nullptr;
  if (out == nullptr)
    return WYRELOG_E_INVALID;
  try {
    auto bridge = std::make_unique<WylSecureDuckdbBridge> ();
    bridge->database = std::make_unique<duckdb::DuckDB> (nullptr);
    bridge->connection =
        std::make_unique<duckdb::Connection> (*bridge->database);
    wyrelog_error_t rc = bridge_query_health (bridge.get ());
    if (rc != WYRELOG_E_OK)
      return rc;
    *out = bridge.release ();
    return WYRELOG_E_OK;
  } catch (const std::bad_alloc &) {
    return WYRELOG_E_NOMEM;
  } catch (const std::exception &) {
    return WYRELOG_E_IO;
  } catch (...) {
    return WYRELOG_E_INTERNAL;
  }
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge *self)
{
  if (self != nullptr && self->namespace_ != nullptr
      && wyl_fact_artifact_namespace_revalidate (self->namespace_)
          != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  if (self != nullptr && self->mode == WYL_SECURE_DUCKDB_VALIDATE_ONLY)
    return WYRELOG_E_OK;
  return bridge_query_health (self);
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_new_with_namespace (WylFactArtifactNamespace *namespace_,
    WylSecureDuckdbMode mode, WylSecureDuckdbBridge **out)
{
  if (out != nullptr) *out = nullptr;
  if (out == nullptr || namespace_ == nullptr
      || (mode != WYL_SECURE_DUCKDB_INIT_EMPTY
          && mode != WYL_SECURE_DUCKDB_VALIDATE_ONLY))
    return WYRELOG_E_INVALID;
  if (wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  if (mode == WYL_SECURE_DUCKDB_VALIDATE_ONLY) {
    auto bridge = std::make_unique<WylSecureDuckdbBridge> ();
    bridge->namespace_ = namespace_;
    bridge->mode = mode;
    *out = bridge.release ();
    return WYRELOG_E_OK;
  }
  wyrelog_error_t rc = wyl_secure_duckdb_bridge_new (out);
  if (rc == WYRELOG_E_OK) {
    (*out)->namespace_ = namespace_;
    (*out)->mode = mode;
  }
  return rc;
}

extern "C" void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  delete self;
}
