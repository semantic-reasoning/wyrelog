/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"

#include <cstring>
#include <memory>
#include <string_view>

#include <duckdb.hpp>

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.2",
    "secure DuckDB bridge requires DuckDB v1.5.2 headers");

struct WylSecureDuckdbBridge
{
  std::unique_ptr<duckdb::DuckDB> database;
  std::unique_ptr<duckdb::Connection> connection;
};

static wyrelog_error_t
bridge_query_health (WylSecureDuckdbBridge *self)
{
  if (self == nullptr)
    return WYRELOG_E_POLICY;
  if (self->connection == nullptr
      || std::strcmp (duckdb_library_version (), "v1.5.2") != 0)
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
  return bridge_query_health (self);
}

extern "C" void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  delete self;
}
