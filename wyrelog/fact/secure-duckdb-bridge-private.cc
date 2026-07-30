/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"
#include "fact/secure-duckdb-filesystem-contract-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"

#include <cstring>
#include <memory>
#include <string_view>

#include <duckdb.hpp>

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5",
    "secure DuckDB bridge requires DuckDB v1.5.5 headers");

struct WylSecureDuckdbBridge
{
  std::unique_ptr < duckdb::DuckDB > database;
  std::unique_ptr < duckdb::Connection > connection;
  std::shared_ptr < WylSecureDuckdbHealth > health;
  WylSecureDuckdbMode mode = WYL_SECURE_DUCKDB_INIT_EMPTY;
  bool finalized = false;
};

static wyrelog_error_t
bridge_query_health (WylSecureDuckdbBridge *self)
{
  if (self == nullptr)
    return WYRELOG_E_POLICY;
  if (self->health != nullptr) {
    const auto health = self->health->Status ();
    if (health != WYRELOG_E_OK)
      return health;
  }
  if (self->finalized)
    return WYRELOG_E_OK;
  if (self->connection == nullptr
      || std::strcmp (duckdb_library_version (), "v1.5.5") != 0)
    return WYRELOG_E_POLICY;
  try {
    auto result = self->connection->Query ("SELECT 1");
    if (self->health != nullptr
        && self->health->Status () != WYRELOG_E_OK)
      return self->health->Status ();
    return result == nullptr || result->HasError ()? WYRELOG_E_IO
        : WYRELOG_E_OK;
  }
  catch (const std::exception &)
  {
    if (self->health != nullptr
        && self->health->Status () != WYRELOG_E_OK)
      return self->health->Status ();
    return WYRELOG_E_IO;
  }
  catch ( ...) {
    if (self->health != nullptr
        && self->health->Status () != WYRELOG_E_OK)
      return self->health->Status ();
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
    auto bridge = std::make_unique < WylSecureDuckdbBridge > ();
    bridge->database = std::make_unique < duckdb::DuckDB > (nullptr);
    bridge->connection =
        std::make_unique < duckdb::Connection > (*bridge->database);
    wyrelog_error_t rc = bridge_query_health (bridge.get ());
    if (rc != WYRELOG_E_OK)
      return rc;
    *out = bridge.release ();
    return WYRELOG_E_OK;
  }
  catch (const std::bad_alloc &)
  {
    return WYRELOG_E_NOMEM;
  }
  catch (const std::exception &)
  {
    return WYRELOG_E_IO;
  }
  catch ( ...) {
    return WYRELOG_E_INTERNAL;
  }
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_health (WylSecureDuckdbBridge *self)
{
  return bridge_query_health (self);
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_new_with_namespace (WylFactArtifactNamespace
    *namespace_, WylSecureDuckdbMode mode, WylSecureDuckdbBridge **out)
{
  if (out != nullptr)
    *out = nullptr;
  if (out == nullptr || namespace_ == nullptr
      || (mode != WYL_SECURE_DUCKDB_INIT_EMPTY
      && mode != WYL_SECURE_DUCKDB_VALIDATE_ONLY))
    return WYRELOG_E_INVALID;
  if (wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    return WYRELOG_E_POLICY;
  try {
    auto bridge = std::make_unique < WylSecureDuckdbBridge > ();
    bridge->mode = mode;
    duckdb::DBConfig config;
    auto filesystem = wyl_secure_duckdb_filesystem_new (namespace_,
            mode == WYL_SECURE_DUCKDB_VALIDATE_ONLY);
    bridge->health = filesystem->SharedHealth ();
    config.options.access_mode = mode == WYL_SECURE_DUCKDB_VALIDATE_ONLY
        ? duckdb::AccessMode::READ_ONLY : duckdb::AccessMode::READ_WRITE;
    config.options.load_extensions = false;
    config.options.use_temporary_directory =
        mode != WYL_SECURE_DUCKDB_VALIDATE_ONLY;
    if (config.options.use_temporary_directory)
      config.options.temporary_directory = filesystem->TemporaryDirectory ();
    config.SetOptionByName ("enable_external_access", duckdb::Value (false));
    config.SetOptionByName ("allow_community_extensions",
        duckdb::Value (false));
    config.SetOptionByName ("autoinstall_known_extensions",
        duckdb::Value (false));
    config.SetOptionByName ("autoload_known_extensions", duckdb::Value (false));
    config.file_system = std::move (filesystem);
    bridge->database =
        std::make_unique < duckdb::DuckDB > ("facts.duckdb", &config);
    bridge->connection =
        std::make_unique < duckdb::Connection > (*bridge->database);
    if (mode == WYL_SECURE_DUCKDB_INIT_EMPTY) {
      auto emptiness =
          bridge->
          connection->Query
            ("SELECT count(*) FROM duckdb_tables() WHERE NOT internal");
      if (emptiness == nullptr || emptiness->HasError ()
          || emptiness->RowCount () != 1
          || emptiness->GetValue (0, 0).ToString () != "0") {
        const auto storage_health = bridge->health->Status ();
        if (storage_health != WYRELOG_E_OK)
          return storage_health;
        return WYRELOG_E_POLICY;
      }
    }
    const auto health = bridge_query_health (bridge.get ());
    if (health != WYRELOG_E_OK)
      return health;
    *out = bridge.release ();
    return WYRELOG_E_OK;
  }
  catch (const std::bad_alloc &)
  {
    return WYRELOG_E_NOMEM;
  }
  catch (const WylSecureDuckdbAuthorityException & exception)
  {
    return exception.error;
  }
  catch (const duckdb::PermissionException &)
  {
    return WYRELOG_E_POLICY;
  }
  catch (const duckdb::IOException &)
  {
    return WYRELOG_E_IO;
  }
  catch (const std::exception &)
  {
    return WYRELOG_E_IO;
  }
  catch ( ...) {
    return WYRELOG_E_INTERNAL;
  }
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_finalize (WylSecureDuckdbBridge *self)
{
  if (self == nullptr)
    return WYRELOG_E_INVALID;
  if (!self->finalized) {
    self->connection.reset ();
    self->database.reset ();
    self->finalized = true;
  }
  return self->health == nullptr ? WYRELOG_E_OK : self->health->Status ();
}

extern "C" void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  if (self != nullptr)
    (void) wyl_secure_duckdb_bridge_finalize (self);
  delete self;
}
