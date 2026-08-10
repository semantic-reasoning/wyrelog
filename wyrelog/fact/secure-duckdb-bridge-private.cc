/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"
#include "fact/secure-duckdb-filesystem-contract-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"
#include "fact/store-identity-private.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <duckdb.hpp>

extern "C" G_GNUC_INTERNAL wyrelog_error_t
wyl_fact_artifact_namespace_open_provisioned_pair_internal
    (WylFactGraphProvisionedPair *, WylFactArtifactNamespace **);

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5",
    "secure DuckDB bridge requires DuckDB v1.5.5 headers");

struct LeaseDeleter
{
  void
  operator() (WylFactArtifactMutationLease *lease) const
  {
    wyl_fact_artifact_mutation_lease_free (lease);
  }
};

struct WylSecureDuckdbBridge
{
  std::unique_ptr<WylFactArtifactMutationLease, LeaseDeleter> authority_lease;
  std::unique_ptr < duckdb::DuckDB > database;
  std::unique_ptr < duckdb::Connection > connection;
  std::shared_ptr < WylSecureDuckdbHealth > health;
  WylSecureDuckdbMode mode = WYL_SECURE_DUCKDB_INIT_EMPTY;
  bool finalized = false;
};

namespace {

  std::mutex pinned_test_control_mutex;
  WylFactStorePinnedTestHook pinned_test_hook = nullptr;
  gpointer pinned_test_hook_data = nullptr;
  wyrelog_error_t pinned_test_authority_error = WYRELOG_E_OK;
  wyrelog_error_t pinned_test_finalize_error = WYRELOG_E_OK;
  wyrelog_error_t pinned_test_r5_error = WYRELOG_E_OK;
  std::mutex pinned_pair_test_control_mutex;
  WylFactStorePinnedTestHook pinned_pair_test_hook = nullptr;
  gpointer pinned_pair_test_hook_data = nullptr;
  WylFactStorePairPreflightTestHook pinned_pair_preflight_test_hook = nullptr;
  gpointer pinned_pair_preflight_test_hook_data = nullptr;
  WylFactStorePairPreflightForTest pinned_pair_preflight_test_error_seam =
      WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY;
  wyrelog_error_t pinned_pair_preflight_test_error = WYRELOG_E_OK;

  struct PinnedTestControl
  {
    WylFactStorePinnedTestHook hook = nullptr;
    gpointer data = nullptr;
    wyrelog_error_t authority_error = WYRELOG_E_OK;
    wyrelog_error_t finalize_error = WYRELOG_E_OK;
    wyrelog_error_t r5_error = WYRELOG_E_OK;

    void
    Fire (WylFactStorePinnedRendezvous rendezvous) const
    {
      if (hook != nullptr)
        hook (rendezvous, data);
    }
  };

  struct PinnedPairTestControl
  {
    WylFactStorePinnedTestHook lifecycle_hook = nullptr;
    gpointer lifecycle_data = nullptr;
    WylFactStorePairPreflightTestHook preflight_hook = nullptr;
    gpointer preflight_data = nullptr;
    WylFactStorePairPreflightForTest preflight_error_seam =
        WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY;
    wyrelog_error_t preflight_error = WYRELOG_E_OK;

    void
    FirePreflight (WylFactStorePairPreflightForTest seam) const
    {
      if (preflight_hook != nullptr)
        preflight_hook (seam, preflight_data);
    }

    PinnedTestControl
    Lifecycle () const
    {
      return { lifecycle_hook, lifecycle_data };
    }
  };

  PinnedTestControl
  take_pinned_test_control ()
  {
    std::lock_guard<std::mutex> lock (pinned_test_control_mutex);
    PinnedTestControl result {
      pinned_test_hook,
      pinned_test_hook_data,
      pinned_test_authority_error,
      pinned_test_finalize_error,
      pinned_test_r5_error,
    };
    pinned_test_hook = nullptr;
    pinned_test_hook_data = nullptr;
    pinned_test_authority_error = WYRELOG_E_OK;
    pinned_test_finalize_error = WYRELOG_E_OK;
    pinned_test_r5_error = WYRELOG_E_OK;
    return result;
  }

  PinnedPairTestControl
  take_pinned_pair_test_control ()
  {
    std::lock_guard<std::mutex> lock (pinned_pair_test_control_mutex);
    PinnedPairTestControl result {
      pinned_pair_test_hook,
      pinned_pair_test_hook_data,
      pinned_pair_preflight_test_hook,
      pinned_pair_preflight_test_hook_data,
      pinned_pair_preflight_test_error_seam,
      pinned_pair_preflight_test_error,
    };
    pinned_pair_test_hook = nullptr;
    pinned_pair_test_hook_data = nullptr;
    pinned_pair_preflight_test_hook = nullptr;
    pinned_pair_preflight_test_hook_data = nullptr;
    pinned_pair_preflight_test_error_seam =
        WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY;
    pinned_pair_preflight_test_error = WYRELOG_E_OK;
    return result;
  }

  /* Build the bounded secure filesystem into |config| and move its lease +
   * health onto |bridge|.  Shared by the one-shot and live opens so both apply
   * an identical hardened configuration. */
  void
  bridge_prepare_bounded_config (WylSecureDuckdbBridge *bridge,
      WylFactArtifactNamespace *namespace_, bool read_only,
      bool allow_temporary_storage, duckdb::DBConfig *config)
  {
    bridge->mode = read_only ? WYL_SECURE_DUCKDB_VALIDATE_ONLY
        : WYL_SECURE_DUCKDB_INIT_EMPTY;
    auto filesystem =
        wyl_secure_duckdb_filesystem_new (namespace_, read_only,
        allow_temporary_storage);
    bridge->health = filesystem->SharedHealth ();
    bridge->authority_lease.reset (filesystem->DetachLeaseOwnership ());
    config->options.access_mode = read_only ? duckdb::AccessMode::READ_ONLY
        : duckdb::AccessMode::READ_WRITE;
    config->options.load_extensions = false;
    config->options.use_temporary_directory =
        !read_only && allow_temporary_storage;
    if (config->options.use_temporary_directory)
      config->options.temporary_directory = filesystem->TemporaryDirectory ();
    config->SetOptionByName ("enable_external_access", duckdb::Value (false));
    config->SetOptionByName ("allow_community_extensions",
        duckdb::Value (false));
    config->SetOptionByName ("autoinstall_known_extensions",
        duckdb::Value (false));
    config->SetOptionByName ("autoload_known_extensions",
        duckdb::Value (false));
    config->file_system = std::move (filesystem);
  }

  void
  bridge_populate_bounded (WylSecureDuckdbBridge *bridge,
      WylFactArtifactNamespace *namespace_, bool read_only,
      bool allow_temporary_storage)
  {
    duckdb::DBConfig config;
    bridge_prepare_bounded_config (bridge, namespace_, read_only,
        allow_temporary_storage, &config);
    bridge->database =
        std::make_unique<duckdb::DuckDB> ("facts.duckdb", &config);
    bridge->connection =
        std::make_unique<duckdb::Connection> (*bridge->database);
  }

  std::unique_ptr<WylSecureDuckdbBridge>
  bridge_new_bounded (WylFactArtifactNamespace *namespace_, bool read_only)
  {
    auto bridge = std::make_unique<WylSecureDuckdbBridge> ();
    bridge_populate_bounded (bridge.get (), namespace_, read_only, true);
    return bridge;
  }

  wyrelog_error_t
  cpp_identity_execute (gpointer context, const gchar *sql,
      const WylFactStoreIdentityCell *params, gsize n_params,
      WylFactStoreIdentityRowFunc row_func, gpointer row_data,
      guint64 *out_rows)
  {
    auto *connection = static_cast<duckdb::Connection *>(context);
    if (out_rows != nullptr)
      *out_rows = 0;
    if (connection == nullptr || sql == nullptr || out_rows == nullptr
        || (n_params != 0 && params == nullptr))
      return WYRELOG_E_IO;
    try {
      auto statement = connection->Prepare (sql);
      if (statement == nullptr || statement->HasError ())
        return WYRELOG_E_IO;
      duckdb::vector<duckdb::Value> values;
      values.reserve (n_params);
      for (gsize i = 0; i < n_params; i++) {
        switch (params[i].type) {
          case WYL_FACT_STORE_IDENTITY_CELL_NULL:
            values.emplace_back (nullptr);
            break;
          case WYL_FACT_STORE_IDENTITY_CELL_INT64:
            values.emplace_back (params[i].as.int64_value);
            break;
          case WYL_FACT_STORE_IDENTITY_CELL_BYTES:
            if (params[i].as.bytes.data == nullptr)
              return WYRELOG_E_IO;
            values.emplace_back (duckdb::string (
                    reinterpret_cast<const char *>(params[i].as.bytes.data),
                    params[i].as.bytes.length));
            break;
          default:
            return WYRELOG_E_IO;
        }
      }
      auto query = statement->Execute (values, false);
      if (query == nullptr || query->HasError ()
          || query->type != duckdb::QueryResultType::MATERIALIZED_RESULT)
        return WYRELOG_E_IO;
      auto &result = query->Cast<duckdb::MaterializedQueryResult> ();
      *out_rows = result.RowCount ();
      for (duckdb::idx_t row = 0;
          row < result.RowCount () && row_func != nullptr; row++) {
        std::vector<WylFactStoreIdentityCell> cells (query->ColumnCount ());
        std::vector<duckdb::string> bytes (query->ColumnCount ());
        bool valid = true;
        for (duckdb::idx_t column = 0; column < query->ColumnCount ();
            column++) {
          auto value = result.GetValue (column, row);
          if (value.IsNull ()) {
            cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_NULL;
          } else if (value.type ().id () == duckdb::LogicalTypeId::BIGINT) {
            cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_INT64;
            cells[column].as.int64_value = value.GetValue<int64_t> ();
          } else if (value.type ().id () == duckdb::LogicalTypeId::VARCHAR
              || value.type ().id () == duckdb::LogicalTypeId::BLOB) {
            bytes[column] = value.GetValue<duckdb::string> ();
            cells[column].type = WYL_FACT_STORE_IDENTITY_CELL_BYTES;
            cells[column].as.bytes.data =
                reinterpret_cast<const guint8 *>(bytes[column].data ());
            cells[column].as.bytes.length = bytes[column].size ();
          } else {
            valid = false;
            break;
          }
        }
        if (!valid || !row_func (cells.data (), cells.size (), row_data))
          break;
      }
      return WYRELOG_E_OK;
    } catch (const std::bad_alloc &)
    {
      return WYRELOG_E_NOMEM;
    } catch (const WylSecureDuckdbAuthorityException &exception)
    {
      return exception.error;
    } catch (const duckdb::PermissionException &)
    {
      return WYRELOG_E_POLICY;
    } catch (const std::exception &)
    {
      return WYRELOG_E_IO;
    } catch (...)
    {
      return WYRELOG_E_INTERNAL;
    }
  }

  wyrelog_error_t
  bridge_finalize_storage (WylSecureDuckdbBridge *bridge,
      bool release_authority)
  {
    if (!bridge->finalized) {
      bridge->connection.reset ();
      bridge->database.reset ();
      bridge->finalized = true;
    }
    const auto result = bridge->health == nullptr ? WYRELOG_E_OK
        : bridge->health->Status ();
    if (release_authority)
      bridge->authority_lease.reset ();
    return result;
  }

  wyrelog_error_t
  current_exception_error ()
  {
    try {
      throw;
    } catch (const std::bad_alloc &)
    {
      return WYRELOG_E_NOMEM;
    } catch (const WylSecureDuckdbAuthorityException &exception)
    {
      return exception.error;
    } catch (const duckdb::PermissionException &)
    {
      return WYRELOG_E_POLICY;
    } catch (const duckdb::IOException &)
    {
      return WYRELOG_E_IO;
    } catch (const std::exception &)
    {
      return WYRELOG_E_IO;
    } catch (...)
    {
      return WYRELOG_E_INTERNAL;
    }
  }

  wyrelog_error_t
  pinned_authority_revalidate (WylSecureDuckdbBridge *bridge,
      WylFactArtifactNamespace *namespace_)
  {
    if (bridge == nullptr || bridge->authority_lease == nullptr)
      return WYRELOG_E_INTERNAL;
    const auto lease_result =
        wyl_fact_artifact_mutation_lease_revalidate
          (bridge->authority_lease.get ());
    if (lease_result != WYRELOG_E_OK)
      return lease_result;
    return wyl_fact_artifact_namespace_revalidate (namespace_);
  }

  struct PinnedLifecycleResults
  {
    wyrelog_error_t body = WYRELOG_E_OK;
    wyrelog_error_t authority = WYRELOG_E_OK;
    wyrelog_error_t finalize = WYRELOG_E_OK;
    wyrelog_error_t r5 = WYRELOG_E_OK;
  };

  wyrelog_error_t
  reduce_pinned_lifecycle (const PinnedLifecycleResults &results,
      bool *cleanup_uncertain)
  {
    *cleanup_uncertain = true;
    if (results.finalize != WYRELOG_E_OK)
      return results.finalize;
    if (results.r5 != WYRELOG_E_OK)
      return results.r5;
    if (results.authority != WYRELOG_E_OK)
      return results.authority;
    *cleanup_uncertain = false;
    return results.body;
  }

}                               // namespace

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
    auto bridge = bridge_new_bounded (namespace_,
        mode == WYL_SECURE_DUCKDB_VALIDATE_ONLY);
    if (mode == WYL_SECURE_DUCKDB_INIT_EMPTY) {
      auto emptiness =
          bridge->
          connection->Query
            ("SELECT count(*) FROM duckdb_tables() WHERE NOT internal");
      if (emptiness == nullptr || emptiness->HasError ()
          || emptiness->RowCount () != 1
          || emptiness->GetValue (0, 0).GetValue<int64_t> () != 0) {
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
  return bridge_finalize_storage (self, true);
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_open_live_pair (WylFactArtifactNamespace *namespace_,
    gboolean writable, WylSecureDuckdbBridge **out_bridge,
    duckdb_database *out_db, duckdb_connection *out_conn)
{
  /* The C-API handoff reinterprets the bounded instance as duckdb's internal
   * DatabaseWrapper (a single shared_ptr<DuckDB>); duckdb_connect/duckdb_close
   * consume it symmetrically.  Legitimate only against the vendored,
   * version-pinned amalgamation -- guard the layout so a bump fails loudly. */
  static_assert (sizeof (duckdb::DatabaseWrapper)
      == sizeof (duckdb::shared_ptr<duckdb::DuckDB>),
      "duckdb::DatabaseWrapper must be a single shared_ptr<DuckDB>");
  if (namespace_ == nullptr || out_bridge == nullptr || out_db == nullptr
      || out_conn == nullptr)
    return WYRELOG_E_INVALID;
  *out_bridge = nullptr;
  *out_db = nullptr;
  *out_conn = nullptr;

  try {
    auto bridge = std::make_unique<WylSecureDuckdbBridge> ();
    const bool read_only = writable == FALSE;
    duckdb::DBConfig config;
    bridge_prepare_bounded_config (bridge.get (), namespace_, read_only,
        writable != FALSE, &config);

    auto database =
        duckdb::make_shared_ptr<duckdb::DuckDB> ("facts.duckdb", &config);
    auto *wrapper = new duckdb::DatabaseWrapper ();
    wrapper->database = std::move (database);
    duckdb_database db = reinterpret_cast<duckdb_database> (wrapper);
    duckdb_connection conn = nullptr;
    if (duckdb_connect (db, &conn) != DuckDBSuccess) {
      duckdb_close (&db);
      return WYRELOG_E_IO;
    }

    /* The bridge keeps only the lease + health; the instance is owned by the
     * returned handle so duckdb_close destructs it and checkpoints through the
     * still-live bounded filesystem under the still-held lease. */
    bridge->finalized = true;
    *out_bridge = bridge.release ();
    *out_db = db;
    *out_conn = conn;
    return WYRELOG_E_OK;
  } catch (...)
  {
    return current_exception_error ();
  }
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_release_live (WylSecureDuckdbBridge *self)
{
  if (self == nullptr)
    return WYRELOG_E_INVALID;
  /* The handle has already been duckdb_close'd, so any shutdown-checkpoint I/O
   * fault is now visible in health.  Observe it, then release the lease. */
  const wyrelog_error_t result = self->health == nullptr ? WYRELOG_E_OK
      : self->health->Status ();
  wyl_secure_duckdb_bridge_free (self);
  return result;
}

extern "C" void
wyl_fact_store_pinned_set_test_hook (WylFactStorePinnedTestHook hook,
    gpointer user_data)
{
  std::lock_guard<std::mutex> lock (pinned_test_control_mutex);
  pinned_test_hook = hook;
  pinned_test_hook_data = user_data;
}

extern "C" void
wyl_fact_store_pinned_set_test_stage_errors
    (wyrelog_error_t authority_error, wyrelog_error_t finalize_error,
    wyrelog_error_t r5_error)
{
  std::lock_guard<std::mutex> lock (pinned_test_control_mutex);
  pinned_test_authority_error = authority_error;
  pinned_test_finalize_error = finalize_error;
  pinned_test_r5_error = r5_error;
}

extern "C" void
wyl_fact_store_pinned_set_pair_test_hook_for_test
    (WylFactStorePinnedTestHook hook, gpointer user_data)
{
  std::lock_guard<std::mutex> lock (pinned_pair_test_control_mutex);
  pinned_pair_test_hook = hook;
  pinned_pair_test_hook_data = user_data;
}

extern "C" void
wyl_fact_store_pinned_set_pair_preflight_hook_for_test
    (WylFactStorePairPreflightTestHook hook, gpointer user_data)
{
  std::lock_guard<std::mutex> lock (pinned_pair_test_control_mutex);
  pinned_pair_preflight_test_hook = hook;
  pinned_pair_preflight_test_hook_data = user_data;
}

extern "C" void
wyl_fact_store_pinned_set_pair_preflight_error_for_test
    (WylFactStorePairPreflightForTest seam, wyrelog_error_t error)
{
  std::lock_guard<std::mutex> lock (pinned_pair_test_control_mutex);
  pinned_pair_preflight_test_error_seam = seam;
  pinned_pair_preflight_test_error = error;
}

static wyrelog_error_t
open_identified_pinned_core (WylFactArtifactNamespace *namespace_,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result,
    const PinnedTestControl &control)
{
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
  wyl_fact_store_identity_process_guard_lock ();
  struct ProcessGuard
  {
    ~ProcessGuard ()
    {
      wyl_fact_store_identity_process_guard_unlock ();
    }
  } process_guard;

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_PRECONSTRUCT);
  const auto r0_result =
      wyl_fact_artifact_namespace_revalidate (namespace_);
  if (r0_result != WYRELOG_E_OK)
    return r0_result;

  std::unique_ptr<WylSecureDuckdbBridge> bridge;
  try {
    bridge = std::make_unique<WylSecureDuckdbBridge> ();
  } catch (...)
  {
    return current_exception_error ();
  }

  PinnedLifecycleResults results;
  bool populated = false;
  try {
    bridge_populate_bounded (bridge.get (), namespace_,
        mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, false);
    populated = true;
  } catch (...)
  {
    results.body = current_exception_error ();
  }

  if (populated) {
    control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R1_POSTCONSTRUCT);
    const auto r1_result =
        pinned_authority_revalidate (bridge.get (), namespace_);
    if (results.body == WYRELOG_E_OK && r1_result != WYRELOG_E_OK)
      results.body = r1_result;

    control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R2_PREIDENTITY);
    const auto r2_result =
        pinned_authority_revalidate (bridge.get (), namespace_);
    if (results.body == WYRELOG_E_OK && r2_result != WYRELOG_E_OK)
      results.body = r2_result;

    if (results.body == WYRELOG_E_OK) {
      WylFactStoreIdentityExecutor executor = {
        bridge->connection.get (), cpp_identity_execute, nullptr
      };
      results.body =
          wyl_fact_store_identity_execute (&executor, identity, mode,
          out_result);
    }
  }

  const bool storage_interacted = populated
      || bridge->authority_lease != nullptr || bridge->health != nullptr;
  if (!storage_interacted)
    return results.body;

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R3_POSTIDENTITY);
  results.authority =
      pinned_authority_revalidate (bridge.get (), namespace_);

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R4_PREFINALIZE);
  const auto r4_result =
      pinned_authority_revalidate (bridge.get (), namespace_);
  if (results.authority == WYRELOG_E_OK && r4_result != WYRELOG_E_OK)
    results.authority = r4_result;
  if (results.authority == WYRELOG_E_OK
      && control.authority_error != WYRELOG_E_OK)
    results.authority = control.authority_error;

  try {
    results.finalize = bridge_finalize_storage (bridge.get (), false);
  } catch (...)
  {
    results.finalize = current_exception_error ();
  }
  if (results.finalize == WYRELOG_E_OK
      && control.finalize_error != WYRELOG_E_OK)
    results.finalize = control.finalize_error;

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R5_FINAL_REVALIDATE);
  results.r5 = pinned_authority_revalidate (bridge.get (), namespace_);
  if (results.r5 == WYRELOG_E_OK && control.r5_error != WYRELOG_E_OK)
    results.r5 = control.r5_error;

  bridge->authority_lease.reset ();
  bridge.reset ();

  bool cleanup_uncertain = false;
  const auto selected = reduce_pinned_lifecycle (results,
      &cleanup_uncertain);
  if (cleanup_uncertain)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  return selected;
}

extern "C" wyrelog_error_t
wyl_fact_store_open_identified_pinned (WylFactArtifactNamespace *namespace_,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result)
{
  if (out_result != nullptr)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (namespace_ == nullptr || out_result == nullptr
      || !wyl_fact_store_identity_input_is_valid (identity)
      || !wyl_fact_store_identity_mode_is_valid (mode))
    return WYRELOG_E_INVALID;
  const auto control = take_pinned_test_control ();
  return open_identified_pinned_core (namespace_, identity, mode, out_result,
      control);
}

extern "C" wyrelog_error_t
wyl_fact_store_open_identified_provisioned_pair_pinned
    (WylFactGraphProvisionedPair *pair,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result)
{
  if (out_result != nullptr)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (pair == nullptr || out_result == nullptr
      || !wyl_fact_store_identity_input_is_valid (identity)
      || !wyl_fact_store_identity_mode_is_valid (mode))
    return WYRELOG_E_INVALID;
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;

  /* The operation-bound preflight is separate from the actual R0-R5
   * lifecycle.  It runs before the hidden factory can create the lock or
   * DuckDB can inspect an empty database.  The pair-owned lifecycle hook is
   * then passed explicitly into the core; the generic global control remains
   * independently synchronized and untouched. */
  const auto control = take_pinned_pair_test_control ();
  constexpr auto preflight = WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY;
  control.FirePreflight (preflight);
  if (control.preflight_error != WYRELOG_E_OK
      && control.preflight_error_seam == preflight)
    return control.preflight_error;
  const auto authority_result =
      wyl_fact_graph_provisioned_pair_revalidate (pair);
  if (authority_result != WYRELOG_E_OK)
    return authority_result;

  WylFactArtifactNamespace *namespace_ = nullptr;
  const auto result =
      wyl_fact_artifact_namespace_open_provisioned_pair_internal (pair,
      &namespace_);
  if (result != WYRELOG_E_OK)
    return result;
  const auto lifecycle_control = control.Lifecycle ();
  const auto open_result =
      open_identified_pinned_core (namespace_, identity, mode, out_result,
      lifecycle_control);
  wyl_fact_artifact_namespace_free (namespace_);
  return open_result;
}

extern "C" void
wyl_secure_duckdb_bridge_free (WylSecureDuckdbBridge *self)
{
  if (self != nullptr)
    (void) wyl_secure_duckdb_bridge_finalize (self);
  delete self;
}
