/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-filesystem-private.hpp"

#include "fact/secure-duckdb-artifact-contract-private.h"
#include "fact/secure-duckdb-file-handle-private.hpp"
#include "fact/secure-duckdb-filesystem-contract-private.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>

namespace {

  constexpr const char *virtual_home = "/__wyrelog_duckdb_home__";
  constexpr duckdb::idx_t writer_main_existing_flag_bits = 2307;
  constexpr duckdb::idx_t writer_main_create_flag_bits = 2315;
  std::atomic<guint> test_faults { 0 };

  enum class LogicalKind
  {
    MAIN,
    SIDECAR,
    LOCK,
    TEMP_ROOT,
    TEMP_CHILD,
    HOME_METADATA,
    HOST_PROBE,
  };

  struct LogicalPath
  {
    LogicalKind kind;
    WylFactArtifactName artifact;
    duckdb::string child;
  };

  [[noreturn]] void io_reject (const duckdb::string & message)
  {
    throw duckdb::IOException ("bounded DuckDB filesystem rejected " + message);
  }

  [[noreturn]] void unsupported (const char *operation)
  {
    throw duckdb::NotImplementedException
      ("bounded DuckDB filesystem does not support %s", operation);
  }

  void require_ok (wyrelog_error_t result, const char *operation)
  {
    if (result != WYRELOG_E_OK)
      throw WylSecureDuckdbAuthorityException (result,
          duckdb::string (operation) + " failed with authority error "
          + std::to_string (static_cast < int >(result)));
  }

  bool is_missing (wyrelog_error_t result)
  {
    return result == WYRELOG_E_NOT_FOUND;
  }

  bool is_home_metadata (const duckdb::string & path)
  {
    const duckdb::string home (virtual_home);
    return path == home || (path.size () > home.size ()
           && path.compare (0, home.size (), home) == 0
           && path[home.size ()] == '/');
  }

  LogicalPath
  logical_path_for (const duckdb::string & path,
      const duckdb::string & temporary_directory)
  {
    if (path == "/proc/self/cgroup")
      return {
               LogicalKind::HOST_PROBE, WYL_FACT_ARTIFACT_MAIN, {
               }
      };
    if (is_home_metadata (path))
      return {
               LogicalKind::HOME_METADATA, WYL_FACT_ARTIFACT_MAIN, {
               }
      };
    WylFactArtifactName artifact;
    if (wyl_secure_duckdb_artifact_name (path, &artifact)) {
      if (artifact == WYL_FACT_ARTIFACT_MAIN)
        return {
                 LogicalKind::MAIN, artifact, {
                 }
        };
      if (artifact == WYL_FACT_ARTIFACT_LOCK)
        return {
                 LogicalKind::LOCK, artifact, {
                 }
        };
      return {
               LogicalKind::SIDECAR, artifact, {
               }
      };
    }
    if (!temporary_directory.empty ()) {
      if (path == temporary_directory)
        return {
                 LogicalKind::TEMP_ROOT, WYL_FACT_ARTIFACT_TEMP, {
                 }
        };
      const duckdb::string prefix = temporary_directory + "/";
      if (path.size () > prefix.size ()
          && path.compare (0, prefix.size (), prefix) == 0) {
        const auto child = path.substr (prefix.size ());
        if (child.find ('/') == duckdb::string::npos
            && child.find ('\\') == duckdb::string::npos)
          return {
                   LogicalKind::TEMP_CHILD, WYL_FACT_ARTIFACT_TEMP, child
          };
      }
    }
    io_reject ("non-canonical logical path: " + path);
  }

  bool exact_flags (duckdb::FileOpenFlags flags, duckdb::idx_t value,
      duckdb::FileLockType lock)
  {
    return flags.GetFlagsInternal () == value && flags.Lock () == lock
           && flags.Compression () == duckdb::FileCompressionType::UNCOMPRESSED
           && flags.GetCachingMode () == duckdb::CachingMode::NO_CACHING;
  }

  duckdb::FileOpenFlags
  writer_main_existing_flags ()
  {
    return duckdb::FileOpenFlags (writer_main_existing_flag_bits,
               duckdb::FileLockType::WRITE_LOCK,
               duckdb::FileCompressionType::UNCOMPRESSED);
  }

  void validate_flags (const LogicalPath & logical, duckdb::FileOpenFlags flags,
      bool read_only)
  {
    bool accepted = false;
    if (logical.kind == LogicalKind::MAIN) {
      accepted = exact_flags (flags, 129, duckdb::FileLockType::NO_LOCK)
          || (read_only
          && exact_flags (flags, 2433, duckdb::FileLockType::READ_LOCK))
          || (!read_only
          && (exact_flags (flags, writer_main_existing_flag_bits,
          duckdb::FileLockType::WRITE_LOCK)
          || exact_flags (flags, writer_main_create_flag_bits,
          duckdb::FileLockType::WRITE_LOCK)));
    } else if (logical.kind == LogicalKind::SIDECAR) {
      accepted = exact_flags (flags, 129, duckdb::FileLockType::NO_LOCK)
          || (logical.artifact == WYL_FACT_ARTIFACT_WAL
          && exact_flags (flags, 1, duckdb::FileLockType::NO_LOCK))
          || (!read_only
          && (exact_flags (flags, 2090, duckdb::FileLockType::WRITE_LOCK)
          || (logical.artifact == WYL_FACT_ARTIFACT_RECOVERY
          && exact_flags (flags, 18, duckdb::FileLockType::NO_LOCK))));
    } else if (logical.kind == LogicalKind::TEMP_CHILD) {
      accepted = !read_only
          && exact_flags (flags, 11, duckdb::FileLockType::NO_LOCK);
    }
    if (!accepted)
      io_reject ("non-source-pinned open tuple for logical path");
  }

  WylSecureDuckdbFileHandle & bounded_handle (duckdb::FileHandle & handle) {
    return handle.Cast < WylSecureDuckdbFileHandle > ();
  }

  gboolean
  collect_temp_child (WylFactDuckdbTempChild *, const gchar * logical_name,
      gpointer user_data)
  {
    auto *names = static_cast < duckdb::vector < duckdb::string > *>(user_data);
    names->push_back (logical_name);
    return TRUE;
  }

  duckdb::idx_t
  checked_file_size_cursor (int64_t size)
  {
    if (size < 0 || static_cast < uint64_t > (size)
        > static_cast < uint64_t > (
          std::numeric_limits < duckdb::idx_t >::max ()))
      io_reject ("append cursor conversion");
    return static_cast < duckdb::idx_t > (size);
  }

}                               // namespace

void
wyl_secure_duckdb_filesystem_set_test_faults (guint faults)
{
  test_faults.store (faults, std::memory_order_release);
}

bool
wyl_secure_duckdb_filesystem_take_test_fault (guint fault)
{
  auto current = test_faults.load (std::memory_order_acquire);
  while ((current & fault) != 0) {
    if (test_faults.compare_exchange_weak (current, current & ~fault,
        std::memory_order_acq_rel, std::memory_order_acquire))
      return true;
  }
  return false;
}

WylSecureDuckdbFileSystem::WylSecureDuckdbFileSystem (WylFactArtifactNamespace
    *namespace_, bool read_only, bool create_temporary_storage)
  :
  lease_ (nullptr),
  temp_root_ (nullptr),
  read_only_ (read_only),
  health_ (std::make_shared<WylSecureDuckdbHealth> ())
{
  if (namespace_ == nullptr)
    throw WylSecureDuckdbAuthorityException (WYRELOG_E_INVALID,
        "invalid namespace binding");
  require_ok (wyl_fact_artifact_namespace_revalidate (namespace_),
      "initial namespace revalidation");
  const auto lease_result = read_only_
      ? wyl_fact_artifact_namespace_acquire_reader_guard (namespace_, &lease_)
      : wyl_fact_artifact_namespace_acquire_mutation_lease (namespace_,
          &lease_);
  require_ok (lease_result, "acquire storage lease");
  if (!read_only_ && create_temporary_storage) {
    WylFactDuckdbTempOrphanEvidence *evidence = nullptr;
    const auto result =
        wyl_fact_duckdb_temp_root_create_with_orphan_evidence (lease_,
            &temp_root_, &evidence);
    if (evidence != nullptr)
      wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
    if (result != WYRELOG_E_OK) {
      wyl_fact_artifact_mutation_lease_free (lease_);
      lease_ = nullptr;
      require_ok (result, "create temporary root");
    }
    g_autofree gchar *logical =
        wyl_fact_duckdb_temp_root_dup_logical_name (temp_root_);
    const auto cleanup_unpublished_temp_root = [this] () {
      WylFactDuckdbTempRetireResult retired =
          WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
      const auto result =
          wyl_fact_duckdb_temp_root_retire (temp_root_, &retired);
      wyl_fact_duckdb_temp_root_free (temp_root_);
      temp_root_ = nullptr;
      wyl_fact_artifact_mutation_lease_free (lease_);
      lease_ = nullptr;
      return result != WYRELOG_E_OK ? result
          : retired == WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED
          ? WYRELOG_E_OK : WYRELOG_E_POLICY;
    };
    if (logical == nullptr) {
      const auto cleanup = cleanup_unpublished_temp_root ();
      throw WylSecureDuckdbAuthorityException (
        cleanup == WYRELOG_E_OK ? WYRELOG_E_NOMEM : cleanup,
        "temporary root logical identity");
    }
    try {
      temporary_directory_ = logical;
    } catch (...) {
      const auto cleanup = cleanup_unpublished_temp_root ();
      if (cleanup != WYRELOG_E_OK)
        throw WylSecureDuckdbAuthorityException (cleanup,
            "clean up unpublished temporary root");
      throw;
    }
  }
}

WylSecureDuckdbFileSystem::~WylSecureDuckdbFileSystem ()
{
  FreeSidecarBindings ();
  for (auto & entry:temp_children_) {
    WylFactDuckdbTempRetireResult retired =
        WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
    const auto result =
        wyl_fact_duckdb_temp_child_retire (entry.second, &retired);
    if (result != WYRELOG_E_OK
        || retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
      health_->Poison (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result);
    wyl_fact_duckdb_temp_child_free (entry.second);
  }
  temp_children_.clear ();
  if (temp_root_ != nullptr) {
    WylFactDuckdbTempRetireResult retired =
        WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
    const auto result = wyl_fact_duckdb_temp_root_retire (temp_root_, &retired);
    if (result != WYRELOG_E_OK
        || retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
      health_->Poison (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result);
    wyl_fact_duckdb_temp_root_free (temp_root_);
  }
  if (owns_lease_)
    wyl_fact_artifact_mutation_lease_free (lease_);
}

WylFactArtifactMutationLease *
WylSecureDuckdbFileSystem::DetachLeaseOwnership ()
{
  if (!owns_lease_)
    return nullptr;
  owns_lease_ = false;
  return lease_;
}

void
WylSecureDuckdbFileSystem::RequireHealthy (const char *operation) const
{
  const auto result = health_->Status ();
  if (result != WYRELOG_E_OK)
    throw WylSecureDuckdbAuthorityException (result,
        duckdb::string (operation) + " rejected by poisoned filesystem");
}

void
WylSecureDuckdbFileSystem::RequireOk (wyrelog_error_t result,
    const char *operation) const
{
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, operation);
}

[[noreturn]] void
WylSecureDuckdbFileSystem::PoisonAndReject (wyrelog_error_t result,
    const char *operation) const
{
  health_->Poison (result);
  throw WylSecureDuckdbAuthorityException (
    result == WYRELOG_E_OK ? WYRELOG_E_IO : result,
    duckdb::string (operation) + " failed with authority error "
    + std::to_string (static_cast<int> (
      result == WYRELOG_E_OK ? WYRELOG_E_IO : result)));
}

void
WylSecureDuckdbFileSystem::RequireLease (const char *operation) const
{
  RequireHealthy (operation);
  RequireOk (wyl_fact_artifact_mutation_lease_revalidate (lease_), operation);
}

void
WylSecureDuckdbFileSystem::RegisterSidecarHandle (
  WylSecureDuckdbFileHandle *handle)
{
  std::lock_guard<std::mutex> lock (registry_mutex_);
  live_sidecar_handles_.push_back (handle);
}

void
WylSecureDuckdbFileSystem::UnregisterSidecarHandle (
  WylSecureDuckdbFileHandle *handle)
{
  std::lock_guard<std::mutex> lock (registry_mutex_);
  const auto found = std::find (live_sidecar_handles_.begin (),
          live_sidecar_handles_.end (), handle);
  if (found != live_sidecar_handles_.end ())
    live_sidecar_handles_.erase (found);
}

void
WylSecureDuckdbFileSystem::AdoptClosedSidecarBinding (
  WylFactArtifactName artifact, WylFactArtifactSidecarBinding *binding)
{
  if (binding == nullptr)
    return;
  try {
    std::lock_guard<std::mutex> lock (registry_mutex_);
    sidecar_bindings_.push_back ({ artifact, binding });
  } catch (...) {
    wyl_fact_artifact_sidecar_binding_free (binding);
    health_->Poison (WYRELOG_E_NOMEM);
    throw;
  }
}

WylFactArtifactSidecarBinding *
WylSecureDuckdbFileSystem::TakeSidecarBinding (WylFactArtifactName artifact)
{
  std::lock_guard<std::mutex> lock (registry_mutex_);
  std::unique_ptr<WylFactArtifactSidecarBinding,
  decltype (&wyl_fact_artifact_sidecar_binding_free)> selected (
    nullptr, wyl_fact_artifact_sidecar_binding_free);
  for (auto *handle : live_sidecar_handles_) {
    if (handle->sidecar_artifact_ != artifact)
      continue;
    auto *binding = handle->DetachSidecarBindingForMove ();
    if (binding == nullptr)
      continue;
    if (selected == nullptr)
      selected.reset (binding);
    else
      wyl_fact_artifact_sidecar_binding_free (binding);
  }
  for (auto it = sidecar_bindings_.rbegin ();
      it != sidecar_bindings_.rend (); ++it) {
    if (it->artifact != artifact || it->binding == nullptr)
      continue;
    if (selected == nullptr) {
      selected.reset (it->binding);
      it->binding = nullptr;
    }
  }
  sidecar_bindings_.erase (std::remove_if (sidecar_bindings_.begin (),
      sidecar_bindings_.end (), [] (const SidecarBindingRecord &record) {
    return record.binding == nullptr;
  }), sidecar_bindings_.end ());
  return selected.release ();
}

WylFactArtifactSidecarBinding *
WylSecureDuckdbFileSystem::BindAndCloseExistingSidecar (
  WylFactArtifactName artifact)
{
  WylFactArtifactSidecarBinding *binding = nullptr;
  int fd = -1;
  RequireOk (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (
        lease_, artifact, TRUE, &binding, &fd),
      "reacquire fixed sidecar binding");
  const auto close_result =
      wyl_fact_artifact_sidecar_binding_close (binding, &fd);
  if (close_result != WYRELOG_E_OK) {
    wyl_fact_artifact_sidecar_binding_free (binding);
    PoisonAndReject (close_result, "checked close reacquired sidecar");
  }
  return binding;
}

void
WylSecureDuckdbFileSystem::FreeSidecarBindings ()
{
  std::lock_guard<std::mutex> lock (registry_mutex_);
  for (auto &record : sidecar_bindings_)
    wyl_fact_artifact_sidecar_binding_free (record.binding);
  sidecar_bindings_.clear ();
}

WylFactDuckdbTempChild *
WylSecureDuckdbFileSystem::FindTempChild (
  const duckdb::string & logical_name) const
{
  const auto found = temp_children_.find (logical_name);
  return found == temp_children_.end ()? nullptr : found->second;
}

void
WylSecureDuckdbFileSystem::RollbackTempChild (
  WylFactDuckdbTempChild *child, WylSecureDuckdbPendingBinding &pending,
  wyrelog_error_t cause) noexcept
{
  (void) pending.Reset ();
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  const auto result = child == nullptr ? WYRELOG_E_POLICY
      : wyl_fact_duckdb_temp_child_retire (child, &retired);
  if (result != WYRELOG_E_OK
      || retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
    health_->Poison (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result);
  if (child != nullptr)
    wyl_fact_duckdb_temp_child_free (child);
  health_->Poison (cause);
}

duckdb::unique_ptr < duckdb::FileHandle >
WylSecureDuckdbFileSystem::OpenFile (const duckdb::string & path,
    duckdb::FileOpenFlags flags,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  RequireLease ("pre-open lease revalidation");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOST_PROBE
      || logical.kind == LogicalKind::HOME_METADATA
      || logical.kind == LogicalKind::TEMP_ROOT
      || logical.kind == LogicalKind::LOCK)
    io_reject ("open outside artifact authority: " + path);
  validate_flags (logical, flags, read_only_);
  if (read_only_ && flags.OpenForWriting ())
    io_reject ("write through validate-only bridge");

  std::optional<WylSecureDuckdbPendingBinding> pending;
  duckdb::unique_ptr < WylSecureDuckdbFileHandle > result;
  const auto make_handle = [&] (WylFactArtifactName artifact) {
    try {
      if (wyl_secure_duckdb_filesystem_take_test_fault (
            WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION))
        throw std::bad_alloc ();
      return duckdb::make_uniq<WylSecureDuckdbFileHandle> (*this, health_,
             path, flags, artifact, std::move (*pending));
    }
    catch (const std::bad_alloc &)
    {
      (void) pending->Reset ();
      health_->Poison (WYRELOG_E_NOMEM);
      throw;
    }
  };
  if (logical.kind == LogicalKind::MAIN) {
    if (flags.ExclusiveCreate () || flags.CreatePrivateFile ()
        || flags.OverwriteExistingFile ())
      io_reject ("main replacement");
    WylFactArtifactIoSession *session = nullptr;
    const auto open_result = read_only_
        ? wyl_fact_artifact_io_session_open_reader_main (lease_, &session)
        : wyl_fact_artifact_io_session_open_writer_main (lease_, &session);
    pending.emplace (health_, session);
    RequireOk (open_result, read_only_ ? "open reader main" : "open writer main");
    result = make_handle (WYL_FACT_ARTIFACT_MAIN);
  } else if (logical.kind == LogicalKind::SIDECAR) {
    if (read_only_) {
      if (logical.artifact != WYL_FACT_ARTIFACT_WAL)
        io_reject ("validate-only non-WAL sidecar");
      WylFactArtifactIoSession *session = nullptr;
      const auto open_result =
          wyl_fact_artifact_io_session_open_reader_wal (lease_, &session);
      pending.emplace (health_, session);
      if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
        return nullptr;
      RequireOk (open_result, "open reader WAL");
      result = make_handle (logical.artifact);
    } else {
      WylFactArtifactIoSession *session = nullptr;
      wyrelog_error_t open_result = WYRELOG_E_NOT_FOUND;
      const bool strict_create = flags.ExclusiveCreate ()
          || flags.CreatePrivateFile ();
      if (!strict_create) {
        open_result = wyl_fact_artifact_io_session_open_sidecar (
          lease_, logical.artifact, FALSE, flags.OpenForWriting (), &session);
        pending.emplace (health_, session);
      }
      if (is_missing (open_result)
          && (flags.CreateFileIfNotExists () || strict_create)) {
        pending.reset ();
        session = nullptr;
        open_result = wyl_fact_artifact_io_session_open_sidecar (
          lease_, logical.artifact, TRUE, flags.OpenForWriting (), &session);
        pending.emplace (health_, session);
      }
      if (open_result != WYRELOG_E_OK) {
        if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
          return nullptr;
        if (open_result == WYRELOG_E_POLICY
            && flags.ReturnNullIfExists () && strict_create)
          return nullptr;
        RequireOk (open_result, "open writer sidecar");
      }
      result = make_handle (logical.artifact);
    }
  } else if (logical.kind == LogicalKind::TEMP_CHILD) {
    if (read_only_)
      io_reject ("temporary file through validate-only bridge");
    auto *child = FindTempChild (logical.child);
    WylFactArtifactIoSession *session = nullptr;
    WylFactDuckdbTempOrphanEvidence *evidence = nullptr;
    wyrelog_error_t open_result;
    bool created_now = false;
    const bool strict_create = flags.ExclusiveCreate ()
        || flags.CreatePrivateFile ();
    if (child == nullptr && (flags.CreateFileIfNotExists () || strict_create)) {
      WylFactDuckdbTempChild *created = nullptr;
      open_result = wyl_fact_artifact_io_session_create_temp_child (
        temp_root_, logical.child.c_str (), flags.OpenForWriting (),
        &created, &session, &evidence);
      pending.emplace (health_, session);
      if (evidence != nullptr) {
        health_->Poison (open_result == WYRELOG_E_OK
            ? WYRELOG_E_POLICY : open_result);
        wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
      }
      if (open_result == WYRELOG_E_OK) {
        child = created;
        try {
          if (wyl_secure_duckdb_filesystem_take_test_fault (
                WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_TEMP_REGISTRATION))
            throw std::bad_alloc ();
          const auto insertion = temp_children_.emplace (logical.child,
                  created);
          if (!insertion.second) {
            RollbackTempChild (created, *pending, WYRELOG_E_POLICY);
            throw WylSecureDuckdbAuthorityException (WYRELOG_E_POLICY,
                "duplicate temporary child registration");
          }
        } catch (const WylSecureDuckdbAuthorityException &) {
          throw;
        } catch (...) {
          RollbackTempChild (created, *pending, WYRELOG_E_NOMEM);
          throw;
        }
        temp_children_created_++;
        created_now = true;
      }
    } else if (child != nullptr && !strict_create) {
      open_result = wyl_fact_artifact_io_session_open_existing_temp_child (
        child, flags.OpenForWriting (), &session);
      pending.emplace (health_, session);
    } else {
      open_result = child == nullptr ? WYRELOG_E_NOT_FOUND : WYRELOG_E_POLICY;
    }
    if (open_result != WYRELOG_E_OK) {
      if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
        return nullptr;
      if (open_result == WYRELOG_E_POLICY
          && flags.ReturnNullIfExists () && strict_create)
        return nullptr;
      RequireOk (open_result, "open temporary child");
    }
    try {
      result = make_handle (WYL_FACT_ARTIFACT_MAIN);
    } catch (...) {
      if (created_now) {
        temp_children_.erase (logical.child);
        temp_children_created_--;
        RollbackTempChild (child, *pending, WYRELOG_E_NOMEM);
      }
      throw;
    }
  } else {
    io_reject ("unsupported open");
  }
  if (flags.OpenForAppending ()) {
    const auto size = result->Size ();
    result->SeekTo (checked_file_size_cursor (size));
  }
  return result;
}

void
WylSecureDuckdbFileSystem::Read (duckdb::FileHandle & handle, void *buffer,
    int64_t bytes, duckdb::idx_t location)
{
  bounded_handle (handle).ReadAt (buffer, bytes, location);
}

void
WylSecureDuckdbFileSystem::Write (duckdb::FileHandle & handle, void *buffer,
    int64_t bytes, duckdb::idx_t location)
{
  bounded_handle (handle).WriteAt (buffer, bytes, location);
}

int64_t
WylSecureDuckdbFileSystem::Read (duckdb::FileHandle & handle, void *buffer,
    int64_t bytes)
{
  return bounded_handle (handle).ReadSome (buffer, bytes);
}

int64_t
WylSecureDuckdbFileSystem::Write (duckdb::FileHandle & handle, void *buffer,
    int64_t bytes)
{
  return bounded_handle (handle).WriteSome (buffer, bytes);
}

bool
WylSecureDuckdbFileSystem::Trim (duckdb::FileHandle &handle, duckdb::idx_t,
    duckdb::idx_t)
{
  bounded_handle (handle).Revalidate ();
  return false;
}

int64_t
WylSecureDuckdbFileSystem::GetFileSize (duckdb::FileHandle & handle)
{
  return bounded_handle (handle).Size ();
}

duckdb::timestamp_t
WylSecureDuckdbFileSystem::GetLastModifiedTime (duckdb::FileHandle & handle)
{
  return bounded_handle (handle).LastModifiedTime ();
}

duckdb::string
WylSecureDuckdbFileSystem::GetVersionTag (duckdb::FileHandle & handle)
{
  return bounded_handle (handle).VersionTag ();
}

duckdb::FileType
WylSecureDuckdbFileSystem::GetFileType (duckdb::FileHandle & handle)
{
  bounded_handle (handle).Revalidate ();
  return duckdb::FileType::FILE_TYPE_REGULAR;
}

duckdb::FileMetadata
WylSecureDuckdbFileSystem::Stats (duckdb::FileHandle & handle)
{
  duckdb::FileMetadata metadata;
  metadata.file_size = GetFileSize (handle);
  metadata.last_modification_time = GetLastModifiedTime (handle);
  metadata.file_type = GetFileType (handle);
  return metadata;
}

void
WylSecureDuckdbFileSystem::Truncate (duckdb::FileHandle & handle, int64_t size)
{
  bounded_handle (handle).TruncateTo (size);
}

bool
WylSecureDuckdbFileSystem::DirectoryExists (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard<std::mutex> lock (mutex_);
  RequireHealthy ("directory existence");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOME_METADATA)
    return false;
  if (logical.kind == LogicalKind::TEMP_ROOT) {
    RequireLease ("temporary root existence");
    return temp_root_ != nullptr;
  }
  io_reject ("directory existence outside temporary authority");
}

void
WylSecureDuckdbFileSystem::CreateDirectory (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard<std::mutex> lock (mutex_);
  RequireHealthy ("directory creation");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::TEMP_ROOT && temp_root_ != nullptr) {
    RequireLease ("temporary root creation");
    return;
  }
  io_reject ("directory creation outside temporary authority");
}

void
WylSecureDuckdbFileSystem::
CreateDirectoriesRecursive (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  CreateDirectory (path, opener);
}

void
WylSecureDuckdbFileSystem::RemoveDirectory (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  RequireLease ("pre-temp-root-retire lease revalidation");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind != LogicalKind::TEMP_ROOT || temp_root_ == nullptr
      || !temp_children_.empty ())
    io_reject ("temporary root retirement");
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  const auto result = wyl_fact_duckdb_temp_root_retire (temp_root_, &retired);
  if (result != WYRELOG_E_OK
      || retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
    PoisonAndReject (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result,
        retired == WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED
        ? "temporary root retirement requires reconciliation"
        : "retire temporary root");
  wyl_fact_duckdb_temp_root_free (temp_root_);
  temp_root_ = nullptr;
}

bool
WylSecureDuckdbFileSystem::ListFiles (const duckdb::string & path,
    const std::function < void (const duckdb::string &, bool) > &callback,
    duckdb::FileOpener *opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  RequireLease ("pre-temp-list lease revalidation");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOME_METADATA)
    io_reject ("virtual-home listing");
  if (logical.kind != LogicalKind::TEMP_ROOT || temp_root_ == nullptr)
    io_reject ("directory listing outside temporary authority");
  duckdb::vector < duckdb::string > names;
  RequireOk (wyl_fact_duckdb_temp_root_foreach_child (temp_root_,
      collect_temp_child, &names), "list temporary children");
  for (const auto & name:names)
    callback (name, false);
  return true;
}

void
WylSecureDuckdbFileSystem::MoveFile (const duckdb::string & source,
    const duckdb::string & target,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard<std::mutex> lock (mutex_);
  RequireLease ("pre-replace lease revalidation");
  if (read_only_)
    io_reject ("rename through validate-only bridge");
  const auto from = logical_path_for (source, temporary_directory_);
  const auto to = logical_path_for (target, temporary_directory_);
  if (from.kind != LogicalKind::SIDECAR || to.kind != LogicalKind::SIDECAR
      || (from.artifact != WYL_FACT_ARTIFACT_CHECKPOINT
      && from.artifact != WYL_FACT_ARTIFACT_RECOVERY)
      || to.artifact != WYL_FACT_ARTIFACT_WAL)
    io_reject ("rename outside fixed WAL replacement authority");

  std::unique_ptr<WylFactArtifactSidecarBinding,
  decltype (&wyl_fact_artifact_sidecar_binding_free)> source_binding (
    TakeSidecarBinding (from.artifact),
    wyl_fact_artifact_sidecar_binding_free);
  if (source_binding == nullptr)
    source_binding.reset (BindAndCloseExistingSidecar (from.artifact));
  std::unique_ptr<WylFactArtifactSidecarBinding,
  decltype (&wyl_fact_artifact_sidecar_binding_free)> destination_binding (
    TakeSidecarBinding (to.artifact),
    wyl_fact_artifact_sidecar_binding_free);
  if (destination_binding == nullptr)
    destination_binding.reset (BindAndCloseExistingSidecar (to.artifact));

  WylFactArtifactSidecarReplaceResult replacement =
      WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_NOT_REPLACED;
  const auto replace_result =
      wyl_fact_artifact_sidecar_binding_replace_existing_wal (
    source_binding.get (), destination_binding.get (), &replacement);

  {
    std::lock_guard<std::mutex> registry_lock (registry_mutex_);
    for (auto &record : sidecar_bindings_) {
      if (record.artifact == from.artifact || record.artifact == to.artifact) {
        wyl_fact_artifact_sidecar_binding_free (record.binding);
        record.binding = nullptr;
      }
    }
    sidecar_bindings_.erase (std::remove_if (sidecar_bindings_.begin (),
        sidecar_bindings_.end (), [] (const SidecarBindingRecord &record) {
      return record.binding == nullptr;
    }), sidecar_bindings_.end ());
  }

  if (replace_result == WYRELOG_E_OK
      && replacement
      == WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_REPLACED_DURABLE) {
    RequireLease ("post-replace lease revalidation");
    return;
  }
  if (replacement
      == WYL_FACT_ARTIFACT_SIDECAR_REPLACE_RESULT_RECONCILE_REQUIRED)
    PoisonAndReject (replace_result == WYRELOG_E_OK
        ? WYRELOG_E_POLICY : replace_result,
        "fixed WAL replacement requires reconciliation");
  PoisonAndReject (replace_result == WYRELOG_E_OK
      ? WYRELOG_E_POLICY : replace_result, "replace fixed WAL sidecar");
}

bool
WylSecureDuckdbFileSystem::FileExists (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  RequireHealthy ("artifact existence");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOST_PROBE
      || logical.kind == LogicalKind::HOME_METADATA)
    return false;
  RequireLease ("pre-exists lease revalidation");
  if (logical.kind == LogicalKind::TEMP_ROOT)
    return temp_root_ != nullptr;
  if (logical.kind == LogicalKind::TEMP_CHILD) {
    gboolean exists = FALSE;
    RequireOk (wyl_fact_duckdb_temp_root_child_exists (temp_root_,
        logical.child.c_str (), &exists), "temporary exists");
    return exists;
  }
  if (logical.kind == LogicalKind::LOCK)
    io_reject ("lock pathname observation");
  wyrelog_error_t result;
  bool provisioned_empty_main = false;
  if (logical.kind == LogicalKind::MAIN) {
    if (read_only_) {
      WylFactArtifactIoSession *session = nullptr;
      result = wyl_fact_artifact_io_session_open_reader_main (lease_, &session);
      if (result == WYRELOG_E_OK) {
        result = wyl_fact_artifact_io_session_finish (session);
      }
    } else {
      WylFactArtifactIoSession *session = nullptr;
      result = wyl_fact_artifact_io_session_open_writer_main (lease_, &session);
      WylSecureDuckdbPendingBinding pending (health_, session);
      RequireOk (result, "open writer main for existence");
      duckdb::unique_ptr<WylSecureDuckdbFileHandle> handle;
      try {
        if (wyl_secure_duckdb_filesystem_take_test_fault (
              WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION))
          throw std::bad_alloc ();
        handle = duckdb::make_uniq<WylSecureDuckdbFileHandle> (*this, health_,
            path, writer_main_existing_flags (),
            WYL_FACT_ARTIFACT_MAIN, std::move (pending));
      }
      catch (const std::bad_alloc &)
      {
        (void) pending.Reset ();
        health_->Poison (WYRELOG_E_NOMEM);
        throw;
      }
      int64_t size = 0;
      std::exception_ptr size_error;
      try {
        size = handle->Size ();
      } catch (...)
      {
        size_error = std::current_exception ();
      }
      handle->Close ();
      if (size_error != nullptr)
        std::rethrow_exception (size_error);
      provisioned_empty_main = size == 0;
    }
  } else if (read_only_) {
    if (logical.artifact != WYL_FACT_ARTIFACT_WAL)
      io_reject ("validate-only sidecar existence");
    WylFactArtifactIoSession *session = nullptr;
    result = wyl_fact_artifact_io_session_open_reader_wal (lease_, &session);
    if (result == WYRELOG_E_OK) {
      result = wyl_fact_artifact_io_session_finish (session);
    }
  } else {
    WylFactArtifactIoSession *session = nullptr;
    result = wyl_fact_artifact_io_session_open_sidecar (
      lease_, logical.artifact, FALSE, FALSE, &session);
    if (result == WYRELOG_E_OK) {
      result = wyl_fact_artifact_io_session_finish (session);
    }
  }
  if (result == WYRELOG_E_OK) {
    RequireLease ("post-exists lease revalidation");
    return !provisioned_empty_main;
  }
  if (is_missing (result)) {
    RequireLease ("post-exists lease revalidation");
    return false;
  }
  RequireOk (result, "artifact exists");
  return false;
}

bool
WylSecureDuckdbFileSystem::IsPipe (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  RequireHealthy ("pipe check");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOST_PROBE
      || logical.kind == LogicalKind::HOME_METADATA)
    return false;
  RequireLease ("pipe check");
  return false;
}

void
WylSecureDuckdbFileSystem::RetireTempChild (const duckdb::string & logical_name)
{
  auto found = temp_children_.find (logical_name);
  if (found == temp_children_.end ())
    io_reject ("unknown temporary child");
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  const auto result =
      wyl_fact_duckdb_temp_child_retire (found->second, &retired);
  if (result != WYRELOG_E_OK
      || retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
    PoisonAndReject (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result,
        retired == WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RECONCILE_REQUIRED
        ? "temporary child retirement requires reconciliation"
        : "retire temporary child");
  wyl_fact_duckdb_temp_child_free (found->second);
  temp_children_.erase (found);
}

bool
WylSecureDuckdbFileSystem::TryRemoveFile (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  RequireLease ("pre-remove lease revalidation");
  if (read_only_)
    io_reject ("remove through validate-only bridge");
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::TEMP_CHILD) {
    if (FindTempChild (logical.child) == nullptr)
      return false;
    RetireTempChild (logical.child);
    return true;
  }
  if (logical.kind != LogicalKind::SIDECAR)
    io_reject ("remove outside sidecar authority");
  std::unique_ptr<WylFactArtifactSidecarBinding,
  decltype (&wyl_fact_artifact_sidecar_binding_free)> binding (
    TakeSidecarBinding (logical.artifact),
    wyl_fact_artifact_sidecar_binding_free);
  if (binding == nullptr) {
    WylFactArtifactSidecarBinding *opened = nullptr;
    int fd = -1;
    const auto open_result =
        wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease_,
            logical.artifact, TRUE, &opened, &fd);
    if (is_missing (open_result))
      return false;
    RequireOk (open_result, "bind sidecar retirement");
    binding.reset (opened);
    const auto close_result =
        wyl_fact_artifact_sidecar_binding_close (binding.get (), &fd);
    if (close_result != WYRELOG_E_OK)
      PoisonAndReject (close_result, "checked close retired sidecar");
  }
  WylFactArtifactSidecarRetireResult retired =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  const auto result =
      wyl_fact_artifact_sidecar_binding_retire (binding.get (), &retired);
  {
    std::lock_guard<std::mutex> registry_lock (registry_mutex_);
    for (auto &record : sidecar_bindings_) {
      if (record.artifact == logical.artifact) {
        wyl_fact_artifact_sidecar_binding_free (record.binding);
        record.binding = nullptr;
      }
    }
    sidecar_bindings_.erase (std::remove_if (sidecar_bindings_.begin (),
        sidecar_bindings_.end (), [] (const SidecarBindingRecord &record) {
      return record.binding == nullptr;
    }), sidecar_bindings_.end ());
  }
  if (result != WYRELOG_E_OK
      || retired != WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED)
    PoisonAndReject (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result,
        retired
        == WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RECONCILE_REQUIRED
        ? "sidecar retirement requires reconciliation"
        : "retire sidecar");
  return true;
}

void
WylSecureDuckdbFileSystem::RemoveFile (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  if (!TryRemoveFile (path, opener))
    io_reject ("remove missing artifact");
}

void
WylSecureDuckdbFileSystem::RemoveFiles (const duckdb::vector < duckdb::string >
    &paths, duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  for (const auto & path:paths)
    (void) TryRemoveFile (path, opener);
}

void
WylSecureDuckdbFileSystem::FileSync (duckdb::FileHandle & handle)
{
  bounded_handle (handle).Sync ();
}

duckdb::string WylSecureDuckdbFileSystem::GetHomeDirectory ()
{
  RequireHealthy ("home directory");
  return virtual_home;
}

duckdb::string
WylSecureDuckdbFileSystem::ExpandPath (const duckdb::string & path)
{
  RequireHealthy ("path expansion");
  (void) logical_path_for (path, temporary_directory_);
  return path;
}

duckdb::string
WylSecureDuckdbFileSystem::PathSeparator (const duckdb::string & path)
{
  RequireHealthy ("path separator");
  (void) logical_path_for (path, temporary_directory_);
  return "/";
}

bool
WylSecureDuckdbFileSystem::IsPathAbsolute (const duckdb::string & path)
{
  RequireHealthy ("absolute path check");
  return is_home_metadata (path);
}

duckdb::vector < duckdb::OpenFileInfo >
WylSecureDuckdbFileSystem::Glob (const duckdb::string &,
    duckdb::FileOpener *)
{
  unsupported ("glob");
}

void
WylSecureDuckdbFileSystem::RegisterSubSystem (duckdb::unique_ptr <
    duckdb::FileSystem >)
{
  unsupported ("subsystems");
}

void
WylSecureDuckdbFileSystem::RegisterSubSystem (duckdb::FileCompressionType,
    duckdb::unique_ptr < duckdb::FileSystem >)
{
  unsupported ("compressed subsystems");
}

void
WylSecureDuckdbFileSystem::UnregisterSubSystem (const duckdb::string &)
{
  unsupported ("subsystems");
}

duckdb::unique_ptr < duckdb::FileSystem >
WylSecureDuckdbFileSystem::ExtractSubSystem (const duckdb::string &)
{
  unsupported ("subsystems");
}

duckdb::vector < duckdb::string > WylSecureDuckdbFileSystem::ListSubSystems ()
{
  return {
  };
}

bool
WylSecureDuckdbFileSystem::CanHandleFile (const duckdb::string & path)
{
  RequireHealthy ("file handling check");
  try {
    const auto logical = logical_path_for (path, temporary_directory_);
    return logical.kind != LogicalKind::HOME_METADATA
           && logical.kind != LogicalKind::HOST_PROBE
           && logical.kind != LogicalKind::LOCK;
  }
  catch (const duckdb::Exception &)
  {
    return false;
  }
}

void
WylSecureDuckdbFileSystem::Seek (duckdb::FileHandle & handle,
    duckdb::idx_t location)
{
  bounded_handle (handle).SeekTo (location);
}

void
WylSecureDuckdbFileSystem::Reset (duckdb::FileHandle & handle)
{
  Seek (handle, 0);
}

duckdb::idx_t
WylSecureDuckdbFileSystem::SeekPosition (duckdb::FileHandle & handle)
{
  return bounded_handle (handle).SeekPosition ();
}

bool
WylSecureDuckdbFileSystem::IsManuallySet ()
{
  return true;
}

bool
WylSecureDuckdbFileSystem::CanSeek ()
{
  return true;
}

bool
WylSecureDuckdbFileSystem::OnDiskFile (duckdb::FileHandle & handle)
{
  bounded_handle (handle).Revalidate ();
  return true;
}

duckdb::unique_ptr < duckdb::FileHandle >
WylSecureDuckdbFileSystem::OpenCompressedFile (duckdb::QueryContext,
    duckdb::unique_ptr < duckdb::FileHandle >, bool)
{
  unsupported ("compressed files");
}

bool
WylSecureDuckdbFileSystem::IsLocalFileSystem () const
{
  /* DuckDB otherwise creates an independent LocalFileSystem and retains it
   * as a fallback beside this injected filesystem. */
  return true;
}

std::string WylSecureDuckdbFileSystem::GetName ()const
{
  return "wyrelog-bounded-duckdb-filesystem";
}

void
WylSecureDuckdbFileSystem::SetDisabledFileSystems (const duckdb::vector <
    duckdb::string > &)
{
  /* No subsystem is registered, so every external scheme is already
   * disabled. */
}

bool
WylSecureDuckdbFileSystem::SubSystemIsDisabled (const duckdb::string &)
{
  return true;
}

bool
WylSecureDuckdbFileSystem::IsDisabledForPath (const duckdb::string & path)
{
  return !CanHandleFile (path);
}

duckdb::string
WylSecureDuckdbFileSystem::CanonicalizePath (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  RequireHealthy ("canonical path");
  (void) logical_path_for (path, temporary_directory_);
  return path;
}

duckdb::unique_ptr < duckdb::FileHandle >
WylSecureDuckdbFileSystem::
OpenFileExtended (const duckdb::OpenFileInfo & info,
    duckdb::FileOpenFlags flags,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  return OpenFile (info.path, flags, opener);
}

bool
WylSecureDuckdbFileSystem::SupportsOpenFileExtended () const
{
  return true;
}

bool
WylSecureDuckdbFileSystem::ListFilesExtended (const duckdb::string & directory,
    const std::function < void (duckdb::OpenFileInfo &) > &callback,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  return ListFiles (directory,[&callback] (const duckdb::string & path, bool) {
    duckdb::OpenFileInfo info (path);
    callback (info);
  }, opener.get ());
}

bool
WylSecureDuckdbFileSystem::SupportsListFilesExtended () const
{
  return false;
}

duckdb::unique_ptr < duckdb::MultiFileList >
WylSecureDuckdbFileSystem::GlobFilesExtended (const duckdb::string &,
    const duckdb::FileGlobInput &, duckdb::optional_ptr < duckdb::FileOpener >)
{
  unsupported ("extended glob");
}

bool
WylSecureDuckdbFileSystem::SupportsGlobExtended () const
{
  return false;
}

duckdb::unique_ptr < WylSecureDuckdbFileSystem >
wyl_secure_duckdb_filesystem_new (WylFactArtifactNamespace *namespace_,
    bool read_only, bool create_temporary_storage)
{
  return duckdb::make_uniq < WylSecureDuckdbFileSystem > (namespace_,
         read_only, create_temporary_storage);
}
