/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-filesystem-private.hpp"

#include "fact/secure-duckdb-artifact-contract-private.h"
#include "fact/secure-duckdb-file-handle-private.hpp"
#include "fact/secure-duckdb-filesystem-contract-private.h"

#include <cstdint>

namespace {

  constexpr const char *virtual_home = "/__wyrelog_duckdb_home__";

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
          LogicalKind::TEMP_CHILD, WYL_FACT_ARTIFACT_TEMP, child};
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

  void validate_flags (const LogicalPath & logical, duckdb::FileOpenFlags flags,
      bool read_only)
  {
    bool accepted = false;
    if (logical.kind == LogicalKind::MAIN) {
      accepted = exact_flags (flags, 129, duckdb::FileLockType::NO_LOCK)
          || (read_only
          && exact_flags (flags, 2433, duckdb::FileLockType::READ_LOCK))
          || (!read_only
          && (exact_flags (flags, 2307, duckdb::FileLockType::WRITE_LOCK)
              || exact_flags (flags, 2315, duckdb::FileLockType::WRITE_LOCK)));
    } else if (logical.kind == LogicalKind::SIDECAR) {
      accepted = exact_flags (flags, 129, duckdb::FileLockType::NO_LOCK)
          || (!read_only
          && exact_flags (flags, 2090, duckdb::FileLockType::WRITE_LOCK));
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

}                               // namespace

WylSecureDuckdbFileSystem::WylSecureDuckdbFileSystem (WylFactArtifactNamespace
    *namespace_, bool read_only)
    :
lease_ (nullptr),
temp_root_ (nullptr),
read_only_ (read_only)
{
  if (namespace_ == nullptr
      || wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    io_reject ("invalid namespace binding");
  const auto lease_result = read_only_
      ? wyl_fact_artifact_namespace_acquire_reader_guard (namespace_, &lease_)
      : wyl_fact_artifact_namespace_acquire_mutation_lease (namespace_,
      &lease_);
  require_ok (lease_result, "acquire storage lease");
  if (!read_only_) {
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
    if (logical == nullptr) {
      wyl_fact_duckdb_temp_root_free (temp_root_);
      temp_root_ = nullptr;
      wyl_fact_artifact_mutation_lease_free (lease_);
      lease_ = nullptr;
      io_reject ("temporary root logical identity");
    }
    temporary_directory_ = logical;
  }
}

WylSecureDuckdbFileSystem::~WylSecureDuckdbFileSystem ()
{
for (auto & entry:temp_children_) {
    WylFactDuckdbTempRetireResult retired =
        WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
    (void) wyl_fact_duckdb_temp_child_retire (entry.second, &retired);
    wyl_fact_duckdb_temp_child_free (entry.second);
  }
  temp_children_.clear ();
  if (temp_root_ != nullptr) {
    WylFactDuckdbTempRetireResult retired =
        WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
    (void) wyl_fact_duckdb_temp_root_retire (temp_root_, &retired);
    wyl_fact_duckdb_temp_root_free (temp_root_);
  }
  wyl_fact_artifact_mutation_lease_free (lease_);
}

void
WylSecureDuckdbFileSystem::RequireLease (const char *operation) const
{
  require_ok (wyl_fact_artifact_mutation_lease_revalidate (lease_), operation);
}

WylFactDuckdbTempChild *
WylSecureDuckdbFileSystem::FindTempChild (const duckdb::string & logical_name) const
{
  const auto found = temp_children_.find (logical_name);
  return found == temp_children_.end ()? nullptr : found->second;
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

  int fd = -1;
  duckdb::unique_ptr < WylSecureDuckdbFileHandle > result;
  if (logical.kind == LogicalKind::MAIN) {
    if (flags.ExclusiveCreate () || flags.CreatePrivateFile ()
        || flags.OverwriteExistingFile ())
      io_reject ("main replacement");
    if (read_only_) {
      WylFactArtifactReaderMainBinding *binding = nullptr;
      require_ok (wyl_fact_artifact_reader_guard_open_main_binding (lease_,
              &binding, &fd), "open reader main");
      result =
          duckdb::make_uniq < WylSecureDuckdbFileHandle > (*this, path, flags,
          fd, binding);
    } else {
      WylFactArtifactMainBinding *binding = nullptr;
      require_ok (wyl_fact_artifact_mutation_lease_open_main_binding (lease_,
              &binding, &fd), "open writer main");
      result =
          duckdb::make_uniq < WylSecureDuckdbFileHandle > (*this, path, flags,
          fd, binding);
    }
  } else if (logical.kind == LogicalKind::SIDECAR) {
    if (read_only_) {
      if (logical.artifact != WYL_FACT_ARTIFACT_WAL)
        io_reject ("validate-only non-WAL sidecar");
      WylFactArtifactReaderWalBinding *binding = nullptr;
      const auto open_result =
          wyl_fact_artifact_reader_guard_open_existing_wal_binding (lease_,
          &binding, &fd);
      if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
        return nullptr;
      require_ok (open_result, "open reader WAL");
      result =
          duckdb::make_uniq < WylSecureDuckdbFileHandle > (*this, path, flags,
          fd, binding);
    } else {
      WylFactArtifactSidecarBinding *binding = nullptr;
      wyrelog_error_t open_result = WYRELOG_E_NOT_FOUND;
      const bool strict_create = flags.ExclusiveCreate ()
          || flags.CreatePrivateFile ();
      if (!strict_create) {
        open_result = flags.OpenForWriting ()
            ?
            wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
            (lease_, logical.artifact, TRUE, &binding, &fd)
            : wyl_fact_artifact_mutation_lease_open_sidecar_binding (lease_,
            logical.artifact, FALSE, FALSE, &binding, &fd);
      }
      if (is_missing (open_result)
          && (flags.CreateFileIfNotExists () || strict_create)) {
        open_result =
            wyl_fact_artifact_mutation_lease_open_sidecar_binding (lease_,
            logical.artifact, TRUE, flags.OpenForWriting (), &binding, &fd);
      }
      if (open_result != WYRELOG_E_OK) {
        if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
          return nullptr;
        if (open_result == WYRELOG_E_POLICY
            && flags.ReturnNullIfExists () && strict_create)
          return nullptr;
        require_ok (open_result, "open writer sidecar");
      }
      result =
          duckdb::make_uniq < WylSecureDuckdbFileHandle > (*this, path, flags,
          fd, binding);
    }
  } else if (logical.kind == LogicalKind::TEMP_CHILD) {
    if (read_only_)
      io_reject ("temporary file through validate-only bridge");
    auto *child = FindTempChild (logical.child);
    WylFactDuckdbTempChildBinding *binding = nullptr;
    WylFactDuckdbTempOrphanEvidence *evidence = nullptr;
    wyrelog_error_t open_result;
    const bool strict_create = flags.ExclusiveCreate ()
        || flags.CreatePrivateFile ();
    if (child == nullptr && (flags.CreateFileIfNotExists () || strict_create)) {
      WylFactDuckdbTempChild *created = nullptr;
      open_result =
          wyl_fact_duckdb_temp_root_create_child_binding (temp_root_,
          logical.child.c_str (), &created, &binding, &fd, &evidence);
      if (evidence != nullptr)
        wyl_fact_duckdb_temp_orphan_evidence_free (evidence);
      if (open_result == WYRELOG_E_OK) {
        child = created;
        temp_children_.emplace (logical.child, created);
        temp_children_created_++;
      }
    } else if (child != nullptr && !strict_create) {
      open_result =
          wyl_fact_duckdb_temp_child_open_binding (child,
          flags.OpenForWriting (), &binding, &fd);
    } else {
      open_result = child == nullptr ? WYRELOG_E_NOT_FOUND : WYRELOG_E_POLICY;
    }
    if (open_result != WYRELOG_E_OK) {
      if (is_missing (open_result) && flags.ReturnNullIfNotExists ())
        return nullptr;
      if (open_result == WYRELOG_E_POLICY
          && flags.ReturnNullIfExists () && strict_create)
        return nullptr;
      require_ok (open_result, "open temporary child");
    }
    result =
        duckdb::make_uniq < WylSecureDuckdbFileHandle > (*this, path, flags, fd,
        binding);
  } else {
    io_reject ("unsupported open");
  }
  if (flags.OpenForAppending ()) {
    const auto size = result->Size ();
    result->SeekTo (static_cast < duckdb::idx_t > (size));
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
WylSecureDuckdbFileSystem::Trim (duckdb::FileHandle &, duckdb::idx_t,
    duckdb::idx_t)
{
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
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOME_METADATA)
    return false;
  if (logical.kind == LogicalKind::TEMP_ROOT)
    return temp_root_ != nullptr;
  io_reject ("directory existence outside temporary authority");
}

void
WylSecureDuckdbFileSystem::CreateDirectory (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::TEMP_ROOT && temp_root_ != nullptr)
    return;
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
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind != LogicalKind::TEMP_ROOT || temp_root_ == nullptr
      || !temp_children_.empty ())
    io_reject ("temporary root retirement");
  WylFactDuckdbTempRetireResult retired =
      WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_NOT_RETIRED;
  require_ok (wyl_fact_duckdb_temp_root_retire (temp_root_, &retired),
      "retire temporary root");
  if (retired != WYL_FACT_DUCKDB_TEMP_RETIRE_RESULT_RETIRED)
    io_reject ("temporary root retirement result");
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
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOME_METADATA)
    io_reject ("virtual-home listing");
  if (logical.kind != LogicalKind::TEMP_ROOT || temp_root_ == nullptr)
    io_reject ("directory listing outside temporary authority");
  duckdb::vector < duckdb::string > names;
  require_ok (wyl_fact_duckdb_temp_root_foreach_child (temp_root_,
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
  std::lock_guard < std::mutex > lock (mutex_);
  if (read_only_)
    io_reject ("rename through validate-only bridge");
  const auto from = logical_path_for (source, temporary_directory_);
  const auto to = logical_path_for (target, temporary_directory_);
  if (from.kind != LogicalKind::SIDECAR
      || to.kind != LogicalKind::SIDECAR || from.artifact == to.artifact)
    io_reject ("rename outside fixed-sidecar authority");
  WylFactArtifactSidecarBinding *binding = nullptr;
  int fd = -1;
  require_ok (wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding
      (lease_, from.artifact, TRUE, &binding, &fd), "bind rename source");
  const auto close_result =
      wyl_fact_artifact_sidecar_binding_close (binding, &fd);
  if (close_result != WYRELOG_E_OK) {
    wyl_fact_artifact_sidecar_binding_free (binding);
    require_ok (close_result, "close rename source");
  }
  const auto publish_result =
      wyl_fact_artifact_sidecar_binding_publish_no_replace (binding,
      to.artifact);
  wyl_fact_artifact_sidecar_binding_free (binding);
  require_ok (publish_result, "publish fixed sidecar");
}

bool
WylSecureDuckdbFileSystem::FileExists (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
  const auto logical = logical_path_for (path, temporary_directory_);
  if (logical.kind == LogicalKind::HOST_PROBE
      || logical.kind == LogicalKind::HOME_METADATA)
    return false;
  RequireLease ("pre-exists lease revalidation");
  if (logical.kind == LogicalKind::TEMP_ROOT)
    return temp_root_ != nullptr;
  if (logical.kind == LogicalKind::TEMP_CHILD) {
    gboolean exists = FALSE;
    require_ok (wyl_fact_duckdb_temp_root_child_exists (temp_root_,
            logical.child.c_str (), &exists), "temporary exists");
    return exists;
  }
  if (logical.kind == LogicalKind::LOCK)
    io_reject ("lock pathname observation");
  int fd = -1;
  wyrelog_error_t result;
  if (logical.kind == LogicalKind::MAIN) {
    if (read_only_) {
      WylFactArtifactReaderMainBinding *binding = nullptr;
      result =
          wyl_fact_artifact_reader_guard_open_main_binding (lease_, &binding,
          &fd);
      if (result == WYRELOG_E_OK) {
        result = wyl_fact_artifact_reader_main_binding_close (binding, &fd);
        wyl_fact_artifact_reader_main_binding_free (binding);
      }
    } else {
      WylFactArtifactMainBinding *binding = nullptr;
      result =
          wyl_fact_artifact_mutation_lease_open_main_binding (lease_, &binding,
          &fd);
      if (result == WYRELOG_E_OK) {
        result = wyl_fact_artifact_main_binding_close (binding, &fd);
        wyl_fact_artifact_main_binding_free (binding);
      }
    }
  } else if (read_only_) {
    if (logical.artifact != WYL_FACT_ARTIFACT_WAL)
      io_reject ("validate-only sidecar existence");
    WylFactArtifactReaderWalBinding *binding = nullptr;
    result =
        wyl_fact_artifact_reader_guard_open_existing_wal_binding (lease_,
        &binding, &fd);
    if (result == WYRELOG_E_OK) {
      result = wyl_fact_artifact_reader_wal_binding_close (binding, &fd);
      wyl_fact_artifact_reader_wal_binding_free (binding);
    }
  } else {
    WylFactArtifactSidecarBinding *binding = nullptr;
    result =
        wyl_fact_artifact_mutation_lease_open_sidecar_binding (lease_,
        logical.artifact, FALSE, FALSE, &binding, &fd);
    if (result == WYRELOG_E_OK) {
      result = wyl_fact_artifact_sidecar_binding_close (binding, &fd);
      wyl_fact_artifact_sidecar_binding_free (binding);
    }
  }
  if (result == WYRELOG_E_OK) {
    RequireLease ("post-exists lease revalidation");
    return true;
  }
  if (is_missing (result)) {
    RequireLease ("post-exists lease revalidation");
    return false;
  }
  require_ok (result, "artifact exists");
  return false;
}

bool
WylSecureDuckdbFileSystem::IsPipe (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
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
    require_ok (result == WYRELOG_E_OK ? WYRELOG_E_POLICY : result,
        "retire temporary child");
  wyl_fact_duckdb_temp_child_free (found->second);
  temp_children_.erase (found);
}

bool
WylSecureDuckdbFileSystem::TryRemoveFile (const duckdb::string & path,
    duckdb::optional_ptr < duckdb::FileOpener > opener)
{
  (void) opener;
  std::lock_guard < std::mutex > lock (mutex_);
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
  WylFactArtifactSidecarBinding *binding = nullptr;
  int fd = -1;
  const auto open_result =
      wyl_fact_artifact_mutation_lease_open_existing_sidecar_binding (lease_,
      logical.artifact, TRUE, &binding, &fd);
  if (is_missing (open_result))
    return false;
  require_ok (open_result, "bind sidecar retirement");
  auto result = wyl_fact_artifact_sidecar_binding_close (binding, &fd);
  WylFactArtifactSidecarRetireResult retired =
      WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_NOT_RETIRED;
  if (result == WYRELOG_E_OK)
    result = wyl_fact_artifact_sidecar_binding_retire (binding, &retired);
  wyl_fact_artifact_sidecar_binding_free (binding);
  require_ok (result, "retire sidecar");
  if (retired != WYL_FACT_ARTIFACT_SIDECAR_RETIRE_RESULT_RETIRED)
    io_reject ("sidecar retirement result");
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
  return virtual_home;
}

duckdb::string
    WylSecureDuckdbFileSystem::ExpandPath (const duckdb::string & path)
{
  (void) logical_path_for (path, temporary_directory_);
  return path;
}

duckdb::string
    WylSecureDuckdbFileSystem::PathSeparator (const duckdb::string & path)
{
  (void) logical_path_for (path, temporary_directory_);
  return "/";
}

bool
WylSecureDuckdbFileSystem::IsPathAbsolute (const duckdb::string & path)
{
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
    bool read_only)
{
  return duckdb::make_uniq < WylSecureDuckdbFileSystem > (namespace_,
      read_only);
}
