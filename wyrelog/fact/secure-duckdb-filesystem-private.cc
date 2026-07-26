/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-filesystem-private.hpp"

#include "fact/secure-duckdb-artifact-contract-private.h"
#include "fact/secure-duckdb-file-handle-private.hpp"
#include "fact/secure-duckdb-filesystem-contract-private.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

struct LogicalArtifact
{
  WylFactArtifactName artifact;
  duckdb::string temp_token;
};

[[noreturn]] void
io_reject (const duckdb::string &message)
{
  throw duckdb::IOException ("bounded DuckDB filesystem rejected " + message);
}

[[noreturn]] void
unsupported (const char *operation)
{
  throw duckdb::NotImplementedException (
      "bounded DuckDB filesystem does not support %s", operation);
}

LogicalArtifact
logical_artifact_for (const duckdb::string &logical_name)
{
  WylFactArtifactName artifact;
  if (wyl_secure_duckdb_artifact_name (logical_name, &artifact))
    return { artifact, {} };
  if (logical_name.rfind ("tmp-", 0) == 0) {
    auto token = logical_name.substr (4);
    if (!token.empty () && token.size () <= 48) {
      for (const auto character : token)
        if (!((character >= 'a' && character <= 'z')
                || (character >= 'A' && character <= 'Z')
                || (character >= '0' && character <= '9')
                || character == '-'))
          io_reject ("invalid temporary logical name: " + logical_name);
      return { WYL_FACT_ARTIFACT_TEMP, std::move (token) };
    }
  }
  io_reject ("non-canonical logical name: " + logical_name);
}

WylSecureDuckdbFileHandle &
bounded_handle (duckdb::FileHandle &handle)
{
  return handle.Cast<WylSecureDuckdbFileHandle> ();
}

void
require_ok (wyrelog_error_t rc, const char *operation)
{
  if (rc != WYRELOG_E_OK)
    io_reject (duckdb::string (operation) + " failed with authority error "
        + std::to_string (static_cast<int> (rc)));
}

bool
is_missing (wyrelog_error_t rc)
{
  return rc == WYRELOG_E_NOT_FOUND;
}

void
validate_flags (duckdb::FileOpenFlags flags)
{
  const duckdb::idx_t allowed =
      duckdb::FileOpenFlags::FILE_FLAGS_READ
      | duckdb::FileOpenFlags::FILE_FLAGS_WRITE
      | duckdb::FileOpenFlags::FILE_FLAGS_FILE_CREATE
      | duckdb::FileOpenFlags::FILE_FLAGS_FILE_CREATE_NEW
      | duckdb::FileOpenFlags::FILE_FLAGS_APPEND
      | duckdb::FileOpenFlags::FILE_FLAGS_PRIVATE
      | duckdb::FileOpenFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS
      | duckdb::FileOpenFlags::FILE_FLAGS_PARALLEL_ACCESS
      | duckdb::FileOpenFlags::FILE_FLAGS_EXCLUSIVE_CREATE
      | duckdb::FileOpenFlags::FILE_FLAGS_NULL_IF_EXISTS
      | duckdb::FileOpenFlags::FILE_FLAGS_MULTI_CLIENT_ACCESS
      | duckdb::FileOpenFlags::FILE_FLAGS_DISABLE_LOGGING;
  if ((flags.GetFlagsInternal () & ~allowed) != 0)
    io_reject ("unsupported open flags");
  if (!flags.OpenForReading () && !flags.OpenForWriting ())
    io_reject ("open without read or write authority");
  if (flags.Compression () != duckdb::FileCompressionType::UNCOMPRESSED
      && flags.Compression () != duckdb::FileCompressionType::AUTO_DETECT)
    io_reject ("compressed access");
  if ((flags.CreateFileIfNotExists () || flags.OverwriteExistingFile ()
          || flags.ExclusiveCreate () || flags.CreatePrivateFile ())
      && !flags.OpenForWriting ())
    io_reject ("creation without write authority");
}

} // namespace

WylSecureDuckdbFileSystem::WylSecureDuckdbFileSystem (
    WylFactArtifactNamespace *namespace_)
    : namespace_ (namespace_), main_bound_ (false), lock_fd_ (-1),
      lock_type_ (duckdb::FileLockType::NO_LOCK)
{
  if (namespace_ == nullptr
      || wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    io_reject ("invalid namespace binding");
  main_bound_ = wyl_fact_artifact_namespace_revalidate_main (namespace_)
      == WYRELOG_E_OK;
}

WylSecureDuckdbFileSystem::~WylSecureDuckdbFileSystem ()
{
  if (lock_fd_ >= 0)
    close (lock_fd_);
}

int
WylSecureDuckdbFileSystem::AcquireLockDescriptor (
    duckdb::FileLockType requested)
{
  if (requested == duckdb::FileLockType::NO_LOCK)
    return -1;
  if (lock_fd_ < 0) {
    require_ok (wyl_fact_artifact_namespace_lock (namespace_,
        requested == duckdb::FileLockType::WRITE_LOCK, &lock_fd_),
        "database lock");
    lock_type_ = requested;
    require_ok (wyl_fact_artifact_namespace_sync_directory (namespace_),
        "lock directory sync");
  } else if (lock_type_ == duckdb::FileLockType::READ_LOCK
      && requested == duckdb::FileLockType::WRITE_LOCK) {
    if (flock (lock_fd_, LOCK_EX | LOCK_NB) != 0)
      io_reject ("database lock upgrade");
    lock_type_ = duckdb::FileLockType::WRITE_LOCK;
  }
  const int duplicate = fcntl (lock_fd_, F_DUPFD_CLOEXEC, 0);
  if (duplicate < 0)
    io_reject ("database lock duplication");
  return duplicate;
}

duckdb::unique_ptr<duckdb::FileHandle>
WylSecureDuckdbFileSystem::OpenFile (const duckdb::string &path,
    duckdb::FileOpenFlags flags,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  std::lock_guard<std::mutex> open_lock (open_mutex_);
  validate_flags (flags);
  const auto logical = logical_artifact_for (path);
  const auto artifact = logical.artifact;
  if (artifact == WYL_FACT_ARTIFACT_MAIN && main_bound_)
    require_ok (wyl_fact_artifact_namespace_revalidate_main (namespace_),
        "pre-open main revalidation");
  const bool writable = flags.OpenForWriting ();
  const bool must_create = flags.ExclusiveCreate ()
      || flags.CreatePrivateFile ();
  const bool overwrite = flags.OverwriteExistingFile ();
  const bool may_create = flags.CreateFileIfNotExists () || must_create
      || overwrite;
  if (artifact == WYL_FACT_ARTIFACT_MAIN && main_bound_
      && (must_create || overwrite))
    io_reject ("replacing the held main binding is forbidden");
  int fd = -1;
  wyrelog_error_t rc;
  bool created = false;

  if (overwrite) {
    if (artifact == WYL_FACT_ARTIFACT_TEMP)
      io_reject ("temporary replacement is not provided by the namespace");
    rc = wyl_fact_artifact_namespace_unlink (namespace_, artifact);
    if (rc != WYRELOG_E_OK && !is_missing (rc))
      require_ok (rc, "replace unlink");
    rc = wyl_fact_artifact_namespace_open_file (namespace_, artifact,
        TRUE, writable, &fd);
    created = rc == WYRELOG_E_OK;
  } else if (must_create) {
    if (flags.ReturnNullIfExists ()) {
      int existing_fd = -1;
      rc = artifact == WYL_FACT_ARTIFACT_TEMP
          ? wyl_fact_artifact_namespace_open_temp (namespace_,
              logical.temp_token.c_str (), FALSE, FALSE, &existing_fd)
          : wyl_fact_artifact_namespace_open_file (namespace_, artifact,
              FALSE, FALSE, &existing_fd);
      if (rc == WYRELOG_E_OK) {
        close (existing_fd);
        return nullptr;
      }
      if (!is_missing (rc))
        require_ok (rc, "exclusive existence check");
    }
    rc = artifact == WYL_FACT_ARTIFACT_TEMP
        ? wyl_fact_artifact_namespace_open_temp (namespace_,
            logical.temp_token.c_str (), TRUE, writable, &fd)
        : wyl_fact_artifact_namespace_open_file (namespace_, artifact,
            TRUE, writable, &fd);
    created = rc == WYRELOG_E_OK;
  } else {
    rc = artifact == WYL_FACT_ARTIFACT_TEMP
        ? wyl_fact_artifact_namespace_open_temp (namespace_,
            logical.temp_token.c_str (), FALSE, writable, &fd)
        : wyl_fact_artifact_namespace_open_file (namespace_, artifact,
            FALSE, writable, &fd);
    if (is_missing (rc) && may_create) {
      rc = artifact == WYL_FACT_ARTIFACT_TEMP
          ? wyl_fact_artifact_namespace_open_temp (namespace_,
              logical.temp_token.c_str (), TRUE, writable, &fd)
          : wyl_fact_artifact_namespace_open_file (namespace_, artifact,
              TRUE, writable, &fd);
      created = rc == WYRELOG_E_OK;
    }
  }

  if (rc != WYRELOG_E_OK) {
    if (is_missing (rc) && flags.ReturnNullIfNotExists ())
      return nullptr;
    require_ok (rc, "open");
  }
  if (created)
    require_ok (wyl_fact_artifact_namespace_sync_directory (namespace_),
        "created-file directory sync");

  int lock_fd = -1;
  try {
    lock_fd = AcquireLockDescriptor (flags.Lock ());
  } catch (...) {
    close (fd);
    throw;
  }
  if (artifact == WYL_FACT_ARTIFACT_MAIN) {
    rc = main_bound_
        ? wyl_fact_artifact_namespace_revalidate_main (namespace_)
        : wyl_fact_artifact_namespace_bind_main (namespace_);
    if (rc != WYRELOG_E_OK) {
      close (fd);
      if (lock_fd >= 0)
        close (lock_fd);
      require_ok (rc, "bind main");
    }
    main_bound_ = true;
  } else {
    rc = wyl_fact_artifact_namespace_revalidate_main (namespace_);
    if (rc != WYRELOG_E_OK) {
      close (fd);
      if (lock_fd >= 0)
        close (lock_fd);
      require_ok (rc, "revalidate main");
    }
  }

  auto result = duckdb::make_uniq<WylSecureDuckdbFileHandle> (*this,
      namespace_, artifact, path, flags, fd, lock_fd);
  if (!result->Revalidate ())
    io_reject ("opened handle lost identity");
  if (flags.OpenForAppending ()) {
    const auto size = result->Size ();
    if (size < 0 || !result->SeekTo (static_cast<duckdb::idx_t> (size)))
      io_reject ("append seek");
  }
  return result;
}

void
WylSecureDuckdbFileSystem::Read (duckdb::FileHandle &handle, void *buffer,
    int64_t bytes, duckdb::idx_t location)
{
  if (bytes < 0 || !bounded_handle (handle).ReadAt (buffer,
          static_cast<duckdb::idx_t> (bytes), location))
    io_reject ("positioned read");
}

void
WylSecureDuckdbFileSystem::Write (duckdb::FileHandle &handle, void *buffer,
    int64_t bytes, duckdb::idx_t location)
{
  if (bytes < 0 || !bounded_handle (handle).WriteAt (buffer,
          static_cast<duckdb::idx_t> (bytes), location))
    io_reject ("positioned write");
}

int64_t
WylSecureDuckdbFileSystem::Read (duckdb::FileHandle &handle, void *buffer,
    int64_t bytes)
{
  auto result = bounded_handle (handle).ReadSome (buffer, bytes);
  if (result < 0)
    io_reject ("read");
  return result;
}

int64_t
WylSecureDuckdbFileSystem::Write (duckdb::FileHandle &handle, void *buffer,
    int64_t bytes)
{
  auto result = bounded_handle (handle).WriteSome (buffer, bytes);
  if (result < 0)
    io_reject ("write");
  return result;
}

bool
WylSecureDuckdbFileSystem::Trim (duckdb::FileHandle &, duckdb::idx_t,
    duckdb::idx_t)
{
  return false;
}

int64_t
WylSecureDuckdbFileSystem::GetFileSize (duckdb::FileHandle &handle)
{
  auto size = bounded_handle (handle).Size ();
  if (size < 0)
    io_reject ("file size");
  return size;
}

duckdb::timestamp_t
WylSecureDuckdbFileSystem::GetLastModifiedTime (duckdb::FileHandle &handle)
{
  auto value = bounded_handle (handle).LastModifiedTime ();
  if (value == duckdb::timestamp_t::ninfinity ())
    io_reject ("last modified time");
  return value;
}

duckdb::string
WylSecureDuckdbFileSystem::GetVersionTag (duckdb::FileHandle &handle)
{
  auto &bounded = bounded_handle (handle);
  struct stat st;
  if (!bounded.Revalidate () || fstat (bounded.Fd (), &st) != 0
      || !bounded.Revalidate ())
    io_reject ("version tag");
  return std::to_string (static_cast<uint64_t> (st.st_dev)) + ":"
      + std::to_string (static_cast<uint64_t> (st.st_ino)) + ":"
      + std::to_string (static_cast<int64_t> (st.st_size));
}

duckdb::FileType
WylSecureDuckdbFileSystem::GetFileType (duckdb::FileHandle &handle)
{
  if (!bounded_handle (handle).Revalidate ())
    io_reject ("file type");
  return duckdb::FileType::FILE_TYPE_REGULAR;
}

duckdb::FileMetadata
WylSecureDuckdbFileSystem::Stats (duckdb::FileHandle &handle)
{
  duckdb::FileMetadata metadata;
  metadata.file_size = GetFileSize (handle);
  metadata.last_modification_time = GetLastModifiedTime (handle);
  metadata.file_type = GetFileType (handle);
  return metadata;
}

void
WylSecureDuckdbFileSystem::Truncate (duckdb::FileHandle &handle, int64_t size)
{
  if (!bounded_handle (handle).TruncateTo (size))
    io_reject ("truncate");
}

bool WylSecureDuckdbFileSystem::DirectoryExists (const duckdb::string &,
    duckdb::optional_ptr<duckdb::FileOpener>) { unsupported ("directories"); }
void WylSecureDuckdbFileSystem::CreateDirectory (const duckdb::string &,
    duckdb::optional_ptr<duckdb::FileOpener>) { unsupported ("directories"); }
void WylSecureDuckdbFileSystem::CreateDirectoriesRecursive (
    const duckdb::string &, duckdb::optional_ptr<duckdb::FileOpener>)
{ unsupported ("directories"); }
void WylSecureDuckdbFileSystem::RemoveDirectory (const duckdb::string &,
    duckdb::optional_ptr<duckdb::FileOpener>) { unsupported ("directories"); }
bool WylSecureDuckdbFileSystem::ListFiles (const duckdb::string &,
    const std::function<void (const duckdb::string &, bool)> &,
    duckdb::FileOpener *) { unsupported ("directory listing"); }

void
WylSecureDuckdbFileSystem::MoveFile (const duckdb::string &source,
    const duckdb::string &target,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  const auto source_artifact = logical_artifact_for (source);
  const auto target_artifact = logical_artifact_for (target);
  if (source_artifact.artifact == WYL_FACT_ARTIFACT_TEMP
      || target_artifact.artifact == WYL_FACT_ARTIFACT_TEMP)
    io_reject ("temporary rename is not provided by the namespace");
  if (source_artifact.artifact == WYL_FACT_ARTIFACT_MAIN
      || target_artifact.artifact == WYL_FACT_ARTIFACT_MAIN)
    io_reject ("renaming the held main binding is forbidden");
  require_ok (wyl_fact_artifact_namespace_rename (namespace_,
      source_artifact.artifact, target_artifact.artifact), "rename");
}

bool
WylSecureDuckdbFileSystem::FileExists (const duckdb::string &path,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  /* DuckDB v1.5.5 performs this exact allocator-sizing probe.  Returning
   * false denies the host path without turning it into filesystem authority. */
  if (path == "/proc/self/cgroup")
    return false;
  const auto logical = logical_artifact_for (path);
  int fd = -1;
  auto rc = logical.artifact == WYL_FACT_ARTIFACT_TEMP
      ? wyl_fact_artifact_namespace_open_temp (namespace_,
          logical.temp_token.c_str (), FALSE, FALSE, &fd)
      : wyl_fact_artifact_namespace_open_file (namespace_,
          logical.artifact, FALSE, FALSE, &fd);
  if (rc == WYRELOG_E_OK) {
    close (fd);
    return true;
  }
  if (is_missing (rc))
    return false;
  require_ok (rc, "exists");
}

bool
WylSecureDuckdbFileSystem::IsPipe (const duckdb::string &path,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  (void) logical_artifact_for (path);
  return false;
}

void
WylSecureDuckdbFileSystem::RemoveFile (const duckdb::string &path,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  const auto logical = logical_artifact_for (path);
  if (logical.artifact == WYL_FACT_ARTIFACT_TEMP)
    io_reject ("temporary removal is not provided by the namespace");
  if (logical.artifact == WYL_FACT_ARTIFACT_MAIN)
    io_reject ("removing the held main binding is forbidden");
  require_ok (wyl_fact_artifact_namespace_unlink (namespace_,
      logical.artifact), "remove");
  require_ok (wyl_fact_artifact_namespace_sync_directory (namespace_),
      "remove directory sync");
}

bool
WylSecureDuckdbFileSystem::TryRemoveFile (const duckdb::string &path,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  const auto logical = logical_artifact_for (path);
  if (logical.artifact == WYL_FACT_ARTIFACT_TEMP)
    io_reject ("temporary removal is not provided by the namespace");
  if (logical.artifact == WYL_FACT_ARTIFACT_MAIN)
    io_reject ("removing the held main binding is forbidden");
  auto rc = wyl_fact_artifact_namespace_unlink (namespace_,
      logical.artifact);
  if (rc == WYRELOG_E_OK)
  {
    require_ok (wyl_fact_artifact_namespace_sync_directory (namespace_),
        "try-remove directory sync");
    return true;
  }
  if (is_missing (rc))
    return false;
  require_ok (rc, "try remove");
}

void
WylSecureDuckdbFileSystem::RemoveFiles (
    const duckdb::vector<duckdb::string> &paths,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  for (const auto &path : paths)
    (void) TryRemoveFile (path, nullptr);
}

void
WylSecureDuckdbFileSystem::FileSync (duckdb::FileHandle &handle)
{
  if (!bounded_handle (handle).Sync ())
    io_reject ("file sync");
  require_ok (wyl_fact_artifact_namespace_sync_directory (namespace_),
      "directory sync");
}

duckdb::string WylSecureDuckdbFileSystem::GetHomeDirectory ()
{ unsupported ("home-directory discovery"); }
duckdb::string WylSecureDuckdbFileSystem::ExpandPath (
    const duckdb::string &path)
{
  (void) logical_artifact_for (path);
  return path;
}
duckdb::string WylSecureDuckdbFileSystem::PathSeparator (
    const duckdb::string &path)
{
  (void) logical_artifact_for (path);
  return "/";
}
bool WylSecureDuckdbFileSystem::IsPathAbsolute (const duckdb::string &)
{ return false; }
duckdb::vector<duckdb::OpenFileInfo> WylSecureDuckdbFileSystem::Glob (
    const duckdb::string &, duckdb::FileOpener *) { unsupported ("glob"); }
void WylSecureDuckdbFileSystem::RegisterSubSystem (
    duckdb::unique_ptr<duckdb::FileSystem>) { unsupported ("subsystems"); }
void WylSecureDuckdbFileSystem::RegisterSubSystem (
    duckdb::FileCompressionType, duckdb::unique_ptr<duckdb::FileSystem>)
{ unsupported ("compressed subsystems"); }
void WylSecureDuckdbFileSystem::UnregisterSubSystem (const duckdb::string &)
{ unsupported ("subsystems"); }
duckdb::unique_ptr<duckdb::FileSystem>
WylSecureDuckdbFileSystem::ExtractSubSystem (const duckdb::string &)
{ unsupported ("subsystems"); }
duckdb::vector<duckdb::string> WylSecureDuckdbFileSystem::ListSubSystems ()
{ return {}; }
bool WylSecureDuckdbFileSystem::CanHandleFile (const duckdb::string &path)
{
  try {
    (void) logical_artifact_for (path);
    return true;
  } catch (const duckdb::IOException &) {
    return false;
  }
}

void WylSecureDuckdbFileSystem::Seek (duckdb::FileHandle &handle,
    duckdb::idx_t location)
{
  if (!bounded_handle (handle).SeekTo (location))
    io_reject ("seek");
}
void WylSecureDuckdbFileSystem::Reset (duckdb::FileHandle &handle)
{ Seek (handle, 0); }
duckdb::idx_t WylSecureDuckdbFileSystem::SeekPosition (
    duckdb::FileHandle &handle)
{ return bounded_handle (handle).SeekPosition (); }
bool WylSecureDuckdbFileSystem::IsManuallySet () { return true; }
bool WylSecureDuckdbFileSystem::CanSeek () { return true; }
bool WylSecureDuckdbFileSystem::OnDiskFile (duckdb::FileHandle &handle)
{
  if (!bounded_handle (handle).Revalidate ())
    io_reject ("on-disk test");
  return true;
}
duckdb::unique_ptr<duckdb::FileHandle>
WylSecureDuckdbFileSystem::OpenCompressedFile (duckdb::QueryContext,
    duckdb::unique_ptr<duckdb::FileHandle>, bool)
{ unsupported ("compressed files"); }
bool WylSecureDuckdbFileSystem::IsLocalFileSystem () const { return false; }
std::string WylSecureDuckdbFileSystem::GetName () const
{ return "wyrelog-bounded-duckdb-filesystem"; }
void WylSecureDuckdbFileSystem::SetDisabledFileSystems (
    const duckdb::vector<duckdb::string> &) { unsupported ("subsystems"); }
bool WylSecureDuckdbFileSystem::SubSystemIsDisabled (const duckdb::string &)
{ return true; }
bool WylSecureDuckdbFileSystem::IsDisabledForPath (const duckdb::string &path)
{ return !CanHandleFile (path); }
duckdb::string WylSecureDuckdbFileSystem::CanonicalizePath (
    const duckdb::string &path, duckdb::optional_ptr<duckdb::FileOpener> opener)
{
  (void) opener;
  (void) logical_artifact_for (path);
  return path;
}

duckdb::unique_ptr<duckdb::FileHandle>
WylSecureDuckdbFileSystem::OpenFileExtended (const duckdb::OpenFileInfo &info,
    duckdb::FileOpenFlags flags,
    duckdb::optional_ptr<duckdb::FileOpener> opener)
{ return OpenFile (info.path, flags, opener); }
bool WylSecureDuckdbFileSystem::SupportsOpenFileExtended () const
{ return true; }
bool WylSecureDuckdbFileSystem::ListFilesExtended (const duckdb::string &,
    const std::function<void (duckdb::OpenFileInfo &)> &,
    duckdb::optional_ptr<duckdb::FileOpener>)
{ unsupported ("extended directory listing"); }
bool WylSecureDuckdbFileSystem::SupportsListFilesExtended () const
{ return true; }
duckdb::unique_ptr<duckdb::MultiFileList>
WylSecureDuckdbFileSystem::GlobFilesExtended (const duckdb::string &,
    const duckdb::FileGlobInput &,
    duckdb::optional_ptr<duckdb::FileOpener>)
{ unsupported ("extended glob"); }
bool WylSecureDuckdbFileSystem::SupportsGlobExtended () const
{ return true; }

duckdb::unique_ptr<duckdb::FileSystem>
wyl_secure_duckdb_filesystem_new (WylFactArtifactNamespace *namespace_)
{
  return duckdb::make_uniq<WylSecureDuckdbFileSystem> (namespace_);
}
