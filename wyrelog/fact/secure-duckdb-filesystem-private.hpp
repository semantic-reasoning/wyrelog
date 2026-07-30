/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "fact/graph-artifact-namespace-private.h"
#include "fact/secure-duckdb-file-handle-private.hpp"

enum WylSecureDuckdbFilesystemTestFault : guint
{
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_NONE = 0,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_HANDLE_ALLOCATION = 1U << 0,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_TEMP_REGISTRATION = 1U << 1,
  WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION = 1U << 2,
};

void wyl_secure_duckdb_filesystem_set_test_faults (guint);
bool wyl_secure_duckdb_filesystem_take_test_fault (guint);

class WylSecureDuckdbAuthorityException final: public
duckdb::IOException
{
public:
  WylSecureDuckdbAuthorityException (wyrelog_error_t error,
      const duckdb::string & message)
    :
    duckdb::IOException (message),
    error (error)
  {
  }

  wyrelog_error_t
      error;
};

/* Production DuckDB filesystem backed only by opaque held authorities.
 * Every accepted string is a closed logical spelling, never a host path. */
class
WylSecureDuckdbFileSystem
final:
public
duckdb::FileSystem
{
public:
  WylSecureDuckdbFileSystem (WylFactArtifactNamespace *, bool read_only);
  ~
  WylSecureDuckdbFileSystem ()
  override;

  const
  duckdb::string &
  TemporaryDirectory () const
  {
    return
      temporary_directory_;
  }
  size_t
  TempChildrenCreatedForTest () const
  {
    return
      temp_children_created_;
  }
  std::shared_ptr<WylSecureDuckdbHealth>
  SharedHealth () const
  {
    return health_;
  }

  duckdb::unique_ptr <
  duckdb::FileHandle >
  OpenFile (const duckdb::string &,
      duckdb::FileOpenFlags,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  Read (duckdb::FileHandle &, void *, int64_t, duckdb::idx_t)
  override;
  void
  Write (duckdb::FileHandle &, void *, int64_t, duckdb::idx_t)
  override;
  int64_t
  Read (duckdb::FileHandle &, void *, int64_t)
  override;
  int64_t
  Write (duckdb::FileHandle &, void *, int64_t)
  override;
  bool
  Trim (duckdb::FileHandle &, duckdb::idx_t, duckdb::idx_t)
  override;
  int64_t
  GetFileSize (duckdb::FileHandle &)
  override;
  duckdb::timestamp_t
  GetLastModifiedTime (duckdb::FileHandle &)
  override;
  duckdb::string
  GetVersionTag (duckdb::FileHandle &)
  override;
  duckdb::FileType
  GetFileType (duckdb::FileHandle &)
  override;
  duckdb::FileMetadata
  Stats (duckdb::FileHandle &)
  override;
  void
  Truncate (duckdb::FileHandle &, int64_t)
  override;

  bool
  DirectoryExists (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  CreateDirectory (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  CreateDirectoriesRecursive (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  RemoveDirectory (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  bool
  ListFiles (const duckdb::string &,
      const std::function < void (const duckdb::string &, bool) > &,
      duckdb::FileOpener * = nullptr) override;
  void
  MoveFile (const duckdb::string &, const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  bool
  FileExists (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  bool
  IsPipe (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  RemoveFile (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  bool
  TryRemoveFile (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  RemoveFiles (const duckdb::vector < duckdb::string > &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;
  void
  FileSync (duckdb::FileHandle &)
  override;

  duckdb::string
  GetHomeDirectory ()
  override;
  duckdb::string
  ExpandPath (const duckdb::string &)
  override;
  duckdb::string
  PathSeparator (const duckdb::string &)
  override;
  bool
  IsPathAbsolute (const duckdb::string &)
  override;
  duckdb::vector <
  duckdb::OpenFileInfo >
  Glob (const duckdb::string &, duckdb::FileOpener * = nullptr) override;
  void
  RegisterSubSystem (duckdb::unique_ptr < duckdb::FileSystem >)
  override;
  void
  RegisterSubSystem (duckdb::FileCompressionType,
      duckdb::unique_ptr < duckdb::FileSystem >)
  override;
  void
  UnregisterSubSystem (const duckdb::string &)
  override;
  duckdb::unique_ptr <
  duckdb::FileSystem >
  ExtractSubSystem (const duckdb::string &)
  override;
  duckdb::vector <
  duckdb::string >
  ListSubSystems ()
  override;
  bool
  CanHandleFile (const duckdb::string &)
  override;
  void
  Seek (duckdb::FileHandle &, duckdb::idx_t)
  override;
  void
  Reset (duckdb::FileHandle &)
  override;
  duckdb::idx_t
  SeekPosition (duckdb::FileHandle &)
  override;
  bool
  IsManuallySet ()
  override;
  bool
  CanSeek ()
  override;
  bool
  OnDiskFile (duckdb::FileHandle &)
  override;
  duckdb::unique_ptr <
  duckdb::FileHandle >
  OpenCompressedFile (duckdb::QueryContext,
      duckdb::unique_ptr < duckdb::FileHandle >, bool)
  override;
  bool
  IsLocalFileSystem () const
  override;
  std::string
  GetName () const
  override;
  void
  SetDisabledFileSystems (const duckdb::vector < duckdb::string > &)
  override;
  bool
  SubSystemIsDisabled (const duckdb::string &)
  override;
  bool
  IsDisabledForPath (const duckdb::string &)
  override;
  duckdb::string
  CanonicalizePath (const duckdb::string &,
      duckdb::optional_ptr < duckdb::FileOpener > = nullptr) override;

protected:
  duckdb::unique_ptr <
  duckdb::FileHandle >
  OpenFileExtended (const duckdb::OpenFileInfo &, duckdb::FileOpenFlags,
      duckdb::optional_ptr < duckdb::FileOpener >)
  override;
  bool
  SupportsOpenFileExtended () const
  override;
  bool
  ListFilesExtended (const duckdb::string &,
      const std::function < void (duckdb::OpenFileInfo &) > &,
      duckdb::optional_ptr < duckdb::FileOpener >)
  override;
  bool
  SupportsListFilesExtended () const
  override;
  duckdb::unique_ptr <
  duckdb::MultiFileList >
  GlobFilesExtended (const duckdb::string &, const duckdb::FileGlobInput &,
      duckdb::optional_ptr < duckdb::FileOpener >)
  override;
  bool
  SupportsGlobExtended () const
  override;

private:
  friend class WylSecureDuckdbFileHandle;

  struct SidecarBindingRecord
  {
    WylFactArtifactName artifact;
    WylFactArtifactSidecarBinding *binding;
  };

  void
  RequireLease (const char *) const;
  void
  RequireHealthy (const char *) const;
  void
  RequireOk (wyrelog_error_t, const char *) const;
  [[noreturn]] void
  PoisonAndReject (wyrelog_error_t, const char *) const;
  void
  RegisterSidecarHandle (WylSecureDuckdbFileHandle *);
  void
  UnregisterSidecarHandle (WylSecureDuckdbFileHandle *);
  void
  AdoptClosedSidecarBinding (WylFactArtifactName,
      WylFactArtifactSidecarBinding *);
  WylFactArtifactSidecarBinding *
  TakeSidecarBinding (WylFactArtifactName);
  WylFactArtifactSidecarBinding *
  BindAndCloseExistingSidecar (WylFactArtifactName);
  void
  FreeSidecarBindings ();
  WylFactDuckdbTempChild *
  FindTempChild (const duckdb::string &) const;
  void
  RollbackTempChild (WylFactDuckdbTempChild *,
      WylSecureDuckdbPendingBinding &, wyrelog_error_t) noexcept;
  void
  RetireTempChild (const duckdb::string &);

  WylFactArtifactMutationLease *
      lease_;
  WylFactDuckdbTempRoot *
      temp_root_;
  bool
      read_only_;
  std::shared_ptr<WylSecureDuckdbHealth>
  health_;
  duckdb::string
      temporary_directory_;
  std::unordered_map <
  std::string,
  WylFactDuckdbTempChild * >
  temp_children_;
  size_t
      temp_children_created_ = 0;
  std::vector<SidecarBindingRecord>
  sidecar_bindings_;
  std::vector<WylSecureDuckdbFileHandle *>
  live_sidecar_handles_;
  mutable
  std::mutex
      mutex_;
  mutable
  std::mutex
      registry_mutex_;
};

duckdb::unique_ptr < WylSecureDuckdbFileSystem >
wyl_secure_duckdb_filesystem_new (WylFactArtifactNamespace *, bool read_only);
