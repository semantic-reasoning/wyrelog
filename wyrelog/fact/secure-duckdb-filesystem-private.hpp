/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <mutex>

#include "fact/graph-artifact-namespace-private.h"

/* Production DuckDB filesystem backed only by a held graph-artifact
 * namespace.  The logical paths accepted here are labels, never host paths.
 * The caller retains the namespace and must keep it alive for this object. */
class WylSecureDuckdbFileSystem final : public duckdb::FileSystem
{
public:
  explicit WylSecureDuckdbFileSystem (WylFactArtifactNamespace *);
  ~WylSecureDuckdbFileSystem () override;

  duckdb::unique_ptr<duckdb::FileHandle> OpenFile (const duckdb::string &,
      duckdb::FileOpenFlags,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void Read (duckdb::FileHandle &, void *, int64_t, duckdb::idx_t) override;
  void Write (duckdb::FileHandle &, void *, int64_t, duckdb::idx_t) override;
  int64_t Read (duckdb::FileHandle &, void *, int64_t) override;
  int64_t Write (duckdb::FileHandle &, void *, int64_t) override;
  bool Trim (duckdb::FileHandle &, duckdb::idx_t, duckdb::idx_t) override;
  int64_t GetFileSize (duckdb::FileHandle &) override;
  duckdb::timestamp_t GetLastModifiedTime (duckdb::FileHandle &) override;
  duckdb::string GetVersionTag (duckdb::FileHandle &) override;
  duckdb::FileType GetFileType (duckdb::FileHandle &) override;
  duckdb::FileMetadata Stats (duckdb::FileHandle &) override;
  void Truncate (duckdb::FileHandle &, int64_t) override;

  bool DirectoryExists (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void CreateDirectory (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void CreateDirectoriesRecursive (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void RemoveDirectory (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  bool ListFiles (const duckdb::string &,
      const std::function<void (const duckdb::string &, bool)> &,
      duckdb::FileOpener * = nullptr) override;
  void MoveFile (const duckdb::string &, const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  bool FileExists (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  bool IsPipe (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void RemoveFile (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  bool TryRemoveFile (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void RemoveFiles (const duckdb::vector<duckdb::string> &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;
  void FileSync (duckdb::FileHandle &) override;

  duckdb::string GetHomeDirectory () override;
  duckdb::string ExpandPath (const duckdb::string &) override;
  duckdb::string PathSeparator (const duckdb::string &) override;
  bool IsPathAbsolute (const duckdb::string &) override;
  duckdb::vector<duckdb::OpenFileInfo> Glob (const duckdb::string &,
      duckdb::FileOpener * = nullptr) override;
  void RegisterSubSystem (duckdb::unique_ptr<duckdb::FileSystem>) override;
  void RegisterSubSystem (duckdb::FileCompressionType,
      duckdb::unique_ptr<duckdb::FileSystem>) override;
  void UnregisterSubSystem (const duckdb::string &) override;
  duckdb::unique_ptr<duckdb::FileSystem> ExtractSubSystem (
      const duckdb::string &) override;
  duckdb::vector<duckdb::string> ListSubSystems () override;
  bool CanHandleFile (const duckdb::string &) override;
  void Seek (duckdb::FileHandle &, duckdb::idx_t) override;
  void Reset (duckdb::FileHandle &) override;
  duckdb::idx_t SeekPosition (duckdb::FileHandle &) override;
  bool IsManuallySet () override;
  bool CanSeek () override;
  bool OnDiskFile (duckdb::FileHandle &) override;
  duckdb::unique_ptr<duckdb::FileHandle> OpenCompressedFile (
      duckdb::QueryContext, duckdb::unique_ptr<duckdb::FileHandle>,
      bool) override;
  bool IsLocalFileSystem () const override;
  std::string GetName () const override;
  void SetDisabledFileSystems (const duckdb::vector<duckdb::string> &) override;
  bool SubSystemIsDisabled (const duckdb::string &) override;
  bool IsDisabledForPath (const duckdb::string &) override;
  duckdb::string CanonicalizePath (const duckdb::string &,
      duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override;

protected:
  duckdb::unique_ptr<duckdb::FileHandle> OpenFileExtended (
      const duckdb::OpenFileInfo &, duckdb::FileOpenFlags,
      duckdb::optional_ptr<duckdb::FileOpener>) override;
  bool SupportsOpenFileExtended () const override;
  bool ListFilesExtended (const duckdb::string &,
      const std::function<void (duckdb::OpenFileInfo &)> &,
      duckdb::optional_ptr<duckdb::FileOpener>) override;
  bool SupportsListFilesExtended () const override;
  duckdb::unique_ptr<duckdb::MultiFileList> GlobFilesExtended (
      const duckdb::string &, const duckdb::FileGlobInput &,
      duckdb::optional_ptr<duckdb::FileOpener>) override;
  bool SupportsGlobExtended () const override;

private:
  int AcquireLockDescriptor (duckdb::FileLockType);

  WylFactArtifactNamespace *namespace_;
  bool main_bound_;
  std::mutex open_mutex_;
  int lock_fd_;
  duckdb::FileLockType lock_type_;
};

duckdb::unique_ptr<duckdb::FileSystem>
wyl_secure_duckdb_filesystem_new (WylFactArtifactNamespace *);
