/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-bridge-private.h"
#include "fact/secure-duckdb-filesystem-contract-private.h"
#include "fact/secure-duckdb-filesystem-private.hpp"
#include "fact/store-identity-private.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
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
  bool preconstruction_provenance_failure = false;
};

namespace {

  constexpr duckdb::idx_t restore_stage_read_chunk = 64 * 1024;
  constexpr char restore_stage_main_name[] = "facts.duckdb";
  constexpr char restore_stage_wal_name[] = "facts.duckdb.wal";
  constexpr char restore_stage_wal_checkpoint_name[] =
      "facts.duckdb.wal.checkpoint";
  constexpr char restore_stage_wal_recovery_name[] =
      "facts.duckdb.wal.recovery";
  constexpr char restore_stage_virtual_secret_directory[] =
      "facts.duckdb/.duckdb/stored_secrets";
  constexpr char restore_stage_virtual_secret_parent[] =
      "facts.duckdb/.duckdb";

  bool
  restore_stage_path_allowed_for_configuration (const duckdb::string &path)
  {
    return path == restore_stage_main_name || path == restore_stage_wal_name
           || path == restore_stage_wal_checkpoint_name
           || path == restore_stage_wal_recovery_name
           || path == restore_stage_virtual_secret_parent
           || path == restore_stage_virtual_secret_directory;
  }

  std::mutex restore_stage_test_mutex;
  WylSecureDuckdbRestoreStageTestHook restore_stage_test_hook = nullptr;
  gpointer restore_stage_test_data = nullptr;

  void
  restore_stage_test_fire (WylSecureDuckdbRestoreStageTestPoint point)
  {
    WylSecureDuckdbRestoreStageTestHook hook = nullptr;
    gpointer data = nullptr;
    {
      std::lock_guard<std::mutex> lock (restore_stage_test_mutex);
      hook = restore_stage_test_hook;
      data = restore_stage_test_data;
    }
    if (hook != nullptr)
      hook (point, data);
  }

  [[noreturn]] void
  restore_stage_io_reject (const char *operation)
  {
    throw duckdb::IOException ("offline restore stage filesystem rejected %s",
        operation);
  }

  class RestoreStageReaderFileSystem;

  class RestoreStageReaderFileHandle final: public duckdb::FileHandle
  {
public:
    RestoreStageReaderFileHandle (duckdb::FileSystem &file_system,
        const duckdb::string &path, duckdb::FileOpenFlags flags)
      : duckdb::FileHandle (file_system, path, flags)
    {
    }

    void Close () override
    {
      closed_.store (true);
    }

    bool Closed () const
    {
      return closed_.load ();
    }

    int64_t Offset () const
    {
      return offset_;
    }

    void SetOffset (int64_t offset)
    {
      offset_ = offset;
    }

private:
    std::atomic<bool> closed_ { false };
    int64_t offset_ = 0;
  };

  class RestoreStageReaderFileSystem final: public duckdb::FileSystem
  {
public:
    RestoreStageReaderFileSystem (WylFactOfflineRestoreStageReader *reader,
        std::shared_ptr<WylSecureDuckdbHealth> health)
      : reader_ (reader), health_ (std::move (health))
    {
      if (reader_ == nullptr || health_ == nullptr)
        throw duckdb::IOException ("offline restore stage reader missing");
    }

    duckdb::unique_ptr<duckdb::FileHandle>
    OpenFile (const duckdb::string &path, duckdb::FileOpenFlags flags,
        duckdb::optional_ptr<duckdb::FileOpener> opener = nullptr) override
    {
      (void) opener;
      RequireHealthy ("open");
      if (path == restore_stage_wal_name && flags.ReturnNullIfNotExists ())
        return nullptr;
      if (path != restore_stage_main_name || !flags.OpenForReading ()
          || flags.OpenForWriting () || flags.OpenForAppending ()
          || flags.CreateFileIfNotExists () || flags.OverwriteExistingFile ()
          || flags.ExclusiveCreate () || flags.ReturnNullIfExists ()
          || flags.DirectIO () || flags.CreatePrivateFile ()
          || flags.EnableExtensionInstall ()
          || flags.Lock () == duckdb::FileLockType::WRITE_LOCK) {
        Reject ("open path or flags");
      }
      /* DuckDB marks read-only database handles as parallel/multi-client.
       * Every reader callback is serialized below, and writes remain denied. */
      return duckdb::make_uniq<RestoreStageReaderFileHandle> (*this, path,
             flags);
    }

    void Read (duckdb::FileHandle &handle, void *buffer, int64_t bytes,
        duckdb::idx_t location) override
    {
      auto &stage_handle = Handle (handle);
      if (bytes == 0)
        return;
      if (buffer == nullptr || bytes < 0
          || location > static_cast<duckdb::idx_t> (G_MAXINT64)
          || static_cast<uint64_t> (bytes)
          > static_cast<uint64_t> (G_MAXINT64) -location)
        Reject ("read bounds");
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      ReadExact (static_cast<uint8_t *> (buffer),
          static_cast<uint64_t> (location), static_cast<uint64_t> (bytes));
      (void) stage_handle;
    }

    int64_t Read (duckdb::FileHandle &handle, void *buffer,
        int64_t bytes) override
    {
      if (bytes == 0)
        return 0;
      if (buffer == nullptr || bytes < 0)
        Reject ("sequential read bounds");
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      auto &stage_handle = Handle (handle);
      const int64_t count = ReadSome (static_cast<uint8_t *> (buffer), bytes,
              stage_handle.Offset ());
      stage_handle.SetOffset (stage_handle.Offset () + count);
      return count;
    }

    bool Trim (duckdb::FileHandle &, duckdb::idx_t,
        duckdb::idx_t) override
    {
      Reject ("trim");
    }

    int64_t GetFileSize (duckdb::FileHandle &handle) override
    {
      (void) Handle (handle);
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      return Size ();
    }

    duckdb::timestamp_t GetLastModifiedTime (duckdb::FileHandle &handle)
    override
    {
      (void) Handle (handle);
      RequireHealthy ("modified time");
      return duckdb::timestamp_t::ninfinity ();
    }

    duckdb::string GetVersionTag (duckdb::FileHandle &handle) override
    {
      (void) Handle (handle);
      RequireHealthy ("version tag");
      return "offline-restore-stage";
    }

    duckdb::FileType GetFileType (duckdb::FileHandle &handle) override
    {
      (void) Handle (handle);
      RequireHealthy ("file type");
      return duckdb::FileType::FILE_TYPE_REGULAR;
    }

    duckdb::FileMetadata Stats (duckdb::FileHandle &handle) override
    {
      duckdb::FileMetadata result;
      result.file_size = GetFileSize (handle);
      result.last_modification_time = GetLastModifiedTime (handle);
      result.file_type = GetFileType (handle);
      return result;
    }

    void Truncate (duckdb::FileHandle &, int64_t) override
    {
      Reject ("truncate");
    }

    bool DirectoryExists (const duckdb::string &path,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      if (path == restore_stage_virtual_secret_parent
          || path == restore_stage_virtual_secret_directory) {
        RequireHealthy ("virtual secret directory check");
        return false;
      }
      Reject ("directory existence");
    }

    void CreateDirectory (const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("directory creation");
    }

    void CreateDirectoriesRecursive (const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("recursive directory creation");
    }

    void RemoveDirectory (const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("directory removal");
    }

    bool ListFiles (const duckdb::string &,
        const std::function<void(const duckdb::string &, bool)> &,
        duckdb::FileOpener * = nullptr) override
    {
      Reject ("directory listing");
    }

    void MoveFile (const duckdb::string &, const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("rename");
    }

    bool FileExists (const duckdb::string &path,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      RequireHealthy ("existence check");
      if (path == restore_stage_main_name)
        return true;
      if (path == restore_stage_wal_name)
        return false;
      /* DuckDB probes this host resource file to estimate memory limits.
       * Do not expose the host filesystem: report it absent so DuckDB uses
       * its conservative fallback, and continue rejecting every other path. */
      if (path == "/proc/self/cgroup")
        return false;
      Reject ("existence path");
    }

    bool IsPipe (const duckdb::string &path,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      if (path != restore_stage_main_name)
        Reject ("pipe path");
      RequireHealthy ("pipe check");
      return false;
    }

    void RemoveFile (const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("file removal");
    }

    bool TryRemoveFile (const duckdb::string &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("conditional file removal");
    }

    void RemoveFiles (const duckdb::vector<duckdb::string> &,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      Reject ("multiple file removal");
    }

    void FileSync (duckdb::FileHandle &) override
    {
      Reject ("sync");
    }

    duckdb::string GetHomeDirectory () override
    {
      RequireHealthy ("home directory");
      /* SecretManager requires a home string during initialization. Keep its
       * derived path inside the database's virtual namespace; never map it to
       * the host home directory. */
      return restore_stage_main_name;
    }

    duckdb::string ExpandPath (const duckdb::string &path) override
    {
      if (!restore_stage_path_allowed_for_configuration (path))
        Reject ("path expansion");
      RequireHealthy ("path expansion");
      return path;
    }

    duckdb::string PathSeparator (const duckdb::string &path) override
    {
      if (!restore_stage_path_allowed_for_configuration (path))
        Reject ("path separator");
      RequireHealthy ("path separator");
      return "/";
    }

    bool IsPathAbsolute (const duckdb::string &path) override
    {
      if (!restore_stage_path_allowed_for_configuration (path))
        Reject ("absolute path check");
      RequireHealthy ("absolute path check");
      return false;
    }

    duckdb::vector<duckdb::OpenFileInfo> Glob (const duckdb::string &,
        duckdb::FileOpener * = nullptr) override
    {
      Reject ("glob");
    }

    void RegisterSubSystem (duckdb::unique_ptr<duckdb::FileSystem>) override
    {
      Reject ("subsystem registration");
    }

    void RegisterSubSystem (duckdb::FileCompressionType,
        duckdb::unique_ptr<duckdb::FileSystem>) override
    {
      Reject ("compression subsystem registration");
    }

    void UnregisterSubSystem (const duckdb::string &) override
    {
      Reject ("subsystem removal");
    }

    duckdb::unique_ptr<duckdb::FileSystem> ExtractSubSystem
      (const duckdb::string &) override
    {
      Reject ("subsystem extraction");
    }

    duckdb::vector<duckdb::string> ListSubSystems () override
    {
      return {};
    }

    bool CanHandleFile (const duckdb::string &) override
    {
      RequireHealthy ("file handler check");
      return true;
    }

    void Seek (duckdb::FileHandle &handle, duckdb::idx_t location) override
    {
      if (location > static_cast<duckdb::idx_t> (G_MAXINT64))
        Reject ("seek bounds");
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      auto &stage_handle = Handle (handle);
      const int64_t size = Size ();
      if (static_cast<int64_t> (location) > size)
        Reject ("seek past end");
      stage_handle.SetOffset (static_cast<int64_t> (location));
    }

    void Reset (duckdb::FileHandle &handle) override
    {
      Seek (handle, 0);
    }

    duckdb::idx_t SeekPosition (duckdb::FileHandle &handle) override
    {
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      return static_cast<duckdb::idx_t> (Handle (handle).Offset ());
    }

    bool IsManuallySet () override
    {
      return true;
    }

    bool CanSeek () override
    {
      return true;
    }

    bool OnDiskFile (duckdb::FileHandle &handle) override
    {
      (void) Handle (handle);
      RequireHealthy ("on-disk query");
      return false;
    }

    duckdb::unique_ptr<duckdb::FileHandle> OpenCompressedFile
      (duckdb::QueryContext, duckdb::unique_ptr<duckdb::FileHandle>, bool)
    override
    {
      Reject ("compressed file");
    }

    bool IsLocalFileSystem () const override
    {
      /* Claim all path spellings so DuckDB cannot fall back to host I/O. */
      return true;
    }

    std::string GetName () const override
    {
      return "wyrelog-offline-restore-stage-reader";
    }

    void SetDisabledFileSystems (const duckdb::vector<duckdb::string> &)
    override
    {
    }

    bool SubSystemIsDisabled (const duckdb::string &) override
    {
      return true;
    }

    bool IsDisabledForPath (const duckdb::string &) override
    {
      return false;
    }

    duckdb::string CanonicalizePath (const duckdb::string &path,
        duckdb::optional_ptr<duckdb::FileOpener> = nullptr) override
    {
      if (!restore_stage_path_allowed_for_configuration (path))
        Reject ("path canonicalization");
      RequireHealthy ("path canonicalization");
      return path;
    }

protected:
    duckdb::unique_ptr<duckdb::FileHandle> OpenFileExtended
      (const duckdb::OpenFileInfo &info, duckdb::FileOpenFlags flags,
        duckdb::optional_ptr<duckdb::FileOpener> opener) override
    {
      return OpenFile (info.path, flags, opener);
    }

    bool SupportsOpenFileExtended () const override
    {
      return true;
    }

    bool ListFilesExtended (const duckdb::string &,
        const std::function<void(duckdb::OpenFileInfo &)> &,
        duckdb::optional_ptr<duckdb::FileOpener>) override
    {
      Reject ("extended directory listing");
    }

    bool SupportsListFilesExtended () const override
    {
      return false;
    }

    duckdb::unique_ptr<duckdb::MultiFileList> GlobFilesExtended
      (const duckdb::string &, const duckdb::FileGlobInput &,
        duckdb::optional_ptr<duckdb::FileOpener>) override
    {
      Reject ("extended glob");
    }

    bool SupportsGlobExtended () const override
    {
      return false;
    }

private:
    RestoreStageReaderFileHandle &Handle (duckdb::FileHandle &handle)
    {
      if (&handle.file_system != this)
        Reject ("foreign file handle");
      auto &stage_handle = handle.Cast<RestoreStageReaderFileHandle> ();
      if (stage_handle.Closed ())
        Reject ("closed file handle");
      return stage_handle;
    }

    void RequireHealthy (const char *operation)
    {
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      const wyrelog_error_t health = health_->Status ();
      if (health != WYRELOG_E_OK)
        throw WylSecureDuckdbAuthorityException (health,
            duckdb::StringUtil::Format ("restore-stage %s after failure",
            operation));
      const wyrelog_error_t rc =
          wyl_fact_offline_restore_stage_reader_revalidate (reader_);
      if (rc != WYRELOG_E_OK) {
        health_->Poison (rc);
        throw WylSecureDuckdbAuthorityException (rc,
            duckdb::StringUtil::Format ("restore-stage %s authority",
            operation));
      }
    }

    [[noreturn]] void Reject (const char *operation)
    {
      health_->Poison (WYRELOG_E_POLICY);
      restore_stage_io_reject (operation);
    }

    int64_t Size ()
    {
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      RequireHealthy ("size");
      guint64 size = 0;
      const wyrelog_error_t rc =
          wyl_fact_offline_restore_stage_reader_get_size (reader_, &size);
      if (rc != WYRELOG_E_OK || size > static_cast<guint64> (G_MAXINT64)) {
        const wyrelog_error_t error = rc == WYRELOG_E_OK
            ? WYRELOG_E_POLICY : rc;
        health_->Poison (error);
        throw WylSecureDuckdbAuthorityException (error,
            "restore-stage size unavailable");
      }
      return static_cast<int64_t> (size);
    }

    void ReadExact (uint8_t *buffer, uint64_t offset, uint64_t bytes)
    {
      std::lock_guard<std::recursive_mutex> lock (reader_mutex_);
      if (!first_read_hook_fired_) {
        first_read_hook_fired_ = true;
        restore_stage_test_fire
          (WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_BEFORE_FIRST_READ);
      }
      uint64_t done = 0;
      while (done < bytes) {
        const gsize request = static_cast<gsize> (std::min<uint64_t> (
              restore_stage_read_chunk, bytes - done));
        gsize actual = 0;
        const wyrelog_error_t rc =
            wyl_fact_offline_restore_stage_reader_read_at (reader_,
                offset + done, buffer + done, request, &actual);
        if (rc != WYRELOG_E_OK || actual != request || actual == 0) {
          const wyrelog_error_t error = rc == WYRELOG_E_OK
              ? WYRELOG_E_IO : rc;
          health_->Poison (error);
          throw WylSecureDuckdbAuthorityException (error,
              "restore-stage bounded read failed");
        }
        done += actual;
      }
    }

    int64_t ReadSome (uint8_t *buffer, int64_t requested, int64_t offset)
    {
      if (requested == 0)
        return 0;
      const int64_t size = Size ();
      if (offset < 0 || offset > size)
        Reject ("read offset");
      const uint64_t remaining = static_cast<uint64_t> (size - offset);
      const uint64_t bytes = std::min<uint64_t> (
        static_cast<uint64_t> (requested), remaining);
      ReadExact (buffer, static_cast<uint64_t> (offset), bytes);
      return static_cast<int64_t> (bytes);
    }

    WylFactOfflineRestoreStageReader *reader_;
    std::shared_ptr<WylSecureDuckdbHealth> health_;
    std::recursive_mutex reader_mutex_;
    bool first_read_hook_fired_ = false;
  };

  guint64
  test_restore_stage_filesystem_contract
    (WylFactOfflineRestoreStageReader *reader)
  {
    guint64 verified = 0;
    auto probe = [reader] (const std::function<void
        (RestoreStageReaderFileSystem &)> &operation) {
      auto health = std::make_shared<WylSecureDuckdbHealth> ();
      RestoreStageReaderFileSystem filesystem (reader, health);
      try {
        operation (filesystem);
      } catch (...)
      {
        return health->Status () == WYRELOG_E_POLICY;
      }
      return false;
    };

    auto health = std::make_shared<WylSecureDuckdbHealth> ();
    RestoreStageReaderFileSystem filesystem (reader, health);
    if (!filesystem.FileExists ("/proc/self/cgroup"))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CGROUP_HIDDEN;
    if (!filesystem.DirectoryExists (restore_stage_virtual_secret_parent)
        && !filesystem.DirectoryExists
          (restore_stage_virtual_secret_directory))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_SECRET_PATHS_VIRTUAL;
    try {
      auto dispatch_health = std::make_shared<WylSecureDuckdbHealth> ();
      duckdb::DBConfig config;
      config.options.load_extensions = false;
      config.options.use_temporary_directory = false;
      config.options.maximum_threads = 1;
      config.options.checkpoint_on_shutdown = false;
      config.file_system = duckdb::make_uniq<RestoreStageReaderFileSystem>
          (reader, dispatch_health);
      duckdb::DuckDB database (nullptr, &config);
      auto &local = duckdb::FileSystem::GetLocal (*database.instance);
      try {
        (void) local.FileExists ("/etc/passwd");
      } catch (...)
      {
        if (dispatch_health->Status () == WYRELOG_E_POLICY) {
          verified |=
              WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_DISPATCHED;
          verified |=
              WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_HOST_PATH_REJECTED;
        }
      }
    } catch (...)
    {
    }
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      auto handle = fs.OpenFile ("facts.duckdb/../etc/passwd",
      duckdb::FileOpenFlags::FILE_FLAGS_READ);
      (void) handle;
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_ALIAS_REJECTED;
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      auto handle = fs.OpenFile (restore_stage_main_name,
      duckdb::FileOpenFlags (duckdb::FileOpenFlags::FILE_FLAGS_READ
      | duckdb::FileOpenFlags::FILE_FLAGS_WRITE));
      (void) handle;
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_WRITE_REJECTED;
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      auto handle = fs.OpenFile (restore_stage_main_name,
      duckdb::FileOpenFlags (duckdb::FileOpenFlags::FILE_FLAGS_READ
      | duckdb::FileOpenFlags::FILE_FLAGS_APPEND));
      (void) handle;
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_APPEND_REJECTED;
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      auto handle = fs.OpenFile (restore_stage_main_name,
      duckdb::FileOpenFlags (duckdb::FileOpenFlags::FILE_FLAGS_READ
      | duckdb::FileOpenFlags::FILE_FLAGS_FILE_CREATE));
      (void) handle;
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CREATE_REJECTED;
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      auto handle = fs.OpenFile (restore_stage_main_name,
      duckdb::FileOpenFlags (duckdb::FileOpenFlags::FILE_FLAGS_READ
      | duckdb::FileOpenFlags::FILE_FLAGS_DIRECT_IO));
      (void) handle;
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_DIRECT_IO_REJECTED;
    if (probe ([] (RestoreStageReaderFileSystem &fs) {
      fs.MoveFile (restore_stage_main_name, "facts.duckdb.copy");
    }) && probe ([] (RestoreStageReaderFileSystem &fs) {
      fs.RemoveFile (restore_stage_main_name);
    }) && probe ([] (RestoreStageReaderFileSystem &fs) {
      (void) fs.Glob ("*");
    }))
      verified |= WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_MUTATION_REJECTED;

    try {
      const duckdb::idx_t flags = duckdb::FileOpenFlags::FILE_FLAGS_READ
          | duckdb::FileOpenFlags::FILE_FLAGS_NULL_IF_NOT_EXISTS
          | duckdb::FileOpenFlags::FILE_FLAGS_PARALLEL_ACCESS
          | duckdb::FileOpenFlags::FILE_FLAGS_MULTI_CLIENT_ACCESS;
      auto handle = filesystem.OpenFile (restore_stage_main_name,
              duckdb::FileOpenFlags (flags));
      std::atomic<bool> read_ok { true };
      int64_t counts[2] = { 0, 0 };
      auto read = [&] (size_t index) {
        uint8_t bytes[4096];
        try {
          counts[index] = filesystem.Read (*handle, bytes, sizeof bytes);
        } catch (...)
        {
          read_ok.store (false);
        }
      };
      std::thread first (read, 0);
      std::thread second (read, 1);
      first.join ();
      second.join ();
      if (read_ok.load () && counts[0] == 4096 && counts[1] == 4096
          && filesystem.SeekPosition (*handle) == 8192) {
        filesystem.Seek (*handle, 0);
        if (filesystem.SeekPosition (*handle) == 0)
          verified |=
              WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_PARALLEL_READ_ALLOWED;
      }
      handle->Close ();
      try {
        (void) filesystem.SeekPosition (*handle);
      } catch (...)
      {
        if (health->Status () == WYRELOG_E_POLICY)
          verified |=
              WYL_SECURE_DUCKDB_RESTORE_STAGE_FS_TEST_CLOSED_HANDLE_REJECTED;
      }
    } catch (...)
    {
    }
    return verified;
  }

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
  wyrelog_error_t pinned_pair_test_authority_error = WYRELOG_E_OK;
  wyrelog_error_t pinned_pair_test_finalize_error = WYRELOG_E_OK;
  wyrelog_error_t pinned_pair_test_r5_error = WYRELOG_E_OK;

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
    wyrelog_error_t authority_error = WYRELOG_E_OK;
    wyrelog_error_t finalize_error = WYRELOG_E_OK;
    wyrelog_error_t r5_error = WYRELOG_E_OK;

    void
    FirePreflight (WylFactStorePairPreflightForTest seam) const
    {
      if (preflight_hook != nullptr)
        preflight_hook (seam, preflight_data);
    }

    PinnedTestControl
    Lifecycle () const
    {
      return { lifecycle_hook, lifecycle_data, authority_error,
               finalize_error, r5_error };
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
      pinned_pair_test_authority_error,
      pinned_pair_test_finalize_error,
      pinned_pair_test_r5_error,
    };
    pinned_pair_test_hook = nullptr;
    pinned_pair_test_hook_data = nullptr;
    pinned_pair_preflight_test_hook = nullptr;
    pinned_pair_preflight_test_hook_data = nullptr;
    pinned_pair_preflight_test_error_seam =
        WYL_FACT_STORE_PAIR_PREFLIGHT_PRE_FACTORY;
    pinned_pair_preflight_test_error = WYRELOG_E_OK;
    pinned_pair_test_authority_error = WYRELOG_E_OK;
    pinned_pair_test_finalize_error = WYRELOG_E_OK;
    pinned_pair_test_r5_error = WYRELOG_E_OK;
    return result;
  }

  /* Build the bounded secure filesystem into |config| and move its lease +
   * health onto |bridge|.  Shared by the one-shot and live opens so both apply
   * an identical hardened configuration. */
  void
  bridge_prepare_bounded_config (WylSecureDuckdbBridge *bridge,
      WylFactArtifactNamespace *namespace_, bool read_only,
      bool allow_temporary_storage,
      WylFactArtifactMutationLease *adopted_lease,
      duckdb::DBConfig *config)
  {
    bridge->mode = read_only ? WYL_SECURE_DUCKDB_VALIDATE_ONLY
        : WYL_SECURE_DUCKDB_INIT_EMPTY;
    duckdb::unique_ptr<WylSecureDuckdbFileSystem> filesystem;
    try {
      filesystem = wyl_secure_duckdb_filesystem_new (namespace_, read_only,
              allow_temporary_storage, adopted_lease);
    } catch (const WylSecureDuckdbAuthorityException &)
    {
      /* The constructor has no health object to return when initial namespace
       * or lease authority fails.  Preserve that typed origin on the bridge
       * before propagating the original error. */
      bridge->preconstruction_provenance_failure = true;
      throw;
    }
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
        allow_temporary_storage, nullptr, &config);
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
  validate_restore_stage_identity_once
    (WylFactOfflineRestoreStageReader *reader,
      const WylFactStoreIdentity *expected_identity,
      WylFactStoreIdentityResult *out_identity_result)
  {
    std::unique_ptr<WylSecureDuckdbBridge> bridge;
    wyrelog_error_t result = WYRELOG_E_OK;
    try {
      bridge = std::make_unique<WylSecureDuckdbBridge> ();
      bridge->mode = WYL_SECURE_DUCKDB_VALIDATE_ONLY;
      bridge->health = std::make_shared<WylSecureDuckdbHealth> ();

      duckdb::DBConfig config;
      config.options.access_mode = duckdb::AccessMode::READ_ONLY;
      config.options.load_extensions = false;
      config.options.use_temporary_directory = false;
      config.options.maximum_threads = 1;
      config.options.checkpoint_on_shutdown = false;
      config.SetOptionByName ("enable_external_access", duckdb::Value (false));
      config.SetOptionByName ("allow_community_extensions",
          duckdb::Value (false));
      config.SetOptionByName ("autoinstall_known_extensions",
          duckdb::Value (false));
      config.SetOptionByName ("autoload_known_extensions",
          duckdb::Value (false));
      config.file_system = duckdb::make_uniq<RestoreStageReaderFileSystem>
          (reader, bridge->health);

      bridge->database = std::make_unique<duckdb::DuckDB>
          (restore_stage_main_name, &config);
      bridge->connection =
          std::make_unique<duckdb::Connection> (*bridge->database);

      result = wyl_fact_offline_restore_stage_reader_revalidate (reader);
      if (result == WYRELOG_E_OK) {
        WylFactStoreIdentityExecutor executor = {
          bridge->connection.get (), cpp_identity_execute, nullptr
        };
        result = wyl_fact_store_identity_execute (&executor,
                expected_identity, WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY,
                out_identity_result);
        if (result == WYRELOG_E_OK)
          restore_stage_test_fire
            (WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_IDENTITY);
      }
    } catch (...)
    {
      result = current_exception_error ();
    }
    if (bridge != nullptr) {
      const wyrelog_error_t close_result =
          bridge_finalize_storage (bridge.get (), false);
      if (close_result != WYRELOG_E_OK) {
        result = close_result;
        *out_identity_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
      }
    }
    restore_stage_test_fire (WYL_SECURE_DUCKDB_RESTORE_STAGE_TEST_AFTER_CLOSE);
    return result;
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

extern "C" void
wyl_secure_duckdb_bridge_set_restore_stage_test_hook_for_test
  (WylSecureDuckdbRestoreStageTestHook hook, gpointer user_data)
{
  std::lock_guard<std::mutex> lock (restore_stage_test_mutex);
  restore_stage_test_hook = hook;
  restore_stage_test_data = user_data;
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_test_restore_stage_filesystem_contract
  (WylFactOfflineRestoreStageReader *reader, guint64 *out_contract)
{
  if (out_contract != nullptr)
    *out_contract = 0;
  if (reader == nullptr || out_contract == nullptr)
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  return WYRELOG_E_POLICY;
#else
  *out_contract = test_restore_stage_filesystem_contract (reader);
  return WYRELOG_E_OK;
#endif
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_validate_restore_stage_identity
  (WylFactOfflineRestoreStageReader *reader, guint64 expected_bytes,
    const gchar *expected_checksum,
    const WylFactStoreIdentity *expected_identity,
    WylFactStoreIdentityResult *out_result)
{
  if (out_result != nullptr)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (reader == nullptr || expected_bytes == 0 || expected_checksum == nullptr
      || expected_identity == nullptr || out_result == nullptr
      || !wyl_fact_store_identity_input_is_valid (expected_identity))
    return WYRELOG_E_INVALID;
#ifdef G_OS_WIN32
  return WYRELOG_E_POLICY;
#else
  wyrelog_error_t rc =
      wyl_fact_offline_restore_stage_reader_verify_content (reader,
          expected_bytes, expected_checksum);
  if (rc != WYRELOG_E_OK)
    return rc;

  WylFactStoreIdentityResult identity_result =
      WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  {
    wyl_fact_store_identity_process_guard_lock ();
    struct ProcessGuard
    {
      ~ProcessGuard ()
      {
        wyl_fact_store_identity_process_guard_unlock ();
      }
    } process_guard;
    rc = validate_restore_stage_identity_once (reader, expected_identity,
            &identity_result);
  }

  const wyrelog_error_t authority =
      wyl_fact_offline_restore_stage_reader_revalidate (reader);
  const wyrelog_error_t content =
      wyl_fact_offline_restore_stage_reader_verify_content (reader,
          expected_bytes, expected_checksum);
  if (authority != WYRELOG_E_OK)
    return authority;
  if (content != WYRELOG_E_OK)
    return content;
  *out_result = identity_result;
  return rc;
#endif
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

static wyrelog_error_t
bridge_open_live_common (WylFactArtifactNamespace *namespace_,
    WylFactArtifactMutationLease *adopted_lease, gboolean writable,
    WylSecureDuckdbBridge **out_bridge,
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
        writable != FALSE, adopted_lease, &config);

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
wyl_secure_duckdb_bridge_open_live_pair (WylFactArtifactNamespace *namespace_,
    gboolean writable, WylSecureDuckdbBridge **out_bridge,
    duckdb_database *out_db, duckdb_connection *out_conn)
{
  return bridge_open_live_common (namespace_, nullptr, writable, out_bridge,
             out_db, out_conn);
}

extern "C" wyrelog_error_t
wyl_secure_duckdb_bridge_open_live_with_lease
  (WylFactArtifactNamespace *namespace_,
    WylFactArtifactMutationLease *adopted_lease, gboolean writable,
    WylSecureDuckdbBridge **out_bridge, duckdb_database *out_db,
    duckdb_connection *out_conn)
{
  if (adopted_lease == nullptr)
    return WYRELOG_E_INVALID;
  return bridge_open_live_common (namespace_, adopted_lease, writable,
             out_bridge, out_db, out_conn);
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

extern "C" WylFactArtifactMutationLease *
wyl_secure_duckdb_bridge_authority_lease (WylSecureDuckdbBridge *self)
{
  return self == nullptr ? nullptr : self->authority_lease.get ();
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

extern "C" void
wyl_fact_store_pinned_set_pair_test_stage_errors_for_test
  (wyrelog_error_t authority_error, wyrelog_error_t finalize_error,
    wyrelog_error_t r5_error)
{
  std::lock_guard<std::mutex> lock (pinned_pair_test_control_mutex);
  pinned_pair_test_authority_error = authority_error;
  pinned_pair_test_finalize_error = finalize_error;
  pinned_pair_test_r5_error = r5_error;
}

static wyrelog_error_t
open_identified_pinned_core (WylFactArtifactNamespace *namespace_,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result,
    WylFactStorePinnedFailureOrigin *out_failure_origin,
    bool notify_failure_observed,
    const PinnedTestControl &control)
{
  *out_result = WYL_FACT_STORE_IDENTITY_RESULT_OPEN;
  *out_failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_NONE;
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
  if (r0_result != WYRELOG_E_OK) {
    *out_failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE;
    if (notify_failure_observed)
      control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_FAILURE_OBSERVED);
    return r0_result;
  }
  if (notify_failure_observed)
    control.Fire (
      WYL_FACT_STORE_PINNED_RENDEZVOUS_R0_POSTREVALIDATE_PRECONSTRUCT);

  std::unique_ptr<WylSecureDuckdbBridge> bridge;
  try {
    bridge = std::make_unique<WylSecureDuckdbBridge> ();
  } catch (...)
  {
    return current_exception_error ();
  }

  PinnedLifecycleResults results;
  bool populated = false;
  bool provenance_failure = false;
  try {
    bridge_populate_bounded (bridge.get (), namespace_,
        mode == WYL_FACT_STORE_IDENTITY_VALIDATE_ONLY, false);
    populated = true;
  } catch (...)
  {
    results.body = current_exception_error ();
  }
  provenance_failure = bridge->preconstruction_provenance_failure;

  if (populated) {
    control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R1_POSTCONSTRUCT);
    const auto r1_result =
        pinned_authority_revalidate (bridge.get (), namespace_);
    if (r1_result != WYRELOG_E_OK)
      provenance_failure = true;
    if (results.body == WYRELOG_E_OK && r1_result != WYRELOG_E_OK)
      results.body = r1_result;

    control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R2_PREIDENTITY);
    const auto r2_result =
        pinned_authority_revalidate (bridge.get (), namespace_);
    if (r2_result != WYRELOG_E_OK)
      provenance_failure = true;
    if (results.body == WYRELOG_E_OK && r2_result != WYRELOG_E_OK)
      results.body = r2_result;

    if (results.body == WYRELOG_E_OK) {
      if (notify_failure_observed)
        control.Fire (
          WYL_FACT_STORE_PINNED_RENDEZVOUS_INTERNAL_PREIDENTITY);
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
  if (!storage_interacted) {
    if (results.body != WYRELOG_E_OK) {
      *out_failure_origin = provenance_failure ?
          WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE :
          WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_STORAGE;
      if (provenance_failure && notify_failure_observed)
        control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_FAILURE_OBSERVED);
    }
    return results.body;
  }

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R3_POSTIDENTITY);
  results.authority =
      pinned_authority_revalidate (bridge.get (), namespace_);
  if (results.authority != WYRELOG_E_OK)
    provenance_failure = true;

  control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_R4_PREFINALIZE);
  const auto r4_result =
      pinned_authority_revalidate (bridge.get (), namespace_);
  if (r4_result != WYRELOG_E_OK)
    provenance_failure = true;
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
  if (results.r5 != WYRELOG_E_OK)
    provenance_failure = true;
  if (results.r5 == WYRELOG_E_OK && control.r5_error != WYRELOG_E_OK)
    results.r5 = control.r5_error;

  if (bridge->health != nullptr
      && bridge->health->ProvenanceFailureObserved ())
    provenance_failure = true;

  bridge->authority_lease.reset ();
  bridge.reset ();

  bool cleanup_uncertain = false;
  const auto selected = reduce_pinned_lifecycle (results,
          &cleanup_uncertain);
  if (cleanup_uncertain)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_INTERNAL;
  if (selected != WYRELOG_E_OK) {
    *out_failure_origin = provenance_failure ?
        WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE :
        WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_STORAGE;
    if (provenance_failure && notify_failure_observed)
      control.Fire (WYL_FACT_STORE_PINNED_RENDEZVOUS_FAILURE_OBSERVED);
  }
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
  WylFactStorePinnedFailureOrigin failure_origin;
  return open_identified_pinned_core (namespace_, identity, mode, out_result,
             &failure_origin, false, control);
}

extern "C" wyrelog_error_t
wyl_fact_store_open_identified_provisioned_pair_pinned
  (WylFactGraphProvisionedPair *pair,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result)
{
  WylFactStorePinnedFailureOrigin failure_origin;
  return wyl_fact_store_open_identified_provisioned_pair_pinned_classified
           (pair, identity, mode, out_result, &failure_origin);
}

extern "C" wyrelog_error_t
wyl_fact_store_open_identified_provisioned_pair_pinned_classified
  (WylFactGraphProvisionedPair *pair,
    const WylFactStoreIdentity *identity, WylFactStoreIdentityOpenMode mode,
    WylFactStoreIdentityResult *out_result,
    WylFactStorePinnedFailureOrigin *out_failure_origin)
{
  if (out_result != nullptr)
    *out_result = WYL_FACT_STORE_IDENTITY_RESULT_NONE;
  if (out_failure_origin != nullptr)
    *out_failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_NONE;
  if (pair == nullptr || out_result == nullptr || out_failure_origin == nullptr
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
      && control.preflight_error_seam == preflight) {
    *out_failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_STORAGE;
    return control.preflight_error;
  }
  const auto authority_result =
      wyl_fact_graph_provisioned_pair_revalidate (pair);
  if (authority_result != WYRELOG_E_OK) {
    *out_failure_origin = WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE;
    return authority_result;
  }

  WylFactArtifactNamespace *namespace_ = nullptr;
  const auto result =
      wyl_fact_artifact_namespace_open_provisioned_pair_internal (pair,
          &namespace_);
  if (result != WYRELOG_E_OK) {
    *out_failure_origin = result == WYRELOG_E_POLICY
        || result == WYRELOG_E_NOT_FOUND ?
        WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_PROVENANCE :
        WYL_FACT_STORE_PINNED_FAILURE_ORIGIN_STORAGE;
    return result;
  }
  const auto lifecycle_control = control.Lifecycle ();
  const auto open_result =
      open_identified_pinned_core (namespace_, identity, mode, out_result,
          out_failure_origin, true, lifecycle_control);
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
