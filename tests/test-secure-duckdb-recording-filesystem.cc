/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This is deliberately a test fixture, not a DuckDB VFS for wyrelog.  It
 * owns a public LocalFileSystem and permits only absolute paths below the
 * per-test directory.  In particular it does not register or route DuckDB
 * subsystems: protocol, compression, subsystem, and ambient-path requests are
 * rejected before they can reach LocalFileSystem.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <duckdb.hpp>

#include <filesystem>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

static const gchar *self_path;

namespace fs = std::filesystem;

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.2");

struct Event {
  std::string operation;
  std::string path;
  duckdb::idx_t flags = 0;
  duckdb::FileLockType lock = duckdb::FileLockType::NO_LOCK;
  duckdb::FileCompressionType compression = duckdb::FileCompressionType::UNCOMPRESSED;
  int outcome = -1;
};

struct ControlEvent {
  std::string operation;
  std::string path;
};

struct RecorderState {
  std::vector<Event> events;
  std::vector<ControlEvent> controls;
  guint rejected = 0;
  guint subsystem_attempts = 0;
};

class RecordingFileSystem;

class RecordingFileHandle final : public duckdb::FileHandle {
public:
  RecordingFileHandle (RecordingFileSystem &owner, std::string path,
      duckdb::FileOpenFlags flags, duckdb::unique_ptr<duckdb::FileHandle> inner);

  void Close () override;
  ~RecordingFileHandle () override { Close (); }

  duckdb::unique_ptr<duckdb::FileHandle> inner;
  RecordingFileSystem &owner;
  bool closed = false;
};

class RecordingFileSystem final : public duckdb::FileSystem {
public:
  RecordingFileSystem (const std::string &sandbox,
      std::shared_ptr<RecorderState> recorder)
      : sandbox_ (fs::canonical (fs::path (sandbox))),
        local_ (duckdb::FileSystem::CreateLocal ()), recorder_ (std::move (recorder))
  {
  }

  const std::vector<Event> &events () const { return recorder_->events; }
  guint rejected () const { return recorder_->rejected; }
  void RecordClose (const std::string &path, duckdb::FileOpenFlags flags)
  {
    record ("close", path, flags);
  }

  duckdb::unique_ptr<duckdb::FileHandle> OpenFile (const duckdb::string &path,
      duckdb::FileOpenFlags flags, duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    if (flags.Compression () != duckdb::FileCompressionType::AUTO_DETECT
        && flags.Compression () != duckdb::FileCompressionType::UNCOMPRESSED)
      reject ("compressed file access is not permitted");
    record ("open", checked, flags);
    auto inner = local_->OpenFile (checked.string (), flags, nullptr);
    if (!inner)
      return nullptr;
    return duckdb::make_uniq<RecordingFileHandle> (*this, checked.string (),
        flags, std::move (inner));
  }

  void Read (duckdb::FileHandle &handle, void *buffer, int64_t bytes,
      duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    record ("read-at", recording.GetPath ());
    local_->Read (*recording.inner, buffer, bytes, location);
  }

  void Write (duckdb::FileHandle &handle, void *buffer, int64_t bytes,
      duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    record ("write-at", recording.GetPath ());
    local_->Write (*recording.inner, buffer, bytes, location);
  }

  int64_t Read (duckdb::FileHandle &handle, void *buffer, int64_t bytes) override
  {
    auto &recording = unwrap (handle);
    record ("read", recording.GetPath ());
    return local_->Read (*recording.inner, buffer, bytes);
  }

  int64_t Write (duckdb::FileHandle &handle, void *buffer, int64_t bytes) override
  {
    auto &recording = unwrap (handle);
    record ("write", recording.GetPath ());
    return local_->Write (*recording.inner, buffer, bytes);
  }

  bool Trim (duckdb::FileHandle &handle, duckdb::idx_t offset,
      duckdb::idx_t length) override
  {
    auto &recording = unwrap (handle);
    record ("trim", recording.GetPath ());
    return local_->Trim (*recording.inner, offset, length);
  }

  int64_t GetFileSize (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("size", recording.GetPath ());
    return local_->GetFileSize (*recording.inner);
  }

  duckdb::timestamp_t GetLastModifiedTime (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("last-modified", recording.GetPath ());
    return local_->GetLastModifiedTime (*recording.inner);
  }

  duckdb::string GetVersionTag (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("version", recording.GetPath ());
    return local_->GetVersionTag (*recording.inner);
  }

  duckdb::FileType GetFileType (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("type", recording.GetPath ());
    return local_->GetFileType (*recording.inner);
  }

  duckdb::FileMetadata Stats (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("stats", recording.GetPath ());
    return local_->Stats (*recording.inner);
  }

  void Truncate (duckdb::FileHandle &handle, int64_t size) override
  {
    auto &recording = unwrap (handle);
    record ("truncate", recording.GetPath ());
    local_->Truncate (*recording.inner, size);
  }

  bool DirectoryExists (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("directory-exists", checked);
    return local_->DirectoryExists (checked.string (), nullptr);
  }

  void CreateDirectory (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("create-directory", checked);
    local_->CreateDirectory (checked.string (), nullptr);
  }

  void CreateDirectoriesRecursive (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("create-directories", checked);
    local_->CreateDirectoriesRecursive (checked.string (), nullptr);
  }

  void RemoveDirectory (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("remove-directory", checked);
    local_->RemoveDirectory (checked.string (), nullptr);
  }

  bool ListFiles (const duckdb::string &path,
      const std::function<void (const duckdb::string &, bool)> &callback,
      duckdb::FileOpener *opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("list", checked);
    return local_->ListFiles (checked.string (), callback, nullptr);
  }

  void MoveFile (const duckdb::string &source, const duckdb::string &target,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto source_checked = check_path (source);
    const auto target_checked = check_path (target);
    record ("move", source_checked);
    record ("move-target", target_checked);
    local_->MoveFile (source_checked.string (), target_checked.string (), nullptr);
  }

  bool FileExists (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    // DuckDB 1.5.2 asks this exact Linux cgroup probe while sizing its block
    // allocator. Record the denied probe separately from filesystem events;
    // it is never forwarded to LocalFileSystem.
    if (path == "/proc/self/cgroup") {
      record_control ("deny-host-exists", path);
      return false;
    }
    if (path.rfind ("/sys/fs/cgroup/", 0) == 0)
      reject ("unapproved cgroup host path: " + path);
    const auto checked = check_path (path);
    record ("exists", checked);
    return local_->FileExists (checked.string (), nullptr);
  }

  bool IsPipe (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("is-pipe", checked);
    return local_->IsPipe (checked.string (), nullptr);
  }

  void RemoveFile (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("remove", checked);
    local_->RemoveFile (checked.string (), nullptr);
  }

  bool TryRemoveFile (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto removed = local_->TryRemoveFile (checked.string (), nullptr);
    record ("try-remove", checked, {}, removed ? 1 : 0);
    return removed;
  }

  void RemoveFiles (const duckdb::vector<duckdb::string> &paths,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    duckdb::vector<duckdb::string> checked;
    checked.reserve (paths.size ());
    for (const auto &path : paths) {
      const auto checked_path = check_path (path);
      record ("remove-many", checked_path);
      checked.push_back (checked_path.string ());
    }
    local_->RemoveFiles (checked, nullptr);
  }

  void FileSync (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("sync", recording.GetPath ());
    local_->FileSync (*recording.inner);
  }

  duckdb::string PathSeparator (const duckdb::string &path) override
  {
    const auto checked = check_path (path);
    record ("separator", checked);
    return local_->PathSeparator (checked.string ());
  }

  bool IsPathAbsolute (const duckdb::string &path) override
  {
    return fs::path (path).is_absolute ();
  }

  duckdb::vector<duckdb::OpenFileInfo> Glob (const duckdb::string &path,
      duckdb::FileOpener *opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("glob", checked);
    reject ("glob access is not permitted");
  }

  void RegisterSubSystem (duckdb::unique_ptr<duckdb::FileSystem> subsystem) override
  {
    (void) subsystem;
    ++recorder_->subsystem_attempts;
    record_control ("register-subsystem");
    reject ("subsystem registration is not permitted");
  }

  void RegisterSubSystem (duckdb::FileCompressionType compression,
      duckdb::unique_ptr<duckdb::FileSystem> subsystem) override
  {
    (void) compression;
    (void) subsystem;
    ++recorder_->subsystem_attempts;
    record_control ("register-compressed-subsystem");
    reject ("compressed subsystem registration is not permitted");
  }

  void UnregisterSubSystem (const duckdb::string &name) override { reject ("subsystems are not permitted: " + name); }
  duckdb::unique_ptr<duckdb::FileSystem> ExtractSubSystem (const duckdb::string &name) override
  {
    reject ("subsystems are not permitted: " + name);
  }
  duckdb::vector<duckdb::string> ListSubSystems () override { return {}; }
  bool CanHandleFile (const duckdb::string &) override { return false; }

  duckdb::string GetHomeDirectory () override
  {
    record_control ("get-home-directory");
    reject ("home-directory access is not permitted");
  }

  duckdb::string ExpandPath (const duckdb::string &path) override
  {
    const auto checked = check_path (path);
    record ("expand", checked);
    return checked.string ();
  }

  void Seek (duckdb::FileHandle &handle, duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    record ("seek", recording.GetPath ());
    local_->Seek (*recording.inner, location);
  }
  void Reset (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("reset", recording.GetPath ());
    local_->Reset (*recording.inner);
  }
  duckdb::idx_t SeekPosition (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("seek-position", recording.GetPath ());
    return local_->SeekPosition (*recording.inner);
  }
  bool IsManuallySet () override { return true; }
  bool CanSeek () override { return local_->CanSeek (); }
  bool OnDiskFile (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    record ("on-disk", recording.GetPath ());
    return local_->OnDiskFile (*recording.inner);
  }
  duckdb::unique_ptr<duckdb::FileHandle> OpenCompressedFile (duckdb::QueryContext,
      duckdb::unique_ptr<duckdb::FileHandle>, bool) override
  {
    reject ("compressed files are not permitted");
  }
  std::string GetName () const override { return "wyrelog-test-recording-filesystem"; }
  duckdb::string CanonicalizePath (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("canonicalize", checked);
    return checked.string ();
  }

protected:
  duckdb::unique_ptr<duckdb::FileHandle> OpenFileExtended (
      const duckdb::OpenFileInfo &info, duckdb::FileOpenFlags flags,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    return OpenFile (info.path, flags, opener);
  }
  bool SupportsOpenFileExtended () const override { return true; }
  duckdb::unique_ptr<duckdb::MultiFileList> GlobFilesExtended (
      const duckdb::string &path, const duckdb::FileGlobInput &,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("glob-extended", checked);
    reject ("extended glob access is not permitted");
  }
  bool SupportsGlobExtended () const override { return true; }

private:
  RecordingFileHandle &unwrap (duckdb::FileHandle &handle)
  {
    return handle.Cast<RecordingFileHandle> ();
  }

  [[noreturn]] void reject (const std::string &reason)
  {
    ++recorder_->rejected;
    throw duckdb::PermissionException ("test recording filesystem rejected " + reason);
  }

  fs::path check_path (const std::string &raw)
  {
    if (raw.empty () || raw.find ("://") != std::string::npos)
      reject ("ambient or protocol path");
    const fs::path candidate (raw);
    if (!candidate.is_absolute ())
      reject ("relative path");
    for (const auto &part : candidate) {
      if (part == "..")
        reject ("parent traversal");
    }
    const fs::path normalized = candidate.lexically_normal ();
    const fs::path relative = normalized.lexically_relative (sandbox_);
    if (relative.is_absolute ())
      reject ("ambient path");
    for (const auto &part : relative) {
      if (part == "..")
        reject ("outside sandbox: " + raw);
    }
    fs::path probe = sandbox_;
    for (const auto &part : relative) {
      probe /= part;
      std::error_code error;
      const auto status = fs::symlink_status (probe, error);
      if (!error && fs::is_symlink (status))
        reject ("symbolic-link path");
    }
    return normalized;
  }

  void record (const std::string &operation, const fs::path &path,
      duckdb::FileOpenFlags flags = {}, int outcome = -1)
  {
    recorder_->events.push_back ({ operation, path.string (), flags.GetFlagsInternal (),
        flags.Lock (), flags.Compression (), outcome });
  }
  void record (const std::string &operation, const std::string &path)
  {
    record (operation, check_path (path));
  }
  void record_control (const std::string &operation)
  {
    recorder_->controls.push_back ({ operation, "" });
  }
  void record_control (const std::string &operation, const std::string &path)
  {
    recorder_->controls.push_back ({ operation, path });
  }

  fs::path sandbox_;
  duckdb::unique_ptr<duckdb::FileSystem> local_;
  std::shared_ptr<RecorderState> recorder_;
};

RecordingFileHandle::RecordingFileHandle (RecordingFileSystem &owner,
    std::string path, duckdb::FileOpenFlags flags,
    duckdb::unique_ptr<duckdb::FileHandle> inner_handle)
    : FileHandle (owner, std::move (path), flags), inner (std::move (inner_handle)), owner (owner)
{
}

void
RecordingFileHandle::Close ()
{
  if (!closed) {
    closed = true;
    owner.RecordClose (GetPath (), GetFlags ());
    inner->Close ();
  }
}

static void
remove_tree (const gchar *path)
{
  g_autoptr (GDir) directory = g_dir_open (path, 0, NULL);
  if (directory != NULL) {
    const gchar *name;
    while ((name = g_dir_read_name (directory)) != NULL) {
      g_autofree gchar *child = g_build_filename (path, name, NULL);
      if (g_file_test (child, G_FILE_TEST_IS_DIR) && !g_file_test (child, G_FILE_TEST_IS_SYMLINK))
        remove_tree (child);
      else
        g_assert_cmpint (g_remove (child), ==, 0);
    }
  }
  g_assert_cmpint (g_rmdir (path), ==, 0);
}

static void
assert_rejected_without_forwarding (RecordingFileSystem &filesystem,
    const std::string &path)
{
  const auto event_count = filesystem.events ().size ();
  const auto rejected = filesystem.rejected ();
  try {
    filesystem.FileExists (path, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::Exception &) {
  }
  g_assert_cmpuint (filesystem.rejected (), ==, rejected + 1);
  g_assert_cmpuint (filesystem.events ().size (), ==, event_count);
}

static gboolean
has_operation (const Event &event, const gchar *operation)
{
  return event.operation == operation;
}

static void
assert_source_152_plain_lifecycle_event (const Event &event,
    const fs::path &database)
{
  const std::string main_path = database.string ();
  const std::string wal_path = main_path + ".wal";
  const std::string checkpoint_path = wal_path + ".checkpoint";
  const std::string recovery_path = wal_path + ".recovery";
  const gboolean is_main = event.path == main_path;
  const gboolean is_wal = event.path == wal_path || event.path == checkpoint_path
      || event.path == recovery_path;
  g_assert_true (is_main || is_wal);

  const gboolean allowed_main_operation = has_operation (event, "open")
      || has_operation (event, "close") || has_operation (event, "separator")
      || has_operation (event, "canonicalize") || has_operation (event, "exists")
      || has_operation (event, "write-at") || has_operation (event, "sync")
      || has_operation (event, "on-disk") || has_operation (event, "read")
      || has_operation (event, "size") || has_operation (event, "read-at");
  const gboolean allowed_wal_operation = has_operation (event, "open")
      || has_operation (event, "close") || has_operation (event, "size")
      || has_operation (event, "read") || has_operation (event, "read-at")
      || has_operation (event, "seek") || has_operation (event, "reset")
      || has_operation (event, "seek-position")
      || has_operation (event, "write") || has_operation (event, "sync")
      || has_operation (event, "try-remove");
  g_assert_true (is_main ? allowed_main_operation : allowed_wal_operation);

  if (has_operation (event, "open") || has_operation (event, "close")) {
    const gboolean main_flags = is_main &&
        ((event.flags == 129 && event.lock == duckdb::FileLockType::NO_LOCK)
        || (event.flags == 2315 && event.lock == duckdb::FileLockType::WRITE_LOCK)
        || (event.flags == 2307 && event.lock == duckdb::FileLockType::WRITE_LOCK)
        || (event.flags == 2433 && event.lock == duckdb::FileLockType::READ_LOCK));
    const gboolean wal_flags = is_wal &&
        ((event.flags == 129 && event.lock == duckdb::FileLockType::NO_LOCK)
        || (event.flags == 2090 && event.lock == duckdb::FileLockType::WRITE_LOCK));
    g_assert_true (main_flags || wal_flags);
  } else {
    g_assert_cmpuint (event.flags, ==, 0);
    g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
  }
  g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
}

static void
assert_source_152_control_events (const std::vector<ControlEvent> &controls,
    size_t baseline, guint database_opens)
{
#ifdef __linux__
  // DBConfig queries this once for default memory and once for its block
  // allocator in each of the two DuckDB 1.5.2 lifecycles above.
  g_assert_cmpuint (controls.size (), ==, baseline + 2 * database_opens);
  for (size_t i = baseline; i < controls.size (); i++) {
    g_assert_cmpstr (controls[i].operation.c_str (), ==, "deny-host-exists");
    g_assert_cmpstr (controls[i].path.c_str (), ==, "/proc/self/cgroup");
  }
#else
  g_assert_cmpuint (controls.size (), ==, baseline);
#endif
}

struct FileIdentity {
  dev_t device;
  ino_t inode;
  off_t size;
  mode_t mode;
  nlink_t links;
  time_t modified;
  time_t changed;
  std::string digest;
};

static FileIdentity
snapshot_file (const fs::path &path)
{
  struct stat buffer;
  g_assert_cmpint (g_stat (path.c_str (), &buffer), ==, 0);
  gchar *contents = NULL;
  gsize length = 0;
  g_assert_true (g_file_get_contents (path.c_str (), &contents, &length, NULL));
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
      (const guchar *) contents, length);
  g_free (contents);
  return { buffer.st_dev, buffer.st_ino, buffer.st_size, buffer.st_mode,
      buffer.st_nlink, buffer.st_mtime, buffer.st_ctime, digest };
}

static void
assert_same_file (const FileIdentity &before, const FileIdentity &after)
{
  g_assert_cmpint (after.device, ==, before.device);
  g_assert_cmpint (after.inode, ==, before.inode);
  g_assert_cmpint (after.size, ==, before.size);
  g_assert_cmpint (after.mode, ==, before.mode);
  g_assert_cmpint (after.links, ==, before.links);
  g_assert_cmpint (after.modified, ==, before.modified);
  g_assert_cmpint (after.changed, ==, before.changed);
  g_assert_cmpstr (after.digest.c_str (), ==, before.digest.c_str ());
}

static void
configure_test_database (duckdb::DBConfig *config, const fs::path &root,
    std::shared_ptr<RecorderState> recorder)
{
  config->file_system = duckdb::make_uniq<RecordingFileSystem> (root.string (),
      std::move (recorder));
  config->options.maximum_threads = 1;
  config->options.load_extensions = false;
}

static void
assert_duckdb_152 (void)
{
  g_assert_cmpstr (duckdb_library_version (), ==, "v1.5.2");
}

static int
crash_writer_child (const gchar *sandbox)
{
  if (g_strcmp0 (duckdb_library_version (), "v1.5.2") != 0)
    _exit (90);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  duckdb::DBConfig config;
  configure_test_database (&config, root, recorder);
  duckdb::DuckDB db (database.string (), &config);
  duckdb::Connection connection (db);
  auto result = connection.Query ("INSERT INTO facts VALUES (99)");
  if (result->HasError () || !fs::exists (database.string () + ".wal"))
    _exit (91);
  for (const auto &event : recorder->events) {
    if (dprintf (STDOUT_FILENO, "E\t%s\t%s\t%llu\t%u\t%u\t%d\n",
            event.operation.c_str (), event.path.c_str (),
            (unsigned long long) event.flags, (unsigned) event.lock,
            (unsigned) event.compression, event.outcome) < 0)
      _exit (92);
  }
  for (const auto &control : recorder->controls) {
    if (dprintf (STDOUT_FILENO, "C\t%s\t%s\n", control.operation.c_str (),
            control.path.c_str ()) < 0)
      _exit (92);
  }
  if (dprintf (STDOUT_FILENO, "END\n") < 0)
    _exit (92);
  _exit (0);
}

static gboolean is_mutation_event (const Event &event);

static void
parse_child_trace (const gchar *output, std::vector<Event> *events,
    std::vector<ControlEvent> *controls)
{
  g_auto (GStrv) lines = g_strsplit (output, "\n", -1);
  gboolean ended = FALSE;
  for (guint i = 0; lines[i] != NULL; i++) {
    if (lines[i][0] == '\0') {
      g_assert_true (ended || lines[i + 1] == NULL);
      continue;
    }
    if (g_strcmp0 (lines[i], "END") == 0) {
      g_assert_false (ended);
      ended = TRUE;
      continue;
    }
    g_assert_false (ended);
    g_auto (GStrv) fields = g_strsplit (lines[i], "\t", -1);
    if (g_strcmp0 (fields[0], "E") == 0) {
      g_assert_nonnull (fields[1]);
      g_assert_nonnull (fields[2]);
      g_assert_nonnull (fields[3]);
      g_assert_nonnull (fields[4]);
      g_assert_nonnull (fields[5]);
      g_assert_nonnull (fields[6]);
      g_assert_null (fields[7]);
      char *end = NULL;
      errno = 0;
      const auto flags = strtoull (fields[3], &end, 10);
      g_assert_cmpint (errno, ==, 0);
      g_assert_cmpstr (end, ==, "");
      errno = 0;
      const auto lock = strtoul (fields[4], &end, 10);
      g_assert_cmpint (errno, ==, 0);
      g_assert_cmpstr (end, ==, "");
      errno = 0;
      const auto compression = strtoul (fields[5], &end, 10);
      g_assert_cmpint (errno, ==, 0);
      g_assert_cmpstr (end, ==, "");
      errno = 0;
      const auto outcome = strtol (fields[6], &end, 10);
      g_assert_cmpint (errno, ==, 0);
      g_assert_cmpstr (end, ==, "");
      g_assert_cmpint (outcome, >=, -1);
      g_assert_cmpint (outcome, <=, 1);
      events->push_back ({ fields[1], fields[2], (duckdb::idx_t) flags,
          (duckdb::FileLockType) lock, (duckdb::FileCompressionType) compression,
          (int) outcome });
    } else if (g_strcmp0 (fields[0], "C") == 0) {
      g_assert_nonnull (fields[1]);
      g_assert_nonnull (fields[2]);
      g_assert_null (fields[3]);
      controls->push_back ({ fields[1], fields[2] });
    } else {
      g_assert_not_reached ();
    }
  }
  g_assert_true (ended);
}

static void
assert_live_wal_path (const Event &event, const fs::path &database)
{
  const std::string main_path = database.string ();
  const std::string wal_path = main_path + ".wal";
  if (event.path != main_path && event.path != wal_path)
    g_error ("unexpected live-WAL path: %s", event.path.c_str ());
  g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
}

static void
assert_read_only_live_wal_trace (const RecorderState &recorder,
    const fs::path &database)
{
  gboolean wal_open = FALSE;
  gboolean wal_read = FALSE;
  for (const auto &event : recorder.events) {
    assert_live_wal_path (event, database);
    g_assert_cmpint (event.outcome, ==, -1);
    g_assert_false (is_mutation_event (event));
    if (has_operation (event, "open") || has_operation (event, "close")) {
      const gboolean allowed_main = event.path == database.string () &&
          ((event.flags == 129 && event.lock == duckdb::FileLockType::NO_LOCK)
          || (event.flags == 2433 && event.lock == duckdb::FileLockType::READ_LOCK));
      const gboolean allowed_wal = event.path == database.string () + ".wal"
          && event.flags == 129 && event.lock == duckdb::FileLockType::NO_LOCK;
      g_assert_true (allowed_main || allowed_wal);
      wal_open = wal_open || (allowed_wal && has_operation (event, "open"));
    }
    wal_read = wal_read || (event.path == database.string () + ".wal"
        && (has_operation (event, "read") || has_operation (event, "read-at")));
  }
  g_assert_true (wal_open && wal_read);
}

static void
test_recording_filesystem_persistent_database (void)
{
  assert_duckdb_152 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-recording-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (sandbox);
  struct stat stat_buffer;
  g_assert_cmpint (g_stat (sandbox, &stat_buffer), ==, 0);
  g_assert_cmpint (stat_buffer.st_mode & 0777, ==, 0700);

  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (root.string (), recorder);

  assert_rejected_without_forwarding (filesystem, "../facts.duckdb");
  assert_rejected_without_forwarding (filesystem, "/tmp/wyl-not-ours.duckdb");
  assert_rejected_without_forwarding (filesystem, "https://example.invalid/facts.duckdb");
  assert_rejected_without_forwarding (filesystem, "/sys/fs/cgroup/unapproved");
  const fs::path linked = root / "outside-link";
  g_assert_cmpint (symlink ("/tmp", linked.c_str ()), ==, 0);
  assert_rejected_without_forwarding (filesystem, (linked / "facts.duckdb").string ());
  g_assert_cmpint (g_remove (linked.c_str ()), ==, 0);
  const guint rejected_baseline = recorder->rejected;
  const guint subsystem_baseline = recorder->subsystem_attempts;
  const size_t event_baseline = recorder->events.size ();
  const size_t control_baseline = recorder->controls.size ();

  {
    duckdb::DBConfig config;
    config.file_system = duckdb::make_uniq<RecordingFileSystem> (root.string (), recorder);
    // Avoid DuckDB's auto-thread probe, which reads host /proc state.  The
    // fixture intentionally rejects all ambient paths rather than forwarding
    // them to LocalFileSystem.
    config.options.maximum_threads = 1;
    config.options.load_extensions = false;
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_true (!result->HasError ());
  }
  {
    duckdb::DBConfig reopen_config;
    reopen_config.file_system = duckdb::make_uniq<RecordingFileSystem> (root.string (), recorder);
    reopen_config.options.maximum_threads = 1;
    reopen_config.options.load_extensions = false;
    duckdb::DuckDB db (database.string (), &reopen_config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts");
    g_assert_true (!result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 1);
    g_assert_cmpstr (result->GetValue (0, 0).ToString ().c_str (), ==, "42");
  }
  g_assert_cmpuint (recorder->rejected, ==, rejected_baseline);
  g_assert_cmpuint (recorder->subsystem_attempts, ==, subsystem_baseline);
  g_assert_cmpuint (recorder->events.size (), >, event_baseline);
  gboolean saw_main_open = false;
  gboolean saw_wal_open = false;
  gboolean saw_main_close = false;
  gboolean saw_wal_close = false;
  gboolean saw_wal_sync_before_close = false;
  for (size_t i = event_baseline; i < recorder->events.size (); i++) {
    const auto &event = recorder->events[i];
    assert_source_152_plain_lifecycle_event (event, database);
    const gboolean is_main = event.path == database.string ();
    const gboolean is_wal = event.path == database.string () + ".wal";
    saw_main_open = saw_main_open || (is_main && has_operation (event, "open"));
    saw_wal_open = saw_wal_open || (is_wal && has_operation (event, "open"));
    if (is_wal && has_operation (event, "sync"))
      saw_wal_sync_before_close = true;
    if (is_main && has_operation (event, "close"))
      saw_main_close = true;
    if (is_wal && has_operation (event, "close")) {
      saw_wal_close = true;
      g_assert_true (saw_wal_sync_before_close);
    }
  }
  g_assert_true (saw_main_open && saw_wal_open);
  g_assert_true (saw_main_close && saw_wal_close);
  assert_source_152_control_events (recorder->controls, control_baseline, 2);

  remove_tree (sandbox);
}

static gboolean
is_mutation_event (const Event &event)
{
  return has_operation (event, "write") || has_operation (event, "write-at")
      || has_operation (event, "sync") || has_operation (event, "truncate")
      || has_operation (event, "trim") || has_operation (event, "remove")
      || has_operation (event, "try-remove") || has_operation (event, "remove-many")
      || has_operation (event, "move") || has_operation (event, "move-target")
      || has_operation (event, "create-directory")
      || has_operation (event, "create-directories");
}

static void
test_recording_filesystem_live_wal_read_only_recovery (void)
{
  assert_duckdb_152 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-live-wal-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = database.string () + ".wal";

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  g_assert_false (fs::exists (wal));

  const gchar *argv[] = { self_path, "--crash-writer", root.c_str (), NULL };
  g_autoptr (GSubprocess) child = g_subprocess_newv (argv,
      (GSubprocessFlags) (G_SUBPROCESS_FLAGS_STDOUT_PIPE
          | G_SUBPROCESS_FLAGS_STDERR_SILENCE),
      &error);
  g_assert_no_error (error);
  gchar *child_stdout = NULL;
  g_assert_true (g_subprocess_communicate_utf8 (child, NULL, NULL,
          &child_stdout, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (g_subprocess_get_successful (child));
  std::vector<Event> child_events;
  std::vector<ControlEvent> child_controls;
  parse_child_trace (child_stdout, &child_events, &child_controls);
  g_free (child_stdout);
  gboolean child_wal_open = FALSE;
  gboolean child_wal_write = FALSE;
  gboolean child_wal_sync = FALSE;
  gboolean child_checkpoint_noop = FALSE;
  const std::string checkpoint = wal.string () + ".checkpoint";
  for (const auto &event : child_events) {
    assert_source_152_plain_lifecycle_event (event, database);
    if (event.path == checkpoint) {
      g_assert_cmpstr (event.operation.c_str (), ==, "try-remove");
      g_assert_cmpint (event.outcome, ==, 0);
      g_assert_true (child_wal_write && child_wal_sync);
      g_assert_false (child_checkpoint_noop);
      child_checkpoint_noop = TRUE;
      continue;
    }
    assert_live_wal_path (event, database);
    g_assert_cmpint (event.outcome, ==, -1);
    child_wal_open = child_wal_open || (event.path == wal.string ()
        && has_operation (event, "open"));
    child_wal_write = child_wal_write || (event.path == wal.string ()
        && has_operation (event, "write"));
    child_wal_sync = child_wal_sync || (event.path == wal.string ()
        && has_operation (event, "sync"));
  }
  g_assert_true (child_wal_open && child_wal_write && child_wal_sync);
  g_assert_false (child_checkpoint_noop);
  assert_source_152_control_events (child_controls, 0, 1);
  g_assert_true (fs::exists (wal));
  g_assert_false (fs::exists (checkpoint));
  const FileIdentity main_before_ro = snapshot_file (database);
  const FileIdentity wal_before_ro = snapshot_file (wal);

  auto read_only_recorder = std::make_shared<RecorderState> ();
  gboolean read_only_opened = false;
  guint64 read_only_rows = 0;
  gchar *read_only_error = NULL;
  try {
    duckdb::DBConfig config;
    configure_test_database (&config, root, read_only_recorder);
    config.options.access_mode = duckdb::AccessMode::READ_ONLY;
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts ORDER BY value");
    if (result->HasError ())
      read_only_error = g_strdup (result->GetError ().c_str ());
    else {
      read_only_opened = true;
      read_only_rows = result->RowCount ();
    }
  } catch (const duckdb::Exception &exception) {
    read_only_error = g_strdup (exception.what ());
  }
  assert_read_only_live_wal_trace (*read_only_recorder, database);
  assert_source_152_control_events (read_only_recorder->controls, 0, 1);
  assert_same_file (main_before_ro, snapshot_file (database));
  assert_same_file (wal_before_ro, snapshot_file (wal));
  g_assert_true (read_only_opened);
  g_assert_null (read_only_error);
  g_assert_cmpuint (read_only_rows, ==, 2);
  g_free (read_only_error);

  auto recovery_recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recovery_recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts ORDER BY value");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 2);
    g_assert_cmpstr (result->GetValue (0, 0).ToString ().c_str (), ==, "42");
    g_assert_cmpstr (result->GetValue (0, 1).ToString ().c_str (), ==, "99");
  }
  gboolean recovery_wal_open = FALSE;
  gboolean recovery_wal_read = FALSE;
  gboolean recovery_wal_write = FALSE;
  gboolean recovery_wal_sync = FALSE;
  gboolean recovery_main_write = FALSE;
  gboolean recovery_main_sync_after_write = FALSE;
  gboolean recovery_wal_remove_after_sync = FALSE;
  gboolean recovery_checkpoint_noop = FALSE;
  for (const auto &event : recovery_recorder->events) {
    assert_source_152_plain_lifecycle_event (event, database);
    if (event.path == checkpoint) {
      g_assert_cmpstr (event.operation.c_str (), ==, "try-remove");
      g_assert_cmpint (event.outcome, ==, 0);
      g_assert_true (recovery_wal_write && recovery_wal_sync);
      g_assert_false (recovery_checkpoint_noop);
      recovery_checkpoint_noop = TRUE;
      continue;
    }
    assert_live_wal_path (event, database);
    if (event.outcome != -1) {
      g_assert_cmpstr (event.operation.c_str (), ==, "try-remove");
      g_assert_true (event.path == wal.string ());
      g_assert_cmpint (event.outcome, ==, 1);
      g_assert_true (recovery_main_sync_after_write);
    }
    recovery_wal_open = recovery_wal_open || (event.path == wal.string ()
        && has_operation (event, "open"));
    recovery_wal_read = recovery_wal_read || (event.path == wal.string ()
        && (has_operation (event, "read") || has_operation (event, "read-at")));
    recovery_wal_write = recovery_wal_write || (event.path == wal.string ()
        && has_operation (event, "write"));
    recovery_wal_sync = recovery_wal_sync || (event.path == wal.string ()
        && has_operation (event, "sync"));
    if (event.path == database.string () && has_operation (event, "write-at"))
      recovery_main_write = TRUE;
    if (event.path == database.string () && has_operation (event, "sync")
        && recovery_main_write)
      recovery_main_sync_after_write = TRUE;
    if (event.path == wal.string () && has_operation (event, "try-remove")
        && recovery_main_sync_after_write && event.outcome == 1) {
      g_assert_false (recovery_wal_remove_after_sync);
      recovery_wal_remove_after_sync = TRUE;
    }
  }
  g_assert_true (recovery_wal_open && recovery_wal_read);
  g_assert_true (recovery_checkpoint_noop);
  g_assert_true (recovery_main_write && recovery_main_sync_after_write
      && recovery_wal_remove_after_sync);
  assert_source_152_control_events (recovery_recorder->controls, 0, 1);
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (database.string () + ".wal.checkpoint"));
  g_assert_false (fs::exists (database.string () + ".wal.recovery"));
  remove_tree (sandbox);
}

int
main (int argc, char **argv)
{
  if (argc == 3 && g_strcmp0 (argv[1], "--crash-writer") == 0)
    return crash_writer_child (argv[2]);
  self_path = argv[0];
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/persistent-db",
      test_recording_filesystem_persistent_database);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/live-wal-read-only-recovery",
      test_recording_filesystem_live_wal_read_only_recovery);
  return g_test_run ();
}
