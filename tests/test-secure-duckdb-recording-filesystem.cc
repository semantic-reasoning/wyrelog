/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This is deliberately a test fixture, not a DuckDB VFS for wyrelog.  It
 * owns a public LocalFileSystem and permits only absolute paths below the
 * per-test directory.  In particular it does not register or route DuckDB
 * subsystems: protocol, compression, subsystem, and ambient-path requests are
 * rejected before they can reach LocalFileSystem.
 * The fixture is source/version pinned; changing DuckDB requires deliberate
 * fixture regeneration and review.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <duckdb.hpp>

#include <algorithm>
#include <filesystem>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

static const gchar *self_path;

namespace fs = std::filesystem;

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5");

struct Event {
  std::string operation;
  std::string path;
  duckdb::idx_t flags = 0;
  duckdb::FileLockType lock = duckdb::FileLockType::NO_LOCK;
  duckdb::FileCompressionType compression = duckdb::FileCompressionType::UNCOMPRESSED;
  int outcome = -1;
  std::string error_class;
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
  gboolean checkpoint_fault_armed = FALSE;
  guint checkpoint_fault_stage = 0;
  guint checkpoint_fault_fires = 0;
  std::string checkpoint_main;
  std::string checkpoint_wal;
};

static void write_trace_or_exit (const RecorderState &recorder, int error_code);
static void write_checkpoint_trace_or_exit (const RecorderState &recorder,
    int error_code);

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
    try {
      auto inner = local_->OpenFile (checked.string (), flags, nullptr);
      record ("open", checked, flags);
      if (!inner)
        return nullptr;
      return duckdb::make_uniq<RecordingFileHandle> (*this, checked.string (),
          flags, std::move (inner));
    } catch (const duckdb::IOException &) {
      record ("open", checked, flags, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      record ("open", checked, flags, 0, "DuckDBException");
      throw;
    }
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
    // DuckDB 1.5.5 asks this exact Linux cgroup probe while sizing its block
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
    if (recorder_->checkpoint_fault_armed && recorder_->checkpoint_fault_stage == 1
        && checked.string () == recorder_->checkpoint_wal + ".checkpoint" && !removed)
      recorder_->checkpoint_fault_stage = 2;
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
    /* Inject only after the OS reports this file's sync complete. */
    local_->FileSync (*recording.inner);
    record ("sync", recording.GetPath ());
    if (!recorder_->checkpoint_fault_armed)
      return;
    if (recording.GetPath () == recorder_->checkpoint_wal
        && recorder_->checkpoint_fault_stage == 0) {
      recorder_->checkpoint_fault_stage = 1;
      return;
    }
    if (recording.GetPath () == recorder_->checkpoint_main
        && recorder_->checkpoint_fault_stage == 2) {
      recorder_->checkpoint_fault_stage = 3;
      return;
    }
    if (recording.GetPath () == recorder_->checkpoint_main
        && recorder_->checkpoint_fault_stage == 3) {
      recorder_->checkpoint_fault_fires++;
      write_checkpoint_trace_or_exit (*recorder_, 110);
      _exit (109);
    }
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
      duckdb::FileOpenFlags flags = {}, int outcome = -1,
      std::string error_class = {})
  {
    recorder_->events.push_back ({ operation, path.string (), flags.GetFlagsInternal (),
        flags.Lock (), flags.Compression (), outcome, std::move (error_class) });
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
assert_source_155_plain_lifecycle_event (const Event &event,
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
assert_source_155_control_events (const std::vector<ControlEvent> &controls,
    size_t baseline, guint database_opens)
{
#ifdef __linux__
  // DBConfig queries this once for default memory and once for its block
  // allocator in each of the two DuckDB 1.5.5 lifecycles above.
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

struct ArtifactSet {
  std::vector<std::pair<std::string, FileIdentity>> files;
};

static ArtifactSet
snapshot_artifacts (const fs::path &root)
{
  ArtifactSet artifacts;
  for (const auto &entry : fs::directory_iterator (root)) {
    g_assert_true (entry.is_regular_file ());
    artifacts.files.push_back ({ entry.path ().filename ().string (),
        snapshot_file (entry.path ()) });
  }
  std::sort (artifacts.files.begin (), artifacts.files.end (),
      [] (const auto &left, const auto &right) { return left.first < right.first; });
  return artifacts;
}

static void
assert_same_artifacts (const ArtifactSet &before, const ArtifactSet &after)
{
  g_assert_cmpuint (after.files.size (), ==, before.files.size ());
  for (size_t i = 0; i < before.files.size (); i++) {
    g_assert_cmpstr (after.files[i].first.c_str (), ==, before.files[i].first.c_str ());
    assert_same_file (before.files[i].second, after.files[i].second);
  }
}

struct TimedLine {
  GMainLoop *loop;
  GCancellable *cancellable;
  gchar *line = NULL;
  GError *error = NULL;
  gboolean complete = FALSE;
  gboolean timed_out = FALSE;
};

static gboolean
timed_line_timeout (gpointer user_data)
{
  auto *state = static_cast<TimedLine *> (user_data);
  state->timed_out = TRUE;
  g_cancellable_cancel (state->cancellable);
  return G_SOURCE_REMOVE;
}

static void
timed_line_finished (GObject *source, GAsyncResult *result, gpointer user_data)
{
  auto *state = static_cast<TimedLine *> (user_data);
  gsize length = 0;
  state->line = g_data_input_stream_read_line_finish (
      G_DATA_INPUT_STREAM (source), result, &length, &state->error);
  state->complete = TRUE;
  g_main_loop_quit (state->loop);
}

static gchar *
read_line_with_timeout (GDataInputStream *stream, guint timeout_ms)
{
  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  TimedLine state { loop, cancellable };
  const guint timeout_id = g_timeout_add (timeout_ms, timed_line_timeout, &state);
  g_data_input_stream_read_line_async (stream, G_PRIORITY_DEFAULT,
      cancellable, timed_line_finished, &state);
  g_main_loop_run (loop);
  if (!state.timed_out)
    g_source_remove (timeout_id);
  g_assert_true (state.complete);
  g_assert_false (state.timed_out);
  g_assert_no_error (state.error);
  g_assert_nonnull (state.line);
  return state.line;
}

struct TimedWait {
  GMainLoop *loop;
  GCancellable *cancellable;
  GError *error = NULL;
  gboolean complete = FALSE;
  gboolean succeeded = FALSE;
  gboolean timed_out = FALSE;
};

static gboolean
timed_wait_timeout (gpointer user_data)
{
  auto *state = static_cast<TimedWait *> (user_data);
  state->timed_out = TRUE;
  g_cancellable_cancel (state->cancellable);
  return G_SOURCE_REMOVE;
}

static void
timed_wait_finished (GObject *source, GAsyncResult *result, gpointer user_data)
{
  auto *state = static_cast<TimedWait *> (user_data);
  state->succeeded = g_subprocess_wait_check_finish (G_SUBPROCESS (source), result,
      &state->error);
  state->complete = TRUE;
  g_main_loop_quit (state->loop);
}

static void
wait_check_with_timeout (GSubprocess *process, guint timeout_ms)
{
  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  TimedWait state { loop, cancellable };
  const guint timeout_id = g_timeout_add (timeout_ms, timed_wait_timeout, &state);
  g_subprocess_wait_check_async (process, cancellable, timed_wait_finished, &state);
  g_main_loop_run (loop);
  if (!state.timed_out)
    g_source_remove (timeout_id);
  g_assert_true (state.complete);
  if (state.timed_out) {
    g_clear_error (&state.error);
    g_subprocess_force_exit (process);
    g_assert_true (g_subprocess_wait (process, NULL, NULL));
    g_error ("holder did not exit after RELEASE within %u ms", timeout_ms);
  }
  g_assert_no_error (state.error);
  g_assert_true (state.succeeded);
}

struct TimedCommunicate {
  GMainLoop *loop;
  GCancellable *cancellable;
  GSubprocess *process;
  GError *error = NULL;
  gchar *stdout_buf = NULL;
  gboolean complete = FALSE;
  gboolean succeeded = FALSE;
  gboolean timed_out = FALSE;
};

static gboolean
timed_communicate_timeout (gpointer user_data)
{
  auto *state = static_cast<TimedCommunicate *> (user_data);
  state->timed_out = TRUE;
  /* A cancelled communicate leaves a live fault-injection child running. */
  g_subprocess_force_exit (state->process);
  g_cancellable_cancel (state->cancellable);
  return G_SOURCE_REMOVE;
}

static void
timed_communicate_finished (GObject *source, GAsyncResult *result,
    gpointer user_data)
{
  auto *state = static_cast<TimedCommunicate *> (user_data);
  state->succeeded = g_subprocess_communicate_utf8_finish (
      G_SUBPROCESS (source), result, &state->stdout_buf, NULL, &state->error);
  state->complete = TRUE;
  g_main_loop_quit (state->loop);
}

static gchar *
communicate_utf8_with_timeout (GSubprocess *process, guint timeout_ms)
{
  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GCancellable) cancellable = g_cancellable_new ();
  TimedCommunicate state { loop, cancellable, process };
  const guint timeout_id = g_timeout_add (timeout_ms, timed_communicate_timeout,
      &state);
  g_subprocess_communicate_utf8_async (process, NULL, cancellable,
      timed_communicate_finished, &state);
  g_main_loop_run (loop);
  if (!state.timed_out)
    g_source_remove (timeout_id);
  g_assert_true (state.complete);
  if (state.timed_out) {
    g_clear_error (&state.error);
    g_free (state.stdout_buf);
    g_autoptr (GError) reap_error = NULL;
    g_assert_true (g_subprocess_wait (process, NULL, &reap_error));
    g_assert_no_error (reap_error);
    g_error ("fault-injection child did not finish within %u ms", timeout_ms);
  }
  g_assert_no_error (state.error);
  g_assert_true (state.succeeded);
  return state.stdout_buf;
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
assert_duckdb_155 (void)
{
  g_assert_cmpstr (duckdb_library_version (), ==, "v1.5.5");
}

static gboolean is_mutation_event (const Event &event);

static int
crash_writer_child (const gchar *sandbox)
{
  if (g_strcmp0 (duckdb_library_version (), "v1.5.5") != 0)
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
    if (dprintf (STDOUT_FILENO, "E\t%s\t%s\t%llu\t%u\t%u\t%d\t%s\n",
            event.operation.c_str (), event.path.c_str (),
            (unsigned long long) event.flags, (unsigned) event.lock,
            (unsigned) event.compression, event.outcome, event.error_class.c_str ()) < 0)
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

static void
write_trace_or_exit (const RecorderState &recorder, int error_code)
{
  for (const auto &event : recorder.events) {
    if (dprintf (STDOUT_FILENO, "E\t%s\t%s\t%llu\t%u\t%u\t%d\t%s\n",
            event.operation.c_str (), event.path.c_str (),
            (unsigned long long) event.flags, (unsigned) event.lock,
            (unsigned) event.compression, event.outcome, event.error_class.c_str ()) < 0)
      _exit (error_code);
  }
  for (const auto &control : recorder.controls) {
    if (dprintf (STDOUT_FILENO, "C\t%s\t%s\n", control.operation.c_str (),
            control.path.c_str ()) < 0)
      _exit (error_code);
  }
  if (dprintf (STDOUT_FILENO, "END\n") < 0)
  _exit (error_code);
}

static void
write_checkpoint_trace_or_exit (const RecorderState &recorder, int error_code)
{
  /* Keep the marker adjacent to the final recorded main-file sync. */
  for (const auto &control : recorder.controls) {
    if (dprintf (STDOUT_FILENO, "C\t%s\t%s\n", control.operation.c_str (),
            control.path.c_str ()) < 0)
      _exit (error_code);
  }
  for (const auto &event : recorder.events) {
    if (dprintf (STDOUT_FILENO, "E\t%s\t%s\t%llu\t%u\t%u\t%d\t%s\n",
            event.operation.c_str (), event.path.c_str (),
            (unsigned long long) event.flags, (unsigned) event.lock,
            (unsigned) event.compression, event.outcome, event.error_class.c_str ()) < 0)
      _exit (error_code);
  }
  if (dprintf (STDOUT_FILENO, "MARKER\tcheckpoint-main-sync-2\t%s\t2\n",
          recorder.checkpoint_main.c_str ()) < 0
      || dprintf (STDOUT_FILENO, "END\n") < 0)
    _exit (error_code);
}

static int
hold_writer_child (const gchar *sandbox)
{
  if (g_strcmp0 (duckdb_library_version (), "v1.5.5") != 0)
    _exit (100);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    duckdb::DuckDB db (database.string (), &config);
    const size_t ready_event_count = recorder->events.size ();
    guint main_write_locks = 0;
    for (const auto &event : recorder->events) {
      if (event.operation == "open" && event.path == database.string ()
          && event.flags == 2307
          && event.lock == duckdb::FileLockType::WRITE_LOCK
          && event.outcome == -1 && event.error_class.empty ())
        main_write_locks++;
    }
    if (main_write_locks != 1)
      _exit (105);
    if (dprintf (STDOUT_FILENO, "READY\n") < 0)
      _exit (101);
    char command[16] = {};
    if (fgets (command, sizeof command, stdin) == NULL
        || strcmp (command, "RELEASE\n") != 0)
      _exit (102);
    if (recorder->events.size () != ready_event_count)
      _exit (104);
    for (size_t i = 0; i < ready_event_count; i++)
      if (recorder->events[i].outcome != -1 || !recorder->events[i].error_class.empty ())
        _exit (104);
  }
  write_trace_or_exit (*recorder, 103);
  _exit (0);
}

static int
checkpoint_crash_child (const gchar *sandbox)
{
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  duckdb::DBConfig config;
  configure_test_database (&config, root, recorder);
  duckdb::DuckDB db (database.string (), &config);
  duckdb::Connection connection (db);
  recorder->checkpoint_main = database.string ();
  recorder->checkpoint_wal = database.string () + ".wal";
  recorder->checkpoint_fault_armed = TRUE;
  auto result = connection.Query ("CHECKPOINT");
  if (result->HasError () || recorder->checkpoint_fault_fires != 1)
    _exit (111);
  _exit (112);
}

static void
parse_child_trace (const gchar *output, std::vector<Event> *events,
    std::vector<ControlEvent> *controls)
{
  g_assert_true (g_str_has_suffix (output, "\n"));
  g_auto (GStrv) lines = g_strsplit (output, "\n", -1);
  gboolean ended = FALSE;
  for (guint i = 0; lines[i] != NULL; i++) {
    if (lines[i][0] == '\0') {
      g_assert_true (ended);
      g_assert_null (lines[i + 1]);
      break;
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
      g_assert_nonnull (fields[7]);
      g_assert_null (fields[8]);
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
          (int) outcome, fields[7] });
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
  assert_duckdb_155 ();
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
    assert_source_155_plain_lifecycle_event (event, database);
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
  assert_source_155_control_events (recorder->controls, control_baseline, 2);

  remove_tree (sandbox);
}

static void
test_recording_filesystem_temporary_spill_cleanup (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-temp-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (sandbox);
  const fs::path root = fs::canonical (sandbox);
  const fs::path temp = root / "tmp";
  g_assert_true (fs::create_directory (temp));
  auto recorder = std::make_shared<RecorderState> ();
  duckdb::DBConfig config;
  configure_test_database (&config, root, recorder);
  duckdb::DuckDB db (nullptr, &config);
  duckdb::Connection connection (db);
  auto setup = connection.Query ("SET memory_limit='1MB'; SET temp_directory='" + temp.string ()
      + "';");
  g_assert_false (setup->HasError ());
  auto result = connection.Query (
      "SELECT i FROM range(1000000) t(i) ORDER BY hash(i) DESC LIMIT 10");
  g_assert_false (result->HasError ());
  g_assert_cmpuint (result->RowCount (), ==, 10);
  gboolean saw_temp = FALSE;
  for (const auto &event : recorder->events) {
    const fs::path path = event.path;
    const std::string path_string = path.string ();
    const std::string root_prefix = root.string () + "/";
    const std::string temp_prefix = temp.string () + "/";
    g_assert_true (path == root || path_string.rfind (root_prefix, 0) == 0);
    if (path_string.rfind (temp_prefix, 0) == 0)
      saw_temp = TRUE;
  }
  g_assert_true (saw_temp);
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
  assert_duckdb_155 ();
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
    assert_source_155_plain_lifecycle_event (event, database);
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
  assert_source_155_control_events (child_controls, 0, 1);
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
  assert_source_155_control_events (read_only_recorder->controls, 0, 1);
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
    assert_source_155_plain_lifecycle_event (event, database);
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
  assert_source_155_control_events (recovery_recorder->controls, 0, 1);
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (database.string () + ".wal.checkpoint"));
  g_assert_false (fs::exists (database.string () + ".wal.recovery"));
  remove_tree (sandbox);
}

static void
test_recording_filesystem_rw_writer_contention (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-writer-lock-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  const ArtifactSet seeded = snapshot_artifacts (root);
  g_assert_cmpuint (seeded.files.size (), ==, 1);
  g_assert_cmpstr (seeded.files[0].first.c_str (), ==, "facts.duckdb");

  const gchar *argv[] = { self_path, "--hold-writer", root.c_str (), NULL };
  g_autoptr (GSubprocess) holder = g_subprocess_newv (argv,
      (GSubprocessFlags) (G_SUBPROCESS_FLAGS_STDIN_PIPE
          | G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE),
      &error);
  g_assert_no_error (error);
  g_autoptr (GDataInputStream) holder_stdout = g_data_input_stream_new (
      g_subprocess_get_stdout_pipe (holder));
  g_autofree gchar *ready = read_line_with_timeout (holder_stdout, 5000);
  g_assert_cmpstr (ready, ==, "READY");
  assert_same_artifacts (seeded, snapshot_artifacts (root));

  auto contender_recorder = std::make_shared<RecorderState> ();
  gboolean contender_opened = FALSE;
  g_autofree gchar *contender_error = NULL;
  try {
    duckdb::DBConfig config;
    configure_test_database (&config, root, contender_recorder);
    duckdb::DuckDB db (database.string (), &config);
    contender_opened = TRUE;
  } catch (const duckdb::IOException &exception) {
    contender_error = g_strdup (exception.what ());
  } catch (const duckdb::Exception &exception) {
    contender_error = g_strdup (exception.what ());
  }
  g_assert_false (contender_opened);
  g_assert_nonnull (contender_error);
  g_assert_true (g_str_has_prefix (contender_error,
      "{\"exception_type\":\"IO\",\"exception_message\":\"Could not set lock on file \\\""));
  guint failed_main_write_locks = 0;
  const std::string main_path = database.string ();
  for (const auto &event : contender_recorder->events) {
    if (event.path != main_path)
      g_error ("unexpected contender path: %s", event.path.c_str ());
    g_assert_true (event.outcome == -1 || event.outcome == 0);
    g_assert_false (is_mutation_event (event));
    if (has_operation (event, "open")) {
      const gboolean allowed_preflight = (event.flags == 129
          && event.lock == duckdb::FileLockType::NO_LOCK)
          || (event.flags == 2307 && event.lock == duckdb::FileLockType::WRITE_LOCK);
      g_assert_true (allowed_preflight);
      if (event.flags == 2307 && event.lock == duckdb::FileLockType::WRITE_LOCK) {
        g_assert_cmpint (event.outcome, ==, 0);
        g_assert_cmpstr (event.error_class.c_str (), ==, "IOException");
        failed_main_write_locks++;
      } else {
        g_assert_cmpint (event.outcome, ==, -1);
        g_assert_true (event.error_class.empty ());
      }
    } else {
      g_assert_cmpint (event.outcome, ==, -1);
      g_assert_true (event.error_class.empty ());
      g_assert_true (has_operation (event, "close") || has_operation (event, "read")
          || has_operation (event, "read-at") || has_operation (event, "size")
          || has_operation (event, "exists") || has_operation (event, "canonicalize")
          || has_operation (event, "separator") || has_operation (event, "on-disk"));
    }
  }
  g_assert_cmpuint (failed_main_write_locks, ==, 1);
  assert_source_155_control_events (contender_recorder->controls, 0, 1);
  assert_same_artifacts (seeded, snapshot_artifacts (root));

  gsize written = 0;
  g_assert_true (g_output_stream_write_all (g_subprocess_get_stdin_pipe (holder),
          "RELEASE\n", 8, &written, NULL, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (written, ==, 8);
  g_assert_true (g_output_stream_close (g_subprocess_get_stdin_pipe (holder), NULL, &error));
  g_assert_no_error (error);
  wait_check_with_timeout (holder, 5000);
  GString *trace_text = g_string_new (NULL);
  while (TRUE) {
    gsize line_length = 0;
    g_autofree gchar *line = g_data_input_stream_read_line (holder_stdout,
        &line_length, NULL, &error);
    g_assert_no_error (error);
    if (line == NULL)
      break;
    g_string_append_len (trace_text, line, line_length);
    g_string_append_c (trace_text, '\n');
  }
  std::vector<Event> holder_events;
  std::vector<ControlEvent> holder_controls;
  parse_child_trace (trace_text->str, &holder_events, &holder_controls);
  g_string_free (trace_text, TRUE);
  guint holder_main_write_locks = 0;
  for (const auto &event : holder_events) {
    assert_source_155_plain_lifecycle_event (event, database);
    assert_live_wal_path (event, database);
    g_assert_cmpint (event.outcome, ==, -1);
    g_assert_true (event.error_class.empty ());
    g_assert_false (is_mutation_event (event));
    if (event.operation == "open" && event.path == database.string ()
        && event.flags == 2307 && event.lock == duckdb::FileLockType::WRITE_LOCK)
      holder_main_write_locks++;
  }
  g_assert_cmpuint (holder_main_write_locks, ==, 1);
  assert_source_155_control_events (holder_controls, 0, 1);
  assert_same_artifacts (seeded, snapshot_artifacts (root));

  auto restored_recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, restored_recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto write = connection.Query ("INSERT INTO facts VALUES (77)");
    g_assert_false (write->HasError ());
    auto read = connection.Query ("SELECT value FROM facts WHERE value = 77");
    g_assert_false (read->HasError ());
    g_assert_cmpuint (read->RowCount (), ==, 1);
  }
  remove_tree (sandbox);
}

static void
test_recording_filesystem_explicit_checkpoint_discovery (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-checkpoint-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = database.string () + ".wal";
  const std::string checkpoint = wal.string () + ".checkpoint";
  const std::string recovery = wal.string () + ".recovery";

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    config.options.checkpoint_on_shutdown = false;
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("INSERT INTO facts VALUES (99)");
    g_assert_false (result->HasError ());
  }
  g_assert_true (fs::exists (wal));
  g_assert_false (fs::exists (checkpoint));
  g_assert_false (fs::exists (recovery));
  const ArtifactSet pre_checkpoint = snapshot_artifacts (root);
  g_assert_cmpuint (pre_checkpoint.files.size (), ==, 2);
  g_assert_cmpstr (pre_checkpoint.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_cmpstr (pre_checkpoint.files[1].first.c_str (), ==, "facts.duckdb.wal");

  auto recorder = std::make_shared<RecorderState> ();
  size_t checkpoint_begin = 0;
  size_t checkpoint_end = 0;
  ArtifactSet post_checkpoint;
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder);
    duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection connection (db);
    checkpoint_begin = recorder->events.size ();
    auto checkpoint_result = connection.Query ("CHECKPOINT");
    g_assert_false (checkpoint_result->HasError ());
    checkpoint_end = recorder->events.size ();
    post_checkpoint = snapshot_artifacts (root);
    g_assert_false (fs::exists (wal));
    g_assert_false (fs::exists (checkpoint));
    g_assert_false (fs::exists (recovery));
    auto rows = connection.Query ("SELECT value FROM facts ORDER BY value");
    g_assert_false (rows->HasError ());
    g_assert_cmpuint (rows->RowCount (), ==, 2);
    g_assert_cmpstr (rows->GetValue (0, 0).ToString ().c_str (), ==, "42");
    g_assert_cmpstr (rows->GetValue (0, 1).ToString ().c_str (), ==, "99");
  }
  g_assert_cmpuint (post_checkpoint.files.size (), ==, 1);
  g_assert_cmpstr (post_checkpoint.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (checkpoint));
  g_assert_false (fs::exists (recovery));
  std::vector<std::string> sync_paths;
  guint checkpoint_noops = 0;
  guint wal_cleanups = 0;
  size_t wal_sync = checkpoint_end;
  size_t checkpoint_noop = checkpoint_end;
  size_t main_sync_one = checkpoint_end;
  size_t main_sync_two = checkpoint_end;
  size_t first_cleanup = checkpoint_end;
  guint main_syncs = 0;
  gboolean saw_wal_write = FALSE;
  guint main_writes = 0;
  for (size_t i = checkpoint_begin; i < checkpoint_end; i++) {
    const auto &event = recorder->events[i];
    assert_source_155_plain_lifecycle_event (event, database);
    g_assert_true (event.path == database.string () || event.path == wal.string ()
        || event.path == checkpoint);
    g_assert_true (event.error_class.empty ());
    const gboolean expected_mutation = (event.path == wal.string ()
          && (event.operation == "write" || event.operation == "sync"
              || event.operation == "try-remove"))
        || (event.path == checkpoint && event.operation == "try-remove")
        || (event.path == database.string ()
            && (event.operation == "write-at" || event.operation == "sync"));
    if (is_mutation_event (event))
      g_assert_true (expected_mutation);
    if (event.path == checkpoint) {
      g_assert_cmpstr (event.operation.c_str (), ==, "try-remove");
      g_assert_cmpint (event.outcome, ==, 0);
      g_assert_cmpuint (event.flags, ==, 0);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
      checkpoint_noops++;
      checkpoint_noop = i;
    } else if (event.path == wal.string () && event.operation == "try-remove") {
      g_assert_cmpint (event.outcome, ==, 1);
      g_assert_cmpuint (wal_cleanups, ==, 0);
      wal_cleanups++;
      first_cleanup = i;
    } else {
      g_assert_cmpint (event.outcome, ==, -1);
    }
    if (event.operation == "sync") {
      g_assert_cmpuint (event.flags, ==, 0);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      if (event.path == wal.string ())
        wal_sync = i;
      else if (event.path == database.string ()) {
        main_syncs++;
        if (main_syncs == 1)
          main_sync_one = i;
        else if (main_syncs == 2)
          main_sync_two = i;
      }
      sync_paths.push_back (event.path);
    }
    if (event.path == wal.string () && event.operation == "write")
      saw_wal_write = TRUE;
    if (event.path == database.string () && event.operation == "write-at")
      main_writes++;
  }
  g_assert_cmpuint (checkpoint_noops, ==, 1);
  g_assert_cmpuint (wal_cleanups, ==, 1);
  g_assert_cmpuint (sync_paths.size (), ==, 3);
  g_assert_true (sync_paths[0] == wal.string ());
  g_assert_true (sync_paths[1] == database.string ());
  g_assert_true (sync_paths[2] == database.string ());
  g_assert_true (saw_wal_write);
  g_assert_cmpuint (main_writes, ==, 3);
  g_assert_cmpuint (main_syncs, ==, 2);
  g_assert_cmpuint (wal_sync, <, checkpoint_noop);
  g_assert_cmpuint (checkpoint_noop, <, main_sync_one);
  g_assert_cmpuint (main_sync_one, <, main_sync_two);
  g_assert_cmpuint (main_sync_two, <, first_cleanup);
  g_assert_cmpuint (first_cleanup + 1, ==, checkpoint_end);
  assert_source_155_control_events (recorder->controls, 0, 1);
  remove_tree (sandbox);
}

static void
test_recording_filesystem_checkpoint_crash_phase_a (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-checkpoint-crash-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (sandbox);
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = database.string () + ".wal";
  {
    auto state = std::make_shared<RecorderState> (); duckdb::DBConfig config;
    configure_test_database (&config, root, state); duckdb::DuckDB db (database.string (), &config);
    duckdb::Connection c (db); g_assert_false (c.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)")->HasError ());
  }
  {
    auto state = std::make_shared<RecorderState> (); duckdb::DBConfig config;
    configure_test_database (&config, root, state); config.options.checkpoint_on_shutdown = false;
    duckdb::DuckDB db (database.string (), &config); duckdb::Connection c (db);
    g_assert_false (c.Query ("INSERT INTO facts VALUES (99)")->HasError ());
  }
  g_assert_true (fs::exists (wal));
  const gchar *argv[] = { self_path, "--checkpoint-crash", root.c_str (), NULL };
  g_autoptr (GSubprocess) child = g_subprocess_newv (argv,
      (GSubprocessFlags) (G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE), &error);
  g_assert_no_error (error);
  g_autofree gchar *output = communicate_utf8_with_timeout (child, 5000);
  g_assert_cmpint (g_subprocess_get_exit_status (child), ==, 109);
  g_auto (GStrv) lines = g_strsplit (output, "\n", -1);
  guint line_count = 0;
  while (lines[line_count] != NULL)
    line_count++;
  g_assert_cmpuint (line_count, >=, 3);
  g_assert_cmpstr (lines[line_count - 1], ==, "");
  g_assert_cmpstr (lines[line_count - 2], ==, "END");
  const std::string database_path = database.string ();
  const std::string expected_marker = std::string ("MARKER\tcheckpoint-main-sync-2\t")
      + database_path + "\t2";
  g_assert_cmpstr (lines[line_count - 3], ==, expected_marker.c_str ());
  GString *trace = g_string_new (NULL);
  for (guint i = 0; i + 3 < line_count; i++) {
    g_string_append (trace, lines[i]);
    g_string_append_c (trace, '\n');
  }
  g_string_append (trace, "END\n");
  std::vector<Event> events; std::vector<ControlEvent> controls;
  parse_child_trace (trace->str, &events, &controls);
  g_string_free (trace, TRUE);
  guint wal_sync = 0;
  guint main_sync = 0;
  guint checkpoint_noop = 0;
  guint wal_writes = 0;
  guint main_writes = 0;
  guint checkpoint_stage = 0;
  for (const auto &event : events) {
    assert_source_155_plain_lifecycle_event (event, database);
    g_assert_true (event.error_class.empty ());
    if (event.operation == "sync" && event.path == wal.string ()) {
      g_assert_cmpuint (checkpoint_stage, ==, 0);
      checkpoint_stage = 1;
      wal_sync++;
    }
    if (event.operation == "try-remove"
        && event.path == database.string () + ".wal.checkpoint") {
      g_assert_cmpint (event.outcome, ==, 0);
      g_assert_cmpuint (checkpoint_stage, ==, 1);
      checkpoint_stage = 2;
      checkpoint_noop++;
    }
    if (event.operation == "sync" && event.path == database.string ()) {
      g_assert_cmpuint (checkpoint_stage, >=, 2);
      g_assert_cmpuint (checkpoint_stage, <, 4);
      checkpoint_stage++;
      main_sync++;
    }
    if (event.operation == "write" && event.path == wal.string ())
      wal_writes++;
    if (event.operation == "write-at" && event.path == database.string ())
      main_writes++;
    g_assert_false (event.operation == "try-remove" && event.path == wal.string ());
  }
  g_assert_cmpuint (wal_sync, ==, 1);
  g_assert_cmpuint (main_sync, ==, 2);
  g_assert_cmpuint (checkpoint_noop, ==, 1);
  g_assert_cmpuint (checkpoint_stage, ==, 4);
  g_assert_false (events.empty ());
  g_assert_cmpstr (events.back ().operation.c_str (), ==, "sync");
  g_assert_cmpstr (events.back ().path.c_str (), ==, database_path.c_str ());
  g_assert_cmpuint (wal_writes, ==, 1);
  g_assert_cmpuint (main_writes, ==, 3);
  const ArtifactSet artifacts = snapshot_artifacts (root);
  g_assert_cmpuint (artifacts.files.size (), ==, 2);
  g_assert_cmpstr (artifacts.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_cmpstr (artifacts.files[1].first.c_str (), ==, "facts.duckdb.wal");
  g_assert_false (fs::exists (database.string () + ".wal.checkpoint"));
  g_assert_false (fs::exists (database.string () + ".wal.recovery"));

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
  gboolean recovery_wal_cleanup = FALSE;
  for (const auto &event : recovery_recorder->events) {
    assert_source_155_plain_lifecycle_event (event, database);
    g_assert_true (event.error_class.empty ());
    recovery_wal_open = recovery_wal_open || (event.path == wal.string ()
        && event.operation == "open");
    recovery_wal_read = recovery_wal_read || (event.path == wal.string ()
        && (event.operation == "read" || event.operation == "read-at"));
    if (event.path == wal.string () && event.operation == "try-remove"
        && event.outcome == 1) {
      recovery_wal_cleanup = TRUE;
    }
  }
  g_assert_true (recovery_wal_open && recovery_wal_read);
  g_assert_true (recovery_wal_cleanup);
  assert_source_155_control_events (recovery_recorder->controls, 0, 1);
  const ArtifactSet recovered = snapshot_artifacts (root);
  g_assert_cmpuint (recovered.files.size (), ==, 1);
  g_assert_cmpstr (recovered.files[0].first.c_str (), ==, "facts.duckdb");
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
  if (argc == 3 && g_strcmp0 (argv[1], "--hold-writer") == 0)
    return hold_writer_child (argv[2]);
  if (argc == 3 && g_strcmp0 (argv[1], "--checkpoint-crash") == 0)
    return checkpoint_crash_child (argv[2]);
  self_path = argv[0];
  g_test_init (&argc, &argv, NULL);
#ifdef __APPLE__
  /* DuckDB 1.5.5's macOS VFS teardown dereferences a null shared_ptr when
   * closing this test's injected filesystem. Keep the portable bridge smoke
   * test enabled while avoiding a known upstream abort on Apple platforms. */
  g_test_message ("Skipping injected-filesystem suite: DuckDB 1.5.5 macOS teardown abort");
  return g_test_run ();
#else
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/persistent-db",
      test_recording_filesystem_persistent_database);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/temporary-spill-cleanup",
      test_recording_filesystem_temporary_spill_cleanup);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/live-wal-read-only-recovery",
      test_recording_filesystem_live_wal_read_only_recovery);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/rw-writer-contention",
      test_recording_filesystem_rw_writer_contention);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/explicit-checkpoint-discovery",
      test_recording_filesystem_explicit_checkpoint_discovery);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/checkpoint-crash-phase-a",
      test_recording_filesystem_checkpoint_crash_phase_a);
  return g_test_run ();
#endif
}
