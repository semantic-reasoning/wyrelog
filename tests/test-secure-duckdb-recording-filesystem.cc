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
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <map>
#include <regex>
#include <sys/stat.h>
#ifndef G_OS_WIN32
#include <unistd.h>
#else
#include <process.h>
#include <io.h>
#include <fcntl.h>

/* GLib child-process tests consume a text trace on stdout.  MSVC has neither
 * POSIX dprintf nor STDOUT_FILENO, so provide the same checked writer without
 * changing the trace language. */
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
static int
dprintf (int fd, const char *format, ...)
{
  if (fd != STDOUT_FILENO)
    return -1;
  va_list arguments;
  va_start (arguments, format);
  gchar *line = g_strdup_vprintf (format, arguments);
  va_end (arguments);
  if (line == NULL)
    return -1;
  const size_t length = strlen (line);
  const size_t written = fwrite (line, 1, length, stdout);
  g_free (line);
  if (written != length || fflush (stdout) != 0)
    return -1;
  return (int) written;
}
#endif
#include <string>
#include <string_view>
#include <stdexcept>
#include <utility>
#include <vector>

#ifndef WYL_DUCKDB_SOURCE_BUILD
#error "recording contract tests require DuckDB's pinned source build"
#endif

static const gchar *self_path;

namespace fs = std::filesystem;

/* GLib's filename and subprocess APIs consume UTF-8 on Windows, whereas a
 * filesystem::path keeps its native wide representation there.  Keep the
 * converted string in the caller for as long as its C pointer is borrowed. */
static std::string
path_to_utf8 (const fs::path &path)
{
#if defined(__cpp_lib_char8_t)
  const auto encoded = path.u8string ();
  return std::string (encoded.begin (), encoded.end ());
#else
  return path.u8string ();
#endif
}

/* Paths cross the DuckDB/GLib boundary as UTF-8.  Do not let the host
 * separator (or the Windows narrow-codepage conversion) leak into the
 * recording grammar: all pathname comparisons below operate on fs::path. */
static fs::path
path_from_utf8 (const std::string &path)
{
  return fs::u8path (path);
}

static std::string
path_with_suffix (const fs::path &path, const char *suffix)
{
  return path_to_utf8 (path) + suffix;
}

static bool
path_is_at_or_below (const std::string &recorded, const fs::path &root)
{
  const fs::path candidate = path_from_utf8 (recorded);
  const fs::path relative = candidate.lexically_relative (root);
  if (relative.empty () || relative.is_absolute ())
    return candidate == root;
  for (const auto &part : relative)
    if (part == "..")
      return false;
  return true;
}

static_assert (std::string_view (DUCKDB_VERSION) == "v1.5.5");
static_assert (WYL_DUCKDB_SOURCE_BUILD == 1,
    "recording contract tests require the pinned DuckDB source build");

/* Assert a result cell renders to an expected string. duckdb::Value::ToString
 * returns a temporary std::string; passing its c_str() straight into
 * g_assert_cmpstr binds the pointer to the macro's internal local and the
 * backing string is freed at the end of that declaration, before the compare
 * runs (clang-cl -Wdangling-gsl). glibc happens to leave the freed buffer
 * intact; the Windows allocator does not, yielding a spurious empty read.
 * Keep the string alive in a named local here. */
static void
assert_value_text (const duckdb::Value &value, const char *expected)
{
  const std::string actual = value.ToString ();
  g_assert_cmpstr (actual.c_str (), ==, expected);
}

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

/* This protocol is deliberately test-only.  It is not an authority layer for
 * the product filesystem: it makes the recording fixture fail before it
 * reaches LocalFileSystem when a source-pinned scenario's next forwarded call
 * differs from its declared token. */
class ForwardExpectation {
  friend class ForwardExpectationBuilder;
  friend class RecordingFileSystem;

private:
  std::string operation;
  std::string raw_path;
  duckdb::idx_t flags = 0;
  duckdb::FileLockType lock = duckdb::FileLockType::NO_LOCK;
  duckdb::FileCompressionType compression =
      duckdb::FileCompressionType::UNCOMPRESSED;
  std::vector<uint64_t> scalars;
  std::string handle;
  std::vector<std::string> paths;
  int terminal_outcome = 1;
  std::string terminal_error;
  std::vector<uint64_t> terminal_scalars;
};

/* The forwarding protocol has enough independent semantic fields that a
 * partial aggregate initializer can accidentally turn an omitted field into
 * an accepted default.  Keep direct-wrapper fixtures honest: FWD requires a
 * deliberate value for every compared field before it can become a token. */
class ForwardExpectationBuilder {
public:
  ForwardExpectationBuilder (std::string operation, std::string raw_path)
  {
    expectation_.operation = std::move (operation);
    expectation_.raw_path = std::move (raw_path);
  }

  ForwardExpectationBuilder &Flags (duckdb::idx_t flags, duckdb::FileLockType lock,
      duckdb::FileCompressionType compression)
  {
    expectation_.flags = flags;
    expectation_.lock = lock;
    expectation_.compression = compression;
    flags_set_ = true;
    return *this;
  }
  ForwardExpectationBuilder &Scalars (std::vector<uint64_t> scalars)
  {
    expectation_.scalars = std::move (scalars);
    scalars_set_ = true;
    return *this;
  }
  ForwardExpectationBuilder &Handle (std::string handle)
  {
    expectation_.handle = std::move (handle);
    handle_set_ = true;
    return *this;
  }
  ForwardExpectationBuilder &Paths (std::vector<std::string> paths)
  {
    expectation_.paths = std::move (paths);
    paths_set_ = true;
    return *this;
  }
  ForwardExpectationBuilder &Completion (int outcome, std::string error,
      std::vector<uint64_t> scalars)
  {
    expectation_.terminal_outcome = outcome;
    expectation_.terminal_error = std::move (error);
    expectation_.terminal_scalars = std::move (scalars);
    completion_set_ = true;
    return *this;
  }
  ForwardExpectation Build ()
  {
    g_assert_true (flags_set_);
    g_assert_true (scalars_set_);
    g_assert_true (handle_set_);
    g_assert_true (paths_set_);
    g_assert_true (completion_set_);
    return std::move (expectation_);
  }

private:
  ForwardExpectation expectation_;
  bool flags_set_ = false;
  bool scalars_set_ = false;
  bool handle_set_ = false;
  bool paths_set_ = false;
  bool completion_set_ = false;
};

static ForwardExpectationBuilder
FWD (const std::string &operation, const std::string &path)
{
  return ForwardExpectationBuilder (operation, path);
}

struct ForwardCompletion {
  size_t token = 0;
  int outcome = 0;
  std::string error;
};

struct RecorderState {
  std::vector<Event> events;
  std::vector<ControlEvent> controls;
  guint rejected = 0;
  guint subsystem_attempts = 0;
  guint home_directory_calls = 0;
  gboolean checkpoint_fault_armed = FALSE;
  guint checkpoint_fault_stage = 0;
  guint checkpoint_fault_fires = 0;
  std::string checkpoint_main;
  std::string checkpoint_wal;
  struct OpenAuthorization {
    duckdb::idx_t flags;
    duckdb::FileLockType lock;
    duckdb::FileCompressionType compression;
    duckdb::CachingMode caching;
  };
  /* This is intentionally empty until a scenario declares the source-pinned
   * tuples it expects to forward.  The recorder is not a general-purpose
   * FileOpenFlags validator: an undeclared tuple is denied before LocalFS. */
  std::vector<OpenAuthorization> open_authorizations;
  gboolean forwarding_protocol_enabled = FALSE;
  std::vector<ForwardExpectation> forwarding_expectations;
  std::vector<ForwardCompletion> forwarding_completions;
  size_t forwarding_cursor = 0;
  guint local_forwards = 0;
};

static void write_trace_or_exit (const RecorderState &recorder, int error_code);
static void write_checkpoint_trace_or_exit (const RecorderState &recorder,
    int error_code);
static void assert_wal_crash_writer_trace_language (const std::vector<Event> &events,
    const std::vector<ControlEvent> &controls, const fs::path &database);

class RecordingFileSystem;

class RecordingFileHandle final : public duckdb::FileHandle {
public:
  RecordingFileHandle (RecordingFileSystem &owner, std::string path,
      duckdb::FileOpenFlags flags, duckdb::unique_ptr<duckdb::FileHandle> inner,
      std::string forwarding_handle = {});

  void Close () override;
  ~RecordingFileHandle () override
  {
    if (!closed)
      Close ();
  }

  duckdb::unique_ptr<duckdb::FileHandle> inner;
  RecordingFileSystem &owner;
  bool closed = false;
  std::string forwarding_handle;
};

class RecordingFileSystem final : public duckdb::FileSystem {
public:
  using duckdb::FileSystem::ListFiles;

  enum class HomeDirectoryBehavior {
    SANDBOX,
    DENY,
  };

  RecordingFileSystem (const std::string &sandbox,
      std::shared_ptr<RecorderState> recorder,
      HomeDirectoryBehavior home_directory_behavior = HomeDirectoryBehavior::SANDBOX)
      : sandbox_ (fs::canonical (path_from_utf8 (sandbox))),
        local_ (duckdb::FileSystem::CreateLocal ()), recorder_ (std::move (recorder)),
        home_directory_behavior_ (home_directory_behavior)
  {
  }

  const std::vector<Event> &events () const { return recorder_->events; }
  guint rejected () const { return recorder_->rejected; }
  guint local_forwards () const { return recorder_->local_forwards; }
  const std::vector<ForwardCompletion> &forwarding_completions () const
  {
    return recorder_->forwarding_completions;
  }
  void EnableForwardingProtocolForTest (std::vector<ForwardExpectation> expectations)
  {
    g_assert_false (recorder_->forwarding_protocol_enabled);
    recorder_->forwarding_protocol_enabled = TRUE;
    recorder_->forwarding_expectations = std::move (expectations);
  }
  void AssertForwardingProtocolCompleteForTest () const
  {
    g_assert_true (recorder_->forwarding_protocol_enabled);
    g_assert_cmpuint (recorder_->forwarding_cursor, ==,
        recorder_->forwarding_expectations.size ());
    g_assert_cmpuint (recorder_->forwarding_completions.size (), ==,
        recorder_->forwarding_expectations.size ());
  }
  bool SupportsListFilesExtendedForTest () const { return SupportsListFilesExtended (); }
  bool ListFilesExtendedForTest (const duckdb::string &directory,
      const std::function<void (duckdb::OpenFileInfo &)> &callback)
  {
    return ListFilesExtended (directory, callback, nullptr);
  }
  bool SupportsGlobExtendedForTest () const { return SupportsGlobExtended (); }
  bool SupportsOpenFileExtendedForTest () const { return SupportsOpenFileExtended (); }
  duckdb::unique_ptr<duckdb::FileHandle> OpenFileExtendedForTest (
      const duckdb::OpenFileInfo &info, duckdb::FileOpenFlags flags)
  {
    return OpenFileExtended (info, flags, nullptr);
  }
  bool IsLocalFileSystem () const override { return true; }
  void CheckListEntryForTest (const std::string &directory, const std::string &entry)
  {
    (void) check_list_entry (check_path (directory), entry);
  }
  void CloseHandle (RecordingFileHandle &handle);
  [[noreturn]] void RejectClosedHandle (const RecordingFileHandle &handle);
  void AuthorizeOpenForScenario (duckdb::FileOpenFlags flags)
  {
    recorder_->open_authorizations.push_back ({ flags.GetFlagsInternal (), flags.Lock (),
        flags.Compression (), flags.GetCachingMode () });
  }
  duckdb::unique_ptr<duckdb::FileHandle> OpenFile (const duckdb::string &path,
      duckdb::FileOpenFlags flags, duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    validate_open_flags (path_to_utf8 (checked), flags);
    const auto token = preflight ("open", path, flags);
    try {
      ++recorder_->local_forwards;
      auto inner = local_->OpenFile (path_to_utf8 (checked), flags, nullptr);
      complete (token, inner ? 1 : 0, {});
      record ("open", checked, flags);
      if (!inner)
        return nullptr;
      return duckdb::make_uniq<RecordingFileHandle> (*this, path_to_utf8 (checked),
          flags, std::move (inner), handle_for_token (token));
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("open", checked, flags, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("open", checked, flags, 0, "DuckDBException");
      throw;
    }
  }

  void Read (duckdb::FileHandle &handle, void *buffer, int64_t bytes,
      duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("read-at", recording.GetPath (), {},
        { (uint64_t) bytes, (uint64_t) location }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->Read (*recording.inner, buffer, bytes, location);
      complete (token, 1, {});
      record ("read-at", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("read-at", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("read-at", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  void Write (duckdb::FileHandle &handle, void *buffer, int64_t bytes,
      duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("write-at", recording.GetPath (), {},
        { (uint64_t) bytes, (uint64_t) location }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->Write (*recording.inner, buffer, bytes, location);
      complete (token, 1, {});
      record ("write-at", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("write-at", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("write-at", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  int64_t Read (duckdb::FileHandle &handle, void *buffer, int64_t bytes) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("read", recording.GetPath (), {},
        { (uint64_t) bytes }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->Read (*recording.inner, buffer, bytes);
      complete (token, 1, {}, { (uint64_t) result });
      record ("read", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("read", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("read", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  int64_t Write (duckdb::FileHandle &handle, void *buffer, int64_t bytes) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("write", recording.GetPath (), {},
        { (uint64_t) bytes }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->Write (*recording.inner, buffer, bytes);
      complete (token, 1, {}, { (uint64_t) result });
      record ("write", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("write", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("write", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  bool Trim (duckdb::FileHandle &handle, duckdb::idx_t offset,
      duckdb::idx_t length) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("trim", recording.GetPath (), {},
        { (uint64_t) offset, (uint64_t) length }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->Trim (*recording.inner, offset, length);
      complete (token, result ? 1 : 0, {});
      record ("trim", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("trim", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("trim", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  int64_t GetFileSize (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("size", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto size = local_->GetFileSize (*recording.inner);
      complete (token, 1, {}, { (uint64_t) size });
      record ("size", recording.GetPath ());
      return size;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("size", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("size", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  duckdb::timestamp_t GetLastModifiedTime (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("last-modified", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->GetLastModifiedTime (*recording.inner);
      complete (token, 1, {});
      record ("last-modified", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("last-modified", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("last-modified", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  duckdb::string GetVersionTag (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("version", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->GetVersionTag (*recording.inner);
      complete (token, 1, {});
      record ("version", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("version", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("version", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  duckdb::FileType GetFileType (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("type", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->GetFileType (*recording.inner);
      complete (token, 1, {});
      record ("type", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("type", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("type", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  duckdb::FileMetadata Stats (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("stats", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->Stats (*recording.inner);
      complete (token, 1, {});
      record ("stats", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("stats", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("stats", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  void Truncate (duckdb::FileHandle &handle, int64_t size) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("truncate", recording.GetPath (), {},
        { (uint64_t) size }, recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->Truncate (*recording.inner, size);
      complete (token, 1, {});
      record ("truncate", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("truncate", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("truncate", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }

  bool DirectoryExists (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("directory-exists", path, {});
    try {
      ++recorder_->local_forwards;
      const bool exists = local_->DirectoryExists (path_to_utf8 (checked), nullptr);
      complete (token, exists ? 1 : 0, {});
      record ("directory-exists", checked, {}, exists ? 1 : 0);
      return exists;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("directory-exists", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("directory-exists", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  void CreateDirectory (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("create-directory", path, {});
    try {
      ++recorder_->local_forwards;
      local_->CreateDirectory (path_to_utf8 (checked), nullptr);
      complete (token, 1, {});
      record ("create-directory", checked, {}, 1);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("create-directory", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("create-directory", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  void CreateDirectoriesRecursive (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("create-directories", path, {});
    try {
      ++recorder_->local_forwards;
      local_->CreateDirectoriesRecursive (path_to_utf8 (checked), nullptr);
      complete (token, 1, {});
      record ("create-directories", checked);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("create-directories", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("create-directories", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  void RemoveDirectory (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("remove-directory", path, {});
    try {
      ++recorder_->local_forwards;
      local_->RemoveDirectory (path_to_utf8 (checked), nullptr);
      complete (token, 1, {});
      record ("remove-directory", checked, {}, 1);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("remove-directory", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("remove-directory", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  bool ListFiles (const duckdb::string &path,
      const std::function<void (const duckdb::string &, bool)> &callback,
      duckdb::FileOpener *opener) override
  {
    (void) opener;
    if (list_invocation_active_)
      reject ("nested ListFiles callback invocation", path);
    const auto checked = check_path (path);
    const auto token = preflight ("list", path, {});
    record ("list", checked);
    list_invocation_active_ = true;
    try {
      ++recorder_->local_forwards;
      const bool completed = local_->ListFiles (path_to_utf8 (checked),
          [this, &callback, &checked] (const duckdb::string &entry, bool is_directory) {
          const auto entry_checked = check_list_entry (checked, entry);
          /* ListFiles' callback is an observable namespace result, not an
           * implementation detail. Record the canonical sandbox entry and
           * type while preserving DuckDB's original callback spelling. */
          const auto entry_token = preflight ("list-entry", entry, {},
              { is_directory ? 1u : 0u });
          record_list_entry (entry_checked, is_directory);
          /* A ListFiles callback is a separate observable completion.  Keep
           * its forwarding token ahead of user code so both success and a
           * thrown callback produce one canonical, identity-checked result. */
          const auto callback_token = preflight ("list-callback-complete", entry, {},
              { is_directory ? 1u : 0u });
          try {
            callback (entry, is_directory);
            complete (entry_token, 1, {});
            complete (callback_token, 1, {});
            record_list_callback_completion (entry_checked, is_directory, 1, {});
          } catch (const duckdb::Exception &) {
            complete (entry_token, 0, "DuckDBException");
            complete (callback_token, 0, "DuckDBException");
            record_list_callback_completion (entry_checked, is_directory, 0,
                "DuckDBException");
            throw;
          } catch (const std::exception &) {
            complete (entry_token, 0, "CallbackException");
            complete (callback_token, 0, "CallbackException");
            record_list_callback_completion (entry_checked, is_directory, 0,
                "CallbackException");
            throw;
          }
        }, nullptr);
      list_invocation_active_ = false;
      complete (token, completed ? 1 : 0, {});
      record ("list-complete", checked, {}, completed ? 1 : 0);
      return completed;
    } catch (const duckdb::IOException &) {
      list_invocation_active_ = false;
      complete (token, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      list_invocation_active_ = false;
      complete (token, 0, "DuckDBException");
      throw;
    } catch (const std::exception &) {
      list_invocation_active_ = false;
      complete (token, 0, "CallbackException");
      throw;
    }
  }

  void MoveFile (const duckdb::string &source, const duckdb::string &target,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto source_checked = check_path (source);
    const auto target_checked = check_path (target);
    const auto token = preflight ("move", source, {}, {}, {}, { target });
    try {
      ++recorder_->local_forwards;
      local_->MoveFile (path_to_utf8 (source_checked), path_to_utf8 (target_checked), nullptr);
      complete (token, 1, {});
      record ("move", source_checked);
      record ("move-target", target_checked);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("move", source_checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("move", source_checked, {}, 0, "DuckDBException");
      throw;
    }
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
      reject ("unapproved cgroup host path: " + path, path);
    const auto checked = check_path (path);
    const auto token = preflight ("exists", path, {});
    bool exists;
    try {
      ++recorder_->local_forwards;
      exists = local_->FileExists (path_to_utf8 (checked), nullptr);
      complete (token, exists ? 1 : 0, {});
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("exists", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("exists", checked, {}, 0, "DuckDBException");
      throw;
    }
    /* Existence is an observable result for every namespace role, not only
     * temporary blocks.  Scenario FSMs therefore bind the exact bool too. */
    record ("exists", checked, {}, exists ? 1 : 0);
    return exists;
  }

  bool IsPipe (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("is-pipe", path, {});
    try {
      ++recorder_->local_forwards;
      const bool result = local_->IsPipe (path_to_utf8 (checked), nullptr);
      complete (token, result ? 1 : 0, {});
      record ("is-pipe", checked, {}, result ? 1 : 0);
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("is-pipe", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("is-pipe", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  void RemoveFile (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("remove", path, {});
    try {
      ++recorder_->local_forwards;
      local_->RemoveFile (path_to_utf8 (checked), nullptr);
      complete (token, 1, {});
      record ("remove", checked);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("remove", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("remove", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  bool TryRemoveFile (const duckdb::string &path,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    const auto token = preflight ("try-remove", path, {});
    bool removed;
    try {
      ++recorder_->local_forwards;
      removed = local_->TryRemoveFile (path_to_utf8 (checked), nullptr);
      complete (token, removed ? 1 : 0, {});
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("try-remove", checked, {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("try-remove", checked, {}, 0, "DuckDBException");
      throw;
    }
    record ("try-remove", checked, {}, removed ? 1 : 0);
    if (recorder_->checkpoint_fault_armed && recorder_->checkpoint_fault_stage == 1
        && path_to_utf8 (checked) == path_with_suffix (
            path_from_utf8 (recorder_->checkpoint_wal), ".checkpoint") && !removed)
      recorder_->checkpoint_fault_stage = 2;
    return removed;
  }

  void RemoveFiles (const duckdb::vector<duckdb::string> &paths,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    duckdb::vector<duckdb::string> checked;
    std::vector<std::string> raw_paths;
    checked.reserve (paths.size ());
    for (const auto &path : paths) {
      const auto checked_path = check_path (path);
      raw_paths.push_back (path);
      checked.push_back (path_to_utf8 (checked_path));
    }
    const std::string raw_path = raw_paths.empty () ? std::string () : raw_paths.front ();
    const auto token = preflight ("remove-many", raw_path, {}, {}, {}, raw_paths);
    try {
      ++recorder_->local_forwards;
      local_->RemoveFiles (checked, nullptr);
      complete (token, 1, {});
      for (const auto &path : checked)
        record ("remove-many", path);
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      throw;
    }
  }

  void FileSync (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    /* Inject only after the OS reports this file's sync complete. */
    const auto token = preflight ("sync", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->FileSync (*recording.inner);
      complete (token, 1, {});
      record ("sync", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("sync", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("sync", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
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
    const auto token = preflight ("separator", path, {});
    try {
      ++recorder_->local_forwards;
      const auto result = local_->PathSeparator (path_to_utf8 (checked));
      complete (token, 1, {});
      record ("separator", checked);
      return result;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("separator", checked, {}, 0, "DuckDBException");
      throw;
    }
  }

  bool IsPathAbsolute (const duckdb::string &path) override
  {
    return path_from_utf8 (path).is_absolute ();
  }

  duckdb::vector<duckdb::OpenFileInfo> Glob (const duckdb::string &path,
      duckdb::FileOpener *opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("glob", checked);
    reject ("glob access is not permitted", path);
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
    recorder_->home_directory_calls++;
    if (home_directory_behavior_ == HomeDirectoryBehavior::DENY)
      reject ("home-directory access is not permitted");
    return path_to_utf8 (sandbox_);
  }

  duckdb::string ExpandPath (const duckdb::string &path) override
  {
    const auto checked = check_path (path);
    record ("expand", checked);
    return path_to_utf8 (checked);
  }

  void Seek (duckdb::FileHandle &handle, duckdb::idx_t location) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("seek", recording.GetPath (), {}, { (uint64_t) location },
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->Seek (*recording.inner, location);
      complete (token, 1, {});
      record ("seek", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("seek", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("seek", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }
  void Reset (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("reset", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      local_->Reset (*recording.inner);
      complete (token, 1, {});
      record ("reset", recording.GetPath ());
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("reset", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("reset", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }
  duckdb::idx_t SeekPosition (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("seek-position", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const auto result = local_->SeekPosition (*recording.inner);
      complete (token, 1, {}, { (uint64_t) result });
      record ("seek-position", recording.GetPath ());
      return result;
    } catch (const duckdb::IOException &) {
      complete (token, 0, "IOException");
      record ("seek-position", recording.GetPath (), {}, 0, "IOException");
      throw;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("seek-position", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
  }
  bool IsManuallySet () override { return true; }
  bool CanSeek () override
  {
    const auto token = preflight ("can-seek", {}, {});
    try {
      ++recorder_->local_forwards;
      const bool result = local_->CanSeek ();
      complete (token, result ? 1 : 0, {});
      return result;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      throw;
    }
  }
  bool OnDiskFile (duckdb::FileHandle &handle) override
  {
    auto &recording = unwrap (handle);
    const auto token = preflight ("on-disk", recording.GetPath (), {}, {},
        recording.forwarding_handle);
    try {
      ++recorder_->local_forwards;
      const bool result = local_->OnDiskFile (*recording.inner);
      complete (token, result ? 1 : 0, {});
      record ("on-disk", recording.GetPath ());
      return result;
    } catch (const duckdb::Exception &) {
      complete (token, 0, "DuckDBException");
      record ("on-disk", recording.GetPath (), {}, 0, "DuckDBException");
      throw;
    }
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
    return path_to_utf8 (checked);
  }

  void SetDisabledFileSystems (const duckdb::vector<duckdb::string> &names) override
  {
    (void) names;
    record_control ("set-disabled-filesystems");
    reject ("disabled filesystem configuration is not permitted");
  }
  bool SubSystemIsDisabled (const duckdb::string &name) override
  {
    record_control ("subsystem-is-disabled", name);
    return true;
  }
  bool IsDisabledForPath (const duckdb::string &path) override
  {
    record_control ("is-disabled-for-path", path);
    return true;
  }

protected:
  duckdb::unique_ptr<duckdb::FileHandle> OpenFileExtended (
      const duckdb::OpenFileInfo &info, duckdb::FileOpenFlags flags,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    return OpenFile (info.path, flags, opener);
  }
  bool SupportsOpenFileExtended () const override { return true; }
  bool ListFilesExtended (const duckdb::string &directory,
      const std::function<void (duckdb::OpenFileInfo &)> &callback,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) callback;
    (void) opener;
    reject ("extended list access is not permitted", directory);
  }
  bool SupportsListFilesExtended () const override { return false; }
  duckdb::unique_ptr<duckdb::MultiFileList> GlobFilesExtended (
      const duckdb::string &path, const duckdb::FileGlobInput &,
      duckdb::optional_ptr<duckdb::FileOpener> opener) override
  {
    (void) opener;
    const auto checked = check_path (path);
    record ("glob-extended", checked);
    reject ("extended glob access is not permitted", path);
  }
  bool SupportsGlobExtended () const override { return true; }

private:
  static constexpr size_t NO_FORWARD_TOKEN = std::numeric_limits<size_t>::max ();

  size_t preflight (const std::string &operation, const std::string &raw_path,
      duckdb::FileOpenFlags flags, const std::vector<uint64_t> &scalars = {},
      const std::string &handle = {}, const std::vector<std::string> &paths = {})
  {
    if (!recorder_->forwarding_protocol_enabled)
      return NO_FORWARD_TOKEN;
    if (recorder_->forwarding_cursor == recorder_->forwarding_expectations.size ())
      reject ("unexpected forwarded operation: " + operation, raw_path, flags);
    const size_t token = recorder_->forwarding_cursor;
    const auto &expected = recorder_->forwarding_expectations[token];
    if (expected.operation != operation || expected.raw_path != raw_path
        || expected.flags != flags.GetFlagsInternal () || expected.lock != flags.Lock ()
        || expected.compression != flags.Compression () || expected.scalars != scalars
        || (operation != "open" && expected.handle != handle) || expected.paths != paths)
      reject ("forwarding token mismatch: " + operation, raw_path, flags);
    ++recorder_->forwarding_cursor;
    return token;
  }

  std::string handle_for_token (size_t token) const
  {
    return token == NO_FORWARD_TOKEN ? std::string () :
        recorder_->forwarding_expectations[token].handle;
  }

  void complete (size_t token, int outcome, const std::string &error,
      const std::vector<uint64_t> &scalars = {})
  {
    if (token == NO_FORWARD_TOKEN)
      return;
    const auto &expected = recorder_->forwarding_expectations[token];
    /* A completion is mandatory even for an exception.  Keep it distinct from
     * the event trace: this checks the forwarding contract, not a later
     * language recognizer. */
    g_assert_cmpint (outcome, ==, expected.terminal_outcome);
    g_assert_cmpstr (error.c_str (), ==, expected.terminal_error.c_str ());
    g_assert_true (scalars == expected.terminal_scalars);
    recorder_->forwarding_completions.push_back ({ token, outcome, error });
  }

  RecordingFileHandle &unwrap (duckdb::FileHandle &handle)
  {
    auto &recording = handle.Cast<RecordingFileHandle> ();
    if (recording.closed)
      reject ("stale closed handle", recording.GetPath (), recording.GetFlags ());
    return recording;
  }

  [[noreturn]] void reject (const std::string &reason, const std::string &path = {},
      duckdb::FileOpenFlags flags = {})
  {
    /* Rejection is itself a closed fixture observation.  It is deliberately
     * recorded before throwing, and never delegates the rejected request to
     * LocalFileSystem.  Keep the raw spelling: it proves that an ambient or
     * traversal path was stopped before canonicalization could hide it. */
    recorder_->events.push_back ({ "deny", path, flags.GetFlagsInternal (), flags.Lock (),
        flags.Compression (), 0, "PermissionException:" + reason });
    ++recorder_->rejected;
    throw duckdb::PermissionException ("test recording filesystem rejected " + reason);
  }

  void validate_open_flags (const std::string &path, duckdb::FileOpenFlags flags)
  {
    const auto authorized = std::any_of (recorder_->open_authorizations.begin (),
        recorder_->open_authorizations.end (), [&flags] (const auto &entry) {
          return entry.flags == flags.GetFlagsInternal () && entry.lock == flags.Lock ()
              && entry.compression == flags.Compression ()
              && entry.caching == flags.GetCachingMode ();
        });
    if (!authorized)
      reject ("unsupported FileOpenFlags", path, flags);
  }

  fs::path check_path (const std::string &raw)
  {
    if (raw.empty () || raw.find ("://") != std::string::npos)
      reject ("ambient or protocol path", raw);
    const fs::path candidate = path_from_utf8 (raw);
    if (!candidate.is_absolute ())
      reject ("relative path", raw);
    for (const auto &part : candidate) {
      if (part == "..")
        reject ("parent traversal", raw);
    }
    const fs::path normalized = candidate.lexically_normal ();
    const fs::path relative = normalized.lexically_relative (sandbox_);
    if (relative.is_absolute ())
      reject ("ambient path", raw);
    for (const auto &part : relative) {
      if (part == "..")
        reject ("outside sandbox: " + raw, raw);
    }
    fs::path probe = sandbox_;
    for (const auto &part : relative) {
      probe /= part;
      std::error_code error;
      const auto status = fs::symlink_status (probe, error);
      if (!error && fs::is_symlink (status))
        reject ("symbolic-link path", raw);
    }
    return normalized;
  }

  fs::path check_list_entry (const fs::path &directory, const std::string &entry)
  {
    const fs::path candidate = path_from_utf8 (entry);
    if (candidate.empty ())
      reject ("empty list entry", entry);
    if (candidate.is_absolute ())
      return check_path (entry);
    for (const auto &part : candidate)
      if (part == "..")
        reject ("parent traversal in list entry", entry);
    return check_path (path_to_utf8 (directory / candidate));
  }

  void record (const std::string &operation, const fs::path &path,
      duckdb::FileOpenFlags flags = {}, int outcome = -1,
      std::string error_class = {})
  {
    record_observation (operation, path, flags.GetFlagsInternal (), flags.Lock (),
        flags.Compression (), outcome, std::move (error_class));
  }
  void record_list_callback_completion (const fs::path &path, bool is_directory,
      int outcome, std::string error_class)
  {
    /* The callback result has no FileOpenFlags, but its entry type is part of
     * the observed ListFiles contract. Keep that type in the canonical event
     * flags field so source-trace consumers can bind path, type, and result. */
    record_observation ("list-callback-complete", path, is_directory ? 1 : 0,
        duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED,
        outcome, std::move (error_class));
  }
  void record_list_entry (const fs::path &path, bool is_directory)
  {
    /* The entry and its callback completion must agree on this type. The
     * outcome retains the historical source observation while flags carries
     * the type for the paired lifecycle recognizer. */
    record_observation ("list-entry", path, is_directory ? 1 : 0,
        duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED,
        is_directory ? 1 : 0, {});
  }
  void record_observation (const std::string &operation, const fs::path &path,
      duckdb::idx_t flags, duckdb::FileLockType lock,
      duckdb::FileCompressionType compression, int outcome, std::string error_class)
  {
    recorder_->events.push_back ({ operation, path_to_utf8 (path), flags, lock,
        compression, outcome, std::move (error_class) });
    if (g_getenv ("WYL_DUCKDB_RECORDING_TRACE") != NULL) {
      const auto &event = recorder_->events.back ();
      g_printerr ("TRACE\t%s\t%s\t%llu\t%u\t%u\t%d\t%s\n",
          event.operation.c_str (), event.path.c_str (),
          (unsigned long long) event.flags, (unsigned) event.lock,
          (unsigned) event.compression, event.outcome, event.error_class.c_str ());
    }
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
  HomeDirectoryBehavior home_directory_behavior_;
  bool list_invocation_active_ = false;
};

RecordingFileHandle::RecordingFileHandle (RecordingFileSystem &owner,
    std::string path, duckdb::FileOpenFlags flags,
    duckdb::unique_ptr<duckdb::FileHandle> inner_handle,
    std::string protocol_handle)
    : FileHandle (owner, std::move (path), flags), inner (std::move (inner_handle)), owner (owner),
      forwarding_handle (std::move (protocol_handle))
{
}

void
RecordingFileHandle::Close ()
{
  if (closed)
    owner.RejectClosedHandle (*this);
  closed = true;
  owner.CloseHandle (*this);
}

void
RecordingFileSystem::CloseHandle (RecordingFileHandle &handle)
{
  const auto checked = check_path (handle.GetPath ());
  const auto token = preflight ("close", handle.GetPath (), handle.GetFlags (), {},
      handle.forwarding_handle);
  try {
    ++recorder_->local_forwards;
    handle.inner->Close ();
    complete (token, 1, {});
    record ("close", checked, handle.GetFlags ());
  } catch (const duckdb::IOException &) {
    complete (token, 0, "IOException");
    record ("close", checked, handle.GetFlags (), 0, "IOException");
    throw;
  } catch (const duckdb::Exception &) {
    complete (token, 0, "DuckDBException");
    record ("close", checked, handle.GetFlags (), 0, "DuckDBException");
    throw;
  }
}

[[noreturn]] void
RecordingFileSystem::RejectClosedHandle (const RecordingFileHandle &handle)
{
  reject ("double close", handle.GetPath (), handle.GetFlags ());
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

static std::string
outside_sandbox_probe_path (const char *leaf)
{
  /* A literal "/tmp/..." is a real absolute path on POSIX but, lacking a
   * drive letter, is only drive-relative on Windows -- std::filesystem
   * then misclassifies it as a relative path before the sandbox-boundary
   * check ever runs. A sibling of the platform temp directory is
   * genuinely absolute, and genuinely outside this test's sandbox root
   * (which lives one level deeper), on every platform. */
  return path_to_utf8 (fs::temp_directory_path () / leaf);
}

static void
assert_rejected_without_forwarding (RecordingFileSystem &filesystem,
    const std::string &path, const gchar *reason)
{
  const auto event_count = filesystem.events ().size ();
  const auto rejected = filesystem.rejected ();
  try {
    filesystem.FileExists (path, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::Exception &) {
  }
  g_assert_cmpuint (filesystem.rejected (), ==, rejected + 1);
  g_assert_cmpuint (filesystem.events ().size (), ==, event_count + 1);
  const auto &denied = filesystem.events ().back ();
  g_assert_cmpstr (denied.operation.c_str (), ==, "deny");
  g_assert_cmpstr (denied.path.c_str (), ==, path.c_str ());
  g_assert_cmpuint (denied.flags, ==, 0);
  g_assert_true (denied.lock == duckdb::FileLockType::NO_LOCK);
  g_assert_true (denied.compression == duckdb::FileCompressionType::UNCOMPRESSED);
  g_assert_cmpint (denied.outcome, ==, 0);
  g_autofree gchar *expected = g_strdup_printf ("PermissionException:%s", reason);
  g_assert_cmpstr (denied.error_class.c_str (), ==, expected);
}

static void
assert_open_flags_rejected_without_forwarding (RecordingFileSystem &filesystem,
    const std::string &path, duckdb::FileOpenFlags flags)
{
  const auto event_count = filesystem.events ().size ();
  const auto rejected = filesystem.rejected ();
  try {
    filesystem.OpenFile (path, flags, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (filesystem.rejected (), ==, rejected + 1);
  g_assert_cmpuint (filesystem.events ().size (), ==, event_count + 1);
  const auto &denied = filesystem.events ().back ();
  g_assert_cmpstr (denied.operation.c_str (), ==, "deny");
  g_assert_cmpstr (denied.path.c_str (), ==, path.c_str ());
  g_assert_cmpuint (denied.flags, ==, flags.GetFlagsInternal ());
  g_assert_true (denied.lock == flags.Lock ());
  g_assert_true (denied.compression == flags.Compression ());
  g_assert_cmpint (denied.outcome, ==, 0);
  g_assert_cmpstr (denied.error_class.c_str (), ==,
      "PermissionException:unsupported FileOpenFlags");
}

enum class DirectWrapperDisposition {
  FORWARD_EXACT,
  PREFLIGHT_DENY,
  DETERMINISTIC_NO_FORWARD,
};

struct DirectWrapperManifestEntry {
  const char *wrapper;
  DirectWrapperDisposition disposition;
};

/* This manifest is intentionally separate from source-scenario languages.
 * It documents the direct wrapper contract, so an unrelated DuckDB lifecycle
 * change cannot silently widen the fixture's authority. */
static constexpr DirectWrapperManifestEntry direct_wrapper_manifest[] = {
  { "OpenFile", DirectWrapperDisposition::FORWARD_EXACT },
  { "OpenFileExtended", DirectWrapperDisposition::FORWARD_EXACT },
  { "SupportsOpenFileExtended", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "Read", DirectWrapperDisposition::FORWARD_EXACT },
  { "ReadAt", DirectWrapperDisposition::FORWARD_EXACT },
  { "Write", DirectWrapperDisposition::FORWARD_EXACT },
  { "WriteAt", DirectWrapperDisposition::FORWARD_EXACT },
  { "Trim", DirectWrapperDisposition::FORWARD_EXACT },
  { "FileSync", DirectWrapperDisposition::FORWARD_EXACT },
  { "GetFileSize", DirectWrapperDisposition::FORWARD_EXACT },
  { "GetLastModifiedTime", DirectWrapperDisposition::FORWARD_EXACT },
  { "GetVersionTag", DirectWrapperDisposition::FORWARD_EXACT },
  { "GetFileType", DirectWrapperDisposition::FORWARD_EXACT },
  { "Stats", DirectWrapperDisposition::FORWARD_EXACT },
  { "Truncate", DirectWrapperDisposition::FORWARD_EXACT },
  { "Close", DirectWrapperDisposition::FORWARD_EXACT },
  { "DirectoryExists", DirectWrapperDisposition::FORWARD_EXACT },
  { "CreateDirectory", DirectWrapperDisposition::FORWARD_EXACT },
  { "CreateDirectoriesRecursive", DirectWrapperDisposition::FORWARD_EXACT },
  { "RemoveDirectory", DirectWrapperDisposition::FORWARD_EXACT },
  { "MoveFile", DirectWrapperDisposition::FORWARD_EXACT },
  { "FileExists", DirectWrapperDisposition::FORWARD_EXACT },
  { "RemoveFile", DirectWrapperDisposition::FORWARD_EXACT },
  { "TryRemoveFile", DirectWrapperDisposition::FORWARD_EXACT },
  { "RemoveFiles", DirectWrapperDisposition::FORWARD_EXACT },
  { "ListFiles", DirectWrapperDisposition::FORWARD_EXACT },
  { "ListFilesExtended", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "SupportsListFilesExtended", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "IsPipe", DirectWrapperDisposition::FORWARD_EXACT },
  { "PathSeparator", DirectWrapperDisposition::FORWARD_EXACT },
  { "CanSeek", DirectWrapperDisposition::FORWARD_EXACT },
  { "Seek", DirectWrapperDisposition::FORWARD_EXACT },
  { "Reset", DirectWrapperDisposition::FORWARD_EXACT },
  { "SeekPosition", DirectWrapperDisposition::FORWARD_EXACT },
  { "OnDiskFile", DirectWrapperDisposition::FORWARD_EXACT },
  { "Glob", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "GlobFilesExtended", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "SupportsGlobExtended", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "FileExists(outside)", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "OpenCompressedFile", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "RegisterSubSystem", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "RegisterCompressedSubSystem", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "UnregisterSubSystem", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "ExtractSubSystem", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "SetDisabledFileSystems", DirectWrapperDisposition::PREFLIGHT_DENY },
  { "IsPathAbsolute", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "IsManuallySet", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "IsLocalFileSystem", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "GetName", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "GetHomeDirectory", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "ExpandPath", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "CanonicalizePath", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "SubSystemIsDisabled", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "IsDisabledForPath", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "ListSubSystems", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
  { "CanHandleFile", DirectWrapperDisposition::DETERMINISTIC_NO_FORWARD },
};

static ForwardExpectation
direct_fwd (const std::string &operation, const std::string &path,
    duckdb::idx_t flags, duckdb::FileLockType lock,
    duckdb::FileCompressionType compression, std::vector<uint64_t> scalars,
    std::string handle, std::vector<std::string> paths, int outcome,
    std::string error, std::vector<uint64_t> terminal_scalars)
{
  return FWD (operation, path).Flags (flags, lock, compression)
      .Scalars (std::move (scalars)).Handle (std::move (handle))
      .Paths (std::move (paths)).Completion (outcome, std::move (error),
          std::move (terminal_scalars)).Build ();
}

static void
test_recording_filesystem_direct_wrapper_dispositions (void)
{
  g_assert_cmpuint (G_N_ELEMENTS (direct_wrapper_manifest), ==, 56);
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-direct-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  const std::string database_utf8 = path_to_utf8 (database);
  duckdb::FileOpenFlags flags (11);
  const auto no_lock = duckdb::FileLockType::NO_LOCK;
  const auto plain = duckdb::FileCompressionType::UNCOMPRESSED;

  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (path_to_utf8 (root), recorder);
  filesystem.AuthorizeOpenForScenario (flags);
  filesystem.EnableForwardingProtocolForTest ({
      direct_fwd ("open", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "direct-main", {}, 1, "", {}),
      direct_fwd ("write", database_utf8, 0, no_lock, plain, { 3 }, "direct-main",
          {}, 1, "", { 3 }),
      direct_fwd ("sync", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", {}),
      direct_fwd ("read-at", database_utf8, 0, no_lock, plain, { 3, 0 },
          "direct-main", {}, 1, "", {}),
      direct_fwd ("size", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", { 3 }),
      direct_fwd ("last-modified", database_utf8, 0, no_lock, plain, {},
          "direct-main", {}, 1, "", {}),
      direct_fwd ("version", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", {}),
      direct_fwd ("type", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", {}),
      direct_fwd ("stats", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", {}),
      direct_fwd ("is-pipe", database_utf8, 0, no_lock, plain, {}, {}, {}, 0, "", {}),
      direct_fwd ("separator", database_utf8, 0, no_lock, plain, {}, {}, {}, 1, "", {}),
      direct_fwd ("can-seek", "", 0, no_lock, plain, {}, {}, {}, 1, "", {}),
      direct_fwd ("on-disk", database_utf8, 0, no_lock, plain, {}, "direct-main", {},
          1, "", {}),
      direct_fwd ("close", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "direct-main", {}, 1, "", {}),
  });
  auto handle = filesystem.OpenFile (database_utf8, flags, nullptr);
  const char payload[] = "abc";
  char readback[3] = {};
  g_assert_cmpint (filesystem.Write (*handle, (void *) payload, 3), ==, 3);
  filesystem.FileSync (*handle);
  filesystem.Read (*handle, readback, 3, 0);
  g_assert_cmpmem (readback, 3, payload, 3);
  g_assert_cmpint (filesystem.GetFileSize (*handle), ==, 3);
  (void) filesystem.GetLastModifiedTime (*handle);
  (void) filesystem.GetVersionTag (*handle);
  (void) filesystem.GetFileType (*handle);
  (void) filesystem.Stats (*handle);
  g_assert_false (filesystem.IsPipe (database_utf8, nullptr));
  const auto separator = filesystem.PathSeparator (database_utf8);
  g_assert_false (separator.empty ());
  g_assert_true (filesystem.CanSeek ());
  g_assert_true (filesystem.OnDiskFile (*handle));
  handle->Close ();
  filesystem.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (filesystem.local_forwards (), ==, 14);

  /* Exhaustion is a pre-forward failure, even though the preceding token was
   * valid and fully completed. */
  const guint forwards_after_complete = filesystem.local_forwards ();
  try {
    (void) filesystem.FileExists (database_utf8, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (filesystem.local_forwards (), ==, forwards_after_complete);

  const fs::path directory = root / "namespace";
  const fs::path source = directory / "source";
  const fs::path target = directory / "target";
  const fs::path nested_directory = directory / "nested" / "leaf";
  const std::string directory_utf8 = path_to_utf8 (directory);
  const std::string source_utf8 = path_to_utf8 (source);
  const std::string target_utf8 = path_to_utf8 (target);
  const std::string nested_directory_utf8 = path_to_utf8 (nested_directory);
  auto names_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem names (path_to_utf8 (root), names_recorder);
  names.EnableForwardingProtocolForTest ({
      direct_fwd ("directory-exists", directory_utf8, 0, no_lock, plain, {}, {}, {},
          0, "", {}),
      direct_fwd ("create-directory", directory_utf8, 0, no_lock, plain, {}, {}, {},
          1, "", {}),
      direct_fwd ("create-directories", nested_directory_utf8, 0, no_lock, plain, {}, {}, {},
          1, "", {}),
      direct_fwd ("move", source_utf8, 0, no_lock, plain, {}, {}, { target_utf8 }, 1,
          "", {}),
      direct_fwd ("remove", target_utf8, 0, no_lock, plain, {}, {}, {}, 1, "", {}),
      direct_fwd ("remove-directory", nested_directory_utf8, 0, no_lock, plain, {}, {}, {},
          1, "", {}),
      direct_fwd ("remove-directory", directory_utf8, 0, no_lock, plain, {}, {}, {},
          1, "", {}),
  });
  g_assert_false (names.DirectoryExists (directory_utf8, nullptr));
  names.CreateDirectory (directory_utf8, nullptr);
  names.CreateDirectoriesRecursive (nested_directory_utf8, nullptr);
  g_assert_true (g_file_set_contents (source_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);
  names.MoveFile (source_utf8, target_utf8, nullptr);
  names.RemoveFile (target_utf8, nullptr);
  names.RemoveDirectory (nested_directory_utf8, nullptr);
  names.RemoveDirectory (directory_utf8, nullptr);
  names.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (names.local_forwards (), ==, 7);

  /* The public OpenFileInfo overload reaches this protected virtual hook;
   * prove it takes the same preflighted, exact-forward path as OpenFile. */
  auto extended_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem extended (path_to_utf8 (root), extended_recorder);
  extended.AuthorizeOpenForScenario (flags);
  extended.EnableForwardingProtocolForTest ({
      direct_fwd ("open", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "extended-main", {}, 1, "", {}),
      direct_fwd ("close", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "extended-main", {}, 1, "", {}),
  });
  duckdb::OpenFileInfo extended_info (database_utf8);
  auto extended_handle = extended.OpenFileExtendedForTest (extended_info, flags);
  extended_handle->Close ();
  extended.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (extended.local_forwards (), ==, 2);

  const guint denied_before = filesystem.local_forwards ();
  try {
    (void) filesystem.Glob (database_utf8, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  try {
    (void) filesystem.FileExists ("/tmp/wyl-direct-deny", nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (filesystem.local_forwards (), ==, denied_before);
  g_assert_true (filesystem.IsPathAbsolute (database_utf8));
  g_assert_true (filesystem.IsManuallySet ());
  g_assert_true (filesystem.IsLocalFileSystem ());
  const std::string filesystem_name = filesystem.GetName ();
  g_assert_cmpstr (filesystem_name.c_str (), ==,
      "wyrelog-test-recording-filesystem");
  g_assert_false (filesystem.SupportsListFilesExtendedForTest ());
  g_assert_true (filesystem.SupportsGlobExtendedForTest ());
  g_assert_true (filesystem.SupportsOpenFileExtendedForTest ());
  const auto home = filesystem.GetHomeDirectory ();
  const auto expanded = filesystem.ExpandPath (database_utf8);
  const auto canonicalized = filesystem.CanonicalizePath (database_utf8, nullptr);
  const std::string root_utf8 = path_to_utf8 (root);
  g_assert_cmpstr (home.c_str (), ==, root_utf8.c_str ());
  g_assert_cmpstr (expanded.c_str (), ==, database_utf8.c_str ());
  g_assert_cmpstr (canonicalized.c_str (), ==, database_utf8.c_str ());
  g_assert_true (filesystem.SubSystemIsDisabled ("httpfs"));
  g_assert_true (filesystem.IsDisabledForPath (database_utf8));
  g_assert_cmpuint (filesystem.ListSubSystems ().size (), ==, 0);
  g_assert_false (filesystem.CanHandleFile (database_utf8));
  g_assert_cmpuint (filesystem.local_forwards (), ==, denied_before);

  const fs::path list_directory = root / "direct-list";
  const fs::path list_entry = list_directory / "entry";
  const std::string list_directory_utf8 = path_to_utf8 (list_directory);
  const std::string list_entry_utf8 = path_to_utf8 (list_entry);
  g_assert_true (fs::create_directory (list_directory));
  g_assert_true (g_file_set_contents (list_entry_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);
  auto list_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem list (path_to_utf8 (root), list_recorder);
  list.EnableForwardingProtocolForTest ({
      direct_fwd ("list", list_directory_utf8, 0, no_lock, plain, {}, {}, {}, 1, "", {}),
      direct_fwd ("list-entry", "entry", 0, no_lock, plain, { 0 }, {}, {}, 1, "", {}),
      direct_fwd ("list-callback-complete", "entry", 0, no_lock, plain, { 0 }, {}, {},
          1, "", {}),
  });
  std::function<void (duckdb::OpenFileInfo &)> extended_callback =
      [] (duckdb::OpenFileInfo &info) { g_assert_cmpstr (info.path.c_str (), ==, "entry"); };
  g_assert_true (list.ListFiles (list_directory_utf8, extended_callback, nullptr));
  list.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (list.local_forwards (), ==, 1);
  const guint list_forwards = list.local_forwards ();
  try {
    list.ListFilesExtendedForTest (list_directory_utf8,
        [] (duckdb::OpenFileInfo &) {});
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (list.local_forwards (), ==, list_forwards);

  auto simple_list_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem simple_list (path_to_utf8 (root), simple_list_recorder);
  simple_list.EnableForwardingProtocolForTest ({
      direct_fwd ("list", list_directory_utf8, 0, no_lock, plain, {}, {}, {}, 1, "", {}),
      direct_fwd ("list-entry", "entry", 0, no_lock, plain, { 0 }, {}, {}, 1, "", {}),
      direct_fwd ("list-callback-complete", "entry", 0, no_lock, plain, { 0 }, {}, {},
          1, "", {}),
  });
  g_assert_true (simple_list.ListFiles (list_directory_utf8,
      [] (const duckdb::string &entry, bool is_directory) {
        g_assert_cmpstr (entry.c_str (), ==, "entry");
        g_assert_false (is_directory);
      }, nullptr));
  simple_list.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (simple_list.local_forwards (), ==, 1);

  auto reentrant_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem reentrant (path_to_utf8 (root), reentrant_recorder);
  reentrant.EnableForwardingProtocolForTest ({
      direct_fwd ("list", list_directory_utf8, 0, no_lock, plain, {}, {}, {},
          0, "DuckDBException", {}),
      direct_fwd ("list-entry", "entry", 0, no_lock, plain, { 0 }, {}, {},
          0, "DuckDBException", {}),
      direct_fwd ("list-callback-complete", "entry", 0, no_lock, plain, { 0 }, {}, {},
          0, "DuckDBException", {}),
  });
  try {
    reentrant.ListFiles (list_directory_utf8,
        [&reentrant, &list_directory_utf8] (const duckdb::string &, bool) {
          std::function<void (const duckdb::string &, bool)> no_op =
              [] (const duckdb::string &, bool) {};
          reentrant.ListFiles (list_directory_utf8, no_op, nullptr);
        }, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  reentrant.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (reentrant.local_forwards (), ==, 1);

  for (const auto &attempt : { 0, 1, 2, 3, 4 }) {
    try {
      switch (attempt) {
      case 0:
        filesystem.OpenCompressedFile (duckdb::QueryContext (), {}, false);
        break;
      case 1:
        filesystem.RegisterSubSystem (duckdb::FileSystem::CreateLocal ());
        break;
      case 2:
        filesystem.RegisterSubSystem (duckdb::FileCompressionType::GZIP,
            duckdb::FileSystem::CreateLocal ());
        break;
      case 3:
        filesystem.UnregisterSubSystem ("httpfs");
        break;
      default:
        (void) filesystem.ExtractSubSystem ("httpfs");
        break;
      }
      g_assert_not_reached ();
    } catch (const duckdb::PermissionException &) {
    }
  }
  try {
    filesystem.SetDisabledFileSystems ({ "httpfs" });
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (filesystem.local_forwards (), ==, denied_before);

  /* A LocalFS exception completes exactly its current token; it must not make
   * the next expectation available as an accidental follow-on forward. */
  const fs::path absent = root / "not-present";
  const std::string absent_utf8 = path_to_utf8 (absent);
  auto failure_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem failure (path_to_utf8 (root), failure_recorder);
  failure.EnableForwardingProtocolForTest ({
      direct_fwd ("remove", absent_utf8, 0, no_lock, plain, {}, {}, {}, 0,
          "IOException", {}),
  });
  try {
    failure.RemoveFile (absent_utf8, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::IOException &) {
  }
  failure.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (failure.local_forwards (), ==, 1);
  remove_tree (sandbox);
}

/* The protocol must reject a mismatched next token before LocalFileSystem is
 * reached.  This intentionally exercises the fixture directly: the broader
 * scenario recognizers below remain evidence consumers, while this test proves
 * the preflight/terminal contract itself. */
static void
test_recording_filesystem_forwarding_protocol_preflight (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-forward-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  const std::string database_utf8 = path_to_utf8 (database);
  duckdb::FileOpenFlags flags (11);
  /* DuckDB 1.5.5's LocalFileSystem only implements hole-punch trimming on
   * Linux. macOS and Windows return false without forwarding an error. Keep
   * that source-pinned result exact in the forwarding contract rather than
   * treating an optional filesystem capability as a portable success. */
#if defined(__linux__)
  constexpr int local_trim_outcome = 1;
#else
  constexpr int local_trim_outcome = 0;
#endif

  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (path_to_utf8 (root), recorder);
  filesystem.AuthorizeOpenForScenario (flags);
  filesystem.EnableForwardingProtocolForTest ({
      direct_fwd ("open", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "main-0", {}, 1, "", {}),
      direct_fwd ("close", database_utf8, flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "main-0", {}, 1, "", {}),
  });
  {
    auto handle = filesystem.OpenFile (database_utf8, flags, nullptr);
    g_assert_nonnull (handle);
    handle->Close ();
  }
  filesystem.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (filesystem.local_forwards (), ==, 2);
  g_assert_cmpuint (filesystem.forwarding_completions ().size (), ==, 2);
  g_assert_cmpint (filesystem.forwarding_completions ()[0].outcome, ==, 1);
  g_assert_cmpint (filesystem.forwarding_completions ()[1].outcome, ==, 1);

  auto denied_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem denied (path_to_utf8 (root), denied_recorder);
  denied.AuthorizeOpenForScenario (flags);
  denied.EnableForwardingProtocolForTest ({
      direct_fwd ("open", database_utf8 + ".other", flags.GetFlagsInternal (), flags.Lock (),
          flags.Compression (), {}, "main-0", {}, 1, "", {}),
  });
  try {
    (void) denied.OpenFile (database_utf8, flags, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (denied.local_forwards (), ==, 0);
  g_assert_cmpuint (denied.forwarding_completions ().size (), ==, 0);
  g_assert_cmpuint (denied.events ().size (), ==, 1);
  g_assert_cmpstr (denied.events ().back ().operation.c_str (), ==, "deny");

  auto io_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem io (path_to_utf8 (root), io_recorder);
  io.AuthorizeOpenForScenario (flags);
  io.EnableForwardingProtocolForTest ({
      direct_fwd ("open", database_utf8, flags.GetFlagsInternal (), flags.Lock (), flags.Compression (), {}, "main-io", {}, 1, "", {}),
      direct_fwd ("write", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 3 }, "main-io", {}, 1, "", { 3 }),
      direct_fwd ("sync", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, "main-io", {}, 1, "", {}),
      direct_fwd ("seek", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, "main-io", {}, 1, "", {}),
      direct_fwd ("read", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 3 }, "main-io", {}, 1, "", { 3 }),
      direct_fwd ("write-at", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 1, 1 }, "main-io", {}, 1, "", {}),
      direct_fwd ("read-at", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 3, 0 }, "main-io", {}, 1, "", {}),
      direct_fwd ("seek-position", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, "main-io", {}, 1, "", { 3 }),
      direct_fwd ("trim", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0, 2 }, "main-io", {}, local_trim_outcome, "", {}),
      direct_fwd ("truncate", database_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 2 }, "main-io", {}, 1, "", {}),
      direct_fwd ("close", database_utf8, flags.GetFlagsInternal (), flags.Lock (), flags.Compression (), {}, "main-io", {}, 1, "", {}),
  });
  auto handle = io.OpenFile (database_utf8, flags, nullptr);
  const char payload[] = "abc";
  char buffer[3] = {};
  g_assert_cmpint (io.Write (*handle, (void *) payload, 3), ==, 3);
  io.FileSync (*handle);
  io.Seek (*handle, 0);
  g_assert_cmpint (io.Read (*handle, buffer, 3), ==, 3);
  g_assert_cmpmem (buffer, 3, payload, 3);
  const char replacement = 'Z';
  io.Write (*handle, (void *) &replacement, 1, 1);
  memset (buffer, 0, sizeof buffer);
  io.Read (*handle, buffer, 3, 0);
  g_assert_cmpmem (buffer, 3, "aZc", 3);
  g_assert_cmpuint (io.SeekPosition (*handle), ==, 3);
  g_assert_cmpint (io.Trim (*handle, 0, 2), ==, local_trim_outcome);
  io.Truncate (*handle, 2);
  handle->Close ();
  io.AssertForwardingProtocolCompleteForTest ();
  const guint forwards_before_stale = io.local_forwards ();
  try {
    io.Seek (*handle, 0);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (io.local_forwards (), ==, forwards_before_stale);
  try {
    handle->Close ();
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (io.local_forwards (), ==, forwards_before_stale);

  const fs::path namespace_dir = root / "namespace";
  const fs::path source = namespace_dir / "source";
  const fs::path target = namespace_dir / "target";
  const std::string namespace_utf8 = path_to_utf8 (namespace_dir);
  const std::string source_utf8 = path_to_utf8 (source);
  const std::string target_utf8 = path_to_utf8 (target);
  auto namespace_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem names (path_to_utf8 (root), namespace_recorder);
  names.EnableForwardingProtocolForTest ({
      direct_fwd ("create-directory", namespace_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 1, "", {}),
      direct_fwd ("directory-exists", namespace_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 1, "", {}),
      direct_fwd ("move", source_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, { target_utf8 }, 1, "", {}),
      direct_fwd ("exists", source_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 0, "", {}),
      direct_fwd ("exists", target_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 1, "", {}),
      direct_fwd ("remove-many", target_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, { target_utf8 }, 1, "", {}),
      direct_fwd ("try-remove", target_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 0, "", {}),
      direct_fwd ("remove-directory", namespace_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 1, "", {}),
  });
  names.CreateDirectory (namespace_utf8, nullptr);
  g_assert_true (names.DirectoryExists (namespace_utf8, nullptr));
  g_assert_true (g_file_set_contents (source_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);
  names.MoveFile (source_utf8, target_utf8, nullptr);
  g_assert_false (names.FileExists (source_utf8, nullptr));
  g_assert_true (names.FileExists (target_utf8, nullptr));
  duckdb::vector<duckdb::string> removal = { target_utf8 };
  names.RemoveFiles (removal, nullptr);
  g_assert_false (names.TryRemoveFile (target_utf8, nullptr));
  names.RemoveDirectory (namespace_utf8, nullptr);
  names.AssertForwardingProtocolCompleteForTest ();

  const fs::path bad_one = root / "bad-one";
  const fs::path bad_two = root / "bad-two";
  auto bad_vector_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem bad_vector (path_to_utf8 (root), bad_vector_recorder);
  bad_vector.EnableForwardingProtocolForTest ({
      direct_fwd ("remove-many", path_to_utf8 (bad_one), 0, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, { path_to_utf8 (bad_one) }, 1, "", {}),
  });
  duckdb::vector<duckdb::string> mismatched_removal = {
      path_to_utf8 (bad_one), path_to_utf8 (bad_two) };
  try {
    bad_vector.RemoveFiles (mismatched_removal, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  g_assert_cmpuint (bad_vector.local_forwards (), ==, 0);
  remove_tree (sandbox);
}

/* The scenario streams below are complete source-pinned DuckDB 1.5.5
 * languages: every tuple is consumed once, including the two metadata-only
 * probes caused by the explicitly configured home directory. */
enum class TracePathRole { HOME, HOME_METADATA, MAIN, WAL, CHECKPOINT };

struct ExactTraceToken {
  const char *operation;
  TracePathRole path;
  duckdb::idx_t flags;
  duckdb::FileLockType lock;
  int outcome;
  const char *error_class;
};

static void
assert_exact_trace (const gchar *scenario, const std::vector<Event> &events,
    const fs::path &database, const ExactTraceToken *tokens, size_t token_count)
{
  const std::string home = path_to_utf8 (database.parent_path ());
  const std::string home_metadata = path_to_utf8 (database.parent_path () / ".duckdb");
  const std::string main = path_to_utf8 (database);
  const std::string wal = path_with_suffix (database, ".wal");
  const std::string checkpoint = path_with_suffix (path_from_utf8 (wal), ".checkpoint");
  g_assert_cmpuint (events.size (), ==, token_count);
  for (size_t i = 0; i < token_count; i++) {
    const auto &event = events[i];
    const auto &token = tokens[i];
    const std::string &path = token.path == TracePathRole::HOME ? home :
        token.path == TracePathRole::HOME_METADATA ? home_metadata :
        token.path == TracePathRole::MAIN ? main :
        token.path == TracePathRole::WAL ? wal : checkpoint;
    g_assert_cmpstr (event.operation.c_str (), ==, token.operation);
    g_assert_cmpstr (event.path.c_str (), ==, path.c_str ());
    g_assert_cmpuint (event.flags, ==, token.flags);
    g_assert_true (event.lock == token.lock);
    g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
    g_assert_cmpint (event.outcome, ==, token.outcome);
    g_assert_cmpstr (event.error_class.c_str (), ==, token.error_class);
  }
  (void) scenario;
}

#define H(operation) \
  { operation, TracePathRole::HOME, 0, duckdb::FileLockType::NO_LOCK, -1, "" }
#define D(operation) \
  { operation, TracePathRole::HOME_METADATA, 0, duckdb::FileLockType::NO_LOCK, -1, "" }
#define M(operation, flags, lock, outcome) \
  { operation, TracePathRole::MAIN, flags, duckdb::FileLockType::lock, outcome, "" }
#define W(operation, flags, lock, outcome) \
  { operation, TracePathRole::WAL, flags, duckdb::FileLockType::lock, outcome, "" }
#define C(operation, flags, lock, outcome) \
  { operation, TracePathRole::CHECKPOINT, flags, duckdb::FileLockType::lock, outcome, "" }

static void
assert_writer_contender_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
#ifdef G_OS_WIN32
  /* On Windows the holder's write lock is enforced as a zero file share mode,
   * so the contender's very first metadata read-open is already denied with a
   * sharing violation. It never reaches DuckDB's write-lock acquisition or the
   * intervening read/canonicalize/exists probes the advisory-locked POSIX path
   * performs, so the recorded language is the two home separators plus that one
   * rejected read-open. */
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    { "open", TracePathRole::MAIN, 129, duckdb::FileLockType::NO_LOCK,
        0, "IOException" },
  };
#else
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    { "open", TracePathRole::MAIN, 2307, duckdb::FileLockType::WRITE_LOCK,
        0, "IOException" },
  };
#endif
  assert_exact_trace ("writer-contender", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_writer_holder_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("writer-holder", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

/* The writer that opens after the holder's RELEASE is not merely required to
 * succeed. This is its complete source-pinned 1.5.5 recovery/write/shutdown
 * language, separate from both the holder and the failed contender streams. */
static void
assert_writer_restored_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 2090, WRITE_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("write", 0, NO_LOCK, -1), W ("sync", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("write", 0, NO_LOCK, -1), W ("sync", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("close", 2090, WRITE_LOCK, -1),
    C ("try-remove", 0, NO_LOCK, 0), M ("on-disk", 0, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("sync", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("sync", 0, NO_LOCK, -1),
    W ("try-remove", 0, NO_LOCK, 1), M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("writer-restored", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_persistent_database_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 0),
    W ("try-remove", 0, NO_LOCK, 0), M ("open", 2315, WRITE_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("sync", 0, NO_LOCK, -1),
    W ("open", 2090, WRITE_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("write", 0, NO_LOCK, -1), W ("sync", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("write", 0, NO_LOCK, -1),
    W ("sync", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("write", 0, NO_LOCK, -1), W ("sync", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("close", 2090, WRITE_LOCK, -1),
    C ("try-remove", 0, NO_LOCK, 0), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), W ("try-remove", 0, NO_LOCK, 1),
    M ("close", 2315, WRITE_LOCK, -1), H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("persistent-db", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_crash_writer_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 2090, WRITE_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("write", 0, NO_LOCK, -1), W ("sync", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1),
  };
  assert_exact_trace ("crash-writer", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_live_wal_read_only_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("open", 2433, READ_LOCK, -1),
    M ("size", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), W ("open", 129, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("read", 0, NO_LOCK, -1),
    W ("reset", 0, NO_LOCK, -1), W ("read", 0, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), W ("close", 129, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("close", 2433, READ_LOCK, -1),
  };
  assert_exact_trace ("live-wal-read-only", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_wal_recovery_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), W ("reset", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("close", 129, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("on-disk", 0, NO_LOCK, -1), W ("open", 2090, WRITE_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("write", 0, NO_LOCK, -1),
    W ("sync", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("close", 2090, WRITE_LOCK, -1), C ("try-remove", 0, NO_LOCK, 0),
    M ("on-disk", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), W ("try-remove", 0, NO_LOCK, 1),
    M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("wal-recovery", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

/* These three scenario-owned FSMs deliberately consume the complete VFS
 * lifecycle, rather than accepting an operation language around the query.
 * The trace comes from the pinned DuckDB 1.5.5 source build: startup probes,
 * checkpoint/recovery work, and destructor teardown are all grammar tokens. */
static void
assert_explicit_checkpoint_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), W ("reset", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("close", 129, NO_LOCK, -1), W ("open", 2090, WRITE_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("write", 0, NO_LOCK, -1),
    W ("sync", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("close", 2090, WRITE_LOCK, -1), C ("try-remove", 0, NO_LOCK, 0),
    M ("on-disk", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), W ("try-remove", 0, NO_LOCK, 1),
    M ("on-disk", 0, NO_LOCK, -1), M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("explicit-checkpoint", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_interrupted_checkpoint_child_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), W ("reset", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("close", 129, NO_LOCK, -1), W ("open", 2090, WRITE_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("size", 0, NO_LOCK, -1), W ("write", 0, NO_LOCK, -1),
    W ("sync", 0, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("close", 2090, WRITE_LOCK, -1), C ("try-remove", 0, NO_LOCK, 0),
    M ("on-disk", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    M ("write-at", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1), M ("write-at", 0, NO_LOCK, -1),
    M ("sync", 0, NO_LOCK, -1),
  };
  assert_exact_trace ("interrupted-checkpoint-child", events, database, tokens,
      G_N_ELEMENTS (tokens));
}

static void
assert_interrupted_checkpoint_recovery_exact_trace (const std::vector<Event> &events,
    const fs::path &database)
{
  static const ExactTraceToken tokens[] = {
    H ("separator"), D ("separator"),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("separator", 0, NO_LOCK, -1),
    M ("separator", 0, NO_LOCK, -1), M ("canonicalize", 0, NO_LOCK, -1),
    M ("open", 129, NO_LOCK, -1), M ("read", 0, NO_LOCK, -1),
    M ("close", 129, NO_LOCK, -1), M ("exists", 0, NO_LOCK, 1),
    M ("open", 2307, WRITE_LOCK, -1), M ("size", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("read-at", 0, NO_LOCK, -1), M ("on-disk", 0, NO_LOCK, -1),
    W ("open", 129, NO_LOCK, -1), W ("size", 0, NO_LOCK, -1),
    W ("read", 0, NO_LOCK, -1), C ("open", 129, NO_LOCK, -1),
    W ("close", 129, NO_LOCK, -1), W ("try-remove", 0, NO_LOCK, 1),
    M ("on-disk", 0, NO_LOCK, -1), M ("read-at", 0, NO_LOCK, -1),
    M ("close", 2307, WRITE_LOCK, -1),
  };
  assert_exact_trace ("interrupted-checkpoint-recovery", events, database,
      tokens, G_N_ELEMENTS (tokens));
}

#undef H
#undef D
#undef M
#undef W
#undef C

static gboolean
is_expected_home_metadata_path (const std::string &path, const fs::path &database)
{
  const fs::path candidate = path_from_utf8 (path);
  const fs::path configured_home = database.parent_path ();
  const fs::path secret_root = configured_home / ".duckdb";
  const fs::path secret_store = secret_root / "stored_secrets";
  return candidate == configured_home || candidate == secret_root || candidate == secret_store;
}

static void
assert_source_155_platform_control_language (const std::vector<ControlEvent> &controls,
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
#elif defined(G_OS_WIN32)
  /* Windows LocalFileSystem has no Linux cgroup probe.  The closed Windows
   * control language for these scenarios is the empty suffix. */
  g_assert_cmpuint (controls.size (), ==, baseline);
#else
  /* Other source-build platforms currently share the empty control suffix. */
  g_assert_cmpuint (controls.size (), ==, baseline);
#endif
}

/* A fixture digest deliberately includes every recorded event in order.  The
 * per-test root is made stable before hashing; DuckDB temporary leaf names
 * are deliberately normalized because they are allocator-generated rather
 * than logical VFS tokens. */
static std::string
normalized_trace_digest (const std::vector<Event> &events, const fs::path &root)
{
  GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
  for (const auto &event : events) {
    fs::path recorded = path_from_utf8 (event.path);
    std::string path;
    if (recorded == root) {
      path = "$ROOT";
    } else if (path_is_at_or_below (event.path, root)) {
      const fs::path relative = recorded.lexically_relative (root);
      path = "$ROOT" + path_to_utf8 (fs::path (".") / relative).substr (1);
    } else {
      path = event.path;
    }
    fs::path normalized;
    for (const auto &part : path_from_utf8 (path)) {
      const std::string part_utf8 = path_to_utf8 (part);
      if (part_utf8.rfind ("duckdb_temp_storage_", 0) == 0)
        normalized /= path_from_utf8 ("$DUCKDB_TEMP");
      else
        normalized /= part;
    }
    path = path_to_utf8 (normalized);
#ifdef G_OS_WIN32
    /* The digest is a cross-platform fixture: the recorded VFS event grammar
     * is byte-identical to the POSIX golden except that fs::path rebuilds the
     * normalized path with the native separator. Fold '\\' to '/' here so the
     * one pinned hash covers both hosts. Recorded event paths are left native
     * for the fixed-token structural walks, which compare them verbatim. */
    std::replace (path.begin (), path.end (), '\\', '/');
#endif
    const std::string line = event.operation + "\t" + path + "\t"
        + std::to_string (event.flags) + "\t"
        + std::to_string ((unsigned) event.lock) + "\t"
        + std::to_string ((unsigned) event.compression) + "\t"
        + std::to_string (event.outcome) + "\t" + event.error_class + "\n";
    g_checksum_update (checksum, (const guchar *) line.data (), line.size ());
  }
  const std::string digest = g_checksum_get_string (checksum);
  g_checksum_free (checksum);
  return digest;
}

static void
assert_trace_fixture (const gchar *name, const std::vector<Event> &events,
    const fs::path &root, const gchar *expected)
{
  const std::string actual = normalized_trace_digest (events, root);
  if (g_getenv ("WYL_DUCKDB_RECORDING_TRACE") != NULL)
    g_printerr ("TRACE-DIGEST\t%s\t%s\n", name, actual.c_str ());
  if (expected != NULL)
    g_assert_cmpstr (actual.c_str (), ==, expected);
}

struct FileIdentity {
#ifdef G_OS_WIN32
  /* Windows does not give this test a stable POSIX inode/link/timestamp
   * language. Its closed artifact identity is bytes plus logical size.
   * readable is false when the file was write-locked at snapshot time, in
   * which case only the (stat-derived) size is trustworthy. */
  off_t size;
  bool readable;
  std::string digest;
#else
  dev_t device;
  ino_t inode;
  off_t size;
  mode_t mode;
  nlink_t links;
  time_t modified;
  time_t changed;
  std::string digest;
#endif
};

static FileIdentity
snapshot_file (const fs::path &path)
{
  const std::string utf8_path = path_to_utf8 (path);
  GStatBuf buffer;
  int stat_res = g_stat (utf8_path.c_str (), &buffer);
  g_assert_cmpint (stat_res, ==, 0);
  gchar *contents = NULL;
  gsize length = 0;
  const gboolean read = g_file_get_contents (utf8_path.c_str (), &contents,
      &length, NULL);
#ifdef G_OS_WIN32
  /* DuckDB opens a write-locked database on Windows with a share mode that
   * denies concurrent readers (FileLockType::WRITE_LOCK maps to a zero share
   * mode), so a snapshot taken while the database is held open cannot hash
   * the bytes -- only stat's size is observable. Report the file as unreadable
   * and let assert_same_file fall back to size for that pairing; every
   * snapshot taken with the database closed still carries a content digest. */
  if (!read)
    return { buffer.st_size, false, std::string () };
#else
  g_assert_true (read);
#endif
  g_autofree gchar *digest = g_compute_checksum_for_data (G_CHECKSUM_SHA256,
      (const guchar *) contents, length);
  g_free (contents);
#ifdef G_OS_WIN32
  return { buffer.st_size, true, digest };
#else
  return { buffer.st_dev, buffer.st_ino, buffer.st_size, buffer.st_mode,
      buffer.st_nlink, buffer.st_mtime, buffer.st_ctime, digest };
#endif
}

static void
assert_same_file (const FileIdentity &before, const FileIdentity &after)
{
#ifndef G_OS_WIN32
  g_assert_cmpint (after.device, ==, before.device);
  g_assert_cmpint (after.inode, ==, before.inode);
  g_assert_cmpint (after.size, ==, before.size);
  g_assert_cmpint (after.mode, ==, before.mode);
  g_assert_cmpint (after.links, ==, before.links);
  g_assert_cmpint (after.modified, ==, before.modified);
  g_assert_cmpint (after.changed, ==, before.changed);
  g_assert_cmpstr (after.digest.c_str (), ==, before.digest.c_str ());
#else
  g_assert_cmpint (after.size, ==, before.size);
  /* Compare content only when both snapshots could read the bytes. A snapshot
   * captured while the database was write-locked carries size alone; the size
   * equality above still detects any growth or truncation during contention,
   * and the post-release snapshot (database closed, hence readable) performs
   * the full content comparison against the same baseline. */
  if (before.readable && after.readable)
    g_assert_cmpstr (after.digest.c_str (), ==, before.digest.c_str ());
#endif
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
    artifacts.files.push_back ({ path_to_utf8 (entry.path ().filename ()),
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

static duckdb::FileOpenFlags
source_155_open_flags (duckdb::idx_t flags,
    duckdb::FileLockType lock = duckdb::FileLockType::NO_LOCK)
{
  return duckdb::FileOpenFlags (flags, lock,
      duckdb::FileCompressionType::UNCOMPRESSED);
}

/* Every lifecycle must state its own forwarding authority at construction.
 * Do not turn these into a fixture-wide version vocabulary: the tuple set is
 * part of the scenario's evidence, just like its exact event grammar. */
static void
configure_test_database (duckdb::DBConfig *config, const fs::path &root,
    std::shared_ptr<RecorderState> recorder,
    std::initializer_list<duckdb::FileOpenFlags> open_authorizations)
{
  auto filesystem = duckdb::make_uniq<RecordingFileSystem> (path_to_utf8 (root), recorder);
  for (const auto &flags : open_authorizations)
    filesystem->AuthorizeOpenForScenario (flags);
  config->file_system = std::move (filesystem);
  /* DuckDB's OpenerFileSystem obtains this setting before it forms persistent
   * secret defaults. Pin the metadata-only home path to the fixture so it
   * never synthesizes the host home directory for the bounded recorder. */
  config->SetOption ("home_directory", duckdb::Value (path_to_utf8 (root)));
  config->options.maximum_threads = 1;
  config->options.load_extensions = false;
}

static void
assert_duckdb_155 (void)
{
  g_assert_cmpstr (duckdb_library_version (), ==, "v1.5.5");
}

static int
crash_writer_child (const gchar *sandbox)
{
  if (g_strcmp0 (duckdb_library_version (), "v1.5.5") != 0)
    _exit (90);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  duckdb::DBConfig config;
  configure_test_database (&config, root, recorder, {
      source_155_open_flags (129),
      source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
      source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
  duckdb::DuckDB db (path_to_utf8 (database), &config);
  duckdb::Connection connection (db);
  auto result = connection.Query ("INSERT INTO facts VALUES (99)");
  if (result->HasError () || !fs::exists (path_from_utf8 (path_with_suffix (database, ".wal"))))
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
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    const size_t ready_event_count = recorder->events.size ();
    guint main_write_locks = 0;
    for (const auto &event : recorder->events) {
      if (event.operation == "open" && event.path == path_to_utf8 (database)
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
    for (size_t i = 0; i < ready_event_count; i++) {
      const auto &event = recorder->events[i];
      /* FileExists is the one successful probe whose concrete bool is now
       * part of the source-pinned trace contract. */
      const bool recorded_exists = event.operation == "exists" && event.outcome == 1;
      if ((!recorded_exists && event.outcome != -1) || !event.error_class.empty ())
        _exit (104);
    }
  }
  write_trace_or_exit (*recorder, 103);
  _exit (0);
}

static int
contend_writer_child (const gchar *sandbox)
{
  if (g_strcmp0 (duckdb_library_version (), "v1.5.5") != 0)
    _exit (106);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  /* The holder created and still owns this database. Requiring it to exist
   * before the contending open keeps the Windows rejection check below
   * unambiguous: a "Cannot open file" there can then only be the holder's
   * sharing violation, never a missing-file open failure. */
  if (!fs::exists (database))
    _exit (109);
  auto recorder = std::make_shared<RecorderState> ();
  gboolean opened = FALSE;
  gboolean rejected = FALSE;
  try {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    opened = TRUE;
  } catch (const duckdb::IOException &exception) {
#ifdef G_OS_WIN32
    /* Windows enforces the database write lock through the file share mode, so
     * a contending open is denied at CreateFileW with a sharing violation
     * rather than at DuckDB's advisory-lock step. The trailing OS text is
     * localized (and carries a Restart Manager holder report), so match only
     * the stable, locale-independent prefix. */
    rejected = g_str_has_prefix (exception.what (),
        "{\"exception_type\":\"IO\",\"exception_message\":\"Cannot open file \\\"");
#else
    rejected = g_str_has_prefix (exception.what (),
        "{\"exception_type\":\"IO\",\"exception_message\":\"Could not set lock on file \\\"");
#endif
  } catch (const duckdb::Exception &) {
  }
  if (opened || !rejected)
    _exit (107);
  write_trace_or_exit (*recorder, 108);
  _exit (0);
}

static int
checkpoint_crash_child (const gchar *sandbox)
{
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  duckdb::DBConfig config;
  configure_test_database (&config, root, recorder, {
      source_155_open_flags (129),
      source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
      source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
  duckdb::DuckDB db (path_to_utf8 (database), &config);
  duckdb::Connection connection (db);
  recorder->checkpoint_main = path_to_utf8 (database);
  recorder->checkpoint_wal = path_with_suffix (database, ".wal");
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
assert_read_only_live_wal_trace (const RecorderState &recorder,
    const fs::path &database)
{
  assert_live_wal_read_only_exact_trace (recorder.events, database);
  assert_source_155_platform_control_language (recorder.controls, 0, 1);
}

static void
assert_no_host_home_forwarding (const RecorderState &recorder, const fs::path &sandbox_root)
{
  const fs::path host_home = path_from_utf8 (g_get_home_dir ());
  for (const auto &event : recorder.events) {
    /* The sandbox itself may be nested under the real host home directory
     * (e.g. Windows resolves the per-user TEMP root under the profile
     * directory), so containment within the sandbox is not a leak even
     * though it is also "at or below" host_home. Only a path that escapes
     * the sandbox into the real home tree is the forwarding bug this
     * guards against. */
    if (path_is_at_or_below (event.path, sandbox_root))
      continue;
    g_assert_false (path_is_at_or_below (event.path, host_home));
  }
}

static void
test_recording_filesystem_home_directory_resolution (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-home-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path probe_database = root / "metadata-paths.duckdb";
  g_assert_true (is_expected_home_metadata_path (path_to_utf8 (root), probe_database));
  g_assert_true (is_expected_home_metadata_path (path_to_utf8 (root / ".duckdb"), probe_database));
  g_assert_true (is_expected_home_metadata_path (
      path_to_utf8 (root / ".duckdb" / "stored_secrets"), probe_database));
  g_assert_false (is_expected_home_metadata_path (
      path_to_utf8 (root / ".duckdb" / "unexpected"), probe_database));

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    auto filesystem = duckdb::make_uniq<RecordingFileSystem> (path_to_utf8 (root), recorder);
    filesystem->AuthorizeOpenForScenario (source_155_open_flags (129));
    filesystem->AuthorizeOpenForScenario (source_155_open_flags (2315,
        duckdb::FileLockType::WRITE_LOCK));
    config.file_system = std::move (filesystem);
    config.options.maximum_threads = 1;
    config.options.load_extensions = false;
    duckdb::DuckDB db (path_to_utf8 (root / "unset-home.duckdb"), &config);
    g_assert_cmpuint (recorder->home_directory_calls, ==, 1);
    g_assert_cmpstr (recorder->controls.back ().operation.c_str (), ==, "get-home-directory");
    assert_no_host_home_forwarding (*recorder, root);
  }

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    auto filesystem = duckdb::make_uniq<RecordingFileSystem> (path_to_utf8 (root), recorder,
        RecordingFileSystem::HomeDirectoryBehavior::DENY);
    filesystem->AuthorizeOpenForScenario (source_155_open_flags (129));
    filesystem->AuthorizeOpenForScenario (source_155_open_flags (2315,
        duckdb::FileLockType::WRITE_LOCK));
    config.file_system = std::move (filesystem);
    config.SetOption ("home_directory", duckdb::Value (path_to_utf8 (root)));
    config.options.maximum_threads = 1;
    config.options.load_extensions = false;
    duckdb::DuckDB db (path_to_utf8 (root / "configured-home.duckdb"), &config);
    g_assert_cmpuint (recorder->home_directory_calls, ==, 0);
    assert_no_host_home_forwarding (*recorder, root);
  }

  {
    auto recorder = std::make_shared<RecorderState> ();
    gboolean denied = FALSE;
    try {
      duckdb::DBConfig config;
      auto filesystem = duckdb::make_uniq<RecordingFileSystem> (path_to_utf8 (root), recorder,
          RecordingFileSystem::HomeDirectoryBehavior::DENY);
      filesystem->AuthorizeOpenForScenario (source_155_open_flags (129));
      filesystem->AuthorizeOpenForScenario (source_155_open_flags (2315,
          duckdb::FileLockType::WRITE_LOCK));
      config.file_system = std::move (filesystem);
      config.options.maximum_threads = 1;
      config.options.load_extensions = false;
      duckdb::DuckDB db (path_to_utf8 (root / "denied-home.duckdb"), &config);
    } catch (const duckdb::PermissionException &) {
      denied = TRUE;
    }
    g_assert_true (denied);
    g_assert_cmpuint (recorder->home_directory_calls, ==, 1);
    assert_no_host_home_forwarding (*recorder, root);
  }

  {
    auto local = duckdb::FileSystem::CreateLocal ();
    const duckdb::string home = local->GetHomeDirectory ();
    g_assert_false (home.empty ());
    g_assert_cmpstr (home.c_str (), ==, g_get_home_dir ());
  }

  remove_tree (sandbox);
}

static void
assert_persistent_database_trace_language (const RecorderState &recorder,
    size_t event_baseline, size_t control_baseline, const fs::path &root,
    const fs::path &database)
{
  g_assert_cmpuint (event_baseline, ==, 0);
  assert_persistent_database_exact_trace (recorder.events, database);
  assert_no_host_home_forwarding (recorder, root);
  assert_source_155_platform_control_language (recorder.controls, control_baseline, 2);
}

/* Consume the complete temporary-directory stream.  The exact number and
 * interleaving of DuckDB spill children is allocator dependent, but each
 * child is still a finite state machine: open, zero or more I/O operations,
 * close, then retire.  Keeping that nondeterminism local prevents a broad
 * "under tmp" whitelist from hiding a new VFS token. */
static void
assert_temporary_spill_trace_language (const RecorderState &recorder,
    const fs::path &root, const fs::path &database, const fs::path &temp,
    gboolean absent_root, gboolean seeded_foreign_entries)
{
  enum class FixedPath { ROOT, HOME, MAIN, WAL };
  struct FixedToken {
    FixedPath path;
    const char *operation;
    guint flags;
    unsigned lock;
    int outcome;
  };
  /* Unlike the persistent-db fixture, this is a single DuckDB lifecycle.
   * Keep its non-spill prefix local and exact: the only intentionally dynamic
   * language below is the storage-child lifecycle itself. */
  static const std::vector<FixedToken> existing_prefix = {
    { FixedPath::ROOT, "separator", 0, 0, -1 },
    { FixedPath::HOME, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "open", 129, 0, -1 },
    { FixedPath::MAIN, "read", 0, 0, -1 },
    { FixedPath::MAIN, "close", 129, 0, -1 },
    { FixedPath::MAIN, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "canonicalize", 0, 0, -1 },
    { FixedPath::MAIN, "open", 129, 0, -1 },
    { FixedPath::MAIN, "read", 0, 0, -1 },
    { FixedPath::MAIN, "close", 129, 0, -1 },
    { FixedPath::MAIN, "exists", 0, 0, 1 },
    { FixedPath::MAIN, "open", 2307, 2, -1 },
    { FixedPath::MAIN, "size", 0, 0, -1 },
    { FixedPath::MAIN, "read-at", 0, 0, -1 },
    { FixedPath::MAIN, "read-at", 0, 0, -1 },
    { FixedPath::MAIN, "read-at", 0, 0, -1 },
    { FixedPath::MAIN, "read-at", 0, 0, -1 },
    { FixedPath::WAL, "open", 129, 0, -1 },
  };
  static const std::vector<FixedToken> absent_prefix = {
    { FixedPath::ROOT, "separator", 0, 0, -1 },
    { FixedPath::HOME, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "open", 129, 0, -1 },
    { FixedPath::MAIN, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "separator", 0, 0, -1 },
    { FixedPath::MAIN, "canonicalize", 0, 0, -1 },
    { FixedPath::MAIN, "open", 129, 0, -1 },
    { FixedPath::MAIN, "exists", 0, 0, 0 },
    { FixedPath::WAL, "try-remove", 0, 0, 0 },
    { FixedPath::MAIN, "open", 2315, 2, -1 },
    { FixedPath::MAIN, "write-at", 0, 0, -1 },
    { FixedPath::MAIN, "write-at", 0, 0, -1 },
    { FixedPath::MAIN, "write-at", 0, 0, -1 },
    { FixedPath::MAIN, "sync", 0, 0, -1 },
  };
  const std::string root_path = path_to_utf8 (root);
  const std::string home = path_to_utf8 (root / ".duckdb");
  const std::string main = path_to_utf8 (database);
  const std::string wal = path_with_suffix (database, ".wal");
  const std::vector<FixedToken> &prefix = absent_root ? absent_prefix : existing_prefix;
  auto assert_fixed = [&] (const Event &event, const FixedToken &token) {
    const std::string *expected_path = NULL;
    switch (token.path) {
    case FixedPath::ROOT: expected_path = &root_path; break;
    case FixedPath::HOME: expected_path = &home; break;
    case FixedPath::MAIN: expected_path = &main; break;
    case FixedPath::WAL: expected_path = &wal; break;
    }
    g_assert_cmpstr (event.path.c_str (), ==, expected_path->c_str ());
    g_assert_cmpstr (event.operation.c_str (), ==, token.operation);
    g_assert_cmpuint (event.flags, ==, token.flags);
    g_assert_cmpuint ((unsigned) event.lock, ==, token.lock);
    g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
    g_assert_cmpint (event.outcome, ==, token.outcome);
    g_assert_true (event.error_class.empty ());
  };
  const std::string temp_path = path_to_utf8 (temp);
  const std::string broad_prefix = path_to_utf8 (temp / "duckdb_temp_foreign");
  const std::string foreign = path_to_utf8 (temp / "foreign");
  const std::regex storage_name ("^duckdb_temp_storage_(DEFAULT|S[0-9]+K)-[0-9]+\\.tmp$");
  const std::regex block_name ("^duckdb_temp_block-[0-9]+\\.block$");
  struct ChildState { gboolean live = FALSE; gboolean retired = FALSE; guint opens = 0; guint closes = 0; };
  std::map<std::string, ChildState> storage;
  gboolean saw_main_close = FALSE, suffix_started = FALSE, separator_pending = FALSE;
  gboolean saw_directory_exists = FALSE, saw_create = FALSE, saw_remove_directory = FALSE;
  gboolean saw_storage_open = FALSE, saw_storage_truncate = FALSE, saw_storage_remove = FALSE;
  gboolean saw_storage_write = FALSE;
  gboolean saw_block = FALSE, saw_list = FALSE, list_active = FALSE, saw_list_complete = FALSE;
  gboolean list_callback_pending = FALSE;
  std::string pending_list_callback_path;
  guint pending_list_callback_type = 0;
  gboolean saw_foreign_entry = FALSE, saw_broad_entry = FALSE, saw_broad_remove = FALSE;

  g_assert_cmpuint (recorder.events.size (), >, 0);
  g_assert_cmpuint (recorder.events.size (), >, prefix.size ());
  size_t event_index = 0;
  for (const auto &token : prefix)
    assert_fixed (recorder.events[event_index++], token);
  for (; event_index < recorder.events.size (); event_index++) {
    const auto &event = recorder.events[event_index];
    const fs::path path = path_from_utf8 (event.path);
    const std::string filename = path_to_utf8 (path.filename ());
    /* No ambient path can be smuggled into this scenario. */
    g_assert_true (path_is_at_or_below (event.path, root));

    if (event.path == main) {
      const FixedToken suffix = { FixedPath::MAIN, "close",
          absent_root ? 2315u : 2307u, 2, -1 };
      g_assert_false (suffix_started);
      g_assert_false (separator_pending);
      assert_fixed (event, suffix);
      saw_main_close = suffix_started = TRUE;
      continue;
    }
    g_assert_false (event.path == wal || event.path == path_with_suffix (
        path_from_utf8 (wal), ".checkpoint")
        || is_expected_home_metadata_path (event.path, database));

    if (event.path == temp_path) {
      g_assert_cmpuint (event.flags, ==, 0);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
      g_assert_true (event.error_class.empty ());
      if (event.operation == "directory-exists") {
        g_assert_false (suffix_started);
        g_assert_false (saw_directory_exists);
        g_assert_cmpint (event.outcome, ==, absent_root ? 0 : 1);
        saw_directory_exists = TRUE;
      } else if (event.operation == "create-directory") {
        g_assert_false (suffix_started);
        g_assert_true (absent_root && saw_directory_exists && !saw_create);
        g_assert_cmpint (event.outcome, ==, 1);
        saw_create = TRUE;
      } else if (event.operation == "separator") {
        g_assert_false (separator_pending);
        g_assert_true (saw_directory_exists);
        if (suffix_started)
          g_assert_true (saw_list_complete);
        g_assert_cmpint (event.outcome, ==, -1);
        separator_pending = TRUE;
      } else if (event.operation == "list") {
        g_assert_true (seeded_foreign_entries && suffix_started && !list_active);
        g_assert_cmpint (event.outcome, ==, -1);
        saw_list = list_active = TRUE;
      } else if (event.operation == "list-complete") {
        g_assert_true (suffix_started && list_active && !list_callback_pending);
        g_assert_cmpint (event.outcome, ==, 1);
        list_active = FALSE;
        saw_list_complete = TRUE;
      } else if (event.operation == "remove-directory") {
        g_assert_true (absent_root && saw_main_close && !list_active && !separator_pending);
        g_assert_cmpint (event.outcome, ==, 1);
        saw_remove_directory = TRUE;
      } else {
        g_assert_not_reached ();
      }
      continue;
    }

    /* The only children admitted by this scenario are the source-pinned
     * storage/block grammar plus the two deliberately seeded boundary names. */
    g_assert_true (path_is_at_or_below (event.path, temp));
    if (event.operation == "open" || event.operation == "close")
      g_assert_cmpuint (event.flags, ==, 11);
    else if (event.operation == "list-entry" || event.operation == "list-callback-complete")
      g_assert_cmpuint (event.flags, <=, 1);
    else
      g_assert_cmpuint (event.flags, ==, 0);
    g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
    g_assert_true (event.error_class.empty ());
    if (event.operation == "list-entry") {
      g_assert_false (separator_pending);
      g_assert_true (suffix_started && list_active && !list_callback_pending);
      g_assert_cmpint (event.outcome, ==, 0);
      if (event.path == foreign) {
        g_assert_true (seeded_foreign_entries);
        saw_foreign_entry = TRUE;
      } else if (event.path == broad_prefix) {
        g_assert_true (seeded_foreign_entries);
        saw_broad_entry = TRUE;
      } else {
        g_assert_true (std::regex_match (filename, storage_name));
      }
      pending_list_callback_path = event.path;
      pending_list_callback_type = event.flags;
      list_callback_pending = TRUE;
      continue;
    }
    if (event.operation == "list-callback-complete") {
      g_assert_false (separator_pending);
      g_assert_true (suffix_started && list_active && list_callback_pending);
      g_assert_cmpstr (event.path.c_str (), ==, pending_list_callback_path.c_str ());
      g_assert_cmpuint (event.flags, ==, pending_list_callback_type);
      g_assert_cmpint (event.outcome, ==, 1);
      list_callback_pending = FALSE;
      continue;
    }
    if (event.path == broad_prefix) {
      /* This observes DuckDB's broad cleanup prefix; it is evidence, not a
       * capability grant for #629's bounded temporary authority. */
      g_assert_true (seeded_foreign_entries && suffix_started && saw_list_complete
          && event.operation == "remove-many");
      g_assert_true (separator_pending);
      g_assert_cmpint (event.outcome, ==, -1);
      saw_broad_remove = TRUE;
      separator_pending = FALSE;
      continue;
    }
    if (std::regex_match (filename, block_name)) {
      g_assert_false (suffix_started);
      g_assert_true (separator_pending);
      g_assert_cmpstr (event.operation.c_str (), ==, "exists");
      g_assert_cmpint (event.outcome, ==, 0);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      saw_block = TRUE;
      separator_pending = FALSE;
      continue;
    }
    g_assert_true (std::regex_match (filename, storage_name));
    g_assert_false (suffix_started);
    auto &state = storage[filename];
    if (event.operation == "open") {
      g_assert_true (separator_pending);
      if (state.retired)
        state = {};
      g_assert_false (state.live);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      g_assert_cmpint (event.outcome, ==, -1);
      state.live = TRUE;
      state.opens++;
      saw_storage_open = TRUE;
      separator_pending = FALSE;
    } else if (event.operation == "close") {
      g_assert_false (separator_pending);
      g_assert_false (state.retired);
      g_assert_true (state.live);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      g_assert_cmpint (event.outcome, ==, -1);
      state.live = FALSE;
      state.closes++;
    } else if (event.operation == "remove") {
      g_assert_false (separator_pending);
      g_assert_false (state.retired);
      g_assert_false (state.live);
      g_assert_cmpuint (state.closes, >, 0);
      g_assert_cmpint (event.outcome, ==, -1);
      state.retired = TRUE;
      saw_storage_remove = TRUE;
    } else {
      g_assert_false (separator_pending);
      g_assert_false (state.retired);
      g_assert_true (event.operation == "read" || event.operation == "read-at"
          || event.operation == "write" || event.operation == "write-at"
          || event.operation == "sync" || event.operation == "size"
          || event.operation == "seek" || event.operation == "seek-position"
          || event.operation == "reset" || event.operation == "truncate");
      g_assert_true (state.live);
      g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
      g_assert_cmpint (event.outcome, ==, -1);
      saw_storage_truncate = saw_storage_truncate || event.operation == "truncate";
      saw_storage_write = saw_storage_write || event.operation == "write"
          || event.operation == "write-at";
    }
  }
  g_assert_true (saw_main_close && saw_directory_exists);
  g_assert_false (separator_pending);
  /* The storage child is opened, has its backing extended, and is removed.
   * POSIX DuckDB extends the spill file with truncate(); the Windows build
   * extends it with write-at and never emits a truncate. Require the extend
   * step on both hosts, but only assert the specific truncate token where it
   * is the platform's chosen mechanism. */
  g_assert_true (saw_storage_open && saw_storage_remove && saw_block);
  g_assert_true (saw_storage_truncate || saw_storage_write);
#ifndef G_OS_WIN32
  g_assert_true (saw_storage_truncate);
#endif
  g_assert_false (list_active);
  g_assert_false (list_callback_pending);
  if (seeded_foreign_entries)
    g_assert_true (saw_list && saw_list_complete && saw_foreign_entry && saw_broad_entry && saw_broad_remove);
  else
    g_assert_false (saw_list || saw_list_complete || saw_foreign_entry || saw_broad_entry || saw_broad_remove);
  g_assert_true (absent_root ? (saw_create && saw_remove_directory) : (!saw_create && !saw_remove_directory));
  for (const auto &[name, state] : storage) {
    (void) name;
    g_assert_false (state.live);
    g_assert_cmpuint (state.opens, ==, state.closes);
    g_assert_true (state.retired);
  }
  assert_no_host_home_forwarding (recorder, root);
  assert_source_155_platform_control_language (recorder.controls, 0, 1);
}

static void
test_recording_filesystem_persistent_database (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-recording-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (sandbox);
  GStatBuf stat_buffer;
  int stat_res = g_stat (sandbox, &stat_buffer);
  g_assert_cmpint (stat_res, ==, 0);
#ifndef G_OS_WIN32
  /* Windows has no POSIX mode bits to check here; NTFS reports a fixed
   * st_mode for a writable directory regardless of ACLs. */
  g_assert_cmpint (stat_buffer.st_mode & 0777, ==, 0700);
#endif

  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (path_to_utf8 (root), recorder);

  assert_rejected_without_forwarding (filesystem, "../facts.duckdb", "relative path");
  const std::string not_ours = outside_sandbox_probe_path ("wyl-not-ours.duckdb");
  assert_rejected_without_forwarding (filesystem, not_ours,
      ("outside sandbox: " + not_ours).c_str ());
  assert_rejected_without_forwarding (filesystem, "https://example.invalid/facts.duckdb",
      "ambient or protocol path");
  assert_rejected_without_forwarding (filesystem, "/sys/fs/cgroup/unapproved",
      "unapproved cgroup host path: /sys/fs/cgroup/unapproved");
#ifndef G_OS_WIN32
  const fs::path linked = root / "outside-link";
  const std::string linked_utf8 = path_to_utf8 (linked);
  g_assert_cmpint (symlink ("/tmp", linked_utf8.c_str ()), ==, 0);
  assert_rejected_without_forwarding (filesystem, path_to_utf8 (linked / "facts.duckdb"),
      "symbolic-link path");
  g_assert_cmpint (g_remove (linked_utf8.c_str ()), ==, 0);
#endif
  /* These requests have a sandboxed pathname, so only the complete pinned
   * FileOpenFlags tuple is under test. Unknown bits, mismatched lock mode,
   * and compression all fail closed before LocalFileSystem::OpenFile. */
  assert_open_flags_rejected_without_forwarding (filesystem, path_to_utf8 (database),
      duckdb::FileOpenFlags (duckdb::FileOpenFlags::FILE_FLAGS_READ | (duckdb::idx_t (1) << 63)));
  assert_open_flags_rejected_without_forwarding (filesystem, path_to_utf8 (database),
      duckdb::FileOpenFlags (129, duckdb::FileLockType::WRITE_LOCK,
          duckdb::FileCompressionType::UNCOMPRESSED));
  assert_open_flags_rejected_without_forwarding (filesystem, path_to_utf8 (database),
      duckdb::FileOpenFlags (129, duckdb::FileLockType::NO_LOCK,
          duckdb::FileCompressionType::GZIP));
  {
    const size_t events_before = filesystem.events ().size ();
    const std::string database_utf8 = path_to_utf8 (database);
    try {
      (void) filesystem.Glob (database_utf8, nullptr);
      g_assert_not_reached ();
    } catch (const duckdb::PermissionException &) {
    }
    g_assert_cmpuint (filesystem.events ().size (), ==, events_before + 2);
    const auto &recorded = filesystem.events ()[events_before];
    const auto &denied = filesystem.events ().back ();
    g_assert_cmpstr (recorded.operation.c_str (), ==, "glob");
    g_assert_cmpstr (recorded.path.c_str (), ==, database_utf8.c_str ());
    g_assert_cmpstr (denied.operation.c_str (), ==, "deny");
    g_assert_cmpstr (denied.path.c_str (), ==, database_utf8.c_str ());
  }
  {
    /* Exercise DuckDB's public extended entry point, rather than calling the
     * fixture override directly. SupportsGlobExtended() must route this
     * through GlobFilesExtended, record that exact attempt, and deny before
     * LocalFileSystem receives the pathname. */
    const size_t events_before = filesystem.events ().size ();
    const guint rejected_before = filesystem.rejected ();
    const std::string database_utf8 = path_to_utf8 (database);
    try {
      (void) filesystem.GlobFiles (database_utf8,
          duckdb::FileGlobInput (duckdb::FileGlobOptions::DISALLOW_EMPTY));
      g_assert_not_reached ();
    } catch (const duckdb::PermissionException &) {
    }
    g_assert_cmpuint (filesystem.rejected (), ==, rejected_before + 1);
    g_assert_cmpuint (filesystem.events ().size (), ==, events_before + 2);
    const auto &extended = filesystem.events ()[events_before];
    const auto &denied = filesystem.events ()[events_before + 1];
    g_assert_cmpstr (extended.operation.c_str (), ==, "glob-extended");
    g_assert_cmpstr (extended.path.c_str (), ==, database_utf8.c_str ());
    g_assert_cmpuint (extended.flags, ==, 0);
    g_assert_cmpint (extended.outcome, ==, -1);
    g_assert_cmpstr (extended.error_class.c_str (), ==, "");
    g_assert_cmpstr (denied.operation.c_str (), ==, "deny");
    g_assert_cmpstr (denied.path.c_str (), ==, database_utf8.c_str ());
    g_assert_cmpuint (denied.flags, ==, 0);
    g_assert_cmpint (denied.outcome, ==, 0);
    g_assert_cmpstr (denied.error_class.c_str (), ==,
        "PermissionException:extended glob access is not permitted");
  }
  const guint rejected_baseline = recorder->rejected;
  const guint subsystem_baseline = recorder->subsystem_attempts;
  const size_t event_baseline = recorder->events.size ();
  const size_t control_baseline = recorder->controls.size ();

  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_true (!result->HasError ());
  }
  {
    duckdb::DBConfig reopen_config;
    configure_test_database (&reopen_config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &reopen_config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts");
    g_assert_true (!result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 1);
    assert_value_text (result->GetValue (0, 0), "42");
  }
  g_assert_cmpuint (recorder->rejected, ==, rejected_baseline);
  g_assert_cmpuint (recorder->subsystem_attempts, ==, subsystem_baseline);
  RecorderState scenario_recorder;
  scenario_recorder.events.assign (recorder->events.begin () + event_baseline,
      recorder->events.end ());
  scenario_recorder.controls.assign (recorder->controls.begin () + control_baseline,
      recorder->controls.end ());
  assert_persistent_database_trace_language (scenario_recorder, 0, 0, root, database);
  assert_trace_fixture ("persistent-db", scenario_recorder.events, root,
      "84302dc24ec80b11b3a1ad76afb9cc2de77d3cd0afa7d6d47d96b40c3ab80982");

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
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path temp = root / "tmp";
  const fs::path database = root / "temp-source.duckdb";
  g_assert_true (fs::create_directory (temp));
  auto recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (11), source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto setup = connection.Query ("SET memory_limit='20MB'; SET temp_directory='" + path_to_utf8 (temp)
        + "';");
    g_assert_false (setup->HasError ());
    auto result = connection.Query (
        "SELECT i FROM range(5000000) t(i) ORDER BY (i * 1103515245) % 1000003 DESC");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 5000000);
  }
  recorder->events.clear ();
  recorder->controls.clear ();
  const fs::path stale_storage = temp / "duckdb_temp_storage_S32K-0.tmp";
  const fs::path broad_prefix = temp / "duckdb_temp_foreign";
  const fs::path foreign = temp / "foreign";
  const std::string stale_storage_utf8 = path_to_utf8 (stale_storage);
  const std::string broad_prefix_utf8 = path_to_utf8 (broad_prefix);
  const std::string foreign_utf8 = path_to_utf8 (foreign);
  g_assert_true (g_file_set_contents (stale_storage_utf8.c_str (), "stale", -1, &error));
  g_assert_no_error (error);
  g_assert_true (g_file_set_contents (broad_prefix_utf8.c_str (), "foreign", -1, &error));
  g_assert_no_error (error);
  g_assert_true (g_file_set_contents (foreign_utf8.c_str (), "foreign", -1, &error));
  g_assert_no_error (error);
  size_t workload_end = 0;
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (11), source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto setup = connection.Query ("SET memory_limit='20MB'; SET temp_directory='" + path_to_utf8 (temp)
        + "';");
    g_assert_false (setup->HasError ());
    auto result = connection.Query (
        "SELECT i FROM range(5000000) t(i) ORDER BY (i * 1103515245) % 1000003 DESC");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 5000000);
    workload_end = recorder->events.size ();
  }
  const size_t teardown_end = recorder->events.size ();
  g_assert_cmpuint (workload_end, <, teardown_end);
  assert_temporary_spill_trace_language (*recorder, root, database, temp, FALSE, TRUE);
  /* The recorder must survive DuckDB teardown and observe the temporary
   * directory empty only after all injected-VFS owners have been destroyed. */
  g_assert_false (fs::exists (stale_storage));
  g_assert_false (fs::exists (broad_prefix));
  g_assert_true (fs::exists (foreign));
  remove_tree (sandbox);
}

static void
test_recording_filesystem_temporary_spill_absent_root (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-temp-absent-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (sandbox);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path temp = root / "not-created";
  const fs::path database = root / "temp-absent-source.duckdb";
  g_assert_false (fs::exists (temp));
  auto recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (11), source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto setup = connection.Query ("SET memory_limit='20MB'; SET temp_directory='" + path_to_utf8 (temp)
        + "';");
    g_assert_false (setup->HasError ());
    auto result = connection.Query (
        "SELECT i FROM range(5000000) t(i) ORDER BY (i * 1103515245) % 1000003 DESC");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 5000000);
  }
  assert_temporary_spill_trace_language (*recorder, root, database, temp, TRUE, FALSE);
  g_assert_false (fs::exists (temp));
  remove_tree (sandbox);
}

static void
assert_list_callback_trace_language (const std::vector<Event> &events,
    const fs::path &root, const fs::path &listed, bool is_directory,
    bool callback_succeeded, const std::string &callback_error = {})
{
  const std::string root_utf8 = path_to_utf8 (root);
  const std::string listed_utf8 = path_to_utf8 (listed);
  /* NFA: LIST(root) -> ENTRY(listed,type) -> CALLBACK(listed,type,result)
   * -> COMPLETE(root,success). */
  g_assert_cmpuint (events.size (), ==, callback_succeeded ? 4 : 3);
  g_assert_cmpstr (events[0].operation.c_str (), ==, "list");
  g_assert_cmpstr (events[0].path.c_str (), ==, root_utf8.c_str ());
  g_assert_cmpint (events[0].outcome, ==, -1);
  g_assert_cmpstr (events[1].operation.c_str (), ==, "list-entry");
  g_assert_cmpstr (events[1].path.c_str (), ==, listed_utf8.c_str ());
  g_assert_cmpuint (events[1].flags, ==, is_directory ? 1 : 0);
  g_assert_cmpint (events[1].outcome, ==, is_directory ? 1 : 0);
  g_assert_cmpstr (events[2].operation.c_str (), ==, "list-callback-complete");
  g_assert_cmpstr (events[2].path.c_str (), ==, listed_utf8.c_str ());
  g_assert_cmpuint (events[2].flags, ==, is_directory ? 1 : 0);
  g_assert_cmpint (events[2].outcome, ==, callback_succeeded ? 1 : 0);
  g_assert_cmpstr (events[2].error_class.c_str (), ==, callback_error.c_str ());
  if (callback_succeeded) {
    g_assert_cmpstr (events[3].operation.c_str (), ==, "list-complete");
    g_assert_cmpstr (events[3].path.c_str (), ==, root_utf8.c_str ());
    g_assert_cmpint (events[3].outcome, ==, 1);
  }
  for (const auto &event : events) {
    if (event.operation != "list-entry" && event.operation != "list-callback-complete")
      g_assert_cmpuint (event.flags, ==, 0);
    g_assert_true (event.lock == duckdb::FileLockType::NO_LOCK);
    g_assert_true (event.compression == duckdb::FileCompressionType::UNCOMPRESSED);
    if (event.operation != "list-callback-complete")
      g_assert_true (event.error_class.empty ());
  }
}

static void
test_recording_filesystem_list_callback_trace (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-list-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path file_parent = root / "file-parent";
  const fs::path directory_parent = root / "directory-parent";
  const fs::path listed = file_parent / "listed";
  const fs::path listed_directory = directory_parent / "listed-directory";
  const std::string listed_utf8 = path_to_utf8 (listed);
  g_assert_true (fs::create_directory (file_parent));
  g_assert_true (fs::create_directory (directory_parent));
  g_assert_true (g_file_set_contents (listed_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);
  g_assert_true (fs::create_directory (listed_directory));

  const auto exercise_callback = [] (const fs::path &entry, bool is_directory,
      bool callback_succeeded) {
    auto recorder = std::make_shared<RecorderState> ();
    RecordingFileSystem filesystem (path_to_utf8 (entry.parent_path ()), recorder);
    const std::string entry_name = path_to_utf8 (entry.filename ());
    std::vector<std::pair<std::string, bool>> callbacks;
    if (callback_succeeded) {
      g_assert_true (filesystem.ListFiles (path_to_utf8 (entry.parent_path ()),
          [&callbacks] (const duckdb::string &path, bool type) {
            callbacks.push_back ({ path, type });
          }, nullptr));
      g_assert_cmpuint (callbacks.size (), ==, 1);
      g_assert_cmpstr (callbacks[0].first.c_str (), ==, entry_name.c_str ());
      g_assert_cmpint (callbacks[0].second, ==, is_directory);
    } else {
      try {
        filesystem.ListFiles (path_to_utf8 (entry.parent_path ()),
            [&entry_name, is_directory] (const duckdb::string &path, bool type) {
              if (path == entry_name && type == is_directory)
                throw std::runtime_error ("callback failure");
            }, nullptr);
        g_assert_not_reached ();
      } catch (const std::runtime_error &) {
      }
    }
    assert_list_callback_trace_language (recorder->events, entry.parent_path (), entry, is_directory,
        callback_succeeded, callback_succeeded ? "" : "CallbackException");
  };
  exercise_callback (listed, false, true);
  exercise_callback (listed_directory, true, true);
  exercise_callback (listed, false, false);
  exercise_callback (listed_directory, true, false);

  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (path_to_utf8 (root), recorder);

  const guint rejected_before = filesystem.rejected ();
  const size_t events_before = filesystem.events ().size ();
  const std::string not_a_list_entry = outside_sandbox_probe_path ("not-a-list-entry");
  for (const auto &[entry, reason] : { std::pair<std::string, std::string> {
          not_a_list_entry, "outside sandbox: " + not_a_list_entry },
          { "../not-a-list-entry", "parent traversal in list entry" } }) {
    try {
      filesystem.CheckListEntryForTest (path_to_utf8 (root), entry);
      g_assert_not_reached ();
    } catch (const duckdb::PermissionException &) {
    }
    const auto &denied = filesystem.events ().back ();
    g_assert_cmpstr (denied.operation.c_str (), ==, "deny");
    g_assert_cmpstr (denied.path.c_str (), ==, entry.c_str ());
    g_assert_cmpint (denied.outcome, ==, 0);
    g_autofree gchar *expected = g_strdup_printf ("PermissionException:%s", reason.c_str ());
    g_assert_cmpstr (denied.error_class.c_str (), ==, expected);
  }
  g_assert_cmpuint (filesystem.rejected (), ==, rejected_before + 2);
  g_assert_cmpuint (filesystem.events ().size (), ==, events_before + 2);
  remove_tree (sandbox);
}

static void
test_recording_filesystem_list_forwarding_protocol (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-list-fsm-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path entry = root / "entry";
  const std::string root_utf8 = path_to_utf8 (root);
  const std::string entry_utf8 = path_to_utf8 (entry);
  g_assert_true (g_file_set_contents (entry_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);

  const auto assert_callback_failure = [&entry_utf8, &root_utf8] (const RecordingFileSystem &subject,
      const char *error_class, gboolean nested_rejection) {
    const auto &events = subject.events ();
    /* The entry token retains the callback type; the paired completion adds
     * its terminal result/error and must be emitted even when user code
     * throws. */
    g_assert_cmpuint (events.size (), ==, nested_rejection ? 4 : 3);
    g_assert_cmpstr (events[1].operation.c_str (), ==, "list-entry");
    g_assert_cmpstr (events[1].path.c_str (), ==, entry_utf8.c_str ());
    g_assert_cmpint (events[1].outcome, ==, 0);
    const size_t completion = nested_rejection ? 3 : 2;
    if (nested_rejection) {
      g_assert_cmpstr (events[2].operation.c_str (), ==, "deny");
      g_assert_cmpstr (events[2].path.c_str (), ==, root_utf8.c_str ());
      g_assert_cmpstr (events[2].error_class.c_str (), ==,
          "PermissionException:nested ListFiles callback invocation");
    }
    g_assert_cmpstr (events[completion].operation.c_str (), ==,
        "list-callback-complete");
    g_assert_cmpstr (events[completion].path.c_str (), ==, entry_utf8.c_str ());
    g_assert_cmpuint (events[completion].flags, ==, 0);
    g_assert_cmpint (events[completion].outcome, ==, 0);
    g_assert_cmpstr (events[completion].error_class.c_str (), ==, error_class);
  };

  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (root_utf8, recorder);
  filesystem.EnableForwardingProtocolForTest ({
      direct_fwd ("list", root_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 1, "", {}),
      direct_fwd ("list-entry", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 1, "", {}),
      direct_fwd ("list-callback-complete", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 1, "", {}),
  });
  g_assert_true (filesystem.ListFiles (root_utf8,
      [] (const duckdb::string &name, bool is_directory) {
        g_assert_cmpstr (name.c_str (), ==, "entry");
        g_assert_false (is_directory);
      }, nullptr));
  filesystem.AssertForwardingProtocolCompleteForTest ();

  auto partial_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem partial (root_utf8, partial_recorder);
  partial.EnableForwardingProtocolForTest ({
      direct_fwd ("list", root_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 0, "CallbackException", {}),
      direct_fwd ("list-entry", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 0, "CallbackException", {}),
      direct_fwd ("list-callback-complete", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 0, "CallbackException", {}),
  });
  try {
    partial.ListFiles (root_utf8,
        [] (const duckdb::string &, bool) { throw std::runtime_error ("stop"); }, nullptr);
    g_assert_not_reached ();
  } catch (const std::runtime_error &) {
  }
  partial.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (partial.local_forwards (), ==, 1);
  assert_callback_failure (partial, "CallbackException", FALSE);

  auto nested_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem nested (root_utf8, nested_recorder);
  nested.EnableForwardingProtocolForTest ({
      direct_fwd ("list", root_utf8, 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, {}, {}, {}, 0, "DuckDBException", {}),
      direct_fwd ("list-entry", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 0, "DuckDBException", {}),
      direct_fwd ("list-callback-complete", "entry", 0, duckdb::FileLockType::NO_LOCK, duckdb::FileCompressionType::UNCOMPRESSED, { 0 }, {}, {}, 0, "DuckDBException", {}),
  });
  try {
    nested.ListFiles (root_utf8,
        [&nested, &root_utf8] (const duckdb::string &, bool) {
          nested.ListFiles (root_utf8, [] (const duckdb::string &, bool) {}, nullptr);
        }, nullptr);
    g_assert_not_reached ();
  } catch (const duckdb::PermissionException &) {
  }
  nested.AssertForwardingProtocolCompleteForTest ();
  g_assert_cmpuint (nested.local_forwards (), ==, 1);
  assert_callback_failure (nested, "DuckDBException", TRUE);
  remove_tree (sandbox);
}

static void
test_recording_filesystem_utf8_path_boundary (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-utf8-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / path_from_utf8 ("facts-\xED\x95\x9C\xEA\xB8\x80.duckdb");
  const std::string database_utf8 = path_to_utf8 (database);
  auto recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem filesystem (path_to_utf8 (root), recorder);
  filesystem.AuthorizeOpenForScenario (duckdb::FileOpenFlags (11));
  {
    auto handle = filesystem.OpenFile (database_utf8, duckdb::FileOpenFlags (11), nullptr);
    g_assert_nonnull (handle);
    handle->Close ();
  }
  g_assert_cmpuint (recorder->events.size (), ==, 2);
  for (const auto &event : recorder->events)
    g_assert_cmpstr (event.path.c_str (), ==, database_utf8.c_str ());
  g_assert_cmpstr (recorder->events[0].operation.c_str (), ==, "open");
  g_assert_cmpstr (recorder->events[1].operation.c_str (), ==, "close");
  remove_tree (sandbox);
}

/* This is deliberately a lifecycle, not another conversion unit test.  It
 * proves that the same non-ASCII spelling survives DBConfig, DuckDB's
 * temporary-store ListFiles callback, and a separately exec'd trace writer. */
static void
test_recording_filesystem_utf8_lifecycle (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-utf8-life-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path parent = fs::canonical (path_from_utf8 (sandbox));
  const fs::path root = parent / path_from_utf8 ("\xEA\xB2\xBD\xEB\xA1\x9C-\xF0\x9F\xA6\x86");
  const fs::path temp = root / path_from_utf8 ("\xEC\x9E\x84\xEC\x8B\x9C-\xF0\x9F\x93\xA6");
  /* Keep the child protocol's pinned facts.duckdb basename; its parent
   * directory is non-ASCII, so every recorded absolute path still crosses
   * the UTF-8 boundary. */
  const fs::path database = root / "facts.duckdb";
  const std::string root_utf8 = path_to_utf8 (root);
  const std::string temp_utf8 = path_to_utf8 (temp);
  const std::string database_utf8 = path_to_utf8 (database);
  g_assert_true (g_utf8_validate (root_utf8.c_str (), -1, NULL));
  g_assert_true (fs::create_directory (root));
  g_assert_true (fs::create_directory (temp));

  auto recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (11), source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (database_utf8, &config);
    duckdb::Connection connection (db);
    auto setup = connection.Query ("SET memory_limit='20MB'; SET temp_directory='" + temp_utf8
        + "'; CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42);");
    g_assert_false (setup->HasError ());
    auto result = connection.Query (
        "SELECT i FROM range(5000000) t(i) ORDER BY (i * 1103515245) % 1000003 DESC");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 5000000);
  }
  gboolean saw_temp = FALSE;
  for (const auto &event : recorder->events) {
    g_assert_true (g_utf8_validate (event.path.c_str (), -1, NULL));
    g_assert_true (path_is_at_or_below (event.path, root));
    saw_temp = saw_temp || path_is_at_or_below (event.path, temp);
  }
  g_assert_true (saw_temp);
  g_assert_true (fs::is_empty (temp));

  const std::string listed_leaf = "\xEB\xAA\xA9\xEB\xA1\x9D-\xF0\x9F\x93\x84";
  const fs::path listed = temp / path_from_utf8 (listed_leaf);
  const std::string listed_utf8 = path_to_utf8 (listed);
  g_assert_true (g_file_set_contents (listed_utf8.c_str (), "x", -1, &error));
  g_assert_no_error (error);
  auto list_recorder = std::make_shared<RecorderState> ();
  RecordingFileSystem list_filesystem (root_utf8, list_recorder);
  std::vector<std::pair<std::string, bool>> callbacks;
  g_assert_true (list_filesystem.ListFiles (temp_utf8,
      [&callbacks] (const duckdb::string &path, bool is_directory) {
        callbacks.push_back ({ path, is_directory });
      }, nullptr));
  g_assert_cmpuint (callbacks.size (), ==, 1);
  /* Compare against the original UTF-8 leaf rather than round-tripping through
   * fs::path::filename(): on Windows the STL renders a filename() ending in a
   * 4-byte (astral) code point as an empty component, which would spuriously
   * fail even though the filesystem returned the exact expected bytes. */
  g_assert_cmpstr (callbacks[0].first.c_str (), ==, listed_leaf.c_str ());
  g_assert_false (callbacks[0].second);
  assert_list_callback_trace_language (list_recorder->events, temp, listed, false, true);

  const gchar *argv[] = { self_path, "--crash-writer", root_utf8.c_str (), NULL };
  g_autoptr (GSubprocess) child = g_subprocess_newv (argv,
      (GSubprocessFlags) (G_SUBPROCESS_FLAGS_STDOUT_PIPE
          | G_SUBPROCESS_FLAGS_STDERR_SILENCE), &error);
  g_assert_no_error (error);
  g_autofree gchar *child_stdout = communicate_utf8_with_timeout (child, 5000);
  g_assert_true (g_subprocess_get_successful (child));
  std::vector<Event> child_events;
  std::vector<ControlEvent> child_controls;
  parse_child_trace (child_stdout, &child_events, &child_controls);
  assert_wal_crash_writer_trace_language (child_events, child_controls, database);
  for (const auto &event : child_events) {
    g_assert_true (g_utf8_validate (event.path.c_str (), -1, NULL));
    g_assert_true (path_is_at_or_below (event.path, root));
  }
  remove_tree (path_to_utf8 (parent).c_str ());
}

static void
assert_wal_crash_writer_trace_language (const std::vector<Event> &events,
    const std::vector<ControlEvent> &controls, const fs::path &database)
{
  assert_crash_writer_exact_trace (events, database);
  assert_source_155_platform_control_language (controls, 0, 1);
}

static void
assert_wal_recovery_trace_language (const RecorderState &recorder,
    const fs::path &database)
{
  assert_wal_recovery_exact_trace (recorder.events, database);
  assert_source_155_platform_control_language (recorder.controls, 0, 1);
}

static void
assert_writer_contender_full_stream (const gchar *stream,
    const fs::path &database)
{
  std::vector<Event> events;
  std::vector<ControlEvent> controls;
  parse_child_trace (stream, &events, &controls);
  assert_writer_contender_exact_trace (events, database);
  assert_source_155_platform_control_language (controls, 0, 1);
}

static void
assert_writer_holder_full_stream (const gchar *stream,
    const fs::path &database)
{
  static constexpr const char ready[] = "READY\n";
  g_assert_true (g_str_has_prefix (stream, ready));
  std::vector<Event> events;
  std::vector<ControlEvent> controls;
  parse_child_trace (stream + sizeof ready - 1, &events, &controls);
  assert_writer_holder_exact_trace (events, database);
  assert_source_155_platform_control_language (controls, 0, 1);
}

static void
test_recording_filesystem_live_wal_read_only_recovery (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-live-wal-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = path_from_utf8 (path_with_suffix (database, ".wal"));

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  g_assert_false (fs::exists (wal));

  const std::string root_utf8 = path_to_utf8 (root);
  const gchar *argv[] = { self_path, "--crash-writer", root_utf8.c_str (), NULL };
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
  assert_wal_crash_writer_trace_language (child_events, child_controls, database);
  const std::string checkpoint = path_with_suffix (wal, ".checkpoint");
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
    configure_test_database (&config, root, read_only_recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2433, duckdb::FileLockType::READ_LOCK) });
    config.options.access_mode = duckdb::AccessMode::READ_ONLY;
    duckdb::DuckDB db (path_to_utf8 (database), &config);
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
  assert_same_file (main_before_ro, snapshot_file (database));
  assert_same_file (wal_before_ro, snapshot_file (wal));
  g_assert_true (read_only_opened);
  g_assert_null (read_only_error);
  g_assert_cmpuint (read_only_rows, ==, 2);
  g_free (read_only_error);

  auto recovery_recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recovery_recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts ORDER BY value");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 2);
    assert_value_text (result->GetValue (0, 0), "42");
    assert_value_text (result->GetValue (0, 1), "99");
  }
  assert_wal_recovery_trace_language (*recovery_recorder, database);
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".checkpoint"))));
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".recovery"))));
  remove_tree (sandbox);
}

static void
test_recording_filesystem_rw_writer_contention (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-writer-lock-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  const ArtifactSet seeded = snapshot_artifacts (root);
  g_assert_cmpuint (seeded.files.size (), ==, 1);
  g_assert_cmpstr (seeded.files[0].first.c_str (), ==, "facts.duckdb");

  const std::string root_utf8 = path_to_utf8 (root);
  const gchar *argv[] = { self_path, "--hold-writer", root_utf8.c_str (), NULL };
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

  const gchar *contender_argv[] = { self_path, "--contend-writer", root_utf8.c_str (), NULL };
  g_autoptr (GSubprocess) contender = g_subprocess_newv (contender_argv,
      (GSubprocessFlags) (G_SUBPROCESS_FLAGS_STDOUT_PIPE
          | G_SUBPROCESS_FLAGS_STDERR_SILENCE), &error);
  g_assert_no_error (error);
  g_autofree gchar *contender_stream = communicate_utf8_with_timeout (contender,
      5000);
  g_assert_true (g_subprocess_get_successful (contender));
  assert_writer_contender_full_stream (contender_stream, database);
  assert_same_artifacts (seeded, snapshot_artifacts (root));

  gsize written = 0;
  g_assert_true (g_output_stream_write_all (g_subprocess_get_stdin_pipe (holder),
          "RELEASE\n", 8, &written, NULL, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (written, ==, 8);
  g_assert_true (g_output_stream_close (g_subprocess_get_stdin_pipe (holder), NULL, &error));
  g_assert_no_error (error);
  wait_check_with_timeout (holder, 5000);
  GString *holder_stream = g_string_new ("READY\n");
  while (TRUE) {
    gsize line_length = 0;
    g_autofree gchar *line = g_data_input_stream_read_line (holder_stdout,
        &line_length, NULL, &error);
    g_assert_no_error (error);
    if (line == NULL)
      break;
    g_string_append_len (holder_stream, line, line_length);
    g_string_append_c (holder_stream, '\n');
  }
  assert_writer_holder_full_stream (holder_stream->str, database);
  g_string_free (holder_stream, TRUE);
  assert_same_artifacts (seeded, snapshot_artifacts (root));

  auto restored_recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, restored_recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto write = connection.Query ("INSERT INTO facts VALUES (77)");
    g_assert_false (write->HasError ());
    auto read = connection.Query ("SELECT value FROM facts WHERE value = 77");
    g_assert_false (read->HasError ());
    g_assert_cmpuint (read->RowCount (), ==, 1);
  }
  assert_writer_restored_exact_trace (restored_recorder->events, database);
  assert_source_155_platform_control_language (restored_recorder->controls, 0, 1);
  remove_tree (sandbox);
}

static void
assert_explicit_checkpoint_full_stream (const std::vector<Event> &events,
    size_t checkpoint_begin, size_t checkpoint_end, const fs::path &database)
{
  /* These offsets name the query boundary in the fixture only.  The FSM
   * below intentionally consumes the startup and destructor tokens as well. */
  g_assert_cmpuint (checkpoint_begin, <=, checkpoint_end);
  g_assert_cmpuint (checkpoint_end, <=, events.size ());
  assert_explicit_checkpoint_exact_trace (events, database);
}

static void
test_recording_filesystem_explicit_checkpoint_discovery (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-checkpoint-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = path_from_utf8 (path_with_suffix (database, ".wal"));
  const std::string checkpoint = path_with_suffix (wal, ".checkpoint");
  const std::string recovery = path_with_suffix (wal, ".recovery");

  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)");
    g_assert_false (result->HasError ());
  }
  {
    auto recorder = std::make_shared<RecorderState> ();
    duckdb::DBConfig config;
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    config.options.checkpoint_on_shutdown = false;
    duckdb::DuckDB db (path_to_utf8 (database), &config);
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
    configure_test_database (&config, root, recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
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
    assert_value_text (rows->GetValue (0, 0), "42");
    assert_value_text (rows->GetValue (0, 1), "99");
  }
  g_assert_cmpuint (post_checkpoint.files.size (), ==, 1);
  g_assert_cmpstr (post_checkpoint.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (checkpoint));
  g_assert_false (fs::exists (recovery));
  assert_explicit_checkpoint_full_stream (recorder->events, checkpoint_begin,
      checkpoint_end, database);
  assert_source_155_platform_control_language (recorder->controls, 0, 1);
  remove_tree (sandbox);
}

static void
assert_interrupted_checkpoint_full_stream (const std::vector<Event> &events,
    const fs::path &database)
{
  assert_interrupted_checkpoint_child_exact_trace (events, database);
}

static void
assert_interrupted_checkpoint_recovery_full_stream (const std::vector<Event> &events,
    const fs::path &database)
{
  assert_interrupted_checkpoint_recovery_exact_trace (events, database);
}

static void
test_recording_filesystem_checkpoint_crash_phase_a (void)
{
  assert_duckdb_155 ();
  g_autoptr (GError) error = NULL;
  g_autofree gchar *sandbox = g_dir_make_tmp ("wyl-duckdb-checkpoint-crash-XXXXXX", &error);
  g_assert_no_error (error);
  const fs::path root = fs::canonical (path_from_utf8 (sandbox));
  const fs::path database = root / "facts.duckdb";
  const fs::path wal = path_from_utf8 (path_with_suffix (database, ".wal"));
  {
    auto state = std::make_shared<RecorderState> (); duckdb::DBConfig config;
    configure_test_database (&config, root, state, {
        source_155_open_flags (129),
        source_155_open_flags (2315, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) }); duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection c (db); g_assert_false (c.Query ("CREATE TABLE facts(value INTEGER); INSERT INTO facts VALUES (42)")->HasError ());
  }
  {
    auto state = std::make_shared<RecorderState> (); duckdb::DBConfig config;
    configure_test_database (&config, root, state, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) }); config.options.checkpoint_on_shutdown = false;
    duckdb::DuckDB db (path_to_utf8 (database), &config); duckdb::Connection c (db);
    g_assert_false (c.Query ("INSERT INTO facts VALUES (99)")->HasError ());
  }
  g_assert_true (fs::exists (wal));
  const std::string root_utf8 = path_to_utf8 (root);
  const gchar *argv[] = { self_path, "--checkpoint-crash", root_utf8.c_str (), NULL };
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
  const std::string database_path = path_to_utf8 (database);
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
  assert_interrupted_checkpoint_full_stream (events, database);
  /* The child emits controls before its event stream; consume that independent
   * channel rather than treating the crash trace as events-only evidence. */
  assert_source_155_platform_control_language (controls, 0, 1);
  const ArtifactSet artifacts = snapshot_artifacts (root);
  g_assert_cmpuint (artifacts.files.size (), ==, 2);
  g_assert_cmpstr (artifacts.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_cmpstr (artifacts.files[1].first.c_str (), ==, "facts.duckdb.wal");
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".checkpoint"))));
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".recovery"))));

  auto recovery_recorder = std::make_shared<RecorderState> ();
  {
    duckdb::DBConfig config;
    configure_test_database (&config, root, recovery_recorder, {
        source_155_open_flags (129),
        source_155_open_flags (2307, duckdb::FileLockType::WRITE_LOCK),
        source_155_open_flags (2090, duckdb::FileLockType::WRITE_LOCK) });
    duckdb::DuckDB db (path_to_utf8 (database), &config);
    duckdb::Connection connection (db);
    auto result = connection.Query ("SELECT value FROM facts ORDER BY value");
    g_assert_false (result->HasError ());
    g_assert_cmpuint (result->RowCount (), ==, 2);
    assert_value_text (result->GetValue (0, 0), "42");
    assert_value_text (result->GetValue (0, 1), "99");
  }
  assert_interrupted_checkpoint_recovery_full_stream (recovery_recorder->events,
      database);
  assert_source_155_platform_control_language (recovery_recorder->controls, 0, 1);
  const ArtifactSet recovered = snapshot_artifacts (root);
  g_assert_cmpuint (recovered.files.size (), ==, 1);
  g_assert_cmpstr (recovered.files[0].first.c_str (), ==, "facts.duckdb");
  g_assert_false (fs::exists (wal));
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".checkpoint"))));
  g_assert_false (fs::exists (path_from_utf8 (path_with_suffix (wal, ".recovery"))));
  remove_tree (sandbox);
}

int
main (int argc, char **argv)
{
#ifdef G_OS_WIN32
  /* The child-process trace is an exact byte grammar consumed on stdout.
   * Windows opens stdout in text mode, which would translate every '\n' in
   * the trace to "\r\n"; the parent splits strictly on '\n' and would then
   * see a trailing '\r' on every line. Emit the trace verbatim instead. Each
   * child is a fresh re-exec of this binary and runs this same line at its own
   * main() entry before the dispatch below; it is harmless for the parent's
   * own TAP output. */
  _setmode (_fileno (stdout), _O_BINARY);
  /* The CRT argv is decoded in the system ANSI codepage, which cannot
   * represent the non-ASCII sandbox paths this suite hands to its re-exec'd
   * children. Reparse the command line as UTF-8 so a child resolves the same
   * pathname the parent spawned it with (leaked deliberately: it must outlive
   * both g_test_init and self_path). */
  argv = g_win32_get_command_line ();
  argc = (int) g_strv_length (argv);
#endif
  if (argc == 3 && g_strcmp0 (argv[1], "--crash-writer") == 0)
    return crash_writer_child (argv[2]);
  if (argc == 3 && g_strcmp0 (argv[1], "--hold-writer") == 0)
    return hold_writer_child (argv[2]);
  if (argc == 3 && g_strcmp0 (argv[1], "--contend-writer") == 0)
    return contend_writer_child (argv[2]);
  if (argc == 3 && g_strcmp0 (argv[1], "--checkpoint-crash") == 0)
    return checkpoint_crash_child (argv[2]);
  self_path = argv[0];
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/home-directory-resolution",
      test_recording_filesystem_home_directory_resolution);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/persistent-db",
      test_recording_filesystem_persistent_database);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/temporary-spill-cleanup",
      test_recording_filesystem_temporary_spill_cleanup);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/temporary-spill-absent-root",
      test_recording_filesystem_temporary_spill_absent_root);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/list-callback-trace",
      test_recording_filesystem_list_callback_trace);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/list-forwarding-protocol",
      test_recording_filesystem_list_forwarding_protocol);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/forwarding-protocol-preflight",
      test_recording_filesystem_forwarding_protocol_preflight);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/direct-wrapper-dispositions",
      test_recording_filesystem_direct_wrapper_dispositions);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/utf8-path-boundary",
      test_recording_filesystem_utf8_path_boundary);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/utf8-lifecycle",
      test_recording_filesystem_utf8_lifecycle);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/live-wal-read-only-recovery",
      test_recording_filesystem_live_wal_read_only_recovery);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/rw-writer-contention",
      test_recording_filesystem_rw_writer_contention);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/explicit-checkpoint-discovery",
      test_recording_filesystem_explicit_checkpoint_discovery);
  g_test_add_func ("/secure-duckdb-bridge/recording-filesystem/checkpoint-crash-phase-a",
      test_recording_filesystem_checkpoint_crash_phase_a);
  return g_test_run ();
}
