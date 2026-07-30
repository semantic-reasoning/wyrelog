/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "fact/secure-duckdb-file-handle-private.hpp"
#include "fact/secure-duckdb-filesystem-private.hpp"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace {

  static_assert (std::numeric_limits < duckdb::idx_t >::is_integer
      && !std::numeric_limits < duckdb::idx_t >::is_signed,
      "DuckDB idx_t must remain an unsigned integer");
  static_assert (std::numeric_limits < off_t >::is_integer
      && std::numeric_limits < off_t >::is_signed,
      "POSIX off_t must remain a signed integer");
  static_assert (sizeof (duckdb::idx_t) >= sizeof (off_t),
      "DuckDB idx_t must represent every nonnegative off_t");
  static_assert (sizeof (size_t) >= sizeof (ssize_t),
      "size_t must represent every positive ssize_t");
  static_assert (sizeof (size_t) <= sizeof (uint64_t),
      "adapter arithmetic requires uint64_t to represent size_t");
  static_assert (sizeof (int64_t) >= sizeof (off_t),
      "adapter metadata requires int64_t to represent off_t");
  static_assert (sizeof (dev_t) <= sizeof (uint64_t)
      && sizeof (ino_t) <= sizeof (uint64_t),
      "adapter version tags require uint64_t device/inode identities");

  [[noreturn]] void io_reject (const char *operation)
  {
    throw duckdb::IOException ("bounded DuckDB file handle rejected %s",
        operation);
  }

  struct CheckedRange
  {
    size_t bytes;
    off_t offset;
  };

  struct CheckedTransfer
  {
    size_t bytes;
    duckdb::idx_t cursor;
    int64_t result;
  };

/* This is the single adapter conversion boundary.  Validate a complete
 * request before buffer access, syscall, or cursor mutation. */
  CheckedRange checked_range (int64_t byte_count, duckdb::idx_t location)
  {
    if (byte_count < 0 || static_cast < uint64_t > (byte_count)
        > static_cast < uint64_t > (SSIZE_MAX)
        || location
        > static_cast < duckdb::idx_t > (std::numeric_limits < off_t >::max ()))
      io_reject ("numeric conversion");
    const auto bytes = static_cast < uint64_t > (byte_count);
    const auto offset = static_cast < uint64_t > (location);
    if (bytes
        > static_cast < uint64_t > (std::numeric_limits <
        off_t >::max ()) - offset)
      io_reject ("numeric endpoint");
    return {
             static_cast < size_t >(bytes), static_cast < off_t > (offset)
    };
  }

  off_t
  checked_progress_offset (const CheckedRange &range, size_t progress)
  {
    if (progress > range.bytes)
      io_reject ("progress offset");
    const auto unsigned_progress = static_cast < uint64_t > (progress);
    const auto unsigned_offset = static_cast < uint64_t > (range.offset);
    if (unsigned_progress
        > static_cast < uint64_t > (std::numeric_limits < off_t >::max ())
        - unsigned_offset)
      io_reject ("progress endpoint");
    return static_cast < off_t > (unsigned_offset + unsigned_progress);
  }

  CheckedTransfer
  checked_transfer (ssize_t amount, size_t remaining)
  {
    if (amount < 0
        || static_cast < uint64_t > (amount)
        > static_cast < uint64_t > (remaining))
      io_reject ("syscall transfer");
    const auto transferred = static_cast < uint64_t > (amount);
    return {
             static_cast < size_t > (transferred),
             static_cast < duckdb::idx_t > (transferred),
             static_cast < int64_t > (transferred)
    };
  }

  off_t checked_size (int64_t size)
  {
    if (size < 0 || static_cast < uint64_t > (size)
        > static_cast < uint64_t > (std::numeric_limits < off_t >::max ()))
      io_reject ("truncate conversion");
    return static_cast < off_t > (size);
  }

  int64_t checked_stat_size (off_t size)
  {
    if (size < 0 || static_cast < uint64_t > (size)
        > static_cast < uint64_t > (std::numeric_limits < int64_t >::max ()))
      io_reject ("file-size conversion");
    return static_cast < int64_t > (size);
  }

  int64_t checked_timestamp (int64_t seconds, long nanoseconds)
  {
    constexpr int64_t scale = 1000000;
    if (nanoseconds < 0 || nanoseconds >= 1000000000L
        || seconds > (std::numeric_limits < int64_t >::max ()
        - nanoseconds / 1000) / scale
        || seconds < std::numeric_limits < int64_t >::min () / scale)
      io_reject ("timestamp conversion");
    return seconds * scale + nanoseconds / 1000;
  }

}                               // namespace

wyrelog_error_t
WylSecureDuckdbHealth::Status () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  return error_;
}

void
WylSecureDuckdbHealth::Poison (wyrelog_error_t error)
{
  std::lock_guard<std::mutex> lock (mutex_);
  if (error_ == WYRELOG_E_OK)
    error_ = error == WYRELOG_E_OK ? WYRELOG_E_IO : error;
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylSecureDuckdbBindingKind kind, int fd) noexcept
  : health_ (health), kind_ (kind), fd_ (fd), binding_ { }
{
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactMainBinding *binding, int fd) noexcept
  : WylSecureDuckdbPendingBinding (health,
      WylSecureDuckdbBindingKind::WRITER_MAIN, fd)
{
  binding_.writer_main = binding;
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactReaderMainBinding *binding, int fd) noexcept
  : WylSecureDuckdbPendingBinding (health,
      WylSecureDuckdbBindingKind::READER_MAIN, fd)
{
  binding_.reader_main = binding;
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactSidecarBinding *binding, int fd) noexcept
  : WylSecureDuckdbPendingBinding (health,
      WylSecureDuckdbBindingKind::WRITER_SIDECAR, fd)
{
  binding_.writer_sidecar = binding;
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactReaderWalBinding *binding, int fd) noexcept
  : WylSecureDuckdbPendingBinding (health,
      WylSecureDuckdbBindingKind::READER_WAL, fd)
{
  binding_.reader_wal = binding;
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactDuckdbTempChildBinding *binding, int fd) noexcept
  : WylSecureDuckdbPendingBinding (health,
      WylSecureDuckdbBindingKind::TEMP_CHILD, fd)
{
  binding_.temp_child = binding;
}

WylSecureDuckdbPendingBinding::~WylSecureDuckdbPendingBinding ()
{
  (void) Reset ();
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::RevalidateFd () const noexcept
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      return wyl_fact_artifact_main_binding_revalidate_fd (
        binding_.writer_main, fd_);
    case WylSecureDuckdbBindingKind::READER_MAIN:
      return wyl_fact_artifact_reader_main_binding_revalidate_fd (
        binding_.reader_main, fd_);
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      return wyl_fact_artifact_sidecar_binding_revalidate_fd (
        binding_.writer_sidecar, fd_);
    case WylSecureDuckdbBindingKind::READER_WAL:
      return wyl_fact_artifact_reader_wal_binding_revalidate_fd (
        binding_.reader_wal, fd_);
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      return wyl_fact_duckdb_temp_child_binding_revalidate_fd (
        binding_.temp_child, fd_);
  }
  return WYRELOG_E_POLICY;
}

bool
WylSecureDuckdbPendingBinding::HasBinding () const noexcept
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      return binding_.writer_main != nullptr;
    case WylSecureDuckdbBindingKind::READER_MAIN:
      return binding_.reader_main != nullptr;
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      return binding_.writer_sidecar != nullptr;
    case WylSecureDuckdbBindingKind::READER_WAL:
      return binding_.reader_wal != nullptr;
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      return binding_.temp_child != nullptr;
  }
  return false;
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::CheckedClose () noexcept
{
  if (wyl_secure_duckdb_filesystem_take_test_fault (
        WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION))
    (void) close (fd_);
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      return wyl_fact_artifact_main_binding_close (
        binding_.writer_main, &fd_);
    case WylSecureDuckdbBindingKind::READER_MAIN:
      return wyl_fact_artifact_reader_main_binding_close (
        binding_.reader_main, &fd_);
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      return wyl_fact_artifact_sidecar_binding_close (
        binding_.writer_sidecar, &fd_);
    case WylSecureDuckdbBindingKind::READER_WAL:
      return wyl_fact_artifact_reader_wal_binding_close (
        binding_.reader_wal, &fd_);
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      return wyl_fact_duckdb_temp_child_binding_close (
        binding_.temp_child, &fd_);
  }
  return WYRELOG_E_POLICY;
}

void
WylSecureDuckdbPendingBinding::FreeBinding () noexcept
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      g_clear_pointer (&binding_.writer_main,
          wyl_fact_artifact_main_binding_free);
      break;
    case WylSecureDuckdbBindingKind::READER_MAIN:
      g_clear_pointer (&binding_.reader_main,
          wyl_fact_artifact_reader_main_binding_free);
      break;
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      g_clear_pointer (&binding_.writer_sidecar,
          wyl_fact_artifact_sidecar_binding_free);
      break;
    case WylSecureDuckdbBindingKind::READER_WAL:
      g_clear_pointer (&binding_.reader_wal,
          wyl_fact_artifact_reader_wal_binding_free);
      break;
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      g_clear_pointer (&binding_.temp_child,
          wyl_fact_duckdb_temp_child_binding_free);
      break;
  }
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::Reset () noexcept
{
  wyrelog_error_t result = WYRELOG_E_OK;
  if (fd_ >= 0 && HasBinding ())
    result = CheckedClose ();
  else if (fd_ >= 0 || HasBinding ())
    result = WYRELOG_E_POLICY;
  FreeBinding ();
  fd_ = -1;
  if (result != WYRELOG_E_OK)
    health_->Poison (result);
  return result;
}

void
WylSecureDuckdbPendingBinding::Release () noexcept
{
  fd_ = -1;
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      binding_.writer_main = nullptr;
      break;
    case WylSecureDuckdbBindingKind::READER_MAIN:
      binding_.reader_main = nullptr;
      break;
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      binding_.writer_sidecar = nullptr;
      break;
    case WylSecureDuckdbBindingKind::READER_WAL:
      binding_.reader_wal = nullptr;
      break;
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      binding_.temp_child = nullptr;
      break;
  }
}

WylSecureDuckdbFileHandle::WylSecureDuckdbFileHandle (
  WylSecureDuckdbFileSystem &filesystem,
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  const duckdb::string &path, duckdb::FileOpenFlags flags,
  WylFactArtifactName artifact, WylSecureDuckdbPendingBinding &&pending)
  : duckdb::FileHandle (filesystem, path, flags), owner_ (&filesystem),
  health_ (health), kind_ (pending.kind_), sidecar_artifact_ (artifact),
  fd_ (pending.fd_), binding_ {}, offset_ (0)
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      binding_.writer_main = pending.binding_.writer_main;
      break;
    case WylSecureDuckdbBindingKind::READER_MAIN:
      binding_.reader_main = pending.binding_.reader_main;
      break;
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      binding_.writer_sidecar = pending.binding_.writer_sidecar;
      break;
    case WylSecureDuckdbBindingKind::READER_WAL:
      binding_.reader_wal = pending.binding_.reader_wal;
      break;
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      binding_.temp_child = pending.binding_.temp_child;
      break;
  }
  const auto validation = fd_ < 0 || !pending.HasBinding ()
      ? WYRELOG_E_POLICY
      : pending.RevalidateFd ();
  if (validation != WYRELOG_E_OK) {
    health_->Poison (validation);
    io_reject ("new binding");
  }
  if (kind_ == WylSecureDuckdbBindingKind::WRITER_SIDECAR)
    owner_->RegisterSidecarHandle (this);
  pending.Release ();
}

WylSecureDuckdbFileHandle::~WylSecureDuckdbFileHandle ()
{
  try {
    Close ();
  } catch ( ...) {
    /* A provider that cannot prove descriptor identity deliberately leaves it
     * open; a destructor must not raw-close a possibly reused foreign fd. */
  }
  if (kind_ == WylSecureDuckdbBindingKind::WRITER_SIDECAR)
    owner_->UnregisterSidecarHandle (this);
  FreeBinding ();
}

wyrelog_error_t
WylSecureDuckdbFileHandle::RevalidateFd () const
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      return wyl_fact_artifact_main_binding_revalidate_fd (binding_.writer_main,
                 fd_);
    case WylSecureDuckdbBindingKind::READER_MAIN:
      return
        wyl_fact_artifact_reader_main_binding_revalidate_fd
          (binding_.reader_main, fd_);
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      return
        wyl_fact_artifact_sidecar_binding_revalidate_fd
          (binding_.writer_sidecar, fd_);
    case WylSecureDuckdbBindingKind::READER_WAL:
      return
        wyl_fact_artifact_reader_wal_binding_revalidate_fd
          (binding_.reader_wal, fd_);
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      return
        wyl_fact_duckdb_temp_child_binding_revalidate_fd (binding_.temp_child,
            fd_);
  }
  return WYRELOG_E_POLICY;
}

wyrelog_error_t
WylSecureDuckdbFileHandle::CheckedClose ()
{
  if (wyl_secure_duckdb_filesystem_take_test_fault (
        WYL_SECURE_DUCKDB_FILESYSTEM_TEST_FAULT_CHECKED_CLOSE_REVALIDATION))
    (void) close (fd_);
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      return wyl_fact_artifact_main_binding_close (binding_.writer_main, &fd_);
    case WylSecureDuckdbBindingKind::READER_MAIN:
      return wyl_fact_artifact_reader_main_binding_close (binding_.reader_main,
                 &fd_);
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      return wyl_fact_artifact_sidecar_binding_close (binding_.writer_sidecar,
                 &fd_);
    case WylSecureDuckdbBindingKind::READER_WAL:
      return wyl_fact_artifact_reader_wal_binding_close (binding_.reader_wal,
                 &fd_);
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      return wyl_fact_duckdb_temp_child_binding_close (binding_.temp_child,
                 &fd_);
  }
  return WYRELOG_E_POLICY;
}

void
WylSecureDuckdbFileHandle::FreeBinding ()
{
  switch (kind_) {
    case WylSecureDuckdbBindingKind::WRITER_MAIN:
      g_clear_pointer (&binding_.writer_main,
          wyl_fact_artifact_main_binding_free);
      break;
    case WylSecureDuckdbBindingKind::READER_MAIN:
      g_clear_pointer (&binding_.reader_main,
          wyl_fact_artifact_reader_main_binding_free);
      break;
    case WylSecureDuckdbBindingKind::WRITER_SIDECAR:
      g_clear_pointer (&binding_.writer_sidecar,
          wyl_fact_artifact_sidecar_binding_free);
      break;
    case WylSecureDuckdbBindingKind::READER_WAL:
      g_clear_pointer (&binding_.reader_wal,
          wyl_fact_artifact_reader_wal_binding_free);
      break;
    case WylSecureDuckdbBindingKind::TEMP_CHILD:
      g_clear_pointer (&binding_.temp_child,
          wyl_fact_duckdb_temp_child_binding_free);
      break;
  }
}

void
WylSecureDuckdbFileHandle::Revalidate () const
{
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::RevalidateUnlocked () const
{
  RequireHealthy ();
  if (fd_ < 0)
    io_reject ("closed handle");
  const auto result = RevalidateFd ();
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "working descriptor identity");
}

void
WylSecureDuckdbFileHandle::ReadAt (void *buffer, int64_t byte_count,
    duckdb::idx_t location)
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForReading ())
    io_reject ("read without read flag");
  const auto range = checked_range (byte_count, location);
  if (range.bytes != 0 && buffer == nullptr)
    io_reject ("null read buffer");
  RevalidateUnlocked ();
  auto *cursor = static_cast < unsigned char *>(buffer);
  size_t done = 0;
  while (done < range.bytes) {
    const auto offset = checked_progress_offset (range, done);
    const ssize_t amount =
        pread (fd_, cursor + done, range.bytes - done, offset);
    if (amount <= 0)
      PoisonAndReject (WYRELOG_E_IO, "positioned read");
    done += checked_transfer (amount, range.bytes - done).bytes;
  }
  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::WriteAt (void *buffer, int64_t byte_count,
    duckdb::idx_t location)
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForWriting ())
    io_reject ("write without write flag");
  const auto range = checked_range (byte_count, location);
  if (range.bytes != 0 && buffer == nullptr)
    io_reject ("null write buffer");
  RevalidateUnlocked ();
  auto *cursor = static_cast < unsigned char *>(buffer);
  size_t done = 0;
  while (done < range.bytes) {
    const auto offset = checked_progress_offset (range, done);
    const ssize_t amount =
        pwrite (fd_, cursor + done, range.bytes - done, offset);
    if (amount <= 0)
      PoisonAndReject (WYRELOG_E_IO, "positioned write");
    done += checked_transfer (amount, range.bytes - done).bytes;
  }
  RevalidateUnlocked ();
}

int64_t
WylSecureDuckdbFileHandle::ReadSome (void *buffer, int64_t byte_count)
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForReading ())
    io_reject ("read without read flag");
  const auto range = checked_range (byte_count, offset_);
  if (range.bytes != 0 && buffer == nullptr)
    io_reject ("null read buffer");
  RevalidateUnlocked ();
  const ssize_t amount = pread (fd_, buffer, range.bytes, range.offset);
  if (amount < 0)
    PoisonAndReject (WYRELOG_E_IO, "read");
  RevalidateUnlocked ();
  const auto transfer = checked_transfer (amount, range.bytes);
  offset_ += transfer.cursor;
  return transfer.result;
}

int64_t
WylSecureDuckdbFileHandle::WriteSome (void *buffer, int64_t byte_count)
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForWriting ())
    io_reject ("write without write flag");
  const auto range = checked_range (byte_count, offset_);
  if (range.bytes != 0 && buffer == nullptr)
    io_reject ("null write buffer");
  RevalidateUnlocked ();
  const ssize_t amount = pwrite (fd_, buffer, range.bytes, range.offset);
  if (amount < 0)
    PoisonAndReject (WYRELOG_E_IO, "write");
  RevalidateUnlocked ();
  const auto transfer = checked_transfer (amount, range.bytes);
  offset_ += transfer.cursor;
  return transfer.result;
}

void
WylSecureDuckdbFileHandle::Sync ()
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForWriting ())
    io_reject ("sync without write flag");
  RevalidateUnlocked ();
  if (fsync (fd_) != 0)
    PoisonAndReject (WYRELOG_E_IO, "sync");
  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::TruncateTo (int64_t size)
{
  std::lock_guard < std::mutex > lock (mutex_);
  if (!flags.OpenForWriting ())
    io_reject ("truncate without write flag");
  const off_t checked = checked_size (size);
  RevalidateUnlocked ();
  if (ftruncate (fd_, checked) != 0)
    PoisonAndReject (WYRELOG_E_IO, "truncate");
  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::SeekTo (duckdb::idx_t location)
{
  (void) checked_range (0, location);
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
  offset_ = location;
}

duckdb::idx_t WylSecureDuckdbFileHandle::SeekPosition ()const
{
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
  return offset_;
}

int64_t
WylSecureDuckdbFileHandle::Size () const
{
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
  struct stat status;
  if (fstat (fd_, &status) != 0)
    PoisonAndReject (WYRELOG_E_IO, "file size");
  RevalidateUnlocked ();
  return checked_stat_size (status.st_size);
}

duckdb::timestamp_t WylSecureDuckdbFileHandle::LastModifiedTime ()const
{
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
  struct stat
      status;
  if (fstat (fd_, &status) != 0)
    PoisonAndReject (WYRELOG_E_IO, "last modified time");
  RevalidateUnlocked ();
#if defined(__APPLE__)
  return duckdb::timestamp_t (checked_timestamp (status.st_mtimespec.tv_sec,
             status.st_mtimespec.tv_nsec));
#else
  return duckdb::timestamp_t (checked_timestamp (status.st_mtim.tv_sec,
             status.st_mtim.tv_nsec));
#endif
}

duckdb::string WylSecureDuckdbFileHandle::VersionTag ()const
{
  std::lock_guard < std::mutex > lock (mutex_);
  RevalidateUnlocked ();
  struct stat
      status;
  if (fstat (fd_, &status) != 0)
    PoisonAndReject (WYRELOG_E_IO, "version tag");
  RevalidateUnlocked ();
  const
  auto
      size = checked_stat_size (status.st_size);
  return std::to_string (static_cast < uint64_t > (status.st_dev)) + ":"
         + std::to_string (static_cast < uint64_t > (status.st_ino)) + ":"
         + std::to_string (size);
}

void
WylSecureDuckdbFileHandle::Close ()
{
  WylFactArtifactSidecarBinding *closed_sidecar = nullptr;
  {
    std::lock_guard<std::mutex> lock (mutex_);
    if (fd_ < 0)
      return;
    const auto result = CheckedClose ();
    if (result != WYRELOG_E_OK)
      PoisonAndReject (result, "checked close");
    if (kind_ == WylSecureDuckdbBindingKind::WRITER_SIDECAR) {
      closed_sidecar = binding_.writer_sidecar;
      binding_.writer_sidecar = nullptr;
    }
  }
  if (closed_sidecar != nullptr)
    owner_->AdoptClosedSidecarBinding (sidecar_artifact_, closed_sidecar);
}

void
WylSecureDuckdbFileHandle::RequireHealthy () const
{
  if (health_->Status () != WYRELOG_E_OK)
    io_reject ("poisoned filesystem");
}

[[noreturn]] void
WylSecureDuckdbFileHandle::PoisonAndReject (wyrelog_error_t error,
    const char *operation) const
{
  health_->Poison (error);
  io_reject (operation);
}

WylFactArtifactSidecarBinding *
WylSecureDuckdbFileHandle::DetachSidecarBindingForMove ()
{
  std::lock_guard<std::mutex> lock (mutex_);
  if (kind_ != WylSecureDuckdbBindingKind::WRITER_SIDECAR
      || binding_.writer_sidecar == nullptr)
    return nullptr;
  if (fd_ >= 0) {
    const auto result = CheckedClose ();
    if (result != WYRELOG_E_OK)
      PoisonAndReject (result, "checked close before fixed WAL replacement");
  }
  auto *binding = binding_.writer_sidecar;
  binding_.writer_sidecar = nullptr;
  return binding;
}
