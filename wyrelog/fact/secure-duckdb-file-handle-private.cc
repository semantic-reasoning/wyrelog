/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/secure-duckdb-file-handle-private.hpp"
#include "fact/secure-duckdb-filesystem-private.hpp"

#include <climits>
#include <cstdint>
#include <limits>

namespace {

  static_assert (std::numeric_limits < duckdb::idx_t >::is_integer
      && !std::numeric_limits < duckdb::idx_t >::is_signed,
      "DuckDB idx_t must remain an unsigned integer");
  static_assert (sizeof (duckdb::idx_t) >= sizeof (uint64_t),
      "DuckDB idx_t must represent every nonnegative uint64_t");
  static_assert (sizeof (size_t) <= sizeof (uint64_t),
      "adapter arithmetic requires uint64_t to represent size_t");

  [[noreturn]] void io_reject (const char *operation)
  {
    throw duckdb::IOException ("bounded DuckDB file handle rejected %s",
        operation);
  }

  struct CheckedRange
  {
    size_t bytes;
    uint64_t offset;
  };

  struct CheckedTransfer
  {
    size_t bytes;
    duckdb::idx_t cursor;
    int64_t result;
  };

/* This is the single adapter conversion boundary.  Validate a complete
 * request before buffer access, session operation, or cursor mutation. */
  CheckedRange checked_range (int64_t byte_count, duckdb::idx_t location)
  {
    if (byte_count < 0 || static_cast < uint64_t > (byte_count)
        > static_cast < uint64_t > (SSIZE_MAX)
        || location
        > static_cast < duckdb::idx_t > (std::numeric_limits < uint64_t >::max ()))
      io_reject ("numeric conversion");
    const auto bytes = static_cast < uint64_t > (byte_count);
    const auto offset = static_cast < uint64_t > (location);
    if (offset > static_cast < uint64_t > (SSIZE_MAX)
        || bytes > static_cast < uint64_t > (SSIZE_MAX) - offset)
      io_reject ("numeric endpoint");
    return {
             static_cast < size_t >(bytes), static_cast < uint64_t > (offset)
    };
  }

  CheckedTransfer
  checked_transfer (gsize amount, size_t remaining)
  {
    if (static_cast < uint64_t > (amount)
        > static_cast < uint64_t > (remaining))
      io_reject ("session transfer");
    const auto transferred = static_cast < uint64_t > (amount);
    return {
             static_cast < size_t > (transferred),
             static_cast < duckdb::idx_t > (transferred),
             static_cast < int64_t > (transferred)
    };
  }

  uint64_t checked_size (int64_t size)
  {
    if (size < 0 || static_cast < uint64_t > (size)
        > static_cast < uint64_t > (std::numeric_limits < uint64_t >::max ()))
      io_reject ("truncate conversion");
    return static_cast < uint64_t > (size);
  }

  int64_t checked_stat_size (uint64_t size)
  {
    if (static_cast < uint64_t > (size)
        > static_cast < uint64_t > (std::numeric_limits < int64_t >::max ()))
      io_reject ("file-size conversion");
    return static_cast < int64_t > (size);
  }

  int64_t checked_timestamp (uint64_t seconds, uint32_t nanoseconds)
  {
    constexpr uint64_t scale = 1000000;
    if (nanoseconds >= 1000000000U
        || seconds > (static_cast<uint64_t>(std::numeric_limits < int64_t >::max ())
        - nanoseconds / 1000) / scale)
      io_reject ("timestamp conversion");
    return static_cast<int64_t>(seconds * scale + nanoseconds / 1000);
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
  WylFactArtifactIoSession *session) noexcept
  : health_ (health), session_ (session)
{
}

#ifndef G_OS_WIN32
WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactMainBinding *binding, int fd) noexcept
  : health_ (health)
{
  (void) wyl_fact_artifact_io_session_new_writer_main (binding, fd, &session_);
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactReaderMainBinding *binding, int fd) noexcept
  : health_ (health)
{
  (void) wyl_fact_artifact_io_session_new_reader_main (binding, fd, &session_);
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactSidecarBinding *binding, int fd) noexcept
  : health_ (health)
{
  (void) wyl_fact_artifact_io_session_new_writer_sidecar (binding, fd, &session_);
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactArtifactReaderWalBinding *binding, int fd) noexcept
  : health_ (health)
{
  (void) wyl_fact_artifact_io_session_new_reader_wal (binding, fd, &session_);
}

WylSecureDuckdbPendingBinding::WylSecureDuckdbPendingBinding (
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  WylFactDuckdbTempChildBinding *binding, int fd) noexcept
  : health_ (health)
{
  (void) wyl_fact_artifact_io_session_new_temp_child (binding, fd, &session_);
}
#endif

WylSecureDuckdbPendingBinding::~WylSecureDuckdbPendingBinding ()
{
  FreeSession ();
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::Reset () noexcept
{
  const auto result = CheckedClose ();
  FreeSession ();
  if (result != WYRELOG_E_OK)
    health_->Poison (result);
  return result;
}

void
WylSecureDuckdbPendingBinding::Release () noexcept
{
  session_ = nullptr;
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::RevalidateSession () const noexcept
{
  if (session_ == nullptr)
    return WYRELOG_E_POLICY;
  return wyl_fact_artifact_io_session_revalidate (session_);
}

bool
WylSecureDuckdbPendingBinding::HasSession () const noexcept
{
  return session_ != nullptr;
}

wyrelog_error_t
WylSecureDuckdbPendingBinding::CheckedClose () noexcept
{
  if (session_ == nullptr)
    return WYRELOG_E_OK;
  const auto result = wyl_fact_artifact_io_session_finish (session_);
  session_ = nullptr;
  return result;
}

void
WylSecureDuckdbPendingBinding::FreeSession () noexcept
{
  if (session_ != nullptr) {
    wyl_fact_artifact_io_session_free (session_);
    session_ = nullptr;
  }
}

WylSecureDuckdbFileHandle::WylSecureDuckdbFileHandle (
  WylSecureDuckdbFileSystem &owner,
  const std::shared_ptr<WylSecureDuckdbHealth> &health,
  const duckdb::string &path, duckdb::FileOpenFlags flags,
  WylFactArtifactName sidecar_artifact,
  WylSecureDuckdbPendingBinding &&pending)
  : duckdb::FileHandle (owner, path, flags),
  owner_ (&owner),
  health_ (health),
  sidecar_artifact_ (sidecar_artifact),
  session_ (pending.session_),
  offset_ (0)
{
  if (health_ == nullptr || session_ == nullptr
      || pending.RevalidateSession () != WYRELOG_E_OK) {
    pending.Reset ();
    PoisonAndReject (WYRELOG_E_POLICY, "constructor session validation");
  }
  pending.Release ();
#ifndef G_OS_WIN32
  if (wyl_fact_artifact_io_session_get_kind (session_)
      == WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR)
    owner_->RegisterSidecarHandle (this);
#endif
}

WylSecureDuckdbFileHandle::~WylSecureDuckdbFileHandle ()
{
  try {
    Close ();
  } catch ( ...) {
    /* A provider that cannot prove descriptor identity deliberately leaves it
     * open; a destructor must not raw-close a possibly reused foreign fd. */
  }
#ifndef G_OS_WIN32
  owner_->UnregisterSidecarHandle (this);
#endif
}

void
WylSecureDuckdbFileHandle::RequireHealthy () const
{
  const auto status = health_->Status ();
  if (status != WYRELOG_E_OK)
    PoisonAndReject (status, "health state");
}

[[noreturn]] void
WylSecureDuckdbFileHandle::PoisonAndReject (wyrelog_error_t error,
    const char *operation) const
{
  health_->Poison (error);
  io_reject (operation);
}

wyrelog_error_t
WylSecureDuckdbFileHandle::RevalidateSession () const
{
  if (session_ == nullptr)
    return WYRELOG_E_POLICY;
  return wyl_fact_artifact_io_session_revalidate (session_);
}

void
WylSecureDuckdbFileHandle::RevalidateUnlocked () const
{
  RequireHealthy ();
  const auto result = RevalidateSession ();
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "boundary revalidation");
}

void
WylSecureDuckdbFileHandle::Revalidate () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::ReadAt (void *buffer, int64_t bytes,
    duckdb::idx_t location)
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  const auto range = checked_range (bytes, location);
  gsize bytes_read = 0;
  const auto result = wyl_fact_artifact_io_session_read (session_,
          range.offset, buffer, range.bytes, &bytes_read);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "ReadAt session read");

  const auto transfer = checked_transfer (bytes_read, range.bytes);
  if (transfer.bytes != range.bytes)
    PoisonAndReject (WYRELOG_E_IO, "short read");

  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::WriteAt (void *buffer, int64_t bytes,
    duckdb::idx_t location)
{
  std::lock_guard<std::mutex> lock (mutex_);
  if (!flags.OpenForWriting ())
    io_reject ("write without write flag");
  RevalidateUnlocked ();

  const auto range = checked_range (bytes, location);
  if (range.bytes != 0 && buffer == nullptr)
    io_reject ("null write buffer");
  gsize bytes_written = 0;
  const auto result = wyl_fact_artifact_io_session_write (session_,
          range.offset, buffer, range.bytes, &bytes_written);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "WriteAt session write");

  const auto transfer = checked_transfer (bytes_written, range.bytes);
  if (transfer.bytes != range.bytes)
    PoisonAndReject (WYRELOG_E_IO, "short write");

  RevalidateUnlocked ();
}

int64_t
WylSecureDuckdbFileHandle::ReadSome (void *buffer, int64_t bytes)
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  const auto range = checked_range (bytes, offset_);
  gsize bytes_read = 0;
  const auto result = wyl_fact_artifact_io_session_read (session_,
          range.offset, buffer, range.bytes, &bytes_read);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "ReadSome session read");

  const auto transfer = checked_transfer (bytes_read, range.bytes);
  offset_ += transfer.cursor;

  RevalidateUnlocked ();
  return transfer.result;
}

int64_t
WylSecureDuckdbFileHandle::WriteSome (void *buffer, int64_t bytes)
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  const auto range = checked_range (bytes, offset_);
  gsize bytes_written = 0;
  const auto result = wyl_fact_artifact_io_session_write (session_,
          range.offset, buffer, range.bytes, &bytes_written);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "WriteSome session write");

  const auto transfer = checked_transfer (bytes_written, range.bytes);
  offset_ += transfer.cursor;

  RevalidateUnlocked ();
  return transfer.result;
}

void
WylSecureDuckdbFileHandle::Sync ()
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  const auto result = wyl_fact_artifact_io_session_flush (session_);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "Sync session flush");

  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::TruncateTo (int64_t size)
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  const auto target_size = checked_size (size);
  const auto result = wyl_fact_artifact_io_session_truncate (session_,
          target_size);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "TruncateTo session truncate");

  RevalidateUnlocked ();
}

void
WylSecureDuckdbFileHandle::SeekTo (duckdb::idx_t location)
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();
  (void) checked_range (0, location);
  offset_ = location;
}

duckdb::idx_t
WylSecureDuckdbFileHandle::SeekPosition () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();
  return offset_;
}

int64_t
WylSecureDuckdbFileHandle::Size () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  guint64 size = 0;
  const auto result = wyl_fact_artifact_io_session_size (session_, &size);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "Size session size");

  RevalidateUnlocked ();
  return checked_stat_size (size);
}

duckdb::timestamp_t
WylSecureDuckdbFileHandle::LastModifiedTime () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  guint64 seconds = 0;
  guint32 nanoseconds = 0;
  const auto result = wyl_fact_artifact_io_session_last_modified (session_,
          &seconds, &nanoseconds);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "last modified time");

  RevalidateUnlocked ();
  const auto micros = checked_timestamp (seconds, nanoseconds);
  return duckdb::timestamp_t (micros);
}

duckdb::string
WylSecureDuckdbFileHandle::VersionTag () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  RevalidateUnlocked ();

  guint64 size = 0;
  const auto result = wyl_fact_artifact_io_session_size (session_, &size);
  if (result != WYRELOG_E_OK)
    PoisonAndReject (result, "version tag size");

  RevalidateUnlocked ();
  const auto checked = checked_stat_size (size);
  return std::to_string (checked);
}

void
WylSecureDuckdbFileHandle::Close ()
{
  WylFactArtifactSidecarBinding *closed_sidecar = nullptr;
  {
    std::lock_guard<std::mutex> lock (mutex_);
    if (session_ == nullptr)
      return;
#ifndef G_OS_WIN32
    if (wyl_fact_artifact_io_session_get_kind (session_)
        == WYL_FACT_ARTIFACT_IO_SESSION_WRITER_SIDECAR) {
      /* A closed WAL sidecar binding is handed to the filesystem so a later
       * fixed replacement can reuse it; it is retained, not freed here. */
      const auto close_result = wyl_fact_artifact_io_session_close (session_);
      if (close_result == WYRELOG_E_OK)
        closed_sidecar =
            wyl_fact_artifact_io_session_detach_writer_sidecar (session_);
      wyl_fact_artifact_io_session_free (session_);
      session_ = nullptr;
      if (close_result != WYRELOG_E_OK)
        PoisonAndReject (close_result, "checked close");
    } else {
#endif
    const auto close_result = wyl_fact_artifact_io_session_finish (session_);
    session_ = nullptr;
    if (close_result != WYRELOG_E_OK)
      PoisonAndReject (close_result, "checked close");
#ifndef G_OS_WIN32
  }
#endif
  }
  if (closed_sidecar != nullptr)
    owner_->AdoptClosedSidecarBinding (sidecar_artifact_, closed_sidecar);
}

#ifndef G_OS_WIN32
WylFactArtifactSidecarBinding *
WylSecureDuckdbFileHandle::DetachSidecarBindingForMove ()
{
  std::lock_guard<std::mutex> lock (mutex_);
  RequireHealthy ();
  if (session_ == nullptr)
    return nullptr;
  /* Revalidate the pinned identity before mutating anything, so a rejected
   * move leaves the binding intact for the handle's own Close() to re-detect
   * and reject.  On success, checked-close the working descriptor, then detach
   * and release the session husk: the mover owns the sole binding and the
   * handle's later Close() is a clean no-op that cannot touch a reused fd. */
  const auto revalidate = wyl_fact_artifact_io_session_revalidate (session_);
  if (revalidate != WYRELOG_E_OK)
    PoisonAndReject (revalidate, "revalidate before sidecar detach");
  const auto close_result = wyl_fact_artifact_io_session_close (session_);
  if (close_result != WYRELOG_E_OK)
    PoisonAndReject (close_result, "checked close before sidecar detach");
  WylFactArtifactSidecarBinding *sidecar =
      wyl_fact_artifact_io_session_detach_writer_sidecar (session_);
  wyl_fact_artifact_io_session_free (session_);
  session_ = nullptr;
  return sidecar;
}
#endif
