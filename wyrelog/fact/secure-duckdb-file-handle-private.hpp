/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <memory>
#include <mutex>

#include "fact/artifact-io-session-private.h"
#include "fact/graph-artifact-namespace-private.h"

class WylSecureDuckdbFileSystem;

class WylSecureDuckdbHealth final
{
public:
  wyrelog_error_t Status () const;
  void Poison (wyrelog_error_t);

private:
  mutable std::mutex mutex_;
  wyrelog_error_t error_ = WYRELOG_E_OK;
};

/* Own the provider-issued session until FileHandle construction has
 * completed.  In particular, duckdb::make_uniq may throw before the
 * FileHandle constructor is entered. */
class WylSecureDuckdbPendingBinding final
{
public:
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactArtifactIoSession *) noexcept;
#ifndef G_OS_WIN32
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactArtifactMainBinding *, int) noexcept;
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactArtifactReaderMainBinding *, int) noexcept;
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactArtifactSidecarBinding *, int) noexcept;
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactArtifactReaderWalBinding *, int) noexcept;
  WylSecureDuckdbPendingBinding (
    const std::shared_ptr<WylSecureDuckdbHealth> &,
    WylFactDuckdbTempChildBinding *, int) noexcept;
#endif
  ~WylSecureDuckdbPendingBinding ();
  WylSecureDuckdbPendingBinding (
    const WylSecureDuckdbPendingBinding &) = delete;
  WylSecureDuckdbPendingBinding &
  operator = (const WylSecureDuckdbPendingBinding &) = delete;

  wyrelog_error_t
  Reset () noexcept;

private:
  friend class WylSecureDuckdbFileHandle;

  void
  Release () noexcept;
  wyrelog_error_t
  RevalidateSession () const noexcept;
  bool
  HasSession () const noexcept;
  wyrelog_error_t
  CheckedClose () noexcept;
  void
  FreeSession () noexcept;

  std::shared_ptr<WylSecureDuckdbHealth>
  health_;
  WylFactArtifactIoSession *
      session_ = nullptr;
};

/* A DuckDB working descriptor is useful only together with its provider
 * session.  This class never operates on raw file descriptors: every I/O
 * boundary and terminal close operates through the platform-neutral session. */
class WylSecureDuckdbFileHandle final: public
duckdb::FileHandle
{
public:
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, WylFactArtifactName,
      WylSecureDuckdbPendingBinding &&);
  ~
  WylSecureDuckdbFileHandle ()
  override;
  WylSecureDuckdbFileHandle (const WylSecureDuckdbFileHandle &) = delete;
  WylSecureDuckdbFileHandle &
  operator = (const WylSecureDuckdbFileHandle &) = delete;

  void
  ReadAt (void *, int64_t, duckdb::idx_t);
  void
  WriteAt (void *, int64_t, duckdb::idx_t);
  int64_t
  ReadSome (void *, int64_t);
  int64_t
  WriteSome (void *, int64_t);
  void
  Sync ();
  void
  TruncateTo (int64_t);
  void
  Revalidate () const;
  void
  SeekTo (duckdb::idx_t);
  duckdb::idx_t
  SeekPosition () const;
  int64_t
  Size () const;
  duckdb::timestamp_t
  LastModifiedTime () const;
  duckdb::string
  VersionTag () const;
  void
  Close ()
  override;

private:
  friend class WylSecureDuckdbFileSystem;

  wyrelog_error_t
  RevalidateSession () const;
  void
  RevalidateUnlocked () const;
  void
  RequireHealthy () const;
  [[noreturn]] void
  PoisonAndReject (wyrelog_error_t, const char *) const;
#ifndef G_OS_WIN32
  WylFactArtifactSidecarBinding *
  DetachSidecarBindingForMove ();
#endif

  WylSecureDuckdbFileSystem *
      owner_;
  std::shared_ptr<WylSecureDuckdbHealth>
  health_;
  WylFactArtifactName
      sidecar_artifact_ = WYL_FACT_ARTIFACT_MAIN;
  WylFactArtifactIoSession *
      session_ = nullptr;
  mutable
  std::mutex
      mutex_;
  duckdb::idx_t
      offset_;
};
