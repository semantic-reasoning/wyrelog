/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <memory>
#include <mutex>

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

enum class WylSecureDuckdbBindingKind
{
  WRITER_MAIN,
  READER_MAIN,
  WRITER_SIDECAR,
  READER_WAL,
  TEMP_CHILD,
};

/* A DuckDB working descriptor is useful only together with its provider
 * binding.  This class never closes a raw descriptor behind the provider:
 * every I/O boundary and the terminal close validate the actual descriptor
 * number through the authority that issued it. */
class WylSecureDuckdbFileHandle final: public
duckdb::FileHandle
{
public:
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactMainBinding *);
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactReaderMainBinding *);
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactName,
      WylFactArtifactSidecarBinding *);
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactReaderWalBinding *);
  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactDuckdbTempChildBinding *);
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

  WylSecureDuckdbFileHandle (WylSecureDuckdbFileSystem &,
      const std::shared_ptr<WylSecureDuckdbHealth> &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylSecureDuckdbBindingKind);
  wyrelog_error_t
  RevalidateFd () const;
  void
  RevalidateUnlocked () const;
  wyrelog_error_t
  CheckedClose ();
  void
  FreeBinding ();
  void
  RequireHealthy () const;
  [[noreturn]] void
  PoisonAndReject (wyrelog_error_t, const char *) const;
  WylFactArtifactSidecarBinding *
  DetachSidecarBindingForMove ();

  WylSecureDuckdbFileSystem *
      owner_;
  std::shared_ptr<WylSecureDuckdbHealth>
  health_;
  WylSecureDuckdbBindingKind
      kind_;
  WylFactArtifactName
      sidecar_artifact_ = WYL_FACT_ARTIFACT_MAIN;
  int
      fd_;
  union
  {
    WylFactArtifactMainBinding *
        writer_main;
    WylFactArtifactReaderMainBinding *
        reader_main;
    WylFactArtifactSidecarBinding *
        writer_sidecar;
    WylFactArtifactReaderWalBinding *
        reader_wal;
    WylFactDuckdbTempChildBinding *
        temp_child;
  } binding_;
  mutable
  std::mutex
      mutex_;
  duckdb::idx_t
      offset_;
};
