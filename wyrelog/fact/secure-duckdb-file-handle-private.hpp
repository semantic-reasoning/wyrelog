/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <mutex>

#include "fact/graph-artifact-namespace-private.h"

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
class WylSecureDuckdbFileHandle final:public
    duckdb::FileHandle
{
public:
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactMainBinding *);
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactReaderMainBinding *);
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactSidecarBinding *);
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylFactArtifactReaderWalBinding *);
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
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
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, const duckdb::string &,
      duckdb::FileOpenFlags, int, WylSecureDuckdbBindingKind);
  wyrelog_error_t
  RevalidateFd () const;
  void
  RevalidateUnlocked () const;
  wyrelog_error_t
  CheckedClose ();
  void
  FreeBinding ();

  WylSecureDuckdbBindingKind
      kind_;
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
