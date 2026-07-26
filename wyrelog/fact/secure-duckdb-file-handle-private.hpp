/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <duckdb.hpp>
#include <memory>
#include <mutex>
#ifndef G_OS_WIN32
#include <sys/types.h>
#endif
#include "fact/graph-artifact-namespace-private.h"

/* Private POSIX handle used by the bounded DuckDB filesystem.  It owns a
 * duplicated descriptor and never resolves the logical name as a pathname. */
class WylSecureDuckdbFileHandle final : public duckdb::FileHandle
{
public:
  WylSecureDuckdbFileHandle (duckdb::FileSystem &, WylFactArtifactNamespace *,
      WylFactArtifactName, const duckdb::string &, duckdb::FileOpenFlags,
      int owned_fd, int owned_lock_fd = -1);
  ~WylSecureDuckdbFileHandle () override;
  WylSecureDuckdbFileHandle (const WylSecureDuckdbFileHandle &) = delete;
  WylSecureDuckdbFileHandle &operator =
      (const WylSecureDuckdbFileHandle &) = delete;

  bool ReadAt (void *, duckdb::idx_t, duckdb::idx_t);
  bool WriteAt (void *, duckdb::idx_t, duckdb::idx_t);
  int64_t ReadSome (void *, int64_t);
  int64_t WriteSome (void *, int64_t);
  bool Sync (); bool TruncateTo (int64_t);
  bool Revalidate () const;
  bool SeekTo (duckdb::idx_t);
  duckdb::idx_t SeekPosition () const;
  int64_t Size () const;
  duckdb::timestamp_t LastModifiedTime () const;
  void Close () override;
  int Fd () const { return fd_; }
  bool LockHeld () const { return lock_fd_ >= 0; }

private:
  WylFactArtifactNamespace *namespace_;
  WylFactArtifactName artifact_;
  int fd_;
  dev_t device_;
  ino_t inode_;
  int lock_fd_;
  mutable std::mutex mutex_;
  duckdb::idx_t offset_;
};
