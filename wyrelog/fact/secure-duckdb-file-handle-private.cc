/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef G_OS_WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "fact/secure-duckdb-file-handle-private.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

WylSecureDuckdbFileHandle::WylSecureDuckdbFileHandle (duckdb::FileSystem &fs,
    WylFactArtifactNamespace *ns, WylFactArtifactName artifact,
    const duckdb::string &path, duckdb::FileOpenFlags flags, int owned_fd,
    bool lock_held)
    : duckdb::FileHandle (fs, path, flags), namespace_ (ns),
      artifact_ (artifact), fd_ (owned_fd), device_ (0), inode_ (0),
      lock_held_ (lock_held)
{
  if (ns == nullptr || fd_ < 0 || wyl_fact_artifact_namespace_revalidate (ns)
      != WYRELOG_E_OK) {
    if (fd_ >= 0)
      close (fd_);
    fd_ = -1;
    return;
  }
  struct stat st;
  if (fstat (fd_, &st) != 0 || !S_ISREG (st.st_mode) || st.st_nlink != 1
      || wyl_fact_artifact_namespace_revalidate (ns) != WYRELOG_E_OK) {
    close (fd_); fd_ = -1; return;
  }
  device_ = st.st_dev; inode_ = st.st_ino;
}

WylSecureDuckdbFileHandle::~WylSecureDuckdbFileHandle ()
{ if (fd_ >= 0) close (fd_); }

bool WylSecureDuckdbFileHandle::Revalidate () const
{
  if (fd_ < 0 || namespace_ == nullptr
      || wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    return false;
  struct stat st;
  return fstat (fd_, &st) == 0 && S_ISREG (st.st_mode) && st.st_nlink == 1
      && st.st_dev == device_ && st.st_ino == inode_;
}

bool WylSecureDuckdbFileHandle::ReadAt (void *buffer, duckdb::idx_t bytes,
    duckdb::idx_t location)
{
  if (!Revalidate ()) return false;
  const ssize_t n = pread (fd_, buffer, bytes, (off_t) location);
  return n == (ssize_t) bytes && Revalidate ();
}

bool WylSecureDuckdbFileHandle::WriteAt (void *buffer, duckdb::idx_t bytes,
    duckdb::idx_t location)
{
  if (!Revalidate ()) return false;
  const ssize_t n = pwrite (fd_, buffer, bytes, (off_t) location);
  return n == (ssize_t) bytes && Revalidate ();
}

bool WylSecureDuckdbFileHandle::Sync ()
{ return Revalidate () && fsync (fd_) == 0 && Revalidate (); }

bool WylSecureDuckdbFileHandle::TruncateTo (int64_t size)
{ return size >= 0 && Revalidate () && ftruncate (fd_, size) == 0
      && Revalidate (); }
