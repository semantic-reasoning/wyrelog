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
    int owned_lock_fd)
    : duckdb::FileHandle (fs, path, flags), namespace_ (ns),
      artifact_ (artifact), fd_ (owned_fd), device_ (0), inode_ (0),
      lock_fd_ (owned_lock_fd), offset_ (0)
{
  if (ns == nullptr || fd_ < 0 || wyl_fact_artifact_namespace_revalidate (ns)
      != WYRELOG_E_OK) {
    if (fd_ >= 0)
      close (fd_);
    if (lock_fd_ >= 0)
      close (lock_fd_);
    fd_ = -1;
    lock_fd_ = -1;
    return;
  }
  struct stat st;
  if (fstat (fd_, &st) != 0 || !S_ISREG (st.st_mode) || st.st_nlink != 1
      || wyl_fact_artifact_namespace_revalidate (ns) != WYRELOG_E_OK) {
    close (fd_); fd_ = -1;
    if (lock_fd_ >= 0) close (lock_fd_);
    lock_fd_ = -1;
    return;
  }
  device_ = st.st_dev; inode_ = st.st_ino;
}

WylSecureDuckdbFileHandle::~WylSecureDuckdbFileHandle ()
{ Close (); }

bool WylSecureDuckdbFileHandle::Revalidate () const
{
  if (fd_ < 0 || namespace_ == nullptr
      || wyl_fact_artifact_namespace_revalidate (namespace_) != WYRELOG_E_OK)
    return false;
  if (artifact_ != WYL_FACT_ARTIFACT_MAIN
      && wyl_fact_artifact_namespace_revalidate_main (namespace_)
          != WYRELOG_E_OK)
    return false;
  struct stat st;
  return fstat (fd_, &st) == 0 && S_ISREG (st.st_mode) && st.st_nlink == 1
      && st.st_dev == device_ && st.st_ino == inode_;
}

bool WylSecureDuckdbFileHandle::ReadAt (void *buffer, duckdb::idx_t bytes,
    duckdb::idx_t location)
{
  if (!Revalidate ())
    return false;
  auto *cursor = static_cast<unsigned char *> (buffer);
  duckdb::idx_t done = 0;
  while (done < bytes) {
    const ssize_t n = pread (fd_, cursor + done, bytes - done,
        static_cast<off_t> (location + done));
    if (n <= 0)
      return false;
    done += static_cast<duckdb::idx_t> (n);
  }
  return Revalidate ();
}

bool WylSecureDuckdbFileHandle::WriteAt (void *buffer, duckdb::idx_t bytes,
    duckdb::idx_t location)
{
  if (!Revalidate ())
    return false;
  auto *cursor = static_cast<unsigned char *> (buffer);
  duckdb::idx_t done = 0;
  while (done < bytes) {
    const ssize_t n = pwrite (fd_, cursor + done, bytes - done,
        static_cast<off_t> (location + done));
    if (n <= 0)
      return false;
    done += static_cast<duckdb::idx_t> (n);
  }
  return Revalidate ();
}

bool WylSecureDuckdbFileHandle::Sync ()
{ return Revalidate () && fsync (fd_) == 0 && Revalidate (); }

bool WylSecureDuckdbFileHandle::TruncateTo (int64_t size)
{ return size >= 0 && Revalidate () && ftruncate (fd_, size) == 0
      && Revalidate (); }

int64_t WylSecureDuckdbFileHandle::ReadSome (void *buffer, int64_t bytes)
{
  if (bytes < 0 || !buffer)
    return -1;
  std::lock_guard<std::mutex> lock (mutex_);
  if (!Revalidate ()) return -1;
  const ssize_t n = pread (fd_, buffer, (size_t) bytes, (off_t) offset_);
  if (n < 0 || !Revalidate ()) return -1;
  offset_ += (duckdb::idx_t) n;
  return n;
}

int64_t WylSecureDuckdbFileHandle::WriteSome (void *buffer, int64_t bytes)
{
  if (bytes < 0 || !buffer)
    return -1;
  std::lock_guard<std::mutex> lock (mutex_);
  if (!Revalidate ()) return -1;
  const ssize_t n = pwrite (fd_, buffer, (size_t) bytes, (off_t) offset_);
  if (n < 0 || !Revalidate ()) return -1;
  offset_ += (duckdb::idx_t) n;
  return n;
}

bool WylSecureDuckdbFileHandle::SeekTo (duckdb::idx_t offset)
{
  std::lock_guard<std::mutex> lock (mutex_);
  if (!Revalidate ()) return false;
  offset_ = offset;
  return true;
}

duckdb::idx_t WylSecureDuckdbFileHandle::SeekPosition () const
{
  std::lock_guard<std::mutex> lock (mutex_);
  return Revalidate () ? offset_ : 0;
}

int64_t WylSecureDuckdbFileHandle::Size () const
{
  if (!Revalidate ()) return -1;
  struct stat st;
  return fstat (fd_, &st) == 0 && Revalidate () ? st.st_size : -1;
}

duckdb::timestamp_t WylSecureDuckdbFileHandle::LastModifiedTime () const
{
  if (!Revalidate ()) return duckdb::timestamp_t::ninfinity ();
  struct stat st;
  if (fstat (fd_, &st) != 0 || !Revalidate ())
    return duckdb::timestamp_t::ninfinity ();
#if defined(__APPLE__)
  return duckdb::timestamp_t ((int64_t) st.st_mtimespec.tv_sec * 1000000
      + st.st_mtimespec.tv_nsec / 1000);
#else
  return duckdb::timestamp_t ((int64_t) st.st_mtim.tv_sec * 1000000
      + st.st_mtim.tv_nsec / 1000);
#endif
}

void WylSecureDuckdbFileHandle::Close ()
{
  std::lock_guard<std::mutex> lock (mutex_);
  if (fd_ >= 0) close (fd_);
  if (lock_fd_ >= 0) close (lock_fd_);
  fd_ = -1;
  lock_fd_ = -1;
}
