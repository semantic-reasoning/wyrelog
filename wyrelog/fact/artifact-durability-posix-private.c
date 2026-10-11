/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#endif

#include "fact/artifact-durability-posix-private.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

WylFactArtifactDurabilityResult
wyl_fact_artifact_durability_classify_fullfsync_errno (gint error_number)
{
  if (error_number == EINVAL || error_number == ENOTTY
      || error_number == ENOTSUP || error_number == EOPNOTSUPP)
    return WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
  return WYL_FACT_ARTIFACT_DURABILITY_ERROR;
}

WylFactArtifactDurabilityResult
wyl_fact_artifact_durability_classify_directory_fsync_errno (gint error_number)
{
  if (error_number == EINVAL || error_number == ENOTSUP
      || error_number == EOPNOTSUPP)
    return WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
  return WYL_FACT_ARTIFACT_DURABILITY_ERROR;
}

#ifdef __APPLE__
static WylFactArtifactDurabilityResult
fullfsync_fd (gint fd)
{
#ifdef F_FULLFSYNC
  if (fcntl (fd, F_FULLFSYNC) == 0)
    return WYL_FACT_ARTIFACT_DURABILITY_PROVEN;
  gint error_number = errno;
  return wyl_fact_artifact_durability_classify_fullfsync_errno
           (error_number);
#else
  (void) fd;
  return WYL_FACT_ARTIFACT_DURABILITY_UNSUPPORTED;
#endif
}
#endif

WylFactArtifactDurabilityResult
wyl_fact_artifact_durability_sync_fd (gint fd)
{
  struct stat st;
  if (fd < 0 || fstat (fd, &st) != 0)
    return WYL_FACT_ARTIFACT_DURABILITY_ERROR;

  if (S_ISREG (st.st_mode)) {
#ifdef __APPLE__
    return fullfsync_fd (fd);
#else
    return fsync (fd) == 0 ? WYL_FACT_ARTIFACT_DURABILITY_PROVEN
                           : WYL_FACT_ARTIFACT_DURABILITY_ERROR;
#endif
  }

  if (S_ISDIR (st.st_mode)) {
    if (fsync (fd) != 0) {
      gint error_number = errno;
      return wyl_fact_artifact_durability_classify_directory_fsync_errno
               (error_number);
    }
#ifdef __APPLE__
    return fullfsync_fd (fd);
#else
    return WYL_FACT_ARTIFACT_DURABILITY_PROVEN;
#endif
  }

  errno = EINVAL;
  return WYL_FACT_ARTIFACT_DURABILITY_ERROR;
}

gboolean
wyl_fact_artifact_durability_sync_fd_proven (gint fd)
{
  return wyl_fact_artifact_durability_sync_fd (fd)
         == WYL_FACT_ARTIFACT_DURABILITY_PROVEN;
}
