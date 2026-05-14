/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 open(O_NOFOLLOW|O_CLOEXEC|O_NOCTTY) and the
 * fstat/read/close trio under strict c_std=c17. Must precede every
 * system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "wyctl-token-file.h"

#include <errno.h>
#include <string.h>

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

const gchar *
wyctl_token_file_status_message (WyctlTokenFileStatus status)
{
  switch (status) {
    case WYCTL_TOKEN_FILE_OK:
      return NULL;
    case WYCTL_TOKEN_FILE_MISSING_PATH:
      return "wyctl: missing --access-token-file";
    case WYCTL_TOKEN_FILE_NOT_FOUND:
      return "wyctl: access token file not found: %s";
    case WYCTL_TOKEN_FILE_SYMLINK:
      return "wyctl: access token file is a symlink"
          " (refusing to follow): %s";
    case WYCTL_TOKEN_FILE_NOT_REGULAR:
      return "wyctl: access token file is not a regular file: %s";
    case WYCTL_TOKEN_FILE_OWNER_MISMATCH:
      return "wyctl: access token file not owned by current user: %s";
    case WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD:
      return "wyctl: access token file permissions too broad"
          " (require 0600): %s";
    case WYCTL_TOKEN_FILE_IO:
      return "wyctl: unable to read access token file: %s";
    case WYCTL_TOKEN_FILE_EMPTY:
      return "wyctl: empty access token file: %s";
    case WYCTL_TOKEN_FILE_INVALID_BYTES:
      return "wyctl: invalid access token file: %s";
    case WYCTL_TOKEN_FILE_TOO_LARGE:
      return "wyctl: access token file too large: %s";
    case WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY:
      return "wyctl: access token file not marked read-only: %s";
    case WYCTL_TOKEN_FILE_WINDOWS_ACL_UNAVAILABLE:
      return "wyctl: access token file ACL validation unavailable: %s";
  }
  return NULL;
}

#ifndef G_OS_WIN32
WyctlTokenFileStatus
wyctl_token_file_classify_stat (const struct stat *st, uid_t euid)
{
  if (st == NULL)
    return WYCTL_TOKEN_FILE_IO;
  if (!S_ISREG (st->st_mode))
    return WYCTL_TOKEN_FILE_NOT_REGULAR;
  if (st->st_uid != euid)
    return WYCTL_TOKEN_FILE_OWNER_MISMATCH;
  if ((st->st_mode & (S_IRWXG | S_IRWXO)) != 0)
    return WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD;
  return WYCTL_TOKEN_FILE_OK;
}
#endif

WyctlTokenFileStatus
wyctl_token_file_read (const gchar *path, gchar **out_token)
{
  if (out_token == NULL)
    return WYCTL_TOKEN_FILE_IO;
  *out_token = NULL;

  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;

#ifdef G_OS_WIN32
  /* Stubbed for commit 6 to wire GetFileAttributesW + read-only
   * attribute + reparse-point rejection. The status is selected so
   * any caller that mistakenly ships without the Windows path lit
   * fails closed. */
  (void) path;
  return WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY;
#else
  int fd = open (path, O_NOFOLLOW | O_CLOEXEC | O_RDONLY | O_NOCTTY);
  if (fd < 0) {
    int saved = errno;
    if (saved == ELOOP)
      return WYCTL_TOKEN_FILE_SYMLINK;
    if (saved == ENOENT || saved == ENOTDIR)
      return WYCTL_TOKEN_FILE_NOT_FOUND;
    return WYCTL_TOKEN_FILE_IO;
  }

  struct stat st;
  if (fstat (fd, &st) != 0) {
    close (fd);
    return WYCTL_TOKEN_FILE_IO;
  }

  WyctlTokenFileStatus classify = wyctl_token_file_classify_stat (&st,
      geteuid ());
  if (classify != WYCTL_TOKEN_FILE_OK) {
    close (fd);
    return classify;
  }

  if (st.st_size > (off_t) WYCTL_TOKEN_FILE_MAX_BYTES) {
    close (fd);
    return WYCTL_TOKEN_FILE_TOO_LARGE;
  }

  /* Read from the same fd we fstatted. No second path-based syscall
   * is allowed past this point — that would reopen the TOCTOU
   * window the open(O_NOFOLLOW) + fstat sequence just closed. */
  gsize cap = WYCTL_TOKEN_FILE_MAX_BYTES;
  gchar *buf = g_malloc (cap + 1);
  gsize got = 0;
  while (got < cap) {
    ssize_t n = read (fd, buf + got, cap - got);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      close (fd);
      g_free (buf);
      return WYCTL_TOKEN_FILE_IO;
    }
    if (n == 0)
      break;
    got += (gsize) n;
  }
  if (got >= cap) {
    /* Probe for additional bytes; if the file grew during read or
     * the initial st.st_size was misleading (e.g. sparse), we still
     * refuse to truncate. */
    gchar overflow = 0;
    ssize_t n = read (fd, &overflow, 1);
    if (n > 0) {
      close (fd);
      g_free (buf);
      return WYCTL_TOKEN_FILE_TOO_LARGE;
    }
  }
  close (fd);
  buf[got] = '\0';

  if (got == 0) {
    g_free (buf);
    return WYCTL_TOKEN_FILE_EMPTY;
  }

  /* Embedded NUL bytes never belong in a bearer token. Surfacing
   * INVALID_BYTES here keeps higher-level normalize logic from
   * mis-classifying the file. */
  if (memchr (buf, '\0', got) != NULL) {
    g_free (buf);
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  }

  *out_token = buf;
  return WYCTL_TOKEN_FILE_OK;
#endif
}
