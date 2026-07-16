/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 open(O_NOFOLLOW|O_CLOEXEC|O_NOCTTY) and the
 * fstat/read/close trio under strict c_std=c17. Must precede every
 * system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* Apple SDKs gate POSIX-only BSD features behind _DARWIN_C_SOURCE
 * when the compiler is invoked under -std=cNN (clang predefines
 * __STRICT_ANSI__). _POSIX_C_SOURCE alone does not expose
 * O_NOFOLLOW on macOS. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "wyctl-token-file.h"

#include <errno.h>
#include <glib/gstdio.h>
#include <string.h>

#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

void
wyctl_token_file_free_sensitive (gchar *value, gsize capacity)
{
  if (value == NULL)
    return;
  if (capacity == 0)
    capacity = strlen (value) + 1;
  volatile gchar *wipe = (volatile gchar *) value;
  for (gsize i = 0; i < capacity; i++)
    wipe[i] = 0;
  g_free (value);
}

WyctlTokenFileStatus
wyctl_token_file_write_protected (const gchar *path, const gchar *token,
    gsize token_len)
{
  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;
  if (token == NULL || token_len == 0 || token_len > WYCTL_TOKEN_FILE_MAX_BYTES)
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
#ifdef G_OS_WIN32
  wchar_t *wpath = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wpath == NULL)
    return WYCTL_TOKEN_FILE_IO;
  HANDLE h = CreateFileW (wpath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
      FILE_ATTRIBUTE_READONLY, NULL);
  g_free (wpath);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError () == ERROR_FILE_EXISTS
        ? WYCTL_TOKEN_FILE_IO : WYCTL_TOKEN_FILE_IO;
  DWORD written = 0;
  gboolean ok = WriteFile (h, token, (DWORD) token_len, &written, NULL)
      && written == token_len && FlushFileBuffers (h);
  CloseHandle (h);
  if (!ok) {
    g_unlink (path);
    return WYCTL_TOKEN_FILE_IO;
  }
  return WYCTL_TOKEN_FILE_OK;
#else
  int fd = open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOCTTY,
      0600);
  if (fd < 0)
    return WYCTL_TOKEN_FILE_IO;
  gsize written = 0;
  while (written < token_len) {
    ssize_t n = write (fd, token + written, token_len - written);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close (fd);
      g_unlink (path);
      return WYCTL_TOKEN_FILE_IO;
    }
    written += (gsize) n;
  }
  if (fsync (fd) != 0 || close (fd) != 0) {
    g_unlink (path);
    return WYCTL_TOKEN_FILE_IO;
  }
  return WYCTL_TOKEN_FILE_OK;
#endif
}

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

/* Pure attribute-bit-mask classifier (Windows semantics). Compiled
 * on every platform so the Linux unit-test runner exercises the
 * Windows rejection rules with synthetic inputs. */
WyctlTokenFileStatus
wyctl_token_file_classify_windows_attrs (guint32 attrs)
{
  /* FILE_ATTRIBUTE_REPARSE_POINT — symlink, mountpoint, or any
   * other reparse target. We refuse the same way the POSIX path
   * refuses a terminal symlink. */
  if (attrs & 0x00000400u)
    return WYCTL_TOKEN_FILE_SYMLINK;
  /* FILE_ATTRIBUTE_READONLY missing — the issue requires at least
   * this much hardening on Windows. */
  if ((attrs & 0x00000001u) == 0)
    return WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY;
  return WYCTL_TOKEN_FILE_OK;
}

WyctlTokenFileStatus
wyctl_token_file_read (const gchar *path, gchar **out_token)
{
  if (out_token == NULL)
    return WYCTL_TOKEN_FILE_IO;
  *out_token = NULL;

  if (path == NULL || path[0] == '\0')
    return WYCTL_TOKEN_FILE_MISSING_PATH;

#ifdef G_OS_WIN32
  /* Convert the operator-supplied UTF-8 path to UTF-16 for the
   * Win32 wide-string API. */
  wchar_t *wpath = (wchar_t *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  if (wpath == NULL)
    return WYCTL_TOKEN_FILE_IO;

  DWORD attrs = GetFileAttributesW (wpath);
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    DWORD err = GetLastError ();
    g_free (wpath);
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
      return WYCTL_TOKEN_FILE_NOT_FOUND;
    return WYCTL_TOKEN_FILE_IO;
  }

  WyctlTokenFileStatus classify =
      wyctl_token_file_classify_windows_attrs ((guint32) attrs);
  if (classify != WYCTL_TOKEN_FILE_OK) {
    g_free (wpath);
    return classify;
  }

  HANDLE h = CreateFileW (wpath, GENERIC_READ, FILE_SHARE_READ, NULL,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  g_free (wpath);
  if (h == INVALID_HANDLE_VALUE)
    return WYCTL_TOKEN_FILE_IO;

  gsize cap = WYCTL_TOKEN_FILE_MAX_BYTES;
  gchar *buf = g_malloc (cap + 1);
  gsize got = 0;
  while (got < cap) {
    DWORD chunk = (DWORD) (cap - got);
    DWORD read_n = 0;
    if (!ReadFile (h, buf + got, chunk, &read_n, NULL)) {
      CloseHandle (h);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_IO;
    }
    if (read_n == 0)
      break;
    got += (gsize) read_n;
  }
  if (got >= cap) {
    gchar overflow = 0;
    DWORD probe = 0;
    if (ReadFile (h, &overflow, 1, &probe, NULL) && probe > 0) {
      CloseHandle (h);
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_TOO_LARGE;
    }
  }
  CloseHandle (h);
  buf[got] = '\0';

  if (got == 0) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_EMPTY;
  }
  if (memchr (buf, '\0', got) != NULL) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  }

  *out_token = buf;
  return WYCTL_TOKEN_FILE_OK;
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
      wyctl_token_file_free_sensitive (buf, cap + 1);
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
      wyctl_token_file_free_sensitive (buf, cap + 1);
      return WYCTL_TOKEN_FILE_TOO_LARGE;
    }
  }
  close (fd);
  buf[got] = '\0';

  if (got == 0) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_EMPTY;
  }

  /* Embedded NUL bytes never belong in a bearer token. Surfacing
   * INVALID_BYTES here keeps higher-level normalize logic from
   * mis-classifying the file. */
  if (memchr (buf, '\0', got) != NULL) {
    wyctl_token_file_free_sensitive (buf, cap + 1);
    return WYCTL_TOKEN_FILE_INVALID_BYTES;
  }

  *out_token = buf;
  return WYCTL_TOKEN_FILE_OK;
#endif
}
