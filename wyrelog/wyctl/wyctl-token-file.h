/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#ifndef G_OS_WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

G_BEGIN_DECLS;

/* Maximum number of bytes wyctl will read from a bearer-token file
 * before rejecting. Tokens are typically tens to hundreds of bytes;
 * the cap exists so a misconfigured or hostile path cannot OOM the
 * process even if it survives every other check. */
#define WYCTL_TOKEN_FILE_MAX_BYTES (64u * 1024u)

/* Outcomes for wyctl_token_file_read. Each status maps to exactly
 * one stderr diagnostic returned by wyctl_token_file_status_message,
 * so operators can grep the runbook table to figure out the fix
 * without consulting source. */
typedef enum
{
  WYCTL_TOKEN_FILE_OK = 0,
  WYCTL_TOKEN_FILE_MISSING_PATH,
  WYCTL_TOKEN_FILE_NOT_FOUND,
  WYCTL_TOKEN_FILE_SYMLINK,
  WYCTL_TOKEN_FILE_NOT_REGULAR,
  WYCTL_TOKEN_FILE_OWNER_MISMATCH,
  WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD,
  WYCTL_TOKEN_FILE_IO,
  WYCTL_TOKEN_FILE_EMPTY,
  WYCTL_TOKEN_FILE_INVALID_BYTES,
  WYCTL_TOKEN_FILE_TOO_LARGE,
  WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY,
  WYCTL_TOKEN_FILE_WINDOWS_ACL_UNAVAILABLE,
} WyctlTokenFileStatus;

/* Open the token file safely and copy its bytes into *out_token.
 *
 * POSIX: open(path, O_NOFOLLOW | O_CLOEXEC | O_RDONLY | O_NOCTTY) so
 * a terminal symlink at path is refused; fstat() on the resulting
 * fd so the symlink/owner/mode check operates on the very inode the
 * read will consume (no TOCTOU window between stat and open).
 * Permissions stricter than 0600 are accepted (0400 is fine);
 * group/other permission bits are refused via the
 * (S_IRWXG | S_IRWXO) mask.
 *
 * Diagnostic invariants: no return path includes the token bytes in
 * an error message; only the path is logged. *out_token is NULL on
 * any non-OK status. On OK, *out_token is a newly-allocated
 * NUL-terminated buffer the caller frees with g_free(). */
WyctlTokenFileStatus wyctl_token_file_read (const gchar * path,
    gchar ** out_token);

#ifndef G_OS_WIN32
/* Pure-function classifier: given the result of fstat on an already-
 * opened fd and the invoking process's effective uid, decide whether
 * the regular-file / owner / mode invariants hold. Exists so tests
 * can exercise the owner-mismatch path without requiring root or
 * chown. Returns WYCTL_TOKEN_FILE_OK when every check passes. */
WyctlTokenFileStatus wyctl_token_file_classify_stat (const struct stat *st,
    uid_t euid);
#endif

/* Pure-function classifier for the Windows GetFileAttributesW result.
 * Operates on a plain guint32 bit mask so it can be exercised from
 * the Linux unit-test runner without linking any Win32 API: the
 * caller supplies synthetic attribute bits and the classifier
 * applies the read-only / reparse-point rules.
 *
 * The two attribute literals we care about are stable across every
 * supported Windows SDK:
 *   FILE_ATTRIBUTE_READONLY      = 0x00000001
 *   FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
 *
 * Returns WYCTL_TOKEN_FILE_SYMLINK if the reparse-point bit is set,
 * WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY if the read-only bit is
 * unset, and WYCTL_TOKEN_FILE_OK otherwise. */
WyctlTokenFileStatus wyctl_token_file_classify_windows_attrs (guint32 attrs);

/* Human-readable diagnostic string for a status code. The returned
 * string contains a single '%s' placeholder for the path (except
 * for WYCTL_TOKEN_FILE_MISSING_PATH whose message stands alone,
 * because the path is by definition empty or NULL). Returns NULL
 * for unknown statuses. */
const gchar *wyctl_token_file_status_message (WyctlTokenFileStatus status);

G_END_DECLS;
