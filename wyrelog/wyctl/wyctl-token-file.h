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
  WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN,
  WYCTL_TOKEN_FILE_ALREADY_EXISTS,
  WYCTL_TOKEN_FILE_UNSAFE_PARENT,
  WYCTL_TOKEN_FILE_PERMISSION_DENIED,
  /* A protected create or replace failed and its cleanup could not remove
   * the new, owner-only file (for a replace, its temporary file), which may
   * hold part or all of the token. */
  WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS,
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

/* Wipe and release bytes returned by wyctl_token_file_read. */
void wyctl_token_file_free_sensitive (gchar * value, gsize capacity);

/* Create a protected, no-replace bearer-token destination. */
/* Check the destination without following its final component. OK means it
 * was absent at the time of the check; the protected writer still enforces
 * no-replace when it creates the file. */
WyctlTokenFileStatus wyctl_token_file_check_available (const gchar * path);
WyctlTokenFileStatus wyctl_token_file_write_protected (const gchar * path,
    const gchar * token, gsize token_len);
WyctlTokenFileStatus wyctl_token_file_write_pair_protected (
  const gchar * refresh_path, const gchar * refresh_token,
  gsize refresh_token_len, const gchar * access_path,
  const gchar * access_token, gsize access_token_len,
  const gchar ** failed_path);

/* Replace a previously validated protected token file atomically. A
 * durability-uncertain result means the namespace replacement happened but
 * the parent-directory flush failed; callers must not replay a consumed
 * refresh token automatically.
 *
 * The new token is written to a temporary file beside path and renamed over
 * it. A failure after that temporary file is created removes it and reports
 * IO; when it cannot be removed, the result is INCOMPLETE_REMAINS and the
 * target keeps its old token. out_leftover may be NULL. Otherwise it is set
 * to NULL on entry and, only on INCOMPLETE_REMAINS, to a newly allocated
 * path of the temporary file, which the caller frees with g_free(). On
 * POSIX that is the temporary's name inside the symlink-resolved parent
 * directory; on Windows it is path, as the caller spelled it, followed by
 * ".tmp." and a random id. */
WyctlTokenFileStatus wyctl_token_file_replace_protected (const gchar * path,
    const gchar * token, gsize token_len, gchar ** out_leftover);
WyctlTokenFileStatus wyctl_token_file_remove_protected (const gchar * path);

typedef struct _WyctlTokenFileLock WyctlTokenFileLock;
WyctlTokenFileStatus wyctl_token_file_lock_refresh (const gchar * path,
    WyctlTokenFileLock ** out_lock);
void wyctl_token_file_unlock_refresh (WyctlTokenFileLock * lock);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (WyctlTokenFileLock,
    wyctl_token_file_unlock_refresh)

#if defined (WYL_ENABLE_FAULT_INJECTION) && !defined (G_OS_WIN32)
/* Test-only fault points on the POSIX paths of
 * wyctl_token_file_write_protected (#1546) and
 * wyctl_token_file_replace_protected (#1551), together the protected
 * writes. Compiled in only when the
 * enable_fault_injection build option is set; otherwise none of these
 * symbols exist and the writer makes the plain system calls.
 *
 * Each armed point fires once, on the next protected write that reaches
 * it, and then disarms itself; points armed together fire independently,
 * except at the cleanup unlink, where an armed CLEANUP_UNLINK fires and
 * leaves CLEANUP_ENOENT armed.
 * WRITE, FILE_SYNC, DIR_SYNC, CLEANUP_UNLINK and RENAME (replace only)
 * skip the real call and fail with EIO. FILE_CLOSE and DIR_CLOSE make the
 * real close, so no descriptor leaks, and then report EIO. CLEANUP_ENOENT
 * removes the new file's name first, so the real cleanup unlink fails with
 * a genuine ENOENT. DIR_SYNC covers two call sites, the success path and
 * the cleanup flush, and no single write reaches both; CLEANUP_UNLINK and
 * CLEANUP_ENOENT share one, in the cleanup every failed write, file sync,
 * file close or rename goes through. A fault point either makes a step
 * fail or, for CLEANUP_ENOENT, removes the new file as a concurrent process
 * could; it never bypasses a check. */
typedef enum
{
  WYCTL_TOKEN_FILE_FAULT_WRITE = 1u << 0,
  WYCTL_TOKEN_FILE_FAULT_FILE_SYNC = 1u << 1,
  WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE = 1u << 2,
  WYCTL_TOKEN_FILE_FAULT_DIR_SYNC = 1u << 3,
  WYCTL_TOKEN_FILE_FAULT_DIR_CLOSE = 1u << 4,
  WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK = 1u << 5,
  WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT = 1u << 6,
  WYCTL_TOKEN_FILE_FAULT_RENAME = 1u << 7,
} WyctlTokenFileFault;

/* Replace the armed set with mask; 0 disarms every point. Also resets the
 * cleanup-enoent counter below. */
void wyctl_token_file_arm_faults_once (guint mask);

/* The points armed and not yet reached. */
guint wyctl_token_file_armed_faults (void);

/* How many cleanup unlinks, since the last arm, ran with CLEANUP_ENOENT and
 * really failed with ENOENT. Lets a test tell the ENOENT branch from a
 * plain successful unlink. */
guint wyctl_token_file_fault_cleanup_enoent_seen (void);

/* Parse a comma-separated list of fault point names (write, file-sync,
 * file-close, dir-sync, dir-close, cleanup-unlink, cleanup-enoent, rename)
 * into a mask. Returns FALSE, leaving *out unchanged, for NULL, empty,
 * unknown or empty-element input. */
gboolean wyctl_token_file_parse_faults (const gchar * spec, guint * out);

/* Test only: the next count protected writes (creates and replaces) run
 * with every fault point suspended, so a fault can be aimed at a later
 * write, such as the pair writer's access file or the access-file replace
 * that follows a refresh-file replace. wyctl reaches it through the hidden
 * --fault-inject-token-file-skip=N flag. A later call replaces the count;
 * it does not add to it.
 *
 * The hook assumes a single thread: the armed set, the skip count and the
 * per-write suspension are process-wide, so concurrent protected writes
 * would race for the armed points. */
void wyctl_token_file_fault_skip_protected_writes (guint count);

typedef void (*WyctlTokenFileFaultHook) (gpointer user_data);

/* Test only: call hook (user_data) once, in the next replace that reaches
 * its target identity check -- after the temporary is written, flushed and
 * closed, and before the target is checked again and the temporary renamed
 * over it -- and then forget it. NULL clears it. It runs whatever the armed
 * set and the skip count are, and wyctl has no flag for it. It lets a test
 * change the target as a concurrent process could; it bypasses no check.
 * Single-thread, like the fault points. */
void wyctl_token_file_fault_set_identity_hook (WyctlTokenFileFaultHook hook,
    gpointer user_data);
#endif

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
