/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 symlink/lstat/mkfifo/realpath under strict
 * c_std=c17. glibc declares realpath only with _XOPEN_SOURCE (or the
 * default feature set), not with _POSIX_C_SOURCE alone. Must precede every
 * system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include "test-exit-status.h"

#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef G_OS_WIN32
#include <poll.h>
#endif

#ifdef G_OS_WIN32
#include <windows.h>
#endif

#include "wyctl-token-file.h"

static gchar *
make_token_file_with_mode (const gchar *contents, mode_t mode)
{
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-token-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  if (contents != NULL && contents[0] != '\0') {
    gsize len = strlen (contents);
    gsize wrote = 0;
    while (wrote < len) {
      ssize_t n = write (fd, contents + wrote, len - wrote);
      g_assert_cmpint (n, >=, 0);
      wrote += (gsize) n;
    }
  }
  g_assert_true (g_close (fd, NULL));
  g_assert_cmpint (g_chmod (path, mode), ==, 0);
  return path;
}

static void
test_missing_path (void)
{
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (NULL, &token), ==,
      WYCTL_TOKEN_FILE_MISSING_PATH);
  g_assert_null (token);

  g_assert_cmpint (wyctl_token_file_read ("", &token), ==,
      WYCTL_TOKEN_FILE_MISSING_PATH);
  g_assert_null (token);
}

static void
test_not_found (void)
{
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read ("/nonexistent/path/wyctl-token-test",
      &token), ==, WYCTL_TOKEN_FILE_NOT_FOUND);
  g_assert_null (token);
}

static void
test_accepts_mode_0600 (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("token-1\n", 0600);
  g_autofree gchar *token = NULL;
  WyctlTokenFileStatus rc = wyctl_token_file_read (path, &token);
  g_assert_cmpint (rc, ==, WYCTL_TOKEN_FILE_OK);
  g_assert_nonnull (token);
  /* The helper does not trim whitespace — that's normalize's job. */
  g_assert_cmpstr (token, ==, "token-1\n");
  g_unlink (path);
}

static void
test_accepts_mode_0400 (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("token-1\n", 0400);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (token, ==, "token-1\n");
  g_unlink (path);
}

static void
test_rejects_mode_0640 (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("token-1", 0640);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD);
  g_assert_null (token);
  g_unlink (path);
}

static void
test_rejects_mode_0604 (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("token-1", 0604);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD);
  g_assert_null (token);
  g_unlink (path);
}

static void
test_rejects_mode_0660 (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("token-1", 0660);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_PERMISSIONS_TOO_BROAD);
  g_assert_null (token);
  g_unlink (path);
}

static void
test_rejects_terminal_symlink (void)
{
  g_autofree gchar *real = make_token_file_with_mode ("token-1", 0600);

  g_autoptr (GError) error = NULL;
  gchar *link_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-link-XXXXXX", &link_path, &error);
  g_assert_no_error (error);
  g_assert_true (g_close (fd, NULL));
  /* The tmpfile is a placeholder; replace with a symlink to the
   * real file so the helper's O_NOFOLLOW rejection fires. */
  g_unlink (link_path);
  g_assert_cmpint (symlink (real, link_path), ==, 0);

  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (link_path, &token), ==,
      WYCTL_TOKEN_FILE_SYMLINK);
  g_assert_null (token);

  g_unlink (link_path);
  g_free (link_path);
  g_unlink (real);
}

static void
test_rejects_non_regular_via_classifier (void)
{
  /* mkfifo + open(O_NOFOLLOW|O_RDONLY) blocks waiting for a writer,
   * so use the pure classifier helper to assert the non-regular
   * rejection path. */
  g_autoptr (GError) error = NULL;
  gchar *fifo_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-fifo-XXXXXX", &fifo_path, &error);
  g_assert_no_error (error);
  g_assert_true (g_close (fd, NULL));
  g_unlink (fifo_path);
  g_assert_cmpint (mkfifo (fifo_path, 0600), ==, 0);

  struct stat st;
  g_assert_cmpint (lstat (fifo_path, &st), ==, 0);
  g_assert_cmpint (wyctl_token_file_classify_stat (&st, geteuid ()), ==,
      WYCTL_TOKEN_FILE_NOT_REGULAR);

  g_unlink (fifo_path);
  g_free (fifo_path);
}

static void
test_rejects_empty_file (void)
{
  g_autofree gchar *path = make_token_file_with_mode ("", 0600);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_EMPTY);
  g_assert_null (token);
  g_unlink (path);
}

static void
test_rejects_too_large (void)
{
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-large-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);

  gsize n = WYCTL_TOKEN_FILE_MAX_BYTES + 16;
  g_autofree gchar *blob = g_malloc (n);
  memset (blob, 'a', n);
  gsize wrote = 0;
  while (wrote < n) {
    ssize_t w = write (fd, blob + wrote, n - wrote);
    g_assert_cmpint (w, >=, 0);
    wrote += (gsize) w;
  }
  g_assert_true (g_close (fd, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);

  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_TOO_LARGE);
  g_assert_null (token);
  g_unlink (path);
  g_free (path);
}

static void
test_rejects_embedded_nul (void)
{
  /* Create a file with an embedded NUL byte directly via write(2)
   * since g_file_set_contents treats the buffer as a C string. */
  g_autoptr (GError) error = NULL;
  gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-nul-XXXXXX", &path, &error);
  g_assert_no_error (error);
  static const char bytes[] = { 'a', 'b', '\0', 'c', '\n' };
  ssize_t w = write (fd, bytes, sizeof (bytes));
  g_assert_cmpint (w, ==, (ssize_t) sizeof (bytes));
  g_assert_true (g_close (fd, NULL));
  g_assert_cmpint (g_chmod (path, 0600), ==, 0);

  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_INVALID_BYTES);
  g_assert_null (token);
  g_unlink (path);
  g_free (path);
}

static void
test_owner_mismatch_via_classifier (void)
{
  /* Stat a real regular file so we have a struct stat with valid
   * S_IFREG and 0600 bits, then drive the classifier with an euid
   * deliberately different from the real owner — no root or chown
   * required. */
  g_autofree gchar *path = make_token_file_with_mode ("token-1", 0600);
  struct stat st;
  g_assert_cmpint (lstat (path, &st), ==, 0);
  uid_t fake_euid = st.st_uid + 1;
  g_assert_cmpint (wyctl_token_file_classify_stat (&st, fake_euid), ==,
      WYCTL_TOKEN_FILE_OWNER_MISMATCH);
  /* And: matching euid is OK. */
  g_assert_cmpint (wyctl_token_file_classify_stat (&st, st.st_uid), ==,
      WYCTL_TOKEN_FILE_OK);
  g_unlink (path);
}

/* Windows-attribute classifier tests. These run on every platform
 * because the classifier is pure bit math — no Win32 API is needed.
 * They lock the rejection rules so a future Windows-side regression
 * (e.g. failing to refuse a reparse point) is visible on the Linux
 * CI before any Windows tester sees it. */
#define WYCTL_WIN_ATTR_READONLY 0x00000001u
#define WYCTL_WIN_ATTR_NORMAL 0x00000080u
#define WYCTL_WIN_ATTR_REPARSE_POINT 0x00000400u

static void
test_windows_attrs_accept_readonly (void)
{
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs
        (WYCTL_WIN_ATTR_READONLY), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs
        (WYCTL_WIN_ATTR_READONLY | WYCTL_WIN_ATTR_NORMAL), ==,
      WYCTL_TOKEN_FILE_OK);
}

static void
test_windows_attrs_reject_not_readonly (void)
{
  /* Plain file with no read-only bit. */
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs
        (WYCTL_WIN_ATTR_NORMAL), ==, WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY);
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs (0), ==,
      WYCTL_TOKEN_FILE_WINDOWS_NOT_READONLY);
}

static void
test_windows_attrs_reject_reparse_point (void)
{
  /* Reparse-point set even if read-only is also set: refuse. */
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs
        (WYCTL_WIN_ATTR_REPARSE_POINT | WYCTL_WIN_ATTR_READONLY), ==,
      WYCTL_TOKEN_FILE_SYMLINK);
  g_assert_cmpint (wyctl_token_file_classify_windows_attrs
        (WYCTL_WIN_ATTR_REPARSE_POINT), ==, WYCTL_TOKEN_FILE_SYMLINK);
}

static void
test_status_message_table_has_no_token_placeholder (void)
{
  /* Each status format string must either stand alone (for
   * MISSING_PATH) or contain exactly one %s — for the path. No
   * placeholder may exist for the token bytes themselves; that
   * would risk leaking credentials into stderr. */
  for (int s = WYCTL_TOKEN_FILE_OK;
      s <= WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS; s++) {
    const gchar *msg = wyctl_token_file_status_message (
      (WyctlTokenFileStatus) s);
    if (s == WYCTL_TOKEN_FILE_OK)
      continue;
    g_assert_nonnull (msg);
    int placeholders = 0;
    for (const gchar * p = msg; *p != '\0'; p++) {
      if (p[0] == '%' && p[1] == 's')
        placeholders++;
    }
    g_assert_cmpint (placeholders, <=, 1);
    /* No test-token-like string is baked into the table. */
    g_assert_null (strstr (msg, "token-1"));
  }
}

static void
test_output_preflight (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-output-preflight-XXXXXX",
          NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "token", NULL);
  g_autofree gchar *missing_parent = g_build_filename (dir, "missing",
          "token", NULL);
  g_assert_cmpint (wyctl_token_file_check_available (path), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpint (wyctl_token_file_check_available (missing_parent), ==,
      WYCTL_TOKEN_FILE_IO);
  g_assert_true (g_file_set_contents (path, "old", -1, NULL));
  g_assert_cmpint (wyctl_token_file_check_available (path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_unlink (path);
  g_assert_cmpint (g_mkdir (path, 0700), ==, 0);
  g_assert_cmpint (wyctl_token_file_check_available (path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_rmdir (path);
#ifndef G_OS_WIN32
  g_assert_cmpint (symlink ("missing-target", path), ==, 0);
  g_assert_cmpint (wyctl_token_file_check_available (path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_unlink (path);
#endif
  g_rmdir (dir);
}

static void
test_protected_writer_is_no_replace (void)
{
  g_autofree gchar *path = NULL;
  gint fd = g_file_open_tmp ("wyctl-output-XXXXXX", &path, NULL);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_unlink (path);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "access-1", 8),
      ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "access-2", 8),
      ==, WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (token, ==, "access-1");
  g_unlink (path);
}

/* A successful replace clears *out_leftover and leaves no temporary file
 * beside the target. */
static void
test_protected_replace_and_remove (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-replace-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *path = g_build_filename (dir, "token", NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "old-token", 9),
      ==, WYCTL_TOKEN_FILE_OK);
  gchar *leftover = (gchar *) "not cleared";
  g_assert_cmpint (wyctl_token_file_replace_protected (path, "new-token", 9,
      &leftover), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_null (leftover);
  GDir *entries = g_dir_open (dir, 0, NULL);
  g_assert_nonnull (entries);
  g_assert_cmpstr (g_dir_read_name (entries), ==, "token");
  g_assert_null (g_dir_read_name (entries));
  g_dir_close (entries);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (token, ==, "new-token");
  g_assert_cmpint (wyctl_token_file_remove_protected (path), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_false (g_file_test (path, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_protected_pair_rolls_back_only_its_refresh_file (void)
{
  g_autofree gchar *directory = g_dir_make_tmp ("wyctl-pair-XXXXXX", NULL);
  g_assert_nonnull (directory);
  g_autofree gchar *refresh_path = g_build_filename (directory, "refresh",
          NULL);
  g_autofree gchar *access_path = g_build_filename (directory, "access", NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (access_path,
      "preexisting", 11), ==, WYCTL_TOKEN_FILE_OK);
  const gchar *failed_path = NULL;
  g_assert_cmpint (wyctl_token_file_write_pair_protected (refresh_path,
      "refresh-new", 11, access_path, "access-new", 10, &failed_path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpstr (failed_path, ==, access_path);
  g_assert_false (g_file_test (refresh_path, G_FILE_TEST_EXISTS));
  g_autofree gchar *access = NULL;
  g_assert_cmpint (wyctl_token_file_read (access_path, &access), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (access, ==, "preexisting");
  g_assert_cmpint (wyctl_token_file_write_pair_protected (refresh_path,
      "refresh-new", 11, access_path, "access-new", 10, &failed_path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpstr (failed_path, ==, access_path);
  g_assert_cmpstr (access, ==, "preexisting");
  g_unlink (access_path);
  g_rmdir (directory);
}

static void
test_protected_pair_identifies_refresh_collision (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-pair-refresh-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *refresh_path = g_build_filename (dir, "refresh", NULL);
  g_autofree gchar *access_path = g_build_filename (dir, "access", NULL);
  g_assert_true (g_file_set_contents (refresh_path, "old", -1, NULL));
  const gchar *failed_path = NULL;
  g_assert_cmpint (wyctl_token_file_write_pair_protected (refresh_path,
      "new-refresh", 11, access_path, "new-access", 10, &failed_path), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpstr (failed_path, ==, refresh_path);
  g_assert_false (g_file_test (access_path, G_FILE_TEST_EXISTS));
  g_unlink (refresh_path);
  g_rmdir (dir);
}

#ifndef G_OS_WIN32
static void
test_refresh_lock_serializes_processes (void)
{
  g_autofree gchar *root = g_dir_make_tmp ("wyctl-lock-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_autofree gchar *parent = g_build_filename (root, "real", NULL);
  g_autofree gchar *alias = g_build_filename (root, "alias", NULL);
  g_assert_cmpint (g_mkdir (parent, 0700), ==, 0);
  g_assert_cmpint (symlink ("real", alias), ==, 0);
  g_autofree gchar *path = g_build_filename (parent, "token", NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "token", 5), ==,
      WYCTL_TOKEN_FILE_OK);
  g_autofree gchar *path_alias = g_strdup_printf ("%s/./token", alias);
  WyctlTokenFileLock *parent_lock = NULL;
  g_assert_cmpint (wyctl_token_file_lock_refresh (path, &parent_lock), ==,
      WYCTL_TOKEN_FILE_OK);
  gint pipe_fds[2];
  g_assert_cmpint (pipe (pipe_fds), ==, 0);
  pid_t child = fork ();
  g_assert_cmpint (child, >=, 0);
  if (child == 0) {
    close (pipe_fds[0]);
    (void) write (pipe_fds[1], "r", 1);
    WyctlTokenFileLock *child_lock = NULL;
    if (wyctl_token_file_lock_refresh (path_alias, &child_lock)
        != WYCTL_TOKEN_FILE_OK)
      WYL_TEST_EXIT (2);
    (void) write (pipe_fds[1], "x", 1);
    wyctl_token_file_unlock_refresh (child_lock);
    WYL_TEST_EXIT (0);
  }
  close (pipe_fds[1]);
  struct pollfd probe = { .fd = pipe_fds[0], .events = POLLIN };
  g_assert_cmpint (poll (&probe, 1, 2000), ==, 1);
  gchar ready = 0;
  g_assert_cmpint (read (pipe_fds[0], &ready, 1), ==, 1);
  g_assert_cmpint (ready, ==, 'r');
  g_assert_cmpint (poll (&probe, 1, 100), ==, 0);
  wyctl_token_file_unlock_refresh (parent_lock);
  g_assert_cmpint (poll (&probe, 1, 2000), ==, 1);
  gchar byte = 0;
  g_assert_cmpint (read (pipe_fds[0], &byte, 1), ==, 1);
  g_assert_cmpint (byte, ==, 'x');
  gint child_status = 0;
  g_assert_cmpint (waitpid (child, &child_status, 0), ==, child);
  g_assert_true (WIFEXITED (child_status));
  g_assert_cmpint (WEXITSTATUS (child_status), ==, 0);
  close (pipe_fds[0]);
  g_autofree gchar *lock_path = g_strconcat (path, ".lock", NULL);
  g_assert_cmpint (g_unlink (lock_path), ==, 0);
  g_assert_cmpint (g_unlink (path), ==, 0);
  g_assert_cmpint (g_unlink (alias), ==, 0);
  g_assert_cmpint (g_rmdir (parent), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}
#endif

#ifndef G_OS_WIN32
static void
assert_parent_alias_token (const gchar *path, const gchar *expected)
{
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (token, ==, expected);
  struct stat st;
  g_assert_cmpint (g_lstat (path, &st), ==, 0);
  g_assert_true (S_ISREG (st.st_mode));
  g_assert_cmpuint (st.st_uid, ==, geteuid ());
  g_assert_cmpuint (st.st_mode & 0777, ==, 0600);
}

/* #1557: preflight, create, replace and remove agree on direct and earlier
 * parent aliases; terminal links retain their existing refusal contracts. */
static void
test_protected_parent_symlink (gconstpointer data)
{
  gboolean ancestor = GPOINTER_TO_INT (data) != 0;
  g_autofree gchar *root = g_dir_make_tmp ("wyctl-parent-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_autofree gchar *real = g_build_filename (root, "real", NULL);
  g_autofree gchar *alias = g_build_filename (root, "alias", NULL);
  g_assert_cmpint (g_mkdir (real, 0700), ==, 0);
  g_assert_cmpint (symlink ("real", alias), ==, 0);
  g_autofree gchar *parent = ancestor ? g_build_filename (real, "inner", NULL)
      : g_strdup (real);
  if (ancestor)
    g_assert_cmpint (g_mkdir (parent, 0700), ==, 0);
  g_autofree gchar *alias_parent = ancestor ? g_build_filename (alias, "inner", NULL)
      : g_strdup (alias);
  g_autofree gchar *path = g_build_filename (alias_parent, "token", NULL);
  g_autofree gchar *target = g_build_filename (parent, "token", NULL);
  g_assert_cmpint (wyctl_token_file_check_available (path), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "old-token", 9), ==,
      WYCTL_TOKEN_FILE_OK);
  assert_parent_alias_token (target, "old-token");
  g_assert_cmpint (wyctl_token_file_check_available (path), ==, WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "collision", 9), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  assert_parent_alias_token (target, "old-token");
  gchar *leftover = (gchar *) "not cleared";
  g_assert_cmpint (wyctl_token_file_replace_protected (path, "new-token", 9,
      &leftover), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_null (leftover);
  assert_parent_alias_token (target, "new-token");

  g_autofree gchar *terminal = g_build_filename (alias_parent, "terminal", NULL);
  g_assert_cmpint (symlink ("token", terminal), ==, 0);
  g_assert_cmpint (wyctl_token_file_check_available (terminal), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpint (wyctl_token_file_write_protected (terminal, "collision", 9), ==,
      WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpint (wyctl_token_file_replace_protected (terminal, "collision", 9,
      &leftover), ==, WYCTL_TOKEN_FILE_SYMLINK);
  g_assert_null (leftover);
  g_assert_cmpint (wyctl_token_file_remove_protected (terminal), ==, WYCTL_TOKEN_FILE_IO);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (terminal, &token), ==, WYCTL_TOKEN_FILE_SYMLINK);
  g_assert_null (token);
  assert_parent_alias_token (target, "new-token");
  g_assert_cmpint (g_unlink (terminal), ==, 0);
  g_assert_cmpint (wyctl_token_file_remove_protected (path), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_false (g_file_test (target, G_FILE_TEST_EXISTS));
  if (ancestor)
    g_assert_cmpint (g_rmdir (parent), ==, 0);
  g_assert_cmpint (g_unlink (alias), ==, 0);
  g_assert_cmpint (g_rmdir (real), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static void
test_protected_pair_parent_symlink (void)
{
  g_autofree gchar *root = g_dir_make_tmp ("wyctl-pair-alias-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_autofree gchar *real = g_build_filename (root, "real", NULL);
  g_autofree gchar *alias = g_build_filename (root, "alias", NULL);
  g_assert_cmpint (g_mkdir (real, 0700), ==, 0);
  g_assert_cmpint (symlink ("real", alias), ==, 0);
  g_autofree gchar *refresh = g_build_filename (alias, "refresh", NULL);
  g_autofree gchar *access = g_build_filename (alias, "access", NULL);
  g_autofree gchar *real_refresh = g_build_filename (real, "refresh", NULL);
  g_autofree gchar *real_access = g_build_filename (real, "access", NULL);
  const gchar *failed = (const gchar *) "not cleared";
  g_assert_cmpint (wyctl_token_file_write_pair_protected (refresh, "refresh-new", 11,
      access, "access-new", 10, &failed), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_null (failed);
  assert_parent_alias_token (real_refresh, "refresh-new");
  assert_parent_alias_token (real_access, "access-new");
  g_assert_cmpint (wyctl_token_file_remove_protected (refresh), ==, WYCTL_TOKEN_FILE_OK);
  /* The access collision rolls back only the newly created refresh file. */
  g_assert_cmpint (wyctl_token_file_write_pair_protected (refresh, "refresh-new", 11,
      access, "collision", 9, &failed), ==, WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpstr (failed, ==, access);
  g_assert_false (g_file_test (real_refresh, G_FILE_TEST_EXISTS));
  assert_parent_alias_token (real_access, "access-new");
  g_assert_cmpint (wyctl_token_file_remove_protected (access), ==, WYCTL_TOKEN_FILE_OK);
  /* Two spellings of one destination cannot publish a pair or leave its first file. */
  g_assert_cmpint (wyctl_token_file_write_pair_protected (real_refresh, "refresh-new", 11,
      refresh, "access-new", 10, &failed), ==, WYCTL_TOKEN_FILE_ALREADY_EXISTS);
  g_assert_cmpstr (failed, ==, refresh);
  g_assert_false (g_file_test (real_refresh, G_FILE_TEST_EXISTS));
  g_assert_cmpint (g_unlink (alias), ==, 0);
  g_assert_cmpint (g_rmdir (real), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static void
test_parent_resolution_failures (void)
{
  g_autofree gchar *root = g_dir_make_tmp ("wyctl-parent-errors-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_autofree gchar *loop = g_build_filename (root, "loop", NULL);
  g_autofree gchar *dangling = g_build_filename (root, "dangling", NULL);
  g_autofree gchar *file = g_build_filename (root, "file", NULL);
  g_assert_cmpint (symlink ("loop", loop), ==, 0);
  g_assert_cmpint (symlink ("absent", dangling), ==, 0);
  g_assert_true (g_file_set_contents (file, "parent", -1, NULL));
  const gchar *parents[] = { loop, dangling, file };
  const WyctlTokenFileStatus expected[] = { WYCTL_TOKEN_FILE_UNSAFE_PARENT,
                                            WYCTL_TOKEN_FILE_IO, WYCTL_TOKEN_FILE_UNSAFE_PARENT };
  for (gsize i = 0; i < G_N_ELEMENTS (parents); i++) {
    g_autofree gchar *path = g_build_filename (parents[i], "token", NULL);
    g_assert_cmpint (wyctl_token_file_check_available (path), ==, expected[i]);
    g_assert_cmpint (wyctl_token_file_write_protected (path, "token", 5), ==, expected[i]);
  }
  g_assert_cmpint (g_unlink (loop), ==, 0);
  g_assert_cmpint (g_unlink (dangling), ==, 0);
  g_assert_cmpint (g_unlink (file), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static void
test_parent_resolution_permission_denied (void)
{
  if (geteuid () == 0) {
    g_test_skip ("root bypasses directory permissions");
    return;
  }
  g_autofree gchar *root = g_dir_make_tmp ("wyctl-parent-mode-XXXXXX", NULL);
  g_assert_nonnull (root);
  g_autofree gchar *path = g_build_filename (root, "token", NULL);
  g_assert_cmpint (g_chmod (root, 0000), ==, 0);
  WyctlTokenFileStatus check = wyctl_token_file_check_available (path);
  WyctlTokenFileStatus write = wyctl_token_file_write_protected (path, "token", 5);
  g_assert_cmpint (g_chmod (root, 0700), ==, 0);
  g_assert_cmpint (check, ==, WYCTL_TOKEN_FILE_PERMISSION_DENIED);
  g_assert_cmpint (write, ==, WYCTL_TOKEN_FILE_PERMISSION_DENIED);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

#else
static gboolean
create_windows_directory_symlink (const gchar *target, const gchar *link)
{
  g_autofree wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *wlink = (wchar_t *) g_utf8_to_utf16 (link, -1,
          NULL, NULL, NULL);
  return wtarget != NULL && wlink != NULL
         && CreateSymbolicLinkW (wlink, wtarget, SYMBOLIC_LINK_FLAG_DIRECTORY);
}

static gboolean
create_windows_file_symlink (const gchar *target, const gchar *link)
{
  g_autofree wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1,
          NULL, NULL, NULL);
  g_autofree wchar_t *wlink = (wchar_t *) g_utf8_to_utf16 (link, -1,
          NULL, NULL, NULL);
  return wtarget != NULL && wlink != NULL
         && CreateSymbolicLinkW (wlink, wtarget, 0);
}

static void
test_windows_parent_reparse_is_rejected (void)
{
  g_autofree gchar *real_dir = g_dir_make_tmp ("wyctl-parent-XXXXXX", NULL);
  g_assert_nonnull (real_dir);
  g_autofree gchar *link_dir = g_strdup_printf ("%s-link", real_dir);
  if (!create_windows_directory_symlink (real_dir, link_dir)) {
    g_rmdir (real_dir);
    g_test_skip ("creating Windows directory symlinks requires a privilege");
    return;
  }
  g_autofree gchar *path = g_build_filename (link_dir, "token", NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "access-1", 8),
      !=, WYCTL_TOKEN_FILE_OK);
  g_assert_false (g_file_test (g_build_filename (real_dir, "token", NULL),
      G_FILE_TEST_EXISTS));
  g_remove (link_dir);
  g_rmdir (real_dir);
}

static void
test_windows_ancestor_reparse_is_rejected (void)
{
  g_autofree gchar *real_root = g_dir_make_tmp ("wyctl-ancestor-XXXXXX",
          NULL);
  g_assert_nonnull (real_root);
  g_autofree gchar *real_parent = g_build_filename (real_root, "inner", NULL);
  g_assert_cmpint (g_mkdir (real_parent, 0700), ==, 0);
  g_autofree gchar *alias_root = g_strdup_printf ("%s-alias", real_root);
  if (!create_windows_directory_symlink (real_root, alias_root)) {
    g_rmdir (real_parent);
    g_rmdir (real_root);
    g_test_skip ("creating Windows directory symlinks requires a privilege");
    return;
  }
  g_autofree gchar *path = g_build_filename (alias_root, "inner", "token",
          NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "access-1", 8),
      !=, WYCTL_TOKEN_FILE_OK);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), !=,
      WYCTL_TOKEN_FILE_OK);
  g_assert_null (token);
  g_assert_false (g_file_test (g_build_filename (real_parent, "token", NULL),
      G_FILE_TEST_EXISTS));
  g_remove (alias_root);
  g_rmdir (real_parent);
  g_rmdir (real_root);
}

static void
test_windows_final_reparse_is_rejected (void)
{
  g_autofree gchar *dir = g_dir_make_tmp ("wyctl-final-XXXXXX", NULL);
  g_assert_nonnull (dir);
  g_autofree gchar *real = g_build_filename (dir, "real-token", NULL);
  g_autofree gchar *link = g_build_filename (dir, "token", NULL);
  g_assert_true (g_file_set_contents (real, "access-1", -1, NULL));
  g_autofree wchar_t *wreal = (wchar_t *) g_utf8_to_utf16 (real, -1,
          NULL, NULL, NULL);
  g_assert_nonnull (wreal);
  SetFileAttributesW (wreal, FILE_ATTRIBUTE_READONLY);
  if (!create_windows_file_symlink (real, link)) {
    g_remove (real);
    g_rmdir (dir);
    g_test_skip ("creating Windows file symlinks requires a privilege");
    return;
  }
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (link, &token), ==,
      WYCTL_TOKEN_FILE_SYMLINK);
  g_assert_null (token);
  g_remove (link);
  g_remove (real);
  g_rmdir (dir);
}
#endif

#if defined (WYL_ENABLE_FAULT_INJECTION) && !defined (G_OS_WIN32)
typedef struct
{
  gchar *dir;
  gchar *path;
  gchar *second_path;
} FaultFixture;

static void
fault_fixture_init (FaultFixture *fixture)
{
  wyctl_token_file_arm_faults_once (0);
  wyctl_token_file_fault_skip_protected_writes (0);
  fixture->dir = g_dir_make_tmp ("wyctl-fault-XXXXXX", NULL);
  g_assert_nonnull (fixture->dir);
  fixture->path = g_build_filename (fixture->dir, "token", NULL);
  fixture->second_path = g_build_filename (fixture->dir, "second", NULL);
}

/* Number of replace temporaries (.wyctl-token-*) in DIR; the first one's
 * name is stored in *first when FIRST is non-NULL. */
static guint
count_replace_temporaries (const gchar *dir, gchar **first)
{
  GDir *entries = g_dir_open (dir, 0, NULL);
  g_assert_nonnull (entries);
  guint count = 0;
  const gchar *name;
  while ((name = g_dir_read_name (entries)) != NULL) {
    if (!g_str_has_prefix (name, ".wyctl-token-"))
      continue;
    if (count == 0 && first != NULL)
      *first = g_strdup (name);
    count++;
  }
  g_dir_close (entries);
  return count;
}

static void
fault_fixture_clear (FaultFixture *fixture)
{
  wyctl_token_file_arm_faults_once (0);
  wyctl_token_file_fault_skip_protected_writes (0);
  gchar *temporary = NULL;
  while (count_replace_temporaries (fixture->dir, &temporary) > 0) {
    g_autofree gchar *temporary_path = g_build_filename (fixture->dir,
            temporary, NULL);
    g_assert_cmpint (g_unlink (temporary_path), ==, 0);
    g_clear_pointer (&temporary, g_free);
  }
  g_unlink (fixture->path);
  g_unlink (fixture->second_path);
  g_rmdir (fixture->dir);
  g_free (fixture->path);
  g_free (fixture->second_path);
  g_free (fixture->dir);
}

static void
assert_protected_file (const gchar *path, const gchar *expected)
{
  struct stat st;
  g_assert_cmpint (lstat (path, &st), ==, 0);
  g_assert_true (S_ISREG (st.st_mode));
  g_assert_cmpint (st.st_mode & 0777, ==, 0600);
  g_autofree gchar *contents = NULL;
  gsize length = 0;
  g_assert_true (g_file_get_contents (path, &contents, &length, NULL));
  g_assert_cmpmem (contents, length, expected, strlen (expected));
}

/* Number of open descriptors, or -1 where /proc/self/fd is unavailable. The
 * directory handle used to count is open during both counts, so it cancels
 * out of a before/after comparison. */
static gint
count_open_fds (void)
{
#ifdef __linux__
  GDir *dir = g_dir_open ("/proc/self/fd", 0, NULL);
  g_assert_nonnull (dir);
  gint count = 0;
  while (g_dir_read_name (dir) != NULL)
    count++;
  g_dir_close (dir);
  return count;
#else
  return -1;
#endif
}

static void
test_fault_spec_parse (void)
{
  static const struct
  {
    const gchar *name;
    guint bit;
  } names[] = {
    { "write", WYCTL_TOKEN_FILE_FAULT_WRITE },
    { "file-sync", WYCTL_TOKEN_FILE_FAULT_FILE_SYNC },
    { "file-close", WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE },
    { "dir-sync", WYCTL_TOKEN_FILE_FAULT_DIR_SYNC },
    { "dir-close", WYCTL_TOKEN_FILE_FAULT_DIR_CLOSE },
    { "cleanup-unlink", WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK },
    { "cleanup-enoent", WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT },
    { "rename", WYCTL_TOKEN_FILE_FAULT_RENAME },
  };
  guint all = 0;
  for (gsize i = 0; i < G_N_ELEMENTS (names); i++) {
    guint mask = 0;
    g_assert_true (wyctl_token_file_parse_faults (names[i].name, &mask));
    g_assert_cmpuint (mask, ==, names[i].bit);
    g_assert_cmpuint (all & names[i].bit, ==, 0);
    all |= names[i].bit;
  }
  guint mask = 0;
  g_assert_true (wyctl_token_file_parse_faults
        ("write,file-sync,file-close,dir-sync,dir-close,cleanup-unlink,"
      "cleanup-enoent,rename", &mask));
  g_assert_cmpuint (mask, ==, all);
  g_assert_true (wyctl_token_file_parse_faults ("file-sync,cleanup-unlink",
      &mask));
  g_assert_cmpuint (mask, ==, WYCTL_TOKEN_FILE_FAULT_FILE_SYNC
      | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);

  static const gchar *const rejected[] = {
    "", ",", "write,", ",write", "write,,dir-sync", "bogus", "write,bogus",
    "Write", " write", "write ",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (rejected); i++)
    g_assert_false (wyctl_token_file_parse_faults (rejected[i], &mask));
  g_assert_false (wyctl_token_file_parse_faults (NULL, &mask));
}

static void
test_write_fault_is_io (void)
{
  static const guint faults[] = {
    WYCTL_TOKEN_FILE_FAULT_WRITE,
    WYCTL_TOKEN_FILE_FAULT_FILE_SYNC,
    WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (faults[i]);
    gint fds_before = count_open_fds ();
    g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
        "secret-1", 8), ==, WYCTL_TOKEN_FILE_IO);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    fault_fixture_clear (&fixture);
  }

  /* A failed write's cleanup flushes the directory, as the sync and close
   * failure paths do; a fault there is ignored, so the status stays IO. */
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_WRITE
      | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_IO);
  g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  fault_fixture_clear (&fixture);
}

static void
test_dir_sync_fault_is_durability_uncertain (void)
{
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  assert_protected_file (fixture.path, "secret-1");
  fault_fixture_clear (&fixture);
}

static void
test_cleanup_flush_fault_stays_io (void)
{
  static const guint faults[] = {
    WYCTL_TOKEN_FILE_FAULT_FILE_SYNC,
    WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (faults[i]
        | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
    gint fds_before = count_open_fds ();
    g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
        "secret-1", 8), ==, WYCTL_TOKEN_FILE_IO);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    fault_fixture_clear (&fixture);
  }
}

static void
test_cleanup_unlink_not_reached_on_success (void)
{
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==,
      WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
  assert_protected_file (fixture.path, "secret-1");
  fault_fixture_clear (&fixture);
}

/* A failed write, file sync or file close whose cleanup cannot remove the
 * new file reports INCOMPLETE_REMAINS and leaves that file behind: empty
 * after a failed write, complete after a failed sync or close. */
static void
test_cleanup_unlink_fault_fires_independently (void)
{
  static const struct
  {
    guint fault;
    const gchar *left;
  } faults[] = {
    { WYCTL_TOKEN_FILE_FAULT_WRITE, "" },
    { WYCTL_TOKEN_FILE_FAULT_FILE_SYNC, "secret-1" },
    { WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE, "secret-1" },
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (faults[i].fault
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
    gint fds_before = count_open_fds ();
    g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
        "secret-1", 8), ==, WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    assert_protected_file (fixture.path, faults[i].left);
    fault_fixture_clear (&fixture);
  }
}

/* A cleanup unlink that finds the name already gone (ENOENT) has nothing left
 * to remove, so the failed write stays IO and the cleanup flush still runs:
 * the armed DIR_SYNC is consumed there. The seen counter proves the real
 * cleanup unlink met ENOENT, not a plain success. */
static void
test_cleanup_enoent_is_io (void)
{
  static const guint faults[] = {
    WYCTL_TOKEN_FILE_FAULT_WRITE,
    WYCTL_TOKEN_FILE_FAULT_FILE_SYNC,
    WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE,
  };
  for (gsize i = 0; i < G_N_ELEMENTS (faults); i++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (faults[i]
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT
        | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
    gint fds_before = count_open_fds ();
    WyctlTokenFileStatus status =
        wyctl_token_file_write_protected (fixture.path, "secret-1", 8);
    g_assert_cmpint (status, ==, WYCTL_TOKEN_FILE_IO);
    g_assert_cmpuint (wyctl_token_file_fault_cleanup_enoent_seen (), ==, 1);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
    fault_fixture_clear (&fixture);
  }
}

/* With both cleanup faults armed, CLEANUP_UNLINK fires and CLEANUP_ENOENT is
 * not consumed: it stays armed for a later cleanup. A cleanup that leaves the
 * file is not flushed, so DIR_SYNC stays armed too. */
static void
test_cleanup_unlink_wins_over_enoent (void)
{
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_FILE_SYNC
      | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK
      | WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT
      | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==,
      WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT
      | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
  g_assert_cmpuint (wyctl_token_file_fault_cleanup_enoent_seen (), ==, 0);
  assert_protected_file (fixture.path, "secret-1");
  fault_fixture_clear (&fixture);
}

/* The faults a replace reaches: writing, flushing and closing its temporary
 * file, and renaming it over the target. */
static const guint replace_faults[] = {
  WYCTL_TOKEN_FILE_FAULT_WRITE,
  WYCTL_TOKEN_FILE_FAULT_FILE_SYNC,
  WYCTL_TOKEN_FILE_FAULT_FILE_CLOSE,
  WYCTL_TOKEN_FILE_FAULT_RENAME,
};

static void
replace_fixture_init (FaultFixture *fixture)
{
  fault_fixture_init (fixture);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture->path,
      "old-token", 9), ==, WYCTL_TOKEN_FILE_OK);
}

/* A failed replace removes its temporary file: IO, no leftover, and the
 * target keeps the old token. */
static void
test_replace_fault_is_io (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (replace_faults); i++) {
    FaultFixture fixture;
    replace_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (replace_faults[i]);
    gint fds_before = count_open_fds ();
    gchar *leftover = NULL;
    WyctlTokenFileStatus status = wyctl_token_file_replace_protected
          (fixture.path, "new-token", 9, &leftover);
    g_assert_cmpint (status, ==, WYCTL_TOKEN_FILE_IO);
    g_assert_null (leftover);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    assert_protected_file (fixture.path, "old-token");
    g_assert_cmpuint (count_replace_temporaries (fixture.dir, NULL), ==, 0);
    fault_fixture_clear (&fixture);
  }
}

/* A failed replace whose cleanup cannot remove the temporary file reports
 * INCOMPLETE_REMAINS and names it: the resolved directory plus the
 * temporary's name. It is empty after a failed write and holds the new token
 * otherwise; the target keeps the old token. */
static void
test_replace_incomplete_remains (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (replace_faults); i++) {
    FaultFixture fixture;
    replace_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (replace_faults[i]
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
    gint fds_before = count_open_fds ();
    g_autofree gchar *leftover = NULL;
    WyctlTokenFileStatus status = wyctl_token_file_replace_protected
          (fixture.path, "new-token", 9, &leftover);
    g_assert_cmpint (status, ==, WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS);
    g_assert_nonnull (leftover);
    g_assert_cmpint (count_open_fds (), ==, fds_before);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    g_autofree gchar *temporary = NULL;
    g_assert_cmpuint (count_replace_temporaries (fixture.dir, &temporary), ==,
        1);
    gchar *resolved = realpath (fixture.dir, NULL);
    g_assert_nonnull (resolved);
    g_autofree gchar *expected = g_build_filename (resolved, temporary, NULL);
    free (resolved);
    g_assert_cmpstr (leftover, ==, expected);
    assert_protected_file (leftover,
        replace_faults[i] == WYCTL_TOKEN_FILE_FAULT_WRITE ? "" : "new-token");
    assert_protected_file (fixture.path, "old-token");
    fault_fixture_clear (&fixture);
  }
}

/* A replace cleanup that finds its temporary already gone stays IO, with no
 * leftover; the cleanup flush runs and consumes DIR_SYNC. */
static void
test_replace_cleanup_enoent_is_io (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (replace_faults); i++) {
    FaultFixture fixture;
    replace_fixture_init (&fixture);
    wyctl_token_file_arm_faults_once (replace_faults[i]
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_ENOENT
        | WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
    gchar *leftover = NULL;
    WyctlTokenFileStatus status = wyctl_token_file_replace_protected
          (fixture.path, "new-token", 9, &leftover);
    g_assert_cmpint (status, ==, WYCTL_TOKEN_FILE_IO);
    g_assert_cmpuint (wyctl_token_file_fault_cleanup_enoent_seen (), ==, 1);
    g_assert_null (leftover);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    assert_protected_file (fixture.path, "old-token");
    g_assert_cmpuint (count_replace_temporaries (fixture.dir, NULL), ==, 0);
    fault_fixture_clear (&fixture);
  }
}

/* #1557: both create and replace accept a symlinked parent. A leftover is
 * named inside the resolved directory at every cleanup site. */
static void
test_replace_leftover_resolves_parent_symlink (void)
{
  for (gsize i = 0; i < G_N_ELEMENTS (replace_faults); i++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    g_autofree gchar *real = g_build_filename (fixture.dir, "real", NULL);
    g_assert_cmpint (g_mkdir (real, 0700), ==, 0);
    g_autofree gchar *link = g_build_filename (fixture.dir, "link", NULL);
    g_assert_cmpint (symlink ("real", link), ==, 0);
    g_autofree gchar *real_token = g_build_filename (real, "token", NULL);
    g_autofree gchar *link_token = g_build_filename (link, "token", NULL);
    g_assert_cmpint (wyctl_token_file_write_protected (link_token, "old-token",
        9), ==, WYCTL_TOKEN_FILE_OK);
    g_assert_cmpint (wyctl_token_file_check_available (link_token), ==,
        WYCTL_TOKEN_FILE_ALREADY_EXISTS);
    g_assert_cmpint (wyctl_token_file_write_protected (link_token, "x", 1), ==,
        WYCTL_TOKEN_FILE_ALREADY_EXISTS);
    wyctl_token_file_arm_faults_once (replace_faults[i]
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
    g_autofree gchar *leftover = NULL;
    g_assert_cmpint (wyctl_token_file_replace_protected (link_token,
        "new-token", 9, &leftover), ==, WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS);
    g_autofree gchar *temporary = NULL;
    g_assert_cmpuint (count_replace_temporaries (real, &temporary), ==, 1);
    gchar *resolved = realpath (real, NULL);
    g_assert_nonnull (resolved);
    g_autofree gchar *expected = g_build_filename (resolved, temporary, NULL);
    free (resolved);
    g_assert_cmpstr (leftover, ==, expected);
    g_assert_false (g_str_has_prefix (leftover, link));
    assert_protected_file (leftover,
        replace_faults[i] == WYCTL_TOKEN_FILE_FAULT_WRITE ? "" : "new-token");
    assert_protected_file (real_token, "old-token");
    g_assert_cmpint (g_unlink (leftover), ==, 0);
    g_assert_cmpint (g_unlink (real_token), ==, 0);
    g_assert_cmpint (g_unlink (link), ==, 0);
    g_assert_cmpint (g_rmdir (real), ==, 0);
    fault_fixture_clear (&fixture);
  }
}

/* The rename happened but the directory flush failed. */
static void
test_replace_dir_sync_fault_is_durability_uncertain (void)
{
  FaultFixture fixture;
  replace_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_DIR_SYNC);
  gchar *leftover = NULL;
  g_assert_cmpint (wyctl_token_file_replace_protected (fixture.path,
      "new-token", 9, &leftover), ==, WYCTL_TOKEN_FILE_DURABILITY_UNCERTAIN);
  g_assert_null (leftover);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  assert_protected_file (fixture.path, "new-token");
  g_assert_cmpuint (count_replace_temporaries (fixture.dir, NULL), ==, 0);
  fault_fixture_clear (&fixture);
}

/* A skipped protected write also skips the faults of a replace. */
static void
test_fault_skip_covers_replace (void)
{
  FaultFixture fixture;
  replace_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_RENAME);
  wyctl_token_file_fault_skip_protected_writes (1);
  g_assert_cmpint (wyctl_token_file_replace_protected (fixture.path,
      "new-token", 9, NULL), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==,
      WYCTL_TOKEN_FILE_FAULT_RENAME);
  g_assert_cmpint (wyctl_token_file_replace_protected (fixture.path,
      "newer-token", 11, NULL), ==, WYCTL_TOKEN_FILE_IO);
  assert_protected_file (fixture.path, "new-token");
  fault_fixture_clear (&fixture);
}

/* The pair writer passes INCOMPLETE_REMAINS through with the failing path.
 * Skip 0 aims the faults at the refresh write, so nothing else is written;
 * skip 1 aims them at the access write, and the refresh file is rolled
 * back while the access leftover stays. */
static void
test_pair_incomplete_remains (void)
{
  for (guint skip = 0; skip < 2; skip++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_fault_skip_protected_writes (skip);
    wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_FILE_SYNC
        | WYCTL_TOKEN_FILE_FAULT_CLEANUP_UNLINK);
    const gchar *failed_path = NULL;
    g_assert_cmpint (wyctl_token_file_write_pair_protected (fixture.path,
        "refresh-1", 9, fixture.second_path, "access-1", 8, &failed_path),
        ==, WYCTL_TOKEN_FILE_INCOMPLETE_REMAINS);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    if (skip == 0) {
      g_assert_true (failed_path == fixture.path);
      assert_protected_file (fixture.path, "refresh-1");
      g_assert_false (g_file_test (fixture.second_path, G_FILE_TEST_EXISTS));
    } else {
      g_assert_true (failed_path == fixture.second_path);
      g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
      assert_protected_file (fixture.second_path, "access-1");
    }
    fault_fixture_clear (&fixture);
  }
}

/* The directory was flushed before the failed close, so the write is
 * complete and durable: OK, with the file kept and no descriptor leaked. */
static void
test_dir_close_fault_keeps_file (void)
{
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_DIR_CLOSE);
  gint fds_before = count_open_fds ();
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpint (count_open_fds (), ==, fds_before);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  assert_protected_file (fixture.path, "secret-1");
  fault_fixture_clear (&fixture);
}

/* A parent close failure after a flushed directory is success on either
 * write of the pair: skip 0 aims it at the refresh write, skip 1 at the
 * access write. Both files are kept. */
static void
test_pair_dir_close_fault_is_ok (void)
{
  for (guint skip = 0; skip < 2; skip++) {
    FaultFixture fixture;
    fault_fixture_init (&fixture);
    wyctl_token_file_fault_skip_protected_writes (skip);
    wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_DIR_CLOSE);
    const gchar *failed_path = NULL;
    g_assert_cmpint (wyctl_token_file_write_pair_protected (fixture.path,
        "refresh-1", 9, fixture.second_path, "access-1", 8, &failed_path),
        ==, WYCTL_TOKEN_FILE_OK);
    g_assert_null (failed_path);
    g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
    assert_protected_file (fixture.path, "refresh-1");
    assert_protected_file (fixture.second_path, "access-1");
    fault_fixture_clear (&fixture);
  }
}

static void
test_fault_skip_protected_writes (void)
{
  FaultFixture fixture;
  fault_fixture_init (&fixture);
  wyctl_token_file_fault_skip_protected_writes (1);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_WRITE);
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.path,
      "secret-1", 8), ==, WYCTL_TOKEN_FILE_OK);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==,
      WYCTL_TOKEN_FILE_FAULT_WRITE);
  assert_protected_file (fixture.path, "secret-1");
  g_assert_cmpint (wyctl_token_file_write_protected (fixture.second_path,
      "secret-2", 8), ==, WYCTL_TOKEN_FILE_IO);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  g_assert_false (g_file_test (fixture.second_path, G_FILE_TEST_EXISTS));
  fault_fixture_clear (&fixture);

  /* The pair writer makes the refresh write first; skipping it lets the
   * fault land on the access write, and the refresh file is rolled back. */
  fault_fixture_init (&fixture);
  wyctl_token_file_fault_skip_protected_writes (1);
  wyctl_token_file_arm_faults_once (WYCTL_TOKEN_FILE_FAULT_FILE_SYNC);
  const gchar *failed_path = NULL;
  g_assert_cmpint (wyctl_token_file_write_pair_protected (fixture.path,
      "refresh-1", 9, fixture.second_path, "access-1", 8, &failed_path), ==,
      WYCTL_TOKEN_FILE_IO);
  g_assert_cmpuint (wyctl_token_file_armed_faults (), ==, 0);
  g_assert_true (failed_path == fixture.second_path);
  g_assert_false (g_file_test (fixture.path, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (fixture.second_path, G_FILE_TEST_EXISTS));
  fault_fixture_clear (&fixture);
}
#endif

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/wyctl/token-file/missing-path", test_missing_path);
  g_test_add_func ("/wyctl/token-file/not-found", test_not_found);
  g_test_add_func ("/wyctl/token-file/accepts-0600", test_accepts_mode_0600);
  g_test_add_func ("/wyctl/token-file/accepts-0400", test_accepts_mode_0400);
  g_test_add_func ("/wyctl/token-file/rejects-0640", test_rejects_mode_0640);
  g_test_add_func ("/wyctl/token-file/rejects-0604", test_rejects_mode_0604);
  g_test_add_func ("/wyctl/token-file/rejects-0660", test_rejects_mode_0660);
  g_test_add_func ("/wyctl/token-file/rejects-terminal-symlink",
      test_rejects_terminal_symlink);
  g_test_add_func ("/wyctl/token-file/rejects-non-regular",
      test_rejects_non_regular_via_classifier);
  g_test_add_func ("/wyctl/token-file/rejects-empty", test_rejects_empty_file);
  g_test_add_func ("/wyctl/token-file/rejects-too-large",
      test_rejects_too_large);
  g_test_add_func ("/wyctl/token-file/rejects-embedded-nul",
      test_rejects_embedded_nul);
  g_test_add_func ("/wyctl/token-file/owner-mismatch-via-classifier",
      test_owner_mismatch_via_classifier);
  g_test_add_func ("/wyctl/token-file/status-message-no-token",
      test_status_message_table_has_no_token_placeholder);
  g_test_add_func ("/wyctl/token-file/windows-attrs-accept-readonly",
      test_windows_attrs_accept_readonly);
  g_test_add_func ("/wyctl/token-file/windows-attrs-reject-not-readonly",
      test_windows_attrs_reject_not_readonly);
  g_test_add_func ("/wyctl/token-file/windows-attrs-reject-reparse-point",
      test_windows_attrs_reject_reparse_point);
  g_test_add_func ("/wyctl/token-file/protected-writer-no-replace",
      test_protected_writer_is_no_replace);
  g_test_add_func ("/wyctl/token-file/output-preflight",
      test_output_preflight);
  g_test_add_func ("/wyctl/token-file/protected-replace-and-remove",
      test_protected_replace_and_remove);
  g_test_add_func ("/wyctl/token-file/protected-pair-rollback",
      test_protected_pair_rolls_back_only_its_refresh_file);
  g_test_add_func ("/wyctl/token-file/protected-pair-refresh-collision",
      test_protected_pair_identifies_refresh_collision);
#ifndef G_OS_WIN32
  g_test_add_func ("/wyctl/token-file/refresh-lock-serializes-processes",
      test_refresh_lock_serializes_processes);
#endif
#ifndef G_OS_WIN32
  g_test_add_data_func ("/wyctl/token-file/protected-direct-parent-symlink",
      GINT_TO_POINTER (0), test_protected_parent_symlink);
  g_test_add_data_func ("/wyctl/token-file/protected-ancestor-symlink",
      GINT_TO_POINTER (1), test_protected_parent_symlink);
  g_test_add_func ("/wyctl/token-file/protected-pair-parent-symlink",
      test_protected_pair_parent_symlink);
  g_test_add_func ("/wyctl/token-file/parent-resolution-failures",
      test_parent_resolution_failures);
  g_test_add_func ("/wyctl/token-file/parent-resolution-permission-denied",
      test_parent_resolution_permission_denied);
#else
  g_test_add_func ("/wyctl/token-file/windows-parent-reparse-rejected",
      test_windows_parent_reparse_is_rejected);
  g_test_add_func ("/wyctl/token-file/windows-ancestor-reparse-rejected",
      test_windows_ancestor_reparse_is_rejected);
  g_test_add_func ("/wyctl/token-file/windows-final-reparse-rejected",
      test_windows_final_reparse_is_rejected);
#endif
#if defined (WYL_ENABLE_FAULT_INJECTION) && !defined (G_OS_WIN32)
  g_test_add_func ("/wyctl/token-file/fault-spec-parse", test_fault_spec_parse);
  g_test_add_func ("/wyctl/token-file/write-fault-is-io",
      test_write_fault_is_io);
  g_test_add_func ("/wyctl/token-file/dir-sync-fault-is-durability-uncertain",
      test_dir_sync_fault_is_durability_uncertain);
  g_test_add_func ("/wyctl/token-file/cleanup-flush-fault-stays-io",
      test_cleanup_flush_fault_stays_io);
  g_test_add_func ("/wyctl/token-file/cleanup-unlink-not-reached-on-success",
      test_cleanup_unlink_not_reached_on_success);
  g_test_add_func ("/wyctl/token-file/cleanup-unlink-fault-fires-independently",
      test_cleanup_unlink_fault_fires_independently);
  g_test_add_func ("/wyctl/token-file/cleanup-enoent-is-io",
      test_cleanup_enoent_is_io);
  g_test_add_func ("/wyctl/token-file/cleanup-unlink-wins-over-enoent",
      test_cleanup_unlink_wins_over_enoent);
  g_test_add_func ("/wyctl/token-file/replace-fault-is-io",
      test_replace_fault_is_io);
  g_test_add_func ("/wyctl/token-file/replace-incomplete-remains",
      test_replace_incomplete_remains);
  g_test_add_func ("/wyctl/token-file/replace-cleanup-enoent-is-io",
      test_replace_cleanup_enoent_is_io);
  g_test_add_func ("/wyctl/token-file/replace-leftover-resolves-parent-"
      "symlink", test_replace_leftover_resolves_parent_symlink);
  g_test_add_func ("/wyctl/token-file/replace-dir-sync-fault-is-durability-"
      "uncertain", test_replace_dir_sync_fault_is_durability_uncertain);
  g_test_add_func ("/wyctl/token-file/fault-skip-covers-replace",
      test_fault_skip_covers_replace);
  g_test_add_func ("/wyctl/token-file/pair-incomplete-remains",
      test_pair_incomplete_remains);
  g_test_add_func ("/wyctl/token-file/dir-close-fault-keeps-file",
      test_dir_close_fault_keeps_file);
  g_test_add_func ("/wyctl/token-file/pair-dir-close-fault-is-ok",
      test_pair_dir_close_fault_is_ok);
  g_test_add_func ("/wyctl/token-file/fault-skip-protected-writes",
      test_fault_skip_protected_writes);
#endif
  return wyl_test_normalize_exit_status (g_test_run ());
}
