/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 symlink/lstat/mkfifo under strict c_std=c17.
 * Must precede every system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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
      s <= WYCTL_TOKEN_FILE_WINDOWS_ACL_UNAVAILABLE; s++) {
    const gchar *msg = wyctl_token_file_status_message (
        (WyctlTokenFileStatus) s);
    if (msg == NULL)
      continue;
    int placeholders = 0;
    for (const gchar * p = msg; *p != '\0'; p++) {
      if (p[0] == '%' && p[1] == 's')
        placeholders++;
    }
    g_assert_cmpint (placeholders, <=, 1);
    /* Sanity check: ensure no leftover test-token-like string baked
     * into the table. */
    g_assert_null (strstr (msg, "token-1"));
  }
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
      !=, WYCTL_TOKEN_FILE_OK);
  g_autofree gchar *token = NULL;
  g_assert_cmpint (wyctl_token_file_read (path, &token), ==,
      WYCTL_TOKEN_FILE_OK);
  g_assert_cmpstr (token, ==, "access-1");
  g_unlink (path);
}

#ifndef G_OS_WIN32
static void
test_protected_writer_rejects_parent_symlink (void)
{
  g_autofree gchar *real_dir = g_dir_make_tmp ("wyctl-parent-XXXXXX", NULL);
  g_assert_nonnull (real_dir);
  g_autofree gchar *link_dir = g_strdup_printf ("%s-link", real_dir);
  g_assert_cmpint (symlink (real_dir, link_dir), ==, 0);
  g_autofree gchar *path = g_build_filename (link_dir, "token", NULL);
  g_assert_cmpint (wyctl_token_file_write_protected (path, "access-1", 8),
      !=, WYCTL_TOKEN_FILE_OK);
  g_assert_false (g_file_test (g_build_filename (real_dir, "token", NULL),
          G_FILE_TEST_EXISTS));
  g_unlink (link_dir);
  g_rmdir (real_dir);
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
#ifndef G_OS_WIN32
  g_test_add_func ("/wyctl/token-file/protected-writer-rejects-parent-symlink",
      test_protected_writer_rejects_parent_symlink);
#else
  g_test_add_func ("/wyctl/token-file/windows-parent-reparse-rejected",
      test_windows_parent_reparse_is_rejected);
  g_test_add_func ("/wyctl/token-file/windows-final-reparse-rejected",
      test_windows_final_reparse_is_rejected);
#endif
  return g_test_run ();
}
