/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Expose POSIX.1-2008 symlink/lstat under strict c_std=c17. Must
 * precede every system header. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
/* Apple SDKs gate POSIX-only BSD features behind _DARWIN_C_SOURCE
 * when the compiler is invoked under -std=cNN (clang predefines
 * __STRICT_ANSI__). Setting _POSIX_C_SOURCE alone is not enough. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
/* Regression tests for CodeQL alert #7 (cpp/toctou-race-condition,
 * CWE-367) on wyrelog/policy/store.c.
 *
 * The encrypted policy store now performs its own canonical envelope I/O
 * through pinned-handle primitives:
 *   POSIX  -- directory fd captured at open time, O_NOFOLLOW on every
 *             openat() of the final component.
 *   Win32  -- CreateFileW with FILE_FLAG_OPEN_REPARSE_POINT plus an
 *             attribute check via GetFileInformationByHandle; reparse
 *             points (symlinks, junctions, mount points) are refused
 *             before keyprovider materialization.
 * SQLite still opens its main database and later auxiliary files by
 * lease-resolved pathnames throughout the store lifetime; only the initial
 * main-database open has pre/post parent checks. The full-lifetime trusted
 * namespace requirement is documented separately. These tests exercise the
 * four pinned Wyrelog-I/O behavioral contracts on both legs; they do not claim
 * to pin SQLite VFS opens or the canonical SQLite inode.
 * The two symlink-creation cases require Developer Mode (Win10 1703+)
 * on Windows; runs that lack SeCreateSymbolicLinkPrivilege skip those
 * cases with a printf rather than failing. */

#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-dev-private.h"

#include <sys/stat.h>
#ifdef G_OS_WIN32
#include <windows.h>
/* MSVC's <sys/stat.h> exposes _S_IFREG/_S_IFMT but no POSIX S_ISREG
 * convenience macro. Provide one so the regular-file check below
 * stays cross-platform. */
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#else
#include <unistd.h>
#endif

/* SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE is documented in
 * recent Windows SDKs but may be missing from older mingw headers. */
#ifdef G_OS_WIN32
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#endif

static int
create_file_symlink (const gchar *target, const gchar *linkpath)
{
#ifdef G_OS_WIN32
  wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1, NULL, NULL, NULL);
  wchar_t *wlink = (wchar_t *) g_utf8_to_utf16 (linkpath, -1, NULL, NULL, NULL);
  if (wtarget == NULL || wlink == NULL) {
    g_free (wtarget);
    g_free (wlink);
    return -1;
  }
  BOOL ok = CreateSymbolicLinkW (wlink, wtarget,
      SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
  if (!ok)
    ok = CreateSymbolicLinkW (wlink, wtarget, 0);
  g_free (wtarget);
  g_free (wlink);
  return ok ? 0 : -1;
#else
  return symlink (target, linkpath);
#endif
}

static int
create_dir_symlink (const gchar *target, const gchar *linkpath)
{
#ifdef G_OS_WIN32
  wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1, NULL, NULL, NULL);
  wchar_t *wlink = (wchar_t *) g_utf8_to_utf16 (linkpath, -1, NULL, NULL, NULL);
  if (wtarget == NULL || wlink == NULL) {
    g_free (wtarget);
    g_free (wlink);
    return -1;
  }
  BOOL ok = CreateSymbolicLinkW (wlink, wtarget,
      SYMBOLIC_LINK_FLAG_DIRECTORY
      | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
  if (!ok)
    ok = CreateSymbolicLinkW (wlink, wtarget, SYMBOLIC_LINK_FLAG_DIRECTORY);
  g_free (wtarget);
  g_free (wlink);
  return ok ? 0 : -1;
#else
  return symlink (target, linkpath);
#endif
}

/* Probe whether the current process can create symlinks. On POSIX
 * this is always true. On Windows it requires either Developer Mode
 * (Win10 1703+) or SeCreateSymbolicLinkPrivilege; CI without either
 * returns FALSE and the symlink-dependent cases are skipped with a
 * soft success rather than reported as a failure. */
static gboolean
can_create_symlinks (void)
{
#ifdef G_OS_WIN32
  GError *err = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyl-symlink-probe-XXXXXX", &err);
  if (dir == NULL) {
    g_clear_error (&err);
    return FALSE;
  }
  g_autofree gchar *target = g_build_filename (dir, "t", NULL);
  g_autofree gchar *link = g_build_filename (dir, "l", NULL);
  gboolean ok = FALSE;
  if (g_file_set_contents (target, "", 0, NULL)
      && create_file_symlink (target, link) == 0) {
    (void) g_remove (link);
    ok = TRUE;
  }
  (void) g_remove (target);
  (void) g_rmdir (dir);
  return ok;
#else
  return TRUE;
#endif
}

static gchar *
make_tmpdir (void)
{
  GError *error = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-policy-store-toctou-XXXXXX", &error);
  if (dir == NULL) {
    g_clear_error (&error);
    return NULL;
  }
  return dir;
}

static void
rmrf (const gchar *path)
{
  if (path == NULL)
    return;
  GDir *dir = g_dir_open (path, 0, NULL);
  if (dir != NULL) {
    const gchar *child;
    while ((child = g_dir_read_name (dir)) != NULL) {
      g_autofree gchar *p = g_build_filename (path, child, NULL);
      if (g_file_test (p, G_FILE_TEST_IS_DIR)
          && !g_file_test (p, G_FILE_TEST_IS_SYMLINK))
        rmrf (p);
      else
        (void) g_remove (p);
    }
    g_dir_close (dir);
  }
  (void) g_rmdir (path);
}

static wyl_policy_store_open_options_t
make_encrypted_opts (const gchar *path, wyl_keyprovider_dev_t *kp)
{
  wyl_policy_store_open_options_t opts = { 0 };
  opts.path = path;
  opts.require_encrypted = TRUE;
  opts.keyprovider_vtable = wyl_keyprovider_dev_get_vtable ();
  opts.keyprovider_state = kp;
  /* The dev keyprovider is owned by the test (autoptr); the store
   * must not free it. wipe is invoked unconditionally on the state
   * after open returns -- that is acceptable, the next test allocates
   * a fresh state. */
  opts.keyprovider_state_free = NULL;
  return opts;
}

/* The symlink-at-canonical-path case must be refused with
 * WYRELOG_E_POLICY before the daemon ever opens the file. Skipped
 * (soft success) when the test process cannot create symlinks. */
static gint
test_symlink_at_canonical_rejected (void)
{
  if (!can_create_symlinks ()) {
    g_printerr ("test_symlink_at_canonical_rejected: skipped"
        " (no symlink-create privilege)\n");
    return 0;
  }

  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 100;
  g_autofree gchar *canonical = g_build_filename (dir, "policy.sqlite", NULL);
  g_autofree gchar *target = g_build_filename (dir, "decoy", NULL);

  /* Create the symlink target as an empty regular file, then point
   * canonical at it. The store must refuse to follow. */
  if (g_file_set_contents (target, "", 0, NULL) == FALSE) {
    rmrf (dir);
    return 101;
  }
  if (create_file_symlink (target, canonical) != 0) {
    rmrf (dir);
    return 102;
  }

  g_autoptr (wyl_keyprovider_dev_t) kp = wyl_keyprovider_dev_new ();
  wyl_policy_store_open_options_t opts = make_encrypted_opts (canonical, kp);
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);

  /* The store handle must not have been produced. */
  if (store != NULL) {
    wyl_policy_store_close (store);
    rmrf (dir);
    return 103;
  }
  if (rc != WYRELOG_E_POLICY) {
    rmrf (dir);
    return 104;
  }

  rmrf (dir);
  return 0;
}

/* A non-existent canonical path is a legitimate fresh-store init.
 * The new ENOENT branch on openat must treat it as a normal create
 * rather than an error. */
static gint
test_fresh_store_creates_without_check (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 200;
  g_autofree gchar *canonical = g_build_filename (dir, "policy.sqlite", NULL);

  g_autoptr (wyl_keyprovider_dev_t) kp = wyl_keyprovider_dev_new ();
  wyl_policy_store_open_options_t opts = make_encrypted_opts (canonical, kp);
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
  if (rc != WYRELOG_E_OK || store == NULL) {
    if (store != NULL)
      wyl_policy_store_close (store);
    rmrf (dir);
    return 201;
  }
  /* Materialize the schema so sqlite actually writes the work file.
   * Without DDL, journal_mode=MEMORY leaves the work file empty and
   * persist would round-trip an empty plaintext that decrypt then
   * refuses on reopen. */
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK) {
    wyl_policy_store_close (store);
    rmrf (dir);
    return 202;
  }
  wyl_policy_store_close (store);

  rmrf (dir);
  return 0;
}

/* Open + close + reopen on a real regular file. The reopen must
 * walk the decrypt-from-bytes path successfully. */
static gint
test_normal_open_still_works (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 300;
  g_autofree gchar *canonical = g_build_filename (dir, "policy.sqlite", NULL);

  /* First open: create the encrypted store on disk. */
  {
    g_autoptr (wyl_keyprovider_dev_t) kp = wyl_keyprovider_dev_new ();
    wyl_policy_store_open_options_t opts = make_encrypted_opts (canonical, kp);
    wyl_policy_store_t *store = NULL;
    wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
    if (rc != WYRELOG_E_OK || store == NULL) {
      if (store != NULL)
        wyl_policy_store_close (store);
      rmrf (dir);
      return 301;
    }
    /* Materialize schema so the work file contains real bytes before
     * close persists the encrypted blob. */
    if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK) {
      wyl_policy_store_close (store);
      rmrf (dir);
      return 304;
    }
    /* close persists the encrypted blob to canonical. */
    wyl_policy_store_close (store);
  }

  /* canonical must now exist as a regular file. */
  GStatBuf st;
  if (g_lstat (canonical, &st) != 0 || !S_ISREG (st.st_mode)) {
    rmrf (dir);
    return 302;
  }

  /* Second open: must traverse the read_through_dirfd +
   * decrypt_from_bytes path. */
  {
    g_autoptr (wyl_keyprovider_dev_t) kp = wyl_keyprovider_dev_new ();
    wyl_policy_store_open_options_t opts = make_encrypted_opts (canonical, kp);
    wyl_policy_store_t *store = NULL;
    wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
    if (rc != WYRELOG_E_OK || store == NULL) {
      if (store != NULL)
        wyl_policy_store_close (store);
      rmrf (dir);
      return 303;
    }
    wyl_policy_store_close (store);
  }

  rmrf (dir);
  return 0;
}

/* Operators may arrange /var/lib/wyrelog/ as a symlink farm. The
 * reparse-point/lstat check is on the final path component only, so
 * a symlinked parent directory must remain permitted. Skipped (soft
 * success) when the test process cannot create symlinks. */
static gint
test_parent_directory_symlink_is_permitted (void)
{
  if (!can_create_symlinks ()) {
    g_printerr ("test_parent_directory_symlink_is_permitted: skipped"
        " (no symlink-create privilege)\n");
    return 0;
  }

  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 400;
  g_autofree gchar *real_parent = g_build_filename (dir, "real", NULL);
  g_autofree gchar *link_parent = g_build_filename (dir, "link", NULL);

  if (g_mkdir_with_parents (real_parent, 0700) != 0) {
    rmrf (dir);
    return 401;
  }
  if (create_dir_symlink (real_parent, link_parent) != 0) {
    rmrf (dir);
    return 402;
  }

  g_autofree gchar *canonical =
      g_build_filename (link_parent, "policy.sqlite", NULL);
  g_autoptr (wyl_keyprovider_dev_t) kp = wyl_keyprovider_dev_new ();
  wyl_policy_store_open_options_t opts = make_encrypted_opts (canonical, kp);
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
  if (rc != WYRELOG_E_OK || store == NULL) {
    if (store != NULL)
      wyl_policy_store_close (store);
    rmrf (dir);
    return 403;
  }
  if (wyl_policy_store_create_schema (store) != WYRELOG_E_OK) {
    wyl_policy_store_close (store);
    rmrf (dir);
    return 404;
  }
  wyl_policy_store_close (store);

  rmrf (dir);
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = test_symlink_at_canonical_rejected ()) != 0) {
    g_printerr ("test_symlink_at_canonical_rejected failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_fresh_store_creates_without_check ()) != 0) {
    g_printerr ("test_fresh_store_creates_without_check failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_normal_open_still_works ()) != 0) {
    g_printerr ("test_normal_open_still_works failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_parent_directory_symlink_is_permitted ()) != 0) {
    g_printerr ("test_parent_directory_symlink_is_permitted failed: %d\n", rc);
    return rc;
  }

  return 0;
}
