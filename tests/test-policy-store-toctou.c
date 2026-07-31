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
#include "wyrelog/policy/store-lease-private.h"
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
  /* The dev keyprovider backing storage is owned by the test (autoptr), so it
   * must outlive the store. A successful open retains operational ownership
   * and wipes it at store close; failure wipes it before returning. */
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

/* --- #618 maintenance-exclusive store-file identity pinning ---
 *
 * The offline remediation tool takes the store under a maintenance lease that,
 * atop the existing exclusive flock, opens and pins the STORE FILE's own
 * identity (dev/ino/nlink/owner/mode) and fails closed on any substitution.
 * These exercise the POSIX raw-lease contract directly. */
#ifndef G_OS_WIN32
static gboolean
write_owner_only_store (const gchar *path)
{
  if (!g_file_set_contents (path, "store", 5, NULL))
    return FALSE;
  return g_chmod (path, 0600) == 0;
}

/* A clean owner-only store is accepted and its identity re-verifies OK. */
static gint
test_maintenance_acquire_pins_clean_store (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 500;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  if (!write_owner_only_store (store)) {
    rmrf (dir);
    return 501;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (rc != WYRELOG_E_OK || lease == NULL) {
    if (lease != NULL)
      wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 502;
  }
  if (wyl_policy_store_lease_verify_store_identity (lease) != WYRELOG_E_OK) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 503;
  }
  wyl_policy_store_lease_release (lease);
  rmrf (dir);
  return 0;
}

/* A symlink at the store path is refused (O_NOFOLLOW ELOOP). */
static gint
test_maintenance_symlink_rejected (void)
{
  if (!can_create_symlinks ()) {
    g_printerr ("test_maintenance_symlink_rejected: skipped"
        " (no symlink-create privilege)\n");
    return 0;
  }
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 510;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  g_autofree gchar *target = g_build_filename (dir, "real.sqlite", NULL);
  if (!write_owner_only_store (target)) {
    rmrf (dir);
    return 511;
  }
  if (create_file_symlink (target, store) != 0) {
    rmrf (dir);
    return 512;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (lease != NULL) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 513;
  }
  if (rc != WYRELOG_E_POLICY) {
    rmrf (dir);
    return 514;
  }
  rmrf (dir);
  return 0;
}

/* A hardlinked store (st_nlink == 2) is refused. */
static gint
test_maintenance_hardlink_rejected (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 520;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  g_autofree gchar *alias = g_build_filename (dir, "alias.sqlite", NULL);
  if (!write_owner_only_store (store)) {
    rmrf (dir);
    return 521;
  }
  if (link (store, alias) != 0) {
    rmrf (dir);
    return 522;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (lease != NULL) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 523;
  }
  if (rc != WYRELOG_E_POLICY) {
    rmrf (dir);
    return 524;
  }
  rmrf (dir);
  return 0;
}

/* A group/world-accessible store (0644) is refused. */
static gint
test_maintenance_loose_mode_rejected (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 530;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  if (!g_file_set_contents (store, "store", 5, NULL)
      || g_chmod (store, 0644) != 0) {
    rmrf (dir);
    return 531;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (lease != NULL) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 532;
  }
  if (rc != WYRELOG_E_POLICY) {
    rmrf (dir);
    return 533;
  }
  rmrf (dir);
  return 0;
}

/* A store owned by a different uid is refused. Requires root to arrange the
 * foreign ownership; skipped (soft success) otherwise. */
static gint
test_maintenance_wrong_owner_rejected (void)
{
  if (geteuid () != 0) {
    g_printerr ("test_maintenance_wrong_owner_rejected: skipped"
        " (requires root to chown to a foreign uid)\n");
    return 0;
  }
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 540;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  if (!write_owner_only_store (store)) {
    rmrf (dir);
    return 541;
  }
  if (chown (store, 1, 1) != 0) {
    rmrf (dir);
    return 542;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (lease != NULL) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 543;
  }
  if (rc != WYRELOG_E_POLICY) {
    rmrf (dir);
    return 544;
  }
  rmrf (dir);
  return 0;
}

/* verify_store_identity is OK while the store is unchanged and E_POLICY once
 * the store file is replaced by a different inode under the held lease. */
static gint
test_maintenance_verify_detects_swap (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 550;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  if (!write_owner_only_store (store)) {
    rmrf (dir);
    return 551;
  }
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (rc != WYRELOG_E_OK || lease == NULL) {
    if (lease != NULL)
      wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 552;
  }
  if (wyl_policy_store_lease_verify_store_identity (lease) != WYRELOG_E_OK) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 553;
  }
  /* Replace the store with a fresh, distinct inode. The held descriptor keeps
   * the original inode number allocated, so the recreated file differs. */
  if (g_remove (store) != 0 || !write_owner_only_store (store)) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 554;
  }
  if (wyl_policy_store_lease_verify_store_identity (lease) != WYRELOG_E_POLICY) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 555;
  }
  wyl_policy_store_lease_release (lease);
  rmrf (dir);
  return 0;
}

/* A second maintenance acquire on the same store is refused with BUSY while
 * the first lease is held (exclusivity). */
static gint
test_maintenance_second_acquire_busy (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 560;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  if (!write_owner_only_store (store)) {
    rmrf (dir);
    return 561;
  }
  wyl_policy_store_lease_t *first = NULL;
  if (wyl_policy_store_lease_acquire_maintenance (store, &first)
      != WYRELOG_E_OK || first == NULL) {
    if (first != NULL)
      wyl_policy_store_lease_release (first);
    rmrf (dir);
    return 562;
  }
  wyl_policy_store_lease_t *second = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &second);
  if (second != NULL) {
    wyl_policy_store_lease_release (second);
    wyl_policy_store_lease_release (first);
    rmrf (dir);
    return 563;
  }
  if (rc != WYRELOG_E_BUSY) {
    wyl_policy_store_lease_release (first);
    rmrf (dir);
    return 564;
  }
  wyl_policy_store_lease_release (first);
  rmrf (dir);
  return 0;
}

/* An absent store is not a fresh-create case for remediation: NOT_FOUND. */
static gint
test_maintenance_absent_store_not_found (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  if (dir == NULL)
    return 570;
  g_autofree gchar *store = g_build_filename (dir, "policy.sqlite", NULL);
  wyl_policy_store_lease_t *lease = NULL;
  wyrelog_error_t rc = wyl_policy_store_lease_acquire_maintenance (store,
      &lease);
  if (lease != NULL) {
    wyl_policy_store_lease_release (lease);
    rmrf (dir);
    return 571;
  }
  if (rc != WYRELOG_E_NOT_FOUND) {
    rmrf (dir);
    return 572;
  }
  rmrf (dir);
  return 0;
}
#endif /* !G_OS_WIN32 */

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
#ifndef G_OS_WIN32
  if ((rc = test_maintenance_acquire_pins_clean_store ()) != 0) {
    g_printerr ("test_maintenance_acquire_pins_clean_store failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_symlink_rejected ()) != 0) {
    g_printerr ("test_maintenance_symlink_rejected failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_hardlink_rejected ()) != 0) {
    g_printerr ("test_maintenance_hardlink_rejected failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_loose_mode_rejected ()) != 0) {
    g_printerr ("test_maintenance_loose_mode_rejected failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_wrong_owner_rejected ()) != 0) {
    g_printerr ("test_maintenance_wrong_owner_rejected failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_verify_detects_swap ()) != 0) {
    g_printerr ("test_maintenance_verify_detects_swap failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_second_acquire_busy ()) != 0) {
    g_printerr ("test_maintenance_second_acquire_busy failed: %d\n", rc);
    return rc;
  }
  if ((rc = test_maintenance_absent_store_not_found ()) != 0) {
    g_printerr ("test_maintenance_absent_store_not_found failed: %d\n", rc);
    return rc;
  }
#endif /* !G_OS_WIN32 */

  return 0;
}
