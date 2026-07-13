/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#include "wyrelog/policy/store-private.h"

#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
#endif

#define LOCK_SUFFIX ".wyrelog-lock"
#define CLEAR_SUFFIX ".wyrelog-clear"

#define LEASE_HELPER_ARG "--lease-helper"

static gchar *test_lease_self_path;

static gint run_helper_exit (const gchar * path);
typedef struct
{
  guint probes;
  guint derives;
  guint wipes;
  gboolean wiped;
} CountingProvider;

static wyrelog_error_t
counting_probe (gpointer data)
{
  CountingProvider *provider = data;
  provider->probes++;
  return provider->wiped ? WYRELOG_E_INTERNAL : WYRELOG_E_OK;
}

static wyrelog_error_t
counting_derive (gpointer data, const gchar *label, guint8 *out, gsize out_len)
{
  CountingProvider *provider = data;
  provider->derives++;
  if (provider->wiped || label == NULL || out == NULL)
    return WYRELOG_E_INTERNAL;
  memset (out, 0x5a, out_len);
  return WYRELOG_E_OK;
}

static void
counting_wipe (gpointer data)
{
  CountingProvider *provider = data;
  provider->wipes++;
  provider->wiped = TRUE;
}

static const wyl_keyprovider_vtable_t counting_vtable = {
  .probe = counting_probe,
  .derive = counting_derive,
  .wipe = counting_wipe,
};

static gint
lease_helper_main (int argc, char **argv)
{
  if (argc != 3 && argc != 4)
    return 2;

  CountingProvider provider = { 0 };
  wyl_policy_store_open_options_t opts = {
    .path = argv[2],
    .keyprovider_vtable = &counting_vtable,
    .keyprovider_state = &provider,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  wyrelog_error_t rc = wyl_policy_store_open_with_options (&opts, &store);
  if (rc == WYRELOG_E_BUSY)
    return 73;
  if (rc != WYRELOG_E_OK)
    return 74;

  gboolean oneshot = argc == 4 && g_strcmp0 (argv[3], "--oneshot") == 0;
  if (!oneshot) {
    g_print ("READY\n");
    fflush (stdout);
    (void) getchar ();
  }
  wyl_policy_store_close (store);
  return 0;
}

typedef struct
{
  guint probes;
  guint seals;
  guint unseals;
  guint derives;
  guint wipes;
  guint frees;
} OwnedProviderCounters;

typedef struct
{
  OwnedProviderCounters *counters;
} OwnedProvider;

static wyrelog_error_t
owned_probe (gpointer data)
{
  OwnedProvider *provider = data;
  provider->counters->probes++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
owned_seal (gpointer data, const guint8 *plaintext, gsize plaintext_len,
    wyl_sealed_blob_t *out_blob)
{
  OwnedProvider *provider = data;
  (void) plaintext;
  (void) plaintext_len;
  (void) out_blob;
  provider->counters->seals++;
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
owned_unseal (gpointer data, const wyl_sealed_blob_t *blob, guint8 *out,
    gsize capacity, gsize *written)
{
  OwnedProvider *provider = data;
  (void) blob;
  (void) out;
  (void) capacity;
  (void) written;
  provider->counters->unseals++;
  return WYRELOG_E_INTERNAL;
}

static wyrelog_error_t
owned_derive (gpointer data, const gchar *label, guint8 *out, gsize out_len)
{
  OwnedProvider *provider = data;
  (void) label;
  (void) out;
  (void) out_len;
  provider->counters->derives++;
  return WYRELOG_E_INTERNAL;
}

static void
owned_wipe (gpointer data)
{
  OwnedProvider *provider = data;
  provider->counters->wipes++;
}

static void
owned_free (gpointer data)
{
  OwnedProvider *provider = data;
  provider->counters->frees++;
  g_free (provider);
}

static const wyl_keyprovider_vtable_t owned_vtable = {
  .probe = owned_probe,
  .seal = owned_seal,
  .unseal = owned_unseal,
  .derive = owned_derive,
  .wipe = owned_wipe,
};

static wyl_policy_store_open_options_t
encrypted_opts (const gchar *path, CountingProvider *provider)
{
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = &counting_vtable,
    .keyprovider_state = provider,
    .require_encrypted = TRUE,
  };
  return opts;
}

static wyl_policy_store_open_options_t
plaintext_provider_opts (const gchar *path, CountingProvider *provider)
{
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = &counting_vtable,
    .keyprovider_state = provider,
  };
  return opts;
}

static gchar *
make_tmpdir (void)
{
  GError *error = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-store-lease-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (dir);
  return dir;
}

static void
remove_store_files (const gchar *path)
{
  static const gchar *suffixes[] = {
    "", CLEAR_SUFFIX, LOCK_SUFFIX, ".wyrelog-tmp", "-wal", "-shm",
    CLEAR_SUFFIX "-journal", CLEAR_SUFFIX "-wal", CLEAR_SUFFIX "-shm",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (suffixes); i++) {
    g_autofree gchar *candidate = g_strdup_printf ("%s%s", path, suffixes[i]);
    (void) g_remove (candidate);
  }
}

static void
assert_lock_stable (const gchar *path)
{
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", path, LOCK_SUFFIX);
  GStatBuf statbuf;
  g_assert_cmpint (g_stat (lock_path, &statbuf), ==, 0);
#ifndef G_OS_WIN32
  g_assert_true (S_ISREG (statbuf.st_mode));
  g_assert_cmpuint (statbuf.st_mode & 0777, ==, 0600);
#endif
}

static gint
run_helper_exit (const gchar *path)
{
  const gchar *argv[] = { test_lease_self_path, LEASE_HELPER_ARG, path,
    "--oneshot", NULL
  };
  GError *error = NULL;
  GSubprocess *process = g_subprocess_newv (argv,
      G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
      &error);
  g_assert_no_error (error);
  g_assert_true (g_subprocess_wait (process, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (g_subprocess_get_if_exited (process));
  gint status = g_subprocess_get_exit_status (process);
  g_object_unref (process);
  return status;
}

static void
test_same_process_and_different_paths (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path_a = g_build_filename (dir, "a.store", NULL);
  g_autofree gchar *path_b = g_build_filename (dir, "b.store", NULL);
  CountingProvider provider_a = { 0 };
  OwnedProviderCounters busy_counters = { 0 };
  OwnedProvider *provider_busy = g_new0 (OwnedProvider, 1);
  provider_busy->counters = &busy_counters;
  CountingProvider provider_b = { 0 };
  wyl_policy_store_open_options_t opts_a = encrypted_opts (path_a,
      &provider_a);
  wyl_policy_store_open_options_t opts_busy = {
    .path = path_a,
    .keyprovider_vtable = &owned_vtable,
    .keyprovider_state = provider_busy,
    .keyprovider_state_free = owned_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_open_options_t opts_b = encrypted_opts (path_b,
      &provider_b);
  wyl_policy_store_t *store_a = NULL;
  wyl_policy_store_t *store_b = NULL;
  wyl_policy_store_t *busy = NULL;

  g_assert_cmpint (wyl_policy_store_open_with_options (&opts_a, &store_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store_a), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts_busy, &busy), ==,
      WYRELOG_E_BUSY);
  g_assert_null (busy);
  g_assert_cmpuint (busy_counters.probes, ==, 0);
  g_assert_cmpuint (busy_counters.seals, ==, 0);
  g_assert_cmpuint (busy_counters.unseals, ==, 0);
  g_assert_cmpuint (busy_counters.derives, ==, 0);
  g_assert_cmpuint (busy_counters.wipes, ==, 1);
  g_assert_cmpuint (busy_counters.frees, ==, 1);
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts_b, &store_b), ==,
      WYRELOG_E_OK);

  /* The rejected same-process open must not accidentally release the
   * process-associated fcntl lock held by store_a. */
  const gchar *holder_argv[] = { test_lease_self_path, LEASE_HELPER_ARG,
    path_a, NULL
  };
  GError *spawn_error = NULL;
  GSubprocess *contender = g_subprocess_newv (holder_argv,
      G_SUBPROCESS_FLAGS_STDOUT_SILENCE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
      &spawn_error);
  g_assert_no_error (spawn_error);
  g_assert_true (g_subprocess_wait (contender, NULL, &spawn_error));
  g_assert_no_error (spawn_error);
  g_assert_true (g_subprocess_get_if_exited (contender));
  g_assert_cmpint (g_subprocess_get_exit_status (contender), ==, 73);
  g_object_unref (contender);
  g_autofree gchar *missing_parent_path =
      g_build_filename (dir, "missing", "policy.store", NULL);
  g_assert_cmpint (run_helper_exit (missing_parent_path), ==, 74);

  wyl_policy_store_close (store_b);
  wyl_policy_store_close (store_a);
  CountingProvider reopen_provider = { 0 };
  wyl_policy_store_open_options_t reopen_opts = encrypted_opts (path_a,
      &reopen_provider);
  wyl_policy_store_t *reopened = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&reopen_opts, &reopened),
      ==, WYRELOG_E_OK);
  wyl_policy_store_close (reopened);
  assert_lock_stable (path_a);
  assert_lock_stable (path_b);
  remove_store_files (path_a);
  remove_store_files (path_b);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_relative_absolute_identity (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "relative.store", NULL);
  g_autofree gchar *old_cwd = g_get_current_dir ();
  CountingProvider first = { 0 };
  CountingProvider second = { 0 };
  wyl_policy_store_open_options_t first_opts = encrypted_opts (path, &first);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&first_opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (g_chdir (dir), ==, 0);
  wyl_policy_store_open_options_t second_opts =
      encrypted_opts ("relative.store", &second);
  wyl_policy_store_t *other = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&second_opts, &other),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (second.probes, ==, 0);
  g_assert_cmpint (g_chdir (old_cwd), ==, 0);
  wyl_policy_store_close (store);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static gboolean
create_directory_alias (const gchar *target, const gchar *alias)
{
#ifdef G_OS_WIN32
  wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1, NULL, NULL,
      NULL);
  wchar_t *walias = (wchar_t *) g_utf8_to_utf16 (alias, -1, NULL, NULL, NULL);
  if (wtarget == NULL || walias == NULL) {
    g_free (wtarget);
    g_free (walias);
    return FALSE;
  }
  BOOL ok = CreateSymbolicLinkW (walias, wtarget, 0x1 | 0x2);
  if (!ok)
    ok = CreateSymbolicLinkW (walias, wtarget, 0x1);
  g_free (wtarget);
  g_free (walias);
  return ok;
#else
  return symlink (target, alias) == 0;
#endif
}

static gint
remove_directory_alias (const gchar *alias)
{
#ifdef G_OS_WIN32
  wchar_t *walias = (wchar_t *) g_utf8_to_utf16 (alias, -1, NULL, NULL, NULL);
  if (walias == NULL)
    return -1;
  BOOL ok = RemoveDirectoryW (walias);
  g_free (walias);
  return ok ? 0 : -1;
#else
  return g_remove (alias);
#endif
}

#ifndef G_OS_WIN32
typedef struct
{
  const gchar *alias;
  const gchar *replacement;
  gboolean swapped;
} SwapProvider;

static wyrelog_error_t
swap_probe (gpointer data)
{
  SwapProvider *provider = data;
  if (g_remove (provider->alias) != 0
      || !create_directory_alias (provider->replacement, provider->alias))
    return WYRELOG_E_IO;
  provider->swapped = TRUE;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
swap_derive (gpointer data, const gchar *label, guint8 *out, gsize out_len)
{
  SwapProvider *provider = data;
  if (!provider->swapped || label == NULL || out == NULL)
    return WYRELOG_E_INTERNAL;
  memset (out, 0x5a, out_len);
  return WYRELOG_E_OK;
}

static const wyl_keyprovider_vtable_t swap_vtable = {
  .probe = swap_probe,
  .derive = swap_derive,
};

static void
test_parent_alias_swap_stays_pinned (void)
{
  g_autofree gchar *root = make_tmpdir ();
  g_autofree gchar *dir_a = g_build_filename (root, "a", NULL);
  g_autofree gchar *dir_b = g_build_filename (root, "b", NULL);
  g_autofree gchar *alias = g_build_filename (root, "alias", NULL);
  g_assert_cmpint (g_mkdir (dir_a, 0700), ==, 0);
  g_assert_cmpint (g_mkdir (dir_b, 0700), ==, 0);
  g_assert_true (create_directory_alias (dir_a, alias));
  g_autofree gchar *alias_path = g_build_filename (alias, "policy.store",
      NULL);
  g_autofree gchar *path_a = g_build_filename (dir_a, "policy.store", NULL);
  g_autofree gchar *path_b = g_build_filename (dir_b, "policy.store", NULL);
  SwapProvider provider = {
    .alias = alias,
    .replacement = dir_b,
  };
  wyl_policy_store_open_options_t opts = {
    .path = alias_path,
    .keyprovider_vtable = &swap_vtable,
    .keyprovider_state = &provider,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_true (provider.swapped);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);

  g_assert_true (g_file_test (path_a, G_FILE_TEST_IS_REGULAR));
  assert_lock_stable (path_a);
  g_assert_false (g_file_test (path_b, G_FILE_TEST_EXISTS));
  g_autofree gchar *lock_b = g_strdup_printf ("%s%s", path_b, LOCK_SUFFIX);
  g_autofree gchar *clear_b = g_strdup_printf ("%s%s", path_b, CLEAR_SUFFIX);
  g_assert_false (g_file_test (lock_b, G_FILE_TEST_EXISTS));
  g_assert_false (g_file_test (clear_b, G_FILE_TEST_EXISTS));

  g_assert_cmpint (g_remove (alias), ==, 0);
  remove_store_files (path_a);
  g_assert_cmpint (g_rmdir (dir_a), ==, 0);
  g_assert_cmpint (g_rmdir (dir_b), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}
#endif

static void
test_parent_alias_identity (void)
{
  g_autofree gchar *root = make_tmpdir ();
  g_autofree gchar *real_dir = g_build_filename (root, "real", NULL);
  g_autofree gchar *alias_dir = g_build_filename (root, "alias", NULL);
  g_assert_cmpint (g_mkdir (real_dir, 0700), ==, 0);
  if (!create_directory_alias (real_dir, alias_dir)) {
    g_test_skip ("directory symlink creation is unavailable");
    g_assert_cmpint (g_rmdir (real_dir), ==, 0);
    g_assert_cmpint (g_rmdir (root), ==, 0);
    return;
  }
  g_autofree gchar *real_path = g_build_filename (real_dir, "policy.store",
      NULL);
  g_autofree gchar *alias_path = g_build_filename (alias_dir, "policy.store",
      NULL);
  CountingProvider first = { 0 };
  CountingProvider second = { 0 };
  wyl_policy_store_open_options_t first_opts = encrypted_opts (real_path,
      &first);
  wyl_policy_store_open_options_t second_opts = encrypted_opts (alias_path,
      &second);
  wyl_policy_store_t *store = NULL;
  wyl_policy_store_t *other = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&first_opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_open_with_options (&second_opts, &other),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (second.probes, ==, 0);
  wyl_policy_store_close (store);
  remove_store_files (real_path);
  g_assert_cmpint (remove_directory_alias (alias_dir), ==, 0);
  g_assert_cmpint (g_rmdir (real_dir), ==, 0);
  g_assert_cmpint (g_rmdir (root), ==, 0);
}

static void
test_providerless_plaintext_dual_open (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "plain.sqlite", NULL);
  wyl_policy_store_t *first = NULL;
  wyl_policy_store_t *second = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &first), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_open (path, &second), ==, WYRELOG_E_OK);
  wyl_policy_store_close (second);
  wyl_policy_store_close (first);
  wyl_policy_store_t *memory_a = NULL;
  wyl_policy_store_t *memory_b = NULL;
  g_assert_cmpint (wyl_policy_store_open (":memory:", &memory_a), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_open (":memory:", &memory_b), ==,
      WYRELOG_E_OK);
  wyl_policy_store_close (memory_b);
  wyl_policy_store_close (memory_a);
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", path, LOCK_SUFFIX);
  g_assert_false (g_file_test (lock_path, G_FILE_TEST_EXISTS));
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_plaintext_provider_is_leased (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "plain-provider.sqlite",
      NULL);
  CountingProvider first_provider = { 0 };
  CountingProvider second_provider = { 0 };
  wyl_policy_store_open_options_t first_opts = plaintext_provider_opts (path,
      &first_provider);
  wyl_policy_store_open_options_t second_opts = plaintext_provider_opts (path,
      &second_provider);
  wyl_policy_store_t *first = NULL;
  wyl_policy_store_t *second = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&first_opts, &first), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_open_with_options (&second_opts, &second),
      ==, WYRELOG_E_BUSY);
  wyl_policy_store_close (first);
  assert_lock_stable (path);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_early_error_releases_lease (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "early.store", NULL);
  wyl_policy_store_open_options_t invalid_opts = {
    .path = path,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&invalid_opts, &store),
      ==, WYRELOG_E_POLICY);
  CountingProvider provider = { 0 };
  wyl_policy_store_open_options_t valid_opts = encrypted_opts (path,
      &provider);
  g_assert_cmpint (wyl_policy_store_open_with_options (&valid_opts, &store), ==,
      WYRELOG_E_OK);
  wyl_policy_store_close (store);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static gboolean
create_file_alias (const gchar *target, const gchar *alias)
{
#ifdef G_OS_WIN32
  wchar_t *wtarget = (wchar_t *) g_utf8_to_utf16 (target, -1, NULL, NULL,
      NULL);
  wchar_t *walias = (wchar_t *) g_utf8_to_utf16 (alias, -1, NULL, NULL, NULL);
  if (wtarget == NULL || walias == NULL) {
    g_free (wtarget);
    g_free (walias);
    return FALSE;
  }
  BOOL ok = CreateSymbolicLinkW (walias, wtarget, 0x2);
  if (!ok)
    ok = CreateSymbolicLinkW (walias, wtarget, 0);
  g_free (wtarget);
  g_free (walias);
  return ok;
#else
  return symlink (target, alias) == 0;
#endif
}

static void
test_lock_symlink_rejected (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "linked.store", NULL);
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", path, LOCK_SUFFIX);
  g_autofree gchar *target = g_build_filename (dir, "target", NULL);
  g_assert_true (g_file_set_contents (target, "x", 1, NULL));
  if (!create_file_alias (target, lock_path)) {
    g_test_skip ("file symlink creation is unavailable");
  } else {
    CountingProvider provider = { 0 };
    wyl_policy_store_open_options_t opts = encrypted_opts (path, &provider);
    wyl_policy_store_t *store = NULL;
    g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
        WYRELOG_E_POLICY);
    g_assert_cmpuint (provider.probes, ==, 0);
    g_assert_cmpint (run_helper_exit (path), ==, 74);
    g_assert_cmpint (g_remove (lock_path), ==, 0);
  }
  g_assert_cmpint (g_remove (target), ==, 0);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

#ifndef G_OS_WIN32
static void
test_hardlink_contender_preserves_external_lock (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "owner.store", NULL);
  g_autofree gchar *alias_path = g_build_filename (dir, "alias.store", NULL);
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", path, LOCK_SUFFIX);
  g_autofree gchar *alias_lock = g_strdup_printf ("%s%s", alias_path,
      LOCK_SUFFIX);
  CountingProvider owner_provider = { 0 };
  wyl_policy_store_open_options_t owner_opts = encrypted_opts (path,
      &owner_provider);
  wyl_policy_store_t *owner = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&owner_opts, &owner), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (owner), ==, WYRELOG_E_OK);
  g_assert_cmpint (link (lock_path, alias_lock), ==, 0);

  CountingProvider contender_provider = { 0 };
  wyl_policy_store_open_options_t contender_opts = encrypted_opts (alias_path,
      &contender_provider);
  wyl_policy_store_t *contender = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&contender_opts,
          &contender), ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (contender_provider.probes, ==, 0);
  g_assert_cmpint (g_remove (alias_lock), ==, 0);
  g_assert_cmpint (run_helper_exit (path), ==, 73);

  wyl_policy_store_close (owner);
  g_assert_cmpint (run_helper_exit (path), ==, 0);
  remove_store_files (alias_path);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static void
test_precreated_malicious_hardlink_unchanged (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "victim.store", NULL);
  g_autofree gchar *lock_path = g_strdup_printf ("%s%s", path, LOCK_SUFFIX);
  g_autofree gchar *target = g_build_filename (dir, "operator-data", NULL);
  const gchar contents[] = "do-not-modify";
  g_assert_true (g_file_set_contents (target, contents, sizeof contents - 1,
          NULL));
  g_assert_cmpint (g_chmod (target, 0644), ==, 0);
  g_assert_cmpint (link (target, lock_path), ==, 0);

  OwnedProviderCounters counters = { 0 };
  OwnedProvider *provider = g_new0 (OwnedProvider, 1);
  provider->counters = &counters;
  wyl_policy_store_open_options_t opts = {
    .path = path,
    .keyprovider_vtable = &owned_vtable,
    .keyprovider_state = provider,
    .keyprovider_state_free = owned_free,
    .require_encrypted = TRUE,
  };
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_POLICY);
  g_assert_null (store);
  g_assert_cmpuint (counters.probes, ==, 0);
  g_assert_cmpuint (counters.seals, ==, 0);
  g_assert_cmpuint (counters.unseals, ==, 0);
  g_assert_cmpuint (counters.derives, ==, 0);
  g_assert_cmpuint (counters.wipes, ==, 1);
  g_assert_cmpuint (counters.frees, ==, 1);

  GStatBuf statbuf;
  g_assert_cmpint (g_stat (target, &statbuf), ==, 0);
  g_assert_cmpuint (statbuf.st_mode & 0777, ==, 0644);
  gchar *actual = NULL;
  gsize actual_len = 0;
  g_assert_true (g_file_get_contents (target, &actual, &actual_len, NULL));
  g_assert_cmpuint (actual_len, ==, sizeof contents - 1);
  g_assert_cmpmem (actual, actual_len, contents, sizeof contents - 1);
  g_free (actual);

  g_assert_cmpint (g_remove (lock_path), ==, 0);
  g_assert_cmpint (g_remove (target), ==, 0);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

static gint
fork_exec_helper (const gchar *path)
{
  pid_t child = fork ();
  g_assert_cmpint (child, >=, 0);
  if (child == 0) {
    char *const argv[] = { test_lease_self_path, (char *) LEASE_HELPER_ARG,
      (char *) path, (char *) "--oneshot", NULL
    };
    execve (test_lease_self_path, argv, environ);
    _exit (74);
  }
  int status = 0;
  g_assert_cmpint (waitpid (child, &status, 0), ==, child);
  g_assert_true (WIFEXITED (status));
  return WEXITSTATUS (status);
}

static void
test_fork_exec_policy (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "fork.store", NULL);
  CountingProvider provider = { 0 };
  wyl_policy_store_open_options_t opts = encrypted_opts (path, &provider);
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&opts, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  g_assert_cmpint (fork_exec_helper (path), ==, 73);
  g_assert_cmpint (fork_exec_helper (path), ==, 73);
  wyl_policy_store_close (store);
  g_assert_cmpint (fork_exec_helper (path), ==, 0);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}
#endif

static GSubprocess *
spawn_holder (const gchar *path, GDataInputStream **out_stdout)
{
  const gchar *argv[] = { test_lease_self_path, LEASE_HELPER_ARG, path,
    NULL
  };
  GError *error = NULL;
  GSubprocess *process = g_subprocess_newv (argv,
      G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE
      | G_SUBPROCESS_FLAGS_STDERR_PIPE, &error);
  g_assert_no_error (error);
  g_assert_nonnull (process);
  *out_stdout =
      g_data_input_stream_new (g_subprocess_get_stdout_pipe (process));
  gsize len = 0;
  gchar *line = g_data_input_stream_read_line (*out_stdout, &len, NULL, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (line, ==, "READY");
  g_free (line);
  return process;
}

static void
test_subprocess_busy_crash_and_reacquire (void)
{
  g_autofree gchar *dir = make_tmpdir ();
  g_autofree gchar *path = g_build_filename (dir, "process.store", NULL);
  CountingProvider seed_provider = { 0 };
  wyl_policy_store_open_options_t seed_opts = encrypted_opts (path,
      &seed_provider);
  wyl_policy_store_t *seed_store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&seed_opts, &seed_store),
      ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (seed_store), ==,
      WYRELOG_E_OK);
  wyl_policy_store_close (seed_store);
  gchar *before = NULL;
  gsize before_len = 0;
  g_assert_true (g_file_get_contents (path, &before, &before_len, NULL));

  GDataInputStream *holder_stdout = NULL;
  GSubprocess *holder = spawn_holder (path, &holder_stdout);
  CountingProvider busy_provider = { 0 };
  wyl_policy_store_open_options_t busy_opts = encrypted_opts (path,
      &busy_provider);
  wyl_policy_store_t *busy_store = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&busy_opts, &busy_store),
      ==, WYRELOG_E_BUSY);
  g_assert_cmpuint (busy_provider.probes, ==, 0);
  gchar *during = NULL;
  gsize during_len = 0;
  g_assert_true (g_file_get_contents (path, &during, &during_len, NULL));
  g_assert_cmpuint (during_len, ==, before_len);
  g_assert_cmpmem (during, during_len, before, before_len);
  g_free (during);

  g_subprocess_force_exit (holder);
  GError *error = NULL;
  g_assert_true (g_subprocess_wait (holder, NULL, &error));
  g_assert_no_error (error);
  g_clear_object (&holder_stdout);
  g_clear_object (&holder);

  CountingProvider reopen_provider = { 0 };
  wyl_policy_store_open_options_t reopen_opts = encrypted_opts (path,
      &reopen_provider);
  wyl_policy_store_t *reopened = NULL;
  g_assert_cmpint (wyl_policy_store_open_with_options (&reopen_opts, &reopened),
      ==, WYRELOG_E_OK);
  wyl_policy_store_close (reopened);
  assert_lock_stable (path);
  g_free (before);
  remove_store_files (path);
  g_assert_cmpint (g_rmdir (dir), ==, 0);
}

int
main (int argc, char **argv)
{
  if (argc < 1 || argv == NULL || argv[0] == NULL || argv[0][0] == '\0')
    g_error ("policy-store lease test has no executable path");
  if (argc >= 2 && g_strcmp0 (argv[1], LEASE_HELPER_ARG) == 0)
    return lease_helper_main (argc, argv);

  test_lease_self_path = g_canonicalize_filename (argv[0], NULL);
  if (test_lease_self_path == NULL || !g_path_is_absolute (test_lease_self_path)
      || !g_file_test (test_lease_self_path, G_FILE_TEST_IS_REGULAR))
    g_error ("policy-store lease test executable path is invalid");

  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/policy-store-lease/same-process-different-paths",
      test_same_process_and_different_paths);
  g_test_add_func ("/policy-store-lease/relative-absolute",
      test_relative_absolute_identity);
  g_test_add_func ("/policy-store-lease/parent-alias",
      test_parent_alias_identity);
  g_test_add_func ("/policy-store-lease/providerless-plaintext",
      test_providerless_plaintext_dual_open);
  g_test_add_func ("/policy-store-lease/plaintext-provider",
      test_plaintext_provider_is_leased);
  g_test_add_func ("/policy-store-lease/early-error-release",
      test_early_error_releases_lease);
  g_test_add_func ("/policy-store-lease/lock-symlink",
      test_lock_symlink_rejected);
  g_test_add_func ("/policy-store-lease/subprocess-crash",
      test_subprocess_busy_crash_and_reacquire);
#ifndef G_OS_WIN32
  g_test_add_func ("/policy-store-lease/parent-alias-swap",
      test_parent_alias_swap_stays_pinned);
  g_test_add_func ("/policy-store-lease/hardlink-contender",
      test_hardlink_contender_preserves_external_lock);
  g_test_add_func ("/policy-store-lease/malicious-hardlink",
      test_precreated_malicious_hardlink_unchanged);
  g_test_add_func ("/policy-store-lease/fork-exec-policy",
      test_fork_exec_policy);
#endif
  int rc = g_test_run ();
  g_clear_pointer (&test_lease_self_path, g_free);
  return rc;
}
