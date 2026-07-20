/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Tests for the `wyctl key status --store' recovery probe and the
 * `wyctl key recover' (alias `resume') crash-recovery subcommand
 * (issue #364 PR2).
 *
 * These are thin CLI-delegation checks: the wyctl binary is driven as a
 * subprocess against an encrypted policy store on disk, using the file
 * KeyProvider spec form (`file:PATH').  The library rotation crash seam
 * (wyl_policy_store_rotation_runtime_t.checkpoint) is used in-process to
 * fabricate two on-disk states:
 *   - a clean freshly-rotated NEW store (rotate old -> new, no fault), and
 *   - an interrupted OLD+PENDING store (rotate aborted at a pre-
 *     linearization seam so the canonical stays byte-for-byte old and a
 *     pending rotation-intent sidecar is left behind).
 *
 * The subcommands run offline against those stores.  We assert the
 * rendered non-secret `key=value' lines, the exit-code contract
 * (0 ok / 1 failure / 2 usage), idempotent recovery, the fail-closed
 * ambiguous path, and secret hygiene (the raw 32-byte provider key bytes
 * never appear in captured stdout+stderr).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <sodium.h>
#include <string.h>
#include <sys/wait.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-keyprovider-file-private.h"

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

#define KEY_BYTES 32

/* ------------------------------------------------------------------ */
/* Store / keyprovider fixture helpers.                               */
/* ------------------------------------------------------------------ */

/* Write a deterministic 32-byte policy key file. */
static void
write_policy_key (const gchar *path, guint8 seed)
{
  guint8 key[KEY_BYTES];
  for (gsize i = 0; i < sizeof key; i++)
    key[i] = (guint8) (seed + i);
  g_assert_true (g_file_set_contents (path, (const gchar *) key, sizeof key,
          NULL));
}

static wyrelog_error_t
open_encrypted (const gchar *store_path, const gchar *key_path,
    wyl_policy_store_t **out_store)
{
  wyl_keyprovider_file_t *keyprovider = wyl_keyprovider_file_new (key_path);
  if (keyprovider == NULL)
    return WYRELOG_E_IO;
  wyl_policy_store_open_options_t opts = {
    .path = store_path,
    .keyprovider_vtable = wyl_keyprovider_file_get_vtable (),
    .keyprovider_state = keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_open_with_options (&opts, out_store);
}

/* Create a fresh encrypted store sealed under `key_path' and establish a
 * service CVK.  The recovery probe classifies a retained root by unsealing and
 * validating its service CVK under the provider, so the store must carry one;
 * a NULL service_cvk_runtime falls back to the libsodium default runtime, the
 * same path wyctl exercises. */
static void
create_encrypted_store (const gchar *store_path, const gchar *key_path)
{
  wyl_policy_store_t *store = NULL;
  g_assert_cmpint (open_encrypted (store_path, key_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  const guint8 *cvk = NULL;
  gsize cvk_len = 0;
  g_assert_cmpint (wyl_policy_store_ensure_service_cvk_for_issuance (store,
          &cvk, &cvk_len), ==, WYRELOG_E_OK);
  wyl_policy_store_close (store);
}

typedef struct
{
  wyl_policy_store_rotation_stage_t fail_stage;
} RotationFault;

static int
rotation_checkpoint (gpointer data, wyl_policy_store_rotation_stage_t stage)
{
  const RotationFault *fault = data;
  return fault->fail_stage == stage ? -1 : 0;
}

/* Rotate the store key from `old_key_path' to `new_key_path'.  When
 * `fault_stage' is nonzero, abort the rotation inside the checkpoint at that
 * seam.  Returns the library rc. */
static wyrelog_error_t
rotate_store (const gchar *store_path, const gchar *old_key_path,
    const gchar *new_key_path, wyl_policy_store_rotation_stage_t fault_stage)
{
  wyl_keyprovider_file_t *old_keyprovider =
      wyl_keyprovider_file_new (old_key_path);
  if (old_keyprovider == NULL)
    return WYRELOG_E_IO;
  wyl_keyprovider_file_t *new_keyprovider =
      wyl_keyprovider_file_new (new_key_path);
  if (new_keyprovider == NULL) {
    wyl_keyprovider_file_free (old_keyprovider);
    return WYRELOG_E_IO;
  }
  const wyl_keyprovider_vtable_t *vt = wyl_keyprovider_file_get_vtable ();
  RotationFault fault = {.fail_stage = fault_stage };
  wyl_policy_store_rotation_runtime_t rotation_runtime = {
    .checkpoint = rotation_checkpoint,
    .data = &fault,
  };
  wyl_policy_store_open_options_t old_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = old_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
    .rotation_runtime = fault_stage != 0 ? &rotation_runtime : NULL,
  };
  wyl_policy_store_open_options_t new_opts = {
    .keyprovider_vtable = vt,
    .keyprovider_state = new_keyprovider,
    .keyprovider_state_free = (void (*)(gpointer)) wyl_keyprovider_file_free,
    .require_encrypted = TRUE,
  };
  return wyl_policy_store_rotate_keyprovider (store_path, &old_opts, &new_opts);
}

static gchar *
file_spec (const gchar *path)
{
  return g_strdup_printf ("file:%s", path);
}

/* ------------------------------------------------------------------ */
/* Subprocess drive + key=value extraction.                           */
/* ------------------------------------------------------------------ */

/* Extract the value of a `key=value' record occupying the whole (single-pair)
 * line in `text', returning a freshly allocated string (or NULL on miss).
 * Values are terminated by the next space or newline so multi-pair lines are
 * not consumed wholesale. */
static gchar *
extract_kv (const gchar *text, const gchar *key)
{
  gsize key_len = strlen (key);
  for (const gchar * p = text; *p != '\0';) {
    const gchar *line_end = strchr (p, '\n');
    gsize line_len = (line_end == NULL) ? strlen (p) : (gsize) (line_end - p);
    if (line_len > key_len + 1 && p[key_len] == '='
        && memcmp (p, key, key_len) == 0) {
      const gchar *value = p + key_len + 1;
      gsize value_len = line_len - key_len - 1;
      const gchar *space = memchr (value, ' ', value_len);
      if (space != NULL)
        value_len = (gsize) (space - value);
      return g_strndup (value, value_len);
    }
    if (line_end == NULL)
      break;
    p = line_end + 1;
  }
  return NULL;
}

/* Drive `wyctl key <subcommand> --store STORE --from-keyprovider FROM
 * --to-keyprovider TO' and return the child exit code (or -1 if it did not
 * exit normally).  Captured stdout/stderr are returned via the out params. */
static gint
run_wyctl_key (const gchar *subcommand, const gchar *store,
    const gchar *from_spec, const gchar *to_spec, gchar **out, gchar **err)
{
  gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "key",
    (gchar *) subcommand,
    "--store", (gchar *) store,
    "--from-keyprovider", (gchar *) from_spec,
    "--to-keyprovider", (gchar *) to_spec,
    NULL,
  };
  g_autoptr (GError) error = NULL;
  gint wait_status = 0;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          out, err, &wait_status, &error));
  g_assert_no_error (error);
  if (WIFEXITED (wait_status))
    return WEXITSTATUS (wait_status);
  return -1;
}

/* Drive wyctl with an explicit argv (already including the wyctl path). */
static gint
run_wyctl_argv (gchar **argv, gchar **out, gchar **err)
{
  g_autoptr (GError) error = NULL;
  gint wait_status = 0;
  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          out, err, &wait_status, &error));
  g_assert_no_error (error);
  if (WIFEXITED (wait_status))
    return WEXITSTATUS (wait_status);
  return -1;
}

static gboolean
bytes_contained (const gchar *haystack, gsize haystack_len,
    const guint8 *needle, gsize needle_len)
{
  if (needle_len == 0 || haystack_len < needle_len)
    return FALSE;
  for (gsize i = 0; i + needle_len <= haystack_len; i++) {
    if (memcmp (haystack + i, needle, needle_len) == 0)
      return TRUE;
  }
  return FALSE;
}

/* ------------------------------------------------------------------ */
/* Fixture: a tmp dir holding the store and old/new key files.        */
/* ------------------------------------------------------------------ */

typedef struct
{
  gchar *dir;
  gchar *store;
  gchar *old_key;
  gchar *new_key;
  gchar *old_spec;
  gchar *new_spec;
} KeyFixture;

static void
key_fixture_init (KeyFixture *fx)
{
  fx->dir = g_dir_make_tmp ("wyctl-key-XXXXXX", NULL);
  g_assert_nonnull (fx->dir);
  fx->store = g_build_filename (fx->dir, "policy.store", NULL);
  fx->old_key = g_build_filename (fx->dir, "old.key", NULL);
  fx->new_key = g_build_filename (fx->dir, "new.key", NULL);
  write_policy_key (fx->old_key, 0x10);
  write_policy_key (fx->new_key, 0x60);
  fx->old_spec = file_spec (fx->old_key);
  fx->new_spec = file_spec (fx->new_key);
}

static void
key_fixture_clear (KeyFixture *fx)
{
  g_autofree gchar *sidecar =
      g_strconcat (fx->store, ".wyrelog-rotation-intent", NULL);
  g_autofree gchar *lock = g_strconcat (fx->store, ".wyrelog-lock", NULL);
  (void) g_remove (sidecar);
  (void) g_remove (lock);
  (void) g_remove (fx->store);
  (void) g_remove (fx->old_key);
  (void) g_remove (fx->new_key);
  (void) g_rmdir (fx->dir);
  g_clear_pointer (&fx->dir, g_free);
  g_clear_pointer (&fx->store, g_free);
  g_clear_pointer (&fx->old_key, g_free);
  g_clear_pointer (&fx->new_key, g_free);
  g_clear_pointer (&fx->old_spec, g_free);
  g_clear_pointer (&fx->new_spec, g_free);
}

/* ------------------------------------------------------------------ */
/* Tests.                                                             */
/* ------------------------------------------------------------------ */

/* (1) status on a clean freshly-rotated (NEW) store. */
static void
test_key_status_new (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key, 0), ==,
      WYRELOG_E_OK);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("status", fx.store, fx.old_spec, fx.new_spec,
      &out, &err);
  if (rc != 0)
    g_printerr ("status-new stderr: %s\n", err);
  g_assert_cmpint (rc, ==, 0);

  g_autofree gchar *state = extract_kv (out, "state");
  g_autofree gchar *action = extract_kv (out, "safe-next-action");
  g_autofree gchar *retire = extract_kv (out, "retire-old-root");
  g_autofree gchar *roots = extract_kv (out, "required-roots");
  g_assert_cmpstr (state, ==, "new");
  g_assert_cmpstr (action, ==, "none");
  g_assert_cmpstr (retire, ==, "yes");
  /* A fully-rotated store is sealed under the new provider: the operator must
   * retain the NEW root, never the old one that can no longer open it. */
  g_assert_cmpstr (roots, ==, "new");

  key_fixture_clear (&fx);
}

/* (2) status on an interrupted (OLD+PENDING) store. */
static void
test_key_status_interrupted (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  /* Abort before the canonical rename: the store stays old-encrypted and a
   * pending rotation-intent sidecar is left behind. */
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME), ==, WYRELOG_E_IO);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("status", fx.store, fx.old_spec, fx.new_spec,
      &out, &err);
  if (rc != 0)
    g_printerr ("status-interrupted stderr: %s\n", err);
  g_assert_cmpint (rc, ==, 0);

  g_autofree gchar *state = extract_kv (out, "state");
  g_autofree gchar *intent = extract_kv (out, "intent-state");
  g_autofree gchar *action = extract_kv (out, "safe-next-action");
  g_autofree gchar *txn = extract_kv (out, "transaction-id");
  g_autofree gchar *roots = extract_kv (out, "required-roots");
  g_assert_cmpstr (state, ==, "old");
  g_assert_cmpstr (intent, ==, "pending");
  g_assert_cmpstr (action, ==, "resume-old");
  g_assert_nonnull (txn);
  g_assert_cmpuint (strlen (txn), >, 0);
  /* resume-old still needs both retained roots to re-run the rotation. */
  g_assert_cmpstr (roots, ==, "both");

  key_fixture_clear (&fx);
}

/* (2b) status on a settled store with no rotation in flight: OLD+ABSENT keeps
 * the old root (required-roots=old) and does not offer to retire it. */
static void
test_key_status_clean_old (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("status", fx.store, fx.old_spec, fx.new_spec,
      &out, &err);
  if (rc != 0)
    g_printerr ("status-clean-old stderr: %s\n", err);
  g_assert_cmpint (rc, ==, 0);

  g_autofree gchar *state = extract_kv (out, "state");
  g_autofree gchar *intent = extract_kv (out, "intent-state");
  g_autofree gchar *action = extract_kv (out, "safe-next-action");
  g_autofree gchar *roots = extract_kv (out, "required-roots");
  g_autofree gchar *retire = extract_kv (out, "retire-old-root");
  g_assert_cmpstr (state, ==, "old");
  g_assert_cmpstr (intent, ==, "absent");
  g_assert_cmpstr (action, ==, "none");
  g_assert_cmpstr (roots, ==, "old");
  g_assert_cmpstr (retire, ==, "no");

  key_fixture_clear (&fx);
}

/* (3) recover on the interrupted store converges to NEW and is idempotent. */
static void
test_key_recover_converges_and_idempotent (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME), ==, WYRELOG_E_IO);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("recover", fx.store, fx.old_spec, fx.new_spec,
      &out, &err);
  if (rc != 0)
    g_printerr ("recover stderr: %s\n", err);
  g_assert_cmpint (rc, ==, 0);
  g_autofree gchar *status = extract_kv (out, "status");
  g_assert_cmpstr (status, ==, "recovered");

  /* status now reports a clean new root. */
  g_autofree gchar *sout = NULL;
  g_autofree gchar *serr = NULL;
  g_assert_cmpint (run_wyctl_key ("status", fx.store, fx.old_spec, fx.new_spec,
          &sout, &serr), ==, 0);
  g_autofree gchar *state = extract_kv (sout, "state");
  g_assert_cmpstr (state, ==, "new");

  /* recover again: idempotent no-op, still exit 0. */
  g_autofree gchar *out2 = NULL;
  g_autofree gchar *err2 = NULL;
  gint rc2 = run_wyctl_key ("recover", fx.store, fx.old_spec, fx.new_spec,
      &out2, &err2);
  if (rc2 != 0)
    g_printerr ("recover-again stderr: %s\n", err2);
  g_assert_cmpint (rc2, ==, 0);
  g_autofree gchar *status2 = extract_kv (out2, "status");
  g_assert_cmpstr (status2, ==, "recovered");

  key_fixture_clear (&fx);
}

/* (3b) the `resume' alias routes to the same recover path. */
static void
test_key_resume_alias (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME), ==, WYRELOG_E_IO);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("resume", fx.store, fx.old_spec, fx.new_spec,
      &out, &err);
  if (rc != 0)
    g_printerr ("resume stderr: %s\n", err);
  g_assert_cmpint (rc, ==, 0);
  g_autofree gchar *status = extract_kv (out, "status");
  g_assert_cmpstr (status, ==, "recovered");

  key_fixture_clear (&fx);
}

/* (4) recover with a from-keyprovider that authenticates neither root fails
 * closed (ambiguous) with exit 1 and the documented message. */
static void
test_key_recover_fail_closed_ambiguous (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);

  /* A syntactically-valid but wrong 32-byte key: readable (passes preflight)
   * yet authenticates nothing. */
  g_autofree gchar *wrong_key = g_build_filename (fx.dir, "wrong.key", NULL);
  write_policy_key (wrong_key, 0xA0);
  g_autofree gchar *wrong_spec = file_spec (wrong_key);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;
  gint rc = run_wyctl_key ("recover", fx.store, wrong_spec, fx.new_spec,
      &out, &err);
  g_assert_cmpint (rc, ==, 1);
  g_assert_nonnull (g_strstr_len (err, -1, "wyctl: key recovery fail-closed:"));
  g_assert_nonnull (g_strstr_len (err, -1, "operator action required"));

  (void) g_remove (wrong_key);
  key_fixture_clear (&fx);
}

/* (5) usage and unreadable-spec exit codes. */
static void
test_key_usage_and_unreadable (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key, 0), ==,
      WYRELOG_E_OK);

  g_autofree gchar *out = NULL;
  g_autofree gchar *err = NULL;

  /* status --store without --from-keyprovider -> usage exit 2. */
  {
    gchar *argv[] = {
      WYL_TEST_WYCTL_PATH, "key", "status", "--store", fx.store,
      "--to-keyprovider", fx.new_spec, NULL,
    };
    gint rc = run_wyctl_argv (argv, &out, &err);
    g_assert_cmpint (rc, ==, 2);
    g_assert_nonnull (g_strstr_len (err, -1,
            "wyctl: missing --from-keyprovider"));
  }

  /* recover missing --to-keyprovider -> usage exit 2. */
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  {
    gchar *argv[] = {
      WYL_TEST_WYCTL_PATH, "key", "recover", "--store", fx.store,
      "--from-keyprovider", fx.old_spec, NULL,
    };
    gint rc = run_wyctl_argv (argv, &out, &err);
    g_assert_cmpint (rc, ==, 2);
    g_assert_nonnull (g_strstr_len (err, -1,
            "wyctl: missing --to-keyprovider"));
  }

  /* recover missing --store -> usage exit 2. */
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  {
    gchar *argv[] = {
      WYL_TEST_WYCTL_PATH, "key", "recover",
      "--from-keyprovider", fx.old_spec, "--to-keyprovider", fx.new_spec, NULL,
    };
    gint rc = run_wyctl_argv (argv, &out, &err);
    g_assert_cmpint (rc, ==, 2);
    g_assert_nonnull (g_strstr_len (err, -1, "wyctl: missing --store"));
  }

  /* unreadable keyprovider spec -> exit 1. */
  g_clear_pointer (&out, g_free);
  g_clear_pointer (&err, g_free);
  {
    g_autofree gchar *missing = g_build_filename (fx.dir, "no-such-key", NULL);
    g_autofree gchar *missing_spec = file_spec (missing);
    gint rc = run_wyctl_key ("status", fx.store, missing_spec, fx.new_spec,
        &out, &err);
    g_assert_cmpint (rc, ==, 1);
    g_assert_nonnull (g_strstr_len (err, -1, "keyprovider unreadable"));
  }

  key_fixture_clear (&fx);
}

/* (6) secret hygiene: the raw 32-byte provider key bytes must never appear in
 * captured stdout+stderr of a status or recover run. */
static void
test_key_secret_hygiene (void)
{
  KeyFixture fx;
  key_fixture_init (&fx);
  create_encrypted_store (fx.store, fx.old_key);
  g_assert_cmpint (rotate_store (fx.store, fx.old_key, fx.new_key,
          WYL_POLICY_ROTATION_BEFORE_CANONICAL_RENAME), ==, WYRELOG_E_IO);

  guint8 old_bytes[KEY_BYTES];
  guint8 new_bytes[KEY_BYTES];
  gsize len = 0;
  g_autofree gchar *old_raw = NULL;
  g_autofree gchar *new_raw = NULL;
  g_assert_true (g_file_get_contents (fx.old_key, &old_raw, &len, NULL));
  g_assert_cmpuint (len, ==, KEY_BYTES);
  memcpy (old_bytes, old_raw, KEY_BYTES);
  g_assert_true (g_file_get_contents (fx.new_key, &new_raw, &len, NULL));
  g_assert_cmpuint (len, ==, KEY_BYTES);
  memcpy (new_bytes, new_raw, KEY_BYTES);

  g_autoptr (GString) captured = g_string_new (NULL);

  /* status run. */
  g_autofree gchar *sout = NULL;
  g_autofree gchar *serr = NULL;
  g_assert_cmpint (run_wyctl_key ("status", fx.store, fx.old_spec, fx.new_spec,
          &sout, &serr), ==, 0);
  g_string_append (captured, sout);
  g_string_append (captured, serr);

  /* recover run. */
  g_autofree gchar *rout = NULL;
  g_autofree gchar *rerr = NULL;
  g_assert_cmpint (run_wyctl_key ("recover", fx.store, fx.old_spec, fx.new_spec,
          &rout, &rerr), ==, 0);
  g_string_append (captured, rout);
  g_string_append (captured, rerr);

  g_assert_false (bytes_contained (captured->str, captured->len, old_bytes,
          KEY_BYTES));
  g_assert_false (bytes_contained (captured->str, captured->len, new_bytes,
          KEY_BYTES));

  key_fixture_clear (&fx);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/wyctl/key/status-new", test_key_status_new);
  g_test_add_func ("/wyctl/key/status-interrupted",
      test_key_status_interrupted);
  g_test_add_func ("/wyctl/key/status-clean-old", test_key_status_clean_old);
  g_test_add_func ("/wyctl/key/recover-converges-and-idempotent",
      test_key_recover_converges_and_idempotent);
  g_test_add_func ("/wyctl/key/resume-alias", test_key_resume_alias);
  g_test_add_func ("/wyctl/key/recover-fail-closed-ambiguous",
      test_key_recover_fail_closed_ambiguous);
  g_test_add_func ("/wyctl/key/usage-and-unreadable",
      test_key_usage_and_unreadable);
  g_test_add_func ("/wyctl/key/secret-hygiene", test_key_secret_hygiene);

  return g_test_run ();
}
