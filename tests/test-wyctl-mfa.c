/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Tests for the wyctl mfa enroll/reset subcommands (issue #331 commit 6).
 *
 * The subcommands run offline against a policy store file: there is no
 * daemon round-trip and no bearer token.  Each test spins up a fresh
 * unencrypted SQLite policy store, then drives the wyctl binary as a
 * subprocess with --store pointing at that file.  The base32 secret
 * the operator would type into an authenticator is printed to stdout
 * during enroll, so the harness:
 *   1. spawns wyctl with stdout / stdin pipes
 *   2. reads stdout until it sees the `secret_base32=...' line
 *   3. computes the matching 6-digit TOTP code with wyl_totp_code_at_step
 *   4. writes the code to stdin and closes it
 *   5. waits for wyctl to exit and asserts the enrollment row landed
 *
 * Footgun coverage these tests lock down (mirrors the architect brief):
 *   - Abort paths do not write any enrollment row (atomic-enroll
 *     contract).
 *   - Reset path leaves the subject unenrolled when the second prompt
 *     is aborted (documented contract: the prior enrollment was deleted
 *     before the new one was attempted).
 *   - Bootstrap auto-revoke removes the wr.login.skip_mfa direct
 *     permission for the bootstrap admin on first successful enroll,
 *     and does NOT fire for non-bootstrap subjects.
 *   - otpauth URI percent-encodes subjects that contain ':' or '/'.
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <sqlite3.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "auth/totp.h"

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH is required"
#endif

#define WYL_TEST_LOGIN_SKIP_MFA_PERMISSION "wr.login.skip_mfa"
#define WYL_TEST_LOGIN_SKIP_MFA_SCOPE "login"

/* Read from `stream' until either |needle| is seen at the start of a
 * line or EOF is reached.  Captured bytes are appended to `acc'.  Returns
 * the position of the first byte AFTER the matched newline, or -1 on
 * EOF without a match. */
static gssize
read_until_line_prefix (GInputStream *stream, GString *acc, const gchar *prefix)
{
  gsize prefix_len = strlen (prefix);
  /* Scan whatever we already accumulated first so callers that picked
   * up the marker from a previous read are short-circuited. */
  for (;;) {
    const gchar *line_start = acc->str;
    for (gsize i = 0; i + prefix_len <= acc->len; i++) {
      if ((i == 0 || acc->str[i - 1] == '\n')
          && memcmp (acc->str + i, prefix, prefix_len) == 0) {
        /* Find the newline terminating this line. */
        for (gsize j = i + prefix_len; j < acc->len; j++) {
          if (acc->str[j] == '\n')
            return (gssize) (j + 1);
        }
        /* No newline yet: keep reading. */
        break;
      }
      (void) line_start;
    }

    gchar buf[256];
    g_autoptr (GError) error = NULL;
    gssize n = g_input_stream_read (stream, buf, sizeof buf, NULL, &error);
    if (n < 0) {
      g_clear_error (&error);
      return -1;
    }
    if (n == 0)
      return -1;
    g_string_append_len (acc, buf, n);
  }
}

/* Drain stream to EOF, appending to acc. */
static void
read_to_eof (GInputStream *stream, GString *acc)
{
  for (;;) {
    gchar buf[512];
    g_autoptr (GError) error = NULL;
    gssize n = g_input_stream_read (stream, buf, sizeof buf, NULL, &error);
    if (n <= 0) {
      g_clear_error (&error);
      return;
    }
    g_string_append_len (acc, buf, n);
  }
}

/* Extract the value of a `key=value' record in `text', returning a
 * freshly allocated string (or NULL on miss). */
static gchar *
extract_kv (const gchar *text, const gchar *key)
{
  gsize key_len = strlen (key);
  for (const gchar * p = text; *p != '\0';) {
    const gchar *line_end = strchr (p, '\n');
    gsize line_len = (line_end == NULL) ? strlen (p) : (gsize) (line_end - p);
    if (line_len > key_len + 1 && p[key_len] == '='
        && memcmp (p, key, key_len) == 0) {
      return g_strndup (p + key_len + 1, line_len - key_len - 1);
    }
    if (line_end == NULL)
      break;
    p = line_end + 1;
  }
  return NULL;
}

/* Create a fresh empty SQLite policy store at `path' with the standard
 * schema. */
static void
create_empty_store (const gchar *path)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (path, &store), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
}

/* Open a store at `path' and run a fact-emitting callback under a
 * sealed shell. */
static gboolean
lookup_enrollment (const gchar *store_path, const gchar *subject,
    WylTotpEnrollment *out)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (store_path, &store) != WYRELOG_E_OK)
    return FALSE;
  gboolean found = FALSE;
  if (wyl_policy_store_totp_enrollment_lookup (store, subject, out, &found)
      != WYRELOG_E_OK)
    return FALSE;
  return found;
}

static gboolean
direct_perm_exists (const gchar *store_path, const gchar *subject,
    const gchar *perm, const gchar *scope)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  if (wyl_policy_store_open (store_path, &store) != WYRELOG_E_OK)
    return FALSE;
  gboolean exists = FALSE;
  if (wyl_policy_store_direct_permission_exists (store, subject, perm, scope,
          &exists) != WYRELOG_E_OK)
    return FALSE;
  return exists;
}

/* Pre-seal the policy store as if --bootstrap-admin-subject=<subject>
 * --bootstrap-admin-allow-skip-mfa had been applied by the daemon. */
static void
seal_bootstrap_admin (const gchar *store_path, const gchar *subject,
    gboolean allow_skip_mfa)
{
  g_autoptr (wyl_policy_store_t) store = NULL;
  g_assert_cmpint (wyl_policy_store_open (store_path, &store), ==,
      WYRELOG_E_OK);
  g_assert_cmpint (wyl_policy_store_create_schema (store), ==, WYRELOG_E_OK);
  gboolean applied = FALSE;
  g_autofree gchar *existing = NULL;
  g_assert_cmpint (wyl_policy_store_apply_bootstrap_admin (store, subject,
          allow_skip_mfa, &applied, &existing), ==, WYRELOG_E_OK);
  g_assert_true (applied);
}

/* What kind of input to feed to wyctl on stdin once the secret has
 * been printed.  EOF aborts the prompt; VALID computes and writes the
 * matching TOTP code; OVERRIDE writes whatever literal string the
 * caller supplied (used to force "wrong-code" paths); PERTURB computes
 * the valid code and then deterministically changes one digit so the
 * code is guaranteed wrong, eliminating the 1-in-10^6 false-pass
 * window of a fixed override like "000000". */
typedef enum
{
  WYCTL_TEST_FEED_EOF = 0,
  WYCTL_TEST_FEED_VALID = 1,
  WYCTL_TEST_FEED_OVERRIDE = 2,
  WYCTL_TEST_FEED_PERTURB = 3,
} WyctlTestFeedMode;

/* Spawn `wyctl' with the supplied argv (already including the wyctl
 * path as argv[0]) and `envp' (NULL to inherit) and drive the TOTP
 * stdin handshake using `mode'.  Factored out of `run_wyctl_mfa' so
 * the GSettings-fallback tests in this file can build their own argv
 * (with no `--store') and pass a custom envp that points GSettings at
 * a keyfile fixture. */
static gint
run_wyctl_mfa_argv_env (const gchar *const *argv, gchar **envp,
    WyctlTestFeedMode mode, const gchar *override_code,
    GString *stdout_acc, GString *stderr_acc)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GSubprocessLauncher) launcher =
      g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDIN_PIPE
      | G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE);
  if (envp != NULL)
    g_subprocess_launcher_set_environ (launcher, envp);
  g_autoptr (GSubprocess) sub =
      g_subprocess_launcher_spawnv (launcher, argv, &error);
  g_assert_no_error (error);
  g_assert_nonnull (sub);

  GInputStream *stdout_pipe = g_subprocess_get_stdout_pipe (sub);
  GOutputStream *stdin_pipe = g_subprocess_get_stdin_pipe (sub);

  /* Read stdout until the `secret_base32=' line so we know wyctl has
   * printed the secret and is about to block on stdin. */
  gssize after = read_until_line_prefix (stdout_pipe, stdout_acc,
      "secret_base32=");
  if (after >= 0 && mode != WYCTL_TEST_FEED_EOF) {
    const gchar *code = NULL;
    g_autofree gchar *computed = NULL;
    if (mode == WYCTL_TEST_FEED_OVERRIDE) {
      g_assert_nonnull (override_code);
      code = override_code;
    } else {
      /* VALID and PERTURB both need the secret-derived code. */
      g_autofree gchar *secret_b32 = extract_kv (stdout_acc->str,
          "secret_base32");
      g_assert_nonnull (secret_b32);
      g_autofree guint8 *seed = NULL;
      gsize seed_len = 0;
      g_autoptr (GError) dec_error = NULL;
      g_assert_cmpint (wyl_totp_base32_decode (secret_b32, &seed, &seed_len,
              &dec_error), ==, WYRELOG_E_OK);
      g_assert_cmpuint (seed_len, ==, WYL_TOTP_SEED_BYTES);
      guint64 step = (guint64) (g_get_real_time () / G_USEC_PER_SEC)
          / WYL_TOTP_STEP_SECONDS;
      guint code_int = 0;
      g_autoptr (GError) code_error = NULL;
      g_assert_cmpint (wyl_totp_code_at_step (seed, seed_len, step, &code_int,
              &code_error), ==, WYRELOG_E_OK);
      if (mode == WYCTL_TEST_FEED_PERTURB) {
        /* Perturb the lowest digit by +1 (mod 10).  Result is the
         * same length as the valid code and is guaranteed NOT to
         * equal the current step's canonical code.  The residual
         * 2-in-10^6 false-pass risk (collision with prev / next step
         * inside the validator's ±1 skew window) is half the original
         * "000000" override's 3-in-10^6 window and is the lowest
         * achievable without re-deriving the secret. */
        guint perturbed = (code_int / 10) * 10 + ((code_int % 10 + 1) % 10);
        computed = g_strdup_printf ("%06u", perturbed);
      } else {
        computed = g_strdup_printf ("%06u", code_int);
      }
      code = computed;
    }
    g_autofree gchar *payload = g_strdup_printf ("%s\n", code);
    gsize written = 0;
    g_autoptr (GError) wr_error = NULL;
    g_assert_true (g_output_stream_write_all (stdin_pipe, payload,
            strlen (payload), &written, NULL, &wr_error));
    g_assert_no_error (wr_error);
  }
  /* Close stdin: feeds EOF to wyctl whether or not we wrote a code. */
  g_autoptr (GError) close_error = NULL;
  g_output_stream_close (stdin_pipe, NULL, &close_error);
  g_clear_error (&close_error);

  /* Drain stdout / stderr. */
  read_to_eof (stdout_pipe, stdout_acc);
  GInputStream *stderr_pipe = g_subprocess_get_stderr_pipe (sub);
  if (stderr_pipe != NULL)
    read_to_eof (stderr_pipe, stderr_acc);

  g_autoptr (GError) wait_error = NULL;
  g_subprocess_wait (sub, NULL, &wait_error);
  g_assert_no_error (wait_error);

  if (g_subprocess_get_if_exited (sub))
    return g_subprocess_get_exit_status (sub);
  return -1;
}

/* Thin wrapper preserving the original `run_wyctl_mfa' contract used
 * by the issue #331 tests: build `--subject SUBJECT --store STORE_PATH'
 * argv with no extra envp and drive the handshake. */
static gint
run_wyctl_mfa (const gchar *subcommand, const gchar *subject,
    const gchar *store_path, WyctlTestFeedMode mode,
    const gchar *override_code, GString *stdout_acc, GString *stderr_acc)
{
  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa",
    subcommand,
    "--subject", subject,
    "--store", store_path,
    NULL,
  };
  return run_wyctl_mfa_argv_env (argv, NULL, mode, override_code, stdout_acc,
      stderr_acc);
}

static void
test_mfa_enroll_happy_path (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", "alice.user", store, WYCTL_TEST_FEED_VALID,
      NULL, out, err);
  if (rc != 0)
    g_printerr ("happy stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  g_autofree gchar *uri = extract_kv (out->str, "otpauth_uri");
  g_assert_nonnull (uri);
  g_assert_true (g_str_has_prefix (uri, "otpauth://totp/"));
  g_assert_nonnull (strstr (uri, "issuer=wyrelog"));
  g_assert_nonnull (strstr (uri, "algorithm=SHA1"));
  g_assert_nonnull (strstr (uri, "digits=6"));
  g_assert_nonnull (strstr (uri, "period=30"));

  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (store, "alice.user", &enr));
  g_assert_nonnull (enr.id_uuidv7);
  wyl_totp_enrollment_clear (&enr);

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_enroll_abort_on_eof_writes_nothing (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", "bob.user", store, WYCTL_TEST_FEED_EOF,
      NULL, out, err);
  g_assert_cmpint (rc, !=, 0);

  WylTotpEnrollment enr = { 0 };
  g_assert_false (lookup_enrollment (store, "bob.user", &enr));
  wyl_totp_enrollment_clear (&enr);

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_enroll_abort_on_wrong_code (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  /* PERTURB derives the valid code from the printed secret, then
   * deliberately flips the ones digit (+1 mod 10).  The result is
   * guaranteed not to equal the current step's canonical code; the
   * residual flake risk is the 2-in-10^6 chance of accidentally
   * matching the prev / next step inside the validator's ±1 skew
   * window.  Strictly stronger than a static "000000" override. */
  gint rc = run_wyctl_mfa ("enroll", "carol.user", store,
      WYCTL_TEST_FEED_PERTURB, NULL, out, err);
  g_assert_cmpint (rc, !=, 0);

  WylTotpEnrollment enr = { 0 };
  g_assert_false (lookup_enrollment (store, "carol.user", &enr));
  wyl_totp_enrollment_clear (&enr);

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_reset_happy_path (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  /* Pre-seed an existing enrollment row for dave so reset has something
   * to delete. */
  {
    g_autoptr (wyl_policy_store_t) s = NULL;
    g_assert_cmpint (wyl_policy_store_open (store, &s), ==, WYRELOG_E_OK);
    WylTotpEnrollment seed = { 0 };
    seed.subject_id = g_strdup ("dave.user");
    for (gsize i = 0; i < WYL_TOTP_ENROLLMENT_SECRET_BYTES; i++)
      seed.secret[i] = (guint8) (0xAA ^ i);
    seed.last_verified_step = INT64_MIN;
    seed.enrolled_at = 1700000000;
    g_assert_cmpint (wyl_policy_store_totp_enrollment_insert (s, &seed), ==,
        WYRELOG_E_OK);
    g_autofree gchar *old_id = g_strdup (seed.id_uuidv7);
    wyl_totp_enrollment_clear (&seed);

    g_autoptr (GString) out = g_string_new (NULL);
    g_autoptr (GString) err = g_string_new (NULL);
    /* Re-open to free our lock before invoking wyctl. */
    wyl_policy_store_close (g_steal_pointer (&s));

    gint rc = run_wyctl_mfa ("reset", "dave.user", store, WYCTL_TEST_FEED_VALID,
        NULL, out, err);
    if (rc != 0)
      g_printerr ("reset stderr: %s\n", err->str);
    g_assert_cmpint (rc, ==, 0);

    WylTotpEnrollment after = { 0 };
    g_assert_true (lookup_enrollment (store, "dave.user", &after));
    g_assert_nonnull (after.id_uuidv7);
    /* The new uuid MUST differ from the pre-existing one. */
    g_assert_cmpstr (after.id_uuidv7, !=, old_id);
    wyl_totp_enrollment_clear (&after);
  }

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_reset_abort_leaves_subject_unenrolled (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  /* Seed an existing enrollment for eve. */
  {
    g_autoptr (wyl_policy_store_t) s = NULL;
    g_assert_cmpint (wyl_policy_store_open (store, &s), ==, WYRELOG_E_OK);
    WylTotpEnrollment seed = { 0 };
    seed.subject_id = g_strdup ("eve.user");
    for (gsize i = 0; i < WYL_TOTP_ENROLLMENT_SECRET_BYTES; i++)
      seed.secret[i] = (guint8) (0x55 + i);
    seed.last_verified_step = INT64_MIN;
    seed.enrolled_at = 1700000000;
    g_assert_cmpint (wyl_policy_store_totp_enrollment_insert (s, &seed), ==,
        WYRELOG_E_OK);
    wyl_totp_enrollment_clear (&seed);
  }

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("reset", "eve.user", store, WYCTL_TEST_FEED_EOF,
      NULL, out, err);
  g_assert_cmpint (rc, !=, 0);

  WylTotpEnrollment after = { 0 };
  g_assert_false (lookup_enrollment (store, "eve.user", &after));
  wyl_totp_enrollment_clear (&after);

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_enroll_bootstrap_admin_auto_revokes_skip_mfa (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);
  /* Bootstrap with skip-mfa for the admin. */
  seal_bootstrap_admin (store, "admin1", TRUE);

  /* Pre-condition: skip_mfa is granted. */
  g_assert_true (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", "admin1", store, WYCTL_TEST_FEED_VALID,
      NULL, out, err);
  if (rc != 0)
    g_printerr ("bootstrap-revoke stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  /* Atomicity reasoning: wyctl_mfa_run_enroll_flow wraps the
   * enrollment insert + audit row + direct-permission revoke + FSM
   * transition in a single outer savepoint via
   * wyl_policy_store_begin_mutation / commit_mutation.  We assert
   * both visible halves of the commit here — enrollment present AND
   * skip_mfa absent — which is sufficient to demonstrate that the
   * mutation block landed as a unit on this happy path.  The
   * sibling test_mfa_enroll_atomic_rollback_on_audit_failure
   * exercises the failure path: a forced mid-flow audit-emit
   * failure rolls back the enrollment insert AND leaves skip_mfa
   * untouched. */
  /* Post-condition (a): enrollment row exists. */
  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (store, "admin1", &enr));
  wyl_totp_enrollment_clear (&enr);

  /* Post-condition (b): skip_mfa is gone. */
  g_assert_false (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));

  g_unlink (store);
  g_rmdir (tmp);
}

/* Atomicity regression: force a mid-flow failure after the enrollment
 * insert but at the audit-emit step, and verify the outer savepoint
 * rolls EVERYTHING back — the bootstrap admin remains unenrolled AND
 * still holds wr.login.skip_mfa.  Without the outer savepoint, the
 * enrollment insert would persist while skip_mfa was still armed,
 * creating an auth-bypass window. */
static void
test_mfa_enroll_atomic_rollback_on_audit_failure (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);
  seal_bootstrap_admin (store, "admin1", TRUE);

  /* Pre-condition: skip_mfa is granted, no enrollment. */
  g_assert_true (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));
  WylTotpEnrollment pre_enr = { 0 };
  g_assert_false (lookup_enrollment (store, "admin1", &pre_enr));
  wyl_totp_enrollment_clear (&pre_enr);

  /* Failure injection: drop the audit_events table.  The wyctl
   * enrollment flow's mfa_enrolled audit row (mutation #2 in the
   * outer savepoint) will fail at INSERT, the rollback fires, and
   * the enrollment row (mutation #1) must NOT survive. */
  {
    g_autoptr (wyl_policy_store_t) s = NULL;
    g_assert_cmpint (wyl_policy_store_open (store, &s), ==, WYRELOG_E_OK);
    sqlite3 *db = wyl_policy_store_get_db (s);
    g_assert_nonnull (db);
    char *err_msg = NULL;
    int sqlite_rc = sqlite3_exec (db, "DROP TABLE audit_events;", NULL, NULL,
        &err_msg);
    if (sqlite_rc != SQLITE_OK) {
      g_printerr ("drop audit_events failed: %s\n",
          err_msg != NULL ? err_msg : "(unknown)");
      sqlite3_free (err_msg);
    }
    g_assert_cmpint (sqlite_rc, ==, SQLITE_OK);
  }

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", "admin1", store, WYCTL_TEST_FEED_VALID,
      NULL, out, err);
  /* wyctl must exit non-zero — the audit failure is surfaced. */
  g_assert_cmpint (rc, !=, 0);

  /* Atomicity assertion: the rollback must have unwound the
   * enrollment row that wyctl inserted before hitting the audit
   * failure.  If this fails, the outer savepoint is broken — that's
   * the auth-bypass regression the savepoint defends against.
   *
   * The store is still missing audit_events, but
   * wyl_policy_store_totp_enrollment_lookup and
   * wyl_policy_store_direct_permission_exists query only their own
   * tables (totp_enrollments / direct_permissions), so the lookups
   * below succeed without the audit_events table. */
  WylTotpEnrollment post_enr = { 0 };
  g_assert_false (lookup_enrollment (store, "admin1", &post_enr));
  wyl_totp_enrollment_clear (&post_enr);

  /* And skip_mfa MUST still be granted — the auto-revoke is part of
   * the same savepoint scope and must be invisible after rollback. */
  g_assert_true (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_enroll_non_bootstrap_subject_does_not_revoke (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);
  /* Bootstrap admin is admin1.  Subject "frank" is NOT the bootstrap
   * admin, and has no skip_mfa grant.  Enrolling frank should be a
   * plain enroll — no revoke side-effect. */
  seal_bootstrap_admin (store, "admin1", TRUE);

  /* Sanity: admin1 still holds skip_mfa, frank does not. */
  g_assert_true (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));
  g_assert_false (direct_perm_exists (store, "frank.user",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", "frank.user", store,
      WYCTL_TEST_FEED_VALID, NULL, out, err);
  if (rc != 0)
    g_printerr ("non-bootstrap stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (store, "frank.user", &enr));
  wyl_totp_enrollment_clear (&enr);

  /* admin1's skip_mfa MUST remain — enrolling a different subject does
   * not touch the bootstrap admin's grant. */
  g_assert_true (direct_perm_exists (store, "admin1",
          WYL_TEST_LOGIN_SKIP_MFA_PERMISSION, WYL_TEST_LOGIN_SKIP_MFA_SCOPE));

  g_unlink (store);
  g_rmdir (tmp);
}

static void
test_mfa_enroll_url_encodes_subject (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *store = g_build_filename (tmp, "policy.sqlite", NULL);
  create_empty_store (store);

  /* Subject deliberately carries reserved chars (`:' and `/') so the
   * URI builder must percent-encode them per the Key URI Format. */
  const gchar *subject = "weird:user/name";

  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa ("enroll", subject, store, WYCTL_TEST_FEED_VALID,
      NULL, out, err);
  if (rc != 0)
    g_printerr ("url-encode stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  g_autofree gchar *uri = extract_kv (out->str, "otpauth_uri");
  g_assert_nonnull (uri);
  /* Raw `:' and `/' from the subject MUST be percent-encoded in the
   * label segment.  The static `wyrelog:' issuer-prefix colon is the
   * lone unescaped `:' permitted by the spec; check that the
   * percent-encoded forms are present. */
  g_assert_nonnull (strstr (uri, "%3A"));
  g_assert_nonnull (strstr (uri, "%2F"));

  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (store, subject, &enr));
  wyl_totp_enrollment_clear (&enr);

  g_unlink (store);
  g_rmdir (tmp);
}

/* ------------------------------------------------------------------
 * Issue #333 — GSettings fallback for `--store' / `--keyprovider'.
 *
 * The tests below drive `wyctl mfa enroll' as a subprocess with a
 * GSettings keyfile fixture that supplies `default-policy-store' (and,
 * for symmetry, `default-keyprovider').  Same memory backend invariant
 * the unit tests at tests/test-wyctl-config.c rely on, except this
 * file goes one layer further out and exercises the wyctl binary so
 * the resolver call site inside `run_mfa_enroll' is the thing actually
 * under test.
 *
 * The tests intentionally do NOT cover --keyprovider against a real
 * encrypted store: the harness uses unencrypted stores throughout,
 * matching the rest of this file.  Coverage of the keyprovider key is
 * therefore the unit-level symmetry tests in test-wyctl-config.c plus
 * a single subprocess test below that asserts the resolver consumes
 * the keyprovider key when --keyprovider is omitted (we route through
 * a clearly invalid spec so the failure mode is keyprovider-rejected,
 * not store-open-failed, proving the value flowed through the
 * resolver call site).
 * ------------------------------------------------------------------ */

static gchar *
make_keyfile_xdg_dir_mfa (const gchar *const *keys, const gchar *const *values)
{
  g_autoptr (GError) error = NULL;
  gchar *xdg = g_dir_make_tmp ("wyctl-mfa-xdg-XXXXXX", &error);
  g_assert_no_error (error);

  g_autofree gchar *settings_dir = g_build_filename (xdg, "glib-2.0",
      "settings", NULL);
  g_assert_cmpint (g_mkdir_with_parents (settings_dir, 0700), ==, 0);

  g_autofree gchar *keyfile_path = g_build_filename (settings_dir, "keyfile",
      NULL);
  g_autoptr (GKeyFile) keyfile = g_key_file_new ();
  for (gsize i = 0; keys != NULL && keys[i] != NULL; i++) {
    g_assert_nonnull (values[i]);
    g_key_file_set_string (keyfile, "org/wyrelog/wyctl", keys[i], values[i]);
  }
  g_assert_true (g_key_file_save_to_file (keyfile, keyfile_path, &error));
  g_assert_no_error (error);
  return xdg;
}

static gchar *
gvariant_literal_for_string_mfa (const gchar *value)
{
  g_autoptr (GVariant) variant = g_variant_new_string (value);
  return g_variant_print (variant, FALSE);
}

static void
remove_dir_recursive_mfa (const gchar *path)
{
  g_autoptr (GError) error = NULL;
  g_autoptr (GFile) file = g_file_new_for_path (path);
  g_autoptr (GFileEnumerator) en = g_file_enumerate_children (file,
      G_FILE_ATTRIBUTE_STANDARD_NAME ","
      G_FILE_ATTRIBUTE_STANDARD_TYPE, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
      NULL, &error);
  if (en != NULL) {
    while (TRUE) {
      g_autoptr (GFileInfo) info = g_file_enumerator_next_file (en, NULL,
          &error);
      if (info == NULL)
        break;
      g_autofree gchar *child = g_build_filename (path,
          g_file_info_get_name (info), NULL);
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        remove_dir_recursive_mfa (child);
      else
        g_unlink (child);
    }
  }
  g_clear_error (&error);
  g_rmdir (path);
}

/* Build an envp anchored at the parent process's env, with
 * XDG_CONFIG_HOME pointed at `xdg_dir' and the GSettings keyfile
 * backend selected.  When `disable_gsettings' is TRUE, also set
 * WYCTL_DISABLE_GSETTINGS=1 so the fallback is suppressed.  Caller
 * frees with g_strfreev. */
static gchar **
build_mfa_gsettings_envp (const gchar *xdg_dir, gboolean disable_gsettings)
{
  gchar **envp = g_get_environ ();
  envp = g_environ_setenv (envp, "XDG_CONFIG_HOME", xdg_dir, TRUE);
  envp = g_environ_setenv (envp, "GSETTINGS_BACKEND", "keyfile", TRUE);
  if (disable_gsettings)
    envp = g_environ_setenv (envp, "WYCTL_DISABLE_GSETTINGS", "1", TRUE);
  else
    envp = g_environ_unsetenv (envp, "WYCTL_DISABLE_GSETTINGS");
  return envp;
}

/* (1) CLI value wins over GSettings: both set, CLI is explicit, the
 *     row must land in the CLI-named store and the GSettings-named
 *     store must remain empty. */
static void
test_mfa_enroll_cli_store_wins_over_gsettings (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *cli_store = g_build_filename (tmp, "cli.sqlite", NULL);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (cli_store);
  create_empty_store (gs_store);

  g_autofree gchar *literal = gvariant_literal_for_string_mfa (gs_store);
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.cli",
    "--store", cli_store,
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_VALID, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);
  if (rc != 0)
    g_printerr ("cli-wins stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  WylTotpEnrollment cli_enr = { 0 };
  g_assert_true (lookup_enrollment (cli_store, "alice.cli", &cli_enr));
  wyl_totp_enrollment_clear (&cli_enr);

  WylTotpEnrollment gs_enr = { 0 };
  g_assert_false (lookup_enrollment (gs_store, "alice.cli", &gs_enr));
  wyl_totp_enrollment_clear (&gs_enr);

  g_unlink (cli_store);
  g_unlink (gs_store);
  g_rmdir (tmp);
}

/* (2) Populated GSettings + missing CLI --store: resolver supplies the
 *     path and the row lands in the GSettings-named store. */
static void
test_mfa_enroll_gsettings_supplies_store (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (gs_store);

  g_autofree gchar *literal = gvariant_literal_for_string_mfa (gs_store);
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.gs",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_VALID, NULL,
      out, err);
  if (rc != 0)
    g_printerr ("gs-supplies stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (gs_store, "alice.gs", &enr));
  wyl_totp_enrollment_clear (&enr);

  remove_dir_recursive_mfa (xdg);
  g_unlink (gs_store);
  g_rmdir (tmp);
}

/* (3) Both unset (empty GSettings + no CLI): existing
 *     "missing --store" diagnostic must surface. */
static void
test_mfa_enroll_both_unset_surfaces_missing_flag (void)
{
  /* Empty keyfile (no keys at all); the schema default for
   * default-policy-store is the empty string and the resolver maps
   * that to "unset". */
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (NULL, NULL);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.none",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  /* Feed EOF: we never reach the secret prompt because the missing-
   * flag diagnostic fires before any store is opened. */
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_EOF, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);

  g_assert_cmpint (rc, !=, 0);
  g_assert_nonnull (g_strstr_len (err->str, -1, "wyctl: missing --store"));
}

/* (4) WYCTL_DISABLE_GSETTINGS=1 + populated GSettings + no CLI:
 *     the kill switch suppresses the fallback and the missing-flag
 *     diagnostic surfaces. */
static void
test_mfa_enroll_kill_switch_disables_fallback (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (gs_store);

  g_autofree gchar *literal = gvariant_literal_for_string_mfa (gs_store);
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, TRUE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.kill",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_EOF, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);

  g_assert_cmpint (rc, !=, 0);
  g_assert_nonnull (g_strstr_len (err->str, -1, "wyctl: missing --store"));

  /* Sanity: the GSettings-named store stayed empty even though it was
   * fully populated in the keyfile.  Proves the kill switch beat the
   * resolver, not that the resolver got confused. */
  WylTotpEnrollment enr = { 0 };
  g_assert_false (lookup_enrollment (gs_store, "alice.kill", &enr));
  wyl_totp_enrollment_clear (&enr);

  g_unlink (gs_store);
  g_rmdir (tmp);
}

/* (5) Defense-in-depth: after a successful fully-GSettings-resolved
 *     enrollment, the operator-supplied keyfile MUST contain only the
 *     store path (and any other operator-set keys).  No seed bytes,
 *     no otpauth URI, no verification code, no UUIDv7.  This pins the
 *     invariant that the wyctl GSettings keys are operator-config
 *     only, never the destination of any enrollment artifact.
 *
 *     We can't introspect dconf in a test sandbox, but the keyfile
 *     backend writes to a single file under XDG_CONFIG_HOME so a
 *     byte-level scan against the captured enrollment artifacts is
 *     equivalent: any leak would mean the wyctl code path or the
 *     resolver wrote into the GSettings backend, which would show up
 *     in this file. */
static void
test_mfa_enroll_gsettings_backing_store_has_no_secrets (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (gs_store);

  g_autofree gchar *literal = gvariant_literal_for_string_mfa (gs_store);
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.scan",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_VALID, NULL,
      out, err);
  if (rc != 0)
    g_printerr ("scan stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  /* Capture the secrets the enrollment produced before scanning. */
  g_autofree gchar *secret_b32 = extract_kv (out->str, "secret_base32");
  g_autofree gchar *otpauth_uri = extract_kv (out->str, "otpauth_uri");
  WylTotpEnrollment enr = { 0 };
  g_assert_true (lookup_enrollment (gs_store, "alice.scan", &enr));
  g_autofree gchar *enrollment_id = g_strdup (enr.id_uuidv7);
  wyl_totp_enrollment_clear (&enr);
  g_assert_nonnull (secret_b32);
  g_assert_nonnull (otpauth_uri);
  g_assert_nonnull (enrollment_id);

  /* Read the keyfile back from disk and scan it for any of those
   * artifacts.  The keyfile is the entire GSettings backing store for
   * this test (XDG_CONFIG_HOME points only at the temp xdg dir). */
  g_autofree gchar *keyfile_path = g_build_filename (xdg, "glib-2.0",
      "settings", "keyfile", NULL);
  g_autofree gchar *keyfile_bytes = NULL;
  gsize keyfile_len = 0;
  g_autoptr (GError) read_error = NULL;
  g_assert_true (g_file_get_contents (keyfile_path, &keyfile_bytes,
          &keyfile_len, &read_error));
  g_assert_no_error (read_error);

  /* The path the operator wrote to GSettings IS expected to be
   * present; nothing else may be. */
  g_assert_nonnull (g_strstr_len (keyfile_bytes, keyfile_len, gs_store));
  g_assert_null (g_strstr_len (keyfile_bytes, keyfile_len, secret_b32));
  g_assert_null (g_strstr_len (keyfile_bytes, keyfile_len, otpauth_uri));
  g_assert_null (g_strstr_len (keyfile_bytes, keyfile_len, enrollment_id));

  /* And the subject we just enrolled must not have been written into
   * the GSettings keyfile either: defense-in-depth against a future
   * change that accidentally persists `default-subject'.  See the
   * issue #333 brief: --subject is per-invocation, never a default. */
  g_assert_null (g_strstr_len (keyfile_bytes, keyfile_len, "alice.scan"));

  remove_dir_recursive_mfa (xdg);
  g_unlink (gs_store);
  g_rmdir (tmp);
}

/* (6) Empty-string GSettings is treated as unset.  Mirrors the unit
 *     test test_resolve_string_empty_settings_is_unset.  Forces the
 *     keyfile to contain `default-policy-store=''' explicitly so the
 *     code path that reads the value (rather than absent-key default)
 *     is exercised. */
static void
test_mfa_enroll_empty_gsettings_string_is_unset (void)
{
  g_autofree gchar *literal = gvariant_literal_for_string_mfa ("");
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.empty",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_EOF, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);

  g_assert_cmpint (rc, !=, 0);
  g_assert_nonnull (g_strstr_len (err->str, -1, "wyctl: missing --store"));
}

/* (7) The same matrix for `mfa reset': populated GSettings, no CLI,
 *     reset path must consume the GSettings value.  Seeds an existing
 *     enrollment row first so the delete-then-enroll path actually
 *     has something to delete. */
static void
test_mfa_reset_gsettings_supplies_store (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (gs_store);

  {
    g_autoptr (wyl_policy_store_t) s = NULL;
    g_assert_cmpint (wyl_policy_store_open (gs_store, &s), ==, WYRELOG_E_OK);
    WylTotpEnrollment seed = { 0 };
    seed.subject_id = g_strdup ("alice.reset");
    for (gsize i = 0; i < WYL_TOTP_ENROLLMENT_SECRET_BYTES; i++)
      seed.secret[i] = (guint8) (0x33 ^ i);
    seed.last_verified_step = INT64_MIN;
    seed.enrolled_at = 1700000000;
    g_assert_cmpint (wyl_policy_store_totp_enrollment_insert (s, &seed), ==,
        WYRELOG_E_OK);
    wyl_totp_enrollment_clear (&seed);
  }

  g_autofree gchar *literal = gvariant_literal_for_string_mfa (gs_store);
  const gchar *keys[] = { "default-policy-store", NULL };
  const gchar *values[] = { literal, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "reset",
    "--subject", "alice.reset",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_VALID, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);
  if (rc != 0)
    g_printerr ("reset-gs stderr: %s\n", err->str);
  g_assert_cmpint (rc, ==, 0);

  WylTotpEnrollment after = { 0 };
  g_assert_true (lookup_enrollment (gs_store, "alice.reset", &after));
  wyl_totp_enrollment_clear (&after);

  g_unlink (gs_store);
  g_rmdir (tmp);
}

/* (8) Subprocess coverage for the `default-keyprovider' resolver call
 *     site: with --keyprovider omitted but GSettings populated, wyctl
 *     must consume the GSettings value.  We point GSettings at a
 *     deliberately-unreadable keyprovider spec so the failure mode is
 *     `keyprovider unreadable' / `open store failed', not "missing
 *     --keyprovider".  That proves the resolver fed the spec into
 *     wyctl_mfa_open_store rather than the value being silently
 *     dropped. */
static void
test_mfa_enroll_gsettings_supplies_keyprovider (void)
{
  g_autofree gchar *tmp = g_dir_make_tmp ("wyctl-mfa-XXXXXX", NULL);
  g_assert_nonnull (tmp);
  g_autofree gchar *gs_store = g_build_filename (tmp, "gs.sqlite", NULL);
  create_empty_store (gs_store);

  /* Keyprovider spec that is syntactically a `file:' spec but refers
   * to a path that does not exist.  wyl_keyprovider_file_new_from_spec
   * returns NULL, wyctl_mfa_open_store returns WYRELOG_E_IO, and wyctl
   * exits non-zero with "open store failed".  We never reach the
   * stdin prompt. */
  g_autofree gchar *bogus_kp = g_build_filename (tmp, "no-such-keyprovider",
      NULL);
  g_autofree gchar *kp_spec = g_strdup_printf ("file:%s", bogus_kp);

  g_autofree gchar *store_lit = gvariant_literal_for_string_mfa (gs_store);
  g_autofree gchar *kp_lit = gvariant_literal_for_string_mfa (kp_spec);
  const gchar *keys[] = {
    "default-policy-store",
    "default-keyprovider",
    NULL,
  };
  const gchar *values[] = { store_lit, kp_lit, NULL };
  g_autofree gchar *xdg = make_keyfile_xdg_dir_mfa (keys, values);
  g_auto (GStrv) envp = build_mfa_gsettings_envp (xdg, FALSE);

  const gchar *argv[] = {
    WYL_TEST_WYCTL_PATH,
    "mfa", "enroll",
    "--subject", "alice.kp",
    NULL,
  };
  g_autoptr (GString) out = g_string_new (NULL);
  g_autoptr (GString) err = g_string_new (NULL);
  gint rc = run_wyctl_mfa_argv_env (argv, envp, WYCTL_TEST_FEED_EOF, NULL,
      out, err);
  remove_dir_recursive_mfa (xdg);

  g_assert_cmpint (rc, !=, 0);
  /* The resolver consumed --keyprovider from GSettings.  The expected
   * failure mode is the keyprovider-rejected path, NOT "missing
   * --keyprovider" (which would prove the value never flowed). */
  g_assert_null (g_strstr_len (err->str, -1, "wyctl: missing --keyprovider"));
  g_assert_nonnull (g_strstr_len (err->str, -1, "wyctl: open store failed"));

  g_unlink (gs_store);
  g_rmdir (tmp);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/wyctl/mfa/enroll-happy-path", test_mfa_enroll_happy_path);
  g_test_add_func ("/wyctl/mfa/enroll-abort-on-eof-writes-nothing",
      test_mfa_enroll_abort_on_eof_writes_nothing);
  g_test_add_func ("/wyctl/mfa/enroll-abort-on-wrong-code",
      test_mfa_enroll_abort_on_wrong_code);
  g_test_add_func ("/wyctl/mfa/reset-happy-path", test_mfa_reset_happy_path);
  g_test_add_func ("/wyctl/mfa/reset-abort-leaves-subject-unenrolled",
      test_mfa_reset_abort_leaves_subject_unenrolled);
  g_test_add_func ("/wyctl/mfa/enroll-bootstrap-admin-auto-revokes-skip-mfa",
      test_mfa_enroll_bootstrap_admin_auto_revokes_skip_mfa);
  g_test_add_func ("/wyctl/mfa/enroll-atomic-rollback-on-audit-failure",
      test_mfa_enroll_atomic_rollback_on_audit_failure);
  g_test_add_func ("/wyctl/mfa/enroll-non-bootstrap-subject-does-not-revoke",
      test_mfa_enroll_non_bootstrap_subject_does_not_revoke);
  g_test_add_func ("/wyctl/mfa/enroll-url-encodes-subject",
      test_mfa_enroll_url_encodes_subject);

  /* Issue #333: GSettings fallback for --store / --keyprovider. */
  g_test_add_func ("/wyctl/mfa/enroll-cli-store-wins-over-gsettings",
      test_mfa_enroll_cli_store_wins_over_gsettings);
  g_test_add_func ("/wyctl/mfa/enroll-gsettings-supplies-store",
      test_mfa_enroll_gsettings_supplies_store);
  g_test_add_func ("/wyctl/mfa/enroll-both-unset-surfaces-missing-flag",
      test_mfa_enroll_both_unset_surfaces_missing_flag);
  g_test_add_func ("/wyctl/mfa/enroll-kill-switch-disables-fallback",
      test_mfa_enroll_kill_switch_disables_fallback);
  g_test_add_func ("/wyctl/mfa/enroll-gsettings-backing-store-has-no-secrets",
      test_mfa_enroll_gsettings_backing_store_has_no_secrets);
  g_test_add_func ("/wyctl/mfa/enroll-empty-gsettings-string-is-unset",
      test_mfa_enroll_empty_gsettings_string_is_unset);
  g_test_add_func ("/wyctl/mfa/reset-gsettings-supplies-store",
      test_mfa_reset_gsettings_supplies_store);
  g_test_add_func ("/wyctl/mfa/enroll-gsettings-supplies-keyprovider",
      test_mfa_enroll_gsettings_supplies_keyprovider);

  return g_test_run ();
}
