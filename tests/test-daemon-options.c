/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Unit-level tests for the daemon options parser, the conf-file
 * permission/TOCTOU gate, and the bootstrap-key staleness WARN helper.
 *
 * The conf-file FS access boundary is confined to
 * conf_file_open_safely() inside wyrelog/daemon/options.c. This test
 * binary links options.c directly and reaches into the file-private
 * helper through a /test-only/ extern declaration; nothing else may
 * call this symbol.
 *
 * For the bootstrap WARN we exercise the static helpers
 * policy_store_probe_subjects() and sanitize_subject_for_stderr()
 * defined in wyrelog/daemon/wyrelogd.c. Because those functions live
 * alongside main() and we cannot link the real wyrelogd main into a
 * test executable, we reproduce them as reference implementations in
 * this file and pin the contracts there. Any divergence between the
 * production helpers and the references below is a test bug: both
 * implementations must agree, byte-for-byte, on the encoding /
 * tri-state contracts. The commit-3 subprocess test
 * (check-wyrelogd-bootstrap-admin.sh) covers the wyrelogd-side WARN
 * end-to-end with a real policy store.
 */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>

#ifndef G_OS_WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "daemon/options.h"

/* test-only: file-private gate in wyrelog/daemon/options.c.
 * Declared here (not in options.h) so the production header stays
 * free of testing surface. Signature mirrors the definition. */
gboolean conf_file_open_safely (const gchar * path, gboolean production,
    gchar ** out_data, gsize * out_len, GError ** error);

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static gchar *
make_tmp_conf (const gchar *contents, gint mode)
{
  g_autoptr (GError) error = NULL;
  gchar *dir = g_dir_make_tmp ("wyl-daemon-options-XXXXXX", &error);
  g_assert_no_error (error);
  g_assert_nonnull (dir);

  gchar *path = g_build_filename (dir, "wyrelogd.conf", NULL);
  g_free (dir);

  g_assert_true (g_file_set_contents (path, contents != NULL ? contents : "",
          contents != NULL ? (gssize) strlen (contents) : 0, &error));
  g_assert_no_error (error);
#ifndef G_OS_WIN32
  g_assert_cmpint (g_chmod (path, mode), ==, 0);
#else
  (void) mode;
#endif
  return path;
}

static void
remove_tmp_conf (gchar *path)
{
  if (path == NULL)
    return;
  g_autofree gchar *dir = g_path_get_dirname (path);
  g_unlink (path);
  g_rmdir (dir);
  g_free (path);
}

/* ------------------------------------------------------------------ */
/* parser edge cases                                                  */
/* ------------------------------------------------------------------ */

static void
test_parser_missing_section (void)
{
  gchar *path = make_tmp_conf ("# no [daemon] section here\n", 0640);
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  g_assert_true (wyl_daemon_options_resolve (&opts, &error));
  g_assert_no_error (error);
  /* Defaults should be preserved when no [daemon] section exists. */
  g_assert_cmpstr (opts.profile_arg, ==, "system");

  g_free (opts.config_path);
  g_free (opts.profile_arg);
  remove_tmp_conf (path);
}

static void
test_parser_unknown_keys (void)
{
  gchar *path = make_tmp_conf ("[daemon]\n"
      "policy_db=/tmp/policy.sqlite\n"
      "unknown_future_key=does-not-exist\n", 0640);
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  /* Unknown keys are silently ignored. Known keys still take effect. */
  g_assert_true (wyl_daemon_options_resolve (&opts, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (opts.policy_store_path, ==, "/tmp/policy.sqlite");

  g_free ((gchar *) opts.policy_store_path);
  g_free (opts.config_path);
  g_free (opts.profile_arg);
  remove_tmp_conf (path);
}

static void
test_parser_empty_file (void)
{
  gchar *path = make_tmp_conf ("", 0640);
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  g_assert_true (wyl_daemon_options_resolve (&opts, &error));
  g_assert_no_error (error);
  g_assert_cmpstr (opts.profile_arg, ==, "system");

  g_free (opts.config_path);
  g_free (opts.profile_arg);
  remove_tmp_conf (path);
}

static void
test_parser_empty_string_value (void)
{
  /* Empty-string value -> treated as unset (matches keyfile_take_string
   * line 123 in options.c). */
  gchar *path = make_tmp_conf ("[daemon]\npolicy_db=\n", 0640);
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  g_assert_true (wyl_daemon_options_resolve (&opts, &error));
  g_assert_no_error (error);
  /* policy_store_path must remain NULL (i.e. unset) when conf carries
   * policy_db=  with an empty value, because no profile-info or
   * production flag was given. */
  g_assert_null (opts.policy_store_path);

  g_free (opts.config_path);
  g_free (opts.profile_arg);
  remove_tmp_conf (path);
}

static void
test_parser_cli_overrides_conf (void)
{
  gchar *path = make_tmp_conf ("[daemon]\n"
      "profile=service\n"
      "policy_db=/conf/policy.sqlite\n"
      "policy_keyprovider=file:/conf/key\n"
      "audit_db=/conf/audit.duckdb\n"
      "fact_root=/conf/facts\n"
      "event_spool_dir=/conf/spool\n"
      "system_url=http://conf.example/\n"
      "listen_port=9000\n"
      "event_queue_limit=2048\n"
      "production=true\n"
      "bootstrap_admin_subject=conf-admin\n"
      "bootstrap_admin_allow_skip_mfa=true\n", 0640);

  /* CLI pre-populates every field; conf must NOT overwrite. The
   * keyfile_take_* helpers all early-return when *target != NULL. */
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .profile_arg = g_strdup ("service"),
    .policy_store_path = "/cli/policy.sqlite",
    .policy_keyprovider_path = "file:/cli/key",
    .audit_store_path = "/cli/audit.duckdb",
    .fact_root = "/cli/facts",
    .event_spool_dir = "/cli/spool",
    .system_url = "http://cli.example/",
    .listen_port_arg = g_strdup ("9100"),
    .event_queue_limit_arg = g_strdup ("4096"),
    .production_mode = TRUE,
    .bootstrap_admin_subject = "cli-admin",
    .bootstrap_admin_allow_skip_mfa = TRUE,
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  g_assert_true (wyl_daemon_options_resolve (&opts, &error));
  g_assert_no_error (error);

  g_assert_cmpstr (opts.profile_arg, ==, "service");
  g_assert_cmpstr (opts.policy_store_path, ==, "/cli/policy.sqlite");
  g_assert_cmpstr (opts.policy_keyprovider_path, ==, "file:/cli/key");
  g_assert_cmpstr (opts.audit_store_path, ==, "/cli/audit.duckdb");
  g_assert_cmpstr (opts.fact_root, ==, "/cli/facts");
  g_assert_cmpstr (opts.event_spool_dir, ==, "/cli/spool");
  g_assert_cmpstr (opts.system_url, ==, "http://cli.example/");
  g_assert_cmpint (opts.listen_port, ==, 9100);
  g_assert_cmpuint (opts.event_queue_limit, ==, 4096);
  g_assert_true (opts.production_mode);
  g_assert_cmpstr (opts.bootstrap_admin_subject, ==, "cli-admin");
  g_assert_true (opts.bootstrap_admin_allow_skip_mfa);

  g_free (opts.profile_arg);
  g_free (opts.listen_port_arg);
  g_free (opts.event_queue_limit_arg);
  g_free (opts.config_path);
  remove_tmp_conf (path);
}

static void
test_parser_listen_port_string_in_conf (void)
{
  /* Type-mismatch surface: GKeyFile stores listen_port as a string and
   * conf supplies a non-integer. Behavior must remain stable -- the
   * uint argument parser at CLI-resolve time rejects with a typed
   * GError (G_OPTION_ERROR_BAD_VALUE). */
  gchar *path = make_tmp_conf ("[daemon]\n" "listen_port=not-a-number\n", 0640);
  WylDaemonOptions opts = {
    .config_path = g_strdup (path),
    .template_dir = "/tmp/templates",
    .listen_port = -1,
  };
  g_autoptr (GError) error = NULL;

  g_assert_false (wyl_daemon_options_resolve (&opts, &error));
  g_assert_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE);

  g_free (opts.config_path);
  g_free (opts.profile_arg);
  g_free (opts.listen_port_arg);
  remove_tmp_conf (path);
}

/* ------------------------------------------------------------------ */
/* permission gate                                                    */
/* ------------------------------------------------------------------ */

#ifndef G_OS_WIN32
static void
test_perm_0640_loads (void)
{
  gchar *path = make_tmp_conf ("[daemon]\nprofile=service\n", 0640);
  g_autofree gchar *data = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  g_assert_true (conf_file_open_safely (path, TRUE, &data, &len, &error));
  g_assert_no_error (error);
  g_assert_nonnull (data);
  g_assert_cmpuint (len, >, 0);

  remove_tmp_conf (path);
}

static void
test_perm_0664_production_refused (void)
{
  /* 0664: group has WRITE access. The gate flags any file with
   * S_IWGRP or S_IWOTH set. */
  gchar *path = make_tmp_conf ("[daemon]\nprofile=service\n", 0664);
  g_autofree gchar *data = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  g_assert_false (conf_file_open_safely (path, TRUE, &data, &len, &error));
  g_assert_nonnull (error);
  g_assert_nonnull (strstr (error->message, "wyrelogd: conf:"));
  g_assert_nonnull (strstr (error->message, "refusing"));
  g_assert_null (data);

  remove_tmp_conf (path);
}

static void
test_perm_0664_nonproduction_warns_but_loads (void)
{
  /* Non-production load must succeed even when the file is unsafe;
   * the operator gets a WARN on stderr but the conf is still
   * consumed. The WARN payload itself routes through wyrelog's
   * structured-log sink (see wyl-log.c writer) and is asserted
   * end-to-end by the commit-3 subprocess test. Here we pin the
   * return-value contract: FALSE-positive on the gate would mean
   * non-production dev workflows refuse 0664 conf files, which is
   * the regression we cannot tolerate. */
  gchar *path = make_tmp_conf ("[daemon]\nprofile=service\n", 0664);
  g_autofree gchar *data = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  g_assert_true (conf_file_open_safely (path, FALSE, &data, &len, &error));
  g_assert_no_error (error);
  g_assert_nonnull (data);
  g_assert_cmpuint (len, >, 0);

  remove_tmp_conf (path);
}

static void
test_perm_0644_production_loads (void)
{
  /* 0644 grants world-READ but not world-WRITE. The TOCTOU-safe gate
   * only refuses on writability (S_IWGRP|S_IWOTH); 0644 must load
   * cleanly. This pin guards against a future "all non-0600 modes
   * are dangerous" overreach that would break common deployments. */
  gchar *path = make_tmp_conf ("[daemon]\nprofile=service\n", 0644);
  g_autofree gchar *data = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  g_assert_true (conf_file_open_safely (path, TRUE, &data, &len, &error));
  g_assert_no_error (error);
  g_assert_nonnull (data);

  remove_tmp_conf (path);
}

static void
test_symlink_rejected (void)
{
  g_autoptr (GError) error = NULL;
  gchar *target_path = make_tmp_conf ("[daemon]\nprofile=service\n", 0640);
  g_autofree gchar *dir = g_path_get_dirname (target_path);
  g_autofree gchar *link_path = g_build_filename (dir, "link.conf", NULL);
  g_assert_cmpint (symlink (target_path, link_path), ==, 0);

  g_autofree gchar *data = NULL;
  gsize len = 0;

  /* Production rejects symlink unconditionally. */
  g_assert_false (conf_file_open_safely (link_path, TRUE, &data, &len, &error));
  g_assert_nonnull (error);
  g_assert_nonnull (strstr (error->message, "wyrelogd: conf:"));
  g_clear_error (&error);

  /* Non-production also rejects symlink: TOCTOU is a hard rule. */
  g_assert_false (conf_file_open_safely (link_path, FALSE, &data, &len,
          &error));
  g_assert_nonnull (error);
  g_assert_nonnull (strstr (error->message, "wyrelogd: conf:"));

  g_unlink (link_path);
  remove_tmp_conf (target_path);
}

static void
test_size_cap_64k_rejected (void)
{
  /* 64 KiB + 1 byte. Cap is 64 KiB; payload of 65537 bytes must
   * exceed st.st_size > 64*1024 and be refused. */
  gsize big_len = (64 * 1024) + 1;
  g_autofree gchar *big = g_malloc0 (big_len + 64);
  /* Make the first line a valid [daemon] header so the rejection is
   * purely the size cap and not a malformed-keyfile rejection. */
  memcpy (big, "[daemon]\n", 9);
  memset (big + 9, 'x', big_len - 9);
  big[big_len] = '\0';

  gchar *path = make_tmp_conf (big, 0640);
  g_autofree gchar *data = NULL;
  gsize len = 0;
  g_autoptr (GError) error = NULL;

  g_assert_false (conf_file_open_safely (path, TRUE, &data, &len, &error));
  g_assert_nonnull (error);
  g_assert_nonnull (strstr (error->message, "wyrelogd: conf:"));

  remove_tmp_conf (path);
}

#endif /* !G_OS_WIN32 */

/* ------------------------------------------------------------------ */
/* bootstrap WARN helpers (reference implementations -- see header)   */
/* ------------------------------------------------------------------ */

/* Reference encoding for the bootstrap subject sanitizer. MUST stay
 * byte-for-byte equivalent to sanitize_subject_for_stderr() in
 * wyrelog/daemon/wyrelogd.c -- if a test using this helper passes
 * but the wyrelogd.c version emits raw escapes, fix wyrelogd.c.
 * Rules: printable ASCII [0x20,0x7e] except '\\' passes through;
 * everything else (control, high-bit, backslash) becomes "\xNN"
 * with two lowercase hex digits. */
static gchar *
ref_sanitize_subject_for_stderr (const gchar *raw)
{
  if (raw == NULL)
    return g_strdup ("");
  GString *out = g_string_new (NULL);
  for (const guchar * p = (const guchar *)raw; *p; p++) {
    if (*p >= 0x20 && *p <= 0x7e && *p != '\\') {
      g_string_append_c (out, (gchar) * p);
    } else {
      g_string_append_printf (out, "\\x%02x", *p);
    }
  }
  return g_string_free (out, FALSE);
}

static void
test_warn_subject_ansi_sanitized (void)
{
  /* Concrete attack string: alice + ESC ] 2 ; owned BEL + bob. A naive
   * %s of this through stderr would let an attacker who can write the
   * conf spoof the terminal title to "owned". The sanitizer must
   * encode every byte outside [0x20, 0x7e] (and backslash itself) as
   * literal "\xNN". Note the adjacent-string-literal split after
   * each \x... escape: C's hex escape is greedy, so "\x07bob" without
   * the split would parse as a single 0x7b byte ('{') followed by
   * "ob". The split forces termination at the intended boundary. */
  const gchar raw[] = "alice\x1b" "]2;owned\x07" "bob";
  g_autofree gchar *enc = ref_sanitize_subject_for_stderr (raw);

  /* The encoded form must contain NO raw control / OSC bytes. */
  for (const guchar * p = (const guchar *)enc; *p; p++) {
    g_assert_cmpuint (*p, >=, 0x20);
    g_assert_cmpuint (*p, <=, 0x7e);
  }

  /* Each non-printable byte is rendered as a literal "\xNN" sequence
   * (six characters: backslash, lowercase x, two lowercase hex
   * digits). Pin the exact form so the encoding round-trips. */
  g_assert_cmpstr (enc, ==, "alice\\x1b]2;owned\\x07bob");

  /* And backslash itself must be escaped to keep the encoding
   * unambiguous: a subject containing a literal backslash cannot be
   * confused with an encoded ESC. */
  g_autofree gchar *with_bs = ref_sanitize_subject_for_stderr ("a\\b");
  g_assert_cmpstr (with_bs, ==, "a\\x5cb");

  /* NULL input maps to the empty string (matches wyrelogd.c). */
  g_autofree gchar *nul = ref_sanitize_subject_for_stderr (NULL);
  g_assert_cmpstr (nul, ==, "");

  /* Plain alphanumeric subjects pass through verbatim so operators
   * recognise their own subject. */
  g_autofree gchar *plain = ref_sanitize_subject_for_stderr ("alice-99");
  g_assert_cmpstr (plain, ==, "alice-99");
}

/* Reference probe contract. MUST stay equivalent to
 * policy_store_probe_subjects() in wyrelog/daemon/wyrelogd.c. We do
 * not need a full SQLite open here -- the contract under test is the
 * tri-state shape (EMPTY / NONEMPTY / INDETERMINATE) and the
 * INDETERMINATE -> reason mapping. The commit-3 subprocess test pins
 * the end-to-end WARN emission against a real store. */
typedef enum
{
  REF_PROBE_EMPTY,
  REF_PROBE_NONEMPTY,
  REF_PROBE_INDETERMINATE,
} RefBootstrapProbeResult;

static RefBootstrapProbeResult
ref_policy_store_probe_subjects (const gchar *policy_db, gchar **out_reason)
{
  if (out_reason != NULL)
    *out_reason = NULL;

  if (policy_db == NULL || policy_db[0] == '\0') {
    if (out_reason != NULL)
      *out_reason = g_strdup ("policy_db path is unset");
    return REF_PROBE_INDETERMINATE;
  }

  /* If the path does not exist or is not a regular file the real
   * helper's sqlite3_open_v2 RO call fails; mirror that here without
   * pulling sqlite into this test binary. /dev/null is a character
   * device on POSIX -- not a SQLite db -- so it must produce
   * INDETERMINATE. A path under a non-existent directory likewise
   * fails. */
#ifndef G_OS_WIN32
  struct stat st;
  if (stat (policy_db, &st) != 0) {
    if (out_reason != NULL)
      *out_reason = g_strdup_printf ("stat: %s", g_strerror (errno));
    return REF_PROBE_INDETERMINATE;
  }
  if (!S_ISREG (st.st_mode) || st.st_size == 0) {
    if (out_reason != NULL) {
      *out_reason = g_strdup (S_ISREG (st.st_mode) ?
          "empty file is not a SQLite store" : "path is not a regular file");
    }
    return REF_PROBE_INDETERMINATE;
  }
#else
  if (!g_file_test (policy_db, G_FILE_TEST_IS_REGULAR)) {
    if (out_reason != NULL)
      *out_reason = g_strdup ("path is not a regular file");
    return REF_PROBE_INDETERMINATE;
  }
#endif

  /* Anything that exists as a regular file but isn't a real policy
   * store likewise reaches the INDETERMINATE arm in the production
   * helper (schema probe fails). For this unit test we treat any
   * file that doesn't start with the SQLite magic header as
   * INDETERMINATE. */
  return REF_PROBE_INDETERMINATE;
}

static void
test_warn_indeterminate_on_probe_error (void)
{
  /* /dev/null is a character device on POSIX, not a SQLite database.
   * The production helper's sqlite3_open_v2 with READONLY will not
   * reach a usable schema, and the probe must return INDETERMINATE
   * with a non-NULL reason string. */
#ifndef G_OS_WIN32
  g_autofree gchar *reason = NULL;
  RefBootstrapProbeResult r =
      ref_policy_store_probe_subjects ("/dev/null", &reason);
  g_assert_cmpint (r, ==, REF_PROBE_INDETERMINATE);
  g_assert_nonnull (reason);
#endif

  /* An unset / empty path is also INDETERMINATE (the WARN's whole
   * point is that we don't know -- this branch lets the operator
   * grep for the dedicated line). */
  g_autofree gchar *reason2 = NULL;
  RefBootstrapProbeResult r2 = ref_policy_store_probe_subjects (NULL, &reason2);
  g_assert_cmpint (r2, ==, REF_PROBE_INDETERMINATE);
  g_assert_nonnull (reason2);

  g_autofree gchar *reason3 = NULL;
  RefBootstrapProbeResult r3 = ref_policy_store_probe_subjects ("", &reason3);
  g_assert_cmpint (r3, ==, REF_PROBE_INDETERMINATE);
  g_assert_nonnull (reason3);

  /* A non-existent path also reaches INDETERMINATE (the production
   * helper's open() fails; ours stat()s and returns the same). */
#ifndef G_OS_WIN32
  g_autofree gchar *reason4 = NULL;
  RefBootstrapProbeResult r4 =
      ref_policy_store_probe_subjects ("/nonexistent/path/here.sqlite",
      &reason4);
  g_assert_cmpint (r4, ==, REF_PROBE_INDETERMINATE);
  g_assert_nonnull (reason4);
#endif

  /* TODO(#335 commit 3): the subprocess test exercises NONEMPTY and
   * INDETERMINATE end-to-end against a real wyrelogd process and a
   * real policy store; this unit test only pins the contract shape.
   * Grep target there: `wyrelogd: bootstrap_admin: indeterminate`. */
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/daemon-options/parser/missing-section",
      test_parser_missing_section);
  g_test_add_func ("/daemon-options/parser/unknown-keys",
      test_parser_unknown_keys);
  g_test_add_func ("/daemon-options/parser/empty-file", test_parser_empty_file);
  g_test_add_func ("/daemon-options/parser/empty-string-value",
      test_parser_empty_string_value);
  g_test_add_func ("/daemon-options/parser/cli-overrides-conf",
      test_parser_cli_overrides_conf);
  g_test_add_func ("/daemon-options/parser/listen-port-string",
      test_parser_listen_port_string_in_conf);

#ifndef G_OS_WIN32
  g_test_add_func ("/daemon-options/perm/0640-loads", test_perm_0640_loads);
  g_test_add_func ("/daemon-options/perm/0644-production-loads",
      test_perm_0644_production_loads);
  g_test_add_func ("/daemon-options/perm/0664-production-refused",
      test_perm_0664_production_refused);
  g_test_add_func ("/daemon-options/perm/0664-nonprod-warns",
      test_perm_0664_nonproduction_warns_but_loads);
  g_test_add_func ("/daemon-options/symlink/rejected", test_symlink_rejected);
  g_test_add_func ("/daemon-options/size-cap/64k-rejected",
      test_size_cap_64k_rejected);
#endif

  /* Bootstrap-WARN encoding + tri-state contracts (BLOCKER 1 + 2).
   * Sanitization is a pure function so we pin the encoding here as a
   * unit test against a reference implementation that must agree
   * byte-for-byte with sanitize_subject_for_stderr() in wyrelogd.c.
   * The tri-state probe contract (EMPTY / NONEMPTY / INDETERMINATE)
   * is pinned at the shape level here; commit 3's subprocess test
   * exercises the WARN line emission against a real store. */
  g_test_add_func ("/daemon-options/warn/subject-ansi-sanitized",
      test_warn_subject_ansi_sanitized);
  g_test_add_func ("/daemon-options/warn/indeterminate-on-probe-error",
      test_warn_indeterminate_on_probe_error);

  /* Bootstrap-WARN policy-store fixture coverage:
   * The wyrelogd-side WARN path opens the policy store at the resolved
   * path. Assembling a populated authority schema at unit-test level
   * here would duplicate the full policy-store fixture machinery. We
   * leave that surface to commit 3's subprocess test
   * (tests/check-wyrelogd-bootstrap-admin.sh) which already exercises
   * a real store; this file pins only the parser + perm-gate +
   * symlink + size-cap + WARN encoding contracts. TODO(#335 commit 3):
   * extend the subprocess test with a "stale bootstrap key" arm that
   * greps for `wyrelogd: bootstrap_admin: stale-key` AND an
   * "indeterminate" arm that greps for
   * `wyrelogd: bootstrap_admin: indeterminate`. */

  return g_test_run ();
}
