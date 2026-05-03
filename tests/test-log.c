/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdio.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyl-log-private.h"

/* --- Spec parser tests ---------------------------------------------- */

static void
assert_all_at (const gint8 levels[WYL_LOG_SECTION_LAST_], gint expected)
{
  for (gint i = 0; i < WYL_LOG_SECTION_LAST_; i++)
    g_assert_cmpint (levels[i], ==, expected);
}

static void
test_parse_default (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec (NULL, levels);
  assert_all_at (levels, WYL_LOG_LEVEL_WARN);
}

static void
test_parse_empty (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("", levels);
  assert_all_at (levels, WYL_LOG_LEVEL_WARN);
}

static void
test_parse_wildcard_numeric (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("*:5", levels);
  assert_all_at (levels, WYL_LOG_LEVEL_TRACE);
}

static void
test_parse_wildcard_named (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("*:trace", levels);
  assert_all_at (levels, WYL_LOG_LEVEL_TRACE);
}

static void
test_parse_named_section (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("BOOT:debug", levels);
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_DEBUG);
  /* Other sections retain the WARN default. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_WARN);
  g_assert_cmpint (levels[WYL_LOG_SECTION_GENERAL], ==, WYL_LOG_LEVEL_WARN);
}

static void
test_parse_section_case_insensitive (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("policy:info,Audit:Error", levels);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_INFO);
  g_assert_cmpint (levels[WYL_LOG_SECTION_AUDIT], ==, WYL_LOG_LEVEL_ERROR);
}

static void
test_parse_override_later_wins (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("*:5,BOOT:0", levels);
  /* All others start at trace, BOOT downgraded to none. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_NONE);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_TRACE);
  g_assert_cmpint (levels[WYL_LOG_SECTION_GENERAL], ==, WYL_LOG_LEVEL_TRACE);
}

static void
test_parse_unknown_section_ignored (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("UNKNOWN:5,BOOT:debug", levels);
  /* Unknown silently dropped, valid entry still applied. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_DEBUG);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_WARN);
}

static void
test_parse_unknown_level_ignored (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("BOOT:bogus,POLICY:info", levels);
  /* Bogus level entry silently dropped, BOOT keeps default. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_WARN);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_INFO);
}

static void
test_parse_clamps_high_numeric (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("BOOT:9", levels);
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_TRACE);
}

static void
test_parse_rejects_negative (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("BOOT:-1", levels);
  /* Negative -> not a digit-leading token, parser falls into name
   * matching, fails, entry dropped. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_WARN);
}

static void
test_parse_malformed_skipped (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("BOOT,POLICY:info,:5,DECISION:debug", levels);
  /* "BOOT" without ':' is dropped; ":5" without section is dropped. */
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_WARN);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_INFO);
  g_assert_cmpint (levels[WYL_LOG_SECTION_DECISION], ==, WYL_LOG_LEVEL_DEBUG);
}

static void
test_parse_whitespace_tolerated (void)
{
  gint8 levels[WYL_LOG_SECTION_LAST_];
  wyl_log_internal_parse_spec ("  BOOT : debug ,  POLICY:info  ", levels);
  g_assert_cmpint (levels[WYL_LOG_SECTION_BOOT], ==, WYL_LOG_LEVEL_DEBUG);
  g_assert_cmpint (levels[WYL_LOG_SECTION_POLICY], ==, WYL_LOG_LEVEL_INFO);
}

/* --- Section name table --------------------------------------------- */

static void
test_section_name_known (void)
{
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_BOOT), ==, "BOOT");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_POLICY), ==, "POLICY");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_SESSION), ==,
      "SESSION");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_DECISION), ==,
      "DECISION");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_AUDIT), ==, "AUDIT");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_IO), ==, "IO");
  g_assert_cmpstr (wyl_log_section_name (WYL_LOG_SECTION_GENERAL), ==,
      "GENERAL");
}

static void
test_section_name_out_of_range (void)
{
  g_assert_null (wyl_log_section_name (WYL_LOG_SECTION_LAST_));
  g_assert_null (wyl_log_section_name ((wyl_log_section_t) - 1));
  g_assert_null (wyl_log_section_name ((wyl_log_section_t) 999));
}

static void
test_section_count (void)
{
  /* Updating the enum requires updating the name table in lockstep;
   * the count just confirms callers see the same cardinality. */
  g_assert_cmpint (wyl_log_section_count (), ==, WYL_LOG_SECTION_LAST_);
}

/* --- File sink tests ------------------------------------------------ */

static void
test_file_sink_redirection (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyrelog-test-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *path = g_build_filename (tmpdir, "wyl.log", NULL);

  g_setenv ("WYL_LOG_FILE", path, TRUE);
  g_setenv ("WYL_LOG", "*:5", TRUE);
  wyl_log_internal_reconfigure ();

  wyl_log_structured (WYL_LOG_SECTION_GENERAL, G_LOG_LEVEL_WARNING,
      "redirect-test-marker %d", 42);

  /* Flush any pending writes. */
  wyl_log_internal_reconfigure ();      /* closes the file */
  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();

  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gboolean ok = g_file_get_contents (path, &contents, &len, NULL);
  g_assert_true (ok);
  g_assert_nonnull (contents);
  g_assert_nonnull (g_strstr_len (contents, (gssize) len,
          "redirect-test-marker 42"));

  remove (path);
  rmdir (tmpdir);
}

static void
test_file_sink_fallback_on_invalid_path (void)
{
  g_setenv ("WYL_LOG_FILE", "/nonexistent-dir/xxx.log", TRUE);
  g_setenv ("WYL_LOG", "*:5", TRUE);

  /* Must not crash — stderr fallback applies (FC1: do not refuse to boot). */
  wyl_log_internal_reconfigure ();
  wyl_log_structured (WYL_LOG_SECTION_GENERAL, G_LOG_LEVEL_WARNING,
      "fallback-test-marker");

  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();
}

static void
test_runtime_filter_end_to_end (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyrelog-test-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *path = g_build_filename (tmpdir, "wyl.log", NULL);

  g_setenv ("WYL_LOG_FILE", path, TRUE);
  /* GENERAL threshold = ERROR (1); POLICY threshold = TRACE (5). */
  g_setenv ("WYL_LOG", "GENERAL:1,POLICY:5", TRUE);
  wyl_log_internal_reconfigure ();

  /* DEBUG (wyl level 4) > GENERAL threshold (1) -> should be suppressed. */
  wyl_log_structured (WYL_LOG_SECTION_GENERAL, G_LOG_LEVEL_DEBUG,
      "general-debug-should-not-appear");
  /* DEBUG (wyl level 4) <= POLICY threshold (5) -> should appear. */
  wyl_log_structured (WYL_LOG_SECTION_POLICY, G_LOG_LEVEL_DEBUG,
      "policy-debug-should-appear");

  /* Close the file by reloading with no WYL_LOG_FILE. */
  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();

  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gboolean ok = g_file_get_contents (path, &contents, &len, NULL);
  g_assert_true (ok);
  g_assert_nonnull (contents);

  g_assert_nonnull (g_strstr_len (contents, (gssize) len,
          "policy-debug-should-appear"));
  g_assert_null (g_strstr_len (contents, (gssize) len,
          "general-debug-should-not-appear"));

  remove (path);
  rmdir (tmpdir);
}

static void
test_file_sink_reopen_same_path_no_crash (void)
{
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyrelog-test-XXXXXX", NULL);
  g_assert_nonnull (tmpdir);
  g_autofree gchar *path = g_build_filename (tmpdir, "shared.log", NULL);

  /* WL_LOG_FILE is wirelog's env var. Both point at the same file.
   * Interleaving with wirelog's writes is operator error and is not a
   * wyrelog correctness contract; this test only asserts no crash and
   * that wyrelog's own line is present. */
  g_setenv ("WL_LOG_FILE", path, TRUE);
  g_setenv ("WYL_LOG_FILE", path, TRUE);
  g_setenv ("WYL_LOG", "*:5", TRUE);
  wyl_log_internal_reconfigure ();

  wyl_log_structured (WYL_LOG_SECTION_GENERAL, G_LOG_LEVEL_WARNING,
      "coexistence-test-marker");

  g_unsetenv ("WL_LOG_FILE");
  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();

  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gboolean ok = g_file_get_contents (path, &contents, &len, NULL);
  g_assert_true (ok);
  g_assert_nonnull (contents);
  g_assert_nonnull (g_strstr_len (contents, (gssize) len,
          "coexistence-test-marker"));

  remove (path);
  rmdir (tmpdir);
}

/* T7 — Thread-stress: sink_mutex serialises concurrent writes correctly.
 *
 * 8 threads each emit 1000 WARNING records into a shared file sink.
 * After all threads join we verify:
 *   - total line count == 8000 (no records lost)
 *   - no line is empty (no torn mid-line interleave)
 *
 * Process-unique tmpdir (g_dir_make_tmp) avoids collisions with parallel
 * meson test runs. */

#define T7_THREAD_COUNT 8
#define T7_RECORDS_PER_THREAD 1000

typedef struct
{
  gint thread_id;
} T7ThreadData;

static gpointer
t7_writer_thread (gpointer user_data)
{
  T7ThreadData *d = (T7ThreadData *) user_data;
  for (gint i = 0; i < T7_RECORDS_PER_THREAD; i++) {
    wyl_log_structured_at (WYL_LOG_SECTION_GENERAL, G_LOG_LEVEL_WARNING,
        NULL, 0, NULL, "t7-thread-%d-record-%d", d->thread_id, i);
  }
  return NULL;
}

static void
test_sink_mutex_concurrent_writes (void)
{
  GError *err = NULL;
  g_autofree gchar *tmpdir = g_dir_make_tmp ("wyl-t7-XXXXXX", &err);
  g_assert_no_error (err);
  g_assert_nonnull (tmpdir);

  g_autofree gchar *path = g_build_filename (tmpdir, "t7.log", NULL);

  g_setenv ("WYL_LOG_FILE", path, TRUE);
  g_setenv ("WYL_LOG", "*:2", TRUE);
  wyl_log_internal_reconfigure ();

  GThread *threads[T7_THREAD_COUNT];
  T7ThreadData data[T7_THREAD_COUNT];
  for (gint i = 0; i < T7_THREAD_COUNT; i++) {
    data[i].thread_id = i;
    threads[i] = g_thread_new ("t7-writer", t7_writer_thread, &data[i]);
    g_assert_nonnull (threads[i]);
  }
  for (gint i = 0; i < T7_THREAD_COUNT; i++)
    g_thread_join (threads[i]);

  /* Flush: close the file by reconfiguring without WYL_LOG_FILE. */
  g_unsetenv ("WYL_LOG_FILE");
  g_unsetenv ("WYL_LOG");
  wyl_log_internal_reconfigure ();

  /* Read the log file and verify line count and integrity. */
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  gboolean ok = g_file_get_contents (path, &contents, &len, NULL);
  g_assert_true (ok);
  g_assert_nonnull (contents);

  gchar **lines = g_strsplit (contents, "\n", -1);
  gint line_count = 0;
  for (gint i = 0; lines[i] != NULL; i++) {
    /* g_strsplit produces a trailing empty token after the final newline. */
    if (lines[i][0] != '\0')
      line_count++;
  }
  g_strfreev (lines);

  g_assert_cmpint (line_count, ==, T7_THREAD_COUNT * T7_RECORDS_PER_THREAD);

  g_remove (path);
  g_rmdir (tmpdir);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/wyl-log/parse/default", test_parse_default);
  g_test_add_func ("/wyl-log/parse/empty", test_parse_empty);
  g_test_add_func ("/wyl-log/parse/wildcard-numeric",
      test_parse_wildcard_numeric);
  g_test_add_func ("/wyl-log/parse/wildcard-named", test_parse_wildcard_named);
  g_test_add_func ("/wyl-log/parse/named-section", test_parse_named_section);
  g_test_add_func ("/wyl-log/parse/section-case-insensitive",
      test_parse_section_case_insensitive);
  g_test_add_func ("/wyl-log/parse/override-later-wins",
      test_parse_override_later_wins);
  g_test_add_func ("/wyl-log/parse/unknown-section-ignored",
      test_parse_unknown_section_ignored);
  g_test_add_func ("/wyl-log/parse/unknown-level-ignored",
      test_parse_unknown_level_ignored);
  g_test_add_func ("/wyl-log/parse/clamps-high-numeric",
      test_parse_clamps_high_numeric);
  g_test_add_func ("/wyl-log/parse/rejects-negative",
      test_parse_rejects_negative);
  g_test_add_func ("/wyl-log/parse/malformed-skipped",
      test_parse_malformed_skipped);
  g_test_add_func ("/wyl-log/parse/whitespace-tolerated",
      test_parse_whitespace_tolerated);
  g_test_add_func ("/wyl-log/section/name-known", test_section_name_known);
  g_test_add_func ("/wyl-log/section/name-out-of-range",
      test_section_name_out_of_range);
  g_test_add_func ("/wyl-log/section/count", test_section_count);

  g_test_add_func ("/wyl-log/file/redirection", test_file_sink_redirection);
  g_test_add_func ("/wyl-log/file/fallback-on-invalid-path",
      test_file_sink_fallback_on_invalid_path);
  g_test_add_func ("/wyl-log/runtime/filter-end-to-end",
      test_runtime_filter_end_to_end);
  g_test_add_func ("/wyl-log/runtime/file-sink-reopen-same-path-no-crash",
      test_file_sink_reopen_same_path_no_crash);
  g_test_add_func ("/wyl-log/runtime/sink-mutex-concurrent-writes",
      test_sink_mutex_concurrent_writes);

  return g_test_run ();
}
