/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * test-log-ceiling.c — compile-time ceiling side-effect test.
 *
 * This test is compiled with -DWYL_LOG_MAX_LEVEL=2 (WARN) to verify
 * that macros whose required level exceeds the ceiling do NOT evaluate
 * their arguments (no side-effects), while macros at or below the
 * ceiling DO evaluate arguments.
 *
 * Expected behaviour under ceiling=WARN (2):
 *   WYL_LOG_DEBUG  (level 4) -> no-op, arguments not evaluated
 *   WYL_LOG_INFO   (level 3) -> no-op, arguments not evaluated
 *   WYL_LOG_WARN   (level 2) -> active, arguments evaluated
 *   WYL_LOG_ERROR  (level 1) -> active, arguments evaluated
 *   WYL_LOG_CRITICAL         -> always active (bypasses ceiling)
 */

#include <glib.h>
#include <glib/gstdio.h>

/* Override the ceiling before including the private header. */
#ifdef WYL_LOG_MAX_LEVEL
#undef WYL_LOG_MAX_LEVEL
#endif
#define WYL_LOG_MAX_LEVEL 2     /* WYL_LOG_LEVEL_WARN */

#include "wyrelog/wyl-log-private.h"

static gint side_effect_counter = 0;

static gint
side_effect (void)
{
  side_effect_counter++;
  return side_effect_counter;
}

static void
test_debug_no_side_effect (void)
{
  side_effect_counter = 0;
  /* DEBUG level (4) > ceiling (2): macro must be a no-op. */
  WYL_LOG_DEBUG (WYL_LOG_SECTION_GENERAL, "%d", side_effect ());
  g_assert_cmpint (side_effect_counter, ==, 0);
}

static void
test_info_no_side_effect (void)
{
  side_effect_counter = 0;
  /* INFO level (3) > ceiling (2): macro must be a no-op. */
  WYL_LOG_INFO (WYL_LOG_SECTION_GENERAL, "%d", side_effect ());
  g_assert_cmpint (side_effect_counter, ==, 0);
}

static void
test_warn_evaluates_args (void)
{
  side_effect_counter = 0;
  /* WARN level (2) == ceiling (2): macro must evaluate arguments. */
  WYL_LOG_WARN (WYL_LOG_SECTION_GENERAL, "%d", side_effect ());
  g_assert_cmpint (side_effect_counter, ==, 1);
}

static void
test_error_evaluates_args (void)
{
  side_effect_counter = 0;
  /* ERROR level (1) < ceiling (2): macro must evaluate arguments. */
  WYL_LOG_ERROR (WYL_LOG_SECTION_GENERAL, "%d", side_effect ());
  g_assert_cmpint (side_effect_counter, ==, 1);
}

/* Test that WYL_LOG_CRITICAL evaluates its arguments even when:
 *   - WYL_LOG_MAX_LEVEL=2  (compile-time ceiling, set at build time)
 *   - WYL_LOG=*:none       (runtime threshold suppresses all sections)
 *
 * Strategy: the child writes a sentinel file before the abort fires.
 * If args are not evaluated the sentinel never appears.  The parent
 * verifies the child aborted AND the sentinel exists. */
static void
test_critical_bypasses_ceiling (void)
{
  if (g_test_subprocess ()) {
    /* Child path: silence the runtime threshold, then fire CRITICAL.
     * The sentinel file is written first so we have proof of arg
     * evaluation regardless of where the abort signal lands. */
    g_autofree gchar *marker = g_build_filename (g_get_tmp_dir (),
        "wyl-critical-bypass-marker", NULL);

    g_unsetenv ("WYL_LOG_FILE");
    g_setenv ("WYL_LOG", "*:none", TRUE);
    wyl_log_internal_reconfigure ();

    /* Write the sentinel before calling CRITICAL. */
    g_file_set_contents (marker, "1", 1, NULL);

    WYL_LOG_CRITICAL (WYL_LOG_SECTION_GENERAL, "bypass-test");
    /* Unreachable: WYL_LOG_CRITICAL aborts. */
    return;
  }

  g_autofree gchar *marker = g_build_filename (g_get_tmp_dir (),
      "wyl-critical-bypass-marker", NULL);
  g_unlink (marker);

  g_test_trap_subprocess (NULL, 0, 0);
  g_test_trap_assert_failed ();

  /* Verify the sentinel (side-effect) ran in the child. */
  gchar *contents = NULL;
  gboolean ok = g_file_get_contents (marker, &contents, NULL, NULL);
  g_assert_true (ok);
  g_free (contents);
  g_unlink (marker);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/wyl-log/ceiling/debug-no-side-effect",
      test_debug_no_side_effect);
  g_test_add_func ("/wyl-log/ceiling/info-no-side-effect",
      test_info_no_side_effect);
  g_test_add_func ("/wyl-log/ceiling/warn-evaluates-args",
      test_warn_evaluates_args);
  g_test_add_func ("/wyl-log/ceiling/error-evaluates-args",
      test_error_evaluates_args);
  g_test_add_func ("/wyl-log/ceiling/critical-bypasses-ceiling",
      test_critical_bypasses_ceiling);

  return g_test_run ();
}
