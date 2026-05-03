/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

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

  return g_test_run ();
}
