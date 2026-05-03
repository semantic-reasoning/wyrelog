/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#ifndef WYL_LOG_DOMAIN
#define WYL_LOG_DOMAIN "wyrelog"
#endif

/*
 * Severity macros mapped onto GLib log levels:
 *
 *   WYL_LOG_DEBUG    -> G_LOG_LEVEL_DEBUG     (verbose)
 *   WYL_LOG_INFO     -> G_LOG_LEVEL_INFO      (informational)
 *   WYL_LOG_WARN     -> G_LOG_LEVEL_WARNING   (recoverable warning)
 *   WYL_LOG_ERROR    -> G_LOG_LEVEL_CRITICAL  (recoverable error;
 *                                              program continues)
 *   WYL_LOG_CRITICAL -> G_LOG_LEVEL_ERROR     (invariant violation;
 *                                              terminates the program)
 *
 * The mapping for ERROR/CRITICAL is intentionally inverted relative to
 * the GLib level names because GLib treats G_LOG_LEVEL_ERROR as
 * always-fatal (it calls abort()) and G_LOG_LEVEL_CRITICAL as
 * non-fatal. Library code reaches for WYL_LOG_ERROR to record handled
 * but bad events; only WYL_LOG_CRITICAL is intended to terminate.
 */

#define WYL_LOG_DEBUG(...) \
  g_log (WYL_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define WYL_LOG_INFO(...) \
  g_log (WYL_LOG_DOMAIN, G_LOG_LEVEL_INFO, __VA_ARGS__)
#define WYL_LOG_WARN(...) \
  g_log (WYL_LOG_DOMAIN, G_LOG_LEVEL_WARNING, __VA_ARGS__)
#define WYL_LOG_ERROR(...) \
  g_log (WYL_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL, __VA_ARGS__)
#define WYL_LOG_CRITICAL(...) \
  g_log (WYL_LOG_DOMAIN, G_LOG_LEVEL_ERROR, __VA_ARGS__)

/* --- Section grammar -------------------------------------------------
 *
 * Sections are coarse functional buckets that operators filter on at
 * runtime via WYL_LOG=SECTION:LEVEL[,...]. Adding a new section is
 * load-bearing for the parser test suite: any new value before
 * WYL_LOG_SECTION_LAST_ must also appear in the static name table in
 * wyl-log.c.
 *
 * Section names are operator-visible (they appear in env-var input
 * and in formatted log output). Names are deliberately neutral and
 * do not advertise wyrelog-internal axioms.
 */
typedef enum
{
  WYL_LOG_SECTION_BOOT = 0,
  WYL_LOG_SECTION_POLICY,
  WYL_LOG_SECTION_SESSION,
  WYL_LOG_SECTION_DECISION,
  WYL_LOG_SECTION_AUDIT,
  WYL_LOG_SECTION_IO,
  WYL_LOG_SECTION_GENERAL,
  WYL_LOG_SECTION_LAST_,
} wyl_log_section_t;

/* Numeric levels match the WYL_LOG=*:N grammar. The runtime threshold
 * test is `wyl_level <= section_threshold`, so larger numbers are
 * more verbose. */
#define WYL_LOG_LEVEL_NONE   0
#define WYL_LOG_LEVEL_ERROR  1
#define WYL_LOG_LEVEL_WARN   2
#define WYL_LOG_LEVEL_INFO   3
#define WYL_LOG_LEVEL_DEBUG  4
#define WYL_LOG_LEVEL_TRACE  5

/* Compile-time ceiling supplied by meson via -DWYL_LOG_MAX_LEVEL=N.
 * Defaults to TRACE if the build system did not set it (e.g. when
 * compiling a single test file outside of meson). */
#ifndef WYL_LOG_MAX_LEVEL
#define WYL_LOG_MAX_LEVEL WYL_LOG_LEVEL_TRACE
#endif

/* Public-ish helpers (private header — intra-library only). */
const char *wyl_log_section_name (wyl_log_section_t section);
gint wyl_log_section_count (void);

/* Structured log entry point. Carries a WYL_SECTION GLib log field so
 * the wyrelog writer can route by section. Callers normally reach for
 * the section-aware macros that arrive in a follow-up commit; this
 * function is the single landing point those macros expand to. */
void
wyl_log_structured (wyl_log_section_t section, GLogLevelFlags level,
    const char *fmt, ...)
G_GNUC_PRINTF (3, 4);

/*
 * Internal hooks (suffix _internal_: not stable API). Exposed so the
 * parser-test suite can drive the spec parser without mutating
 * process-global env state, and so a future test can probe the
 * active section threshold table without reaching into static
 * storage.
 */
     void wyl_log_internal_parse_spec (const char *spec, gint8 *levels);
     gint wyl_log_internal_get_section_level (wyl_log_section_t section);
