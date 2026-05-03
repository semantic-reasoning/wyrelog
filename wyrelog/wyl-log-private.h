/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#ifndef WYL_LOG_DOMAIN
#define WYL_LOG_DOMAIN "wyrelog"
#endif

/*
 * Section-aware, compile-time-ceiling-aware severity macros.
 *
 * Every macro takes a WYL_LOG_SECTION_* constant as its first argument
 * followed by a printf-style format and variadic arguments.
 *
 * Mapping onto GLib log levels (ERROR/CRITICAL intentionally inverted):
 *
 *   WYL_LOG_DEBUG(s,...)    -> WYL_LOG_LEVEL_DEBUG  ceiling,
 *                              G_LOG_LEVEL_DEBUG
 *   WYL_LOG_INFO(s,...)     -> WYL_LOG_LEVEL_INFO   ceiling,
 *                              G_LOG_LEVEL_INFO
 *   WYL_LOG_WARN(s,...)     -> WYL_LOG_LEVEL_WARN   ceiling,
 *                              G_LOG_LEVEL_WARNING
 *   WYL_LOG_ERROR(s,...)    -> WYL_LOG_LEVEL_ERROR  ceiling,
 *                              G_LOG_LEVEL_CRITICAL (recoverable;
 *                              program continues)
 *   WYL_LOG_CRITICAL(s,...) -> WYL_LOG_LEVEL_ERROR  ceiling,
 *                              G_LOG_LEVEL_ERROR    (invariant violation;
 *                              GLib calls abort() — program terminates)
 *
 * The ERROR/CRITICAL inversion is deliberate: GLib treats
 * G_LOG_LEVEL_ERROR as always-fatal (abort()) and G_LOG_LEVEL_CRITICAL
 * as non-fatal. WYL_LOG_ERROR is for handled-but-bad events;
 * WYL_LOG_CRITICAL is reserved for unrecoverable invariant violations
 * and must NOT be used for errors that are expected to be handled.
 *
 * When WYL_LOG_MAX_LEVEL is below the macro's required level the macro
 * expands to G_STMT_START {} G_STMT_END so arguments are never
 * evaluated (compile-time dead-code elimination, no side-effects).
 */

#define WYL_LOG_DEBUG(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_DEBUG <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured ((section), G_LOG_LEVEL_DEBUG, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_INFO(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_INFO <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured ((section), G_LOG_LEVEL_INFO, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_WARN(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_WARN <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured ((section), G_LOG_LEVEL_WARNING, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_ERROR(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_ERROR <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured ((section), G_LOG_LEVEL_CRITICAL, __VA_ARGS__); \
  } G_STMT_END

/* WYL_LOG_CRITICAL expands to G_LOG_LEVEL_ERROR which GLib treats as
 * always-fatal (calls abort()). Use ONLY for unrecoverable invariant
 * violations. Do NOT invoke for errors that callers are expected to
 * handle; use WYL_LOG_ERROR instead. */
#define WYL_LOG_CRITICAL(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_ERROR <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured ((section), G_LOG_LEVEL_ERROR, __VA_ARGS__); \
  } G_STMT_END

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

/* Internal hooks (suffix _internal_: not stable API). */
     gint wyl_log_internal_get_section_level (wyl_log_section_t section);
     void wyl_log_internal_parse_spec (const char *spec,
    gint8 levels[WYL_LOG_SECTION_LAST_]);
     void wyl_log_internal_reconfigure (void);
