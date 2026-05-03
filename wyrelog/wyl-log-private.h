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
 *   WYL_LOG_CRITICAL(s,...) -> BYPASSES WYL_LOG_MAX_LEVEL ceiling,
 *                              G_LOG_LEVEL_ERROR    (invariant violation;
 *                              GLib calls abort() — program terminates)
 *
 * The ERROR/CRITICAL inversion is deliberate: GLib treats
 * G_LOG_LEVEL_ERROR as always-fatal (abort()) and G_LOG_LEVEL_CRITICAL
 * as non-fatal. WYL_LOG_ERROR is for handled-but-bad events;
 * WYL_LOG_CRITICAL is reserved for unrecoverable invariant violations
 * and must NOT be used for errors that are expected to be handled.
 *
 * WYL_LOG_DEBUG/INFO/WARN/ERROR are subject to WYL_LOG_MAX_LEVEL and
 * may compile to no-ops (G_STMT_START {} G_STMT_END) when the ceiling
 * is set below their required level — arguments are never evaluated in
 * that case (compile-time dead-code elimination, no side-effects).
 *
 * WYL_LOG_CRITICAL bypasses WYL_LOG_MAX_LEVEL entirely because
 * invariant violations must always abort, even under
 * -Dwyrelog_log_max_level=none. Silencing an abort-class invariant
 * violation is a safety defect, not a tuning option.
 *
 * All macros pass __FILE__, __LINE__, and G_STRFUNC to the internal
 * entry point so the formatted output includes source location.
 */

#define WYL_LOG_DEBUG(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_DEBUG <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured_at ((section), G_LOG_LEVEL_DEBUG, \
          __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_INFO(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_INFO <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured_at ((section), G_LOG_LEVEL_INFO, \
          __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_WARN(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_WARN <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured_at ((section), G_LOG_LEVEL_WARNING, \
          __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
  } G_STMT_END

#define WYL_LOG_ERROR(section, ...) \
  G_STMT_START { \
    if (WYL_LOG_LEVEL_ERROR <= WYL_LOG_MAX_LEVEL) \
      wyl_log_structured_at ((section), G_LOG_LEVEL_CRITICAL, \
          __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
  } G_STMT_END

/* WYL_LOG_CRITICAL bypasses WYL_LOG_MAX_LEVEL because invariant
 * violations must always abort. Setting -Dwyrelog_log_max_level=none
 * still emits and aborts for CRITICAL. Use ONLY for unrecoverable
 * invariant violations. Do NOT invoke for errors that callers are
 * expected to handle; use WYL_LOG_ERROR instead. */
#define WYL_LOG_CRITICAL(section, ...) \
  G_STMT_START { \
    wyl_log_structured_at ((section), G_LOG_LEVEL_ERROR, \
        __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); \
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
 *
 * Output routing note: the writer routes each record to the file sink
 * (WYL_LOG_FILE) XOR stderr — tee-style logging to both is not
 * supported in v0. fflush() errors are not currently propagated;
 * persistent I/O errors silently drop records.
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

/* Primary structured log entry point. Accepts source location fields
 * (file, line, func) that are emitted as CODE_FILE / CODE_LINE /
 * CODE_FUNC GLib structured fields and included in the formatted
 * output line. Callers use the WYL_LOG_* macros which supply
 * __FILE__, __LINE__, G_STRFUNC automatically.
 *
 * wyl_log_structured is a thin wrapper that passes NULL / 0 / NULL for
 * location fields; it exists for call sites (e.g. tests) that do not
 * need source attribution. */
void
wyl_log_structured_at (wyl_log_section_t section, GLogLevelFlags level,
    const char *file, gint line, const char *func, const char *fmt, ...)
G_GNUC_PRINTF (6, 7);

     void wyl_log_structured (wyl_log_section_t section, GLogLevelFlags level,
    const char *fmt, ...)
  G_GNUC_PRINTF (3, 4);

/* Internal hooks (suffix _internal_: not stable API). */
     gint wyl_log_internal_get_section_level (wyl_log_section_t section);
     void wyl_log_internal_parse_spec (const char *spec,
    gint8 levels[WYL_LOG_SECTION_LAST_]);

/* wyl_log_internal_reconfigure — reload log configuration from env vars.
 *
 * Re-reads WYL_LOG (section:level spec) and WYL_LOG_FILE (output path)
 * on each call. If WYL_LOG_FILE changes, the prior file is closed and
 * the new path opened in append mode.
 *
 * Properties:
 *   - Idempotent: calling it multiple times with the same environment
 *     is equivalent to calling it once; the prior sink is closed and
 *     reopened on each call.
 *   - Thread-safe: section levels are updated under log_mutex; the
 *     file sink is swapped under sink_mutex. The two locks are never
 *     held simultaneously.
 *   - NOT async-signal-safe: do NOT call from signal handlers. The
 *     function acquires mutexes and calls fopen/fclose.
 *   - NOT safe across fork(2). The file FILE* is inherited along with
 *     its userspace stdio buffer. The child MUST NOT call fclose on
 *     the inherited handle (which would flush shared OS-level buffers
 *     and potentially corrupt the parent's pending writes); instead
 *     the child should construct a fresh log state from scratch (e.g.
 *     via wyl_log_internal_reconfigure after the inherited FILE* has
 *     been abandoned with freopen(/dev/null, ...) or by re-execing). */
     void wyl_log_internal_reconfigure (void);
