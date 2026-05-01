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
