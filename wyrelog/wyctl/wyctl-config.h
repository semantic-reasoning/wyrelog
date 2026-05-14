/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <gio/gio.h>
#include <glib.h>

G_BEGIN_DECLS;

#define WYCTL_GSETTINGS_SCHEMA_ID "org.wyrelog.wyctl"
#define WYCTL_GSETTINGS_DISABLE_ENV "WYCTL_DISABLE_GSETTINGS"

/* Open the wyctl GSettings tree, or return NULL if the schema is
 * not installed or the operator has set WYCTL_DISABLE_GSETTINGS=1.
 * Never aborts: a missing schema is reported as NULL, not g_error.
 * The returned object is owned by the caller; g_object_unref () to
 * release. */
GSettings *wyctl_open_settings (void);

/* Reconcile a CLI-supplied option with a GSettings fallback for a
 * string-typed key. Precedence: explicit CLI value > GSettings value
 * > unset. cli_value != NULL returns g_strdup (cli_value) — an empty
 * string is treated as a deliberate (if broken) user value, not as
 * absence. cli_value == NULL && settings != NULL reads the key from
 * GSettings; an empty string from the schema is the "unset" sentinel
 * and surfaces as NULL so the caller's missing-option diagnostic
 * remains the single source of truth. The returned string is always
 * owned by the caller (or NULL). Free with g_free (). */
gchar *wyctl_resolve_string_option (const gchar * cli_value,
    GSettings * settings, const gchar * key);

/* Same as wyctl_resolve_string_option, but the schema key is unsigned
 * 32-bit and the returned value is rendered with %u so it can be
 * threaded through the existing CLI parsers (e.g. parse_timeout_ms)
 * unchanged. */
gchar *wyctl_resolve_uint_option_as_string (const gchar * cli_value,
    GSettings * settings, const gchar * key);

G_END_DECLS;
