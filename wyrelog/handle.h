/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>
#include <glib-object.h>

#include "wyrelog/error.h"

G_BEGIN_DECLS;

/*
 * WylHandle - server-side embedding handle.
 *
 * Owns the policy database, audit log, and worker threads of an
 * embedded wyrelog instance. Created with wyl_init, shut down with
 * wyl_shutdown, released with g_object_unref (or g_autoptr(WylHandle)
 * in scoped form).
 */
G_DECLARE_FINAL_TYPE (WylHandle, wyl_handle, WYL, HANDLE, GObject);
#define WYL_TYPE_HANDLE (wyl_handle_get_type ())

/* Lifecycle */
wyrelog_error_t wyl_init (const gchar * config_path, WylHandle ** out_handle);
void wyl_shutdown (WylHandle * handle);

/*
 * Returns the handle's construct-time identifier as a 36-character
 * canonical string (caller frees with g_free or g_autofree). May
 * return NULL only if the handle is NULL or not a WylHandle. The id
 * is stable for the lifetime of the handle so log lines, audit
 * events, and metrics emitted by the daemon can be correlated back
 * to a specific embedding instance.
 */
gchar *wyl_handle_dup_id_string (const WylHandle * self);

/*
 * Returns the construct-time wall-clock stamp in microseconds since
 * the Unix epoch (g_get_real_time). Returns -1 on a NULL argument.
 */
gint64 wyl_handle_get_created_at_us (const WylHandle * self);

G_END_DECLS;
