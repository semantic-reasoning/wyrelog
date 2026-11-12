/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

typedef struct
{
  gboolean installed;
} WylDaemonSignalScope;

void wyl_daemon_signal_scope_clear (WylDaemonSignalScope * scope);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC (WylDaemonSignalScope,
    wyl_daemon_signal_scope_clear)

void wyl_daemon_install_early_signal_handlers (void);
gboolean wyl_daemon_early_signal_received (void);

void wyl_daemon_install_signal_handlers (GMainLoop * loop, guint * sigint_id,
    guint * sigterm_id);
void wyl_daemon_remove_signal_handler (guint * source_id);

void wyl_daemon_run_main_loop (GMainLoop * loop);
