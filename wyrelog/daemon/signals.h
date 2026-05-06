/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

void wyl_daemon_install_early_signal_handlers (void);
gboolean wyl_daemon_early_signal_received (void);

void wyl_daemon_install_signal_handlers (GMainLoop * loop, guint * sigint_id,
    guint * sigterm_id);
void wyl_daemon_remove_signal_handler (guint * source_id);
