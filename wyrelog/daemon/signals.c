/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "daemon/signals.h"

#include <signal.h>

#ifdef G_OS_UNIX
#include <glib-unix.h>
#endif

#ifdef G_OS_UNIX
static gboolean
quit_loop_from_signal (gpointer user_data)
{
  GMainLoop *loop = user_data;

  g_main_loop_quit (loop);
  return G_SOURCE_CONTINUE;
}

void
wyl_daemon_install_signal_handlers (GMainLoop *loop, guint *sigint_id,
    guint *sigterm_id)
{
  *sigint_id = g_unix_signal_add (SIGINT, quit_loop_from_signal, loop);
  *sigterm_id = g_unix_signal_add (SIGTERM, quit_loop_from_signal, loop);
}

void
wyl_daemon_remove_signal_handler (guint *source_id)
{
  if (*source_id != 0) {
    g_source_remove (*source_id);
    *source_id = 0;
  }
}
#else
void
wyl_daemon_install_signal_handlers (GMainLoop *loop, guint *sigint_id,
    guint *sigterm_id)
{
  (void) loop;
  *sigint_id = 0;
  *sigterm_id = 0;
}

void
wyl_daemon_remove_signal_handler (guint *source_id)
{
  (void) source_id;
}
#endif
