/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SA_RESTART and struct sigaction require POSIX-2001 visibility, which
 * is not exposed under strict c_std=c17 unless we ask for it. */
#define _POSIX_C_SOURCE 200809L

#include "daemon/signals.h"

#include <signal.h>
#include <string.h>

#ifdef G_OS_UNIX
#include <glib-unix.h>
#endif

#ifdef G_OS_UNIX
static volatile sig_atomic_t early_signal_received_flag = 0;

static void
early_signal_handler (int signum)
{
  (void) signum;
  early_signal_received_flag = 1;
}

void
wyl_daemon_install_early_signal_handlers (void)
{
  struct sigaction sa;

  memset (&sa, 0, sizeof (sa));
  sa.sa_handler = early_signal_handler;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
}

gboolean
wyl_daemon_early_signal_received (void)
{
  return early_signal_received_flag != 0;
}

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
wyl_daemon_install_early_signal_handlers (void)
{
}

gboolean
wyl_daemon_early_signal_received (void)
{
  return FALSE;
}

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
