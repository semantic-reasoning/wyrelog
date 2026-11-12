/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SA_RESTART and struct sigaction require POSIX-2001 visibility, which
 * is not exposed under strict c_std=c17 unless we ask for it. */
#define _POSIX_C_SOURCE 200809L

#include "daemon/signals.h"

#include <signal.h>
#include <string.h>

#ifdef G_OS_UNIX
#include <glib-unix.h>
#elif defined(G_OS_WIN32)
#include <windows.h>
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

#elif defined(G_OS_WIN32)
static volatile LONG console_shutdown_requested = 0;
static gboolean console_handler_installed = FALSE;

static BOOL WINAPI
console_ctrl_handler (DWORD event)
{
  if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT)
    return FALSE;
  /* This runs on a Windows console thread. The runtime's main-context
   * polling source owns loop and storage teardown. */
  InterlockedExchange (&console_shutdown_requested, 1);
  return TRUE;
}

void
wyl_daemon_install_early_signal_handlers (void)
{
  if (console_handler_installed)
    return;
  InterlockedExchange (&console_shutdown_requested, 0);
  if (!SetConsoleCtrlHandler (console_ctrl_handler, TRUE))
    g_error ("Cannot install daemon console handler: %lu",
        (unsigned long) GetLastError ());
  console_handler_installed = TRUE;
}

gboolean
wyl_daemon_early_signal_received (void)
{
  return InterlockedCompareExchange (&console_shutdown_requested, 0, 0) != 0;
}

void
wyl_daemon_install_signal_handlers (GMainLoop *loop, guint *sigint_id,
    guint *sigterm_id)
{
  (void) loop;
  *sigint_id = 0;
  *sigterm_id = 0;
}

#endif

void
wyl_daemon_signal_scope_clear (WylDaemonSignalScope *scope)
{
#ifdef G_OS_WIN32
  if (scope->installed && console_handler_installed) {
    if (!SetConsoleCtrlHandler (console_ctrl_handler, FALSE))
      g_error ("Cannot remove daemon console handler: %lu",
          (unsigned long) GetLastError ());
    console_handler_installed = FALSE;
  }
#endif
  scope->installed = FALSE;
}

void
wyl_daemon_remove_signal_handler (guint *source_id)
{
  if (*source_id != 0) {
    g_source_remove (*source_id);
    *source_id = 0;
  }
}

void
wyl_daemon_run_main_loop (GMainLoop *loop)
{
  if (!wyl_daemon_early_signal_received ())
    g_main_loop_run (loop);
}
