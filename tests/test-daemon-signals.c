/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Include the production implementation to exercise the console callback
 * before loop dispatch, without broadcasting an event to the runner. */
#include "../wyrelog/daemon/signals.c"
#include "test-exit-status.h"

typedef struct
{
  GMainLoop *loop;
  gboolean visited;
} LoopProbe;

static gboolean
finish_normal_loop (gpointer data)
{
  LoopProbe *probe = data;
  probe->visited = TRUE;
  g_main_loop_quit (probe->loop);
  return G_SOURCE_REMOVE;
}

static gboolean unexpected_source (gpointer data);

static void
test_early_and_repeated_shutdown (void)
{
#ifdef G_OS_WIN32
  gboolean own_console = GetConsoleCP () == 0;
  if (own_console)
    g_assert_true (AllocConsole ());
#endif
  WylDaemonSignalScope scope = { TRUE };
  wyl_daemon_install_early_signal_handlers ();
  g_assert_false (wyl_daemon_early_signal_received ());
  g_autoptr (GMainLoop) loop = g_main_loop_new (NULL, FALSE);
  LoopProbe probe = { loop, FALSE };
  guint normal = g_idle_add (finish_normal_loop, &probe);
  wyl_daemon_run_main_loop (loop);
  if (!probe.visited)
    g_source_remove (normal);
  g_assert_true (probe.visited);
#ifdef G_OS_WIN32
  g_assert_false (console_ctrl_handler (CTRL_CLOSE_EVENT));
  g_assert_false (wyl_daemon_early_signal_received ());
  g_assert_true (console_ctrl_handler (CTRL_BREAK_EVENT));
  g_assert_true (console_ctrl_handler (CTRL_C_EVENT));
#else
  g_assert_cmpint (raise (SIGTERM), ==, 0);
  g_assert_cmpint (raise (SIGINT), ==, 0);
#endif
  g_assert_true (wyl_daemon_early_signal_received ());
  guint interrupt_id = 0;
  guint terminate_id = 0;
  wyl_daemon_install_signal_handlers (loop, &interrupt_id, &terminate_id);
  g_assert_true (wyl_daemon_early_signal_received ());
  guint pending = g_idle_add (unexpected_source, NULL);
  wyl_daemon_run_main_loop (loop);
  g_source_remove (pending);
  wyl_daemon_remove_signal_handler (&interrupt_id);
  wyl_daemon_remove_signal_handler (&terminate_id);
  wyl_daemon_signal_scope_clear (&scope);
  g_assert_false (scope.installed);
#ifdef G_OS_WIN32
  g_assert_false (console_handler_installed);
  if (own_console)
    g_assert_true (FreeConsole ());
#endif
}

static gboolean
unexpected_source (gpointer data)
{
  (void) data;
  g_assert_not_reached ();
  return G_SOURCE_REMOVE;
}

static void
test_source_cleanup (void)
{
  guint source = g_idle_add (unexpected_source, NULL);
  wyl_daemon_remove_signal_handler (&source);
  g_assert_cmpuint (source, ==, 0);
  wyl_daemon_remove_signal_handler (&source);
  while (g_main_context_iteration (NULL, FALSE)) {
  }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/daemon-signals/early-and-repeated-shutdown",
      test_early_and_repeated_shutdown);
  g_test_add_func ("/daemon-signals/source-cleanup", test_source_cleanup);
  return wyl_test_normalize_exit_status (g_test_run ());
}
