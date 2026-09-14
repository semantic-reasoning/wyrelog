/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile int *shared_state;

static void
mark_atexit (void)
{
  shared_state[1] = 1;
}

static int
run_termination_probe (int use__Exit)
{
  shared_state = mmap (NULL, 2 * sizeof (*shared_state),
          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (shared_state == MAP_FAILED)
    return 1;
  shared_state[0] = 0;
  shared_state[1] = 0;
  if (atexit (mark_atexit) != 0)
    return 2;

  pid_t child = fork ();
  if (child == -1)
    return 3;
  if (child == 0){
    int status = 512 - 256;
    if (use__Exit)
      WYL_TEST__EXIT ((*shared_state)++ ? 0 : status);
    WYL_TEST_EXIT ((*shared_state)++ ? 0 : status);
  }

  int wait_status = 0;
  if (waitpid (child, &wait_status, 0) != child)
    return 4;
  int ok = WIFEXITED (wait_status) && WEXITSTATUS (wait_status) == 1
      && shared_state[0] == 1 && shared_state[1] == 0;
  /* Keep the final mapping alive for the parent's registered atexit handler. */
  return ok ? 0 : 5;
}

int
main (void)
{
  int rc = run_termination_probe (0);
  if (rc != 0)
    return wyl_test_normalize_exit_status (rc);
  rc = run_termination_probe (1);
  return wyl_test_normalize_exit_status (rc);
}
