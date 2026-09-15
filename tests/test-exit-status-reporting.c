/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>

#include "test-exit-status.h"

static int
check_alpha (void)
{
  return 1601;
}

static int
check_beta (void)
{
  return 1601;
}

int
main (int argc, char **argv)
{
  if (argc > 1 && strcmp (argv[1], "second") == 0)
    return wyl_test_normalize_exit_status_named ("check-beta", check_beta ());
  return wyl_test_normalize_exit_status_named ("check-alpha", check_alpha ());
}
