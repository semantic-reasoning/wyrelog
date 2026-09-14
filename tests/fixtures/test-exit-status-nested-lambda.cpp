/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../test-exit-status.h"

int
main ()
{
#ifdef WYL_TEST_OUTER_RETURN_MUTATION
  return wyl_test_normalize_exit_status (256);
#else
  const int nested_status = [] {
        return 256;
      } ();
  if (nested_status != 256)
    return wyl_test_normalize_exit_status (2);
  return wyl_test_normalize_exit_status (0);
#endif
}
