/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <errno.h>

#include <glib.h>

#include "wyl-posix-errno-private.h"

static void
test_operation_unsupported_pair (void)
{
  g_assert_true (wyl_posix_errno_is_operation_unsupported (ENOTSUP));
  g_assert_true (wyl_posix_errno_is_operation_unsupported (EOPNOTSUPP));
  g_assert_false (wyl_posix_errno_is_operation_unsupported (EINVAL));
  g_assert_false (wyl_posix_errno_is_operation_unsupported (EIO));

#if defined(__linux__)
  g_assert_cmpint (ENOTSUP, ==, EOPNOTSUPP);
#elif defined(__APPLE__)
  g_assert_cmpint (ENOTSUP, !=, EOPNOTSUPP);
#endif
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/posix/errno/operation-unsupported-pair",
      test_operation_unsupported_pair);
  return g_test_run ();
}
