/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <errno.h>

#include <glib.h>

static inline gboolean
wyl_posix_errno_is_operation_unsupported (int error_code)
{
  if (error_code == ENOTSUP)
    return TRUE;
#if EOPNOTSUPP != ENOTSUP
  if (error_code == EOPNOTSUPP)
    return TRUE;
#endif
  return FALSE;
}
