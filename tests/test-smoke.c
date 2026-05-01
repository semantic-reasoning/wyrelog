/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/error.h"

int
main (void)
{
  const char *msg = wyrelog_error_string (WYRELOG_E_OK);

  if (msg == NULL || msg[0] == '\0')
    return 1;

  return 0;
}
