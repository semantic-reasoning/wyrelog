/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/error.h"
#include "wyrelog/wyrelog.h"

int
main (void)
{
  const char *msg = wyrelog_error_string (WYRELOG_E_OK);

  if (msg == NULL || msg[0] == '\0')
    return 1;

  const char *version = wyrelog_version_string ();
  if (version == NULL || version[0] == '\0')
    return 2;

  /* Input validation: NULL out_handle must be rejected. */
  if (wyl_init ("ignored", NULL) != WYRELOG_E_INVALID)
    return 3;

  /* Successful path returns a non-NULL WylHandle. */
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 4;
  if (handle == NULL)
    return 5;

  return 0;
}
