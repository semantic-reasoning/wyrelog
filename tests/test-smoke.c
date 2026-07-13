/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/error.h"
#include "wyrelog/wyrelog.h"

G_STATIC_ASSERT (WYRELOG_E_OK == 0);
G_STATIC_ASSERT (WYRELOG_E_INVALID == -1);
G_STATIC_ASSERT (WYRELOG_E_NOMEM == -2);
G_STATIC_ASSERT (WYRELOG_E_IO == -3);
G_STATIC_ASSERT (WYRELOG_E_CRYPTO == -4);
G_STATIC_ASSERT (WYRELOG_E_POLICY == -5);
G_STATIC_ASSERT (WYRELOG_E_AUTH == -6);
G_STATIC_ASSERT (WYRELOG_E_INTERNAL == -7);
G_STATIC_ASSERT (WYRELOG_E_EXEC == -8);
G_STATIC_ASSERT (WYRELOG_E_NOT_FOUND == -9);
G_STATIC_ASSERT (WYRELOG_E_BREAK_GLASS_DISABLED == -10);
G_STATIC_ASSERT (WYRELOG_E_BUSY == -11);

int
main (void)
{
  const gchar *msg = wyrelog_error_string (WYRELOG_E_OK);

  if (msg == NULL || msg[0] == '\0')
    return 1;
  if (g_strcmp0 (wyrelog_error_string (WYRELOG_E_BUSY),
          "resource is busy") != 0)
    return 6;

  const gchar *version = wyrelog_version_string ();
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
