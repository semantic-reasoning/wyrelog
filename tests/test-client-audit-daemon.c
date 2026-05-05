/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/client.h"

int
main (int argc, char **argv)
{
  if (argc != 2)
    return 1;

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (argv[1], &client) != WYRELOG_E_OK)
    return 2;

  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return 3;

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return 4;
  if (has_next)
    return 5;

  has_next = TRUE;
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return 6;
  if (has_next)
    return 7;

  return 0;
}
