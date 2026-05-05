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

#ifdef WYL_TEST_HAS_AUDIT
  g_autoptr (WylAuditIter) start_iter = NULL;
  if (wyl_client_audit_query (client, "action(\"daemon_start\")", &start_iter)
      != WYRELOG_E_OK)
    return 8;

  has_next = FALSE;
  if (wyl_audit_iter_next (start_iter, &has_next) != WYRELOG_E_OK)
    return 9;
  if (!has_next)
    return 10;
  g_autoptr (WylAuditEvent) start_event = wyl_audit_iter_ref_event (start_iter);
  if (start_event == NULL)
    return 13;
  if (g_strcmp0 (wyl_audit_event_get_action (start_event), "daemon_start")
      != 0)
    return 14;

  has_next = TRUE;
  if (wyl_audit_iter_next (start_iter, &has_next) != WYRELOG_E_OK)
    return 11;
  if (has_next)
    return 12;
#endif

  return 0;
}
