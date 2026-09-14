/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>

#include "wyrelog/client.h"

int
main (int argc, char **argv)
{
  if (argc != 2)
    return wyl_test_normalize_exit_status (1);

  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new (argv[1], &client) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (2);

  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (3);

  gboolean has_next = TRUE;
#ifdef WYL_TEST_HAS_AUDIT
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_IO)
    return wyl_test_normalize_exit_status (4);
  return wyl_test_normalize_exit_status (0);
#else
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (4);
  if (has_next)
    return wyl_test_normalize_exit_status (5);

  has_next = TRUE;
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return wyl_test_normalize_exit_status (6);
  if (has_next)
    return wyl_test_normalize_exit_status (7);
#endif

  return wyl_test_normalize_exit_status (0);
}
