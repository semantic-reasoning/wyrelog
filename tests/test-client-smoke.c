/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stddef.h>

#include "wyrelog/client.h"

int
main (void)
{
  const char *version = wyrelog_client_version_string ();
  if (version == NULL || version[0] == '\0')
    return 1;

  /* Input validation: NULL out_client must be rejected. */
  if (wyl_client_new ("http://example.invalid", NULL) != WYRELOG_E_INVALID)
    return 2;

  /* Successful path returns a non-NULL WylClient. */
  g_autoptr (WylClient) client = NULL;
  if (wyl_client_new ("http://example.invalid", &client) != WYRELOG_E_OK)
    return 3;
  if (client == NULL)
    return 4;

  /* Audit iterator returns a non-NULL WylAuditIter on success and
   * yields no rows in the stub state. */
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (client, NULL, &iter) != WYRELOG_E_OK)
    return 5;
  if (iter == NULL)
    return 6;

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return 7;
  if (has_next != FALSE)
    return 8;

  return 0;
}
