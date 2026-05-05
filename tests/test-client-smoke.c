/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/client.h"

int
main (void)
{
  const gchar *version = wyrelog_client_version_string ();
  if (version == NULL || version[0] == '\0')
    return 1;

  g_autoptr (WylClient) client = NULL;

  /* Input validation: NULL out_client must be rejected. */
  if (wyl_client_new ("http://example.invalid", NULL) != WYRELOG_E_INVALID)
    return 2;
  if (wyl_client_new (NULL, &client) != WYRELOG_E_INVALID)
    return 9;
  if (wyl_client_new ("", &client) != WYRELOG_E_INVALID)
    return 10;
  if (wyl_client_new ("file:///tmp/wyrelog.sock", &client) != WYRELOG_E_INVALID)
    return 11;

  /* Successful path returns a non-NULL WylClient. */
  client = NULL;
  if (wyl_client_new ("http://example.invalid", &client) != WYRELOG_E_OK)
    return 3;
  if (client == NULL)
    return 4;
  g_autofree gchar *base_url = wyl_client_dup_base_url (client);
  if (g_strcmp0 (base_url, "http://example.invalid") != 0)
    return 12;

  /* Audit iterator returns a non-NULL WylAuditIter on success and
   * yields no rows in the stub state. */
  g_autoptr (WylAuditIter) iter = NULL;
  if (wyl_client_audit_query (NULL, NULL, &iter) != WYRELOG_E_INVALID)
    return 13;
  if (wyl_client_audit_query (client, NULL, NULL) != WYRELOG_E_INVALID)
    return 14;
  if (wyl_client_audit_query (client, "decision=deny", &iter) != WYRELOG_E_OK)
    return 5;
  if (iter == NULL)
    return 6;
  g_autofree gchar *query_filter = wyl_audit_iter_dup_query_filter (iter);
  if (g_strcmp0 (query_filter, "decision=deny") != 0)
    return 15;
  g_autofree gchar *request_uri = wyl_audit_iter_dup_request_uri (iter);
  if (g_strcmp0 (request_uri,
          "http://example.invalid/audit/events?filter=decision%3Ddeny") != 0)
    return 16;

  gboolean has_next = TRUE;
  if (wyl_audit_iter_next (iter, &has_next) != WYRELOG_E_OK)
    return 7;
  if (has_next)
    return 8;

  return 0;
}
