/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/client.h"

struct _WylAuditIter
{
  GObject parent_instance;
};

G_DEFINE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, G_TYPE_OBJECT);

static void
wyl_audit_iter_class_init (WylAuditIterClass *klass)
{
  (void) klass;
}

static void
wyl_audit_iter_init (WylAuditIter *self)
{
  (void) self;
}

wyrelog_error_t
wyl_client_audit_query (WylClient *client, const gchar *query_filter,
    WylAuditIter **out_iter)
{
  (void) client;
  (void) query_filter;

  if (out_iter == NULL)
    return WYRELOG_E_INVALID;

  *out_iter = g_object_new (WYL_TYPE_AUDIT_ITER, NULL);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_audit_iter_next (WylAuditIter *iter, gboolean *out_has_next)
{
  (void) iter;

  if (out_has_next == NULL)
    return WYRELOG_E_INVALID;

  *out_has_next = FALSE;
  return WYRELOG_E_OK;
}
