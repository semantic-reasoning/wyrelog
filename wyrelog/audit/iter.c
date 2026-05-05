/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/client.h"

struct _WylAuditIter
{
  GObject parent_instance;
  WylClient *client;
  gchar *query_filter;
};

G_DEFINE_FINAL_TYPE (WylAuditIter, wyl_audit_iter, G_TYPE_OBJECT);

static void
wyl_audit_iter_finalize (GObject *object)
{
  WylAuditIter *self = WYL_AUDIT_ITER (object);

  g_clear_object (&self->client);
  g_free (self->query_filter);

  G_OBJECT_CLASS (wyl_audit_iter_parent_class)->finalize (object);
}

static void
wyl_audit_iter_class_init (WylAuditIterClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = wyl_audit_iter_finalize;
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
  if (out_iter == NULL)
    return WYRELOG_E_INVALID;
  *out_iter = NULL;
  if (client == NULL || !WYL_IS_CLIENT (client))
    return WYRELOG_E_INVALID;

  WylAuditIter *iter = g_object_new (WYL_TYPE_AUDIT_ITER, NULL);
  iter->client = g_object_ref (client);
  iter->query_filter = g_strdup (query_filter);
  *out_iter = iter;
  return WYRELOG_E_OK;
}

gchar *
wyl_audit_iter_dup_query_filter (const WylAuditIter *iter)
{
  g_return_val_if_fail (WYL_IS_AUDIT_ITER ((WylAuditIter *) iter), NULL);
  return g_strdup (iter->query_filter);
}

wyrelog_error_t
wyl_audit_iter_next (WylAuditIter *iter, gboolean *out_has_next)
{
  if (iter == NULL || !WYL_IS_AUDIT_ITER (iter) || out_has_next == NULL)
    return WYRELOG_E_INVALID;

  *out_has_next = FALSE;
  return WYRELOG_E_OK;
}
