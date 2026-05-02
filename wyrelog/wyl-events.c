/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-events-private.h"

static const gchar *const domain_names[] = {
  "principal",
  "session",
};

G_STATIC_ASSERT (G_N_ELEMENTS (domain_names) == WYL_ACCESS_EVENT_DOMAIN_LAST_);

const gchar *
wyl_access_event_domain_name (wyl_access_event_domain_t domain)
{
  if ((guint) domain >= WYL_ACCESS_EVENT_DOMAIN_LAST_)
    return NULL;
  return domain_names[domain];
}

const gchar *
wyl_access_event_kind_name (const wyl_access_event_t *event)
{
  if (event == NULL)
    return NULL;
  switch (event->domain) {
    case WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL:
      return wyl_principal_event_name (event->event.principal);
    case WYL_ACCESS_EVENT_DOMAIN_SESSION:
      return wyl_session_event_name (event->event.session);
    case WYL_ACCESS_EVENT_DOMAIN_LAST_:
    default:
      return NULL;
  }
}

gsize
wyl_access_event_total_kinds (void)
{
  return (gsize) WYL_PRINCIPAL_EVENT_LAST_ + (gsize) WYL_SESSION_EVENT_LAST_;
}
