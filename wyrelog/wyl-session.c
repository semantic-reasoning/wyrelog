/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _WylSession
{
  GObject parent_instance;
};

G_DEFINE_FINAL_TYPE (WylSession, wyl_session, G_TYPE_OBJECT);

static void
wyl_session_class_init (WylSessionClass *klass)
{
  (void) klass;
}

static void
wyl_session_init (WylSession *self)
{
  (void) self;
}

wyrelog_error_t
wyl_session_login (WylHandle *handle, const wyl_login_req_t *req,
    WylSession **out_session)
{
  (void) handle;
  (void) req;

  if (out_session == NULL)
    return WYRELOG_E_INVALID;

  *out_session = g_object_new (WYL_TYPE_SESSION, NULL);
  return WYRELOG_E_OK;
}

wyrelog_error_t
wyl_session_logout (WylHandle *handle, wyl_session_id_t sid)
{
  (void) handle;
  (void) sid;
  return WYRELOG_E_INTERNAL;
}
