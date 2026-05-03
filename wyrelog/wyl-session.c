/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

#include "wyl-id-private.h"

struct _WylSession
{
  GObject parent_instance;
  wyl_id_t id;
  gint64 created_at_us;
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
  /* Stamp the session with a fresh id and timestamp at login time so
   * audit events emitted on its behalf can be correlated back to the
   * specific session that produced them. The stamps are independent
   * of wyl_session_id_t (the integer handle exposed for logout
   * dispatch) -- this id is the long-lived persistence-side
   * identifier. Failure to mint an id is fatal for the same reason
   * it is on WylAuditEvent and WylHandle: a zero-id session would
   * collapse correlation downstream. */
  if (wyl_id_new (&self->id) != WYRELOG_E_OK)
    g_error ("wyl_session_init: failed to mint identifier");
  self->created_at_us = g_get_real_time ();
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

gchar *
wyl_session_dup_id_string (const WylSession *self)
{
  gchar buf[WYL_ID_STRING_BUF];

  g_return_val_if_fail (WYL_IS_SESSION (self), NULL);

  if (wyl_id_format (&self->id, buf, sizeof buf) != WYRELOG_E_OK)
    return NULL;
  return g_strdup (buf);
}

gint64
wyl_session_get_created_at_us (const WylSession *self)
{
  g_return_val_if_fail (WYL_IS_SESSION (self), -1);
  return self->created_at_us;
}
