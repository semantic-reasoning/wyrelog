/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _wyl_login_req
{
  gchar *username;
};

struct _wyl_grant_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
};

struct _wyl_revoke_req
{
  gint placeholder;
};

wyl_login_req_t *
wyl_login_req_new (void)
{
  return g_new0 (wyl_login_req_t, 1);
}

void
wyl_login_req_free (wyl_login_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->username);
  g_free (req);
}

void
wyl_login_req_set_username (wyl_login_req_t *req, const gchar *username)
{
  g_return_if_fail (req != NULL);
  g_free (req->username);
  req->username = g_strdup (username);
}

const gchar *
wyl_login_req_get_username (const wyl_login_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->username;
}

wyl_grant_req_t *
wyl_grant_req_new (void)
{
  return g_new0 (wyl_grant_req_t, 1);
}

void
wyl_grant_req_free (wyl_grant_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->action);
  g_free (req->resource_id);
  g_free (req);
}

void
wyl_grant_req_set_subject_id (wyl_grant_req_t *req, const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_grant_req_get_subject_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_grant_req_set_action (wyl_grant_req_t *req, const gchar *action)
{
  g_return_if_fail (req != NULL);
  g_free (req->action);
  req->action = g_strdup (action);
}

const gchar *
wyl_grant_req_get_action (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->action;
}

void
wyl_grant_req_set_resource_id (wyl_grant_req_t *req, const gchar *resource_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->resource_id);
  req->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_grant_req_get_resource_id (const wyl_grant_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->resource_id;
}

wyl_revoke_req_t *
wyl_revoke_req_new (void)
{
  return g_new0 (wyl_revoke_req_t, 1);
}

void
wyl_revoke_req_free (wyl_revoke_req_t *req)
{
  g_free (req);
}

wyrelog_error_t
wyl_perm_grant (WylHandle *handle, const wyl_grant_req_t *req)
{
  (void) handle;
  (void) req;
  return WYRELOG_E_INTERNAL;
}

wyrelog_error_t
wyl_perm_revoke (WylHandle *handle, const wyl_revoke_req_t *req)
{
  (void) handle;
  (void) req;
  return WYRELOG_E_INTERNAL;
}
