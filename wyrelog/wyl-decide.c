/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _wyl_decide_req
{
  gchar *subject_id;
  gchar *action;
  gchar *resource_id;
};

struct _wyl_decide_resp
{
  gint placeholder;
};

wyl_decide_req_t *
wyl_decide_req_new (void)
{
  return g_new0 (wyl_decide_req_t, 1);
}

void
wyl_decide_req_free (wyl_decide_req_t *req)
{
  if (req == NULL)
    return;
  g_free (req->subject_id);
  g_free (req->action);
  g_free (req->resource_id);
  g_free (req);
}

void
wyl_decide_req_set_subject_id (wyl_decide_req_t *req, const gchar *subject_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->subject_id);
  req->subject_id = g_strdup (subject_id);
}

const gchar *
wyl_decide_req_get_subject_id (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->subject_id;
}

void
wyl_decide_req_set_action (wyl_decide_req_t *req, const gchar *action)
{
  g_return_if_fail (req != NULL);
  g_free (req->action);
  req->action = g_strdup (action);
}

const gchar *
wyl_decide_req_get_action (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->action;
}

void
wyl_decide_req_set_resource_id (wyl_decide_req_t *req, const gchar *resource_id)
{
  g_return_if_fail (req != NULL);
  g_free (req->resource_id);
  req->resource_id = g_strdup (resource_id);
}

const gchar *
wyl_decide_req_get_resource_id (const wyl_decide_req_t *req)
{
  g_return_val_if_fail (req != NULL, NULL);
  return req->resource_id;
}

wyl_decide_resp_t *
wyl_decide_resp_new (void)
{
  return g_new0 (wyl_decide_resp_t, 1);
}

void
wyl_decide_resp_free (wyl_decide_resp_t *resp)
{
  g_free (resp);
}

wyrelog_error_t
wyl_decide (WylHandle *handle, const wyl_decide_req_t *req,
    wyl_decide_resp_t *resp)
{
  (void) handle;
  (void) req;
  (void) resp;
  return WYRELOG_E_INTERNAL;
}
