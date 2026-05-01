/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyrelog/wyrelog.h"

struct _wyl_login_req
{
  int placeholder;
};

struct _wyl_grant_req
{
  int placeholder;
};

struct _wyl_revoke_req
{
  int placeholder;
};

wyl_login_req_t *
wyl_login_req_new (void)
{
  return g_new0 (wyl_login_req_t, 1);
}

void
wyl_login_req_free (wyl_login_req_t *req)
{
  g_free (req);
}

wyl_grant_req_t *
wyl_grant_req_new (void)
{
  return g_new0 (wyl_grant_req_t, 1);
}

void
wyl_grant_req_free (wyl_grant_req_t *req)
{
  g_free (req);
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
