/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static gint
check_default_username_is_null (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  if (req == NULL)
    return 10;
  if (wyl_login_req_get_username (req) != NULL)
    return 11;
  if (wyl_login_req_get_skip_mfa (req))
    return 12;
  return 0;
}

static gint
check_set_then_get (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "alice");
  const gchar *got = wyl_login_req_get_username (req);
  if (got == NULL)
    return 20;
  if (strcmp (got, "alice") != 0)
    return 21;
  return 0;
}

static gint
check_caller_buffer_is_copied (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  gchar buf[16] = "bob";
  wyl_login_req_set_username (req, buf);
  /* Mutate the caller's buffer; the request should be unaffected. */
  buf[0] = 'X';
  const gchar *got = wyl_login_req_get_username (req);
  if (got == NULL)
    return 30;
  if (strcmp (got, "bob") != 0)
    return 31;
  return 0;
}

static gint
check_set_replaces_prior_value (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "first");
  wyl_login_req_set_username (req, "second");
  const gchar *got = wyl_login_req_get_username (req);
  if (got == NULL)
    return 40;
  if (strcmp (got, "second") != 0)
    return 41;
  return 0;
}

static gint
check_set_null_clears (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "carol");
  wyl_login_req_set_username (req, NULL);
  if (wyl_login_req_get_username (req) != NULL)
    return 50;
  return 0;
}

static gint
check_get_null_request (void)
{
  if (wyl_login_req_get_username (NULL) != NULL)
    return 60;
  return 0;
}

static gint
check_free_null_is_safe (void)
{
  wyl_login_req_free (NULL);
  return 0;
}

static gint
check_skip_mfa_set_then_get (void)
{
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_skip_mfa (req, TRUE);
  if (!wyl_login_req_get_skip_mfa (req))
    return 80;
  wyl_login_req_set_skip_mfa (req, FALSE);
  if (wyl_login_req_get_skip_mfa (req))
    return 81;
  return 0;
}

static gint
check_skip_mfa_null_request (void)
{
  if (wyl_login_req_get_skip_mfa (NULL))
    return 90;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_default_username_is_null ()) != 0)
    return rc;
  if ((rc = check_set_then_get ()) != 0)
    return rc;
  if ((rc = check_caller_buffer_is_copied ()) != 0)
    return rc;
  if ((rc = check_set_replaces_prior_value ()) != 0)
    return rc;
  if ((rc = check_set_null_clears ()) != 0)
    return rc;
  if ((rc = check_get_null_request ()) != 0)
    return rc;
  if ((rc = check_free_null_is_safe ()) != 0)
    return rc;
  if ((rc = check_skip_mfa_set_then_get ()) != 0)
    return rc;
  if ((rc = check_skip_mfa_null_request ()) != 0)
    return rc;

  return 0;
}
