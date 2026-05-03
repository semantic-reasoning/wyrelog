/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static gint
check_defaults_are_null (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  if (req == NULL)
    return 10;
  if (wyl_revoke_req_get_subject_id (req) != NULL)
    return 11;
  if (wyl_revoke_req_get_action (req) != NULL)
    return 12;
  if (wyl_revoke_req_get_resource_id (req) != NULL)
    return 13;
  return 0;
}

static gint
check_subject_round_trip (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (req, "alice");
  if (g_strcmp0 (wyl_revoke_req_get_subject_id (req), "alice") != 0)
    return 20;
  return 0;
}

static gint
check_action_round_trip (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_action (req, "write");
  if (g_strcmp0 (wyl_revoke_req_get_action (req), "write") != 0)
    return 30;
  return 0;
}

static gint
check_resource_round_trip (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_resource_id (req, "doc/42");
  if (g_strcmp0 (wyl_revoke_req_get_resource_id (req), "doc/42") != 0)
    return 40;
  return 0;
}

static gint
check_caller_buffer_is_copied (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  gchar buf[16] = "alice";
  wyl_revoke_req_set_subject_id (req, buf);
  buf[0] = 'X';
  if (g_strcmp0 (wyl_revoke_req_get_subject_id (req), "alice") != 0)
    return 50;
  return 0;
}

static gint
check_set_replaces_prior (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_action (req, "read");
  wyl_revoke_req_set_action (req, "write");
  if (g_strcmp0 (wyl_revoke_req_get_action (req), "write") != 0)
    return 60;
  return 0;
}

static gint
check_set_null_clears (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (req, "alice");
  wyl_revoke_req_set_subject_id (req, NULL);
  if (wyl_revoke_req_get_subject_id (req) != NULL)
    return 70;
  return 0;
}

static gint
check_fields_are_independent (void)
{
  g_autoptr (wyl_revoke_req_t) req = wyl_revoke_req_new ();
  wyl_revoke_req_set_subject_id (req, "alice");
  wyl_revoke_req_set_action (req, "write");
  wyl_revoke_req_set_resource_id (req, "doc/42");

  /* Clearing one field must not perturb the others. */
  wyl_revoke_req_set_action (req, NULL);
  if (g_strcmp0 (wyl_revoke_req_get_subject_id (req), "alice") != 0)
    return 80;
  if (wyl_revoke_req_get_action (req) != NULL)
    return 81;
  if (g_strcmp0 (wyl_revoke_req_get_resource_id (req), "doc/42") != 0)
    return 82;
  return 0;
}

static gint
check_get_null_request (void)
{
  if (wyl_revoke_req_get_subject_id (NULL) != NULL)
    return 90;
  if (wyl_revoke_req_get_action (NULL) != NULL)
    return 91;
  if (wyl_revoke_req_get_resource_id (NULL) != NULL)
    return 92;
  return 0;
}

static gint
check_free_null_is_safe (void)
{
  wyl_revoke_req_free (NULL);
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_defaults_are_null ()) != 0)
    return rc;
  if ((rc = check_subject_round_trip ()) != 0)
    return rc;
  if ((rc = check_action_round_trip ()) != 0)
    return rc;
  if ((rc = check_resource_round_trip ()) != 0)
    return rc;
  if ((rc = check_caller_buffer_is_copied ()) != 0)
    return rc;
  if ((rc = check_set_replaces_prior ()) != 0)
    return rc;
  if ((rc = check_set_null_clears ()) != 0)
    return rc;
  if ((rc = check_fields_are_independent ()) != 0)
    return rc;
  if ((rc = check_get_null_request ()) != 0)
    return rc;
  if ((rc = check_free_null_is_safe ()) != 0)
    return rc;

  return 0;
}
