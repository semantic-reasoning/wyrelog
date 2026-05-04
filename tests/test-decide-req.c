/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static gint
check_defaults_are_null (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  if (req == NULL)
    return 10;
  if (wyl_decide_req_get_subject_id (req) != NULL)
    return 11;
  if (wyl_decide_req_get_action (req) != NULL)
    return 12;
  if (wyl_decide_req_get_resource_id (req) != NULL)
    return 13;
  if (wyl_decide_req_has_guard_context (req))
    return 14;
  return 0;
}

static gint
check_subject_round_trip (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "alice");
  if (g_strcmp0 (wyl_decide_req_get_subject_id (req), "alice") != 0)
    return 20;
  return 0;
}

static gint
check_action_round_trip (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_action (req, "read");
  if (g_strcmp0 (wyl_decide_req_get_action (req), "read") != 0)
    return 30;
  return 0;
}

static gint
check_resource_round_trip (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_resource_id (req, "doc/42");
  if (g_strcmp0 (wyl_decide_req_get_resource_id (req), "doc/42") != 0)
    return 40;
  return 0;
}

static gint
check_caller_buffer_is_copied (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  gchar buf[16] = "alice";
  wyl_decide_req_set_subject_id (req, buf);
  buf[0] = 'X';
  if (g_strcmp0 (wyl_decide_req_get_subject_id (req), "alice") != 0)
    return 50;
  return 0;
}

static gint
check_set_replaces_prior (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "first");
  wyl_decide_req_set_subject_id (req, "second");
  if (g_strcmp0 (wyl_decide_req_get_subject_id (req), "second") != 0)
    return 60;
  return 0;
}

static gint
check_set_null_clears (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_subject_id (req, NULL);
  if (wyl_decide_req_get_subject_id (req) != NULL)
    return 70;
  return 0;
}

static gint
check_fields_are_independent (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_action (req, "read");
  wyl_decide_req_set_resource_id (req, "doc/42");

  /* Clearing one field must not perturb the others. */
  wyl_decide_req_set_action (req, NULL);
  if (g_strcmp0 (wyl_decide_req_get_subject_id (req), "alice") != 0)
    return 80;
  if (wyl_decide_req_get_action (req) != NULL)
    return 81;
  if (g_strcmp0 (wyl_decide_req_get_resource_id (req), "doc/42") != 0)
    return 82;
  return 0;
}

static gint
check_get_null_request (void)
{
  if (wyl_decide_req_get_subject_id (NULL) != NULL)
    return 90;
  if (wyl_decide_req_get_action (NULL) != NULL)
    return 91;
  if (wyl_decide_req_get_resource_id (NULL) != NULL)
    return 92;
  return 0;
}

static gint
check_free_null_is_safe (void)
{
  wyl_decide_req_free (NULL);
  return 0;
}

static gint
check_guard_context_round_trip (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_guard_context (req, 1234, "trusted", 42);

  if (!wyl_decide_req_has_guard_context (req))
    return 110;
  if (wyl_decide_req_get_guard_timestamp (req) != 1234)
    return 111;
  if (g_strcmp0 (wyl_decide_req_get_guard_loc_class (req), "trusted") != 0)
    return 112;
  if (wyl_decide_req_get_guard_risk (req) != 42)
    return 113;
  return 0;
}

static gint
check_guard_context_copies_loc_class (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  gchar loc_class[16] = "public";
  wyl_decide_req_set_guard_context (req, 99, loc_class, 7);
  loc_class[0] = 'X';

  if (g_strcmp0 (wyl_decide_req_get_guard_loc_class (req), "public") != 0)
    return 120;
  return 0;
}

static gint
check_guard_context_clear_resets_fields (void)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_guard_context (req, 1234, "trusted", 42);
  wyl_decide_req_clear_guard_context (req);

  if (wyl_decide_req_has_guard_context (req))
    return 130;
  if (wyl_decide_req_get_guard_timestamp (req) != 0)
    return 131;
  if (wyl_decide_req_get_guard_loc_class (req) != NULL)
    return 132;
  if (wyl_decide_req_get_guard_risk (req) != 0)
    return 133;
  return 0;
}

static gint
check_guard_context_get_null_request (void)
{
  if (wyl_decide_req_has_guard_context (NULL))
    return 140;
  if (wyl_decide_req_get_guard_timestamp (NULL) != 0)
    return 141;
  if (wyl_decide_req_get_guard_loc_class (NULL) != NULL)
    return 142;
  if (wyl_decide_req_get_guard_risk (NULL) != 0)
    return 143;
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
  if ((rc = check_guard_context_round_trip ()) != 0)
    return rc;
  if ((rc = check_guard_context_copies_loc_class ()) != 0)
    return rc;
  if ((rc = check_guard_context_clear_resets_fields ()) != 0)
    return rc;
  if ((rc = check_guard_context_get_null_request ()) != 0)
    return rc;

  return 0;
}
