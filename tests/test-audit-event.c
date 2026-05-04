/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static gint
check_construction (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  if (ev == NULL)
    return 10;
  if (!WYL_IS_AUDIT_EVENT (ev))
    return 11;
  return 0;
}

static gint
check_id_is_nonempty_and_canonical (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  g_autofree gchar *id = wyl_audit_event_dup_id_string (ev);
  if (id == NULL)
    return 20;
  if (strlen (id) != 36)
    return 21;
  if (id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-')
    return 22;
  if (id[14] != '7')
    return 23;
  return 0;
}

static gint
check_id_is_stable_across_calls (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  g_autofree gchar *first = wyl_audit_event_dup_id_string (ev);
  g_autofree gchar *second = wyl_audit_event_dup_id_string (ev);
  if (first == NULL || second == NULL)
    return 30;
  if (strcmp (first, second) != 0)
    return 31;
  return 0;
}

static gint
check_distinct_events_have_distinct_ids (void)
{
  g_autoptr (WylAuditEvent) a = wyl_audit_event_new ();
  g_autoptr (WylAuditEvent) b = wyl_audit_event_new ();
  g_autofree gchar *ida = wyl_audit_event_dup_id_string (a);
  g_autofree gchar *idb = wyl_audit_event_dup_id_string (b);
  if (ida == NULL || idb == NULL)
    return 40;
  if (strcmp (ida, idb) == 0)
    return 41;
  return 0;
}

static gint
check_created_at_is_recent (void)
{
  gint64 before = g_get_real_time ();
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  gint64 after = g_get_real_time ();
  gint64 created = wyl_audit_event_get_created_at_us (ev);
  if (created < before || created > after)
    return 50;
  return 0;
}

static gint
check_created_at_monotonic_with_minting_order (void)
{
  g_autoptr (WylAuditEvent) a = wyl_audit_event_new ();
  g_usleep (2000);
  g_autoptr (WylAuditEvent) b = wyl_audit_event_new ();
  if (wyl_audit_event_get_created_at_us (a)
      >= wyl_audit_event_get_created_at_us (b))
    return 60;
  return 0;
}

static gint
check_accessor_null_safety (void)
{
  if (wyl_audit_event_get_created_at_us (NULL) != -1)
    return 70;
  if (wyl_audit_event_dup_id_string (NULL) != NULL)
    return 71;
  return 0;
}

static gint
check_decision_default_is_deny (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  if (wyl_audit_event_get_decision (ev) != WYL_DECISION_DENY)
    return 110;
  return 0;
}

static gint
check_set_decision_round_trip (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_decision (ev, WYL_DECISION_ALLOW);
  if (wyl_audit_event_get_decision (ev) != WYL_DECISION_ALLOW)
    return 120;
  wyl_audit_event_set_decision (ev, WYL_DECISION_DENY);
  if (wyl_audit_event_get_decision (ev) != WYL_DECISION_DENY)
    return 121;
  return 0;
}

static gint
check_get_decision_null_is_deny (void)
{
  if (wyl_audit_event_get_decision (NULL) != WYL_DECISION_DENY)
    return 130;
  return 0;
}

static gint
check_string_field_defaults_are_null (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  if (wyl_audit_event_get_subject_id (ev) != NULL)
    return 140;
  if (wyl_audit_event_get_action (ev) != NULL)
    return 141;
  if (wyl_audit_event_get_resource_id (ev) != NULL)
    return 142;
  if (wyl_audit_event_get_deny_reason (ev) != NULL)
    return 143;
  if (wyl_audit_event_get_deny_origin (ev) != NULL)
    return 144;
  return 0;
}

static gint
check_string_field_round_trips (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "alice");
  wyl_audit_event_set_action (ev, "read");
  wyl_audit_event_set_resource_id (ev, "doc/42");
  wyl_audit_event_set_deny_reason (ev, "not_authenticated");
  wyl_audit_event_set_deny_origin (ev, "principal_state");
  if (g_strcmp0 (wyl_audit_event_get_subject_id (ev), "alice") != 0)
    return 150;
  if (g_strcmp0 (wyl_audit_event_get_action (ev), "read") != 0)
    return 151;
  if (g_strcmp0 (wyl_audit_event_get_resource_id (ev), "doc/42") != 0)
    return 152;
  if (g_strcmp0 (wyl_audit_event_get_deny_reason (ev), "not_authenticated")
      != 0)
    return 153;
  if (g_strcmp0 (wyl_audit_event_get_deny_origin (ev), "principal_state")
      != 0)
    return 154;
  return 0;
}

static gint
check_string_set_null_clears (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  wyl_audit_event_set_subject_id (ev, "alice");
  wyl_audit_event_set_deny_reason (ev, "not_armed");
  wyl_audit_event_set_deny_origin (ev, "perm_state");
  wyl_audit_event_set_subject_id (ev, NULL);
  wyl_audit_event_set_deny_reason (ev, NULL);
  wyl_audit_event_set_deny_origin (ev, NULL);
  if (wyl_audit_event_get_subject_id (ev) != NULL)
    return 160;
  if (wyl_audit_event_get_deny_reason (ev) != NULL)
    return 161;
  if (wyl_audit_event_get_deny_origin (ev) != NULL)
    return 162;
  return 0;
}

static gint
check_string_caller_buffer_is_copied (void)
{
  g_autoptr (WylAuditEvent) ev = wyl_audit_event_new ();
  gchar buf[16] = "alice";
  wyl_audit_event_set_subject_id (ev, buf);
  buf[0] = 'X';
  if (g_strcmp0 (wyl_audit_event_get_subject_id (ev), "alice") != 0)
    return 170;
  return 0;
}

static gint
check_string_get_null_event (void)
{
  if (wyl_audit_event_get_subject_id (NULL) != NULL)
    return 180;
  if (wyl_audit_event_get_action (NULL) != NULL)
    return 181;
  if (wyl_audit_event_get_resource_id (NULL) != NULL)
    return 182;
  if (wyl_audit_event_get_deny_reason (NULL) != NULL)
    return 183;
  if (wyl_audit_event_get_deny_origin (NULL) != NULL)
    return 184;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_construction ()) != 0)
    return rc;
  if ((rc = check_id_is_nonempty_and_canonical ()) != 0)
    return rc;
  if ((rc = check_id_is_stable_across_calls ()) != 0)
    return rc;
  if ((rc = check_distinct_events_have_distinct_ids ()) != 0)
    return rc;
  if ((rc = check_created_at_is_recent ()) != 0)
    return rc;
  if ((rc = check_created_at_monotonic_with_minting_order ()) != 0)
    return rc;
  if ((rc = check_accessor_null_safety ()) != 0)
    return rc;
  if ((rc = check_decision_default_is_deny ()) != 0)
    return rc;
  if ((rc = check_set_decision_round_trip ()) != 0)
    return rc;
  if ((rc = check_get_decision_null_is_deny ()) != 0)
    return rc;
  if ((rc = check_string_field_defaults_are_null ()) != 0)
    return rc;
  if ((rc = check_string_field_round_trips ()) != 0)
    return rc;
  if ((rc = check_string_set_null_clears ()) != 0)
    return rc;
  if ((rc = check_string_caller_buffer_is_copied ()) != 0)
    return rc;
  if ((rc = check_string_get_null_event ()) != 0)
    return rc;

  return 0;
}
