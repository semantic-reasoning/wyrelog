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

  return 0;
}
