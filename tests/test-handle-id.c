/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyrelog.h"

static gint
check_init_yields_id (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;
  if (handle == NULL)
    return 11;
  g_autofree gchar *id = wyl_handle_dup_id_string (handle);
  if (id == NULL)
    return 12;
  if (strlen (id) != 36)
    return 13;
  if (id[14] != '7')
    return 14;
  g_object_unref (handle);
  return 0;
}

static gint
check_id_is_stable (void)
{
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;
  g_autofree gchar *first = wyl_handle_dup_id_string (handle);
  g_autofree gchar *second = wyl_handle_dup_id_string (handle);
  gint rc = 0;
  if (first == NULL || second == NULL)
    rc = 21;
  else if (strcmp (first, second) != 0)
    rc = 22;
  g_object_unref (handle);
  return rc;
}

static gint
check_distinct_handles_have_distinct_ids (void)
{
  WylHandle *a = NULL;
  WylHandle *b = NULL;
  if (wyl_init (NULL, &a) != WYRELOG_E_OK)
    return 30;
  if (wyl_init (NULL, &b) != WYRELOG_E_OK)
    return 31;
  g_autofree gchar *ida = wyl_handle_dup_id_string (a);
  g_autofree gchar *idb = wyl_handle_dup_id_string (b);
  gint rc = 0;
  if (ida == NULL || idb == NULL)
    rc = 32;
  else if (strcmp (ida, idb) == 0)
    rc = 33;
  g_object_unref (a);
  g_object_unref (b);
  return rc;
}

static gint
check_created_at_is_recent (void)
{
  gint64 before = g_get_real_time ();
  WylHandle *handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  gint64 after = g_get_real_time ();
  gint64 created = wyl_handle_get_created_at_us (handle);
  gint rc = 0;
  if (created < before || created > after)
    rc = 41;
  g_object_unref (handle);
  return rc;
}

static gint
check_accessor_null_safety (void)
{
  if (wyl_handle_get_created_at_us (NULL) != -1)
    return 50;
  if (wyl_handle_dup_id_string (NULL) != NULL)
    return 51;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_init_yields_id ()) != 0)
    return rc;
  if ((rc = check_id_is_stable ()) != 0)
    return rc;
  if ((rc = check_distinct_handles_have_distinct_ids ()) != 0)
    return rc;
  if ((rc = check_created_at_is_recent ()) != 0)
    return rc;
  if ((rc = check_accessor_null_safety ()) != 0)
    return rc;

  return 0;
}
