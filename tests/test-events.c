/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyl-events-private.h"

/* --- Domain name round-trip ------------------------------------- */

static gint
check_domain_names (void)
{
  for (guint d = 0; d < WYL_ACCESS_EVENT_DOMAIN_LAST_; d++) {
    const gchar *name =
        wyl_access_event_domain_name ((wyl_access_event_domain_t) d);
    if (name == NULL || name[0] == '\0')
      return (gint) (1 + d);
  }
  if (wyl_access_event_domain_name (WYL_ACCESS_EVENT_DOMAIN_LAST_) != NULL)
    return 5;
  return 0;
}

/* --- Total kinds counter --------------------------------------- */

static gint
check_total_kinds (void)
{
  /* 7 principal events + 6 session events = 13 carried variants. */
  if (wyl_access_event_total_kinds () !=
      (gsize) WYL_PRINCIPAL_EVENT_LAST_ + (gsize) WYL_SESSION_EVENT_LAST_)
    return 10;
  if (wyl_access_event_total_kinds () != 13)
    return 11;
  return 0;
}

/* --- Exhaustive event-kind name coverage ----------------------- */

static gint
check_exhaustive_kind_names (void)
{
  /* Every principal event ordinal under the principal domain
   * yields a non-NULL name and matches the F1 accessor. */
  for (guint e = 0; e < WYL_PRINCIPAL_EVENT_LAST_; e++) {
    wyl_access_event_t ev = {
      .domain = WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL,
      .event = {.principal = (wyl_principal_event_t) e},
      .timestamp_us = 0,
      .user_id = NULL,
      .session_id = NULL,
    };
    const gchar *got = wyl_access_event_kind_name (&ev);
    const gchar *expect = wyl_principal_event_name ((wyl_principal_event_t) e);
    if (g_strcmp0 (got, expect) != 0)
      return (gint) (20 + e);
  }
  /* Same for the session domain. */
  for (guint e = 0; e < WYL_SESSION_EVENT_LAST_; e++) {
    wyl_access_event_t ev = {
      .domain = WYL_ACCESS_EVENT_DOMAIN_SESSION,
      .event = {.session = (wyl_session_event_t) e},
      .timestamp_us = 0,
      .user_id = NULL,
      .session_id = NULL,
    };
    const gchar *got = wyl_access_event_kind_name (&ev);
    const gchar *expect = wyl_session_event_name ((wyl_session_event_t) e);
    if (g_strcmp0 (got, expect) != 0)
      return (gint) (40 + e);
  }
  return 0;
}

/* --- Out-of-range envelopes fail closed ------------------------ */

static gint
check_out_of_range (void)
{
  if (wyl_access_event_kind_name (NULL) != NULL)
    return 60;

  wyl_access_event_t bad_domain = {
    .domain = WYL_ACCESS_EVENT_DOMAIN_LAST_,
    .event = {.principal = WYL_PRINCIPAL_EVENT_LOGIN_OK},
  };
  if (wyl_access_event_kind_name (&bad_domain) != NULL)
    return 61;

  wyl_access_event_t bad_principal = {
    .domain = WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL,
    .event = {.principal = WYL_PRINCIPAL_EVENT_LAST_},
  };
  if (wyl_access_event_kind_name (&bad_principal) != NULL)
    return 62;

  wyl_access_event_t bad_session = {
    .domain = WYL_ACCESS_EVENT_DOMAIN_SESSION,
    .event = {.session = WYL_SESSION_EVENT_LAST_},
  };
  if (wyl_access_event_kind_name (&bad_session) != NULL)
    return 63;
  return 0;
}

/* --- Zero-init carries the principal LOGIN_OK kind ------------- */

static gint
check_zero_init (void)
{
  /* Stack zero-init: domain==PRINCIPAL (0), event.principal==LOGIN_OK
   * (0), all metadata pointers NULL, timestamp 0. The envelope
   * is observably valid in this state. */
  wyl_access_event_t ev = { 0 };
  if (ev.domain != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL)
    return 70;
  if (ev.event.principal != WYL_PRINCIPAL_EVENT_LOGIN_OK)
    return 71;
  if (ev.timestamp_us != 0)
    return 72;
  if (ev.user_id != NULL)
    return 73;
  if (ev.session_id != NULL)
    return 74;
  if (g_strcmp0 (wyl_access_event_kind_name (&ev), "login_ok") != 0)
    return 75;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_domain_names ()) != 0)
    return rc;
  if ((rc = check_total_kinds ()) != 0)
    return rc;
  if ((rc = check_exhaustive_kind_names ()) != 0)
    return rc;
  if ((rc = check_out_of_range ()) != 0)
    return rc;
  if ((rc = check_zero_init ()) != 0)
    return rc;
  return 0;
}
