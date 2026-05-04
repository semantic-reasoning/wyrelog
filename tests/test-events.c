/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <string.h>

#include "wyrelog/wyl-events-private.h"

/* -----------------------------------------------------------------------
 * Legacy flat-struct tests (preserved exactly)
 * --------------------------------------------------------------------- */

/* --- Domain name round-trip ------------------------------------- */

static gint
check_domain_names (void)
{
  for (guint d = 0; d < (guint) WYL_ACCESS_EVENT_DOMAIN_LAST_; d++) {
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

/* -----------------------------------------------------------------------
 * Helpers for GObject-based tests
 * --------------------------------------------------------------------- */

/* Mint a non-NIL id for testing by filling bytes with a fixed pattern. */
static wyl_id_t
make_test_id (guint8 seed)
{
  wyl_id_t id;
  memset (id.bytes, seed, WYL_ID_BYTES);
  /* Force version=7 (nibble at byte 6 high) and variant=10 (byte 8)
   * so id_is_nil() does not match WYL_ID_NIL (all zeros).
   * For test purposes we just need non-NIL; the ID need not be
   * a valid UUIDv7 for constructor acceptance. */
  id.bytes[6] = (guint8) ((id.bytes[6] & 0x0f) | 0x70);
  id.bytes[8] = (guint8) ((id.bytes[8] & 0x3f) | 0x80);
  return id;
}

/* -----------------------------------------------------------------------
 * GObject ctor tests - PRINCIPAL domain
 * --------------------------------------------------------------------- */

static gint
test_event_ctor_principal_valid (void)
{
  wyl_id_t eid = make_test_id (1);
  wyl_id_t pid = make_test_id (2);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK,
      "password", "10.0.0.1", "TestAgent/1.0",
      G_GINT64_CONSTANT (123456789), NULL, &e);

  if (rc != WYRELOG_E_OK)
    return 100;
  if (e == NULL)
    return 101;
  if (wyl_access_event_get_domain (e) != WYL_ACCESS_EVENT_DOMAIN_PRINCIPAL)
    return 102;
  if (!wyl_id_equal (&eid, &(wyl_id_t) {
            .bytes = { 0 }
          }
      )){
    wyl_id_t got = wyl_access_event_get_event_id (e);
    if (!wyl_id_equal (&got, &eid))
      return 103;
  }
  {
    wyl_id_t got_eid = wyl_access_event_get_event_id (e);
    if (!wyl_id_equal (&got_eid, &eid))
      return 103;
  }
  if (wyl_access_event_get_timestamp_us (e) != G_GINT64_CONSTANT (123456789))
    return 104;
  {
    wyl_id_t got_pid = wyl_access_event_get_principal_id (e);
    if (!wyl_id_equal (&got_pid, &pid))
      return 105;
  }
  if (wyl_access_event_get_principal_fsm_event (e) !=
      WYL_PRINCIPAL_EVENT_LOGIN_OK)
    return 106;
  if (g_strcmp0 (wyl_access_event_get_auth_method (e), "password") != 0)
    return 107;
  if (g_strcmp0 (wyl_access_event_get_principal_source_ip (e), "10.0.0.1") != 0)
    return 108;
  if (g_strcmp0 (wyl_access_event_get_principal_user_agent (e),
          "TestAgent/1.0") != 0)
    return 109;
  if (wyl_access_event_get_context (e) != NULL)
    return 110;

  g_object_unref (e);
  return 0;
}

static gint
test_event_ctor_principal_nil_event_id_rejects (void)
{
  wyl_id_t pid = make_test_id (3);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (WYL_ID_NIL, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK, "password", NULL, NULL, 0, NULL, &e);

  if (rc != WYRELOG_E_INVALID)
    return 120;
  if (e != NULL)
    return 121;
  return 0;
}

static gint
test_event_ctor_principal_nil_principal_id_rejects (void)
{
  wyl_id_t eid = make_test_id (4);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (eid, WYL_ID_NIL,
      WYL_PRINCIPAL_EVENT_LOGIN_OK, "password", NULL, NULL, 0, NULL, &e);

  if (rc != WYRELOG_E_INVALID)
    return 130;
  if (e != NULL)
    return 131;
  return 0;
}

static gint
test_event_ctor_principal_null_auth_method_rejects (void)
{
  wyl_id_t eid = make_test_id (5);
  wyl_id_t pid = make_test_id (6);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK, NULL, NULL, NULL, 0, NULL, &e);

  if (rc != WYRELOG_E_INVALID)
    return 140;
  if (e != NULL)
    return 141;
  return 0;
}

static gint
test_event_ctor_principal_null_out_rejects (void)
{
  wyl_id_t eid = make_test_id (7);
  wyl_id_t pid = make_test_id (8);
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK, "password", NULL, NULL, 0, NULL, NULL);

  if (rc != WYRELOG_E_INVALID)
    return 150;
  return 0;
}

static gint
test_event_ctor_principal_sentinel_fsm_rejects (void)
{
  wyl_id_t eid = make_test_id (9);
  wyl_id_t pid = make_test_id (10);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LAST_, "password", NULL, NULL, 0, NULL, &e);

  if (rc != WYRELOG_E_INVALID)
    return 160;
  if (e != NULL)
    return 161;
  return 0;
}

/* -----------------------------------------------------------------------
 * GObject ctor tests - SESSION domain
 * --------------------------------------------------------------------- */

static gint
test_event_ctor_session_valid (void)
{
  wyl_id_t eid = make_test_id (11);
  wyl_id_t sid = make_test_id (12);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_session (eid, sid,
      WYL_SESSION_EVENT_REQUEST,
      "192.168.1.1", "Browser/2.0", G_GINT64_CONSTANT (987654321), NULL, &e);

  if (rc != WYRELOG_E_OK)
    return 200;
  if (e == NULL)
    return 201;
  if (wyl_access_event_get_domain (e) != WYL_ACCESS_EVENT_DOMAIN_SESSION)
    return 202;
  {
    wyl_id_t got_eid = wyl_access_event_get_event_id (e);
    if (!wyl_id_equal (&got_eid, &eid))
      return 203;
  }
  if (wyl_access_event_get_timestamp_us (e) != G_GINT64_CONSTANT (987654321))
    return 204;
  {
    wyl_id_t got_sid = wyl_access_event_get_session_id (e);
    if (!wyl_id_equal (&got_sid, &sid))
      return 205;
  }
  if (wyl_access_event_get_session_fsm_event (e) != WYL_SESSION_EVENT_REQUEST)
    return 206;
  if (g_strcmp0 (wyl_access_event_get_session_source_ip (e),
          "192.168.1.1") != 0)
    return 207;
  if (g_strcmp0 (wyl_access_event_get_session_user_agent (e),
          "Browser/2.0") != 0)
    return 208;

  g_object_unref (e);
  return 0;
}

static gint
test_event_ctor_session_sentinel_fsm_rejects (void)
{
  wyl_id_t eid = make_test_id (13);
  wyl_id_t sid = make_test_id (14);
  WylAccessEvent *e = NULL;
  wyrelog_error_t rc;

  rc = wyl_access_event_new_session (eid, sid,
      WYL_SESSION_EVENT_LAST_, NULL, NULL, 0, NULL, &e);

  if (rc != WYRELOG_E_INVALID)
    return 210;
  if (e != NULL)
    return 211;
  return 0;
}

/* -----------------------------------------------------------------------
 * Autoptr cleanup (build-level: no crash = pass)
 * --------------------------------------------------------------------- */

static gint
test_event_autoptr_cleanup (void)
{
  wyl_id_t eid = make_test_id (15);
  wyl_id_t pid = make_test_id (16);

  {
    g_autoptr (WylAccessEvent) e = NULL;
    wyrelog_error_t rc = wyl_access_event_new_principal (eid, pid,
        WYL_PRINCIPAL_EVENT_MFA_OK,
        "totp", NULL, NULL, 0, NULL, &e);
    if (rc != WYRELOG_E_OK || e == NULL)
      return 220;
    /* e is released by g_autoptr at end of block */
  }
  return 0;
}

/* -----------------------------------------------------------------------
 * Cross-domain accessor isolation
 * --------------------------------------------------------------------- */

static gint
test_event_cross_domain_accessor_isolation (void)
{
  wyl_id_t eid = make_test_id (17);
  wyl_id_t pid = make_test_id (18);
  WylAccessEvent *e = NULL;

  wyrelog_error_t rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK,
      "password", NULL, NULL, 0, NULL, &e);
  if (rc != WYRELOG_E_OK)
    return 230;

  /* Calling session accessor on a principal event returns NIL sentinel */
  wyl_id_t result = wyl_access_event_get_session_id (e);
  if (!wyl_id_equal (&result, &WYL_ID_NIL))
    return 231;

  g_object_unref (e);
  return 0;
}

/* -----------------------------------------------------------------------
 * Context attachment
 * --------------------------------------------------------------------- */

static gint
test_event_context_attachment (void)
{
  wyl_id_t eid = make_test_id (19);
  wyl_id_t pid = make_test_id (20);
  WylAccessContext *ctx = NULL;
  WylAccessEvent *e = NULL;

  wyrelog_error_t rc =
      wyl_access_context_new (G_GINT64_CONSTANT (111222333), "1.2.3.4", "UA/1",
      "req-abc", &ctx);
  if (rc != WYRELOG_E_OK || ctx == NULL)
    return 240;

  rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK, "password", NULL, NULL, 0, ctx, &e);
  if (rc != WYRELOG_E_OK)
    return 241;

  /* Accessor must return the attached context */
  WylAccessContext *got = wyl_access_event_get_context (e);
  if (got == NULL)
    return 242;
  if (wyl_access_context_get_timestamp_us (got) !=
      G_GINT64_CONSTANT (111222333))
    return 243;
  if (g_strcmp0 (wyl_access_context_get_source_ip (got), "1.2.3.4") != 0)
    return 244;

  /* Release the caller's reference; event still holds its own */
  g_object_unref (ctx);
  /* Now release the event; its dispose releases the context ref */
  g_object_unref (e);
  return 0;
}

/* -----------------------------------------------------------------------
 * Owned strings: caller mutation after ctor must not affect stored value
 * --------------------------------------------------------------------- */

static gint
test_event_owned_strings (void)
{
  wyl_id_t eid = make_test_id (21);
  wyl_id_t pid = make_test_id (22);
  WylAccessEvent *e = NULL;

  gchar method_buf[] = "original";

  wyrelog_error_t rc = wyl_access_event_new_principal (eid, pid,
      WYL_PRINCIPAL_EVENT_LOGIN_OK,
      method_buf, NULL, NULL, 0, NULL, &e);
  if (rc != WYRELOG_E_OK)
    return 250;

  /* Mutate the caller's buffer */
  method_buf[0] = 'X';

  /* Event must still carry the original string */
  if (g_strcmp0 (wyl_access_event_get_auth_method (e), "original") != 0)
    return 251;

  g_object_unref (e);
  return 0;
}

/* -----------------------------------------------------------------------
 * Total kinds preserved (existing contract)
 * --------------------------------------------------------------------- */

static gint
test_event_total_kinds_preserved (void)
{
  if (wyl_access_event_total_kinds () != 13)
    return 260;
  return 0;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int
main (void)
{
  gint rc;

  /* Legacy flat-struct tests */
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

  /* GObject ctor tests - PRINCIPAL */
  if ((rc = test_event_ctor_principal_valid ()) != 0)
    return rc;
  if ((rc = test_event_ctor_principal_nil_event_id_rejects ()) != 0)
    return rc;
  if ((rc = test_event_ctor_principal_nil_principal_id_rejects ()) != 0)
    return rc;
  if ((rc = test_event_ctor_principal_null_auth_method_rejects ()) != 0)
    return rc;
  if ((rc = test_event_ctor_principal_null_out_rejects ()) != 0)
    return rc;
  if ((rc = test_event_ctor_principal_sentinel_fsm_rejects ()) != 0)
    return rc;

  /* GObject ctor tests - SESSION */
  if ((rc = test_event_ctor_session_valid ()) != 0)
    return rc;
  if ((rc = test_event_ctor_session_sentinel_fsm_rejects ()) != 0)
    return rc;

  /* Autoptr, cross-domain, context, owned strings */
  if ((rc = test_event_autoptr_cleanup ()) != 0)
    return rc;
  if ((rc = test_event_cross_domain_accessor_isolation ()) != 0)
    return rc;
  if ((rc = test_event_context_attachment ()) != 0)
    return rc;
  if ((rc = test_event_owned_strings ()) != 0)
    return rc;

  /* Preserved total-kinds contract */
  if ((rc = test_event_total_kinds_preserved ()) != 0)
    return rc;

  return 0;
}
