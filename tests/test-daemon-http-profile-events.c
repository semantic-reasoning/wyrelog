/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * HTTP integration tests for POST /profile/events (issue #555).
 *
 * The handler under test is profile_events_handler in
 * wyrelog/daemon/http.c. A service-profile daemon (runtime.c) forwards
 * events of the shape {"profile":"service","event":"startup",
 * "timestamp_us":<int64>} over the loopback transport with no session
 * token; the loopback transport itself is the authenticator. The handler
 * must parse and validate the body and return 2xx on the well-formed
 * shape (the producer's spool drain stops on the first non-2xx), while
 * rejecting malformed/oversized/wrong-profile/non-loopback requests.
 *
 * The core logic is exercised directly through
 * wyl_daemon_http_profile_events_ingest_for_test so the non-loopback
 * (transport_ok=FALSE) branch can be driven without a real off-loopback
 * socket, and so the parsed fields can be asserted (proving the body was
 * ingested, not discarded).
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <string.h>

#include <glib.h>
#include <libsoup/soup.h>

#include "daemon/delta.h"
#include "daemon/http.h"
#include "daemon/options.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/* A canonical producer payload with a realistic microsecond timestamp
 * (16 digits, ~1.75e15) that overflows guint but fits gint64. */
#define PRODUCER_PAYLOAD \
  "{\"profile\":\"service\",\"event\":\"startup\"," \
  "\"timestamp_us\":1750000000000000}"

typedef struct
{
  WylHandle *handle;
  SoupServer *server;
  GMainLoop *loop;
  GThread *thread;
  gchar *base_url;
} TestServer;

static gpointer
test_http_server_thread (gpointer data)
{
  TestServer *ts = data;
  g_main_loop_run (ts->loop);
  return NULL;
}

static gboolean
test_server_start (TestServer *ts, WylDaemonProfile profile)
{
  memset (ts, 0, sizeof *ts);
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &ts->handle) != WYRELOG_E_OK)
    return FALSE;

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
    .profile = profile,
  };
  WylDaemonRuntime runtime = {
    .handle = ts->handle,
  };
  if (wyl_daemon_start_delta_callbacks (ts->handle, &runtime) != WYRELOG_E_OK)
    return FALSE;

  ts->loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  ts->server = wyl_daemon_start_http_server_with_runtime (&opts, ts->handle,
      &runtime, &error);
  if (ts->server == NULL)
    return FALSE;
  ts->thread = g_thread_new ("daemon-http-profile-events",
      test_http_server_thread, ts);

  GSList *uris = soup_server_get_uris (ts->server);
  if (uris == NULL)
    return FALSE;
  ts->base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  return ts->base_url != NULL;
}

static void
test_server_stop (TestServer *ts)
{
  if (ts->loop != NULL)
    g_main_loop_quit (ts->loop);
  if (ts->thread != NULL)
    g_thread_join (ts->thread);
  if (ts->server != NULL) {
    soup_server_disconnect (ts->server);
    g_clear_object (&ts->server);
  }
  g_clear_pointer (&ts->loop, g_main_loop_unref);
  g_clear_pointer (&ts->base_url, g_free);
  g_clear_object (&ts->handle);
}

static gint
send_event (SoupSession *session, const gchar *method, const gchar *base_url,
    const gchar *json, guint *out_status, gchar **out_body)
{
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  g_autofree gchar *uri = g_strdup_printf ("%s/profile/events", root);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 1;
  if (json != NULL) {
    g_autoptr (GBytes) payload = g_bytes_new (json, strlen (json));
    soup_message_set_request_body_from_bytes (msg, "application/json", payload);
  }
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 2;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
check_happy_path (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_event (session, "POST", base_url, PRODUCER_PAYLOAD, &status,
          &body) != 0)
    return 100;
  if (status != 200)
    return 101;
  if (strstr (body, "\"ok\":true") == NULL)
    return 102;

  /* Prove the body was ingested, not discarded: the core echoes the
   * parsed fields. */
  gint core_status = 0;
  const gchar *token = NULL;
  g_autofree gchar *out_profile = NULL;
  g_autofree gchar *out_event = NULL;
  gint64 out_ts = 0;
  if (wyl_daemon_http_profile_events_ingest_for_test
      (WYL_DAEMON_PROFILE_SYSTEM, TRUE, FALSE, PRODUCER_PAYLOAD,
          strlen (PRODUCER_PAYLOAD), &core_status, &token, &out_profile,
          &out_event, &out_ts) != WYRELOG_E_OK)
    return 103;
  if (core_status != 200)
    return 104;
  if (g_strcmp0 (out_profile, "service") != 0)
    return 105;
  if (g_strcmp0 (out_event, "startup") != 0)
    return 106;
  if (out_ts != G_GINT64_CONSTANT (1750000000000000))
    return 107;
  return 0;
}

static gint
check_literal_producer_payload (const gchar *base_url)
{
  /* Regression guard for the exact producer shape (runtime.c:260). */
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_event (session, "POST", base_url,
          "{\"profile\":\"service\",\"event\":\"startup\","
          "\"timestamp_us\":1750000000000000}", &status, &body) != 0)
    return 200;
  if (status != 200 || strstr (body, "\"ok\":true") == NULL)
    return 201;
  return 0;
}

static gint
check_method_gate (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  static const gchar *methods[] = { "GET", "PUT", "DELETE" };
  for (gsize i = 0; i < G_N_ELEMENTS (methods); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_event (session, methods[i], base_url, NULL, &status, &body) != 0)
      return 300 + (gint) i *10;
    if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
      return 301 + (gint) i *10;
  }
  return 0;
}

static gint
check_malformed_rejected (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  static const gchar *cases[] = {
    "",                         /* empty body */
    "not json",                 /* junk */
    "{\"profile\":\"service\",\"event\":\"startup\"}",  /* missing timestamp */
    "{\"profile\":\"service\",\"timestamp_us\":1}",     /* missing event */
    "{\"event\":\"startup\",\"timestamp_us\":1}",       /* missing profile */
    "{\"profile\":\"service\",\"event\":\"startup\"," "\"timestamp_us\":\"1\"}",        /* wrong type */
    "{\"profile\":\"service\",\"event\":\"startup\"," "\"timestamp_us\":-1}",   /* negative ts */
    "{\"profile\":\"\",\"event\":\"startup\"," "\"timestamp_us\":1}",   /* empty profile */
    "{\"profile\":\"service\",\"event\":\"\"," "\"timestamp_us\":1}",   /* empty event */
    "{\"profile\":\"service\",\"event\":\"startup\"," "\"timestamp_us\":1,\"extra\":\"x\"}",    /* extra member */
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_event (session, "POST", base_url, cases[i], &status, &body) != 0)
      return 400 + (gint) i *10;
    if (status != 400
        || strstr (body, "\"invalid_profile_event_request\"") == NULL)
      return 401 + (gint) i *10;
  }
  return 0;
}

static gint
check_oversized_rejected (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  /* Build a >1024-byte well-formed-looking body (padded event value). */
  g_autoptr (GString) big = g_string_new
      ("{\"profile\":\"service\",\"event\":\"");
  for (gsize i = 0; i < 1200; i++)
    g_string_append_c (big, 'a');
  g_string_append (big, "\",\"timestamp_us\":1}");

  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_event (session, "POST", base_url, big->str, &status, &body) != 0)
    return 500;
  if (status != 400
      || strstr (body, "\"invalid_profile_event_request\"") == NULL)
    return 501;
  return 0;
}

static gint
check_non_system_profile_denied (const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_event (session, "POST", base_url, PRODUCER_PAYLOAD, &status,
          &body) != 0)
    return 600;
  if (status != 403 || strstr (body, "\"profile_event_ingest_denied\"") == NULL)
    return 601;
  g_clear_pointer (&body, g_free);

  /* Precedence over the wire: a SERVICE-profile daemon sending an oversize
   * body is denied 403 (profile gate) rather than 400 (size gate). */
  g_autoptr (GString) big = g_string_new
      ("{\"profile\":\"service\",\"event\":\"");
  for (gsize i = 0; i < 1200; i++)
    g_string_append_c (big, 'a');
  g_string_append (big, "\",\"timestamp_us\":1}");
  if (send_event (session, "POST", base_url, big->str, &status, &body) != 0)
    return 602;
  if (status != 403 || strstr (body, "\"profile_event_ingest_denied\"") == NULL)
    return 603;
  return 0;
}

static gint
check_non_loopback_denied (void)
{
  /* Drive the core with transport_ok=FALSE without an off-loopback
   * socket; must deny with the same token as the wrong-profile case. */
  gint status = 0;
  const gchar *token = NULL;
  g_autofree gchar *out_profile = NULL;
  g_autofree gchar *out_event = NULL;
  gint64 out_ts = 0;
  if (wyl_daemon_http_profile_events_ingest_for_test
      (WYL_DAEMON_PROFILE_SYSTEM, FALSE, FALSE, PRODUCER_PAYLOAD,
          strlen (PRODUCER_PAYLOAD), &status, &token, &out_profile, &out_event,
          &out_ts) != WYRELOG_E_OK)
    return 700;
  if (status != 403)
    return 701;
  if (g_strcmp0 (token, "profile_event_ingest_denied") != 0)
    return 702;
  if (out_profile != NULL || out_event != NULL)
    return 703;
  return 0;
}

static gint
check_denial_precedes_oversize (void)
{
  /* Precedence: an unauthorized (non-loopback) caller sending an oversize
   * body must be denied 403 by the transport gate, NOT 400 by the shape
   * gate — so the endpoint's existence and size boundary are not leaked. */
  gint status = 0;
  const gchar *token = NULL;
  g_autofree gchar *out_profile = NULL;
  g_autofree gchar *out_event = NULL;
  gint64 out_ts = 0;
  if (wyl_daemon_http_profile_events_ingest_for_test
      (WYL_DAEMON_PROFILE_SYSTEM, FALSE, TRUE, NULL, 0, &status, &token,
          &out_profile, &out_event, &out_ts) != WYRELOG_E_OK)
    return 750;
  if (status != 403 || g_strcmp0 (token, "profile_event_ingest_denied") != 0)
    return 751;

  /* Same precedence for a SERVICE-profile caller with an oversize body. */
  if (wyl_daemon_http_profile_events_ingest_for_test
      (WYL_DAEMON_PROFILE_SERVICE, TRUE, TRUE, NULL, 0, &status, &token,
          &out_profile, &out_event, &out_ts) != WYRELOG_E_OK)
    return 752;
  if (status != 403 || g_strcmp0 (token, "profile_event_ingest_denied") != 0)
    return 753;
  return 0;
}

int
main (void)
{
  gint rc = 0;
  TestServer sys = { 0 };
  if (!test_server_start (&sys, WYL_DAEMON_PROFILE_SYSTEM))
    return 1;

  if ((rc = check_happy_path (sys.base_url)) != 0)
    goto out_system;
  if ((rc = check_literal_producer_payload (sys.base_url)) != 0)
    goto out_system;
  if ((rc = check_method_gate (sys.base_url)) != 0)
    goto out_system;
  if ((rc = check_malformed_rejected (sys.base_url)) != 0)
    goto out_system;
  if ((rc = check_oversized_rejected (sys.base_url)) != 0)
    goto out_system;
  if ((rc = check_non_loopback_denied ()) != 0)
    goto out_system;
  if ((rc = check_denial_precedes_oversize ()) != 0)
    goto out_system;

out_system:
  test_server_stop (&sys);
  if (rc != 0)
    return rc;

  TestServer svc = { 0 };
  if (!test_server_start (&svc, WYL_DAEMON_PROFILE_SERVICE))
    return 2;
  rc = check_non_system_profile_denied (svc.base_url);
  test_server_stop (&svc);
  return rc;
}
