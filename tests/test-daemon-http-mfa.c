/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * HTTP integration tests for /auth/mfa/verify (issue #331 commit 4).
 *
 * The handler under test is mfa_verify_handler in wyrelog/daemon/http.c.
 * The route is registered next to the other auth handlers so this
 * test boots the same SoupServer harness as test-daemon-http-decide.
 *
 * Footgun coverage these tests exist to lock down:
 *   F2 (no secret echo): error JSON bodies surface only error codes;
 *     this file asserts the submitted code never appears in the body.
 *   F3 (replay): two verifies with the same code on the same session
 *     must yield (200, 401) and never (200, 200).
 *   F5 (enumeration): any session_token that fails to resolve to a
 *     live mfa_required session returns the SAME error code, regardless
 *     of whether the token is unknown, malformed, or in a wrong state.
 */

#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

#include <stdint.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <libsoup/soup.h>

#include "auth/mfa-validator.h"
#include "auth/totp.h"
#include "daemon/delta.h"
#include "daemon/http.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/session.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

static const guint8 MFA_TEST_SEED[WYL_TOTP_SEED_BYTES] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;
  g_main_loop_run (http->loop);
  return NULL;
}

static gchar *
extract_json_string (const gchar *body, const gchar *name)
{
  g_autofree gchar *prefix = g_strdup_printf ("\"%s\":\"", name);
  const gchar *start = strstr (body, prefix);
  if (start == NULL)
    return NULL;
  start += strlen (prefix);
  const gchar *end = strchr (start, '"');
  if (end == NULL)
    return NULL;
  return g_strndup (start, (gsize) (end - start));
}

static gint
send_raw (SoupSession *session, const gchar *method, const gchar *base_url,
    const gchar *path_and_query, guint *out_status, gchar **out_body)
{
  if (out_status == NULL || out_body == NULL)
    return 1;
  *out_status = 0;
  *out_body = NULL;

  g_autofree gchar *root = g_strdup (base_url);
  while (root[0] != '\0' && g_str_has_suffix (root, "/"))
    root[strlen (root) - 1] = '\0';
  g_autofree gchar *uri = g_strdup_printf ("%s%s", root, path_and_query);
  g_autoptr (SoupMessage) msg = soup_message_new (method, uri);
  if (msg == NULL)
    return 2;
  g_autoptr (GError) error = NULL;
  g_autoptr (GBytes) bytes = soup_session_send_and_read (session, msg, NULL,
      &error);
  if (bytes == NULL)
    return 3;
  const gchar *request_id = soup_message_headers_get_one
      (soup_message_get_response_headers (msg), "X-Wyrelog-Request-Id");
  if (request_id == NULL || request_id[0] == '\0')
    return 4;
  gsize size = 0;
  const gchar *data = g_bytes_get_data (bytes, &size);
  *out_status = soup_message_get_status (msg);
  *out_body = g_strndup (data, size);
  return 0;
}

static gint
do_login (SoupSession *session, const gchar *base_url, const gchar *username,
    gchar **out_session_token)
{
  *out_session_token = NULL;
  g_autofree gchar *path = g_strdup_printf ("/auth/login?username=%s",
      username);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return -1;
  if (status != 200)
    return -2;
  *out_session_token = extract_json_string (body, "session_token");
  if (*out_session_token == NULL)
    return -3;
  return 0;
}

static gint
seed_enrollment (WylHandle *handle, const gchar *subject_id)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  WylTotpEnrollment enr = { 0 };
  enr.subject_id = g_strdup (subject_id);
  memcpy (enr.secret, MFA_TEST_SEED, WYL_TOTP_SEED_BYTES);
  enr.last_verified_step = INT64_MIN;
  enr.enrolled_at = 1700000000;
  wyrelog_error_t rc = wyl_policy_store_totp_enrollment_insert (store, &enr);
  wyl_totp_enrollment_clear (&enr);
  return (rc == WYRELOG_E_OK) ? 0 : -1;
}

static gint
compute_current_code (gchar out_proof[8])
{
  gint64 now = (gint64) time (NULL);
  guint64 step = (guint64) (now / WYL_TOTP_STEP_SECONDS);
  guint code = 0;
  if (wyl_totp_code_at_step (MFA_TEST_SEED, sizeof MFA_TEST_SEED, step, &code,
          NULL) != WYRELOG_E_OK)
    return -1;
  g_snprintf (out_proof, 8, "%06u", code);
  return 0;
}

static gint
check_exact_auth_alias_canaries (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  WylDaemonExactRouteStateSnapshot before = { 0 }, after = { 0 };
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw (session, "POST", base_url,
          "/auth/login/x?username=mfa.alias-login", &status, &body) != 0)
    return 1300;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return 1301;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &after)
      || memcmp (&before, &after, sizeof before) != 0)
    return 1302;

  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.alias-verify", &session_token) != 0
      || seed_enrollment (handle, "mfa.alias-verify") != 0)
    return 1303;
  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 1304;
  WylTotpEnrollment enrollment_before = { 0 }, enrollment_after = { 0 };
  gboolean found_before = FALSE, found_after = FALSE;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_totp_enrollment_lookup (store, "mfa.alias-verify",
          &enrollment_before, &found_before) != WYRELOG_E_OK || !found_before)
    return 1305;
  g_autofree gchar *path = g_strdup_printf
      ("/auth/mfa/verify/x?session_token=%s&code=%s", session_token, proof);
  before = (WylDaemonExactRouteStateSnapshot) {
  0};
  after = (WylDaemonExactRouteStateSnapshot) {
  0};
  g_clear_pointer (&body, g_free);
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &before)
      || send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 1306;
  if (status != 404 || g_strcmp0 (body, "{\"error\":\"not_found\"}") != 0)
    return 1307;
  if (!wyl_daemon_http_exact_route_state_snapshot_for_test (server, &after)
      || memcmp (&before, &after, sizeof before) != 0
      || wyl_policy_store_totp_enrollment_lookup (store, "mfa.alias-verify",
          &enrollment_after, &found_after) != WYRELOG_E_OK || !found_after
      || enrollment_after.last_verified_step !=
      enrollment_before.last_verified_step)
    return 1308;
  wyl_totp_enrollment_clear (&enrollment_before);
  wyl_totp_enrollment_clear (&enrollment_after);
  return 0;
}

static gint
check_happy_path (SoupServer *server, WylHandle *handle, const gchar *base_url)
{
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.happy", &session_token) != 0)
    return 100;
  if (seed_enrollment (handle, "mfa.happy") != 0)
    return 101;
  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 102;

  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
      session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 103;
  if (status != 200)
    return 104;
  if (strstr (body, "\"principal_state\":\"authenticated\"") == NULL)
    return 105;
  if (strstr (body, "\"access_token\":\"") == NULL)
    return 106;
  if (strstr (body, "\"refresh_token\":\"") == NULL)
    return 107;
  g_autofree gchar *body_session = extract_json_string (body, "session_token");
  if (body_session == NULL || g_strcmp0 (body_session, session_token) != 0)
    return 108;
  /* F2: the submitted code MUST NOT appear in the body. */
  if (strstr (body, proof) != NULL)
    return 109;
  /* The stored WylSession must remain refable for subsequent calls. */
  g_autoptr (WylSession) stored =
      wyl_daemon_http_ref_session (server, session_token);
  if (stored == NULL)
    return 110;
  return 0;
}

static gint
check_wrong_code_rejected (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.wrong", &session_token) != 0)
    return 200;
  if (seed_enrollment (handle, "mfa.wrong") != 0)
    return 201;
  /* Pick a guaranteed-different code. */
  gchar correct[8];
  if (compute_current_code (correct) != 0)
    return 202;
  guint c = (guint) g_ascii_strtoull (correct, NULL, 10);
  guint wrong = (c + 1) % 1000000;
  gchar proof[8];
  g_snprintf (proof, sizeof proof, "%06u", wrong);

  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
      session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 203;
  if (status != 401)
    return 204;
  if (strstr (body, "\"mfa_invalid\"") == NULL)
    return 205;
  /* F2: don't leak the submitted code. */
  if (strstr (body, proof) != NULL)
    return 206;
  return 0;
}

static gint
check_no_enrollment_returns_enrollment_required (SoupServer *server,
    WylHandle *handle, const gchar *base_url)
{
  (void) server;
  (void) handle;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.no-enroll", &session_token) != 0)
    return 300;
  /* Intentionally do NOT seed an enrollment row. */
  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=000000",
      session_token);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 301;
  if (status != 401)
    return 302;
  if (strstr (body, "\"enrollment_required\"") == NULL)
    return 303;
  return 0;
}

static gint
check_authority_lookup_faults_are_not_missing (SoupServer *server,
    WylHandle *handle, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  g_autofree gchar *missing_token = NULL;
  if (do_login (session, base_url, "mfa.principal-missing", &missing_token)
      != 0)
    return 320;
  sqlite3 *db = wyl_policy_store_get_db (wyl_handle_get_policy_store (handle));
  if (sqlite3_exec (db,
          "DELETE FROM principal_states "
          "WHERE subject_id='mfa.principal-missing';", NULL, NULL, NULL)
      != SQLITE_OK)
    return 321;
  g_autofree gchar *missing_path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=000000", missing_token);
  if (send_raw (session, "POST", base_url, missing_path, &status, &body) != 0
      || status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 322;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *fault_token = NULL;
  if (do_login (session, base_url, "mfa.principal-read-fault", &fault_token)
      != 0)
    return 323;
  wyl_policy_store_principal_state_lookup_fail_on_call_for_test
      (wyl_handle_get_policy_store (handle), 1);
  g_autofree gchar *fault_path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=000000", fault_token);
  if (send_raw (session, "POST", base_url, fault_path, &status, &body) != 0
      || status != 500 || strstr (body, "\"mfa_verify_failed\"") == NULL)
    return 324;

  g_clear_pointer (&body, g_free);
  g_autofree gchar *enrollment_token = NULL;
  const gchar *subject = "mfa.enrollment-read-fault";
  if (do_login (session, base_url, subject, &enrollment_token) != 0
      || seed_enrollment (handle, subject) != 0)
    return 325;
  gchar correct[8];
  if (compute_current_code (correct) != 0)
    return 326;
  guint code = (guint) g_ascii_strtoull (correct, NULL, 10);
  wyl_policy_store_totp_enrollment_lookup_fail_on_call_for_test
      (wyl_handle_get_policy_store (handle), 2);
  g_autofree gchar *enrollment_path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=%06u", enrollment_token,
      (code + 1) % 1000000);
  if (send_raw (session, "POST", base_url, enrollment_path, &status, &body)
      != 0 || status != 500 || strstr (body, "\"mfa_verify_failed\"") == NULL)
    return 327;
  return 0;
}

static gint
check_missing_session_token (SoupServer *server, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (send_raw (session, "POST", base_url,
          "/auth/mfa/verify?code=000000", &status, &body) != 0)
    return 400;
  if (status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 401;
  g_clear_pointer (&body, g_free);

  if (send_raw (session, "POST", base_url,
          "/auth/mfa/verify?session_token=&code=000000", &status, &body) != 0)
    return 402;
  if (status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 403;
  return 0;
}

static gint
check_unknown_session_token (SoupServer *server, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  guint status = 0;
  g_autofree gchar *body = NULL;

  if (send_raw (session, "POST", base_url,
          "/auth/mfa/verify?session_token=bogus-token&code=000000",
          &status, &body) != 0)
    return 500;
  /* F5: same error code as missing-token; never leak existence. */
  if (status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 501;
  return 0;
}

static gint
check_wrong_state_session (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  (void) server;
  /* Acquire an already-authenticated session via skip_mfa. */
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *path =
      g_strdup_printf ("/auth/login?username=mfa.skip&skip_mfa=true");
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 600;
  }
  if (status != 200) {
    wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
    return 601;
  }
  g_autofree gchar *session_token = extract_json_string (body,
      "session_token");
  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (session_token == NULL)
    return 602;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *verify_path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=000000",
      session_token);
  if (send_raw (session, "POST", base_url, verify_path, &status, &body) != 0)
    return 603;
  /* F5: wrong-state session must return the same code as
   * unknown-session, not a distinguishable one. */
  if (status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 604;
  return 0;
}

static gint
check_missing_code (SoupServer *server, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.missing-code", &session_token) != 0)
    return 700;
  guint status = 0;
  g_autofree gchar *body = NULL;
  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s", session_token);
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 701;
  if (status != 400 || strstr (body, "\"invalid_mfa_request\"") == NULL)
    return 702;
  g_clear_pointer (&body, g_free);

  g_autofree gchar *path_empty =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=",
      session_token);
  if (send_raw (session, "POST", base_url, path_empty, &status, &body) != 0)
    return 703;
  if (status != 400 || strstr (body, "\"invalid_mfa_request\"") == NULL)
    return 704;
  return 0;
}

static gint
check_malformed_codes (SoupServer *server, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.malformed", &session_token) != 0)
    return 800;

  static const struct
  {
    const gchar *code;
  } cases[] = {
    {"12345"},                  /* 5 chars */
    {"1234567"},                /* 7 chars */
    {"12345a"},                 /* non-digit at end */
    {"a12345"},                 /* non-digit at front */
    {"%201234"},                /* url-encoded leading space */
    {"+12345"},                 /* leading plus */
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_autofree gchar *path =
        g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
        session_token, cases[i].code);
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
      return 801 + (gint) i *10;
    if (status != 400 || strstr (body, "\"invalid_mfa_request\"") == NULL)
      return 802 + (gint) i *10;
  }
  return 0;
}

static gint
check_method_gate (SoupServer *server, const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  static const gchar *methods[] = { "GET", "PUT", "DELETE" };
  for (gsize i = 0; i < G_N_ELEMENTS (methods); i++) {
    guint status = 0;
    g_autofree gchar *body = NULL;
    if (send_raw (session, methods[i], base_url,
            "/auth/mfa/verify?session_token=t&code=123456", &status,
            &body) != 0)
      return 900 + (gint) i *10;
    if (status != 405 || strstr (body, "\"method_not_allowed\"") == NULL)
      return 901 + (gint) i *10;
  }
  return 0;
}

static gint
check_replay_rejection (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.replay", &session_token) != 0)
    return 1000;
  if (seed_enrollment (handle, "mfa.replay") != 0)
    return 1001;
  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 1002;

  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
      session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 1003;
  if (status != 200)
    return 1004;
  g_clear_pointer (&body, g_free);

  /* Second call with the SAME code on the SAME session. The validator
   * persisted last_verified_step on the first call; the second call
   * must be rejected as a replay.  The session-state gate will catch
   * this first (it is now authenticated, not mfa_required), so the
   * surfaced code is the uniform mfa_auth_required. */
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 1005;
  if (status != 401)
    return 1006;
  if (strstr (body, "\"mfa_auth_required\"") == NULL &&
      strstr (body, "\"mfa_invalid\"") == NULL)
    return 1007;
  return 0;
}

static gint
check_tenant_sealed_between_login_and_verify (SoupServer *server,
    WylHandle *handle, const gchar *base_url)
{
  (void) server;
  /* Use a non-default tenant: the policy store explicitly refuses to
   * seal __wr_default (see wyl_policy_store_set_tenant_sealed). */
  static const gchar *tenant_id = "mfa-sealed-tenant";
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean created = FALSE;
  if (wyl_policy_store_create_tenant (store, tenant_id, &created) !=
      WYRELOG_E_OK)
    return 1100;

  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *login_path =
      g_strdup_printf ("/auth/login?username=mfa.sealed&tenant=%s", tenant_id);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, login_path, &status, &body) != 0)
    return 1101;
  if (status != 200)
    return 1102;
  g_autofree gchar *session_token = extract_json_string (body,
      "session_token");
  if (session_token == NULL)
    return 1103;
  g_clear_pointer (&body, g_free);
  if (seed_enrollment (handle, "mfa.sealed") != 0)
    return 1104;

  if (wyl_policy_store_set_tenant_sealed (store, tenant_id, TRUE)
      != WYRELOG_E_OK)
    return 1105;

  gchar proof[8];
  if (compute_current_code (proof) != 0) {
    (void) wyl_policy_store_set_tenant_sealed (store, tenant_id, FALSE);
    return 1106;
  }
  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
      session_token, proof);
  gint send_rc = send_raw (session, "POST", base_url, path, &status, &body);
  /* Unseal before asserting so a failure does not leave the harness
   * with a sealed tenant for any follow-up test. */
  (void) wyl_policy_store_set_tenant_sealed (store, tenant_id, FALSE);
  if (send_rc != 0)
    return 1107;
  if (status != 400)
    return 1108;
  if (strstr (body, "\"tenant_sealed\"") == NULL)
    return 1109;
  return 0;
}

static gint
check_locked_principal_returns_locked (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  (void) server;
  /* Structural coverage of the "principal LOCKED -> 429 mfa_locked"
   * branch. Commit 5 introduces the FSM-driven lockout; here we
   * directly write principal_state=locked for the subject AFTER login
   * so the handler observes a locked principal at verify time. */
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, "mfa.locked", &session_token) != 0)
    return 1200;
  if (seed_enrollment (handle, "mfa.locked") != 0)
    return 1201;

  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  if (wyl_policy_store_set_principal_state (store, "mfa.locked",
          "locked") != WYRELOG_E_OK)
    return 1202;

  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 1203;
  g_autofree gchar *path =
      g_strdup_printf ("/auth/mfa/verify?session_token=%s&code=%s",
      session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return 1204;
  /* Per issue #331 spec: HTTP 429 with mfa_locked code. */
  if (status != 429)
    return 1205;
  if (strstr (body, "\"mfa_locked\"") == NULL)
    return 1206;
  return 0;
}

static gint
check_elapsed_lock_returns_auth_required (WylHandle *handle,
    const gchar *base_url)
{
  const gchar *subject = "mfa.elapsed-lock";
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, subject, &session_token) != 0
      || seed_enrollment (handle, subject) != 0)
    return 1250;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  for (gint i = 0; i < 5; i++) {
    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = 0;
    if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
            &state, &count, &locked_at) != WYRELOG_E_OK)
      return 1251;
  }
  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 1252;
  g_autofree gchar *path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=%s", session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0
      || status != 401 || strstr (body, "\"mfa_auth_required\"") == NULL)
    return 1253;
  return 0;
}

static gint
check_elapsed_unlock_publication_fault_returns_500 (WylHandle *handle,
    const gchar *base_url)
{
  const gchar *subject = "mfa.elapsed-unlock-fault";
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, subject, &session_token) != 0
      || seed_enrollment (handle, subject) != 0)
    return 1260;
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gint64 ago = (gint64) time (NULL) - (16 * 60);
  for (gint failure = 0; failure < 5; failure++) {
    g_autofree gchar *state = NULL;
    gint64 count = 0, locked_at = 0;
    if (wyl_policy_store_apply_principal_failure (store, subject, 5, ago,
            &state, &count, &locked_at) != WYRELOG_E_OK)
      return 1261;
  }
  gchar proof[8];
  if (compute_current_code (proof) != 0)
    return 1262;
  wyl_handle_set_engine_replacement_fault_once_for_test (handle,
      WYL_ENGINE_REPLACEMENT_FAULT_PUBLICATION_VERIFY_POLICY);
  g_autofree gchar *path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=%s", session_token, proof);
  guint status = 0;
  g_autofree gchar *body = NULL;
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0
      || status != 500 || strstr (body, "\"mfa_verify_failed\"") == NULL
      || !wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 1263;
  g_autofree gchar *state = NULL;
  gint64 count = -1, locked_at = 0;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info (store, subject, &state,
          &count, &locked_at, &found) != WYRELOG_E_OK || !found
      || g_strcmp0 (state, "unverified") != 0 || count != 0
      || locked_at != G_MININT64)
    return 1264;
  return 0;
}

static gint
check_failed_attempt_lock_publication (SoupServer *server, WylHandle *handle,
    const gchar *base_url, const gchar *username, gboolean inject_fault,
    gint error_base)
{
  (void) server;
  g_autoptr (SoupSession) session = soup_session_new ();
  g_autofree gchar *session_token = NULL;
  if (do_login (session, base_url, username, &session_token) != 0
      || seed_enrollment (handle, username) != 0)
    return error_base;
  gchar correct[8];
  if (compute_current_code (correct) != 0)
    return error_base + 1;
  guint code = (guint) g_ascii_strtoull (correct, NULL, 10);
  g_autofree gchar *path = g_strdup_printf
      ("/auth/mfa/verify?session_token=%s&code=%06u", session_token,
      (code + 1) % 1000000);
  guint status = 0;
  g_autofree gchar *body = NULL;
  for (guint attempt = 1; attempt <= 4; attempt++) {
    if (send_raw (session, "POST", base_url, path, &status, &body) != 0
        || status != 401 || strstr (body, "\"mfa_invalid\"") == NULL)
      return error_base + 1 + (gint) attempt;
    g_clear_pointer (&body, g_free);
  }
  if (inject_fault)
    wyl_handle_set_engine_replacement_fault_once_for_test (handle,
        WYL_ENGINE_REPLACEMENT_FAULT_PRINCIPAL_STATES);
  if (send_raw (session, "POST", base_url, path, &status, &body) != 0)
    return error_base + 6;
  if (status != (inject_fault ? 500 : 401)
      || strstr (body, inject_fault ? "\"mfa_verify_failed\"" :
          "\"mfa_invalid\"") == NULL)
    return error_base + 7;

  g_autofree gchar *state = NULL;
  gint64 count = 0;
  gint64 locked_at = G_MININT64;
  gboolean found = FALSE;
  if (wyl_policy_store_get_principal_lock_info
      (wyl_handle_get_policy_store (handle), username, &state, &count,
          &locked_at, &found) != WYRELOG_E_OK || !found || count != 5
      || g_strcmp0 (state, "locked") != 0 || locked_at == G_MININT64)
    return error_base + 8;
  if (!inject_fault) {
    g_clear_pointer (&body, g_free);
    if (send_raw (session, "POST", base_url, path, &status, &body) != 0
        || status != 429 || strstr (body, "\"mfa_locked\"") == NULL)
      return error_base + 9;
  }
  return 0;
}

typedef struct
{
  const gchar *subject_id;
  gint64 event_id;
  gboolean force_failure;
} LockoutReconcileVerify;

static wyrelog_error_t
capture_lockout_event_id (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer data)
{
  (void) from_state;
  (void) to_state;
  LockoutReconcileVerify *verify = data;
  if (g_strcmp0 (subject_id, verify->subject_id) == 0
      && g_strcmp0 (event, "lock") == 0)
    verify->event_id = event_id;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
verify_lockout_reconciliation (WylHandle *handle, gpointer data)
{
  LockoutReconcileVerify *verify = data;
  if (verify->force_failure)
    return WYRELOG_E_POLICY;
  const gchar *symbols[] = {
    verify->subject_id,
    "locked",
    "mfa_required",
    "lock",
  };
  gint64 ids[G_N_ELEMENTS (symbols)] = { 0 };
  for (gsize i = 0; i < G_N_ELEMENTS (symbols); i++) {
    if (wyl_handle_intern_engine_symbol (handle, symbols[i], &ids[i])
        != WYRELOG_E_OK)
      return WYRELOG_E_POLICY;
  }
  const gint64 state_row[] = { ids[0], ids[1] };
  const gint64 event_row[] = {
    verify->event_id, ids[0], ids[2], ids[3], ids[1]
  };
  gboolean has_state = FALSE;
  gboolean has_event = FALSE;
  if (wyl_handle_engine_contains (handle, "principal_state", state_row,
          G_N_ELEMENTS (state_row), &has_state) != WYRELOG_E_OK
      || wyl_handle_engine_contains (handle, "principal_fired", event_row,
          G_N_ELEMENTS (event_row), &has_event) != WYRELOG_E_OK)
    return WYRELOG_E_INTERNAL;
  return has_state && has_event ? WYRELOG_E_OK : WYRELOG_E_POLICY;
}

static gint
check_lock_publication_fault_repairs (SoupServer *server, WylHandle *handle,
    const gchar *base_url)
{
  gint rc = check_failed_attempt_lock_publication (server, handle, base_url,
      "mfa.lock-fault", TRUE, 1500);
  if (rc != 0)
    return rc;
  if (!wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 1510;
  LockoutReconcileVerify verify = {
    .subject_id = "mfa.lock-fault",
    .event_id = -1,
    .force_failure = TRUE,
  };
  if (wyl_policy_store_foreach_principal_event
      (wyl_handle_get_policy_store (handle), capture_lockout_event_id,
          &verify) != WYRELOG_E_OK || verify.event_id <= 0)
    return 1511;
  if (wyl_handle_reconcile_committed_engine_pair (handle,
          verify_lockout_reconciliation, &verify) != WYRELOG_E_POLICY
      || !wyl_handle_engine_pair_is_poisoned (handle)
      || wyl_handle_engine_pair_is_ready (handle))
    return 1512;
  verify.force_failure = FALSE;
  if (wyl_handle_reconcile_committed_engine_pair (handle,
          verify_lockout_reconciliation, &verify) != WYRELOG_E_OK
      || wyl_handle_engine_pair_is_poisoned (handle)
      || !wyl_handle_engine_pair_is_ready (handle))
    return 1513;
  return 0;
}

int
main (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 1;

  /* Install the TOTP validator on the handle so the HTTP route can
   * resolve it via wyl_handle_get_mfa_validator. The daemon init
   * path wires this in production; the test wires it explicitly. */
  wyl_handle_set_mfa_validator (handle, wyl_mfa_validator_totp, NULL);

  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 2;
  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 3;
  GThread *thread = g_thread_new ("daemon-http-mfa",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 4;
  g_autofree gchar *base_url = g_uri_to_string (uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);

  gint rc;
  if ((rc = check_method_gate (http.server, base_url)) != 0)
    goto out;
  if ((rc = check_exact_auth_alias_canaries (http.server, handle,
              base_url)) != 0)
    goto out;
  if ((rc = check_missing_session_token (http.server, base_url)) != 0)
    goto out;
  if ((rc = check_unknown_session_token (http.server, base_url)) != 0)
    goto out;
  if ((rc = check_missing_code (http.server, base_url)) != 0)
    goto out;
  if ((rc = check_malformed_codes (http.server, base_url)) != 0)
    goto out;
  if ((rc = check_no_enrollment_returns_enrollment_required (http.server,
              handle, base_url)) != 0)
    goto out;
  if ((rc = check_authority_lookup_faults_are_not_missing (http.server,
              handle, base_url)) != 0)
    goto out;
  if ((rc = check_wrong_code_rejected (http.server, handle, base_url)) != 0)
    goto out;
  if ((rc = check_wrong_state_session (http.server, handle, base_url)) != 0)
    goto out;
  if ((rc = check_happy_path (http.server, handle, base_url)) != 0)
    goto out;
  if ((rc = check_replay_rejection (http.server, handle, base_url)) != 0)
    goto out;
  if ((rc = check_tenant_sealed_between_login_and_verify (http.server, handle,
              base_url)) != 0)
    goto out;
  if ((rc = check_locked_principal_returns_locked (http.server, handle,
              base_url)) != 0)
    goto out;
  if ((rc = check_elapsed_lock_returns_auth_required (handle, base_url)) != 0)
    goto out;
  if ((rc = check_failed_attempt_lock_publication (http.server, handle,
              base_url, "mfa.fifth-lock", FALSE, 1400)) != 0)
    goto out;
  if ((rc = check_lock_publication_fault_repairs (http.server, handle,
              base_url)) != 0)
    goto out;
  if ((rc = check_elapsed_unlock_publication_fault_returns_500 (handle,
              base_url)) != 0)
    goto out;

out:
  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return rc;
}
