/* SPDX-License-Identifier: GPL-3.0-or-later */
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700
#endif

/*
 * Drives `wyctl service-credential issue` as a child process against a
 * wyrelogd HTTP server booted in-process on loopback, in the spirit of
 * test-wyctl-policy-daemon: boot the daemon, seed a privileged operator,
 * write its bearer access token to a temp file, then exec the wyctl binary
 * against the live daemon and assert the CLI exit code.
 *
 * Why this seeds via the daemon-http test seams instead of
 * wyl_client_login_skip_mfa: a service subject must be svc:<tenant>:... where
 * <tenant> is an alphanumeric-bounded tenant segment, so the default tenant
 * (__wr_default, which login binds to) is not a legal service-subject tenant.
 * The operator's bearer session must therefore be bound to a real tenant
 * (tenant-a here), which login_skip_mfa cannot express. seed_human_session +
 * issue_human_tokens give a bearer token bound to that tenant -- the same
 * seeding shape check_service_principal_management_contract uses.
 *
 * Scope note: this test deliberately does NOT reach the delivered=yes escrow
 * receipt. That outcome needs an encrypted keyprovider store to seal a service
 * CVK, both escrow roots configured, and the publication override -- none of
 * which this harness installs. The delivered escrow-receipt path is already
 * covered by check_service_principal_management_contract (daemon-http) and
 * test-client-smoke. What this test proves is the CLI-specific wiring end to
 * end: the CLI-minted bearer request is ACCEPTED, authorization is genuinely
 * enforced, and the CLI maps the daemon's rc onto the documented exit codes.
 *
 * With an authorized operator but NO escrow roots configured, the issue
 * handler passes auth and then returns 503 service_credential_unavailable (the
 * handoff module fails closed on unconfigured roots), which the client maps to
 * WYRELOG_E_IO -> wyctl exit 5. A control operator that is authenticated with
 * an active session but WITHOUT the wr.service_credential.manage grant is
 * denied at the decision (403) -> wyctl exit 4. The delta between exit 5 (auth
 * passed, service unavailable) and exit 4 (denied) is what proves the token
 * was accepted and authorization actually gates the call.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "daemon/delta.h"
#include "daemon/http.h"
#include "wyrelog/client.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-id-private.h"
#include "wyrelog/wyl-session-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

#ifndef WYL_TEST_WYCTL_PATH
#error "WYL_TEST_WYCTL_PATH must be defined by the build."
#endif

/* A real, alphanumeric-bounded tenant so svc:<tenant>:worker is a legal
 * service subject; the default tenant would be rejected by the validator. */
#define WYL_TEST_SERVICE_TENANT "tenant-a"

/* A future absolute expiry in epoch microseconds (2030-01-01) so the daemon's
 * expires_at_us > 0 gate is satisfied and the request reaches the escrow
 * handoff (which then fails closed on the missing roots). */
#define WYL_TEST_FUTURE_EXPIRY_US "1893456000000000"

/* A canonical 27-char alphanumeric request id (WYL_REQUEST_ID_STRING_LEN). It
 * passes the client's is-canonical gate so the recover request reaches the
 * daemon; the unconfigured operation surface then returns 404 NOT_FOUND. */
#define WYL_TEST_RECOVER_REQUEST_ID "abcdefghijklmnopqrstuvwxyz0"

typedef struct
{
  SoupServer *server;
  GMainLoop *loop;
} TestHttpServer;

static gpointer
test_http_server_thread (gpointer data)
{
  TestHttpServer *http = data;

  g_main_loop_run (http->loop);
  return NULL;
}

/* Seed the policy facts the management decision reads: an authenticated
 * principal and an active session scoped to the canonical session id (which
 * the authorize path evaluates as the decide resource). When |grant_manage| is
 * TRUE, wr.service_credential.manage is granted and armed on that same scope so
 * the decision ALLOWs; when FALSE the operator is a valid authenticated human
 * whose request is denied purely for lack of the grant. */
static wyrelog_error_t
seed_service_operator (WylHandle *handle, const gchar *subject,
    const gchar *session_scope, gboolean grant_manage)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyrelog_error_t rc = wyl_policy_store_set_principal_state (store, subject,
      "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, session_scope, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  if (grant_manage) {
    rc = wyl_policy_store_grant_direct_permission (store, subject,
        "wr.service_credential.manage", session_scope);
    if (rc != WYRELOG_E_OK)
      return rc;
    rc = wyl_policy_store_set_permission_state (store, subject,
        "wr.service_credential.manage", session_scope, "armed");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return wyl_handle_reload_engine_pair (handle);
}

static gchar *
write_token_file (const gchar *token)
{
  g_autoptr (GError) error = NULL;
  gchar *token_path = NULL;
  gint fd = g_file_open_tmp ("wyctl-svc-cred-daemon-token-XXXXXX", &token_path,
      &error);
  g_assert_no_error (error);
  g_assert_cmpint (fd, >=, 0);
  g_assert_true (g_close (fd, NULL));
  g_assert_true (g_file_set_contents (token_path, token, -1, &error));
  g_assert_no_error (error);
  /* wyctl's token-file safety check requires 0600-or-stricter; g_file_set_
   * contents applies the umask (0644 on CI), so force 0600. */
  g_assert_cmpint (g_chmod (token_path, 0600), ==, 0);
  return token_path;
}

/* Seed one bearer operator bound to WYL_TEST_SERVICE_TENANT and return the
 * path to a temp file holding its access token (owned by the caller). */
static gchar *
seed_bearer_operator (SoupServer *server, WylHandle *handle,
    const gchar *subject, gboolean grant_manage)
{
  wyl_id_t session_id = WYL_ID_NIL;
  gchar session_text[WYL_ID_STRING_BUF];
  g_assert_cmpint (wyl_id_new (&session_id), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_id_format (&session_id, session_text,
          sizeof session_text), ==, WYRELOG_E_OK);

  g_assert_true (wyl_daemon_http_seed_human_session_for_test (server,
          session_text, subject, WYL_TEST_SERVICE_TENANT));

  g_autoptr (WylSession) session = wyl_daemon_http_ref_session (server,
      session_text);
  g_assert_nonnull (session);

  /* Seed the policy facts first: issuing a human access token requires the
   * subject's principal_state to already read "authenticated" (the daemon's
   * human_session_matches gate), so the grant/state seeding must precede the
   * token mint. */
  g_assert_cmpint (seed_service_operator (handle, subject, session_text,
          grant_manage), ==, WYRELOG_E_OK);

  g_autofree gchar *access = NULL;
  g_autofree gchar *refresh = NULL;
  g_assert_cmpint (wyl_daemon_http_issue_human_tokens_for_test (server, session,
          session_text, subject, WYL_TEST_SERVICE_TENANT, &access, &refresh),
      ==, WYRELOG_E_OK);
  g_assert_nonnull (access);

  return write_token_file (access);
}

/* Run wyctl and assert its exit code is one of |ok_exits|, that stdout is empty
 * (the receipt is printed only on success, and no secret is ever printed), and
 * that neither stream leaks obvious secret material. */
static void
assert_wyctl_exit_no_secret (gchar **argv, const int *ok_exits, gsize n_ok)
{
  g_autofree gchar *stdout_buf = NULL;
  g_autofree gchar *stderr_buf = NULL;
  gint wait_status = 0;
  g_autoptr (GError) error = NULL;

  g_assert_true (g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
          &stdout_buf, &stderr_buf, &wait_status, &error));
  g_assert_no_error (error);
  g_assert_true (WIFEXITED (wait_status));

  int code = WEXITSTATUS (wait_status);
  gboolean matched = FALSE;
  for (gsize i = 0; i < n_ok; i++)
    matched = matched || code == ok_exits[i];
  if (!matched) {
    g_printerr ("wyctl exited %d\nstdout: %s\nstderr: %s\n", code,
        stdout_buf ? stdout_buf : "(null)", stderr_buf ? stderr_buf : "(null)");
    g_assert_not_reached ();
  }

  /* No receipt line and no secret on any failure path. */
  g_assert_cmpstr (stdout_buf, ==, "");
  g_assert_null (strstr (stderr_buf, "-----BEGIN"));
  g_assert_null (strstr (stderr_buf, "secret="));
}

int
main (void)
{
  g_autoptr (WylHandle) handle = NULL;
  const WylHandleOpenOptions open_opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
  };
  if (wyl_handle_open_with_options (&open_opts, &handle) != WYRELOG_E_OK)
    return 1;

  gboolean tenant_created = FALSE;
  if (wyl_policy_store_create_tenant (wyl_handle_get_policy_store (handle),
          WYL_TEST_SERVICE_TENANT, &tenant_created) != WYRELOG_E_OK
      || !tenant_created)
    return 2;

  /* No operation_root / credential_publication_root: the escrow handoff fails
   * closed with 503 service_credential_unavailable AFTER authorization, which
   * is exactly the CLI rc-mapping edge this test exercises. */
  WylDaemonOptions opts = {
    .template_dir = WYL_TEST_TEMPLATE_DIR,
    .listen_port = 0,
  };
  WylDaemonRuntime runtime = {
    .handle = handle,
  };
  if (wyl_daemon_start_delta_callbacks (handle, &runtime) != WYRELOG_E_OK)
    return 3;

  TestHttpServer http = { 0 };
  http.loop = g_main_loop_new (NULL, FALSE);
  g_autoptr (GError) error = NULL;
  http.server = wyl_daemon_start_http_server_with_runtime (&opts, handle,
      &runtime, &error);
  if (http.server == NULL)
    return 4;
  GThread *thread = g_thread_new ("wyctl-svc-cred-daemon",
      test_http_server_thread, &http);

  GSList *uris = soup_server_get_uris (http.server);
  if (uris == NULL)
    return 5;
  /* Build a canonical literal-loopback base URL: the client's secret-transport
   * gate on issue requires exactly 127.0.0.1 (or an IPv6 loopback literal), so
   * pin the host and take only the bound port from the server. */
  gint port = g_uri_get_port ((GUri *) uris->data);
  g_slist_free_full (uris, (GDestroyNotify) g_uri_unref);
  if (port <= 0)
    return 6;
  g_autofree gchar *base_url = g_strdup_printf ("http://127.0.0.1:%d", port);

  /* (a) Authorized operator: authenticated + active session + the manage
   * grant. (b) Control operator: authenticated + active session but no
   * grant. */
  g_autofree gchar *authorized_token_path = seed_bearer_operator (http.server,
      handle, "human-svc-admin", TRUE);
  g_autofree gchar *denied_token_path = seed_bearer_operator (http.server,
      handle, "human-svc-denied", FALSE);

  /* (a) Auth passes, but no escrow roots -> 503 -> wyctl exit 5. Exit 5 (and
   * not 4/6) proves the bearer token was accepted and authorization PASSED. */
  gchar *issue_authorized_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-credential", "issue",
    "--subject", "svc:" WYL_TEST_SERVICE_TENANT ":worker",
    "--tenant", WYL_TEST_SERVICE_TENANT,
    "--destination", "worker.cred",
    "--expires-at-us", WYL_TEST_FUTURE_EXPIRY_US,
    "--access-token-file", authorized_token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  const int authorized_ok[] = { 5 };
  assert_wyctl_exit_no_secret (issue_authorized_argv, authorized_ok,
      G_N_ELEMENTS (authorized_ok));

  /* (b) Same call with the ungranted operator -> decision DENY (403) ->
   * wyctl exit 4 (or 6 if auth fails earlier). The delta from (a) proves
   * authorization is genuinely enforced. */
  gchar *issue_denied_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-credential", "issue",
    "--subject", "svc:" WYL_TEST_SERVICE_TENANT ":worker",
    "--tenant", WYL_TEST_SERVICE_TENANT,
    "--destination", "worker.cred",
    "--expires-at-us", WYL_TEST_FUTURE_EXPIRY_US,
    "--access-token-file", denied_token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  /* Policy DENY maps to 403 -> E_POLICY -> exit 4.  Exit 6 (E_AUTH) is
   * deliberately NOT accepted: the control operator is authenticated, so a
   * failure here must be the manage-grant denial, proving authz is enforced. */
  const int denied_ok[] = { 4 };
  assert_wyctl_exit_no_secret (issue_denied_argv, denied_ok,
      G_N_ELEMENTS (denied_ok));

  /*
   * (c)/(d) Delegation surface: `service-credential status` and
   * `service-credential recover` drive the #475 client end to end against the
   * live daemon and map the daemon's rc onto the documented exit codes without
   * ever printing stdout or leaking a secret. Both are guarded management
   * commands, so each invocation supplies the guard context (--guard-timestamp
   * / --guard-loc-class / --guard-risk) the CLI now requires -- the same guard
   * values as the authorized issue leg above, so the armed manage grant makes
   * the daemon's guarded decision ALLOW rather than reject at the guard gate.
   *
   * The reachable exit depends on the build profile of the in-process daemon,
   * which the shared WYL_HAS_FACT_STORE macro also selects here:
   *
   *  - Fact-store DISABLED (this leg): the /service-credential-operations
   *    routes are compiled out of daemon/http.c (they live under
   *    #ifdef WYL_HAS_FACT_STORE), so every request 404s at the default
   *    handler -> E_NOT_FOUND -> wyctl exit 5 for both verbs.
   *
   *  - Fact-store ENABLED: the routes exist, the guard params are present, and
   *    the authorized operator holds the armed wr.service_credential.manage
   *    grant, so authorization ALLOWs (profile==SYSTEM precheck passes on this
   *    harness). This harness configures NO operation_root, so the two verbs
   *    diverge on the unconfigured surface: status lists an empty operation set
   *    -> 200 -> E_OK -> wyctl exit 0 (empty stdout, nothing to print); recover
   *    has nothing to recover for the (canonical) request id -> 404 NOT_FOUND
   *    -> E_NOT_FOUND -> wyctl exit 5.
   *
   * Either way the CLI wiring, guard pass-through, and rc->exit mapping are
   * exercised. The fully seeded auth-delta (allow / deny / bad-bearer) and the
   * populated operation-surface happy paths for these endpoints are covered at
   * the HTTP layer by test-daemon-http-decide.c, which drives the guarded
   * routes directly with a configured operation_root.
   */
#ifdef WYL_HAS_FACT_STORE
  const int status_ok[] = { 0 };
  const int recover_ok[] = { 5 };
#else
  const int status_ok[] = { 5 };
  const int recover_ok[] = { 5 };
#endif

  gchar *status_authorized_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-credential", "status",
    "--tenant", WYL_TEST_SERVICE_TENANT,
    "--access-token-file", authorized_token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_wyctl_exit_no_secret (status_authorized_argv, status_ok,
      G_N_ELEMENTS (status_ok));

  gchar *recover_authorized_argv[] = {
    (gchar *) WYL_TEST_WYCTL_PATH,
    "--daemon-url", base_url,
    "service-credential", "recover",
    "--request-id", WYL_TEST_RECOVER_REQUEST_ID,
    "--tenant", WYL_TEST_SERVICE_TENANT,
    "--access-token-file", authorized_token_path,
    "--guard-timestamp", "123",
    "--guard-loc-class", "public",
    "--guard-risk", "10",
    NULL,
  };
  assert_wyctl_exit_no_secret (recover_authorized_argv, recover_ok,
      G_N_ELEMENTS (recover_ok));

  g_unlink (authorized_token_path);
  g_unlink (denied_token_path);

  g_main_loop_quit (http.loop);
  g_thread_join (thread);
  soup_server_disconnect (http.server);
  g_clear_object (&http.server);
  g_clear_pointer (&http.loop, g_main_loop_unref);
  return 0;
}
