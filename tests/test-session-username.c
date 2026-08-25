/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/wyl-common-private.h"
#include "wyrelog/wyl-handle-private.h"
#include "wyrelog/wyl-session-private.h"
#include "wyrelog/wyl-session-layout-private.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
store_active_scope (WylHandle *handle, const gchar *scope)
{
  return wyl_policy_store_set_session_state (wyl_handle_get_policy_store
               (handle), scope, "active");
}

static wyrelog_error_t
grant_direct (WylHandle *handle, const gchar *subject_id,
    const gchar *permission, const gchar *scope)
{
  g_autoptr (wyl_grant_req_t) grant = wyl_grant_req_new ();
  wyl_grant_req_set_subject_id (grant, subject_id);
  wyl_grant_req_set_action (grant, permission);
  wyl_grant_req_set_resource_id (grant, scope);
  return wyl_perm_grant (handle, grant);
}

static wyrelog_error_t
grant_role_permission (WylHandle *handle, const gchar *subject_id,
    const gchar *role_id, const gchar *permission, const gchar *scope)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  gboolean exists = FALSE;
  wyrelog_error_t rc = wyl_policy_store_role_exists (store, role_id, &exists);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!exists) {
    rc = wyl_policy_store_upsert_role (store, role_id, role_id);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  rc = wyl_policy_store_permission_exists (store, permission, &exists);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!exists) {
    rc = wyl_policy_store_upsert_permission (store, permission, permission,
            "basic");
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  rc = wyl_policy_store_grant_role_permission (store, role_id, permission);
  if (rc != WYRELOG_E_OK)
    return rc;

  g_autoptr (wyl_role_grant_req_t) grant = wyl_role_grant_req_new ();
  wyl_role_grant_req_set_subject_id (grant, subject_id);
  wyl_role_grant_req_set_role_id (grant, role_id);
  wyl_role_grant_req_set_scope (grant, scope);
  return wyl_role_grant (handle, grant);
}

typedef struct
{
  const gchar *session_id;
  const gchar *state;
  guint matches;
} SessionStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *session_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} SessionEventExpect;

static wyrelog_error_t
session_state_expect_cb (const gchar *session_id, const gchar *state,
    gpointer user_data)
{
  SessionStateExpect *expect = user_data;

  if (g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
session_event_expect_cb (gint64 event_id, const gchar *session_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  SessionEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (session_id, expect->session_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0) {
    if (expect->event_id <= 0)
      expect->event_id = event_id;
    expect->matches++;
  }
  return WYRELOG_E_OK;
}

typedef struct
{
  const gchar *subject_id;
  const gchar *state;
  guint matches;
} PrincipalStateExpect;

typedef struct
{
  gint64 event_id;
  const gchar *subject_id;
  const gchar *event;
  const gchar *from_state;
  const gchar *to_state;
  guint matches;
} PrincipalEventExpect;

typedef struct
{
  const gchar *relation;
  const gint64 *row;
  guint matches;
} PrincipalEventFactExpect;

typedef struct
{
  const gchar *relation;
  const gint64 *row;
  guint ncols;
  WylDeltaKind kind;
  guint matches;
} DeltaFactExpect;

typedef struct
{
  guint principal_fired;
  guint session_fired;
} LogoutDeltaCounts;

static void
logout_delta_counts_cb (const gchar *relation, const gint64 *row,
    guint ncols, WylDeltaKind kind, gpointer user_data)
{
  LogoutDeltaCounts *counts = user_data;
  (void) row;
  (void) ncols;
  if (kind != WYL_DELTA_INSERT)
    return;
  if (g_strcmp0 (relation, "principal_fired") == 0)
    counts->principal_fired++;
  else if (g_strcmp0 (relation, "session_fired") == 0)
    counts->session_fired++;
}

static wyrelog_error_t
principal_state_expect_cb (const gchar *subject_id, const gchar *state,
    gpointer user_data)
{
  PrincipalStateExpect *expect = user_data;

  if (g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (state, expect->state) == 0)
    expect->matches++;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
principal_event_expect_cb (gint64 event_id, const gchar *subject_id,
    const gchar *event, const gchar *from_state, const gchar *to_state,
    gpointer user_data)
{
  PrincipalEventExpect *expect = user_data;

  if ((expect->event_id <= 0 || event_id == expect->event_id)
      && g_strcmp0 (subject_id, expect->subject_id) == 0
      && g_strcmp0 (event, expect->event) == 0
      && g_strcmp0 (from_state, expect->from_state) == 0
      && g_strcmp0 (to_state, expect->to_state) == 0) {
    if (expect->event_id <= 0)
      expect->event_id = event_id;
    expect->matches++;
  }
  return WYRELOG_E_OK;
}

static void
principal_event_fact_expect_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  PrincipalEventFactExpect *expect = user_data;

  if (g_strcmp0 (relation, expect->relation) != 0 || ncols != 5)
    return;
  if (row[0] == expect->row[0] && row[1] == expect->row[1]
      && row[2] == expect->row[2] && row[3] == expect->row[3]
      && row[4] == expect->row[4])
    expect->matches++;
}

static void
delta_fact_expect_cb (const gchar *relation, const gint64 *row, guint ncols,
    WylDeltaKind kind, gpointer user_data)
{
  DeltaFactExpect *expect = user_data;

  if (g_strcmp0 (relation, expect->relation) != 0 || ncols != expect->ncols
      || kind != expect->kind)
    return;
  for (guint i = 0; i < ncols; i++) {
    if (row[i] != expect->row[i])
      return;
  }
  expect->matches++;
}

static void
delta_relation_count_cb (const gchar *relation, const gint64 *row,
    guint ncols, WylDeltaKind kind, gpointer user_data)
{
  guint *matches = user_data;

  (void) row;

  if (g_strcmp0 (relation, "session_fired") == 0 && ncols == 5
      && kind == WYL_DELTA_INSERT)
    (*matches)++;
}

static wyrelog_error_t
intern_principal_fired_row (WylHandle *handle, gint64 event_id,
    const gchar *subject_id, const gchar *from_state, const gchar *event,
    const gchar *to_state, gint64 row[5])
{
  row[0] = event_id;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, subject_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, from_state, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, event, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, to_state, &row[4]);
}

static wyrelog_error_t
intern_session_fired_row (WylHandle *handle, gint64 event_id,
    const gchar *session_id, const gchar *from_state, const gchar *event,
    const gchar *to_state, gint64 row[5])
{
  row[0] = event_id;
  wyrelog_error_t rc =
      wyl_handle_intern_engine_symbol (handle, session_id, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, from_state, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_handle_intern_engine_symbol (handle, event, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_intern_engine_symbol (handle, to_state, &row[4]);
}

static wyrelog_error_t
count_principal_event_fact (WylHandle *handle, const gchar *relation,
    const gint64 row[5], guint *out_matches)
{
  PrincipalEventFactExpect expect = { relation, row, 0 };

  wyrelog_error_t rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
          relation, principal_event_fact_expect_cb, &expect);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_matches = expect.matches;
  return WYRELOG_E_OK;
}

static gint
expect_session_transition (WylHandle *handle, const gchar *session_id,
    const gchar *from_state, const gchar *event, const gchar *to_state,
    gint base_code)
{
  SessionEventExpect event_expect = {
    .session_id = session_id,
    .event = event,
    .from_state = from_state,
    .to_state = to_state,
  };
  if (wyl_policy_store_foreach_session_event (wyl_handle_get_policy_store
        (handle), session_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return base_code;
  if (event_expect.matches != 1)
    return base_code + 1;

  gint64 row[5];
  if (intern_session_fired_row (handle, event_expect.event_id, session_id,
      from_state, event, to_state, row) != WYRELOG_E_OK)
    return base_code + 2;
  guint matches = 0;
  if (count_principal_event_fact (handle, "session_fired", row, &matches)
      != WYRELOG_E_OK)
    return base_code + 3;
  if (matches != 1)
    return base_code + 4;

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return base_code + 5;
  if (intern_session_fired_row (handle, event_expect.event_id, session_id,
      from_state, event, to_state, row) != WYRELOG_E_OK)
    return base_code + 6;
  matches = 0;
  if (count_principal_event_fact (handle, "session_fired", row, &matches)
      != WYRELOG_E_OK)
    return base_code + 7;
  return matches == 1 ? 0 : base_code + 8;
}

static WylSession *
login_with_username (const gchar *username)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return NULL;

  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, username);

  WylSession *session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK)
    return NULL;
  return session;
}

static gint
check_login_propagates_username (void)
{
  g_autoptr (WylSession) session = login_with_username ("alice");
  if (session == NULL)
    return 10;
  g_autofree gchar *got = wyl_session_dup_username (session);
  if (got == NULL)
    return 11;
  if (strcmp (got, "alice") != 0)
    return 12;
  return 0;
}

static gint
check_login_with_null_request (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_OK)
    return 21;
  if (session == NULL)
    return 22;
  /* No request -> no username carried into the session. */
  if (wyl_session_dup_username (session) != NULL)
    return 23;
  return 0;
}

static gint
check_login_with_unset_username (void)
{
  g_autoptr (WylSession) session = login_with_username (NULL);
  if (session == NULL)
    return 30;
  if (wyl_session_dup_username (session) != NULL)
    return 31;
  return 0;
}

static gint
check_login_binds_default_tenant (void)
{
  g_autoptr (WylSession) session = login_with_username ("tenant-user");
  if (session == NULL)
    return 34;
  g_autofree gchar *tenant = wyl_session_dup_tenant (session);
  if (g_strcmp0 (tenant, "__wr_default") != 0)
    return 35;
  return 0;
}

static gint
check_login_accepts_registry_ready_tenant (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 36;

  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "tenant-user");
  wyl_login_req_set_tenant (req, "unknown");

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK)
    return 37;
  if (session == NULL)
    return 38;
  g_autofree gchar *tenant = wyl_session_dup_tenant (session);
  if (g_strcmp0 (tenant, "unknown") != 0)
    return 52;
  return 0;
}

static gint
check_login_validates_tenant_before_skip_mfa (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 39;

  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "tenant-user");
  wyl_login_req_set_tenant (req, "bad tenant");
  wyl_login_req_set_skip_mfa (req, TRUE);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_INVALID)
    return 44;
  if (session != NULL)
    return 45;
  return 0;
}

/*
 * Session construction accepts syntactically valid tenant ids; the
 * daemon-owned tenant registry is responsible for deciding whether a
 * tenant is active on the wire. Invalid tenant syntax still fails closed
 * at the lower session boundary.
 */
static gint
check_login_rejects_invalid_tenant_syntax (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 46;

  g_autoptr (wyl_login_req_t) reject_req = wyl_login_req_new ();
  wyl_login_req_set_username (reject_req, "tenant-user");
  wyl_login_req_set_tenant (reject_req, "evil co");

  g_autoptr (WylSession) reject_session = NULL;
  if (wyl_session_login (handle, reject_req, &reject_session)
      != WYRELOG_E_INVALID)
    return 47;
  if (reject_session != NULL)
    return 48;

  g_autoptr (wyl_login_req_t) accept_req = wyl_login_req_new ();
  wyl_login_req_set_username (accept_req, "tenant-user");
  wyl_login_req_set_tenant (accept_req, WYL_TENANT_DEFAULT);

  g_autoptr (WylSession) accept_session = NULL;
  if (wyl_session_login (handle, accept_req, &accept_session) != WYRELOG_E_OK)
    return 49;
  if (accept_session == NULL)
    return 50;
  g_autofree gchar *bound_tenant = wyl_session_dup_tenant (accept_session);
  if (g_strcmp0 (bound_tenant, WYL_TENANT_DEFAULT) != 0)
    return 51;
  return 0;
}

static gint
check_request_buffer_independent_of_session (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;

  wyl_login_req_t *req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "bob");

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, req, &session) != WYRELOG_E_OK) {
    wyl_login_req_free (req);
    return 41;
  }

  /* Free the request before reading the session. The session's copy
   * of the username must survive. */
  wyl_login_req_free (req);

  g_autofree gchar *got = wyl_session_dup_username (session);
  if (got == NULL)
    return 42;
  if (strcmp (got, "bob") != 0)
    return 43;
  return 0;
}

static gint
check_dup_returns_distinct_buffers (void)
{
  g_autoptr (WylSession) session = login_with_username ("carol");
  if (session == NULL)
    return 50;
  g_autofree gchar *first = wyl_session_dup_username (session);
  g_autofree gchar *second = wyl_session_dup_username (session);
  if (first == NULL || second == NULL)
    return 51;
  if (first == second)
    return 52;
  if (strcmp (first, second) != 0)
    return 53;
  return 0;
}

static gint
check_dup_null_session (void)
{
  if (wyl_session_dup_username (NULL) != NULL)
    return 60;
  return 0;
}

static gint
check_login_requires_mfa_before_allow (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 70;

  if (store_active_scope (handle, "login-scope") != WYRELOG_E_OK)
    return 71;
  if (grant_direct (handle, "login-user", "site.login-permission",
      "login-scope") != WYRELOG_E_OK)
    return 72;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 76;
  if (session == NULL)
    return 77;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "login-user");
  wyl_decide_req_set_action (decide, "site.login-permission");
  wyl_decide_req_set_resource_id (decide, "login-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 78;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 79;
  return 0;
}

static gint
check_mfa_verify_authenticates_engine_principal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 80;

  if (store_active_scope (handle, "login-scope") != WYRELOG_E_OK)
    return 81;
  if (grant_direct (handle, "login-user", "site.login-permission",
      "login-scope") != WYRELOG_E_OK)
    return 82;
  if (wyl_handle_apply_permission_state_transition (handle, "login-user",
      "site.login-permission", "login-scope", "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 231;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 86;
  if (session == NULL)
    return 87;
  if (wyl_session_is_mfa_assured_private (session))
    return 233;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 88;
  if (!wyl_session_is_mfa_assured_private (session))
    return 234;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "login-user");
  wyl_decide_req_set_action (decide, "site.login-permission");
  wyl_decide_req_set_resource_id (decide, "login-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 89;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 90;
  return 0;
}

static gint
check_mfa_delta_callback_survives_state_reload (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 91;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "mfa-delta-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 92;

  gint64 row[5];
  if (intern_principal_fired_row (handle, 2, "mfa-delta-user",
      "mfa_required", "mfa_ok", "authenticated", row) != WYRELOG_E_OK)
    return 93;
  DeltaFactExpect expect = {
    .relation = "principal_fired",
    .row = row,
    .ncols = 5,
    .kind = WYL_DELTA_INSERT,
  };
  if (wyl_handle_engine_set_delta_callback (handle, delta_fact_expect_cb,
      &expect) != WYRELOG_E_OK)
    return 94;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 95;
  return expect.matches == 1 ? 0 : 96;
}

static gint
check_mfa_verify_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 100;

  if (wyl_session_mfa_verify (NULL, NULL) != WYRELOG_E_INVALID)
    return 101;
  if (wyl_session_mfa_verify (handle, NULL) != WYRELOG_E_INVALID)
    return 102;

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, NULL, &session) != WYRELOG_E_OK)
    return 103;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_INVALID)
    return 104;
  return 0;
}

static gint
check_login_persists_mfa_required_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 110;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "persist-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 111;

  PrincipalStateExpect expect = {
    .subject_id = "persist-user",
    .state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 112;
  if (expect.matches != 1)
    return 113;
  return 0;
}

static gint
check_mfa_verify_persists_authenticated_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 120;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "persist-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 121;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 122;

  PrincipalStateExpect expect = {
    .subject_id = "persist-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 123;
  if (expect.matches != 1)
    return 124;
  return 0;
}

static gint
check_login_persists_active_session_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 130;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 131;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 132;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "active",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 133;
  if (expect.matches != 1)
    return 134;
  return 0;
}

static gint
check_login_inserts_wirelog_session_fired (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 136;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-fired-login-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 137;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 138;
  return expect_session_transition (handle, session_id, "idle", "request",
             "active", 139);
}

static gint
check_login_delta_callback_survives_state_reload (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 141;

  gint64 row[5];
  if (intern_principal_fired_row (handle, 1, "login-delta-user",
      "unverified", "login_ok", "mfa_required", row) != WYRELOG_E_OK)
    return 142;
  DeltaFactExpect principal_expect = {
    .relation = "principal_fired",
    .row = row,
    .ncols = 5,
    .kind = WYL_DELTA_INSERT,
  };
  if (wyl_handle_engine_set_delta_callback (handle, delta_fact_expect_cb,
      &principal_expect) != WYRELOG_E_OK)
    return 143;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "login-delta-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 144;
  if (principal_expect.matches != 1)
    return 145;

  guint session_fired = 0;
  if (wyl_handle_engine_set_delta_callback (handle, delta_relation_count_cb,
      &session_fired) != WYRELOG_E_OK)
    return 146;
  g_autoptr (wyl_login_req_t) second_login = wyl_login_req_new ();
  wyl_login_req_set_username (second_login, "login-delta-session-user");
  g_autoptr (WylSession) second_session = NULL;
  if (wyl_session_login (handle, second_login, &second_session) != WYRELOG_E_OK)
    return 147;
  return session_fired == 1 ? 0 : 148;
}

static gint
check_login_session_id_is_active_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 140;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-id-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 142;
  if (wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
    return 143;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 144;
  if (grant_direct (handle, "session-id-user", "site.session-id-permission",
      session_id) != WYRELOG_E_OK)
    return 145;
  if (wyl_handle_apply_permission_state_transition (handle, "session-id-user",
      "site.session-id-permission", session_id, "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 233;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "session-id-user");
  wyl_decide_req_set_action (decide, "site.session-id-permission");
  wyl_decide_req_set_resource_id (decide, session_id);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 147;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 148;
  return 0;
}

static wyrelog_error_t
allow_mfa_validator (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  const gchar *expected_proof = user_data;

  (void) handle;

  g_autofree gchar *username = wyl_session_dup_username (session);
  if (g_strcmp0 (username, "mfa-proof-user") != 0)
    return WYRELOG_E_INTERNAL;
  if (g_strcmp0 (proof, expected_proof) != 0)
    return WYRELOG_E_POLICY;
  return WYRELOG_E_OK;
}

static wyrelog_error_t
reject_mfa_validator (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  guint *calls = user_data;

  (void) handle;
  (void) session;
  (void) proof;

  (*calls)++;
  return WYRELOG_E_POLICY;
}

static gint
check_mfa_verify_with_proof_requires_validator (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 100;

  if (store_active_scope (handle, "mfa-proof-scope") != WYRELOG_E_OK)
    return 101;
  if (grant_direct (handle, "mfa-proof-user", "site.mfa-proof-permission",
      "mfa-proof-scope") != WYRELOG_E_OK)
    return 102;
  if (wyl_handle_apply_permission_state_transition (handle, "mfa-proof-user",
      "site.mfa-proof-permission", "mfa-proof-scope", "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 234;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "mfa-proof-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 103;

  if (wyl_session_mfa_verify_with_proof (NULL, session, "123456",
      allow_mfa_validator, "123456") != WYRELOG_E_INVALID)
    return 104;
  if (wyl_session_mfa_verify_with_proof (handle, NULL, "123456",
      allow_mfa_validator, "123456") != WYRELOG_E_INVALID)
    return 105;
  if (wyl_session_mfa_verify_with_proof (handle, session, NULL,
      allow_mfa_validator, "123456") != WYRELOG_E_INVALID)
    return 106;
  if (wyl_session_mfa_verify_with_proof (handle, session, "",
      allow_mfa_validator, "123456") != WYRELOG_E_INVALID)
    return 107;
  if (wyl_session_mfa_verify_with_proof (handle, session, "123456",
      NULL, "123456") != WYRELOG_E_INVALID)
    return 108;

  guint reject_calls = 0;
  if (wyl_session_mfa_verify_with_proof (handle, session, "123456",
      reject_mfa_validator, &reject_calls) != WYRELOG_E_POLICY)
    return 109;
  if (reject_calls != 1)
    return 110;

  PrincipalStateExpect required = {
    .subject_id = "mfa-proof-user",
    .state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &required) != WYRELOG_E_OK)
    return 111;
  if (required.matches != 1)
    return 112;

  PrincipalStateExpect authenticated = {
    .subject_id = "mfa-proof-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &authenticated)
      != WYRELOG_E_OK)
    return 113;
  if (authenticated.matches != 0)
    return 114;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "mfa-proof-user");
  wyl_decide_req_set_action (decide, "site.mfa-proof-permission");
  wyl_decide_req_set_resource_id (decide, "mfa-proof-scope");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 115;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 116;

  if (wyl_session_mfa_verify_with_proof (handle, session, "123456",
      allow_mfa_validator, "123456") != WYRELOG_E_OK)
    return 117;
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 118;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 119;

  return 0;
}

static gint
check_login_skip_mfa_rejected_by_default (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 149;

  if (wyl_handle_get_login_skip_mfa_allowed (handle))
    return 150;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "skip-mfa-denied-user");
  wyl_login_req_set_skip_mfa (login, TRUE);

  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_POLICY)
    return 151;
  if (session != NULL)
    return 152;

  PrincipalStateExpect expect = {
    .subject_id = "skip-mfa-denied-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 153;
  return expect.matches == 0 ? 0 : 154;
}

static gint
check_login_skip_mfa_authenticates_principal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;

  if (store_active_scope (handle, "skip-mfa-scope") != WYRELOG_E_OK)
    return 151;
  if (grant_direct (handle, "skip-mfa-user", "site.skip-mfa-permission",
      "skip-mfa-scope") != WYRELOG_E_OK)
    return 152;
  if (wyl_handle_apply_permission_state_transition (handle, "skip-mfa-user",
      "site.skip-mfa-permission", "skip-mfa-scope", "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 232;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "skip-mfa-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 155;
  if (wyl_session_is_mfa_assured_private (session))
    return 235;

  PrincipalStateExpect expect = {
    .subject_id = "skip-mfa-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 156;
  if (expect.matches != 1)
    return 157;
  PrincipalEventExpect event_expect = {
    .subject_id = "skip-mfa-user",
    .event = "login_skip_mfa",
    .from_state = "unverified",
    .to_state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_event (wyl_handle_get_policy_store
        (handle), principal_event_expect_cb, &event_expect) != WYRELOG_E_OK)
    return 160;
  if (event_expect.matches != 1)
    return 161;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "skip-mfa-user");
  wyl_decide_req_set_action (decide, "site.skip-mfa-permission");
  wyl_decide_req_set_resource_id (decide, "skip-mfa-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 158;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 159;
  return 0;
}

static wyrelog_error_t
login_skip_mfa_user (WylHandle *handle, const gchar *username,
    WylSession **out_session)
{
  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, username);
  wyl_login_req_set_skip_mfa (login, TRUE);
  return wyl_session_login (handle, login, out_session);
}

static gint
check_login_skip_mfa_uses_deployment_mode (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 160;

  if (wyl_policy_store_set_deployment_mode (wyl_handle_get_policy_store
        (handle), "development") != WYRELOG_E_OK)
    return 161;
  if (!wyl_handle_get_login_skip_mfa_allowed (handle))
    return 162;

  g_autoptr (WylSession) development_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-development-user",
      &development_session) != WYRELOG_E_OK)
    return 163;
  if (development_session == NULL)
    return 164;

  if (wyl_policy_store_set_deployment_mode (wyl_handle_get_policy_store
        (handle), "demo") != WYRELOG_E_OK)
    return 165;

  g_autoptr (WylSession) demo_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-demo-user", &demo_session)
      != WYRELOG_E_OK)
    return 166;
  if (demo_session == NULL)
    return 167;

  wyl_handle_set_login_skip_mfa_allowed (handle, FALSE);
  if (!wyl_handle_get_login_skip_mfa_allowed (handle))
    return 168;

  if (wyl_policy_store_set_deployment_mode (wyl_handle_get_policy_store
        (handle), "production") != WYRELOG_E_OK)
    return 169;
  if (wyl_handle_get_login_skip_mfa_allowed (handle))
    return 170;

  g_autoptr (WylSession) production_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-production-user",
      &production_session) != WYRELOG_E_POLICY)
    return 171;
  if (production_session != NULL)
    return 172;
  return 0;
}

static gint
check_login_skip_mfa_uses_policy_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 173;

  if (grant_direct (handle, "skip-mfa-policy-user", "wr.login.skip_mfa",
      "login") != WYRELOG_E_OK)
    return 174;
  if (wyl_policy_store_set_permission_state (wyl_handle_get_policy_store
        (handle), "skip-mfa-policy-user", "wr.login.skip_mfa", "login",
      "armed") != WYRELOG_E_OK)
    return 200;

  g_autoptr (WylSession) policy_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-policy-user", &policy_session)
      != WYRELOG_E_OK)
    return 175;
  if (policy_session == NULL)
    return 176;

  PrincipalStateExpect expect = {
    .subject_id = "skip-mfa-policy-user",
    .state = "authenticated",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 177;
  if (expect.matches != 1)
    return 178;

  g_autoptr (WylSession) other_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-other-user", &other_session)
      != WYRELOG_E_POLICY)
    return 179;
  if (other_session != NULL)
    return 180;

  if (grant_direct (handle, "skip-mfa-wrong-scope-user", "wr.login.skip_mfa",
      "not-login") != WYRELOG_E_OK)
    return 181;
  g_autoptr (WylSession) wrong_scope_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-wrong-scope-user",
      &wrong_scope_session) != WYRELOG_E_POLICY)
    return 182;
  if (wrong_scope_session != NULL)
    return 183;

  if (grant_role_permission (handle, "skip-mfa-role-user",
      "site.skip-mfa-role", "wr.login.skip_mfa", "login") != WYRELOG_E_OK)
    return 184;
  if (wyl_policy_store_set_permission_state (wyl_handle_get_policy_store
        (handle), "skip-mfa-role-user", "wr.login.skip_mfa", "login",
      "armed") != WYRELOG_E_OK)
    return 201;
  g_autoptr (WylSession) role_session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-role-user", &role_session)
      != WYRELOG_E_OK)
    return 185;
  if (role_session == NULL)
    return 186;

  return 0;
}

static gint
check_login_skip_mfa_does_not_use_state_without_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 187;

  gint64 event_id = -1;
  if (wyl_handle_apply_permission_state_transition (handle,
      "skip-mfa-state-only-user", "wr.login.skip_mfa", "login", "grant",
      NULL, &event_id) != WYRELOG_E_OK)
    return 188;
  if (event_id <= 0)
    return 189;

  g_autoptr (WylSession) session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-state-only-user", &session)
      != WYRELOG_E_POLICY)
    return 190;
  return session == NULL ? 0 : 191;
}

static gint
check_login_skip_mfa_policy_permission_observes_state_lifecycle (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 192;

  if (grant_direct (handle, "skip-mfa-dormant-user", "wr.login.skip_mfa",
      "login") != WYRELOG_E_OK)
    return 193;

  gint64 event_id = -1;
  if (wyl_handle_apply_permission_state_transition (handle,
      "skip-mfa-dormant-user", "wr.login.skip_mfa", "login", "grant",
      NULL, &event_id) != WYRELOG_E_OK)
    return 194;
  if (event_id <= 0)
    return 195;
  event_id = -1;
  if (wyl_handle_apply_permission_state_transition (handle,
      "skip-mfa-dormant-user", "wr.login.skip_mfa", "login", "revoke",
      NULL, &event_id) != WYRELOG_E_OK)
    return 196;
  if (event_id <= 0)
    return 197;

  g_autoptr (WylSession) session = NULL;
  if (login_skip_mfa_user (handle, "skip-mfa-dormant-user", &session)
      != WYRELOG_E_POLICY)
    return 198;
  return session == NULL ? 0 : 199;
}

static gint
check_login_skip_mfa_inserts_wirelog_principal_fired (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 162;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "skip-mfa-fired-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 163;

  gint64 row[5];
  if (intern_principal_fired_row (handle, 1, "skip-mfa-fired-user",
      "unverified", "login_skip_mfa", "authenticated", row)
      != WYRELOG_E_OK)
    return 164;
  guint matches = 0;
  if (count_principal_event_fact (handle, "principal_fired", row, &matches)
      != WYRELOG_E_OK)
    return 165;
  if (matches != 1)
    return 166;

  if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
    return 167;
  if (intern_principal_fired_row (handle, 1, "skip-mfa-fired-user",
      "unverified", "login_skip_mfa", "authenticated", row)
      != WYRELOG_E_OK)
    return 168;
  matches = 0;
  if (count_principal_event_fact (handle, "principal_fired", row, &matches)
      != WYRELOG_E_OK)
    return 169;
  return matches == 1 ? 0 : 170;
}

static gint
check_login_skip_mfa_does_not_bypass_guarded_permission (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 166;

  if (store_active_scope (handle, "skip-mfa-guarded-scope") != WYRELOG_E_OK)
    return 167;
  if (grant_role_permission (handle, "skip-mfa-guarded-user",
      "site.skip-mfa-guarded-role", "wr.audit.read",
      "skip-mfa-guarded-scope") != WYRELOG_E_OK)
    return 168;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "skip-mfa-guarded-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 169;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "skip-mfa-guarded-user");
  wyl_decide_req_set_action (decide, "wr.audit.read");
  wyl_decide_req_set_resource_id (decide, "skip-mfa-guarded-scope");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 170;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 171;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 172;

  wyl_decide_req_set_guard_context (decide, 123, "public", 69);
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 173;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 174;

  return 0;
}

static gint
check_session_logout_preserves_locked_and_revoked_principals (void)
{
  const gchar *subjects[] = { "logout-locked-user", "logout-revoked-user",
                              "logout-unverified-user" };
  const wyl_principal_event_t prepare_events[] = {
    WYL_PRINCIPAL_EVENT_LOCK, WYL_PRINCIPAL_EVENT_REVOKE,
  };
  const gchar *states[] = { "locked", "revoked", "unverified" };

  for (guint i = 0; i < G_N_ELEMENTS (subjects); i++) {
    g_autoptr (WylHandle) handle = NULL;
    if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
      return 170 + (gint) i * 10;
    g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
    wyl_login_req_set_username (login, subjects[i]);
    g_autoptr (WylSession) session = NULL;
    if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
      return 171 + (gint) i * 10;
    if (i == 1 && wyl_session_mfa_verify (handle, session) != WYRELOG_E_OK)
      return 172 + (gint) i * 10;

    if (i == 2) {
      if (wyl_policy_store_set_principal_state
            (wyl_handle_get_policy_store (handle), subjects[i], "unverified")
          != WYRELOG_E_OK)
        return 173 + (gint) i * 10;
    } else {
      wyl_principal_state_t to = WYL_PRINCIPAL_STATE_LAST_;
      gboolean transitioned = FALSE;
      gint64 event_id = -1;
      if (wyl_policy_store_apply_principal_transition
            (wyl_handle_get_policy_store (handle), subjects[i],
          prepare_events[i], 0, 0, NULL, &to, &transitioned, &event_id)
          != WYRELOG_E_OK
          || !transitioned)
        return 173 + (gint) i * 10;
    }

    wyl_session_id_t sid = wyl_session_get_id (session);
    if (sid == 0 || wyl_session_logout (handle, sid) != WYRELOG_E_OK)
      return 174 + (gint) i * 10;
    PrincipalStateExpect state = {
      .subject_id = subjects[i],
      .state = states[i],
    };
    if (wyl_policy_store_foreach_principal_state
          (wyl_handle_get_policy_store (handle), principal_state_expect_cb,
        &state) != WYRELOG_E_OK || state.matches != 1)
      return 175 + (gint) i * 10;
    PrincipalEventExpect logout = {
      .subject_id = subjects[i],
      .event = "logout",
      .from_state = i == 2 ? "mfa_required" : "authenticated",
      .to_state = "unverified",
    };
    if (wyl_policy_store_foreach_principal_event
          (wyl_handle_get_policy_store (handle), principal_event_expect_cb,
        &logout) != WYRELOG_E_OK || logout.matches != 0)
      return 176 + (gint) i * 10;
  }
  return 0;
}

static gint
check_session_logout_logs_out_principal (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 150;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "logout-principal-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 151;
  wyl_session_id_t sid = wyl_session_get_id (session);
  if (sid == 0)
    return 152;

  /* A rejected publication must leave both authorities untouched so the
   * caller can retry the same logout deterministically. */
  wyl_handle_set_committed_publication_fault_once_for_test (handle,
      WYL_COMMITTED_PUBLICATION_FAULT_VALIDATE);
  if (wyl_session_logout (handle, sid) != WYRELOG_E_IO)
    return 153;
  PrincipalStateExpect pending = {
    .subject_id = "logout-principal-user",
    .state = "mfa_required",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &pending) != WYRELOG_E_OK
      || pending.matches != 1
      || wyl_session_state_load_private (session) != WYL_SESSION_STATE_ACTIVE)
    return 154;
  LogoutDeltaCounts delta_counts = { 0 };
  if (wyl_handle_engine_set_delta_callback (handle, logout_delta_counts_cb,
      &delta_counts) != WYRELOG_E_OK)
    return 155;
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 156;

  PrincipalStateExpect state = {
    .subject_id = "logout-principal-user",
    .state = "unverified",
  };
  if (wyl_policy_store_foreach_principal_state (wyl_handle_get_policy_store
        (handle), principal_state_expect_cb, &state) != WYRELOG_E_OK
      || state.matches != 1)
    return 158;

  PrincipalEventExpect event = {
    .subject_id = "logout-principal-user",
    .event = "logout",
    .from_state = "mfa_required",
    .to_state = "unverified",
  };
  if (wyl_policy_store_foreach_principal_event (wyl_handle_get_policy_store
        (handle), principal_event_expect_cb, &event) != WYRELOG_E_OK
      || event.matches != 1)
    return 157;
  if (wyl_handle_engine_set_delta_callback (handle, NULL, NULL)
      != WYRELOG_E_OK
      || delta_counts.principal_fired != 1
      || delta_counts.session_fired != 1)
    return 158;

  /* The durable event rows are independently keyed; the callback above
   * proves both publication deltas were emitted without comparing IDs from
   * separate tables. */
  if (event.event_id <= 0)
    return 157;

  /* The registry tombstone makes the public logout retry idempotent and must
   * not append a second principal transition. */
  if (wyl_session_logout (handle, sid) != WYRELOG_E_OK)
    return 159;
  event.matches = 0;
  if (wyl_policy_store_foreach_principal_event (wyl_handle_get_policy_store
        (handle), principal_event_expect_cb, &event) != WYRELOG_E_OK
      || event.matches != 1)
    return 160;

  /* The authenticated edge must be published as well, not just the login
   * session's initial mfa_required edge. */
  g_autoptr (wyl_login_req_t) authenticated_login = wyl_login_req_new ();
  wyl_login_req_set_username (authenticated_login, "logout-auth-user");
  g_autoptr (WylSession) authenticated_session = NULL;
  if (wyl_session_login (handle, authenticated_login,
      &authenticated_session) != WYRELOG_E_OK
      || wyl_session_mfa_verify (handle, authenticated_session)
      != WYRELOG_E_OK)
    return 161;
  wyl_session_id_t authenticated_sid = wyl_session_get_id
        (authenticated_session);
  if (authenticated_sid == 0
      || wyl_session_close (handle, authenticated_session) != WYRELOG_E_OK)
    return 162;
  PrincipalEventExpect authenticated_event = {
    .subject_id = "logout-auth-user",
    .event = "logout",
    .from_state = "authenticated",
    .to_state = "unverified",
  };
  if (wyl_policy_store_foreach_principal_event (wyl_handle_get_policy_store
        (handle), principal_event_expect_cb, &authenticated_event)
      != WYRELOG_E_OK
      || authenticated_event.matches != 1)
    return 163;
  return 0;
}

static gint
check_session_close_persists_closed_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 160;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "close-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 161;
  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 162;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 163;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 164;
  if (expect.matches != 1)
    return 165;
  return 0;
}

static gint
check_session_close_inserts_wirelog_session_fired (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 166;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-fired-close-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 167;
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 168;
  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 169;
  return expect_session_transition (handle, session_id, "active", "logout",
             "closed", 175);
}

static gint
check_session_close_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 170;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "close-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 172;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 173;
  if (grant_direct (handle, "close-user", "site.close-permission",
      session_id) != WYRELOG_E_OK)
    return 174;
  if (wyl_handle_apply_permission_state_transition (handle, "close-user",
      "site.close-permission", session_id, "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 241;

  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 176;

  g_autoptr (wyl_decide_req_t) after = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (after, "close-user");
  wyl_decide_req_set_action (after, "site.close-permission");
  wyl_decide_req_set_resource_id (after, session_id);
  g_autoptr (wyl_decide_resp_t) after_resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, after, after_resp) != WYRELOG_E_OK)
    return 177;
  if (wyl_decide_resp_get_decision (after_resp) != WYL_DECISION_DENY)
    return 178;
  /* Logout now revokes the subject-global principal in the same durable
   * publication, so authentication precedence is the visible deny reason
   * after the session has been closed. */
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (after_resp),
      "not_authenticated") != 0)
    return 179;
  return 0;
}

static gint
check_session_close_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 190;

  if (wyl_session_close (NULL, NULL) != WYRELOG_E_INVALID)
    return 191;
  if (wyl_session_close (handle, NULL) != WYRELOG_E_INVALID)
    return 192;
  return 0;
}

static gint
check_session_elevate_persists_elevated_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 200;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevate-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 201;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 202;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 203;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "elevated",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 204;
  if (expect.matches != 1)
    return 205;
  return 0;
}

static gint
check_session_transitions_insert_wirelog_session_fired (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 206;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-fired-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 207;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 208;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 209;
  gint rc = expect_session_transition (handle, session_id, "active",
          "elevate_grant", "elevated", 210);
  if (rc != 0)
    return rc;
  if (wyl_session_drop_elevation (handle, session) != WYRELOG_E_OK)
    return 219;
  rc = expect_session_transition (handle, session_id, "elevated",
          "elevate_drop", "active", 220);
  if (rc != 0)
    return rc;
  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 229;
  return expect_session_transition (handle, session_id, "active",
             "idle_timeout", "idle", 230);
}

static gint
check_session_drop_elevation_persists_active_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 210;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "drop-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 211;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 212;
  if (wyl_session_drop_elevation (handle, session) != WYRELOG_E_OK)
    return 213;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 214;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "active",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 215;
  if (expect.matches != 1)
    return 216;
  return 0;
}

static gint
check_elevated_session_remains_active_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 220;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevate-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 222;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 223;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 224;
  if (grant_direct (handle, "elevate-user", "site.elevate-permission",
      session_id) != WYRELOG_E_OK)
    return 225;
  if (wyl_handle_apply_permission_state_transition (handle, "elevate-user",
      "site.elevate-permission", session_id, "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 242;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevate-user");
  wyl_decide_req_set_action (decide, "site.elevate-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 227;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 228;
  return 0;
}

static gint
check_elevated_session_close_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 230;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevated-close-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 232;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 233;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 234;
  if (grant_direct (handle, "elevated-close-user",
      "site.elevated-close-permission", session_id) != WYRELOG_E_OK)
    return 235;
  if (wyl_handle_apply_permission_state_transition (handle,
      "elevated-close-user", "site.elevated-close-permission", session_id,
      "grant", NULL, NULL) != WYRELOG_E_OK)
    return 242;

  if (wyl_session_close (handle, session) != WYRELOG_E_OK)
    return 237;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevated-close-user");
  wyl_decide_req_set_action (decide, "site.elevated-close-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 238;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 239;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
      "not_authenticated") != 0)
    return 240;
  return 0;
}

static gint
check_session_idle_timeout_persists_idle_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 260;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "idle-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 261;
  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 262;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 263;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "idle",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 264;
  if (expect.matches != 1)
    return 265;
  return 0;
}

static gint
check_idle_session_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 270;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "idle-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 272;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 273;
  if (grant_direct (handle, "idle-user", "site.idle-permission",
      session_id) != WYRELOG_E_OK)
    return 274;
  if (wyl_handle_apply_permission_state_transition (handle, "idle-user",
      "site.idle-permission", session_id, "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 286;

  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 276;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "idle-user");
  wyl_decide_req_set_action (decide, "site.idle-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 277;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 278;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
      "session_inactive") != 0)
    return 279;
  return 0;
}

static gint
check_elevated_session_idle_timeout_deactivates_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 280;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevated-idle-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 282;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 283;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 284;
  if (grant_direct (handle, "elevated-idle-user",
      "site.elevated-idle-permission", session_id) != WYRELOG_E_OK)
    return 285;
  if (wyl_handle_apply_permission_state_transition (handle,
      "elevated-idle-user", "site.elevated-idle-permission", session_id,
      "grant", NULL, NULL) != WYRELOG_E_OK)
    return 286;

  if (wyl_session_idle_timeout (handle, session) != WYRELOG_E_OK)
    return 287;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "elevated-idle-user");
  wyl_decide_req_set_action (decide, "site.elevated-idle-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 288;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 289;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
      "session_inactive") != 0)
    return 290;
  return 0;
}

static gint
check_session_expire_persists_expiring_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 300;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "expiry-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 301;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 302;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 303;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "expiring",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 304;
  if (expect.matches != 1)
    return 305;
  return 0;
}

static gint
check_expiring_session_deactivates_decision_scope (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 310;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "expiry-user");
  wyl_login_req_set_skip_mfa (login, TRUE);
  wyl_handle_set_login_skip_mfa_allowed (handle, TRUE);
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 312;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 313;
  if (grant_direct (handle, "expiry-user", "site.expiry-permission",
      session_id) != WYRELOG_E_OK)
    return 314;
  if (wyl_handle_apply_permission_state_transition (handle, "expiry-user",
      "site.expiry-permission", session_id, "grant", NULL, NULL)
      != WYRELOG_E_OK)
    return 320;

  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 316;

  g_autoptr (wyl_decide_req_t) decide = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (decide, "expiry-user");
  wyl_decide_req_set_action (decide, "site.expiry-permission");
  wyl_decide_req_set_resource_id (decide, session_id);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, decide, resp) != WYRELOG_E_OK)
    return 317;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 318;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
      "session_inactive") != 0)
    return 319;
  return 0;
}

static gint
check_expiring_session_expire_persists_closed_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 320;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "expiry-close-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 321;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 322;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 323;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 324;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "closed",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 325;
  if (expect.matches != 1)
    return 326;
  return 0;
}

static gint
check_session_expiry_inserts_wirelog_session_fired (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 327;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "session-fired-expiry-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 328;
  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 329;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 337;
  gint rc = expect_session_transition (handle, session_id, "active",
          "expiry", "expiring", 338);
  if (rc != 0)
    return rc;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 347;
  return expect_session_transition (handle, session_id, "expiring",
             "expiry", "closed", 348);
}

static gint
check_elevated_session_expire_persists_expiring_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 330;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "elevated-expiry-state-user");
  g_autoptr (WylSession) session = NULL;
  if (wyl_session_login (handle, login, &session) != WYRELOG_E_OK)
    return 331;
  if (wyl_session_elevate (handle, session) != WYRELOG_E_OK)
    return 332;
  if (wyl_session_expire (handle, session) != WYRELOG_E_OK)
    return 333;

  g_autofree gchar *session_id = wyl_session_dup_id_string (session);
  if (session_id == NULL)
    return 334;
  SessionStateExpect expect = {
    .session_id = session_id,
    .state = "expiring",
  };
  if (wyl_policy_store_foreach_session_state (wyl_handle_get_policy_store
        (handle), session_state_expect_cb, &expect) != WYRELOG_E_OK)
    return 335;
  if (expect.matches != 1)
    return 336;
  return 0;
}

static gint
check_session_elevation_rejects_invalid_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 250;

  if (wyl_session_elevate (NULL, NULL) != WYRELOG_E_INVALID)
    return 251;
  if (wyl_session_elevate (handle, NULL) != WYRELOG_E_INVALID)
    return 252;
  if (wyl_session_drop_elevation (NULL, NULL) != WYRELOG_E_INVALID)
    return 253;
  if (wyl_session_drop_elevation (handle, NULL) != WYRELOG_E_INVALID)
    return 254;
  if (wyl_session_idle_timeout (NULL, NULL) != WYRELOG_E_INVALID)
    return 255;
  if (wyl_session_idle_timeout (handle, NULL) != WYRELOG_E_INVALID)
    return 256;
  if (wyl_session_expire (NULL, NULL) != WYRELOG_E_INVALID)
    return 257;
  if (wyl_session_expire (handle, NULL) != WYRELOG_E_INVALID)
    return 258;
  return 0;
}

static gint
check_poisoned_engine_rejects_session_mutations (void)
{
  g_autoptr (WylHandle) live_handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &live_handle) != WYRELOG_E_OK)
    return 760;
  g_autoptr (WylSession) live_session = NULL;
  if (wyl_session_login (live_handle, NULL, &live_session) != WYRELOG_E_OK)
    return 761;
  wyl_handle_poison_engine_pair (live_handle);
  if (wyl_session_close (live_handle, live_session) != WYRELOG_E_INVALID)
    return 762;

  g_autoptr (WylHandle) login_handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &login_handle) != WYRELOG_E_OK)
    return 763;
  wyl_handle_poison_engine_pair (login_handle);
  g_autoptr (wyl_login_req_t) req = wyl_login_req_new ();
  wyl_login_req_set_username (req, "poison-login-user");
  WylSession *session = NULL;
  if (wyl_session_login (login_handle, req, &session) != WYRELOG_E_INVALID
      || session != NULL)
    return 764;
  return 0;
}

/*
 * The session-username test surface has been split across two binaries
 * compiled from this single translation unit:
 *
 *   - WYL_TEST_VARIANT_LIFECYCLE undefined: login + MFA flows (username
 *     propagation, tenant binding, request buffers, MFA verify, skip-mfa
 *     policy paths, login decision-scope wiring).
 *
 *   - WYL_TEST_VARIANT_LIFECYCLE defined: session lifecycle transitions
 *     (close, elevate / drop-elevation, idle timeout, expire) and their
 *     decision-scope and wirelog event side-effects.
 *
 * Splitting was driven by Meson's default per-test 30s timeout: under CI
 * parallel scheduling the merged test crossed the wall-clock ceiling on
 * Windows (30.10s SIGTERM, 22.77s on prior main). Fixed-count Windows
 * evidence for issue #881 measured a 24.844s maximum for this variant
 * under two-worker contention, so its finite 60s timeout preserves at
 * least 1.5x measured headroom. Both variants continue to run in
 * parallel. Variant-irrelevant static helpers stay defined in this file;
 * the build silences the resulting -Wunused-function warnings.
 */
#ifndef WYL_TEST_VARIANT_LIFECYCLE
/*
 * Issue #752: a login that observes an already-authenticated principal
 * attaches to it - idempotent success, zero durable events, explicitly
 * non-authoritative.  Two properties have to hold together for that session,
 * and neither implies the other:
 *
 *   - it is BOUND to the epoch the login observed, so a token minted for it
 *     is checkable by the supersession gate instead of being dead on
 *     arrival with epoch 0;
 *   - it is NOT mfa_assured, and the proof-free wyl_session_mfa_verify does
 *     not make it so.  That entry point reports the idempotent success the
 *     ratified precedence already granted; it cannot hand an attachment more
 *     authority than the session that actually won the epoch, which does not
 *     carry the bit either (see check_login_skip_mfa_authenticates_principal).
 */
/* Accepts any proof for any subject, so the assertion below is about the
 * boundary's own behaviour and cannot pass merely because a validator
 * rejected the proof. */
static wyrelog_error_t
attach_probe_accepting_validator (WylHandle *handle, WylSession *session,
    const gchar *proof, gpointer user_data)
{
  (void) handle;
  (void) session;
  (void) proof;
  (void) user_data;
  return WYRELOG_E_OK;
}

static gint
check_attached_login_stays_unassured (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 202;

  g_autoptr (wyl_login_req_t) login = wyl_login_req_new ();
  wyl_login_req_set_username (login, "attach-probe-user");

  g_autoptr (WylSession) winner = NULL;
  if (wyl_session_login (handle, login, &winner) != WYRELOG_E_OK)
    return 203;
  if (wyl_session_mfa_verify (handle, winner) != WYRELOG_E_OK)
    return 204;
  if (!wyl_session_is_mfa_assured_private (winner))
    return 205;
  gint64 won_epoch = wyl_session_authn_epoch_load_private (winner);
  if (won_epoch <= 0)
    return 206;

  g_autoptr (WylSession) attached = NULL;
  if (wyl_session_login (handle, login, &attached) != WYRELOG_E_OK)
    return 207;
  if (wyl_session_authn_epoch_load_private (attached) != won_epoch)
    return 208;
  if (wyl_session_is_mfa_assured_private (attached))
    return 209;

  /* Idempotent success, and still no assurance. */
  if (wyl_session_mfa_verify (handle, attached) != WYRELOG_E_OK)
    return 210;
  if (wyl_session_is_mfa_assured_private (attached))
    return 211;
  if (wyl_session_authn_epoch_load_private (attached) != won_epoch)
    return 212;

  /* The idempotent report belongs to the proof-free boundary alone.  The
   * proof-bearing one documents that it applies the transition itself, which
   * an attachment cannot, so it must keep failing closed even with a proof
   * its validator accepts. */
  if (wyl_session_mfa_verify_with_proof (handle, attached, "000000",
      attach_probe_accepting_validator, NULL) != WYRELOG_E_POLICY)
    return 218;
  if (wyl_session_is_mfa_assured_private (attached))
    return 219;

  /* The idempotent report is guarded on the durable pair, not merely on the
   * attach marker.  Advance the watermark with a real authenticating
   * transition (there is no authenticated -> authenticated edge, so it takes
   * logout then a fresh skip-MFA login) and the attachment must go back to
   * failing closed: its expected epoch is now stale, so the verify falls
   * through to the MFA_OK CAS, which cannot move an already-authenticated
   * principal.  Without this the guard could be reduced to "is it attached?"
   * and nothing would notice. */
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
  wyl_principal_state_t to = WYL_PRINCIPAL_STATE_LAST_;
  gboolean moved = FALSE;
  gint64 event_id = -1;
  gint64 now_secs = g_get_real_time () / G_USEC_PER_SEC;
  if (wyl_policy_store_apply_principal_transition (store, "attach-probe-user",
      WYL_PRINCIPAL_EVENT_LOGOUT, 0, now_secs, NULL, &to, &moved,
      &event_id) != WYRELOG_E_OK || !moved)
    return 213;
  if (wyl_policy_store_apply_principal_transition (store, "attach-probe-user",
      WYL_PRINCIPAL_EVENT_LOGIN_SKIP_MFA, 0, now_secs, NULL, &to, &moved,
      &event_id) != WYRELOG_E_OK || !moved
      || to != WYL_PRINCIPAL_STATE_AUTHENTICATED)
    return 214;
  gint64 advanced_epoch = 0;
  gboolean advanced_found = FALSE;
  if (wyl_policy_store_get_principal_authn_epoch (store, "attach-probe-user",
      &advanced_epoch, &advanced_found) != WYRELOG_E_OK || !advanced_found
      || advanced_epoch <= won_epoch)
    return 215;
  if (wyl_session_mfa_verify (handle, attached) == WYRELOG_E_OK)
    return 216;
  if (wyl_session_is_mfa_assured_private (attached))
    return 217;
  return 0;
}

int
main (void)
{
  gint rc;

  if ((rc = check_login_propagates_username ()) != 0)
    return rc;
  if ((rc = check_login_with_null_request ()) != 0)
    return rc;
  if ((rc = check_login_with_unset_username ()) != 0)
    return rc;
  if ((rc = check_login_binds_default_tenant ()) != 0)
    return rc;
  if ((rc = check_login_accepts_registry_ready_tenant ()) != 0)
    return rc;
  if ((rc = check_login_validates_tenant_before_skip_mfa ()) != 0)
    return rc;
  if ((rc = check_login_rejects_invalid_tenant_syntax ()) != 0)
    return rc;
  if ((rc = check_request_buffer_independent_of_session ()) != 0)
    return rc;
  if ((rc = check_dup_returns_distinct_buffers ()) != 0)
    return rc;
  if ((rc = check_dup_null_session ()) != 0)
    return rc;
  if ((rc = check_login_requires_mfa_before_allow ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_authenticates_engine_principal ()) != 0)
    return rc;
  if ((rc = check_mfa_delta_callback_survives_state_reload ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_rejects_invalid_args ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_with_proof_requires_validator ()) != 0)
    return rc;
  if ((rc = check_login_persists_mfa_required_state ()) != 0)
    return rc;
  if ((rc = check_mfa_verify_persists_authenticated_state ()) != 0)
    return rc;
  if ((rc = check_login_persists_active_session_state ()) != 0)
    return rc;
  if ((rc = check_login_inserts_wirelog_session_fired ()) != 0)
    return rc;
  if ((rc = check_login_delta_callback_survives_state_reload ()) != 0)
    return rc;
  if ((rc = check_login_session_id_is_active_decision_scope ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_rejected_by_default ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_authenticates_principal ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_uses_deployment_mode ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_uses_policy_permission ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_does_not_use_state_without_permission ())
      != 0)
    return rc;
  if ((rc = check_login_skip_mfa_policy_permission_observes_state_lifecycle ())
      != 0)
    return rc;
  if ((rc = check_login_skip_mfa_inserts_wirelog_principal_fired ()) != 0)
    return rc;
  if ((rc = check_login_skip_mfa_does_not_bypass_guarded_permission ()) != 0)
    return rc;
  if ((rc = check_poisoned_engine_rejects_session_mutations ()) != 0)
    return rc;
  if ((rc = check_attached_login_stays_unassured ()) != 0)
    return rc;

  return 0;
}
#else /* WYL_TEST_VARIANT_LIFECYCLE */
typedef gint (*LifecycleCheckFunc) (void);

typedef struct
{
  const gchar *id;
  LifecycleCheckFunc func;
} LifecycleCheck;

typedef enum
{
  LIFECYCLE_GATE_NONE,
  LIFECYCLE_GATE_BEGIN,
  LIFECYCLE_GATE_END,
  LIFECYCLE_GATE_INVALID,
} LifecycleGatePhase;

typedef struct
{
  LifecycleGatePhase phase;
  guint ordinal;
} LifecycleGate;

#define LIFECYCLE_PROGRESS_ENV \
  "WYL_TEST_SESSION_USERNAME_LIFECYCLE_PROGRESS"
#define LIFECYCLE_GATE_ENV "WYL_TEST_SESSION_USERNAME_LIFECYCLE_GATE"
#define LIFECYCLE_PROGRESS_PREFIX "WYL_SESSION_USERNAME_LIFECYCLE"

static const LifecycleCheck lifecycle_checks[] = {
  { "close-persists-closed-state",
    check_session_close_persists_closed_state },
  { "logout-preserves-locked-and-revoked-principals",
    check_session_logout_preserves_locked_and_revoked_principals },
  { "logout-logs-out-principal", check_session_logout_logs_out_principal },
  { "close-inserts-session-fired",
    check_session_close_inserts_wirelog_session_fired },
  { "close-deactivates-decision-scope",
    check_session_close_deactivates_decision_scope },
  { "close-rejects-invalid-args", check_session_close_rejects_invalid_args },
  { "elevate-persists-elevated-state",
    check_session_elevate_persists_elevated_state },
  { "transitions-insert-session-fired",
    check_session_transitions_insert_wirelog_session_fired },
  { "drop-elevation-persists-active-state",
    check_session_drop_elevation_persists_active_state },
  { "elevated-remains-active-decision-scope",
    check_elevated_session_remains_active_decision_scope },
  { "elevated-close-deactivates-decision-scope",
    check_elevated_session_close_deactivates_decision_scope },
  { "idle-timeout-persists-idle-state",
    check_session_idle_timeout_persists_idle_state },
  { "idle-deactivates-decision-scope",
    check_idle_session_deactivates_decision_scope },
  { "elevated-idle-timeout-deactivates-scope",
    check_elevated_session_idle_timeout_deactivates_scope },
  { "expire-persists-expiring-state",
    check_session_expire_persists_expiring_state },
  { "expiring-deactivates-decision-scope",
    check_expiring_session_deactivates_decision_scope },
  { "expiring-expire-persists-closed-state",
    check_expiring_session_expire_persists_closed_state },
  { "expiry-inserts-session-fired",
    check_session_expiry_inserts_wirelog_session_fired },
  { "elevated-expire-persists-expiring-state",
    check_elevated_session_expire_persists_expiring_state },
  { "elevation-rejects-invalid-args",
    check_session_elevation_rejects_invalid_args },
};

G_STATIC_ASSERT (G_N_ELEMENTS (lifecycle_checks) == 20);

static LifecycleGate
lifecycle_gate_from_env (void)
{
  LifecycleGate gate = { LIFECYCLE_GATE_NONE, 0 };
  const gchar *value = g_getenv (LIFECYCLE_GATE_ENV);
  if (value == NULL)
    return gate;

  const gchar *ordinal_text = NULL;
  if (g_str_has_prefix (value, "begin:")) {
    gate.phase = LIFECYCLE_GATE_BEGIN;
    ordinal_text = value + strlen ("begin:");
  } else if (g_str_has_prefix (value, "end:")) {
    gate.phase = LIFECYCLE_GATE_END;
    ordinal_text = value + strlen ("end:");
  } else {
    gate.phase = LIFECYCLE_GATE_INVALID;
    return gate;
  }

  gchar *end = NULL;
  guint64 ordinal = g_ascii_strtoull (ordinal_text, &end, 10);
  if (ordinal_text[0] == '\0' || end == NULL || end[0] != '\0'
      || ordinal == 0 || ordinal > G_N_ELEMENTS (lifecycle_checks)) {
    gate.phase = LIFECYCLE_GATE_INVALID;
    return gate;
  }
  gate.ordinal = (guint) ordinal;
  return gate;
}

static gboolean
lifecycle_progress_begin (const LifecycleCheck *check, guint ordinal,
    gint64 elapsed_ms)
{
  return fprintf (stderr, LIFECYCLE_PROGRESS_PREFIX
             " BEGIN id=%s ordinal=%u elapsed_ms=%" G_GINT64_FORMAT "\n",
             check->id, ordinal, elapsed_ms) >= 0 && fflush (stderr) == 0;
}

static gboolean
lifecycle_progress_end (const LifecycleCheck *check, guint ordinal,
    gint64 elapsed_ms, gint64 duration_ms, gint rc)
{
  return fprintf (stderr, LIFECYCLE_PROGRESS_PREFIX
             " END id=%s ordinal=%u elapsed_ms=%" G_GINT64_FORMAT
             " duration_ms=%" G_GINT64_FORMAT " rc=%d\n",
             check->id, ordinal, elapsed_ms, duration_ms, rc) >= 0
         && fflush (stderr) == 0;
}

static gint
lifecycle_gate_wait (LifecycleGate gate, LifecycleGatePhase phase,
    guint ordinal)
{
  if (gate.phase != phase || gate.ordinal != ordinal)
    return 0;

  return fgetc (stdin) == EOF ? 121 : 0;
}

int
main (void)
{
  const gboolean progress =
      g_strcmp0 (g_getenv (LIFECYCLE_PROGRESS_ENV), "1") == 0;
  const LifecycleGate gate = lifecycle_gate_from_env ();
  if (gate.phase == LIFECYCLE_GATE_INVALID
      || (gate.phase != LIFECYCLE_GATE_NONE && !progress))
    return 122;

  const gint64 started_us = g_get_monotonic_time ();
  for (guint i = 0; i < G_N_ELEMENTS (lifecycle_checks); i++) {
    const LifecycleCheck *check = &lifecycle_checks[i];
    const guint ordinal = i + 1;
    const gint64 check_started_us = g_get_monotonic_time ();
    if (progress && !lifecycle_progress_begin (check, ordinal,
        (check_started_us - started_us) / 1000))
      return 123;

    gint rc = lifecycle_gate_wait (gate, LIFECYCLE_GATE_BEGIN, ordinal);
    if (rc != 0)
      return rc;

    rc = check->func ();
    const gint64 check_ended_us = g_get_monotonic_time ();
    if (progress && !lifecycle_progress_end (check, ordinal,
        (check_ended_us - started_us) / 1000,
        (check_ended_us - check_started_us) / 1000, rc))
      return 124;

    gint gate_rc = lifecycle_gate_wait (gate, LIFECYCLE_GATE_END, ordinal);
    if (gate_rc != 0)
      return gate_rc;
    if (rc != 0)
      return rc;
  }

  return 0;
}
#endif /* WYL_TEST_VARIANT_LIFECYCLE */
