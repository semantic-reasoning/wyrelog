/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
#include "wyrelog/wyl-decide-private.h"
#include "wyrelog/wyl-handle-private.h"

/*
 * wyl_decide returns a fail-closed DENY when no policy engine pair is wired.
 * When a handle-owned engine pair is present, it queries allow_bool/3.
 */

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
}

static wyrelog_error_t
insert_symbol_row1 (WylHandle *handle, const gchar *relation,
    const gchar *value)
{
  gint64 row[1];
  wyrelog_error_t rc = intern_symbol (handle, value, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 1);
}

static wyrelog_error_t
insert_symbol_row2 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b)
{
  gint64 row[2];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 2);
}

static wyrelog_error_t
insert_symbol_row3 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 3);
}

static wyrelog_error_t
insert_symbol_row4 (WylHandle *handle, const gchar *relation,
    const gchar *a, const gchar *b, const gchar *c, const gchar *d)
{
  gint64 row[4];
  wyrelog_error_t rc = intern_symbol (handle, a, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, b, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, c, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, d, &row[3]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_insert (handle, relation, row, 4);
}

static wyrelog_error_t
insert_allow_fixture_state (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource, gboolean armed)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.decide-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.decide-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "principal_state", subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row1 (handle, "session_active", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!armed)
    return WYRELOG_E_OK;
  return insert_symbol_row4 (handle, "perm_state", subject, action, resource,
      "armed");
}

static wyrelog_error_t
insert_allow_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  return insert_allow_fixture_state (handle, subject, action, resource, TRUE);
}

static wyrelog_error_t
insert_grant_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.decide-role",
      action);
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row3 (handle, "member_of", subject, "wr.decide-role",
      resource);
}

/*
 * Seeds everything allow_guard_base (templates/access/decision.dl) needs
 * for an ALLOW EXCEPT the store fact principal_state(subject,
 * "authenticated"). This mirrors a fully validated live service (svc:)
 * bearer: it holds a role grant, its session scope is active, and the
 * permission is armed, but no principal_state row was ever written for it
 * (that fact is emitted only for human sessions,
 * insert_policy_store_principal_state in wyl-handle.c). Wall 1 (#740) --
 * the missing principal_state fact -- is therefore the sole remaining
 * blocker on this subject.
 */
static wyrelog_error_t
insert_service_grant_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.decide-role", action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.decide-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row1 (handle, "session_active", "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row4 (handle, "perm_state", subject, action, resource,
      "armed");
}

/*
 * #762: like insert_service_grant_fixture but WITHOUT the durable
 * perm_state("armed") row and without principal_state -- exactly the fact
 * shape of a fully validated live service (svc:) bearer that holds an
 * approved data-plane grant at an active scope. The store rejects a
 * durable perm_state row for svc: subjects, so armed/3 rule-1 has nothing
 * to fire on and the decide denies not_armed. wyl_decide injects the
 * armed perm_state TRANSIENTLY when the service-bearer flag is set and the
 * action is an approved data-plane permission, which is what this fixture
 * exercises. principal_state is likewise supplied transiently (#740).
 */
static wyrelog_error_t
insert_service_grant_unarmed_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  wyrelog_error_t rc =
      insert_symbol_row2 (handle, "role_permission", "wr.decide-role", action);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row3 (handle, "member_of", subject, "wr.decide-role",
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = insert_symbol_row2 (handle, "session_state", resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  return insert_symbol_row1 (handle, "session_active", "active");
}

static wyrelog_error_t
seed_policy_store_decide_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource, const gchar *perm_state)
{
  wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);

  wyrelog_error_t rc = wyl_policy_store_upsert_permission (store, action,
      action, "basic");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_grant_direct_permission (store, subject, action,
      resource);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_principal_state (store, subject, "authenticated");
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = wyl_policy_store_set_session_state (store, resource, "active");
  if (rc != WYRELOG_E_OK)
    return rc;
  if (perm_state != NULL) {
    rc = wyl_policy_store_set_permission_state (store, subject, action,
        resource, perm_state);
    if (rc != WYRELOG_E_OK)
      return rc;
  }
  return wyl_handle_reload_engine_pair (handle);
}

static wyrelog_error_t
decide_policy_store_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource, wyl_decide_resp_t *resp)
{
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  return wyl_decide (handle, req, resp);
}

typedef struct
{
  const gchar *expected_window;
  gint64 expected_timestamp;
  gboolean answer;
  guint calls;
} WindowExpect;

typedef struct
{
  const gint64 *row;
  guint matches;
} GuardFactExpect;

typedef enum
{
  GUARD_FACT_EVAL_GUARD,
  GUARD_FACT_CONTEXT_NOW,
  GUARD_FACT_GUARD_CONTEXT,
} GuardFactKind;

static gboolean
window_expect_cb (gint64 timestamp, const gchar *window_name,
    gpointer user_data)
{
  WindowExpect *expect = user_data;
  expect->calls++;
  if (timestamp != expect->expected_timestamp)
    return FALSE;
  if (g_strcmp0 (window_name, expect->expected_window) != 0)
    return FALSE;
  return expect->answer;
}

static void
count_context_now_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  (void) relation;
  GuardFactExpect *expect = user_data;
  if (ncols == 3 && row[0] == expect->row[0] && row[1] == expect->row[2])
    expect->matches++;
}

static void
count_eval_guard_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  (void) relation;
  GuardFactExpect *expect = user_data;
  if (ncols == 4 && row[0] == expect->row[0] && row[1] == expect->row[1]
      && row[2] == expect->row[2])
    expect->matches++;
}

static void
count_guard_context_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  (void) relation;
  GuardFactExpect *expect = user_data;
  if (ncols == 6 && row[1] == expect->row[0] && row[2] == expect->row[2])
    expect->matches++;
}

static void
count_any_guard_context_field_cb (const gchar *relation, const gint64 *row,
    guint ncols, gpointer user_data)
{
  guint *seen = user_data;

  (void) relation;
  (void) row;
  (void) ncols;

  (*seen)++;
}

static gint
check_guard_context_field_absent (WylHandle *handle, const gchar *relation,
    gint base_code)
{
  guint seen = 0;
  wyrelog_error_t rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
      relation, count_any_guard_context_field_cb, &seen);
  if (rc != WYRELOG_E_OK)
    return base_code;
  if (seen != 0)
    return base_code + 1;
  return 0;
}

static gint
check_guard_bridge_facts_absent (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource, gint base_code)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, subject, &row[0]);
  if (rc != WYRELOG_E_OK)
    return base_code;
  rc = intern_symbol (handle, action, &row[1]);
  if (rc != WYRELOG_E_OK)
    return base_code + 1;
  rc = intern_symbol (handle, resource, &row[2]);
  if (rc != WYRELOG_E_OK)
    return base_code + 2;

  GuardFactExpect expect = { row, 0 };
  rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
      "context_now", count_context_now_cb, &expect);
  if (rc != WYRELOG_E_OK)
    return base_code + 3;
  if (expect.matches != 0)
    return base_code + 4;

  expect.matches = 0;
  rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
      "eval_guard", count_eval_guard_cb, &expect);
  if (rc != WYRELOG_E_OK)
    return base_code + 5;
  if (expect.matches != 0)
    return base_code + 6;

  expect.matches = 0;
  rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
      "guard_context", count_guard_context_cb, &expect);
  if (rc != WYRELOG_E_OK)
    return base_code + 7;
  if (expect.matches != 0)
    return base_code + 8;

  rc = check_guard_context_field_absent (handle, "guard_context_timestamp",
      base_code + 9);
  if (rc != 0)
    return rc;
  rc = check_guard_context_field_absent (handle, "guard_context_loc_class",
      base_code + 11);
  if (rc != 0)
    return rc;
  rc = check_guard_context_field_absent (handle, "guard_context_risk",
      base_code + 13);
  if (rc != 0)
    return rc;
  rc = check_guard_context_field_absent (handle, "guard_context_in_window",
      base_code + 15);
  if (rc != 0)
    return rc;

  return 0;
}

static gint
count_guard_bridge_fact (WylHandle *handle, const gint64 row[3],
    GuardFactKind kind, guint *out_matches)
{
  GuardFactExpect expect = { row, 0 };
  const gchar *relation = NULL;
  WylTupleCallback cb = NULL;

  switch (kind) {
    case GUARD_FACT_EVAL_GUARD:
      relation = "eval_guard";
      cb = count_eval_guard_cb;
      break;
    case GUARD_FACT_CONTEXT_NOW:
      relation = "context_now";
      cb = count_context_now_cb;
      break;
    case GUARD_FACT_GUARD_CONTEXT:
      relation = "guard_context";
      cb = count_guard_context_cb;
      break;
    default:
      return 999;
  }

  wyrelog_error_t rc = wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
      relation, cb, &expect);
  if (rc != WYRELOG_E_OK)
    return 998;
  *out_matches = expect.matches;
  return 0;
}

static gint
check_guard_cleanup_fault_residue (WylHandle *handle, gint base_code)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, "cleanup-user", &row[0]);
  if (rc != WYRELOG_E_OK)
    return base_code;
  rc = intern_symbol (handle, "wr.audit.read", &row[1]);
  if (rc != WYRELOG_E_OK)
    return base_code + 1;
  rc = intern_symbol (handle, "cleanup-resource", &row[2]);
  if (rc != WYRELOG_E_OK)
    return base_code + 2;

  guint eval_guard = 0;
  guint context_now = 0;
  guint guard_context = 0;
  gint check = count_guard_bridge_fact (handle, row, GUARD_FACT_EVAL_GUARD,
      &eval_guard);
  if (check != 0)
    return base_code + 3;
  check = count_guard_bridge_fact (handle, row, GUARD_FACT_CONTEXT_NOW,
      &context_now);
  if (check != 0)
    return base_code + 4;
  check = count_guard_bridge_fact (handle, row, GUARD_FACT_GUARD_CONTEXT,
      &guard_context);
  if (check != 0)
    return base_code + 5;

  if (eval_guard != 0 || context_now != 0 || guard_context != 0)
    return base_code + 6;

  gint field_check = check_guard_context_field_absent (handle,
      "guard_context_timestamp", base_code + 7);
  if (field_check != 0)
    return field_check;
  field_check = check_guard_context_field_absent (handle,
      "guard_context_loc_class", base_code + 9);
  if (field_check != 0)
    return field_check;
  field_check = check_guard_context_field_absent (handle,
      "guard_context_risk", base_code + 11);
  if (field_check != 0)
    return field_check;
  field_check = check_guard_context_field_absent (handle,
      "guard_context_in_window", base_code + 13);
  if (field_check != 0)
    return field_check;

  return 0;
}

static wyrelog_error_t
run_stream_window_decide (WylHandle *handle, gboolean install_matcher,
    gboolean matcher_answer, wyl_decision_t *out_decision, guint *out_calls)
{
  WindowExpect expect = {
    .expected_window = "off_hours",
    .expected_timestamp = 4242,
    .answer = matcher_answer,
    .calls = 0,
  };
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "window-user");
  wyl_decide_req_set_action (req, "wr.stream.write_reserved");
  wyl_decide_req_set_resource_id (req, "window-resource");
  wyl_decide_req_set_guard_context (req, 4242, "trusted", 1);
  if (install_matcher)
    wyl_decide_req_set_guard_window_matcher (req, window_expect_cb, &expect);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyrelog_error_t rc = wyl_decide (handle, req, resp);
  if (rc != WYRELOG_E_OK)
    return rc;
  *out_decision = wyl_decide_resp_get_decision (resp);
  *out_calls = expect.calls;
  return WYRELOG_E_OK;
}

static gint
check_decide_returns_ok_and_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_action (req, "read");
  wyl_decide_req_set_resource_id (req, "doc/42");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 11;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 12;
  return 0;
}

static gint
check_decide_rejects_null_args (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 20;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  if (wyl_decide (NULL, req, resp) != WYRELOG_E_INVALID)
    return 21;
  if (wyl_decide (handle, NULL, resp) != WYRELOG_E_INVALID)
    return 22;
  if (wyl_decide (handle, req, NULL) != WYRELOG_E_INVALID)
    return 23;
  return 0;
}

static gint
check_decide_rejects_incomplete_req_as_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  /* Pre-set ALLOW; invalid decide must overwrite back to DENY. */
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 31;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 32;
  wyl_decide_req_set_subject_id (req, "alice");
  wyl_decide_req_set_action (req, "read");
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 33;
  return 0;
}

static gint
check_decide_rejects_invalid_guard_context (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 34;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "ctx-user");
  wyl_decide_req_set_action (req, "read");
  wyl_decide_req_set_resource_id (req, "ctx-resource");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_req_set_guard_context (req, -1, "trusted", 1);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 35;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 36;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_req_set_guard_context (req, 1, "unknown", 1);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 37;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 38;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_req_set_guard_context (req, 1, NULL, 1);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 39;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 40;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_req_set_guard_context (req, 1, "trusted", -1);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 41;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 42;

  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_decide_req_set_guard_context (req, 1, "trusted", 101);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INVALID)
    return 43;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 44;

  wyl_decide_req_set_guard_context (req, 1, "semi_trusted", 100);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 45;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 46;

  return 0;
}

static gint
check_decide_allows_engine_tuple (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 41;
  if (insert_allow_fixture (handle, "decide-user-a",
          "wr.decide-permission-a", "decide-resource-a") != WYRELOG_E_OK)
    return 42;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-a");
  wyl_decide_req_set_action (req, "wr.decide-permission-a");
  wyl_decide_req_set_resource_id (req, "decide-resource-a");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 43;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 44;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 45;
  if (wyl_decide_resp_get_deny_origin (resp) != NULL)
    return 46;
  return 0;
}

static gint
check_decide_denies_engine_miss (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 50;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 51;
  if (insert_allow_fixture (handle, "decide-user-b",
          "wr.decide-permission-b", "decide-resource-b") != WYRELOG_E_OK)
    return 52;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-b");
  wyl_decide_req_set_action (req, "wr.decide-permission-b");
  wyl_decide_req_set_resource_id (req, "other-resource-b");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 53;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 54;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 55;
  if (wyl_decide_resp_get_deny_origin (resp) != NULL)
    return 56;
  return 0;
}

static gint
check_decide_unclassified_read_denies (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 210;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 211;
  if (insert_grant_fixture (handle, "missing-session-user",
          "missing-session-permission", "missing-session-resource")
      != WYRELOG_E_OK)
    return 212;
  if (insert_symbol_row2 (handle, "principal_state", "missing-session-user",
          "authenticated") != WYRELOG_E_OK)
    return 213;
  if (insert_symbol_row1 (handle, "session_active", "active")
      != WYRELOG_E_OK)
    return 214;
  if (insert_symbol_row4 (handle, "perm_state", "missing-session-user",
          "missing-session-permission", "missing-session-resource", "armed")
      != WYRELOG_E_OK)
    return 215;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "missing-session-user");
  wyl_decide_req_set_action (req, "missing-session-permission");
  wyl_decide_req_set_resource_id (req, "missing-session-resource");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 216;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 217;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 218;
  if (wyl_decide_resp_get_deny_origin (resp) != NULL)
    return 219;
  return 0;
}

static gint
check_decide_allows_guarded_permission_with_context (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 60;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 61;
  if (insert_allow_fixture_state (handle, "decide-user-c", "wr.audit.read",
          "decide-resource-c", FALSE) != WYRELOG_E_OK)
    return 62;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-c");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "decide-resource-c");
  wyl_decide_req_set_guard_context (req, 123, "public", 69);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 63;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 64;
  gint guard_rc = check_guard_bridge_facts_absent (handle, "decide-user-c",
      "wr.audit.read", "decide-resource-c", 67);
  if (guard_rc != 0)
    return guard_rc;

  wyl_decide_req_clear_guard_context (req);
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 65;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 66;

  return 0;
}

static gint
check_decide_denies_guarded_permission_on_context_miss (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 70;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 71;
  if (insert_allow_fixture_state (handle, "decide-user-d", "wr.audit.read",
          "decide-resource-d", TRUE) != WYRELOG_E_OK)
    return 72;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-d");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "decide-resource-d");
  wyl_decide_req_set_guard_context (req, 123, "public", 70);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 73;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 74;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 75;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 76;

  return 0;
}

/* The self-arm route's eligibility gate is decide(actor,
 * wr.service.self_authorize, __wr_default). Prove the bootstrap wr.system_admin
 * role carries that permission and that its strict guard (risk < 30 AND loc
 * trusted) arms it via rule-3: ALLOW under a satisfying guard, DENY otherwise.
 * The guard is not the primary control (see the route), but a failing guard
 * must still deny the eligibility decision. */
static gint
check_decide_allows_self_authorize_for_system_admin (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 300;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 301;
  /* Seed only a wr.system_admin membership at __wr_default and rely on the
   * bootstrap role_permission fact for has_permission -- no direct grant. */
  if (insert_symbol_row3 (handle, "member_of", "self-arm-admin",
          "wr.system_admin", "__wr_default") != WYRELOG_E_OK)
    return 302;
  if (insert_symbol_row2 (handle, "principal_state", "self-arm-admin",
          "authenticated") != WYRELOG_E_OK)
    return 303;
  if (insert_symbol_row2 (handle, "session_state", "__wr_default", "active")
      != WYRELOG_E_OK)
    return 304;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 305;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "self-arm-admin");
  wyl_decide_req_set_action (req, "wr.service.self_authorize");
  wyl_decide_req_set_resource_id (req, "__wr_default");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_req_set_guard_context (req, 123, "trusted", 29);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 306;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 307;

  wyl_decide_req_set_guard_context (req, 123, "trusted", 30);
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 308;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 309;

  wyl_decide_req_set_guard_context (req, 123, "untrusted", 1);
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 310;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 311;

  return 0;
}

static gint
check_policy_store_replay_requires_durable_permission_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 123;

  if (seed_policy_store_decide_fixture (handle, "replay-legacy-user",
          "site.replay.read", "tenant/replay", NULL) != WYRELOG_E_OK)
    return 124;

  gboolean has_durable_state = TRUE;
  if (wyl_policy_store_permission_state_exists (wyl_handle_get_policy_store
          (handle), "replay-legacy-user", "site.replay.read",
          "tenant/replay", &has_durable_state) != WYRELOG_E_OK)
    return 125;
  if (has_durable_state)
    return 126;

  gboolean contains = TRUE;
  gint64 armed_row[4];
  if (intern_symbol (handle, "replay-legacy-user", &armed_row[0])
      != WYRELOG_E_OK)
    return 150;
  if (intern_symbol (handle, "site.replay.read", &armed_row[1])
      != WYRELOG_E_OK)
    return 151;
  if (intern_symbol (handle, "tenant/replay", &armed_row[2])
      != WYRELOG_E_OK)
    return 152;
  if (intern_symbol (handle, "armed", &armed_row[3]) != WYRELOG_E_OK)
    return 153;
  if (wyl_handle_engine_contains (handle, "perm_state", armed_row, 4,
          &contains) != WYRELOG_E_OK)
    return 154;
  if (contains)
    return 155;

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (decide_policy_store_fixture (handle, "replay-legacy-user",
          "site.replay.read", "tenant/replay", resp) != WYRELOG_E_OK)
    return 127;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 128;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 129;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 156;
  return 0;
}

static gint
check_policy_store_replay_preserves_dormant_permission_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 130;

  if (seed_policy_store_decide_fixture (handle, "replay-dormant-user",
          "site.replay.write", "tenant/replay", "dormant") != WYRELOG_E_OK)
    return 131;
  gboolean contains = FALSE;
  gint64 dormant_row[4];
  if (intern_symbol (handle, "replay-dormant-user", &dormant_row[0])
      != WYRELOG_E_OK)
    return 142;
  if (intern_symbol (handle, "site.replay.write", &dormant_row[1])
      != WYRELOG_E_OK)
    return 143;
  if (intern_symbol (handle, "tenant/replay", &dormant_row[2])
      != WYRELOG_E_OK)
    return 144;
  if (intern_symbol (handle, "dormant", &dormant_row[3]) != WYRELOG_E_OK)
    return 145;
  if (wyl_handle_engine_contains (handle, "perm_state", dormant_row, 4,
          &contains) != WYRELOG_E_OK)
    return 146;
  if (!contains)
    return 147;

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (decide_policy_store_fixture (handle, "replay-dormant-user",
          "site.replay.write", "tenant/replay", resp) != WYRELOG_E_OK)
    return 132;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 133;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 134;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 135;
  return 0;
}

static gint
check_policy_store_replay_preserves_armed_permission_state (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 136;

  if (seed_policy_store_decide_fixture (handle, "replay-armed-user",
          "site.replay.admin", "tenant/replay", "armed") != WYRELOG_E_OK)
    return 137;

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (decide_policy_store_fixture (handle, "replay-armed-user",
          "site.replay.admin", "tenant/replay", resp) != WYRELOG_E_OK)
    return 138;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 139;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 140;
  return 0;
}

static gint
check_persistent_permission_state_authority_matrix (void)
{
  g_autoptr (GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("wyrelog-decide-XXXXXX", &error);
  if (dir == NULL)
    return 157;

  g_autofree gchar *policy_path = g_build_filename (dir, "policy.sqlite", NULL);
#ifdef WYL_HAS_AUDIT
  /* Each handle gets its own audit DuckDB path so the close/reopen
   * across the two blocks does not trip the same-file reopen
   * sensitivity that surfaces under ASAN + MALLOC_PERTURB_ on Linux.
   * The test exercises the policy_store reopen, not the audit store
   * lifecycle, so distinct audit paths preserve the test intent. */
  g_autofree gchar *audit_path = g_build_filename (dir, "audit.duckdb", NULL);
  g_autofree gchar *audit_path2 = g_build_filename (dir, "audit2.duckdb", NULL);
#endif

  {
    g_autoptr (WylHandle) handle = NULL;
    WylHandleOpenOptions opts = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .policy_store_path = policy_path,
#ifdef WYL_HAS_AUDIT
      .audit_store_path = audit_path,
#endif
    };
    if (wyl_handle_open_with_options (&opts, &handle) != WYRELOG_E_OK)
      return 158;
    if (seed_policy_store_decide_fixture (handle, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", NULL) != WYRELOG_E_OK)
      return 159;

    g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
    if (decide_policy_store_fixture (handle, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", resp) != WYRELOG_E_OK)
      return 160;
    if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
      return 161;
    if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
      return 162;

    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 163;
    g_autoptr (wyl_decide_resp_t) reload_resp = wyl_decide_resp_new ();
    if (decide_policy_store_fixture (handle, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", reload_resp)
        != WYRELOG_E_OK)
      return 164;
    if (wyl_decide_resp_get_decision (reload_resp) != WYL_DECISION_DENY)
      return 165;
    if (g_strcmp0 (wyl_decide_resp_get_deny_reason (reload_resp),
            "not_armed") != 0)
      return 166;
  }

  {
    g_autoptr (WylHandle) handle = NULL;
    WylHandleOpenOptions opts = {
      .template_dir = WYL_TEST_TEMPLATE_DIR,
      .policy_store_path = policy_path,
#ifdef WYL_HAS_AUDIT
      .audit_store_path = audit_path2,
#endif
    };
    if (wyl_handle_open_with_options (&opts, &handle) != WYRELOG_E_OK)
      return 167;

    g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
    if (decide_policy_store_fixture (handle, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", resp) != WYRELOG_E_OK)
      return 168;
    if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
      return 169;
    if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
      return 170;

    wyl_policy_store_t *store = wyl_handle_get_policy_store (handle);
    if (wyl_policy_store_set_permission_state (store, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", "armed") != WYRELOG_E_OK)
      return 171;
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 172;
    g_clear_pointer (&resp, wyl_decide_resp_free);
    resp = wyl_decide_resp_new ();
    if (decide_policy_store_fixture (handle, "matrix-direct-user",
            "site.matrix.read", "tenant/matrix", resp) != WYRELOG_E_OK)
      return 173;
    if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
      return 174;
    if (wyl_decide_resp_get_deny_reason (resp) != NULL)
      return 175;

    if (wyl_policy_store_upsert_permission (store, "site.matrix.transition",
            "transition only", "basic") != WYRELOG_E_OK)
      return 176;
    if (wyl_policy_store_set_principal_state (store, "matrix-transition-user",
            "authenticated") != WYRELOG_E_OK)
      return 177;
    if (wyl_policy_store_set_session_state (store, "tenant/matrix-transition",
            "active") != WYRELOG_E_OK)
      return 178;
    if (wyl_policy_store_set_permission_state (store, "matrix-transition-user",
            "site.matrix.transition", "tenant/matrix-transition", "armed")
        != WYRELOG_E_OK)
      return 179;
    if (wyl_handle_reload_engine_pair (handle) != WYRELOG_E_OK)
      return 180;
    g_clear_pointer (&resp, wyl_decide_resp_free);
    resp = wyl_decide_resp_new ();
    if (decide_policy_store_fixture (handle, "matrix-transition-user",
            "site.matrix.transition", "tenant/matrix-transition", resp)
        != WYRELOG_E_OK)
      return 181;
    if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
      return 182;
    if (wyl_decide_resp_get_deny_reason (resp) != NULL)
      return 183;
  }

#ifdef WYL_HAS_AUDIT
  g_remove (audit_path);
  g_remove (audit_path2);
#endif
  g_remove (policy_path);
  g_rmdir (dir);
  return 0;
}

static gint
check_decide_cleans_guard_facts_after_guarded_deny (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 80;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 81;
  if (insert_allow_fixture_state (handle, "decide-user-e", "wr.audit.read",
          "decide-resource-e", FALSE) != WYRELOG_E_OK)
    return 82;
  if (insert_symbol_row1 (handle, "frozen", "decide-resource-e")
      != WYRELOG_E_OK)
    return 83;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "decide-user-e");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "decide-resource-e");
  wyl_decide_req_set_guard_context (req, 123, "public", 69);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 84;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 85;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "frozen") != 0)
    return 86;

  return check_guard_bridge_facts_absent (handle, "decide-user-e",
      "wr.audit.read", "decide-resource-e", 87);
}

static gint
check_decide_reports_state_deny_reasons (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 220;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 221;
  if (insert_grant_fixture (handle, "state-deny-user",
          "state-deny-permission", "state-deny-resource") != WYRELOG_E_OK)
    return 222;
  if (insert_symbol_row2 (handle, "session_state", "state-deny-resource",
          "active") != WYRELOG_E_OK)
    return 223;
  if (insert_symbol_row1 (handle, "session_active", "active")
      != WYRELOG_E_OK)
    return 224;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "state-deny-user");
  wyl_decide_req_set_action (req, "state-deny-permission");
  wyl_decide_req_set_resource_id (req, "state-deny-resource");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 225;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 226;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "not_authenticated") != 0)
    return 227;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp),
          "principal_state") != 0)
    return 228;

  if (insert_grant_fixture (handle, "inactive-session-user",
          "inactive-session-permission", "inactive-session-resource")
      != WYRELOG_E_OK)
    return 229;
  if (insert_symbol_row2 (handle, "principal_state", "inactive-session-user",
          "authenticated") != WYRELOG_E_OK)
    return 230;
  if (insert_symbol_row2 (handle, "session_state", "inactive-session-resource",
          "idle") != WYRELOG_E_OK)
    return 231;
  wyl_decide_req_set_subject_id (req, "inactive-session-user");
  wyl_decide_req_set_action (req, "inactive-session-permission");
  wyl_decide_req_set_resource_id (req, "inactive-session-resource");
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 232;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 233;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "session_inactive") != 0)
    return 234;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "session_state")
      != 0)
    return 235;
  return 0;
}

static gint
check_decide_prioritizes_guarded_blockers (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 240;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 241;
  if (insert_allow_fixture_state (handle, "guard-priority-user",
          "wr.audit.read", "guard-priority-resource", FALSE)
      != WYRELOG_E_OK)
    return 242;
  if (insert_symbol_row4 (handle, "policy_violation", "sod",
          "guard-priority-user", "wr.audit.read", "fixture")
      != WYRELOG_E_OK)
    return 243;
  if (insert_symbol_row2 (handle, "disabled_role_for", "guard-priority-user",
          "wr.audit.read") != WYRELOG_E_OK)
    return 244;
  if (insert_symbol_row1 (handle, "frozen", "guard-priority-resource")
      != WYRELOG_E_OK)
    return 245;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "guard-priority-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "guard-priority-resource");
  wyl_decide_req_set_guard_context (req, 123, "public", 70);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 246;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 247;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "frozen") != 0)
    return 248;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "frozen") != 0)
    return 249;

  return check_guard_bridge_facts_absent (handle, "guard-priority-user",
      "wr.audit.read", "guard-priority-resource", 250);
}

static gint
check_guard_cleanup_fault (const gchar *relation, gint base_code)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return base_code;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return base_code + 1;
  if (insert_allow_fixture_state (handle, "cleanup-user", "wr.audit.read",
          "cleanup-resource", FALSE) != WYRELOG_E_OK)
    return base_code + 2;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "cleanup-user");
  wyl_decide_req_set_action (req, "wr.audit.read");
  wyl_decide_req_set_resource_id (req, "cleanup-resource");
  wyl_decide_req_set_guard_context (req, 123, "public", 69);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_handle_set_engine_remove_fault_once (handle, relation,
      WYRELOG_E_INTERNAL);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INTERNAL)
    return base_code + 3;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return base_code + 4;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "guard_cleanup_failed") != 0)
    return base_code + 5;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "eval_guard") != 0)
    return base_code + 6;
  return check_guard_cleanup_fault_residue (handle, base_code + 7);
}

static gint
check_decide_fail_closes_on_guard_cleanup_faults (void)
{
  gint rc = check_guard_cleanup_fault ("eval_guard", 130);
  if (rc != 0)
    return rc;
  rc = check_guard_cleanup_fault ("context_now", 160);
  if (rc != 0)
    return rc;
  rc = check_guard_cleanup_fault ("guard_context_timestamp", 190);
  if (rc != 0)
    return rc;
  rc = check_guard_cleanup_fault ("guard_context_loc_class", 220);
  if (rc != 0)
    return rc;
  rc = check_guard_cleanup_fault ("guard_context_risk", 250);
  if (rc != 0)
    return rc;
  return check_guard_cleanup_fault ("guard_context", 280);
}

static gint
check_window_guard_cleanup_fault (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 310;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 311;
  if (insert_allow_fixture_state (handle, "cleanup-window-user",
          "wr.stream.write_reserved", "cleanup-window-resource", FALSE)
      != WYRELOG_E_OK)
    return 312;

  WindowExpect expect = {
    .expected_window = "off_hours",
    .expected_timestamp = 4242,
    .answer = TRUE,
    .calls = 0,
  };
  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "cleanup-window-user");
  wyl_decide_req_set_action (req, "wr.stream.write_reserved");
  wyl_decide_req_set_resource_id (req, "cleanup-window-resource");
  wyl_decide_req_set_guard_context (req, 4242, "trusted", 1);
  wyl_decide_req_set_guard_window_matcher (req, window_expect_cb, &expect);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_handle_set_engine_remove_fault_once (handle, "guard_context_in_window",
      WYRELOG_E_INTERNAL);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INTERNAL)
    return 313;
  if (expect.calls != 1)
    return 314;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 315;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "guard_cleanup_failed") != 0)
    return 316;

  return check_guard_bridge_facts_absent (handle, "cleanup-window-user",
      "wr.stream.write_reserved", "cleanup-window-resource", 317);
}

static gint
check_decide_evaluates_window_guard (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 90;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 91;
  if (insert_allow_fixture_state (handle, "window-user",
          "wr.stream.write_reserved", "window-resource", FALSE)
      != WYRELOG_E_OK)
    return 92;

  wyl_decision_t decision = WYL_DECISION_ALLOW;
  guint calls = 99;
  if (run_stream_window_decide (handle, FALSE, FALSE, &decision, &calls)
      != WYRELOG_E_OK)
    return 93;
  if (decision != WYL_DECISION_DENY || calls != 0)
    return 94;
  if (check_guard_bridge_facts_absent (handle, "window-user",
          "wr.stream.write_reserved", "window-resource", 95) != 0)
    return 102;

  if (run_stream_window_decide (handle, TRUE, FALSE, &decision, &calls)
      != WYRELOG_E_OK)
    return 103;
  if (decision != WYL_DECISION_DENY || calls != 1)
    return 104;
  if (check_guard_bridge_facts_absent (handle, "window-user",
          "wr.stream.write_reserved", "window-resource", 105) != 0)
    return 112;

  if (run_stream_window_decide (handle, TRUE, TRUE, &decision, &calls)
      != WYRELOG_E_OK)
    return 113;
  if (decision != WYL_DECISION_ALLOW || calls != 1)
    return 114;
  if (check_guard_bridge_facts_absent (handle, "window-user",
          "wr.stream.write_reserved", "window-resource", 115) != 0)
    return 122;

  return 0;
}

/*
 * #740 WALL 1: a fully validated live service (svc:) bearer has no store
 * fact principal_state(subject,"authenticated") -- that row is written
 * only for human sessions -- so allow_guard_base denies not_authenticated
 * even after a role grant. wyl_decide injects the fact TRANSIENTLY when
 * the request carries the daemon-set service-bearer-authenticated flag,
 * and removes it on every exit path.
 *
 * SCOPE: these cases exercise ONLY the principal_state blocker (Wall 1).
 * They seed session_state active directly so Wall 2 (fresh-tenant
 * session_state seeding, #382) is not in play; public end-to-end service
 * /decide allow at a fresh tenant remains gated by Wall 2 and is out of
 * scope for this test.
 */
static gint
check_decide_service_bearer_injects_principal_state (void)
{
  const gchar *subject = "svc:decide-user-740";
  const gchar *action = "wr.decide-permission-svc";
  const gchar *resource = "svc-decide-resource-740";
  gint64 probe_row[2];
  gboolean present = TRUE;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 700;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 701;
  if (insert_service_grant_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 702;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  /* Case A (bug): flag unset -> DENY not_authenticated / principal_state. */
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 703;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 704;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_authenticated")
      != 0)
    return 705;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "principal_state")
      != 0)
    return 706;

  /* Case B (deny->allow): flag set -> ALLOW. */
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 707;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 708;

  /* Case C (no residue): the transient fact must not persist. */
  if (intern_symbol (handle, subject, &probe_row[0]) != WYRELOG_E_OK)
    return 709;
  if (intern_symbol (handle, "authenticated", &probe_row[1]) != WYRELOG_E_OK)
    return 710;
  if (wyl_handle_engine_contains (handle, "principal_state", probe_row, 2,
          &present) != WYRELOG_E_OK)
    return 711;
  if (present)
    return 712;
  /* A subsequent flag-unset decide must deny again (no leaked authority). */
  wyl_decide_req_set_service_bearer_authenticated (req, FALSE);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 713;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 714;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_authenticated")
      != 0)
    return 715;

  return 0;
}

/*
 * With the service-bearer flag set, blockers that outrank
 * not_authenticated must still deny: the transient principal_state fact
 * clears ONLY the authentication gate, it does not force an ALLOW.
 */
static gint
check_decide_service_bearer_respects_other_blockers (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 720;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 721;

  /* Case D (freeze still denies). */
  if (insert_service_grant_fixture (handle, "svc:frozen-user-740",
          "wr.decide-permission-svc", "svc-frozen-resource-740")
      != WYRELOG_E_OK)
    return 722;
  if (insert_symbol_row1 (handle, "frozen", "svc-frozen-resource-740")
      != WYRELOG_E_OK)
    return 723;

  g_autoptr (wyl_decide_req_t) freeze_req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (freeze_req, "svc:frozen-user-740");
  wyl_decide_req_set_action (freeze_req, "wr.decide-permission-svc");
  wyl_decide_req_set_resource_id (freeze_req, "svc-frozen-resource-740");
  wyl_decide_req_set_service_bearer_authenticated (freeze_req, TRUE);
  g_autoptr (wyl_decide_resp_t) freeze_resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, freeze_req, freeze_resp) != WYRELOG_E_OK)
    return 724;
  if (wyl_decide_resp_get_decision (freeze_resp) != WYL_DECISION_DENY)
    return 725;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (freeze_resp), "frozen") != 0)
    return 726;

  /* Case E (disabled_role still denies). */
  if (insert_service_grant_fixture (handle, "svc:disabled-user-740",
          "wr.decide-permission-svc", "svc-disabled-resource-740")
      != WYRELOG_E_OK)
    return 727;
  if (insert_symbol_row2 (handle, "disabled_role_for", "svc:disabled-user-740",
          "wr.decide-permission-svc") != WYRELOG_E_OK)
    return 728;

  g_autoptr (wyl_decide_req_t) disabled_req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (disabled_req, "svc:disabled-user-740");
  wyl_decide_req_set_action (disabled_req, "wr.decide-permission-svc");
  wyl_decide_req_set_resource_id (disabled_req, "svc-disabled-resource-740");
  wyl_decide_req_set_service_bearer_authenticated (disabled_req, TRUE);
  g_autoptr (wyl_decide_resp_t) disabled_resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, disabled_req, disabled_resp) != WYRELOG_E_OK)
    return 729;
  if (wyl_decide_resp_get_decision (disabled_resp) != WYL_DECISION_DENY)
    return 730;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (disabled_resp),
          "disabled_role") != 0)
    return 731;

  return 0;
}

/*
 * Case F: a human subject with a real principal_state row and the flag
 * left unset behaves exactly as before -- ALLOW -- proving the new lever
 * is inert for the human path.
 */
static gint
check_decide_human_path_unchanged_without_flag (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 740;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 741;
  if (insert_allow_fixture (handle, "human-user-740",
          "wr.decide-permission-human", "human-resource-740") != WYRELOG_E_OK)
    return 742;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "human-user-740");
  wyl_decide_req_set_action (req, "wr.decide-permission-human");
  wyl_decide_req_set_resource_id (req, "human-resource-740");
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 743;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 744;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 745;
  return 0;
}

/*
 * #740 WALL 1 fail-closed: if the transient principal_state row cannot be
 * removed after the decide, wyl_decide must fail closed (DENY,
 * principal_state_cleanup_failed) and propagate the error rather than let
 * the injected authenticated state leak into a later decide. Mirrors the
 * guard-eval cleanup-fault behaviour, using the same engine-remove
 * fault-once seam.
 */
static gint
check_decide_fail_closes_on_pstate_cleanup_fault (void)
{
  const gchar *subject = "svc:cleanup-user-740";
  const gchar *action = "wr.decide-permission-svc";
  const gchar *resource = "svc-cleanup-resource-740";

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 760;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 761;
  if (insert_service_grant_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 762;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_handle_set_engine_remove_fault_once (handle, "principal_state",
      WYRELOG_E_INTERNAL);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INTERNAL)
    return 763;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 764;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "principal_state_cleanup_failed") != 0)
    return 765;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "principal_state")
      != 0)
    return 766;
  return 0;
}

/*
 * #762 WALL 3 (deny->allow): a fully validated live service (svc:) bearer
 * that holds an APPROVED data-plane grant at an active scope still can't
 * authorize -- armed/3 rule-1 needs a durable perm_state("armed") EDB row
 * and the store rejects perm_state for svc: subjects. wyl_decide injects
 * that armed row TRANSIENTLY when the service-bearer flag is set AND the
 * action is an approved data-plane permission, so the grant arms and
 * (with the #740 principal_state + #744 session_state) allows. The fact
 * is removed on every exit path; nothing is written to the policy store.
 */
static gint
check_decide_service_bearer_arms_data_plane_permission (void)
{
  const gchar *subject = "svc:decide-user-762";
  const gchar *action = "wr.svc.read_decision";
  const gchar *resource = "svc-decide-resource-762";
  gint64 probe_row[4];
  gboolean present = TRUE;

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 800;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 801;
  if (insert_service_grant_unarmed_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 802;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  /* Case A (bug): flag unset -> DENY (no principal_state either). */
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 803;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 804;

  /* Case B (deny->allow): flag set -> ALLOW. Before the #762 injection
   * this denies not_armed / perm_state even with the flag set. */
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 805;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 806;

  /* Case C (no residue): the transient armed perm_state must not persist. */
  if (intern_symbol (handle, subject, &probe_row[0]) != WYRELOG_E_OK)
    return 807;
  if (intern_symbol (handle, action, &probe_row[1]) != WYRELOG_E_OK)
    return 808;
  if (intern_symbol (handle, resource, &probe_row[2]) != WYRELOG_E_OK)
    return 809;
  if (intern_symbol (handle, "armed", &probe_row[3]) != WYRELOG_E_OK)
    return 810;
  if (wyl_handle_engine_contains (handle, "perm_state", probe_row, 4, &present)
      != WYRELOG_E_OK)
    return 811;
  if (present)
    return 812;

  /* A subsequent flag-unset decide must deny again (no leaked arming). */
  wyl_decide_req_set_service_bearer_authenticated (req, FALSE);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 813;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 814;

  return 0;
}

/*
 * #762 control-plane guard: the transient arming is gated on the approved
 * data-plane C-list (wyl_policy_store_approved_data_plane_permission_*).
 * A svc: bearer that holds a NON data-plane (control-plane) permission is
 * never armed, even with the flag set and has_permission true -> DENY
 * not_armed / perm_state.
 */
static gint
check_decide_service_bearer_does_not_arm_control_plane (void)
{
  const gchar *subject = "svc:decide-user-762-cp";
  const gchar *action = "wr.policy.grant_role";
  const gchar *resource = "svc-decide-resource-762-cp";

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 820;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 821;
  if (insert_service_grant_unarmed_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 822;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 823;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 824;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") != 0)
    return 825;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 826;

  return 0;
}

/*
 * #762 ungranted guard: a svc: bearer WITHOUT the data-plane grant fails
 * gate-2 (has_permission false), so nothing is armed. The deny is a
 * pre-arm authorization reason, never not_armed (which requires
 * has_permission to hold).
 */
static gint
check_decide_service_bearer_ungranted_denies (void)
{
  const gchar *subject = "svc:decide-user-762-ung";
  const gchar *action = "wr.svc.read_decision";
  const gchar *resource = "svc-decide-resource-762-ung";

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 830;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 831;
  /* Active scope but NO role grant -> has_permission is false. */
  if (insert_symbol_row2 (handle, "session_state", resource, "active")
      != WYRELOG_E_OK)
    return 832;
  if (insert_symbol_row1 (handle, "session_active", "active") != WYRELOG_E_OK)
    return 833;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 834;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 835;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "not_armed") == 0)
    return 836;

  return 0;
}

/*
 * #762 freeze still denies: an armed data-plane grant with the flag set is
 * still denied on the freeze gate -- the transient arming clears only the
 * not_armed blocker, it never forces ALLOW past an independent conjunct of
 * allow_guard_base.
 */
static gint
check_decide_service_bearer_data_plane_respects_freeze (void)
{
  const gchar *subject = "svc:decide-user-762-frz";
  const gchar *action = "wr.svc.read_decision";
  const gchar *resource = "svc-decide-resource-762-frz";

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 840;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 841;
  if (insert_service_grant_unarmed_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 842;
  if (insert_symbol_row1 (handle, "frozen", resource) != WYRELOG_E_OK)
    return 843;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);
  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();

  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 844;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 845;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp), "frozen") != 0)
    return 846;

  return 0;
}

/*
 * #762 fail-closed: if the transient armed perm_state row cannot be
 * removed after the decide, wyl_decide must fail closed (DENY,
 * perm_state_cleanup_failed) and propagate the error rather than let the
 * injected arming leak into a later decide. Mirrors the principal_state
 * cleanup-fault behaviour using the same engine-remove fault-once seam.
 */
static gint
check_decide_fail_closes_on_perm_state_cleanup_fault (void)
{
  const gchar *subject = "svc:decide-user-762-clf";
  const gchar *action = "wr.svc.read_decision";
  const gchar *resource = "svc-decide-resource-762-clf";

  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 850;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 851;
  if (insert_service_grant_unarmed_fixture (handle, subject, action, resource)
      != WYRELOG_E_OK)
    return 852;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, subject);
  wyl_decide_req_set_action (req, action);
  wyl_decide_req_set_resource_id (req, resource);
  wyl_decide_req_set_service_bearer_authenticated (req, TRUE);

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  wyl_decide_resp_set_decision (resp, WYL_DECISION_ALLOW);
  wyl_handle_set_engine_remove_fault_once (handle, "perm_state",
      WYRELOG_E_INTERNAL);
  if (wyl_decide (handle, req, resp) != WYRELOG_E_INTERNAL)
    return 853;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_DENY)
    return 854;
  if (g_strcmp0 (wyl_decide_resp_get_deny_reason (resp),
          "perm_state_cleanup_failed") != 0)
    return 855;
  if (g_strcmp0 (wyl_decide_resp_get_deny_origin (resp), "perm_state") != 0)
    return 856;
  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_decide_returns_ok_and_deny ()) != 0)
    return rc;
  if ((rc = check_decide_rejects_null_args ()) != 0)
    return rc;
  if ((rc = check_decide_rejects_incomplete_req_as_deny ()) != 0)
    return rc;
  if ((rc = check_decide_rejects_invalid_guard_context ()) != 0)
    return rc;
  if ((rc = check_decide_allows_engine_tuple ()) != 0)
    return rc;
  if ((rc = check_decide_denies_engine_miss ()) != 0)
    return rc;
  if ((rc = check_decide_unclassified_read_denies ()) != 0)
    return rc;
  if ((rc = check_decide_allows_guarded_permission_with_context ()) != 0)
    return rc;
  if ((rc = check_decide_denies_guarded_permission_on_context_miss ()) != 0)
    return rc;
  if ((rc = check_decide_allows_self_authorize_for_system_admin ()) != 0)
    return rc;
  if ((rc = check_policy_store_replay_requires_durable_permission_state ())
      != 0)
    return rc;
  if ((rc = check_policy_store_replay_preserves_dormant_permission_state ())
      != 0)
    return rc;
  if ((rc = check_policy_store_replay_preserves_armed_permission_state ())
      != 0)
    return rc;
  if ((rc = check_persistent_permission_state_authority_matrix ()) != 0)
    return rc;
  if ((rc = check_decide_cleans_guard_facts_after_guarded_deny ()) != 0)
    return rc;
  if ((rc = check_decide_reports_state_deny_reasons ()) != 0)
    return rc;
  if ((rc = check_decide_prioritizes_guarded_blockers ()) != 0)
    return rc;
  if ((rc = check_decide_fail_closes_on_guard_cleanup_faults ()) != 0)
    return rc;
  if ((rc = check_window_guard_cleanup_fault ()) != 0)
    return rc;
  if ((rc = check_decide_evaluates_window_guard ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_injects_principal_state ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_respects_other_blockers ()) != 0)
    return rc;
  if ((rc = check_decide_human_path_unchanged_without_flag ()) != 0)
    return rc;
  if ((rc = check_decide_fail_closes_on_pstate_cleanup_fault ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_arms_data_plane_permission ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_does_not_arm_control_plane ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_ungranted_denies ()) != 0)
    return rc;
  if ((rc = check_decide_service_bearer_data_plane_respects_freeze ()) != 0)
    return rc;
  if ((rc = check_decide_fail_closes_on_perm_state_cleanup_fault ()) != 0)
    return rc;
  return 0;
}
