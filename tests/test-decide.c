/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"
#include "wyrelog/policy/store-private.h"
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

static gint
check_policy_store_replay_synthesizes_legacy_direct_grant_state (void)
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
  gint64 synthesized_row[4];
  if (intern_symbol (handle, "replay-legacy-user", &synthesized_row[0])
      != WYRELOG_E_OK)
    return 150;
  if (intern_symbol (handle, "site.replay.read", &synthesized_row[1])
      != WYRELOG_E_OK)
    return 151;
  if (intern_symbol (handle, "tenant/replay", &synthesized_row[2])
      != WYRELOG_E_OK)
    return 152;
  if (intern_symbol (handle, "armed", &synthesized_row[3]) != WYRELOG_E_OK)
    return 153;
  if (wyl_handle_engine_contains (handle, "perm_state", synthesized_row, 4,
          &contains) != WYRELOG_E_OK)
    return 154;
  if (contains)
    return 155;

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (decide_policy_store_fixture (handle, "replay-legacy-user",
          "site.replay.read", "tenant/replay", resp) != WYRELOG_E_OK)
    return 127;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 128;
  if (wyl_decide_resp_get_deny_reason (resp) != NULL)
    return 129;
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
  if ((rc = check_policy_store_replay_synthesizes_legacy_direct_grant_state ())
      != 0)
    return rc;
  if ((rc = check_policy_store_replay_preserves_dormant_permission_state ())
      != 0)
    return rc;
  if ((rc = check_policy_store_replay_preserves_armed_permission_state ())
      != 0)
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
  return 0;
}
