/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>

#include "wyrelog/wyrelog.h"

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

/*
 * Decide-path coverage for the break-glass override surface.
 * Compiled only when both enable_break_glass and enable_audit are on
 * since the override path requires the audit conn for its arming
 * trail; the meson registration mirrors that gate.
 */

#if defined(WYL_HAS_BREAK_GLASS) && defined(WYL_HAS_AUDIT)

#include "access/break-glass-private.h"
#include "wyl-handle-private.h"

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
seed_armed_allow_fixture (WylHandle *handle, const gchar *subject,
    const gchar *action, const gchar *resource)
{
  wyrelog_error_t rc = insert_symbol_row2 (handle, "role_permission",
      "wr.decide-role", action);
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
  return insert_symbol_row4 (handle, "perm_state", subject, action, resource,
      "armed");
}

static gint
check_decide_marks_break_glass_used_when_armed (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 10;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 11;
  if (seed_armed_allow_fixture (handle, "bg-decide-user-1",
          "wr.decide-permission-1", "bg-decide-resource-1") != WYRELOG_E_OK)
    return 12;

  if (wyl_handle_break_glass_has_been_used (handle))
    return 13;
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60) != WYRELOG_E_OK)
    return 14;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 15;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "bg-decide-user-1");
  wyl_decide_req_set_action (req, "wr.decide-permission-1");
  wyl_decide_req_set_resource_id (req, "bg-decide-resource-1");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 16;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 17;
  if (!wyl_handle_break_glass_has_been_used (handle))
    return 18;
  if (!wyl_handle_break_glass_is_active (handle))
    return 19;

  /* A second decide on the same activation keeps the used bit
   * latched (no clear-and-reset semantics until disarm). */
  g_autoptr (wyl_decide_resp_t) resp2 = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp2) != WYRELOG_E_OK)
    return 20;
  if (!wyl_handle_break_glass_has_been_used (handle))
    return 21;
  return 0;
}

static gint
check_decide_does_not_mark_when_inactive (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 30;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 31;
  if (seed_armed_allow_fixture (handle, "bg-decide-user-2",
          "wr.decide-permission-2", "bg-decide-resource-2") != WYRELOG_E_OK)
    return 32;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "bg-decide-user-2");
  wyl_decide_req_set_action (req, "wr.decide-permission-2");
  wyl_decide_req_set_resource_id (req, "bg-decide-resource-2");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 33;
  if (wyl_decide_resp_get_decision (resp) != WYL_DECISION_ALLOW)
    return 34;
  /* Without an arming, the used bit remains FALSE through decide. */
  if (wyl_handle_break_glass_has_been_used (handle))
    return 35;
  return 0;
}

static gint
check_disarm_clears_used_and_active (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 40;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 41;
  if (seed_armed_allow_fixture (handle, "bg-decide-user-3",
          "wr.decide-permission-3", "bg-decide-resource-3") != WYRELOG_E_OK)
    return 42;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_POLICY_CORRUPTION, 60) != WYRELOG_E_OK)
    return 43;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "bg-decide-user-3");
  wyl_decide_req_set_action (req, "wr.decide-permission-3");
  wyl_decide_req_set_resource_id (req, "bg-decide-resource-3");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 44;
  if (!wyl_handle_break_glass_has_been_used (handle))
    return 45;

  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 46;
  if (wyl_handle_break_glass_is_active (handle))
    return 47;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 48;
  return 0;
}

static gint
check_ttl_expiry_disarm_and_rearm (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 70;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 71;
  if (seed_armed_allow_fixture (handle, "bg-decide-user-4",
          "wr.decide-permission-4", "bg-decide-resource-4") != WYRELOG_E_OK)
    return 72;

  /* Arm with a 1-second per-arm TTL. The host-side gate
   * wyl_handle_break_glass_is_active applies this operator TTL, so
   * a g_usleep past the horizon flips the gate to FALSE long before
   * the 900-second DL self-disable horizon would fire. */
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 1) != WYRELOG_E_OK)
    return 73;
  if (!wyl_handle_break_glass_is_active (handle))
    return 74;

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "bg-decide-user-4");
  wyl_decide_req_set_action (req, "wr.decide-permission-4");
  wyl_decide_req_set_resource_id (req, "bg-decide-resource-4");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) != WYRELOG_E_OK)
    return 75;
  if (!wyl_handle_break_glass_has_been_used (handle))
    return 76;

  /* Sleep past the 1-second TTL and verify the host-side gate
   * reports the activation has expired. */
  g_usleep (G_USEC_PER_SEC + (G_USEC_PER_SEC / 2));
  if (wyl_handle_break_glass_is_active (handle))
    return 77;

  /* Disarm is idempotent against an in-memory activation that has
   * already passed its operator-TTL: the call still succeeds and
   * tears the activation flag down so a subsequent arm starts from
   * a clean slate. */
  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 78;
  if (wyl_handle_break_glass_is_active (handle))
    return 79;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 80;

  /* Re-arm with a fresh TTL and confirm the new activation is live;
   * the prior expiry must not bleed into the new window. */
  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60) != WYRELOG_E_OK)
    return 81;
  if (!wyl_handle_break_glass_is_active (handle))
    return 82;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 83;
  return 0;
}

static gint
check_decide_fact_insert_failure_does_not_latch_used (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 90;
  if (wyl_handle_open_engine_pair (handle, WYL_TEST_TEMPLATE_DIR)
      != WYRELOG_E_OK)
    return 91;
  if (seed_armed_allow_fixture (handle, "bg-decide-user-5",
          "wr.decide-permission-5", "bg-decide-resource-5") != WYRELOG_E_OK)
    return 92;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_INCIDENT_RESPONSE, 60) != WYRELOG_E_OK)
    return 93;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 94;

  /* Trip the next "now" insert so insert_break_glass_facts() returns
   * non-OK before the engine_decide call. wyl_decide must propagate
   * the failure and bypass both the audit-emit block and the
   * mark-used latch: the audit-then-mark invariant requires that a
   * decide which fails before audit commits leaves the used bit
   * exactly as it was. */
  wyl_handle_set_engine_insert_fault_once (handle, "now", WYRELOG_E_INVALID);

  g_autoptr (wyl_decide_req_t) req = wyl_decide_req_new ();
  wyl_decide_req_set_subject_id (req, "bg-decide-user-5");
  wyl_decide_req_set_action (req, "wr.decide-permission-5");
  wyl_decide_req_set_resource_id (req, "bg-decide-resource-5");

  g_autoptr (wyl_decide_resp_t) resp = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp) == WYRELOG_E_OK)
    return 95;
  if (wyl_handle_break_glass_has_been_used (handle))
    return 96;

  /* The activation itself remains intact: only the per-decide fact
   * injection failed. A follow-up decide with no fault hook armed
   * must succeed and now latch the used bit. */
  g_autoptr (wyl_decide_resp_t) resp2 = wyl_decide_resp_new ();
  if (wyl_decide (handle, req, resp2) != WYRELOG_E_OK)
    return 97;
  if (!wyl_handle_break_glass_has_been_used (handle))
    return 98;
  return 0;
}

static gint
check_arm_writes_audit_row (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (NULL, &handle) != WYRELOG_E_OK)
    return 50;

  if (wyl_handle_break_glass_arm (handle,
          WYL_BREAK_GLASS_REASON_SECURITY_OFFICER_LOCKOUT, 60) != WYRELOG_E_OK)
    return 51;

  wyl_audit_conn_t *conn = wyl_handle_get_audit_conn (handle);
  g_autofree gchar *arm_json = NULL;
  if (wyl_audit_conn_query_events_json (conn,
          "action(\"break_glass_arm\")", &arm_json) != WYRELOG_E_OK)
    return 52;
  if (g_strstr_len (arm_json, -1, "\"action\":\"break_glass_arm\"") == NULL)
    return 53;
  if (g_strstr_len (arm_json, -1, "\"resource_id\":\"wr.break_glass\"")
      == NULL)
    return 54;
  if (g_strstr_len (arm_json, -1,
          "\"deny_reason\":\"security_officer_lockout\"") == NULL)
    return 55;
  if (g_strstr_len (arm_json, -1, "\"deny_origin\":\"break_glass\"") == NULL)
    return 56;
  if (g_strstr_len (arm_json, -1, "\"decision\":1") == NULL)
    return 57;

  if (wyl_handle_break_glass_disarm (handle) != WYRELOG_E_OK)
    return 58;

  g_autofree gchar *disarm_json = NULL;
  if (wyl_audit_conn_query_events_json (conn,
          "action(\"break_glass_disarm\")", &disarm_json) != WYRELOG_E_OK)
    return 59;
  if (g_strstr_len (disarm_json, -1, "\"action\":\"break_glass_disarm\"")
      == NULL)
    return 60;
  if (g_strstr_len (disarm_json, -1, "\"resource_id\":\"wr.break_glass\"")
      == NULL)
    return 61;
  if (g_strstr_len (disarm_json, -1, "\"deny_origin\":\"break_glass\"")
      == NULL)
    return 62;
  return 0;
}

#endif /* WYL_HAS_BREAK_GLASS && WYL_HAS_AUDIT */

int
main (void)
{
#if defined(WYL_HAS_BREAK_GLASS) && defined(WYL_HAS_AUDIT)
  gint rc;
  if ((rc = check_decide_marks_break_glass_used_when_armed ()) != 0)
    return rc;
  if ((rc = check_decide_does_not_mark_when_inactive ()) != 0)
    return rc;
  if ((rc = check_disarm_clears_used_and_active ()) != 0)
    return rc;
  if ((rc = check_ttl_expiry_disarm_and_rearm ()) != 0)
    return rc;
  if ((rc = check_decide_fact_insert_failure_does_not_latch_used ()) != 0)
    return rc;
  if ((rc = check_arm_writes_audit_row ()) != 0)
    return rc;
#endif
  return 0;
}
