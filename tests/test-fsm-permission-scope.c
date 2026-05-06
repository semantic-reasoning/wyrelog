/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "wyrelog/wyl-permission-scope-private.h"
#include "wyrelog/wyl-guard-expr-private.h"
#include "wyrelog/wyl-dl-static-private.h"
#include "wyrelog/wyl-handle-private.h"

#ifndef WYL_TEST_FSM_PERMISSION_SCOPE_DL_PATH
#error "WYL_TEST_FSM_PERMISSION_SCOPE_DL_PATH must be defined by the build."
#endif

#ifndef WYL_TEST_TEMPLATE_DIR
#error "WYL_TEST_TEMPLATE_DIR must be defined by the build."
#endif

static wyrelog_error_t
intern_symbol (WylHandle *handle, const gchar *symbol, gint64 *out_id)
{
  return wyl_handle_intern_engine_symbol (handle, symbol, out_id);
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
contains_armed (WylHandle *handle, const gchar *user, const gchar *perm,
    const gchar *scope, gboolean *out_contains)
{
  gint64 row[3];
  wyrelog_error_t rc = intern_symbol (handle, user, &row[0]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, perm, &row[1]);
  if (rc != WYRELOG_E_OK)
    return rc;
  rc = intern_symbol (handle, scope, &row[2]);
  if (rc != WYRELOG_E_OK)
    return rc;
  return wyl_handle_engine_contains (handle, "armed", row, 3, out_contains);
}

/* --- Stratification self-check ---------------------------------- */

/*
 * Lifts the window guard derivation rules, the two armed/3 rules,
 * and the eval_guard host bridge fact into wyl_dl_rule_t form and
 * asserts the program is stratified.
 * The negation edge in the state-driven rule references
 * \+ perm_arm_rule, and the guarded rule goes through eval_guard /
 * context_now / guard_context. The window guard rules depend only
 * on the guard catalogue projection. No edge can close a cycle because
 * perm_arm_rule, guard_row, guard_cmp_row, guard_and_row,
 * perm_state, has_permission, context_now,
 * guard_context, guard_context_timestamp,
 * guard_context_loc_class, guard_context_risk,
 * guard_context_in_window and eval_guard are EDB-only.
 */
static gint
check_stratification (void)
{
  static const wyl_dl_body_atom_t window_direct_body[] = {
    {.predicate = "perm_arm_rule",.negated = FALSE},
    {.predicate = "guard_row",.negated = FALSE},
    {.predicate = "guard_cmp_row",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t window_and_body[] = {
    {.predicate = "perm_arm_rule",.negated = FALSE},
    {.predicate = "guard_row",.negated = FALSE},
    {.predicate = "guard_and_row",.negated = FALSE},
    {.predicate = "guard_cmp_row",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t window_observed_body[] = {
    {.predicate = "perm_window_guard",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t perm_state_step_body[] = {
    {.predicate = "perm_state_transition",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t rule1_body[] = {
    {.predicate = "perm_state",.negated = FALSE},
    {.predicate = "perm_arm_rule",.negated = TRUE},
  };
  static const wyl_dl_body_atom_t rule3_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "context_now",.negated = FALSE},
    {.predicate = "guard_context",.negated = FALSE},
    {.predicate = "guard_context_timestamp",.negated = FALSE},
    {.predicate = "guard_context_loc_class",.negated = FALSE},
    {.predicate = "guard_context_risk",.negated = FALSE},
    {.predicate = "perm_arm_rule",.negated = FALSE},
    {.predicate = "perm_window_guard",.negated = TRUE},
    {.predicate = "eval_guard",.negated = FALSE},
  };
  static const wyl_dl_body_atom_t rule4_body[] = {
    {.predicate = "has_permission",.negated = FALSE},
    {.predicate = "context_now",.negated = FALSE},
    {.predicate = "guard_context",.negated = FALSE},
    {.predicate = "guard_context_timestamp",.negated = FALSE},
    {.predicate = "guard_context_loc_class",.negated = FALSE},
    {.predicate = "guard_context_risk",.negated = FALSE},
    {.predicate = "perm_arm_rule",.negated = FALSE},
    {.predicate = "perm_window_guard",.negated = FALSE},
    {.predicate = "guard_context_in_window",.negated = FALSE},
    {.predicate = "eval_guard",.negated = FALSE},
  };
  wyl_dl_rule_t rules[] = {
    {.head = "perm_window_guard",.body = window_direct_body,.body_len =
          G_N_ELEMENTS (window_direct_body)},
    {.head = "perm_window_guard",.body = window_and_body,.body_len =
          G_N_ELEMENTS (window_and_body)},
    {.head = "perm_window_guard",.body = window_and_body,.body_len =
          G_N_ELEMENTS (window_and_body)},
    {.head = "perm_window_guard_observed",.body = window_observed_body,
        .body_len = G_N_ELEMENTS (window_observed_body)},
    {.head = "perm_state_step",.body = perm_state_step_body,.body_len =
          G_N_ELEMENTS (perm_state_step_body)},
    {.head = "armed",.body = rule1_body,.body_len = G_N_ELEMENTS (rule1_body)},
    {.head = "armed",.body = rule3_body,.body_len = G_N_ELEMENTS (rule3_body)},
    {.head = "armed",.body = rule4_body,.body_len = G_N_ELEMENTS (rule4_body)},
  };

  if (wyl_dl_static_check (rules, G_N_ELEMENTS (rules)) != WYRELOG_E_OK)
    return 1;
  return 0;
}

/* --- Catalogue size + lookup invariants ------------------------- */

static gint
check_catalogue_invariants (void)
{
  if (wyl_perm_arm_rule_count () != 11)
    return 11;
  if (wyl_perm_arm_rule_lookup (NULL) != NULL)
    return 12;
  if (wyl_perm_arm_rule_lookup ("nope.unregistered") != NULL)
    return 13;
  if (wyl_perm_arm_rule_lookup ("wr.sys.admin") == NULL)
    return 14;
  if (g_strcmp0 (wyl_guard_expr_timestamp_window (wyl_perm_arm_rule_lookup
              ("wr.stream.write_reserved")), "off_hours") != 0)
    return 15;
  if (wyl_guard_expr_timestamp_window (wyl_perm_arm_rule_lookup
          ("wr.audit.read")) != NULL)
    return 16;
  /* The accessor view of the catalogue must agree with the lookup
   * view on every row. */
  for (gsize i = 0; i < wyl_perm_arm_rule_count (); i++) {
    const gchar *id = wyl_perm_arm_rule_perm_id (i);
    if (id == NULL)
      return (gint) (15 + i);
    const wyl_guard_expr_t *via_idx = wyl_perm_arm_rule_expr (i);
    const wyl_guard_expr_t *via_lookup = wyl_perm_arm_rule_lookup (id);
    if (via_idx == NULL || via_idx != via_lookup)
      return (gint) (30 + i);
    if (wyl_guard_validate (via_idx) != WYRELOG_E_OK)
      return (gint) (50 + i);
  }
  return 0;
}

static gint
check_loc_class_contract (void)
{
  static const gchar *const valid[] = {
    "trusted",
    "semi_trusted",
    "public",
    "untrusted",
  };
  static const gchar *const invalid[] = {
    NULL,
    "",
    "unknown",
    "Trusted",
    " trusted",
    "trusted ",
  };

  for (gsize i = 0; i < G_N_ELEMENTS (valid); i++) {
    if (!wyl_guard_loc_class_is_valid (valid[i]))
      return (gint) (70 + i);
  }
  for (gsize i = 0; i < G_N_ELEMENTS (invalid); i++) {
    if (wyl_guard_loc_class_is_valid (invalid[i]))
      return (gint) (80 + i);
  }
  return 0;
}

/* --- Eval guard fixtures --------------------------------------- */

static const wyl_scope_t scope_trusted_low_risk = {
  .user = "u1",
  .timestamp = 0,
  .loc_class = "trusted",
  .risk = 10,
  .in_window = NULL,
  .in_window_user_data = NULL,
};

static const wyl_scope_t scope_public_low_risk = {
  .user = "u2",
  .timestamp = 0,
  .loc_class = "public",
  .risk = 10,
  .in_window = NULL,
  .in_window_user_data = NULL,
};

static const wyl_scope_t scope_trusted_high_risk = {
  .user = "u3",
  .timestamp = 0,
  .loc_class = "trusted",
  .risk = 90,
  .in_window = NULL,
  .in_window_user_data = NULL,
};

static gint
check_catalogue_derivation (void)
{
  /* wr.sys.admin = and(risk<30, loc_class=trusted) */
  const wyl_guard_expr_t *admin = wyl_perm_arm_rule_lookup ("wr.sys.admin");
  if (admin == NULL)
    return 70;
  if (!wyl_eval_guard (admin, &scope_trusted_low_risk))
    return 71;
  if (wyl_eval_guard (admin, &scope_public_low_risk))
    return 72;
  if (wyl_eval_guard (admin, &scope_trusted_high_risk))
    return 73;

  /* wr.audit.read = risk<70 — passes regardless of loc_class. */
  const wyl_guard_expr_t *read = wyl_perm_arm_rule_lookup ("wr.audit.read");
  if (read == NULL)
    return 74;
  if (!wyl_eval_guard (read, &scope_public_low_risk))
    return 75;
  if (wyl_eval_guard (read, &scope_trusted_high_risk))
    return 76;

  /* wr.sys.merkle_seal = loc_class=trusted — risk-agnostic. */
  const wyl_guard_expr_t *seal =
      wyl_perm_arm_rule_lookup ("wr.sys.merkle_seal");
  if (seal == NULL)
    return 77;
  if (!wyl_eval_guard (seal, &scope_trusted_high_risk))
    return 78;
  if (wyl_eval_guard (seal, &scope_public_low_risk))
    return 79;

  const wyl_guard_expr_t *stream =
      wyl_perm_arm_rule_lookup ("wr.stream.write_reserved");
  if (stream == NULL)
    return 80;
  if (wyl_eval_guard (stream, &scope_trusted_low_risk))
    return 81;
  return 0;
}

/* --- Synthetic AND/OR/NOT/nested/depth-4 fixtures --------------- */

static gint
check_synthetic_fixtures (void)
{
  /* AND fixture (depth 2). */
  g_autoptr (wyl_guard_expr_t) f_and =
      wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "30"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
          "trusted"));
  if (f_and == NULL)
    return 80;
  if (!wyl_eval_guard (f_and, &scope_trusted_low_risk))
    return 81;
  if (wyl_eval_guard (f_and, &scope_public_low_risk))
    return 82;

  /* OR fixture (depth 2). Left leg accepts risk strictly below
   * 20; right leg accepts a trusted location. */
  g_autoptr (wyl_guard_expr_t) f_or =
      wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "20"),
      wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ, "trusted"));
  if (f_or == NULL)
    return 83;
  /* risk=90 fails left, loc_class=trusted satisfies right. */
  if (!wyl_eval_guard (f_or, &scope_trusted_high_risk))
    return 84;
  /* risk=10 satisfies left, loc_class=public fails right; OR overall true. */
  if (!wyl_eval_guard (f_or, &scope_public_low_risk))
    return 85;
  /* Force a scope where both sides fail. */
  static const wyl_scope_t scope_all_fail = {
    .user = "u4",.timestamp = 0,.loc_class = "public",.risk = 90,
    .in_window = NULL,.in_window_user_data = NULL,
  };
  if (wyl_eval_guard (f_or, &scope_all_fail))
    return 86;

  /* NOT fixture (depth 2). */
  g_autoptr (wyl_guard_expr_t) f_not =
      wyl_guard_not (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_GE,
          "80"));
  if (f_not == NULL)
    return 87;
  if (!wyl_eval_guard (f_not, &scope_trusted_low_risk))
    return 88;
  if (wyl_eval_guard (f_not, &scope_trusted_high_risk))
    return 89;

  /* Nested mixed (depth 3). */
  g_autoptr (wyl_guard_expr_t) f_nested =
      wyl_guard_and (wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
              WYL_GUARD_OP_LT, "20"), wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS,
              WYL_GUARD_OP_EQ, "trusted")),
      wyl_guard_not (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_GE,
              "80")));
  if (f_nested == NULL)
    return 90;
  if (!wyl_eval_guard (f_nested, &scope_trusted_low_risk))
    return 91;
  /* high risk fails the NOT branch even with loc_class trusted. */
  if (wyl_eval_guard (f_nested, &scope_trusted_high_risk))
    return 92;

  /* Depth-4 boundary fixture. */
  g_autoptr (wyl_guard_expr_t) f_depth4 =
      wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_cmp
              (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30"),
              wyl_guard_cmp (WYL_GUARD_FIELD_LOC_CLASS, WYL_GUARD_OP_EQ,
                  "trusted")), wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
              WYL_GUARD_OP_GE, "0")), wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
          WYL_GUARD_OP_LT, "100"));
  if (f_depth4 == NULL)
    return 93;
  if (wyl_guard_validate (f_depth4) != WYRELOG_E_OK)
    return 94;
  if (wyl_guard_depth (f_depth4) != 4)
    return 95;
  if (!wyl_eval_guard (f_depth4, &scope_trusted_low_risk))
    return 96;

  /* Depth-5 negative — validator rejects before any eval would run. */
  g_autoptr (wyl_guard_expr_t) f_depth5 =
      wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_and (wyl_guard_cmp
                  (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "10"),
                  wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "20")),
              wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "30")),
          wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "40")),
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "50"));
  if (f_depth5 == NULL)
    return 97;
  if (wyl_guard_validate (f_depth5) != WYRELOG_E_POLICY)
    return 98;
  return 0;
}

/* --- in_window host injection ----------------------------------- */

typedef struct
{
  const gchar *expected_window;
  gint64 expected_ts;
  gboolean answer;
  guint calls;
} window_stub_t;

static gboolean
window_stub_cb (gint64 ts, const gchar *window_name, gpointer user_data)
{
  window_stub_t *st = (window_stub_t *) user_data;
  st->calls++;
  if (g_strcmp0 (window_name, st->expected_window) != 0)
    return FALSE;
  if (ts != st->expected_ts)
    return FALSE;
  return st->answer;
}

static gint
check_in_window_callback (void)
{
  g_autoptr (wyl_guard_expr_t) g =
      wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN, "off_hours");
  if (g == NULL)
    return 110;
  const wyl_guard_expr_t *stream =
      wyl_perm_arm_rule_lookup ("wr.stream.write_reserved");
  if (stream == NULL)
    return 116;

  /* Without a callback, the timestamp-in test fails closed. */
  wyl_scope_t no_cb = {
    .user = "u",.timestamp = 1234,.loc_class = "trusted",.risk = 0,
    .in_window = NULL,.in_window_user_data = NULL,
  };
  if (wyl_eval_guard (g, &no_cb))
    return 111;
  if (wyl_eval_guard (stream, &no_cb))
    return 117;

  /* With a callback that says yes, eval returns TRUE. */
  window_stub_t st_yes = {
    .expected_window = "off_hours",.expected_ts = 1234,
    .answer = TRUE,.calls = 0,
  };
  wyl_scope_t cb_yes = {
    .user = "u",.timestamp = 1234,.loc_class = "trusted",.risk = 0,
    .in_window = window_stub_cb,.in_window_user_data = &st_yes,
  };
  if (!wyl_eval_guard (g, &cb_yes))
    return 112;
  if (!wyl_eval_guard (stream, &cb_yes))
    return 118;
  if (st_yes.calls != 2)
    return 113;

  /* Same callback, says no. */
  window_stub_t st_no = {
    .expected_window = "off_hours",.expected_ts = 1234,
    .answer = FALSE,.calls = 0,
  };
  wyl_scope_t cb_no = {
    .user = "u",.timestamp = 1234,.loc_class = "trusted",.risk = 0,
    .in_window = window_stub_cb,.in_window_user_data = &st_no,
  };
  if (wyl_eval_guard (g, &cb_no))
    return 114;
  if (wyl_eval_guard (stream, &cb_no))
    return 119;
  if (st_no.calls != 2)
    return 115;
  return 0;
}

static gint
check_timestamp_window_extraction (void)
{
  g_autoptr (wyl_guard_expr_t) direct =
      wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN, "off_hours");
  if (direct == NULL)
    return 120;
  if (g_strcmp0 (wyl_guard_expr_timestamp_window (direct), "off_hours") != 0)
    return 121;

  g_autoptr (wyl_guard_expr_t) and_one =
      wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT,
          "50"), wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN,
          "off_hours"));
  if (and_one == NULL)
    return 122;
  if (g_strcmp0 (wyl_guard_expr_timestamp_window (and_one), "off_hours") != 0)
    return 123;

  g_autoptr (wyl_guard_expr_t) and_same =
      wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP,
          WYL_GUARD_OP_IN, "off_hours"), wyl_guard_cmp
      (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN, "off_hours"));
  if (and_same == NULL)
    return 124;
  if (g_strcmp0 (wyl_guard_expr_timestamp_window (and_same), "off_hours") != 0)
    return 125;

  g_autoptr (wyl_guard_expr_t) risk_only =
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "50");
  if (risk_only == NULL)
    return 139;
  if (wyl_guard_expr_timestamp_window (risk_only) != NULL)
    return 140;

  g_autoptr (wyl_guard_expr_t) timestamp_order =
      wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_LT, "1234");
  if (timestamp_order == NULL)
    return 141;
  if (wyl_guard_expr_timestamp_window (timestamp_order) != NULL)
    return 142;

  g_autoptr (wyl_guard_expr_t) and_conflict =
      wyl_guard_and (wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP,
          WYL_GUARD_OP_IN, "off_hours"), wyl_guard_cmp
      (WYL_GUARD_FIELD_TIMESTAMP, WYL_GUARD_OP_IN, "office_hours"));
  if (and_conflict == NULL)
    return 126;
  if (wyl_guard_expr_timestamp_window (and_conflict) != NULL)
    return 127;

  g_autoptr (wyl_guard_expr_t) disjunctive =
      wyl_guard_or (wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP,
          WYL_GUARD_OP_IN, "off_hours"), wyl_guard_cmp (WYL_GUARD_FIELD_RISK,
          WYL_GUARD_OP_LT, "50"));
  if (disjunctive == NULL)
    return 128;
  if (wyl_guard_expr_timestamp_window (disjunctive) != NULL)
    return 129;

  g_autoptr (wyl_guard_expr_t) negated =
      wyl_guard_not (wyl_guard_cmp (WYL_GUARD_FIELD_TIMESTAMP,
          WYL_GUARD_OP_IN, "off_hours"));
  if (negated == NULL)
    return 135;
  if (wyl_guard_expr_timestamp_window (negated) != NULL)
    return 136;

  g_autoptr (wyl_guard_expr_t) tag = wyl_guard_tag ("break_glass");
  if (tag == NULL)
    return 137;
  if (wyl_guard_expr_timestamp_window (tag) != NULL)
    return 138;

  return 0;
}

/* --- Argument validation ---------------------------------------- */

static gint
check_argument_validation (void)
{
  const wyl_scope_t s = {.loc_class = "trusted",.risk = 0 };
  if (wyl_eval_guard (NULL, &s))
    return 130;
  g_autoptr (wyl_guard_expr_t) e =
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "10");
  if (wyl_eval_guard (e, NULL))
    return 131;
  /* Tag node is always FALSE in v0. */
  g_autoptr (wyl_guard_expr_t) t = wyl_guard_tag ("anything");
  if (wyl_eval_guard (t, &s))
    return 132;
  /* Tenant cmp is reserved for tenant-scoped policy wiring; v0 fails closed. */
  g_autoptr (wyl_guard_expr_t) tenant_cmp =
      wyl_guard_cmp (WYL_GUARD_FIELD_TENANT, WYL_GUARD_OP_EQ, "anything");
  if (wyl_eval_guard (tenant_cmp, &s))
    return 133;
  /* Malformed risk value is rejected. */
  g_autoptr (wyl_guard_expr_t) bad_value =
      wyl_guard_cmp (WYL_GUARD_FIELD_RISK, WYL_GUARD_OP_LT, "not-a-number");
  if (wyl_eval_guard (bad_value, &s))
    return 134;
  return 0;
}

/* --- .dl static fact guard -------------------------------------- */

/*
 * perm_arm_rule rows are runtime-seeded from the C catalogue. The
 * template may declare and reference the relation, but it must not
 * also carry static facts; otherwise runtime seeding produces
 * duplicate placeholder rows before guard payload handles are
 * introduced.
 */
static gboolean
line_is_static_perm_arm_rule_fact (const gchar *line)
{
  const gchar *prefix = "perm_arm_rule";
  if (!g_str_has_prefix (line, prefix))
    return FALSE;
  const gchar *p = line + strlen (prefix);
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != '(')
    return FALSE;
  p++;
  while (*p == ' ' || *p == '\t')
    p++;
  return *p == '"';
}

static gboolean
line_is_static_perm_state_transition_fact (const gchar *line)
{
  const gchar *prefix = "perm_state_transition";
  if (!g_str_has_prefix (line, prefix))
    return FALSE;
  const gchar *p = line + strlen (prefix);
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != '(')
    return FALSE;
  p++;
  while (*p == ' ' || *p == '\t')
    p++;
  return *p == '"';
}

static gint
check_template_static_fact_guards (void)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  g_autoptr (GError) err = NULL;
  if (!g_file_get_contents (WYL_TEST_FSM_PERMISSION_SCOPE_DL_PATH,
          &contents, &len, &err)) {
    g_printerr ("cannot read %s: %s\n",
        WYL_TEST_FSM_PERMISSION_SCOPE_DL_PATH, err ? err->message : "?");
    return 200;
  }
  g_auto (GStrv) lines = g_strsplit (contents, "\n", -1);
  for (gsize i = 0; lines[i] != NULL; i++) {
    g_autofree gchar *trimmed = g_strdup (g_strchug (lines[i]));
    if (trimmed[0] == '%' || trimmed[0] == '\0'
        || g_str_has_prefix (trimmed, "//")
        || g_str_has_prefix (trimmed, ".decl"))
      continue;
    if (line_is_static_perm_arm_rule_fact (trimmed))
      return 210;
    if (line_is_static_perm_state_transition_fact (trimmed))
      return 211;
  }
  return 0;
}

static void
count_rows_cb (const gchar *relation, const gint64 *row, guint ncols,
    gpointer user_data)
{
  guint *count = user_data;

  (void) relation;
  (void) row;
  (void) ncols;

  (*count)++;
}

static gint
check_perm_state_transition_schema_only (void)
{
  g_autoptr (WylHandle) handle = NULL;
  if (wyl_init (WYL_TEST_TEMPLATE_DIR, &handle) != WYRELOG_E_OK)
    return 220;

  static const gchar *relations[] = {
    "perm_state_transition",
    "perm_state_step",
  };
  for (gsize i = 0; i < G_N_ELEMENTS (relations); i++) {
    guint count = 0;
    if (wyl_engine_snapshot (wyl_handle_get_read_engine (handle),
            relations[i], count_rows_cb, &count) != WYRELOG_E_OK)
      return (gint) (221 + i);
    if (count != 0)
      return (gint) (230 + i);
  }

  if (insert_symbol_row4 (handle, "perm_state", "schema-user",
          "schema-perm", "schema-scope", "armed") != WYRELOG_E_OK)
    return 240;
  gboolean found = FALSE;
  if (contains_armed (handle, "schema-user", "schema-perm", "schema-scope",
          &found) != WYRELOG_E_OK)
    return 241;
  if (!found)
    return 242;

  if (insert_symbol_row4 (handle, "perm_state", "schema-guard-user",
          "wr.audit.read", "schema-guard-scope", "armed") != WYRELOG_E_OK)
    return 243;
  if (contains_armed (handle, "schema-guard-user", "wr.audit.read",
          "schema-guard-scope", &found) != WYRELOG_E_OK)
    return 244;
  if (found)
    return 245;

  return 0;
}

int
main (void)
{
  gint rc;
  if ((rc = check_stratification ()) != 0)
    return rc;
  if ((rc = check_catalogue_invariants ()) != 0)
    return rc;
  if ((rc = check_loc_class_contract ()) != 0)
    return rc;
  if ((rc = check_catalogue_derivation ()) != 0)
    return rc;
  if ((rc = check_synthetic_fixtures ()) != 0)
    return rc;
  if ((rc = check_in_window_callback ()) != 0)
    return rc;
  if ((rc = check_timestamp_window_extraction ()) != 0)
    return rc;
  if ((rc = check_argument_validation ()) != 0)
    return rc;
  if ((rc = check_template_static_fact_guards ()) != 0)
    return rc;
  if ((rc = check_perm_state_transition_schema_only ()) != 0)
    return rc;
  return 0;
}
