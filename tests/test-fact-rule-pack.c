/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>
#include <string.h>

#include "wyrelog/fact/rule-pack-private.h"

#define SHOP "w_73_68_6f_70_"
#define SHOP_ORDERS SHOP "w_6f_72_64_65_72_73"
#define SHOP_CUSTOMERS SHOP "w_63_75_73_74_6f_6d_65_72_73"
#define SHOP_BIG SHOP "w_62_69_67"
#define SHOP_QUIET SHOP "w_71_75_69_65_74"
#define SHOP_VIP SHOP "w_76_69_70"
#define SHOP_LABEL SHOP "w_6c_61_62_65_6c"
#define SHOP_TEXT SHOP "w_74_65_78_74"

static const wyl_policy_fact_relation_schema_column_t orders_cols[] = {
  {"order_id", "symbol", FALSE, TRUE},
  {"amount", "int64", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t customers_cols[] = {
  {"customer_id", "symbol", FALSE, TRUE},
  {"vip", "bool", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t one_symbol[] = {
  {"id", "symbol", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t one_string[] = {
  {"s", "string", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t one_int[] = {
  {"n", "int64", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t one_compound[] = {
  {"r", "compound_ref", FALSE, TRUE},
};
static const wyl_policy_fact_relation_schema_column_t ref_cols[] = {
  {"r", "compound_ref", FALSE, TRUE},
  {"n", "int64", FALSE, TRUE},
};

#define REL(ns, name, cols) {ns, name, cols, G_N_ELEMENTS (cols)}

static const wyl_fact_graph_program_relation_t relations[] = {
  REL ("shop", "orders", orders_cols),
  REL ("shop", "customers", customers_cols),
  REL ("shop", "big", one_symbol),
  REL ("shop", "quiet", one_symbol),
  REL ("shop", "vip", one_symbol),
  REL ("shop", "label", one_symbol),
  REL ("shop", "text", one_string),
  REL ("shop", "amounts", one_int),
  REL ("shop", "ref", ref_cols),
  REL ("shop", "cref", one_compound),
  REL ("crm", "cref2", one_compound),
  REL ("shop", "a", one_symbol),
  REL ("shop", "b", one_symbol),
  REL ("shop", "c", one_symbol),
  REL ("crm", "orders", one_symbol),
  REL ("x", "y.z", one_symbol),
  REL ("x.y", "z", one_symbol),
  REL ("m", "p:-q", one_symbol),
};

static gchar *
accept (const gchar *text)
{
  gchar *rules = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  wyrelog_error_t rc = wyl_fact_rule_pack_compile (text, strlen (text),
          relations, G_N_ELEMENTS (relations), &rules, &rejection);
  if (rc != WYRELOG_E_OK)
    g_test_message ("refused: %s rule=%u atom=%u",
        wyl_fact_rule_pack_reject_name (rejection.reason),
        rejection.rule_index, rejection.atom_index);
  g_assert_cmpint (rc, ==, WYRELOG_E_OK);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NONE);
  wyl_fact_rule_pack_rejection_clear (&rejection);
  return rules;
}

static void
assert_refused_len (const gchar *text, gsize len,
    wyl_fact_rule_pack_reject_t reason, guint rule_index, guint atom_index)
{
  gchar *rules = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  wyrelog_error_t rc = wyl_fact_rule_pack_compile (text, len, relations,
          G_N_ELEMENTS (relations), &rules, &rejection);
  g_assert_cmpint (rc, ==, WYRELOG_E_POLICY);
  g_assert_null (rules);
  g_assert_cmpstr (wyl_fact_rule_pack_reject_name (rejection.reason), ==,
      wyl_fact_rule_pack_reject_name (reason));
  g_assert_cmpuint (rejection.rule_index, ==, rule_index);
  g_assert_cmpuint (rejection.atom_index, ==, atom_index);
  wyl_fact_rule_pack_rejection_clear (&rejection);
}

static void
assert_refused (const gchar *text, wyl_fact_rule_pack_reject_t reason,
    guint rule_index, guint atom_index)
{
  assert_refused_len (text, strlen (text), reason, rule_index, atom_index);
}

static void
test_accept_renders_encoded_rules (void)
{
  g_autofree gchar *rules = accept ("shop.big(O) :- shop.orders(O, _).\n");
  g_assert_cmpstr (rules, ==,
      SHOP_BIG "(V0) :- " SHOP_ORDERS "(V0, _).\n");
}

/* Comments, blank lines, an unqualified name, a later rule reading an earlier
 * head, constants of every kind, and a negated atom over a base relation: the
 * last is the case that keeps the acyclicity check from refusing negation. */
static void
test_accept_pack_with_negation (void)
{
  g_autofree gchar *rules = accept ("# derived order sets\n"
          "\n"
          "vip(O) :- shop.orders(O, Amount), customers(O, true).  # trailing\n"
          "shop.quiet(Order) :- shop.orders(Order, _),"
          " !customers(Order, _).\r\n"
          "   big(O):-vip(O),shop.orders(O,-42),customers(O,false).");
  g_assert_cmpstr (rules, ==,
      SHOP_VIP "(V0) :- " SHOP_ORDERS "(V0, V1), " SHOP_CUSTOMERS
      "(V0, 1).\n"
      SHOP_QUIET "(V0) :- " SHOP_ORDERS "(V0, _), !" SHOP_CUSTOMERS
      "(V0, _).\n"
      SHOP_BIG "(V0) :- " SHOP_VIP "(V0), " SHOP_ORDERS "(V0, -42), "
      SHOP_CUSTOMERS "(V0, 0).\n");
}

static void
test_accept_escapes_string_constants (void)
{
  g_autofree gchar *rules =
      accept ("label(S) :- text(S), text(\"q\\\"x\\\\y caf\xc3\xa9\").\n");
  g_assert_cmpstr (rules, ==,
      SHOP_LABEL "(V0) :- " SHOP_TEXT "(V0), " SHOP_TEXT
      "(\"q\\\"x\\\\y caf\xc3\xa9\").\n");
}

static void
test_accept_extreme_integers_and_odd_names (void)
{
  g_autofree gchar *rules =
      accept ("amounts(N) :- shop.orders(_, N),"
          " shop.orders(_, -9223372036854775808),"
          " shop.orders(_, 9223372036854775807).\n"
          "m.p:-q(X) :- shop.big(X).\n");
  g_assert_cmpstr (rules, ==,
      SHOP "w_61_6d_6f_75_6e_74_73(V0) :- " SHOP_ORDERS "(_, V0), "
      SHOP_ORDERS "(_, -9223372036854775808), "
      SHOP_ORDERS "(_, 9223372036854775807).\n"
      "w_6d_w_70_3a_2d_71(V0) :- " SHOP_BIG "(V0).\n");
}

/* symbol and string share a class; the head reads a string column. */
static void
test_accept_symbol_string_class (void)
{
  g_autofree gchar *rules = accept ("label(S) :- text(S).");
  g_assert_cmpstr (rules, ==, SHOP_LABEL "(V0) :- " SHOP_TEXT "(V0).\n");
}

/* A compound variable may move between relations of one namespace. */
static void
test_accept_compound_within_namespace (void)
{
  g_autofree gchar *rules = accept ("shop.cref(R) :- shop.ref(R, _).");
  g_assert_cmpstr (rules, ==,
      SHOP "w_63_72_65_66(V0) :- " SHOP "w_72_65_66(V0, _).\n");
}

static void
test_accept_empty_pack (void)
{
  g_autofree gchar *rules = accept ("# nothing yet\n\n");
  g_assert_cmpstr (rules, ==, "");
}

static void
test_refuse_size_limits (void)
{
  g_autoptr (GString) big = g_string_new (NULL);
  while (big->len <= WYL_FACT_RULE_PACK_MAX_BYTES)
    g_string_append (big, "# padding padding padding padding padding\n");
  assert_refused_len (big->str, big->len, WYL_FACT_RULE_PACK_REJECT_TOO_LARGE,
      0, 0);

  g_autoptr (GString) many = g_string_new (NULL);
  for (guint i = 0; i <= WYL_FACT_RULE_PACK_MAX_RULES; i++)
    g_string_append (many, "big(O) :- shop.orders(O, _).\n");
  assert_refused (many->str, WYL_FACT_RULE_PACK_REJECT_TOO_MANY_RULES,
      WYL_FACT_RULE_PACK_MAX_RULES + 1, 0);

  g_autoptr (GString) wide = g_string_new ("big(O) :- shop.orders(O, _).\n"
          "big(O) :- shop.orders(O, _)");
  for (guint i = 1; i < WYL_FACT_RULE_PACK_MAX_BODY_ATOMS; i++)
    g_string_append (wide, ", shop.orders(O, _)");
  g_autofree gchar *at_limit = g_strconcat (wide->str, ".\n", NULL);
  g_autofree gchar *limit_rules = accept (at_limit);
  g_string_append (wide, ", shop.orders(O, _).\n");
  assert_refused (wide->str, WYL_FACT_RULE_PACK_REJECT_TOO_MANY_BODY_ATOMS, 2,
      WYL_FACT_RULE_PACK_MAX_BODY_ATOMS + 1);
}

static void
test_refuse_syntax (void)
{
  const gchar *ok = "big(O) :- shop.orders(O, _).\n";
  const struct
  {
    const gchar *rule;
    guint atom;
  } cases[] = {
    {"big(O) shop.orders(O, _).", 0},
    {"big(O) :- shop.orders(O, _)", 1},
    {"big(O) :- shop.orders(O, _). big(O) :- shop.orders(O, _).", 1},
    {"big(O) :-\n shop.orders(O, _).", 1},
    {"big(o) :- shop.orders(o, _).", 0},
    {"big(O) :- .", 1},
    {"big(O).", 0},
    {"!big(O) :- shop.orders(O, _).", 0},
    {"big() :- shop.orders(O, _).", 0},
    {"big(O) :- shop.orders(O, _),.", 2},
    {"big(O) :- shop.orders(O, \"a\\n\").", 1},
    {"big(O) :- shop.orders(O, \"open).", 1},
    {"big(O) :- shop.orders(O, _) # mid-rule comment.", 1},
    {"big(O) :- shop.orders(O, 12x).", 1},
    {"big(O) :- shop.orders(O, _abc).", 1},
    {"big(O) :- shop.orders(O, _). trailing", 1},
    {"big(O) :- shop.orders(O, A > 1).", 1},
  };
  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++) {
    g_autofree gchar *text = g_strconcat (ok, cases[i].rule, "\n", ok, NULL);
    g_test_message ("case %" G_GSIZE_FORMAT ": %s", i, cases[i].rule);
    assert_refused (text, WYL_FACT_RULE_PACK_REJECT_SYNTAX, 2, cases[i].atom);
  }

  const gchar embedded_nul[] = "big(O) :- shop.orders(O, _).\0\n";
  assert_refused_len (embedded_nul, sizeof (embedded_nul) - 1,
      WYL_FACT_RULE_PACK_REJECT_SYNTAX, 1, 1);
}

static void
test_refuse_invalid_constants (void)
{
  assert_refused ("big(O) :- shop.orders(O, 9223372036854775808).",
      WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT, 1, 1);
  assert_refused ("big(O) :- shop.orders(O, -9223372036854775809).",
      WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT, 1, 1);
  assert_refused ("label(S) :- text(S), text(\"a\tb\").",
      WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT, 1, 2);
  assert_refused ("label(S) :- text(S), text(\"a\x7f\").",
      WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT, 1, 2);
  assert_refused ("label(S) :- text(S), text(\"\xc3\x28\").",
      WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT, 1, 2);
}

static void
test_refuse_relations_and_arity (void)
{
  assert_refused ("shop.nope(O) :- shop.orders(O, _).",
      WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION, 1, 0);
  assert_refused ("big(O) :- shop.orders(O, _), shop.nope(O).",
      WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION, 1, 2);
  /* The namespace is not a relation name, and a relation name is not
   * matched against another namespace. */
  assert_refused ("big(O) :- crm.customers(O, _).",
      WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION, 1, 1);
  assert_refused ("big(O) :- orders(O, _).",
      WYL_FACT_RULE_PACK_REJECT_AMBIGUOUS_RELATION, 1, 1);
  assert_refused ("big(O) :- x.y.z(O).",
      WYL_FACT_RULE_PACK_REJECT_AMBIGUOUS_RELATION, 1, 1);
  assert_refused ("big(O, A) :- shop.orders(O, A).",
      WYL_FACT_RULE_PACK_REJECT_ARITY, 1, 0);
  assert_refused ("big(O) :- shop.orders(O).",
      WYL_FACT_RULE_PACK_REJECT_ARITY, 1, 1);
}

static void
test_refuse_head_wildcard (void)
{
  assert_refused ("big(_) :- shop.orders(_, _).",
      WYL_FACT_RULE_PACK_REJECT_HEAD_WILDCARD, 1, 0);
}

static void
test_refuse_unsafe_variables (void)
{
  assert_refused ("big(X) :- shop.orders(O, _).",
      WYL_FACT_RULE_PACK_REJECT_UNSAFE_HEAD_VARIABLE, 1, 0);
  /* Occurring under negation does not bind a variable. */
  assert_refused ("big(X) :- shop.orders(O, _), !customers(X, _).",
      WYL_FACT_RULE_PACK_REJECT_UNSAFE_HEAD_VARIABLE, 1, 0);
  assert_refused ("big(O) :- shop.orders(O, _), !customers(C, true).",
      WYL_FACT_RULE_PACK_REJECT_UNSAFE_NEGATED_VARIABLE, 1, 2);
}

static void
test_refuse_type_mismatch (void)
{
  /* int64 into a symbol head. */
  assert_refused ("big(A) :- shop.orders(_, A).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  /* compound_ref and int64 share only a wire representation. */
  assert_refused ("amounts(R) :- shop.ref(R, _).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  assert_refused ("amounts(N) :- shop.ref(_, N), shop.ref(N, _).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 2);
  /* bool and int64 likewise. */
  assert_refused ("big(O) :- customers(O, 1).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  assert_refused ("big(O) :- shop.orders(O, true).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  assert_refused ("big(O) :- shop.orders(O, \"1\").",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  assert_refused ("big(O) :- shop.orders(O, _), big(7).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 2);
  /* Compound handles are shared only within a namespace. */
  assert_refused ("crm.cref2(R) :- shop.ref(R, _).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
  assert_refused ("shop.cref(R) :- shop.ref(R, _), crm.cref2(R).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 2);
  /* No constant names a compound handle. */
  assert_refused ("amounts(N) :- shop.ref(1, N).",
      WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH, 1, 1);
}

static void
test_refuse_cycles (void)
{
  const gchar *text = "big(O) :- shop.orders(O, _).\n"
      "shop.a(X) :- shop.b(X).\n"
      "shop.b(X) :- shop.a(X), big(X).\n"
      "shop.c(X) :- shop.c(X).\n"
      "label(X) :- shop.a(X).\n";
  gchar *rules = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile (text, strlen (text), relations,
      G_N_ELEMENTS (relations), &rules, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_null (rules);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_CYCLE);
  g_assert_cmpuint (rejection.rule_index, ==, 2);
  g_assert_cmpuint (rejection.n_cycle_rules, ==, 3);
  g_assert_cmpuint (rejection.cycle_rules[0], ==, 2);
  g_assert_cmpuint (rejection.cycle_rules[1], ==, 3);
  g_assert_cmpuint (rejection.cycle_rules[2], ==, 4);
  wyl_fact_rule_pack_rejection_clear (&rejection);
  g_assert_null (rejection.cycle_rules);

  /* A cycle through negation is a cycle. */
  assert_refused ("big(X) :- shop.orders(X, _), !big(X).",
      WYL_FACT_RULE_PACK_REJECT_CYCLE, 1, 0);
}

static void
test_invalid_arguments (void)
{
  gchar *rules = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile (NULL, 0, relations, 1, &rules,
      &rejection), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_rule_pack_compile ("", 0, NULL, 1, &rules,
      &rejection), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_rule_pack_compile ("", 0, relations, 1, NULL,
      &rejection), ==, WYRELOG_E_INVALID);
  g_assert_cmpint (wyl_fact_rule_pack_compile ("", 0, relations, 1, &rules,
      NULL), ==, WYRELOG_E_INVALID);
  g_assert_null (rules);
}

static void
test_reason_names (void)
{
  g_assert_cmpstr (wyl_fact_rule_pack_reject_name
        (WYL_FACT_RULE_PACK_REJECT_CYCLE), ==, "rule_pack_cycle");
  g_assert_cmpstr (wyl_fact_rule_pack_reject_name
        (WYL_FACT_RULE_PACK_REJECT_UNSAFE_NEGATED_VARIABLE), ==,
      "rule_pack_unsafe_negated_variable");
  for (gint r = WYL_FACT_RULE_PACK_REJECT_NONE;
      r <= WYL_FACT_RULE_PACK_REJECT_COMPILE; r++)
    g_assert_nonnull (wyl_fact_rule_pack_reject_name (r));
  g_assert_null (wyl_fact_rule_pack_reject_name
        (WYL_FACT_RULE_PACK_REJECT_COMPILE + 1));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/rule-pack/accept/rendered",
      test_accept_renders_encoded_rules);
  g_test_add_func ("/fact/rule-pack/accept/negation",
      test_accept_pack_with_negation);
  g_test_add_func ("/fact/rule-pack/accept/escapes",
      test_accept_escapes_string_constants);
  g_test_add_func ("/fact/rule-pack/accept/extremes",
      test_accept_extreme_integers_and_odd_names);
  g_test_add_func ("/fact/rule-pack/accept/symbol-string",
      test_accept_symbol_string_class);
  g_test_add_func ("/fact/rule-pack/accept/compound",
      test_accept_compound_within_namespace);
  g_test_add_func ("/fact/rule-pack/accept/empty", test_accept_empty_pack);
  g_test_add_func ("/fact/rule-pack/refuse/limits", test_refuse_size_limits);
  g_test_add_func ("/fact/rule-pack/refuse/syntax", test_refuse_syntax);
  g_test_add_func ("/fact/rule-pack/refuse/constants",
      test_refuse_invalid_constants);
  g_test_add_func ("/fact/rule-pack/refuse/relations",
      test_refuse_relations_and_arity);
  g_test_add_func ("/fact/rule-pack/refuse/head-wildcard",
      test_refuse_head_wildcard);
  g_test_add_func ("/fact/rule-pack/refuse/unsafe",
      test_refuse_unsafe_variables);
  g_test_add_func ("/fact/rule-pack/refuse/types", test_refuse_type_mismatch);
  g_test_add_func ("/fact/rule-pack/refuse/cycles", test_refuse_cycles);
  g_test_add_func ("/fact/rule-pack/invalid", test_invalid_arguments);
  g_test_add_func ("/fact/rule-pack/reason-names", test_reason_names);
  return wyl_test_normalize_exit_status (g_test_run ());
}
