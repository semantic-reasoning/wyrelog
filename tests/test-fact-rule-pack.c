/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>
#include <string.h>

#include "wyrelog/fact/rule-pack-private.h"
#include "wyrelog/wyl-engine-private.h"
#include <wirelog/wirelog-parser.h>

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
  g_autofree gchar *recursive = NULL;
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (text, strlen (text),
      relations, G_N_ELEMENTS (relations), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
      &recursive, NULL, &rejection), ==, WYRELOG_E_OK);
  g_assert_cmpstr (recursive, ==, rules);
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
  if (reason != WYL_FACT_RULE_PACK_REJECT_CYCLE) {
    g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (text, len, relations,
        G_N_ELEMENTS (relations), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
        &rules, NULL, &rejection), ==, WYRELOG_E_POLICY);
    g_assert_null (rules);
    g_assert_cmpint (rejection.reason, ==, reason);
    g_assert_cmpuint (rejection.rule_index, ==, rule_index);
    g_assert_cmpuint (rejection.atom_index, ==, atom_index);
    wyl_fact_rule_pack_rejection_clear (&rejection);
  }
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

static gchar **
accept_canonical (const gchar *text, gchar **out_rules)
{
  gchar **canonical = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile_canonical (text, strlen (text),
      relations, G_N_ELEMENTS (relations), out_rules, &canonical,
      &rejection), ==, WYRELOG_E_OK);
  g_assert_nonnull (canonical);
  g_autofree gchar *recursive = NULL;
  g_auto (GStrv) recursive_canonical = NULL;
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (text, strlen (text),
      relations, G_N_ELEMENTS (relations), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
      &recursive, &recursive_canonical, &rejection), ==, WYRELOG_E_OK);
  g_assert_cmpstr (recursive, ==, *out_rules);
  g_assert_true (g_strv_equal ((const gchar * const *) canonical,
      (const gchar * const *) recursive_canonical));
  wyl_fact_rule_pack_rejection_clear (&rejection);
  return canonical;
}

/* Each rule is stored as its canonical text: the rule re-rendered from its
 * parse, without spaces or comments, with integers in shortest decimal form
 * and only \" and \\ escaped.  Joined by newlines, the canonical texts are
 * a pack that compiles to the same program and is its own canonical form. */
static void
test_canonical_rule_text (void)
{
  const gchar *pack = "# derived order sets\n"
      "\n"
      "vip(O) :- shop.orders(O, Amount), customers(O, true).  # trailing\n"
      "shop.quiet(Order) :-\r shop.orders(Order, _),"
      " ! customers(Order, _).\r\n"
      "   big(O):-vip(O),shop.orders(O,-0),shop.orders(O, 007),"
      "customers(O,false).\n"
      "label(S) :- text(S), text(\"q\\\"x\\\\y caf\xc3\xa9\").\n";
  g_autofree gchar *rules = NULL;
  g_auto (GStrv) canonical = accept_canonical (pack, &rules);
  g_assert_cmpuint (g_strv_length (canonical), ==, 4);
  g_assert_cmpstr (canonical[0], ==,
      "vip(O):-shop.orders(O,Amount),customers(O,true).");
  g_assert_cmpstr (canonical[1], ==,
      "shop.quiet(Order):-shop.orders(Order,_),!customers(Order,_).");
  g_assert_cmpstr (canonical[2], ==,
      "big(O):-vip(O),shop.orders(O,0),shop.orders(O,7),customers(O,false).");
  g_assert_cmpstr (canonical[3], ==,
      "label(S):-text(S),text(\"q\\\"x\\\\y caf\xc3\xa9\").");

  g_autofree gchar *joined = g_strjoinv ("\n", canonical);
  g_autofree gchar *again_rules = NULL;
  g_auto (GStrv) again = accept_canonical (joined, &again_rules);
  g_assert_cmpstr (again_rules, ==, rules);
  g_assert_true (g_strv_equal ((const gchar * const *) again,
      (const gchar * const *) canonical));

  /* Without the canonical output the call is the plain compile. */
  g_autofree gchar *plain = accept (pack);
  g_assert_cmpstr (plain, ==, rules);
}

/* A canonical rule is never longer than the source text it came from, so a
 * pack within WYL_FACT_RULE_PACK_MAX_BYTES stores within it too.  The tight
 * case is a source already written compactly: every argument kind, a
 * negation and an escape then come back byte for byte. */
static void
test_canonical_rule_text_of_compact_source (void)
{
  const gchar *compact[] = {
    "a(X):-b(X),c(X),!amounts(-1),shop.orders(\"\\\"\",9).",
    "shop.vip(O):-customers(O,true),!m.p:-q(_),"
    "shop.orders(O,-9223372036854775808).",
  };
  g_autofree gchar *pack = g_strjoin ("\n", compact[0], compact[1], NULL);
  g_autofree gchar *rules = NULL;
  g_auto (GStrv) canonical = accept_canonical (pack, &rules);
  g_assert_cmpuint (g_strv_length (canonical), ==, 2);
  g_assert_cmpstr (canonical[0], ==, compact[0]);
  g_assert_cmpstr (canonical[1], ==, compact[1]);

  g_clear_pointer (&rules, g_free);
  g_auto (GStrv) empty = accept_canonical ("# nothing\n", &rules);
  g_assert_cmpuint (g_strv_length (empty), ==, 0);
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

#define G_EDGE "w_67_w_65_64_67_65"
#define G_REACH "w_67_w_72_65_61_63_68_61_62_6c_65"
#define G_BLOCK "w_67_w_62_6c_6f_63_6b_65_64"
#define G_VISIBLE "w_67_w_76_69_73_69_62_6c_65"
#define G_SEED "w_67_w_73_65_65_64"
#define G_P "w_67_w_70"
#define G_Q "w_67_w_71"

static const wyl_policy_fact_relation_schema_column_t pair_int[] = {
  { "x", "int64", FALSE, TRUE }, { "y", "int64", FALSE, TRUE },
};
static const wyl_fact_graph_program_relation_t recursive_relations[] = {
  REL ("g", "edge", pair_int), REL ("g", "reachable", pair_int),
  REL ("g", "blocked", pair_int), REL ("g", "visible", pair_int),
  REL ("g", "seed", one_int), REL ("g", "p", one_int),
  REL ("g", "q", one_int),
};

static const gchar *recursive_packs[] = {
  "reachable(X,Y):-edge(X,Y).\n"
  "reachable(X,Z):-reachable(X,Y),edge(Y,Z).\n"
  "visible(X,Y):-reachable(X,Y),!blocked(X,Y).",
  "reachable(X,Y):-edge(X,Y).\n"
  "reachable(X,Z):-reachable(X,Y),reachable(Y,Z).\n"
  "visible(X,Y):-reachable(X,Y),!blocked(X,Y).",
  "p(X):-seed(X).\nq(X):-p(X).\np(X):-q(X).",
  "p(X):-p(X).",
};

static const gchar *recursive_rendered[] = {
  G_REACH "(V0, V1) :- " G_EDGE "(V0, V1).\n"
  G_REACH "(V0, V1) :- " G_REACH "(V0, V2), " G_EDGE "(V2, V1).\n"
  G_VISIBLE "(V0, V1) :- " G_REACH "(V0, V1), !" G_BLOCK "(V0, V1).\n",
  G_REACH "(V0, V1) :- " G_EDGE "(V0, V1).\n"
  G_REACH "(V0, V1) :- " G_REACH "(V0, V2), " G_REACH "(V2, V1).\n"
  G_VISIBLE "(V0, V1) :- " G_REACH "(V0, V1), !" G_BLOCK "(V0, V1).\n",
  G_P "(V0) :- " G_SEED "(V0).\n" G_Q "(V0) :- " G_P "(V0).\n"
  G_P "(V0) :- " G_Q "(V0).\n",
  G_P "(V0) :- " G_P "(V0).\n",
};

typedef struct
{
  const gchar *relation;
  guint width;
  gboolean rows[4][4];
} RecursiveRows;

static void
capture_recursive (const gchar *relation, const gint64 *row, guint width,
    gpointer data)
{
  RecursiveRows *actual = data;
  g_assert_cmpstr (relation, ==, actual->relation);
  g_assert_cmpuint (width, ==, actual->width);
  g_assert_cmpint (row[0], >=, 0);
  g_assert_cmpint (row[0], <, 4);
  gint64 y = width == 2 ? row[1] : 0;
  g_assert_cmpint (y, >=, 0);
  g_assert_cmpint (y, <, 4);
  g_assert_false (actual->rows[row[0]][y]);
  actual->rows[row[0]][y] = TRUE;
}

static void
check_recursive_rows (WylEngine *engine, const gchar *relation, guint width,
    gboolean expected[4][4])
{
  RecursiveRows actual = { .relation = relation, .width = width };
  g_assert_cmpint (wyl_engine_snapshot (engine, relation, capture_recursive,
      &actual), ==, WYRELOG_E_OK);
  for (guint x = 0; x < 4; x++)
    for (guint y = 0; y < 4; y++)
      g_assert_cmpint (actual.rows[x][y], ==, expected[x][y]);
}

static void
insert_recursive (WylEngine *engine, const gchar *input, guint width,
    gint64 x, gint64 y)
{
  const gint64 row[] = { x, y };
  g_assert_cmpint (wyl_engine_owned_insert (engine, input, row, width), ==,
      WYRELOG_E_OK);
}

static void
test_recursive_compilation_and_execution (void)
{
  for (guint kind = 0; kind < G_N_ELEMENTS (recursive_packs); kind++) {
    const gchar *pack = recursive_packs[kind];
    g_autofree gchar *rules = NULL;
    g_auto (GStrv) canonical = NULL;
    wyl_fact_rule_pack_rejection_t rejection = { 0 };
    g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (pack, strlen (pack),
        recursive_relations, G_N_ELEMENTS (recursive_relations),
        WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rules, &canonical,
        &rejection), ==, WYRELOG_E_OK);
    g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NONE);
    g_assert_cmpstr (rules, ==, recursive_rendered[kind]);
    g_autofree gchar *joined = g_strjoinv ("\n", canonical);
    g_assert_cmpstr (joined, ==, pack);
    g_autofree gchar *program = wyl_fact_graph_program_render (
      recursive_relations, G_N_ELEMENTS (recursive_relations), rules);

    /* Real parser witness: acceptance exercised the recursive compile
     * backstop, not merely a positive cycle that the parser optimized away. */
    wirelog_error_t error = WIRELOG_OK;
    wirelog_program_t *parsed = wirelog_parse_string (program, &error);
    g_assert_cmpint (error, ==, WIRELOG_OK);
    g_assert_nonnull (parsed);
    gboolean recursive = FALSE;
    for (guint s = 0; s < wirelog_program_get_stratum_count (parsed); s++) {
      const wirelog_stratum_t *stratum = wirelog_program_get_stratum (parsed, s);
      g_assert_nonnull (stratum);
      recursive |= stratum->is_recursive;
    }
    g_assert_true (recursive);
    wirelog_program_free (parsed);

    g_autoptr (WylEngine) engine = NULL;
    g_assert_cmpint (wyl_engine_open_source (program, 1, &engine), ==,
        WYRELOG_E_OK);
    wyl_engine_set_owner (engine, WYL_ENGINE_OWNER_READ);
    gboolean expected[4][4] = { { FALSE } };
    if (kind < 2) {
      insert_recursive (engine, G_EDGE "_input", 2, 0, 1);
      insert_recursive (engine, G_EDGE "_input", 2, 1, 2);
      insert_recursive (engine, G_BLOCK "_input", 2, 0, 2);
      expected[0][1] = expected[0][2] = expected[1][2] = TRUE;
      check_recursive_rows (engine, G_REACH "_observed", 2, expected);
      /* Durable rows in a recursive head union with derived rows. Duplicate
       * support must not produce duplicate snapshot tuples. */
      insert_recursive (engine, G_REACH "_input", 2, 0, 1);
      insert_recursive (engine, G_REACH "_input", 2, 3, 0);
      expected[3][0] = expected[3][1] = expected[3][2] = TRUE;
      check_recursive_rows (engine, G_REACH "_observed", 2, expected);
      expected[0][2] = FALSE;
      check_recursive_rows (engine, G_VISIBLE "_observed", 2, expected);
    } else {
      /* No seed is valid and has an empty least fixed point. */
      check_recursive_rows (engine, G_P "_observed", 1, expected);
      if (kind == 2) {
        insert_recursive (engine, G_SEED "_input", 1, 0, 0);
        insert_recursive (engine, G_P "_input", 1, 3, 0);
        expected[0][0] = expected[3][0] = TRUE;
        check_recursive_rows (engine, G_P "_observed", 1, expected);
        check_recursive_rows (engine, G_Q "_observed", 1, expected);
      }
    }
    /* Both old entry points still refuse these exact accepted packs. */
    g_clear_pointer (&rules, g_free);
    g_clear_pointer (&canonical, g_strfreev);
    g_assert_cmpint (wyl_fact_rule_pack_compile_canonical (pack, strlen (pack),
        recursive_relations, G_N_ELEMENTS (recursive_relations), &rules,
        &canonical, &rejection), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_CYCLE);
    g_assert_null (rules);
    g_assert_null (canonical);
    wyl_fact_rule_pack_rejection_clear (&rejection);
    g_assert_cmpint (wyl_fact_rule_pack_compile (pack, strlen (pack),
        recursive_relations, G_N_ELEMENTS (recursive_relations), &rules,
        &rejection), ==, WYRELOG_E_POLICY);
    g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_CYCLE);
    wyl_fact_rule_pack_rejection_clear (&rejection);
  }
}

static void
assert_negative_cycle (const gchar *pack, guint rule, guint atom,
    const gchar *head, const gchar *body, const guint *cycle, guint n_cycle)
{
  /* Diagnostics must not depend on schema enumeration or SCC numbering. */
  wyl_fact_graph_program_relation_t reversed[G_N_ELEMENTS (relations)];
  for (guint i = 0; i < G_N_ELEMENTS (relations); i++)
    reversed[i] = relations[G_N_ELEMENTS (relations) - i - 1];
  for (guint order = 0; order < 2; order++) {
    g_autofree gchar *rules = NULL;
    g_auto (GStrv) canonical = NULL;
    wyl_fact_rule_pack_rejection_t rejection = { 0 };
    g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (pack, strlen (pack),
        order ? reversed : relations, G_N_ELEMENTS (relations),
        WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rules, &canonical,
        &rejection), ==, WYRELOG_E_POLICY);
    g_assert_null (rules);
    g_assert_null (canonical);
    g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NEGATIVE_CYCLE);
    g_assert_cmpstr (wyl_fact_rule_pack_reject_name (rejection.reason), ==,
        "rule_pack_negative_cycle");
    g_assert_cmpuint (rejection.rule_index, ==, rule);
    g_assert_cmpuint (rejection.atom_index, ==, atom);
    g_assert_cmpstr (rejection.cycle_head_namespace, ==, "shop");
    g_assert_cmpstr (rejection.cycle_head_relation, ==, head);
    g_assert_cmpstr (rejection.cycle_body_namespace, ==, "shop");
    g_assert_cmpstr (rejection.cycle_body_relation, ==, body);
    g_assert_cmpuint (rejection.n_cycle_rules, ==, n_cycle);
    for (guint i = 0; i < n_cycle; i++)
      g_assert_cmpuint (rejection.cycle_rules[i], ==, cycle[i]);
    wyl_fact_rule_pack_rejection_clear (&rejection);
    g_assert_null (rejection.cycle_rules);
    g_assert_null (rejection.cycle_head_namespace);
    g_assert_null (rejection.cycle_body_relation);
    wyl_fact_rule_pack_rejection_clear (&rejection);
  }
}

static void
test_signed_cycle_diagnostics (void)
{
  const guint self[] = { 1 };
  assert_negative_cycle ("shop.a(X):-big(X),!a(X).", 1, 2, "a", "a", self, 1);
  const guint pair[] = { 2, 3 };
  assert_negative_cycle ("big(X):-shop.orders(X,_).\n"
      "a(X):-b(X).\nb(X):-big(X),!a(X).\nc(X):-c(X).\n"
      "label(X):-a(X).\na(X):-big(X).", 3, 2, "b", "a", pair, 2);
  const guint first[] = { 1, 2 };
  assert_negative_cycle ("a(X):-big(X),!b(X),!b(X).\nb(X):-a(X).\n"
      "c(X):-big(X),!c(X).", 1, 2, "a", "b", first, 2);
  assert_negative_cycle ("a(X):-big(X),!b(X).\nb(X):-big(X),!a(X).",
      1, 2, "a", "b", first, 2);
}

static void
test_recursive_alias_identity (void)
{
  const wyl_fact_graph_program_relation_t schemas[] = {
    REL ("left", "p", one_int), REL ("right", "p", one_int),
    REL ("x", "y.z", one_int), REL ("x.y", "z", one_int),
  };
  const gchar *pack = "left.p(X):-right.p(X).\n"
      "right.p(X):-left.p(X).\ny.z(X):-z(X).\nz(X):-y.z(X).";
  g_autofree gchar *rules = NULL;
  g_auto (GStrv) canonical = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (pack, strlen (pack),
      schemas, G_N_ELEMENTS (schemas), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
      &rules, &canonical, &rejection), ==, WYRELOG_E_OK);
  g_assert_cmpstr (rules, ==,
      "w_6c_65_66_74_w_70(V0) :- w_72_69_67_68_74_w_70(V0).\n"
      "w_72_69_67_68_74_w_70(V0) :- w_6c_65_66_74_w_70(V0).\n"
      "w_78_w_79_2e_7a(V0) :- w_78_2e_79_w_7a(V0).\n"
      "w_78_2e_79_w_7a(V0) :- w_78_w_79_2e_7a(V0).\n");
  g_autofree gchar *joined = g_strjoinv ("\n", canonical);
  g_assert_cmpstr (joined, ==, pack);
  g_clear_pointer (&rules, g_free);
  const gchar *negative = "y.z(X):-z(X),!y.z(X).";
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (negative,
      strlen (negative), schemas, G_N_ELEMENTS (schemas),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rules, NULL, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NEGATIVE_CYCLE);
  g_assert_cmpstr (rejection.cycle_head_namespace, ==, "x");
  g_assert_cmpstr (rejection.cycle_head_relation, ==, "y.z");
  g_assert_cmpstr (rejection.cycle_body_namespace, ==, "x");
  g_assert_cmpstr (rejection.cycle_body_relation, ==, "y.z");
  wyl_fact_rule_pack_rejection_clear (&rejection);
  const gchar *alias = "shop.a(X):-a(X).";
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode (alias, strlen (alias),
      relations, G_N_ELEMENTS (relations), WYL_FACT_RULE_PACK_POSITIVE_RECURSION,
      &rules, NULL, &rejection), ==, WYRELOG_E_OK);
  g_assert_cmpstr (rules, ==, SHOP "w_61(V0) :- " SHOP "w_61(V0).\n");
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
  gchar **canonical = (gchar **) 1;
  rules = (gchar *) 1;
  g_assert_cmpint (wyl_fact_rule_pack_compile_with_mode ("", 0, relations,
      G_N_ELEMENTS (relations), (wyl_fact_rule_pack_mode_t) 99, &rules,
      &canonical, &rejection), ==, WYRELOG_E_INVALID);
  g_assert_null (rules);
  g_assert_null (canonical);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NONE);
}

static void
test_stored_reader_contract (void)
{
  gchar *rows[] = { "reachable(X,Y):-edge(X,Y).",
                    "reachable(X,Z):-reachable(X,Y),edge(Y,Z).", NULL };
  wyl_policy_fact_rule_pack_info_t pack = {
    .pack_version = 7, .rules = rows, .n_rules = 2,
  };
  g_assert_cmpint (wyl_policy_fact_rule_pack_digest (
        (const gchar * const *) rows, 2, pack.digest), ==, WYRELOG_E_OK);
  g_autofree gchar *rendered = NULL;
  wyl_fact_rule_pack_rejection_t rejection = { 0 };
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_OK);
  g_assert_cmpstr (rendered, ==,
      G_REACH "(V0, V1) :- " G_EDGE "(V0, V1).\n"
      G_REACH "(V0, V1) :- " G_REACH "(V0, V2), " G_EDGE "(V2, V1).\n");
  g_clear_pointer (&rendered, g_free);
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_ACYCLIC, &rendered, &rejection), ==, WYRELOG_E_POLICY);
  g_assert_null (rendered);
  g_assert_cmpint (rejection.reason, ==,
      WYL_FACT_RULE_PACK_REJECT_UNSUPPORTED_RECURSION);
  g_assert_cmpuint (rejection.rule_index, ==, 2);
  wyl_fact_rule_pack_rejection_clear (&rejection);

  pack.digest[0] ^= 1;
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_null (rendered);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_STORED_IDENTITY);
  pack.digest[0] ^= 1;
  pack.pack_version = 0;
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_STORED_IDENTITY);
  pack.pack_version = 7;
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      (wyl_fact_rule_pack_mode_t) 99, &rendered, &rejection), ==,
      WYRELOG_E_INVALID);
  g_assert_cmpint (rejection.reason, ==,
      WYL_FACT_RULE_PACK_REJECT_UNSUPPORTED_CAPABILITY);

  rows[0] = "reachable(X,Y) :- edge(X,Y).";
  g_assert_cmpint (wyl_policy_fact_rule_pack_digest (
        (const gchar * const *) rows, 2, pack.digest), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NONCANONICAL);
  g_assert_cmpuint (rejection.rule_index, ==, 1);
  g_assert_null (rendered);

  rows[0] = "p(X):-seed(X),!p(X).";
  rows[1] = NULL;
  pack.n_rules = 1;
  g_assert_cmpint (wyl_policy_fact_rule_pack_digest (
        (const gchar * const *) rows, 1, pack.digest), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_ACYCLIC, &rendered, &rejection), ==, WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_NEGATIVE_CYCLE);
  g_assert_null (rendered);
  wyl_fact_rule_pack_rejection_clear (&rejection);
  pack.n_rules = WYL_FACT_RULE_PACK_MAX_RULES + 1;
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_STORED_IDENTITY);
  pack.n_rules = 1;
  rows[0] = NULL;
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_STORED_IDENTITY);
  g_autofree gchar *large = g_strnfill (WYL_FACT_RULE_PACK_MAX_BYTES / 2, 'x');
  rows[0] = rows[1] = large;
  pack.n_rules = 2;
  g_assert_cmpint (wyl_policy_fact_rule_pack_digest (
        (const gchar * const *) rows, 2, pack.digest), ==, WYRELOG_E_OK);
  g_assert_cmpint (wyl_fact_rule_pack_compile_stored (&pack,
      recursive_relations, G_N_ELEMENTS (recursive_relations),
      WYL_FACT_RULE_PACK_POSITIVE_RECURSION, &rendered, &rejection), ==,
      WYRELOG_E_POLICY);
  g_assert_cmpint (rejection.reason, ==, WYL_FACT_RULE_PACK_REJECT_STORED_IDENTITY);
  g_assert_null (rendered);
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
      r <= WYL_FACT_RULE_PACK_REJECT_UNSUPPORTED_CAPABILITY; r++)
    g_assert_nonnull (wyl_fact_rule_pack_reject_name (r));
  g_assert_cmpstr (wyl_fact_rule_pack_reject_name
        (WYL_FACT_RULE_PACK_REJECT_EMPTY), ==, "rule_pack_empty");
  g_assert_null (wyl_fact_rule_pack_reject_name
        (WYL_FACT_RULE_PACK_REJECT_UNSUPPORTED_CAPABILITY + 1));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/rule-pack/stored-reader", test_stored_reader_contract);
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
  g_test_add_func ("/fact/rule-pack/canonical", test_canonical_rule_text);
  g_test_add_func ("/fact/rule-pack/canonical/compact",
      test_canonical_rule_text_of_compact_source);
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
  g_test_add_func ("/fact/rule-pack/recursive/execute",
      test_recursive_compilation_and_execution);
  g_test_add_func ("/fact/rule-pack/recursive/negative-cycles",
      test_signed_cycle_diagnostics);
  g_test_add_func ("/fact/rule-pack/recursive/aliases", test_recursive_alias_identity);
  g_test_add_func ("/fact/rule-pack/invalid", test_invalid_arguments);
  g_test_add_func ("/fact/rule-pack/reason-names", test_reason_names);
  return wyl_test_normalize_exit_status (g_test_run ());
}
