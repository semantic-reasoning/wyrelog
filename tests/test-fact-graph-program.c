/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "test-exit-status.h"
#include <glib.h>

#include "wyrelog/fact/graph-program-private.h"

#define SHOP_ORDERS "w_73_68_6f_70_w_6f_72_64_65_72_73"
#define ORDER_ID "w_6f_72_64_65_72_5f_69_64"
#define AMOUNT "w_61_6d_6f_75_6e_74"

static const wyl_policy_fact_relation_schema_column_t orders_columns[] = {
  {"order_id", "symbol", FALSE, TRUE},
  {"amount", "int64", FALSE, TRUE},
};

/* The program a graph engine is built from, pinned byte for byte.  A rule
 * pack is appended to this text, so an absent pack must leave it exactly as
 * the replay path has always produced it. */
static void
test_render_without_rules (void)
{
  const wyl_fact_graph_program_relation_t relations[] = {
    {"shop", "orders", orders_columns, G_N_ELEMENTS (orders_columns)},
  };
  g_autofree gchar *program = wyl_fact_graph_program_render (relations,
          G_N_ELEMENTS (relations), NULL);
  g_assert_cmpstr (program, ==,
      ".decl " SHOP_ORDERS "(" ORDER_ID ": symbol, " AMOUNT ": int64)\n"
      ".decl " SHOP_ORDERS "_observed(" ORDER_ID ": symbol, " AMOUNT
      ": int64)\n"
      SHOP_ORDERS "_observed(V0, V1) :- " SHOP_ORDERS "(V0, V1).\n");
}

static void
test_render_appends_rules_after_declarations (void)
{
  const wyl_policy_fact_relation_schema_column_t flag_columns[] = {
    {"f", "bool", FALSE, TRUE},
    {"c", "compound_ref", FALSE, TRUE},
    {"s", "string", FALSE, TRUE},
  };
  const wyl_fact_graph_program_relation_t relations[] = {
    {"a", "b", flag_columns, G_N_ELEMENTS (flag_columns)},
    {"a", "c", flag_columns, 1},
  };
  g_autofree gchar *program = wyl_fact_graph_program_render (relations,
          G_N_ELEMENTS (relations), "RULES\n");
  g_assert_cmpstr (program, ==,
      ".decl w_61_w_62(w_66: int64, w_63: int64, w_73: symbol)\n"
      ".decl w_61_w_62_observed(w_66: int64, w_63: int64, w_73: symbol)\n"
      "w_61_w_62_observed(V0, V1, V2) :- w_61_w_62(V0, V1, V2).\n"
      ".decl w_61_w_63(w_66: int64)\n"
      ".decl w_61_w_63_observed(w_66: int64)\n"
      "w_61_w_63_observed(V0) :- w_61_w_63(V0).\n" "RULES\n");
}

static void
test_render_refuses_unknown_type (void)
{
  const wyl_policy_fact_relation_schema_column_t columns[] = {
    {"x", "float64", FALSE, TRUE},
  };
  const wyl_fact_graph_program_relation_t relations[] = {
    {"a", "b", columns, G_N_ELEMENTS (columns)},
  };
  g_assert_null (wyl_fact_graph_program_render (relations, 1, NULL));
  g_assert_null (wyl_fact_graph_program_render (NULL, 1, NULL));
}

static void
test_relation_name_encoding (void)
{
  g_autofree gchar *name = wyl_fact_graph_program_relation_name ("shop",
          "orders");
  g_assert_cmpstr (name, ==, SHOP_ORDERS);
  g_autofree gchar *dotted = wyl_fact_graph_program_relation_name ("a.b",
          "c:-d");
  g_assert_cmpstr (dotted, ==, "w_61_2e_62_w_63_3a_2d_64");
  g_assert_null (wyl_fact_graph_program_relation_name (NULL, "x"));
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/fact/graph-program/without-rules",
      test_render_without_rules);
  g_test_add_func ("/fact/graph-program/appends-rules",
      test_render_appends_rules_after_declarations);
  g_test_add_func ("/fact/graph-program/unknown-type",
      test_render_refuses_unknown_type);
  g_test_add_func ("/fact/graph-program/relation-name",
      test_relation_name_encoding);
  return wyl_test_normalize_exit_status (g_test_run ());
}
