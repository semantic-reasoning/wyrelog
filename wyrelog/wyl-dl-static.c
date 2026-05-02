/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "wyl-dl-static-private.h"
#include "wyl-common-private.h"

#include <glib.h>
#include <stdint.h>

/*
 * Implementation overview.
 *
 * 1. Walk the rules once and intern every distinct predicate name in
 *    a GHashTable that maps name -> small integer index. The number
 *    of distinct predicates V bounds every subsequent array.
 *
 * 2. Walk the rules a second time and emit one edge per body atom:
 *    edge from body-predicate-index to head-predicate-index, with
 *    the body atom's negation flag carried alongside. Edges are
 *    stored in per-source adjacency lists.
 *
 * 3. Run Tarjan's SCC on the graph. After SCC computation, walk
 *    every edge once: if both endpoints share a component AND the
 *    edge is marked negated, the program is rejected.
 *
 * The algorithm is O(V + E). Allocations are released through
 * g_autoptr / g_autofree on both success and failure paths; the
 * out_edges array of GArray pointers is freed by an explicit helper
 * because g_autoptr does not compose with arrays of owned pointers.
 */

typedef struct edge_t
{
  int to;
  bool negated;
} edge_t;

typedef struct scc_state_t
{
  int n_predicates;

  /* Per-predicate adjacency: out_edges[i] -> array of edge_t. */
  GArray **out_edges;

  /* Tarjan bookkeeping. */
  int *index;
  int *lowlink;
  bool *on_stack;
  int next_index;

  GArray *stack;
  int *comp_id;
  int next_comp_id;
} scc_state_t;


static int
intern_predicate (GHashTable *names, const char *p, int *next_id)
{
  gpointer slot = g_hash_table_lookup (names, p);
  if (slot != NULL)
    return GPOINTER_TO_INT (slot) - 1;

  int id = (*next_id)++;
  g_hash_table_insert (names, (gpointer) p, GINT_TO_POINTER (id + 1));
  return id;
}

static void
strongconnect (scc_state_t *s, int v)
{
  s->index[v] = s->next_index;
  s->lowlink[v] = s->next_index;
  s->next_index++;
  g_array_append_val (s->stack, v);
  s->on_stack[v] = true;

  GArray *out = s->out_edges[v];
  for (guint i = 0; i < out->len; i++) {
    edge_t e = g_array_index (out, edge_t, i);
    int w = e.to;
    if (s->index[w] == -1) {
      strongconnect (s, w);
      if (s->lowlink[w] < s->lowlink[v])
        s->lowlink[v] = s->lowlink[w];
    } else if (s->on_stack[w]) {
      if (s->index[w] < s->lowlink[v])
        s->lowlink[v] = s->index[w];
    }
  }

  if (s->lowlink[v] == s->index[v]) {
    int comp = s->next_comp_id++;
    int w;
    do {
      w = g_array_index (s->stack, int, s->stack->len - 1);
      g_array_set_size (s->stack, s->stack->len - 1);
      s->on_stack[w] = false;
      s->comp_id[w] = comp;
    } while (w != v);
  }
}

static void
free_out_edges (GArray **out_edges, int n)
{
  if (out_edges == NULL)
    return;
  for (int i = 0; i < n; i++) {
    if (out_edges[i] != NULL)
      g_array_unref (out_edges[i]);
  }
  g_free (out_edges);
}

wyrelog_error_t
wyl_dl_static_check (const wyl_dl_rule_t *rules, size_t n)
{
  if (n == 0)
    return WYRELOG_E_OK;
  if (rules == NULL)
    return WYRELOG_E_INVALID;

  /* Validate input shape before allocating anything. */
  for (size_t i = 0; i < n; i++) {
    if (rules[i].head == NULL)
      return WYRELOG_E_INVALID;
    if (rules[i].body_len > 0 && rules[i].body == NULL)
      return WYRELOG_E_INVALID;
    for (size_t j = 0; j < rules[i].body_len; j++) {
      if (rules[i].body[j].predicate == NULL)
        return WYRELOG_E_INVALID;
    }
  }

  /* Pass 1: intern every distinct predicate name. The hash table
   * does not own the strings; the caller does. */
  g_autoptr (GHashTable) names = g_hash_table_new (g_str_hash, g_str_equal);
  int next_id = 0;
  for (size_t i = 0; i < n; i++) {
    intern_predicate (names, rules[i].head, &next_id);
    for (size_t j = 0; j < rules[i].body_len; j++)
      intern_predicate (names, rules[i].body[j].predicate, &next_id);
  }

  int V = next_id;
  if (V == 0)
    return WYRELOG_E_OK;

  scc_state_t s = { 0 };
  s.n_predicates = V;
  s.out_edges = g_new0 (GArray *, V);
  for (int i = 0; i < V; i++)
    s.out_edges[i] = g_array_new (FALSE, FALSE, sizeof (edge_t));

  /* Pass 2: emit edges. */
  for (size_t i = 0; i < n; i++) {
    int head_id =
        GPOINTER_TO_INT (g_hash_table_lookup (names, rules[i].head)) - 1;
    for (size_t j = 0; j < rules[i].body_len; j++) {
      int body_id = GPOINTER_TO_INT (g_hash_table_lookup (names,
              rules[i].body[j].predicate)) - 1;
      edge_t e = {.to = head_id,
        .negated = rules[i].body[j].negated
      };
      g_array_append_val (s.out_edges[body_id], e);
    }
  }

  /* Tarjan bookkeeping. */
  g_autofree int *index = g_new (int, V);
  g_autofree int *lowlink = g_new (int, V);
  g_autofree bool *on_stack = g_new0 (bool, V);
  g_autofree int *comp_id = g_new (int, V);
  for (int i = 0; i < V; i++) {
    index[i] = -1;
    lowlink[i] = 0;
    comp_id[i] = -1;
  }
  g_autoptr (GArray) stack = g_array_new (FALSE, FALSE, sizeof (int));

  s.index = index;
  s.lowlink = lowlink;
  s.on_stack = on_stack;
  s.comp_id = comp_id;
  s.stack = stack;
  s.next_index = 0;
  s.next_comp_id = 0;

  for (int i = 0; i < V; i++) {
    if (index[i] == -1)
      strongconnect (&s, i);
  }

  /* Reject when any negated edge has both endpoints in the same
   * SCC. Self-loops (singleton SCC with a negated self-edge) are
   * caught by the same rule. */
  wyrelog_error_t rc = WYRELOG_E_OK;
  for (int v = 0; v < V && rc == WYRELOG_E_OK; v++) {
    GArray *out = s.out_edges[v];
    for (guint i = 0; i < out->len; i++) {
      edge_t e = g_array_index (out, edge_t, i);
      if (e.negated && comp_id[v] == comp_id[e.to]) {
        rc = WYRELOG_E_POLICY;
        break;
      }
    }
  }

  free_out_edges (s.out_edges, V);
  return rc;
}
