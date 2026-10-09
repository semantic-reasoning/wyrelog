/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/rule-pack-private.h"

#include <string.h>
#include <wirelog/wirelog.h>
#include <wirelog/wirelog-parser.h>

/* Parsing and the acceptance check for a graph's rule pack (#1213).  Operator
 * text never reaches wirelog: it is parsed into atoms here, names are resolved
 * against the registered relations and re-rendered hex-encoded, variables are
 * renamed, and string constants are re-escaped. */

typedef enum
{
  ARG_VARIABLE,
  ARG_WILDCARD,
  ARG_STRING,
  ARG_INTEGER,
  ARG_BOOL,
} ArgKind;

typedef struct
{
  ArgKind kind;
  gchar *text;                  /* variable name or decoded string */
  gint64 integer;
  gboolean boolean;
} RuleArg;

typedef struct
{
  gchar *name;
  gboolean negated;
  GArray *args;                 /* RuleArg */
  gsize relation;               /* index into the registered relations */
} RuleAtom;

typedef struct
{
  RuleAtom head;
  GPtrArray *body;              /* RuleAtom * */
} PackRule;

typedef enum
{
  CLASS_NONE = 0,
  CLASS_SYMBOL,
  CLASS_INT64,
  CLASS_BOOL,
  CLASS_COMPOUND,
} TypeClass;

typedef struct
{
  const gchar *p;
  const gchar *end;
  guint rule_index;
  guint atom_index;
  wyl_fact_rule_pack_reject_t reason;
} Cursor;

static void
rule_arg_clear (gpointer data)
{
  RuleArg *arg = data;
  g_free (arg->text);
}

static void
rule_atom_clear (RuleAtom *atom)
{
  g_clear_pointer (&atom->name, g_free);
  g_clear_pointer (&atom->args, g_array_unref);
}

static void
rule_atom_free (gpointer data)
{
  RuleAtom *atom = data;
  rule_atom_clear (atom);
  g_free (atom);
}

static void
pack_rule_free (gpointer data)
{
  PackRule *rule = data;
  rule_atom_clear (&rule->head);
  g_clear_pointer (&rule->body, g_ptr_array_unref);
  g_free (rule);
}

static const gchar *const reject_names[] = {
  [WYL_FACT_RULE_PACK_REJECT_NONE] = "rule_pack_none",
  [WYL_FACT_RULE_PACK_REJECT_TOO_LARGE] = "rule_pack_too_large",
  [WYL_FACT_RULE_PACK_REJECT_TOO_MANY_RULES] = "rule_pack_too_many_rules",
  [WYL_FACT_RULE_PACK_REJECT_TOO_MANY_BODY_ATOMS] =
      "rule_pack_too_many_body_atoms",
  [WYL_FACT_RULE_PACK_REJECT_SYNTAX] = "rule_pack_syntax",
  [WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT] = "rule_pack_invalid_constant",
  [WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION] = "rule_pack_unknown_relation",
  [WYL_FACT_RULE_PACK_REJECT_AMBIGUOUS_RELATION] =
      "rule_pack_ambiguous_relation",
  [WYL_FACT_RULE_PACK_REJECT_ARITY] = "rule_pack_arity",
  [WYL_FACT_RULE_PACK_REJECT_HEAD_WILDCARD] = "rule_pack_head_wildcard",
  [WYL_FACT_RULE_PACK_REJECT_UNSAFE_HEAD_VARIABLE] =
      "rule_pack_unsafe_head_variable",
  [WYL_FACT_RULE_PACK_REJECT_UNSAFE_NEGATED_VARIABLE] =
      "rule_pack_unsafe_negated_variable",
  [WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH] = "rule_pack_type_mismatch",
  [WYL_FACT_RULE_PACK_REJECT_CYCLE] = "rule_pack_cycle",
  [WYL_FACT_RULE_PACK_REJECT_COMPILE] = "rule_pack_compile",
};

const gchar *
wyl_fact_rule_pack_reject_name (wyl_fact_rule_pack_reject_t reason)
{
  if ((guint) reason >= G_N_ELEMENTS (reject_names))
    return NULL;
  return reject_names[reason];
}

void
wyl_fact_rule_pack_rejection_clear (wyl_fact_rule_pack_rejection_t *rejection)
{
  if (rejection == NULL)
    return;
  g_free (rejection->cycle_rules);
  *rejection = (wyl_fact_rule_pack_rejection_t) {
    0
  };
}

/* ---- parsing ---------------------------------------------------------- */

static gboolean
fail (Cursor *c, wyl_fact_rule_pack_reject_t reason)
{
  c->reason = reason;
  return FALSE;
}

static gboolean
at_end (const Cursor *c)
{
  return c->p >= c->end;
}

/* Spaces, tabs and carriage returns: whitespace that does not end a line. */
static void
skip_inline_space (Cursor *c)
{
  while (!at_end (c) && (*c->p == ' ' || *c->p == '\t' || *c->p == '\r'))
    c->p++;
}

static gboolean
consume (Cursor *c, const gchar *token)
{
  gsize len = strlen (token);
  skip_inline_space (c);
  if ((gsize) (c->end - c->p) < len || memcmp (c->p, token, len) != 0)
    return FALSE;
  c->p += len;
  return TRUE;
}

/* The characters a registered namespace or relation name may contain. */
static gboolean
is_name_char (gchar ch)
{
  return g_ascii_isalnum (ch) || ch == '.' || ch == '_' || ch == ':'
         || ch == '-';
}

static gboolean
is_word_char (gchar ch)
{
  return g_ascii_isalnum (ch) || ch == '_';
}

static gboolean
parse_string (Cursor *c, RuleArg *arg)
{
  g_autoptr (GString) value = g_string_new (NULL);
  c->p++;                       /* opening quote */
  for (;;) {
    if (at_end (c) || *c->p == '\n')
      return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
    guchar ch = (guchar) * c->p;
    if (ch == '"')
      break;
    if (ch == '\\') {
      if (c->end - c->p < 2 || (c->p[1] != '"' && c->p[1] != '\\'))
        return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
      g_string_append_c (value, c->p[1]);
      c->p += 2;
      continue;
    }
    if (ch < 0x20 || ch == 0x7f)
      return fail (c, WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT);
    g_string_append_c (value, (gchar) ch);
    c->p++;
  }
  c->p++;                       /* closing quote */
  if (!g_utf8_validate_len (value->str, value->len, NULL))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT);
  arg->kind = ARG_STRING;
  arg->text = g_string_free (g_steal_pointer (&value), FALSE);
  return TRUE;
}

static gboolean
parse_integer (Cursor *c, RuleArg *arg)
{
  const gchar *start = c->p;
  if (*c->p == '-')
    c->p++;
  const gchar *digits = c->p;
  while (!at_end (c) && g_ascii_isdigit (*c->p))
    c->p++;
  if (c->p == digits || (!at_end (c) && is_word_char (*c->p)))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  g_autofree gchar *text = g_strndup (start, c->p - start);
  gint64 value = 0;
  if (!g_ascii_string_to_signed (text, 10, G_MININT64, G_MAXINT64,
      &value, NULL))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_INVALID_CONSTANT);
  arg->kind = ARG_INTEGER;
  arg->integer = value;
  return TRUE;
}

static gboolean
parse_argument (Cursor *c, RuleArg *arg)
{
  skip_inline_space (c);
  if (at_end (c))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  gchar ch = *c->p;
  if (ch == '"')
    return parse_string (c, arg);
  if (ch == '-' || g_ascii_isdigit (ch))
    return parse_integer (c, arg);

  const gchar *start = c->p;
  while (!at_end (c) && is_word_char (*c->p))
    c->p++;
  gsize len = c->p - start;
  if (len == 1 && ch == '_') {
    arg->kind = ARG_WILDCARD;
    return TRUE;
  }
  if (len > 0 && g_ascii_isupper (ch)) {
    arg->kind = ARG_VARIABLE;
    arg->text = g_strndup (start, len);
    return TRUE;
  }
  if (len == 4 && memcmp (start, "true", 4) == 0) {
    arg->kind = ARG_BOOL;
    arg->boolean = TRUE;
    return TRUE;
  }
  if (len == 5 && memcmp (start, "false", 5) == 0) {
    arg->kind = ARG_BOOL;
    arg->boolean = FALSE;
    return TRUE;
  }
  return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
}

static gboolean
parse_atom (Cursor *c, gboolean allow_negation, RuleAtom *atom)
{
  skip_inline_space (c);
  if (allow_negation && !at_end (c) && *c->p == '!') {
    atom->negated = TRUE;
    c->p++;
    skip_inline_space (c);
  }
  const gchar *start = c->p;
  while (!at_end (c) && is_name_char (*c->p))
    c->p++;
  if (c->p == start || at_end (c) || *c->p != '(')
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  atom->name = g_strndup (start, c->p - start);
  c->p++;

  atom->args = g_array_new (FALSE, TRUE, sizeof (RuleArg));
  g_array_set_clear_func (atom->args, rule_arg_clear);
  for (;;) {
    RuleArg arg = { 0 };
    if (!parse_argument (c, &arg)) {
      rule_arg_clear (&arg);
      return FALSE;
    }
    g_array_append_val (atom->args, arg);
    if (consume (c, ","))
      continue;
    if (consume (c, ")"))
      return TRUE;
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  }
}

static gboolean
parse_rule (Cursor *c, PackRule *rule)
{
  c->atom_index = 0;
  if (!parse_atom (c, FALSE, &rule->head))
    return FALSE;
  if (!consume (c, ":-"))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  for (;;) {
    c->atom_index = rule->body->len + 1;
    if (c->atom_index > WYL_FACT_RULE_PACK_MAX_BODY_ATOMS)
      return fail (c, WYL_FACT_RULE_PACK_REJECT_TOO_MANY_BODY_ATOMS);
    RuleAtom *atom = g_new0 (RuleAtom, 1);
    g_ptr_array_add (rule->body, atom);
    if (!parse_atom (c, TRUE, atom))
      return FALSE;
    if (consume (c, ","))
      continue;
    if (consume (c, "."))
      break;
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  }
  /* Nothing but a comment may follow a rule on its line. */
  skip_inline_space (c);
  if (!at_end (c) && *c->p == '#')
    while (!at_end (c) && *c->p != '\n')
      c->p++;
  if (!at_end (c) && *c->p != '\n')
    return fail (c, WYL_FACT_RULE_PACK_REJECT_SYNTAX);
  return TRUE;
}

static gboolean
parse_pack (Cursor *c, GPtrArray *rules)
{
  for (;;) {
    while (!at_end (c) && (g_ascii_isspace (*c->p) || *c->p == '#')) {
      if (*c->p == '#')
        while (!at_end (c) && *c->p != '\n')
          c->p++;
      else
        c->p++;
    }
    if (at_end (c))
      return TRUE;
    c->rule_index = rules->len + 1;
    c->atom_index = 0;
    if (c->rule_index > WYL_FACT_RULE_PACK_MAX_RULES)
      return fail (c, WYL_FACT_RULE_PACK_REJECT_TOO_MANY_RULES);
    PackRule *rule = g_new0 (PackRule, 1);
    rule->body = g_ptr_array_new_with_free_func (rule_atom_free);
    g_ptr_array_add (rules, rule);
    if (!parse_rule (c, rule))
      return FALSE;
  }
}

/* ---- per-rule checks -------------------------------------------------- */

static TypeClass
column_class (const gchar *column_type)
{
  if (g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0)
    return CLASS_SYMBOL;
  if (g_strcmp0 (column_type, "int64") == 0)
    return CLASS_INT64;
  if (g_strcmp0 (column_type, "bool") == 0)
    return CLASS_BOOL;
  if (g_strcmp0 (column_type, "compound_ref") == 0)
    return CLASS_COMPOUND;
  return CLASS_NONE;
}

static wyl_fact_rule_pack_reject_t
resolve_atom (RuleAtom *atom, const wyl_fact_graph_program_relation_t *rels,
    gsize n_rels)
{
  gsize matches = 0;
  gsize name_len = strlen (atom->name);
  for (gsize i = 0; i < n_rels; i++) {
    const gchar *ns = rels[i].namespace_id;
    const gchar *rel = rels[i].relation_name;
    gsize ns_len = strlen (ns);
    gboolean qualified = name_len == ns_len + 1 + strlen (rel)
        && strncmp (atom->name, ns, ns_len) == 0
        && atom->name[ns_len] == '.'
        && strcmp (atom->name + ns_len + 1, rel) == 0;
    if (qualified || strcmp (atom->name, rel) == 0) {
      matches++;
      atom->relation = i;
    }
  }
  if (matches == 0)
    return WYL_FACT_RULE_PACK_REJECT_UNKNOWN_RELATION;
  if (matches > 1)
    return WYL_FACT_RULE_PACK_REJECT_AMBIGUOUS_RELATION;
  if (atom->args->len != rels[atom->relation].n_columns)
    return WYL_FACT_RULE_PACK_REJECT_ARITY;
  return WYL_FACT_RULE_PACK_REJECT_NONE;
}

static RuleAtom *
rule_atom_at (PackRule *rule, guint atom_index)
{
  return atom_index == 0 ? &rule->head
      : g_ptr_array_index (rule->body, atom_index - 1);
}

static gboolean
atom_has_unbound_variable (const RuleAtom *atom, GHashTable *bound)
{
  for (guint a = 0; a < atom->args->len; a++) {
    const RuleArg *arg = &g_array_index (atom->args, RuleArg, a);
    if (arg->kind == ARG_VARIABLE && !g_hash_table_contains (bound, arg->text))
      return TRUE;
  }
  return FALSE;
}

static gboolean
check_rule (PackRule *rule, const wyl_fact_graph_program_relation_t *rels,
    gsize n_rels, Cursor *c)
{
  guint n_atoms = rule->body->len + 1;

  for (guint i = 0; i < n_atoms; i++) {
    c->atom_index = i;
    wyl_fact_rule_pack_reject_t reason =
        resolve_atom (rule_atom_at (rule, i), rels, n_rels);
    if (reason != WYL_FACT_RULE_PACK_REJECT_NONE)
      return fail (c, reason);
  }

  c->atom_index = 0;
  for (guint a = 0; a < rule->head.args->len; a++)
    if (g_array_index (rule->head.args, RuleArg, a).kind == ARG_WILDCARD)
      return fail (c, WYL_FACT_RULE_PACK_REJECT_HEAD_WILDCARD);

  g_autoptr (GHashTable) bound = g_hash_table_new (g_str_hash, g_str_equal);
  for (guint i = 0; i < rule->body->len; i++) {
    const RuleAtom *atom = g_ptr_array_index (rule->body, i);
    if (atom->negated)
      continue;
    for (guint a = 0; a < atom->args->len; a++) {
      const RuleArg *arg = &g_array_index (atom->args, RuleArg, a);
      if (arg->kind == ARG_VARIABLE)
        g_hash_table_add (bound, arg->text);
    }
  }
  if (atom_has_unbound_variable (&rule->head, bound))
    return fail (c, WYL_FACT_RULE_PACK_REJECT_UNSAFE_HEAD_VARIABLE);
  for (guint i = 1; i < n_atoms; i++) {
    const RuleAtom *atom = rule_atom_at (rule, i);
    c->atom_index = i;
    if (atom->negated && atom_has_unbound_variable (atom, bound))
      return fail (c, WYL_FACT_RULE_PACK_REJECT_UNSAFE_NEGATED_VARIABLE);
  }

  /* One class per variable across the whole rule, from declared column
   * types.  A constant's class is fixed by its spelling, and no constant
   * has the compound class: a handle id is not something an operator can
   * name.
   *
   * A compound variable also stays within one namespace.  wirelog allocates
   * a compound handle rather than interning it by structure, and replay
   * shares handles only per namespace, so equal compounds stored under two
   * namespaces carry different handles: a join across them would match
   * nothing, and a head would hold another namespace's handle. */
  g_autoptr (GHashTable) classes = g_hash_table_new (g_str_hash, g_str_equal);
  g_autoptr (GHashTable) compound_namespaces =
      g_hash_table_new (g_str_hash, g_str_equal);
  for (guint i = 0; i < n_atoms; i++) {
    const RuleAtom *atom = rule_atom_at (rule, i);
    const wyl_fact_graph_program_relation_t *rel = &rels[atom->relation];
    c->atom_index = i;
    for (guint a = 0; a < atom->args->len; a++) {
      const RuleArg *arg = &g_array_index (atom->args, RuleArg, a);
      TypeClass column = column_class (rel->columns[a].column_type);
      TypeClass value = CLASS_NONE;
      switch (arg->kind) {
        case ARG_WILDCARD:
          continue;
        case ARG_STRING:
          value = CLASS_SYMBOL;
          break;
        case ARG_INTEGER:
          value = CLASS_INT64;
          break;
        case ARG_BOOL:
          value = CLASS_BOOL;
          break;
        case ARG_VARIABLE:
          value = GPOINTER_TO_INT (g_hash_table_lookup (classes, arg->text));
          if (value == CLASS_NONE) {
            g_hash_table_insert (classes, arg->text,
                GINT_TO_POINTER (column));
            value = column;
          }
          break;
      }
      if (column == CLASS_NONE || value != column)
        return fail (c, WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH);
      if (column == CLASS_COMPOUND) {
        const gchar *ns = g_hash_table_lookup (compound_namespaces, arg->text);
        if (ns == NULL)
          g_hash_table_insert (compound_namespaces, arg->text,
              (gpointer) rel->namespace_id);
        else if (strcmp (ns, rel->namespace_id) != 0)
          return fail (c, WYL_FACT_RULE_PACK_REJECT_TYPE_MISMATCH);
      }
    }
  }
  return TRUE;
}

/* ---- acyclicity ------------------------------------------------------- */

typedef struct
{
  GPtrArray *rules;
  gint *index;
  gint *lowlink;
  gint *component;
  gboolean *on_stack;
  GArray *stack;
  gint next_index;
  gint n_components;
} Tarjan;

static void
tarjan_visit (Tarjan *t, gsize v)
{
  t->index[v] = t->lowlink[v] = t->next_index++;
  g_array_append_val (t->stack, v);
  t->on_stack[v] = TRUE;
  for (guint r = 0; r < t->rules->len; r++) {
    PackRule *rule = g_ptr_array_index (t->rules, r);
    if (rule->head.relation != v)
      continue;
    for (guint b = 0; b < rule->body->len; b++) {
      gsize w = ((RuleAtom *) g_ptr_array_index (rule->body, b))->relation;
      if (t->index[w] < 0) {
        tarjan_visit (t, w);
        t->lowlink[v] = MIN (t->lowlink[v], t->lowlink[w]);
      } else if (t->on_stack[w]) {
        t->lowlink[v] = MIN (t->lowlink[v], t->index[w]);
      }
    }
  }
  if (t->lowlink[v] == t->index[v]) {
    gsize w;
    do {
      w = g_array_index (t->stack, gsize, t->stack->len - 1);
      g_array_set_size (t->stack, t->stack->len - 1);
      t->on_stack[w] = FALSE;
      t->component[w] = t->n_components;
    } while (w != v);
    t->n_components++;
  }
}

/* A rule is on a cycle when its head and one of its body relations fall in
 * the same strongly connected component of the head-to-body graph: either
 * the body relation is the head itself, or each reaches the other through
 * the pack.  The recursion depth is bounded by the number of distinct heads,
 * which is at most WYL_FACT_RULE_PACK_MAX_RULES. */
static GArray *
find_cycle_rules (GPtrArray *rules, gsize n_rels)
{
  Tarjan t = {
    .rules = rules,
    .index = g_new (gint, n_rels),
    .lowlink = g_new0 (gint, n_rels),
    .component = g_new0 (gint, n_rels),
    .on_stack = g_new0 (gboolean, n_rels),
    .stack = g_array_new (FALSE, FALSE, sizeof (gsize)),
  };
  for (gsize i = 0; i < n_rels; i++)
    t.index[i] = -1;
  for (guint r = 0; r < rules->len; r++) {
    PackRule *rule = g_ptr_array_index (rules, r);
    if (t.index[rule->head.relation] < 0)
      tarjan_visit (&t, rule->head.relation);
  }

  GArray *cyclic = g_array_new (FALSE, FALSE, sizeof (guint));
  for (guint r = 0; r < rules->len; r++) {
    PackRule *rule = g_ptr_array_index (rules, r);
    gsize head = rule->head.relation;
    for (guint b = 0; b < rule->body->len; b++) {
      gsize body = ((RuleAtom *) g_ptr_array_index (rule->body, b))->relation;
      if (t.index[body] >= 0 && t.component[body] == t.component[head]) {
        guint ordinal = r + 1;
        g_array_append_val (cyclic, ordinal);
        break;
      }
    }
  }
  g_free (t.index);
  g_free (t.lowlink);
  g_free (t.component);
  g_free (t.on_stack);
  g_array_unref (t.stack);
  return cyclic;
}

/* ---- rendering -------------------------------------------------------- */

static void
render_atom (GString *out, const RuleAtom *atom,
    const wyl_fact_graph_program_relation_t *rels, GHashTable *variables)
{
  const wyl_fact_graph_program_relation_t *rel = &rels[atom->relation];
  g_autofree gchar *name =
      wyl_fact_graph_program_relation_name (rel->namespace_id,
          rel->relation_name);
  if (atom->negated)
    g_string_append_c (out, '!');
  g_string_append (out, name);
  g_string_append_c (out, '(');
  for (guint a = 0; a < atom->args->len; a++) {
    const RuleArg *arg = &g_array_index (atom->args, RuleArg, a);
    if (a > 0)
      g_string_append (out, ", ");
    switch (arg->kind) {
      case ARG_WILDCARD:
        g_string_append_c (out, '_');
        break;
      case ARG_VARIABLE: {
        gpointer slot = NULL;
        guint number;
        if (g_hash_table_lookup_extended (variables, arg->text, NULL, &slot)) {
          number = GPOINTER_TO_UINT (slot);
        } else {
          number = g_hash_table_size (variables);
          g_hash_table_insert (variables, arg->text,
              GUINT_TO_POINTER (number));
        }
        g_string_append_printf (out, "V%u", number);
        break;
      }
      case ARG_STRING:
        /* wirelog's lexer decodes exactly \" and \\. */
        g_string_append_c (out, '"');
        for (const gchar * p = arg->text; *p != '\0'; p++) {
          if (*p == '"' || *p == '\\')
            g_string_append_c (out, '\\');
          g_string_append_c (out, *p);
        }
        g_string_append_c (out, '"');
        break;
      case ARG_INTEGER:
        g_string_append_printf (out, "%" G_GINT64_FORMAT, arg->integer);
        break;
      case ARG_BOOL:
        /* Replay stores a bool cell as 0 or 1 in an int64 column. */
        g_string_append_c (out, arg->boolean ? '1' : '0');
        break;
    }
  }
  g_string_append_c (out, ')');
}

static gchar *
render_rules (GPtrArray *rules, const wyl_fact_graph_program_relation_t *rels)
{
  g_autoptr (GString) out = g_string_new (NULL);
  for (guint r = 0; r < rules->len; r++) {
    PackRule *rule = g_ptr_array_index (rules, r);
    g_autoptr (GHashTable) variables =
        g_hash_table_new (g_str_hash, g_str_equal);
    render_atom (out, &rule->head, rels, variables);
    g_string_append (out, " :- ");
    for (guint b = 0; b < rule->body->len; b++) {
      if (b > 0)
        g_string_append (out, ", ");
      render_atom (out, g_ptr_array_index (rule->body, b), rels, variables);
    }
    g_string_append (out, ".\n");
  }
  return g_string_free (g_steal_pointer (&out), FALSE);
}

/* The backstop: wirelog compiles the program a rebuild would open.  An
 * acyclic pack is always stratifiable, so a recursive stratum here means the
 * acyclicity check above is wrong, not that the pack is. */
static wyrelog_error_t
compile_program (const wyl_fact_graph_program_relation_t *rels, gsize n_rels,
    const gchar *rules, gboolean *out_compiled)
{
  *out_compiled = FALSE;
  g_autofree gchar *program = wyl_fact_graph_program_render (rels, n_rels,
          rules);
  if (program == NULL)
    return WYRELOG_E_INVALID;
  wirelog_error_t parse_error = WIRELOG_OK;
  wirelog_program_t *parsed = wirelog_parse_string (program, &parse_error);
  if (parsed == NULL || parse_error != WIRELOG_OK) {
    if (parsed != NULL)
      wirelog_program_free (parsed);
    return WYRELOG_E_OK;
  }
  wyrelog_error_t rc = WYRELOG_E_OK;
  uint32_t n_strata = wirelog_program_get_stratum_count (parsed);
  for (uint32_t s = 0; s < n_strata; s++) {
    const wirelog_stratum_t *stratum = wirelog_program_get_stratum (parsed, s);
    if (stratum == NULL || stratum->is_recursive)
      rc = WYRELOG_E_INTERNAL;
  }
  wirelog_program_free (parsed);
  *out_compiled = rc == WYRELOG_E_OK;
  return rc;
}

wyrelog_error_t
wyl_fact_rule_pack_compile (const gchar *text, gsize text_len,
    const wyl_fact_graph_program_relation_t *relations, gsize n_relations,
    gchar **out_rules, wyl_fact_rule_pack_rejection_t *out_rejection)
{
  if (out_rules != NULL)
    *out_rules = NULL;
  if (out_rejection != NULL)
    *out_rejection = (wyl_fact_rule_pack_rejection_t) {
      0
    };
  if (text == NULL || (relations == NULL && n_relations > 0)
      || out_rules == NULL || out_rejection == NULL)
    return WYRELOG_E_INVALID;
  for (gsize i = 0; i < n_relations; i++)
    if (relations[i].namespace_id == NULL
        || relations[i].relation_name == NULL
        || (relations[i].columns == NULL && relations[i].n_columns > 0))
      return WYRELOG_E_INVALID;

  if (text_len > WYL_FACT_RULE_PACK_MAX_BYTES) {
    out_rejection->reason = WYL_FACT_RULE_PACK_REJECT_TOO_LARGE;
    return WYRELOG_E_POLICY;
  }

  Cursor c = {.p = text,.end = text + text_len };
  g_autoptr (GPtrArray) rules = g_ptr_array_new_with_free_func (pack_rule_free);
  gboolean ok = parse_pack (&c, rules);
  for (guint r = 0; ok && r < rules->len; r++) {
    c.rule_index = r + 1;
    ok = check_rule (g_ptr_array_index (rules, r), relations, n_relations, &c);
  }
  if (!ok) {
    out_rejection->reason = c.reason;
    out_rejection->rule_index = c.rule_index;
    out_rejection->atom_index = c.atom_index;
    return WYRELOG_E_POLICY;
  }

  g_autoptr (GArray) cyclic = find_cycle_rules (rules, n_relations);
  if (cyclic->len > 0) {
    out_rejection->reason = WYL_FACT_RULE_PACK_REJECT_CYCLE;
    out_rejection->rule_index = g_array_index (cyclic, guint, 0);
    out_rejection->n_cycle_rules = cyclic->len;
    out_rejection->cycle_rules =
        (guint *) g_array_free (g_steal_pointer (&cyclic), FALSE);
    return WYRELOG_E_POLICY;
  }

  g_autofree gchar *rendered = render_rules (rules, relations);
  gboolean compiled = FALSE;
  wyrelog_error_t rc = compile_program (relations, n_relations, rendered,
          &compiled);
  if (rc != WYRELOG_E_OK)
    return rc;
  if (!compiled) {
    out_rejection->reason = WYL_FACT_RULE_PACK_REJECT_COMPILE;
    return WYRELOG_E_POLICY;
  }
  *out_rules = g_steal_pointer (&rendered);
  return WYRELOG_E_OK;
}
