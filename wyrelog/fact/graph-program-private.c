/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fact/graph-program-private.h"

void
wyl_fact_graph_program_append_identifier (GString *out,
    const gchar *identifier)
{
  g_string_append_c (out, 'w');
  if (identifier == NULL)
    return;
  for (const gchar * p = identifier; *p != '\0'; p++)
    g_string_append_printf (out, "_%02x", (guchar) * p);
}

gchar *
wyl_fact_graph_program_relation_name (const gchar *namespace_id,
    const gchar *relation_name)
{
  if (namespace_id == NULL || relation_name == NULL)
    return NULL;

  g_autoptr (GString) out = g_string_new (NULL);
  wyl_fact_graph_program_append_identifier (out, namespace_id);
  g_string_append_c (out, '_');
  wyl_fact_graph_program_append_identifier (out, relation_name);
  return g_string_free (g_steal_pointer (&out), FALSE);
}

const gchar *
wyl_fact_graph_program_wire_type (const gchar *column_type)
{
  if (g_strcmp0 (column_type, "symbol") == 0
      || g_strcmp0 (column_type, "string") == 0)
    return "symbol";
  if (g_strcmp0 (column_type, "int64") == 0
      || g_strcmp0 (column_type, "bool") == 0
      || g_strcmp0 (column_type, "compound_ref") == 0)
    return "int64";
  return NULL;
}

static gboolean
append_declaration (GString *program, const gchar *name,
    const wyl_fact_graph_program_relation_t *rel)
{
  g_string_append (program, ".decl ");
  g_string_append (program, name);
  g_string_append_c (program, '(');
  for (gsize col = 0; col < rel->n_columns; col++) {
    const gchar *wire_type =
        wyl_fact_graph_program_wire_type (rel->columns[col].column_type);
    if (wire_type == NULL)
      return FALSE;
    if (col > 0)
      g_string_append (program, ", ");
    wyl_fact_graph_program_append_identifier (program,
        rel->columns[col].column_name);
    g_string_append_printf (program, ": %s", wire_type);
  }
  g_string_append (program, ")\n");
  return TRUE;
}

static void
append_variables (GString *program, gsize n_columns)
{
  g_string_append_c (program, '(');
  for (gsize col = 0; col < n_columns; col++) {
    if (col > 0)
      g_string_append (program, ", ");
    g_string_append_printf (program, "V%" G_GSIZE_FORMAT, col);
  }
  g_string_append_c (program, ')');
}

gchar *
wyl_fact_graph_program_render (const wyl_fact_graph_program_relation_t *
    relations, gsize n_relations, const gchar *rules)
{
  if (relations == NULL && n_relations > 0)
    return NULL;

  g_autoptr (GString) program = g_string_new (NULL);
  for (gsize i = 0; i < n_relations; i++) {
    const wyl_fact_graph_program_relation_t *rel = &relations[i];
    g_autofree gchar *relation =
        wyl_fact_graph_program_relation_name (rel->namespace_id,
            rel->relation_name);
    if (relation == NULL)
      return NULL;
    g_autofree gchar *observed = g_strdup_printf ("%s_observed", relation);

    if (!append_declaration (program, relation, rel)
        || !append_declaration (program, observed, rel))
      return NULL;

    g_string_append (program, observed);
    append_variables (program, rel->n_columns);
    g_string_append (program, " :- ");
    g_string_append (program, relation);
    append_variables (program, rel->n_columns);
    g_string_append (program, ".\n");
  }
  if (rules != NULL)
    g_string_append (program, rules);
  return g_string_free (g_steal_pointer (&program), FALSE);
}
