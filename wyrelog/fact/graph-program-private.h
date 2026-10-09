/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <glib.h>

#include "wyrelog/policy/store-private.h"

G_BEGIN_DECLS;

/* One declared relation of a fact graph's wirelog program, in customer names.
 * The renderer hex-encodes every name, so no customer byte reaches the
 * program text unencoded. */
typedef struct
{
  const gchar *namespace_id;
  const gchar *relation_name;
  const wyl_policy_fact_relation_schema_column_t *columns;
  gsize n_columns;
} wyl_fact_graph_program_relation_t;

/* Appends the wirelog spelling of one customer identifier: 'w' followed by
 * "_%02x" per byte. */
void wyl_fact_graph_program_append_identifier (GString * out,
    const gchar * identifier);

/* Returns the wirelog name of a relation, "<ns>_<rel>" with both parts
 * encoded as wyl_fact_graph_program_append_identifier does. */
gchar *wyl_fact_graph_program_relation_name (const gchar * namespace_id,
    const gchar * relation_name);

/* Returns the wirelog type a declared column type is carried as, or NULL for
 * an unknown type.  symbol and string are carried as symbol; int64, bool and
 * compound_ref all as int64, which is a shared wire representation and not a
 * shared type. */
const gchar *wyl_fact_graph_program_wire_type (const gchar * column_type);

/* Renders the program a graph engine is built from: per relation, a .decl for
 * the relation and for its _observed twin plus the identity rule between
 * them, in array order, followed by @rules verbatim when it is not NULL.
 * Returns NULL when a column carries an unknown type. */
gchar *wyl_fact_graph_program_render (const wyl_fact_graph_program_relation_t *
    relations, gsize n_relations, const gchar * rules);

G_END_DECLS;
